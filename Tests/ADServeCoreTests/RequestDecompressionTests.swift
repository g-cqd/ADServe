// Opt-in, capped request-body decompression (security hardening): a `Content-Encoding: gzip` request body
// is transparently inflated for the handler ONLY when the server enables it, and ALWAYS under a hard
// output-size cap so a decompression bomb (tiny gzip → gigabytes, CWE-409) is rejected before it can
// exhaust memory. These are real-socket integration tests: a known gzip blob is POSTed over loopback and we
// assert the inflated bytes reach the handler (small body), the connection is dropped without a success
// response (bomb), and the feature is OFF by default.

import Foundation
import HTTPTypes
import Logging
import NIOCore
import NIOPosix
import Testing

@testable import ADServeCore

@Suite struct RequestDecompressionTests {
    // MARK: gzip fixtures (static `gzip -n` wire blobs — deterministic, no compression lib needed)

    /// The exact plaintext that `smallGzip` inflates to (61 bytes). The echo handler returning these bytes
    /// is positive proof the engine inflated the body before the handler ran.
    static let smallPlaintext = Array("the quick brown fox jumps over the lazy dog — decompressed!".utf8)

    /// A real 80-byte gzip member (`gzip -n`) of `smallPlaintext`. Inflates to 61 bytes — well under any
    /// cap used here, so it decompresses cleanly.
    static let smallGzip = base64(
        "H4sIAAAAAAAAAyvJSFUoLM1MzlZIKsovz1NIy69QyCrNLShWyC9LLVIoAUrnJFZVKqTkpys8apiikJKanJ9bUJRaXJya"
            + "oggAj5ZQYT0AAAA=")

    /// The decompressed size of `bombGzip`: 256 KiB. Used only to size the caps so the bomb's inflation is
    /// provably above the decompression ceiling (and below the body ceiling).
    static let bombInflatedSize = 256 * 1024

    /// A decompression BOMB: a 289-byte gzip member (`gzip -n`) of 256 KiB of zeros (~907:1). A handler that
    /// gunzipped it with no cap would balloon to 256 KiB from 289 bytes — the exact attack the capped
    /// decompressor exists to stop.
    static let bombGzip = base64(
        "H4sIAAAAAAAAA+3BMQEAAADCoPVP7W0HoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            + "AAAAAAAAAA3gAi6g7iAAAEAA==")

    static func base64(_ string: String) -> [UInt8] {
        guard let data = Data(base64Encoded: string) else {
            fatalError("invalid base64 gzip fixture")
        }
        return [UInt8](data)
    }

    // MARK: real-socket round trip

    /// Binds a one-listener `HTTPServer` with the given decompression policy + body ceiling, connects a
    /// client, writes a raw request (header text + raw body BYTES — binary-safe, unlike a `String` body),
    /// and returns the full raw response read to EOF. `Connection: close` makes the server close after the
    /// response (or after it rejects the bomb), so the client's read always ends. Bounded readiness wait +
    /// best-effort teardown, so a bind failure or a dropped connection can never hang the test.
    static func roundTrip(
        headerText: String, body: [UInt8], routes: any HTTPHandling,
        requestDecompression: RequestDecompressionPolicy, maxBodyBytes: Int = 1_000_000
    ) async throws -> [UInt8] {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        do {
            let response = try await serve(
                headerText: headerText, body: body, routes: routes,
                requestDecompression: requestDecompression, maxBodyBytes: maxBodyBytes, group: group)
            try? await group.shutdownGracefully()
            return response
        } catch {
            try? await group.shutdownGracefully()
            throw error
        }
    }

    private static func serve(
        headerText: String, body: [UInt8], routes: any HTTPHandling,
        requestDecompression: RequestDecompressionPolicy, maxBodyBytes: Int,
        group: MultiThreadedEventLoopGroup
    ) async throws -> [UInt8] {
        // A free loopback port (bind :0, read the assignment, release it).
        let probe = try await ServerBootstrap(group: group).bind(host: "127.0.0.1", port: 0).get()
        let port = probe.localAddress?.port ?? 0
        try await probe.close().get()

        let readiness = ServerReadiness()
        let server = HTTPServer(
            listeners: [ListenerConfig(host: "127.0.0.1", port: port, routes: routes)], pool: nil,
            envelope: HTTPFields(), logger: Logger(label: "decompression-test"), threadCount: 1,
            loopCount: 1, readiness: readiness, maxBodyBytes: maxBodyBytes,
            requestDecompression: requestDecompression)
        let serverTask = Task { try? await server.run() }
        defer { serverTask.cancel() }

        // Await readiness, bounded (≤2s) so a bind failure surfaces as a connect error, never a hang.
        var spins = 0
        while !readiness.isReady && spins < 200 {
            try await Task.sleep(for: .milliseconds(10))
            spins += 1
        }

        let promise = group.next().makePromise(of: [UInt8].self)
        let client = try await ClientBootstrap(group: group)
            .channelInitializer { channel in channel.pipeline.addHandler(ResponseCollector(promise)) }
            .connect(host: "127.0.0.1", port: port).get()
        // Write the header text and the raw body bytes (binary gzip survives — no lossy `String` round trip).
        var buffer = client.allocator.buffer(capacity: headerText.utf8.count + body.count)
        buffer.writeString(headerText)
        buffer.writeBytes(body)
        try await client.writeAndFlush(buffer).get()
        let bytes = try await promise.futureResult.get()
        try? await client.close().get()
        return bytes
    }

    /// A handler that echoes the EXACT request body it received back as the response body, so a test can
    /// prove what bytes the engine handed it (the inflated plaintext when decompression ran, or the raw
    /// gzip bytes when it did not). Matches any method; never needs storage.
    static func echoBodyRoutes() -> InputStubRoutes {
        InputStubRoutes { input in
            .raw(body: input.request.body, contentType: "application/octet-stream", status: .ok)
        }
    }

    /// The body bytes of an HTTP/1.1 response (everything past the `\r\n\r\n` header terminator); `nil` if
    /// no full header block is present (e.g. the connection was dropped with no response at all).
    static func responseBody(_ bytes: [UInt8]) -> [UInt8]? {
        let crlfCrlf: [UInt8] = [13, 10, 13, 10]
        guard bytes.count >= crlfCrlf.count else { return nil }
        for i in 0 ... (bytes.count - crlfCrlf.count) where Array(bytes[i ..< i + crlfCrlf.count]) == crlfCrlf {
            return Array(bytes[(i + crlfCrlf.count)...])
        }
        return nil
    }

    /// The header block of an HTTP/1.1 response as text (everything up to and including `\r\n\r\n`), or the
    /// whole thing as text if there is no body separator.
    static func header(_ bytes: [UInt8]) -> String {
        guard let body = responseBody(bytes) else { return String(decoding: bytes, as: UTF8.self) }
        return String(decoding: bytes[..<(bytes.count - body.count)], as: UTF8.self)
    }

    // MARK: tests

    /// A small gzip body, with decompression ENABLED, is inflated before the handler runs: the echo handler
    /// sees — and returns — the original plaintext, not the gzip bytes. Proves the decompressor is wired in
    /// and that the handler observes the INFLATED body.
    @Test func enabledInflatesSmallGzipBody() async throws {
        // The fixture really is compressed wire bytes distinct from its plaintext.
        #expect(Self.smallGzip != Self.smallPlaintext)

        let headerText =
            "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n"
            + "Content-Encoding: gzip\r\nContent-Length: \(Self.smallGzip.count)\r\n\r\n"
        let response = try await Self.roundTrip(
            headerText: headerText, body: Self.smallGzip, routes: Self.echoBodyRoutes(),
            requestDecompression: .enabled(maxSize: 1_000_000))

        #expect(Self.header(response).contains("200"))
        #expect(Self.responseBody(response) == Self.smallPlaintext)
    }

    /// A decompression BOMB (a tiny gzip that inflates far past the cap) is rejected: the decompressor errors
    /// at the cap, the connection is dropped, and NO successful response — and none of the inflated payload —
    /// is returned. The engine body ceiling (4 MiB) is well ABOVE the decompression cap (64 KiB) and the
    /// inflated size (256 KiB), so the rejection is attributable to the DECOMPRESSION cap specifically, not
    /// the ordinary body-size guard.
    @Test func enabledRejectsDecompressionBomb() async throws {
        // The bomb really is a tiny input that would explode: compressed << inflated.
        #expect(Self.bombGzip.count < Self.bombInflatedSize / 100)

        let headerText =
            "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n"
            + "Content-Encoding: gzip\r\nContent-Length: \(Self.bombGzip.count)\r\n\r\n"
        let response = try await Self.roundTrip(
            headerText: headerText, body: Self.bombGzip, routes: Self.echoBodyRoutes(),
            requestDecompression: .enabled(maxSize: 64 * 1024), maxBodyBytes: 4 * 1024 * 1024)

        // No 200 success line, and the inflated payload is nowhere in the response (the handler never ran):
        // the whole response is far smaller than the would-be inflated body.
        #expect(!Self.header(response).contains("200"))
        #expect(response.count < Self.bombInflatedSize)
    }

    /// With decompression DISABLED (the default), a gzip body is passed through UNINFLATED: the echo handler
    /// receives the raw gzip bytes verbatim, exactly as today. Guards the opt-in contract — the feature must
    /// be off unless explicitly enabled.
    @Test func disabledPassesGzipBodyThroughVerbatim() async throws {
        let headerText =
            "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n"
            + "Content-Encoding: gzip\r\nContent-Length: \(Self.smallGzip.count)\r\n\r\n"
        let response = try await Self.roundTrip(
            headerText: headerText, body: Self.smallGzip, routes: Self.echoBodyRoutes(),
            requestDecompression: .disabled)

        #expect(Self.header(response).contains("200"))
        // The handler saw the raw gzip bytes — NOT the inflated plaintext.
        #expect(Self.responseBody(response) == Self.smallGzip)
        #expect(Self.responseBody(response) != Self.smallPlaintext)
    }
}
