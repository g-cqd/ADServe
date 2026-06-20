// A TLS + HTTP/2 loopback client, the secure counterpart to `Loopback` (which is h1 plaintext). It
// binds an `HTTPServer` on an ephemeral self-signed cert, connects over TLS negotiating `h2` by ALPN,
// opens one HTTP/2 stream, sends a request, and collects the response — so the streaming / SSE / static
// paths can be integration-tested over HTTP/2 + TLS, not only h1. The client speaks the SAME
// swift-http-types parts the engine serves (via `HTTP2FramePayloadToHTTPClientCodec`), so the h2 path
// is exercised end to end. Best-effort teardown + bounded waits, so it can never hang CI.

import Foundation
import HTTPTypes
import Logging
import NIOCore
import NIOHTTP2
import NIOHTTPTypes
import NIOHTTPTypesHTTP2
import NIOPosix
import NIOSSL
import Synchronization

@testable import ADServeCore

/// An error from the TLS test harness (cert generation / missing mux).
struct TLSHarnessError: Error, CustomStringConvertible {
    let message: String
    init(_ message: String) { self.message = message }
    var description: String { message }
}

/// An ephemeral self-signed cert + key, generated once per test process via `openssl` into a temp dir
/// (cached behind a `Mutex`, so a run with several TLS tests pays the ~50ms generation only once). The
/// cert is short-lived (1 day) and never committed — "ephemeral" in the literal sense.
enum EphemeralTLS {
    private static let cached = Mutex<TLSSource?>(nil)

    static func source() throws -> TLSSource {
        try cached.withLock { box in
            if let existing = box { return existing }
            let generated = try generate()
            box = generated
            return generated
        }
    }

    private static func generate() throws -> TLSSource {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("adserve-tls-\(UInt64.random(in: .min ... .max))")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let cert = dir.appendingPathComponent("cert.pem").path
        let key = dir.appendingPathComponent("key.pem").path

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key, "-out", cert,
            "-days", "1", "-nodes", "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"
        ]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        let fileManager = FileManager.default
        guard process.terminationStatus == 0, fileManager.fileExists(atPath: cert),
            fileManager.fileExists(atPath: key)
        else {
            throw TLSHarnessError("openssl self-signed cert generation failed (is openssl on PATH?)")
        }
        return .pem(certificate: cert, privateKey: key)
    }
}

/// One HTTP/2 response collected by the loopback client.
struct H2Response {
    let status: Int
    let headers: HTTPFields
    let body: [UInt8]

    /// The body decoded as UTF-8 text (the streaming/SSE/static bodies under test are text).
    var text: String { String(decoding: body, as: UTF8.self) }
    /// One response header value by (case-insensitive) name, or `nil`.
    func header(_ name: String) -> String? { HTTPField.Name(name).flatMap { headers[$0] } }
    /// True if a header named `name` carries `value` (case-insensitive compare on the value).
    func headerEquals(_ name: String, _ value: String) -> Bool {
        header(name)?.lowercased() == value.lowercased()
    }
}

/// Binds an `HTTPServer` (TLS, ALPN `h2`+`http/1.1`) on an OS-assigned loopback port and drives one
/// HTTP/2 request over it, returning the collected response. The first secure/h2 coverage in the suite.
enum LoopbackTLS {
    private typealias H2Stream = NIOAsyncChannel<HTTPResponsePart, HTTPRequestPart>
    private typealias H2Mux = NIOHTTP2Handler.AsyncStreamMultiplexer<H2Stream>

    static func runH2(
        path: String, routes: any HTTPHandling, method: HTTPRequest.Method = .get,
        headers: [(name: String, value: String)] = []
    ) async throws -> H2Response {
        let tls = try EphemeralTLS.source()
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        do {
            let response = try await serve(
                path: path, routes: routes, method: method, headers: headers, tls: tls, group: group)
            try? await group.shutdownGracefully()
            return response
        } catch {
            try? await group.shutdownGracefully()
            throw error
        }
    }

    private static func serve(
        path: String, routes: any HTTPHandling, method: HTTPRequest.Method,
        headers: [(name: String, value: String)], tls: TLSSource, group: MultiThreadedEventLoopGroup
    ) async throws -> H2Response {
        let probe = try await ServerBootstrap(group: group).bind(host: "127.0.0.1", port: 0).get()
        let port = probe.localAddress?.port ?? 0
        try await probe.close().get()

        let readiness = ServerReadiness()
        let server = HTTPServer(
            listeners: [
                ListenerConfig(
                    host: "127.0.0.1", port: port, wire: .https(tls, alpn: [.http2, .http1]),
                    routes: routes)
            ], pool: nil, envelope: HTTPFields(), logger: Logger(label: "loopback-tls"), threadCount: 1,
            loopCount: 1, readiness: readiness)
        let serverTask = Task { try? await server.run() }
        defer { serverTask.cancel() }

        var spins = 0
        while !readiness.isReady && spins < 200 {
            try await Task.sleep(for: .milliseconds(10))
            spins += 1
        }

        let mux = try await connect(port: port, group: group)
        let stream = try await mux.openStream { streamChannel in
            streamChannel.eventLoop.makeCompletedFuture {
                try streamChannel.pipeline.syncOperations.addHandler(HTTP2FramePayloadToHTTPClientCodec())
                return try H2Stream(wrappingChannelSynchronously: streamChannel)
            }
        }

        var requestFields = HTTPFields()
        for header in headers {
            if let name = HTTPField.Name(header.name) { requestFields[name] = header.value }
        }
        let request = HTTPRequest(
            method: method, scheme: "https", authority: "127.0.0.1:\(port)", path: path,
            headerFields: requestFields)

        return try await stream.executeThenClose { inbound, outbound in
            try await outbound.write(.head(request))
            try await outbound.write(.end(nil))
            var status = 0
            var responseHeaders = HTTPFields()
            var body: [UInt8] = []
            for try await part in inbound {
                switch part {
                    case .head(let response):
                        status = response.status.code
                        responseHeaders = response.headerFields
                    case .body(let buffer):
                        body.append(contentsOf: buffer.readableBytesView)
                    case .end:
                        break
                }
            }
            return H2Response(status: status, headers: responseHeaders, body: body)
        }
    }

    /// Connects over TLS (insecure verification — a test self-signed cert), negotiating `h2` by ALPN,
    /// and returns the HTTP/2 stream multiplexer once the pipeline is configured.
    private static func connect(port: Int, group: MultiThreadedEventLoopGroup) async throws -> H2Mux {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .none  // test-only: trust the ephemeral self-signed cert
        clientConfig.applicationProtocols = ["h2"]
        let clientContext = try NIOSSLContext(configuration: clientConfig)

        let muxPromise = group.next().makePromise(of: H2Mux.self)
        _ = try await ClientBootstrap(group: group)
            .channelInitializer { channel in
                do {
                    let sslHandler = try NIOSSLClientHandler(context: clientContext, serverHostname: nil)
                    try channel.pipeline.syncOperations.addHandler(sslHandler)
                    let mux = try channel.pipeline.syncOperations.configureAsyncHTTP2Pipeline(
                        mode: .client
                    ) { streamChannel in
                        streamChannel.eventLoop.makeCompletedFuture {
                            try streamChannel.pipeline.syncOperations.addHandler(
                                HTTP2FramePayloadToHTTPClientCodec())
                            return try H2Stream(wrappingChannelSynchronously: streamChannel)
                        }
                    }
                    muxPromise.succeed(mux)
                    return channel.eventLoop.makeSucceededVoidFuture()
                } catch {
                    muxPromise.fail(error)
                    return channel.eventLoop.makeFailedFuture(error)
                }
            }
            .connect(host: "127.0.0.1", port: port).get()
        return try await muxPromise.futureResult.get()
    }
}
