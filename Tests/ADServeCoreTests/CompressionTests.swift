// M2 on-the-fly response compression: gzip/deflate on the HTTP/1 pipeline, gated by a predicate
// (compressible MIME types only, no existing Content-Encoding, never SSE), honoring Accept-Encoding.

import ADTestKit
import Foundation
import HTTPTypes
import Testing

@testable import ADServeCore

@Suite struct MIMECompressibilityTests {
    @Test func knownCompressibleTypes() {
        #expect(MIMEDatabase.isCompressible(type: "text/html"))
        #expect(MIMEDatabase.isCompressible(type: "text/css"))
        #expect(MIMEDatabase.isCompressible(type: "application/json"))
        #expect(MIMEDatabase.isCompressible(type: "application/javascript"))
        #expect(MIMEDatabase.isCompressible(type: "image/svg+xml"))
    }

    @Test func knownIncompressibleTypes() {
        // Per mime-db (the authoritative source the static path already trusts): already-compressed and
        // media payloads are not worth re-compressing. (Note mime-db DOES mark application/octet-stream
        // compressible, so it is intentionally absent here.)
        #expect(!MIMEDatabase.isCompressible(type: "image/png"))
        #expect(!MIMEDatabase.isCompressible(type: "image/jpeg"))
        #expect(!MIMEDatabase.isCompressible(type: "video/mp4"))
        #expect(!MIMEDatabase.isCompressible(type: "application/zip"))
        #expect(!MIMEDatabase.isCompressible(type: "application/gzip"))
    }

    @Test func unknownTypeIsNotCompressed() {
        #expect(!MIMEDatabase.isCompressible(type: "totally/unknown"))
        #expect(!MIMEDatabase.isCompressible(type: ""))
    }
}

@Suite struct ResponseCompressionTests {
    /// A compressible body the client accepts gzip for is gzipped: `Content-Encoding: gzip` is set and
    /// the plaintext no longer appears verbatim on the wire (it's compressed).
    @Test func compressibleResponseIsGzippedWhenAccepted() async throws {
        let marker = "<p>UNIQUE-MARKER-hello-world</p>"
        let body = String(repeating: marker, count: 100)  // ~3 KB, very compressible
        let routes = StubRoutes { _ in .html(Array(body.utf8)) }
        let response = try await Loopback.run(
            path: "/", routes: routes, headers: [("Accept-Encoding", "gzip")])
        let lower = response.lowercased()
        #expect(lower.contains("content-encoding: gzip"))
        #expect(!response.contains(marker))  // body is compressed, not the literal plaintext
    }

    @Test func noAcceptEncodingMeansNoCompression() async throws {
        let marker = "<p>plain-body-marker</p>"
        let routes = StubRoutes { _ in .html(Array(String(repeating: marker, count: 100).utf8)) }
        let response = try await Loopback.run(path: "/", routes: routes)  // no Accept-Encoding
        #expect(!response.lowercased().contains("content-encoding"))
        #expect(response.contains(marker))  // served as plaintext
    }

    @Test func incompressibleTypeIsNotCompressed() async throws {
        // image/png is not mime-db-compressible — even with Accept-Encoding: gzip it is sent as-is.
        let marker = "PNG-MARKER-bytes-here"
        let routes = StubRoutes { _ in
            .raw(body: Array(String(repeating: marker, count: 80).utf8), contentType: "image/png", status: .ok)
        }
        let response = try await Loopback.run(
            path: "/", routes: routes, headers: [("Accept-Encoding", "gzip")])
        #expect(!response.lowercased().contains("content-encoding"))
        #expect(response.contains(marker))
    }

    /// An SSE stream must never be compressed (it would buffer the long-lived body); the engine skips it
    /// even with `Accept-Encoding: gzip`.
    @Test func sseStreamIsNeverCompressed() async throws {
        let routes = StubRoutes { _ in
            .sse { writer in try await writer.send("sse-payload-marker", event: "e", id: "1") }
        }
        let response = try await Loopback.run(
            path: "/events", routes: routes, headers: [("Accept-Encoding", "gzip")])
        #expect(!response.lowercased().contains("content-encoding: gzip"))
        #expect(response.contains("data: sse-payload-marker"))  // plaintext SSE framing intact
    }

    /// A precompressed static variant (`.br`, already carrying `Content-Encoding: br`) is passed through
    /// untouched — the on-the-fly compressor sees the existing encoding and does not re-compress to gzip.
    @Test func precompressedStaticIsNotDoubleCompressed() async throws {
        let dir = TemporaryDirectory(prefix: "adserve-compress")
        defer { dir.cleanup() }
        try Data(String(repeating: "IDENTITY-CSS-", count: 80).utf8)
            .write(to: URL(fileURLWithPath: dir.file("app.css")))
        try Data("BROTLI-VARIANT-MARKER".utf8).write(to: URL(fileURLWithPath: dir.file("app.css.br")))
        let routes = StubRoutes { _ in
            .file(root: dir.path, subpath: "app.css", contentType: "text/css; charset=utf-8")
        }
        let response = try await Loopback.run(
            path: "/app.css", routes: routes, headers: [("Accept-Encoding", "br, gzip")])
        let lower = response.lowercased()
        #expect(lower.contains("content-encoding: br"))  // the precompressed variant
        #expect(!lower.contains("content-encoding: gzip"))  // NOT re-compressed
        #expect(response.contains("BROTLI-VARIANT-MARKER"))  // served as-is
    }

    @Test func compressionCanBeDisabled() async throws {
        let marker = "<p>disabled-compression-marker</p>"
        let body = String(repeating: marker, count: 100)
        let routes = StubRoutes { _ in .html(Array(body.utf8)) }
        let response = try await Loopback.run(
            path: "/", routes: routes, headers: [("Accept-Encoding", "gzip")], compression: false)
        #expect(!response.lowercased().contains("content-encoding"))
        #expect(response.contains(marker))  // plaintext — compressor not installed
    }
}

/// On-the-fly compression of STREAMED static files over a KEPT-ALIVE connection — the framing the
/// `Connection: close` harness structurally cannot see, plus the two new server options (`keepAlive`,
/// `idleTimeout`). A wrong `Content-Length` only bites a client that honors it (a browser on keep-alive);
/// `Loopback.run` reads to EOF and would pass regardless, which is exactly how the original bug shipped.
@Suite struct StaticCompressionFramingTests {
    /// ~5 KB of very compressible HTML, NO `.gz`/`.br` sibling → the on-the-fly compressor engages (not
    /// the precompressed-static path).
    private func staticHTMLRoutes(_ dir: TemporaryDirectory) throws -> StubRoutes {
        let html =
            "<!doctype html><html><body>"
            + String(repeating: "<p>hello compressible world</p>", count: 160) + "</body></html>"
        try Data(html.utf8).write(to: URL(fileURLWithPath: dir.file("index.html")))
        return StubRoutes { _ in
            .file(root: dir.path, subpath: "index.html", contentType: "text/html; charset=utf-8")
        }
    }

    /// THE regression. A compressible static file with no precompressed sibling, fetched with
    /// `Accept-Encoding: gzip` over a kept-alive connection. Before the fix the engine flushed the
    /// response head (carrying the identity `Content-Length`) on its own, so `HTTPResponseCompressor`
    /// emitted that stale length beside a gzipped (shorter) body — every browser then blocked waiting for
    /// bytes that never come (the page/preview hangs until the idle timeout). The fix flushes the head
    /// WITH the first body chunk, so the compressor switches the response to chunked. Assert it is gzipped
    /// AND self-framed (chunked, terminated) — a client does NOT hang.
    @Test func compressedStaticFileOverKeepAliveDoesNotHang() async throws {
        let dir = TemporaryDirectory(prefix: "adserve-static-gzip")
        defer { dir.cleanup() }
        let routes = try staticHTMLRoutes(dir)
        let response = try await Loopback.runKeepAlive(
            path: "/index.html", routes: routes, headers: [("Accept-Encoding", "gzip")])
        let lower = response.lowercased()
        #expect(lower.contains("content-encoding: gzip"))  // compression engaged
        #expect(lower.contains("transfer-encoding: chunked"))  // → chunked, no stale Content-Length
        #expect(!lower.contains("content-length:"))  // the bug header is gone
        #expect(response.hasSuffix("0\r\n\r\n"))  // last-chunk terminator → self-framed, no hang
    }

    /// Without `Accept-Encoding` the same file is identity with an EXACT `Content-Length`: the head still
    /// rides with the first chunk (one batched flush), so the length is correct and the client reads
    /// exactly that many bytes (length-delimited, not chunked).
    @Test func uncompressedStaticFileOverKeepAliveHasExactContentLength() async throws {
        let dir = TemporaryDirectory(prefix: "adserve-static-plain")
        defer { dir.cleanup() }
        let routes = try staticHTMLRoutes(dir)
        let response = try await Loopback.runKeepAlive(path: "/index.html", routes: routes)
        let lower = response.lowercased()
        #expect(!lower.contains("content-encoding"))  // not compressed
        #expect(lower.contains("content-length:"))  // identity length present
        #expect(!lower.contains("transfer-encoding: chunked"))  // length-delimited
        #expect(HTTP1ResponseFraming.isComplete(Array(response.utf8)))  // CL satisfied → no hang
    }

    /// A `Range` request for a compressible file is NOT compressed (gzip + ranges are incoherent — the
    /// `Content-Range` describes identity bytes). It stays identity: 206 + `Content-Range`, no encoding.
    @Test func rangeRequestIsServedIdentityNotCompressed() async throws {
        let dir = TemporaryDirectory(prefix: "adserve-static-range")
        defer { dir.cleanup() }
        let routes = try staticHTMLRoutes(dir)
        let response = try await Loopback.runKeepAlive(
            path: "/index.html", routes: routes,
            headers: [("Accept-Encoding", "gzip"), ("Range", "bytes=0-99")])
        let lower = response.lowercased()
        #expect(response.hasPrefix("HTTP/1.1 206"))
        #expect(lower.contains("content-range: bytes 0-99/"))
        #expect(!lower.contains("content-encoding"))  // a range is served identity
        #expect(lower.contains("content-length: 100"))
    }

    /// The server-wide `keepAlive: false` option answers EVERY request with `Connection: close` (and
    /// closes the socket) even though the client requested keep-alive — so idle sockets never linger and a
    /// network-idle-waiting preview settles at once.
    @Test func serverKeepAliveFalseAnswersWithConnectionClose() async throws {
        let routes = StubRoutes { _ in .raw(body: Array("ok".utf8), contentType: "text/plain", status: .ok) }
        let response = try await Loopback.runKeepAlive(path: "/", routes: routes, keepAlive: false)
        #expect(response.hasPrefix("HTTP/1.1 200"))
        #expect(response.lowercased().contains("connection: close"))
        #expect(response.hasSuffix("ok"))
    }

    /// A small configurable `idleTimeout` closes an otherwise-idle kept-alive connection (slowloris
    /// defense; also lets a network-idle-waiting preview settle without disabling keep-alive). Observed
    /// within a generous bound.
    @Test func configurableIdleTimeoutClosesIdleConnection() async throws {
        let routes = StubRoutes { _ in .raw(body: Array("hi".utf8), contentType: "text/plain", status: .ok) }
        let closed = try await Loopback.observeServerClose(
            path: "/", routes: routes, idleTimeout: .milliseconds(200), within: .seconds(3))
        #expect(closed)
    }
}
