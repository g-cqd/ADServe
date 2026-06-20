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
