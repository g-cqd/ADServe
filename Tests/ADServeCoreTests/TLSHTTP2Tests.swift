import Foundation
import HTTPCore
import Testing

@testable import ADServeCore

/// `.stream` / `.sse` / `.file` exercised over HTTP/2 + TLS via the `LoopbackTLS` harness — the secure,
/// multiplexed counterpart to the h1 plaintext integration tests. One ALPN-negotiated `h2` stream per
/// request over URLSession's HTTP/2 client (ALPN-negotiated, asserted via transaction metrics).
@Suite struct TLSHTTP2IntegrationTests {
    @Test func plainRawResponseRoundTripsOverHTTP2() async throws {
        let routes = StubRoutes { _ in .raw(body: Array("h2-ok".utf8), contentType: "text/plain", status: .ok) }
        let response = try await LoopbackTLS.runH2(path: "/", routes: routes)
        #expect(response.status == 200)
        #expect(response.negotiatedProtocol == "h2")  // ALPN really settled on HTTP/2
        #expect(response.text == "h2-ok")
        #expect(response.headerEquals("content-type", "text/plain"))
        // HTTP/2 forbids the Connection header — the engine must not emit it on the h2 path.
        #expect(response.header("connection") == nil)
    }

    @Test func streamedBodyChunksRoundTripOverHTTP2() async throws {
        let routes = StubRoutes { _ in
            .stream(contentType: "text/plain") { writer in
                try await writer.write(Array("chunk-1;".utf8))
                try await writer.write(Array("chunk-2;".utf8))
                try await writer.write(Array("chunk-3".utf8))
            }
        }
        let response = try await LoopbackTLS.runH2(path: "/stream", routes: routes)
        #expect(response.status == 200)
        #expect(response.headerEquals("content-type", "text/plain"))
        // A streamed body carries no Content-Length (length unknown); h2 is length-less.
        #expect(response.header("content-length") == nil)
        #expect(response.text == "chunk-1;chunk-2;chunk-3")
    }

    @Test func sseFramedEventsRoundTripOverHTTP2() async throws {
        let routes = StubRoutes { _ in
            .sse { writer in
                try await writer.send("<div>1</div>", event: "morph", id: "1")
                try await writer.comment("keep-alive")
                try await writer.send("{\"a\":1}", event: "patch", id: "2")
            }
        }
        let response = try await LoopbackTLS.runH2(path: "/events", routes: routes)
        #expect(response.status == 200)
        #expect(response.headerEquals("content-type", "text/event-stream"))
        #expect(response.headerEquals("cache-control", "no-store"))
        #expect(response.text.contains("event: morph\nid: 1\ndata: <div>1</div>\n\n"))
        #expect(response.text.contains(": keep-alive\n"))
        #expect(response.text.contains("event: patch\nid: 2\ndata: {\"a\":1}\n\n"))
    }

    @Test func staticFileRoundTripsOverHTTP2WithETag() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("adserve-h2-static-\(UInt64.random(in: .min ... .max))")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try Data("body{color:red}".utf8).write(to: root.appendingPathComponent("app.css"))

        let routes = StubRoutes { _ in
            .file(root: root.path, subpath: "app.css", contentType: "text/css; charset=utf-8")
        }
        let response = try await LoopbackTLS.runH2(path: "/app.css", routes: routes)
        #expect(response.status == 200)
        #expect(response.headerEquals("content-type", "text/css; charset=utf-8"))
        #expect(response.header("etag") != nil)
        #expect(response.headerEquals("content-length", "15"))
        #expect(response.text == "body{color:red}")
    }

    @Test func staticConditionalRequestGets304OverHTTP2() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("adserve-h2-cond-\(UInt64.random(in: .min ... .max))")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try Data("x".utf8).write(to: root.appendingPathComponent("a.js"))

        let routes = StubRoutes { _ in
            .file(root: root.path, subpath: "a.js", contentType: "text/javascript")
        }
        let first = try await LoopbackTLS.runH2(path: "/a.js", routes: routes)
        let etag = try #require(first.header("etag"))
        let second = try await LoopbackTLS.runH2(
            path: "/a.js", routes: routes, headers: [("if-none-match", etag)])
        #expect(second.status == 304)
        #expect(second.body.isEmpty)
    }
}
