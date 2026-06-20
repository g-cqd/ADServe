import HTTPTypes
import Synchronization
import Testing

@testable import ADServeCore

/// An in-memory `ResponseBodyWriter` that records every chunk — the headless double for driving a
/// `.stream` body closure without a live socket (mirrors how the suite drives `run`/`match` directly).
/// `Sendable` via a `Mutex`, so it is safe to hand to the `@Sendable` body closure.
final class CollectingBodyWriter: ResponseBodyWriter {
    private let store = Mutex<[[UInt8]]>([])
    var chunks: [[UInt8]] { store.withLock { $0 } }
    var bytes: [UInt8] { store.withLock { $0.flatMap { $0 } } }
    func write(_ bytes: [UInt8]) async throws { store.withLock { $0.append(bytes) } }
    func flush() async throws {}
}

@Suite struct StreamingResponseTests {
    @Test func streamCarriesContentTypeAndDefaultStatusAndHeaders() {
        let content = ResponseContent.stream(contentType: "text/html; charset=utf-8") { _ in }
        guard case .stream(let contentType, let status, let headers, _) = content else {
            Issue.record("expected .stream")
            return
        }
        #expect(contentType == "text/html; charset=utf-8")
        #expect(status == .ok)  // associated-value default
        #expect(headers.isEmpty)  // associated-value default
    }

    @Test func streamBodyWritesChunksInOrder() async throws {
        let content = ResponseContent.stream(contentType: "text/html") { writer in
            try await writer.write(Array("<head>…</head>".utf8))  // an early <head> flush
            try await writer.write(Array("<body>".utf8))
            try await writer.write(Array("</body>".utf8))
        }
        guard case .stream(_, _, _, let body) = content else {
            Issue.record("expected .stream")
            return
        }
        let collector = CollectingBodyWriter()
        try await body(collector)
        #expect(collector.chunks.count == 3)  // discrete chunks → head can flush before the body
        #expect(collector.bytes == Array("<head>…</head><body></body>".utf8))
    }

    @Test func emptyChunkIsSkippedByTheWriterContract() async throws {
        // The engine's ChannelBodyWriter no-ops on empty input; the in-memory double records faithfully,
        // so this asserts only the ordering contract callers rely on.
        let content = ResponseContent.stream(contentType: "text/plain") { writer in
            try await writer.write([])
            try await writer.write(Array("x".utf8))
        }
        guard case .stream(_, _, _, let body) = content else {
            Issue.record("expected .stream")
            return
        }
        let collector = CollectingBodyWriter()
        try await body(collector)
        #expect(collector.bytes == Array("x".utf8))
    }

    @Test func statusCodeReadsStreamStatus() {
        #expect(statusCode(of: .stream(contentType: "text/html", status: .accepted) { _ in }) == 202)
        #expect(statusCode(of: .stream(contentType: "text/html") { _ in }) == 200)
    }

    @Test func withHeadersMergesIntoStreamWithoutLosingTheBody() async throws {
        var extra = HTTPFields()
        extra[HTTPField.Name("x-test")!] = "1"
        let decorated =
            ResponseContent.stream(contentType: "text/html") { writer in
                try await writer.write(Array("hi".utf8))
            }
            .withHeaders(extra)

        guard case .stream(let contentType, _, let headers, let body) = decorated else {
            Issue.record("expected withHeaders to preserve .stream")
            return
        }
        #expect(contentType == "text/html")
        #expect(headers[HTTPField.Name("x-test")!] == "1")
        let collector = CollectingBodyWriter()
        try await body(collector)
        #expect(collector.bytes == Array("hi".utf8))  // the body closure survived decoration
    }

    @Test func midStreamThrowPropagatesAfterFlushingEarlierChunks() async throws {
        struct StreamFailure: Error {}
        let content = ResponseContent.stream(contentType: "text/html") { writer in
            try await writer.write(Array("partial".utf8))
            throw StreamFailure()
        }
        guard case .stream(_, _, _, let body) = content else {
            Issue.record("expected .stream")
            return
        }
        let collector = CollectingBodyWriter()
        await #expect(throws: StreamFailure.self) { try await body(collector) }
        #expect(collector.bytes == Array("partial".utf8))  // chunks before the throw still reached the sink
    }
}

@Suite struct StreamingIntegrationTests {
    /// End-to-end over a real loopback socket: a `.stream` route's head goes out, both writer chunks
    /// round-trip, and there is NO `Content-Length` (proving the body was streamed, not buffered).
    @Test func streamedResponseRoundTripsWithoutContentLength() async throws {
        let routes = StubRoutes { _ in
            .stream(contentType: "text/html; charset=utf-8") { writer in
                try await writer.write(Array("<head>EARLY</head>".utf8))
                try await writer.write(Array("<body>LATE</body>".utf8))
            }
        }
        let response = try await Loopback.run(path: "/stream", routes: routes)
        let lower = response.lowercased()
        #expect(response.hasPrefix("HTTP/1.1 200"))
        #expect(lower.contains("content-type: text/html; charset=utf-8"))
        #expect(lower.contains("transfer-encoding: chunked"))  // streamed → chunked framing, not buffered
        #expect(!lower.contains("content-length:"))  // unbuffered: length is unknown up front
        #expect(response.contains("<head>EARLY</head>"))  // first writer chunk (its own HTTP chunk)
        #expect(response.contains("<body>LATE</body>"))  // second writer chunk (wire order = write order)
        #expect(lower.contains("x-request-id:"))  // the envelope still rides a streamed head
    }
}
