import ADTestKit
import HTTPCore
import Logging
import Testing

@testable import ADServeCore

@Suite struct SSEFramingTests {
    @Test func dataOnlyEventEndsWithBlankLine() {
        #expect(SSEFraming.event(event: nil, data: "hello", id: nil, retry: nil) == "data: hello\n\n")
    }

    @Test func allFieldsInSpecOrderEventIdRetryData() {
        let frame = SSEFraming.event(event: "morph", data: "x", id: "42", retry: 3000)
        #expect(frame == "event: morph\nid: 42\nretry: 3000\ndata: x\n\n")
    }

    @Test func multiLineDataBecomesOneDataLineEach() {
        #expect(
            SSEFraming.event(event: nil, data: "a\nb\nc", id: nil, retry: nil)
                == "data: a\ndata: b\ndata: c\n\n")
    }

    @Test func crlfDataDropsTheCarriageReturn() {
        #expect(SSEFraming.event(event: nil, data: "a\r\nb", id: nil, retry: nil) == "data: a\ndata: b\n\n")
    }

    @Test func emptyDataIsASingleEmptyDataLine() {
        #expect(SSEFraming.event(event: nil, data: "", id: nil, retry: nil) == "data: \n\n")
    }

    @Test func newlineInEventOrIdIsTruncatedSoNoSecondFrameCanBeInjected() {
        let frame = SSEFraming.event(event: "morph\ndata: evil", data: "ok", id: "1\n2", retry: nil)
        #expect(frame == "event: morph\nid: 1\ndata: ok\n\n")  // injected newline content dropped
    }

    @Test func commentIsSingleLine() {
        #expect(SSEFraming.comment("keep-alive") == ": keep-alive\n")
        #expect(SSEFraming.comment("a\nb") == ": a\n")
    }
}

@Suite struct SSELimiterTests {
    @Test func acquiresUpToLimitThenRefusesUntilReleased() {
        let limiter = SSELimiter(limit: 2)
        #expect(limiter.tryAcquire())  // 1/2
        #expect(limiter.tryAcquire())  // 2/2
        #expect(!limiter.tryAcquire())  // at capacity
        limiter.release()  // 1/2
        #expect(limiter.tryAcquire())  // 2/2 again
        #expect(!limiter.tryAcquire())
    }

    @Test func zeroLimitRefusesEverything() {
        #expect(!SSELimiter(limit: 0).tryAcquire())
    }
}

@Suite struct SSEIntegrationTests {
    /// End-to-end: an SSE route's framed events round-trip with `text/event-stream` + `no-store` and no
    /// `Content-Length`. The body is finite so the connection closes and the harness reads to EOF.
    @Test func sseFramedEventsRoundTripWithNoStore() async throws {
        let routes = StubRoutes { _ in
            .sse { writer in
                try await writer.send("<div>1</div>", event: "morph", id: "1")
                try await writer.comment("keep-alive")
                try await writer.send("{\"a\":1}", event: "patch", id: "2")
            }
        }
        let response = try await Loopback.run(path: "/events", routes: routes)
        let lower = response.lowercased()
        #expect(response.hasPrefix("HTTP/1.1 200"))
        #expect(lower.contains("content-type: text/event-stream"))
        #expect(lower.contains("cache-control: no-store"))
        #expect(!lower.contains("content-length:"))
        #expect(response.contains("event: morph\nid: 1\ndata: <div>1</div>\n\n"))
        #expect(response.contains(": keep-alive\n"))
        #expect(response.contains("event: patch\nid: 2\ndata: {\"a\":1}\n\n"))
    }

    /// The F-5 contract: when the client disconnects, the SSE source unwinds promptly — its next
    /// write to the dead peer throws, so the body exits and the slot frees. Drives an INFINITE SSE
    /// body (writing every 20ms), disconnects mid-stream, and asserts the body exits within bounds.
    @Test func clientDisconnectCancelsTheSseSource() async throws {
        // Deterministic boundaries (ADTestKit): `wait(forAtLeast:)` throws on a missed signal instead
        // of a silent poll-loop timeout, so a regression fails fast at the probe's creation site.
        let firstByte = AsyncEventProbe<Void>()
        let bodyExited = AsyncEventProbe<Void>()
        let routes = StubRoutes { _ in
            .sse { writer in
                defer { bodyExited.record(()) }  // runs when the body unwinds (dead-peer write threw)
                while true {
                    try await writer.comment("ping")
                    try await Task.sleep(for: .milliseconds(20))
                }
            }
        }
        let stillLoopingWhileConnected = try await Loopback.withServer(routes: routes) { port in
            // Connect WITHOUT `Connection: close` so the stream stays open until WE disconnect.
            let client = try TestSocket.connect(host: "127.0.0.1", port: port)
            try client.send("GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            if let chunk = client.readChunk(timeout: .seconds(3)), !chunk.isEmpty {
                firstByte.record(())  // the SSE is sending
            }
            let stillLooping = bodyExited.count == 0  // …and the body loops while connected
            client.close()  // the client disconnects mid-stream
            return stillLooping
        }
        _ = try await firstByte.wait(forAtLeast: 1, timeout: .seconds(3))
        #expect(stillLoopingWhileConnected)
        _ = try await bodyExited.wait(forAtLeast: 1, timeout: .seconds(3))  // source unwound
    }
}
