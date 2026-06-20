import ADTestKit
import HTTPTypes
import Logging
import NIOCore
import NIOPosix
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

    /// The F-5 contract: when the client disconnects, the engine cancels the SSE source promptly (its
    /// heartbeat sleep throws) so the body unwinds and the slot frees — without waiting for a failed
    /// write. Drives an INFINITE SSE body, disconnects mid-stream, and asserts the body exits.
    @Test func clientDisconnectCancelsTheSseSource() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        // Deterministic boundaries (ADTestKit): `wait(forAtLeast:)` throws on a missed signal instead of
        // a silent poll-loop timeout, so a regression fails fast and points at the probe's creation site.
        let firstByte = AsyncEventProbe<Void>()
        let bodyExited = AsyncEventProbe<Void>()
        let routes = StubRoutes { _ in
            .sse { writer in
                defer { bodyExited.record(()) }  // runs when the body unwinds (cancelled)
                while true {
                    try await writer.comment("ping")
                    try await Task.sleep(for: .milliseconds(20))
                }
            }
        }
        do {
            let probe = try await ServerBootstrap(group: group).bind(host: "127.0.0.1", port: 0).get()
            let port = probe.localAddress?.port ?? 0
            try await probe.close().get()
            let readiness = ServerReadiness()
            let server = HTTPServer(
                listeners: [ListenerConfig(host: "127.0.0.1", port: port, routes: routes)], pool: nil,
                envelope: HTTPFields(), logger: Logger(label: "sse-disconnect"), threadCount: 1,
                loopCount: 1, readiness: readiness)
            let serverTask = Task { try? await server.run() }
            defer { serverTask.cancel() }
            try await waitForReadiness(readiness)

            // Connect WITHOUT `Connection: close` so the stream stays open until WE disconnect.
            let client = try await ClientBootstrap(group: group)
                .channelInitializer { channel in channel.pipeline.addHandler(FirstByteSignal(firstByte)) }
                .connect(host: "127.0.0.1", port: port).get()
            var request = client.allocator.buffer(capacity: 64)
            request.writeString("GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            try await client.writeAndFlush(request).get()
            _ = try await firstByte.wait(forAtLeast: 1, timeout: .seconds(3))  // the SSE is sending
            #expect(bodyExited.count == 0)  // …and the body is still looping while connected

            try await client.close().get()  // the client disconnects mid-stream
            _ = try await bodyExited.wait(forAtLeast: 1, timeout: .seconds(3))  // source cancelled, unwound
            serverTask.cancel()
            try? await group.shutdownGracefully()
        } catch {
            try? await group.shutdownGracefully()
            throw error
        }
    }
}

/// Records into `probe` on the first inbound read — signals that the server's SSE stream has started.
/// `@unchecked Sendable`: `probe` is `Sendable`; `fired` is touched only on the event loop.
private final class FirstByteSignal: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    private let probe: AsyncEventProbe<Void>
    private var fired = false
    init(_ probe: AsyncEventProbe<Void>) { self.probe = probe }
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        if !fired {
            fired = true
            probe.record(())
        }
    }
}

/// Awaits server readiness (a synchronous flag, not a probe), throwing after ~3s so a bind failure
/// fails the test fast instead of hanging CI.
private func waitForReadiness(_ readiness: ServerReadiness) async throws {
    var spins = 0
    while !readiness.isReady {
        if spins >= 300 { throw TLSHarnessError("server did not become ready within 3s") }
        try await Task.sleep(for: .milliseconds(10))
        spins += 1
    }
}
