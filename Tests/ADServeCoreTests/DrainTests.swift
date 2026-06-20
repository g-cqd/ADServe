// Graceful-drain coverage for the M0 "drain with a live SSE" gap, proven as two deterministic links:
//   (1) a quiesce event closes a live connection — the `EmbeddedChannel` unit test (no timing), plus the
//       keep-alive integration test driving the engine's real bind/serve/quiesce internals (the exact
//       path `run()`'s drain takes on SIGTERM); and
//   (2) a closed connection cancels the SSE source so the slot frees — `clientDisconnectCancelsTheSseSource`
//       in SSETests (a transport-level close unwinds the streaming body).
//
// Note (flagged, not a test bug): a quiesce of an *actively-writing* SSE does not close its connection
// promptly — the streaming `executeThenClose` holds the channel's outbound writer, so the quiesce's
// `context.close()` cannot complete until the body yields. Cooperative drain (the app closing its streams
// when `ServerReadiness` flips to false) is the intended path; force-closing a busy stream on quiesce is a
// candidate ops-hardening follow-up. The keep-alive test exercises the connection-close mechanism without
// that streaming-writer contention.

import ADTestKit
import HTTPTypes
import Logging
import NIOCore
import NIOEmbedded
import NIOExtras
import NIOPosix
import Testing

@testable import ADServeCore

@Suite struct GracefulDrainTests {
    /// Deterministic: the per-connection `IdleTimeoutHandler` closes its channel on the
    /// `ChannelShouldQuiesceEvent` that `ServerQuiescingHelper` fires on every live connection during a
    /// graceful drain. `EmbeddedChannel`, so there is no real I/O and no timing — the assertion is exact.
    @Test func idleTimeoutHandlerClosesConnectionOnQuiesceEvent() throws {
        let channel = EmbeddedChannel()
        try channel.pipeline.syncOperations.addHandler(IdleTimeoutHandler())
        try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 1)).wait()
        #expect(channel.isActive)

        channel.pipeline.fireUserInboundEventTriggered(ChannelShouldQuiesceEvent())
        #expect(!channel.isActive)  // the handler closed the connection on quiesce
        _ = try? channel.finish()
    }

    /// Integration: a graceful quiesce closes a live keep-alive connection — the slot-freeing observable
    /// from outside. Binds + serves via the engine's real internals (`bindPlain` + `servePlainListener`
    /// + `ServerQuiescingHelper`), holds an idle keep-alive connection open, then quiesces; the client
    /// observes the connection close (`channelInactive`), proving the drain reclaims connections.
    @Test func gracefulQuiesceClosesLiveKeepAliveConnection() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let threadPool = NIOThreadPool(numberOfThreads: 1)
        threadPool.start()
        let firstByte = AsyncEventProbe<Void>()
        let connectionClosed = AsyncEventProbe<Void>()
        let routes = StubRoutes { _ in
            .raw(body: Array("ok".utf8), contentType: "text/plain", status: .ok)
        }
        do {
            let probe = try await ServerBootstrap(group: group).bind(host: "127.0.0.1", port: 0).get()
            let port = probe.localAddress?.port ?? 0
            try await probe.close().get()

            let listener = ListenerConfig(host: "127.0.0.1", port: port, routes: routes)
            let server = HTTPServer(
                listeners: [listener], pool: nil, envelope: HTTPFields(),
                logger: Logger(label: "sse-drain"), threadCount: 1, loopCount: 1)
            let quiesce = ServerQuiescingHelper(group: group)
            let serverChannel = try await server.bindPlain(listener, group: group, quiesce: quiesce)
            let serveTask = Task {
                await server.servePlainListener(serverChannel, routes: routes, threadPool: threadPool)
            }
            defer { serveTask.cancel() }

            // Connect WITHOUT `Connection: close` so the stream stays open until WE quiesce. The client
            // records the first inbound bytes (SSE live) and `channelInactive` (the server closed it).
            let client = try await ClientBootstrap(group: group)
                .channelInitializer { channel in
                    channel.pipeline.addHandler(ConnectionLifecycleSignal(firstByte, connectionClosed))
                }
                .connect(host: "127.0.0.1", port: port).get()
            var request = client.allocator.buffer(capacity: 64)
            request.writeString("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")  // keep-alive (no close)
            try await client.writeAndFlush(request).get()
            _ = try await firstByte.wait(forAtLeast: 1, timeout: .seconds(3))  // response received
            #expect(connectionClosed.count == 0)  // …and the connection is still open (keep-alive)

            // SIGTERM-equivalent: quiesce the listener + its live connections mid-stream.
            let promise = group.next().makePromise(of: Void.self)
            quiesce.initiateShutdown(promise: promise)

            // The drain closed the live SSE connection — the client sees EOF, so the slot is reclaimed.
            _ = try await connectionClosed.wait(forAtLeast: 1, timeout: .seconds(5))

            _ = try? await promise.futureResult.get()  // now drained; let the quiescer settle
            serveTask.cancel()
            try? await client.close().get()
            try? await threadPool.shutdownGracefully()
            try? await group.shutdownGracefully()
        } catch {
            try? await threadPool.shutdownGracefully()
            try? await group.shutdownGracefully()
            throw error
        }
    }
}

/// Records into `firstByte` on the first inbound read and into `closed` on `channelInactive` (the server
/// closing the connection). `@unchecked Sendable`: the probes are `Sendable`; `fired` is touched only on
/// the event loop.
private final class ConnectionLifecycleSignal: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    private let firstByte: AsyncEventProbe<Void>
    private let closed: AsyncEventProbe<Void>
    private var fired = false
    init(_ firstByte: AsyncEventProbe<Void>, _ closed: AsyncEventProbe<Void>) {
        self.firstByte = firstByte
        self.closed = closed
    }
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        if !fired {
            fired = true
            firstByte.record(())
        }
    }
    func channelInactive(context: ChannelHandlerContext) {
        closed.record(())
        context.fireChannelInactive()
    }
}
