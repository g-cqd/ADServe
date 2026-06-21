// M5 WebSockets: an end-to-end echo over the real HTTP/1 Upgrade — text + binary round-trip, a
// client ping is auto-ponged by the engine, and a client close winds the connection down. A non-upgrade
// GET to a WS path gets 426.

import HTTPTypes
import Logging
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOWebSocket
import Testing

@testable import ADServeCore

/// A minimal `HTTPHandling` exposing one `WS` route (so the Core suite tests WebSockets without the DSL).
struct WebSocketStubRoutes: HTTPHandling {
    let path: String
    let handler: WebSocketHandler
    func match(method: HTTPRequest.Method, path: Substring) -> RouteMatch {
        guard method == .get, path == self.path[...] else { return .notFound }
        let wsHandler = handler
        return .matched(
            MatchedRoute(
                needsStorage: false, cache: .unset, webSocketHandler: wsHandler,
                run: { _ in
                    var headers = HTTPFields()
                    headers[HTTPField.Name("upgrade")!] = "websocket"
                    headers[HTTPField.Name("connection")!] = "Upgrade"
                    return .full(
                        body: Array("upgrade required\n".utf8), contentType: "text/plain; charset=utf-8",
                        status: HTTPResponse.Status(code: 426), headers: headers)
                }))
    }
}

@Suite struct WebSocketEchoTests {
    private typealias WSClientChannel = NIOAsyncChannel<WebSocketFrame, WebSocketFrame>

    @Test func echoesTextAndBinaryAutoPongsAndCloses() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        // The server echoes every message back; the engine handles ping/pong + close itself.
        let routes = WebSocketStubRoutes(path: "/ws") { connection in
            for await message in connection.messages {
                try? await connection.send(message)
            }
        }
        do {
            let probe = try await ServerBootstrap(group: group).bind(host: "127.0.0.1", port: 0).get()
            let port = probe.localAddress?.port ?? 0
            try await probe.close().get()
            let readiness = ServerReadiness()
            let server = HTTPServer(
                listeners: [ListenerConfig(host: "127.0.0.1", port: port, routes: routes)], pool: nil,
                envelope: HTTPFields(), logger: .init(label: "ws"), threadCount: 1, loopCount: 1,
                readiness: readiness)
            let serverTask = Task { try? await server.run() }
            defer { serverTask.cancel() }
            var spins = 0
            while !readiness.isReady && spins < 300 {
                try await Task.sleep(for: .milliseconds(10))
                spins += 1
            }

            let wsChannel = try await connect(path: "/ws", port: port, group: group)
            let outcome = try await wsChannel.executeThenClose {
                inbound, outbound -> (text: String?, binary: [UInt8]?, pong: Bool) in
                var iterator = inbound.makeAsyncIterator()
                let allocator = ByteBufferAllocator()

                // Text round-trip.
                try await outbound.write(masked(.text, Array("hello-ws".utf8), allocator))
                let textEcho = try await iterator.next().map { String(buffer: $0.unmaskedData) }

                // Binary round-trip.
                try await outbound.write(masked(.binary, [0x01, 0x02, 0x03], allocator))
                let binaryEcho = try await iterator.next()
                    .map { frame -> [UInt8] in
                        var data = frame.unmaskedData
                        return data.readBytes(length: data.readableBytes) ?? []
                    }

                // Ping → the engine auto-pongs.
                try await outbound.write(masked(.ping, Array("png".utf8), allocator))
                let pong = (try await iterator.next())?.opcode == .pong

                // Close.
                var closeBuffer = allocator.buffer(capacity: 2)
                closeBuffer.writeInteger(UInt16(1000))
                try await outbound.write(
                    WebSocketFrame(fin: true, opcode: .connectionClose, maskKey: .random(), data: closeBuffer))
                return (textEcho, binaryEcho, pong)
            }

            #expect(outcome.text == "hello-ws")
            #expect(outcome.binary == [0x01, 0x02, 0x03])
            #expect(outcome.pong)

            serverTask.cancel()
            try? await group.shutdownGracefully()
        } catch {
            try? await group.shutdownGracefully()
            throw error
        }
    }

    @Test func nonUpgradeGetToWebSocketPathGets426() async throws {
        let routes = WebSocketStubRoutes(path: "/ws") { _ in }
        let response = try await Loopback.run(path: "/ws", routes: routes)
        #expect(response.hasPrefix("HTTP/1.1 426"))
        #expect(response.lowercased().contains("upgrade: websocket"))
    }

    @Test func fragmentedTextMessageIsReassembledBeforeTheHandlerSeesIt() async throws {
        // "Hello WS" sent as three masked fragments — text(fin:false) + continuation(fin:false) +
        // continuation(fin:true). The engine's NIOWebSocketFrameAggregator must reassemble them into one
        // message before `connection.messages` yields it, so the echo is the whole string.
        let echo = try await withEchoServer { wsChannel in
            try await wsChannel.executeThenClose { inbound, outbound -> String? in
                var iterator = inbound.makeAsyncIterator()
                let allocator = ByteBufferAllocator()
                try await outbound.write(frame(.text, Array("Hel".utf8), fin: false, allocator))
                try await outbound.write(frame(.continuation, Array("lo ".utf8), fin: false, allocator))
                try await outbound.write(frame(.continuation, Array("WS".utf8), fin: true, allocator))
                let reassembled = try await iterator.next().map { String(buffer: $0.unmaskedData) }
                try await outbound.write(closeFrame(allocator))
                return reassembled
            }
        }
        #expect(echo == "Hello WS")
    }

    @Test func aFrameLargerThanTheMaxFrameSizeTearsDownTheConnection() async throws {
        // A single frame just over the server's 1 MiB `maxFrameSize` is a protocol violation (a DoS bound):
        // the engine rejects it and closes — it must NOT echo it back.
        let closed = try await withEchoServer { wsChannel in
            try await wsChannel.executeThenClose { inbound, outbound -> Bool in
                var iterator = inbound.makeAsyncIterator()
                let allocator = ByteBufferAllocator()
                let oversized = [UInt8](repeating: 0x41, count: (1 << 20) + 1)
                try? await outbound.write(masked(.text, oversized, allocator))
                do {
                    if let next = try await iterator.next() { return next.opcode == .connectionClose }
                    return true  // channel closed (nil) — torn down, not echoed
                } catch {
                    return true  // read errored — connection torn down
                }
            }
        }
        #expect(closed)
    }

    /// A masked client→server frame (RFC 6455 requires client frames be masked).
    private func masked(_ opcode: WebSocketOpcode, _ bytes: [UInt8], _ allocator: ByteBufferAllocator)
        -> WebSocketFrame
    {
        var buffer = allocator.buffer(capacity: bytes.count)
        buffer.writeBytes(bytes)
        return WebSocketFrame(fin: true, opcode: opcode, maskKey: .random(), data: buffer)
    }

    /// A masked client→server frame with an explicit `fin` (for sending a fragmented message).
    private func frame(
        _ opcode: WebSocketOpcode, _ bytes: [UInt8], fin: Bool, _ allocator: ByteBufferAllocator
    ) -> WebSocketFrame {
        var buffer = allocator.buffer(capacity: bytes.count)
        buffer.writeBytes(bytes)
        return WebSocketFrame(fin: fin, opcode: opcode, maskKey: .random(), data: buffer)
    }

    /// A masked close frame with status 1000 (normal).
    private func closeFrame(_ allocator: ByteBufferAllocator) -> WebSocketFrame {
        var buffer = allocator.buffer(capacity: 2)
        buffer.writeInteger(UInt16(1000))
        return WebSocketFrame(fin: true, opcode: .connectionClose, maskKey: .random(), data: buffer)
    }

    /// Bind a WebSocket echo server on a loopback port, perform the HTTP/1 upgrade, run `body` with the
    /// negotiated frame channel, then tear everything down. Bounded readiness wait; best-effort cleanup.
    private func withEchoServer<R>(_ body: (WSClientChannel) async throws -> R) async throws -> R {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let routes = WebSocketStubRoutes(path: "/ws") { connection in
            for await message in connection.messages { try? await connection.send(message) }
        }
        do {
            let probe = try await ServerBootstrap(group: group).bind(host: "127.0.0.1", port: 0).get()
            let port = probe.localAddress?.port ?? 0
            try await probe.close().get()
            let readiness = ServerReadiness()
            let server = HTTPServer(
                listeners: [ListenerConfig(host: "127.0.0.1", port: port, routes: routes)], pool: nil,
                envelope: HTTPFields(), logger: .init(label: "ws"), threadCount: 1, loopCount: 1,
                readiness: readiness)
            let serverTask = Task { try? await server.run() }
            defer { serverTask.cancel() }
            var spins = 0
            while !readiness.isReady && spins < 300 {
                try await Task.sleep(for: .milliseconds(10))
                spins += 1
            }
            let wsChannel = try await connect(path: "/ws", port: port, group: group)
            let result = try await body(wsChannel)
            serverTask.cancel()
            try? await group.shutdownGracefully()
            return result
        } catch {
            try? await group.shutdownGracefully()
            throw error
        }
    }

    /// Connect + perform the HTTP/1 WebSocket upgrade, returning the negotiated frame channel.
    private func connect(path: String, port: Int, group: MultiThreadedEventLoopGroup) async throws
        -> WSClientChannel
    {
        let promise = group.next().makePromise(of: WSClientChannel.self)
        let upgrader = NIOTypedWebSocketClientUpgrader<WSClientChannel>(
            upgradePipelineHandler: { channel, _ in
                channel.eventLoop.makeCompletedFuture { try WSClientChannel(wrappingChannelSynchronously: channel) }
            })
        var requestHead = HTTPRequestHead(version: .http1_1, method: .GET, uri: path)
        requestHead.headers.add(name: "Host", value: "127.0.0.1:\(port)")
        let configuration = NIOUpgradableHTTPClientPipelineConfiguration<WSClientChannel>(
            upgradeConfiguration: NIOTypedHTTPClientUpgradeConfiguration(
                upgradeRequestHead: requestHead, upgraders: [upgrader],
                notUpgradingCompletionHandler: { channel in
                    channel.close(promise: nil)
                    return channel.eventLoop.makeFailedFuture(TLSHarnessError("server did not upgrade"))
                }))
        _ = try await ClientBootstrap(group: group)
            .channelInitializer { channel in
                do {
                    let negotiation = try channel.pipeline.syncOperations
                        .configureUpgradableHTTPClientPipeline(configuration: configuration)
                    negotiation.cascade(to: promise)
                    return channel.eventLoop.makeSucceededVoidFuture()
                } catch {
                    promise.fail(error)
                    return channel.eventLoop.makeFailedFuture(error)
                }
            }
            .connect(host: "127.0.0.1", port: port).get()
        return try await promise.futureResult.get()
    }
}

/// The CSWSH gate (`webSocketOriginAllowed`) applied in the upgrader's `shouldUpgrade`: same-origin or
/// originless handshakes upgrade; a cross-origin / malformed Origin is rejected before any socket opens.
@Suite struct WebSocketOriginGateTests {
    @Test func originlessHandshakeIsAllowed() {
        // A non-browser client (CLI/native) sends no Origin → no ambient cookies → no CSWSH risk.
        #expect(webSocketOriginAllowed(origin: nil, host: "app.com"))
        #expect(webSocketOriginAllowed(origin: "", host: "app.com"))
    }

    @Test func sameOriginIsAllowed() {
        #expect(webSocketOriginAllowed(origin: "https://app.com", host: "app.com"))
        #expect(webSocketOriginAllowed(origin: "http://app.com:8080", host: "app.com:8080"))
        #expect(webSocketOriginAllowed(origin: "https://APP.com", host: "app.com"))  // case-insensitive host
    }

    @Test func crossOriginIsRejected() {
        #expect(!webSocketOriginAllowed(origin: "https://evil.com", host: "app.com"))  // the CSWSH attempt
        #expect(!webSocketOriginAllowed(origin: "https://app.com.evil.com", host: "app.com"))  // suffix trick
        #expect(!webSocketOriginAllowed(origin: "https://app.com:9999", host: "app.com:8080"))  // port mismatch
    }

    @Test func malformedOrNullOriginIsRejected() {
        #expect(!webSocketOriginAllowed(origin: "null", host: "app.com"))  // sandboxed iframe / file://
        #expect(!webSocketOriginAllowed(origin: "app.com", host: "app.com"))  // no scheme → malformed
        #expect(!webSocketOriginAllowed(origin: "https://app.com", host: nil))  // missing Host → reject
    }
}

/// `WebSocketHub` — the topic-keyed broadcast actor. A recording mock connection captures sent text; a
/// failing mock proves a dropped peer never blocks the rest of the fan-out.
@Suite struct WebSocketHubTests {
    private actor RecordingConn: WebSocketConnection {
        private(set) var sent: [String] = []
        nonisolated var messages: AsyncStream<WebSocketMessage> { AsyncStream { $0.finish() } }
        func send(_ message: WebSocketMessage) async throws {
            if case .text(let text) = message { sent.append(text) }
        }
        func ping(_ data: [UInt8]) async throws {}
        func close(code: WebSocketCloseCode) async throws {}
    }

    private actor FailingConn: WebSocketConnection {
        struct Dropped: Error {}
        nonisolated var messages: AsyncStream<WebSocketMessage> { AsyncStream { $0.finish() } }
        func send(_ message: WebSocketMessage) async throws { throw Dropped() }
        func ping(_ data: [UInt8]) async throws {}
        func close(code: WebSocketCloseCode) async throws {}
    }

    @Test func broadcastReachesOnlyTheTopicSubscribers() async {
        let hub = WebSocketHub()
        let a = RecordingConn()
        let b = RecordingConn()
        let other = RecordingConn()
        _ = await hub.subscribe("parts", a)
        _ = await hub.subscribe("parts", b)
        _ = await hub.subscribe("orders", other)
        #expect(await hub.subscriberCount("parts") == 2)

        await hub.broadcast(#"{"id":1}"#, to: "parts")
        #expect(await a.sent == [#"{"id":1}"#])
        #expect(await b.sent == [#"{"id":1}"#])
        #expect(await other.sent.isEmpty)  // a different topic never receives
    }

    @Test func unsubscribeStopsDelivery() async {
        let hub = WebSocketHub()
        let a = RecordingConn()
        let b = RecordingConn()
        let tokenA = await hub.subscribe("parts", a)
        _ = await hub.subscribe("parts", b)

        await hub.unsubscribe(tokenA, from: "parts")
        #expect(await hub.subscriberCount("parts") == 1)
        await hub.broadcast("x", to: "parts")
        #expect(await a.sent.isEmpty)  // unsubscribed before the broadcast
        #expect(await b.sent == ["x"])
        // Idempotent + drops the topic when empty.
        await hub.unsubscribe(tokenA, from: "parts")  // no-op, no trap
    }

    @Test func broadcastIsFailureIsolated() async {
        let hub = WebSocketHub()
        let good = RecordingConn()
        _ = await hub.subscribe("t", FailingConn())  // throws on send
        _ = await hub.subscribe("t", good)
        await hub.broadcast("payload", to: "t")
        #expect(await good.sent == ["payload"])  // the failing peer did not block this one
    }

    @Test func broadcastToUnknownTopicIsANoOp() async {
        let hub = WebSocketHub()
        await hub.broadcast("nobody-home", to: "ghost")  // must not trap
        #expect(await hub.subscriberCount("ghost") == 0)
    }

    @Test func broadcastPrunesAConnectionThatFailedToSend() async {
        let hub = WebSocketHub()
        let good = RecordingConn()
        _ = await hub.subscribe("t", FailingConn())  // a half-open / dropped peer: send throws
        _ = await hub.subscribe("t", good)
        #expect(await hub.subscriberCount("t") == 2)

        await hub.broadcast("x", to: "t")
        #expect(await good.sent == ["x"])  // the live peer received it…
        #expect(await hub.subscriberCount("t") == 1)  // …and the dead peer was pruned on its failed send

        await hub.broadcast("y", to: "t")  // a later broadcast no longer re-attempts the doomed send
        #expect(await good.sent == ["x", "y"])
        #expect(await hub.subscriberCount("t") == 1)
    }
}
