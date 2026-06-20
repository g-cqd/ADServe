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

    /// A masked client→server frame (RFC 6455 requires client frames be masked).
    private func masked(_ opcode: WebSocketOpcode, _ bytes: [UInt8], _ allocator: ByteBufferAllocator)
        -> WebSocketFrame
    {
        var buffer = allocator.buffer(capacity: bytes.count)
        buffer.writeBytes(bytes)
        return WebSocketFrame(fin: true, opcode: opcode, maskKey: .random(), data: buffer)
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
