// WebSockets (RFC 6455) over apple/swift-nio's `NIOWebSocket`: the HTTP/1 Upgrade is wired into the
// bootstrap (see HTTPServerBootstrap), a matched `WebSocketRoute`'s handler runs the upgraded channel,
// and the handler talks to the peer through `WebSocketConnection` — send text/binary/ping/close + an
// `AsyncStream` of inbound messages (control frames are handled by the engine: ping → auto-pong, close →
// clean shutdown). Fragmented frames are reassembled by `NIOWebSocketFrameAggregator`. permessage-deflate
// is deferred (no apple/swift-server library; in-house later). The DSL adds `WS("/path") { conn in … }`.

import HTTPTypes
import NIOConcurrencyHelpers
import NIOCore
import NIOWebSocket

// MARK: - Public surface

/// One WebSocket message — a complete (reassembled) text or binary payload. Control frames never appear.
public enum WebSocketMessage: Sendable, Equatable {
    case text(String)
    case binary([UInt8])
}

/// A WebSocket close code (RFC 6455 §7.4). Maps to the wire `uint16`; the common presets are provided.
public struct WebSocketCloseCode: Sendable, Equatable {
    public let code: UInt16
    public init(_ code: UInt16) { self.code = code }
    public static let normalClosure = WebSocketCloseCode(1000)
    public static let goingAway = WebSocketCloseCode(1001)
    public static let protocolError = WebSocketCloseCode(1002)
    public static let unsupportedData = WebSocketCloseCode(1003)
    public static let policyViolation = WebSocketCloseCode(1008)
    public static let messageTooBig = WebSocketCloseCode(1009)
    public static let internalServerError = WebSocketCloseCode(1011)
}

/// The handler's view of an upgraded WebSocket: an `AsyncStream` of inbound messages plus send/close. All
/// methods are safe to call from any task; sends are serialized so the engine heartbeat-pong and the
/// handler never write a frame concurrently.
public protocol WebSocketConnection: Sendable {
    /// Inbound text/binary messages; the stream ENDS when the peer closes, the connection drops, or the
    /// server quiesces — so `for await message in conn.messages { … }` is the natural serve loop.
    var messages: AsyncStream<WebSocketMessage> { get }
    func send(_ message: WebSocketMessage) async throws
    func sendText(_ text: String) async throws
    func sendBinary(_ bytes: [UInt8]) async throws
    /// Send a ping (the peer should pong; the engine auto-pongs the peer's pings).
    func ping(_ data: [UInt8]) async throws
    /// Send a close frame with `code`, then let the connection wind down.
    func close(code: WebSocketCloseCode) async throws
}

extension WebSocketConnection {
    public func sendText(_ text: String) async throws { try await send(.text(text)) }
    public func sendBinary(_ bytes: [UInt8]) async throws { try await send(.binary(bytes)) }
}

/// The handler for an upgraded WebSocket route: it owns the connection until it returns (or the peer
/// closes). A typical body is `for await message in conn.messages { try await conn.send(...) }`.
public typealias WebSocketHandler = @Sendable (any WebSocketConnection) async -> Void

/// A matched WebSocket route — the engine upgrades the request and runs `handler`. The DSL's `WS(_:)`
/// lowers to this; `HTTPHandling.webSocketRoute(path:)` resolves it for the upgrade decision.
public struct WebSocketRoute: Sendable {
    public let handler: WebSocketHandler
    public init(handler: @escaping WebSocketHandler) { self.handler = handler }
}

extension HTTPHandling {
    /// The WebSocket route for `path` (a `GET` carrying the `Upgrade: websocket` headers), or `nil` if the
    /// path is not a WebSocket endpoint. The engine calls this in the upgrader's `shouldUpgrade`. Resolves
    /// generically: a `GET` match whose `MatchedRoute` carries a `webSocketHandler`.
    public func webSocketRoute(path: Substring) -> WebSocketRoute? {
        guard case .matched(let route) = match(method: .get, path: path),
            let handler = route.webSocketHandler
        else { return nil }
        return WebSocketRoute(handler: handler)
    }
}

// MARK: - Engine implementation

/// The NIOAsyncChannel of an upgraded WebSocket: inbound reassembled frames, outbound frames.
typealias WebSocketChannel = NIOAsyncChannel<WebSocketFrame, WebSocketFrame>

/// The engine's `WebSocketConnection`: frames out through a FIFO-gated writer (so the inbound auto-pong
/// and the handler's sends never race the NIO outbound writer), messages in via the `AsyncStream` the
/// driver feeds. A `final class` so it is shared by reference between the handler task and the reader.
final class EngineWebSocketConnection: WebSocketConnection {
    let messages: AsyncStream<WebSocketMessage>
    private let writer: WebSocketFrameWriter

    init(messages: AsyncStream<WebSocketMessage>, writer: WebSocketFrameWriter) {
        self.messages = messages
        self.writer = writer
    }

    func send(_ message: WebSocketMessage) async throws {
        switch message {
            case .text(let text): try await writer.write(opcode: .text, bytes: Array(text.utf8))
            case .binary(let bytes): try await writer.write(opcode: .binary, bytes: bytes)
        }
    }

    func ping(_ data: [UInt8]) async throws { try await writer.write(opcode: .ping, bytes: data) }

    func close(code: WebSocketCloseCode) async throws { try await writer.writeClose(code: code) }
}

/// Serializes frame writes to the WS outbound through a FIFO gate (the same non-reentrant async mutex the
/// SSE path uses), so concurrent senders never interleave a `outbound.write`. Back-pressure is preserved:
/// the gate is held across the suspending write.
struct WebSocketFrameWriter: Sendable {
    let outbound: NIOAsyncChannelOutboundWriter<WebSocketFrame>
    let allocator: ByteBufferAllocator
    let gate: FIFOAsyncGate

    func write(opcode: WebSocketOpcode, bytes: [UInt8]) async throws {
        var buffer = allocator.buffer(capacity: bytes.count)
        buffer.writeBytes(bytes)
        try await guarded(WebSocketFrame(fin: true, opcode: opcode, data: buffer))
    }

    /// Echo a control-frame payload (used to auto-pong an inbound ping).
    func writeControl(opcode: WebSocketOpcode, data: ByteBuffer) async throws {
        try await guarded(WebSocketFrame(fin: true, opcode: opcode, data: data))
    }

    func writeClose(code: WebSocketCloseCode) async throws {
        var buffer = allocator.buffer(capacity: 2)
        buffer.writeInteger(code.code)
        try await guarded(WebSocketFrame(fin: true, opcode: .connectionClose, data: buffer))
    }

    private func guarded(_ frame: WebSocketFrame) async throws {
        await gate.acquire()
        do {
            try await outbound.write(frame)
        } catch {
            await gate.release()
            throw error
        }
        await gate.release()
    }
}

/// The negotiated outcome of an accepted h1 connection: a normal HTTP connection, or one upgraded to a
/// WebSocket (carrying the channel + the matched route's handler).
enum EngineH1Result: Sendable {
    case http(EngineConnection)
    case webSocket(WebSocketChannel, WebSocketRoute)
}

extension HTTPServer {
    /// Runs an upgraded WebSocket: feeds inbound text/binary into the connection's message stream
    /// (auto-ponging pings, ending cleanly on a close frame), runs the route `handler` concurrently, and
    /// closes when either side finishes. Cancelling the serve task (graceful drain) cancels the inbound
    /// read, which finishes the stream so the handler's `for await` ends — the slot frees promptly.
    func driveWebSocket(_ channel: WebSocketChannel, handler: @escaping WebSocketHandler) async {
        let allocator = channel.channel.allocator
        do {
            try await channel.executeThenClose { inbound, outbound in
                let (stream, continuation) = AsyncStream<WebSocketMessage>.makeStream()
                let writer = WebSocketFrameWriter(
                    outbound: outbound, allocator: allocator, gate: FIFOAsyncGate())
                let connection = EngineWebSocketConnection(messages: stream, writer: writer)
                await withTaskGroup(of: Void.self) { group in
                    group.addTask {
                        await handler(connection)
                        continuation.finish()  // handler returned → stop the message stream
                    }
                    group.addTask {
                        defer { continuation.finish() }  // peer closed / drained → end the stream
                        do {
                            for try await frame in inbound {
                                switch frame.opcode {
                                    case .text:
                                        continuation.yield(.text(String(buffer: frame.unmaskedData)))
                                    case .binary:
                                        var data = frame.unmaskedData
                                        continuation.yield(.binary(data.readBytes(length: data.readableBytes) ?? []))
                                    case .ping:
                                        try? await writer.writeControl(opcode: .pong, data: frame.unmaskedData)
                                    case .connectionClose:
                                        return
                                    default:
                                        break  // pong / continuation / reserved — ignore
                                }
                            }
                        } catch {
                            // Read error (reset / drain cancellation) — finish via `defer`.
                        }
                    }
                    await group.next()  // whichever ends first (handler done OR peer closed)
                    group.cancelAll()
                }
                try? await writer.writeClose(code: .normalClosure)  // best-effort clean close
            }
        } catch {
            // Connection-level error — drop it.
        }
    }
}
