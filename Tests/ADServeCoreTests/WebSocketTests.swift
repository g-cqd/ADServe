// WebSockets (RFC 6455) over the engine's route-scoped seam: handshake + upgrade, text/binary echo
// through the event→actions handler, engine auto-pong, clean close, fragmented-message reassembly,
// the oversized-frame teardown, the 426 fallback for a plain GET, the CSWSH origin gate (pure + on
// the wire), and the engine's WebSocketHub (register/subscribe/publish fan-out + the hub-bound
// route push path). The client is a raw-socket RFC 6455 implementation (masked frames), so the
// server engine is exercised over the real wire.

import Foundation
import HTTPCore
import HTTPServer
import Logging
import Testing
import WebSocket

@testable import ADServeCore

// MARK: - Client-side frames (RFC 6455 §5: client frames are MASKED)

enum WSClient {
    /// Encodes one client frame (fin/opcode/payload) with a random 4-byte mask.
    static func frame(fin: Bool, opcode: UInt8, payload: [UInt8]) -> [UInt8] {
        var out: [UInt8] = [(fin ? 0x80 : 0x00) | opcode]
        let mask: [UInt8] = [
            UInt8.random(in: .min ... .max), UInt8.random(in: .min ... .max),
            UInt8.random(in: .min ... .max), UInt8.random(in: .min ... .max)
        ]
        if payload.count < 126 {
            out.append(0x80 | UInt8(payload.count))
        } else if payload.count <= 0xFFFF {
            out.append(0x80 | 126)
            out.append(UInt8(payload.count >> 8))
            out.append(UInt8(payload.count & 0xFF))
        } else {
            out.append(0x80 | 127)
            for shift in stride(from: 56, through: 0, by: -8) {
                out.append(UInt8((UInt64(payload.count) >> UInt64(shift)) & 0xFF))
            }
        }
        out.append(contentsOf: mask)
        for (index, byte) in payload.enumerated() { out.append(byte ^ mask[index % 4]) }
        return out
    }

    static func text(_ string: String, fin: Bool = true, continuation: Bool = false) -> [UInt8] {
        frame(fin: fin, opcode: continuation ? 0x0 : 0x1, payload: Array(string.utf8))
    }

    static func binary(_ payload: [UInt8]) -> [UInt8] {
        frame(fin: true, opcode: 0x2, payload: payload)
    }

    static func ping(_ payload: [UInt8] = []) -> [UInt8] {
        frame(fin: true, opcode: 0x9, payload: payload)
    }

    static func close(code: UInt16) -> [UInt8] {
        frame(fin: true, opcode: 0x8, payload: [UInt8(code >> 8), UInt8(code & 0xFF)])
    }

    /// One decoded SERVER frame (server frames are unmasked).
    struct Frame: Equatable {
        let fin: Bool
        let opcode: UInt8
        let payload: [UInt8]
    }

    /// Decodes the FIRST complete server frame in `bytes`, returning it + the bytes it consumed.
    static func decodeFirst(_ bytes: [UInt8]) -> (frame: Frame, consumed: Int)? {
        guard bytes.count >= 2 else { return nil }
        let fin = bytes[0] & 0x80 != 0
        let opcode = bytes[0] & 0x0F
        var length = Int(bytes[1] & 0x7F)
        var cursor = 2
        if length == 126 {
            guard bytes.count >= cursor + 2 else { return nil }
            length = Int(bytes[cursor]) << 8 | Int(bytes[cursor + 1])
            cursor += 2
        } else if length == 127 {
            guard bytes.count >= cursor + 8 else { return nil }
            var wide: UInt64 = 0
            for offset in 0 ..< 8 { wide = wide << 8 | UInt64(bytes[cursor + offset]) }
            length = Int(wide)
            cursor += 8
        }
        guard bytes.count >= cursor + length else { return nil }
        return (
            Frame(fin: fin, opcode: opcode, payload: Array(bytes[cursor ..< cursor + length])),
            cursor + length
        )
    }
}

/// A live upgraded WebSocket client over a `TestSocket`: performs the RFC 6455 §4 handshake and
/// reads/decodes server frames with a bounded buffer.
final class WSSocket: @unchecked Sendable {
    let socket: TestSocket
    private var buffer: [UInt8] = []

    init(socket: TestSocket) {
        self.socket = socket
    }

    /// Connects + upgrades; throws unless the server answers `101 Switching Protocols`.
    static func upgrade(port: Int, path: String = "/ws") throws -> WSSocket {
        let socket = try TestSocket.connect(host: "127.0.0.1", port: port)
        let key = Data((0 ..< 16).map { _ in UInt8.random(in: .min ... .max) }).base64EncodedString()
        try socket.send(
            "GET \(path) HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n"
                + "Connection: Upgrade\r\nSec-WebSocket-Key: \(key)\r\n"
                + "Sec-WebSocket-Version: 13\r\n\r\n")
        // Read the 101 head (ends at CRLF CRLF); anything after it is the first frames.
        var head: [UInt8] = []
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while HTTP1ResponseFraming.headerBoundary(head) == nil, ContinuousClock.now < deadline {
            guard let chunk = socket.readChunk(timeout: .milliseconds(100)) else { continue }
            if chunk.isEmpty { break }
            head.append(contentsOf: chunk)
        }
        guard let boundary = HTTP1ResponseFraming.headerBoundary(head) else {
            throw TLSHarnessError(message: "no upgrade response")
        }
        let headText = String(decoding: head[..<boundary], as: UTF8.self)
        guard headText.hasPrefix("HTTP/1.1 101") else {
            throw TLSHarnessError(message: "upgrade refused: \(headText.prefix(64))")
        }
        let client = WSSocket(socket: socket)
        client.buffer = Array(head[(boundary + 4)...])
        return client
    }

    func send(_ frame: [UInt8]) throws { try socket.send(frame) }

    /// The next complete server frame, or `nil` when `timeout` elapses / the peer closes first.
    func nextFrame(timeout: Duration = .seconds(3)) -> WSClient.Frame? {
        let deadline = ContinuousClock.now.advanced(by: timeout)
        while ContinuousClock.now < deadline {
            if let (frame, consumed) = WSClient.decodeFirst(buffer) {
                buffer.removeFirst(consumed)
                return frame
            }
            guard let chunk = socket.readChunk(timeout: .milliseconds(100)) else { continue }
            if chunk.isEmpty { return nil }  // EOF
            buffer.append(contentsOf: chunk)
        }
        return nil
    }

    /// Whether the server closes the socket within `within`.
    func observeClose(within: Duration) -> Bool { socket.observeClose(within: within) }

    func close() { socket.close() }
}

// MARK: - Routes

/// One WS route at `/ws` handled by `handler` (event → actions); a plain GET gets the 426 fallback.
struct WebSocketStubRoutes: HTTPHandling {
    let handler: any WebSocketHandler
    let hub: WebSocketHub?
    let topic: String?

    init(handler: any WebSocketHandler, hub: WebSocketHub? = nil, topic: String? = nil) {
        self.handler = handler
        self.hub = hub
        self.topic = topic
    }

    var hasWebSocketRoutes: Bool { true }

    func match(method: HTTPMethod, path: Substring) -> RouteMatch {
        guard method == .get, path == "/ws" else { return .notFound }
        return .matched(
            MatchedRoute(
                needsStorage: false, cache: .unset, webSocketHandler: handler, webSocketHub: hub,
                webSocketTopic: topic,
                run: { _ in
                    var headers = HTTPFields()
                    headers.setValue("websocket", for: HTTPFieldName("upgrade")!)
                    headers.setValue("Upgrade", for: HTTPFieldName("connection")!)
                    return .full(
                        body: Array("upgrade required\n".utf8),
                        contentType: "text/plain; charset=utf-8", status: .upgradeRequired,
                        headers: headers)
                }))
    }
}

/// An echo handler: text and binary messages are echoed back verbatim.
struct EchoWebSocketHandler: WebSocketHandler {
    func isOriginAllowed(_ origin: String?) -> Bool { true }  // ADServe's gate wraps this handler
    func handle(_ event: WebSocketEvent) async -> [WebSocketAction] {
        switch event {
            case .message(let opcode, let payload) where opcode == .text:
                return [.sendText(String(decoding: payload, as: UTF8.self))]
            case .message(let opcode, let payload) where opcode == .binary:
                return [.sendBinary(payload)]
            default:
                return []
        }
    }
}

/// Binds a one-route WS server, upgrades a client at `/ws`, runs `body`, tears down.
private func withWebSocketServer<R: Sendable>(
    routes: any HTTPHandling,
    _ body: @escaping @Sendable (WSSocket) throws -> R
) async throws -> R {
    try await Loopback.withServer(routes: routes) { port in
        let client = try WSSocket.upgrade(port: port)
        return try body(client)
    }
}

// MARK: - Live-socket behavior

@Suite struct WebSocketEchoTests {
    @Test func echoesTextAndBinaryAutoPongsAndCloses() async throws {
        try await withWebSocketServer(
            routes: WebSocketStubRoutes(handler: EchoWebSocketHandler())
        ) { ws in
            // Text echo.
            try ws.send(WSClient.text("hello-ws"))
            let echoed = ws.nextFrame()
            #expect(echoed?.opcode == 0x1)
            #expect(echoed.map { String(decoding: $0.payload, as: UTF8.self) } == "hello-ws")
            // Binary echo.
            try ws.send(WSClient.binary([0x01, 0x02, 0x03]))
            let binary = ws.nextFrame()
            #expect(binary?.opcode == 0x2)
            #expect(binary?.payload == [0x01, 0x02, 0x03])
            // The engine auto-pongs a ping (payload echoed).
            try ws.send(WSClient.ping([0xAB]))
            let pong = ws.nextFrame()
            #expect(pong?.opcode == 0xA)
            #expect(pong?.payload == [0xAB])
            // A close is echoed (1000) and the connection winds down.
            try ws.send(WSClient.close(code: 1000))
            let close = ws.nextFrame()
            #expect(close?.opcode == 0x8)
            #expect(close?.payload.prefix(2) == [0x03, 0xE8])  // 1000
        }
    }

    @Test func nonUpgradeGetToWebSocketPathGets426() async throws {
        let response = try await Loopback.run(
            path: "/ws", routes: WebSocketStubRoutes(handler: EchoWebSocketHandler()))
        #expect(response.hasPrefix("HTTP/1.1 426"))
        #expect(response.lowercased().contains("upgrade: websocket"))
    }

    @Test func fragmentedTextMessageIsReassembledBeforeTheHandlerSeesIt() async throws {
        try await withWebSocketServer(
            routes: WebSocketStubRoutes(handler: EchoWebSocketHandler())
        ) { ws in
            // "Hello WS" split across three frames: text(fin:false) + continuation + final.
            try ws.send(WSClient.text("Hel", fin: false))
            try ws.send(WSClient.text("lo ", fin: false, continuation: true))
            try ws.send(WSClient.text("WS", fin: true, continuation: true))
            let echoed = ws.nextFrame()
            #expect(echoed?.opcode == 0x1)
            #expect(echoed.map { String(decoding: $0.payload, as: UTF8.self) } == "Hello WS")
        }
    }

    @Test func aFrameLargerThanTheMaxFrameSizeTearsDownTheConnection() async throws {
        try await withWebSocketServer(
            routes: WebSocketStubRoutes(handler: EchoWebSocketHandler())
        ) { ws in
            // Just over the engine's 1 MiB frame cap → protocol close (1009) / teardown, no echo.
            let oversized = [UInt8](repeating: 0x41, count: (1 << 20) + 1)
            try? ws.send(WSClient.frame(fin: true, opcode: 0x1, payload: oversized))
            if let frame = ws.nextFrame(timeout: .seconds(3)) {
                #expect(frame.opcode == 0x8)  // a Close, never the echoed text
            }
            #expect(ws.observeClose(within: .seconds(3)))
        }
    }

    @Test func hubBoundRoutePushesAPublishedMessageToTheSubscriber() async throws {
        // A Channel-shaped route: the connection auto-subscribes to the hub topic on upgrade; a
        // publish from the server side reaches the client as a text frame.
        let hub = WebSocketHub()
        let routes = WebSocketStubRoutes(handler: EchoWebSocketHandler(), hub: hub, topic: "parts")
        let published: String = try await Loopback.withServer(routes: routes) { port in
            let ws = try WSSocket.upgrade(port: port)
            // Retry-publish until the (actor-hop-away) registration lands, bounded.
            let deadline = ContinuousClock.now.advanced(by: .seconds(3))
            var delivered: WSClient.Frame?
            while delivered == nil, ContinuousClock.now < deadline {
                let gate = DispatchSemaphore(value: 0)
                Task {
                    await hub.publish(.text("part-42"), to: "parts")
                    gate.signal()
                }
                gate.wait()
                delivered = ws.nextFrame(timeout: .milliseconds(200))
            }
            guard let delivered else { throw TLSHarnessError(message: "no hub push arrived") }
            return String(decoding: delivered.payload, as: UTF8.self)
        }
        #expect(published == "part-42")
    }
}

// MARK: - Origin gate (pure + on the wire)

@Suite struct WebSocketOriginGateTests {
    @Test func originlessHandshakeIsAllowed() {
        #expect(WebSocketOrigin.isAllowed(origin: nil, host: "example.com"))
        #expect(WebSocketOrigin.isAllowed(origin: "", host: "example.com"))
    }

    @Test func sameOriginIsAllowed() {
        #expect(WebSocketOrigin.isAllowed(origin: "https://example.com", host: "example.com"))
        #expect(WebSocketOrigin.isAllowed(origin: "https://EXAMPLE.com", host: "example.com"))
        #expect(WebSocketOrigin.isAllowed(origin: "http://app.local:8080", host: "app.local:8080"))
    }

    @Test func crossOriginIsRejected() {
        #expect(!WebSocketOrigin.isAllowed(origin: "https://evil.com", host: "example.com"))
        #expect(!WebSocketOrigin.isAllowed(origin: "https://app.com.evil.com", host: "app.com"))
        #expect(!WebSocketOrigin.isAllowed(origin: "https://app.local:9999", host: "app.local:8080"))
    }

    @Test func malformedOrNullOriginIsRejected() {
        #expect(!WebSocketOrigin.isAllowed(origin: "null", host: "example.com"))
        #expect(!WebSocketOrigin.isAllowed(origin: "example.com", host: "example.com"))  // no scheme
        #expect(!WebSocketOrigin.isAllowed(origin: "https://example.com", host: nil))  // no Host
    }

    @Test func crossOriginUpgradeIsRefusedOnTheWire() async throws {
        // The gate runs engine-side in shouldUpgrade: a cross-origin handshake is not upgraded —
        // the plain-GET fallback answers 426 instead of 101.
        let response = try await Loopback.run(
            path: "/ws", routes: WebSocketStubRoutes(handler: EchoWebSocketHandler()),
            headers: [
                ("Upgrade", "websocket"), ("Connection", "Upgrade"),
                ("Sec-WebSocket-Key", "AAAAAAAAAAAAAAAAAAAAAA=="), ("Sec-WebSocket-Version", "13"),
                ("Origin", "https://evil.example")
            ])
        #expect(!response.hasPrefix("HTTP/1.1 101"))
        #expect(response.hasPrefix("HTTP/1.1 426"))
    }
}

// MARK: - Hub (engine actor)

@Suite struct WebSocketHubTests {
    /// A recording sink: appends every delivered message.
    private final class Recorder: @unchecked Sendable {
        private let lock = NSLock()
        private var received: [WebSocketMessage] = []
        func record(_ message: WebSocketMessage) {
            lock.lock()
            received.append(message)
            lock.unlock()
        }
        var messages: [WebSocketMessage] {
            lock.lock()
            defer { lock.unlock() }
            return received
        }
    }

    @Test func broadcastReachesOnlyTheTopicSubscribers() async {
        let hub = WebSocketHub()
        let parts = Recorder()
        let other = Recorder()
        let partsToken = await hub.register { parts.record($0) }
        let otherToken = await hub.register { other.record($0) }
        await hub.subscribe(partsToken, to: "parts")
        await hub.subscribe(otherToken, to: "other")
        await hub.broadcast("update-1", to: "parts")
        #expect(parts.messages == [.text("update-1")])
        #expect(other.messages.isEmpty)
    }

    @Test func unsubscribeStopsDelivery() async {
        let hub = WebSocketHub()
        let recorder = Recorder()
        let token = await hub.register { recorder.record($0) }
        await hub.subscribe(token, to: "parts")
        await hub.broadcast("one", to: "parts")
        await hub.unsubscribe(token, from: "parts")
        await hub.unsubscribe(token, from: "parts")  // idempotent
        await hub.broadcast("two", to: "parts")
        #expect(recorder.messages == [.text("one")])
        #expect(await hub.subscriberCount(of: "parts") == 0)
    }

    @Test func removeDropsEverySubscription() async {
        let hub = WebSocketHub()
        let recorder = Recorder()
        let token = await hub.register { recorder.record($0) }
        await hub.subscribe(token, to: "a")
        await hub.subscribe(token, to: "b")
        await hub.remove(token)
        await hub.broadcast("gone", to: "a")
        await hub.broadcast("gone", to: "b")
        #expect(recorder.messages.isEmpty)
    }

    @Test func broadcastToUnknownTopicIsANoOp() async {
        let hub = WebSocketHub()
        let recorder = Recorder()
        let token = await hub.register { recorder.record($0) }
        await hub.subscribe(token, to: "parts")
        await hub.broadcast("nothing", to: "nobody-listens")
        #expect(recorder.messages.isEmpty)
    }

    @Test func publishFansOutBinaryToo() async {
        let hub = WebSocketHub()
        let recorder = Recorder()
        let token = await hub.register { recorder.record($0) }
        await hub.subscribe(token, to: "bin")
        await hub.publish(.binary([1, 2, 3]), to: "bin")
        #expect(recorder.messages == [.binary([1, 2, 3])])
    }
}
