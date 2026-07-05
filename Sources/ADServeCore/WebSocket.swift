// WebSockets (RFC 6455) over the HTTP package's route-scoped seam: a matched route's
// `WebSocketHandler` (the sans-I/O event → actions protocol from the `WebSocket` module) is
// resolved at the request head via `EngineResponder.resolveWebSocket`, the engine completes the
// Upgrade (h1) or Extended CONNECT (h2/h3, RFC 8441/9220) and drives the handler; fragmented
// frames are reassembled and pings auto-ponged by the engine. Server push rides the engine's
// `WebSocketHub`: a hub-bound route auto-subscribes each connection to its topic, and
// `hub.publish(_:to:)` fans a message out to every subscriber. ADServe adds its cross-site
// WebSocket hijacking gate (same-origin or origin-less handshakes only) around every handler.
//
// This replaced the pre-migration connection-owning API (`{ conn in for await message in
// conn.messages … } `): the HTTP package's handler seam is event/action-shaped and its hub is the
// push channel, so ADServe's WS surface follows it (the `WS`/`Channel` DSL keeps its names).

public import ADServeEngineNames
import HTTPCore
public import HTTPServer
public import WebSocket

/// The broadcast hub for WebSocket fan-out — the engine's topic-keyed publish/subscribe actor.
/// A hub-bound route (`Channel(_:on:topic:)`) auto-subscribes each connection on upgrade and
/// unsubscribes it on disconnect; publish with ``WebSocketHub/publish(_:to:)`` or the
/// ``broadcast(_:to:)`` convenience.
public typealias WebSocketHub = HTTPEngineWebSocketHub

/// A complete WebSocket data message — UTF-8 `text` or `binary` bytes (RFC 6455 §5.6).
public typealias WebSocketMessage = WebSocket.WebSocketMessage

/// A WebSocket close code (RFC 6455 §7.4).
public typealias WebSocketCloseCode = WebSocket.WebSocketCloseCode

/// A frame the handler asks the connection to send in response to an event (RFC 6455 §5).
public typealias WebSocketAction = WebSocket.WebSocketAction

/// A connection event surfaced to the handler: `.message`, `.ping`, `.pong`, or `.close`.
public typealias WebSocketEvent = WebSocket.WebSocketConnection.Event

extension WebSocketHub {
    /// Broadcast `text` to every connection subscribed to `topic` — the pre-migration spelling of
    /// ``WebSocketHub/publish(_:to:)``.
    public func broadcast(_ text: String, to topic: String) {
        publish(.text(text), to: topic)
    }
}

/// The Cross-Site WebSocket Hijacking (CSWSH) origin gate — a caseless-enum namespace.
enum WebSocketOrigin {
    /// The CSWSH gate, applied before any socket opens. A browser ALWAYS sends `Origin` on a WebSocket
    /// handshake along with the target site's ambient cookies, so a cross-origin `Origin` means another
    /// site is opening an authenticated socket on the victim's behalf — the WebSocket analogue of CSRF,
    /// which CORS does NOT protect (the upgrade is not a CORS-gated request). Allow the upgrade only when:
    ///   • `Origin` is ABSENT — a non-browser client (CLI, native, server-to-server): no ambient cookies,
    ///     no CSWSH risk; or
    ///   • `Origin`'s authority (host[:port]) equals the request `Host` — a same-origin page.
    /// A present-but-cross-origin or malformed/`null` Origin, or a missing `Host`, is rejected (no
    /// upgrade → the route's plain-GET path answers `426`). Pure + framework-agnostic so it unit-tests
    /// without a live socket. Secure-by-default and zero-config; a future per-route allowlist can widen
    /// it for legitimate cross-origin sockets. No recursion; O(origin length).
    static func isAllowed(origin: String?, host: String?) -> Bool {
        // no Origin → non-browser client, no CSWSH risk
        guard let origin, !origin.isEmpty else { return true }
        // A malformed/`null` Origin (no "://" authority) or a missing `Host` header is rejected.
        guard let host, let schemeEnd = origin.firstRange(of: "://") else { return false }
        return origin[schemeEnd.upperBound...].lowercased() == host.lowercased()
    }
}

/// Wraps a route's WebSocket handler in ADServe's CSWSH gate: the origin/host comparison runs in
/// `shouldUpgrade` (which sees the full request — the engine's `isOriginAllowed(_:)` seam receives
/// only the origin, not the `Host` it must be compared against), so `isOriginAllowed` then admits
/// what the gate already vetted.
struct OriginGatedWebSocketHandler: WebSocketHandler {
    let inner: any WebSocketHandler

    func shouldUpgrade(_ request: HTTPRequest) -> Bool {
        WebSocketOrigin.isAllowed(
            origin: request.headerFields[.origin], host: request.effectiveAuthority)
            && inner.shouldUpgrade(request)
    }

    func isOriginAllowed(_ origin: String?) -> Bool { true }

    func handle(_ event: WebSocketEvent) async -> [WebSocketAction] {
        await inner.handle(event)
    }
}

/// A matched WebSocket endpoint: the handler plus its optional hub binding — what
/// `EngineResponder.resolveWebSocket` hands the engine.
public struct WebSocketEndpoint: Sendable {
    public let handler: any WebSocketHandler
    public let hub: WebSocketHub?
    public let topic: String?

    public init(handler: any WebSocketHandler, hub: WebSocketHub? = nil, topic: String? = nil) {
        self.handler = handler
        self.hub = hub
        self.topic = topic
    }
}

extension HTTPHandling {
    /// The WebSocket endpoint for `path` (a `GET` route carrying a WebSocket handler), or `nil` if
    /// the path is not a WebSocket endpoint. The engine resolves this at the request head to decide
    /// an Upgrade (h1) or Extended CONNECT accept (h2/h3). Resolves generically: a `GET` match whose
    /// `MatchedRoute` carries a `webSocketHandler`.
    public func webSocketEndpoint(path: Substring) -> WebSocketEndpoint? {
        guard case .matched(let route) = match(method: .get, path: path),
            let handler = route.webSocketHandler
        else { return nil }
        return WebSocketEndpoint(
            handler: handler, hub: route.webSocketHub, topic: route.webSocketTopic)
    }
}
