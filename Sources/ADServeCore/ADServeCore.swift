// ADServeCore — the ad-server ENGINE. The optimizable server layer:
// the value types a request/response flows through, the connection pool, the
// hashing/request-id helpers, and the routing contract the DSL satisfies. The engine
// bootstrap + the response-writing envelope live in HTTPServer.swift. Headers, method,
// and status are the HTTP package's `HTTPCore` value types throughout — no stringly
// tuples. The engine knows nothing route-specific.

public import ADConcurrency
import ADJSON
import Crypto
import Foundation
public import HTTPCore
public import HTTPServer
public import Logging
import Synchronization
public import WebSocket

#if canImport(UniformTypeIdentifiers)
    public import UniformTypeIdentifiers
#endif

// MARK: - Wire (per-listener transport: HTTP version(s) × TLS)

/// An ALPN-negotiable application protocol. The raw value is the ALPN identifier the TLS
/// handshake advertises/selects.
public enum ALPN: String, Sendable {
    case http1 = "http/1.1"
    case http2 = "h2"
    /// HTTP/3 (QUIC) — the HTTP package serves it via its QUIC transport (Darwin-only today);
    /// not yet wired through the ADServe listener surface. A harmless ALPN id otherwise.
    case http3 = "h3"
}

/// Whether the server requires (and verifies) a client certificate — the mTLS toggle. `.none` is the
/// default one-way TLS; `.required` makes the transport reject the handshake unless the client
/// presents a certificate (mutual TLS). See `verifyPeer` on the transport seam for chain policy.
public enum ClientCertificateVerification: Sendable {
    case none
    case required
}

/// TLS material: a PEM certificate chain + private key on disk, plus optional mutual-TLS
/// settings (require a client certificate). The engine converts the PEM pair into the PKCS#12
/// identity the HTTP transport consumes at bind time (via the system `openssl`, the same
/// pragmatic path the HTTP package's own `DevTLSIdentity` uses — native PEM intake in
/// `TransportTLS` is a recorded upstream gap).
public struct TLSSource: Sendable {
    public let certificatePath: String
    public let privateKeyPath: String
    /// Client-certificate policy (mTLS). `.none` = one-way TLS.
    public let clientVerification: ClientCertificateVerification
    /// A PEM trust-root (CA) file the client certificate must chain to when `clientVerification` is
    /// `.required`; `nil` falls back to the system trust store.
    public let trustRootsPath: String?

    public init(
        certificatePath: String, privateKeyPath: String,
        clientVerification: ClientCertificateVerification = .none, trustRootsPath: String? = nil
    ) {
        self.certificatePath = certificatePath
        self.privateKeyPath = privateKeyPath
        self.clientVerification = clientVerification
        self.trustRootsPath = trustRootsPath
    }

    /// A PEM certificate-chain file + PEM private-key file (one-way TLS unless `clientVerification` is set).
    public static func pem(
        certificate: String, privateKey: String,
        clientVerification: ClientCertificateVerification = .none, trustRoots: String? = nil
    ) -> TLSSource {
        TLSSource(
            certificatePath: certificate, privateKeyPath: privateKey,
            clientVerification: clientVerification, trustRootsPath: trustRoots)
    }
}

/// A listener's wire protocol — the ALPN-offered HTTP version(s) × optional TLS. `tls == nil`
/// is plaintext. Shaped to admit `.http3` later with no surface churn.
public struct Wire: Sendable {
    public let alpn: [ALPN]
    public let tls: TLSSource?

    public init(alpn: [ALPN], tls: TLSSource?) {
        self.alpn = alpn
        self.tls = tls
    }

    /// Plaintext HTTP/1.1 (the loopback-behind-Caddy default).
    public static let http1 = Wire(alpn: [.http1], tls: nil)
    /// TLS 1.3 with ALPN (h2 + http/1.1 by default; pass `alpn:` to constrain, e.g. `[.http1]`).
    public static func https(_ tls: TLSSource, alpn: [ALPN] = [.http2, .http1]) -> Wire {
        Wire(alpn: alpn, tls: tls)
    }
}

// MARK: - Configuration

/// One bound listener: a host/port, its `Wire` (HTTP version(s) × TLS), and the route table
/// the engine dispatches against for it. The connection pool + response envelope are
/// engine-wide (shared across listeners — the central shared pool), so they go to
/// `HTTPServer`, not here.
public struct ListenerConfig: Sendable {
    public let host: String
    public let port: Int
    /// When non-nil, the listener binds a UNIX-domain socket at this path instead of `host:port` — for
    /// a behind-proxy deploy where the proxy (Caddy/nginx) talks to the app over a local socket (no TCP
    /// port, filesystem-permission access control). The existing socket file is replaced on bind.
    public let unixDomainSocketPath: String?
    public let wire: Wire
    public let routes: any HTTPHandling

    public init(
        host: String = "127.0.0.1", port: Int, wire: Wire = .http1, routes: any HTTPHandling
    ) {
        self.host = host
        self.port = port
        self.unixDomainSocketPath = nil
        self.wire = wire
        self.routes = routes
    }

    /// Bind a UNIX-domain socket at `path` (plaintext by default; pass a `wire` for TLS over the socket).
    public init(unixDomainSocketPath path: String, wire: Wire = .http1, routes: any HTTPHandling) {
        self.host = ""
        self.port = 0
        self.unixDomainSocketPath = path
        self.wire = wire
        self.routes = routes
    }

    /// A human label for logs: the socket path, or `host:port`.
    public var addressDescription: String {
        unixDomainSocketPath ?? "\(host):\(port)"
    }
}

/// A lock-free readiness flag — `true` once the server is serving, `false` while draining. The app
/// shares one instance between the engine (which flips it across the lifecycle) and the `/readyz`
/// route (which fails fast while draining, so orchestrators stop new traffic). A lock-free `Atomic`,
/// not a `Mutex`: the flag is read on the `/readyz` hot path and carries no associated state, so a
/// release/acquire pair is both correct and cheaper than taking a lock.
public final class ServerReadiness: Sendable {
    private let ready = Atomic<Bool>(false)
    public init() {}
    public var isReady: Bool { ready.load(ordering: .acquiring) }
    public func set(_ value: Bool) { ready.store(value, ordering: .releasing) }
}

/// The network transport the engine binds on. `.posix` = the HTTP package's event-driven BSD-socket
/// backbone (kqueue on Darwin, epoll on Linux) — cross-platform, the plaintext default. `.network` =
/// Network.framework (Apple-native), where TLS + ALPN + the QUIC/HTTP-3 path live; a TLS listener
/// always binds `.network` regardless of this setting (the POSIX backbones are cleartext).
public enum EngineTransport: String, Sendable {
    case posix
    case network
    /// The pre-migration name for the cross-platform BSD-socket transport — now the HTTP package's
    /// kqueue/epoll backbone, not SwiftNIO.
    @available(*, deprecated, renamed: "posix")
    public static var nio: EngineTransport { .posix }
}

// MARK: - Connection pool (type-erased)

/// A type-erased, scoped connection pool the engine offloads `.storage` routes through.
///
/// The engine is **persistence-agnostic**: it holds an `AnyConnectionPool`, not a
/// `ResourcePool<Conn>`, so ADServeCore depends on no storage package — a non-storage
/// server simply has no pool (`nil`). The application builds one from a concrete
/// `ADConcurrency.ResourcePool<Conn>` at its composition root, pinning the resource type there.
///
/// `withLease` brackets a checkout/checkin around the handler so the noncopyable lease's
/// scope-exit auto-return is preserved across the type-erased boundary (the resource is checked in
/// when `body` returns). The handler reaches the resource via the `any PooledResource` on
/// `HandlerInput.connection` and down-casts to its concrete type (the app's invariant: the pool
/// holds exactly that type).
public struct AnyConnectionPool: Sendable {
    private let _withLease: @Sendable (_ body: @Sendable (any PooledResource) -> ResponseContent) -> ResponseContent?

    /// `lease` must check a resource out, pass it to `body`, and check it back in when `body`
    /// returns — returning `nil` only when the pool is momentarily drained. A `ResourcePool`
    /// lease does exactly this (`pool.lease()` + the noncopyable `ResourceLease`).
    public init(
        _ lease:
            @escaping @Sendable (
                _ body: @Sendable (any PooledResource) -> ResponseContent
            ) -> ResponseContent?
    ) {
        self._withLease = lease
    }

    /// Run `body` with a checked-out resource; `nil` if the pool was momentarily drained.
    public func withLease(
        _ body: @Sendable (any PooledResource) -> ResponseContent
    ) -> ResponseContent? {
        _withLease(body)
    }
}

// MARK: - Request / response value types

/// The request as the DSL/app see it — pure `HTTPCore` value types, no transport leakage.
public struct ServerRequest: Sendable {
    public let method: HTTPMethod
    /// The request target (path + optional `?query`), i.e. the `:path` pseudo-header.
    public let target: String
    public let headers: HTTPFields
    /// The accumulated request body (empty for GET; capped by the engine). Reach via `ctx.body`.
    public let body: [UInt8]

    public init(method: HTTPMethod, target: String, headers: HTTPFields, body: [UInt8] = []) {
        self.method = method
        self.target = target
        self.headers = headers
        self.body = body
    }

    /// The path with any `?query` stripped.
    public var path: Substring { target.prefix { $0 != "?" } }

    /// The percent-decoded query parameters (`?k=v&…`; last value wins; bare `?k` → `""`). Empty if
    /// the target has no `?`. Recomputed per access — bind it once in a handler if used repeatedly.
    public var query: [String: String] { parseQueryString(target) }

    /// A single percent-decoded query parameter by name, or `nil` if absent.
    public func query(_ key: String) -> String? { query[key] }
}

/// A back-pressured sink for a streamed response body. The engine hands a route's `.stream` body
/// closure a writer backed by the connection's outbound channel; `write` suspends while the channel
/// is not writable (the back-pressure point), so a slow client throttles the producer and peak memory
/// stays bounded. Reference-semantic + `Sendable`, NOT an `inout`/`mutating` sink — exclusive access
/// to an `inout` cannot be held across an `await`; the writer owns its channel handle by value and its
/// methods are non-mutating. This matches ADHTML's `AsyncHTMLByteSink.write(_:)` (`[UInt8]`, not a
/// slice) 1:1, so the gated `ADHTMLNIO` bridge is a direct forwarder.
public protocol ResponseBodyWriter: Sendable {
    /// Append a chunk of already-rendered bytes, suspending for channel back-pressure as needed.
    func write(_ bytes: [UInt8]) async throws
    /// Drain anything buffered. A no-op on the channel writer (each `write` flushes), present so a
    /// buffering sink has a flush point.
    func flush() async throws
}

/// RFC-0019 C4's name for the public, back-pressured `.stream` body seam that `ADHTMLNIO` adapts its
/// `AsyncHTMLByteSink` onto. ADServe ships the contract as `ResponseBodyWriter` (whose `write(_: [UInt8])`
/// matches the sink 1:1 — see above); this alias exposes it under the name the RFC + ADHTML reference.
public typealias ResponseStreamWriter = ResponseBodyWriter

/// A sink for Server-Sent Events (`text/event-stream`). The engine hands a route's `.sse` body closure
/// a writer over the connection; each `send`/`comment` frames + flushes one event immediately (so a
/// heartbeat reaches the client at once) and suspends for back-pressure. Reference-semantic +
/// `Sendable` (the same rationale as `ResponseBodyWriter`: an `inout` cannot cross an `await`). The
/// engine frames per the WHATWG spec — multi-line `data` becomes one `data:` line each; `event`/`id`
/// are forced single-line so a stray newline cannot inject a second event.
public protocol SSEWriter: Sendable {
    /// Send one event: optional `event:`/`id:`/`retry:` fields + one or more `data:` lines, then the
    /// terminating blank line. `data`'s embedded newlines are split into multiple `data:` lines.
    func send(event: String?, data: String, id: String?, retry: Int?) async throws
    /// A `: comment` line — the SSE keep-alive heartbeat (no event is dispatched to the client).
    func comment(_ text: String) async throws
}

extension SSEWriter {
    /// Convenience: send `data` with an optional `event`/`id` (no `retry`).
    public func send(_ data: String, event: String? = nil, id: String? = nil) async throws {
        try await send(event: event, data: data, id: id, retry: nil)
    }
}

/// What a handler returns. The cross-cutting envelope (security set, Link, Vary,
/// request-id) + cache-control/ETag are applied by the engine, not here.
public enum ResponseContent: Sendable {
    /// A body with an explicit content-type + status.
    case raw(body: [UInt8], contentType: String, status: HTTPStatus)
    /// 404 with the body `Not Found` (a route-level miss — distinct from the engine's
    /// own unmatched-path 404, which is `not found\n`).
    case notFound
    /// A `text/plain` status response (405, the engine's 404, a 503 fallback, …).
    case plain(HTTPStatus, String)
    /// A body + explicit status + EXTRA response headers, applied OVER the envelope (they
    /// can override an envelope header). For routes that need their own header set — the
    /// CORS + MCP header set on `POST /mcp` / `OPTIONS /mcp`.
    case full(body: [UInt8], contentType: String, status: HTTPStatus, headers: HTTPFields)
    /// A streamed response: an early head (NO `Content-Length`/ETag — the length is unknown, so h1 is
    /// chunked and h2 is length-less) followed by writer-driven body chunks. The engine drives `body`
    /// AFTER the head is on the wire, so `<head>` flushes before the body completes (TTFB); back-pressure
    /// is implicit in each `writer.write`. A mid-stream throw tears the connection — the client sees a
    /// truncated, unterminated body, never a clean `end` implying success.
    case stream(
        contentType: String, status: HTTPStatus = .ok, headers: HTTPFields = HTTPFields(),
        body: @Sendable (any ResponseBodyWriter) async throws -> Void)
    /// A long-lived Server-Sent Events stream (`text/event-stream`, `Cache-Control: no-store`, status
    /// 200). The engine frames events, caps concurrency (503 past the limit), heartbeat-friendly
    /// idle handling, and cancels `body` the instant the peer disconnects or the server quiesces — so
    /// the slot frees promptly. `body` typically loops an app change-feed until cancelled. When
    /// `heartbeat` is non-nil the engine emits a `: ` keep-alive comment every interval (serialized
    /// against the body's writes), so an idle stream stays alive without the app heartbeating itself;
    /// the default (`nil`) keeps the app-driven heartbeat valid and adds zero overhead.
    case sse(
        headers: HTTPFields = HTTPFields(), heartbeat: Duration? = nil,
        body: @Sendable (any SSEWriter) async throws -> Void)
    /// A guarded static file served from `root` + `subpath`. The engine resolves it OFF the event loop
    /// (NIOFileSystem): 404 if missing / not a regular file / a symlink / outside the canonicalized root
    /// jail; otherwise a strong size+mtime `ETag` with `If-None-Match` → 304, and the body streamed in
    /// chunks. The DSL `Static(_:root:)` validates the subpath (no dotfiles; an allow-listed extension →
    /// `contentType`) and produces this; `headers` carries any response-middleware decoration.
    case file(root: String, subpath: String, contentType: String, headers: HTTPFields = HTTPFields())

    /// JSON body. Defaults to Bun's `Response.json` content-type; pass `contentType`
    /// to override (e.g. `/search` emits `application/json` with no charset).
    public static func json(_ bytes: [UInt8], contentType: String = "application/json;charset=utf-8")
        -> ResponseContent
    {
        .raw(body: bytes, contentType: contentType, status: .ok)
    }

    /// A text body with an explicit content-type.
    public static func text(_ bytes: [UInt8], contentType: String) -> ResponseContent {
        .raw(body: bytes, contentType: contentType, status: .ok)
    }

    /// JSON body with a typed media type (the type-safe output-format path).
    public static func json(_ bytes: [UInt8], as type: MediaType) -> ResponseContent {
        .raw(body: bytes, contentType: type.value, status: .ok)
    }

    /// A body with a typed media type.
    public static func text(_ bytes: [UInt8], as type: MediaType) -> ResponseContent {
        .raw(body: bytes, contentType: type.value, status: .ok)
    }

    /// An HTML body (`text/html; charset=utf-8`) — the typed path for server-rendered pages and
    /// fragments. `status` defaults to `200` but is overridable (a `404` fragment, a `422` form
    /// re-render). The host transports the bytes; it stays view-agnostic (ADR-0012).
    public static func html(_ bytes: [UInt8], status: HTTPStatus = .ok) -> ResponseContent {
        .raw(body: bytes, contentType: MediaType.html.value, status: status)
    }

    /// A hypermedia FRAGMENT (RFC-0019 C2): a `text/html; charset=utf-8` PARTIAL (no doctype/`<html>`)
    /// the ADHTML runtime morphs into a target region. Wire-identical to `.html` — the distinction is
    /// intent (the caller renders a partial, not a whole document) — so the engine's ETag/304 + envelope
    /// apply unchanged. Pair with `ctx.isFragment` to serve one route two ways: full page on first load,
    /// fragment on a client action.
    public static func fragment(_ bytes: [UInt8], status: HTTPStatus = .ok) -> ResponseContent {
        .raw(body: bytes, contentType: MediaType.html.value, status: status)
    }
}

/// Type-safe output format — the response content-type as a value, not a raw string.
/// Built from an Apple `UTType` (the type-safe, Apple-native path) where that suffices;
/// the apple-docs presets are explicit strings because `UTType.preferredMIMEType` carries
/// no charset and the surface uses inconsistent charset spacing + non-registered forms
/// (`application/opensearchdescription+xml`, `application/linkset+json`).
public struct MediaType: Sendable {
    public let value: String
    private init(value: String) { self.value = value }

    /// `;charset=utf-8` vs `; charset=utf-8` — the apple-docs surface uses both spellings.
    public enum Charset: Sendable {
        case utf8, utf8Spaced
        fileprivate var suffix: String { self == .utf8 ? ";charset=utf-8" : "; charset=utf-8" }
    }

    #if canImport(UniformTypeIdentifiers)
        /// From an Apple `UTType` (+ optional charset) — the type-safe, Apple-native constructor. Only a
        /// convenience: `UTType` is Apple-only (absent on Linux, ADServe's primary target), carries no
        /// charset, and can't express `text/event-stream`/`application/problem+json`/`…+json`, so the
        /// authoritative source is the generated mime-db table below — not `UTType`.
        @available(macOS 11.0, *)
        public init(_ type: UTType, charset: Charset? = nil) {
            let mime = type.preferredMIMEType ?? "application/octet-stream"
            value = charset.map { mime + $0.suffix } ?? mime
        }
    #endif

    /// The media type for a file extension (lowercased, dot-free) from the generated jshttp/mime-db
    /// table, or `nil` if unknown. Appends `; charset=…` when the table records one (`text/*` defaults
    /// to utf-8). The authoritative, cross-platform path — works identically on Linux.
    public init?(fileExtension ext: String) {
        guard let entry = MIMEDatabase.entry(forExtension: ext.lowercased()) else { return nil }
        self.init(value: entry.charset.map { "\(entry.type); charset=\($0)" } ?? entry.type)
    }

    /// The media type for a path by its final-segment extension, or `nil` (no extension / dotfile /
    /// unknown type). Drives `Static`'s content-type and any handler mapping a filename to a type.
    public init?(path: String) {
        guard let ext = MediaType.fileExtension(of: path) else { return nil }
        self.init(fileExtension: ext)
    }

    /// The lowercase extension of a path's final segment (no dot), or `nil` for none / a leading-dot
    /// dotfile. The single ext-extraction the `path` init and the static-asset lookup share.
    public static func fileExtension(of path: String) -> String? {
        let lastSegment = path.split(separator: "/").last.map(String.init) ?? path
        guard let dotIndex = lastSegment.lastIndex(of: "."), dotIndex != lastSegment.startIndex else {
            return nil
        }
        return lastSegment[lastSegment.index(after: dotIndex)...].lowercased()
    }

    /// An explicit content-type (the non-`UTType`-expressible cases + the parity strings).
    public static func custom(_ value: String) -> MediaType { MediaType(value: value) }

    public static let json = MediaType(value: "application/json;charset=utf-8")
    public static let jsonRaw = MediaType(value: "application/json")
    public static let jsonSpaced = MediaType(value: "application/json; charset=utf-8")
    public static let text = MediaType(value: "text/plain; charset=utf-8")
    public static let css = MediaType(value: "text/css; charset=utf-8")
    public static let html = MediaType(value: "text/html; charset=utf-8")
    public static let openSearch = MediaType(value: "application/opensearchdescription+xml")
    public static let linkset = MediaType(value: "application/linkset+json")
}

/// Per-route cache policy: the `Cache-Control` value (if any) + whether to attach a
/// SHA-256-prefix `ETag` (and honor `If-None-Match` → 304). The named app values
/// (apiCorpus, discovery, …) are app extensions.
public struct CachePolicy: Sendable {
    public var cacheControl: String?
    public var etag: Bool

    public init(cacheControl: String? = nil, etag: Bool = false) {
        self.cacheControl = cacheControl
        self.etag = etag
    }

    public static let unset = CachePolicy()
    public static let noStore = CachePolicy(cacheControl: "no-store")
    public static let noCache = CachePolicy(cacheControl: "no-cache")
    public static let immutable = CachePolicy(cacheControl: "public, max-age=31536000, immutable")
}

// MARK: - Content codec (pluggable body decode/encode port)

/// Decodes a typed value from a request body. The default is `JSONBodyCodec` (ADJSON); a server can
/// plug a different wire format — form-encoded, MessagePack, a content-type-negotiating codec — by
/// conforming this one method. `contentType` is the request's `Content-Type`, for negotiation.
public protocol RequestBodyDecoder: Sendable {
    func decode<T: Decodable>(_ type: T.Type, from body: [UInt8], contentType: String?) throws -> T
}

/// Encodes a typed value into a response body plus the content-type to advertise.
public protocol ResponseBodyEncoder: Sendable {
    func encode<T: Encodable>(_ value: T) throws -> (bytes: [UInt8], contentType: String)
}

/// The request decoder + response encoder a handler's `ctx.decode` / `ctx.json` route through.
/// Defaults to `.json`; configure the server with another `ContentCodec` to swap the wire format
/// across every route at once.
public struct ContentCodec: Sendable {
    public let decoder: any RequestBodyDecoder
    public let encoder: any ResponseBodyEncoder
    public init(decoder: any RequestBodyDecoder, encoder: any ResponseBodyEncoder) {
        self.decoder = decoder
        self.encoder = encoder
    }
    /// JSON via ADJSON — the default codec.
    public static let json = ContentCodec(decoder: JSONBodyCodec(), encoder: JSONBodyCodec())
}

/// The default codec: JSON over ADJSON's Foundation-mirroring `JSONDecoder` / `JSONEncoder`.
public struct JSONBodyCodec: RequestBodyDecoder, ResponseBodyEncoder {
    public init() {}
    public func decode<T: Decodable>(_ type: T.Type, from body: [UInt8], contentType: String?) throws
        -> T
    {
        if let contentType, !contentType.isEmpty, !Self.isJSON(contentType) {
            throw HTTPError.unsupportedMediaType("expected a JSON content type, got '\(contentType)'")
        }
        return try ADJSON.JSONDecoder().decode(type, from: body)
    }
    public func encode<T: Encodable>(_ value: T) throws -> (bytes: [UInt8], contentType: String) {
        (try ADJSON.JSONEncoder().encodeToBytes(value), "application/json;charset=utf-8")
    }
    /// True if `contentType` is `application/json` or carries a `+json` structured-syntax suffix.
    private static func isJSON(_ contentType: String) -> Bool {
        let lower = contentType.lowercased()
        return lower.hasPrefix("application/json") || lower.contains("+json")
    }
}

// MARK: - Middleware (the async request/response pipeline seam)

/// Request-scoped info a middleware sees alongside the request.
public struct MiddlewareContext: Sendable {
    public let requestID: String
    public let logger: Logger
    /// Request-scoped storage shared with the handler — the middleware→handler channel.
    public let storage: RequestStorage
    public init(requestID: String, logger: Logger, storage: RequestStorage = RequestStorage()) {
        self.requestID = requestID
        self.logger = logger
        self.storage = storage
    }
}

/// An async interceptor in the request pipeline (the onion model). `intercept` may return without
/// calling `next` (short-circuit — e.g. a 401), call `next` with a rewritten request, and/or
/// transform `next`'s response. Registered globally (per listener) and/or per group/route: the
/// global chain wraps routing, the route chain wraps the matched handler.
public protocol HTTPMiddleware: Sendable {
    func intercept(
        _ request: ServerRequest, _ context: MiddlewareContext,
        next: @escaping @Sendable (ServerRequest) async -> ResponseContent
    ) async -> ResponseContent
}

/// Compose `middleware` into a single async handler around `terminal` — the onion model, with
/// `middleware[0]` outermost. The engine uses this for `[server-wide] + [route]` middleware; it is
/// public so a consumer can build a custom pipeline too.
public func composeMiddleware(
    _ middleware: [any HTTPMiddleware], context: MiddlewareContext,
    terminal: @escaping @Sendable (ServerRequest) async -> ResponseContent
) -> @Sendable (ServerRequest) async -> ResponseContent {
    var chain = terminal
    for layer in middleware.reversed() {
        let next = chain
        chain = { request in await layer.intercept(request, context, next: next) }
    }
    return chain
}

// MARK: - Built-in observability middleware

/// A built-in middleware that logs every request — method, path, status, duration, request-id —
/// through the context's swift-log `Logger` (the first observability pillar; structured metadata).
/// Requests slower than `slowThreshold` log at `.warning` (the "slow-request log"), the rest at
/// `level`. Install it server-wide: `HTTPServer(…, middleware: [RequestLogging()])`. Timing uses the
/// monotonic clock, so it never runs backwards.
public struct RequestLogging: HTTPMiddleware {
    /// Level for normal requests (slow ones always log at `.warning`).
    public var level: Logger.Level
    /// Requests at or above this many milliseconds are logged at `.warning`.
    public var slowThresholdMillis: Double
    public init(level: Logger.Level = .info, slowThresholdMillis: Double = 1000) {
        self.level = level
        self.slowThresholdMillis = slowThresholdMillis
    }

    public func intercept(
        _ request: ServerRequest, _ context: MiddlewareContext,
        next: @Sendable (ServerRequest) async -> ResponseContent
    ) async -> ResponseContent {
        let start = LiveClock.monotonicNanoseconds()
        let response = await next(request)
        let elapsedMillis = Double(LiveClock.monotonicNanoseconds() - start) / 1_000_000
        let isSlow = elapsedMillis >= slowThresholdMillis
        context.logger.log(
            level: isSlow ? .warning : level, "request",
            metadata: [
                "method": "\(request.method.rawValue)", "path": "\(request.path)",
                "status": "\(resolvedStatusCode(of: response, storage: context.storage))",
                "duration_ms": .stringConvertible(elapsedMillis), "request_id": "\(context.requestID)"
            ])
        return response
    }
}

/// The numeric status of a response (for logging/metrics).
public func statusCode(of content: ResponseContent) -> Int {
    switch content {
        case .raw(_, _, let status), .full(_, _, let status, _): return Int(status.code)
        case .plain(let status, _): return Int(status.code)
        case .stream(_, let status, _, _): return Int(status.code)
        case .sse: return 200  // SSE is always 200 text/event-stream
        // The nominal status; the engine resolves the real 200/304/404 off-loop in `writeFile`.
        case .file: return 200
        case .notFound: return 404
    }
}

/// The status to REPORT for `content`: the engine-recorded real status when present (e.g. a `.file`'s
/// resolved 200/206/304/404/416, known only after off-loop resolution), else the nominal
/// `statusCode(of:)`. A response-observing middleware (`RequestLogging`, `MetricsMiddleware`) calls this
/// with `context.storage` so its access log / metric carries the status actually written, not the
/// pre-resolution placeholder. The engine seeds the `ResponseStatusBox` and records into it from the
/// route terminal, before the middleware chain unwinds.
public func resolvedStatusCode(of content: ResponseContent, storage: RequestStorage) -> Int {
    storage[ResponseStatusKey.self]?.code ?? statusCode(of: content)
}

// MARK: - Routing contract (the engine ⇄ DSL seam)

/// The per-request inputs the engine hands a matched route's `run`.
public struct HandlerInput: Sendable {
    public let request: ServerRequest
    /// Present iff the route declared `.storage` (a resource was checked out for the call). The
    /// engine is persistence-agnostic, so this is the type-erased `any PooledResource`; a typed
    /// handler context (e.g. the DSL's `StorageContext`) down-casts it to the concrete type.
    public let connection: (any PooledResource)?
    public let logger: Logger
    public let requestID: String
    /// The content codec the handler's `decode` / `json` helpers route through (default `.json`).
    public let codec: ContentCodec
    /// Request-scoped storage shared with the middleware chain — the middleware→handler channel.
    public let storage: RequestStorage

    public init(
        request: ServerRequest, connection: (any PooledResource)?, logger: Logger, requestID: String,
        codec: ContentCodec = .json, storage: RequestStorage = RequestStorage()
    ) {
        self.request = request
        self.connection = connection
        self.logger = logger
        self.requestID = requestID
        self.codec = codec
        self.storage = storage
    }
}

/// A route the engine resolved for a request: whether it needs a pooled connection,
/// its cache policy, and the bound (captures-applied) handler. `run` is synchronous —
/// the business logic is sync and runs on the offload thread for `.storage` routes.
public struct MatchedRoute: Sendable {
    public let needsStorage: Bool
    public let cache: CachePolicy
    /// The group + route middleware to wrap this handler with (outermost first). Empty for most routes.
    public let middleware: [any HTTPMiddleware]
    /// A per-route request-body ceiling (bytes), or `nil` for the server default. May be higher than
    /// the server default (an upload route — the engine reads it via `bodyLimit` at the request head to
    /// size accumulation) or lower (a tighter bound, enforced post-match as a problem+json 413).
    public let maxBodyBytes: Int?
    public let run: @Sendable (HandlerInput) throws -> ResponseContent
    /// A WebSocket handler if this route is a `WS` endpoint, else `nil` — the sans-I/O event/action
    /// seam from the HTTP package's `WebSocket` module. The engine reads it (via
    /// `webSocketHandler(path:)`) to decide an Upgrade; a plain `GET` to the path still runs `run`.
    public let webSocketHandler: (any WebSocketHandler)?
    /// The broadcast hub a WebSocket route is bound to, or `nil` for a plain WebSocket — the engine
    /// registers each upgraded connection with it and auto-subscribes it to `webSocketTopic`.
    public let webSocketHub: WebSocketHub?
    /// The topic a hub-backed WebSocket connection is auto-subscribed to.
    public let webSocketTopic: String?
    /// An async streaming-body handler if this route consumes its body incrementally, else `nil`. When
    /// present the engine takes the streaming path (`run` is a placeholder, never invoked).
    public let streamingRun: StreamingRequestHandler?

    public init(
        needsStorage: Bool, cache: CachePolicy, middleware: [any HTTPMiddleware] = [],
        maxBodyBytes: Int? = nil, webSocketHandler: (any WebSocketHandler)? = nil,
        webSocketHub: WebSocketHub? = nil, webSocketTopic: String? = nil,
        streamingRun: StreamingRequestHandler? = nil,
        run: @escaping @Sendable (HandlerInput) throws -> ResponseContent
    ) {
        self.needsStorage = needsStorage
        self.cache = cache
        self.middleware = middleware
        self.maxBodyBytes = maxBodyBytes
        self.webSocketHandler = webSocketHandler
        self.webSocketHub = webSocketHub
        self.webSocketTopic = webSocketTopic
        self.streamingRun = streamingRun
        self.run = run
    }
}

public enum RouteMatch: Sendable {
    case matched(MatchedRoute)
    /// The path exists but not for this method; carries the methods that ARE allowed (for `Allow:`).
    case methodNotAllowed(allowed: [HTTPMethod])
    case notFound
}

/// The route table the engine dispatches against. The DSL's `RouteTable` conforms.
public protocol HTTPHandling: Sendable {
    func match(method: HTTPMethod, path: Substring) -> RouteMatch
    /// The matched route's per-route body ceiling (`.maxBody`), or `nil` for the server default. The
    /// engine peeks this at the request head — *before* draining the body — so an upload route can
    /// raise its limit ABOVE the server default. Default `nil` (the server-wide cap applies).
    func bodyLimit(method: HTTPMethod, path: Substring) -> Int?
    /// Whether any route declares a WebSocket handler — drives the HTTP/2 / HTTP/3 Extended CONNECT
    /// advertisement (RFC 8441 / RFC 9220). Default `false` (no WebSocket routes).
    var hasWebSocketRoutes: Bool { get }
}

extension HTTPHandling {
    public func bodyLimit(method: HTTPMethod, path: Substring) -> Int? { nil }
    public var hasWebSocketRoutes: Bool { false }
}

// MARK: - Hashing / conditional / request-id (engine-generic HTTP)

/// Lowercase-hex SHA-256 (matches JS `Bun.CryptoHasher('sha256').digest('hex')`).
/// The `hashable`→ETag path and the app's `/data/search/*.<hash>.json` filenames both
/// use it, so it lives here once.
public func sha256HexLower(_ bytes: [UInt8]) -> String {
    var hasher = SHA256()
    hasher.update(data: bytes)  // safe DataProtocol overload (no unsafe buffer pointer)
    let hex: [UInt8] = Array("0123456789abcdef".utf8)
    var out: [UInt8] = []
    out.reserveCapacity(64)
    for b in hasher.finalize() {
        out.append(hex[Int(b >> 4)])
        out.append(hex[Int(b & 0xF)])
    }
    return String(decoding: out, as: UTF8.self)
}

/// Loose RFC 7232 `If-None-Match`: `*`, a single tag, or a comma list;
/// the strong/weak prefix is compared verbatim.
public func matchesIfNoneMatch(_ headerValue: String, _ etag: String) -> Bool {
    let value = trimOWS(headerValue[...])
    if value == "*" { return true }
    for part in value.split(separator: ",") where trimOWS(part) == etag[...] { return true }
    return false
}

private func trimOWS(_ s: Substring) -> Substring {
    var sub = s
    while let f = sub.first, f == " " || f == "\t" { sub = sub.dropFirst() }
    while let l = sub.last, l == " " || l == "\t" { sub = sub.dropLast() }
    return sub
}

/// Echo a valid inbound `X-Request-Id` (`/^[A-Za-z0-9._:+/=-]{1,128}$/`), else
/// mint a lowercase v4 UUID.
public func resolveRequestID(_ headers: HTTPFields) -> String {
    if let incoming = headers[requestIDName], isValidRequestID(incoming) { return incoming }
    return UUID().uuidString.lowercased()
}

/// `x-request-id` — lowercase token name, defined once.
public let requestIDName = HTTPFieldName("x-request-id")!

private func isValidRequestID(_ s: String) -> Bool {
    let utf8 = s.utf8
    guard (1 ... 128).contains(utf8.count) else { return false }
    for b in utf8 {
        switch b {
            case UInt8(ascii: "A") ... UInt8(ascii: "Z"), UInt8(ascii: "a") ... UInt8(ascii: "z"),
                UInt8(ascii: "0") ... UInt8(ascii: "9"):
                continue
            case UInt8(ascii: "."), UInt8(ascii: "_"), UInt8(ascii: ":"), UInt8(ascii: "+"),
                UInt8(ascii: "/"), UInt8(ascii: "="), UInt8(ascii: "-"):
                continue
            default:
                return false
        }
    }
    return true
}

// MARK: - Query string parsing

/// Parse `target`'s `?k=v&k2=v2` into a percent-decoded map (last value wins; bare `?k` → `""`).
func parseQueryString(_ target: String) -> [String: String] {
    guard let mark = target.firstIndex(of: "?") else { return [:] }
    var out: [String: String] = [:]
    for pair in target[target.index(after: mark)...].split(separator: "&") {
        let kv = pair.split(separator: "=", maxSplits: 1)
        guard let key = kv.first else { continue }
        out[percentDecodeToken(String(key))] = kv.count > 1 ? percentDecodeToken(String(kv[1])) : ""
    }
    return out
}

/// Percent-decode (`%XX`, `+` → space) a query token. Hand-rolled (no Foundation), like the other
/// engine byte helpers.
func percentDecodeToken(_ s: String) -> String {
    let chars = Array(s.utf8)
    var bytes: [UInt8] = []
    bytes.reserveCapacity(chars.count)
    var i = 0
    while i < chars.count {
        let c = chars[i]
        if c == UInt8(ascii: "+") {
            bytes.append(UInt8(ascii: " "))
            i += 1
        } else if c == UInt8(ascii: "%"), i + 2 < chars.count,
            let hi = hexNibble(chars[i + 1]), let lo = hexNibble(chars[i + 2])
        {
            bytes.append(hi << 4 | lo)
            i += 3
        } else {
            bytes.append(c)
            i += 1
        }
    }
    return String(decoding: bytes, as: UTF8.self)
}

private func hexNibble(_ b: UInt8) -> UInt8? {
    switch b {
        case UInt8(ascii: "0") ... UInt8(ascii: "9"): return b - UInt8(ascii: "0")
        case UInt8(ascii: "a") ... UInt8(ascii: "f"): return b - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A") ... UInt8(ascii: "F"): return b - UInt8(ascii: "A") + 10
        default: return nil
    }
}

/// True if `path` contains a `.` or `..` segment (directory traversal) in its literal form. The
/// engine rejects such requests with 400 before routing; percent-encoded dot-segments are caught
/// at capture-decode time (`PathTemplate.decodeSegment`).
public func pathHasTraversal(_ path: Substring) -> Bool {
    for segment in path.split(separator: "/", omittingEmptySubsequences: true)
    where segment == "." || segment == ".." {
        return true
    }
    return false
}
