// Request-scoped storage + built-in middleware (CORS, security headers) + the response-header merge
// they decorate `next`'s response with. All compose through the `HTTPMiddleware` onion.

public import HTTPTypes
private import Synchronization

// MARK: - Request-scoped storage

/// A typed key for request-scoped storage. Define one per value you pass middleware → handler:
/// `enum CurrentUser: StorageKey { typealias Value = User }`, then `context.storage[CurrentUser.self] = user`.
public protocol StorageKey: Sendable {
    associatedtype Value: Sendable
}

/// A `Sendable`, mutable, per-request bag shared by the middleware chain and the handler — the
/// channel an auth middleware uses to hand a resolved user (or a tracing middleware its span) to the
/// handler. Keyed by a `StorageKey` type, so reads/writes are typed. One instance per request, on
/// both `MiddlewareContext` and `HandlerInput`.
public final class RequestStorage: Sendable {
    private let values = Mutex<[ObjectIdentifier: any Sendable]>([:])
    public init() {}
    public subscript<Key: StorageKey>(_ key: Key.Type) -> Key.Value? {
        get { values.withLock { $0[ObjectIdentifier(key)] as? Key.Value } }
        set { values.withLock { $0[ObjectIdentifier(key)] = newValue } }
    }
}

// MARK: - Resolved-status reporting (the real status for logging/metrics)

/// A request-scoped, lock-free holder for the response's REAL status code — the status an observer
/// (`RequestLogging`, `MetricsMiddleware`) should report. It exists because a `.file` response's true
/// status (200 / 206 / 304 / 404 / 416) is only known after the engine resolves the file OFF the event
/// loop, by which point a middleware computing `statusCode(of:)` on the still-nominal `.file` content
/// would record a misleading 200. The engine resolves the file in the route terminal (innermost, before
/// the chain unwinds) and records the real status here, so an outer observing middleware reads the
/// resolved value. `0` means "not recorded" → fall back to the content's nominal status.
public final class ResponseStatusBox: Sendable {
    private let value = Atomic<Int>(0)
    public init() {}
    /// The recorded real status, or `nil` if the engine recorded none (use the nominal status then).
    public var code: Int? {
        let raw = value.load(ordering: .relaxed)
        return raw == 0 ? nil : raw
    }
    /// Record the resolved status (engine-internal: called once the real status is known).
    public func record(_ code: Int) { value.store(code, ordering: .relaxed) }
}

/// The `RequestStorage` key under which the engine seeds a `ResponseStatusBox` for every request.
public enum ResponseStatusKey: StorageKey {
    public typealias Value = ResponseStatusBox
}

/// The `RequestStorage` key carrying the connection's peer IP (the engine seeds it from the channel's
/// remote address when available). Behind a proxy this is the proxy's address — prefer an
/// `X-Forwarded-For` header for the true client there. Read via `ctx.remoteAddress`; used as the default
/// rate-limit key and available to any IP-aware middleware.
public enum RemoteAddressKey: StorageKey {
    public typealias Value = String
}

// MARK: - Response header decoration

extension ResponseContent {
    /// A copy of this response with `extra` headers merged in (overriding on conflict). Response-side
    /// middleware (CORS, security headers) uses this to decorate `next`'s response. Non-`.full` shapes
    /// are promoted to `.full` so the headers ride through the engine's envelope.
    public func withHeaders(_ extra: HTTPFields) -> ResponseContent {
        switch self {
            case .raw(let body, let contentType, let status):
                return .full(body: body, contentType: contentType, status: status, headers: extra)
            case .plain(let status, let message):
                return .full(
                    body: Array(message.utf8), contentType: "text/plain; charset=utf-8", status: status,
                    headers: extra)
            case .notFound:
                return .full(
                    body: Array("Not Found".utf8), contentType: "text/plain; charset=utf-8",
                    status: .notFound, headers: extra)
            case .full(let body, let contentType, let status, var headers):
                mergeResponseHeaders(extra, into: &headers)
                return .full(body: body, contentType: contentType, status: status, headers: headers)
            case .stream(let contentType, let status, var headers, let body):
                mergeResponseHeaders(extra, into: &headers)
                return .stream(contentType: contentType, status: status, headers: headers, body: body)
            case .sse(var headers, let heartbeat, let body):
                mergeResponseHeaders(extra, into: &headers)
                return .sse(headers: headers, heartbeat: heartbeat, body: body)
            case .file(let root, let subpath, let contentType, var headers):
                mergeResponseHeaders(extra, into: &headers)
                return .file(root: root, subpath: subpath, contentType: contentType, headers: headers)
        }
    }
}

// MARK: - CORS

/// A CORS middleware. It OWNS the preflight (an `OPTIONS` carrying `Access-Control-Request-Method`):
/// it answers `204` with the `Access-Control-Allow-*` set and never calls `next`, so it suppresses
/// the engine's auto-`OPTIONS` for that path. For actual requests it calls `next` and decorates the
/// response with `Access-Control-Allow-Origin` (+ credentials/expose). Install it server-wide (so it
/// is outermost and sees the preflight before routing).
public struct CORS: HTTPMiddleware {
    public var allowOrigin: String
    public var allowMethods: [HTTPRequest.Method]
    public var allowHeaders: [String]
    public var exposeHeaders: [String]
    public var allowCredentials: Bool
    public var maxAgeSeconds: Int

    public init(
        allowOrigin: String = "*",
        allowMethods: [HTTPRequest.Method] = [.get, .post, .put, .patch, .delete, .options],
        allowHeaders: [String] = ["Content-Type", "Authorization"], exposeHeaders: [String] = [],
        allowCredentials: Bool = false, maxAgeSeconds: Int = 600
    ) {
        self.allowOrigin = allowOrigin
        self.allowMethods = allowMethods
        self.allowHeaders = allowHeaders
        self.exposeHeaders = exposeHeaders
        self.allowCredentials = allowCredentials
        self.maxAgeSeconds = maxAgeSeconds
    }

    public func intercept(
        _ request: ServerRequest, _ context: MiddlewareContext,
        next: @Sendable (ServerRequest) async -> ResponseContent
    ) async -> ResponseContent {
        let isPreflight =
            request.method == .options && request.headers[name("access-control-request-method")] != nil
        var cors = HTTPFields()
        cors[name("access-control-allow-origin")] = allowOrigin
        if allowCredentials { cors[name("access-control-allow-credentials")] = "true" }
        if !exposeHeaders.isEmpty {
            cors[name("access-control-expose-headers")] = exposeHeaders.joined(separator: ", ")
        }
        if isPreflight {
            cors[name("access-control-allow-methods")] = allowMethods.map(\.rawValue).joined(separator: ", ")
            cors[name("access-control-allow-headers")] = allowHeaders.joined(separator: ", ")
            cors[name("access-control-max-age")] = String(maxAgeSeconds)
            return .full(body: [], contentType: "text/plain; charset=utf-8", status: .noContent, headers: cors)
        }
        return (await next(request)).withHeaders(cors)
    }
}

// MARK: - Security headers

/// Adds a baseline security-header set to every response (a composable, per-scope alternative to the
/// engine's constant `envelope`). Defaults are conservative; pass your own `HTTPFields` to override.
/// HSTS is OPT-IN (`hsts:`) — `Strict-Transport-Security` is a long-lived browser commitment that
/// forces HTTPS for the whole host (and, with `includeSubDomains`, every subdomain) for `maxAgeSeconds`,
/// so it must be a deliberate choice, never a silent default.
public struct SecurityHeaders: HTTPMiddleware {
    public var headers: HTTPFields

    /// An opt-in HSTS (`Strict-Transport-Security`) policy. Only serve it over TLS — a browser caches
    /// the directive and will refuse plaintext to the host until it expires; `preload` additionally
    /// petitions for the browser preload list, which is effectively irreversible, so leave it off unless
    /// you have committed to permanent HTTPS for the apex + all subdomains.
    public struct HSTS: Sendable {
        public var maxAgeSeconds: Int
        public var includeSubdomains: Bool
        public var preload: Bool
        public init(
            maxAgeSeconds: Int = 31_536_000, includeSubdomains: Bool = true, preload: Bool = false
        ) {
            self.maxAgeSeconds = maxAgeSeconds
            self.includeSubdomains = includeSubdomains
            self.preload = preload
        }
        /// The `Strict-Transport-Security` header value.
        public var headerValue: String {
            var out = "max-age=\(maxAgeSeconds)"
            if includeSubdomains { out += "; includeSubDomains" }
            if preload { out += "; preload" }
            return out
        }
    }

    public init(_ headers: HTTPFields? = nil, hsts: HSTS? = nil) {
        if let headers {
            self.headers = headers
        } else {
            var defaults = HTTPFields()
            defaults[name("x-content-type-options")] = "nosniff"
            defaults[name("x-frame-options")] = "DENY"
            defaults[name("referrer-policy")] = "strict-origin-when-cross-origin"
            defaults[name("cross-origin-opener-policy")] = "same-origin"
            defaults[name("cross-origin-resource-policy")] = "same-origin"
            // Deny the powerful features a typical API/site never needs, so an injected script can't
            // reach them. Override by passing your own `HTTPFields` if a feature IS needed.
            defaults[name("permissions-policy")] =
                "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), "
                + "microphone=(), payment=(), usb=()"
            self.headers = defaults
        }
        if let hsts { self.headers[name("strict-transport-security")] = hsts.headerValue }
    }

    public func intercept(
        _ request: ServerRequest, _ context: MiddlewareContext,
        next: @Sendable (ServerRequest) async -> ResponseContent
    ) async -> ResponseContent {
        (await next(request)).withHeaders(headers)
    }
}

// MARK: - CSP nonce

/// The request-scoped CSP nonce key. The handler reads `ctx.storage[CSPNonceKey.self]` to stamp the
/// inline `<script nonce="…">` (and the runtime `<script>`); the `CSPNonce` middleware mints the value
/// and emits the matching `script-src 'nonce-…'`, so a strict CSP admits exactly those inline scripts.
public enum CSPNonceKey: StorageKey {
    public typealias Value = String
}

/// Per-request CSP nonce middleware (ADHTML hydration under a strict CSP). Mints a fresh 128-bit nonce
/// from the system CSPRNG, stores it on `RequestStorage` (so the handler can stamp `<script nonce="…">`),
/// and sets the response `Content-Security-Policy` from `policy(nonce)` — replacing any inherited CSP,
/// so the nonce is the single source of truth. Install it on the routes that render hydratable HTML.
///
/// The nonce is regenerated per request and never reused: a predictable or reused nonce would defeat the
/// inline-script protection it exists for, so it is NOT derived from the request-id (which can be
/// client-supplied) — it is CSPRNG bytes, hex-encoded (a valid CSP `base64-value`).
public struct CSPNonce: HTTPMiddleware {
    /// Builds the full `Content-Security-Policy` value from the per-request nonce.
    public var policy: @Sendable (_ nonce: String) -> String

    public init(
        policy: @escaping @Sendable (_ nonce: String) -> String = CSPNonce.strictHydrationPolicy
    ) {
        self.policy = policy
    }

    /// `script-src 'nonce-…' 'strict-dynamic'; object-src 'none'; base-uri 'none'` — admits the inline
    /// state script + the runtime (and what the runtime loads, via `strict-dynamic`), nothing else.
    public static let strictHydrationPolicy: @Sendable (String) -> String = { nonce in
        "script-src 'nonce-\(nonce)' 'strict-dynamic'; object-src 'none'; base-uri 'none'"
    }

    public func intercept(
        _ request: ServerRequest, _ context: MiddlewareContext,
        next: @Sendable (ServerRequest) async -> ResponseContent
    ) async -> ResponseContent {
        let nonce = Self.makeNonce()
        context.storage[CSPNonceKey.self] = nonce
        let response = await next(request)
        var headers = HTTPFields()
        headers[name("content-security-policy")] = policy(nonce)
        return response.withHeaders(headers)
    }

    /// 16 CSPRNG bytes (128 bits) as lowercase hex. `UInt8.random(in:)` draws from
    /// `SystemRandomNumberGenerator` — the platform CSPRNG (arc4random / getrandom) — and hex is a valid
    /// CSP `base64-value`, so no Foundation base64 dependency is needed.
    static func makeNonce() -> String {
        let hex: [UInt8] = Array("0123456789abcdef".utf8)
        var out: [UInt8] = []
        out.reserveCapacity(32)
        for _ in 0 ..< 16 {
            let byte = UInt8.random(in: .min ... .max)
            out.append(hex[Int(byte >> 4)])
            out.append(hex[Int(byte & 0xF)])
        }
        return String(decoding: out, as: UTF8.self)
    }
}

/// A lowercase HTTP field name (the swift-http-types canonical form). Traps on an invalid token —
/// these are compile-time-constant literals.
private func name(_ token: String) -> HTTPField.Name { HTTPField.Name(token)! }
