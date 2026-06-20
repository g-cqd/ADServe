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
                for field in extra { headers[field.name] = field.value }
                return .full(body: body, contentType: contentType, status: status, headers: headers)
            case .stream(let contentType, let status, var headers, let body):
                for field in extra { headers[field.name] = field.value }
                return .stream(contentType: contentType, status: status, headers: headers, body: body)
            case .sse(var headers, let body):
                for field in extra { headers[field.name] = field.value }
                return .sse(headers: headers, body: body)
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
public struct SecurityHeaders: HTTPMiddleware {
    public var headers: HTTPFields

    public init(_ headers: HTTPFields? = nil) {
        if let headers {
            self.headers = headers
            return
        }
        var defaults = HTTPFields()
        defaults[name("x-content-type-options")] = "nosniff"
        defaults[name("x-frame-options")] = "DENY"
        defaults[name("referrer-policy")] = "strict-origin-when-cross-origin"
        defaults[name("cross-origin-opener-policy")] = "same-origin"
        defaults[name("cross-origin-resource-policy")] = "same-origin"
        self.headers = defaults
    }

    public func intercept(
        _ request: ServerRequest, _ context: MiddlewareContext,
        next: @Sendable (ServerRequest) async -> ResponseContent
    ) async -> ResponseContent {
        (await next(request)).withHeaders(headers)
    }
}

/// A lowercase HTTP field name (the swift-http-types canonical form). Traps on an invalid token —
/// these are compile-time-constant literals.
private func name(_ token: String) -> HTTPField.Name { HTTPField.Name(token)! }
