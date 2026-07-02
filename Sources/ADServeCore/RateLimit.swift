// Fixed-window rate limiting as an `HTTPMiddleware`. In-memory counters keyed by a pluggable key
// (default: the `X-Forwarded-For` client, else the peer IP, else a single global bucket). Emits the IETF
// `RateLimit-Limit`/`-Remaining`/`-Reset` headers on every response, and a `429` + `Retry-After` once a
// key exceeds `limit` requests in the window.

import Foundation
import HTTPCore
import Synchronization

/// One rate-limit decision for a request.
private struct RateDecision {
    let allowed: Bool
    let remaining: Int
    let resetSeconds: Int
}

/// The in-memory fixed-window counter store. Lock-guarded; a stale-key sweep runs when the map grows
/// past a soft cap, so an unbounded key space (e.g. spoofed `X-Forwarded-For`) can't grow memory without
/// bound. A production deployment swaps in a shared store via a custom key + external limiter.
private final class RateWindowStore: Sendable {
    private struct Window {
        var start: Double
        var count: Int
    }
    private let windows = Mutex<[String: Window]>([:])
    private let sweepThreshold = 10_000

    func admit(key: String, limit: Int, windowSeconds: Int) -> RateDecision {
        let now = Date().timeIntervalSince1970
        let window = Double(windowSeconds)
        return windows.withLock { map in
            if map.count > sweepThreshold {
                map = map.filter { $0.value.start + window >= now }  // drop expired windows
            }
            var entry = map[key] ?? Window(start: now, count: 0)
            if now >= entry.start + window { entry = Window(start: now, count: 0) }  // new window
            entry.count += 1
            map[key] = entry
            let resetSeconds = max(0, Int((entry.start + window - now).rounded(.up)))
            return RateDecision(
                allowed: entry.count <= limit, remaining: max(0, limit - entry.count),
                resetSeconds: resetSeconds)
        }
    }
}

/// Fixed-window rate-limit middleware. `limit` requests per `windowSeconds` per key. Install it
/// server-wide (outermost, so it also caps 404s) or per group. The default key is the client IP
/// (`X-Forwarded-For` behind a proxy, else the peer address); pass `key:` to bucket by an API token,
/// account, route, etc.
public struct RateLimit: HTTPMiddleware {
    public let limit: Int
    public let windowSeconds: Int
    private let key: @Sendable (ServerRequest, MiddlewareContext) -> String
    private let store = RateWindowStore()

    public init(
        limit: Int, windowSeconds: Int = 60,
        key: @escaping @Sendable (ServerRequest, MiddlewareContext) -> String = RateLimit.clientKey
    ) {
        self.limit = max(1, limit)
        self.windowSeconds = max(1, windowSeconds)
        self.key = key
    }

    /// The default key: the first `X-Forwarded-For` hop (the real client behind a proxy), else the
    /// engine-seeded peer IP, else a single shared `"global"` bucket.
    public static let clientKey: @Sendable (ServerRequest, MiddlewareContext) -> String = {
        request, context in
        if let forwarded = forwardedForName.flatMap({ request.headers[$0] }),
            let first = forwarded.split(separator: ",").first
        {
            return first.trimmingCharacters(in: .whitespaces)
        }
        return context.storage[RemoteAddressKey.self] ?? "global"
    }

    public func intercept(
        _ request: ServerRequest, _ context: MiddlewareContext,
        next: @Sendable (ServerRequest) async -> ResponseContent
    ) async -> ResponseContent {
        let decision = store.admit(key: key(request, context), limit: limit, windowSeconds: windowSeconds)
        var headers = HTTPFields()
        headers.setValue(String(limit), for: rateLimitName)
        headers.setValue(String(decision.remaining), for: rateRemainingName)
        headers.setValue(String(decision.resetSeconds), for: rateResetName)
        guard decision.allowed else {
            headers.setValue(String(decision.resetSeconds), for: .retryAfter)
            return .full(
                body: Array("rate limit exceeded\n".utf8), contentType: "text/plain; charset=utf-8",
                status: .tooManyRequests, headers: headers)
        }
        return (await next(request)).withHeaders(headers)
    }
}

// Field names HTTPCore does not register (`retry-after` IS registered and used as `.retryAfter`
// above). Compile-time-constant valid HTTP tokens, so the optionals always bind; they are never
// unwrapped — writes route through the module's skip-on-nil `setValue(_:for:)` overload and the
// read through `flatMap` — so an impossible failure degrades (header absent / forwarded hop
// unread) instead of trapping the server.
private let forwardedForName = HTTPFieldName("x-forwarded-for")
private let rateLimitName = HTTPFieldName("ratelimit-limit")
private let rateRemainingName = HTTPFieldName("ratelimit-remaining")
private let rateResetName = HTTPFieldName("ratelimit-reset")
