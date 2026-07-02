// M3 middleware: signed-cookie sessions (round-trip + tamper rejection), rate limiting (429 + headers),
// and request timeout (504). A shared middleware INSTANCE is passed to successive `Loopback.run` calls so
// the in-memory store / counter persists across the (per-call) server instances.

import ADTestKit
import Foundation
import HTTPCore
import Testing

@testable import ADServeCore

@Suite struct SessionTests {
    private let secret = Array("a-stable-32-byte-test-secret-!!!".utf8)

    /// A handler that POSTs `user=alice` into the session and GETs it back out.
    private func sessionEchoRoutes() -> InputStubRoutes {
        InputStubRoutes { input in
            if input.request.method == .post {
                input.storage[SessionKey.self]?["user"] = "alice"
                return .raw(body: Array("stored".utf8), contentType: "text/plain", status: .ok)
            }
            let user = input.storage[SessionKey.self]?["user"] ?? "none"
            return .raw(body: Array(user.utf8), contentType: "text/plain", status: .ok)
        }
    }

    @Test func signedSessionSurvivesARoundTrip() async throws {
        let sessions = try Sessions(secret: secret, store: InMemorySessionStore(), secure: false)
        let routes = sessionEchoRoutes()

        let first = try await Loopback.runRaw(
            "POST / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", routes: routes, middleware: [sessions])
        let cookie = try #require(sessionCookie(first))
        #expect(cookie.contains("session="))

        let second = try await Loopback.run(
            path: "/", routes: routes, headers: [("Cookie", cookie)], middleware: [sessions])
        #expect(second.hasSuffix("alice"))  // the session loaded server-side
    }

    @Test func tamperedSessionCookieIsRejected() async throws {
        let sessions = try Sessions(secret: secret, store: InMemorySessionStore(), secure: false)
        let routes = sessionEchoRoutes()

        let first = try await Loopback.runRaw(
            "POST / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", routes: routes, middleware: [sessions])
        let cookie = try #require(sessionCookie(first))
        // Flip the last character of the signed cookie → the HMAC no longer verifies.
        let tampered = String(cookie.dropLast()) + (cookie.hasSuffix("a") ? "b" : "a")

        let second = try await Loopback.run(
            path: "/", routes: routes, headers: [("Cookie", tampered)], middleware: [sessions])
        #expect(second.hasSuffix("none"))  // rejected → a fresh, empty session
    }

    @Test func readOnlyRequestSetsNoCookie() async throws {
        let sessions = try Sessions(secret: secret, store: InMemorySessionStore(), secure: false)
        // A GET that only reads the (empty) session must not mint one / set a cookie.
        let routes = InputStubRoutes { input in
            _ = input.storage[SessionKey.self]?["user"]
            return .raw(body: Array("ok".utf8), contentType: "text/plain", status: .ok)
        }
        let response = try await Loopback.run(path: "/", routes: routes, middleware: [sessions])
        #expect(!response.lowercased().contains("set-cookie"))
    }

    /// The `session=<id>.<mac>` value from the first `Set-Cookie` header (without attributes).
    private func sessionCookie(_ response: String) -> String? {
        for line in response.split(separator: "\r\n") where line.lowercased().hasPrefix("set-cookie:") {
            let value = line.dropFirst("set-cookie:".count).trimmingCharacters(in: .whitespaces)
            return value.split(separator: ";").first.map(String.init)
        }
        return nil
    }
}

@Suite struct RateLimitTests {
    @Test func returns429WithHeadersPastTheLimit() async throws {
        // limit 2/window, shared instance → the in-memory counter persists across the three calls (same
        // loopback peer IP → same key).
        let limiter = RateLimit(limit: 2, windowSeconds: 60)
        let routes = StubRoutes { _ in .raw(body: Array("ok".utf8), contentType: "text/plain", status: .ok) }

        let first = try await Loopback.run(path: "/", routes: routes, middleware: [limiter])
        #expect(first.hasPrefix("HTTP/1.1 200"))
        #expect(first.lowercased().contains("ratelimit-limit: 2"))
        #expect(first.lowercased().contains("ratelimit-remaining: 1"))

        let second = try await Loopback.run(path: "/", routes: routes, middleware: [limiter])
        #expect(second.hasPrefix("HTTP/1.1 200"))
        #expect(second.lowercased().contains("ratelimit-remaining: 0"))

        let third = try await Loopback.run(path: "/", routes: routes, middleware: [limiter])
        #expect(third.hasPrefix("HTTP/1.1 429"))
        #expect(third.lowercased().contains("retry-after:"))
        #expect(third.lowercased().contains("ratelimit-remaining: 0"))
    }

    @Test func distinctKeysHaveIndependentBuckets() async throws {
        // Keying by a request header lets two different values exhaust independently.
        let limiter = RateLimit(limit: 1, windowSeconds: 60) { request, _ in
            request.headers[HTTPFieldName("x-api-key")!] ?? "none"
        }
        let routes = StubRoutes { _ in .raw(body: Array("ok".utf8), contentType: "text/plain", status: .ok) }
        // key "a": first ok, second 429.
        _ = try await Loopback.run(path: "/", routes: routes, headers: [("X-API-Key", "a")], middleware: [limiter])
        let aSecond = try await Loopback.run(
            path: "/", routes: routes, headers: [("X-API-Key", "a")], middleware: [limiter])
        #expect(aSecond.hasPrefix("HTTP/1.1 429"))
        // key "b": still has its own budget.
        let bFirst = try await Loopback.run(
            path: "/", routes: routes, headers: [("X-API-Key", "b")], middleware: [limiter])
        #expect(bFirst.hasPrefix("HTTP/1.1 200"))
    }
}

@Suite struct TimeoutMiddlewareTests {
    @Test func slowRequestGets504() async throws {
        // Timeout (outermost) races a deliberately-slow downstream middleware; the deadline wins.
        let routes = StubRoutes { _ in .raw(body: Array("late".utf8), contentType: "text/plain", status: .ok) }
        let middleware: [any HTTPMiddleware] = [Timeout(seconds: 0.1), SleepMiddleware(seconds: 2)]
        let response = try await Loopback.run(path: "/", routes: routes, middleware: middleware)
        #expect(response.hasPrefix("HTTP/1.1 504"))
        #expect(response.contains("Gateway Timeout"))
    }

    @Test func fastRequestPassesThrough() async throws {
        let routes = StubRoutes { _ in .raw(body: Array("quick".utf8), contentType: "text/plain", status: .ok) }
        let response = try await Loopback.run(path: "/", routes: routes, middleware: [Timeout(seconds: 5)])
        #expect(response.hasPrefix("HTTP/1.1 200"))
        #expect(response.hasSuffix("quick"))
    }
}

/// A middleware that sleeps before delegating — to drive the request-timeout test deterministically.
private struct SleepMiddleware: HTTPMiddleware {
    let seconds: Double
    func intercept(
        _ request: ServerRequest, _ context: MiddlewareContext,
        next: @escaping @Sendable (ServerRequest) async -> ResponseContent
    ) async -> ResponseContent {
        try? await Task.sleep(for: .seconds(seconds))
        return await next(request)
    }
}
