// Phase 1 hardening regression: the Sessions middleware rejects a weak secret at CONSTRUCTION (fail
// fast at boot, not forge-able at runtime) and derives its HMAC key via HKDF; rotate() defends against
// session fixation. Mutation-resistant via ADTestKit's `expectThrows(where:)` (concrete type + payload).

import ADTestKit
import Foundation
import HTTPCore
import Testing

@testable import ADServeCore

@Suite struct SessionSecurityTests {
    @Test func `a secret shorter than the minimum is rejected at construction`() {
        let short = Array("too-short-secret".utf8)  // 16 bytes < 32
        expectThrows {
            _ = try Sessions(secret: short)
        } where: { (error: SessionConfigError) in
            error == .secretTooShort(provided: 16, minimum: 32)
        }
    }

    @Test func `a secret at the minimum length is accepted`() throws {
        _ = try Sessions(secret: [UInt8](repeating: 0xAB, count: Sessions.minimumSecretBytes))
    }

    @Test func `the HKDF-derived key signs and verifies a session id round-trip`() async throws {
        let sessions = try Sessions(
            secret: [UInt8](repeating: 0x11, count: 48), store: InMemorySessionStore(), secure: false)
        let routes = InputStubRoutes { input in
            if input.request.method == .post {
                input.storage[SessionKey.self]?["uid"] = "alice"
                return .raw(body: Array("ok".utf8), contentType: "text/plain", status: .ok)
            }
            let uid = input.storage[SessionKey.self]?["uid"] ?? "none"
            return .raw(body: Array(uid.utf8), contentType: "text/plain", status: .ok)
        }
        let first = try await Loopback.runRaw(
            "POST / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", routes: routes, middleware: [sessions])
        let cookie = try #require(sessionCookie(first))
        let second = try await Loopback.run(
            path: "/", routes: routes, headers: [("Cookie", cookie)], middleware: [sessions])
        #expect(second.hasSuffix("alice"))  // verified server-side with the derived key
    }

    @Test func `rotate issues a fresh session id (fixation defense)`() async throws {
        let sessions = try Sessions(
            secret: [UInt8](repeating: 0x07, count: 32), store: InMemorySessionStore(), secure: false)
        let routes = InputStubRoutes { input in
            input.storage[SessionKey.self]?["k"] = "v"
            if input.request.headers[HTTPFieldName("x-rotate")!] != nil {
                input.storage[SessionKey.self]?.rotate()
            }
            return .raw(body: Array("ok".utf8), contentType: "text/plain", status: .ok)
        }
        let first = try await Loopback.runRaw(
            "POST / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", routes: routes, middleware: [sessions])
        let cookieA = try #require(sessionCookie(first))
        let second = try await Loopback.run(
            path: "/", routes: routes, headers: [("Cookie", cookieA), ("X-Rotate", "1")],
            middleware: [sessions])
        let cookieB = sessionCookie(second)
        #expect(cookieB != nil)
        #expect(cookieB != cookieA)  // the id changed → an attacker-fixed id is now useless
    }

    /// The `session=<id>.<mac>` value from the first `Set-Cookie` (without attributes).
    private func sessionCookie(_ response: String) -> String? {
        for line in response.split(separator: "\r\n") where line.lowercased().hasPrefix("set-cookie:") {
            let value = line.dropFirst("set-cookie:".count).trimmingCharacters(in: .whitespaces)
            return value.split(separator: ";").first.map(String.init)
        }
        return nil
    }
}
