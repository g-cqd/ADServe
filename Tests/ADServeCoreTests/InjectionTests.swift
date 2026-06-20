// Phase 1 hardening regression: `Set-Cookie` building strips the bytes a hostile cookie value/name could
// use to inject a header (CR/LF/NUL → HTTP response splitting) or a forged attribute (`;`). Defense in
// depth over swift-http-types' own header-value validation.

import Testing

@testable import ADServeCore

@Suite struct InjectionTests {
    @Test func `Set-Cookie strips CRLF and NUL from a hostile value`() {
        // A classic response-splitting payload: a value that tries to start a second header line.
        let cookie = SetCookie(name: "sid", value: "abc\r\nSet-Cookie: evil=1\u{0}", secure: true)
        let header = cookie.headerValue
        #expect(!header.contains("\r"))
        #expect(!header.contains("\n"))
        #expect(!header.contains("\u{0}"))
        // The injected text is now inert characters on a SINGLE line — no real second header.
        #expect(header.hasPrefix("sid=abcSet-Cookie: evil=1"))
    }

    @Test func `Set-Cookie strips a semicolon that would forge an attribute`() {
        // No `path` (so the only real attribute is the injected-then-stripped `;`): a value carrying its
        // own `; HttpOnly` must not produce a real HttpOnly attribute.
        let cookie = SetCookie(name: "sid", value: "v; HttpOnly", path: nil)
        let header = cookie.headerValue
        #expect(header == "sid=v HttpOnly")  // the `;` is gone; ` HttpOnly` is part of the value, not an attr
        #expect(!header.contains(";"))
    }

    @Test func `a Set-Cookie name is reduced to a bare token`() {
        // A name carrying `=`, `;`, and a space cannot break the `name=value` framing.
        let cookie = SetCookie(name: "a=b; c", value: "v", path: nil)
        #expect(cookie.headerValue == "abc=v")
    }

    @Test func `legitimate cookies are unchanged`() {
        let cookie = SetCookie(
            name: "session", value: "abc123def456", path: "/", domain: "example.com", maxAge: 3600,
            secure: true, httpOnly: true, sameSite: .lax)
        #expect(
            cookie.headerValue
                == "session=abc123def456; Path=/; Domain=example.com; Max-Age=3600; Secure; HttpOnly; SameSite=Lax"
        )
    }
}
