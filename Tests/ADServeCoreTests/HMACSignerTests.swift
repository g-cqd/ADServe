// `HMACSigner` (extracted from `Sessions`): a stateless HMAC-SHA256 signer with HKDF key derivation +
// domain separation by `info`. Mutation-resistant via ADTestKit's `expectThrows(where:)` (concrete type +
// payload). The domain-separation test is the load-bearing one for reuse: it proves the SAME secret yields
// independent keys for the cookie scheme and the action-token scheme.

import ADTestKit
import Testing

@testable import ADServeCore

@Suite struct HMACSignerTests {
    private func signer(_ byte: UInt8 = 0x11, info: String = "test.v1") throws -> HMACSigner {
        try HMACSigner(secret: [UInt8](repeating: byte, count: 32), info: info)
    }

    @Test func `sign then verify round-trips the payload`() throws {
        let signer = try signer()
        let token = signer.sign("session-abc")
        #expect(token.hasPrefix("session-abc."))  // the `<payload>.<tag>` shape (the Sessions cookie shape)
        #expect(signer.verify(token) == "session-abc")
    }

    @Test func `a structured dotted payload round-trips — split on the LAST dot`() throws {
        let signer = try signer()
        let token = signer.sign("a3f1c2.1750000000.deadbeef")  // an action token: id.exp.sid8
        #expect(signer.verify(token) == "a3f1c2.1750000000.deadbeef")
    }

    @Test func `a tampered payload or tag fails verification`() throws {
        let signer = try signer()
        let token = signer.sign("uid-7")
        let tag = String(token.split(separator: ".").last!)
        #expect(signer.verify("uid-8.\(tag)") == nil)  // tag is for uid-7, payload swapped
        #expect(signer.verify("\(token)0") == nil)  // mutated tag
        #expect(signer.verify("no-dot-token") == nil)  // no separator
        #expect(signer.verify("uid-7.") == nil)  // empty tag
    }

    @Test func `isValid checks the tag of a payload`() throws {
        let signer = try signer()
        let tag = signer.tag(for: "x")
        #expect(signer.isValid(tag: tag, for: "x"))
        #expect(!signer.isValid(tag: tag, for: "y"))  // right tag, wrong payload
        #expect(!signer.isValid(tag: "zz", for: "x"))  // non-hex tag
    }

    @Test func `a secret shorter than the minimum is rejected at construction`() {
        expectThrows {
            _ = try HMACSigner(secret: Array("short".utf8), info: "x")  // 5 bytes < 32
        } where: { (error: HMACSignerError) in
            error == .secretTooShort(provided: 5, minimum: 32)
        }
    }

    @Test func `the same secret with different info derives independent keys (domain separation)`() throws {
        let secret = [UInt8](repeating: 0x5A, count: 40)
        let cookies = try HMACSigner(secret: secret, info: "ADServe.Sessions.v1.cookie-signing")
        let actions = try HMACSigner(secret: secret, info: "ADHTML.Actions.v1.token-signing")
        #expect(cookies.tag(for: "p") != actions.tag(for: "p"))  // independent keys -> different tags
        #expect(actions.verify(cookies.sign("p")) == nil)  // a cookie token never verifies under the action key
    }
}
