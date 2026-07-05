// Phase 1 DoS hardening: the admission limiters hold their cap under a concurrent thundering herd (CAS
// correctness at peak contention — also a data-race check), and the default connection cap is finite so a
// fresh server resists connection-flood / FD exhaustion. Uses ADTestKit's expectExactlyKSucceed oracle.

import ADTestKit
import Testing

@testable import ADServeCore

@Suite struct DoSHardeningTests {
    @Test func `the default connection cap is finite`() {
        #expect(HTTPServer.defaultMaxConnections > 0)
    }

    @Test func `ConnectionLimiter admits exactly the limit under a concurrent herd`() async {
        let limit = 16
        let limiter = ConnectionLimiter(limit: limit)
        struct AtCapacity: Error {}
        // 128 "connections" race for 16 slots at once and none release → the peak is measured.
        let outcome = await expectExactlyKSucceed(of: 128, succeed: limit) { _ in
            guard limiter.tryAcquire() else { throw AtCapacity() }
        }
        #expect(outcome.successCount == limit)
        #expect(outcome.failureCount == 128 - limit)
    }

    @Test func `ConnectionLimiter with limit 0 admits everyone (explicit unlimited opt-in)`() async {
        let limiter = ConnectionLimiter(limit: 0)
        struct Unreachable: Error {}
        let outcome = await expectExactlyKSucceed(of: 64, succeed: 64) { _ in
            guard limiter.tryAcquire() else { throw Unreachable() }
        }
        #expect(outcome.successCount == 64)
    }

    @Test func `SSELimiter admits exactly the limit under a concurrent herd`() async {
        let limit = 8
        let limiter = SSELimiter(limit: limit)
        struct AtCapacity: Error {}
        let outcome = await expectExactlyKSucceed(of: 96, succeed: limit) { _ in
            guard limiter.tryAcquire() else { throw AtCapacity() }
        }
        #expect(outcome.successCount == limit)
        #expect(outcome.failureCount == 96 - limit)
    }

    @Test func `an over-long multipart boundary is rejected (closes the O(n^2) scan)`() {
        // RFC 2046 caps a boundary at 70 chars. An attacker who set a giant boundary (via Content-Type)
        // over a matching adversarial body would force `ByteSearch.split` into an O(body × boundary) scan
        // ≈ O(n²) — a request-body-sized CPU-DoS. Both entry points now reject > 70.
        let giant = String(repeating: "-", count: 5_000)
        #expect(MultipartParser.boundary(fromContentType: "multipart/form-data; boundary=\(giant)") == nil)
        // The public `parse` guards too, so a direct call with a giant boundary short-circuits to empty.
        #expect(MultipartParser.parse([1, 2, 3], boundary: giant).parts.isEmpty)
        // A legitimate boundary is still accepted + parsed (the cap must not reject valid forms).
        let ok = "----ADFormBoundaryXYZ"
        #expect(MultipartParser.boundary(fromContentType: "multipart/form-data; boundary=\(ok)") == ok)
    }

    @Test func `a max-length boundary over an adversarial body stays linear`() {
        // With the ≤70 cap the needle is bounded, so even a worst-case body (every position a near-miss to
        // a 70-byte boundary) is O(body × 70) = O(body). Uncapped, a body-length boundary was O(n²) → hang.
        let boundary = String(repeating: "-", count: 69) + "X"  // 70 chars: forces the full no-match scan
        let body = [UInt8](repeating: UInt8(ascii: "-"), count: 100_000)  // all near-misses, never matches
        let elapsed = ContinuousClock().measure { _ = MultipartParser.parse(body, boundary: boundary) }
        // Debug-safe budget: the capped scan is O(body × 70) ≈ 7M compares (well under a second even at
        // -Onone); an uncapped O(n²) would be ~10^10 (minutes). 5s cleanly separates the two.
        #expect(elapsed < .seconds(5), "capped-boundary multipart parse is not linear: \(elapsed)")
    }
}
