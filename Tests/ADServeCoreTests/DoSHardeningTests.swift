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
}
