// Data-race + no-recursion load tests for the engine's shared-state primitives under concurrent peak
// contention. Each test drives one primitive with ADTestKit's thundering-herd oracle
// (`expectAllConcurrent` / `expectExactlyKSucceed`) and asserts an EXACT post-state (a count, a gate's
// free flag, every saved id loading back) — so a regression that drops, double-counts, or over-admits
// surfaces as a failed exact assertion, not a vague flake. The no-recursion checks run a reachable
// iterative parser (`MultipartParser`) on a 512 KiB stack via `DepthSweep`, where a recursive descent
// would SIGBUS instead of returning.
//
// SCOPE NOTE: the DSL route-trie (`ADServeDSL.RouteTable.match`) is the canonical iterative-descent
// target named in the task, but `RouteTable`/`CompiledRoute` live in `ADServeDSL`, which the
// `ADServeCoreTests` target does not depend on (and `Package.swift` is out of scope here). Its descent
// is already explicit-stack (see `SearchFrame` in ADServeDSL.swift) and is depth-swept by the DSL test
// target; this file covers the reachable `MultipartParser` boundary scan instead.

import ADTestKit
import Foundation
import HTTPCore
import Logging
import Synchronization
import Testing

@testable import ADServeCore

@Suite struct ConcurrencyTests {
    // MARK: - 1. InMemorySessionStore (Mutex-guarded store)

    /// Admitted when a worker throws nothing; the herd never crashes the Mutex-guarded map.
    private struct StoreFault: Error {}

    @Test func `InMemorySessionStore survives a save/load/delete herd on DISTINCT ids and all load back`()
        async
    {
        let store = InMemorySessionStore()
        let count = 256

        // Every worker owns a distinct id: save a known value, read it back, save again. No deletes here,
        // so the post-state is fully determined — all `count` ids must load their final value.
        let outcome = await expectAllConcurrent(count: count) { worker in
            let id = "id-\(worker)"
            await store.save(id, values: ["w": "\(worker)"])
            let mid = await store.load(id)
            guard mid?["w"] == "\(worker)" else { throw StoreFault() }
            await store.save(id, values: ["w": "\(worker)", "final": "yes"])
        }
        #expect(outcome.complete)
        #expect(outcome.successCount == count)

        // Final-state consistency: each distinct id loads back exactly its last-written value.
        for worker in 0 ..< count {
            let values = await store.load("id-\(worker)")
            #expect(values?["w"] == "\(worker)")
            #expect(values?["final"] == "yes")
        }
    }

    @Test func `InMemorySessionStore tolerates concurrent save+load+delete churn on the SAME id`() async {
        let store = InMemorySessionStore()
        let id = "hot"
        await store.save(id, values: ["seed": "1"])

        // Maximum contention on one key: even workers save, odd workers delete, all read. The final value
        // is nondeterministic (last writer wins / a delete may win), so we assert only the invariant the
        // Mutex must hold — no crash, every worker settles — then re-establish a known state and confirm
        // the map is still usable (read-after-write succeeds), proving the lock was never left poisoned.
        let outcome = await expectAllConcurrent(count: 200) { worker in
            if worker.isMultiple(of: 2) {
                await store.save(id, values: ["w": "\(worker)"])
            } else {
                await store.delete(id)
            }
            _ = await store.load(id)
        }
        #expect(outcome.complete)
        #expect(outcome.successCount == 200)

        await store.save(id, values: ["settled": "ok"])
        #expect(await store.load(id) == ["settled": "ok"])
        await store.delete(id)
        #expect(await store.load(id) == nil)
    }

    // MARK: - 2. ConnectionLimiter / SSELimiter (wait-free CAS admission)

    private struct AtCapacity: Error {}

    /// A churn angle distinct from DoSHardeningTests' acquire-and-hold herd: every worker that wins a slot
    /// IMMEDIATELY releases it, so the limiter cycles through far more than `limit` admissions but its
    /// `inUse` must return to zero. We prove the return-to-zero by then running a hold-only herd that must
    /// admit exactly `limit` — an off-by-one leak in the churn would shrink that follow-on count.
    @Test func `ConnectionLimiter churn (acquire+release) leaves capacity intact for a later herd`() async {
        let limit = 16
        let limiter = ConnectionLimiter(limit: limit)

        let churn = await expectAllConcurrent(count: 512) { _ in
            if limiter.tryAcquire() { limiter.release() }
        }
        #expect(churn.complete)
        #expect(churn.successCount == 512)  // a churn worker never throws (acquire-or-skip)

        // inUse must be back at 0: a fresh hold-only herd admits exactly `limit` and rejects the overflow.
        let herd = await expectExactlyKSucceed(of: 128, succeed: limit) { _ in
            guard limiter.tryAcquire() else { throw AtCapacity() }
        }
        #expect(herd.successCount == limit)
        #expect(herd.failureCount == 128 - limit)
    }

    @Test func `SSELimiter churn (acquire+release) leaves capacity intact for a later herd`() async {
        let limit = 8
        let limiter = SSELimiter(limit: limit)

        let churn = await expectAllConcurrent(count: 400) { _ in
            if limiter.tryAcquire() { limiter.release() }
        }
        #expect(churn.complete)
        #expect(churn.successCount == 400)

        let herd = await expectExactlyKSucceed(of: 96, succeed: limit) { _ in
            guard limiter.tryAcquire() else { throw AtCapacity() }
        }
        #expect(herd.successCount == limit)
        #expect(herd.failureCount == 96 - limit)
    }

    /// Varying limits: the CAS admission cap is exact across a range of caps (and the unlimited `0` opt-in
    /// admits everyone). One herd per limit, all under the same thundering-herd contention.
    @Test(arguments: [1, 2, 7, 32, 100])
    func `ConnectionLimiter admits exactly its limit across varying caps`(limit: Int) async {
        let limiter = ConnectionLimiter(limit: limit)
        let count = 200
        let expected = min(limit, count)
        let herd = await expectExactlyKSucceed(of: count, succeed: expected) { _ in
            guard limiter.tryAcquire() else { throw AtCapacity() }
        }
        #expect(herd.successCount == expected)
        #expect(herd.failureCount == count - expected)
    }

    @Test func `ConnectionLimiter with limit 0 is unlimited under a herd`() async {
        let limiter = ConnectionLimiter(limit: 0)
        let herd = await expectExactlyKSucceed(of: 256, succeed: 256) { _ in
            guard limiter.tryAcquire() else { throw AtCapacity() }
        }
        #expect(herd.successCount == 256)
    }

    // MARK: - 3. RateLimit (fixed-window keyed counter, via the public middleware)

    /// Exactly `limit` requests on the SAME key are admitted (200) within one window; the overflow gets
    /// 429. We hit the counter through `RateLimit.intercept` (its store is private) with a constant key,
    /// so the entire herd lands in one bucket — the precise over-admission race the CAS-free counter must
    /// resist. `succeed` == the count of 200s (a 429 throws), asserted exactly.
    @Test func `RateLimit admits exactly the limit on one key under a concurrent herd`() async {
        let limit = 20
        let count = 300
        let limiter = RateLimit(limit: limit, windowSeconds: 600) { _, _ in "same-key" }
        let request = ServerRequest(method: .get, target: "/", headers: HTTPFields())

        struct RateLimited: Error {}
        let outcome = await expectExactlyKSucceed(of: count, succeed: limit) { _ in
            let context = MiddlewareContext(requestID: "r", logger: Logger(label: "t"))
            let response = await limiter.intercept(request, context) { _ in
                .raw(body: Array("ok".utf8), contentType: "text/plain", status: .ok)
            }
            let code = response.statusCode
            guard code == 200 else {
                #expect(code == 429)  // the only non-200 the limiter ever returns
                throw RateLimited()
            }
        }
        #expect(outcome.successCount == limit)
        #expect(outcome.failureCount == count - limit)
    }

    @Test func `RateLimit keeps distinct keys independent under a mixed herd`() async {
        // Two keys, each with its own budget of `limit`; 2*limit workers split across them must ALL pass
        // (no cross-key contention bleeds one bucket into the other).
        let limit = 25
        let limiter = RateLimit(limit: limit, windowSeconds: 600) { request, _ in
            request.headers[HTTPFieldName("x-key")!] ?? "none"
        }
        struct RateLimited: Error {}
        let outcome = await expectAllConcurrent(count: 2 * limit) { worker in
            var headers = HTTPFields()
            headers.setValue(worker.isMultiple(of: 2) ? "a" : "b", for: HTTPFieldName("x-key")!)
            let request = ServerRequest(method: .get, target: "/", headers: headers)
            let context = MiddlewareContext(requestID: "r", logger: Logger(label: "t"))
            let response = await limiter.intercept(request, context) { _ in
                .raw(body: Array("ok".utf8), contentType: "text/plain", status: .ok)
            }
            guard response.statusCode == 200 else { throw RateLimited() }
        }
        #expect(outcome.complete)
        #expect(outcome.successCount == 2 * limit)  // limit per key, both buckets fully spent, none over
    }

    // MARK: - 4. ActiveRequests (atomic counter) / FIFOAsyncGate (async mutex)

    /// Balanced enter/leave brackets under a herd must net to zero on the relaxed atomic — a lost or
    /// duplicated update would leave a nonzero residue. We then enter `extra` times WITHOUT leaving and
    /// assert the count is exactly `extra`, pinning the absolute value (not just "back to start").
    @Test func `ActiveRequests enter/leave nets to a consistent count under a herd`() async {
        let active = ActiveRequests()

        let balanced = await expectAllConcurrent(count: 1000) { _ in
            active.enter()
            await Task.yield()
            active.leave()
        }
        #expect(balanced.complete)
        #expect(balanced.successCount == 1000)
        #expect(active.count == 0)  // every bracket closed → exact zero

        let extra = 37
        let opened = await expectAllConcurrent(count: extra) { _ in active.enter() }
        #expect(opened.successCount == extra)
        #expect(active.count == extra)  // exact residual, no atomic drift
    }

    /// `FIFOAsyncGate` is a non-reentrant async mutex. Under a herd of acquire→(critical section)→release,
    /// it must guarantee MUTUAL EXCLUSION (never two holders at once) and return to free at the end. We
    /// track the live-holder count + its peak in a `Mutex`; a `Task.yield` inside the critical section
    /// widens the window so a broken gate would let the peak exceed 1.
    @Test func `FIFOAsyncGate enforces mutual exclusion under a concurrent herd and ends free`() async {
        let gate = FIFOAsyncGate()
        let holders = Mutex<(live: Int, peak: Int)>((0, 0))
        let count = 200

        let outcome = await expectAllConcurrent(count: count) { _ in
            await gate.acquire()
            holders.withLock { state in
                state.live += 1
                state.peak = max(state.peak, state.live)
            }
            await Task.yield()  // hold the gate across a suspension — the real serialization test
            holders.withLock { $0.live -= 1 }
            await gate.release()
        }
        #expect(outcome.complete)
        #expect(outcome.successCount == count)

        let final = holders.withLock { $0 }
        #expect(final.live == 0)  // every holder released
        #expect(final.peak == 1)  // mutual exclusion held — never two inside the gate at once

        // The gate is free again: a fresh acquire returns without deadlocking.
        await gate.acquire()
        await gate.release()
    }

    // MARK: - 5. NO-RECURSION: the multipart boundary scan on a constrained stack

    /// A `multipart/form-data` body with `n` boundary-delimited parts. The scan (`split` → `firstRange`)
    /// must be iterative: a recursive descent over the parts would blow a 512 KiB stack at high `n`.
    private static func multipartBody(parts n: Int, boundary: String) -> [UInt8] {
        var out: [UInt8] = []
        for index in 0 ..< n {
            out.append(contentsOf: Array("--\(boundary)\r\n".utf8))
            out.append(contentsOf: Array("Content-Disposition: form-data; name=\"f\(index)\"\r\n\r\n".utf8))
            out.append(contentsOf: Array("v\(index)\r\n".utf8))
        }
        out.append(contentsOf: Array("--\(boundary)--\r\n".utf8))
        return out
    }

    @Test func `MultipartParser boundary scan is iterative — survives a deep body on a small stack`() {
        let boundary = "BoUnDaRy"
        // Straddle plausible recursion caps and push far past them; each depth runs on a pinned 512 KiB
        // stack, so a recursive split/scan surfaces as a SIGBUS rather than a silent pass.
        DepthSweep.around(64, 256, 1024, upTo: 3000)
            .run { depth in
                let body = Self.multipartBody(parts: depth, boundary: boundary)
                let form = MultipartParser.parse(body, boundary: boundary)
                // Total + correct: every part parsed back, in order, with its value — survival AND fidelity.
                guard form.parts.count == depth else {
                    Issue.record("multipart parse lost parts at depth \(depth): got \(form.parts.count)")
                    return
                }
                if depth > 0 {
                    let first = form.parts.first
                    let last = form.parts.last
                    if first?.name != "f0" || first?.text != "v0" {
                        Issue.record("first part wrong at depth \(depth)")
                    }
                    if last?.name != "f\(depth - 1)" || last?.text != "v\(depth - 1)" {
                        Issue.record("last part wrong at depth \(depth)")
                    }
                }
            }
    }

    @Test func `MultipartParser boundary-token scan handles a very long boundary on a small stack`() {
        // The boundary token itself is long, so `firstRange`'s inner match loop runs many iterations per
        // candidate — still iterative; a deep body with this boundary must not overflow the pinned stack.
        let boundary = String(repeating: "x", count: 70)
        runOnConstrainedStack {
            let body = Self.multipartBody(parts: 800, boundary: boundary)
            let form = MultipartParser.parse(body, boundary: boundary)
            if form.parts.count != 800 {
                Issue.record("long-boundary parse lost parts: got \(form.parts.count)")
            }
        }
    }
}
