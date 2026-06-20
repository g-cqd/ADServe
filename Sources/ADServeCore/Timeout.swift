// Request-timeout middleware: races the handler chain against a wall-clock deadline and answers `504
// Gateway Timeout` if the deadline wins. Distinct from the engine's idle timeout (which reaps a stalled
// CONNECTION): this bounds the time spent producing ONE response. The deadline is enforced promptly — the
// 504 is returned the instant it fires, abandoning the slow handler (it runs to completion unobserved;
// Swift cancellation is cooperative, so a handler that never suspends can't be force-stopped, but its
// late result is discarded). The losing task is also `cancel()`ed so a cancellation-aware handler unwinds.

import Foundation
import HTTPTypes
import Synchronization

/// Answers `504 Gateway Timeout` when a request takes longer than `seconds` to produce a response.
/// Place it INSIDE any response-shaping middleware you want to run on the 504 (e.g. logging) and OUTSIDE
/// the slow handler. Not for long-lived `.sse`/`.stream` routes — those are unbounded by design; scope
/// the timeout to the request/response routes that should be quick.
public struct Timeout: HTTPMiddleware {
    public let seconds: Double

    public init(seconds: Double) { self.seconds = max(0, seconds) }

    public func intercept(
        _ request: ServerRequest, _ context: MiddlewareContext,
        next: @escaping @Sendable (ServerRequest) async -> ResponseContent
    ) async -> ResponseContent {
        let deadline = seconds
        let requestID = context.requestID
        return await withCheckedContinuation { (continuation: CheckedContinuation<ResponseContent, Never>) in
            // One-shot: whichever of the handler / deadline finishes first resumes the continuation; the
            // loser's `claim()` is a no-op (so the continuation resumes exactly once).
            let claimed = Mutex(false)
            @Sendable func claim() -> Bool {
                claimed.withLock { taken in
                    if taken { return false }
                    taken = true
                    return true
                }
            }
            let handlerTask = Task {
                let response = await next(request)
                if claim() { continuation.resume(returning: response) }
            }
            Task {
                try? await Task.sleep(for: .seconds(deadline))
                if claim() {
                    handlerTask.cancel()  // cooperative: let a cancellation-aware handler unwind
                    continuation.resume(returning: Self.timeoutResponse(requestID))
                }
            }
        }
    }

    static func timeoutResponse(_ requestID: String) -> ResponseContent {
        .problem(
            ProblemDetails(
                title: "Gateway Timeout", status: 504, detail: "the request exceeded the time limit",
                instance: requestID))
    }
}
