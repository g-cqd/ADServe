// Request-timeout middleware: races the handler chain against a wall-clock deadline and answers `504
// Gateway Timeout` if the deadline wins. Distinct from the engine's idle timeout (which reaps a stalled
// CONNECTION): this bounds the time spent producing ONE response. The handler and the deadline run as
// STRUCTURED child tasks (a task group), so they belong to the request's task tree: a client disconnect
// cancels this request and thus the handler too (no detached-task leak), and on timeout the loser is
// `cancelAll()`ed so a cancellation-aware handler unwinds. Swift cancellation is cooperative, so a
// handler that never suspends can't be force-stopped — its late result is simply discarded.

import Foundation
import HTTPCore

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
        // Structured race: the handler and the deadline are CHILD tasks of this request's task tree (not
        // detached `Task {}`s). So a client disconnect that cancels this request now propagates into the
        // handler child, which unwinds — where the old unstructured version LEAKED the handler (it ran to
        // completion holding a pooled connection / CPU for a gone client). Whichever child finishes first
        // wins; `cancelAll()` cancels the loser so a cancellation-aware handler unwinds promptly.
        return await withTaskGroup(of: ResponseContent?.self) { group in
            group.addTask { await next(request) }
            group.addTask {
                try? await Task.sleep(for: .seconds(deadline))
                return Task.isCancelled ? nil : Self.timeoutResponse(requestID)
            }
            let winner = await group.next() ?? nil  // first child to finish (handler response or the 504)
            group.cancelAll()
            return winner ?? Self.timeoutResponse(requestID)
        }
    }

    static func timeoutResponse(_ requestID: String) -> ResponseContent {
        .problem(
            ProblemDetails(
                title: "Gateway Timeout", status: 504, detail: "the request exceeded the time limit",
                instance: requestID))
    }
}
