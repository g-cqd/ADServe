// The serving + graceful-drain lifecycle as a `swift-service-lifecycle` `Service`. The engine
// servers run inline (the task-group body); a single coordinator child task waits for graceful
// shutdown, then flips readiness off, waits for in-flight REQUESTS to finish (idle keep-alive
// connections are ignored, bounded by `drainSeconds`), and asks each engine server to shut down —
// which stops its transport (no new accepts) and force-closes any connection that has not drained
// within its deadline. The serve loops then return on their own.

import HTTPServer
import Logging
import ServiceLifecycle

/// The serving + graceful-drain lifecycle as a `swift-service-lifecycle` `Service`.
struct ServingService: Service {
    let engines: [ListenerEngine]
    let active: ActiveRequests
    let readiness: ServerReadiness?
    let drainSeconds: Int
    let logger: Logger

    private enum Phase: Sendable, Equatable { case served, signalled }

    func run() async throws {
        await withTaskGroup(of: Phase.self) { taskGroup in
            // The serve loops; end once every listener's transport finishes (shutdown or failure).
            taskGroup.addTask {
                await withDiscardingTaskGroup { serving in
                    for engine in engines {
                        serving.addTask { try? await engine.server.run() }
                    }
                }
                return .served
            }
            // The graceful-shutdown waiter.
            taskGroup.addTask {
                // `gracefulShutdown()` returns when a shutdown signal arrives, or throws
                // `CancellationError` if this waiter is cancelled first (e.g. serving already ended).
                // Both outcomes mean "stop", so the error is deliberately swallowed — `.signalled`
                // is reported either way to trigger the drain below.
                do { try await gracefulShutdown() } catch {}
                return .signalled
            }

            if await taskGroup.next() == .signalled {
                taskGroup.addTask {
                    await self.drain()
                    return .signalled
                }
                _ = await taskGroup.next()  // the drain child
                _ = await taskGroup.next()  // the serve loops, once the transports have stopped
            } else {
                // Listeners finished on their own; end the still-suspended graceful-shutdown waiter.
                taskGroup.cancelAll()
            }
        }
    }

    /// Drains in-flight work after a shutdown signal: readiness off (orchestrators stop routing new
    /// traffic), wait for active REQUESTS (not idle connections) bounded by the drain deadline, then
    /// stop each engine server — its transport stops accepting and any connection still open after
    /// the per-server grace window is force-closed.
    private func drain() async {
        readiness?.set(false)
        logger.info("ad-server draining (stop accepting)")
        let deadline = ContinuousClock.now.advanced(by: .seconds(drainSeconds))
        while active.count > 0 && ContinuousClock.now < deadline {
            try? await Task.sleep(for: .milliseconds(50))
        }
        if active.count > 0 {
            logger.warning(
                "ad-server drain deadline exceeded; forcing close",
                metadata: ["inflight": "\(active.count)"])
        }
        await withTaskGroup(of: Void.self) { group in
            for engine in engines {
                group.addTask { await engine.server.shutdown(within: .seconds(1)) }
            }
        }
    }
}
