// The serving + graceful-drain lifecycle as a `swift-service-lifecycle` `Service`, plus the
// per-connection idle/quiesce close handler. Extracted from HTTPServer.swift so the engine type
// stays within the file/type-length budget; the behavior is unchanged.

import Logging
import NIOCore
import NIOExtras
import NIOHTTPTypes
import ServiceLifecycle

/// The serving + graceful-drain lifecycle as a `swift-service-lifecycle` `Service`. The accept
/// loops run inline (the task-group body); a single coordinator child task waits for graceful
/// shutdown, then stops accepting (closes the server channels — the accept loops end naturally,
/// no cancellation), drains in-flight requests (bounded by `drainSeconds`), and quiesces the
/// connections (each child closes on `ChannelShouldQuiesceEvent`). The accept loops then return
/// on their own; `cancelAll` only ever reaches the coordinator (the inline serving is already
/// done by then), so no accept loop is cancelled mid-flight — which previously orphaned
/// just-accepted `NIOAsyncChannel`s (their writers deinited without `finish()`).
struct ServingService: Service {
    let serveTasks: [@Sendable () async -> Void]
    let channels: [any Channel]
    let quiescers: [ServerQuiescingHelper]
    let group: any EventLoopGroup
    let active: ActiveRequests
    let readiness: ServerReadiness?
    let drainSeconds: Int
    let logger: Logger

    private enum Phase: Sendable, Equatable { case served, signalled }

    func run() async throws {
        await withTaskGroup(of: Phase.self) { taskGroup in
            // The accept loops; ends once every connection (and the listeners) close.
            taskGroup.addTask {
                await withDiscardingTaskGroup { serving in
                    for serve in serveTasks { serving.addTask { await serve() } }
                }
                return .served
            }
            // The graceful-shutdown waiter.
            taskGroup.addTask {
                do { try await gracefulShutdown() } catch {}
                return .signalled
            }

            if await taskGroup.next() == .signalled {
                // Run the drain as its OWN child task. Every allocating await it performs (the
                // `Task.sleep`s, the quiesce sub-group, the close-future `get()`s) then lives on
                // THIS child's task allocator — not interleaved, on the *parent* allocator, with the
                // still-live serving child. Doing those awaits inline in the group body (as before)
                // freed the parent's `Task.sleep` buffer out of order against the concurrent child
                // under `-O`, tripping the task-allocator LIFO assertion ("freed pointer was not the
                // last allocation") and aborting the process on every SIGTERM.
                taskGroup.addTask {
                    await self.drain()
                    return .signalled
                }
                _ = await taskGroup.next()  // the drain child, once the listeners/connections close
                _ = await taskGroup.next()  // the accept loops, now that connections have closed
            } else {
                // Listeners finished on their own; end the still-suspended graceful-shutdown waiter.
                taskGroup.cancelAll()
            }
        }
    }

    /// Drains in-flight work and quiesces the listeners after a shutdown signal. Runs as its own
    /// structured child task (see `run()`) so its allocating awaits stay on a dedicated task
    /// allocator rather than the parent group's — the inline version freed a `Task.sleep` buffer
    /// out of order against the concurrently-live serving child and tripped the release-build
    /// task-allocator LIFO assertion.
    private func drain() async {
        readiness?.set(false)
        logger.info("ad-server draining (stop accepting)")
        // Stop READING new connections first (don't close the listeners yet): closing a
        // listening channel while a child is mid-accept makes NIOAsyncChannelHandler drop
        // that child's writer in `channelActive` (deinit-without-finish trap). With autoRead
        // off, the kernel's accept queue stops draining into NIO, so no child is in flight
        // when the quiescer finally closes the listeners.
        for channel in channels { _ = channel.setOption(ChannelOptions.autoRead, value: false) }
        try? await Task.sleep(for: .milliseconds(100))
        // Wait for in-flight requests to finish (idle keep-alive connections are ignored),
        // bounded by the drain deadline.
        let deadline = ContinuousClock.now.advanced(by: .seconds(drainSeconds))
        while active.count > 0 && ContinuousClock.now < deadline {
            try? await Task.sleep(for: .milliseconds(50))
        }
        if active.count > 0 {
            logger.warning(
                "ad-server drain deadline exceeded; forcing close",
                metadata: ["inflight": "\(active.count)"])
        }
        // Quiesce (close the listeners + every still-open connection — each child closes on
        // `ChannelShouldQuiesceEvent`) and AWAIT completion, so the ELG isn't torn down with
        // channel-close work still pending (which would schedule on a shut-down event loop).
        await withTaskGroup(of: Void.self) { quiesceGroup in
            for quiesce in quiescers {
                quiesceGroup.addTask {
                    let promise = group.next().makePromise(of: Void.self)
                    quiesce.initiateShutdown(promise: promise)
                    try? await promise.futureResult.get()
                }
            }
        }
        // Also await the listening channels' full close, so no channel-close work is still
        // queued on the event loops when the caller tears the group down afterwards.
        for channel in channels { try? await channel.closeFuture.get() }
    }
}

/// Closes the connection on the read-idle deadline (`IdleStateHandler`) or when the server
/// quiesces (`ChannelShouldQuiesceEvent`, fired by `ServerQuiescingHelper` during a drain —
/// closing here ends the connection's inbound so `executeThenClose` finishes its writer
/// cleanly); forwards every other inbound user event untouched.
final class IdleTimeoutHandler: ChannelInboundHandler {
    typealias InboundIn = HTTPRequestPart

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if event is IdleStateHandler.IdleStateEvent || event is ChannelShouldQuiesceEvent {
            context.close(promise: nil)
        } else {
            context.fireUserInboundEventTriggered(event)
        }
    }
}
