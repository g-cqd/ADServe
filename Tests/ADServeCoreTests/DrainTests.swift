// Graceful-drain lifecycle over the new engine: tearing the server down (the embedding-owner
// cancellation path — the same per-listener shutdown the SIGTERM drain ends in) force-closes a live
// keep-alive connection and releases the listener port. The SIGTERM trigger itself is
// swift-service-lifecycle's ServiceGroup wiring (unchanged machinery); an in-process `kill` cannot
// be tested here because the signal is process-wide — it would drain every concurrently running
// loopback server in the suite.

import Foundation
import HTTPCore
import Logging
import Testing

@testable import ADServeCore

@Suite struct GracefulDrainTests {
    @Test func serverTeardownClosesALiveKeepAliveConnection() async throws {
        let routes = StubRoutes { _ in
            .raw(body: Array("ok".utf8), contentType: "text/plain", status: .ok)
        }
        let port = try Loopback.freePort()
        let readiness = ServerReadiness()
        let server = HTTPServer(
            listeners: [ListenerConfig(host: "127.0.0.1", port: port, routes: routes)], pool: nil,
            envelope: HTTPFields(), logger: Logger(label: "drain-cancel"), threadCount: 1,
            loopCount: 1, readiness: readiness)
        let serverTask = Task { _ = try? await server.run() }
        try await Loopback.awaitReadiness(readiness)

        // Hold an idle keep-alive connection open (served once), then cancel the server task: the
        // teardown force-closes the connection (the client sees EOF) within the bound.
        let client = try await runOnThread { () -> TestSocket in
            let socket = try TestSocket.connect(host: "127.0.0.1", port: port)
            try socket.send("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n")
            let served = socket.readUntilComplete(backstop: .seconds(2))
            guard !served.isEmpty else { throw TLSHarnessError(message: "request never served") }
            return socket
        }
        serverTask.cancel()
        let closed = try await runOnThread { client.observeClose(within: .seconds(5)) }
        #expect(closed)
    }

    @Test func serverTeardownClosesALiveKeepAliveConnectionAcrossManyIterations() async throws {
        // Regression lock for a ~10% intermittent hang: a `closeDescriptor`/`enqueue` control-closure
        // racing the loop's `isRunning` flip (during `KqueueEventLoop`/`EpollEventLoop.runLoop()` shutdown)
        // could be skipped by the inner drain's `isRunning` gate and stranded — permanently parking the
        // connection's `serve` task, hanging teardown. Fixed by an unconditional final drain before
        // `close(kq)`/`close(epfd)`. A single run can't distinguish "fixed" from "got lucky", so this
        // repeats the exact single-shot scenario many times with a bound tight enough (1s, down from the
        // single-shot test's 5s) that a reintroduced race would show up as a failure, not just a slow pass.
        for iteration in 0 ..< 60 {
            let routes = StubRoutes { _ in
                .raw(body: Array("ok".utf8), contentType: "text/plain", status: .ok)
            }
            let port = try Loopback.freePort()
            let readiness = ServerReadiness()
            let server = HTTPServer(
                listeners: [ListenerConfig(host: "127.0.0.1", port: port, routes: routes)], pool: nil,
                envelope: HTTPFields(), logger: Logger(label: "drain-cancel-stress"), threadCount: 1,
                loopCount: 1, readiness: readiness)
            let serverTask = Task { _ = try? await server.run() }
            try await Loopback.awaitReadiness(readiness)

            let client = try await runOnThread { () -> TestSocket in
                let socket = try TestSocket.connect(host: "127.0.0.1", port: port)
                try socket.send("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n")
                let served = socket.readUntilComplete(backstop: .seconds(2))
                guard !served.isEmpty else { throw TLSHarnessError(message: "request never served") }
                return socket
            }
            serverTask.cancel()
            let closed = try await runOnThread { client.observeClose(within: .seconds(1)) }
            #expect(closed, "iteration \(iteration): teardown did not close the live connection within 1s")
        }
    }
}
