// M0 named-gap coverage for two engine changes: (1) accurate static logging — an observing middleware
// reads the REAL resolved static status (200/206/304/404/416) via `resolvedStatusCode`, not the nominal
// 200 the unresolved `.file` content carries; and (2) the optional engine-side SSE heartbeat — a
// configurable interval makes the engine emit `: ` keep-alive comments on an otherwise idle stream.

import ADTestKit
import Foundation
import HTTPCore
import Testing

@testable import ADServeCore

@Suite struct ResolvedStatusTests {
    /// A `.file` that 404s must surface 404 to an observing middleware — the bug this closes is that the
    /// nominal `statusCode(of: .file)` is always 200 until the engine resolves the file off-loop.
    @Test func missingStaticFileReportsRealStatusToMiddleware() async throws {
        let dir = TemporaryDirectory(prefix: "adserve-status")
        defer { dir.cleanup() }
        let captured = AsyncEventProbe<Int>()
        let routes = StubRoutes { _ in
            .file(root: dir.path, subpath: "missing.css", contentType: "text/css")
        }
        let response = try await Loopback.run(
            path: "/missing.css", routes: routes, middleware: [StatusCaptureMiddleware(captured)])
        #expect(response.hasPrefix("HTTP/1.1 404"))
        let statuses = try await captured.wait(forAtLeast: 1, timeout: .seconds(2))
        #expect(statuses.first == 404)  // the engine-resolved status, not the nominal 200
    }

    @Test func servedStaticFileReportsTwoHundredToMiddleware() async throws {
        let dir = TemporaryDirectory(prefix: "adserve-status")
        defer { dir.cleanup() }
        try Data("body{}".utf8).write(to: URL(fileURLWithPath: dir.file("app.css")))
        let captured = AsyncEventProbe<Int>()
        let routes = StubRoutes { _ in
            .file(root: dir.path, subpath: "app.css", contentType: "text/css; charset=utf-8")
        }
        let response = try await Loopback.run(
            path: "/app.css", routes: routes, middleware: [StatusCaptureMiddleware(captured)])
        #expect(response.hasPrefix("HTTP/1.1 200"))
        let statuses = try await captured.wait(forAtLeast: 1, timeout: .seconds(2))
        #expect(statuses.first == 200)
    }

    @Test func conditionalStaticFileReportsThreeOhFourToMiddleware() async throws {
        let dir = TemporaryDirectory(prefix: "adserve-status")
        defer { dir.cleanup() }
        try Data("x".utf8).write(to: URL(fileURLWithPath: dir.file("a.js")))
        let routes = StubRoutes { _ in
            .file(root: dir.path, subpath: "a.js", contentType: "text/javascript")
        }
        // First request reads the ETag; the conditional second request resolves to 304.
        let first = try await Loopback.run(path: "/a.js", routes: routes)
        let etag = try #require(headerValue(first, "etag"))
        let captured = AsyncEventProbe<Int>()
        let response = try await Loopback.run(
            path: "/a.js", routes: routes, headers: [("If-None-Match", etag)],
            middleware: [StatusCaptureMiddleware(captured)])
        #expect(response.hasPrefix("HTTP/1.1 304"))
        let statuses = try await captured.wait(forAtLeast: 1, timeout: .seconds(2))
        #expect(statuses.first == 304)  // the conditional hit, surfaced to the middleware
    }

    @Test func nonFileResponseFallsBackToNominalStatus() async throws {
        let captured = AsyncEventProbe<Int>()
        let routes = StubRoutes { _ in
            .full(body: [], contentType: "text/plain; charset=utf-8", status: .created, headers: HTTPFields())
        }
        let response = try await Loopback.run(
            path: "/created", routes: routes, middleware: [StatusCaptureMiddleware(captured)])
        #expect(response.hasPrefix("HTTP/1.1 201"))
        let statuses = try await captured.wait(forAtLeast: 1, timeout: .seconds(2))
        #expect(statuses.first == 201)  // no box recorded → nominal status (correct for non-file)
    }
}

@Suite struct SSEHeartbeatTests {
    /// With a heartbeat interval the engine emits `: ` keep-alive comments on an idle stream — the app
    /// sent only one event, so every `: \n` line is engine-emitted. A wide margin (idle window ≫ interval)
    /// keeps it robust against CI jitter.
    @Test func engineHeartbeatEmitsKeepAliveCommentsOnIdleStream() async throws {
        let routes = StubRoutes { _ in
            .sse(heartbeat: .milliseconds(25)) { writer in
                try await writer.send("start", event: "go", id: "1")
                try await Task.sleep(for: .milliseconds(250))  // idle window ≈ 10 heartbeat intervals
            }
        }
        let response = try await Loopback.run(path: "/events", routes: routes)
        #expect(response.contains("event: go\nid: 1\ndata: start\n\n"))
        let pings = response.components(separatedBy: ": \n").count - 1
        #expect(pings >= 1)  // the engine kept the idle stream alive
    }

    /// Default (`heartbeat == nil`): the engine emits NO pings — the app-driven heartbeat stays the only
    /// source, so the prior behavior is unchanged.
    @Test func noHeartbeatByDefaultEmitsNoEnginePings() async throws {
        let routes = StubRoutes { _ in
            .sse { writer in
                try await writer.send("only", event: "e", id: "1")
                try await Task.sleep(for: .milliseconds(80))
            }
        }
        let response = try await Loopback.run(path: "/events", routes: routes)
        #expect(response.contains("data: only"))
        #expect(!response.contains(": \n"))  // no engine heartbeat without an interval
    }
}

/// Records the engine-resolved response status (`resolvedStatusCode`) into a probe after `next` — the
/// shape `RequestLogging`/`MetricsMiddleware` use to report the real status.
private struct StatusCaptureMiddleware: HTTPMiddleware {
    let probe: AsyncEventProbe<Int>
    init(_ probe: AsyncEventProbe<Int>) { self.probe = probe }
    func intercept(
        _ request: ServerRequest, _ context: MiddlewareContext,
        next: @Sendable (ServerRequest) async -> ResponseContent
    ) async -> ResponseContent {
        let response = await next(request)
        probe.record(resolvedStatusCode(of: response, storage: context.storage))
        return response
    }
}

/// One header value out of a raw HTTP/1.1 response (case-insensitive name).
private func headerValue(_ response: String, _ name: String) -> String? {
    for line in response.split(separator: "\r\n") {
        let parts = line.split(separator: ":", maxSplits: 1)
        if parts.count == 2, parts[0].lowercased() == name {
            return parts[1].trimmingCharacters(in: .whitespaces)
        }
    }
    return nil
}
