import ADServeCore
import HTTPTypes
import InMemoryTracing
import Instrumentation
import Logging
import Metrics
import MetricsTestKit
import ServiceContextModule
import Testing
import Tracing

@testable import ADServeObservability

// The metrics + instrumentation systems bootstrap process-globally exactly once (a global `let`'s
// initializer is run once, thread-safe). Only this (serialized) suite touches them, and each test
// clears the tracer / uses fresh dimensions, so there's no cross-test interference.
let testMetrics = TestMetrics()
let testTracer = InMemoryTracer()
private let bootstrapOnce: Void = {
    MetricsSystem.bootstrap(testMetrics)
    InstrumentationSystem.bootstrap(testTracer)
}()

private func makeContext() -> MiddlewareContext {
    MiddlewareContext(requestID: "rid-123", logger: Logger(label: "test"))
}

@Suite("Observability middleware", .serialized)
struct ObservabilityTests {
    @Test("MetricsMiddleware records a counter + timer dimensioned by method and status")
    func metrics() async throws {
        _ = bootstrapOnce
        let response = await MetricsMiddleware().intercept(
            ServerRequest(method: .get, target: "/x", headers: HTTPFields()), makeContext()
        ) { _ in .plain(.ok, "ok") }
        #expect(statusCode(of: response) == 200)

        let counter = try testMetrics.expectCounter(
            "http_requests_total", [("method", "GET"), ("status", "200")])
        #expect(counter.totalValue == 1)
        let timer = try testMetrics.expectTimer(
            "http_request_duration_seconds", [("method", "GET"), ("status", "200")])
        #expect(timer.values.count == 1)
        #expect(timer.values.allSatisfy { $0 >= 0 })
    }

    @Test("MetricsMiddleware returns the downstream response unchanged")
    func metricsTransparent() async {
        let response = await MetricsMiddleware().intercept(
            ServerRequest(method: .post, target: "/y", headers: HTTPFields()), makeContext()
        ) { _ in .plain(.created, "made") }
        #expect(statusCode(of: response) == 201)
    }

    @Test("TracingMiddleware opens a .server span and marks 5xx as errored")
    func tracingError() async throws {
        _ = bootstrapOnce
        testTracer.clearAll(includingActive: true)
        _ = await TracingMiddleware().intercept(
            ServerRequest(method: .post, target: "/boom", headers: HTTPFields()), makeContext()
        ) { _ in .plain(.internalServerError, "boom") }

        let spans = testTracer.popFinishedSpans()
        #expect(spans.count == 1)
        let span = try #require(spans.first)
        #expect(span.operationName == "POST")
        if case .server = span.kind {} else { Issue.record("expected a .server span kind") }
        if case .error = span.status?.code {} else { Issue.record("expected an .error span status") }
        #expect(span.attributes.count >= 3)  // method, path, status_code (+ request id when present)
    }

    @Test("TracingMiddleware leaves a 2xx span unerrored")
    func tracingOK() async throws {
        _ = bootstrapOnce
        testTracer.clearAll(includingActive: true)
        _ = await TracingMiddleware().intercept(
            ServerRequest(method: .get, target: "/ok", headers: HTTPFields()), makeContext()
        ) { _ in .plain(.ok, "ok") }

        let span = try #require(testTracer.popFinishedSpans().first)
        #expect(span.operationName == "GET")
        if case .error = span.status?.code { Issue.record("a 2xx must not be errored") }
    }

    @Test("HTTPFieldsExtractor reads propagation headers off the carrier")
    func extractor() {
        var headers = HTTPFields()
        headers[HTTPField.Name("traceparent")!] = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        let extractor = HTTPFieldsExtractor()
        #expect(
            extractor.extract(key: "traceparent", from: headers)
                == "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
        #expect(extractor.extract(key: "absent", from: headers) == nil)
    }
}
