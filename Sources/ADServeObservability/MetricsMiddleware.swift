// ADServeObservability — opt-in observability middleware bridging ADServe's `HTTPMiddleware` seam to
// the swift-server ecosystem primitives (swift-metrics + swift-distributed-tracing). Kept in a
// SEPARATE target so a consumer of the bare engine/DSL never resolves these dependencies; add the
// `ADServeObservability` product only if you want the integration.
//
// Install both globally (so they also observe 404/405 — they wrap routing, not just the handler):
//   App(middleware: [TracingMiddleware(), MetricsMiddleware(), RequestLogging()]) { … }
// then bootstrap your backends once at process start (`MetricsSystem.bootstrap`, `InstrumentationSystem
// .bootstrap`). With nothing bootstrapped, both middleware are no-ops.

public import ADServeCore
import Dispatch
import HTTPTypes
import Metrics

/// A server-wide middleware that records a swift-metrics counter + latency timer for every request,
/// each dimensioned by HTTP method and response status. It deliberately never uses the request path
/// as a dimension — that would explode the metric-series cardinality (`/items/1`, `/items/2`, …);
/// method × status stays bounded. Latency is measured on the monotonic clock (`DispatchTime`), so it
/// never runs backwards.
///
/// Emits, with the default labels:
///   - `http_requests_total{method,status}` — a `Counter`, incremented once per request.
///   - `http_request_duration_seconds{method,status}` — a `Timer` (recorded with ns precision).
///
/// Bootstrap a backend (`MetricsSystem.bootstrap(...)`) at startup; otherwise the records are no-ops.
public struct MetricsMiddleware: HTTPMiddleware {
    /// The counter metric label (default `http_requests_total`).
    public let requestsLabel: String
    /// The latency timer metric label (default `http_request_duration_seconds`).
    public let durationLabel: String

    public init(
        requestsLabel: String = "http_requests_total",
        durationLabel: String = "http_request_duration_seconds"
    ) {
        self.requestsLabel = requestsLabel
        self.durationLabel = durationLabel
    }

    public func intercept(
        _ request: ServerRequest, _ context: MiddlewareContext,
        next: @Sendable (ServerRequest) async -> ResponseContent
    ) async -> ResponseContent {
        let start = DispatchTime.now()
        let response = await next(request)
        let dimensions = [
            ("method", request.method.rawValue),
            ("status", String(statusCode(of: response)))
        ]
        // swift-metrics dedups handlers by label+dimensions inside the backend, so creating the
        // metric per request is the documented usage (not a per-request allocation of state).
        Counter(label: requestsLabel, dimensions: dimensions).increment()
        Timer(label: durationLabel, dimensions: dimensions).recordInterval(since: start)
        return response
    }
}
