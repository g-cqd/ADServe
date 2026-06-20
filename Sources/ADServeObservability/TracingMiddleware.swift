public import ADServeCore
import HTTPTypes
import Instrumentation
import ServiceContextModule
import Tracing

/// Reads propagation headers (e.g. W3C `traceparent`/`tracestate`, B3) off an `HTTPFields` carrier so
/// the instrument can rebuild an upstream `ServiceContext`.
struct HTTPFieldsExtractor: Extractor {
    func extract(key: String, from carrier: HTTPFields) -> String? {
        guard let name = HTTPField.Name(key) else { return nil }
        return carrier[name]
    }
}

/// A server-wide middleware that opens a distributed-tracing span for every request. It extracts any
/// upstream trace context from the request headers (so the span joins an existing distributed trace),
/// starts a `.server`-kind span named by HTTP method, tags it with the OpenTelemetry HTTP attributes,
/// marks 5xx responses as errored, and ends the span when the response is ready. With no tracer
/// bootstrapped (`InstrumentationSystem.bootstrap(...)`) it is a no-op.
///
/// Install it globally so it also spans `notFound`/`methodNotAllowed`:
///   `App(middleware: [TracingMiddleware()]) { … }`.
///
/// - Note: the span's task-local `ServiceContext` is active for the duration of `next` on the request
///   task. ADServe offloads a `.storage` route's *synchronous* handler body to a thread pool, so spans
///   started by instrumented calls INSIDE such a handler won't automatically parent to this span. The
///   request-level span — timing, status, attributes — is unaffected.
public struct TracingMiddleware: HTTPMiddleware {
    public init() {}

    public func intercept(
        _ request: ServerRequest, _ context: MiddlewareContext,
        next: @Sendable (ServerRequest) async -> ResponseContent
    ) async -> ResponseContent {
        var serviceContext = ServiceContext.topLevel
        InstrumentationSystem.instrument.extract(
            request.headers, into: &serviceContext, using: HTTPFieldsExtractor())

        return await withSpan(request.method.rawValue, context: serviceContext, ofKind: .server) {
            span in
            span.attributes["http.request.method"] = request.method.rawValue
            span.attributes["url.path"] = String(request.path)
            if let requestID = request.headers[requestIDName] {
                span.attributes["http.request.id"] = requestID
            }
            let response = await next(request)
            let status = statusCode(of: response)
            span.attributes["http.response.status_code"] = status
            // OTel: a server span is errored only for 5xx (a 4xx is the client's fault, not the span's).
            if status >= 500 { span.setStatus(SpanStatus(code: .error)) }
            return response
        }
    }
}
