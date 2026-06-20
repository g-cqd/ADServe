// Typed HTTP errors, RFC 9457 problem+json, and the REST response factories. A handler is
// `throws`, so it can `throw HTTPError.badRequest(...)` (or let `try ctx.decode(_:)` propagate); the
// engine's error boundary maps an `HTTPError` to its status as `application/problem+json`, and any
// OTHER thrown error to a 500 problem. Response factories (`.created`/`.noContent`/`.redirect`/…)
// keep handlers from hand-rolling `.full(...)` for common REST shapes.

import ADJSON
public import HTTPTypes

// MARK: - Typed error

/// An error a handler throws to produce a specific HTTP status. Carries an optional human `detail`
/// and extra response headers (e.g. `WWW-Authenticate` on a 401, `Retry-After` on a 429).
public struct HTTPError: Error, Sendable, CustomStringConvertible {
    public var status: HTTPResponse.Status
    public var detail: String?
    public var headers: HTTPFields

    public init(_ status: HTTPResponse.Status, _ detail: String? = nil, headers: HTTPFields = [:]) {
        self.status = status
        self.detail = detail
        self.headers = headers
    }

    public var description: String {
        "HTTPError(\(status.code) \(status.reasonPhrase)\(detail.map { ": \($0)" } ?? ""))"
    }

    public static func badRequest(_ detail: String? = nil) -> HTTPError { .init(.badRequest, detail) }
    public static func unauthorized(_ detail: String? = nil) -> HTTPError { .init(.unauthorized, detail) }
    public static func forbidden(_ detail: String? = nil) -> HTTPError { .init(.forbidden, detail) }
    public static func notFound(_ detail: String? = nil) -> HTTPError { .init(.notFound, detail) }
    public static func conflict(_ detail: String? = nil) -> HTTPError { .init(.conflict, detail) }
    public static func unsupportedMediaType(_ detail: String? = nil) -> HTTPError {
        .init(HTTPResponse.Status(code: 415), detail)
    }
    public static func contentTooLarge(_ detail: String? = nil) -> HTTPError {
        .init(HTTPResponse.Status(code: 413), detail)
    }
    public static func unprocessableContent(_ detail: String? = nil) -> HTTPError {
        .init(HTTPResponse.Status(code: 422), detail)
    }
    public static func tooManyRequests(_ detail: String? = nil) -> HTTPError {
        .init(HTTPResponse.Status(code: 429), detail)
    }
    public static func internalServerError(_ detail: String? = nil) -> HTTPError {
        .init(.internalServerError, detail)
    }
}

// MARK: - RFC 9457 problem details

/// The `application/problem+json` body shape (RFC 9457) for typed REST errors.
public struct ProblemDetails: Encodable, Sendable {
    public var type: String
    public var title: String
    public var status: Int
    public var detail: String?
    public var instance: String?

    public init(
        type: String = "about:blank", title: String, status: Int, detail: String? = nil,
        instance: String? = nil
    ) {
        self.type = type
        self.title = title
        self.status = status
        self.detail = detail
        self.instance = instance
    }
}

// MARK: - Response factories

extension ResponseContent {
    /// An `application/problem+json` (RFC 9457) response.
    public static func problem(_ problem: ProblemDetails, headers: HTTPFields = [:]) -> ResponseContent {
        let bytes =
            (try? ADJSON.JSONEncoder().encodeToBytes(problem))
            ?? Array(#"{"title":"Internal Server Error","status":500}"#.utf8)
        return .full(
            body: bytes, contentType: "application/problem+json",
            status: HTTPResponse.Status(code: problem.status), headers: headers)
    }

    /// The problem response for a thrown `HTTPError` (used by the engine's error boundary).
    public static func problem(_ error: HTTPError, instance: String? = nil) -> ResponseContent {
        problem(
            ProblemDetails(
                title: error.status.reasonPhrase, status: error.status.code, detail: error.detail,
                instance: instance), headers: error.headers)
    }

    /// `201 Created`, optionally with a `Location` header.
    public static func created(
        _ bytes: [UInt8] = [], contentType: String = "application/json;charset=utf-8",
        location: String? = nil
    ) -> ResponseContent {
        var headers = HTTPFields()
        if let location { headers[.location] = location }
        return .full(body: bytes, contentType: contentType, status: .created, headers: headers)
    }

    /// `204 No Content`.
    public static var noContent: ResponseContent {
        .full(body: [], contentType: "text/plain; charset=utf-8", status: .noContent, headers: HTTPFields())
    }

    /// `202 Accepted`.
    public static func accepted(
        _ bytes: [UInt8] = [], contentType: String = "application/json;charset=utf-8"
    ) -> ResponseContent {
        .full(body: bytes, contentType: contentType, status: .accepted, headers: HTTPFields())
    }

    /// A redirect to `location` — `303 See Other` by default, `308 Permanent Redirect` when `permanent`.
    public static func redirect(to location: String, permanent: Bool = false) -> ResponseContent {
        var headers = HTTPFields()
        headers[.location] = location
        return .full(
            body: [], contentType: "text/plain; charset=utf-8",
            status: HTTPResponse.Status(code: permanent ? 308 : 303), headers: headers)
    }

    /// A bare status with an empty body (e.g. `.status(.notModified)`).
    public static func status(_ status: HTTPResponse.Status) -> ResponseContent {
        .full(body: [], contentType: "text/plain; charset=utf-8", status: status, headers: HTTPFields())
    }
}
