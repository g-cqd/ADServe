// RFC-0019 (reactive hypermedia) — ADServe's transport seam: `ctx.isFragment` (the `ADH-Request` signal,
// C1) and `ResponseContent.fragment` (a text/html partial, C2), so ONE route serves a full page on first
// load and a morphable fragment on a client action.

import ADServeCore
import HTTPCore
import Logging
import Testing

@testable import ADServeDSL

private func table(@RouteGroupBuilder _ routes: () -> [RouteNode]) -> any HTTPHandling {
    listeners(Server { App(pool: .none) { routes() } }, defaultPort: 8080)[0].routes
}

private func run(
    _ table: any HTTPHandling, _ method: HTTPMethod, _ path: String, headers: HTTPFields = HTTPFields()
) -> ResponseContent? {
    guard case .matched(let route) = table.match(method: method, path: path[...]) else { return nil }
    let request = ServerRequest(method: method, target: path, headers: headers, body: [])
    return try? route.run(
        HandlerInput(request: request, connection: nil, logger: Logger(label: "t"), requestID: "r", codec: .json))
}

private func raw(_ content: ResponseContent?) -> (body: String, contentType: String)? {
    guard case .raw(let body, let contentType, _)? = content else { return nil }
    return (String(decoding: body, as: UTF8.self), contentType)
}

@Suite struct ReactiveHypermediaTests {
    /// `ctx.isFragment` is true exactly when the request carries `ADH-Request` (C1) → the same route
    /// serves a full page on navigation and a morphable fragment on a client action.
    @Test func isFragmentDrivesTheRouteTwoWays() {
        let routes = table {
            GET("parts", pool: .none) { ctx in
                ctx.isFragment
                    ? .fragment(Array("<tr>row</tr>".utf8))
                    : .html(Array("<!doctype html><html>page</html>".utf8))
            }
        }
        // Plain navigation (no header) → full page.
        #expect(raw(run(routes, .get, "/parts"))?.body == "<!doctype html><html>page</html>")
        // An ADHTML action fetch (`ADH-Request: 1`) → the fragment.
        var headers = HTTPFields()
        headers.setValue("1", for: HTTPFieldName("ADH-Request")!)
        let fragment = raw(run(routes, .get, "/parts", headers: headers))
        #expect(fragment?.body == "<tr>row</tr>")
        #expect(fragment?.contentType == MediaType.html.value)  // text/html; charset=utf-8 (C2)
    }

    /// `.fragment` is a `text/html; charset=utf-8` partial with an overridable status — wire-identical to
    /// `.html`, distinct only in intent.
    @Test func fragmentIsATextHTMLPartial() {
        guard
            case .raw(let body, let contentType, let status) = ResponseContent.fragment(
                Array("<li>x</li>".utf8), status: .created)
        else {
            Issue.record("fragment is not a .raw response")
            return
        }
        #expect(contentType == MediaType.html.value)
        #expect(contentType.contains("text/html"))  // C2 wire contract
        #expect(status == .created)
        #expect(String(decoding: body, as: UTF8.self) == "<li>x</li>")
    }
}
