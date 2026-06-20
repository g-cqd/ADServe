import HTTPTypes
import Logging
import Testing

import ADServeCore
import ADServeDSL

// A DTO for the codec round-trip tests.
private struct Item: Codable, Equatable, Sendable {
    let id: Int
    let name: String
}

// Build the engine's RouteTable from a DSL `Server { App { … } }`.
private func table(@RouteGroupBuilder _ routes: () -> [RouteNode]) -> any HTTPHandling {
    let nodes = routes()
    let apps = Server { App(pool: .none) { nodes } }
    return listeners(apps, defaultPort: 8080)[0].routes
}

private func runMatched(
    _ table: any HTTPHandling, _ method: HTTPRequest.Method, _ path: String, body: [UInt8] = [],
    codec: ContentCodec = .json
) -> ResponseContent? {
    guard case .matched(let route) = table.match(method: method, path: path[...]) else { return nil }
    let request = ServerRequest(method: method, target: path, headers: HTTPFields(), body: body)
    return try? route.run(
        HandlerInput(request: request, connection: nil, logger: Logger(label: "t"), requestID: "r", codec: codec))
}

private func plain(_ content: ResponseContent?) -> (HTTPResponse.Status, String)? {
    guard case .plain(let status, let message)? = content else { return nil }
    return (status, message)
}

@Suite("Path templates")
struct PathTemplateTests {
    @Test("binds named segments and parses typed captures")
    func bindsAndTypes() {
        let params = PathTemplate("items/{id}/comments/{cid}").match("/items/42/comments/7")
        #expect(params?.id == "42")
        #expect(params?["cid"] == "7")
        #expect(params?.int("id") == 42)
        #expect(params?.int("cid") == 7)
    }

    @Test("rejects literal mismatch, and segment-count mismatch")
    func rejects() {
        let template = PathTemplate("items/{id}")
        #expect(template.match("/widgets/42") == nil)  // literal mismatch
        #expect(template.match("/items") == nil)  // too few
        #expect(template.match("/items/42/extra") == nil)  // too many
        #expect(template.match("/items/42")?.id == "42")
    }

    @Test("trailing catch-all captures the remainder including slashes")
    func catchAll() {
        let params = PathTemplate("files/{path*}").match("/files/a/b/c.txt")
        #expect(params?.path == "a/b/c.txt")
    }

    @Test("percent-decodes captures and rejects encoded traversal / separators")
    func decodingAndTraversal() {
        #expect(PathTemplate("items/{id}").match("/items/a%20b")?.id == "a b")  // %20 → space
        #expect(PathTemplate("items/{id}").match("/items/%2e%2e") == nil)  // encoded ".."
        #expect(PathTemplate("items/{id}").match("/items/a%2Fb") == nil)  // encoded "/" in a param
        #expect(PathTemplate("files/{rest*}").match("/files/a/%2e%2e/etc") == nil)  // encoded ".." in catch-all
        #expect(PathTemplate("files/{rest*}").match("/files/a/b/c.txt")?.rest == "a/b/c.txt")  // normal
        #expect(PathTemplate("items/{id}").match("/items/a%ZZb") == nil)  // malformed escape
    }

    @Test("pathHasTraversal flags literal dot-segments")
    func traversalDetection() {
        #expect(pathHasTraversal("/a/../b"[...]))
        #expect(pathHasTraversal("/a/./b"[...]))
        #expect(!pathHasTraversal("/a/b/c"[...]))
        #expect(!pathHasTraversal("/items/42"[...]))
    }
}

@Suite("REST verbs + typed routing")
struct RESTRoutingTests {
    @Test("each verb routes; typed path params reach the handler")
    func verbsAndParams() {
        let routes = table {
            GET("items/{id}", pool: .none) { _, params in .plain(.ok, "get-\(params.id ?? "?")") }
            POST("items", pool: .none) { _ in .plain(.created, "made") }
            PUT("items/{id}", pool: .none) { _, params in .plain(.ok, "put-\(params.id ?? "?")") }
            PATCH("items/{id}", pool: .none) { _, params in .plain(.ok, "patch-\(params.id ?? "?")") }
            DELETE("items/{id}", pool: .none) { _, params in .plain(.ok, "del-\(params.id ?? "?")") }
        }
        #expect(plain(runMatched(routes, .get, "/items/42"))?.1 == "get-42")
        #expect(plain(runMatched(routes, .post, "/items"))?.0 == .created)
        #expect(plain(runMatched(routes, .put, "/items/7"))?.1 == "put-7")
        #expect(plain(runMatched(routes, .patch, "/items/9"))?.1 == "patch-9")
        #expect(plain(runMatched(routes, .delete, "/items/3"))?.1 == "del-3")
    }

    @Test("Group prefix composes with typed templates")
    func groupCompose() {
        let routes = table {
            Group("api/v1") {
                GET("items/{id}", pool: .none) { _, params in .plain(.ok, params.id ?? "?") }
            }
        }
        #expect(plain(runMatched(routes, .get, "/api/v1/items/55"))?.1 == "55")
        #expect(runMatched(routes, .get, "/items/55") == nil)  // un-prefixed does not match
    }

    @Test("unknown method on a known path → methodNotAllowed with the Allow set; unknown path → notFound")
    func methodNotAllowedAndNotFound() {
        let routes = table {
            GET("items/{id}", pool: .none) { _, params in .plain(.ok, params.id ?? "?") }
            DELETE("items/{id}", pool: .none) { _, _ in .plain(.ok, "del") }
        }
        guard case .methodNotAllowed(let allowed) = routes.match(method: .put, path: "/items/1"[...]) else {
            Issue.record("expected methodNotAllowed")
            return
        }
        #expect(allowed.contains(.get))
        #expect(allowed.contains(.delete))
        guard case .notFound = routes.match(method: .get, path: "/nope"[...]) else {
            Issue.record("expected notFound")
            return
        }
    }
}

@Suite("Request helpers + content codec")
struct RequestHelperTests {
    private func context(target: String, body: [UInt8] = [], codec: ContentCodec = .json) -> RequestContext {
        RequestContext(
            HandlerInput(
                request: ServerRequest(method: .post, target: target, headers: HTTPFields(), body: body),
                connection: nil, logger: Logger(label: "t"), requestID: "r", codec: codec))
    }

    @Test("ctx.query parses + percent-decodes")
    func query() {
        let ctx = context(target: "/search?q=hello%20world&limit=10&flag")
        #expect(ctx.query["q"] == "hello world")
        #expect(ctx.query.q == "hello world")  // dynamic member
        #expect(ctx.query["limit"] == "10")
        #expect(ctx.query["flag"] == "")
        #expect(ctx.query["absent"] == nil)
    }

    @Test("ctx.query typed accessors: int/bool/double/require")
    func typedQuery() throws {
        let ctx = context(target: "/search?limit=10&ratio=1.5&verbose&debug=false")
        #expect(ctx.query.int("limit") == 10)
        #expect(ctx.query.int("ratio") == nil)  // not an integer
        #expect(ctx.query.double("ratio") == 1.5)
        #expect(ctx.query.bool("verbose") == true)  // bare flag
        #expect(ctx.query.bool("debug") == false)
        #expect(ctx.query.bool("absent") == nil)
        #expect(try ctx.query.require("limit") == "10")
        #expect(try ctx.query.requireInt("limit") == 10)
        #expect(throws: HTTPError.self) { _ = try ctx.query.require("absent") }
        #expect(throws: HTTPError.self) { _ = try ctx.query.requireInt("ratio") }
    }

    @Test("default JSON codec round-trips decode/encode")
    func jsonRoundTrip() throws {
        let item = Item(id: 7, name: "gear")
        let (bytes, contentType) = try ContentCodec.json.encoder.encode(item)
        #expect(contentType == "application/json;charset=utf-8")
        let back = try ContentCodec.json.decoder.decode(Item.self, from: bytes, contentType: nil)
        #expect(back == item)
    }

    @Test("ctx.decode reads a typed JSON body")
    func decodeBody() throws {
        let ctx = context(target: "/items", body: Array(#"{"id":3,"name":"bolt"}"#.utf8))
        let item = try ctx.decode(Item.self)
        #expect(item == Item(id: 3, name: "bolt"))
    }

    @Test("ctx.json + ctx.decode route through a CUSTOM codec, not ADJSON")
    func customCodec() throws {
        // Encoder emits a fixed marker; decoder ignores the body and returns a fixed value — both
        // prove the pluggable port is what runs.
        struct MarkerEncoder: ResponseBodyEncoder {
            func encode<T: Encodable>(_ value: T) throws -> (bytes: [UInt8], contentType: String) {
                (Array("MARKER".utf8), "application/x-marker")
            }
        }
        struct FixedDecoder: RequestBodyDecoder {
            func decode<T: Decodable>(_ type: T.Type, from body: [UInt8], contentType: String?) throws -> T {
                try JSONBodyCodec().decode(type, from: Array(#"{"id":99,"name":"fixed"}"#.utf8), contentType: nil)
            }
        }
        let codec = ContentCodec(decoder: FixedDecoder(), encoder: MarkerEncoder())
        let ctx = context(target: "/items", body: Array(#"{"id":1,"name":"real"}"#.utf8), codec: codec)

        guard case .raw(let bytes, let contentType, _) = try ctx.json(Item(id: 1, name: "x")) else {
            Issue.record("expected .raw")
            return
        }
        #expect(String(decoding: bytes, as: UTF8.self) == "MARKER")
        #expect(contentType == "application/x-marker")
        #expect(try ctx.decode(Item.self) == Item(id: 99, name: "fixed"))  // decoder ignored the real body
    }
}

@Suite("Middleware pipeline")
struct MiddlewareTests {
    private actor OrderLog {
        private(set) var entries: [String] = []
        func append(_ entry: String) { entries.append(entry) }
    }

    private struct Recorder: HTTPMiddleware {
        let tag: String
        let log: OrderLog
        func intercept(
            _ request: ServerRequest, _ context: MiddlewareContext,
            next: @Sendable (ServerRequest) async -> ResponseContent
        ) async -> ResponseContent {
            await log.append("\(tag)-in")
            let response = await next(request)
            await log.append("\(tag)-out")
            return response
        }
    }

    private struct Gate: HTTPMiddleware {
        func intercept(
            _ request: ServerRequest, _ context: MiddlewareContext,
            next: @Sendable (ServerRequest) async -> ResponseContent
        ) async -> ResponseContent {
            .plain(.unauthorized, "denied")  // never calls next
        }
    }

    private let request = ServerRequest(method: .get, target: "/", headers: HTTPFields())
    private let mwContext = MiddlewareContext(requestID: "r", logger: Logger(label: "t"))

    @Test("onion order: outer-in then inner-out, with the handler in the center")
    func onionOrder() async {
        let log = OrderLog()
        let terminal: @Sendable (ServerRequest) async -> ResponseContent = { _ in
            await log.append("handler")
            return .plain(.ok, "ok")
        }
        let chain = composeMiddleware(
            [Recorder(tag: "A", log: log), Recorder(tag: "B", log: log)], context: mwContext,
            terminal: terminal)
        _ = await chain(request)
        #expect(await log.entries == ["A-in", "B-in", "handler", "B-out", "A-out"])
    }

    @Test("a middleware can short-circuit — the handler never runs")
    func shortCircuit() async {
        let log = OrderLog()
        let terminal: @Sendable (ServerRequest) async -> ResponseContent = { _ in
            await log.append("handler")
            return .plain(.ok, "ok")
        }
        let chain = composeMiddleware([Gate()], context: mwContext, terminal: terminal)
        let response = await chain(request)
        #expect(await log.entries.isEmpty)
        if case .plain(let status, _) = response {
            #expect(status == .unauthorized)
        } else {
            Issue.record("expected the gate's 401")
        }
    }
}

@Suite("Observability middleware")
struct ObservabilityTests {
    private let request = ServerRequest(method: .get, target: "/items/9?x=1", headers: HTTPFields())

    @Test("statusCode(of:) extracts the numeric status of every response shape")
    func statusExtraction() {
        #expect(statusCode(of: .plain(.ok, "x")) == 200)
        #expect(statusCode(of: .notFound) == 404)
        #expect(statusCode(of: .raw(body: [], contentType: "x", status: .created)) == 201)
        #expect(
            statusCode(of: .full(body: [], contentType: "x", status: .noContent, headers: HTTPFields()))
                == 204)
    }

    @Test("RequestLogging runs and passes the response through unchanged")
    func passThrough() async {
        let terminal: @Sendable (ServerRequest) async -> ResponseContent = { _ in .plain(.ok, "ok") }
        let ctx = MiddlewareContext(requestID: "rid-1", logger: Logger(label: "test"))
        // threshold 0 exercises the slow-request `.warning` branch; threshold high exercises `.info`.
        for middleware in [RequestLogging(slowThresholdMillis: 0), RequestLogging(slowThresholdMillis: 1e9)] {
            let chain = composeMiddleware([middleware], context: ctx, terminal: terminal)
            guard case .plain(let status, let body) = await chain(request) else {
                Issue.record("response not passed through")
                return
            }
            #expect(status == .ok)
            #expect(body == "ok")
        }
    }
}

@Suite("Errors + response factories")
struct ErrorTests {
    @Test("a throwing handler propagates HTTPError through the route's run")
    func handlerThrows() {
        let routes = table {
            GET("boom", pool: .none) { _ in throw HTTPError.badRequest("no") }
        }
        guard case .matched(let route) = routes.match(method: .get, path: "/boom"[...]) else {
            Issue.record("expected match")
            return
        }
        #expect(throws: HTTPError.self) {
            _ = try route.run(
                HandlerInput(
                    request: ServerRequest(method: .get, target: "/boom", headers: HTTPFields()),
                    connection: nil, logger: Logger(label: "t"), requestID: "r"))
        }
    }

    @Test("response factories produce the right status, headers, and problem body")
    func factories() {
        if case .full(_, _, let status, let headers) = ResponseContent.created(location: "/items/1") {
            #expect(status == .created)
            #expect(headers[.location] == "/items/1")
        } else {
            Issue.record(".created shape")
        }
        if case .full(_, _, let status, _) = ResponseContent.noContent { #expect(status == .noContent) }
        if case .full(_, _, let status, let headers) = ResponseContent.redirect(to: "/x") {
            #expect(status.code == 303)
            #expect(headers[.location] == "/x")
        } else {
            Issue.record(".redirect shape")
        }
        if case .full(_, _, let status, _) = ResponseContent.redirect(to: "/x", permanent: true) {
            #expect(status.code == 308)
        }
        if case .full(let body, let contentType, let status, _) = ResponseContent.problem(
            HTTPError.notFound("gone"))
        {
            #expect(status == .notFound)
            #expect(contentType == "application/problem+json")
            let text = String(decoding: body, as: UTF8.self)
            #expect(text.contains("404"))
            #expect(text.contains("gone"))
        } else {
            Issue.record(".problem shape")
        }
    }
}

private func fieldName(_ token: String) -> HTTPField.Name { HTTPField.Name(token)! }
private enum CurrentUser: StorageKey { typealias Value = String }
private struct SetUser: HTTPMiddleware {
    func intercept(
        _ request: ServerRequest, _ context: MiddlewareContext,
        next: @Sendable (ServerRequest) async -> ResponseContent
    ) async -> ResponseContent {
        context.storage[CurrentUser.self] = "alice"
        return await next(request)
    }
}

@Suite("Middleware — CORS, security headers, storage, 415")
struct MiddlewareBuiltinsTests {
    private let ctx = MiddlewareContext(requestID: "r", logger: Logger(label: "t"))

    @Test("CORS owns the preflight (204 + Allow set) and never calls the handler")
    func corsPreflight() async {
        let chain = composeMiddleware(
            [CORS(allowOrigin: "https://x.com", allowMethods: [.get, .post])], context: ctx,
            terminal: { _ in .plain(.ok, "handler ran") })
        var headers = HTTPFields()
        headers[fieldName("access-control-request-method")] = "GET"
        let response = await chain(ServerRequest(method: .options, target: "/x", headers: headers))
        guard case .full(_, _, let status, let h) = response else {
            Issue.record("preflight not a full response")
            return
        }
        #expect(status == .noContent)  // 204, not the handler's 200 → handler never ran
        #expect(h[fieldName("access-control-allow-origin")] == "https://x.com")
        #expect(h[fieldName("access-control-allow-methods")]?.contains("GET") == true)
    }

    @Test("CORS decorates an actual request's response with Allow-Origin")
    func corsActual() async {
        let chain = composeMiddleware(
            [CORS(allowOrigin: "https://x.com")], context: ctx, terminal: { _ in .plain(.ok, "ok") })
        let response = await chain(ServerRequest(method: .get, target: "/x", headers: HTTPFields()))
        guard case .full(_, _, let status, let h) = response else {
            Issue.record("not decorated")
            return
        }
        #expect(status == .ok)  // handler ran
        #expect(h[fieldName("access-control-allow-origin")] == "https://x.com")
    }

    @Test("SecurityHeaders decorates the response")
    func securityHeaders() async {
        let chain = composeMiddleware([SecurityHeaders()], context: ctx, terminal: { _ in .plain(.ok, "ok") })
        let response = await chain(ServerRequest(method: .get, target: "/", headers: HTTPFields()))
        if case .full(_, _, _, let h) = response {
            #expect(h[fieldName("x-content-type-options")] == "nosniff")
            #expect(h[fieldName("x-frame-options")] == "DENY")
        } else {
            Issue.record("not decorated")
        }
    }

    @Test("request storage is shared middleware → handler")
    func requestStorage() async {
        let storage = RequestStorage()
        let context = MiddlewareContext(requestID: "r", logger: Logger(label: "t"), storage: storage)
        let chain = composeMiddleware([SetUser()], context: context, terminal: { _ in .plain(.ok, "ok") })
        _ = await chain(ServerRequest(method: .get, target: "/", headers: HTTPFields()))
        #expect(storage[CurrentUser.self] == "alice")
    }

    @Test("the JSON codec rejects a non-JSON content type with 415")
    func unsupportedMediaType() throws {
        let body = Array(#"{"id":1,"name":"x"}"#.utf8)
        #expect(throws: HTTPError.self) {
            _ = try JSONBodyCodec().decode(Item.self, from: body, contentType: "text/xml")
        }
        #expect(try JSONBodyCodec().decode(Item.self, from: body, contentType: "application/json") == Item(id: 1, name: "x"))
        #expect(try JSONBodyCodec().decode(Item.self, from: body, contentType: nil) == Item(id: 1, name: "x"))
    }
}

@Suite("Per-route body limit")
struct BodyLimitTests {
    @Test(".maxBody surfaces on the matched route; a group default applies; an inner route wins")
    func maxBodyThreading() {
        let routes = table {
            POST("upload", pool: .none) { _ in .noContent }.maxBody(10)
            Group("admin") {
                POST("small", pool: .none) { _ in .noContent }  // inherits the group's 100
                POST("tiny", pool: .none) { _ in .noContent }.maxBody(5)  // own 5 wins over the group
            }.maxBody(100)
            POST("plain", pool: .none) { _ in .noContent }  // no limit → nil
        }
        func limit(_ method: HTTPRequest.Method, _ path: String) -> Int? {
            guard case .matched(let route) = routes.match(method: method, path: path[...]) else {
                Issue.record("no route for \(method) \(path)")
                return nil
            }
            return route.maxBodyBytes
        }
        #expect(limit(.post, "/upload") == 10)
        #expect(limit(.post, "/admin/small") == 100)
        #expect(limit(.post, "/admin/tiny") == 5)
        #expect(limit(.post, "/plain") == nil)  // matched (no Issue recorded) but carries no limit
    }

    @Test("RouteTable.bodyLimit surfaces the matched route's ceiling for the engine's head-time peek")
    func bodyLimitPeek() {
        let routes = table {
            POST("upload", pool: .none) { _ in .noContent }.maxBody(50_000_000)  // upload, above any default
            POST("plain", pool: .none) { _ in .noContent }
        }
        #expect(routes.bodyLimit(method: .post, path: "/upload"[...]) == 50_000_000)
        #expect(routes.bodyLimit(method: .post, path: "/plain"[...]) == nil)
        #expect(routes.bodyLimit(method: .post, path: "/missing"[...]) == nil)  // no match → nil
    }
}

@Suite("Routing specificity order")
struct RoutingSpecificityTests {
    @Test("literal routes are scoped to their segment; param/catch-all reached by structure")
    func scoping() {
        let routes = table {
            GET("items/{id}", pool: .none) { _, p in .plain(.ok, "item-\(p.id ?? "?")") }
            GET("users/{id}", pool: .none) { _, p in .plain(.ok, "user-\(p.id ?? "?")") }
            GET("{resource}/{id}/raw", pool: .none) { _, p in .plain(.ok, "raw-\(p.resource ?? "?")") }
        }
        #expect(plain(runMatched(routes, .get, "/items/42"))?.1 == "item-42")
        #expect(plain(runMatched(routes, .get, "/users/7"))?.1 == "user-7")
        #expect(plain(runMatched(routes, .get, "/anything/9/raw"))?.1 == "raw-anything")  // param-first reached
        #expect(runMatched(routes, .get, "/nope/1") == nil)  // no 2-segment route for first-segment "nope"
    }

    @Test(
        "a literal segment beats a {param} regardless of declaration order",
        arguments: [true, false])
    func literalBeatsParam(literalFirst: Bool) {
        // Build the SAME overlapping pair in both declaration orders; specificity must pick the literal
        // `items/{id}` for `/items/5` either way — proving the result no longer depends on order.
        let routes: any HTTPHandling
        if literalFirst {
            routes = table {
                GET("items/{id}", pool: .none) { _, p in .plain(.ok, "lit-\(p.id ?? "?")") }
                GET("{resource}/{id}", pool: .none) { _, p in .plain(.ok, "wild-\(p.resource ?? "?")") }
            }
        } else {
            routes = table {
                GET("{resource}/{id}", pool: .none) { _, p in .plain(.ok, "wild-\(p.resource ?? "?")") }
                GET("items/{id}", pool: .none) { _, p in .plain(.ok, "lit-\(p.id ?? "?")") }
            }
        }
        #expect(plain(runMatched(routes, .get, "/items/5"))?.1 == "lit-5")  // literal wins both orders
        #expect(plain(runMatched(routes, .get, "/widgets/9"))?.1 == "wild-widgets")  // param catches the rest
    }
}

@Suite("Routing trie — adversarial")
struct RoutingTrieAdversarialTests {
    @Test("exact beats param beats catch-all at one position")
    func specificityLadder() {
        let routes = table {
            GET("files/readme", pool: .none) { _ in .plain(.ok, "exact") }
            GET("files/{id}", pool: .none) { _, p in .plain(.ok, "param-\(p.id ?? "?")") }
            GET("files/{rest*}", pool: .none) { _, p in .plain(.ok, "catchall-\(p.rest ?? "?")") }
        }
        #expect(plain(runMatched(routes, .get, "/files/readme"))?.1 == "exact")
        #expect(plain(runMatched(routes, .get, "/files/other"))?.1 == "param-other")
        #expect(plain(runMatched(routes, .get, "/files/a/b"))?.1 == "catchall-a/b")
    }

    @Test("backtracks when a more-specific branch dead-ends")
    func backtracking() {
        let routes = table {
            GET("a/b/c", pool: .none) { _ in .plain(.ok, "exact-abc") }
            GET("a/{x}", pool: .none) { _, p in .plain(.ok, "ax-\(p.x ?? "?")") }
            GET("a/{x}/{y}", pool: .none) { _, p in .plain(.ok, "axy-\(p.x ?? "?")-\(p.y ?? "?")") }
            GET("{p}/{q}", pool: .none) { _, p in .plain(.ok, "pq-\(p.p ?? "?")") }
        }
        #expect(plain(runMatched(routes, .get, "/a/b/c"))?.1 == "exact-abc")  // exact wins
        #expect(plain(runMatched(routes, .get, "/a/zzz"))?.1 == "ax-zzz")  // literal "a" then param {x}
        // The literal "a/b" branch dead-ends on the 3rd segment "d"; backtrack into "a"'s param subtree.
        #expect(plain(runMatched(routes, .get, "/a/b/d"))?.1 == "axy-b-d")
        #expect(plain(runMatched(routes, .get, "/m/n"))?.1 == "pq-m")  // root-level param branch
    }

    @Test("405 collects every method at a node, de-duplicated")
    func methodNotAllowedAtNode() {
        let routes = table {
            GET("items/{id}", pool: .none) { _, p in .plain(.ok, p.id ?? "?") }
            DELETE("items/{id}", pool: .none) { _, _ in .plain(.ok, "del") }
            PATCH("items/{id}", pool: .none) { _, _ in .plain(.ok, "patch") }
        }
        guard case .methodNotAllowed(let allowed) = routes.match(method: .put, path: "/items/1"[...]) else {
            Issue.record("expected methodNotAllowed")
            return
        }
        #expect(Set(allowed) == [.get, .delete, .patch])
        #expect(allowed.count == 3)  // no duplicates
    }

    @Test("405 unions methods across backtracking branches")
    func methodNotAllowedUnion() {
        let routes = table {
            GET("{a}/{b}", pool: .none) { _, _ in .plain(.ok, "ab") }
            POST("files/{rest*}", pool: .none) { _, _ in .plain(.ok, "files") }
        }
        // DELETE /files/x reaches GET via {a}/{b} AND POST via files/{rest*} — two different terminals.
        guard case .methodNotAllowed(let allowed) = routes.match(method: .delete, path: "/files/x"[...]) else {
            Issue.record("expected methodNotAllowed union")
            return
        }
        #expect(allowed.contains(.get))
        #expect(allowed.contains(.post))
    }

    @Test("exact path and a param overlap: exact serves its method; both fold into the 405 set")
    func exactParamMethodSplit() {
        let routes = table {
            GET("users/me", pool: .none) { _ in .plain(.ok, "me") }
            GET("users/{id}", pool: .none) { _, p in .plain(.ok, "id-\(p.id ?? "?")") }
        }
        #expect(plain(runMatched(routes, .get, "/users/me"))?.1 == "me")  // exact wins
        #expect(plain(runMatched(routes, .get, "/users/42"))?.1 == "id-42")  // param for the rest
        guard case .methodNotAllowed(let allowed) = routes.match(method: .post, path: "/users/me"[...]) else {
            Issue.record("expected methodNotAllowed")
            return
        }
        #expect(allowed == [.get])  // exact GET + param GET, de-duped to a single entry
    }

    @Test("encoded traversal is rejected under specificity backtracking")
    func encodedTraversalRejected() {
        let routes = table {
            GET("files/{id}", pool: .none) { _, p in .plain(.ok, "id-\(p.id ?? "?")") }
            GET("files/{rest*}", pool: .none) { _, p in .plain(.ok, "rest-\(p.rest ?? "?")") }
        }
        #expect(runMatched(routes, .get, "/files/%2e%2e") == nil)  // encoded ".." — param + catch-all both reject
        #expect(runMatched(routes, .get, "/files/a%2Fb") == nil)  // encoded "/" in a single param
        #expect(runMatched(routes, .get, "/files/a/%2e%2e/x") == nil)  // encoded ".." inside the catch-all
        #expect(plain(runMatched(routes, .get, "/files/readme"))?.1 == "id-readme")  // normal → param
        #expect(plain(runMatched(routes, .get, "/files/a/b/c"))?.1 == "rest-a/b/c")  // normal multi → catch-all
    }

    @Test("root path matches, and 405/404 behave at the root")
    func rootPath() {
        let routes = table {
            GET("/", pool: .none) { _ in .plain(.ok, "root") }
        }
        #expect(plain(runMatched(routes, .get, "/"))?.1 == "root")
        guard case .methodNotAllowed(let allowed) = routes.match(method: .post, path: "/"[...]) else {
            Issue.record("expected methodNotAllowed at root")
            return
        }
        #expect(allowed.contains(.get))
        #expect(runMatched(routes, .get, "/anything") == nil)
    }

    @Test("opaque GET(match:) matchers are residual — the trie wins; opaque serves only trie misses")
    func opaqueCoexistence() {
        let routes = table {
            GET("items/{id}", pool: .none) { _, p in .plain(.ok, "trie-\(p.id ?? "?")") }
            GET(match: { $0.hasPrefix("/legacy/") ? true : nil }, pool: .none) { _, _ in .plain(.ok, "opaque") }
        }
        #expect(plain(runMatched(routes, .get, "/items/9"))?.1 == "trie-9")  // structured route wins
        #expect(plain(runMatched(routes, .get, "/legacy/x"))?.1 == "opaque")  // only the opaque matcher fits
        #expect(runMatched(routes, .get, "/nope") == nil)  // neither
        // The opaque matcher still contributes its method to a 405 for a path it accepts.
        guard case .methodNotAllowed(let allowed) = routes.match(method: .post, path: "/legacy/x"[...]) else {
            Issue.record("expected methodNotAllowed from the opaque-only path")
            return
        }
        #expect(allowed.contains(.get))
    }
}
