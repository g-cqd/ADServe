import ADServeCore
import HTTPCore
import HTTPServer
import Logging
import Testing
import WebSocket

@testable import ADServeDSL

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
    _ table: any HTTPHandling, _ method: HTTPMethod, _ path: String, body: [UInt8] = [],
    codec: ContentCodec = .json
) -> ResponseContent? {
    guard case .matched(let route) = table.match(method: method, path: path[...]) else { return nil }
    let request = ServerRequest(method: method, target: path, headers: HTTPFields(), body: body)
    return try? route.run(
        HandlerInput(request: request, connection: nil, logger: Logger(label: "t"), requestID: "r", codec: codec))
}

private func plain(_ content: ResponseContent?) -> (HTTPStatus, String)? {
    guard case .plain(let status, let message)? = content else { return nil }
    return (status, message)
}

struct PathTemplateTests {
    @Test
    func `binds named segments and parses typed captures`() {
        let params = PathTemplate("items/{id}/comments/{cid}").match("/items/42/comments/7")
        #expect(params?.id == "42")
        #expect(params?["cid"] == "7")
        #expect(params?.int("id") == 42)
        #expect(params?.int("cid") == 7)
    }

    @Test
    func `rejects literal mismatch, and segment-count mismatch`() {
        let template = PathTemplate("items/{id}")
        #expect(template.match("/widgets/42") == nil)  // literal mismatch
        #expect(template.match("/items") == nil)  // too few
        #expect(template.match("/items/42/extra") == nil)  // too many
        #expect(template.match("/items/42")?.id == "42")
    }

    @Test
    func `trailing catch-all captures the remainder including slashes`() {
        let params = PathTemplate("files/{path*}").match("/files/a/b/c.txt")
        #expect(params?.path == "a/b/c.txt")
    }

    @Test
    func `percent-decodes captures and rejects encoded traversal / separators`() {
        #expect(PathTemplate("items/{id}").match("/items/a%20b")?.id == "a b")  // %20 → space
        #expect(PathTemplate("items/{id}").match("/items/%2e%2e") == nil)  // encoded ".."
        #expect(PathTemplate("items/{id}").match("/items/a%2Fb") == nil)  // encoded "/" in a param
        #expect(PathTemplate("files/{rest*}").match("/files/a/%2e%2e/etc") == nil)  // encoded ".." in catch-all
        #expect(PathTemplate("files/{rest*}").match("/files/a/b/c.txt")?.rest == "a/b/c.txt")  // normal
        #expect(PathTemplate("items/{id}").match("/items/a%ZZb") == nil)  // malformed escape
    }

    @Test
    func `rejects NUL and control bytes (open() truncation guard)`() {
        // A smuggled NUL can truncate the path at open(), serving a different file than the extension
        // allow-list checked — so `decodeSegment` rejects any C0/DEL byte, on the decoded bytes.
        #expect(PathTemplate("items/{id}").match("/items/passwd%00.css") == nil)  // NUL truncation attempt
        #expect(PathTemplate("items/{id}").match("/items/%00") == nil)  // bare encoded NUL
        #expect(PathTemplate("files/{rest*}").match("/files/a/%09/b") == nil)  // TAB (C0) in catch-all
        #expect(PathTemplate("items/{id}").match("/items/x%7fy") == nil)  // DEL (0x7f)
        #expect(PathTemplate("items/{id}").match("/items/normal.css")?.id == "normal.css")  // unaffected
    }

    @Test
    func `pathHasTraversal flags literal dot-segments`() {
        #expect(PathSafety.hasTraversal("/a/../b"[...]))
        #expect(PathSafety.hasTraversal("/a/./b"[...]))
        #expect(!PathSafety.hasTraversal("/a/b/c"[...]))
        #expect(!PathSafety.hasTraversal("/items/42"[...]))
    }
}

struct RESTRoutingTests {
    @Test
    func `each verb routes; typed path params reach the handler`() {
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

    @Test
    func `Scope prefix composes with typed templates`() {
        let routes = table {
            Scope("api/v1") {
                GET("items/{id}", pool: .none) { _, params in .plain(.ok, params.id ?? "?") }
            }
        }
        #expect(plain(runMatched(routes, .get, "/api/v1/items/55"))?.1 == "55")
        #expect(runMatched(routes, .get, "/items/55") == nil)  // un-prefixed does not match
    }

    @Test
    func `unknown method on a known path → methodNotAllowed with the Allow set; unknown path → notFound`() {
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

struct RequestHelperTests {
    private func context(target: String, body: [UInt8] = [], codec: ContentCodec = .json) -> ADServeDSL.RequestContext {
        RequestContext(
            HandlerInput(
                request: ServerRequest(method: .post, target: target, headers: HTTPFields(), body: body),
                connection: nil, logger: Logger(label: "t"), requestID: "r", codec: codec))
    }

    @Test
    func `ctx.query parses + percent-decodes`() {
        let ctx = context(target: "/search?q=hello%20world&limit=10&flag")
        #expect(ctx.query["q"] == "hello world")
        #expect(ctx.query.q == "hello world")  // dynamic member
        #expect(ctx.query["limit"] == "10")
        #expect(ctx.query["flag"] == "")
        #expect(ctx.query["absent"] == nil)
    }

    @Test
    func `ctx.query typed accessors: int/bool/double/require`() throws {
        let ctx = context(target: "/search?limit=10&ratio=1.5&verbose&debug=false")
        #expect(ctx.query.int("limit") == 10)
        #expect(ctx.query.int("ratio") == nil)  // not an integer
        #expect(ctx.query.double("ratio") == 1.5)
        #expect(ctx.query.bool("verbose") == true)  // bare flag
        #expect(ctx.query.bool("debug") == false)
        #expect(ctx.query.bool("absent") == nil)
        #expect(try ctx.query.require("limit") == "10")
        #expect(try ctx.query.requireInt("limit") == 10)
        #expect(throws: ADServeCore.HTTPError.self) { _ = try ctx.query.require("absent") }
        #expect(throws: ADServeCore.HTTPError.self) { _ = try ctx.query.requireInt("ratio") }
    }

    @Test
    func `default JSON codec round-trips decode/encode`() throws {
        let item = Item(id: 7, name: "gear")
        let (bytes, contentType) = try ContentCodec.json.encoder.encode(item)
        #expect(contentType == "application/json;charset=utf-8")
        let back = try ContentCodec.json.decoder.decode(Item.self, from: bytes, contentType: nil)
        #expect(back == item)
    }

    @Test
    func `ctx.decode reads a typed JSON body`() throws {
        let ctx = context(target: "/items", body: Array(#"{"id":3,"name":"bolt"}"#.utf8))
        let item = try ctx.decode(Item.self)
        #expect(item == Item(id: 3, name: "bolt"))
    }

    @Test
    func `ctx.json + ctx.decode route through a CUSTOM codec, not ADJSON`() throws {
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

struct MiddlewareTests {
    private actor OrderLog {
        private(set) var entries: [String] = []
        func append(_ entry: String) { entries.append(entry) }
    }

    private struct Recorder: ADServeCore.HTTPMiddleware {
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

    private struct Gate: ADServeCore.HTTPMiddleware {
        func intercept(
            _ request: ServerRequest, _ context: MiddlewareContext,
            next: @Sendable (ServerRequest) async -> ResponseContent
        ) async -> ResponseContent {
            .plain(.unauthorized, "denied")  // never calls next
        }
    }

    private let request = ServerRequest(method: .get, target: "/", headers: HTTPFields())
    private let mwContext = MiddlewareContext(requestID: "r", logger: Logger(label: "t"))

    @Test
    func `onion order: outer-in then inner-out, with the handler in the center`() async {
        let log = OrderLog()
        let terminal: @Sendable (ServerRequest) async -> ResponseContent = { _ in
            await log.append("handler")
            return .plain(.ok, "ok")
        }
        let chain = MiddlewarePipeline.compose(
            [Recorder(tag: "A", log: log), Recorder(tag: "B", log: log)], context: mwContext,
            terminal: terminal)
        _ = await chain(request)
        #expect(await log.entries == ["A-in", "B-in", "handler", "B-out", "A-out"])
    }

    @Test
    func `a middleware can short-circuit — the handler never runs`() async {
        let log = OrderLog()
        let terminal: @Sendable (ServerRequest) async -> ResponseContent = { _ in
            await log.append("handler")
            return .plain(.ok, "ok")
        }
        let chain = MiddlewarePipeline.compose([Gate()], context: mwContext, terminal: terminal)
        let response = await chain(request)
        #expect(await log.entries.isEmpty)
        if case .plain(let status, _) = response {
            #expect(status == .unauthorized)
        } else {
            Issue.record("expected the gate's 401")
        }
    }
}

struct ObservabilityTests {
    private let request = ServerRequest(method: .get, target: "/items/9?x=1", headers: HTTPFields())

    @Test
    func `statusCode(of:) extracts the numeric status of every response shape`() {
        #expect(ResponseContent.plain(.ok, "x").statusCode == 200)
        #expect(ResponseContent.notFound.statusCode == 404)
        #expect(ResponseContent.raw(body: [], contentType: "x", status: .created).statusCode == 201)
        #expect(
            ResponseContent.full(body: [], contentType: "x", status: .noContent, headers: HTTPFields())
                .statusCode == 204)
    }

    @Test
    func `RequestLogging runs and passes the response through unchanged`() async {
        let terminal: @Sendable (ServerRequest) async -> ResponseContent = { _ in .plain(.ok, "ok") }
        let ctx = MiddlewareContext(requestID: "rid-1", logger: Logger(label: "test"))
        // threshold 0 exercises the slow-request `.warning` branch; threshold high exercises `.info`.
        for middleware in [RequestLogging(slowThresholdMillis: 0), RequestLogging(slowThresholdMillis: 1e9)] {
            let chain = MiddlewarePipeline.compose([middleware], context: ctx, terminal: terminal)
            guard case .plain(let status, let body) = await chain(request) else {
                Issue.record("response not passed through")
                return
            }
            #expect(status == .ok)
            #expect(body == "ok")
        }
    }
}

struct ErrorTests {
    @Test
    func `a throwing handler propagates HTTPError through the route's run`() {
        let routes = table {
            GET("boom", pool: .none) { _ in throw ADServeCore.HTTPError.badRequest("no") }
        }
        guard case .matched(let route) = routes.match(method: .get, path: "/boom"[...]) else {
            Issue.record("expected match")
            return
        }
        #expect(throws: ADServeCore.HTTPError.self) {
            _ = try route.run(
                HandlerInput(
                    request: ServerRequest(method: .get, target: "/boom", headers: HTTPFields()),
                    connection: nil, logger: Logger(label: "t"), requestID: "r"))
        }
    }

    @Test
    func `response factories produce the right status, headers, and problem body`() {
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
            ADServeCore.HTTPError.notFound("gone"))
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

private func fieldName(_ token: String) -> HTTPFieldName { HTTPFieldName(token)! }
private enum CurrentUser: StorageKey { typealias Value = String }
private struct SetUser: ADServeCore.HTTPMiddleware {
    func intercept(
        _ request: ServerRequest, _ context: MiddlewareContext,
        next: @Sendable (ServerRequest) async -> ResponseContent
    ) async -> ResponseContent {
        context.storage[CurrentUser.self] = "alice"
        return await next(request)
    }
}

struct MiddlewareBuiltinsTests {
    private let ctx = MiddlewareContext(requestID: "r", logger: Logger(label: "t"))

    @Test
    func `CORS owns the preflight (204 + Allow set) and never calls the handler`() async {
        let chain = MiddlewarePipeline.compose(
            [CORS(allowOrigin: "https://x.com", allowMethods: [.get, .post])], context: ctx,
            terminal: { _ in .plain(.ok, "handler ran") })
        var headers = HTTPFields()
        headers.setValue("GET", for: fieldName("access-control-request-method"))
        let response = await chain(ServerRequest(method: .options, target: "/x", headers: headers))
        guard case .full(_, _, let status, let h) = response else {
            Issue.record("preflight not a full response")
            return
        }
        #expect(status == .noContent)  // 204, not the handler's 200 → handler never ran
        #expect(h[fieldName("access-control-allow-origin")] == "https://x.com")
        #expect(h[fieldName("access-control-allow-methods")]?.contains("GET") == true)
    }

    @Test
    func `CORS decorates an actual request's response with Allow-Origin`() async {
        let chain = MiddlewarePipeline.compose(
            [CORS(allowOrigin: "https://x.com")], context: ctx, terminal: { _ in .plain(.ok, "ok") })
        let response = await chain(ServerRequest(method: .get, target: "/x", headers: HTTPFields()))
        guard case .full(_, _, let status, let h) = response else {
            Issue.record("not decorated")
            return
        }
        #expect(status == .ok)  // handler ran
        #expect(h[fieldName("access-control-allow-origin")] == "https://x.com")
    }

    @Test
    func `SecurityHeaders decorates the response`() async {
        let chain = MiddlewarePipeline.compose([SecurityHeaders()], context: ctx, terminal: { _ in .plain(.ok, "ok") })
        let response = await chain(ServerRequest(method: .get, target: "/", headers: HTTPFields()))
        if case .full(_, _, _, let h) = response {
            #expect(h[fieldName("x-content-type-options")] == "nosniff")
            #expect(h[fieldName("x-frame-options")] == "DENY")
        } else {
            Issue.record("not decorated")
        }
    }

    @Test
    func `request storage is shared middleware → handler`() async {
        let storage = RequestStorage()
        let context = MiddlewareContext(requestID: "r", logger: Logger(label: "t"), storage: storage)
        let chain = MiddlewarePipeline.compose([SetUser()], context: context, terminal: { _ in .plain(.ok, "ok") })
        _ = await chain(ServerRequest(method: .get, target: "/", headers: HTTPFields()))
        #expect(storage[CurrentUser.self] == "alice")
    }

    @Test
    func `the JSON codec rejects a non-JSON content type with 415`() throws {
        let body = Array(#"{"id":1,"name":"x"}"#.utf8)
        #expect(throws: ADServeCore.HTTPError.self) {
            _ = try JSONBodyCodec().decode(Item.self, from: body, contentType: "text/xml")
        }
        #expect(
            try JSONBodyCodec().decode(Item.self, from: body, contentType: "application/json") == Item(id: 1, name: "x")
        )
        #expect(try JSONBodyCodec().decode(Item.self, from: body, contentType: nil) == Item(id: 1, name: "x"))
    }
}

struct BodyLimitTests {
    @Test
    func `.maxBody surfaces on the matched route; a group default applies; an inner route wins`() {
        let routes = table {
            POST("upload", pool: .none) { _ in .noContent }.maxBody(10)
            Scope("admin") {
                POST("small", pool: .none) { _ in .noContent }  // inherits the group's 100
                POST("tiny", pool: .none) { _ in .noContent }.maxBody(5)  // own 5 wins over the group
            }
            .maxBody(100)
            POST("plain", pool: .none) { _ in .noContent }  // no limit → nil
        }
        func limit(_ method: HTTPMethod, _ path: String) -> Int? {
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

    @Test
    func `RouteTable.bodyLimit surfaces the matched route's ceiling for the engine's head-time peek`() {
        let routes = table {
            POST("upload", pool: .none) { _ in .noContent }.maxBody(50_000_000)  // upload, above any default
            POST("plain", pool: .none) { _ in .noContent }
        }
        #expect(routes.bodyLimit(method: .post, path: "/upload"[...]) == 50_000_000)
        #expect(routes.bodyLimit(method: .post, path: "/plain"[...]) == nil)
        #expect(routes.bodyLimit(method: .post, path: "/missing"[...]) == nil)  // no match → nil
    }
}

struct StaticAssetDSLTests {
    @Test
    func `content-type allow-list maps known extensions and rejects the rest`() {
        #expect(staticContentType(forPath: "app.js") == "text/javascript; charset=utf-8")
        #expect(staticContentType(forPath: "a/b/style.css") == "text/css; charset=utf-8")
        #expect(staticContentType(forPath: "icon.SVG") == "image/svg+xml")  // extension is case-insensitive
        #expect(staticContentType(forPath: "runtime.min.js") == "text/javascript; charset=utf-8")
        #expect(staticContentType(forPath: "noext") == nil)  // no extension
        #expect(staticContentType(forPath: "app.exe") == nil)  // not allow-listed
        #expect(staticContentType(forPath: ".env") == nil)  // leading-dot dotfile
    }

    @Test
    func `Static serves allow-listed files; 404s dotfiles + non-allow-listed extensions`() {
        let routes = table { Static("/assets", root: "/tmp/whatever") }
        guard case .file(_, let subpath, let contentType, _)? = runMatched(routes, .get, "/assets/app.css")
        else {
            Issue.record("expected .file for an allow-listed asset")
            return
        }
        #expect(subpath == "app.css")
        #expect(contentType == "text/css; charset=utf-8")
        #expect(staticSubpath(runMatched(routes, .get, "/assets/sub/app.js")) == "sub/app.js")  // nested
        #expect(isNotFoundContent(runMatched(routes, .get, "/assets/.env")))  // dotfile
        #expect(isNotFoundContent(runMatched(routes, .get, "/assets/secret.exe")))  // not allow-listed
    }

    @Test
    func `Static appends the index file for an extension-less directory request`() {
        let routes = table { Static("/site", root: "/tmp/x") }
        #expect(staticSubpath(runMatched(routes, .get, "/site/docs")) == "docs/index.html")
        #expect(staticSubpath(runMatched(routes, .get, "/site/a/b")) == "a/b/index.html")
        #expect(staticSubpath(runMatched(routes, .get, "/site/app.css")) == "app.css")  // a real file, unchanged
    }

    @Test
    func `Static index can be disabled`() {
        let routes = table { Static("/site", root: "/tmp/x", index: nil) }
        #expect(isNotFoundContent(runMatched(routes, .get, "/site/docs")))  // extension-less + no index → 404
    }

    @Test
    func `File serves one specific file jailed in its own directory`() {
        let routes = table { File("/favicon.ico", path: "Public/favicon.ico") }
        guard case .file(let root, let subpath, let contentType, _)? = runMatched(routes, .get, "/favicon.ico")
        else {
            Issue.record("expected .file for the single-file route")
            return
        }
        #expect(root == "Public")
        #expect(subpath == "favicon.ico")
        #expect(contentType.hasPrefix("image/"))
    }

    @Test
    func `File at the site root serves its target`() {
        let routes = table { File("/", path: "Public/index.html") }
        guard case .file(let root, let subpath, let contentType, _)? = runMatched(routes, .get, "/") else {
            Issue.record("expected .file at the root")
            return
        }
        #expect(root == "Public")
        #expect(subpath == "index.html")
        #expect(contentType == "text/html; charset=utf-8")
    }
}

private func isNotFoundContent(_ content: ResponseContent?) -> Bool {
    if case .notFound? = content { return true }
    return false
}

private func staticSubpath(_ content: ResponseContent?) -> String? {
    if case .file(_, let subpath, _, _)? = content { return subpath }
    return nil
}
