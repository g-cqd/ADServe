// A hierarchical, type-safe server-DEFINITION DSL.
//
// Decouples the SERVER (the ADServeCore engine) from its DEFINITION (this DSL) from the
// BUSINESS LOGIC (the handler bodies). The definition leverages Swift type-safety
// end-to-end — typed HTTP verbs (GET/POST/OPTIONS), a typed pool that picks the handler's
// context type (so a pure-config route cannot touch the DB), typed cache + output
// (`MediaType`), result builders for the tree, and `@dynamicMemberLookup` on the context
// — and lowers to the existing `CompiledRoute`/`RouteTable` seam.
//
//   Server {
//     App(pool: .shared) {                        // an application on a port; the central shared pool
//       GET("search") { ctx in .json(…, as: .jsonRaw) }
//       Scope("api") {                            // → /api/*
//         GET("filters") { ctx in .json(WebRoutes.filters(ctx.db)) }.cache(.apiCorpus)
//         Scope("symbols") { GET("index.json") { ctx in … }.etag }
//       }
//       Scope("discovery", pool: .none) {         // no ctx.db in here (compile-enforced)
//         GET("robots.txt") { ctx in .text(Discovery.robotsTxt(cfg), as: .text) }.cache(.discovery, etag: true)
//       }
//     }
//   }

import ADJSON
public import ADServeCore
import HTTPCore
public import WebSocket

// MARK: - Pool (type-safe storage)

/// A route's pool. Its `Context` associated type decides the handler's context, so the
/// compiler forbids reaching `ctx.db` from a `.none` route.
public protocol PoolScope: Sendable {
    associatedtype Context: HandlerContext
    var needsStorage: Bool { get }
}

/// The central shared pool (shared process threads). The handler gets a DB context.
public struct SharedPool: PoolScope {
    public typealias Context = StorageContext
    public var needsStorage: Bool { true }
    public init() {}
}

/// No pool — a pure-config route. The handler gets a plain context (no `db`).
public struct NoPool: PoolScope {
    public typealias Context = RequestContext
    public var needsStorage: Bool { false }
    public init() {}
}

extension PoolScope where Self == SharedPool { public static var shared: SharedPool { SharedPool() } }
extension PoolScope where Self == NoPool { public static var none: NoPool { NoPool() } }

// MARK: - The definition tree

/// A node in the definition tree — a leaf route or a path `Scope`. Lowers to
/// `[CompiledRoute]` given an accumulated path prefix.
public struct RouteNode: Sendable {
    var cache: CachePolicy
    var middleware: [any HTTPMiddleware] = []
    var maxBodyBytes: Int? = nil
    var doc: RouteDoc? = nil
    let make:
        @Sendable (_ prefix: String, _ cache: CachePolicy, _ middleware: [any HTTPMiddleware]) ->
            [CompiledRoute]

    /// Set the route's cache policy (`Cache-Control` + ETag). No-op on a `Scope`.
    public func cache(_ policy: CachePolicy) -> RouteNode {
        var copy = self
        copy.cache = policy
        return copy
    }
    public func cache(_ policy: CachePolicy, etag: Bool) -> RouteNode {
        var copy = self
        copy.cache = CachePolicy(cacheControl: policy.cacheControl, etag: etag)
        return copy
    }
    public var etag: RouteNode {
        var copy = self
        copy.cache.etag = true
        return copy
    }

    /// Wrap this route — or, on a `Scope`, every route inside it — with middleware (outermost first).
    public func middleware(_ middleware: any HTTPMiddleware...) -> RouteNode {
        var copy = self
        copy.middleware += middleware
        return copy
    }

    /// Set this route's request-body ceiling to `bytes` (a 413 before the handler runs) — *higher* than
    /// the server default for an upload endpoint, or *lower* for a tighter bound. On a `Scope`, applies
    /// to every route inside that doesn't set its own.
    public func maxBody(_ bytes: Int) -> RouteNode {
        var copy = self
        copy.maxBodyBytes = bytes
        return copy
    }

    func build(prefix: String, inheritedMiddleware: [any HTTPMiddleware] = []) -> [CompiledRoute] {
        var routes = make(prefix, cache, inheritedMiddleware + middleware)
        // Stamp limit + doc onto routes lacking one — so an inner route's modifier wins over a group's.
        if let maxBodyBytes {
            routes = routes.map { $0.maxBodyBytes == nil ? $0.withMaxBodyBytes(maxBodyBytes) : $0 }
        }
        if let doc {
            routes = routes.map { $0.doc == nil ? $0.withDoc(doc) : $0 }
        }
        return routes
    }
}

@resultBuilder
public enum RouteGroupBuilder {
    public static func buildExpression(_ node: RouteNode) -> [RouteNode] { [node] }
    /// Splice a pre-built list (lets a `@RouteGroupBuilder` helper compose into an `App` — e.g.
    /// share one route set across a loopback `App` and a TLS `App`).
    public static func buildExpression(_ nodes: [RouteNode]) -> [RouteNode] { nodes }
    public static func buildBlock(_ parts: [RouteNode]...) -> [RouteNode] { parts.flatMap { $0 } }
    public static func buildArray(_ parts: [[RouteNode]]) -> [RouteNode] { parts.flatMap { $0 } }
    public static func buildOptional(_ part: [RouteNode]?) -> [RouteNode] { part ?? [] }
    public static func buildEither(first: [RouteNode]) -> [RouteNode] { first }
    public static func buildEither(second: [RouteNode]) -> [RouteNode] { second }
}

/// A path-prefix scope; composes its prefix into the children's paths. Nestable — `Scope("api") {
/// Scope("v1") { GET … } }` mounts the children under `/api/v1`.
public func Scope(_ prefix: String, @RouteGroupBuilder _ children: () -> [RouteNode]) -> RouteNode {
    let nodes = children()
    return RouteNode(cache: .unset) { parentPrefix, _, scopeMiddleware in
        let scopePrefix = joinPath(parentPrefix, prefix)
        return nodes.flatMap { $0.build(prefix: scopePrefix, inheritedMiddleware: scopeMiddleware) }
    }
}

/// The former spelling of ``Scope(_:_:)`` — kept as a deprecated alias so existing route trees keep
/// compiling. Prefer `Scope` (Rails-style path scoping).
@available(*, deprecated, renamed: "Scope(_:_:)")
public func Group(_ prefix: String, @RouteGroupBuilder _ children: () -> [RouteNode]) -> RouteNode {
    Scope(prefix, children)
}

// MARK: - Static assets

/// Serve guarded static files from `root` under `mountPath` (adserve-requirements #4): e.g.
/// `Static("/assets", root: "Public")` maps `GET /assets/app.css` → `Public/app.css`. The match is a
/// catch-all (lowest priority, so explicit routes always win), and the bytes are jailed + served by the
/// engine off the event loop (the resolved real path must stay inside `root` — `..` and symlink escape
/// are rejected). The handler here rejects dotfiles and any extension NOT on the content-type
/// allow-list (so source files, `.env`, etc. are never served), and stamps the `cache` policy
/// (`.immutable` by default — pair it with content-hashed filenames). SRI hashing stays in
/// ADHTML/`ADHTMLSRI`; ADServe just serves the bytes.
///
/// - Important: `root` is a TRUST BOUNDARY. The request path can never escape it (`..`, encoded
///   separators, NUL, and symlinks are all rejected), but EVERY regular file *inside* `root` whose
///   extension is on the servable allow-list (`.css`, `.js`, `.json`, `.svg`, `.txt`, …) is publicly
///   readable. Point `root` ONLY at a directory that contains exclusively public assets — never a project
///   root, a config/secrets directory, or a path that climbs out of the app (`../../…`).
public func Static(
    _ mountPath: String, root: String, index: String? = "index.html", cache: CachePolicy = .immutable
) -> RouteNode {
    let template = mountPath.hasSuffix("/") ? mountPath + "{path*}" : mountPath + "/{path*}"
    return GET(template, pool: .none) { (_: RequestContext, params: PathParameters) -> ResponseContent in
        guard var subpath = params.path, !subpath.isEmpty else { return .notFound }
        // Reject dotfiles (any segment starting with "."); PathTemplate already rejected `.`/`..` and
        // encoded separators, so the subpath cannot climb out of `root`.
        for segment in subpath.split(separator: "/") where segment.hasPrefix(".") { return .notFound }
        // Directory index: an extension-less final segment is treated as a directory → serve its `index`
        // (e.g. `/docs/guide` → `docs/guide/index.html`). The engine still 404s if the index is missing
        // (no directory listing). A real extension-less asset would need an explicit `File(_:path:)` route.
        if let index, MediaType.fileExtension(of: subpath) == nil {
            subpath += "/" + index
        }
        guard let contentType = staticContentType(forPath: subpath) else { return .notFound }
        return .file(root: root, subpath: subpath, contentType: contentType)
    }
    .cache(cache)
}

/// Serve ONE specific file at an exact route: `File("/favicon.ico", path: "Public/favicon.ico")` or
/// `File("/", path: "Public/index.html")` for a site root. The file is jailed inside its own directory
/// (the engine rejects `..`/symlink escape), and the content-type is derived from its extension unless
/// `contentType` overrides. Pairs with `Static` for the catch-all + an explicit root index.
public func File(
    _ routePath: String, path filePath: String, contentType: String? = nil, cache: CachePolicy = .unset
) -> RouteNode {
    // Jail the file inside its OWN directory: root = the file's directory, subpath = its basename.
    let lastSlash = filePath.lastIndex(of: "/")
    let directory = lastSlash.map { String(filePath[..<$0]) } ?? "."
    let name = lastSlash.map { String(filePath[filePath.index(after: $0)...]) } ?? filePath
    let root = directory.isEmpty ? "/" : directory
    let resolvedType =
        contentType ?? MediaType(path: filePath)?.value ?? "application/octet-stream"
    return GET(routePath, pool: .none) { (_: RequestContext) -> ResponseContent in
        .file(root: root, subpath: name, contentType: resolvedType)
    }
    .cache(cache)
}

/// The content-type for a static path, or `nil` (→ 404) for an extension-less path, a dotfile, or an
/// extension NOT on the servable allow-set. Two separated concerns: the allow-set is the SECURITY
/// boundary (WHICH extensions are servable — never source/configs/scripts), while the content-type
/// STRING comes from the authoritative generated mime-db table via `MediaType(fileExtension:)` — so the
/// types are correct + cross-platform without hand-maintenance.
func staticContentType(forPath path: String) -> String? {
    guard let ext = MediaType.fileExtension(of: path), staticServableExtensions.contains(ext),
        let mediaType = MediaType(fileExtension: ext)
    else { return nil }
    return mediaType.value
}

/// The web-asset extensions `Static` will serve — the curated security allow-set (the default covers
/// the ADHTML runtime + CSS/SVG/fonts/images/wasm). A project needing more types wraps `Static`. The
/// content-TYPE for each is resolved from the generated `MIMEDatabase`, not hand-typed here.
let staticServableExtensions: Set<String> = [
    "js", "mjs", "css", "html", "htm", "json", "map", "svg", "png", "jpg", "jpeg", "gif", "webp",
    "avif", "ico", "woff", "woff2", "ttf", "otf", "txt", "xml", "wasm", "webmanifest"
]

// MARK: - Routes (typed verbs + typed pool → typed context)

// Each verb has an exact-path form `VERB("path") { ctx in … }` and a typed-template form
// `VERB("path/{id}") { ctx, params in … }`, disambiguated by the handler's argument count. `GET`
// additionally keeps the opaque-matcher form for irregular grammars (e.g. RegexBuilder). Storage
// verbs default to the shared pool (`ctx.db`); `OPTIONS` defaults to no pool.

public func GET<P: PoolScope>(
    _ subpath: String = "/", pool: P = SharedPool(),
    _ handler: @escaping @Sendable (P.Context) throws -> ResponseContent
) -> RouteNode { exactRoute(.get, subpath, pool: pool, handler) }
public func GET<P: PoolScope>(
    _ template: String = "/", pool: P = SharedPool(),
    _ handler: @escaping @Sendable (P.Context, PathParameters) throws -> ResponseContent
) -> RouteNode { templateRoute(.get, template, pool: pool, handler) }

public func POST<P: PoolScope>(
    _ subpath: String = "/", pool: P = SharedPool(),
    _ handler: @escaping @Sendable (P.Context) throws -> ResponseContent
) -> RouteNode { exactRoute(.post, subpath, pool: pool, handler) }
public func POST<P: PoolScope>(
    _ template: String = "/", pool: P = SharedPool(),
    _ handler: @escaping @Sendable (P.Context, PathParameters) throws -> ResponseContent
) -> RouteNode { templateRoute(.post, template, pool: pool, handler) }

public func PUT<P: PoolScope>(
    _ subpath: String = "/", pool: P = SharedPool(),
    _ handler: @escaping @Sendable (P.Context) throws -> ResponseContent
) -> RouteNode { exactRoute(.put, subpath, pool: pool, handler) }
public func PUT<P: PoolScope>(
    _ template: String = "/", pool: P = SharedPool(),
    _ handler: @escaping @Sendable (P.Context, PathParameters) throws -> ResponseContent
) -> RouteNode { templateRoute(.put, template, pool: pool, handler) }

public func PATCH<P: PoolScope>(
    _ subpath: String = "/", pool: P = SharedPool(),
    _ handler: @escaping @Sendable (P.Context) throws -> ResponseContent
) -> RouteNode { exactRoute(.patch, subpath, pool: pool, handler) }
public func PATCH<P: PoolScope>(
    _ template: String = "/", pool: P = SharedPool(),
    _ handler: @escaping @Sendable (P.Context, PathParameters) throws -> ResponseContent
) -> RouteNode { templateRoute(.patch, template, pool: pool, handler) }

public func DELETE<P: PoolScope>(
    _ subpath: String = "/", pool: P = SharedPool(),
    _ handler: @escaping @Sendable (P.Context) throws -> ResponseContent
) -> RouteNode { exactRoute(.delete, subpath, pool: pool, handler) }
public func DELETE<P: PoolScope>(
    _ template: String = "/", pool: P = SharedPool(),
    _ handler: @escaping @Sendable (P.Context, PathParameters) throws -> ResponseContent
) -> RouteNode { templateRoute(.delete, template, pool: pool, handler) }

public func HEAD<P: PoolScope>(
    _ subpath: String = "/", pool: P = SharedPool(),
    _ handler: @escaping @Sendable (P.Context) throws -> ResponseContent
) -> RouteNode { exactRoute(.head, subpath, pool: pool, handler) }
public func HEAD<P: PoolScope>(
    _ template: String = "/", pool: P = SharedPool(),
    _ handler: @escaping @Sendable (P.Context, PathParameters) throws -> ResponseContent
) -> RouteNode { templateRoute(.head, template, pool: pool, handler) }

public func OPTIONS<P: PoolScope>(
    _ subpath: String = "/", pool: P = NoPool(),
    _ handler: @escaping @Sendable (P.Context) throws -> ResponseContent
) -> RouteNode { exactRoute(.options, subpath, pool: pool, handler) }
public func OPTIONS<P: PoolScope>(
    _ template: String = "/", pool: P = NoPool(),
    _ handler: @escaping @Sendable (P.Context, PathParameters) throws -> ResponseContent
) -> RouteNode { templateRoute(.options, template, pool: pool, handler) }

/// A WebSocket endpoint: a `GET` at `subpath` the engine UPGRADES (HTTP/1 `Upgrade: websocket`, or
/// an HTTP/2/3 Extended CONNECT) and drives through `handler` — the sans-I/O event → actions seam
/// (fragmented frames are reassembled and pings auto-ponged by the engine before your handler sees
/// them). A non-upgrade `GET` to the same path gets `426 Upgrade Required`. Cross-site handshakes
/// are rejected by ADServe's CSWSH gate (same-origin or origin-less only).
///
///   WS("chat", handler: EchoHandler())
public func WS(_ subpath: String = "/", handler: any WebSocketHandler) -> RouteNode {
    webSocketRoute(subpath, handler: handler, hub: nil, topic: nil)
}

/// The closure form of ``WS(_:handler:)``: `handle` receives each connection event (`.message`,
/// `.ping`, `.pong`, `.close`) and returns the frames to send back.
///
///   WS("chat") { event in
///     guard case .message(let opcode, let payload) = event, opcode == .text else { return [] }
///     return [.sendText(String(decoding: payload, as: UTF8.self))]   // echo
///   }
public func WS(
    _ subpath: String = "/",
    _ handle: @escaping @Sendable (WebSocketEvent) async -> [WebSocketAction]
) -> RouteNode {
    WS(subpath, handler: ClosureWebSocketHandler(isOriginAllowed: { _ in true }, handle: handle))
}

/// A `WS` endpoint bound to a ``WebSocketHub`` topic: the engine AUTO-subscribes each connection
/// when the socket opens and unsubscribes it when it closes (or drops, or the server quiesces),
/// collapsing the subscribe / hold-open / unsubscribe lifecycle into one line. The server pushes to
/// every subscriber with `hub.broadcast(_:to:)` / `hub.publish(_:to:)` (typically fired from a
/// mutation route). This is the server-push ("live updates") shape; inbound frames are ignored —
/// use the `receiving:` overload to react to them.
///
///     let hub = WebSocketHub()
///     Channel("/ws/parts", on: hub, topic: "parts")            // clients subscribe to receive pushes
///     // …from the mutation route:  Task { await hub.broadcast(partJSON, to: "parts") }
public func Channel(_ subpath: String = "/", on hub: WebSocketHub, topic: String) -> RouteNode {
    webSocketRoute(
        subpath,
        handler: ClosureWebSocketHandler(isOriginAllowed: { _ in true }, handle: { _ in [] }),
        hub: hub, topic: topic)
}

/// The bidirectional ``Channel``: as the subscribe-only form, plus inbound text frames are decoded
/// as `Inbound` (JSON, via ADJSON) and delivered to `onMessage`. Failure-safe — a non-text or
/// undecodable frame is skipped, never thrown (a hostile peer can't tear the connection down). The
/// handler typically re-publishes through the hub it captured.
///
///     Channel("/ws/room", on: hub, topic: "room", receiving: ChatLine.self) { line in
///       await hub.broadcast(render(line), to: "room")          // re-broadcast to everyone
///     }
public func Channel<Inbound: Decodable & Sendable>(
    _ subpath: String = "/", on hub: WebSocketHub, topic: String,
    receiving: Inbound.Type = Inbound.self,
    _ onMessage: @escaping @Sendable (Inbound) async -> Void
) -> RouteNode {
    let handler = ClosureWebSocketHandler(
        isOriginAllowed: { _ in true },
        handle: { event in
            guard case .message(let opcode, let payload) = event, opcode == .text,
                let value = try? ADJSON.JSONDecoder().decode(Inbound.self, from: payload)
            else { return [] }  // skip a non-text / undecodable frame (failure-safe)
            await onMessage(value)
            return []
        })
    return webSocketRoute(subpath, handler: handler, hub: hub, topic: topic)
}

/// The shared lowering behind ``WS`` and ``Channel``: one `GET` route carrying the WebSocket
/// handler (+ optional hub binding) whose plain-request fallback answers `426 Upgrade Required`.
private func webSocketRoute(
    _ subpath: String, handler: any WebSocketHandler, hub: WebSocketHub?, topic: String?
) -> RouteNode {
    precondition(
        !subpath.contains("{"), "ADServe: a WS route path '\(subpath)' cannot contain a path parameter")
    return RouteNode(cache: .unset) { prefix, cache, middleware in
        let full = joinPath(prefix, subpath)
        let bind: @Sendable (Substring) -> (@Sendable (HandlerInput) throws -> ResponseContent)? = { path in
            pathMatchesExact(path, full) ? { @Sendable _ in webSocketUpgradeRequired() } : nil
        }
        return [
            CompiledRoute(
                method: .get, needsStorage: false, cache: cache, exactPath: full, middleware: middleware,
                pathTemplate: full, webSocketHandler: handler, webSocketHub: hub,
                webSocketTopic: topic, bind: bind)
        ]
    }
}

/// A streaming-upload route: the handler is ASYNC and receives the body as a back-pressured
/// `RequestBodyStream` (`input.bodyStream`) — for large uploads that must not buffer in memory. The
/// route's own body cap does NOT apply (bound the body yourself, e.g. `try await input.bodyStream
/// .collect(maxBytes:)`). Route-level middleware is not applied to a streaming route; server-wide
/// middleware (auth, logging) still wraps it. Defaults to `POST`.
///
///   Stream("upload") { input in
///     var total = 0
///     for await chunk in input.bodyStream { total += chunk.count }
///     return .json(Array("{\"bytes\":\(total)}".utf8), as: .jsonRaw)
///   }
public func Stream(_ subpath: String, _ handler: @escaping StreamingRequestHandler) -> RouteNode {
    precondition(
        !subpath.contains("{"),
        "ADServe: a streaming route path '\(subpath)' cannot contain a path parameter")
    return RouteNode(cache: .unset) { prefix, cache, middleware in
        let full = joinPath(prefix, subpath)
        let bind: @Sendable (Substring) -> (@Sendable (HandlerInput) throws -> ResponseContent)? = { path in
            // Placeholder: the engine takes the streaming path when `streamingRun` is set, so `run` is
            // never invoked for a matched streaming request.
            pathMatchesExact(path, full) ? { @Sendable _ in .plain(.internalServerError, "streaming route\n") } : nil
        }
        return [
            CompiledRoute(
                method: .post, needsStorage: false, cache: cache, exactPath: full, middleware: middleware,
                pathTemplate: full, streamingRun: handler, bind: bind)
        ]
    }
}

/// `426 Upgrade Required` + the `Upgrade`/`Connection` headers — the answer to a plain `GET` of a WS
/// endpoint (RFC 6455 §4.2.1 / RFC 7231 §6.5.15).
private func webSocketUpgradeRequired() -> ResponseContent {
    var headers = HTTPFields()
    headers.setValue("websocket", for: HTTPFieldName("upgrade")!)
    headers.setValue("Upgrade", for: HTTPFieldName("connection")!)
    return .full(
        body: Array("upgrade required\n".utf8), contentType: "text/plain; charset=utf-8",
        status: .upgradeRequired, headers: headers)
}

/// `GET` with an opaque typed-capture matcher — for irregular path grammars. Matched against the
/// full request path, so the enclosing `Scope` prefix does not apply.
public func GET<P: PoolScope, Captures: Sendable>(
    match: @escaping @Sendable (Substring) -> Captures?, pool: P = SharedPool(),
    _ handler: @escaping @Sendable (P.Context, Captures) throws -> ResponseContent
) -> RouteNode {
    matchRoute(.get, match: match, pool: pool, handler)
}

// MARK: - Route builders (exact path / typed template / opaque matcher)

private func exactRoute<P: PoolScope>(
    _ method: HTTPMethod, _ subpath: String, pool: P,
    _ handler: @escaping @Sendable (P.Context) throws -> ResponseContent
) -> RouteNode {
    precondition(
        !subpath.contains("{"),
        "ADServe: exact route path '\(subpath)' contains '{' — use the typed-template overload: "
            + "`VERB(\"\(subpath)\") { ctx, params in … }`")
    let needsStorage = pool.needsStorage
    let run: @Sendable (HandlerInput) throws -> ResponseContent = { input in try handler(P.Context(input)) }
    return RouteNode(cache: .unset) { prefix, cache, middleware in
        let full = joinPath(prefix, subpath)
        let bind: @Sendable (Substring) -> (@Sendable (HandlerInput) throws -> ResponseContent)? = {
            pathMatchesExact($0, full) ? run : nil
        }
        return [
            CompiledRoute(
                method: method, needsStorage: needsStorage, cache: cache, exactPath: full,
                middleware: middleware, pathTemplate: full, bind: bind)
        ]
    }
}

private func templateRoute<P: PoolScope>(
    _ method: HTTPMethod, _ template: String, pool: P,
    _ handler: @escaping @Sendable (P.Context, PathParameters) throws -> ResponseContent
) -> RouteNode {
    let needsStorage = pool.needsStorage
    return RouteNode(cache: .unset) { prefix, cache, middleware in
        let fullTemplate = joinPath(prefix, template)
        let pathTemplate = PathTemplate(fullTemplate)
        let bind: @Sendable (Substring) -> (@Sendable (HandlerInput) throws -> ResponseContent)? = { path in
            guard let params = pathTemplate.match(path) else { return nil }
            return { input in try handler(P.Context(input), params) }
        }
        return [
            CompiledRoute(
                method: method, needsStorage: needsStorage, cache: cache, exactPath: nil,
                middleware: middleware, pathTemplate: fullTemplate, bind: bind)
        ]
    }
}

private func matchRoute<P: PoolScope, Captures: Sendable>(
    _ method: HTTPMethod, match: @escaping @Sendable (Substring) -> Captures?, pool: P,
    _ handler: @escaping @Sendable (P.Context, Captures) throws -> ResponseContent
) -> RouteNode {
    let needsStorage = pool.needsStorage
    let bind: @Sendable (Substring) -> (@Sendable (HandlerInput) throws -> ResponseContent)? = { path in
        guard let captures = match(path) else { return nil }
        return { input in try handler(P.Context(input), captures) }
    }
    return RouteNode(cache: .unset) { _, cache, middleware in
        [
            CompiledRoute(
                method: method, needsStorage: needsStorage, cache: cache, exactPath: nil,
                middleware: middleware, bind: bind)
        ]
    }
}

// MARK: - App + Server

/// An app's pool config (the engine binds one app/port in the PoC). `.shared` = the central
/// pool on the shared process threads; `.concurrent` = an independent pool (future); `.none`
/// = no DB.
public enum PoolRef: Sendable { case shared, concurrent, none }

/// An application served on a port — the lowered form of an `App { … }`. A nil `port` binds
/// the process default; a nil `wire` inherits the `Server`'s default protocol. Both are
/// resolved by `Server(protocol:)` + `listeners(_:defaultPort:)`.
public struct Application: Sendable {
    public let port: Int?
    public let wire: Wire?
    let routes: [CompiledRoute]
}

/// An application served on a port. Omit `port` to bind the process default; give distinct
/// ports for multiple `App`s under one `Server` (e.g. a TLS listener + the loopback listener).
/// `protocol:` overrides the `Server`-level default `Wire` (HTTP version(s) × TLS).
///
/// `cors:` installs a ``CORS`` middleware OUTERMOST (so it owns the preflight before routing) — the one-line,
/// discoverable way to allow a cross-origin caller, e.g. a sibling web app's components reaching this app's
/// JSON API on another port (`App(port: apiPort, cors: CORS(allowOrigin: "https://web.app")) { … }`). It is
/// exactly `middleware: [CORS(…)] + middleware`; reach for the `middleware:` array directly for finer control.
public func App(
    port: Int? = nil, `protocol` wire: Wire? = nil, pool: PoolRef = .shared,
    cors: CORS? = nil, middleware: [any HTTPMiddleware] = [],
    @RouteGroupBuilder _ routes: () -> [RouteNode]
) -> Application {
    var stack = middleware
    if let cors { stack.insert(cors, at: 0) }  // outermost: CORS must see the OPTIONS preflight before routing
    return Application(
        port: port, wire: wire,
        routes: routes().flatMap { $0.build(prefix: "", inheritedMiddleware: stack) })
}

@resultBuilder
public enum ServerBuilder {
    public static func buildExpression(_ app: Application) -> [Application] { [app] }
    public static func buildBlock(_ parts: [Application]...) -> [Application] { parts.flatMap { $0 } }
    public static func buildArray(_ parts: [[Application]]) -> [Application] { parts.flatMap { $0 } }
    public static func buildOptional(_ part: [Application]?) -> [Application] { part ?? [] }
    public static func buildEither(first: [Application]) -> [Application] { first }
    public static func buildEither(second: [Application]) -> [Application] { second }
}

/// The server definition → its applications (one engine listener each). `protocol:` is the
/// default `Wire` applied to every `App` that didn't set its own. Lower to engine
/// `ListenerConfig`s with `listeners(_:defaultPort:)`.
public func Server(
    `protocol` wire: Wire = .http1, @ServerBuilder _ build: () -> [Application]
) -> [Application] {
    build().map { Application(port: $0.port, wire: $0.wire ?? wire, routes: $0.routes) }
}

/// Lower the `Server { … }` applications to engine `ListenerConfig`s: each `App` becomes one
/// listener (its own `port`/`wire`, else the defaults) over a `RouteTable` of its routes.
public func listeners(
    _ apps: [Application], defaultPort: Int, host: String = "127.0.0.1"
) -> [ListenerConfig] {
    apps.map {
        ListenerConfig(
            host: host, port: $0.port ?? defaultPort, wire: $0.wire ?? .http1,
            routes: RouteTable(routes: $0.routes))
    }
}

// MARK: - helpers

/// `joinPath("", "search") → "/search"`; `joinPath("/api", "filters") → "/api/filters"`. A scope-root
/// route (the default `"/"` subpath inside `Scope("parts")`) composes to `"/parts/"`; the trailing slash
/// is canonicalized away at match time by ``pathMatchesExact(_:_:)``, so it is reachable as `/parts` too.
private func joinPath(_ prefix: String, _ sub: String) -> String {
    let suffix = sub.hasPrefix("/") ? String(sub.dropFirst()) : sub
    return prefix + "/" + suffix
}

/// Trailing-slash-insensitive exact-path comparison — the acceptance oracle for the exact/WS/streaming
/// binds. ADServe treats a trailing slash as canonical, so `/parts` and `/parts/` address the SAME route:
/// in particular a scope-root route (the default `"/"` subpath inside `Scope("parts")`, which compiles to
/// `"/parts/"`) is reachable as `/parts`. Both sides are compared with one trailing slash *trimmed* (the
/// process root `"/"` is preserved); the segment trie is already slash-insensitive
/// (`omittingEmptySubsequences`), so this just brings the oracle into line with it. **Allocation-free** —
/// only zero-copy `Substring` slicing, so it adds nothing to `mallocCountTotal` on the hot routing path.
private func pathMatchesExact(_ requestPath: Substring, _ routePath: String) -> Bool {
    trimmedTrailingSlash(requestPath) == trimmedTrailingSlash(routePath[...])
}

/// `s` with a single trailing `/` removed, **except** a lone `"/"` (the process root) which is preserved.
/// Returns a zero-copy slice — no allocation. O(1): inspects only the last element + one index step.
private func trimmedTrailingSlash(_ s: Substring) -> Substring {
    guard s.last == "/" else { return s }
    let trimmed = s.dropLast()
    return trimmed.isEmpty ? s : trimmed
}
