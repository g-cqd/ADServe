// ADServeDSL — the engine-facing route types + handler contexts. The DSL
// SURFACE (`Server`/`App`/`Group`/`GET`…) lives in ServerDSL.swift; this file holds what the
// surface lowers TO: the `@dynamicMemberLookup` handler contexts (the connection is only
// reachable on a `.shared` (storage) context — compile-time enforced), the `CompiledRoute`
// the engine dispatches, and the `RouteTable` (`HTTPHandling`) it dispatches against. The
// DSL sees only ADServeCore's public surface — it cannot touch engine internals.

public import ADConcurrency
public import ADServeCore
public import HTTPTypes
public import Logging

// MARK: - Handler contexts

/// A handler context, buildable from the engine's per-request input. The `request` + `codec`
/// requirements power the shared `query`/`decode`/`json`/`body` helpers below — free on every context.
public protocol HandlerContext: Sendable {
    init(_ input: HandlerInput)
    var request: ServerRequest { get }
    var codec: ContentCodec { get }
    var storage: RequestStorage { get }
}

extension HandlerContext {
    /// Typed access to the percent-decoded query parameters (`?k=v&…`): `ctx.query.page`,
    /// `ctx.query["page"]`, `ctx.query.int("page")`, `try ctx.query.require("page")`.
    public var query: QueryParameters { QueryParameters(request.query) }
    /// The raw request body bytes.
    public var body: [UInt8] { request.body }
    /// Decode the request body into `T` via the configured codec (default: JSON over ADJSON). Throws
    /// the codec's decoding error — catch it in the handler to return a `.badRequest`.
    public func decode<T: Decodable>(_ type: T.Type) throws -> T {
        try codec.decoder.decode(type, from: request.body, contentType: request.headers[.contentType])
    }
    /// Encode `value` into a response via the configured codec (status defaults to `200`).
    public func json<T: Encodable>(_ value: T, status: HTTPResponse.Status = .ok) throws
        -> ResponseContent
    {
        let (bytes, contentType) = try codec.encoder.encode(value)
        return .raw(body: bytes, contentType: contentType, status: status)
    }
}

/// The default context. `@dynamicMemberLookup` forwards `ctx.method`/`.path`/
/// `.target`/`.headers` to the underlying request.
@dynamicMemberLookup
public struct RequestContext: HandlerContext {
    public let request: ServerRequest
    public let codec: ContentCodec
    public let storage: RequestStorage
    public let logger: Logger
    public let requestID: String

    public init(_ input: HandlerInput) {
        request = input.request
        codec = input.codec
        storage = input.storage
        logger = input.logger
        requestID = input.requestID
    }

    public subscript<T>(dynamicMember keyPath: KeyPath<ServerRequest, T>) -> T {
        request[keyPath: keyPath]
    }
}

/// The context for storage routes (`pool: .shared`) — `connection` is non-optional (the
/// engine checked one out). You cannot reach `connection` without a storage pool.
@dynamicMemberLookup
public struct StorageContext: HandlerContext {
    public let request: ServerRequest
    /// The type-erased pooled resource. The app down-casts via its `db` accessor (the app's
    /// invariant: a `.shared` route's pool holds exactly the app's connection type).
    public let connection: any PooledResource
    public let codec: ContentCodec
    public let storage: RequestStorage
    public let logger: Logger
    public let requestID: String

    public init(_ input: HandlerInput) {
        request = input.request
        codec = input.codec
        storage = input.storage
        // Safe: the engine only builds a StorageContext for a `needsStorage` route, and
        // only after a successful checkout.
        connection = input.connection!
        logger = input.logger
        requestID = input.requestID
    }

    public subscript<T>(dynamicMember keyPath: KeyPath<ServerRequest, T>) -> T {
        request[keyPath: keyPath]
    }
}

// MARK: - Compiled route (engine-facing)

/// A fully-built route. `bind` returns a captures-applied handler when the path
/// matches, else nil; `exactPath` (when non-nil) lets the table index it O(1).
public struct CompiledRoute: Sendable {
    let method: HTTPRequest.Method
    let needsStorage: Bool
    let cache: CachePolicy
    let exactPath: String?
    /// Group + route middleware wrapping this route's handler (outermost first). Empty for most routes.
    let middleware: [any HTTPMiddleware]
    /// A per-route request-body ceiling (bytes), or `nil` for the server default.
    let maxBodyBytes: Int?
    /// The route's documentable path template (`"/items/{id}"`), or `nil` for an opaque matcher.
    /// Drives OpenAPI generation; never used for matching.
    let pathTemplate: String?
    /// OpenAPI metadata supplied by `.summary`/`.tags`/`.body`/`.responds` (nil = undocumented).
    let doc: RouteDoc?
    let bind: @Sendable (Substring) -> (@Sendable (HandlerInput) throws -> ResponseContent)?

    init(
        method: HTTPRequest.Method, needsStorage: Bool, cache: CachePolicy, exactPath: String?,
        middleware: [any HTTPMiddleware] = [], maxBodyBytes: Int? = nil,
        pathTemplate: String? = nil, doc: RouteDoc? = nil,
        bind: @escaping @Sendable (Substring) -> (@Sendable (HandlerInput) throws -> ResponseContent)?
    ) {
        self.method = method
        self.needsStorage = needsStorage
        self.cache = cache
        self.exactPath = exactPath
        self.middleware = middleware
        self.maxBodyBytes = maxBodyBytes
        self.pathTemplate = pathTemplate
        self.doc = doc
        self.bind = bind
    }

    /// A copy carrying a per-route body ceiling — used by `RouteNode.build` to stamp a `.maxBody(_:)`
    /// (or an enclosing group's) limit onto routes that don't already have one.
    func withMaxBodyBytes(_ bytes: Int) -> CompiledRoute {
        CompiledRoute(
            method: method, needsStorage: needsStorage, cache: cache, exactPath: exactPath,
            middleware: middleware, maxBodyBytes: bytes,
            pathTemplate: pathTemplate, doc: doc, bind: bind)
    }

    /// A copy carrying OpenAPI metadata — used by `RouteNode.build` to stamp `.summary`/`.body`/… onto
    /// routes that don't already have a doc.
    func withDoc(_ doc: RouteDoc) -> CompiledRoute {
        CompiledRoute(
            method: method, needsStorage: needsStorage, cache: cache, exactPath: exactPath,
            middleware: middleware, maxBodyBytes: maxBodyBytes,
            pathTemplate: pathTemplate, doc: doc, bind: bind)
    }
}

// MARK: - Dispatch table

/// One position in the route trie. Specificity ordering is applied at every node during `match`: a
/// literal child is tried before the single `{param}` child, which is tried before the terminal
/// `{catchAll*}` — so the most specific route wins, independent of declaration order.
///
/// `@unchecked Sendable`: every field is written ONLY during `RouteTable.init` (a single-threaded
/// build) and never mutated afterward. The finished trie is published by value into `ListenerConfig`
/// before any request task exists, so the concurrent reads in `match` observe a frozen graph.
private final class TrieNode: @unchecked Sendable {
    /// Static-segment children, keyed by the RAW segment text (literals match without decoding,
    /// mirroring `PathTemplate`).
    var literals: [String: TrieNode] = [:]
    /// The single `{param}` child (at most one slot per position) + its declared name.
    var param: (name: String, node: TrieNode)?
    /// A terminal `{catchAll*}` consuming the remainder, with its routes by method.
    var catchAll: (name: String, routes: [HTTPRequest.Method: RoutePayload])?
    /// Routes terminating exactly at this node, by method (last writer wins per method).
    var routes: [HTTPRequest.Method: RoutePayload] = [:]
}

/// One frame of the iterative trie descent in `RouteTable.match`: the node under exploration, the
/// path-segment `index` at that node, and a `stage` cursor (0 literal → 1 param → 2 catch-all → 3
/// exhausted) so a popped child returns the parent to its next alternative. Replaces the former
/// recursive `search` closure with an explicit stack (no recursion).
private struct SearchFrame {
    let node: TrieNode
    let index: Int
    var stage: UInt8
}

/// The slim per-route projection the trie indexes: exactly what `MatchedRoute` needs, plus the route's
/// own `bind`. `bind` is the AUTHORITATIVE acceptance oracle — it performs the same percent-decode +
/// traversal rejection + capture binding as the legacy matcher and returns `nil` on reject. The trie
/// only decides structural reachability + specificity ordering, then asks `bind` whether the concrete
/// path is truly accepted — so trie acceptance can never diverge from `PathTemplate`'s semantics.
private struct RoutePayload: Sendable {
    let needsStorage: Bool
    let cache: CachePolicy
    let middleware: [any HTTPMiddleware]
    let maxBodyBytes: Int?
    let bind: @Sendable (Substring) -> (@Sendable (HandlerInput) throws -> ResponseContent)?

    init(_ route: CompiledRoute) {
        needsStorage = route.needsStorage
        cache = route.cache
        middleware = route.middleware
        maxBodyBytes = route.maxBodyBytes
        bind = route.bind
    }

    func matched(_ run: @escaping @Sendable (HandlerInput) throws -> ResponseContent) -> MatchedRoute {
        MatchedRoute(
            needsStorage: needsStorage, cache: cache, middleware: middleware, maxBodyBytes: maxBodyBytes,
            run: run)
    }
}

/// The dispatch table the engine runs against (an `HTTPHandling`). Routes are folded into a segment
/// trie keyed by path structure; `match` descends it in SPECIFICITY order (static > param > catch-all)
/// with backtracking, so the most specific route wins regardless of declaration order — `/users/me`
/// beats `/users/{id}`, and `/files/{id}` beats `/files/{rest*}`. Exact paths are just all-literal trie
/// paths (top priority for free). Opaque `GET(match:)` matchers, which carry an arbitrary closure and
/// no decomposable path, live in a residual list tried only after the trie misses. The DSL surface
/// lowers a `Server { … }` to the `[CompiledRoute]` this is built from.
public struct RouteTable: HTTPHandling {
    private let root: TrieNode
    /// Opaque `GET(match:)` routes in declaration order — consulted only after the trie misses.
    private let opaque: [CompiledRoute]

    public init(routes: [CompiledRoute]) {
        let root = TrieNode()
        var opaque: [CompiledRoute] = []
        for route in routes {
            guard let pathString = route.exactPath ?? route.pathTemplate else {
                opaque.append(route)  // opaque matcher: nothing to index by segment
                continue
            }
            Self.insert(route, into: root, segments: PathTemplate(pathString).segments)
        }
        self.root = root
        self.opaque = opaque
    }

    /// Insert one route's decomposed segments into the trie (build time only).
    private static func insert(
        _ route: CompiledRoute, into root: TrieNode, segments: [PathTemplate.Segment]
    ) {
        var node = root
        for segment in segments {
            switch segment {
                case .literal(let text):
                    if let next = node.literals[text] {
                        node = next
                    } else {
                        let next = TrieNode()
                        node.literals[text] = next
                        node = next
                    }
                case .param(let name):
                    if let existing = node.param {
                        node = existing.node
                    } else {
                        let next = TrieNode()
                        node.param = (name, next)
                        node = next
                    }
                case .catchAll(let name):
                    var entry = node.catchAll ?? (name: name, routes: [:])
                    entry.routes[route.method] = RoutePayload(route)
                    node.catchAll = entry
                    return  // a catch-all is terminal — it consumes the remainder
            }
        }
        node.routes[route.method] = RoutePayload(route)  // last writer wins per (node, method)
    }

    public func match(method: HTTPRequest.Method, path: Substring) -> RouteMatch {
        let parts = path.split(separator: "/", omittingEmptySubsequences: true)
        // Insertion-ordered, de-duplicated 405 set: methods that WOULD serve this exact path were they
        // the request method. `bind`-guarded so a template that rejects the concrete path (e.g. encoded
        // traversal) never inflates `Allow`.
        var allowed: [HTTPRequest.Method] = []
        func remember(_ candidate: HTTPRequest.Method) {
            if !allowed.contains(candidate) { allowed.append(candidate) }
        }

        // Serve `method` from a terminal's route map via its authoritative `bind`; otherwise record the
        // terminal's other bind-accepting methods for a possible 405.
        func accept(_ map: [HTTPRequest.Method: RoutePayload]) -> MatchedRoute? {
            if let payload = map[method], let run = payload.bind(path) {
                return payload.matched(run)
            }
            for (candidate, payload) in map where candidate != method {
                if payload.bind(path) != nil { remember(candidate) }
            }
            return nil
        }

        // Depth-first descent in specificity order (literal → param → catch-all) with backtracking,
        // driven by an EXPLICIT stack (no recursion). A frame's `stage` cursor advances literal → param
        // → catch-all; pushing a child explores its subtree first (LIFO), and when that subtree is
        // exhausted the child is popped and the parent resumes at its next stage — exactly the order the
        // former recursive `search` produced. The first `accept` hit wins (returns immediately). Depth
        // is bounded by the path's segment count (URI length is capped; the literal-traversal pre-check
        // has already run), so the stack cannot grow unboundedly.
        var stack: [SearchFrame] = [SearchFrame(node: root, index: 0, stage: 0)]
        while let top = stack.last {
            if top.index == parts.count {
                // Terminal position: accept here (or backtrack); a deeper node is never descended.
                stack.removeLast()
                if let hit = accept(top.node.routes) { return .matched(hit) }
                continue
            }
            switch top.stage {
                case 0:  // the literal child for this segment
                    stack[stack.count - 1].stage = 1
                    if let child = top.node.literals[String(parts[top.index])] {
                        stack.append(SearchFrame(node: child, index: top.index + 1, stage: 0))
                    }
                case 1:  // then the single `{param}` child
                    stack[stack.count - 1].stage = 2
                    if let param = top.node.param {
                        stack.append(SearchFrame(node: param.node, index: top.index + 1, stage: 0))
                    }
                case 2:  // then the terminal `{catchAll*}` (consumes the remainder)
                    stack[stack.count - 1].stage = 3
                    if let catchAll = top.node.catchAll, let hit = accept(catchAll.routes) {
                        return .matched(hit)
                    }
                default:  // exhausted → backtrack to the parent's next alternative
                    stack.removeLast()
            }
        }

        // Trie miss: try opaque matchers in declaration order (structured routes always win over these).
        for route in opaque {
            guard let run = route.bind(path) else { continue }
            if route.method == method {
                return .matched(
                    MatchedRoute(
                        needsStorage: route.needsStorage, cache: route.cache, middleware: route.middleware,
                        maxBodyBytes: route.maxBodyBytes, run: run))
            }
            remember(route.method)
        }

        return allowed.isEmpty ? .notFound : .methodNotAllowed(allowed: allowed)
    }

    /// The matched route's per-route body ceiling (`.maxBody`), or `nil`. The engine peeks this at the
    /// request head so an upload route can accept a body larger than the server default.
    public func bodyLimit(method: HTTPRequest.Method, path: Substring) -> Int? {
        guard case .matched(let route) = match(method: method, path: path) else { return nil }
        return route.maxBodyBytes
    }
}
