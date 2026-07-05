// The bridge between ADServe's routing/middleware model and the HTTP package's serving engine.
// `EngineResponder` conforms to the engine's `HTTPRouter` seam (`HTTPResponder & RouteResolver`):
// the server hands it every parsed request (with the per-request `RequestContext` + `RequestBody`),
// and queries it at the request HEAD for per-route metadata (body limit, WebSocket handler,
// streaming opt-in) — so route-scoped limits are enforced before the body buffers, exactly as the
// `HTTPHandling` contract documents. Response finalization (the envelope/ETag/compression path)
// lives in HTTPServerRespond.swift.

import ADConcurrency
import ADServeEngineNames
import HTTPCore
import HTTPServer
import HTTPTransport
import Logging
import WebSocket

/// The per-request values the finalization path (HTTPServerRespond.swift) needs alongside the
/// response content: identity, HEAD/keep-alive/HTTP-2 flags, the conditional + negotiation request
/// headers, and the request-scoped storage the terminal seeded.
struct ResponseEnvironment: Sendable {
    let requestID: String
    let isHead: Bool
    let keepAlive: Bool
    /// True on a multiplexed protocol (h2/h3) — the `Connection` header is forbidden there.
    let isHTTP2: Bool
    let ifNoneMatch: String?
    let acceptEncoding: String?
    let storage: RequestStorage
}

/// ADServe's routing DSL exposed to the HTTP engine as its responder + head-time route resolver.
struct EngineResponder: HTTPRouter {
    let routes: any HTTPHandling
    let configuration: EngineConfiguration
    /// Blocking work (`.storage` handler offload, static-file stat/read) runs here — never on the
    /// cooperative pool (forward progress).
    let offload: BlockingOffloadPool

    // MARK: HTTPResponder

    func respond(
        to request: HTTPRequest, body: RequestBody, context: RequestContext
    ) async -> ServerResponse {
        configuration.active.enter()
        defer { configuration.active.leave() }
        let environment = makeEnvironment(request, context: context)
        let target = request.path
        let path = target.prefix { $0 != "?" }

        // Reject directory traversal (`.`/`..` segments) before routing — a catch-all route would
        // otherwise hand `../../etc/passwd` to a handler.
        if PathSafety.hasTraversal(path) {
            return await finalize(
                .plain(.badRequest, "bad request path\n"), cache: .unset, environment: environment)
        }

        // FIX #1: ONE combined trie descent for the request method. The streaming opt-in, the bound
        // handler, the per-route body limit, and the 404/405 outcome ALL come from this single
        // `RouteMatch` — replacing the former `streamingHandler(...)` + `match(...)` (two descents).
        var matchResult = routes.matchRoute(method: request.method, path: path)

        // A streaming-body route consumes the body incrementally (the engine delivers `.stream`
        // because `resolve` reported `streamsBody`); route-level middleware is not applied to it.
        // Evaluated on the REQUEST-method match, before any HEAD→GET fallback — exactly as before.
        if case .matched(let route) = matchResult, let streamingHandler = route.streamingRun {
            return await respondStreaming(
                request, body: body, handler: streamingHandler, environment: environment)
        }

        // A HEAD with no explicit HEAD route falls back to the GET route (the engine suppresses the
        // body at serialization time). This is the only SECOND descent, and only for a HEAD that missed.
        if environment.isHead, case .matched = matchResult {
        } else if environment.isHead {
            matchResult = routes.matchRoute(method: .get, path: path)
        }

        // FIX #8: match FIRST, THEN decide the body. A matched route gets its buffered body; a
        // 404 / 405 drains-and-discards instead of accumulating — a POST to an unknown path or a
        // wrong method no longer buffers its body into the request (the streaming path above already
        // returned without collecting).
        let bytes: [UInt8]
        if case .matched = matchResult {
            bytes = await body.collect()
        } else {
            await Self.drainAndDiscard(body)
            bytes = []
        }
        let serverRequest = ServerRequest(
            method: request.method, target: target, headers: request.headerFields, body: bytes)

        let resolved = resolveMatch(
            matchResult, method: request.method, requestID: environment.requestID,
            bodySize: bytes.count, storage: environment.storage)

        // Compose server-wide + route middleware (server-wide outermost) around the terminal.
        let mwContext = MiddlewareContext(
            requestID: environment.requestID, logger: configuration.logger,
            storage: environment.storage)
        let chain = MiddlewarePipeline.compose(
            configuration.middleware + resolved.middleware, context: mwContext,
            terminal: resolved.terminal)
        let content = await chain(serverRequest)
        return await finalize(content, cache: resolved.cache, environment: environment)
    }

    // MARK: RouteResolver (the head-time seam)

    /// Head-time metadata: the effective body ceiling (a route may RAISE the server default for an
    /// upload; a LOWER bound stays post-match so it can answer as problem+json), and the streaming
    /// opt-in (whose body the route bounds itself — the server cap does not apply).
    func resolve(method: HTTPMethod, path: String) -> ResolvedRoute? {
        let bare = path.prefix { $0 != "?" }
        let serverDefault = configuration.maxBodyBytes
        // FIX #1: ONE combined descent — BOTH the streaming opt-in and the per-route body ceiling are
        // read from a single match (was `streamingHandler` + `bodyLimit`, two separate descents). No
        // `RequestContext` exists at head time, so the match result cannot be memoized for `respond`;
        // this is the second of the request's two total descents.
        guard case .matched(let route) = routes.matchRoute(method: method, path: bare) else {
            // No route for this method (404 / 405): the server default bounds any body it still carries.
            return ResolvedRoute(bodyLimit: serverDefault)
        }
        // A streaming route bounds its own body (the server cap does not apply); it raises the head-time
        // ceiling so the engine hands the body off incrementally rather than rejecting it early.
        if route.streamingRun != nil {
            return ResolvedRoute(bodyLimit: Int.max / 2, streamsBody: true)
        }
        // A route may RAISE the server default (an upload); a LOWER per-route bound stays post-match so
        // it can answer as problem+json.
        return ResolvedRoute(bodyLimit: max(route.maxBodyBytes ?? serverDefault, serverDefault))
    }

    /// The WebSocket endpoint for `path`, wrapped in ADServe's CSWSH origin gate (same-origin or
    /// origin-less handshakes only — evaluated in `shouldUpgrade`, which sees the full request).
    func resolveWebSocket(path: String) -> ResolvedRoute? {
        let bare = path.prefix { $0 != "?" }
        guard let endpoint = routes.webSocketEndpoint(path: bare) else { return nil }
        return ResolvedRoute(
            webSocketHandler: OriginGatedWebSocketHandler(inner: endpoint.handler),
            webSocketHub: endpoint.hub,
            webSocketTopic: endpoint.topic)
    }

    var hasWebSocketRoutes: Bool { routes.hasWebSocketRoutes }

    // MARK: Internals

    private func makeEnvironment(
        _ request: HTTPRequest, context: RequestContext
    ) -> ResponseEnvironment {
        let storage = RequestStorage()
        storage[ResponseStatusKey.self] = ResponseStatusBox()
        if let peer = context.connection.peer, !peer.host.isEmpty {
            storage[RemoteAddressKey.self] = peer.host
        }
        if let subject = context.connection.tlsPeerSubject {
            storage[TLSPeerSubjectKey.self] = subject
        }
        let negotiated = context.connection.negotiatedApplicationProtocol
        return ResponseEnvironment(
            requestID: RequestID.resolve(request.headerFields),
            isHead: request.method == .head,
            keepAlive: isKeepAlive(request),
            isHTTP2: negotiated == "h2" || negotiated == "h3",
            ifNoneMatch: request.headerFields[.ifNoneMatch],
            acceptEncoding: request.headerFields[.acceptEncoding],
            storage: storage)
    }

    /// HTTP/1.1 defaults to keep-alive unless `Connection: close`; the server-wide `keepAlive:
    /// false` policy overrides everything → always close. Unused on h2/h3 (no Connection header).
    private func isKeepAlive(_ request: HTTPRequest) -> Bool {
        guard configuration.keepAliveEnabled else { return false }
        guard let connection = request.headerFields[.connection]?.lowercased() else { return true }
        return !connection.contains("close")
    }

    /// FIX #8: consume a NON-matched request's body off the wire without accumulating it. A POST to an
    /// unknown path (404) or a wrong method (405) must still drain its body so HTTP/1.1 keep-alive
    /// framing stays exact, but the 404/405 terminal never reads those bytes — so each chunk is
    /// discarded instead of buffered into the request. A `.collected` body was already fully read by
    /// the engine during framing (nothing left on the wire), so this is a no-op there.
    private static func drainAndDiscard(_ body: RequestBody) async {
        guard body.isStreaming else { return }
        for await _ in body.asStream {}
    }

    /// Drives a streaming-body route: the handler consumes the incremental body (wrapped in the
    /// server-wide middleware chain + the error boundary); the engine reads the wire concurrently.
    private func respondStreaming(
        _ request: HTTPRequest, body: RequestBody, handler: @escaping StreamingRequestHandler,
        environment: ResponseEnvironment
    ) async -> ServerResponse {
        let serverRequest = ServerRequest(
            method: request.method, target: request.path, headers: request.headerFields, body: [])
        let bodyStream = RequestBodyStream(base: body.asStream)
        let requestID = environment.requestID
        let logger = configuration.logger
        let codec = configuration.codec
        let storage = environment.storage
        let terminal: @Sendable (ServerRequest) async -> ResponseContent = { request in
            let input = StreamingHandlerInput(
                request: request, bodyStream: bodyStream, logger: logger, requestID: requestID,
                codec: codec, storage: storage)
            do {
                return try await handler(input)
            } catch let error as HTTPError {
                return .problem(error, instance: requestID)
            } catch {
                return .problem(
                    ProblemDetails(title: "Internal Server Error", status: 500, instance: requestID))
            }
        }
        let mwContext = MiddlewareContext(requestID: requestID, logger: logger, storage: storage)
        let chain = MiddlewarePipeline.compose(
            configuration.middleware, context: mwContext, terminal: terminal)
        let content = await chain(serverRequest)
        return await finalize(content, cache: .unset, environment: environment)
    }

    /// The cache policy, route middleware, and terminal response-producer for a match result — the
    /// `.matched` error boundary + storage offload, or the 404 / 405 / auto-OPTIONS responses.
    private func resolveMatch(
        _ matchResult: RouteMatch, method: HTTPMethod, requestID: String, bodySize: Int,
        storage: RequestStorage
    ) -> ResolvedTerminal {
        switch matchResult {
            case .matched(let route):
                return resolveMatched(
                    route, requestID: requestID, bodySize: bodySize, storage: storage)
            case .methodNotAllowed(let allowed):
                let allow = allowHeader(allowed)
                let terminal: @Sendable (ServerRequest) async -> ResponseContent
                if method == .options {
                    // Auto-OPTIONS: 204 + Allow for a known path with no explicit OPTIONS route.
                    terminal = { _ in
                        .full(
                            body: [], contentType: "text/plain; charset=utf-8", status: .noContent,
                            headers: allow)
                    }
                } else {
                    terminal = { _ in
                        .full(
                            body: Array("method not allowed\n".utf8),
                            contentType: "text/plain; charset=utf-8", status: .methodNotAllowed,
                            headers: allow)
                    }
                }
                return ResolvedTerminal(cache: .unset, middleware: [], terminal: terminal)
            case .notFound:
                return ResolvedTerminal(
                    cache: .unset, middleware: [],
                    terminal: { _ in .plain(.notFound, "not found\n") })
        }
    }

    /// The `.matched` terminal: the error boundary, the per-route (lower) body bound, the
    /// `.storage` offload through the pooled connection, and the off-loop static-file resolution.
    private func resolveMatched(
        _ route: MatchedRoute, requestID: String, bodySize: Int, storage: RequestStorage
    ) -> ResolvedTerminal {
        let pool = configuration.pool
        let logger = configuration.logger
        let codec = configuration.codec
        let offload = offload
        let needsStorage = route.needsStorage
        let run = route.run
        let routeBodyLimit = route.maxBodyBytes
        // The error boundary: a thrown `HTTPError` becomes its status as problem+json; any
        // other thrown error becomes a 500 problem (keeping handler throws off the wire).
        let mapErrors: @Sendable (HandlerInput) -> ResponseContent = { input in
            do {
                return try run(input)
            } catch let error as HTTPError {
                return .problem(error, instance: requestID)
            } catch {
                return .problem(
                    ProblemDetails(title: "Internal Server Error", status: 500, instance: requestID))
            }
        }
        let terminal: @Sendable (ServerRequest) async -> ResponseContent = { request in
            // Per-route body ceiling: reject an oversized body before the handler (or its
            // connection checkout) runs. The body was already capped at the effective head-time
            // limit during accumulation, so this only enforces a *lower* per-route bound.
            if let routeBodyLimit, bodySize > routeBodyLimit {
                return .problem(
                    .contentTooLarge(
                        "request body exceeds this route's \(routeBodyLimit)-byte limit"),
                    instance: requestID)
            }
            let content: ResponseContent
            if needsStorage {
                guard let pool else { return .plain(.serviceUnavailable, "") }
                let result = try? await offload.run {
                    pool.withLease { connection in
                        mapErrors(
                            HandlerInput(
                                request: request, connection: connection, logger: logger,
                                requestID: requestID, codec: codec, storage: storage))
                    } ?? .plain(.serviceUnavailable, "")
                }
                content = result ?? .plain(.serviceUnavailable, "")
            } else {
                content = mapErrors(
                    HandlerInput(
                        request: request, connection: nil, logger: logger, requestID: requestID,
                        codec: codec, storage: storage))
            }
            // Resolve a `.file` off the cooperative pool now (before the chain unwinds): record the
            // real static status for observing middleware and stash the plan for reuse.
            await self.recordStaticStatus(content, request: request, storage: storage)
            return content
        }
        return ResolvedTerminal(cache: route.cache, middleware: route.middleware, terminal: terminal)
    }

    /// `Allow:` header listing the methods registered for a path (sent on 405 + auto-OPTIONS).
    private func allowHeader(_ methods: [HTTPMethod]) -> HTTPFields {
        var fields = HTTPFields()
        fields.setValue(methods.map(\.rawValue).joined(separator: ", "), for: .allow)
        return fields
    }
}

/// The cache policy, route middleware, and terminal handler for a resolved match — the per-request
/// response producer the middleware chain wraps.
private struct ResolvedTerminal {
    let cache: CachePolicy
    let middleware: [any HTTPMiddleware]
    let terminal: @Sendable (ServerRequest) async -> ResponseContent
}
