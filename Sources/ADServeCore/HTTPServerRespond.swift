// The response path: route resolution (the error boundary + storage offload), the response-writing
// envelope (ETag/304, content-type/length, cache-control, the constant header set, request-id, h1
// connection header), and the materialized buffered-response shape. Extracted from HTTPServer.swift;
// behavior unchanged. `RequestExchange` (the per-request transport context) lives on HTTPServer.swift.

import ADConcurrency
import HTTPTypes
import Logging
import NIOCore
import NIOHTTPTypes
import NIOPosix

/// The flattened buffered response a `write` starts from: status, content-type, body bytes, and any
/// route-supplied headers (applied over the envelope). A named struct rather than a 4-tuple — it
/// names the fields at the write site and stays within the large-tuple budget.
struct MaterializedResponse {
    var status: HTTPResponse.Status
    var contentType: String
    var body: [UInt8]
    var headers: HTTPFields
}

extension HTTPServer {
    func writeBodyTooLarge(_ exchange: RequestExchange) async throws {
        try await write(
            .plain(HTTPResponse.Status(code: 413), "request too large\n"), cache: .unset,
            requestID: resolveRequestID(exchange.head.headerFields), keepAlive: false, exchange: exchange)
    }

    /// Resolves + runs the route for one request, then writes the response. Returns
    /// whether to keep the connection alive.
    func respond(
        _ exchange: RequestExchange, body: [UInt8], routes: any HTTPHandling, threadPool: NIOThreadPool
    ) async throws -> Bool {
        let head = exchange.head
        let keepAlive = isKeepAlive(head)
        let request = ServerRequest(
            method: head.method, target: head.path ?? "/", headers: head.headerFields, body: body)
        let requestID = resolveRequestID(head.headerFields)
        let isHead = head.method == .head
        let storage = RequestStorage()

        // Reject directory traversal (`.`/`..` segments) before routing — a catch-all route would
        // otherwise hand `../../etc/passwd` to a handler.
        if pathHasTraversal(request.path) {
            try await write(
                .plain(.badRequest, "bad request path\n"), cache: .unset, requestID: requestID,
                keepAlive: keepAlive, suppressBody: isHead, exchange: exchange)
            return keepAlive
        }

        // Resolve the route. A HEAD with no explicit HEAD route falls back to the GET route (the
        // body is suppressed at write time).
        var matchResult = routes.match(method: head.method, path: request.path)
        if isHead {
            if case .matched = matchResult {
            } else {
                matchResult = routes.match(method: .get, path: request.path)
            }
        }

        let resolved = resolveRoute(
            matchResult, method: head.method, requestID: requestID, body: body, storage: storage,
            threadPool: threadPool)

        // Compose server-wide + route middleware (server-wide outermost) around the terminal.
        let mwContext = MiddlewareContext(requestID: requestID, logger: logger, storage: storage)
        let chain = composeMiddleware(
            middleware + resolved.middleware, context: mwContext, terminal: resolved.terminal)
        let content = await chain(request)

        try await write(
            content, cache: resolved.cache, requestID: requestID, keepAlive: keepAlive,
            suppressBody: isHead, exchange: exchange)
        return keepAlive
    }

    /// The cache policy, route middleware, and terminal response-producer for a match result — the
    /// `.matched` error boundary + storage offload, or the 404 / 405 / auto-OPTIONS responses. Split
    /// out of `respond` so each stays within the function-body-length budget.
    private func resolveRoute(
        _ matchResult: RouteMatch, method: HTTPRequest.Method, requestID: String, body: [UInt8],
        storage: RequestStorage, threadPool: NIOThreadPool
    ) -> ResolvedRoute {
        switch matchResult {
            case .matched(let route):
                let pool = self.pool
                let logger = self.logger
                let codec = self.codec
                let needsStorage = route.needsStorage
                let run = route.run
                let routeBodyLimit = route.maxBodyBytes
                let bodySize = body.count
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
                let terminal: @Sendable (ServerRequest) async -> ResponseContent = { req in
                    // Per-route body ceiling: reject an oversized body before the handler (or its
                    // connection checkout) runs. The body was already capped at the server-wide limit
                    // during accumulation, so this only enforces a *lower* per-route bound.
                    if let routeBodyLimit, bodySize > routeBodyLimit {
                        return .problem(
                            .contentTooLarge("request body exceeds this route's \(routeBodyLimit)-byte limit"),
                            instance: requestID)
                    }
                    if needsStorage {
                        guard let pool else { return .plain(.serviceUnavailable, "") }
                        let result = try? await threadPool.runIfActive {
                            pool.withLease { connection in
                                mapErrors(
                                    HandlerInput(
                                        request: req, connection: connection, logger: logger,
                                        requestID: requestID, codec: codec, storage: storage))
                            } ?? .plain(.serviceUnavailable, "")
                        }
                        return result ?? .plain(.serviceUnavailable, "")
                    }
                    return mapErrors(
                        HandlerInput(
                            request: req, connection: nil, logger: logger, requestID: requestID,
                            codec: codec, storage: storage))
                }
                return ResolvedRoute(cache: route.cache, middleware: route.middleware, terminal: terminal)
            case .methodNotAllowed(let allowed):
                let allow = allowHeader(allowed)
                let terminal: @Sendable (ServerRequest) async -> ResponseContent
                if method == .options {
                    // Auto-OPTIONS: 204 + Allow for a known path with no explicit OPTIONS route.
                    terminal = { _ in
                        .full(body: [], contentType: "text/plain; charset=utf-8", status: .noContent, headers: allow)
                    }
                } else {
                    terminal = { _ in
                        .full(
                            body: Array("method not allowed\n".utf8),
                            contentType: "text/plain; charset=utf-8", status: .methodNotAllowed, headers: allow)
                    }
                }
                return ResolvedRoute(cache: .unset, middleware: [], terminal: terminal)
            case .notFound:
                return ResolvedRoute(
                    cache: .unset, middleware: [], terminal: { _ in .plain(.notFound, "not found\n") })
        }
    }

    /// Applies the response envelope: ETag/304, content-type/length, cache-control, the
    /// constant header set, the minted/echoed request-id, and (h1 only) the connection header.
    func write(
        _ content: ResponseContent, cache: CachePolicy, requestID: String, keepAlive: Bool,
        suppressBody: Bool = false, exchange: RequestExchange
    ) async throws {
        var materialized = materialize(content)
        var headers = HTTPFields()
        var emitEntity = true

        // ETag computed once from the original entity; on a match, blank the body → 304
        // but keep the ETag header (RFC 7232).
        if cache.etag {
            let etag = "\"\(sha256HexLower(materialized.body).prefix(16))\""
            headers[.eTag] = etag
            if let inm = exchange.head.headerFields[.ifNoneMatch], matchesIfNoneMatch(inm, etag) {
                materialized.status = .notModified
                materialized.body = []
                emitEntity = false
            }
        }
        if emitEntity {
            headers[.contentType] = materialized.contentType
            headers[.contentLength] = String(materialized.body.count)
        }
        if let cacheControl = cache.cacheControl { headers[.cacheControl] = cacheControl }
        headers.append(contentsOf: envelope)
        headers[requestIDName] = requestID
        // HTTP/2 forbids the connection-specific `Connection` header (an HTTP/1.1 concept).
        if !exchange.isHTTP2 { headers[.connection] = keepAlive ? "keep-alive" : "close" }
        // Route-supplied headers override the envelope (CORS / the MCP `/mcp` set).
        for field in materialized.headers { headers[field.name] = field.value }

        try await exchange.outbound.write(
            .head(HTTPResponse(status: materialized.status, headerFields: headers)))
        if !materialized.body.isEmpty && !suppressBody {
            // `HTTPResponsePart.body` is a `ByteBuffer`, so the route's `[UInt8]` must be copied into
            // NIO-owned storage once (a single contiguous memcpy — unavoidable without threading a
            // `ByteBuffer` through the whole `ResponseContent`/route surface). Take that one buffer from
            // the connection's pooled allocator with the exact capacity, rather than a throwaway
            // `ByteBufferAllocator()` per response: NIO can then pool/account it against the channel
            // (its documented recommendation). The body is identical bytes either way.
            var buffer = exchange.allocator.buffer(capacity: materialized.body.count)
            buffer.writeBytes(materialized.body)
            try await exchange.outbound.write(.body(buffer))
        }
        try await exchange.outbound.write(.end(nil))
    }

    func materialize(_ content: ResponseContent) -> MaterializedResponse {
        switch content {
            case .raw(let body, let contentType, let status):
                return MaterializedResponse(
                    status: status, contentType: contentType, body: body, headers: HTTPFields())
            case .notFound:
                return MaterializedResponse(
                    status: .notFound, contentType: "text/plain; charset=utf-8",
                    body: Array("Not Found".utf8), headers: HTTPFields())
            case .plain(let status, let message):
                return MaterializedResponse(
                    status: status, contentType: "text/plain; charset=utf-8",
                    body: Array(message.utf8), headers: HTTPFields())
            case .full(let body, let contentType, let status, let headers):
                return MaterializedResponse(
                    status: status, contentType: contentType, body: body, headers: headers)
        }
    }

    /// HTTP/1.1 default keep-alive unless `Connection: close` (HTTP/1.0 clients are out
    /// of scope; fetch + Caddy are 1.1). For h2 this is unused (one request per stream).
    func isKeepAlive(_ head: HTTPRequest) -> Bool {
        guard let connection = head.headerFields[.connection]?.lowercased() else { return true }
        return !connection.contains("close")
    }

    /// `Allow:` header listing the methods registered for a path (sent on 405 + auto-OPTIONS).
    func allowHeader(_ methods: [HTTPRequest.Method]) -> HTTPFields {
        var fields = HTTPFields()
        fields[HTTPField.Name("Allow")!] = methods.map(\.rawValue).joined(separator: ", ")
        return fields
    }
}

/// The cache policy, route middleware, and terminal handler for a resolved match — the per-request
/// response producer the middleware chain wraps.
private struct ResolvedRoute {
    let cache: CachePolicy
    let middleware: [any HTTPMiddleware]
    let terminal: @Sendable (ServerRequest) async -> ResponseContent
}
