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

/// The engine's `ResponseBodyWriter`, backed by the connection's outbound channel writer. Each `write`
/// copies the chunk into a pooled NIO `ByteBuffer` (one memcpy — identical to the buffered path) and
/// awaits `outbound.write`, which suspends while the channel is not writable: that suspension IS the
/// back-pressure. `NIOAsyncChannelOutboundWriter` flushes per write, so `<head>` reaches the client
/// immediately and `flush()` has nothing to drain. `Sendable` (both stored values are), so it crosses
/// into the `@Sendable` `.stream` body closure.
struct ChannelBodyWriter: ResponseBodyWriter {
    let outbound: NIOAsyncChannelOutboundWriter<HTTPResponsePart>
    let allocator: ByteBufferAllocator

    func write(_ bytes: [UInt8]) async throws {
        guard !bytes.isEmpty else { return }
        var buffer = allocator.buffer(capacity: bytes.count)
        buffer.writeBytes(bytes)
        try await outbound.write(.body(buffer))
    }

    func flush() async throws {}
}

/// Pure WHATWG `text/event-stream` framing — separated from the channel writer so the grammar
/// (field order, multi-line `data`, single-line sanitization) is unit-testable without a socket.
enum SSEFraming {
    /// One event frame: optional `event:`/`id:`/`retry:` fields, then one `data:` line per line of
    /// `data`, then the terminating blank line that dispatches the event.
    static func event(event: String?, data: String, id: String?, retry: Int?) -> String {
        var frame = ""
        if let event { frame += "event: \(singleLine(event))\n" }
        if let id { frame += "id: \(singleLine(id))\n" }
        if let retry { frame += "retry: \(retry)\n" }
        // One `data:` line per line of `data`. Split at the SCALAR level: Swift clusters "\r\n" into a
        // single `Character`, so a Character-level split on "\n" would miss CRLF entirely. Stripping a
        // trailing CR off each piece then makes "\r\n" collapse to one line break.
        for piece in data.unicodeScalars.split(separator: "\n", omittingEmptySubsequences: false) {
            var line = String(String.UnicodeScalarView(piece))
            if line.hasSuffix("\r") { line.removeLast() }
            frame += "data: \(line)\n"
        }
        return frame + "\n"
    }

    /// A `: comment` line — the SSE keep-alive heartbeat (dispatches no event).
    static func comment(_ text: String) -> String { ": \(singleLine(text))\n" }

    /// Everything up to the first newline — keeps a single-line field (`event:`/`id:`/`: comment`) from
    /// being split into multiple lines by an embedded `\n`/`\r` (frame-injection defense).
    static func singleLine(_ value: String) -> String {
        String(value.prefix { $0 != "\n" && $0 != "\r" })
    }
}

/// The engine's `SSEWriter`: frames each event/comment via `SSEFraming` and writes it as one chunk
/// (flushed immediately, so a heartbeat reaches the client at once). `Sendable` (both stored values are).
struct ChannelSSEWriter: SSEWriter {
    let outbound: NIOAsyncChannelOutboundWriter<HTTPResponsePart>
    let allocator: ByteBufferAllocator

    func send(event: String?, data: String, id: String?, retry: Int?) async throws {
        try await writeFrame(SSEFraming.event(event: event, data: data, id: id, retry: retry))
    }

    func comment(_ text: String) async throws {
        try await writeFrame(SSEFraming.comment(text))
    }

    private func writeFrame(_ frame: String) async throws {
        var buffer = allocator.buffer(capacity: frame.utf8.count)
        buffer.writeString(frame)
        try await outbound.write(.body(buffer))
    }
}

/// A minimal FIFO async mutex serializing the SSE body's writes against the engine heartbeat's writes
/// (only built when a heartbeat interval is set). Non-reentrant: `acquire` suspends until the holder
/// `release`s, and the holder keeps the gate across its suspending `outbound.write` — so the two
/// writer tasks never call the NIO async writer concurrently, while per-event back-pressure is
/// preserved (a blocked write blocks the next acquirer too, which is the desired throttle). Contention
/// is at most two waiters (body + heartbeat), so the waiter array stays tiny.
actor FIFOAsyncGate {
    private var held = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func acquire() async {
        if !held {
            held = true
            return
        }
        await withCheckedContinuation { waiters.append($0) }
    }

    func release() {
        if waiters.isEmpty {
            held = false
        } else {
            waiters.removeFirst().resume()
        }
    }
}

/// An `SSEWriter` that routes every frame through an `FIFOAsyncGate`, so the body and the engine
/// heartbeat can both write to one channel without racing the NIO outbound writer. Releases the gate
/// on both success and a thrown write (so a failed write never strands the gate held).
struct GatedSSEWriter: SSEWriter {
    let inner: ChannelSSEWriter
    let gate: FIFOAsyncGate

    func send(event: String?, data: String, id: String?, retry: Int?) async throws {
        await gate.acquire()
        do {
            try await inner.send(event: event, data: data, id: id, retry: retry)
        } catch {
            await gate.release()
            throw error
        }
        await gate.release()
    }

    func comment(_ text: String) async throws {
        await gate.acquire()
        do {
            try await inner.comment(text)
        } catch {
            await gate.release()
            throw error
        }
        await gate.release()
    }
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
        // One storage instance per request, shared by the middleware context, the terminal, and the
        // write path (`exchange.storage`). Seed the resolved-status box so an observing middleware can
        // read the engine-recorded real status (notably a static file's off-loop-resolved status).
        let storage = exchange.storage
        storage[ResponseStatusKey.self] = ResponseStatusBox()
        if let remoteAddress = exchange.remoteAddress { storage[RemoteAddressKey.self] = remoteAddress }
        if let peerCertificateDER = exchange.peerCertificateDER {
            storage[PeerCertificateKey.self] = peerCertificateDER
        }

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
                    let content: ResponseContent
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
                        content = result ?? .plain(.serviceUnavailable, "")
                    } else {
                        content = mapErrors(
                            HandlerInput(
                                request: req, connection: nil, logger: logger, requestID: requestID,
                                codec: codec, storage: storage))
                    }
                    // Resolve a `.file` off-loop now (before the chain unwinds): record the real static
                    // status for observing middleware and stash the plan for `writeFile` to reuse.
                    await self.recordStaticStatus(
                        content, request: req, storage: storage, threadPool: threadPool)
                    return content
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
        // Streaming responses take a distinct path: an early head (no Content-Length/ETag — the body
        // length is unknown, so h1 is chunked and h2 length-less), then writer-driven body chunks
        // (back-pressure implicit in each `await outbound.write`), then end. A mid-stream throw
        // propagates out, dropping the connection WITHOUT a clean `.end` (the client sees truncation).
        if case .stream(let contentType, let status, let extra, let body) = content {
            var headers = commonHeaders(
                cache: cache, requestID: requestID, keepAlive: keepAlive, isHTTP2: exchange.isHTTP2)
            headers[.contentType] = contentType
            mergeResponseHeaders(extra, into: &headers)
            try await exchange.outbound.write(.head(HTTPResponse(status: status, headerFields: headers)))
            if !suppressBody {
                try await body(
                    ChannelBodyWriter(outbound: exchange.outbound, allocator: exchange.allocator))
            }
            try await exchange.outbound.write(.end(nil))
            return
        }

        // Server-Sent Events: a long-lived text/event-stream. Admission-controlled (503 at capacity),
        // `no-store`, status 200, with the source cancelled the instant the peer disconnects or the
        // server quiesces (so the slot frees promptly — see `driveSSE`).
        if case .sse(let extra, let heartbeat, let body) = content {
            guard sseLimiter.tryAcquire() else {
                try await write(
                    .plain(.serviceUnavailable, "SSE capacity reached\n"), cache: .noStore,
                    requestID: requestID, keepAlive: keepAlive, suppressBody: suppressBody,
                    exchange: exchange)
                return
            }
            defer { sseLimiter.release() }
            var headers = commonHeaders(
                cache: .noStore, requestID: requestID, keepAlive: keepAlive, isHTTP2: exchange.isHTTP2)
            headers[.contentType] = "text/event-stream"
            mergeResponseHeaders(extra, into: &headers)
            try await exchange.outbound.write(.head(HTTPResponse(status: .ok, headerFields: headers)))
            if !suppressBody {
                try await driveSSE(
                    body,
                    writer: ChannelSSEWriter(outbound: exchange.outbound, allocator: exchange.allocator),
                    heartbeat: heartbeat, onClose: exchange.onClose)
            }
            try? await exchange.outbound.write(.end(nil))  // best-effort: the peer may already be gone
            return
        }

        // A guarded static file: the jail/stat/read run off the event loop (NIOThreadPool); the engine
        // then writes 200 (streamed body) / 304 / 404. See HTTPServerStatic.swift.
        if case .file(let root, let subpath, let contentType, let fileHeaders) = content {
            try await writeFile(
                StaticFileRequest(
                    root: root, subpath: subpath, contentType: contentType, headers: fileHeaders),
                cache: cache, requestID: requestID, exchange: exchange)
            return
        }

        var materialized = materialize(content)
        var headers = commonHeaders(
            cache: cache, requestID: requestID, keepAlive: keepAlive, isHTTP2: exchange.isHTTP2)
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
        // Route-supplied headers override the envelope (CORS / the MCP `/mcp` set); `set-cookie` appends.
        mergeResponseHeaders(materialized.headers, into: &headers)

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

    /// Drives an SSE `body` to completion, cancelling it the instant the channel closes (peer
    /// disconnect or server quiesce) or the serving task is cancelled — so the source stops and the
    /// slot frees without waiting for the next failed write. Normal completion or cancellation is a
    /// clean end; any other thrown error propagates (dropping the connection).
    ///
    /// With a `heartbeat` interval the engine also runs a child task emitting a `: ` keep-alive comment
    /// every interval. Both the body and the heartbeat write through one `FIFOAsyncGate` (a FIFO async
    /// mutex) so the two tasks never call the NIO outbound writer concurrently — and the gate is held
    /// across each suspending write, so per-event back-pressure is preserved. Without a heartbeat the
    /// body is the sole writer and writes directly (zero added overhead, the prior behavior verbatim).
    private func driveSSE(
        _ body: @escaping @Sendable (any SSEWriter) async throws -> Void, writer: ChannelSSEWriter,
        heartbeat: Duration?, onClose: EventLoopFuture<Void>
    ) async throws {
        let gate = heartbeat != nil ? FIFOAsyncGate() : nil
        let bodyWriter: any SSEWriter = gate.map { GatedSSEWriter(inner: writer, gate: $0) } ?? writer
        let bodyTask = Task { try await body(bodyWriter) }
        onClose.whenComplete { _ in bodyTask.cancel() }

        let heartbeatTask: Task<Void, Never>?
        if let heartbeat, let gate {
            let pinger = GatedSSEWriter(inner: writer, gate: gate)
            heartbeatTask = Task {
                while !Task.isCancelled {
                    try? await Task.sleep(for: heartbeat)
                    if Task.isCancelled { break }
                    do { try await pinger.comment("") } catch { break }  // peer gone → stop pinging
                }
            }
        } else {
            heartbeatTask = nil
        }

        try await withTaskCancellationHandler {
            defer { heartbeatTask?.cancel() }
            do {
                try await bodyTask.value
            } catch is CancellationError {
                // Peer disconnected / server quiescing — a normal SSE end, not an error to surface.
            }
        } onCancel: {
            bodyTask.cancel()
            heartbeatTask?.cancel()
        }
    }

    /// The headers common to every response: cache-control (if any), the constant envelope (security
    /// set + Link + Vary), the echoed/minted request-id, and — h1 only (HTTP/2 forbids it) — the
    /// keep-alive/close connection header. The buffered path layers content-type/length (+ ETag) on
    /// top; the streamed path layers content-type (no length/ETag, since the body is unbounded).
    func commonHeaders(
        cache: CachePolicy, requestID: String, keepAlive: Bool, isHTTP2: Bool
    ) -> HTTPFields {
        var headers = HTTPFields()
        if let cacheControl = cache.cacheControl { headers[.cacheControl] = cacheControl }
        headers.append(contentsOf: envelope)
        headers[requestIDName] = requestID
        if !isHTTP2 { headers[.connection] = keepAlive ? "keep-alive" : "close" }
        return headers
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
            case .stream, .sse, .file:
                // Unreachable: these are handled in `write` before `materialize`. Return a benign 500
                // (failure-safe — never traps) should a future buffered caller forget to gate on them.
                return MaterializedResponse(
                    status: .internalServerError, contentType: "text/plain; charset=utf-8", body: [],
                    headers: HTTPFields())
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
