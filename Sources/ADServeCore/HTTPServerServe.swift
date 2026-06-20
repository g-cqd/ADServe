// The async serving loops: per-listener accept, ALPN fan-out (h1 connection vs h2 stream
// multiplexer), and the per-connection request loop that accumulates the (capped) body and hands
// each request to `respond`. Extracted from HTTPServer.swift; behavior unchanged. Fully structured:
// each connection (or h2 stream) is a child task of its accept loop.

import HTTPTypes
import NIOCore
import NIOHTTP2
import NIOHTTPTypes
import NIOPosix
import NIOSSL

/// `Retry-After` — not provided as an `HTTPField.Name` static by swift-http-types.
private let retryAfterName = HTTPField.Name("retry-after")!

/// The buffered-body framing decision for a request head (computed by `evaluateBufferedBodyHead`).
struct BufferedBodyDecision {
    /// The declared body is malformed/negative or exceeds the ceiling → answer 413 and close.
    let overflow: Bool
    /// The route-aware byte ceiling to accumulate the body against.
    let effectiveLimit: Int
    /// How many bytes to pre-reserve from a trusted Content-Length (0 = none).
    let reserve: Int
}

extension HTTPServer {
    /// Answers a connection rejected by the max-connection gate: a minimal `503 Service Unavailable` +
    /// `Connection: close` + `Retry-After`, then closes (h1). Best-effort — a peer that has already gone
    /// just gets a dropped connection.
    func rejectOverConnectionLimit(_ connection: EngineConnection) async {
        let body = Array("server at connection capacity\n".utf8)
        let allocator = connection.channel.allocator
        do {
            try await connection.executeThenClose { inbound, outbound in
                // Read the first request to its `.end` BEFORE responding: the NIO HTTP/1 pipeline handler
                // pairs a response with a received request and traps on a response written in the idle
                // state. We answer one request, then close (Connection: close) — never draining the whole
                // keep-alive stream.
                for try await part in inbound {
                    if case .end = part { break }
                }
                var headers = HTTPFields()
                headers[.contentType] = "text/plain; charset=utf-8"
                headers[.contentLength] = String(body.count)
                headers[.connection] = "close"
                headers[retryAfterName] = "1"
                try await outbound.write(
                    .head(HTTPResponse(status: .serviceUnavailable, headerFields: headers)))
                var buffer = allocator.buffer(capacity: body.count)
                buffer.writeBytes(body)
                try await outbound.write(.body(buffer))
                try await outbound.write(.end(nil))
            }
        } catch {
            // The peer may already be gone — the connection just drops.
        }
    }

    /// The accept loop for a plaintext listener: each connection's `EngineH1Result` negotiation becomes a
    /// child task — a normal HTTP connection, or an upgraded WebSocket driven to completion.
    func servePlainListener(
        _ serverChannel: NIOAsyncChannel<EventLoopFuture<EngineH1Result>, Never>,
        routes: any HTTPHandling, threadPool: NIOThreadPool
    ) async {
        do {
            try await withThrowingDiscardingTaskGroup { taskGroup in
                try await serverChannel.executeThenClose { inbound in
                    for try await negotiation in inbound {
                        taskGroup.addTask {
                            guard let result = try? await negotiation.get() else { return }
                            switch result {
                                case .http(let connection):
                                    guard connectionLimiter.tryAcquire() else {
                                        await rejectOverConnectionLimit(connection)
                                        return
                                    }
                                    defer { connectionLimiter.release() }
                                    await serveConnection(
                                        connection, routes: routes, threadPool: threadPool, isHTTP2: false)
                                case .webSocket(let wsChannel, let route):
                                    guard connectionLimiter.tryAcquire() else {
                                        wsChannel.channel.close(mode: .all, promise: nil)
                                        return
                                    }
                                    defer { connectionLimiter.release() }
                                    await driveWebSocket(wsChannel, handler: route.handler)
                            }
                        }
                    }
                }
            }
        } catch {
            // Listener-level error (group shutdown, accept failure) — stop this listener.
        }
    }

    /// The accept loop for a TLS listener: per connection, await ALPN, then serve the h1
    /// connection or fan out the h2 stream channels.
    func serveSecureListener(
        _ serverChannel: NIOAsyncChannel<EventLoopFuture<EngineNegotiated>, Never>,
        routes: any HTTPHandling, threadPool: NIOThreadPool
    ) async {
        do {
            try await withThrowingDiscardingTaskGroup { taskGroup in
                try await serverChannel.executeThenClose { inbound in
                    for try await negotiation in inbound {
                        taskGroup.addTask {
                            guard let negotiated = try? await negotiation.get() else { return }
                            switch negotiated {
                                case .http1_1(let connection):
                                    guard connectionLimiter.tryAcquire() else {
                                        await rejectOverConnectionLimit(connection)
                                        return
                                    }
                                    defer { connectionLimiter.release() }
                                    let peerCert = await peerCertificateDER(connection.channel)
                                    await serveConnection(
                                        connection, routes: routes, threadPool: threadPool, isHTTP2: false,
                                        peerCertificateDER: peerCert)
                                case .http2(let (_, multiplexer)):
                                    // An h2 connection (not its streams) takes one slot. Past the limit we
                                    // decline to serve; the unread connection idle-times out and closes.
                                    guard connectionLimiter.tryAcquire() else { return }
                                    defer { connectionLimiter.release() }
                                    await serveMultiplexer(multiplexer, routes: routes, threadPool: threadPool)
                            }
                        }
                    }
                }
            }
        } catch {
            // Listener-level error — stop this listener.
        }
    }

    /// Serves an HTTP/2 connection: each inbound stream channel is one request, served as a
    /// child task (multiplexed concurrently over the one connection).
    func serveMultiplexer(
        _ multiplexer: NIOHTTP2Handler.AsyncStreamMultiplexer<EngineConnection>,
        routes: any HTTPHandling, threadPool: NIOThreadPool
    ) async {
        do {
            try await withThrowingDiscardingTaskGroup { taskGroup in
                for try await stream in multiplexer.inbound {
                    taskGroup.addTask {
                        await serveConnection(stream, routes: routes, threadPool: threadPool, isHTTP2: true)
                    }
                }
            }
        } catch {
            // Connection-level error (GOAWAY, reset) — drop it.
        }
    }

    /// Reads the verified mTLS client certificate (DER) off a TLS h1 channel, or `nil` (plaintext / no
    /// client cert). Called once per connection by the secure accept loop, so plaintext never pays for it.
    /// The cert is extracted INSIDE the event-loop-bound `map` (the SSL handler is not `Sendable`, so it
    /// never crosses the `await`); only the DER `[UInt8]` — which is `Sendable` — is returned out.
    func peerCertificateDER(_ channel: any Channel) async -> [UInt8]? {
        let future = channel.pipeline.handler(type: NIOSSLServerHandler.self)
            .map { handler -> [UInt8]? in
                guard let certificate = handler.peerCertificate else { return nil }
                return try? certificate.toDERBytes()
            }
        return (try? await future.get()) ?? nil
    }

    /// Spawns the async streaming handler (wrapped in the server-wide middleware chain + the error
    /// boundary) for a streaming-body request, returning a task that yields its response. The handler
    /// consumes `bridge` (back-pressured) while the serve loop feeds it; on completion it closes the
    /// consumer so the feed loop unblocks even if the body wasn't drained. The request's `body` is empty —
    /// the handler reads `input.bodyStream`. (Route-level middleware is not applied to streaming routes.)
    func streamingResponseTask(
        head: HTTPRequest, handler: @escaping StreamingRequestHandler,
        bridge: BackpressuredStream<[UInt8]>, exchange: RequestExchange
    ) -> Task<ResponseContent, Never> {
        let requestID = resolveRequestID(head.headerFields)
        let request = ServerRequest(
            method: head.method, target: head.path ?? "/", headers: head.headerFields, body: [])
        let storage = exchange.storage
        storage[ResponseStatusKey.self] = ResponseStatusBox()
        if let remoteAddress = exchange.remoteAddress { storage[RemoteAddressKey.self] = remoteAddress }
        if let peerCertificateDER = exchange.peerCertificateDER {
            storage[PeerCertificateKey.self] = peerCertificateDER
        }
        let logger = self.logger
        let codec = self.codec
        let serverMiddleware = self.middleware
        let bodyStream = RequestBodyStream(source: bridge)
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
        let context = MiddlewareContext(requestID: requestID, logger: logger, storage: storage)
        let chain = composeMiddleware(serverMiddleware, context: context, terminal: terminal)
        return Task {
            let response = await chain(request)
            bridge.closeConsumer()  // handler done → unblock the feed loop if the body wasn't fully read
            return response
        }
    }

    /// Drives one streaming-body request: feeds the body to the async handler chunk-by-chunk
    /// (back-pressured) via `bridge`, then writes its response. Returns whether to keep the connection
    /// alive — `false` if the handler abandoned the body (the unread bytes would desync keep-alive). The
    /// `inout` iterator is the serve loop's, so the body is read in line with the request stream.
    func serveStreamingRequest(
        head: HTTPRequest, handler: @escaping StreamingRequestHandler, exchange: RequestExchange,
        iterator: inout NIOAsyncChannelInboundStream<HTTPRequestPart>.AsyncIterator
    ) async throws -> Bool {
        let bridge = BackpressuredStream<[UInt8]>()
        let task = streamingResponseTask(head: head, handler: handler, bridge: bridge, exchange: exchange)
        var reachedEnd = false
        feed: while let bodyPart = try await iterator.next() {
            switch bodyPart {
                case .body(let buffer):
                    if await bridge.send([UInt8](buffer.readableBytesView)) == false {
                        break feed  // the handler abandoned the body (e.g. a 401)
                    }
                case .end:
                    reachedEnd = true
                    break feed
                case .head:
                    break feed  // an unexpected pipelined head — stop feeding
            }
        }
        bridge.finish()
        let keepAlive = reachedEnd && isKeepAlive(head)
        let content = await task.value
        try await write(
            content, cache: .unset, requestID: resolveRequestID(head.headerFields), keepAlive: keepAlive,
            suppressBody: head.method == .head, exchange: exchange)
        return keepAlive
    }

    /// The buffered-body framing decision for a request head: whether the declared body is malformed /
    /// oversized (`overflow` → 413-and-close), the route-aware ceiling to accumulate against, and how much
    /// to pre-reserve. A present Content-Length must be a valid NON-NEGATIVE integer (RFC 9110 §8.6) —
    /// `Int.init` rejects non-numeric/fractional but ACCEPTS a leading `-`, so a negative length is caught
    /// here as a framing error. The route's `.maxBody` is consulted only when the declared body could
    /// exceed the server default (a Content-Length over it, or a chunked body of unknown size), so ordinary
    /// small requests never pay for the lookup; a lower per-route bound is still enforced post-match.
    func evaluateBufferedBodyHead(_ head: HTTPRequest, routes: any HTTPHandling) -> BufferedBodyDecision {
        let contentLengthField = head.headerFields[.contentLength]
        let declaredLength = contentLengthField.flatMap(Int.init)
        let declaredLengthInvalid = contentLengthField != nil && (declaredLength.map { $0 < 0 } ?? true)
        let couldExceedDefault =
            (declaredLength ?? 0) > maxBodyBytes
            || (declaredLength == nil && head.headerFields[.transferEncoding] != nil)
        let effectiveLimit =
            couldExceedDefault
            ? max(routes.bodyLimit(method: head.method, path: (head.path ?? "/")[...]) ?? maxBodyBytes, maxBodyBytes)
            : maxBodyBytes
        let overflow = declaredLengthInvalid || (declaredLength ?? 0) > effectiveLimit
        // Pre-size from Content-Length (capped at the ceiling), so accumulation doesn't grow-and-copy and a
        // lying length can't reserve past the operator-chosen bound.
        let reserve = (!overflow && (declaredLength ?? 0) > 0) ? min(declaredLength ?? 0, effectiveLimit) : 0
        return BufferedBodyDecision(overflow: overflow, effectiveLimit: effectiveLimit, reserve: reserve)
    }

    /// Serves successive requests on one connection (h1) or one stream (h2) until close /
    /// `Connection: close` (h1) or stream end (h2).
    func serveConnection(
        _ channel: EngineConnection, routes: any HTTPHandling, threadPool: NIOThreadPool,
        isHTTP2: Bool, peerCertificateDER: [UInt8]? = nil
    ) async {
        do {
            // The channel's pooled allocator — used for the response body buffer so NIO can
            // account/optimise it against this connection (NIO's documented guidance over a
            // throwaway `ByteBufferAllocator()`). A cheap `Sendable` value, captured once.
            let allocator = channel.channel.allocator
            // Resolves on client disconnect / server quiesce — an SSE stream cancels its source on it.
            let onClose = channel.channel.closeFuture
            // The peer IP (nil for a UDS / unknown peer, or an h2 stream that doesn't carry it).
            let remoteAddress = channel.channel.remoteAddress?.ipAddress
            try await channel.executeThenClose { inbound, outbound in
                var requestHead: HTTPRequest?
                var body: [UInt8] = []
                var overflow = false
                var effectiveLimit = maxBodyBytes
                // An EXPLICIT iterator (not `for try await`) so a streaming-body route's `.head` branch can
                // read its own body parts in a nested loop, handing each to the async handler back-pressured.
                var iterator = inbound.makeAsyncIterator()
                while let part = try await iterator.next() {
                    switch part {
                        case .head(let head):
                            requestHead = head
                            body = []
                            overflow = false
                            // Streaming-body route (detected FIRST, before any buffered-body cap): hand the
                            // body to the async handler chunk-by-chunk (back-pressured) rather than buffering
                            // it — a streaming upload sets its own bound (`bodyStream.collect`), so the server
                            // body cap doesn't apply. The nested feed loop owns the iterator until `.end`, then
                            // `continue` resumes the outer keep-alive loop.
                            if let streamingHandler = routes.streamingHandler(
                                method: head.method, path: (head.path ?? "/").prefix { $0 != "?" })
                            {
                                requestHead = nil
                                active.enter()
                                defer { active.leave() }
                                let exchange = RequestExchange(
                                    head: head, outbound: outbound, isHTTP2: isHTTP2, allocator: allocator,
                                    onClose: onClose, threadPool: threadPool, storage: RequestStorage(),
                                    remoteAddress: remoteAddress, peerCertificateDER: peerCertificateDER)
                                let keepAlive = try await serveStreamingRequest(
                                    head: head, handler: streamingHandler, exchange: exchange,
                                    iterator: &iterator)
                                if !keepAlive { return }
                                continue
                            }
                            // The buffered-body framing decision (overflow / route-aware ceiling / reserve).
                            // A malformed or oversized declared length sets `overflow`, routing to the same
                            // 413-and-close path the post-hoc `.body` overflow uses.
                            let decision = evaluateBufferedBodyHead(head, routes: routes)
                            overflow = decision.overflow
                            effectiveLimit = decision.effectiveLimit
                            if decision.reserve > 0 { body.reserveCapacity(decision.reserve) }
                            // `Expect: 100-continue` (HTTP/2 only here): the client announced it is WAITING
                            // for our go-ahead before sending the body. Send the `100 Continue` interim now
                            // (head only) so it proceeds — UNLESS we already know the declared body is
                            // oversized/malformed (`overflow`), in which case the `.end` 413-and-close path
                            // answers and we never invite a body we would only reject (RFC 9110 §10.1.1).
                            // The HTTP/1 path is handled by `HTTP1ExpectContinueHandler` in the pipeline,
                            // ahead of the response compressor (which cannot tolerate an interim head).
                            if isHTTP2, !overflow,
                                let expect = head.headerFields[.expect],
                                expect.lowercased().contains("100-continue")
                            {
                                try await outbound.write(.head(HTTPResponse(status: .continue)))
                            }
                        case .body(let buffer):
                            if !overflow {
                                body.append(contentsOf: buffer.readableBytesView)
                                if body.count > effectiveLimit {
                                    overflow = true
                                    body = []
                                }
                            }
                        case .end:
                            guard let head = requestHead else { continue }
                            requestHead = nil
                            active.enter()
                            defer { active.leave() }
                            let exchange = RequestExchange(
                                head: head, outbound: outbound, isHTTP2: isHTTP2, allocator: allocator,
                                onClose: onClose, threadPool: threadPool, storage: RequestStorage(),
                                remoteAddress: remoteAddress, peerCertificateDER: peerCertificateDER)
                            let keepAlive: Bool
                            if overflow {
                                try await writeBodyTooLarge(exchange)
                                keepAlive = false
                            } else {
                                keepAlive = try await respond(
                                    exchange, body: body, routes: routes, threadPool: threadPool)
                            }
                            body = []
                            if !keepAlive { return }
                    }
                }
            }
        } catch {
            // Connection-level error (client reset, malformed framing) — drop it.
        }
    }
}
