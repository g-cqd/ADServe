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

    /// The accept loop for a plaintext listener: each connection becomes a child task.
    func servePlainListener(
        _ serverChannel: NIOAsyncChannel<EngineConnection, Never>, routes: any HTTPHandling,
        threadPool: NIOThreadPool
    ) async {
        do {
            try await withThrowingDiscardingTaskGroup { taskGroup in
                try await serverChannel.executeThenClose { inbound in
                    for try await connection in inbound {
                        taskGroup.addTask {
                            guard connectionLimiter.tryAcquire() else {
                                await rejectOverConnectionLimit(connection)
                                return
                            }
                            defer { connectionLimiter.release() }
                            await serveConnection(
                                connection, routes: routes, threadPool: threadPool, isHTTP2: false)
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
                for try await part in inbound {
                    switch part {
                        case .head(let head):
                            requestHead = head
                            body = []
                            overflow = false
                            // A present Content-Length must be a valid NON-NEGATIVE integer (RFC 9110
                            // §8.6). `Int.init` already rejects non-numeric / fractional values (→ nil);
                            // it ACCEPTS a leading `-`, so a negative length (e.g. `-1`) parses and must be
                            // caught here. Distinguish "header present but unparseable/negative" from
                            // "header absent": only the former is a framing error.
                            let contentLengthField = head.headerFields[.contentLength]
                            let declaredLength = contentLengthField.flatMap(Int.init)
                            // Present but unparseable (`Int.init` → nil) or negative ⇒ a framing error.
                            let declaredLengthInvalid =
                                contentLengthField != nil && (declaredLength.map { $0 < 0 } ?? true)
                            // The body ceiling for THIS request. Normally the server default — but a route
                            // may raise its own limit above it (uploads). So only when the declared body
                            // could exceed the default (a Content-Length over it, or a chunked body of
                            // unknown size) do we consult the route's `.maxBody`; ordinary small/bodyless
                            // requests never pay for that lookup. A lower per-route limit is still enforced
                            // post-match in `respond()` (as a problem+json 413).
                            let couldExceedDefault =
                                (declaredLength ?? 0) > maxBodyBytes
                                || (declaredLength == nil && head.headerFields[.transferEncoding] != nil)
                            effectiveLimit =
                                couldExceedDefault
                                ? max(
                                    routes.bodyLimit(method: head.method, path: (head.path ?? "/")[...])
                                        ?? maxBodyBytes, maxBodyBytes)
                                : maxBodyBytes
                            // Reject a malformed/negative/oversized Content-Length BEFORE pre-sizing the
                            // buffer, rather than trusting it into `reserveCapacity` and only catching an
                            // oversized body post-hoc during accumulation. An oversized declared length is
                            // compared against `effectiveLimit` (the route-aware ceiling — so an upload
                            // route's raised limit still applies), exactly mirroring the `.body` overflow
                            // check below. Both faults route to the SAME 413-and-close path the post-hoc
                            // overflow uses (the `.end` case writes `writeBodyTooLarge` when `overflow`).
                            if declaredLengthInvalid || (declaredLength ?? 0) > effectiveLimit {
                                overflow = true
                            }
                            // Pre-size from Content-Length (capped at the effective limit) so accumulation
                            // doesn't repeatedly grow-and-copy; a lying length can't reserve beyond the
                            // route's own (operator-chosen) ceiling. Skipped once `overflow` is set above.
                            if !overflow, let declaredLength, declaredLength > 0 {
                                body.reserveCapacity(min(declaredLength, effectiveLimit))
                            }
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
