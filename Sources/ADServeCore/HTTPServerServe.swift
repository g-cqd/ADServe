// The async serving loops: per-listener accept, ALPN fan-out (h1 connection vs h2 stream
// multiplexer), and the per-connection request loop that accumulates the (capped) body and hands
// each request to `respond`. Extracted from HTTPServer.swift; behavior unchanged. Fully structured:
// each connection (or h2 stream) is a child task of its accept loop.

import HTTPTypes
import NIOCore
import NIOHTTP2
import NIOHTTPTypes
import NIOPosix

extension HTTPServer {
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
                                    await serveConnection(
                                        connection, routes: routes, threadPool: threadPool, isHTTP2: false)
                                case .http2(let (_, multiplexer)):
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

    /// Serves successive requests on one connection (h1) or one stream (h2) until close /
    /// `Connection: close` (h1) or stream end (h2).
    func serveConnection(
        _ channel: EngineConnection, routes: any HTTPHandling, threadPool: NIOThreadPool,
        isHTTP2: Bool
    ) async {
        do {
            // The channel's pooled allocator — used for the response body buffer so NIO can
            // account/optimise it against this connection (NIO's documented guidance over a
            // throwaway `ByteBufferAllocator()`). A cheap `Sendable` value, captured once.
            let allocator = channel.channel.allocator
            // Resolves on client disconnect / server quiesce — an SSE stream cancels its source on it.
            let onClose = channel.channel.closeFuture
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
                                onClose: onClose)
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
