// The NIO bootstrap + the async serving loop + the response-writing envelope.
// One NIO listener per `ListenerConfig`, all sharing one event-loop group,
// offload thread pool, connection pool, and response envelope. Each listener
// speaks its `Wire`: plaintext HTTP/1.1, or — under TLS — HTTP/1.1 and/or
// HTTP/2 chosen by ALPN. Both versions bridge to the SAME
// `HTTPRequest`/`HTTPResponse`/`HTTPFields` value types via the NIOHTTPTypes
// codecs, so one `serveConnection` loop serves an h1 connection or an h2
// stream identically. Fully structured concurrency: each listener is a child
// task of `run()`; each connection (or h2 stream) a child task of its accept
// loop; the one blocking handler per `.storage` request is offloaded to the
// NIOThreadPool with a pooled connection.

import ADConcurrency
public import HTTPTypes
public import Logging
import NIOCore
import NIOExtras
import NIOHTTP1
import NIOHTTP2
import NIOHTTPTypes
import NIOHTTPTypesHTTP1
import NIOHTTPTypesHTTP2
import NIOPosix
import NIOSSL
import ServiceLifecycle
import Synchronization
import UnixSignals

// NIOTransportServices (Network.framework) is Apple-only; the engine falls back to NIOPosix
// elsewhere so the package still builds on Linux (the dylib + CI stay cross-platform).
#if canImport(Network)
    import NIOTransportServices
#endif

/// One accepted connection (h1) or h2 stream: streams `HTTPRequestPart`/`HTTPResponsePart`.
private typealias EngineConnection = NIOAsyncChannel<HTTPRequestPart, HTTPResponsePart>
/// The ALPN outcome on a TLS connection: an h1 connection, or an h2 connection whose stream
/// channels arrive on the multiplexer.
private typealias EngineNegotiated = NIONegotiatedHTTPVersion<
    EngineConnection, (Void, NIOHTTP2Handler.AsyncStreamMultiplexer<EngineConnection>)
>

/// A shared count of requests actively being handled — so a drain waits for real in-flight
/// work (not idle keep-alive connections, which linger until force-closed). A lock-free
/// `Atomic` (the counter is hot: every request brackets it); boxed in a class so the
/// `~Copyable` atomic lives behind a shared reference the (copied) engine value carries.
private final class ActiveRequests: Sendable {
    private let value = Atomic<Int>(0)
    func enter() { value.wrappingAdd(1, ordering: .relaxed) }
    func leave() { value.wrappingSubtract(1, ordering: .relaxed) }
    var count: Int { value.load(ordering: .relaxed) }
}

/// A lightweight engine error with a message (startup/config failures).
private struct EngineError: Error { let message: String }

/// The ad-server engine. Binds one NIO listener per `ListenerConfig`, all sharing the
/// event-loop group + offload pool + connection pool + envelope; serves until cancelled.
/// The app builds the listeners (DSL) + the response `envelope` and hands them in.
public struct HTTPServer: Sendable {
    let listeners: [ListenerConfig]
    /// The type-erased connection pool — `nil` for a server with no `.storage` routes (headless).
    let pool: AnyConnectionPool?
    /// The constant headers applied to every response (security set + Link + Vary).
    let envelope: HTTPFields
    let logger: Logger
    let threadCount: Int
    let loopCount: Int
    /// Flipped true once all listeners are bound, false when draining (read by `/readyz`).
    let readiness: ServerReadiness?
    /// The bound transport — `.network` uses NIOTransportServices on Apple, else `.nio`.
    let transport: EngineTransport
    /// Server-wide middleware (outermost first). Wraps routing on EVERY request, so it also sees
    /// `notFound`/`methodNotAllowed` and can short-circuit before dispatch. Per-group/route
    /// middleware (from the DSL) rides `MatchedRoute.middleware` and wraps only the matched handler.
    let middleware: [any HTTPMiddleware]
    /// The content codec a handler's `ctx.decode`/`ctx.json` route through (default `.json`).
    let codec: ContentCodec
    /// Server-wide DEFAULT request-body ceiling in bytes; a larger body → 413 + close before the
    /// handler runs. Default 1 MiB. A route may override it with `.maxBody(_:)` — *higher* (an upload
    /// endpoint; the engine peeks the route at the request head to size accumulation) or *lower* (a
    /// tighter bound, enforced post-match as a problem+json 413).
    let maxBodyBytes: Int
    /// In-flight request count, so a drain waits for real work, not idle keep-alive connections.
    private let active = ActiveRequests()

    public init(
        listeners: [ListenerConfig], pool: AnyConnectionPool?, envelope: HTTPFields, logger: Logger,
        threadCount: Int, loopCount: Int = 2, readiness: ServerReadiness? = nil,
        transport: EngineTransport = .nio, middleware: [any HTTPMiddleware] = [],
        codec: ContentCodec = .json, maxBodyBytes: Int = 1_000_000
    ) {
        self.listeners = listeners
        self.pool = pool
        self.envelope = envelope
        self.logger = logger
        self.threadCount = max(1, threadCount)
        self.loopCount = max(1, loopCount)
        self.readiness = readiness
        self.transport = transport
        self.middleware = middleware
        self.codec = codec
        self.maxBodyBytes = max(0, maxBodyBytes)
    }

    public func run() async throws {
        let threadPool = NIOThreadPool(numberOfThreads: threadCount)
        threadPool.start()
        let group = makeEventLoopGroup()

        // Serve under a `ServiceGroup` in its own scope, so the listeners + quiescing helpers
        // (each holds an event-loop promise) are released BEFORE the ELG is torn down — otherwise
        // their teardown would schedule on an already-shutdown event loop.
        try await serveUntilShutdown(group: group, threadPool: threadPool)

        try? await group.shutdownGracefully()
        try? await threadPool.shutdownGracefully()
        logger.info("ad-server stopped")
    }

    /// Binds the listeners and serves them under a `ServiceGroup` until graceful shutdown. Scoped
    /// so every NIO value that holds an event-loop promise (the listeners + quiescing helpers) is
    /// released when this returns, before the caller tears the ELG down.
    private func serveUntilShutdown(group: any EventLoopGroup, threadPool: NIOThreadPool) async throws {
        // Bind every listener up front, keeping the underlying server channels so a shutdown can
        // stop accepting (closing a listening channel ends its accept loop; existing connections
        // are untouched and drain on their own). One `ServerQuiescingHelper` per listener tracks
        // its accepted child channels so a drain can close them cleanly (no task cancellation).
        var serverChannels: [any Channel] = []
        var quiescers: [ServerQuiescingHelper] = []
        var serveTasks: [@Sendable () async -> Void] = []
        for listener in listeners {
            let routes = listener.routes
            let quiesce = ServerQuiescingHelper(group: group)
            quiescers.append(quiesce)
            logger.info(
                "ad-server listening",
                metadata: [
                    "host": "\(listener.host)", "port": "\(listener.port)",
                    "tls": "\(listener.wire.tls != nil)", "alpn": "\(listener.wire.alpn.map(\.rawValue))",
                    "threads": "\(threadCount)", "loops": "\(loopCount)"
                ])
            if listener.wire.tls != nil {
                let serverChannel = try await bindSecure(listener, group: group, quiesce: quiesce)
                serverChannels.append(serverChannel.channel)
                serveTasks.append {
                    await serveSecureListener(serverChannel, routes: routes, threadPool: threadPool)
                }
            } else {
                let serverChannel = try await bindPlain(listener, group: group, quiesce: quiesce)
                serverChannels.append(serverChannel.channel)
                serveTasks.append {
                    await servePlainListener(serverChannel, routes: routes, threadPool: threadPool)
                }
            }
        }
        readiness?.set(true)

        // Serve: SIGTERM/SIGINT trigger graceful shutdown, which stops accepting, drains in-flight
        // requests (bounded by `drainSeconds`), then quiesces the connections.
        let service = ServingService(
            serveTasks: serveTasks, channels: serverChannels, quiescers: quiescers, group: group,
            active: active, readiness: readiness, drainSeconds: Self.drainSeconds, logger: logger)
        let serviceGroup = ServiceGroup(
            services: [service], gracefulShutdownSignals: [.sigterm, .sigint], logger: logger)
        do {
            try await serviceGroup.run()
        } catch {
            logger.error("ad-server service group failed", metadata: ["error": "\(error)"])
        }
    }

    /// Max seconds to let in-flight requests finish after a shutdown signal before forcing close.
    private static let drainSeconds = 25

    /// The event-loop group for the configured transport: NIOTransportServices
    /// (Network.framework) on Apple when `.network`, else NIOPosix.
    private func makeEventLoopGroup() -> any EventLoopGroup {
        #if canImport(Network)
            if transport == .network { return NIOTSEventLoopGroup(loopCount: loopCount) }
        #endif
        return MultiThreadedEventLoopGroup(numberOfThreads: loopCount)
    }

    private func baseBootstrap(_ group: any EventLoopGroup) -> ServerBootstrap {
        ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 256)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            // TCP_NODELAY: without it Nagle + delayed ACKs add multi-ms latency to small
            // keep-alive responses (Bun.serve sets this; matching it is required).
            .childChannelOption(ChannelOptions.socketOption(.tcp_nodelay), value: 1)
    }

    /// Installs the quiescing helper's collector on a server channel, so the drain can close
    /// every accepted child channel (each child closes on `ChannelShouldQuiesceEvent`).
    private func quiesceInitializer(_ quiesce: ServerQuiescingHelper)
        -> @Sendable (any Channel) -> EventLoopFuture<Void>
    {
        { channel in
            channel.eventLoop.makeCompletedFuture {
                try channel.pipeline.syncOperations.addHandler(
                    quiesce.makeServerChannelHandler(channel: channel))
            }
        }
    }

    /// The plaintext HTTP/1.1 child pipeline — shared by both transports.
    private func plainInitializer() -> @Sendable (any Channel) -> EventLoopFuture<EngineConnection> {
        { childChannel in
            childChannel.eventLoop.makeCompletedFuture {
                try childChannel.pipeline.syncOperations.configureHTTPServerPipeline()
                // Bridge NIO's HTTP/1 parts ↔ swift-http-types parts (server, plaintext).
                try childChannel.pipeline.syncOperations.addHandler(HTTP1ToHTTPServerCodec(secure: false))
                try Self.addIdleTimeout(childChannel)
                return try EngineConnection(wrappingChannelSynchronously: childChannel)
            }
        }
    }

    /// Binds one plaintext HTTP/1.1 listener on the configured transport.
    private func bindPlain(
        _ listener: ListenerConfig, group: any EventLoopGroup, quiesce: ServerQuiescingHelper
    ) async throws -> NIOAsyncChannel<EngineConnection, Never> {
        #if canImport(Network)
            if transport == .network {
                return try await NIOTSListenerBootstrap(group: group)
                    .serverChannelInitializer(quiesceInitializer(quiesce))
                    .bind(
                        host: listener.host, port: listener.port, childChannelInitializer: plainInitializer())
            }
        #endif
        return try await baseBootstrap(group)
            .serverChannelInitializer(quiesceInitializer(quiesce))
            .bind(host: listener.host, port: listener.port, childChannelInitializer: plainInitializer())
    }

    /// Binds one TLS 1.3 listener that negotiates HTTP/1.1 or HTTP/2 by ALPN. Each child's
    /// output is the *negotiation future* — the initializer returns as soon as the ALPN handler
    /// is installed, so the channel activates and the handshake (which the negotiation depends
    /// on) can proceed; `serveSecureListener` awaits the result per connection. `autoRead` lets
    /// the handshake bytes flow before the inner per-connection channel takes over reads.
    private func bindSecure(
        _ listener: ListenerConfig, group: any EventLoopGroup, quiesce: ServerQuiescingHelper
    ) async throws -> NIOAsyncChannel<EventLoopFuture<EngineNegotiated>, Never> {
        #if canImport(Network)
            if transport == .network {
                throw EngineError(message: "TLS over the .network transport is not yet implemented (F3b)")
            }
        #endif
        let sslContext = try makeTLSContext(listener.wire.tls!, alpn: listener.wire.alpn)
        return try await baseBootstrap(group)
            .serverChannelInitializer(quiesceInitializer(quiesce))
            .childChannelOption(ChannelOptions.autoRead, value: true)
            .bind(host: listener.host, port: listener.port) { childChannel in
                childChannel.eventLoop
                    .makeCompletedFuture {
                        try childChannel.pipeline.syncOperations.addHandler(
                            NIOSSLServerHandler(context: sslContext))
                    }
                    .flatMap {
                        // `secure: true` ⇒ `:scheme https`. Returns EventLoopFuture<EventLoopFuture<…>>:
                        // the OUTER (pipeline ready) is the child's init future; the INNER (negotiation) is
                        // the child's output, awaited later.
                        childChannel.configureAsyncHTTPServerPipeline(
                            http1ConnectionInitializer: { channel in
                                channel.eventLoop.makeCompletedFuture {
                                    try channel.pipeline.syncOperations.addHandler(HTTP1ToHTTPServerCodec(secure: true))
                                    try Self.addIdleTimeout(channel)
                                    return try EngineConnection(wrappingChannelSynchronously: channel)
                                }
                            },
                            http2ConnectionInitializer: { channel in channel.eventLoop.makeSucceededVoidFuture() },
                            http2StreamInitializer: { stream in
                                stream.eventLoop.makeCompletedFuture {
                                    try stream.pipeline.syncOperations.addHandler(HTTP2FramePayloadToHTTPServerCodec())
                                    return try EngineConnection(wrappingChannelSynchronously: stream)
                                }
                            }
                        )
                    }
            }
    }

    /// Builds a TLS 1.3 server context from PEM material, advertising the listener's ALPN ids.
    private func makeTLSContext(_ tls: TLSSource, alpn: [ALPN]) throws -> NIOSSLContext {
        let chain = try NIOSSLCertificate.fromPEMFile(tls.certificatePath)
        let key = try NIOSSLPrivateKey(file: tls.privateKeyPath, format: .pem)
        var config = TLSConfiguration.makeServerConfiguration(
            certificateChain: chain.map { .certificate($0) }, privateKey: .privateKey(key))
        config.minimumTLSVersion = .tlsv13
        config.applicationProtocols = alpn.map(\.rawValue)
        return try NIOSSLContext(configuration: config)
    }

    /// The accept loop for a plaintext listener: each connection becomes a child task.
    private func servePlainListener(
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
    private func serveSecureListener(
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
    private func serveMultiplexer(
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
    private func serveConnection(
        _ channel: EngineConnection, routes: any HTTPHandling, threadPool: NIOThreadPool,
        isHTTP2: Bool
    ) async {
        do {
            // The channel's pooled allocator — used for the response body buffer so NIO can
            // account/optimise it against this connection (NIO's documented guidance over a
            // throwaway `ByteBufferAllocator()`). A cheap `Sendable` value, captured once.
            let allocator = channel.channel.allocator
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
                            let keepAlive: Bool
                            if overflow {
                                try await writeBodyTooLarge(
                                    to: head, outbound: outbound, isHTTP2: isHTTP2, allocator: allocator)
                                keepAlive = false
                            } else {
                                keepAlive = try await respond(
                                    to: head, body: body, routes: routes, outbound: outbound, threadPool: threadPool,
                                    isHTTP2: isHTTP2, allocator: allocator)
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

    /// Read-idle deadline per connection/stream. Positioned after HTTP decoding, so
    /// the timer resets on each decoded request part, not on raw bytes: a peer that
    /// connects and stalls (or dribbles an incomplete request) is closed instead of
    /// pinning a slot indefinitely (slowloris, CWE-400). Generous vs. the ms-scale
    /// handler latency, so it never trips a legitimate in-flight request.
    private static let idleTimeout = TimeAmount.seconds(60)

    /// Installs the read-idle timeout + the close-on-idle handler at the tail of the
    /// (already-built) HTTP child pipeline, just before the async-channel sink.
    private static func addIdleTimeout(_ channel: any Channel) throws {
        try channel.pipeline.syncOperations.addHandler(IdleStateHandler(readTimeout: idleTimeout))
        try channel.pipeline.syncOperations.addHandler(IdleTimeoutHandler())
    }

    private func writeBodyTooLarge(
        to head: HTTPRequest, outbound: NIOAsyncChannelOutboundWriter<HTTPResponsePart>, isHTTP2: Bool,
        allocator: ByteBufferAllocator
    ) async throws {
        try await write(
            .plain(HTTPResponse.Status(code: 413), "request too large\n"), cache: .unset,
            requestHeaders: head.headerFields, requestID: resolveRequestID(head.headerFields),
            keepAlive: false, isHTTP2: isHTTP2, outbound: outbound, allocator: allocator)
    }

    /// Resolves + runs the route for one request, then writes the response. Returns
    /// whether to keep the connection alive.
    private func respond(
        to head: HTTPRequest, body: [UInt8], routes: any HTTPHandling,
        outbound: NIOAsyncChannelOutboundWriter<HTTPResponsePart>, threadPool: NIOThreadPool,
        isHTTP2: Bool, allocator: ByteBufferAllocator
    ) async throws -> Bool {
        let keepAlive = isKeepAlive(head)
        let target = head.path ?? "/"
        let request = ServerRequest(
            method: head.method, target: target, headers: head.headerFields, body: body)
        let requestID = resolveRequestID(head.headerFields)
        let isHead = head.method == .head
        let storage = RequestStorage()

        // Reject directory traversal (`.`/`..` segments) before routing — a catch-all route would
        // otherwise hand `../../etc/passwd` to a handler.
        if pathHasTraversal(request.path) {
            try await write(
                .plain(.badRequest, "bad request path\n"), cache: .unset,
                requestHeaders: head.headerFields, requestID: requestID, keepAlive: keepAlive,
                isHTTP2: isHTTP2, suppressBody: isHead, outbound: outbound, allocator: allocator)
            return keepAlive
        }

        // Resolve the route. A HEAD with no explicit HEAD route falls back to the GET route (the
        // body is suppressed at write time).
        var matchResult = routes.match(method: head.method, path: request.path)
        if isHead {
            if case .matched = matchResult {} else {
                matchResult = routes.match(method: .get, path: request.path)
            }
        }

        // Derive the cache policy, the route-scoped middleware, and the terminal that produces the
        // response content (the handler run, or the 404 / 405 / auto-OPTIONS response).
        let cache: CachePolicy
        let routeMiddleware: [any HTTPMiddleware]
        let terminal: @Sendable (ServerRequest) async -> ResponseContent
        switch matchResult {
            case .matched(let route):
                cache = route.cache
                routeMiddleware = route.middleware
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
                terminal = { req in
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
            case .methodNotAllowed(let allowed):
                cache = .unset
                routeMiddleware = []
                let allow = allowHeader(allowed)
                if head.method == .options {
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
            case .notFound:
                cache = .unset
                routeMiddleware = []
                terminal = { _ in .plain(.notFound, "not found\n") }
        }

        // Compose server-wide + route middleware (server-wide outermost) around the terminal.
        let mwContext = MiddlewareContext(requestID: requestID, logger: logger, storage: storage)
        let chain = composeMiddleware(
            middleware + routeMiddleware, context: mwContext, terminal: terminal)
        let content = await chain(request)

        try await write(
            content, cache: cache, requestHeaders: head.headerFields, requestID: requestID,
            keepAlive: keepAlive, isHTTP2: isHTTP2, suppressBody: isHead, outbound: outbound,
            allocator: allocator)
        return keepAlive
    }

    /// Applies the response envelope: ETag/304, content-type/length, cache-control, the
    /// constant header set, the minted/echoed request-id, and (h1 only) the connection header.
    private func write(
        _ content: ResponseContent, cache: CachePolicy, requestHeaders: HTTPFields, requestID: String,
        keepAlive: Bool, isHTTP2: Bool, suppressBody: Bool = false,
        outbound: NIOAsyncChannelOutboundWriter<HTTPResponsePart>,
        allocator: ByteBufferAllocator
    ) async throws {
        var (status, contentType, body, extraHeaders) = materialize(content)
        var headers = HTTPFields()
        var emitEntity = true

        // ETag computed once from the original entity; on a match, blank the body → 304
        // but keep the ETag header (RFC 7232).
        if cache.etag {
            let etag = "\"\(sha256HexLower(body).prefix(16))\""
            headers[.eTag] = etag
            if let inm = requestHeaders[.ifNoneMatch], matchesIfNoneMatch(inm, etag) {
                status = .notModified
                body = []
                emitEntity = false
            }
        }
        if emitEntity {
            headers[.contentType] = contentType
            headers[.contentLength] = String(body.count)
        }
        if let cc = cache.cacheControl { headers[.cacheControl] = cc }
        headers.append(contentsOf: envelope)
        headers[requestIDName] = requestID
        // HTTP/2 forbids the connection-specific `Connection` header (an HTTP/1.1 concept).
        if !isHTTP2 { headers[.connection] = keepAlive ? "keep-alive" : "close" }
        // Route-supplied headers override the envelope (CORS / the MCP `/mcp` set).
        for field in extraHeaders { headers[field.name] = field.value }

        try await outbound.write(.head(HTTPResponse(status: status, headerFields: headers)))
        if !body.isEmpty && !suppressBody {
            // `HTTPResponsePart.body` is a `ByteBuffer`, so the route's `[UInt8]` must be copied into
            // NIO-owned storage once (a single contiguous memcpy — unavoidable without threading a
            // `ByteBuffer` through the whole `ResponseContent`/route surface). Take that one buffer from
            // the connection's pooled allocator with the exact capacity, rather than a throwaway
            // `ByteBufferAllocator()` per response: NIO can then pool/account it against the channel
            // (its documented recommendation). The body is identical bytes either way.
            var buffer = allocator.buffer(capacity: body.count)
            buffer.writeBytes(body)
            try await outbound.write(.body(buffer))
        }
        try await outbound.write(.end(nil))
    }

    private func materialize(_ content: ResponseContent)
        -> (status: HTTPResponse.Status, contentType: String, body: [UInt8], headers: HTTPFields)
    {
        switch content {
            case .raw(let b, let ct, let st): return (st, ct, b, HTTPFields())
            case .notFound:
                return (.notFound, "text/plain; charset=utf-8", Array("Not Found".utf8), HTTPFields())
            case .plain(let st, let msg):
                return (st, "text/plain; charset=utf-8", Array(msg.utf8), HTTPFields())
            case .full(let b, let ct, let st, let h): return (st, ct, b, h)
        }
    }

    /// HTTP/1.1 default keep-alive unless `Connection: close` (HTTP/1.0 clients are out
    /// of scope; fetch + Caddy are 1.1). For h2 this is unused (one request per stream).
    private func isKeepAlive(_ head: HTTPRequest) -> Bool {
        guard let connection = head.headerFields[.connection]?.lowercased() else { return true }
        return !connection.contains("close")
    }

    /// `Allow:` header listing the methods registered for a path (sent on 405 + auto-OPTIONS).
    private func allowHeader(_ methods: [HTTPRequest.Method]) -> HTTPFields {
        var fields = HTTPFields()
        fields[HTTPField.Name("Allow")!] = methods.map(\.rawValue).joined(separator: ", ")
        return fields
    }
}

/// The serving + graceful-drain lifecycle as a `swift-service-lifecycle` `Service`. The accept
/// loops run inline (the task-group body); a single coordinator child task waits for graceful
/// shutdown, then stops accepting (closes the server channels — the accept loops end naturally,
/// no cancellation), drains in-flight requests (bounded by `drainSeconds`), and quiesces the
/// connections (each child closes on `ChannelShouldQuiesceEvent`). The accept loops then return
/// on their own; `cancelAll` only ever reaches the coordinator (the inline serving is already
/// done by then), so no accept loop is cancelled mid-flight — which previously orphaned
/// just-accepted `NIOAsyncChannel`s (their writers deinited without `finish()`).
private struct ServingService: Service {
    let serveTasks: [@Sendable () async -> Void]
    let channels: [any Channel]
    let quiescers: [ServerQuiescingHelper]
    let group: any EventLoopGroup
    let active: ActiveRequests
    let readiness: ServerReadiness?
    let drainSeconds: Int
    let logger: Logger

    private enum Phase: Sendable, Equatable { case served, signalled }

    func run() async throws {
        await withTaskGroup(of: Phase.self) { taskGroup in
            // The accept loops; ends once every connection (and the listeners) close.
            taskGroup.addTask {
                await withDiscardingTaskGroup { serving in
                    for serve in serveTasks { serving.addTask { await serve() } }
                }
                return .served
            }
            // The graceful-shutdown waiter.
            taskGroup.addTask {
                do { try await gracefulShutdown() } catch {}
                return .signalled
            }

            if await taskGroup.next() == .signalled {
                // Run the drain as its OWN child task. Every allocating await it performs (the
                // `Task.sleep`s, the quiesce sub-group, the close-future `get()`s) then lives on
                // THIS child's task allocator — not interleaved, on the *parent* allocator, with the
                // still-live serving child. Doing those awaits inline in the group body (as before)
                // freed the parent's `Task.sleep` buffer out of order against the concurrent child
                // under `-O`, tripping the task-allocator LIFO assertion ("freed pointer was not the
                // last allocation") and aborting the process on every SIGTERM.
                taskGroup.addTask { await self.drain(); return .signalled }
                _ = await taskGroup.next()  // the drain child, once the listeners/connections close
                _ = await taskGroup.next()  // the accept loops, now that connections have closed
            } else {
                // Listeners finished on their own; end the still-suspended graceful-shutdown waiter.
                taskGroup.cancelAll()
            }
        }
    }

    /// Drains in-flight work and quiesces the listeners after a shutdown signal. Runs as its own
    /// structured child task (see `run()`) so its allocating awaits stay on a dedicated task
    /// allocator rather than the parent group's — the inline version freed a `Task.sleep` buffer
    /// out of order against the concurrently-live serving child and tripped the release-build
    /// task-allocator LIFO assertion.
    private func drain() async {
        readiness?.set(false)
        logger.info("ad-server draining (stop accepting)")
        // Stop READING new connections first (don't close the listeners yet): closing a
        // listening channel while a child is mid-accept makes NIOAsyncChannelHandler drop
        // that child's writer in `channelActive` (deinit-without-finish trap). With autoRead
        // off, the kernel's accept queue stops draining into NIO, so no child is in flight
        // when the quiescer finally closes the listeners.
        for channel in channels { _ = channel.setOption(ChannelOptions.autoRead, value: false) }
        try? await Task.sleep(for: .milliseconds(100))
        // Wait for in-flight requests to finish (idle keep-alive connections are ignored),
        // bounded by the drain deadline.
        let deadline = ContinuousClock.now.advanced(by: .seconds(drainSeconds))
        while active.count > 0 && ContinuousClock.now < deadline {
            try? await Task.sleep(for: .milliseconds(50))
        }
        if active.count > 0 {
            logger.warning(
                "ad-server drain deadline exceeded; forcing close",
                metadata: ["inflight": "\(active.count)"])
        }
        // Quiesce (close the listeners + every still-open connection — each child closes on
        // `ChannelShouldQuiesceEvent`) and AWAIT completion, so the ELG isn't torn down with
        // channel-close work still pending (which would schedule on a shut-down event loop).
        await withTaskGroup(of: Void.self) { quiesceGroup in
            for quiesce in quiescers {
                quiesceGroup.addTask {
                    let promise = group.next().makePromise(of: Void.self)
                    quiesce.initiateShutdown(promise: promise)
                    try? await promise.futureResult.get()
                }
            }
        }
        // Also await the listening channels' full close, so no channel-close work is still
        // queued on the event loops when the caller tears the group down afterwards.
        for channel in channels { try? await channel.closeFuture.get() }
    }
}

/// Closes the connection on the read-idle deadline (`IdleStateHandler`) or when the server
/// quiesces (`ChannelShouldQuiesceEvent`, fired by `ServerQuiescingHelper` during a drain —
/// closing here ends the connection's inbound so `executeThenClose` finishes its writer
/// cleanly); forwards every other inbound user event untouched.
private final class IdleTimeoutHandler: ChannelInboundHandler {
    typealias InboundIn = HTTPRequestPart

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if event is IdleStateHandler.IdleStateEvent || event is ChannelShouldQuiesceEvent {
            context.close(promise: nil)
        } else {
            context.fireUserInboundEventTriggered(event)
        }
    }
}
