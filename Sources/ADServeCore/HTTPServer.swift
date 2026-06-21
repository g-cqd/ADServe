// The NIO engine type + the serving entry point. One NIO listener per `ListenerConfig`, all sharing
// one event-loop group, offload thread pool, connection pool, and response envelope. The listener
// bootstrap lives in HTTPServerBootstrap.swift, the accept/serve loops in HTTPServerServe.swift, the
// response path in HTTPServerRespond.swift, and the graceful-drain `Service` in ServingService.swift.
// Both HTTP versions bridge to the SAME `HTTPRequest`/`HTTPResponse`/`HTTPFields` value types via the
// NIOHTTPTypes codecs, so one `serveConnection` loop serves an h1 connection or an h2 stream
// identically. Fully structured concurrency: each listener is a child task of `run()`; each
// connection (or h2 stream) a child task of its accept loop; the one blocking handler per `.storage`
// request is offloaded to the NIOThreadPool with a pooled connection.

public import HTTPTypes
public import Logging
import NIOCore
import NIOExtras
import NIOHTTP2
import NIOHTTPCompression
import NIOHTTPTypes
import NIOPosix
import ServiceLifecycle
import Synchronization
import UnixSignals

// NIOTransportServices (Network.framework) is Apple-only; the engine falls back to NIOPosix
// elsewhere so the package still builds on Linux (the dylib + CI stay cross-platform).
#if canImport(Network)
    import NIOTransportServices
#endif

/// One accepted connection (h1) or h2 stream: streams `HTTPRequestPart`/`HTTPResponsePart`.
typealias EngineConnection = NIOAsyncChannel<HTTPRequestPart, HTTPResponsePart>
/// The ALPN outcome on a TLS connection: an h1 connection, or an h2 connection whose stream
/// channels arrive on the multiplexer.
typealias EngineNegotiated = NIONegotiatedHTTPVersion<
    EngineConnection, (Void, NIOHTTP2Handler.AsyncStreamMultiplexer<EngineConnection>)
>

/// A shared count of requests actively being handled — so a drain waits for real in-flight
/// work (not idle keep-alive connections, which linger until force-closed). A lock-free
/// `Atomic` (the counter is hot: every request brackets it); boxed in a class so the
/// `~Copyable` atomic lives behind a shared reference the (copied) engine value carries.
final class ActiveRequests: Sendable {
    private let value = Atomic<Int>(0)
    func enter() { value.wrappingAdd(1, ordering: .relaxed) }
    func leave() { value.wrappingSubtract(1, ordering: .relaxed) }
    var count: Int { value.load(ordering: .relaxed) }
}

/// A lightweight engine error with a message (startup/config failures).
struct EngineError: Error { let message: String }

/// The per-request transport context threaded through `respond`/`write`: the decoded request head,
/// the outbound writer, the wire flavor (HTTP/2 forbids the `Connection` header), the channel's pooled
/// allocator (NIO accounts the response buffer against the connection), and the channel's close future
/// (resolves on client disconnect or server quiesce — an SSE stream cancels its source on it). Bundled
/// so the write path stays within the engine's parameter-count budget.
struct RequestExchange {
    let head: HTTPRequest
    let outbound: NIOAsyncChannelOutboundWriter<HTTPResponsePart>
    let isHTTP2: Bool
    let allocator: ByteBufferAllocator
    let onClose: EventLoopFuture<Void>
    /// The offload pool — `.file` responses run their blocking jail/stat/read here, off the event loop.
    let threadPool: NIOThreadPool
    /// The per-request storage shared with the middleware chain + terminal — the write path reads the
    /// terminal-resolved `StaticPlan` (`ResolvedStaticPlanKey`) from it to avoid a second stat.
    let storage: RequestStorage
    /// The connection's peer IP (`channel.remoteAddress?.ipAddress`), seeded into `storage` for IP-aware
    /// middleware. `nil` for a UDS/unknown peer.
    let remoteAddress: String?
    /// The mTLS client certificate (DER), captured once per h1 connection; `nil` unless mutual TLS was
    /// used. Seeded into `storage` (`PeerCertificateKey`).
    let peerCertificateDER: [UInt8]?
}

/// A wait-free admission counter for concurrent CONNECTIONS (the max-connection accept gate). Identical
/// CAS-loop mechanics to `SSELimiter`, but `limit == 0` means UNLIMITED (the default — no cap) rather
/// than "refuse everything". `tryAcquire` brackets each accepted connection (h1 socket / h2 connection,
/// NOT individual h2 streams); past the limit the engine answers 503 + close (h1) or declines to serve
/// (h2). Boxed in a class so the (copied) engine value shares one counter.
final class ConnectionLimiter: Sendable {
    private let inUse = Atomic<Int>(0)
    let limit: Int
    init(limit: Int) { self.limit = max(0, limit) }

    /// Reserve a connection slot, or `false` at capacity. Always succeeds when `limit == 0` (unlimited).
    func tryAcquire() -> Bool {
        if limit == 0 { return true }
        var current = inUse.load(ordering: .relaxed)
        while current < limit {
            let (exchanged, original) = inUse.compareExchange(
                expected: current, desired: current + 1, ordering: .relaxed)
            if exchanged { return true }
            current = original
        }
        return false
    }

    func release() {
        if limit == 0 { return }
        inUse.wrappingSubtract(1, ordering: .relaxed)
    }
}

/// A wait-free admission counter for concurrent SSE streams. `tryAcquire` reserves a slot via a CAS
/// loop (never overshoots `limit`); the `.sse` write path returns a 503 when it fails, and `release`
/// frees the slot when the stream ends. Boxed in a class so the engine value shares one counter.
final class SSELimiter: Sendable {
    private let inUse = Atomic<Int>(0)
    let limit: Int
    init(limit: Int) { self.limit = max(0, limit) }

    /// Reserve a slot, or `false` at capacity (the caller answers 503 instead of opening the stream).
    func tryAcquire() -> Bool {
        var current = inUse.load(ordering: .relaxed)
        while current < limit {
            let (exchanged, original) = inUse.compareExchange(
                expected: current, desired: current + 1, ordering: .relaxed)
            if exchanged { return true }
            current = original
        }
        return false
    }

    func release() { inUse.wrappingSubtract(1, ordering: .relaxed) }
}

/// HTTP/1 connection-lifetime policy (RFC-0019 §3.4). Controls the `Connection` header + the
/// per-connection idle deadline, the one knob a `networkidle`-waiting client (a browser preview, a
/// crawler) cares about. No effect on HTTP/2, which forbids `Connection` and is one request per stream.
public enum KeepAlivePolicy: Sendable {
    /// Persistent connections (default) with the default 60s all-idle deadline.
    case keepAlive
    /// Answer EVERY request with `Connection: close` and close the socket after the response — so idle
    /// sockets never linger (a `networkidle` client settles at once) and the client reads to EOF rather
    /// than trusting `Content-Length`.
    case close
    /// Persistent, but with a custom all-idle deadline (e.g. `.seconds(5)` so a preview settles quickly
    /// without giving up keep-alive). A non-positive duration disables the deadline entirely.
    case idleTimeout(Duration)
}

/// Whether the engine transparently inflates a `Content-Encoding: gzip`/`deflate` REQUEST body before the
/// handler sees it — and, when it does, the HARD ceiling on the inflated output (decompression-bomb
/// defense, CWE-409). Off by default: an app that never decompresses request bodies pays nothing and its
/// behavior is unchanged. When enabled, a body that inflates past `maxSize` is rejected (the decompressor
/// errors → the connection is closed before the oversized output is buffered), so a tiny gzip can never
/// be expanded into gigabytes in memory. The cap is an ABSOLUTE output-size bound (not a mere ratio): a
/// ratio alone still lets a large compressed input inflate without limit, whereas a size bound caps the
/// peak memory regardless of input size. Applies to the HTTP/1 pipeline (plaintext + secure h1); HTTP/2
/// request bodies are not inflated here (this is an HTTP/1 handler — terminate request compression at a
/// proxy for h2).
public enum RequestDecompressionPolicy: Sendable {
    /// No request-body decompression (default). A `Content-Encoding` request body is passed through to the
    /// handler verbatim — exactly today's behavior.
    case disabled
    /// Inflate gzip/deflate request bodies, rejecting any whose decompressed output would exceed `maxSize`
    /// bytes. Choose `maxSize` no smaller than the largest legitimately-compressed body you accept; it is
    /// clamped to at least 1 byte (a non-positive cap would reject every compressed body).
    case enabled(maxSize: Int)
}

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
    /// On-the-fly response compression (gzip/deflate) on the HTTP/1 pipeline (plaintext + secure h1),
    /// gated by a predicate (compressible MIME types, no existing `Content-Encoding`, not SSE). Default
    /// on. HTTP/2 streams are not compressed on the fly — `HTTPResponseCompressor` is an HTTP/1 handler;
    /// serve precompressed static for h2, or terminate compression at the proxy. Large dynamic bodies
    /// should still be precompressed (compression runs on the event loop).
    let responseCompression: Bool
    /// Opt-in request-body decompression policy (`.disabled` by default). When `.enabled(maxSize:)`, the
    /// HTTP/1 pipeline inflates a `Content-Encoding: gzip`/`deflate` body with a HARD output-size cap, so a
    /// decompression bomb (tiny gzip → gigabytes) is rejected before it can exhaust memory. `nil` once the
    /// policy is `.disabled`, so the decompressor is never installed and the request path is unchanged.
    let requestDecompressionLimit: NIOHTTPDecompression.DecompressionLimit?
    /// The per-connection all-idle deadline (slowloris/CWE-400 defense): a connection idle this long in
    /// BOTH directions is closed. Default 60s. Non-positive (`.zero` or less) disables it entirely — a
    /// connection then lives until the peer or a drain closes it. An SSE source must heartbeat within
    /// this window (its writes reset the timer).
    let idleTimeout: Duration
    /// Whether HTTP/1 keep-alive is offered (derived from `KeepAlivePolicy`). When `false` the server
    /// answers EVERY request with `Connection: close` and closes the socket after the response. No effect
    /// on HTTP/2 (it forbids the `Connection` header; each stream is already one request).
    let keepAliveEnabled: Bool
    /// In-flight request count, so a drain waits for real work, not idle keep-alive connections.
    let active = ActiveRequests()
    /// Admission control for concurrent SSE streams (a `.sse` response past the limit gets a 503).
    let sseLimiter: SSELimiter
    /// Admission control for concurrent connections (`maxConnections`). Past the limit a new h1 connection
    /// gets a 503 + close, an h2 connection is declined. `0` opts INTO unlimited (use only behind a proxy
    /// that caps connections); the default is finite so a fresh server can't be driven to FD/memory
    /// exhaustion out of the box.
    let connectionLimiter: ConnectionLimiter

    /// The default concurrent-connection cap when `maxConnections` is unspecified — finite by design
    /// (a bounded server resists connection-flood DoS / FD exhaustion). Tune it to your deployment's
    /// `RLIMIT_NOFILE`; pass `maxConnections: 0` to disable the cap entirely.
    public static let defaultMaxConnections = 8192

    /// The default event-loop count: one loop per available core (`System.coreCount`, which honors Linux
    /// cgroup v1/v2 CPU quotas — a constrained container gets its quota, not the host's core count). This is
    /// the NIO / swift-server convention, and what lets the accept/serve path scale across cores; the prior
    /// hardcoded `2` left multicore throughput unused (~17% on an 8-core host, and more as cores grow). Pass
    /// an explicit `loopCount:` to pin it (tests use `1` for determinism; a latency-isolated deployment may
    /// want fewer). Evaluated once.
    public static let defaultLoopCount = System.coreCount

    public init(
        listeners: [ListenerConfig], pool: AnyConnectionPool?, envelope: HTTPFields, logger: Logger,
        threadCount: Int, loopCount: Int = HTTPServer.defaultLoopCount, readiness: ServerReadiness? = nil,
        transport: EngineTransport = .nio, middleware: [any HTTPMiddleware] = [],
        codec: ContentCodec = .json, maxBodyBytes: Int = 1_000_000, maxConcurrentSSE: Int = 1024,
        maxConnections: Int = HTTPServer.defaultMaxConnections, responseCompression: Bool = true,
        keepAlive: KeepAlivePolicy = .keepAlive,
        requestDecompression: RequestDecompressionPolicy = .disabled
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
        self.sseLimiter = SSELimiter(limit: maxConcurrentSSE)
        self.connectionLimiter = ConnectionLimiter(limit: maxConnections)
        self.responseCompression = responseCompression
        switch requestDecompression {
            case .disabled:
                self.requestDecompressionLimit = nil
            case .enabled(let maxSize):
                // A hard ABSOLUTE output ceiling (clamped ≥ 1 so a non-positive cap can't reject every
                // body): inflated output over it makes the decompressor error, closing the connection
                // before the bomb is buffered.
                self.requestDecompressionLimit = .size(max(1, maxSize))
        }
        switch keepAlive {
            case .keepAlive: (self.keepAliveEnabled, self.idleTimeout) = (true, .seconds(60))
            case .close: (self.keepAliveEnabled, self.idleTimeout) = (false, .seconds(60))
            case .idleTimeout(let deadline): (self.keepAliveEnabled, self.idleTimeout) = (true, deadline)
        }
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
                    "address": "\(listener.addressDescription)",
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
    static let drainSeconds = 25

    /// The event-loop group for the configured transport: NIOTransportServices
    /// (Network.framework) on Apple when `.network`, else NIOPosix.
    private func makeEventLoopGroup() -> any EventLoopGroup {
        #if canImport(Network)
            if transport == .network { return NIOTSEventLoopGroup(loopCount: loopCount) }
        #endif
        return MultiThreadedEventLoopGroup(numberOfThreads: loopCount)
    }
}
