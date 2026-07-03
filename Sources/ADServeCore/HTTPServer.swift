// The engine type + the serving entry point. One HTTP-package server per `ListenerConfig`, all
// sharing one blocking-offload pool, connection pool, response envelope, and admission counters.
// The routing/middleware bridge lives in EngineResponder.swift, the response envelope in
// HTTPServerRespond.swift, the transport composition in EngineTransports.swift, and the
// graceful-drain `Service` in ServingService.swift. Fully structured concurrency: each listener's
// serve loop is a child task of `run()`; the one blocking handler per `.storage` request is
// offloaded to the `BlockingOffloadPool` with a pooled connection.

import ADConcurrency
import ADServeEngineNames
import Foundation
public import HTTPCore
import HTTPServer
import HTTPTransport
public import Logging
import ServiceLifecycle
import Synchronization
import UnixSignals

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

/// A wait-free admission counter for concurrent CONNECTIONS (the max-connection accept gate).
/// Identical CAS-loop mechanics to `SSELimiter`, but `limit == 0` means UNLIMITED (the default —
/// no cap) rather than "refuse everything". `tryAcquire` brackets each accepted transport
/// connection; past the limit the transport answers a canned 503 + close. Boxed in a class so the
/// (copied) engine value shares one counter.
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
/// loop (never overshoots `limit`); the `.sse` response path returns a 503 when it fails, and `release`
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

/// HTTP/1 connection-lifetime policy. Controls the `Connection` header + the per-connection idle
/// deadline, the one knob a `networkidle`-waiting client (a browser preview, a crawler) cares
/// about. No effect on HTTP/2, which forbids `Connection` and is one request per stream.
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

/// Whether the engine transparently inflates a `Content-Encoding: gzip`/`deflate` REQUEST body before
/// the handler sees it — and, when it does, the HARD ceiling on the inflated output
/// (decompression-bomb defense, CWE-409). Off by default: an app that never decompresses request
/// bodies pays nothing and its behavior is unchanged. When enabled, a body that inflates past
/// `maxSize` is rejected with `413` before the oversized output reaches the handler, so a tiny gzip
/// can never be expanded into gigabytes in memory. The cap is an ABSOLUTE output-size bound (not a
/// mere ratio): a ratio alone still lets a large compressed input inflate without limit, whereas a
/// size bound caps the peak memory regardless of input size.
public enum RequestDecompressionPolicy: Sendable {
    /// No request-body decompression (default). A `Content-Encoding` request body is passed through to
    /// the handler verbatim — exactly today's behavior.
    case disabled
    /// Inflate gzip/deflate request bodies, rejecting any whose decompressed output would exceed
    /// `maxSize` bytes. Choose `maxSize` no smaller than the largest legitimately-compressed body you
    /// accept; it is clamped to at least 1 byte (a non-positive cap would reject every compressed body).
    case enabled(maxSize: Int)
}

/// The engine-wide values `EngineResponder` + the response path share, bundled so the responder
/// stays within the stored-property budget and the (copied) server value shares one set.
struct EngineConfiguration: Sendable {
    let pool: AnyConnectionPool?
    let envelope: HTTPFields
    let logger: Logger
    let middleware: [any HTTPMiddleware]
    let codec: ContentCodec
    let maxBodyBytes: Int
    let keepAliveEnabled: Bool
    let responseCompression: Bool
    let sseLimiter: SSELimiter
    let active: ActiveRequests
}

/// The ad-server engine. Binds one listener per `ListenerConfig` on the HTTP package's serving
/// stack (`HTTPServing.HTTPServer` over a `TransportBackbone`), all sharing the offload pool +
/// connection pool + envelope; serves until cancelled. The app builds the listeners (DSL) + the
/// response `envelope` and hands them in.
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
    /// The bound transport — `.network` uses Network.framework; `.posix` the kqueue/epoll backbone.
    let transport: EngineTransport
    /// Server-wide middleware (outermost first). Wraps routing on EVERY request, so it also sees
    /// `notFound`/`methodNotAllowed` and can short-circuit before dispatch. Per-group/route
    /// middleware (from the DSL) rides `MatchedRoute.middleware` and wraps only the matched handler.
    let middleware: [any HTTPMiddleware]
    /// The content codec a handler's `ctx.decode`/`ctx.json` route through (default `.json`).
    let codec: ContentCodec
    /// Server-wide DEFAULT request-body ceiling in bytes; a larger body → 413 + close before the
    /// handler runs. Default 1 MiB. A route may override it with `.maxBody(_:)` — *higher* (an upload
    /// endpoint; the engine resolves the route at the request head to size accumulation) or *lower*
    /// (a tighter bound, enforced post-match as a problem+json 413).
    let maxBodyBytes: Int
    /// On-the-fly gzip for eligible BUFFERED responses (mime-db-compressible type, ≥ the sub-MTU
    /// floor, client accepts gzip, no prior `Content-Encoding`/`Content-Range`). Default on.
    /// Streamed responses (`.stream`/`.sse`/`.file`) are never compressed on the fly — serve
    /// precompressed `.br`/`.gz` sidecars for static assets.
    let responseCompression: Bool
    /// Opt-in request-body decompression cap (`nil` = `.disabled`): the HARD inflated-output ceiling
    /// the engine's decompression middleware enforces (CWE-409) before the handler sees the body.
    let requestDecompressionMaxBytes: Int?
    /// The per-connection all-idle deadline (slowloris/CWE-400 defense): a connection idle this long
    /// is closed. Default 60s. Non-positive (`.zero` or less) disables it entirely — a connection
    /// then lives until the peer or a drain closes it. An SSE source must heartbeat within this
    /// window on shared infrastructure that reaps idle flows.
    let idleTimeout: Duration
    /// Whether HTTP/1 keep-alive is offered (derived from `KeepAlivePolicy`). When `false` the server
    /// answers EVERY request with `Connection: close` and closes the socket after the response. No
    /// effect on HTTP/2 (it forbids the `Connection` header; each stream is already one request).
    let keepAliveEnabled: Bool
    /// In-flight request count, so a drain waits for real work, not idle keep-alive connections.
    let active = ActiveRequests()
    /// Admission control for concurrent SSE streams (a `.sse` response past the limit gets a 503).
    let sseLimiter: SSELimiter
    /// Admission control for concurrent connections (`maxConnections`). Past the limit a new
    /// connection gets a canned 503 + close. `0` opts INTO unlimited (use only behind a proxy that
    /// caps connections); the default is finite so a fresh server can't be driven to FD/memory
    /// exhaustion out of the box.
    let connectionLimiter: ConnectionLimiter

    /// The default concurrent-connection cap when `maxConnections` is unspecified — finite by design
    /// (a bounded server resists connection-flood DoS / FD exhaustion). Tune it to your deployment's
    /// `RLIMIT_NOFILE`; pass `maxConnections: 0` to disable the cap entirely.
    public static let defaultMaxConnections = 8192

    /// The default event-loop count: one loop per available core — what lets the accept/serve path
    /// scale across cores (the kqueue/epoll backbones shard one loop per core, each connection's
    /// serve task pinned to its loop). Pass an explicit `loopCount:` to pin it (tests use `1` for
    /// determinism; a latency-isolated deployment may want fewer). Evaluated once.
    public static let defaultLoopCount = ProcessInfo.processInfo.activeProcessorCount

    /// The on-the-fly response-compression floor: a body below this many bytes is served
    /// uncompressed. A response that fits one TCP segment (~1 MTU) gains nothing on the wire from
    /// compression — it is one packet either way — so compressing it only spends CPU and can ENLARGE
    /// it (gzip framing is ~18 bytes). Mirrors nginx's `gzip_min_length`.
    static let minimumCompressibleResponseBytes = 1400

    public init(
        listeners: [ListenerConfig], pool: AnyConnectionPool?, envelope: HTTPFields, logger: Logger,
        threadCount: Int, loopCount: Int = HTTPServer.defaultLoopCount,
        readiness: ServerReadiness? = nil,
        transport: EngineTransport = .posix, middleware: [any HTTPMiddleware] = [],
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
                self.requestDecompressionMaxBytes = nil
            case .enabled(let maxSize):
                // A hard ABSOLUTE output ceiling (clamped ≥ 1 so a non-positive cap can't reject
                // every body): inflated output past it is rejected before the handler sees it.
                self.requestDecompressionMaxBytes = max(1, maxSize)
        }
        switch keepAlive {
            case .keepAlive: (self.keepAliveEnabled, self.idleTimeout) = (true, .seconds(60))
            case .close: (self.keepAliveEnabled, self.idleTimeout) = (false, .seconds(60))
            case .idleTimeout(let deadline): (self.keepAliveEnabled, self.idleTimeout) = (true, deadline)
        }
    }

    public func run() async throws {
        let offload = BlockingOffloadPool(width: threadCount)
        var engines: [ListenerEngine] = []
        // One "bound" tick per listener; the last one flips readiness (the /readyz contract).
        let unbound = Atomic<Int>(listeners.count)
        let readiness = self.readiness
        for listener in listeners {
            logger.info(
                "ad-server listening",
                metadata: [
                    "address": "\(listener.addressDescription)",
                    "tls": "\(listener.wire.tls != nil)",
                    "alpn": "\(listener.wire.alpn.map(\.rawValue))",
                    "threads": "\(threadCount)", "loops": "\(loopCount)"
                ])
            let onBound: @Sendable () -> Void = {
                if unbound.wrappingSubtract(1, ordering: .acquiringAndReleasing).oldValue == 1 {
                    readiness?.set(true)
                }
            }
            engines.append(try makeEngine(listener, offload: offload, onBound: onBound))
        }

        // Serve: SIGTERM/SIGINT trigger graceful shutdown, which stops accepting, drains in-flight
        // requests (bounded by `drainSeconds`), then force-closes lingering connections.
        let service = ServingService(
            engines: engines, active: active, readiness: readiness,
            drainSeconds: Self.drainSeconds, logger: logger)
        let serviceGroup = ServiceGroup(
            services: [service], gracefulShutdownSignals: [.sigterm, .sigint], logger: logger)
        do {
            try await serviceGroup.run()
        } catch is CancellationError {
            // Cancelled by the owner (tests, an embedding app) — tear down below.
        } catch {
            logger.error("ad-server service group failed", metadata: ["error": "\(error)"])
        }
        // Idempotent teardown: stops the transports (releasing ports/threads) and force-closes any
        // connection the drain (if one ran) left behind — also the whole teardown on cancellation.
        for engine in engines { await engine.server.shutdown(within: .zero) }
        offload.shutdown()
        logger.info("ad-server stopped")
    }

    /// Max seconds to let in-flight requests finish after a shutdown signal before forcing close.
    static let drainSeconds = 25

    /// Builds one listener's serving stack: responder bridge (+ the opt-in decompression layer),
    /// transport (with the bound notifier + connection gate), limits, and the engine server.
    private func makeEngine(
        _ listener: ListenerConfig, offload: BlockingOffloadPool,
        onBound: @escaping @Sendable () -> Void
    ) throws -> ListenerEngine {
        let configuration = EngineConfiguration(
            pool: pool, envelope: envelope, logger: logger, middleware: middleware, codec: codec,
            maxBodyBytes: maxBodyBytes, keepAliveEnabled: keepAliveEnabled,
            responseCompression: responseCompression, sseLimiter: sseLimiter, active: active)
        let core = EngineResponder(
            routes: listener.routes, configuration: configuration, offload: offload)
        let responder: any HTTPResponder
        if let maxSize = requestDecompressionMaxBytes {
            // `MiddlewareChain` forwards the RouteResolver seam, so head-time resolution survives.
            responder = MiddlewareChain(
                [DecompressionMiddleware(maxDecompressedSize: maxSize, maxRatio: Int.max)],
                terminatingAt: core)
        } else {
            responder = core
        }
        let transport = ConnectionLimitingTransport(
            NotifyingTransport(try makeTransport(listener), onBound: onBound),
            limiter: connectionLimiter)
        let server = HTTPEngineServer(
            transport: transport, responder: responder, limits: makeLimits())
        return ListenerEngine(server: server, address: listener.addressDescription)
    }

    /// The transport for a listener: UNIX-domain socket when configured; else Network.framework for
    /// TLS (the POSIX backbones are cleartext) or when `.network` was selected; else the platform's
    /// event-driven POSIX backbone (kqueue on Darwin, epoll on Linux).
    private func makeTransport(_ listener: ListenerConfig) throws -> any ServerTransport {
        if let socketPath = listener.unixDomainSocketPath {
            return UnixDomainSocketTransport(path: socketPath)
        }
        guard listener.port >= 0, listener.port <= Int(UInt16.max) else {
            throw EngineError(message: "listener port out of range: \(listener.port)")
        }
        var configuration = TransportConfiguration(
            host: listener.host, port: UInt16(listener.port),
            backbone: transport == .network ? .networkFramework : .recommended,
            eventLoopCount: loopCount)
        if let tls = listener.wire.tls {
            configuration.backbone = .networkFramework
            configuration.tls = try TLSMaterial.transportTLS(from: tls, alpn: listener.wire.alpn)
        }
        // `make` is `throws(TransportError)` since the HTTP engine's migration additives — an
        // unsupported backbone surfaces as a boot error here, not a trap.
        return try TransportFactory.make(configuration)
    }

    /// ADServe's knobs mapped onto the engine's `HTTPLimits`: the server body cap, the single
    /// all-idle deadline (both the mid-request and the between-requests timers), and connection
    /// ceilings pushed out of the way (ADServe's own `ConnectionLimiter` owns that gate, answering
    /// a 503 instead of the engine's silent close).
    private func makeLimits() -> HTTPLimits {
        var limits = HTTPLimits.default
        // The engine's h1 parser enforces this GLOBAL cap at parse time, BEFORE the per-route
        // resolver can RAISE it (recorded upstream gap) — so it is set to a coarse transport
        // ceiling and `EngineResponder.resolve` supplies the effective cap (the server default, or
        // a route's raise) for every request head.
        limits.maxBodySize = max(maxBodyBytes, 64 << 20)
        // The WebSocket message (and, via the engine, single-frame) cap mirrors the server's body
        // policy DIRECTLY — not the floored h1 parse ceiling above, whose 64 MiB coarseness exists
        // only so per-route raises can beat parse-time enforcement. WS has no per-route raise, so
        // the configured body cap is the right bound for reassembled or unfragmented messages
        // (default 1 MB; an oversized frame closes 1009 instead of buffering without bound).
        limits.maxWebSocketMessageSize = maxBodyBytes
        let idle: Duration = idleTimeout > .zero ? idleTimeout : .seconds(1 << 24)
        limits.idleTimeout = idle
        limits.keepAliveTimeout = idle
        limits.maxConnections = 1 << 30
        limits.maxConnectionsPerClient = 1 << 20
        return limits
    }
}

/// One listener's running pieces: the engine server (whose `shutdown(within:)` stops its transport
/// and force-closes stragglers) and a log label.
struct ListenerEngine: Sendable {
    let server: HTTPEngineServer
    let address: String
}
