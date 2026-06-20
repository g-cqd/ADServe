// The NIO listener bootstrap: plaintext + TLS child-pipeline construction, ALPN negotiation wiring,
// the TLS context, and the per-connection read-idle timeout. Extracted from HTTPServer.swift; the
// behavior is unchanged. One listener per `ListenerConfig`; each speaks its `Wire`.

import Foundation
import NIOCore
import NIOExtras
import NIOHTTP1
import NIOHTTP2
import NIOHTTPCompression
import NIOHTTPTypes
import NIOHTTPTypesHTTP1
import NIOHTTPTypesHTTP2
import NIOPosix
import NIOSSL
import NIOWebSocket

#if canImport(Network)
    import NIOTransportServices
#endif

extension HTTPServer {
    func baseBootstrap(_ group: any EventLoopGroup) -> ServerBootstrap {
        ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 256)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            // TCP_NODELAY: without it Nagle + delayed ACKs add multi-ms latency to small
            // keep-alive responses (Bun.serve sets this; matching it is required).
            .childChannelOption(ChannelOptions.socketOption(.tcp_nodelay), value: 1)
    }

    /// Installs the quiescing helper's collector on a server channel, so the drain can close
    /// every accepted child channel (each child closes on `ChannelShouldQuiesceEvent`).
    func quiesceInitializer(_ quiesce: ServerQuiescingHelper)
        -> @Sendable (any Channel) -> EventLoopFuture<Void>
    {
        { channel in
            channel.eventLoop.makeCompletedFuture {
                try channel.pipeline.syncOperations.addHandler(
                    quiesce.makeServerChannelHandler(channel: channel))
            }
        }
    }

    /// Adds the HTTP/1 `Expect: 100-continue` handler ahead of (head-ward of) the response compressor, so
    /// the `100 Continue` interim it writes never flows through `HTTPResponseCompressor` — which pops its
    /// accept-encoding queue on EVERY response head, interim included, and would underflow on the final
    /// response. Must be installed before the compressor in the pipeline.
    static func addExpectContinue(_ channel: any Channel) throws {
        try channel.pipeline.syncOperations.addHandler(HTTP1ExpectContinueHandler())
    }

    /// A fresh `HTTPResponseCompressor` (one per connection — it is stateful) gated to compress only what
    /// is worth it and safe: a body whose bare `Content-Type` is mime-db-compressible, with NO existing
    /// `Content-Encoding` (so a precompressed `.br`/`.gz` static variant is passed through untouched), and
    /// NEVER `text/event-stream` (compressing buffers, which would stall a long-lived SSE stream).
    /// `isSupported` already encodes the client's `Accept-Encoding` (with q-values) ∩ what HTTP allows.
    static func makeResponseCompressor() -> HTTPResponseCompressor {
        HTTPResponseCompressor(responseCompressionPredicate: { responseHead, isSupported in
            guard isSupported else { return .doNotCompress }
            if responseHead.headers.contains(name: "Content-Encoding") { return .doNotCompress }
            // A 206/range response: compressing it would drop `Content-Length` (→ chunked) while the
            // `Content-Range` still describes identity bytes — an incoherent range. Serve ranges as
            // identity (nginx does the same); the full entity (200) still compresses normally.
            if responseHead.headers.contains(name: "Content-Range") { return .doNotCompress }
            guard let contentType = responseHead.headers.first(name: "Content-Type") else {
                return .doNotCompress
            }
            let lower = contentType.lowercased()
            if lower.hasPrefix("text/event-stream") { return .doNotCompress }
            let bareType =
                lower.split(separator: ";", maxSplits: 1).first
                .map { $0.trimmingCharacters(in: .whitespaces) } ?? lower
            return MIMEDatabase.isCompressible(type: bareType) ? .compressIfPossible : .doNotCompress
        })
    }

    /// Adds the engine's app-level HTTP/1 handlers (expect-continue, the gated response compressor, the
    /// swift-http-types bridge, the idle timeout) ON TOP of an already-configured HTTP/1 codec, returning
    /// the wrapped async connection. Shared by the plaintext not-upgrading path and the secure h1 path.
    func configureHTTP1AppHandlers(_ channel: any Channel, secure: Bool) throws -> EngineConnection {
        try Self.addExpectContinue(channel)
        if responseCompression {
            try channel.pipeline.syncOperations.addHandler(Self.makeResponseCompressor())
        }
        try channel.pipeline.syncOperations.addHandler(HTTP1ToHTTPServerCodec(secure: secure))
        try addIdleTimeout(channel)
        return try EngineConnection(wrappingChannelSynchronously: channel)
    }

    /// The plaintext HTTP/1.1 child pipeline WITH WebSocket-Upgrade negotiation: a `GET` carrying the
    /// `Upgrade: websocket` headers whose path matches a `WS` route upgrades to a WebSocket channel;
    /// everything else becomes a normal HTTP connection. The child's output is the per-connection
    /// negotiation future (`EngineH1Result`), which `servePlainListener` awaits — mirroring the TLS ALPN
    /// negotiation. WebSocket-over-TLS (wss direct) is not wired here; terminate TLS at the proxy.
    func upgradableInitializer(
        routes: any HTTPHandling
    ) -> @Sendable (any Channel) -> EventLoopFuture<EventLoopFuture<EngineH1Result>> {
        { childChannel in
            let wsUpgrader = NIOTypedWebSocketServerUpgrader<EngineH1Result>(
                maxFrameSize: 1 << 20,
                shouldUpgrade: { channel, head in
                    let matched = routes.webSocketRoute(path: head.uri.prefix { $0 != "?" }) != nil
                    return channel.eventLoop.makeSucceededFuture(matched ? HTTPHeaders() : nil)
                },
                upgradePipelineHandler: { channel, head in
                    channel.eventLoop.makeCompletedFuture {
                        try channel.pipeline.syncOperations.addHandler(
                            NIOWebSocketFrameAggregator(
                                minNonFinalFragmentSize: 0, maxAccumulatedFrameCount: 1024,
                                maxAccumulatedFrameSize: 1 << 20))
                        let wsChannel = try WebSocketChannel(wrappingChannelSynchronously: channel)
                        let route =
                            routes.webSocketRoute(path: head.uri.prefix { $0 != "?" })
                            ?? WebSocketRoute { _ in }
                        return EngineH1Result.webSocket(wsChannel, route)
                    }
                })
            let configuration = NIOUpgradableHTTPServerPipelineConfiguration<EngineH1Result>(
                upgradeConfiguration: NIOTypedHTTPServerUpgradeConfiguration(
                    upgraders: [wsUpgrader],
                    notUpgradingCompletionHandler: { channel in
                        channel.eventLoop.makeCompletedFuture {
                            EngineH1Result.http(try self.configureHTTP1AppHandlers(channel, secure: false))
                        }
                    }))
            return childChannel.pipeline.configureUpgradableHTTPServerPipeline(configuration: configuration)
        }
    }

    /// Binds one plaintext HTTP/1.1 listener on the configured transport — or, when the listener carries a
    /// `unixDomainSocketPath`, on that UNIX-domain socket (always via NIOPosix; Network.framework doesn't
    /// do UDS). The existing socket file is replaced so a restart doesn't fail on a stale node. Each child
    /// yields a `EngineH1Result` negotiation (HTTP or upgraded WebSocket).
    func bindPlain(
        _ listener: ListenerConfig, group: any EventLoopGroup, quiesce: ServerQuiescingHelper
    ) async throws -> NIOAsyncChannel<EventLoopFuture<EngineH1Result>, Never> {
        let initializer = upgradableInitializer(routes: listener.routes)
        if let socketPath = listener.unixDomainSocketPath {
            return try await baseBootstrap(group)
                .serverChannelInitializer(quiesceInitializer(quiesce))
                .bind(
                    unixDomainSocketPath: socketPath, cleanupExistingSocketFile: true,
                    childChannelInitializer: initializer)
        }
        #if canImport(Network)
            if transport == .network {
                return try await NIOTSListenerBootstrap(group: group)
                    .serverChannelInitializer(quiesceInitializer(quiesce))
                    .bind(host: listener.host, port: listener.port, childChannelInitializer: initializer)
            }
        #endif
        return try await baseBootstrap(group)
            .serverChannelInitializer(quiesceInitializer(quiesce))
            .bind(host: listener.host, port: listener.port, childChannelInitializer: initializer)
    }

    /// Binds one TLS 1.3 listener that negotiates HTTP/1.1 or HTTP/2 by ALPN. Each child's
    /// output is the *negotiation future* — the initializer returns as soon as the ALPN handler
    /// is installed, so the channel activates and the handshake (which the negotiation depends
    /// on) can proceed; `serveSecureListener` awaits the result per connection. `autoRead` lets
    /// the handshake bytes flow before the inner per-connection channel takes over reads.
    func bindSecure(
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
                                    try self.configureHTTP1AppHandlers(channel, secure: true)
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

    /// Builds a TLS 1.3 server context from PEM material, advertising the listener's ALPN ids. When the
    /// source requires mutual TLS, NIOSSL is told to demand + verify a client certificate against the
    /// trust roots (`.noHostnameVerification` — a CLIENT cert has no server hostname to check, but its
    /// chain must validate), so an unauthenticated client's handshake is rejected.
    func makeTLSContext(_ tls: TLSSource, alpn: [ALPN]) throws -> NIOSSLContext {
        let chain = try NIOSSLCertificate.fromPEMFile(tls.certificatePath)
        let key = try NIOSSLPrivateKey(file: tls.privateKeyPath, format: .pem)
        var config = TLSConfiguration.makeServerConfiguration(
            certificateChain: chain.map { .certificate($0) }, privateKey: .privateKey(key))
        config.minimumTLSVersion = .tlsv13
        config.applicationProtocols = alpn.map(\.rawValue)
        if tls.clientVerification == .required {
            config.certificateVerification = .noHostnameVerification
            if let trustRootsPath = tls.trustRootsPath { config.trustRoots = .file(trustRootsPath) }
        }
        return try NIOSSLContext(configuration: config)
    }

    /// All-idle deadline per connection/stream. Positioned after HTTP decoding, so it resets on each
    /// decoded request part AND each response write — not on raw bytes. A peer that connects and stalls
    /// (or dribbles an incomplete request) is closed instead of pinning a slot indefinitely (slowloris,
    /// CWE-400), while a long-lived SSE stream stays open because its server-write heartbeats reset the
    /// timer (a read-only timer would wrongly reap a healthy server→client stream). Generous vs. the
    /// ms-scale handler latency, so it never trips a legitimate in-flight request; an SSE source must
    /// heartbeat within this window.
    /// Installs the all-idle timeout + the close-on-idle handler at the tail of the (already-built)
    /// HTTP child pipeline, just before the async-channel sink. A non-positive `idleTimeout` disables
    /// the deadline (no handler installed) — a connection then lives until the peer or a drain closes it.
    func addIdleTimeout(_ channel: any Channel) throws {
        guard idleTimeout > .zero else { return }
        try channel.pipeline.syncOperations.addHandler(IdleStateHandler(allTimeout: TimeAmount(idleTimeout)))
        try channel.pipeline.syncOperations.addHandler(IdleTimeoutHandler())
    }
}

/// Answers `Expect: 100-continue` on the HTTP/1 pipeline: on a request head announcing it, the handler
/// writes the `100 Continue` interim toward the encoder so the client proceeds with the body. It sits
/// head-ward of `HTTPResponseCompressor`, so the interim never reaches the compressor (which pops its
/// accept-encoding queue on every response head and would underflow on the final response). The request
/// head is forwarded unchanged. h2 `Expect` is handled separately in the serve loop (no h1 compressor
/// there to conflict). The interim is unconditional for h1: an oversized body still earns its 413 next.
final class HTTP1ExpectContinueHandler: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = HTTPServerRequestPart
    typealias InboundOut = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        if case .head(let head) = unwrapInboundIn(data),
            head.headers[canonicalForm: "expect"].contains(where: { $0.lowercased() == "100-continue" })
        {
            let interim = HTTPResponseHead(version: head.version, status: .continue)
            context.writeAndFlush(wrapOutboundOut(.head(interim)), promise: nil)
        }
        context.fireChannelRead(data)
    }
}
