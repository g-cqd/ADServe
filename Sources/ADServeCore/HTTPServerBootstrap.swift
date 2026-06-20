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

    /// The plaintext HTTP/1.1 child pipeline — shared by both transports.
    func plainInitializer() -> @Sendable (any Channel) -> EventLoopFuture<EngineConnection> {
        let compress = responseCompression
        return { childChannel in
            childChannel.eventLoop.makeCompletedFuture {
                try childChannel.pipeline.syncOperations.configureHTTPServerPipeline()
                // `Expect: 100-continue` ahead of the compressor (the interim must not pass through it).
                try Self.addExpectContinue(childChannel)
                // The compressor operates on the NIO HTTP/1 parts, so it sits between the HTTP codec and
                // the swift-http-types bridge: outbound it compresses the body before encoding; inbound it
                // reads the request's `Accept-Encoding`.
                if compress {
                    try childChannel.pipeline.syncOperations.addHandler(Self.makeResponseCompressor())
                }
                // Bridge NIO's HTTP/1 parts ↔ swift-http-types parts (server, plaintext).
                try childChannel.pipeline.syncOperations.addHandler(HTTP1ToHTTPServerCodec(secure: false))
                try Self.addIdleTimeout(childChannel)
                return try EngineConnection(wrappingChannelSynchronously: childChannel)
            }
        }
    }

    /// Binds one plaintext HTTP/1.1 listener on the configured transport.
    func bindPlain(
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
    func bindSecure(
        _ listener: ListenerConfig, group: any EventLoopGroup, quiesce: ServerQuiescingHelper
    ) async throws -> NIOAsyncChannel<EventLoopFuture<EngineNegotiated>, Never> {
        #if canImport(Network)
            if transport == .network {
                throw EngineError(message: "TLS over the .network transport is not yet implemented (F3b)")
            }
        #endif
        let sslContext = try makeTLSContext(listener.wire.tls!, alpn: listener.wire.alpn)
        let compress = responseCompression
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
                                    // `Expect: 100-continue` ahead of the compressor on the secure h1 path too.
                                    try Self.addExpectContinue(channel)
                                    // Compress on the secure h1 path too (before the swift-http-types bridge).
                                    if compress {
                                        try channel.pipeline.syncOperations.addHandler(
                                            Self.makeResponseCompressor())
                                    }
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
    func makeTLSContext(_ tls: TLSSource, alpn: [ALPN]) throws -> NIOSSLContext {
        let chain = try NIOSSLCertificate.fromPEMFile(tls.certificatePath)
        let key = try NIOSSLPrivateKey(file: tls.privateKeyPath, format: .pem)
        var config = TLSConfiguration.makeServerConfiguration(
            certificateChain: chain.map { .certificate($0) }, privateKey: .privateKey(key))
        config.minimumTLSVersion = .tlsv13
        config.applicationProtocols = alpn.map(\.rawValue)
        return try NIOSSLContext(configuration: config)
    }

    /// All-idle deadline per connection/stream. Positioned after HTTP decoding, so it resets on each
    /// decoded request part AND each response write — not on raw bytes. A peer that connects and stalls
    /// (or dribbles an incomplete request) is closed instead of pinning a slot indefinitely (slowloris,
    /// CWE-400), while a long-lived SSE stream stays open because its server-write heartbeats reset the
    /// timer (a read-only timer would wrongly reap a healthy server→client stream). Generous vs. the
    /// ms-scale handler latency, so it never trips a legitimate in-flight request; an SSE source must
    /// heartbeat within this window.
    static var idleTimeout: TimeAmount { .seconds(60) }

    /// Installs the all-idle timeout + the close-on-idle handler at the tail of the (already-built)
    /// HTTP child pipeline, just before the async-channel sink.
    static func addIdleTimeout(_ channel: any Channel) throws {
        try channel.pipeline.syncOperations.addHandler(IdleStateHandler(allTimeout: idleTimeout))
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
