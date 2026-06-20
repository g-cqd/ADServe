import Foundation
import HTTPTypes
import Logging
import NIOCore
import NIOPosix

@testable import ADServeCore

/// A minimal `HTTPHandling` for integration tests: every `GET` (any path) runs `respond`; other
/// methods 404. Lets a loopback test serve a chosen `ResponseContent` (e.g. a `.stream`/`.sse`)
/// straight through the engine without pulling in the DSL.
struct StubRoutes: HTTPHandling {
    let respond: @Sendable (ServerRequest) -> ResponseContent
    func match(method: HTTPRequest.Method, path: Substring) -> RouteMatch {
        guard method == .get else { return .notFound }
        let run = respond
        return .matched(
            MatchedRoute(needsStorage: false, cache: .unset, run: { input in run(input.request) }))
    }
}

/// Like `StubRoutes` but matches ANY method and hands the handler the full `HandlerInput` (so a test can
/// reach `input.storage` — the session, the seeded remote address — not just the request).
struct InputStubRoutes: HTTPHandling {
    let respond: @Sendable (HandlerInput) -> ResponseContent
    func match(method: HTTPRequest.Method, path: Substring) -> RouteMatch {
        let run = respond
        return .matched(
            MatchedRoute(needsStorage: false, cache: .unset, run: { input in run(input) }))
    }
}

/// Collects all inbound bytes on a client connection, fulfilling `promise` when the server closes the
/// socket (the harness sends `Connection: close`, so the server closes after `.end` → the client sees
/// EOF). `@unchecked Sendable`: `accumulated` is touched ONLY from the channel's event loop
/// (`channelRead`/`channelInactive`), the standard NIO handler confinement invariant.
final class ResponseCollector: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    private let promise: EventLoopPromise<[UInt8]>
    private var accumulated: [UInt8] = []
    init(_ promise: EventLoopPromise<[UInt8]>) { self.promise = promise }
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        accumulated.append(contentsOf: unwrapInboundIn(data).readableBytesView)
    }
    func channelInactive(context: ChannelHandlerContext) { promise.succeed(accumulated) }
    func errorCaught(context: ChannelHandlerContext, error: any Error) { promise.fail(error) }
}

/// HTTP/1.1 response framing check for the KEPT-ALIVE collector: is `bytes` a COMPLETE response a client
/// could stop reading on? `Transfer-Encoding: chunked` → terminated by the `0\r\n\r\n` last-chunk;
/// `Content-Length: N` → N body bytes present. A response with neither is close-delimited (never
/// "complete" here — it ends at EOF). Byte-accurate, since a compressed body is binary (a lossy
/// `String` round-trip would mis-measure it).
enum HTTP1ResponseFraming {
    static func isComplete(_ bytes: [UInt8]) -> Bool {
        guard let headerEnd = headerBoundary(bytes) else { return false }
        let header = String(decoding: bytes[..<headerEnd], as: UTF8.self).lowercased()
        let bodyStart = headerEnd + 4  // past the `\r\n\r\n`
        if header.contains("transfer-encoding: chunked") {
            return contains(Array(bytes[bodyStart...]), subsequence: [0x30, 13, 10, 13, 10])  // "0\r\n\r\n"
        }
        if let contentLength = contentLength(header) { return bytes.count - bodyStart >= contentLength }
        return false
    }

    /// Index of the `\r` beginning the `\r\n\r\n` that ends the header block.
    static func headerBoundary(_ bytes: [UInt8]) -> Int? {
        guard bytes.count >= 4 else { return nil }
        for i in 0 ... (bytes.count - 4)
        where bytes[i] == 13 && bytes[i + 1] == 10 && bytes[i + 2] == 13 && bytes[i + 3] == 10 { return i }
        return nil
    }

    static func contentLength(_ lowercasedHeader: String) -> Int? {
        guard let range = lowercasedHeader.range(of: "content-length:") else { return nil }
        return Int(lowercasedHeader[range.upperBound...].drop { $0 == " " }.prefix { $0.isNumber })
    }

    static func contains(_ haystack: [UInt8], subsequence needle: [UInt8]) -> Bool {
        guard !needle.isEmpty, needle.count <= haystack.count else { return false }
        for start in 0 ... (haystack.count - needle.count)
        where Array(haystack[start ..< start + needle.count]) == needle { return true }
        return false
    }
}

/// Collects a response over a KEPT-ALIVE connection and resolves the instant it is framing-complete
/// (`HTTP1ResponseFraming.isComplete`) — so a correctly-framed response returns at once. If the response
/// is NOT self-terminating (the stale-`Content-Length`-beside-a-compressed-body bug, where a real client
/// would block forever), a scheduled `backstop` resolves with whatever arrived, so the test asserts on
/// the truncation instead of hanging. `@unchecked Sendable`: state is touched only on the channel's event
/// loop (handler callbacks + a task scheduled on that same loop).
final class CompletionCollector: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    private let promise: EventLoopPromise<[UInt8]>
    private let backstop: TimeAmount
    private var accumulated: [UInt8] = []
    private var done = false
    init(_ promise: EventLoopPromise<[UInt8]>, backstop: TimeAmount) {
        self.promise = promise
        self.backstop = backstop
    }
    func channelActive(context: ChannelHandlerContext) {
        context.eventLoop.scheduleTask(in: backstop) { [weak self] in self?.finish() }
        context.fireChannelActive()
    }
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        accumulated.append(contentsOf: unwrapInboundIn(data).readableBytesView)
        if HTTP1ResponseFraming.isComplete(accumulated) { finish() }
    }
    func channelInactive(context: ChannelHandlerContext) { finish() }
    func errorCaught(context: ChannelHandlerContext, error: any Error) { finish() }
    private func finish() {
        guard !done else { return }
        done = true
        promise.succeed(accumulated)
    }
}

/// Reports whether the SERVER closes a kept-alive connection within a bound — `true` on `channelInactive`
/// (the configurable idle timeout firing), `false` if still open when the backstop elapses. Same event-
/// loop confinement as `CompletionCollector`.
final class CloseObserver: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    private let promise: EventLoopPromise<Bool>
    private let backstop: TimeAmount
    private var done = false
    init(_ promise: EventLoopPromise<Bool>, backstop: TimeAmount) {
        self.promise = promise
        self.backstop = backstop
    }
    func channelActive(context: ChannelHandlerContext) {
        context.eventLoop.scheduleTask(in: backstop) { [weak self] in self?.resolve(false) }  // still open
        context.fireChannelActive()
    }
    func channelInactive(context: ChannelHandlerContext) { resolve(true) }  // server closed
    func errorCaught(context: ChannelHandlerContext, error: any Error) { resolve(true) }
    private func resolve(_ value: Bool) {
        guard !done else { return }
        done = true
        promise.succeed(value)
    }
}

/// Binds an `HTTPServer` on an OS-assigned loopback port, sends one raw HTTP/1.1 request, and returns
/// the full raw response as text (read to EOF). The first real-socket coverage in the suite — reused
/// by the streaming/SSE/static integration tests. Best-effort teardown (cancel the serve task; a fresh
/// port per call keeps tests isolated) and bounded waits, so it can never hang CI.
enum Loopback {
    static func run(
        path: String, routes: any HTTPHandling, headers: [(name: String, value: String)] = [],
        middleware: [any HTTPMiddleware] = [], compression: Bool = true
    ) async throws -> String {
        // `Connection: close` makes the server close after `.end`, ending the client's read at EOF.
        var request = "GET \(path) HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n"
        for header in headers { request += "\(header.name): \(header.value)\r\n" }
        return try await runRaw(
            request + "\r\n", routes: routes, middleware: middleware, compression: compression)
    }

    /// Send a fully-formed raw HTTP/1.1 request (caller supplies request line + headers + body) and read
    /// the whole response to EOF — for exercising the wire directly (e.g. `Expect: 100-continue`, where
    /// the engine writes a `100` interim before the final response). Include `Connection: close`.
    static func runRaw(
        _ rawRequest: String, routes: any HTTPHandling, middleware: [any HTTPMiddleware] = [],
        compression: Bool = true
    ) async throws -> String {
        // The harness ELG (probe + client). `shutdownGracefully` must be awaited (the strict test
        // settings forbid the blocking `syncShutdownGracefully` in an async context), so bracket the
        // work in do/catch rather than a `defer`.
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        do {
            let response = try await serve(
                request: rawRequest, routes: routes, middleware: middleware, compression: compression,
                group: group)
            try? await group.shutdownGracefully()
            return response
        } catch {
            try? await group.shutdownGracefully()
            throw error
        }
    }

    private static func serve(
        request: String, routes: any HTTPHandling, middleware: [any HTTPMiddleware], compression: Bool,
        group: MultiThreadedEventLoopGroup
    ) async throws -> String {
        // Discover a free loopback port (bind :0, read the assignment, release it).
        let probe = try await ServerBootstrap(group: group).bind(host: "127.0.0.1", port: 0).get()
        let port = probe.localAddress?.port ?? 0
        try await probe.close().get()

        let readiness = ServerReadiness()
        let server = HTTPServer(
            listeners: [ListenerConfig(host: "127.0.0.1", port: port, routes: routes)], pool: nil,
            envelope: HTTPFields(), logger: Logger(label: "loopback-test"), threadCount: 1, loopCount: 1,
            readiness: readiness, middleware: middleware, responseCompression: compression)
        let serverTask = Task { try? await server.run() }
        defer { serverTask.cancel() }

        // Await readiness, bounded (≤2s) so a bind failure surfaces as a connect error, never a hang.
        var spins = 0
        while !readiness.isReady && spins < 200 {
            try await Task.sleep(for: .milliseconds(10))
            spins += 1
        }

        let promise = group.next().makePromise(of: [UInt8].self)
        let client = try await ClientBootstrap(group: group)
            .channelInitializer { channel in channel.pipeline.addHandler(ResponseCollector(promise)) }
            .connect(host: "127.0.0.1", port: port).get()
        var buffer = client.allocator.buffer(capacity: request.utf8.count)
        buffer.writeString(request)
        try await client.writeAndFlush(buffer).get()
        let bytes = try await promise.futureResult.get()
        return String(decoding: bytes, as: UTF8.self)
    }

    /// Like `run`, but over a connection the CLIENT keeps ALIVE (`Connection: keep-alive`): reads until
    /// the response is self-framed — chunked terminated, or `Content-Length` bytes received — so a wrong
    /// `Content-Length` does NOT read to a convenient EOF (the way `Connection: close` masks it). If the
    /// response never self-terminates (the compression hang), a `backstop` resolves with what arrived, so
    /// the caller asserts on the truncation instead of hanging. Threads the server options under test.
    static func runKeepAlive(
        path: String, routes: any HTTPHandling, headers: [(name: String, value: String)] = [],
        keepAlive: Bool = true, idleTimeout: Duration = .seconds(60), compression: Bool = true,
        backstop: Duration = .milliseconds(700)
    ) async throws -> String {
        var request = "GET \(path) HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n"
        for header in headers { request += "\(header.name): \(header.value)\r\n" }
        request += "\r\n"
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let stop = TimeAmount(backstop)
        do {
            let bytes = try await connect(
                request: request, routes: routes, keepAlive: keepAlive, idleTimeout: idleTimeout,
                compression: compression, group: group
            ) { CompletionCollector($0, backstop: stop) }
            try? await group.shutdownGracefully()
            return String(decoding: bytes, as: UTF8.self)
        } catch {
            try? await group.shutdownGracefully()
            throw error
        }
    }

    /// Opens a kept-alive connection, sends one request, and reports whether the SERVER closes it within
    /// `within` — proving the configurable `idleTimeout` fires (`true`) or that the connection stays open
    /// (`false` on the backstop).
    static func observeServerClose(
        path: String, routes: any HTTPHandling, idleTimeout: Duration, within: Duration
    ) async throws -> Bool {
        let request = "GET \(path) HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n"
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let stop = TimeAmount(within)
        do {
            let closed = try await connect(
                request: request, routes: routes, keepAlive: true, idleTimeout: idleTimeout,
                compression: true, group: group
            ) { CloseObserver($0, backstop: stop) }
            try? await group.shutdownGracefully()
            return closed
        } catch {
            try? await group.shutdownGracefully()
            throw error
        }
    }

    /// Binds a one-listener server with the options under test, connects a client, sends `request`, and
    /// resolves whatever the supplied collector promises (response bytes, or a closed-within-bound Bool).
    private static func connect<R: Sendable>(
        request: String, routes: any HTTPHandling, keepAlive: Bool, idleTimeout: Duration,
        compression: Bool, group: MultiThreadedEventLoopGroup,
        makeCollector: @escaping @Sendable (EventLoopPromise<R>) -> any ChannelHandler
    ) async throws -> R {
        let probe = try await ServerBootstrap(group: group).bind(host: "127.0.0.1", port: 0).get()
        let port = probe.localAddress?.port ?? 0
        try await probe.close().get()

        let readiness = ServerReadiness()
        // Map the harness's two axes to the engine policy: keep-alive carries the given idle deadline;
        // disabled → Connection: close.
        let policy: KeepAlivePolicy = keepAlive ? .idleTimeout(idleTimeout) : .close
        let server = HTTPServer(
            listeners: [ListenerConfig(host: "127.0.0.1", port: port, routes: routes)], pool: nil,
            envelope: HTTPFields(), logger: Logger(label: "loopback-keepalive"), threadCount: 1,
            loopCount: 1, readiness: readiness, responseCompression: compression, keepAlive: policy)
        let serverTask = Task { try? await server.run() }
        defer { serverTask.cancel() }

        var spins = 0
        while !readiness.isReady && spins < 200 {
            try await Task.sleep(for: .milliseconds(10))
            spins += 1
        }

        let promise = group.next().makePromise(of: R.self)
        let client = try await ClientBootstrap(group: group)
            .channelInitializer { channel in
                // Build + add the collector ON the event loop (sync ops): the existential `any
                // ChannelHandler` it returns never crosses isolation, so no Sendable violation.
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(makeCollector(promise))
                }
            }
            .connect(host: "127.0.0.1", port: port).get()
        var buffer = client.allocator.buffer(capacity: request.utf8.count)
        buffer.writeString(request)
        try await client.writeAndFlush(buffer).get()
        let result = try await promise.futureResult.get()
        try? await client.close().get()
        return result
    }
}
