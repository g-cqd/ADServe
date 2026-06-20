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

/// Collects all inbound bytes on a client connection, fulfilling `promise` when the server closes the
/// socket (the harness sends `Connection: close`, so the server closes after `.end` → the client sees
/// EOF). `@unchecked Sendable`: `accumulated` is touched ONLY from the channel's event loop
/// (`channelRead`/`channelInactive`), the standard NIO handler confinement invariant.
private final class ResponseCollector: ChannelInboundHandler, @unchecked Sendable {
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
}
