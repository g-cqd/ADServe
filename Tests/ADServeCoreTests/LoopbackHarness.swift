import Foundation
import HTTPCore
import Logging

@testable import ADServeCore

/// A minimal `HTTPHandling` for integration tests: every `GET` (any path) runs `respond`; other
/// methods 404. Lets a loopback test serve a chosen `ResponseContent` (e.g. a `.stream`/`.sse`)
/// straight through the engine without pulling in the DSL.
struct StubRoutes: HTTPHandling {
    let respond: @Sendable (ServerRequest) -> ResponseContent
    func match(method: HTTPMethod, path: Substring) -> RouteMatch {
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
    func match(method: HTTPMethod, path: Substring) -> RouteMatch {
        let run = respond
        return .matched(
            MatchedRoute(needsStorage: false, cache: .unset, run: { input in run(input) }))
    }
}

/// A generic harness failure (readiness never came up, a socket call failed, openssl missing, …).
struct TLSHarnessError: Error {
    let message: String
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
        where bytes[i] == 13 && bytes[i + 1] == 10 && bytes[i + 2] == 13 && bytes[i + 3] == 10 {
            return i
        }
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

/// A blocking POSIX TCP (or UNIX-domain) test client with per-read timeouts — the raw wire driver
/// the loopback tests speak HTTP/1.1 (and WebSocket frames) through. Blocking is fine here: each
/// test drives one or two clients, and every read is bounded by `SO_RCVTIMEO` so nothing can hang.
final class TestSocket: @unchecked Sendable {
    let descriptor: Int32

    private init(descriptor: Int32) {
        self.descriptor = descriptor
    }

    deinit { _ = Darwin.close(descriptor) }

    /// Connects to `host:port` (TCP, loopback tests).
    static func connect(host: String, port: Int) throws -> TestSocket {
        let descriptor = socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw TLSHarnessError(message: "socket() failed") }
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = in_port_t(UInt16(port).bigEndian)
        address.sin_addr.s_addr = inet_addr(host)
        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { rebound in
                Darwin.connect(descriptor, rebound, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connected == 0 else {
            _ = Darwin.close(descriptor)
            throw TLSHarnessError(message: "connect(\(host):\(port)) failed: errno \(errno)")
        }
        var flag: Int32 = 1
        _ = setsockopt(descriptor, IPPROTO_TCP, TCP_NODELAY, &flag, socklen_t(MemoryLayout<Int32>.size))
        // A send to a peer that already closed must fail with EPIPE, not kill the test process.
        var noSigpipe: Int32 = 1
        _ = setsockopt(
            descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSigpipe, socklen_t(MemoryLayout<Int32>.size))
        return TestSocket(descriptor: descriptor)
    }

    /// Connects to a UNIX-domain socket at `path`.
    static func connectUnix(path: String) throws -> TestSocket {
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw TLSHarnessError(message: "socket(AF_UNIX) failed") }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        withUnsafeMutableBytes(of: &address.sun_path) { raw in
            raw.baseAddress?.copyMemory(from: bytes, byteCount: min(bytes.count, raw.count - 1))
        }
        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { rebound in
                Darwin.connect(descriptor, rebound, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0 else {
            _ = Darwin.close(descriptor)
            throw TLSHarnessError(message: "connect(\(path)) failed: errno \(errno)")
        }
        var noSigpipe: Int32 = 1
        _ = setsockopt(
            descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSigpipe, socklen_t(MemoryLayout<Int32>.size))
        return TestSocket(descriptor: descriptor)
    }

    func send(_ bytes: [UInt8]) throws {
        var offset = 0
        while offset < bytes.count {
            let written = bytes.withUnsafeBytes { raw in
                Darwin.send(descriptor, raw.baseAddress.map { $0 + offset }, bytes.count - offset, 0)
            }
            guard written > 0 else { throw TLSHarnessError(message: "send failed: errno \(errno)") }
            offset += written
        }
    }

    func send(_ text: String) throws { try send(Array(text.utf8)) }

    /// One bounded read (≤ `timeout`): the received chunk, `[]` on EOF, or `nil` on timeout.
    func readChunk(timeout: Duration) -> [UInt8]? {
        var tv = timeval(
            tv_sec: Int(timeout.components.seconds),
            tv_usec: Int32(timeout.components.attoseconds / 1_000_000_000_000))
        _ = setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var buffer = [UInt8](repeating: 0, count: 65_536)
        let count = buffer.withUnsafeMutableBytes { raw in
            recv(descriptor, raw.baseAddress, raw.count, 0)
        }
        if count > 0 { return Array(buffer[0 ..< count]) }
        if count == 0 { return [] }
        return nil  // timeout (EAGAIN) or error
    }

    /// Reads to EOF (bounded by `timeout` per read; a stall past it returns what arrived).
    func readToEOF(timeout: Duration = .seconds(5)) -> [UInt8] {
        var accumulated: [UInt8] = []
        while let chunk = readChunk(timeout: timeout) {
            if chunk.isEmpty { break }  // EOF
            accumulated.append(contentsOf: chunk)
        }
        return accumulated
    }

    /// Reads until the response is framing-complete (`HTTP1ResponseFraming`), EOF, or `backstop`
    /// elapses — the kept-alive collector (a wrong Content-Length cannot hide behind EOF).
    func readUntilComplete(backstop: Duration) -> [UInt8] {
        let deadline = ContinuousClock.now.advanced(by: backstop)
        var accumulated: [UInt8] = []
        while ContinuousClock.now < deadline {
            if HTTP1ResponseFraming.isComplete(accumulated) { break }
            guard let chunk = readChunk(timeout: .milliseconds(50)) else { continue }
            if chunk.isEmpty { break }  // EOF
            accumulated.append(contentsOf: chunk)
        }
        return accumulated
    }

    /// Whether the SERVER closes this connection within `within` — `true` on EOF, `false` if still
    /// open when the bound elapses.
    func observeClose(within: Duration) -> Bool {
        let deadline = ContinuousClock.now.advanced(by: within)
        while ContinuousClock.now < deadline {
            guard let chunk = readChunk(timeout: .milliseconds(50)) else { continue }
            if chunk.isEmpty { return true }  // EOF — the server closed
        }
        return false
    }

    func close() {
        _ = shutdown(descriptor, SHUT_RDWR)
    }
}

/// Runs blocking client I/O on a DEDICATED thread and resumes the caller — never on the cooperative
/// pool. The suite runs many tests in parallel, each with a blocking POSIX client; parking those on
/// cooperative threads starves the server-side pump tasks (a forward-progress violation) and every
/// read then times out empty.
func runOnThread<R: Sendable>(_ body: @escaping @Sendable () throws -> R) async throws -> R {
    try await withCheckedThrowingContinuation { continuation in
        let thread = Thread {
            continuation.resume(with: Result { try body() })
        }
        thread.name = "adserve-test-client"
        thread.start()
    }
}

/// Binds an `HTTPServer` on an OS-assigned loopback port, sends one raw HTTP/1.1 request, and returns
/// the full raw response as text (read to EOF). Reused by the streaming/SSE/static integration tests.
/// Best-effort teardown (cancel the serve task; a fresh port per call keeps tests isolated) and bounded
/// waits, so it can never hang CI.
enum Loopback {
    static func run(
        path: String, routes: any HTTPHandling, headers: [(name: String, value: String)] = [],
        middleware: [any HTTPMiddleware] = [], compression: Bool = true
    ) async throws -> String {
        // `Connection: close` makes the server close after the exchange, ending the read at EOF.
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
        let bytes = try await runRawBytes(
            Array(rawRequest.utf8), routes: routes, middleware: middleware, compression: compression)
        return String(decoding: bytes, as: UTF8.self)
    }

    /// The byte-level `runRaw` (binary-safe request AND response — compressed bodies survive).
    static func runRawBytes(
        _ rawRequest: [UInt8], routes: any HTTPHandling, middleware: [any HTTPMiddleware] = [],
        compression: Bool = true
    ) async throws -> [UInt8] {
        try await withServer(routes: routes, middleware: middleware, compression: compression) { port in
            let client = try TestSocket.connect(host: "127.0.0.1", port: port)
            try client.send(rawRequest)
            return client.readToEOF()
        }
    }

    /// Like `run`, but over a connection the CLIENT keeps ALIVE (`Connection: keep-alive`): reads until
    /// the response is self-framed — chunked terminated, or `Content-Length` bytes received — so a wrong
    /// `Content-Length` does NOT read to a convenient EOF (the way `Connection: close` masks it). If the
    /// response never self-terminates, a `backstop` resolves with what arrived, so the caller asserts on
    /// the truncation instead of hanging. Threads the server options under test.
    static func runKeepAlive(
        path: String, routes: any HTTPHandling, headers: [(name: String, value: String)] = [],
        keepAlive: Bool = true, idleTimeout: Duration = .seconds(60), compression: Bool = true,
        backstop: Duration = .milliseconds(700)
    ) async throws -> String {
        var lines = "GET \(path) HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n"
        for header in headers { lines += "\(header.name): \(header.value)\r\n" }
        let request = lines + "\r\n"
        // Map the harness two axes to the engine policy: keep-alive carries the given idle deadline;
        // disabled → Connection: close.
        let policy: KeepAlivePolicy = keepAlive ? .idleTimeout(idleTimeout) : .close
        let bytes = try await withServer(
            routes: routes, compression: compression, keepAlive: policy
        ) { port in
            let client = try TestSocket.connect(host: "127.0.0.1", port: port)
            try client.send(request)
            return client.readUntilComplete(backstop: backstop)
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    /// Opens a kept-alive connection, sends one request, and reports whether the SERVER closes it within
    /// `within` — proving the configurable `idleTimeout` fires (`true`) or that the connection stays open
    /// (`false` on the backstop).
    static func observeServerClose(
        path: String, routes: any HTTPHandling, idleTimeout: Duration, within: Duration
    ) async throws -> Bool {
        let request = "GET \(path) HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n"
        return try await withServer(
            routes: routes, keepAlive: .idleTimeout(idleTimeout)
        ) { port in
            let client = try TestSocket.connect(host: "127.0.0.1", port: port)
            try client.send(request)
            _ = client.readUntilComplete(backstop: .seconds(2))  // consume the response first
            return client.observeClose(within: within)
        }
    }

    /// Discover a free loopback port: bind :0, read the assignment, release it. The same
    /// probe-then-bind pattern the pre-migration harness used; raciness is irrelevant at test scale.
    static func freePort() throws -> Int {
        let probe = socket(AF_INET, SOCK_STREAM, 0)
        guard probe >= 0 else { throw TLSHarnessError(message: "probe socket failed") }
        defer { _ = Darwin.close(probe) }
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = 0
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { rebound in
                bind(probe, rebound, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else { throw TLSHarnessError(message: "probe bind failed") }
        var assigned = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &assigned) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { rebound in
                getsockname(probe, rebound, &length)
            }
        }
        guard named == 0 else { throw TLSHarnessError(message: "getsockname failed") }
        return Int(UInt16(bigEndian: assigned.sin_port))
    }

    /// Await `readiness` (≤2s, 10ms spins) so a bind failure surfaces as a thrown error, never a hang.
    static func awaitReadiness(_ readiness: ServerReadiness) async throws {
        var spins = 0
        while !readiness.isReady && spins < 200 {
            try await Task.sleep(for: .milliseconds(10))
            spins += 1
        }
        guard readiness.isReady else { throw TLSHarnessError(message: "server never became ready") }
    }

    /// Binds a one-listener server with the options under test, runs `body` with the bound port on a
    /// worker thread (the client I/O is blocking), and tears the server down.
    static func withServer<R: Sendable>(
        routes: any HTTPHandling, middleware: [any HTTPMiddleware] = [], compression: Bool = true,
        keepAlive: KeepAlivePolicy = .keepAlive,
        maxConnections: Int = HTTPServer.defaultMaxConnections,
        maxBodyBytes: Int = 1_000_000,
        requestDecompression: RequestDecompressionPolicy = .disabled,
        _ body: @escaping @Sendable (Int) throws -> R
    ) async throws -> R {
        let port = try freePort()
        let readiness = ServerReadiness()
        let server = HTTPServer(
            listeners: [ListenerConfig(host: "127.0.0.1", port: port, routes: routes)], pool: nil,
            envelope: HTTPFields(), logger: Logger(label: "loopback-test"), threadCount: 2,
            loopCount: 1, readiness: readiness, middleware: middleware,
            maxBodyBytes: maxBodyBytes, maxConnections: maxConnections,
            responseCompression: compression, keepAlive: policyOrDefault(keepAlive),
            requestDecompression: requestDecompression)
        let serverTask = Task { try? await server.run() }
        defer { serverTask.cancel() }
        try await awaitReadiness(readiness)
        // The client speaks blocking POSIX I/O — run it on a dedicated thread, never the pool.
        return try await runOnThread { try body(port) }
    }

    private static func policyOrDefault(_ policy: KeepAlivePolicy) -> KeepAlivePolicy { policy }
}
