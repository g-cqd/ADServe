// The engine's transport composition over the HTTP package's `ServerTransport` seam: a bound
// notifier (drives `ServerReadiness`), the connection-capacity gate (answers a canned `503` +
// `Retry-After` past `maxConnections`, preserving the pre-migration behavior — the HTTP package's
// own cap closes silently), and a UNIX-domain-socket transport (the HTTP package ships none — a
// recorded upstream gap; this one rides the public transport abstraction).

import Foundation
import HTTPTransport
import Synchronization

#if canImport(Darwin)
    import Darwin
#elseif canImport(Glibc)
    import Glibc
#elseif canImport(Musl)
    import Musl
#endif

/// Forwards to `inner` and fires `onBound` once the listener is accepting — the readiness signal
/// `ServerReadiness` (and the loopback tests' spin-wait) key off.
final class NotifyingTransport: ServerTransport {
    private let inner: any ServerTransport
    private let onBound: @Sendable () -> Void

    init(_ inner: any ServerTransport, onBound: @escaping @Sendable () -> Void) {
        self.inner = inner
        self.onBound = onBound
    }

    var backbone: TransportBackbone { inner.backbone }
    var boundPort: UInt16 { inner.boundPort }

    func start() async throws -> AsyncStream<any TransportConnection> {
        let connections = try await inner.start()
        onBound()
        return connections
    }

    func shutdown() async { await inner.shutdown() }

    func reload(tls: TransportTLS) async throws { try await inner.reload(tls: tls) }
}

/// Admission control for concurrent CONNECTIONS: past the `ConnectionLimiter` cap a new connection
/// is answered with a minimal `503 Service Unavailable` + `Retry-After` and closed; admitted ones
/// release their slot exactly once when they close.
final class ConnectionLimitingTransport: ServerTransport {
    private let inner: any ServerTransport
    private let limiter: ConnectionLimiter

    init(_ inner: any ServerTransport, limiter: ConnectionLimiter) {
        self.inner = inner
        self.limiter = limiter
    }

    var backbone: TransportBackbone { inner.backbone }
    var boundPort: UInt16 { inner.boundPort }

    func start() async throws -> AsyncStream<any TransportConnection> {
        let upstream = try await inner.start()
        let limiter = limiter
        return AsyncStream { continuation in
            let pump = Task {
                for await connection in upstream {
                    if limiter.tryAcquire() {
                        continuation.yield(LimitedConnection(connection, limiter: limiter))
                    } else {
                        // Reject out-of-band so the accept loop never blocks on a refused peer.
                        Task { await Self.reject(connection) }
                    }
                }
                continuation.finish()
            }
            continuation.onTermination = { _ in pump.cancel() }
        }
    }

    func shutdown() async { await inner.shutdown() }

    func reload(tls: TransportTLS) async throws { try await inner.reload(tls: tls) }

    /// The canned over-capacity response: `503` + `Connection: close` + `Retry-After: 1`.
    private static func reject(_ connection: any TransportConnection) async {
        let body = "server at connection capacity\n"
        let response =
            "HTTP/1.1 503 Service Unavailable\r\n"
            + "content-type: text/plain; charset=utf-8\r\n"
            + "content-length: \(body.utf8.count)\r\n"
            + "connection: close\r\n"
            + "retry-after: 1\r\n\r\n" + body
        try? await connection.send(Array(response.utf8))
        await connection.close()
    }
}

/// A connection that releases its `ConnectionLimiter` slot exactly once on close/cancel (with an
/// ARC backstop), forwarding everything else to the wrapped connection.
private final class LimitedConnection: TransportConnection {
    private let inner: any TransportConnection
    private let limiter: ConnectionLimiter
    private let released = Atomic<Bool>(false)

    init(_ inner: any TransportConnection, limiter: ConnectionLimiter) {
        self.inner = inner
        self.limiter = limiter
    }

    deinit { release() }

    private func release() {
        if released.exchange(true, ordering: .acquiringAndReleasing) == false { limiter.release() }
    }

    var id: TransportConnectionID { inner.id }
    var peer: TransportAddress { inner.peer }
    var negotiatedApplicationProtocol: String? { inner.negotiatedApplicationProtocol }
    var isSecure: Bool { inner.isSecure }
    var tlsPeerSubject: String? { inner.tlsPeerSubject }
    var preferredTaskExecutor: (any TaskExecutor)? { inner.preferredTaskExecutor }

    // The reads are wrapped in per-op cancellation handlers: the socket backbones park `receive`
    // in a continuation that does NOT honor task cancellation (they rely on the serve-task-level
    // `cancel()` handler — which the idle watchdog's child-task cancellation never reaches), so an
    // idle deadline would otherwise never actually close the connection. Recorded upstream; the
    // wrapper restores the documented `TransportConnection` contract at a task-status record per
    // read.
    func receive(maxLength: Int) async throws -> [UInt8]? {
        let inner = inner
        return try await withTaskCancellationHandler {
            try await inner.receive(maxLength: maxLength)
        } onCancel: {
            inner.cancel()
        }
    }

    func receive(into buffer: inout [UInt8], maxLength: Int) async throws -> Int {
        // `buffer` is `inout` and cannot cross into the cancellation-handler closure pair; read into
        // a fresh chunk (the wrapper is not on the zero-copy path) and append.
        let inner = inner
        let chunk = try await withTaskCancellationHandler {
            try await inner.receive(maxLength: maxLength)
        } onCancel: {
            inner.cancel()
        }
        guard let chunk, !chunk.isEmpty else { return 0 }
        buffer.append(contentsOf: chunk)
        return chunk.count
    }

    func send(_ bytes: [UInt8]) async throws { try await inner.send(bytes) }

    func send(_ head: [UInt8], _ body: [UInt8]) async throws { try await inner.send(head, body) }

    func close() async {
        await inner.close()
        release()
    }

    func cancel() {
        inner.cancel()
        release()
    }
}

/// A UNIX-domain-socket `ServerTransport` (`AF_UNIX`/`SOCK_STREAM`): binds the path (replacing a
/// stale socket file), accepts on a dedicated thread, and serves each connection through a
/// reader-thread-backed `TransportConnection`. Intended for the behind-proxy deploy (Caddy/nginx →
/// local socket); the HTTP package ships no UDS backbone (recorded upstream gap), so this rides its
/// public transport abstraction. One OS thread per live connection — fine for a local proxy hop.
final class UnixDomainSocketTransport: ServerTransport {
    private let path: String
    private let listener = Mutex<Int32?>(nil)

    init(path: String) {
        self.path = path
    }

    var backbone: TransportBackbone { .recommended }
    var boundPort: UInt16 { 0 }

    func start() async throws -> AsyncStream<any TransportConnection> {
        let descriptor = try Self.bindListener(path)
        listener.withLock { $0 = descriptor }
        return AsyncStream { continuation in
            let thread = Thread {
                var nextID: UInt64 = 1
                while true {
                    let accepted = accept(descriptor, nil, nil)
                    guard accepted >= 0 else { break }  // listener closed → stop accepting
                    Self.disableSigpipe(accepted)
                    continuation.yield(
                        UnixDomainSocketConnection(
                            descriptor: accepted, id: TransportConnectionID(nextID)))
                    nextID &+= 1
                }
                continuation.finish()
            }
            thread.name = "adserve-uds-accept"
            thread.start()
        }
    }

    func shutdown() async {
        let descriptor = listener.withLock { held -> Int32? in
            defer { held = nil }
            return held
        }
        if let descriptor {
            _ = close(descriptor)
            _ = unsafe unlink(path)
        }
    }

    /// A write to a peer that already closed must fail with EPIPE, not raise SIGPIPE (which would
    /// kill the process). Darwin has no `MSG_NOSIGNAL`, so the option is set per accepted socket;
    /// on Linux the readiness backbones use `MSG_NOSIGNAL` and `SO_NOSIGPIPE` does not exist.
    private static func disableSigpipe(_ descriptor: Int32) {
        #if canImport(Darwin)
            var flag: Int32 = 1
            _ = unsafe setsockopt(
                descriptor, SOL_SOCKET, SO_NOSIGPIPE, &flag, socklen_t(MemoryLayout<Int32>.size))
        #endif
    }

    /// Creates, binds (replacing any stale socket file), and listens on the `AF_UNIX` socket.
    private static func bindListener(_ path: String) throws -> Int32 {
        guard path.utf8.count < MemoryLayout<sockaddr_un>.size - 8 else {
            throw EngineError(message: "UNIX-domain socket path too long: \(path)")
        }
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            throw EngineError(message: "socket(AF_UNIX) failed: errno \(errno)")
        }
        _ = unsafe unlink(path)  // replace a stale node so a restart doesn't fail
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        withUnsafeMutableBytes(of: &address.sun_path) { raw in
            unsafe raw.baseAddress?.copyMemory(from: bytes, byteCount: bytes.count)
        }
        let bound: Int32 = withUnsafePointer(to: &address) { pointer in
            unsafe pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { rebound in
                unsafe bind(descriptor, rebound, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bound == 0, listen(descriptor, 128) == 0 else {
            _ = close(descriptor)
            throw EngineError(message: "bind/listen on \(path) failed: errno \(errno)")
        }
        return descriptor
    }
}

/// A single-consumer inbound-byte mailbox: the reader thread `deliver`s chunks (unbounded only by
/// the peer's send rate x the consumer's pace — a local proxy hop) and `finish`es at EOF; the
/// connection's `take()` suspends until a chunk (or the end) arrives. Lost-wakeup-free: the waiter
/// continuation and the buffer live under one `Mutex`.
final class InboundByteMailbox: Sendable {
    private struct State {
        var buffered: [[UInt8]] = []
        var waiter: CheckedContinuation<[UInt8]?, Never>?
        var finished = false
    }
    private let state = Mutex(State())

    /// Reader-thread side: hand one chunk to the consumer (waking it if parked).
    func deliver(_ chunk: [UInt8]) {
        let waiter = state.withLock { state -> CheckedContinuation<[UInt8]?, Never>? in
            if let parked = state.waiter {
                state.waiter = nil
                return parked
            }
            state.buffered.append(chunk)
            return nil
        }
        waiter?.resume(returning: chunk)
    }

    /// Reader-thread side: end of stream (EOF / read error) — wakes a parked consumer with `nil`.
    func finish() {
        let waiter = state.withLock { state -> CheckedContinuation<[UInt8]?, Never>? in
            state.finished = true
            defer { state.waiter = nil }
            return state.waiter
        }
        waiter?.resume(returning: nil)
    }

    /// Consumer side: the next chunk, or `nil` at end. Single-consumer by contract (the serve loop).
    func take() async -> [UInt8]? {
        await withCheckedContinuation { (continuation: CheckedContinuation<[UInt8]?, Never>) in
            state.withLock { state in
                if !state.buffered.isEmpty {
                    continuation.resume(returning: state.buffered.removeFirst())
                } else if state.finished {
                    continuation.resume(returning: nil)
                } else {
                    state.waiter = continuation
                }
            }
        }
    }
}

/// One accepted UNIX-domain-socket connection: a dedicated reader thread feeds inbound chunks into
/// a mailbox the actor drains (honoring `maxLength` via a leftover buffer); writes go straight to
/// the socket (local proxy hop — the kernel buffer absorbs them).
actor UnixDomainSocketConnection: TransportConnection {
    nonisolated let id: TransportConnectionID
    nonisolated let peer = TransportAddress(host: "", port: 0)

    private let descriptor: Int32
    private let closed: Atomic<Bool>
    private let inbound = InboundByteMailbox()
    private var leftover: [UInt8] = []

    init(descriptor: Int32, id: TransportConnectionID) {
        self.descriptor = descriptor
        self.id = id
        self.closed = Atomic<Bool>(false)
        let mailbox = inbound
        let reader = Thread {
            var buffer = [UInt8](repeating: 0, count: 16_384)
            while true {
                let count = buffer.withUnsafeMutableBytes { raw in
                    unsafe read(descriptor, raw.baseAddress, raw.count)
                }
                guard count > 0 else { break }  // EOF or error → end the inbound stream
                mailbox.deliver(Array(buffer[0 ..< count]))
            }
            mailbox.finish()
        }
        reader.name = "adserve-uds-read"
        reader.start()
    }

    deinit {
        if closed.exchange(true, ordering: .acquiringAndReleasing) == false {
            HTTPServer.closeDescriptor(descriptor)
        }
    }

    func receive(maxLength: Int) async throws -> [UInt8]? {
        if !leftover.isEmpty {
            let taken = Array(leftover.prefix(maxLength))
            leftover.removeFirst(taken.count)
            return taken
        }
        guard let chunk = await inbound.take() else { return nil }
        if chunk.count > maxLength {
            leftover = Array(chunk[maxLength...])
            return Array(chunk[0 ..< maxLength])
        }
        return chunk
    }

    nonisolated func send(_ bytes: [UInt8]) async throws {
        guard closed.load(ordering: .acquiring) == false else {
            throw EngineError(message: "connection closed")
        }
        var offset = 0
        while offset < bytes.count {
            let written = bytes.withUnsafeBytes { raw in
                unsafe write(descriptor, raw.baseAddress.map { unsafe $0 + offset }, bytes.count - offset)
            }
            guard written > 0 else { throw EngineError(message: "UDS write failed: errno \(errno)") }
            offset += written
        }
    }

    nonisolated func close() async { cancel() }

    nonisolated func cancel() {
        if closed.exchange(true, ordering: .acquiringAndReleasing) == false {
            // Shut both directions down so the parked reader thread unblocks, then release the fd.
            _ = shutdown(descriptor, SHUT_RDWR)
            HTTPServer.closeDescriptor(descriptor)
        }
    }
}
