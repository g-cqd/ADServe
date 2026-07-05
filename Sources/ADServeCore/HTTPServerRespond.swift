// The response path: the response-writing envelope (ETag/304, content-type, cache-control, the
// constant header set, request-id, h1 connection header), gzip response compression, and the
// mapping from ADServe's `ResponseContent` onto the engine's `ServerResponse` — buffered bodies
// directly, `.stream`/`.sse`/`.file` as engine `ResponseStream`s (h1 chunked, h2 DATA frames).
// The route resolution + middleware composition live in EngineResponder.swift.

import ADServeEngineNames
import Foundation
import HTTPCore
import HTTPServer
import Synchronization

/// The flattened buffered response the envelope path starts from: status, content-type, body bytes,
/// and any route-supplied headers (applied over the envelope).
struct MaterializedResponse {
    var status: HTTPStatus
    var contentType: String
    var body: [UInt8]
    var headers: HTTPFields
}

/// ADServe's `ResponseBodyWriter` over the engine's chunk writer: each `write` hands the chunk to
/// the connection (h1 chunked frame / h2 DATA), suspending for transport back-pressure; `flush` is
/// a no-op (the engine flushes per chunk).
struct EngineBodyWriter: ResponseBodyWriter {
    let writer: any HTTPEngineBodyWriter

    func write(_ bytes: [UInt8]) async throws {
        guard !bytes.isEmpty else { return }
        try await writer.write(bytes)
    }

    func flush() async throws {}
}

/// Pure WHATWG `text/event-stream` framing — separated from the writer so the grammar
/// (field order, multi-line `data`, single-line sanitization) is unit-testable without a socket.
enum SSEFraming {
    /// One event frame: optional `event:`/`id:`/`retry:` fields, then one `data:` line per line of
    /// `data`, then the terminating blank line that dispatches the event.
    static func event(event: String?, data: String, id: String?, retry: Int?) -> String {
        var frame = ""
        if let event { frame += "event: \(singleLine(event))\n" }
        if let id { frame += "id: \(singleLine(id))\n" }
        if let retry { frame += "retry: \(retry)\n" }
        // One `data:` line per line of `data`. Split at the SCALAR level: Swift clusters "\r\n" into a
        // single `Character`, so a Character-level split on "\n" would miss CRLF entirely. Stripping a
        // trailing CR off each piece then makes "\r\n" collapse to one line break.
        for piece in data.unicodeScalars.split(separator: "\n", omittingEmptySubsequences: false) {
            var line = String(String.UnicodeScalarView(piece))
            if line.hasSuffix("\r") { line.removeLast() }
            frame += "data: \(line)\n"
        }
        return frame + "\n"
    }

    /// A `: comment` line — the SSE keep-alive heartbeat (dispatches no event).
    static func comment(_ text: String) -> String { ": \(singleLine(text))\n" }

    /// Everything up to the first newline — keeps a single-line field (`event:`/`id:`/`: comment`) from
    /// being split into multiple lines by an embedded `\n`/`\r` (frame-injection defense).
    static func singleLine(_ value: String) -> String {
        String(value.prefix { $0 != "\n" && $0 != "\r" })
    }
}

/// The engine's `SSEWriter`: frames each event/comment via `SSEFraming` and writes it as one chunk
/// (flushed immediately, so a heartbeat reaches the client at once).
struct EngineSSEWriter: SSEWriter {
    let writer: any HTTPEngineBodyWriter

    func send(event: String?, data: String, id: String?, retry: Int?) async throws {
        try await writer.write(
            Array(SSEFraming.event(event: event, data: data, id: id, retry: retry).utf8))
    }

    func comment(_ text: String) async throws {
        try await writer.write(Array(SSEFraming.comment(text).utf8))
    }
}

/// A minimal FIFO async mutex serializing the SSE body's writes against the engine heartbeat's writes
/// (only built when a heartbeat interval is set). Non-reentrant: `acquire` suspends until the holder
/// `release`s, and the holder keeps the gate across its suspending write — so the two writer tasks
/// never call the engine writer concurrently, while per-event back-pressure is preserved (a blocked
/// write blocks the next acquirer too, which is the desired throttle). Contention is at most two
/// waiters (body + heartbeat), so the waiter array stays tiny.
actor FIFOAsyncGate {
    private var held = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func acquire() async {
        if !held {
            held = true
            return
        }
        await withCheckedContinuation { waiters.append($0) }
    }

    func release() {
        if waiters.isEmpty {
            held = false
        } else {
            waiters.removeFirst().resume()
        }
    }
}

/// An `SSEWriter` that routes every frame through an `FIFOAsyncGate`, so the body and the engine
/// heartbeat can both write to one connection without racing the engine writer. Releases the gate
/// on both success and a thrown write (so a failed write never strands the gate held).
struct GatedSSEWriter: SSEWriter {
    let inner: EngineSSEWriter
    let gate: FIFOAsyncGate

    func send(event: String?, data: String, id: String?, retry: Int?) async throws {
        await gate.acquire()
        do {
            try await inner.send(event: event, data: data, id: id, retry: retry)
        } catch {
            await gate.release()
            throw error
        }
        await gate.release()
    }

    func comment(_ text: String) async throws {
        await gate.acquire()
        do {
            try await inner.comment(text)
        } catch {
            await gate.release()
            throw error
        }
        await gate.release()
    }
}

/// Releases one SSE-limiter slot exactly once: explicitly when the stream producer finishes, or via
/// ARC when the response is dropped without the producer ever running (e.g. a failed head write) —
/// so a slot can never leak.
final class SSESlot: Sendable {
    private let released = Atomic<Bool>(false)
    private let limiter: SSELimiter

    init(limiter: SSELimiter) { self.limiter = limiter }

    func release() {
        if released.exchange(true, ordering: .acquiringAndReleasing) == false { limiter.release() }
    }

    deinit { release() }
}

extension EngineResponder {
    /// Applies the response envelope and lowers `content` onto the engine's `ServerResponse`:
    /// ETag/304, content-type, cache-control, the constant header set, the minted/echoed request-id,
    /// (h1 only) the connection header, and gzip compression for eligible buffered bodies.
    func finalize(
        _ content: ResponseContent, cache: CachePolicy, environment: ResponseEnvironment
    ) async -> ServerResponse {
        switch content {
            case .stream(let contentType, let status, let extra, let body):
                return streamResponse(
                    contentType: contentType, status: status, extra: extra, body: body,
                    cache: cache, environment: environment)
            case .sse(let extra, let heartbeat, let body):
                return sseResponse(
                    extra: extra, heartbeat: heartbeat, body: body, environment: environment)
            case .file(let root, let subpath, let contentType, let fileHeaders):
                return await fileResponse(
                    StaticFileRequest(
                        root: root, subpath: subpath, contentType: contentType,
                        headers: fileHeaders),
                    cache: cache, environment: environment)
            default:
                return bufferedResponse(materialize(content), cache: cache, environment: environment)
        }
    }

    /// The buffered path: ETag/304, content-type, header merge, and gzip compression.
    private func bufferedResponse(
        _ response: MaterializedResponse, cache: CachePolicy, environment: ResponseEnvironment
    ) -> ServerResponse {
        var materialized = response
        var headers = commonHeaders(cache: cache, environment: environment)
        var emitEntity = true

        // ETag computed once from the original entity; on a match, blank the body → 304
        // but keep the ETag header (RFC 7232).
        if cache.etag {
            let etag = "\"\(ConditionalRequest.sha256HexLower(materialized.body).prefix(16))\""
            headers.setValue(etag, for: .etag)
            if let inm = environment.ifNoneMatch, ConditionalRequest.matchesIfNoneMatch(inm, etag) {
                materialized.status = .notModified
                materialized.body = []
                emitEntity = false
            }
        }
        if emitEntity {
            headers.setValue(materialized.contentType, for: .contentType)
        }
        // Route-supplied headers override the envelope (CORS / the MCP `/mcp` set); `set-cookie` appends.
        headers.mergeResponse(materialized.headers)
        if emitEntity {
            compressIfEligible(&materialized.body, headers: &headers, environment: environment)
        }
        // No explicit Content-Length: the engine's serializer frames the (possibly compressed) body.
        return ServerResponse(
            HTTPResponse(status: materialized.status, headerFields: headers),
            body: materialized.body)
    }

    /// On-the-fly gzip for a buffered response, mirroring the pre-migration policy: the client must
    /// accept gzip, the body must be at least ``HTTPServer/minimumCompressibleResponseBytes`` (a
    /// sub-MTU body gains nothing), the bare content-type must be mime-db-compressible, and a
    /// pre-encoded (`Content-Encoding`) or range (`Content-Range`) response is never re-encoded.
    /// Streamed responses (`.stream`/`.sse`/`.file`) are never compressed on the fly — serve
    /// precompressed `.br`/`.gz` sidecars for static assets instead.
    private func compressIfEligible(
        _ body: inout [UInt8], headers: inout HTTPFields, environment: ResponseEnvironment
    ) {
        guard configuration.responseCompression,
            body.count >= HTTPServer.minimumCompressibleResponseBytes,
            !headers.contains(.contentEncoding), !headers.contains(.contentRange),
            let accept = environment.acceptEncoding, AcceptEncoding.allows(accept, "gzip"),
            let contentType = headers[.contentType]
        else { return }
        let lower = contentType.lowercased()
        let bareType =
            lower.split(separator: ";", maxSplits: 1).first
            .map { $0.trimmingCharacters(in: .whitespaces) } ?? lower
        guard MIMEDatabase.isCompressible(type: bareType) else { return }
        guard let compressed = GzipEncoder().encode(body), compressed.count < body.count else {
            return
        }
        body = compressed
        headers.setValue("gzip", for: .contentEncoding)
        headers.append("Accept-Encoding", for: .vary)
    }

    /// A writer-driven streamed response: the head goes out first (h1 chunked / h2 length-less),
    /// then the body chunks as the route produces them (back-pressure implicit in each write).
    private func streamResponse(
        contentType: String, status: HTTPStatus, extra: HTTPFields,
        body: @escaping @Sendable (any ResponseBodyWriter) async throws -> Void,
        cache: CachePolicy, environment: ResponseEnvironment
    ) -> ServerResponse {
        var headers = commonHeaders(cache: cache, environment: environment)
        headers.setValue(contentType, for: .contentType)
        headers.mergeResponse(extra)
        let head = HTTPResponse(status: status, headerFields: headers)
        return ServerResponse(
            head,
            stream: ResponseStream { writer in try await body(EngineBodyWriter(writer: writer)) })
    }

    /// A Server-Sent Events stream: admission-controlled (503 at capacity), `no-store`, status 200,
    /// with an optional engine heartbeat serialized against the body's writes through a FIFO gate.
    private func sseResponse(
        extra: HTTPFields, heartbeat: Duration?,
        body: @escaping @Sendable (any SSEWriter) async throws -> Void,
        environment: ResponseEnvironment
    ) -> ServerResponse {
        guard configuration.sseLimiter.tryAcquire() else {
            return bufferedResponse(
                materialize(.plain(.serviceUnavailable, "SSE capacity reached\n")),
                cache: .noStore, environment: environment)
        }
        let slot = SSESlot(limiter: configuration.sseLimiter)
        var headers = commonHeaders(cache: .noStore, environment: environment)
        headers.setValue("text/event-stream", for: .contentType)
        headers.mergeResponse(extra)
        let head = HTTPResponse(status: .ok, headerFields: headers)
        if environment.isHead {
            slot.release()
            return ServerResponse(head)
        }
        return ServerResponse(
            head,
            stream: ResponseStream { writer in
                defer { slot.release() }
                try await Self.driveSSE(body, writer: writer, heartbeat: heartbeat)
            })
    }

    /// Drives an SSE `body` to completion. With a `heartbeat` interval the engine also runs a child
    /// task emitting a `: ` keep-alive comment every interval; both writers share one `FIFOAsyncGate`
    /// so they never interleave a frame, and the gate is held across each suspending write so
    /// per-event back-pressure is preserved. A peer disconnect surfaces as a thrown write — the body
    /// unwinds and the stream ends; cancellation (server quiesce) is a clean end.
    private static func driveSSE(
        _ body: @escaping @Sendable (any SSEWriter) async throws -> Void,
        writer: any HTTPEngineBodyWriter, heartbeat: Duration?
    ) async throws {
        let inner = EngineSSEWriter(writer: writer)
        let gate = heartbeat != nil ? FIFOAsyncGate() : nil
        let bodyWriter: any SSEWriter = gate.map { GatedSSEWriter(inner: inner, gate: $0) } ?? inner

        let heartbeatTask: Task<Void, Never>?
        if let heartbeat, let gate {
            let pinger = GatedSSEWriter(inner: inner, gate: gate)
            heartbeatTask = Task {
                while !Task.isCancelled {
                    try? await Task.sleep(for: heartbeat)
                    if Task.isCancelled { break }
                    do { try await pinger.comment("") } catch { break }  // peer gone → stop pinging
                }
            }
        } else {
            heartbeatTask = nil
        }
        defer { heartbeatTask?.cancel() }
        do {
            try await body(bodyWriter)
        } catch is CancellationError {
            // Peer disconnected / server quiescing — a normal SSE end, not an error to surface.
        }
    }

    /// The headers common to every response: cache-control (if any), the constant envelope (security
    /// set + Link + Vary), the echoed/minted request-id, and — h1 only (h2/h3 forbid it) — the
    /// keep-alive/close connection header.
    func commonHeaders(cache: CachePolicy, environment: ResponseEnvironment) -> HTTPFields {
        // Start from the pre-built constant envelope (a CoW copy, sized exactly once) and set only the
        // per-request fields, instead of re-appending the whole envelope field-by-field into a store that
        // grows from empty — several reallocations per response on the hottest response-side path.
        var headers = configuration.envelope
        if let cacheControl = cache.cacheControl {
            headers.setValue(cacheControl, for: .cacheControl)
        }
        headers.setValue(environment.requestID, for: RequestID.name)
        if !environment.isHTTP2 {
            headers.setValue(environment.keepAlive ? "keep-alive" : "close", for: .connection)
        }
        return headers
    }

    func materialize(_ content: ResponseContent) -> MaterializedResponse {
        switch content {
            case .raw(let body, let contentType, let status):
                return MaterializedResponse(
                    status: status, contentType: contentType, body: body, headers: HTTPFields())
            case .notFound:
                return MaterializedResponse(
                    status: .notFound, contentType: "text/plain; charset=utf-8",
                    body: Array("Not Found".utf8), headers: HTTPFields())
            case .plain(let status, let message):
                return MaterializedResponse(
                    status: status, contentType: "text/plain; charset=utf-8",
                    body: Array(message.utf8), headers: HTTPFields())
            case .full(let body, let contentType, let status, let headers):
                return MaterializedResponse(
                    status: status, contentType: contentType, body: body, headers: headers)
            case .stream, .sse, .file:
                // Unreachable: these are handled in `finalize` before `materialize`. Return a benign
                // 500 (failure-safe — never traps) should a future buffered caller forget to gate.
                return MaterializedResponse(
                    status: .internalServerError, contentType: "text/plain; charset=utf-8", body: [],
                    headers: HTTPFields())
        }
    }
}

/// `Accept-Encoding` membership: whether the header permits a coding token (present, or `*`, and not
/// explicitly `;q=0`) — shared by the response-compression gate and the precompressed-static path.
enum AcceptEncoding {
    static func allows(_ acceptEncoding: String, _ token: String) -> Bool {
        for part in acceptEncoding.lowercased().split(separator: ",") {
            let fields = part.split(separator: ";")
            guard let name = fields.first?.trimmingCharacters(in: .whitespaces),
                name == token || name == "*"
            else { continue }
            let zeroQ = fields.dropFirst()
                .contains {
                    $0.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: " ", with: "")
                        == "q=0"
                }
            if !zeroQ { return true }
        }
        return false
    }
}
