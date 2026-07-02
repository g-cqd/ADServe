// Guarded static-asset serving (adserve-requirements #4 + the hardening round). The blocking
// jail/stat/range/encoding decision runs on the engine's blocking-offload pool (never the
// cooperative pool) and returns a PLAN; the response half then streams the chosen file (or byte
// range) back in bounded chunks through the engine's `ResponseStream` — each chunk read off-pool
// and written with implicit transport back-pressure. The path is canonicalized with
// `standardizedFileURL` + `resolvingSymlinksInPath`, so `..` (already rejected upstream by
// PathTemplate) AND symlink escape are caught — every served path (identity or `.br`/`.gz`
// sibling) must stay inside the resolved root.
//
// Hardening: a strong size+mtime ETag (B1); precompressed `.br`/`.gz` negotiation by
// `Accept-Encoding` for compressible types (B2); HTTP `Range`/206 + 416 (B3); and chunked
// streaming so even a large file never materializes whole (B4).

import ADConcurrency
import Foundation
import HTTPCore
import HTTPServer
import Synchronization

#if canImport(Darwin)
    import Darwin
#elseif canImport(Glibc)
    import Glibc
#elseif canImport(Musl)
    import Musl
#endif

/// The validated descriptor the DSL `Static(_:root:)` produces.
struct StaticFileRequest {
    let root: String
    let subpath: String
    let contentType: String
    let headers: HTTPFields
}

/// The off-loop resolution: which file to read, with what status/range/encoding, or a terminal status.
/// `Sendable` so it can cross back from the offload-pool thread — and so the route terminal can stash it
/// on `RequestStorage` (`ResolvedStaticPlanKey`) for `writeFile` to reuse without a second stat.
enum StaticPlan: Sendable {
    case notFound
    case notModified(etag: String, lastModified: String)
    case rangeNotSatisfiable(totalSize: Int)
    /// Serve `absolutePath` (identity or a `.br`/`.gz` sibling). `range` non-nil ⇒ 206 partial content.
    /// `lastModified` is the IMF-fixdate of the served file's mtime (emitted as `Last-Modified`).
    case serve(
        absolutePath: String, partial: Bool, etag: String, lastModified: String, contentEncoding: String?,
        totalSize: Int, range: ClosedRange<Int>?)

    /// The HTTP status this plan resolves to — recorded into the `ResponseStatusBox` so observing
    /// middleware (`RequestLogging`/metrics) log the real static status, not the nominal 200.
    var statusCode: Int {
        switch self {
            case .notFound: return 404
            case .notModified: return 304
            case .rangeNotSatisfiable: return 416
            case .serve(_, let partial, _, _, _, _, _): return partial ? 206 : 200
        }
    }
}

/// The `RequestStorage` key under which the route terminal stashes the resolved `StaticPlan`, so
/// `writeFile` reuses it (single stat per static request) and the `ResponseStatusBox` carries the real
/// status before the middleware chain unwinds.
enum ResolvedStaticPlanKey: StorageKey {
    typealias Value = StaticPlan
}

/// Owns one read-only file descriptor for a streamed static response: closed exactly once —
/// explicitly when the stream producer finishes, or via ARC if the response is dropped without the
/// producer ever running (e.g. a failed head write) — so a descriptor can never leak.
final class FileDescriptorBox: Sendable {
    private let closed = Atomic<Bool>(false)
    let descriptor: Int32

    init(descriptor: Int32) { self.descriptor = descriptor }

    func close() {
        if closed.exchange(true, ordering: .acquiringAndReleasing) == false {
            HTTPServer.closeDescriptor(descriptor)
        }
    }

    deinit { close() }
}

extension EngineResponder {
    /// Resolve a `.file` response off the cooperative pool into a `StaticPlan`, BEFORE the middleware
    /// chain unwinds: stash it on `storage` (`ResolvedStaticPlanKey`) so `fileResponse` reuses it (one
    /// stat per request, not two) and record its real status in the `ResponseStatusBox` so observing
    /// middleware (`RequestLogging`/metrics) log the true 200/206/304/404/416. A no-op otherwise.
    func recordStaticStatus(
        _ content: ResponseContent, request: ServerRequest, storage: RequestStorage
    ) async {
        guard case .file(let root, let subpath, let contentType, let headers) = content else { return }
        let file = StaticFileRequest(
            root: root, subpath: subpath, contentType: contentType, headers: headers)
        let requestHeaders = request.headers
        let plan =
            (try? await offload.run {
                HTTPServer.planStaticFile(file: file, headers: requestHeaders)
            }) ?? .notFound
        storage[ResolvedStaticPlanKey.self] = plan
        storage[ResponseStatusKey.self]?.record(plan.statusCode)
    }

    /// Lowers a `.file` onto the engine response: 404 / 304 / 416 directly, or a 200/206 whose body
    /// is a `ResponseStream` reading bounded chunks from ONE held descriptor (TOCTOU-safe) off-pool.
    func fileResponse(
        _ file: StaticFileRequest, cache: CachePolicy, environment: ResponseEnvironment
    ) async -> ServerResponse {
        // Reuse the plan the route terminal already resolved (single stat); fall back to a fresh
        // resolution for direct callers that bypass the terminal (e.g. unit tests).
        let plan: StaticPlan
        if let cached = environment.storage[ResolvedStaticPlanKey.self] {
            plan = cached
        } else {
            plan =
                (try? await offload.run {
                    HTTPServer.planStaticFile(file: file, headers: HTTPFields())
                }) ?? .notFound
        }

        switch plan {
            case .notFound:
                return await finalize(
                    .plain(.notFound, "not found\n"), cache: .noStore, environment: environment)

            case .notModified(let etag, let lastModified):
                var headers = staticHeaders(cache: cache, environment: environment)
                headers.setValue(etag, for: .etag)
                headers.setValue(lastModified, for: .lastModified)
                mergeResponseHeaders(file.headers, into: &headers)
                return ServerResponse(HTTPResponse(status: .notModified, headerFields: headers))

            case .rangeNotSatisfiable(let totalSize):
                var headers = staticHeaders(cache: cache, environment: environment)
                headers.setValue("bytes */\(totalSize)", for: .contentRange)
                mergeResponseHeaders(file.headers, into: &headers)
                return ServerResponse(
                    HTTPResponse(status: .rangeNotSatisfiable, headerFields: headers))

            case .serve(
                let path, let partial, let etag, let lastModified, let encoding, let totalSize,
                let range):
                let serve = ResolvedServe(
                    path: path, partial: partial, etag: etag, lastModified: lastModified,
                    contentEncoding: encoding, totalSize: totalSize, range: range)
                return await serveResponse(serve, file: file, cache: cache, environment: environment)
        }
    }

    /// The `.serve` arm of ``fileResponse``: opens the ONE descriptor the whole response streams
    /// from (a mid-flight unlink/replace cannot swap the served bytes — the fd pins the inode), so a
    /// file that vanished between the plan's stat and this open collapses to 404.
    private func serveResponse(
        _ serve: ResolvedServe, file: StaticFileRequest, cache: CachePolicy,
        environment: ResponseEnvironment
    ) async -> ServerResponse {
        guard let descriptor = await openDescriptor(serve.path) else {
            return await finalize(
                .plain(.notFound, "not found\n"), cache: .noStore, environment: environment)
        }
        let start = serve.range?.lowerBound ?? 0
        let length = serve.range.map { $0.upperBound - $0.lowerBound + 1 } ?? serve.totalSize
        var headers = staticHeaders(cache: cache, environment: environment)
        headers.setValue(file.contentType, for: .contentType)
        headers.setValue(String(length), for: .contentLength)
        headers.setValue(serve.etag, for: .etag)
        headers.setValue(serve.lastModified, for: .lastModified)
        if let encoding = serve.contentEncoding {
            headers.setValue(encoding, for: .contentEncoding)
            headers.setValue("Accept-Encoding", for: .vary)
        }
        if let range = serve.range {
            headers.setValue(
                "bytes \(range.lowerBound)-\(range.upperBound)/\(serve.totalSize)",
                for: .contentRange)
        }
        mergeResponseHeaders(file.headers, into: &headers)
        let status: HTTPStatus = serve.partial ? .partialContent : .ok
        let head = HTTPResponse(status: status, headerFields: headers)
        if environment.isHead || length == 0 {
            // No body (HEAD / empty file / 0-length range): the preset Content-Length stands.
            descriptor.close()
            return ServerResponse(head)
        }
        let offload = offload
        return ServerResponse(
            head,
            stream: ResponseStream(contentLength: length) { writer in
                defer { descriptor.close() }
                let chunkSize = 256 * 1024
                var sent = 0
                while sent < length {
                    let offset = start + sent
                    let count = min(chunkSize, length - sent)
                    let chunk = try await offload.run {
                        HTTPServer.readChunk(fd: descriptor.descriptor, offset: offset, count: count)
                    }
                    guard let chunk, !chunk.isEmpty else {
                        // Truncated / changed underneath us: end the stream short — the engine
                        // closes the connection rather than under-deliver the Content-Length.
                        throw StaticStreamError.truncated
                    }
                    try await writer.write(chunk)
                    sent += chunk.count
                }
            })
    }

    /// The `.serve` case's payload, regrouped as one value so the serving arm stays within the
    /// parameter budget.
    private struct ResolvedServe {
        let path: String
        let partial: Bool
        let etag: String
        let lastModified: String
        let contentEncoding: String?
        let totalSize: Int
        let range: ClosedRange<Int>?
    }

    /// Opens `path` read-only on the offload pool, boxed for exactly-once close; `nil` on failure.
    private func openDescriptor(_ path: String) async -> FileDescriptorBox? {
        let opened = try? await offload.run { HTTPServer.openForReading(path) }
        guard let descriptor = opened ?? nil else { return nil }
        return FileDescriptorBox(descriptor: descriptor)
    }

    /// The headers every static response shares: the common envelope (cache-control, security set,
    /// request-id, connection) plus `Accept-Ranges: bytes` (range support is advertised on all).
    private func staticHeaders(
        cache: CachePolicy, environment: ResponseEnvironment
    ) -> HTTPFields {
        var headers = commonHeaders(cache: cache, environment: environment)
        headers.setValue("bytes", for: .acceptRanges)
        return headers
    }
}

/// A static stream that could not deliver its full advertised length (the file was truncated or
/// replaced mid-flight) — thrown so the engine tears the connection down instead of under-delivering.
enum StaticStreamError: Error {
    case truncated
}

extension HTTPServer {
    /// BLOCKING — runs on the offload pool. Canonicalizes + jails the path, requires a regular file,
    /// negotiates a precompressed `.br`/`.gz` sibling (compressible types, no `Range`), derives a strong
    /// size+mtime ETag, and decides 200 / 206 / 304 / 416 / 404 — WITHOUT reading the body (that streams
    /// later). Any failure collapses to 404 (no information leak about why).
    static func planStaticFile(file: StaticFileRequest, headers: HTTPFields) -> StaticPlan {
        let fileManager = FileManager.default
        let rootReal = URL(fileURLWithPath: file.root).standardizedFileURL.resolvingSymlinksInPath().path
        let identityReal =
            URL(fileURLWithPath: file.root + "/" + file.subpath)
            .standardizedFileURL.resolvingSymlinksInPath().path
        guard isInsideRoot(identityReal, root: rootReal),
            let identityAttrs = regularFileAttributes(fileManager, identityReal)
        else { return .notFound }

        // Defense in depth: refuse a hidden file — any RESOLVED path component under the root starting with
        // `.` (e.g. `.env`, `.git/config`) — even when reached via a hand-built `.file()` route. The DSL
        // `Static()` already rejects dotfiles, but making the engine itself the final gate means a bypassed
        // DSL can't leak one. (`.`/`..` are already neutralized by canonicalization + the jail; this targets
        // hidden NAMES, and the root's own dot-components are exempt — only the part below the root counts.)
        for segment in identityReal.dropFirst(rootReal.count).split(separator: "/") where segment.hasPrefix(".") {
            return .notFound
        }

        let rangeHeader = headers[.range]

        // Precompressed negotiation: only for compressible types and only without a Range (a range
        // request serves the identity bytes — ranges over the compressed stream are not offered).
        var servePath = identityReal
        var serveAttrs = identityAttrs
        var contentEncoding: String?
        let ext = MediaType.fileExtension(of: file.subpath)
        let compressible = ext.flatMap { MIMEDatabase.entry(forExtension: $0)?.compressible } ?? false
        if compressible, rangeHeader == nil {
            let accept = headers[.acceptEncoding] ?? ""
            for (token, suffix) in [("br", ".br"), ("gzip", ".gz")] where contentEncoding == nil {
                if AcceptEncoding.allows(accept, token),
                    let (path, attrs) = precompressedSibling(fileManager, identityReal, suffix, root: rootReal)
                {
                    servePath = path
                    serveAttrs = attrs
                    contentEncoding = token
                }
            }
        }

        let size = fileSize(serveAttrs)
        let mtime = modificationTime(serveAttrs)
        let etag = contentEncoding.map { "\"\(size)-\(mtime)-\($0)\"" } ?? "\"\(size)-\(mtime)\""
        let lastModified = HTTPDate.format(mtime)

        // Conditional GET: `If-None-Match` (the strong validator) takes precedence; only when it is absent
        // do we consult `If-Modified-Since` (whole-second mtime comparison). Either hit → 304.
        if let ifNoneMatch = headers[.ifNoneMatch] {
            if matchesIfNoneMatch(ifNoneMatch, etag) {
                return .notModified(etag: etag, lastModified: lastModified)
            }
        } else if let ifModifiedSince = headers[.ifModifiedSince].flatMap(HTTPDate.parse), mtime <= ifModifiedSince {
            return .notModified(etag: etag, lastModified: lastModified)
        }

        if let rangeHeader {
            switch parseByteRange(rangeHeader, totalSize: size) {
                case .satisfiable(let range):
                    return .serve(
                        absolutePath: servePath, partial: true, etag: etag, lastModified: lastModified,
                        contentEncoding: nil, totalSize: size, range: range)
                case .unsatisfiable:
                    return .rangeNotSatisfiable(totalSize: size)
                case .ignore:
                    break  // malformed / multi-range → serve the whole entity (200)
            }
        }

        return .serve(
            absolutePath: servePath, partial: false, etag: etag, lastModified: lastModified,
            contentEncoding: contentEncoding, totalSize: size, range: nil)
    }

    // MARK: - Blocking helpers (offload pool)

    private static func isInsideRoot(_ path: String, root: String) -> Bool {
        path == root || path.hasPrefix(root + "/")
    }

    private static func regularFileAttributes(_ fileManager: FileManager, _ path: String)
        -> [FileAttributeKey: Any]?
    {
        guard let attributes = try? fileManager.attributesOfItem(atPath: path),
            (attributes[.type] as? FileAttributeType) == .typeRegular
        else { return nil }
        return attributes
    }

    /// A `.br`/`.gz` sibling of `identityReal` if it exists, is a regular file, and is jailed in root.
    private static func precompressedSibling(
        _ fileManager: FileManager, _ identityReal: String, _ suffix: String, root: String
    ) -> (path: String, attributes: [FileAttributeKey: Any])? {
        let candidate =
            URL(fileURLWithPath: identityReal + suffix).standardizedFileURL.resolvingSymlinksInPath().path
        guard isInsideRoot(candidate, root: root),
            let attributes = regularFileAttributes(fileManager, candidate)
        else { return nil }
        return (candidate, attributes)
    }

    /// File size, extracted across platforms (`NSNumber` on Darwin, `Int`/`UInt64` on swift-foundation).
    private static func fileSize(_ attributes: [FileAttributeKey: Any]) -> Int {
        if let size = attributes[.size] as? Int { return size }
        if let size = attributes[.size] as? UInt64 { return Int(size) }
        if let size = attributes[.size] as? NSNumber { return size.intValue }
        return 0
    }

    /// Whole-second last-modified time (for the ETag).
    private static func modificationTime(_ attributes: [FileAttributeKey: Any]) -> Int {
        Int(((attributes[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0).rounded())
    }

    // MARK: - Held-descriptor file IO (TOCTOU-safe streaming)
    //
    // The static streamer opens ONE descriptor for the whole response and reads each chunk positionally
    // (`pread`) from it. `pread` carries the offset per call, so reads dispatched to different offload-pool
    // tasks share no seek state; the open fd pins the original inode, so an unlink/replace mid-stream
    // cannot swap the served bytes. The `unsafe` regions are the libc calls — the read buffer is owned by
    // the local `Array` for the duration of the call and bounded by `count`, and `fd` is a plain `Int32`
    // (Sendable) opened/closed by the single owner (`writeFile`'s `.serve` case, via `defer`).

    /// Open `path` read-only; `nil` on failure (e.g. the file vanished since the plan's stat). `O_NOFOLLOW`
    /// is defense-in-depth against a TOCTOU symlink swap: the plan only ever passes a symlink-RESOLVED,
    /// jailed path (a real asset's final component is never a symlink, and a symlinked deploy root is already
    /// resolved away), so only a final component that BECAME a symlink since the stat — an attacker racing a
    /// planted link to escape the root — makes the open fail (ELOOP), collapsing the response to 404.
    static func openForReading(_ path: String) -> Int32? {
        let fd = path.withCString { cString in unsafe open(cString, O_RDONLY | O_NOFOLLOW) }
        return fd >= 0 ? fd : nil
    }

    /// Close a descriptor opened by `openForReading` (best-effort; the result is irrelevant here).
    static func closeDescriptor(_ fd: Int32) {
        _ = close(fd)
    }

    /// One positional read of `[offset, offset+count)` from `fd`. Returns the bytes (short at EOF), `[]` at
    /// EOF, or `nil` on a read error — each ends the stream.
    static func readChunk(fd: Int32, offset: Int, count: Int) -> [UInt8]? {
        guard count > 0 else { return [] }
        var buffer = [UInt8](repeating: 0, count: count)
        let read = buffer.withUnsafeMutableBytes { raw in
            unsafe pread(fd, raw.baseAddress, count, off_t(offset))
        }
        guard read >= 0 else { return nil }
        if read < count { buffer.removeLast(count - read) }
        return read == 0 ? [] : buffer
    }

    private enum RangeOutcome {
        case satisfiable(ClosedRange<Int>)
        case unsatisfiable
        case ignore
    }

    /// Parses a single `bytes=` range against `totalSize` (RFC 9110). Multi-range / malformed → `.ignore`
    /// (serve the whole entity); a syntactically valid but out-of-bounds range → `.unsatisfiable` (416).
    private static func parseByteRange(_ header: String, totalSize: Int) -> RangeOutcome {
        guard let equals = header.firstIndex(of: "="), header[..<equals].trimmingCharacters(in: .whitespaces) == "bytes"
        else { return .ignore }
        let spec = header[header.index(after: equals)...].trimmingCharacters(in: .whitespaces)
        if spec.contains(",") { return .ignore }  // multi-range: not offered
        guard let dash = spec.firstIndex(of: "-") else { return .ignore }
        let startText = spec[..<dash]
        let endText = spec[spec.index(after: dash)...]
        guard totalSize > 0 else { return .unsatisfiable }

        if startText.isEmpty {
            // `-N`: the last N bytes.
            guard let suffix = Int(endText), suffix > 0 else { return .ignore }
            let start = max(0, totalSize - suffix)
            return .satisfiable(start ... (totalSize - 1))
        }
        guard let start = Int(startText), start >= 0 else { return .ignore }
        if start >= totalSize { return .unsatisfiable }
        if endText.isEmpty {
            return .satisfiable(start ... (totalSize - 1))  // `N-`: to the end
        }
        guard let end = Int(endText), end >= start else { return .ignore }
        return .satisfiable(start ... min(end, totalSize - 1))
    }
}
