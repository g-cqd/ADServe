// Guarded static-asset serving (adserve-requirements #4 + the hardening round). The blocking
// jail/stat/range/encoding decision runs on the engine's NIOThreadPool (off the event loop) and returns
// a PLAN; the engine then streams the chosen file (or byte range) back in bounded chunks — also off the
// loop — writing each on the loop (implicit back-pressure). The path is canonicalized with
// `standardizedFileURL` + `resolvingSymlinksInPath`, so `..` (already rejected upstream by PathTemplate)
// AND symlink escape are caught — every served path (identity or `.br`/`.gz` sibling) must stay inside
// the resolved root.
//
// Hardening: a strong size+mtime ETag (B1); precompressed `.br`/`.gz` negotiation by `Accept-Encoding`
// for compressible types (B2); HTTP `Range`/206 + 416 (B3); and chunked streaming so even a large file
// never materializes whole (B4).

import Foundation
import HTTPTypes
import NIOCore
import NIOHTTPTypes
import NIOPosix

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

// Header names not provided as `HTTPField.Name` statics by swift-http-types.
private let rangeName = HTTPField.Name("range")!
private let acceptRangesName = HTTPField.Name("accept-ranges")!
private let contentRangeName = HTTPField.Name("content-range")!
private let contentEncodingName = HTTPField.Name("content-encoding")!
private let varyName = HTTPField.Name("vary")!

extension HTTPServer {
    /// Resolve a `.file` response off the event loop into a `StaticPlan`, BEFORE the middleware chain
    /// unwinds: stash it on `storage` (`ResolvedStaticPlanKey`) so `writeFile` reuses it (one stat per
    /// request, not two) and record its real status in the `ResponseStatusBox` so observing middleware
    /// (`RequestLogging`/metrics) log the true 200/206/304/404/416. A no-op for non-`.file` content.
    func recordStaticStatus(
        _ content: ResponseContent, request: ServerRequest, storage: RequestStorage,
        threadPool: NIOThreadPool
    ) async {
        guard case .file(let root, let subpath, let contentType, let headers) = content else { return }
        let file = StaticFileRequest(
            root: root, subpath: subpath, contentType: contentType, headers: headers)
        let plan =
            (try? await threadPool.runIfActive {
                Self.planStaticFile(file: file, headers: request.headers)
            }) ?? .notFound
        storage[ResolvedStaticPlanKey.self] = plan
        storage[ResponseStatusKey.self]?.record(plan.statusCode)
    }

    func writeFile(
        _ file: StaticFileRequest, cache: CachePolicy, requestID: String, exchange: RequestExchange
    ) async throws {
        let head = exchange.head
        let keepAlive = isKeepAlive(head)
        let suppressBody = head.method == .head

        // Reuse the plan the route terminal already resolved (single stat); fall back to a fresh
        // resolution for direct `write` callers that bypass the terminal (e.g. unit tests).
        let plan: StaticPlan
        if let cached = exchange.storage[ResolvedStaticPlanKey.self] {
            plan = cached
        } else {
            plan =
                (try? await exchange.threadPool.runIfActive {
                    Self.planStaticFile(file: file, headers: head.headerFields)
                }) ?? .notFound
        }

        switch plan {
            case .notFound:
                try await write(
                    .plain(.notFound, "not found\n"), cache: .noStore, requestID: requestID,
                    keepAlive: keepAlive, suppressBody: suppressBody, exchange: exchange)

            case .notModified(let etag, let lastModified):
                var headers = staticHeaders(
                    cache: cache, requestID: requestID, keepAlive: keepAlive, exchange: exchange)
                headers[.eTag] = etag
                headers[.lastModified] = lastModified
                mergeResponseHeaders(file.headers, into: &headers)
                try await exchange.outbound.write(
                    contentsOf: [.head(HTTPResponse(status: .notModified, headerFields: headers)), .end(nil)])

            case .rangeNotSatisfiable(let totalSize):
                var headers = staticHeaders(
                    cache: cache, requestID: requestID, keepAlive: keepAlive, exchange: exchange)
                headers[contentRangeName] = "bytes */\(totalSize)"
                mergeResponseHeaders(file.headers, into: &headers)
                let responseHead = HTTPResponse(status: HTTPResponse.Status(code: 416), headerFields: headers)
                try await exchange.outbound.write(contentsOf: [.head(responseHead), .end(nil)])

            case .serve(let path, let partial, let etag, let lastModified, let encoding, let totalSize, let range):
                // Open the file ONCE and stream every chunk from this single descriptor: a mid-flight
                // unlink/replace can no longer swap the bytes served (the open fd pins the original inode),
                // and the prior re-open-per-chunk (a fresh TOCTOU window each chunk) is gone. A file that
                // vanished between the plan's stat and this open collapses to 404.
                guard let fd = Self.openForReading(path) else {
                    try await write(
                        .plain(.notFound, "not found\n"), cache: .noStore, requestID: requestID,
                        keepAlive: keepAlive, suppressBody: suppressBody, exchange: exchange)
                    return
                }
                defer { Self.closeDescriptor(fd) }
                let start = range?.lowerBound ?? 0
                let length = range.map { $0.upperBound - $0.lowerBound + 1 } ?? totalSize
                var headers = staticHeaders(
                    cache: cache, requestID: requestID, keepAlive: keepAlive, exchange: exchange)
                headers[.contentType] = file.contentType
                headers[.contentLength] = String(length)
                headers[.eTag] = etag
                headers[.lastModified] = lastModified
                if let encoding {
                    headers[contentEncodingName] = encoding
                    headers[varyName] = "Accept-Encoding"
                }
                if let range {
                    headers[contentRangeName] = "bytes \(range.lowerBound)-\(range.upperBound)/\(totalSize)"
                }
                mergeResponseHeaders(file.headers, into: &headers)
                let status = partial ? HTTPResponse.Status(code: 206) : .ok
                let responseHead = HTTPResponse(status: status, headerFields: headers)
                if suppressBody || length == 0 {
                    // No body (HEAD / empty file / 0-length range): head + end in ONE flush.
                    try await exchange.outbound.write(contentsOf: [.head(responseHead), .end(nil)])
                } else {
                    try await streamFileBody(
                        head: responseHead, fd: fd, start: start, length: length, exchange: exchange)
                }
        }
    }

    /// The headers every static response shares: the common envelope (cache-control, security set,
    /// request-id, connection) plus `Accept-Ranges: bytes` (range support is advertised on all of them).
    private func staticHeaders(
        cache: CachePolicy, requestID: String, keepAlive: Bool, exchange: RequestExchange
    ) -> HTTPFields {
        var headers = commonHeaders(
            cache: cache, requestID: requestID, keepAlive: keepAlive, isHTTP2: exchange.isHTTP2)
        headers[acceptRangesName] = "bytes"
        return headers
    }

    /// Streams `[start, start+length)` of the file in bounded chunks: each chunk is read off the event
    /// loop (NIOThreadPool) and written on it (back-pressure implicit) — so even a large file never
    /// materializes whole. The response HEAD rides along with the first body chunk in one batched write,
    /// NEVER flushed on its own: a lone head reaches `HTTPResponseCompressor` before any body, so the
    /// compressor cannot recompute `Content-Length` for the compressed bytes and emits the original
    /// (identity) length — a gzip-accepting client (every browser) then blocks waiting for bytes that
    /// never arrive, and the response hangs until the idle timeout fires. Batching lets the compressor
    /// switch the response to chunked (when it compresses) or pass the head through with its identity
    /// `Content-Length` intact (when it does not). A short/failed read ends the body (the connection
    /// drops without a clean end).
    private func streamFileBody(
        head: HTTPResponse, fd: Int32, start: Int, length: Int, exchange: RequestExchange
    ) async throws {
        let chunkSize = 256 * 1024
        var sent = 0
        var headPending = true
        while sent < length {
            let offset = start + sent
            let count = min(chunkSize, length - sent)
            let chunk = try await exchange.threadPool.runIfActive {
                Self.readChunk(fd: fd, offset: offset, count: count)
            }
            guard let chunk, !chunk.isEmpty else { break }  // truncated / changed underneath us
            var buffer = exchange.allocator.buffer(capacity: chunk.count)
            buffer.writeBytes(chunk)
            if headPending {
                try await exchange.outbound.write(contentsOf: [.head(head), .body(buffer)])
                headPending = false
            } else {
                try await exchange.outbound.write(.body(buffer))
            }
            sent += chunk.count
        }
        if headPending {
            // The first read yielded nothing (file truncated/vanished mid-flight): still emit the head,
            // batched with the end, so the exchange terminates rather than dangling.
            try await exchange.outbound.write(contentsOf: [.head(head), .end(nil)])
        } else {
            try await exchange.outbound.write(.end(nil))
        }
    }

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

        let rangeHeader = headers[rangeName]

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
                if acceptsEncoding(accept, token),
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

    /// True if `acceptEncoding` permits `token` (present and not explicitly `;q=0`).
    private static func acceptsEncoding(_ acceptEncoding: String, _ token: String) -> Bool {
        for part in acceptEncoding.lowercased().split(separator: ",") {
            let fields = part.split(separator: ";")
            guard let name = fields.first?.trimmingCharacters(in: .whitespaces), name == token || name == "*"
            else { continue }
            let zeroQ = fields.dropFirst()
                .contains {
                    $0.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: " ", with: "") == "q=0"
                }
            if !zeroQ { return true }
        }
        return false
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
