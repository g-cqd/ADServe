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

/// The validated descriptor the DSL `Static(_:root:)` produces.
struct StaticFileRequest {
    let root: String
    let subpath: String
    let contentType: String
    let headers: HTTPFields
}

/// The off-loop resolution: which file to read, with what status/range/encoding, or a terminal status.
/// `Sendable` so it can cross back from the offload-pool thread.
private enum StaticPlan: Sendable {
    case notFound
    case notModified(etag: String)
    case rangeNotSatisfiable(totalSize: Int)
    /// Serve `absolutePath` (identity or a `.br`/`.gz` sibling). `range` non-nil ⇒ 206 partial content.
    case serve(
        absolutePath: String, partial: Bool, etag: String, contentEncoding: String?, totalSize: Int,
        range: ClosedRange<Int>?)
}

// Header names not provided as `HTTPField.Name` statics by swift-http-types.
private let rangeName = HTTPField.Name("range")!
private let acceptRangesName = HTTPField.Name("accept-ranges")!
private let contentRangeName = HTTPField.Name("content-range")!
private let contentEncodingName = HTTPField.Name("content-encoding")!
private let varyName = HTTPField.Name("vary")!

extension HTTPServer {
    func writeFile(
        _ file: StaticFileRequest, cache: CachePolicy, requestID: String, exchange: RequestExchange
    ) async throws {
        let head = exchange.head
        let keepAlive = isKeepAlive(head)
        let suppressBody = head.method == .head

        let plan =
            (try? await exchange.threadPool.runIfActive { Self.planStaticFile(file: file, head: head) })
            ?? .notFound

        switch plan {
            case .notFound:
                try await write(
                    .plain(.notFound, "not found\n"), cache: .noStore, requestID: requestID,
                    keepAlive: keepAlive, suppressBody: suppressBody, exchange: exchange)

            case .notModified(let etag):
                var headers = staticHeaders(
                    cache: cache, requestID: requestID, keepAlive: keepAlive, exchange: exchange)
                headers[.eTag] = etag
                for field in file.headers { headers[field.name] = field.value }
                try await exchange.outbound.write(.head(HTTPResponse(status: .notModified, headerFields: headers)))
                try await exchange.outbound.write(.end(nil))

            case .rangeNotSatisfiable(let totalSize):
                var headers = staticHeaders(
                    cache: cache, requestID: requestID, keepAlive: keepAlive, exchange: exchange)
                headers[contentRangeName] = "bytes */\(totalSize)"
                for field in file.headers { headers[field.name] = field.value }
                try await exchange.outbound.write(
                    .head(HTTPResponse(status: HTTPResponse.Status(code: 416), headerFields: headers)))
                try await exchange.outbound.write(.end(nil))

            case .serve(let path, let partial, let etag, let encoding, let totalSize, let range):
                let start = range?.lowerBound ?? 0
                let length = range.map { $0.upperBound - $0.lowerBound + 1 } ?? totalSize
                var headers = staticHeaders(
                    cache: cache, requestID: requestID, keepAlive: keepAlive, exchange: exchange)
                headers[.contentType] = file.contentType
                headers[.contentLength] = String(length)
                headers[.eTag] = etag
                if let encoding {
                    headers[contentEncodingName] = encoding
                    headers[varyName] = "Accept-Encoding"
                }
                if let range {
                    headers[contentRangeName] = "bytes \(range.lowerBound)-\(range.upperBound)/\(totalSize)"
                }
                for field in file.headers { headers[field.name] = field.value }
                let status = partial ? HTTPResponse.Status(code: 206) : .ok
                try await exchange.outbound.write(.head(HTTPResponse(status: status, headerFields: headers)))
                if !suppressBody && length > 0 {
                    try await streamFileBody(path: path, start: start, length: length, exchange: exchange)
                }
                try await exchange.outbound.write(.end(nil))
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
    /// materializes whole. A short/failed read ends the body (the connection drops without a clean end).
    private func streamFileBody(
        path: String, start: Int, length: Int, exchange: RequestExchange
    ) async throws {
        let chunkSize = 256 * 1024
        var sent = 0
        while sent < length {
            let offset = start + sent
            let count = min(chunkSize, length - sent)
            let chunk = try await exchange.threadPool.runIfActive {
                Self.readChunk(path: path, offset: offset, count: count)
            }
            guard let chunk, !chunk.isEmpty else { break }  // truncated / changed underneath us
            var buffer = exchange.allocator.buffer(capacity: chunk.count)
            buffer.writeBytes(chunk)
            try await exchange.outbound.write(.body(buffer))
            sent += chunk.count
        }
    }

    /// BLOCKING — runs on the offload pool. Canonicalizes + jails the path, requires a regular file,
    /// negotiates a precompressed `.br`/`.gz` sibling (compressible types, no `Range`), derives a strong
    /// size+mtime ETag, and decides 200 / 206 / 304 / 416 / 404 — WITHOUT reading the body (that streams
    /// later). Any failure collapses to 404 (no information leak about why).
    private static func planStaticFile(file: StaticFileRequest, head: HTTPRequest) -> StaticPlan {
        let fileManager = FileManager.default
        let rootReal = URL(fileURLWithPath: file.root).standardizedFileURL.resolvingSymlinksInPath().path
        let identityReal =
            URL(fileURLWithPath: file.root + "/" + file.subpath)
            .standardizedFileURL.resolvingSymlinksInPath().path
        guard isInsideRoot(identityReal, root: rootReal),
            let identityAttrs = regularFileAttributes(fileManager, identityReal)
        else { return .notFound }

        let rangeHeader = head.headerFields[rangeName]

        // Precompressed negotiation: only for compressible types and only without a Range (a range
        // request serves the identity bytes — ranges over the compressed stream are not offered).
        var servePath = identityReal
        var serveAttrs = identityAttrs
        var contentEncoding: String?
        let ext = MediaType.fileExtension(of: file.subpath)
        let compressible = ext.flatMap { MIMEDatabase.entry(forExtension: $0)?.compressible } ?? false
        if compressible, rangeHeader == nil {
            let accept = head.headerFields[.acceptEncoding] ?? ""
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

        if let ifNoneMatch = head.headerFields[.ifNoneMatch], matchesIfNoneMatch(ifNoneMatch, etag) {
            return .notModified(etag: etag)
        }

        if let rangeHeader {
            switch parseByteRange(rangeHeader, totalSize: size) {
                case .satisfiable(let range):
                    return .serve(
                        absolutePath: servePath, partial: true, etag: etag, contentEncoding: nil,
                        totalSize: size, range: range)
                case .unsatisfiable:
                    return .rangeNotSatisfiable(totalSize: size)
                case .ignore:
                    break  // malformed / multi-range → serve the whole entity (200)
            }
        }

        return .serve(
            absolutePath: servePath, partial: false, etag: etag, contentEncoding: contentEncoding,
            totalSize: size, range: nil)
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

    /// One chunk `[offset, offset+count)`; `nil`/empty on any failure (ends the stream).
    private static func readChunk(path: String, offset: Int, count: Int) -> [UInt8]? {
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? handle.close() }
        do {
            try handle.seek(toOffset: UInt64(offset))
            return try handle.read(upToCount: count).map { [UInt8]($0) }
        } catch {
            return nil
        }
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
