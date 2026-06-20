// Guarded static-asset serving (adserve-requirements #4). The blocking jail/stat/read run on the
// engine's NIOThreadPool (off the event loop) via Foundation; the engine then writes 200 (the bytes),
// 304 (If-None-Match), or 404. The path is canonicalized with `standardizedFileURL` +
// `resolvingSymlinksInPath`, so both `..` (already rejected upstream by PathTemplate) and symlink
// escape are caught — the resolved target must sit inside the resolved root.

import Foundation
import HTTPTypes
import NIOCore
import NIOHTTPTypes
import NIOPosix

/// The validated descriptor the DSL `Static(_:root:)` produces: the root dir, the request's relative
/// subpath (already percent-decoded + `..`-rejected by `PathTemplate`, dotfiles rejected by the
/// handler), the allow-listed content-type, and any response-middleware header decoration.
struct StaticFileRequest {
    let root: String
    let subpath: String
    let contentType: String
    let headers: HTTPFields
}

/// The outcome of resolving + reading a static file off the event loop. `Sendable` so it can cross back
/// from the offload-pool thread.
private enum StaticResolution: Sendable {
    case notFound
    case notModified(etag: String)
    case ok(bytes: [UInt8], etag: String)
}

extension HTTPServer {
    func writeFile(
        _ file: StaticFileRequest, cache: CachePolicy, requestID: String, exchange: RequestExchange
    ) async throws {
        let keepAlive = isKeepAlive(exchange.head)
        let suppressBody = exchange.head.method == .head
        let ifNoneMatch = exchange.head.headerFields[.ifNoneMatch]

        // Resolve + read on the offload pool — blocking Foundation I/O must not touch the event loop.
        let resolution =
            (try? await exchange.threadPool.runIfActive {
                Self.resolveStaticFile(root: file.root, subpath: file.subpath, ifNoneMatch: ifNoneMatch)
            }) ?? .notFound

        switch resolution {
            case .notFound:
                try await write(
                    .plain(.notFound, "not found\n"), cache: .noStore, requestID: requestID,
                    keepAlive: keepAlive, suppressBody: suppressBody, exchange: exchange)
            case .notModified(let etag):
                var headers = commonHeaders(
                    cache: cache, requestID: requestID, keepAlive: keepAlive, isHTTP2: exchange.isHTTP2)
                headers[.eTag] = etag
                for field in file.headers { headers[field.name] = field.value }
                try await exchange.outbound.write(
                    .head(HTTPResponse(status: .notModified, headerFields: headers)))
                try await exchange.outbound.write(.end(nil))
            case .ok(let bytes, let etag):
                var headers = commonHeaders(
                    cache: cache, requestID: requestID, keepAlive: keepAlive, isHTTP2: exchange.isHTTP2)
                headers[.contentType] = file.contentType
                headers[.contentLength] = String(bytes.count)
                headers[.eTag] = etag
                for field in file.headers { headers[field.name] = field.value }
                try await exchange.outbound.write(.head(HTTPResponse(status: .ok, headerFields: headers)))
                if !suppressBody && !bytes.isEmpty {
                    var buffer = exchange.allocator.buffer(capacity: bytes.count)
                    buffer.writeBytes(bytes)
                    try await exchange.outbound.write(.body(buffer))
                }
                try await exchange.outbound.write(.end(nil))
        }
    }

    /// BLOCKING — runs on the offload pool. Canonicalizes + jails the path (real-path resolution
    /// defeats `..` and symlink escape), requires a regular file, derives an mtime ETag, and reads the
    /// bytes (unless `If-None-Match` already matches → 304). Any failure collapses to 404 — no
    /// information leak about why (existence, type, permission).
    private static func resolveStaticFile(root: String, subpath: String, ifNoneMatch: String?)
        -> StaticResolution
    {
        let fileManager = FileManager.default
        // Canonicalize BOTH root and target (resolve `..` and every symlink), then jail: the target's
        // real path must equal root or sit beneath `root/`. A symlink inside root pointing outside
        // resolves to an out-of-root real path and is rejected here.
        let rootReal = URL(fileURLWithPath: root).standardizedFileURL.resolvingSymlinksInPath().path
        let targetReal =
            URL(fileURLWithPath: root + "/" + subpath)
            .standardizedFileURL.resolvingSymlinksInPath().path
        guard targetReal == rootReal || targetReal.hasPrefix(rootReal + "/") else { return .notFound }

        // Must exist and be a regular file (not a directory / device / fifo).
        guard let attributes = try? fileManager.attributesOfItem(atPath: targetReal),
            (attributes[.type] as? FileAttributeType) == .typeRegular
        else { return .notFound }

        // ETag keyed on last-modified (changes on rebuild). `modificationDate` is a `Date`
        // cross-platform, sidestepping the NSNumber/Int size-attribute ambiguity.
        let mtime = (attributes[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0
        let etag = "\"\(Int(mtime.rounded()))\""
        if let ifNoneMatch, matchesIfNoneMatch(ifNoneMatch, etag) { return .notModified(etag: etag) }

        guard let data = try? Data(contentsOf: URL(fileURLWithPath: targetReal)) else { return .notFound }
        return .ok(bytes: [UInt8](data), etag: etag)
    }
}
