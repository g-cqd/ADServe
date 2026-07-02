import Foundation
import HTTPCore
import Testing

@testable import ADServeCore

@Suite struct StaticFileServingTests {
    /// A fresh temp directory for one test (best-effort cleanup via the caller's `defer`).
    private func makeTempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("adserve-static-\(UInt64.random(in: .min ... .max))")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    @Test func servesAnExistingFileWithContentTypeAndETag() async throws {
        let root = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: root) }
        try Data("body{}".utf8).write(to: root.appendingPathComponent("app.css"))

        let routes = StubRoutes { _ in
            .file(root: root.path, subpath: "app.css", contentType: "text/css; charset=utf-8")
        }
        let response = try await Loopback.run(path: "/app.css", routes: routes)
        let lower = response.lowercased()
        #expect(response.hasPrefix("HTTP/1.1 200"))
        #expect(lower.contains("content-type: text/css; charset=utf-8"))
        #expect(lower.contains("etag:"))
        #expect(lower.contains("content-length: 6"))
        #expect(response.contains("body{}"))
    }

    @Test func missingFileIs404() async throws {
        let root = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: root) }
        let routes = StubRoutes { _ in
            .file(root: root.path, subpath: "nope.css", contentType: "text/css")
        }
        #expect(try await Loopback.run(path: "/nope.css", routes: routes).hasPrefix("HTTP/1.1 404"))
    }

    @Test func traversalSubpathIsJailedTo404() async throws {
        // Defense in depth: a subpath that smuggled `..` past PathTemplate is still rejected by the
        // engine's real-path jail (the resolved target is outside the resolved root).
        let root = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: root) }
        let secret = root.deletingLastPathComponent()
            .appendingPathComponent("secret-\(UInt64.random(in: .min ... .max)).txt")
        try Data("TOPSECRET".utf8).write(to: secret)
        defer { try? FileManager.default.removeItem(at: secret) }

        let routes = StubRoutes { _ in
            .file(root: root.path, subpath: "../" + secret.lastPathComponent, contentType: "text/plain")
        }
        let response = try await Loopback.run(path: "/x", routes: routes)
        #expect(response.hasPrefix("HTTP/1.1 404"))
        #expect(!response.contains("TOPSECRET"))  // never served
    }

    @Test func symlinkEscapeIsRejected() async throws {
        let root = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: root) }
        let secret = root.deletingLastPathComponent()
            .appendingPathComponent("secret-\(UInt64.random(in: .min ... .max)).txt")
        try Data("TOPSECRET".utf8).write(to: secret)
        defer { try? FileManager.default.removeItem(at: secret) }
        // A symlink INSIDE root pointing OUTSIDE root — the primary threat PathTemplate cannot catch.
        let link = root.appendingPathComponent("link.txt")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: secret)

        let routes = StubRoutes { _ in
            .file(root: root.path, subpath: "link.txt", contentType: "text/plain")
        }
        let response = try await Loopback.run(path: "/link.txt", routes: routes)
        #expect(response.hasPrefix("HTTP/1.1 404"))
        #expect(!response.contains("TOPSECRET"))
    }

    @Test func conditionalRequestGets304() async throws {
        let root = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: root) }
        try Data("x".utf8).write(to: root.appendingPathComponent("a.js"))
        let routes = StubRoutes { _ in
            .file(root: root.path, subpath: "a.js", contentType: "text/javascript")
        }
        // First request reads the ETag; the conditional second request gets 304 with no body.
        let first = try await Loopback.run(path: "/a.js", routes: routes)
        guard let etag = staticTestHeader(first, "etag") else {
            Issue.record("expected an ETag on the first response")
            return
        }
        let second = try await Loopback.run(
            path: "/a.js", routes: routes, headers: [("If-None-Match", etag)])
        #expect(second.hasPrefix("HTTP/1.1 304"))
    }

    // MARK: - B1: size in the ETag

    @Test func etagIncludesSizeSoDifferentlySizedFilesDiffer() async throws {
        let root = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: root) }
        try Data("short".utf8).write(to: root.appendingPathComponent("a.txt"))
        try Data(String(repeating: "x", count: 9999).utf8).write(to: root.appendingPathComponent("b.txt"))
        let routesA = StubRoutes { _ in .file(root: root.path, subpath: "a.txt", contentType: "text/plain") }
        let routesB = StubRoutes { _ in .file(root: root.path, subpath: "b.txt", contentType: "text/plain") }
        let etagA = staticTestHeader(try await Loopback.run(path: "/a.txt", routes: routesA), "etag")
        let etagB = staticTestHeader(try await Loopback.run(path: "/b.txt", routes: routesB), "etag")
        #expect(etagA != nil)
        #expect(etagA != etagB)  // size is part of the ETag
    }

    // MARK: - B3: Range / 206 / 416

    @Test func acceptRangesIsAdvertisedAndARangeRequestGets206() async throws {
        let root = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: root) }
        try Data("0123456789".utf8).write(to: root.appendingPathComponent("d.txt"))
        let routes = StubRoutes { _ in .file(root: root.path, subpath: "d.txt", contentType: "text/plain") }
        let full = try await Loopback.run(path: "/d.txt", routes: routes)
        #expect(full.lowercased().contains("accept-ranges: bytes"))

        let partial = try await Loopback.run(
            path: "/d.txt", routes: routes, headers: [("Range", "bytes=0-3")])
        let lower = partial.lowercased()
        #expect(partial.hasPrefix("HTTP/1.1 206"))
        #expect(lower.contains("content-range: bytes 0-3/10"))
        #expect(lower.contains("content-length: 4"))
        #expect(!partial.contains("456789"))  // only the requested slice, not the rest
    }

    @Test func unsatisfiableRangeGets416() async throws {
        let root = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: root) }
        try Data("0123456789".utf8).write(to: root.appendingPathComponent("d.txt"))
        let routes = StubRoutes { _ in .file(root: root.path, subpath: "d.txt", contentType: "text/plain") }
        let response = try await Loopback.run(
            path: "/d.txt", routes: routes, headers: [("Range", "bytes=100-200")])
        #expect(response.hasPrefix("HTTP/1.1 416"))
        #expect(response.lowercased().contains("content-range: bytes */10"))
    }

    // MARK: - B2: precompressed variants

    @Test func precompressedBrotliSiblingIsServedWhenAcceptable() async throws {
        let root = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: root) }
        try Data("IDENTITY-CSS".utf8).write(to: root.appendingPathComponent("app.css"))
        try Data("BROTLI-BYTES".utf8).write(to: root.appendingPathComponent("app.css.br"))
        let routes = StubRoutes { _ in
            .file(root: root.path, subpath: "app.css", contentType: "text/css; charset=utf-8")
        }
        let compressed = try await Loopback.run(
            path: "/app.css", routes: routes, headers: [("Accept-Encoding", "br")])
        let lowerC = compressed.lowercased()
        #expect(lowerC.contains("content-encoding: br"))
        #expect(lowerC.contains("vary: accept-encoding"))
        #expect(lowerC.contains("content-type: text/css; charset=utf-8"))  // the identity type
        #expect(compressed.contains("BROTLI-BYTES"))
        #expect(!compressed.contains("IDENTITY-CSS"))

        let identity = try await Loopback.run(path: "/app.css", routes: routes)
        #expect(!identity.lowercased().contains("content-encoding:"))
        #expect(identity.contains("IDENTITY-CSS"))
    }

    @Test func incompressibleTypeIsNeverServedPrecompressed() async throws {
        let root = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: root) }
        try Data("PNG-IDENTITY".utf8).write(to: root.appendingPathComponent("img.png"))
        try Data("PNG-BR".utf8).write(to: root.appendingPathComponent("img.png.br"))
        let routes = StubRoutes { _ in .file(root: root.path, subpath: "img.png", contentType: "image/png") }
        // png is not compressible (mime-db), so the .br sibling is ignored even with Accept-Encoding: br.
        let response = try await Loopback.run(
            path: "/img.png", routes: routes, headers: [("Accept-Encoding", "br")])
        #expect(!response.lowercased().contains("content-encoding:"))
        #expect(response.contains("PNG-IDENTITY"))
    }

    // MARK: - B4: chunked streaming of large files

    @Test func largeFileStreamsAcrossChunksIntact() async throws {
        let root = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: root) }
        // > 256 KiB so it spans multiple read chunks; a tail marker proves the last chunk arrived.
        let body = String(repeating: "A", count: 600_000) + "TAIL-MARKER"
        try Data(body.utf8).write(to: root.appendingPathComponent("big.txt"))
        let routes = StubRoutes { _ in .file(root: root.path, subpath: "big.txt", contentType: "text/plain") }
        let response = try await Loopback.run(path: "/big.txt", routes: routes)
        #expect(response.hasPrefix("HTTP/1.1 200"))
        #expect(response.lowercased().contains("content-length: \(body.utf8.count)"))
        #expect(response.contains("TAIL-MARKER"))  // the final chunk streamed intact
    }
}

/// Reads one header value out of a raw HTTP/1.1 response (case-insensitive name).
private func staticTestHeader(_ response: String, _ name: String) -> String? {
    for line in response.split(separator: "\r\n") {
        let parts = line.split(separator: ":", maxSplits: 1)
        if parts.count == 2, parts[0].lowercased() == name {
            return parts[1].trimmingCharacters(in: .whitespaces)
        }
    }
    return nil
}
