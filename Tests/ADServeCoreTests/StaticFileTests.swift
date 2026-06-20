import Foundation
import HTTPTypes
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
