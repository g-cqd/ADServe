// M4 static polish: HTTP-date formatting/parsing + Last-Modified / If-Modified-Since on static files.

import ADTestKit
import Foundation
import HTTPTypes
import Testing

@testable import ADServeCore

@Suite struct HTTPDateTests {
    @Test func formatsKnownEpochs() {
        #expect(HTTPDate.format(784_111_777) == "Sun, 06 Nov 1994 08:49:37 GMT")
        #expect(HTTPDate.format(0) == "Thu, 01 Jan 1970 00:00:00 GMT")
        #expect(HTTPDate.format(1_700_000_000) == "Tue, 14 Nov 2023 22:13:20 GMT")
    }

    @Test func parsesKnownDates() {
        #expect(HTTPDate.parse("Sun, 06 Nov 1994 08:49:37 GMT") == 784_111_777)
        #expect(HTTPDate.parse("Thu, 01 Jan 1970 00:00:00 GMT") == 0)
    }

    @Test func roundTrips() {
        for epoch in [0, 1, 784_111_777, 1_700_000_000, 2_000_000_000] {
            #expect(HTTPDate.parse(HTTPDate.format(epoch)) == epoch)
        }
    }

    @Test func rejectsMalformedInput() {
        #expect(HTTPDate.parse("not a date") == nil)
        #expect(HTTPDate.parse("") == nil)
        #expect(HTTPDate.parse("Sun, 06 Foo 1994 08:49:37 GMT") == nil)  // bad month
    }
}

@Suite struct LastModifiedTests {
    private func tempFile(_ name: String, _ contents: String) throws -> (root: String, cleanup: () -> Void) {
        let dir = TemporaryDirectory(prefix: "adserve-lastmod")
        try Data(contents.utf8).write(to: URL(fileURLWithPath: dir.file(name)))
        return (dir.path, dir.cleanup)
    }

    @Test func staticResponseCarriesLastModified() async throws {
        let (root, cleanup) = try tempFile("a.txt", "hello")
        defer { cleanup() }
        let routes = StubRoutes { _ in .file(root: root, subpath: "a.txt", contentType: "text/plain") }
        let response = try await Loopback.run(path: "/a.txt", routes: routes)
        #expect(response.hasPrefix("HTTP/1.1 200"))
        #expect(response.lowercased().contains("last-modified:"))
    }

    @Test func ifModifiedSinceMatchingGets304() async throws {
        let (root, cleanup) = try tempFile("a.txt", "hello")
        defer { cleanup() }
        let routes = StubRoutes { _ in .file(root: root, subpath: "a.txt", contentType: "text/plain") }
        let first = try await Loopback.run(path: "/a.txt", routes: routes)
        let lastModified = try #require(header(first, "last-modified"))
        let second = try await Loopback.run(
            path: "/a.txt", routes: routes, headers: [("If-Modified-Since", lastModified)])
        #expect(second.hasPrefix("HTTP/1.1 304"))
        #expect(second.lowercased().contains("last-modified:"))  // 304 still carries the validator
    }

    @Test func ifModifiedSinceWithAnOldDateGets200() async throws {
        let (root, cleanup) = try tempFile("a.txt", "hello")
        defer { cleanup() }
        let routes = StubRoutes { _ in .file(root: root, subpath: "a.txt", contentType: "text/plain") }
        let response = try await Loopback.run(
            path: "/a.txt", routes: routes,
            headers: [("If-Modified-Since", "Thu, 01 Jan 1970 00:00:00 GMT")])
        #expect(response.hasPrefix("HTTP/1.1 200"))  // the file is newer than the epoch
    }

    @Test func ifNoneMatchTakesPrecedenceOverIfModifiedSince() async throws {
        let (root, cleanup) = try tempFile("a.txt", "hello")
        defer { cleanup() }
        let routes = StubRoutes { _ in .file(root: root, subpath: "a.txt", contentType: "text/plain") }
        // A mismatching ETag must force 200 even though the (matching) If-Modified-Since alone would 304.
        let first = try await Loopback.run(path: "/a.txt", routes: routes)
        let lastModified = try #require(header(first, "last-modified"))
        let response = try await Loopback.run(
            path: "/a.txt", routes: routes,
            headers: [("If-None-Match", "\"stale-etag\""), ("If-Modified-Since", lastModified)])
        #expect(response.hasPrefix("HTTP/1.1 200"))
    }

    private func header(_ response: String, _ name: String) -> String? {
        for line in response.split(separator: "\r\n") {
            let parts = line.split(separator: ":", maxSplits: 1)
            if parts.count == 2, parts[0].lowercased() == name {
                return parts[1].trimmingCharacters(in: .whitespaces)
            }
        }
        return nil
    }
}
