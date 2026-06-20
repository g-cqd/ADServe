import Foundation
import HTTPTypes
import Testing

@testable import ADServeCore

// Path-traversal regression matrix for the static-file jail (`isInsideRoot`, HTTPServerStatic.swift). The
// existing StaticFileServingTests cover `../` and a single symlink escape; these pin the two vectors they
// don't: the PREFIX-SIBLING escape (a resolved path that shares the root's string prefix but lives in a
// sibling dir — `<root>-evil/`), which only the `+ "/"` in `path.hasPrefix(root + "/")` rejects, and the
// PRECOMPRESSED-SIBLING jail (the `.br`/`.gz` negotiation path runs its own `isInsideRoot`). Each is
// mutation-resistant: dropping the `+ "/"` or the sibling jail re-opens the hole and fails the test.
@Suite struct StaticTraversalTests {
    private func makeTempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("adserve-traversal-\(UInt64.random(in: .min ... .max))")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    @Test func prefixSiblingDirectoryIsRejected() async throws {
        // root = <base>/jail; a sibling <base>/jail-evil shares the "…/jail" prefix but is OUTSIDE root.
        // Without the trailing slash in the jail check, ".../jail-evil/secret".hasPrefix(".../jail") is
        // TRUE and the secret leaks; the `+ "/"` makes it false → 404.
        let base = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: base) }
        let jail = base.appendingPathComponent("jail")
        let evil = base.appendingPathComponent("jail-evil")
        try FileManager.default.createDirectory(at: jail, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: evil, withIntermediateDirectories: true)
        try Data("TOPSECRET".utf8).write(to: evil.appendingPathComponent("secret.txt"))

        let routes = StubRoutes { _ in
            .file(root: jail.path, subpath: "../jail-evil/secret.txt", contentType: "text/plain")
        }
        let response = try await Loopback.run(path: "/x", routes: routes)
        #expect(response.hasPrefix("HTTP/1.1 404"))
        #expect(!response.contains("TOPSECRET"))  // the prefix-sibling secret is never served
    }

    @Test func precompressedSiblingSymlinkEscapeFallsBackToIdentity() async throws {
        // The identity file is in-root, but its `.br` sibling is a symlink pointing OUTSIDE root. The
        // precompressed-negotiation jail must reject the escaping sibling and serve the identity bytes —
        // never the symlink target.
        let root = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: root) }
        let secret = root.deletingLastPathComponent()
            .appendingPathComponent("evil-\(UInt64.random(in: .min ... .max)).br")
        try Data("ESCAPED-BR".utf8).write(to: secret)
        defer { try? FileManager.default.removeItem(at: secret) }
        try Data("IDENTITY-CSS".utf8).write(to: root.appendingPathComponent("app.css"))
        try FileManager.default.createSymbolicLink(
            at: root.appendingPathComponent("app.css.br"), withDestinationURL: secret)

        let routes = StubRoutes { _ in
            .file(root: root.path, subpath: "app.css", contentType: "text/css; charset=utf-8")
        }
        let response = try await Loopback.run(
            path: "/app.css", routes: routes, headers: [("Accept-Encoding", "br")])
        #expect(response.hasPrefix("HTTP/1.1 200"))
        #expect(!response.lowercased().contains("content-encoding: br"))  // escaping .br rejected
        #expect(response.contains("IDENTITY-CSS"))
        #expect(!response.contains("ESCAPED-BR"))  // the symlink target never served
    }

    @Test func absoluteSubpathStaysJailed() async throws {
        // An absolute-looking subpath (`root + "/" + "/etc/hosts"`) standardizes inside root, not to /etc.
        let root = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: root) }
        let routes = StubRoutes { _ in
            .file(root: root.path, subpath: "/etc/hosts", contentType: "text/plain")
        }
        let response = try await Loopback.run(path: "/x", routes: routes)
        #expect(response.hasPrefix("HTTP/1.1 404"))  // no file at <root>/etc/hosts; /etc/hosts not reached
    }
}
