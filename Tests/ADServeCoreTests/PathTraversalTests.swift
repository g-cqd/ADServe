// Path-traversal / static-jail SECURITY MATRIX for the guarded static-asset path.
//
// The defense is layered across TWO modules:
//   • The DSL `Static()` + `PathTemplate` (Sources/ADServeDSL/ServerDSL.swift / PathTemplate.swift) — the
//     FIRST line: it percent-decodes each path segment and REJECTS a decoded `.`/`..`/`/`, rejects any
//     dotfile segment, and serves only allow-listed extensions. That layer is exercised by the DSL test
//     target (this `ADServeCoreTests` target does not — and cannot — link ADServeDSL).
//   • The ENGINE jail in Sources/ADServeCore/HTTPServerStatic.swift (`planStaticFile`, `isInsideRoot`,
//     `precompressedSibling`, `standardizedFileURL`/`resolvingSymlinksInPath`) — the SECOND, defense-in-
//     depth line: every resolved real path (identity OR a `.br`/`.gz` sibling) must stay inside the
//     resolved root, so `..` AND symlink escape are caught even if a subpath smuggled past the DSL.
//
// This matrix drives the ENGINE jail directly: a `StubRoutes` returns a crafted
// `.file(root:subpath:contentType:)` and the assertions read the RAW HTTP/1.1 response (exact status +
// exact body presence), so a mutation that widens the jail (drops the `+ "/"`, skips the sibling jail,
// stops resolving symlinks) flips a 404→200 / makes an escaped payload appear and FAILS the test. Where a
// vector's true guard is the DSL layer (encoded `%2e%2e`, dotfiles), the test locks what the ENGINE alone
// does with those bytes and the comment states which layer owns the rejection — so the security contract
// is pinned end-to-end and the module boundary is explicit.

import ADTestKit
import Foundation
import HTTPCore
import Testing

@testable import ADServeCore

@Suite struct PathTraversalTests {
    // A unique out-of-root sentinel name (so a stray match can only be THIS test's file, never ambient).
    private func sentinelName(_ ext: String) -> String {
        "escaped-\(UInt64.random(in: .min ... .max)).\(ext)"
    }

    // MARK: - 1. Precompressed `.br`/`.gz` SIBLING that is a SYMLINK pointing OUTSIDE root

    @Test func precompressedGzipSiblingSymlinkOutOfRootIsNotServed() async throws {
        // root/app.css is a legit in-root identity file; root/app.css.gz is a SYMLINK to an out-of-root
        // payload. With `Accept-Encoding: gzip` the negotiator considers the `.gz` sibling — but
        // `precompressedSibling`'s own `isInsideRoot` on the RESOLVED (symlink-followed) path must reject
        // it, so the response falls back to identity 200 and the escaped bytes are NEVER returned.
        //
        // `compression: false` disables the engine's on-the-fly `HTTPResponseCompressor`: with it enabled,
        // a `gzip`-accepting client makes the compressor gzip the legitimate IDENTITY body itself (emitting
        // `Content-Encoding: gzip` over the SAFE bytes) — which would mask whether the precompressed-sibling
        // jail held. Disabled, any `Content-Encoding: gzip` could ONLY come from the engine serving the
        // (escaping) `.gz` sibling, so its absence + the readable identity body is an unambiguous PASS.
        let root = TemporaryDirectory(prefix: "adserve-traversal-precomp-gz")
        defer { root.cleanup() }
        let outOfRoot = TemporaryDirectory(prefix: "adserve-traversal-precomp-gz-evil")
        defer { outOfRoot.cleanup() }

        let escaped = outOfRoot.file(sentinelName("gz"))
        try Data("ESCAPED-GZIP-PAYLOAD".utf8).write(to: URL(fileURLWithPath: escaped))
        try Data("IDENTITY-CSS-BYTES".utf8).write(to: URL(fileURLWithPath: root.file("app.css")))
        try FileManager.default.createSymbolicLink(
            atPath: root.file("app.css.gz"), withDestinationPath: escaped)

        let routes = StubRoutes { _ in
            .file(root: root.path, subpath: "app.css", contentType: "text/css; charset=utf-8")
        }
        let response = try await Loopback.run(
            path: "/app.css", routes: routes, headers: [("Accept-Encoding", "gzip")], compression: false)

        #expect(response.hasPrefix("HTTP/1.1 200"))
        #expect(!response.lowercased().contains("content-encoding: gzip"))  // escaping .gz rejected
        #expect(response.contains("IDENTITY-CSS-BYTES"))
        #expect(!response.contains("ESCAPED-GZIP-PAYLOAD"))  // out-of-root bytes never served
    }

    @Test func precompressedBrotliSiblingSymlinkToEtcHostsIsNotServed() async throws {
        // Same jail on the brotli branch, pointed at a real out-of-root system file (/etc/hosts). The `.br`
        // sibling symlink resolves outside root → identity served; /etc/hosts contents never appear.
        // `compression: false` (as in the gzip case) keeps the body readable so the no-leak check is exact.
        let root = TemporaryDirectory(prefix: "adserve-traversal-precomp-br")
        defer { root.cleanup() }
        try Data("IDENTITY-JS-BYTES".utf8).write(to: URL(fileURLWithPath: root.file("app.js")))
        try FileManager.default.createSymbolicLink(
            atPath: root.file("app.js.br"), withDestinationPath: "/etc/hosts")
        let hostsBytes = (try? Data(contentsOf: URL(fileURLWithPath: "/etc/hosts"))) ?? Data()
        let hostsMarker = String(decoding: hostsBytes.prefix(64), as: UTF8.self)

        let routes = StubRoutes { _ in
            .file(root: root.path, subpath: "app.js", contentType: "text/javascript")
        }
        let response = try await Loopback.run(
            path: "/app.js", routes: routes, headers: [("Accept-Encoding", "br")], compression: false)

        #expect(response.hasPrefix("HTTP/1.1 200"))
        #expect(!response.lowercased().contains("content-encoding: br"))  // escaping .br rejected
        #expect(response.contains("IDENTITY-JS-BYTES"))
        // Defensive: the first non-trivial line of /etc/hosts must not have leaked into the body.
        if let firstLine = hostsMarker.split(separator: "\n").first(where: { $0.count >= 6 }) {
            #expect(!response.contains(String(firstLine)))
        }
    }

    // MARK: - 2. A regular file that is a SYMLINK pointing OUTSIDE root → 404

    @Test func regularFileSymlinkOutOfRootIs404() async throws {
        // The identity target itself is a symlink that resolves outside root. `planStaticFile` canonicalizes
        // with `resolvingSymlinksInPath`, so `isInsideRoot` on the resolved path is false → 404, and the
        // out-of-root secret is never served.
        let root = TemporaryDirectory(prefix: "adserve-traversal-symlink")
        defer { root.cleanup() }
        let outOfRoot = TemporaryDirectory(prefix: "adserve-traversal-symlink-evil")
        defer { outOfRoot.cleanup() }

        let secret = outOfRoot.file(sentinelName("txt"))
        try Data("TOPSECRET-OUT-OF-ROOT".utf8).write(to: URL(fileURLWithPath: secret))
        try FileManager.default.createSymbolicLink(
            atPath: root.file("link.txt"), withDestinationPath: secret)

        let routes = StubRoutes { _ in
            .file(root: root.path, subpath: "link.txt", contentType: "text/plain")
        }
        let response = try await Loopback.run(path: "/link.txt", routes: routes)

        #expect(response.hasPrefix("HTTP/1.1 404"))
        #expect(!response.contains("TOPSECRET-OUT-OF-ROOT"))
    }

    @Test func symlinkToEtcHostsIs404() async throws {
        // An in-root regular-looking entry that is a symlink to a real system file → still 404 (no leak).
        let root = TemporaryDirectory(prefix: "adserve-traversal-symlink-hosts")
        defer { root.cleanup() }
        try FileManager.default.createSymbolicLink(
            atPath: root.file("hosts.txt"), withDestinationPath: "/etc/hosts")

        let routes = StubRoutes { _ in
            .file(root: root.path, subpath: "hosts.txt", contentType: "text/plain")
        }
        let response = try await Loopback.run(path: "/hosts.txt", routes: routes)
        #expect(response.hasPrefix("HTTP/1.1 404"))
    }

    // MARK: - 3. Encoded traversal `%2e%2e%2f` / `..%2f`

    @Test func percentEncodedTraversalSubpathIsInertAndDoesNotEscape() async throws {
        // DECODE-rejection of `%2e%2e%2f` ("../") is the DSL `PathTemplate.decodeSegment`'s job (it decodes
        // each segment and rejects a decoded `.`/`..`/`/`). The ENGINE never percent-decodes a subpath, so
        // the literal bytes `..%2f`/`%2e%2e%2f` are treated as an ordinary (nonexistent) filename: the
        // resolved path stays INSIDE root and there is no such file → 404. This locks that the encoded form
        // cannot escape the engine jail even if it reached `.file()` undecoded — it does NOT reach the
        // sibling parent file. (Were the engine to decode, `..` would then resolve out — and `isInsideRoot`
        // would still reject it; see vector 7.)
        let root = TemporaryDirectory(prefix: "adserve-traversal-encoded")
        defer { root.cleanup() }
        // A real out-of-root parent sibling the encoded form must NOT reach.
        let parentSecret =
            URL(fileURLWithPath: root.path).deletingLastPathComponent()
            .appendingPathComponent(sentinelName("css"))
        try Data("PARENT-SECRET-CSS".utf8).write(to: parentSecret)
        defer { try? FileManager.default.removeItem(at: parentSecret) }

        for encoded in ["%2e%2e%2f\(parentSecret.lastPathComponent)", "..%2f\(parentSecret.lastPathComponent)"] {
            let routes = StubRoutes { _ in
                .file(root: root.path, subpath: encoded, contentType: "text/css")
            }
            let response = try await Loopback.run(path: "/x", routes: routes)
            #expect(response.hasPrefix("HTTP/1.1 404"))  // literal name, no such file
            #expect(!response.contains("PARENT-SECRET-CSS"))  // parent sibling never reached
        }
    }

    // MARK: - 4. Unicode normalization (NFC file vs NFD request, and vice-versa)

    @Test func unicodeNFCFileServedConsistentlyForNFDRequestAndStaysJailed() async throws {
        // A file whose name is NFC on creation, requested via the NFD byte sequence (and vice-versa). On the
        // case-/normalization-insensitive dev FS (APFS) both forms resolve to the same in-root inode, so the
        // engine serves it consistently (200) — and the resolved real path is still inside root, so
        // normalization is NOT a jail bypass. This pins the observed dev-FS behavior; on a normalization-
        // SENSITIVE FS the mismatched form would simply 404 (still no escape).
        let root = TemporaryDirectory(prefix: "adserve-traversal-unicode")
        defer { root.cleanup() }
        let nfc = "caf\u{00E9}.css"  // é precomposed (NFC)
        let nfd = "cafe\u{0301}.css"  // e + combining acute (NFD)
        // Swift String equality is canonical, so `nfc == nfd`; the on-the-wire/on-disk UTF-8 bytes differ.
        #expect(nfc == nfd)  // sanity: canonically equal …
        #expect(Array(nfc.utf8) != Array(nfd.utf8))  // … but the byte encodings genuinely differ

        try Data("CAFE-IDENTITY".utf8).write(to: URL(fileURLWithPath: root.file(nfc)))

        // Request via the NFD form.
        let nfdRoutes = StubRoutes { _ in
            .file(root: root.path, subpath: nfd, contentType: "text/css; charset=utf-8")
        }
        let nfdResponse = try await Loopback.run(path: "/cafe.css", routes: nfdRoutes)
        #expect(nfdResponse.hasPrefix("HTTP/1.1 200"))  // dev FS resolves NFD→NFC inode
        #expect(nfdResponse.contains("CAFE-IDENTITY"))

        // Request via the exact NFC form it was written with.
        let nfcRoutes = StubRoutes { _ in
            .file(root: root.path, subpath: nfc, contentType: "text/css; charset=utf-8")
        }
        let nfcResponse = try await Loopback.run(path: "/cafe.css", routes: nfcRoutes)
        #expect(nfcResponse.hasPrefix("HTTP/1.1 200"))
        #expect(nfcResponse.contains("CAFE-IDENTITY"))
    }

    @Test func unicodeNormalizationCannotEscapeRoot() async throws {
        // A precomposed-vs-decomposed spelling of a `..`-adjacent name must not become a traversal: a
        // subpath that normalizes/resolves out of root is still rejected. Here an NFD-spelled segment plus a
        // real `../` escapes → the engine jail rejects it (404), proving normalization does not weaken
        // `isInsideRoot`.
        let root = TemporaryDirectory(prefix: "adserve-traversal-unicode-escape")
        defer { root.cleanup() }
        let outOfRoot =
            URL(fileURLWithPath: root.path).deletingLastPathComponent()
            .appendingPathComponent("cafe\u{0301}-\(UInt64.random(in: .min ... .max)).txt")
        try Data("UNICODE-ESCAPE-SECRET".utf8).write(to: outOfRoot)
        defer { try? FileManager.default.removeItem(at: outOfRoot) }

        let routes = StubRoutes { _ in
            .file(root: root.path, subpath: "../" + outOfRoot.lastPathComponent, contentType: "text/plain")
        }
        let response = try await Loopback.run(path: "/x", routes: routes)
        #expect(response.hasPrefix("HTTP/1.1 404"))
        #expect(!response.contains("UNICODE-ESCAPE-SECRET"))
    }

    // MARK: - 5. Case-sensitivity on the case-insensitive dev FS + the extension allow-list

    @Test func caseInsensitiveFilesystemServesAndStaysJailed() async throws {
        // On the case-insensitive dev FS, an on-disk `APP.CSS` resolves for a `app.css` lookup. The engine
        // serves it (the file exists + is jailed) — this LOCKS that case-folding does not let the resolved
        // path leave root (it is still `<root>/app.css`). The allow-list bypass concern is covered below.
        let root = TemporaryDirectory(prefix: "adserve-traversal-case")
        defer { root.cleanup() }
        try Data("UPPERCASE-FILE".utf8).write(to: URL(fileURLWithPath: root.file("APP.CSS")))

        let routes = StubRoutes { _ in
            .file(root: root.path, subpath: "app.css", contentType: "text/css; charset=utf-8")
        }
        let response = try await Loopback.run(path: "/app.css", routes: routes)
        #expect(response.hasPrefix("HTTP/1.1 200"))  // case-insensitive FS resolves APP.CSS
        #expect(response.contains("UPPERCASE-FILE"))
    }

    @Test func extensionAllowListIsCaseFoldedSoUppercaseCannotBypass() {
        // The allow-list (`staticServableExtensions`, all lowercase) is the SECURITY boundary in
        // `Static()`. Its case-proofing rests on `MediaType.fileExtension(of:)` LOWER-CASING the extension
        // before the membership test — so neither an uppercase ALLOWED ext sneaks a different code path, nor
        // an uppercase DISALLOWED ext (e.g. `.PHP`, `.ENV`) slips through a case mismatch. This pins that
        // primitive directly (it is the Core-visible mechanism the DSL allow-list depends on).
        #expect(MediaType.fileExtension(of: "APP.CSS") == "css")
        #expect(MediaType.fileExtension(of: "app.CsS") == "css")
        #expect(MediaType.fileExtension(of: "evil.PHP") == "php")  // folds → a disallowed ext stays disallowed
        #expect(MediaType.fileExtension(of: "config.ENV") == "env")
        #expect(MediaType.fileExtension(of: "archive.GZ") == "gz")
    }

    // MARK: - 6. Dotfile request (`/.env`)

    @Test func engineRejectsADotfileEvenWhenReachedDirectly() async throws {
        // Defense in depth: the engine jail now refuses a hidden file (any resolved path segment starting
        // with `.`), so even a hand-built `.file(subpath: ".env")` that bypasses the DSL `Static()` dotfile
        // guard is a 404 — the engine is the FINAL gate, not only the DSL. (Production still rejects it at
        // the DSL layer first; this proves the second layer holds if the first is bypassed.)
        let root = TemporaryDirectory(prefix: "adserve-traversal-dotfile")
        defer { root.cleanup() }
        try Data("SECRET=hunter2".utf8).write(to: URL(fileURLWithPath: root.file(".env")))

        let present = StubRoutes { _ in
            .file(root: root.path, subpath: ".env", contentType: "text/plain")
        }
        let presentResponse = try await Loopback.run(path: "/.env", routes: present)
        #expect(presentResponse.hasPrefix("HTTP/1.1 404"))  // engine rejects the hidden file
        #expect(!presentResponse.contains("SECRET=hunter2"))  // the secret never leaks

        // And the dotfile must NEVER be reachable from outside root, even by the engine (jail still holds).
        let outOfRoot =
            URL(fileURLWithPath: root.path).deletingLastPathComponent()
            .appendingPathComponent(".env-\(UInt64.random(in: .min ... .max))")
        try Data("OUT-OF-ROOT-DOTENV".utf8).write(to: outOfRoot)
        defer { try? FileManager.default.removeItem(at: outOfRoot) }
        let escape = StubRoutes { _ in
            .file(root: root.path, subpath: "../" + outOfRoot.lastPathComponent, contentType: "text/plain")
        }
        let escapeResponse = try await Loopback.run(path: "/x", routes: escape)
        #expect(escapeResponse.hasPrefix("HTTP/1.1 404"))
        #expect(!escapeResponse.contains("OUT-OF-ROOT-DOTENV"))
    }

    // MARK: - 7. Absolute-path-like subpath / `..` that escapes → 404

    @Test func dotDotEscapingSubpathIs404() async throws {
        // The canonical traversal: a subpath with enough `../` to climb above root resolves outside → 404.
        let root = TemporaryDirectory(prefix: "adserve-traversal-dotdot")
        defer { root.cleanup() }
        let outOfRoot =
            URL(fileURLWithPath: root.path).deletingLastPathComponent()
            .appendingPathComponent(sentinelName("txt"))
        try Data("ESCAPED-VIA-DOTDOT".utf8).write(to: outOfRoot)
        defer { try? FileManager.default.removeItem(at: outOfRoot) }

        let routes = StubRoutes { _ in
            .file(
                root: root.path, subpath: "../" + outOfRoot.lastPathComponent, contentType: "text/plain")
        }
        let response = try await Loopback.run(path: "/x", routes: routes)
        #expect(response.hasPrefix("HTTP/1.1 404"))
        #expect(!response.contains("ESCAPED-VIA-DOTDOT"))
    }

    @Test func deeplyNestedDotDotEscapeToEtcPasswdIs404() async throws {
        // Many `../` segments aiming at a real system file: the standardized path leaves root → 404, and no
        // /etc/passwd content leaks.
        let root = TemporaryDirectory(prefix: "adserve-traversal-deep")
        defer { root.cleanup() }
        let routes = StubRoutes { _ in
            .file(
                root: root.path, subpath: "../../../../../../../../etc/passwd",
                contentType: "text/plain")
        }
        let response = try await Loopback.run(path: "/x", routes: routes)
        #expect(response.hasPrefix("HTTP/1.1 404"))
        #expect(!response.lowercased().contains("root:"))  // /etc/passwd first field never served
    }

    @Test func absoluteLookingSubpathStaysJailedTo404() async throws {
        // An absolute-LOOKING subpath (`/etc/hosts`) is joined as `<root>/etc/hosts` and standardized INSIDE
        // root — it does not jump to the real /etc. No such in-root file → 404; /etc/hosts is never read.
        let root = TemporaryDirectory(prefix: "adserve-traversal-abs")
        defer { root.cleanup() }
        let routes = StubRoutes { _ in
            .file(root: root.path, subpath: "/etc/hosts", contentType: "text/plain")
        }
        let response = try await Loopback.run(path: "/x", routes: routes)
        #expect(response.hasPrefix("HTTP/1.1 404"))
    }

    @Test func prefixSiblingDirectoryEscapeIsRejected() async throws {
        // The string-prefix trap: a sibling dir `<root>-evil` shares the `<root>` string prefix but is
        // OUTSIDE root. Only the trailing slash in `isInsideRoot` (`hasPrefix(root + "/")`) distinguishes
        // them; without it `<root>-evil/secret` would falsely pass the jail. Asserting 404 + no leak locks
        // the `+ "/"`.
        let base = TemporaryDirectory(prefix: "adserve-traversal-prefix")
        defer { base.cleanup() }
        let jail = base.file("jail")
        let evil = base.file("jail-evil")
        try FileManager.default.createDirectory(atPath: jail, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: evil, withIntermediateDirectories: true)
        try Data("PREFIX-SIBLING-SECRET".utf8)
            .write(
                to: URL(fileURLWithPath: evil).appendingPathComponent("secret.txt"))

        let routes = StubRoutes { _ in
            .file(root: jail, subpath: "../jail-evil/secret.txt", contentType: "text/plain")
        }
        let response = try await Loopback.run(path: "/x", routes: routes)
        #expect(response.hasPrefix("HTTP/1.1 404"))
        #expect(!response.contains("PREFIX-SIBLING-SECRET"))
    }

    // MARK: - O_NOFOLLOW on the file open (TOCTOU symlink-swap defense)

    @Test func openForReadingRefusesAFinalComponentSymlink() throws {
        // `planStaticFile` only ever hands `openForReading` a symlink-RESOLVED, jailed path, so a real
        // asset's final component is never a symlink — O_NOFOLLOW never rejects a legitimate file (a
        // symlinked deploy root is resolved away before the open). But if that final component has BECOME a
        // symlink between the plan's stat and the open — an attacker racing a planted link to read OUTSIDE
        // the jailed root — O_NOFOLLOW makes the open fail (ELOOP) → the stream collapses to 404. This pins
        // that open-time guard directly: a regular file opens; a symlink to it (even an in-tree, otherwise
        // legitimate target) does not.
        let dir = TemporaryDirectory(prefix: "adserve-nofollow")
        defer { dir.cleanup() }
        let real = dir.file("real.txt")
        try Data("REAL-BYTES".utf8).write(to: URL(fileURLWithPath: real))
        let link = dir.file("link.txt")
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: real)

        // A regular file opens cleanly.
        let realFd = HTTPServer.openForReading(real)
        #expect(realFd != nil)
        if let fd = realFd { HTTPServer.closeDescriptor(fd) }

        // A final-component symlink — even to the in-tree real file — is refused by O_NOFOLLOW.
        #expect(HTTPServer.openForReading(link) == nil)
    }
}
