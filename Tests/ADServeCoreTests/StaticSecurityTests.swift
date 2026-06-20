// Phase 1 hardening regression: the static streamer opens ONE descriptor for the whole response, so a
// mid-flight unlink/replace cannot swap the bytes served — the held fd pins the original inode. (The
// prior implementation re-opened the path per chunk, a fresh TOCTOU window each chunk.)

import ADTestKit
import Foundation
import Testing

@testable import ADServeCore

@Suite struct StaticSecurityTests {
    @Test func `a held descriptor keeps serving the original bytes after the file is replaced`() throws {
        let dir = TemporaryDirectory(prefix: "adserve-toctou")
        defer { dir.cleanup() }
        let path = dir.file("data.bin")
        let original = Array("ORIGINAL-CONTENT-1234567890".utf8)  // 27 bytes
        try Data(original).write(to: URL(fileURLWithPath: path))

        let fd = try #require(HTTPServer.openForReading(path))
        defer { HTTPServer.closeDescriptor(fd) }

        // Read the first chunk from the held fd.
        let firstChunk = try #require(HTTPServer.readChunk(fd: fd, offset: 0, count: 10))
        #expect(firstChunk == Array(original.prefix(10)))

        // The attacker swaps the file for a NEW inode (atomic temp+rename) mid-stream.
        try Data(Array("REPLACED-WITH-EVIL-PAYLOAD!".utf8))
            .write(to: URL(fileURLWithPath: path), options: .atomic)

        // The held fd still reads the ORIGINAL inode's remaining bytes — not the replacement.
        let rest = try #require(HTTPServer.readChunk(fd: fd, offset: 10, count: original.count - 10))
        #expect(rest == Array(original.suffix(from: 10)))
    }

    @Test func `a held descriptor keeps serving after the file is deleted`() throws {
        let dir = TemporaryDirectory(prefix: "adserve-toctou-del")
        defer { dir.cleanup() }
        let path = dir.file("data.bin")
        let original = Array("KEEP-ME-AFTER-UNLINK".utf8)
        try Data(original).write(to: URL(fileURLWithPath: path))

        let fd = try #require(HTTPServer.openForReading(path))
        defer { HTTPServer.closeDescriptor(fd) }
        _ = try #require(HTTPServer.readChunk(fd: fd, offset: 0, count: 4))

        try FileManager.default.removeItem(atPath: path)  // unlink mid-stream

        // The open fd holds the inode alive; the remaining bytes are still readable + correct.
        let rest = try #require(HTTPServer.readChunk(fd: fd, offset: 4, count: original.count - 4))
        #expect(rest == Array(original.suffix(from: 4)))
    }

    @Test func `opening a missing file fails cleanly`() {
        #expect(HTTPServer.openForReading("/no/such/adserve/file/\(UInt64.random(in: .min ... .max))") == nil)
    }
}
