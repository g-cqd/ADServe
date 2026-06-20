// Parser fuzz suite (security): proves ADServe's hand-rolled byte/string parsers NEVER trap on hostile
// input. Each parser is fed thousands of mutated copies of a valid seed via ADTestKit's `fuzzNeverTraps`
// — survival (reaching the returned `FuzzReport`) is the pass, because a precondition / fatalError /
// out-of-bounds / stack overflow would abort the process before the loop could return one. Every parser
// here is total by contract (returns a value/nil, or — none of these do — throws a typed error), so the
// `exercise` closures simply call the parser and discard the result; nothing is expected to be caught.
//
// A separate constrained-stack / DepthSweep test pins the multipart parser to a 512 KiB worker stack and
// feeds it adversarially deep (many-delimiter) input, proving the splitter is iterative and resists a
// stack-overflow DoS. Seeds are fixed (`Seed(rawValue: 0xC0FFEE)` + a few named ones) so every run
// reproduces the exact same corpus; set `ADTESTKIT_FUZZ_TRACE` to print the last vector before a crash.

import ADFCore
import ADTestKit
import Foundation
import HTTPTypes
import Testing

@testable import ADServeCore

@Suite(.tags(.fuzz))
struct ParserFuzzTests {
    /// The shared deterministic seed for the byte-mutation parsers (the task's pinned corpus seed).
    private static let seed = Seed(rawValue: 0xC0FF_EE)
    /// The per-parser iteration budget.
    private static let iterations = 3000
    /// 1...8 edits per iteration — the canonical four-shape mutator default.
    private static let edits = 1 ... 8

    // MARK: - 1. multipart/form-data

    @Test
    func `MultipartParser.parse never traps on a mutated multipart body`() {
        let boundary = "----adserve-fuzz-boundary"
        let valid = Self.multipartBody(boundary: boundary)
        let report = fuzzNeverTraps(
            seed: Self.seed, iterations: Self.iterations, edits: Self.edits,
            corpus: { valid },
            exercise: { mutated in
                // Returns a (possibly empty) form; a bad part is skipped, never trapped on.
                _ = MultipartParser.parse(mutated, boundary: boundary)
            })
        #expect(report.iterations == Self.iterations)
    }

    @Test
    func `MultipartParser.parse never traps when the boundary string also appears inside the body`() {
        // The hostile shape: the literal delimiter is smuggled into a part's bytes, so the splitter sees
        // far more (and ragged) segments than a well-formed body — exactly where an off-by-one would trap.
        let boundary = "BOUNDARY"
        let valid = Self.multipartBodyWithEmbeddedBoundary(boundary: boundary)
        let report = fuzzNeverTraps(
            seed: Self.seed, iterations: Self.iterations, edits: Self.edits,
            corpus: { valid },
            exercise: { mutated in
                _ = MultipartParser.parse(mutated, boundary: boundary)
            })
        #expect(report.iterations == Self.iterations)
    }

    @Test
    func `MultipartParser.boundary(fromContentType:) never traps on a mutated Content-Type`() {
        let valid = Array(#"multipart/form-data; boundary="----adserve-fuzz-boundary""#.utf8)
        let report = fuzzNeverTraps(
            seed: Self.seed, iterations: Self.iterations, edits: Self.edits,
            corpus: { valid },
            exercise: { mutated in
                // The header is bytes on the wire; decode lossily (a real malformed header would too) and
                // extract the boundary. Returns the token or nil.
                _ = MultipartParser.boundary(fromContentType: String(decoding: mutated, as: UTF8.self))
            })
        #expect(report.iterations == Self.iterations)
    }

    // MARK: - 2. x-www-form-urlencoded

    @Test
    func `URLEncodedForm never traps on a mutated form body`() {
        let valid = Array("name=ada&id=42&note=hello+world&pct=%41%42%2B&empty=&flag".utf8)
        let report = fuzzNeverTraps(
            seed: Self.seed, iterations: Self.iterations, edits: Self.edits,
            corpus: { valid },
            exercise: { mutated in
                _ = URLEncodedForm(mutated)
            })
        #expect(report.iterations == Self.iterations)
    }

    // MARK: - 3. RequestCookies (Cookie: header)

    @Test
    func `RequestCookies never traps on a mutated Cookie header`() {
        let valid = Array(#"sid=abc123; theme="dark"; path=/; tab=\t; k=v=w; lonely"#.utf8)
        let report = fuzzNeverTraps(
            seed: Self.seed, iterations: Self.iterations, edits: Self.edits,
            corpus: { valid },
            exercise: { mutated in
                // The header is a String on the request; the parser must survive any UTF-8 the mutation
                // produces (including invalid sequences, which decode to U+FFFD rather than trapping).
                _ = RequestCookies(String(decoding: mutated, as: UTF8.self))
            })
        #expect(report.iterations == Self.iterations)
    }

    // MARK: - 4. HTTPDate

    @Test
    func `HTTPDate.parse never traps on a mutated IMF-fixdate`() {
        let valid = Array("Sun, 06 Nov 1994 08:49:37 GMT".utf8)
        let report = fuzzNeverTraps(
            seed: Self.seed, iterations: Self.iterations, edits: Self.edits,
            corpus: { valid },
            exercise: { mutated in
                // Returns whole epoch seconds or nil; a malformed date (bad day/month/time) is just nil.
                _ = HTTPDate.parse(String(decoding: mutated, as: UTF8.self))
            })
        #expect(report.iterations == Self.iterations)
    }

    // MARK: - 5. Byte-range (Range: header) against a fixed total size

    @Test
    func `the byte-range parser never traps on a mutated Range header`() throws {
        // `parseByteRange` is private; reach it through `HTTPServer.planStaticFile`, which calls it once it
        // has stat'd a real regular file. A fixed-size temp file pins `totalSize`, then we fuzz only the
        // Range header string — driving every branch (suffix `-N`, `N-`, `N-M`, multi-range, garbage).
        let root = try Self.makeTempDir()
        defer { try? FileManager.default.removeItem(at: root) }
        let totalSize = 1024
        try Data(repeating: 0x41, count: totalSize).write(to: root.appendingPathComponent("d.txt"))
        let request = StaticFileRequest(
            root: root.path, subpath: "d.txt", contentType: "text/plain", headers: HTTPFields())
        guard let rangeName = HTTPField.Name("range") else {
            Issue.record("could not build the Range header name")
            return
        }

        let valid = Array("bytes=0-499".utf8)
        let report = fuzzNeverTraps(
            seed: Self.seed, iterations: Self.iterations, edits: Self.edits,
            corpus: { valid },
            exercise: { mutated in
                // `HTTPField` legalizes invalid bytes to spaces (never traps), so the mutated bytes still
                // arrive at `parseByteRange` as a hostile Range spec — exercising every branch.
                var headers = HTTPFields()
                headers.append(HTTPField(name: rangeName, value: String(decoding: mutated, as: UTF8.self)))
                _ = HTTPServer.planStaticFile(file: request, headers: headers)
            })
        #expect(report.iterations == Self.iterations)
    }

    // MARK: - 6. Percent-decoding (ADFCore.PercentCoding)

    @Test
    func `PercentCoding.decode never traps on a mutated escape stream`() {
        let valid = Array("%41%42%2Bhello+world%FF%00%7E/path%2fseg".utf8)
        let report = fuzzNeverTraps(
            seed: Self.seed, iterations: Self.iterations, edits: Self.edits,
            corpus: { valid },
            exercise: { mutated in
                // Both policies: RFC 3986 (`+` verbatim) and form (`+` → space). A truncated (`%`, `%A`)
                // or non-hex (`%G0`) escape returns nil rather than trapping.
                _ = PercentCoding.decode(mutated)
                _ = PercentCoding.decodeForm(mutated)
            })
        #expect(report.iterations == Self.iterations)
    }

    // MARK: - Stack-overflow DoS: deeply pathological multipart on a constrained stack

    @Test
    func `MultipartParser.parse on a 512 KiB stack survives adversarially deep input`() {
        // A body that is nothing but `delimiterCount` back-to-back delimiters forces the maximum number of
        // split segments — the worst case for the splitter. Run on a small worker stack at escalating
        // depths (each straddling plausible caps, far past any sane part count): a non-iterative splitter
        // would recurse per segment and SIGBUS here instead of returning. Reaching the end of the sweep is
        // the proof of bounded (constant) stack use.
        let boundary = "----adserve-deep-boundary"
        DepthSweep.around(64, 256, 1024, upTo: 20_000)
            .run { delimiterCount in
                let body = Self.deeplyNestedMultipart(boundary: boundary, delimiterCount: delimiterCount)
                _ = MultipartParser.parse(body, boundary: boundary)
            }
    }

    // MARK: - Seed corpora

    /// A minimal well-formed two-part multipart body (one text field, one file part).
    private static func multipartBody(boundary: String) -> [UInt8] {
        let crlf = "\r\n"
        let body =
            "--\(boundary)\(crlf)"
            + "Content-Disposition: form-data; name=\"field\"\(crlf)\(crlf)"
            + "value\(crlf)"
            + "--\(boundary)\(crlf)"
            + "Content-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\(crlf)"
            + "Content-Type: text/plain\(crlf)\(crlf)"
            + "file-bytes\(crlf)"
            + "--\(boundary)--\(crlf)"
        return Array(body.utf8)
    }

    /// A multipart body whose single part's bytes contain the raw `--boundary` delimiter, so the splitter
    /// sees an extra (ragged) segment that does not begin a real part.
    private static func multipartBodyWithEmbeddedBoundary(boundary: String) -> [UInt8] {
        let crlf = "\r\n"
        let body =
            "--\(boundary)\(crlf)"
            + "Content-Disposition: form-data; name=\"field\"\(crlf)\(crlf)"
            + "before--\(boundary)after-not-a-real-part\(crlf)"
            + "--\(boundary)--\(crlf)"
        return Array(body.utf8)
    }

    /// `delimiterCount` back-to-back `--boundary` delimiters (no headers, no bodies) — the maximum-segment,
    /// maximum-depth shape for the stack-safety probe.
    private static func deeplyNestedMultipart(boundary: String, delimiterCount: Int) -> [UInt8] {
        let delimiter = Array("--\(boundary)\r\n".utf8)
        var body: [UInt8] = []
        body.reserveCapacity(delimiter.count * delimiterCount)
        for _ in 0 ..< delimiterCount { body.append(contentsOf: delimiter) }
        return body
    }

    /// A fresh unique temporary directory for the byte-range file fixture.
    private static func makeTempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ADServeParserFuzz-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }
}
