// In-house form parsing: `application/x-www-form-urlencoded` (reusing `ADFCore.PercentCoding`) and
// `multipart/form-data` (RFC 7578). MultipartKit is `vapor/*` (excluded by the dependency rule), so the
// parser is hand-rolled over the buffered request body. Reach it via `ctx.form()` / `ctx.multipart()`.
// Streaming-multipart over an inbound `AsyncSequence` waits for M6; this operates on the capped body.

import ADFCore
import Foundation
import HTTPTypes

// MARK: - x-www-form-urlencoded

/// The fields of an `application/x-www-form-urlencoded` body — `k=v&k2=v2`, with `+` → space and `%XX`
/// decoded (the form rule layered on `ADFCore.PercentCoding`). Last value wins on a duplicate key.
public struct URLEncodedForm: Sendable {
    private let byName: [String: String]

    public init(_ body: [UInt8]) {
        var parsed: [String: String] = [:]
        let text = String(decoding: body, as: UTF8.self)
        for pair in text.split(separator: "&", omittingEmptySubsequences: true) {
            let kv = pair.split(separator: "=", maxSplits: 1)
            guard let key = kv.first else { continue }
            let name = Self.formDecode(key)
            parsed[name] = kv.count > 1 ? Self.formDecode(kv[1]) : ""
        }
        byName = parsed
    }

    public subscript(_ name: String) -> String? { byName[name] }
    public var all: [String: String] { byName }
    public var isEmpty: Bool { byName.isEmpty }
    public func int(_ name: String) -> Int? { byName[name].flatMap(Int.init) }

    /// `+` → space, then RFC 3986 percent-decode (`%2B` stays `+`). Malformed escapes fall back to the
    /// raw text rather than dropping the value.
    static func formDecode(_ token: Substring) -> String {
        // Fast path: a token with neither `+` nor `%` is already its decoded form — skip the byte-array
        // copy, the percent-decode pass, and the re-`String` (most form values are unencoded). One scan,
        // no allocation, then a single `String(token)`.
        if !token.utf8.contains(where: { $0 == UInt8(ascii: "+") || $0 == UInt8(ascii: "%") }) {
            return String(token)
        }
        var bytes = Array(token.utf8)
        for index in bytes.indices where bytes[index] == UInt8(ascii: "+") {
            bytes[index] = UInt8(ascii: " ")
        }
        guard let decoded = PercentCoding.decode(bytes) else { return String(token) }
        return String(decoding: decoded, as: UTF8.self)
    }
}

// MARK: - multipart/form-data

/// One parsed `multipart/form-data` part: a named field, with an optional `filename` + part `Content-Type`
/// (present for a file upload), and the raw part bytes.
public struct MultipartPart: Sendable {
    public let name: String
    public let filename: String?
    public let contentType: String?
    public let body: [UInt8]

    public init(name: String, filename: String?, contentType: String?, body: [UInt8]) {
        self.name = name
        self.filename = filename
        self.contentType = contentType
        self.body = body
    }

    /// The part body decoded as UTF-8 (for a text field).
    public var text: String { String(decoding: body, as: UTF8.self) }
    /// A part carrying a `filename` is a file upload.
    public var isFile: Bool { filename != nil }
}

/// A parsed `multipart/form-data` body: the parts in wire order, plus name-keyed + field/file views.
public struct MultipartForm: Sendable {
    public let parts: [MultipartPart]

    public init(parts: [MultipartPart]) { self.parts = parts }

    /// The first part named `name`, or `nil`.
    public subscript(_ name: String) -> MultipartPart? { parts.first { $0.name == name } }
    /// Non-file parts as a name→text map (last wins on a duplicate name).
    public var fields: [String: String] {
        var out: [String: String] = [:]
        for part in parts where !part.isFile { out[part.name] = part.text }
        return out
    }
    /// The file parts (those carrying a `filename`).
    public var files: [MultipartPart] { parts.filter(\.isFile) }
}

/// The hand-rolled `multipart/form-data` parser (RFC 7578) over a buffered body.
public enum MultipartParser {
    private static let crlf: [UInt8] = [13, 10]
    private static let dashDash: [UInt8] = [45, 45]

    /// The `boundary` token from a `Content-Type: multipart/form-data; boundary=…` value, or `nil` if the
    /// type is not multipart / the boundary is missing. A quoted boundary is unquoted.
    public static func boundary(fromContentType contentType: String) -> String? {
        guard contentType.range(of: "multipart/form-data", options: .caseInsensitive) != nil,
            let marker = contentType.range(of: "boundary=", options: .caseInsensitive)
        else { return nil }
        var value = contentType[marker.upperBound...]
        if let semicolon = value.firstIndex(of: ";") { value = value[..<semicolon] }
        var boundary = value.trimmingCharacters(in: .whitespaces)
        if boundary.count >= 2, boundary.hasPrefix("\""), boundary.hasSuffix("\"") {
            boundary = String(boundary.dropFirst().dropLast())
        }
        return boundary.isEmpty ? nil : boundary
    }

    /// Parse `body` against `boundary` into parts. Returns an empty form when there are no parts; never
    /// traps on malformed input (a bad part is skipped).
    public static func parse(_ body: [UInt8], boundary: String) -> MultipartForm {
        let delimiter = Array("--\(boundary)".utf8)
        let segments = ByteSearch.split(body, on: delimiter)
        var parts: [MultipartPart] = []
        // segments[0] is the preamble (before the first delimiter, normally empty). A segment beginning
        // with "--" is the closing delimiter (`--boundary--`) — stop.
        for segment in segments.dropFirst() {
            if segment.starts(with: dashDash) { break }
            var content = segment
            if content.starts(with: crlf) { content.removeFirst(2) }  // CRLF after the delimiter
            if content.count >= 2, content.suffix(2).elementsEqual(crlf) { content.removeLast(2) }  // before next
            if let part = parsePart(content) { parts.append(part) }
        }
        return MultipartForm(parts: parts)
    }

    /// One part: headers up to the blank line, then the raw body. Requires a `name` (an unnamed part is
    /// not valid `form-data` and is dropped).
    private static func parsePart(_ bytes: ArraySlice<UInt8>) -> MultipartPart? {
        let separator: [UInt8] = [13, 10, 13, 10]
        guard let range = ByteSearch.firstRange(of: separator, in: bytes) else { return nil }
        let headerText = String(decoding: bytes[..<range.lowerBound], as: UTF8.self)
        let partBody = Array(bytes[range.upperBound...])

        var name: String?
        var filename: String?
        var contentType: String?
        for line in headerText.split(separator: "\r\n", omittingEmptySubsequences: true) {
            let lower = line.lowercased()
            if lower.hasPrefix("content-disposition:") {
                name = parameter("name", in: line)
                filename = parameter("filename", in: line)
            } else if lower.hasPrefix("content-type:") {
                contentType = line.dropFirst("content-type:".count).trimmingCharacters(in: .whitespaces)
            }
        }
        guard let name else { return nil }
        return MultipartPart(name: name, filename: filename, contentType: contentType, body: partBody)
    }

    /// The value of a `key="value"` (or `key=value`) parameter in a header line, unquoted; `nil` if absent.
    private static func parameter(_ key: String, in line: Substring) -> String? {
        guard let marker = line.range(of: "\(key)=", options: .caseInsensitive) else { return nil }
        var value = line[marker.upperBound...]
        if value.first == "\"" {
            value = value.dropFirst()
            if let end = value.firstIndex(of: "\"") { value = value[..<end] }
        } else if let semicolon = value.firstIndex(of: ";") {
            value = value[..<semicolon]
        }
        return String(value)
    }
}
