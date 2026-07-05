// Typed string path templates for the route DSL: `"items/{id}/comments/{cid}"` → named captures the
// handler reads as `params.id` / `params.int("cid")`. Parsed once when a route is built; matched
// against the full request path. The verb overloads in ServerDSL.swift take a template + a
// two-argument handler `(ctx, params)`, disambiguated from the exact-path overload by closure arity.

import ADFCore

/// A parsed path template: literal segments, `{name}` single-segment parameters, and an optional
/// trailing `{name*}` catch-all that captures the remainder (including slashes).
public struct PathTemplate: Sendable {
    enum Segment: Sendable, Equatable {
        case literal(String)
        case param(String)
        case catchAll(String)
    }
    let segments: [Segment]

    /// Parse a template. Validation is fail-fast (templates are developer-written literals): a
    /// duplicate parameter name, a catch-all that isn't the final segment, or an unbalanced brace
    /// traps at startup — never at request time.
    public init(_ template: String) {
        var parsed: [Segment] = []
        var names: Set<String> = []
        for part in template.split(separator: "/", omittingEmptySubsequences: true) {
            let token = String(part)
            if token.hasPrefix("{"), token.hasSuffix("}") {
                let inner = String(token.dropFirst().dropLast())
                precondition(
                    !inner.isEmpty && !inner.contains("{") && !inner.contains("}"),
                    "ADServe: malformed path parameter '\(token)' in template '\(template)'")
                let isCatchAll = inner.hasSuffix("*")
                let name = isCatchAll ? String(inner.dropLast()) : inner
                precondition(
                    names.insert(name).inserted,
                    "ADServe: duplicate path parameter '\(name)' in template '\(template)'")
                parsed.append(isCatchAll ? .catchAll(name) : .param(name))
            } else {
                precondition(
                    !token.contains("{") && !token.contains("}"),
                    "ADServe: unbalanced brace in path segment '\(token)' of template '\(template)'")
                parsed.append(.literal(token))
            }
        }
        if let catchAll = parsed.firstIndex(where: { if case .catchAll = $0 { true } else { false } }) {
            precondition(
                catchAll == parsed.count - 1,
                "ADServe: a catch-all `{name*}` must be the final segment in template '\(template)'")
        }
        segments = parsed
    }

    /// Match the full request `path`, binding + percent-decoding `{name}` segments. `nil` if it does
    /// not match. A trailing `{name*}` captures the rest (decoded per-segment, rejoined with `/`);
    /// otherwise every request segment must be consumed. Captures are percent-decoded via the
    /// family's `ADFCore.PercentCoding`, and a capture that decodes to `.`/`..` or contains a `/`
    /// (an encoded path separator) is REJECTED — closing the encoded-traversal hole.
    public func match(_ path: Substring) -> PathParameters? {
        match(segments: path.split(separator: "/", omittingEmptySubsequences: true))
    }

    /// The split-free core of ``match(_:)``: bind against the request path's ALREADY-split segments.
    /// The routing trie splits the request path once during its descent (`omittingEmptySubsequences:
    /// true`), so it hands those exact segments straight here — the per-route `bind` no longer re-splits
    /// the path (FIX #7). Behavior is byte-identical to `match(_:)` (which just splits then calls this).
    func match(segments parts: [Substring]) -> PathParameters? {
        var captures: [String: String] = [:]
        var index = 0
        for segment in segments {
            switch segment {
                case .literal(let literal):
                    guard index < parts.count, parts[index] == literal[...] else { return nil }
                    index += 1
                case .param(let name):
                    guard index < parts.count, let value = Self.decodeSegment(parts[index]) else {
                        return nil
                    }
                    captures[name] = value
                    index += 1
                case .catchAll(let name):
                    guard index < parts.count else { return nil }
                    var pieces: [String] = []
                    for raw in parts[index...] {
                        guard let piece = Self.decodeSegment(raw) else { return nil }
                        pieces.append(piece)
                    }
                    captures[name] = pieces.joined(separator: "/")
                    index = parts.count
            }
        }
        guard index == parts.count else { return nil }
        return PathParameters(captures)
    }

    /// Percent-decode one path segment (RFC 3986 via `ADFCore.PercentCoding`), rejecting malformed
    /// escapes, traversal/separator smuggling (`.`, `..`, or a decoded `/`), and NUL / C0 / DEL control
    /// bytes. The control-byte guard is defense-in-depth against a smuggled NUL (`%00`): a path segment
    /// never legitimately contains one, and a NUL can TRUNCATE the path at the `open()` syscall — serving a
    /// different file than the extension allow-list checked on the pre-NUL bytes. Rejecting it here (on the
    /// decoded bytes, not via Foundation's escaping) closes the bypass platform-independently.
    static func decodeSegment(_ segment: Substring) -> String? {
        guard let bytes = PercentCoding.decode(Array(segment.utf8)) else { return nil }
        let decoded = String(decoding: bytes, as: UTF8.self)
        if decoded == "." || decoded == ".." || decoded.contains("/") { return nil }
        for scalar in decoded.unicodeScalars where scalar.value < 0x20 || scalar.value == 0x7f {
            return nil
        }
        return decoded
    }
}

/// Path captures by name: `params.id` (`@dynamicMemberLookup`), `params["id"]`, or typed
/// `params.int("id")`. Values are the raw path segments (not percent-decoded in v1).
@dynamicMemberLookup
public struct PathParameters: Sendable {
    let values: [String: String]
    init(_ values: [String: String]) { self.values = values }

    public subscript(_ name: String) -> String? { values[name] }
    public subscript(dynamicMember name: String) -> String? { values[name] }

    /// A capture parsed as `Int`, or `nil` if absent / not an integer.
    public func int(_ name: String) -> Int? { values[name].flatMap(Int.init) }
}
