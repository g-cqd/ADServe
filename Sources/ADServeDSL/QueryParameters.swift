import ADServeCore

/// Typed read access to the request's (already percent-decoded) query parameters. Reach it via
/// `ctx.query`: `ctx.query.page` / `ctx.query["page"]` (optional `String`), `ctx.query.int("page")`
/// (typed), or `ctx.query.require("page")` / `requireInt` (throws `HTTPError.badRequest` if absent or
/// the wrong type — caught by the engine's error boundary as a 400).
@dynamicMemberLookup
public struct QueryParameters: Sendable {
    let values: [String: String]
    init(_ values: [String: String]) { self.values = values }

    public subscript(_ name: String) -> String? { values[name] }
    public subscript(dynamicMember name: String) -> String? { values[name] }

    /// The whole map, when you need to iterate.
    public var all: [String: String] { values }

    public func int(_ name: String) -> Int? { values[name].flatMap(Int.init) }
    public func double(_ name: String) -> Double? { values[name].flatMap(Double.init) }

    /// `true` for `true`/`1`/`yes`/`on` and a bare flag (`?verbose`); `false` for `false`/`0`/`no`/
    /// `off`; `nil` if absent.
    public func bool(_ name: String) -> Bool? {
        guard let raw = values[name] else { return nil }
        switch raw.lowercased() {
            case "false", "0", "no", "off": return false
            default: return true
        }
    }

    /// A required parameter; throws `HTTPError.badRequest` if absent.
    public func require(_ name: String) throws -> String {
        guard let value = values[name] else {
            throw HTTPError.badRequest("missing required query parameter '\(name)'")
        }
        return value
    }

    /// A required `Int`; throws `HTTPError.badRequest` if absent or not an integer.
    public func requireInt(_ name: String) throws -> Int {
        guard let value = int(name) else {
            throw HTTPError.badRequest("query parameter '\(name)' must be an integer")
        }
        return value
    }
}
