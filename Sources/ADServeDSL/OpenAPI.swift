// OpenAPI 3.1 generation from the route DSL. A route carries optional documentation metadata
// (`.summary`/`.tags`/`.body`/`.responds`); `openAPIDocument(info:from:)` walks the same `Server { … }`
// value the engine serves and emits a valid OpenAPI document — so the served routes and the published
// contract can never drift. Request/response bodies reuse the family's `@Schemable` macro (ADJSON):
// a `@Schemable struct` exposes `jsonSchemaText`, which is embedded verbatim into `components/schemas`
// (OpenAPI 3.1 schemas ARE JSON Schema, so no translation is needed).

public import ADJSON
import HTTPTypes

// MARK: - Document metadata

/// The top-level `info` block of an OpenAPI document.
public struct OpenAPIInfo: Sendable {
    public var title: String
    public var version: String
    public var description: String?
    public init(title: String, version: String, description: String? = nil) {
        self.title = title
        self.version = version
        self.description = description
    }
}

/// A reference to a `@Schemable` type's JSON Schema: a component name (the type's simple name) plus the
/// schema document text. Built from any `ADJSONSchemaProviding` type (i.e. `@Schemable`).
public struct SchemaRef: Sendable {
    public let name: String
    public let schemaText: String
    public init(name: String, schemaText: String) {
        self.name = name
        self.schemaText = schemaText
    }
    public init<T: ADJSONSchemaProviding>(_ type: T.Type) {
        self.init(name: String(describing: T.self), schemaText: T.jsonSchemaText)
    }
}

/// Per-route OpenAPI metadata, populated by the `.summary`/`.describe`/`.tags`/`.operationId`/
/// `.deprecated`/`.body`/`.responds` modifiers. A route with no doc is still served — it's simply
/// omitted-but-for-its-path from the generated document (the path + verb always appear).
public struct RouteDoc: Sendable {
    public var summary: String?
    public var description: String?
    public var operationId: String?
    public var tags: [String]
    public var deprecated: Bool
    public var requestBody: SchemaRef?
    /// Documented responses, keyed by status code. Empty → a default `200` is emitted (OpenAPI
    /// requires every operation to declare at least one response).
    public var responses: [Int: SchemaRef]
    public init(
        summary: String? = nil, description: String? = nil, operationId: String? = nil,
        tags: [String] = [], deprecated: Bool = false, requestBody: SchemaRef? = nil,
        responses: [Int: SchemaRef] = [:]
    ) {
        self.summary = summary
        self.description = description
        self.operationId = operationId
        self.tags = tags
        self.deprecated = deprecated
        self.requestBody = requestBody
        self.responses = responses
    }
}

// MARK: - DSL doc modifiers

extension RouteNode {
    private func mutatingDoc(_ mutate: (inout RouteDoc) -> Void) -> RouteNode {
        var copy = self
        var doc = copy.doc ?? RouteDoc()
        mutate(&doc)
        copy.doc = doc
        return copy
    }

    /// A one-line operation summary.
    public func summary(_ text: String) -> RouteNode { mutatingDoc { $0.summary = text } }
    /// A longer operation description (Markdown allowed per OpenAPI).
    public func describe(_ text: String) -> RouteNode { mutatingDoc { $0.description = text } }
    /// A stable operation id (must be unique across the document).
    public func operationId(_ id: String) -> RouteNode { mutatingDoc { $0.operationId = id } }
    /// Append OpenAPI tags (grouping the operation in tooling).
    public func tags(_ tags: String...) -> RouteNode { mutatingDoc { $0.tags += tags } }
    /// Mark the operation deprecated.
    public var deprecated: RouteNode { mutatingDoc { $0.deprecated = true } }
    /// Document the request body as a `@Schemable` type (`application/json`).
    public func body<T: ADJSONSchemaProviding>(_ type: T.Type) -> RouteNode {
        mutatingDoc { $0.requestBody = SchemaRef(type) }
    }
    /// Document a response body as a `@Schemable` type for `status` (default `200`).
    public func responds<T: ADJSONSchemaProviding>(_ type: T.Type, status: Int = 200) -> RouteNode {
        mutatingDoc { $0.responses[status] = SchemaRef(type) }
    }
}

// MARK: - A minimal ordered JSON writer

// A small ordered-JSON tree with a `.raw` leaf for embedding a `@Schemable` schema document verbatim.
// Objects keep insertion order, so the generated document is deterministic (diffable, testable). The
// tree's depth is bounded by the document shape this file builds (~6 levels), never by input — schema
// text rides as a single `.raw` leaf — so the recursive walk can't be driven deep by user data.
indirect enum DocJSON {
    case string(String)
    case int(Int)
    case bool(Bool)
    case array([DocJSON])
    case object([(String, DocJSON)])
    case raw(String)

    var serialized: String {
        var out = ""
        write(into: &out)
        return out
    }

    private func write(into out: inout String) {
        switch self {
            case .string(let value): DocJSON.escape(value, into: &out)
            case .int(let value): out += String(value)
            case .bool(let value): out += value ? "true" : "false"
            case .raw(let value): out += value
            case .array(let items):
                out += "["
                for (index, item) in items.enumerated() {
                    if index > 0 { out += "," }
                    item.write(into: &out)
                }
                out += "]"
            case .object(let pairs):
                out += "{"
                for (index, pair) in pairs.enumerated() {
                    if index > 0 { out += "," }
                    DocJSON.escape(pair.0, into: &out)
                    out += ":"
                    pair.1.write(into: &out)
                }
                out += "}"
        }
    }

    private static func escape(_ string: String, into out: inout String) {
        out += "\""
        for scalar in string.unicodeScalars {
            switch scalar {
                case "\"": out += "\\\""
                case "\\": out += "\\\\"
                case "\n": out += "\\n"
                case "\r": out += "\\r"
                case "\t": out += "\\t"
                case let c where c.value < 0x20:
                    let hex = String(c.value, radix: 16)
                    out += "\\u" + String(repeating: "0", count: 4 - hex.count) + hex
                default: out.unicodeScalars.append(scalar)
            }
        }
        out += "\""
    }
}

// MARK: - Generation

/// Generate an OpenAPI 3.1 document (as a JSON string) from the applications a `Server { … }` produced.
/// Pass the SAME `[Application]` value to `listeners(_:defaultPort:)` so the served routes and the
/// published contract stay in lockstep. Routes with no documentable path (opaque `GET(match:)`
/// matchers) are skipped; every other route contributes its path + verb, enriched by any `.summary`/
/// `.body`/`.responds`/… metadata.
public func openAPIDocument(info: OpenAPIInfo, from apps: [Application]) -> String {
    let routes = apps.flatMap(\.routes).filter { $0.pathTemplate != nil }

    // Group by path, preserving first-seen path order; within a path, keep first-seen verb.
    var pathOrder: [String] = []
    var byPath: [String: [(method: HTTPRequest.Method, doc: RouteDoc?)]] = [:]
    for route in routes {
        guard let path = route.pathTemplate else { continue }
        if byPath[path] == nil { pathOrder.append(path) }
        if byPath[path]?.contains(where: { $0.method == route.method }) == true { continue }
        byPath[path, default: []].append((route.method, route.doc))
    }

    // Collect every referenced schema, de-duplicated by component name (first wins).
    var schemaOrder: [String] = []
    var schemas: [String: String] = [:]
    func register(_ ref: SchemaRef?) {
        guard let ref, schemas[ref.name] == nil else { return }
        schemaOrder.append(ref.name)
        schemas[ref.name] = ref.schemaText
    }
    for route in routes {
        register(route.doc?.requestBody)
        for (_, ref) in (route.doc?.responses ?? [:]) { register(ref) }
    }

    var root: [(String, DocJSON)] = [
        ("openapi", .string("3.1.0")),
        ("info", openAPIInfoObject(info)),
        ("paths", .object(pathOrder.map { path in (path, pathItemObject(byPath[path] ?? [], path: path)) }))
    ]
    if !schemaOrder.isEmpty {
        let entries = schemaOrder.map { name in (name, DocJSON.raw(schemas[name] ?? "{}")) }
        root.append(("components", .object([("schemas", .object(entries))])))
    }
    return DocJSON.object(root).serialized
}

private func openAPIInfoObject(_ info: OpenAPIInfo) -> DocJSON {
    var fields: [(String, DocJSON)] = [("title", .string(info.title)), ("version", .string(info.version))]
    if let description = info.description { fields.append(("description", .string(description))) }
    return .object(fields)
}

/// Fixed verb order so a path's operations serialize deterministically.
private let methodOrder = ["GET", "PUT", "POST", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"]

private func pathItemObject(
    _ operations: [(method: HTTPRequest.Method, doc: RouteDoc?)], path: String
) -> DocJSON {
    let parameters = pathParameterObjects(of: path)
    let sorted = operations.sorted {
        (methodOrder.firstIndex(of: $0.method.rawValue) ?? methodOrder.count)
            < (methodOrder.firstIndex(of: $1.method.rawValue) ?? methodOrder.count)
    }
    return .object(
        sorted.map { ($0.method.rawValue.lowercased(), operationObject($0.doc, parameters: parameters)) })
}

private func operationObject(_ doc: RouteDoc?, parameters: [DocJSON]) -> DocJSON {
    var fields: [(String, DocJSON)] = []
    if let summary = doc?.summary { fields.append(("summary", .string(summary))) }
    if let description = doc?.description { fields.append(("description", .string(description))) }
    if let operationId = doc?.operationId { fields.append(("operationId", .string(operationId))) }
    if let tags = doc?.tags, !tags.isEmpty { fields.append(("tags", .array(tags.map(DocJSON.string)))) }
    if doc?.deprecated == true { fields.append(("deprecated", .bool(true))) }
    if !parameters.isEmpty { fields.append(("parameters", .array(parameters))) }
    if let body = doc?.requestBody { fields.append(("requestBody", requestBodyObject(body))) }
    fields.append(("responses", responsesObject(doc?.responses ?? [:])))
    return .object(fields)
}

private func pathParameterObjects(of path: String) -> [DocJSON] {
    path.split(separator: "/")
        .compactMap { segment -> DocJSON? in
            guard segment.first == "{", segment.last == "}" else { return nil }
            var name = segment.dropFirst().dropLast()
            if name.last == "*" { name = name.dropLast() }  // catch-all `{rest*}` → `rest`
            return .object([
                ("name", .string(String(name))),
                ("in", .string("path")),
                ("required", .bool(true)),
                ("schema", .object([("type", .string("string"))]))
            ])
        }
}

private func mediaObject(_ ref: SchemaRef) -> DocJSON {
    .object([
        (
            "content",
            .object([
                (
                    "application/json",
                    .object([
                        ("schema", .object([("$ref", .string("#/components/schemas/\(ref.name)"))]))
                    ])
                )
            ])
        )
    ])
}

private func requestBodyObject(_ ref: SchemaRef) -> DocJSON {
    var fields = objectFields(mediaObject(ref))
    fields.insert(("required", .bool(true)), at: 0)
    return .object(fields)
}

private func responsesObject(_ responses: [Int: SchemaRef]) -> DocJSON {
    guard !responses.isEmpty else {
        return .object([("200", .object([("description", .string("OK"))]))])
    }
    let entries = responses.keys.sorted()
        .map { status -> (String, DocJSON) in
            let ref = responses[status]
            var fields: [(String, DocJSON)] = [
                ("description", .string(HTTPResponse.Status(code: status).reasonPhrase))
            ]
            if let ref { fields.append(contentsOf: objectFields(mediaObject(ref))) }
            return (String(status), .object(fields))
        }
    return .object(entries)
}

/// Unwrap a `.object`'s pairs (the small helpers above build `.object`s, then compose them).
private func objectFields(_ json: DocJSON) -> [(String, DocJSON)] {
    if case .object(let pairs) = json { return pairs }
    return []
}
