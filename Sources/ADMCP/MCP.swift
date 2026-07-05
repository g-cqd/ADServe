// The Model Context Protocol core. In-house JSON-RPC 2.0 over a
// newline-delimited stdio transport — no `@modelcontextprotocol/sdk`. The dispatcher
// handles initialize / ping / tools/list / tools/call (+ notifications/initialized);
// the tool surface is provided by the DSL (`MCPToolProviding`). Everything is built on
// ADJSON `JSONValue` so the wire shapes stay intrinsic-identical to the SDK's output.

public import ADConcurrency
public import ADJSON
import Foundation
public import Logging

// MARK: - JSONValue helpers (minimal, ADJSON-agnostic)

/// Typed accessors over an optional ``JSONValue`` for MCP request parsing — a caseless-enum namespace.
/// Named `MCPJSON` (not `JSON`) to avoid colliding with ADJSON's `JSON` cursor type this module imports.
public enum MCPJSON {
    public static func object(_ value: JSONValue?) -> OrderedDictionary<String, JSONValue>? {
        if case .object(let object)? = value { return object }
        return nil
    }
    public static func string(_ value: JSONValue?) -> String? {
        if case .string(let string)? = value { return string }
        return nil
    }
    public static func array(_ value: JSONValue?) -> [JSONValue]? {
        if case .array(let array)? = value { return array }
        return nil
    }
    public static func number(_ value: JSONValue?) -> Double? {
        if case .number(let number)? = value { return number }
        return nil
    }
    public static func bool(_ value: JSONValue?) -> Bool? {
        if case .bool(let bool)? = value { return bool }
        return nil
    }
    /// A JSON number read as an Int (the MCP args send integers as JSON numbers). NaN/infinite → nil;
    /// out-of-range magnitudes clamp to `Int.min`/`Int.max` instead of trapping on the `Int(Double)`
    /// conversion.
    public static func int(_ value: JSONValue?) -> Int? {
        guard let n = number(value), n.isFinite else { return nil }
        if n >= Double(Int.max) { return Int.max }
        if n <= Double(Int.min) { return Int.min }
        return Int(n)
    }
    /// `object[key]` for a `.object` value.
    public static func member(_ value: JSONValue?, _ key: String) -> JSONValue? { object(value)?[key] }
}

// MARK: - Server identity + tool contract

/// The MCP `serverInfo` + `instructions` (app-provided, like SiteConfig).
public struct MCPServerInfo: Sendable {
    public let name: String
    public let version: String
    public let instructions: String?
    public init(name: String, version: String, instructions: String?) {
        self.name = name
        self.version = version
        self.instructions = instructions
    }
}

/// A tool's `tools/list` entry. `inputSchema`/`annotations` are pre-built JSONValues
/// (the DSL's `Schema` helpers build them — the zod replacement).
public struct MCPToolDefinition: Sendable {
    public let name: String
    public let description: String
    public let inputSchema: JSONValue
    public let annotations: JSONValue
    public init(name: String, description: String, inputSchema: JSONValue, annotations: JSONValue) {
        self.name = name
        self.description = description
        self.inputSchema = inputSchema
        self.annotations = annotations
    }
}

/// The per-call context handed to a tool. stdio is a single serial client, so one
/// connection suffices (no pool).
public struct MCPToolContext: Sendable {
    /// The type-erased per-call resource (stdio is a single serial client, so one suffices). A
    /// tool down-casts to its concrete connection type (the app's invariant: the pool holds it).
    public let connection: any PooledResource
    public let logger: Logger
    public init(connection: any PooledResource, logger: Logger) {
        self.connection = connection
        self.logger = logger
    }
}

/// A tool's outcome: pre-serialized payload bytes, a `JSONValue` payload, or an error
/// message. `.ok`/`.okValue` both project to `{content,structuredContent}`; `.failure`
/// to `{content,isError:true}`. `.okValue` lets JSON-producing tools hand the value
/// straight through — the dispatcher encodes it once for `text` and reuses it as
/// `structuredContent` (no encode→parse→re-encode round trip). `.ok` stays for tools
/// that already emit raw bytes (the search cascade), where one parse is unavoidable.
public enum MCPToolResult: Sendable {
    case ok([UInt8])
    case okValue(JSONValue)
    case failure(String)
}

/// The tool surface the dispatcher resolves against (the DSL's `ToolRegistry` conforms).
public protocol MCPToolProviding: Sendable {
    var toolDefinitions: [MCPToolDefinition] { get }
    func invoke(name: String, arguments: JSONValue, context: MCPToolContext) -> MCPToolResult
}

// MARK: - Resource contract

/// A `resources/list` entry. The list is corpus-derived (dynamic), so it is built
/// per call against the connection in the context.
public struct MCPResourceListItem: Sendable {
    public let uri: String
    public let name: String
    public init(uri: String, name: String) {
        self.uri = uri
        self.name = name
    }
}

/// One `resources/read` content block — `text` OR base64 `blob`, with a mime type.
public struct MCPResourceContent: Sendable {
    public let uri: String
    public let text: String?
    public let blob: String?
    public let mimeType: String
    public init(uri: String, text: String? = nil, blob: String? = nil, mimeType: String) {
        self.uri = uri
        self.text = text
        self.blob = blob
        self.mimeType = mimeType
    }
}

/// A `resources/read` outcome: content blocks, or a not-found for an unregistered URI
/// (the dispatcher maps it to the MCP `-32002` error).
public enum MCPResourceResult: Sendable {
    case contents([MCPResourceContent])
    case notFound(String)
}

/// The resource surface the dispatcher resolves against. Optional on the dispatcher —
/// a tools-only server passes none, and `resources/list` then returns an empty set.
public protocol MCPResourceProviding: Sendable {
    func listResources(context: MCPToolContext) -> [MCPResourceListItem]
    func readResource(uri: String, context: MCPToolContext) -> MCPResourceResult
}

// MARK: - Dispatcher

/// Handles one JSON-RPC line; returns the response bytes (with the trailing newline) or
/// nil for notifications / non-requests.
public struct MCPDispatcher: Sendable {
    let serverInfo: MCPServerInfo
    let tools: any MCPToolProviding
    let resources: (any MCPResourceProviding)?

    public init(
        serverInfo: MCPServerInfo, tools: any MCPToolProviding,
        resources: (any MCPResourceProviding)? = nil
    ) {
        self.serverInfo = serverInfo
        self.tools = tools
        self.resources = resources
    }

    /// The protocol versions the SDK supports (newest first); we echo the client's if it
    /// is one of these, else fall back to the latest.
    private static let supportedVersions = [
        "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05", "2024-10-07"
    ]

    public func handle(line: String, context: MCPToolContext) -> [UInt8]? {
        let trimmed = line.hasSuffix("\r") ? String(line.dropLast()) : line
        if trimmed.isEmpty { return nil }
        guard let request = try? JSONValue(parsing: trimmed), let object = MCPJSON.object(request) else {
            return encodeLine(rpcError(.null, code: -32700, message: "Parse error"))
        }
        let id = object["id"]
        guard let method = MCPJSON.string(object["method"]) else { return nil }
        let params = object["params"] ?? .object([:])

        switch method {
            case "initialize":
                return respond(id, initializeResult(params))
            case "notifications/initialized":
                return nil
            case "ping":
                return respond(id, .object([:]))
            case "tools/list":
                return respond(id, toolsListResult())
            case "tools/call":
                return respond(id, toolsCallResult(params, context: context))
            case "resources/list":
                return respond(id, resourcesListResult(context: context))
            case "resources/read":
                guard let uri = MCPJSON.string(MCPJSON.member(params, "uri")) else {
                    guard let id else { return nil }
                    return encodeLine(rpcError(id, code: -32602, message: "Missing resource uri"))
                }
                switch resources?.readResource(uri: uri, context: context) ?? .notFound(uri) {
                    case .contents(let blocks):
                        return respond(id, resourceContentsValue(blocks))
                    case .notFound(let missing):
                        guard let id else { return nil }
                        return encodeLine(rpcError(id, code: -32002, message: "Resource not found: \(missing)"))
                }
            default:
                guard let id else { return nil }
                return encodeLine(rpcError(id, code: -32601, message: "Method not found"))
        }
    }

    // MARK: result builders

    private func initializeResult(_ params: JSONValue) -> JSONValue {
        let requested = MCPJSON.string(MCPJSON.member(params, "protocolVersion"))
        let version: String =
            if let requested, Self.supportedVersions.contains(requested) { requested } else { "2025-11-25" }
        var result: OrderedDictionary<String, JSONValue> = [
            "protocolVersion": .string(version),
            "capabilities": .object([
                "resources": .object(["listChanged": .bool(true)]),
                "tools": .object(["listChanged": .bool(true)])
            ]),
            "serverInfo": .object([
                "name": .string(serverInfo.name), "version": .string(serverInfo.version)
            ])
        ]
        if let instructions = serverInfo.instructions { result["instructions"] = .string(instructions) }
        return .object(result)
    }

    private func toolsListResult() -> JSONValue {
        .object([
            "tools": .array(
                tools.toolDefinitions.map { definition in
                    .object([
                        "name": .string(definition.name),
                        "description": .string(definition.description),
                        "inputSchema": definition.inputSchema,
                        "annotations": definition.annotations,
                        "execution": .object(["taskSupport": .string("forbidden")])
                    ])
                })
        ])
    }

    private func resourcesListResult(context: MCPToolContext) -> JSONValue {
        let items = resources?.listResources(context: context) ?? []
        return .object([
            "resources": .array(items.map { .object(["uri": .string($0.uri), "name": .string($0.name)]) })
        ])
    }

    private func resourceContentsValue(_ blocks: [MCPResourceContent]) -> JSONValue {
        .object([
            "contents": .array(
                blocks.map { block in
                    var entry: OrderedDictionary<String, JSONValue> = ["uri": .string(block.uri)]
                    if let text = block.text { entry["text"] = .string(text) }
                    if let blob = block.blob { entry["blob"] = .string(blob) }
                    entry["mimeType"] = .string(block.mimeType)
                    return .object(entry)
                })
        ])
    }

    private func toolsCallResult(_ params: JSONValue, context: MCPToolContext) -> JSONValue {
        guard let name = MCPJSON.string(MCPJSON.member(params, "name")) else {
            return errorContent("Missing tool name")
        }
        let arguments = MCPJSON.member(params, "arguments") ?? .object([:])
        switch tools.invoke(name: name, arguments: arguments, context: context) {
            case .ok(let bytes):
                let text = String(decoding: bytes, as: UTF8.self)
                let structured = (try? JSONValue(parsing: text)) ?? .null
                return .object([
                    "content": .array([textContent(text)]), "structuredContent": structured
                ])
            case .okValue(let value):
                let bytes = (try? value.encoded()).map(Array.init) ?? Array("null".utf8)
                return .object([
                    "content": .array([textContent(String(decoding: bytes, as: UTF8.self))]),
                    "structuredContent": value
                ])
            case .failure(let message):
                return errorContent(message)
        }
    }

    private func textContent(_ text: String) -> JSONValue {
        .object(["type": .string("text"), "text": .string(text)])
    }

    private func errorContent(_ message: String) -> JSONValue {
        .object(["content": .array([textContent(message)]), "isError": .bool(true)])
    }

    private func respond(_ id: JSONValue?, _ result: JSONValue) -> [UInt8]? {
        guard let id else { return nil }
        return encodeLine(rpcResult(id, result))
    }

    private func rpcResult(_ id: JSONValue, _ result: JSONValue) -> JSONValue {
        .object(["jsonrpc": .string("2.0"), "id": id, "result": result])
    }

    private func rpcError(_ id: JSONValue, code: Int, message: String) -> JSONValue {
        .object([
            "jsonrpc": .string("2.0"), "id": id,
            "error": .object(["code": .number(Double(code)), "message": .string(message)])
        ])
    }

    private func encodeLine(_ value: JSONValue) -> [UInt8] {
        var bytes = (try? value.encoded()).map { Array($0) } ?? Array("null".utf8)
        bytes.append(0x0A)
        return bytes
    }
}

// MARK: - stdio transport

/// Reads newline-delimited JSON-RPC from stdin and writes responses to stdout. One
/// serial client; synchronous read loop (the process exists to serve stdin).
public struct StdioMCPTransport: Sendable {
    let dispatcher: MCPDispatcher
    let context: MCPToolContext
    public init(dispatcher: MCPDispatcher, context: MCPToolContext) {
        self.dispatcher = dispatcher
        self.context = context
    }

    public func run() {
        let out = FileHandle.standardOutput
        while let line = readLine(strippingNewline: true) {
            if let response = dispatcher.handle(line: line, context: context) {
                out.write(Data(response))
            }
        }
    }
}
