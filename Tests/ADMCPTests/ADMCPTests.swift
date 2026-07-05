import ADConcurrency
import ADJSON
import Logging
import Testing

@testable import ADMCP

@Schemable
private struct GreetInput: Codable {
    let name: String
}

/// A throwaway `PooledResource` so a test can build an `MCPToolContext` (no real pool needed).
private struct TestConnection: PooledResource {
    init?(path: String) {}
}

private func testContext() -> MCPToolContext {
    MCPToolContext(connection: TestConnection(path: "")!, logger: Logger(label: "test"))
}

struct ADMCPTests {
    private func registry() -> ToolRegistry {
        ToolRegistry {
            Tool("ping", "No-arg tool").respond { _ in .okValue(.string("pong")) }
            Tool("greet", "Typed-input tool").input(GreetInput.self)
                .respond { input, _ in
                    .okValue(.string("Hello \(input.name)"))
                }
        }
    }

    @Test
    func `the Tool DSL builds a registry whose definitions carry name + a @Schemable schema`() {
        let defs = registry().toolDefinitions
        #expect(defs.count == 2)
        #expect(defs.map(\.name) == ["ping", "greet"])
        // The typed tool's input schema is the @Schemable JSON Schema — a JSON object.
        if case .object(let greetSchema) = defs[1].inputSchema {
            #expect(greetSchema["type"] == .string("object"))
        } else {
            Issue.record("greet's input schema should be a JSON object")
        }
    }

    @Test
    func `invoke routes by name and decodes typed input from the arguments JSONValue`() {
        let reg = registry()
        let ctx = testContext()

        if case .okValue(let value) = reg.invoke(name: "ping", arguments: .object([:]), context: ctx) {
            #expect(value == .string("pong"))
        } else {
            Issue.record("ping should succeed")
        }

        let greet = reg.invoke(name: "greet", arguments: .object(["name": .string("Ada")]), context: ctx)
        if case .okValue(let value) = greet {
            #expect(value == .string("Hello Ada"))
        } else {
            Issue.record("greet should succeed")
        }

        if case .failure = reg.invoke(name: "nope", arguments: .object([:]), context: ctx) {
        } else {
            Issue.record("an unknown tool should fail")
        }
    }

    @Test
    func `the dispatcher answers tools/list and tools/call over JSON-RPC`() throws {
        let dispatcher = MCPDispatcher(
            serverInfo: MCPServerInfo(name: "test", version: "1.0", instructions: nil),
            tools: registry())
        let ctx = testContext()

        let listLine = #"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#
        let listBytes = try #require(dispatcher.handle(line: listLine, context: ctx))
        let list = try JSONValue(parsing: String(decoding: listBytes, as: UTF8.self))
        #expect(MCPJSON.object(list)?["id"] == .int(1))
        let tools = MCPJSON.array(MCPJSON.member(MCPJSON.member(list, "result"), "tools")) ?? []
        #expect(Set(tools.compactMap { MCPJSON.string(MCPJSON.member($0, "name")) }) == ["ping", "greet"])

        let callLine =
            #"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"greet","arguments":{"name":"Ada"}}}"#
        let callBytes = try #require(dispatcher.handle(line: callLine, context: ctx))
        let call = String(decoding: callBytes, as: UTF8.self)
        #expect(call.contains("Hello Ada"))
        #expect(call.contains(#""id":2"#))
    }
}
