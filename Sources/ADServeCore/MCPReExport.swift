// The MCP JSON-RPC 2.0 core + the `Tool` DSL now live in the standalone, transport-agnostic ADMCP
// package (depending only on ADJSON / ADConcurrency / swift-log — no HTTP/NIO engine). Re-export it
// so the existing surface stays reachable through `import ADServeCore` — and, via ADServeDSL's
// `public import ADServeCore`, through `import ADServeDSL` — with zero source change for consumers.
@_exported import ADMCP
