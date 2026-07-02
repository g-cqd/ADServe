// The DSL's transport-adjacent route surface: WebSocket (`WS`), hub-bound channels (`Channel`),
// streaming uploads (`Stream`), and the `App(cors:)` sugar — split from RESTDSLTests.swift to keep
// each file within the length budget.

import ADServeCore
import HTTPCore
import HTTPServer
import Logging
import Testing
import WebSocket

@testable import ADServeDSL

/// Build a dispatchable `RouteTable` from route nodes (the same lowering `Server`/`App` performs).
private func table(@RouteGroupBuilder _ routes: () -> [RouteNode]) -> any HTTPHandling {
    RouteTable(routes: routes().flatMap { $0.build(prefix: "") })
}

/// Run a request through the table's matched handler (nil when the route misses).
private func runMatched(
    _ routes: any HTTPHandling, _ method: HTTPMethod, _ path: String, body: [UInt8] = []
) -> ResponseContent? {
    guard case .matched(let route) = routes.match(method: method, path: path[...]) else { return nil }
    let input = HandlerInput(
        request: ServerRequest(
            method: method, target: path, headers: HTTPFields(), body: body),
        connection: nil, logger: Logger(label: "dsl-test"), requestID: "test")
    return try? route.run(input)
}

struct WebSocketDSLTests {
    @Test
    func `WS registers a websocket route and answers 426 to a plain GET`() {
        let routes = table { WS("chat") { _ in [] } }
        #expect(routes.webSocketEndpoint(path: "/chat") != nil)
        #expect(routes.webSocketEndpoint(path: "/other") == nil)
        guard case .full(_, _, let status, let headers)? = runMatched(routes, .get, "/chat") else {
            Issue.record("expected a 426 .full response for a non-upgrade GET")
            return
        }
        #expect(status.code == 426)
        #expect(headers[HTTPFieldName("upgrade")!] == "websocket")
        #expect(headers[HTTPFieldName("connection")!] == "Upgrade")
    }

    @Test
    func `WS routes nest under a Scope prefix`() {
        let routes = table { Scope("api") { WS("socket") { _ in [] } } }
        #expect(routes.webSocketEndpoint(path: "/api/socket") != nil)
        #expect(routes.webSocketEndpoint(path: "/socket") == nil)
    }
}

struct StreamingDSLTests {
    @Test
    func `Stream registers a POST streaming route resolvable by streamingHandler`() {
        let routes = table { Stream("upload") { _ in .plain(.ok, "ok") } }
        #expect(routes.streamingHandler(method: .post, path: "/upload") != nil)
        #expect(routes.streamingHandler(method: .get, path: "/upload") == nil)  // POST only
        #expect(routes.streamingHandler(method: .post, path: "/elsewhere") == nil)
    }

    @Test
    func `Stream routes nest under a Scope prefix`() {
        let routes = table { Scope("api") { Stream("upload") { _ in .plain(.ok, "ok") } } }
        #expect(routes.streamingHandler(method: .post, path: "/api/upload") != nil)
        #expect(routes.streamingHandler(method: .post, path: "/upload") == nil)
    }
}

/// `Channel(_:on:topic:)` — the WS endpoint bound to a `WebSocketHub` topic: the ENGINE
/// auto-subscribes each upgraded connection and unsubscribes it on disconnect (covered live in
/// WebSocketTests' hub-push test); structurally the route must resolve as a WS endpoint carrying
/// the hub + topic. The typed overload decodes inbound text frames and skips garbage.
@Suite struct ChannelDSLTests {
    private struct Ping: Codable, Equatable, Sendable { let n: Int }
    private actor Sink {
        private(set) var got: [Ping] = []
        func add(_ ping: Ping) { got.append(ping) }
    }

    @Test func channelResolvesToAWebSocketRouteAtItsPath() {
        let hub = WebSocketHub()
        let routes = table { Channel("/ws/parts", on: hub, topic: "parts") }
        #expect(routes.webSocketEndpoint(path: "/ws/parts") != nil)
        #expect(routes.webSocketEndpoint(path: "/ws/other") == nil)
    }

    @Test func channelCarriesItsHubAndTopicForTheEngine() {
        let hub = WebSocketHub()
        let routes = table { Channel("/ws/parts", on: hub, topic: "parts") }
        let endpoint = routes.webSocketEndpoint(path: "/ws/parts")
        #expect(endpoint?.hub === hub)
        #expect(endpoint?.topic == "parts")
    }

    @Test func typedChannelDecodesInboundFramesAndSkipsGarbage() async {
        let hub = WebSocketHub()
        let sink = Sink()
        let routes = table {
            Channel("/ws/ping", on: hub, topic: "ping", receiving: Ping.self) { ping in
                await sink.add(ping)
            }
        }
        guard let endpoint = routes.webSocketEndpoint(path: "/ws/ping") else {
            Issue.record("expected a WS route at /ws/ping")
            return
        }
        _ = await endpoint.handler.handle(.message(opcode: .text, payload: Array(#"{"n":1}"#.utf8)))
        _ = await endpoint.handler.handle(.message(opcode: .text, payload: Array("not json".utf8)))
        _ = await endpoint.handler.handle(.message(opcode: .binary, payload: [1, 2, 3]))
        _ = await endpoint.handler.handle(.message(opcode: .text, payload: Array(#"{"n":2}"#.utf8)))
        #expect(await sink.got == [Ping(n: 1), Ping(n: 2)])  // only the two valid frames, in order
    }
}

/// `App(cors:)` — the one-line, discoverable way to install a `CORS` middleware OUTERMOST (the cross-port
/// `ctx.fetch` use case). Verified structurally: the sugar wires CORS as the first middleware, and it stays
/// strictly opt-in.
@Suite struct AppCORSSugarTests {
    @Test func appCorsSugarInstallsCORSOutermostAndIsOptIn() {
        let withCORS = Server {
            App(pool: .none, cors: CORS(allowOrigin: "https://web.app")) {
                GET("x", pool: .none) { _ in .plain(.ok, "ok") }
            }
        }
        let middleware = withCORS[0].routes.first?.middleware
        #expect(middleware?.first is CORS)  // present AND outermost — it owns the OPTIONS preflight
        #expect((middleware?.first as? CORS)?.allowOrigin == "https://web.app")

        let withoutCORS = Server {
            App(pool: .none) { GET("x", pool: .none) { _ in .plain(.ok, "ok") } }
        }
        #expect(withoutCORS[0].routes.first?.middleware.contains { $0 is CORS } == false)  // opt-in only
    }
}
