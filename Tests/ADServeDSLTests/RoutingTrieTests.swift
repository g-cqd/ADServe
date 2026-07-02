// Route-trie dispatch: specificity ordering (static > param > catch-all) and the adversarial
// backtracking cases — split from RESTDSLTests.swift to keep each file within the length budget.

import ADServeCore
import HTTPCore
import Logging
import Testing

@testable import ADServeDSL

/// Build a dispatchable `RouteTable` from route nodes (the same lowering `Server`/`App` performs).
private func table(@RouteGroupBuilder _ routes: () -> [RouteNode]) -> any HTTPHandling {
    RouteTable(routes: routes().flatMap { $0.build(prefix: "") })
}

/// Run a request through the table matched handler (nil when the route misses).
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

/// The (status, utf8-body) of a buffered response for compact assertions.
private func plain(_ content: ResponseContent?) -> (HTTPStatus, String)? {
    switch content {
        case .raw(let body, _, let status), .full(let body, _, let status, _):
            return (status, String(decoding: body, as: UTF8.self))
        case .plain(let status, let message): return (status, message)
        default: return nil
    }
}

struct RoutingSpecificityTests {
    @Test
    func `literal routes are scoped to their segment; param/catch-all reached by structure`() {
        let routes = table {
            GET("items/{id}", pool: .none) { _, p in .plain(.ok, "item-\(p.id ?? "?")") }
            GET("users/{id}", pool: .none) { _, p in .plain(.ok, "user-\(p.id ?? "?")") }
            GET("{resource}/{id}/raw", pool: .none) { _, p in .plain(.ok, "raw-\(p.resource ?? "?")") }
        }
        #expect(plain(runMatched(routes, .get, "/items/42"))?.1 == "item-42")
        #expect(plain(runMatched(routes, .get, "/users/7"))?.1 == "user-7")
        #expect(plain(runMatched(routes, .get, "/anything/9/raw"))?.1 == "raw-anything")  // param-first reached
        #expect(runMatched(routes, .get, "/nope/1") == nil)  // no 2-segment route for first-segment "nope"
    }

    @Test(
        "a literal segment beats a {param} regardless of declaration order",
        arguments: [true, false])
    func literalBeatsParam(literalFirst: Bool) {
        // Build the SAME overlapping pair in both declaration orders; specificity must pick the literal
        // `items/{id}` for `/items/5` either way — proving the result no longer depends on order.
        let routes: any HTTPHandling
        if literalFirst {
            routes = table {
                GET("items/{id}", pool: .none) { _, p in .plain(.ok, "lit-\(p.id ?? "?")") }
                GET("{resource}/{id}", pool: .none) { _, p in .plain(.ok, "wild-\(p.resource ?? "?")") }
            }
        } else {
            routes = table {
                GET("{resource}/{id}", pool: .none) { _, p in .plain(.ok, "wild-\(p.resource ?? "?")") }
                GET("items/{id}", pool: .none) { _, p in .plain(.ok, "lit-\(p.id ?? "?")") }
            }
        }
        #expect(plain(runMatched(routes, .get, "/items/5"))?.1 == "lit-5")  // literal wins both orders
        #expect(plain(runMatched(routes, .get, "/widgets/9"))?.1 == "wild-widgets")  // param catches the rest
    }
}

struct RoutingTrieAdversarialTests {
    @Test
    func `exact beats param beats catch-all at one position`() {
        let routes = table {
            GET("files/readme", pool: .none) { _ in .plain(.ok, "exact") }
            GET("files/{id}", pool: .none) { _, p in .plain(.ok, "param-\(p.id ?? "?")") }
            GET("files/{rest*}", pool: .none) { _, p in .plain(.ok, "catchall-\(p.rest ?? "?")") }
        }
        #expect(plain(runMatched(routes, .get, "/files/readme"))?.1 == "exact")
        #expect(plain(runMatched(routes, .get, "/files/other"))?.1 == "param-other")
        #expect(plain(runMatched(routes, .get, "/files/a/b"))?.1 == "catchall-a/b")
    }

    @Test
    func `backtracks when a more-specific branch dead-ends`() {
        let routes = table {
            GET("a/b/c", pool: .none) { _ in .plain(.ok, "exact-abc") }
            GET("a/{x}", pool: .none) { _, p in .plain(.ok, "ax-\(p.x ?? "?")") }
            GET("a/{x}/{y}", pool: .none) { _, p in .plain(.ok, "axy-\(p.x ?? "?")-\(p.y ?? "?")") }
            GET("{p}/{q}", pool: .none) { _, p in .plain(.ok, "pq-\(p.p ?? "?")") }
        }
        #expect(plain(runMatched(routes, .get, "/a/b/c"))?.1 == "exact-abc")  // exact wins
        #expect(plain(runMatched(routes, .get, "/a/zzz"))?.1 == "ax-zzz")  // literal "a" then param {x}
        // The literal "a/b" branch dead-ends on the 3rd segment "d"; backtrack into "a"'s param subtree.
        #expect(plain(runMatched(routes, .get, "/a/b/d"))?.1 == "axy-b-d")
        #expect(plain(runMatched(routes, .get, "/m/n"))?.1 == "pq-m")  // root-level param branch
    }

    @Test
    func `405 collects every method at a node, de-duplicated`() {
        let routes = table {
            GET("items/{id}", pool: .none) { _, p in .plain(.ok, p.id ?? "?") }
            DELETE("items/{id}", pool: .none) { _, _ in .plain(.ok, "del") }
            PATCH("items/{id}", pool: .none) { _, _ in .plain(.ok, "patch") }
        }
        guard case .methodNotAllowed(let allowed) = routes.match(method: .put, path: "/items/1"[...]) else {
            Issue.record("expected methodNotAllowed")
            return
        }
        #expect(Set(allowed) == [.get, .delete, .patch])
        #expect(allowed.count == 3)  // no duplicates
    }

    @Test
    func `405 unions methods across backtracking branches`() {
        let routes = table {
            GET("{a}/{b}", pool: .none) { _, _ in .plain(.ok, "ab") }
            POST("files/{rest*}", pool: .none) { _, _ in .plain(.ok, "files") }
        }
        // DELETE /files/x reaches GET via {a}/{b} AND POST via files/{rest*} — two different terminals.
        guard case .methodNotAllowed(let allowed) = routes.match(method: .delete, path: "/files/x"[...]) else {
            Issue.record("expected methodNotAllowed union")
            return
        }
        #expect(allowed.contains(.get))
        #expect(allowed.contains(.post))
    }

    @Test
    func `exact path and a param overlap: exact serves its method; both fold into the 405 set`() {
        let routes = table {
            GET("users/me", pool: .none) { _ in .plain(.ok, "me") }
            GET("users/{id}", pool: .none) { _, p in .plain(.ok, "id-\(p.id ?? "?")") }
        }
        #expect(plain(runMatched(routes, .get, "/users/me"))?.1 == "me")  // exact wins
        #expect(plain(runMatched(routes, .get, "/users/42"))?.1 == "id-42")  // param for the rest
        guard case .methodNotAllowed(let allowed) = routes.match(method: .post, path: "/users/me"[...]) else {
            Issue.record("expected methodNotAllowed")
            return
        }
        #expect(allowed == [.get])  // exact GET + param GET, de-duped to a single entry
    }

    @Test
    func `encoded traversal is rejected under specificity backtracking`() {
        let routes = table {
            GET("files/{id}", pool: .none) { _, p in .plain(.ok, "id-\(p.id ?? "?")") }
            GET("files/{rest*}", pool: .none) { _, p in .plain(.ok, "rest-\(p.rest ?? "?")") }
        }
        #expect(runMatched(routes, .get, "/files/%2e%2e") == nil)  // encoded ".." — param + catch-all both reject
        #expect(runMatched(routes, .get, "/files/a%2Fb") == nil)  // encoded "/" in a single param
        #expect(runMatched(routes, .get, "/files/a/%2e%2e/x") == nil)  // encoded ".." inside the catch-all
        #expect(plain(runMatched(routes, .get, "/files/readme"))?.1 == "id-readme")  // normal → param
        #expect(plain(runMatched(routes, .get, "/files/a/b/c"))?.1 == "rest-a/b/c")  // normal multi → catch-all
    }

    @Test
    func `root path matches, and 405/404 behave at the root`() {
        let routes = table {
            GET("/", pool: .none) { _ in .plain(.ok, "root") }
        }
        #expect(plain(runMatched(routes, .get, "/"))?.1 == "root")
        guard case .methodNotAllowed(let allowed) = routes.match(method: .post, path: "/"[...]) else {
            Issue.record("expected methodNotAllowed at root")
            return
        }
        #expect(allowed.contains(.get))
        #expect(runMatched(routes, .get, "/anything") == nil)
    }

    @Test
    func `opaque GET(match:) matchers are residual — the trie wins; opaque serves only trie misses`() {
        let routes = table {
            GET("items/{id}", pool: .none) { _, p in .plain(.ok, "trie-\(p.id ?? "?")") }
            GET(match: { $0.hasPrefix("/legacy/") ? true : nil }, pool: .none) { _, _ in .plain(.ok, "opaque") }
        }
        #expect(plain(runMatched(routes, .get, "/items/9"))?.1 == "trie-9")  // structured route wins
        #expect(plain(runMatched(routes, .get, "/legacy/x"))?.1 == "opaque")  // only the opaque matcher fits
        #expect(runMatched(routes, .get, "/nope") == nil)  // neither
        // The opaque matcher still contributes its method to a 405 for a path it accepts.
        guard case .methodNotAllowed(let allowed) = routes.match(method: .post, path: "/legacy/x"[...]) else {
            Issue.record("expected methodNotAllowed from the opaque-only path")
            return
        }
        #expect(allowed.contains(.get))
    }
}
