import HTTPCore
import Testing

@testable import ADServeCore
@testable import ADServeDSL

private func sampleTable() -> any HTTPHandling {
    let apps = Server {
        App(pool: .none) {
            GET("healthz", pool: .none) { _ in .plain(.ok, "ok") }.cache(.noStore)
            Scope("api") {
                GET("filters", pool: .none) { _ in .plain(.ok, "f") }.etag
            }
            POST("mcp", pool: .none) { _ in .plain(.ok, "m") }
        }
    }
    return listeners(apps, defaultPort: 8080)[0].routes
}

private func match(_ t: any HTTPHandling, _ method: HTTPMethod, _ path: String) -> RouteMatch {
    t.match(method: method, path: path[...])
}

@Suite struct RouteMatchTests {
    @Test func exactAndScopedPathsMatch() {
        let t = sampleTable()
        #expect(isMatched(match(t, .get, "/healthz")))
        #expect(isMatched(match(t, .get, "/api/filters")))
        #expect(isMatched(match(t, .post, "/mcp")))
    }

    // A scope-root route — the default "/" subpath, i.e. `GET { … }` inside `Scope("parts")` — must
    // INHERIT the scope's path and answer the bare prefix. It compiles to "/parts/", and a request carries
    // a canonicalized trailing slash, so BOTH "/parts" and "/parts/" reach it (likewise the nested template).
    @Test func scopeRootRouteInheritsScopePath() {
        let apps = Server {
            App(pool: .none) {
                Scope("parts") {
                    GET(pool: .none) { _ in .plain(.ok, "list") }
                    POST(pool: .none) { _ in .plain(.ok, "create") }
                    Scope("{id}") {
                        GET(pool: .none) { _, _ in .plain(.ok, "detail") }
                    }
                }
            }
        }
        let t = listeners(apps, defaultPort: 8080)[0].routes
        #expect(isMatched(match(t, .get, "/parts")))  // bare scope path — the regression
        #expect(isMatched(match(t, .get, "/parts/")))  // …and with the trailing slash
        #expect(isMatched(match(t, .post, "/parts")))
        #expect(isMatched(match(t, .get, "/parts/7")))  // nested template under the scope
        #expect(isMatched(match(t, .get, "/parts/7/")))
        // A wrong method on the bare scope path is a 405 (the path exists), not a 404.
        if case .methodNotAllowed(let allowed) = match(t, .put, "/parts") {
            #expect(allowed.contains(.get) && allowed.contains(.post))
        } else {
            Issue.record("expected methodNotAllowed for PUT /parts")
        }
    }

    // `Group` is the deprecated former spelling of `Scope`; it must still compose the same prefix so
    // existing route trees keep working. (`@available(deprecated)` on the test suppresses the use warning.)
    @available(*, deprecated)
    @Test func deprecatedGroupAliasComposesLikeScope() {
        let apps = Server {
            App(pool: .none) {
                Group("api") {
                    GET("filters", pool: .none) { _ in .plain(.ok, "f") }
                }
            }
        }
        let t = listeners(apps, defaultPort: 8080)[0].routes
        #expect(isMatched(match(t, .get, "/api/filters")))
        #expect(!isMatched(match(t, .get, "/filters")))
    }

    @Test func methodMismatchIs405() {
        if case .methodNotAllowed = match(sampleTable(), .get, "/mcp") {
        } else {
            Issue.record("expected methodNotAllowed for GET /mcp")
        }
    }

    @Test func unknownPathIs404() {
        if case .notFound = match(sampleTable(), .get, "/nope") {
        } else {
            Issue.record("expected notFound for GET /nope")
        }
    }

    @Test func cachePolicyIsCarried() {
        guard case .matched(let health) = match(sampleTable(), .get, "/healthz") else {
            Issue.record("expected match")
            return
        }
        #expect(health.cache.cacheControl == "no-store")
        #expect(health.needsStorage == false)

        guard case .matched(let filters) = match(sampleTable(), .get, "/api/filters") else {
            Issue.record("expected match")
            return
        }
        #expect(filters.cache.etag)
    }

    private func isMatched(_ m: RouteMatch) -> Bool {
        if case .matched = m { return true }
        return false
    }
}
