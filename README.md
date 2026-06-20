# ADServe

A reusable, **persistence-agnostic** HTTP/1.1 + HTTP/2 + TLS server engine and a result-builder
route DSL for Swift 6 — extracted from the apple-docs `ad-server` so any project can build on it.

Built on swift-nio, swift-http-types, swift-nio-ssl/http2, swift-crypto, swift-log, and
swift-service-lifecycle. JSON via the first-party [ADJSON]; pooling via [ADConcurrency].

## Products

| Library | What it is |
| --- | --- |
| **ADServeCore** | The engine: NIO bootstrap + async serving loop, HTTP/1.1 & HTTP/2 (ALPN), TLS 1.3, the response envelope (security headers, ETag/304, request-id), slowloris/idle protection, ServiceLifecycle graceful drain, a **type-erased connection pool**, and the in-house **MCP** (Model Context Protocol) JSON-RPC core + stdio transport. Knows nothing route-specific. |
| **ADServeDSL** | The declaration surface: `Server { App { GET("…") { ctx in … } } }`, typed verbs, `Group` nesting, a typed pool that picks the handler's context (`@dynamicMemberLookup`), `.cache`/ETag modifiers, and the MCP `Tool` DSL. Lowers to the engine's `HTTPHandling` contract. |

## Persistence-agnostic by design

The engine never depends on a database. It pools `any PooledResource` through a type-erased
`AnyConnectionPool`; the **application** pins the concrete connection type at its composition root:

```swift
import ADConcurrency
import ADServeCore

// 1. Your handle already has `init?(path:)` → conform it once.
extension MyConnection: PooledResource {}

// 2. Build the engine's type-erased pool from a concrete ResourcePool.
let real = ResourcePool<MyConnection>(path: dbPath, count: threads)!
let pool = AnyConnectionPool { body in
    guard let lease = real.lease() else { return nil }   // scoped: auto-returns on exit
    return body(lease.resource)
}

// 3. Hand it to the engine (or pass `nil` for a headless, no-storage server).
let server = HTTPServer(listeners: …, pool: pool, envelope: …, logger: …, threadCount: threads)
try await server.run()
```

A `.storage` route's handler reaches the resource via `ctx.connection` (typed-erased) and
down-casts to its concrete type — the app's invariant: the pool holds exactly that type. A server
with no `.storage` routes passes `pool: nil` and depends on no storage package at all.

## Layering

`ADServe` depends only on the swift-server/apple NIO stack + `ADJSON` + `ADConcurrency`. It has **no
dependency on any persistence package** (verify: `swift package show-dependencies` shows no
storage package). Keep it that way — that is what makes it reusable.

## Versioning & pinning

The first-party deps (`ADJSON`, `ADConcurrency`) follow the g-cqd `AD*` family
policy:

- **Today (pre-1.0):** every first-party `AD*` dependency resolves by
  `branch: "main"` — there are no semver tags yet, so the graph tracks the tip of
  main. (The apple/swift-server stack is already version-pinned by SwiftPM
  requirements.)
- **Planned:** cut semver tags (0.x stabilizing toward 1.0) for the `AD*` siblings
  and pin the resolved graph via the **committed `Package.resolved`** (already in
  this repo — it pins the exact revisions resolution uses), so a clean checkout
  builds what CI validated.
- **Local development:** override a first-party dependency to a sibling checkout
  with its `*_PATH` env var — `ADJSON_PATH`, `ADCONCURRENCY_PATH`. Never set a
  `*_PATH` in CI or a release build; those resolve the published package.

## Build

```sh
swift build
swift test
```

[ADJSON]: https://github.com/g-cqd/ADJSON
[ADConcurrency]: https://github.com/g-cqd/ADConcurrency
