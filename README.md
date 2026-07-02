# ADServe

A reusable, **persistence-agnostic** HTTP/1.1 + HTTP/2 + TLS server engine and a result-builder
route DSL for Swift 6 — extracted from the apple-docs `ad-server` so any project can build on it.

Built on the in-house, **SwiftNIO-free** [HTTP] package: its `HTTPCore` currency types
(method/status/fields), its sans-I/O h1/h2 protocol engines, and its switchable transport
backbones (a kqueue/epoll readiness loop for plaintext; Network.framework for TLS + ALPN).
Rounded out by swift-crypto, swift-log, and swift-service-lifecycle. JSON via the first-party
[ADJSON]; pooling and blocking-work offload via `ADConcurrency` (an [ADFoundation] module).

## Products

| Library | What it is |
| --- | --- |
| **ADServeCore** | The engine: ADServe's routing/middleware model bridged onto the HTTP package's serving stack through its `HTTPRouter` seam (`HTTPResponder & RouteResolver`) — HTTP/1.1 & HTTP/2 (ALPN), TLS 1.3, route-scoped WebSocket + broadcast hub, the response envelope (security headers, ETag/304, request-id), gzip response compression, per-route body limits and streaming request bodies resolved at the request head, slowloris/idle protection, ServiceLifecycle graceful drain, a **type-erased connection pool**, and the in-house **MCP** (Model Context Protocol) JSON-RPC core. Knows nothing route-specific. |
| **ADServeDSL** | The declaration surface: `Server { App { GET("…") { ctx in … } } }`, typed verbs, `Scope` nesting, a typed pool that picks the handler's context (`@dynamicMemberLookup`), `.cache`/ETag/`.maxBody` modifiers, `WS`/`Channel`/`Stream` routes, and the MCP `Tool` DSL. Lowers to the engine's `HTTPHandling` contract. |
| **ADServeObservability** | Opt-in swift-metrics + swift-distributed-tracing middleware; a consumer of the bare engine never resolves them. |
| **ADMCP** | The transport-agnostic MCP JSON-RPC core + `Tool` DSL as its own product — usable over stdio without the HTTP engine. **Unchanged by the engine migration** (it never depended on it). |

## The engine underneath

ADServe used to bootstrap SwiftNIO channels; it now drives the [HTTP] package end to end and
resolves **no NIO package at all** (verify: `swift package show-dependencies` — the graph is
swift-log/-crypto/-service-lifecycle + the observability trio + ADJSON/ADFoundation + HTTP).

- **Currency types** are `HTTPCore`'s: `HTTPMethod`, `HTTPStatus`, `HTTPFields`/`HTTPFieldName`
  (ordered, validation-aware — set with `setValue(_:for:)`, append repeatables like `Set-Cookie`).
- **Routing** stays ADServe's trie-dispatched `HTTPHandling`; the engine queries it at the request
  *head* (before the body buffers) for per-route body limits, the streaming opt-in, and WebSocket
  endpoints.
- **WebSockets** are route-scoped on the engine's sans-I/O seam: a handler receives connection
  events (`.message`/`.ping`/`.pong`/`.close`) and returns the actions to send; fragmented frames
  are reassembled and pings auto-ponged before your handler sees them. Server push rides the
  engine's `WebSocketHub` (`Channel(_:on:topic:)` auto-subscribes each connection;
  `hub.broadcast(_:to:)` fans out). ADServe's same-origin CSWSH gate wraps every handler.
- **TLS** listeners take PEM material (`TLSSource.pem`) and bind Network.framework; the PEM pair is
  converted to the transport's PKCS#12 identity at bind time via the system `openssl`. Mutual TLS
  (`clientVerification: .required`) surfaces the verified peer as `ctx.tlsPeerSubject`.
- **UNIX-domain sockets** keep working (`ListenerConfig(unixDomainSocketPath:)`) via an in-house
  `AF_UNIX` transport on the package's public `ServerTransport` seam.
- **Compression**: eligible buffered responses are gzipped (mime-db-compressible, ≥ ~1 MTU, client
  accepts, never ranges/SSE/pre-encoded). Streamed responses and static files are never compressed
  on the fly — ship precompressed `.br`/`.gz` sidecars, which the static path negotiates.
- Blocking work (`.storage` handlers, static-file stat/read) runs on `ADConcurrency`'s
  `BlockingOffloadPool` (`threadCount` wide), never on the cooperative pool.

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

A `.storage` route's handler reaches the resource via `ctx.connection` (type-erased) and
down-casts to its concrete type — the app's invariant: the pool holds exactly that type. A server
with no `.storage` routes passes `pool: nil` and depends on no storage package at all.

## Layering

`ADServe` depends only on the in-house [HTTP] engine, a slim swift-server/apple floor
(swift-log/-crypto/-service-lifecycle), and the `AD*` family (`ADJSON`, `ADFoundation`). It has
**no dependency on any persistence package** and **no dependency on SwiftNIO** (verify both:
`swift package show-dependencies`). Keep it that way — that is what makes it reusable.

## Versioning & pinning

The first-party deps (`HTTP`, `ADJSON`, `ADFoundation`) follow the g-cqd `AD*` family policy:

- **Today (pre-1.0):** every first-party dependency resolves by `branch: "main"` — there are no
  semver tags yet, so the graph tracks the tip of main. (The apple/swift-server floor is already
  version-pinned by SwiftPM requirements.)
- **Planned:** cut semver tags (0.x stabilizing toward 1.0) for the siblings and pin the resolved
  graph via the **committed `Package.resolved`** (already in this repo — it pins the exact
  revisions resolution uses), so a clean checkout builds what CI validated.
- **Local development:** override a first-party dependency to a sibling checkout with its `*_PATH`
  env var — `HTTP_PATH`, `ADJSON_PATH`, `ADFOUNDATION_PATH`. Never set a `*_PATH` in CI or a
  release build; those resolve the published package.

## Build

```sh
swift build
swift test
```

[HTTP]: https://github.com/g-cqd/HTTP
[ADJSON]: https://github.com/g-cqd/ADJSON
[ADFoundation]: https://github.com/g-cqd/ADFoundation
