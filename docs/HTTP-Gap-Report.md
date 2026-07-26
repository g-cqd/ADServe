# ADServe → HTTP: capabilities ADServe has that HTTP currently lacks

**Audience:** the `../HTTP` team.
**Purpose:** ADServe is being re-based to sit on top of the `HTTP` package as a thin layer
(MCP + typed route DSL + persistence pool + OpenAPI + body codecs). This document lists the things
ADServe provides today that `HTTP` does not yet, grouped by whether they **block** that re-basing.
Shared so the HTTP team can decide what to absorb; ADServe can revisit its own implementation later.

Status legend: **Blocking** = ADServe cannot reach feature parity on top of HTTP without it.
**Non-blocking** = ADServe carries its own layer today, but upstreaming benefits every HTTP consumer.

---

## Blocking — seams HTTP must expose for ADServe to reach parity

### G1 — Per-request connection context in the responder seam
`HTTPResponder.respond(to:body:)` exposes no peer address, TLS peer subject / client certificate,
`isSecure`, connection id, or a per-request mutable bag. ADServe needs these for `ctx.remoteAddress`,
peer-certificate access, request-id propagation, and to attach the pooled DB handle to its storage
context.

*Verified:* `HTTPResponder` is `func respond(to request: HTTPRequest, body: [UInt8]) async ->
ServerResponse` — nothing else is threaded through.

*Suggested shape:* a context parameter (or a task-local) carrying `TransportConnection`'s `peer` /
`tlsPeerSubject` / `isSecure` / `id` plus an opaque typed storage bag, made available to the
responder. (`TransportConnection` already carries all of these — they just are not surfaced to the
responder.)

*Until then:* `remoteAddress` and `peerCertificateDER` degrade to `nil` in ADServe.

### G2 — Streaming (back-pressured) request body
The full body is buffered to `[UInt8]` before the responder runs. ADServe upload routes (`Stream(...)`)
need incremental delivery; the HTTP/1 chunked and HTTP/2-3 DATA frames already arrive incrementally
inside the engine.

*Suggested shape:* an opt-in `AsyncSequence<[UInt8]>` / back-pressured body hook on the responder
seam, with a per-route opt-out of buffering.

*Until then:* ADServe `Stream(...)` routes are stubbed (`501`) and tracked.

### G3 — Route-scoped WebSocket upgrade
HTTP wires a single server-level `webSocketHandler`. ADServe attaches a WS handler per path and
returns `426` to a non-upgrade GET on that path. Needed for the `WS(...)` route, the `Channel(...)`
helper, and the broadcast hub.

*Suggested shape:* per-path WS handler resolution by the responder, or a documented dispatch-by-path
pattern over the server-level handler.

### G4 — Per-route request-body limit
`BodyLimitMiddleware` is a single global cap. ADServe's `.maxBody(_:)` raises or lowers the ceiling
per route (for example an upload endpoint) and ideally applies it **before** the body is buffered.

*Suggested shape:* a per-route body-limit hook visible to the responder at the request head.

*Until then:* ADServe can still enforce the cap after buffering (a `413` post-hoc), but not before.

---

## Non-blocking — nice features HTTP lacks (ADServe carries them; good upstream candidates)

| # | Capability ADServe has | HTTP status | Disposition |
|---|------------------------|-------------|-------------|
| G5 | RFC 9457 `application/problem+json` (typed `HTTPError` + `ProblemDetails`) | only `.text` / `.json` / `.status` | Keep in ADServe; good upstream candidate. |
| G6 | Request form parsers — `x-www-form-urlencoded` + `multipart/form-data` (RFC 7578) | query-string parsing only | Keep in ADServe; good upstream candidate. |
| G7 | Pluggable typed body-codec seam (decode/encode body into typed values; JSON today) | returns raw `[UInt8]` | Stays in ADServe (its codec policy). |
| G8 | Per-request handler timeout → `504` middleware | connection-level idle / slowloris watchdog only | Keep in ADServe; upstream candidate. |
| G9 | Exported HMAC-SHA256 + HKDF signer | `HMACSHA256` / `SHA256` exist but are internal | Ask HTTP to make theirs `public` to dedupe. |
| G10 | Server-side, pluggable session store with TTL | `SessionMiddleware` is stateless signed-cookie only | Keep ADServe's store over HTTP cookie signing; upstream the store seam if shared. |
| G11 | WebSocket topic broadcast hub (fan-out over the WS engine) | WS engine only, no fan-out helper | Keep in ADServe atop HTTP WS (depends on G3). |

---

## Out of scope for HTTP (ADServe-only, listed for completeness)

- **MCP** (Model Context Protocol): JSON-RPC core, tools DSL, and stdio transport. Stays in ADServe.
- **Persistence-agnostic connection pool** (`AnyConnectionPool`). Stays in ADServe.

---

## Migration notes (behavioural deltas ADServe must absorb, not gaps)

- `SetCookie.headerValue` is `String?` (fail-closed) — callers must unwrap.
- `HTTPLimits` defaults are lower (`maxConnections` 65,536); use `.highThroughput` to match permissive
  ceilings.
- ALPN hardening (RFC 7301 §3.2): a TLS connection that negotiated neither `h2` nor `http/1.1` is
  refused rather than downgraded.
- `HTTPMiddleware` is `respond(to:body:next:)` — ADServe re-expresses its onion `composeMiddleware`
  over it.
