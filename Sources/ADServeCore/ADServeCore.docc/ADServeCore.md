# ``ADServeCore``

The `ad-server` engine — the optimizable serving layer the route DSL and the
business logic sit on top of.

## Overview

`ADServeCore` owns the value types a request/response flows through, the NIO
bootstrap and serving loop, a **type-erased** connection pool, the response envelope
(security headers, ETag/304, request-id). It is **persistence-agnostic** — it pools
`any PooledResource` through ``AnyConnectionPool`` and knows nothing route-specific:
routes are declared with ``ADServeDSL`` and matched through the ``HTTPHandling``
contract, and the application pins the concrete connection type at its composition root.

Each listener speaks its ``Wire`` (plaintext HTTP/1.1, or TLS with HTTP/2 +
HTTP/1.1 by ALPN). One blocking handler per `.storage` request is offloaded to a
thread pool with a pooled resource checked out for the duration of the call
(returned on scope exit), so one resource is touched by one thread at a time.

## Topics

### Server

- ``HTTPServer``
- ``ListenerConfig``
- ``ServerReadiness``
- ``EngineTransport``

### Wire & TLS

- ``Wire``
- ``ALPN``
- ``TLSSource``

### Connection pool

- ``AnyConnectionPool``

### Request & response

- ``ServerRequest``
- ``ResponseContent``
- ``MediaType``
- ``CachePolicy``

### Routing contract

- ``HTTPHandling``
- ``HandlerInput``
- ``MatchedRoute``
- ``RouteMatch``

> The Model Context Protocol (MCP) JSON-RPC core + `Tool` DSL now live in the standalone
> **ADMCP** package (re-exported here for source compatibility).

### HTTP helpers

- ``sha256HexLower(_:)``
- ``matchesIfNoneMatch(_:_:)``
- ``resolveRequestID(_:)``
