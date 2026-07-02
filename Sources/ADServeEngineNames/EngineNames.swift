// The engine-name shim. ADServeCore's own public engine type is named `HTTPServer`, and in Swift a
// same-named local type shadows the module for qualification — `HTTPServer.HTTPServer<…>` cannot be
// spelled there. This module has no such clash, so it re-exports the handful of HTTP-package server
// names ADServeCore needs under `HTTPEngine*` typealiases. Nothing else lives here.

public import HTTPServer

/// The HTTP package's serving engine (`HTTPServer` from the `HTTPServer` module), specialized to
/// the production clock.
public typealias HTTPEngineServer = HTTPServer<ContinuousClock>

/// The HTTP package's chunk-writer seam a `ResponseStream` producer writes through.
public typealias HTTPEngineBodyWriter = ResponseBodyWriter

/// The HTTP package's topic-keyed WebSocket broadcast hub.
public typealias HTTPEngineWebSocketHub = WebSocketHub
