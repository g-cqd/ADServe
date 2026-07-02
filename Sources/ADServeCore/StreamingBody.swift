// Streaming request bodies: a route variant whose handler is ASYNC and receives the inbound
// body as an incremental `AsyncSequence` of byte chunks — for large uploads that must not
// materialize in memory. The engine resolves the streaming opt-in at the request HEAD (via the
// `RouteResolver` seam) and delivers the body as it arrives off the wire, draining it to completion
// even if the handler abandons the stream (so keep-alive framing stays exact).

public import HTTPCore
public import HTTPServer
public import Logging

// MARK: - The body sequence the handler sees

/// The inbound request body as an `AsyncSequence` of byte chunks (each a slice the engine read off
/// the socket), delivered incrementally. Reach it via the streaming handler's `input.bodyStream`.
/// Materialize with `try await body.collect(maxBytes:)` only when you must.
public struct RequestBodyStream: AsyncSequence, Sendable {
    public typealias Element = [UInt8]
    let base: HTTPRequestBodyStream

    /// Wraps the engine's incremental body stream.
    public init(base: HTTPRequestBodyStream) {
        self.base = base
    }

    public struct AsyncIterator: AsyncIteratorProtocol {
        var base: HTTPRequestBodyStream.Iterator
        public mutating func next() async -> [UInt8]? { await base.next() }
    }

    public func makeAsyncIterator() -> AsyncIterator {
        AsyncIterator(base: base.makeAsyncIterator())
    }

    /// Drain the whole body into one `[UInt8]`, throwing `HTTPError.contentTooLarge` past `maxBytes` —
    /// the escape hatch for a handler that wants the buffered body after all (still bounded).
    public func collect(maxBytes: Int) async throws -> [UInt8] {
        var out: [UInt8] = []
        for await chunk in self {
            out.append(contentsOf: chunk)
            if out.count > maxBytes {
                throw HTTPError.contentTooLarge("streamed body exceeds the \(maxBytes)-byte limit")
            }
        }
        return out
    }
}

// MARK: - Streaming route contract

/// The per-request inputs a streaming route's async handler receives: the request (its `body` is
/// EMPTY — read `bodyStream` instead), the incremental `bodyStream`, and the usual logger / id /
/// codec / storage.
public struct StreamingHandlerInput: Sendable {
    public let request: ServerRequest
    public let bodyStream: RequestBodyStream
    public let logger: Logger
    public let requestID: String
    public let codec: ContentCodec
    public let storage: RequestStorage

    public init(
        request: ServerRequest, bodyStream: RequestBodyStream, logger: Logger, requestID: String,
        codec: ContentCodec = .json, storage: RequestStorage = RequestStorage()
    ) {
        self.request = request
        self.bodyStream = bodyStream
        self.logger = logger
        self.requestID = requestID
        self.codec = codec
        self.storage = storage
    }
}

/// An async handler for a streaming-upload route — it consumes `input.bodyStream` and returns the
/// response. The engine drives the body off the socket while this runs, and drains any remainder
/// the handler abandons so the connection's framing stays exact.
public typealias StreamingRequestHandler = @Sendable (StreamingHandlerInput) async throws -> ResponseContent

extension HTTPHandling {
    /// The streaming async handler for `method`+`path` (a route that consumes its body incrementally),
    /// or `nil` for a normal buffered route. The engine resolves this at the request head — BEFORE
    /// draining the body — so a streaming upload is never materialized. Resolves generically via a
    /// `MatchedRoute`'s `streamingRun`.
    public func streamingHandler(method: HTTPMethod, path: Substring) -> StreamingRequestHandler? {
        guard case .matched(let route) = match(method: method, path: path) else { return nil }
        return route.streamingRun
    }
}
