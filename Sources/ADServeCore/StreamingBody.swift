// Streaming request bodies (M6): a route variant whose handler is ASYNC and receives the inbound body as
// a back-pressured `AsyncSequence` of byte chunks — for large uploads that must not materialize in memory.
// This introduces the engine's first async handler path, opt-in alongside the synchronous `run` (the
// engine reads the body chunk-by-chunk and hands each to the handler, which throttles the socket reads).

public import HTTPTypes
public import Logging
import Synchronization

// MARK: - Back-pressured hand-off

/// A single-producer / single-consumer, ZERO-buffer async hand-off: `send` suspends until the consumer
/// takes the element (so the producer — the engine reading the socket — is throttled by the consumer's
/// pace), `next` suspends until an element arrives or the stream `finish`es. This is the back-pressure
/// the streaming body needs without buffering: at most one chunk is in flight. In-house (MultipartKit /
/// async-algorithms `AsyncChannel` are excluded / not a dependency).
final class BackpressuredStream<Element: Sendable>: Sendable {
    private struct State {
        var element: Element?
        var producer: CheckedContinuation<Bool, Never>?
        var consumer: CheckedContinuation<Element?, Never>?
        var finished = false  // producer signalled end-of-body
        var consumerClosed = false  // consumer abandoned the body (e.g. a middleware short-circuit)
    }
    private let state = Mutex(State())

    /// Offer one element; suspends until the consumer takes it (zero-buffer rendezvous). Returns `false`
    /// if the consumer has stopped reading — the producer should then stop sending (no deadlock).
    func send(_ element: Element) async -> Bool {
        await withCheckedContinuation { (producer: CheckedContinuation<Bool, Never>) in
            state.withLock { state in
                if state.consumerClosed {
                    producer.resume(returning: false)
                } else if let consumer = state.consumer {
                    state.consumer = nil
                    consumer.resume(returning: element)
                    producer.resume(returning: true)  // handed off directly — no wait
                } else {
                    state.element = element
                    state.producer = producer  // wait until the consumer takes it (or closes)
                }
            }
        }
    }

    /// Signal end-of-stream; wakes a waiting consumer with `nil`.
    func finish() {
        let consumer = state.withLock { state -> CheckedContinuation<Element?, Never>? in
            state.finished = true
            defer { state.consumer = nil }
            return state.consumer
        }
        consumer?.resume(returning: nil)
    }

    /// The consumer is done reading; unblock a waiting producer (its `send` returns `false`) and make
    /// future sends no-ops. Called when the handler finishes without draining the body.
    func closeConsumer() {
        let producer = state.withLock { state -> CheckedContinuation<Bool, Never>? in
            state.consumerClosed = true
            state.element = nil
            defer { state.producer = nil }
            return state.producer
        }
        producer?.resume(returning: false)
    }

    /// Take the next element, or `nil` at end. Resumes a waiting producer once taken.
    func next() async -> Element? {
        await withCheckedContinuation { (consumer: CheckedContinuation<Element?, Never>) in
            state.withLock { state in
                if let element = state.element {
                    state.element = nil
                    let producer = state.producer
                    state.producer = nil
                    consumer.resume(returning: element)
                    producer?.resume(returning: true)
                } else if state.finished {
                    consumer.resume(returning: nil)
                } else {
                    state.consumer = consumer
                }
            }
        }
    }
}

// MARK: - The body sequence the handler sees

/// The inbound request body as an `AsyncSequence` of byte chunks (each a slice the engine read off the
/// socket), back-pressured: iterating slowly throttles the upload. Reach it via the streaming handler's
/// `input.body`. Materialize with `try await body.collect(maxBytes:)` only when you must.
public struct RequestBodyStream: AsyncSequence, Sendable {
    public typealias Element = [UInt8]
    let source: BackpressuredStream<[UInt8]>

    public struct AsyncIterator: AsyncIteratorProtocol {
        let source: BackpressuredStream<[UInt8]>
        public mutating func next() async -> [UInt8]? { await source.next() }
    }
    public func makeAsyncIterator() -> AsyncIterator { AsyncIterator(source: source) }

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

/// The per-request inputs a streaming route's async handler receives: the request (its `body` is EMPTY —
/// read `bodyStream` instead), the back-pressured `bodyStream`, and the usual logger / id / codec / storage.
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

/// An async handler for a streaming-upload route — it consumes `input.bodyStream` (back-pressured) and
/// returns the response. The engine drives the body off the socket while this runs.
public typealias StreamingRequestHandler = @Sendable (StreamingHandlerInput) async throws -> ResponseContent

extension HTTPHandling {
    /// The streaming async handler for `method`+`path` (a route that consumes its body incrementally), or
    /// `nil` for a normal buffered route. The engine peeks this at the request head — BEFORE draining the
    /// body — so a streaming upload is never materialized. Resolves generically via a `MatchedRoute`'s
    /// `streamingRun`.
    public func streamingHandler(method: HTTPRequest.Method, path: Substring) -> StreamingRequestHandler? {
        guard case .matched(let route) = match(method: method, path: path) else { return nil }
        return route.streamingRun
    }
}
