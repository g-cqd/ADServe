// M6 streaming request bodies: a streaming route's async handler receives the body as a back-pressured
// AsyncSequence of chunks — a large upload is processed without materializing, exceeds the buffered-body
// cap that a normal route enforces, and `bodyStream.collect(maxBytes:)` bounds it when the handler wants.

import HTTPTypes
import Testing

@testable import ADServeCore

/// A minimal `HTTPHandling` exposing one streaming route (so the Core suite tests M6 without the DSL).
struct StreamingStubRoutes: HTTPHandling {
    let path: String
    let handler: StreamingRequestHandler
    func match(method: HTTPRequest.Method, path: Substring) -> RouteMatch {
        guard path == self.path[...] else { return .notFound }
        let streamingHandler = handler
        return .matched(
            MatchedRoute(
                needsStorage: false, cache: .unset, streamingRun: streamingHandler,
                run: { _ in .plain(.internalServerError, "streaming route\n") }))
    }
}

@Suite struct StreamingBodyTests {
    @Test func largeUploadIsStreamedAndCounted() async throws {
        let bodySize = 700_000
        let body = String(repeating: "x", count: bodySize)
        let routes = StreamingStubRoutes(path: "/upload") { input in
            var total = 0
            var chunks = 0
            for await chunk in input.bodyStream {
                total += chunk.count
                chunks += 1
            }
            return .raw(body: Array("total=\(total);chunks=\(chunks)".utf8), contentType: "text/plain", status: .ok)
        }
        let request =
            "POST /upload HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: \(bodySize)\r\n\r\n\(body)"
        let response = try await Loopback.runRaw(request, routes: routes)
        #expect(response.hasPrefix("HTTP/1.1 200"))
        #expect(response.contains("total=\(bodySize)"))
    }

    @Test func streamingRouteAcceptsABodyLargerThanTheBufferedCap() async throws {
        // 2 MB > the 1 MiB server default — a buffered route would 413; a streaming route accepts it.
        let bodySize = 2_000_000
        let body = String(repeating: "y", count: bodySize)
        let routes = StreamingStubRoutes(path: "/upload") { input in
            var total = 0
            for await chunk in input.bodyStream { total += chunk.count }
            return .raw(body: Array("total=\(total)".utf8), contentType: "text/plain", status: .ok)
        }
        let request =
            "POST /upload HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: \(bodySize)\r\n\r\n\(body)"
        let response = try await Loopback.runRaw(request, routes: routes)
        #expect(response.hasPrefix("HTTP/1.1 200"))
        #expect(response.contains("total=\(bodySize)"))
    }

    @Test func collectEnforcesItsOwnLimit() async throws {
        let bodySize = 100_000
        let body = String(repeating: "z", count: bodySize)
        let routes = StreamingStubRoutes(path: "/upload") { input in
            do {
                _ = try await input.bodyStream.collect(maxBytes: 1000)
                return .plain(.ok, "ok\n")
            } catch {
                return .plain(HTTPResponse.Status(code: 413), "too large\n")
            }
        }
        let request =
            "POST /upload HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: \(bodySize)\r\n\r\n\(body)"
        let response = try await Loopback.runRaw(request, routes: routes)
        #expect(response.hasPrefix("HTTP/1.1 413"))
    }

    @Test func emptyBodyStreamsZeroChunks() async throws {
        let routes = StreamingStubRoutes(path: "/upload") { input in
            var total = 0
            for await chunk in input.bodyStream { total += chunk.count }
            return .raw(body: Array("total=\(total)".utf8), contentType: "text/plain", status: .ok)
        }
        let request = "POST /upload HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        let response = try await Loopback.runRaw(request, routes: routes)
        #expect(response.hasPrefix("HTTP/1.1 200"))
        #expect(response.hasSuffix("total=0"))
    }
}
