// HTTP/2 multiplexing stress: many concurrent streams on ONE connection complete with per-stream-isolated
// responses, even ABOVE the server's advertised SETTINGS_MAX_CONCURRENT_STREAMS (NIO's default 100) — the
// client throttles the excess and they finish as slots free (a graceful cap, not dropped work).

import HTTPTypes
import Testing

@testable import ADServeCore

@Suite struct HTTP2StressTests {
    @Test func manyConcurrentStreamsOnOneConnectionStayIsolatedAndAllComplete() async throws {
        // Each stream sends `x-stream: <i>`; the route echoes it, so a crossed wire (stream i receiving
        // stream j's body) fails the per-stream assertion below.
        let routes = StubRoutes { request in
            let id = request.headers[HTTPField.Name("x-stream")!] ?? "?"
            return .raw(body: Array("stream-\(id)".utf8), contentType: "text/plain", status: .ok)
        }
        let count = 150  // ABOVE the 100-stream cap → the client throttles the excess; all must still finish.
        let results = try await LoopbackTLS.runH2Concurrent(count: count, routes: routes)

        #expect(results.count == count)
        #expect(results.allSatisfy { $0.status == 200 })
        // Per-stream isolation: every stream received exactly its OWN echo, none crossed.
        let byStream = Dictionary(uniqueKeysWithValues: results.map { ($0.stream, $0.body) })
        for index in 0 ..< count {
            #expect(byStream[index] == "stream-\(index)")
        }
    }
}
