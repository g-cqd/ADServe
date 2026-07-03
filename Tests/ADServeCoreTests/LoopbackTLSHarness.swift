// A TLS + HTTP/2 loopback client, the secure counterpart to `Loopback` (which is h1 plaintext). It
// binds an `HTTPServer` on an ephemeral self-signed cert and drives real requests over TLS with
// ALPN `h2` through URLSession (whose HTTP/2 client multiplexes streams over one connection and
// respects the server SETTINGS), asserting the negotiated protocol via task transaction metrics —
// so the streaming / SSE / static paths are integration-tested over HTTP/2 + TLS, not only h1.
// Best-effort teardown + bounded waits, so it can never hang CI.

// Darwin-gated: ADServe serves TLS through the Network.framework backbone (Linux has no
// TLS listener without the engine's opt-in portable-TLS build), and the URLSession h2
// client + task transaction metrics this harness drives live in Darwin Foundation.
#if canImport(Network)

    import Foundation
    import HTTPCore
    import Logging
    import Synchronization

    @testable import ADServeCore

    /// An ephemeral self-signed cert + key, generated once per test process via `openssl` into a temp dir
    /// (cached behind a `Mutex`, so a run with several TLS tests pays the ~50ms generation only once). The
    /// cert is short-lived (1 day) and never committed — "ephemeral" in the literal sense.
    enum EphemeralTLS {
        private static let cached = Mutex<TLSSource?>(nil)

        static func source() throws -> TLSSource {
            try cached.withLock { box in
                if let existing = box { return existing }
                let generated = try generate()
                box = generated
                return generated
            }
        }

        private static func generate() throws -> TLSSource {
            let dir = FileManager.default.temporaryDirectory
                .appendingPathComponent("adserve-tls-\(UInt64.random(in: .min ... .max))")
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let cert = dir.appendingPathComponent("cert.pem").path
            let key = dir.appendingPathComponent("key.pem").path

            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            process.arguments = [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key, "-out", cert,
                "-days", "1", "-nodes", "-subj", "/CN=localhost",
                "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"
            ]
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            try process.run()
            process.waitUntilExit()
            let fileManager = FileManager.default
            guard process.terminationStatus == 0, fileManager.fileExists(atPath: cert),
                fileManager.fileExists(atPath: key)
            else {
                throw TLSHarnessError(message: "openssl self-signed cert generation failed (openssl on PATH?)")
            }
            return .pem(certificate: cert, privateKey: key)
        }
    }

    /// One HTTP/2 response collected by the loopback client.
    struct H2Response {
        let status: Int
        /// Response headers, lowercased names (URLSession preserves case variably; compare lowercased).
        let headerValues: [String: String]
        let body: [UInt8]
        /// The ALPN protocol the task actually used (`"h2"` expected) from the transaction metrics.
        let negotiatedProtocol: String?

        /// The body decoded as UTF-8 text (the streaming/SSE/static bodies under test are text).
        var text: String { String(decoding: body, as: UTF8.self) }
        /// One response header value by (case-insensitive) name, or `nil`.
        func header(_ name: String) -> String? { headerValues[name.lowercased()] }
        /// True if a header named `name` carries `value` (case-insensitive compare on the value).
        func headerEquals(_ name: String, _ value: String) -> Bool {
            header(name)?.lowercased() == value.lowercased()
        }
    }

    /// Trusts the ephemeral self-signed server certificate (test only) and records per-task transaction
    /// metrics so a test can assert the negotiated protocol was h2.
    final class InsecureTrustDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
        private let protocols = Mutex<[Int: String]>([:])

        func urlSession(
            _ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
            completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
        ) {
            if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
                let trust = challenge.protectionSpace.serverTrust
            {
                completionHandler(.useCredential, URLCredential(trust: trust))
            } else {
                completionHandler(.performDefaultHandling, nil)
            }
        }

        func urlSession(
            _ session: URLSession, task: URLSessionTask,
            didFinishCollecting metrics: URLSessionTaskMetrics
        ) {
            if let name = metrics.transactionMetrics.last?.networkProtocolName {
                protocols.withLock { $0[task.taskIdentifier] = name }
            }
        }

        /// The most recently negotiated protocol across the session tasks (one host, one connection).
        var lastProtocol: String? {
            protocols.withLock { state in state.values.first }
        }
    }

    /// Binds an `HTTPServer` (TLS, ALPN `h2`+`http/1.1`) on an OS-assigned loopback port and drives
    /// HTTP/2 requests over it, returning collected responses. The secure/h2 coverage in the suite.
    enum LoopbackTLS {
        /// Serves `routes` over TLS+h2 and performs one request, returning the decoded response.
        static func runH2(
            path: String, routes: any HTTPHandling, method: String = "GET",
            headers: [(name: String, value: String)] = []
        ) async throws -> H2Response {
            let responses = try await withH2Server(routes: routes) { session, delegate, base in
                [
                    try await request(
                        session, delegate: delegate, base: base, path: path, method: method, headers: headers)
                ]
            }
            guard let first = responses.first else { throw TLSHarnessError(message: "no h2 response") }
            return first
        }

        /// One stream result of the concurrent fan-out.
        struct H2StreamResult: Sendable {
            let stream: Int
            let status: Int
            let body: String
        }

        /// Opens `count` CONCURRENT requests through one URLSession pinned to one host connection —
        /// URLSession multiplexes them as h2 streams and respects the server SETTINGS cap, so all
        /// `count` complete even above `maxConcurrentStreams`.
        static func runH2Concurrent(count: Int, path: String = "/", routes: any HTTPHandling)
            async throws -> [H2StreamResult]
        {
            try await withH2Server(routes: routes) { session, delegate, base in
                try await withThrowingTaskGroup(of: H2StreamResult.self) { group in
                    for stream in 0 ..< count {
                        group.addTask {
                            let response = try await request(
                                session, delegate: delegate, base: base, path: path, method: "GET",
                                headers: [(name: "x-stream", value: "\(stream)")])
                            return H2StreamResult(
                                stream: stream, status: response.status, body: response.text)
                        }
                    }
                    var results: [H2StreamResult] = []
                    results.reserveCapacity(count)
                    for try await result in group { results.append(result) }
                    return results
                }
            }
        }

        /// Binds the TLS server, builds the trusting session, runs `body`, and tears everything down.
        private static func withH2Server<R: Sendable>(
            routes: any HTTPHandling,
            _ body: @escaping @Sendable (URLSession, InsecureTrustDelegate, String) async throws -> R
        ) async throws -> R {
            let tls = try EphemeralTLS.source()
            let port = try Loopback.freePort()
            let readiness = ServerReadiness()
            let server = HTTPServer(
                listeners: [
                    ListenerConfig(
                        host: "127.0.0.1", port: port,
                        wire: .https(tls, alpn: [.http2, .http1]), routes: routes)
                ],
                pool: nil, envelope: HTTPFields(), logger: Logger(label: "loopback-tls"),
                threadCount: 2, loopCount: 1, readiness: readiness)
            let serverTask = Task { try? await server.run() }
            defer { serverTask.cancel() }
            try await Loopback.awaitReadiness(readiness)

            let delegate = InsecureTrustDelegate()
            let configuration = URLSessionConfiguration.ephemeral
            configuration.httpMaximumConnectionsPerHost = 1  // force h2 multiplexing over ONE connection
            configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
            let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
            defer { session.invalidateAndCancel() }
            return try await body(session, delegate, "https://127.0.0.1:\(port)")
        }

        /// One request through the trusting session, decoded into an `H2Response`.
        private static func request(
            _ session: URLSession, delegate: InsecureTrustDelegate, base: String, path: String,
            method: String, headers: [(name: String, value: String)]
        ) async throws -> H2Response {
            guard let url = URL(string: base + path) else {
                throw TLSHarnessError(message: "bad URL \(base + path)")
            }
            var request = URLRequest(url: url)
            request.httpMethod = method
            for header in headers { request.setValue(header.value, forHTTPHeaderField: header.name) }
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse else {
                throw TLSHarnessError(message: "non-HTTP response")
            }
            var headerValues: [String: String] = [:]
            for (name, value) in http.allHeaderFields {
                if let name = name as? String, let value = value as? String {
                    headerValues[name.lowercased()] = value
                }
            }
            // The metrics delegate fires before the task completes, so the protocol is recorded by now.
            return H2Response(
                status: http.statusCode, headerValues: headerValues, body: [UInt8](data),
                negotiatedProtocol: delegate.lastProtocol)
        }
    }

#endif
