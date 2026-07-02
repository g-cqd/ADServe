import ADServeCore
import ADServeDSL
import Foundation
import HTTPCore
import Logging

// A minimal, runnable ADServe server for LIVE load benchmarking — ADSERVE_DEV-gated, never shipped in a
// product. It complements the in-process ordo-one suite (`ADServeSuite`, which times PURE routing under
// `swift package benchmark`) with the one thing that suite structurally cannot give: end-to-end req/s +
// latency percentiles under a real HTTP client over a real socket. It also fills a genuine gap — a server
// framework with no runnable server — so it doubles as the canonical "how do I actually run one" example.
//
// Routes are TechEmpower-shaped so the numbers are recognizable + comparable:
//   GET /plaintext   → "Hello, World!"            (raw request/response overhead — the headline number)
//   GET /json        → a fixed small JSON body    (the response framing/write path; no per-request encode)
//   GET /users/{id}  → echoes the path param      (routing + one path capture)
//   GET /health      → "ok"                        (liveness)
//
// Run:        ADSERVE_DEV=1 swift run -c release ADServeBench [port]
// Load-test:  oha/wrk/bombardier — or the committed Bun harness in Benchmarks/loadtest.js — against
//             http://127.0.0.1:<port>/plaintext.

let port =
    CommandLine.arguments.dropFirst().first.flatMap(Int.init)
    ?? ProcessInfo.processInfo.environment["ADSERVE_BENCH_PORT"].flatMap(Int.init)
    ?? 8080
let threads =
    ProcessInfo.processInfo.environment["ADSERVE_BENCH_THREADS"].flatMap(Int.init)
    ?? ProcessInfo.processInfo.activeProcessorCount
// Event loops (the perf-critical knob: one accept/serve loop per core is the NIO norm). Defaults to the
// engine's `HTTPServer.defaultLoopCount` (= System.coreCount); override with ADSERVE_BENCH_LOOPS to sweep.
let loops =
    ProcessInfo.processInfo.environment["ADSERVE_BENCH_LOOPS"].flatMap(Int.init)
    ?? HTTPServer.defaultLoopCount

var logger = Logger(label: "adserve-bench")
// Suppress per-connection info logs so request logging can't skew throughput; the engine's "listening"
// line is re-raised to info just before run() so the operator still sees the bind.
logger.logLevel = .warning

// One fixed JSON body, encoded ONCE — this route measures the response write/framing path, not JSON
// serialization (that belongs to a separate, dedicated case).
let jsonBody = Array(#"{"message":"Hello, World!"}"#.utf8)
let plaintextBody = "Hello, World!"

let apps = Server {
    App(pool: .none) {
        GET("plaintext", pool: .none) { _ in .plain(.ok, plaintextBody) }
        GET("json", pool: .none) { _ in .json(jsonBody, as: .json) }
        GET("users/{id}", pool: .none) { _, params in .plain(.ok, params.id ?? "?") }
        GET("health", pool: .none) { _ in .plain(.ok, "ok") }
    }
}

// The constant response envelope. Empty by default (the leanest cross-stack comparison vs bare peer
// servers). ADSERVE_BENCH_ENVELOPE=1 installs a realistic security-header set — what a real deployment
// carries on EVERY response — so the bench can represent that work (and exercise the per-response
// envelope-merge path).
var envelope = HTTPFields()
if ProcessInfo.processInfo.environment["ADSERVE_BENCH_ENVELOPE"] != nil {
    envelope.setValue("max-age=63072000; includeSubDomains", for: HTTPFieldName("Strict-Transport-Security")!)
    envelope.setValue("nosniff", for: HTTPFieldName("X-Content-Type-Options")!)
    envelope.setValue("DENY", for: HTTPFieldName("X-Frame-Options")!)
    envelope.setValue("no-referrer", for: HTTPFieldName("Referrer-Policy")!)
    envelope.setValue("default-src 'self'", for: HTTPFieldName("Content-Security-Policy")!)
    envelope.setValue("geolocation=(), microphone=()", for: HTTPFieldName("Permissions-Policy")!)
    envelope.setValue("Accept-Encoding", for: HTTPFieldName("Vary")!)
}

let server = HTTPServer(
    listeners: listeners(apps, defaultPort: port),
    pool: nil, envelope: envelope, logger: logger, threadCount: threads, loopCount: loops)

logger.logLevel = .info
logger.info(
    "adserve-bench starting",
    metadata: ["port": "\(port)", "loops": "\(loops)", "threads": "\(threads)"])
try await server.run()
