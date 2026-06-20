import ADServeCore
import Benchmark

// ADServe's benchmark suite on ordo-one's framework, matching the sibling ADFoundation / ADJSON / ADDB
// suites. Run with `ADSERVE_DEV=1 swift package benchmark`. The guards track `.mallocCountTotal` (CI
// installs jemalloc) so a reintroduced allocation in the hot request/response header paths (cookie
// parse + Set-Cookie serialize, run per request) trips the threshold instead of rotting silently.

nonisolated(unsafe) let benchmarks = {
    let cowMetrics = Benchmark.Configuration(metrics: [.wallClock, .throughput, .mallocCountTotal])

    // Cookie request-header parse — a representative `Cookie:` header with several pairs and a quoted
    // value (the RFC 6265 form the parser strips).
    let cookieHeader = "session=abc123; theme=\"dark\"; lang=en-US; _ga=GA1.2.345; csrf=t0k3n"
    Benchmark("cookies/parse 5-pair", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(RequestCookies(cookieHeader)) }
    }

    // Set-Cookie serialization — a fully-attributed session cookie (the secure-by-intent shape).
    let setCookie = SetCookie(
        name: "session", value: "abc123def456", path: "/", domain: "example.com",
        maxAge: 3600, secure: true, httpOnly: true, sameSite: .lax)
    Benchmark("cookies/serialize attributed", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(setCookie.headerValue) }
    }
}
