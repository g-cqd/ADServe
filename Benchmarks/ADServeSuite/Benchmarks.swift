import ADFCore
import ADServeCore
import ADServeDSL
import Benchmark
import HTTPCore

// ADServe's benchmark suite on ordo-one's framework, matching the sibling ADFoundation / ADJSON / ADDB
// suites. Run with `ADSERVE_DEV=1 swift package benchmark`. The guards track `.mallocCountTotal` (CI
// installs jemalloc) so a reintroduced allocation in the hot request/response paths trips the threshold
// instead of rotting silently. The suite imports ADServeCore + ADServeDSL + ADFCore as PRODUCTS (not
// `@testable`), so every case below exercises PUBLIC API — the same surface an app pins.
//
// Grouped `category/name`, inputs built ONCE outside each `scaledIterations` loop, and the
// borrowed-vs-copy pairs (`percent/decode borrowed` vs `… copy`) isolate the cost of the `[UInt8]`
// allocation the zero-copy path avoids — the malloc-count delta the byte kernels are holding.
//
// INTERNAL hot paths a `package`-level benchmark seam should expose (unreachable from a products-only
// import, so deliberately NOT forced open here):
//   - `HTTPDate.format(_:)` / `HTTPDate.parse(_:)` (Cookies/HTTPDate.swift) — `Last-Modified` /
//     `If-Modified-Since` formatting + parsing, run on every conditional static-file request.
//   - `HTTPResponder.commonHeaders(_:)` + `materialize(_:)` (HTTPServerRespond.swift) — the per-response
//     security/Vary/request-id header set + the `ResponseContent` → bytes/status/ETag lowering, the
//     single hottest response-side path (runs once per request).
//   - `SSEFraming.event/comment` (HTTPServerRespond.swift) — the `text/event-stream` frame serializer.
//   - `MIMEDatabase.isCompressible(type:)` + `MIMEDatabase.entry(forExtension:)` (Generated/MIMEDatabase
//     .swift) — the generated lookup is reached here through the public `MediaType(fileExtension:)`
//     wrapper (the `mime/*` group below), but the bare `isCompressible(type:)` content-negotiation probe
//     has no public surface.

nonisolated(unsafe) let benchmarks = {
    let cowMetrics = Benchmark.Configuration(metrics: [.wallClock, .throughput, .mallocCountTotal])

    // MARK: cookies  (request-header parse + Set-Cookie serialize — run per request)

    // RFC 6265 `Cookie:` headers at increasing pair counts: a single pair (a bare session id), a
    // typical browser header (~5 pairs, one quoted value the parser strips), and a "farm" header an
    // analytics-heavy site sends (~20 pairs). The parser splits on `;`, trims OWS, and last-wins on a
    // duplicate name — so the per-pair cost (and any re-introduced allocation) scales with this.
    let cookie1 = "session=abc123"
    let cookieTypical = "session=abc123; theme=\"dark\"; lang=en-US; _ga=GA1.2.345; csrf=t0k3n"
    let cookieFarm = (0 ..< 20).map { "k\($0)=v\($0)x\($0 &* 7)" }.joined(separator: "; ")
    Benchmark("cookies/parse 1-pair", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(RequestCookies(cookie1)) }
    }
    Benchmark("cookies/parse 5-pair", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(RequestCookies(cookieTypical)) }
    }
    Benchmark("cookies/parse 20-pair", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(RequestCookies(cookieFarm)) }
    }

    // Set-Cookie serialization: the minimal delete idiom (`name=; Path=/; Max-Age=0` via `.expiring`)
    // vs a fully-attributed session cookie (the secure-by-intent shape — Path/Domain/Max-Age + the
    // Secure/HttpOnly/SameSite flags). Each present attribute is a sanitize + append, so the attributed
    // form measures the full header-build cost.
    let setCookieMinimal = SetCookie.expiring("session")
    let setCookieAttributed = SetCookie(
        name: "session", value: "abc123def456", path: "/", domain: "example.com",
        maxAge: 3600, secure: true, httpOnly: true, sameSite: .lax)
    Benchmark("cookies/serialize minimal", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(setCookieMinimal.headerValue) }
    }
    Benchmark("cookies/serialize attributed", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(setCookieAttributed.headerValue) }
    }

    // MARK: routing  (DSL `RouteTable.match` — the per-request trie descent)

    // One representative table, built ONCE (a public `Server { App { … } }` lowered to its `RouteTable`
    // via `listeners(_:defaultPort:)[0].routes`). The handler bodies never run — `match` only descends
    // the trie and `bind`s the concrete path — so each case below times pure routing: literal lookup,
    // `{param}` capture (+ its percent-decode), the catch-all remainder, and the 404 / 405 verdicts.
    let routes: any HTTPHandling = listeners(
        Server {
            App(pool: .none) {
                GET("health", pool: .none) { _ in .plain(.ok, "ok") }
                GET("users/{id}", pool: .none) { _, params in .plain(.ok, params.id ?? "?") }
                DELETE("users/{id}", pool: .none) { _, _ in .plain(.ok, "deleted") }
                GET("users/{id}/posts/{postID}", pool: .none) { _, params in .plain(.ok, params.id ?? "?") }
                GET("orgs/{org}/repos/{repo}/commits/{sha}", pool: .none) { _, params in
                    .plain(.ok, params.org ?? "?")
                }
                GET("files/{path*}", pool: .none) { _, params in .plain(.ok, params.path ?? "?") }
            }
        }, defaultPort: 8080)[0]
        .routes

    Benchmark("routing/exact hit", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(routes.match(method: .get, path: "/health"[...])) }
    }
    Benchmark("routing/param 1-capture", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(routes.match(method: .get, path: "/users/42"[...])) }
    }
    Benchmark("routing/param 2-capture", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(routes.match(method: .get, path: "/users/42/posts/7"[...])) }
    }
    Benchmark("routing/param 3-capture", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations {
            blackHole(routes.match(method: .get, path: "/orgs/swift/repos/server/commits/abc123"[...]))
        }
    }
    Benchmark("routing/catch-all", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(routes.match(method: .get, path: "/files/a/b/c/d.txt"[...])) }
    }
    // A `{param}` segment carrying percent-escapes — the match drives `PathTemplate.decodeSegment` →
    // `PercentCoding.decode` per captured segment (vs the un-encoded `param 1-capture` baseline).
    Benchmark("routing/param encoded", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations {
            blackHole(routes.match(method: .get, path: "/users/a%20b%2Dc%5Fd"[...]))
        }
    }
    // The negative verdicts: an unknown path (full trie miss → `.notFound`) and a known path under an
    // unbound method (the `Allow`-set scan → `.methodNotAllowed`) — both walk the trie to exhaustion.
    Benchmark("routing/miss notFound", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(routes.match(method: .get, path: "/nope/missing"[...])) }
    }
    Benchmark("routing/method 405", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(routes.match(method: .put, path: "/users/42"[...])) }
    }

    // MARK: mime  (file-extension → media-type — the generated mime-db table via its public wrapper)

    // `MediaType(fileExtension:)` / `MediaType(path:)` lower to the generated `MIMEDatabase` string-switch
    // (a hashed jump, no parsing) — the `Static` content-type lookup, run per asset request. A hit
    // (`css`), an unknown extension (`nil` — the negative branch), the path-form (final-segment ext
    // extraction first), and the bare ext-split helper.
    Benchmark("mime/ext hit", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(MediaType(fileExtension: "css")) }
    }
    Benchmark("mime/ext miss", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(MediaType(fileExtension: "qqq")) }
    }
    Benchmark("mime/path lookup", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(MediaType(path: "/assets/app.min.css")) }
    }
    Benchmark("mime/ext extract", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(MediaType.fileExtension(of: "/assets/app.min.css")) }
    }

    // MARK: content  (ResponseContent factories — the per-handler return construction)

    // The typed-body factories a handler returns. All lower to a `.raw(body:contentType:status:)` case —
    // the bytes ride by reference (no copy), so this measures the enum wrap + the content-type wiring,
    // not a payload copy. A representative HTML page + a JSON document, sized once.
    let htmlBytes = [UInt8]("<!doctype html><title>x</title><h1>Hello</h1>".utf8)
    let jsonBytes = [UInt8](#"{"id":7,"name":"gear","tags":["a","b"]}"#.utf8)
    Benchmark("content/html", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(ResponseContent.html(htmlBytes)) }
    }
    Benchmark("content/json", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(ResponseContent.json(jsonBytes)) }
    }
    Benchmark("content/fragment", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(ResponseContent.fragment(htmlBytes)) }
    }
    Benchmark("content/raw", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations {
            blackHole(ResponseContent.raw(body: jsonBytes, contentType: "application/json", status: .ok))
        }
    }
    Benchmark("content/text typed", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(ResponseContent.text(htmlBytes, as: .text)) }
    }

    // MARK: percent  (RFC 3986 percent-coding — `ADFCore.PercentCoding`, the path/query decode kernel)

    // The decode hot path at three escape densities: none (the common case — a pure copy/scan, the
    // fast exit), light (~1 escape per token, a typical path capture), and heavy (every byte escaped, a
    // hostile/worst-case query value). `decode` returns `nil` on a malformed escape rather than trapping.
    let percentNone = [UInt8]("the-quick-brown-fox-jumps-over-the-lazy-dog".utf8)
    let percentLight = [UInt8]("hello%20world%2Ffoo%20bar%20baz".utf8)
    let percentHeavy = [UInt8](String(repeating: "%20", count: 64).utf8)
    Benchmark("percent/decode none", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(PercentCoding.decode(percentNone)) }
    }
    Benchmark("percent/decode light", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(PercentCoding.decode(percentLight)) }
    }
    Benchmark("percent/decode heavy", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(PercentCoding.decode(percentHeavy)) }
    }
    // The `application/x-www-form-urlencoded` variant (`+` → space) + the encode direction (escaping
    // everything outside the unreserved set), so the query-component round trip is covered both ways.
    let formValue = [UInt8]("hello+world&q=a%20b+c".utf8)
    let encodeInput = [UInt8]("a b/c?d=e&f g".utf8)
    Benchmark("percent/decodeForm", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(PercentCoding.decodeForm(formValue)) }
    }
    Benchmark("percent/encode", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(PercentCoding.encode(encodeInput)) }
    }

    // BORROWED-vs-COPY: `decode` takes `some Collection<UInt8>`, so the same bytes can arrive as a
    // borrowed `ArraySlice` (zero-copy — the engine decodes straight off the request buffer) or as a
    // freshly-allocated `[UInt8]`. The pair's malloc-count delta is exactly the cost of that one input
    // copy — the allocation the borrowed call site avoids on every decoded path/query segment.
    Benchmark("percent/decode borrowed", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(PercentCoding.decode(percentLight[...])) }
    }
    Benchmark("percent/decode copy", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(PercentCoding.decode([UInt8](percentLight))) }
    }

    // MARK: form  (in-house body parsing — `URLEncodedForm` + `multipart/form-data`, public, no vapor dep)

    // `application/x-www-form-urlencoded` body parse: split on `&`, `+`→space + percent-decode each side,
    // last-wins on a duplicate key — the `ctx.form()` path.
    let urlEncodedBody = [UInt8]("name=Jane+Doe&email=jane%40example.com&role=admin&active=true".utf8)
    Benchmark("form/urlencoded parse", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(URLEncodedForm(urlEncodedBody)) }
    }

    // `multipart/form-data` (RFC 7578): the `boundary=` extraction from the content-type, then the full
    // body parse into parts (a text field + a file part) — the `ctx.multipart()` path, built once.
    let multipartContentType = "multipart/form-data; boundary=----ADServeBoundary7MA4YWxkTrZu0gW"
    let multipartBoundary = MultipartParser.boundary(fromContentType: multipartContentType) ?? ""
    let multipartBody: [UInt8] = {
        let crlf = "\r\n"
        let body =
            "------ADServeBoundary7MA4YWxkTrZu0gW\(crlf)"
            + "Content-Disposition: form-data; name=\"title\"\(crlf)\(crlf)"
            + "A Benchmark Title\(crlf)"
            + "------ADServeBoundary7MA4YWxkTrZu0gW\(crlf)"
            + "Content-Disposition: form-data; name=\"file\"; filename=\"note.txt\"\(crlf)"
            + "Content-Type: text/plain\(crlf)\(crlf)"
            + "the file payload bytes go here\(crlf)"
            + "------ADServeBoundary7MA4YWxkTrZu0gW--\(crlf)"
        return [UInt8](body.utf8)
    }()
    Benchmark("form/multipart boundary", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(MultipartParser.boundary(fromContentType: multipartContentType)) }
    }
    Benchmark("form/multipart parse", configuration: cowMetrics) { bm in
        for _ in bm.scaledIterations { blackHole(MultipartParser.parse(multipartBody, boundary: multipartBoundary)) }
    }
}
