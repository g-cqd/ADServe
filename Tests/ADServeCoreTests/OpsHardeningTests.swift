// M1 ops-hardening coverage: cookies (request parse + Set-Cookie build), HSTS + Permissions-Policy on
// SecurityHeaders, `Expect: 100-continue`, and the max-connection cap (503 + close past the limit).

import ADTestKit
import Foundation
import HTTPTypes
import Logging
import NIOCore
import NIOPosix
import Testing

@testable import ADServeCore

// MARK: - Cookies

@Suite struct CookieTests {
    @Test func parsesCookieHeaderPairs() {
        let cookies = RequestCookies("session=abc123; theme=dark; empty=")
        #expect(cookies["session"] == "abc123")
        #expect(cookies["theme"] == "dark")
        #expect(cookies["empty"] == "")
        #expect(cookies["absent"] == nil)
        #expect(cookies.contains("session"))
        #expect(!cookies.isEmpty)
        #expect(cookies.all.count == 3)
    }

    @Test func stripsAQuotedValue() {
        #expect(RequestCookies(#"a="quoted value""#)["a"] == "quoted value")
    }

    @Test func toleratesWhitespaceAroundNames() {
        let cookies = RequestCookies("  a=1;b=2 ;  c=3")
        #expect(cookies["a"] == "1")
        #expect(cookies["b"] == "2 ")  // trailing OWS belongs to the value per RFC 6265, only the name trims
        #expect(cookies["c"] == "3")
    }

    @Test func emptyOrNilHeaderYieldsNoCookies() {
        #expect(RequestCookies(nil).isEmpty)
        #expect(RequestCookies("").isEmpty)
    }

    @Test func lastValueWinsOnDuplicateName() {
        #expect(RequestCookies("a=1; a=2")["a"] == "2")
    }

    @Test func setCookieSerializesEveryAttributeInOrder() {
        let cookie = SetCookie(
            name: "session", value: "xyz", path: "/app", domain: "example.com", maxAge: 3600,
            secure: true, httpOnly: true, sameSite: .lax)
        #expect(
            cookie.headerValue
                == "session=xyz; Path=/app; Domain=example.com; Max-Age=3600; Secure; HttpOnly; SameSite=Lax")
    }

    @Test func setCookieOmitsAbsentAttributes() {
        #expect(SetCookie(name: "a", value: "b", path: nil).headerValue == "a=b")
    }

    @Test func expiringCookieDeletesWithMaxAgeZero() {
        #expect(SetCookie.expiring("session").headerValue == "session=; Path=/; Max-Age=0")
    }
}

@Suite struct CookieIntegrationTests {
    @Test func settingCookieEmitsSetCookieHeader() async throws {
        let routes = StubRoutes { _ in
            ResponseContent.raw(body: Array("ok".utf8), contentType: "text/plain", status: .ok)
                .settingCookie(
                    SetCookie(
                        name: "session", value: "xyz", maxAge: 600, secure: true, httpOnly: true, sameSite: .strict))
        }
        let response = try await Loopback.run(path: "/", routes: routes)
        let lower = response.lowercased()
        #expect(lower.contains("set-cookie: session=xyz"))
        #expect(response.contains("Secure"))
        #expect(response.contains("HttpOnly"))
        #expect(response.contains("SameSite=Strict"))
    }

    @Test func multipleCookiesEmitSeparateSetCookieHeaders() async throws {
        let routes = StubRoutes { _ in
            ResponseContent.raw(body: [], contentType: "text/plain", status: .ok)
                .settingCookie(SetCookie(name: "a", value: "1"))
                .settingCookie(SetCookie(name: "b", value: "2"))
        }
        let response = try await Loopback.run(path: "/", routes: routes)
        let count = response.lowercased().components(separatedBy: "set-cookie:").count - 1
        #expect(count == 2)  // appended, never collapsed into one header
        #expect(response.contains("a=1"))
        #expect(response.contains("b=2"))
    }

    @Test func requestCookiesAreParsedFromTheHeader() async throws {
        let routes = StubRoutes { request in
            let value = RequestCookies(request.headers[.cookie])["session"] ?? "none"
            return .raw(body: Array(value.utf8), contentType: "text/plain", status: .ok)
        }
        let response = try await Loopback.run(
            path: "/", routes: routes, headers: [("Cookie", "session=abc; other=1")])
        #expect(response.hasSuffix("abc"))
    }
}

// MARK: - Security headers

@Suite struct SecurityHeaderTests {
    private func value(_ headers: HTTPFields, _ name: String) -> String? { headers[HTTPField.Name(name)!] }

    @Test func defaultsIncludePermissionsPolicy() {
        let policy = value(SecurityHeaders().headers, "permissions-policy")
        #expect(policy?.contains("camera=()") == true)
        #expect(policy?.contains("geolocation=()") == true)
    }

    @Test func hstsIsAbsentByDefault() {
        #expect(value(SecurityHeaders().headers, "strict-transport-security") == nil)
    }

    @Test func hstsHeaderBuiltFromPolicy() {
        let headers = SecurityHeaders(
            hsts: .init(maxAgeSeconds: 63_072_000, includeSubdomains: true, preload: true)
        )
        .headers
        #expect(
            value(headers, "strict-transport-security") == "max-age=63072000; includeSubDomains; preload")
    }

    @Test func hstsAppliesEvenOverACustomHeaderSet() {
        let headers = SecurityHeaders(HTTPFields(), hsts: .init(maxAgeSeconds: 100, includeSubdomains: false))
            .headers
        #expect(value(headers, "strict-transport-security") == "max-age=100")
    }
}

// MARK: - Expect: 100-continue

@Suite struct ExpectContinueTests {
    /// A request announcing `Expect: 100-continue` must receive the `100 Continue` interim BEFORE the
    /// final response — the engine writes it as soon as it sees the head (before draining the body).
    @Test func engineSendsInterimContinueBeforeTheFinalResponse() async throws {
        let routes = StubRoutes { _ in .raw(body: Array("done".utf8), contentType: "text/plain", status: .ok) }
        let request =
            "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nExpect: 100-continue\r\n"
            + "Content-Length: 5\r\n\r\nhello"
        let response = try await Loopback.runRaw(request, routes: routes)
        #expect(response.contains("HTTP/1.1 100 Continue"))
        #expect(response.contains("HTTP/1.1 200"))
        // The interim precedes the final on the wire.
        let continueIndex = try #require(response.range(of: "100 Continue")).lowerBound
        let finalIndex = try #require(response.range(of: "HTTP/1.1 200")).lowerBound
        #expect(continueIndex < finalIndex)
    }
}

// MARK: - Max connections

@Suite struct ConnectionLimitTests {
    @Test func limiterAcquiresUpToLimitThenRefusesUntilReleased() {
        let limiter = ConnectionLimiter(limit: 2)
        #expect(limiter.tryAcquire())
        #expect(limiter.tryAcquire())
        #expect(!limiter.tryAcquire())  // at capacity
        limiter.release()
        #expect(limiter.tryAcquire())
        #expect(!limiter.tryAcquire())
    }

    @Test func zeroLimitIsUnlimited() {
        let limiter = ConnectionLimiter(limit: 0)
        for _ in 0 ..< 1000 { #expect(limiter.tryAcquire()) }  // never refuses
    }

    /// Integration: one slot, held by a live keep-alive connection, forces the next connection to 503.
    @Test func extraConnectionPastTheLimitGets503() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let firstServed = AsyncEventProbe<Void>()
        let routes = StubRoutes { _ in .raw(body: Array("ok".utf8), contentType: "text/plain", status: .ok) }
        do {
            let probe = try await ServerBootstrap(group: group).bind(host: "127.0.0.1", port: 0).get()
            let port = probe.localAddress?.port ?? 0
            try await probe.close().get()
            let readiness = ServerReadiness()
            let server = HTTPServer(
                listeners: [ListenerConfig(host: "127.0.0.1", port: port, routes: routes)], pool: nil,
                envelope: HTTPFields(), logger: Logger(label: "maxconn"), threadCount: 1, loopCount: 1,
                readiness: readiness, maxConnections: 1)
            let serverTask = Task { try? await server.run() }
            defer { serverTask.cancel() }
            var spins = 0
            while !readiness.isReady && spins < 300 {
                try await Task.sleep(for: .milliseconds(10))
                spins += 1
            }

            // Connection A: keep-alive (no `close`), holds the only slot once served.
            let clientA = try await ClientBootstrap(group: group)
                .channelInitializer { channel in channel.pipeline.addHandler(FirstReadProbe(firstServed)) }
                .connect(host: "127.0.0.1", port: port).get()
            var requestA = clientA.allocator.buffer(capacity: 64)
            requestA.writeString("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            try await clientA.writeAndFlush(requestA).get()
            _ = try await firstServed.wait(forAtLeast: 1, timeout: .seconds(3))  // A served → slot held

            // Connection B: over the cap → 503 + close.
            let bPromise = group.next().makePromise(of: [UInt8].self)
            let clientB = try await ClientBootstrap(group: group)
                .channelInitializer { channel in channel.pipeline.addHandler(EOFCollector(bPromise)) }
                .connect(host: "127.0.0.1", port: port).get()
            var requestB = clientB.allocator.buffer(capacity: 64)
            requestB.writeString("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            try await clientB.writeAndFlush(requestB).get()
            let bResponse = String(decoding: try await bPromise.futureResult.get(), as: UTF8.self)
            #expect(bResponse.hasPrefix("HTTP/1.1 503"))
            #expect(bResponse.lowercased().contains("retry-after:"))

            try? await clientA.close().get()
            try? await clientB.close().get()
            serverTask.cancel()
            try? await group.shutdownGracefully()
        } catch {
            try? await group.shutdownGracefully()
            throw error
        }
    }
}

/// Records into `probe` on the first inbound read.
private final class FirstReadProbe: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    private let probe: AsyncEventProbe<Void>
    private var fired = false
    init(_ probe: AsyncEventProbe<Void>) { self.probe = probe }
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        if !fired {
            fired = true
            probe.record(())
        }
    }
}

/// Accumulates inbound bytes and fulfills `promise` at EOF (`channelInactive`).
private final class EOFCollector: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    private let promise: EventLoopPromise<[UInt8]>
    private var accumulated: [UInt8] = []
    init(_ promise: EventLoopPromise<[UInt8]>) { self.promise = promise }
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        accumulated.append(contentsOf: unwrapInboundIn(data).readableBytesView)
    }
    func channelInactive(context: ChannelHandlerContext) { promise.succeed(accumulated) }
    func errorCaught(context: ChannelHandlerContext, error: any Error) { promise.fail(error) }
}
