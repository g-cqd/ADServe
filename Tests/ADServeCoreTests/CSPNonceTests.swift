import HTTPCore
import Logging
import Testing

@testable import ADServeCore

@Suite struct CSPNonceTests {
    @Test func nonceIs128BitHexAndUniquePerCall() {
        let a = CSPNonce.makeNonce()
        let b = CSPNonce.makeNonce()
        #expect(a.count == 32)  // 16 CSPRNG bytes → 32 hex chars (128 bits)
        #expect(a.allSatisfy { $0.isHexDigit })
        #expect(a != b)  // regenerated per call (a reused nonce would defeat the protection)
    }

    @Test func nonceFlowsToStorageAndMatchesTheCSPHeader() async {
        let ctx = MiddlewareContext(requestID: "r", logger: Logger(label: "t"))
        // The terminal stands in for a handler: it reads the nonce the middleware stored and echoes it,
        // exactly as a real handler would stamp it onto `<script nonce="…">`.
        let chain = composeMiddleware(
            [CSPNonce()], context: ctx,
            terminal: { _ in .plain(.ok, ctx.storage[CSPNonceKey.self] ?? "MISSING") })
        let response = await chain(ServerRequest(method: .get, target: "/", headers: HTTPFields()))
        guard case .full(let body, _, _, let headers) = response else {
            Issue.record("expected withHeaders to promote to .full")
            return
        }
        let nonceHandlerSaw = String(decoding: body, as: UTF8.self)
        #expect(nonceHandlerSaw != "MISSING")  // the handler saw a stored nonce
        let csp = headers[HTTPFieldName("content-security-policy")!] ?? ""
        #expect(csp.contains("'nonce-\(nonceHandlerSaw)'"))  // the CSP carries the SAME nonce
        #expect(csp.contains("strict-dynamic"))  // the default strict policy
    }

    @Test func eachRequestGetsADistinctNonce() async {
        func nonce(for storage: RequestStorage) async -> String {
            let ctx = MiddlewareContext(requestID: "r", logger: Logger(label: "t"), storage: storage)
            let chain = composeMiddleware(
                [CSPNonce()], context: ctx,
                terminal: { _ in .plain(.ok, ctx.storage[CSPNonceKey.self] ?? "MISSING") })
            let response = await chain(ServerRequest(method: .get, target: "/", headers: HTTPFields()))
            guard case .full(let body, _, _, _) = response else { return "MISSING" }
            return String(decoding: body, as: UTF8.self)
        }
        let first = await nonce(for: RequestStorage())
        let second = await nonce(for: RequestStorage())
        #expect(first != second)
    }

    @Test func customPolicyReplacesTheDefault() async {
        let ctx = MiddlewareContext(requestID: "r", logger: Logger(label: "t"))
        let middleware = CSPNonce { nonce in "default-src 'self'; script-src 'nonce-\(nonce)'" }
        let chain = composeMiddleware([middleware], context: ctx, terminal: { _ in .plain(.ok, "x") })
        let response = await chain(ServerRequest(method: .get, target: "/", headers: HTTPFields()))
        guard case .full(_, _, _, let headers) = response else {
            Issue.record("expected .full")
            return
        }
        let csp = headers[HTTPFieldName("content-security-policy")!] ?? ""
        #expect(csp.hasPrefix("default-src 'self'; script-src 'nonce-"))
        #expect(!csp.contains("strict-dynamic"))  // the default policy was not used
    }
}
