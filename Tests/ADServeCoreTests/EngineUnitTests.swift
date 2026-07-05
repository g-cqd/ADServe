import ADJSON
import HTTPCore
import Testing

@testable import ADServeCore

@Suite struct JsonIntTests {
    @Test func decodesIntegerNumbers() {
        #expect(MCPJSON.int(.number(5)) == 5)
        #expect(MCPJSON.int(.number(3.9)) == 3)
        #expect(MCPJSON.int(.number(-7)) == -7)
    }

    @Test func nonFiniteIsNil() {
        #expect(MCPJSON.int(.number(.infinity)) == nil)
        #expect(MCPJSON.int(.number(-.infinity)) == nil)
        #expect(MCPJSON.int(.number(.nan)) == nil)
    }

    @Test func outOfRangeClampsInsteadOfTrapping() {
        #expect(MCPJSON.int(.number(1e300)) == Int.max)
        #expect(MCPJSON.int(.number(-1e300)) == Int.min)
    }

    @Test func nonNumberIsNil() {
        #expect(MCPJSON.int(.string("5")) == nil)
        #expect(MCPJSON.int(.bool(true)) == nil)
        #expect(MCPJSON.int(nil) == nil)
    }
}

@Suite struct JsonHelperTests {
    @Test func typedAccessors() {
        #expect(MCPJSON.string(.string("hi")) == "hi")
        #expect(MCPJSON.string(.number(5)) == nil)
        #expect(MCPJSON.number(.number(2.5)) == 2.5)
        #expect(MCPJSON.bool(.bool(true)) == true)
        #expect(MCPJSON.array(.array([.number(1)]))?.count == 1)
        #expect(MCPJSON.object(.object(["a": .number(1)]))?["a"] != nil)
        #expect(MCPJSON.number(MCPJSON.member(.object(["a": .number(9)]), "a")) == 9)
    }
}

@Suite struct ConditionalHeaderTests {
    @Test func matchesIfNoneMatchVariants() {
        #expect(ConditionalRequest.matchesIfNoneMatch("*", "\"abc\""))
        #expect(ConditionalRequest.matchesIfNoneMatch("\"abc\"", "\"abc\""))
        #expect(ConditionalRequest.matchesIfNoneMatch("  \"x\" , \"abc\" ", "\"abc\""))
        #expect(!ConditionalRequest.matchesIfNoneMatch("\"zzz\"", "\"abc\""))
    }

    @Test func requestIdEchoedWhenValidElseMinted() {
        var valid = HTTPFields()
        valid.setValue("valid.id-123", for: RequestID.name)
        #expect(RequestID.resolve(valid) == "valid.id-123")

        var invalid = HTTPFields()
        invalid.setValue("has spaces", for: RequestID.name)
        let minted = RequestID.resolve(invalid)
        #expect(minted != "has spaces")
        #expect(minted.count == 36)
        #expect(minted == minted.lowercased())
    }

    @Test func sha256MatchesKnownVector() {
        #expect(
            ConditionalRequest.sha256HexLower(Array("abc".utf8))
                == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }
}

@Suite struct ResponseFactoryTests {
    @Test func htmlMediaTypeValue() {
        #expect(MediaType.html.value == "text/html; charset=utf-8")
    }

    @Test func htmlFactorySetsContentTypeBodyAndDefaultStatus() {
        let bytes = Array("<p>hi</p>".utf8)
        guard case .raw(let body, let contentType, let status) = ResponseContent.html(bytes) else {
            Issue.record("expected .html to lower to .raw")
            return
        }
        #expect(contentType == "text/html; charset=utf-8")
        #expect(body == bytes)
        #expect(status == .ok)
    }

    @Test func htmlFactoryHonorsExplicitStatus() {
        guard case .raw(_, _, let status) = ResponseContent.html([], status: .notFound) else {
            Issue.record("expected .raw")
            return
        }
        #expect(status == .notFound)
    }
}
