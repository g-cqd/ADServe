import ADJSON
import HTTPCore
import Testing

@testable import ADServeCore

@Suite struct JsonIntTests {
    @Test func decodesIntegerNumbers() {
        #expect(jsonInt(.number(5)) == 5)
        #expect(jsonInt(.number(3.9)) == 3)
        #expect(jsonInt(.number(-7)) == -7)
    }

    @Test func nonFiniteIsNil() {
        #expect(jsonInt(.number(.infinity)) == nil)
        #expect(jsonInt(.number(-.infinity)) == nil)
        #expect(jsonInt(.number(.nan)) == nil)
    }

    @Test func outOfRangeClampsInsteadOfTrapping() {
        #expect(jsonInt(.number(1e300)) == Int.max)
        #expect(jsonInt(.number(-1e300)) == Int.min)
    }

    @Test func nonNumberIsNil() {
        #expect(jsonInt(.string("5")) == nil)
        #expect(jsonInt(.bool(true)) == nil)
        #expect(jsonInt(nil) == nil)
    }
}

@Suite struct JsonHelperTests {
    @Test func typedAccessors() {
        #expect(jsonString(.string("hi")) == "hi")
        #expect(jsonString(.number(5)) == nil)
        #expect(jsonNumber(.number(2.5)) == 2.5)
        #expect(jsonBool(.bool(true)) == true)
        #expect(jsonArray(.array([.number(1)]))?.count == 1)
        #expect(jsonObject(.object(["a": .number(1)]))?["a"] != nil)
        #expect(jsonNumber(jsonMember(.object(["a": .number(9)]), "a")) == 9)
    }
}

@Suite struct ConditionalHeaderTests {
    @Test func matchesIfNoneMatchVariants() {
        #expect(matchesIfNoneMatch("*", "\"abc\""))
        #expect(matchesIfNoneMatch("\"abc\"", "\"abc\""))
        #expect(matchesIfNoneMatch("  \"x\" , \"abc\" ", "\"abc\""))
        #expect(!matchesIfNoneMatch("\"zzz\"", "\"abc\""))
    }

    @Test func requestIdEchoedWhenValidElseMinted() {
        var valid = HTTPFields()
        valid.setValue("valid.id-123", for: requestIDName)
        #expect(resolveRequestID(valid) == "valid.id-123")

        var invalid = HTTPFields()
        invalid.setValue("has spaces", for: requestIDName)
        let minted = resolveRequestID(invalid)
        #expect(minted != "has spaces")
        #expect(minted.count == 36)
        #expect(minted == minted.lowercased())
    }

    @Test func sha256MatchesKnownVector() {
        #expect(
            sha256HexLower(Array("abc".utf8))
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
