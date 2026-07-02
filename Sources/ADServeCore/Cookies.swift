// HTTP cookies (RFC 6265): request-side parsing of the `Cookie:` header and response-side `Set-Cookie`
// building with the standard attributes. In-house (the dependency rule excludes vapor/*); the request
// accessor `ctx.cookies` lives in the DSL, the response side is `ResponseContent.settingCookie(_:)`.
//
// Set-Cookie is the one repeatable RESPONSE header that must not collapse — each cookie is its own
// header line — so `settingCookie` APPENDS a field and the engine's response-header merge appends
// `set-cookie` (overwriting every other name). See `mergeResponseHeaders`.

import HTTPCore

// MARK: - Request cookies

/// The cookies parsed from a request's `Cookie:` header — `name=value` pairs split on `;`. Last value
/// wins on a duplicate name (matching the query-param convention). Built once from the header; reach it
/// via `ctx.cookies` and read with `cookies["session"]`.
public struct RequestCookies: Sendable {
    private let byName: [String: String]

    /// Parse a `Cookie:` header value (`nil`/empty → no cookies). Each pair is `name=value`; an optional
    /// surrounding pair of double quotes on the value is stripped (RFC 6265 `cookie-value` quoted form).
    public init(_ header: String?) {
        guard let header, !header.isEmpty else {
            byName = [:]
            return
        }
        var parsed: [String: String] = [:]
        for pair in header.split(separator: ";") {
            let trimmed = pair.drop { $0 == " " || $0 == "\t" }
            guard let equals = trimmed.firstIndex(of: "=") else { continue }
            let name = trimmed[..<equals].trimmingTrailingSpaces()
            guard !name.isEmpty else { continue }
            var value = Substring(trimmed[trimmed.index(after: equals)...])
            if value.count >= 2, value.first == "\"", value.last == "\"" {
                value = value.dropFirst().dropLast()
            }
            parsed[String(name)] = String(value)
        }
        byName = parsed
    }

    /// The value for `name`, or `nil` if absent.
    public subscript(_ name: String) -> String? { byName[name] }
    /// True if a cookie named `name` is present.
    public func contains(_ name: String) -> Bool { byName[name] != nil }
    /// Every cookie as a name→value map.
    public var all: [String: String] { byName }
    /// `true` if the request carried no cookies.
    public var isEmpty: Bool { byName.isEmpty }
}

// MARK: - Set-Cookie

/// The `SameSite` attribute controlling cross-site send behavior. `none` REQUIRES `secure` (browsers
/// reject `SameSite=None` without `Secure`); set both when you mean it.
public enum SameSite: String, Sendable, CaseIterable {
    case strict = "Strict"
    case lax = "Lax"
    case none = "None"
}

/// A response cookie serialized into a `Set-Cookie` header. Sensible secure defaults are NOT forced —
/// the caller opts into `secure`/`httpOnly`/`sameSite` — but a session cookie should set all three.
/// Expiry is via `maxAge` (seconds; `0` expires immediately, the standard delete idiom with an empty
/// value); the legacy `Expires` date form is intentionally omitted (Max-Age supersedes it).
public struct SetCookie: Sendable {
    public var name: String
    public var value: String
    public var path: String?
    public var domain: String?
    public var maxAge: Int?
    public var secure: Bool
    public var httpOnly: Bool
    public var sameSite: SameSite?

    public init(
        name: String, value: String, path: String? = "/", domain: String? = nil, maxAge: Int? = nil,
        secure: Bool = false, httpOnly: Bool = false, sameSite: SameSite? = nil
    ) {
        self.name = name
        self.value = value
        self.path = path
        self.domain = domain
        self.maxAge = maxAge
        self.secure = secure
        self.httpOnly = httpOnly
        self.sameSite = sameSite
    }

    /// A cookie that deletes `name` on the client: empty value + `Max-Age=0` (expire now). Carry the same
    /// `path`/`domain` the cookie was set with, or the browser keeps the original.
    public static func expiring(_ name: String, path: String? = "/", domain: String? = nil) -> SetCookie {
        SetCookie(name: name, value: "", path: path, domain: domain, maxAge: 0)
    }

    /// The `Set-Cookie` header value: `name=value` plus each present attribute (`Path`/`Domain`/
    /// `Max-Age`/`Secure`/`HttpOnly`/`SameSite`). Caller-controlled components are SANITIZED first
    /// (`sanitized(_:isName:)`) so a hostile value cannot inject a CRLF (HTTP response splitting) or a `;`
    /// (a forged attribute) — defense-in-depth over swift-http-types' own header-value validation.
    public var headerValue: String {
        var out = "\(Self.sanitized(name, isName: true))=\(Self.sanitized(value, isName: false))"
        if let path { out += "; Path=\(Self.sanitized(path, isName: false))" }
        if let domain { out += "; Domain=\(Self.sanitized(domain, isName: false))" }
        if let maxAge { out += "; Max-Age=\(maxAge)" }  // Int → structurally safe
        if secure { out += "; Secure" }
        if httpOnly { out += "; HttpOnly" }
        if let sameSite { out += "; SameSite=\(sameSite.rawValue)" }  // closed enum → safe
        return out
    }

    /// Strips characters that could break out of a `Set-Cookie` field: control characters (CR/LF/NUL/TAB
    /// and the rest of %x00–1F + DEL — the response-splitting / header-injection vector) plus `;` (the
    /// attribute separator). A name is additionally reduced to a bare token (no `=`, `,`, or space). RFC
    /// 6265 forbids these in cookie name/value anyway; removing them keeps a hostile value from forging a
    /// second header line or a fake attribute. Filtering on UTF-8 bytes leaves multi-byte scalars intact.
    static func sanitized(_ component: String, isName: Bool) -> String {
        String(
            decoding: component.utf8.filter { byte in
                if byte < 0x20 || byte == 0x7F { return false }  // C0 controls (incl. CR, LF, NUL, TAB) + DEL
                if byte == UInt8(ascii: ";") { return false }  // attribute / pair separator
                if isName {
                    if byte == UInt8(ascii: "=") || byte == UInt8(ascii: ",") || byte == UInt8(ascii: " ") {
                        return false  // a cookie-name must be a bare token
                    }
                }
                return true
            }, as: UTF8.self)
    }
}

extension ResponseContent {
    /// A copy of this response with a `Set-Cookie` header for `cookie` APPENDED (not overwriting any
    /// existing `Set-Cookie`), so several cookies can be set on one response. Non-`.full` shapes are
    /// promoted so the header rides the engine envelope.
    public func settingCookie(_ cookie: SetCookie) -> ResponseContent {
        var extra = HTTPFields()
        // `headerValue` is sanitized (no control bytes), so the field-value validation always passes.
        extra.append(cookie.headerValue, for: .setCookie)
        return withHeaders(extra)
    }

    /// A copy with a `Set-Cookie` for each of `cookies` appended.
    public func settingCookies(_ cookies: [SetCookie]) -> ResponseContent {
        guard !cookies.isEmpty else { return self }
        var extra = HTTPFields()
        for cookie in cookies { extra.append(cookie.headerValue, for: .setCookie) }
        return withHeaders(extra)
    }
}

// MARK: - Response header merge (append `Set-Cookie`, overwrite the rest)

/// Merge `extra` into `base` with the right repeatability: `set-cookie` is APPENDED (each cookie is its
/// own header line — collapsing them is wrong), every other name overwrites. The single place the engine
/// folds route/middleware headers onto the response envelope, so multi-cookie responses survive.
func mergeResponseHeaders(_ extra: HTTPFields, into base: inout HTTPFields) {
    for field in extra {
        if field.name == .setCookie {
            base.append(field)
        } else {
            base.setValue(field.value, for: field.name)
        }
    }
}

extension Substring {
    /// Drop trailing spaces/tabs (the cookie-name side of a `name = value` pair may carry OWS).
    fileprivate func trimmingTrailingSpaces() -> Substring {
        var sub = self
        while let last = sub.last, last == " " || last == "\t" { sub = sub.dropLast() }
        return sub
    }
}
