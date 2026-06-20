// Signed-cookie sessions: an `HTTPMiddleware` that carries a tamper-proof session id in a cookie
// (HMAC-SHA256 over the id, via swift-crypto) and keeps the session VALUES server-side in a pluggable
// `SessionStore` (in-memory by default). The handler reaches the session via `ctx.session`; the
// middleware persists changes and sets/rotates/expires the cookie after the handler returns.

import Crypto
import Foundation
import HTTPTypes
import Synchronization

// MARK: - Store

/// A server-side session backing store, keyed by session id. The default is `InMemorySessionStore`; a
/// production deployment plugs a shared store (Redis, SQL, …) so sessions survive a restart / span hosts.
public protocol SessionStore: Sendable {
    /// The values for `id`, or `nil` if absent/expired.
    func load(_ id: String) async -> [String: String]?
    /// Persist `values` for `id` (creating or replacing).
    func save(_ id: String, values: [String: String]) async
    /// Drop `id` (logout / rotation of the old id).
    func delete(_ id: String) async
}

/// An in-memory `SessionStore` with a per-entry TTL — the zero-config default. Lock-guarded; entries
/// expire lazily on access (a session older than `ttlSeconds` is treated as absent and removed).
public final class InMemorySessionStore: SessionStore {
    private struct Entry {
        var values: [String: String]
        var deadline: Double
    }
    private let entries = Mutex<[String: Entry]>([:])
    private let ttlSeconds: Double

    public init(ttlSeconds: Int = 86_400) { self.ttlSeconds = Double(ttlSeconds) }

    public func load(_ id: String) async -> [String: String]? {
        entries.withLock { store in
            guard let entry = store[id] else { return nil }
            if entry.deadline < Date().timeIntervalSince1970 {
                store[id] = nil
                return nil
            }
            return entry.values
        }
    }

    public func save(_ id: String, values: [String: String]) async {
        let deadline = Date().timeIntervalSince1970 + ttlSeconds
        entries.withLock { $0[id] = Entry(values: values, deadline: deadline) }
    }

    public func delete(_ id: String) async {
        entries.withLock { $0[id] = nil }
    }
}

// MARK: - Session

/// The per-request session a handler reads + mutates via `ctx.session`. Mutations are tracked so the
/// middleware persists only when something changed (no write churn on read-only requests). `rotate()`
/// re-issues the id on the next response (session-fixation defense); `invalidate()` logs out (clears
/// state, deletes server-side, expires the cookie).
public final class Session: Sendable {
    private struct State {
        var values: [String: String]
        var modified = false
        var rotated = false
        var invalidated = false
    }
    private let state: Mutex<State>
    /// The id this session was loaded from, or `nil` for a brand-new session.
    let loadedID: String?

    init(values: [String: String], loadedID: String?) {
        self.state = Mutex(State(values: values))
        self.loadedID = loadedID
    }

    public subscript(_ key: String) -> String? {
        get { state.withLock { $0.values[key] } }
        set {
            state.withLock { state in
                state.values[key] = newValue
                state.modified = true
            }
        }
    }

    /// Every session value.
    public var values: [String: String] { state.withLock { $0.values } }
    /// `true` if this session held no prior data (no valid cookie was presented).
    public var isNew: Bool { loadedID == nil }

    public func removeValue(forKey key: String) {
        state.withLock { state in
            state.values.removeValue(forKey: key)
            state.modified = true
        }
    }

    /// Re-issue the session id on the next response (rotate after a privilege change / login).
    public func rotate() { state.withLock { $0.rotated = true } }

    /// Log out: clear the session, delete it server-side, and expire the cookie.
    public func invalidate() {
        state.withLock { state in
            state.values = [:]
            state.invalidated = true
        }
    }

    /// Snapshot for the middleware's persist step.
    var snapshot: SessionSnapshot {
        state.withLock {
            SessionSnapshot(
                values: $0.values, modified: $0.modified, rotated: $0.rotated, invalidated: $0.invalidated)
        }
    }
}

/// An immutable snapshot of a `Session`'s state + lifecycle flags, taken by the middleware after the
/// handler to decide what to persist + which cookie to set.
struct SessionSnapshot {
    let values: [String: String]
    let modified: Bool
    let rotated: Bool
    let invalidated: Bool
}

/// The `RequestStorage` key the `Sessions` middleware stores the live `Session` under; `ctx.session`
/// reads it.
public enum SessionKey: StorageKey {
    public typealias Value = Session
}

/// A misconfiguration of the `Sessions` middleware, surfaced at construction so a weak setup fails fast
/// (at boot) rather than shipping forgeable sessions.
public enum SessionConfigError: Error, Equatable, Sendable {
    /// The signing secret was shorter than the required minimum (a weak key an attacker could brute-force).
    case secretTooShort(provided: Int, minimum: Int)
}

// MARK: - Middleware

/// Signed-cookie session middleware. Install it server-wide (or per group). It reads + HMAC-verifies the
/// session cookie, loads the values from `store`, exposes the `Session` on `ctx.session`, then persists
/// changes and (re)sets/expires the cookie. The cookie carries ONLY a signed id — never the values — so a
/// client cannot read or forge session state.
public struct Sessions: HTTPMiddleware {
    private let store: any SessionStore
    private let key: SymmetricKey
    private let cookieName: String
    private let maxAgeSeconds: Int
    private let secure: Bool
    private let httpOnly: Bool
    private let sameSite: SameSite

    /// The minimum signing-secret length (bytes). Below this a key is brute-forceable; construction throws.
    public static let minimumSecretBytes = 32

    /// `secret` is the signing-key material — keep it stable across restarts (else every session is
    /// invalidated) and confidential (its disclosure lets an attacker forge session ids). It MUST be at
    /// least ``minimumSecretBytes`` bytes (`SessionConfigError.secretTooShort` otherwise). The actual HMAC
    /// key is HKDF-SHA256-**derived** from it, so the signing key is always a uniform 32 bytes regardless
    /// of how the secret's entropy is distributed (a hardening over keying the HMAC with raw bytes).
    public init(
        secret: [UInt8], store: any SessionStore = InMemorySessionStore(), cookieName: String = "session",
        maxAgeSeconds: Int = 86_400, secure: Bool = true, httpOnly: Bool = true,
        sameSite: SameSite = .lax
    ) throws {
        guard secret.count >= Self.minimumSecretBytes else {
            throw SessionConfigError.secretTooShort(provided: secret.count, minimum: Self.minimumSecretBytes)
        }
        self.store = store
        self.key = HKDF<SHA256>
            .deriveKey(
                inputKeyMaterial: SymmetricKey(data: secret),
                info: Data("ADServe.Sessions.v1.cookie-signing".utf8), outputByteCount: 32)
        self.cookieName = cookieName
        self.maxAgeSeconds = maxAgeSeconds
        self.secure = secure
        self.httpOnly = httpOnly
        self.sameSite = sameSite
    }

    public func intercept(
        _ request: ServerRequest, _ context: MiddlewareContext,
        next: @Sendable (ServerRequest) async -> ResponseContent
    ) async -> ResponseContent {
        let cookies = RequestCookies(request.headers[.cookie])
        let loadedID = cookies[cookieName].flatMap(verify)
        let values: [String: String]
        if let loadedID { values = await store.load(loadedID) ?? [:] } else { values = [:] }
        let session = Session(values: values, loadedID: loadedID)
        context.storage[SessionKey.self] = session

        let response = await next(request)
        return await persist(session, response: response)
    }

    /// Save changes + reconcile the cookie after the handler. No-op when an existing session was only
    /// read (avoids per-request store writes); rotates / expires when asked.
    private func persist(_ session: Session, response: ResponseContent) async -> ResponseContent {
        let snapshot = session.snapshot
        if snapshot.invalidated {
            if let old = session.loadedID { await store.delete(old) }
            return response.settingCookie(.expiring(cookieName, path: "/"))
        }

        // A brand-new session is only materialized once it holds data; a read-only existing session is
        // left untouched.
        let needsWrite = snapshot.modified || snapshot.rotated
        guard needsWrite, !(session.loadedID == nil && snapshot.values.isEmpty) else { return response }

        var id = session.loadedID
        if snapshot.rotated || id == nil {
            if let old = session.loadedID { await store.delete(old) }  // rotation drops the old id
            id = Self.makeSessionID()
        }
        guard let id else { return response }
        await store.save(id, values: snapshot.values)
        // Re-set the cookie only when the id changed (new or rotated); otherwise the client already has it.
        if id != session.loadedID {
            return response.settingCookie(makeCookie(id))
        }
        return response
    }

    private func makeCookie(_ id: String) -> SetCookie {
        SetCookie(
            name: cookieName, value: sign(id), path: "/", maxAge: maxAgeSeconds, secure: secure,
            httpOnly: httpOnly, sameSite: sameSite)
    }

    // MARK: - Signing

    /// `<id>.<hmac-hex>` — the id plus its HMAC-SHA256 tag, so tampering with the id is detectable.
    private func sign(_ id: String) -> String {
        let mac = HMAC<SHA256>.authenticationCode(for: Array(id.utf8), using: key)
        return "\(id).\(Self.hexEncode(Array(mac)))"
    }

    /// The id from a signed cookie if the HMAC verifies (constant-time), else `nil`.
    private func verify(_ cookie: String) -> String? {
        guard let dot = cookie.lastIndex(of: ".") else { return nil }
        let id = String(cookie[..<dot])
        let tag = String(cookie[cookie.index(after: dot)...])
        guard !id.isEmpty, let macBytes = Self.hexDecode(tag) else { return nil }
        let valid = HMAC<SHA256>
            .isValidAuthenticationCode(
                Data(macBytes), authenticating: Array(id.utf8), using: key)
        return valid ? id : nil
    }

    /// 32 CSPRNG bytes as lowercase hex — an unguessable session id.
    static func makeSessionID() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        for index in bytes.indices { bytes[index] = UInt8.random(in: .min ... .max) }
        return hexEncode(bytes)
    }

    static func hexEncode(_ bytes: [UInt8]) -> String {
        let digits: [UInt8] = Array("0123456789abcdef".utf8)
        var out: [UInt8] = []
        out.reserveCapacity(bytes.count * 2)
        for byte in bytes {
            out.append(digits[Int(byte >> 4)])
            out.append(digits[Int(byte & 0x0F)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    static func hexDecode(_ string: String) -> [UInt8]? {
        let chars = Array(string.utf8)
        guard chars.count % 2 == 0 else { return nil }
        var out: [UInt8] = []
        out.reserveCapacity(chars.count / 2)
        var index = 0
        while index < chars.count {
            guard let high = nibble(chars[index]), let low = nibble(chars[index + 1]) else { return nil }
            out.append(high << 4 | low)
            index += 2
        }
        return out
    }

    private static func nibble(_ byte: UInt8) -> UInt8? {
        switch byte {
            case UInt8(ascii: "0") ... UInt8(ascii: "9"): return byte - UInt8(ascii: "0")
            case UInt8(ascii: "a") ... UInt8(ascii: "f"): return byte - UInt8(ascii: "a") + 10
            case UInt8(ascii: "A") ... UInt8(ascii: "F"): return byte - UInt8(ascii: "A") + 10
            default: return nil
        }
    }
}
