// A stateless HMAC-SHA256 signer over an HKDF-SHA256-derived key — extracted from `Sessions` so the
// signed-cookie scheme and other signed-token schemes (e.g. ADHTML server-action tokens) share ONE audited
// primitive. The `info` label DOMAIN-SEPARATES keys: the same root secret yields cryptographically
// independent keys for distinct `info` strings, so a cookie-signing key and an action-token key never
// coincide even when an app reuses one secret for both.

import Crypto
import Foundation

/// Construction error: a secret below the safe minimum is rejected at boot (fail fast, never sign with a
/// brute-forceable key).
public enum HMACSignerError: Error, Equatable, Sendable {
    case secretTooShort(provided: Int, minimum: Int)
}

/// A stateless HMAC-SHA256 signer. Immutable + `Sendable`: build once at boot, share across requests.
public struct HMACSigner: Sendable {
    /// The minimum signing-secret length (bytes). Below this a key is brute-forceable; construction throws.
    public static let minimumSecretBytes = 32

    private let key: SymmetricKey

    /// `secret` MUST be ≥ ``minimumSecretBytes`` bytes (`HMACSignerError.secretTooShort` otherwise). The
    /// HMAC key is HKDF-SHA256-**derived** from it under the context label `info`, so (a) the key is a
    /// uniform 32 bytes regardless of the secret's entropy distribution, and (b) two signers built from the
    /// SAME secret with DIFFERENT `info` have independent keys (domain separation). Keep `secret` stable
    /// across restarts (else live signatures stop verifying) and confidential (disclosure forges tags).
    public init(secret: [UInt8], info: String) throws {
        guard secret.count >= Self.minimumSecretBytes else {
            throw HMACSignerError.secretTooShort(provided: secret.count, minimum: Self.minimumSecretBytes)
        }
        self.key = HKDF<SHA256>
            .deriveKey(
                inputKeyMaterial: SymmetricKey(data: secret),
                info: Data(info.utf8), outputByteCount: 32)
    }

    /// `"<payload>.<hmac-hex>"` — the payload followed by its tag, so tampering with the payload is
    /// detectable on ``verify(_:)``.
    public func sign(_ payload: String) -> String { "\(payload).\(tag(for: payload))" }

    /// The payload of a `"<payload>.<hmac-hex>"` token if its tag verifies (constant-time), else `nil`.
    /// Splits on the LAST `.`, so the payload may itself contain `.` (e.g. a structured `a.b.c` token).
    public func verify(_ token: String) -> String? {
        guard let dot = token.lastIndex(of: ".") else { return nil }
        let payload = String(token[..<dot])
        let tag = String(token[token.index(after: dot)...])
        guard !payload.isEmpty, isValid(tag: tag, for: payload) else { return nil }
        return payload
    }

    /// The lowercase-hex HMAC-SHA256 tag of `payload`.
    public func tag(for payload: String) -> String {
        Self.hexEncode(Array(HMAC<SHA256>.authenticationCode(for: Array(payload.utf8), using: key)))
    }

    /// Constant-time check that `hex` is the HMAC tag of `payload` (never branches on secret data).
    public func isValid(tag hex: String, for payload: String) -> Bool {
        guard let macBytes = Self.hexDecode(hex) else { return false }
        return HMAC<SHA256>
            .isValidAuthenticationCode(
                Data(macBytes), authenticating: Array(payload.utf8), using: key)
    }

    // MARK: - Hex (shared utility; `Sessions.makeSessionID` reuses `hexEncode`)

    public static func hexEncode(_ bytes: [UInt8]) -> String {
        let digits: [UInt8] = Array("0123456789abcdef".utf8)
        var out: [UInt8] = []
        out.reserveCapacity(bytes.count * 2)
        for byte in bytes {
            out.append(digits[Int(byte >> 4)])
            out.append(digits[Int(byte & 0x0F)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    public static func hexDecode(_ string: String) -> [UInt8]? {
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
