// PEM → PKCS#12 conversion for the transport seam. ADServe's public `TLSSource` is a PEM
// certificate-chain + private-key pair on disk (what certbot & friends emit); the HTTP package's
// `TransportTLS` consumes a PKCS#12 identity blob. Until `TransportTLS` grows native PEM intake
// (a recorded upstream gap), the engine converts at bind time by shelling out to the system
// `openssl` — the exact pragmatic path the HTTP package's own `DevTLSIdentity` takes for its
// self-signed dev identities, so the operational dependency is already established upstream.

import Foundation
import HTTPTransport

/// Builds the transport TLS identity for a listener from ADServe's PEM-based `TLSSource`.
enum TLSMaterial {
    /// Converts `source` (PEM chain + key paths) into the `TransportTLS` the transport consumes,
    /// advertising `alpn`. mTLS: `.required` demands a client certificate at the handshake; the
    /// presented chain is accepted as-is (chain-to-`trustRoots` validation has no seam in
    /// `TransportTLS` today — `verifyPeer` receives raw DER, and ADServe ships no X.509 path
    /// validator; recorded as an upstream gap).
    static func transportTLS(from source: TLSSource, alpn: [ALPN]) throws -> TransportTLS {
        let passphrase = "adserve-\(UUID().uuidString)"
        let pkcs12 = try exportPKCS12(
            certificatePath: source.certificatePath, privateKeyPath: source.privateKeyPath,
            passphrase: passphrase)
        var tls = TransportTLS(
            pkcs12: pkcs12, passphrase: passphrase, applicationProtocols: alpn.map(\.rawValue))
        if source.clientVerification == .required {
            tls.clientAuth = .required
            tls.verifyPeer = { chain in !chain.isEmpty }
        }
        return tls
    }

    /// `openssl pkcs12 -export` over the PEM pair, returning the identity blob.
    private static func exportPKCS12(
        certificatePath: String, privateKeyPath: String, passphrase: String
    ) throws -> [UInt8] {
        let manager = FileManager.default
        let directory = manager.temporaryDirectory.appendingPathComponent(
            "adserve-tls-\(UUID().uuidString)", isDirectory: true)
        try manager.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? manager.removeItem(at: directory) }
        let bundle = directory.appendingPathComponent("identity.p12").path

        // OpenSSL 3 defaults to AES-256 PKCS#12, which older `SecPKCS12Import` rejects; `-legacy`
        // restores the SHA1/3DES form it reads. LibreSSL (no `-legacy` flag) already emits that form.
        var arguments = [
            "pkcs12", "-export", "-inkey", privateKeyPath, "-in", certificatePath,
            "-out", bundle, "-name", "adserve", "-passout", "pass:\(passphrase)"
        ]
        if try isOpenSSL3OrNewer() { arguments.insert("-legacy", at: 2) }
        try run(arguments)

        guard let data = manager.contents(atPath: bundle) else {
            throw EngineError(message: "openssl produced no PKCS#12 output")
        }
        return [UInt8](data)
    }

    /// Whether the resolved `openssl` is OpenSSL 3+ (which needs `-legacy`) rather than LibreSSL.
    private static func isOpenSSL3OrNewer() throws -> Bool {
        let version = try invoke(["version"])
        return version.contains("OpenSSL 3") || version.contains("OpenSSL 4")
    }

    private static func run(_ arguments: [String]) throws {
        _ = try invoke(arguments)
    }

    /// Runs `openssl` with `arguments`, returning stdout; throws with stderr on a non-zero exit.
    private static func invoke(_ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["openssl"] + arguments
        let output = Pipe()
        let errors = Pipe()
        process.standardOutput = output
        process.standardError = errors
        do {
            try process.run()
        } catch {
            throw EngineError(message: "could not launch openssl: \(error)")
        }
        // Drain before waiting so a large write cannot deadlock against a full pipe buffer.
        let stdout = output.fileHandleForReading.readDataToEndOfFile()
        let stderr = errors.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw EngineError(
                message: "openssl \(arguments.first ?? "") failed: "
                    + String(decoding: stderr, as: Unicode.UTF8.self))
        }
        return String(decoding: stdout, as: Unicode.UTF8.self)
    }
}
