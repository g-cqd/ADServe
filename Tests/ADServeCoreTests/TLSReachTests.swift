// M4 TLS reach: mutual-TLS (accept a client presenting a CA-signed cert, reject one without) + the
// verified peer identity exposed to the handler, and UNIX-domain-socket binding (behind-proxy
// deploys). The mTLS client is URLSession presenting a PKCS#12 identity; the engine surfaces the
// verified leaf SUBJECT to handlers (`ctx.tlsPeerSubject` / `TLSPeerSubjectKey`) — the raw DER
// chain the NIO engine used to expose awaits an upstream transport seam (HTTP G3 follow-up).

import Foundation
import HTTPCore
import Logging
import Security
import Synchronization
import Testing

@testable import ADServeCore

@Suite struct UnixDomainSocketTests {
    @Test func bindsAndServesOverAUnixDomainSocket() async throws {
        // A SHORT path (UDS paths are capped ~104 bytes; a temp-dir path can overflow).
        let socketPath = "/tmp/adserve-uds-\(UInt64.random(in: .min ... .max)).sock"
        defer { try? FileManager.default.removeItem(atPath: socketPath) }
        let routes = StubRoutes { _ in
            .raw(body: Array("uds-ok".utf8), contentType: "text/plain", status: .ok)
        }
        let readiness = ServerReadiness()
        let server = HTTPServer(
            listeners: [ListenerConfig(unixDomainSocketPath: socketPath, routes: routes)], pool: nil,
            envelope: HTTPFields(), logger: Logger(label: "uds"), threadCount: 1, loopCount: 1,
            readiness: readiness)
        let serverTask = Task { try? await server.run() }
        defer { serverTask.cancel() }
        try await Loopback.awaitReadiness(readiness)

        let response = try await runOnThread { () -> String in
            let client = try TestSocket.connectUnix(path: socketPath)
            try client.send("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            return String(decoding: client.readToEOF(), as: UTF8.self)
        }
        #expect(response.hasPrefix("HTTP/1.1 200"))
        #expect(response.hasSuffix("uds-ok"))
    }
}

@Suite struct MutualTLSTests {
    @Test func acceptsAClientWithACASignedCertAndExposesIt() async throws {
        let certs = try MTLSCertificates.generate()
        defer { certs.cleanup() }
        let response = try await serveMTLS(presentClientCert: true, certs: certs)
        #expect(response.status == 200)
        #expect(response.body.hasSuffix("authed"))  // the handler saw the verified peer identity
    }

    @Test func rejectsAClientWithoutACertificate() async throws {
        let certs = try MTLSCertificates.generate()
        defer { certs.cleanup() }
        // No client cert → the server (clientVerification: .required) aborts the handshake; the
        // client never receives a served response.
        let response = try? await serveMTLS(presentClientCert: false, certs: certs)
        #expect(response?.status != 200)
    }

    private struct MTLSResponse {
        let status: Int
        let body: String
    }

    /// Bind an mTLS h1 server (server cert ephemeral; a client certificate REQUIRED at the
    /// handshake), then connect a URLSession client that optionally presents the CA-signed client
    /// identity. Throws when the handshake is rejected.
    private func serveMTLS(
        presentClientCert: Bool, certs: MTLSCertificates
    ) async throws -> MTLSResponse {
        let serverBase = try EphemeralTLS.source()
        let serverTLS = TLSSource.pem(
            certificate: serverBase.certificatePath, privateKey: serverBase.privateKeyPath,
            clientVerification: .required, trustRoots: certs.caPath)
        let routes = InputStubRoutes { input in
            let authed = input.storage[TLSPeerSubjectKey.self] != nil ? "authed" : "anon"
            return .raw(body: Array(authed.utf8), contentType: "text/plain", status: .ok)
        }
        let port = try Loopback.freePort()
        let readiness = ServerReadiness()
        let server = HTTPServer(
            listeners: [
                ListenerConfig(
                    host: "127.0.0.1", port: port, wire: .https(serverTLS, alpn: [.http1]),
                    routes: routes)
            ], pool: nil, envelope: HTTPFields(), logger: Logger(label: "mtls"), threadCount: 1,
            loopCount: 1, readiness: readiness)
        let serverTask = Task { try? await server.run() }
        defer { serverTask.cancel() }
        try await Loopback.awaitReadiness(readiness)

        let identity = presentClientCert ? try certs.clientIdentity() : nil
        let delegate = MTLSClientDelegate(identity: identity)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 5
        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        guard let url = URL(string: "https://127.0.0.1:\(port)/") else {
            throw TLSHarnessError(message: "bad URL")
        }
        let (data, response) = try await session.data(from: url)
        guard let http = response as? HTTPURLResponse else {
            throw TLSHarnessError(message: "non-HTTP response")
        }
        return MTLSResponse(status: http.statusCode, body: String(decoding: data, as: UTF8.self))
    }
}

/// Trusts the self-signed server (test only) and presents the client identity when challenged.
final class MTLSClientDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    private let identity: SecIdentity?

    init(identity: SecIdentity?) {
        self.identity = identity
    }

    func urlSession(
        _ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        switch challenge.protectionSpace.authenticationMethod {
            case NSURLAuthenticationMethodServerTrust:
                if let trust = challenge.protectionSpace.serverTrust {
                    completionHandler(.useCredential, URLCredential(trust: trust))
                } else {
                    completionHandler(.performDefaultHandling, nil)
                }
            case NSURLAuthenticationMethodClientCertificate:
                if let identity {
                    completionHandler(
                        .useCredential,
                        URLCredential(identity: identity, certificates: nil, persistence: .forSession))
                } else {
                    // Decline: the handshake proceeds certless and the server must reject it.
                    completionHandler(.performDefaultHandling, nil)
                }
            default:
                completionHandler(.performDefaultHandling, nil)
        }
    }
}

/// A CA + a CA-signed client cert/key (+ its PKCS#12 identity), generated with `openssl` into a
/// temp dir for the mTLS tests.
struct MTLSCertificates {
    let caPath: String
    let clientCertPath: String
    let clientKeyPath: String
    let clientP12Path: String
    let p12Passphrase: String
    private let directory: String

    func cleanup() { try? FileManager.default.removeItem(atPath: directory) }

    /// The client identity imported from the PKCS#12 (the URLSession client-certificate credential).
    func clientIdentity() throws -> SecIdentity {
        let data = try Data(contentsOf: URL(fileURLWithPath: clientP12Path))
        let options: [String: Any] = [kSecImportExportPassphrase as String: p12Passphrase]
        var items: CFArray?
        let status = SecPKCS12Import(data as CFData, options as CFDictionary, &items)
        guard status == errSecSuccess, let array = items as? [[String: Any]],
            let first = array.first,
            let raw = first[kSecImportItemIdentity as String]
        else {
            throw TLSHarnessError(message: "SecPKCS12Import failed: \(status)")
        }
        // CFDictionary member — unconditionally a SecIdentity when present.
        return unsafeDowncast(raw as AnyObject, to: SecIdentity.self)
    }

    static func generate() throws -> MTLSCertificates {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("adserve-mtls-\(UInt64.random(in: .min ... .max))")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let ca = dir.appendingPathComponent("ca.crt").path
        let caKey = dir.appendingPathComponent("ca.key").path
        let csr = dir.appendingPathComponent("client.csr").path
        let clientCert = dir.appendingPathComponent("client.crt").path
        let clientKey = dir.appendingPathComponent("client.key").path
        let clientP12 = dir.appendingPathComponent("client.p12").path
        let passphrase = "adserve-mtls-test"

        try runOpenSSL([
            "req", "-x509", "-newkey", "rsa:2048", "-keyout", caKey, "-out", ca, "-days", "1",
            "-nodes", "-subj", "/CN=ADServe Test CA"
        ])
        try runOpenSSL([
            "req", "-newkey", "rsa:2048", "-keyout", clientKey, "-out", csr, "-nodes",
            "-subj", "/CN=adserve-test-client"
        ])
        try runOpenSSL([
            "x509", "-req", "-in", csr, "-CA", ca, "-CAkey", caKey, "-CAcreateserial",
            "-out", clientCert, "-days", "1"
        ])
        // OpenSSL 3 defaults to AES-256 PKCS#12, which SecPKCS12Import can reject; -legacy restores
        // the readable form (LibreSSL already emits it and has no -legacy flag).
        var export = [
            "pkcs12", "-export", "-inkey", clientKey, "-in", clientCert, "-out", clientP12,
            "-name", "adserve-test-client", "-passout", "pass:\(passphrase)"
        ]
        if (try? runOpenSSL(["version"], capture: true))?.contains("OpenSSL 3") == true {
            export.insert("-legacy", at: 2)
        }
        try runOpenSSL(export)
        return MTLSCertificates(
            caPath: ca, clientCertPath: clientCert, clientKeyPath: clientKey,
            clientP12Path: clientP12, p12Passphrase: passphrase, directory: dir.path)
    }

    @discardableResult
    private static func runOpenSSL(_ arguments: [String], capture: Bool = false) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["openssl"] + arguments
        let output = Pipe()
        process.standardOutput = capture ? output : FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        let captured =
            capture
            ? String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self) : ""
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw TLSHarnessError(message: "openssl \(arguments.first ?? "") failed (openssl on PATH?)")
        }
        return captured
    }
}
