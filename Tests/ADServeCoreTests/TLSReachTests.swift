// M4 TLS reach: mutual-TLS (accept a client with a CA-signed cert, reject one without) + the peer cert
// exposed to the handler, and UNIX-domain-socket binding (behind-proxy deploys).

import ADTestKit
import Foundation
import HTTPTypes
import Logging
import NIOCore
import NIOPosix
import NIOSSL
import Testing

@testable import ADServeCore

@Suite struct UnixDomainSocketTests {
    @Test func bindsAndServesOverAUnixDomainSocket() async throws {
        // A SHORT path (UDS paths are capped ~104 bytes; a temp-dir path can overflow).
        let socketPath = "/tmp/adserve-uds-\(UInt64.random(in: .min ... .max)).sock"
        defer { try? FileManager.default.removeItem(atPath: socketPath) }
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let routes = StubRoutes { _ in .raw(body: Array("uds-ok".utf8), contentType: "text/plain", status: .ok) }
        do {
            let readiness = ServerReadiness()
            let server = HTTPServer(
                listeners: [ListenerConfig(unixDomainSocketPath: socketPath, routes: routes)], pool: nil,
                envelope: HTTPFields(), logger: Logger(label: "uds"), threadCount: 1, loopCount: 1,
                readiness: readiness)
            let serverTask = Task { try? await server.run() }
            defer { serverTask.cancel() }
            var spins = 0
            while !readiness.isReady && spins < 300 {
                try await Task.sleep(for: .milliseconds(10))
                spins += 1
            }

            let promise = group.next().makePromise(of: [UInt8].self)
            let client = try await ClientBootstrap(group: group)
                .channelInitializer { channel in channel.pipeline.addHandler(ResponseCollector(promise)) }
                .connect(unixDomainSocketPath: socketPath).get()
            var request = client.allocator.buffer(capacity: 64)
            request.writeString("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            try await client.writeAndFlush(request).get()
            let response = String(decoding: try await promise.futureResult.get(), as: UTF8.self)
            #expect(response.hasPrefix("HTTP/1.1 200"))
            #expect(response.hasSuffix("uds-ok"))

            try? await client.close().get()
            serverTask.cancel()
            try? await group.shutdownGracefully()
        } catch {
            try? await group.shutdownGracefully()
            throw error
        }
    }
}

@Suite struct MutualTLSTests {
    @Test func acceptsAClientWithACASignedCertAndExposesIt() async throws {
        let certs = try MTLSCertificates.generate()
        defer { certs.cleanup() }
        let response = try await serveMTLS(presentClientCert: true, certs: certs)
        #expect(response.contains("HTTP/1.1 200"))
        #expect(response.hasSuffix("authed"))  // the handler saw the verified peer certificate
    }

    @Test func rejectsAClientWithoutACertificate() async throws {
        let certs = try MTLSCertificates.generate()
        defer { certs.cleanup() }
        // No client cert → the server (clientVerification: .required) aborts the handshake; the client
        // never receives a served response.
        let response = (try? await serveMTLS(presentClientCert: false, certs: certs)) ?? ""
        #expect(!response.contains("HTTP/1.1 200"))
    }

    /// Bind an mTLS h1 server (server cert ephemeral; client certs verified against the generated CA), then
    /// connect a client that optionally presents the CA-signed client cert. Returns the raw response (empty
    /// when the handshake is rejected).
    private func serveMTLS(presentClientCert: Bool, certs: MTLSCertificates) async throws -> String {
        let serverBase = try EphemeralTLS.source()
        let serverTLS = TLSSource.pem(
            certificate: serverBase.certificatePath, privateKey: serverBase.privateKeyPath,
            clientVerification: .required, trustRoots: certs.caPath)
        let routes = InputStubRoutes { input in
            let authed = input.storage[PeerCertificateKey.self] != nil ? "authed" : "anon"
            return .raw(body: Array(authed.utf8), contentType: "text/plain", status: .ok)
        }
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        do {
            let probe = try await ServerBootstrap(group: group).bind(host: "127.0.0.1", port: 0).get()
            let port = probe.localAddress?.port ?? 0
            try await probe.close().get()
            let readiness = ServerReadiness()
            let server = HTTPServer(
                listeners: [
                    ListenerConfig(
                        host: "127.0.0.1", port: port, wire: .https(serverTLS, alpn: [.http1]), routes: routes)
                ], pool: nil, envelope: HTTPFields(), logger: Logger(label: "mtls"), threadCount: 1,
                loopCount: 1, readiness: readiness)
            let serverTask = Task { try? await server.run() }
            defer { serverTask.cancel() }
            var spins = 0
            while !readiness.isReady && spins < 300 {
                try await Task.sleep(for: .milliseconds(10))
                spins += 1
            }

            var clientConfig = TLSConfiguration.makeClientConfiguration()
            clientConfig.certificateVerification = .none  // test: don't verify the server's self-signed cert
            clientConfig.applicationProtocols = ["http/1.1"]
            if presentClientCert {
                clientConfig.certificateChain = try NIOSSLCertificate.fromPEMFile(certs.clientCertPath)
                    .map { .certificate($0) }
                clientConfig.privateKey = .privateKey(try NIOSSLPrivateKey(file: certs.clientKeyPath, format: .pem))
            }
            let clientContext = try NIOSSLContext(configuration: clientConfig)

            let promise = group.next().makePromise(of: [UInt8].self)
            let client = try await ClientBootstrap(group: group)
                .channelInitializer { channel in
                    channel.eventLoop.makeCompletedFuture {
                        try channel.pipeline.syncOperations.addHandler(
                            NIOSSLClientHandler(context: clientContext, serverHostname: nil))
                        try channel.pipeline.syncOperations.addHandler(ResponseCollector(promise))
                    }
                }
                .connect(host: "127.0.0.1", port: port).get()
            var request = client.allocator.buffer(capacity: 64)
            request.writeString("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            try await client.writeAndFlush(request).get()
            // Bound wait: a rejected handshake closes with no bytes (the collector resolves empty / fails).
            let bytes = (try? await promise.futureResult.get()) ?? []
            try? await client.close().get()
            serverTask.cancel()
            try? await group.shutdownGracefully()
            return String(decoding: bytes, as: UTF8.self)
        } catch {
            try? await group.shutdownGracefully()
            throw error
        }
    }
}

/// A CA + a CA-signed client cert/key, generated with `openssl` into a temp dir for the mTLS tests.
struct MTLSCertificates {
    let caPath: String
    let clientCertPath: String
    let clientKeyPath: String
    private let directory: String

    func cleanup() { try? FileManager.default.removeItem(atPath: directory) }

    static func generate() throws -> MTLSCertificates {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("adserve-mtls-\(UInt64.random(in: .min ... .max))")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let ca = dir.appendingPathComponent("ca.crt").path
        let caKey = dir.appendingPathComponent("ca.key").path
        let csr = dir.appendingPathComponent("client.csr").path
        let clientCert = dir.appendingPathComponent("client.crt").path
        let clientKey = dir.appendingPathComponent("client.key").path

        try runOpenSSL([
            "req", "-x509", "-newkey", "rsa:2048", "-keyout", caKey, "-out", ca, "-days", "1", "-nodes",
            "-subj", "/CN=ADServe Test CA"
        ])
        try runOpenSSL([
            "req", "-newkey", "rsa:2048", "-keyout", clientKey, "-out", csr, "-nodes",
            "-subj", "/CN=adserve-test-client"
        ])
        try runOpenSSL([
            "x509", "-req", "-in", csr, "-CA", ca, "-CAkey", caKey, "-CAcreateserial", "-out", clientCert,
            "-days", "1"
        ])
        return MTLSCertificates(
            caPath: ca, clientCertPath: clientCert, clientKeyPath: clientKey, directory: dir.path)
    }

    private static func runOpenSSL(_ arguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["openssl"] + arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw TLSHarnessError("openssl \(arguments.first ?? "") failed (is openssl on PATH?)")
        }
    }
}
