// A from-scratch HTTP/1.1 server on Apple's Network.framework — NO SwiftNIO. The PRODUCTION transport
// candidate for a Darwin-only ADServe: Network.framework gives TLS, TCP_NODELAY, and connection management
// for free (the raw kqueue spike has none of that). Per-connection serial queue (parallel across cores),
// receive→route→send keep-alive loop, request-line path parse, precomputed responses. Routes byte-match
// ADServeBench. Build: swiftc -O server.swift -o server ; run: ./server [port].

import Foundation
import Network

let port: UInt16 = CommandLine.arguments.count > 1 ? (UInt16(CommandLine.arguments[1]) ?? 8080) : 8080

func resp(_ body: String, _ ctype: String) -> Data {
    Data(
        "HTTP/1.1 200 OK\r\nContent-Length: \(body.utf8.count)\r\nContent-Type: \(ctype)\r\nConnection: keep-alive\r\n\r\n\(body)"
            .utf8)
}
let R_PLAINTEXT = resp("Hello, World!", "text/plain")
let R_JSON = resp(#"{"message":"Hello, World!"}"#, "application/json")
let R_HEALTH = resp("ok", "text/plain")
let R_NOTFOUND = Data("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n".utf8)
let L_PLAINTEXT = Array("/plaintext".utf8)
let L_JSON = Array("/json".utf8)
let L_HEALTH = Array("/health".utf8)
let L_USERS = Array("/users/".utf8)

func route(_ data: Data) -> Data {
    data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> Data in
        let b = raw.bindMemory(to: UInt8.self)
        let n = b.count
        var i = 0
        while i < n && b[i] != 0x20 { i += 1 }
        i += 1
        let s = i
        while i < n && b[i] != 0x20 { i += 1 }
        let len = i - s
        func eq(_ lit: [UInt8]) -> Bool {
            guard len == lit.count else { return false }
            for k in 0 ..< len where b[s + k] != lit[k] { return false }
            return true
        }
        if eq(L_PLAINTEXT) { return R_PLAINTEXT }
        if eq(L_JSON) { return R_JSON }
        if eq(L_HEALTH) { return R_HEALTH }
        if len > L_USERS.count {
            var pref = true
            for k in 0 ..< L_USERS.count where b[s + k] != L_USERS[k] {
                pref = false
                break
            }
            if pref {
                let id = Data(bytes: b.baseAddress! + s + L_USERS.count, count: len - L_USERS.count)
                return Data(
                    "HTTP/1.1 200 OK\r\nContent-Length: \(id.count)\r\nContent-Type: text/plain\r\nConnection: keep-alive\r\n\r\n"
                        .utf8) + id
            }
        }
        return R_NOTFOUND
    }
}

func receiveLoop(_ conn: NWConnection) {
    conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
        if let data = data, !data.isEmpty {
            conn.send(content: route(data), completion: .contentProcessed { _ in receiveLoop(conn) })
        } else if isComplete || error != nil {
            conn.cancel()
        } else {
            receiveLoop(conn)
        }
    }
}

let params = NWParameters.tcp
if let tcp = params.defaultProtocolStack.transportProtocol as? NWProtocolTCP.Options { tcp.noDelay = true }
let listener = try! NWListener(using: params, on: NWEndpoint.Port(rawValue: port)!)
listener.newConnectionHandler = { conn in
    conn.start(queue: DispatchQueue(label: "conn"))  // own queue → parallel across cores
    receiveLoop(conn)
}
listener.start(queue: DispatchQueue(label: "listener"))
FileHandle.standardError.write("nw-swift listening on \(port)\n".data(using: .utf8)!)
dispatchMain()
