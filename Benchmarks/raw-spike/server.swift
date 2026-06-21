// A from-scratch raw-socket HTTP/1.1 server — NO SwiftNIO. The question it answers: is NIO the thing making
// ADServe slower than Go/Erlang/Bun, or is it Swift/ARC? Thread-per-connection (the kernel spreads the
// connection threads across cores), blocking read/write, a minimal request-line path parse, precomputed
// keep-alive responses, TCP_NODELAY. Routes byte-match ADServeBench: /plaintext /json /users/:id /health.
// Build: swiftc -O server.swift -o server ; run: ./server [port].

import Foundation

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

let port: UInt16 = CommandLine.arguments.count > 1 ? (UInt16(CommandLine.arguments[1]) ?? 8080) : 8080

// Precomputed full responses (head + body) — one write() per request for the static routes.
func resp(_ body: String, _ ctype: String) -> [UInt8] {
    Array(
        "HTTP/1.1 200 OK\r\nContent-Length: \(body.utf8.count)\r\nContent-Type: \(ctype)\r\nConnection: keep-alive\r\n\r\n\(body)"
            .utf8)
}
let R_PLAINTEXT = resp("Hello, World!", "text/plain")
let R_JSON = resp(#"{"message":"Hello, World!"}"#, "application/json")
let R_HEALTH = resp("ok", "text/plain")
let R_NOTFOUND = Array("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n".utf8)

@inline(__always)
func pathEquals(_ b: UnsafePointer<UInt8>, _ s: Int, _ len: Int, _ lit: [UInt8]) -> Bool {
    guard len == lit.count else { return false }
    for i in 0 ..< len where b[s + i] != lit[i] { return false }
    return true
}
let L_PLAINTEXT = Array("/plaintext".utf8)
let L_JSON = Array("/json".utf8)
let L_HEALTH = Array("/health".utf8)
let L_USERS = Array("/users/".utf8)

func handle(_ fd: Int32) {
    var one: Int32 = 1
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, socklen_t(MemoryLayout<Int32>.size))
    var buf = [UInt8](repeating: 0, count: 8192)
    while true {
        let n = buf.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
        if n <= 0 {
            close(fd)
            return
        }
        buf.withUnsafeBufferPointer { bp in
            let b = bp.baseAddress!
            // request line: METHOD SP PATH SP ... — skip to first SP, then read path to next SP.
            var i = 0
            while i < n && b[i] != 0x20 { i += 1 }
            i += 1
            let s = i
            while i < n && b[i] != 0x20 { i += 1 }
            let len = i - s
            let out: [UInt8]
            if pathEquals(b, s, len, L_PLAINTEXT) {
                out = R_PLAINTEXT
            } else if pathEquals(b, s, len, L_JSON) {
                out = R_JSON
            } else if pathEquals(b, s, len, L_HEALTH) {
                out = R_HEALTH
            } else if len > L_USERS.count && pathEquals(b, s, L_USERS.count, L_USERS) {
                let id = Array(UnsafeBufferPointer(start: b + s + L_USERS.count, count: len - L_USERS.count))
                out =
                    Array(
                        "HTTP/1.1 200 OK\r\nContent-Length: \(id.count)\r\nContent-Type: text/plain\r\nConnection: keep-alive\r\n\r\n"
                            .utf8) + id
            } else {
                out = R_NOTFOUND
            }
            _ = out.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
        }
    }
}

let listenFd = socket(AF_INET, SOCK_STREAM, 0)
var yes: Int32 = 1
setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
var addr = sockaddr_in()
addr.sin_family = sa_family_t(AF_INET)
addr.sin_port = port.bigEndian
addr.sin_addr.s_addr = INADDR_ANY
let bindRc = withUnsafePointer(to: &addr) { p in
    p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        bind(listenFd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
    }
}
guard bindRc == 0 else {
    FileHandle.standardError.write("bind failed\n".data(using: .utf8)!)
    exit(1)
}
listen(listenFd, 1024)
FileHandle.standardError.write("raw-swift listening on \(port)\n".data(using: .utf8)!)
while true {
    let clientFd = accept(listenFd, nil, nil)
    if clientFd < 0 { continue }
    Thread.detachNewThread { handle(clientFd) }
}
