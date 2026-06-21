# raw-spike — is SwiftNIO the bottleneck?

A throwaway, from-scratch HTTP/1.1 server (`server.swift`) on **raw Darwin sockets — no SwiftNIO**:
thread-per-connection, blocking read/write, a minimal request-line path parse, precomputed keep-alive
responses, `TCP_NODELAY`. Routes byte-match `ADServeBench`. ~80 lines, `swiftc -O server.swift -o server`.

It exists to answer one question raised after the cross-stack benchmark (ADServe last of five): **is the gap
SwiftNIO, or Swift/ARC?**

## Result (best-of-5, oha `-z 5s -c 64`, same 8-core box)

| Server                | /plaintext | note |
|-----------------------|-----------:|------|
| Bun                   |   203,831  | JS/Zig |
| **raw-swift (this)**  | **196,809**| **no NIO** |
| Go net/http           |   162,927  | |
| Erlang raw gen_tcp    |   142,905  | |
| Hummingbird (NIO)     |   114,713  | Swift/NIO |
| **ADServe (NIO)**     |  **94,644**| Swift/NIO |

**The raw Swift server is ~2.08× faster than NIO-ADServe** (and ~1.7× faster than NIO-Hummingbird) — landing
second overall, a hair behind Bun and ahead of Go/Erlang/everything else.

## What this proves

- **SwiftNIO's `ChannelHandler` pipeline is the dominant cost**, not Swift. Both NIO servers (ADServe,
  Hummingbird) sit at the bottom; a raw-socket Swift server vaults to the top. Swift/ARC is *not* the floor —
  raw Swift is top-tier.
- The implied ceiling for a Darwin-only, from-scratch ADServe transport is ~2× the current throughput.

## Honest caveats (why this is a spike, not a server)

- **Best case for raw sockets:** tiny responses + keep-alive + no TLS means the transport overhead dominates,
  so NIO's per-event pipeline cost is *maximally* visible. Real workloads (bigger bodies, TLS, HTTP/2) shrink
  the relative gap.
- **No TLS, no HTTP/2, no robust parsing/limits/timeouts/backpressure** — all of which NIO provides,
  battle-tested. A production from-scratch transport must re-provide what ADServe needs. **TLS must not be
  hand-rolled** — on Darwin that means `Network.framework` (NWListener/NWConnection, which also gives
  kqueue-class performance + connection management) or Security.framework.
- Thread-per-connection is fine for moderate connection counts; high-C10k scaling wants a kqueue reactor or
  `Network.framework`.

## Network.framework: tested + RULED OUT (`server-networkframework.swift`)

The obvious "production transport with TLS for free" is Apple's `Network.framework` (NWListener/NWConnection).
Built + benchmarked it (per-connection serial queue, receive→route→send keep-alive). Result:

| Server                         | /plaintext | p50     |
|--------------------------------|-----------:|---------|
| raw-swift (raw sockets)        |   178.1k   | 0.35 ms |
| ADServe (NIO)                  |    97.6k   | 0.37 ms |
| **nw-swift (Network.framework)**|   **89.9k**| **0.81 ms** |

**Network.framework is SLOWER than NIO** (89.9k vs 97.6k) and **2.3× the latency** — half the raw-socket
throughput. Its NWConnection / dispatch-queue model adds real per-request overhead. So the TLS-for-free path
does NOT deliver the win; it's out.

## The path (Darwin-only — Linux is out of scope per the project)

The fast transport is **raw sockets** (the spike), not Network.framework. TLS for the fast path comes from the
**fronting proxy** — ADServe's canonical deployment is already proxy-fronted (Caddy terminates TLS + adds the
`Date` header), so a raw *plaintext* HTTP/1.1 engine needs no in-process TLS for that case. Direct-TLS / HTTP-2
deployments keep the existing NIO engine (a feature path, where the perf delta matters less).

So: a from-scratch raw-Darwin engine as the **plaintext fast path**, the NIO engine retained for TLS/HTTP-2,
both under ADServe's HTTP semantics (routing DSL, security envelope, response model, path-traversal/static
hardening, the 275 tests). Production-grade means a robust parser + limits/timeouts/backpressure + likely a
**kqueue reactor** (rather than thread-per-connection) for connection scaling. Phased + continuously
benchmarked against this spike's ~178–197k ceiling.
