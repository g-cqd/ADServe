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

## The path (Darwin-only — Linux is out of scope per the project)

Replace NIO as ADServe's transport with a from-scratch Darwin engine — likely **`Network.framework`** (TLS +
perf + connection mgmt for free) or a hand-rolled kqueue reactor — keeping ADServe's HTTP semantics (routing
DSL, the security envelope, the response model, the path-traversal/static hardening, the 275 tests) on top.
Phased + continuously benchmarked against this spike's ~197k ceiling.
