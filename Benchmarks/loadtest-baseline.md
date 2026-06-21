# ADServe live-load baseline

End-to-end HTTP throughput + latency for the engine over a real socket — the live counterpart to the
in-process `ADServeSuite` micro-benchmarks (which time pure routing under `swift package benchmark`).
Captured with the runnable `ADServeBench` server (`Sources/ADServeBench/`) + the dep-free Bun load
generator (`Benchmarks/loadtest.js`).

## Reproduce

```sh
# 1. build + run the bench server (engine defaults: 2 event loops, full security envelope, keep-alive,
#    idle-timeout + connection-limiter installed — i.e. a REAL server, not a toy)
ADSERVE_DEV=1 swift run -c release --build-system native ADServeBench 18080

# 2. in another shell, drive load (closed-loop, fixed concurrency)
bun Benchmarks/loadtest.js http://127.0.0.1:18080/plaintext 64 5000 1000
```

## Baseline — 2026-06-21

Host: Apple Silicon, 8 logical cores (macOS / Darwin 25.5.0). Release build. Bun 1.3 client.
Server config: engine defaults (`loopCount: 2`, `maxConnections: 8192`, response compression on, idle
60 s). 64 concurrent connections, 4 s measured window after 0.8 s warmup.

| Route          | req/s  | p50 (ms) | p90 (ms) | p99 (ms) | errors |
|----------------|-------:|---------:|---------:|---------:|-------:|
| `/json`        | 74,883 |    0.827 |    1.093 |    1.524 |      0 |
| `/plaintext`   | 71,214 |    0.853 |    1.156 |    1.616 |      0 |
| `/users/{id}`  | 68,247 |    0.892 |    1.174 |    1.780 |      0 |

Concurrency sweep, `/plaintext` (req/s): c=16 → 62,093 · c=64 → 67,132 · c=128 → 65,859 · c=256 → 66,246.

## Interpretation

- **~70k req/s, sub-ms p50, p99 < 1.8 ms, zero errors** through the full engine path (routing + per-route
  no-pool context + response framing + the constant envelope). Param routing (`/users/{id}`) costs only
  ~9% over raw plaintext — the segment trie + one path capture are cheap.
- **These are a client-limited LOWER BOUND, not the server's ceiling.** Throughput plateaus from c=16
  onward (62k→67k across a 16× concurrency range), which is the signature of a saturated *load generator*,
  not a saturated server (server p99 stays ~1.6 ms with plenty of headroom on only 2 event loops). A single
  Bun process can't push harder; the server has more to give.

## Caveats / next steps

- **Coordinated omission:** the generator is closed-loop, so the measured tail (p99) is optimistic. For
  rigorous tails, drive `ADServeBench` with an open-loop / constant-rate tool (`oha`, `wrk2`).
- **Find the real ceiling:** run the load generator from multiple processes/hosts (or a faster tool) and
  raise the server's `loopCount` toward the core count, to push past the single-client plateau.
- **Comparative numbers:** to substantiate "most performant," benchmark the same routes against
  Hummingbird / Vapor under the identical harness. Tracked as a follow-up.
