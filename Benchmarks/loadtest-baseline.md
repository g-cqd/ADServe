# ADServe live-load baseline

End-to-end HTTP throughput + latency for the engine over a real socket — the live counterpart to the
in-process `ADServeSuite` micro-benchmarks (which time pure routing under `swift package benchmark`).
Captured with the runnable `ADServeBench` server (`Sources/ADServeBench/`).

## Reproduce

```sh
# build + run the bench server. Event loops now default to HTTPServer.defaultLoopCount (= System.coreCount,
# cgroup-aware) — peak multicore out of the box. ADSERVE_BENCH_LOOPS overrides it (e.g. to sweep scaling).
ADSERVE_DEV=1 swift run -c release --build-system native ADServeBench 18080

# drive load — oha (Rust, open-loop, low client overhead → leaves cores for the server) is the primary
# tool; the committed Benchmarks/loadtest.js (dep-free Bun) is the portable smoke check.
oha -z 5s -c 64 --no-tui http://127.0.0.1:18080/plaintext
bun Benchmarks/loadtest.js http://127.0.0.1:18080/plaintext 64 5000 1000
```

## Baseline — 2026-06-21

Host: Apple Silicon, 8 logical cores (macOS / Darwin 25.5.0). Release build. Server through the FULL engine
(security envelope, keep-alive, idle timeout, connection limiter, response compression). Driver: oha 1.14,
`/plaintext`, 4 s window.

### Event-loop scaling (the architecture check), oha, 64 connections

| `loopCount`         | req/s  | p50 (ms) | p99 (ms) |
|---------------------|-------:|---------:|---------:|
| 1                   | 36,685 |    1.739 |    2.412 |
| 2 *(engine default)*| 72,605 |    0.828 |    1.476 |
| 4                   | 81,271 |    0.673 |    1.936 |
| 8                   | 85,122 |    0.529 |    4.614 |
| 8 @ conc 128        | 86,415 |    1.087 |    8.682 |
| 8 @ conc 256        | 85,791 |    2.253 |   16.609 |

**1 → 2 loops scales near-linearly (36.7k → 72.6k)** — the accept/serve path parallelizes cleanly. 2 → 8
shows diminishing returns that are a CO-LOCATED artifact: oha and the server share the same 8 cores, so past
~half the cores the load generator and the server start competing. The ~86k plateau is this machine's
combined server+client ceiling, not the server's.

### Per route, oha, `loopCount: 8`, 64 connections

| Route          | req/s  | p50 (ms) | p99 (ms) | success |
|----------------|-------:|---------:|---------:|--------:|
| `/json`        | 89,329 |    0.509 |    4.225 | 100.00% |
| `/plaintext`   | 87,634 |    0.534 |    3.861 | 100.00% |
| `/users/{id}`  | 84,705 |    0.528 |    4.823 | 100.00% |

Param routing costs only ~3% over raw plaintext — the segment trie + one path capture are nearly free.

### Portable dep-free check (Bun `loadtest.js`, closed-loop, `loopCount: 2`)

`/json` 74.9k · `/plaintext` 71.2k · `/users/{id}` 68.2k req/s, 0 errors, p99 < 1.8 ms. Lower than oha
because the single-process JS client is itself CPU-bound (it caps near ~70k regardless of server loops);
use it for a quick portable smoke, oha for real numbers.

## Findings

- **~85–89k req/s, sub-ms p50, p99 ~4 ms, 100% success** through the full engine on 8 loops — solid for a
  real server (not a bare socket). Clean 1→2 loop scaling shows the design parallelizes.
- **FIXED — `HTTPServer` now defaults `loopCount` to `System.coreCount`** (`defaultLoopCount`). This sweep is
  what surfaced it: the prior hardcoded `2` left ~17% throughput unused on an 8-core host (72.6k vs 85–87k),
  and far more as cores grow. `System.coreCount` is the NIO/swift-server convention and is cgroup-aware (a
  constrained container gets its CPU quota, not the host count), so it is safe by default; apps still pass an
  explicit `loopCount:` to pin it. Verified: out-of-box `swift run ADServeBench` now serves **86.1k** req/s
  (was ~72k), 273 tests green.
- **FIXED — sub-MTU responses no longer on-the-fly-compressed** (`gzip_min_length`;
  `HTTPServer.minimumCompressibleResponseBytes = 1400`). The Hummingbird comparison below surfaced it +
  `sample` localized it: ADServe was building a gzip Huffman tree for a 13-byte body (the predicate gated on
  MIME + not-206 but had no size floor). Skipping it recovered `/plaintext` from ~88k to **~99–106k** req/s.
  Compressing a sub-MTU body never helps (one packet either way) and can enlarge it; large + streamed bodies
  still compress. 274 tests green.

## Cross-stack comparison (5-way)

Same machine, same oha (`-z 5s -c 64`), routes byte-matched, each server benchmarked ALONE (never
co-resident, so each gets the full 8-core box), best-of-2. ADServe is run with the `gzip_min_length` fix.

| Server (stack)                | /plaintext | /json  | /users/{id} | p50      |
|-------------------------------|-----------:|-------:|------------:|----------|
| **Bun** (JS / Zig, `routes`)  | **203.8k** | 197.5k |      169.2k | 0.28 ms  |
| **raw-swift** (no NIO, `Benchmarks/raw-spike`) | **196.8k** | 180.2k | 173.9k | 0.30 ms |
| **Go** `net/http` (Go)        |     162.9k | 155.7k |      156.4k | 0.33 ms  |
| **Erlang** raw `gen_tcp` (BEAM)|    142.9k | 140.5k |      136.8k | 0.33 ms  |
| **Hummingbird 2.25** (Swift/NIO)| 114.7k | 112.4k |      109.2k | 0.27 ms  |
| **ADServe** (Swift/NIO)       |     102.4k | 100.5k |       95.5k | 0.36 ms  |

**Headline — the bottleneck is SwiftNIO, not Swift.** A from-scratch raw-Darwin-socket Swift server
(`Benchmarks/raw-spike`) hits **196.8k — ~2× NIO-ADServe and ~1.7× NIO-Hummingbird** — second overall, behind
only Bun. Both NIO servers sit at the bottom; raw Swift vaults to the top. So Swift/ARC is *not* the floor: the
NIO `ChannelHandler` pipeline is ~half the throughput on this micro-workload. (Caveat: tiny-response keep-alive
is the BEST case for raw — TLS/HTTP-2/large bodies shrink the gap. And the spike has no TLS/robustness; see its
README.) **Implication:** the path to "most performant" is a Darwin-only from-scratch transport on **raw
sockets** under ADServe's existing HTTP/routing/security layer — NOT micro-tuning the NIO path (the per-request
header A/B confirmed that's a dead end: 93.2k vs 93.7k, noise), and NOT `Network.framework` (tested + ruled out:
**89.9k, slower than NIO** with 2.3× the latency — see `raw-spike/README.md`). TLS for the fast path comes from
the fronting proxy (ADServe is proxy-fronted); the NIO engine stays for direct-TLS / HTTP-2.

Reproduce: the four external servers are tiny (~15 lines each) — a Bun `Bun.serve({routes})`, a Go
`net/http.ServeMux`, an Erlang `gen_tcp` listener with `{packet, http_bin}`, and the Hummingbird `Router`
quickstart — all with the same `/plaintext` `/json` `/users/:id` `/health` routes.

## Caveats / next steps

- **Co-located ceiling:** server + load generator share these 8 cores, so the multicore plateau is a machine
  artifact. The true server ceiling needs the load driven from a SEPARATE host.
- **Comparative claim:** done vs Hummingbird (above) — ADServe trails by ~15% after the compression fix.
  The network is NOT blocked for public deps (only private AD* repos need local paths), so a Vapor leg + a
  feature-matched comparison (Hummingbird with the same DoS defenses on) are the next comparative steps.
- **Close the residual gap (the live #1 target):** profile + trim the core per-request path — the per-request
  active-request atomics, the response-head materialization/envelope merge — to reach Hummingbird's ~117k.
- **Tails:** oha is open-loop, so its p99/p99.9 are sound; push `-q` (rate limiting) for latency-at-fixed-load
  curves if needed.
