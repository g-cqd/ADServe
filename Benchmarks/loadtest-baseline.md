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

## Comparison — vs Hummingbird 2.25 (the closest NIO peer)

Same machine, same oha (`-z 5s -c 64`), routes byte-matched, each server benchmarked ALONE (never
co-resident), default config both (≈core-count event loops). Caveat: this is **default vs default**, not
feature-matched — Hummingbird's default is leaner (no built-in response compression / connection-limiter /
idle-timeout), whereas ADServe ships those DoS defenses ON.

| Route          | ADServe (before fix) | ADServe (after `gzip_min_length`) | Hummingbird |
|----------------|---------------------:|----------------------------------:|------------:|
| `/plaintext`   |                87.7k |                          ~99–106k |      117.5k |
| `/json`        |                90.2k |                            ~90–98k |      116.9k |
| `/users/{id}`  |                83.5k |                              ~90k |      113.6k |

**Honest read:** ADServe is **not yet the fastest here** — Hummingbird leads. ~Half the original ~34% gap was
ADServe compressing tiny bodies (now fixed → ~15% gap). The **residual ~15% is the core per-request path**
(per-request active-count atomics + response materialization vs Hummingbird's leaner handler) — the next #1
target. ADServe does hold a slightly better p99 tail (its safety machinery costs throughput but smooths tails).

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
