// Minimal closed-loop load generator for ADServeBench — Bun, zero external deps. Spawns CONCURRENCY
// workers, each looping `GET <url>` (draining the body so keep-alive connections are reused) for
// DURATION after a WARMUP window, recording per-request latency. Reports req/s + latency p50/p90/p99.
//
// Usage:  bun Benchmarks/loadtest.js [url] [concurrency] [durationMs] [warmupMs]
// e.g.    bun Benchmarks/loadtest.js http://127.0.0.1:8080/plaintext 64 5000 1000
//
// Methodology note (assessed, not hidden): this is CLOSED-loop (fixed in-flight concurrency). A stalled
// request blocks its worker, so the measured tail (p99) is subject to coordinated omission — treat it as
// an OPTIMISTIC lower bound. The req/s headline and p50 are reliable. For rigorous tails, drive the same
// server with an open-loop / constant-rate tool (oha, wrk2); this harness is the dep-free baseline.

const url = process.argv[2] ?? "http://127.0.0.1:8080/plaintext";
const concurrency = Number(process.argv[3] ?? 64);
const durationMs = Number(process.argv[4] ?? 5000);
const warmupMs = Number(process.argv[5] ?? 1000);

const latencies = [];
let recording = false;
let count = 0;
let errors = 0;
let stop = false;

async function worker() {
  while (!stop) {
    const t0 = performance.now();
    try {
      const res = await fetch(url);
      await res.arrayBuffer(); // drain → connection returns to Bun's keep-alive pool
      if (res.status !== 200) errors++;
    } catch {
      errors++;
    }
    const dt = performance.now() - t0;
    if (recording) {
      latencies.push(dt);
      count++;
    }
  }
}

const workers = Array.from({ length: concurrency }, () => worker());
await Bun.sleep(warmupMs); // let connections + the server's loops settle
recording = true;
const start = performance.now();
await Bun.sleep(durationMs);
const elapsed = (performance.now() - start) / 1000;
stop = true;
await Promise.all(workers);

latencies.sort((a, b) => a - b);
const pct = (p) => latencies[Math.min(latencies.length - 1, Math.floor((p / 100) * latencies.length))] ?? 0;
const round = (x) => Math.round(x * 1000) / 1000;
console.log(
  JSON.stringify(
    {
      url,
      concurrency,
      durationSec: round(elapsed),
      requests: count,
      errors,
      rps: Math.round(count / elapsed),
      latencyMs: { p50: round(pct(50)), p90: round(pct(90)), p99: round(pct(99)), max: round(pct(100)) },
    },
    null,
    2,
  ),
);
