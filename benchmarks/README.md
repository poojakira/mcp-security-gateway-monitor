# Performance Benchmarks

The monitor sits **inline** with every MCP tool call, so its per-call overhead
directly bounds the throughput of the system it protects. This suite measures
the real latency distribution and single-threaded throughput of the hot path.

## Running

```bash
python benchmarks/benchmark.py                 # default 20,000 iterations
python benchmarks/benchmark.py --iterations 50000
python benchmarks/benchmark.py --json          # machine-readable
```

The harness runs a warm-up phase (discarded), times each call with
`time.perf_counter_ns`, and uses a realistic workload mix (80% benign / 20%
attack, exercising every detector branch) with the audit log writing to a real
temp-file append so hash-chaining + disk cost are included.

## Measured results (dev/CI sandbox)

Measured on the development sandbox (single thread, 20,000 iterations after a
2,000-iteration warm-up). **Numbers are hardware-dependent** — re-run on your
own target to get representative figures.

| Path                            | p50    | p95    | p99     | mean   | throughput          |
| ------------------------------- | ------ | ------ | ------- | ------ | ------------------- |
| `inspect_call` (full, + audit)  | 68.3µs | 95.7µs | 113.0µs | 71.0µs | ~14,000 calls/sec   |
| `inspect_output` (full, + audit)| 52.0µs | 60.2µs | 80.5µs  | 55.0µs | ~18,000 calls/sec   |

### Honest interpretation

- **Sub-millisecond p99.** The full `inspect_call` — four detectors plus a
  hash-chained audit append — completes in ~113µs at p99 on this hardware. For
  context, a single LLM tool-call round trip is typically hundreds of
  milliseconds, so the monitor adds well under 0.1% latency overhead in a
  realistic agent loop.
- **~14k calls/sec single-threaded.** The core is pure-Python and CPU-bound;
  it scales horizontally across processes/workers since each `inspect_call` is
  independent and the only shared state is the append-only audit log.
- **Max latency outliers exist** (see `max` in the tool output) and are
  dominated by occasional allocation / GC and first-touch temp-file I/O, not
  steady-state cost — which is why p50/p95/p99 are the numbers to trust.
- **What this does *not* measure:** the optional ML classifier (`[ml]`) and the
  `[dpi]` deep-packet-inspection path, which are heavier and run out-of-band in
  the layered/defense10 configurations, not on this core hot path.

These figures are produced by `benchmark.py` and are covered by
`tests/test_benchmark.py`, which asserts the harness runs and that percentile
ordering / non-negativity / positive-throughput invariants hold (it does not
assert absolute latencies, which would be flaky across hardware).
