"""Smoke tests for the performance benchmark harness.

These do not assert absolute latency numbers (those are hardware-dependent and
would make the suite flaky). They assert the harness runs, returns well-formed
statistics, and that the measured invariants hold (percentile ordering, all
values non-negative, throughput positive).
"""

from __future__ import annotations

from benchmarks.benchmark import run_benchmarks


def _run():
    # Small iteration count keeps the test fast but still exercises the path.
    return run_benchmarks(iterations=200, warmup=20, verbose=False)


def test_benchmark_runs_and_returns_results():
    result = _run()
    assert result["iterations"] == 200
    assert isinstance(result["results"], list)
    assert len(result["results"]) == 2


def test_benchmark_reports_both_hot_paths():
    labels = {r["label"] for r in _run()["results"]}
    assert any("inspect_call" in label for label in labels)
    assert any("inspect_output" in label for label in labels)


def test_benchmark_percentiles_are_ordered():
    for r in _run()["results"]:
        assert r["p50_us"] <= r["p95_us"] <= r["p99_us"] <= r["max_us"]


def test_benchmark_values_are_non_negative():
    for r in _run()["results"]:
        assert r["p50_us"] >= 0
        assert r["mean_us"] >= 0
        assert r["max_us"] >= 0


def test_benchmark_throughput_is_positive():
    for r in _run()["results"]:
        assert r["throughput_per_sec"] > 0
