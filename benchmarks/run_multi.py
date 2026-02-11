#!/usr/bin/env python3
"""Multi-run benchmark aggregation for paper-grade cross-run CIs.

Usage:
    python benchmarks/run_multi.py --runs 5

Invokes pytest N times on the whitepaper benchmark suite, reads
benchmarks/whitepaper_results.json after each run, and aggregates
all performance means into benchmarks/multi_run_results.json.
"""

import argparse
import json
import statistics
import subprocess
import sys
from pathlib import Path


def _aggregate(all_run_means: list[float]) -> dict[str, float]:
    """Compute cross-run statistics with 95% CI."""
    from scipy.stats import t as t_dist

    n = len(all_run_means)
    mean = statistics.mean(all_run_means)
    if n >= 2:
        stdev = statistics.stdev(all_run_means)
        t_val = t_dist.ppf(0.975, df=n - 1)
        margin = t_val * (stdev / (n**0.5))
    else:
        stdev = 0.0
        margin = 0.0
    return {
        "mean_of_means": mean,
        "stdev": stdev,
        "ci95_lower": mean - margin,
        "ci95_upper": mean + margin,
        "n_runs": n,
    }


def _extract_means(performance: dict) -> dict[str, float]:
    """Extract all 'mean' values from the performance section."""
    means: dict[str, float] = {}
    for key, value in performance.items():
        if isinstance(value, dict):
            if "mean" in value:
                means[key] = value["mean"]
            else:
                # Nested (e.g., secret_scan_by_size has sub-keys per size)
                for sub_key, sub_val in value.items():
                    if isinstance(sub_val, dict) and "mean" in sub_val:
                        means[f"{key}.{sub_key}"] = sub_val["mean"]
    return means


def main():
    parser = argparse.ArgumentParser(description="Multi-run benchmark aggregation")
    parser.add_argument("--runs", type=int, default=5, help="Number of benchmark runs")
    args = parser.parse_args()

    results_path = Path("benchmarks/whitepaper_results.json")
    per_run_results: list[dict] = []
    all_means: dict[str, list[float]] = {}

    print(f"Running {args.runs} benchmark iterations...\n")

    for i in range(1, args.runs + 1):
        print(f"--- Run {i}/{args.runs} ---")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "tests/performance/test_whitepaper_benchmarks.py",
                "-v",
                "-s",
                "--tb=short",
                "-q",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f"  WARNING: Run {i} exited with code {result.returncode}")
            if result.stderr:
                # Print last few lines of stderr for debugging
                lines = result.stderr.strip().split("\n")
                for line in lines[-5:]:
                    print(f"    {line}")

        if not results_path.exists():
            print(f"  ERROR: {results_path} not found after run {i}, skipping")
            continue

        with open(results_path) as f:
            run_data = json.load(f)

        per_run_results.append(run_data)
        performance = run_data.get("performance", {})
        means = _extract_means(performance)

        for metric, value in means.items():
            all_means.setdefault(metric, []).append(value)

        print(f"  Collected {len(means)} performance metrics")

    # Aggregate
    aggregated: dict[str, dict] = {}
    for metric, values in all_means.items():
        aggregated[metric] = _aggregate(values)

    output = {
        "aggregated_performance": aggregated,
        "n_runs": len(per_run_results),
        "per_run_results": per_run_results,
    }

    output_path = Path("benchmarks/multi_run_results.json")
    output_path.parent.mkdir(exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, default=str)

    print(f"\n{'=' * 60}")
    print(f"Aggregated results from {len(per_run_results)} runs → {output_path}")
    print(f"{'=' * 60}")

    # Summary table
    if aggregated:
        print(f"\n{'Metric':<45} {'Mean':>10} {'StdDev':>10} {'CI95':>20}")
        print("-" * 90)
        for metric, stats in sorted(aggregated.items()):
            print(
                f"{metric:<45} {stats['mean_of_means']:>10.4f} "
                f"{stats['stdev']:>10.4f} "
                f"[{stats['ci95_lower']:.4f}, {stats['ci95_upper']:.4f}]"
            )


if __name__ == "__main__":
    main()
