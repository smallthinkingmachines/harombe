"""Conftest for performance benchmarks — adds CLI options and session fixtures."""

import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--benchmark-runs",
        action="store",
        default="1",
        type=int,
        help="Number of independent benchmark runs for multi-run aggregation (default: 1)",
    )


@pytest.fixture(scope="session")
def benchmark_run_count(request):
    """Return the number of benchmark runs requested via --benchmark-runs."""
    return request.config.getoption("--benchmark-runs")
