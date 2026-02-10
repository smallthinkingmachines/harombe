"""Tests for PatternBase and PatternMetrics."""

import pytest

from harombe.llm.client import Message
from harombe.patterns.base import PatternBase, PatternMetrics


class TestPatternMetrics:
    def test_initial_state(self):
        m = PatternMetrics()
        assert m.total_requests == 0
        assert m.local_requests == 0
        assert m.cloud_requests == 0
        assert m.escalations == 0
        assert m.average_latency_ms == 0.0

    def test_record_local_request(self):
        m = PatternMetrics()
        m.record_request(target="local", latency_ms=10.0)
        assert m.total_requests == 1
        assert m.local_requests == 1
        assert m.cloud_requests == 0
        assert m.average_latency_ms == 10.0

    def test_record_cloud_request(self):
        m = PatternMetrics()
        m.record_request(target="cloud", latency_ms=50.0)
        assert m.total_requests == 1
        assert m.cloud_requests == 1

    def test_average_latency(self):
        m = PatternMetrics()
        m.record_request(target="local", latency_ms=10.0)
        m.record_request(target="cloud", latency_ms=30.0)
        assert m.average_latency_ms == 20.0

    def test_record_escalation(self):
        m = PatternMetrics()
        m.record_escalation()
        m.record_escalation()
        assert m.escalations == 2

    def test_to_dict(self):
        m = PatternMetrics()
        m.record_request(target="local", latency_ms=5.0)
        m.record_escalation()
        d = m.to_dict()
        assert d == {
            "total_requests": 1,
            "local_requests": 1,
            "cloud_requests": 0,
            "escalations": 1,
            "average_latency_ms": 5.0,
        }


class TestPatternBase:
    def test_name_attribute(self):
        p = PatternBase(name="test_pattern")
        assert p.name == "test_pattern"

    def test_has_metrics(self):
        p = PatternBase(name="test")
        assert isinstance(p.metrics, PatternMetrics)

    @pytest.mark.asyncio
    async def test_complete_raises_not_implemented(self):
        p = PatternBase(name="test")
        with pytest.raises(NotImplementedError):
            await p.complete([Message(role="user", content="hi")])

    def test_timer_helpers(self):
        p = PatternBase(name="test")
        start = p._start_timer()
        elapsed = p._elapsed_ms(start)
        assert elapsed >= 0
