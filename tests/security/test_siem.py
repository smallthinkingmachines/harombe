"""Tests for SIEM integration."""

import time
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from harombe.security.audit_db import AuditEvent, EventType
from harombe.security.siem_integration import (
    DatadogExporter,
    ElasticsearchExporter,
    ExportResult,
    SIEMConfig,
    SIEMEvent,
    SIEMIntegrator,
    SIEMPlatform,
    SplunkExporter,
    _iso_to_epoch,
    _severity_to_datadog_status,
)

# --- Fixtures ---


def _make_audit_event(
    event_type: EventType = EventType.REQUEST,
    actor: str = "agent-001",
    action: str = "read_file",
    status: str = "success",
    tool_name: str = "filesystem",
    correlation_id: str = "corr-123",
    session_id: str = "sess-456",
    duration_ms: int | None = 150,
    error_message: str | None = None,
    metadata: dict | None = None,
) -> AuditEvent:
    """Create a test audit event."""
    return AuditEvent(
        correlation_id=correlation_id,
        session_id=session_id,
        event_type=event_type,
        actor=actor,
        action=action,
        tool_name=tool_name,
        status=status,
        duration_ms=duration_ms,
        error_message=error_message,
        metadata=metadata or {},
    )


def _make_splunk_config(**kwargs) -> SIEMConfig:
    """Create a Splunk config for testing."""
    defaults = {
        "platform": SIEMPlatform.SPLUNK,
        "endpoint": "https://splunk.example.com:8088",
        "token": "test-hec-token",
        "index": "harombe-test",
        "batch_size": 10,
        "flush_interval_s": 1.0,
        "max_retries": 2,
        "retry_delay_s": 0.01,
        "timeout_s": 5.0,
    }
    defaults.update(kwargs)
    return SIEMConfig(**defaults)


def _make_elk_config(**kwargs) -> SIEMConfig:
    """Create an Elasticsearch config for testing."""
    defaults = {
        "platform": SIEMPlatform.ELASTICSEARCH,
        "endpoint": "https://elk.example.com:9200",
        "token": "test-api-key",
        "index": "harombe-test",
        "batch_size": 10,
        "flush_interval_s": 1.0,
        "max_retries": 2,
        "retry_delay_s": 0.01,
        "timeout_s": 5.0,
    }
    defaults.update(kwargs)
    return SIEMConfig(**defaults)


def _make_datadog_config(**kwargs) -> SIEMConfig:
    """Create a Datadog config for testing."""
    defaults = {
        "platform": SIEMPlatform.DATADOG,
        "endpoint": "https://http-intake.logs.datadoghq.com",
        "token": "test-dd-api-key",
        "index": "harombe-test",
        "batch_size": 10,
        "flush_interval_s": 1.0,
        "max_retries": 2,
        "retry_delay_s": 0.01,
        "timeout_s": 5.0,
    }
    defaults.update(kwargs)
    return SIEMConfig(**defaults)


# --- SIEMPlatform Enum Tests ---


class TestSIEMPlatform:
    """Tests for SIEMPlatform enum."""

    def test_platform_values(self):
        assert SIEMPlatform.SPLUNK == "splunk"
        assert SIEMPlatform.ELASTICSEARCH == "elasticsearch"
        assert SIEMPlatform.DATADOG == "datadog"

    def test_platform_from_string(self):
        assert SIEMPlatform("splunk") == SIEMPlatform.SPLUNK
        assert SIEMPlatform("elasticsearch") == SIEMPlatform.ELASTICSEARCH
        assert SIEMPlatform("datadog") == SIEMPlatform.DATADOG

    def test_invalid_platform(self):
        with pytest.raises(ValueError):
            SIEMPlatform("invalid")


# --- SIEMConfig Tests ---


class TestSIEMConfig:
    """Tests for SIEMConfig model."""

    def test_default_values(self):
        config = SIEMConfig(
            platform=SIEMPlatform.SPLUNK,
            endpoint="https://splunk.example.com:8088",
        )
        assert config.enabled is True
        assert config.batch_size == 50
        assert config.flush_interval_s == 5.0
        assert config.max_retries == 3
        assert config.retry_delay_s == 1.0
        assert config.timeout_s == 10.0
        assert config.index == "harombe-security"
        assert config.token == ""

    def test_custom_values(self):
        config = _make_splunk_config(batch_size=100, max_retries=5)
        assert config.batch_size == 100
        assert config.max_retries == 5

    def test_batch_size_bounds(self):
        with pytest.raises(ValueError):
            SIEMConfig(
                platform=SIEMPlatform.SPLUNK,
                endpoint="https://example.com",
                batch_size=0,
            )
        with pytest.raises(ValueError):
            SIEMConfig(
                platform=SIEMPlatform.SPLUNK,
                endpoint="https://example.com",
                batch_size=1001,
            )

    def test_disabled_config(self):
        config = _make_splunk_config(enabled=False)
        assert config.enabled is False


# --- SIEMEvent Tests ---


class TestSIEMEvent:
    """Tests for SIEMEvent conversion."""

    def test_from_audit_event_basic(self):
        event = _make_audit_event()
        siem_event = SIEMEvent.from_audit_event(event)

        assert siem_event.event_id == event.event_id
        assert siem_event.event_type == "request"
        assert siem_event.actor == "agent-001"
        assert siem_event.action == "read_file"
        assert siem_event.status == "success"
        assert siem_event.tool_name == "filesystem"
        assert siem_event.correlation_id == "corr-123"
        assert siem_event.session_id == "sess-456"
        assert siem_event.duration_ms == 150
        assert siem_event.source == "harombe"
        assert siem_event.severity == "info"
        assert siem_event.timestamp.endswith("Z")

    def test_error_event_severity(self):
        event = _make_audit_event(event_type=EventType.ERROR, status="error")
        siem_event = SIEMEvent.from_audit_event(event)
        assert siem_event.severity == "error"

    def test_security_decision_severity(self):
        event = _make_audit_event(event_type=EventType.SECURITY_DECISION)
        siem_event = SIEMEvent.from_audit_event(event)
        assert siem_event.severity == "warning"

    def test_error_status_severity(self):
        event = _make_audit_event(status="error")
        siem_event = SIEMEvent.from_audit_event(event)
        assert siem_event.severity == "error"

    def test_with_metadata(self):
        event = _make_audit_event(metadata={"path": "/etc/passwd", "method": "GET"})
        siem_event = SIEMEvent.from_audit_event(event)
        assert siem_event.metadata["path"] == "/etc/passwd"
        assert siem_event.metadata["method"] == "GET"

    def test_with_error_message(self):
        event = _make_audit_event(
            status="error",
            error_message="Permission denied",
        )
        siem_event = SIEMEvent.from_audit_event(event)
        assert siem_event.error_message == "Permission denied"

    def test_without_optional_fields(self):
        event = _make_audit_event(
            tool_name=None,
            session_id=None,
            duration_ms=None,
        )
        siem_event = SIEMEvent.from_audit_event(event)
        assert siem_event.tool_name is None
        assert siem_event.session_id is None
        assert siem_event.duration_ms is None


# --- Splunk Exporter Tests ---


class TestSplunkExporter:
    """Tests for Splunk HEC exporter."""

    def test_format_events(self):
        config = _make_splunk_config()
        exporter = SplunkExporter(config)
        event = SIEMEvent.from_audit_event(_make_audit_event())

        formatted = exporter.format_events([event])
        assert len(formatted) == 1
        assert formatted[0]["sourcetype"] == "harombe:security"
        assert formatted[0]["source"] == "harombe"
        assert formatted[0]["index"] == "harombe-test"
        assert "event" in formatted[0]
        assert "time" in formatted[0]

    def test_format_multiple_events(self):
        config = _make_splunk_config()
        exporter = SplunkExporter(config)
        events = [
            SIEMEvent.from_audit_event(_make_audit_event(action=f"action_{i}")) for i in range(5)
        ]
        formatted = exporter.format_events(events)
        assert len(formatted) == 5

    def test_get_headers(self):
        config = _make_splunk_config()
        exporter = SplunkExporter(config)
        headers = exporter.get_headers()
        assert headers["Authorization"] == "Splunk test-hec-token"
        assert headers["Content-Type"] == "application/json"

    def test_get_url(self):
        config = _make_splunk_config()
        exporter = SplunkExporter(config)
        assert exporter.get_url() == "https://splunk.example.com:8088/services/collector/event"

    def test_get_url_strips_trailing_slash(self):
        config = _make_splunk_config(endpoint="https://splunk.example.com:8088/")
        exporter = SplunkExporter(config)
        assert exporter.get_url() == "https://splunk.example.com:8088/services/collector/event"

    @pytest.mark.asyncio
    async def test_send_success(self):
        config = _make_splunk_config()
        exporter = SplunkExporter(config)
        event = SIEMEvent.from_audit_event(_make_audit_event())

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.is_closed = False
        exporter._client = mock_client

        result = await exporter.send([event])
        assert result.success is True
        assert result.events_sent == 1
        assert result.platform == SIEMPlatform.SPLUNK
        assert result.latency_ms > 0

    @pytest.mark.asyncio
    async def test_send_with_retry(self):
        config = _make_splunk_config(max_retries=2, retry_delay_s=0.01)
        exporter = SplunkExporter(config)
        event = SIEMEvent.from_audit_event(_make_audit_event())

        # First call fails, second succeeds
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            side_effect=[
                httpx.RequestError("Connection refused"),
                mock_response,
            ]
        )
        mock_client.is_closed = False
        exporter._client = mock_client

        result = await exporter.send([event])
        assert result.success is True
        assert result.retries == 1

    @pytest.mark.asyncio
    async def test_send_all_retries_fail(self):
        config = _make_splunk_config(max_retries=2, retry_delay_s=0.01)
        exporter = SplunkExporter(config)
        event = SIEMEvent.from_audit_event(_make_audit_event())

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            side_effect=httpx.RequestError("Connection refused"),
        )
        mock_client.is_closed = False
        exporter._client = mock_client

        result = await exporter.send([event])
        assert result.success is False
        assert result.events_failed == 1
        assert result.error is not None
        assert result.retries == 3  # initial + 2 retries

    @pytest.mark.asyncio
    async def test_send_empty_events(self):
        config = _make_splunk_config()
        exporter = SplunkExporter(config)
        result = await exporter.send([])
        assert result.success is True
        assert result.events_sent == 0


# --- Elasticsearch Exporter Tests ---


class TestElasticsearchExporter:
    """Tests for Elasticsearch exporter."""

    def test_format_events(self):
        config = _make_elk_config()
        exporter = ElasticsearchExporter(config)
        event = SIEMEvent.from_audit_event(_make_audit_event())

        formatted = exporter.format_events([event])
        assert len(formatted) == 1
        assert formatted[0]["_index"] == "harombe-test"
        assert formatted[0]["_id"] == event.event_id
        assert "_source" in formatted[0]

    def test_get_headers_with_token(self):
        config = _make_elk_config(token="my-api-key")
        exporter = ElasticsearchExporter(config)
        headers = exporter.get_headers()
        assert headers["Authorization"] == "ApiKey my-api-key"
        assert headers["Content-Type"] == "application/json"

    def test_get_headers_without_token(self):
        config = _make_elk_config(token="")
        exporter = ElasticsearchExporter(config)
        headers = exporter.get_headers()
        assert "Authorization" not in headers
        assert headers["Content-Type"] == "application/json"

    def test_get_url(self):
        config = _make_elk_config()
        exporter = ElasticsearchExporter(config)
        assert exporter.get_url() == "https://elk.example.com:9200/harombe-test/_bulk"

    @pytest.mark.asyncio
    async def test_send_success(self):
        config = _make_elk_config()
        exporter = ElasticsearchExporter(config)
        event = SIEMEvent.from_audit_event(_make_audit_event())

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.is_closed = False
        exporter._client = mock_client

        result = await exporter.send([event])
        assert result.success is True
        assert result.events_sent == 1
        assert result.platform == SIEMPlatform.ELASTICSEARCH


# --- Datadog Exporter Tests ---


class TestDatadogExporter:
    """Tests for Datadog exporter."""

    def test_format_events(self):
        config = _make_datadog_config()
        exporter = DatadogExporter(config)
        event = SIEMEvent.from_audit_event(_make_audit_event())

        formatted = exporter.format_events([event])
        assert len(formatted) == 1
        assert formatted[0]["ddsource"] == "harombe"
        assert formatted[0]["service"] == "harombe-security"
        assert formatted[0]["hostname"] == "harombe-gateway"
        assert "ddtags" in formatted[0]
        assert "type:request" in formatted[0]["ddtags"]
        assert formatted[0]["status"] == "info"

    def test_format_error_event(self):
        config = _make_datadog_config()
        exporter = DatadogExporter(config)
        event = SIEMEvent.from_audit_event(
            _make_audit_event(event_type=EventType.ERROR, status="error")
        )

        formatted = exporter.format_events([event])
        assert formatted[0]["status"] == "error"

    def test_get_headers(self):
        config = _make_datadog_config()
        exporter = DatadogExporter(config)
        headers = exporter.get_headers()
        assert headers["DD-API-KEY"] == "test-dd-api-key"
        assert headers["Content-Type"] == "application/json"

    def test_get_url(self):
        config = _make_datadog_config()
        exporter = DatadogExporter(config)
        assert exporter.get_url() == "https://http-intake.logs.datadoghq.com/api/v2/logs"

    @pytest.mark.asyncio
    async def test_send_success(self):
        config = _make_datadog_config()
        exporter = DatadogExporter(config)
        event = SIEMEvent.from_audit_event(_make_audit_event())

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.is_closed = False
        exporter._client = mock_client

        result = await exporter.send([event])
        assert result.success is True
        assert result.events_sent == 1
        assert result.platform == SIEMPlatform.DATADOG


# --- SIEMIntegrator Tests ---


class TestSIEMIntegrator:
    """Tests for the main SIEMIntegrator."""

    def test_init_no_configs(self):
        integrator = SIEMIntegrator()
        assert len(integrator.platforms) == 0
        assert integrator.stats["events_received"] == 0

    def test_init_with_configs(self):
        configs = [_make_splunk_config(), _make_elk_config()]
        integrator = SIEMIntegrator(configs)
        assert len(integrator.platforms) == 2
        assert SIEMPlatform.SPLUNK in integrator.platforms
        assert SIEMPlatform.ELASTICSEARCH in integrator.platforms

    def test_init_disabled_config_skipped(self):
        configs = [
            _make_splunk_config(enabled=True),
            _make_elk_config(enabled=False),
        ]
        integrator = SIEMIntegrator(configs)
        assert len(integrator.platforms) == 1
        assert SIEMPlatform.SPLUNK in integrator.platforms
        assert SIEMPlatform.ELASTICSEARCH not in integrator.platforms

    def test_add_platform(self):
        integrator = SIEMIntegrator()
        integrator.add_platform(_make_datadog_config())
        assert SIEMPlatform.DATADOG in integrator.platforms
        assert "datadog" in integrator.stats["per_platform"]

    def test_add_disabled_platform_ignored(self):
        integrator = SIEMIntegrator()
        integrator.add_platform(_make_datadog_config(enabled=False))
        assert len(integrator.platforms) == 0

    def test_remove_platform(self):
        configs = [_make_splunk_config(), _make_elk_config()]
        integrator = SIEMIntegrator(configs)
        integrator.remove_platform(SIEMPlatform.SPLUNK)
        assert SIEMPlatform.SPLUNK not in integrator.platforms
        assert SIEMPlatform.ELASTICSEARCH in integrator.platforms

    def test_remove_nonexistent_platform(self):
        integrator = SIEMIntegrator()
        integrator.remove_platform(SIEMPlatform.DATADOG)  # No error

    def test_get_stats(self):
        configs = [_make_splunk_config()]
        integrator = SIEMIntegrator(configs)
        stats = integrator.get_stats()
        assert stats["events_received"] == 0
        assert stats["events_exported"] == 0
        assert "splunk" in stats["per_platform"]

    @pytest.mark.asyncio
    async def test_export_event_buffers(self):
        configs = [_make_splunk_config(batch_size=100)]
        integrator = SIEMIntegrator(configs)

        # Mock the exporter so we don't make real HTTP calls
        mock_exporter = AsyncMock()
        mock_exporter.send = AsyncMock(
            return_value=ExportResult(success=True, platform=SIEMPlatform.SPLUNK, events_sent=1)
        )
        integrator._exporters[SIEMPlatform.SPLUNK] = mock_exporter

        event = _make_audit_event()
        await integrator.export_event(event)

        # Event should be buffered, not sent yet (batch_size=100)
        assert integrator.stats["events_received"] == 1
        assert len(integrator._buffers[SIEMPlatform.SPLUNK]) == 1
        mock_exporter.send.assert_not_called()

    @pytest.mark.asyncio
    async def test_export_event_triggers_flush_on_batch_full(self):
        configs = [_make_splunk_config(batch_size=2)]
        integrator = SIEMIntegrator(configs)

        mock_exporter = AsyncMock()
        mock_exporter.send = AsyncMock(
            return_value=ExportResult(
                success=True, platform=SIEMPlatform.SPLUNK, events_sent=2, latency_ms=5.0
            )
        )
        mock_exporter.close = AsyncMock()
        integrator._exporters[SIEMPlatform.SPLUNK] = mock_exporter

        # Send 2 events to fill the batch
        await integrator.export_event(_make_audit_event(action="action_1"))
        await integrator.export_event(_make_audit_event(action="action_2"))

        # Should have flushed
        mock_exporter.send.assert_called_once()
        assert integrator.stats["events_exported"] == 2
        assert integrator.stats["exports_successful"] == 1

    @pytest.mark.asyncio
    async def test_export_events_batch(self):
        configs = [_make_splunk_config(batch_size=100)]
        integrator = SIEMIntegrator(configs)

        mock_exporter = AsyncMock()
        mock_exporter.send = AsyncMock(
            return_value=ExportResult(
                success=True, platform=SIEMPlatform.SPLUNK, events_sent=5, latency_ms=10.0
            )
        )
        mock_exporter.close = AsyncMock()
        integrator._exporters[SIEMPlatform.SPLUNK] = mock_exporter

        events = [_make_audit_event(action=f"action_{i}") for i in range(5)]
        results = await integrator.export_events(events)

        assert len(results) == 1
        assert results[0].success is True
        assert integrator.stats["events_received"] == 5

    @pytest.mark.asyncio
    async def test_flush_all(self):
        configs = [_make_splunk_config(batch_size=100), _make_elk_config(batch_size=100)]
        integrator = SIEMIntegrator(configs)

        for platform in integrator.platforms:
            mock_exporter = AsyncMock()
            mock_exporter.send = AsyncMock(
                return_value=ExportResult(
                    success=True, platform=platform, events_sent=3, latency_ms=5.0
                )
            )
            mock_exporter.close = AsyncMock()
            integrator._exporters[platform] = mock_exporter

        # Buffer some events
        for i in range(3):
            await integrator.export_event(_make_audit_event(action=f"action_{i}"))

        results = await integrator.flush_all()
        assert len(results) == 2  # One per platform

    @pytest.mark.asyncio
    async def test_flush_all_empty_buffers(self):
        configs = [_make_splunk_config()]
        integrator = SIEMIntegrator(configs)
        results = await integrator.flush_all()
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_start_and_stop(self):
        configs = [_make_splunk_config(flush_interval_s=0.1)]
        integrator = SIEMIntegrator(configs)

        mock_exporter = AsyncMock()
        mock_exporter.send = AsyncMock(
            return_value=ExportResult(success=True, platform=SIEMPlatform.SPLUNK, events_sent=0)
        )
        mock_exporter.close = AsyncMock()
        integrator._exporters[SIEMPlatform.SPLUNK] = mock_exporter

        await integrator.start()
        assert integrator._running is True
        assert integrator._flush_task is not None

        await integrator.stop()
        assert integrator._running is False
        mock_exporter.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_start_idempotent(self):
        configs = [_make_splunk_config(flush_interval_s=0.1)]
        integrator = SIEMIntegrator(configs)

        mock_exporter = AsyncMock()
        mock_exporter.close = AsyncMock()
        integrator._exporters[SIEMPlatform.SPLUNK] = mock_exporter

        await integrator.start()
        task1 = integrator._flush_task
        await integrator.start()  # Should not create a second task
        task2 = integrator._flush_task
        assert task1 is task2

        await integrator.stop()

    @pytest.mark.asyncio
    async def test_export_to_multiple_platforms(self):
        configs = [
            _make_splunk_config(batch_size=100),
            _make_elk_config(batch_size=100),
            _make_datadog_config(batch_size=100),
        ]
        integrator = SIEMIntegrator(configs)

        for platform in integrator.platforms:
            mock_exporter = AsyncMock()
            mock_exporter.send = AsyncMock(
                return_value=ExportResult(
                    success=True, platform=platform, events_sent=1, latency_ms=3.0
                )
            )
            mock_exporter.close = AsyncMock()
            integrator._exporters[platform] = mock_exporter

        await integrator.export_event(_make_audit_event())
        results = await integrator.flush_all()

        assert len(results) == 3
        assert all(r.success for r in results)
        # Each platform should get the event
        for platform in integrator.platforms:
            assert integrator.stats["per_platform"][platform.value]["events_exported"] == 1

    @pytest.mark.asyncio
    async def test_partial_platform_failure(self):
        configs = [_make_splunk_config(batch_size=100), _make_elk_config(batch_size=100)]
        integrator = SIEMIntegrator(configs)

        # Splunk succeeds, ELK fails
        splunk_exporter = AsyncMock()
        splunk_exporter.send = AsyncMock(
            return_value=ExportResult(
                success=True, platform=SIEMPlatform.SPLUNK, events_sent=1, latency_ms=5.0
            )
        )
        splunk_exporter.close = AsyncMock()

        elk_exporter = AsyncMock()
        elk_exporter.send = AsyncMock(
            return_value=ExportResult(
                success=False,
                platform=SIEMPlatform.ELASTICSEARCH,
                events_failed=1,
                error="Connection refused",
                latency_ms=100.0,
                retries=3,
            )
        )
        elk_exporter.close = AsyncMock()

        integrator._exporters[SIEMPlatform.SPLUNK] = splunk_exporter
        integrator._exporters[SIEMPlatform.ELASTICSEARCH] = elk_exporter

        await integrator.export_event(_make_audit_event())
        results = await integrator.flush_all()

        assert len(results) == 2
        assert integrator.stats["events_exported"] == 1
        assert integrator.stats["events_failed"] == 1
        assert integrator.stats["exports_successful"] == 1
        assert integrator.stats["exports_failed"] == 1


# --- Statistics Tests ---


class TestSIEMStatistics:
    """Tests for statistics tracking."""

    @pytest.mark.asyncio
    async def test_stats_update_on_success(self):
        configs = [_make_splunk_config(batch_size=100)]
        integrator = SIEMIntegrator(configs)

        mock_exporter = AsyncMock()
        mock_exporter.send = AsyncMock(
            return_value=ExportResult(
                success=True, platform=SIEMPlatform.SPLUNK, events_sent=5, latency_ms=25.0
            )
        )
        mock_exporter.close = AsyncMock()
        integrator._exporters[SIEMPlatform.SPLUNK] = mock_exporter

        events = [_make_audit_event(action=f"action_{i}") for i in range(5)]
        await integrator.export_events(events)

        stats = integrator.get_stats()
        assert stats["events_received"] == 5
        assert stats["events_exported"] == 5
        assert stats["exports_total"] == 1
        assert stats["exports_successful"] == 1
        assert stats["avg_latency_ms"] == 25.0

    @pytest.mark.asyncio
    async def test_stats_update_on_failure(self):
        configs = [_make_splunk_config(batch_size=100)]
        integrator = SIEMIntegrator(configs)

        mock_exporter = AsyncMock()
        mock_exporter.send = AsyncMock(
            return_value=ExportResult(
                success=False,
                platform=SIEMPlatform.SPLUNK,
                events_failed=3,
                error="Timeout",
                latency_ms=10000.0,
                retries=3,
            )
        )
        mock_exporter.close = AsyncMock()
        integrator._exporters[SIEMPlatform.SPLUNK] = mock_exporter

        events = [_make_audit_event(action=f"action_{i}") for i in range(3)]
        await integrator.export_events(events)

        stats = integrator.get_stats()
        assert stats["events_failed"] == 3
        assert stats["exports_failed"] == 1
        assert stats["total_retries"] == 3

    @pytest.mark.asyncio
    async def test_per_platform_stats(self):
        configs = [_make_splunk_config(batch_size=100), _make_elk_config(batch_size=100)]
        integrator = SIEMIntegrator(configs)

        for platform in integrator.platforms:
            mock_exporter = AsyncMock()
            mock_exporter.send = AsyncMock(
                return_value=ExportResult(
                    success=True, platform=platform, events_sent=2, latency_ms=5.0
                )
            )
            mock_exporter.close = AsyncMock()
            integrator._exporters[platform] = mock_exporter

        events = [_make_audit_event(action=f"action_{i}") for i in range(2)]
        await integrator.export_events(events)

        stats = integrator.get_stats()
        assert stats["per_platform"]["splunk"]["events_exported"] == 2
        assert stats["per_platform"]["elasticsearch"]["events_exported"] == 2

    @pytest.mark.asyncio
    async def test_running_average_latency(self):
        configs = [_make_splunk_config(batch_size=1)]
        integrator = SIEMIntegrator(configs)

        latencies = [10.0, 20.0, 30.0]
        call_count = 0

        async def mock_send(events):
            nonlocal call_count
            latency = latencies[call_count] if call_count < len(latencies) else 0
            call_count += 1
            return ExportResult(
                success=True,
                platform=SIEMPlatform.SPLUNK,
                events_sent=len(events),
                latency_ms=latency,
            )

        mock_exporter = AsyncMock()
        mock_exporter.send = mock_send
        mock_exporter.close = AsyncMock()
        integrator._exporters[SIEMPlatform.SPLUNK] = mock_exporter

        for i in range(3):
            await integrator.export_event(_make_audit_event(action=f"action_{i}"))

        stats = integrator.get_stats()
        # Running average of 10, 20, 30 = 20.0
        assert abs(stats["avg_latency_ms"] - 20.0) < 0.1


# --- Helper Function Tests ---


class TestHelperFunctions:
    """Tests for utility functions."""

    def test_severity_to_datadog_status(self):
        assert _severity_to_datadog_status("info") == "info"
        assert _severity_to_datadog_status("warning") == "warn"
        assert _severity_to_datadog_status("error") == "error"
        assert _severity_to_datadog_status("critical") == "critical"
        assert _severity_to_datadog_status("unknown") == "info"

    def test_iso_to_epoch(self):
        epoch = _iso_to_epoch("2026-01-01T00:00:00Z")
        # Should be close to 1767225600 (depends on timezone)
        assert epoch > 0
        assert isinstance(epoch, float)

    def test_iso_to_epoch_no_z(self):
        epoch = _iso_to_epoch("2026-01-01T00:00:00")
        assert epoch > 0


# --- ExportResult Tests ---


class TestExportResult:
    """Tests for ExportResult model."""

    def test_success_result(self):
        result = ExportResult(
            success=True,
            platform=SIEMPlatform.SPLUNK,
            events_sent=10,
            latency_ms=50.0,
        )
        assert result.success is True
        assert result.events_sent == 10
        assert result.events_failed == 0
        assert result.error is None

    def test_failure_result(self):
        result = ExportResult(
            success=False,
            platform=SIEMPlatform.ELASTICSEARCH,
            events_failed=5,
            error="Connection timeout",
            retries=3,
            latency_ms=30000.0,
        )
        assert result.success is False
        assert result.events_failed == 5
        assert result.events_sent == 0
        assert result.error == "Connection timeout"
        assert result.retries == 3


# --- Exporter Close Tests ---


class TestExporterClose:
    """Tests for exporter resource cleanup."""

    @pytest.mark.asyncio
    async def test_close_client(self):
        config = _make_splunk_config()
        exporter = SplunkExporter(config)

        mock_client = AsyncMock()
        mock_client.is_closed = False
        mock_client.aclose = AsyncMock()
        exporter._client = mock_client

        await exporter.close()
        mock_client.aclose.assert_called_once()
        assert exporter._client is None

    @pytest.mark.asyncio
    async def test_close_already_closed(self):
        config = _make_splunk_config()
        exporter = SplunkExporter(config)

        mock_client = AsyncMock()
        mock_client.is_closed = True
        exporter._client = mock_client

        await exporter.close()
        # Should not try to close again
        mock_client.aclose.assert_not_called()

    @pytest.mark.asyncio
    async def test_close_no_client(self):
        config = _make_splunk_config()
        exporter = SplunkExporter(config)
        await exporter.close()  # No error when client is None


# --- Performance Tests ---


class TestSIEMPerformance:
    """Performance benchmarks for SIEM integration."""

    def test_event_conversion_performance(self):
        """Event conversion should be fast."""
        events = [_make_audit_event(action=f"action_{i}") for i in range(1000)]

        start = time.perf_counter()
        for event in events:
            SIEMEvent.from_audit_event(event)
        elapsed_ms = (time.perf_counter() - start) * 1000

        # 1000 conversions should take <100ms
        assert elapsed_ms < 100, f"1000 conversions took {elapsed_ms:.1f}ms"

    def test_format_events_performance(self):
        """Formatting events should be fast."""
        events = [
            SIEMEvent.from_audit_event(_make_audit_event(action=f"action_{i}")) for i in range(1000)
        ]

        for exporter_cls, config_fn in [
            (SplunkExporter, _make_splunk_config),
            (ElasticsearchExporter, _make_elk_config),
            (DatadogExporter, _make_datadog_config),
        ]:
            exporter = exporter_cls(config_fn())
            start = time.perf_counter()
            exporter.format_events(events)
            elapsed_ms = (time.perf_counter() - start) * 1000

            # 1000 events formatting should take <200ms
            assert elapsed_ms < 200, f"{exporter_cls.__name__}: 1000 events took {elapsed_ms:.1f}ms"


# --- Edge Cases ---


class TestEdgeCases:
    """Edge case tests."""

    def test_siem_event_empty_metadata(self):
        event = _make_audit_event(metadata={})
        siem_event = SIEMEvent.from_audit_event(event)
        assert siem_event.metadata == {}

    def test_siem_event_large_metadata(self):
        large_meta = {f"key_{i}": f"value_{i}" * 100 for i in range(100)}
        event = _make_audit_event(metadata=large_meta)
        siem_event = SIEMEvent.from_audit_event(event)
        assert len(siem_event.metadata) == 100

    @pytest.mark.asyncio
    async def test_integrator_no_exporters_export(self):
        integrator = SIEMIntegrator()
        await integrator.export_event(_make_audit_event())
        assert integrator.stats["events_received"] == 1
        # No exporters → no buffer entries

    @pytest.mark.asyncio
    async def test_integrator_start_stop_no_exporters(self):
        integrator = SIEMIntegrator()
        await integrator.start()
        assert integrator._flush_task is None  # No task created without exporters
        await integrator.stop()

    def test_config_all_platforms(self):
        """Ensure all three platforms can be configured."""
        configs = [
            _make_splunk_config(),
            _make_elk_config(),
            _make_datadog_config(),
        ]
        integrator = SIEMIntegrator(configs)
        assert len(integrator.platforms) == 3
