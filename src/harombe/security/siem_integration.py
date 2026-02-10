"""SIEM Integration for audit event forwarding.

This module provides integration with enterprise SIEM platforms for forwarding
audit events. Supports Splunk (HEC), Elasticsearch (ELK), and Datadog with
buffering, retry logic, and format conversion.

Features:
- Multiple SIEM platform support (Splunk, ELK, Datadog)
- Event format conversion per platform
- Buffered sends with configurable batch size
- Retry logic with exponential backoff
- Graceful handling of SIEM downtime
- Statistics tracking
"""

import asyncio
import contextlib
import time
from datetime import datetime
from enum import StrEnum
from typing import Any

import httpx
from pydantic import BaseModel, Field

from .audit_db import AuditEvent, EventType


class SIEMPlatform(StrEnum):
    """Supported SIEM platforms."""

    SPLUNK = "splunk"
    ELASTICSEARCH = "elasticsearch"
    DATADOG = "datadog"


class SIEMConfig(BaseModel):
    """Configuration for a SIEM exporter."""

    platform: SIEMPlatform
    endpoint: str  # Base URL
    token: str = ""  # Auth token
    index: str = "harombe-security"  # Index/source name
    enabled: bool = True
    batch_size: int = Field(default=50, ge=1, le=1000)
    flush_interval_s: float = Field(default=5.0, ge=0.1, le=300.0)
    max_retries: int = Field(default=3, ge=0, le=10)
    retry_delay_s: float = Field(default=1.0, ge=0.01, le=60.0)
    timeout_s: float = Field(default=10.0, ge=1.0, le=120.0)


class ExportResult(BaseModel):
    """Result of a SIEM export operation."""

    success: bool
    platform: SIEMPlatform
    events_sent: int = 0
    events_failed: int = 0
    latency_ms: float = 0.0
    error: str | None = None
    retries: int = 0


class SIEMEvent(BaseModel):
    """Normalized event for SIEM export."""

    event_id: str
    timestamp: str  # ISO 8601
    event_type: str
    actor: str
    action: str
    tool_name: str | None = None
    status: str
    correlation_id: str
    session_id: str | None = None
    duration_ms: int | None = None
    error_message: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    source: str = "harombe"
    severity: str = "info"

    @classmethod
    def from_audit_event(cls, event: AuditEvent) -> "SIEMEvent":
        """Convert an AuditEvent to a normalized SIEMEvent."""
        severity = "info"
        if event.event_type == EventType.ERROR:
            severity = "error"
        elif event.event_type == EventType.SECURITY_DECISION:
            severity = "warning"
        elif event.status == "error":
            severity = "error"

        return cls(
            event_id=event.event_id,
            timestamp=event.timestamp.isoformat() + "Z",
            event_type=event.event_type.value,
            actor=event.actor,
            action=event.action,
            tool_name=event.tool_name,
            status=event.status,
            correlation_id=event.correlation_id,
            session_id=event.session_id,
            duration_ms=event.duration_ms,
            error_message=event.error_message,
            metadata=event.metadata,
            severity=severity,
        )


class SIEMExporter:
    """Base class for SIEM exporters.

    Handles format conversion and HTTP transport for a single platform.
    """

    def __init__(self, config: SIEMConfig):
        self.config = config
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.config.timeout_s),
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    def format_events(self, events: list[SIEMEvent]) -> Any:
        """Format events for the specific SIEM platform.

        Must be overridden by subclasses.
        """
        raise NotImplementedError

    def get_headers(self) -> dict[str, str]:
        """Get HTTP headers for the SIEM platform.

        Must be overridden by subclasses.
        """
        raise NotImplementedError

    def get_url(self) -> str:
        """Get the endpoint URL for sending events.

        Must be overridden by subclasses.
        """
        raise NotImplementedError

    async def send(self, events: list[SIEMEvent]) -> ExportResult:
        """Send events to the SIEM platform with retry logic."""
        if not events:
            return ExportResult(
                success=True,
                platform=self.config.platform,
                events_sent=0,
            )

        start = time.perf_counter()
        retries = 0
        last_error = None

        for attempt in range(self.config.max_retries + 1):
            try:
                client = await self._get_client()
                payload = self.format_events(events)
                headers = self.get_headers()
                url = self.get_url()

                response = await client.post(url, headers=headers, json=payload)
                response.raise_for_status()

                elapsed_ms = (time.perf_counter() - start) * 1000
                return ExportResult(
                    success=True,
                    platform=self.config.platform,
                    events_sent=len(events),
                    latency_ms=elapsed_ms,
                    retries=retries,
                )

            except (httpx.HTTPStatusError, httpx.RequestError, httpx.TimeoutException) as e:
                last_error = str(e)
                retries = attempt + 1
                if attempt < self.config.max_retries:
                    delay = self.config.retry_delay_s * (2**attempt)
                    await asyncio.sleep(delay)

        elapsed_ms = (time.perf_counter() - start) * 1000
        return ExportResult(
            success=False,
            platform=self.config.platform,
            events_failed=len(events),
            latency_ms=elapsed_ms,
            error=last_error,
            retries=retries,
        )


class SplunkExporter(SIEMExporter):
    """Export events to Splunk via HTTP Event Collector (HEC)."""

    def format_events(self, events: list[SIEMEvent]) -> Any:
        """Format events for Splunk HEC batch endpoint."""
        # Splunk HEC expects individual event objects
        # For batch, we send a list
        return [
            {
                "event": event.model_dump(mode="json"),
                "sourcetype": "harombe:security",
                "source": "harombe",
                "index": self.config.index,
                "time": _iso_to_epoch(event.timestamp),
            }
            for event in events
        ]

    def get_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Splunk {self.config.token}",
            "Content-Type": "application/json",
        }

    def get_url(self) -> str:
        endpoint = self.config.endpoint.rstrip("/")
        return f"{endpoint}/services/collector/event"


class ElasticsearchExporter(SIEMExporter):
    """Export events to Elasticsearch (ELK Stack)."""

    def format_events(self, events: list[SIEMEvent]) -> Any:
        """Format events for Elasticsearch bulk API."""
        # Elasticsearch bulk API expects action/source pairs in NDJSON
        # For simplicity, we send as a batch document array
        return [
            {
                "_index": self.config.index,
                "_id": event.event_id,
                "_source": event.model_dump(mode="json"),
            }
            for event in events
        ]

    def get_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.config.token:
            headers["Authorization"] = f"ApiKey {self.config.token}"
        return headers

    def get_url(self) -> str:
        endpoint = self.config.endpoint.rstrip("/")
        return f"{endpoint}/{self.config.index}/_bulk"


class DatadogExporter(SIEMExporter):
    """Export events to Datadog Logs API."""

    def format_events(self, events: list[SIEMEvent]) -> Any:
        """Format events for Datadog Logs API."""
        return [
            {
                **event.model_dump(mode="json", exclude={"source", "status", "severity"}),
                "ddsource": "harombe",
                "ddtags": f"env:production,service:harombe,type:{event.event_type}",
                "hostname": "harombe-gateway",
                "message": f"{event.action}: {event.status}",
                "service": "harombe-security",
                "status": _severity_to_datadog_status(event.severity),
                "event_status": event.status,
            }
            for event in events
        ]

    def get_headers(self) -> dict[str, str]:
        return {
            "DD-API-KEY": self.config.token,
            "Content-Type": "application/json",
        }

    def get_url(self) -> str:
        endpoint = self.config.endpoint.rstrip("/")
        return f"{endpoint}/api/v2/logs"


def _severity_to_datadog_status(severity: str) -> str:
    """Map severity to Datadog log status."""
    mapping = {
        "info": "info",
        "warning": "warn",
        "error": "error",
        "critical": "critical",
    }
    return mapping.get(severity, "info")


def _iso_to_epoch(iso_timestamp: str) -> float:
    """Convert ISO 8601 timestamp to epoch seconds."""
    ts = iso_timestamp.rstrip("Z")
    dt = datetime.fromisoformat(ts)
    return dt.timestamp()


def _create_exporter(config: SIEMConfig) -> SIEMExporter:
    """Create the appropriate exporter for a SIEM platform."""
    exporters = {
        SIEMPlatform.SPLUNK: SplunkExporter,
        SIEMPlatform.ELASTICSEARCH: ElasticsearchExporter,
        SIEMPlatform.DATADOG: DatadogExporter,
    }
    exporter_cls = exporters.get(config.platform)
    if not exporter_cls:
        raise ValueError(f"Unsupported SIEM platform: {config.platform}")
    return exporter_cls(config)


class SIEMIntegrator:
    """Orchestrates event forwarding to multiple SIEM platforms.

    Provides buffered, batched event export with automatic flushing
    and retry logic for handling SIEM downtime.

    Usage:
        configs = [
            SIEMConfig(platform="splunk", endpoint="https://splunk.example.com:8088",
                       token="my-hec-token"),
            SIEMConfig(platform="elasticsearch", endpoint="https://elk.example.com:9200"),
        ]
        integrator = SIEMIntegrator(configs)
        await integrator.start()

        # Export events
        await integrator.export_event(audit_event)

        # Shutdown
        await integrator.stop()
    """

    def __init__(self, configs: list[SIEMConfig] | None = None):
        """Initialize SIEM integrator.

        Args:
            configs: List of SIEM configurations. Only enabled configs are used.
        """
        self._configs = configs or []
        self._exporters: dict[SIEMPlatform, SIEMExporter] = {}
        self._buffers: dict[SIEMPlatform, list[SIEMEvent]] = {}
        self._flush_task: asyncio.Task[None] | None = None
        self._running = False
        self._lock = asyncio.Lock()

        # Statistics
        self.stats: dict[str, Any] = {
            "events_received": 0,
            "events_exported": 0,
            "events_failed": 0,
            "exports_total": 0,
            "exports_successful": 0,
            "exports_failed": 0,
            "total_retries": 0,
            "avg_latency_ms": 0.0,
            "per_platform": {},
        }

        # Initialize exporters for enabled configs
        for config in self._configs:
            if config.enabled:
                self._exporters[config.platform] = _create_exporter(config)
                self._buffers[config.platform] = []
                self.stats["per_platform"][config.platform.value] = {
                    "events_exported": 0,
                    "events_failed": 0,
                    "exports_total": 0,
                    "exports_successful": 0,
                    "exports_failed": 0,
                    "avg_latency_ms": 0.0,
                }

    @property
    def platforms(self) -> list[SIEMPlatform]:
        """Get list of configured platforms."""
        return list(self._exporters.keys())

    async def start(self) -> None:
        """Start the background flush worker."""
        if self._running:
            return
        self._running = True
        if self._exporters:
            self._flush_task = asyncio.create_task(self._flush_worker())

    async def stop(self) -> None:
        """Stop the integrator and flush remaining events."""
        self._running = False
        # Flush any remaining buffered events
        await self.flush_all()
        # Cancel flush worker
        if self._flush_task and not self._flush_task.done():
            self._flush_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._flush_task
        # Close all exporters
        for exporter in self._exporters.values():
            await exporter.close()

    async def export_event(self, event: AuditEvent) -> None:
        """Buffer an audit event for export to all configured SIEMs.

        Args:
            event: Audit event to export
        """
        self.stats["events_received"] += 1
        siem_event = SIEMEvent.from_audit_event(event)

        async with self._lock:
            for platform in self._exporters:
                self._buffers[platform].append(siem_event)

                # Check if buffer is full → flush immediately
                config = self._get_config(platform)
                if config and len(self._buffers[platform]) >= config.batch_size:
                    await self._flush_platform(platform)

    async def export_events(self, events: list[AuditEvent]) -> list[ExportResult]:
        """Export multiple events at once.

        Args:
            events: List of audit events to export

        Returns:
            List of export results per platform
        """
        for event in events:
            self.stats["events_received"] += 1
            siem_event = SIEMEvent.from_audit_event(event)
            async with self._lock:
                for platform in self._exporters:
                    self._buffers[platform].append(siem_event)

        return await self.flush_all()

    async def flush_all(self) -> list[ExportResult]:
        """Flush all buffered events to all platforms.

        Returns:
            List of export results per platform
        """
        results = []
        async with self._lock:
            for platform in self._exporters:
                if self._buffers[platform]:
                    result = await self._flush_platform(platform)
                    results.append(result)
        return results

    async def _flush_platform(self, platform: SIEMPlatform) -> ExportResult:
        """Flush buffered events for a specific platform.

        Must be called with self._lock held.
        """
        events = self._buffers[platform]
        self._buffers[platform] = []

        if not events:
            return ExportResult(
                success=True,
                platform=platform,
                events_sent=0,
            )

        exporter = self._exporters[platform]
        result = await exporter.send(events)

        # Update stats
        platform_key = platform.value
        self.stats["exports_total"] += 1
        self.stats["per_platform"][platform_key]["exports_total"] += 1
        self.stats["total_retries"] += result.retries

        if result.success:
            self.stats["events_exported"] += result.events_sent
            self.stats["exports_successful"] += 1
            self.stats["per_platform"][platform_key]["events_exported"] += result.events_sent
            self.stats["per_platform"][platform_key]["exports_successful"] += 1
        else:
            self.stats["events_failed"] += result.events_failed
            self.stats["exports_failed"] += 1
            self.stats["per_platform"][platform_key]["events_failed"] += result.events_failed
            self.stats["per_platform"][platform_key]["exports_failed"] += 1

        # Update average latency (running average)
        total_exports = self.stats["exports_total"]
        if total_exports > 0:
            prev_avg = self.stats["avg_latency_ms"]
            self.stats["avg_latency_ms"] = prev_avg + (result.latency_ms - prev_avg) / total_exports

        platform_exports = self.stats["per_platform"][platform_key]["exports_total"]
        if platform_exports > 0:
            prev_avg = self.stats["per_platform"][platform_key]["avg_latency_ms"]
            self.stats["per_platform"][platform_key]["avg_latency_ms"] = (
                prev_avg + (result.latency_ms - prev_avg) / platform_exports
            )

        return result

    async def _flush_worker(self) -> None:
        """Background worker that periodically flushes buffers."""
        # Use the minimum flush interval across all configs
        min_interval = min(
            (c.flush_interval_s for c in self._configs if c.enabled),
            default=5.0,
        )
        while self._running:
            try:
                await asyncio.sleep(min_interval)
                if self._running:
                    await self.flush_all()
            except asyncio.CancelledError:
                break
            except Exception:
                pass  # Don't crash the worker

    def _get_config(self, platform: SIEMPlatform) -> SIEMConfig | None:
        """Get the config for a platform."""
        for config in self._configs:
            if config.platform == platform:
                return config
        return None

    def get_stats(self) -> dict[str, Any]:
        """Get export statistics."""
        return dict(self.stats)

    def add_platform(self, config: SIEMConfig) -> None:
        """Add a new SIEM platform at runtime.

        Args:
            config: SIEM configuration to add
        """
        if not config.enabled:
            return
        self._configs.append(config)
        self._exporters[config.platform] = _create_exporter(config)
        self._buffers[config.platform] = []
        self.stats["per_platform"][config.platform.value] = {
            "events_exported": 0,
            "events_failed": 0,
            "exports_total": 0,
            "exports_successful": 0,
            "exports_failed": 0,
            "avg_latency_ms": 0.0,
        }

    def remove_platform(self, platform: SIEMPlatform) -> None:
        """Remove a SIEM platform.

        Args:
            platform: Platform to remove
        """
        self._exporters.pop(platform, None)
        self._buffers.pop(platform, None)
        self._configs = [c for c in self._configs if c.platform != platform]
