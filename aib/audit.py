"""
AIB — Unified Audit Trail
Logs every cross-protocol interaction as an OpenTelemetry span.

MVP: in-memory store with OTLP-compatible structure.
Production: export to Jaeger, Grafana Tempo, or Datadog.
"""

import uuid
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional
from contextlib import contextmanager


@dataclass
class AuditEntry:
    trace_id: str
    passport_id: str
    source_protocol: str
    target_protocol: str
    action: str  # tool_call, task_send, message, discover, translate
    target_url: str
    status: str = "pending"  # pending, success, error, timeout, revoked
    timestamp: str = ""
    duration_ms: float = 0.0
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


class AuditTrail:
    """In-memory audit store. Each entry mimics an OpenTelemetry span."""

    def __init__(self, max_entries: int = 10000):
        self._entries: list[AuditEntry] = []
        self._max = max_entries

    @contextmanager
    def trace(
        self,
        passport_id: str,
        source_protocol: str,
        target_protocol: str,
        action: str,
        target_url: str,
        metadata: Optional[dict] = None,
    ):
        """
        Context manager that auto-records duration and status.

        Usage:
            with audit.trace("urn:aib:...", "mcp", "a2a", "task_send", "https://...") as entry:
                # do work
                entry.metadata["response_code"] = 200
            # entry.status is set to "success" on clean exit, "error" on exception
        """
        entry = AuditEntry(
            trace_id=str(uuid.uuid4()),
            passport_id=passport_id,
            source_protocol=source_protocol,
            target_protocol=target_protocol,
            action=action,
            target_url=target_url,
            timestamp=datetime.now(timezone.utc).isoformat(),
            metadata=metadata or {},
        )
        start = time.monotonic()
        try:
            yield entry
            entry.status = "success"
        except Exception as e:
            entry.status = "error"
            entry.metadata["error"] = str(e)
            raise
        finally:
            entry.duration_ms = round((time.monotonic() - start) * 1000, 2)
            self._append(entry)

    def log(
        self,
        passport_id: str,
        source_protocol: str,
        target_protocol: str,
        action: str,
        target_url: str,
        status: str = "success",
        duration_ms: float = 0.0,
        metadata: Optional[dict] = None,
    ) -> AuditEntry:
        """Direct log without context manager."""
        entry = AuditEntry(
            trace_id=str(uuid.uuid4()),
            passport_id=passport_id,
            source_protocol=source_protocol,
            target_protocol=target_protocol,
            action=action,
            target_url=target_url,
            status=status,
            timestamp=datetime.now(timezone.utc).isoformat(),
            duration_ms=duration_ms,
            metadata=metadata or {},
        )
        self._append(entry)
        return entry

    def query(
        self,
        passport_id: Optional[str] = None,
        protocol: Optional[str] = None,
        action: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> list[AuditEntry]:
        """Query audit entries with optional filters."""
        results = self._entries
        if passport_id:
            results = [e for e in results if e.passport_id == passport_id]
        if protocol:
            results = [e for e in results if protocol in (e.source_protocol, e.target_protocol)]
        if action:
            results = [e for e in results if e.action == action]
        if status:
            results = [e for e in results if e.status == status]
        return results[-limit:]

    def stats(self, passport_id: Optional[str] = None) -> dict:
        """Aggregate statistics."""
        entries = self.query(passport_id=passport_id, limit=self._max)
        if not entries:
            return {"total": 0}

        protocols = {}
        actions = {}
        statuses = {}
        total_duration = 0.0

        for e in entries:
            protocols[e.target_protocol] = protocols.get(e.target_protocol, 0) + 1
            actions[e.action] = actions.get(e.action, 0) + 1
            statuses[e.status] = statuses.get(e.status, 0) + 1
            total_duration += e.duration_ms

        return {
            "total": len(entries),
            "avg_duration_ms": round(total_duration / len(entries), 2),
            "by_protocol": protocols,
            "by_action": actions,
            "by_status": statuses,
        }

    def _append(self, entry: AuditEntry):
        self._entries.append(entry)
        if len(self._entries) > self._max:
            self._entries = self._entries[-self._max:]
