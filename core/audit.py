"""
Security Event Audit Logging.

PURPOSE:
Provides the append-only security event log required for operational deployment: every
verification, threat detection, authorization denial, and key-establishment run is recorded
with a UTC timestamp and can be exported for offline review.

STORAGE FORMAT:
JSON Lines (one JSON object per line). This format is append-only by construction, so a
crash mid-write cannot corrupt earlier records, and it streams without loading the whole
log into memory.

SECRET HYGIENE (IMPORTANT):
Secret key material is NEVER written to the log. Only these derived, non-invertible
quantities are recorded:
  - the key's 1-bit density (a single aggregate float),
  - a 16-hex-character prefix of the message digest,
  - the nonce (a public protocol value, safe to log and needed for replay forensics).
Callers must not place raw key bits, verifier tokens, or master secrets into the detail
payload; sanitize_detail() strips known-sensitive keys as a defence in depth.

SCIENTIFIC DISCLOSURES:
- The log is tamper-evident only to the extent the host filesystem is trusted. It is not
  cryptographically chained, so it does not defend against an attacker with write access.
- No artificial intelligence or machine learning is used.
"""

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.models import SecurityEvent


DEFAULT_LOG_DIR = ".qds_audit"
DEFAULT_LOG_FILE = "security_events.jsonl"

EVENT_TYPES = (
    "VERIFICATION",
    "THREAT_DETECTED",
    "THREAT_CLASSIFIED",
    "AUTH_DENIED",
    "AUTH_GRANTED",
    "REPLAY_BLOCKED",
    "KEY_DISTRIBUTION",
    "CALIBRATION",
    "ATTACK_SIMULATION",
)

# Detail keys that must never reach disk, matched case-insensitively as substrings.
SENSITIVE_KEY_FRAGMENTS = (
    "key_bits",
    "shared_key",
    "secret",
    "token",
    "password",
    "api_key",
    "credential",
    "master",
)


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string with second resolution."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sanitize_detail(detail: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Remove known-sensitive entries from an event detail payload.

    Args:
        detail: Arbitrary event payload, or None.

    Returns:
        A shallow-sanitized copy. Redacted entries are replaced with the marker
        "[REDACTED]" so that their presence remains visible in the audit trail.
    """
    if not detail:
        return {}

    clean: Dict[str, Any] = {}
    for key, value in detail.items():
        lowered = str(key).lower()
        if any(fragment in lowered for fragment in SENSITIVE_KEY_FRAGMENTS):
            clean[key] = "[REDACTED]"
        elif isinstance(value, dict):
            clean[key] = sanitize_detail(value)
        else:
            clean[key] = value
    return clean


def _json_safe(value: Any) -> Any:
    """Convert a value into something json.dumps can serialize."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return str(value)


class AuditLogger:
    """
    Append-only JSON Lines security event logger.

    Writes are serialized behind a lock so concurrent Streamlit reruns cannot interleave
    partial lines.
    """

    def __init__(
        self,
        log_dir: str = DEFAULT_LOG_DIR,
        log_file: str = DEFAULT_LOG_FILE,
        enabled: bool = True,
    ) -> None:
        """
        Initialize the audit logger.

        Args:
            log_dir: Directory the log file lives in (created on first write).
            log_file: Log file name.
            enabled: When False, all log calls become no-ops but still return the event.
        """
        self.log_dir = log_dir
        self.log_file = log_file
        self.enabled = enabled
        self._lock = threading.Lock()

    @property
    def path(self) -> str:
        """Full filesystem path of the log file."""
        return os.path.join(self.log_dir, self.log_file)

    def log_event(
        self,
        event_type: str,
        severity: str = "INFO",
        verdict: str = "",
        message_digest_prefix: str = "",
        detail: Optional[Dict[str, Any]] = None,
    ) -> SecurityEvent:
        """
        Append a security event to the log.

        Args:
            event_type: Category from EVENT_TYPES (free-form values are permitted but
                discouraged; unknown values are recorded as-is).
            severity: "INFO", "WARNING", or "CRITICAL".
            verdict: Verification verdict, if applicable.
            message_digest_prefix: Truncated digest identifying the message.
            detail: Structured payload; sanitized before writing.

        Returns:
            The SecurityEvent that was recorded (returned even when logging is disabled).
        """
        event = SecurityEvent(
            event_id=uuid.uuid4().hex[:16],
            timestamp=utc_now_iso(),
            event_type=event_type,
            severity=severity,
            verdict=verdict,
            message_digest_prefix=message_digest_prefix[:16],
            detail=sanitize_detail(detail),
        )

        if not self.enabled:
            return event

        record = {
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "event_type": event.event_type,
            "severity": event.severity,
            "verdict": event.verdict,
            "message_digest_prefix": event.message_digest_prefix,
            "detail": _json_safe(event.detail),
        }

        with self._lock:
            os.makedirs(self.log_dir, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record) + "\n")

        return event

    def read_events(self, limit: Optional[int] = None) -> List[SecurityEvent]:
        """
        Read events back from the log, newest last.

        Malformed lines are skipped rather than raising, so a partially written final
        line cannot make the whole log unreadable.

        Args:
            limit: Return only the most recent `limit` events. All events when None.

        Returns:
            List of SecurityEvent instances in file order.
        """
        if not os.path.exists(self.path):
            return []

        events: List[SecurityEvent] = []
        with open(self.path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    events.append(SecurityEvent(
                        event_id=record.get("event_id", ""),
                        timestamp=record.get("timestamp", ""),
                        event_type=record.get("event_type", "UNKNOWN"),
                        severity=record.get("severity", "INFO"),
                        verdict=record.get("verdict", ""),
                        message_digest_prefix=record.get("message_digest_prefix", ""),
                        detail=record.get("detail", {}),
                    ))
                except (json.JSONDecodeError, ValueError):
                    continue

        if limit is not None and limit >= 0:
            return events[-limit:]
        return events

    def export_json(self, limit: Optional[int] = None) -> str:
        """
        Export the log as a pretty-printed JSON array, suitable for a download button.

        Args:
            limit: Export only the most recent `limit` events.

        Returns:
            JSON string.
        """
        events = self.read_events(limit=limit)
        payload = [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp,
                "event_type": e.event_type,
                "severity": e.severity,
                "verdict": e.verdict,
                "message_digest_prefix": e.message_digest_prefix,
                "detail": e.detail,
            }
            for e in events
        ]
        return json.dumps(payload, indent=2)

    def summary(self) -> Dict[str, Any]:
        """
        Aggregate counts for the dashboard.

        Returns:
            Dict with total event count and per-type / per-severity breakdowns.
        """
        events = self.read_events()
        by_type: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}

        for event in events:
            by_type[event.event_type] = by_type.get(event.event_type, 0) + 1
            by_severity[event.severity] = by_severity.get(event.severity, 0) + 1

        return {
            "total_events": len(events),
            "by_type": by_type,
            "by_severity": by_severity,
            "log_path": self.path,
            "first_event": events[0].timestamp if events else None,
            "last_event": events[-1].timestamp if events else None,
        }

    def clear(self) -> None:
        """Delete the log file, if present."""
        with self._lock:
            if os.path.exists(self.path):
                os.remove(self.path)


# Process-wide default logger used by the application layer.
default_logger = AuditLogger()
