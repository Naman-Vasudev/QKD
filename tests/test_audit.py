"""
Unit Test Suite for Security Event Audit Logging.

Includes explicit secret-hygiene tests: the audit log is an exportable artifact, so key
material must never reach it.
"""

import json
import os
import shutil
import tempfile
import unittest

from core.audit import AuditLogger, sanitize_detail
from core.models import SecurityEvent


class TestSanitization(unittest.TestCase):

    def test_1_sensitive_keys_are_redacted(self) -> None:
        clean = sanitize_detail({
            "shared_key": [0, 1, 0, 1],
            "key_bits": [1, 1, 1],
            "verifier_token": "deadbeef",
            "master_secret": "hunter2",
            "api_key": "sk-123",
            "observed_error_rate": 0.5,
        })
        self.assertEqual(clean["shared_key"], "[REDACTED]")
        self.assertEqual(clean["key_bits"], "[REDACTED]")
        self.assertEqual(clean["verifier_token"], "[REDACTED]")
        self.assertEqual(clean["master_secret"], "[REDACTED]")
        self.assertEqual(clean["api_key"], "[REDACTED]")
        # Non-sensitive values must survive untouched.
        self.assertEqual(clean["observed_error_rate"], 0.5)

    def test_2_nested_dicts_are_sanitized(self) -> None:
        clean = sanitize_detail({"outer": {"secret_value": "x", "safe": 1}})
        self.assertEqual(clean["outer"]["secret_value"], "[REDACTED]")
        self.assertEqual(clean["outer"]["safe"], 1)

    def test_3_empty_detail(self) -> None:
        self.assertEqual(sanitize_detail(None), {})
        self.assertEqual(sanitize_detail({}), {})


class TestAuditLogger(unittest.TestCase):

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.logger = AuditLogger(log_dir=self.tmpdir)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_1_event_is_written_and_read_back(self) -> None:
        self.logger.log_event(
            event_type="VERIFICATION",
            severity="INFO",
            verdict="ACCEPT",
            message_digest_prefix="abcdef0123456789",
            detail={"num_errors": 0},
        )
        events = self.logger.read_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, "VERIFICATION")
        self.assertEqual(events[0].verdict, "ACCEPT")
        self.assertEqual(events[0].detail["num_errors"], 0)

    def test_2_log_is_append_only(self) -> None:
        for i in range(5):
            self.logger.log_event(event_type="VERIFICATION", detail={"i": i})
        events = self.logger.read_events()
        self.assertEqual(len(events), 5)
        self.assertEqual([e.detail["i"] for e in events], [0, 1, 2, 3, 4])

    def test_3_jsonl_format_one_object_per_line(self) -> None:
        for i in range(3):
            self.logger.log_event(event_type="VERIFICATION", detail={"i": i})
        with open(self.logger.path, encoding="utf-8") as handle:
            lines = [line for line in handle if line.strip()]
        self.assertEqual(len(lines), 3)
        for line in lines:
            json.loads(line)  # each line must parse independently

    def test_4_event_ids_are_unique(self) -> None:
        for _ in range(20):
            self.logger.log_event(event_type="VERIFICATION")
        ids = {e.event_id for e in self.logger.read_events()}
        self.assertEqual(len(ids), 20)

    def test_5_secrets_never_reach_disk(self) -> None:
        self.logger.log_event(
            event_type="VERIFICATION",
            detail={
                "shared_key": [1] * 256,
                "master_secret": "topsecret",
                "key_one_density": 0.5,
            },
        )
        raw = open(self.logger.path, encoding="utf-8").read()
        self.assertNotIn("topsecret", raw)
        self.assertIn("[REDACTED]", raw)
        # The safe aggregate must still be present for forensics.
        self.assertIn("key_one_density", raw)

    def test_6_digest_prefix_is_truncated(self) -> None:
        event = self.logger.log_event(
            event_type="VERIFICATION",
            message_digest_prefix="0123456789abcdef" * 4,
        )
        self.assertEqual(len(event.message_digest_prefix), 16)

    def test_7_limit_returns_most_recent(self) -> None:
        for i in range(10):
            self.logger.log_event(event_type="VERIFICATION", detail={"i": i})
        recent = self.logger.read_events(limit=3)
        self.assertEqual([e.detail["i"] for e in recent], [7, 8, 9])

    def test_8_malformed_lines_are_skipped(self) -> None:
        self.logger.log_event(event_type="VERIFICATION", detail={"i": 1})
        with open(self.logger.path, "a", encoding="utf-8") as handle:
            handle.write("{not valid json\n")
        self.logger.log_event(event_type="VERIFICATION", detail={"i": 2})
        events = self.logger.read_events()
        self.assertEqual(len(events), 2)

    def test_9_summary_aggregates(self) -> None:
        self.logger.log_event(event_type="VERIFICATION", severity="INFO")
        self.logger.log_event(event_type="THREAT_DETECTED", severity="CRITICAL")
        self.logger.log_event(event_type="THREAT_DETECTED", severity="CRITICAL")
        summary = self.logger.summary()
        self.assertEqual(summary["total_events"], 3)
        self.assertEqual(summary["by_type"]["THREAT_DETECTED"], 2)
        self.assertEqual(summary["by_severity"]["CRITICAL"], 2)
        self.assertIsNotNone(summary["first_event"])

    def test_10_export_json_is_valid(self) -> None:
        self.logger.log_event(event_type="VERIFICATION", verdict="ACCEPT")
        payload = json.loads(self.logger.export_json())
        self.assertIsInstance(payload, list)
        self.assertEqual(payload[0]["verdict"], "ACCEPT")

    def test_11_clear_removes_log(self) -> None:
        self.logger.log_event(event_type="VERIFICATION")
        self.assertTrue(os.path.exists(self.logger.path))
        self.logger.clear()
        self.assertFalse(os.path.exists(self.logger.path))
        self.assertEqual(self.logger.read_events(), [])

    def test_12_missing_log_reads_empty(self) -> None:
        fresh = AuditLogger(log_dir=os.path.join(self.tmpdir, "does_not_exist"))
        self.assertEqual(fresh.read_events(), [])
        self.assertEqual(fresh.summary()["total_events"], 0)

    def test_13_disabled_logger_writes_nothing(self) -> None:
        disabled = AuditLogger(log_dir=self.tmpdir, log_file="off.jsonl", enabled=False)
        event = disabled.log_event(event_type="VERIFICATION")
        self.assertIsInstance(event, SecurityEvent)
        self.assertFalse(os.path.exists(disabled.path))

    def test_14_invalid_severity_rejected(self) -> None:
        with self.assertRaises(ValueError):
            SecurityEvent(
                event_id="x", timestamp="t", event_type="VERIFICATION",
                severity="LOUD",
            )

    def test_15_non_serializable_values_are_coerced(self) -> None:
        class Opaque:
            def __str__(self) -> str:
                return "opaque-object"

        self.logger.log_event(event_type="VERIFICATION", detail={"obj": Opaque()})
        events = self.logger.read_events()
        self.assertEqual(events[0].detail["obj"], "opaque-object")


if __name__ == "__main__":
    unittest.main()
