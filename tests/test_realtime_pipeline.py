#!/usr/bin/env python3
"""Tests for realtime LSM pipeline behavior."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lha_realtime.analyzer import matches_file_identifier
from lha_realtime.config import Settings
from lha_realtime.pipeline import RealtimePipeline
from lha_realtime.state import StateStore


class FileIdentifierMatcherTest(unittest.TestCase):
    def test_exact_path_only_matches_same_path(self) -> None:
        self.assertTrue(matches_file_identifier("/tmp/a.txt", "/tmp/a.txt"))
        self.assertFalse(matches_file_identifier("/tmp/b.txt", "/tmp/a.txt"))

    def test_single_star_does_not_cross_path_segments(self) -> None:
        self.assertTrue(matches_file_identifier("/workspace/a.txt", "/workspace/*"))
        self.assertFalse(matches_file_identifier("/workspace/a/b.txt", "/workspace/*"))

    def test_double_star_crosses_path_segments(self) -> None:
        self.assertTrue(matches_file_identifier("/workspace/a.py", "/workspace/**/*.py"))
        self.assertTrue(matches_file_identifier("/workspace/a/b.py", "/workspace/**/*.py"))

    def test_file_identifier_star_is_path_glob(self) -> None:
        self.assertTrue(matches_file_identifier("/tmp/anything", "/tmp/*"))
        self.assertFalse(matches_file_identifier("/tmp/nested/anything", "/tmp/*"))

    def test_regex_uses_fullmatch(self) -> None:
        pattern = r"^/tmp/[a-zA-Z0-9]+\.txt$"
        self.assertTrue(matches_file_identifier("/tmp/abc123.txt", pattern))
        self.assertFalse(matches_file_identifier("/tmp/a/b.txt", pattern))
        self.assertFalse(matches_file_identifier("/tmp/abc123.txt.bak", pattern))

    def test_invalid_regex_does_not_allow(self) -> None:
        self.assertFalse(matches_file_identifier("/tmp/a.txt", r"(/tmp/[a-z]+\.txt"))


class RealtimePipelineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.settings = Settings(
            input_dir=self.root / "input",
            log_dir=self.root / "logs",
            state_dir=self.root / "state",
            db_path=self.root / "state" / "realtime.db",
            max_attempts=2,
        )
        self.kernel_syscalls = self.root / "kernel_syscall_seq.jsonl"
        self.kernel_lsm = self.root / "kernel_lsm_hook_result.jsonl"
        self.kernel_syscalls.write_text("", encoding="utf-8")
        self.kernel_lsm.write_text("", encoding="utf-8")
        self.store = StateStore(settings=self.settings)
        self.pipeline = RealtimePipeline(store=self.store, settings=self.settings, push_reports=False)

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def round_end(self, round_id: str, score: float = 1.0, bad_ir: bool = False, is_mock: bool = False, ir: bool = True) -> dict:
        payload = {
            "push_type": "round_end",
            "round_id": round_id,
            "overall_score": score,
            "time_start": "2026-06-16 10:00:00+0800",
            "time_end": "2026-06-16 10:00:01+0800",
            "action_json": "[]",
            "is_mock": is_mock,
        }
        if bad_ir:
            payload["ir_json"] = "{"
        elif ir:
            payload["ir_json"] = json.dumps({"level2": {"policies": []}})
        return payload

    def round_start(self, round_id: str, is_mock: bool = False) -> dict:
        return {
            "push_type": "round_start",
            "round_id": round_id,
            "time_start": "2026-06-16 10:00:00+0800",
            "session_key": "agent:main:main",
            "is_mock": is_mock,
        }

    def round_ir_ready(self, round_id: str, ir: dict | None = None, is_mock: bool = False) -> dict:
        return {
            "push_type": "round_ir_ready",
            "round_id": round_id,
            "ir_json": json.dumps(ir if ir is not None else {"level2": {"policies": []}}),
            "is_mock": is_mock,
        }

    def round_kernel(self, round_id: str, is_mock: bool = False) -> dict:
        return {
            "push_type": "round_kernel",
            "round_id": round_id,
            "kernel_syscall_seq": str(self.kernel_syscalls),
            "kernel_lsm_hook_result": str(self.kernel_lsm),
            "kernel_resource_facts": json.dumps({"resource_facts": []}),
            "is_mock": is_mock,
        }

    def write_lsm_hooks(self, *paths: str) -> None:
        rows = []
        for index, path in enumerate(paths, start=1):
            rows.append(
                {
                    "event_id": index,
                    "hook_name": "file_open",
                    "result": "allow",
                    "return_value": 0,
                    "pid": 1000 + index,
                    "tid": 1000 + index,
                    "timestamp_mono_ns": index,
                    "path": path,
                    "fd": None,
                    "category": "file",
                    "resource_role": "normal_resource",
                    "tool_call_id": f"call-{index}",
                    "tool_name": "cmd_executor__exec_command",
                    "related_event_id": None,
                }
            )
        self.kernel_lsm.write_text(
            "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n",
            encoding="utf-8",
        )

    def drain_ingest(self) -> None:
        while self.pipeline.ingest_once(limit=100):
            pass

    def drain_analysis(self) -> None:
        while self.pipeline.analyze_once():
            pass

    def test_round_is_analyzed_after_all_messages_arrive(self) -> None:
        # 四类消息乱序到达，全部就位后才分析。
        self.store.enqueue_message(self.round_kernel("r1"))
        self.store.enqueue_message(self.round_end("r1"))
        self.store.enqueue_message(self.round_ir_ready("r1"))
        self.store.enqueue_message(self.round_start("r1"))

        self.drain_ingest()
        self.drain_analysis()

        round_dir = self.settings.input_dir / "r1"
        self.assertTrue((round_dir / "round_start.json").is_file())
        self.assertTrue((round_dir / "round_end.json").is_file())
        self.assertTrue((round_dir / "round_kernel.json").is_file())
        self.assertTrue((round_dir / "analysis_report.md").is_file())
        self.assertEqual(self.store.get_round("r1")["status"], "done")
        report = (round_dir / "analysis_report.md").read_text(encoding="utf-8")
        self.assertIn("报告生成时间", report)

    def test_analysis_waits_until_round_start_arrives(self) -> None:
        # 缺少 round_start 时，即使其余三类消息齐备也不能触发分析。
        self.store.enqueue_message(self.round_end("wait-start"))
        self.store.enqueue_message(self.round_kernel("wait-start"))
        self.store.enqueue_message(self.round_ir_ready("wait-start"))
        self.drain_ingest()

        round_dir = self.settings.input_dir / "wait-start"
        self.assertEqual(self.store.get_round("wait-start")["status"], "receiving")
        self.assertFalse(self.pipeline.analyze_once())
        self.assertFalse((round_dir / "analysis_report.md").exists())

        self.store.enqueue_message(self.round_start("wait-start"))
        self.drain_ingest()
        self.drain_analysis()
        self.assertEqual(self.store.get_round("wait-start")["status"], "done")
        self.assertTrue((round_dir / "analysis_report.md").is_file())

    def test_second_round_end_updates_metadata_without_new_generation(self) -> None:
        self.store.enqueue_message(self.round_start("dup"))
        self.store.enqueue_message(self.round_end("dup", score=1.0))
        self.store.enqueue_message(self.round_kernel("dup"))
        self.drain_ingest()
        self.drain_analysis()
        round_dir = self.settings.input_dir / "dup"
        self.assertTrue((round_dir / "analysis_report.md").is_file())
        self.assertEqual(self.store.get_round("dup")["status"], "done")

        # A lone late round_end only refreshes metadata; it must NOT churn the generation
        # nor wipe the finished report (that was the production churn bug).
        self.store.enqueue_message(self.round_end("dup", score=2.0))
        self.drain_ingest()
        self.assertEqual(self.store.get_round("dup")["generation"], 1)
        self.assertEqual(self.store.get_round("dup")["status"], "done")
        self.assertTrue((round_dir / "analysis_report.md").is_file())
        round_end = json.loads((round_dir / "round_end.json").read_text(encoding="utf-8"))
        self.assertEqual(round_end["overall_score"], 2.0)

    def test_replaying_one_required_message_reruns_using_persisted_inputs(self) -> None:
        # A completed round re-runs the full pipeline from its persisted inputs even when
        # only a single required message (here: kernel) is replayed.
        self.write_lsm_hooks("/etc/passwd")
        self.store.enqueue_message(self.round_start("r"))
        self.store.enqueue_message(self.round_end("r", ir=False))
        self.store.enqueue_message(self.round_kernel("r"))
        self.store.enqueue_message(self.round_ir_ready("r"))
        self.drain_ingest()
        self.drain_analysis()
        round_dir = self.settings.input_dir / "r"
        self.assertEqual(self.store.get_round("r")["status"], "done")
        self.assertEqual(self.store.get_round("r")["generation"], 1)

        # Replay ONLY the kernel message — the round must fully re-run (new generation,
        # fresh report) reusing the IR + inputs already on disk.
        self.store.enqueue_message(self.round_kernel("r"))
        self.drain_ingest()
        self.drain_analysis()
        self.assertEqual(self.store.get_round("r")["status"], "done")
        self.assertEqual(self.store.get_round("r")["generation"], 2)
        self.assertTrue((round_dir / "analysis_report.md").is_file())

    def test_replayed_round_reruns_full_pipeline_and_repushes(self) -> None:
        # Every replay of a round runs the complete analyze + push pipeline again.
        pipeline = RealtimePipeline(store=self.store, settings=self.settings, push_reports=True)

        def feed_full_round(round_id: str) -> None:
            self.store.enqueue_message(self.round_start(round_id))
            self.store.enqueue_message(self.round_end(round_id))
            self.store.enqueue_message(self.round_kernel(round_id))
            self.store.enqueue_message(self.round_ir_ready(round_id))

        def drain() -> None:
            while pipeline.ingest_once(limit=100):
                pass
            while pipeline.analyze_once():
                pass

        with patch("lha_realtime.analyzer.push_and_mark_report", return_value=True) as push:
            feed_full_round("replay")
            drain()
            self.assertEqual(self.store.get_round("replay")["status"], "done")
            first_pushes = push.call_count
            self.assertGreaterEqual(first_pushes, 1)

            feed_full_round("replay")
            drain()
            self.assertEqual(self.store.get_round("replay")["status"], "done")
            self.assertGreater(push.call_count, first_pushes)
            self.assertGreater(self.store.get_round("replay")["generation"], 1)

    def test_ir_ready_after_kernel_unblocks_analysis(self) -> None:
        # Reproduces the production bug: round_end arrives with empty ir, kernel arrives,
        # and the real IR only shows up later via round_ir_ready. Analysis must wait for IR
        # and then use the real allowlist.
        self.write_lsm_hooks("/etc/passwd", "/workspace/ok.py")
        self.store.enqueue_message(self.round_start("late-ir"))
        self.store.enqueue_message(self.round_end("late-ir", ir=False))
        self.store.enqueue_message(self.round_kernel("late-ir"))
        self.drain_ingest()

        round_dir = self.settings.input_dir / "late-ir"
        self.assertEqual(self.store.get_round("late-ir")["status"], "receiving")
        self.assertFalse(self.pipeline.analyze_once())
        self.assertFalse((round_dir / "analysis_report.md").exists())

        ir = {
            "policies": [
                {
                    "effect": "allow",
                    "objects": [
                        {"type": "file", "identifier": "/workspace/**/*.py", "actions": ["read"]},
                    ],
                }
            ]
        }
        self.store.enqueue_message(self.round_ir_ready("late-ir", ir=ir))
        self.drain_ingest()
        self.drain_analysis()

        self.assertEqual(self.store.get_round("late-ir")["status"], "done")
        violations_path = round_dir / "analysis_violations.jsonl"
        violations = [
            json.loads(line)
            for line in violations_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertEqual([violation["path"] for violation in violations], ["/etc/passwd"])

    def test_empty_ir_round_end_does_not_trigger_premature_analysis(self) -> None:
        self.store.enqueue_message(self.round_start("empty-ir"))
        self.store.enqueue_message(self.round_end("empty-ir", ir=False))
        self.store.enqueue_message(self.round_kernel("empty-ir"))
        self.drain_ingest()

        self.assertEqual(self.store.get_round("empty-ir")["status"], "receiving")
        self.assertFalse(self.pipeline.analyze_once())
        self.assertFalse((self.settings.input_dir / "empty-ir" / "analysis_report.md").exists())

    def test_burst_messages_are_queued_and_processed(self) -> None:
        for index in range(20):
            round_id = f"burst-{index}"
            self.store.enqueue_message(self.round_start(round_id))
            self.store.enqueue_message(self.round_end(round_id))
            self.store.enqueue_message(self.round_kernel(round_id))

        self.drain_ingest()
        self.drain_analysis()

        for index in range(20):
            round_id = f"burst-{index}"
            self.assertEqual(self.store.get_round(round_id)["status"], "done")
            self.assertTrue((self.settings.input_dir / round_id / "analysis_report.md").is_file())

    def test_analysis_failure_retries_then_marks_failed(self) -> None:
        self.store.enqueue_message(self.round_start("bad"))
        self.store.enqueue_message(self.round_end("bad", bad_ir=True))
        self.store.enqueue_message(self.round_kernel("bad"))
        self.drain_ingest()

        self.assertTrue(self.pipeline.analyze_once())
        self.assertEqual(self.store.get_round("bad")["status"], "queued")
        self.assertTrue(self.pipeline.analyze_once())
        self.assertEqual(self.store.get_round("bad")["status"], "analysis_failed")

    def test_analysis_uses_new_file_identifier_matching(self) -> None:
        self.write_lsm_hooks(
            "/tmp/exact.txt",
            "/workspace/a.py",
            "/workspace/a/b.py",
            "/workspace/a/b.txt",
            "/tmp/abc123.txt",
            "/tmp/abc123.txt.bak",
        )
        ir = {
            "policies": [
                {
                    "subject": "shell_exec",
                    "effect": "allow",
                    "objects": [
                        {"type": "file", "identifier": "/tmp/exact.txt", "actions": ["read"]},
                        {"type": "file", "identifier": "/workspace/**/*.py", "actions": ["read"]},
                        {"type": "file", "identifier": r"^/tmp/[a-zA-Z0-9]+\.txt$", "actions": ["read"]},
                    ],
                }
            ]
        }
        round_end = self.round_end("new-match")
        round_end["ir_json"] = json.dumps(ir)
        self.store.enqueue_message(self.round_start("new-match"))
        self.store.enqueue_message(round_end)
        self.store.enqueue_message(self.round_kernel("new-match"))

        self.drain_ingest()
        self.drain_analysis()

        violations_path = self.settings.input_dir / "new-match" / "analysis_violations.jsonl"
        violations = [
            json.loads(line)
            for line in violations_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertEqual(
            [violation["path"] for violation in violations],
            ["/workspace/a/b.txt", "/tmp/abc123.txt.bak"],
        )

    def test_pending_inbox_survives_store_reopen(self) -> None:
        self.store.enqueue_message(self.round_end("recover"))
        self.store.close()

        self.store = StateStore(settings=self.settings)
        self.pipeline = RealtimePipeline(store=self.store, settings=self.settings, push_reports=False)
        self.drain_ingest()

        self.assertTrue((self.settings.input_dir / "recover" / "round_end.json").is_file())
        self.assertEqual(self.store.get_round("recover")["status"], "receiving")

    def test_mock_round_push_is_disabled_by_default(self) -> None:
        self.store.enqueue_message(self.round_start("mock-skip", is_mock=True))
        self.store.enqueue_message(self.round_end("mock-skip", is_mock=True))
        self.store.enqueue_message(self.round_kernel("mock-skip", is_mock=True))
        self.drain_ingest()

        with patch("lha_realtime.analyzer.push_and_mark_report", return_value=True) as push:
            self.drain_analysis()

        push.assert_not_called()

    def test_mock_round_push_can_be_enabled(self) -> None:
        settings = Settings(
            input_dir=self.root / "input-mock-push",
            log_dir=self.root / "logs-mock-push",
            state_dir=self.root / "state-mock-push",
            db_path=self.root / "state-mock-push" / "realtime.db",
            max_attempts=2,
            push_mock_reports=True,
        )
        store = StateStore(settings=settings)
        pipeline = RealtimePipeline(store=store, settings=settings, push_reports=True)
        try:
            store.enqueue_message(self.round_start("mock-push", is_mock=True))
            store.enqueue_message(self.round_end("mock-push", is_mock=True))
            store.enqueue_message(self.round_kernel("mock-push", is_mock=True))
            while pipeline.ingest_once(limit=100):
                pass

            with patch("lha_realtime.analyzer.push_and_mark_report", return_value=True) as push:
                while pipeline.analyze_once():
                    pass

            push.assert_called_once()
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
