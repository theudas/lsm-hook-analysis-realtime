#!/usr/bin/env python3
"""Tests for realtime LSM pipeline behavior."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from lha_realtime.config import Settings
from lha_realtime.pipeline import RealtimePipeline
from lha_realtime.state import StateStore


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

    def round_end(self, round_id: str, score: float = 1.0, bad_ir: bool = False) -> dict:
        return {
            "push_type": "round_end",
            "round_id": round_id,
            "overall_score": score,
            "time_start": "2026-06-16 10:00:00+0800",
            "time_end": "2026-06-16 10:00:01+0800",
            "action_json": "[]",
            "ir_json": "{" if bad_ir else json.dumps({"level2": {"policies": []}}),
        }

    def round_kernel(self, round_id: str) -> dict:
        return {
            "push_type": "round_kernel",
            "round_id": round_id,
            "kernel_syscall_seq": str(self.kernel_syscalls),
            "kernel_lsm_hook_result": str(self.kernel_lsm),
            "kernel_resource_facts": json.dumps({"resource_facts": []}),
        }

    def drain_ingest(self) -> None:
        while self.pipeline.ingest_once(limit=100):
            pass

    def drain_analysis(self) -> None:
        while self.pipeline.analyze_once():
            pass

    def test_round_is_analyzed_after_both_messages_arrive(self) -> None:
        self.store.enqueue_message(self.round_kernel("r1"))
        self.store.enqueue_message(self.round_end("r1"))

        self.drain_ingest()
        self.drain_analysis()

        round_dir = self.settings.input_dir / "r1"
        self.assertTrue((round_dir / "round_end.json").is_file())
        self.assertTrue((round_dir / "round_kernel.json").is_file())
        self.assertTrue((round_dir / "analysis_report.md").is_file())
        self.assertEqual(self.store.get_round("r1")["status"], "done")

    def test_duplicate_round_clears_old_outputs_and_reanalyzes(self) -> None:
        self.store.enqueue_message(self.round_end("dup", score=1.0))
        self.store.enqueue_message(self.round_kernel("dup"))
        self.drain_ingest()
        self.drain_analysis()
        self.assertTrue((self.settings.input_dir / "dup" / "analysis_report.md").is_file())

        self.store.enqueue_message(self.round_end("dup", score=2.0))
        self.drain_ingest()
        round_dir = self.settings.input_dir / "dup"
        self.assertFalse((round_dir / "analysis_report.md").exists())
        self.assertEqual(self.store.get_round("dup")["generation"], 2)

        self.store.enqueue_message(self.round_kernel("dup"))
        self.drain_ingest()
        self.drain_analysis()
        round_end = json.loads((round_dir / "round_end.json").read_text(encoding="utf-8"))
        self.assertEqual(round_end["overall_score"], 2.0)
        self.assertTrue((round_dir / "analysis_report.md").is_file())
        self.assertEqual(self.store.get_round("dup")["status"], "done")

    def test_burst_messages_are_queued_and_processed(self) -> None:
        for index in range(20):
            round_id = f"burst-{index}"
            self.store.enqueue_message(self.round_end(round_id))
            self.store.enqueue_message(self.round_kernel(round_id))

        self.drain_ingest()
        self.drain_analysis()

        for index in range(20):
            round_id = f"burst-{index}"
            self.assertEqual(self.store.get_round(round_id)["status"], "done")
            self.assertTrue((self.settings.input_dir / round_id / "analysis_report.md").is_file())

    def test_analysis_failure_retries_then_marks_failed(self) -> None:
        self.store.enqueue_message(self.round_end("bad", bad_ir=True))
        self.store.enqueue_message(self.round_kernel("bad"))
        self.drain_ingest()

        self.assertTrue(self.pipeline.analyze_once())
        self.assertEqual(self.store.get_round("bad")["status"], "queued")
        self.assertTrue(self.pipeline.analyze_once())
        self.assertEqual(self.store.get_round("bad")["status"], "analysis_failed")

    def test_pending_inbox_survives_store_reopen(self) -> None:
        self.store.enqueue_message(self.round_end("recover"))
        self.store.close()

        self.store = StateStore(settings=self.settings)
        self.pipeline = RealtimePipeline(store=self.store, settings=self.settings, push_reports=False)
        self.drain_ingest()

        self.assertTrue((self.settings.input_dir / "recover" / "round_end.json").is_file())
        self.assertEqual(self.store.get_round("recover")["status"], "receiving")


if __name__ == "__main__":
    unittest.main()
