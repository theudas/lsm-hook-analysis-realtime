#!/usr/bin/env python3
"""白盒用例：pipeline 的文件落盘工具、消息分派分支与 worker 生命周期。

pipeline 是唯一会删文件和起线程的模块，用例重点放在三类风险分支上：
清理目录时的越界保护、消息分派的每一条早退路径、以及分析任务被新一代
取代时的三个检查点（分析前 / 分析后 / 上报前）。
"""

from __future__ import annotations

import json
import runpy
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from lha_realtime import analyzer, pipeline as pipeline_mod
from lha_realtime.config import Settings
from lha_realtime.pipeline import (
    RealtimePipeline,
    atomic_write_json,
    clear_round_dir,
    copy_kernel_file,
    has_round_artifacts,
    is_within_input_dir,
    safe_len,
)
from lha_realtime.state import StateStore


class SafeLenTest(unittest.TestCase):
    def test_none_is_zero(self) -> None:
        """None 的长度按 0 处理，日志摘要不报错。"""
        self.assertEqual(safe_len(None), 0)

    def test_non_string_values_are_stringified(self) -> None:
        """非字符串值先转字符串再取长度。"""
        self.assertEqual(safe_len("abc"), 3)
        self.assertEqual(safe_len(1234), 4)
        self.assertEqual(safe_len([]), 2)


class FileHelperTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.settings = Settings(
            input_dir=self.root / "input",
            log_dir=self.root / "logs",
            state_dir=self.root / "state",
            db_path=self.root / "state" / "realtime.db",
        )
        self.settings.input_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_atomic_write_creates_parents_and_leaves_no_temp_file(self) -> None:
        """原子写自动建父目录且不残留临时文件。"""
        target = self.root / "nested" / "deep" / "payload.json"
        atomic_write_json(target, {"k": "值"})
        self.assertEqual(json.loads(target.read_text(encoding="utf-8")), {"k": "值"})
        self.assertEqual([p.name for p in target.parent.iterdir()], ["payload.json"])

    def test_atomic_write_overwrites_in_place(self) -> None:
        """重复写入同一路径时原地覆盖。"""
        target = self.root / "p.json"
        atomic_write_json(target, {"v": 1})
        atomic_write_json(target, {"v": 2})
        self.assertEqual(json.loads(target.read_text(encoding="utf-8")), {"v": 2})

    def test_is_within_input_dir(self) -> None:
        """正确区分 input 目录内外的路径。"""
        self.assertTrue(is_within_input_dir(self.settings.input_dir / "r1", self.settings))
        self.assertFalse(is_within_input_dir(self.root / "elsewhere", self.settings))
        self.assertFalse(is_within_input_dir(Path("/etc"), self.settings))

    def test_path_traversal_escape_is_rejected(self) -> None:
        """带 .. 的穿越路径被判定为越界。"""
        escape = self.settings.input_dir / ".." / "elsewhere"
        self.assertFalse(is_within_input_dir(escape, self.settings))

    def test_has_round_artifacts(self) -> None:
        """按已知产物文件名判断目录是否有残留。"""
        round_dir = self.settings.input_dir / "r1"
        round_dir.mkdir(parents=True)
        self.assertFalse(has_round_artifacts(round_dir))
        (round_dir / "round_end.json").write_text("{}", encoding="utf-8")
        self.assertTrue(has_round_artifacts(round_dir))

    def test_clear_round_dir_refuses_paths_outside_input_dir(self) -> None:
        """拒绝清理 input 目录之外的路径，防止误删。"""
        victim = self.root / "not-input"
        victim.mkdir()
        (victim / "keep.txt").write_text("important", encoding="utf-8")
        with self.assertRaises(RuntimeError):
            clear_round_dir(victim, self.settings)
        self.assertTrue((victim / "keep.txt").is_file())

    def test_clear_round_dir_removes_inputs_dotfiles_and_analysis_dirs(self) -> None:
        """清理输入、临时点文件与 analysis_ 目录，保留无关文件。"""
        round_dir = self.settings.input_dir / "r1"
        round_dir.mkdir(parents=True)
        (round_dir / "round_end.json").write_text("{}", encoding="utf-8")
        (round_dir / "analysis_report.md").write_text("old", encoding="utf-8")
        (round_dir / ".round_end.json.tmp").write_text("stale", encoding="utf-8")
        (round_dir / "analysis_extra").mkdir()
        (round_dir / "analysis_extra" / "inner.txt").write_text("x", encoding="utf-8")
        (round_dir / "unrelated.txt").write_text("keep me", encoding="utf-8")

        clear_round_dir(round_dir, self.settings)

        self.assertFalse((round_dir / "round_end.json").exists())
        self.assertFalse((round_dir / "analysis_report.md").exists())
        self.assertFalse((round_dir / ".round_end.json.tmp").exists())
        self.assertFalse((round_dir / "analysis_extra").exists())
        # 不属于 round 产物的文件不动。
        self.assertTrue((round_dir / "unrelated.txt").is_file())

    def test_clear_round_dir_creates_a_missing_directory(self) -> None:
        """目录不存在时先创建再清理。"""
        round_dir = self.settings.input_dir / "fresh"
        clear_round_dir(round_dir, self.settings)
        self.assertTrue(round_dir.is_dir())

    def test_copy_kernel_file_handles_missing_sources(self) -> None:
        dst = self.root / "dst.jsonl"
        self.assertIsNone(copy_kernel_file("r1", None, dst))
        self.assertIsNone(copy_kernel_file("r1", "", dst))
        self.assertIsNone(copy_kernel_file("r1", str(self.root / "nope.jsonl"), dst))
        # 源目录不是文件时同样跳过，而不是抛异常。
        self.assertIsNone(copy_kernel_file("r1", str(self.root), dst))
        self.assertFalse(dst.exists())

    def test_copy_kernel_file_copies_content_atomically(self) -> None:
        """内核文件按原子方式拷贝且不留临时文件。"""
        src = self.root / "src.jsonl"
        src.write_text('{"a": 1}\n', encoding="utf-8")
        dst = self.root / "nested" / "dst.jsonl"
        result = copy_kernel_file("r1", str(src), dst)
        self.assertEqual(result, dst)
        self.assertEqual(dst.read_text(encoding="utf-8"), '{"a": 1}\n')
        self.assertEqual([p.name for p in dst.parent.iterdir()], ["dst.jsonl"])


class PipelineTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.settings = Settings(
            input_dir=self.root / "input",
            log_dir=self.root / "logs",
            state_dir=self.root / "state",
            db_path=self.root / "state" / "realtime.db",
            max_attempts=2,
            ingest_poll_interval=0.001,
            analysis_poll_interval=0.001,
        )
        self.kernel_syscalls = self.root / "kernel_syscall_seq.jsonl"
        self.kernel_lsm = self.root / "kernel_lsm_hook_result.jsonl"
        self.kernel_syscalls.write_text("", encoding="utf-8")
        self.kernel_lsm.write_text("", encoding="utf-8")
        self.store = StateStore(settings=self.settings)
        self.pipeline = RealtimePipeline(store=self.store, settings=self.settings, push_reports=False)

    def tearDown(self) -> None:
        self.pipeline.stop()
        self.store.close()
        self.tmp.cleanup()

    def round_start(self, round_id: str, **extra) -> dict:
        return {"push_type": "round_start", "round_id": round_id,
                "time_start": "t0", "session_key": "s", **extra}

    def round_end(self, round_id: str, **extra) -> dict:
        return {"push_type": "round_end", "round_id": round_id,
                "time_end": "t1", "action_json": "[]", **extra}

    def round_kernel(self, round_id: str, **extra) -> dict:
        return {
            "push_type": "round_kernel",
            "round_id": round_id,
            "kernel_syscall_seq": str(self.kernel_syscalls),
            "kernel_lsm_hook_result": str(self.kernel_lsm),
            "kernel_resource_facts": json.dumps({"resource_facts": []}),
            **extra,
        }

    def round_ir(self, round_id: str, ir: dict | None = None, **extra) -> dict:
        return {
            "push_type": "round_ir_ready",
            "round_id": round_id,
            "ir_json": json.dumps(ir if ir is not None else {"policies": []}),
            **extra,
        }

    def feed_full_round(self, round_id: str, **extra) -> None:
        self.store.enqueue_message(self.round_start(round_id, **extra))
        self.store.enqueue_message(self.round_end(round_id, **extra))
        self.store.enqueue_message(self.round_kernel(round_id, **extra))
        self.store.enqueue_message(self.round_ir(round_id, **extra))

    def drain(self, pipeline: RealtimePipeline | None = None) -> None:
        target = pipeline or self.pipeline
        while target.ingest_once(limit=100):
            pass
        while target.analyze_once():
            pass


class MessageDispatchTest(PipelineTestBase):
    def test_non_dict_payload_is_ignored(self) -> None:
        """payload 不是字典时忽略且不建 round。"""
        message_id = self.store.enqueue_message({"round_id": "x", "push_type": "round_end"})
        with self.store._lock, self.store._conn:
            self.store._conn.execute(
                "UPDATE inbox_messages SET payload_json = ? WHERE id = ?", ("[1, 2]", message_id)
            )
        self.assertEqual(self.pipeline.ingest_once(), 1)
        row = self.store._conn.execute(
            "SELECT * FROM inbox_messages WHERE id = ?", (message_id,)
        ).fetchone()
        self.assertEqual(row["status"], "done")
        self.assertIsNone(self.store.get_round("x"))

    def test_message_without_round_id_is_ignored(self) -> None:
        """缺少 round_id 的消息被丢弃并标记处理完成。"""
        self.store.enqueue_message({"push_type": "round_end"})
        self.assertEqual(self.pipeline.ingest_once(), 1)
        self.assertEqual(self.store.counts()["pending_messages"], 0)

    def test_unhandled_push_type_is_ignored(self) -> None:
        """未支持的 push_type 不落盘、不建状态。"""
        self.store.enqueue_message({"push_type": "heartbeat", "round_id": "hb"})
        self.pipeline.ingest_once()
        self.assertIsNone(self.store.get_round("hb"))
        self.assertFalse((self.settings.input_dir / "hb").exists())

    def test_empty_ir_ready_is_skipped_without_marking_has_ir(self) -> None:
        """空 IR 的 round_ir_ready 不置 has_ir，继续等待真实 IR。"""
        self.store.enqueue_message(self.round_start("e"))
        self.store.enqueue_message(self.round_end("e"))
        self.store.enqueue_message(self.round_kernel("e"))
        self.store.enqueue_message({"push_type": "round_ir_ready", "round_id": "e", "ir_json": ""})
        self.pipeline.ingest_once(limit=100)

        state = self.store.get_round("e")
        self.assertEqual(state["has_ir"], 0)
        self.assertEqual(state["status"], "receiving")
        self.assertFalse((self.settings.input_dir / "e" / "ir.json").exists())

    def test_legacy_round_end_ir_json_is_adopted_when_no_standalone_ir(self) -> None:
        """旧上游把 IR 放在 round_end 里时被采纳并触发就绪。"""
        self.store.enqueue_message(self.round_start("legacy"))
        self.store.enqueue_message(self.round_kernel("legacy"))
        self.store.enqueue_message(
            self.round_end("legacy", ir_json=json.dumps({"policies": []}))
        )
        self.pipeline.ingest_once(limit=100)

        state = self.store.get_round("legacy")
        self.assertEqual(state["has_ir"], 1)
        # 四类输入齐备后立即入队分析，因此状态已经从 ready 前进到 queued。
        self.assertEqual(state["status"], "queued")
        self.assertTrue((self.settings.input_dir / "legacy" / "ir.json").is_file())

    def test_persist_ir_writes_and_flags_without_an_emptiness_check(self) -> None:
        # _persist_ir 是 round_end 兼容路径直接调用的版本：调用方已确认 ir_json 非空，
        # 它必须无条件落盘并返回新的 round 状态（不会返回 None）。
        self.store.begin_round_for_message("direct", self.settings.input_dir / "direct")
        state = self.pipeline._persist_ir(
            "direct", 1, self.settings.input_dir / "direct", {"ir_json": json.dumps({"policies": []})}
        )
        self.assertEqual(state["has_ir"], 1)
        self.assertTrue((self.settings.input_dir / "direct" / "ir.json").is_file())

    def test_record_ir_returns_none_only_for_an_empty_payload(self) -> None:
        """_record_ir 仅在 ir_json 为空时返回 None。"""
        self.store.begin_round_for_message("guarded", self.settings.input_dir / "guarded")
        round_dir = self.settings.input_dir / "guarded"
        self.assertIsNone(self.pipeline._record_ir("guarded", 1, round_dir, {}))
        self.assertIsNone(self.pipeline._record_ir("guarded", 1, round_dir, {"ir_json": ""}))
        self.assertIsNotNone(
            self.pipeline._record_ir("guarded", 1, round_dir, {"ir_json": json.dumps({})})
        )

    def test_standalone_ir_wins_over_a_later_round_end_ir_json(self) -> None:
        """已有独立 IR 后，迟到的 round_end.ir_json 不覆盖它。"""
        self.store.enqueue_message(self.round_ir("both", ir={"policies": [{"effect": "allow", "objects": []}]}))
        self.pipeline.ingest_once(limit=100)
        self.store.enqueue_message(self.round_end("both", ir_json=json.dumps({"policies": []})))
        self.pipeline.ingest_once(limit=100)

        saved = json.loads((self.settings.input_dir / "both" / "ir.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["push_type"], "round_ir_ready")

    def test_kernel_files_that_cannot_be_copied_leave_paths_null(self) -> None:
        """内核文件拷贝失败时路径留空，但 round_kernel 仍算到达。"""
        self.store.enqueue_message(
            {
                "push_type": "round_kernel",
                "round_id": "nofiles",
                "kernel_syscall_seq": str(self.root / "missing.jsonl"),
                "kernel_lsm_hook_result": None,
            }
        )
        self.pipeline.ingest_once()
        state = self.store.get_round("nofiles")
        self.assertIsNone(state["syscall_path"])
        self.assertIsNone(state["lsm_path"])
        self.assertEqual(state["has_round_kernel"], 1)

    def test_orphan_artifacts_without_state_are_cleared_before_reuse(self) -> None:
        """有产物无状态的目录在复用前被清理干净。"""
        round_dir = self.settings.input_dir / "orphan"
        round_dir.mkdir(parents=True)
        stale = round_dir / "analysis_report.md"
        stale.write_text("stale report from a previous deployment", encoding="utf-8")
        (round_dir / "round_end.json").write_text("{}", encoding="utf-8")

        self.store.enqueue_message(self.round_start("orphan"))
        self.pipeline.ingest_once()

        self.assertFalse(stale.exists())
        self.assertTrue((round_dir / "round_start.json").is_file())


class NewGenerationDecisionTest(PipelineTestBase):
    def decide(self, round_id: str, push_type: str) -> bool:
        return self.pipeline._should_start_new_generation(
            round_id, push_type, self.settings.input_dir / round_id
        )

    def test_unknown_round_without_artifacts_stays_on_generation_one(self) -> None:
        """全新 round 且目录干净时不触发新代次。"""
        self.assertFalse(self.decide("ghost", "round_kernel"))

    def test_unknown_round_with_artifacts_forces_a_clear(self) -> None:
        """无状态但有产物时要求先清理再处理。"""
        round_dir = self.settings.input_dir / "ghost2"
        round_dir.mkdir(parents=True)
        (round_dir / "ir.json").write_text("{}", encoding="utf-8")
        self.assertTrue(self.decide("ghost2", "round_kernel"))

    def test_metadata_messages_never_start_a_new_generation(self) -> None:
        """round_end/round_start 等元数据消息不触发重跑。"""
        self.feed_full_round("meta")
        self.drain()
        self.assertEqual(self.store.get_round("meta")["status"], "done")
        self.assertFalse(self.decide("meta", "round_end"))
        self.assertFalse(self.decide("meta", "round_start"))

    def test_required_input_on_a_settled_round_starts_a_re_run(self) -> None:
        """已结束的 round 再收到 IR 或内核消息时触发重跑。"""
        self.feed_full_round("settled")
        self.drain()
        self.assertTrue(self.decide("settled", "round_kernel"))
        self.assertTrue(self.decide("settled", "round_ir_ready"))

    def test_required_input_while_still_receiving_overwrites_in_place(self) -> None:
        """round 仍在收集阶段时重复消息原地覆盖，不换代次。"""
        self.store.enqueue_message(self.round_start("inflight"))
        self.pipeline.ingest_once()
        self.assertEqual(self.store.get_round("inflight")["status"], "receiving")
        self.assertFalse(self.decide("inflight", "round_kernel"))

    def test_failed_round_is_terminal_and_can_be_replayed(self) -> None:
        """分析失败的 round 属终态，可被重放重跑。"""
        self.store.enqueue_message(self.round_start("bad"))
        self.store.enqueue_message(self.round_end("bad", ir_json="{"))
        self.store.enqueue_message(self.round_kernel("bad"))
        self.drain()
        self.assertEqual(self.store.get_round("bad")["status"], "analysis_failed")
        self.assertTrue(self.decide("bad", "round_ir_ready"))


class IngestFailureTest(PipelineTestBase):
    def test_transient_failure_is_requeued_until_max_attempts(self) -> None:
        self.store.enqueue_message(self.round_start("boom"))
        with patch.object(self.pipeline, "process_message", side_effect=RuntimeError("nope")):
            self.pipeline.ingest_once()
            row = self.store._conn.execute("SELECT * FROM inbox_messages").fetchone()
            # max_attempts=2，第一次失败后仍可重试。
            self.assertEqual(row["status"], "pending")
            self.assertEqual(row["last_error"], "nope")

            self.pipeline.ingest_once()
            row = self.store._conn.execute("SELECT * FROM inbox_messages").fetchone()
            self.assertEqual(row["status"], "failed")

    def test_one_bad_message_does_not_block_the_rest_of_the_batch(self) -> None:
        """单条消息处理失败不影响同批次其余消息。"""
        self.store.enqueue_message(self.round_start("ok1"))
        self.store.enqueue_message(self.round_start("ok2"))
        original = self.pipeline.process_message
        calls = {"n": 0}

        def flaky(message):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("first one explodes")
            return original(message)

        with patch.object(self.pipeline, "process_message", side_effect=flaky):
            self.assertEqual(self.pipeline.ingest_once(limit=10), 2)
        self.assertIsNotNone(self.store.get_round("ok2"))


class AnalysisSupersessionTest(PipelineTestBase):
    def queue_job(self, round_id: str = "sup") -> None:
        self.feed_full_round(round_id)
        while self.pipeline.ingest_once(limit=100):
            pass

    def bump_generation(self, round_id: str = "sup") -> None:
        self.store.begin_round_for_message(
            round_id, self.settings.input_dir / round_id, force_new_generation=True
        )

    def orphan_the_queued_job(self, round_id: str = "sup") -> None:
        """只推进 round 的 generation，不撤销已排队的任务。

        对应真实竞态：worker 已经把任务取走（或即将取走），而重放请求正好在
        cancel 与 worker 读取之间落地。此时任务仍是 queued，但它的 generation
        已经过期——analyze_once 的三道 is_current_generation 检查就是为此存在。
        """
        with self.store._lock, self.store._conn:
            self.store._conn.execute(
                "UPDATE round_states SET generation = generation + 1 WHERE round_id = ?",
                (round_id,),
            )

    def test_job_superseded_before_analysis_is_abandoned(self) -> None:
        """任务在分析前已被取代时直接放弃，不做无谓分析。"""
        self.queue_job()
        self.orphan_the_queued_job()
        with patch.object(analyzer, "analyze_round") as analyze:
            self.assertTrue(self.pipeline.analyze_once())
        analyze.assert_not_called()
        row = self.store._conn.execute(
            "SELECT * FROM analysis_jobs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        self.assertEqual(row["status"], "failed")
        self.assertIn("superseded before analysis", row["last_error"])

    def test_job_superseded_during_analysis_does_not_write_outputs(self) -> None:
        """分析过程中被取代时不写出报告，避免覆盖新结果。"""
        self.queue_job()
        real_analyze = analyzer.analyze_round

        def analyze_then_supersede(round_dir):
            result = real_analyze(round_dir)
            self.bump_generation()
            return result

        with patch.object(analyzer, "analyze_round", side_effect=analyze_then_supersede), \
             patch.object(analyzer, "write_outputs") as write_outputs:
            self.pipeline.analyze_once()
        write_outputs.assert_not_called()

    def test_job_superseded_before_push_does_not_report(self) -> None:
        """上报前被取代时不上报，避免推送过期报告。"""
        self.queue_job()
        pipeline = RealtimePipeline(store=self.store, settings=self.settings, push_reports=True)
        real_write = analyzer.write_outputs

        def write_then_supersede(round_dir, result):
            paths = real_write(round_dir, result)
            self.bump_generation()
            return paths

        with patch.object(analyzer, "write_outputs", side_effect=write_then_supersede), \
             patch.object(analyzer, "push_and_mark_report") as push:
            pipeline.analyze_once()
        push.assert_not_called()

    def test_superseded_job_is_not_retried_even_below_max_attempts(self) -> None:
        self.queue_job()
        self.orphan_the_queued_job()
        self.pipeline.analyze_once()
        # 被取代的任务重试没有意义，必须直接置 failed 而不是回到 queued。
        self.assertIsNone(self.store.fetch_queued_job())


class AnalysisPushTest(PipelineTestBase):
    def test_push_failure_marks_the_job_failed(self) -> None:
        """上报失败经重试后任务置 analysis_failed 并记录原因。"""
        pipeline = RealtimePipeline(store=self.store, settings=self.settings, push_reports=True)
        self.feed_full_round("pushfail")
        while pipeline.ingest_once(limit=100):
            pass

        with patch.object(analyzer, "push_and_mark_report", return_value=False):
            pipeline.analyze_once()
            pipeline.analyze_once()

        self.assertEqual(self.store.get_round("pushfail")["status"], "analysis_failed")
        self.assertIn("report push failed", self.store.get_round("pushfail")["last_error"])

    def test_mock_round_is_analyzed_but_not_pushed(self) -> None:
        """mock round 正常生成报告但跳过上报。"""
        pipeline = RealtimePipeline(store=self.store, settings=self.settings, push_reports=True)
        self.feed_full_round("mocked", is_mock=True)
        while pipeline.ingest_once(limit=100):
            pass

        with patch.object(analyzer, "push_and_mark_report") as push:
            pipeline.analyze_once()

        push.assert_not_called()
        self.assertEqual(self.store.get_round("mocked")["status"], "done")
        self.assertTrue((self.settings.input_dir / "mocked" / "analysis_report.md").is_file())

    def test_analyze_once_on_empty_queue_returns_false(self) -> None:
        """队列为空时分析循环返回 False 以进入休眠。"""
        self.assertFalse(self.pipeline.analyze_once())


class WorkerLifecycleTest(PipelineTestBase):
    def test_start_spawns_one_ingest_worker_and_n_analysis_workers(self) -> None:
        """启动后线程数与命名符合配置的 worker 数量。"""
        settings = Settings(
            input_dir=self.settings.input_dir,
            log_dir=self.settings.log_dir,
            state_dir=self.settings.state_dir,
            db_path=self.settings.db_path,
            analyzer_workers=3,
            ingest_poll_interval=0.001,
            analysis_poll_interval=0.001,
        )
        pipeline = RealtimePipeline(store=self.store, settings=settings, push_reports=False)
        pipeline.start()
        try:
            names = [thread.name for thread in pipeline._threads]
            self.assertEqual(names, ["lha-ingest", "lha-analyze-1", "lha-analyze-2", "lha-analyze-3"])
            self.assertTrue(all(thread.is_alive() for thread in pipeline._threads))
        finally:
            pipeline.stop()
            pipeline.join()
        self.assertFalse(any(thread.is_alive() for thread in pipeline._threads))

    def test_zero_or_negative_worker_setting_still_starts_one_worker(self) -> None:
        """worker 数配成 0 时兜底启动一个分析线程。"""
        settings = Settings(
            input_dir=self.settings.input_dir,
            log_dir=self.settings.log_dir,
            state_dir=self.settings.state_dir,
            db_path=self.settings.db_path,
            analyzer_workers=0,
            ingest_poll_interval=0.001,
            analysis_poll_interval=0.001,
        )
        pipeline = RealtimePipeline(store=self.store, settings=settings, push_reports=False)
        pipeline.start()
        try:
            self.assertEqual(len(pipeline._threads), 2)
        finally:
            pipeline.stop()
            pipeline.join()

    def test_running_workers_process_a_round_end_to_end(self) -> None:
        """真实多线程环境下完整处理一个 round 到 done。"""
        self.pipeline.start()
        try:
            self.feed_full_round("threaded")
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                state = self.store.get_round("threaded")
                if state and state["status"] == "done":
                    break
                time.sleep(0.01)
        finally:
            self.pipeline.stop()
            self.pipeline.join()

        self.assertEqual(self.store.get_round("threaded")["status"], "done")
        self.assertTrue((self.settings.input_dir / "threaded" / "analysis_report.md").is_file())

    def test_stop_is_observed_by_both_loops(self) -> None:
        self.pipeline._stop.set()
        # 已置位时循环体直接退出，不会阻塞。
        ingest = threading.Thread(target=self.pipeline.ingest_loop)
        analysis = threading.Thread(target=self.pipeline.analysis_loop)
        ingest.start()
        analysis.start()
        ingest.join(timeout=5)
        analysis.join(timeout=5)
        self.assertFalse(ingest.is_alive())
        self.assertFalse(analysis.is_alive())


class MainEntrypointTest(unittest.TestCase):
    def test_main_starts_logs_a_heartbeat_then_stops_on_interrupt(self) -> None:
        """main 启动 worker、打心跳日志，收到中断后停止并回收。"""
        fake = MagicMock()
        fake.push_reports = False
        fake.store.counts.return_value = {"pending_messages": 0, "queued_jobs": 0}
        sleeps = {"n": 0}

        def sleep(_seconds):
            sleeps["n"] += 1
            if sleeps["n"] >= 2:
                raise KeyboardInterrupt
            return None

        with patch.object(pipeline_mod, "RealtimePipeline", return_value=fake), \
             patch.object(pipeline_mod.time, "sleep", side_effect=sleep):
            pipeline_mod.main()

        fake.start.assert_called_once()
        self.assertEqual(fake.store.counts.call_count, 1)
        fake.stop.assert_called_once()
        fake.join.assert_called_once()

    def test_module_entrypoint_runs_main(self) -> None:
        """`python3 -m lha_realtime.pipeline` 走 __main__ 分支。"""
        store = MagicMock()
        store.fetch_pending_messages.return_value = []
        store.fetch_queued_job.return_value = None
        store.counts.return_value = {"pending_messages": 0, "queued_jobs": 0}

        def sleep(seconds):
            # 只打断 main 的心跳等待，worker 循环的短轮询照常返回。
            if seconds == 30:
                raise KeyboardInterrupt
            return None

        with patch("lha_realtime.state.StateStore", return_value=store), \
             patch("time.sleep", side_effect=sleep):
            runpy.run_module("lha_realtime.pipeline", run_name="__main__")

        store.counts.assert_not_called()


if __name__ == "__main__":
    unittest.main()
