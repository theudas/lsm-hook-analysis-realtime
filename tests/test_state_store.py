#!/usr/bin/env python3
"""白盒用例：StateStore 的 schema 迁移、状态机流转与防御性分支。

SQLite 层是整个服务的事实来源：round 是否就绪、任务是否被新一代取代、消息是否
还要重试，全部由这里决定。用例按"状态机的每条边"组织，并覆盖老库升级、
无效入参、目标行不存在等不会在正常链路上出现、但一出现就会静默丢数据的分支。
"""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from lha_realtime.config import Settings
from lha_realtime.state import (
    FINAL_JOB_STATUSES,
    ROUND_TERMINAL_STATUSES,
    StateStore,
    json_size,
    now_iso,
)


class HelperTest(unittest.TestCase):
    def test_now_iso_has_second_precision(self) -> None:
        stamp = now_iso()
        self.assertRegex(stamp, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$")

    def test_json_size_counts_utf8_bytes_not_characters(self) -> None:
        self.assertEqual(json_size({"a": 1}), len('{"a": 1}'))
        # 中文按 UTF-8 计 3 字节，确保日志里的 size 是真实字节数。
        self.assertEqual(json_size({"k": "中"}), len('{"k": "中"}'.encode("utf-8")))


class StateStoreTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.settings = Settings(
            input_dir=self.root / "input",
            log_dir=self.root / "logs",
            state_dir=self.root / "state",
            db_path=self.root / "state" / "realtime.db",
        )
        self.store = StateStore(settings=self.settings)

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def round_dir(self, round_id: str) -> Path:
        return self.settings.input_dir / round_id

    def make_ready_round(self, round_id: str = "r") -> int:
        """把一个 round 推进到 ready 并返回其 generation。"""
        generation, _ = self.store.begin_round_for_message(round_id, self.round_dir(round_id))
        for kind, filename in (
            ("round_start", "round_start.json"),
            ("round_end", "round_end.json"),
            ("round_ir", "ir.json"),
            ("round_kernel", "round_kernel.json"),
        ):
            state = self.store.record_round_input(
                round_id, generation, kind, self.round_dir(round_id) / filename
            )
        self.assertEqual(state["status"], "ready")
        return generation


class SchemaMigrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.settings = Settings(
            input_dir=self.root / "input",
            log_dir=self.root / "logs",
            state_dir=self.root / "state",
            db_path=self.root / "state" / "old.db",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_pre_ir_database_gains_the_new_columns(self) -> None:
        # 模拟 has_ir / round_start 相关列引入之前建的库。
        self.settings.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.settings.db_path)
        conn.executescript(
            """
            CREATE TABLE round_states (
                round_id TEXT PRIMARY KEY,
                generation INTEGER NOT NULL,
                status TEXT NOT NULL,
                round_dir TEXT NOT NULL,
                has_round_end INTEGER NOT NULL DEFAULT 0,
                has_round_kernel INTEGER NOT NULL DEFAULT 0,
                round_end_path TEXT,
                round_kernel_path TEXT,
                syscall_path TEXT,
                lsm_path TEXT,
                analysis_job_id INTEGER,
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            INSERT INTO round_states VALUES
                ('legacy', 1, 'done', '/tmp/legacy', 1, 1, NULL, NULL, NULL, NULL, NULL, NULL, 'x', 'x');
            """
        )
        conn.commit()
        conn.close()

        store = StateStore(settings=self.settings)
        try:
            columns = {
                row["name"]
                for row in store._conn.execute("PRAGMA table_info(round_states)").fetchall()
            }
            self.assertLessEqual({"has_ir", "ir_path", "has_round_start", "round_start_path"}, columns)
            legacy = store.get_round("legacy")
            self.assertEqual(legacy["has_ir"], 0)
            self.assertEqual(legacy["has_round_start"], 0)
            # 迁移是幂等的：再打开一次不应报 duplicate column。
            store.init_db()
        finally:
            store.close()


class InboxTest(StateStoreTestBase):
    def test_enqueue_records_type_round_id_and_size(self) -> None:
        """入库消息记录 push_type、round_id、字节数并初始为 pending。"""
        message_id = self.store.enqueue_message({"push_type": "round_end", "round_id": "r1"})
        row = self.store._conn.execute(
            "SELECT * FROM inbox_messages WHERE id = ?", (message_id,)
        ).fetchone()
        self.assertEqual(row["push_type"], "round_end")
        self.assertEqual(row["round_id"], "r1")
        self.assertEqual(row["status"], "pending")
        self.assertGreater(row["payload_size"], 0)

    def test_payload_without_known_keys_is_still_accepted(self) -> None:
        """不带已知字段的 payload 也接收入库，不丢消息。"""
        self.store.enqueue_message({"anything": 1})
        row = self.store.fetch_pending_messages()[0]
        self.assertIsNone(row["push_type"])
        self.assertIsNone(row["round_id"])

    def test_fetch_marks_messages_processing_and_counts_attempts(self) -> None:
        self.store.enqueue_message({"round_id": "a"})
        first = self.store.fetch_pending_messages()
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0]["attempts"], 0)
        # 已被取走的消息不会再次出现在 pending 里。
        self.assertEqual(self.store.fetch_pending_messages(), [])

        self.store.fail_message(int(first[0]["id"]), "transient", retry=True)
        second = self.store.fetch_pending_messages()
        self.assertEqual(second[0]["attempts"], 1)

    def test_fetch_respects_limit_and_id_order(self) -> None:
        """取消息按 id 升序并遵守条数上限。"""
        ids = [self.store.enqueue_message({"round_id": f"r{i}"}) for i in range(5)]
        rows = self.store.fetch_pending_messages(limit=2)
        self.assertEqual([row["id"] for row in rows], ids[:2])

    def test_fetch_on_empty_inbox_returns_empty_list(self) -> None:
        """inbox 为空时返回空列表。"""
        self.assertEqual(self.store.fetch_pending_messages(), [])

    def test_fail_without_retry_is_terminal(self) -> None:
        """标记为不可重试的消息置 failed 且不再被取出。"""
        message_id = self.store.enqueue_message({"round_id": "a"})
        self.store.fetch_pending_messages()
        self.store.fail_message(message_id, "permanent", retry=False)
        row = self.store._conn.execute(
            "SELECT * FROM inbox_messages WHERE id = ?", (message_id,)
        ).fetchone()
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["last_error"], "permanent")
        self.assertEqual(self.store.fetch_pending_messages(), [])

    def test_complete_message_stores_generation_and_keeps_old_value_on_none(self) -> None:
        """完成消息时记录代次，传 None 不覆盖已有值。"""
        message_id = self.store.enqueue_message({"round_id": "a"})
        self.store.complete_message(message_id, 3)
        self.store.complete_message(message_id, None)
        row = self.store._conn.execute(
            "SELECT * FROM inbox_messages WHERE id = ?", (message_id,)
        ).fetchone()
        self.assertEqual(row["status"], "done")
        self.assertEqual(row["generation"], 3)


class RoundStateTest(StateStoreTestBase):
    def test_first_message_creates_generation_one(self) -> None:
        """首条消息为 round 建档，代次从 1 开始。"""
        generation, should_clear = self.store.begin_round_for_message("new", self.round_dir("new"))
        self.assertEqual(generation, 1)
        self.assertFalse(should_clear)
        self.assertEqual(self.store.get_round("new")["status"], "receiving")

    def test_orphan_artifacts_on_first_sight_request_a_clear(self) -> None:
        """首次见到但磁盘有残留产物时要求清理。"""
        _, should_clear = self.store.begin_round_for_message(
            "orphan", self.round_dir("orphan"), force_new_generation=True
        )
        self.assertTrue(should_clear)

    def test_existing_round_without_force_keeps_its_generation(self) -> None:
        """未强制新代次时沿用当前代次。"""
        self.store.begin_round_for_message("same", self.round_dir("same"))
        generation, should_clear = self.store.begin_round_for_message("same", self.round_dir("same"))
        self.assertEqual(generation, 1)
        self.assertFalse(should_clear)

    def test_unknown_round_has_no_current_generation(self) -> None:
        """查询未知 round 返回 None 而不是抛异常。"""
        self.assertIsNone(self.store.current_generation("ghost"))
        self.assertIsNone(self.store.get_round("ghost"))
        self.assertFalse(self.store.is_current_generation("ghost", 1))

    def test_unsupported_input_kind_is_rejected(self) -> None:
        """非法的输入类型直接抛 ValueError。"""
        self.store.begin_round_for_message("r", self.round_dir("r"))
        with self.assertRaises(ValueError):
            self.store.record_round_input("r", 1, "round_middle", self.round_dir("r") / "x.json")

    def test_recording_against_a_missing_generation_raises(self) -> None:
        """针对不存在的代次写入时显式报错。"""
        self.store.begin_round_for_message("r", self.round_dir("r"))
        with self.assertRaises(RuntimeError):
            self.store.record_round_input("r", 99, "round_end", self.round_dir("r") / "round_end.json")

    def test_round_only_becomes_ready_after_all_four_inputs(self) -> None:
        """四类输入全部就位后 round 才转为 ready。"""
        generation, _ = self.store.begin_round_for_message("r", self.round_dir("r"))
        for kind, filename in (
            ("round_end", "round_end.json"),
            ("round_kernel", "round_kernel.json"),
            ("round_ir", "ir.json"),
        ):
            state = self.store.record_round_input(
                "r", generation, kind, self.round_dir("r") / filename
            )
            self.assertEqual(state["status"], "receiving")
        state = self.store.record_round_input(
            "r", generation, "round_start", self.round_dir("r") / "round_start.json"
        )
        self.assertEqual(state["status"], "ready")

    def test_kernel_paths_are_only_overwritten_by_non_null_values(self) -> None:
        """重复的 round_kernel 不会把已有内核文件路径覆盖成空。"""
        generation, _ = self.store.begin_round_for_message("r", self.round_dir("r"))
        base = self.round_dir("r")
        self.store.record_round_input(
            "r", generation, "round_kernel", base / "round_kernel.json",
            syscall_path=base / "kernel_syscall_seq.jsonl",
            lsm_path=base / "kernel_lsm_hook_result.jsonl",
        )
        # 第二次没带内核文件路径：COALESCE 必须保留上一次的值。
        state = self.store.record_round_input("r", generation, "round_kernel", base / "round_kernel.json")
        self.assertTrue(state["syscall_path"].endswith("kernel_syscall_seq.jsonl"))
        self.assertTrue(state["lsm_path"].endswith("kernel_lsm_hook_result.jsonl"))

    def test_replay_bumps_generation_and_keeps_persisted_inputs(self) -> None:
        """重放推进代次但保留磁盘输入与就绪标记。"""
        generation = self.make_ready_round("r")
        job_id = self.store.enqueue_analysis_job("r", generation, self.round_dir("r"))
        self.store.complete_job(job_id)
        self.assertEqual(self.store.get_round("r")["status"], "done")

        new_generation, should_clear = self.store.begin_round_for_message(
            "r", self.round_dir("r"), force_new_generation=True
        )
        self.assertEqual(new_generation, 2)
        # 重跑保留磁盘输入，因此不清目录。
        self.assertFalse(should_clear)
        state = self.store.get_round("r")
        self.assertEqual(state["status"], "receiving")
        self.assertIsNone(state["analysis_job_id"])
        self.assertTrue(state["has_round_start"] and state["has_ir"])

    def test_replay_cancels_an_in_flight_job(self) -> None:
        """重放会取消在途分析任务并标注取代原因。"""
        generation = self.make_ready_round("r")
        job_id = self.store.enqueue_analysis_job("r", generation, self.round_dir("r"))
        self.store.fetch_queued_job()

        self.store.begin_round_for_message("r", self.round_dir("r"), force_new_generation=True)
        row = self.store._conn.execute("SELECT * FROM analysis_jobs WHERE id = ?", (job_id,)).fetchone()
        self.assertEqual(row["status"], "cancelled")
        self.assertEqual(row["last_error"], "superseded by re-run")
        self.assertIn(row["status"], FINAL_JOB_STATUSES)
        self.assertFalse(self.store.is_current_generation("r", generation))

    def test_finished_jobs_are_not_cancelled_by_a_replay(self) -> None:
        """重放不会改写已完成任务的状态。"""
        generation = self.make_ready_round("r")
        job_id = self.store.enqueue_analysis_job("r", generation, self.round_dir("r"))
        self.store.fetch_queued_job()
        self.store.complete_job(job_id)

        self.store.begin_round_for_message("r", self.round_dir("r"), force_new_generation=True)
        row = self.store._conn.execute("SELECT * FROM analysis_jobs WHERE id = ?", (job_id,)).fetchone()
        self.assertEqual(row["status"], "done")


class AnalysisJobTest(StateStoreTestBase):
    def test_enqueue_is_idempotent_per_generation(self) -> None:
        """同一代次重复入队只产生一个任务。"""
        generation = self.make_ready_round("r")
        first = self.store.enqueue_analysis_job("r", generation, self.round_dir("r"))
        second = self.store.enqueue_analysis_job("r", generation, self.round_dir("r"))
        self.assertEqual(first, second)
        self.assertEqual(self.store.counts()["queued_jobs"], 1)

    def test_enqueue_moves_round_from_ready_to_queued(self) -> None:
        """入队后 round 状态转 queued 并记录任务 id。"""
        generation = self.make_ready_round("r")
        job_id = self.store.enqueue_analysis_job("r", generation, self.round_dir("r"))
        state = self.store.get_round("r")
        self.assertEqual(state["status"], "queued")
        self.assertEqual(state["analysis_job_id"], job_id)

    def test_fetch_on_empty_queue_returns_none(self) -> None:
        """队列为空时取任务返回 None。"""
        self.assertIsNone(self.store.fetch_queued_job())

    def test_fetch_claims_the_oldest_job_exactly_once(self) -> None:
        """任务按 id 顺序被独占取走，不会重复分发。"""
        gen_a = self.make_ready_round("a")
        gen_b = self.make_ready_round("b")
        self.store.enqueue_analysis_job("a", gen_a, self.round_dir("a"))
        self.store.enqueue_analysis_job("b", gen_b, self.round_dir("b"))

        first = self.store.fetch_queued_job()
        self.assertEqual(first["round_id"], "a")
        self.assertEqual(first["status"], "analyzing")
        self.assertEqual(first["attempts"], 1)
        self.assertEqual(self.store.get_round("a")["status"], "analyzing")
        self.assertEqual(self.store.fetch_queued_job()["round_id"], "b")
        self.assertIsNone(self.store.fetch_queued_job())

    def test_status_transitions_propagate_to_the_round(self) -> None:
        """任务状态变更同步反映到 round 状态。"""
        generation = self.make_ready_round("r")
        job_id = self.store.enqueue_analysis_job("r", generation, self.round_dir("r"))
        self.store.fetch_queued_job()

        self.store.mark_job_reporting(job_id)
        self.assertEqual(self.store.get_round("r")["status"], "reporting")
        self.store.complete_job(job_id)
        self.assertEqual(self.store.get_round("r")["status"], "done")
        self.assertIn("done", ROUND_TERMINAL_STATUSES)

    def test_failure_with_retry_requeues_the_job(self) -> None:
        """可重试的失败把任务放回队列并累加尝试次数。"""
        generation = self.make_ready_round("r")
        job_id = self.store.enqueue_analysis_job("r", generation, self.round_dir("r"))
        self.store.fetch_queued_job()

        self.store.fail_job(job_id, "boom", retry=True)
        self.assertEqual(self.store.get_round("r")["status"], "queued")
        self.assertEqual(self.store.get_round("r")["last_error"], "boom")
        # 重新排队后能再次被取走，且 attempts 累加。
        self.assertEqual(self.store.fetch_queued_job()["attempts"], 2)

    def test_failure_without_retry_is_terminal(self) -> None:
        """不可重试的失败置 analysis_failed 且不再出队。"""
        generation = self.make_ready_round("r")
        job_id = self.store.enqueue_analysis_job("r", generation, self.round_dir("r"))
        self.store.fetch_queued_job()

        self.store.fail_job(job_id, "fatal", retry=False)
        self.assertEqual(self.store.get_round("r")["status"], "analysis_failed")
        self.assertIsNone(self.store.fetch_queued_job())

    def test_operations_on_an_unknown_job_are_silent_no_ops(self) -> None:
        # 任务行被并发清掉时这些调用必须安静返回，而不是抛异常打断 worker。
        self.store.fail_job(9999, "gone")
        self.store.complete_job(9999)
        self.store.mark_job_reporting(9999)

    def test_enqueue_raises_if_the_job_row_cannot_be_read_back(self) -> None:
        # 防御性分支：INSERT 之后立刻回读不到行（并发删库/磁盘异常），必须显式报错，
        # 否则 round 会永远停在 ready 而没有任何任务在跑。
        # sqlite3.Connection.execute 是只读的 C 属性，无法直接 patch，这里用代理包一层。
        generation = self.make_ready_round("r")
        real_conn = self.store._conn

        class BlindSelectConn:
            def execute(self, sql, *args, **kwargs):
                if "SELECT id" in sql and "analysis_jobs" in sql:
                    empty = unittest.mock.MagicMock()
                    empty.fetchone.return_value = None
                    return empty
                return real_conn.execute(sql, *args, **kwargs)

            def __enter__(self):
                return real_conn.__enter__()

            def __exit__(self, *exc):
                return real_conn.__exit__(*exc)

        self.store._conn = BlindSelectConn()
        try:
            with self.assertRaises(RuntimeError):
                self.store.enqueue_analysis_job("r", generation, self.round_dir("r"))
        finally:
            self.store._conn = real_conn

    def test_counts_reflect_pending_and_queued_work(self) -> None:
        """计数接口如实反映待处理消息与排队任务数。"""
        self.assertEqual(self.store.counts(), {"pending_messages": 0, "queued_jobs": 0})
        self.store.enqueue_message({"round_id": "r"})
        generation = self.make_ready_round("r")
        self.store.enqueue_analysis_job("r", generation, self.round_dir("r"))
        self.assertEqual(self.store.counts(), {"pending_messages": 1, "queued_jobs": 1})


class PersistenceTest(StateStoreTestBase):
    def test_state_survives_a_reopen(self) -> None:
        """round 与任务状态在重开库后完整保留。"""
        generation = self.make_ready_round("r")
        self.store.enqueue_analysis_job("r", generation, self.round_dir("r"))
        self.store.close()

        self.store = StateStore(settings=self.settings)
        self.assertEqual(self.store.get_round("r")["status"], "queued")
        self.assertEqual(self.store.counts()["queued_jobs"], 1)

    def test_explicit_db_path_argument_wins_over_settings(self) -> None:
        """显式传入的 db_path 优先于配置项。"""
        custom = self.root / "elsewhere" / "custom.db"
        store = StateStore(db_path=custom, settings=self.settings)
        try:
            self.assertEqual(store.db_path, custom)
            self.assertTrue(custom.is_file())
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
