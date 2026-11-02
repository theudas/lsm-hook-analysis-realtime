#!/usr/bin/env python3
"""白盒用例：看门狗的超时告警、过期归档、孤儿目录扫描与消息清理。

覆盖 lha_realtime/watchdog.py 与 pipeline 的看门狗接线。所有用例都用临时目录
里的 Settings，绝不触碰仓库真实的 input/（历史上曾有一个 runpy 用例放跑了
真实看门狗，把 48k 个 round 归档走——别再犯）。
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

from lha_realtime.config import Settings
from lha_realtime.pipeline import RealtimePipeline
from lha_realtime.state import StateStore
from lha_realtime.watchdog import (
    COMPLETE_MASK,
    IR_BIT,
    REQUIRED_FILES,
    StaleRoundWatchdog,
    _age_seconds,
    _fmt_age,
    _is_within,
    input_mask,
    is_complete_on_disk,
    missing_on_disk,
)


@contextmanager
def allow_service_logs(name: str):
    """assertLogs 前临时摘掉 logger 上挂的 SuppressServiceLogs 过滤器。

    tests/__init__.py 会往服务 logger 上挂丢弃全部记录的过滤器；assertLogs
    只接管 handlers 不动 filters，不过滤的话一条记录也捕不到。
    """
    logger = logging.getLogger(name)
    saved = logger.filters[:]
    logger.filters = []
    try:
        yield
    finally:
        logger.filters = saved


class WatchdogTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.settings = Settings(
            input_dir=self.root / "input",
            log_dir=self.root / "logs",
            state_dir=self.root / "state",
            db_path=self.root / "state" / "realtime.db",
            stale_archive_dir=self.root / "stale_archive",
        )
        self.store = StateStore(settings=self.settings)
        self.watchdog = StaleRoundWatchdog(store=self.store, settings=self.settings)

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def make_round(self, round_id: str, kinds=("round_start",)) -> Path:
        """造一个停在 receiving 的 round，返回其目录。"""
        round_dir = self.settings.input_dir / round_id
        round_dir.mkdir(parents=True, exist_ok=True)
        generation, _ = self.store.begin_round_for_message(round_id, round_dir)
        for kind in kinds:
            path = round_dir / f"{kind}.json"
            path.write_text("{}", encoding="utf-8")
            self.store.record_round_input(round_id, generation, kind, path)
        return round_dir

    def backdate(self, table: str, key_column: str, key: str, hours: float) -> None:
        stamp = (datetime.now() - timedelta(hours=hours)).isoformat(timespec="seconds")
        with self.store._lock, self.store._conn:
            self.store._conn.execute(
                f"UPDATE {table} SET updated_at = ? WHERE {key_column} = ?", (stamp, key)
            )

    def backdate_round(self, round_id: str, hours: float) -> None:
        self.backdate("round_states", "round_id", round_id, hours)

    def age_dir(self, path: Path, hours: float) -> None:
        stamp = time.time() - hours * 3600
        for entry in (path, *path.iterdir()):
            os.utime(entry, (stamp, stamp))


class InputMaskTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name) / "round"
        self.dir.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write(self, name: str, payload) -> Path:
        path = self.dir / name
        if isinstance(payload, str):
            path.write_text(payload, encoding="utf-8")
        else:
            path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return path

    def test_empty_dir_has_zero_mask(self) -> None:
        self.assertEqual(input_mask(self.dir), 0)
        self.assertFalse(is_complete_on_disk(self.dir))
        self.assertEqual(len(missing_on_disk(self.dir)), len(REQUIRED_FILES) + 1)

    def test_all_required_files_plus_ir_is_complete(self) -> None:
        for name in REQUIRED_FILES:
            self.write(name, {})
        self.write("ir.json", {"ir_json": "..."})
        self.assertEqual(input_mask(self.dir), COMPLETE_MASK)
        self.assertTrue(is_complete_on_disk(self.dir))
        self.assertEqual(missing_on_disk(self.dir), [])

    def test_ir_bit_is_the_high_bit(self) -> None:
        self.assertEqual(IR_BIT, 1 << len(REQUIRED_FILES))
        self.assertEqual(COMPLETE_MASK, (1 << (len(REQUIRED_FILES) + 1)) - 1)

    def test_standalone_ir_json_without_payload_does_not_count(self) -> None:
        for name in REQUIRED_FILES:
            self.write(name, {})
        self.write("ir.json", {"ir_json": ""})
        self.assertEqual(input_mask(self.dir) & IR_BIT, 0)
        self.assertIn("ir.json", missing_on_disk(self.dir))

    def test_embedded_ir_in_round_end_counts(self) -> None:
        """旧上游把 IR 内嵌在 round_end.ir_json 里，同样算收齐。"""
        for name in REQUIRED_FILES:
            self.write(name, {})
        self.write("round_end.json", {"ir_json": "..."})
        self.assertTrue(is_complete_on_disk(self.dir))

    def test_broken_ir_json_falls_back_to_round_end(self) -> None:
        for name in REQUIRED_FILES:
            self.write(name, {})
        self.write("ir.json", "{not json")
        self.write("round_end.json", {"ir_json": "..."})
        self.assertTrue(is_complete_on_disk(self.dir))

    def test_broken_round_end_json_counts_as_no_ir(self) -> None:
        for name in REQUIRED_FILES:
            self.write(name, {})
        self.write("round_end.json", "{not json")
        self.assertEqual(input_mask(self.dir) & IR_BIT, 0)
        self.assertIn("ir.json", missing_on_disk(self.dir))

    def test_empty_ir_and_no_round_end_is_incomplete(self) -> None:
        for name in REQUIRED_FILES:
            self.write(name, {})
        self.assertFalse(is_complete_on_disk(self.dir))
        self.assertEqual(missing_on_disk(self.dir), ["ir.json"])


class PrivateHelpersTest(unittest.TestCase):
    def test_fmt_age_covers_all_units(self) -> None:
        self.assertEqual(_fmt_age(59), "59 秒")
        self.assertEqual(_fmt_age(600), "10 分钟")
        self.assertEqual(_fmt_age(7200), "2.0 小时")
        self.assertEqual(_fmt_age(3 * 86400), "3.0 天")

    def test_age_seconds_handles_missing_and_garbage(self) -> None:
        self.assertIsNone(_age_seconds(None))
        self.assertIsNone(_age_seconds(""))
        self.assertIsNone(_age_seconds("not-a-date"))
        stamp = datetime.now().isoformat(timespec="seconds")
        age = _age_seconds(stamp)
        self.assertIsNotNone(age)
        self.assertGreaterEqual(age, 0)

    def test_is_within_checks_containment(self) -> None:
        self.assertTrue(_is_within(Path("/a/b/round"), Path("/a/b")))
        self.assertFalse(_is_within(Path("/x/round"), Path("/a/b")))


class EnabledPropertyTest(unittest.TestCase):
    def _settings(self, **kwargs) -> Settings:
        return Settings(
            input_dir=Path("/tmp/lha-input"),
            log_dir=Path("/tmp/lha-logs"),
            state_dir=Path("/tmp/lha-state"),
            db_path=Path("/tmp/lha-state/realtime.db"),
            stale_archive_dir=Path("/tmp/lha-stale"),
            **kwargs,
        )

    def test_all_knobs_zero_disables_watchdog(self) -> None:
        settings = self._settings(stale_round_hours=0, stale_warn_minutes=0, message_retention_days=0)
        watchdog = StaleRoundWatchdog(store=MagicMock(), settings=settings)
        self.assertFalse(watchdog.enabled)

    def test_any_knobs_nonzero_enables_watchdog(self) -> None:
        for kwargs in (
            {"stale_round_hours": 1},
            {"stale_warn_minutes": 1},
            {"message_retention_days": 1},
        ):
            with self.subTest(kwargs=kwargs):
                settings = self._settings(**kwargs)
                watchdog = StaleRoundWatchdog(store=MagicMock(), settings=settings)
                self.assertTrue(watchdog.enabled)


class WarnTest(WatchdogTestBase):
    def test_fresh_round_is_not_warned(self) -> None:
        self.make_round("fresh")
        result = self.watchdog.scan_once()
        self.assertEqual(result, {"receiving": 1, "warned": 0, "expired": 0, "purged_messages": 0})

    def test_stale_round_warns_once_per_updated_at(self) -> None:
        self.make_round("slow")
        self.backdate_round("slow", hours=1)
        first = self.watchdog.scan_once()
        self.assertEqual(first["warned"], 1)
        second = self.watchdog.scan_once()
        self.assertEqual(second["warned"], 0)
        # 新消息刷新 updated_at 后再次超时，允许再告警一次。
        self.backdate_round("slow", hours=2)
        third = self.watchdog.scan_once()
        self.assertEqual(third["warned"], 1)

    def test_warn_log_names_missing_inputs(self) -> None:
        self.make_round("no-end", kinds=("round_start",))
        self.backdate_round("no-end", hours=1)
        with allow_service_logs("lha_realtime_watchdog"):
            with self.assertLogs("lha_realtime_watchdog", level="WARNING") as ctx:
                self.watchdog.scan_once()
        joined = "\n".join(record.getMessage() for record in ctx.records)
        self.assertIn("no-end", joined)
        self.assertIn("round_end", joined)
        self.assertIn("round_kernel", joined)
        self.assertIn("round_ir", joined)

    def test_unparseable_updated_at_is_skipped(self) -> None:
        self.make_round("broken-ts")
        with self.store._lock, self.store._conn:
            self.store._conn.execute(
                "UPDATE round_states SET updated_at = 'not-a-date' WHERE round_id = ?", ("broken-ts",)
            )
        with allow_service_logs("lha_realtime_watchdog"):
            with self.assertLogs("lha_realtime_watchdog", level="WARNING") as ctx:
                result = self.watchdog.scan_once()
        self.assertEqual(result["receiving"], 1)
        self.assertEqual(result["warned"], 0)
        self.assertTrue(any("updated_at" in record.getMessage() for record in ctx.records))


class ExpireTest(WatchdogTestBase):
    def test_stale_state_round_is_archived_and_deleted(self) -> None:
        round_dir = self.make_round("old", kinds=("round_start",))
        self.backdate_round("old", hours=25)
        result = self.watchdog.scan_once()

        self.assertEqual(result["expired"], 1)
        self.assertFalse(round_dir.exists())
        archive = self.settings.stale_archive_dir / "old"
        self.assertTrue(archive.is_dir())
        self.assertIsNone(self.store.get_round("old"))

        manifests = list(self.settings.stale_archive_dir.glob("manifest_*.json"))
        self.assertEqual(len(manifests), 1)
        payload = json.loads(manifests[0].read_text(encoding="utf-8"))
        self.assertEqual(payload["expired_count"], 1)
        entry = payload["expired"][0]
        self.assertEqual(entry["round_id"], "old")
        self.assertEqual(entry["source"], "state")
        self.assertEqual(entry["archived_to"], str(archive))
        self.assertIn("round_end", entry["missing"])
        self.assertGreaterEqual(entry["waited_seconds"], 25 * 3600 - 60)

    def test_expired_rounds_do_not_warn_again(self) -> None:
        self.make_round("gone", kinds=("round_start",))
        self.backdate_round("gone", hours=25)
        result = self.watchdog.scan_once()
        self.assertEqual(result["expired"], 1)
        self.assertEqual(result["warned"], 0)

    def test_complete_on_disk_round_is_never_expired(self) -> None:
        """磁盘收齐但状态仍停在 receiving（崩溃残留）的 round 永不归档。"""
        round_dir = self.settings.input_dir / "complete-but-receiving"
        round_dir.mkdir(parents=True)
        generation, _ = self.store.begin_round_for_message("complete-but-receiving", round_dir)
        for name in REQUIRED_FILES:
            (round_dir / name).write_text("{}", encoding="utf-8")
        (round_dir / "round_end.json").write_text(json.dumps({"ir_json": "..."}), encoding="utf-8")
        # 只登记 round_start，状态行停在 receiving。
        self.store.record_round_input(
            "complete-but-receiving", generation, "round_start", round_dir / "round_start.json"
        )
        self.backdate_round("complete-but-receiving", hours=100)

        result = self.watchdog.scan_once()
        self.assertEqual(result["expired"], 0)
        self.assertTrue(round_dir.is_dir())
        self.assertIsNotNone(self.store.get_round("complete-but-receiving"))

    def test_complete_on_disk_round_clears_stale_warn_state(self) -> None:
        round_dir = self.make_round("late-ir", kinds=("round_start",))
        self.backdate_round("late-ir", hours=1)
        self.watchdog.scan_once()
        # 磁盘侧补齐全部输入后，即使状态行没跟上也不再告警。
        for name in REQUIRED_FILES:
            (round_dir / name).write_text("{}", encoding="utf-8")
        (round_dir / "round_end.json").write_text(json.dumps({"ir_json": "..."}), encoding="utf-8")
        result = self.watchdog.scan_once()
        self.assertEqual(result["warned"], 0)

    def test_expire_aborts_if_round_settles_mid_scan(self) -> None:
        """状态行删除是原子的：恰好在此刻收齐（不再是 receiving）就放弃过期。"""
        round_dir = self.make_round("racing", kinds=("round_start",))
        self.backdate_round("racing", hours=25)
        self.store.delete_round = MagicMock(return_value=False)
        result = self.watchdog.scan_once()
        self.assertEqual(result["expired"], 0)
        self.assertTrue(round_dir.is_dir())
        self.assertIsNotNone(self.store.get_round("racing"))

    def _last_manifest(self) -> dict:
        manifests = sorted(self.settings.stale_archive_dir.glob("manifest_*.json"))
        self.assertTrue(manifests, "expected a manifest to be written")
        return json.loads(manifests[-1].read_text(encoding="utf-8"))

    def test_state_round_outside_input_clears_row_only(self) -> None:
        """round_dir 在 input/ 之外：只清状态行，磁盘目录原样保留。"""
        elsewhere = self.root / "elsewhere" / "offsite"
        elsewhere.mkdir(parents=True)
        generation, _ = self.store.begin_round_for_message("offsite", elsewhere)
        (elsewhere / "round_start.json").write_text("{}", encoding="utf-8")
        self.store.record_round_input("offsite", generation, "round_start", elsewhere / "round_start.json")
        self.backdate_round("offsite", hours=25)

        result = self.watchdog.scan_once()
        self.assertEqual(result["expired"], 1)
        self.assertTrue(elsewhere.is_dir())
        self.assertIsNone(self.store.get_round("offsite"))
        self.assertIsNone(self._last_manifest()["expired"][0]["archived_to"])

    def test_state_round_without_disk_artifacts_clears_row_only(self) -> None:
        """状态行存在但磁盘目录从未创建：过期时无需归档任何东西。"""
        ghost_dir = self.settings.input_dir / "ghost"
        self.store.begin_round_for_message("ghost", ghost_dir)
        self.backdate_round("ghost", hours=25)

        result = self.watchdog.scan_once()
        self.assertEqual(result["expired"], 1)
        self.assertFalse(ghost_dir.exists())
        self.assertIsNone(self.store.get_round("ghost"))
        self.assertIsNone(self._last_manifest()["expired"][0]["archived_to"])


class OrphanScanTest(WatchdogTestBase):
    def test_orphan_dir_past_ttl_is_archived(self) -> None:
        orphan = self.settings.input_dir / "orphan-1"
        orphan.mkdir(parents=True)
        (orphan / "round_start.json").write_text("{}", encoding="utf-8")
        self.age_dir(orphan, hours=30)

        result = self.watchdog.scan_once()
        self.assertEqual(result["expired"], 1)
        self.assertFalse(orphan.exists())
        self.assertTrue((self.settings.stale_archive_dir / "orphan-1").is_dir())

        payload = json.loads(
            next(self.settings.stale_archive_dir.glob("manifest_*.json")).read_text(encoding="utf-8")
        )
        entry = payload["expired"][0]
        self.assertEqual(entry["source"], "orphan")
        self.assertEqual(entry["round_id"], "orphan-1")
        self.assertIn("round_kernel.json", entry["missing"])
        self.assertIn("ir.json", entry["missing"])

    def test_orphan_with_state_row_is_untouched(self) -> None:
        """有状态行的目录归状态路径管，孤儿扫描不能重复处理。"""
        round_dir = self.make_round("known")  # 有 receiving 状态行，但只等了 0 小时
        self.age_dir(round_dir, hours=30)
        result = self.watchdog.scan_once()
        self.assertEqual(result["expired"], 0)
        self.assertTrue(round_dir.is_dir())

    def test_young_orphan_dir_is_kept(self) -> None:
        orphan = self.settings.input_dir / "young"
        orphan.mkdir(parents=True)
        (orphan / "round_start.json").write_text("{}", encoding="utf-8")
        result = self.watchdog.scan_once()
        self.assertEqual(result["expired"], 0)
        self.assertTrue(orphan.is_dir())

    def test_complete_orphan_dir_is_kept(self) -> None:
        orphan = self.settings.input_dir / "complete"
        orphan.mkdir(parents=True)
        for name in REQUIRED_FILES:
            (orphan / name).write_text("{}", encoding="utf-8")
        (orphan / "round_end.json").write_text(json.dumps({"ir_json": "..."}), encoding="utf-8")
        self.age_dir(orphan, hours=30 * 24)
        result = self.watchdog.scan_once()
        self.assertEqual(result["expired"], 0)
        self.assertTrue(orphan.is_dir())

    def test_dot_entries_and_files_are_ignored(self) -> None:
        (self.settings.input_dir / ".DS_Store").write_text("", encoding="utf-8")
        hidden = self.settings.input_dir / ".hidden"
        hidden.mkdir()
        result = self.watchdog.scan_once()
        self.assertEqual(result["expired"], 0)
        self.assertTrue(hidden.is_dir())

    def test_empty_orphan_dir_uses_dir_mtime(self) -> None:
        empty = self.settings.input_dir / "empty"
        empty.mkdir()
        self.age_dir(empty, hours=25)
        result = self.watchdog.scan_once()
        self.assertEqual(result["expired"], 1)
        self.assertFalse(empty.exists())

    def test_rearchived_round_gets_suffix(self) -> None:
        """同名 round 第二、三次收不齐时，归档目的地追加 __2、__3。"""
        for _ in range(3):
            orphan = self.settings.input_dir / "twice"
            orphan.mkdir(parents=True)
            (orphan / "round_start.json").write_text("{}", encoding="utf-8")
            self.age_dir(orphan, hours=25)
            result = self.watchdog.scan_once()
            self.assertEqual(result["expired"], 1)
        archive = self.settings.stale_archive_dir
        for name in ("twice", "twice__2", "twice__3"):
            self.assertTrue((archive / name).is_dir(), name)

    def test_many_expirations_log_a_summary(self) -> None:
        for index in range(21):
            orphan = self.settings.input_dir / f"bulk-{index}"
            orphan.mkdir()
            (orphan / "round_start.json").write_text("{}", encoding="utf-8")
            self.age_dir(orphan, hours=25)
        with allow_service_logs("lha_realtime_watchdog"):
            with self.assertLogs("lha_realtime_watchdog", level="WARNING") as ctx:
                result = self.watchdog.scan_once()
        self.assertEqual(result["expired"], 21)
        self.assertTrue(any("本轮共过期 21 个" in record.getMessage() for record in ctx.records))

    def test_unreadable_input_dir_is_reported(self) -> None:
        """input 路径不可列出（这里是：根本不是目录）：记录告警，本轮不做过期。"""
        blocked = self.root / "input-file"
        blocked.write_text("", encoding="utf-8")
        settings = Settings(
            input_dir=blocked,
            log_dir=self.root / "logs",
            state_dir=self.root / "state",
            db_path=self.root / "state" / "realtime.db",
            stale_archive_dir=self.root / "stale_archive",
        )
        watchdog = StaleRoundWatchdog(store=self.store, settings=settings)
        with allow_service_logs("lha_realtime_watchdog"):
            with self.assertLogs("lha_realtime_watchdog", level="WARNING") as ctx:
                result = watchdog.scan_once()
        self.assertTrue(any("无法读取 input 目录" in record.getMessage() for record in ctx.records))
        self.assertEqual(result["expired"], 0)

    def test_archive_inside_input_dir_disables_expiry_only(self) -> None:
        """归档目录在 input/ 之内会自我吞噬：过期跳过，告警照常。"""
        self.settings = Settings(
            input_dir=self.root / "input",
            log_dir=self.root / "logs",
            state_dir=self.root / "state",
            db_path=self.root / "state" / "realtime.db",
            stale_archive_dir=self.root / "input" / "stale_archive",
        )
        self.watchdog = StaleRoundWatchdog(store=self.store, settings=self.settings)
        round_dir = self.make_round("stuck", kinds=("round_start",))
        self.backdate_round("stuck", hours=100)

        with allow_service_logs("lha_realtime_watchdog"):
            with self.assertLogs("lha_realtime_watchdog", level="ERROR") as ctx:
                result = self.watchdog.scan_once()
        self.assertTrue(any("归档目录" in record.getMessage() for record in ctx.records))
        self.assertEqual(result["expired"], 0)
        self.assertEqual(result["warned"], 1)
        self.assertTrue(round_dir.is_dir())


class PurgeTest(WatchdogTestBase):
    def test_old_done_messages_are_purged(self) -> None:
        old_id = self.store.enqueue_message({"push_type": "round_start", "round_id": "r1"})
        self.store.complete_message(old_id, generation=None)
        fresh_id = self.store.enqueue_message({"push_type": "round_start", "round_id": "r2"})
        pending_id = self.store.enqueue_message({"push_type": "round_start", "round_id": "r3"})

        with self.store._lock, self.store._conn:
            self.store._conn.execute(
                "UPDATE inbox_messages SET updated_at = ? WHERE id = ?",
                ((datetime.now() - timedelta(days=40)).isoformat(timespec="seconds"), old_id),
            )

        result = self.watchdog.scan_once()
        self.assertEqual(result["purged_messages"], 1)
        with self.store._lock, self.store._conn:
            remaining = {
                row["id"]
                for row in self.store._conn.execute("SELECT id FROM inbox_messages").fetchall()
            }
        self.assertEqual(remaining, {fresh_id, pending_id})

    def test_retention_zero_disables_purge(self) -> None:
        self.settings = Settings(
            input_dir=self.root / "input",
            log_dir=self.root / "logs",
            state_dir=self.root / "state",
            db_path=self.root / "state" / "realtime.db",
            stale_archive_dir=self.root / "stale_archive",
            message_retention_days=0,
        )
        self.watchdog = StaleRoundWatchdog(store=self.store, settings=self.settings)
        message_id = self.store.enqueue_message({"push_type": "round_start", "round_id": "r1"})
        self.store.complete_message(message_id, generation=None)
        with self.store._lock, self.store._conn:
            self.store._conn.execute(
                "UPDATE inbox_messages SET updated_at = ? WHERE id = ?",
                ((datetime.now() - timedelta(days=400)).isoformat(timespec="seconds"), message_id),
            )
        result = self.watchdog.scan_once()
        self.assertEqual(result["purged_messages"], 0)


class PipelineIntegrationTest(WatchdogTestBase):
    def test_watchdog_loop_scans_until_stopped(self) -> None:
        pipeline = RealtimePipeline(store=self.store, settings=self.settings, push_reports=False)
        calls = []
        scanned = threading.Event()

        def fake_scan():
            calls.append(1)
            scanned.set()
            return {"receiving": 0, "warned": 0, "expired": 0, "purged_messages": 0}

        pipeline.watchdog.scan_once = fake_scan
        thread = threading.Thread(target=pipeline.watchdog_loop)
        thread.start()
        self.assertTrue(scanned.wait(timeout=5))
        pipeline.stop()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
