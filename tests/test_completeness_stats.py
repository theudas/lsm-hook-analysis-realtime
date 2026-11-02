#!/usr/bin/env python3
"""白盒用例：采集完整度看板脚本的扫描、分桶与页面渲染。

completeness_stats.py 是脚本不是包，这里用 importlib 按路径加载；它自身没有
副作用（只往 sys.path 塞项目根目录），因此可以安全 import。
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import re
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from pathlib import Path

from lha_realtime.watchdog import COMPLETE_MASK

_SPEC = importlib.util.spec_from_file_location(
    "completeness_stats", Path(__file__).resolve().parent.parent / "scripts" / "completeness_stats.py"
)
cs = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(cs)

T0 = 1_700_000_000  # 2023-11-14 22:13:20 UTC，一个整点无关的中性时间戳。


def write_round(input_dir: Path, round_id: str, files: list[str], mtime: float, ir_in_end: bool = False) -> Path:
    round_dir = input_dir / round_id
    round_dir.mkdir(parents=True)
    for name in files:
        path = round_dir / name
        if name == "round_end.json" and ir_in_end:
            path.write_text(json.dumps({"ir_json": "..."}), encoding="utf-8")
        else:
            path.write_text("{}", encoding="utf-8")
        os.utime(path, (mtime, mtime))
    os.utime(round_dir, (mtime, mtime))
    return round_dir


class ScanRoundsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.input_dir = Path(self.tmp.name) / "input"
        self.input_dir.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_scan_classifies_complete_and_incomplete_rounds(self) -> None:
        write_round(self.input_dir, "ok", [
            "round_start.json", "round_end.json", "round_kernel.json",
            "kernel_syscall_seq.jsonl", "kernel_lsm_hook_result.jsonl",
        ], T0, ir_in_end=True)
        write_round(self.input_dir, "start-only", ["round_start.json"], T0)

        records = {r["id"]: r for r in cs.scan_rounds(self.input_dir)}
        self.assertEqual(records["ok"]["m"], COMPLETE_MASK)
        self.assertEqual(records["start-only"]["m"], 1)

    def test_scan_ignores_dot_dirs_and_files(self) -> None:
        (self.input_dir / ".DS_Store").write_text("", encoding="utf-8")
        (self.input_dir / ".hidden").mkdir()
        write_round(self.input_dir, "real", ["round_start.json"], T0)
        self.assertEqual([r["id"] for r in cs.scan_rounds(self.input_dir)], ["real"])

    def test_scan_missing_input_dir_returns_empty(self) -> None:
        self.assertEqual(cs.scan_rounds(self.input_dir / "nope"), [])

    def test_round_time_prefers_round_start_mtime(self) -> None:
        round_dir = write_round(self.input_dir, "r", [
            "round_start.json", "round_end.json", "ir.json",
        ], T0)
        os.utime(round_dir / "round_end.json", (T0 - 5000, T0 - 5000))
        self.assertEqual(cs.round_time(round_dir), T0)

    def test_round_time_falls_back_to_earliest_arrival_file(self) -> None:
        round_dir = write_round(self.input_dir, "r", ["round_end.json", "ir.json"], T0)
        os.utime(round_dir / "ir.json", (T0 - 3000, T0 - 3000))
        self.assertEqual(cs.round_time(round_dir), T0 - 3000)

    def test_round_time_uses_kernel_files_then_dir_mtime(self) -> None:
        round_dir = write_round(self.input_dir, "r", ["kernel_syscall_seq.jsonl"], T0)
        self.assertEqual(cs.round_time(round_dir), T0)
        empty = self.input_dir / "empty"
        empty.mkdir()
        os.utime(empty, (T0 + 99, T0 + 99))
        self.assertEqual(cs.round_time(empty), T0 + 99)


class MissingFromMaskTest(unittest.TestCase):
    def test_full_mask_has_no_missing(self) -> None:
        self.assertEqual(cs.missing_from_mask(COMPLETE_MASK), [])

    def test_missing_inputs_are_named(self) -> None:
        self.assertEqual(cs.missing_from_mask(0), ["round_start", "round_end", "round_kernel", "ir"])

    def test_missing_kernel_payload_is_grouped(self) -> None:
        mask = COMPLETE_MASK & ~(1 << 3)  # 缺 kernel_syscall_seq.jsonl
        self.assertEqual(cs.missing_from_mask(mask), ["内核数据文件"])
        both = COMPLETE_MASK & ~((1 << 3) | (1 << 4))
        self.assertEqual(cs.missing_from_mask(both), ["内核数据文件"])

    def test_missing_start_and_ir(self) -> None:
        mask = COMPLETE_MASK & ~((1 << 0) | (1 << 5))
        self.assertEqual(cs.missing_from_mask(mask), ["round_start", "ir"])


class BucketTest(unittest.TestCase):
    def test_auto_bucket_seconds_by_span(self) -> None:
        day = 86400
        self.assertEqual(cs.auto_bucket_seconds(2 * day), 3600)
        self.assertEqual(cs.auto_bucket_seconds(2 * day + 1), day)
        self.assertEqual(cs.auto_bucket_seconds(180 * day), day)
        self.assertEqual(cs.auto_bucket_seconds(180 * day + 1), 7 * day)

    def test_bucketize_keeps_empty_buckets(self) -> None:
        records = [
            {"id": "a", "t": T0, "m": COMPLETE_MASK},
            {"id": "b", "t": T0 + 5 * 3600, "m": 1},
        ]
        buckets, seconds = cs.bucketize(records, T0, T0 + 5 * 3600, 3600)
        self.assertEqual(seconds, 3600)
        self.assertEqual(len(buckets), 6)
        self.assertEqual(buckets[0], {"start": buckets[0]["start"], "ok": 1, "bad": 0})
        self.assertEqual(buckets[5]["bad"], 1)
        for middle in buckets[1:5]:
            self.assertEqual((middle["ok"], middle["bad"]), (0, 0))

    def test_bucketize_counts_ok_and_bad(self) -> None:
        records = [
            {"id": "a", "t": T0, "m": COMPLETE_MASK},
            {"id": "b", "t": T0 + 60, "m": COMPLETE_MASK},
            {"id": "c", "t": T0 + 120, "m": 1},
        ]
        buckets, _ = cs.bucketize(records, T0, T0 + 300, 3600)
        self.assertEqual((buckets[0]["ok"], buckets[0]["bad"]), (2, 1))

    def test_bucketize_excludes_out_of_range_records(self) -> None:
        records = [
            {"id": "before", "t": T0 - 10, "m": COMPLETE_MASK},
            {"id": "in", "t": T0, "m": COMPLETE_MASK},
            {"id": "after", "t": T0 + 7200, "m": COMPLETE_MASK},
        ]
        buckets, _ = cs.bucketize(records, T0, T0 + 3600, 3600)
        self.assertEqual(len(buckets), 2)
        self.assertEqual(buckets[0]["ok"], 1)

    def test_bucketize_coarsens_when_over_limit(self) -> None:
        records = [{"id": "a", "t": T0, "m": COMPLETE_MASK}]
        buckets, seconds = cs.bucketize(records, T0, T0 + 300 * 3600, 3600)
        self.assertLessEqual(len(buckets), cs.MAX_BUCKETS)
        self.assertGreater(seconds, 3600)

    def test_bucket_label_by_granularity(self) -> None:
        # 标签用本地时间（与运维看板习惯一致），分钟截断到整点。
        self.assertEqual(cs.bucket_label(T0, 3600), datetime.fromtimestamp(T0).strftime("%m-%d %H:00"))
        self.assertEqual(cs.bucket_label(T0, 86400), datetime.fromtimestamp(T0).strftime("%Y-%m-%d"))

    def test_nice_ceiling_rounds_to_step_units(self) -> None:
        self.assertEqual(cs.nice_ceiling(0), 1.0)
        self.assertEqual(cs.nice_ceiling(3), 5.0)
        self.assertEqual(cs.nice_ceiling(8), 10.0)
        self.assertEqual(cs.nice_ceiling(100), 100.0)

    def test_pct_and_compact_formatting(self) -> None:
        self.assertEqual(cs.pct(0), "0%")
        self.assertEqual(cs.pct(0.05), "5.0%")
        self.assertEqual(cs.pct(0.5), "50%")
        self.assertEqual(cs.compact(999), "999")
        self.assertEqual(cs.compact(1500), "1.5K")


class BuildTest(unittest.TestCase):
    def _records(self) -> list[dict]:
        return [
            {"id": "ok-1", "t": T0, "m": COMPLETE_MASK},
            {"id": "ok-2", "t": T0 + 100, "m": COMPLETE_MASK},
            {"id": "bad-old", "t": T0 + 200, "m": 1},
            {"id": "bad-new", "t": T0 + 400, "m": 2},
        ]

    def test_build_computes_totals_ratio_and_patterns(self) -> None:
        data = cs.build(self._records(), T0, T0 + 1000)
        self.assertEqual(data["total"], 4)
        self.assertEqual(data["ok"], 2)
        self.assertEqual(data["bad"], 2)
        self.assertEqual(data["ratio"], 0.5)
        patterns = data["patterns"]
        self.assertEqual(
            [p["missing"] for p in patterns],
            [["round_end", "round_kernel", "ir"], ["round_start", "round_kernel", "ir"]],
        )
        self.assertEqual(patterns[0]["ids"], ["bad-old"])

    def test_build_respects_time_range(self) -> None:
        data = cs.build(self._records(), T0, T0 + 150)
        self.assertEqual(data["total"], 2)
        self.assertEqual(data["ok"], 2)

    def test_examples_are_newest_first_and_limited(self) -> None:
        data = cs.build(self._records(), T0, T0 + 1000, examples_limit=1)
        self.assertEqual([r["id"] for r in data["examples"]], ["bad-new"])


class RenderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.input_dir = self.root / "input"
        self.input_dir.mkdir()
        write_round(self.input_dir, "complete-round", [
            "round_start.json", "round_end.json", "round_kernel.json",
            "kernel_syscall_seq.jsonl", "kernel_lsm_hook_result.jsonl",
        ], T0, ir_in_end=True)
        write_round(self.input_dir, "half-round", ["round_start.json"], T0 + 3600)
        self.records = cs.scan_rounds(self.input_dir)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_render_writes_self_contained_page(self) -> None:
        out = self.root / "reports" / "completeness.html"
        data = cs.render(self.records, self.input_dir, out, examples_limit=10)

        self.assertEqual((data["total"], data["ok"], data["bad"]), (2, 1, 1))
        page = out.read_text(encoding="utf-8")
        self.assertIn('"rounds":[["complete-round"', page)
        self.assertIn("half-round", page)
        self.assertNotIn('id="refresh"', page)
        # 纯静态产物：页面里没有任何刷新按钮或 fetch 调用，不依赖本地服务。
        self.assertNotIn("fetch(", page)
        self.assertNotIn("/*__DATA__*/null", page)
        # 页面不携带部署机器的绝对路径：语料目录只允许以相对路径出现
        # （前面是 "." 的属于 ../../.. 形式的相对路径，不算泄漏）。
        for absolute in (str(self.input_dir.resolve()), str(self.root.resolve())):
            leak = re.search(r"(?:^|(?<=[\"'> (:]))" + re.escape(absolute), page)
            self.assertIsNone(leak, f"absolute path leaked: {absolute}")

    def test_chart_svg_clamps_tiny_segment_to_nonnegative_height(self) -> None:
        """段高不足 2px 表面缝时钳到 0，不产生负 height（负值会被浏览器丢弃并报错）。"""
        svg = cs.chart_svg([{"start": T0, "ok": 1, "bad": 1000}], 3600)
        self.assertNotIn('height="-', svg)
        self.assertIn('class="bar-ok"', svg)

    def test_generate_returns_zero_and_writes_report(self) -> None:
        out = self.root / "reports" / "completeness.html"
        args = type("Args", (), {"input_dir": self.input_dir, "out": out, "examples": 5})()
        stderr, stdout = io.StringIO(), io.StringIO()
        with redirect_stderr(stderr), redirect_stdout(stdout):
            code = cs.generate(args)
        self.assertEqual(code, 0)
        self.assertTrue(out.is_file())
        self.assertIn("rounds=2 ok=1 bad=1 ratio=50%", stdout.getvalue())

    def test_generate_exits_one_on_empty_input(self) -> None:
        empty = self.root / "empty-input"
        empty.mkdir()
        out = self.root / "reports" / "completeness.html"
        args = type("Args", (), {"input_dir": empty, "out": out, "examples": 5})()
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = cs.generate(args)
        self.assertEqual(code, 1)
        self.assertIn("没有可统计的 round", stderr.getvalue())
        self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
