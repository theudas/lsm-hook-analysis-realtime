#!/usr/bin/env python3
"""白盒用例：报告上报链路与 mock round 识别。

覆盖 analyzer 中与外部 HTTP 接口交互的全部失败模式——连接失败、HTTP 错误码、
响应不是 JSON、响应未返回 ok=true——以及 marker 落盘与 analyze_write_and_push
的组合分支。所有用例都不发起真实网络请求。
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib import error

from lha_realtime import analyzer


def fake_response(body: str) -> MagicMock:
    response = MagicMock()
    response.read.return_value = body.encode("utf-8")
    response.__enter__ = lambda self: self
    response.__exit__ = lambda self, *args: False
    return response


class IsMockRoundTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.round_dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_empty_round_dir_is_not_mock(self) -> None:
        """目录里没有任何元数据文件时不判为 mock。"""
        self.assertFalse(analyzer.is_mock_round(self.round_dir))

    def test_is_mock_true_in_round_end(self) -> None:
        (self.round_dir / "round_end.json").write_text(json.dumps({"is_mock": True}), encoding="utf-8")
        self.assertTrue(analyzer.is_mock_round(self.round_dir))

    def test_is_mock_true_only_in_ir_is_still_detected(self) -> None:
        # round_end / round_kernel 都不带标记时，仍要检查最后一个来源 ir.json。
        (self.round_dir / "round_end.json").write_text(json.dumps({"is_mock": False}), encoding="utf-8")
        (self.round_dir / "ir.json").write_text(json.dumps({"is_mock": True}), encoding="utf-8")
        self.assertTrue(analyzer.is_mock_round(self.round_dir))

    def test_corrupt_metadata_file_is_skipped_not_fatal(self) -> None:
        (self.round_dir / "round_end.json").write_text("{broken", encoding="utf-8")
        (self.round_dir / "round_kernel.json").write_text(json.dumps({"is_mock": True}), encoding="utf-8")
        self.assertTrue(analyzer.is_mock_round(self.round_dir))

    def test_non_boolean_true_is_not_treated_as_mock(self) -> None:
        # 显式用 is True 比较：字符串 "true" 不算 mock。
        (self.round_dir / "round_end.json").write_text(json.dumps({"is_mock": "true"}), encoding="utf-8")
        self.assertFalse(analyzer.is_mock_round(self.round_dir))


class PushKernelReportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.round_dir = Path(self.tmp.name)
        self.report = self.round_dir / "analysis_report.md"
        self.report.write_text("# report", encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_successful_push_returns_parsed_response(self) -> None:
        """上报成功返回解析后的响应，请求体含 round_id 与报告绝对路径。"""
        with patch.object(analyzer.request, "urlopen", return_value=fake_response('{"ok": true, "id": 7}')) as urlopen:
            result = analyzer.push_kernel_report("r1", self.report)

        self.assertEqual(result, {"ok": True, "id": 7})
        sent = urlopen.call_args[0][0]
        self.assertEqual(sent.method, "POST")
        self.assertEqual(sent.headers["Content-type"], "application/json")
        payload = json.loads(sent.data.decode("utf-8"))
        self.assertEqual(payload["round_id"], "r1")
        # 上报的必须是绝对路径，后端据此读取报告。
        self.assertTrue(Path(payload["judge_result_kernel_md_path"]).is_absolute())

    def test_http_error_is_wrapped_as_runtime_error(self) -> None:
        """HTTP 错误码被包装为带状态码的 RuntimeError。"""
        http_error = error.HTTPError(
            "http://example/api", 500, "Server Error", {}, io.BytesIO(b'{"ok": false}')
        )
        self.addCleanup(http_error.close)
        with patch.object(analyzer.request, "urlopen", side_effect=http_error):
            with self.assertRaises(RuntimeError) as ctx:
                analyzer.push_kernel_report("r1", self.report)
        self.assertIn("HTTP 500", str(ctx.exception))

    def test_url_error_is_wrapped_as_runtime_error(self) -> None:
        """连接失败（URLError）被包装为 RuntimeError。"""
        with patch.object(analyzer.request, "urlopen", side_effect=error.URLError("connection refused")):
            with self.assertRaises(RuntimeError) as ctx:
                analyzer.push_kernel_report("r1", self.report)
        self.assertIn("上报失败", str(ctx.exception))

    def test_non_json_response_is_rejected(self) -> None:
        """响应不是 JSON 时判为上报失败。"""
        with patch.object(analyzer.request, "urlopen", return_value=fake_response("<html>502</html>")):
            with self.assertRaises(RuntimeError) as ctx:
                analyzer.push_kernel_report("r1", self.report)
        self.assertIn("响应不是 JSON", str(ctx.exception))

    def test_response_without_ok_true_is_rejected(self) -> None:
        """响应缺少 ok=true（含字符串 'true'）时判为上报失败。"""
        for body in ('{"ok": false}', '{"code": 0}', '{"ok": "true"}'):
            with self.subTest(body=body):
                with patch.object(analyzer.request, "urlopen", return_value=fake_response(body)):
                    with self.assertRaises(RuntimeError) as ctx:
                        analyzer.push_kernel_report("r1", self.report)
                self.assertIn("ok=true", str(ctx.exception))

    def test_push_of_a_missing_report_file_still_attempts_the_call(self) -> None:
        # 报告文件不存在只是日志里的一个字段，不应短路上报。
        with patch.object(analyzer.request, "urlopen", return_value=fake_response('{"ok": true}')) as urlopen:
            analyzer.push_kernel_report("r1", self.round_dir / "gone.md")
        urlopen.assert_called_once()


class MarkAndPushTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.round_dir = Path(self.tmp.name)
        self.report = self.round_dir / "analysis_report.md"
        self.report.write_text("# report", encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_marker_records_endpoint_and_response(self) -> None:
        """上报 marker 记录 round_id、接口地址与响应内容。"""
        analyzer.mark_report_pushed(self.round_dir, "r1", self.report, {"ok": True})
        marker = json.loads((self.round_dir / analyzer.PUSH_MARKER_NAME).read_text(encoding="utf-8"))
        self.assertEqual(marker["round_id"], "r1")
        self.assertEqual(marker["response"], {"ok": True})
        self.assertTrue(marker["endpoint"])

    def test_push_and_mark_writes_marker_on_success(self) -> None:
        """上报成功后写入 marker 文件。"""
        with patch.object(analyzer, "push_kernel_report", return_value={"ok": True}):
            self.assertTrue(analyzer.push_and_mark_report(self.round_dir, "r1", self.report))
        self.assertTrue((self.round_dir / analyzer.PUSH_MARKER_NAME).is_file())

    def test_push_and_mark_returns_false_and_skips_marker_on_failure(self) -> None:
        """上报失败时返回 False 且不写 marker，避免误标已上报。"""
        with patch.object(analyzer, "push_kernel_report", side_effect=RuntimeError("boom")):
            self.assertFalse(analyzer.push_and_mark_report(self.round_dir, "r1", self.report))
        self.assertFalse((self.round_dir / analyzer.PUSH_MARKER_NAME).exists())


class AnalyzeWriteAndPushTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.round_dir = Path(self.tmp.name) / "awp"
        self.round_dir.mkdir()
        self.write_round()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write_round(self, is_mock: bool = False) -> None:
        (self.round_dir / "round_start.json").write_text(
            json.dumps({"round_id": "awp", "session_key": "s", "time_start": "t0"}), encoding="utf-8"
        )
        (self.round_dir / "round_end.json").write_text(
            json.dumps({"round_id": "awp", "action_json": "[]", "time_end": "t1", "is_mock": is_mock}),
            encoding="utf-8",
        )
        (self.round_dir / "round_kernel.json").write_text(
            json.dumps({"round_id": "awp", "kernel_resource_facts": json.dumps({"resource_facts": []})}),
            encoding="utf-8",
        )
        (self.round_dir / "ir.json").write_text(
            json.dumps({"round_id": "awp", "ir_json": json.dumps({"policies": []})}), encoding="utf-8"
        )
        (self.round_dir / "kernel_lsm_hook_result.jsonl").write_text("", encoding="utf-8")
        (self.round_dir / "kernel_syscall_seq.jsonl").write_text("", encoding="utf-8")

    def test_push_disabled_only_writes_outputs(self) -> None:
        """push=False 时只产出报告，不调用上报。"""
        with patch.object(analyzer, "push_and_mark_report") as push:
            result, report_path = analyzer.analyze_write_and_push(self.round_dir, push=False)
        push.assert_not_called()
        self.assertEqual(result["round_id"], "awp")
        self.assertTrue(report_path.is_file())

    def test_mock_round_is_never_pushed(self) -> None:
        """mock round 在该入口一律不上报。"""
        self.write_round(is_mock=True)
        with patch.object(analyzer, "push_and_mark_report") as push:
            analyzer.analyze_write_and_push(self.round_dir, push=True)
        push.assert_not_called()

    def test_successful_push_path(self) -> None:
        """正常 round 走完分析→写报告→上报全链路。"""
        with patch.object(analyzer, "push_and_mark_report", return_value=True) as push:
            analyzer.analyze_write_and_push(self.round_dir, push=True)
        push.assert_called_once()

    def test_failed_push_raises(self) -> None:
        """上报失败时抛出异常，交由上层重试。"""
        with patch.object(analyzer, "push_and_mark_report", return_value=False):
            with self.assertRaises(RuntimeError):
                analyzer.analyze_write_and_push(self.round_dir, push=True)


class AnalyzeRoundMetadataTest(unittest.TestCase):
    """analyze_round 里把命中的敏感规则元数据写进 violation 记录的分支。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.round_dir = Path(self.tmp.name) / "meta"
        self.round_dir.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_sensitive_violation_carries_rule_metadata_and_counts(self) -> None:
        """敏感越权记录带规则 id、等级、ATT&CK、理由与依据，且两判据一致。"""
        (self.round_dir / "round_start.json").write_text(
            json.dumps({"round_id": "meta", "session_key": "s", "time_start": "t0"}), encoding="utf-8"
        )
        (self.round_dir / "round_end.json").write_text(
            json.dumps({"action_json": "[]", "time_end": "t1", "overall_score": 0.9}), encoding="utf-8"
        )
        (self.round_dir / "round_kernel.json").write_text(json.dumps({"round_id": "meta"}), encoding="utf-8")
        (self.round_dir / "ir.json").write_text(
            json.dumps({"ir_json": json.dumps({"policies": []})}), encoding="utf-8"
        )
        (self.round_dir / "kernel_lsm_hook_result.jsonl").write_text(
            json.dumps(
                {
                    "event_id": 1,
                    "hook_name": "file_open",
                    "result": "allow",
                    "return_value": 0,
                    "pid": 10,
                    "tid": 10,
                    "timestamp_mono_ns": 1,
                    "path": "/root/.ssh/id_rsa",
                    "category": "file",
                    "resource_role": "privacy_resource",
                    "tool_name": "exec",
                    "args": {"flags": "O_RDONLY"},
                }
            )
            + "\n",
            encoding="utf-8",
        )
        (self.round_dir / "kernel_syscall_seq.jsonl").write_text("", encoding="utf-8")

        result = analyzer.analyze_round(self.round_dir)

        violation = result["violations"][0]
        self.assertEqual(violation["sensitive_rule"], "private_keys")
        self.assertEqual(violation["sensitive_severity"], "critical")
        self.assertIn("T1552.004", violation["sensitive_attck"])
        self.assertTrue(violation["sensitive_reason"])
        self.assertTrue(violation["sensitive_basis"])
        # 两个判据都命中：ir_json 未放行，且内核标了 privacy_resource。
        self.assertTrue(violation["by_ir_json"])
        self.assertTrue(violation["by_resource_role"])
        self.assertTrue(violation["judges_agree"])
        self.assertEqual(result["counts"]["judge_mismatch"], 0)
        # round_id 缺失于 round_end 时回落到 round_start。
        self.assertEqual(result["round_id"], "meta")
        self.assertEqual(result["tool_name"], "exec")
        self.assertTrue(result["is_anomaly"])

    def test_round_id_falls_back_to_directory_name(self) -> None:
        """round_end/round_start 都没有 round_id 时回落到目录名。"""
        for name in ("round_start.json", "round_end.json", "round_kernel.json"):
            (self.round_dir / name).write_text("{}", encoding="utf-8")
        result = analyzer.analyze_round(self.round_dir)
        self.assertEqual(result["round_id"], "meta")
        self.assertIsNone(result["tool_name"])
        self.assertFalse(result["is_anomaly"])


if __name__ == "__main__":
    unittest.main()
