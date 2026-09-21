#!/usr/bin/env python3
"""Tests for realtime LSM pipeline behavior."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lha_realtime.analyzer import analyze_round, classify, matches_file_identifier, matching_sensitive_rule
from lha_realtime.config import Settings
from lha_realtime.pipeline import RealtimePipeline
from lha_realtime.rules import SENSITIVE_RULES
from lha_realtime.state import StateStore


class FileIdentifierMatcherTest(unittest.TestCase):
    def test_exact_path_only_matches_same_path(self) -> None:
        """无通配符的 IR 标识只匹配完全相同的路径。"""
        self.assertTrue(matches_file_identifier("/tmp/a.txt", "/tmp/a.txt"))
        self.assertFalse(matches_file_identifier("/tmp/b.txt", "/tmp/a.txt"))

    def test_single_star_does_not_cross_path_segments(self) -> None:
        """单个 * 只在一层路径段内匹配，不跨越 /。"""
        self.assertTrue(matches_file_identifier("/workspace/a.txt", "/workspace/*"))
        self.assertFalse(matches_file_identifier("/workspace/a/b.txt", "/workspace/*"))

    def test_double_star_crosses_path_segments(self) -> None:
        """** 可跨越任意层目录匹配。"""
        self.assertTrue(matches_file_identifier("/workspace/a.py", "/workspace/**/*.py"))
        self.assertTrue(matches_file_identifier("/workspace/a/b.py", "/workspace/**/*.py"))

    def test_file_identifier_star_is_path_glob(self) -> None:
        """IR 文件标识里的 * 按路径 glob 解释，而非正则。"""
        self.assertTrue(matches_file_identifier("/tmp/anything", "/tmp/*"))
        self.assertFalse(matches_file_identifier("/tmp/nested/anything", "/tmp/*"))

    def test_regex_uses_fullmatch(self) -> None:
        """正则型标识用 fullmatch，不接受部分匹配。"""
        pattern = r"^/tmp/[a-zA-Z0-9]+\.txt$"
        self.assertTrue(matches_file_identifier("/tmp/abc123.txt", pattern))
        self.assertFalse(matches_file_identifier("/tmp/a/b.txt", pattern))
        self.assertFalse(matches_file_identifier("/tmp/abc123.txt.bak", pattern))

    def test_invalid_regex_does_not_allow(self) -> None:
        """非法正则标识不放行，避免异常造成漏判。"""
        self.assertFalse(matches_file_identifier("/tmp/a.txt", r"(/tmp/[a-z]+\.txt"))


class AnalyzerActionMismatchTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.round_dir = Path(self.tmp.name) / "round"
        self.round_dir.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write_round(self, *, ir: dict, lsm: list[dict], syscalls: list[dict] | None = None) -> None:
        (self.round_dir / "round_start.json").write_text(
            json.dumps(
                {
                    "push_type": "round_start",
                    "round_id": "round",
                    "time_start": "2026-06-16 10:00:00+0800",
                    "session_key": "agent:main:main",
                }
            ),
            encoding="utf-8",
        )
        (self.round_dir / "round_end.json").write_text(
            json.dumps(
                {
                    "push_type": "round_end",
                    "round_id": "round",
                    "time_end": "2026-06-16 10:00:01+0800",
                    "action_json": "[]",
                }
            ),
            encoding="utf-8",
        )
        (self.round_dir / "round_kernel.json").write_text(
            json.dumps(
                {
                    "push_type": "round_kernel",
                    "round_id": "round",
                    "kernel_resource_facts": json.dumps({"resource_facts": []}),
                }
            ),
            encoding="utf-8",
        )
        (self.round_dir / "ir.json").write_text(
            json.dumps({"push_type": "round_ir_ready", "round_id": "round", "ir_json": json.dumps(ir)}),
            encoding="utf-8",
        )
        (self.round_dir / "kernel_lsm_hook_result.jsonl").write_text(
            "\n".join(json.dumps(row, ensure_ascii=False) for row in lsm) + "\n",
            encoding="utf-8",
        )
        syscall_rows = syscalls or []
        (self.round_dir / "kernel_syscall_seq.jsonl").write_text(
            "\n".join(json.dumps(row, ensure_ascii=False) for row in syscall_rows),
            encoding="utf-8",
        )

    def test_file_action_mismatch_marks_round_anomalous(self) -> None:
        """IR 只允许 read 而实际观测到 write/create 时判为异常。"""
        ir = {
            "policies": [
                {
                    "effect": "allow",
                    "objects": [
                        {"type": "file", "identifier": "/tmp/action.txt", "actions": ["read"]},
                    ],
                }
            ]
        }
        self.write_round(
            ir=ir,
            lsm=[
                {
                    "event_id": "file-write",
                    "hook_name": "file_open",
                    "result": "allow",
                    "return_value": 0,
                    "pid": 1000,
                    "tid": 1000,
                    "timestamp_mono_ns": 1,
                    "path": "/tmp/action.txt",
                    "category": "other",
                    "resource_role": "declared_resource",
                    "tool_call_id": "call-1",
                    "tool_name": "safe_file_reader__read_text",
                    "related_event_id": None,
                    "args": {"flags": "O_WRONLY|O_CREAT"},
                }
            ],
        )

        result = analyze_round(self.round_dir)

        self.assertTrue(result["is_anomaly"])
        mismatch = next(item for item in result["anomaly_types"] if item["type"] == "文件访问出现未授权动作")
        self.assertEqual(mismatch["items"][0]["allowed"], ["read"])
        self.assertEqual(mismatch["items"][0]["extra"], ["create", "write"])

    def test_inode_unlink_is_judged_as_delete_action(self) -> None:
        # inode_unlink 是删除文件的 LSM hook：IR 只允许 read 时，删除应作为未授权的 delete 动作被判定。
        ir = {
            "policies": [
                {
                    "effect": "allow",
                    "objects": [
                        {"type": "file", "identifier": "/workspace/test_a.txt", "actions": ["read"]},
                    ],
                }
            ]
        }
        self.write_round(
            ir=ir,
            lsm=[
                {
                    "event_id": "file-delete",
                    "hook_name": "inode_unlink",
                    "result": "allow",
                    "return_value": 0,
                    "pid": 1000,
                    "tid": 1000,
                    "timestamp_mono_ns": 1,
                    "path": "/workspace/test_a.txt",
                    "category": "workspace",
                    "resource_role": "declared_resource",
                    "tool_call_id": "call-1",
                    "tool_name": "exec",
                    "related_event_id": None,
                    "args": {"pathname": "/workspace/test_a.txt", "inode": 123},
                }
            ],
        )

        result = analyze_round(self.round_dir)

        self.assertTrue(result["is_anomaly"])
        mismatch = next(item for item in result["anomaly_types"] if item["type"] == "文件访问出现未授权动作")
        self.assertEqual(mismatch["items"][0]["allowed"], ["read"])
        self.assertEqual(mismatch["items"][0]["extra"], ["delete"])

    def test_lsm_only_network_action_mismatch_marks_round_anomalous(self) -> None:
        """仅凭 LSM socket hook（无对应 syscall）也能判出未授权网络动作。"""
        ir = {
            "policies": [
                {
                    "effect": "allow",
                    "objects": [
                        {"type": "network", "identifier": "*", "actions": ["send"]},
                    ],
                }
            ]
        }
        self.write_round(
            ir=ir,
            lsm=[
                {
                    "event_id": "net-recv",
                    "hook_name": "socket_recvmsg",
                    "result": "allow",
                    "return_value": 0,
                    "pid": 1000,
                    "tid": 1000,
                    "timestamp_mono_ns": 1,
                    "category": "unknown",
                    "fd": 3,
                    "tool_call_id": "call-1",
                    "tool_name": "safe_file_reader__read_text",
                    "args": {"fd": 3},
                }
            ],
        )

        result = analyze_round(self.round_dir)

        self.assertTrue(result["is_anomaly"])
        self.assertEqual(result["network_observed"], ["receive"])
        mismatch = next(item for item in result["anomaly_types"] if item["type"] == "网络访问出现未授权动作")
        self.assertEqual(mismatch["allowed"], ["send"])
        self.assertEqual(mismatch["extra"], ["receive"])

    def test_localhost_15100_only_network_is_not_anomalous(self) -> None:
        # 工具去平台拉取线上配置：连接仅落在 127.0.0.1:15100 / ::1:15100，整轮网络按正常处理。
        ir = {"policies": []}
        self.write_round(
            ir=ir,
            lsm=[
                {
                    "event_id": "net-send",
                    "hook_name": "socket_sendmsg",
                    "result": "allow",
                    "return_value": 0,
                    "pid": 1000,
                    "tid": 1000,
                    "timestamp_mono_ns": 5,
                    "category": "unknown",
                    "fd": 0,
                    "args": {"decision_scope": "collector_program", "fd": 0},
                },
                {
                    "event_id": "net-recv",
                    "hook_name": "socket_recvmsg",
                    "result": "allow",
                    "return_value": 0,
                    "pid": 1000,
                    "tid": 1000,
                    "timestamp_mono_ns": 6,
                    "category": "unknown",
                    "fd": 0,
                    "args": {"decision_scope": "collector_program", "fd": 0},
                },
            ],
            syscalls=[
                {
                    "action": "connect",
                    "event_id": "sc-connect-v4",
                    "pid": 1000,
                    "fd": 3,
                    "timestamp_mono_ns": 1,
                    "args": {"remote_ip": "127.0.0.1", "remote_port": "15100", "sockfd": 3},
                },
                {
                    "action": "connect",
                    "event_id": "sc-connect-v6",
                    "pid": 1000,
                    "fd": 3,
                    "timestamp_mono_ns": 2,
                    "args": {"remote_ip": "::1", "remote_port": "15100", "sockfd": 3},
                },
                {
                    "action": "sendto",
                    "event_id": "sc-send",
                    "pid": 1000,
                    "fd": 3,
                    "timestamp_mono_ns": 3,
                    "args": {"fd": 3},
                },
                {
                    "action": "recvmsg",
                    "event_id": "sc-recv",
                    "pid": 1000,
                    "fd": 3,
                    "timestamp_mono_ns": 4,
                    "args": {"fd": 3},
                },
            ],
        )

        result = analyze_round(self.round_dir)

        self.assertTrue(result["network_suppressed"])
        self.assertEqual(result["network_observed"], [])
        self.assertEqual(result["network_endpoints"], [])
        self.assertFalse(
            any(item["type"] == "网络访问出现未授权动作" for item in result["anomaly_types"])
        )
        self.assertFalse(result["is_anomaly"])

    def test_mixed_localhost_and_external_endpoint_still_flags_external(self) -> None:
        # 同时出现 127.0.0.1:15100（忽略）与 8.152.192.7:443（恶意）：仍判异常，只保留外部端点。
        ir = {"policies": []}
        self.write_round(
            ir=ir,
            lsm=[
                {
                    "event_id": "net-send",
                    "hook_name": "socket_sendmsg",
                    "result": "allow",
                    "return_value": 0,
                    "pid": 1000,
                    "tid": 1000,
                    "timestamp_mono_ns": 5,
                    "category": "unknown",
                    "fd": 0,
                    "args": {"fd": 0},
                }
            ],
            syscalls=[
                {
                    "action": "connect",
                    "event_id": "sc-connect-local",
                    "pid": 1000,
                    "fd": 3,
                    "timestamp_mono_ns": 1,
                    "args": {"remote_ip": "127.0.0.1", "remote_port": "15100", "sockfd": 3},
                },
                {
                    "action": "connect",
                    "event_id": "sc-connect-ext",
                    "pid": 1000,
                    "fd": 4,
                    "timestamp_mono_ns": 2,
                    "args": {"remote_ip": "8.152.192.7", "remote_port": "443", "sockfd": 4},
                },
                {
                    "action": "sendto",
                    "event_id": "sc-send-ext",
                    "pid": 1000,
                    "fd": 4,
                    "timestamp_mono_ns": 3,
                    "args": {"fd": 4},
                },
            ],
        )

        result = analyze_round(self.round_dir)

        self.assertFalse(result["network_suppressed"])
        self.assertEqual(result["network_endpoints"], ["8.152.192.7:443"])
        self.assertIn("127.0.0.1:15100", result["network_ignored_endpoints"])
        self.assertTrue(result["is_anomaly"])
        mismatch = next(
            item for item in result["anomaly_types"] if item["type"] == "网络访问出现未授权动作"
        )
        self.assertEqual(mismatch["endpoints"], ["8.152.192.7:443"])

    def test_d04795d0_lsm_socket_hooks_mark_round_anomalous(self) -> None:
        """真实 round d04795d0 回放：socket hook 应判出 send/receive 越权。"""
        fixture = Path(__file__).resolve().parents[1] / "input" / "d04795d0"
        if not fixture.is_dir():
            self.skipTest("d04795d0 fixture is not present")

        result = analyze_round(fixture)

        self.assertTrue(result["is_anomaly"])
        self.assertEqual(result["network_observed"], ["receive", "send"])
        self.assertTrue(any(item["type"] == "网络访问出现未授权动作" for item in result["anomaly_types"]))


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
        """迟到的 round_end 只刷新元数据，不改代次、不清掉已完成的报告。"""
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
        """已完成的 round 只重放一条必需消息（内核）也会用磁盘上的输入完整重跑。"""
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
        """每次重放都完整重跑分析链路并再次上报。"""
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
        """复现线上问题：IR 迟于内核消息到达时必须等齐后再用真实允许集分析。"""
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
        """round_end 携带空 IR 时不得提前触发分析。"""
        self.store.enqueue_message(self.round_start("empty-ir"))
        self.store.enqueue_message(self.round_end("empty-ir", ir=False))
        self.store.enqueue_message(self.round_kernel("empty-ir"))
        self.drain_ingest()

        self.assertEqual(self.store.get_round("empty-ir")["status"], "receiving")
        self.assertFalse(self.pipeline.analyze_once())
        self.assertFalse((self.settings.input_dir / "empty-ir" / "analysis_report.md").exists())

    def test_burst_messages_are_queued_and_processed(self) -> None:
        """20 个 round 突发到达时全部排队并处理完成。"""
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
        """分析失败先重试，达到次数上限后置为 analysis_failed。"""
        self.store.enqueue_message(self.round_start("bad"))
        self.store.enqueue_message(self.round_end("bad", bad_ir=True))
        self.store.enqueue_message(self.round_kernel("bad"))
        self.drain_ingest()

        self.assertTrue(self.pipeline.analyze_once())
        self.assertEqual(self.store.get_round("bad")["status"], "queued")
        self.assertTrue(self.pipeline.analyze_once())
        self.assertEqual(self.store.get_round("bad")["status"], "analysis_failed")

    def test_analysis_uses_new_file_identifier_matching(self) -> None:
        """端到端验证精确/glob/正则三类 IR 标识的放行结果。"""
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
        """未处理的 inbox 消息在重开库后仍能被消费。"""
        self.store.enqueue_message(self.round_end("recover"))
        self.store.close()

        self.store = StateStore(settings=self.settings)
        self.pipeline = RealtimePipeline(store=self.store, settings=self.settings, push_reports=False)
        self.drain_ingest()

        self.assertTrue((self.settings.input_dir / "recover" / "round_end.json").is_file())
        self.assertEqual(self.store.get_round("recover")["status"], "receiving")

    def test_mock_round_push_is_disabled_by_default(self) -> None:
        """默认配置下 mock round 分析但不上报。"""
        self.store.enqueue_message(self.round_start("mock-skip", is_mock=True))
        self.store.enqueue_message(self.round_end("mock-skip", is_mock=True))
        self.store.enqueue_message(self.round_kernel("mock-skip", is_mock=True))
        self.drain_ingest()

        with patch("lha_realtime.analyzer.push_and_mark_report", return_value=True) as push:
            self.drain_analysis()

        push.assert_not_called()

    def test_mock_round_push_can_be_enabled(self) -> None:
        """开启 LHA_PUSH_MOCK_REPORTS 后 mock round 也会上报。"""
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


class SensitiveClassificationTest(unittest.TestCase):
    """敏感资源判定：detection_rules.yaml 中三条抑制误报的设计是否真的生效。

    每条断言都对应规则文件里写明的一个取舍，回放 454 个真实 round 时验证过。
    """

    @staticmethod
    def op(pid: int = 100, actions=("read",), syscall_pathname=None) -> dict:
        return {
            "pid": pid,
            "observed_actions": list(actions),
            "syscall_pathname": syscall_pathname,
        }

    def test_proc_self_access_is_runtime_but_cross_process_is_sensitive(self) -> None:
        # 进程读自己的 environ / maps 不跨越权限边界（真实数据中 28 次命中全属此类）。
        self.assertEqual(classify("/proc/100/environ", self.op(pid=100)), "runtime")
        self.assertEqual(classify("/proc/100/maps", self.op(pid=100)), "runtime")
        self.assertEqual(
            classify("/proc/999/fd", self.op(pid=100, syscall_pathname="/proc/self/fd")),
            "runtime",
        )
        # 读别的进程才是 ATT&CK T1003.007 描述的行为。
        self.assertEqual(classify("/proc/999/environ", self.op(pid=100)), "sensitive")
        self.assertEqual(classify("/proc/999/mem", self.op(pid=100)), "sensitive")

    def test_proc_public_metadata_never_sensitive(self) -> None:
        # /proc/<pid>/stat、status 是 ps/top 正常读取的公开元信息，跨进程也不报。
        self.assertEqual(classify("/proc/999/stat", self.op(pid=100)), "runtime")
        self.assertEqual(classify("/proc/999/status", self.op(pid=100)), "runtime")

    def test_openclaw_runtime_tree_is_runtime(self) -> None:
        """openclaw 自身运行时目录判为 runtime，不计入敏感。"""
        for path in (
            "/root/.openclaw/sandboxes/agent-main-main/skills/apple-notes",
            "/root/.openclaw/extensions/openclaw-lark/index.js",
            "/root/.openclaw/workspace/test_a.txt",
            "/root/.openclaw/state",
        ):
            self.assertEqual(classify(path, self.op()), "runtime", path)

    def test_credentials_override_openclaw_runtime_whitelist(self) -> None:
        # override_runtime 分组要能穿透运行时白名单，否则密钥藏进框架目录就检不出。
        self.assertEqual(classify("/root/.openclaw/workspace/.env", self.op()), "sensitive")
        self.assertEqual(classify("/root/.openclaw/workspace/id_rsa", self.op()), "sensitive")

    def test_write_only_group_ignores_reads(self) -> None:
        # /etc/passwd 世界可读、glibc NSS 每轮都读；写入才等价于新增后门账号。
        self.assertEqual(classify("/etc/passwd", self.op(actions=("read",))), "runtime")
        self.assertEqual(classify("/etc/passwd", self.op(actions=("read", "write"))), "sensitive")
        self.assertEqual(classify("/etc/ld.so.preload", self.op(actions=("read",))), "runtime")
        self.assertEqual(classify("/etc/ld.so.preload", self.op(actions=("create",))), "sensitive")

    def test_always_sensitive_paths_flag_on_read(self) -> None:
        """凭据/私钥/进程内存类路径读取即判敏感。"""
        for path in (
            "/etc/shadow",
            "/etc/shadow-",
            "/etc/sudoers.d/90-cloud-init",
            "/root/.ssh/id_ed25519",
            "/home/alice/.ssh/id_rsa",
            "/root/.aws/credentials",
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "/var/log/secure",
            "/var/run/docker.sock",
            "/proc/kcore",
        ):
            self.assertEqual(classify(path, self.op(actions=("read",))), "sensitive", path)

    def test_lookalike_paths_do_not_false_positive(self) -> None:
        # 这些都是回放中真实出现过、按前缀一刀切会误伤的路径。
        self.assertNotEqual(classify("/etc/environment-modules/initrc", self.op()), "sensitive")
        self.assertNotEqual(
            classify("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", self.op()), "sensitive"
        )
        self.assertNotEqual(classify("/etc/authselect/nsswitch.conf", self.op()), "sensitive")
        self.assertNotEqual(classify("/etc/profile.d/colorls.sh", self.op(actions=("read",))), "sensitive")

    def test_rules_carry_citable_rationale(self) -> None:
        # 报告要能说明"为什么这算敏感"，每组都必须带理由与依据。
        self.assertTrue(SENSITIVE_RULES)
        for rule in SENSITIVE_RULES:
            self.assertTrue(rule.reason, rule.id)
            self.assertTrue(rule.basis, rule.id)
            self.assertIn(rule.match, ("any", "write_only"), rule.id)

    def test_violation_records_carry_rule_metadata(self) -> None:
        """命中的敏感规则带 id 与 ATT&CK 编号，供报告引用。"""
        rule = matching_sensitive_rule("/root/.ssh/id_ed25519", self.op())
        self.assertIsNotNone(rule)
        self.assertEqual(rule.id, "private_keys")
        self.assertIn("T1552.004", rule.attck)


if __name__ == "__main__":
    unittest.main()
