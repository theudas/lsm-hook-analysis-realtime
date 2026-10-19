#!/usr/bin/env python3
"""白盒用例：采集完整性自检（把"没检测到"与"没采集到"分开）。

IR 已就绪但内核事件流为空 → 判定基于空证据，报告标"采集异常"；
捕获到 connect 但无任何 send/recv → 收发证据可能缺失，报告标"可疑"。
状态只影响报告注记，不改变判定本身。
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from lha_realtime.analyzer import analyze_round, write_outputs


def lsm_hook(event_id: str, hook_name: str, *, path: str | None = None, args: dict | None = None) -> dict:
    return {
        "event_id": event_id,
        "hook_name": hook_name,
        "result": "allow",
        "return_value": 0,
        "pid": 1000,
        "tid": 1000,
        "timestamp_mono_ns": int(event_id.rsplit("-", 1)[-1]),
        "category": "unknown",
        "path": path,
        "args": args or {},
    }


def connect(event_id: str, fd: int, ts: int, **target) -> dict:
    return {"action": "connect", "event_id": event_id, "pid": 1000, "fd": fd, "timestamp_mono_ns": ts,
            "args": {"sockfd": fd, **target}}


def io(action: str, event_id: str, fd: int, ts: int) -> dict:
    return {"action": action, "event_id": event_id, "pid": 1000, "fd": fd, "timestamp_mono_ns": ts}


class CollectionStatusRoundTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.round_dir = Path(self.tmp.name) / "round"
        self.round_dir.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write_round(self, lsm: list, syscalls: list | None = None) -> None:
        payloads = {
            "round_start.json": {"round_id": "round", "time_start": "t0", "session_key": "s"},
            "round_end.json": {"round_id": "round", "time_end": "t1", "action_json": "[]"},
            "round_kernel.json": {"round_id": "round", "kernel_resource_facts": json.dumps({"resource_facts": []})},
            "ir.json": {"round_id": "round", "ir_json": json.dumps({"policies": []})},
        }
        for name, payload in payloads.items():
            (self.round_dir / name).write_text(json.dumps(payload), encoding="utf-8")
        (self.round_dir / "kernel_lsm_hook_result.jsonl").write_text(
            "\n".join(json.dumps(row) for row in lsm), encoding="utf-8"
        )
        (self.round_dir / "kernel_syscall_seq.jsonl").write_text(
            "\n".join(json.dumps(row) for row in syscalls or []), encoding="utf-8"
        )

    def test_zero_kernel_events_is_flagged(self) -> None:
        """IR 就绪但内核零事件：状态 no_kernel_events，报告标采集异常。"""
        self.write_round([], [])
        result = analyze_round(self.round_dir)
        self.assertEqual(result["collection_status"], "no_kernel_events")
        self.assertFalse(result["is_anomaly"])

        _, report_path = write_outputs(self.round_dir, result)
        report = report_path.read_text(encoding="utf-8")
        self.assertIn("采集完整性: **异常（内核零事件）**", report)
        self.assertIn("不构成\"无越权行为\"的证明", report)

    def test_connect_without_io_is_flagged_as_suspect(self) -> None:
        """只有 connect 没有任何收发痕迹：状态 connect_without_io，报告提示证据可能缺失。"""
        self.write_round(
            [],
            [connect("c-1", 3, 1, remote_ip="8.152.192.7", remote_port="15100")],
        )
        result = analyze_round(self.round_dir)
        self.assertEqual(result["collection_status"], "connect_without_io")

        _, report_path = write_outputs(self.round_dir, result)
        report = report_path.read_text(encoding="utf-8")
        self.assertIn("采集完整性: 可疑（有 connect 无收发痕迹）", report)

    def test_connect_with_sendmsg_is_ok(self) -> None:
        """connect + 收发痕迹齐全（LSM 层 sendmsg）：状态 ok，无告警注记。"""
        self.write_round(
            [lsm_hook("h-1", "socket_sendmsg")],
            [connect("c-1", 3, 1, remote_ip="8.152.192.7", remote_port="15100")],
        )
        result = analyze_round(self.round_dir)
        self.assertEqual(result["collection_status"], "ok")

    def test_connect_with_syscall_sendto_is_ok(self) -> None:
        """connect + 收发痕迹齐全（syscall 层 sendto）：状态 ok。"""
        self.write_round(
            [],
            [connect("c-1", 3, 1, remote_ip="8.152.192.7", remote_port="15100"),
             io("sendto", "s-2", 3, 2)],
        )
        result = analyze_round(self.round_dir)
        self.assertEqual(result["collection_status"], "ok")

    def test_file_only_round_is_ok(self) -> None:
        """无 connect、无收发、只有文件事件：正常 round，状态 ok。"""
        self.write_round([lsm_hook("h-1", "file_open", path="/tmp/a.txt", args={"flags": "O_RDONLY"})])
        result = analyze_round(self.round_dir)
        self.assertEqual(result["collection_status"], "ok")

        _, report_path = write_outputs(self.round_dir, result)
        report = report_path.read_text(encoding="utf-8")
        self.assertNotIn("采集完整性", report)

    def test_collector_stdio_counts_as_io_evidence(self) -> None:
        """connect + 仅采集器通道的 stdio 痕迹：视为有收发痕迹，状态 ok（而非 connect_without_io）。"""
        self.write_round(
            [lsm_hook("h-1", "socket_sendmsg",
                      args={"decision_scope": "collector_program", "fd": 0, "observation_only": True})],
            [connect("c-1", 3, 1, remote_ip="127.0.0.1", remote_port="15100")],
        )
        result = analyze_round(self.round_dir)
        self.assertEqual(result["collection_status"], "ok")


if __name__ == "__main__":
    unittest.main()
