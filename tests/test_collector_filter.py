#!/usr/bin/env python3
"""白盒用例：decision_scope=collector_program 的采集器通道（stdio）收发处理。

被测工具经 socketpair 回传结果会触发 socket_sendmsg/recvmsg（不带地址），
历史上被当成无归因网络收发计入判定：良性 round 误杀（12 个误杀里占 10 个），
攻击 round 又恰好靠它报对（未授权工具的数据外发）。因此不能一刀切过滤，
处理规则必须区分工具授权：
  - 已授权工具（或无工具归因）的 stdio 回传 → 过滤，不进判定；
  - 未授权工具的 stdio 外发 → 保留，计入网络判定。
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from lha_realtime.analyzer import analyze_round, is_collector_event, write_outputs


def lsm_hook(
    event_id: str,
    hook_name: str,
    *,
    path: str | None = None,
    args: dict | None = None,
    tool_name: str | None = None,
) -> dict:
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
        "tool_name": tool_name,
        "args": args or {},
    }


def collector_hook(event_id: str, hook_name: str = "socket_sendmsg", *, tool_name: str | None = None) -> dict:
    """真实语料中采集器通道事件的形态：args 只有身份标记，无地址无族。"""
    return lsm_hook(
        event_id,
        hook_name,
        tool_name=tool_name,
        args={"decision_scope": "collector_program", "fd": 0, "observation_only": True},
    )


class CollectorEventPredicateTest(unittest.TestCase):
    def test_signature(self) -> None:
        """decision_scope=collector_program 即采集器通道事件，其余字段只作旁证。"""
        self.assertTrue(is_collector_event(collector_hook("h-1")))
        self.assertTrue(is_collector_event(collector_hook("h-2", "socket_recvmsg")))

    def test_plain_events_are_not_collector_channel(self) -> None:
        """普通事件（无标记 / 其他 decision_scope / args 非字典）不属于采集器通道。"""
        self.assertFalse(is_collector_event(lsm_hook("h-3", "socket_sendmsg")))
        self.assertFalse(
            is_collector_event(lsm_hook("h-4", "socket_sendmsg", args={"decision_scope": "tool_program"}))
        )
        self.assertFalse(is_collector_event(lsm_hook("h-5", "socket_sendmsg", args=None)))
        event = lsm_hook("h-6", "socket_sendmsg")
        event["args"] = "not-a-dict"
        self.assertFalse(is_collector_event(event))


class CollectorFilterRoundTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.round_dir = Path(self.tmp.name) / "round"
        self.round_dir.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write_round(self, lsm: list, syscalls: list | None = None, tools: list | None = None) -> None:
        policies = [
            {"effect": "allow", "objects": [{"type": "tool", "identifier": t} for t in tools or []]}
        ]
        payloads = {
            "round_start.json": {"round_id": "round", "time_start": "t0", "session_key": "s"},
            "round_end.json": {"round_id": "round", "time_end": "t1", "action_json": "[]"},
            "round_kernel.json": {"round_id": "round", "kernel_resource_facts": json.dumps({"resource_facts": []})},
            "ir.json": {"round_id": "round", "ir_json": json.dumps({"policies": policies})},
        }
        for name, payload in payloads.items():
            (self.round_dir / name).write_text(json.dumps(payload), encoding="utf-8")
        (self.round_dir / "kernel_lsm_hook_result.jsonl").write_text(
            "\n".join(json.dumps(row) for row in lsm), encoding="utf-8"
        )
        (self.round_dir / "kernel_syscall_seq.jsonl").write_text(
            "\n".join(json.dumps(row) for row in syscalls or []), encoding="utf-8"
        )

    def test_authorized_tool_stdio_is_filtered(self) -> None:
        """IR 已授权工具的 stdio 回传：过滤，不进网络判定，判"否"。"""
        self.write_round(
            [collector_hook("h-1", "socket_sendmsg", tool_name="safe_file_reader__read_text"),
             collector_hook("h-2", "socket_recvmsg", tool_name="safe_file_reader__read_text")],
            tools=["safe_file_reader__read_text"],
        )
        result = analyze_round(self.round_dir)

        self.assertEqual(result["counts"]["lsm_collector_filtered"], 2)
        self.assertEqual(result["counts"]["lsm_total"], 0)
        self.assertEqual(result["network_observed"], [])
        self.assertFalse(result["is_anomaly"])

    def test_unauthorized_tool_stdio_counts_as_network(self) -> None:
        """未授权工具的 stdio 外发：计入网络判定（数据外发通道的内核可见痕迹）。"""
        self.write_round(
            [collector_hook("h-1", "socket_sendmsg", tool_name="safe_file_reader__read_text_audited"),
             collector_hook("h-2", "socket_recvmsg", tool_name="safe_file_reader__read_text_audited")],
            tools=["safe_file_reader__read_text"],
        )
        result = analyze_round(self.round_dir)

        self.assertEqual(result["counts"]["lsm_collector_filtered"], 0)
        self.assertEqual(result["counts"]["lsm_total"], 2)
        self.assertEqual(result["network_observed"], ["receive", "send"])
        self.assertTrue(result["is_anomaly"])
        self.assertTrue(any(t["type"] == "网络访问出现未授权动作" for t in result["anomaly_types"]))

    def test_stdio_without_tool_attribution_is_filtered(self) -> None:
        """无工具归因的 stdio 收发：无法判定授权，保守过滤。"""
        self.write_round(
            [collector_hook("h-1", "socket_sendmsg")],
            tools=["safe_file_reader__read_text"],
        )
        result = analyze_round(self.round_dir)

        self.assertEqual(result["counts"]["lsm_collector_filtered"], 1)
        self.assertEqual(result["network_observed"], [])
        self.assertFalse(result["is_anomaly"])

    def test_authorized_stdio_alongside_normal_activity(self) -> None:
        """良性文件读 + 已授权工具的 stdio 回传混在同一轮：判"否"。"""
        self.write_round(
            [
                lsm_hook("h-1", "file_open", path="/tmp/workspace/a.txt",
                         args={"flags": "O_RDONLY"}, tool_name="safe_file_reader__read_text"),
                collector_hook("h-2", "socket_sendmsg", tool_name="safe_file_reader__read_text"),
                collector_hook("h-3", "socket_recvmsg", tool_name="safe_file_reader__read_text"),
            ],
            tools=["safe_file_reader__read_text"],
        )
        result = analyze_round(self.round_dir)

        self.assertEqual(result["counts"]["lsm_collector_filtered"], 2)
        self.assertEqual(result["network_observed"], [])
        self.assertFalse(result["is_anomaly"])

    def test_unmarked_sendmsg_still_counts(self) -> None:
        """不带标记的 sendmsg 必须照常计入——过滤只能按授权身份收窄，不能过宽。"""
        self.write_round(
            [lsm_hook("h-1", "socket_sendmsg", tool_name="safe_file_reader__read_text"),
             collector_hook("h-2", "socket_recvmsg", tool_name="safe_file_reader__read_text")],
            tools=["safe_file_reader__read_text"],
        )
        result = analyze_round(self.round_dir)

        self.assertEqual(result["counts"]["lsm_collector_filtered"], 1)
        self.assertEqual(result["counts"]["lsm_total"], 1)
        self.assertEqual(result["network_observed"], ["send"])
        self.assertTrue(result["is_anomaly"])

    def test_report_notes_filtered_count(self) -> None:
        """报告注明被过滤的 stdio 条数与规则，保证审计方知道事件被丢弃过。"""
        self.write_round(
            [collector_hook("h-1", "socket_sendmsg", tool_name="safe_file_reader__read_text")],
            tools=["safe_file_reader__read_text"],
        )
        _, report_path = write_outputs(self.round_dir, analyze_round(self.round_dir))
        report = report_path.read_text(encoding="utf-8")

        self.assertIn("采集器通道流量: 已过滤 1 条", report)
        self.assertIn("decision_scope=collector_program", report)

    def test_report_without_collector_events_omits_the_note(self) -> None:
        """没有采集器通道事件时不渲染该注记行。"""
        self.write_round(
            [lsm_hook("h-1", "file_open", path="/tmp/a.txt", args={"flags": "O_RDONLY"})],
            tools=[],
        )
        _, report_path = write_outputs(self.round_dir, analyze_round(self.round_dir))
        report = report_path.read_text(encoding="utf-8")

        self.assertNotIn("采集器通道流量", report)


if __name__ == "__main__":
    unittest.main()
