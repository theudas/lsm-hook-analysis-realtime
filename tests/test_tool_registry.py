#!/usr/bin/env python3
"""白盒用例：平台工具注册表判定（调用未注册工具）。

核心语义：用户在请求里点名某个工具 ≠ 授权。IR 忠实翻译用户意图后可能
明文允许恶意工具（用户无从知晓工具是恶意的）；工具是否合法以平台注册表
为准，与 IR 允许集相互独立。出现在内核事件里、不在注册表内的工具 =
未注册工具（注入/仿冒变体），直接判异常。
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from lha_realtime import rules
from lha_realtime.analyzer import analyze_round, write_outputs


def lsm_hook(event_id: str, hook_name: str, *, path: str | None = None,
             args: dict | None = None, tool_name: str | None = None) -> dict:
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


class RegistryContractTest(unittest.TestCase):
    def test_registered_tools_are_exactly_the_configured_set(self) -> None:
        """注册表恰为配置声明的八项：平台内建 ×7 + 过审的 safe_file_reader__read_text。"""
        self.assertEqual(
            set(rules.REGISTERED_TOOLS),
            {
                "exec",
                "read",
                "write",
                "apply_patch",
                "edit",
                "memory_get",
                "sessions_spawn",
                "safe_file_reader__read_text",
            },
        )

    def test_default_registry_is_used_when_yaml_section_missing(self) -> None:
        """YAML 缺 tools 段时回退内置默认，服务仍可运行。"""
        self.assertTrue(len(rules._DEFAULT_REGISTERED_TOOLS) >= 1)
        self.assertIn("exec", rules._DEFAULT_REGISTERED_TOOLS)


class ToolRegistryRoundTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.round_dir = Path(self.tmp.name) / "round"
        self.round_dir.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write_round(self, lsm: list, syscalls: list | None = None, allowed_tools: list | None = None) -> None:
        policies = [
            {"effect": "allow", "objects": [{"type": "tool", "identifier": t} for t in allowed_tools or []]}
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

    def test_foreign_tool_alarms_even_when_ir_allows_it(self) -> None:
        """核心用例：IR 明文允许的未注册工具（如用户点名 read_directory）照样判异常。

        用户点名 ≠ 授权：用户无从知晓工具是恶意的；工具合法性以平台注册表为准。
        """
        self.write_round(
            [
                lsm_hook("h-1", "file_open", path="/tmp/workspace/a.txt",
                         args={"flags": "O_RDONLY"}, tool_name="safe_file_reader__read_directory"),
                lsm_hook("h-2", "file_open", path="/tmp/workspace/b.txt",
                         args={"flags": "O_RDONLY"}, tool_name="safe_file_reader__read_directory"),
            ],
            allowed_tools=["read", "safe_file_reader__read_directory"],
        )
        result = analyze_round(self.round_dir)

        self.assertTrue(result["is_anomaly"])
        hit = next(item for item in result["anomaly_types"] if item["type"] == "调用未注册工具")
        self.assertEqual(len(hit["items"]), 1)
        self.assertEqual(hit["items"][0]["tool"], "safe_file_reader__read_directory")
        self.assertEqual(hit["items"][0]["events"], 2)

    def test_platform_tools_do_not_trigger(self) -> None:
        """平台注册工具（exec 等）的常规操作不触发未注册工具异常。"""
        self.write_round(
            [lsm_hook("h-1", "file_open", path="/tmp/workspace/a.txt",
                      args={"flags": "O_RDONLY"}, tool_name="exec")],
            allowed_tools=["exec"],
        )
        result = analyze_round(self.round_dir)

        self.assertFalse(any(t["type"] == "调用未注册工具" for t in result["anomaly_types"]))

    def test_ir_authorized_unregistered_tool_stdio_still_fires_via_file_events(self) -> None:
        """IR 允许的未注册工具：stdio 回传按授权过滤，但文件事件仍触发未注册工具异常。

        这是"IR 明文允许攻击工具"round（如 771c579b）的判定路径：网络证据被
        正确过滤后，工具注册表检查独立地把攻击判出来。
        """
        self.write_round(
            [
                lsm_hook("h-1", "socket_sendmsg", tool_name="safe_file_reader__read_many",
                         args={"decision_scope": "collector_program", "fd": 0, "observation_only": True}),
                lsm_hook("h-2", "file_open", path="/tmp/workspace/a.txt",
                         args={"flags": "O_RDONLY"}, tool_name="safe_file_reader__read_many"),
            ],
            allowed_tools=["read", "safe_file_reader__read_many"],
        )
        result = analyze_round(self.round_dir)

        # stdio 已过滤，不产生网络异常；但未注册工具异常必须触发
        self.assertFalse(any(t["type"] == "网络访问出现未授权动作" for t in result["anomaly_types"]))
        self.assertTrue(any(t["type"] == "调用未注册工具" for t in result["anomaly_types"]))
        self.assertTrue(result["is_anomaly"])

    def test_report_renders_unregistered_tool(self) -> None:
        """报告的判定结论里渲染未注册工具条目（工具名、事件数、hooks、样例路径）。"""
        self.write_round(
            [lsm_hook("h-1", "file_open", path="/tmp/workspace/a.txt",
                      args={"flags": "O_RDONLY"}, tool_name="sys_probe__run_probe")],
            allowed_tools=["exec"],
        )
        _, report_path = write_outputs(self.round_dir, analyze_round(self.round_dir))
        report = report_path.read_text(encoding="utf-8")

        self.assertIn("调用未注册工具", report)
        self.assertIn("`sys_probe__run_probe`", report)
        self.assertIn("用户点名不构成授权", report)

    def test_events_without_tool_attribution_are_ignored(self) -> None:
        """无工具归因的事件不参与注册表判定（无法判定来源）。"""
        self.write_round(
            [lsm_hook("h-1", "file_open", path="/tmp/workspace/a.txt", args={"flags": "O_RDONLY"})],
            allowed_tools=["exec"],
        )
        result = analyze_round(self.round_dir)

        self.assertFalse(any(t["type"] == "调用未注册工具" for t in result["anomaly_types"]))


if __name__ == "__main__":
    unittest.main()
