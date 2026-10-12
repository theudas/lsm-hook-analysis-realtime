#!/usr/bin/env python3
"""白盒用例：scripts/hotspot_stats.py 的豁免建议判定与 YAML 片段。

这个页面的价值在于“建议豁免”的结论可信：这里钉住每一档结论的边界，并验证
生成的 YAML 合入规则后确实能折叠对应行为、又不会把写入一起吞掉。
"""

from __future__ import annotations

import collections
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

import yaml

from lha_realtime import rules

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "hotspot_stats.py"
spec = importlib.util.spec_from_file_location("hotspot_stats", SCRIPT)
hotspot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hotspot)


def meta(*, categories=("runtime",), actions=("read",), hooks=("file_open",), deeper=False) -> dict:
    return {"rounds": {"r1", "r2"}, "hooks": collections.Counter(hooks), "actions": set(actions),
            "categories": set(categories), "count": 5, "examples": [], "deeper": deeper}


class AdviseFileTest(unittest.TestCase):
    def verdict(self, path: str, **kwargs) -> str:
        return hotspot.advise_file(path, meta(**kwargs), 0.3)[0]

    def test_read_only_runtime_file_in_system_dir_is_accepted(self) -> None:
        """系统目录、runtime、只读：建议豁免。"""
        self.assertEqual(self.verdict("/etc/hosts"), hotspot.ACCEPT)

    def test_sensitive_hit_is_rejected(self) -> None:
        """敏感命中一律不建议，哪怕同一路径也有 runtime 访问。"""
        self.assertEqual(self.verdict("/root/.ssh", categories=("runtime", "sensitive")), hotspot.REJECT)

    def test_observed_write_is_rejected(self) -> None:
        """观测到写入/创建/删除：豁免会掩盖篡改。"""
        self.assertEqual(self.verdict("/etc/hosts", actions=("read", "write")), hotspot.REJECT)
        self.assertEqual(self.verdict("/usr/share/x", actions=("delete",)), hotspot.REJECT)

    def test_writing_to_output_devices_is_accepted(self) -> None:
        """写终端/空设备是正常输出；但 create 仍不放行。"""
        self.assertEqual(self.verdict("/dev/tty", actions=("read", "write")), hotspot.ACCEPT)
        self.assertEqual(self.verdict("/dev/null", actions=("write", "create")), hotspot.REJECT)

    def test_user_writable_dirs_are_rejected_unless_framework_runtime(self) -> None:
        """用户可写目录不建议；已归为框架运行时的需人工确认。"""
        self.assertEqual(self.verdict("/tmp/<x>/audit.log", categories=("other",)), hotspot.REJECT)
        self.assertEqual(self.verdict("/home/hx/hzx", categories=("other",)), hotspot.REJECT)
        self.assertEqual(self.verdict("/root/.openclaw/extensions"), hotspot.REVIEW)

    def test_exec_and_unclassified_paths_need_review(self) -> None:
        """含 bprm_check、或系统目录下未归类为 runtime、或不在系统目录：需人工确认。"""
        self.assertEqual(self.verdict("/usr/bin/bash", hooks=("file_open", "bprm_check")), hotspot.REVIEW)
        self.assertEqual(self.verdict("/etc/environment-modules", categories=("other",)), hotspot.REVIEW)
        self.assertEqual(self.verdict("/opt/app/lib"), hotspot.REVIEW)


class AdviseNetTest(unittest.TestCase):
    def test_unix_socket_and_loopback_need_review_with_config(self) -> None:
        verdict, _, snippet = hotspot.advise_net("/run/foo.sock", meta(), 0.3)
        self.assertEqual(verdict, hotspot.REVIEW)
        self.assertEqual(yaml.safe_load(snippet)["system_baseline"][0]["endpoints"], ["/run/foo.sock"])
        verdict, _, snippet = hotspot.advise_net("::1:15100", meta(), 0.3)
        self.assertEqual(verdict, hotspot.REVIEW)
        self.assertEqual(yaml.safe_load(snippet), {"network": {"ignored_endpoints": ["::1:15100"]}})
        self.assertEqual(hotspot.advise_net("localhost:80", meta(), 0.3)[0], hotspot.REVIEW)

    def test_remote_address_is_rejected_without_config(self) -> None:
        """非本机地址不给配置：是否放行外连由人决定。"""
        verdict, _, snippet = hotspot.advise_net("8.152.192.7:15100", meta(), 0.3)
        self.assertEqual(verdict, hotspot.REJECT)
        self.assertIsNone(snippet)
        self.assertFalse(hotspot.is_loopback("not-an-ip:1"))


class FileYamlTest(unittest.TestCase):
    def compile(self, path: str, m: dict) -> rules.BaselineRule:
        entries = yaml.safe_load(hotspot.file_yaml(path, m, 0.3))["system_baseline"]
        (rule,) = rules._compile_baseline(entries)
        return rule

    def test_generated_rule_folds_reads_but_not_writes(self) -> None:
        rule = self.compile("/etc/hosts", meta())
        self.assertTrue(rule.matches({"hook_name": "file_open", "path": "/etc/hosts", "observed_actions": ["read"]},
                                     "runtime"))
        self.assertFalse(rule.matches({"hook_name": "file_open", "path": "/etc/hosts",
                                       "observed_actions": ["read", "write"]}, "runtime"))
        # 精确文件不连带同名开头的路径。
        self.assertFalse(rule.matches({"hook_name": "file_open", "path": "/etc/hosts.allow",
                                       "observed_actions": ["read"]}, "runtime"))

    def test_directory_bucket_and_pid_placeholder_become_globs(self) -> None:
        rule = self.compile("/proc/<pid>/fd", meta(deeper=True))
        op = {"hook_name": "file_open", "path": "/proc/123/fd/4", "observed_actions": ["read"]}
        self.assertTrue(rule.matches(op, "runtime"))
        # 跨进程读取会被归为 sensitive，生成的规则限定 runtime，不会吞掉它。
        self.assertFalse(rule.matches(op, "sensitive"))


class RenderTest(unittest.TestCase):
    def test_generated_page_is_static_and_uses_relative_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            input_dir = Path(tmp) / "input"
            round_dir = input_dir / "r1"
            round_dir.mkdir(parents=True)
            hook = {"event_id": "e1", "hook_name": "file_open", "result": "allow", "pid": 1,
                    "timestamp_mono_ns": 1, "path": "/etc/hosts", "args": {"flags": "O_RDONLY"}}
            (round_dir / "kernel_lsm_hook_result.jsonl").write_text(json.dumps(hook), encoding="utf-8")
            (round_dir / "kernel_syscall_seq.jsonl").write_text("", encoding="utf-8")
            out = Path(tmp) / "hotspot.html"
            args = type("Args", (), {"input_dir": input_dir, "out": out, "json": None, "depth": 3, "top": 30,
                                     "threshold": 0.2})()
            self.assertEqual(hotspot.generate(args), 0)
            page = out.read_text(encoding="utf-8")
        self.assertIn("/etc/hosts", page)
        self.assertIn("✓ 建议豁免", page)
        self.assertIn('id="refresh"', page)
        # 页面元信息只写相对项目根目录的路径。
        self.assertNotIn(f"语料 {input_dir}", page)
        self.assertIn("语料 ../", page)
        self.assertIn("规则 lha_realtime/detection_rules.yaml", page)


if __name__ == "__main__":
    unittest.main()
