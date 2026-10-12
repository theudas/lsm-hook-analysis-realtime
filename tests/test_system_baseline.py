#!/usr/bin/env python3
"""白盒用例：system_baseline 系统基线折叠与按端点的网络判定。

基线是"屏蔽"能力，最怕的是屏蔽过头：这里除了覆盖 NSS socket、netlink、
运行时 mprotect、无路径 hook 这几类该折叠的行为，也逐一钉住不该折叠的边界——
敏感命中、/tmp 下的可疑库、未忽略的外部端点都必须照常出现在越权清单和判定里。
"""

from __future__ import annotations

import json
import logging
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lha_realtime import analyzer, rules
from lha_realtime.analyzer import analyze_round, parse_network_activity, write_outputs
from lha_realtime.rules import BaselineRule, endpoint_token, is_baseline_endpoint, matching_baseline_rule


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


class BaselineRuleLoadingTest(unittest.TestCase):
    def test_endpoint_token_strips_address_family(self) -> None:
        """端点串去掉地址族前缀，空串或纯空白返回 None。"""
        self.assertEqual(endpoint_token("AF_UNIX /var/run/nscd/socket"), "/var/run/nscd/socket")
        self.assertEqual(endpoint_token("8.8.8.8:53"), "8.8.8.8:53")
        self.assertIsNone(endpoint_token(""))
        self.assertIsNone(endpoint_token("   "))

    def test_entry_without_conditions_is_dropped(self) -> None:
        """没有任何条件的条目会匹配一切，必须丢弃而不是屏蔽全部行为。"""
        with self.assertLogs("lha_realtime_rules", level="WARNING"):
            compiled = rules._compile_baseline([{"id": "everything", "title": "x"}])
        self.assertEqual(compiled, ())

    def test_non_list_and_non_dict_entries_are_ignored(self) -> None:
        """system_baseline 不是列表、或条目不是映射时一律忽略。"""
        self.assertEqual(rules._compile_baseline({"id": "x"}), ())
        self.assertEqual(rules._compile_baseline(["x", None]), ())

    def test_entry_fields_are_compiled(self) -> None:
        """条目字段被编译为集合；只有字面 true 才开启 path_missing。"""
        (rule,) = rules._compile_baseline(
            [{"id": "m", "hooks": ["file_mprotect"], "categories": ["runtime"], "path_missing": "yes"}]
        )
        self.assertEqual(rule.hooks, frozenset({"file_mprotect"}))
        self.assertEqual(rule.categories, frozenset({"runtime"}))
        self.assertFalse(rule.path_missing)

    def test_conditions_are_combined_with_and(self) -> None:
        """多个条件按 AND 组合：/tmp 下的可疑库不会被 runtime_mprotect 吞掉。"""
        rule = BaselineRule(id="m", title="m", reason="", hooks=frozenset({"file_mprotect"}),
                            categories=frozenset({"runtime"}))
        self.assertTrue(rule.matches({"hook_name": "file_mprotect", "path": "/usr/lib64/libc.so.6"}, "runtime"))
        self.assertFalse(rule.matches({"hook_name": "file_mprotect", "path": "/tmp/evil.so"}, "other"))
        self.assertFalse(rule.matches({"hook_name": "file_open", "path": "/usr/lib64/libc.so.6"}, "runtime"))

    def test_path_conditions_require_a_matching_path(self) -> None:
        """prefixes / globs 条件要求路径命中；无路径的操作不匹配。"""
        (rule,) = rules._compile_baseline([{"id": "lib", "prefixes": ["/usr/lib64/"], "globs": ["/opt/**/*.so"]}])
        self.assertTrue(rule.matches({"path": "/usr/lib64/libc.so.6"}, "runtime"))
        self.assertTrue(rule.matches({"path": "/opt/a/b/x.so"}, "other"))
        self.assertFalse(rule.matches({"path": "/usr/lib64x/libc.so.6"}, "runtime"))
        self.assertFalse(rule.matches({"path": None}, "unknown"))

    def test_actions_condition_requires_all_observed_actions_to_be_declared(self) -> None:
        """actions: [read] 只豁免纯读取；带写入或动作未知的操作不匹配。"""
        (rule,) = rules._compile_baseline([{"id": "hosts", "globs": ["/etc/hosts"], "actions": ["read"]}])
        self.assertTrue(rule.matches({"path": "/etc/hosts", "observed_actions": ["read"]}, "runtime"))
        self.assertFalse(rule.matches({"path": "/etc/hosts", "observed_actions": ["read", "write"]}, "runtime"))
        self.assertFalse(rule.matches({"path": "/etc/hosts", "observed_actions": []}, "runtime"))
        self.assertFalse(rule.matches({"path": "/etc/hosts"}, "runtime"))

    def test_sensitive_category_is_never_folded(self) -> None:
        """即使基线条件全部成立，敏感命中也不会被折叠。"""
        catch_all = BaselineRule(id="all_open", title="t", reason="", hooks=frozenset({"file_open"}))
        with patch.object(rules, "BASELINE_RULES", (catch_all,)):
            self.assertIsNone(matching_baseline_rule({"hook_name": "file_open"}, "sensitive"))
            self.assertIs(matching_baseline_rule({"hook_name": "file_open"}, "other"), catch_all)

    def test_packaged_yaml_declares_baseline_rules(self) -> None:
        """随包 YAML 声明了全部基线规则，平台地址不是基线端点。"""
        ids = {rule.id for rule in rules.BASELINE_RULES}
        self.assertTrue(
            {"nss_unix_socket", "netlink_socket", "dynamic_loader_open", "runtime_mprotect", "pathless_file_hook"}
            <= ids
        )
        self.assertTrue(is_baseline_endpoint("AF_UNIX /var/run/nscd/socket"))
        self.assertFalse(is_baseline_endpoint("AF_INET 8.152.192.7:15100"))

    def test_only_two_loopback_endpoints_are_ignored(self) -> None:
        """忽略端点只有 127.0.0.1:15100 与 localhost:15100。"""
        self.assertEqual(set(rules.IGNORED_NETWORK_ENDPOINTS), {"127.0.0.1:15100", "localhost:15100"})

    def test_malformed_yaml_is_logged_as_error(self) -> None:
        """YAML 语法错误时输出 ERROR 日志，不再静默回退。"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.yaml"
            path.write_text("files: [unclosed\n", encoding="utf-8")
            with self.assertLogs("lha_realtime_rules", level=logging.ERROR):
                self.assertEqual(rules._load_yaml(path), {})


class PerEndpointNetworkTest(unittest.TestCase):
    def test_nss_socket_only_round_is_suppressed(self) -> None:
        """只连 nscd 的 round 整轮网络按正常处理，端点记为系统基线。"""
        observed = parse_network_activity(
            [lsm_hook("h-5", "socket_sendmsg")],
            [connect("c-1", 3, 1, sun_path="/var/run/nscd/socket"), io("sendto", "s-2", 3, 2)],
        )
        self.assertTrue(observed["suppressed"])
        self.assertEqual(observed["actions"], set())
        self.assertEqual(observed["baseline_endpoints"], {"/var/run/nscd/socket"})
        self.assertEqual(observed["ignored_endpoints"], set())

    def test_actions_on_excluded_endpoints_do_not_count_when_another_endpoint_exists(self) -> None:
        """send 落在忽略端点、receive 落在外部端点：只有 receive 计入判定。"""
        observed = parse_network_activity(
            [],
            [
                connect("c-1", 3, 1, remote_ip="127.0.0.1", remote_port="15100"),
                connect("c-2", 4, 2, remote_ip="8.8.8.8", remote_port=53),
                io("sendto", "s-3", 3, 3),
                io("recvfrom", "s-4", 4, 4),
            ],
        )
        self.assertFalse(observed["suppressed"])
        self.assertEqual(observed["actions"], {"receive"})
        self.assertEqual(observed["observed_actions"], {"send", "receive"})
        self.assertEqual(observed["endpoints"], {"8.8.8.8:53"})

    def test_unattributed_actions_still_count_when_another_endpoint_exists(self) -> None:
        """LSM 层 sendmsg 不带地址，出现未排除端点时必须保守计入。"""
        observed = parse_network_activity(
            [lsm_hook("h-5", "socket_sendmsg")],
            [connect("c-1", 4, 1, remote_ip="8.152.192.7", remote_port="15100")],
        )
        self.assertEqual(observed["actions"], {"send"})
        self.assertEqual(observed["endpoints"], {"8.152.192.7:15100"})


class BaselineFoldingRoundTest(unittest.TestCase):
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

    def test_system_noise_is_folded_and_suspicious_items_are_kept(self) -> None:
        """系统噪声折叠；敏感文件、可疑库、库目录写入、bprm_check 照常列出。"""
        self.write_round(
            [
                lsm_hook("h-1", "file_mprotect", path="/usr/lib64/libc.so.6"),
                lsm_hook("h-2", "file_mprotect", path="/usr/lib64/libc.so.6"),
                lsm_hook("h-3", "file_mprotect", path="/tmp/evil.so"),
                lsm_hook("h-4", "file_permission"),
                lsm_hook("h-5", "socket_create", args={"family": "AF_NETLINK"}),
                lsm_hook("h-6", "socket_connect",
                         args={"sa_family": "AF_UNIX", "remote_addr": {"sun_path": "/var/run/nscd/socket"}}),
                lsm_hook("h-7", "file_open", path="/root/.ssh/id_rsa", args={"flags": "O_RDONLY"}),
                lsm_hook("h-8", "file_open", path="/usr/lib64/libc.so.6", args={"flags": "O_RDONLY|O_CLOEXEC"}),
                # 写入共享库目录命中 binary_directory_write（敏感），绝不能被加载噪声规则吞掉。
                lsm_hook("h-9", "file_open", path="/usr/lib64/libevil.so", args={"flags": "O_WRONLY|O_CREAT"}),
                lsm_hook("h-10", "bprm_check", path="/usr/bin/curl"),
            ]
        )
        result = analyze_round(self.round_dir)

        folded = {entry["id"]: entry["count"] for entry in result["suppressed"]}
        self.assertEqual(
            folded,
            {"runtime_mprotect": 2, "pathless_file_hook": 1, "netlink_socket": 1, "nss_unix_socket": 1,
             "dynamic_loader_open": 1},
        )
        self.assertEqual(result["counts"]["suppressed"], 6)
        kept = sorted(v["path"] for v in result["violations"])
        self.assertEqual(kept, ["/root/.ssh/id_rsa", "/tmp/evil.so", "/usr/bin/curl", "/usr/lib64/libevil.so"])
        self.assertEqual(result["counts"]["violations"], 4)
        self.assertTrue(result["is_anomaly"])
        # 同一路径的折叠样例去重。
        mprotect = next(e for e in result["suppressed"] if e["id"] == "runtime_mprotect")
        self.assertEqual(mprotect["samples"], ["/usr/lib64/libc.so.6"])

    def test_ignored_endpoint_ops_are_folded_but_platform_endpoint_is_flagged(self) -> None:
        """127.0.0.1:15100 的操作折叠，8.152.192.7:15100 照常判异常。"""
        self.write_round(
            [
                lsm_hook("h-1", "socket_connect", args={"sa_family": "AF_INET",
                         "remote_addr": {"sin_addr": "127.0.0.1", "sin_port": "15100"}}),
                lsm_hook("h-2", "socket_connect", args={"sa_family": "AF_INET",
                         "remote_addr": {"sin_addr": "8.152.192.7", "sin_port": "15100"}}),
                lsm_hook("h-3", "socket_sendmsg"),
            ],
            [connect("c-1", 3, 1, remote_ip="8.152.192.7", remote_port="15100")],
        )
        result = analyze_round(self.round_dir)

        self.assertEqual([e["id"] for e in result["suppressed"]], ["ignored_network_endpoint"])
        self.assertTrue(result["is_anomaly"])
        self.assertEqual(result["network_endpoints"], ["8.152.192.7:15100"])

    def test_report_renders_folded_summary(self) -> None:
        """报告头部注明折叠条数，文末渲染折叠汇总表，violations.jsonl 不含折叠项。"""
        self.write_round(
            [
                lsm_hook("h-1", "file_mprotect", path="/usr/lib64/libc.so.6"),
                lsm_hook("h-2", "socket_connect",
                         args={"sa_family": "AF_UNIX", "remote_addr": {"sun_path": "/var/run/nscd/socket"}}),
                lsm_hook("h-3", "socket_sendmsg"),
            ],
            [connect("c-1", 3, 1, sun_path="/var/run/nscd/socket"), io("sendto", "s-2", 3, 2)],
        )
        result = analyze_round(self.round_dir)
        _, report_path = write_outputs(self.round_dir, result)
        report = report_path.read_text(encoding="utf-8")

        self.assertFalse(result["is_anomaly"])
        self.assertIn("另有 2 条系统基线行为已折叠，见文末汇总", report)
        self.assertIn("## 已折叠的系统基线行为", report)
        self.assertIn("| 运行时库内存保护变更 (`runtime_mprotect`) |", report)
        self.assertIn("系统基线端点 `/var/run/nscd/socket`（本机 NSS 查询等）", report)
        violations = (self.round_dir / "analysis_violations.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("file_mprotect", violations)

    def test_report_without_folds_omits_the_section(self) -> None:
        """没有折叠项时不渲染汇总段，也不加头部注释。"""
        self.write_round([lsm_hook("h-1", "file_open", path="/tmp/a.txt", args={"flags": "O_RDONLY"})])
        _, report_path = write_outputs(self.round_dir, analyze_round(self.round_dir))
        report = report_path.read_text(encoding="utf-8")
        self.assertNotIn("已折叠的系统基线行为", report)
        self.assertNotIn("系统基线行为已折叠", report)


if __name__ == "__main__":
    unittest.main()
