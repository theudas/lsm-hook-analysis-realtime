#!/usr/bin/env python3
"""白盒用例：analyzer.write_outputs 的 Markdown 报告渲染分支。

报告生成是 analyzer 里最长的一段顺序逻辑，且每个分支都直接决定交付给前端的
内容。这里直接构造 result 结构驱动渲染，逐个覆盖：异常类型三种渲染、文件越权
四种分类表、网络三种分组、忽略端点抑制、内核资源事实表。
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from lha_realtime.analyzer import write_outputs


def make_result(**overrides) -> dict:
    result = {
        "round_id": "rpt",
        "session_key": "agent:main:main",
        "time_start": "2026-06-16 10:00:00+0800",
        "time_end": "2026-06-16 10:00:01+0800",
        "overall_score": 0.5,
        "tool_name": "cmd_executor__exec_command",
        "allowed_files": [],
        "allowed_tools": [],
        "file_actions": {},
        "allowed_networks": [],
        "allowed_network_actions": [],
        "network_observed": [],
        "network_endpoints": [],
        "network_suppressed": False,
        "network_ignored_endpoints": [],
        "is_anomaly": False,
        "anomaly_types": [],
        "user_actions": [],
        "resource_facts": [],
        "counts": {
            "lsm_total": 0,
            "syscall_total": 0,
            "kernel_file_ops": 0,
            "violations": 0,
            "judge_mismatch": 0,
        },
        "violations": [],
    }
    result.update(overrides)
    return result


def file_violation(**overrides) -> dict:
    violation = {
        "path": "/tmp/a.txt",
        "hook_name": "file_open",
        "result": "allow",
        "category": "other",
        "observed_actions": ["read"],
        "read_bytes": 0,
        "judges_agree": True,
        "is_network": False,
    }
    violation.update(overrides)
    return violation


def net_violation(**overrides) -> dict:
    violation = {
        "path": None,
        "hook_name": "socket_sendmsg",
        "result": "allow",
        "category": "unknown",
        "observed_actions": ["read"],
        "read_bytes": 0,
        "judges_agree": True,
        "is_network": True,
        "net_detail": "AF_INET 8.8.8.8:53",
    }
    violation.update(overrides)
    return violation


class ReportRenderingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.round_dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def render(self, result: dict) -> str:
        violations_path, report_path = write_outputs(self.round_dir, result)
        self.assertTrue(violations_path.is_file())
        self.assertTrue(report_path.is_file())
        return report_path.read_text(encoding="utf-8")

    # ---------- 判定结论段 ----------

    def test_clean_round_reports_no_anomaly(self) -> None:
        """无异常的 round 报告写明「否」「无」，且含报告生成时间。"""
        report = self.render(make_result())
        self.assertIn("- 是否异常: 否", report)
        self.assertIn("- 异常类型: 无", report)
        self.assertIn("报告生成时间", report)
        self.assertIn("### 文件\n\n无", report)
        self.assertIn("### 网络\n\n无", report)

    def test_sensitive_anomaly_groups_paths_and_prints_rationale(self) -> None:
        """同一敏感分组的多个路径聚合成一条，并输出判定理由与规则依据。"""
        result = make_result(
            is_anomaly=True,
            anomaly_types=[
                {
                    "type": "访问危险文件（敏感越权）",
                    "paths": ["/etc/shadow", "/root/.ssh/id_rsa"],
                    "items": [
                        {
                            "path": "/etc/shadow",
                            "rule": "credential_store",
                            "title": "系统口令散列与提权授权库",
                            "severity": "critical",
                            "attck": ["T1003.008", "T1548.003"],
                            "reason": "读取即等价于拿到凭据",
                            "basis": "Falco sensitive_file_names",
                            "actions": ["read"],
                        },
                        {
                            "path": "/etc/sudoers",
                            "rule": "credential_store",
                            "title": "系统口令散列与提权授权库",
                            "severity": "critical",
                            "attck": ["T1003.008"],
                            "reason": "读取即等价于拿到凭据",
                            "basis": "Falco sensitive_file_names",
                            "actions": [],
                        },
                    ],
                }
            ],
        )
        report = self.render(result)
        self.assertIn("- 是否异常: 是", report)
        self.assertIn("[critical] 系统口令散列与提权授权库，ATT&CK T1003.008/T1548.003 — 命中 2 个路径", report)
        self.assertIn("`/etc/shadow`（read）", report)
        # 无动作的条目不带括号。
        self.assertIn("      - `/etc/sudoers`\n", report)
        self.assertIn("判定理由: 读取即等价于拿到凭据", report)
        self.assertIn("规则依据: Falco sensitive_file_names", report)

    def test_sensitive_anomaly_without_metadata_falls_back_to_defaults(self) -> None:
        """缺少标题/等级时退化为「敏感资源」与 high，不输出空理由。"""
        result = make_result(
            is_anomaly=True,
            anomaly_types=[
                {
                    "type": "访问危险文件（敏感越权）",
                    "paths": ["/x"],
                    "items": [{"path": "/x", "rule": None, "title": None, "actions": ["read"]}],
                }
            ],
        )
        report = self.render(result)
        self.assertIn("[high] 敏感资源 — 命中 1 个路径", report)
        self.assertNotIn("判定理由", report)
        self.assertNotIn("规则依据", report)

    def test_sensitive_anomaly_with_empty_items_list(self) -> None:
        """items 为空或 None 时标题仍渲染，不抛异常。"""
        result = make_result(
            is_anomaly=True,
            anomaly_types=[{"type": "访问危险文件（敏感越权）", "paths": [], "items": None}],
        )
        report = self.render(result)
        self.assertIn("访问危险文件（敏感越权）:", report)

    def test_file_action_mismatch_is_rendered_with_event_id(self) -> None:
        """文件未授权动作一行写清允许集、实际动作与 event_id。"""
        result = make_result(
            is_anomaly=True,
            anomaly_types=[
                {
                    "type": "文件访问出现未授权动作",
                    "items": [
                        {
                            "path": "/workspace/a.py",
                            "allowed": ["read"],
                            "extra": ["write"],
                            "hook_name": "file_open",
                            "event_id": 42,
                        }
                    ],
                }
            ],
        )
        report = self.render(result)
        self.assertIn("`/workspace/a.py` 允许[read] 实际出现[write]（event_id 42）", report)

    def test_all_three_anomaly_types_render_together(self) -> None:
        # 三类异常同时命中时，渲染循环必须依次处理完每一项而不是在第一项后停下。
        result = make_result(
            is_anomaly=True,
            anomaly_types=[
                {
                    "type": "访问危险文件（敏感越权）",
                    "paths": ["/etc/shadow"],
                    "items": [{"path": "/etc/shadow", "rule": "credential_store",
                               "title": "口令库", "severity": "critical", "actions": ["read"]}],
                },
                {
                    "type": "文件访问出现未授权动作",
                    "items": [{"path": "/w/a.py", "allowed": ["read"], "extra": ["write"],
                               "hook_name": "file_open", "event_id": 1}],
                },
                {
                    "type": "网络访问出现未授权动作",
                    "allowed": [],
                    "extra": ["send"],
                    "endpoints": ["8.8.8.8:53"],
                },
            ],
        )
        report = self.render(result)
        self.assertIn("[critical] 口令库 — 命中 1 个路径", report)
        self.assertIn("`/w/a.py` 允许[read] 实际出现[write]（event_id 1）", report)
        self.assertIn("网络访问出现未授权动作: 允许[] 实际出现[send]，目标 8.8.8.8:53", report)

    def test_network_mismatch_with_and_without_endpoints(self) -> None:
        """网络未授权动作在有/无目标端点两种情况下的渲染。"""
        with_endpoints = self.render(
            make_result(
                is_anomaly=True,
                anomaly_types=[
                    {
                        "type": "网络访问出现未授权动作",
                        "allowed": ["send"],
                        "extra": ["receive"],
                        "endpoints": ["8.8.8.8:53"],
                    }
                ],
            )
        )
        self.assertIn("允许[send] 实际出现[receive]，目标 8.8.8.8:53", with_endpoints)

        without_endpoints = self.render(
            make_result(
                is_anomaly=True,
                anomaly_types=[
                    {"type": "网络访问出现未授权动作", "allowed": [], "extra": ["send"], "endpoints": []}
                ],
            )
        )
        self.assertIn("允许[] 实际出现[send]", without_endpoints)
        self.assertNotIn("目标", without_endpoints.split("## 用户态允许集")[0])

    def test_unrecognised_anomaly_type_is_skipped_without_breaking_the_report(self) -> None:
        # 渲染器只认三种类型；将来新增类型时不应让报告生成失败，而是安静跳过。
        result = make_result(
            is_anomaly=True,
            anomaly_types=[
                {"type": "尚未支持的新类型", "items": []},
                {
                    "type": "网络访问出现未授权动作",
                    "allowed": [],
                    "extra": ["send"],
                    "endpoints": [],
                },
            ],
        )
        report = self.render(result)
        self.assertNotIn("尚未支持的新类型", report)
        self.assertIn("实际出现[send]", report)

    # ---------- 允许集与用户态行为段 ----------

    def test_allowlist_and_user_actions_are_listed(self) -> None:
        """IR 允许文件/工具与用户态实际调用被完整列出。"""
        result = make_result(
            allowed_files=["/workspace/**"],
            file_actions={"/workspace/**": ["read", "write"]},
            allowed_tools=["exec"],
            user_actions=[{"tool": "exec", "arguments": {"cmd": "ls"}, "resources": []}],
        )
        report = self.render(result)
        self.assertIn("`/workspace/**` （动作: read, write）", report)
        self.assertIn("允许工具: `exec`", report)
        self.assertIn('`exec` {"cmd": "ls"}', report)

    # ---------- 文件越权清单 ----------

    def test_all_four_categories_render_their_own_table(self) -> None:
        """敏感/其他/运行时/未知四类各出一张表，敏感表多一列依据。"""
        result = make_result(
            violations=[
                file_violation(path="/etc/shadow", category="sensitive", read_bytes=32,
                               sensitive_title="系统口令散列与提权授权库",
                               sensitive_severity="critical", sensitive_attck=["T1003.008"]),
                file_violation(path="/srv/data", category="other"),
                file_violation(path="/usr/lib/libc.so", category="runtime"),
                file_violation(path=None, category="unknown"),
            ],
            counts={"lsm_total": 4, "syscall_total": 0, "kernel_file_ops": 4,
                    "violations": 4, "judge_mismatch": 1},
        )
        report = self.render(result)
        self.assertIn("#### 敏感资源（1 个路径 / 1 次）", report)
        self.assertIn("| path | 敏感依据 | hook | 动作 | 次数 | 读取字节 | 判据一致 |", report)
        self.assertIn("系统口令散列与提权授权库（critical，ATT&CK T1003.008）", report)
        self.assertIn("#### 其他（1 个路径 / 1 次）", report)
        self.assertIn("#### 运行时加载（1 个路径 / 1 次）", report)
        self.assertIn("#### 未知路径（1 个路径 / 1 次）", report)
        self.assertIn("| path | hook | 动作 | 次数 | 读取字节 | 判据一致 |", report)

    def test_sensitive_entry_without_attck_omits_the_suffix(self) -> None:
        """没有 ATT&CK 编号时依据列不拼接空后缀。"""
        result = make_result(
            violations=[
                file_violation(path="/etc/shadow", category="sensitive",
                               sensitive_title="口令库", sensitive_severity=None, sensitive_attck=[])
            ]
        )
        report = self.render(result)
        self.assertIn("口令库（high）", report)

    def test_conflicting_judges_on_one_path_render_as_partial(self) -> None:
        """同一路径两个判据结论不一致时判据列显示「部分」。"""
        result = make_result(
            violations=[
                file_violation(path="/srv/a", judges_agree=True, read_bytes=10),
                file_violation(path="/srv/a", judges_agree=False, read_bytes=5, hook_name="inode_unlink"),
                file_violation(path="/srv/b", judges_agree=False),
            ]
        )
        report = self.render(result)
        self.assertIn("| `/srv/a` | file_open, inode_unlink | read | 2 | 15 | 部分 |", report)
        self.assertIn("| `/srv/b` | file_open | read | 1 | 0 | no |", report)

    def test_read_bytes_none_is_treated_as_zero(self) -> None:
        report = self.render(make_result(violations=[file_violation(read_bytes=None)]))
        self.assertIn("| 1 | 0 |", report)

    # ---------- 网络越权清单 ----------

    def test_network_groups_are_rendered_in_fixed_order(self) -> None:
        """网络表按数据收发→连接管理→其他固定顺序输出。"""
        result = make_result(
            violations=[
                net_violation(hook_name="socket_sendmsg"),
                net_violation(hook_name="socket_sendmsg"),
                net_violation(hook_name="socket_connect", net_detail=None),
                net_violation(hook_name="socket_setsockopt", net_detail="AF_INET"),
            ]
        )
        report = self.render(result)
        self.assertIn("#### 数据收发 (2)", report)
        self.assertIn("| 数据发送 | socket_sendmsg | AF_INET 8.8.8.8:53 | allow | 2 |", report)
        self.assertIn("#### 连接管理 (1)", report)
        self.assertIn("| 发起连接 | socket_connect | - | allow | 1 |", report)
        self.assertIn("#### 其他 (1)", report)
        self.assertIn("| 设置选项 | socket_setsockopt |", report)
        network_section = report.split("### 网络")[1]
        self.assertLess(network_section.index("数据收发"), network_section.index("连接管理"))

    def test_unknown_network_hook_uses_its_own_name_as_behavior(self) -> None:
        """未登记的 socket hook 用自身名称作为行为描述。"""
        report = self.render(make_result(violations=[net_violation(hook_name="socket_weird")]))
        self.assertIn("| socket_weird | socket_weird |", report)

    def test_suppressed_network_reports_ignored_endpoints(self) -> None:
        """整轮网络被抑制时说明原因并列出忽略端点。"""
        report = self.render(
            make_result(
                network_suppressed=True,
                network_ignored_endpoints=["127.0.0.1:15100"],
                violations=[net_violation()],
            )
        )
        self.assertIn("无（本轮网络连接目标均为忽略端点：`127.0.0.1:15100`，为工具拉取线上配置，按正常处理）", report)

    def test_suppressed_network_without_listed_endpoints(self) -> None:
        report = self.render(make_result(network_suppressed=True, network_ignored_endpoints=[]))
        self.assertIn("无（本轮网络连接目标均为忽略端点，为工具拉取线上配置，按正常处理）", report)

    # ---------- 内核资源事实 ----------

    def test_resource_facts_table_is_appended_when_present(self) -> None:
        """内核资源事实表正常渲染，缺字段退化为空单元格。"""
        result = make_result(
            resource_facts=[
                {
                    "path": "/etc/hosts",
                    "actions": ["read"],
                    "open_count": 2,
                    "read_count": 3,
                    "read_returned_bytes": 512,
                    "lsm_allow_count": 2,
                },
                {"path": "/etc/partial"},
            ]
        )
        report = self.render(result)
        self.assertIn("## 内核资源事实佐证", report)
        self.assertIn("| `/etc/hosts` | read | 2 | 3 | 512 | 2 |", report)
        # 缺字段的事实退化成空单元格而不是报错。
        self.assertIn("| `/etc/partial` |  |  |  |  |  |", report)

    # ---------- 违规明细落盘 ----------

    def test_violations_jsonl_carries_round_id_on_every_line(self) -> None:
        """违规明细每行都带 round_id，便于后续汇总。"""
        result = make_result(violations=[file_violation(path="/a"), file_violation(path="/b")])
        write_outputs(self.round_dir, result)
        lines = (self.round_dir / "analysis_violations.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        for line in lines:
            self.assertEqual(json.loads(line)["round_id"], "rpt")

    def test_rewriting_outputs_truncates_the_previous_run(self) -> None:
        """重跑分析时覆盖写，不残留上一次的违规记录。"""
        write_outputs(self.round_dir, make_result(violations=[file_violation(path="/a")]))
        write_outputs(self.round_dir, make_result(violations=[]))
        self.assertEqual((self.round_dir / "analysis_violations.jsonl").read_text(encoding="utf-8"), "")


if __name__ == "__main__":
    unittest.main()
