#!/usr/bin/env python3
"""白盒用例：analyzer 的输入加载、IR 解析、内核事件归并与分类判定分支。

覆盖目标是 analyzer 中不经由 analyze_round 主链路就无法触达的分支：
文件缺失/损坏、IR 回退、字节归属的 fd 复用边界、网络端点回溯等。
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lha_realtime import analyzer


class LoaderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_file_size_returns_zero_for_missing_path(self) -> None:
        """文件不存在时 file_size 返回 0 而不是抛异常。"""
        self.assertEqual(analyzer.file_size(self.root / "nope.json"), 0)

    def test_load_json_file_missing_returns_empty_dict(self) -> None:
        """JSON 文件缺失时返回空字典，分析链路继续。"""
        self.assertEqual(analyzer.load_json_file(self.root / "missing.json"), {})

    def test_load_json_file_propagates_decode_error(self) -> None:
        """JSON 内容损坏时向上抛出，由 worker 转为可重试失败。"""
        path = self.root / "bad.json"
        path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(json.JSONDecodeError):
            analyzer.load_json_file(path)

    def test_load_jsonl_missing_returns_empty_list(self) -> None:
        """JSONL 文件缺失时返回空列表。"""
        self.assertEqual(analyzer.load_jsonl(self.root / "missing.jsonl"), [])

    def test_load_jsonl_skips_blank_lines(self) -> None:
        """JSONL 中的空行与纯空白行被跳过。"""
        path = self.root / "rows.jsonl"
        path.write_text('{"a": 1}\n\n   \n{"a": 2}\n', encoding="utf-8")
        self.assertEqual(analyzer.load_jsonl(path), [{"a": 1}, {"a": 2}])

    def test_load_jsonl_propagates_decode_error(self) -> None:
        """JSONL 存在非法行时抛出解析错误并记录行号。"""
        path = self.root / "bad.jsonl"
        path.write_text('{"a": 1}\nnot-json\n', encoding="utf-8")
        with self.assertRaises(json.JSONDecodeError):
            analyzer.load_jsonl(path)


class LoadIrSourceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.round_dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_prefers_standalone_ir_json(self) -> None:
        """IR 优先取独立的 ir.json，而不是 round_end 里的副本。"""
        (self.round_dir / "ir.json").write_text(
            json.dumps({"ir_json": json.dumps({"policies": []})}), encoding="utf-8"
        )
        source = analyzer.load_ir_source(self.round_dir, {"ir_json": "from-round-end"})
        self.assertNotEqual(source["ir_json"], "from-round-end")

    def test_empty_ir_json_falls_back_to_round_end(self) -> None:
        """ir.json 存在但内容为空时回退到 round_end.ir_json。"""
        (self.round_dir / "ir.json").write_text(json.dumps({"ir_json": ""}), encoding="utf-8")
        source = analyzer.load_ir_source(self.round_dir, {"ir_json": "from-round-end"})
        self.assertEqual(source["ir_json"], "from-round-end")

    def test_reads_round_end_from_disk_when_not_supplied(self) -> None:
        """未传入 round_end 时自行从磁盘读取。"""
        (self.round_dir / "round_end.json").write_text(
            json.dumps({"ir_json": json.dumps({"policies": []})}), encoding="utf-8"
        )
        self.assertTrue(analyzer.load_ir_source(self.round_dir).get("ir_json"))

    def test_returns_empty_dict_when_no_ir_anywhere(self) -> None:
        """两处都没有 IR 时返回空字典。"""
        self.assertEqual(analyzer.load_ir_source(self.round_dir, {}), {})


class ParseAllowlistTest(unittest.TestCase):
    @staticmethod
    def source(ir: dict) -> dict:
        return {"ir_json": json.dumps(ir)}

    def test_missing_ir_json_yields_empty_allowlist(self) -> None:
        """缺少 ir_json 时得到空允许集，不误放行。"""
        allowed = analyzer.parse_allowlist({})
        self.assertEqual(allowed["files"], set())
        self.assertEqual(allowed["tools"], set())
        self.assertEqual(allowed["networks"], set())

    def test_deny_policies_are_skipped(self) -> None:
        """effect 非 allow 的策略不进入允许集。"""
        allowed = analyzer.parse_allowlist(
            self.source(
                {
                    "policies": [
                        {
                            "effect": "deny",
                            "objects": [{"type": "file", "identifier": "/tmp/x", "actions": ["read"]}],
                        }
                    ]
                }
            )
        )
        self.assertEqual(allowed["files"], set())

    def test_level2_policies_take_precedence_over_top_level(self) -> None:
        """level2.policies 优先于顶层 policies。"""
        allowed = analyzer.parse_allowlist(
            self.source(
                {
                    "level2": {
                        "policies": [
                            {
                                "effect": "allow",
                                "objects": [{"type": "file", "identifier": "/l2", "actions": ["read"]}],
                            }
                        ]
                    },
                    "policies": [
                        {
                            "effect": "allow",
                            "objects": [{"type": "file", "identifier": "/top", "actions": ["read"]}],
                        }
                    ],
                }
            )
        )
        self.assertEqual(allowed["files"], {"/l2"})

    def test_empty_file_identifier_is_ignored(self) -> None:
        """空的 file identifier 被忽略，不会变成万能放行。"""
        allowed = analyzer.parse_allowlist(
            self.source(
                {
                    "policies": [
                        {
                            "effect": "allow",
                            "objects": [
                                {"type": "file", "identifier": "", "actions": ["read"]},
                                {"type": "file", "identifier": None, "actions": ["read"]},
                            ],
                        }
                    ]
                }
            )
        )
        self.assertEqual(allowed["files"], set())

    def test_duplicate_actions_are_deduplicated_in_order(self) -> None:
        """同一路径的多条策略动作合并去重且保序。"""
        allowed = analyzer.parse_allowlist(
            self.source(
                {
                    "policies": [
                        {
                            "effect": "allow",
                            "objects": [
                                {"type": "file", "identifier": "/tmp/a", "actions": ["read", "write"]},
                                {"type": "file", "identifier": "/tmp/a", "actions": ["read", "delete"]},
                            ],
                        }
                    ]
                }
            )
        )
        self.assertEqual(allowed["file_actions"]["/tmp/a"], ["read", "write", "delete"])

    def test_tool_and_network_objects_are_collected(self) -> None:
        """tool 与 network 类型对象分别归集，未知类型被忽略。"""
        allowed = analyzer.parse_allowlist(
            self.source(
                {
                    "policies": [
                        {
                            "effect": "allow",
                            "objects": [
                                {"type": "tool", "identifier": "cmd_executor__exec_command"},
                                {"type": "network", "identifier": "api.example.com", "actions": ["send"]},
                                {"type": "network", "identifier": "", "actions": ["receive"]},
                                {"type": "unknown_kind", "identifier": "ignored"},
                            ],
                        }
                    ]
                }
            )
        )
        self.assertEqual(allowed["tools"], {"cmd_executor__exec_command"})
        self.assertEqual(allowed["networks"], {"api.example.com"})
        # 空 identifier 的网络对象不进入 networks，但其 actions 仍计入允许动作集。
        self.assertEqual(allowed["network_actions"], {"send", "receive"})


class ParseUserActionsAndFactsTest(unittest.TestCase):
    def test_parse_user_actions_defaults_missing_fields(self) -> None:
        """action_json 缺字段时 arguments/resources 退化为空值。"""
        actions = analyzer.parse_user_actions({"action_json": json.dumps([{"tool": "exec"}])})
        self.assertEqual(actions, [{"tool": "exec", "arguments": {}, "resources": []}])

    def test_parse_user_actions_handles_missing_key(self) -> None:
        """round_end 没有 action_json 时返回空列表。"""
        self.assertEqual(analyzer.parse_user_actions({}), [])

    def test_parse_resource_facts_empty_raw(self) -> None:
        """kernel_resource_facts 缺失或为空串时返回空列表。"""
        self.assertEqual(analyzer.parse_resource_facts({}), [])
        self.assertEqual(analyzer.parse_resource_facts({"kernel_resource_facts": ""}), [])

    def test_parse_resource_facts_valid(self) -> None:
        """正常的 kernel_resource_facts 被解析为事实列表。"""
        raw = json.dumps({"resource_facts": [{"path": "/tmp/a"}]})
        self.assertEqual(analyzer.parse_resource_facts({"kernel_resource_facts": raw}), [{"path": "/tmp/a"}])

    def test_parse_resource_facts_broken_json_returns_empty(self) -> None:
        self.assertEqual(analyzer.parse_resource_facts({"kernel_resource_facts": "{oops"}), [])

    def test_parse_resource_facts_non_object_json_returns_empty(self) -> None:
        # json.loads 成功但结果是 list，.get 抛 AttributeError，同样必须兜住。
        self.assertEqual(analyzer.parse_resource_facts({"kernel_resource_facts": "[1, 2]"}), [])


class NetworkHelperTest(unittest.TestCase):
    def test_is_network_hook(self) -> None:
        """按 socket_ 前缀识别网络类 LSM hook，None 不误判。"""
        self.assertTrue(analyzer.is_network_hook("socket_connect"))
        self.assertFalse(analyzer.is_network_hook("file_open"))
        self.assertFalse(analyzer.is_network_hook(None))

    def test_network_hook_actions_only_maps_send_and_recv(self) -> None:
        """只有 sendmsg/recvmsg 映射到 IR 动作，connect 等不产生动作。"""
        self.assertEqual(analyzer.network_hook_actions("socket_sendmsg"), {"send"})
        self.assertEqual(analyzer.network_hook_actions("socket_recvmsg"), {"receive"})
        self.assertEqual(analyzer.network_hook_actions("socket_connect"), set())

    def test_net_group_covers_all_three_buckets(self) -> None:
        """网络 hook 归入数据收发/连接管理/其他三组。"""
        self.assertEqual(analyzer.net_group("socket_sendmsg"), "数据收发")
        self.assertEqual(analyzer.net_group("socket_connect"), "连接管理")
        self.assertEqual(analyzer.net_group("socket_setsockopt"), "其他")

    def test_network_detail_returns_empty_for_file_hook(self) -> None:
        """文件类 hook 不产生网络目标描述。"""
        self.assertEqual(analyzer.network_detail({"hook_name": "file_open"}), "")

    def test_network_detail_unix_socket_path(self) -> None:
        """Unix 域套接字取 sun_path 作为目标。"""
        detail = analyzer.network_detail(
            {"hook_name": "socket_connect", "args": {"family": "AF_UNIX", "sun_path": "/run/x.sock"}}
        )
        self.assertEqual(detail, "AF_UNIX /run/x.sock")

    def test_network_detail_ipv4_with_and_without_port(self) -> None:
        """IPv4 目标带端口时拼成 ip:port，无端口时只留 ip。"""
        with_port = analyzer.network_detail(
            {
                "hook_name": "socket_connect",
                "args": {"family": "AF_INET", "remote_addr": {"sin_addr": "10.0.0.1", "sin_port": 80}},
            }
        )
        self.assertEqual(with_port, "AF_INET 10.0.0.1:80")
        without_port = analyzer.network_detail(
            {"hook_name": "socket_connect", "args": {"sin_addr": "10.0.0.2"}}
        )
        self.assertEqual(without_port, "10.0.0.2")

    def test_network_detail_ipv6(self) -> None:
        """IPv6 目标从 sin6_addr/sin6_port 提取。"""
        detail = analyzer.network_detail(
            {
                "hook_name": "socket_connect",
                "args": {"family": "AF_INET6", "remote_addr": {"sin6_addr": "::1", "sin6_port": 15100}},
            }
        )
        self.assertEqual(detail, "AF_INET6 ::1:15100")

    def test_network_detail_without_any_target(self) -> None:
        """无任何地址信息时返回空串。"""
        self.assertEqual(analyzer.network_detail({"hook_name": "socket_create", "args": {}}), "")


class ConnectEndpointsTest(unittest.TestCase):
    def test_non_connect_syscalls_are_ignored(self) -> None:
        """只有 connect 系统调用参与端点表构建。"""
        self.assertEqual(analyzer.connect_endpoints([{"action": "read", "pid": 1, "fd": 3}]), {})

    def test_unix_socket_connect_uses_sun_path(self) -> None:
        """没有 remote_ip 时退回 sun_path 作为端点。"""
        conns = analyzer.connect_endpoints(
            [
                {
                    "action": "connect",
                    "pid": 1,
                    "fd": 3,
                    "timestamp_mono_ns": 5,
                    "args": {"sun_path": "/run/docker.sock"},
                }
            ]
        )
        self.assertEqual(conns[(1, 3)], [(5, "/run/docker.sock")])

    def test_sockfd_arg_wins_over_top_level_fd(self) -> None:
        """端点按 args.sockfd 归属，优先于顶层 fd。"""
        conns = analyzer.connect_endpoints(
            [
                {
                    "action": "connect",
                    "pid": 1,
                    "fd": 99,
                    "timestamp_mono_ns": 1,
                    "args": {"remote_ip": "1.2.3.4", "remote_port": 443, "sockfd": 7},
                }
            ]
        )
        self.assertEqual(conns[(1, 7)], [(1, "1.2.3.4:443")])


class ParseNetworkActivityTest(unittest.TestCase):
    def test_endpoint_lookup_picks_latest_connect_before_the_send(self) -> None:
        """send 关联的是它之前最近一次 connect，而非之后的连接。"""
        syscalls = [
            {
                "action": "connect",
                "event_id": 1,
                "pid": 1,
                "fd": 3,
                "timestamp_mono_ns": 10,
                "args": {"remote_ip": "1.1.1.1", "remote_port": 80, "sockfd": 3},
            },
            {
                "action": "connect",
                "event_id": 2,
                "pid": 1,
                "fd": 3,
                "timestamp_mono_ns": 30,
                "args": {"remote_ip": "2.2.2.2", "remote_port": 80, "sockfd": 3},
            },
            {"action": "sendto", "event_id": 3, "pid": 1, "fd": 3, "timestamp_mono_ns": 20},
        ]
        observed = analyzer.parse_network_activity([], syscalls)
        # send 发生在 t=20：应关联 t=10 的连接，而不是之后 t=30 的那次。
        self.assertIn("1.1.1.1:80", observed["all_endpoints"])
        self.assertEqual(observed["observed_actions"], {"send"})

    def test_send_before_any_connect_falls_back_to_first_record(self) -> None:
        """收发早于所有 connect 记录时回退到第一条连接。"""
        syscalls = [
            {
                "action": "connect",
                "event_id": 1,
                "pid": 1,
                "fd": 3,
                "timestamp_mono_ns": 100,
                "args": {"remote_ip": "9.9.9.9", "remote_port": 53, "sockfd": 3},
            },
            {"action": "recvfrom", "event_id": 2, "pid": 1, "fd": 3, "timestamp_mono_ns": 1},
        ]
        observed = analyzer.parse_network_activity([], syscalls)
        self.assertEqual(observed["observed_actions"], {"receive"})
        self.assertIn("9.9.9.9:53", observed["all_endpoints"])

    def test_unknown_fd_send_records_action_without_endpoint(self) -> None:
        """fd 无法关联端点时仍记录动作，不做整轮抑制。"""
        observed = analyzer.parse_network_activity(
            [], [{"action": "send", "event_id": 1, "pid": 1, "fd": 42, "timestamp_mono_ns": 1}]
        )
        self.assertEqual(observed["observed_actions"], {"send"})
        self.assertEqual(observed["all_endpoints"], set())
        self.assertFalse(observed["suppressed"])

    def test_lsm_hook_detail_contributes_endpoint(self) -> None:
        """LSM hook 自带的目标信息也计入端点集合。"""
        observed = analyzer.parse_network_activity(
            [
                {
                    "hook_name": "socket_sendmsg",
                    "args": {"family": "AF_INET", "remote_addr": {"sin_addr": "5.5.5.5", "sin_port": 8080}},
                },
                {"hook_name": "socket_bind", "args": {}},
            ],
            [],
        )
        self.assertEqual(observed["observed_actions"], {"send"})
        self.assertIn("AF_INET 5.5.5.5:8080", observed["all_endpoints"])

    def test_no_network_activity_is_not_suppressed(self) -> None:
        observed = analyzer.parse_network_activity([], [])
        self.assertFalse(observed["suppressed"])
        self.assertEqual(observed["actions"], set())

    def test_connect_without_a_resolvable_target_contributes_no_endpoint(self) -> None:
        # 既没有 remote_ip 也没有 sun_path：连接记录在案但端点为 None，不得进入端点集合。
        observed = analyzer.parse_network_activity(
            [],
            [
                {"action": "connect", "event_id": 1, "pid": 1, "fd": 3,
                 "timestamp_mono_ns": 1, "args": {"sockfd": 3}},
                {"action": "sendmsg", "event_id": 2, "pid": 1, "fd": 3, "timestamp_mono_ns": 2},
            ],
        )
        self.assertEqual(observed["all_endpoints"], set())
        self.assertEqual(observed["observed_actions"], {"send"})
        # 无法识别任何端点时不做整轮抑制，保持原判定。
        self.assertFalse(observed["suppressed"])
        self.assertEqual(observed["actions"], {"send"})


class ExtractKernelFileOpsTest(unittest.TestCase):
    @staticmethod
    def hook(**overrides) -> dict:
        base = {
            "event_id": "h1",
            "hook_name": "file_open",
            "result": "allow",
            "return_value": 0,
            "pid": 100,
            "tid": 100,
            "timestamp_mono_ns": 10,
            "path": "/tmp/a.txt",
            "fd": None,
            "category": "file",
            "resource_role": "normal_resource",
            "related_event_id": "s-open",
            "args": {"flags": "O_RDONLY"},
        }
        base.update(overrides)
        return base

    def test_read_and_write_bytes_are_attributed_to_the_open(self) -> None:
        """读写字节数与次数正确归属到对应的 open 事件。"""
        syscalls = [
            {
                "event_id": "s-open",
                "action": "open",
                "pid": 100,
                "fd": None,
                "return_value": 5,
                "timestamp_mono_ns": 10,
                "syscall": "openat",
                "result": "ok",
                "requested_bytes": None,
            },
            {
                "event_id": "s-read",
                "action": "read",
                "pid": 100,
                "fd": 5,
                "timestamp_mono_ns": 11,
                "returned_bytes": 128,
            },
            {
                "event_id": "s-write",
                "action": "write",
                "pid": 100,
                "fd": 5,
                "timestamp_mono_ns": 12,
                "returned_bytes": 64,
            },
        ]
        ops = analyzer.extract_kernel_file_ops([self.hook()], syscalls)
        self.assertEqual(len(ops), 1)
        op = ops[0]
        self.assertEqual((op["read_bytes"], op["read_count"]), (128, 1))
        self.assertEqual((op["write_bytes"], op["write_count"]), (64, 1))
        self.assertEqual(op["observed_actions"], ["read", "write"])
        self.assertEqual(op["syscall"], "openat")

    def test_bytes_after_fd_is_reopened_are_not_counted(self) -> None:
        """fd 被复用后的读写不得记到上一次 open 上。"""
        syscalls = [
            {
                "event_id": "s-open",
                "action": "open",
                "pid": 100,
                "fd": None,
                "return_value": 5,
                "timestamp_mono_ns": 10,
            },
            {"event_id": "s-read1", "action": "read", "pid": 100, "fd": 5, "timestamp_mono_ns": 11, "returned_bytes": 10},
            # fd 5 被复用给另一个文件：其后的读不应记到第一次 open 上。
            {
                "event_id": "s-open2",
                "action": "open",
                "pid": 100,
                "fd": None,
                "return_value": 5,
                "timestamp_mono_ns": 20,
            },
            {"event_id": "s-read2", "action": "read", "pid": 100, "fd": 5, "timestamp_mono_ns": 21, "returned_bytes": 999},
        ]
        ops = analyzer.extract_kernel_file_ops([self.hook()], syscalls)
        self.assertEqual(ops[0]["read_bytes"], 10)
        self.assertEqual(ops[0]["read_count"], 1)

    def test_negative_open_return_value_skips_attribution(self) -> None:
        """open 返回负值（失败）时不做字节归属。"""
        syscalls = [
            {
                "event_id": "s-open",
                "action": "open",
                "pid": 100,
                "fd": None,
                "return_value": -13,
                "timestamp_mono_ns": 10,
            }
        ]
        ops = analyzer.extract_kernel_file_ops([self.hook()], syscalls)
        self.assertEqual(ops[0]["read_bytes"], 0)
        self.assertEqual(ops[0]["write_bytes"], 0)

    def test_io_before_the_open_is_not_attributed_to_it(self) -> None:
        # 同一个 (pid, fd) 在本次 open 之前的读写属于上一个文件，必须被窗口下界挡住。
        syscalls = [
            {
                "event_id": "s-open",
                "action": "open",
                "pid": 100,
                "fd": None,
                "return_value": 5,
                "timestamp_mono_ns": 10,
            },
            {"event_id": "r-early", "action": "read", "pid": 100, "fd": 5,
             "timestamp_mono_ns": 1, "returned_bytes": 111},
            {"event_id": "w-early", "action": "write", "pid": 100, "fd": 5,
             "timestamp_mono_ns": 2, "returned_bytes": 222},
        ]
        ops = analyzer.extract_kernel_file_ops([self.hook()], syscalls)
        self.assertEqual(ops[0]["read_bytes"], 0)
        self.assertEqual(ops[0]["write_bytes"], 0)
        self.assertEqual(ops[0]["read_count"], 0)
        self.assertEqual(ops[0]["write_count"], 0)

    def test_missing_related_syscall_leaves_syscall_fields_none(self) -> None:
        """关联不到 syscall 时相关字段留空而不报错。"""
        ops = analyzer.extract_kernel_file_ops([self.hook(related_event_id="nope")], [])
        self.assertIsNone(ops[0]["syscall"])
        self.assertIsNone(ops[0]["syscall_result"])
        self.assertIsNone(ops[0]["syscall_return_value"])

    def test_action_defaults_to_read_when_nothing_observed(self) -> None:
        """既无 flags 也无读写记录时保守记为 read。"""
        ops = analyzer.extract_kernel_file_ops([self.hook(args={})], [])
        self.assertEqual(ops[0]["observed_actions"], ["read"])

    def test_rmdir_hook_is_a_delete_action(self) -> None:
        """inode_rmdir 映射为 delete 动作。"""
        ops = analyzer.extract_kernel_file_ops([self.hook(hook_name="inode_rmdir", args={})], [])
        self.assertIn("delete", ops[0]["observed_actions"])

    def test_ops_are_sorted_by_timestamp(self) -> None:
        """输出的文件操作按时间戳升序排列。"""
        ops = analyzer.extract_kernel_file_ops(
            [
                self.hook(event_id="late", timestamp_mono_ns=99, related_event_id=None),
                self.hook(event_id="early", timestamp_mono_ns=1, related_event_id=None),
            ],
            [],
        )
        self.assertEqual([op["event_id"] for op in ops], ["early", "late"])


class FlagsToActionsTest(unittest.TestCase):
    def test_empty_flags(self) -> None:
        """flags 为空或 None 时不产生任何动作。"""
        self.assertEqual(analyzer.flags_to_actions(None), set())
        self.assertEqual(analyzer.flags_to_actions(""), set())

    def test_flag_combinations(self) -> None:
        """O_RDONLY/O_WRONLY/O_RDWR/O_CREAT/O_TRUNC 各自映射到正确动作。"""
        self.assertEqual(analyzer.flags_to_actions("O_RDONLY"), {"read"})
        self.assertEqual(analyzer.flags_to_actions("O_WRONLY|O_CREAT"), {"write", "create"})
        self.assertEqual(analyzer.flags_to_actions("O_RDWR"), {"read", "write"})
        self.assertEqual(analyzer.flags_to_actions("O_TRUNC"), {"write"})


class PatternMatchingTest(unittest.TestCase):
    def test_is_regex_pattern_detects_metacharacters(self) -> None:
        """按元字符启发式区分正则与普通路径。"""
        self.assertTrue(analyzer.is_regex_pattern(r"^/tmp/.*$"))
        self.assertFalse(analyzer.is_regex_pattern("/tmp/plain.txt"))

    def test_empty_identifier_never_matches(self) -> None:
        """空 identifier 永不匹配，不会放行任意路径。"""
        self.assertFalse(analyzer.matches_file_identifier("/tmp/a", ""))
        self.assertFalse(analyzer.matches_file_identifier("/tmp/a", None))

    def test_none_path_never_matches(self) -> None:
        """路径为 None 时不匹配任何标识。"""
        self.assertFalse(analyzer.matches_file_identifier(None, "/tmp/a"))

    def test_plain_identifier_without_wildcards_requires_exact_match(self) -> None:
        """无通配符标识不做前缀匹配，必须完全相等。"""
        self.assertFalse(analyzer.matches_file_identifier("/tmp/a/b", "/tmp/a"))

    def test_is_allowed_handles_none_path_and_empty_set(self) -> None:
        """空路径或空允许集时一律不放行。"""
        self.assertFalse(analyzer.is_allowed(None, {"/tmp/a"}))
        self.assertFalse(analyzer.is_allowed("/tmp/a", set()))
        self.assertTrue(analyzer.is_allowed("/tmp/a", {"/other", "/tmp/*"}))

    def test_matching_allowed_actions_unions_every_matching_identifier(self) -> None:
        """路径命中多条标识时取动作并集，未命中返回 None。"""
        allowed = {
            "files": {"/workspace/**", "/workspace/a.py"},
            "file_actions": {"/workspace/**": ["read"], "/workspace/a.py": ["write"]},
        }
        self.assertEqual(analyzer.matching_allowed_actions("/workspace/a.py", allowed), {"read", "write"})
        self.assertIsNone(analyzer.matching_allowed_actions("/etc/passwd", allowed))


class ClassificationEdgeTest(unittest.TestCase):
    def test_none_path_is_unknown(self) -> None:
        """路径为 None 时分类为 unknown 且不命中敏感规则。"""
        self.assertEqual(analyzer.classify(None), "unknown")
        self.assertIsNone(analyzer.matching_sensitive_rule(None))

    def test_unrelated_path_is_other(self) -> None:
        """既非敏感也非运行时的路径归为 other。"""
        self.assertEqual(analyzer.classify("/srv/app/data.txt", None), "other")

    def test_openclaw_doc_basename_outside_prefix_is_runtime(self) -> None:
        """AGENT.md 等框架文档在 workspace/.openclaw 下判为 runtime。"""
        self.assertTrue(analyzer.is_openclaw_runtime("/home/dev/workspace/AGENT.md"))
        self.assertTrue(analyzer.is_openclaw_runtime("/data/.openclaw/MEMORY.md"))
        self.assertFalse(analyzer.is_openclaw_runtime("/home/dev/other/AGENT.md"))

    def test_proc_self_access_requires_an_op(self) -> None:
        """缺少操作上下文时不能判定为读自身 /proc。"""
        self.assertFalse(analyzer.is_proc_self_access("/proc/1/environ", None))

    def test_proc_self_access_needs_a_pid_shaped_path(self) -> None:
        """路径不含数字 pid 段时不走 proc self 判定。"""
        self.assertFalse(analyzer.is_proc_self_access("/proc/self", {"pid": 1}))

    def test_proc_self_rule_can_be_disabled(self) -> None:
        with patch.object(analyzer, "PROC_SELF_IS_RUNTIME", False):
            self.assertFalse(analyzer.is_proc_self_access("/proc/1/environ", {"pid": 1}))

    def test_write_only_rule_with_unknown_actions_is_not_sensitive(self) -> None:
        # observed_actions 缺失时 write_only 组保守放行（op=None → actions=None）。
        self.assertIsNone(analyzer.matching_sensitive_rule("/etc/passwd", None))


class DetectAnomaliesTest(unittest.TestCase):
    empty_net = {"actions": set(), "endpoints": set()}
    empty_allowed = {"files": set(), "file_actions": {}, "network_actions": set()}

    def test_no_input_means_no_anomaly(self) -> None:
        """无越权无网络动作时判定为正常。"""
        result = analyzer.detect_anomalies([], [], self.empty_allowed, self.empty_net)
        self.assertFalse(result["is_anomaly"])
        self.assertEqual(result["types"], [])

    def test_non_sensitive_violations_do_not_create_a_sensitive_type(self) -> None:
        """非敏感类越权与空路径不产生敏感异常项。"""
        violations = [
            {"category": "other", "path": "/tmp/a", "observed_actions": ["read"]},
            {"category": "sensitive", "path": None},
        ]
        result = analyzer.detect_anomalies(violations, [], self.empty_allowed, self.empty_net)
        self.assertFalse(result["is_anomaly"])

    def test_sensitive_hits_merge_actions_per_path(self) -> None:
        """同一敏感路径的多次命中合并动作后输出一条。"""
        violations = [
            {
                "category": "sensitive",
                "path": "/etc/shadow",
                "sensitive_rule": "credential_store",
                "sensitive_title": "系统口令散列与提权授权库",
                "sensitive_severity": "critical",
                "sensitive_attck": ["T1003.008"],
                "sensitive_reason": "r",
                "sensitive_basis": "b",
                "observed_actions": ["read"],
            },
            {
                "category": "sensitive",
                "path": "/etc/shadow",
                "sensitive_rule": "credential_store",
                "observed_actions": ["write"],
            },
        ]
        result = analyzer.detect_anomalies(violations, [], self.empty_allowed, self.empty_net)
        item = result["types"][0]
        self.assertEqual(item["type"], "访问危险文件（敏感越权）")
        self.assertEqual(item["paths"], ["/etc/shadow"])
        self.assertEqual(item["items"][0]["actions"], ["read", "write"])

    def test_file_op_within_allowed_actions_is_not_a_mismatch(self) -> None:
        """实际动作在允许集合内时不算未授权。"""
        allowed = {"files": {"/tmp/a"}, "file_actions": {"/tmp/a": ["read", "write"]}, "network_actions": set()}
        ops = [{"path": "/tmp/a", "observed_actions": ["read"], "hook_name": "file_open", "event_id": 1}]
        result = analyzer.detect_anomalies([], ops, allowed, self.empty_net)
        self.assertFalse(result["is_anomaly"])

    def test_network_action_outside_allowlist_is_flagged(self) -> None:
        """网络动作超出允许集时输出异常项并附带目标端点。"""
        net = {"actions": {"send"}, "endpoints": {"1.2.3.4:80"}}
        result = analyzer.detect_anomalies([], [], self.empty_allowed, net)
        item = result["types"][0]
        self.assertEqual(item["type"], "网络访问出现未授权动作")
        self.assertEqual(item["extra"], ["send"])
        self.assertEqual(item["endpoints"], ["1.2.3.4:80"])


if __name__ == "__main__":
    unittest.main()
