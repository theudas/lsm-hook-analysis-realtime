#!/usr/bin/env python3
"""
Round-level LSM hook analysis.

This module is intentionally callable from realtime workers: it analyzes exactly
one round directory and does not decide whether a round should be skipped.
"""

from __future__ import annotations

import json
import re
import time
from datetime import datetime
from pathlib import Path
from urllib import error, request

from .config import SETTINGS
from .logging_utils import setup_logging
from .rules import (
    OPENCLAW_RUNTIME_BASENAMES,
    OPENCLAW_RUNTIME_PREFIXES,
    PROC_SELF_IS_RUNTIME,
    REGISTERED_TOOLS,
    RUNTIME_PREFIXES,
    SENSITIVE_RULES,
    glob_to_regex,
    is_baseline_endpoint,
    is_ignored_endpoint,
    matching_baseline_rule,
)


PUSH_MARKER_NAME = "analysis_kernel_report_push.json"
log = setup_logging("lha_realtime_analyzer", "analyzer.log")


def file_size(path: Path) -> int:
    return path.stat().st_size if path.is_file() else 0


def load_json_file(path: Path) -> dict:
    if not path.is_file():
        log.warning("输入 JSON 文件不存在 path=%s", path)
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        log.exception("输入 JSON 解析失败 path=%s size=%d bytes", path, file_size(path))
        raise
    log.info("已加载 JSON path=%s size=%d bytes keys=%s", path, file_size(path), sorted(data.keys()))
    return data


def load_jsonl(path: Path) -> list:
    if not path.is_file():
        log.warning("输入 JSONL 文件不存在 path=%s", path)
        return []
    rows = []
    try:
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if line.strip():
                rows.append(json.loads(line))
    except json.JSONDecodeError:
        log.exception("输入 JSONL 解析失败 path=%s line=%d size=%d bytes", path, line_no, file_size(path))
        raise
    log.info("已加载 JSONL path=%s rows=%d size=%d bytes", path, len(rows), file_size(path))
    return rows


def load_ir_source(round_dir: Path, round_end: dict | None = None) -> dict:
    """IR 优先取独立的 ir.json（round_ir_ready）；否则回退 round_end.json 的 ir_json（旧上游）。"""
    ir_path = round_dir / "ir.json"
    if ir_path.is_file():
        payload = load_json_file(ir_path)
        if payload.get("ir_json"):
            return payload
        log.warning("ir.json 存在但 ir_json 为空 path=%s", ir_path)
    if round_end is None:
        round_end = load_json_file(round_dir / "round_end.json")
    return round_end if round_end.get("ir_json") else {}


def parse_allowlist(ir_source: dict) -> dict:
    """从 ir_json 展开用户态允许集合：文件路径 / 工具。

    ir_source 可以是 ir.json（round_ir_ready）或 round_end.json 的 payload，两者都含 ir_json 键。
    """
    allowed = {
        "files": set(),
        "tools": set(),
        "file_actions": {},
        "networks": set(),
        "network_actions": set(),
    }
    ir = json.loads(ir_source.get("ir_json") or "{}")
    policies = ir.get("level2", {}).get("policies")
    if policies is None:
        policies = ir.get("policies", [])
    for pol in policies:
        if pol.get("effect") != "allow":
            continue
        for obj in pol.get("objects", []):
            if obj.get("type") == "file":
                identifier = obj.get("identifier")
                if not identifier:
                    log.warning("忽略空 file identifier policy=%s", pol)
                    continue
                allowed["files"].add(identifier)
                actions = allowed["file_actions"].setdefault(identifier, [])
                for action in obj.get("actions", []):
                    if action not in actions:
                        actions.append(action)
            elif obj.get("type") == "tool":
                allowed["tools"].add(obj["identifier"])
            elif obj.get("type") == "network":
                identifier = obj.get("identifier")
                if identifier:
                    allowed["networks"].add(identifier)
                for action in obj.get("actions", []):
                    allowed["network_actions"].add(action)
    return allowed


def parse_user_actions(round_end: dict) -> list:
    """从 action_json 取用户态实际记录的工具调用。"""
    actions = json.loads(round_end.get("action_json") or "[]")
    return [
        {
            "tool": action.get("tool"),
            "arguments": action.get("arguments", {}),
            "resources": action.get("resources", []),
        }
        for action in actions
    ]


def parse_resource_facts(round_kernel: dict) -> list:
    """round_kernel.json 里 kernel_resource_facts 是字符串化的 JSON，含每路径汇总。"""
    raw = round_kernel.get("kernel_resource_facts")
    if not raw:
        log.info("round_kernel.kernel_resource_facts 为空")
        return []
    try:
        facts = json.loads(raw).get("resource_facts", [])
        log.info("已解析 kernel_resource_facts count=%d raw_len=%d", len(facts), len(raw))
        return facts
    except (json.JSONDecodeError, AttributeError):
        log.exception("kernel_resource_facts 解析失败 raw_len=%d", len(raw))
        return []


# 网络类 LSM hook 的行为标签与分组。
NET_BEHAVIOR = {
    "socket_sendmsg": "数据发送",
    "socket_recvmsg": "数据接收",
    "socket_create": "创建套接字",
    "socket_connect": "发起连接",
    "socket_bind": "绑定",
    "socket_listen": "监听",
    "socket_accept": "接受连接",
    "socket_setsockopt": "设置选项",
    "socket_getsockopt": "读取选项",
    "socket_shutdown": "关闭连接",
}


NET_HOOK_ACTIONS = {
    "socket_sendmsg": "send",
    "socket_recvmsg": "receive",
}


# 文件类 LSM hook 直接隐含的 IR 动作（open 类走 flags_to_actions，这里覆盖删除等无 flags 的 hook）。
# inode_unlink 对应 unlink(2)/rm 删除文件，inode_rmdir 对应删除目录，均映射为 delete。
FILE_HOOK_ACTIONS = {
    "inode_unlink": "delete",
    "inode_rmdir": "delete",
}


def is_network_hook(hook_name: str | None) -> bool:
    return bool(hook_name) and hook_name.startswith("socket_")


def network_hook_actions(hook_name: str | None) -> set:
    """Map LSM socket hooks to the IR network action vocabulary."""
    action = NET_HOOK_ACTIONS.get(hook_name)
    return {action} if action else set()


def net_group(hook_name: str | None) -> str:
    if hook_name in ("socket_sendmsg", "socket_recvmsg"):
        return "数据收发"
    if hook_name in ("socket_create", "socket_connect", "socket_bind", "socket_listen", "socket_accept"):
        return "连接管理"
    return "其他"


def network_target(hook: dict) -> tuple:
    """从网络 hook 提取 (地址族, 远端地址)，缺失的一项为 None。"""
    if not is_network_hook(hook.get("hook_name")):
        return None, None
    args = hook.get("args", {}) or {}
    family = args.get("family") or args.get("sa_family")
    remote = args.get("remote_addr") if isinstance(args.get("remote_addr"), dict) else {}
    target = remote.get("sun_path") or args.get("sun_path")
    if not target and (remote.get("sin_addr") or args.get("sin_addr")):
        ip = remote.get("sin_addr") or args.get("sin_addr")
        port = remote.get("sin_port") or args.get("sin_port")
        target = f"{ip}:{port}" if port is not None else ip
    if not target and (remote.get("sin6_addr") or args.get("sin6_addr")):
        ip = remote.get("sin6_addr") or args.get("sin6_addr")
        port = remote.get("sin6_port") or args.get("sin6_port")
        target = f"{ip}:{port}" if port is not None else ip
    return family or None, str(target) if target else None


def network_detail(hook: dict) -> str:
    """从网络 hook 提取简明目标信息：地址族 + 远端地址（若有）。"""
    return " ".join(str(p) for p in network_target(hook) if p)


def is_collector_event(event: dict) -> bool:
    """识别经采集器通道产生的 stdio 收发事件（socket_sendmsg/recvmsg，fd=0）。

    被测工具的 stdin/stdout 是与运行时之间的 socketpair，工具回传结果时触发
    socket_sendmsg/recvmsg，且不带地址（net_target 为空）。采集链路给这类事件
    打了身份标记：args.decision_scope == "collector_program"（同时携带
    observation_only: true）。全量语料扫描中该字段只出现过这一个取值。

    注意：这不是"采集器自己的流量"——事件 pid 与被测工具进程相同，语义是
    "工具经 stdio 通道的数据回传"。它既出现在良性 round（工具正常返回结果，
    是误杀来源），也出现在攻击 round（数据经该通道外发，是部分攻击唯一的
    内核可见痕迹），因此不能一刀切过滤，须结合工具授权判定（analyze_round）。
    """
    args = event.get("args")
    return isinstance(args, dict) and args.get("decision_scope") == "collector_program"


def extract_kernel_file_ops(lsm: list, syscalls: list) -> list:
    """以 LSM file_open 事件为主线，经 related_event_id 关联其 syscall，附带读写字节。"""
    sys_by_id = {s["event_id"]: s for s in syscalls}

    opens = {}
    reads = {}
    writes = {}
    for syscall in syscalls:
        if syscall.get("action") == "open":
            ret = syscall.get("return_value")
            if isinstance(ret, int) and ret >= 0:
                opens.setdefault((syscall["pid"], ret), []).append(syscall["timestamp_mono_ns"])
        elif syscall.get("action") == "read":
            reads.setdefault((syscall["pid"], syscall["fd"]), []).append(
                (syscall["timestamp_mono_ns"], syscall.get("returned_bytes") or 0)
            )
        elif syscall.get("action") == "write":
            writes.setdefault((syscall["pid"], syscall["fd"]), []).append(
                (syscall["timestamp_mono_ns"], syscall.get("returned_bytes") or 0)
            )
    for values in opens.values():
        values.sort()
    for values in reads.values():
        values.sort()
    for values in writes.values():
        values.sort()

    ops = []
    for hook in lsm:
        net_family, net_target = network_target(hook)
        related = sys_by_id.get(hook.get("related_event_id"))
        open_fd = related.get("return_value") if related and related.get("action") == "open" else None
        open_ts = hook["timestamp_mono_ns"]

        read_bytes = read_count = 0
        write_bytes = write_count = 0
        if isinstance(open_fd, int) and open_fd >= 0:
            later = [ts for ts in opens.get((hook["pid"], open_fd), []) if ts > open_ts]
            next_open_ts = min(later) if later else float("inf")
            for ts, nb in reads.get((hook["pid"], open_fd), []):
                if open_ts <= ts < next_open_ts:
                    read_bytes += nb
                    read_count += 1
            for ts, nb in writes.get((hook["pid"], open_fd), []):
                if open_ts <= ts < next_open_ts:
                    write_bytes += nb
                    write_count += 1

        observed_actions = flags_to_actions(hook.get("args", {}).get("flags"))
        hook_action = FILE_HOOK_ACTIONS.get(hook.get("hook_name"))
        if hook_action:
            observed_actions.add(hook_action)
        if read_count:
            observed_actions.add("read")
        if write_count:
            observed_actions.add("write")
        if not observed_actions:
            observed_actions.add("read")

        ops.append(
            {
                "event_id": hook["event_id"],
                "hook_name": hook["hook_name"],
                "result": hook["result"],
                "return_value": hook.get("return_value"),
                "pid": hook["pid"],
                "tid": hook.get("tid"),
                "timestamp_mono_ns": open_ts,
                "path": hook.get("path"),
                "syscall_pathname": (hook.get("args") or {}).get("syscall_pathname"),
                "fd": hook.get("fd"),
                "category": hook.get("category"),
                "resource_role": hook.get("resource_role"),
                "tool_call_id": hook.get("tool_call_id"),
                "tool_name": hook.get("tool_name"),
                "related_event_id": hook.get("related_event_id"),
                "syscall": related.get("syscall") if related else None,
                "syscall_result": related.get("result") if related else None,
                "syscall_return_value": related.get("return_value") if related else None,
                "requested_bytes": related.get("requested_bytes") if related else None,
                "read_bytes": read_bytes,
                "read_count": read_count,
                "write_bytes": write_bytes,
                "write_count": write_count,
                "observed_actions": sorted(observed_actions),
                "is_network": is_network_hook(hook["hook_name"]),
                "net_detail": network_detail(hook),
                "net_family": net_family,
                "net_target": net_target,
            }
        )
    ops.sort(key=lambda row: row["timestamp_mono_ns"])
    return ops


def flags_to_actions(flags: str | None) -> set:
    """把 file_open 的 open flags 映射到 IR 动作词汇 read/write/create。"""
    actions = set()
    if not flags:
        return actions
    if "O_CREAT" in flags:
        actions.add("create")
    if "O_WRONLY" in flags or "O_RDWR" in flags or "O_TRUNC" in flags:
        actions.add("write")
    if "O_RDONLY" in flags or "O_RDWR" in flags:
        actions.add("read")
    return actions


NETWORK_SEND_ACTIONS = ("send", "sendto", "sendmsg")
NETWORK_RECV_ACTIONS = ("recv", "recvfrom", "recvmsg")


def connect_endpoints(syscalls: list) -> dict:
    """从 connect syscall 建立 (pid, fd) -> [(ts, endpoint)]，用于给 send/recv 标注目标（best-effort）。"""
    conns: dict = {}
    for syscall in syscalls:
        if syscall.get("action") != "connect":
            continue
        args = syscall.get("args", {}) or {}
        ip = args.get("remote_ip")
        port = args.get("remote_port")
        if ip:
            endpoint = f"{ip}:{port}" if port is not None else ip
        else:
            endpoint = args.get("sun_path")
        fd = args.get("sockfd", args.get("fd", syscall.get("fd")))
        conns.setdefault((syscall.get("pid"), fd), []).append(
            (syscall.get("timestamp_mono_ns", 0), endpoint)
        )
    for values in conns.values():
        values.sort()
    return conns


def is_excluded_endpoint(endpoint: str | None) -> bool:
    """端点不参与网络判定：配置的忽略端点，或 system_baseline 声明的本机系统端点。"""
    return is_ignored_endpoint(endpoint) or is_baseline_endpoint(endpoint)


def parse_network_activity(lsm: list, syscalls: list) -> dict:
    """汇总该 round 的 send / receive 网络行为，并按端点逐条决定是否计入判定。

    只要出现 send/receive 系统调用或对应 LSM hook 就计入，不论目标是外部主机、
    本地 IPC 还是监控端口；并 best-effort 关联目标端点用于报告展示。

    两类端点不参与判定：detection_rules.yaml 的 network.ignored_endpoints（工具
    去平台拉取线上配置的 127.0.0.1:15100 / localhost:15100，端口需完整匹配），
    以及 system_baseline 声明的本机系统端点（nscd / sssd 的 Unix socket 等）。

    - 能关联到端点的动作：端点被排除则不计入，否则计入。
    - 无法关联端点的动作（LSM 层 sendmsg/recvmsg 不带地址）：若本轮可识别端点全部
      被排除、且其中有配置的忽略端点，则视为发生在忽略端点上、整轮按正常处理；
      只有基线端点、出现其他端点（如 8.152.192.7:15100）或无法识别任何端点时照常计入。
    """
    conns = connect_endpoints(syscalls)

    def lookup(pid, fd, ts):
        records = conns.get((pid, fd))
        if not records:
            return None
        chosen = None
        for rec_ts, endpoint in records:
            if rec_ts <= ts:
                chosen = endpoint
            else:
                break
        return chosen if chosen is not None else records[0][1]

    observed_actions = set()
    attributed_actions = set()
    unattributed_actions = set()
    all_endpoints = set()

    def record(actions: set, endpoint: str | None) -> None:
        observed_actions.update(actions)
        if not endpoint:
            unattributed_actions.update(actions)
            return
        all_endpoints.add(endpoint)
        if not is_excluded_endpoint(endpoint):
            attributed_actions.update(actions)

    # connect 的目标本身也纳入端点集合，即使之后没有 send/recv（例如恶意 connect 探测）。
    for records in conns.values():
        for _ts, endpoint in records:
            if endpoint:
                all_endpoints.add(endpoint)

    for hook in lsm:
        hook_actions = network_hook_actions(hook.get("hook_name"))
        if hook_actions:
            record(hook_actions, network_detail(hook) or None)

    for syscall in syscalls:
        action = syscall.get("action")
        if action in NETWORK_SEND_ACTIONS:
            actions = {"send"}
        elif action in NETWORK_RECV_ACTIONS:
            actions = {"receive"}
        else:
            continue
        record(actions, lookup(syscall.get("pid"), syscall.get("fd"), syscall.get("timestamp_mono_ns", 0)))

    ignored_endpoints = {e for e in all_endpoints if is_ignored_endpoint(e)}
    baseline_endpoints = {e for e in all_endpoints - ignored_endpoints if is_baseline_endpoint(e)}
    remaining_endpoints = all_endpoints - ignored_endpoints - baseline_endpoints
    # 可识别端点全部被排除、且其中有配置的忽略端点 → 整轮网络视为正常。
    # 只有基线端点时不整轮抑制：基线端点（如 nscd）只排除确实归属到它的收发，
    # 不“吸收”无法归属的 LSM 收发——那些可能来自 socketpair 等真实的本地 IPC。
    suppressed = bool(ignored_endpoints) and not remaining_endpoints
    effective_actions = set() if suppressed else attributed_actions | unattributed_actions

    return {
        "actions": effective_actions,
        "endpoints": remaining_endpoints,
        "observed_actions": observed_actions,
        "all_endpoints": all_endpoints,
        "ignored_endpoints": ignored_endpoints,
        "baseline_endpoints": baseline_endpoints,
        "suppressed": suppressed,
    }


REGEX_HINTS = ("^", "$", "+", "|", "(", ")", "{", "}", "\\", ".*")
GLOB_HINTS = ("*", "?", "[")


def is_regex_pattern(identifier: str) -> bool:
    """Best-effort inference because IR identifiers do not carry pattern type."""
    return any(hint in identifier for hint in REGEX_HINTS)


def matches_file_identifier(path: str | None, identifier: str | None) -> bool:
    if path is None or not identifier:
        if not identifier:
            log.warning("空 file identifier 不放行 path=%s", path)
        return False
    if path == identifier:
        return True
    if is_regex_pattern(identifier):
        try:
            return re.fullmatch(identifier, path) is not None
        except re.error:
            log.warning("非法 file regex identifier 不放行 path=%s identifier=%s", path, identifier)
            return False
    if any(ch in identifier for ch in GLOB_HINTS):
        return re.fullmatch(glob_to_regex(identifier), path) is not None
    return False


def is_allowed(path: str | None, allowed_files: set) -> bool:
    if path is None:
        return False
    for pattern in allowed_files:
        if matches_file_identifier(path, pattern):
            return True
    return False


# 敏感资源分组、运行时加载文件、openclaw 运行时文件/文档的定义均在 detection_rules.yaml 中配置，
# 由 lha_realtime.rules 加载为 SENSITIVE_RULES / RUNTIME_PREFIXES /
# OPENCLAW_RUNTIME_PREFIXES / OPENCLAW_RUNTIME_BASENAMES。


def is_openclaw_runtime(path: str) -> bool:
    if path.startswith(OPENCLAW_RUNTIME_PREFIXES):
        return True
    basename = path.rsplit("/", 1)[-1]
    if basename in OPENCLAW_RUNTIME_BASENAMES and ("/.openclaw/" in path or "/workspace/" in path):
        return True
    return False


_PROC_PID_RE = re.compile(r"^/proc/(\d+)(/|$)")


def is_proc_self_access(path: str, op: dict | None) -> bool:
    """路径是进程在读自己的 /proc/<pid>/*（等价于 /proc/self/*）。

    进程读自己的环境变量、内存映射、fd 表不跨越任何权限边界，是 glibc / Node /
    shell 的常规行为；跨进程读取才是 ATT&CK T1003.007 描述的凭据窃取。
    回放 454 个 round 时，全部 28 次 /proc/*/environ 与 /proc/*/maps 命中都属于本类。
    """
    if not PROC_SELF_IS_RUNTIME or not op:
        return False
    matched = _PROC_PID_RE.match(path)
    if not matched:
        return False
    if str(op.get("pid")) == matched.group(1):
        return True
    syscall_path = op.get("syscall_pathname")
    return isinstance(syscall_path, str) and syscall_path.startswith("/proc/self/")


def matching_sensitive_rule(path: str | None, op: dict | None = None):
    """返回命中的敏感分组（SensitiveRule），未命中返回 None。

    判定顺序与 detection_rules.yaml 文档一致：
      override_runtime 组 → openclaw 运行时 → 其余敏感组。
    write_only 组还要求本次实际观测到写/创建/删除动作。
    """
    if path is None:
        return None
    actions = op.get("observed_actions") if op else None
    if is_proc_self_access(path, op):
        return None
    openclaw_runtime = is_openclaw_runtime(path)
    for rule in SENSITIVE_RULES:
        if openclaw_runtime and not rule.override_runtime:
            continue
        if rule.matches_path(path) and rule.matches_actions(actions):
            return rule
    return None


def classify(path: str | None, op: dict | None = None) -> str:
    if path is None:
        return "unknown"
    if matching_sensitive_rule(path, op) is not None:
        return "sensitive"
    if is_openclaw_runtime(path):
        return "runtime"
    if path.startswith(RUNTIME_PREFIXES):
        return "runtime"
    return "other"


def matching_allowed_actions(path: str | None, allowed: dict) -> set | None:
    """path 命中 IR 文件标识时，返回所有命中标识的允许动作并集；未命中返回 None。"""
    matched = None
    for identifier in allowed["files"]:
        if matches_file_identifier(path, identifier):
            if matched is None:
                matched = set()
            matched.update(allowed["file_actions"].get(identifier, []))
    return matched


# 落在 network.ignored_endpoints 上的网络操作与基线一样折叠，用这条伪规则汇总。
IGNORED_ENDPOINT_FOLD = {
    "id": "ignored_network_endpoint",
    "title": "忽略的网络端点",
    "reason": "network.ignored_endpoints 配置的端点（工具拉取线上配置的本地回环），按正常处理",
}
FOLD_SAMPLE_LIMIT = 3


def fold_rule(op: dict, category: str | None) -> dict | None:
    """该越权操作应折叠到报告汇总时，返回折叠规则（id/title/reason），否则返回 None。"""
    rule = matching_baseline_rule(op, category)
    if rule is not None:
        return {"id": rule.id, "title": rule.title, "reason": rule.reason}
    if op.get("is_network") and is_ignored_endpoint(op.get("net_target")):
        return IGNORED_ENDPOINT_FOLD
    return None


def add_fold(folded: dict, rule: dict, op: dict) -> None:
    entry = folded.setdefault(rule["id"], {**rule, "count": 0, "samples": []})
    entry["count"] += 1
    sample = op.get("path") or op.get("net_detail") or op.get("hook_name")
    if sample and sample not in entry["samples"] and len(entry["samples"]) < FOLD_SAMPLE_LIMIT:
        entry["samples"].append(sample)


def detect_anomalies(violations: list, kernel_ops: list, allowed: dict, net_observed: dict) -> dict:
    """依据两条规则给出明确判定：敏感文件越权、IR action 与实际行为不一致。"""
    types = []

    sensitive_hits: dict = {}
    for violation in violations:
        if violation.get("category") != "sensitive" or not violation.get("path"):
            continue
        sensitive_hits.setdefault(
            violation["path"],
            {
                "path": violation["path"],
                "rule": violation.get("sensitive_rule"),
                "title": violation.get("sensitive_title"),
                "severity": violation.get("sensitive_severity"),
                "attck": violation.get("sensitive_attck") or [],
                "reason": violation.get("sensitive_reason"),
                "basis": violation.get("sensitive_basis"),
                "actions": set(),
            },
        )["actions"].update(violation.get("observed_actions") or [])
    if sensitive_hits:
        items = [
            {**hit, "actions": sorted(hit["actions"])}
            for hit in sorted(sensitive_hits.values(), key=lambda h: h["path"])
        ]
        types.append(
            {
                "type": "访问危险文件（敏感越权）",
                "paths": [hit["path"] for hit in items],
                "items": items,
            }
        )

    file_mismatches = []
    for op in kernel_ops:
        allowed_actions = matching_allowed_actions(op.get("path"), allowed)
        if allowed_actions is None:
            continue
        extra = sorted(a for a in op.get("observed_actions", []) if a not in allowed_actions)
        if extra:
            file_mismatches.append(
                {
                    "path": op["path"],
                    "allowed": sorted(allowed_actions),
                    "extra": extra,
                    "hook_name": op.get("hook_name"),
                    "event_id": op.get("event_id"),
                }
            )
    if file_mismatches:
        types.append({"type": "文件访问出现未授权动作", "items": file_mismatches})

    net_extra = sorted(net_observed["actions"] - allowed["network_actions"])
    if net_extra:
        types.append(
            {
                "type": "网络访问出现未授权动作",
                "allowed": sorted(allowed["network_actions"]),
                "extra": net_extra,
                "endpoints": sorted(net_observed["endpoints"]),
            }
        )

    # 平台工具注册表之外的工具（注入/仿冒变体）：不看 IR 是否允许——
    # 用户点名某个工具不构成授权，用户无从知晓该工具是恶意的。
    foreign_tools: dict = {}
    for op in kernel_ops:
        tool = op.get("tool_name")
        if not tool or tool in REGISTERED_TOOLS:
            continue
        entry = foreign_tools.setdefault(tool, {"tool": tool, "events": 0, "hooks": set(), "paths": set()})
        entry["events"] += 1
        if op.get("hook_name"):
            entry["hooks"].add(op["hook_name"])
        if op.get("path"):
            entry["paths"].add(op["path"])
    if foreign_tools:
        types.append(
            {
                "type": "调用未注册工具",
                "items": [
                    {
                        "tool": entry["tool"],
                        "events": entry["events"],
                        "hooks": sorted(entry["hooks"]),
                        "paths": sorted(entry["paths"])[:5],
                    }
                    for entry in sorted(foreign_tools.values(), key=lambda e: (-e["events"], e["tool"]))
                ],
            }
        )

    return {"is_anomaly": bool(types), "types": types}


def analyze_round(round_dir: Path) -> dict:
    started = time.monotonic()
    input_files = {
        "round_start": round_dir / "round_start.json",
        "round_end": round_dir / "round_end.json",
        "round_kernel": round_dir / "round_kernel.json",
        "ir": round_dir / "ir.json",
        "lsm": round_dir / "kernel_lsm_hook_result.jsonl",
        "syscalls": round_dir / "kernel_syscall_seq.jsonl",
    }
    log.info(
        "[%s] 开始分析 round_dir=%s files=%s",
        round_dir.name,
        round_dir,
        {name: {"exists": path.is_file(), "size": file_size(path)} for name, path in input_files.items()},
    )

    round_start = load_json_file(input_files["round_start"])
    round_end = load_json_file(input_files["round_end"])
    round_kernel = load_json_file(input_files["round_kernel"])
    lsm_all = load_jsonl(input_files["lsm"])
    syscalls = load_jsonl(input_files["syscalls"])

    # ---- 采集完整性自检：把"没检测到"与"没采集到"分开。----
    # IR 已就绪却零内核事件 → 判定基于空证据，不构成"无越权"的证明；
    # 捕获到 connect 却无任何收发痕迹 → 收发证据可能缺失，判定置信度受限。
    if not lsm_all and not syscalls:
        collection_status = "no_kernel_events"
    else:
        has_connect = any(s.get("action") == "connect" for s in syscalls)
        has_net_io = any(
            (e.get("hook_name") or "").startswith(("socket_sendmsg", "socket_recvmsg")) for e in lsm_all
        ) or any(
            (s.get("action") or "") in NETWORK_SEND_ACTIONS + NETWORK_RECV_ACTIONS for s in syscalls
        )
        collection_status = "connect_without_io" if has_connect and not has_net_io else "ok"

    allowed = parse_allowlist(load_ir_source(round_dir, round_end))

    # 采集器通道（decision_scope=collector_program）的 stdio 收发：被测工具与
    # 运行时之间的 socketpair 回传，不是真正的网络访问。已授权工具的结果回传
    # 直接过滤；未授权工具的 stdio 外发保留——它是数据外发通道的内核可见痕迹，
    # 也是"调用了 IR 未授权工具"这类攻击（工具变体、注入工具）唯一的判据。
    collector_filtered = 0
    lsm = []
    for event in lsm_all:
        if is_collector_event(event):
            tool = event.get("tool_name")
            if not tool or tool in allowed["tools"]:
                collector_filtered += 1
                continue
        lsm.append(event)

    user_actions = parse_user_actions(round_end)
    resource_facts = parse_resource_facts(round_kernel)
    kernel_ops = extract_kernel_file_ops(lsm, syscalls)
    net_observed = parse_network_activity(lsm, syscalls)

    violations = []
    folded: dict = {}
    role_ir_mismatch = 0
    for op in kernel_ops:
        ir_violation = not is_allowed(op["path"], allowed["files"])
        role_violation = op["resource_role"] == "privacy_resource"
        if ir_violation != role_violation:
            role_ir_mismatch += 1
        if ir_violation or role_violation:
            category = classify(op["path"], op)
            rule = fold_rule(op, category)
            if rule is not None:
                add_fold(folded, rule, op)
                continue
            violation = dict(op)
            violation["kernel_category"] = violation.pop("category", None)
            sensitive_rule = matching_sensitive_rule(op["path"], op)
            violation["category"] = category
            if sensitive_rule is not None:
                violation["sensitive_rule"] = sensitive_rule.id
                violation["sensitive_title"] = sensitive_rule.title
                violation["sensitive_severity"] = sensitive_rule.severity
                violation["sensitive_attck"] = list(sensitive_rule.attck)
                violation["sensitive_reason"] = sensitive_rule.reason
                violation["sensitive_basis"] = sensitive_rule.basis
            violation["by_ir_json"] = ir_violation
            violation["by_resource_role"] = role_violation
            violation["judges_agree"] = ir_violation == role_violation
            violations.append(violation)

    anomaly = detect_anomalies(violations, kernel_ops, allowed, net_observed)

    result = {
        "round_id": round_end.get("round_id") or round_start.get("round_id") or round_dir.name,
        "session_key": round_start.get("session_key"),
        "time_start": round_end.get("time_start") or round_start.get("time_start"),
        "time_end": round_end.get("time_end"),
        "overall_score": round_end.get("overall_score"),
        "tool_name": round_kernel.get("round_id") and next(
            (op["tool_name"] for op in kernel_ops if op.get("tool_name")),
            None,
        ),
        "allowed_files": sorted(allowed["files"]),
        "allowed_tools": sorted(allowed["tools"]),
        "file_actions": allowed["file_actions"],
        "allowed_networks": sorted(allowed["networks"]),
        "allowed_network_actions": sorted(allowed["network_actions"]),
        "network_observed": sorted(net_observed["actions"]),
        "network_endpoints": sorted(net_observed["endpoints"]),
        "network_suppressed": net_observed["suppressed"],
        "network_ignored_endpoints": sorted(net_observed["ignored_endpoints"]),
        "network_baseline_endpoints": sorted(net_observed["baseline_endpoints"]),
        "is_anomaly": anomaly["is_anomaly"],
        "anomaly_types": anomaly["types"],
        "user_actions": user_actions,
        "resource_facts": resource_facts,
        "collection_status": collection_status,
        "suppressed": sorted(folded.values(), key=lambda entry: (-entry["count"], entry["id"])),
        "counts": {
            "lsm_total": len(lsm),
            "lsm_collector_filtered": collector_filtered,
            "syscall_total": len(syscalls),
            "kernel_file_ops": len(kernel_ops),
            "violations": len(violations),
            "judge_mismatch": role_ir_mismatch,
            "suppressed": sum(entry["count"] for entry in folded.values()),
        },
        "violations": violations,
    }
    counts = result["counts"]
    sensitive = sum(1 for violation in violations if violation["category"] == "sensitive")
    log.info(
        "[%s] 分析完成 elapsed=%.3fs lsm_total=%d syscall_total=%d kernel_file_ops=%d "
        "violations=%d suppressed=%d sensitive=%d judge_mismatch=%d collection_status=%s "
        "net_suppressed=%s net_ignored=%s net_baseline=%s net_observed=%s net_endpoints=%s",
        result["round_id"],
        time.monotonic() - started,
        counts["lsm_total"],
        counts["syscall_total"],
        counts["kernel_file_ops"],
        counts["violations"],
        counts["suppressed"],
        sensitive,
        counts["judge_mismatch"],
        collection_status,
        net_observed["suppressed"],
        sorted(net_observed["ignored_endpoints"]),
        sorted(net_observed["baseline_endpoints"]),
        sorted(net_observed["observed_actions"]),
        result["network_endpoints"],
    )
    return result


def write_outputs(round_dir: Path, result: dict) -> tuple[Path, Path]:
    started = time.monotonic()
    violations_path = round_dir / "analysis_violations.jsonl"
    with violations_path.open("w", encoding="utf-8") as file:
        for violation in result["violations"]:
            file.write(json.dumps({"round_id": result["round_id"], **violation}, ensure_ascii=False) + "\n")

    lines = []
    add = lines.append
    counts = result["counts"]
    add(f"# 越权分析报告 — round `{result['round_id']}`\n")

    add("## 判定结论\n")
    add(f"- 是否异常: {'是' if result['is_anomaly'] else '否'}")
    if result["anomaly_types"]:
        add("- 异常类型:")
        for item in result["anomaly_types"]:
            if item["type"] == "访问危险文件（敏感越权）":
                add(f"  - {item['type']}:")
                # 同一敏感分组内的路径共享判定理由与依据，按组聚合输出，避免逐条重复。
                grouped: dict = {}
                for hit in item.get("items") or []:
                    key = hit.get("rule") or hit.get("title") or "-"
                    grouped.setdefault(key, {"meta": hit, "paths": []})["paths"].append(hit)
                for group in grouped.values():
                    meta = group["meta"]
                    attck = f"，ATT&CK {'/'.join(meta['attck'])}" if meta.get("attck") else ""
                    severity = meta.get("severity") or "high"
                    add(f"    - [{severity}] {meta.get('title') or '敏感资源'}{attck} — 命中 {len(group['paths'])} 个路径")
                    for hit in group["paths"]:
                        actions = f"（{', '.join(hit['actions'])}）" if hit.get("actions") else ""
                        add(f"      - `{hit['path']}`{actions}")
                    if meta.get("reason"):
                        add(f"      判定理由: {meta['reason']}")
                    if meta.get("basis"):
                        add(f"      规则依据: {meta['basis']}")
            elif item["type"] == "文件访问出现未授权动作":
                add(f"  - {item['type']}:")
                for mismatch in item["items"]:
                    add(
                        f"    - `{mismatch['path']}` 允许[{', '.join(mismatch['allowed'])}] "
                        f"实际出现[{', '.join(mismatch['extra'])}]（event_id {mismatch['event_id']}）"
                    )
            elif item["type"] == "网络访问出现未授权动作":
                endpoints = f"，目标 {', '.join(item['endpoints'])}" if item.get("endpoints") else ""
                add(
                    f"  - {item['type']}: 允许[{', '.join(item['allowed'])}] "
                    f"实际出现[{', '.join(item['extra'])}]{endpoints}"
                )
            elif item["type"] == "调用未注册工具":
                add(
                    f"  - {item['type']}（平台工具注册表之外的工具；用户点名不构成授权——"
                    f"用户无从知晓该工具是否恶意，即使用户态 IR 已允许）:"
                )
                for entry in item["items"]:
                    paths = (
                        f"，涉及路径 {', '.join('`' + p + '`' for p in entry['paths'])}"
                        if entry.get("paths")
                        else ""
                    )
                    add(
                        f"    - `{entry['tool']}`（{entry['events']} 条内核事件，"
                        f"hooks: {', '.join(entry['hooks'])}{paths}）"
                    )
    else:
        add("- 异常类型: 无")
    add("")

    add(f"- 报告生成时间: {datetime.now().isoformat(timespec='seconds')}")
    add(f"- 会话: `{result.get('session_key')}`")
    add(f"- round时间段: {result['time_start']} → {result['time_end']}")
    add(f"- 工具: `{result['tool_name']}`")
    add(f"- 用户态判定得分: {result['overall_score']}")
    add(
        f"- 内核事件: LSM {counts['lsm_total']} 条 / syscall {counts['syscall_total']} 条 / "
        f"放行文件操作 {counts['kernel_file_ops']} 个"
    )
    collector_filtered = counts.get("lsm_collector_filtered") or 0
    if collector_filtered:
        add(
            f"- 采集器通道流量: 已过滤 {collector_filtered} 条"
            f"（decision_scope=collector_program 的 stdio 回传；已授权工具的正常结果回传，"
            f"未授权工具的 stdio 外发仍计入网络判定）"
        )
    collection_status = result.get("collection_status")
    if collection_status == "no_kernel_events":
        add("- ⚠ 采集完整性: **异常（内核零事件）** —— IR 已就绪但 LSM / syscall 流均为空。")
        add("  本轮判定基于空证据得出，不构成\"无越权行为\"的证明，请检查采集链路。")
    elif collection_status == "connect_without_io":
        add("- ⚠ 采集完整性: 可疑（有 connect 无收发痕迹）—— 捕获到 connect 但无任何 send/recv。")
        add("  收发证据可能缺失，本轮判定的置信度受限。")
    folded_total = counts.get("suppressed") or 0
    folded_note = f"；另有 {folded_total} 条系统基线行为已折叠，见文末汇总" if folded_total else ""
    add(
        f"- **越权操作: {counts['violations']} 个**（ir_json 与内核 resource_role 判据分歧: "
        f"{counts['judge_mismatch']} 处{folded_note}）\n"
    )

    add("## 用户态允许集 (ir_json)\n")
    add("允许文件:")
    for path in result["allowed_files"]:
        actions = ", ".join(result["file_actions"].get(path, []))
        add(f"  - `{path}` （动作: {actions}）")
    add("允许工具: " + ", ".join(f"`{tool}`" for tool in result["allowed_tools"]) + "\n")

    add("## 用户态实际记录行为 (action_json)\n")
    for user_action in result["user_actions"]:
        add(f"  - `{user_action['tool']}` {json.dumps(user_action['arguments'], ensure_ascii=False)}")
    add("")

    file_viol = [v for v in result["violations"] if not v.get("is_network")]
    net_viol = [v for v in result["violations"] if v.get("is_network")]

    add("## 越权清单（内核 LSM 放行，但用户态不允许）\n")
    add(
        "> 判据一致：对同一次操作，两个独立判据是否给出相同结论——"
        "判据A `ir_json` 允许集判为越权，判据B 内核 `resource_role` 标记为 `privacy_resource`。"
        "yes=两者都认定越权；no=两者结论不一致（仅其一命中）。\n"
    )

    add("### 文件\n")
    if not file_viol:
        add("无\n")
    else:
        by_cat = {}
        for violation in file_viol:
            by_cat.setdefault(violation["category"], []).append(violation)
        cat_title = {
            "sensitive": "敏感资源",
            "runtime": "运行时加载",
            "other": "其他",
            "unknown": "未知路径",
        }
        for category in ("sensitive", "other", "runtime", "unknown"):
            items = by_cat.get(category)
            if not items:
                continue
            agg: dict = {}
            for violation in items:
                entry = agg.setdefault(
                    violation["path"],
                    {"hooks": set(), "actions": set(), "count": 0, "read_bytes": 0, "agree": set()},
                )
                entry["hooks"].add(violation["hook_name"])
                entry["actions"].update(violation.get("observed_actions", []))
                entry["count"] += 1
                entry["read_bytes"] += violation.get("read_bytes", 0) or 0
                entry["agree"].add(bool(violation["judges_agree"]))
                if violation.get("sensitive_title"):
                    attck = "/".join(violation.get("sensitive_attck") or [])
                    entry["basis"] = (
                        f"{violation['sensitive_title']}"
                        f"（{violation.get('sensitive_severity') or 'high'}"
                        f"{'，ATT&CK ' + attck if attck else ''}）"
                    )
            sensitive_table = category == "sensitive"
            add(f"#### {cat_title[category]}（{len(agg)} 个路径 / {len(items)} 次）\n")
            if sensitive_table:
                add("| path | 敏感依据 | hook | 动作 | 次数 | 读取字节 | 判据一致 |")
                add("|---|---|---|---|---|---|---|")
            else:
                add("| path | hook | 动作 | 次数 | 读取字节 | 判据一致 |")
                add("|---|---|---|---|---|---|")
            for path in sorted(agg, key=lambda p: (-agg[p]["count"], p or "")):
                entry = agg[path]
                agree = {True: "yes", False: "no"}
                agree_val = agree[next(iter(entry["agree"]))] if len(entry["agree"]) == 1 else "部分"
                basis = f" {entry.get('basis', '-')} |" if sensitive_table else ""
                add(
                    f"| `{path}` |{basis} {', '.join(sorted(entry['hooks']))} | "
                    f"{', '.join(sorted(entry['actions']))} | {entry['count']} | "
                    f"{entry['read_bytes']} | {agree_val} |"
                )
            add("")

    add("### 网络\n")
    if result.get("network_suppressed"):
        ignored = ", ".join(f"`{e}`" for e in result.get("network_ignored_endpoints", []))
        baseline = ", ".join(f"`{e}`" for e in result.get("network_baseline_endpoints") or [])
        if baseline:
            add(
                f"无（本轮网络连接目标均已排除：忽略端点 {ignored}（工具拉取线上配置）；"
                f"系统基线端点 {baseline}（本机 NSS 查询等），按正常处理）\n"
            )
        else:
            add(
                "无（本轮网络连接目标均为忽略端点"
                f"{'：' + ignored if ignored else ''}，为工具拉取线上配置，按正常处理）\n"
            )
    elif not net_viol:
        add("无\n")
    else:
        by_group: dict = {}
        for violation in net_viol:
            key = (
                net_group(violation["hook_name"]),
                violation["hook_name"],
                NET_BEHAVIOR.get(violation["hook_name"], violation["hook_name"]),
                violation.get("net_detail") or "-",
                violation["result"],
            )
            by_group.setdefault(key[0], {}).setdefault(key[1:], 0)
            by_group[key[0]][key[1:]] += 1
        for group in ("数据收发", "连接管理", "其他"):
            rows = by_group.get(group)
            if not rows:
                continue
            total = sum(rows.values())
            add(f"#### {group} ({total})\n")
            add("| 行为 | hook | 目标 | result | 次数 |")
            add("|---|---|---|---|---|")
            for (hook_name, behavior, detail, res), count in sorted(rows.items()):
                add(f"| {behavior} | {hook_name} | {detail} | {res} | {count} |")
            add("")

    if result.get("suppressed"):
        add("## 已折叠的系统基线行为\n")
        add("> 以下操作命中 detection_rules.yaml 的 system_baseline 或忽略端点，不计入越权清单、不参与网络判定；敏感命中不会被折叠。\n")
        add("| 规则 | 说明 | 次数 | 示例 |")
        add("|---|---|---|---|")
        for entry in result["suppressed"]:
            samples = ", ".join(f"`{sample}`" for sample in entry.get("samples") or []) or "-"
            add(f"| {entry['title']} (`{entry['id']}`) | {entry.get('reason') or '-'} | {entry['count']} | {samples} |")
        add("")

    if result["resource_facts"]:
        add("## 内核资源事实佐证 (round_kernel.kernel_resource_facts)\n")
        add("| path | actions | open_count | read_count | read_bytes | lsm_allow_count |")
        add("|---|---|---|---|---|---|")
        for fact in result["resource_facts"]:
            add(
                f"| `{fact.get('path')}` | {', '.join(fact.get('actions', []))} | "
                f"{fact.get('open_count', '')} | {fact.get('read_count', '')} | "
                f"{fact.get('read_returned_bytes', '')} | {fact.get('lsm_allow_count', '')} |"
            )
        add("")

    report_path = round_dir / "analysis_report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    log.info(
        "[%s] 分析产物写入完成 elapsed=%.3fs violations_path=%s violations_size=%d bytes "
        "report_path=%s report_size=%d bytes",
        result["round_id"],
        time.monotonic() - started,
        violations_path,
        file_size(violations_path),
        report_path,
        file_size(report_path),
    )
    return violations_path, report_path


def is_mock_round(round_dir: Path) -> bool:
    """mock round 只用于本地测试，不应推送到正式展示接口。"""
    for name in ("round_end.json", "round_kernel.json", "ir.json"):
        path = round_dir / name
        if not path.is_file():
            continue
        try:
            metadata = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if metadata.get("is_mock") is True:
            return True
    return False


def push_kernel_report(round_id: str, report_path: Path) -> dict:
    """把内核态判断结果 Markdown 路径上报给前端展示接口。"""
    started = time.monotonic()
    payload = {
        "round_id": round_id,
        "judge_result_kernel_md_path": str(report_path.resolve()),
    }
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    log.info(
        "[%s] 开始上报内核分析报告 url=%s timeout=%ss payload=%s report_exists=%s report_size=%d bytes",
        round_id,
        SETTINGS.kernel_report_url,
        SETTINGS.kernel_report_push_timeout,
        payload,
        report_path.is_file(),
        file_size(report_path),
    )
    req = request.Request(
        SETTINGS.kernel_report_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=SETTINGS.kernel_report_push_timeout) as resp:
            body = resp.read().decode("utf-8")
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        log.exception("[%s] 上报失败 HTTPError status=%s elapsed=%.3fs body=%s", round_id, exc.code, time.monotonic() - started, body)
        raise RuntimeError(f"上报失败: HTTP {exc.code} {body}") from exc
    except error.URLError as exc:
        log.exception("[%s] 上报失败 URLError elapsed=%.3fs error=%s", round_id, time.monotonic() - started, exc)
        raise RuntimeError(f"上报失败: {exc}") from exc

    try:
        result = json.loads(body)
    except json.JSONDecodeError as exc:
        log.exception("[%s] 上报失败，响应不是 JSON elapsed=%.3fs body=%s", round_id, time.monotonic() - started, body)
        raise RuntimeError(f"上报失败: 响应不是 JSON: {body}") from exc
    if result.get("ok") is not True:
        log.error("[%s] 上报失败，响应未返回 ok=true elapsed=%.3fs response=%s", round_id, time.monotonic() - started, result)
        raise RuntimeError(f"上报失败: 响应未返回 ok=true: {result}")
    log.info("[%s] 上报成功 elapsed=%.3fs response=%s", round_id, time.monotonic() - started, result)
    return result


def mark_report_pushed(round_dir: Path, round_id: str, report_path: Path, response: dict) -> None:
    marker = {
        "round_id": round_id,
        "judge_result_kernel_md_path": str(report_path.resolve()),
        "endpoint": SETTINGS.kernel_report_url,
        "response": response,
    }
    marker_path = round_dir / PUSH_MARKER_NAME
    marker_path.write_text(json.dumps(marker, ensure_ascii=False, indent=2), encoding="utf-8")
    log.info("[%s] 已写入上报标记 marker_path=%s marker_size=%d bytes", round_id, marker_path, file_size(marker_path))


def push_and_mark_report(round_dir: Path, round_id: str, report_path: Path) -> bool:
    try:
        response = push_kernel_report(round_id, report_path)
    except RuntimeError as exc:
        log.error("[%s] 上报失败 error=%s report_path=%s", round_id, exc, report_path)
        return False

    mark_report_pushed(round_dir, round_id, report_path, response)
    return True


def analyze_write_and_push(round_dir: Path, push: bool = True) -> tuple[dict, Path]:
    result = analyze_round(round_dir)
    _, report_path = write_outputs(round_dir, result)
    if push and not is_mock_round(round_dir):
        if not push_and_mark_report(round_dir, result["round_id"], report_path):
            raise RuntimeError(f"report push failed for round {result['round_id']}")
    return result, report_path
