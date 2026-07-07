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
    IGNORED_NETWORK_ENDPOINTS,
    OPENCLAW_RUNTIME_BASENAMES,
    OPENCLAW_RUNTIME_PREFIXES,
    RUNTIME_PREFIXES,
    SENSITIVE_PREFIXES,
    is_ignored_endpoint,
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


def network_detail(hook: dict) -> str:
    """从网络 hook 提取简明目标信息：地址族 + 远端地址（若有）。"""
    if not is_network_hook(hook.get("hook_name")):
        return ""
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
    parts = [p for p in (family, target) if p]
    return " ".join(str(p) for p in parts)


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


def parse_network_activity(lsm: list, syscalls: list) -> dict:
    """汇总该 round 的 send / receive 网络行为，并按忽略端点做整轮判定。

    只要出现 send/receive 系统调用或对应 LSM hook 就计入，不论目标是外部主机、
    本地 IPC 还是监控端口；并 best-effort 关联目标端点用于报告展示。

    针对 detection_rules.yaml 中配置的忽略端点（如工具去平台拉取线上配置的
    127.0.0.1:15100 / ::1:15100 / localhost:15100，端口需完整匹配）：若本轮所有
    可识别端点都落在忽略集合内，则整轮网络行为按正常处理（effective actions 置空、
    展示端点仅保留未忽略者）；只要出现其他端点（如恶意的 8.152.192.7），或无法识别
    任何端点，则保持原有判定逻辑。
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
    all_endpoints = set()

    # connect 的目标本身也纳入端点集合，即使之后没有 send/recv（例如恶意 connect 探测）。
    for records in conns.values():
        for _ts, endpoint in records:
            if endpoint:
                all_endpoints.add(endpoint)

    for hook in lsm:
        hook_actions = network_hook_actions(hook.get("hook_name"))
        if not hook_actions:
            continue
        observed_actions.update(hook_actions)
        detail = network_detail(hook)
        if detail:
            all_endpoints.add(detail)

    for syscall in syscalls:
        action = syscall.get("action")
        if action in NETWORK_SEND_ACTIONS:
            observed_actions.add("send")
        elif action in NETWORK_RECV_ACTIONS:
            observed_actions.add("receive")
        else:
            continue
        endpoint = lookup(syscall.get("pid"), syscall.get("fd"), syscall.get("timestamp_mono_ns", 0))
        if endpoint:
            all_endpoints.add(endpoint)

    ignored_endpoints = {e for e in all_endpoints if is_ignored_endpoint(e)}
    remaining_endpoints = all_endpoints - ignored_endpoints
    # 存在可识别端点且全部属于忽略集合 → 整轮网络视为正常（工具拉取线上配置）。
    suppressed = bool(all_endpoints) and not remaining_endpoints
    effective_actions = set() if suppressed else observed_actions

    return {
        "actions": effective_actions,
        "endpoints": remaining_endpoints,
        "observed_actions": observed_actions,
        "all_endpoints": all_endpoints,
        "ignored_endpoints": ignored_endpoints,
        "suppressed": suppressed,
    }


REGEX_HINTS = ("^", "$", "+", "|", "(", ")", "{", "}", "\\", ".*")
GLOB_HINTS = ("*", "?", "[")


def is_regex_pattern(identifier: str) -> bool:
    """Best-effort inference because IR identifiers do not carry pattern type."""
    return any(hint in identifier for hint in REGEX_HINTS)


def glob_to_regex(pattern: str) -> str:
    """Translate IR file globs so * stays within one path segment and ** spans dirs."""
    out = ["^"]
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "*":
            if index + 1 < len(pattern) and pattern[index + 1] == "*":
                index += 2
                if index < len(pattern) and pattern[index] == "/":
                    out.append("(?:.*/)?")
                    index += 1
                else:
                    out.append(".*")
                continue
            out.append("[^/]*")
            index += 1
            continue
        if char == "?":
            out.append("[^/]")
            index += 1
            continue
        if char == "[":
            end = index + 1
            if end < len(pattern) and pattern[end] in ("!", "^"):
                end += 1
            if end < len(pattern) and pattern[end] == "]":
                end += 1
            while end < len(pattern) and pattern[end] != "]":
                end += 1
            if end >= len(pattern):
                out.append(re.escape(char))
                index += 1
                continue
            content = pattern[index + 1 : end]
            if content.startswith("!"):
                content = "^" + content[1:]
            elif content.startswith("^"):
                content = "\\" + content
            out.append("[" + content.replace("\\", "\\\\") + "]")
            index = end + 1
            continue
        out.append(re.escape(char))
        index += 1
    out.append("$")
    return "".join(out)


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


# 敏感文件、运行时加载文件、openclaw 运行时文件/文档的定义均在 detection_rules.yaml 中配置，
# 由 lha_realtime.rules 加载为 SENSITIVE_PREFIXES / RUNTIME_PREFIXES /
# OPENCLAW_RUNTIME_PREFIXES / OPENCLAW_RUNTIME_BASENAMES。


def is_openclaw_runtime(path: str) -> bool:
    if path.startswith(OPENCLAW_RUNTIME_PREFIXES):
        return True
    basename = path.rsplit("/", 1)[-1]
    if basename in OPENCLAW_RUNTIME_BASENAMES and ("/.openclaw/" in path or "/workspace/" in path):
        return True
    return False


def classify(path: str | None) -> str:
    if path is None:
        return "unknown"
    if is_openclaw_runtime(path):
        return "runtime"
    if path.startswith(SENSITIVE_PREFIXES):
        return "sensitive"
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


def detect_anomalies(violations: list, kernel_ops: list, allowed: dict, net_observed: dict) -> dict:
    """依据两条规则给出明确判定：敏感文件越权、IR action 与实际行为不一致。"""
    types = []

    sensitive_paths = sorted(
        {v["path"] for v in violations if v.get("category") == "sensitive" and v.get("path")}
    )
    if sensitive_paths:
        types.append({"type": "访问危险文件（敏感越权）", "paths": sensitive_paths})

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
    lsm = load_jsonl(input_files["lsm"])
    syscalls = load_jsonl(input_files["syscalls"])

    allowed = parse_allowlist(load_ir_source(round_dir, round_end))
    user_actions = parse_user_actions(round_end)
    resource_facts = parse_resource_facts(round_kernel)
    kernel_ops = extract_kernel_file_ops(lsm, syscalls)
    net_observed = parse_network_activity(lsm, syscalls)

    violations = []
    role_ir_mismatch = 0
    for op in kernel_ops:
        ir_violation = not is_allowed(op["path"], allowed["files"])
        role_violation = op["resource_role"] == "privacy_resource"
        if ir_violation != role_violation:
            role_ir_mismatch += 1
        if ir_violation or role_violation:
            violation = dict(op)
            violation["kernel_category"] = violation.pop("category", None)
            violation["category"] = classify(op["path"])
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
        "is_anomaly": anomaly["is_anomaly"],
        "anomaly_types": anomaly["types"],
        "user_actions": user_actions,
        "resource_facts": resource_facts,
        "counts": {
            "lsm_total": len(lsm),
            "syscall_total": len(syscalls),
            "kernel_file_ops": len(kernel_ops),
            "violations": len(violations),
            "judge_mismatch": role_ir_mismatch,
        },
        "violations": violations,
    }
    counts = result["counts"]
    sensitive = sum(1 for violation in violations if violation["category"] == "sensitive")
    log.info(
        "[%s] 分析完成 elapsed=%.3fs lsm_total=%d syscall_total=%d kernel_file_ops=%d "
        "violations=%d sensitive=%d judge_mismatch=%d net_suppressed=%s net_ignored=%s "
        "net_observed=%s net_endpoints=%s",
        result["round_id"],
        time.monotonic() - started,
        counts["lsm_total"],
        counts["syscall_total"],
        counts["kernel_file_ops"],
        counts["violations"],
        sensitive,
        counts["judge_mismatch"],
        net_observed["suppressed"],
        sorted(net_observed["ignored_endpoints"]),
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
                paths = ", ".join(f"`{p}`" for p in item["paths"])
                add(f"  - {item['type']}: {paths}")
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
    add(
        f"- **越权操作: {counts['violations']} 个**（ir_json 与内核 resource_role 判据分歧: "
        f"{counts['judge_mismatch']} 处）\n"
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
            add(f"#### {cat_title[category]}（{len(agg)} 个路径 / {len(items)} 次）\n")
            add("| path | hook | 动作 | 次数 | 读取字节 | 判据一致 |")
            add("|---|---|---|---|---|---|")
            for path in sorted(agg, key=lambda p: (-agg[p]["count"], p or "")):
                entry = agg[path]
                agree = {True: "yes", False: "no"}
                agree_val = agree[next(iter(entry["agree"]))] if len(entry["agree"]) == 1 else "部分"
                add(
                    f"| `{path}` | {', '.join(sorted(entry['hooks']))} | "
                    f"{', '.join(sorted(entry['actions']))} | {entry['count']} | "
                    f"{entry['read_bytes']} | {agree_val} |"
                )
            add("")

    add("### 网络\n")
    if result.get("network_suppressed"):
        ignored = ", ".join(f"`{e}`" for e in result.get("network_ignored_endpoints", []))
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
