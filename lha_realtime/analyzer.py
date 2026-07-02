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
from pathlib import Path
from urllib import error, request

from .config import SETTINGS
from .logging_utils import setup_logging


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
    allowed = {"files": set(), "tools": set(), "file_actions": {}}
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


def extract_kernel_file_ops(lsm: list, syscalls: list) -> list:
    """以 LSM file_open 事件为主线，经 related_event_id 关联其 syscall，附带读写字节。"""
    sys_by_id = {s["event_id"]: s for s in syscalls}

    opens = {}
    reads = {}
    for syscall in syscalls:
        if syscall.get("action") == "open":
            ret = syscall.get("return_value")
            if isinstance(ret, int) and ret >= 0:
                opens.setdefault((syscall["pid"], ret), []).append(syscall["timestamp_mono_ns"])
        elif syscall.get("action") == "read":
            reads.setdefault((syscall["pid"], syscall["fd"]), []).append(
                (syscall["timestamp_mono_ns"], syscall.get("returned_bytes") or 0)
            )
    for values in opens.values():
        values.sort()
    for values in reads.values():
        values.sort()

    ops = []
    for hook in lsm:
        related = sys_by_id.get(hook.get("related_event_id"))
        open_fd = related.get("return_value") if related and related.get("action") == "open" else None
        open_ts = hook["timestamp_mono_ns"]

        read_bytes = read_count = 0
        if isinstance(open_fd, int) and open_fd >= 0:
            later = [ts for ts in opens.get((hook["pid"], open_fd), []) if ts > open_ts]
            next_open_ts = min(later) if later else float("inf")
            for ts, nb in reads.get((hook["pid"], open_fd), []):
                if open_ts <= ts < next_open_ts:
                    read_bytes += nb
                    read_count += 1

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
            }
        )
    ops.sort(key=lambda row: row["timestamp_mono_ns"])
    return ops


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


SENSITIVE_PREFIXES = (
    "/etc/passwd",
    "/etc/group",
    "/etc/shadow",
    "/etc/gshadow",
    "/var/log/secure",
    "/var/log/",
    "/root/.ssh",
    "/root/.openclaw",
    "/proc/",
    "/run/secrets",
)
RUNTIME_PREFIXES = (
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
    "/etc/ld.so.cache",
    "/usr/share/locale",
    "/usr/lib/locale",
    "/usr/bin",
    "/bin",
    "/etc/nsswitch.conf",
    "/run/systemd/userdb",
)


def classify(path: str | None) -> str:
    if path is None:
        return "unknown"
    if path.startswith(SENSITIVE_PREFIXES):
        return "sensitive"
    if path.startswith(RUNTIME_PREFIXES):
        return "runtime"
    return "other"


def analyze_round(round_dir: Path) -> dict:
    started = time.monotonic()
    input_files = {
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

    round_end = load_json_file(input_files["round_end"])
    round_kernel = load_json_file(input_files["round_kernel"])
    lsm = load_jsonl(input_files["lsm"])
    syscalls = load_jsonl(input_files["syscalls"])

    allowed = parse_allowlist(load_ir_source(round_dir, round_end))
    user_actions = parse_user_actions(round_end)
    resource_facts = parse_resource_facts(round_kernel)
    kernel_ops = extract_kernel_file_ops(lsm, syscalls)

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

    result = {
        "round_id": round_end.get("round_id", round_dir.name),
        "time_start": round_end.get("time_start"),
        "time_end": round_end.get("time_end"),
        "overall_score": round_end.get("overall_score"),
        "tool_name": round_kernel.get("round_id") and next(
            (op["tool_name"] for op in kernel_ops if op.get("tool_name")),
            None,
        ),
        "allowed_files": sorted(allowed["files"]),
        "allowed_tools": sorted(allowed["tools"]),
        "file_actions": allowed["file_actions"],
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
        "violations=%d sensitive=%d judge_mismatch=%d",
        result["round_id"],
        time.monotonic() - started,
        counts["lsm_total"],
        counts["syscall_total"],
        counts["kernel_file_ops"],
        counts["violations"],
        sensitive,
        counts["judge_mismatch"],
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
    add(f"- 时间窗: {result['time_start']} → {result['time_end']}")
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

    by_cat = {}
    for violation in result["violations"]:
        by_cat.setdefault(violation["category"], []).append(violation)
    cat_title = {
        "sensitive": "敏感越权",
        "runtime": "运行时加载",
        "other": "其他",
        "unknown": "未知路径",
    }
    add("## 越权清单（内核 LSM 放行，但用户态不允许）\n")
    for category in ("sensitive", "other", "runtime", "unknown"):
        items = by_cat.get(category)
        if not items:
            continue
        add(f"### {cat_title[category]} ({len(items)})\n")
        add("| path | hook | result | pid | event_id | rel_syscall | 读取字节 | 判据一致 |")
        add("|---|---|---|---|---|---|---|---|")
        for violation in items:
            agree = "yes" if violation["judges_agree"] else "no"
            add(
                f"| `{violation['path']}` | {violation['hook_name']} | {violation['result']} | "
                f"{violation['pid']} | {violation['event_id']} | {violation['related_event_id']} | "
                f"{violation['read_bytes']} | {agree} |"
            )
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
