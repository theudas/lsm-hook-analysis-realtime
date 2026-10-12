#!/usr/bin/env python3
"""内核行为豁免建议：重放语料，找出高频出现、可以加入豁免的内核行为。

只看内核侧事实（LSM hook、观测到的读写动作、路径、网络端点），不看工具调用与
IR 允许集。对每个 round 的全部内核操作，先用当前 detection_rules.yaml 排除已被
system_baseline / 忽略端点豁免的部分，再统计剩余行为出现在多少比例的 round 里：

  - 豁免建议      高频行为逐项给出 建议豁免 / 需人工确认 / 不建议 及依据，附可展开的 YAML
  - 文件行为热力图  路径 × 内核 hook，每格 = 出现该组合的 round 比例
  - 网络行为热力图  端点 × 内核 hook，每格 = 出现该组合的 round 比例
  - 已生效的豁免    现有基线规则各自折叠了多少内核操作

产出一个自包含 HTML（不依赖 JavaScript 也能完整显示）。只读 input/，不写任何
round 产物、不连后端、不碰 state/realtime.db。

用法（在项目根目录执行）：
  python3 scripts/hotspot_stats.py            # 生成 reports/hotspot.html
  python3 scripts/hotspot_stats.py --serve    # 启动本地页面，页面上的“刷新”按钮会重新统计
"""

from __future__ import annotations

import argparse
import collections
import html
import ipaddress
import json
import logging
import os
import re
import subprocess
import sys
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from lha_realtime import analyzer  # noqa: E402
from lha_realtime.rules import BASELINE_RULES, WRITE_ACTIONS, _rules_path  # noqa: E402

# 路径所在位置决定豁免的风险：系统目录的只读访问通常是系统自带行为；
# 用户可写目录里的内容多来自测试用例或工具自身产物，豁免会掩盖真实行为。
SYSTEM_DIRS = ("/usr/", "/lib/", "/lib64/", "/etc/", "/proc/", "/sys/", "/dev/", "/run/", "/var/run/",
               "/var/lib/", "/var/cache/")
USER_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/root/", "/workspace/")
EXEC_HOOKS = {"bprm_check"}
# 终端与空设备：程序把输出写到这里是常规行为，写入不代表篡改。
OUTPUT_DEVICES = ("/dev/null", "/dev/zero", "/dev/full", "/dev/tty", "/dev/pts", "/dev/console")

ACCEPT, REVIEW, REJECT = "accept", "review", "reject"
VERDICT_LABEL = {ACCEPT: "✓ 建议豁免", REVIEW: "! 需人工确认", REJECT: "✕ 不建议豁免"}
VERDICT_ORDER = {ACCEPT: 0, REVIEW: 1, REJECT: 2}


def rel(path: Path | str) -> str:
    """输出里一律写相对项目根目录的路径，不暴露部署机器上的绝对路径。"""
    return Path(os.path.relpath(Path(path).resolve(), PROJECT_ROOT)).as_posix()


def bucket(path: str, depth: int) -> str:
    """把路径归一到前 depth 段，并抹掉 pid、临时目录名等每轮都会变的部分。"""
    path = re.sub(r"^/proc/\d+", "/proc/<pid>", path)
    path = re.sub(r"^/tmp/[^/]+", "/tmp/<x>", path)
    parts = [p for p in path.split("/") if p]
    return "/" + "/".join(parts[:depth])


def pct(value: float) -> str:
    return f"{value * 100:.1f}%" if 0 < value < 0.1 else f"{value * 100:.0f}%"


def round_dirs(input_dir: Path) -> list[Path]:
    return sorted(d for d in input_dir.iterdir() if (d / "kernel_lsm_hook_result.jsonl").is_file())


def new_meta() -> dict:
    return {"rounds": set(), "hooks": collections.Counter(), "actions": set(), "categories": set(),
            "count": 0, "examples": [], "deeper": False}


def collect(input_dir: Path, depth: int) -> dict:
    files: dict = collections.defaultdict(new_meta)
    nets: dict = collections.defaultdict(new_meta)
    folds: dict = collections.defaultdict(new_meta)
    file_cells = collections.defaultdict(set)
    net_cells = collections.defaultdict(set)
    fold_cells = collections.defaultdict(set)
    rounds = broken = total_ops = folded_ops = 0
    for round_dir in round_dirs(input_dir):
        try:
            lsm = analyzer.load_jsonl(round_dir / "kernel_lsm_hook_result.jsonl")
            syscalls = analyzer.load_jsonl(round_dir / "kernel_syscall_seq.jsonl")
            ops = analyzer.extract_kernel_file_ops(lsm, syscalls)
        except (ValueError, KeyError, TypeError, AttributeError):
            broken += 1
            continue
        rounds += 1
        rid = round_dir.name
        for op in ops:
            total_ops += 1
            hook = op.get("hook_name") or "-"
            path = op.get("path")
            category = analyzer.classify(path, op) if path else "unknown"
            rule = analyzer.fold_rule(op, category)
            if rule is not None:
                folded_ops += 1
                meta = folds[rule["id"]]
                meta["title"] = rule["title"]
                key, meta_cells = rule["id"], fold_cells
            elif op.get("is_network"):
                if not op.get("net_target"):
                    continue  # LSM 层收发不带地址，无法归到具体端点
                key, meta, meta_cells = op["net_target"], nets[op["net_target"]], net_cells
            elif path:
                key = bucket(path, depth)
                meta, meta_cells = files[key], file_cells
                normalized = bucket(path, 64)
                meta["deeper"] |= normalized != key
                if normalized not in meta["examples"] and len(meta["examples"]) < 3:
                    meta["examples"].append(normalized)
            else:
                continue
            meta["rounds"].add(rid)
            meta["hooks"][hook] += 1
            if not op.get("is_network"):
                # 网络 hook 没有 open flags，observed_actions 里的 read 只是缺省值，不展示。
                meta["actions"].update(op.get("observed_actions") or ())
            meta["categories"].add(category)
            meta["count"] += 1
            meta_cells[(key, hook)].add(rid)
    return {
        "rounds": rounds, "broken": broken, "total_ops": total_ops, "folded_ops": folded_ops,
        "files": files, "nets": nets, "folds": folds,
        "file_cells": file_cells, "net_cells": net_cells, "fold_cells": fold_cells,
    }


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")[:48] or "candidate"


def yaml_list(values) -> str:
    return "[" + ", ".join(json.dumps(v, ensure_ascii=False) for v in values) + "]"


def advise_file(path: str, meta: dict, share: float) -> tuple[str, list]:
    reasons = [f"出现在 {pct(share)} 的 round（{len(meta['rounds'])} 轮 / {meta['count']} 次）"]
    categories = meta["categories"]
    writes = sorted(meta["actions"] & WRITE_ACTIONS)
    location = path + "/"
    if "sensitive" in categories:
        return REJECT, reasons + ["命中敏感分组；基线规则本身也不会折叠敏感命中"]
    if writes and path.startswith(OUTPUT_DEVICES) and set(writes) == {"write"}:
        return ACCEPT, reasons + ["终端/空设备，写入是程序的正常输出，不构成篡改"]
    if writes:
        return REJECT, reasons + [f"观测到 {', '.join(writes)}，豁免会掩盖篡改，只读访问才适合豁免"]
    reasons.append("只观测到读取")
    if location.startswith(USER_DIRS):
        if categories == {"runtime"}:
            return REVIEW, reasons + ["位于用户目录，但已归类为框架运行时文件，确认是框架自身文件后可豁免"]
        return REJECT, reasons + ["位于用户可写目录，内容多来自测试用例或工具自身产物，宜保留观察"]
    if EXEC_HOOKS & set(meta["hooks"]):
        return REVIEW, reasons + ["包含 bprm_check（程序执行），豁免后报告里不再显示执行了该程序"]
    if not location.startswith(SYSTEM_DIRS):
        return REVIEW, reasons + ["不在常见系统目录下，需确认是否属于系统自带行为"]
    if categories != {"runtime"}:
        return REVIEW, reasons + ["位于系统目录，但未被 runtime_prefixes 覆盖（类别 other），需确认用途"]
    return ACCEPT, reasons + ["位于系统目录，已归类为运行时加载，属于系统自带的只读行为"]


def file_yaml(path: str, meta: dict, share: float) -> str:
    pattern = re.sub(r"<[^>]+>", "*", path)
    globs = [pattern, f"{pattern}/**"] if meta["deeper"] else [pattern]
    hooks = [h for h, _ in meta["hooks"].most_common()]
    lines = [
        f"  - id: {slug(path)}",
        f'    title: "{path} 访问"',
        f'    reason: "高频内核行为：出现在 {pct(share)} 的 round（由 hotspot_stats 生成，确认后再改写说明）"',
        f"    hooks: {yaml_list(hooks)}",
        f"    categories: {yaml_list(sorted(meta['categories']))}",
        f"    actions: {yaml_list(sorted(meta['actions']))}",
        "    globs:",
        *(f"      - {json.dumps(g, ensure_ascii=False)}" for g in globs),
    ]
    return "system_baseline:\n" + "\n".join(lines)


def is_loopback(endpoint: str) -> bool:
    host = endpoint.rsplit(":", 1)[0]
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def advise_net(endpoint: str, meta: dict, share: float) -> tuple[str, list, str | None]:
    reasons = [f"出现在 {pct(share)} 的 round（{len(meta['rounds'])} 轮 / {meta['count']} 次）"]
    if endpoint.startswith("/"):
        reasons.append("本机 Unix socket，不出本机；确认是系统服务的套接字后可加入 system_baseline")
        snippet = "\n".join([
            "system_baseline:",
            f"  - id: {slug(endpoint)}",
            f'    title: "{endpoint} 本机套接字"',
            f'    reason: "高频内核行为：出现在 {pct(share)} 的 round（由 hotspot_stats 生成，确认后再改写说明）"',
            "    endpoints:",
            f"      - {json.dumps(endpoint, ensure_ascii=False)}",
        ])
        return REVIEW, reasons, snippet
    if is_loopback(endpoint):
        reasons.append("本机回环地址；确认是平台或系统自身服务后可加入 network.ignored_endpoints")
        return REVIEW, reasons, f"network:\n  ignored_endpoints:\n    - {json.dumps(endpoint)}"
    reasons.append("非本机地址：豁免会掩盖外连，是否放行需人工决定，这里不给配置")
    return REJECT, reasons, None


def build(stats: dict, top: int, threshold: float) -> dict:
    total = stats["rounds"]

    def share(meta: dict) -> float:
        return len(meta["rounds"]) / total if total else 0.0

    suggestions = []
    for path, meta in stats["files"].items():
        if share(meta) < threshold:
            continue
        verdict, reasons = advise_file(path, meta, share(meta))
        suggestions.append({
            "kind": "文件", "behavior": path, "verdict": verdict, "reasons": reasons, "share": share(meta),
            "rounds": len(meta["rounds"]), "count": meta["count"], "hooks": [h for h, _ in meta["hooks"].most_common()],
            "actions": sorted(meta["actions"]), "examples": meta["examples"] if meta["deeper"] else [],
            "yaml": file_yaml(path, meta, share(meta)) if verdict != REJECT else None,
        })
    for endpoint, meta in stats["nets"].items():
        if share(meta) < threshold:
            continue
        verdict, reasons, snippet = advise_net(endpoint, meta, share(meta))
        suggestions.append({
            "kind": "网络", "behavior": endpoint, "verdict": verdict, "reasons": reasons, "share": share(meta),
            "rounds": len(meta["rounds"]), "count": meta["count"], "hooks": [h for h, _ in meta["hooks"].most_common()],
            "actions": sorted(meta["actions"]), "examples": [], "yaml": snippet,
        })
    suggestions.sort(key=lambda s: (VERDICT_ORDER[s["verdict"]], -s["share"], s["behavior"]))
    verdict_of = {s["behavior"]: s["verdict"] for s in suggestions}

    def matrix(metas: dict, cells: dict, label=None) -> dict:
        rows = sorted(metas, key=lambda k: (-len(metas[k]["rounds"]), k))[:top]
        hooks = collections.Counter()
        for row in rows:
            hooks.update(metas[row]["hooks"])
        cols = [h for h, _ in hooks.most_common()]
        return {
            "rows": rows,
            "cols": cols,
            "cells": [[len(cells.get((r, c), ())) / total if total else 0 for c in cols] for r in rows],
            "notes": {
                r: {"label": label(r) if label else r, "share": share(metas[r]), "count": metas[r]["count"],
                    "categories": "/".join(sorted(metas[r]["categories"])), "verdict": verdict_of.get(r)}
                for r in rows
            },
        }

    titles = {rule.id: rule.title for rule in BASELINE_RULES}
    titles["ignored_network_endpoint"] = analyzer.IGNORED_ENDPOINT_FOLD["title"]
    counts = collections.Counter(s["verdict"] for s in suggestions)
    return {
        "summary": {
            "rounds": total, "broken": stats["broken"], "total_ops": stats["total_ops"],
            "folded_ops": stats["folded_ops"], "accept": counts[ACCEPT], "review": counts[REVIEW],
            "reject": counts[REJECT],
        },
        "suggestions": suggestions,
        "file": matrix(stats["files"], stats["file_cells"]),
        "net": matrix(stats["nets"], stats["net_cells"]),
        "fold": matrix(stats["folds"], stats["fold_cells"], label=lambda r: titles.get(r, r)),
    }


# ---------------------------------------------------------------------------
# HTML 渲染：表格与颜色全部在这里算好，页面不依赖 JavaScript 也能完整显示。
# ---------------------------------------------------------------------------

# 色阶两端（浅色 / 深色主题各一套）：低值贴近卡片底色，高值为单一蓝色的深/亮端。
SEQ = {"light": ("#fcfcfb", "#104281"), "dark": ("#1a1a19", "#86b6ef")}
INK = {"light": ("#52514e", "#ffffff"), "dark": ("#c3c2b7", "#0b0b0b")}
HOT = 0.55  # 归一化值超过它时格内文字换成反色


def _srgb_to_oklab(hex_color: str) -> tuple:
    def lin(c: float) -> float:
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (lin(int(hex_color[i:i + 2], 16) / 255) for i in (1, 3, 5))
    l_ = (0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b) ** (1 / 3)
    m_ = (0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b) ** (1 / 3)
    s_ = (0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b) ** (1 / 3)
    return (
        0.2104542553 * l_ + 0.7936177850 * m_ - 0.0040720468 * s_,
        1.9779984951 * l_ - 2.4285922050 * m_ + 0.4505937099 * s_,
        0.0259040371 * l_ + 0.7827717662 * m_ - 0.8086757660 * s_,
    )


def _oklab_to_hex(lab: tuple) -> str:
    L, a, b = lab
    l_ = (L + 0.3963377774 * a + 0.2158037573 * b) ** 3
    m_ = (L - 0.1055613458 * a - 0.0638541728 * b) ** 3
    s_ = (L - 0.0894841775 * a - 1.2914855480 * b) ** 3
    rgb = (
        4.0767416621 * l_ - 3.3077115913 * m_ + 0.2309699292 * s_,
        -1.2684380046 * l_ + 2.6097574011 * m_ - 0.3413193965 * s_,
        -0.0041960863 * l_ - 0.7034186147 * m_ + 1.7076147010 * s_,
    )

    def enc(c: float) -> int:
        c = min(1.0, max(0.0, c))
        c = 12.92 * c if c <= 0.0031308 else 1.055 * c ** (1 / 2.4) - 0.055
        return round(c * 255)

    return "#" + "".join(f"{enc(c):02x}" for c in rgb)


def seq_color(theme: str, value: float) -> str:
    """在 OKLab 空间里按 value∈[0,1] 插值，得到感知均匀的单色色阶。"""
    lo, hi = (_srgb_to_oklab(c) for c in SEQ[theme])
    return _oklab_to_hex(tuple(x + (y - x) * value for x, y in zip(lo, hi)))


def verdict_badge(verdict: str | None) -> str:
    if not verdict:
        return ""
    return f'<span class="verdict {verdict}"><span class="dot"></span>{html.escape(VERDICT_LABEL[verdict])}</span>'


def heatmap_html(title: str, desc: str, mx: dict, *, show_verdict: bool) -> str:
    esc = html.escape
    out = [f"<section><h2>{esc(title)}</h2><p class=\"desc\">{esc(desc)}</p>"]
    if not mx["rows"]:
        return "".join(out) + '<p class="empty">无数据</p></section>'
    out.append('<div class="legend"><span>0</span><span class="bar"></span><span>100% 的 round</span></div>')
    out.append('<div class="scroll"><table class="hm"><thead><tr><th></th>')
    out.extend(f'<th title="{esc(col)}">{esc(col)}</th>' for col in mx["cols"])
    out.append("<th>合计</th></tr></thead><tbody>")
    for row, cells in zip(mx["rows"], mx["cells"]):
        note = mx["notes"][row]
        tags = f'<span class="tag">{esc(note["categories"])}</span>' if note["categories"] else ""
        if show_verdict:
            tags += verdict_badge(note["verdict"])
        out.append(f'<tr><th scope="row">{esc(note["label"])}{tags}</th>')
        for col, value in zip(mx["cols"], cells):
            tip = f"{note['label']} × {col}：{pct(value)} 的 round 出现"
            if not value:
                out.append(f'<td class="cell zero" tabindex="0" title="{esc(tip)}"></td>')
                continue
            style = ";".join(
                f"--bg-{t[0]}:{seq_color(t, value)};--ink-{t[0]}:{INK[t][1] if value > HOT else INK[t][0]}"
                for t in ("light", "dark")
            )
            out.append(f'<td class="cell" tabindex="0" style="{style}" title="{esc(tip)}">{pct(value)}</td>')
        out.append(f'<td class="total">{pct(note["share"])} · {note["count"]:,} 次</td></tr>')
    out.append("</tbody></table></div></section>")
    return "".join(out)


def suggestions_html(items: list, threshold: float) -> str:
    esc = html.escape
    out = [
        "<section id=\"suggestions\"><h2>豁免建议</h2>",
        f'<p class="desc">出现在 ≥ {pct(threshold)} 的 round、且尚未被现有规则豁免的内核行为。'
        "“建议豁免”与“需人工确认”附 YAML 片段，确认后合入 detection_rules.yaml 即可；"
        "敏感命中即使加入也不会被折叠。</p>",
    ]
    if not items:
        return "".join(out) + '<p class="empty">没有达到阈值的高频行为，当前规则已覆盖。</p></section>'
    out.append('<div class="scroll"><table class="list"><thead><tr><th>结论</th><th>内核行为</th>'
               "<th>hook / 动作</th><th>round 占比</th><th>依据与配置建议</th></tr></thead><tbody>")
    for item in items:
        examples = ""
        if item["examples"]:
            examples = '<div class="examples">如 ' + "、".join(f"<code>{esc(e)}</code>" for e in item["examples"]) + "</div>"
        reasons = "".join(f"<li>{esc(r)}</li>" for r in item["reasons"])
        config = ""
        if item["yaml"]:
            config = (f'<details><summary>YAML 配置建议</summary><pre>{esc(item["yaml"])}</pre>'
                      '<button type="button" class="js-only copy">复制</button></details>')
        out.append(
            f'<tr class="row-{item["verdict"]}"><td>{verdict_badge(item["verdict"])}</td>'
            f'<td><span class="kind">{esc(item["kind"])}</span><code>{esc(item["behavior"])}</code>{examples}</td>'
            f'<td>{esc(", ".join(item["hooks"]))}<div class="sub">{esc(", ".join(item["actions"]) or "-")}</div></td>'
            f'<td class="num">{pct(item["share"])}<div class="sub">{item["rounds"]} 轮 / {item["count"]:,} 次</div></td>'
            f"<td><ul>{reasons}</ul>{config}</td></tr>"
        )
    out.append("</tbody></table></div></section>")
    return "".join(out)


def render(data: dict, out: Path) -> None:
    esc = html.escape
    s, m = data["summary"], data["meta"]
    parts = [
        '<header><div><h1>内核行为豁免建议</h1>',
        f'<div class="meta">生成于 <span id="generated">{esc(m["generated"])}</span> · 规则 {esc(m["rules"])}'
        f' · 语料 {esc(m["input_dir"])} · 路径归并到前 {m["depth"]} 段 · 阈值 {pct(m["threshold"])}</div></div>',
        '<div class="refresh js-only"><button type="button" id="refresh">刷新</button>'
        '<span id="refresh-status" role="status"></span></div>',
        '<noscript><div class="meta">刷新：重新运行 <code>python3 scripts/hotspot_stats.py</code></div></noscript>',
        "</header>",
        '<div class="tiles">',
    ]

    def tile(label: str, value: str, sub: str) -> None:
        parts.append(f'<div class="tile"><div class="label">{esc(label)}</div>'
                     f'<div class="value">{esc(value)}</div><div class="sub">{esc(sub)}</div></div>')

    folded_share = s["folded_ops"] / s["total_ops"] if s["total_ops"] else 0
    tile("分析 round", f"{s['rounds']:,}", f"另有 {s['broken']} 个损坏跳过" if s["broken"] else "无损坏")
    tile("内核操作", f"{s['total_ops']:,}", "全部 LSM 放行记录")
    tile("已被豁免折叠", pct(folded_share), f"{s['folded_ops']:,} 条")
    tile("建议豁免", str(s["accept"]), "系统自带的常规行为")
    tile("需人工确认", str(s["review"]), "看依据后再决定")
    tile("不建议豁免", str(s["reject"]), "高频但豁免有风险")
    parts.append("</div>")

    parts.append(suggestions_html(data["suggestions"], m["threshold"]))
    parts.append(heatmap_html(
        "文件行为 × 内核 hook",
        "尚未被豁免的文件类内核操作。每格 = 出现该路径 × hook 组合的 round 比例；整行都深色的通常是系统自带行为。",
        data["file"], show_verdict=True,
    ))
    parts.append(heatmap_html(
        "网络端点 × 内核 hook",
        "尚未被豁免、能识别出端点的网络类内核操作（LSM 层收发不带地址，不计入）。",
        data["net"], show_verdict=True,
    ))
    parts.append(heatmap_html(
        "已生效的豁免",
        "现有 system_baseline 规则与忽略端点在各 hook 上折叠了多少 round 的内核操作。",
        data["fold"], show_verdict=False,
    ))

    template = (Path(__file__).parent / "hotspot_template.html").read_text(encoding="utf-8")
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(f".{out.name}.tmp")
    tmp.write_text(template.replace("<!--__BODY__-->", "\n".join(parts)), encoding="utf-8")
    tmp.replace(out)


def generate(args) -> int:
    stats = collect(args.input_dir, args.depth)
    if not stats["rounds"]:
        print(f"没有可分析的 round：{rel(args.input_dir)}", file=sys.stderr)
        return 1
    data = build(stats, args.top, args.threshold)
    data["meta"] = {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "input_dir": rel(args.input_dir),
        "rules": rel(_rules_path()),
        "depth": args.depth,
        "threshold": args.threshold,
    }
    render(data, args.out)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    s = data["summary"]
    print(f"rounds={s['rounds']} ops={s['total_ops']} folded={s['folded_ops']} accept={s['accept']} "
          f"review={s['review']} reject={s['reject']} -> {rel(args.out)}")
    return 0


def serve(args) -> int:
    """本地页面服务：GET / 返回最新 HTML，POST /refresh 在子进程里重新统计。

    用子进程重新生成，是因为检测规则在 import 时加载；这样每次刷新都会读到最新的
    detection_rules.yaml 和 input/ 下新到的 round。
    """
    child = [sys.executable, str(Path(__file__).resolve()), "--input-dir", str(args.input_dir),
             "--out", str(args.out), "--depth", str(args.depth), "--top", str(args.top),
             "--threshold", str(args.threshold)]
    lock = threading.Lock()

    def regenerate() -> tuple[bool, str]:
        with lock:
            proc = subprocess.run(child, capture_output=True, text=True)
        lines = (proc.stdout if proc.returncode == 0 else proc.stderr).strip().splitlines()
        return proc.returncode == 0, lines[-1] if lines else ""

    class Handler(BaseHTTPRequestHandler):
        def reply(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path.split("?", 1)[0] not in ("/", "/hotspot.html") or not args.out.is_file():
                self.reply(404, b"not found", "text/plain; charset=utf-8")
                return
            self.reply(200, args.out.read_bytes(), "text/html; charset=utf-8")

        def do_POST(self) -> None:
            if self.path != "/refresh":
                self.reply(404, b"not found", "text/plain; charset=utf-8")
                return
            # 只接受本页面发起的刷新，避免其他网页跨站触发重算。
            origin = self.headers.get("Origin")
            if origin and origin.split("://", 1)[-1] != self.headers.get("Host"):
                self.reply(403, b'{"ok": false, "error": "cross-origin refresh rejected"}', "application/json")
                return
            ok, message = regenerate()
            body = json.dumps({"ok": ok, "message": message}, ensure_ascii=False).encode("utf-8")
            self.reply(200 if ok else 500, body, "application/json; charset=utf-8")

        def log_message(self, fmt: str, *values) -> None:
            print(f"[hotspot] {self.address_string()} {fmt % values}")

    ok, message = regenerate()
    print(message)
    if not ok:
        return 1
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"打开 http://{args.host}:{args.port}/ 查看；页面上的“刷新”按钮会重新统计。Ctrl+C 退出。")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input-dir", type=Path, default=PROJECT_ROOT / "input")
    parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "reports" / "hotspot.html")
    parser.add_argument("--json", type=Path, help="同时把统计数据写成 JSON")
    parser.add_argument("--depth", type=int, default=3, help="路径归并到前几段（默认 3）")
    parser.add_argument("--top", type=int, default=30, help="热力图最多展示的行数")
    parser.add_argument("--threshold", type=float, default=0.2, help="进入豁免建议的最低 round 占比（默认 0.2）")
    parser.add_argument("--serve", action="store_true", help="启动本地页面，支持页面内刷新")
    parser.add_argument("--host", default="127.0.0.1", help="--serve 监听地址（默认只对本机开放）")
    parser.add_argument("--port", type=int, default=8765, help="--serve 监听端口")
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)  # 重放上百个 round，analyzer 的逐条日志只会刷屏
    return serve(args) if args.serve else generate(args)


if __name__ == "__main__":
    raise SystemExit(main())
