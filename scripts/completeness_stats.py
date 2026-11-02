#!/usr/bin/env python3
"""采集完整度看板：input/ 下每个 round 收齐了没有，按时间看比例与示例。

只读 input/，不写任何 round 产物、不连后端、不碰 state/realtime.db。“收齐”的
判定与分析和看门狗共用同一套口径（lha_realtime.watchdog）：六类输入（round_start /
round_end / round_kernel + 两份内核 JSONL / ir）齐全才算收齐；ir 允许来自旧上游
内嵌在 round_end.ir_json 的格式。

产出一个自包含 HTML：不依赖 JavaScript 也能完整看到全时间范围的结论；打开
JavaScript 后可按时间范围筛选（时间桶粒度自动选择，可手动切换），图、表、
统计卡片全部随所选范围联动。

用法（在项目根目录执行）：
  python3 scripts/completeness_stats.py            # 生成 reports/completeness.html
  python3 scripts/completeness_stats.py --serve    # 启动本地页面，页面上的“刷新”按钮会重新统计
"""

from __future__ import annotations

import argparse
import collections
import html
import json
import logging
import math
import os
import subprocess
import sys
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from lha_realtime.watchdog import COMPLETE_MASK, REQUIRED_FILES, input_mask  # noqa: E402

HOUR, DAY, WEEK = 3600, 86400, 7 * 86400
MAX_BUCKETS = 240
ARRIVAL_FILES = ("round_start.json", "round_end.json", "round_kernel.json", "ir.json")


def rel(path: Path | str) -> str:
    """输出里一律写相对项目根目录的路径，不暴露部署机器上的绝对路径。"""
    return Path(os.path.relpath(Path(path).resolve(), PROJECT_ROOT)).as_posix()


def pct(value: float) -> str:
    return f"{value * 100:.1f}%" if 0 < value < 0.1 else f"{value * 100:.0f}%"


def compact(value: int) -> str:
    return f"{value / 1000:.1f}K" if value >= 1000 else f"{value:,}"


def round_time(round_dir: Path) -> float:
    """round 的起点时间：round_start.json 的落盘时间即首条消息到达时间。

    消息乱序到达时回退到其余输入文件里最早的；内核 JSONL 用 copy2 拷贝、保留
    上游 mtime，只能作最后回退。取整到秒，与页面内嵌数据的时间戳精度一致。"""
    start = round_dir / "round_start.json"
    if start.is_file():
        stamps = [start.stat().st_mtime]
    else:
        stamps = [(round_dir / name).stat().st_mtime for name in ARRIVAL_FILES if (round_dir / name).is_file()]
        if not stamps:
            stamps = [(round_dir / name).stat().st_mtime for name in REQUIRED_FILES if (round_dir / name).is_file()]
    if not stamps:
        stamps = [round_dir.stat().st_mtime]
    return round(min(stamps))


def scan_rounds(input_dir: Path) -> list[dict]:
    if not input_dir.is_dir():
        return []
    records = []
    for entry in sorted(input_dir.iterdir()):
        if not entry.is_dir() or entry.name.startswith("."):
            continue
        records.append({"id": entry.name, "t": round_time(entry), "m": input_mask(entry)})
    return records


def missing_from_mask(mask: int) -> list[str]:
    items = []
    if not mask & 1:
        items.append("round_start")
    if not mask & 2:
        items.append("round_end")
    if not mask & 4:
        items.append("round_kernel")
    elif not (mask & 8 and mask & 16):
        items.append("内核数据文件")
    if not mask & 32:
        items.append("ir")
    return items


def auto_bucket_seconds(span: float) -> int:
    if span <= 2 * DAY:
        return HOUR
    if span <= 180 * DAY:
        return DAY
    return WEEK


def bucketize(records: list[dict], t0: float, t1: float, seconds: int) -> tuple[list[dict], int]:
    """把 [t0, t1] 连续切成时间桶（空桶保留，断采期一目了然），桶数超上限自动放粗。"""
    if t1 < t0:
        t1 = t0
    while (t1 - t0) / max(seconds, 1) > MAX_BUCKETS:
        seconds *= 2
    start = math.floor(t0 / seconds) * seconds
    spans: dict[int, list[int]] = {}
    for record in records:
        t = record["t"]
        if t < t0 or t > t1:
            continue
        bucket = spans.setdefault(int((t - start) // seconds), [0, 0])
        bucket[0 if record["m"] == COMPLETE_MASK else 1] += 1
    buckets = []
    for idx in range(int((t1 - start) // seconds) + 1):
        ok, bad = spans.get(idx, [0, 0])
        buckets.append({"start": start + idx * seconds, "ok": ok, "bad": bad})
    return buckets, seconds


def bucket_label(t: float, seconds: int) -> str:
    dt = datetime.fromtimestamp(t)
    if seconds < DAY:
        return dt.strftime("%m-%d %H:00")
    return dt.strftime("%Y-%m-%d")


def nice_ceiling(value: float) -> float:
    """把 y 轴上限抬到 1/2/5×10^k 的整数刻度。"""
    if value <= 0:
        return 1.0
    power = 10 ** math.floor(math.log10(value))
    for step in (1, 2, 5, 10):
        if step * power >= value:
            return step * power
    return power * 10


def build(records: list[dict], t0: float, t1: float, bucket_seconds: int | None = None,
          examples_limit: int = 50) -> dict:
    in_range = [r for r in records if t0 <= r["t"] <= t1]
    total = len(in_range)
    ok = sum(1 for r in in_range if r["m"] == COMPLETE_MASK)
    bad = total - ok
    seconds = bucket_seconds or auto_bucket_seconds(t1 - t0)
    buckets, seconds = bucketize(in_range, t0, t1, seconds)

    patterns: dict[tuple[str, ...], list[str]] = collections.OrderedDict()
    for record in in_range:
        if record["m"] == COMPLETE_MASK:
            continue
        patterns.setdefault(tuple(missing_from_mask(record["m"])), []).append(record["id"])
    pattern_rows = [
        {"missing": list(key), "count": len(ids), "ids": ids}
        for key, ids in sorted(patterns.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    ]
    examples = sorted((r for r in in_range if r["m"] != COMPLETE_MASK), key=lambda r: -r["t"])[:examples_limit]
    return {
        "total": total, "ok": ok, "bad": bad,
        "ratio": ok / total if total else 0.0,
        "t0": t0, "t1": t1, "seconds": seconds,
        "buckets": buckets,
        "patterns": pattern_rows,
        "examples": examples,
    }


# ---------------------------------------------------------------------------
# HTML 渲染：统计卡片、图、表全部在服务端算好，页面不依赖 JavaScript 也能完整显示。
# 打开 JavaScript 后由页面脚本按所选时间范围重建同样的结构。
# ---------------------------------------------------------------------------

CHART_W, CHART_H = 960, 240


def chart_svg(buckets: list[dict], seconds: int) -> str:
    esc = html.escape
    left, right, top, bottom = 46, 8, 8, 24
    plot_w, plot_h = CHART_W - left - right, CHART_H - top - bottom
    ceiling = nice_ceiling(max((b["ok"] + b["bad"] for b in buckets), default=0))
    n = max(len(buckets), 1)
    slot = plot_w / n
    bar_w = min(24.0, slot * 0.72)

    def y(value: float) -> float:
        return top + plot_h * (1 - value / ceiling)

    def top_rounded(x: float, y0: float, w: float, h: float) -> str:
        r = min(4.0, w / 2, h)
        return (f"M{x:.1f},{y0 + h:.1f} L{x:.1f},{y0 + r:.1f} Q{x:.1f},{y0:.1f} {x + r:.1f},{y0:.1f} "
                f"L{x + w - r:.1f},{y0:.1f} Q{x + w:.1f},{y0:.1f} {x + w:.1f},{y0 + r:.1f} "
                f"L{x + w:.1f},{y0 + h:.1f} Z")

    parts = [f'<svg viewBox="0 0 {CHART_W} {CHART_H}" role="img" aria-label="收齐与收不齐 round 数随时间变化">']
    for tick in range(5):
        value = ceiling * tick / 4
        gy = y(value)
        parts.append(f'<line class="grid" x1="{left}" y1="{gy:.1f}" x2="{CHART_W - right}" y2="{gy:.1f}"/>')
        parts.append(f'<text class="tick" x="{left - 6}" y="{gy + 4:.1f}" text-anchor="end">{compact(round(value))}</text>')
    parts.append(f'<line class="axis" x1="{left}" y1="{top + plot_h}" x2="{CHART_W - right}" y2="{top + plot_h}"/>')

    gap = 2.0
    for idx, bucket in enumerate(buckets):
        bx = left + slot * idx + (slot - bar_w) / 2
        ok_h = plot_h * bucket["ok"] / ceiling
        bad_h = plot_h * bucket["bad"] / ceiling
        base = top + plot_h
        if bucket["bad"]:
            # 收不齐（红）堆在最上面；圆角是数据端，只给最顶段。
            parts.append(f'<path class="bar-bad" d="{top_rounded(bx, y(bucket["ok"] + bucket["bad"]), bar_w, bad_h)}"/>')
        if bucket["ok"]:
            if bucket["bad"]:
                # 与上面的红段之间留 2px 表面缝，内段方角。段高不足缝宽时钳到 0，
                # 否则 <rect height> 为负会被浏览器整段丢弃并报错。
                parts.append(f'<rect class="bar-ok" x="{bx:.1f}" y="{base - ok_h + gap:.1f}" '
                             f'width="{bar_w:.1f}" height="{max(ok_h - gap, 0.0):.1f}"/>')
            else:
                parts.append(f'<path class="bar-ok" d="{top_rounded(bx, base - ok_h, bar_w, ok_h)}"/>')
        title = (f"{bucket_label(bucket['start'], seconds)}：收齐 {bucket['ok']}，收不齐 {bucket['bad']}，"
                 f"共 {bucket['ok'] + bucket['bad']}，收齐率 {pct(bucket['ok'] / (bucket['ok'] + bucket['bad'])) if bucket['ok'] + bucket['bad'] else '-'}")
        parts.append(
            f'<rect class="hit" x="{left + slot * idx:.1f}" y="{top}" width="{slot:.1f}" height="{plot_h}" '
            f'tabindex="0"><title>{esc(title)}</title></rect>'
        )

    shown = min(n, 8)
    for i in range(shown):
        idx = round(i * (n - 1) / (shown - 1)) if shown > 1 else 0
        if not 0 <= idx < n:
            continue
        x = left + slot * idx + slot / 2
        label = bucket_label(buckets[idx]["start"], seconds)
        parts.append(f'<text class="tick" x="{x:.1f}" y="{CHART_H - 6}" text-anchor="middle">{esc(label)}</text>')
    parts.append("</svg>")
    return "".join(parts)


def tiles_html(data: dict) -> str:
    esc = html.escape
    span_days = max((data["t1"] - data["t0"]) / 86400, 0)
    top_missing = "、".join(data["patterns"][0]["missing"]) if data["patterns"] else "-"
    top_missing_count = data["patterns"][0]["count"] if data["patterns"] else 0
    tiles = [
        ("round 总数", compact(data["total"]), f"范围 {span_days:.1f} 天"),
        ("收齐", compact(data["ok"]), pct(data["ratio"]) if data["total"] else "-"),
        ("收不齐", compact(data["bad"]), pct(1 - data["ratio"]) if data["total"] else "-"),
        ("收齐率", pct(data["ratio"]) if data["total"] else "-",
         f"收不齐中最常见缺失：{esc(top_missing)}（{compact(top_missing_count)}）"),
    ]
    parts = ['<div class="tiles" id="tiles">']
    for label, value, sub in tiles:
        parts.append(f'<div class="tile"><div class="label">{esc(label)}</div>'
                     f'<div class="value">{esc(value)}</div><div class="sub">{sub}</div></div>')
    parts.append("</div>")
    return "".join(parts)


def chart_section_html(data: dict) -> str:
    esc = html.escape
    out = [
        '<section id="chart-section"><h2>收齐 / 收不齐 随时间</h2>',
        '<p class="desc">每根柱 = 一个时间桶内的 round 数；灰色为收齐，红色为收不齐。'
        '时间桶粒度随所选范围自动选择（不超过两天的范围按小时，半年内按天，更久按周）。</p>',
        '<div class="legend"><span class="key ok"></span>收齐<span class="key bad"></span>收不齐</div>',
        f'<div class="chart" id="chart">{chart_svg(data["buckets"], data["seconds"])}</div>',
        bucket_table_html(data),
        "</section>",
    ]
    return "".join(out)


def bucket_table_html(data: dict) -> str:
    esc = html.escape
    rows = []
    for bucket in reversed(data["buckets"]):
        total = bucket["ok"] + bucket["bad"]
        ratio = pct(bucket["ok"] / total) if total else "-"
        rows.append(
            f'<tr><td>{esc(bucket_label(bucket["start"], data["seconds"]))}</td>'
            f'<td class="num">{bucket["ok"]:,}</td><td class="num">{bucket["bad"]:,}</td>'
            f'<td class="num">{total:,}</td><td class="num">{ratio}</td></tr>'
        )
    return (
        '<div id="bucket-table"><details><summary>按时间桶查看数据表</summary><div class="scroll">'
        '<table class="list"><thead><tr><th>时间桶</th><th>收齐</th><th>收不齐</th><th>合计</th>'
        f"<th>收齐率</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div></details></div>"
    )


def patterns_html(data: dict) -> str:
    esc = html.escape
    out = [
        '<section id="patterns"><h2>收不齐的缺失模式</h2>',
        '<p class="desc">按缺失的消息组合归类。数值是所选时间范围内的 round 数；'
        "示例展开可看具体的 round_id。</p>",
    ]
    if not data["patterns"]:
        return "".join(out) + '<div id="pattern-rows"><p class="empty">所选范围内没有收不齐的 round。</p></div></section>'
    out.append('<div id="pattern-rows"><div class="scroll"><table class="list"><thead><tr><th>缺失</th>'
               "<th>round 数</th><th>占全部</th><th>占收不齐</th><th>round 示例</th></tr></thead><tbody>")
    for row in data["patterns"]:
        share_total = row["count"] / data["total"] if data["total"] else 0
        share_bad = row["count"] / data["bad"] if data["bad"] else 0
        sample = "、".join(f'<code>{esc(rid)}</code>' for rid in row["ids"][:3])
        more = ""
        if len(row["ids"]) > 3:
            items = "".join(f"<li><code>{esc(rid)}</code></li>" for rid in row["ids"][:20])
            more = f'<details><summary>共 {len(row["ids"])} 个，展开前 20 个</summary><ul>{items}</ul></details>'
        out.append(
            f'<tr><td>{esc("、".join(row["missing"]))}</td><td class="num">{row["count"]:,}</td>'
            f'<td class="num">{pct(share_total)}</td><td class="num">{pct(share_bad)}</td>'
            f"<td>{sample}{more}</td></tr>"
        )
    out.append("</tbody></table></div></div></section>")
    return "".join(out)


def fmt_age(seconds: float) -> str:
    if seconds < 3600:
        return f"{seconds / 60:.0f} 分钟"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} 小时"
    return f"{seconds / 86400:.1f} 天"


def examples_html(data: dict, input_dir: Path, now: float) -> str:
    esc = html.escape
    out = [
        '<section id="examples"><h2>收不齐的 round 示例</h2>',
        '<p class="desc">所选时间范围内最晚开始的收不齐 round。等待时长从 round 首条消息到达起算。</p>',
    ]
    if not data["examples"]:
        return "".join(out) + '<div id="example-rows"><p class="empty">所选范围内没有收不齐的 round。</p></div></section>'
    out.append('<div id="example-rows"><div class="scroll"><table class="list"><thead><tr><th>round_id</th>'
               "<th>开始时间</th><th>等待</th><th>缺失</th><th>目录</th></tr></thead><tbody>")
    for record in data["examples"]:
        started = datetime.fromtimestamp(record["t"]).strftime("%Y-%m-%d %H:%M")
        missing = "、".join(missing_from_mask(record["m"]))
        out.append(
            f'<tr><td><code>{esc(record["id"])}</code></td><td>{esc(started)}</td>'
            f'<td class="num">{esc(fmt_age(max(now - record["t"], 0)))}</td>'
            f'<td>{esc(missing)}</td><td><code>{esc(rel(input_dir / record["id"]))}</code></td></tr>'
        )
    out.append("</tbody></table></div></div></section>")
    return "".join(out)


def controls_html() -> str:
    return (
        '<div class="controls js-only" id="controls">'
        '<button type="button" class="preset active" data-days="all">全部</button>'
        '<button type="button" class="preset" data-days="1">近 24 小时</button>'
        '<button type="button" class="preset" data-days="7">近 7 天</button>'
        '<button type="button" class="preset" data-days="30">近 30 天</button>'
        '<button type="button" class="preset" data-days="90">近 90 天</button>'
        '<span class="range">从 <input type="datetime-local" id="from"> 到 <input type="datetime-local" id="to"></span>'
        '<span class="range">粒度 <select id="bucket"><option value="auto" selected>自动</option>'
        '<option value="3600">小时</option><option value="86400">天</option><option value="604800">周</option></select></span>'
        '<span id="range-caption" class="meta"></span>'
        "</div>"
    )


def render(records: list[dict], input_dir: Path, out: Path, examples_limit: int) -> dict:
    esc = html.escape
    now = time.time()
    if records:
        t0, t1 = min(r["t"] for r in records), max(r["t"] for r in records)
    else:
        t0 = t1 = now
    data = build(records, t0, t1, examples_limit=examples_limit)
    parts = [
        '<header><div><h1>采集完整度</h1>',
        f'<div class="meta">生成于 <span id="generated">{esc(datetime.now().isoformat(timespec="seconds"))}</span>'
        f' · 语料 {esc(rel(input_dir))} · 收齐口径与分析和看门狗一致（六类输入齐全）</div></div>',
        '<div class="refresh js-only"><button type="button" id="refresh">刷新</button>'
        '<span id="refresh-status" role="status"></span></div>',
        '<noscript><div class="meta">筛选时间范围需开启 JavaScript；当前显示全时间范围。</div></noscript>',
        "</header>",
        controls_html(),
        tiles_html(data),
        chart_section_html(data),
        patterns_html(data),
        examples_html(data, input_dir, now),
    ]
    payload = {
        "now": round(now),
        "inputDir": rel(input_dir),
        "rounds": [[r["id"], round(r["t"]), r["m"]] for r in records],
    }
    template = (Path(__file__).parent / "completeness_template.html").read_text(encoding="utf-8")
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(f".{out.name}.tmp")
    page = template.replace("<!--__BODY__-->", "\n".join(parts))
    page = page.replace("/*__DATA__*/null", json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    tmp.write_text(page, encoding="utf-8")
    tmp.replace(out)
    return data


def generate(args) -> int:
    records = scan_rounds(args.input_dir)
    if not records:
        print(f"没有可统计的 round：{rel(args.input_dir)}", file=sys.stderr)
        return 1
    data = render(records, args.input_dir, args.out, args.examples)
    print(f"rounds={data['total']} ok={data['ok']} bad={data['bad']} "
          f"ratio={pct(data['ratio'])} -> {rel(args.out)}")
    return 0


def serve(args) -> int:
    """本地页面服务：GET / 返回最新 HTML，POST /refresh 在子进程里重新统计。"""

    child = [sys.executable, str(Path(__file__).resolve()), "--input-dir", str(args.input_dir),
             "--out", str(args.out), "--examples", str(args.examples)]
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
            if self.path.split("?", 1)[0] not in ("/", "/completeness.html") or not args.out.is_file():
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
            print(f"[completeness] {self.address_string()} {fmt % values}")

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
    parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "reports" / "completeness.html")
    parser.add_argument("--examples", type=int, default=50, help="示例表最多列出的 round 数（默认 50）")
    parser.add_argument("--serve", action="store_true", help="启动本地页面，支持页面内刷新")
    parser.add_argument("--host", default="127.0.0.1", help="--serve 监听地址（默认只对本机开放）")
    parser.add_argument("--port", type=int, default=8766, help="--serve 监听端口")
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)  # 扫描上万个 round，逐条日志只会刷屏
    return serve(args) if args.serve else generate(args)


if __name__ == "__main__":
    raise SystemExit(main())
