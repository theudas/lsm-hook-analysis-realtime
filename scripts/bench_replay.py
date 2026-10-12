#!/usr/bin/env python3
"""全量语料回放基准：一次跑完同时产出 P-1-1、P-1-2 与语料统计。

采集三组数据：

  P-1-1  单 round 端到端分析耗时分布（p50/p90/p95/p99/max/mean）
  P-1-2  全量语料回放总耗时
  语料   可分析 / 跳过 / 损坏的分类计数，异常判定、事件量、敏感命中分布

只读 input/，不写任何产物、不连后端、不碰 state/realtime.db。

用法：
  python3 scripts/bench_replay.py
  python3 scripts/bench_replay.py --input-dir ./input --json reports/bench_replay.json
"""

from __future__ import annotations

import argparse
import collections
import json
import logging
import statistics
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from lha_realtime.analyzer import analyze_round  # noqa: E402


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return float("nan")
    s = sorted(values)
    k = (len(s) - 1) * pct
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def has_ir(round_dir: Path) -> bool:
    """IR 可来自独立的 ir.json，或旧上游内嵌在 round_end.ir_json。"""
    ir = round_dir / "ir.json"
    if ir.is_file():
        try:
            if json.loads(ir.read_text(encoding="utf-8")).get("ir_json"):
                return True
        except json.JSONDecodeError:
            pass
    end = round_dir / "round_end.json"
    if end.is_file():
        try:
            return bool(json.loads(end.read_text(encoding="utf-8")).get("ir_json"))
        except json.JSONDecodeError:
            return False
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="全量语料回放基准（P-1-1 / P-1-2 / 语料统计）")
    parser.add_argument("--input-dir", default=str(PROJECT_ROOT / "input"))
    parser.add_argument("--json", default="", help="把结构化结果另存为 JSON")
    parser.add_argument("--limit", type=int, default=0, help="只跑前 N 个可分析 round（调试用）")
    args = parser.parse_args()

    # 回放期间关掉 analyzer 日志，否则 I/O 会污染耗时测量。
    logging.disable(logging.CRITICAL)

    input_dir = Path(args.input_dir).resolve()
    if not input_dir.is_dir():
        print(f"[FATAL] 输入目录不存在：{input_dir}")
        return 1

    all_dirs = sorted(d for d in input_dir.iterdir() if d.is_dir())
    analyzable, skipped_no_kernel, skipped_no_ir = [], [], []
    for d in all_dirs:
        lsm = d / "kernel_lsm_hook_result.jsonl"
        sysc = d / "kernel_syscall_seq.jsonl"
        if not (lsm.is_file() and sysc.is_file()):
            skipped_no_kernel.append(d.name)
        elif not has_ir(d):
            skipped_no_ir.append(d.name)
        else:
            analyzable.append(d)
    if args.limit:
        analyzable = analyzable[: args.limit]

    print(f"语料目录         : {input_dir}")
    print(f"round 目录总数   : {len(all_dirs)}")
    print(f"  可分析         : {len(analyzable)}")
    print(f"  跳过-缺内核数据: {len(skipped_no_kernel)}")
    print(f"  跳过-缺 IR     : {len(skipped_no_ir)}")
    print("回放中 ...", flush=True)

    durations_ms: list[float] = []
    corrupt: list[tuple[str, str]] = []
    anomaly_rounds = 0
    anomaly_type_counter: collections.Counter[str] = collections.Counter()
    totals = collections.Counter()
    sensitive_paths: collections.Counter[str] = collections.Counter()
    sensitive_groups: collections.Counter[str] = collections.Counter()
    sensitive_rounds: set[str] = set()

    t0 = time.monotonic()
    for round_dir in analyzable:
        t_round = time.monotonic()
        try:
            result = analyze_round(round_dir)
        except Exception as exc:  # 损坏输入：计入容错统计，不中断回放
            corrupt.append((round_dir.name, f"{type(exc).__name__}: {exc}"))
            continue
        durations_ms.append((time.monotonic() - t_round) * 1000.0)

        counts = result["counts"]
        totals["lsm"] += counts["lsm_total"]
        totals["syscall"] += counts["syscall_total"]
        totals["file_ops"] += counts["kernel_file_ops"]
        totals["violations"] += counts["violations"]
        totals["judge_mismatch"] += counts["judge_mismatch"]
        if result["is_anomaly"]:
            anomaly_rounds += 1
            for t in result["anomaly_types"]:
                # anomaly_types 是 [{"type": 名称, "items": [...]}, ...]
                anomaly_type_counter[t.get("type", "<unknown>")] += 1
        for v in result["violations"]:
            if v.get("category") == "sensitive":
                totals["sensitive_hits"] += 1
                sensitive_paths[v.get("path") or "<none>"] += 1
                sensitive_groups[v.get("sensitive_rule") or "<none>"] += 1
                sensitive_rounds.add(result["round_id"])
    wall = time.monotonic() - t0

    ok = len(durations_ms)
    print()
    print("==================== P-1-2 全量回放 ====================")
    print(f"实际完成分析     : {ok} round")
    print(f"解析失败（损坏） : {len(corrupt)} round")
    for name, err in corrupt:
        print(f"    {name}: {err}")
    print(f"全量回放总耗时   : {wall:.2f}s")
    if ok:
        print(f"平均每 round     : {wall / ok * 1000:.1f}ms")

    print()
    print("==================== P-1-1 单 round 耗时 ====================")
    if durations_ms:
        print(f"p50={percentile(durations_ms,0.50):.1f}ms  p90={percentile(durations_ms,0.90):.1f}ms  "
              f"p95={percentile(durations_ms,0.95):.1f}ms  p99={percentile(durations_ms,0.99):.1f}ms")
        print(f"max={max(durations_ms):.1f}ms  min={min(durations_ms):.1f}ms  "
              f"mean={statistics.fmean(durations_ms):.1f}ms")

    print()
    print("==================== 语料统计 ====================")
    print(f"判为异常         : {anomaly_rounds} / {ok}"
          + (f"  ({anomaly_rounds / ok * 100:.0f}%)" if ok else ""))
    for t, n in anomaly_type_counter.most_common():
        print(f"    {t}: {n}")
    print(f"LSM 事件总数     : {totals['lsm']}")
    print(f"syscall 总数     : {totals['syscall']}")
    print(f"内核文件操作数   : {totals['file_ops']}")
    print(f"越权记录数       : {totals['violations']}")
    print(f"判据分歧数       : {totals['judge_mismatch']}")
    print(f"敏感命中         : {len(sensitive_paths)} 种路径 / {totals['sensitive_hits']} 次 / "
          f"分布在 {len(sensitive_rounds)} 个 round")
    for g, n in sensitive_groups.most_common():
        print(f"    {g}: {n} 次")
    print("==================================================")

    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({
            "input_dir": str(input_dir),
            "round_dirs_total": len(all_dirs),
            "analyzable": len(analyzable),
            "skipped_no_kernel": len(skipped_no_kernel),
            "skipped_no_ir": len(skipped_no_ir),
            "corrupt": corrupt,
            "analyzed_ok": ok,
            "replay_wall_seconds": wall,
            "per_round_ms": {
                "p50": percentile(durations_ms, 0.50),
                "p90": percentile(durations_ms, 0.90),
                "p95": percentile(durations_ms, 0.95),
                "p99": percentile(durations_ms, 0.99),
                "max": max(durations_ms) if durations_ms else None,
                "min": min(durations_ms) if durations_ms else None,
                "mean": statistics.fmean(durations_ms) if durations_ms else None,
            },
            "anomaly_rounds": anomaly_rounds,
            "anomaly_types": dict(anomaly_type_counter),
            "totals": dict(totals),
            "sensitive_path_kinds": len(sensitive_paths),
            "sensitive_rounds": len(sensitive_rounds),
            "sensitive_groups": dict(sensitive_groups),
            "sensitive_top_paths": sensitive_paths.most_common(30),
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"结构化结果已写入 : {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
