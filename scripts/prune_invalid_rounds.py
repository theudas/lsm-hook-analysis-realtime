#!/usr/bin/env python3
"""把 input/ 下无法完整分析的 round 移到归档目录，使 input/ 只剩有效语料。

分三类移走：
  缺内核 JSONL   没有 kernel_lsm_hook_result.jsonl 或 kernel_syscall_seq.jsonl
  缺 IR          ir.json 与 round_end.ir_json 都没有可用的 IR
  损坏           输入齐全但 analyze_round() 抛异常（多为 JSON 解析失败）

默认只演练不动文件。确认清单无误后加 --apply 执行。移动而非删除：归档目录仍可
用 bench_replay.py --input-dir 回放，容错类用例的证据不会因清理而消失。

用法：
  python3 scripts/prune_invalid_rounds.py                  # 演练，只打印清单
  python3 scripts/prune_invalid_rounds.py --apply          # 移到 ../input_invalid
  python3 scripts/prune_invalid_rounds.py --apply --dest /data/invalid_rounds
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from lha_realtime.analyzer import analyze_round  # noqa: E402


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


def dir_size(path: Path) -> int:
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file())


def classify(input_dir: Path) -> dict[str, list[tuple[str, str]]]:
    """返回 {类别: [(round_id, 备注), ...]}。"""
    buckets: dict[str, list[tuple[str, str]]] = {
        "valid": [], "no_kernel": [], "no_ir": [], "corrupt": [],
    }
    for d in sorted(input_dir.iterdir()):
        if not d.is_dir():
            continue
        lsm = d / "kernel_lsm_hook_result.jsonl"
        sysc = d / "kernel_syscall_seq.jsonl"
        if not (lsm.is_file() and sysc.is_file()):
            missing = [f.name for f in (lsm, sysc) if not f.is_file()]
            buckets["no_kernel"].append((d.name, "缺 " + "、".join(missing)))
        elif not has_ir(d):
            buckets["no_ir"].append((d.name, "ir.json 与 round_end.ir_json 均无可用 IR"))
        else:
            try:
                analyze_round(d)
            except Exception as exc:
                buckets["corrupt"].append((d.name, f"{type(exc).__name__}: {exc}"))
            else:
                buckets["valid"].append((d.name, ""))
    return buckets


def main() -> int:
    parser = argparse.ArgumentParser(description="归档 input/ 下无法完整分析的 round")
    parser.add_argument("--input-dir", default=str(PROJECT_ROOT / "input"))
    parser.add_argument("--dest", default="", help="归档目录，默认为 input 的同级 input_invalid")
    parser.add_argument("--apply", action="store_true", help="真的移动；不加则只演练")
    parser.add_argument("--list-all", action="store_true", help="逐个列出被移走的 round_id")
    args = parser.parse_args()

    logging.disable(logging.CRITICAL)

    input_dir = Path(args.input_dir).resolve()
    if not input_dir.is_dir():
        print(f"[FATAL] 输入目录不存在：{input_dir}")
        return 1
    dest = Path(args.dest).resolve() if args.dest else input_dir.parent / "input_invalid"

    # 归档目录不能落在 input/ 里面，否则会把移走的东西又算成 round。
    if dest == input_dir or input_dir in dest.parents:
        print(f"[FATAL] 归档目录不能位于 input/ 之内：{dest}")
        return 1

    print(f"语料目录 : {input_dir}")
    print(f"归档目录 : {dest}")
    print(f"模式     : {'执行移动' if args.apply else '演练（不动文件）'}")
    print("分类中 ...", flush=True)

    buckets = classify(input_dir)
    labels = {"valid": "有效（保留）", "no_kernel": "缺内核 JSONL",
              "no_ir": "缺 IR", "corrupt": "输入损坏"}
    to_move = [(cat, rid, note) for cat in ("no_kernel", "no_ir", "corrupt")
               for rid, note in buckets[cat]]

    print()
    print(f"{'类别':>14s} {'目录数':>7s} {'占用':>10s}")
    for cat in ("valid", "no_kernel", "no_ir", "corrupt"):
        items = buckets[cat]
        size = sum(dir_size(input_dir / rid) for rid, _ in items)
        print(f"{labels[cat]:>14s} {len(items):>7d} {size / 1048576:>9.1f}M")
    print(f"{'合计':>14s} {sum(len(v) for v in buckets.values()):>7d}")
    print()
    print(f"将移走 {len(to_move)} 个，保留 {len(buckets['valid'])} 个。")

    # 损坏的数量少且值得逐条看，其余按需展开。
    if buckets["corrupt"]:
        print("\n输入损坏（逐条）：")
        for rid, note in buckets["corrupt"]:
            print(f"  {rid}: {note}")
    if args.list_all:
        for cat in ("no_kernel", "no_ir"):
            if buckets[cat]:
                print(f"\n{labels[cat]}（{len(buckets[cat])} 个）：")
                for rid, note in buckets[cat]:
                    print(f"  {rid}: {note}")

    if not args.apply:
        print("\n演练结束，未改动任何文件。确认无误后加 --apply 执行。")
        return 0

    conflicts = [rid for _, rid, _ in to_move if (dest / rid).exists()]
    if conflicts:
        print(f"\n[FATAL] 归档目录下已存在同名 round，未做任何改动：{conflicts[:5]}"
              + (f" 等 {len(conflicts)} 个" if len(conflicts) > 5 else ""))
        return 1

    dest.mkdir(parents=True, exist_ok=True)
    moved = []
    for cat, rid, note in to_move:
        shutil.move(str(input_dir / rid), str(dest / rid))
        moved.append({"round_id": rid, "category": cat, "note": note})

    manifest = dest / f"manifest_{time.strftime('%Y%m%d_%H%M%S')}.json"
    manifest.write_text(json.dumps({
        "moved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source": str(input_dir),
        "dest": str(dest),
        "moved_count": len(moved),
        "kept_count": len(buckets["valid"]),
        "moved": moved,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"\n已移走 {len(moved)} 个 round 到 {dest}")
    print(f"input/ 现存 {len(buckets['valid'])} 个 round，全部可完整分析。")
    print(f"清单已写入 {manifest}")
    print("\n回放归档语料（容错类用例取证用）：")
    print(f"  python3 scripts/bench_replay.py --input-dir {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
