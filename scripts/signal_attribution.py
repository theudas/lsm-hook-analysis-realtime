#!/usr/bin/env python3
"""信号归因与对抗评测：四层判据的承重分析与逃逸面量化。

四个信号层（analyzer.detect_anomalies 的四类异常，互相独立计算）：
  L1_sensitive  访问危险文件（敏感越权）      路径+动作命中敏感分组
  L2_action     文件访问出现未授权动作        路径在 IR 集内、动作超出声明
  L3_network    网络访问出现未授权动作        收发动作超出 IR network_actions
  L4_registry   调用未注册工具                tool_name 不在平台注册表

is_anomaly = 任一层触发，且四层从同一批输入独立得出——因此一次回放拿到每轮
的触发层集合后，消融（关掉某层）与独立召回（只留某层）都可在层集合上后验
计算，与在代码里禁用该层完全等价。

对抗变体（改写内核 JSONL 后重放；GT 不变，测的是信号鲁棒性而非 GT）：
  A1 名字伪装（弱）：注册表外的 tool_name（攻击者控制的工具名）全部改为
     注册名 "read" → L4 失明；collector stdio 门控是否同时失明取决于该 round
     的 IR 是否允许 read（允许则 stdio 外发也被过滤）。
  A2 名字伪装（强）：改为 该 round IR 允许集 ∩ 注册表 中的工具名（无交集时
     退化为 "read"，计数记录）→ 同时骗过 L4 与 stdio 门控，L3 的 stdio 证据
     也被过滤。
  B 路径混淆：LSM 事件里命中敏感分组路径模式的 path / args.pathname /
     args.syscall_pathname 改写为 /tmp/.c_<hash>（同一原路径映射一致），
     模拟 fd 传递 / 挂载重映射一类"敏感路径在内核侧不可见"的敌手 → L1 失明。
     只改写 LSM 文件：syscall 序列的 path 字段不参与判定。

口径与 eval_metrics.py 一致：告警 = analyze_round().is_anomaly；
GT 取 gt_labels.json；FPR = FP/(FP+TN)；FNR = FN/(FN+TP)。

用法：
  /path/to/python scripts/signal_attribution.py            # 全量 240 round
  /path/to/python scripts/signal_attribution.py --limit 5  # 冒烟
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import shutil
import sys
import tempfile
import time
from pathlib import Path

# 回放时静默 analyzer 的逐轮日志，只保留评估结果。
logging.disable(logging.CRITICAL)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from lha_realtime.analyzer import analyze_round, load_ir_source, parse_allowlist  # noqa: E402
from lha_realtime.rules import SENSITIVE_RULES  # noqa: E402

# 工具注册表判据已于 2026-10-26 从 analyzer 移除；此处保留当时的 8 项名单用于
# 定义对抗变体的"攻击者可控名字"（语料良性 round 的运行时词表 + 平台内建工具），
# 使历史对比口径不变。
REGISTERED_TOOLS = frozenset({
    "exec", "read", "write", "apply_patch", "edit",
    "memory_get", "sessions_spawn", "safe_file_reader__read_text",
})

DEFAULT_GT = PROJECT_ROOT / "reports" / "eval_artifacts_20261013" / "gt_labels.json"
DEFAULT_BASELINE = PROJECT_ROOT / "reports" / "eval_artifacts_20261013" / "yaml_tuned_v1.json"
DEFAULT_INPUT = PROJECT_ROOT / "input"
OUT_DIR = PROJECT_ROOT / "reports" / "eval_artifacts_signal_attribution"

LSM_JSONL = "kernel_lsm_hook_result.jsonl"
SYS_JSONL = "kernel_syscall_seq.jsonl"

LAYER_BY_TYPE = {
    "访问危险文件（敏感越权）": "L1_sensitive",
    "文件访问出现未授权动作": "L2_action",
    "网络访问出现未授权动作": "L3_network",
    "调用未注册工具": "L4_registry",
}
LAYERS = ["L1_sensitive", "L2_action", "L3_network", "L4_registry"]

SPOOF_FALLBACK = "read"  # A1 固定伪装名 / A2 无交集时的退化名：均为注册名


# ---------------------------------------------------------------- 回放

def layers_of(result: dict) -> list:
    types = {item.get("type") for item in result.get("anomaly_types") or []}
    return sorted({LAYER_BY_TYPE[t] for t in types if t in LAYER_BY_TYPE})


def replay_round(round_dir: Path) -> dict:
    try:
        result = analyze_round(round_dir)
    except Exception as exc:  # 损坏 round 单独记录，不中断整体评估
        return {"error": repr(exc)}
    return {
        "verdict": result["is_anomaly"],
        "layers": layers_of(result),
        "types": [item["type"] for item in result.get("anomaly_types") or []],
        "collection_status": result.get("collection_status"),
    }


# ---------------------------------------------------------------- 对抗变体改写

def spoof_name(name, mode: str, allowed_tools: list) -> tuple[str, bool]:
    """把注册表外的工具名改成注册名。返回 (新名, 是否退化到 fallback)。"""
    if not name or name in REGISTERED_TOOLS:
        return name, False
    if mode == "A2":
        candidates = sorted(t for t in allowed_tools if t in REGISTERED_TOOLS)
        if candidates:
            return candidates[0], False
    return SPOOF_FALLBACK, True


def obfuscate_path(path: str) -> str:
    return "/tmp/.c_" + hashlib.sha1(path.encode("utf-8")).hexdigest()[:10]


def is_sensitive_path(path: str) -> bool:
    return any(rule.matches_path(path) for rule in SENSITIVE_RULES)


def transform_event(event: dict, mode: str, allowed_tools: list) -> dict:
    if mode in ("A1", "A2"):
        if "tool_name" in event:
            event["tool_name"], _ = spoof_name(event.get("tool_name"), mode, allowed_tools)
    elif mode == "B":
        for key in ("path",):
            value = event.get(key)
            if isinstance(value, str) and is_sensitive_path(value):
                event[key] = obfuscate_path(value)
        args = event.get("args")
        if isinstance(args, dict):
            for key in ("pathname", "syscall_pathname"):
                value = args.get(key)
                if isinstance(value, str) and is_sensitive_path(value):
                    args[key] = obfuscate_path(value)
    return event


def materialize_variant(src_dir: Path, dst_dir: Path, mode: str, allowed_tools: list) -> None:
    """把 round 目录复制到 dst，LSM JSONL 按 mode 改写后重写。"""
    dst_dir.mkdir(parents=True, exist_ok=True)
    for item in src_dir.iterdir():
        if item.name == LSM_JSONL:
            continue
        if item.is_file():
            shutil.copy2(item, dst_dir / item.name)
    lines = []
    for line in (src_dir / LSM_JSONL).read_text(encoding="utf-8").splitlines():
        if line.strip():
            lines.append(json.dumps(
                transform_event(json.loads(line), mode, allowed_tools), ensure_ascii=False
            ))
    (dst_dir / LSM_JSONL).write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------- 指标

def metrics(verdicts: dict, gt: dict) -> dict:
    tp = fp = tn = fn = 0
    for rid, rec in verdicts.items():
        label = gt[rid]["label"]
        alarm = rec["verdict"]
        if label == "attack":
            tp += alarm
            fn += not alarm
        else:
            fp += alarm
            tn += not alarm
    n = tp + fp + tn + fn
    return {
        "N": n, "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "Accuracy": round(100 * (tp + tn) / n, 2) if n else None,
        "Precision": round(100 * tp / (tp + fp), 2) if tp + fp else None,
        "Recall": round(100 * tp / (tp + fn), 2) if tp + fn else None,
        "FPR": round(100 * fp / (fp + tn), 2) if fp + tn else None,
        "FNR": round(100 * fn / (fn + tp), 2) if fn + tp else None,
    }


def verdict_with_layers(rec: dict, active: set) -> bool:
    return bool(set(rec.get("layers") or []) & active)


def ablation(scenario: dict, gt: dict) -> dict:
    """关掉某层 / 只留某层后的指标（后验过滤，与代码内禁用等价）。"""
    out = {"ALL": metrics(scenario, gt)}
    for layer in LAYERS:
        only = {r: {**rec, "verdict": verdict_with_layers(rec, {layer})} for r, rec in scenario.items()}
        without = {r: {**rec, "verdict": verdict_with_layers(rec, set(LAYERS) - {layer})} for r, rec in scenario.items()}
        out[f"only_{layer}"] = metrics(only, gt)
        out[f"without_{layer}"] = metrics(without, gt)
    return out


def layer_stats(scenario: dict, gt: dict) -> dict:
    attacks = [r for r in scenario if gt[r]["label"] == "attack"]
    fires = {layer: sum(1 for r in attacks if layer in (scenario[r].get("layers") or []))
             for layer in LAYERS}
    # 触发层集合在 TP 上的共现分布（哪几层同时承重）。
    combos: dict = {}
    for rid in attacks:
        if scenario[rid]["verdict"]:
            key = "+".join(scenario[rid].get("layers") or []) or "(none)"
            combos[key] = combos.get(key, 0) + 1
    # 每层的"独苗"TP：关掉它该 round 即漏报。
    sole = {layer: sorted(r for r in attacks
                          if scenario[r]["verdict"] and (scenario[r].get("layers") or []) == [layer])
            for layer in LAYERS}
    return {"fires_on_attacks": fires, "tp_combinations": combos, "sole_signal_rounds": sole}


def family_breakdown(scenario: dict, gt: dict) -> dict:
    """按攻击工具族分解每个场景的召回。family = GT hit[0]。"""
    families: dict = {}
    for rid, rec in scenario.items():
        info = gt[rid]
        if info["label"] != "attack":
            continue
        family = (info.get("hit") or ["(none)"])[0]
        entry = families.setdefault(family, {"total": 0, "detected": 0})
        entry["total"] += 1
        entry["detected"] += bool(rec["verdict"])
    return families


# ---------------------------------------------------------------- 主流程

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gt", type=Path, default=DEFAULT_GT)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--limit", type=int, default=0, help="只跑前 N 个 round（冒烟）")
    parser.add_argument("--out", type=Path, default=OUT_DIR)
    args = parser.parse_args()

    gt = json.loads(args.gt.read_text(encoding="utf-8"))
    eval_set = sorted(json.loads(args.baseline.read_text(encoding="utf-8"))["verdicts"])
    if args.limit:
        eval_set = eval_set[: args.limit]
    eval_set = [r for r in eval_set if r in gt and (args.input / r).is_dir()]
    print(f"评估集合 {len(eval_set)} round；注册工具 {len(REGISTERED_TOOLS)} 项；"
          f"敏感分组 {len(SENSITIVE_RULES)} 组", flush=True)

    started = time.time()

    # ---- 基线回放（当前代码）----
    baseline = {rid: replay_round(args.input / rid) for rid in eval_set}
    errors = [r for r, rec in baseline.items() if "error" in rec]
    if errors:
        print(f"警告：{len(errors)} 个 round 回放失败 {errors[:3]}", flush=True)
    base_ok = {r: rec for r, rec in baseline.items() if "error" not in rec}

    # ---- 对抗变体 ----
    scenarios: dict = {"baseline": base_ok}
    variant_notes: dict = {}
    for mode, title in (
        ("A1", "A1 名字伪装(弱)：注册表外工具名 → read"),
        ("A2", "A2 名字伪装(强)：注册表外工具名 → IR允许∩注册表"),
        ("B", "B 路径混淆：敏感路径 → /tmp/.c_<hash>"),
    ):
        t0 = time.time()
        verdicts: dict = {}
        fallbacks = []
        with tempfile.TemporaryDirectory(prefix=f"lha_attr_{mode}_") as tmp:
            tmp_root = Path(tmp)
            for rid in eval_set:
                src = args.input / rid
                rec = baseline[rid]
                if "error" in rec:
                    continue
                allowed = parse_allowlist(load_ir_source(src))["tools"]
                dst = tmp_root / rid
                materialize_variant(src, dst, mode, sorted(allowed))
                verdicts[rid] = replay_round(dst)
                if mode == "A2":
                    # 记录退化为 fallback 的 round（IR 允许集与注册表无交集）。
                    foreign = any(
                        (name := json.loads(line).get("tool_name"))
                        and name not in REGISTERED_TOOLS
                        for line in (src / LSM_JSONL).read_text(encoding="utf-8").splitlines()
                        if line.strip()
                    )
                    if foreign and not (set(allowed) & set(REGISTERED_TOOLS)):
                        fallbacks.append(rid)
                shutil.rmtree(dst, ignore_errors=True)
        scenarios[mode] = verdicts
        variant_notes[mode] = {"desc": title, "a2_fallback_rounds": fallbacks}
        print(f"{title}: 完成 {len(verdicts)} round，{time.time()-t0:.1f}s，"
              f"A2 退化 {len(fallbacks)}", flush=True)

    # ---- 汇总 ----
    summary: dict = {
        "config": {
            "code": "signal_attribution.py @ current HEAD",
            "eval_set": str(args.baseline),
            "layers": LAYERS,
            "variants": {
                "A1": "注册表外 tool_name → 'read'（L4 失明；stdio 门控视 IR 而定）",
                "A2": "注册表外 tool_name → IR允许∩注册表（L4+stdio 门控双失明；"
                      "无交集退化为 read）",
                "B": "LSM 敏感路径 → /tmp/.c_<hash>（L1 失明；syscall 文件不改，"
                     "其 path 不参与判定）",
            },
        },
        "variant_notes": variant_notes,
        "metrics": {name: metrics(scen, gt) for name, scen in scenarios.items()},
        "layer_stats": {name: layer_stats(scen, gt) for name, scen in scenarios.items()},
        "ablation": ablation(base_ok, gt),
        "families": {name: family_breakdown(scen, gt) for name, scen in scenarios.items()},
    }

    # 每 round 明细矩阵。
    matrix: dict = {}
    for rid in eval_set:
        entry = {"label": gt[rid]["label"], "hit": gt[rid].get("hit") or []}
        for name, scen in scenarios.items():
            if rid in scen:
                entry[name] = {k: scen[rid].get(k) for k in ("verdict", "layers", "collection_status")}
        matrix[rid] = entry

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")
    (args.out / "attribution_matrix.json").write_text(
        json.dumps(matrix, ensure_ascii=False, indent=1), encoding="utf-8")

    # 终端摘要。
    print("\n==== 指标（全量） ====")
    header = ["场景", "TP", "FP", "TN", "FN", "Acc%", "FPR%", "FNR%", "Recall%"]
    print(" | ".join(header))
    for name in ("baseline", "A1", "A2", "B"):
        m = summary["metrics"][name]
        print(" | ".join(str(x) for x in [name, m["TP"], m["FP"], m["TN"], m["FN"],
                                          m["Accuracy"], m["FPR"], m["FNR"], m["Recall"]]))
    print("\n==== 消融（基线层集合后验） ====")
    print("层 | 攻击round触发数 | solo召回% | 关掉后召回% | 关掉后FPR%")
    for layer in LAYERS:
        only = summary["ablation"][f"only_{layer}"]
        without = summary["ablation"][f"without_{layer}"]
        fires = summary["layer_stats"]["baseline"]["fires_on_attacks"][layer]
        print(f"{layer} | {fires} | {only['Recall']} | {without['Recall']} | {without['FPR']}")
    print("\n==== TP 层组合分布（基线） ====")
    for combo, count in sorted(summary["layer_stats"]["baseline"]["tp_combinations"].items(),
                               key=lambda kv: -kv[1]):
        print(f"{combo}: {count}")
    print(f"\n产物: {args.out}/summary.json, attribution_matrix.json")
    print(f"总耗时 {time.time()-started:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
