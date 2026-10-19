#!/usr/bin/env python3
"""误杀率/准确率回放评估：重放 GT 标注的 round，输出四指标与翻转明细。

只读 input/，不写 round 目录、不连后端、不碰 state/realtime.db。
产物写到 reports/，便于前后对比。

口径：
  - 评估集 = 上一次评估（yaml_tuned_v1.json）的 round 集合，保证逐轮可比；
  - 告警 = analyze_round().is_anomaly；GT 取 gt_labels.json 的 attack/benign；
  - 误杀率 FPR = FP / (FP + TN)；召回率 Recall = TP / (TP + FN)；
  - 精确率 Precision = TP / (TP + FP)；准确率 Accuracy = (TP + TN) / N。

用法：
  python3 scripts/eval_metrics.py                       # 对比 v4 基线
  python3 scripts/eval_metrics.py --tag collector_filter --baseline reports/eval_artifacts_20261013/yaml_tuned_v1.json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

# 回放时静默 analyzer 的逐轮日志，只保留评估结果。
logging.disable(logging.CRITICAL)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from lha_realtime.analyzer import analyze_round  # noqa: E402

DEFAULT_GT = PROJECT_ROOT / "reports" / "eval_artifacts_20261013" / "gt_labels.json"
DEFAULT_BASELINE = PROJECT_ROOT / "reports" / "eval_artifacts_20261013" / "yaml_tuned_v1.json"
DEFAULT_INPUT = PROJECT_ROOT / "input"


def replay(round_ids: list[str], input_dir: Path) -> dict:
    verdicts: dict = {}
    for round_id in round_ids:
        round_dir = input_dir / round_id
        try:
            result = analyze_round(round_dir)
        except Exception as exc:  # 损坏 round 单独记录，不中断整体评估
            verdicts[round_id] = {"error": repr(exc)}
            continue
        verdicts[round_id] = {
            "is_anomaly": result["is_anomaly"],
            "net_observed": sorted(result["network_observed"]),
            "net_endpoints": sorted(result["network_endpoints"]),
            "net_suppressed": result["network_suppressed"],
            "collector_filtered": result["counts"].get("lsm_collector_filtered", 0),
            "lsm_total": result["counts"]["lsm_total"],
            "collection_status": result.get("collection_status"),
            "types": [item["type"] for item in result["anomaly_types"]],
        }
    return verdicts


def evaluate(verdicts: dict, gt: dict) -> dict:
    tp = fp = tn = fn = 0
    errors = []
    for round_id, verdict in verdicts.items():
        label = gt.get(round_id, {}).get("label")
        if label not in ("attack", "benign"):
            continue
        if "error" in verdict:
            errors.append(round_id)
            continue
        alarm = verdict["is_anomaly"]
        if label == "attack":
            tp += alarm
            fn += not alarm
        else:
            fp += alarm
            tn += not alarm
    n = tp + fp + tn + fn
    return {
        "N": n,
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "replay_errors": errors,
        "Accuracy": round((tp + tn) / n * 100, 2) if n else None,
        "Precision": round(tp / (tp + fp) * 100, 2) if tp + fp else None,
        "Recall": round(tp / (tp + fn) * 100, 2) if tp + fn else None,
        "FPR": round(fp / (fp + tn) * 100, 2) if fp + tn else None,
        "FNR": round(fn / (tp + fn) * 100, 2) if tp + fn else None,
    }


def flips_against(verdicts: dict, baseline_verdicts: dict) -> list:
    out = []
    for round_id, new in verdicts.items():
        old = baseline_verdicts.get(round_id)
        if old is None or "error" in new:
            continue
        if bool(old.get("is_anomaly")) != bool(new["is_anomaly"]):
            out.append(
                {
                    "round": round_id,
                    "dir": f"{'是' if new['is_anomaly'] else '否'}←{'是' if old.get('is_anomaly') else '否'}",
                    "new": new["is_anomaly"],
                }
            )
    return sorted(out, key=lambda f: f["round"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", default="eval", help="产物目录名后缀")
    parser.add_argument("--gt", type=Path, default=DEFAULT_GT)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE,
                        help="对比基线的 verdicts JSON（含 verdicts 键或直接是 verdicts 映射）")
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT)
    args = parser.parse_args()

    gt = json.loads(args.gt.read_text(encoding="utf-8"))
    baseline_doc = json.loads(args.baseline.read_text(encoding="utf-8"))
    baseline_verdicts = baseline_doc.get("verdicts", baseline_doc)
    # 评估集沿用基线的 round 集合，逐轮可比。
    round_ids = sorted(baseline_verdicts)

    started = time.monotonic()
    verdicts = replay(round_ids, args.input_dir)
    metrics = evaluate(verdicts, gt)
    flips = flips_against(verdicts, baseline_verdicts)

    out_dir = PROJECT_ROOT / "reports" / f"eval_artifacts_{args.tag}"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "verdicts.json").write_text(
        json.dumps(verdicts, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    doc = {
        "config": (
            "v6: decision_scope stdio filter + IR tool-authorization gate + platform "
            f"tool registry + collection completeness check (vs {args.baseline.name})"
        ),
        "N": metrics["N"],
        **metrics,
        "flips_vs_baseline": flips,
        "baseline": str(args.baseline),
        "replay_seconds": round(time.monotonic() - started, 2),
    }
    (out_dir / "metrics.json").write_text(
        json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8"
    )

    print(json.dumps(doc, ensure_ascii=False, indent=1))
    print(f"\n产物: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
