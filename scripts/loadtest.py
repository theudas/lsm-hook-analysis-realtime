#!/usr/bin/env python3
"""
Pipeline load test (Level B) for the realtime LSM analysis service.

It exercises the REAL ingest + analysis workers without Socket.IO and without
the report backend:

  - reporting is forced OFF (push_reports=False); the kernel report endpoint is
    never contacted.
  - a throwaway SQLite DB and a throwaway input dir are used, so state/realtime.db
    and input/ are never touched.

Synthetic rounds are cloned from the real rounds in ./input (any round that has
round_end.json + kernel_lsm_hook_result.jsonl + kernel_syscall_seq.jsonl). Each
synthetic round is fed as three inbox messages (round_start + round_end +
round_kernel) at a controlled rate, exactly like the receiver would. The IR
gating flag is satisfied from the ir_json embedded in the cloned round_end.

Metrics reported:
  - target vs achieved enqueue rate (rounds/s)
  - sustainable throughput (rounds drained / wall clock)
  - end-to-end latency distribution: first message enqueued -> analysis job done
    (measured with a monotonic clock, independent of the DB's 1s timestamps)
  - backlog curve: max pending messages / max queued jobs, and whether it grew
    unbounded (i.e. the offered rate exceeded capacity)

Usage examples:
  python3 scripts/loadtest.py --rate 20 --rounds 400 --workers 1
  python3 scripts/loadtest.py --rate 100 --rounds 2000 --workers 4 --quiet
  for r in 5 10 20 50 100; do python3 scripts/loadtest.py --rate $r --rounds 1000 --workers 4 --quiet; done
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import statistics
import tempfile
import threading
import time
from dataclasses import replace
from pathlib import Path

# Import the package from the project root regardless of CWD.
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from lha_realtime.config import SETTINGS  # noqa: E402
from lha_realtime.pipeline import RealtimePipeline  # noqa: E402
from lha_realtime.state import StateStore  # noqa: E402


def find_templates(input_dir: Path, limit: int | None = None) -> list[dict]:
    """Collect real, complete rounds to clone payloads from."""
    templates = []
    for d in sorted(input_dir.iterdir()):
        if not d.is_dir():
            continue
        end = d / "round_end.json"
        lsm = d / "kernel_lsm_hook_result.jsonl"
        sysc = d / "kernel_syscall_seq.jsonl"
        if not (end.is_file() and lsm.is_file() and sysc.is_file()):
            continue
        try:
            end_payload = json.loads(end.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        kernel_path = d / "round_kernel.json"
        kernel_payload = {}
        if kernel_path.is_file():
            try:
                kernel_payload = json.loads(kernel_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                kernel_payload = {}
        templates.append(
            {
                "name": d.name,
                "end_payload": end_payload,
                "kernel_payload": kernel_payload,
                # Point the kernel file refs at the already-materialized jsonl in
                # this template dir so copy_kernel_file actually copies bytes.
                "syscall_src": str(sysc.resolve()),
                "lsm_src": str(lsm.resolve()),
            }
        )
        if limit and len(templates) >= limit:
            break
    return templates


def make_messages(template: dict, round_id: str) -> tuple[dict, dict, dict]:
    start = {
        "push_type": "round_start",
        "round_id": round_id,
        "time_start": template["end_payload"].get("time_start"),
        "session_key": template["end_payload"].get("session_key"),
        "is_mock": True,
    }

    end = dict(template["end_payload"])
    end["push_type"] = "round_end"
    end["round_id"] = round_id
    end["is_mock"] = True  # belt-and-suspenders; reporting is already off

    kernel = dict(template["kernel_payload"])
    kernel["push_type"] = "round_kernel"
    kernel["round_id"] = round_id
    kernel["is_mock"] = True
    kernel["kernel_syscall_seq"] = template["syscall_src"]
    kernel["kernel_lsm_hook_result"] = template["lsm_src"]
    return start, end, kernel


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return float("nan")
    s = sorted(values)
    k = (len(s) - 1) * pct
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


class BacklogSampler(threading.Thread):
    def __init__(self, store: StateStore, interval: float):
        super().__init__(daemon=True)
        self.store = store
        self.interval = interval
        self._stop = threading.Event()
        self.samples: list[tuple[float, int, int]] = []  # (t, pending, queued)

    def run(self) -> None:
        t0 = time.monotonic()
        while not self._stop.is_set():
            c = self.store.counts()
            self.samples.append((time.monotonic() - t0, c["pending_messages"], c["queued_jobs"]))
            self._stop.wait(self.interval)

    def stop(self) -> None:
        self._stop.set()


class DoneWatcher(threading.Thread):
    """Poll analysis_jobs for completed jobs and stamp a monotonic finish time."""

    def __init__(self, store: StateStore, interval: float):
        super().__init__(daemon=True)
        self.store = store
        self.interval = interval
        self._stop = threading.Event()
        self.done_at: dict[str, float] = {}  # round_id -> monotonic finish time

    def run(self) -> None:
        while not self._stop.is_set():
            with self.store._lock:
                rows = self.store._conn.execute(
                    "SELECT round_id FROM analysis_jobs WHERE status = 'done'"
                ).fetchall()
            now = time.monotonic()
            for row in rows:
                rid = row["round_id"]
                if rid not in self.done_at:
                    self.done_at[rid] = now
            self._stop.wait(self.interval)

    def stop(self) -> None:
        self._stop.set()


def run_load_test(args: argparse.Namespace) -> int:
    if args.quiet:
        logging.disable(logging.CRITICAL)

    src_input = Path(args.input_dir).resolve()
    templates = find_templates(src_input, limit=args.template_limit)
    if not templates:
        print(f"[FATAL] no complete template rounds found under {src_input}")
        return 1
    print(f"templates: {len(templates)} complete round(s) from {src_input}")

    workdir = Path(tempfile.mkdtemp(prefix="lha_loadtest_"))
    tmp_input = workdir / "input"
    tmp_state = workdir / "state"
    tmp_input.mkdir(parents=True)
    tmp_state.mkdir(parents=True)

    settings = replace(
        SETTINGS,
        input_dir=tmp_input,
        state_dir=tmp_state,
        db_path=tmp_state / "loadtest.db",
        analyzer_workers=args.workers,
        ingest_poll_interval=args.ingest_poll,
        analysis_poll_interval=args.analysis_poll,
        push_mock_reports=False,
    )

    store = StateStore(settings=settings)
    pipeline = RealtimePipeline(store=store, settings=settings, push_reports=False)

    backlog = BacklogSampler(store, args.sample_interval)
    watcher = DoneWatcher(store, args.watch_interval)

    send_at: dict[str, float] = {}  # round_id -> monotonic time first msg enqueued

    print(
        f"config: rate={args.rate}/s rounds={args.rounds} workers={args.workers} "
        f"ingest_poll={args.ingest_poll}s analysis_poll={args.analysis_poll}s "
        f"reporting=OFF"
    )

    pipeline.start()
    backlog.start()
    watcher.start()

    interval = 1.0 / args.rate if args.rate > 0 else 0.0
    t_start = time.monotonic()
    for i in range(args.rounds):
        tmpl = templates[i % len(templates)]
        round_id = f"lt-{i:08d}"
        start_msg, end_msg, kernel_msg = make_messages(tmpl, round_id)
        now = time.monotonic()
        send_at[round_id] = now
        store.enqueue_message(start_msg)
        store.enqueue_message(end_msg)
        store.enqueue_message(kernel_msg)
        if interval:
            target = t_start + (i + 1) * interval
            slack = target - time.monotonic()
            if slack > 0:
                time.sleep(slack)
    t_send_done = time.monotonic()
    achieved_rate = args.rounds / (t_send_done - t_start) if t_send_done > t_start else float("inf")
    print(f"enqueue done: {args.rounds} rounds in {t_send_done - t_start:.2f}s "
          f"(achieved {achieved_rate:.1f}/s, target {args.rate}/s)")

    # Drain: wait until all jobs are done or timeout.
    deadline = time.monotonic() + args.drain_timeout
    while time.monotonic() < deadline:
        if len(watcher.done_at) >= args.rounds:
            break
        time.sleep(0.05)
    t_drain_done = time.monotonic()

    pipeline.stop()
    backlog.stop()
    watcher.stop()
    time.sleep(0.2)

    completed = len(watcher.done_at)
    latencies = [
        (watcher.done_at[rid] - send_at[rid]) * 1000.0
        for rid in watcher.done_at
        if rid in send_at
    ]
    max_pending = max((p for _, p, _ in backlog.samples), default=0)
    max_queued = max((q for _, _, q in backlog.samples), default=0)
    # Backlog trend: compare queued in first third vs last third of send window.
    final_pending, final_queued = (backlog.samples[-1][1], backlog.samples[-1][2]) if backlog.samples else (0, 0)

    drain_wall = t_drain_done - t_start
    sustained = completed / drain_wall if drain_wall > 0 else float("nan")

    print("\n==================== RESULT ====================")
    print(f"rounds offered      : {args.rounds}")
    print(f"rounds completed    : {completed}"
          + ("" if completed == args.rounds else f"  (DRAIN INCOMPLETE — capacity exceeded or timeout)"))
    print(f"target enqueue rate : {args.rate:.1f} rounds/s")
    print(f"achieved enqueue    : {achieved_rate:.1f} rounds/s")
    print(f"sustained throughput: {sustained:.1f} rounds/s  (completed / total wall {drain_wall:.2f}s)")
    print(f"backlog peak        : pending_msgs={max_pending}  queued_jobs={max_queued}")
    print(f"backlog at end      : pending_msgs={final_pending}  queued_jobs={final_queued}")
    if latencies:
        print("end-to-end latency (first msg enqueued -> job done), ms:")
        print(f"   p50={percentile(latencies,0.50):.0f}  p90={percentile(latencies,0.90):.0f}  "
              f"p95={percentile(latencies,0.95):.0f}  p99={percentile(latencies,0.99):.0f}  "
              f"max={max(latencies):.0f}  mean={statistics.fmean(latencies):.0f}")
    # Backlog should stay small relative to the offered rate. A backlog larger
    # than ~1s of offered load means a stage (ingest or analysis) can't keep up.
    backlog_budget = max(10, args.rate)
    healthy_backlog = max_pending <= backlog_budget and max_queued <= backlog_budget
    if completed == args.rounds and healthy_backlog:
        verdict = "SUSTAINABLE at this rate"
    elif completed == args.rounds:
        bottleneck = "ingest (pending msgs)" if max_pending > max_queued else "analysis (queued jobs)"
        verdict = f"OVER CAPACITY — backlog built up, bottleneck = {bottleneck} (drained only because load stopped)"
    else:
        verdict = "OVER CAPACITY — drain did not complete within timeout"
    print(f"verdict             : {verdict}")
    print("===============================================")

    store.close()
    if not args.keep:
        shutil.rmtree(workdir, ignore_errors=True)
    else:
        print(f"workdir kept: {workdir}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Level-B pipeline load test (no reporting).")
    p.add_argument("--rate", type=float, default=20.0, help="target rounds/sec to enqueue (0 = as fast as possible)")
    p.add_argument("--rounds", type=int, default=400, help="total synthetic rounds")
    p.add_argument("--workers", type=int, default=1, help="LHA_ANALYZER_WORKERS equivalent")
    p.add_argument("--input-dir", default=str(PROJECT_ROOT / "input"), help="source dir of real rounds to clone")
    p.add_argument("--template-limit", type=int, default=None, help="cap number of templates used")
    p.add_argument("--ingest-poll", type=float, default=SETTINGS.ingest_poll_interval, help="ingest poll interval (s)")
    p.add_argument("--analysis-poll", type=float, default=SETTINGS.analysis_poll_interval, help="analysis poll interval (s)")
    p.add_argument("--sample-interval", type=float, default=0.25, help="backlog sampling interval (s)")
    p.add_argument("--watch-interval", type=float, default=0.02, help="done-watcher poll interval (s)")
    p.add_argument("--drain-timeout", type=float, default=120.0, help="max seconds to wait for drain")
    p.add_argument("--quiet", action="store_true", help="silence pipeline logging to measure the ceiling")
    p.add_argument("--keep", action="store_true", help="keep the temp workdir for inspection")
    return p


if __name__ == "__main__":
    raise SystemExit(run_load_test(build_parser().parse_args()))
