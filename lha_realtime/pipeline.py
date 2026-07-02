#!/usr/bin/env python3
"""Realtime ingest and analysis workers."""

from __future__ import annotations

import json
import shutil
import threading
import time
from pathlib import Path
from typing import Any

from . import analyzer
from .config import SETTINGS, Settings, ensure_runtime_dirs
from .logging_utils import setup_logging
from .state import ROUND_TERMINAL_STATUSES, StateStore, json_size, now_iso


INPUT_FILES = {
    "round_end.json",
    "round_kernel.json",
    "ir.json",
    "kernel_syscall_seq.jsonl",
    "kernel_lsm_hook_result.jsonl",
    "analysis_violations.jsonl",
    "analysis_report.md",
    analyzer.PUSH_MARKER_NAME,
}

log = setup_logging("lha_realtime_pipeline", "pipeline.log")


def safe_len(value: Any) -> int:
    if value is None:
        return 0
    return len(str(value))


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def is_within_input_dir(path: Path, settings: Settings = SETTINGS) -> bool:
    try:
        path.resolve().relative_to(settings.input_dir.resolve())
    except ValueError:
        return False
    return True


def has_round_artifacts(round_dir: Path) -> bool:
    return any((round_dir / name).exists() for name in INPUT_FILES)


def clear_round_dir(round_dir: Path, settings: Settings = SETTINGS) -> None:
    if not is_within_input_dir(round_dir, settings):
        raise RuntimeError(f"refusing to clear path outside input dir: {round_dir}")
    round_dir.mkdir(parents=True, exist_ok=True)
    for child in list(round_dir.iterdir()):
        if child.name.startswith("."):
            child.unlink(missing_ok=True)
            continue
        if child.name in INPUT_FILES or child.name.startswith("analysis_"):
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink(missing_ok=True)


def copy_kernel_file(round_id: str, src_path: str | None, dst: Path) -> Path | None:
    if not src_path:
        log.warning("[%s] 内核文件路径为空，跳过 dst=%s", round_id, dst)
        return None
    src = Path(src_path)
    if not src.is_file():
        log.warning("[%s] 内核文件不存在或不可访问，跳过 src=%s", round_id, src)
        return None
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_name(f".{dst.name}.tmp")
    shutil.copy2(src, tmp)
    tmp.replace(dst)
    log.info("[%s] 内核文件拷贝完成 src=%s dst=%s size=%d bytes", round_id, src, dst, dst.stat().st_size)
    return dst


class RealtimePipeline:
    def __init__(self, store: StateStore | None = None, settings: Settings = SETTINGS, push_reports: bool = True):
        ensure_runtime_dirs(settings)
        self.settings = settings
        self.store = store or StateStore(settings=settings)
        self.push_reports = push_reports
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    def stop(self) -> None:
        self._stop.set()

    def start(self) -> None:
        self._threads.append(threading.Thread(target=self.ingest_loop, name="lha-ingest", daemon=True))
        for index in range(max(1, self.settings.analyzer_workers)):
            self._threads.append(
                threading.Thread(target=self.analysis_loop, name=f"lha-analyze-{index + 1}", daemon=True)
            )
        for thread in self._threads:
            thread.start()

    def join(self) -> None:
        for thread in self._threads:
            thread.join()

    def ingest_loop(self) -> None:
        log.info("ingest worker started")
        while not self._stop.is_set():
            processed = self.ingest_once()
            if processed == 0:
                time.sleep(self.settings.ingest_poll_interval)

    def analysis_loop(self) -> None:
        log.info("analysis worker started")
        while not self._stop.is_set():
            processed = self.analyze_once()
            if not processed:
                time.sleep(self.settings.analysis_poll_interval)

    def ingest_once(self, limit: int = 10) -> int:
        messages = self.store.fetch_pending_messages(limit=limit)
        for message in messages:
            try:
                generation = self.process_message(message)
            except Exception as exc:  # noqa: BLE001 - keep worker alive and retry transient failures.
                log.exception("inbox message failed id=%s error=%s", message["id"], exc)
                attempts = int(message.get("attempts") or 0) + 1
                self.store.fail_message(
                    int(message["id"]),
                    str(exc),
                    retry=attempts < self.settings.max_attempts,
                )
            else:
                self.store.complete_message(int(message["id"]), generation)
        return len(messages)

    def analyze_once(self) -> bool:
        job = self.store.fetch_queued_job()
        if job is None:
            return False

        job_id = int(job["id"])
        round_id = str(job["round_id"])
        generation = int(job["generation"])
        round_dir = Path(job["round_dir"])
        try:
            if not self.store.is_current_generation(round_id, generation):
                raise RuntimeError(f"job superseded before analysis: {round_id} generation={generation}")

            result = analyzer.analyze_round(round_dir)
            if not self.store.is_current_generation(round_id, generation):
                raise RuntimeError(f"job superseded after analysis: {round_id} generation={generation}")

            _, report_path = analyzer.write_outputs(round_dir, result)
            if not self.store.is_current_generation(round_id, generation):
                raise RuntimeError(f"job superseded before report push: {round_id} generation={generation}")

            self.store.mark_job_reporting(job_id)
            is_mock = analyzer.is_mock_round(round_dir)
            should_push = self.push_reports and (self.settings.push_mock_reports or not is_mock)
            if should_push:
                if not analyzer.push_and_mark_report(round_dir, result["round_id"], report_path):
                    raise RuntimeError(f"report push failed for round {result['round_id']}")
            elif self.push_reports and is_mock:
                log.info("[%s] mock round，跳过上报；设置 LHA_PUSH_MOCK_REPORTS=1 可开启", round_id)
            self.store.complete_job(job_id)
            log.info("[%s] round generation=%s analysis job done", round_id, generation)
        except Exception as exc:  # noqa: BLE001 - worker must keep running.
            log.exception("[%s] analysis job failed generation=%s error=%s", round_id, generation, exc)
            attempts = int(job.get("attempts") or 0)
            self.store.fail_job(
                job_id,
                str(exc),
                retry=attempts < self.settings.max_attempts and self.store.is_current_generation(round_id, generation),
            )
        return True

    def process_message(self, message: dict[str, Any]) -> int | None:
        payload = json.loads(message["payload_json"])
        if not isinstance(payload, dict):
            log.warning("收到非 dict payload，忽略 message_id=%s", message["id"])
            return None

        push_type = payload.get("push_type")
        round_id = payload.get("round_id")
        if not round_id:
            log.warning("消息缺少 round_id，忽略 message_id=%s push_type=%s", message["id"], push_type)
            return None
        if push_type not in {"round_end", "round_kernel", "round_ir_ready"}:
            log.info("[%s] 忽略未处理 push_type=%s message_id=%s", round_id, push_type, message["id"])
            return None

        round_dir = self.settings.input_dir / str(round_id)
        force_new = self._should_start_new_generation(str(round_id), push_type, round_dir)
        generation, should_clear = self.store.begin_round_for_message(str(round_id), round_dir, force_new_generation=force_new)
        if should_clear:
            log.info("[%s] orphan artifacts on disk with no state, clearing generation=%s", round_id, generation)
            clear_round_dir(round_dir, self.settings)
        round_dir.mkdir(parents=True, exist_ok=True)

        log.info(
            "[%s] processing push message_id=%s generation=%s push_type=%s size=%d bytes received_at=%s",
            round_id,
            message["id"],
            generation,
            push_type,
            json_size(payload),
            message.get("received_at") or now_iso(),
        )

        if push_type == "round_ir_ready":
            state = self._record_ir(str(round_id), generation, round_dir, payload)
            if state is None:
                return generation
        elif push_type == "round_end":
            # round_end 只提供报告元数据（action_json/score/time），不参与就绪门控。
            path = round_dir / "round_end.json"
            atomic_write_json(path, payload)
            state = self.store.record_round_input(str(round_id), generation, "round_end", path)
            # 向后兼容：旧上游把 IR 放在 round_end.ir_json 里；仅当尚无独立 IR 时采用。
            if payload.get("ir_json") and not state.get("has_ir"):
                ir_state = self._record_ir(str(round_id), generation, round_dir, payload)
                if ir_state is not None:
                    state = ir_state
        else:
            path = round_dir / "round_kernel.json"
            atomic_write_json(path, payload)
            syscall_path = copy_kernel_file(
                str(round_id),
                payload.get("kernel_syscall_seq"),
                round_dir / "kernel_syscall_seq.jsonl",
            )
            lsm_path = copy_kernel_file(
                str(round_id),
                payload.get("kernel_lsm_hook_result"),
                round_dir / "kernel_lsm_hook_result.jsonl",
            )
            state = self.store.record_round_input(
                str(round_id),
                generation,
                "round_kernel",
                path,
                syscall_path=syscall_path,
                lsm_path=lsm_path,
            )

        if state["status"] == "ready":
            job_id = self.store.enqueue_analysis_job(str(round_id), generation, round_dir)
            log.info("[%s] round ready, queued analysis job_id=%s generation=%s", round_id, job_id, generation)
        return generation

    def _record_ir(self, round_id: str, generation: int, round_dir: Path, payload: dict[str, Any]) -> dict[str, Any] | None:
        """Persist a non-empty IR payload to ir.json and mark has_ir. Empty IR is skipped."""
        if not payload.get("ir_json"):
            log.info("[%s] IR 为空，跳过（等待真正的 round_ir_ready）generation=%s", round_id, generation)
            return None
        path = round_dir / "ir.json"
        atomic_write_json(path, payload)
        return self.store.record_round_input(round_id, generation, "round_ir", path)

    def _should_start_new_generation(self, round_id: str, push_type: str, round_dir: Path) -> bool:
        state = self.store.get_round(round_id)
        if state is None:
            return has_round_artifacts(round_dir)
        # Only a required input (IR / kernel) can start a new run; round_end and other
        # metadata never do (that would double-push on a normal late round_end).
        if push_type not in {"round_ir_ready", "round_kernel"}:
            return False
        # A settled round that receives a required input again is a replay/re-run: bump
        # the generation and re-run the whole pipeline on the persisted inputs. While a
        # round is still receiving or in-flight, duplicates overwrite in place instead.
        return state["status"] in ROUND_TERMINAL_STATUSES


def main() -> None:
    pipeline = RealtimePipeline()
    pipeline.start()
    log.info(
        "realtime pipeline started input_dir=%s db_path=%s analyzer_workers=%d push_reports=%s",
        SETTINGS.input_dir.resolve(),
        SETTINGS.db_path.resolve(),
        max(1, SETTINGS.analyzer_workers),
        pipeline.push_reports,
    )
    try:
        while True:
            time.sleep(30)
            counts = pipeline.store.counts()
            log.info("pipeline heartbeat counts=%s", counts)
    except KeyboardInterrupt:
        log.info("received interrupt, stopping pipeline")
        pipeline.stop()
        pipeline.join()


if __name__ == "__main__":
    main()
