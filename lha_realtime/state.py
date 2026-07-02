#!/usr/bin/env python3
"""SQLite-backed inbox, round state, and analysis job storage."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import SETTINGS, Settings, ensure_runtime_dirs


ROUND_RESET_STATUSES = {
    "ready",
    "queued",
    "analyzing",
    "reporting",
    "done",
    "analysis_failed",
    "report_failed",
    "cancelled",
}
# Statuses where a round has settled: a replayed required input should re-run the
# whole pipeline from the inputs already persisted on disk.
ROUND_TERMINAL_STATUSES = {
    "done",
    "analysis_failed",
    "report_failed",
    "cancelled",
}
FINAL_JOB_STATUSES = {"done", "failed", "cancelled"}


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def json_size(data: dict[str, Any]) -> int:
    return len(json.dumps(data, ensure_ascii=False).encode("utf-8"))


class StateStore:
    def __init__(self, db_path: Path | None = None, settings: Settings = SETTINGS):
        self.settings = settings
        ensure_runtime_dirs(settings)
        self.db_path = db_path or settings.db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        # WAL + NORMAL: skip the per-commit fsync (synced at checkpoint instead).
        # Never corrupts the DB; a power loss / OS crash may drop only the last
        # few committed transactions. Safe and faster for this realtime workload.
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self.init_db()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def init_db(self) -> None:
        with self._lock, self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS inbox_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    received_at TEXT NOT NULL,
                    push_type TEXT,
                    round_id TEXT,
                    generation INTEGER,
                    payload_json TEXT NOT NULL,
                    payload_size INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_inbox_status_id
                    ON inbox_messages(status, id);

                CREATE TABLE IF NOT EXISTS round_states (
                    round_id TEXT PRIMARY KEY,
                    generation INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    round_dir TEXT NOT NULL,
                    has_round_start INTEGER NOT NULL DEFAULT 0,
                    has_round_end INTEGER NOT NULL DEFAULT 0,
                    has_round_kernel INTEGER NOT NULL DEFAULT 0,
                    has_ir INTEGER NOT NULL DEFAULT 0,
                    round_start_path TEXT,
                    round_end_path TEXT,
                    round_kernel_path TEXT,
                    ir_path TEXT,
                    syscall_path TEXT,
                    lsm_path TEXT,
                    analysis_job_id INTEGER,
                    last_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS analysis_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    round_id TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    round_dir TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(round_id, generation)
                );

                CREATE INDEX IF NOT EXISTS idx_jobs_status_id
                    ON analysis_jobs(status, id);
                """
            )
            self._migrate_round_states_columns()

    def _migrate_round_states_columns(self) -> None:
        """Add columns introduced after the original schema (idempotent).

        CREATE TABLE IF NOT EXISTS never alters an existing table, so databases
        created before has_ir/ir_path existed need an explicit backfill.
        """
        existing = {
            row["name"]
            for row in self._conn.execute("PRAGMA table_info(round_states)").fetchall()
        }
        additions = {
            "has_ir": "INTEGER NOT NULL DEFAULT 0",
            "ir_path": "TEXT",
            "has_round_start": "INTEGER NOT NULL DEFAULT 0",
            "round_start_path": "TEXT",
        }
        for column, definition in additions.items():
            if column not in existing:
                self._conn.execute(
                    f"ALTER TABLE round_states ADD COLUMN {column} {definition}"
                )

    def enqueue_message(self, payload: dict[str, Any]) -> int:
        timestamp = now_iso()
        raw = json.dumps(payload, ensure_ascii=False)
        with self._lock, self._conn:
            cursor = self._conn.execute(
                """
                INSERT INTO inbox_messages (
                    received_at, push_type, round_id, payload_json, payload_size,
                    status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
                """,
                (
                    timestamp,
                    payload.get("push_type"),
                    payload.get("round_id"),
                    raw,
                    len(raw.encode("utf-8")),
                    timestamp,
                    timestamp,
                ),
            )
            return int(cursor.lastrowid)

    def fetch_pending_messages(self, limit: int = 10) -> list[dict[str, Any]]:
        with self._lock, self._conn:
            rows = self._conn.execute(
                """
                SELECT * FROM inbox_messages
                WHERE status = 'pending'
                ORDER BY id
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            ids = [row["id"] for row in rows]
            if ids:
                placeholders = ",".join("?" for _ in ids)
                self._conn.execute(
                    f"""
                    UPDATE inbox_messages
                    SET status = 'processing',
                        attempts = attempts + 1,
                        updated_at = ?
                    WHERE id IN ({placeholders})
                    """,
                    [now_iso(), *ids],
                )
            return [dict(row) for row in rows]

    def complete_message(self, message_id: int, generation: int | None = None) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                UPDATE inbox_messages
                SET status = 'done',
                    generation = COALESCE(?, generation),
                    updated_at = ?
                WHERE id = ?
                """,
                (generation, now_iso(), message_id),
            )

    def fail_message(self, message_id: int, error_message: str, retry: bool = True) -> None:
        with self._lock, self._conn:
            status = "pending" if retry else "failed"
            self._conn.execute(
                """
                UPDATE inbox_messages
                SET status = ?,
                    last_error = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (status, error_message, now_iso(), message_id),
            )

    def get_round(self, round_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM round_states WHERE round_id = ?",
                (round_id,),
            ).fetchone()
            return dict(row) if row else None

    def begin_round_for_message(self, round_id: str, round_dir: Path, force_new_generation: bool = False) -> tuple[int, bool]:
        """Return active generation and whether old data should be cleared."""
        timestamp = now_iso()
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT * FROM round_states WHERE round_id = ?",
                (round_id,),
            ).fetchone()
            if row is None:
                self._conn.execute(
                    """
                    INSERT INTO round_states (
                        round_id, generation, status, round_dir,
                        created_at, updated_at
                    ) VALUES (?, 1, 'receiving', ?, ?, ?)
                    """,
                    (round_id, str(round_dir), timestamp, timestamp),
                )
                return 1, force_new_generation

            generation = int(row["generation"])
            # The new-generation decision is owned entirely by the caller
            # (_should_start_new_generation). A re-run (replay of a settled round)
            # bumps the generation for job identity and supersedes any in-flight job,
            # but intentionally KEEPS the persisted inputs and their flags so the round
            # is immediately complete again from disk — a replay of even a single
            # required message re-runs the full pipeline on the existing inputs.
            if force_new_generation:
                generation += 1
                self._conn.execute(
                    """
                    UPDATE analysis_jobs
                    SET status = 'cancelled',
                        last_error = 'superseded by re-run',
                        updated_at = ?
                    WHERE round_id = ?
                      AND status NOT IN ('done', 'failed', 'cancelled')
                    """,
                    (timestamp, round_id),
                )
                self._conn.execute(
                    """
                    UPDATE round_states
                    SET generation = ?,
                        status = 'receiving',
                        round_dir = ?,
                        analysis_job_id = NULL,
                        last_error = NULL,
                        updated_at = ?
                    WHERE round_id = ?
                    """,
                    (generation, str(round_dir), timestamp, round_id),
                )
                return generation, False

            return generation, False

    def record_round_input(
        self,
        round_id: str,
        generation: int,
        input_kind: str,
        file_path: Path,
        syscall_path: Path | None = None,
        lsm_path: Path | None = None,
    ) -> dict[str, Any]:
        if input_kind not in {"round_start", "round_end", "round_kernel", "round_ir"}:
            raise ValueError(f"unsupported input_kind: {input_kind}")

        timestamp = now_iso()
        with self._lock, self._conn:
            if input_kind == "round_start":
                self._conn.execute(
                    """
                    UPDATE round_states
                    SET has_round_start = 1,
                        round_start_path = ?,
                        updated_at = ?
                    WHERE round_id = ?
                      AND generation = ?
                    """,
                    (str(file_path), timestamp, round_id, generation),
                )
            elif input_kind == "round_end":
                self._conn.execute(
                    """
                    UPDATE round_states
                    SET has_round_end = 1,
                        round_end_path = ?,
                        updated_at = ?
                    WHERE round_id = ?
                      AND generation = ?
                    """,
                    (str(file_path), timestamp, round_id, generation),
                )
            elif input_kind == "round_ir":
                self._conn.execute(
                    """
                    UPDATE round_states
                    SET has_ir = 1,
                        ir_path = ?,
                        updated_at = ?
                    WHERE round_id = ?
                      AND generation = ?
                    """,
                    (str(file_path), timestamp, round_id, generation),
                )
            else:
                self._conn.execute(
                    """
                    UPDATE round_states
                    SET has_round_kernel = 1,
                        round_kernel_path = ?,
                        syscall_path = COALESCE(?, syscall_path),
                        lsm_path = COALESCE(?, lsm_path),
                        updated_at = ?
                    WHERE round_id = ?
                      AND generation = ?
                    """,
                    (
                        str(file_path),
                        str(syscall_path) if syscall_path else None,
                        str(lsm_path) if lsm_path else None,
                        timestamp,
                        round_id,
                        generation,
                    ),
                )

            row = self._conn.execute(
                "SELECT * FROM round_states WHERE round_id = ? AND generation = ?",
                (round_id, generation),
            ).fetchone()
            if row is None:
                raise RuntimeError(f"round state disappeared: {round_id} generation={generation}")
            # 四类消息（round_start / round_end / round_kernel / round_ir_ready）
            # 到达顺序不确定，必须全部就位后再触发分析，保证报告内容完整不为空。
            ready = (
                bool(row["has_round_start"])
                and bool(row["has_round_end"])
                and bool(row["has_ir"])
                and bool(row["has_round_kernel"])
            )
            if ready and row["status"] == "receiving":
                self._conn.execute(
                    """
                    UPDATE round_states
                    SET status = 'ready',
                        updated_at = ?
                    WHERE round_id = ?
                      AND generation = ?
                    """,
                    (timestamp, round_id, generation),
                )
            return dict(self._conn.execute(
                "SELECT * FROM round_states WHERE round_id = ? AND generation = ?",
                (round_id, generation),
            ).fetchone())

    def enqueue_analysis_job(self, round_id: str, generation: int, round_dir: Path) -> int:
        timestamp = now_iso()
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO analysis_jobs (
                    round_id, generation, round_dir, status,
                    created_at, updated_at
                ) VALUES (?, ?, ?, 'queued', ?, ?)
                """,
                (round_id, generation, str(round_dir), timestamp, timestamp),
            )
            row = self._conn.execute(
                """
                SELECT id
                FROM analysis_jobs
                WHERE round_id = ?
                  AND generation = ?
                """,
                (round_id, generation),
            ).fetchone()
            if row is None:
                raise RuntimeError(f"failed to enqueue analysis job: {round_id} generation={generation}")
            job_id = int(row["id"])
            self._conn.execute(
                """
                UPDATE round_states
                SET status = 'queued',
                    analysis_job_id = ?,
                    updated_at = ?
                WHERE round_id = ?
                  AND generation = ?
                  AND status = 'ready'
                """,
                (job_id, timestamp, round_id, generation),
            )
            return job_id

    def fetch_queued_job(self) -> dict[str, Any] | None:
        timestamp = now_iso()
        with self._lock, self._conn:
            row = self._conn.execute(
                """
                SELECT * FROM analysis_jobs
                WHERE status = 'queued'
                ORDER BY id
                LIMIT 1
                """
            ).fetchone()
            if row is None:
                return None
            self._conn.execute(
                """
                UPDATE analysis_jobs
                SET status = 'analyzing',
                    attempts = attempts + 1,
                    updated_at = ?
                WHERE id = ?
                """,
                (timestamp, row["id"]),
            )
            self._conn.execute(
                """
                UPDATE round_states
                SET status = 'analyzing',
                    updated_at = ?
                WHERE round_id = ?
                  AND generation = ?
                """,
                (timestamp, row["round_id"], row["generation"]),
            )
            updated = self._conn.execute(
                "SELECT * FROM analysis_jobs WHERE id = ?",
                (row["id"],),
            ).fetchone()
            return dict(updated)

    def mark_job_reporting(self, job_id: int) -> None:
        self._set_job_and_round_status(job_id, "reporting")

    def complete_job(self, job_id: int) -> None:
        self._set_job_and_round_status(job_id, "done")

    def fail_job(self, job_id: int, error_message: str, retry: bool = False) -> None:
        timestamp = now_iso()
        with self._lock, self._conn:
            row = self._conn.execute("SELECT * FROM analysis_jobs WHERE id = ?", (job_id,)).fetchone()
            if row is None:
                return
            status = "queued" if retry else "failed"
            round_status = "queued" if retry else "analysis_failed"
            self._conn.execute(
                """
                UPDATE analysis_jobs
                SET status = ?,
                    last_error = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (status, error_message, timestamp, job_id),
            )
            self._conn.execute(
                """
                UPDATE round_states
                SET status = ?,
                    last_error = ?,
                    updated_at = ?
                WHERE round_id = ?
                  AND generation = ?
                """,
                (round_status, error_message, timestamp, row["round_id"], row["generation"]),
            )

    def current_generation(self, round_id: str) -> int | None:
        row = self.get_round(round_id)
        return int(row["generation"]) if row else None

    def is_current_generation(self, round_id: str, generation: int) -> bool:
        current = self.current_generation(round_id)
        return current == generation

    def _set_job_and_round_status(self, job_id: int, status: str) -> None:
        timestamp = now_iso()
        with self._lock, self._conn:
            row = self._conn.execute("SELECT * FROM analysis_jobs WHERE id = ?", (job_id,)).fetchone()
            if row is None:
                return
            self._conn.execute(
                "UPDATE analysis_jobs SET status = ?, updated_at = ? WHERE id = ?",
                (status, timestamp, job_id),
            )
            self._conn.execute(
                """
                UPDATE round_states
                SET status = ?,
                    updated_at = ?
                WHERE round_id = ?
                  AND generation = ?
                """,
                (status, timestamp, row["round_id"], row["generation"]),
            )

    def counts(self) -> dict[str, int]:
        with self._lock:
            return {
                "pending_messages": int(self._conn.execute(
                    "SELECT COUNT(*) FROM inbox_messages WHERE status = 'pending'"
                ).fetchone()[0]),
                "queued_jobs": int(self._conn.execute(
                    "SELECT COUNT(*) FROM analysis_jobs WHERE status = 'queued'"
                ).fetchone()[0]),
            }
