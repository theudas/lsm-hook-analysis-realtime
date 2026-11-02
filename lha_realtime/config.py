#!/usr/bin/env python3
"""Runtime configuration for the realtime LSM analysis service."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


PACKAGE_DIR = Path(__file__).parent
PROJECT_ROOT = PACKAGE_DIR.parent


def _int_env(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {value!r}") from exc


def _float_env(name: str, default: float) -> float:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number, got {value!r}") from exc


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


@dataclass(frozen=True)
class Settings:
    server_url: str = os.environ.get("LHA_SERVER_URL", "ws://8.152.192.7:15100")
    socketio_path: str = os.environ.get("LHA_SOCKETIO_PATH", "/wss")
    namespace: str = os.environ.get("LHA_NAMESPACE", "/wss/monitor")

    input_dir: Path = Path(os.environ.get("LHA_INPUT_DIR", PROJECT_ROOT / "input"))
    log_dir: Path = Path(os.environ.get("LHA_LOG_DIR", PROJECT_ROOT / "logs"))
    state_dir: Path = Path(os.environ.get("LHA_STATE_DIR", PROJECT_ROOT / "state"))
    db_path: Path = Path(os.environ.get("LHA_DB_PATH", PROJECT_ROOT / "state" / "realtime.db"))

    api_base_url: str = os.environ.get("LHA_API_BASE_URL", "http://8.152.192.7:15100")
    kernel_report_url: str = os.environ.get(
        "LHA_KERNEL_REPORT_URL",
        f"{os.environ.get('LHA_API_BASE_URL', 'http://8.152.192.7:15100').rstrip('/')}/api/rounds/detection/kernel",
    )
    kernel_report_push_timeout: int = _int_env("LHA_KERNEL_REPORT_PUSH_TIMEOUT", 900)
    push_mock_reports: bool = _bool_env("LHA_PUSH_MOCK_REPORTS", False)

    analyzer_workers: int = _int_env("LHA_ANALYZER_WORKERS", 1)
    ingest_poll_interval: float = float(os.environ.get("LHA_INGEST_POLL_INTERVAL", "0.02"))
    analysis_poll_interval: float = float(os.environ.get("LHA_ANALYSIS_POLL_INTERVAL", "0.02"))
    retry_backoff_seconds: int = _int_env("LHA_RETRY_BACKOFF_SECONDS", 10)
    max_attempts: int = _int_env("LHA_MAX_ATTEMPTS", 3)

    # 采集看门狗：round 长时间收不齐时先告警、超时后归档（0 关闭对应动作）。
    stale_round_hours: float = _float_env("LHA_STALE_ROUND_HOURS", 24.0)
    stale_warn_minutes: float = _float_env("LHA_STALE_WARN_MINUTES", 30.0)
    stale_scan_interval_minutes: float = _float_env("LHA_STALE_SCAN_MINUTES", 5.0)
    stale_archive_dir: Path = Path(os.environ.get("LHA_STALE_ARCHIVE_DIR", PROJECT_ROOT / "stale_archive"))
    message_retention_days: int = _int_env("LHA_MESSAGE_RETENTION_DAYS", 30)


SETTINGS = Settings()


def ensure_runtime_dirs(settings: Settings = SETTINGS) -> None:
    settings.input_dir.mkdir(parents=True, exist_ok=True)
    settings.log_dir.mkdir(parents=True, exist_ok=True)
    settings.state_dir.mkdir(parents=True, exist_ok=True)
