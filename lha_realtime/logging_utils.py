#!/usr/bin/env python3
"""Logging helpers shared by realtime service modules."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from .config import SETTINGS, ensure_runtime_dirs


def setup_logging(name: str, filename: str, log_dir: Path | None = None) -> logging.Logger:
    ensure_runtime_dirs()
    target_dir = log_dir or SETTINGS.log_dir
    target_dir.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    logger.propagate = False

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    for handler in (
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(target_dir / filename, encoding="utf-8"),
    ):
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger
