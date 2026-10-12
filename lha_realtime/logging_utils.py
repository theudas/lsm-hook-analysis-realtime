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
    # 先关闭再摘除：直接 clear() 会丢掉旧 FileHandler 的引用而不释放它持有的
    # 文件句柄。StreamHandler.close() 不会关闭 sys.stdout，只有 FileHandler
    # 才会关自己的文件，因此这里对两类 handler 都安全。
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
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
