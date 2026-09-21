#!/usr/bin/env python3
"""白盒用例：共享日志配置。

setup_logging 会在每次调用时重建 handler。曾经的实现直接 handlers.clear()，
丢掉旧 FileHandler 的引用却不释放它持有的文件句柄——常驻服务只调用一次影响
有限，但 receiver 被反复 import/reload 时会累积泄漏。这里把"旧 handler 必须
被关闭、而 sys.stdout 不能被顺手关掉"钉死。
"""

from __future__ import annotations

import logging
import sys
import tempfile
import unittest
from pathlib import Path

from lha_realtime.logging_utils import setup_logging


class SetupLoggingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.log_dir = Path(self.tmp.name) / "logs"
        self.name = "lha_test_logger"

    def tearDown(self) -> None:
        logger = logging.getLogger(self.name)
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            handler.close()
        self.tmp.cleanup()

    def test_creates_the_log_dir_and_attaches_both_handlers(self) -> None:
        """创建日志目录并同时挂载控制台与文件两个 handler。"""
        logger = setup_logging(self.name, "test.log", log_dir=self.log_dir)
        self.assertTrue(self.log_dir.is_dir())
        self.assertEqual(logger.level, logging.INFO)
        self.assertFalse(logger.propagate)
        kinds = sorted(type(handler).__name__ for handler in logger.handlers)
        self.assertEqual(kinds, ["FileHandler", "StreamHandler"])

    def test_messages_reach_the_log_file(self) -> None:
        """日志内容按格式写入文件，含级别与 logger 名。"""
        logger = setup_logging(self.name, "test.log", log_dir=self.log_dir)
        logger.info("hello 白盒")
        for handler in logger.handlers:
            handler.flush()
        content = (self.log_dir / "test.log").read_text(encoding="utf-8")
        self.assertIn("hello 白盒", content)
        self.assertIn("[INFO]", content)
        self.assertIn(self.name, content)

    def test_reconfiguring_closes_the_previous_file_handler(self) -> None:
        """重新配置时关闭旧 FileHandler，释放文件句柄。"""
        first = setup_logging(self.name, "test.log", log_dir=self.log_dir)
        old_file_handler = next(
            handler for handler in first.handlers if isinstance(handler, logging.FileHandler)
        )
        self.assertIsNotNone(old_file_handler.stream)

        setup_logging(self.name, "test.log", log_dir=self.log_dir)

        # FileHandler.close() 会关掉文件并把 stream 置 None；这是"句柄已释放"的证据。
        self.assertIsNone(old_file_handler.stream)

    def test_reconfiguring_does_not_close_stdout(self) -> None:
        """重新配置不会连带关闭 sys.stdout。"""
        setup_logging(self.name, "test.log", log_dir=self.log_dir)
        setup_logging(self.name, "test.log", log_dir=self.log_dir)
        self.assertFalse(sys.stdout.closed)

    def test_repeated_setup_does_not_accumulate_handlers(self) -> None:
        """反复调用不会累积 handler 造成重复输出。"""
        for _ in range(5):
            logger = setup_logging(self.name, "test.log", log_dir=self.log_dir)
        self.assertEqual(len(logger.handlers), 2)

    def test_logging_still_works_after_reconfiguration(self) -> None:
        """重新配置后日志仍能正常写入。"""
        setup_logging(self.name, "test.log", log_dir=self.log_dir)
        logger = setup_logging(self.name, "test.log", log_dir=self.log_dir)
        logger.info("after reload")
        for handler in logger.handlers:
            handler.flush()
        self.assertIn("after reload", (self.log_dir / "test.log").read_text(encoding="utf-8"))

    def test_separate_names_get_separate_loggers(self) -> None:
        """不同名字得到独立 logger 与独立日志文件。"""
        first = setup_logging(self.name, "a.log", log_dir=self.log_dir)
        second = setup_logging(self.name + "_other", "b.log", log_dir=self.log_dir)
        try:
            self.assertIsNot(first, second)
            self.assertTrue((self.log_dir / "a.log").is_file())
            self.assertTrue((self.log_dir / "b.log").is_file())
        finally:
            for handler in list(second.handlers):
                second.removeHandler(handler)
                handler.close()


if __name__ == "__main__":
    unittest.main()
