"""测试包初始化：抑制服务模块的日志输出。

analyzer / pipeline / receiver 都在模块导入时调用 setup_logging()，给自己挂一个
INFO 级的 StreamHandler(sys.stdout)。跑测试时这会刷出成百上千行服务日志，把
unittest 的结果淹没，也会把测试噪声追加进 logs/ 下线上服务正在写的同名文件。

这里用「在 logger 上挂过滤器」而不是改级别或摘 handler，原因是三条约束：

1. setup_logging() 每次调用都重设 level、重建 handler，但不动 filters，
   所以过滤器能活过模块 import 以及后续任意次 setup_logging() 调用；
2. test_logging_utils.py 断言 logger.level == INFO、恰好挂着 FileHandler 与
   StreamHandler 两个、且 logger.info() 的内容要真的落进文件。改级别或摘
   handler 会直接弄挂这些用例。本文件只针对下面三个服务 logger，
   test_logging_utils 用的是独立名字 lha_test_logger，不受影响；
3. logging.getLogger(name) 只按名字取 Logger 对象，不会触发模块导入，
   因此这里无需 import lha_realtime，也就不会干扰 test_receiver 在 import 前
   替换 StateStore / RealtimePipeline 的做法。

过滤发生在 logger 层，记录不会到达任何 handler，因此跑测试也不再往
logs/analyzer.log 等文件里写东西。

日志语句本身照常执行（Logger.info 先过 isEnabledFor，级别仍是 INFO），
被丢弃发生在之后的 handle 阶段，所以覆盖率统计不受影响。

调试单条测试想看服务日志时，设 LHA_TEST_LOGS=1 即可放行：

    LHA_TEST_LOGS=1 python3 -m unittest tests.test_realtime_pipeline
"""

from __future__ import annotations

import logging
import os

SERVICE_LOGGERS = (
    "lha_realtime_analyzer",
    "lha_realtime_pipeline",
    "lha_realtime_receiver",
)

_TRUTHY = {"1", "true", "yes", "y", "on"}


class SuppressServiceLogs(logging.Filter):
    """丢弃全部记录。挂在服务 logger 上，使测试输出只剩 unittest 自己的结果。"""

    def filter(self, record: logging.LogRecord) -> bool:
        return False


def _install() -> None:
    if os.environ.get("LHA_TEST_LOGS", "").strip().lower() in _TRUTHY:
        return
    for name in SERVICE_LOGGERS:
        logger = logging.getLogger(name)
        if not any(isinstance(f, SuppressServiceLogs) for f in logger.filters):
            logger.addFilter(SuppressServiceLogs())


_install()
