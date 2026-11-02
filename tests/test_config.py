#!/usr/bin/env python3
"""白盒用例：环境变量解析与运行时目录准备。

config 决定服务启动时读到什么值，解析失败必须在启动阶段就明确报错，而不是把
一个错误的默认值带进运行期。
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lha_realtime.config import PROJECT_ROOT, Settings, _bool_env, _float_env, _int_env, ensure_runtime_dirs


class IntEnvTest(unittest.TestCase):
    def test_unset_variable_uses_the_default(self) -> None:
        """整型环境变量未设置时使用默认值。"""
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(_int_env("LHA_MISSING", 7), 7)

    def test_valid_value_is_parsed(self) -> None:
        """合法整数字符串被正确解析。"""
        with patch.dict(os.environ, {"LHA_X": "42"}):
            self.assertEqual(_int_env("LHA_X", 7), 42)

    def test_negative_and_zero_are_accepted(self) -> None:
        """负数与 0 都是合法取值。"""
        with patch.dict(os.environ, {"LHA_X": "-1"}):
            self.assertEqual(_int_env("LHA_X", 7), -1)
        with patch.dict(os.environ, {"LHA_X": "0"}):
            self.assertEqual(_int_env("LHA_X", 7), 0)

    def test_non_integer_fails_loudly_with_the_variable_name(self) -> None:
        """非整数取值在启动阶段报错并指明变量名。"""
        with patch.dict(os.environ, {"LHA_X": "abc"}):
            with self.assertRaises(ValueError) as ctx:
                _int_env("LHA_X", 7)
        self.assertIn("LHA_X", str(ctx.exception))

    def test_empty_string_is_an_error_not_the_default(self) -> None:
        """空串视为配置错误而非回退默认值。"""
        with patch.dict(os.environ, {"LHA_X": ""}):
            with self.assertRaises(ValueError):
                _int_env("LHA_X", 7)


class FloatEnvTest(unittest.TestCase):
    def test_unset_variable_uses_the_default(self) -> None:
        """浮点型环境变量未设置时使用默认值。"""
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(_float_env("LHA_MISSING", 1.5), 1.5)

    def test_valid_value_is_parsed(self) -> None:
        """合法浮点字符串（含小数与 0）被正确解析。"""
        for value, expected in (("2.5", 2.5), ("0", 0.0), ("0.001", 0.001), ("48", 48.0)):
            with self.subTest(value=value):
                with patch.dict(os.environ, {"LHA_F": value}):
                    self.assertEqual(_float_env("LHA_F", 1.0), expected)

    def test_non_float_fails_loudly_with_the_variable_name(self) -> None:
        """非浮点取值在启动阶段报错并指明变量名。"""
        with patch.dict(os.environ, {"LHA_F": "soon"}):
            with self.assertRaises(ValueError) as ctx:
                _float_env("LHA_F", 1.0)
        self.assertIn("LHA_F", str(ctx.exception))

    def test_empty_string_is_an_error_not_the_default(self) -> None:
        """空串视为配置错误而非回退默认值。"""
        with patch.dict(os.environ, {"LHA_F": ""}):
            with self.assertRaises(ValueError):
                _float_env("LHA_F", 1.0)


class BoolEnvTest(unittest.TestCase):
    def test_unset_variable_uses_the_default(self) -> None:
        """布尔型环境变量未设置时使用默认值。"""
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(_bool_env("LHA_MISSING"))
            self.assertTrue(_bool_env("LHA_MISSING", True))

    def test_accepted_truthy_spellings(self) -> None:
        """1/true/yes/y/on 及大小写与空格变体均为真。"""
        for value in ("1", "true", "TRUE", " yes ", "y", "on", "On"):
            with self.subTest(value=value):
                with patch.dict(os.environ, {"LHA_B": value}):
                    self.assertTrue(_bool_env("LHA_B"))

    def test_everything_else_is_false(self) -> None:
        """其余取值一律为假，不做宽松解释。"""
        for value in ("0", "false", "no", "", "maybe", "2"):
            with self.subTest(value=value):
                with patch.dict(os.environ, {"LHA_B": value}):
                    self.assertFalse(_bool_env("LHA_B", default=True))


class SettingsTest(unittest.TestCase):
    def test_defaults_are_self_consistent(self) -> None:
        """默认配置自洽：上报地址基于 API 根地址，库路径在状态目录下。"""
        settings = Settings()
        self.assertTrue(settings.kernel_report_url.startswith(settings.api_base_url.rstrip("/")))
        self.assertTrue(settings.kernel_report_url.endswith("/api/rounds/detection/kernel"))
        self.assertEqual(settings.db_path.parent, settings.state_dir)
        self.assertGreaterEqual(settings.max_attempts, 1)

    def test_settings_are_frozen(self) -> None:
        """配置对象不可变，运行期无法被意外改写。"""
        settings = Settings()
        with self.assertRaises(Exception):
            settings.max_attempts = 99  # type: ignore[misc]

    def test_overrides_are_honoured(self) -> None:
        """显式传入的配置项覆盖默认值。"""
        settings = Settings(analyzer_workers=4, push_mock_reports=True)
        self.assertEqual(settings.analyzer_workers, 4)
        self.assertTrue(settings.push_mock_reports)

    def test_watchdog_defaults_are_sane(self) -> None:
        """看门狗默认值：半小时告警、一天过期、五分钟一轮、归档在项目根目录下。"""
        settings = Settings(
            input_dir=Path("/tmp/lha-input"),
            log_dir=Path("/tmp/lha-logs"),
            state_dir=Path("/tmp/lha-state"),
            db_path=Path("/tmp/lha-state/realtime.db"),
        )
        self.assertEqual(settings.stale_warn_minutes, 30.0)
        self.assertEqual(settings.stale_round_hours, 24.0)
        self.assertEqual(settings.stale_scan_interval_minutes, 5.0)
        self.assertEqual(settings.message_retention_days, 30)
        self.assertEqual(settings.stale_archive_dir, PROJECT_ROOT / "stale_archive")

    def test_stale_knobs_are_overridable(self) -> None:
        """TTL/告警/扫描间隔/归档目录/保留期都可显式覆盖，0 表示关闭对应动作。

        环境变量在模块导入时一次性读入（与进程启动配置的约定一致），无法在
        实例化时覆盖；env 解析由 FloatEnvTest/IntEnvTest 直接测函数。"""
        settings = Settings(
            input_dir=Path("/tmp/lha-input"),
            log_dir=Path("/tmp/lha-logs"),
            state_dir=Path("/tmp/lha-state"),
            db_path=Path("/tmp/lha-state/realtime.db"),
            stale_round_hours=0,
            stale_warn_minutes=1.5,
            stale_scan_interval_minutes=0.5,
            stale_archive_dir=Path("/tmp/lha-custom-archive"),
            message_retention_days=7,
        )
        self.assertEqual(settings.stale_round_hours, 0.0)
        self.assertEqual(settings.stale_warn_minutes, 1.5)
        self.assertEqual(settings.stale_scan_interval_minutes, 0.5)
        self.assertEqual(settings.message_retention_days, 7)
        self.assertEqual(settings.stale_archive_dir, Path("/tmp/lha-custom-archive"))


class EnsureRuntimeDirsTest(unittest.TestCase):
    def test_creates_all_three_directories_and_is_idempotent(self) -> None:
        """input/logs/state 三个目录被创建且可重复调用。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "nested"
            settings = Settings(
                input_dir=root / "input",
                log_dir=root / "logs",
                state_dir=root / "state",
                db_path=root / "state" / "realtime.db",
            )
            ensure_runtime_dirs(settings)
            ensure_runtime_dirs(settings)
            for directory in (settings.input_dir, settings.log_dir, settings.state_dir):
                self.assertTrue(directory.is_dir(), directory)


if __name__ == "__main__":
    unittest.main()
