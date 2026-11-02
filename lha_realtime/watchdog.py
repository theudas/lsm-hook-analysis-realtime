#!/usr/bin/env python3
"""采集看门狗：对一直收不齐的 round 先告警、超时后归档。

四类消息（round_start / round_end / round_kernel / round_ir_ready）正常在几秒到
几分钟内收齐。一个 round 长时间停在 receiving，或 input/ 里留着没有状态行的
半成品目录，都说明上游采集或推送出了问题；放任不管只会让目录和状态库无限膨胀。

处理策略（设 0 可分别关闭对应动作）：

  - 超过 ``LHA_STALE_WARN_MINUTES`` 未收齐：记一条 WARNING。每个 round 在同一次
    updated_at 上只记一次；来了新消息会重新计时，再次超时后会再记。
  - 超过 ``LHA_STALE_ROUND_HOURS`` 未收齐：input/<round_id>/ 移到归档目录并删除
    状态行。之后同一 round_id 再来消息会作为全新 round 从头收集，数据不丢。
  - 只处理 status='receiving' 的 round 与 input/ 下没有状态行的未收齐目录；
    磁盘上六类输入齐全的 round（无论有没有状态行）永不过期——语料回放依赖它们。
  - 顺带删除超过 ``LHA_MESSAGE_RETENTION_DAYS`` 的已完成消息行（仅审计用途）。

每次发生过期都向归档目录写一份 manifest，记录每个 round 等了多久、缺哪些消息。
"""

from __future__ import annotations

import json
import shutil
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .config import SETTINGS, Settings
from .logging_utils import setup_logging
from .state import StateStore

log = setup_logging("lha_realtime_watchdog", "watchdog.log")

# 磁盘视角的“收齐”口径，与 pipeline 的就绪门控一致；scripts/completeness_stats.py
# 共用这里的判定，保证看板与归档对“收齐”的定义不漂移。
REQUIRED_FILES = (
    "round_start.json",
    "round_end.json",
    "round_kernel.json",
    "kernel_syscall_seq.jsonl",
    "kernel_lsm_hook_result.jsonl",
)
IR_BIT = 1 << len(REQUIRED_FILES)
COMPLETE_MASK = (1 << (len(REQUIRED_FILES) + 1)) - 1

# round_states 各输入位对应的消息名，用于告警里写清还差什么。
INPUT_FLAGS = (
    ("has_round_start", "round_start"),
    ("has_round_end", "round_end"),
    ("has_round_kernel", "round_kernel"),
    ("has_ir", "round_ir"),
)


def has_usable_ir(round_dir: Path) -> bool:
    """IR 可来自独立的 ir.json，或旧上游内嵌在 round_end.ir_json。"""
    ir = round_dir / "ir.json"
    if ir.is_file():
        try:
            if json.loads(ir.read_text(encoding="utf-8")).get("ir_json"):
                return True
        except (OSError, json.JSONDecodeError):
            pass
    end = round_dir / "round_end.json"
    if end.is_file():
        try:
            return bool(json.loads(end.read_text(encoding="utf-8")).get("ir_json"))
        except (OSError, json.JSONDecodeError):
            return False
    return False


def input_mask(round_dir: Path) -> int:
    """把目录里已有的输入折叠成一个位掩码：bit i = REQUIRED_FILES[i] 存在，
    最高位 = IR 可用（独立 ir.json 或 round_end 内嵌）。全部置位即收齐。"""
    mask = 0
    for bit, name in enumerate(REQUIRED_FILES):
        if (round_dir / name).is_file():
            mask |= 1 << bit
    if has_usable_ir(round_dir):
        mask |= IR_BIT
    return mask


def is_complete_on_disk(round_dir: Path) -> bool:
    return input_mask(round_dir) == COMPLETE_MASK


def missing_on_disk(round_dir: Path) -> list[str]:
    names = [name for name in REQUIRED_FILES if not (round_dir / name).is_file()]
    if not has_usable_ir(round_dir):
        names.append("ir.json")
    return names


def _missing_from_flags(row: dict[str, Any]) -> list[str]:
    return [label for flag, label in INPUT_FLAGS if not row.get(flag)]


def _fmt_age(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f} 秒"
    if seconds < 3600:
        return f"{seconds / 60:.0f} 分钟"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} 小时"
    return f"{seconds / 86400:.1f} 天"


def _age_seconds(updated_at: str | None) -> float | None:
    if not updated_at:
        return None
    try:
        ts = datetime.fromisoformat(updated_at).timestamp()
    except ValueError:
        return None
    return time.time() - ts


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


class StaleRoundWatchdog:
    def __init__(self, store: StateStore, settings: Settings = SETTINGS):
        self.store = store
        self.settings = settings
        # round_id -> 告警时的 updated_at。新消息会刷新 updated_at，从而允许再次告警。
        self._warned: dict[str, str] = {}
        self._archive_checked = False
        self._archive_broken = False

    @property
    def enabled(self) -> bool:
        return bool(
            self.settings.stale_round_hours
            or self.settings.stale_warn_minutes
            or self.settings.message_retention_days
        )

    def scan_once(self) -> dict[str, int]:
        """执行一轮扫描，返回计数便于日志与测试断言。"""
        result = {"receiving": 0, "warned": 0, "expired": 0, "purged_messages": 0}
        can_expire = self.settings.stale_round_hours > 0 and self._archive_allowed()
        ttl = self.settings.stale_round_hours * 3600
        warn_after = self.settings.stale_warn_minutes * 60

        rows = self.store.fetch_receiving_rounds()
        result["receiving"] = len(rows)
        known_ids = self.store.round_ids()
        expired: list[dict[str, Any]] = []
        for row in rows:
            round_id = str(row["round_id"])
            age = _age_seconds(row["updated_at"])
            if age is None:
                log.warning("[%s] updated_at 无法解析：%r，跳过看门狗检查", round_id, row["updated_at"])
                continue
            if is_complete_on_disk(Path(row["round_dir"])):
                # 磁盘事实优先于状态行：六类输入已收齐的 round 永不归档也不告警，
                # 哪怕状态机因崩溃停在 receiving（语料回放依赖这些目录）。
                self._warned.pop(round_id, None)
                continue
            if can_expire and age >= ttl:
                entry = self._expire_state_round(row, age)
                if entry is not None:
                    expired.append(entry)
                    result["expired"] += 1
                self._warned.pop(round_id, None)
            elif warn_after and age >= warn_after and self._warned.get(round_id) != row["updated_at"]:
                log.warning(
                    "[%s] round 已等待 %s 未收齐（缺 %s），请检查上游采集",
                    round_id, _fmt_age(age), "、".join(_missing_from_flags(row)) or "-",
                )
                self._warned[round_id] = str(row["updated_at"])
                result["warned"] += 1
        # 已收齐或已过期的不再占用告警集合，防止长期运行时集合膨胀。
        self._warned = {rid: ts for rid, ts in self._warned.items() if rid in known_ids}

        if can_expire:
            expired.extend(self._expire_orphans(ttl, known_ids))
            result["expired"] = len(expired)
        if expired:
            self._log_and_manifest(expired)

        if self.settings.message_retention_days:
            cutoff = (datetime.now() - timedelta(days=self.settings.message_retention_days)).isoformat(timespec="seconds")
            purged = self.store.purge_messages_before(cutoff)
            result["purged_messages"] = purged
            if purged:
                log.info("已清理 %d 条超过 %d 天的已完成消息", purged, self.settings.message_retention_days)

        if result["receiving"] or result["warned"] or result["expired"] or result["purged_messages"]:
            log.info(
                "看门狗扫描：receiving=%d warned=%d expired=%d purged_messages=%d",
                result["receiving"], result["warned"], result["expired"], result["purged_messages"],
            )
        return result

    def _archive_allowed(self) -> bool:
        """归档目录不得位于 input/ 之内，否则会把自己归档的东西再当成 round。"""
        if not self._archive_checked:
            self._archive_checked = True
            archive = self.settings.stale_archive_dir.resolve()
            root = self.settings.input_dir.resolve()
            if archive == root or root in archive.parents:
                self._archive_broken = True
                log.error(
                    "归档目录 %s 位于 input/ 之内，看门狗跳过过期归档（告警与消息清理不受影响）",
                    archive,
                )
        return not self._archive_broken

    def _expire_state_round(self, row: dict[str, Any], age: float) -> dict[str, Any] | None:
        round_id = str(row["round_id"])
        # 先删状态行（事务内校验仍是 receiving）：若此刻恰好收齐，放弃本次过期。
        if not self.store.delete_round(round_id):
            return None
        round_dir = Path(row["round_dir"])
        dest = None
        if _is_within(round_dir, self.settings.input_dir):
            dest = self._archive_dir(round_dir)
        entry = {
            "round_id": round_id,
            "source": "state",
            "waited_seconds": round(age),
            "missing": _missing_from_flags(row),
            "round_dir": str(round_dir),
            "archived_to": str(dest) if dest else None,
        }
        log.warning(
            "[%s] 采集超时：等待 %s 未收齐（缺 %s），%s",
            round_id, _fmt_age(age), "、".join(entry["missing"]) or "-",
            f"已归档到 {dest}" if dest else "磁盘无产物或不在 input/ 下，仅清状态行",
        )
        return entry

    def _expire_orphans(self, ttl: float, known_ids: set[str]) -> list[dict[str, Any]]:
        """input/ 下没有状态行、未收齐、且超过 TTL 没有新消息的目录。

        状态库被重置或历史部署留下的半成品目录没有状态行，只能按磁盘事实判定：
        最后一次文件变化距今超过 TTL 即视为死掉。收齐的目录永不动——语料回放靠它们。
        """
        entries: list[dict[str, Any]] = []
        now = time.time()
        try:
            children = list(self.settings.input_dir.iterdir())
        except OSError:
            log.warning("无法读取 input 目录：%s", self.settings.input_dir)
            return entries
        for child in children:
            if not child.is_dir() or child.name.startswith(".") or child.name in known_ids:
                continue
            if is_complete_on_disk(child):
                continue
            stamps = [p.stat().st_mtime for p in child.iterdir() if p.is_file()]
            last_activity = max(stamps) if stamps else child.stat().st_mtime
            age = now - last_activity
            if age < ttl:
                continue
            missing = missing_on_disk(child)
            dest = self._archive_dir(child)
            entry = {
                "round_id": child.name,
                "source": "orphan",
                "waited_seconds": round(age),
                "missing": missing,
                "round_dir": str(child),
                "archived_to": str(dest) if dest else None,
            }
            entries.append(entry)
            log.warning(
                "[%s] 孤儿目录超时：%.1f 天没有新消息且未收齐（缺 %s），已归档到 %s",
                child.name, age / 86400, "、".join(missing), dest,
            )
        return entries

    def _archive_dir(self, round_dir: Path) -> Path | None:
        if not round_dir.is_dir():
            return None
        dest = self._unique_destination(self.settings.stale_archive_dir / round_dir.name)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(round_dir), str(dest))
        return dest

    def _unique_destination(self, base: Path) -> Path:
        """同名 round 可能先后两次收不齐：第二次归档追加 __2、__3 后缀。"""
        if not base.exists():
            return base
        n = 2
        while True:
            candidate = base.with_name(f"{base.name}__{n}")
            if not candidate.exists():
                return candidate
            n += 1

    def _log_and_manifest(self, entries: list[dict[str, Any]]) -> None:
        manifest = self._write_manifest(entries)
        if len(entries) > 20:
            log.warning(
                "看门狗：本轮共过期 %d 个 round，明细见 %s（上面只展示了前 20 个）",
                len(entries), manifest,
            )

    def _write_manifest(self, entries: list[dict[str, Any]]) -> Path:
        self.settings.stale_archive_dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S")
        manifest = self._unique_destination(self.settings.stale_archive_dir / f"manifest_{stamp}.json")
        manifest.write_text(
            json.dumps(
                {
                    "archived_at": datetime.now().isoformat(timespec="seconds"),
                    "input_dir": str(self.settings.input_dir),
                    "expired_count": len(entries),
                    "expired": entries,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        return manifest
