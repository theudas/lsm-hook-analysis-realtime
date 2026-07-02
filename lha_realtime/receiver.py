#!/usr/bin/env python3
"""
Realtime Socket.IO receiver.

The Socket.IO callback only persists incoming push payloads to SQLite. File
copying, analysis, and report pushing are handled by background workers.
"""

from __future__ import annotations

from datetime import datetime

import socketio

from .config import SETTINGS, ensure_runtime_dirs
from .logging_utils import setup_logging
from .pipeline import RealtimePipeline, safe_len
from .state import StateStore, json_size


log = setup_logging("lha_realtime_receiver", "receiver.log")
store = StateStore()
pipeline = RealtimePipeline(store=store)

sio = socketio.Client(
    reconnection=True,
    reconnection_attempts=0,
    reconnection_delay=1,
    reconnection_delay_max=30,
    logger=False,
    engineio_logger=False,
)


@sio.on("push", namespace=SETTINGS.namespace)
def on_push(data):
    received_at = datetime.now().isoformat(timespec="seconds")
    if not isinstance(data, dict):
        log.warning("收到非字典消息，忽略 received_at=%s data_type=%s data=%r", received_at, type(data).__name__, data)
        return

    push_type = data.get("push_type")
    round_id = data.get("round_id")
    log.info(
        "[%s] 收到 push received_at=%s push_type=%s push_time=%s keys=%s size=%d bytes",
        round_id or "-",
        received_at,
        push_type,
        data.get("push_time"),
        sorted(data.keys()),
        json_size(data),
    )

    if not round_id:
        log.warning("消息缺少 round_id，忽略 push_type=%s keys=%s", push_type, sorted(data.keys()))
        return

    if push_type == "round_end":
        log.info(
            "[%s] round_end 摘要 overall_score=%s time_start=%s time_end=%s is_mock=%s "
            "action_json_len=%d ir_json_len=%d",
            round_id,
            data.get("overall_score"),
            data.get("time_start"),
            data.get("time_end"),
            data.get("is_mock"),
            safe_len(data.get("action_json")),
            safe_len(data.get("ir_json")),
        )
    elif push_type == "round_kernel":
        log.info(
            "[%s] round_kernel 摘要 is_mock=%s syscall_path=%s lsm_path=%s resource_facts_len=%d",
            round_id,
            data.get("is_mock"),
            data.get("kernel_syscall_seq"),
            data.get("kernel_lsm_hook_result"),
            safe_len(data.get("kernel_resource_facts")),
        )
    elif push_type == "round_ir_ready":
        log.info(
            "[%s] round_ir_ready 摘要 is_mock=%s ir_json_len=%d",
            round_id,
            data.get("is_mock"),
            safe_len(data.get("ir_json")),
        )
    else:
        log.info("[%s] push_type=%s 将只记录后由 pipeline 忽略", round_id, push_type)

    message_id = store.enqueue_message(data)
    log.info("[%s] push 已写入 inbox message_id=%s push_type=%s", round_id, message_id, push_type)


@sio.event(namespace=SETTINGS.namespace)
def connect():
    log.info("已连接到 server=%s namespace=%s socketio_path=%s", SETTINGS.server_url, SETTINGS.namespace, SETTINGS.socketio_path)


@sio.event(namespace=SETTINGS.namespace)
def disconnect():
    log.warning("连接断开，等待自动重连...")


def main() -> None:
    ensure_runtime_dirs()
    pipeline.start()
    log.info(
        "实时接收端启动 server=%s namespace=%s socketio_path=%s input_dir=%s db_path=%s",
        SETTINGS.server_url,
        SETTINGS.namespace,
        SETTINGS.socketio_path,
        SETTINGS.input_dir.resolve(),
        SETTINGS.db_path.resolve(),
    )
    sio.connect(
        SETTINGS.server_url,
        socketio_path=SETTINGS.socketio_path,
        namespaces=[SETTINGS.namespace],
        transports=["websocket"],
    )
    sio.wait()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("收到中断，退出。")
    finally:
        pipeline.stop()
        if sio.connected:
            sio.disconnect()
        store.close()
