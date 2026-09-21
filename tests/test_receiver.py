#!/usr/bin/env python3
"""白盒用例：Socket.IO 接收端的消息分派与进程生命周期。

receiver 在 import 时就会建库、起 worker、创建 Socket.IO 客户端，因此所有用例
都先把 StateStore / RealtimePipeline 换成替身再加载模块，保证测试既不碰生产
state/realtime.db，也不会发起真实连接。

覆盖点：非法 payload 的两条早退、四种 push_type 各自的摘要分支、未知
push_type 的兜底，以及 main() 与 __main__ 入口的启动/清理路径。
"""

from __future__ import annotations

import importlib
import runpy
import sys
import unittest
from unittest.mock import MagicMock, patch

import socketio


def load_receiver():
    """在替身就位的前提下重新加载 receiver，返回 (module, store, pipeline)。"""
    store = MagicMock()
    store.enqueue_message.return_value = 1
    pipeline_cls = MagicMock()
    sys.modules.pop("lha_realtime.receiver", None)
    with patch("lha_realtime.state.StateStore", return_value=store), \
         patch("lha_realtime.pipeline.RealtimePipeline", pipeline_cls):
        module = importlib.import_module("lha_realtime.receiver")
    return module, store, pipeline_cls.return_value


class ReceiverTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.receiver, self.store, self.pipeline = load_receiver()

    def tearDown(self) -> None:
        sys.modules.pop("lha_realtime.receiver", None)


class OnPushTest(ReceiverTestBase):
    def test_handlers_are_registered_on_the_client(self) -> None:
        """回调函数已注册到 Socket.IO 客户端上。"""
        self.assertIsInstance(self.receiver.sio, socketio.Client)
        self.assertTrue(callable(self.receiver.on_push))

    def test_non_dict_message_is_dropped(self) -> None:
        """非字典消息（字符串/列表/None/数字）一律丢弃。"""
        for payload in ("a string", ["a", "list"], None, 42):
            with self.subTest(payload=payload):
                self.receiver.on_push(payload)
        self.store.enqueue_message.assert_not_called()

    def test_message_without_round_id_is_dropped(self) -> None:
        """缺少 round_id 的推送不入库。"""
        self.receiver.on_push({"push_type": "round_end"})
        self.store.enqueue_message.assert_not_called()

    def test_empty_round_id_is_treated_as_missing(self) -> None:
        """round_id 为空串等同缺失，不入库。"""
        self.receiver.on_push({"push_type": "round_end", "round_id": ""})
        self.store.enqueue_message.assert_not_called()

    def test_round_start_is_enqueued_verbatim(self) -> None:
        """round_start 原样入库，不在接收端做裁剪。"""
        payload = {
            "push_type": "round_start",
            "round_id": "r1",
            "push_time": "2026-06-16 10:00:00",
            "time_start": "2026-06-16 10:00:00",
            "session_key": "agent:main:main",
            "is_mock": False,
        }
        self.receiver.on_push(payload)
        self.store.enqueue_message.assert_called_once_with(payload)

    def test_round_end_summary_tolerates_missing_fields(self) -> None:
        # action_json / ir_json 缺失时 safe_len 返回 0，摘要日志不能抛异常。
        self.receiver.on_push({"push_type": "round_end", "round_id": "r1"})
        self.store.enqueue_message.assert_called_once()

    def test_round_end_with_full_payload(self) -> None:
        """字段齐全的 round_end 摘要日志与入库均正常。"""
        self.receiver.on_push(
            {
                "push_type": "round_end",
                "round_id": "r1",
                "overall_score": 0.8,
                "time_start": "t0",
                "time_end": "t1",
                "is_mock": True,
                "action_json": "[]",
                "ir_json": '{"policies": []}',
            }
        )
        self.store.enqueue_message.assert_called_once()

    def test_round_kernel_summary(self) -> None:
        """round_kernel 的内核文件路径摘要与入库。"""
        self.receiver.on_push(
            {
                "push_type": "round_kernel",
                "round_id": "r1",
                "kernel_syscall_seq": "/tmp/syscalls.jsonl",
                "kernel_lsm_hook_result": "/tmp/lsm.jsonl",
                "kernel_resource_facts": '{"resource_facts": []}',
            }
        )
        self.store.enqueue_message.assert_called_once()

    def test_round_ir_ready_summary(self) -> None:
        """round_ir_ready 的 IR 长度摘要与入库。"""
        self.receiver.on_push(
            {"push_type": "round_ir_ready", "round_id": "r1", "ir_json": '{"policies": []}'}
        )
        self.store.enqueue_message.assert_called_once()

    def test_unknown_push_type_is_still_persisted(self) -> None:
        # 接收端不做过滤：未知类型也入库，由 pipeline 决定忽略，避免丢消息。
        self.receiver.on_push({"push_type": "round_future", "round_id": "r1"})
        self.store.enqueue_message.assert_called_once()

    def test_missing_push_type_is_still_persisted(self) -> None:
        """没有 push_type 的消息同样入库，交由 pipeline 判断。"""
        self.receiver.on_push({"round_id": "r1"})
        self.store.enqueue_message.assert_called_once()


class ConnectionEventTest(ReceiverTestBase):
    def test_connect_and_disconnect_handlers_are_side_effect_free(self) -> None:
        """连接与断开回调只记日志，不产生数据副作用。"""
        self.receiver.connect()
        self.receiver.disconnect()
        self.store.enqueue_message.assert_not_called()


class MainTest(ReceiverTestBase):
    def test_main_starts_workers_then_connects_with_websocket_transport(self) -> None:
        """main 先起 worker 再按配置的 path/namespace 建立 websocket 连接。"""
        with patch.object(self.receiver.sio, "connect") as connect, \
             patch.object(self.receiver.sio, "wait") as wait:
            self.receiver.main()

        self.pipeline.start.assert_called_once()
        connect.assert_called_once()
        wait.assert_called_once()
        kwargs = connect.call_args.kwargs
        self.assertEqual(kwargs["transports"], ["websocket"])
        self.assertEqual(kwargs["namespaces"], [self.receiver.SETTINGS.namespace])
        self.assertEqual(kwargs["socketio_path"], self.receiver.SETTINGS.socketio_path)


class ScriptEntrypointTest(unittest.TestCase):
    """`python3 -m lha_realtime.receiver` 的 try/except/finally 清理路径。"""

    def run_as_main(self, wait_side_effect=None, connects: bool = True):
        store = MagicMock()
        pipeline_cls = MagicMock()

        def fake_connect(self, *args, **kwargs):
            self.connected = connects

        sys.modules.pop("lha_realtime.receiver", None)
        with patch("lha_realtime.state.StateStore", return_value=store), \
             patch("lha_realtime.pipeline.RealtimePipeline", pipeline_cls), \
             patch.object(socketio.Client, "connect", fake_connect), \
             patch.object(socketio.Client, "wait", side_effect=wait_side_effect or (lambda self: None), autospec=True), \
             patch.object(socketio.Client, "disconnect") as disconnect:
            runpy.run_module("lha_realtime.receiver", run_name="__main__")
        return store, pipeline_cls.return_value, disconnect

    def tearDown(self) -> None:
        sys.modules.pop("lha_realtime.receiver", None)

    def test_normal_exit_stops_pipeline_and_closes_the_store(self) -> None:
        """正常退出时停 worker、断开连接、关闭数据库。"""
        store, pipeline, disconnect = self.run_as_main()
        pipeline.start.assert_called_once()
        pipeline.stop.assert_called_once()
        disconnect.assert_called_once()
        store.close.assert_called_once()

    def test_keyboard_interrupt_still_runs_the_cleanup(self) -> None:
        """收到 Ctrl+C 中断时清理逻辑照常执行。"""
        def interrupt(self):
            raise KeyboardInterrupt

        store, pipeline, disconnect = self.run_as_main(wait_side_effect=interrupt)
        pipeline.stop.assert_called_once()
        disconnect.assert_called_once()
        store.close.assert_called_once()

    def test_cleanup_skips_disconnect_when_never_connected(self) -> None:
        """从未连上时跳过 disconnect，不产生多余调用。"""
        store, pipeline, disconnect = self.run_as_main(connects=False)
        pipeline.stop.assert_called_once()
        disconnect.assert_not_called()
        store.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
