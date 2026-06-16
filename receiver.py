#!/usr/bin/env python3
"""Compatibility entrypoint for the realtime LSM receiver service."""

from lha_realtime.receiver import main, pipeline, sio, store, log


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
