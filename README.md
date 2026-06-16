# LSM Hook Realtime Analysis

实时版 LSM hook 分析服务，复用 `lsm-hook-analysis-v2` 的 round 输入格式、分析报告格式和内核报告上报接口，但把原来的 cron 批处理改成常驻流水线：

1. `lha_realtime/receiver.py` 监听 Socket.IO `push` 事件。
2. 接收回调把原始消息快速写入 SQLite inbox。
3. 后台 ingest worker 将 `round_end` / `round_kernel` 写入 `input/<round_id>/`，并拷贝内核 JSONL 文件。
4. round 同时具备 `round_end.json` 和 `round_kernel.json` 后进入分析队列。
5. analyze worker 生成 `analysis_violations.jsonl` / `analysis_report.md`，并上报报告路径。

SQLite 只保存控制数据：消息状态、round generation、文件路径、分析任务状态、错误和重试次数。JSON/JSONL 输入文件和 Markdown 报告仍保存在文件系统中。

## Run

首次运行先安装依赖：

```bash
cd /home/hx/try/lsm-hook-analysis-realtime
python3 -m pip install -r requirements.txt
```

前台测试启动，适合调试时直接看日志：

```bash
cd /home/hx/try/lsm-hook-analysis-realtime
python3 -m lha_realtime.receiver
```

也可以继续使用兼容入口：

```bash
cd /home/hx/try/lsm-hook-analysis-realtime
python3 receiver.py
```

临时后台启动：

```bash
cd /home/hx/try/lsm-hook-analysis-realtime
mkdir -p logs
nohup python3 receiver.py > logs/service.out 2>&1 &
```

查看本地日志：

```bash
tail -f logs/receiver.log
tail -f logs/pipeline.log
tail -f logs/analyzer.log
```

## systemd 部署

建议服务器长期运行时使用 systemd：

```bash
sudo tee /etc/systemd/system/lha_realtime.service >/dev/null <<'EOF'
[Unit]
Description=LHA Realtime Socket.IO Receiver and Analyzer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/hx/try/lsm-hook-analysis-realtime
ExecStart=/usr/bin/python3 /home/hx/try/lsm-hook-analysis-realtime/receiver.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1
# 测试阶段如需上报 is_mock=true 的 round，可取消下一行注释。
# Environment=LHA_PUSH_MOCK_REPORTS=1

[Install]
WantedBy=multi-user.target
EOF
```

启动并设置开机自启：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now lha_realtime.service
```

查看状态和实时日志：

```bash
systemctl status lha_realtime.service
journalctl -u lha_realtime.service -f
```

重启或停止：

```bash
sudo systemctl restart lha_realtime.service
sudo systemctl stop lha_realtime.service
```

## 删除已有服务并重新部署

项目提供两个一键重部署脚本，都会先删除已有 `lha_realtime.service`，再重新写入 service 文件并启动。

不处理 mock round（默认，`is_mock=true` 只分析不上报）：

```bash
cd /home/hx/try/lsm-hook-analysis-realtime
bash scripts/redeploy_ignore_mock.sh
```

处理 mock round（设置 `LHA_PUSH_MOCK_REPORTS=1`，`is_mock=true` 也会上报）：

```bash
cd /home/hx/try/lsm-hook-analysis-realtime
bash scripts/redeploy_push_mock.sh
```

如果之前已经创建过 `lha_realtime.service`，可以先彻底删除旧服务：

```bash
sudo systemctl disable --now lha_realtime.service
sudo rm -f /etc/systemd/system/lha_realtime.service
sudo systemctl daemon-reload
sudo systemctl reset-failed lha_realtime.service
```

确认旧服务已不存在：

```bash
systemctl status lha_realtime.service
```

然后重新执行上面的 systemd 部署步骤，重新写入 `/etc/systemd/system/lha_realtime.service`，再启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now lha_realtime.service
```

Useful environment variables:

- `LHA_SERVER_URL` defaults to `ws://8.152.192.7:15100`
- `LHA_SOCKETIO_PATH` defaults to `/wss`
- `LHA_NAMESPACE` defaults to `/wss/monitor`
- `LHA_INPUT_DIR` defaults to `./input`
- `LHA_DB_PATH` defaults to `./state/realtime.db`
- `LHA_KERNEL_REPORT_URL` defaults to `$LHA_API_BASE_URL/api/rounds/detection/kernel`
- `LHA_PUSH_MOCK_REPORTS` defaults to `0`; set to `1` to push reports for `is_mock=true` rounds
- `LHA_ANALYZER_WORKERS` defaults to `1`
- `LHA_MAX_ATTEMPTS` defaults to `3`

## Duplicate Round Behavior

测试阶段如果再次收到已经处理过的 `round_id`，服务会把它作为新的 generation：

- 取消旧的未完成分析任务。
- 清理 `input/<round_id>/` 下旧的 round 输入、内核 JSONL、分析报告和上报 marker。
- 重新等待 `round_end` 与 `round_kernel`，再分析并上报。

同一 generation 内，`round_end` 和 `round_kernel` 可以任意先后到达；只有两者都到达后才会触发分析。

## Tests

```bash
cd /home/hx/try/lsm-hook-analysis-realtime
python3 -m unittest discover -s tests -v
```

## Project Layout

```text
lsm-hook-analysis-realtime/
├── lha_realtime/
│   ├── analyzer.py        # round 分析、报告生成、报告上报
│   ├── config.py          # 环境变量和默认路径配置
│   ├── logging_utils.py   # 共享日志配置
│   ├── pipeline.py        # inbox 消费、落盘、分析 worker、重复 round 处理
│   ├── receiver.py        # Socket.IO 接收端
│   └── state.py           # SQLite inbox、round state、analysis jobs
├── tests/
│   └── test_realtime_pipeline.py
├── receiver.py            # 兼容启动入口
├── requirements.txt
└── README.md
```
