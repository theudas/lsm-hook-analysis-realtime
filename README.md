# LSM Hook Realtime Analysis

实时版 LSM hook 分析服务。它会持续接收监控服务推送的 round 信息，收到完整 round 后立即分析，并把分析报告路径上报给后端接口。

## 1. 服务做什么

处理链路：

```text
Socket.IO push
  -> SQLite inbox
  -> input/<round_id>/ 文件落盘
  -> 分析 round
  -> 生成 analysis_report.md
  -> POST 上报报告路径
```

说明：

- SQLite 只保存消息状态、round 状态、任务状态和文件路径。
- 真实输入和输出文件保存在 `input/<round_id>/` 下。
- 同一个 `round_id` 再次到达时，会作为新的 round 重新处理。

## 2. 推荐部署方式

服务器部署建议直接使用一键脚本。两个脚本都会先删除已有的 `lha_realtime.service`，再重新部署并启动。

### 2.1 不上报 Mock Round

默认模式：`is_mock=true` 的 round 会分析并生成报告，但不会上报。

```bash
cd /home/hx/try/lsm-hook-analysis-realtime
bash scripts/redeploy_ignore_mock.sh
```

### 2.2 上报 Mock Round

测试模式：`is_mock=true` 的 round 也会分析并上报。

```bash
cd /home/hx/try/lsm-hook-analysis-realtime
bash scripts/redeploy_push_mock.sh
```

脚本执行完后，systemd 服务名是：

```text
lha_realtime.service
```

## 3. 常用运维命令

查看服务状态：

```bash
systemctl status lha_realtime.service
```

查看 systemd 实时日志：

```bash
journalctl -u lha_realtime.service -f
```

重启服务：

```bash
sudo systemctl restart lha_realtime.service
```

停止服务：

```bash
sudo systemctl stop lha_realtime.service
```

查看本地日志：

```bash
cd /home/hx/try/lsm-hook-analysis-realtime
tail -f logs/receiver.log
tail -f logs/pipeline.log
tail -f logs/analyzer.log
```

## 4. 本地调试

如果只是临时调试，不想注册 systemd 服务，可以前台启动：

```bash
cd /home/hx/try/lsm-hook-analysis-realtime
python3 -m pip install -r requirements.txt
python3 -m lha_realtime.receiver
```

也可以使用兼容入口：

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

## 5. 手动 Systemd 部署

通常直接用第 2 节的一键脚本即可。需要手动部署时，可以按下面步骤操作。

### 5.1 写入 Service 文件

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

### 5.2 启动 Service

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now lha_realtime.service
```

### 5.3 删除旧 Service

```bash
sudo systemctl disable --now lha_realtime.service
sudo rm -f /etc/systemd/system/lha_realtime.service
sudo systemctl daemon-reload
sudo systemctl reset-failed lha_realtime.service
```

## 6. 配置项

常用环境变量：

- `LHA_SERVER_URL`：Socket.IO 服务地址，默认 `ws://8.152.192.7:15100`
- `LHA_SOCKETIO_PATH`：Socket.IO path，默认 `/wss`
- `LHA_NAMESPACE`：Socket.IO namespace，默认 `/wss/monitor`
- `LHA_INPUT_DIR`：round 输入和分析输出目录，默认 `./input`
- `LHA_DB_PATH`：SQLite 状态库路径，默认 `./state/realtime.db`
- `LHA_KERNEL_REPORT_URL`：报告上报接口，默认 `$LHA_API_BASE_URL/api/rounds/detection/kernel`
- `LHA_PUSH_MOCK_REPORTS`：是否上报 `is_mock=true` 的 round，默认 `0`，设置 `1` 后上报
- `LHA_ANALYZER_WORKERS`：分析 worker 数量，默认 `1`
- `LHA_MAX_ATTEMPTS`：失败重试次数，默认 `3`

## 7. 重复 Round 的处理

测试阶段可能重复收到同一个 `round_id`。当前策略是把它当成新的 round：

- 取消旧的未完成分析任务。
- 清理 `input/<round_id>/` 下旧的输入、内核 JSONL、分析报告和上报 marker。
- 重新等待 `round_end` 和 `round_kernel`。
- 两者都到达后重新分析，并按配置决定是否上报。

## 8. 运行测试

```bash
cd /home/hx/try/lsm-hook-analysis-realtime
python3 -m unittest discover -s tests -v
```

## 9. 项目结构

```text
lsm-hook-analysis-realtime/
├── lha_realtime/
│   ├── analyzer.py        # round 分析、报告生成、报告上报
│   ├── config.py          # 环境变量和默认路径配置
│   ├── logging_utils.py   # 共享日志配置
│   ├── pipeline.py        # inbox 消费、落盘、分析 worker、重复 round 处理
│   ├── receiver.py        # Socket.IO 接收端
│   └── state.py           # SQLite inbox、round state、analysis jobs
├── scripts/
│   ├── redeploy_ignore_mock.sh
│   └── redeploy_push_mock.sh
├── tests/
│   └── test_realtime_pipeline.py
├── receiver.py            # 兼容启动入口
├── requirements.txt
└── README.md
```
