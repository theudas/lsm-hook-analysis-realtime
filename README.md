# LSM Hook Realtime Analysis

实时版 LSM hook 分析服务。它会持续接收监控服务推送的 round 信息。每个 round 由四类消息组成——`round_start`、`round_end`、`round_kernel`、`round_ir_ready`，到达顺序不固定；服务会等这四类消息全部收齐后再启动分析，保证报告内容完整不为空，并把分析报告路径上报给后端接口。报告中包含“报告生成时间”。

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
- 重新等待四类消息 `round_start` / `round_end` / `round_kernel` / `round_ir_ready`。
- 四者全部到达后重新分析，并按配置决定是否上报。

## 8. 运行测试

跑全部单元测试：

```bash
cd /home/hx/try/lsm-hook-analysis-realtime
python3 -m unittest discover -s tests -v
```

### 8.1 覆盖率统计（白盒）

先装测试依赖（只多一个 `coverage`，生产运行不需要）：

```bash
python3 -m pip install -r requirements-dev.txt
```

统计语句 + 分支覆盖率，并生成可点开逐行查看的 HTML 报告：

```bash
python3 -m coverage run -m unittest discover -s tests
python3 -m coverage report      # 终端表格，带未覆盖行号
python3 -m coverage html        # 输出到 reports/coverage/html/index.html
```

统计口径写在 `.coveragerc` 里（`branch = True`，只统计 `lha_realtime` 包），
不需要在命令行重复指定参数。

当前基线：**295 个用例，语句覆盖 100%，分支覆盖 100%**。

### 8.2 测试文件分工

| 文件 | 覆盖对象 |
|---|---|
| `test_realtime_pipeline.py` | 端到端链路、乱序到达、重复 round、敏感分类回归 |
| `test_analyzer_parsing.py` | 输入加载、IR 解析、内核事件归并、网络端点回溯 |
| `test_analyzer_report.py` | `analysis_report.md` 的全部渲染分支 |
| `test_analyzer_push.py` | 上报 HTTP 链路的各种失败模式、mock round 识别 |
| `test_rules_loading.py` | `detection_rules.yaml` 加载容错、glob 编译 |
| `test_state_store.py` | SQLite schema 迁移、round/job 状态机流转 |
| `test_pipeline_internals.py` | 目录清理越界保护、消息分派早退、worker 生命周期 |
| `test_receiver.py` | Socket.IO 回调分派、进程启动与清理路径 |
| `test_config.py` | 环境变量解析与运行时目录准备 |
| `test_logging_utils.py` | 日志 handler 的重建与句柄释放 |

### 8.3 用例清单

全部 295 个用例逐条列在 `tests/TEST_CASES.md`，按测试文件 → 测试类 → 用例编号组织，
每条带验证点说明。该文件由测试源码解析生成，不手工维护；改动测试后重新生成：

```bash
cd /home/hx/try/lsm-hook-analysis-realtime
python3 scripts/gen_testcases.py
```

生成结果与 `unittest` 实际收集到的用例逐名对齐，可用于验收对照。

测试不会碰生产数据：所有用例都在临时目录里建库和落盘，`receiver` 的用例在
import 前就把 `StateStore` / `RealtimePipeline` 换成替身，也不会发起真实连接。

## 9. 项目结构

```text
lsm-hook-analysis-realtime/
├── lha_realtime/
│   ├── analyzer.py        # round 分析、报告生成、报告上报
│   ├── config.py          # 环境变量和默认路径配置
│   ├── detection_rules.yaml # 敏感资源分组与判定依据（改这里无需改代码）
│   ├── logging_utils.py   # 共享日志配置
│   ├── pipeline.py        # inbox 消费、落盘、分析 worker、重复 round 处理
│   ├── receiver.py        # Socket.IO 接收端
│   ├── rules.py           # 加载 detection_rules.yaml，编译敏感规则
│   └── state.py           # SQLite inbox、round state、analysis jobs
├── scripts/
│   ├── gen_testcases.py            # 生成 tests/TEST_CASES.md
│   ├── redeploy_ignore_mock.sh
│   └── redeploy_push_mock.sh
├── tests/
│   ├── TEST_CASES.md               # 全部用例清单（自动生成）
│   ├── test_realtime_pipeline.py   # 端到端链路与回归
│   ├── test_analyzer_parsing.py    # 解析与内核事件归并
│   ├── test_analyzer_report.py     # 报告渲染分支
│   ├── test_analyzer_push.py       # 上报链路失败模式
│   ├── test_rules_loading.py       # 规则加载与 glob 编译
│   ├── test_state_store.py         # SQLite 状态机
│   ├── test_pipeline_internals.py  # 落盘工具与 worker
│   ├── test_receiver.py            # Socket.IO 接收端
│   ├── test_config.py              # 环境变量解析
│   └── test_logging_utils.py       # 日志 handler 重建
├── receiver.py            # 兼容启动入口
├── .coveragerc            # 覆盖率统计口径
├── requirements.txt
├── requirements-dev.txt   # 测试依赖（coverage）
└── README.md
```
