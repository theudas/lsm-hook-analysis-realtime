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

一键脚本只适合默认服务器（`8.152.192.7:15100`）：unit 文件不读 `.env`，服务器地址完全依赖 `config.py` 的内置默认值；脚本还会把依赖装进系统 Python（不建 venv）。**换服务器部署不要用一键脚本**，走第 5 节手动部署（`.env` + `EnvironmentFile`），或按 `.claude/skills/deploy/SKILL.md` 的标准流程操作。

### 2.1 不上报 Mock Round

默认模式：`is_mock=true` 的 round 会分析并生成报告，但不会上报。

```bash
cd lsm-hook-analysis-realtime
bash scripts/redeploy_ignore_mock.sh
```

### 2.2 上报 Mock Round

测试模式：`is_mock=true` 的 round 也会分析并上报。

```bash
cd lsm-hook-analysis-realtime
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
cd lsm-hook-analysis-realtime
tail -f logs/receiver.log
tail -f logs/pipeline.log
tail -f logs/analyzer.log
tail -f logs/watchdog.log
```

## 4. 本地调试

如果只是临时调试，不想注册 systemd 服务，可以前台启动：

```bash
cd lsm-hook-analysis-realtime
python3 -m pip install -r requirements.txt
python3 -m lha_realtime.receiver
```

也可以使用兼容入口：

```bash
cd lsm-hook-analysis-realtime
python3 receiver.py
```

临时后台启动：

```bash
cd lsm-hook-analysis-realtime
mkdir -p logs
nohup python3 receiver.py > logs/service.out 2>&1 &
```

## 5. 手动 Systemd 部署

通常直接用第 2 节的一键脚本即可。需要手动部署时，可以按下面步骤操作。

### 5.1 写入 Service 文件

systemd 要求 `WorkingDirectory` 和 `ExecStart` 用绝对路径，把下面的 `/path/to/lsm-hook-analysis-realtime` 替换成实际部署路径。`EnvironmentFile` 指向 `.env`（创建方式见 `.claude/skills/deploy/SKILL.md` 第 1.2 节，权限 600），第 6 节的环境变量都写在里面；测试阶段如需上报 `is_mock=true` 的 round，在 `.env` 里设 `LHA_PUSH_MOCK_REPORTS=1`：

```bash
sudo tee /etc/systemd/system/lha_realtime.service >/dev/null <<'EOF'
[Unit]
Description=LHA Realtime Socket.IO Receiver and Analyzer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/path/to/lsm-hook-analysis-realtime
EnvironmentFile=/path/to/lsm-hook-analysis-realtime/.env
ExecStart=/path/to/lsm-hook-analysis-realtime/.venv/bin/python /path/to/lsm-hook-analysis-realtime/receiver.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
```

`ExecStart` 用 venv 里的解释器：先按第 4 节装好依赖（`python3 -m venv .venv` + `.venv/bin/python -m pip install -r requirements.txt`）。机器上没有 venv、坚持用系统 Python 时，把 `ExecStart` 换回 `/usr/bin/python3`。

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

常用环境变量（systemd 部署经 unit 的 `EnvironmentFile` 读取 `.env`，前台运行用 `set -a; . ./.env; set +a`）：

- `LHA_SERVER_URL`：Socket.IO 服务地址，默认 `ws://8.152.192.7:15100`
- `LHA_SOCKETIO_PATH`：Socket.IO path，默认 `/wss`
- `LHA_NAMESPACE`：Socket.IO namespace，默认 `/wss/monitor`
- `LHA_INPUT_DIR`：round 输入和分析输出目录，默认 `./input`
- `LHA_DB_PATH`：SQLite 状态库路径，默认 `./state/realtime.db`
- `LHA_KERNEL_REPORT_URL`：报告上报接口，默认 `$LHA_API_BASE_URL/api/rounds/detection/kernel`
- `LHA_PUSH_MOCK_REPORTS`：是否上报 `is_mock=true` 的 round，默认 `0`，设置 `1` 后上报
- `LHA_ANALYZER_WORKERS`：分析 worker 数量，默认 `1`
- `LHA_MAX_ATTEMPTS`：失败重试次数，默认 `3`
- `LHA_STALE_WARN_MINUTES`：round 停在 receiving 多久后告警，默认 `30`，设 `0` 关闭
- `LHA_STALE_ROUND_HOURS`：多久未收齐后归档，默认 `24`，设 `0` 关闭
- `LHA_STALE_SCAN_MINUTES`：看门狗扫描间隔（分钟），默认 `5`
- `LHA_STALE_ARCHIVE_DIR`：过期 round 归档目录，默认 `./stale_archive`
- `LHA_MESSAGE_RETENTION_DAYS`：已完成消息行的保留天数，默认 `30`，设 `0` 关闭

## 7. 重复 Round 的处理

测试阶段可能重复收到同一个 `round_id`。当前策略是把它当成新的 round：

- 取消旧的未完成分析任务。
- 清理 `input/<round_id>/` 下旧的输入、内核 JSONL、分析报告和上报 marker。
- 重新等待四类消息 `round_start` / `round_end` / `round_kernel` / `round_ir_ready`。
- 四者全部到达后重新分析，并按配置决定是否上报。

## 7.1 内核行为豁免建议（热力图）

用来及时发现可以加入豁免的高频内核行为（在项目根目录执行）：

```bash
python3 scripts/hotspot_stats.py           # 生成静态文件 reports/hotspot.html，浏览器直接打开
```

- 只看内核侧事实（hook、读写动作、路径、端点），不看工具调用与 IR。已被 `system_baseline` / 忽略端点豁免的操作先排除。
- “豁免建议”列出出现在 ≥ 20% round（`--threshold` 可调）的行为，逐项给出 建议豁免 / 需人工确认 / 不建议 及依据；
  前两档附可展开的 YAML 片段，确认后合入 `detection_rules.yaml`，重新运行脚本即可看到它被折叠。
- 判定口径：敏感命中、观测到写入/创建/删除、位于 `/tmp`、`/home`、`/root` 等用户可写目录 → 不建议；
  含 `bprm_check`、未归为 runtime、本机 Unix socket 或回环端点 → 需人工确认；系统目录下的只读 runtime 行为、写终端/空设备 → 建议。
  非本机网络地址不给配置，是否放行由人决定。
- 每次运行都会读最新的规则文件和 `input/` 下新到的 round；要看最新数据就重新运行脚本。

## 7.2 看门狗：收不齐 round 的告警与归档

四类消息正常几秒到几分钟内收齐。一个 round 长时间停在 receiving，或 `input/` 里留着没有状态行的
半成品目录，都说明上游采集或推送出了问题。`pipeline` 启动时会拉起一个看门狗线程，默认每 5 分钟扫一轮，
日志在 `logs/watchdog.log`：

- 超过 `LHA_STALE_WARN_MINUTES` 未收齐：记一条 WARNING，指明该 round 等了多久、还缺哪些消息。
  同一个 round 在同一次 `updated_at` 上只告警一次；来了新消息会重新计时，再次超时会再告警。
- 超过 `LHA_STALE_ROUND_HOURS` 未收齐：`input/<round_id>/` 移到归档目录并删除状态行。
  之后同一 `round_id` 再来消息会作为全新 round 从头收集，数据不丢。每轮发生过期都会在归档目录写一份
  `manifest_<时间戳>.json`，记录每个 round 等了多久、缺哪些消息、被移到了哪里，便于事后对账。
- 只处理 `receiving` 状态的 round 与 `input/` 下没有状态行的未收齐目录；磁盘上六类输入齐全的 round
  永不归档也不告警——语料回放依赖它们。
- 顺带清理超过 `LHA_MESSAGE_RETENTION_DAYS` 的已完成消息行（仅审计用途）。

三个阈值（告警、过期、消息清理）都设 `0` 可分别关闭对应动作；全为 `0` 时看门狗线程不启动。

## 7.3 采集完整度看板

按时间维度盘点收齐 / 收不齐的比例，把“上游采集不完整”从事后盘点提前到随时可看（在项目根目录执行）：

```bash
python3 scripts/completeness_stats.py           # 生成静态文件 reports/completeness.html，浏览器直接打开
```

- 与看门狗共用同一套“收齐”口径（五类文件 + 可用 IR），看板、归档、就绪门控三者的判定不漂移。
- 时间范围可选预设（近 1 小时 / 1 天 / 7 天 / 30 天）或自定义起止；分桶粒度按跨度自动选（小时 / 天 / 周）。
- 主图按时间桶展示收齐（灰）与收不齐（红）的数量对比，悬停可看每桶明细；下方给缺失模式排行
  （缺 `round_end`、缺内核数据文件等）与收不齐的 round 示例（最新在前，含缺失清单与等待时长）。
- 要看最新数据就重新运行脚本；产物是自包含 HTML，浏览器直接打开即可。

## 8. 运行测试

跑全部单元测试：

```bash
cd lsm-hook-analysis-realtime
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

当前基线：**420 个用例，语句覆盖 100%，分支覆盖 100%**。

### 8.2 测试文件分工

| 文件 | 覆盖对象 |
|---|---|
| `test_realtime_pipeline.py` | 端到端链路、乱序到达、重复 round、敏感分类回归 |
| `test_analyzer_parsing.py` | 输入加载、IR 解析、内核事件归并、网络端点回溯 |
| `test_analyzer_report.py` | `analysis_report.md` 的全部渲染分支 |
| `test_analyzer_push.py` | 上报 HTTP 链路的各种失败模式、mock round 识别 |
| `test_collector_filter.py` | collector stdio 收发按工具授权区分过滤 |
| `test_collection_status.py` | 空内核流标采集异常、connect 无收发标可疑 |
| `test_rules_loading.py` | `detection_rules.yaml` 加载容错、glob 编译 |
| `test_system_baseline.py` | `system_baseline` 折叠边界、按端点的网络判定 |
| `test_hotspot_stats.py` | 豁免建议的判定边界、生成 YAML 的折叠效果 |
| `test_completeness_stats.py` | 收齐口径的扫描分类、时间分桶、看板页面渲染 |
| `test_state_store.py` | SQLite schema 迁移、round/job 状态机流转 |
| `test_pipeline_internals.py` | 目录清理越界保护、消息分派早退、worker 生命周期 |
| `test_stale_rounds.py` | 超时告警去重、过期归档与 manifest、孤儿目录扫描、消息清理 |
| `test_receiver.py` | Socket.IO 回调分派、进程启动与清理路径 |
| `test_config.py` | 环境变量解析与运行时目录准备 |
| `test_logging_utils.py` | 日志 handler 的重建与句柄释放 |

### 8.3 用例清单

全部 420 个用例逐条列在 `tests/TEST_CASES.md`，按测试文件 → 测试类 → 用例编号组织，
每条带验证点说明。该文件由测试源码解析生成，不手工维护；改动测试后重新生成：

```bash
cd lsm-hook-analysis-realtime
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
│   ├── detection_rules.yaml # 敏感资源分组、系统基线折叠与判定依据（改这里无需改代码）
│   ├── logging_utils.py   # 共享日志配置
│   ├── pipeline.py        # inbox 消费、落盘、分析 worker、重复 round 处理
│   ├── receiver.py        # Socket.IO 接收端
│   ├── rules.py           # 加载 detection_rules.yaml，编译敏感规则
│   ├── state.py           # SQLite inbox、round state、analysis jobs
│   └── watchdog.py        # 收不齐 round 的超时告警、过期归档与消息清理
├── scripts/
│   ├── bench_replay.py              # 全量语料回放性能基准（单 round 耗时分布、吞吐与语料统计）
│   ├── collect_case_evidence.py    # 逐条采集测试报告用例的执行证据
│   ├── completeness_stats.py        # 采集完整度看板（收齐比例、缺失模式、示例，生成静态 HTML）
│   ├── completeness_template.html   # 看板页面模板
│   ├── eval_metrics.py              # GT 标注回放评测：四指标与相对基线的翻转明细
│   ├── gen_testcases.py            # 生成 tests/TEST_CASES.md
│   ├── hotspot_stats.py            # 语料重放 → 内核行为豁免建议页面（生成静态 HTML）
│   ├── hotspot_template.html       # 页面模板
│   ├── loadtest.py                  # 负载测试：真实 ingest/分析 worker 并发压测（不经 Socket.IO）
│   ├── prune_invalid_rounds.py     # 把 input/ 下无法完整分析的 round 移到归档目录
│   ├── redeploy_ignore_mock.sh
│   ├── redeploy_push_mock.sh
│   └── signal_attribution.py       # 信号归因与对抗评测（四层判据承重分析、伪装逃逸量化）
├── tests/
│   ├── TEST_CASES.md               # 全部用例清单（自动生成）
│   ├── test_realtime_pipeline.py   # 端到端链路与回归
│   ├── test_analyzer_parsing.py    # 解析与内核事件归并
│   ├── test_analyzer_report.py     # 报告渲染分支
│   ├── test_analyzer_push.py       # 上报链路失败模式
│   ├── test_collector_filter.py    # 采集器 stdio 通道过滤
│   ├── test_collection_status.py   # 采集完整性自检
│   ├── test_completeness_stats.py  # 采集完整度看板
│   ├── test_rules_loading.py       # 规则加载与 glob 编译
│   ├── test_system_baseline.py     # 系统基线折叠与网络端点判定
│   ├── test_hotspot_stats.py       # 豁免建议判定与 YAML 片段
│   ├── test_state_store.py         # SQLite 状态机
│   ├── test_pipeline_internals.py  # 落盘工具与 worker
│   ├── test_stale_rounds.py        # 看门狗：告警、归档、孤儿扫描
│   ├── test_receiver.py            # Socket.IO 接收端
│   ├── test_config.py              # 环境变量解析
│   └── test_logging_utils.py       # 日志 handler 重建
├── receiver.py            # 兼容启动入口
├── .coveragerc            # 覆盖率统计口径
├── requirements.txt
├── requirements-dev.txt   # 测试依赖（coverage）
└── README.md
```
