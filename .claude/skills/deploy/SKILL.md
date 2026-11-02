---
name: deploy
description: 全新部署、重装或换机迁移 lha_realtime 实时分析服务时使用：venv 依赖安装、.env 配置（服务器地址必改项）、前台验证、systemd 注册、启动后验证清单、一键脚本适用边界与常见坑。
---

# 部署 lha_realtime 服务

本 skill 把本项目部署成常驻 systemd 服务：装依赖 → 写 `.env` → 前台验证 → 注册 systemd → 验证。本文件是部署的唯一权威规程，日常运维见 `README.md`。

## 0. 开工前先确认两件事

1. **目标服务器地址**：Socket.IO / API 是否就是默认的 `8.152.192.7:15100`。不是 → **必须写 `.env`**。代码在 `lha_realtime/config.py` 里内置了这个默认地址，不配置不会报错，而是**静默连默认地址**。
2. **mock round 是否上报**：默认不上报（`LHA_PUSH_MOCK_REPORTS=0`，只分析）；测试模式才设 1。

前置条件：Linux + systemd + root/sudo；Python ≥ 3.9；安装路径不含空格；能访问 Socket.IO 服务和报告上报接口。

## 1. 标准部署（任何服务器，推荐）

### 1.1 安装依赖

```bash
cd <项目根目录>
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
```

依赖只有 `python-socketio[client]` 和 `PyYAML`。系统缺 `venv` 时先装（Debian/Ubuntu：`python3-venv`）。

### 1.2 写 `.env`（项目根目录）

```bash
cat > .env <<'EOF'
LHA_SERVER_URL=ws://<IP>:15100
LHA_SOCKETIO_PATH=/wss
LHA_NAMESPACE=/wss/monitor
LHA_API_BASE_URL=http://<IP>:15100
LHA_KERNEL_REPORT_URL=http://<IP>:15100/api/rounds/detection/kernel

# 0：mock round 只分析不上报；1：也上报
LHA_PUSH_MOCK_REPORTS=0
LHA_ANALYZER_WORKERS=1
LHA_MAX_ATTEMPTS=3
LHA_RETRY_BACKOFF_SECONDS=10
EOF
chmod 600 .env
```

把 `<IP>` 换成实际服务器地址。连接默认服务器时可省略此步（但写了更明确）。

### 1.3 前台验证（再上 systemd 之前必做）

```bash
set -a
. ./.env
set +a
.venv/bin/python receiver.py
```

成功标志：控制台 / `logs/receiver.log` 出现 Socket.IO 连接成功或「收到 push」日志。确认后 `Ctrl+C` 退出。注意区分「进程启动了」和「连上了」——连不上时客户端会无限重连，进程看起来一直活着。

### 1.4 注册 systemd（动态路径版）

```bash
PROJECT_DIR="$(pwd -P)"

sudo tee /etc/systemd/system/lha_realtime.service >/dev/null <<EOF
[Unit]
Description=LSM Hook Realtime Analysis
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${PROJECT_DIR}
EnvironmentFile=${PROJECT_DIR}/.env
Environment=PYTHONUNBUFFERED=1
ExecStart=${PROJECT_DIR}/.venv/bin/python ${PROJECT_DIR}/receiver.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now lha_realtime.service
```

### 1.5 部署后验证清单（逐项确认）

```bash
sudo systemctl status lha_realtime.service --no-pager   # active (running)
sudo journalctl -u lha_realtime.service -f              # 连接正常、无循环报错
tail -f logs/receiver.log                               # 收到 push / round 处理日志
ls -l input state logs                                  # 自动创建，无需手工建
```

可选：`.venv/bin/python -m unittest discover -s tests -t .`（历史样本回归用例缺样本时自动跳过，属正常）。

## 2. 环境变量清单

**换服务器必改**（三个 URL 里的 IP 必须一致）：

| 变量 | 默认值 | 说明 |
|---|---|---|
| `LHA_SERVER_URL` | `ws://8.152.192.7:15100` | Socket.IO 服务地址 |
| `LHA_API_BASE_URL` | `http://8.152.192.7:15100` | 后端 API 基地址 |
| `LHA_KERNEL_REPORT_URL` | `<API_BASE>/api/rounds/detection/kernel` | 报告上报接口 |

**通常不动**：`LHA_SOCKETIO_PATH`（`/wss`）、`LHA_NAMESPACE`（`/wss/monitor`）。

**行为开关**：`LHA_PUSH_MOCK_REPORTS`（0/1，见第 0 节）、`LHA_ANALYZER_WORKERS`（分析并发，默认 1）、`LHA_MAX_ATTEMPTS` / `LHA_RETRY_BACKOFF_SECONDS`（上报重试）、`LHA_KERNEL_REPORT_PUSH_TIMEOUT`（上报超时，默认 900s）、`LHA_INGEST_POLL_INTERVAL` / `LHA_ANALYSIS_POLL_INTERVAL`（轮询间隔，默认 0.02s）。

**看门狗与保留**（stale round 告警/归档）：`LHA_STALE_ROUND_HOURS`（24）、`LHA_STALE_WARN_MINUTES`（30）、`LHA_STALE_SCAN_MINUTES`（5）、`LHA_MESSAGE_RETENTION_DAYS`（30）；设 0 关闭对应动作。

**目录覆盖**（默认都在项目根目录下）：`LHA_INPUT_DIR`、`LHA_LOG_DIR`、`LHA_STATE_DIR`、`LHA_DB_PATH`（`state/realtime.db`）、`LHA_STALE_ARCHIVE_DIR`、`LHA_RULES_PATH`（默认 `lha_realtime/detection_rules.yaml`，语义见 detection-rules skill）。

## 3. 一键脚本（只适合默认服务器）

```bash
bash scripts/redeploy_ignore_mock.sh   # mock 不上报（生产行为）
bash scripts/redeploy_push_mock.sh      # mock 也上报（测试模式）
```

适用边界与坑：

- **unit 文件不读 `.env`**，只设置 `LHA_PUSH_MOCK_REPORTS`——服务器地址完全靠 `config.py` 内置默认值（`8.152.192.7`）。**换服务器不要用一键脚本**，走第 1 节。
- 用系统 Python（`/usr/bin/python3`，可用 `PYTHON_BIN` 环境变量覆盖），依赖装进系统 Python，不建 venv。
- 每次执行都先删掉已有服务再重建，等价于重启；已在运行的生产服务不要随手重跑。
- 安装路径按脚本自身位置动态推算，克隆到任何目录都能用。

## 4. 常见坑

- **服务正常但收不到消息**：九成是没配 `.env`，静默连了默认 `8.152.192.7`。查 `journalctl` 里的连接地址。
- **升级保留状态**：备份 `input/`、`state/`、`logs/`（SQLite 状态库在 `state/`）。**全新部署不要从旧环境拷这些目录**。
- systemd 的 `WorkingDirectory` / `ExecStart` 必须绝对路径，用 `$(pwd -P)` 展开，别手写相对路径。
- `.env` 权限 600；安装路径不要含空格。
- 同一个 `round_id` 再次到达会作为新 round 重新处理，属预期行为。

## 5. 卸载

```bash
sudo systemctl disable --now lha_realtime.service
sudo rm -f /etc/systemd/system/lha_realtime.service
sudo systemctl daemon-reload
sudo systemctl reset-failed lha_realtime.service
```

## 6. 维护约定

改动部署方式、新增环境变量时，同步更新 `lha_realtime/config.py`、`README.md` 和本 skill，不一致时以 `config.py` 实际实现为准。
