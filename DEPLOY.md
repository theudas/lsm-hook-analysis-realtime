# LSM Hook Realtime Analysis 部署说明

本文适用于源码包的全新部署。源码包不包含历史 `input/`、`logs/`、`state/`、`reports/` 数据；服务首次启动时会自动创建所需运行目录和 SQLite 状态库。

## 1. 环境要求

- Linux（使用 systemd 时需要 systemd）
- Python 3.9 或更高版本
- 可访问 Socket.IO 服务和报告上报接口
- 使用 systemd 部署时需要 root 或 sudo 权限

## 2. 解压与安装

将压缩包放到任意安装目录后执行：

```bash
unzip lsm-hook-analysis-realtime-source-20260720.zip
cd lsm-hook-analysis-realtime

python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
```

后续命令均在项目根目录执行。安装目录不要包含空格。如果系统未安装 `venv` 或 `unzip`，请先通过系统包管理器安装。

## 3. 配置

建议将环境变量保存在项目根目录的 `.env` 文件中：

> 以下配置以服务器 IP `8.152.192.7` 为例。部署到其他服务器或环境时，必须将该 IP 替换为实际的 Socket.IO 和 API 服务地址。

```bash
cat > .env <<'EOF'
LHA_SERVER_URL=ws://8.152.192.7:15100
LHA_SOCKETIO_PATH=/wss
LHA_NAMESPACE=/wss/monitor
LHA_API_BASE_URL=http://8.152.192.7:15100
LHA_KERNEL_REPORT_URL=http://8.152.192.7:15100/api/rounds/detection/kernel

# 0：mock round 只分析不上报；1：也上报 mock round
LHA_PUSH_MOCK_REPORTS=0
LHA_ANALYZER_WORKERS=1
LHA_MAX_ATTEMPTS=3
LHA_RETRY_BACKOFF_SECONDS=10
EOF

chmod 600 .env
```

请按实际环境修改服务地址。默认情况下，`input/`、`logs/`、`state/` 均创建在项目根目录，无需填写绝对路径。也可以通过以下变量改为其他位置：

- `LHA_INPUT_DIR`：round 输入和分析输出目录
- `LHA_LOG_DIR`：应用日志目录
- `LHA_STATE_DIR`：状态目录
- `LHA_DB_PATH`：SQLite 状态库文件
- `LHA_RULES_PATH`：自定义检测规则 YAML；默认使用 `lha_realtime/detection_rules.yaml`
- `LHA_KERNEL_REPORT_PUSH_TIMEOUT`：报告上报超时秒数，默认 `900`
- `LHA_INGEST_POLL_INTERVAL`：消息消费轮询间隔，默认 `0.02`
- `LHA_ANALYSIS_POLL_INTERVAL`：分析任务轮询间隔，默认 `0.02`

## 4. 前台验证

```bash
set -a
. ./.env
set +a
.venv/bin/python receiver.py
```

确认服务能够连接后按 `Ctrl+C` 退出，再配置 systemd。

## 5. Systemd 部署

下面的命令会自动读取当前项目目录，并将实际路径写入 systemd 服务，无需手工修改路径：

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
sudo systemctl status lha_realtime.service --no-pager
```

项目自带的一键部署脚本包含固定的安装路径。跨机器部署时请使用本文的动态路径方式。

## 6. 运维

```bash
# 查看实时日志
sudo journalctl -u lha_realtime.service -f

# 重启或停止
sudo systemctl restart lha_realtime.service
sudo systemctl stop lha_realtime.service

# 查看应用日志
ls -l logs
```

运行数据目录：

- `input/`：每个 round 的输入文件和分析结果
- `state/`：SQLite 状态库
- `logs/`：应用日志
- `reports/`：预留报告目录

升级前如需保留任务状态和分析记录，请备份以上目录。全新部署不应从旧环境复制这些目录。

## 7. 测试

```bash
.venv/bin/python -m unittest discover -s tests -v
```

测试中的历史样本回归用例在样本不存在时会自动跳过，不影响全新源码包部署。

## 8. 卸载服务

```bash
sudo systemctl disable --now lha_realtime.service
sudo rm -f /etc/systemd/system/lha_realtime.service
sudo systemctl daemon-reload
sudo systemctl reset-failed lha_realtime.service
```
