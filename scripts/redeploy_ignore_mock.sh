#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="lha_realtime.service"
PROJECT_DIR="/home/hx/try/lsm-hook-analysis-realtime"
PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"

cd "$PROJECT_DIR"

echo "[1/5] Installing Python dependencies..."
"$PYTHON_BIN" -m pip install -r requirements.txt

echo "[2/5] Removing existing systemd service if present..."
sudo systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
sudo rm -f "/etc/systemd/system/$SERVICE_NAME"
sudo systemctl daemon-reload
sudo systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true

echo "[3/5] Writing systemd service with LHA_PUSH_MOCK_REPORTS=0..."
sudo tee "/etc/systemd/system/$SERVICE_NAME" >/dev/null <<EOF
[Unit]
Description=LHA Realtime Socket.IO Receiver and Analyzer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$PROJECT_DIR
ExecStart=$PYTHON_BIN $PROJECT_DIR/receiver.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1
Environment=LHA_PUSH_MOCK_REPORTS=0

[Install]
WantedBy=multi-user.target
EOF

echo "[4/5] Starting service..."
sudo systemctl daemon-reload
sudo systemctl enable --now "$SERVICE_NAME"

echo "[5/5] Current service status:"
sudo systemctl status "$SERVICE_NAME" --no-pager
