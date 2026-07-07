#!/usr/bin/env python3
"""检测规则加载：从 detection_rules.yaml 读取敏感/运行时文件定义与忽略网络端点。

规则文件缺失或某个键为空时，回退到内置默认值，保证服务始终可运行。
可通过环境变量 LHA_RULES_PATH 指定其他 YAML 路径。
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml


PACKAGE_DIR = Path(__file__).parent
DEFAULT_RULES_PATH = PACKAGE_DIR / "detection_rules.yaml"


# 内置默认值：当 YAML 缺失或对应键为空时使用，与 detection_rules.yaml 的意图保持一致。
_DEFAULT_SENSITIVE_PREFIXES = (
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/var/log/secure",
    "/var/log/audit",
    "/root/.ssh",
    "/root/.aws",
    "/root/.config/gcloud",
    "/root/.docker/config.json",
    "/root/.kube/config",
    "/root/.openclaw",
    "/run/secrets",
)
_DEFAULT_SENSITIVE_GLOBS = (
    "/proc/*/environ",
    "/proc/*/mem",
    "/proc/*/maps",
    "/proc/*/smaps",
    "/proc/*/pagemap",
    "/proc/kcore",
)
_DEFAULT_RUNTIME_PREFIXES = (
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
    "/etc/ld.so.cache",
    "/etc/ld.so.preload",
    "/usr/share/locale",
    "/usr/lib/locale",
    "/usr/bin",
    "/bin",
    "/sbin",
    "/usr/sbin",
    "/etc/nsswitch.conf",
    "/etc/passwd",
    "/etc/group",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/localtime",
    "/etc/ssl/certs",
    "/etc/pki",
    "/proc/",
    "/sys/",
    "/dev/null",
    "/dev/urandom",
    "/dev/random",
    "/run/systemd/userdb",
)
_DEFAULT_OPENCLAW_RUNTIME_PREFIXES = (
    "/usr/lib/node_modules/openclaw",
    "/root/.openclaw/extensions",
    "/root/.openclaw/agents",
    "/root/.openclaw/completions",
    "/root/.openclaw/workspace",
    "/root/.openclaw/logs",
    "/root/.openclaw/before_tool_call_lab.jsonl",
    "/root/.openclaw/exec-approvals",
    "/root/.openclaw/.exec-approvals",
)
_DEFAULT_OPENCLAW_RUNTIME_BASENAMES = (
    "AGENT.md",
    "AGENTS.md",
    "SOUL.md",
    "HEARTBEAT.md",
    "TOOLS.md",
    "IDENTITY.md",
    "MEMORY.md",
    "USER.md",
)
_DEFAULT_IGNORED_NETWORK_ENDPOINTS = (
    "127.0.0.1:15100",
    "::1:15100",
    "localhost:15100",
)


def _rules_path() -> Path:
    override = os.environ.get("LHA_RULES_PATH")
    return Path(override) if override else DEFAULT_RULES_PATH


def _load_yaml(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}


def _tuple(values, default: tuple) -> tuple:
    """把 YAML 列表转成去空、去重（保序）的字符串元组；空/非法则回退默认。"""
    if not isinstance(values, list):
        return default
    seen: list = []
    for value in values:
        if isinstance(value, str) and value and value not in seen:
            seen.append(value)
    return tuple(seen) if seen else default


_RULES = _load_yaml(_rules_path())
_FILES = _RULES.get("files") if isinstance(_RULES.get("files"), dict) else {}
_NETWORK = _RULES.get("network") if isinstance(_RULES.get("network"), dict) else {}

SENSITIVE_PREFIXES = _tuple(_FILES.get("sensitive_prefixes"), _DEFAULT_SENSITIVE_PREFIXES)
SENSITIVE_GLOBS = _tuple(_FILES.get("sensitive_globs"), _DEFAULT_SENSITIVE_GLOBS)
RUNTIME_PREFIXES = _tuple(_FILES.get("runtime_prefixes"), _DEFAULT_RUNTIME_PREFIXES)
OPENCLAW_RUNTIME_PREFIXES = _tuple(
    _FILES.get("openclaw_runtime_prefixes"), _DEFAULT_OPENCLAW_RUNTIME_PREFIXES
)
OPENCLAW_RUNTIME_BASENAMES = _tuple(
    _FILES.get("openclaw_runtime_basenames"), _DEFAULT_OPENCLAW_RUNTIME_BASENAMES
)
IGNORED_NETWORK_ENDPOINTS = _tuple(
    _NETWORK.get("ignored_endpoints"), _DEFAULT_IGNORED_NETWORK_ENDPOINTS
)


def is_ignored_endpoint(endpoint: str | None) -> bool:
    """端点是否属于忽略集合（工具拉取线上配置的本地回环连接）。

    端点串可能带地址族前缀（如 ``AF_INET 127.0.0.1:15100``）或仅为 ``ip:port``；
    这里取最后一个空白分隔 token 作为 ``ip:port`` 进行完整匹配（端口必须一致）。
    """
    if not endpoint:
        return False
    token = endpoint.split()[-1] if endpoint.split() else endpoint
    return token in IGNORED_NETWORK_ENDPOINTS
