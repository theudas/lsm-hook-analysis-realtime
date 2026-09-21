#!/usr/bin/env python3
"""检测规则加载：从 detection_rules.yaml 读取敏感/运行时文件定义与忽略网络端点。

规则文件缺失或某个键为空时，回退到内置默认值，保证服务始终可运行。
可通过环境变量 LHA_RULES_PATH 指定其他 YAML 路径。

敏感资源以 ``sensitive_groups`` 分组表达，每组带威胁语义（reason）、公开依据
（basis / attck）与匹配动作（match）。加载后编译为 ``SENSITIVE_RULES``：一个有序
的 :class:`SensitiveRule` 列表，供 analyzer 判定并在报告中给出判定理由。
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml


PACKAGE_DIR = Path(__file__).parent
DEFAULT_RULES_PATH = PACKAGE_DIR / "detection_rules.yaml"

# 触发 write_only 组的动作集合（与 analyzer 的动作词汇一致）。
WRITE_ACTIONS = frozenset({"write", "create", "delete"})


@dataclass(frozen=True)
class SensitiveRule:
    """一组敏感资源：路径集合 + 为什么敏感 + 什么动作才算越权。"""

    id: str
    title: str
    severity: str
    match: str  # "any" | "write_only"
    reason: str
    basis: str
    attck: tuple = ()
    override_runtime: bool = False
    prefixes: tuple = ()
    glob_regexes: tuple = field(default=(), repr=False)

    def matches_path(self, path: str) -> bool:
        if self.prefixes and path.startswith(self.prefixes):
            return True
        return any(pattern.fullmatch(path) for pattern in self.glob_regexes)

    def matches_actions(self, actions) -> bool:
        """write_only 组只在实际观测到写/创建/删除时成立；动作未知时保守放行。"""
        if self.match != "write_only":
            return True
        if actions is None:
            return False
        return bool(WRITE_ACTIONS & set(actions))

    def label(self) -> str:
        """报告中展示的判定理由，例如：SSH 与私钥材料（critical，ATT&CK T1552.004）。"""
        suffix = f"，ATT&CK {'/'.join(self.attck)}" if self.attck else ""
        return f"{self.title}（{self.severity}{suffix}）"


# 内置默认值：当 YAML 缺失或对应键为空时使用，保证服务在没有规则文件时仍可运行。
# 只保留最小可辩护集合，完整分组与依据见 detection_rules.yaml。
_DEFAULT_SENSITIVE_GROUPS = (
    {
        "id": "credential_store",
        "title": "系统口令散列与提权授权库",
        "severity": "critical",
        "match": "any",
        "attck": ["T1003.008", "T1548.003"],
        "reason": "存放口令散列与 sudo/PAM 授权策略，默认仅 root 可读，读取即等价于拿到凭据",
        "basis": "Falco sensitive_file_names；Neo23x0 auditd etcpasswd/pam/actions；CIS 6.1.x",
        "prefixes": ["/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/pam.d", "/etc/pam.conf"],
    },
    {
        "id": "private_keys",
        "title": "SSH 与私钥材料",
        "severity": "critical",
        "match": "any",
        "override_runtime": True,
        "attck": ["T1552.004", "T1098.004"],
        "reason": "私钥与授权公钥，读到即可冒充身份横向移动",
        "basis": "ATT&CK T1552.004；Neo23x0 auditd -w /root/.ssh -k rootkey",
        "prefixes": ["/root/.ssh", "/etc/ssh/ssh_host_"],
        "globs": ["/home/*/.ssh/**", "/**/id_rsa", "/**/id_ed25519", "/**/authorized_keys"],
    },
    {
        "id": "cloud_and_registry_credentials",
        "title": "云 / 容器 / 制品仓库凭据",
        "severity": "critical",
        "match": "any",
        "override_runtime": True,
        "attck": ["T1552.001"],
        "reason": "长期有效的云 API 密钥与仓库令牌，泄露后无法靠重启缓解",
        "basis": "ATT&CK T1552.001 正文点名 ~/.aws/credentials、~/.netrc、/run/secrets",
        "prefixes": [
            "/root/.aws",
            "/root/.azure",
            "/root/.config/gcloud",
            "/root/.docker/config.json",
            "/root/.kube/config",
            "/root/.netrc",
            "/root/.gnupg",
            "/run/secrets",
            "/var/run/secrets",
        ],
        "globs": ["/home/*/.aws/**", "/**/.env"],
    },
    {
        "id": "process_and_kernel_memory",
        "title": "进程与内核内存窥探",
        "severity": "critical",
        "match": "any",
        "attck": ["T1003.007"],
        "reason": "跨进程读取环境变量与内存映射可直接捞取其他进程持有的密钥",
        "basis": "ATT&CK T1003.007 OS Credential Dumping: Proc Filesystem",
        "prefixes": ["/proc/kcore", "/proc/kallsyms", "/dev/mem", "/dev/kmem"],
        "globs": [
            "/proc/*/environ",
            "/proc/*/mem",
            "/proc/*/maps",
            "/proc/*/smaps",
            "/proc/*/pagemap",
            "/proc/*/cmdline",
        ],
    },
    {
        "id": "audit_and_auth_logs",
        "title": "认证日志与审计轨迹",
        "severity": "high",
        "match": "any",
        "attck": ["T1070.002"],
        "reason": "读取可获得账号与登录来源情报，写入/删除是反取证行为",
        "basis": "Neo23x0 auditd -w /var/log/audit/ -k auditlog、-w /var/log/wtmp -k session",
        "prefixes": [
            "/var/log/audit",
            "/etc/audit",
            "/var/log/secure",
            "/var/log/auth.log",
            "/var/log/wtmp",
            "/var/log/btmp",
            "/var/log/journal",
        ],
    },
    {
        "id": "account_database_write",
        "title": "账号数据库写入",
        "severity": "critical",
        "match": "write_only",
        "attck": ["T1136.001"],
        "reason": "写入等价于新增后门账号；读取是 glibc NSS 的常规行为",
        "basis": "Neo23x0 auditd -w /etc/passwd -k etcpasswd；ATT&CK T1136.001",
        "prefixes": ["/etc/passwd", "/etc/group", "/etc/nsswitch.conf"],
    },
    {
        "id": "preload_and_loader_hijack",
        "title": "动态链接器劫持",
        "severity": "critical",
        "match": "write_only",
        "attck": ["T1574.006"],
        "reason": "写入后所有新进程都会加载攻击者的 .so",
        "basis": "Tracee ld_preload signature；Neo23x0 auditd -w /etc/ld.so.preload",
        "prefixes": ["/etc/ld.so.preload", "/etc/ld.so.conf"],
    },
)
_DEFAULT_RUNTIME_PREFIXES = (
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
    "/usr/libexec",
    "/etc/ld.so.cache",
    "/etc/ld.so.preload",
    "/usr/share",
    "/usr/lib/locale",
    "/usr/bin",
    "/bin",
    "/sbin",
    "/usr/sbin",
    "/usr/local/bin",
    "/etc/nsswitch.conf",
    "/etc/authselect",
    "/etc/passwd",
    "/etc/group",
    "/etc/hosts",
    "/etc/host.conf",
    "/etc/resolv.conf",
    "/etc/localtime",
    "/etc/ssl/certs",
    "/etc/pki",
    "/etc/crypto-policies",
    "/etc/profile",
    "/etc/bashrc",
    "/etc/os-release",
    "/etc/machine-id",
    "/proc/",
    "/sys/",
    "/dev/null",
    "/dev/tty",
    "/dev/urandom",
    "/dev/random",
    "/run/systemd",
)
_DEFAULT_OPENCLAW_RUNTIME_PREFIXES = (
    "/usr/lib/node_modules/openclaw",
    "/root/.openclaw",
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


def glob_to_regex(pattern: str) -> str:
    """把路径 glob 编译成正则：``*`` 限单层路径段，``**`` 跨目录。

    与 IR 文件标识的匹配语义一致，analyzer 的 matches_file_identifier 与本模块的
    敏感 glob 共用这一份实现。
    """
    out = ["^"]
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "*":
            if index + 1 < len(pattern) and pattern[index + 1] == "*":
                index += 2
                if index < len(pattern) and pattern[index] == "/":
                    out.append("(?:.*/)?")
                    index += 1
                else:
                    out.append(".*")
                continue
            out.append("[^/]*")
            index += 1
            continue
        if char == "?":
            out.append("[^/]")
            index += 1
            continue
        if char == "[":
            end = index + 1
            if end < len(pattern) and pattern[end] in ("!", "^"):
                end += 1
            if end < len(pattern) and pattern[end] == "]":
                end += 1
            while end < len(pattern) and pattern[end] != "]":
                end += 1
            if end >= len(pattern):
                out.append(re.escape(char))
                index += 1
                continue
            content = pattern[index + 1 : end]
            if content.startswith("!"):
                content = "^" + content[1:]
            elif content.startswith("^"):
                content = "\\" + content
            out.append("[" + content.replace("\\", "\\\\") + "]")
            index = end + 1
            continue
        out.append(re.escape(char))
        index += 1
    out.append("$")
    return "".join(out)


def _compile_groups(groups) -> tuple:
    """把 YAML 的 sensitive_groups 编译成有序 SensitiveRule 元组。

    override_runtime 的组排在前面，因为它们要穿透 openclaw 运行时白名单。
    """
    if not isinstance(groups, list):
        return ()
    rules = []
    for index, group in enumerate(groups):
        if not isinstance(group, dict):
            continue
        prefixes = _tuple(group.get("prefixes"), ())
        globs = _tuple(group.get("globs"), ())
        if not prefixes and not globs:
            continue
        attck = _tuple(group.get("attck"), ())
        rules.append(
            (
                0 if group.get("override_runtime") else 1,
                index,
                SensitiveRule(
                    id=str(group.get("id") or f"group_{index}"),
                    title=str(group.get("title") or group.get("id") or "敏感资源"),
                    severity=str(group.get("severity") or "high"),
                    match="write_only" if group.get("match") == "write_only" else "any",
                    reason=str(group.get("reason") or ""),
                    basis=str(group.get("basis") or ""),
                    attck=attck,
                    override_runtime=bool(group.get("override_runtime")),
                    prefixes=prefixes,
                    glob_regexes=tuple(re.compile(glob_to_regex(g)) for g in globs),
                ),
            )
        )
    rules.sort(key=lambda item: (item[0], item[1]))
    return tuple(rule for _, _, rule in rules)


_RULES = _load_yaml(_rules_path())
_FILES = _RULES.get("files") if isinstance(_RULES.get("files"), dict) else {}
_NETWORK = _RULES.get("network") if isinstance(_RULES.get("network"), dict) else {}

SENSITIVE_RULES = _compile_groups(_FILES.get("sensitive_groups")) or _compile_groups(
    list(_DEFAULT_SENSITIVE_GROUPS)
)

# /proc/<pid>/... 中 <pid> 就是访问者自身时判为 runtime：进程读自己的 /proc/self/*
# 不跨越任何权限边界，跨进程读才是 ATT&CK T1003.007 描述的行为。
PROC_SELF_IS_RUNTIME = _FILES.get("proc_self_is_runtime", True) is not False

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
