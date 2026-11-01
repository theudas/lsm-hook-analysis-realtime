---
name: detection-rules
description: 配置 lha_realtime/detection_rules.yaml（敏感分组、系统基线、忽略网络端点、运行时前缀）时使用：字段语义、判定模型、常见任务配方、修改后的回放验证流程与红线约束。
---

# 检测规则配置（detection_rules.yaml）

本项目的越权检测判定全部由 `lha_realtime/detection_rules.yaml` 驱动，改配置不需要改代码。改错方向的代价是误杀（良性操作被判异常）或漏报（攻击放行），所以**每次修改都必须走文末的验证流程**。

## 文件位置与生效方式

- 文件：`lha_realtime/detection_rules.yaml`；可用环境变量 `LHA_RULES_PATH` 指向其他路径。
- 加载时机：`lha_realtime/rules.py` 在 **import 时**加载一次。改完 YAML 需重启服务生效：
  `sudo systemctl restart lha_realtime.service`（本地调试则重启 receiver）。
- 回退行为：文件缺失或某个键为空时，回退 `rules.py` 里的内置默认值（服务不会起不来，但会**静默**丢失你的修改——改完务必按验证流程确认规则真的生效了）。
- `scripts/hotspot_stats.py --serve` 的页面"刷新"在子进程里重读规则，可即时复核豁免效果。

## 顶层结构

```yaml
meta:                  # version / updated，随每次改动递增
network:
  ignored_endpoints:   # 网络判定豁免的端点（字面 IP:端口）
system_baseline:       # 高频系统行为折叠规则（列表）
files:
  proc_self_is_runtime: # /proc 自读降级开关
  sensitive_groups:    # 敏感资源分组（列表，判定核心）
  runtime_prefixes:     # 运行时路径前缀（命中判 runtime）
  openclaw_runtime_prefixes / openclaw_runtime_basenames  # 框架运行时
```

注意：`tools.registered`（工具名字白名单）已在 v6 移除，**不要再加回来**——静态名单可被攻击者起名绕过（对抗评测实测召回 92.94%→76.47%），详见 `reports/信号归因与对抗评测.md`。

## 判定模型（改之前必须理解）

一条内核放行操作被判"敏感越权"需**同时**满足三个条件，本文件控制前两条：

1. **资源性质**：路径命中某 sensitive_group（prefixes 或 globs）。
2. **动作性质**：该组的 `match` 与实际观测动作相符。
   - `any`：读到即成立（凭据、私钥、进程内存类）
   - `write_only`：只在实际观测到 write/create/delete 时成立（持久化面、二进制目录、账号库——读它们是 bash/glibc 的常规行为，按路径一刀切必产生系统性误报）
3. **主体越界**：已在越权清单（IR 允许集或内核 resource_role 判越权）——由 analyzer 完成，不在本文件表达。

分类优先级：`override_runtime` 组 → openclaw 运行时 → 其余敏感组 → runtime 前缀 → other。
标了 `override_runtime: true` 的组（凭据类）能穿透 openclaw 运行时白名单：密钥文件落在框架目录里也要报。

## sensitive_groups 字段

| 字段 | 语义 | 备注 |
|---|---|---|
| `id` / `title` | 标识与展示名 | |
| `severity` | critical/high | **只影响报告呈现与排序，不参与判定** |
| `match` | any / write_only | 见判定模型第 2 条 |
| `override_runtime` | 是否穿透运行时白名单 | 凭据类置 true |
| `attck` | ATT&CK 技术编号列表 | 报告展示 |
| `reason` / `basis` | 威胁语义 / 公开依据 | **必填**，有单测锁定每个组都带 |
| `prefixes` | `str.startswith` 语义 | 注意连带命中（见坑清单） |
| `globs` | `*` 不跨路径分隔符，`**` 跨目录 | 编译逻辑 `glob_to_regex` |

## system_baseline 条件（全部 AND）

命中的操作不进越权清单、只在报告末尾折叠汇总。可用条件：
`hooks`、`categories`（sensitive/runtime/other/unknown）、`families`（地址族）、`endpoints`（Unix socket 路径，**同时会像忽略端点一样从网络判定剔除**）、`path_missing`、`actions`（观测动作必须全部属于该集合）、`prefixes` / `globs`。

三条硬约束：
- **敏感命中永不被折叠**（基线不能用来降低检测力）。
- 没有任何条件的条目会被丢弃并告警（防止"匹配一切"）。
- 折叠规则不能吸收无法归属的收发——只有配置的忽略端点才能触发整轮抑制，纯基线端点不行（历史反例：把 nscd 并入忽略端点吞掉了 2 个真攻击 round）。

## network.ignored_endpoints

- **字面完整匹配** `IP:端口`（或 `localhost:端口`），不做域名解析，端口不同即不匹配；`::1:15100` 和 `127.0.0.1:15100` 是两个不同条目。
- 端点既影响收发判定，也影响 connect 即信号（豁免端点上的 connect 不触发）。
- `8.152.192.7:15100`（攻击外发通道）与 `::1:15100` **刻意不豁免**，有单测锁定（`test_ipv6_loopback_15100_is_judged_normally`）。

## 常见任务配方

**加一个豁免端点**（如平台新组件的外联通道）：
1. `network.ignored_endpoints` 追加 `"IP:端口"`，注释写回放依据（哪些 round、什么行为）。
2. 同步改 `tests/test_rules_loading.py` 的 `test_ignored_endpoints_are_exactly_the_configured_set`（契约测试锁定集合内容）。
3. 跑回放对比：目标 round 判定翻转、TP 零损失。

**加一个敏感分组**：按字段表写全（reason/basis 必填，出处用 ATT&CK/Falco/Neo23x0 auditd/CIS），先在 `reports/信号归因与对抗评测.md` 的 B 变体逻辑下想清楚误报面。

**加一条基线折叠**：条件尽量收窄（hooks+categories+prefixes 组合），跑 `scripts/hotspot_stats.py --serve` 看豁免建议页给的三档判定（建议豁免/需人工确认/不建议）与现成 YAML 片段。

**收窄某个组**：优先用精确 glob 替换前缀，参照坑清单里 `/etc/environment` 的先例。

## 修改后的验证流程（必做，顺序执行）

```bash
python3 -m unittest discover -s tests            # 1. 单测（含配置契约测试）
python3 scripts/eval_metrics.py --tag <改动标签>  # 2. 240 round 回放：FPR/FNR/翻转明细
python3 scripts/signal_attribution.py            # 3. 对抗评测：A2 强伪装召回不得显著回退（现基线约 87.65%，回退 >2pp 视为退化）
```

4. 需要人工复核豁免效果时：`python3 scripts/hotspot_stats.py --serve`，页面刷新即重读新规则。
回放产物在 `reports/eval_artifacts_<标签>/`；判定翻转必须逐 round 核对归因（是消除误杀还是丢真阳性）。

## 红线与已踩过的坑

- **不要用基线/豁免压误报来"凑指标"**：V2 实验（nscd 并入忽略端点）FPR 降到 5.71% 的代价是 2 个真攻击被整轮吞掉。压误报的正道是修根因（如 IR 翻译缺失标注）。
- **前缀 `startswith` 会连带命中**，逐个想清楚：`/etc/shadow` 连带 `/etc/shadow-`（CIS 点名，保留）；`/etc/environment` 曾连带 `/etc/environment-modules/`（误报 3 次，改精确 glob）；`/boot` 连带 `/bootstrap.sh`（改 `/boot/` + glob `/boot` 单列）。
- **不按扩展名收 `*.pem` / `*.crt`**：公开 CA 证书包会误判成私钥材料（`tls-ca-bundle.pem` 实测）。只收 `.p12`/`.pfx` 这类私钥容器。
- `severity` 不要接进判定逻辑——内核侧没有支撑分级的上下文，这是设计决定。
- 大改规则前先读 `DESIGN.md` §6/§7（文献依据与取舍记录）和 `reports/信号归因与对抗评测.md`（各判据承重分析），避免推翻已验证的结论。

## 配置版本史

- v4（2026-10-19）：回放调参——加 `8.152.192.7:18788`、回环校准端口，新增 `systemd_private_socket` 基线；FPR 24.29%→17.14%。
- v5（2026-10-19）：曾加 `tools.registered` 工具注册表（召回 92.94%）。
- v6（2026-10-26）：移除 `tools.registered`（名字可被伪装绕过），检测转由"connect 即信号"等行为判据承重（analyzer 代码实现，详见 DESIGN.md v3）。当前基线：召回 88.82% / FPR 12.86% / A2 强伪装下 87.65%。
