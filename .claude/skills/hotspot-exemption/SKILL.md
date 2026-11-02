---
name: hotspot-exemption
description: 根据 scripts/hotspot_stats.py 产出的内核行为豁免建议页面，把三档判定（建议豁免/需人工确认/不建议）落进 lha_realtime/detection_rules.yaml：数据获取、逐条复核与改写、合入口径、必做的回放验证。当用户要求"应用豁免建议""把热点页的豁免合入规则""处理需人工确认项"时使用。
---

# 从豁免建议页面到规则合入（hotspot_stats → detection_rules.yaml）

豁免建议页面（`scripts/hotspot_stats.py` 产物）重放 `input/` 语料，列出尚未被现有规则折叠的高频内核行为并给出三档判定与现成 YAML 片段。本技能负责把其中的结论**经人工确认后**合入 `detection_rules.yaml`。字段语义、判定模型与红线细节见 `detection-rules` 技能，本技能不重复，只讲"从页面建议到合入"的流程。

## 第一步：拿最新数据（机器可读路径是 --json，不要解析 HTML）

```bash
python3 scripts/hotspot_stats.py --json reports/hotspot.json
# 同步产出 reports/hotspot.html 供人工浏览；JSON 与页面同源
```

- 默认阈值 `--threshold 0.2`：只有出现在 ≥ 20% round 的行为才进建议；路径归并到前 `--depth 3` 段。
- `suggestions[]` 每条字段：`kind`（文件/网络）、`behavior`（路径桶或端点）、`verdict`（accept/review/reject）、`reasons`（判定依据，逐条人话）、`share`/`rounds`/`count`（覆盖面）、`hooks`/`actions`（观测事实）、`yaml`（可合入片段，reject 为 null）。
- 页面另有三张热力图（路径×hook、端点×hook、已生效豁免的折叠量），`reports/hotspot.json` 里对应 `file`/`net`/`fold` 键，可用于评估覆盖面。

## 第二步：按三档判定分流（脚本只是初筛，不是结论）

| 判定 | 含义 | 处置 |
|---|---|---|
| ✓ 建议豁免 (accept) | 系统自带常规行为（系统目录只读 runtime、写终端/空设备） | 逐条复核后可合入；**YAML 不得照抄**（见下） |
| ! 需人工确认 (review) | 有疑点：含 `bprm_check`、不在常见系统目录、用户目录里的 runtime 文件、本机 Unix socket / 回环端点 | 必须把 `reasons` 原样呈给用户，**用户明确同意才合入**；用户可写目录的默认答复是不合入 |
| ✕ 不建议 (reject) | 敏感命中、观测到写入、用户可写目录、非本机网络地址 | 永不合入，也不要改写其他规则去绕开这些判定 |

三档判定只看内核侧事实（hook、读写、路径、端点），合入前必须自己想清楚误报面：这个路径下如果出现攻击行为，折叠后报告里会少什么。

## 第三步：合入口径（逐字段）

片段里的 `reason` 是占位符（原文写着"确认后再改写说明"），**必须改写**成真实依据：出现在多少比例的 round、多少次、为什么属于系统/框架自身行为。改写可参考现有条目（如 `dynamic_loader_open` 的写法）。

1. **id**：用片段生成的 slug 但要查重（与现有 `system_baseline` 的 id 不冲突）；`title` 写清楚是什么行为。
2. **条件尽量收窄**：能写 `hooks + categories + actions` 组合就不要只写路径；`actions: ["read"]` 只豁免纯读取，带写入的操作不会匹配。
3. **globs 语义**：`*` 不跨路径分隔符，`**` 跨目录。片段对观察到更深路径的条目会同时给 `pattern` 与 `pattern/**`，两者一起保留。
4. **符号链接双写**：`/var/run` 是 `/run` 的符号链接，内核可能报告任一路径——端点类条目参照 `nss_unix_socket` 的先例两行都写。
5. **Unix socket**（`kind: 网络`、路径形如 `/run/xxx/socket`）→ 合入 `system_baseline` 的 `endpoints`。注意 `endpoints` 会像忽略端点一样把该端点从网络判定中剔除，**且不能吸收无法归属的收发**（历史反例：nscd 并入忽略端点吞掉 2 个真攻击 round）。
6. **回环端点**（`127.0.0.1:端口`）→ 合入 `network.ignored_endpoints`，**必须同步改** `tests/test_system_baseline.py` 的 `test_ignored_endpoints_are_exactly_the_configured_set`（契约测试锁定集合内容）。端点是字面完整匹配，端口不同即不匹配。
7. `meta.version` 递增、`updated` 改当天；在条目或注释里写回放依据（哪些 round、什么行为）。
8. 改完需重启服务生效：`sudo systemctl restart lha_realtime.service`（本地调试则重启 receiver）。

## 红线（违反任何一条即停）

- **敏感命中永不被折叠**：基线规则匹配到 sensitive 分类的操作时不会生效（代码保证），但也不要试图用放宽 sensitive_groups 的方式配合基线压告警。
- **含 `bprm_check` 的 review 项默认不合入**：豁免后报告里不再显示"执行了该程序"。
- **不要用豁免压误报凑指标**：FPR 的下降若来自真阳性被吞是净损失（nscd 先例：FPR 降到 5.71% 的代价是 2 个真攻击被整轮吞掉）。压误报的正道是修根因。
- 大改前先读 `detection-rules` 技能的红线与坑清单（前缀 `startswith` 连带命中、不按扩展名收 `*.pem` 等）。

## 第四步：验证流程（必做，顺序执行）

```bash
python3 -m unittest discover -s tests            # 1. 单测（含配置契约测试）
python3 scripts/eval_metrics.py --tag <改动标签>  # 2. 回放：FPR/召回与翻转明细
python3 scripts/signal_attribution.py            # 3. 对抗评测：A2 强伪装召回回退 >2pp 视为退化
python3 scripts/hotspot_stats.py --json reports/hotspot.json   # 4. 复核折叠效果
```

- 第 2 步的判定翻转必须逐 round 核对归因：是消除误杀还是丢真阳性。
- 第 4 步确认：已合入的行为应从"豁免建议"消失、移入"已生效的豁免"热力图，`folded_ops` 相应上升。
- 回放产物在 `reports/eval_artifacts_<标签>/`（该目录不入库）。
