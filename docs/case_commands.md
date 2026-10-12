# 测试报告用例取证命令清单

每条用例对应的执行命令，用于截图填入报告「测试结果」一栏。
全部在项目根目录 `/home/hx/try/lsm-hook-analysis-realtime` 下执行。

加 `-v` 会逐条打印 `... ok`，截图更直观；用例数多的（20 项以上）不加 `-v`
只出一行 `Ran N tests — OK`，一屏放得下。

---

## 0. 日志抑制

`tests/__init__.py` 会在测试包导入时给 analyzer / pipeline / receiver 三个服务
logger 挂上过滤器，屏蔽它们的输出。所以下面的命令**直接执行即可**，屏幕上只有
unittest 自己的结果，不需要 `> /dev/null`，也不会往 `logs/` 里写测试噪声。

先验证一条（这条会 import pipeline 与 analyzer，是会刷屏的模块）：

```bash
python3 -m unittest -v tests.test_analyzer_parsing.LoaderTest
```

应只看到 6 行 `... ok` 与 `Ran 6 tests — OK`，没有任何 `[INFO]` 行。
若仍有日志，说明 `tests/__init__.py` 没生效，检查文件是否存在、是否被
`__pycache__` 里的旧字节码盖住（`find . -name __pycache__ -exec rm -rf {} +`）。

调试某条测试想看服务日志时放行：

```bash
LHA_TEST_LOGS=1 python3 -m unittest tests.test_realtime_pipeline
```

`scripts/` 下的三个脚本（`bench_replay.py`、`loadtest.py --quiet`、
`collect_case_evidence.py`）内部另有 `logging.disable(logging.CRITICAL)`，
不受此文件影响。

---

## 0.1 执行顺序

1. 先跑 1.2 节的四条脚本命令（性能与语料统计），耗时最长；
2. 再跑 1.1 / 1.3 / 1.4 的单测命令，每条一两秒；
3. 若打算先执行 `prune_invalid_rounds.py --apply` 清理语料，**必须在清理之后**
   才跑 P-1-1、P-1-2、P-1-3、P-1-4、S-1-1、R-1-1，否则数字对不上报告。

---

## 1.1 功能验证

### F-1-1 四类推送消息乱序到达后完整触发分析

```bash
python3 -m unittest -v \
  tests.test_realtime_pipeline.RealtimePipelineTest.test_round_is_analyzed_after_all_messages_arrive \
  tests.test_realtime_pipeline.RealtimePipelineTest.test_analysis_waits_until_round_start_arrives \
  tests.test_realtime_pipeline.RealtimePipelineTest.test_ir_ready_after_kernel_unblocks_analysis \
  tests.test_realtime_pipeline.RealtimePipelineTest.test_empty_ir_round_end_does_not_trigger_premature_analysis \
  tests.test_realtime_pipeline.RealtimePipelineTest.test_burst_messages_are_queued_and_processed \
  tests.test_state_store.RoundStateTest.test_round_only_becomes_ready_after_all_four_inputs \
  tests.test_pipeline_internals.MessageDispatchTest.test_empty_ir_ready_is_skipped_without_marking_has_ir
```

预期：`Ran 7 tests — OK`

### F-1-2 IR 允许集解析与路径 glob 匹配

```bash
python3 -m unittest \
  tests.test_realtime_pipeline.FileIdentifierMatcherTest \
  tests.test_analyzer_parsing.ParseAllowlistTest \
  tests.test_analyzer_parsing.PatternMatchingTest \
  tests.test_analyzer_parsing.LoadIrSourceTest
```

预期：`Ran 22 tests — OK`

### F-1-3 LSM 事件与 syscall 序列归并

```bash
python3 -m unittest -v \
  tests.test_analyzer_parsing.ExtractKernelFileOpsTest \
  tests.test_analyzer_parsing.FlagsToActionsTest \
  tests.test_realtime_pipeline.AnalyzerActionMismatchTest.test_inode_unlink_is_judged_as_delete_action
```

预期：`Ran 11 tests — OK`

### F-1-4 两条独立判据交叉判定与分歧记账

```bash
python3 -m unittest -v \
  tests.test_analyzer_push.AnalyzeRoundMetadataTest \
  tests.test_analyzer_report.ReportRenderingTest.test_conflicting_judges_on_one_path_render_as_partial \
  tests.test_realtime_pipeline.SensitiveClassificationTest.test_violation_records_carry_rule_metadata
```

预期：`Ran 4 tests — OK`

### F-1-5 三类异常识别与网络回环抑制

```bash
python3 -m unittest \
  tests.test_analyzer_parsing.DetectAnomaliesTest \
  tests.test_realtime_pipeline.AnalyzerActionMismatchTest \
  tests.test_analyzer_parsing.ParseNetworkActivityTest \
  tests.test_analyzer_parsing.NetworkHelperTest \
  tests.test_analyzer_parsing.ConnectEndpointsTest \
  tests.test_rules_loading.IgnoredEndpointTest
```

预期：`Ran 33 tests — OK`

### F-1-6 敏感资源分组判定

```bash
python3 -m unittest \
  tests.test_realtime_pipeline.SensitiveClassificationTest \
  tests.test_analyzer_parsing.ClassificationEdgeTest \
  tests.test_rules_loading.SensitiveRuleTest
```

预期：`Ran 22 tests — OK`

### F-1-7 analysis_report.md 渲染完整性

```bash
python3 -m unittest tests.test_analyzer_report.ReportRenderingTest
```

预期：`Ran 20 tests — OK`

### F-1-8 analysis_violations.jsonl 明细字段完整

```bash
python3 -m unittest -v \
  tests.test_analyzer_report.ReportRenderingTest.test_violations_jsonl_carries_round_id_on_every_line \
  tests.test_analyzer_report.ReportRenderingTest.test_all_four_categories_render_their_own_table \
  tests.test_analyzer_push.AnalyzeRoundMetadataTest.test_sensitive_violation_carries_rule_metadata_and_counts \
  tests.test_realtime_pipeline.SensitiveClassificationTest.test_violation_records_carry_rule_metadata
```

预期：`Ran 4 tests — OK`

### F-1-9 报告路径上报后端接口与幂等标记

```bash
python3 -m unittest -v \
  tests.test_analyzer_push.PushKernelReportTest \
  tests.test_analyzer_push.MarkAndPushTest \
  tests.test_analyzer_push.AnalyzeWriteAndPushTest
```

预期：`Ran 13 tests — OK`

### F-1-10 重复 round_id 按新一代处理

```bash
python3 -m unittest \
  tests.test_realtime_pipeline.RealtimePipelineTest.test_replayed_round_reruns_full_pipeline_and_repushes \
  tests.test_realtime_pipeline.RealtimePipelineTest.test_replaying_one_required_message_reruns_using_persisted_inputs \
  tests.test_realtime_pipeline.RealtimePipelineTest.test_second_round_end_updates_metadata_without_new_generation \
  tests.test_pipeline_internals.NewGenerationDecisionTest \
  tests.test_pipeline_internals.AnalysisSupersessionTest \
  tests.test_state_store.RoundStateTest.test_replay_bumps_generation_and_keeps_persisted_inputs \
  tests.test_state_store.RoundStateTest.test_replay_cancels_an_in_flight_job \
  tests.test_state_store.RoundStateTest.test_finished_jobs_are_not_cancelled_by_a_replay
```

预期：`Ran 16 tests — OK`

---

## 1.2 性能验证

### P-1-1 单 round 端到端分析耗时

```bash
python3 scripts/bench_replay.py --json reports/bench_replay.json
```

截图取输出中的 **「P-1-1 单 round 耗时」** 段落。

### P-1-2 全量语料回放耗时

同一条命令，截图取开头的目录分类计数 + **「P-1-2 全量回放」** 段落。

```bash
python3 scripts/bench_replay.py --json reports/bench_replay.json
```

### P-1-3 消息摄入吞吐与端到端延迟

```bash
for r in 5 10 20 50 100; do
  python3 scripts/loadtest.py --rate $r --rounds 500 --workers 4 --quiet
done
```

五个 RESULT 区块，建议分两三张截图。

### P-1-4 分析 worker 并发扩展性

```bash
for w in 1 2 4 8; do
  python3 scripts/loadtest.py --rate 50 --rounds 500 --workers $w --quiet
done
```

四个 RESULT 区块。

---

## 1.3 安全性验证

### S-1-1 敏感资源判定的误报治理与依据可追溯

```bash
python3 scripts/bench_replay.py --json reports/bench_replay.json
```

截图取 **「语料统计」** 段落（敏感命中路径种类 / 次数 / round 数 / 分组分布）。

### S-1-2 用户态隐瞒行为的检出

```bash
python3 scripts/collect_case_evidence.py S-1-2
```

### S-1-3 内核侧工具名与用户态声明的差异呈现

```bash
python3 scripts/collect_case_evidence.py S-1-3
```

注意：截图要包含 `2b6a4000` 那一段（`is_anomaly=False`），它是结论里"模块不自动判定
工具劫持"的直接证据，不能只截前四个 round。

### S-1-4 敏感数据外发链路识别

```bash
python3 scripts/collect_case_evidence.py S-1-4
```

### S-1-5 目录清理的越界保护

```bash
python3 -m unittest -v \
  tests.test_pipeline_internals.FileHelperTest.test_clear_round_dir_refuses_paths_outside_input_dir \
  tests.test_pipeline_internals.FileHelperTest.test_is_within_input_dir \
  tests.test_pipeline_internals.FileHelperTest.test_path_traversal_escape_is_rejected \
  tests.test_pipeline_internals.FileHelperTest.test_clear_round_dir_removes_inputs_dotfiles_and_analysis_dirs \
  tests.test_pipeline_internals.FileHelperTest.test_clear_round_dir_creates_a_missing_directory
```

预期：`Ran 5 tests — OK`

---

## 1.4 可靠性验证

### R-1-1 损坏与缺失输入的容错

两张截图。单测部分：

```bash
python3 -m unittest -v \
  tests.test_analyzer_parsing.LoaderTest \
  tests.test_analyzer_parsing.ParseUserActionsAndFactsTest
```

预期：`Ran 12 tests — OK`

语料部分（清理前指向 `input/`，清理后指向归档目录）：

```bash
# 未执行清理时
python3 scripts/bench_replay.py

# 已执行 prune_invalid_rounds.py --apply 之后
python3 scripts/bench_replay.py --input-dir ../input_invalid
```

截图取目录分类计数与三个损坏 round 的 `JSONDecodeError` 行。

### R-1-2 上报链路失败模式与重试

```bash
python3 -m unittest -v \
  tests.test_analyzer_push.PushKernelReportTest \
  tests.test_pipeline_internals.AnalysisPushTest \
  tests.test_pipeline_internals.IngestFailureTest \
  tests.test_realtime_pipeline.RealtimePipelineTest.test_analysis_failure_retries_then_marks_failed
```

预期：`Ran 12 tests — OK`

### R-1-3 SQLite 状态机与 schema 迁移

```bash
python3 -m unittest tests.test_state_store
```

预期：`Ran 33 tests — OK`

### R-1-4 规则文件加载容错

```bash
python3 -m unittest tests.test_rules_loading
```

预期：`Ran 32 tests — OK`
（`tests.test_rules_loading` 共 43 项，其中 `IgnoredEndpointTest` 的 5 项与
`SensitiveRuleTest` 的 6 项分别归属 F-1-5 与 F-1-6。若要精确对齐 32 项，用下面这条：）

```bash
python3 -m unittest \
  tests.test_rules_loading.LoadYamlTest \
  tests.test_rules_loading.CompileGroupsTest \
  tests.test_rules_loading.GlobToRegexTest \
  tests.test_rules_loading.TupleHelperTest \
  tests.test_rules_loading.LoadedRuleSetTest
```

### R-1-5 服务常驻与自动重启

三张截图。

单测部分：

```bash
python3 -m unittest \
  tests.test_receiver.OnPushTest \
  tests.test_receiver.ConnectionEventTest \
  tests.test_receiver.MainTest \
  tests.test_receiver.ScriptEntrypointTest \
  tests.test_pipeline_internals.WorkerLifecycleTest \
  tests.test_pipeline_internals.MainEntrypointTest
```

预期：`Ran 22 tests — OK`

部署侧现场验证（systemd 常驻）：

```bash
systemctl status lha_realtime.service --no-pager
```

自动重启验证（kill 后等 5 秒，对比 PID 变化）：

```bash
systemctl show lha_realtime.service -p MainPID -p NRestarts
kill -9 $(systemctl show lha_realtime.service -p MainPID --value)
sleep 6
systemctl show lha_realtime.service -p MainPID -p NRestarts
systemctl is-active lha_realtime.service
```

截图要能看到 `MainPID` 变了、`NRestarts` 加了 1、状态回到 `active`。

### R-1-6 mock round 上报开关

```bash
python3 -m unittest -v \
  tests.test_realtime_pipeline.RealtimePipelineTest.test_mock_round_push_is_disabled_by_default \
  tests.test_realtime_pipeline.RealtimePipelineTest.test_mock_round_push_can_be_enabled \
  tests.test_analyzer_push.IsMockRoundTest \
  tests.test_pipeline_internals.AnalysisPushTest.test_mock_round_is_analyzed_but_not_pushed \
  tests.test_config.BoolEnvTest \
  tests.test_config.SettingsTest
```

预期：`Ran 14 tests — OK`

### R-1-7 代码白盒覆盖率

```bash
python3 -m coverage run -m unittest discover -s tests
python3 -m coverage report
```

两张截图：`Ran 295 tests — OK`，以及按模块的覆盖率表。
注意表里 `analyzer.py` 是 `99.8%`、`Missing 401`，总计 `99.9%` —— 报告结论与此一致，
不要换成 README 里写的 100%。

---

## 一次跑完全部

不想逐条敲，可以用采集脚本按顺序打印所有用例的执行结果：

```bash
python3 scripts/collect_case_evidence.py            # 全部 26 条
python3 scripts/collect_case_evidence.py F-1-1      # 指定某几条
```

输出按 `【用例编号】` 分块，每块含执行命令、`Ran N tests — OK`、覆盖的测试用例清单。
