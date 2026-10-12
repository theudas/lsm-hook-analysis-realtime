#!/usr/bin/env python3
"""逐条采集测试报告用例的执行证据。

每条用例映射到具体的 unittest 子集或语料核查，按用例编号依次执行并打印结果，
输出可直接粘进测试报告的「测试结果」一栏。

用法：
  python3 scripts/collect_case_evidence.py              # 全部
  python3 scripts/collect_case_evidence.py F-1-1 S-1-3  # 只跑指定用例
"""

from __future__ import annotations

import io
import json
import logging
import sys
import time
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

T = "tests."
RP = T + "test_realtime_pipeline."
AP = T + "test_analyzer_parsing."
AR = T + "test_analyzer_report."
AU = T + "test_analyzer_push."
PI = T + "test_pipeline_internals."
RL = T + "test_rules_loading."
SS = T + "test_state_store."
RC = T + "test_receiver."
CF = T + "test_config."
LG = T + "test_logging_utils."

# 用例 -> unittest 子集（类名或方法全名均可）
CASE_TESTS: dict[str, list[str]] = {
    "F-1-1": [
        RP + "RealtimePipelineTest.test_round_is_analyzed_after_all_messages_arrive",
        RP + "RealtimePipelineTest.test_analysis_waits_until_round_start_arrives",
        RP + "RealtimePipelineTest.test_ir_ready_after_kernel_unblocks_analysis",
        RP + "RealtimePipelineTest.test_empty_ir_round_end_does_not_trigger_premature_analysis",
        RP + "RealtimePipelineTest.test_burst_messages_are_queued_and_processed",
        SS + "RoundStateTest.test_round_only_becomes_ready_after_all_four_inputs",
        PI + "MessageDispatchTest.test_empty_ir_ready_is_skipped_without_marking_has_ir",
    ],
    "F-1-2": [
        RP + "FileIdentifierMatcherTest",
        AP + "ParseAllowlistTest",
        AP + "PatternMatchingTest",
        AP + "LoadIrSourceTest",
    ],
    "F-1-3": [
        AP + "ExtractKernelFileOpsTest",
        AP + "FlagsToActionsTest",
        RP + "AnalyzerActionMismatchTest.test_inode_unlink_is_judged_as_delete_action",
    ],
    "F-1-4": [
        AU + "AnalyzeRoundMetadataTest",
        AR + "ReportRenderingTest.test_conflicting_judges_on_one_path_render_as_partial",
        RP + "SensitiveClassificationTest.test_violation_records_carry_rule_metadata",
    ],
    "F-1-5": [
        AP + "DetectAnomaliesTest",
        RP + "AnalyzerActionMismatchTest",
        AP + "ParseNetworkActivityTest",
        AP + "NetworkHelperTest",
        AP + "ConnectEndpointsTest",
        RL + "IgnoredEndpointTest",
    ],
    "F-1-6": [
        RP + "SensitiveClassificationTest",
        AP + "ClassificationEdgeTest",
        RL + "SensitiveRuleTest",
    ],
    "F-1-7": [AR + "ReportRenderingTest"],
    "F-1-8": [
        AR + "ReportRenderingTest.test_violations_jsonl_carries_round_id_on_every_line",
        AR + "ReportRenderingTest.test_all_four_categories_render_their_own_table",
        AU + "AnalyzeRoundMetadataTest.test_sensitive_violation_carries_rule_metadata_and_counts",
        RP + "SensitiveClassificationTest.test_violation_records_carry_rule_metadata",
    ],
    "F-1-9": [
        AU + "PushKernelReportTest",
        AU + "MarkAndPushTest",
        AU + "AnalyzeWriteAndPushTest",
    ],
    "F-1-10": [
        RP + "RealtimePipelineTest.test_replayed_round_reruns_full_pipeline_and_repushes",
        RP + "RealtimePipelineTest.test_replaying_one_required_message_reruns_using_persisted_inputs",
        RP + "RealtimePipelineTest.test_second_round_end_updates_metadata_without_new_generation",
        PI + "NewGenerationDecisionTest",
        PI + "AnalysisSupersessionTest",
        SS + "RoundStateTest.test_replay_bumps_generation_and_keeps_persisted_inputs",
        SS + "RoundStateTest.test_replay_cancels_an_in_flight_job",
        SS + "RoundStateTest.test_finished_jobs_are_not_cancelled_by_a_replay",
    ],
    "S-1-5": [
        PI + "FileHelperTest.test_clear_round_dir_refuses_paths_outside_input_dir",
        PI + "FileHelperTest.test_is_within_input_dir",
        PI + "FileHelperTest.test_path_traversal_escape_is_rejected",
        PI + "FileHelperTest.test_clear_round_dir_removes_inputs_dotfiles_and_analysis_dirs",
        PI + "FileHelperTest.test_clear_round_dir_creates_a_missing_directory",
    ],
    "R-1-1": [AP + "LoaderTest", AP + "ParseUserActionsAndFactsTest"],
    "R-1-2": [
        AU + "PushKernelReportTest",
        PI + "AnalysisPushTest",
        PI + "IngestFailureTest",
        RP + "RealtimePipelineTest.test_analysis_failure_retries_then_marks_failed",
    ],
    "R-1-3": [SS + "InboxTest", SS + "RoundStateTest", SS + "AnalysisJobTest",
              SS + "SchemaMigrationTest", SS + "PersistenceTest", SS + "HelperTest"],
    "R-1-4": [RL + "LoadYamlTest", RL + "CompileGroupsTest", RL + "GlobToRegexTest",
              RL + "TupleHelperTest", RL + "LoadedRuleSetTest"],
    "R-1-5": [RC + "OnPushTest", RC + "ConnectionEventTest", RC + "MainTest",
              RC + "ScriptEntrypointTest", PI + "WorkerLifecycleTest", PI + "MainEntrypointTest"],
    "R-1-6": [
        RP + "RealtimePipelineTest.test_mock_round_push_is_disabled_by_default",
        RP + "RealtimePipelineTest.test_mock_round_push_can_be_enabled",
        AU + "IsMockRoundTest",
        PI + "AnalysisPushTest.test_mock_round_is_analyzed_but_not_pushed",
        CF + "BoolEnvTest", CF + "SettingsTest",
    ],
}

TOOL_HIJACK_ROUNDS = ["6cc866d4", "e71e95be", "b44671f8", "326112c3", "2b6a4000"]


def run_subset(case_id: str, test_ids: list[str]) -> None:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for tid in test_ids:
        suite.addTests(loader.loadTestsFromName(tid))
    names = []
    def walk(s):
        for t in s:
            if isinstance(t, unittest.TestSuite):
                yield from walk(t)
            else:
                yield t
    for t in walk(suite):
        names.append(t.id().replace("tests.", ""))
    stream = io.StringIO()
    t0 = time.perf_counter()
    result = unittest.TextTestRunner(stream=stream, verbosity=0).run(suite)
    elapsed = time.perf_counter() - t0
    status = "OK" if result.wasSuccessful() else "FAILED"
    print(f"执行：python3 -m unittest " + " ".join(test_ids[:2])
          + (" ..." if len(test_ids) > 2 else ""))
    print(f"结果：Ran {result.testsRun} tests in {elapsed:.3f}s — {status}"
          f"（failures={len(result.failures)} errors={len(result.errors)}）")
    print(f"覆盖的测试用例（{len(names)} 项）：")
    for n in sorted(names):
        print(f"  - {n}")
    if not result.wasSuccessful():
        for who, tb in result.failures + result.errors:
            print(f"  !! {who}\n{tb}")


def corpus_s12() -> None:
    from lha_realtime.analyzer import analyze_round
    print("执行：回放声明工具为 safe_file_reader__read_text_audited 的 round，"
          "比对 IR 声明动作与内核观测动作")
    found = 0
    for d in sorted((PROJECT_ROOT / "input").iterdir()):
        if not d.is_dir():
            continue
        if not ((d / "kernel_lsm_hook_result.jsonl").is_file()
                and (d / "kernel_syscall_seq.jsonl").is_file()):
            continue
        try:
            r = analyze_round(d)
        except Exception:
            continue
        tools = {a.get("tool") for a in r["user_actions"] if a.get("tool")}
        if not any("read_text_audited" in (t or "") for t in tools):
            continue
        for t in r["anomaly_types"]:
            if t["type"] != "文件访问出现未授权动作":
                continue
            for it in t["items"]:
                found += 1
                print(f"  round {d.name}  声明工具={sorted(tools)}")
                print(f"    路径={it['path']}  IR 声明动作={it['allowed']}  "
                      f"超出声明的动作={it['extra']}  hook={it['hook_name']}  "
                      f"event_id={it['event_id']}")
    print(f"结果：命中 {found} 条“声明只读、实际写入”的记录")


def corpus_s13() -> None:
    from lha_realtime.analyzer import analyze_round
    print("执行：回放 " + "、".join(TOOL_HIJACK_ROUNDS)
          + "，比对内核侧 tool_name 与 action_json 声明工具，并记录异常判定")
    for rid in TOOL_HIJACK_ROUNDS:
        d = PROJECT_ROOT / "input" / rid
        if not d.is_dir():
            print(f"  round {rid}: 目录不存在，跳过")
            continue
        try:
            r = analyze_round(d)
        except Exception as exc:
            print(f"  round {rid}: 分析失败 {type(exc).__name__}")
            continue
        declared = sorted({a.get("tool") for a in r["user_actions"] if a.get("tool")})
        kernel = sorted({v.get("tool_name") for v in r["violations"] if v.get("tool_name")})
        diff = sorted(set(kernel) - set(declared))
        print(f"  round {rid}")
        print(f"    action_json 声明工具 = {declared}")
        print(f"    内核事件 tool_name   = {kernel}")
        print(f"    IR 允许工具          = {r['allowed_tools']}")
        print(f"    差集（内核−用户态）  = {diff if diff else '无'}")
        print(f"    模块判定 is_anomaly={r['is_anomaly']} "
              f"异常类型={[t['type'] for t in r['anomaly_types']]}")


def corpus_s14() -> None:
    from lha_realtime.analyzer import analyze_round
    print("执行：回放 6bc22d91，检查网络端点识别与回环抑制")
    r = analyze_round(PROJECT_ROOT / "input" / "6bc22d91")
    print(f"  network_endpoints（未忽略） = {r['network_endpoints']}")
    print(f"  network_observed            = {r['network_observed']}")
    print(f"  ignored_endpoints           = {r['network_ignored_endpoints']}")
    print(f"  suppressed                  = {r['network_suppressed']}")
    print(f"  is_anomaly={r['is_anomaly']} 异常类型={[t['type'] for t in r['anomaly_types']]}")


CORPUS_CASES = {"S-1-2": corpus_s12, "S-1-3": corpus_s13, "S-1-4": corpus_s14}

SCRIPT_CASES = {
    "P-1-1": "见 scripts/bench_replay.py 输出的「P-1-1 单 round 耗时」段落",
    "P-1-2": "见 scripts/bench_replay.py 输出的「P-1-2 全量回放」段落",
    "P-1-3": "见 for r in 5 10 20 50 100; do python3 scripts/loadtest.py --rate $r "
             "--rounds 500 --workers 4 --quiet; done 的输出",
    "P-1-4": "见 for w in 1 2 4 8; do python3 scripts/loadtest.py --rate 50 "
             "--rounds 500 --workers $w --quiet; done 的输出",
    "S-1-1": "见 scripts/bench_replay.py 输出的「语料统计」段落",
    "R-1-7": "见 python3 -m coverage run -m unittest discover -s tests && "
             "python3 -m coverage report 的输出",
}

ORDER = ([f"F-1-{i}" for i in range(1, 11)] + [f"P-1-{i}" for i in range(1, 5)]
         + [f"S-1-{i}" for i in range(1, 6)] + [f"R-1-{i}" for i in range(1, 8)])


def main() -> int:
    logging.disable(logging.CRITICAL)
    wanted = [a.upper() for a in sys.argv[1:]] or ORDER
    for case_id in ORDER:
        if case_id not in wanted:
            continue
        print("=" * 72)
        print(f"【{case_id}】")
        print("=" * 72)
        if case_id in CASE_TESTS:
            run_subset(case_id, CASE_TESTS[case_id])
        elif case_id in CORPUS_CASES:
            CORPUS_CASES[case_id]()
        elif case_id in SCRIPT_CASES:
            print(SCRIPT_CASES[case_id])
        else:
            print("（无映射）")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
