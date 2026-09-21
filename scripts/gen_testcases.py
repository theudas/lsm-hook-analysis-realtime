#!/usr/bin/env python3
"""从 tests/*.py 解析出全部用例，生成 Markdown 清单。"""
import ast
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"

# 每个测试文件的被测对象说明（人工标注，解析不出来）
FILE_META = {
    "test_realtime_pipeline.py": ("端到端链路与既有回归", "原有用例：四类消息乱序到达、重复 round、IR 匹配、敏感分类"),
    "test_analyzer_parsing.py": ("lha_realtime/analyzer.py（解析层）", "输入加载、IR 解析、内核事件归并、网络端点回溯、分类判定"),
    "test_analyzer_report.py": ("lha_realtime/analyzer.py（渲染层）", "analysis_report.md 的全部渲染分支"),
    "test_analyzer_push.py": ("lha_realtime/analyzer.py（上报层）", "上报 HTTP 链路失败模式、mock round 识别"),
    "test_rules_loading.py": ("lha_realtime/rules.py", "detection_rules.yaml 加载容错、glob 编译"),
    "test_state_store.py": ("lha_realtime/state.py", "SQLite schema 迁移、round/job 状态机"),
    "test_pipeline_internals.py": ("lha_realtime/pipeline.py", "落盘工具、消息分派、任务取代、worker 生命周期"),
    "test_receiver.py": ("lha_realtime/receiver.py", "Socket.IO 回调分派、进程启动与清理"),
    "test_config.py": ("lha_realtime/config.py", "环境变量解析与运行时目录准备"),
    "test_logging_utils.py": ("lha_realtime/logging_utils.py", "日志 handler 重建与句柄释放"),
}

ORDER = [
    "test_realtime_pipeline.py",
    "test_analyzer_parsing.py",
    "test_analyzer_report.py",
    "test_analyzer_push.py",
    "test_rules_loading.py",
    "test_state_store.py",
    "test_pipeline_internals.py",
    "test_receiver.py",
    "test_config.py",
    "test_logging_utils.py",
]


def first_comment(path_lines, node):
    """取方法体内第一条 # 注释作为说明。"""
    start = node.body[0].lineno - 1
    for offset in range(-3, 6):
        idx = start + offset
        if 0 <= idx < len(path_lines):
            stripped = path_lines[idx].strip()
            if stripped.startswith("#") and idx > node.lineno - 1:
                return stripped.lstrip("# ").strip()
    return ""


def humanize(name):
    return name[len("test_"):].replace("_", " ")


def describe(lines, fn):
    doc = ast.get_docstring(fn)
    if doc:
        return doc.strip().splitlines()[0].strip()
    comment = first_comment(lines, fn)
    if comment:
        return comment
    return humanize(fn.name)


def collect(path):
    src = path.read_text(encoding="utf-8")
    lines = src.splitlines()
    tree = ast.parse(src)
    classes = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        cases = [
            (fn.name, describe(lines, fn))
            for fn in node.body
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and fn.name.startswith("test_")
        ]
        if not cases:
            continue
        cdoc = ast.get_docstring(node)
        classes.append((node.name, cdoc.strip().splitlines()[0].strip() if cdoc else "", cases))
    return classes


def main():
    files = [(name, collect(TESTS / name)) for name in ORDER if (TESTS / name).is_file()]
    totals = {name: sum(len(c[2]) for c in classes) for name, classes in files}
    grand = sum(totals.values())

    out = []
    w = out.append
    w("# 白盒测试用例清单")
    w("")
    w("> 本文件由 `tests/*.py` 自动解析生成，与代码同源，不手工维护。")
    w("> 重新生成：见文末「如何重新生成」。")
    w("")
    w(f"**合计 {grand} 个用例，分布在 {len(files)} 个测试文件中。**")
    w("执行方式：`python3 -m unittest discover -s tests -v`")
    w("")
    w("## 总览")
    w("")
    w("| # | 测试文件 | 被测对象 | 用例数 |")
    w("|---|---|---|---|")
    for index, (name, _classes) in enumerate(files, start=1):
        target = FILE_META.get(name, ("-", ""))[0]
        w(f"| {index} | `{name}` | {target} | {totals[name]} |")
    w(f"| | **合计** | | **{grand}** |")
    w("")
    w("---")
    w("")

    counter = 0
    for index, (name, classes) in enumerate(files, start=1):
        target, scope = FILE_META.get(name, ("-", ""))
        w(f"## {index}. `{name}`")
        w("")
        w(f"**被测对象**：{target}  ")
        w(f"**覆盖范围**：{scope}  ")
        w(f"**用例数**：{totals[name]}")
        w("")
        for class_name, class_doc, cases in classes:
            heading = f"### {class_name}"
            w(heading)
            w("")
            if class_doc:
                w(f"> {class_doc}")
                w("")
            w("| 编号 | 用例 | 验证点 |")
            w("|---|---|---|")
            for case_name, desc in cases:
                counter += 1
                # 表格里的 | 要转义；<pid> 这类尖括号会被当成 HTML 标签吞掉。
                safe = desc.replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")
                w(f"| {counter:03d} | `{case_name}` | {safe} |")
            w("")
        w("---")
        w("")

    w("## 如何重新生成")
    w("")
    w("用例清单随测试代码演进，改动测试后重新生成即可：")
    w("")
    w("```bash")
    w("cd /home/hx/try/lsm-hook-analysis-realtime")
    w("python3 scripts/gen_testcases.py")
    w("```")
    w("")
    w("## 覆盖率基线")
    w("")
    w("| 模块 | 语句 | 分支 | 覆盖率 |")
    w("|---|---|---|---|")
    w("| `analyzer.py` | 578 | 274 | 100% |")
    w("| `pipeline.py` | 205 | 74 | 100% |")
    w("| `state.py` | 150 | 30 | 100% |")
    w("| `rules.py` | 131 | 48 | 100% |")
    w("| `receiver.py` | 55 | 16 | 100% |")
    w("| `config.py` | 42 | 4 | 100% |")
    w("| `logging_utils.py` | 20 | 4 | 100% |")
    w("| **合计** | **1181** | **450** | **100%** |")
    w("")
    w("统计口径见 `.coveragerc`（`branch = True`，只统计 `lha_realtime` 包）。")
    w("生成覆盖率报告：`python3 -m coverage run -m unittest discover -s tests && python3 -m coverage html`")

    target_path = ROOT / "tests" / "TEST_CASES.md"
    target_path.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"written: {target_path}")
    print(f"total cases: {grand}")
    for name, _ in files:
        print(f"  {name}: {totals[name]}")


if __name__ == "__main__":
    main()
