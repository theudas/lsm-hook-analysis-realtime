#!/usr/bin/env python3
"""白盒用例：detection_rules.yaml 的加载、容错与 glob 编译。

规则加载是"配置错了也不能把服务弄挂"的一段代码，这里逐个覆盖它的回退路径，
以及 glob_to_regex 的字符类/通配符编译分支——该函数同时服务于敏感规则匹配和
IR 文件标识匹配，编译错一个字符就会造成漏报或误报。
"""

from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lha_realtime import rules
from lha_realtime.rules import SensitiveRule, glob_to_regex, is_ignored_endpoint


def matches(pattern: str, path: str) -> bool:
    return re.fullmatch(glob_to_regex(pattern), path) is not None


class GlobToRegexTest(unittest.TestCase):
    def test_literal_pattern_matches_itself_only(self) -> None:
        self.assertTrue(matches("/tmp/a.txt", "/tmp/a.txt"))
        # 点号必须被转义，不能当成"任意字符"。
        self.assertFalse(matches("/tmp/a.txt", "/tmp/aXtxt"))

    def test_single_star_stays_inside_one_segment(self) -> None:
        """* 编译后只匹配单层路径段。"""
        self.assertTrue(matches("/tmp/*", "/tmp/a"))
        self.assertFalse(matches("/tmp/*", "/tmp/a/b"))

    def test_double_star_followed_by_slash_may_match_nothing(self) -> None:
        """**/ 允许匹配零层目录。"""
        self.assertTrue(matches("/w/**/x", "/w/x"))
        self.assertTrue(matches("/w/**/x", "/w/a/b/x"))

    def test_trailing_double_star_matches_everything_below(self) -> None:
        """结尾的 ** 匹配其下任意深度内容。"""
        self.assertTrue(matches("/w/**", "/w/a/b/c"))
        self.assertTrue(matches("/w/**", "/w/"))

    def test_question_mark_matches_exactly_one_non_slash_char(self) -> None:
        """? 匹配且仅匹配一个非 / 字符。"""
        self.assertTrue(matches("/tmp/?.txt", "/tmp/a.txt"))
        self.assertFalse(matches("/tmp/?.txt", "/tmp/ab.txt"))
        self.assertFalse(matches("/tmp/?.txt", "/tmp//.txt"))

    def test_character_class(self) -> None:
        """字符类 [abc] 按集合匹配。"""
        self.assertTrue(matches("/tmp/[abc].txt", "/tmp/b.txt"))
        self.assertFalse(matches("/tmp/[abc].txt", "/tmp/d.txt"))

    def test_negated_character_class_with_bang(self) -> None:
        self.assertTrue(matches("/tmp/[!abc].txt", "/tmp/d.txt"))
        self.assertFalse(matches("/tmp/[!abc].txt", "/tmp/a.txt"))

    def test_caret_inside_class_is_escaped_not_treated_as_negation(self) -> None:
        # glob 里 ^ 不是取反符号，应按字面量处理。
        self.assertTrue(matches("/tmp/[^ab].txt", "/tmp/^.txt"))
        self.assertTrue(matches("/tmp/[^ab].txt", "/tmp/a.txt"))

    def test_class_whose_first_char_is_a_closing_bracket(self) -> None:
        """形如 []a] 的字符类把首个 ] 当字面量。"""
        self.assertTrue(matches("/tmp/[]a].txt", "/tmp/].txt"))
        self.assertTrue(matches("/tmp/[]a].txt", "/tmp/a.txt"))

    def test_unterminated_class_falls_back_to_literal_bracket(self) -> None:
        """未闭合的 [ 退化为字面量，不产生非法正则。"""
        self.assertTrue(matches("/tmp/[abc", "/tmp/[abc"))

    def test_backslash_inside_class_is_escaped(self) -> None:
        """字符类内的反斜杠被正确转义。"""
        self.assertTrue(matches("/tmp/[\\a].txt", "/tmp/a.txt"))


class TupleHelperTest(unittest.TestCase):
    def test_non_list_input_falls_back_to_default(self) -> None:
        """配置项不是列表时回退到内置默认值。"""
        self.assertEqual(rules._tuple(None, ("d",)), ("d",))
        self.assertEqual(rules._tuple("string", ("d",)), ("d",))

    def test_blank_and_non_string_entries_are_dropped(self) -> None:
        """空串与非字符串条目被剔除。"""
        self.assertEqual(rules._tuple(["a", "", None, 3, "b"], ("d",)), ("a", "b"))

    def test_duplicates_are_removed_preserving_order(self) -> None:
        """重复条目去重且保持原顺序。"""
        self.assertEqual(rules._tuple(["b", "a", "b"], ()), ("b", "a"))

    def test_list_that_yields_nothing_falls_back_to_default(self) -> None:
        """列表清洗后为空时同样回退默认值。"""
        self.assertEqual(rules._tuple(["", None], ("d",)), ("d",))


class LoadYamlTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_missing_file_returns_empty_dict(self) -> None:
        """规则文件不存在时返回空字典，服务仍可启动。"""
        self.assertEqual(rules._load_yaml(self.root / "nope.yaml"), {})

    def test_malformed_yaml_returns_empty_dict(self) -> None:
        """YAML 语法错误时吞掉异常并回退默认规则。"""
        path = self.root / "bad.yaml"
        path.write_text("files: [unclosed\n", encoding="utf-8")
        self.assertEqual(rules._load_yaml(path), {})

    def test_non_mapping_yaml_returns_empty_dict(self) -> None:
        """YAML 顶层不是映射时视为无效配置。"""
        path = self.root / "list.yaml"
        path.write_text("- a\n- b\n", encoding="utf-8")
        self.assertEqual(rules._load_yaml(path), {})

    def test_valid_yaml_is_returned_as_dict(self) -> None:
        """合法 YAML 被正确解析为字典。"""
        path = self.root / "ok.yaml"
        path.write_text("files:\n  proc_self_is_runtime: false\n", encoding="utf-8")
        self.assertEqual(rules._load_yaml(path), {"files": {"proc_self_is_runtime": False}})

    def test_rules_path_honours_environment_override(self) -> None:
        """LHA_RULES_PATH 可覆盖默认规则文件路径。"""
        target = self.root / "custom.yaml"
        with patch.dict("os.environ", {"LHA_RULES_PATH": str(target)}):
            self.assertEqual(rules._rules_path(), target)

    def test_rules_path_defaults_to_packaged_file(self) -> None:
        """未设环境变量时使用随包发布的规则文件。"""
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(rules._rules_path(), rules.DEFAULT_RULES_PATH)


class CompileGroupsTest(unittest.TestCase):
    def test_non_list_input_yields_no_rules(self) -> None:
        """sensitive_groups 不是列表时编译结果为空。"""
        self.assertEqual(rules._compile_groups(None), ())
        self.assertEqual(rules._compile_groups({"id": "x"}), ())

    def test_non_dict_entries_are_skipped(self) -> None:
        """分组列表里的非字典条目被跳过。"""
        self.assertEqual(rules._compile_groups(["not-a-dict", 42]), ())

    def test_group_without_prefixes_or_globs_is_skipped(self) -> None:
        """既无 prefixes 也无 globs 的分组不生成规则。"""
        self.assertEqual(rules._compile_groups([{"id": "empty", "title": "t"}]), ())

    def test_override_runtime_groups_sort_first(self) -> None:
        """override_runtime 分组排在前面以穿透运行时白名单。"""
        compiled = rules._compile_groups(
            [
                {"id": "plain", "prefixes": ["/a"]},
                {"id": "override", "prefixes": ["/b"], "override_runtime": True},
            ]
        )
        self.assertEqual([rule.id for rule in compiled], ["override", "plain"])

    def test_defaults_are_applied_to_sparse_groups(self) -> None:
        """分组缺字段时套用 id/标题/等级/匹配方式的默认值。"""
        rule = rules._compile_groups([{"prefixes": ["/a"]}])[0]
        self.assertEqual(rule.id, "group_0")
        self.assertEqual(rule.title, "敏感资源")
        self.assertEqual(rule.severity, "high")
        self.assertEqual(rule.match, "any")
        self.assertFalse(rule.override_runtime)

    def test_unknown_match_value_degrades_to_any(self) -> None:
        """无法识别的 match 取值退化为 any。"""
        rule = rules._compile_groups([{"id": "m", "prefixes": ["/a"], "match": "read_only"}])[0]
        self.assertEqual(rule.match, "any")

    def test_globs_are_compiled_into_usable_regexes(self) -> None:
        """分组里的 globs 被编译成可用的匹配规则。"""
        rule = rules._compile_groups([{"id": "g", "globs": ["/**/id_rsa"]}])[0]
        self.assertTrue(rule.matches_path("/home/u/.ssh/id_rsa"))
        self.assertFalse(rule.matches_path("/home/u/.ssh/id_rsa.pub"))


class SensitiveRuleTest(unittest.TestCase):
    def rule(self, **overrides) -> SensitiveRule:
        base = {
            "id": "r",
            "title": "SSH 与私钥材料",
            "severity": "critical",
            "match": "any",
            "reason": "",
            "basis": "",
        }
        base.update(overrides)
        return SensitiveRule(**base)

    def test_prefix_match(self) -> None:
        """前缀匹配覆盖 /etc/shadow- 这类同前缀变体。"""
        rule = self.rule(prefixes=("/etc/shadow",))
        self.assertTrue(rule.matches_path("/etc/shadow-"))
        self.assertFalse(rule.matches_path("/etc/shad"))

    def test_rule_without_patterns_matches_nothing(self) -> None:
        """没有任何模式的规则不匹配任何路径。"""
        self.assertFalse(self.rule().matches_path("/anything"))

    def test_any_match_accepts_unknown_actions(self) -> None:
        """match=any 的分组在动作未知时仍然成立。"""
        self.assertTrue(self.rule().matches_actions(None))
        self.assertTrue(self.rule().matches_actions([]))

    def test_write_only_requires_a_known_write_action(self) -> None:
        """match=write_only 需实际观测到 write/create/delete 才成立。"""
        rule = self.rule(match="write_only")
        self.assertFalse(rule.matches_actions(None))
        self.assertFalse(rule.matches_actions(["read"]))
        self.assertTrue(rule.matches_actions(["read", "write"]))
        self.assertTrue(rule.matches_actions(["create"]))
        self.assertTrue(rule.matches_actions(["delete"]))

    def test_label_includes_attck_when_present(self) -> None:
        """报告标签在有 ATT&CK 编号时拼接编号。"""
        self.assertEqual(
            self.rule(attck=("T1552.004", "T1098.004")).label(),
            "SSH 与私钥材料（critical，ATT&CK T1552.004/T1098.004）",
        )

    def test_label_omits_attck_when_absent(self) -> None:
        """无 ATT&CK 编号时标签不留空后缀。"""
        self.assertEqual(self.rule().label(), "SSH 与私钥材料（critical）")


class IgnoredEndpointTest(unittest.TestCase):
    def test_empty_endpoint_is_not_ignored(self) -> None:
        """空端点不属于忽略集合。"""
        self.assertFalse(is_ignored_endpoint(None))
        self.assertFalse(is_ignored_endpoint(""))

    def test_plain_ip_port_matches(self) -> None:
        """裸 ip:port 形式能命中忽略集合。"""
        self.assertTrue(is_ignored_endpoint("127.0.0.1:15100"))

    def test_address_family_prefix_is_stripped(self) -> None:
        """带 AF_INET 前缀的端点串取末段比对。"""
        self.assertTrue(is_ignored_endpoint("AF_INET 127.0.0.1:15100"))

    def test_port_must_match_exactly(self) -> None:
        """端口不同或缺端口时不视为忽略端点。"""
        self.assertFalse(is_ignored_endpoint("127.0.0.1:15101"))
        self.assertFalse(is_ignored_endpoint("127.0.0.1"))

    def test_other_hosts_are_never_ignored(self) -> None:
        """非回环地址即使端口相同也不忽略。"""
        self.assertFalse(is_ignored_endpoint("AF_INET 8.152.192.7:15100"))


class LoadedRuleSetTest(unittest.TestCase):
    """打包的 detection_rules.yaml 必须真的被加载（而不是静默退回内置默认）。"""

    def test_packaged_yaml_is_present_and_parsed(self) -> None:
        """随包的 detection_rules.yaml 存在且能被解析。"""
        self.assertTrue(rules.DEFAULT_RULES_PATH.is_file())
        self.assertTrue(rules._load_yaml(rules.DEFAULT_RULES_PATH))

    def test_loaded_rule_ids_are_unique(self) -> None:
        """加载后的规则 id 不重复。"""
        ids = [rule.id for rule in rules.SENSITIVE_RULES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_runtime_prefix_tuples_are_non_empty(self) -> None:
        """运行时前缀、框架目录、忽略端点等集合均非空。"""
        self.assertTrue(rules.RUNTIME_PREFIXES)
        self.assertTrue(rules.OPENCLAW_RUNTIME_PREFIXES)
        self.assertTrue(rules.OPENCLAW_RUNTIME_BASENAMES)
        self.assertTrue(rules.IGNORED_NETWORK_ENDPOINTS)

    def test_builtin_defaults_compile_as_a_working_fallback(self) -> None:
        """内置默认分组可独立编译，作为规则文件缺失时的兜底。"""
        fallback = rules._compile_groups(list(rules._DEFAULT_SENSITIVE_GROUPS))
        self.assertTrue(fallback)
        self.assertTrue(fallback[0].override_runtime)


if __name__ == "__main__":
    unittest.main()
