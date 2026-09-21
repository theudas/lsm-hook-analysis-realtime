# 白盒测试用例清单

> 本文件由 `tests/*.py` 自动解析生成，与代码同源，不手工维护。
> 重新生成：见文末「如何重新生成」。

**合计 295 个用例，分布在 10 个测试文件中。**
执行方式：`python3 -m unittest discover -s tests -v`

## 总览

| # | 测试文件 | 被测对象 | 用例数 |
|---|---|---|---|
| 1 | `test_realtime_pipeline.py` | 端到端链路与既有回归 | 34 |
| 2 | `test_analyzer_parsing.py` | lha_realtime/analyzer.py（解析层） | 67 |
| 3 | `test_analyzer_report.py` | lha_realtime/analyzer.py（渲染层） | 20 |
| 4 | `test_analyzer_push.py` | lha_realtime/analyzer.py（上报层） | 20 |
| 5 | `test_rules_loading.py` | lha_realtime/rules.py | 43 |
| 6 | `test_state_store.py` | lha_realtime/state.py | 33 |
| 7 | `test_pipeline_internals.py` | lha_realtime/pipeline.py | 43 |
| 8 | `test_receiver.py` | lha_realtime/receiver.py | 16 |
| 9 | `test_config.py` | lha_realtime/config.py | 12 |
| 10 | `test_logging_utils.py` | lha_realtime/logging_utils.py | 7 |
| | **合计** | | **295** |

---

## 1. `test_realtime_pipeline.py`

**被测对象**：端到端链路与既有回归  
**覆盖范围**：原有用例：四类消息乱序到达、重复 round、IR 匹配、敏感分类  
**用例数**：34

### FileIdentifierMatcherTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 001 | `test_exact_path_only_matches_same_path` | 无通配符的 IR 标识只匹配完全相同的路径。 |
| 002 | `test_single_star_does_not_cross_path_segments` | 单个 * 只在一层路径段内匹配，不跨越 /。 |
| 003 | `test_double_star_crosses_path_segments` | ** 可跨越任意层目录匹配。 |
| 004 | `test_file_identifier_star_is_path_glob` | IR 文件标识里的 * 按路径 glob 解释，而非正则。 |
| 005 | `test_regex_uses_fullmatch` | 正则型标识用 fullmatch，不接受部分匹配。 |
| 006 | `test_invalid_regex_does_not_allow` | 非法正则标识不放行，避免异常造成漏判。 |

### AnalyzerActionMismatchTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 007 | `test_file_action_mismatch_marks_round_anomalous` | IR 只允许 read 而实际观测到 write/create 时判为异常。 |
| 008 | `test_inode_unlink_is_judged_as_delete_action` | inode_unlink 是删除文件的 LSM hook：IR 只允许 read 时，删除应作为未授权的 delete 动作被判定。 |
| 009 | `test_lsm_only_network_action_mismatch_marks_round_anomalous` | 仅凭 LSM socket hook（无对应 syscall）也能判出未授权网络动作。 |
| 010 | `test_localhost_15100_only_network_is_not_anomalous` | 工具去平台拉取线上配置：连接仅落在 127.0.0.1:15100 / ::1:15100，整轮网络按正常处理。 |
| 011 | `test_mixed_localhost_and_external_endpoint_still_flags_external` | 同时出现 127.0.0.1:15100（忽略）与 8.152.192.7:443（恶意）：仍判异常，只保留外部端点。 |
| 012 | `test_d04795d0_lsm_socket_hooks_mark_round_anomalous` | 真实 round d04795d0 回放：socket hook 应判出 send/receive 越权。 |

### RealtimePipelineTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 013 | `test_round_is_analyzed_after_all_messages_arrive` | 四类消息乱序到达，全部就位后才分析。 |
| 014 | `test_analysis_waits_until_round_start_arrives` | 缺少 round_start 时，即使其余三类消息齐备也不能触发分析。 |
| 015 | `test_second_round_end_updates_metadata_without_new_generation` | 迟到的 round_end 只刷新元数据，不改代次、不清掉已完成的报告。 |
| 016 | `test_replaying_one_required_message_reruns_using_persisted_inputs` | 已完成的 round 只重放一条必需消息（内核）也会用磁盘上的输入完整重跑。 |
| 017 | `test_replayed_round_reruns_full_pipeline_and_repushes` | 每次重放都完整重跑分析链路并再次上报。 |
| 018 | `test_ir_ready_after_kernel_unblocks_analysis` | 复现线上问题：IR 迟于内核消息到达时必须等齐后再用真实允许集分析。 |
| 019 | `test_empty_ir_round_end_does_not_trigger_premature_analysis` | round_end 携带空 IR 时不得提前触发分析。 |
| 020 | `test_burst_messages_are_queued_and_processed` | 20 个 round 突发到达时全部排队并处理完成。 |
| 021 | `test_analysis_failure_retries_then_marks_failed` | 分析失败先重试，达到次数上限后置为 analysis_failed。 |
| 022 | `test_analysis_uses_new_file_identifier_matching` | 端到端验证精确/glob/正则三类 IR 标识的放行结果。 |
| 023 | `test_pending_inbox_survives_store_reopen` | 未处理的 inbox 消息在重开库后仍能被消费。 |
| 024 | `test_mock_round_push_is_disabled_by_default` | 默认配置下 mock round 分析但不上报。 |
| 025 | `test_mock_round_push_can_be_enabled` | 开启 LHA_PUSH_MOCK_REPORTS 后 mock round 也会上报。 |

### SensitiveClassificationTest

> 敏感资源判定：detection_rules.yaml 中三条抑制误报的设计是否真的生效。

| 编号 | 用例 | 验证点 |
|---|---|---|
| 026 | `test_proc_self_access_is_runtime_but_cross_process_is_sensitive` | 进程读自己的 environ / maps 不跨越权限边界（真实数据中 28 次命中全属此类）。 |
| 027 | `test_proc_public_metadata_never_sensitive` | /proc/&lt;pid&gt;/stat、status 是 ps/top 正常读取的公开元信息，跨进程也不报。 |
| 028 | `test_openclaw_runtime_tree_is_runtime` | openclaw 自身运行时目录判为 runtime，不计入敏感。 |
| 029 | `test_credentials_override_openclaw_runtime_whitelist` | override_runtime 分组要能穿透运行时白名单，否则密钥藏进框架目录就检不出。 |
| 030 | `test_write_only_group_ignores_reads` | /etc/passwd 世界可读、glibc NSS 每轮都读；写入才等价于新增后门账号。 |
| 031 | `test_always_sensitive_paths_flag_on_read` | 凭据/私钥/进程内存类路径读取即判敏感。 |
| 032 | `test_lookalike_paths_do_not_false_positive` | 这些都是回放中真实出现过、按前缀一刀切会误伤的路径。 |
| 033 | `test_rules_carry_citable_rationale` | 报告要能说明"为什么这算敏感"，每组都必须带理由与依据。 |
| 034 | `test_violation_records_carry_rule_metadata` | 命中的敏感规则带 id 与 ATT&CK 编号，供报告引用。 |

---

## 2. `test_analyzer_parsing.py`

**被测对象**：lha_realtime/analyzer.py（解析层）  
**覆盖范围**：输入加载、IR 解析、内核事件归并、网络端点回溯、分类判定  
**用例数**：67

### LoaderTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 035 | `test_file_size_returns_zero_for_missing_path` | 文件不存在时 file_size 返回 0 而不是抛异常。 |
| 036 | `test_load_json_file_missing_returns_empty_dict` | JSON 文件缺失时返回空字典，分析链路继续。 |
| 037 | `test_load_json_file_propagates_decode_error` | JSON 内容损坏时向上抛出，由 worker 转为可重试失败。 |
| 038 | `test_load_jsonl_missing_returns_empty_list` | JSONL 文件缺失时返回空列表。 |
| 039 | `test_load_jsonl_skips_blank_lines` | JSONL 中的空行与纯空白行被跳过。 |
| 040 | `test_load_jsonl_propagates_decode_error` | JSONL 存在非法行时抛出解析错误并记录行号。 |

### LoadIrSourceTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 041 | `test_prefers_standalone_ir_json` | IR 优先取独立的 ir.json，而不是 round_end 里的副本。 |
| 042 | `test_empty_ir_json_falls_back_to_round_end` | ir.json 存在但内容为空时回退到 round_end.ir_json。 |
| 043 | `test_reads_round_end_from_disk_when_not_supplied` | 未传入 round_end 时自行从磁盘读取。 |
| 044 | `test_returns_empty_dict_when_no_ir_anywhere` | 两处都没有 IR 时返回空字典。 |

### ParseAllowlistTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 045 | `test_missing_ir_json_yields_empty_allowlist` | 缺少 ir_json 时得到空允许集，不误放行。 |
| 046 | `test_deny_policies_are_skipped` | effect 非 allow 的策略不进入允许集。 |
| 047 | `test_level2_policies_take_precedence_over_top_level` | level2.policies 优先于顶层 policies。 |
| 048 | `test_empty_file_identifier_is_ignored` | 空的 file identifier 被忽略，不会变成万能放行。 |
| 049 | `test_duplicate_actions_are_deduplicated_in_order` | 同一路径的多条策略动作合并去重且保序。 |
| 050 | `test_tool_and_network_objects_are_collected` | tool 与 network 类型对象分别归集，未知类型被忽略。 |

### ParseUserActionsAndFactsTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 051 | `test_parse_user_actions_defaults_missing_fields` | action_json 缺字段时 arguments/resources 退化为空值。 |
| 052 | `test_parse_user_actions_handles_missing_key` | round_end 没有 action_json 时返回空列表。 |
| 053 | `test_parse_resource_facts_empty_raw` | kernel_resource_facts 缺失或为空串时返回空列表。 |
| 054 | `test_parse_resource_facts_valid` | 正常的 kernel_resource_facts 被解析为事实列表。 |
| 055 | `test_parse_resource_facts_broken_json_returns_empty` | json.loads 成功但结果是 list，.get 抛 AttributeError，同样必须兜住。 |
| 056 | `test_parse_resource_facts_non_object_json_returns_empty` | json.loads 成功但结果是 list，.get 抛 AttributeError，同样必须兜住。 |

### NetworkHelperTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 057 | `test_is_network_hook` | 按 socket_ 前缀识别网络类 LSM hook，None 不误判。 |
| 058 | `test_network_hook_actions_only_maps_send_and_recv` | 只有 sendmsg/recvmsg 映射到 IR 动作，connect 等不产生动作。 |
| 059 | `test_net_group_covers_all_three_buckets` | 网络 hook 归入数据收发/连接管理/其他三组。 |
| 060 | `test_network_detail_returns_empty_for_file_hook` | 文件类 hook 不产生网络目标描述。 |
| 061 | `test_network_detail_unix_socket_path` | Unix 域套接字取 sun_path 作为目标。 |
| 062 | `test_network_detail_ipv4_with_and_without_port` | IPv4 目标带端口时拼成 ip:port，无端口时只留 ip。 |
| 063 | `test_network_detail_ipv6` | IPv6 目标从 sin6_addr/sin6_port 提取。 |
| 064 | `test_network_detail_without_any_target` | 无任何地址信息时返回空串。 |

### ConnectEndpointsTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 065 | `test_non_connect_syscalls_are_ignored` | 只有 connect 系统调用参与端点表构建。 |
| 066 | `test_unix_socket_connect_uses_sun_path` | 没有 remote_ip 时退回 sun_path 作为端点。 |
| 067 | `test_sockfd_arg_wins_over_top_level_fd` | 端点按 args.sockfd 归属，优先于顶层 fd。 |

### ParseNetworkActivityTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 068 | `test_endpoint_lookup_picks_latest_connect_before_the_send` | send 关联的是它之前最近一次 connect，而非之后的连接。 |
| 069 | `test_send_before_any_connect_falls_back_to_first_record` | 收发早于所有 connect 记录时回退到第一条连接。 |
| 070 | `test_unknown_fd_send_records_action_without_endpoint` | fd 无法关联端点时仍记录动作，不做整轮抑制。 |
| 071 | `test_lsm_hook_detail_contributes_endpoint` | LSM hook 自带的目标信息也计入端点集合。 |
| 072 | `test_no_network_activity_is_not_suppressed` | 既没有 remote_ip 也没有 sun_path：连接记录在案但端点为 None，不得进入端点集合。 |
| 073 | `test_connect_without_a_resolvable_target_contributes_no_endpoint` | 既没有 remote_ip 也没有 sun_path：连接记录在案但端点为 None，不得进入端点集合。 |

### ExtractKernelFileOpsTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 074 | `test_read_and_write_bytes_are_attributed_to_the_open` | 读写字节数与次数正确归属到对应的 open 事件。 |
| 075 | `test_bytes_after_fd_is_reopened_are_not_counted` | fd 被复用后的读写不得记到上一次 open 上。 |
| 076 | `test_negative_open_return_value_skips_attribution` | open 返回负值（失败）时不做字节归属。 |
| 077 | `test_io_before_the_open_is_not_attributed_to_it` | 同一个 (pid, fd) 在本次 open 之前的读写属于上一个文件，必须被窗口下界挡住。 |
| 078 | `test_missing_related_syscall_leaves_syscall_fields_none` | 关联不到 syscall 时相关字段留空而不报错。 |
| 079 | `test_action_defaults_to_read_when_nothing_observed` | 既无 flags 也无读写记录时保守记为 read。 |
| 080 | `test_rmdir_hook_is_a_delete_action` | inode_rmdir 映射为 delete 动作。 |
| 081 | `test_ops_are_sorted_by_timestamp` | 输出的文件操作按时间戳升序排列。 |

### FlagsToActionsTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 082 | `test_empty_flags` | flags 为空或 None 时不产生任何动作。 |
| 083 | `test_flag_combinations` | O_RDONLY/O_WRONLY/O_RDWR/O_CREAT/O_TRUNC 各自映射到正确动作。 |

### PatternMatchingTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 084 | `test_is_regex_pattern_detects_metacharacters` | 按元字符启发式区分正则与普通路径。 |
| 085 | `test_empty_identifier_never_matches` | 空 identifier 永不匹配，不会放行任意路径。 |
| 086 | `test_none_path_never_matches` | 路径为 None 时不匹配任何标识。 |
| 087 | `test_plain_identifier_without_wildcards_requires_exact_match` | 无通配符标识不做前缀匹配，必须完全相等。 |
| 088 | `test_is_allowed_handles_none_path_and_empty_set` | 空路径或空允许集时一律不放行。 |
| 089 | `test_matching_allowed_actions_unions_every_matching_identifier` | 路径命中多条标识时取动作并集，未命中返回 None。 |

### ClassificationEdgeTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 090 | `test_none_path_is_unknown` | 路径为 None 时分类为 unknown 且不命中敏感规则。 |
| 091 | `test_unrelated_path_is_other` | 既非敏感也非运行时的路径归为 other。 |
| 092 | `test_openclaw_doc_basename_outside_prefix_is_runtime` | AGENT.md 等框架文档在 workspace/.openclaw 下判为 runtime。 |
| 093 | `test_proc_self_access_requires_an_op` | 缺少操作上下文时不能判定为读自身 /proc。 |
| 094 | `test_proc_self_access_needs_a_pid_shaped_path` | 路径不含数字 pid 段时不走 proc self 判定。 |
| 095 | `test_proc_self_rule_can_be_disabled` | observed_actions 缺失时 write_only 组保守放行（op=None → actions=None）。 |
| 096 | `test_write_only_rule_with_unknown_actions_is_not_sensitive` | observed_actions 缺失时 write_only 组保守放行（op=None → actions=None）。 |

### DetectAnomaliesTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 097 | `test_no_input_means_no_anomaly` | 无越权无网络动作时判定为正常。 |
| 098 | `test_non_sensitive_violations_do_not_create_a_sensitive_type` | 非敏感类越权与空路径不产生敏感异常项。 |
| 099 | `test_sensitive_hits_merge_actions_per_path` | 同一敏感路径的多次命中合并动作后输出一条。 |
| 100 | `test_file_op_within_allowed_actions_is_not_a_mismatch` | 实际动作在允许集合内时不算未授权。 |
| 101 | `test_network_action_outside_allowlist_is_flagged` | 网络动作超出允许集时输出异常项并附带目标端点。 |

---

## 3. `test_analyzer_report.py`

**被测对象**：lha_realtime/analyzer.py（渲染层）  
**覆盖范围**：analysis_report.md 的全部渲染分支  
**用例数**：20

### ReportRenderingTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 102 | `test_clean_round_reports_no_anomaly` | 无异常的 round 报告写明「否」「无」，且含报告生成时间。 |
| 103 | `test_sensitive_anomaly_groups_paths_and_prints_rationale` | 同一敏感分组的多个路径聚合成一条，并输出判定理由与规则依据。 |
| 104 | `test_sensitive_anomaly_without_metadata_falls_back_to_defaults` | 缺少标题/等级时退化为「敏感资源」与 high，不输出空理由。 |
| 105 | `test_sensitive_anomaly_with_empty_items_list` | items 为空或 None 时标题仍渲染，不抛异常。 |
| 106 | `test_file_action_mismatch_is_rendered_with_event_id` | 文件未授权动作一行写清允许集、实际动作与 event_id。 |
| 107 | `test_all_three_anomaly_types_render_together` | 三类异常同时命中时，渲染循环必须依次处理完每一项而不是在第一项后停下。 |
| 108 | `test_network_mismatch_with_and_without_endpoints` | 网络未授权动作在有/无目标端点两种情况下的渲染。 |
| 109 | `test_unrecognised_anomaly_type_is_skipped_without_breaking_the_report` | 渲染器只认三种类型；将来新增类型时不应让报告生成失败，而是安静跳过。 |
| 110 | `test_allowlist_and_user_actions_are_listed` | IR 允许文件/工具与用户态实际调用被完整列出。 |
| 111 | `test_all_four_categories_render_their_own_table` | 敏感/其他/运行时/未知四类各出一张表，敏感表多一列依据。 |
| 112 | `test_sensitive_entry_without_attck_omits_the_suffix` | 没有 ATT&CK 编号时依据列不拼接空后缀。 |
| 113 | `test_conflicting_judges_on_one_path_render_as_partial` | 同一路径两个判据结论不一致时判据列显示「部分」。 |
| 114 | `test_read_bytes_none_is_treated_as_zero` | ---------- 网络越权清单 ---------- |
| 115 | `test_network_groups_are_rendered_in_fixed_order` | 网络表按数据收发→连接管理→其他固定顺序输出。 |
| 116 | `test_unknown_network_hook_uses_its_own_name_as_behavior` | 未登记的 socket hook 用自身名称作为行为描述。 |
| 117 | `test_suppressed_network_reports_ignored_endpoints` | 整轮网络被抑制时说明原因并列出忽略端点。 |
| 118 | `test_suppressed_network_without_listed_endpoints` | ---------- 内核资源事实 ---------- |
| 119 | `test_resource_facts_table_is_appended_when_present` | 内核资源事实表正常渲染，缺字段退化为空单元格。 |
| 120 | `test_violations_jsonl_carries_round_id_on_every_line` | 违规明细每行都带 round_id，便于后续汇总。 |
| 121 | `test_rewriting_outputs_truncates_the_previous_run` | 重跑分析时覆盖写，不残留上一次的违规记录。 |

---

## 4. `test_analyzer_push.py`

**被测对象**：lha_realtime/analyzer.py（上报层）  
**覆盖范围**：上报 HTTP 链路失败模式、mock round 识别  
**用例数**：20

### IsMockRoundTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 122 | `test_empty_round_dir_is_not_mock` | 目录里没有任何元数据文件时不判为 mock。 |
| 123 | `test_is_mock_true_in_round_end` | round_end / round_kernel 都不带标记时，仍要检查最后一个来源 ir.json。 |
| 124 | `test_is_mock_true_only_in_ir_is_still_detected` | round_end / round_kernel 都不带标记时，仍要检查最后一个来源 ir.json。 |
| 125 | `test_corrupt_metadata_file_is_skipped_not_fatal` | 显式用 is True 比较：字符串 "true" 不算 mock。 |
| 126 | `test_non_boolean_true_is_not_treated_as_mock` | 显式用 is True 比较：字符串 "true" 不算 mock。 |

### PushKernelReportTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 127 | `test_successful_push_returns_parsed_response` | 上报成功返回解析后的响应，请求体含 round_id 与报告绝对路径。 |
| 128 | `test_http_error_is_wrapped_as_runtime_error` | HTTP 错误码被包装为带状态码的 RuntimeError。 |
| 129 | `test_url_error_is_wrapped_as_runtime_error` | 连接失败（URLError）被包装为 RuntimeError。 |
| 130 | `test_non_json_response_is_rejected` | 响应不是 JSON 时判为上报失败。 |
| 131 | `test_response_without_ok_true_is_rejected` | 响应缺少 ok=true（含字符串 'true'）时判为上报失败。 |
| 132 | `test_push_of_a_missing_report_file_still_attempts_the_call` | 报告文件不存在只是日志里的一个字段，不应短路上报。 |

### MarkAndPushTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 133 | `test_marker_records_endpoint_and_response` | 上报 marker 记录 round_id、接口地址与响应内容。 |
| 134 | `test_push_and_mark_writes_marker_on_success` | 上报成功后写入 marker 文件。 |
| 135 | `test_push_and_mark_returns_false_and_skips_marker_on_failure` | 上报失败时返回 False 且不写 marker，避免误标已上报。 |

### AnalyzeWriteAndPushTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 136 | `test_push_disabled_only_writes_outputs` | push=False 时只产出报告，不调用上报。 |
| 137 | `test_mock_round_is_never_pushed` | mock round 在该入口一律不上报。 |
| 138 | `test_successful_push_path` | 正常 round 走完分析→写报告→上报全链路。 |
| 139 | `test_failed_push_raises` | 上报失败时抛出异常，交由上层重试。 |

### AnalyzeRoundMetadataTest

> analyze_round 里把命中的敏感规则元数据写进 violation 记录的分支。

| 编号 | 用例 | 验证点 |
|---|---|---|
| 140 | `test_sensitive_violation_carries_rule_metadata_and_counts` | 敏感越权记录带规则 id、等级、ATT&CK、理由与依据，且两判据一致。 |
| 141 | `test_round_id_falls_back_to_directory_name` | round_end/round_start 都没有 round_id 时回落到目录名。 |

---

## 5. `test_rules_loading.py`

**被测对象**：lha_realtime/rules.py  
**覆盖范围**：detection_rules.yaml 加载容错、glob 编译  
**用例数**：43

### GlobToRegexTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 142 | `test_literal_pattern_matches_itself_only` | 点号必须被转义，不能当成"任意字符"。 |
| 143 | `test_single_star_stays_inside_one_segment` | * 编译后只匹配单层路径段。 |
| 144 | `test_double_star_followed_by_slash_may_match_nothing` | **/ 允许匹配零层目录。 |
| 145 | `test_trailing_double_star_matches_everything_below` | 结尾的 ** 匹配其下任意深度内容。 |
| 146 | `test_question_mark_matches_exactly_one_non_slash_char` | ? 匹配且仅匹配一个非 / 字符。 |
| 147 | `test_character_class` | 字符类 [abc] 按集合匹配。 |
| 148 | `test_negated_character_class_with_bang` | glob 里 ^ 不是取反符号，应按字面量处理。 |
| 149 | `test_caret_inside_class_is_escaped_not_treated_as_negation` | glob 里 ^ 不是取反符号，应按字面量处理。 |
| 150 | `test_class_whose_first_char_is_a_closing_bracket` | 形如 []a] 的字符类把首个 ] 当字面量。 |
| 151 | `test_unterminated_class_falls_back_to_literal_bracket` | 未闭合的 [ 退化为字面量，不产生非法正则。 |
| 152 | `test_backslash_inside_class_is_escaped` | 字符类内的反斜杠被正确转义。 |

### TupleHelperTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 153 | `test_non_list_input_falls_back_to_default` | 配置项不是列表时回退到内置默认值。 |
| 154 | `test_blank_and_non_string_entries_are_dropped` | 空串与非字符串条目被剔除。 |
| 155 | `test_duplicates_are_removed_preserving_order` | 重复条目去重且保持原顺序。 |
| 156 | `test_list_that_yields_nothing_falls_back_to_default` | 列表清洗后为空时同样回退默认值。 |

### LoadYamlTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 157 | `test_missing_file_returns_empty_dict` | 规则文件不存在时返回空字典，服务仍可启动。 |
| 158 | `test_malformed_yaml_returns_empty_dict` | YAML 语法错误时吞掉异常并回退默认规则。 |
| 159 | `test_non_mapping_yaml_returns_empty_dict` | YAML 顶层不是映射时视为无效配置。 |
| 160 | `test_valid_yaml_is_returned_as_dict` | 合法 YAML 被正确解析为字典。 |
| 161 | `test_rules_path_honours_environment_override` | LHA_RULES_PATH 可覆盖默认规则文件路径。 |
| 162 | `test_rules_path_defaults_to_packaged_file` | 未设环境变量时使用随包发布的规则文件。 |

### CompileGroupsTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 163 | `test_non_list_input_yields_no_rules` | sensitive_groups 不是列表时编译结果为空。 |
| 164 | `test_non_dict_entries_are_skipped` | 分组列表里的非字典条目被跳过。 |
| 165 | `test_group_without_prefixes_or_globs_is_skipped` | 既无 prefixes 也无 globs 的分组不生成规则。 |
| 166 | `test_override_runtime_groups_sort_first` | override_runtime 分组排在前面以穿透运行时白名单。 |
| 167 | `test_defaults_are_applied_to_sparse_groups` | 分组缺字段时套用 id/标题/等级/匹配方式的默认值。 |
| 168 | `test_unknown_match_value_degrades_to_any` | 无法识别的 match 取值退化为 any。 |
| 169 | `test_globs_are_compiled_into_usable_regexes` | 分组里的 globs 被编译成可用的匹配规则。 |

### SensitiveRuleTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 170 | `test_prefix_match` | 前缀匹配覆盖 /etc/shadow- 这类同前缀变体。 |
| 171 | `test_rule_without_patterns_matches_nothing` | 没有任何模式的规则不匹配任何路径。 |
| 172 | `test_any_match_accepts_unknown_actions` | match=any 的分组在动作未知时仍然成立。 |
| 173 | `test_write_only_requires_a_known_write_action` | match=write_only 需实际观测到 write/create/delete 才成立。 |
| 174 | `test_label_includes_attck_when_present` | 报告标签在有 ATT&CK 编号时拼接编号。 |
| 175 | `test_label_omits_attck_when_absent` | 无 ATT&CK 编号时标签不留空后缀。 |

### IgnoredEndpointTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 176 | `test_empty_endpoint_is_not_ignored` | 空端点不属于忽略集合。 |
| 177 | `test_plain_ip_port_matches` | 裸 ip:port 形式能命中忽略集合。 |
| 178 | `test_address_family_prefix_is_stripped` | 带 AF_INET 前缀的端点串取末段比对。 |
| 179 | `test_port_must_match_exactly` | 端口不同或缺端口时不视为忽略端点。 |
| 180 | `test_other_hosts_are_never_ignored` | 非回环地址即使端口相同也不忽略。 |

### LoadedRuleSetTest

> 打包的 detection_rules.yaml 必须真的被加载（而不是静默退回内置默认）。

| 编号 | 用例 | 验证点 |
|---|---|---|
| 181 | `test_packaged_yaml_is_present_and_parsed` | 随包的 detection_rules.yaml 存在且能被解析。 |
| 182 | `test_loaded_rule_ids_are_unique` | 加载后的规则 id 不重复。 |
| 183 | `test_runtime_prefix_tuples_are_non_empty` | 运行时前缀、框架目录、忽略端点等集合均非空。 |
| 184 | `test_builtin_defaults_compile_as_a_working_fallback` | 内置默认分组可独立编译，作为规则文件缺失时的兜底。 |

---

## 6. `test_state_store.py`

**被测对象**：lha_realtime/state.py  
**覆盖范围**：SQLite schema 迁移、round/job 状态机  
**用例数**：33

### HelperTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 185 | `test_now_iso_has_second_precision` | 中文按 UTF-8 计 3 字节，确保日志里的 size 是真实字节数。 |
| 186 | `test_json_size_counts_utf8_bytes_not_characters` | 中文按 UTF-8 计 3 字节，确保日志里的 size 是真实字节数。 |

### SchemaMigrationTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 187 | `test_pre_ir_database_gains_the_new_columns` | 模拟 has_ir / round_start 相关列引入之前建的库。 |

### InboxTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 188 | `test_enqueue_records_type_round_id_and_size` | 入库消息记录 push_type、round_id、字节数并初始为 pending。 |
| 189 | `test_payload_without_known_keys_is_still_accepted` | 不带已知字段的 payload 也接收入库，不丢消息。 |
| 190 | `test_fetch_marks_messages_processing_and_counts_attempts` | 已被取走的消息不会再次出现在 pending 里。 |
| 191 | `test_fetch_respects_limit_and_id_order` | 取消息按 id 升序并遵守条数上限。 |
| 192 | `test_fetch_on_empty_inbox_returns_empty_list` | inbox 为空时返回空列表。 |
| 193 | `test_fail_without_retry_is_terminal` | 标记为不可重试的消息置 failed 且不再被取出。 |
| 194 | `test_complete_message_stores_generation_and_keeps_old_value_on_none` | 完成消息时记录代次，传 None 不覆盖已有值。 |

### RoundStateTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 195 | `test_first_message_creates_generation_one` | 首条消息为 round 建档，代次从 1 开始。 |
| 196 | `test_orphan_artifacts_on_first_sight_request_a_clear` | 首次见到但磁盘有残留产物时要求清理。 |
| 197 | `test_existing_round_without_force_keeps_its_generation` | 未强制新代次时沿用当前代次。 |
| 198 | `test_unknown_round_has_no_current_generation` | 查询未知 round 返回 None 而不是抛异常。 |
| 199 | `test_unsupported_input_kind_is_rejected` | 非法的输入类型直接抛 ValueError。 |
| 200 | `test_recording_against_a_missing_generation_raises` | 针对不存在的代次写入时显式报错。 |
| 201 | `test_round_only_becomes_ready_after_all_four_inputs` | 四类输入全部就位后 round 才转为 ready。 |
| 202 | `test_kernel_paths_are_only_overwritten_by_non_null_values` | 重复的 round_kernel 不会把已有内核文件路径覆盖成空。 |
| 203 | `test_replay_bumps_generation_and_keeps_persisted_inputs` | 重放推进代次但保留磁盘输入与就绪标记。 |
| 204 | `test_replay_cancels_an_in_flight_job` | 重放会取消在途分析任务并标注取代原因。 |
| 205 | `test_finished_jobs_are_not_cancelled_by_a_replay` | 重放不会改写已完成任务的状态。 |

### AnalysisJobTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 206 | `test_enqueue_is_idempotent_per_generation` | 同一代次重复入队只产生一个任务。 |
| 207 | `test_enqueue_moves_round_from_ready_to_queued` | 入队后 round 状态转 queued 并记录任务 id。 |
| 208 | `test_fetch_on_empty_queue_returns_none` | 队列为空时取任务返回 None。 |
| 209 | `test_fetch_claims_the_oldest_job_exactly_once` | 任务按 id 顺序被独占取走，不会重复分发。 |
| 210 | `test_status_transitions_propagate_to_the_round` | 任务状态变更同步反映到 round 状态。 |
| 211 | `test_failure_with_retry_requeues_the_job` | 可重试的失败把任务放回队列并累加尝试次数。 |
| 212 | `test_failure_without_retry_is_terminal` | 不可重试的失败置 analysis_failed 且不再出队。 |
| 213 | `test_operations_on_an_unknown_job_are_silent_no_ops` | 任务行被并发清掉时这些调用必须安静返回，而不是抛异常打断 worker。 |
| 214 | `test_enqueue_raises_if_the_job_row_cannot_be_read_back` | 防御性分支：INSERT 之后立刻回读不到行（并发删库/磁盘异常），必须显式报错， |
| 215 | `test_counts_reflect_pending_and_queued_work` | 计数接口如实反映待处理消息与排队任务数。 |

### PersistenceTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 216 | `test_state_survives_a_reopen` | round 与任务状态在重开库后完整保留。 |
| 217 | `test_explicit_db_path_argument_wins_over_settings` | 显式传入的 db_path 优先于配置项。 |

---

## 7. `test_pipeline_internals.py`

**被测对象**：lha_realtime/pipeline.py  
**覆盖范围**：落盘工具、消息分派、任务取代、worker 生命周期  
**用例数**：43

### SafeLenTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 218 | `test_none_is_zero` | None 的长度按 0 处理，日志摘要不报错。 |
| 219 | `test_non_string_values_are_stringified` | 非字符串值先转字符串再取长度。 |

### FileHelperTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 220 | `test_atomic_write_creates_parents_and_leaves_no_temp_file` | 原子写自动建父目录且不残留临时文件。 |
| 221 | `test_atomic_write_overwrites_in_place` | 重复写入同一路径时原地覆盖。 |
| 222 | `test_is_within_input_dir` | 正确区分 input 目录内外的路径。 |
| 223 | `test_path_traversal_escape_is_rejected` | 带 .. 的穿越路径被判定为越界。 |
| 224 | `test_has_round_artifacts` | 按已知产物文件名判断目录是否有残留。 |
| 225 | `test_clear_round_dir_refuses_paths_outside_input_dir` | 拒绝清理 input 目录之外的路径，防止误删。 |
| 226 | `test_clear_round_dir_removes_inputs_dotfiles_and_analysis_dirs` | 清理输入、临时点文件与 analysis_ 目录，保留无关文件。 |
| 227 | `test_clear_round_dir_creates_a_missing_directory` | 目录不存在时先创建再清理。 |
| 228 | `test_copy_kernel_file_handles_missing_sources` | 源目录不是文件时同样跳过，而不是抛异常。 |
| 229 | `test_copy_kernel_file_copies_content_atomically` | 内核文件按原子方式拷贝且不留临时文件。 |

### MessageDispatchTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 230 | `test_non_dict_payload_is_ignored` | payload 不是字典时忽略且不建 round。 |
| 231 | `test_message_without_round_id_is_ignored` | 缺少 round_id 的消息被丢弃并标记处理完成。 |
| 232 | `test_unhandled_push_type_is_ignored` | 未支持的 push_type 不落盘、不建状态。 |
| 233 | `test_empty_ir_ready_is_skipped_without_marking_has_ir` | 空 IR 的 round_ir_ready 不置 has_ir，继续等待真实 IR。 |
| 234 | `test_legacy_round_end_ir_json_is_adopted_when_no_standalone_ir` | 旧上游把 IR 放在 round_end 里时被采纳并触发就绪。 |
| 235 | `test_persist_ir_writes_and_flags_without_an_emptiness_check` | _persist_ir 是 round_end 兼容路径直接调用的版本：调用方已确认 ir_json 非空， |
| 236 | `test_record_ir_returns_none_only_for_an_empty_payload` | _record_ir 仅在 ir_json 为空时返回 None。 |
| 237 | `test_standalone_ir_wins_over_a_later_round_end_ir_json` | 已有独立 IR 后，迟到的 round_end.ir_json 不覆盖它。 |
| 238 | `test_kernel_files_that_cannot_be_copied_leave_paths_null` | 内核文件拷贝失败时路径留空，但 round_kernel 仍算到达。 |
| 239 | `test_orphan_artifacts_without_state_are_cleared_before_reuse` | 有产物无状态的目录在复用前被清理干净。 |

### NewGenerationDecisionTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 240 | `test_unknown_round_without_artifacts_stays_on_generation_one` | 全新 round 且目录干净时不触发新代次。 |
| 241 | `test_unknown_round_with_artifacts_forces_a_clear` | 无状态但有产物时要求先清理再处理。 |
| 242 | `test_metadata_messages_never_start_a_new_generation` | round_end/round_start 等元数据消息不触发重跑。 |
| 243 | `test_required_input_on_a_settled_round_starts_a_re_run` | 已结束的 round 再收到 IR 或内核消息时触发重跑。 |
| 244 | `test_required_input_while_still_receiving_overwrites_in_place` | round 仍在收集阶段时重复消息原地覆盖，不换代次。 |
| 245 | `test_failed_round_is_terminal_and_can_be_replayed` | 分析失败的 round 属终态，可被重放重跑。 |

### IngestFailureTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 246 | `test_transient_failure_is_requeued_until_max_attempts` | max_attempts=2，第一次失败后仍可重试。 |
| 247 | `test_one_bad_message_does_not_block_the_rest_of_the_batch` | 单条消息处理失败不影响同批次其余消息。 |

### AnalysisSupersessionTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 248 | `test_job_superseded_before_analysis_is_abandoned` | 任务在分析前已被取代时直接放弃，不做无谓分析。 |
| 249 | `test_job_superseded_during_analysis_does_not_write_outputs` | 分析过程中被取代时不写出报告，避免覆盖新结果。 |
| 250 | `test_job_superseded_before_push_does_not_report` | 上报前被取代时不上报，避免推送过期报告。 |
| 251 | `test_superseded_job_is_not_retried_even_below_max_attempts` | 被取代的任务重试没有意义，必须直接置 failed 而不是回到 queued。 |

### AnalysisPushTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 252 | `test_push_failure_marks_the_job_failed` | 上报失败经重试后任务置 analysis_failed 并记录原因。 |
| 253 | `test_mock_round_is_analyzed_but_not_pushed` | mock round 正常生成报告但跳过上报。 |
| 254 | `test_analyze_once_on_empty_queue_returns_false` | 队列为空时分析循环返回 False 以进入休眠。 |

### WorkerLifecycleTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 255 | `test_start_spawns_one_ingest_worker_and_n_analysis_workers` | 启动后线程数与命名符合配置的 worker 数量。 |
| 256 | `test_zero_or_negative_worker_setting_still_starts_one_worker` | worker 数配成 0 时兜底启动一个分析线程。 |
| 257 | `test_running_workers_process_a_round_end_to_end` | 真实多线程环境下完整处理一个 round 到 done。 |
| 258 | `test_stop_is_observed_by_both_loops` | 已置位时循环体直接退出，不会阻塞。 |

### MainEntrypointTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 259 | `test_main_starts_logs_a_heartbeat_then_stops_on_interrupt` | main 启动 worker、打心跳日志，收到中断后停止并回收。 |
| 260 | `test_module_entrypoint_runs_main` | `python3 -m lha_realtime.pipeline` 走 __main__ 分支。 |

---

## 8. `test_receiver.py`

**被测对象**：lha_realtime/receiver.py  
**覆盖范围**：Socket.IO 回调分派、进程启动与清理  
**用例数**：16

### OnPushTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 261 | `test_handlers_are_registered_on_the_client` | 回调函数已注册到 Socket.IO 客户端上。 |
| 262 | `test_non_dict_message_is_dropped` | 非字典消息（字符串/列表/None/数字）一律丢弃。 |
| 263 | `test_message_without_round_id_is_dropped` | 缺少 round_id 的推送不入库。 |
| 264 | `test_empty_round_id_is_treated_as_missing` | round_id 为空串等同缺失，不入库。 |
| 265 | `test_round_start_is_enqueued_verbatim` | round_start 原样入库，不在接收端做裁剪。 |
| 266 | `test_round_end_summary_tolerates_missing_fields` | action_json / ir_json 缺失时 safe_len 返回 0，摘要日志不能抛异常。 |
| 267 | `test_round_end_with_full_payload` | 字段齐全的 round_end 摘要日志与入库均正常。 |
| 268 | `test_round_kernel_summary` | round_kernel 的内核文件路径摘要与入库。 |
| 269 | `test_round_ir_ready_summary` | round_ir_ready 的 IR 长度摘要与入库。 |
| 270 | `test_unknown_push_type_is_still_persisted` | 接收端不做过滤：未知类型也入库，由 pipeline 决定忽略，避免丢消息。 |
| 271 | `test_missing_push_type_is_still_persisted` | 没有 push_type 的消息同样入库，交由 pipeline 判断。 |

### ConnectionEventTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 272 | `test_connect_and_disconnect_handlers_are_side_effect_free` | 连接与断开回调只记日志，不产生数据副作用。 |

### MainTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 273 | `test_main_starts_workers_then_connects_with_websocket_transport` | main 先起 worker 再按配置的 path/namespace 建立 websocket 连接。 |

### ScriptEntrypointTest

> `python3 -m lha_realtime.receiver` 的 try/except/finally 清理路径。

| 编号 | 用例 | 验证点 |
|---|---|---|
| 274 | `test_normal_exit_stops_pipeline_and_closes_the_store` | 正常退出时停 worker、断开连接、关闭数据库。 |
| 275 | `test_keyboard_interrupt_still_runs_the_cleanup` | 收到 Ctrl+C 中断时清理逻辑照常执行。 |
| 276 | `test_cleanup_skips_disconnect_when_never_connected` | 从未连上时跳过 disconnect，不产生多余调用。 |

---

## 9. `test_config.py`

**被测对象**：lha_realtime/config.py  
**覆盖范围**：环境变量解析与运行时目录准备  
**用例数**：12

### IntEnvTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 277 | `test_unset_variable_uses_the_default` | 整型环境变量未设置时使用默认值。 |
| 278 | `test_valid_value_is_parsed` | 合法整数字符串被正确解析。 |
| 279 | `test_negative_and_zero_are_accepted` | 负数与 0 都是合法取值。 |
| 280 | `test_non_integer_fails_loudly_with_the_variable_name` | 非整数取值在启动阶段报错并指明变量名。 |
| 281 | `test_empty_string_is_an_error_not_the_default` | 空串视为配置错误而非回退默认值。 |

### BoolEnvTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 282 | `test_unset_variable_uses_the_default` | 布尔型环境变量未设置时使用默认值。 |
| 283 | `test_accepted_truthy_spellings` | 1/true/yes/y/on 及大小写与空格变体均为真。 |
| 284 | `test_everything_else_is_false` | 其余取值一律为假，不做宽松解释。 |

### SettingsTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 285 | `test_defaults_are_self_consistent` | 默认配置自洽：上报地址基于 API 根地址，库路径在状态目录下。 |
| 286 | `test_settings_are_frozen` | 配置对象不可变，运行期无法被意外改写。 |
| 287 | `test_overrides_are_honoured` | 显式传入的配置项覆盖默认值。 |

### EnsureRuntimeDirsTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 288 | `test_creates_all_three_directories_and_is_idempotent` | input/logs/state 三个目录被创建且可重复调用。 |

---

## 10. `test_logging_utils.py`

**被测对象**：lha_realtime/logging_utils.py  
**覆盖范围**：日志 handler 重建与句柄释放  
**用例数**：7

### SetupLoggingTest

| 编号 | 用例 | 验证点 |
|---|---|---|
| 289 | `test_creates_the_log_dir_and_attaches_both_handlers` | 创建日志目录并同时挂载控制台与文件两个 handler。 |
| 290 | `test_messages_reach_the_log_file` | 日志内容按格式写入文件，含级别与 logger 名。 |
| 291 | `test_reconfiguring_closes_the_previous_file_handler` | 重新配置时关闭旧 FileHandler，释放文件句柄。 |
| 292 | `test_reconfiguring_does_not_close_stdout` | 重新配置不会连带关闭 sys.stdout。 |
| 293 | `test_repeated_setup_does_not_accumulate_handlers` | 反复调用不会累积 handler 造成重复输出。 |
| 294 | `test_logging_still_works_after_reconfiguration` | 重新配置后日志仍能正常写入。 |
| 295 | `test_separate_names_get_separate_loggers` | 不同名字得到独立 logger 与独立日志文件。 |

---


## 覆盖率

| 模块 | 语句 | 分支 | 覆盖率 |
|---|---|---|---|
| `analyzer.py` | 578 | 274 | 100% |
| `pipeline.py` | 205 | 74 | 100% |
| `state.py` | 150 | 30 | 100% |
| `rules.py` | 131 | 48 | 100% |
| `receiver.py` | 55 | 16 | 100% |
| `config.py` | 42 | 4 | 100% |
| `logging_utils.py` | 20 | 4 | 100% |
| **合计** | **1181** | **450** | **100%** |
