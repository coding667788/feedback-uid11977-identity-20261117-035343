# 实际测试结果

- 生成时间：2026-11-17 05:05:08
- Python：3.12.8（D:\CC_Codex_FeedBack\runtimes\cc005-csv-python312\python.exe）
- 平台：Windows-11-10.0.26200-SP0 / AMD64
- SQLite：3.45.3
- 用时：56.41 秒
- 结果：**49/49 通过，0 失败，0 跳过**


## tests.test_functional.TestBinding

| 状态 | 用例 | 秒 | 验证内容 |
| --- | --- | --- | --- |
| ✅ 通过 | `test_cannot_swap_expected_version` | 0.91 | 换预期版本仍按原版本 CAS，冲突 409 |
| ✅ 通过 | `test_cannot_swap_resource` | 0.73 | 换资源被拒绝，另一资源行不变 |
| ✅ 通过 | `test_cannot_swap_value` | 0.7 | 换 value 被拒绝，库内保持确认值 |
| ✅ 通过 | `test_code_from_other_intent_rejected` | 0.7 | 他意图的确认码不能批准本意图 |
| ✅ 通过 | `test_cross_session_ticket_move` | 0.77 | 跨浏览器会话搬票据被拒绝 |
| ✅ 通过 | `test_cross_tenant_ticket_move` | 0.75 | 跨租户搬票据被拒绝 |
| ✅ 通过 | `test_one_approval_per_challenge` | 0.64 | 同一 challenge 只产生一份批准/一张票据 |
| ✅ 通过 | `test_prepare_cannot_choose_identity` | 0.57 | 请求不能自选租户/用户/会话 |
| ✅ 通过 | `test_prepare_rejects_stale_expected_version` | 0.6 | prepare 拒绝已过期的预期版本（不生成让人误确认的 challenge） |
| ✅ 通过 | `test_request_cannot_supply_confirm_key` | 0.64 | 请求不能自带确认密钥作为服务端真值 |

## tests.test_functional.TestExpiryAndConflicts

| 状态 | 用例 | 秒 | 验证内容 |
| --- | --- | --- | --- |
| ✅ 通过 | `test_conflict_not_silently_rebased` | 0.85 | 冲突不会被偷偷改成基于新版本执行 |
| ✅ 通过 | `test_ticket_expired_at_boundary` | 0.64 | 票据有效期为 30s（库内 issued/expires 差） |
| ✅ 通过 | `test_version_conflict_between_two_intents` | 0.79 | 两个意图争用同一版本：一个成功，另一个 409 且不写库 |

## tests.test_functional.TestHappyPathAndReplay

| 状态 | 用例 | 秒 | 验证内容 |
| --- | --- | --- | --- |
| ✅ 通过 | `test_execute_rejects_request_supplied_values` | 0.77 | execute 拒绝请求里后补的 config_id/version/value/tenant |
| ✅ 通过 | `test_normal_session_cannot_write_config` | 0.57 | 普通登录会话无写入口；只有 tickets 能触发写入 |
| ✅ 通过 | `test_prepare_does_not_change_config` | 0.62 | prepare 只落不可变意图，不改配置 |
| ✅ 通过 | `test_replay_same_ticket_returns_result_without_second_write` | 0.77 | 同票据重试返回原结果、executions 仍为 1、配置未二次变更 |
| ✅ 通过 | `test_verify_then_execute_applies_exact_intent` | 0.67 | 只执行被确认的 version/value（接口结果 + 数据库行同时校验） |

## tests.test_expiry.TestTicketExpiry

| 状态 | 用例 | 秒 | 验证内容 |
| --- | --- | --- | --- |
| ✅ 通过 | `test_challenge_expiry_blocks_verify` | 5.17 | challenge 过期后不能确认 |
| ✅ 通过 | `test_default_ttl_is_30_seconds` | 1.12 | 默认票据 TTL 恰为 30000ms |
| ✅ 通过 | `test_execute_after_expiry_rejected_and_no_write` | 2.53 | 过期后 410 且零写入 |
| ✅ 通过 | `test_execute_just_before_expiry_succeeds` | 1.34 | 过期前执行成功 |
| ✅ 通过 | `test_replay_after_ticket_expiry_still_returns_original_result` | 2.58 | 票据过期后重试仍返回原结果（不再写）；退出后同样重试被拒 |

## tests.test_concurrency.TestConcurrency

| 状态 | 用例 | 秒 | 验证内容 |
| --- | --- | --- | --- |
| ✅ 通过 | `test_concurrent_verify_same_challenge_single_approval` | 1.43 | 8 进程并发 verify：1 份批准、1 张票据 |
| ✅ 通过 | `test_four_processes_same_ticket_only_one_update` | 1.48 | 4 进程并发同一票据：恰好 1 次配置变更 |
| ✅ 通过 | `test_parallel_independent_intents_serialise_versions` | 1.56 | 6 个同版本意图并发：1 成功 5 冲突 |
| ✅ 通过 | `test_two_intents_same_expected_version_only_one_wins` | 1.41 | 两个意图并发争用同一版本：恰好一个赢 |
| ✅ 通过 | `test_verify_and_execute_race_on_different_processes` | 2.23 | 多进程 verify+execute 竞争：每配置各写一次 |

## tests.test_concurrency.TestExecutionHoldsLock

| 状态 | 用例 | 秒 | 验证内容 |
| --- | --- | --- | --- |
| ✅ 通过 | `test_disable_after_verify_blocks_execute` | 0.72 | 确认后禁用，执行被拒绝 |
| ✅ 通过 | `test_logout_waits_for_inflight_execution` | 1.99 | 执行已持写锁时 logout 必须等待，不会插进票据已用/配置未提交之间 |

## tests.test_concurrency.TestLogoutDisableRace

| 状态 | 用例 | 秒 | 验证内容 |
| --- | --- | --- | --- |
| ✅ 通过 | `test_disable_commits_before_execution_writes` | 1.18 | 禁用先提交：已验证未提交的执行不落库 |
| ✅ 通过 | `test_execution_commits_before_logout_then_logout_wins_retry` | 0.97 | 执行先提交：重试被会话状态拦下，配置不再变 |
| ✅ 通过 | `test_logout_alone_invalidates_pending_ticket` | 1.02 | 退出后未执行票据作废（重新登录也不行） |
| ✅ 通过 | `test_logout_commits_before_execution_writes` | 1.18 | 退出先提交：已验证未提交的执行不落库 |
| ✅ 通过 | `test_session_rotation_invalidates_ticket` | 0.91 | 会话轮换后旧票据不可用、新会话也不能接管 |

## tests.test_crash.TestCrashIntegrity

| 状态 | 用例 | 秒 | 验证内容 |
| --- | --- | --- | --- |
| ✅ 通过 | `test_check_command_after_all_crashes` | 2.77 | 多次崩溃后 check 命令全绿（完整性/唯一性） |

## tests.test_crash.TestCrashPoints

| 状态 | 用例 | 秒 | 验证内容 |
| --- | --- | --- | --- |
| ✅ 通过 | `test_crash_after_commit_before_response` | 1.16 | 故障点③提交后响应未发出：重试返回原结果且不重复写 |
| ✅ 通过 | `test_crash_after_config_updated_before_commit` | 1.16 | 故障点②配置已更新但未提交：回滚，重启重试恰好一次 |
| ✅ 通过 | `test_crash_after_logout_commit_before_response` | 1.12 | logout 提交后崩溃：票据作废、重试 401 |
| ✅ 通过 | `test_crash_after_ticket_marked_used_before_config_update` | 1.08 | 故障点①票据已标记用但配置未更新：事务回滚，重启重试恰好一次 |
| ✅ 通过 | `test_crash_before_ticket_claim_writes_nothing` | 1.09 | 断点在取锁前：无任何写入 |
| ✅ 通过 | `test_crash_twice_same_ticket_committed_then_retried` | 1.36 | 提交后崩 + 重试再崩：仍只有一次更新 |

## tests.test_crash.TestCrashWithFourProcesses

| 状态 | 用例 | 秒 | 验证内容 |
| --- | --- | --- | --- |
| ✅ 通过 | `test_hard_kill_after_config_update_then_fleet_retries` | 1.47 | 外部强杀（配置已改未提交）后 4 进程并发重试：仍只写一次 |
| ✅ 通过 | `test_hard_kill_while_ticket_used_then_fleet_retries` | 1.42 | 外部强杀持锁进程（票据已用未提交）后 4 进程并发重试：仍只写一次 |

## tests.test_commands.TestCommands

| 状态 | 用例 | 秒 | 验证内容 |
| --- | --- | --- | --- |
| ✅ 通过 | `test_brute_force_is_rate_limited` | 0.86 | 确认码暴力尝试被限速，且未产生批准 |
| ✅ 通过 | `test_init_check_code_and_out_of_band_verify` | 0.95 | 无回显部署：确认码只能由本地密钥离线推导 |
| ✅ 通过 | `test_init_refuses_to_clobber_without_force` | 0.12 | init 不会默认覆盖既有库 |

## tests.test_commands.TestDatabaseGuards

| 状态 | 用例 | 秒 | 验证内容 |
| --- | --- | --- | --- |
| ✅ 通过 | `test_intent_and_approval_are_immutable` | 0.01 | 触发器保证意图/批准不可改、审计不可删 |
| ✅ 通过 | `test_used_ticket_cannot_be_reissued` | 0.01 | 已用票据不可回退为 issued、不可删除 |
