# 交付说明与实际测试结果

> 任务：本地敏感操作二次确认服务（UID 11977）。实现目录 `sensitive_confirm/`，测试 `tests/`，入口 `run_tests.py` / `demo.py`。
> 本文所有"实际结果"均来自本机执行，原始记录见 `docs/TEST_RESULTS.md` 与 `docs/test_results.json`。

## 1. 交付物清单

| 交付项 | 位置 | 说明 |
| --- | --- | --- |
| HTTP 服务 | `sensitive_confirm/server.py` | 标准库 `ThreadingHTTPServer`，默认绑定 `127.0.0.1`，多进程可共享同一 SQLite |
| 业务与安全逻辑 | `sensitive_confirm/services.py` | prepare / verify / execute / logout / rotate / disable 及全部事务边界 |
| 数据模型与约束 | `sensitive_confirm/db.py` | WAL + `synchronous=FULL`；触发器保证意图/批准/执行/票据绑定不可变、审计 append-only |
| 二次确认密钥与票据签名 | `sensitive_confirm/security.py`、`tickets.py` | PBKDF2 口令、HMAC 确认码、HMAC 签名票据 |
| 故障注入点 | `sensitive_confirm/crashpoints.py` | 3 个任务要求点 + 2 个附加点；`kill`/`pause` 两种模式 |
| 初始化 / 检查 / 确认码命令 | `sensitive_confirm/cli.py` | `init` / `check` / `show` / `code` / `serve` |
| 自动化测试 | `tests/test_functional.py`、`test_expiry.py`、`test_concurrency.py`、`test_crash.py`、`test_commands.py` | 共 49 个用例，全部启动真实子进程 |
| 一键测试并产出报告 | `run_tests.py` | 写 `docs/TEST_RESULTS.md` / `docs/test_results.json` |
| 手工演示 | `demo.py` | 打印每步 HTTP 结果 + 直接读 SQLite 的配置行 |
| Windows 说明 | `docs/WINDOWS.md` | 命令、接口、错误码、环境变量、FAQ |
| 设计说明 | `docs/DESIGN.md` | 威胁模型、事务/锁顺序、为什么"只执行被确认的那一次" |

## 2. 需求 → 实现 → 测试证据

| 需求 | 实现要点 | 证明方式（接口 + 数据库） |
| --- | --- | --- |
| 普通会话不能直接改配置 | 写路径只有 `execute`，且只接受 ticket；`prepare` 不写 configs | `test_normal_session_cannot_write_config`：用会话令牌调 execute → 401；带字段调 execute → 400；configs 行前后完全相等 |
| prepare 保存不可变意图并返回 challenge/待确认内容 | `intents` 表 + `intents_no_update` 触发器；`summary_json` 即展示内容 | `test_prepare_does_not_change_config`；`TestDatabaseGuards.test_intent_and_approval_are_immutable`（UPDATE 被 SQLite 拒绝） |
| 意图绑定租户/用户/会话/版本/新值 | 5 个字段全部写入 intents；`challenge_hash` 唯一；票据 payload 含 `new_value_sha256` 并在 execute 时与库内意图比对 | 换资源/换值/换版本/跨租户/跨会话 5 个用例 |
| 二次确认密钥独立于登录凭据、init 预置、不能由请求提供 | `confirm_key.json`（init 生成，指纹记录在库 meta）；verify 拒绝请求中的 `confirm_key` 等字段；默认不回显确认码，只能用 `code` 命令离线推导 | `test_request_cannot_supply_confirm_key`；`test_init_check_code_and_out_of_band_verify`（无回显部署下走 CLI 取码成功）；`test_brute_force_is_rate_limited` |
| 成功后签发 30 秒一次性票据 | `expires_at = issued_at + 30000`；`ticket_ttl_ms()` 仅测试可覆盖 | `test_default_ttl_is_30_seconds`（响应 30000ms + 库内差值 30000）；`test_ticket_expired_at_boundary` |
| execute 必须用保存的意图 | execute 只读 `ints`/`tickets`，请求字段出现即 400 | `test_execute_rejects_request_supplied_values`、`test_cannot_swap_value`、`test_cannot_swap_resource`、`test_cannot_swap_expected_version`：每次都同时断言 configs 行未变/只变为确认值 |
| 同一 challenge 最多一份批准 | `approvals.intent_id UNIQUE` + 事务内存在性检查 | `test_one_approval_per_challenge`、`test_concurrent_verify_same_challenge_single_approval`（8 进程并发 → approvals=1, tickets=1） |
| 票据只绑定一个意图和发起会话 | 票据签名 + 库内 session_id/intent_id 逐字段比对（事务内重读） | `test_cross_session_ticket_move`、`test_cross_tenant_ticket_move`、`test_session_rotation_invalidates_ticket` |
| 成功 execute 后同票据重试返回原结果、不二次修改 | `executions.intent_id` 主键 + 返回 `result_json`；重试前重做身份/会话/禁用检查 | `test_replay_same_ticket_returns_result_without_second_write`（executions=1，configs 行完全相同）、`test_crash_after_commit_before_response` |
| 退出/轮换/禁用后未执行票据立即失效 | logout/rotate/disable 在同一事务里同时改 sessions/users 和把 issued 票据置 used | `test_logout_alone_invalidates_pending_ticket`、`test_session_rotation_invalidates_ticket`、`test_disable_after_verify_blocks_execute` |
| 资源版本变化必须冲突、不得改基 | prepare 直接拒绝过期版本；execute 在写锁内再 CAS 一次 | `test_prepare_rejects_stale_expected_version`、`test_cannot_swap_expected_version`、`test_conflict_not_silently_rebased`、`test_version_conflict_between_two_intents` |
| ≥4 个独立服务进程共享数据库 | 测试用 `Fleet(count=4)`，端口独立，共享同一 DB 文件 | `test_four_processes_same_ticket_only_one_update` 等 5 个并发用例 + 2 个强杀后 4 进程重试用例 |
| 票据消费 + 配置 CAS + 幂等结果同事务 | 单条 `BEGIN…COMMIT` 内完成 | 崩溃点①②回滚后票据仍为 issued、executions=0；崩溃点③后 executions=1 |
| 并发执行同一票据只能改一次 | `UPDATE tickets ... AND state='issued'` 的 rowcount 决胜负 | 4 进程同票据：`applied == 1`，其余为幂等重放，configs 版本 +1 |
| 会话状态与写入一起检查；revoke 先提交则不得落库 | 先取写锁再重读会话/账号；logout/disable 单事务 | `test_logout_commits_before_execution_writes`（external 顺序控制）、`test_disable_commits_before_execution_writes`、`test_logout_waits_for_inflight_execution`（反向：logout 被阻塞） |
| 三个可控同步点真实终止进程，重启后完整无重复 | `ticket_marked_used` / `config_updated` / `after_commit`；`os._exit(9)` 与外杀两种 | `TestCrashPoints` 4 个用例 + `TestCrashWithFourProcesses` 2 个用例；`check` 命令在多次崩溃后仍 `ok:true` |

## 3. 实际测试结果

本机：Windows 11 Pro 10.0.26200，AMD64；Python 3.12.8（`D:\CC_Codex_FeedBack\runtimes\cc005-csv-python312\python.exe`）；SQLite 3.45.3。

```
python run_tests.py
...
Ran 49 tests in 56.4s
OK
== 49/49 passed, 0 failed, 0 skipped in 56.4s
```

| 测试文件 | 用例数 | 结果 | 覆盖点 |
| --- | --- | --- | --- |
| `tests/test_functional.py` | 18 | ✅ 全部通过 | 正常流程、幂等重试、换资源/换值/换版本、跨租户/跨会话、越权字段、单批准、stale prepare、双意图冲突 |
| `tests/test_expiry.py` | 5 | ✅ 全部通过 | 过期前成功、过期后 410 且零写入、challenge 过期、默认 30000ms、过期后幂等重放仍可取回结果 |
| `tests/test_concurrency.py` | 12 | ✅ 全部通过 | 4 进程同票据、8 进程同 challenge、双意图争版本、6 意图并发、退出/禁用先提交、执行先提交、写锁阻塞 logout |
| `tests/test_crash.py` | 9 | ✅ 全部通过 | 3 个指定崩溃点 + 取锁前 + logout 提交后 + 连续两次崩溃 + 多次崩溃后 `check` + 外杀 + 4 进程重试 |
| `tests/test_commands.py` | 5 | ✅ 全部通过 | init/check/code、无回显确认、暴力限速、触发器守卫 |

关键"不只是状态码"的证据（均为库内实际值）：

* 正向：`configs.version` 由 3→4，`value` 变为确认值，`updated_by = usr_alpha_alice`；`executions` 按 `intent_id` 恰 1 行；`audit_log` 恰 1 条 `execute_applied`。
* 换值/换资源/换版本：`configs` 行与操作前**逐字段相等**（含 `updated_at`）。
* 双意图争版本：最终 `value` 必为赢家确认值，输家的 `intents` 仍在但 `executions=0`。
* 崩溃点①②：`tickets.state='issued'`、`executions=0`、`configs` 行不变；重启重试后恰好一次。
* 崩溃点③：重试返回 `idempotent_replay=true` 且 `executions` 仍为 1、`configs` 版本不再增加。
* 退出/禁用先提交：`sessions.revoked_at` 有值、`tickets.state='used'`、`executions=0`、`configs` 不变。

## 4. 未完成项与已知限制

1. **确认码的带外投递**：题面不要求短信/TOTP，故本地用"init 生成的密钥文件 + `python -m sensitive_confirm code`"模拟带外通道。默认不回显确认码；`SC_CODE_ECHO=1` 只是本地演示开关。真实部署需接入短信/TOTP/推送，并给确认码加**用户级**频率限制（当前仅"每 challenge 10 次后锁 60 秒"）。
2. **传输安全**：仅监听 `127.0.0.1`、明文 HTTP，无 TLS；跨机部署需要反向代理/证书。
3. **单机时间源**：有效期用本机 UTC 毫秒判断，未处理多机时钟漂移（所有进程同机，无此问题）。
4. **SQLite 单写者**：写事务已尽量短（微秒级），但不适合高写吞吐；横向扩展需换数据库，事务写法可平移。
5. **管理操作**：`/admin/disable-user` 用 init 打印的 hex 密钥做头校验，没有独立的管理员身份体系与审计审批流；生产应换成独立管理面。
6. **故障模型**：崩溃点为应用内可控点（`os._exit`）与外部强杀；`synchronous=FULL` 覆盖 fsync，但未做真实断电/磁盘损坏演练；`check` 只做 `integrity_check` + 外键 + 触发器探测，不做备份恢复。
7. **结果回取边界**：执行已提交但响应丢失后，若期间会话过期/被撤销，按题面"重试必须重新核对会话有效性"会返回 401——此时客户端无法取回原结果（可凭 `executions` 审计离线核对）。这是有意选择的 fail-closed。
8. **前端**：按题面不提供；所有交互为 JSON 接口。
9. **未实现**：多值/批量操作、撤销（undo）、审批人≠发起人的双人复核、指标/告警。

## 5. 复现命令

```bat
python -m sensitive_confirm init --db data\confirm.db --key data\confirm_key.json
python -m sensitive_confirm check --db data\confirm.db --key data\confirm_key.json
python -m sensitive_confirm serve --db data\confirm.db --key data\confirm_key.json --port 8765
python run_tests.py
```

（`SC_CODE_ECHO=1` 可让 prepare 回显确认码，便于手工用 `demo.py` 走完整流程。）
