# 设计说明

## 1. 一句话

`prepare` 把"用户将要批准的这一次操作"冻结成一条不可变意图；`verify` 用**只存在于服务端**的本地密钥对该意图做一次 MAC 校验，
从而产生最多一份批准和一张 30 秒一次性票据；`execute` 只读票据、只读意图，
在一个事务里同时完成"调用身份+会话+账号状态复核 → 票据核销 → 配置 CAS → 幂等结果落库"。

## 2. 威胁模型

| 假设的攻击者 | 防御 |
| --- | --- |
| 只有普通登录会话（可能被 XSS/CSRF 拿到） | 写路径必须 ticket；票据只能由 verify + 确认码产生 |
| 能改请求体 | execute 白名单只认 `ticket`；意图字段共 7 个，任一被请求改写都会 400 |
| 拿到别人的票据 | 票据 MAC 覆盖 intent/tenant/user/session，并在事务内逐字段比对调用者会话 |
| 拿到同一用户的另一个浏览器会话 | 票据与本会话 session_id 强绑定；rotate 后旧票据连会话一起作废 |
| 重放到另一资源/另一版本/另一 value | 执行值全部来自 intents 表；CAS 用意图里的 expected_version |
| 暴力猜确认码 | 8 位码 = HMAC(密钥, 全部意图字段+challenge+过期时间)；每 challenge 10 次后锁 60 秒 |
| 在退出/禁用竞争窗口内抢写 | 执行事务先取写锁，再读会话/账号；revoke 已提交则中止；未提交则排队 |
| 进程在任意点被 kill | 票据核销+配置更新+executions 同事务；重试读 executions 返回原结果 |

**不在范围内**：TOTP/短信（题面明确不要求）、TLS/前端、操作系统级攻击、密钥文件被本地读取（这等价于"拿到短信验证码"）。

## 3. 数据模型（`sensitive_confirm/db.py`）

```
tenants ─┬─ users(disabled)
         ├─ configs(tenant_id, config_id) PK, version, value
         └─ sessions(session_id, token_hash, revoked_at, rotated_at, expires_at)

intents    : 不可变意图（tenant/user/session/config/expected_version/new_value/summary/expires）
             challenge_hash 唯一；UPDATE 被触发器拒绝
approvals  : intent_id UNIQUE → 一个 challenge 最多一份批准；不可改
tickets    : intent_id/approval_id/session_id/tenant_id/user_id 全部冻结（触发器禁止改）
             state ∈ {issued, used}；used 不可回退；不可删除
executions : intent_id PK → 一个意图最多执行一次；ticket_id UNIQUE；结果 JSON 不可改
audit_log  : append-only（禁止 UPDATE/DELETE）
verify_attempts : 失败计数/锁定（无授权力，仅限速）
```

关键点：**票据不是授权凭证本身**。它只是"指向一条已批准意图的短期句柄"。真正决定"改什么"的只有 `intents`，
而 `intents` 在 prepare 之后不可写。

## 4. 三段流程

### prepare

1. 会话校验（租户/用户/会话均来自 token，不接受请求指定）。
2. `BEGIN IMMEDIATE`，读当前配置。
3. **若 `expected_version` 已不是当前版本 → 409 `stale_expected_version`**，不生成意图。
   这避免让用户去确认一份"已经被别人改过"的内容（题面要求资源变了必须冲突，这里把冲突提前到 prepare；execute 仍会再判一次）。
4. 写入 intent（含 `summary_json`，即用户看到的待确认内容）；审计。
5. 用本地密钥计算 8 位确认码，仅当 `SC_CODE_ECHO=1` 时随响应回显；默认不带。

### verify

1. 会话校验 + 失败计数限速。
2. `BEGIN IMMEDIATE`；读 intent；校验**会话与 intent 归属一致**（跨会话/跨租户直接 403）；校验未过期。
3. 用数据库里的 intent 字段重新计算确认码，`hmac.compare_digest` 比较。
4. 若该 intent 已有 approval → 409 `already_confirmed`（并发下也由 `UNIQUE(intent_id)` 兜底）。
5. 写 approval + ticket（30 秒，MAC 签名，payload 覆盖 intent/challenge/session/expires）。
6. 请求中出现 `confirm_key` 等字段直接 400，避免"请求自带密钥"的错觉。

### execute

```
读 caller session（401/403 先挡掉）
crashpoint: before_begin           ← 竞态注入点（logout/disable 可在此先提交）
BEGIN
  UPDATE tickets SET state=state   ← 取写锁（WAL RESERVED），之后所有读都在锁内
crashpoint: before_claim
  事务内重读：origin ticket 会话 + 账号 disabled + 会话 revoked/rotated/expires
  逐字段比对 ticket ←→ payload ←→ caller session ←→ intent
  若 executions 已有该 intent：
      ticket.used → 返回原结果（幂等重放）；否则 401 ticket_invalidated
  若 ticket.used 但无 execution → 401 ticket_invalidated（被 logout/disable 清理）
  若 ticket 过期 → 410
  UPDATE tickets SET state='used'   （CAS state='issued'，rowcount!=1 则 409）
crashpoint: ticket_marked_used
  SELECT config ... 版本不符 → 409 version_conflict（回滚，票据也回滚为 issued）
  UPDATE configs SET version=v+1 ... AND version=expected_version（CAS）
crashpoint: config_updated
  INSERT executions（intent_id PK）→ 幂等凭证
  audit
COMMIT
crashpoint: after_commit
```

三个崩溃点都落在事务内部或提交之后，因此：

* 崩溃在 ①② → 整事务回滚，票据仍 `issued`，配置未变；重启重试**正常执行一次**。
* 崩溃在 ③ → 票据 `used`、配置已变、executions 已有；重启重试**返回原结果**，不再写。

### 退出 / 轮换 / 禁用为什么能赢

* 三者都在**一个事务**里更新 `sessions/users` 并 `UPDATE tickets SET state='used'`。
* 执行侧在拿到写锁**之后**才读会话与账号状态（deferred 事务的读快照由第一次读决定，而第一次语句是写）。
* 因此：revoke 先提交 → 执行看到 revoked/disabled/ticket-used → 中止且无写入；
  执行先取锁 → revoke 等待，等执行提交后才撤销，重试因会话已死返回 401 而不会二次写入。
  测试 `TestExecutionHoldsLock.test_logout_waits_for_inflight_execution` 直接验证 logout 线程被阻塞。

## 5. 为什么"只执行被确认的那一次"

1. `execute` 的服务端输入只有一个票据字符串；其余 7 个字段出现即 400。
2. 票据 payload 只含**引用**（intent_id/ticket_id/session_id），不含任何可被当作"新指令"的字段；
   写入用的 value/version 全部从 `intents` 行读取。
3. `intents` 有触发器禁止 UPDATE，`executions` 有 PK 禁止二次执行，`tickets` 禁止改绑定/回退/删除。
4. 测试对每个用例同时断言 HTTP 结果与 `configs` 行（值、版本、updated_by）和 `executions` 计数，
   不是只看 200。

## 6. 并发

* 4+ 进程各自持连接共享 WAL 数据库；写事务由 SQLite 串行化。
* 同票据并发：`UPDATE ... AND state='issued'` 的 rowcount 决定唯一赢家，其余请求要么看到 committed 的 executions 走幂等重放，
  要么（在未提交时的并发窗口）拿到 409/503 —— 两者都不会二次写。
* 不同意图同版本并发：CAS 只有一个成功，另一个 409 且回滚，不会"偷偷改成基于新版本"。
* 冲突返回 409 时**票据不被核销**（事务回滚），但它持有的 expected_version 永远不变，因此后续只会继续冲突——
  必须重新 prepare/确认，符合"确认的是那一次具体操作"。

## 7. 已知取舍 / 未完成项

见 `docs/REPORT.md` 末尾与 `docs/TEST_RESULTS.md`。
