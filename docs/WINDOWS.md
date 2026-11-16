# Windows 运行说明

本服务使用 **Windows 原生 CPython 3.12 标准库 + SQLite**，无第三方依赖、无 Docker、无外网、无邮件/短信、无外部身份平台。
下面的命令均在仓库根目录（含 `sensitive_confirm/` 的目录）执行；示例用 `python`，即本机 Python 3.12（若装有 `py` 启动器可用 `py -3.12`）。

```bat
python --version        :: 需 3.12.x
```

## 1. 初始化（只需要一次）

```bat
python -m sensitive_confirm init --db data\confirm.db --key data\confirm_key.json
```

`init` 会：

* 创建 SQLite 数据库和全部表、触发器（`PRAGMA journal_mode=WAL`、`synchronous=FULL`）；
* 生成 **仅存在于服务端** 的二次确认密钥 `data\confirm_key.json`（含密钥的 sha256 指纹）；
* 预置 2 个租户、3 个登录用户、4 条配置；
* 打印一次 hex 管理密钥（= 密钥文件的 hex 形式），用于本地禁用/启用用户；**不会**由任何 HTTP 接口返回。

输出里的预置数据：

| 租户 | 登录名 | 密码 | user_id |
| --- | --- | --- | --- |
| tenant-alpha | alice | `Alice-Passw0rd!` | usr_alpha_alice |
| tenant-alpha | bob | `Bob-Passw0rd!` | usr_alpha_bob |
| tenant-beta | carol | `Carol-Passw0rd!` | usr_beta_carol |

| 租户 | config_id | 初始 version | 初始 value |
| --- | --- | --- | --- |
| tenant-alpha | svc-api | 1 | `timeout=30s` |
| tenant-alpha | svc-worker | 3 | `replicas=2` |
| tenant-beta | svc-api | 1 | `timeout=10s` |
| tenant-beta | svc-billing | 7 | `currency=USD` |

重复执行 `init` 会拒绝覆盖（避免把生产库/密钥清掉）；确有需要请显式 `--force`（会删除数据库并**重新生成密钥**，旧票据与旧会话立即全部失效）。

## 2. 检查（初始化后、故障演练后随时可跑）

```bat
python -m sensitive_confirm check --db data\confirm.db --key data\confirm_key.json
```

检查项包括：数据库存在与 `PRAGMA integrity_check`、外键、schema 版本、预置用户/配置数量、孤儿票据、
同一 intent 是否出现多份批准，以及**用真实写入探测**触发器是否仍生效（意图不可改、批准不可改、审计不可删、票据不可删/不可回退）。
`ok: true` 且退出码 0 才算通过。

另有两个只读辅助命令：

```bat
python -m sensitive_confirm show --db data\confirm.db
python -m sensitive_confirm code --db data\confirm.db --key data\confirm_key.json --challenge chl_xxx
```

`code` 是"外部带外通道"的模拟：只有持有本地密钥文件的人才能从**数据库里已保存的意图**推导出确认码，证明确认码绑定的是那一条已存操作，而不是请求方临时给出的内容。

## 3. 启动服务（可同时起多个进程共享同一数据库）

```bat
:: 终端 1~4，端口不同即可；它们共享 data\confirm.db
python -m sensitive_confirm serve --db data\confirm.db --key data\confirm_key.json --port 8765
python -m sensitive_confirm serve --db data\confirm.db --key data\confirm_key.json --port 8766
python -m sensitive_confirm serve --db data\confirm.db --key data\confirm_key.json --port 8767
python -m sensitive_confirm serve --db data\confirm.db --key data\confirm_key.json --port 8768
```

默认只绑定 `127.0.0.1`。服务用标准库 `ThreadingHTTPServer`，每个请求线程独立 SQLite 连接；所有状态都在数据库中，因此进程数任意、可随时杀掉重启。

本地演示想看到确认码（真实部署**不要**开启）：

```bat
set SC_CODE_ECHO=1
python -m sensitive_confirm serve --db data\confirm.db --key data\confirm_key.json --port 8765
```

关闭 `SC_CODE_ECHO`（默认）后，任何 HTTP 响应都不含确认码；只能像真实短信/TOTP 一样，由掌握密钥的一方离线取得（本工程用 `python -m sensitive_confirm code` 模拟）。

## 4. 端到端演示 + 测试

```bat
python demo.py --port 8765 --db data\confirm.db
python run_tests.py
```

`run_tests.py` 会自行 init 临时库、起/杀真实子进程（含 4 进程并发与崩溃注入），输出 `docs\TEST_RESULTS.md` 与 `docs\test_results.json`。
只跑某一类：

```bat
python run_tests.py -k crash
python run_tests.py -k concurrency
```

## 5. HTTP 接口

所有请求/响应均为 JSON；会话令牌放 `Authorization: Bearer <token>`（或 `X-Session-Token`）。除 `/health`、`/v1/meta` 外都需要有效会话。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/health` | 存活探测（返回 pid） |
| GET | `/v1/meta` | 服务信息 |
| POST | `/v1/login` | `{tenant_id, login_name, password}` → `session_token` |
| GET | `/v1/whoami` | 当前会话身份 |
| POST | `/v1/logout` | 撤销会话，并同事务内作废该会话所有未用票据 |
| POST | `/v1/session/rotate` | 轮换浏览器会话：旧会话与旧票据立刻失效，返回新令牌 |
| GET | `/v1/configs` / `/v1/configs/<config_id>` | 读（仅本租户） |
| POST | `/v1/prepare` | `{config_id, expected_version, new_value}` → `challenge` + `pending_action` |
| POST | `/v1/verify` | `{challenge, confirmation_code}` → 30 秒一次性 `ticket` |
| POST | `/v1/execute` | `{ticket}` → 执行；重试返回原结果 |
| POST | `/admin/disable-user` | 需头 `X-Admin-Key: <init 打印的 hex>`；`{tenant_id, login_name, disabled}` |

**写入只有一条路径**：`prepare → verify → execute`。普通登录会话没有任何可直接改配置的接口；`execute` 只接受 `ticket`，请求里出现 `config_id/expected_version/new_value/version/value/tenant_id/user_id/session_id` 会直接 400 `request_cannot_override_intent`。

### 错误码速查

| HTTP | error | 含义 |
| --- | --- | --- |
| 400 | `request_cannot_override_intent` | execute 试图后补/替换已确认内容 |
| 400 | `request_cannot_choose_identity` | prepare 试图自选租户/用户/会话 |
| 400 | `request_cannot_supply_key` | verify 试图在请求里自带服务端确认密钥 |
| 401 | `invalid_ticket` / `ticket_invalidated` | 票据伪造/不存在/已被退出或禁用作废 |
| 401 | `session_revoked` / `session_rotated` / `session_expired` | 会话已不可用 |
| 403 | `ticket_bound_to_other_session` / `wrong_session` | 跨会话/跨租户搬票据 |
| 403 | `confirmation_rejected` | 确认码不对（会计数，10 次后锁 60 秒） |
| 403 | `account_disabled` | 账号被禁用 |
| 409 | `already_confirmed` | 同一 challenge 已有批准 |
| 409 | `version_conflict` | 资源版本在 prepare 之后变了（不会覆盖、不会改基） |
| 410 | `challenge_expired` / `ticket_expired` | 过期 |
| 503 | `database_busy` | SQLite 写锁争用，未提交任何内容，可安全重试 |

## 6. 环境变量（仅测试/运维用，均不来自请求）

| 变量 | 作用 |
| --- | --- |
| `SC_CODE_ECHO=1` | 本地演示：prepare 响应回显确认码（默认关闭） |
| `SC_TICKET_TTL_MS` / `SC_INTENT_TTL_MS` | 覆盖票据/挑战有效期（默认 30000 / 300000），仅用于过期边界测试 |
| `SC_CRASHPOINT` | 逗号分隔的故障注入点：`before_begin,ticket_marked_used,config_updated,after_commit,after_session_revoke,before_claim` |
| `SC_CRASHPOINT_MODE` | `kill`（默认，`os._exit(9)`）或 `pause`（stdout 报点后等待 stdin） |
| `SC_HTTP_LOG=1` | 打开 HTTP 访问日志到 stderr |

## 7. 常见问题

* **端口被占用**：换 `--port`。测试全部使用系统分配的随机端口，不会冲突。
* **`database is locked`**：本服务已设 `busy_timeout=30s` 且写事务极短，正常不会出现；真出现会返回 503 且保证未提交，可直接重试。用 `check` 确认库完整性。
* **杀进程后 WAL 残留**：属正常，SQLite 下次打开会自动恢复；`-wal/-shm` 文件不要手工删（已 `.gitignore`）。
* **想重置一切**：`python -m sensitive_confirm init --db data\confirm.db --key data\confirm_key.json --force`。
* **数据目录**：`data\` 与 `.runtime-tmp\` 都已被 `.gitignore` 忽略，测试不会污染仓库。
