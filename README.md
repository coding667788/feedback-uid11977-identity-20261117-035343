# 敏感操作二次确认服务

本地敏感操作二次确认：`prepare`（冻结意图）→ `verify`（本地二次确认密钥）→ `execute`（30 秒一次性票据）。
Windows 原生 Python 3.12 标准库 + SQLite，多进程共享同一数据库，含故障注入与并发测试。

* 快速开始 / 接口 / 错误码：[`docs/WINDOWS.md`](docs/WINDOWS.md)
* 设计（威胁模型、锁顺序、崩溃点）：[`docs/DESIGN.md`](docs/DESIGN.md)
* 交付说明与实际测试结果、未完成项：[`docs/REPORT.md`](docs/REPORT.md)
* 实际测试明细：[`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md)

```bat
python -m sensitive_confirm init --db data\confirm.db --key data\confirm_key.json
python -m sensitive_confirm check --db data\confirm.db --key data\confirm_key.json
python -m sensitive_confirm serve --db data\confirm.db --key data\confirm_key.json --port 8765
python run_tests.py
```

预置账号：`tenant-alpha / alice / Alice-Passw0rd!`、`tenant-alpha / bob / Bob-Passw0rd!`、`tenant-beta / carol / Carol-Passw0rd!`。
