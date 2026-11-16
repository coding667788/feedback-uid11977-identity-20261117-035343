"""Run the whole test suite and write a machine-verified results report.

Usage (Windows native Python 3.12)::

    python run_tests.py            # full suite, ~2 minutes
    python run_tests.py -k crash   # just the crash tests

The report records the actual outcome of every test plus environment details
and the invariant-focused assertions each test makes.  It is written to
``docs/TEST_RESULTS.md`` and printed to stdout.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

MODULES = [
    "tests.test_functional",
    "tests.test_expiry",
    "tests.test_concurrency",
    "tests.test_crash",
    "tests.test_commands",
]

DESCRIPTIONS = {
    # functional
    "test_normal_session_cannot_write_config":
        "普通登录会话无写入口；只有 tickets 能触发写入",
    "test_prepare_does_not_change_config":
        "prepare 只落不可变意图，不改配置",
    "test_verify_then_execute_applies_exact_intent":
        "只执行被确认的 version/value（接口结果 + 数据库行同时校验）",
    "test_replay_same_ticket_returns_result_without_second_write":
        "同票据重试返回原结果、executions 仍为 1、配置未二次变更",
    "test_execute_rejects_request_supplied_values":
        "execute 拒绝请求里后补的 config_id/version/value/tenant",
    "test_prepare_rejects_stale_expected_version":
        "prepare 拒绝已过期的预期版本（不生成让人误确认的 challenge）",
    "test_cannot_swap_resource": "换资源被拒绝，另一资源行不变",
    "test_cannot_swap_value": "换 value 被拒绝，库内保持确认值",
    "test_cannot_swap_expected_version": "换预期版本仍按原版本 CAS，冲突 409",
    "test_code_from_other_intent_rejected": "他意图的确认码不能批准本意图",
    "test_cross_tenant_ticket_move": "跨租户搬票据被拒绝",
    "test_cross_session_ticket_move": "跨浏览器会话搬票据被拒绝",
    "test_prepare_cannot_choose_identity": "请求不能自选租户/用户/会话",
    "test_request_cannot_supply_confirm_key": "请求不能自带确认密钥作为服务端真值",
    "test_one_approval_per_challenge": "同一 challenge 只产生一份批准/一张票据",
    "test_ticket_expired_at_boundary": "票据有效期为 30s（库内 issued/expires 差）",
    "test_version_conflict_between_two_intents":
        "两个意图争用同一版本：一个成功，另一个 409 且不写库",
    "test_conflict_not_silently_rebased": "冲突不会被偷偷改成基于新版本执行",
    # expiry
    "test_execute_just_before_expiry_succeeds": "过期前执行成功",
    "test_execute_after_expiry_rejected_and_no_write": "过期后 410 且零写入",
    "test_replay_after_ticket_expiry_still_returns_original_result":
        "票据过期后重试仍返回原结果（不再写）；退出后同样重试被拒",
    "test_challenge_expiry_blocks_verify": "challenge 过期后不能确认",
    "test_default_ttl_is_30_seconds": "默认票据 TTL 恰为 30000ms",
    # concurrency
    "test_four_processes_same_ticket_only_one_update":
        "4 进程并发同一票据：恰好 1 次配置变更",
    "test_two_intents_same_expected_version_only_one_wins":
        "两个意图并发争用同一版本：恰好一个赢",
    "test_parallel_independent_intents_serialise_versions":
        "6 个同版本意图并发：1 成功 5 冲突",
    "test_concurrent_verify_same_challenge_single_approval":
        "8 进程并发 verify：1 份批准、1 张票据",
    "test_verify_and_execute_race_on_different_processes":
        "多进程 verify+execute 竞争：每配置各写一次",
    "test_logout_commits_before_execution_writes":
        "退出先提交：已验证未提交的执行不落库",
    "test_disable_commits_before_execution_writes":
        "禁用先提交：已验证未提交的执行不落库",
    "test_execution_commits_before_logout_then_logout_wins_retry":
        "执行先提交：重试被会话状态拦下，配置不再变",
    "test_logout_alone_invalidates_pending_ticket": "退出后未执行票据作废（重新登录也不行）",
    "test_session_rotation_invalidates_ticket": "会话轮换后旧票据不可用、新会话也不能接管",
    "test_logout_waits_for_inflight_execution":
        "执行已持写锁时 logout 必须等待，不会插进票据已用/配置未提交之间",
    "test_disable_after_verify_blocks_execute": "确认后禁用，执行被拒绝",
    # crash
    "test_crash_after_ticket_marked_used_before_config_update":
        "故障点①票据已标记用但配置未更新：事务回滚，重启重试恰好一次",
    "test_crash_after_config_updated_before_commit":
        "故障点②配置已更新但未提交：回滚，重启重试恰好一次",
    "test_crash_after_commit_before_response":
        "故障点③提交后响应未发出：重试返回原结果且不重复写",
    "test_crash_before_ticket_claim_writes_nothing": "断点在取锁前：无任何写入",
    "test_crash_after_logout_commit_before_response": "logout 提交后崩溃：票据作废、重试 401",
    "test_crash_twice_same_ticket_committed_then_retried": "提交后崩 + 重试再崩：仍只有一次更新",
    "test_check_command_after_all_crashes": "多次崩溃后 check 命令全绿（完整性/唯一性）",
    "test_hard_kill_while_ticket_used_then_fleet_retries":
        "外部强杀持锁进程（票据已用未提交）后 4 进程并发重试：仍只写一次",
    "test_hard_kill_after_config_update_then_fleet_retries":
        "外部强杀（配置已改未提交）后 4 进程并发重试：仍只写一次",
    # commands
    "test_init_check_code_and_out_of_band_verify":
        "无回显部署：确认码只能由本地密钥离线推导",
    "test_init_refuses_to_clobber_without_force": "init 不会默认覆盖既有库",
    "test_brute_force_is_rate_limited": "确认码暴力尝试被限速，且未产生批准",
    "test_intent_and_approval_are_immutable": "触发器保证意图/批准不可改、审计不可删",
    "test_used_ticket_cannot_be_reissued": "已用票据不可回退为 issued、不可删除",
}


class Recorder(unittest.TextTestResult):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.records: list[dict] = []
        self._t0: dict[str, float] = {}

    def startTest(self, test):
        self._t0[test.id()] = time.time()
        super().startTest(test)

    def _name(self, test) -> str:
        return test.id().split(".")[-1]

    def addSuccess(self, test):
        super().addSuccess(test)
        self.records.append(self._rec(test, "PASS", ""))

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.records.append(self._rec(test, "FAIL", self._short(err)))

    def addError(self, test, err):
        super().addError(test, err)
        self.records.append(self._rec(test, "ERROR", self._short(err)))

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.records.append(self._rec(test, "SKIP", reason))

    def _rec(self, test, status, detail):
        name = self._name(test)
        return {
            "module": test.id().rsplit(".", 1)[0],
            "name": name,
            "status": status,
            "detail": detail,
            "seconds": round(time.time() - self._t0.get(test.id(), time.time()), 2),
            "covers": DESCRIPTIONS.get(name, ""),
        }

    @staticmethod
    def _short(err) -> str:
        if not err:
            return ""
        return str(err[1]).strip().splitlines()[-1][:400]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--pattern", default=None)
    parser.add_argument("--report", default=str(ROOT / "docs" / "TEST_RESULTS.md"))
    args = parser.parse_args(argv)

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for mod in MODULES:
        suite.addTests(loader.loadTestsFromName(mod))
    if args.pattern:
        filtered = unittest.TestSuite()
        for test in _iter(suite):
            if args.pattern.lower() in test.id().lower():
                filtered.addTest(test)
        suite = filtered

    runner = unittest.TextTestRunner(
        verbosity=2, resultclass=Recorder, stream=sys.stdout)
    started = time.time()
    result = runner.run(suite)
    elapsed = time.time() - started

    records = getattr(result, "records", [])
    total = len(records)
    passed = sum(1 for r in records if r["status"] == "PASS")
    failed = sum(1 for r in records if r["status"] in ("FAIL", "ERROR"))
    skipped = sum(1 for r in records if r["status"] == "SKIP")

    env = {
        "python": sys.version.split()[0],
        "executable": sys.executable,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "sqlite": __import__("sqlite3").sqlite_version,
        "elapsed_seconds": round(elapsed, 2),
        "total": total, "passed": passed, "failed": failed, "skipped": skipped,
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    lines = ["# 实际测试结果", "",
             f"- 生成时间：{env['started_at']}",
             f"- Python：{env['python']}（{env['executable']}）",
             f"- 平台：{env['platform']} / {env['machine']}",
             f"- SQLite：{env['sqlite']}",
             f"- 用时：{env['elapsed_seconds']} 秒",
             f"- 结果：**{passed}/{total} 通过，{failed} 失败，{skipped} 跳过**", ""]
    if failed:
        lines.append("## 失败项")
        lines.append("")
        for r in records:
            if r["status"] in ("FAIL", "ERROR"):
                lines.append(f"- `{r['module']}.{r['name']}` [{r['status']}]: {r['detail']}")
        lines.append("")

    current = None
    for r in records:
        if r["module"] != current:
            current = r["module"]
            lines += ["", f"## {current}", "",
                      "| 状态 | 用例 | 秒 | 验证内容 |",
                      "| --- | --- | --- | --- |"]
        mark = {"PASS": "✅ 通过", "FAIL": "❌ 失败",
                "ERROR": "❌ 错误", "SKIP": "⏭ 跳过"}[r["status"]]
        lines.append(f"| {mark} | `{r['name']}` | {r['seconds']} | {r['covers']} |")
    lines.append("")

    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines), encoding="utf-8")
    (report_path.parent / "test_results.json").write_text(
        json.dumps({"env": env, "records": records}, ensure_ascii=False, indent=2),
        encoding="utf-8")

    print()
    print(f"== {passed}/{total} passed, {failed} failed, {skipped} skipped "
          f"in {elapsed:.1f}s")
    print(f"== report: {report_path}")
    return 0 if failed == 0 else 1


def _iter(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _iter(item)
        else:
            yield item


if __name__ == "__main__":
    raise SystemExit(main())
