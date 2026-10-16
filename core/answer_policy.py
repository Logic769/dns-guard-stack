# -*- coding: utf-8 -*-
"""answer_policy.py —— 统一准入策略（方案任务2 的纯函数部分）

来源：`2026-10-10-dns-secure-performance-implementation.md` 任务2「新的接口」。
本模块**只有纯函数与数据类型**，不导入 guard、不碰网络、不读状态 ⇒ 可离线安全回归 ✓。

设计要点（与方案逐条对应）：
  · `Verdict.SECURE` 只能由**本地验证器**确认后产生；
  · `Verdict.ACCEPTED` 只能由**批准的认证 A/alt 适配器**产生 —— B(AD=0) **不得**被标成 ACCEPTED；
  · `Verdict.BOGUS` **不可被任何备用或缓存"修复"** ⇒ 直接失败；
  · `local-b` 的 `UNKNOWN` **绝不单独放行**（这是 P0 的根因）；
  · TTL 到期、策略版本不符的答案在进入 `choose_answer` 前就失效 ⇒ 映射为 SERVFAIL（返回 None）；
  · 运行环境是 **Python 3.6.8** ⇒ 只用 `NamedTuple` / `Optional`，不用 dataclass、不用 `X | None`。
"""
from __future__ import absolute_import

import time
from enum import Enum
from typing import NamedTuple, Optional

POLICY_VERSION = "2026-10-10.1"

# 准入缓存允许的最长有效期（方案：不固定缓存一小时）
ACCEPT_MAX_TTL = 900.0
# 未签名（ACCEPTED）答案的策略上限：比签名答案更保守
ACCEPTED_MAX_TTL = 300.0
# ★ 2026-10-15 审计 F2 澄清（用户裁决 = **内部缓存策略**）：
#   上面两个上限是"本次准入结论在 guard **内部**还能被复用多久"的判定阈值
#   （作用于 `Answer.valid_until` 与 `is_fresh()`），**不是**对客户端下发的报文 TTL。
#   出口由 `guard._finalize_return` 按 RRset 剩余有效期原样下发（只重写事务 ID），
#   客户端看到的 TTL 不受本模块影响 ⇒ "AGH cache_ttl_max=86400 与策略上限冲突"是误读，
#   无需改出口行为；本注记为文档澄清，不改动任何运行时逻辑 ✓。


class Verdict(str, Enum):
    SECURE = "secure"      # 仅本地验证器确认
    ACCEPTED = "accepted"  # 认证运营方、未签名、策略接受
    BOGUS = "bogus"        # 本地验证器明确失败
    TRANSPORT = "transport"  # 运输失败（超时/拒答等），不是安全结论
    UNKNOWN = "unknown"    # 无本地验证结论（例如 B 的 AD=0）


class Answer(NamedTuple):
    wire: Optional[bytes]
    source: str               # local-a / local-alt / local-b
    verdict: Verdict
    valid_until: float        # RRset剩余TTL、签名有效期及策略上限最小值
    policy_version: str


def make_answer(wire, source, verdict, ttl, now=None, policy_version=POLICY_VERSION):
    """按方案计算 `valid_until = min(RRset剩余TTL, 签名有效期, 策略上限)`。

    调用方分别给出已折算好的秒数：`ttl`（RRset 剩余 TTL）、`sig_ttl`（签名剩余有效期）。
    这里只做"取最小 + 加上策略上限"，不猜测来源语义 ✓。
    """
    now = float(now if now is not None else time.time())
    ttl = max(0.0, float(ttl or 0.0))
    if verdict == Verdict.SECURE:
        cap = min(ttl, ACCEPT_MAX_TTL)
    elif verdict == Verdict.ACCEPTED:
        cap = min(ttl, ACCEPTED_MAX_TTL)
    else:
        cap = 0.0
    return Answer(wire, source, verdict, now + cap, policy_version)


def is_fresh(ans, now=None):
    """TTL/策略版本校验：任一不符即失效（⇒ 由上层映射为 SERVFAIL）。"""
    if ans is None or ans.wire is None:
        return False
    if ans.policy_version != POLICY_VERSION:
        return False
    if ans.verdict not in (Verdict.SECURE, Verdict.ACCEPTED):
        return False
    return float(ans.valid_until) > float(now if now is not None else time.time())


def choose_answer(primary, alternate):
    """方案给出的准入裁决 —— **逐字对应其伪代码，不做 freshness 校验** ✓。

    方案明确："TTL过期、策略版本错误**在进入 choose 前**失效" ⇒ 这两件事由
    `finalize_answer()`（守卫的最终出口）负责 ✓，本函数保持纯三规则，便于逐条验收 ✓。
    返回被采纳的 Answer，或 None（⇒ 上层必须回 SERVFAIL，绝不静默丢弃）。
    """
    if any(a is not None and a.verdict == Verdict.BOGUS for a in (primary, alternate)):
        return None                      # bogus 不可被任何备用"修复"
    if primary is not None and primary.verdict in (Verdict.SECURE, Verdict.ACCEPTED):
        return primary
    # local-b 的 UNKNOWN 不能仅凭"没结论"被放行 ⇒ 只能靠认证备用
    if alternate is not None and alternate.verdict in (Verdict.SECURE, Verdict.ACCEPTED):
        return alternate
    return None


def finalize_answer(primary, alternate, now=None):
    """守卫的**最终出口**（方案：`handle()` 所有正常出口都经它 ✓）。

    先做 freshness（TTL/签名有效期）与策略版本校验 ✓ —— 任一不符即**视为失效** ✓；
    再交给纯函数 `choose_answer()` ✓。返回 None 时上层必须回 **SERVFAIL** ✓。
    """
    def _ok(ans):
        return is_fresh(ans, now)

    p = primary if _ok(primary) else None
    a = alternate if _ok(alternate) else None
    # BOGUS 的语义必须保留（即便其 wire 为空 ⇒ 它是"安全结论"而非"没有答案"）
    if any(a is not None and a.verdict == Verdict.BOGUS for a in (primary, alternate)):
        return None
    if primary is not None and primary.verdict == Verdict.TRANSPORT and a is None:
        return None
    return choose_answer(p, a)


def legacy_choose_answer(primary, alternate, now=None):
    """**旧行为对照**（仅供测试证明漏洞存在，生产绝不调用 ✓）。

    对应当前生产 guard 的历史逻辑：`domestic()` / `R3B` / `CNB` / `fallback_b`
    在只有 R1 特征检查时会把 B 的应答直接 `return rewrite_id(rb, qid)`
    —— 即"无本地验证结论也能放行污染候选" ✗。本函数把这个行为**显式复现**出来，
    以便 `tests/test_answer_policy.py` 先证明它在旧策略下会放行、再证明新策略会拒绝 ✓。
    """
    if primary is not None and primary.wire is not None:
        return primary                   # 旧行为：有字节就采用（含 UNKNOWN 的 B）✗
    if alternate is not None and alternate.wire is not None:
        return alternate
    return None


__all__ = ["Verdict", "Answer", "POLICY_VERSION", "ACCEPT_MAX_TTL", "ACCEPTED_MAX_TTL",
           "make_answer", "is_fresh", "choose_answer", "finalize_answer", "legacy_choose_answer"]
