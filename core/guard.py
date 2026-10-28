#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dnsguard v2 —— 夹在 AGH 与 unbound 之间的投毒识别/自动纠偏层。

默认把查询交给 unbound（快、geo 正确）；一旦发现答案可疑，就改用境外干净 DoT 上游，
并把该域名记入持久化黑名单（以后直接走干净上游）。

v2 相对 v1 的判据改造（2026-10-04）：
  R1 同步判据：精确已知注入 IP / 已确认学习集（学习集要求 ≥2 个不同域名交叉印证）
     ＋ 大厂跨族网段（Meta/Twitter/Dropbox，带归属豁免，避免误伤 facebook/x.com/dropbox 自身）
  R2 A 查询 unbound 给不出地址而干净上游有 IPv4 → 采用干净答案（不再把 "rcode=N" 当 IP 学习）
  R3 域名已在黑名单 → 直接走干净上游
  R4 后台核验：真答案是 CNAME 链而 unbound 直接给 A（伪造特征）
  R5 后台核验：清缓存多采样抖动（GFW 注入的典型特征），并做两层对照 ——
     有稳定交集（RRset 子集轮转）或干净上游同样会变（NTP pool 等）时判为"域名自身轮转"，不判投毒
  R6 后台核验：证书对照 —— 只认"域名不匹配"，链不可信/超时属无法判定；
     且必须做对照测试：干净上游的 IP 持有该域名证书时，unbound 的 IP 不持有才算投毒
  CN .cn 分支：不再直接放过，改用加密国内通道（unbound B → 360/AliDNS DoT）核对

安全约束：
  - 只有"合法 IPv4 且被 ≥2 个不同域名指向"的地址才允许进入学习集，
    防止共享 CDN/Akamai/Azure 的 IP 因单条误报造成连带改道。
  - 证书判据只用于"这个 IP 是不是这个域名的主人"，不叠加链信任判断。

用法：guard.py            正常运行
      guard.py --status   打印黑名单与统计
      guard.py --pending  待确认清单
      guard.py --confirm/--ignore/--forget <域名>
      guard.py --allow/--unallow <域名>   人工豁免（误报复核后放行，绕过 suspicious()）
      guard.py --recheck  用国内段/证书对照清洗存量待确认
      guard.py --prune-ips 清理未获 ≥2 域名印证的存量学习 IP
      guard.py --churn <域名>  手动跑一次抖动检测（诊断用）
环境变量（便于旁路灰度测试）：GUARD_PORT / GUARD_STATE_DIR / GUARD_LOG /
      GUARD_UNBOUND / GUARD_UNBOUND_B / GUARD_DOQ / GUARD_DOQ2 / GUARD_UNBOUND_CONTAINER / GUARD_NO_CHURN /
      GUARD_NO_CORROB(关 R8 单路核对) / GUARD_CORROB_TTL / GUARD_CORROB_TIMEOUT
干净上游池：3 条 DoT + 2 路 DoQ 中继（aghdq:5533→NextDNS、aghdq2:5534→Quad9 dns10 无过滤）
"""
import collections
# P34-AO（方案任务2/3）：按**自身目录**导入同发布版本的准入策略，
# 不固定插 /opt/dnsguard —— 保证两进程读同一份不可变版本 ✓。
try:
    import os as _os_rel
    import sys as _sys_rel
    _REL_DIR = _os_rel.path.dirname(_os_rel.path.abspath(__file__))
    if _REL_DIR not in _sys_rel.path:
        _sys_rel.path.insert(0, _REL_DIR)
    from answer_policy import POLICY_VERSION as _POLICY_VERSION
except Exception as _e_rel:
    _POLICY_VERSION = "unavailable:%s" % _e_rel

# ===== 2026-10-10 P34-AQ（方案任务2「最小安全版本」）：CN 未签名路径**不再采用 B** =====
# 方案：B 只能当见证 ⇒ "CN未签名直接选A/alt，B只有本地可确认secure时可直接使用" ✓。
# B 的应答**永远**是 UNKNOWN（见 alt_adapter.classify_response），因此本助手在启用后
# 依次尝试：A（本地认证）→ alt（认证适配器）→ None（⇒ 上层回 SERVFAIL）✓。
# 默认 off ⇒ 行为与今天完全一致 ✓（可回滚、可灰度）。


# ===== 2026-10-10 Task 3（P1-1）：**来源标签 → 出口闸门类别**的集中映射 =====
# 背景：`domestic()` 返回的 `src` 共 5 个取值（A/B/CNV/POL/POL-SF），而出口此前一律写成
# `"local-a" if src == "A" else "local-b"` ⇒ POL / CNV / POL-SF 全被折成 `local-b` ✗：
#   · "POL" ⇒ `local-alt`：该字节**已经过 `finalize_answer()` 准入** ✓ ⇒ 按真实来源过闸 ✓，
#              不再在同一出口被"再裁决一遍" ✗（此前退化成 UNKNOWN ⇒ 重问 alt ⇒ POL 答案永不下发 ✗）；
#   · "CNV" / "POL-SF" ⇒ **None**：两者都是**终局安全结论**（本地否决的 NXDOMAIN / SERVFAIL）✓，
#              已经是 fail-closed ⇒ **不再过闸** ✗（过闸会被 alt 或准入缓存"修复"✗）。
_LABEL_MAP = {"A": "local-a", "B": "local-b", "POL": "local-alt", "CNV": None, "POL-SF": None,
              # ★ 2026-10-11 §6 第 113/114 行：**国内认证加密源**（`unbound-B`，DoT + 本机 DNSSEC 校验）
              # 在 CN 名下晋升为可采纳主源 ⇒ 它有**自己的诚实来源标签** ✓，不再借用 `local-alt` ✓
              # （借用会让"国内 vs 海外"在审计里无法区分 ✗ —— 而 §6 的整个目的就是区分这两者 ✓）。
              "CNB": "local-cn"}


# ===== 方案 §2-b：**证据来源的准确标签** =====
# 现场问题：`_alt_classify(_rawretry, ...)` 原来把**见证通道**（`_witness_addr`，
# aghdq→NextDNS）取回的字节标成 `local-a` ✗ ⇒ ①审计里"来源"与事实不符 ✗；
# ②它进了 `_src_bucket()` 的 `local-a` 桶 ⇒ "本地验证器 A 的采纳率"被非 A 的证据污染 ✗。
# 方案 §2 要求"记录证据来源" ⇒ 新增可区分的 `witness` 标签 ✓。
# `local-b` **保留在名单里**（不删）：B 的候选绝不能被采纳 ⇒ 它的计数必须恒为 0 ✓；
# 保留标签才能在安全门里**看见**任何 B 泄漏 ✗（丢进 `other` 反而会掩盖泄漏 ✗）。
_SRC_WHITELIST = ("local-a", "local-alt", "local-b", "local-cn", "witness", "clean-channel",
                  "negative-cache", "strict", "none")


def _pol_label(ans):
    """§6：把 `_policy_cn_answer()` 的采纳结果折算成 `_LABEL_MAP` 键 ✓。

    国内认证加密源（`source == "local-cn"`，§6 第 113/114 行）⇒ `"CNB"`（⇒ `local-cn` ✓）；
    其余（认证备用 / 见证 / 准入缓存复核）⇒ 沿用历史上的 `"POL"`（⇒ `local-alt` ✓）。
    出口闸门据此按**真实来源**分类 ✓ —— 审计里"国内 vs 海外"从此可分 ✓。
    """
    try:
        if ans is not None and str(getattr(ans, "source", "")) == "local-cn":
            return "CNB"
    except Exception:
        pass
    return "POL"


def _src_kind(src, default="local-a"):
    """把 `domestic()` 的 `src` 标签折算成出口闸门类别 ✓（Task 3 P1-1）。

    返回 `None` 表示**终局结论** ⇒ `_finalize_return()` 只重写 qid、不过闸 ✓。
    未登记的标签按 `default` 处理 ✓（正常流不会发生 ✓）。
    Step-1 §1：若调用方未在更早处定位最终来源，这里作为兜底把折算结果写进请求上下文 ✓。
    """
    _k = None
    if src in _LABEL_MAP:
        _k = _LABEL_MAP[src]
    else:
        _k = default
    try:
        _t = getattr(_TR, "t", None)
        if _t and _t.get("id") is not None and not _t.get("src"):
            _t["src"] = _k if _k else "none"
    except Exception:
        pass
    return _k


def _policy_cn_answer(name, qtype, a_wire, b_wire, deadline=None, query_id=None,
                      _refresh=False, _skip_cache=False):
    # `_refresh=True` **仅**由 §5 后台 CN 刷新路径（`_hot_refresh_one_cn`）使用 ✓：
    # 让采纳时那次 `_adm_cache_put` 带 `refresh=True`，否则「答案没变但寿命快到」
    # 会被 `_adm_same_answer` 闸门拦住 ⇒ 刷新永远不生效 ✗。其余调用点用默认值 ⇒ 行为不变 ✓。
    """启用时返回**可采纳的 `answer_policy.Answer`**（A / alt / 准入缓存）✓，
    或 None（表示"不得采用 B"⇒ 上层必须 SERVFAIL ✓）。

    Task 3（P0-2）：本函数**只做取数与准入裁决** ✓，**不再直接产出返回给客户端的字节** ✗ ——
    4 个调用点统一经 `_finalize_return()` 出口 ✓（⇒ 这 4 条路径同样有 `fin_*` 记账
    并吃得到准入缓存 ✓）。`domestic()` 内两处把 `Answer.wire` 连同 `src="POL"` 返回 ✓，
    由 `handle()` 的出口闸门按 `_LABEL_MAP["POL"] = "local-alt"` 过闸 ✓。
    """
    if not POLICY_MODE:
        return None
    try:
        from answer_policy import finalize_answer
        import alt_adapter as _ALT
    except Exception as _e:
        log("POL  模块导入失败: %s" % _e)
        return None
    # P34-AX（方案 5.2）：已被准入的答案**直接复用** ✓ ⇒ 重复 CN 查询回到毫秒级 ✓（B 的候选永不入缓存 ✗）
    # Validation failure is terminal even before a domestic/cache fast path.
    try:
        _aw = a_wire.get("wire") if isinstance(a_wire, dict) else a_wire
        if any(_ALT.dnssec_bogus(w) for w in (_aw, b_wire) if isinstance(w, bytes)):
            _drop_caches_for(name, why="bogus")
            return None
    except Exception:
        return None
    if not _skip_cache:
        # `_skip_cache=True` 只由后台 CN 刷新用 ✓：让刷新能真正重新裁决，
        # 同时**不 pop** 缓存 ⇒ 刷新期间在线请求继续命中旧记录 ✓（零穿透）。
        _ans = _adm_cache_answer(name, qtype)
        if _ans is not None:
            _tr_flag("adm_hit")            # Step-1 §1：准入缓存命中率
            return _ans
    a_ans = None
    try:
        if a_wire:
            _stats["policy_hint_present"] = _stats.get("policy_hint_present", 0) + 1
            # ★ P34-BC（曾定位到的真 bug ✗→✓）：站点① 传进来的曾一度是 `_veto_udp()` 的
            # **已解析三元组** `(rc, ips, proof)` ✗，**不是应答字节** ✗ ⇒ `classify_response(tuple)`
            # 因 `len<12` 恒返回 None ⇒ 见证**从未被采纳** ⇒ 冷 CN 查询被迫走跨境 alt（2~3.5s ✗）。
            # ★ 方案 §3 第 69 行（本轮）：`_veto_udp()` 改为**一次返回原始 wire** ✓
            # ⇒ 这里**直接用盒里的 wire** ✓，**不再对着同一见证源重取字节** ✗
            #   （旧路径的 `udp_query(..., timeout=1.0)` 是纯粹的重复取数 ✗，多一跳 RTT ✗）。
            if isinstance(a_wire, dict):
                # 新接口：`_VetoHint` —— 原始 wire 就在手里 ✓
                _wc = a_wire.get("wire")
                if _wc:
                    _stats["policy_hint_wire_used"] = _stats.get("policy_hint_wire_used", 0) + 1
                    # ★ 2026-10-15 N3（第四份审计）：`_wc` 来自**见证通道**
                    # （`GUARD_CN_VETO_WITNESS=127.0.0.1:5533` ⇒ aghdq→NextDNS），
                    # 不是本机 Unbound A ⇒ 旧代码把它标成 `local-a` ✗ ⇒
                    # ①审计里"来源"与事实不符；②它进了 `_src_bucket()` 的 `local-a` 桶 ⇒
                    # "本地验证器 A 的采纳率"被非 A 的证据污染 ✗。
                    # 现在按其真实来源标 `witness` ✓（`_SRC_WHITELIST` 本来就含它 ✓），
                    # 并单独计数"见证仅凭运营方声明 AD 就被判 SECURE"的次数 ✓ ——
                    # 让"运营方声明"与"本机验证器独立确认"在指标上分得开 ✓。
                    a_ans = _alt_classify(_wc, "witness")
                    if a_ans is not None:
                        if str(a_ans.verdict.value) == "secure":
                            _stats["cn_witness_secure_ad_declared"] = _stats.get("cn_witness_secure_ad_declared", 0) + 1
                        else:
                            # N3 精细分档（2026-10-16）：见证通道 AD=1 但报文无签名（或签名已过期）
                            # ⇒ 已降级 ACCEPTED ⇒ 与"带签名凭据的 secure"分开计数 ✓。
                            try:
                                _w_why = _ALT.ad_grade(_wc, "witness")[1]
                            except Exception:
                                _w_why = "?"
                            if _w_why in ("ad_declared", "sig_expired"):
                                _stats["cn_witness_ad_declared_accepted"] = _stats.get(
                                    "cn_witness_ad_declared_accepted", 0) + 1
                else:
                    # 拿到盒子但里面没有 wire（超时/无应答）⇒ 只留痕，**绝不重取** ✗ ——
                    # 重取只会再等一个超时，把长尾叠加起来 ✗（这正是 §3 要消除的重复取数 ✗）。
                    _stats["policy_hint_wire_missing"] = _stats.get("policy_hint_wire_missing", 0) + 1
                    _stats["policy_hint_refetch_fail"] = _stats.get("policy_hint_refetch_fail", 0) + 1
            elif isinstance(a_wire, (tuple, list)) and len(a_wire) == 3:
                # 旧接口（兼容保留）：三元组 ⇒ 按同族与 rcode 判"见证是否可用" ✓，
                # 但**不再重取字节** ✗ —— 无法分类时老实回退去看 alt（明确、可记账 ✓）。
                _rc_h, _ips_h, _pr_h = a_wire
                _fam_ok = bool(_ips_h) and (
                    (qtype == 1 and all(":" not in str(x) for x in _ips_h)) or
                    (qtype == 28 and all(":" in str(x) for x in _ips_h)) or qtype not in (1, 28))
                _stats["policy_hint_tuple"] = _stats.get("policy_hint_tuple", 0) + 1
                if _rc_h == 0 and _fam_ok:
                    _stats["policy_hint_tuple_ok"] = _stats.get("policy_hint_tuple_ok", 0) + 1
                else:
                    _stats["policy_hint_tuple_nofam"] = _stats.get("policy_hint_tuple_nofam", 0) + 1
                a_ans = None
            else:
                a_ans = _alt_classify(a_wire, "local-a")
            if a_ans is not None:
                _vk = "policy_hint_" + str(a_ans.verdict.value)
                _stats[_vk] = _stats.get(_vk, 0) + 1
        else:
            _stats["policy_no_hint"] = _stats.get("policy_no_hint", 0) + 1
    except Exception as _eh:
        _stats["policy_hint_exc"] = _stats.get("policy_hint_exc", 0) + 1
        a_ans = None
    b_ans = None
    try:
        if b_wire:
            # §2-a：B 只当见证 ⇒ 恒 UNKNOWN、无有效期 ✓（ttl 传 0 更诚实：
            # 从前写 300.0 让 B 得到一个看似有效的 `valid_until`，只是靠 `classify_response`
            # 内部对 local-b 特判才没被采纳 —— 现在由"0 有效期"**结构上**保证 ✓）。
            b_ans = _ALT.classify_response(b_wire, "local-b", ttl=0.0)   # 恒为 UNKNOWN ✓
    except Exception:
        b_ans = None
    # P34-AQ 修正：原来把超时硬夹在 1.5s ✗，而旁路对 CN 冷查询约 1.66s（任务1 实测）
    # ⇒ alt 一律超时 ⇒ 合法 CN 名被误判 SERVFAIL ✗。改为按剩余 deadline（上限 3.0s，
    # 对齐方案 GUARD_CORROB_DOT_TIMEOUT=3.5 与总 deadline 4.0 ✓）。
    _to = 3.0
    try:
        if deadline:
            _to = max(0.3, min(3.0, float(deadline) - time.time()))
    except Exception:
        _to = 3.0
    # P34-AY（方案 5.2「取用顺序」）✓：**A/见证已给出可采纳答案时，根本不必问 alt** ✗ ——
    # 认证备用对 CN 名常要 0.8~1.7s ✗，而 A/见证（aghdq→NextDNS）通常 0.25~0.4s ✓。
    # 之前无条件先问 alt ⇒ 冷查询被拖到 3s 撞满预算（实测 www.baidu.com 3031ms ⇒ rc=2 ✗）。
    try:
        from answer_policy import is_fresh as _is_fresh
    except Exception:
        _is_fresh = None
    # ★ 2026-10-11 §6 第 113/114 行（**本步唯一逻辑项**）：CN 名的"国内认证加密出口"晋升为**主源** ✓。
    #   开关 `GUARD_CN_DOMESTIC_PRIMARY`（默认**关** ⇒ 不设 = 与 release-14 行为逐字节相同 ✓）。
    #   依据（§6-112/113 实测：`/root/dns-s6-witness-check.json`、`dns-s6-dot-compare.json`）：
    #     · 国内**唯一**能支撑本机校验的运营方是 360（`dot.360.cn`）：其单源旁路对签名域
    #       `rc=0 ad=1 rrsig=1` ✓ ⇒ 正是方案 113 行要的"国内认证加密出口 → 本地 DNSSEC 验证 → 准入" ✓；
    #       AliDNS / DNSPod 剥离 RRSIG 与 NSEC 证明 ⇒ 其单源旁路**全部 rc=2** ⇒ 不可作验证源 ✗（fail-closed ✓）。
    #     · 对未签名 CN 名，`unbound-B` 返回 `cn=100% ov=0` ✓，而现有 A/alt 返回 `cn=0 ov=N` 的**海外边缘** ✗
    #       ——家庭出口实测：sina TTFB 469→31ms、taobao 328.5→70.5ms、163 203→55ms、alicdn 359.5→31.5ms ✓。
    #   ⇒ B 由"只当见证"（`alt_adapter.classify_response()` 对 `local-b` 的结构性 UNKNOWN ✓）
    #     升为**已批准的国内认证源**，裁定门槛与 A/alt **完全一致**（同一 `classify_response()` ✓、
    #     同一 `_alt_classify()` 的 TTL 取值 ✓、同一 `is_fresh()` ✓）：
    #       · `ad=1` ⇒ SECURE ✓；未签名 positive / 带证据的 negative ⇒ ACCEPTED（≤300s ✓）；
    #       · `rcode=2` ⇒ BOGUS ⇒ `is_fresh()` 恒 False ⇒ **不采纳** ⇒ 回退既有 A/alt ✓
    #         （**不新增 fail-closed** ✗：国内出口不可达 ≠ 安全结论 ✓；而**已成为结论的** bogus
    #          仍照旧在出口闸门 fail-closed、不被备用或缓存"修复" ✓ —— 与方案行 20/113 一致 ✓）；
    #       · 裸空壳（§5 的 `bare`）⇒ UNKNOWN ⇒ 不采纳 ✓（脏字节窗口无法借 CN 路径漏出去 ✓）。
    #   ★ release-16 修正（release-15 首次打开开关时被 **canary 夹具**抓到 ✗）：B 被采纳后，
    #     "存在性否决"（`cn_exist_veto()` 的 W1+W2 见证 + zone pin）**不再冗余** ⇒ 开关打开时
    #     ② 采纳前必须过 `cn_exist_veto(..., deny_probe=True)` 的存在性见证 ✓
    #        （闸门只对 deny_probe 打开 ⇒ 既有四个调用方在策略模式下**照旧跳过** ⇒ 行为不变 ✓）。
    #     实测反例：`zz-canary-*.googlevideo.com`、`*.tiktokcdn*.com`（cn_ip.txt 判为 CN）
    #     在 B 侧得**伪造正答案**（`rc=0 an=1`）而认证见证同名 `rc=3` ⇒ 曾致 `client_exposed=4` ✗。
    _dom_ans = None
    if CN_DOMESTIC_PRIMARY and b_wire and name:
        try:
            if is_cn_domain(name):
                _dom_ans = _alt_classify(b_wire, "local-cn")
                if _dom_ans is not None:
                    with _lock:
                        _k = "cn_dom_" + str(_dom_ans.verdict.value)
                        _stats[_k] = _stats.get(_k, 0) + 1
        except Exception:
            with _lock:
                _stats["cn_dom_exc"] = _stats.get("cn_dom_exc", 0) + 1
            _dom_ans = None
    # ★ release-16：把"不得采纳"的不变量**钉在采纳动作本身** ✓ ——
    #   ① 被 pin 的 zone / 命中已知投毒地址 ⇒ 不采纳 ✓；
    #   ② 未签名（ACCEPTED 档）国内答案 ⇒ 必须过**存在性见证**（方案 114 行"多来源核对"）✓：
    #      至少一家独立见证发过话、且**没有任何见证否认该名字存在** ⇒ 才允许采纳 ✓。
    #      `secure`（AD=1，本机 DNSSEC 已校验）不依赖见证 ✓。
    #   代价：探测失败（限流/超时）⇒ 只是**不采纳**（回落切换前的既有链路 ✓），
    #   **绝不 fail-closed** ✗ ⇒ 可用性不会比 release-15 之前更差 ✓。
    if _dom_ans is not None and name:
        _why = None
        try:
            if _cn_zone_denied(name):
                _why = "zone_pinned"
            else:
                _bips_dom = parse_a(b_wire)[1] if b_wire else []
                if _bips_dom and suspicious(_bips_dom, name):
                    _why = "suspicious"
                elif _dom_ans.verdict.value == "accepted":
                    if (CN_DOMESTIC_PRIMARY and CN_DOMESTIC_TRUST_B
                            and is_cn_trusted(name)):
                        # 2026-10-15 拆分：免见证只给"信任判定"通过的域名（国别后缀 /
                        # 人工白名单 / all 档）；其余国内答案必须过存在性见证 ✓
                        with _lock:
                            _stats["cn_dom_witness_bypass"] = _stats.get("cn_dom_witness_bypass", 0) + 1
                            _stats["cn_trust_bypass"] = _stats.get("cn_trust_bypass", 0) + 1
                    else:
                        _cn_bump("cn_trust_witness")
                        _deny = cn_exist_veto(
                            name, qtype, b_wire, _bips_dom, _dl_wall(1.0),
                            w1_hint=(a_wire if isinstance(a_wire, dict) else None),
                            deny_probe=True)
                        if _deny is True:
                            _why = "witness_deny"
                        elif _deny is None:
                            _why = "witness_nonev"
        except Exception:
            _why = "guard_exc"     # 守卫自身出错 ⇒ 保守拒绝 ✓（绝不误放行 ✗）
        if _why is not None:
            with _lock:
                _k = "cn_dom_" + _why
                _stats[_k] = _stats.get(_k, 0) + 1
            log("POL  %-38s 国内源候选被否决（%s）⇒ 回退 A/alt ✓" % (name[:38], _why))
            _dom_ans = None
    _dom_fresh = bool(_dom_ans is not None and _is_fresh is not None and _is_fresh(_dom_ans))
    if _dom_ans is not None and not _dom_fresh:
        # This was historically nested after the fresh-answer return and could never
        # count zero-TTL answers. Keep the fallback decision visible in window deltas.
        with _lock:
            _stats["cn_dom_not_fresh"] = _stats.get("cn_dom_not_fresh", 0) + 1
    if _dom_fresh:
        if _dom_ans.verdict.value in ("secure", "accepted"):
            _adm_cache_put(name, qtype, _dom_ans.wire, _dom_ans.verdict.value, _dom_ans.source,
                           _adm_ttl_from(_dom_ans, _adm_cap_for(_dom_ans.verdict)),
                           refresh=_refresh)
            with _lock:
                _stats["policy_adopt_cn"] = _stats.get("policy_adopt_cn", 0) + 1
                _stats["policy_adopted"] = _stats.get("policy_adopted", 0) + 1
                _stats["policy_domestic"] = _stats.get("policy_domestic", 0) + 1
            log("POL  %-38s 国内认证加密源（%s）⇒ 采用（geo 优先，免问 A/alt）✓"
                % (name[:38], _dom_ans.verdict.value))
            _tr_flag("policy_used")
            _tr_flag("cn_path")
            return _dom_ans
    # Explicitly gated one-shot exception for trusted CN B. It preserves TTL=0,
    # never writes the admission cache, and requires the response to match this
    # query's ID/name/type. Keep disabled until Unbound B's stale EDE marker is
    # verified; otherwise fresh and stale zero-TTL replies are indistinguishable.
    if (not _dom_fresh and _dom_ans is not None
            and _dom_ans.verdict.value == "accepted"
            and CN_DOMESTIC_PRIMARY and CN_DOMESTIC_TRUST_B
            and is_cn_trusted(name)
            and CN_DOMESTIC_ZERO_TTL_ONESHOT and query_id is not None):
        try:
            _zero_ttl_negative_once = _ALT.is_empty_nxdomain_one_shot_candidate(
                b_wire, name, qtype, query_id=query_id)
        except Exception:
            _zero_ttl_negative_once = False
        if _zero_ttl_negative_once:
            with _lock:
                _stats["cn_dom_zero_ttl_oneshot"] = _stats.get("cn_dom_zero_ttl_oneshot", 0) + 1
            log("POL  %-38s 可信 CN B 零 TTL NXDOMAIN ⇒ 单次返回（不缓存）"
                % ((name or "?")[:38]))
            _tr_flag("policy_used")
            _tr_flag("cn_path")
            return _dom_ans
    if a_ans is not None and _is_fresh is not None and _is_fresh(a_ans):
        if a_ans.verdict.value in ("secure", "accepted"):
            _adm_cache_put(name, qtype, a_ans.wire, a_ans.verdict.value, a_ans.source,
                           _adm_ttl_from(a_ans, _adm_cap_for(a_ans.verdict)))
            with _lock:
                _k = "policy_adopt_" + str(a_ans.source).replace("local-", "")
                _stats[_k] = _stats.get(_k, 0) + 1
                _stats["policy_adopted"] = _stats.get("policy_adopted", 0) + 1
                _stats["policy_fastpath"] = _stats.get("policy_fastpath", 0) + 1
            log("POL  %-38s A/见证可采纳（%s）⇒ 直接用，免问备用 ✓" % (name[:38], a_ans.verdict.value))
            _tr_flag("policy_fastpath")   # Step-1 §1：A/见证快路（未问备用）
            return a_ans
    alt_ans = None
    # ★ 方案 §3 第 70 行：**alt 每个请求最多启动一次** ✓ —— 本函数与 `_finalize_return()`
    #   都会走备用 ✗（历史上同一次请求可能付两轮 alt ✗）⇒ 用统一闸门 ✓。
    #   预算也改成**吃剩余**（`_dl_rem`）✓；原 `min(3.0, deadline-now)` 仍留着 cap 3.0 ✓
    #   （`deadline` 由调用方用 `_dl_wall(3.0)` 给 ✓）。
    if not _alt_gate():
        # §4 第 3 项：未就绪 ⇒ **不进入长时间 alt 尝试**（不发包、不占名额）✓
        alt_ans = None
    elif not _src_once("alt"):
        _stats["alt_dup_skipped"] = _stats.get("alt_dup_skipped", 0) + 1
        alt_ans = None
    else:
        try:
            _t_al = time.monotonic()
            _to_eff = _dl_rem(_to)
            if _to_eff is None:
                _to_eff = _to
            alt_ans = _ALT.query_alt(name, qtype, timeout=_to_eff) if _to_eff > 0.05 else None
            _tr_note("alt", (time.monotonic() - _t_al) * 1000.0,
                     "ok" if (alt_ans is not None and alt_ans.verdict.value in ("secure", "accepted")) else "fail")
            if alt_ans is not None and alt_ans.verdict.value in ("secure", "accepted"):
                _tr_flag("alt_ok")
                _src_mark("alt", "ok")
            else:
                _tr_flag("alt_none")
                _src_mark("alt", "fail")
        except Exception:
            alt_ans = None
    if alt_ans is not None and alt_ans.verdict.value == "bogus":
        _drop_caches_for(name, why="bogus")
        return None
    picked = finalize_answer(a_ans, alt_ans)      # 注意：**B 不参与裁决** ✓
    if picked is not None and picked.wire:
        _k = "policy_adopt_" + str(picked.source).replace("local-", "")
        with _lock:
            _stats[_k] = _stats.get(_k, 0) + 1
            _stats["policy_adopted"] = _stats.get("policy_adopted", 0) + 1
        log("POL  %-38s B 只当见证 ⇒ 采用 %s（%s）" % (name[:38], picked.source, picked.verdict.value))
        _adm_cache_put(name, qtype, picked.wire, picked.verdict.value, picked.source,
                       _adm_ttl_from(picked, _adm_cap_for(picked.verdict)))
        return picked
    with _lock:
        _stats["policy_reject_b"] = _stats.get("policy_reject_b", 0) + 1
    # P34-BM：同样先做一次认证源重试 ✓（只重试认证源 ✓，绝不退回 B ✗）
    _tr_flag("policy_used")
    _rp = _retry_authenticated(name, qtype)
    if _rp is not None and _rp.wire:
        _adm_cache_put(name, qtype, _rp.wire, _rp.verdict.value, _rp.source,
                       _adm_ttl_from(_rp, _adm_cap_for(_rp.verdict)))
        log("POL  %-38s 无认证答案可用 ⇒ 认证源重试成功（%s）✓" % (name[:38], _rp.source))
        return _rp
    log("POL  %-38s 无认证答案可用 ⇒ 不采用 B（SERVFAIL）" % name[:38])
    return None

# ===== 2026-10-10 P34-AX（方案 5.2 / 任务2 补救）：**经准入的答案缓存** =====
# 目的：方案允许"在安全约束内测得最优" ✓ —— CN 路径此前**每次**都要打见证 + 问认证备用（实测 0.5~1.5s ✗），
# 因此把**已经过 finalize_answer 准入**的字节缓存起来复用 ✓，把重复查询拉回毫秒级 ✓。
# 关键约束（逐条对齐方案）✓：
#   · **只缓存 SECURE/ACCEPTED 的准入结果** ✓ —— B 的候选永不入缓存 ✗；
#   · `valid_until = min(RRset 剩余 TTL, 准入上限)` ✓（SECURE≤900s / ACCEPTED≤300s ✓），**不固定缓存一小时** ✓；
#   · 记录 `policy_version` ✓，版本不符即失效 ✓；
#   · 键取 `(name, qtype)` ✓（本链路 DO=1/CD=0 固定 ✓、无 ECS ✓；operator 记在记录里 ✓ 便于审计 ✓）；
#   · 有容量上限并做最旧淘汰 ✓（避免无界增长 ✗）。


def _adm_key(name, qtype):
    # 2026-10-28 ECS：第三维 = 客户端 ECS（无 ECS 时为 None）⇒ 不同 /24 的答案互不串用
    return (str(name).lower().rstrip("."), int(qtype or 1), _cur_ecs_key())


def _adm_drop(k):
    """弹出一条准入缓存记录，**并同步扣减字节账** ✓（§5 第 4 项的 16 MiB 预算靠它不漂移 ✓）。

    为什么必须集中成一个函数：`_ADM_CACHE` 有 **6 处** `pop`（命中过期 / schema 拒 /
    证据过期 / 失效 / 条数淘汰 / 字节淘汰）✗ —— 每处各写一遍扣减，漏一处 就会让
    `_ADM_BYTES` **单调虚高** ⇒ 预算闸门被永久触发 ⇒ 缓存再也写不进新条目 ✗
    （症状是"缓存命中率无声下降"，比崩溃难查得多 ✗）。集中一次，结构上不可能漏 ✓。
    """
    try:
        _e = _ADM_CACHE.pop(k, None)
        if _e:
            _ADM_BYTES[0] -= int(_e.get("_sz") or 0)
            if _ADM_BYTES[0] < 0:
                _ADM_BYTES[0] = 0
        return _e
    except Exception:
        return None


def _adm_cache_get(name, qtype, now=None):
    if not POLICY_MODE or not name:
        return None
    _wall_given = now is not None
    now = float(now if now is not None else time.time())
    k = _adm_key(name, qtype)
    rec = _ADM_CACHE.get(k)
    if not rec:
        return None
    if rec.get("policy_version") != str(globals().get("_POLICY_VERSION", "n/a")) or float(rec.get("until") or 0) <= now:
        _adm_drop(k)
        try:
            _stats["adm_cache_expired"] = _stats.get("adm_cache_expired", 0) + 1
        except Exception:
            pass
        return None
    # ★ 方案 §2 第 55 行："**旧 schema 拒绝加载**" ✓ —— 记录结构变更后，旧记录必须
    # 当作未命中 ✗（否则新代码会用旧语义的字段算出错误寿命 ✗，静默出错 ✗）。
    try:
        if int(rec.get("schema") or 0) != int(_ADM_SCHEMA):
            _adm_drop(k)
            _stats["adm_cache_schema_reject"] = _stats.get("adm_cache_schema_reject", 0) + 1
            return None
    except Exception:
        pass
    # ★ 2026-10-15 第三份审计 F2：**名单代次**核对 —— 名单热更新（typed / veto / 例外）
    #   换了内容 ⇒ 此前按旧分类写入的准入缓存**不得**再复用。没有这一步，"把域名移出
    #   国内信任集合"不会立即生效：旧答案仍会命中的 300s 内继续下发（审计 F2）。
    #   注意：这不是"清缓存"，而是**命中时比对**⇒ 结构上不可能漏（不依赖清理是否执行）。
    try:
        if str(rec.get("cn_gen") or "") != _cn_gen_id():
            _adm_drop(k)
            _stats["adm_cache_gen_mismatch"] = _stats.get("adm_cache_gen_mismatch", 0) + 1
            return None
    except Exception:
        pass
    # ★ 方案 §2 第 48 行：**无法证明同一视图时不共用缓存** ✓。
    # 本链路 DO=1/CD=0/无 ECS 是**固定**的（`mk_query_do()` 写死 RD、无 CD、EDNS0 DO=1；
    # AGH 侧 `edns_client_subnet.enabled: false`）⇒ 记录里存下这三项并在命中时比对：
    # 一旦将来有人给某条路径开了 ECS 或 CD，缓存就不会被跨视图共用 ✗（结构上防止串味 ✓）。
    try:
        if (str(rec.get("view") or "default") != "default"
                or bool(rec.get("do")) is not True
                or bool(rec.get("cd")) is not False
                or rec.get("ecs") != _cur_ecs_key()
                or int(rec.get("qclass") or 1) != 1):
            _stats["adm_cache_view_mismatch"] = _stats.get("adm_cache_view_mismatch", 0) + 1
            return None
    except Exception:
        pass
    # ★ 方案 §2 第 55 行："签名到期不返回" ✓ —— **绝对证据失效时刻**单独再判一次 ✗→✓。
    # `until` 已经逐条与策略上限取过 min ✓，这里是对"证据本身"的**二次收口** ✓：
    # 只要证据（RRset 到期 / 签名失效 / SOA 寿命）已经过了，无论 `until` 还剩多少都不再复用 ✗。
    # 有它才敢说"策略上限永不长于证据寿命" ✓ —— 这是方案对"绝对证据失效时间"的要求 ✓。
    try:
        _evu = rec.get("evidence_until")
        if _evu is not None and float(_evu) <= now:
            _adm_drop(k)
            _stats["adm_cache_evidence_expired"] = \
                _stats.get("adm_cache_evidence_expired", 0) + 1
            return None
    except Exception:
        pass
    try:
        _stats["adm_cache_hit"] = _stats.get("adm_cache_hit", 0) + 1
    except Exception:
        pass
    _w = rec.get("wire")
    # ★ 方案 §2 第 50 行：**逐 RR 扣除经过秒数** ✓ —— 这一步是**载荷所在**，不是装饰 ✗。
    # 原因：命中后答案会再次经 `_finalize_return()` → `_alt_classify()` **重新分类**，
    # 而分类只看得见缓存里那份 wire 自己的 TTL 字段 ✗ —— 若不老化，那份 wire 仍写着
    # "TTL=300"，`make_answer(ttl=300, now=now)` 就会算出 `valid_until = now+300` ⇒
    # **每命中一次就把寿命从当下重新起算 300 秒** ✗（无界续期；用户观察到的"上游换了
    # guard 还答旧值"正是这条链 ✓）。老化后：`valid_until = now + 剩余` = **原始绝对截止** ✓
    # ⇒ 无论命中多少次、跨多少层都不会延长原始期限 ✓。
    # 同时"命中不滑动续期"由 `until`/`valid_until` 存**绝对时刻**从结构上保证 ✓。
    try:
        import alt_adapter as _ALT_A
        # ★ 方案 §2 第 48 行"插入**单调**时间"✓：经过秒数优先用 `time.monotonic()` 求差，
        # 而不是用墙上时钟 ✗ —— 否则 NTP 回拨一次就会让"经过秒数"变负（被钳到 0 ⇒
        # 等于**原地续期**回到满 TTL ✗），前跳一次又会把答案提前判死 ✗。
        # 显式传 `now=` 的调用方（离线测试 / 确定性复算）继续走墙上时钟口径 ✓。
        _el = None
        if not _wall_given and rec.get("stored_mono") is not None:
            _el = max(0.0, time.monotonic() - float(rec["stored_mono"]))
        if _el is None:
            _stored = float(rec.get("stored") or now)
            _el = max(0.0, now - _stored)
        if _el >= 1.0:
            _aged = _ALT_A.age_wire(_w, _el, now=now)
            if _aged is not None:
                _w = _aged
    except Exception:
        pass
    return _w


def _adm_ttl_from(ans, cap=300.0, now=None):
    """Task 3（P1-2）：准入缓存 TTL **取自答案** ✓ —— `min(valid_until - now, cap)`，下限 0 ✓。

    返回 0 表示"该答案已过期 / 零 TTL" ⇒ 调用方**不得入缓存** ✗
    （旧代码把 0 补成 60s ✗ ⇒ 把零 TTL 答案延长 ✗）。
    """
    try:
        _now = float(now if now is not None else time.time())
        return max(0.0, min(float(ans.valid_until) - _now, float(cap)))
    except Exception:
        return 0.0


def _adm_cache_answer(name, qtype, now=None):
    """Task 3（P0-2）：从准入缓存重建 `answer_policy.Answer` ✓。

    `_policy_cn_answer()` 现在只返回 `Answer` / None ✓，不再直接产生返回给客户端的字节 ✗。
    缓存未命中 / 已过期 / 记录不可解读 ⇒ None ✓。
    """
    try:
        _w = _adm_cache_get(name, qtype, now=now)
        if not _w:
            return None
        rec = _ADM_CACHE.get(_adm_key(name, qtype)) or {}
        from answer_policy import Answer, Verdict
        _vu = rec.get("valid_until", rec.get("until"))
        return Answer(_w, str(rec.get("source") or "local-alt"),
                      Verdict(str(rec.get("verdict") or "accepted")),
                      float(_vu or 0.0),
                      str(rec.get("policy_version") or "n/a"))
    except Exception:
        return None


def _adm_invalidate(name, qtype=None, why=""):
    """方案 §2 第 51 行：**新观察到 bogus 或强否决时立即失效关联缓存** ✓。

    为什么必需：准入缓存里存的是**已采纳**的答案 ✓，一旦上游在验证侧翻转为
    bogus（签名失效 / 上游 SERVFAIL）或本地给出强否决，继续用缓存命中答复
    就等于把"已被推翻的结论"继续放给客户端 ✗ —— 用户观察到的
    "上游换了 guard 还答旧值"正是这条链 ✓。

    `qtype=None` ⇒ 该名字**所有类型**一起失效 ✓（bogus 结论是名字级的：
    我们不知道上游为何翻，宁可多失效也不算少失效 ✓）。
    返回失效条数 ✓。
    """
    _n = 0
    try:
        _nm = str(name).lower().rstrip(".")
        for _k in list(_ADM_CACHE.keys()):
            if not isinstance(_k, tuple) or len(_k) != 2:
                continue
            if _k[0] != _nm:
                continue
            if qtype is not None and int(_k[1]) != int(qtype):
                continue
            _adm_drop(_k)
            _n += 1
    except Exception:
        pass
    try:
        if _n:
            _stats["adm_cache_invalidated"] = _stats.get("adm_cache_invalidated", 0) + _n
            _stats["adm_cache_invalidated_" + str(why or "other")] = \
                _stats.get("adm_cache_invalidated_" + str(why or "other"), 0) + _n
    except Exception:
        pass
    if _n:
        log("ADM  %-38s 立即失效准入缓存 %d 条（原因=%s）" % (str(name)[:38], _n, why or "?"))
    return _n


def _drop_caches_for(name, qtype=None, why=""):
    """方案 §2 第 51 行后半句：**后台发现 bogus 后阻止后续返回** ✓。

    为什么不能只清准入缓存：本进程里能让"已被推翻的结论"继续出去的**还有两条** ✗ ——
      · `_corrob`（R8 核对钉住的窗口，窗口上限 = `GUARD_CORROB_TTL`，生产是 **3600s** ✗）：
        一旦该名字后来被判为投毒/翻转，窗口内仍会按"已核对"改道发出那份字节 ✗；
      · `_neg_cache`（我方验证器的否定结论）✗：名字被判可疑后，那份"不存在"的结论
        不再是证据 ✗。
    ⇒ 三者一起清 ✓，并分开记账便于核对（`adm_cache_invalidated*` / `pin_invalidated*` /
    `neg_invalidated*`）。`qtype=None` ⇒ 名字级（bogus/投毒都是名字级结论，宁可多清 ✓）。
    """
    _n = _adm_invalidate(name, qtype=qtype, why=why)
    _p = 0
    _q = 0
    try:
        _nm = str(name).lower().rstrip(".")
        with _lock:
            for _k in list(_corrob.keys()):
                if not isinstance(_k, tuple) or len(_k) != 2:
                    continue
                if _k[0] != _nm:
                    continue
                if qtype is not None and int(_k[1]) != int(qtype):
                    continue
                _corrob.pop(_k, None)
                _p += 1
            for _k in list(_neg_cache.keys()):
                if not isinstance(_k, tuple) or len(_k) != 2:
                    continue
                if _k[0] != _nm:
                    continue
                if qtype is not None and int(_k[1]) != int(qtype):
                    continue
                _neg_cache.pop(_k, None)
                _q += 1
    except Exception:
        pass
    # ★ 方案 §2 第 51 行："**安全准入证据和答案缓存分开**" ✓ —— 所以三类分开记账 ✗→✓：
    # 从前 `_corrob` 与 `_neg_cache` 共用一个 `pin_invalidated_*` 计数 ✗，
    # 看板上分不出"是钉住窗口没清掉"还是"否定结论还在用" ✗（两个是完全不同的故障 ✗）。
    for _key, _val in (("pin_invalidated_" + str(why or "other"), _p),
                       ("neg_invalidated_" + str(why or "other"), _q)):
        if not _val:
            continue
        try:
            _stats[_key] = _stats.get(_key, 0) + _val
        except Exception:
            pass
    if _p or _q:
        log("DROP %-38s 一并清除 核对钉住 %d 条 / 否定缓存 %d 条（原因=%s）"
            % (str(name)[:38], _p, _q, why or "?"))
    return _n + _p + _q


def _adm_rr_ttls(wire):
    """记录报文里各 RR 的 TTL 分布 ✓（方案 §2 第 48 行"原始各 RR TTL"）—— 仅用于核对/诊断。

    返回 `{"an":[...],"ns":[...],"ar":[...]}` 形状的 list；解析失败返回 None ✓。
    OPT 不计入（它的字段不是寿命 ✗）。
    """
    try:
        import alt_adapter as _ALT_T
        _h, _q, _out = _ALT_T._parse_rrs(wire)
        if _h is None:
            return None
        out = {}
        for _sec in ("an", "ns", "ar"):
            out[_sec] = [int(_r.get("ttl") or 0) for _r in (_out.get(_sec) or [])
                         if _r.get("type") != 41]
        return out
    except Exception:
        return None


def _adm_evidence_until(wire, now, ttl):
    """方案 §2 第 48 行："**绝对证据失效时间**" ✓ —— 与"我方允许复用到何时"**分开** ✗→✓。

    `ttl`（调用方给的准入 TTL）已经含了策略上限（SECURE≤900 / ACCEPTED≤300）✗；
    这里再问一次 `rrset_validity()` 拿**证据自己的**寿命 ✓（签名失效时刻 / RRset 原始到期 /
    否定答案的 SOA 寿命），并与 `ttl` 取 min 保守收口 ✓ ⇒ 返回值**永不超过**准入 TTL ✓，
    且当证据比策略上限更短时**如实反映更短的证据期限** ✓。
    解析不出来 ⇒ None ✓（宁可不记录，也不编一个数 ✗）。
    """
    try:
        import alt_adapter as _ALT_E
        _ev, _det = _ALT_E.rrset_validity(wire, now=now)
        _ev = float(_ev or 0.0)
        if _ev <= 0:
            return None
        return now + min(_ev, float(ttl))
    except Exception:
        return None


def _adm_evidence_kind(wire):
    """证据类别（`forward`/`negative`/…）✓ —— 诊断用，便于核对"这条缓存靠什么证据活着" ✓。"""
    try:
        import alt_adapter as _ALT_K
        _ev, _det = _ALT_K.rrset_validity(wire)
        if isinstance(_det, dict):
            return str(_det.get("kind") or "?")
    except Exception:
        pass
    return "?"


def _adm_same_answer(a, b):
    """两份报文是不是**同一个答案**（忽略 qid 与各 RR 的 TTL 字段）✓。

    用途：方案 §2 第 50 行"**缓存命中不重新插入、不滑动续期**" ✓。
    为什么需要它：缓存命中的字节会**再走一遍出口闸门** ✓（`_policy_cn_answer` → `_finalize_return`
    → 分类 → `_adm_cache_put`）⇒ 若不拦住，同一条答案会被**重新写回** ✗。
    只比"问题 + 各段 RR 的 (name,type,rdata)" ⇒ 与 TTL/压缩指针/老化程度无关 ✓，
    因此"同一条答案（哪怕已被老化过）"判为相同 ✓、"上游换了答案"判为不同 ✓
    （换答案必须被允许立刻采用新期限 ✓，否则优化就变成了僵化 ✗）。
    """
    try:
        if not a or not b or len(a) < 12 or len(b) < 12:
            return False
        import alt_adapter as _ALT_P
        _ha, _qa, _oa = _ALT_P._parse_rrs(a)
        _hb, _qb, _ob = _ALT_P._parse_rrs(b)
        if _ha is None or _hb is None:
            return False
        if _qa != _qb:
            return False
        if (int(_ha[3]), int(_ha[4]), int(_ha[5])) != (int(_hb[3]), int(_hb[4]), int(_hb[5])):
            return False
        for _sec in ("an", "ns", "ar"):
            _ra = [(r.get("name"), int(r.get("type") or 0), bytes(r.get("rdata") or b""))
                   for r in (_oa.get(_sec) or [])]
            _rb = [(r.get("name"), int(r.get("type") or 0), bytes(r.get("rdata") or b""))
                   for r in (_ob.get(_sec) or [])]
            if _ra != _rb:
                return False
        return True
    except Exception:
        return False


def _adm_cache_put(name, qtype, wire, verdict, source, ttl, now=None, refresh=False):
    """只接受 SECURE/ACCEPTED ✓ —— B 的候选（UNKNOWN/BOGUS）一律不入缓存 ✗。

    `refresh=True` —— **仅**由 §5 的后台刷新路径使用 ✓：允许"同一答案"重写一次，
    以便把寿命推回满 ✓（否则刷新永远不生效 ✗，见下方 `_adm_same_answer` 闸门说明 ✓）。
    """
    if not POLICY_MODE or not name or not wire:
        return
    if str(verdict) not in ("secure", "accepted"):
        try:
            _stats["adm_cache_reject_" + str(verdict)] = _stats.get("adm_cache_reject_" + str(verdict), 0) + 1
        except Exception:
            pass
        return
    now = float(now if now is not None else time.time())
    # 上限：SECURE 900s / ACCEPTED 300s（与 answer_policy 的 cap 一致 ✓）
    cap = 900.0 if str(verdict) == "secure" else 300.0
    ttl = max(0.0, min(float(ttl or 0.0), cap))
    if ttl <= 0:
        # Task 3（P1-2）：**零 TTL / 已过期绝不久化** ✗ —— 直接不入缓存 ✓
        # （旧代码 `ttl = 60.0` 会把零 TTL 答案延长 60s ✗，方案明确禁止 ✗）
        try:
            _stats["adm_cache_ttl_zero"] = _stats.get("adm_cache_ttl_zero", 0) + 1
        except Exception:
            pass
        return
    if len(_ADM_CACHE) >= _ADM_CACHE_MAX:
        _n = max(1, _ADM_CACHE_MAX // 10)
        for _k in sorted(_ADM_CACHE, key=lambda x: _ADM_CACHE[x].get("until", 0))[:_n]:
            _adm_drop(_k)
    _key = _adm_key(name, qtype)
    # ★ 方案 §2 第 50 行："**缓存命中不重新插入、不滑动续期、不更新证明时间**" ✓。
    # 为什么这里必须显式拦住 ✗→✓：命中的字节会再走一遍出口闸门
    # （`_policy_cn_answer` → `_finalize_return` → 分类 → 本函数）✗，
    # 若"同一答案又写一次"，`stored`/`stored_mono` 被刷新 ⇒ 之后每次命中算出的
    # "经过秒数"都从**这次**起算 ⇒ 等于**每次命中都续期** ✗（正是要修的病 ✗）。
    # 只拦"同一个答案" ✓：上游换了答案 ⇒ 判为不同 ⇒ 立刻采用新期限 ✓（不得僵化 ✗）。
    _old = _ADM_CACHE.get(_key)
    if _old is not None and _adm_same_answer(_old.get("wire"), wire) and not refresh:
        # ★ §5：`refresh=True` 是**唯一**的合法例外 ✓ —— 后台刷新的**全部意义**就是
        #   "答案没变、但寿命快到，重取一次把寿命推回满"✗；若被本闸门拦住，刷新器会
        #   "每轮都在跑、`adm_cache_reput_same` 一直涨、而缓存寿命一点没动"✗ = 最坏的
        #   失效形态（指标在动、体验没变 ✗）。刷新路径**另行**保证不降低新鲜度
        #   （`_hot_refresh_one()` 里比对 `until` 后才写 ✓）。
        try:
            _stats["adm_cache_reput_same"] = _stats.get("adm_cache_reput_same", 0) + 1
        except Exception:
            pass
        return
    _sz = 256 + len(wire or b"") + 8 * len(str(name))
    _old_sz = int((_old or {}).get("_sz") or 0)
    # §5 第 4 项：**16 MiB 预算**（与条数上限并列，任一先到即淘汰 ✓）。
    # 写法上刻意只淘汰"当前所需字节"这一个量级、**不用 while**：一次 put 只允许
    # 触发一轮有界淘汰 ⇒ 单次写的耗时是 O(账本大小) 且**可预测** ✓（生产路径上
    # `_ADM_CACHE` 已由 `_ADM_BYTES` 约束在 16 MiB 内 ✓，不会出现"必须丢一大片" ✗）。
    if _ADM_BYTES[0] + _sz - _old_sz > _ADM_BYTES_MAX:
        _st_bump("adm_bytes_high")
        _need = _ADM_BYTES[0] + _sz - _old_sz - _ADM_BYTES_MAX
        _freed = 0
        for _k in sorted(_ADM_CACHE, key=lambda x: _ADM_CACHE[x].get("until", 0)):
            if _freed >= _need:
                break
            if _k == _key:
                continue
            _e = _adm_drop(_k)
            if _e:
                _freed += int(_e.get("_sz") or 0)
                _st_bump("adm_cache_evicted_bytes")
    _ADM_CACHE[_key] = {
        # §5：记录本条记录的**近似字节占用** ⇒ 与条数上限并列的 16 MiB 预算可被精确执行 ✓
        # （方案第 99 行"两个限额任一先到即淘汰" ✗→✓）。
        "_sz": _sz,
        "wire": wire, "until": now + ttl, "verdict": str(verdict), "source": str(source),
        "ttl": ttl, "policy_version": str(globals().get("_POLICY_VERSION", "n/a")),
        "qtype": int(qtype or 1), "valid_until": now + ttl,
        # ★ 方案 §2 第 48 行：记录**插入的单调时间**与**原始各 RR TTL** ✓。
        # `stored` 供命中时计算"经过秒数"（配合 `alt_adapter.age_wire()`）✓；
        # `stored_mono` 是同一时点的 `time.monotonic()`：正常路径（`now=None`）用**单调差**
        # 算经过秒数 ⇒ 墙上时钟被 NTP 回拨/前跳都不会把"剩余寿命"算错 ✓；
        # `rr_ttls` 留档用于核对"是否跨层重新起算"（诊断用，不参与判断 ✓）。
        # `qclass`/`do`/`cd`/`ecs`/`view` = 视图维度 ✓（命中时比对，见 `_adm_cache_get()`）：
        # 无法证明同一视图时**不共用缓存** ✗。
        "stored": now, "stored_mono": time.monotonic(), "rr_ttls": _adm_rr_ttls(wire),
        "qclass": 1, "do": True, "cd": False, "ecs": _cur_ecs_key(), "view": "default",
        # ★ 方案 §2 第 48 行："**绝对证据失效时间**" ✓ —— 它回答的是另一个问题 ✗→✓：
        # `until`/`valid_until` = "我方允许多久复用" ✓（含策略上限，SECURE≤900 / ACCEPTED≤300）；
        # `evidence_until` = "**证据本身**到什么时候失效" ✓（签名失效时刻 / RRset 原始到期），
        # 由 `rrset_validity()` 给出、**不含**任何策略上限 ✓ —— 并再与 `ttl` 取 min 保守收口 ✓。
        # 两者都要可被审计：否则"证据早已过期、只是策略上限还允许复用"这种错误会被
        # `until` 掩盖住 ✗（方案第 55 行"签名到期不返回"查的正是这一项 ✓）。
        "schema": _ADM_SCHEMA,
        # ★ 第三份审计 F2：写入时的**名单代次**（typed|veto|例外的内容指纹）——
        #   命中时比对；名单变了 ⇒ 旧分类下写入的缓存自然不再复用 ✓。
        "cn_gen": _cn_gen_id(),
        "evidence_until": _adm_evidence_until(wire, now, ttl),
        "evidence_kind": _adm_evidence_kind(wire)}
    _ADM_BYTES[0] += _sz - _old_sz
    try:
        _stats["adm_cache_bytes"] = int(_ADM_BYTES[0])
    except Exception:
        pass
    try:
        _stats["adm_cache_put"] = _stats.get("adm_cache_put", 0) + 1
    except Exception:
        pass
    # P2 挂接点①：拿到可采纳答案 ⇒ 该名字不再是死链 ✓（幂等，只清状态）
    try:
        _sf_clear(name, qtype, "adm_put")
    except Exception:
        pass


# ===== 方案 §2-a：**由可信报文取真实有效期**（取代硬编码 `ttl=300.0`）=====
# 现场问题：全链路 5 处调用都写死 `ttl=300.0` ✗，于是
#   · `valid_until` 与报文里的 RRset TTL / RRSIG 失效时间**无关** ✗；
#   · 短 TTL（例如 30s 的 CDN 名）被当成 300s 复用 ⇒ 超出运营方授权时长 ✗；
#   · 长 TTL 的稳定名每 5 分钟就被迫重查 ⇒ 白付延迟 ✗。
# 方案 §2 要求："缓存有效期取 **min(RRset 剩余 TTL, 签名有效期, 策略上限)**，不固定缓存一小时" ✓，
# 并且"对使用的 DNSSEC 证明检查签名失效时间" ✓ ⇒ 有效期必须来自**该条报文自己** ✓。
def _adm_cap_for(verdict, default=300.0):
    """策略上限（方案 §2）：SECURE ≤ 900s / ACCEPTED ≤ 300s —— 与 `answer_policy` 常量同源 ✓。

    现场问题：调用点统一传 `cap=300.0` ✗ ⇒ 即使 `answer_policy.ACCEPT_MAX_TTL=900` ✓，
    SECURE 答案也被截到 300s ✗（策略自相矛盾）。

    注意：`verdict` 可能是 `Verdict` 枚举、也可能是 **`str`** ——
    现场事实：`_adm_cache_put()` 的调用点传的是 `a_ans.verdict.value`（str）✗。两种都要认 ✓。
    """
    try:
        from answer_policy import ACCEPT_MAX_TTL, ACCEPTED_MAX_TTL
    except Exception:
        ACCEPT_MAX_TTL, ACCEPTED_MAX_TTL = 900.0, 300.0
    v = getattr(verdict, "value", verdict)      # 枚举 → 字符串 ✓
    return ACCEPT_MAX_TTL if str(v) == "secure" else (ACCEPTED_MAX_TTL if str(v) == "accepted"
                                                     else float(default))


def _alt_gate():
    """§4 第 3 项：**UNKNOWN / NOT_READY 时业务不进入长时间 alt 尝试** ✓。

    在**消耗 `_src_once("alt")` 槽位之前**调用 ⇒ not-ready 不会把这一请求的
    "唯一一次 alt" 名额浪费掉 ✗（否则 readiness 恢复后同一请求仍会用不上 ✓）。

    返回 True ⇒ 允许进入 alt（已记 `alt_ready`）；False ⇒ **不发起发包**，只记
    `alt_not_ready` 并把恢复交给 timer 驱动的后台 readiness 探测 ✓。
    """
    try:
        import alt_adapter as _A
    except Exception:
        return False
    try:
        ok = bool(_A.alt_ready())
    except Exception:
        ok = False
    try:
        if ok:
            _stats["alt_ready"] = _stats.get("alt_ready", 0) + 1
            _tr_flag("alt_ready")
        else:
            _stats["alt_not_ready"] = _stats.get("alt_not_ready", 0) + 1
            _stats["alt_unavailable_skip"] = _stats.get("alt_unavailable_skip", 0) + 1
            _tr_flag("alt_not_ready")
            # 原因分桶 ⇒ 现场能一眼看出"未就绪"到底是没文件、过期、还是身份变了 ✓
            _why = "other"
            try:
                _r = str(_A.alt_ready_reason() or "")
                if _r.startswith("state_unreadable") or _r.startswith("state_not_object") \
                        or _r.startswith("uninit"):
                    _why = "missing"
                elif _r.startswith("state_stale"):
                    _why = "stale"
                elif "boot_id_changed" in _r or "identity_missing" in _r:
                    _why = "identity_changed"
                elif "config_hash_changed" in _r:
                    _why = "config_changed"
            except Exception:
                _why = "other"
            _stats["alt_ready_" + _why] = _stats.get("alt_ready_" + _why, 0) + 1
            try:
                _tr_note("alt", 0.0, "not_ready:" + str(_A.alt_ready_reason()))
            except Exception:
                pass
        # alt 侧断路器的**绝对量镜像**（alt_adapter 与本进程同进程 ⇒ 直接读快照 ✓）。
        # ★ 只读快照、**绝不调 `breaker_state()`** ✓ —— 后者会把"半开名额"消费掉，
        #   导致随后 `query_alt()` 只看到 `half_open_busy` ⇒ 试探永不发出、断路器
        #   永不恢复 ✗（半开名额只能由真正发包的 `query_alt()` 消耗 ✓）。
        try:
            _sn = _A.breaker_snapshot()
            _stats["alt_breaker_trips"] = int(_sn.get("trips") or 0)
            _stats["alt_transport_ok"] = int(_sn.get("transport_ok") or 0)
            _stats["alt_transport_fail"] = int(_sn.get("transport_fail") or 0)
            _stats["alt_half_open_ok"] = int(_sn.get("half_ok") or 0)
            _stats["alt_half_open_fail"] = int(_sn.get("half_fail") or 0)
        except Exception:
            pass
    except Exception:
        pass
    return ok


def _is_conclusive(wire):
    """该**上游字节**是否足以当作一条结论 ✓（正向 / CNAME 链 / 带证据的否定）。

    ★ 2026-10-11（§5 验收期现场定位的既有缺陷，非 §5 引入）：
      `_dot_query_once()` 的竞速覆盖判据原为 `good = rc not in (2, 5)` —— 只要有非
      SERVFAIL/REFUSED 的 rcode 就算"更好的答案"。实测 `127.0.0.1:5533`（aghdq→NextDNS
      的 UDP 转发器）在**并发**下偶发把查询**原样回显**成 `flags 0x0100→0x8180` 的
      `rc=0 an=0 ns=0 ar=1`（qid 不变，唯一差别是 flags）✗ ⇒ 它会被当成 better，
      覆盖先到的 rc=2，并**写进 `_cache` 10–600s** ✗ ⇒ 客户端持续被答复"该域名没有 A 记录"，
      而真相是 **DNSSEC bogus（SERVFAIL）** ✗ —— 这是**安全结论被降级**。
      实测复现率：12 线程压 5533 ⇒ **0.21%~3.1%**；qid 不符的陈旧帧也曾出现 ✗。
    修法：只有**可结论**的字节才配赢过别人、才配进缓存 ✓；零证据空壳（`classify_kind()`
      返回 `"bare"`：`an=0` 且 `ns=0` 且 `ad=0`）与解析失败一律不算 ✓。
      不误伤 P34-BM：实测所有真 NODATA 都带 SOA（`ns≥1`，权威段 type 6）或 AD=1 ✓。
    """
    if not wire:
        return False
    try:
        import alt_adapter as _A
    except Exception:
        return False
    try:
        return bool(_A.is_conclusive(wire))
    except Exception:
        return False


def _alt_classify(wire, source, now=None):
    """**统一分类入口** ✓：有效期取自报文本身 ⇒ 不再硬编码 `ttl=300.0` ✓。

    `ttl<=0`（零 TTL / 已过期 / 无法解析）⇒ 交 `answer_policy.make_answer` 得
    `valid_until = now + 0` ⇒ `is_fresh()` 立即判 False ⇒ 上层拒绝该答案并回退 ✓，
    **绝不补一个固定值延长它** ✗（与 P1-2 同一条铁律）。
    """
    if not wire:
        return None
    try:
        import alt_adapter as _A
    except Exception:
        return None
    ttl, det = 0.0, {}
    try:
        ttl, det = _A.rrset_validity(wire, now=now)
    except Exception:
        ttl, det = 0.0, {"kind": "exc", "ttl": 0.0, "proven": False}
    try:
        _k = "ttl_zero_" + str(source).replace("local-", "")
        if ttl and ttl > 0:
            _stats["ttl_src_wire"] = _stats.get("ttl_src_wire", 0) + 1
        else:
            _stats[_k] = _stats.get(_k, 0) + 1
    except Exception:
        pass
    try:
        _tr_note("ttl", 0.0, str(det.get("kind") or "?"))     # Step-1 §1：有效期来源可见
    except Exception:
        pass
    _ag_before = None
    try:
        _ag_before = dict(_A.AD_GRADE)
    except Exception:
        pass
    try:
        _ans = _A.classify_response(wire, source, ttl=float(ttl), now=now)
    except Exception:
        return None
    # N3 精细分档（2026-10-16）：把 `ad_grade()` 的四档计数同步进 guard 的 stats ✓
    # （动态键、跨重启累计 —— 它们是健康指标，不属"名单代次"类归零口径 ✓）。
    if _ag_before is not None:
        try:
            for _ag_k, _ag_v in _A.AD_GRADE.items():
                _ag_d = int(_ag_v) - int(_ag_before.get(_ag_k, 0))
                if _ag_d:
                    _ag_key = "ad_grade_" + _ag_k
                    _stats[_ag_key] = _stats.get(_ag_key, 0) + _ag_d
        except Exception:
            pass
    return _ans


def _retry_authenticated(name, qtype):
    """瞬时无可准入答案时，对**认证源**做一次快速重试 ✓ —— **绝不放宽到 B** ✗。

    背景（P34-BL 诊断 ✓）：生产启用新准入后出现的少量 SERVFAIL 属**冷路径瞬时**现象
    （那一刻见证与备用都没给出可准入答案 ✓，随后同名查询即成功 ✓ = 自愈 ✓）。
    这里只做一次"更耐心的重试"，重试对象**仅限认证源** ✓：
      ① 认证备用（alt，两家境外 DoT ✓）；② 见证（aghdq→NextDNS ✓）。
    """
    try:
        import alt_adapter as _ALT
    except Exception:
        return None
    # ★ 方案 §3 第 70 行：**同一请求每个来源最多启动一次** ✓ ——
    #   本函数是"最后一道认证重试"✗，历史上 `_policy_cn_answer()` 与 `_finalize_return()`
    #   都会走到这里 ⇒ 同一次请求可能付**两轮** alt + 见证 ✗（各写死 1.2s ⇒ 尾部叠加 ✗）。
    #   现在：alt / witness 各自只允许一次 ✓，第二次直接复用/放弃并记账 ✓。
    # ★ 方案 §3 第 70 行（后半句）：**alt 已调用过之后，不得再给它完整的 1.2 秒** ✗ ——
    #   剩余预算才是唯一上限 ✓（`GUARD_QUERY_DEADLINE` 保持 4.0 不动 ✓，方案第 68 行 ✓）。
    if not _alt_gate():
        # §4 第 3 项：未就绪 ⇒ 不发包（不占"唯一一次 alt"名额 ✓）
        pass
    elif not _src_once("alt"):
        _stats["fin_retry_alt_dup"] = _stats.get("fin_retry_alt_dup", 0) + 1
    else:
        try:
            _t_r1 = time.monotonic()
            _b1 = _dl_rem(1.2)
            if _b1 is None:
                _b1 = 1.2
            if _b1 > 0.05:
                _a2 = _ALT.query_alt(name, qtype, timeout=_b1)
            else:
                _a2 = None                     # 预算已尽 ⇒ **立即结束** ✓（不再送 1.2s ✗）
            _tr_note("retry_alt", (time.monotonic() - _t_r1) * 1000.0,
                     "ok" if (_a2 is not None and _a2.verdict.value in ("secure", "accepted")) else "fail")
            if _a2 is not None and _a2.verdict.value in ("secure", "accepted"):
                _tr_flag("retry_alt")
                _src_mark("alt", "ok")
                _stats["fin_retry_alt_ok"] = _stats.get("fin_retry_alt_ok", 0) + 1
                return _a2
            if _a2 is not None and _a2.verdict.value == "bogus":
                _drop_caches_for(name, why="bogus")
                return _a2
            _src_mark("alt", "fail")
        except Exception:
            pass
    if not _src_once("witness"):
        _stats["fin_retry_witness_dup"] = _stats.get("fin_retry_witness_dup", 0) + 1
        _stats["fin_retry_fail"] = _stats.get("fin_retry_fail", 0) + 1
        _tr_flag("retry_fail")
        return None
    try:
        _wa = _witness_addr.split(":")
        _waddr = (_wa[0], int(_wa[1]) if len(_wa) > 1 else 53)
    except Exception:
        _waddr = tuple(UNBOUND)
    try:
        _t_r2 = time.monotonic()
        _b2 = _dl_rem(1.2)
        if _b2 is None:
            _b2 = 1.2
        _rawretry = udp_query(_waddr, mk_query_do(name, qtype), timeout=_b2) if _b2 > 0.05 else None
        _tr_note("retry_witness", (time.monotonic() - _t_r2) * 1000.0,
                 "ok" if _rawretry else "fail")
        if _rawretry:
            # §2-a 修正：这里以前写 `("local-a", ttl=300.0)` ✗ —— 但 `_rawretry` 取自
            # `_witness_addr`（aghdq→NextDNS 的见证通道）✗，把它标成 `local-a` 会让
            # **证据来源与事实不符** ✗（方案 §2 要求"记录证据来源"，来源错=审计失真 ✗）。
            _a3 = _alt_classify(_rawretry, "witness")
            if _a3 is not None and _a3.verdict.value in ("secure", "accepted"):
                _tr_flag("retry_witness")
                _src_mark("witness", "ok")
                _stats["fin_retry_witness_ok"] = _stats.get("fin_retry_witness_ok", 0) + 1
                return _a3
        _src_mark("witness", "fail")
    except Exception:
        pass
    _stats["fin_retry_fail"] = _stats.get("fin_retry_fail", 0) + 1
    _tr_flag("retry_fail")
    return None


def _stale_of(wire):
    """§3.2 统一 stale 识别：委托 `alt_adapter.stale_flags()`（EDE 3/19 ⇒ 显式过期答案）。

    任何异常 ⇒ `(False, 0, -1)`：**宁可当作新鲜也不 fail-closed** ✓ ——
    审计报告明确要求"TTL=0 本身不等于伪造，不应笼统拒绝全部零 TTL 正常答案" ✗。
    """
    try:
        import alt_adapter as _A
        return _A.stale_flags(wire)
    except Exception:
        return (False, 0, -1)


def _stale_note(kind, name, ede, min_ttl):
    """§3.2 统一记账：**所有出口路径共用**（含终局结论快路）⇒ 出口 stale 语义一致 ✓。

    kind 为 `None` 表示终局结论（CNV 否决 / POL-SF / 畸形查询边角）。
    """
    _lbl = "terminal" if kind is None else str(kind)
    try:
        with _lock:
            _stats["stale_out"] = _stats.get("stale_out", 0) + 1
            _k = "stale_out_" + _lbl
            _stats[_k] = _stats.get(_k, 0) + 1
    except Exception:
        pass
    log("FIN  %-38s 出口 stale（来源=%s, EDE=%d, min_ttl=%s）⇒ 不写准入缓存、不延长 TTL ✓"
        % ((name or "?")[:38], _lbl, ede, min_ttl))


def _finalize_return(wire, kind, name, qtype, qid, msg):
    """方案任务2 的**出口闸门** ✓：把某条出口的答案送进 `finalize_answer()` 统一裁决。

    `kind` = 该字节的**来源类别** ✓（Task 3 P1-1 起由 `_LABEL_MAP` / `_src_kind()` 集中折算 ✓）：
      local-a        —— 认证源 A（含 domestic() 里 src == "A" 的应答）
      local-alt      —— `_policy_cn_answer()` 采纳的认证备用答案（含 domestic() 的 src == "POL"）
      local-b        —— **B 的候选（只当见证 ✓，永不单独放行 ✗）**
      clean-channel  —— 境外认证 DoT / dnscrypt 的辅助取答案
      negative-cache —— 我方验证器的负缓存（安全结论 ✓）
      strict         —— 严格清单共识结果
      **None**       —— **终局结论**（CNV 否决 / POL-SF / 畸形查询边角）：已经是本地 fail-closed
                        的结论 ⇒ **不过闸** ✓（过闸会被 alt 或准入缓存"修复"✗），只重写 qid ✓。
    `POLICY_MODE=off` 时**原样返回** ✓ ⇒ 行为与今天完全一致 ✓。

    两条不变式（Task 3）✓：
      · **绝不 fail-open** ✗（P2-1）—— 准入模块不可用 / 无法分类 ⇒ SERVFAIL ✓
        （与 `_policy_cn_answer()` 的导入失败分支对齐 ✓），并记账 `fail_closed` +
        `_fc_classify("source_inadmissible")` ✓；
      · **可采纳来源的字节绝不被改写** ✓（P1-2）—— `classify_response()` 判 SECURE/ACCEPTED 时
        只重写 qid 后原样返回 ✓；准入缓存放在**分类之后** ✓ ⇒ 已验证答案不会被缓存内容顶替 ✗。

    §3.2 stale 出口语义（2026-10-15 统一，修正审计"本注释不成立"）✓：
      · 本函数是**唯一出口闸门** ⇒ freshness/stale 判定也在此**统一**（含 `kind is None` 的终局
        快路，该快路历史上完全跳过判定 ✗）；
      · 显式 stale（EDE 3/19，见 `alt_adapter.stale_flags()`）⇒ **允许出口但不入准入缓存、不延长
        TTL、不改字节** ✓，并记 `stale_out` / `stale_out_<kind>`；走 `_stale_of()` / `_stale_note()`；
      · 隐式零 TTL（无 EDE）⇒ 按普通答案处理，**绝不因 TTL==0 笼统拒答** ✗（审计明确要求），
        其不可复用性由 F1 的 `ttl<=0 不入缓存` 保证 ✓；
      · 因此"所有出口严格 freshness 校验"这一说法对**可复用性**成立 ✓、对**可出口性**不成立
        —— 这是数据面（serve-expired 的下游仍需拿到答案）与安全面（不得伪装新鲜）的明确边界 ✓。
    """
    if not POLICY_MODE or not wire:
        return wire
    try:
        _ft = getattr(_TR, "t", None)
        if _ft and _ft.get("id") is not None:
            _ft["src"] = kind if kind is not None else "none"
    except Exception:
        pass
    if kind is None:
        # P1-1：终局结论（CNV / POL-SF / 畸形查询）—— **不过准入闸门** ✓，也不吃缓存 ✗
        # 注意：`_tr()` 返回 **dict** ⇒ 必须下标赋值 ✓（属性赋值会抛 AttributeError 并被裸
        # except 吞掉，分桶里就永远看不到这个来源 ✗）。
        try:
            _tr()["src"] = "none"     # Step-1 §1：终局结论单独归类 ✓
        except Exception:
            pass
        # §3.2：终局快路同样做 stale 识别与记账 ⇒ 出口 stale 语义**处处一致** ✓
        # （历史缺陷：本快路曾完全跳过 freshness 判定，审计 §3.2 记此不一致 ✗）
        _ist, _ede, _mttl = _stale_of(wire)
        if _ist:
            _stale_note(None, name, _ede, _mttl)
        # P2 挂接点③：终局快路同样产出可出口字节 ⇒ 清退避 ✓
        try:
            _sf_clear(name, qtype, "terminal_exit")
        except Exception:
            pass
        return rewrite_id(wire, qid)
    try:
        _tr()["src"] = kind           # Step-1 §1：**最终来源**（local-a/local-alt/local-b/…）
    except Exception:
        pass
    # P2-1：闸门自身**绝不 fail-open** ✗
    try:
        from answer_policy import finalize_answer
        import alt_adapter as _ALT
    except Exception as _e_fin:
        with _lock:
            _stats["fin_import_fail"] = _stats.get("fin_import_fail", 0) + 1
            _stats["fail_closed"] += 1
            try:
                _fc_classify("source_inadmissible")
            except Exception:
                pass
        log("FIN  %-38s 准入模块不可用(%s) ⇒ SERVFAIL(fail-closed)"
            % ((name or "?")[:38], str(_e_fin)[:50]))
        return mk_servfail(msg, qid)
    try:
        _src = "local-b" if str(kind) == "local-b" else str(kind)
        a_ans = _alt_classify(wire, _src)
    except Exception:
        a_ans = None
    if a_ans is None:
        with _lock:
            _k = "fin_classify_fail_" + str(kind)
            _stats[_k] = _stats.get(_k, 0) + 1
            _stats["fail_closed"] += 1
            try:
                _fc_classify("source_inadmissible")
            except Exception:
                pass
        log("FIN  %-38s 来源 %s 无法分类 ⇒ SERVFAIL(fail-closed)" % ((name or "?")[:38], kind))
        return mk_servfail(msg, qid)
    if a_ans.verdict.value in ("secure", "accepted"):
        # §3.2：**快路也要做 freshness 判定** ✓（审计指出本分支曾不调 is_fresh()）。
        # 显式 stale（EDE 3/19）⇒ 允许出口（可能是唯一可用答案 ✓），但**不写准入缓存** ✗、
        # **不延长 TTL** ✗、字节除 qid 外一字不动 ✓ —— 即"可出口、不可复用、不伪装成新鲜"。
        _ist, _ede, _mttl = _stale_of(wire)
        if _ist:
            _stale_note(kind, name, _ede, _mttl)
            # P2 挂接点②：**拿到了成功答案**（stale 但仍可出口）⇒ 该名字不是死链 ✓
            #   本快路为"可出口、不可复用"而不写准入缓存 ⇒ 必须在此单独清退避 ✓
            try:
                _sf_clear(name, qtype, "stale_exit")
            except Exception:
                pass
            return rewrite_id(wire, qid)
        with _lock:
            _k = "fin_ok_" + str(kind)
            _stats[_k] = _stats.get(_k, 0) + 1
        # P1-2 + §2-a：TTL **取自答案** ✓（`valid_until` 剩余值；上限按裁定分档
        # SECURE≤900s / ACCEPTED≤300s ✓；<=0 不入缓存 ✓ —— 零 TTL 绝不被延长 ✗）
        _adm_cache_put(name, qtype, rewrite_id(wire, qid), a_ans.verdict.value, kind,
                       _adm_ttl_from(a_ans, _adm_cap_for(a_ans.verdict)))
        # 只重写 qid、**不动其余字节** ✓（`domestic()` 的 POL 字节自带随机 qid ✗ ⇒ 必须重写 ✓）
        return rewrite_id(wire, qid)
    if a_ans.verdict.value == "bogus":
        # 方案 `answer_policy` 逐字规定：**BOGUS 不可被任何备用或缓存"修复"** ⇒ 直接失败 ✓
        # 因此本检查放在**准入缓存之前** ✓ —— 缓存与认证源重试都不得掩盖本地验证失败 ✗。
        _drop_caches_for(name, why="bogus")
        with _lock:
            _k = "fin_bogus_" + str(kind)
            _stats[_k] = _stats.get(_k, 0) + 1
            _stats["fail_closed"] += 1
            try:
                _fc_classify("source_bogus")
            except Exception:
                pass
        # ★ C（2026-10-22）：BOGUS 是**确定性**结论（签名验证失败），同样值得负缓存 ✓
        #   注意：这里只缓存"拒绝结论"，不缓存任何报文 ⇒ 安全性不变。
        if _SF_BACKOFF_ON:
            try:
                _sf_put(name, qtype)
                with _lock:
                    _stats["sf_put_bogus"] = _stats.get("sf_put_bogus", 0) + 1
            except Exception:
                pass
        log("FIN  %-38s 来源 %s 为 BOGUS（验证失败）⇒ SERVFAIL（不可被 alt/缓存修复 ✓）"
            % ((name or "?")[:38], kind))
        return mk_servfail(msg, qid)
    # P34-AY：来源不可采纳时才去问 alt ✓（顺序修正：可采纳就绝不付备用的延迟 ✗）
    # P34-AX：不可采纳的来源**先吃准入缓存** ✓（避免重复付 alt 的延迟 ✗；
    #   放在分类之后 ⇒ 缓存永不顶替已验证答案 ✓）
    _hit = _adm_cache_get(name, qtype)
    if _hit:
        with _lock:
            _k = "fin_cache_" + str(kind)
            _stats[_k] = _stats.get(_k, 0) + 1
        return rewrite_id(_hit, qid)
    # ★ 快速透传（GUARD_FASTPASS，默认关）：local-a 被判 transport（无 DNSSEC EDE 的裸
    #   SERVFAIL）时，先问一次快速独立源；它**也**明确回 rc=2 ⇒ 两家独立运营方都拒绝
    #   ⇒ 直接透传 SERVFAIL，不再空等 alt 的 2.0s ✓。
    #   其它结果（含超时）⇒ 落到下面的原逻辑，行为与不算本分支时完全一致 ✓。
    if FASTPASS and str(kind) == "local-a" and a_ans.verdict.value == "transport":
        _fp_hit = _fastpass_servfail(name, qtype)
        # ★ 2026-10-22 修复（P2 缺陷）：此处**不**清退避 ✗
        #   原实现（挂接点④）在 `_fp_hit` 为 False 时调 `_sf_clear("fastpass_denied")`，
        #   理由是"快速源没确认死链 ⇒ 死链假设不成立"。**这个推理是错的** ✗✗：
        #   `_fastpass_servfail()` 返回 False 有三种互不相同的情形 ——
        #     ① 快速源给出非 SERVFAIL（确实不该判死链）；
        #     ② **超时 / 无应答**（fastpass_timeout=7 —— 只是没查成，不是没死链）；
        #     ③ 瞬时抖动（fastpass_other=117 的主因）。
        #   把 ②③ 当成"已恢复"⇒ 每次抖动都清零 ⇒ streak 永远停在 1（15s）
        #   ⇒ 退避从未递进到 300s ⇒ 死链域名 106 次查询里 74% 仍是 COLD（实测）。
        #   正确语义：**只有产出真实答案才代表恢复**，那三条路径
        #   （_adm_cache_put / stale_exit / terminal_exit）已经各自挂了 _sf_clear ✓，
        #   本处无需也不应再清 ✗。
        if _fp_hit:
            with _lock:
                _stats["fin_fastpass_servfail"] = _stats.get("fin_fastpass_servfail", 0) + 1
                _stats["fail_closed"] += 1
                try:
                    _fc_classify("fastpass_upstream_servfail")
                except Exception:
                    pass
            log("FIN  %-38s local-a 与快速源均明确 SERVFAIL ⇒ 快速透传（跳过 alt）✓"
                % ((name or "?")[:38]))
            _sf_put(name, qtype)      # A3：双源均明确拒绝 ⇒ 15s 内同问直接回 SERVFAIL ✓
            return mk_servfail(msg, qid)
    # 不是可采纳结论 ⇒ 只能用认证备用；否则 SERVFAIL ✓（绝不把 B 的候选放出去 ✗）
    # ★ §3 第 70 行：alt **每请求最多启动一次** ✓ —— `_policy_cn_answer()` 已经可能问过
    #   alt（CN 路径）✗ ⇒ 这里再问一次就是重复付延迟 ✗。超时改成**吃剩余预算** ✓
    #   （原 `max(0.2, ...)` 会强制至少等 0.2s ✗，即使预算已尽 ⇒ 尾部被叠加 ✗）。
    _alt_ans = None
    if not _alt_gate():
        # §4 第 3 项：未就绪 ⇒ 不发包（不占"唯一一次 alt"名额 ✓）
        pass
    elif not _src_once("alt"):
        _stats["fin_alt_dup_skipped"] = _stats.get("fin_alt_dup_skipped", 0) + 1
    else:
        try:
            _b_alt = _dl_rem(3.0)
            if _b_alt is None:
                _b_alt = 3.0
            # P0（2026-10-22）：再与独立硬上限取小 ⇒ 死链域名不再白等满 3s ✓
            #   只收紧、不放松：硬上限**只可能让等待变短**，不可能变长 ✓
            if ALT_HARD_CAP > 0:
                _b_alt = min(_b_alt, ALT_HARD_CAP)
                with _lock:
                    _stats["alt_capped"] = _stats.get("alt_capped", 0) + 1
            _alt_ans = _ALT.query_alt(name, qtype, timeout=_b_alt) if _b_alt > 0.05 else None
            _src_mark("alt", "ok" if _alt_ans is not None else "fail")
        except Exception:
            _alt_ans = None
    if _alt_ans is not None and _alt_ans.verdict.value == "bogus":
        _drop_caches_for(name, why="bogus")
        return mk_servfail(msg, qid)
    picked = finalize_answer(a_ans, _alt_ans)
    if picked is not None and picked.wire:
        with _lock:
            _k = "fin_rescue_" + str(kind)
            _stats[_k] = _stats.get(_k, 0) + 1
        log("FIN  %-38s 来源 %s 不可采纳 ⇒ 改用 %s（%s）" % (name[:38], kind,
                                                            picked.source, picked.verdict.value))
        _adm_cache_put(name, qtype, rewrite_id(picked.wire, qid), picked.verdict.value,
                       picked.source, _adm_ttl_from(picked, _adm_cap_for(picked.verdict)))
        return rewrite_id(picked.wire, qid)
    # P34-BM：SERVFAIL 之前，对**认证源**做一次快速重试 ✓（救命，且不放宽安全 ✓）
    # A local validator's generic failure may be rescued only by another local
    # validator. Never reinterpret an unannotated validation failure via witness.
    _rr = None if (a_ans.verdict.value == "transport" and
                   str(kind) in ("local-a", "local-alt", "local-cn")) else _retry_authenticated(name, qtype)
    if _rr is not None and _rr.wire:
        _adm_cache_put(name, qtype, rewrite_id(_rr.wire, qid), _rr.verdict.value, _rr.source,
                       _adm_ttl_from(_rr, _adm_cap_for(_rr.verdict)))
        log("FIN  %-38s 来源 %s 不可采纳 ⇒ 认证源重试成功（%s）✓" % (name[:38], kind, _rr.source))
        return rewrite_id(_rr.wire, qid)
    with _lock:
        _k = "fin_null_" + str(kind)
        _stats[_k] = _stats.get(_k, 0) + 1
        _stats["fail_closed"] += 1
        try:
            # P34-BM：标签改为**准确**名称 —— 这里表示"来源不可采纳"✓，**不是**"已确认投毒" ✗
            # （旧名 known_poison 是既有路径的标签，复用会误导审计 ✓ —— 详见 P34-BL 诊断）
            _fc_classify("source_inadmissible")
        except Exception:
            pass
    log("FIN  %-38s 来源 %s 不可采纳且认证源重试仍无答案 ⇒ SERVFAIL" % (name[:38], kind))
    # ★ C（2026-10-22）：**所有来源都不可采纳** ⇒ 这是最典型的死链证据 ⇒ 必须进负缓存 ✓
    #   静态审计：此前 `_sf_put` 只在 FASTPASS 分支（L1326）调用，而该分支要求
    #     `kind=="local-a" && verdict=="transport"`；实测该域名 57 条 FIN 里只有 27 条
    #     （47%）满足 ⇒ 另外 53% 的失败**从不建立负缓存** ⇒ 命中率被结构性压到 17% ✗。
    #   本出口覆盖剩余全部「走到 finalizer 但拿不到任何可采纳答案」的情形 ✓。
    #   安全边界不变：仍只写 expiry+计数、不写报文；且 require 单独开关以免改默认行为。
    if _SF_BACKOFF_ON:
        try:
            _sf_put(name, qtype)
            with _lock:
                _stats["sf_put_inadmissible"] = _stats.get("sf_put_inadmissible", 0) + 1
        except Exception:
            pass
    return mk_servfail(msg, qid)




import json, os, random, socket, ssl, struct, subprocess, sys, tempfile, threading, time, traceback
from concurrent.futures import ThreadPoolExecutor


def _flag(name, default=False):
    """布尔型环境变量的**正确**解析。

    2026-10-07 修：原写法一律用 `os.environ.get(name, "") != ""`，于是 `GUARD_XXX=0`
    会被判成 **True** —— 我按方案 B 写了 `GUARD_CORROB_STRICT_FAIL_CLOSED=0`，
    结果严格模式照旧生效（日志里仍有 strict R8 的 SERVFAIL），白改一轮。
    现在 ""/0/false/no/off 一律为假。
    """
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() not in ("", "0", "false", "no", "off")


# ===== 2026-10-10 Step-1（daily-latency-plan §1）：**业务基线仪表** =====
# 方案 §1 的三条硬要求：
#   ① 记录 客户端/入口/qtype/CN与否/cache状态/排队时长/A·alt·B 各耗时/见证就绪/retry/
#      hedge started·won/最终来源/rcode/总耗时；
#   ② guard 与 verifier 用**同一请求追踪 ID**，主进程与 verifier 分开统计；
#   ③ 业务与 5356 探针分开；按 PID/release/窗口**增量**统计。
# 设计约束（方案「只添加有界计数和分桶，避免逐查询同步落盘」+ 现场内存 1870MB）：
#   · 只用**每线程** state（`_TR = threading.local()`），无锁、无全局队列 ⇒ 零拥塞风险 ✓；
#   · 分桶是**定长 list**（COUNT_KEYS × NBUCKET 页 + 长尾页），永不增长 ⇒ 内存恒有界 ✓；
#   · 详细样本（每请求一行）**默认关闭**（`GUARD_BASE_SAMPLE=0`），开启时也只写**有界**
#     （`_bs_put` 环形缓冲 4096 行，超出丢最旧）⇒ 绝不逐查询无界落盘 ✓；
#   · 全部字段进 `_stats` 字面量 ⇒ 自动被 `stats_writer()` 写进 stats.json、被 chainmon 读 ✓。
# 开关：`GUARD_BASE_INSTR`（默认 **on**，纯计数/内存，无 I/O、无网络、无行为变化）
#       `GUARD_BASE_SAMPLE`（默认 **0**；仅在与基线采集脚本配合时开 1）
_BASE_INSTR = _flag("GUARD_BASE_INSTR", True)
_BASE_SAMPLE = _flag("GUARD_BASE_SAMPLE", False)
# 注意：本段定义在 `STATE_DIR` **之前**（`_flag()` 紧跟其后就是它）⇒ 这里**不能**直接
# 引用 STATE_DIR ✗（会 NameError，test_guard_finalizer 直接 import guard 就会炸）。
# 因此默认路径改为惰性求值 `_sample_path()` ✓。
SAMPLE_PATH = os.environ.get("GUARD_BASE_SAMPLE_PATH")
SAMPLE_MAX_ROWS = int(os.environ.get("GUARD_BASE_SAMPLE_MAX", "4096"))
_TR = threading.local()


def _sample_path():
    return SAMPLE_PATH or os.path.join(STATE_DIR, "base_samples.jsonl")


def _tr():
    """取/建**本次请求**的追踪上下文（每线程一份，无锁）。"""
    t = getattr(_TR, "t", None)
    if t is None:
        t = {"id": None, "t0": None, "mono0": None, "src": None, "qtype": None,
             "name": None, "cn": None, "entry": None, "wait_ms": None,
             "src_cls": None, "done": False, "attempts": [], "flags": [],
             # ★ 方案 §3 第 67 行：`sources_attempted` —— 本次请求**每个来源启动了几次** ✓。
             # 与 `attempts`（最多 12 条、可能截断）不同，本表**不截断**、只记次数与状态 ✓
             # ⇒ "同一来源是否被重复启动"在指标上**可判定** ✗→✓（方案第 70 行硬要求）。
             "src_tries": {}, "dl_mono": None}
        _TR.t = t
    return t


_QRID = [0]
_QRID_LOCK = threading.Lock()


# ★ 方案 §3 第 70 行：**同一请求每个来源最多启动一次**。
#   来源键必须**足够细**（含 qtype ✗ 否则 A/AAAA 会互相顶掉 ✗），且必须**每请求复位** ✓。
_SRC_ONCE = ("a", "b", "alt", "witness", "corrob", "strict")


def _src_once(key):
    """登记一次来源启动；返回 True（首次 ⇒ 允许启动）/ False（已启动过 ⇒ 必须复用 ✓）。

    ★ 这是 §3「不重复取数」的**唯一闸门** ✓ —— 方案第 70 行明确要求"已有 Future 就等待/复用；
    alt 已调用后最终出口**不得重新给它 1.2 秒**" ✗。所有来源启动点（A/B/alt/见证/核对/严格清单）
    都经本函数 ✗ ⇒ 重复启动**结构上不可能** ✓，且每次拒绝都记账 `src_reuse_<key>` ✓
    （让"复用生效了多少次"在指标上可见 ✓，而不是靠读代码相信 ✓）。

    ★ **绝不能**被 `_BASE_INSTR` 门控 ✗ —— 这是**行为闸门**（改变外部流量 ✗），
      不是仪表 ✗。仪表可以关，去重不能关 ✓（否则 `GUARD_BASE_INSTR=0` 会静默恢复
      "重复取数"✗，而指标上完全看不出来 ✗ = 最坏的失效形态）。
      因此：本函数**永远生效** ✓；只有分桶计数受 `_BASE_INSTR` 门控 ✓。

    无请求上下文（后台线程/启动期）⇒ 返回 True（不拦，行为与历史一致 ✓）。
    """
    try:
        t = _tr()
        if t.get("id") is None:
            return True
        d = t.get("src_tries")
        if d is None:
            d = {}
            t["src_tries"] = d
        if key in d:
            d[key] = (d[key][0] + 1, d[key][1])
            try:
                _b_inc("src_reuse_" + str(key))
            except Exception:
                pass
            return False
        d[key] = (1, "started")
        try:
            _b_inc("src_start_" + str(key))
        except Exception:
            pass
        return True
    except Exception:
        return True


def _src_mark(key, state):
    """更新某来源的最终状态（`ok`/`fail`/`timeout`/`skip`）✓ —— 供出口汇总与离线比对 ✓。"""
    try:
        t = _tr()
        if t.get("id") is None:
            return
        d = t.get("src_tries") or {}
        if key in d:
            d[key] = (d[key][0], str(state))
            t["src_tries"] = d
    except Exception:
        pass


def _src_count():
    """本次请求**总共启动了几个来源** ✓ —— 方案第 67 行的 `sources_attempted` ✓。"""
    try:
        t = _tr()
        if t.get("id") is None:
            return 0
        return len(t.get("src_tries") or {})
    except Exception:
        return 0


def _ecs_opt_from_msg(msg):
    """从客户端查询报文里提取 ECS option 的原始 RDATA（family+src+scope+addr），无则 None。

    2026-10-28 ECS 改造：per-user CDN 优选要求把客户端真实 /24 透传到国内腿。
    这里只读不写，异常一律退化为 None（= 按无 ECS 处理，行为与改造前一致）。
    """
    try:
        if not msg or len(msg) < 12:
            return None
        qd = struct.unpack("!H", msg[4:6])[0]
        ar = struct.unpack("!H", msg[10:12])[0]
        if ar < 1:
            return None
        i = 12
        for _ in range(qd):
            while i < len(msg) and msg[i]:
                i += 1 + msg[i]
            i += 1 + 4
        if i > len(msg):
            return None
        for _ in range(ar):
            while i < len(msg) and msg[i]:
                if (msg[i] & 0xC0) == 0xC0:
                    i += 2
                    break
                i += 1 + msg[i]
            else:
                if i < len(msg) and msg[i] == 0:
                    i += 1
            if i + 10 > len(msg):
                return None
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", msg[i:i + 10])
            i += 10
            if i + rdlen > len(msg):
                return None
            if rtype == 41:
                rd = msg[i:i + rdlen]
                j = 0
                while j + 4 <= len(rd):
                    ocode, olen = struct.unpack("!HH", rd[j:j + 4])
                    j += 4
                    if j + olen > len(rd):
                        break
                    if ocode == 8 and olen >= 4:
                        return rd[j:j + olen]
                    j += olen
                return None
            i += rdlen
    except Exception:
        return None
    return None


def _ecs_key(rd):
    """把 ECS RDATA 归一成可哈希的缓存维度；无则 None。"""
    if not rd or len(rd) < 4:
        return None
    try:
        return (struct.unpack("!H", rd[0:2])[0], int(rd[2] & 0xFF), bytes(rd[4:]))
    except Exception:
        return None


def _cur_ecs_rd():
    """当前请求的 ECS RDATA（由 _tr_begin() 在 worker 线程入口写入 _TR）。"""
    try:
        return _tr().get("ecs_rd")
    except Exception:
        return None


def _cur_ecs_key():
    return _ecs_key(_cur_ecs_rd())


def _ecs_clause(rd):
    """ECS option 在 OPT rdata 里的完整编码（code=8 + len + rdata）。"""
    if not rd:
        return b""
    return struct.pack("!HH", 8, len(rd)) + bytes(rd)


def _tr_begin(msg, entry="udp", src_cls=None):
    """在**处理入口**建立请求上下文：追踪 ID + 单调/墙钟起点 ✓。

    追踪 ID 必须与 verifier 侧共用 ⇒ 放在查询**报文里不载**（不能改报文 ✗），
    而是经 IPC meta 的 `rid` 字段传给 verifier（见 `_verifier_dot`）✓。

    `src_cls` = 调用方在**监听线程**里已算好的来源类别（`_src_of()` 的结果）。必须显式
    传入 ✓ —— 处理跑在 executor worker 线程里，而 `_SRC` 是 `threading.local()`，worker 上
    读不到监听线程刚写的值 ⇒ 原先来源类别永远进不了分桶（只 `_stats["q_src_*"]` 有数）。
    """
    t = _tr()
    with _QRID_LOCK:
        _QRID[0] = (_QRID[0] + 1) & 0xFFFFFFFF
        t["id"] = _QRID[0]
    t["ecs_rd"] = _ecs_opt_from_msg(msg)   # 2026-10-28 ECS：每请求复位
    t["mono0"] = time.monotonic()
    t["t0"] = time.time()
    t["entry"] = entry
    t["src_cls"] = src_cls
    t["done"] = False          # 幂等标记必须**每请求复位**（executor worker 线程会复用 ✓）
    t["attempts"] = []
    t["flags"] = []
    t["src"] = None
    t["cn"] = None
    t["wait_ms"] = None
    # ★ §3 第 67 行：**每请求**复位来源尝试表 ✗ —— worker 线程会复用同一个 dict ✓，
    #   不复位就会把上一个请求的 `src_tries` 带到下一个请求 ⇒ 新请求的第一个 A 查询
    #   会被误判成"已启动过"而**跳过** ✗（这是最危险的失效形态：静默少查一次 ✗）。
    t["src_tries"] = {}
    t["dl_mono"] = None
    try:
        _pq = parse_q(msg)
        t["name"], t["qtype"] = (_pq[0], _pq[1]) if _pq and len(_pq) > 1 else (None, None)
    except Exception:
        t["name"], t["qtype"] = (None, None)
    try:
        t["cn"] = bool(t["name"]) and is_cn_domain(t["name"])
    except Exception:
        t["cn"] = None
    return t


def _tr_elapsed_ms():
    t = getattr(_TR, "t", None)
    if not t or t.get("mono0") is None:
        return None
    return (time.monotonic() - t["mono0"]) * 1000.0


def _tr_note(stage, ms, extra=None):
    """登记一次「来源尝试」——阶段名 + 单调耗时（ms）+ 可选结果标签。

    只在**请求上下文已建立且未收口**时记账 ✓（否则 prewarm/keepalive 等后台线程的
    调用会污染下一个请求的分桶 ✗）。
    """
    if not _BASE_INSTR:
        return
    try:
        t = _tr()
        if t.get("id") is None:
            return
        if len(t["attempts"]) < 12:
            t["attempts"].append((stage, round(float(ms), 1), extra))
    except Exception:
        pass


def _tr_flag(tag):
    """登记一个**每请求只应出现一次**的布尔事实（hedge 启动/命中、见证就绪、retry 等）。"""
    if not _BASE_INSTR:
        return
    try:
        t = _tr()
        if t.get("id") is None:
            return
        if tag in t["flags"]:
            return
        if len(t["flags"]) < 16:
            t["flags"].append(tag)
    except Exception:
        pass


def _tag_bucket(tag):
    """把**任意** flag 字符串折算成白名单桶名 ✓。

    `_tr_flag()` 用短字符串做参数（如 `"b_ok" if x else "b_fail"`）⇒ 无法用集合判定，
    只能在此归一化：未登记值一律进 `other` ⇒ `_BS_ALLOW` 不会漏项、字典不会膨胀 ✓。
    """
    if not tag:
        return None
    if tag in ("hedge_started", "hedge_won", "witness_ready", "retry_alt", "retry_witness",
               "retry_fail", "alt_ready", "alt_not_ready", "cache_hit", "adm_hit",
               "budget_skip", "fail_closed", "probe", "cn_path", "b_used", "strict_hit",
               "a_ok", "a_fail", "b_ok", "b_fail", "veto_hit", "veto_none", "policy_used",
               "policy_fastpath", "alt_none", "alt_ok", "r8_ok", "r8_conflict", "ipc_used",
               "budget_keep", "r8_dedup"):
        return tag
    # §2-a：`attres_*` 的 detail 是**有界枚举**（`rrset_validity()` 返回的 kind 与
    # reason ✓）⇒ 显式登记以免全被吞进 `other` ✗（否则 §2-a 的观测项形同虚设 ✗）。
    if tag in _TTL_DETAILS:
        return tag
    return "other"


# §2-a：`rrset_validity()` 的 kind / reason / neg_cache 跳过原因 —— 全部是**固定枚举** ✓
# （`alt_adapter.py` 里的 `detail["kind"]` / `detail["reason"]` / `_neg_reason` 字面量 ✓）。
_TTL_DETAILS = frozenset((
    # kind
    "forward", "negative", "negative_unproven", "incomplete", "empty", "bogus", "exc",
    # reason
    "no_soa", "chain_no_target", "chain_no_target_no_soa", "cname_only_no_proof",
    "no_answer",
    # 否定缓存跳过原因（与 `_neg_reason` 一致 ✓）
    "unproven", "zero_ttl", "ok",
))


def _src_bucket(src):
    """把请求上下文里的**最终来源**折算成白名单桶名 ✓。

    `_BS_ALLOW` 只列了固定几类 ⇒ 未登记值一律进 `other`（保持有界 ✓，且不把域名/任意
    字符串塞进分桶字典 ✗）。
    """
    if not src:
        return "none"
    return src if src in _SRC_WHITELIST else "other"


# ===== 方案 §5：**热命中与有界刷新** =====
# 方案原文要点（第 92-104 行）：
#   · 按**最近业务频次**选最多 100 个 `(name,qtype,view)`，只对"仍有效且接近到期"的
#     **已准入**热门记录尝试后台刷新 ✓；
#   · 初值**刷新并发 2**、平均新增**≤1 QPS** 且**≤业务上游量 10%**，低流量时取更严格限制；
#     **已在 singleflight 刷新则不重复提交** ✗；
#   · 先只为**寿命 ≥60s** 的热门答案、在**剩余寿命约 10%–20%** 时刷新；短 TTL **不全量预热** ✗；
#     **失败不续期**，旧值只在原始有效期内继续使用 ✓；
#   · 刷新缓存限额：**最多 2000 条** ∧ **16 MiB**，**任一先到即淘汰**；
#     **绝不导入其他客户端/上游回答作为已准入答案** ✗；
#   · worker 与提交队列**有界**；**不提高**当前 96 inflight / 16 upstream workers
#     来掩盖等待 ✗；后台任务**优先让位于业务** ✓；
#   · `available` 连续 3 分钟 <300MB，或一分钟持续换页/IO 压力明显升高 ⇒ **暂停刷新**
#     （保留在线安全校验与 canary ✓）；**绝不因负载关闭安全准入** ✗；
#   · 不执行 `swapoff`/`drop_caches` ✗。
#
# 设计上守三条硬约束（不是为了省事，是为了让"不恶化"是结构性的而不是靠分支正确 ✓）：
#   ① **零新 daemon** ✓（方案第 94 行）：全部复用 guard 进程内的有界结构 + 一个后台线程 ✓；
#   ② **不抢业务容量** ✓：刷新**不使用** `_upstream_executor` / `_inflight_sem` / `_cold_sem` ✗
#      —— 它有自己的小执行器与信号量 ⇒ 后台任务**在结构上无法**加剧业务排队 ✓；
#   ③ **失败零副作用** ✓：刷新失败**什么都不写** ⇒ 旧记录自然在原 `until` 到期 ✗→✓
#      （"失败不续期"因此是**结构性**保证 ✓，不依赖某个分支写得对 ✓）。
_HOT_ON = _flag("GUARD_HOT_REFRESH", False)          # 默认**关** ⇒ 不设等于零行为变化 ✓
_HOT_MAX = int(os.environ.get("GUARD_HOT_MAX", "2000"))          # 频次账本上限（§5 第 4 项）✓
_HOT_BYTES_MAX = int(os.environ.get("GUARD_HOT_BYTES_MAX", str(16 * 1024 * 1024)))  # 16 MiB ✓
_HOT_SELECT = int(os.environ.get("GUARD_HOT_SELECT", "100"))     # 只挑前 100 个热门 ✓
_HOT_MIN_TTL = float(os.environ.get("GUARD_HOT_MIN_TTL", "60"))  # 寿命 ≥60s 才刷新 ✓
_HOT_LO = float(os.environ.get("GUARD_HOT_LO", "0.10"))          # 剩余比例窗口下沿 ✓
_HOT_HI = float(os.environ.get("GUARD_HOT_HI", "0.20"))          # 剩余比例窗口上沿 ✓
_HOT_TICK = float(os.environ.get("GUARD_HOT_TICK", "5.0"))       # 扫描周期（秒）✓
_HOT_CONC = int(os.environ.get("GUARD_HOT_CONC", "2"))           # 并发初值 2 ✓
_HOT_QPS = float(os.environ.get("GUARD_HOT_QPS", "1.0"))         # 平均新增 ≤1 QPS ✓
_HOT_SHARE = float(os.environ.get("GUARD_HOT_SHARE", "0.10"))    # ≤业务上游量 10% ✓
# 2026-10-24：`GUARD_HOT_BQPS_FLOOR` —— 业务量下限（**规划容量**，不是实测瞬时量）✓
# 背景：`rate = min(_HOT_QPS, _HOT_SHARE × bqps)`，实测低流量（0.59 QPS）时
# `_HOT_SHARE × bqps = 0.059/s` 把刷新饿死 ⇒ 改 `_HOT_QPS` 毫无效果 ✗。
# 设 floor=400 ⇒ 按「400 QPS 规划的 10% = 40/s」算，再由 `_HOT_QPS`(5/s) 封顶 ✓。
# 默认 0.0 ⇒ 不设该环境变量时行为与改前完全一致 ✓。
_HOT_BQPS_FLOOR = float(os.environ.get("GUARD_HOT_BQPS_FLOOR", "0.0"))
_HOT_TIMEOUT = float(os.environ.get("GUARD_HOT_TIMEOUT", "1.5")) # 刷新单次超时 ✓
_HOT_YIELD_PENDING = int(os.environ.get("GUARD_HOT_YIELD_PENDING", "4"))  # 业务在途则让位 ✓
# 资源闸门（§5 第 6 项）：available 连续 3 分钟 <300MB / 换页压力持续 1 分钟 ⇒ 暂停刷新 ✓
_RES_MEM_MIN_MB = float(os.environ.get("GUARD_RES_MEM_MIN_MB", "300"))
_RES_MEM_HOLD_S = float(os.environ.get("GUARD_RES_MEM_HOLD_S", "180"))
_RES_IO_PAGES_S = float(os.environ.get("GUARD_RES_IO_PAGES_S", "200"))
_RES_IO_HOLD_S = float(os.environ.get("GUARD_RES_IO_HOLD_S", "60"))
# 准入缓存的**对象占用**预算（与条数上限并列，任一先到即淘汰 ✓）
_ADM_BYTES_MAX = int(os.environ.get("GUARD_ADM_BYTES_MAX", str(16 * 1024 * 1024)))
# stats.json 写出周期 ✓ —— 20s 是生产值（不做改动 ✓）；允许夹具缩短，唯一用途是让
# **完成门**不必为了读一次计数而干等 20 秒 ✗（那不是"更严"，只是更慢 ✓）。
# ★ 注意它**不影响**任何判据：判据读的是 `_stats` 的累计值 ✗，与写出频率无关 ✓。
STATS_PERIOD = float(os.environ.get("GUARD_STATS_PERIOD", "20"))

# 频次账本：`(name,qtype,view) -> [freq, last_ts, approx_bytes]`。
# ★ 有界：条数上限 + 字节上限**同时**生效，超限即淘汰最低频/最旧的一批 ✓（永不无界增长 ✓）。
_HOT = {}
_HOT_BYTES = [0]
_HOT_LOCK = threading.Lock()
_HOT_BUCKET = [0.0]          # 令牌桶（平均速率限制 ✓，容量=1 个 tick ⇒ 不能突发 ✗）
_HOT_SEM = threading.BoundedSemaphore(max(1, _HOT_CONC))
_HOT_EXEC = None
_HOT_EXEC_LOCK = threading.Lock()
# 资源闸门状态（只读 /proc，**零网络、零子进程** ✓）
_RES = {"mem_since": 0.0, "io_since": 0.0, "vm_prev": None, "vm_ts": 0.0,
        "paused": False, "reason": "", "avail_mb": -1.0}
# 业务 QPS 估计的起点快照 `[base_q, mono]`（只在 `stats_writer()` 里更新 ✓，无锁 ✓）。
_BOOT_BQ = [0.0, 0.0]


def _st_bump(key, n=1):
    """无锁计数（与现场既有写法一致 ✓）；任何异常都不得影响主链路 ✓。"""
    try:
        _stats[key] = _stats.get(key, 0) + n
    except Exception:
        pass


def _pss_kb():
    """本进程 PSS（KB）✓ —— §5 完成门"新增 DNS 进程总 PSS ≤32MiB"的**硬证据**。

    ★ 为什么必须读 PSS 而不是 RSS：guard 与 verifier 共享了大量只读页
      （Python 解释器、`.so`、常量表）✗ —— RSS 会把这份共享内存**在每个进程里各算一遍** ✗
      ⇒ 两进程 RSS 相加会系统性高估真实占用 ✓（PSS 按共享页摊分，才是"新增多少"的正解 ✓）。
    ★ 只读 `/proc/self/smaps_rollup`（内核已摊分好的汇总行 ✓），**零子进程、零第三方依赖** ✓。
      该文件在 Linux 4.14+ 才有（本机 systemd 239 / AL8 满足 ✓）；读不到就返回 -1 ✓
      —— **绝不**因此影响任何判定 ✗（纯观测 ✓）。
    """
    try:
        with open("/proc/self/smaps_rollup") as f:
            for ln in f:
                if ln.startswith("Pss:"):
                    return int(ln.split()[1])
    except Exception:
        pass
    return -1


def _pss_sample():
    """把 PSS 写进 `_stats`（stats_writer 每 20s 调一次 ✓）—— 进程级资源只在此处落地 ✓。"""
    try:
        v = _pss_kb()
        if v > 0:
            _stats["pss_kb"] = v
            if v > int(_stats.get("pss_peak_kb", 0) or 0):
                _stats["pss_peak_kb"] = v
    except Exception:
        pass


def _hot_key(name, qtype):
    """频次/刷新键 = `(name, qtype, view)` ✓。

    ★ **必须含 qtype**（方案第 73 行"不同 qtype 不共用答案"同一条铁律 ✓）：
      A/AAAA/HTTPS 的答案与寿命完全不同 ✗，合并计数会把"AAAA 热"算成"A 热" ⇒
      刷新一个并不热的类型 ✗（白付上游请求 ✓）。
    ★ `view` 固定 `"default"`：与 `_adm_cache_get()` 的视图维度对齐 ✓ ⇒
      将来若有人给某条路径开 ECS/CD，键会自然分化、不会跨视图互相刷新 ✓。
    """
    return (str(name).lower().rstrip("."), int(qtype or 1), "default")


def _hot_note(name, qtype):
    """登记一次**业务**请求的频次 ✓（只由 `_tr_finish()` 对 client 类流量调用 ✓）。

    ★ 为什么只算 client：方案 §1 已定"业务与探针分开"✗ —— 若把探针/主机自检算进来，
      热门榜会被"我们自己每 60s 打一次的名字"占满 ✗ ⇒ 刷新预算花在没人问的名字上 ✗。
    """
    if not _HOT_ON or not name:
        return
    try:
        k = _hot_key(name, qtype)
        with _HOT_LOCK:
            e = _HOT.get(k)
            if e is None:
                _HOT[k] = [1, time.time(), 96 + 8 * len(k[0])]
                _HOT_BYTES[0] += 96 + 8 * len(k[0])
                _hot_evict_locked()
            else:
                e[0] += 1
                e[1] = time.time()
    except Exception:
        pass


def _hot_evict_locked():
    """条数/字节**任一**超限即淘汰（调用方持 `_HOT_LOCK` ✓）。

    淘汰策略：先按 `(freq, last_ts)` 升序丢掉 10%（**低频优先** ✓）；
    字节超限时若仍不够，再按 `last_ts` 升序继续丢 ✓ —— 两步都用**有界循环**，
    保证函数在 O(账本大小) 内结束、绝不因"丢不掉"而死循环 ✗。
    """
    try:
        if len(_HOT) < _HOT_MAX and _HOT_BYTES[0] <= _HOT_BYTES_MAX:
            return
        order = sorted(_HOT.keys(), key=lambda x: (_HOT[x][0], _HOT[x][1]))
        drop = max(1, len(order) // 10)
        for k in order[:drop]:
            e = _HOT.pop(k, None)
            if e:
                _HOT_BYTES[0] -= e[2]
        _st_bump("hot_evict")
        if _HOT_BYTES[0] > _HOT_BYTES_MAX:
            for k in sorted(_HOT.keys(), key=lambda x: _HOT[x][1])[:drop]:
                e = _HOT.pop(k, None)
                if e:
                    _HOT_BYTES[0] -= e[2]
            _st_bump("hot_evict_bytes")
    except Exception:
        pass


def _mem_available_mb():
    """读 `/proc/meminfo` 的 `MemAvailable`（**不用 free 子进程** ✓，零 fork ✓）。"""
    try:
        with open("/proc/meminfo") as f:
            for ln in f:
                if ln.startswith("MemAvailable:"):
                    return float(ln.split()[1]) / 1024.0
    except Exception:
        pass
    return -1.0


def _vm_pages():
    """换页/回收压力：`pgscan_kswapd + pgscan_direct + pswpout`（累计页数 ✓）。"""
    tot = 0
    try:
        with open("/proc/vmstat") as f:
            for ln in f:
                p = ln.split()
                if len(p) == 2 and p[0] in ("pgscan_kswapd", "pgscan_direct", "pswpout"):
                    tot += int(p[1])
    except Exception:
        return None
    return tot


def _res_gate(now):
    """资源闸门：返回 `(allow, reason)` ✓ —— **只决定"是否刷新"** ✗，绝不影响安全准入 ✓。

    `available` 连续 `_RES_MEM_HOLD_S`(180s) <300MB ⇒ 暂停 ✓；
    换页速率持续 `_RES_IO_HOLD_S`(60s) > `_RES_IO_PAGES_S` ⇒ 暂停 ✓。
    ★ 为什么用"持续"而不是"瞬时"：单次采样必然抖动 ✗（一次 page cache 回收就能让
      available 瞬间掉到阈值下）⇒ 瞬时判据会导致刷新**频繁启停**、行为不可预测 ✗。
    """
    try:
        av = _mem_available_mb()
    except Exception:
        av = -1.0
    _RES["avail_mb"] = av
    if av >= 0:
        _stats["res_mem_available_mb"] = int(av)
    mem_bad = (0 <= av < _RES_MEM_MIN_MB)
    if mem_bad:
        if _RES["mem_since"] <= 0:
            _RES["mem_since"] = now
    else:
        _RES["mem_since"] = 0.0
    if _RES["mem_since"] > 0 and (now - _RES["mem_since"]) >= _RES_MEM_HOLD_S:
        _RES["paused"] = True
        _RES["reason"] = "mem"
        _st_bump("res_mem_low")
        return False, "mem"
    vm = None
    try:
        vm = _vm_pages()
    except Exception:
        vm = None
    if vm is not None:
        prev = _RES["vm_prev"]
        if prev is not None and now > _RES["vm_ts"]:
            rate = float(vm - prev) / max(1e-6, (now - _RES["vm_ts"]))
            _stats["res_io_pages_s"] = int(rate)
            if rate > _RES_IO_PAGES_S:
                if _RES["io_since"] <= 0:
                    _RES["io_since"] = now
            else:
                _RES["io_since"] = 0.0
        _RES["vm_prev"] = vm
        _RES["vm_ts"] = now
    if _RES["io_since"] > 0 and (now - _RES["io_since"]) >= _RES_IO_HOLD_S:
        _RES["paused"] = True
        _RES["reason"] = "io"
        _st_bump("res_io_high")
        return False, "io"
    _RES["paused"] = False
    _RES["reason"] = ""
    return True, ""


def _hot_get_exec():
    """惰性建**独立**小执行器 ✓ —— 不复用 `_upstream_executor` ✗（否则后台任务会
    占掉业务的 worker 名额 ⇒ 恰好违反方案"不提高 worker 来掩盖等待"✗）。"""
    global _HOT_EXEC
    if _HOT_EXEC is None:
        with _HOT_EXEC_LOCK:
            if _HOT_EXEC is None:
                _HOT_EXEC = ThreadPoolExecutor(max_workers=max(1, _HOT_CONC),
                                               thread_name_prefix="hot")
    return _HOT_EXEC


def _hot_decide(rec, now, is_cn):
    """**纯函数**：这条准入缓存记录该不该刷新 ⇒ `(action, reason)` ✓。

    抽成纯函数的理由（与 §2-a 抽 `_alt_classify()` 同一动机 ✓）：判据是 §5 的**核心**✗，
    埋在调度循环里就只能"读代码相信"✗ ⇒ 无法离线逐条回归 ✗（本项目的既有教训：
    `_tr().src=…` 那种被裸 except 吞掉的缺陷，就是"只能靠读"造成的 ✗）。
    现在 `tests/test_hot_refresh.py` 可以对它逐条断言 ✓。

    判据顺序（**先便宜后麻烦**，且顺序本身有意义 ✓）：
      ① `ttl < _HOT_MIN_TTL` ⇒ 短 TTL **不全量预热** ✗（方案第 98 行）——
         先判它：`ttl` 是记录自带的常数，与 `now` 无关 ⇒ 最便宜 ✓；
      ② `remain <= 0` ⇒ 已过期（准不进去也刷不动 ✓）；
      ③ `source != "local-a"` ⇒ **拒绝** ✓（理由见 `_hot_refresh_one()` 顶部注释：
         用 A 重取会把 POL/alt 的"采纳条件"绕过 ✗）；
      ④ `is_cn` ⇒ **拒绝** ✓（CN 的采纳含 B 就近性/存在性否决 ✗，A-only 重取会绕过它 ✗）；
      ⑤ `frac > _HOT_HI` ⇒ 离到期还远，**这一轮不刷** ✓；
      其余 ⇒ 刷新 ✓。

    ★ 为什么低于 `_HOT_LO` 也刷（而不是卡在 10%–20% 这个带内 ✗）：
      方案的窗口是"**约** 10%–20%"⑨，而调度的 tick（默认 5s）与 TTL 是**互相独立**的量 ✗
      —— 短寿命热门（例如 TTL=90s）的窗口只有 9 秒宽，任何 tick 抖动都会整段跳过 ✗
      ⇒ 带内判据会让**一部分热门永远不被刷新** ✗（"刷新器在跑、指标在动、体验没变"✗）。
      因此实现为"**已进入 ≤20% 窗口即刷**"，并向 `hot_below_lo` 单独计数 ✓
      ⇒ 报告里能区分"按窗口刷的"与"已滑过窗口才刷的"✓，既不夸大也不装看不见 ✓。
    """
    if rec is None:
        return "skip", "stale"
    ttl = float(rec.get("ttl") or 0.0)
    if ttl < _HOT_MIN_TTL:
        return "skip", "ttl"
    remain = float(rec.get("until") or 0.0) - float(now)
    if remain <= 0:
        return "skip", "stale"
    _src = str(rec.get("source") or "")
    if _src != "local-a":
        # 2026-10-24：`source == "local-cn"`（国内采纳链的记录）也允许后台刷新 ✓ ——
        # 但**绝不**走 `_hot_refresh_one()` 的 A-only 重取（那会绕过 "B 就近性 + 存在性否决"
        # ⇒ 正是 ③④ 两条判据存在的理由 ✗）；改派 `_hot_refresh_one_cn()` 重跑**完整** CN 采纳链 ✓。
        if not (is_cn and _src == "local-cn"):
            return "skip", "source"
    if is_cn and _src != "local-cn":
        return "skip", "cn"
    if remain / max(1e-6, ttl) > _HOT_HI:
        return "skip", "out_window"
    return ("refresh-cn" if _src == "local-cn" else "refresh"), "in_window"


def _hot_refresh_one(name, qtype, expect_until):
    """后台刷新一个热门记录 ✓（在**独立执行器**里跑，全程不发任何客户端应答 ✓）。

    判据链（任一不满足 ⇒ **什么都不写** ✗，只记账 ✓）：
      ① 重新走 **A 认证源**取原始 wire（与业务同一条上游路径 ✓，不引入新信任方 ✓）；
      ② **重新过准入闸门** `_alt_classify()`（BOGUS/UNKNOWN/零 TTL ⇒ 拒绝 ✓）——
         这是"**绝不导入其他来源回答作为已准入答案**"的落点 ✓；
      ③ TTL>0 ⇒ 才写；写时带 `refresh=True`（**绕过"同答案不重写"闸门** ✓）——
         为什么必须绕过：刷新命中的正是"答案没变但寿命快到"的场景 ✗，若被该闸门拦住，
         刷新会**永远不生效** ✗（看似在跑、指标上 `adm_cache_reput_same` 涨、实际零效果 ✗）。
    """
    try:
        msg = mk_query_do(name, qtype)
        wire = udp_query(UNBOUND, msg, timeout=_HOT_TIMEOUT)
        if not wire:
            _st_bump("hot_failed")
            return
        ans = _alt_classify(wire, "local-a")
        if ans is None or str(ans.verdict.value) not in ("secure", "accepted"):
            _st_bump("hot_failed")
            return
        ttl = _adm_ttl_from(ans, _adm_cap_for(ans.verdict))
        if ttl <= 0:
            _st_bump("hot_failed")
            return
        # 只在"记录没有被别的路径换成更新的一条"时写 ✓（否则可能用更旧的上游视图
        # 覆盖掉刚刚采纳的新答案 ✗ —— 刷新**永远不该降低新鲜度** ✗）。
        cur = _ADM_CACHE.get(_adm_key(name, qtype))
        if cur is not None and float(cur.get("until") or 0) > float(expect_until) + 1e-6:
            _st_bump("hot_skip_raced")
            return
        qid = struct.unpack("!H", msg[:2])[0]
        _adm_cache_put(name, qtype, rewrite_id(wire, qid), str(ans.verdict.value),
                       "local-a", ttl, refresh=True)
        _st_bump("hot_refreshed")
    except Exception:
        _st_bump("hot_failed")


def _hot_refresh_one_cn(name, qtype, expect_until):
    """后台刷新一条 **CN 采纳链** 记录 ✓（2026-10-24）。

    与 `_hot_refresh_one()` 的根本区别：**不自己实现判据** ✗ ——
    A-only 重取会绕过 CN 的三条铁律（B 就近性、存在性见证 `cn_exist_veto(deny_probe=True)`、
    `suspicious()` 的 R1 投毒地址检查）✗。所以这里直接复用**在线请求的同一条链**
    `_policy_cn_answer()`：取到 B 的字节 ⇒ 原样交给它做准入裁决 ⇒ 它自己写 `_adm_cache` ✓。

    刻意做的事：
      ① 先 `pop` 掉 adm 记录再调用 ⇒ 否则 `_policy_cn_answer` 开头 `_adm_cache_answer()`
         会直接命中旧记录返回 ⇒ 刷新变成空转 ✗；
      ② 用 `_refresh=True` ⇒ 答案未变也能把寿命推回满 ✓；
      ③ 失败时**恢复旧记录** ⇒ 刷新失败绝不导致在线请求丢缓存 ✓（只会退化成同步见证）。
    """
    try:
        msg = mk_query_do(name, qtype)
        qid = struct.unpack("!H", msg[:2])[0]
        b_wire = udp_query(UNBOUND_B, msg, timeout=_HOT_TIMEOUT)
        if not b_wire:
            _st_bump("hot_cn_failed")
            return
        ans = None
        try:
            # 刻意**不 pop** 准入缓存 ✓：pop 到写回之间（最长约 500 ms）在线请求会全部穿透 ⇒
            # 每次刷新等于制造一个 500 ms 的慢查询窗口 ✗。`_skip_cache=True` 让裁决函数
            # 跳过开头的 adm 短路 ⇒ 既能重新裁决，旧记录又始终对在线请求生效 ✓。
            ans = _policy_cn_answer(name, qtype, None, b_wire,
                                    deadline=_dl_wall(_HOT_TIMEOUT), query_id=qid,
                                    _refresh=True, _skip_cache=True)
        except Exception:
            ans = None
        if ans is None:
            _st_bump("hot_cn_failed")
            return
        _st_bump("hot_cn_refreshed")
        _st_bump("hot_refreshed")
    except Exception:
        _st_bump("hot_cn_failed")


def hot_refresh():
    """§5 的后台刷新循环 ✓（单线程调度 ⇒ 提交速率天然有界 ✓）。

    速率上限 = `min(_HOT_QPS, _HOT_SHARE × 业务 QPS)` ✓ —— 用 `stats` 里 `base_q`
    的**两次快照差值**估业务速率 ✓（与本进程同源、无额外采样 ✓）。
    ★ 为什么必须"按业务比例"而不是"固定 1 QPS"：方案第 97 行要求
      "低流量时取更严格限制"✗ —— 凌晨 0.2 QPS 的业务配上 1 QPS 的刷新 =
      **上游请求量 6 倍于业务** ✗，完全违背"平均新增不超过业务上游量 10%"✓。
    """
    _last_bq = [_stats.get("base_q", 0) or 0]
    while True:
        try:
            time.sleep(max(1.0, _HOT_TICK))
            if not _HOT_ON:
                continue
            now = time.time()
            ok, why = _res_gate(now)
            if not ok:
                # §5 第 6 项：暂停刷新（**只暂停刷新** ✗；在线安全校验/准入/canary 照旧 ✓）
                _st_bump("hot_pause_" + why)
                continue
            _st_bump("hot_win")
            bq = int(_stats.get("base_q", 0) or 0)
            dbq = max(0, bq - _last_bq[0])
            _last_bq[0] = bq
            # 按**规划容量**取大值：低流量时段不让 `_HOT_SHARE × bqps` 把刷新饿死 ✓
            # （见 `_HOT_BQPS_FLOOR` 注释）；满流量时段 floor 不起作用，仍受 10% 约束 ✓。
            bqps = max(float(dbq) / max(1.0, _HOT_TICK), _HOT_BQPS_FLOOR)
            rate = min(_HOT_QPS, _HOT_SHARE * bqps)
            cap = max(0.0, _HOT_QPS * _HOT_TICK)
            _HOT_BUCKET[0] = min(cap, _HOT_BUCKET[0] + rate * _HOT_TICK)
            allow = int(_HOT_BUCKET[0])
            # ★★ 令牌**只限制"提交（发包）"，绝不限制"扫描/记账"** ✓（本块修掉的真缺陷）。
            #   旧写法是"`allow<=0` ⇒ 立刻 continue"✗，后果：业务量一低（或业务短暂间歇），
            #   **扫描器整个停摆** ✗ ⇒ `hot_skip_*` / `hot_out_window` / `hot_in_window`
            #   全部记不到 ✗ ⇒ 指标上看不见"刷新器到底在想什么"✗，而 §5 恰恰要求
            #   "短 TTL 导致查询增加时**如实记录**"✓、完成门也要按 `hot_skip_*` 判"该不该刷"✓。
            #   实测（G3/G4 首轮）：`hot_win` 27 而 `hot_cands` 恒 0 ⇒ 扫描一次都没发生 ✗。
            #   原则：**观察永远做 ✓，发包按令牌 ✓** —— 两者解耦。
            with _HOT_LOCK:
                top = sorted(_HOT.keys(), key=lambda x: -_HOT[x][0])[:_HOT_SELECT]
            _st_bump("hot_cands", len(top))
            for k in top:
                try:
                    _nm, _qt, _vw = k
                    # ★ 判据全部收在 `_hot_decide()`（纯函数 ✓ 可离线逐条回归 ✓）；
                    #   这里只负责**记账**与**提交**，不再复制一份判断逻辑 ✗
                    #   （否则"判据"与"记账"两处会漂移 ⇒ 指标不再描述真实行为 ✗）。
                    rec = _ADM_CACHE.get(_adm_key(_nm, _qt))
                    try:
                        _iscn = bool(is_cn_domain(_nm))
                    except Exception:
                        _iscn = True     # 判不了 ⇒ **按 CN 处理**（保守拒绝 ✓，宁可少刷 ✓）
                    _act, _why = _hot_decide(rec, now, _iscn)
                    if _act not in ("refresh", "refresh-cn"):
                        _st_bump("hot_skip_" + _why)
                    else:
                        _st_bump("hot_in_window")
                        if _act == "refresh-cn":
                            _st_bump("hot_cn_in_window")
                        _frac = (float(rec.get("until") or 0.0) - now) / max(
                            1e-6, float(rec.get("ttl") or 0.0))
                        _stats["hot_frac_sum"] = float(_stats.get("hot_frac_sum", 0.0)) + _frac
                        _st_bump("hot_frac_n")
                        if _frac < _HOT_LO:
                            # 已滑过 10% 下沿才被刷 ⇒ 单独计数 ✓（见 `_hot_decide()` 说明）
                            _st_bump("hot_below_lo")
                        # ★ 令牌闸门放在**这里**（而不是扫描循环开头）✓：这样
                        #   "本该刷但被速率上限拦住"是一个**可观测**的状态 ✓，
                        #   而不是"整个扫描器停摆、什么都看不见"✗。
                        if allow <= 0:
                            _st_bump("hot_qps_limited")
                            continue
                        # 已在 singleflight 刷新 ⇒ **不重复提交** ✗（方案第 97 行）
                        try:
                            _lk = _query_lock_get((_nm, _qt))
                            if not _lk.acquire(False):
                                _st_bump("hot_skip_lock")
                                continue
                        except Exception:
                            _lk = None
                        # 业务繁忙 ⇒ 让位（§5 第 5 项）✓
                        if int(_pending_count or 0) >= _HOT_YIELD_PENDING:
                            _st_bump("hot_yielded")
                            if _lk is not None:
                                try:
                                    _lk.release()
                                except Exception:
                                    pass
                            continue
                        if not _HOT_SEM.acquire(False):
                            _st_bump("hot_conc_blocked")
                            if _lk is not None:
                                try:
                                    _lk.release()
                                except Exception:
                                    pass
                            continue
                        expect = float(rec.get("until") or 0.0)
                        allow -= 1
                        _HOT_BUCKET[0] = float(allow)
                        _st_bump("hot_submitted")
                        _lk_ref = _lk

                        def _run(_n=_nm, _q=_qt, _e=expect, _l=_lk_ref, _a=_act):
                            try:
                                if _a == "refresh-cn":
                                    _hot_refresh_one_cn(_n, _q, _e)
                                else:
                                    _hot_refresh_one(_n, _q, _e)
                            finally:
                                try:
                                    if _l is not None:
                                        _l.release()
                                except Exception:
                                    pass
                                try:
                                    _HOT_SEM.release()
                                except Exception:
                                    pass
                        try:
                            _hot_get_exec().submit(_run)
                        except Exception:
                            _st_bump("hot_failed")
                            try:
                                if _lk is not None:
                                    _lk.release()
                            except Exception:
                                pass
                            try:
                                _HOT_SEM.release()
                            except Exception:
                                pass
                except Exception:
                    _st_bump("hot_scan_err")
                    continue
        except Exception:
            try:
                _st_bump("hot_loop_err")
            except Exception:
                pass


def _tr_finish(msg, resp, once=False, ignore_cls=()):
    """在**回复点**收口：把本次请求汇总进有界分桶（+ 可选有界明细）。

    `once=True`：只收口一次（TCP 路径的 `finally` 可能二次调用 ⇒ 防止同一请求被
    `q_*`/`base_q` **重复计数** ✗）。用 `t["done"]` 幂等标记 ✓。

    `ignore_cls`：**这些来源类别不进基线**，但照样收口（幂等标记仍置位）✓。
    典型用途：5356 探针（`entry=probe`）与 host/loopback 自检 —— 方案 §1 明确要求
    "业务与探针分开统计"、且主机侧自检不要污染用户侧指标 ✓。
    """
    if not _BASE_INSTR:
        return
    try:
        t = getattr(_TR, "t", None)
        if not t or t.get("id") is None:
            return
        if once and t.get("done"):
            return
        if t.get("src_cls") in ignore_cls:
            t["done"] = True
            t["id"] = None
            return
        el = _tr_elapsed_ms()
        qt = t.get("qtype")
        qt_b = {1: "a", 28: "aaaa", 65: "https", 15: "mx", 16: "txt", 5: "cname"}.get(qt, "other")
        cn_b = "cn" if t.get("cn") else ("noncn" if t.get("cn") is False else "unknown")
        entry_b = t.get("entry") or "udp"
        _scls = t.get("src_cls")
        if _scls:
            # 口径：entry_* = **入口类别（谁在问）**，不是协议 ✓ —— 来源类别可用时优先，
            # 不可用（None）才退回协议名（udp/tcp）✓
            entry_b = {"client": "client", "host": "host", "loopback": "loopback",
                       "probe": "probe", "other": "other"}.get(_scls, entry_b)
        src_b = _src_bucket(t.get("src"))
        rc = None
        try:
            if resp and len(resp) >= 4:
                rc = struct.unpack("!H", resp[2:4])[0] & 0xF
        except Exception:
            rc = None
        with _lock:
            _b_inc("q_" + qt_b)
            _b_inc("q_%s_%s" % (qt_b, cn_b))
            _b_inc("entry_" + entry_b)
            _b_inc("src_" + src_b)
            _b_inc("rc_" + str(rc if rc is not None else "none"))
            if el is not None:
                _b_hist("ms_" + qt_b, el)
                _b_hist("ms_all", el)
                if _scls == "client" and qt_b in ("a", "aaaa"):
                    _b_hist("client_ms_" + qt_b, el)
                _wq = t.get("wait_ms")
                if isinstance(_wq, (int, float)):
                    _b_hist("wait_all", float(_wq))
                for _thr in (1000, 2000, 4000):
                    if el > _thr:
                        _b_inc("gt%dms_%s" % (_thr, qt_b))
                        _b_inc("gt%dms_all" % _thr)
            if rc == 2:
                _b_inc("servfail_" + qt_b)
            for _tg in t.get("flags") or []:
                _tb = _tag_bucket(_tg)
                if _tb:
                    _b_inc("f_" + _tb)
            for _st, _ms, _ex in (t.get("attempts") or []):
                _b_hist("att_" + _st, _ms)
                if (_scls == "client" and qt_b in ("a", "aaaa")
                        and _st in _CLIENT_STAGE_BUCKETS):
                    _b_hist("client_att_" + _st + "_" + qt_b, _ms)
                if _ex:
                    # 结果标签也归一化 ⇒ 例如 `domestic` 的 "POL"/"A" 不会撑爆字典 ✓
                    # §2-a：`ttl` 阶段的 detail 是 `rrset_validity()` 的 kind/reason（固定枚举 ✓），
                    # 必须一并放行 —— 否则 `attres_ttl_other` 会把 §2-a 的观测项全部吞掉 ✗
                    # （实测：68 次全进 other，等于没测 ✓）。
                    if _ex in ("ok", "fail", "timeout", "skip", "none") or _ex in _TTL_DETAILS:
                        _b_inc("attres_%s_%s" % (_st, _ex))
                    else:
                        _b_inc("attres_%s_other" % _st)
            # Step-1 §1：按**来源类别**分列（`client` = 用户侧，可直接与整体基线相减 ✓）
            # 类别取自 `_src_of()` 的**固定值域**，再经白名单归一化 ⇒ 字典有界 ✓
            _rk("base_cls_" + (_scls if _scls in ("client", "host", "loopback",
                                                  "probe", "other") else "none"))
            # 每**请求**级汇总（与按帧累加的分桶互为交叉校验 ✓）——调用方已持 `_lock` ✓
            _fl = t.get("flags") or []
            _at = t.get("attempts") or []
            _rk("base_q")
            if "cache_hit" in _fl:
                _rk("base_cache")
            if "hedge_started" in _fl:
                _rk("base_hedge")
            if "cn_path" in _fl:
                _rk("base_cn")
            if "a_ok" in _fl:
                _rk("base_a_ok")
            if "b_ok" in _fl:
                _rk("base_b")
            if ("retry_alt" in _fl) or ("retry_witness" in _fl):
                _rk("base_retry")
            for _s2, _m2, _e2 in _at:
                if _s2 == "alt":
                    _rk("base_alt_order")
                elif _s2 in ("witness", "a_pre"):
                    _rk("base_witness")
        if _BASE_SAMPLE:
            _bs_put(t, el, rc, qt_b, cn_b, entry_b, src_b)
        # Step-5 §5：**只为用户侧流量**累计热门频次 ✓（探针/主机自检不算 ✗ —— 否则
        # 热门榜会被"我们自己每 60s 打一次的名字"占满 ⇒ 刷新预算花在没人问的名字上 ✗）。
        # 放在 `_lock` **之外**：`_hot_note()` 有自己的锁、与分桶无共享状态 ✓
        # （避免锁嵌套，也避免把 20s 一次的统计路径拉长 ✓）。
        if t.get("src_cls") == "client":
            try:
                _hot_note(t.get("name"), qt)
            except Exception:
                pass
    finally:
        t["done"] = True
        t["id"] = None


# 分桶边界（毫秒）——**定长**，永不增长 ⇒ 内存恒有界 ✓（末桶为"超过最大边界"）
_BS_BOUNDS = (5, 10, 20, 30, 50, 80, 120, 200, 300, 500, 800, 1200, 2000, 3000, 5000, 8000)
_BS_NB = len(_BS_BOUNDS) + 1
# 计数器**键前缀白名单**——防止外部可控字符串（域名/qtype 意外值）撑爆字典。
# 只允许已枚举的字面键进入；未知键累加进 "_other" 单桶 ✓（有界 ✓）。
_BS_ALLOW = set()
for _qt in ("a", "aaaa", "https", "mx", "txt", "cname", "other"):
    _BS_ALLOW.add("q_" + _qt)
    _BS_ALLOW.add("ms_" + _qt)
    _BS_ALLOW.add("servfail_" + _qt)
    for _cn in ("cn", "noncn", "unknown"):
        _BS_ALLOW.add("q_%s_%s" % (_qt, _cn))
    for _thr in (1000, 2000, 4000):
        _BS_ALLOW.add("gt%dms_%s" % (_thr, _qt))
for _thr in (1000, 2000, 4000):
    _BS_ALLOW.add("gt%dms_all" % _thr)
# 口径（Step-1 §1）：entry_* = **入口类别**（谁在问），不是协议。
#   client  = 172.18.0.2 经 AdGuard Home 来的家用设备（方案 §1 的业务基线口径 ✓）
#   host    = 172.18.0.1 主机侧监视器（canary/chainmon/probe 853 层）—— 不是用户流量 ✓
#   loopback= 127.0.0.1 本机自检 ✓
#   probe   = 5356 专用探针端口 ✓（另有 entry_udp/tcp 兜底：来源类别未识别时退回协议名）
for _e in ("udp", "tcp", "probe", "client", "host", "loopback", "other"):
    _BS_ALLOW.add("entry_" + _e)
for _s in ("local-a", "local-alt", "local-b", "local-cn", "clean-channel", "negative-cache",
           "strict", "none", "other", "witness"):
    _BS_ALLOW.add("src_" + _s)
for _r in ("0", "1", "2", "3", "4", "5", "none"):
    _BS_ALLOW.add("rc_" + _r)
for _st in ("a", "alt", "b", "veto", "witness", "r8", "clean", "strict", "retry",
            "retry_alt", "retry_witness", "ttl", "negttl",
            "q-alt", "q-b", "q-clean", "queue", "ipc", "domestic", "a_pre", "a_hint",
            "b_pre", "bget", "dnscrypt", "doq", "doq2", "doq3", "dot", "tcp"):
    _BS_ALLOW.add("att_" + _st)
    for _ex in ("ok", "fail", "timeout", "skip", "none", "other"):
        _BS_ALLOW.add("attres_%s_%s" % (_st, _ex))
# §2-a：`ttl` 阶段的 detail 是**有界枚举**（`rrset_validity()` 的 kind/reason ✓）⇒ 显式登记 ✓。
# 现场坑：漏登记时这些计数会进 `_BS["unk"]`（有界 ✓、不外泄 ✓）而**不是**被错误丢掉 ——
# 实测 unk 立刻报出 `attres_ttl_forward/incomplete/negative/negative_unproven` ⇒ 据此补登 ✓。
# 这正是 §1 设计 `unk` 桶的用途：白名单漏项**可被发现** ✓（而不是静默消失 ✗）。
for _ts in ("ttl", "negttl"):
    for _td in sorted(_TTL_DETAILS):
        _BS_ALLOW.add("attres_%s_%s" % (_ts, _td))
# §3 第 67/70 行：`sources_attempted` 每请求来源启动/复用计数 ✓ ——
# `src_start_<k>` = 该来源真的被启动了一次；`src_reuse_<k>` = **被去重闸门拦下的重复启动次数** ✓。
# 为什么要显式登记：§3 的完成门要求"每个来源最多启动一次"✗，若这两个键落进 `other`，
# "去重到底生效没生效"在指标上就不可判 ✓→✗（只能靠读代码相信 ✗）。
for _sk in _SRC_ONCE:
    _BS_ALLOW.add("src_start_" + _sk)
    _BS_ALLOW.add("src_reuse_" + _sk)
for _tg in ("hedge_started", "hedge_won", "witness_ready", "retry_alt", "retry_witness",
            "retry_fail", "alt_ready", "alt_not_ready", "cache_hit", "adm_hit",
            "budget_skip", "fail_closed", "probe", "cn_path", "b_used", "strict_hit",
            "a_ok", "a_fail", "b_ok", "b_fail", "veto_hit", "veto_none", "policy_used",
            "policy_fastpath", "alt_none", "alt_ok", "r8_ok", "r8_conflict", "ipc_used",
            "budget_keep", "r8_dedup", "other"):
    _BS_ALLOW.add("f_" + _tg)
_BS_ALLOW.add("ms_all")
_BS_ALLOW.add("wait_all")
for _st in ("a", "b", "alt", "veto", "strict", "clean", "domestic", "queue", "cnpath",
            "r8", "ipc", "witness", "retry_alt", "retry_witness", "a_pre", "bget"):
    _BS_ALLOW.add("wait_" + _st)


# Client-only A/AAAA histograms use fixed keys; never derive metric labels from DNS input.
_CLIENT_STAGE_BUCKETS = (
    "a", "alt", "b", "veto", "witness", "r8", "clean", "strict",
    "retry", "retry_alt", "retry_witness", "ttl", "negttl", "q-alt",
    "q-b", "q-clean", "queue", "ipc", "domestic", "a_pre", "a_hint",
    "b_pre", "bget", "dnscrypt", "doq", "doq2", "doq3", "dot", "tcp",
)
for _qt in ("a", "aaaa"):
    _BS_ALLOW.add("client_ms_" + _qt)
    for _stage in _CLIENT_STAGE_BUCKETS:
        _BS_ALLOW.add("client_att_" + _stage + "_" + _qt)

_BS = {"c": {}, "h": {}, "unk": []}
_BS_UNK_MAX = 24          # 未知键只留名字（有界）✓ —— 便于核对白名单是否漏项


def _rk(key):
    """入口/器/帧级**原始计数** helpers（调用方须持 `_lock`）✓。

    与 `_BS["c"]` 的白名单分桶分开：这些键**直接进 `_stats`** ⇒ 会被 `stats_writer()` 导出到
    `stats.json` 顶层，链路与现场脚本都能读到 ✓（`base_q`/`base_cache` 等名字稳定、不随
    qtype 组合爆炸 ✓）。属 `PERSIST_SKIP` ⇒ 只用两次快照的 delta ✓。
    """
    _stats[key] = _stats.get(key, 0) + 1


def _b_inc(key):
    """有界计数（调用方须持 `_lock`）✓ —— 白名单外一律进 `_other`，字典永不无界增长 ✓。"""
    c = _BS["c"]
    if key in c:
        c[key] = c[key] + 1
        return
    if key in _BS_ALLOW:
        c[key] = 1
        return
    c["_other"] = c.get("_other", 0) + 1
    _u = _BS["unk"]
    if len(_u) < _BS_UNK_MAX and key not in _u:
        _u.append(str(key)[:48])


def _b_hist(name, ms):
    """有界直方图（调用方须持 `_lock`）✓ —— 每键定长 `_BS_NB` 个 int，永不增长 ✓。"""
    h = _BS["h"]
    row = h.get(name)
    if row is None:
        if name not in _BS_ALLOW:
            return
        row = [0] * _BS_NB
        h[name] = row
    try:
        v = float(ms)
    except Exception:
        return
    i = len(_BS_BOUNDS)
    for _i, _b in enumerate(_BS_BOUNDS):
        if v <= _b:
            i = _i
            break
    row[i] += 1


def _bs_snapshot():
    """导出分桶快照（写 stats.json 用）✓ —— 深拷贝，调用方在 `_lock` 内 ✓。"""
    out = {"c": dict(_BS["c"]), "h": dict((k, list(v)) for k, v in _BS["h"].items()),
           "bounds": list(_BS_BOUNDS), "n": _BS_NB, "instr": bool(_BASE_INSTR),
           "sample": bool(_BASE_SAMPLE), "unk": list(_BS["unk"])}
    return out


_BS_SAMPLES = collections.deque(maxlen=max(16, SAMPLE_MAX_ROWS))


def _bs_put(t, el, rc, qt_b, cn_b, entry_b, src_b):
    """有界明细明细环（默认关闭）✓ —— deque(maxlen) ⇒ 超出自动丢最旧，绝不无界落盘 ✓。"""
    try:
        _BS_SAMPLES.append({
            "rid": t.get("id"), "name": t.get("name"), "qt": t.get("qtype"),
            "cn": t.get("cn"), "src": t.get("src"), "rc": rc, "ms": round(el or 0.0, 1),
            "entry": entry_b, "qt_b": qt_b, "cn_b": cn_b, "src_b": src_b,
            "flags": list(t.get("flags") or []),
            "att": [[s, m, e] for s, m, e in (t.get("attempts") or [])]})
    except Exception:
        pass


def _bs_flush():
    """把有界明细环**批量**写盘（仅在 `GUARD_BASE_SAMPLE=1` 时由 stats_writer 调用）✓。

    约束（方案 §1「只添加有界计数和分桶，避免逐查询同步落盘」）：
      · 绝不每请求 write ⇒ 无 I/O 抖动；周期 20s，且只在环里有新行时写 ✓
      · 单次最多写 SAMPLE_MAX_ROWS 行；文件超过 8 MiB 时直接**截断重写**（不追加到无界）✓
      · 任何异常都被吞掉 ⇒ 采集绝不拖垮主服务 ✓
    """
    try:
        n = len(_BS_SAMPLES)
        if n == 0:
            return
        rows = list(_BS_SAMPLES)
        _BS_SAMPLES.clear()
        _sp = _sample_path()
        try:
            if os.path.exists(_sp) and os.path.getsize(_sp) > 8 * 1024 * 1024:
                with open(_sp, "w") as f:
                    f.write("")
        except Exception:
            pass
        with open(_sp, "a") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    except Exception:
        pass



LISTEN_HOST = os.environ.get("GUARD_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("GUARD_PORT", "5355"))
STATE_DIR = os.environ.get("GUARD_STATE_DIR", "/opt/dnsguard")
LOG = os.environ.get("GUARD_LOG", "/var/log/dnsguard.log")
# P34-AQ：CN 准入策略开关（默认 off ⇒ 行为不变 ✓）。放在本行之后的理由：
# 它必须在本模块所有 import 之后求值（上次就是把 os 用在了 import 之前 ✗，被 import 冒烟关卡拦下 ✓）。
# ===== 2026-10-10 P34-AS（方案任务2）：**单调节拍总 deadline** =====
# 方案要求：总 deadline 由 handle() 建立并传给全部子函数；备用/排队**只使用剩余时间**，
# 不能在 domestic() 内重新给每个阶段开启完整预算 ✗（CN 路径历史上各自新开 0.9s/3.0s ✗）。
# 用 time.monotonic ✓（不受墙钟跳变影响），同时留一个墙钟版本给既有 API ✓。
_DL = threading.local()


def _dl_begin():
    d = max(0.5, float(QUERY_DEADLINE))
    _DL.mono = time.monotonic() + d
    _DL.wall = time.time() + d
    # §3 第 67 行：把**唯一 deadline 的单调时刻**同时放进请求上下文 ✓
    # ⇒ 出口汇总/离线审计可以直接读它，而不必依赖 thread-local 是否还在 ✓。
    try:
        _t = _tr()
        if _t.get("id") is not None:
            _t["dl_mono"] = _DL.mono
    except Exception:
        pass
    return d


def _dl_left():
    m = getattr(_DL, "mono", None)
    if not m:
        return None
    try:
        return m - time.monotonic()
    except Exception:
        return None


def _dl_wall(cap):
    """按**剩余**时间给子阶段一个墙钟 deadline（上限 cap）✓。

    ★ 方案 §3 第 67 行：**`left<=0` 必须立即结束** ✗ —— 旧写法 `eff = max(0.15, ...)`
    会在预算耗尽后再"送"0.15 秒 ✗（每一跳都送一点 ⇒ 长尾被逐层堆出来 ✗）。
    现在：`left<=0` ⇒ 返回**当前时刻**（等价于"没有预算"）✓，调用方拿到后
    `deadline - time.time() <= 0` ⇒ 立即走超时/放弃分支 ✓。
    """
    left = _dl_left()
    if left is None:
        return time.time() + float(cap)
    if left <= 0:
        try:
            _stats["dl_exhausted"] = _stats.get("dl_exhausted", 0) + 1
        except Exception:
            pass
        return time.time()          # 零预算 ⇒ 调用方立刻判超时 ✓
    eff = min(float(cap), left)
    if eff < float(cap) - 1e-6:
        try:
            _stats["dl_clamped"] = _stats.get("dl_clamped", 0) + 1
        except Exception:
            pass
    return time.time() + eff


def _dl_rem(cap=None):
    """本次请求的**剩余秒数**（单调源）✓；`cap` 给定时取 `min(cap, left)` ✓。

    ★ 方案 §3 第 67 行：所有 socket wait / Future / join / IPC 只用**剩余预算** ✓。
    与 `_dl_wall()` 的分工：墙钟版给**既有 API**（库函数只吃绝对时刻 ✓），
    本函数给**自建的等待/超时**（直接吃秒数 ✓）。`left<=0` 一律返回 `0.0` ✓
    ⇒ 调用方 `if _dl_rem(x) <= 0:` 即可"立即结束" ✓，不再有隐式下限 ✗。
    """
    left = _dl_left()
    if left is None:
        return float(cap) if cap is not None else None
    if left <= 0:
        try:
            _stats["dl_exhausted"] = _stats.get("dl_exhausted", 0) + 1
        except Exception:
            pass
        return 0.0
    return min(float(cap), left) if cap is not None else left


POLICY_MODE = (os.environ.get("GUARD_POLICY_MODE", "off") or "off").strip().lower() in ("on", "1", "enforce")
# ★ 2026-10-11 §6 第 113/114 行：把**国内认证加密出口**（`unbound-B` = 360 `dot.360.cn` DoT
# + 本机 DNSSEC 校验）在 **CN 域名**下晋升为可采纳**主源** ✓。
#   默认**关** ⇒ 不设该变量时全链路与 release-14 **逐字节相同** ✓（零行为变化 ✓）。
#   依据与裁定门槛见 `_policy_cn_answer()` 内 §6 段落；`_LABEL_MAP["CNB"] = "local-cn"` 给
#   它**独立的诚实来源标签** ✓（审计里"国内 vs 海外"从此可分 ✓）。
CN_DOMESTIC_PRIMARY = _flag("GUARD_CN_DOMESTIC_PRIMARY", False)
CN_DOMESTIC_TRUST_B = _flag("GUARD_CN_DOMESTIC_TRUST_B", False)
# Enable only after Unbound B has ede: yes and ede-serve-expired: yes.
CN_DOMESTIC_ZERO_TTL_ONESHOT = _flag("GUARD_CN_DOMESTIC_ZERO_TTL_ONESHOT", False)
_ADM_CACHE = {}
# §5 第 4 项：与"最多 2000 条"并列的**字节预算**（服务端视角是 16 MiB ✓；生产
# `GUARD_ADM_CACHE_MAX` 仍可保持 4000 ⇒ 两个限额**同时**生效、任一先到即淘汰 ✓）。
# 为什么用 list 而不是 global：与现场既有 `_WEAK_EXPIRE_LAST[0]` / `_QRID[0]` 同风格 ✓
# —— 避免在每个写入点写 `global` ✗（漏一处就会静默变成局部变量 ✗ 难查 ✗）。
_ADM_BYTES = [0]
_ADM_CACHE_MAX = int(os.environ.get("GUARD_ADM_CACHE_MAX", "12000"))
# 方案 §2 第 48/55 行：缓存记录**带 schema 号** ✓ —— 记录结构一变就升号，
# `_adm_cache_get()` 命中时比对；号不一致 ⇒ 当作未命中（**旧 schema 拒绝加载** ✓）。
# 为什么必需：缓存记录是"证据 + 策略"的复合体 ✗，字段语义一旦变化（例如
# `valid_until` 从"相对"改成"绝对"），旧记录被复用就会静默给出错误寿命 ✗ ——
# 报错看不见、答案却是错的 ✗，比任何崩溃都危险 ✗。
_ADM_SCHEMA = int(os.environ.get("GUARD_ADM_SCHEMA", "2"))

UNBOUND = (os.environ.get("GUARD_UNBOUND", "127.0.0.1"), 5353)
UNBOUND_B = (os.environ.get("GUARD_UNBOUND_B", "127.0.0.1"), 5354)   # 加密国内源（360/AliDNS DoT）
# ★ 2026-10-10 §3 完成门夹具需要：A/B 的**端口**也要可注入 ✓ ——
#   夹具用"同宿主、不同端口"的假上游（15951/15952），而生产 A/B 之间的差别
#   **只该是实例**（都是 mvance/unbound 镜像 ✓），所以按端口注入是完全等价的重定向 ✓
#   （不改任何语义、不改报文、不改判定 ✓）。缺省值就是原端口 ⇒ 不设等于没改 ✓。
if os.environ.get("GUARD_UNBOUND_PORT"):
    UNBOUND = (UNBOUND[0], int(os.environ["GUARD_UNBOUND_PORT"]))
if os.environ.get("GUARD_UNBOUND_B_PORT"):
    UNBOUND_B = (UNBOUND_B[0], int(os.environ["GUARD_UNBOUND_B_PORT"]))
_DOQ1 = (os.environ.get("GUARD_DOQ", "127.0.0.1"), int(os.environ.get("GUARD_DOQ_PORT", "5533")))
_DOQ2 = (os.environ.get("GUARD_DOQ2", "127.0.0.1"), int(os.environ.get("GUARD_DOQ2_PORT", "5534")))
# 2026-10-19：第三条本机中继 aghcf → Cloudflare 1.1.1.1（DoT）。默认**不纳入**，
#   需显式 GUARD_DOQ3_ENABLE=1 才追加；关闭时 LOCAL_DOQ_LIST 与改动前逐字节等价（回滚安全）。
_DOQ3 = (os.environ.get("GUARD_DOQ3", "127.0.0.1"), int(os.environ.get("GUARD_DOQ3_PORT", "5535")))
# DoQ2（Quad9 dns10）出现持续 QUIC reset/deadline 时可整条摘除；DoQ1+认证 DoT 仍提供独立干净源。
LOCAL_DOQ_LIST = [_DOQ1] if _flag("GUARD_DISABLE_DOQ2") else [_DOQ1, _DOQ2]
if _flag("GUARD_DOQ3_ENABLE"):
    LOCAL_DOQ_LIST = list(LOCAL_DOQ_LIST) + [_DOQ3]
# [0]=aghdq→NextDNS over QUIC   [1]=aghdq2→Quad9(dns10,无过滤) over QUIC
# [2]=aghcf→Cloudflare 1.1.1.1 over DoT（仅 GUARD_DOQ3_ENABLE=1 时存在）
LOCAL_DOQ = LOCAL_DOQ_LIST[0]
UNBOUND_CONTAINER = os.environ.get("GUARD_UNBOUND_CONTAINER", "unbound")
CHURN_ENABLED = not _flag("GUARD_NO_CHURN")            # 抖动检测开关

STATE = os.path.join(STATE_DIR, "poisoned.json")
DIFF_FILE = os.path.join(STATE_DIR, "diff.json")
BAD_IPS_FILE = os.path.join(STATE_DIR, "bad_ips.json")
CN_FILE = os.path.join(STATE_DIR, "cn_ip.txt")
STATS_FILE = os.path.join(STATE_DIR, "stats.json")
ALLOW_FILE = os.path.join(STATE_DIR, "allow.json")
R8_STABLE_FILE = os.path.join(STATE_DIR, "r8_stable.json")

# 2026-10-09：由 v2fly tld-cn 扩充——原值只有 7 个 ASCII 形式，缺 33 个 IDN(punycode)
# CN TLD（.中国/公司/网络/网址…）与 15 个cn品牌 gTLD。线上查询名是 punycode，故必须用
# punycode 形式匹配。生成脚本 build_veto.py/patch_guard.py，数据留档 /opt/dnsguard/cn_tlds.txt
CN_SUFFIX = (".cn", ".com.cn", ".net.cn", ".org.cn", ".gov.cn", ".edu.cn", ".ac.cn", ".alibaba", ".alipay", ".anquan", ".baidu", ".citic", ".icbc", ".shouji", ".sina", ".sohu", ".taobao", ".tmall", ".unicom", ".weibo", ".xihuan", ".yun", ".xn--9krt00a", ".xn--fiqs8s", ".xn--fiqz9s", ".xn--zfr164b", ".xn--55qw42g", ".xn--55qx5d", ".xn--io0a7i", ".xn--ses554g", ".xn--czru2d", ".xn--hxt814e", ".xn--fiq64b", ".xn--czr694b", ".xn--xhq521b", ".xn--1qqw23a", ".xn--vuq861b", ".xn--kput3i", ".xn--3ds443g", ".xn--fiq228c5hs", ".xn--3bst00m", ".xn--6qq986b3xl", ".xn--czrs0t", ".xn--vhquv", ".xn--fjq720a", ".xn--unup4y", ".xn--g2xx48c", ".xn--imr513n", ".xn--otu796d", ".xn--9et52u", ".xn--6frz82g", ".xn--5tzm5g", ".xn--8y0a063a", ".xn--rhqv96g", ".xn--nyqy26a")
# ★ 2026-10-15 N1（第四份审计）：**路由后缀**与**免见证信任后缀**必须分开 ✗→✓。
#   旧状：`CN_SUFFIX` 同时服务 `is_cn_domain()`（路由偏好）与 `is_cn_trusted()`（免见证授权）⇒
#   集合里 30 多个**中文/通用 punycode TLD**（`.在线`=`xn--3ds443g`、`.世界`=`xn--rhqv96g`、
#   `.公司`=`xn--55qx5d` …）因此自动获得"国内答案免存在性见证"的授权 ✗ ——
#   与 F1 同类的授权范围问题（原来是社区名单扩大权限，现在后缀集合扩大权限）。
#   现在：`CN_SUFFIX` 退回**纯路由**用途（集合内容一字不改 ⇒ 分流偏好不变 ✓）；
#   免见证只看 `CN_TRUST_SUFFIX`（国别/行政区 + 企业品牌 gTLD，2026-10-15 用户拍板范围 B）。
#   结果：`.在线` / `.世界` 这类域仍走国内路由，但默认**必须经过见证** ✓。
CN_TRUST_SUFFIX = (".cn", ".com.cn", ".net.cn", ".org.cn", ".gov.cn", ".edu.cn", ".ac.cn",
                   ".alibaba", ".alipay", ".anquan", ".baidu", ".citic", ".icbc", ".shouji",
                   ".sina", ".sohu", ".taobao", ".tmall", ".unicom", ".weibo", ".xihuan", ".yun")
CN_URL = "https://ispip.clang.cn/all_cn.txt"
CN_DOMAINS_FILE = os.environ.get("GUARD_CN_DOMAINS_FILE", "/opt/dnscrypt-proxy/forwarding-rules.txt")
# CN 域名集合（复用 dnscrypt-proxy 的 CN 分流名单，8837 域）。
# 只用 TLD 后缀（.cn 等）会把 qq.com / taobao.com 这类 ".com 的中国域名"判成"非中国"，
# 使它们的 NXDOMAIN 走境外干净通道比对（实测 +300~560ms）。
_CN_DOMAINS = {"set": set(), "mtime": 0.0, "checked": 0.0}


def _load_cn_domains():
    """载入 CN 域名集合；文件 mtime 变化时重载（最多每 60s 检查一次，跟随每周名单刷新）。"""
    st = _CN_DOMAINS
    now = time.time()
    # 2026-10-05 P0-5：无条件节流（旧写法在空集时门控恒假 → 每个 R2 查询都 stat+全量重读+写日志）
    if now - st["checked"] < 60.0:
        return st["set"]
    st["checked"] = now
    try:
        mt = os.path.getmtime(CN_DOMAINS_FILE)
        if mt != st["mtime"]:
            doms = set()
            skipped = 0
            with open(CN_DOMAINS_FILE, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    d = line.split()[0].strip().lower().rstrip(".")
                    # 2026-10-05 P0-5：拒绝"无点"条目。名单里混着 49 个品牌 gTLD（sohu/baidu/.cn…），
                    # 它们被当成"末标签后缀规则"；若生成器某天输出 com/net/top 这类通用标签，
                    # 会把大半个互联网判成 CN。无点条目一律丢弃（.cn 已由 CN_SUFFIX 覆盖）。
                    if d and "." in d:
                        doms.add(d)
                    elif d:
                        skipped += 1
            prev = len(st["set"])
            st["set"] = doms
            st["mtime"] = mt
            st["logged_fail"] = False
            if len(doms) != prev or skipped:
                log("CN 域名集合已载入: %d 条（丢弃无点条目 %d 个）" % (len(doms), skipped))
    except Exception as e:
        if not st.get("logged_fail"):
            st["logged_fail"] = True
            log("CN 域名集合载入失败（回退为仅 TLD 后缀判据）: %s" % str(e)[:80])
    return st["set"]


# 2026-10-15 F5：**匹配类型化**的 CN 名单（由 refresh-cn-rules.py 生成，可选）。
#   v2fly 三种前缀语义不同：`full:` 只精确匹配、`domain:` 含子域、`suffix:` 是域名后缀。
#   旧链路把三者去前缀后合并，再由 is_cn_domain() 一律按「精确 + 子域」匹配 ⇒
#   `full:host.example` 会连 `child.host.example` 一起判国内；国内 B 是允许直接采纳的
#   信任源，分类范围扩大等于信任范围扩大（审计 F5）。
#   该文件缺失/为空/不可解析 ⇒ 返回 None，调用方回退旧语义（= 与历史发布同行为）。
CN_TYPED_FILE = os.environ.get("GUARD_CN_TYPED_FILE", "/opt/dnscrypt-proxy/cn-domains-typed.txt")

# ★ 2026-10-15 第三份审计 F4：**最后有效的类型化名单快照**。
#   为什么需要：`_load_cn_typed()` 失败时若完全没有数据，历史行为会回退"旧合并语义"
#   （自身 + 所有子域）—— 那会把 `full:host` 的**精确**匹配悄悄放大成**子域**信任 ✗，
#   方向恰好是"扩大国内信任"（审计 F4）。现在改为：live → 快照 → 都没有则**只保留
#   `.cn` 国别后缀**判定，其余判为非国内（走 A/alt 认证源）。
#   快照由 `refresh-cn-rules.py` 在每次成功生成 typed 后同步写出，位置与 live 同目录。
CN_TYPED_SNAPSHOT = os.path.join(os.path.dirname(CN_TYPED_FILE), "cn-domains-typed.snapshot.txt")

# ★ 2026-10-15 第三份审计 F1：**国内可信解析例外清单**（人工维护）。
#   背景：社区名单（v2fly geolocation-cn）会把某些**境外** CDN / 大厂域收进 CN 集合，
#   而本项目把"国内域名走国内 B"与"允许直接采纳 B 的未签名答案"绑成了同一份名单 ⇒
#   这些域名的存在性否定失去核对（`GUARD_CN_DOMESTIC_TRUST_B=1` 时跳过见证；2026-10-15
#   拆分"路由 vs 信任"后，跳过见证只对 `is_cn_trusted()` 通过的域名生效）⇒
#   B 侧的伪造正答案被直接下发给公网客户端（审计实测：zz-*.tiktokcdn-us.com）。
#   本清单把"想走国内路由"和"批准国内可信解析"分开：清单内的域名**不走国内路径**，
#   由境外认证源（A / alt）解析 ⇒ 存在性以权威/独立源为准 ✓。
#   文件缺失或为空 = 无例外（行为与历史一致 ✓，不因此扩大任何信任）。
CN_TRUST_EXC_FILE = os.environ.get(
    "GUARD_CN_TRUST_EXC_FILE", "/opt/dnscrypt-proxy/cn-trust-exceptions.txt")
_CN_TRUST_EXC = {"set": set(), "mtime": 0.0, "checked": 0.0, "loaded": False}

# ★ 2026-10-15：把「国内路由意愿」与「国内可信解析授权」**拆成两份判定**。
#   路由：`is_cn_domain()`（语义不变）⇒ 决定是否优先问国内 B。
#   信任：`is_cn_trusted()`（本段）⇒ 决定 B 的答案能否**免存在性见证**被采纳。
#   为什么拆：社区名单是数千条、每日自动更新、由上游分类决定的"路由偏好"；而"批准国内
#   可信解析"是安全边界。两者同源时，一次分类错误（第三份审计 F1：`tiktokcdn-*` 被判国内）
#   会同时把该域升级成"免见证直采"⇒ 国内上游的污染答案被下发公网。
#   档位 `GUARD_CN_TRUST_MODE`：
#     all   = 兼容旧行为（凡国内路由即免见证，等价于原 TRUST_B 语义）
#     known = 只给「国别后缀 + 人工白名单」免见证，其余国内答案必须过见证 ← 默认
#     none  = 一律需见证（最严；国内无签名域每次多一次见证往返）
CN_TRUST_MODE = (os.environ.get("GUARD_CN_TRUST_MODE", "known") or "known").strip().lower()
if CN_TRUST_MODE not in ("all", "known", "none"):
    CN_TRUST_MODE = "known"
CN_TRUST_ALLOW_FILE = os.environ.get(
    "GUARD_CN_TRUST_ALLOW_FILE", "/opt/dnscrypt-proxy/cn-trust-allow.txt")
_CN_TRUST_ALLOW = {"set": set(), "mtime": 0.0, "checked": 0.0, "loaded": False}


def _load_cn_trust_allow():
    """读「免见证的国内可信解析白名单」（60s 节流 + mtime 热重载）。

    语义：命中（自身或父域，标签边界）⇒ 允许 B 的未签名答案不经见证直接采纳。
    文件不存在 ⇒ 空集（只靠国别后缀），计 `cn_trust_allow_missing`（= 未配置，非故障）。
    """
    st = _CN_TRUST_ALLOW
    now = time.time()
    if st["loaded"] and now - st["checked"] < 60.0:
        return st["set"]
    st["checked"] = now
    try:
        mt = os.path.getmtime(CN_TRUST_ALLOW_FILE)
    except Exception:
        _cn_metric("cn_trust_allow_missing", 1)
        if not st["loaded"]:
            st["set"] = set()
            st["loaded"] = True
            _cn_metric("cn_trust_allow_entries", 0)
        return st["set"]
    if st["loaded"] and mt == st["mtime"]:
        return st["set"]
    doms = set()
    try:
        with open(CN_TRUST_ALLOW_FILE, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                d = line.split()[0].strip().lower().rstrip(".")
                if d and "." in d:
                    doms.add(d)
    except Exception as e:
        _cn_note_fail("cn_trust_allow")
        log("CN 信任白名单读取失败（按空集继续 ⇒ 仅国别后缀免见证）: %s" % str(e)[:80])
        return st["set"]
    st["set"] = doms
    st["mtime"] = mt
    st["loaded"] = True
    _cn_metric("cn_trust_allow_missing", 0)
    _cn_metric("cn_trust_allow_entries", len(doms))
    _cn_metric("cn_trust_allow_loaded_ts", int(now))
    log("CN 信任白名单已载入: %d 条（免见证直采）；模式=%s" % (len(doms), CN_TRUST_MODE))
    _cn_gen_set("trust", CN_TRUST_ALLOW_FILE, len(doms))
    return st["set"]


def _in_cn_trust_allow(n):
    """自身或任一父域命中白名单 ⇒ True（标签边界，不做裸 endswith）。"""
    if not n:
        return False
    allow = _load_cn_trust_allow()
    if not allow:
        return False
    if n in allow:
        return True
    parts = n.split(".")
    for i in range(1, len(parts)):
        if ".".join(parts[i:]) in allow:
            return True
    return False


def is_cn_trusted(name):
    """B 的答案能否**免存在性见证**被采纳（信任判定，与路由判定分开）。

    优先级：例外清单（安全兜底，最高）→ 必须先是国内路由 → 国别后缀 → 人工白名单 → 档位默认。
    """
    if not name:
        return False
    n = name.strip().lower().rstrip(".")
    if _in_cn_trust_exc(n):
        _cn_bump("cn_trust_class_exception")
        return False
    if not is_cn_domain(n):
        return False
    if CN_TRUST_MODE == "none":
        # 最严档：连国别后缀也要求见证（极端收紧 / 演练用）
        _cn_bump("cn_trust_class_witness")
        return False
    if n.endswith(CN_TRUST_SUFFIX):
        _cn_bump("cn_trust_class_suffix")
        return True
    if _in_cn_trust_allow(n):
        _cn_bump("cn_trust_class_allow")
        return True
    if CN_TRUST_MODE == "all":
        _cn_bump("cn_trust_class_mode_all")
        return True
    _cn_bump("cn_trust_class_witness")
    return False

# ★ 2026-10-15 第三份审计 F2：**名单代次**。
#   问题：`POLICY_VERSION` 是静态字符串，准入缓存只核对它 + TTL ⇒ 把域名移出国内信任集合
#   之后，此前按旧分类写入的准入缓存仍会继续命中（错误答案继续下发 ✗）。
#   做法：typed / veto / 例外三份名单各自记录**内容指纹**（sha256 前 16 位），拼成
#   `_cn_gen_id()` 写进每条准入缓存；命中时比对不一致即视为未命中（结构上保证，
#   不依赖"清理是否跑到了"）。名单大小不同 ⇒ 代次必然不同 ✓。
_CN_GEN = {"typed": "", "veto": "", "exc": "", "trust": ""}


def _cn_gen_from_file(path):
    """文件内容指纹（sha256 前 16 位）；不可读 ⇒ 空串。"""
    try:
        import hashlib
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 16), b""):
                h.update(chunk)
        return h.hexdigest()[:16]
    except Exception:
        return ""


def _cn_gen_id():
    return "%s|%s|%s|%s" % (_CN_GEN["typed"] or "-", _CN_GEN["veto"] or "-",
                             _CN_GEN["exc"] or "-", _CN_GEN["trust"] or "-")


def _cn_gen_set(which, path, entries):
    """名单成功载入后更新代次；变化时计数并留痕（准入缓存靠代次比对自动失效）。"""
    try:
        gen = _cn_gen_from_file(path)
        old = _CN_GEN.get(which, "")
        _CN_GEN[which] = gen
        if not gen or gen == old:
            return
        _cn_bump("cn_list_gen_change")
        _cn_bump("cn_list_gen_change_" + str(which))
        log("CN 名单代次变化: %s %s → %s（%s 条）⇒ 准入缓存按代次自动失效"
            % (which, old or "-", gen, entries))
        if which == "exc":
            _cn_bump("cn_exc_change_needs_agh_flush")
            log("CN 例外清单已变化 ⇒ guard 侧缓存按代次自动失效；"
                "AGH 侧缓存需在面板「清除缓存」或跑 flush-agh-cache.sh 才立即生效（否则等 TTL）")
    except Exception:
        pass


def _cn_bump(key, n=1):
    """累计型计数（本次运行内次数），与 `_cn_metric` 的"状态量"区分开。"""
    try:
        if key in _stats:
            _stats[key] = _stats.get(key, 0) + int(n)
    except Exception:
        pass


def _load_cn_trust_exc():
    """读国内可信解析例外清单（60s 节流 + mtime 热重载）。

    语义：命中 ⇒ `is_cn_domain()` 立即判"非国内"（优先于 .cn 后缀与 typed 名单）
    ⇒ 该域名走 A/alt 认证源，B 的答案不参与采纳 ✓。
    """
    st = _CN_TRUST_EXC
    now = time.time()
    if st["loaded"] and now - st["checked"] < 60.0:
        return st["set"]
    st["checked"] = now
    try:
        mt = os.path.getmtime(CN_TRUST_EXC_FILE)
    except Exception:
        # 文件不存在：明确计"未配置"，而不是"载入失败" —— 语义是"没有例外"
        _cn_metric("cn_trust_exc_missing", 1)
        if not st["loaded"]:
            st["set"] = set()
            st["loaded"] = True
            _cn_metric("cn_trust_exc_entries", 0)
        return st["set"]
    if st["loaded"] and mt == st["mtime"]:
        return st["set"]
    doms = set()
    try:
        with open(CN_TRUST_EXC_FILE, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                d = line.split()[0].strip().lower().rstrip(".")
                if d and "." in d:
                    doms.add(d)
    except Exception as e:
        _cn_note_fail("cn_trust_exc")
        log("CN 例外清单读取失败（按无例外继续）: %s" % str(e)[:80])
        return st["set"]
    st["set"] = doms
    st["mtime"] = mt
    st["loaded"] = True
    _cn_metric("cn_trust_exc_missing", 0)
    _cn_metric("cn_trust_exc_entries", len(doms))
    _cn_metric("cn_trust_exc_loaded_ts", int(now))
    log("CN 国内信任例外清单已载入: %d 条" % len(doms))
    _cn_gen_set("exc", CN_TRUST_EXC_FILE, len(doms))
    return st["set"]


def _in_cn_trust_exc(n):
    """自身或任一父域命中例外清单 ⇒ True（标签边界，不做裸 endswith）。"""
    if not n:
        return False
    exc = _load_cn_trust_exc()
    if not exc:
        return False
    if n in exc:
        return True
    parts = n.split(".")
    for i in range(1, len(parts)):
        if ".".join(parts[i:]) in exc:
            return True
    return False

_CN_TYPED = {"data": None, "mtime": 0.0, "checked": 0.0, "logged_fail": False}
_CN_TYPE_ALIAS = {"full": "full", "exact": "full", "domain": "domain",
                  "suffix": "suffix", "sfx": "suffix"}


# 2026-10-15 用户要求：**名单载入必须可观测**。原先 typed / veto 只在载入那一刻打一行
# 日志 ⇒ 线上无法回答"当前生效的名单有多大、什么时候载入的、失败过几次"。
# 指标写进 `_stats` ⇒ 自动进 stats.json（20s 周期）与 --status 看板 ✓。
# 全部按 §6（见文末 `_cn_list_keys`）**每次启动归零**：它们是"当前状态量"，不是累计次数。
def _cn_metric(key, value):
    try:
        if key in _stats:
            _stats[key] = value
    except Exception:
        pass


def _cn_note_fail(prefix):
    try:
        k = prefix + "_fail"
        if k in _stats:
            _stats[k] = _stats.get(k, 0) + 1
    except Exception:
        pass


def _cn_typed_snapshot_fallback(st, now):
    """★ 第三份审计 F4：live typed 不可用 ⇒ 用**发布快照**（由 refresh-cn-rules.py 每次
    成功生成后同步写出）。快照也没有 ⇒ 保持 None，调用方判"非国内"（绝不回退旧宽匹配：
    旧语义会把 `full:host` 的精确匹配放大成子域信任，方向是扩大国内信任）。"""
    try:
        if not os.path.exists(CN_TYPED_SNAPSHOT):
            return None
        snap = {"full": set(), "domain": set(), "suffix": set()}
        with open(CN_TYPED_SNAPSHOT, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                kind, sep, dom = line.partition(":")
                if not sep:
                    kind, dom = "domain", kind
                kind = _CN_TYPE_ALIAS.get(kind.strip().lower())
                if not kind:
                    continue
                dom = dom.strip().lower().rstrip(".")
                if dom and "." in dom:
                    snap[kind].add(dom)
        if not (snap["full"] or snap["domain"] or snap["suffix"]):
            return None
        st["data"] = snap
        _cn_bump("cn_typed_snapshot_used")
        _cn_metric("cn_typed_full", len(snap["full"]))
        _cn_metric("cn_typed_domain", len(snap["domain"]))
        _cn_metric("cn_typed_suffix", len(snap["suffix"]))
        _cn_metric("cn_typed_total", len(snap["full"] | snap["domain"] | snap["suffix"]))
        _cn_metric("cn_typed_active", 1)
        _cn_metric("cn_typed_loaded_ts", int(now))
        log("CN 类型化名单已用发布快照回退: full=%d domain=%d suffix=%d"
            % (len(snap["full"]), len(snap["domain"]), len(snap["suffix"])))
        return snap
    except Exception as _es:
        log("CN 类型化快照亦不可用: %s" % str(_es)[:80])
        return None


def _load_cn_typed():
    """按 60s 节流读类型化名单；不可用 ⇒ None（调用方回退旧语义）。"""
    st = _CN_TYPED
    now = time.time()
    if now - st["checked"] < 60.0:
        return st["data"]
    st["checked"] = now
    try:
        mt = os.path.getmtime(CN_TYPED_FILE)
    except Exception:
        # 文件不存在/不可读也要计数：否则线上无法区分"刷新器还没生成"与"生成坏了"
        _cn_note_fail("cn_typed")
        _cn_metric("cn_typed_active", 0)
        # ★ 第三份审计 F4：**冷启动最常见路径**（文件还没生成）同样优先用发布快照
        if st["data"] is None:
            _cn_typed_snapshot_fallback(st, now)
        return st["data"]
    if mt == st["mtime"]:
        return st["data"]
    sets = {"full": set(), "domain": set(), "suffix": set()}
    try:
        with open(CN_TYPED_FILE, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                kind, sep, dom = line.partition(":")
                if not sep:
                    kind, dom = "domain", kind       # 无类型标记 ⇒ 保守按 domain（= 旧行为）
                kind = _CN_TYPE_ALIAS.get(kind.strip().lower())
                if not kind:
                    continue
                dom = dom.strip().lower().rstrip(".")
                if dom and "." in dom:               # 无点条目一律丢弃（同 _load_cn_domains）
                    sets[kind].add(dom)
        if not (sets["full"] or sets["domain"] or sets["suffix"]):
            raise ValueError("empty typed CN list")
    except Exception as e:
        _cn_note_fail("cn_typed")
        _cn_metric("cn_typed_active", 0)
        if not st.get("logged_fail"):
            st["logged_fail"] = True
            log("CN 类型化名单不可用（试发布快照）: %s" % str(e)[:80])
        # ★ 第三份审计 F4：解析失败/空文件 ⇒ 同样用发布快照，而不是回退宽匹配。
        if st["data"] is None:
            _cn_typed_snapshot_fallback(st, now)
        return st["data"]
    st["data"] = sets
    st["mtime"] = mt
    st["logged_fail"] = False
    _cn_gen_set("typed", CN_TYPED_FILE, len(sets["full"] | sets["domain"] | sets["suffix"]))
    _cn_metric("cn_typed_full", len(sets["full"]))
    _cn_metric("cn_typed_domain", len(sets["domain"]))
    _cn_metric("cn_typed_suffix", len(sets["suffix"]))
    _cn_metric("cn_typed_total", len(sets["full"] | sets["domain"] | sets["suffix"]))
    _cn_metric("cn_typed_active", 1)
    _cn_metric("cn_typed_loaded_ts", int(now))
    log("CN 类型化名单已载入: full=%d domain=%d suffix=%d"
        % (len(sets["full"]), len(sets["domain"]), len(sets["suffix"])))
    return st["data"]


def _match_cn_typed(n, sets):
    """按类型语义匹配：full 精确；domain 自身 + 子域；suffix 按标签边界匹配后缀。

    suffix 取「自身或父域 == 后缀」而不是裸字符串 endswith ⇒ 比 v2fly 原义更保守
    （`evilx.com` 不会因 `x.com` 被误判国内），方向是"不扩大国内信任"（审计 F5）。
    """
    if n in sets["full"] or n in sets["domain"] or n in sets["suffix"]:
        return True
    parts = n.split(".")
    for i in range(1, len(parts)):
        p = ".".join(parts[i:])
        if p in sets["domain"] or p in sets["suffix"]:
            return True
    return False


# 2026-10-09：CN 路径「否决名单」。
# 来源 v2fly geolocation-!cn（递归展开 include），语义是"地理位置在中国之外"。
# 用途：即便域名后缀命中 CN 规则，也不走国内 unbound-b 路径——对应本项目已记录的
# "把境外站点判成 CN 会丢失 CDN 就近入口"的风险。文件 mtime 变化时 60s 内热重载。
CN_VETO_FILE = os.environ.get("GUARD_CN_VETO_FILE", "/opt/dnsguard/cn_veto.txt")
# 2026-10-15 第三份审计 F4（veto 侧一致性）：**先读 live 目录的快照**（由
#   refresh-cn-veto-ip.py 在自检通过后维护），发布目录快照降为二级回退。
#   原因：发布时固定的快照会随名单演进落后 —— 否决条目变少 ⇒ 否决面变窄
#   ⇒ 反而扩大国内信任，方向与 F4 要求相反。
CN_VETO_SNAPSHOT = os.environ.get("GUARD_CN_VETO_SNAPSHOT", "") or \
    os.path.join(os.path.dirname(os.path.abspath(CN_VETO_FILE)), "cn-veto.snapshot.txt")
CN_VETO_SNAPSHOT_REL = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "cn-veto.snapshot.txt")

# 2026-10-09 B2/B3：**本地通道堵塞**（不是解析失败）时的应答形态。
#   与"上游真实 SERVFAIL"区分开，并让这类应答尽量**不被下游缓存**。
#   GUARD_OVERLOAD_RCODE: 2=SERVFAIL(默认，最兼容) / 5=REFUSED(语义更准：本机容量不足)
#   GUARD_OVERLOAD_EDE:   RFC8914 信息码（默认 22=No Reachable Authority；0=不附加）
OVERLOAD_RCODE = int(os.environ.get("GUARD_OVERLOAD_RCODE", "2"))
OVERLOAD_EDE = int(os.environ.get("GUARD_OVERLOAD_EDE", "22"))
_CN_VETO = {"set": set(), "mtime": 0.0, "checked": 0.0}


def _load_cn_veto():
    st = _CN_VETO
    now = time.time()
    if now - st["checked"] < 60.0 and st.get("set"):
        return st["set"]
    st["checked"] = now
    try:
        mt = os.path.getmtime(CN_VETO_FILE)
        if mt != st["mtime"]:
            doms = set()
            with open(CN_VETO_FILE, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    d = line.split()[0].strip().lower().rstrip(".")
                    if d and "." in d:
                        doms.add(d)
            if not doms:
                raise ValueError("empty CN veto policy")
            st["set"] = doms
            st["mtime"] = mt
            _cn_metric("cn_veto_entries", len(doms))
            _cn_metric("cn_veto_loaded_ts", int(now))
            _cn_gen_set("veto", CN_VETO_FILE, len(doms))
            log("CN 令牌否决名单已载入: %d 条" % len(doms))
    except Exception as e:
        _cn_note_fail("cn_veto")
        if not st.get("logged_fail"):
            st["logged_fail"] = True
            log("CN veto live policy unavailable; using last-good/release snapshot: %s" % str(e)[:80])
        if not st["set"]:
            # 2026-10-15 第三份审计 F4（veto 侧）：live 快照优先，发布快照兜底。
            _cands = []
            for _p in (CN_VETO_SNAPSHOT, CN_VETO_SNAPSHOT_REL):
                if _p and os.path.abspath(_p) not in _cands:
                    _cands.append(os.path.abspath(_p))
            for _p in _cands:
                try:
                    with open(_p, encoding="utf-8") as f:
                        doms = set(line.split()[0].lower().rstrip(".") for line in f
                                   if line.strip() and not line.lstrip().startswith("#"))
                    if not doms or any("." not in d for d in doms):
                        raise ValueError("invalid CN veto snapshot")
                    st["set"] = doms
                    _cn_metric("cn_veto_entries", len(doms))
                    _cn_metric("cn_veto_loaded_ts", int(now))
                    log("CN veto snapshot loaded: %d entries (%s)" % (len(doms), _p))
                    break
                except Exception:
                    continue
            if not st["set"]:
                # None means policy unavailable; callers must veto CN trust.
                return None
    return st["set"] or None


def refresh_cn_list_metrics():
    """把 CN 名单的「当前生效规模」重新写进 `_stats`（幂等、纯本地读、无网络）。

    为什么必须单独一步：`load_counters()` 会把 `PERSIST_SKIP` 内的键归零，而 veto 的
    启动守卫是在**模块导入时**执行的（早于 `__main__` 里的 `load_counters()`）⇒ 守卫
    阶段写入的 `cn_veto_entries` 会被抹成 0（2026-10-15 线上实测：日志已载入 2167 条，
    stats.json 里却是 0）。此函数在 `load_counters()` 之后重放一次载入，让指标与真实
    生效的名单一致。

    强制的两处：`checked=0` 绕开 60s 节流、`mtime=0` 绕开「文件没变就直接返回缓存」
    的短路 —— 否则载入会直接返回而不写指标。
    """
    for _st, _loader in ((_CN_TYPED, _load_cn_typed), (_CN_VETO, _load_cn_veto)):
        try:
            _st["checked"] = 0.0
            _st["mtime"] = 0.0
            _loader()
        except Exception:
            pass
    try:
        _CN_TRUST_EXC["checked"] = 0.0
        _CN_TRUST_EXC["mtime"] = 0.0
        _load_cn_trust_exc()
    except Exception:
        pass
    try:
        _CN_TRUST_ALLOW["checked"] = 0.0
        _CN_TRUST_ALLOW["mtime"] = 0.0
        _load_cn_trust_allow()
    except Exception:
        pass
    try:
        # cn_ip.txt：只在 mtime 确实变化时重解析（绝不触发下载，见 load_cn_nets 注释）
        if os.path.exists(CN_FILE) and os.path.getmtime(CN_FILE) != _CN_NETS_CHK["mtime"]:
            _CN_NETS_CHK["checked"] = 0.0
            load_cn_nets()
    except Exception:
        pass


def _in_cn_veto(n):
    veto = _load_cn_veto()
    if veto is None:
        return True
    if not veto:
        return False
    if n in veto:
        return True
    parts = n.split(".")
    for i in range(1, len(parts)):
        if ".".join(parts[i:]) in veto:
            return True
    return False


def is_cn_domain(name):
    """是否中国域名：TLD 后缀命中，或落在 CN 域名集合中。

    2026-10-15 F5：名单条目按 v2fly 原匹配类型分别判定（见 `_load_cn_typed`）；
    类型化名单不可用时回退旧语义（精确 + 子域，与历史行为一致）。
    """
    if not name:
        return False
    n = name.strip().lower().rstrip(".")
    # ★ 2026-10-15 第三份审计 F1：**国内可信解析例外优先**（优先于 .cn 后缀与 typed 名单）
    #   命中 ⇒ 该域名不走国内 B 路径（改由境外认证源解析，存在性以权威/独立源为准）。
    if _in_cn_trust_exc(n):
        _cn_bump("cn_dom_exception")
        return False
    # 2026-10-09：否决优先——境外服务即便后缀像 CN，也不走 CN 路径
    if _in_cn_veto(n):
        return False
    if n.endswith(CN_SUFFIX):
        return True
    typed = _load_cn_typed()
    if typed is not None:
        return _match_cn_typed(n, typed)
    # ★ 2026-10-15 第三份审计 F4：typed 不可用（且无发布快照）时**不再回退旧合并语义**。
    #   旧语义对每个条目都做"自身 + 所有子域"匹配 ⇒ 冷启动失败会把 `full:host` 的精确
    #   匹配悄悄放大成子域信任（方向是扩大国内信任）。现在只保留上面的 `.cn` 国别后缀、
    #   例外与 veto 判定，其余判为"非国内" ⇒ 走 A/alt 认证源（可用性略降、信任不扩大）。
    _cn_bump("cn_typed_fallback_denied")
    return False

DIFF_MAX = 300

# P34-AW（方案任务3）：**Mullvad 已从运营方列表移除** ✓ ——
#   其官方公告 2026-11-02 停止公共加密 DNS；方案要求"两家替代验证后再移除、且不能只禁 verifier ✗"。
#   替代的两家（Digitale Gesellschaft / UncensoredDNS）已在任务1 的 unbound-alt 上完成本地验证 ✓。
#   注意：本改动只作用于**发布版**；生产仍保留原列表，直到按方案完成切换验收为止 ✓。
CLEAN_DOT_ALL = [("89.233.43.71", 853, "unicast.censurfridns.dk"),
             ("185.95.218.42", 853, "dns.digitale-gesellschaft.ch")]
# 高负载下可将高 RTT 认证通道降为最后兜底；默认保留全部通道。
CLEAN_DOT = [x for x in CLEAN_DOT_ALL if not (_flag("GUARD_DISABLE_MULLVAD") and x[2] == "base.dns.mullvad.net")]

TIMEOUT = 2.0          # 干净 DoT 单次超时（对冲：HEDGE_MS 后并发其余上游）
DOM_TIMEOUT = 1.2      # 国内 unbound A/B 单次超时；同步路径总预算 < AGH 的 5s
# 首次向 Unbound A 取数默认携带 DO=1，确保本机验证器可以直接返回 AD=1。
# 仍保留环境开关，便于出现兼容性问题时快速回退到原始查询格式。
DOMESTIC_DO = _flag("GUARD_DOMESTIC_DO", True)
# 2026-10-07 二档·第10步：unbound B **只服务 CN 域名**（CN 的国内出口/兜底），并用更紧的截止时间。
# 依据：B 是全链路最慢的一环（实测递归中位 584ms、队列峰值 1415、队列覆写 187 次），
# 让它同时充当"非 CN 兜底/比较源"会污染同步核对的对照口径，也会拖长同步路径。
B_TIMEOUT = float(os.environ.get("GUARD_B_TIMEOUT", "0.9"))
# R8 同步单路核对（P0-A）：明文递归是唯一可注入路径，加密通道不可注入。
# GUARD_NO_CORROB=1 可整体关闭；CORROB_TTL 为核对结果的信任窗口上限（还会被应答 TTL 收紧）。
CORROB_ENABLED = not _flag("GUARD_NO_CORROB")
# 2026-10-10 Patch14：CN-IP 面的门控档位。默认 off = 今天行为（零变化）。
#   off / observe（照做核对但不改道）/ enforce（完整 R8 语义）
CNIP_MODE = (os.environ.get("GUARD_CNIP_MODE", "off") or "off").strip().lower()
if CNIP_MODE not in ("off", "observe", "enforce"):
    CNIP_MODE = "off"
CORROB_TTL = float(os.environ.get("GUARD_CORROB_TTL", "300"))
CORROB_ONESHOT_TIMEOUT = float(os.environ.get("GUARD_CORROB_TIMEOUT", "0.5"))
# 2026-10-05 加固（G-7）：核对权威必须来自带证书校验的 DoT 通道。
#   "dot"=只用境外 DoT（认证）；"any"=旧行为（本机明文 UDP DoQ 中继也可作准，仅排障用）
CORROB_AUTH = os.environ.get("GUARD_CORROB_AUTH", "dot")
CORROB_DOT_TIMEOUT = float(os.environ.get("GUARD_CORROB_DOT_TIMEOUT", "2.0"))
# 2026-10-07：R8 去重锁的**有界**等待上限。原来是无限等 —— 持锁线程一卡，等待者就
# 一直占着 inflight 名额，最终把执行器名额耗光。超时后返回明确的 TIMEOUT 状态。
CORROB_DEDUP_WAIT = float(os.environ.get("GUARD_CORROB_DEDUP_WAIT", "1.0"))
# ★ 2026-10-18 批次 4：明文递归与 R8 核对**并发**发起（sum → max）。
#   默认**关闭**（=今天行为），改法见 `_r8p_start()` 的守卫注释。
_R8P_ENABLED = _flag("GUARD_R8_PARALLEL", False)
_R8P_MAX = max(1, int(os.environ.get("GUARD_R8_PARALLEL_MAX", "8")))
# 2026-10-05 P1-8：实测本机**没有更快的认证通道可加**（quad9/cloudflare/adguard 的 DoT 全部
# timeout/reset），现有三条冷握手 606~709ms + 单程 RTT ~900ms，1.5s 预算偏紧（auth_none≈11.6%），
# 故放宽到 2.0s。总时长由下面的 SYNC_BUDGET 兜住。
# 2026-10-05 P1-6：同步路径 wall-clock 闸门。实测曾出现 AGH 侧 4 次 ≥10s 的上游超时
# （与当时两个跑满 CPU 的遗留进程同窗口）。超过预算就跳过 R8 核对、保留明文答案并计数，
# 保证 guard 的应答不会拖到 AGH 的 upstream_timeout(5s) 之外。
SYNC_BUDGET = float(os.environ.get("GUARD_SYNC_BUDGET", "1.8"))
# 2026-10-05：CN 域名的 A/B 两级源改为**并发**发出（旧的串行 A→B 在 NODATA 时最坏要等
# 2×DOM_TIMEOUT，实测冷 CN 查询 p50 2.2s）。置空可退回串行。
CN_OVERLAP = _flag("GUARD_CN_OVERLAP", True)
# AAAA 不一致时是否改道（默认只检测+告警，避免国内服务 V6 被换成境外边缘）
CORROB_V6 = _flag("GUARD_CORROB_V6")
# 干净侧有应答但无地址（NODATA/NXDOMAIN）时是否 fail-closed（默认只告警）
CORROB_STRICT_NODATA = _flag("GUARD_CORROB_STRICT_NODATA")
# 严格 R8：核对通道不可用或同步预算耗尽时，不接受未核对的境外 A/AAAA 明文。
CORROB_STRICT_FAIL_CLOSED = _flag("GUARD_CORROB_STRICT_FAIL_CLOSED")
# 2026-10-28 R-2（fail-open 收敛）：核对未成功但**保留明文**时，把该答案各 RR 的 TTL
# 截断到本上限 —— 只压"无证据答案"在下游缓存里的滞留窗口（策略上限 <=900s -> 分钟级），
# **不改变是否返回答案**（仍是 fail-open）、不降低 DNSSEC 与多源核对强度。
# 置 0 则完全退回旧行为（不截断）。
FAILOPEN_TTL_CAP = float(os.environ.get("GUARD_FAILOPEN_TTL_CAP", "60"))


def _failopen_cap_ttl(wire):
    """R-2（2026-10-28）：**核对无证据却仍下发明文**时的答案 TTL 收口。

    语义边界（务必保持）：
      · **不改变"是否下发"** —— fail-open 依然生效（可用性优先，见 R8M / R8K 两个出口）；
      · **只压缩寿命** —— 把这份未核对的明文在下游缓存里的滞留窗口，从策略上限
        （ACCEPT_MAX_TTL<=900s / ACCEPTED_MAX_TTL<=300s）压到 FAILOPEN_TTL_CAP（默认 60s）
        ⇒ 万一它是投毒答案，污染自愈时间从十几分钟降到一分钟级；
      · **不改 DNSSEC / 多源核对强度** —— 没有任何判定分支被这条收口影响。

    实现复用 alt_adapter.age_wire(elapsed=0, max_ttl=cap)：逐 RR 原地改写 4 字节、
    报文长度不变 ⇒ 所有压缩指针仍逐字节有效；OPT(41) 不参与（其字段不是寿命）；
    解析失败原样返回 ⇒ 不可能产出畸形报文。任何异常都退回原报文（绝不让收口变成故障）。
    """
    if FAILOPEN_TTL_CAP <= 0:
        return wire
    try:
        import alt_adapter as _ALT_C
        out = bytes(_ALT_C.age_wire(wire, 0, max_ttl=FAILOPEN_TTL_CAP))
    except Exception:
        return wire
    try:
        with _lock:
            _stats["failopen_ttl_capped"] = _stats.get("failopen_ttl_capped", 0) + 1
    except Exception:
        pass
    return out
CERT_TIMEOUT = 2.5
CHURN_GAP = 60         # 全局抖动检测最小间隔（秒），避免频繁清缓存
# 2026-10-09 P4：R5 改候选队列。需两个独立窗口（间隔 R5_WINDOW_MIN~MAX），只进人工队列。
R5_WINDOW_MIN = 600    # 两个窗口最小间隔（10 分钟）
R5_WINDOW_MAX = 1800   # 超过则丢弃候选（30 分钟）
R5_SCHED_TICK = 90     # 调度器扫描间隔（秒）
R5_FILE = os.path.join(STATE_DIR, "r5_candidates.json")
_R5_PENDING = {}       # name -> [{"ts","us","cs","uips","cips"}, ...]
_R5_CAT_CRL = ("crl", "ocsp", "lencr", "letsencrypt")
_R5_CAT_NTP = ("ntp", "pool.ntp", "time.", ".pool.")
_R5_CAT_CDN = ("cdn", "edge", "akadns", "akamai", "cloudfront", "fastly", "gstatic",
               "googlevideo", "appsflyer", "metric", "aaplimg", "llnwd", "wsdvs",
               "edgekey", "akamaiedge", "hinet", "hichina")
REVERIFY_AFTER = 6 * 3600   # 同一域名多久后允许重新后台核验

# 2026-10-09 问题2修复：投毒黑名单**证据分级**。
# 背景（实测）：676 条里 657 条 hits=1；其中 R2「我方 unbound 无地址而干净上游有」与
# R5「多采样抖动」本质是**我们自己的瞬时失败 / CDN 抖动**，却被当作永久投毒 ⇒
#   ① CN 域名被夺走国内出口（www.qq.com 等改走境外干净通道）
#   ② 干净通道不可用即 fail-closed SERVFAIL（24h 1,073 次，其中 www.qq.com 72 次）
# 分级（用户定：**只按证据类型**，不按观察次数）：
#   strong = R1(命中已知注入地址) / R4(CNAME 链被替换) / R6(证书对照不匹配) / 人工确认
#   weak   = R2(我方失败) / R5(多采样抖动) / 其它未知
# 路由：strong 维持"干净唯一 + 失败 fail-closed"（CN 域名改为干净+B 双路）；
#        weak 改为"优先干净、失败**回落普通路径**"（不再 fail-closed）。
POISON_STRONG_PREFIX = ("R1 ", "R4 ", "R6 ", "人工确认")
WEAK_TTL = 3 * 86400            # 弱证据 3 天未再观察 ⇒ 过期移出（转入待确认清单）
WEAK_EXPIRE_INTERVAL = 1800     # 过期扫描节流（秒）
_WEAK_EXPIRE_LAST = [0.0]

# ---- 干净上游竞速：先起本机 DoQ 转发器（实测 22~48ms），HEDGE_MS 内没答案再并发境外 DoT ----
HEDGE_MS = int(os.environ.get("GUARD_HEDGE_MS", "300"))
TOTAL_BUDGET = float(os.environ.get("GUARD_TOTAL_BUDGET", "2.0"))
# 2026-10-07：**整查询**硬上限。R8 在进入核对前用它算"还剩多少额度"，并把核对等待压进剩余额度，
# 保证 guard 的应答一定在 AGH 的 upstream_timeout(5s) 以内返回。
# 默认沿用 TOTAL_BUDGET；实测 TOTAL_BUDGET 原本只钳 _dot_query_once（干净通道取答案），
# **不钳 R8 核对**（核对走 _corrob_query_once → _upstream_call，窗口由 CORROB_DOT_TIMEOUT 决定），
# 所以这里必须单独给一个整查询额度，否则 SYNC_BUDGET 只在进入前查一次、进去还能再跑满一次。
QUERY_DEADLINE = float(os.environ.get("GUARD_QUERY_DEADLINE", str(TOTAL_BUDGET)))
COLD_MAX = int(os.environ.get("GUARD_COLD_MAX", "16"))
# ---- R3（已知投毒域名）优先要"带地址"的答案；空答案再多等 GRACE_MS 看有没有带地址的通道 ----
ADDR_GRACE_MS = int(os.environ.get("GUARD_ADDR_GRACE_MS", "120"))
# ---- 干净通道保活：定期热身，避免空闲后首查付 1.0~1.2s 的 TCP+TLS 冷启动；同时记录各通道 RTT ----
KEEPALIVE_S = int(os.environ.get("GUARD_KEEPALIVE_S", "45"))

# ---- 精确已知注入地址（历史与近期实测命中）----
POISON_IPS = {"46.82.174.68", "59.24.3.173", "78.16.49.15", "159.106.121.75", "8.7.198.45",
              "203.98.7.65", "243.185.187.39", "37.61.54.158", "93.46.8.89", "4.36.66.178",
              "64.33.88.161", "203.161.230.171", "8.7.198.46", "59.24.3.174", "46.82.174.69",
              "93.46.8.90", "2001::1", "180.163.151.162", "157.240.7.20", "31.13.92.37"}


def _norm_ip(ip):
    """IPv6 规范化后再比较。

    parse_a 把 IPv6 写成 "2001:0:0:0:0:0:0:1"，而 POISON_IPS 里写的是 "2001::1"，
    直接字符串比较永远不相等 —— 实测 GFW 现在仍在给 google 系域名的 AAAA 注入 2001::1，
    这条洞会让未在判定表内的域名直接把注入地址放给客户端。"""
    # 2026-10-10 Patch15（Codex P3）：`_strict_probe_once` 会把 `_norm_ip` 的输出放进集合并
    # 交给 `corrob_put`；若传进来的是 bytes（上游/集合回灌），`":" not in ip` 会抛 TypeError。
    if isinstance(ip, bytes):
        with _lock:
            _stats["norm_ip_bytes"] = _stats.get("norm_ip_bytes", 0) + 1
        return ip
    if not isinstance(ip, str):
        return ip
    if ":" not in ip:
        return ip
    try:
        return socket.inet_pton(socket.AF_INET6, ip)
    except Exception:
        return ip


_POISON_IPS_NORM = {_norm_ip(x) for x in POISON_IPS}

# ---- 大厂跨族段：同步判据，带归属豁免 ----
RANGE_HINTS = [("31.13.0.0", 16, "meta"), ("157.240.0.0", 16, "meta"), ("179.60.0.0", 16, "meta"),
               ("185.60.0.0", 16, "meta"), ("69.63.176.0", 20, "meta"),
               # 2026-10-05 移除 ("192.179.0.0", 16, "meta")：RDAP 实证该段属 GOOGLE(NET-192-178-0-0-1,
               # 192.178.0.0-192.179.255.255)，误标 meta 会把 storage.googleapis.com 等 Google 域名
               # 判成"跨族注入"并自动拉黑（已实际发生）。
               
               ("104.244.40.0", 21, "twitter"), ("199.59.148.0", 22, "twitter"),
               ("108.160.160.0", 19, "dropbox")]
# ---- 严格段：合法站点可能就在里面，只在后台拿到交叉证据（证书/抖动）时才判 ----
STRICT_RANGES = [("159.24.3.0", 24), ("174.132.167.0", 24)]
OWNER_DOMAINS = {
    "meta": ("facebook.com", "fb.com", "fb.watch", "fbsbx.com", "instagram.com", "cdninstagram.com",
             "whatsapp.com", "whatsapp.net", "meta.com", "messenger.com", "threads.net", "threads.com",
             "oculus.com", "fbcdn.net"),
    "twitter": ("twitter.com", "x.com", "t.co", "twimg.com", "twitpic.com"),
    "dropbox": ("dropbox.com", "dropboxusercontent.com", "dropboxapi.com", "db.tt"),
}

_lock = threading.Lock()
_table = {}          # domain -> {"why":..., "bad":..., "clean":..., "first":ts, "hits":n}
_stats = {"q": 0, "redirect": 0, "r1": 0, "r2": 0, "r3": 0, "r4": 0, "r5": 0, "clean_fail": 0,
          # 2026-10-09 问题2/3：新增计数**必须**进本字面量，否则 load_counters() 不恢复
          "poison_strong": 0, "poison_weak": 0, "poison_expired": 0, "poison_promoted": 0,
          "r3_strong_clean": 0, "r3_cn_dual_clean": 0, "r3_cn_dual_b": 0, "r3_cn_dual_fail": 0,
          "r3_weak_clean": 0, "r3_weak_fallback": 0, "fc_unbound_servfail": 0,
          # 2026-10-09 清理修复 A：干净答案仅私网地址而跳过 R2 入列的次数
          "r2_private_skipped": 0,
          # 2026-10-09 P7/P4
          "r3_cn_weak_domestic": 0, "r5_queued": 0, "r5_window2": 0, "r5_discarded": 0,
          "r5_same_window": 0, "r5_dropped_rotate": 0,
          # 2026-10-09 P3：学习 IP 状态计数
          "ip_candidate": 0, "ip_confirmed": 0, "ip_review": 0, "ip_rejected": 0,
          "ip_expired_review": 0,
          "fallback_b": 0, "geo_skipped": 0, "cn_skip": 0, "cn_verify_b": 0, "cn_local": 0,
          # 2026-10-07 二档·第10步：B 收敛为 CN-only。b_noncn_blocked=本会为非 CN 域名预发 B 的次数
          # （旧行为），r2_no_b=非 CN 域名在"A 无地址 + 干净侧也无地址"下直接返回原应答的次数
          "b_noncn_blocked": 0, "r2_no_b": 0,
          # 2026-10-08 二档·第7步：**unbound B 的访问收口与消费计数**。
          # B 是链路里唯一的国内加密源，只许服务 CN 域名；全文件唯一允许向 B 发包的地方是
          # resolve_cn_via_unbound_b()（定义处有完整约束说明）。
          #   unbound_b_queries_total    = 本进程真正发往 B 的查询数（被门控挡下、未发包的不计）
          #   unbound_b_queries_guard_cn = 上述查询里消费者标签为 guard_cn 的数量
          #   unbound_b_noncn_attempt    = 非 CN 域名撞到收口点而被拒发包的次数（健康值 = 0）
          # 注：chainmon 探针 / dnscrypt CN 规则 / 人工 dig 都是**直连 B、不经过本进程**，
          # 因此它们不可能在这里被计数；其归类由 chainmon 用「B 自身 num.queries 增量 −
          # 本进程增量 − 探针自计数」反解（见 chainmon 的 b_attrib 块），避免两处口径打架。
          "unbound_b_queries_total": 0, "unbound_b_queries_guard_cn": 0,
          "unbound_b_noncn_attempt": 0,
          "bad_ip_hits": 0, "win_dot": 0, "win_doq": 0, "win_doq2": 0, "win_doq3": 0, "cdn_skipped": 0, "v6_skipped": 0,
          "win_dnscrypt": 0, "fast_dnscrypt_fail": 0, "fast_dnscrypt_ms": None,
          "shadow_tried": 0, "shadow_agree": 0, "shadow_disagree": 0,
          "shadow_empty": 0, "shadow_unavailable": 0,
          # 2026-10-10 Patch6（Codex ⑤）
          "shadow_skipped": 0, "shadow_agree_partial": 0, "shadow_agree_sub": 0,
          # 2026-10-10 Patch6-§1.2（双门 → 恰好一次抽样 + 有界提交记账；全部受 _lock 保护）
          # eligible=进入 shadow_note 的次数；sample_skip=被单次抽样跳过；capacity_skip=槽位满
          # submitted=成功提交；completed+pending=submitted（pending 含排队与运行）
          "shadow_eligible": 0, "shadow_sample_skip": 0, "shadow_capacity_skip": 0,
          "shadow_submitted": 0, "shadow_completed": 0, "shadow_pending": 0,
          "shadow_pending_peak": 0, "shadow_submit_error": 0, "shadow_worker_error": 0,
          # 2026-10-10 Patch8（Codex ⑦）严格清单门控
          "strict_hit": 0, "strict_consensus_ok": 0, "strict_no_consensus": 0,
          "strict_list_size": 0, "strict_list_expired": 0, "strict_cache_skip": 0,
          # 2026-10-10 Patch10（Codex Stage A）
          "strict_consensus_pos": 0, "strict_consensus_neg": 0, "strict_conflict": 0,
          "strict_insufficient": 0, "strict_overload": 0, "strict_servfail": 0,
          "strict_adopt_pos": 0, "strict_adopt_neg": 0, "strict_neg_hit": 0,
          "strict_single_wait": 0, "strict_set_mismatch": 0, "strict_hedge": 0,
          "strict_ad_adopt": 0, "strict_elapsed_ms": 0,
          # 2026-10-10 Patch13（Codex 口径修正）
          "boot_ts": 0, "r8_backoff_skip": 0, "r8_backoff_active": 0, "r8_backoff_cleared": 0,
          "r8_neg_fastfail": 0, "r8_neg_store": 0,
          # 2026-10-10 Patch14（CN-IP 面）
          "cnip_candidate": 0, "cnip_in_cnlist": 0, "cnip_outside_cnlist": 0,
          "cnip_r8_entered": 0, "cnip_r8_agree": 0, "cnip_r8_conflict": 0,
          "cnip_adopt_clean": 0, "cnip_backoff_skip": 0, "cnip_budget_skip": 0,
          "cnip_observe_conflict": 0, "cnip_elapsed_ms": 0, "cnip_veto_conflict": 0,
          "locks_trimmed": 0, "norm_ip_bytes": 0,
          "strict_cand_doq": 0, "strict_operator_dedup": 0, "strict_pin_hit": 0,
          "cn_prefer_b_hit": 0, "cn_prefer_b_miss": 0, "cn_prefer_b_disabled": 0,
          "strict_consensus_prefix_ok": 0, "strict_consensus_exact_ok": 0, "strict_consensus_none": 0,
          "r8_adopt_same_pfx": 0, "r8_adopt_diff_pfx": 0, "r8_adopt_nopfx": 0,
          # 2026-10-10 Patch34-B（Codex 方案 2′）：CN 路径"否定存在否决"
          "cn_veto_checked": 0, "cn_veto_hit": 0, "cn_veto_observe": 0, "cn_veto_proof": 0,
          "cn_veto_neg3": 0, "cn_veto_two_op": 0, "cn_veto_weak1": 0, "cn_veto_nodata_weak": 0,
          "cn_veto_nodata_proof": 0, "cn_veto_notdenial": 0, "cn_veto_noevidence": 0,
          "cn_veto_timeout": 0, "cn_veto_overload": 0, "cn_veto_agree": 0, "cn_veto_setdiff": 0,
          "cn_veto_pin_hit": 0, "cn_veto_allow_skip": 0, "cn_veto_ratelimited": 0,
          "cn_veto_backoff_skip": 0, "cn_veto_budget_skip": 0, "cn_veto_elapsed_ms": 0,
          "cn_zone_deny_set": 0, "cn_zone_deny_hit": 0, "cn_zone_deny_expired": 0, "cn_zone_r8_entered": 0,
          "cn_clean_hit": 0, "cn_clean_set": 0, "cn_clean_expired": 0,
          "cn_veto_w2_used": 0, "cn_veto_w2_skipped": 0, "cn_veto_w2_started": 0,
          # 2026-10-10 Patch27（Codex：R8 运营商级门控）
          "r8_asn_gate_d": 0, "r8_asn_gate_k": 0, "r8_asn_gate_unknown": 0,
          "asn_snapshot_size": 0, "asn_snapshot_reload": 0,
          # 2026-10-10 Patch28（Codex：异步审计）
          "audit_queued": 0, "audit_tried": 0, "audit_agree": 0, "audit_mismatch": 0,
          "audit_unknown": 0, "audit_dropped": 0, "audit_ratelimited": 0,
          "verifier_sem_wait": 0,
          "shadow_agree_super": 0, "shadow_partial": 0, "dnscrypt_adopt_disabled": 0,
          "cert_learned": 0, "jitter_checks": 0, "ip_promoted": 0, "rot_skipped": 0,
          # 快路（DNSSEC 否定证明）：fast_ad=AD 位, fast_nsec=NSEC/非 opt-out NSEC3 + RRSIG
          "fast_nx": 0, "fast_ad": 0, "fast_nsec": 0,
          # 竞速：clean_races=进入干净上游竞速次数, clean_hedged=需要并发 DoT 的次数,
          #       clean_slow=竞速整体超时/无结果次数
          "clean_races": 0, "clean_hedged": 0, "clean_slow": 0,
          # P0-fail-closed 改造新增：主动 SERVFAIL 次数 / 人工豁免命中 / CN-IP 盲区留痕
          "fail_closed": 0, "fail_closed_by_reason": {}, "allow_hits": 0, "cn_foreign": 0,
          # R7：STRICT 段命中后改道次数 / 命中但拿不到干净答案（保留原答案）次数
          "r7": 0, "r7_soft": 0,
          # R8：核对次数/一致/改道/窗口内改发钉住答案/核对通道不可用
          "r8_checked": 0, "r8_agree": 0, "r8_adopt": 0, "r8_pinned": 0, "r8_miss": 0,
          # R-2（2026-10-28）：fail-open 答案被 TTL 截断的次数
          "failopen_ttl_capped": 0,
          # 批次 4：提前并发发起核对的开销度量（started - used = 因早退路径浪费）
          "r8_parallel_started": 0, "r8_parallel_used": 0,
          "r8_parallel_busy": 0, "r8_parallel_late": 0,
          # 2026-10-05 加固新增：明文含未佐证地址 / AAAA 不一致 / 干净侧无地址 / 认证通道可用性 / 非A类查询量
          "r8_extra": 0, "r8_v6_miss": 0, "r8_noans": 0, "r8_auth_ok": 0, "r8_auth_none": 0,
          "qtype_other": 0,
          # 2026-10-05 P0/P1 修复新增
          "cn_b_denied": 0, "r8_extra_soft": 0, "budget_skip": 0,
          "cn_overlap": 0, "tc_retry": 0, "tc_retry_ok": 0,
          "r8t_checked": 0, "r8t_agree": 0, "r8t_extra": 0, "r8t_empty": 0,
          "r8t_none": 0, "r8t_adopt": 0,
          "dnssec_validated": 0, "dnssec_bogus": 0, "overload_drop": 0, "r8_dedup_wait": 0, "r8_circuit_skip": 0, "singleflight_wait": 0, "r8_event_skip": 0, "cold_drop": 0,
          "neg_cache_hit": 0, "neg_cache_store": 0,
          # 2026-10-08 正答案缓存 v1（影子模式，立项 4795158b）。全部计数只为度量：
          # 候选/命中/跳过/过期/策略变化/不一致。**影子模式绝不下发缓存答案。**
          # 2026-10-08 v2 收益度量（**只计数、不改准入**；独立影子表，绝不下发）
          # 2026-10-07 新增：过载/准入相关计数。overload_drop=被拒请求数，
          # admission_reject=因**提交前**有界队列满而被拒（真正会回 SERVFAIL 的那个门）
          "overload_servfail": 0, "admission_reject": 0,
          # 2026-10-09 阶段3：探针通道独立计数（与用户侧完全分开，互不污染）
          "probe_q": 0, "probe_admission_reject": 0, "probe_overload_drop": 0,
          "singleflight_timeout": 0, "corrob_dedup_timeout": 0,
          "corrob_ok": 0, "corrob_nodata": 0, "corrob_timeout": 0,
          "corrob_overload": 0, "corrob_error": 0,
          # 2026-10-07 晚：核对**覆盖率**口径（用户要求）。精确划分：
          #   attempt = cache_hit + success + timeout + overload + error
          #   ok      = cache_hit + success        （= "真的核对过了"）
          #   覆盖率  = ok / attempt
          "corrob_attempt": 0, "corrob_success": 0, "corrob_cache_hit": 0,
          "cold_overload": 0, "cold_timeout": 0}
_ch_stat = {}        # label -> {"rtt_ms":…, "ok":bool, "ts":…, "err":str}（保活线程维护）
_cn_nets = []        # [(网络号, 掩码)]，用于区分"国内 geo 差异"与"真投毒"
_diff = {}           # domain -> {"count","unbound","clean","first","last","ignored"}
_verify_queue = []
_verify_seen = {}    # domain -> ts（超过 REVERIFY_AFTER 允许重新核验）
_learned_bad_ips = set()
_bad_ip_domains = {}  # ip -> [域名...]（兼容保留；投票改用注册域）
# 2026-10-09 P3：每个学习 IP 的完整证据与状态（candidate/confirmed/review/rejected）
_ip_info = {}
IP_OBSERVE_S = 86400          # 24 小时观察期：未满 24h 不进确认集（不参与 R1）
IP_BASIS_STRONG = ("R4", "R6", "人工确认")   # 允许作为"依据"的规则（R1/R5 不算依据）
# 2026-10-09 范围修正（用户指示）：
#   · 独立依据集合——R1 是"命中学习集"的自我印证，**不能**用来证明学习集正确（禁止循环举证）
IP_INDEP_RULES = ("R2", "R4", "R5", "R6", "人工确认")
# 2026-10-10 依用户指示④ + Codex 评审：首次默认 30 天过长 ⇒ **72 小时**；
# 到期不是静默失效，而是自动转 review 待复核（见 _expire_confirmed_ips）；
# 续期必须基于**策略生效后新的双窗口实测**，不能拿旧证据再续。
IP_CONFIRM_TTL = 3 * 86400    # 72 小时
IP_REVIEW_AFTER = 24 * 3600   # 24 小时后进入复核窗口（到期转 review 时记录该时点）
_MULTI_TLD = ("co.uk", "org.uk", "ac.uk", "gov.uk", "com.cn", "net.cn", "org.cn", "gov.cn",
              "edu.cn", "ac.cn", "com.au", "co.jp", "co.kr", "com.tw", "com.hk", "com.br",
              "com.sg", "com.my", "co.in", "co.nz", "com.mx")
_churn_last = 0.0
_allow = set()        # 人工豁免域名（误报复核后放行，suspicious() 直接跳过）
_cn_seen = set()      # CN-IP 盲区留痕去重（最多 500 个域名）
_corrob = {}          # (name,qtype) -> (到期ts, 已核对应答bytes, 已核对IP元组)
_r8_stable = {}       # key -> 最近一次成功认证核对时间
_r8_stable_dirty = False


# ---------------- 基础设施 ----------------
# 2026-10-10 Patch13（Codex）：**比率/流量/核对/告警类计数一律不跨重启恢复**。
# 旧实现恢复所有 int 计数 ⇒ `--status`/看板上是跨天累计值（含压测与我的 canary 扫射 ✗），
# 我据此误判过“r8_miss≈73% 是投毒暴露”✗。改为：这些键每次启动归零，比率一律用 delta 计算。
# 只保留真正需要跨重启的“状态量”（如 learned_ips / strict_list_size，由各自的 reload 重算）。
PERSIST_SKIP = ("q", "r8_checked", "r8_miss", "r8_agree", "r8_adopt", "r8_event_skip",
                "r8_parallel_started", "r8_parallel_used", "r8_parallel_busy", "r8_parallel_late",
                "r8_extra", "r8_extra_soft", "r8_v6_miss", "r8_pinned", "r8_backoff_skip",
                "r8_backoff_active", "r8_backoff_cleared",
                "corrob_attempt", "corrob_ok", "corrob_nodata", "corrob_timeout",
                "corrob_overload", "corrob_error", "corrob_cache_hit", "corrob_dedup_timeout",
                "corrob_success", "r8_dedup_wait", "r8_circuit_skip", "r8_auth_ok", "r8_auth_none",
                "cn_foreign", "cnip_candidate", "cnip_in_cnlist", "cnip_outside_cnlist",
                "cnip_r8_entered", "cnip_r8_agree", "cnip_r8_conflict", "cnip_adopt_clean",
                "cnip_backoff_skip", "cnip_budget_skip", "cnip_observe_conflict",
                "cnip_elapsed_ms", "cnip_veto_conflict", "locks_trimmed", "norm_ip_bytes",
                "strict_cand_doq", "strict_operator_dedup", "strict_pin_hit",
                "cn_prefer_b_hit", "cn_prefer_b_miss", "cn_prefer_b_disabled",
                "strict_consensus_prefix_ok", "strict_consensus_exact_ok", "strict_consensus_none",
                "r8_adopt_same_pfx", "r8_adopt_diff_pfx", "r8_adopt_nopfx",
                "cn_veto_checked", "cn_veto_hit", "cn_veto_observe", "cn_veto_proof",
                "cn_veto_neg3", "cn_veto_two_op", "cn_veto_weak1", "cn_veto_nodata_weak",
                "cn_veto_nodata_proof", "cn_veto_notdenial", "cn_veto_noevidence",
                "cn_veto_timeout", "cn_veto_overload", "cn_veto_agree", "cn_veto_setdiff",
                "cn_veto_pin_hit", "cn_veto_allow_skip", "cn_veto_ratelimited",
                "cn_veto_backoff_skip", "cn_veto_budget_skip", "cn_veto_elapsed_ms",
                "cn_zone_deny_set", "cn_zone_deny_hit", "cn_zone_deny_expired", "cn_zone_r8_entered",
                "cn_clean_hit", "cn_clean_set", "cn_clean_expired",
                "cn_veto_w2_used", "cn_veto_w2_skipped", "cn_veto_w2_started",
                "r8_asn_gate_d", "r8_asn_gate_k", "r8_asn_gate_unknown",
                "asn_snapshot_size", "asn_snapshot_reload",
                "audit_queued", "audit_tried", "audit_agree", "audit_mismatch",
                "audit_unknown", "audit_dropped", "audit_ratelimited",
                "cn_domestic", "dnssec_validated", "dnssec_bogus",
                "budget_skip", "admission_reject", "overload_drop", "fail_closed",
                "strict_hit", "strict_consensus_pos", "strict_consensus_neg", "strict_conflict",
                "strict_insufficient", "strict_overload", "strict_servfail", "strict_adopt_pos",
                "strict_adopt_neg", "strict_neg_hit", "strict_single_wait", "strict_set_mismatch",
                "strict_cache_skip", "strict_list_expired", "shadow_tried", "shadow_agree",
                "shadow_disagree", "shadow_empty", "shadow_unavailable", "shadow_skipped",
                # Patch6-§1.2：有界提交记账必须**每次启动归零**（pending 是活量，重启后必须为 0，
                # 否则 submitted == completed + pending 在启动瞬间就破；窗口一律用 delta 衡量）
                "shadow_eligible", "shadow_sample_skip", "shadow_capacity_skip",
                "shadow_submitted", "shadow_completed", "shadow_pending",
                "shadow_pending_peak", "shadow_submit_error", "shadow_worker_error",
                "clean_fail", "fast_dnscrypt_fail", "fallback_b", "redirect", "r3")


# Step-1 §1：业务基线仪表的**汇总标量键**（chainmon 可直接读；分桶在 st["base"] 里）✓。
# 语义：全部是「窗口内」量 ⇒ 与 PERSIST_SKIP 一致，一律用两次快照 delta 衡量。
_step1_keys = ("base_instr", "base_q", "base_retry", "base_hedge", "base_alt_order",
               "base_a_ok", "base_witness", "base_b", "base_cache", "base_cn",
               "base_cls_client", "base_cls_host", "base_cls_loopback",
               "base_cls_probe", "base_cls_other", "base_cls_none")
for _k in _step1_keys:
    _stats.setdefault(_k, 0)
PERSIST_SKIP = tuple(PERSIST_SKIP) + _step1_keys

# Step-1 §1：**verifier 侧**同 ID 计数（verifier.py 在它自己的进程里递增这些键，
# 由它自己的 `_stats_writer` 落到 verifier-state/stats.json ✓ —— 与 guard 主进程分开统计 ✓）。
_vstep1_keys = ("v_recv", "v_rid_present", "v_rid_absent", "v_pool_r3", "v_pool_corrob",
                "v_pool_strict", "v_pool_veto", "v_pool_overload", "v_err", "v_ms",
                "v_ms_n", "v_badframe")
for _k in _vstep1_keys:
    _stats.setdefault(_k, 0)
PERSIST_SKIP = tuple(PERSIST_SKIP) + _vstep1_keys

# Step-2 §2：有效期/证据来源与准入缓存失效的**窗口量**键 ✓。
# 语义与 `_step1_keys` 一致：全是「自启动以来本窗口内发生的事」⇒ 必须每次启动归零，
# 比率一律用两次快照 delta ✓（否则 `adm_cache_ttl_zero/adm_cache_put` 这类比例会被
# 上次运行的残留污染 ✗ —— 我上一次就是这样误判过 r8_miss 比例 ✗）。
_step2_keys = ("ttl_src_wire", "ttl_zero_a", "ttl_zero_alt", "ttl_zero_witness",
               "neg_ttl_forward", "neg_ttl_negative", "neg_ttl_negative_unproven",
               "neg_cache_skip_unproven", "neg_cache_skip_zero_ttl",
               "adm_cache_put", "adm_cache_hit", "adm_cache_expired",
               "adm_cache_ttl_zero", "adm_cache_invalidated", "adm_cache_view_mismatch",
               "adm_cache_invalidated_bogus", "adm_cache_invalidated_zone_pin",
               "pin_invalidated_bogus", "pin_invalidated_zone_pin",
               "pin_invalidated_mark_strong", "pin_invalidated_mark_new",
               # §2 第 51 行"安全准入证据和答案缓存分开" ⇒ 否定缓存单独记账 ✓
               "neg_invalidated_bogus", "neg_invalidated_zone_pin",
               "neg_invalidated_mark_strong", "neg_invalidated_mark_new",
               # §2 第 48/55 行：schema 拒绝与**证据自身到期**拒绝 ✓
               "adm_cache_schema_reject", "adm_cache_evidence_expired",
               # §2 第 50 行："缓存命中不重新插入" ✓（同答案重复写回被拦下的次数）
               "adm_cache_reput_same")
for _k in _step2_keys:
    _stats.setdefault(_k, 0)
PERSIST_SKIP = tuple(PERSIST_SKIP) + _step2_keys
# §3「消除 CN 路径重复取数与重复重试」新增计数（`_step3_keys`）✓ —— 同上：全是
# 窗口量（"自启动以来发生过几次"）⇒ 必须每次启动归零，比率一律用两次快照 delta ✓。
# ★ `src_start_*` / `src_reuse_*` **不在这里** ✗ —— 它们是 `_b_inc()` 分桶键 ⇒ 已进
# `_BS_ALLOW`（`guard.py:1327` 附近）✓，进 `_stats` 会变成两套账本 ✗。
_step3_keys = ("dl_exhausted", "dl_clamped",
               # 方案第 70 行：同一来源**每请求最多启动一次** ⇒ 被闸门拦下的重复次数 ✓
               "a_dup_skipped", "b_dup_skipped", "witness_dup_skipped",
               "alt_dup_skipped", "fin_alt_dup_skipped",
               "fin_retry_alt_dup", "fin_retry_witness_dup",
               # 方案第 69 行：A 见证**一次返回原始 wire** ⇒ 用上/没拿到（只记账，绝不重取 ✓）
               "policy_hint_wire_used", "policy_hint_wire_missing", "policy_hint_refetch_fail",
               # 方案第 73 行：CN 路径 singleflight ✓
               "cn_sf_lead", "cn_sf_merge", "cn_sf_served",
               "cn_sf_wait_ok", "cn_sf_wait_timeout", "cn_sf_budget_skip",
               # 方案第 73 行：等锁成功但领跑者已发布 ⇒ **让位复用**（绝不串行重查 ✗）
               "cn_sf_reuse_handoff",
               # 方案第 67 行：上游全失败 ⇒ **必须回 SERVFAIL 而不是静默丢包** ✓
               # （完成门首轮实测 ③④ 暴露：`handle()` 返回 None ⇒ 一个字节都不发 ✗）
               "resp_servfail_built",
               # 方案第 67 行：预算已尽 ⇒ 严格清单/救援路径不再新开预算 ✓
               "strict_budget_skip")
for _k in _step3_keys:
    _stats.setdefault(_k, 0)
PERSIST_SKIP = tuple(PERSIST_SKIP) + _step3_keys
# §4「补齐 alt readiness 和连接保持」新增计数（`_step4_keys`）✓ —— 同为窗口量。
# ★ 两个键**早已在 `_tag_bucket()` 的白名单里预留**（`guard.py` 的
#   `_tag_bucket`：`"retry_fail","alt_ready","alt_not_ready","cache_hit","adm_hit"`）
#   ⇒ 本轮把预留给它们的位置真正用起来 ✓（此前只被 `_tr_flag` 触碰、从无函数驱动 ✗，
#   这正是方案第 78 行"不能把未部署的当作已完成"点到的同一类问题 ✓）。
_step4_keys = (
    # §4 第 3 项：readiness 门 —— ready ⇒ 允许进 alt；not_ready ⇒ **不发包** ✓
    "alt_ready", "alt_not_ready",
    # §4 第 3 项：`alt_not_ready` 的**原因分桶**（缺失/过期/身份变/配置变/其它 ✓）
    "alt_ready_missing", "alt_ready_stale", "alt_ready_identity_changed",
    "alt_ready_config_changed", "alt_ready_other",
    # §4 第 3 项：**transport 断路器**镜像（绝对量，直接读 `breaker_snapshot()` ✓）。
    # ★ 刻意**不**在 `_alt_gate()` 里调 `breaker_state()` —— 它探测到 open→half_open 时
    #   会把 `half_open` 置真（"只放 1 个半开试探"）✗；若 `_alt_gate()` 先调一次就把它
    #   消费掉，随后 `query_alt()` 只会看到 `half_open_busy` ⇒ **试探永远发不出去、
    #   断路器永不恢复** ✗。半开名额只能由真正发包的 `query_alt()` 消耗 ✓。
    "alt_breaker_trips", "alt_transport_ok", "alt_transport_fail",
    "alt_half_open_ok", "alt_half_open_fail",
    # §4 第 3 项：not-ready / 断路器不健康 ⇒ **不进入长时间尝试** ⇒ 被跳过的通道次数 ✓
    #（与 `alt_dup_skipped` 区分：那个是"每请求只一次"闸门，这个是"健康门"闸门 ✓）
    "alt_unavailable_skip")
for _k in _step4_keys:
    _stats.setdefault(_k, 0)
PERSIST_SKIP = tuple(PERSIST_SKIP) + _step4_keys


# ===== §5：热命中与有界刷新的计数 =====
# 与 §2/§3/§4 同口径：全部是**每次启动归零**的运行量 ⇒ 比率必须用两次快照的 delta ✓。
# 为什么要单独列表而不靠 `_stats` 里已有：只有在此声明的键才会被 `load_counters()` 归零
# （否则跨重启累计 ⇒ "刷新成功率"会被历史值冲淡 ✗）。
#   hot_win          = 通过资源闸门、真正跑了一轮调度的次数（分母 ✓）
#   hot_cands        = 每轮进入候选榜的键数（观察"热门榜有没有东西" ✓）
#   hot_submitted    = 真正提交给刷新执行器的任务数（**才是"新增上游请求"的分子** ✓）
#   hot_refreshed    = 其中成功写回准入缓存的次数 ✓
#   hot_failed       = 取数/分类/TTL 任一不通过 ⇒ **什么都不写** ✓（"失败不续期"的分子 ✓）
#   hot_pause_mem/io = 资源闸门暂停的次数（§5 第 6 项：暂停刷新、**不动安全准入** ✓）
#   pss_kb/pss_peak_kb = 本进程 PSS 实测/峰值（完成门 ≤32MiB 的**硬证据** ✓）
#   base_bqps_x1000   = 业务 QPS ×1000（刷新速率上限的**依据值**，便于事后核对 ✓）
_step5_keys = (
    "hot_evict", "hot_evict_bytes", "hot_win", "hot_cands", "hot_submitted",
    "hot_refreshed", "hot_failed", "hot_skip_stale", "hot_skip_ttl", "hot_skip_source",
    "hot_skip_cn", "hot_skip_lock", "hot_skip_raced", "hot_out_window", "hot_in_window",
    # ★ `hot_skip_out_window` —— 由 `_hot_decide()` 返回的 `"out_window"` 经
    #   `_st_bump("hot_skip_" + why)` 拼出 ✓。首轮**漏登记**它（只登了字面量 `hot_out_window`
    #   ✗，而那是个**永远不会被写到**的名字 ⇒ 指标恒 0 ✗），后果：G4 判据读了一个死键 ⇒
    #   门假失败 ✓。教训：凡"字符串拼接生成计数键"的地方，**登记清单必须按拼接结果写** ✗。
    "hot_skip_out_window",
    "hot_yielded", "hot_qps_limited", "hot_conc_blocked", "hot_scan_err", "hot_loop_err",
    "hot_pause_mem", "hot_pause_io", "hot_frac_sum", "hot_frac_n", "hot_below_lo",
    # ★ C（2026-10-22）：负缓存扩展后的新计数器 —— 必须登记，否则看板读不到 ✓
    "sf_put_inadmissible", "sf_put_bogus", "sf_cleared", "sf_extended",
    "failopen_ttl_capped",
    "sf_streak_max_ttl", "sf_cache_store", "sf_cache_hit",
    "res_mem_low", "res_io_high", "res_mem_available_mb", "res_io_pages_s",
    "adm_cache_bytes", "adm_cache_evicted_bytes", "adm_bytes_high",
    # ★ 2026-10-11（§5 验收期定位的既有缺陷）：**脏通道字节**的拦截计数 ✓
    #   （`clean_bare` = 竞速里被判"零证据空壳"而不予采纳的上游字节数；
    #    `udp_qid_mismatch` = UDP 应答 qid 与本次查询不符而被丢弃的次数；
    #    `dot_qid_mismatch` = DoT 常连接帧 qid 不符而被丢弃的次数）。
    #   三者都是"**本可变成错误答案**的字节被挡下"的硬证据 ⇒ 必须长期可观测 ✓。
    "clean_bare", "udp_qid_mismatch", "dot_qid_mismatch",
    "pss_kb", "pss_peak_kb", "base_bqps_x1000")
for _k in _step5_keys:
    _stats.setdefault(_k, 0)
PERSIST_SKIP = tuple(PERSIST_SKIP) + _step5_keys


# ===== §6：CN 名单载入指标（2026-10-15 用户要求）=====
# 与 §5 同口径登记：这些是**状态量**（当前规模 / 载入时刻），不是"本次运行发生过几次"
# 的累计量 ⇒ 每次启动归零，由各自的载入函数写入真实值 ✓。
#   cn_typed_full/domain/suffix = 类型化名单三类条目数（_match_cn_typed 的真实输入）
#   cn_typed_total              = 三类并集规模
#   cn_typed_active             = 1=当前按类型判定；0=回退旧合并语义（精确+子域）
#   cn_typed_fail               = 本次运行内 typed 载入失败次数
#   cn_veto_entries             = 生效 veto 名单条目数（含快照回退时的规模）
#   cn_veto_fail                = 本次运行内 veto 载入失败次数
#   cn_ip_nets                  = 已载入的国内 IPv4 段条数（cn_ip.txt）
#   *        _loaded_ts         = 最近一次成功载入的 unix 时间戳（0=本次运行尚未成功）
#   stale_out                   = 出口 stale 应答计数（`stale_out_<kind>` 由 _stale_note 拼接
#                                 生成 ⇒ 按"拼接结果"登记字面量键，参照 hot_skip_out_window 教训）
_cn_list_keys = (
    "cn_typed_full", "cn_typed_domain", "cn_typed_suffix", "cn_typed_total",
    "cn_typed_active", "cn_typed_fail", "cn_typed_loaded_ts",
    "cn_veto_entries", "cn_veto_fail", "cn_veto_loaded_ts",
    "cn_ip_nets",
    # ★ 2026-10-15 第三份审计 F1/F2/F4 的新指标（同为"每次启动归零"的状态量/本次运行计数）：
    #   cn_trust_exc_entries     = 国内可信解析例外清单条目数
    #   cn_trust_exc_loaded_ts   = 该清单最近载入时刻
    #   cn_trust_exc_missing     = 1=清单文件不存在（= 未配置例外，非故障）
    #   cn_trust_exc_fail        = 例外清单读取失败次数
    #   cn_dom_exception         = 因例外而"不走国内路径"的判定次数
    #   cn_typed_snapshot_used   = typed live 不可用时改用发布快照的次数
    #   cn_typed_fallback_denied = typed 与快照都不可用 ⇒ 判为非国内的次数（旧行为会宽匹配）
    #   cn_list_gen_change*      = 名单代次变化次数（typed/veto/exc/trust）⇒ 准入缓存按代次失效
    #   cn_exc_change_needs_agh_flush = 例外变化次数（AGH 侧缓存需人工/脚本清理）
    #   adm_cache_gen_mismatch   = 因名单代次不符而拒绝复用准入缓存的次数
    "cn_trust_exc_entries", "cn_trust_exc_loaded_ts", "cn_trust_exc_missing",
    "cn_trust_exc_fail", "cn_dom_exception", "cn_typed_snapshot_used",
    "cn_typed_fallback_denied", "cn_list_gen_change", "cn_list_gen_change_typed",
    "cn_list_gen_change_veto", "cn_list_gen_change_exc", "cn_list_gen_change_trust",
    "cn_exc_change_needs_agh_flush",
    "adm_cache_gen_mismatch",
    # ★ 2026-10-15 拆分「路由 vs 信任」后的新指标：
    #   cn_trust_allow_entries/loaded_ts/missing/fail = 信任白名单状态
    #   cn_trust_bypass       = 免见证直采次数（仅 trusted）
    #   cn_trust_witness      = 国内答案被要求走见证的次数
    #   cn_trust_class_*      = 信任判定分类计数（suffix/allow/mode_all/witness/exception）
    "cn_trust_allow_entries", "cn_trust_allow_loaded_ts", "cn_trust_allow_missing",
    "cn_trust_allow_fail", "cn_trust_bypass", "cn_trust_witness",
    "cn_trust_class_suffix", "cn_trust_class_allow", "cn_trust_class_mode_all",
    "cn_trust_class_witness", "cn_trust_class_exception",
    # ★ 2026-10-15 第四份审计 N2/N3 的新指标（同为"每次启动归零"的本次运行计数）：
    #   denial_proof_answered        = 否定证明收到"正答案"因而拒绝采纳的次数（N2 修复点）
    #   denial_proof_noad            = 否定证明无 AD（无签名）⇒ 保持原判的次数（N2）
    #   cn_witness_secure_ad_declared = 见证源声明 AD=1 被标 SECURE 的次数（N3：把"运营方声明"
    #                                  与"本机验证器独立确认"在指标上分开）
    "denial_proof_answered", "denial_proof_noad", "cn_witness_secure_ad_declared",
    # ★ 2026-10-16 N3 精细分档：见证通道"仅凭 AD 声明"被降级的次数（与上面一行分口径）；
    #   以及四档分布（均为"每次启动归零"的本次运行计数）。
    #   口径固定：只有**报文 AD=1** 时才进档 —— AD=0 的普通 accepted 由
    #   `alt_adapter.ad_grade()` 返回 `(None, "ad_zero")` ⇒ 既不计入本项，也不进四档桶 ✓。
    "cn_witness_ad_declared_accepted",
    "ad_grade_local_ad", "ad_grade_signed", "ad_grade_ad_declared", "ad_grade_sig_expired",
    "stale_out")
for _k in _cn_list_keys:
    _stats.setdefault(_k, 0)
PERSIST_SKIP = tuple(PERSIST_SKIP) + _cn_list_keys



def load_counters():
    try:
        with open(STATS_FILE) as f:
            prev = json.load(f)
        for k, v in prev.items():
            if k in _stats and isinstance(v, int) and v >= 0 and k not in PERSIST_SKIP:
                _stats[k] = v
    except Exception:
        pass
    # 每次启动归零“每次运行”语义的计数与分类桶（Codex：比率必须用 delta；
    # by_reason 是 dict 型、旧实现既不恢复也不归零 ⇒ 与 fail_closed 永远对不上账 ✗）。
    for _k in PERSIST_SKIP:
        if _k in _stats:
            _stats[_k] = 0
    _stats["fail_closed_by_reason"] = {}
    # Patch13 关键修正：真正的存储是**模块级 `_fc_by_reason`**（stats writer 才把它拷进
    # st["fail_closed_by_reason"]）。只归零 _stats 那份是无效的 ✗ ⇒ 旧实现下“按原因对账”
    # 永远对不上（线上 fail_closed=12686 而 by_reason 只有 2）。此处一并归零。
    try:
        _fc_by_reason.clear()
    except Exception:
        pass
    _stats["boot_ts"] = int(time.time())


def log(msg):
    try:
        # 2026-10-10 P34-A：**删除自截断** ✗ —— 它会在 5MB 时静默清空全部取证历史；
        # 改由 logrotate（/etc/logrotate.d/dnsguard，rename/create 方式，非 copytruncate）轮转 ✓。
        with open(LOG, "a") as f:
            f.write("[%s] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
    except Exception:
        pass


def _atomic_json(path, obj, **kw):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, **kw)
    os.replace(tmp, path)


def load_state():
    global _table
    try:
        with open(STATE) as f:
            _table = json.load(f).get("domains", {})
    except Exception:
        _table = {}


def save_state():
    try:
        _atomic_json(STATE, {"updated": time.time(), "domains": _table}, ensure_ascii=False, indent=1)
    except Exception as e:
        log("save_state error: %s" % e)


# 2026-10-10 Patch13（Codex Q7）：核对失败按名字退避（只抑制重试，不改答案）。
_r8_backoff = {}          # (name,qtype) -> [next_allowed_ts, fail_count]
R8_BACKOFF_BASE = float(os.environ.get("GUARD_R8_BACKOFF_BASE", "20"))
R8_BACKOFF_MAX = float(os.environ.get("GUARD_R8_BACKOFF_MAX", "300"))


def _r8_backoff_active(name, qtype):
    e = _r8_backoff.get((name, qtype))
    if not e:
        return False
    if e[0] > time.time():
        return True
    _r8_backoff.pop((name, qtype), None)
    with _lock:
        _stats["r8_backoff_cleared"] = _stats.get("r8_backoff_cleared", 0) + 1
    return False


def _r8_backoff_record(name, qtype):
    k = (name, qtype)
    e = _r8_backoff.get(k)
    n = (e[1] + 1) if e else 1
    wait = min(R8_BACKOFF_BASE * (2 ** (n - 1)), R8_BACKOFF_MAX)
    _r8_backoff[k] = [time.time() + wait, n]
    # 防止无界增长（Codex P3：两个无界字典）
    if len(_r8_backoff) > 20000:
        _r8_backoff.clear()
    with _lock:
        _stats["r8_backoff_active"] = len(_r8_backoff)
    return wait


# ---- 2026-10-27 P99 调优：R8 负结论短缓存 ----
# 语义保证：只改变"多快失败"，不改变"是否失败"。
# 建立条件与下面 STRICT_NODATA 的 SERVFAIL 出口完全一致 ⇒ 客户端可见 rcode 分布不变。
_r8_neg = {}
R8_NEG_TTL = float(os.environ.get("GUARD_R8_NEG_TTL", "60"))


def _r8_neg_get(name, qtype):
    k = (name, qtype)
    exp = _r8_neg.get(k)
    if not exp:
        return False
    if exp > time.time():
        return True
    _r8_neg.pop(k, None)
    return False


# ---------------- R8 运营商级门控（Patch27，默认关闭）----------------
ASN_SNAP_FILE = os.path.join(STATE_DIR, "asn_class.json")
ASN_GATE = _flag("GUARD_R8_ASN_GATE", False)          # 默认 0 ⇒ 行为与今天完全一致 ✓
_ASN_MAP = {}          # ip(str) -> asn(int)；**不可变使用**（只读 dict，热载时整体替换）


def _asn_load():
    """载入离线 ASN 快照（**零网络** ✓）。失败 ⇒ 空表 ⇒ 一切判为 unknown ⇒ K ⇒ 保留明文 ✓。"""
    global _ASN_MAP
    try:
        with open(ASN_SNAP_FILE, encoding="utf-8") as f:
            d = json.load(f)
        m = d.get("ip_to_asn") or {}
        _ASN_MAP = dict((str(k), int(v)) for k, v in m.items() if v is not None)
    except Exception:
        _ASN_MAP = {}
    with _lock:
        _stats["asn_snapshot_size"] = len(_ASN_MAP)
        _stats["asn_snapshot_reload"] = _stats.get("asn_snapshot_reload", 0) + 1
    log("ASN 快照已载入: %d 条（门控 %s）" % (len(_ASN_MAP), "开" if ASN_GATE else "关"))


def _ip_key(x):
    """把 `_norm_ip` 的输出（IPv4=str / IPv6=bytes）转成快照里的字符串键。"""
    if isinstance(x, bytes):
        try:
            return socket.inet_ntop(socket.AF_INET6, x)
        except Exception:
            return None
    return x if isinstance(x, str) else None


def _side_asn(sset):
    """一侧的"最佳 ASN"：该侧**所有**地址都能查到且 ASN 一致 ⇒ 返回它；否则 None（⇒ unknown ⇒ K）。"""
    if not sset:
        return None
    asns = set()
    for x in sset:
        k = _ip_key(x)
        a = _ASN_MAP.get(k) if k else None
        if a is None:
            return None
        asns.add(a)
    return next(iter(asns)) if len(asns) == 1 else None


def load_r8_stable():
    now = time.time()
    try:
        with open(R8_STABLE_FILE) as f:
            data = json.load(f)
        fresh = {}
        for k, ts in (data.get("domains") or {}).items():
            try:
                name, qtype = k.rsplit("|", 1)
                ts = float(ts)
                if now - ts < CORROB_TTL:
                    fresh[(name, int(qtype))] = ts
            except Exception:
                continue
        with _lock:
            _r8_stable.update(fresh)
    except Exception:
        pass


def save_r8_stable():
    global _r8_stable_dirty
    try:
        with _lock:
            now = time.time()
            domains = {
                "%s|%s" % (k[0], k[1]): ts
                for k, ts in _r8_stable.items()
                if now - ts < CORROB_TTL
            }
            _r8_stable_dirty = False
        _atomic_json(R8_STABLE_FILE, {"updated": now, "domains": domains},
                     ensure_ascii=False, indent=1)
    except Exception:
        pass


def load_allow():
    global _allow
    try:
        with open(ALLOW_FILE) as f:
            _allow = set(str(x).lower().strip().rstrip(".") for x in json.load(f).get("domains", []) if x)
    except Exception:
        _allow = set()


def save_allow():
    try:
        _atomic_json(ALLOW_FILE, {"updated": time.time(), "domains": sorted(_allow)},
                     ensure_ascii=False, indent=1)
    except Exception as e:
        log("save_allow error: %s" % e)


def in_allow(name):
    n = (name or "").lower().strip().rstrip(".")
    if not n:
        return False
    if n in _allow:
        return True
    return any(n.endswith("." + d) for d in _allow)


def load_diff():
    global _diff
    try:
        with open(DIFF_FILE) as f:
            _diff = json.load(f).get("diff", {})
    except Exception:
        _diff = {}


def save_diff():
    try:
        _atomic_json(DIFF_FILE, {"updated": time.time(), "diff": _diff}, ensure_ascii=False, indent=1)
    except Exception as e:
        log("save_diff error: %s" % e)


def _regdom(name):
    """注册域名近似（eTLD+1 的简化版，含常见多段后缀）。同注册域兄弟只计一票。"""
    n = (name or "").strip().lower().rstrip(".")
    if not n:
        return ""
    parts = n.split(".")
    if len(parts) < 2:
        return n
    last2 = ".".join(parts[-2:])
    for t in _MULTI_TLD:
        if n.endswith("." + t) and len(parts) >= 3:
            return ".".join(parts[-3:])
    return last2


def _expire_confirmed_ips(now=None):
    """Codex 建议③：确认到期**自动转 review 并留痕**（不是静默失效）。

    续期要求：策略生效后**新的双窗口实测**证据；旧的证据文件只作长期留存，不作续期依据。
    """
    now = time.time() if now is None else now
    n = 0
    with _lock:
        for _ip, _e in _ip_info.items():
            if _e.get("status") != "confirmed":
                continue
            _exp = _e.get("expires")
            if _exp and now > float(_exp):
                _e["status"] = "review"
                _e["note"] = ("确认到期（%s）→ 转复核；续期需策略生效后新的双窗口实测证据"
                              % time.strftime("%Y-%m-%d %H:%M", time.localtime(_exp)))
                _learned_bad_ips.discard(_ip)
                n += 1
    if n:
        with _lock:
            _stats["ip_expired_review"] = _stats.get("ip_expired_review", 0) + n
        log("IPEX 确认到期转复核 %d 条（到期即失效，需新证据续期）" % n)
        save_bad_ips()
    return n


def _ip_scope_of(e):
    """取（或按记录推导）该 IP 的生效范围：精确域名 + 注册域。

    用户指示①：确认必须带范围。老记录没有 scope 时，用"当时观察到的域名/注册域"推导，
    避免一个 IP 一确认就对全世界所有域名生效。
    """
    sc = e.get("scope") or {}
    doms = list(sc.get("domains") or [])
    regs = list(sc.get("regdomains") or [])
    if not doms and not regs:
        doms = list(e.get("domains") or [])[:30]
        regs = list(e.get("regdomains") or [])[:30]
    return doms, regs


def _ip_hit(ip, name):
    """该 IP 对 name 是否命中"限定范围内的确认"（替换原来的全局集合匹配）。"""
    e = _ip_info.get(ip)
    if not e or e.get("status") != "confirmed":
        return False
    exp = e.get("expires")
    if exp and time.time() > float(exp):
        return False
    n = (name or "").strip().lower().rstrip(".")
    if not n:
        return False
    doms, regs = _ip_scope_of(e)
    for d in doms:
        d = (d or "").lower().rstrip(".")
        if d and (n == d or n.endswith("." + d)):
            return True
    nr = _regdom(n)
    return bool(nr) and nr in set(regs)


def _ip_rule_tag(why):
    """从 why 里取规则标签（用于依据判定：R4/R6/人工确认 才算依据）。"""
    w = why or ""
    for tag in ("R1", "R2", "R3", "R4", "R5", "R6", "人工确认"):
        if w.startswith(tag):
            return tag
    return "?"


def _ip_eval(ip):
    """按 P3 规则判定该 IP 能否升为 confirmed（返回 (bool, 原因)）。"""
    e = _ip_info.get(ip) or {}
    if e.get("status") in ("rejected", "review"):
        return False, "状态=%s（需人工）" % e.get("status")
    # 迁移承认：v1 时期既有的"确认"没有窗口/依据记录（用户 P3 只要求把"同父域印证"的 18 个
    # 移入复核），其余 legacy 予以承认，避免上线瞬间被误降级。review/rejected 已在上面拦截。
    if e.get("legacy") and e.get("status") == "confirmed":
        return True, "legacy 承认（迁移前既有确认）"
    regs = set(e.get("regdomains") or [])
    if len(regs) < 2:
        return False, "不同注册域不足(=%d)" % len(regs)
    wins = set(e.get("windows") or [])
    if len(wins) < 2:
        return False, "时间窗口不足(=%d)" % len(wins)
    rules = set(e.get("rules") or [])
    if not (rules & set(IP_BASIS_STRONG)):
        return False, "无 R4/R6/人工确认依据(现有=%s)" % ",".join(sorted(rules))
    # 2026-10-09 范围修正②：**禁止循环举证** —— 仅 R1（命中学习集）不得作为独立依据。
    if not (rules & set(IP_INDEP_RULES)) and not e.get("independent"):
        return False, "无独立依据（仅 R1 自我印证不算）"
    ours = set(e.get("ours") or [])
    clean = set(e.get("clean") or [])
    if ours and clean and (ours & clean):
        return False, "我方与干净答案出现过交集（非持续不一致）"
    first = float(e.get("first") or 0)
    if not first or (time.time() - first) < IP_OBSERVE_S:
        return False, "未满 24h 观察期(已 %.1fh)" % ((time.time() - first) / 3600.0 if first else 0)
    return True, "满足全部条件"


def _ip_maybe_promote(ip, first=False):
    """评估并落地状态：满足 ⇒ confirmed，否则 candidate。只在状态变化时打日志/计数。"""
    e = _ip_info.setdefault(ip, {"status": "candidate", "first": time.time(), "last": time.time(),
                                 "windows": [], "domains": [], "regdomains": [], "rules": [],
                                 "ours": [], "clean": [], "basis": [], "note": ""})
    ok, why = _ip_eval(ip)
    was = e.get("status")
    if ok and was != "confirmed":
        e["status"] = "confirmed"
        e["confirmed"] = time.time()
        # 范围修正①：确认必须带作用范围与有效期
        if not e.get("scope"):
            e["scope"] = {"domains": sorted(set(e.get("domains") or []))[:30],
                          "regdomains": sorted(set(e.get("regdomains") or []))[:30]}
        e["expires"] = time.time() + IP_CONFIRM_TTL
        e["independent"] = True
        _learned_bad_ips.add(ip)
        with _lock:
            _stats["ip_confirmed"] = _stats.get("ip_confirmed", 0) + 1
            _stats["ip_promoted"] += 1
        log("IPOK 升级为确认投毒地址: %s（注册域=%s 窗口=%d 依据=%s）"
            % (ip, ",".join(sorted(set(e.get("regdomains") or []))[:4]), len(set(e.get("windows") or [])),
               ",".join(sorted(set(e.get("rules") or []) & set(IP_BASIS_STRONG)))))
    elif not ok:
        if was == "confirmed":
            _learned_bad_ips.discard(ip)
            e["status"] = "candidate"
            log("IPDN 降级（不再满足条件）: %s —— %s" % (ip, why))
        else:
            e["status"] = "candidate"
            if first:
                with _lock:
                    _stats["ip_candidate"] = _stats.get("ip_candidate", 0) + 1
                log("IPCD 记为候选（未确认，不参与 R1）: %s —— %s" % (ip, why))
    return e["status"] == "confirmed"


def load_bad_ips():
    global _learned_bad_ips, _bad_ip_domains, _ip_info
    try:
        with open(BAD_IPS_FILE) as f:
            d = json.load(f)
        _learned_bad_ips = set(x for x in d.get("ips", []) if valid_ipv4(x))
        _bad_ip_domains = dict((k, list(v)) for k, v in (d.get("domains") or {}).items())
        # v2：证据与状态；v1 老文件没有 info ⇒ 用 domains 兜一个最小结构
        _ip_info = dict((k, dict(v)) for k, v in (d.get("info") or {}).items())
        for ip in list(_learned_bad_ips):
            _ip_info.setdefault(ip, {"status": "confirmed", "legacy": True,
                                     "first": 0, "last": 0, "windows": [], "domains": list(_bad_ip_domains.get(ip) or []),
                                     "regdomains": sorted(set(_regdom(dom) for dom in (_bad_ip_domains.get(ip) or []))),
                                     "rules": ["legacy"], "ours": [], "clean": [], "basis": [],
                                     "note": "v1 迁移：无窗口/依据记录，予以承认"})
        # 范围修正：为落地记录补齐 scope/expires，并标注是否具备独立依据
        for ip, e in _ip_info.items():
            if not e.get("scope"):
                e["scope"] = {"domains": sorted(set(e.get("domains") or []))[:30],
                              "regdomains": sorted(set(e.get("regdomains") or []))[:30]}
            if not e.get("expires"):
                e["expires"] = time.time() + IP_CONFIRM_TTL
            _r = set(e.get("rules") or [])
            e["independent"] = bool(_r & set(IP_INDEP_RULES)) or bool(e.get("basis")) or bool(e.get("independent"))
        # 只承认仍然"确认"的 IP；candidate/review/rejected 一律不进 R1
        _learned_bad_ips = set(ip for ip in _learned_bad_ips
                               if (_ip_info.get(ip) or {}).get("status", "confirmed") == "confirmed")
    except Exception:
        _learned_bad_ips = set()
        _bad_ip_domains = {}
        _ip_info = {}


def save_bad_ips():
    try:
        with _lock:
            info = dict((k, dict(v)) for k, v in _ip_info.items())
        for k in info:
            info[k]["domains"] = sorted(set(info[k].get("domains") or []))[:30]
            info[k]["regdomains"] = sorted(set(info[k].get("regdomains") or []))[:30]
            info[k]["rules"] = sorted(set(info[k].get("rules") or []))[:10]
            info[k]["windows"] = sorted(set(info[k].get("windows") or []))[-12:]
            info[k]["ours"] = sorted(set(info[k].get("ours") or []))[:12]
            info[k]["clean"] = sorted(set(info[k].get("clean") or []))[:12]
        _atomic_json(BAD_IPS_FILE, {"updated": time.time(), "v": 2,
                                    "ips": sorted(_learned_bad_ips)[:500],
                                    "domains": dict((k, sorted(set(v))[:20]) for k, v in _bad_ip_domains.items()),
                                    "info": info})
    except Exception as e:
        log("save_bad_ips error: %s" % e)


def learn_bad_ips(ips, domain, why="", clean_ips=None, clean_by_source=None):
    """P3（2026-10-09）：记录证据并按新规则判定是否升级为"确认注入地址"。

    与旧版的区别：
      · 投票按**注册域**去重（同注册域兄弟只计一票）；
      · 需 **≥2 注册域 + ≥2 时间窗口 + ≥1 个 R4/R6/人工确认依据 + 我方与干净答案持续不一致**；
      · 有 **24 小时观察期**，未满只做 candidate ⇒ **不参与 R1**（防一次误判扩散）；
      · 完整留证：域名、注册域、规则、窗口、我方答案、干净答案、人工结论。
    """
    changed = False
    if not _cn_nets:        # 国内段还没加载完，先不学习，避免把国内 IP 误收
        return False
    tag = _ip_rule_tag(why)
    rd = _regdom(domain)
    win = int(time.time() // 3600) * 3600
    for ip in ips:
        if not ip or not valid_ipv4(ip):
            continue
        if is_cn_ip(ip) is True:
            continue
        doms = _bad_ip_domains.setdefault(ip, [])
        if domain not in doms:
            doms.append(domain)
        e = _ip_info.get(ip)
        first = e is None
        if e is None:
            e = {"status": "candidate", "first": time.time(), "last": time.time(), "windows": [],
                 "domains": [], "regdomains": [], "rules": [], "ours": [], "clean": [], "basis": [],
                 "note": ""}
            _ip_info[ip] = e
        e["last"] = time.time()
        for k, v in (("domains", domain), ("regdomains", rd), ("rules", tag), ("ours", ip)):
            if v and v not in e[k]:
                e[k].append(v)
        # 范围修正③：按解析器分别保存（避免合并后掩盖来源）；旧式合并列表标 merged=true
        if clean_by_source:
            cbs = e.setdefault("clean_by_source", {})
            for src, vals in clean_by_source.items():
                lst = cbs.setdefault(src, [])
                for c in (vals or []):
                    if c and c not in lst:
                        lst.append(c)
        else:
            for c in (clean_ips or []):
                if c and c not in e["clean"]:
                    e["clean"].append(c)
            if clean_ips:
                e["merged"] = True
        if win not in e["windows"]:
            e["windows"].append(win)
        if tag in IP_BASIS_STRONG and tag not in e["basis"]:
            e["basis"].append(tag)
        if e["status"] in ("rejected", "review"):
            continue
        if _ip_maybe_promote(ip, first=first):
            changed = True
    save_bad_ips()
    return changed


_CN_NETS_CHK = {"mtime": 0.0, "checked": 0.0}


def load_cn_nets(force=False):
    """加载国内 IPv4 段（缓存 7 天；支持 mtime 热重载）。

    2026-10-15：原实现只在进程启动时载入一次（外加 7 天过期才自行下载），于是
    refresh-cn-rules.py 每日刷新的 cn_ip.txt 必须重启 guard 才生效。现按 mtime 做
    60s 节流的重载（与 typed / veto 名单同口径）⇒ 刷新即生效、无需重启服务 ✓。
    """
    global _cn_nets
    refresh_local = False
    if _cn_nets and not force:
        try:
            _now = time.time()
            if _now - _CN_NETS_CHK["checked"] >= 60.0:
                _CN_NETS_CHK["checked"] = _now
                if os.path.getmtime(CN_FILE) != _CN_NETS_CHK["mtime"]:
                    # 本地文件已更新 ⇒ 只需重新解析。绝不走下载分支：否则会拿远端
                    # 旧数据覆盖刷新器刚写好的 cn_ip.txt（2026-10-15 本机实测踩到）。
                    refresh_local = True
        except Exception:
            pass
    if _cn_nets and not force and not refresh_local:
        return
    try:
        stale = (not os.path.exists(CN_FILE)) or (time.time() - os.path.getmtime(CN_FILE) > 7 * 86400)
        if stale or force:
            import urllib.request
            with urllib.request.urlopen(CN_URL, timeout=25) as r:
                data = r.read().decode("utf-8", "ignore")
            with open(CN_FILE, "w") as f:
                f.write(data)
        nets = []
        with open(CN_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "/" not in line or "." not in line.split("/")[0]:
                    continue
                try:
                    net, plen = line.split("/")
                    plen = int(plen)
                    ip = struct.unpack("!I", socket.inet_aton(net))[0]
                    mask = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF if plen else 0
                    nets.append((ip & mask, mask))
                except Exception:
                    continue
        _cn_nets = nets
        try:
            _CN_NETS_CHK["mtime"] = os.path.getmtime(CN_FILE)
        except Exception:
            pass
        # 节流窗口以"最近一次检查"为准（含本次成功载入）⇒ 载入后 60s 内不再重复
        # 检查 mtime；同时热重载最长延迟 60s，与 typed / veto 名单同口径。
        _CN_NETS_CHK["checked"] = time.time()
        _cn_metric("cn_ip_nets", len(nets))
        log("cn nets loaded: %d 条" % len(nets))
    except Exception as e:
        log("cn list load failed: %s" % str(e)[:60])


def valid_ipv4(ip):
    if not ip or ":" in ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or len(p) > 3 or int(p) > 255:
            return False
    return True


def is_cn_ip(ip):
    """True=国内 IPv4；False=非国内；None=判断不了(IPv6/非法)"""
    if not valid_ipv4(ip):
        return None
    try:
        v = struct.unpack("!I", socket.inet_aton(ip))[0]
    except Exception:
        return None
    for net, mask in _cn_nets:
        if (v & mask) == net:
            return True
    return False


def ip_in_cidr(ip, net, plen):
    if not valid_ipv4(ip):
        return False
    try:
        v = struct.unpack("!I", socket.inet_aton(ip))[0]
        n = struct.unpack("!I", socket.inet_aton(net))[0]
        mask = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF if plen else 0
        return (v & mask) == (n & mask)
    except Exception:
        return False


def owner_exempt(name, owner):
    n = (name or "").lower().rstrip(".")
    for d in OWNER_DOMAINS.get(owner, ()):
        if n == d or n.endswith("." + d):
            return True
    return False


def range_hit(ips, name=None, strict=False):
    """返回 (ip, 说明) 或 None；strict=True 时只查严格段（需要交叉证据的配角信号）"""
    for ip in ips:
        if ":" in ip:
            continue
        if strict:
            for net, plen in STRICT_RANGES:
                if ip_in_cidr(ip, net, plen):
                    return ip, "注入段 %s/%d" % (net, plen)
        else:
            for net, plen, owner in RANGE_HINTS:
                if ip_in_cidr(ip, net, plen):
                    if not owner_exempt(name, owner):
                        return ip, "%s 段 %s/%d 跨族" % (owner, net, plen)
                    break
    return None


# ---------------- 证书"归属"核验（只判域名是否匹配，不掺链信任） ----------------
CERT_CACHE = {}
_DECODE_CERT = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
_MATCH_HOSTNAME = getattr(ssl, "match_hostname", None)


def cert_name_match(ip, domain):
    """True=该 IP 的证书确实包含 domain（是这域名的主人）；
       False=证书不含该域名（伪造/劫持特征）；
       None=连不上/解析不了（无法判定，例如被墙或非 TLS 服务）"""
    key = (ip, domain)
    with _lock:
        if key in CERT_CACHE:
            return CERT_CACHE[key]
    v = _cert_probe(ip, domain)
    with _lock:
        if len(CERT_CACHE) > 2000:
            CERT_CACHE.clear()
        CERT_CACHE[key] = v
    return v


def _cert_probe(ip, domain):
    der = None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sk = ctx.wrap_socket(socket.create_connection((ip, 443), timeout=CERT_TIMEOUT),
                             server_hostname=domain)
        der = sk.getpeercert(True)
        sk.close()
    except Exception:
        return None
    if not der or not _DECODE_CERT or not _MATCH_HOSTNAME:
        return _cert_probe_fallback(ip, domain) if not der else None
    path = None
    try:
        fd, path = tempfile.mkstemp(prefix="dgcert")
        os.write(fd, ssl.DER_cert_to_PEM_cert(der).encode())
        os.close(fd)
        dec = _DECODE_CERT(path)
        try:
            _MATCH_HOSTNAME(dec, domain)
            return True
        except Exception:
            return False
    except Exception:
        return None
    finally:
        if path:
            try:
                os.unlink(path)
            except Exception:
                pass


def _cert_probe_fallback(ip, domain):
    """无法解析证书时的退路：用校验型握手，只在明显"域名不匹配"时返回 False。"""
    try:
        ctx = ssl.create_default_context()
        sk = ctx.wrap_socket(socket.create_connection((ip, 443), timeout=CERT_TIMEOUT),
                             server_hostname=domain)
        sk.close()
        return True
    except Exception as e:
        txt = (str(e) + " " + str(getattr(e, "verify_message", ""))).lower()
        if "hostname mismatch" in txt or "not valid for" in txt or "ip address mismatch" in txt:
            return False
        return None


# ---------------- 解析与查询 ----------------
# ===== 2026-10-05 方案1+2：类型化核对（dnsguard 侧）=====
# 覆盖 R8 完全不做的两类请求：
#   ① 非 A/AAAA 类型（TXT/MX/NS/CNAME/SOA/SRV/CAA/SVCB/HTTPS）—— R8 门控只认 {1,28}，这些直接透传；
#   ② CN 域名（.cn 后缀 + 8837 规则集合）—— R8 门控 not name.endswith(CN_SUFFIX) 把它们排除。
# 通道按名字属地选择：CN 名 → CN_DOT（国内 DoT），其余 → CLEAN_DOT（境外认证 DoT）。
# 判据（方向不对称，只抓"多出来的"）：注入只能**新增**记录，不能证明"删除"——
#   明文集 ⊄ 核对集        ⇒ 多出记录（r8t_extra）
#   明文为空而核对集非空    ⇒ 被静默掏空（r8t_empty）※ 实测 microsoft.com TXT: rc0 an=0 42B
#   双方都空               ⇒ 真 NODATA，不动
# 默认 **observe**（只计数留痕不改道），便于先统计误报；GUARD_CORROB_TYPES=enforce 才改道。
CN_DOT = [("223.5.5.5", 853, "dns.alidns.com"),
          ("223.6.6.6", 853, "dns.alidns.com"),
          ("218.30.118.6", 853, "dot.360.cn")]
R8T_MAP = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT",
           28: "AAAA", 33: "SRV", 257: "CAA", 64: "SVCB", 65: "HTTPS"}
# 刻意排除（拦了会砸掉 DNSSEC 链或特殊语义）：
#   43 DS / 48 DNSKEY / 46 RRSIG / 47 NSEC / 50 NSEC3 / 41 OPT / 255 ANY / 12 PTR
CORROB_TYPES_MODE = os.environ.get("GUARD_CORROB_TYPES", "observe").strip().lower()
if CORROB_TYPES_MODE not in ("observe", "enforce"):
    CORROB_TYPES_MODE = ""


def _c_key(name, qtype):
    """2026-10-28 N-2：缓存键加 ECS 维度 —— 不同 /24 的 geo/CDN 答案不得互穿。

    审计依据：此前 _cache / _neg_cache / _r8t_cache / _SF_CACHE / _corrob / _strict_neg
    都按 (name,qtype) 建键，实测三个不同 ECS 查同一域名返回同一地址 ⇒ 600s 内
    首个填充者的网段决定了所有人的答案。无 ECS 时 key 尾巴是 None，与改造前等价
    （旧条目随重启自然失效，属预期的一次冷启动）。
    """
    try:
        e = _cur_ecs_key()
    except Exception:
        e = None
    return (name, qtype, e)


_r8t_cache = {}
R8T_CACHE_MAX = 20000


def _r8t_get(name, qtype):
    """类型化核对结果的短窗缓存。目的：把对 CLEAN_DOT/CN_DOT 的额外查询
    限死成"每 (name,qtype) 每窗口一次" —— 否则 HTTPS/SVCB 这类高频类型会把
    公共解析器打成限流（铁律：公共解析器不能猛打）。"""
    e = _r8t_cache.get(_c_key(name, qtype))
    if e is not None and e[0] > time.time():
        return e[1]
    return None


def _r8t_put(name, qtype, vals, ttl):
    t = max(30, min(ttl if ttl else 60, 300))
    if len(_r8t_cache) > R8T_CACHE_MAX:
        _r8t_cache.clear()
    _r8t_cache[_c_key(name, qtype)] = (time.time() + t, vals)


def parse_q(msg):
    try:
        o = 12
        parts = []
        while msg[o]:
            n = msg[o]
            parts.append(msg[o + 1:o + 1 + n].decode("latin1"))
            o += 1 + n
        o += 1
        qtype, qclass = struct.unpack("!HH", msg[o:o + 4])
        return ".".join(parts), qtype
    except Exception:
        return None, None


def parse_a(msg):
    """返回 (rcode, [A/AAAA 地址], cname 条数, 最小TTL)"""
    try:
        _, rf, qd, an, _, _ = struct.unpack("!HHHHHH", msg[:12])
    except Exception:
        return (None, [], 0, 0)
    o = 12
    ips = []
    cn = 0
    ttls = []
    try:
        for _ in range(qd):
            while msg[o]:
                o += msg[o] + 1
            o += 5
        for _ in range(an):
            if msg[o] & 0xC0 == 0xC0:
                o += 2
            else:
                while msg[o]:
                    o += msg[o] + 1
                o += 1
            t, c, ttl, ln = struct.unpack("!HHIH", msg[o:o + 10])
            o += 10
            rd = msg[o:o + ln]
            o += ln
            if t == 1:
                ips.append(".".join(map(str, rd)))
                ttls.append(ttl)
            elif t == 28:
                h = struct.unpack("!8H", rd)
                ips.append("%x:%x:%x:%x:%x:%x:%x:%x" % h)
            elif t == 5:
                cn += 1
                ttls.append(ttl)
    except Exception:
        pass
    return (rf & 0xF, ips, cn, (min(ttls) if ttls else 0))


# ---------------- DNSSEC 否定证明（快路判据） ----------------
_RR_RRSIG, _RR_NSEC, _RR_NSEC3 = 46, 47, 50


def parse_meta(msg, qtype=None):
    """→ (rcode, AD, 有地址, 有CNAME, 权威段类型集合, NSEC3 opt-out, 答案段 RR 数, 该 qtype 答案数)

    ★ 2026-10-15 N2（第四份审计）：旧实现只统计 A/AAAA/CNAME 三种类型 ⇒ **TXT/MX/CAA 查询的
    正常正答案**（ANCOUNT=1、无地址、无 CNAME、AD=1）会落进"无地址无 CNAME"分支 ⇒
    `denial_proof()` 返回 "ad" ⇒ 见证结果被当成**否定** ⇒ 正常的国内候选被错误否决 ✗。
    现在额外返回"答案段 RR 总数"与"该 qtype 的答案数"，让否定判定建立在
    **答案段确实没有任何记录**之上（见 `denial_proof()`；qtype=None 时从 question 段取）。

    只服务"要不要走快路"的判断；任何异常都当作"没有证明"（fail-closed，继续走原来的干净上游比对）。"""
    try:
        _, rf, qd, an, ns, _ar = struct.unpack("!HHHHHH", msg[:12])
        rcode, ad = rf & 0xF, bool(rf & 0x0020)
    except Exception:
        return (None, False, False, False, set(), False, 0, 0)

    def skip_name(o):
        while o < len(msg):
            l = msg[o]
            if l == 0:
                return o + 1
            if l & 0xC0 == 0xC0:
                return o + 2
            o += 1 + l
        raise ValueError("bad name")

    o = 12
    has_addr = has_cname = False
    an_total = 0
    qhits = 0
    _qt = qtype
    try:
        for _i in range(qd):
            o = skip_name(o)
            if _i == 0 and _qt is None:
                _qt = struct.unpack("!H", msg[o + 2:o + 4])[0]
            o += 4
        for _ in range(an):
            o = skip_name(o)
            t, _c, _ttl, ln = struct.unpack("!HHIH", msg[o:o + 10])
            o += 10
            an_total += 1
            if _qt is not None and t == _qt:
                qhits += 1
            if t in (1, 28):
                has_addr = True
            elif t == 5:
                has_cname = True
            o += ln
        types, optout = set(), False
        for _ in range(ns):
            o = skip_name(o)
            t, _c, _ttl, ln = struct.unpack("!HHIH", msg[o:o + 10])
            o += 10
            # NSEC3 RDATA: 哈希算法(1) 标志(1) 迭代(2) 盐长(1)…　标志最低位 = opt-out
            if t == _RR_NSEC3 and ln >= 2 and (msg[o + 1] & 0x01):
                optout = True
            types.add(t)
            o += ln
    except Exception:
        return (rcode, ad, has_addr, has_cname, set(), False, an_total, qhits)
    return (rcode, ad, has_addr, has_cname, types, optout, an_total, qhits)


def denial_proof(msg, qtype=None):
    """unbound 的"给不出地址"应答是否带密码学否定证明 → "ad" / "nsec" / None

    判为证明必须同时成立：
      · rcode 是 NXDOMAIN(3) 或 NODATA(0)，且应答里既没有地址也没有 CNAME（含 CNAME 的走原逻辑）；
      · AD=1（unbound 端到端验证通过，本机 val-permissive-mode: no），或
        权威段同时含 RRSIG 与 NSEC / 非 opt-out 的 NSEC3。
    为什么排除 NSEC3 opt-out：opt-out 证明既能表示"名下无记录"，也能表示"未签名委派"，
    可以被重放来把真实存在的未签名域名说成不存在（RFC 7129 §6）—— 这类必须保留
    原来的境外干净上游交叉核对，否则就是引入投毒/审查绕过风险。"""
    rcode, ad, has_addr, has_cname, types, optout, an_total, qhits = parse_meta(msg, qtype)
    if rcode not in (0, 3):
        return None
    if an_total > 0:
        # ★ N2：答案段里有记录 ⇒ 这是**正答案**（或 CNAME 中间态），不是否定形态 ✗。
        # 旧实现只看 A/AAAA/CNAME ⇒ TXT/MX/CAA 的正答案被误判为否定 ⇒ 见证被错误采纳 ✗。
        try:
            _stats["denial_proof_answered"] = _stats.get("denial_proof_answered", 0) + 1
        except Exception:
            pass
        return None
    if has_addr or has_cname:
        return None
    if ad:
        return "ad"
    # P34-AR（方案任务2）：`AD=1` 是**本地验证器确认**的唯一硬证据 ✓。
    # 仅有 RRSIG/NSEC/NSEC3 材料时，远端可以重放来把"真实存在的未签名域"说成不存在
    # （RFC 7129 §6）⇒ 方案要求"**仅有RRSIG/NSEC不再认定为strong**" ✓。
    # 策略模式下因此不再认 nsec；默认 off ⇒ 保持今日行为 ✓。
    if POLICY_MODE:
        # 注意：`denial_proof()` 可能在**持锁**路径上被调用 ✓ ⇒ 这里只用**不加锁**的
        # 普通累加（与本文件既有风格一致 ✓），避免 `_lock` 重入死锁 ✗。
        _stats["denial_proof_noad"] = _stats.get("denial_proof_noad", 0) + 1
        return None
    if _RR_RRSIG in types and _RR_NSEC in types:
        return "nsec"
    if _RR_RRSIG in types and _RR_NSEC3 in types and not optout:
        return "nsec"
    return None


def dnssec_material(msg):
    """应答里是否已带 DNSSEC 材料（AD 位或权威段 RRSIG）——没有就说明上游没带 DO"""
    _rc, ad, _ha, _hc, types, _oo, _an, _qh = parse_meta(msg)
    return bool(ad) or _RR_RRSIG in types


def _dec_name(msg, o):
    """解码域名（支持压缩指针），返回 (小写名, 下一个偏移)。"""
    parts, jumped, nxt, hops = [], False, o, 0
    while o < len(msg):
        ln = msg[o]
        if ln == 0:
            o += 1
            if not jumped:
                nxt = o
            break
        if ln & 0xC0 == 0xC0:
            if o + 1 >= len(msg):
                break
            if not jumped:
                nxt = o + 2
                jumped = True
            o = ((ln & 0x3F) << 8) | msg[o + 1]
            hops += 1
            if hops > 24:
                break
            continue
        parts.append(msg[o + 1:o + 1 + ln].decode("latin1", "replace").lower())
        o += 1 + ln
    return ".".join(parts).rstrip("."), nxt


def parse_typed(msg):
    """通用解析：返回 (rcode, [(rtype, 归一化值)], 最小TTL)。方案2 的类型化核对用。
    归一化：域名类取目标名；MX/SRV/SVCB 带优先级等字段；TXT 取拼接字符串；CAA 取 flag|tag|value。"""
    rrs, min_ttl = [], 0
    try:
        _, rf, qd, an, _, _ = struct.unpack("!HHHHHH", msg[:12])
    except Exception:
        return (None, rrs, 0)
    o = 12
    try:
        for _ in range(qd):
            _, o = _dec_name(msg, o)
            o += 4
        for _ in range(an):
            _, o = _dec_name(msg, o)
            t, c, ttl, ln = struct.unpack("!HHIH", msg[o:o + 10])
            o += 10
            rs = o                      # rdata 的**绝对**起点：DNS 压缩指针相对整条报文，不能相对切片解
            rd = msg[o:o + ln]
            o += ln
            v = None
            if t == 1:
                v = ".".join(map(str, rd))
            elif t == 28:
                v = "%x:%x:%x:%x:%x:%x:%x:%x" % struct.unpack("!8H", rd)
            elif t in (2, 5, 12):
                v, _ = _dec_name(msg, rs)
            elif t == 15:
                v = "%d|%s" % (struct.unpack("!H", rd[:2])[0], _dec_name(msg, rs + 2)[0])
            elif t == 16:
                i, ss = 0, []
                while i < len(rd):
                    l2 = rd[i]
                    ss.append(rd[i + 1:i + 1 + l2].decode("latin1", "replace"))
                    i += 1 + l2
                v = "".join(ss)
            elif t == 33:
                pri, w8, port = struct.unpack("!HHH", rd[:6])
                v = "%d|%d|%d|%s" % (pri, w8, port, _dec_name(msg, rs + 6)[0])
            elif t == 257:
                tl = rd[1]
                v = "%d|%s|%s" % (rd[0], rd[2:2 + tl].decode("latin1", "replace"),
                                  rd[2 + tl:].decode("latin1", "replace"))
            elif t in (64, 65):
                v = "%d|%s" % (struct.unpack("!H", rd[:2])[0], _dec_name(msg, rs + 2)[0])
            elif t == 6:
                mn, o2 = _dec_name(msg, rs)
                v = "%s|%s" % (mn, _dec_name(msg, o2)[0])
            if v is not None:
                rrs.append((t, v))
                if min_ttl == 0 or ttl < min_ttl:
                    min_ttl = ttl
    except Exception:
        pass
    return (rf & 0xF, rrs, min_ttl)


def _type_vals(resp, qtype):
    """取应答里**该 qtype** 的归一化值集合（A/AAAA 走 _norm_ip，保证与 R8 同口径）。"""
    if not resp:
        return set()
    rc, rrs, _ttl = parse_typed(resp)
    vals = set(v for (t, v) in rrs if t == qtype)
    if qtype == 1:
        return set(_norm_ip(v) for v in vals)
    if qtype == 28:
        return set(v.lower() for v in vals)
    return vals


def mk_query(name, qtype=1, qid=None):
    if qid is None:
        qid = random.randint(0, 65535)
    qn = b"".join(bytes([len(p)]) + p.encode("latin1") for p in name.split(".")) + b"\x00"
    _e = _ecs_clause(_cur_ecs_rd())
    if not _e:
        return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qn + struct.pack("!HH", qtype, 1)
    # 2026-10-28：有客户端 ECS 时必须带 OPT(41)，否则 ECS 无处安放
    return (struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 1) + qn + struct.pack("!HH", qtype, 1)
            + b"\x00" + struct.pack("!HHIH", 41, 1232, 0x0000, len(_e)) + _e)


def mk_query_do(name, qtype=1, qid=None, no_ecs=False):
    """带 EDNS0 DO=1 的查询：本地向 unbound A 复问一次，用于取 DNSSEC 否定证明判据。

    unbound 只在查询带 DO（或 AD）时才回 NSEC/NSEC3/RRSIG 与 AD 位；上游没带 DO 时
    （例如有人绕过 AGH 直接问 dnsguard）就拿不到证明，快路会白白失效。"""
    if qid is None:
        qid = random.randint(0, 65535)
    qn = b"".join(bytes([len(p)]) + p.encode("latin1") for p in name.split(".")) + b"\x00"
    _e = b"" if no_ecs else _ecs_clause(_cur_ecs_rd())
    return (struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 1) + qn + struct.pack("!HH", qtype, 1)
            + b"\x00" + struct.pack("!HHIH", 41, 1232, 0x8000, len(_e)) + _e)


def udp_query(server, msg, timeout=TIMEOUT):
    try:
        import alt_adapter
        return alt_adapter.exchange_udp(server, msg, timeout)
    except Exception:
        return None


_POOL_N = max(1, int(os.environ.get("GUARD_DOT_POOL_N", "4")))   # 每通道常连接数
_pool = {}          # (ip,port,sni) -> [socket, ...]  空闲常连接（≤ _POOL_N）
_up_lock = {}       # (ip,port,sni) -> Lock           只保护 _pool 列表本身，不做 I/O
_up_sem = {}        # (ip,port,sni) -> BoundedSemaphore(_POOL_N)  该通道在途上限
_cache = {}         # (name,qtype) -> (expiry, resp)
_neg_cache = {}     # (name,qtype) -> (expiry, DNSSEC-proven negative response)
# ---- A3（2026-10-20）：**双源 SERVFAIL** 负缓存 ----
# 只记忆"认证源 A 与快速独立源**都明确回 rc=2**"这一种情形；值只有到期时间戳
#   ⇒ **不存任何应答字节** ✓（出包一律由 mk_servfail() 重建 ⇒ 无内容可注入 ✗）。
# 动机：死链域名（上游两端都拒绝）现状每次重走 W1 超时(1.2s) + alt(2.0s) 全链路
#   ⇒ 同一域名在 15s 内重复查询直接回 SERVFAIL ✓。
# 寿命**复用既有** STRICT_SERVFAIL_TTL（默认 15s）✓ —— 不新增任何 TTL 常量。
_SF_CACHE = {}      # (name,qtype) -> expiry
_SF_MAX = 20000
# ---- P2（2026-10-22）：失败域名的自适应负缓存（滚动续期）----
# 现场依据：同一死链域名在 15s 负缓存未命中时要重走 unbound A(643ms)+fastpass+alt(实测 10014ms)，
#   客户端可见 1202~3989ms；而重访间隔实测 300s ⇒ 15s 覆盖不到 ⇒ 每次重访都吃满。
# 机制：连续失败次数→指数退避 15/30/60/120/240/300（封顶 RFC9520 建议 5 分钟），成功即清零。
# 安全：与 A3 同源，只存 expiry 与计数，不存任何报文 ⇒ 出包一律 mk_servfail() 重建。
_SF_STREAK = {}     # (name,qtype) -> 连续失败次数（成功即清零）
def _cache_stamp():
    return {"wall": time.time(), "mono": time.monotonic()}


def _cache_replay(entry):
    """Old tuple entries are conservatively capped; new ones also age each RR."""
    if not entry:
        return None
    remaining = float(entry[0]) - time.time()
    if remaining <= 0:
        return None
    import alt_adapter
    elapsed = 0.0
    if isinstance(entry[-1], dict) and "mono" in entry[-1]:
        elapsed = max(0.0, time.monotonic() - entry[-1]["mono"],
                      time.time() - entry[-1]["wall"])
        remaining = min(remaining, float(entry[0]) - entry[-1]["wall"] - elapsed)
        if remaining <= 0:
            return None
    return alt_adapter.age_wire(entry[1], elapsed, max_ttl=remaining)

MAX_INFLIGHT = int(os.environ.get("GUARD_MAX_INFLIGHT", "64"))
MAX_PENDING = int(os.environ.get("GUARD_MAX_PENDING", "128"))
# 2026-10-07：ThreadPoolExecutor 的**内部队列是无界的** —— 只要 submit 成功，任务就会一直排队，
# 而排队中的查询既不会被回答、也没有任何超时 ⇒ 上游（AGH）看到的就是"静默 10 秒 i/o timeout"。
# 因此必须在 submit **之前**做有界准入：拿不到名额就立刻回 SERVFAIL，绝不让任务进无界队列。
# MAX_INFLIGHT + MAX_QUEUE 就是"最多允许多少个请求同时在飞或排队"的硬上限。
MAX_QUEUE = int(os.environ.get("GUARD_MAX_QUEUE", "16"))
_inflight_sem = threading.BoundedSemaphore(MAX_INFLIGHT)
_dispatch_sem = threading.BoundedSemaphore(MAX_PENDING)
_executor_slots = threading.BoundedSemaphore(MAX_INFLIGHT + MAX_QUEUE)
_reject_slots = threading.BoundedSemaphore(2)
_reject_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="reject")
_dispatch_reject = 0
_executor = ThreadPoolExecutor(max_workers=MAX_INFLIGHT, thread_name_prefix="guard")

# 2026-10-09 阶段3：**探针专用通道**。
# 动机：闸门是全局的，压测/探针会占满用户槽位（实测 60 QPS 冷 CN 压测时家庭查询被一起拒）。
# 做法：另开一个监听端口，配一套**完全独立**的信号量/线程池/计数；探针请求仍走同一
# handle() 解析流程，但不触碰用户的 _inflight_sem / _dispatch_sem / _executor_slots，
# 也不进用户的 admission_reject（避免压测误触发"拥塞后自动清缓存"）。
# 监听地址默认 172.18.0.1（docker 网桥），家庭用户经 AGH 走 5355，碰不到 5356。
PROBE_LISTEN_HOST = os.environ.get("GUARD_PROBE_HOST", "172.18.0.1")
PROBE_LISTEN_PORT = int(os.environ.get("GUARD_PROBE_PORT", "5356"))
MAX_PROBE_INFLIGHT = int(os.environ.get("GUARD_PROBE_MAX_INFLIGHT", "8"))
MAX_PROBE_PENDING = int(os.environ.get("GUARD_PROBE_MAX_PENDING", "16"))
MAX_PROBE_QUEUE = int(os.environ.get("GUARD_PROBE_MAX_QUEUE", "8"))
_probe_inflight_sem = threading.BoundedSemaphore(MAX_PROBE_INFLIGHT)
_probe_dispatch_sem = threading.BoundedSemaphore(MAX_PROBE_PENDING)
_probe_executor_slots = threading.BoundedSemaphore(MAX_PROBE_INFLIGHT + MAX_PROBE_QUEUE)
_probe_executor = ThreadPoolExecutor(max_workers=MAX_PROBE_INFLIGHT, thread_name_prefix="guard-probe")
_probe_pending = 0
# 2026-10-07：R8 核对的**扇出执行器**。每次核对会给每条认证通道各 submit 一个任务
# （境外 CLEAN_DOT=3 条；CN 目标 CN_DOT=6 条）⇒ 它比 _corrob_sem 更早触顶：
# corrob_sem=6 且境外 3 通道时最多 18 个任务同时在飞，而这里原先是写死的 8。
# 所以"只把 semaphore 从 4 提到 6"是不够的 —— 必须同时确认执行器容量 ≥ 并发核对数 × 通道数。
_r8_executor = ThreadPoolExecutor(
    max_workers=int(os.environ.get("GUARD_R8_WORKERS", "8")),
    thread_name_prefix="r8",
)
_upstream_executor = ThreadPoolExecutor(
    max_workers=int(os.environ.get("GUARD_UPSTREAM_WORKERS", "8")),
    thread_name_prefix="upstream",
)
_cold_sem = threading.BoundedSemaphore(COLD_MAX)
_pending_lock = threading.Lock()
_pending_count = 0
_corrob_locks = {}
_query_locks = {}
# 2026-10-10 Patch15（Codex P3）：两表按 (name,qtype) 无限增长（MemoryMax=128M）⇒ 加上界。
LOCK_TABLE_MAX = int(os.environ.get("GUARD_LOCK_TABLE_MAX", "8000"))


def _locks_trim(d, cap=None):
    """只清理**未被持有**的锁条目（持有中的条目若被清掉会破坏单飞语义）。"""
    cap = cap or LOCK_TABLE_MAX
    if len(d) <= cap:
        return
    target = int(cap * 0.8)
    with _lock:
        for k in [k for k, v in list(d.items()) if not v.locked()]:
            d.pop(k, None)
            if len(d) <= target:
                break
        _stats["locks_trimmed"] = _stats.get("locks_trimmed", 0) + 1


def _query_lock_get(key):
    with _lock:
        lk = _query_locks.get(key)
        if lk is None:
            lk = threading.Lock()
            _query_locks[key] = lk
    _locks_trim(_query_locks)
    return lk


def _cn_bget_lazy(msg, name):
    """给"单飞合并"路径补一个 **与 `domestic()` 返回值同签名** 的 `bget` ✓。

    `domestic()` 的第三元素是"取 B 应答字节"的函数 ✓；单飞合并那批请求**没有**做外部取数
    ⇒ 也就没有那个闭包 ✗，但后续 R8 段仍会调 `bget()` ✓ ⇒ 这里用**同一条收口函数**
    （`resolve_cn_via_unbound_b`，内部做 CN 判定与记账 ✓）做一个惰性版本 ✓
    —— 不引入新路径、不改语义 ✓。

    ★ 放在**模块级**而不是 `handle()` 内的嵌套 `def` ✗：`handle()` 有一条 AST 回归断言
    （`test_guard_finalizer.HandleHasNoBypass`）要求"handle 内每条 `return` 都必须是统一出口闸门
    或 None"✓；嵌套函数里的 `return <普通调用>` 会被 `ast.walk` 一起扫进来 ✗ 造成假阳性 ✗。
    移到模块级后两边都干净 ✓（闸门断言继续把 handle 管住 ✓，本函数自身也不在闸门管辖内 ✓）。
    """
    def _bget():
        return resolve_cn_via_unbound_b(msg, name, consumer="guard_cn")
    return _bget


def _sf_key(name, qtype):
    """单飞键 = `(name, qtype, view, flags, policy)` ✓ —— 方案 §3 第 73 行。

    ★ 为什么键里必须有 `qtype` ✗：不同 qtype **绝不共用答案** ✓（方案逐字要求 ✗）——
      A 与 AAAA 的上游应答是两份不同的 RRset，合并就是把 A 的字节当 AAAA 发出去 ✗。
    ★ 为什么要有 `view` ✗：`_adm_cache_get()` 已按 view/do/cd/ecs/qclass 分视图 ✓，
      单飞若不带上同样的维度，就会出现"在两个视图之间共用一次上游查询" ✗
      —— 这正是 §2 第 48 行禁止的"无法证明同一视图时不共用缓存"✓。当前链路
      view 恒为 `"default"`、do=True、cd=False、ecs=None、qclass=1（见 `_adm_cache_put` 现场依据）
      ⇒ 本键由此**自动**落在同一档 ✓；将来打开 ECS/CD 时键会自动分化 ✓，无需再改。
    """
    # 2026-10-28 N-1: ECS is enabled chain-wide since 13:22, so the old note claiming
    # "ecs=None always holds and the key will split automatically" is no longer valid.
    # Put the ECS view into the single-flight key explicitly.
    return ("sf", str(name).lower(), int(qtype or 0), _cur_ecs_key(), "default", "do1/cd0", bool(POLICY_MODE))


# ★ 方案 §3 第 73 行：**同 question/view/flags/policy 的并发请求必须合并** ✓。
#   现场缺口（§3 完成门首轮实测 ⑤ `A=100/100` 证实 ✗）：
#     · `_dot_query_cold()` 的单飞只管**冷 DoT** ✓，对 A/B 两条本地上游**完全无效** ✗
#       ⇒ 100 个相同冷查询把 A 打 100 次 ✗（方案第 76 行明令禁止 ✗）；
#     · 更关键：原实现只让等待者"等锁 + 再探一次准入缓存"✓，但**非 CN 名压根没接入** ✗，
#       而准入缓存的写入发生在 `_finalize_return()`（比 A 查询**晚得多**）✗
#       ⇒ 即使接入，等待者醒来时缓存**通常还是空的** ⇒ 照样自己扇出 ✗（等于没合并 ✗）。
#   正确做法 = **把领跑者的结果直接交给等待者** ✓（"结果贯穿"而非"等锁再猜"✓）。
#   为此用 `_sf_slot` 承载：领跑者完成后 `publish()` ✓，等待者 `recv()` 拿到同一份字节 ✓。
class _SfSlot(object):
    """一次单飞"结果盒"：领跑者发布 → 等待者复用 ✓（方案第 73 行"结果贯穿"）。

    ★ `done_ts` 是**复用闸门** ✗：只有"进入等待**之前**领跑者就已发布"的结果才允许复用 ✓。
      否则一个**后来的新请求**（锁空闲 ⇒ 走快路拿到 owned）会顺手把上一轮的旧字节当新答案 ✓
      —— 那等于绕过了准入门闩与 TTL 老化 ✗（方案第 55 行禁止 ✗）。
      "进入时刻"由调用方传入（`_sf_enter` 记录），不用当前时间 ⇒ 判据与调度抖动无关 ✓。
    """

    __slots__ = ("ev", "val", "ts", "done_ts")

    def __init__(self):
        self.ev = threading.Event()
        self.val = None          # (uresp, src) 或 ("__none__", None)
        self.ts = time.time()
        self.done_ts = None      # 领跑者发布时间（monotonic）

    def publish(self, val):
        self.val = val
        self.done_ts = time.monotonic()
        self.ev.set()

    def reuse(self, entered_at):
        """领跑者的结果能否被**本次等待**复用 ✓（含"领跑者确实没答案"⇒ 返回 None 不拦 ✗）。"""
        if self.done_ts is None or self.done_ts < entered_at:
            return None
        v = self.val
        if v is None or (isinstance(v, tuple) and v[0] == "__none__"):
            return None
        return v

    def recv(self, wait, entered_at):
        """等待领跑者并取结果 ✓；未就绪/超时/结果不可复用 ⇒ None（调用方**照旧自己查** ✓）。"""
        if wait <= 0:
            return None
        if not self.ev.wait(wait):
            return None
        return self.reuse(entered_at)


_SF_SLOTS = {}
_SF_SLOTS_MAX = int(os.environ.get("GUARD_SF_SLOTS_MAX", "4000"))


def _sf_slot_get(key):
    with _lock:
        sl = _SF_SLOTS.get(key)
        if sl is None:
            sl = _SfSlot()
            _SF_SLOTS[key] = sl
        if len(_SF_SLOTS) > _SF_SLOTS_MAX:
            _now = time.monotonic()
            for k in [k for k, v in list(_SF_SLOTS.items())
                      if v.done_ts is not None and _now - v.done_ts > 30.0]:
                _SF_SLOTS.pop(k, None)
                if len(_SF_SLOTS) <= int(_SF_SLOTS_MAX * 0.8):
                    break
        return sl


def _sf_enter(name, qtype):
    """进入单飞：返回 `(lk, slot, owned)` ✓（方案第 73 行）。

    · `owned=True` ⇒ 本请求是**领跑者** ✓，负责外部取数并在完成后 `slot.publish()` ✓；
    · `owned=False` 且 `slot` 非 None ⇒ 本请求是**等待者** ✓，
      用 `slot.recv(...)` / `slot.reuse(...)` 复用领跑者结果 ✓；
      超时或领跑者也无答案 ⇒ 调用方照旧自己查 ✓（绝不放空 ✗）。
    · **等锁成功 ≠ 领跑者** ✗（这是首轮实测 `A=100/100` 的根因 ✗）：
      100 个并发请求里，除第一个外都要排队等锁 ✓；若把"等到锁"当成"轮到我了"，
      就会**串行地把 A 打 100 次** ✗ —— 旧实现的"等锁 + 再探准入缓存"正是如此，
      而准入缓存要到 `_finalize_return()` 才写入 ✗ ⇒ 等待者醒来时缓存**通常是空的** ✗
      ⇒ 100 次外部查询 ✗。修法：**等锁成功后先看结果盒** ✓，领跑者已发布就**直接复用并放锁** ✓。
    · 等锁时间 = `min(剩余预算 - 保留量, 2.0)` ✓ —— 等待者**绝不能**因等锁耗光自己
      4 秒总预算 ✗（方案第 67 行"所有等待只用剩余预算"✓）；预算不足 ⇒ `(None, slot, False)`
      ⇒ 调用方照旧自己查 ✓（绝不无限等、绝不返回空 ✗）。
    """
    entered_at = time.monotonic()
    key = _sf_key(name, qtype)
    lk = _query_lock_get(key)
    slot = _sf_slot_get(key)
    if lk.acquire(False):
        try:
            _stats["cn_sf_lead"] = _stats.get("cn_sf_lead", 0) + 1
        except Exception:
            pass
        return lk, slot, True
    _rem = _dl_rem()
    wait = 2.0 if _rem is None else max(0.0, min(2.0, _rem - 0.6))
    if wait <= 0.05:
        try:
            _stats["cn_sf_budget_skip"] = _stats.get("cn_sf_budget_skip", 0) + 1
        except Exception:
            pass
        return None, slot, False
    _t = time.monotonic()
    got = lk.acquire(True, wait)
    try:
        _tr_note("cn_sf", (time.monotonic() - _t) * 1000.0, "ok" if got else "timeout")
        if got:
            _stats["cn_sf_wait_ok"] = _stats.get("cn_sf_wait_ok", 0) + 1
        else:
            _stats["cn_sf_wait_timeout"] = _stats.get("cn_sf_wait_timeout", 0) + 1
    except Exception:
        pass
    if got and slot.reuse(entered_at) is not None:
        # 领跑者已在**我们进入等待之前**发布 ✓ ⇒ 放锁当等待者 ✓（绝不串行重查 ✗）
        try:
            lk.release()
        except Exception:
            pass
        try:
            _stats["cn_sf_reuse_handoff"] = _stats.get("cn_sf_reuse_handoff", 0) + 1
        except Exception:
            pass
        return None, slot, False
    return (lk if got else None), slot, bool(got)


def _corrob_lock_get(key):
    with _lock:
        lk = _corrob_locks.get(key)
        if lk is None:
            lk = threading.Lock()
            _corrob_locks[key] = lk
    _locks_trim(_corrob_locks)
    return lk


def submit_limited(fn, *args):
    """有界提交：准入失败返回 False，调用方**必须立刻回 SERVFAIL**。

    不要再用 ThreadPoolExecutor 的内部队列做过载缓冲 —— 它是无界的，排队即"静默不答"。
    这里把"在飞 + 排队"的总量钉死在 MAX_INFLIGHT + MAX_QUEUE。
    """
    if not _executor_slots.acquire(False):
        return False

    def wrapped():
        try:
            return fn(*args)
        finally:
            _executor_slots.release()

    try:
        _executor.submit(wrapped)
    except Exception:
        _executor_slots.release()
        return False
    return True


def _bump_q(key):
    """`_stats` 递增（持 `_lock`）✓ —— 键**预先枚举**在 `_stats` 字面量里 ⇒ 有界 ✓。"""
    _stats[key] = _stats.get(key, 0) + 1


def _tcp_reject_worker(conn):
    try:
        _tcp_overload_servfail(conn)
    finally:
        _reject_slots.release()


def _tcp_fast_reject(conn):
    """TCP 过载拒绝：交给**独立的 2 线程 reject 池**去"读查询 → 回 SERVFAIL"。

    绝不进主 executor（否则又变成排队等 worker）。reject 池也满时，才允许直接关连接。
    """
    if not _reject_slots.acquire(False):
        try:
            conn.close()
        except Exception:
            pass
        return
    try:
        _reject_executor.submit(_tcp_reject_worker, conn)
    except Exception:
        _reject_slots.release()
        try:
            conn.close()
        except Exception:
            pass


def _pool_lock(key):
    """该通道的**短临界区**锁：只保护 _pool[key] 列表本身，**绝不做网络 I/O**。"""
    with _lock:
        if key not in _up_lock:
            _up_lock[key] = threading.Lock()
        return _up_lock[key]


def _pool_sem(key):
    """该通道的在途上限（= _POOL_N）；到上限就等，**不新建连接**。"""
    with _lock:
        if key not in _up_sem:
            _up_sem[key] = threading.BoundedSemaphore(_POOL_N)
        return _up_sem[key]


def _pool_take(key):
    """取一条空闲常连接；没有则返回 None（调用方自己建连）。FIFO 轮转以兼顾保活。"""
    with _pool_lock(key):
        lst = _pool.get(key)
        if lst:
            return lst.pop(0)
    return None


def _pool_give(key, s):
    """把用完的连接还回池；池已满则关闭多余连接（不会无限增长）。"""
    keep = False
    with _pool_lock(key):
        lst = _pool.setdefault(key, [])
        if len(lst) < _POOL_N:
            lst.append(s)
            keep = True
    if not keep:
        try:
            s.close()
        except Exception:
            pass


def _recvn(sock, n):
    """读满 n 字节；对端提前关闭则返回已读部分（**不再忙循环**）。"""
    buf = b""
    try:
        while len(buf) < n:
            d = sock.recv(n - len(buf))
            if not d:
                break
            buf += d
    except Exception:
        pass
    return buf


def _is_tc(resp):
    """应答是否带 TC（截断）位。"""
    return bool(resp) and len(resp) > 3 and (resp[2] & 0x02)


def tcp_query(addr, msg, timeout=2.0):
    """明文 TCP 查询（帧格式同 DoT，只是不套 TLS）。

    2026-10-05：修大应答截断。根因实测 —— unbound 的 edns-buffer-size=1232，
    向 dnscrypt-proxy 取大应答（如 24 条 TXT ≈1928B）时被置 TC，而它**不回退 TCP**，
    于是把 an=0/TC 的截断应答往上抛（github/apple/cloudflare/reddit/netflix 等 10/17 域名失败）。
    而 unbound 的 TCP 口（127.0.0.1:5353）实测能返回完整应答（an=24）。
    """
    s = None
    try:
        s = socket.create_connection(addr, timeout)
        s.settimeout(timeout)
        s.sendall(struct.pack("!H", len(msg)) + msg)
        h = _recvn(s, 2)
        if len(h) < 2:
            return None
        ln = struct.unpack("!H", h)[0]
        buf = _recvn(s, ln)
        if len(buf) < ln:
            return None
        import alt_adapter
        if not alt_adapter.response_matches(msg, buf):
            return None
        return buf
    except Exception:
        return None
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def _dot_raw(msg, ip, port, sni, timeout):
    """用常连接池发一次 DoT 查询；失败则重连一次。

    ★ 2026-10-18（批次 3）：每通道由「1 条连接 + 全通道串行锁」改为
      「_POOL_N 条连接池 + BoundedSemaphore 限流」。
      实测旧写法下同一通道 6 路并发呈 +282ms 线性台阶
      （[284,565,846,1129,1411,1694]，墙钟 1695ms），24 路冷并发 p90 因此被抬到 1834ms；
      改后各路各用一条已建连接，墙钟 ≈ 单路耗时。
      **判定语义完全不变**：合格答案定义、qid 校验、两次重连后放弃都不动。
    """
    key = (ip, port, sni)
    sem = _pool_sem(key)
    t0 = time.time()
    # 等不到槽位就放弃（不新建连接）；上限压在 min(timeout,1.5)，
    # 保证「等待 + 实查」不会突破 GUARD_SYNC_BUDGET(3.8) / CORROB_DOT_TIMEOUT(1.8)。
    if not sem.acquire(timeout=min(timeout, 1.5)):
        with _lock:
            _stats["dot_pool_busy"] = _stats.get("dot_pool_busy", 0) + 1
        return None
    try:
        for attempt in (1, 2):
            s = _pool_take(key)
            try:
                if s is None:
                    ctx = ssl.create_default_context()
                    s = ctx.wrap_socket(socket.create_connection((ip, port), timeout=timeout),
                                        server_hostname=sni)
                s.settimeout(max(0.5, timeout - (time.time() - t0)))
                s.sendall(struct.pack("!H", len(msg)) + msg)
                h = _recvn(s, 2)
                if len(h) < 2:
                    raise IOError("EOF 读取长度头")
                ln = struct.unpack("!H", h)[0]
                buf = _recvn(s, ln)
                if len(buf) < ln:
                    raise IOError("EOF 读取正文 %d/%d" % (len(buf), ln))
                # ★ 2026-10-11：常连接池的错位/陈旧帧 ⇒ qid 必须先核，否则"上一问的字节"会被当成本问结论 ✗
                try:
                    import alt_adapter
                    if not alt_adapter.response_matches(msg, buf):
                        with _lock:
                            _stats["dot_qid_mismatch"] = _stats.get("dot_qid_mismatch", 0) + 1
                        raise IOError("qid 不匹配（连接错位/陈旧帧）")
                except struct.error:
                    raise IOError("正文过短无法读 qid")
                _pool_give(key, s)      # 成功：连接还回池，供后续复用
                return buf
            except Exception:
                try:
                    s.close()
                except Exception:
                    pass
                # 失败的连接已从池中取出，直接丢弃；下一轮 _pool_take 会重新建连
                if attempt == 2:
                    return None
    finally:
        sem.release()


def _udp_raw(msg, ip, port, timeout):
    """一次 UDP 查询：**必须核对应答的 qid**，否则会把别人的应答当成自己的 ✗。

    ★ 2026-10-11 现场根因（§5 验收期实测定位，非 §5 引入）：
      本机 UDP 转发器 `127.0.0.1:5533`（aghdq→NextDNS）在**并发**下偶发把查询**原样回显**成
      `flags 0x0100 → 0x8180` 的"空 NOERROR（rc=0 an=0 ns=0 ar=1）"（qid 不变）；
      同一压测里还观察到 **qid 与本次不符** 的应答被投递到本 socket 上 ✗ ——
      旧代码 `d, _ = s.recvfrom(65535)` **丢弃 peer 地址、从不比对 qid** ⇒
      这份"别人的 46 字节应答"会被当成本次查询的结论，并被 `_dot_query_once` 缓存 60s ✗。
      修法：qid 不匹配（或响应不是"回应本问题"）⇒ 丢弃并**有界重收**；收不到就返回 None ✓。
      这不会改变任何"合格答案"的定义，只把"明显不属于本次查询的字节"挡在门外 ✓。
    """
    return udp_query((ip, port), msg, timeout)


def _upstream_call(ip, port, sni, msg, timeout):
    if sni is None:
        return _udp_raw(msg, ip, port, timeout)
    return _dot_raw(msg, ip, port, sni, timeout)


# ---- B1（2026-10-09）：可选的低延迟干净候选通道，默认关闭 ----
# GUARD_FAST_UDP="127.0.0.2:5353" = 本机 dnscrypt-proxy（DNSCrypt 加密 + 匿名中继）。
# ★ 2026-10-10 更正：加密只保证"到上游那一段传输不被改写"，**不保证上游返回的答案未被污染**。
#   独立核验实测到它与 3 家认证 DoT 在多个 TikTok 主机名上答案与 CNAME 链结构都不同
#   （见 verify_report_corrected_20261010.md §2.1）⇒ **其来源可信度须单独核验**，
#   在核验通过前不得作为"可信共识来源"引用。仅加入 _dot_query_once 的**首轮 fast 集合**；不改变：
#   · 合格答案定义（rcode 非 SERVFAIL/REFUSED）
#   · R8 认证核对通道（仍只用 CLEAN_DOT）
#   · 熔断 / 保活 / 缓存语义
def _parse_fast_udp():
    v = (os.environ.get("GUARD_FAST_UDP") or "").strip()
    if not v:
        return None
    try:
        host, _, p = v.rpartition(":")
        return (host, int(p))
    except Exception:
        return None


FAST_UDP = _parse_fast_udp()
# 2026-10-10 Patch6（Codex ⑤，依据 verify_report_v2 §9 独立核验）：
#   dnscrypt-proxy 在多个 TikTok/Googlevideo 主机名上与 3 家认证 DoT 的答案与 CNAME 链结构均不同，
#   来源待核验。它的采纳路径是"首轮竞速赢者即被采纳、不经 R8"，且同一 dot_query 还被 R3 与侧车
#   verifier.py 使用 ⇒ 一旦被污染会把伪造答案直接下发。⇒ **默认不再采纳它的答案**；
#   若完成上游核验需恢复：设 GUARD_DNSCRYPT_ADOPT=1 并 systemctl restart dnsguard。
DNSCRYPT_ADOPT = FAST_UDP if _flag("GUARD_DNSCRYPT_ADOPT", False) else None


# ---- DNSCrypt 影子核验（2026-10-09，默认关闭）----
# 目的：为"是否允许 DNSCrypt 进入 R8 正式信任路径"收集证据。
# 语义保证（务必保持）：**只记录，不参与任何决策** —— 不回写 holder/不 return/不改 uresp/cresp、
# 不影响 redirect/fail_closed/r8_* 计数。按 GUARD_SHADOW_PCT 采样，异常一律吞掉。
# 比对对象：DNSCrypt 的答案 vs **本次 DoT 核对结果**（现有信任锚），同时记录明文侧供参考。
SHADOW_DNSCRYPT = (os.environ.get("GUARD_SHADOW_DNSCRYPT") or "").strip()
SHADOW_PCT = int(os.environ.get("GUARD_SHADOW_PCT", "50") or "50")


def _shadow_target():
    try:
        host, _, port = SHADOW_DNSCRYPT.rpartition(":")
        return (host, int(port)) if host else None
    except Exception:
        return None


SHADOW_TARGET = _shadow_target()
_shadow_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="shadow")
# Patch6：影子采样改为**有界**（区分"没采到"与"排队后补采"）+ 对争议名字 100% 采样
_SHADOW_MAX = int(os.environ.get("GUARD_SHADOW_MAX", "4") or 4)
_shadow_sem = threading.BoundedSemaphore(_SHADOW_MAX)
_SHADOW_ALWAYS = tuple(x.strip() for x in (os.environ.get(
    "GUARD_SHADOW_ALWAYS", "googlevideo.com,tiktokcdn.com,tiktokv.com") or "").split(",") if x.strip())


def _shadow_always(name):
    n = (name or "").lower()
    return any(n.endswith(x) or ("." + x) in n for x in _SHADOW_ALWAYS)
_shadow_recent = []


def _shadow_worker(msg, name, qtype, uset8, cset8):
    tgt = SHADOW_TARGET
    if not tgt:
        return
    t0 = time.time()
    try:
        b = _udp_raw(msg, tgt[0], tgt[1], 3.0)
    except Exception:
        b = None
    dt = round((time.time() - t0) * 1000.0, 1)
    with _lock:
        _stats["shadow_tried"] = _stats.get("shadow_tried", 0) + 1
    if not b:
        with _lock:
            _stats["shadow_unavailable"] = _stats.get("shadow_unavailable", 0) + 1
        return
    try:
        rc, ips, _cn, _mt = parse_a(b)
    except Exception:
        rc, ips = None, []
    sset = set(_norm_ip(x) for x in (ips or []))
    try:
        ad = bool(b[3] & 0x20)
    except Exception:
        ad = None
    # Patch6（Codex）：一致性不能只看"集合相等"——CDN 轮转下多/少一个地址就被判 disagree，
    # 会同时产生假阳与假阴。改为：有交集 且（相等 或 子集 或 超集）= 一致（并细分）。
    only_shadow = sorted(x for x in (sset - cset8) if isinstance(x, str))
    only_dot = sorted(x for x in (cset8 - sset) if isinstance(x, str))
    with _lock:
        if sset and cset8:
            inter = bool(sset & cset8)
            if inter and sset == cset8:
                _stats["shadow_agree"] = _stats.get("shadow_agree", 0) + 1
                return
            if inter and (sset < cset8 or cset8 < sset):
                _stats["shadow_agree"] = _stats.get("shadow_agree", 0) + 1
                _stats["shadow_agree_partial"] = _stats.get("shadow_agree_partial", 0) + 1
                _stats["shadow_agree_sub" if sset < cset8 else "shadow_agree_super"] = \
                    _stats.get("shadow_agree_sub" if sset < cset8 else "shadow_agree_super", 0) + 1
                return
            if not inter:
                _stats["shadow_disagree"] = _stats.get("shadow_disagree", 0) + 1
                side = "plain" if (bool(sset & uset8) and not bool(sset & cset8)) else "other"
            else:
                _stats["shadow_partial"] = _stats.get("shadow_partial", 0) + 1
                side = "partial"
        else:
            _stats["shadow_empty"] = _stats.get("shadow_empty", 0) + 1
            side = "empty"
        _shadow_recent.append({"t": time.strftime("%F %T"), "name": name, "qtype": qtype,
                               "ms": dt, "rc": rc, "ad": ad, "side": side,
                               "only_shadow": only_shadow[:6], "only_dot": only_dot[:6],
                               "dot": sorted(x for x in cset8 if isinstance(x, str))[:6],
                               "shadow": sorted(x for x in sset if isinstance(x, str))[:6],
                               "plain": sorted(x for x in uset8 if isinstance(x, str))[:6]})
        del _shadow_recent[:-40]
    log("SHAD  %-38s 影子不一致(%s) dot=%s shadow=%s ad=%s %.0fms"
        % (name, side, ",".join(sorted(x for x in cset8 if isinstance(x, str)))[:22],
           ",".join(sorted(x for x in sset if isinstance(x, str)))[:22], ad, dt))


def _shadow_done(done):
    """Patch6-§1.2：槽位生命周期 = worker 结束，**只在此处（回调）release 一次**。
    worker 内部不再 release；submit 失败路径在 shadow_note 里单独 release。"""
    bad = True
    try:
        bad = bool(done.cancelled()) or (done.exception() is not None)
    except Exception:
        bad = True
    with _lock:
        if bad:
            _stats["shadow_worker_error"] = _stats.get("shadow_worker_error", 0) + 1
        _stats["shadow_completed"] = _stats.get("shadow_completed", 0) + 1
        _stats["shadow_pending"] = max(0, _stats.get("shadow_pending", 0) - 1)
    _shadow_sem.release()


def shadow_note(msg, name, qtype, uset8, cset8):
    """R8 决策之外旁路记录。任何异常都不允许冒泡到解析路径。

    Patch6-§1.2：删除原有两个独立随机门（有效采样率 ≈ p²≈1%，41min/q=1520 下
    shadow_tried=0），替换为**恰好一次**抽样；pct<=0 表示整体关闭（always 域名同样关闭）。
    槽位持有到 worker 结束（有界：pending 含排队与运行，上限 _SHADOW_MAX=4、workers=2）。
    """
    if not SHADOW_TARGET or SHADOW_PCT <= 0:
        return
    try:
        with _lock:
            _stats["shadow_eligible"] = _stats.get("shadow_eligible", 0) + 1
        # Patch6-§1.2：单次抽样（always 域名在 pct>0 时不抽样，全采）。
        if not _shadow_always(name) and random.randrange(100) >= SHADOW_PCT:
            with _lock:
                _stats["shadow_sample_skip"] = _stats.get("shadow_sample_skip", 0) + 1
            return
        if not _shadow_sem.acquire(False):
            with _lock:
                _stats["shadow_capacity_skip"] = _stats.get("shadow_capacity_skip", 0) + 1
                _stats["shadow_skipped"] = _stats.get("shadow_skipped", 0) + 1
            return
        # 成功 submit 前先记 pending（峰值同步更新）；submit 异常时减回。
        with _lock:
            _stats["shadow_pending"] = _stats.get("shadow_pending", 0) + 1
            if _stats["shadow_pending"] > _stats.get("shadow_pending_peak", 0):
                _stats["shadow_pending_peak"] = _stats["shadow_pending"]
        try:
            future = _shadow_pool.submit(_shadow_worker, msg, name, qtype, uset8, cset8)
        except Exception:
            with _lock:
                _stats["shadow_pending"] = max(0, _stats.get("shadow_pending", 0) - 1)
                _stats["shadow_submit_error"] = _stats.get("shadow_submit_error", 0) + 1
            _shadow_sem.release()
            return
        with _lock:
            _stats["shadow_submitted"] = _stats.get("shadow_submitted", 0) + 1
        future.add_done_callback(_shadow_done)
    except Exception:
        pass


def shadow_snapshot():
    with _lock:
        return {"config": {"target": SHADOW_DNSCRYPT, "pct": SHADOW_PCT},
                "tried": _stats.get("shadow_tried", 0), "agree": _stats.get("shadow_agree", 0),
                "disagree": _stats.get("shadow_disagree", 0),
                "empty": _stats.get("shadow_empty", 0),
                "unavailable": _stats.get("shadow_unavailable", 0),
                # Patch6-§1.2：有界提交记账（不变量 submitted == completed + pending）
                "eligible": _stats.get("shadow_eligible", 0),
                "sample_skip": _stats.get("shadow_sample_skip", 0),
                "capacity_skip": _stats.get("shadow_capacity_skip", 0),
                "submitted": _stats.get("shadow_submitted", 0),
                "completed": _stats.get("shadow_completed", 0),
                "pending": _stats.get("shadow_pending", 0),
                "pending_peak": _stats.get("shadow_pending_peak", 0),
                "submit_error": _stats.get("shadow_submit_error", 0),
                "worker_error": _stats.get("shadow_worker_error", 0),
                "recent": list(_shadow_recent[-20:])}


def shadow_writer():
    if not SHADOW_TARGET:
        return
    while True:
        try:
            time.sleep(120)
            st = shadow_snapshot()
            st["updated"] = time.time()
            _atomic_json(os.path.join(STATE_DIR, "shadow-dnscrypt.json"), st)
        except Exception:
            pass


def _channel_label(ip, port, sni):
    if sni is None:
        if FAST_UDP and (ip, port) == FAST_UDP:
            return "dnscrypt"
        # 2026-10-19：原写法 `doq` if port==[0] else `doq2` 会把第三条通道(5535)误标成
        # doq2，与 aghdq2(5534) 共用同一个熔断器/统计槽 ⇒ 改为按索引查找。
        for _i, _hp in enumerate(LOCAL_DOQ_LIST):
            if port == _hp[1]:
                return "doq" if _i == 0 else ("doq2" if _i == 1 else "doq3")
        return "doq2"
    return "dot:" + sni.split(".")[-2]

def _channel_usable(ip, port, sni):
    label = _channel_label(ip, port, sni)
    with _lock:
        st = _ch_stat.get(label)
    # 尚未有健康样本时允许首用；失败后熔断 60 秒，随后允许半开探测。
    if not st or st.get("ok") is not False:
        return True
    return time.time() - float(st.get("ts", 0)) >= 60.0

def _clean_channels():
    """干净上游通道清单（本机 DoQ 转发器优先，其次境外 DoT 常连接）"""
    ch = []
    if FAST_UDP:
        ch.append({"label": "dnscrypt", "ip": FAST_UDP[0], "port": FAST_UDP[1], "sni": None})
    for i, (ip, port) in enumerate(LOCAL_DOQ_LIST):
        ch.append({"label": ("doq", "doq2", "doq3")[i] if i < 3 else "doq%d" % i,
                   "ip": ip, "port": port, "sni": None})
    for ip, port, sni in CLEAN_DOT:
        ch.append({"label": "dot:" + sni.split(".")[-2], "ip": ip, "port": port, "sni": sni})
    return ch


def _dot_query_once(msg, name=None, qtype=None, timeout=TIMEOUT, prefer_addr=False):
    """优先用缓存；否则干净上游竞速。

    改动只影响"谁先跑"，不改变"什么算合格答案"：
      · 立刻并发两路本机 DoQ 转发器（aghdq→NextDNS / aghdq2→Quad9，实测 22~48ms）；
      · HEDGE_MS 内没有合格答案，再把 3 条境外 DoT 并发起来（常连接，约 250~300ms）。
    合格答案定义仍是"rcode 不是 SERVFAIL/REFUSED"，与改动前一致（通道集合也没变，
    5 条都是无过滤干净解析器：Mullvad / censurfridns / digitale + NextDNS(无 profile) / Quad9 dns10）。
    prefer_addr=True（只用于 R3 已知投毒域名）：空答案先记着，再多等 ADDR_GRACE_MS
    看有没有带地址的答案，避免某条通道的过滤/空回答抢在真实地址前面。"""
    key = _c_key(name, qtype)
    now = time.time()
    if name is not None:
        # 2026-10-10 Patch9 缺口1：严格清单名字**不得**命中答案缓存（否则共识被静默绕过）。
        # corrob 窗口（corrob_get）里的"已核对应答"仍可用 —— 它本身就是共识产物。
        if _strict_any(name):
            with _lock:
                _stats["strict_cache_skip"] = _stats.get("strict_cache_skip", 0) + 1
        else:
            with _lock:
                hit = _cache.get(key)
            if hit and hit[0] > now:
                _tr_flag("cache_hit")        # Step-1 §1：cache 状态
                return _cache_replay(hit)

    holder = {"buf": None, "src": None, "good": False, "addr": False, "grace_at": None}
    cv = threading.Condition()
    cancel = threading.Event()
    RETRYABLE = (2, 5)          # SERVFAIL / REFUSED：属"通道故障"，不该抢赢真实答案

    def worker(ip, port, sni, label):
        if cancel.is_set():
            return
        b = _upstream_call(ip, port, sni, msg, timeout)
        if not b:
            if label == "dnscrypt":
                with _lock:
                    _stats["fast_dnscrypt_fail"] = _stats.get("fast_dnscrypt_fail", 0) + 1
            return
        rc, ips, _cn, _mt = parse_a(b)
        good = rc is not None and rc not in RETRYABLE
        # ★ 2026-10-11（§5 验收期定位的既有缺陷，非 §5 引入）：仅"rcode 不是 2/5"还**不够**
        #   —— 实测 `127.0.0.1:5533`（aghdq→NextDNS 的 UDP 转发器）在并发下偶发把查询
        #   **原样回显**成 `rc=0 an=0 ns=0 ar=1`（flags 0x0100→0x8180，qid 不变）✗；
        #   旧判据把它当"更好的答案"⇒ 覆盖先到的 rc=2 ⇒ 写进 `_cache` 60s ⇒
        #   客户端在这段时间里被告知"该域名没有 A 记录"（而真相是 DNSSEC bogus）✗。
        #   修法：零证据空壳（`classify_kind()=="bare"`，或解析失败）一律**不算 good** ✓；
        #   真 NODATA/NXDOMAIN 带否定证据（权威段有 RR 或 AD=1）⇒ 仍按"可结论"处理 ✓。
        if good and not _is_conclusive(b):
            with _lock:
                _stats["clean_bare"] = _stats.get("clean_bare", 0) + 1
            good = False
        addr = bool(ips)
        with cv:
            if (holder["buf"] is None
                    or (good and not holder["good"])
                    or (good and addr and not holder["addr"])):
                holder["buf"], holder["src"], holder["good"], holder["addr"] = b, label, good, addr
            cv.notify_all()

    # 首轮只用低延迟 DoQ1；DoQ2（实测约 0.9s）降为延后备用，避免正常查询被慢通道拖住。
    fast = []
    if LOCAL_DOQ_LIST:
        ip, port = LOCAL_DOQ_LIST[0]
        fast.append((ip, port, None, "doq"))
    # 2026-10-19：第三条（aghcf→Cloudflare，实测 p50≈83ms）与 DoQ1 同为首轮并发，
    #   谁先返回用谁 ⇒ 只可能更快。_channel_usable 已熔断失败通道（失败后 60s 不重试）。
    if len(LOCAL_DOQ_LIST) > 2:
        _cf_ip, _cf_port = LOCAL_DOQ_LIST[2]
        if _channel_usable(_cf_ip, _cf_port, None):
            fast.append((_cf_ip, _cf_port, None, "doq3"))
    # Patch6：改用 DNSCRYPT_ADOPT（默认 None ⇒ 不进入可被采纳的首轮竞速）
    if DNSCRYPT_ADOPT and _channel_usable(DNSCRYPT_ADOPT[0], DNSCRYPT_ADOPT[1], None):
        fast.append((DNSCRYPT_ADOPT[0], DNSCRYPT_ADOPT[1], None, "dnscrypt"))
    # 首轮慢源只保留最快的认证 DoT；其余认证 DoT 留给 R8 冲突核对，避免未命中洪峰时重复建立慢连接。
    # 2026-10-28 slow 慢路收敛：原实现无条件把 CLEAN_DOT[0] 塞进 slow，
    # 而 censurfridns / digitale-gesellschaft 实测 ok=False(无应答)，_channel_usable
    # 已把它们熔断 60s —— 但 slow 腿没走这个过滤，每次 hedge 都要白等死通道的整个 timeout。
    # 改为按 _channel_usable 过滤，取第一条仍可用的认证 DoT。
    slow = []
    for _cd in CLEAN_DOT:
        if _channel_usable(_cd[0], _cd[1], _cd[2]):
            slow.append((_cd[0], _cd[1], _cd[2], "dot"))
            break
    if len(LOCAL_DOQ_LIST) > 1:
        ip, port = LOCAL_DOQ_LIST[1]
        # DoQ2 是延后备用；连续失败时由 keepalive 熔断，避免每个查询反复等待坏通道。
        if _channel_usable(ip, port, None):
            slow.append((ip, port, None, "doq2"))
    # 2026-10-19：第三条（aghcf→Cloudflare 1.1.1.1）**不进 slow 而进 fast**：
    #   实测冷查询 p50≈83ms，比 DoQ1（NextDNS≈270ms）快一个量级。若放 slow 则要等
    #   hedge（≈370ms）才启动，等于永远不用它、也降不了延迟。fast 是并发的，
    #   谁先返回用谁，故放进 fast 只降延迟、不增延迟；失败时 cancel 机制保证不影响正确性。
    with _lock:
        _stats["clean_races"] += 1
    t0 = time.time()
    # 自适应竞速：根据当前 DoQ1 保活 RTT 调整备用启动点，且受总预算约束。
    with _lock:
        _doq_rtt = _ch_stat.get("doq", {}).get("rtt_ms")
    hedge_ms = HEDGE_MS
    if isinstance(_doq_rtt, (int, float)):
        # DoQ1 当前 RTT 约 250~300ms。原上限 220ms 会让几乎每个请求
        # 在 DoQ1 正常返回前就启动慢 DoT，造成不必要的 hedge。
        hedge_ms = max(160, min(420, int(_doq_rtt * 1.2 + 40)))
    deadline, hedge_at = t0 + min(timeout, TOTAL_BUDGET), t0 + hedge_ms / 1000.0
    started_slow = False
    for t in fast:
        _upstream_executor.submit(worker, *t)
    while True:
        with cv:
            if holder["good"] and (holder["addr"] or not prefer_addr):
                cancel.set()
                break
            if holder["good"] and prefer_addr and not holder["addr"]:
                if holder["grace_at"] is None:
                    holder["grace_at"] = time.time() + ADDR_GRACE_MS / 1000.0
                if time.time() >= holder["grace_at"]:
                    cancel.set()
                    break
            now2 = time.time()
            if now2 >= deadline:
                cancel.set()
                break
            if not started_slow and now2 >= hedge_at:
                started_slow = True
                for t in slow:
                    _upstream_executor.submit(worker, *t)
            cv.wait(0.01)
    with _lock:
        if started_slow:
            _stats["clean_hedged"] += 1
        if holder["buf"] is None:
            _stats["clean_slow"] += 1
        elif holder["src"]:
            _stats["win_" + holder["src"]] += 1
    # Step-1 §1：hedge **started / won** + 本阶段耗时（单调）✓
    if started_slow:
        _tr_flag("hedge_started")
        if holder["buf"] is not None:
            _tr_flag("hedge_won")
    _tr_note("clean", (time.time() - t0) * 1000.0, "ok" if holder["buf"] else "fail")
    buf = holder["buf"]
    # ★ 2026-10-11：**缓存准入也要过"可结论"门** ✓ —— `worker()` 已把零证据空壳判为不 good，
    #   但"所有通道都只给出空壳 ⇒ holder 里没有可结论字节 ⇒ buf 为 None"这一支同样要
    #   明确处理：此时**不缓存**、让调用方按"干净通道没查到"处理 ✓（fail-closed 或按上层
    #   既有逻辑降级），绝不把空壳当结论缓存 10–600s ✗。
    if buf and not _is_conclusive(buf):
        with _lock:
            _stats["clean_bare"] = _stats.get("clean_bare", 0) + 1
        buf = None
    if buf and name is not None:
        import alt_adapter
        ttl = min(600.0, float(alt_adapter.rrset_validity(buf)[0] or 0.0))
        with _lock:
            if ttl > 0:
                _cache[key] = (time.time() + ttl, buf, _cache_stamp())
            if len(_cache) > 20000:
                # 2026-10-28 N-3：满时淘汰最旧一半，不再整表 clear
                # （整表清空会让所有在途查询同时失去缓冲 ⇒ 集体击穿）
                try:
                    _ks = sorted(_cache, key=lambda _x: _cache[_x][0])[:10000]
                    for _k in _ks:
                        _cache.pop(_k, None)
                except Exception:
                    _cache.clear()
    if not buf:
        with _lock:
            _stats["clean_fail"] += 1
    return buf


def _verifier_dot(msg, name, qtype, timeout, prefer_addr, op="dot", targets=None, pool=None):
    """经 unix socket 把查询交给 verifier sidecar。

    2026-10-07 改：
      ① 增加 **pool 意图**（r3 / corrob）——verifier 才能按工作类型分池，
         否则继续调 COLD_MAX 只是在移动压力；
      ② 应答帧改为 **1 字节状态 + 载荷**，让"权威侧 NODATA"与"我们排队超时/过载"
         能被真正区分（这是方案 B 语义的前提）。
    返回 (status, resp)；status 为 CORROB_* 之一。
    """
    import json
    _t0v = time.monotonic()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout + 0.3)
    def readn(n):
        data = b""
        while len(data) < n:
            part = sock.recv(n-len(data))
            if not part:
                raise IOError("verifier disconnected")
            data += part
        return data
    try:
        # Step-1 §1：`rid` = guard 侧请求追踪 ID ⇒ **verifier 用同一 ID 记账**（方案硬要求）✓
        _rid = None
        try:
            _rid = _tr().get("id")
        except Exception:
            _rid = None
        _pl = {"name": name, "qtype": qtype, "timeout": timeout,
               "prefer_addr": prefer_addr, "op": op,
               "targets": targets, "pool": pool, "rid": _rid}
        # F5（2026-10-15 审计）：每次 IPC 随身携带本进程发布指纹 ⇒ 对端可比对 ✓
        _pl.update(verifier_payload_identity())
        payload = json.dumps(_pl).encode()
        sock.connect(os.environ["GUARD_VERIFIER_SOCKET"])
        sock.sendall(struct.pack("!HH", len(payload), len(msg)) + payload + msg)
        n = struct.unpack("!H", readn(2))[0]
        raw = readn(n) if n else b""
        if not raw:
            _tr_note("ipc", (time.monotonic() - _t0v) * 1000.0, "timeout")
            return CORROB_TIMEOUT, None
        _vst = _VBYTE_STATUS.get(raw[0:1], CORROB_ERROR)
        if _vst == CORROB_VERSION_MISMATCH:
            # F5：对端拒服务 ⇒ 与本进程 ERROR 等价，上层继续走"没查成"的保守路径 ✓
            _relm_note()
            _vst = CORROB_ERROR
        _tr_note("ipc", (time.monotonic() - _t0v) * 1000.0,
                 "ok" if _vst == CORROB_OK else ("timeout" if _vst == CORROB_TIMEOUT else "fail"))
        return _vst, (raw[1:] or None)
    except (OSError, ValueError, struct.error):
        _tr_note("ipc", (time.monotonic() - _t0v) * 1000.0, "fail")
        return CORROB_TIMEOUT, None
    finally:
        sock.close()

def dot_query(msg, name=None, qtype=None, timeout=TIMEOUT, prefer_addr=False):
    """主查询 single-flight：同一名称/类型同时只允许一个上游竞速。"""
    if os.environ.get("GUARD_VERIFIER_SOCKET"):
        # 走 sidecar：带 pool 意图，并区分"过载"与"超时"（两者都不等于权威 NODATA）
        _vst, _vr = _verifier_dot(msg, name, qtype, timeout, prefer_addr, "dot", None, "r3")
        if _vr is None:
            with _lock:
                if _vst == CORROB_OVERLOAD:
                    _stats["cold_overload"] += 1
                else:
                    _stats["cold_timeout"] += 1
        return _vr
    if name is None:
        return _dot_query_once(msg, name, qtype, timeout, prefer_addr)
    key = (name, qtype)
    if not _cold_sem.acquire(False):
        with _lock:
            _stats["cold_drop"] += 1
        return None
    lk = _query_lock_get(key)
    acquired = lk.acquire(False)
    if not acquired:
        with _lock:
            _stats["singleflight_wait"] = _stats.get("singleflight_wait", 0) + 1
        # 2026-10-07：原先是**无超时**的 lk.acquire() —— 一旦持锁线程卡住，等待者会一直
        # 占着 inflight 名额不放，把执行器名额耗光、队列拖死（"静默 10 秒"的成因之一）。
        # 改为有界等待；等不到就放弃单飞合并、自己直接发一次（多打一次上游，换不阻塞）。
        acquired = lk.acquire(timeout=max(0.2, float(timeout) - 0.2))
        if not acquired:
            with _lock:
                _stats["singleflight_timeout"] += 1
    try:
        return _dot_query_once(msg, name, qtype, timeout, prefer_addr)
    finally:
        if acquired:
            lk.release()
        _cold_sem.release()


def rewrite_id(msg, qid):
    return struct.pack("!H", qid) + msg[2:]


# ---------------- 同步判据 R1 ----------------
# ---------------- 严格清单（Codex ⑦） ----------------
STRICT_FILE = os.path.join(STATE_DIR, "strict_hosts.json")
STRICT_BUDGET = float(os.environ.get("GUARD_STRICT_BUDGET", "2.6"))   # 严格路径硬预算（秒）
STRICT_NEG_TTL = float(os.environ.get("GUARD_STRICT_NEG_TTL", "45"))  # 共识否定缓存
STRICT_SERVFAIL_TTL = float(os.environ.get("GUARD_STRICT_SERVFAIL_TTL", "15"))
# P2（2026-10-22）：失败域名负缓存自适应退避（默认关 ⇒ 零行为变化 ✓）
_SF_BACKOFF_ON = _flag("GUARD_SF_BACKOFF", False)
_SF_TTL_MIN = float(os.environ.get("GUARD_SF_TTL_MIN", str(STRICT_SERVFAIL_TTL)))
_SF_TTL_MAX = float(os.environ.get("GUARD_SF_TTL_MAX", "300"))
# 2026-10-10 Patch15（Codex）：60 → 300。理由：判据"≥2 家运营方答案集相等"的延迟下界 = 第二快
# 独立运营方的 RTT ⇒ 客户端只在"共识窗口 + AGH 缓存"双冷时才付 ~1.1s；把 pin 放大到 5 分钟可显著
# 降低双冷概率，而 pin 里存的是**已核对**答案（新鲜度风险有界，非投毒风险）。
STRICT_TTL_CAP = float(os.environ.get("GUARD_STRICT_TTL_CAP", "300"))  # 采纳答案 TTL 上限
# 2026-10-10 Patch21（Codex）：共识判据模式与"前缀类别"长度。
#   prefix（默认）：两路答案完全相等 **或** 落在同一前缀类别（v4 /16、v6 /48）即视为有共识；
#   exact         ：旧行为（要求集合完全相等）—— 单键回退用。
STRICT_CONSENSUS = (os.environ.get("GUARD_STRICT_CONSENSUS", "prefix") or "prefix").strip().lower()
if STRICT_CONSENSUS not in ("prefix", "exact"):
    STRICT_CONSENSUS = "prefix"
STRICT_PFX_V4 = int(os.environ.get("GUARD_STRICT_PREFIX_V4", "16"))
STRICT_PFX_V6 = int(os.environ.get("GUARD_STRICT_PREFIX_V6", "48"))


def _pfx_of(x, bits):
    """把 `_norm_ip` 的输出（IPv4 为 str、IPv6 为 bytes）截成前 bits 位，用于"同类别"比较。"""
    try:
        if isinstance(x, bytes):
            raw = x
            nbytes = (bits + 7) // 8
            return raw[:nbytes]
        if ":" in x:
            raw = socket.inet_pton(socket.AF_INET6, x)
        else:
            raw = socket.inet_aton(x)
        nbytes = (bits + 7) // 8
        return raw[:nbytes]
    except Exception:
        return x


def _prefix_class_agree(sa, sb):
    """两组地址是否存在"同前缀类别"的配对（v4 /16、v6 /48）。用于 GLB/多边缘名字的共识判定。"""
    va4 = [x for x in sa if isinstance(x, str) and ":" not in x]
    vb4 = [x for x in sb if isinstance(x, str) and ":" not in x]
    va6 = [x for x in sa if isinstance(x, bytes) or (isinstance(x, str) and ":" in x)]
    vb6 = [x for x in sb if isinstance(x, bytes) or (isinstance(x, str) and ":" in x)]
    pa = set(_pfx_of(x, STRICT_PFX_V4) for x in va4)
    pb = set(_pfx_of(x, STRICT_PFX_V4) for x in vb4)
    if pa & pb:
        return ("v4/%d" % STRICT_PFX_V4)
    qa = set(_pfx_of(x, STRICT_PFX_V6) for x in va6)
    qb = set(_pfx_of(x, STRICT_PFX_V6) for x in vb6)
    if qa & qb:
        return ("v6/%d" % STRICT_PFX_V6)
    return None
_strict_neg = {}          # (name,qtype) -> (expiry, ("SERVFAIL"|"POS"|"NEG", resp, rcode))
_strict_single = {}       # (name,qtype) -> Lock（单飞）
_strict = {}          # "<host>|<qtype>" -> {"added","by","reason","expires"}


def strict_load():
    """载入严格清单。文件不存在 ⇒ 空表（并打日志）；**存在但损坏 ⇒ 拒绝启动**（不允许静默失效）。"""
    global _strict
    if not os.path.exists(STRICT_FILE):
        _strict = {}
        log("STRICT 清单文件不存在（%s）⇒ 视为空表" % STRICT_FILE)
        return
    try:
        with open(STRICT_FILE, encoding="utf-8") as f:
            d = json.load(f)
        _strict = dict((k, dict(v)) for k, v in (d.get("hosts") or {}).items())
        log("STRICT 清单已载入: %d 条" % len(_strict))
    except Exception as e:
        raise SystemExit("STRICT 清单存在但无法解析（%s）⇒ 拒绝启动，避免禁回退语义静默失效: %s"
                         % (STRICT_FILE, e))


def strict_save():
    try:
        _atomic_json(STRICT_FILE, {"updated": time.time(), "hosts": _strict}, ensure_ascii=False, indent=1)
        return True
    except Exception as e:
        log("STRICT save error: %s" % e)
        return False


def _strict_key(name, qtype):
    return "%s|%d" % ((name or "").lower().rstrip("."), int(qtype or 1))


def _strict_any(name):
    """该名字是否在严格清单（任意 QTYPE）；用于缓存旁路判定。"""
    pfx = "%s|" % (name or "").lower().rstrip(".")
    for k in _strict:
        if k.startswith(pfx):
            return True
    return False


def strict_reload_safe():
    """热载包装：损坏文件时**保留旧清单**并记日志（`SystemExit` 不被 `except Exception` 捕获，
    若直接在 reloader 线程里抛会杀掉该线程 ✗）；启动路径本身仍**拒绝启动**。"""
    try:
        strict_load()
        with _lock:
            _stats["strict_list_size"] = len(_strict)
        log("STRICT 热载: %d 条" % len(_strict))
        return True
    except SystemExit as e:
        log("STRICT 热载失败（保留旧清单 %d 条）: %s" % (len(_strict), str(e)[:80]))
        return False
    except Exception as e:
        log("STRICT 热载异常（保留旧清单）: %s" % str(e)[:80])
        return False


def _strict_entry(name, qtype):
    e = _strict.get(_strict_key(name, qtype))
    if not e:
        return None
    exp = e.get("expires")
    if exp and time.time() > float(exp):
        with _lock:
            _stats["strict_list_expired"] = _stats.get("strict_list_expired", 0) + 1
        return None
    return e


# ---------------- 异步审计（Patch28，默认关闭）----------------
# 目的：为新判据（运营商级门控）提供**前向证据**。硬约束：只计数/只落日志，
# **绝不改答案、绝不 corrob_put（不回写 pin）** ✓；走 verifier 的 strict 池 ✓。
AUDIT_ON = _flag("GUARD_R8_AUDIT", False)              # 默认 0 ⇒ 零行为变化 ✓
AUDIT_PCT = int(os.environ.get("GUARD_R8_AUDIT_PCT", "10"))    # 抽样百分比
AUDIT_WORKERS = int(os.environ.get("GUARD_R8_AUDIT_WORKERS", "2"))
AUDIT_QMAX = int(os.environ.get("GUARD_R8_AUDIT_QMAX", "512"))
AUDIT_MIN_PER_MIN = int(os.environ.get("GUARD_R8_AUDIT_MIN_PER_MIN", "6"))
AUDIT_MAX_PER_MIN = int(os.environ.get("GUARD_R8_AUDIT_MAX_PER_MIN", "20"))
_audit_q = collections.deque(maxlen=AUDIT_QMAX)        # 满则**丢最旧** ✓
_audit_lock = threading.Lock()
_audit_win = [0.0, 0]                                  # [窗口起点, 本窗口计数]
_audit_pool = None


def _audit_allowed():
    """每分钟软节流（≥MIN、≤MAX）✓。"""
    now = time.time()
    with _audit_lock:
        if now - _audit_win[0] >= 60.0:
            _audit_win[0] = now
            _audit_win[1] = 0
        if _audit_win[1] >= AUDIT_MAX_PER_MIN:
            with _lock:
                _stats["audit_ratelimited"] = _stats.get("audit_ratelimited", 0) + 1
            return False
        _audit_win[1] += 1
        return True


def _audit_worker_once(item):
    """单次审计：查一路（strict 池 ✓），与记录的明文集合比对；**只计数/只日志** ✓。"""
    msg, name, qtype, uset8 = item
    try:
        stt, r = _corrob_query_once(msg, name, qtype, None, CORROB_DOT_TIMEOUT, pool="strict")
    except Exception:
        stt, r = CORROB_ERROR, None
    with _lock:
        _stats["audit_tried"] = _stats.get("audit_tried", 0) + 1
    if not r:
        # 过载/超时 ⇒ **unknown**（绝不并进 mismatch ✗，否则剖面被过载污染 ✓）
        with _lock:
            _stats["audit_unknown"] = _stats.get("audit_unknown", 0) + 1
        return
    try:
        _rc, _ips, _cn, _ttl = parse_a(r)
    except Exception:
        with _lock:
            _stats["audit_unknown"] = _stats.get("audit_unknown", 0) + 1
        return
    _cset = set(_norm_ip(x) for x in (_ips or []))
    if not _cset:
        with _lock:
            _stats["audit_unknown"] = _stats.get("audit_unknown", 0) + 1
        return
    if _cset & uset8:
        with _lock:
            _stats["audit_agree"] = _stats.get("audit_agree", 0) + 1
        return
    with _lock:
        _stats["audit_mismatch"] = _stats.get("audit_mismatch", 0) + 1
    log("AUD  %-38s 审计不一致（我方 %s / 审计 %s）——只记录，不改答案 ✓"
        % (name, _ips_str(uset8)[:26], _ips_str(_cset)[:26]))


def _audit_loop():
    while True:
        try:
            with _audit_lock:
                item = _audit_q.popleft() if _audit_q else None
            if item is None:
                time.sleep(0.2)
                continue
            _audit_worker_once(item)
        except Exception:
            time.sleep(0.2)


def audit_note(msg, name, qtype, uset8):
    """在 R8 判定流程中**旁路**登记一次审计（默认关闭 ⇒ 直接返回 ✓）。"""
    if not AUDIT_ON or qtype != 1:
        return
    if random.randrange(100) >= AUDIT_PCT:
        return
    if not _audit_allowed():
        return
    with _audit_lock:
        if len(_audit_q) >= AUDIT_QMAX:
            with _lock:
                _stats["audit_dropped"] = _stats.get("audit_dropped", 0) + 1
            return
        _audit_q.append((msg, name, qtype, set(uset8)))
    with _lock:
        _stats["audit_queued"] = _stats.get("audit_queued", 0) + 1


def _sf_get(name, qtype):
    """A3：命中"双源明确 SERVFAIL"记忆 ⇒ True。

    只代表"两家独立源刚刚都明确拒绝"，**不携带任何应答内容** ✓。
    """
    if not name:
        return False
    k = _c_key(name, qtype)
    e = _SF_CACHE.get(k)
    if not e:
        return False
    if e <= time.time():
        _SF_CACHE.pop(k, None)
        return False
    with _lock:
        _stats["sf_cache_hit"] = _stats.get("sf_cache_hit", 0) + 1
    return True


def _sf_put(name, qtype):
    """A3：落 STRICT_SERVFAIL_TTL 秒（默认 15s）⇒ 拒绝结论短期可复用 ✓。

    P2（2026-10-22）：连续失败时指数退避至 _SF_TTL_MAX（默认 300s）✓。
      · 开关 GUARD_SF_BACKOFF 默认关 ⇒ 不设等于零行为变化 ✓；
      · 次数由 _SF_STREAK 记账，_sf_clear() 在拿到可采纳答案时清零 ✓；
      · 仍只写 expiry，不存报文 ✓。
    """
    if not name:
        return
    _k = _c_key(name, qtype)
    _n = int(_SF_STREAK.get(_k, 0)) + 1
    _SF_STREAK[_k] = _n
    if _SF_BACKOFF_ON:
        # ★ 2026-10-22 方案B：指数上限从固定的 '5' 改为**由 _SF_TTL_MAX 推导** ✗→✓
        #   原实现写死 `2 ** min(_n - 1, 5)` ⇒ 无论 _SF_TTL_MAX 设成多少，
        #   实际天花板恒为 15*32=480s ⇒ 把 GUARD_SF_TTL_MAX 调到 900 **完全无效**（实测确认）。
        #   现在按目标上限反推所需的最大指数，并留 1 级余量：
        #     _cap = ceil(log2(_SF_TTL_MAX / _SF_TTL_MIN))
        #   TTL_MAX=300 ⇒ cap=5（15/30/60/120/240/300，与旧行为一致）
        #   TTL_MAX=900 ⇒ cap=6（…/480/900）
        _cap = 1
        _r = max(1.0, float(_SF_TTL_MAX)) / max(1.0, float(_SF_TTL_MIN))
        while _cap < 20 and (2 ** _cap) < _r:
            _cap += 1
        _ttl = min(_SF_TTL_MAX, _SF_TTL_MIN * (2 ** min(_n - 1, _cap)))
        try:
            _stats["sf_extended"] = _stats.get("sf_extended", 0) + 1
            if _ttl > float(_stats.get("sf_streak_max_ttl") or 0.0):
                _stats["sf_streak_max_ttl"] = _ttl
        except Exception:
            pass
    else:
        _ttl = STRICT_SERVFAIL_TTL
    _SF_CACHE[_k] = time.time() + _ttl
    with _lock:
        _stats["sf_cache_store"] = _stats.get("sf_cache_store", 0) + 1
        if len(_SF_CACHE) > _SF_MAX:
            _now = time.time()
            for k in [k for k, v in list(_SF_CACHE.items()) if v <= _now]:
                _SF_CACHE.pop(k, None)
            _stats["sf_cache_evict"] = _stats.get("sf_cache_evict", 0) + 1


def _sf_clear(name, qtype, why=""):
    """P2：该 (name,qtype) 已拿到可采纳答案/非 SERVFAIL 证据 ⇒ 立刻清零退避 ✓。

    这是"绝不永久锁死已恢复域名"的结构性保证：
      · 只清 _SF_STREAK 与 _SF_CACHE，绝不写入任何答案字节 ✓（答案由调用方按正常路径写）；
      · 幂等，可重复调用；why 只用于记账。
    """
    if not name:
        return False
    _k = _c_key(name, qtype)
    _had = (_k in _SF_CACHE) or (_k in _SF_STREAK)
    _SF_STREAK.pop(_k, None)
    _SF_CACHE.pop(_k, None)
    if _had:
        try:
            _stats["sf_cleared"] = _stats.get("sf_cleared", 0) + 1
            _stats["sf_cleared_" + str(why or "other")] = _stats.get("sf_cleared_" + str(why or "other"), 0) + 1
        except Exception:
            pass
    return _had


def _strict_neg_get(name, qtype):
    e = _strict_neg.get(_c_key(name, qtype))
    if e and e[0] > time.time():
        with _lock:
            _stats["strict_neg_hit"] = _stats.get("strict_neg_hit", 0) + 1
        return e[1]
    if e:
        _strict_neg.pop(_c_key(name, qtype), None)
    return None


def _strict_neg_put(name, qtype, kind, resp, rcode):
    ttl = STRICT_SERVFAIL_TTL if kind == "SERVFAIL" else STRICT_NEG_TTL
    _strict_neg[_c_key(name, qtype)] = (time.time() + ttl, (kind, resp, rcode))


# 2026-10-28 N-2: real operator per local DoQ port (5533=aghdq->NextDNS removed,
# 5534=aghdq2->Quad9, 5535=aghcf->Cloudflare DoT). Must map by PORT, not by list index:
# GUARD_DOQ_PORT makes _DOQ1 also point at 5534, so index-based labeling fakes two operators.
_DOQ_LOCAL_OP = {5533: "nextdns", 5534: "quad9", 5535: "cloudflare"}


def _strict_pick_channels():
    """按近期 RTT 从低到高排**不同运营方**的候选通道（含 DoQ/NextDNS），用于并发共识。

    2026-10-10 Patch16：纳入 DoQ(221ms) 以提高**可用性**；但判据要求"≥2 家不同运营方答案集
    相等" ⇒ **必须按运营方去重**（`doq` 与 `doq2` 同属 NextDNS，若同时入选就退化成单家自证 ✗✗）。
    注意 DoQ 只提高可用性、不降低延迟下界（下界 = 第二快**独立运营方**的 RTT）。"""
    cand = []
    for t in (CLEAN_DOT or []):
        ip, port, sni = t[0], t[1], t[2]
        lab = _channel_label(ip, port, sni)
        with _lock:
            st = dict(_ch_stat.get(lab) or {})
        rtt = st.get("rtt_ms")
        op = (sni or "").split(".")[-2] if sni else "unknown"
        cand.append((rtt if isinstance(rtt, (int, float)) and rtt > 0 else 9999.0, t, op))
    # DoQ：本机 aghdq → NextDNS（fdaa:... 或本地端口），QUIC/TLS 认证，运营方记作 nextdns。
    if _flag("GUARD_STRICT_USE_DOQ", True):
        # 2026-10-28 N-2: operator must be resolved by PORT, not by list index.
        #   GUARD_DOQ_PORT=5534 makes _DOQ1 and _DOQ2 the same endpoint; index-based
        #   labeling reported two independent operators for one Quad9 endpoint (fake dual source).
        #   Dedupe endpoints too: the seen set below only dedupes by operator.
        _seen_ep = set()
        for ix, (ip, port) in enumerate(LOCAL_DOQ_LIST or []):
            _ep = (str(ip), int(port))
            if _ep in _seen_ep:
                with _lock:
                    _stats["strict_endpoint_dedup"] = _stats.get("strict_endpoint_dedup", 0) + 1
                continue
            _seen_ep.add(_ep)
            lab = ("doq", "doq2", "doq3")[ix] if ix < 3 else "doq%d" % ix
            with _lock:
                st = dict(_ch_stat.get(lab) or {})
            rtt = st.get("rtt_ms")
            if not (isinstance(rtt, (int, float)) and rtt > 0):
                continue
            _op = _DOQ_LOCAL_OP.get(int(port), "doq:%d" % int(port))
            cand.append((rtt, (ip, port, None), _op))
    cand.sort(key=lambda x: x[0])
    out, seen = [], set()
    for _r, t, op in cand:
        if op in seen:
            with _lock:
                _stats["strict_operator_dedup"] = _stats.get("strict_operator_dedup", 0) + 1
            continue
        seen.add(op)
        if op in ("nextdns", "quad9", "cloudflare"):
            with _lock:
                _stats["strict_cand_doq"] = _stats.get("strict_cand_doq", 0) + 1
        out.append(t)
    return out


def _ips_str(sset):
    """把集合里的地址渲染成字符串：`_norm_ip` 对 IPv6 返回 bytes（inet_pton 结果），
    直接 join 会抛 TypeError（2026-10-10 实测：AAAA 严格查询被无谓 SERVFAIL ✗）。"""
    out = []
    for x in sset or []:
        if isinstance(x, bytes):
            try:
                out.append(socket.inet_ntop(socket.AF_INET6, x))
            except Exception:
                out.append(repr(x)[:24])
        else:
            out.append(str(x))
    return ",".join(sorted(out))


def _strict_probe_once(msg, name, qtype, tgt, budget):
    """单路探测：返回 ("POS", resp, ips, ttl) / ("NEG", resp, rcode) / ("FAIL", None, None)。"""
    try:
        stt, r = _corrob_query_once(msg, name, qtype, [tgt], budget)
    except Exception:
        return ("FAIL", None, None)
    if stt == CORROB_OVERLOAD:
        with _lock:
            _stats["strict_overload"] = _stats.get("strict_overload", 0) + 1
        return ("FAIL", None, None)
    if not r:
        return ("FAIL", None, None)
    try:
        rc, ips, _cn, ttl = parse_a(r)
    except Exception:
        return ("FAIL", None, None)
    sset = set(_norm_ip(x) for x in (ips or []))
    if sset:
        return ("POS", r, sset, (ttl if isinstance(ttl, int) else 60))
    if rc in (0, 3):
        return ("NEG", r, rc)
    return ("FAIL", None, None)


def _strict_serve(msg, name, qtype, qid):
    """严格路径主逻辑：返回要下发的应答；无法达成共识时返回 None（调用方一律 SERVFAIL）。"""
    _t0 = time.time()
    # (a) 共识窗口（先前已核对的答案）
    hit = corrob_get(name, qtype)
    if hit:
        with _lock:
            _stats["strict_cache_hit"] = _stats.get("strict_cache_hit", 0) + 1
            _stats["strict_adopt_pos"] = _stats.get("strict_adopt_pos", 0) + 1
        return rewrite_id(hit[0], qid)
    # (b) 独立短负缓存
    neg = _strict_neg_get(name, qtype)
    if neg:
        kind, resp, rcode = neg
        if kind == "SERVFAIL" or resp is None:
            return None
        if kind == "NEG":
            with _lock:
                _stats["strict_adopt_neg"] = _stats.get("strict_adopt_neg", 0) + 1
            return rewrite_id(resp, qid)
        return rewrite_id(resp, qid)
    # (c) 单飞：同一 (name,qtype) 只允许一个在跑
    lk = _strict_single.get((name, qtype))
    if lk is None:
        lk = threading.Lock()
        _strict_single[(name, qtype)] = lk
    if not lk.acquire(False):
        with _lock:
            _stats["strict_single_wait"] = _stats.get("strict_single_wait", 0) + 1
        if lk.acquire(timeout=STRICT_BUDGET):
            lk.release()
        hit = corrob_get(name, qtype)
        if hit:
            return rewrite_id(hit[0], qid)
        return None
    try:
        # ★ 方案 §3 第 67 行：严格清单的预算也改成**吃剩余单调预算** ✓ ——
        # 旧写法 `max(0.8, min(STRICT_BUDGET, QUERY_DEADLINE - (time.time()-_t0) - 0.2))`
        # 有两个毛病：①下限 0.8s 会在预算已尽时**再送 0.8 秒** ✗（尾巴就是这么堆出来的 ✗）；
        # ②用墙钟 `time.time()-_t0` ✗，NTP 回拨会让"已用时间"变小 ⇒ 预算被凭空放大 ✗。
        # 现在：`_dl_rem()` 直接给单调剩余 ✓，`<=0` 立即不动手 ✓。
        _b = _dl_rem()
        if _b is None:
            _b = min(STRICT_BUDGET, QUERY_DEADLINE - (time.time() - _t0) - 0.2)
        budget = min(float(STRICT_BUDGET), max(0.0, float(_b) - 0.05))
        if budget <= 0.1:
            with _lock:
                _stats["strict_budget_skip"] = _stats.get("strict_budget_skip", 0) + 1
            return None
        channels = _strict_pick_channels()[:2]
        if len(channels) < 2:
            with _lock:
                _stats["strict_insufficient"] = _stats.get("strict_insufficient", 0) + 1
            return None
        res = [None, None]
        tls = []
        for _i, _t in enumerate(channels):
            _th = threading.Thread(target=lambda i=_i, t=_t: res.__setitem__(
                i, _strict_probe_once(msg, name, qtype, t, budget)), daemon=True)
            _th.start()
            tls.append(_th)
        _deadline = time.time() + budget
        for _th in tls:
            _th.join(max(0.05, _deadline - time.time()))
        got = [r for r in res if r]
        pos = [r for r in got if r[0] == "POS"]
        negs = [r for r in got if r[0] == "NEG"]
        fails = [r for r in got if r[0] == "FAIL"]
        with _lock:
            _stats["strict_elapsed_ms"] = int((time.time() - _t0) * 1000)
        # 判定表（Codex）：≥2 POS 且集合相等 ⇒ 采纳；≥2 NEG 且无 POS ⇒ 采纳否定；
        # 1 POS + 1 NEG ⇒ conflict；结论不足 ⇒ insufficient；两种都 ⇒ SERVFAIL。
        if len(pos) >= 2:
            # 2026-10-10 Patch21：完全相等 **或** 同前缀类别（GLB/多边缘名字可用 ✓）
            _exact = (pos[0][2] == pos[1][2])
            _cls = None if _exact else (_prefix_class_agree(pos[0][2], pos[1][2])
                                       if STRICT_CONSENSUS == "prefix" else None)
            if _exact or _cls:
                with _lock:
                    _stats["strict_consensus_pos"] = _stats.get("strict_consensus_pos", 0) + 1
                    _stats["strict_adopt_pos"] = _stats.get("strict_adopt_pos", 0) + 1
                    if _exact:
                        _stats["strict_consensus_exact_ok"] = _stats.get("strict_consensus_exact_ok", 0) + 1
                    else:
                        _stats["strict_consensus_prefix_ok"] = _stats.get("strict_consensus_prefix_ok", 0) + 1
                _ttl = max(30.0, min(float(pos[0][3] or 60), STRICT_TTL_CAP))
                corrob_put(name, qtype, pos[0][1], sorted(pos[0][2]), int(_ttl))
                log("STR  %-38s 严格共识(POS%s) → 采用认证答案 %s"
                    % (name, "" if _exact else "|同前缀 %s" % _cls, _ips_str(pos[0][2])[:34]))
                return rewrite_id(pos[0][1], qid)
            with _lock:
                _stats["strict_set_mismatch"] = _stats.get("strict_set_mismatch", 0) + 1
                _stats["strict_consensus_none"] = _stats.get("strict_consensus_none", 0) + 1
                _stats["strict_conflict"] = _stats.get("strict_conflict", 0) + 1
            _strict_neg_put(name, qtype, "SERVFAIL", None, 2)
            log("STR  %-38s 严格共识不足（%s vs %s；模式=%s）→ SERVFAIL"
                % (name, _ips_str(pos[0][2])[:22], _ips_str(pos[1][2])[:22], STRICT_CONSENSUS))
            return None
        if len(negs) >= 2 and not pos:
            _rc_all3 = all(r[2] == 3 for r in negs)
            with _lock:
                _stats["strict_consensus_neg"] = _stats.get("strict_consensus_neg", 0) + 1
                _stats["strict_adopt_neg"] = _stats.get("strict_adopt_neg", 0) + 1
            _strict_neg_put(name, qtype, "NEG", negs[0][1], 3 if _rc_all3 else 0)
            log("STR  %-38s 严格共识(NEG, rcode=%d) → 采纳认证否定"
                % (name, 3 if _rc_all3 else 0))
            return rewrite_id(negs[0][1], qid)
        if pos and negs:
            with _lock:
                _stats["strict_conflict"] = _stats.get("strict_conflict", 0) + 1
            _strict_neg_put(name, qtype, "SERVFAIL", None, 2)
            log("STR  %-38s 严格共识冲突(1 POS + 1 NEG) → SERVFAIL" % name)
            return None
        with _lock:
            _stats["strict_insufficient"] = _stats.get("strict_insufficient", 0) + 1
        _strict_neg_put(name, qtype, "SERVFAIL", None, 2)
        log("STR  %-38s 严格共识结论不足（%d 路成功/%d 路失败）→ SERVFAIL"
            % (name, len(got), len(fails)))
        return None
    finally:
        try:
            lk.release()
        except Exception:
            pass


def _strict_consensus(msg, name, qtype, budget):
    """取**两条不同运营方**的认证 DoT 答案，要求答案集交集非空。
    返回 (resp, 交集, minTTL) 或 None。"""
    got = []
    for _tgt in (CLEAN_DOT or [])[:3]:
        try:
            _st, _r = _corrob_query_once(msg, name, qtype, [_tgt], budget, pool="strict")
        except Exception:
            _st, _r = CORROB_ERROR, None
        if not _r:
            continue
        try:
            _rc, _ips, _cn, _ttl = parse_a(_r)
        except Exception:
            continue
        _iset = set(_norm_ip(x) for x in (_ips or []))
        if _iset:
            got.append((_iset, _r, _ttl, _tgt))
    for _i in range(len(got)):
        for _j in range(_i + 1, len(got)):
            _inter = got[_i][0] & got[_j][0]
            if _inter:
                # 采用**认证 DoT 的答案**（不是明文），并要求该答案与交集一致
                return got[_i][1], _inter, (got[_i][2] if isinstance(got[_i][2], int) else 60)
    return None


CORROB_STRIP_ECS = _flag("GUARD_CORROB_STRIP_ECS", True)


def _corrob_query_once(msg, name, qtype, targets_override=None, budget=None, pool="corrob"):
    """同步核对一次。**返回 (status, resp)**：status ∈ {OK, TIMEOUT, ...}，只有 OK 时 resp 非空。
    区分状态是必须的 —— "权威侧 NODATA" 与 "我们自己排队超时" 是两种完全不同的证据。
    budget：本次核对的等待上限（默认 CORROB_DOT_TIMEOUT）；R8 会按整查询剩余额度收紧它。"""
    _bud = float(budget) if budget else CORROB_DOT_TIMEOUT
    # 2026-10-28 N-6：核对通道**剥离 ECS**。原实现把客户端原报文（含真实 /24 ECS）直接
    #   发给核对通道，与明文通道携带同一 ECS ⇒ 上游按 ECS 差异化应答时两侧"一致通过"，
    #   定向投毒可绕过双侧核对。剥离后核对侧拿到上游通用视角的答案，差异只进 DIFF
    #   待确认清单（不 SERVFAIL、不改道）。开关 GUARD_CORROB_STRIP_ECS 默认开。
    if CORROB_STRIP_ECS:
        try:
            _cq_qid = struct.unpack("!H", msg[0:2])[0] if msg and len(msg) >= 2 else None
            msg = mk_query_do(name, qtype, qid=_cq_qid, no_ecs=True)
        except Exception:
            pass
    if os.environ.get("GUARD_VERIFIER_SOCKET"):
        return _verifier_dot(msg, name, qtype, _bud, False, "corrob",
                             targets_override, pool)
    """同步核对：**并发**两路本地 DoQ 中继取先到者（与 dot_query 同款对冲）。
    串行写法实测把成本放大到 ~1.3s，并发写法才是 22~48ms 量级。
    不参与 dot_query 的竞速缓存，避免污染主路径。返回应答或 None。"""
    bucket = "hint" if CORROB_AUTH == "any" else "auth"
    holder = {bucket: None}
    cv = threading.Condition()

    def w(ip, port, sni):
        if not _channel_usable(ip, port, sni):
            with _lock:
                _stats["r8_circuit_skip"] += 1
            return
        b = _upstream_call(ip, port, sni, msg, _bud)
        if not b:
            return
        rc, cips, _cn, _t = parse_a(b)
        if not (cips or rc in (0, 3)):
            return
        with cv:
            if holder[bucket] is None:
                holder[bucket] = b
            cv.notify_all()

    if targets_override is not None:
        # 方案1：CN 域名用国内认证 DoT 核对（R8 的境外通道对国内答案会误判）
        targets = list(targets_override)
        budget = _bud
    elif CORROB_AUTH == "any":
        targets = [(ip, port, None) for ip, port in LOCAL_DOQ_LIST]
        budget = CORROB_ONESHOT_TIMEOUT
    else:
        targets = [(ip, port, sni) for (ip, port, sni) in CLEAN_DOT]
        budget = _bud
    for ip, port, sni in targets:
        _r8_executor.submit(w, ip, port, sni)
    end = time.time() + budget
    with cv:
        while holder[bucket] is None:
            left = end - time.time()
            if left <= 0:
                break
            cv.wait(left)
    with _lock:
        _stats["r8_auth_ok" if holder[bucket] else "r8_auth_none"] += 1
    if holder[bucket] is None:
        return CORROB_TIMEOUT, None
    return CORROB_OK, holder[bucket]


# 2026-10-07：核对结果必须**可区分**。"核对得到 NODATA"与"我们自己排队超时/过载/通道无应答"
# 在语义上完全不同：前者是权威侧的否定证据，后者只是我们没查成。
# 混成一个 None 会让上层无法区分，也就无法写出正确的 fail-closed 规则。
CORROB_OK = "OK"            # 拿到认证答案（含权威 NXDOMAIN）
CORROB_NODATA = "NODATA"    # 权威侧应答但无地址（rcode 0/3）—— 强不一致证据
CORROB_TIMEOUT = "TIMEOUT"  # 通道无应答 / 去重锁等不到 —— **只是我们没查成**
CORROB_OVERLOAD = "OVERLOAD"  # 核对侧过载
CORROB_ERROR = "ERROR"      # 解析/内部异常
# 2026-10-15 审计 F5：sidecar 与主进程加载的**不是同一份不可变发布** ⇒ 明确拒服务。
# 由 verifier 侧在握手指纹校验失败时返回；主进程把它与 ERROR 等价处理（保守，绝不放行）✓。
CORROB_VERSION_MISMATCH = "VERSION_MISMATCH"

# verifier 应答帧的 1 字节状态映射（见 _verifier_dot）
_VSTATUS_BYTE = {CORROB_OK: b"\x00", CORROB_NODATA: b"\x01", CORROB_TIMEOUT: b"\x02",
                 CORROB_OVERLOAD: b"\x03", CORROB_ERROR: b"\x04",
                 CORROB_VERSION_MISMATCH: b"\x05"}
_VBYTE_STATUS = dict((v, k) for k, v in _VSTATUS_BYTE.items())

# ============ 2026-10-15 审计 F5：双进程发布一致性（IPC 随身携带发布指纹）============
# 背景（审计报告 F5）：两份 ExecStart 都写 .../current/...，而**切换软链不会替换已加载的
# 模块** ⇒ guard 与 verifier 可以长期跑在不同发布上，且没有任何信号 ✗（实测 PID 3610428 与
# 3495236 就分属两个发布）。
# 修法（最小、可验证、上层零改动）：guard 每次 IPC 都带上自身发布指纹；verifier 用**自己目录**
# 里的 guard 模块指纹（它按 __file__ 同目录导入 ⇒ 天然代表"我这份代码"）与之比对，不一致即回
# VERSION_MISMATCH 且**不执行任何查询**；主进程把该状态记为 ERROR 等价并限频告警 ✓。
VERIFIER_PROTO = 2          # IPC 协议版本；字段或语义任何变更都必须自增 ✓
_RELM_LOG = {"last": 0.0, "n": 0}


def release_compatible(meta, my_sha=None, my_rel=None, my_proto=None):
    """返回 ok / unverified / mismatch；只有 ok 与 unverified 允许继续处理。

    · 缺 sha（老 guard 或非本协议请求）⇒ unverified：保持向后兼容，但单独计数，**不静默** ✓
    · sha / release_id / proto 任一不一致 ⇒ mismatch：这是**发布错配**，必须拒服务 ✓
    """
    if not isinstance(meta, dict):
        return "mismatch"
    _my_sha = _GUARD_SHA256 if my_sha is None else my_sha
    _my_rel = _RELEASE_ID if my_rel is None else my_rel
    _my_proto = VERIFIER_PROTO if my_proto is None else my_proto
    _sha = meta.get("sha")
    if not _sha:
        return "unverified"
    if str(_sha) != str(_my_sha):
        return "mismatch"
    if meta.get("rel") and str(meta.get("rel")) != str(_my_rel):
        return "mismatch"
    try:
        if int(meta.get("proto") or _my_proto) != int(_my_proto):
            return "mismatch"
    except Exception:
        return "mismatch"
    return "ok"


def verifier_payload_identity():
    """guard 侧 IPC meta 附带的发布指纹（与 release_compatible 对称）✓"""
    return {"rel": _RELEASE_ID, "sha": _GUARD_SHA256,
            "pv": _POLICY_VERSION, "proto": VERIFIER_PROTO}


def _relm_note():
    """verifier 版本错配：计数 + 限频告警（每分钟最多一条，绝不刷屏）✓"""
    with _lock:
        _stats["verifier_release_mismatch"] = _stats.get("verifier_release_mismatch", 0) + 1
    _RELM_LOG["n"] += 1
    _now = time.time()
    if _now - _RELM_LOG["last"] >= 60.0:
        _RELM_LOG["last"] = _now
        log("VERMISMATCH verifier 与本进程发布不一致，已拒服务 %d 次 ⇒ 查 current 软链与两进程 cwd"
            % _RELM_LOG["n"])


def corrob_query(msg, name, qtype, targets_override=None, budget=None):
    """同一域名/类型的 R8 核对串行合并，避免并发请求重复打满 DoT。

    返回 **(status, resp)**；status ∈ {OK, NODATA, TIMEOUT, OVERLOAD, ERROR}，
    只有 OK / NODATA 时 resp 才非空。
    """
    key = (name, qtype)
    _t_r8 = time.monotonic()
    with _lock:
        _stats["corrob_attempt"] += 1
    lk = _corrob_lock_get(key)
    acquired = lk.acquire(False)
    if not acquired:
        _tr_flag("r8_dedup")
        with _lock:
            _stats["r8_dedup_wait"] += 1
        acquired = lk.acquire(timeout=CORROB_DEDUP_WAIT)
        if not acquired:
            with _lock:
                _stats["corrob_dedup_timeout"] += 1
                _stats["corrob_timeout"] += 1      # 去重锁等不到也是一种"没查成"，计入失败桶
            _tr_note("r8", (time.monotonic() - _t_r8) * 1000.0, "timeout")
            return CORROB_TIMEOUT, None
    try:
        hit = corrob_get(name, qtype)
        if hit:
            # 2026-10-10 Patch16：该路径**结构上不可达**（handler 早已 `corrob_get` 命中）⇒
            # 不再在这里记 `corrob_cache_hit`（Codex 指出的死计数器），只保留 corrob_ok。
            with _lock:
                _stats["corrob_ok"] += 1
            _tr_note("r8", (time.monotonic() - _t_r8) * 1000.0, "ok")
            return CORROB_OK, hit[0]
        _st, r = _corrob_query_once(msg, name, qtype, targets_override, budget)
        if r is None:
            with _lock:
                if _st == CORROB_OVERLOAD:
                    _stats["corrob_overload"] += 1
                else:
                    _stats["corrob_timeout"] += 1
            if _st not in (CORROB_OVERLOAD, CORROB_TIMEOUT, CORROB_ERROR):
                _st = CORROB_TIMEOUT
            _tr_note("r8", (time.monotonic() - _t_r8) * 1000.0,
                     "timeout" if _st == CORROB_TIMEOUT else "fail")
            return _st, None
        rc, cips, _cn, _ct = parse_a(r)
        with _lock:
            _stats["corrob_success"] += 1
            _stats["corrob_ok"] += 1
        if not cips and rc in (0, 3):
            with _lock:
                _stats["corrob_nodata"] += 1
            _tr_note("r8", (time.monotonic() - _t_r8) * 1000.0, "skip")
            return CORROB_NODATA, r
        _tr_note("r8", (time.monotonic() - _t_r8) * 1000.0, "ok")
        _tr_flag("r8_ok")
        return CORROB_OK, r
    except Exception:
        with _lock:
            _stats["corrob_error"] += 1
        _tr_note("r8", (time.monotonic() - _t_r8) * 1000.0, "fail")
        return CORROB_ERROR, None
    finally:
        if acquired:
            lk.release()


_r8p_sem = threading.BoundedSemaphore(_R8P_MAX)


def _r8p_start(msg, name, qtype):
    """批次 4：在明文递归**之前**并发发起 R8 核对，返回 handle 或 None。

    ★ 红线②守卫（务必连读）：
      本函数只**提前发起核对**，返回的是一个尚未取值的 handle。
      **它不返回、也不缓存任何应答字节**，调用方拿不到任何可用答案 ⇒
      不可能出现"未核对的上游答案抢先下发"。明文答案的放行判定仍留在
      原 R8 位置（`_r8p_fetch` 的调用点），一行都没动。

    跳过提前发起的条件（都等价于"原本也不会走 R8"，故不损失覆盖面）：
      · 开关关闭 / CORROB 整体关闭；
      · qtype ∉ {1,28}（A/AAAA 之外由 R8T 路径处理，目标通道不同）；
      · CN 域名且未被 zone pin 摘掉（原 R8 块同样对它们放行、不核对）；
      · 已有核对窗口命中（corrob_get 非空 ⇒ 原路径直接改发，不再核对）；
      · 该名字正在核对退避中（原路径跳过同步核对）；
      · 在飞数已达 _R8P_MAX（记 r8_parallel_busy，退回同步路径）。
    """
    if not _R8P_ENABLED or not CORROB_ENABLED:
        return None
    try:
        if qtype not in (1, 28):
            return None
        if is_cn_domain(name) and not _cn_zone_denied(name):
            return None
        if corrob_get(name, qtype) is not None:
            return None
        if _r8_backoff_active(name, qtype):
            return None
        if not _r8p_sem.acquire(False):
            with _lock:
                _stats["r8_parallel_busy"] = _stats.get("r8_parallel_busy", 0) + 1
            return None
    except Exception:
        return None

    box = {}

    def _run():
        try:
            box["r"] = corrob_query(msg, name, qtype)
        except Exception:
            box["r"] = (CORROB_ERROR, None)
        finally:
            try:
                _r8p_sem.release()
            except Exception:
                pass

    t = threading.Thread(target=_run, daemon=True, name="r8p")
    t.start()
    with _lock:
        _stats["r8_parallel_started"] = _stats.get("r8_parallel_started", 0) + 1
    return (t, box)


def _r8p_fetch(handle, msg, name, qtype, budget):
    """取提前发起的核对结论；没有 handle（或已来不及）就退回同步 `corrob_query`。

    **语义与直接调 `corrob_query` 完全一致**：返回 (status, resp)，
    resp 为 None 时调用方原有的"核对未成功"分支照旧生效（含 fail-closed 判定）。
    ★ 超预算时**不退化成再查一遍** ⇒ 直接按超时返回，避免把核对成本翻倍、也避免
      突破 `GUARD_SYNC_BUDGET`（红线③：不减少覆盖面靠的是"原本该查的仍然查了"，
      而不是"超时了再补一次"）。
    """
    if handle is None:
        return corrob_query(msg, name, qtype, budget=budget)
    t, box = handle
    try:
        t.join(max(0.05, float(budget)))
    except Exception:
        pass
    if t.is_alive() or "r" not in box:
        with _lock:
            _stats["r8_parallel_late"] = _stats.get("r8_parallel_late", 0) + 1
        return CORROB_TIMEOUT, None
    with _lock:
        _stats["r8_parallel_used"] = _stats.get("r8_parallel_used", 0) + 1
    return box["r"]


def corrob_get(name, qtype):
    """窗口内返回 (已核对应答, 已核对IP元组)，否则 None"""
    with _lock:
        e = _corrob.get(_c_key(name, qtype))
        if not e:
            return None
        if e[0] <= time.time():
            _corrob.pop(_c_key(name, qtype), None)
            return None
        wire = _cache_replay(e)
        return (wire, e[2]) if wire else None


def corrob_put(name, qtype, resp, ips, ttl):
    """钉住已核对答案：窗口 = `min(应答 TTL, CORROB_TTL)` ✓，**不再有 30 秒强制下限** ✗。

    ★ 方案 §2 第 44/49 行**点名**了这里（"corroboration pin 将窗口强制抬到至少 30 秒"）✗ ——
    旧实现的后果与准入缓存上的 30s 下限**完全同源**：
      · 应答 TTL=5s 的名字被钉住 30s ⇒ 超出运营方授权时长 6 倍 ✗；
      · 更糟的是这个窗口**生产是 `GUARD_CORROB_TTL=3600`** ✗ ⇒ 一小时内的明文答案
        都会被"已核对"钉住直接放行（用户观察到的"上游换了 guard 还答旧值"的一条支路 ✗）。
    现在只保留**报文本身的寿命**为上限 ✓；`ttl` 非正 ⇒ 窗口 0（=不钉住、不落表）✓ ——
    零 TTL / 无地址的答案本来就不构成"已核对证据" ✗。
    注意：`ttl` 必须是**应答的真实剩余寿命** ✓（调用点传的是 `parse_a()` 出来的最小 TTL ✓）。
    """
    win = CORROB_TTL
    # ★ 方案 §2 第 49/50 行：**窗口以被钉住的那份报文自己的寿命为准** ✓。
    # 为什么必须在函数内从 `resp` 现取，而不是信调用方传的 `ttl`：实测调用点里
    # `corrob_put(name, qtype, uresp, uips, ctt8)` 传的是**干净通道**应答的 TTL ✗，
    # 被钉住的却是**明文** `uresp` ⇒ 两条应答 TTL 不同时（CDN 名很常见 ✗），
    # 就会按别人的寿命钉住自己的字节 ✗（干净说 300s 而明文只有 30s ⇒ 超授 10 倍 ✗）。
    # 取 `min(调用方给的 ttl, resp 自己的最小 TTL)` ✓：两个口径都不得被突破 ✓。
    _t = 0.0
    try:
        _t = float(ttl)
    except Exception:
        _t = 0.0
    try:
        if isinstance(resp, (bytes, bytearray)):
            _own = float(parse_a(bytes(resp))[3] or 0.0)
            # `_own <= 0` ⇒ 报文没给出任何可用的寿命 ⇒ 不得凭空给窗口 ✓（见下）
            _t = _own if (_t <= 0 or _own <= 0) else min(_t, _own)
    except Exception:
        pass
    if _t <= 0:
        # ★ 方案 §2 第 49 行："禁止 TTL=0 入缓存" ✓ —— 这里同样不得凭空给窗口 ✗。
        # 旧实现只处理 `ttl > 0`，`ttl == 0` 反而**落回 `CORROB_TTL`（生产 3600）** ✗，
        # 恰好把"零 TTL"变成"最长窗口"，方向完全反了 ✗。
        # 并且**连 `_r8_stable` 也不得更新** ✓ —— 那张表是"最近一次成功认证核对"的时间戳，
        # 用来跳过后续实时 R8 核对（`stable_fast`）✗：没有可用寿命的答案不构成核对成功，
        # 若给它盖上"刚核对过"的章，等于**永久跳过核对** ✗（比窗口本身更危险 ✗）。
        return
    win = min(win, _t)
    with _lock:
        if len(_corrob) > 20000:
            now = time.time()
            for k in [k for k, v in list(_corrob.items()) if v[0] < now]:
                _corrob.pop(k, None)
        _corrob[_c_key(name, qtype)] = (time.time() + win, resp, tuple(ips), _cache_stamp())
        _r8_stable[(name, qtype)] = time.time()
        global _r8_stable_dirty
        _r8_stable_dirty = True


def mk_servfail(msg, qid=None, rcode=2, ede=None):
    """fail-closed 应答：用客户端查询的 question 段构造 SERVFAIL(rcode=2)。
    用于"已判可疑但拿不到干净答案"的场景，绝不把可疑答案下发。返回 None 表示无法构造。

    2026-10-09 B2/B3：新增 rcode / ede，**只给"本地通道堵塞"路径使用**：
      · rcode=5(REFUSED) 表达"本机容量不足"，与"上游真的解析失败"区分开；
      · ede=<RFC8914 信息码> 时附加 EDE（仅当请求带 EDNS0，避免给老客户端塞 OPT）。
      · R1/R3/R8 等真正的 fail-closed 路径仍用默认 SERVFAIL，语义不变。
    """
    try:
        if qid is None:
            qid = struct.unpack("!H", msg[:2])[0]
        flags = struct.unpack("!H", msg[2:4])[0]
        rf = 0x8000 | (flags & 0x7900) | 0x0080 | (int(rcode) & 0xF)
        off = 12
        while off < len(msg) and msg[off]:
            off += 1 + msg[off]
        end = min(off + 5, len(msg))
        if end <= 12:
            return None
        opt = b""
        if ede:
            try:
                arcount = struct.unpack("!H", msg[10:12])[0]
            except Exception:
                arcount = 0
            if arcount > 0:
                # OPT RR: NAME=0, TYPE=41, CLASS=payload(1232), TTL=0, RDLEN=6
                # EDE option: OPTION-CODE=15, LEN=2, INFO-CODE
                opt = (b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 6)
                       + struct.pack("!HHH", 15, 2, int(ede) & 0xFFFF))
        return struct.pack("!HHHHHH", qid, rf, 1, 0, 0, 1 if opt else 0) + msg[12:end] + opt
    except Exception:
        return None


def suspicious(ips, name):
    if in_allow(name):
        with _lock:
            _stats["allow_hits"] += 1
        return None
    for ip in ips:
        # 2026-10-09 范围修正：只在**该 IP 被确认的域名范围**内命中（不再是全局集合匹配）
        if _ip_hit(ip, name):
            with _lock:
                _stats["bad_ip_hits"] += 1
            return "R1 命中已确认投毒地址 %s（限定范围）" % ip
    for ip in ips:
        if _norm_ip(ip) in _POISON_IPS_NORM:
            return "R1 命中已知注入地址 %s" % ip
    hit = range_hit(ips, name, strict=False)
    if hit:
        return "R1 %s（%s）" % (hit[1], hit[0])
    return None


# ---------------- 后台核验 R4/R5/R6 ----------------
def load_r5():
    """载入 R5 候选窗口状态（跨重启保留，便于人工复核）。"""
    global _R5_PENDING
    try:
        with open(R5_FILE) as f:
            d = json.load(f)
        _R5_PENDING = dict((k, list(v)) for k, v in (d.get("pending") or {}).items())
    except Exception:
        _R5_PENDING = {}


def save_r5():
    try:
        with _lock:
            snap = dict((k, list(v)[-4:]) for k, v in _R5_PENDING.items())
        if len(snap) > 400:
            snap = dict(sorted(snap.items(), key=lambda kv: -max((w.get("ts") or 0) for w in kv[1]))[:400])
        _atomic_json(R5_FILE, {"updated": time.time(), "pending": snap})
    except Exception as e:
        log("save_r5 error: %s" % e)


def _r5_category(name):
    """给人工队列打类别，便于批量忽略（用户 P4：NTP/CRL/OCSP/CDN 默认只进队列）。"""
    n = (name or "").lower()
    for t in _R5_CAT_CRL:
        if t in n:
            return "crl/ocsp"
    for t in _R5_CAT_NTP:
        if t in n:
            return "ntp"
    for t in _R5_CAT_CDN:
        if t in n:
            return "cdn/geodns"
    return ""


def _r5_candidate(name, uips, cips, us=None, cs=None):
    """P4：R5 只进候选队列，**绝不写自动黑名单**。
    需两个独立窗口（间隔 R5_WINDOW_MIN~MAX）；任一窗口干净样本变化 ⇒ 丢弃候选。"""
    now = time.time()
    us = [list(x) for x in (us or [])]
    cs = [list(x) for x in (cs or [])]
    if len(set(tuple(sorted(x)) for x in us)) < 2:
        with _lock:
            _stats["r5_discarded"] = _stats.get("r5_discarded", 0) + 1
        return False
    drop = None
    with _lock:
        hist = _R5_PENDING.setdefault(name, [])
        if hist and (now - (hist[-1].get("ts") or 0)) < R5_WINDOW_MIN:
            _stats["r5_same_window"] = _stats.get("r5_same_window", 0) + 1
            return False
        if hist and (now - (hist[0].get("ts") or 0)) > R5_WINDOW_MAX:
            _R5_PENDING[name] = hist[-1:]
            hist = _R5_PENDING[name]
            _stats["r5_discarded"] = _stats.get("r5_discarded", 0) + 1
        if hist:
            prev_cs = set(tuple(sorted(x)) for x in (hist[-1].get("cs") or []))
            cur_cs = set(tuple(sorted(x)) for x in cs)
            if prev_cs and cur_cs and prev_cs != cur_cs:
                _R5_PENDING.pop(name, None)
                _stats["r5_discarded"] = _stats.get("r5_discarded", 0) + 1
                drop = "clean-changed"
        if drop is None:
            hist.append({"ts": now, "us": us, "cs": cs,
                         "uips": [x for x in (uips or [])][:6], "cips": [x for x in (cips or [])][:6]})
            _stats["r5_queued"] = _stats.get("r5_queued", 0) + 1
    if drop is not None:
        log("R5X  %-38s 干净样本发生变化 → 丢弃 R5 候选（不封禁）" % name)
        save_r5()
        return False
    windows = len(hist)
    if windows >= 2:
        cat = _r5_category(name)
        with _lock:
            e = _diff.setdefault(name, {"first": hist[0].get("ts"), "count": 0, "ignored": False})
            e["last"] = now
            e["count"] = int(e.get("count") or 0) + 1
            e["unbound"] = ",".join(hist[-1].get("uips") or [])
            e["clean"] = ",".join(hist[-1].get("cips") or [])
            e["source"] = "R5"
            e["category"] = cat
            e["windows"] = windows
            _stats["r5_window2"] = _stats.get("r5_window2", 0) + 1
        save_diff()
        log("R5Q  %-38s %d 个独立窗口抖动、干净侧稳定 → 进入人工待确认（category=%s），不自动封禁"
            % (name, windows, cat or "-"))
    else:
        log("R5W  %-38s 第 1 个抖动窗口已记录（需第 2 个独立窗口，间隔 >=%ds）"
            % (name, R5_WINDOW_MIN))
    save_r5()
    return True


def r5_scheduler():
    """P4：为已记录第 1 窗口的候选，在 10~30 分钟后自动跑第 2 窗口（不受 REVERIFY_AFTER 限制）。"""
    while True:
        try:
            time.sleep(R5_SCHED_TICK)
            now = time.time()
            with _lock:
                due = [(n, v) for n, v in _R5_PENDING.items()
                       if len(v) == 1 and R5_WINDOW_MIN <= (now - (v[0].get("ts") or now)) <= R5_WINDOW_MAX]
                stale = [n for n, v in _R5_PENDING.items()
                         if len(v) == 1 and (now - (v[0].get("ts") or now)) > R5_WINDOW_MAX]
                for n in stale:
                    _R5_PENDING.pop(n, None)
            if stale:
                log("R5S  丢弃超时的单窗口候选 %d 个" % len(stale))
                save_r5()
            for name, _v in due[:8]:
                try:
                    uips = (_v[0].get("uips") or [])
                    cips = (_v[0].get("cips") or [])
                    jv = jitter_verdict(name, mk_query(name), n=4)
                    if jv == "poison":
                        us = churn_samples(name, n=4)
                        cs = clean_samples(mk_query(name), n=4)
                        _r5_candidate(name, uips, cips, us=us, cs=cs)
                    elif jv in ("rotate", "stable"):
                        with _lock:
                            _R5_PENDING.pop(name, None)
                            _stats["r5_dropped_rotate"] = _stats.get("r5_dropped_rotate", 0) + 1
                        log("R5S  %-38s 第 2 窗口判定=%s → 丢弃候选（域名自身轮转/已稳定）" % (name, jv))
                        save_r5()
                except Exception as e:
                    log("R5S  %-38s 第 2 窗口探测失败: %s" % (name, str(e)[:60]))
        except Exception as e:
            log("r5_scheduler error: %s" % str(e)[:80])


def record_diff(name, uips, cips):
    """记录"与干净上游不一致但当前无法判定"的候选，供人工确认（不自动改路由）"""
    flags = [is_cn_ip(i) for i in uips]
    if flags and all(f is True for f in flags):
        with _lock:
            _stats["geo_skipped"] += 1
        log("GEO  %-38s unbound=%s(国内) clean=%s → 国内就近解析，不计入待确认"
            % (name, ",".join(uips)[:24], ",".join(cips)[:24]))
        return
    if uips and cips and ":" in uips[0] and ":" in cips[0] and uips[0].split(":")[:3] == cips[0].split(":")[:3]:
        with _lock:
            _stats["geo_skipped"] += 1
        log("GEO  %-38s IPv6 同 /48 差异 → 忽略" % name)
        return
    with _lock:
        e = _diff.get(name)
        if e is None:
            if len(_diff) >= DIFF_MAX:
                oldest = min(_diff.items(), key=lambda kv: kv[1].get("last", 0))[0]
                _diff.pop(oldest, None)
            e = {"first": time.time(), "count": 0, "ignored": False}
            _diff[name] = e
        e["count"] = e.get("count", 0) + 1
        e["last"] = time.time()
        e["unbound"] = ",".join(uips[:6])
        e["clean"] = ",".join(cips[:6])
    save_diff()
    log("DIFF %-40s unbound=%s clean=%s (无判定证据，待确认)"
        % (name, ",".join(uips)[:40], ",".join(cips)[:40]))


def churn_samples(name, n=3):
    """清缓存后连查 n 次 unbound A，返回每次的地址集合（已排序元组）"""
    sets = []
    for _ in range(n):
        try:
            subprocess.run(["docker", "exec", UNBOUND_CONTAINER, "unbound-control", "flush", name],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=6)
        except Exception:
            return sets
        time.sleep(0.35)
        r = udp_query(UNBOUND, mk_query(name), timeout=DOM_TIMEOUT)
        if r is None:
            continue
        _, ips, _, _ = parse_a(r)
        if ips:
            sets.append(tuple(sorted(ips)))
    return sets


def clean_samples(qmsg, n=2):
    """对干净上游连取 n 次（不读不写缓存），用于判断"域名本身是否轮转" """
    out = []
    for _ in range(n):
        r = dot_query(qmsg, timeout=3)
        if r is None:
            continue
        _, ips, _, _ = parse_a(r)
        if ips:
            out.append(tuple(sorted(ips)))
    return out


def jitter_verdict(name, qmsg, n=4):
    """抖动判据（R5），带两层对照，避免误伤"本来就轮转"的域名：
         unbound 稳定                     -> "stable"
         unbound 抖动但有稳定交集(RRset 子集轮转) -> "rotate"
         干净上游同样抖动（NTP pool 等）    -> "rotate"
         只有 unbound 抖动且无交集          -> "poison"
       返回 None 表示无法判定（未启用/限速/样本不足）"""
    global _churn_last
    if not CHURN_ENABLED:
        return None
    now = time.time()
    with _lock:
        if now - _churn_last < CHURN_GAP:
            return None
        _churn_last = now
    us = churn_samples(name, n=n)
    with _lock:
        _stats["jitter_checks"] += 1
    if len(us) < 2:
        return None
    if len(set(us)) == 1:
        return "stable"
    common = set(us[0])
    for s in us[1:]:
        common &= set(s)
    if common:
        return "rotate"
    cs = clean_samples(qmsg, n=4)
    if len(set(cs)) > 1:
        return "rotate"
    return "poison"


def verify_one(name, qtype, qmsg, uips, ucn):
    """后台核验：先看干净上游答案，再依次用 证书对照 / 抖动 / 严格段 判定。"""
    if (_diff.get(name) or {}).get("ignored"):
        return                      # 人工已判定忽略，不再自动学习
    resp = dot_query(qmsg, timeout=4)
    if not resp:
        return
    rc, cips, ccn, _ = parse_a(resp)
    if not cips or set(cips) == set(uips):
        return
    v4u = [x for x in uips if ":" not in x]
    v4c = [x for x in cips if ":" not in x]
    # ① 国内就近差异
    flags = [is_cn_ip(i) for i in uips]
    if flags and all(f is True for f in flags):
        with _lock:
            _stats["geo_skipped"] += 1
        log("GEO  %-38s unbound=%s(国内) → 就近差异，不判投毒" % (name, ",".join(uips)[:24]))
        return
    # ② CNAME 伪造特征（真答案是链，unbound 直接给 A）
    if ccn > 0 and ucn == 0:
        mark(name, "R4 真答案是 CNAME 链而 unbound 直接给 A", ",".join(uips), ",".join(cips))
        return
    # ③ 证书对照（只认"域名不匹配"，且必须证明干净上游的 IP 才是主人）
    if v4u and v4c:
        vu = cert_name_match(v4u[0], name)
        if vu is True:
            with _lock:
                _stats["cdn_skipped"] += 1
            log("CDN  %-38s unbound=%s 证书含该域名 → 同域名 CDN 边缘差异" % (name, v4u[0]))
            return
        if vu is False:
            vc = None
            cip = None
            for x in v4c[:2]:
                vc = cert_name_match(x, name)
                cip = x
                if vc is not None:
                    break
            if vc is True:
                with _lock:
                    _stats["cert_learned"] += 1
                mark(name, "R6 证书对照：unbound 的 %s 不持有该域名证书，干净上游的 %s 持有"
                     % (v4u[0], cip), ",".join(uips), ",".join(cips))
                return
            log("CERT %-38s unbound=%s 证书不含该域名，但干净上游 %s 也拿不到该域名证书 → 无法判定"
                % (name, v4u[0], cip or "?"))
    # ④ 纯 IPv6 差异：本机无 IPv6，无法核验
    if not v4u:
        with _lock:
            _stats["v6_skipped"] += 1
        log("V6   %-38s IPv6 差异（无法核验），仅记录" % name)
        return
    # ⑤ 多采样抖动（R5，带"域名本身轮转"对照）
    jv = jitter_verdict(name, qmsg, n=4)
    if jv == "poison":
        with _lock:
            _stats["r5"] += 1
        # 2026-10-09 P4：**不再写入自动黑名单**，只进候选队列（两个独立窗口后进入人工待确认）。
        # 实时防护由 R8/R6 等强证据承担（本函数下方的 range_hit 与后台核验均不变）。
        try:
            _r5_candidate(name, uips, cips,
                          us=churn_samples(name, n=4), cs=clean_samples(qmsg, n=4))
        except Exception as e:
            log("R5C  %-38s 候选记录失败: %s" % (name, str(e)[:60]))
        return
    if jv == "rotate":
        with _lock:
            _stats["rot_skipped"] += 1
        log("ROT  %-38s 答案会变但干净上游同样会变/存在稳定交集 → 域名自身轮转，不判投毒" % name)
        return
    # ⑥ 严格注入段 + 干净上游不一致
    hit = range_hit(uips, name, strict=True)
    if hit:
        mark(name, "R1 %s，且干净上游答案不同（%s）" % (hit[1], hit[0]), ",".join(uips), ",".join(cips))
        return
    # ⑦ 其余 → 待确认清单
    if not (_diff.get(name) or {}).get("ignored"):
        record_diff(name, uips, cips)


def verifier():
    while True:
        item = None
        with _lock:
            if _verify_queue:
                item = _verify_queue.pop(0)
        if not item:
            time.sleep(1.0)
            continue
        name, qtype, qmsg, uips, ucn = item
        try:
            verify_one(name, qtype, qmsg, uips, ucn)
        except Exception as e:
            log("verify error %s: %s" % (name, e))


def queue_verify(name, qtype, qmsg, uips, ucn):
    now = time.time()
    with _lock:
        if name in _table:
            return
        seen = _verify_seen.get(name)
        if seen and now - seen < REVERIFY_AFTER:
            return
        if len(_verify_queue) > 500:
            return
        _verify_seen[name] = now
        if len(_verify_seen) > 20000:
            _verify_seen.clear()
        _verify_queue.append((name, qtype, qmsg, uips, ucn))


# ---------------- 状态写入 ----------------
# 2026-10-09 清理修复 A：unbound 默认 `private-address` 会剥掉 RFC1918/保留地址，
# 导致"我方无地址、干净通道有地址"的假象。这里识别"全部是私网/保留地址"的答案。
_PRIV_PREFIX = ("10.", "127.", "169.254.", "192.168.", "0.", "224.", "225.", "226.", "227.",
                "228.", "229.", "230.", "231.", "232.", "233.", "234.", "235.", "236.", "237.",
                "238.", "239.", "240.", "241.", "242.", "243.", "244.", "245.", "246.", "247.",
                "248.", "249.", "250.", "251.", "252.", "253.", "254.", "255.")


def _is_private_v4(ip):
    """RFC1918 / 环回 / 链路本地 / CGNAT / 组播 / 保留段。"""
    if not ip or ":" in ip:
        return False
    if ip.startswith(_PRIV_PREFIX):
        return True
    try:
        a, b = int(ip.split(".")[0]), int(ip.split(".")[1])
    except Exception:
        return False
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 100 and 64 <= b <= 127:
        return True
    return False


def _all_private(ips):
    v4 = [x for x in (ips or []) if ":" not in x]
    return bool(v4) and all(_is_private_v4(x) for x in v4)


def _strength_of(why):
    """按证据类型判强弱（问题2）。strong = R1/R4/R6/人工确认；其余一律 weak。

    为什么不按观察次数：R2/R5 的"再次观察"往往还是同一类抖动，累计次数无法区分真伪；
    真实投毒会再次以 R1/R4/R6（带具体坏地址/结构异常/证书不符）命中 ⇒ 届时自动升强。
    """
    w = why or ""
    for _p in POISON_STRONG_PREFIX:
        if w.startswith(_p):
            return "strong"
    return "weak"


def _poison_entry(name):
    """取域名对应的黑名单条目：精确优先，其次父域匹配（与 known 判定口径一致）。"""
    e = _table.get(name)
    if e:
        return e
    for _d, _v in _table.items():
        if name.endswith("." + _d):
            return _v
    return None


def _expire_weak_poison(now=None):
    """弱证据 WEAK_TTL 未再观察 ⇒ 移出黑名单并转入待确认清单（可人工 --confirm 恢复）。"""
    now = time.time() if now is None else now
    n = 0
    with _lock:
        for _d in list(_table.keys()):
            _e = _table.get(_d) or {}
            _st = _e.get("strength") or _strength_of(_e.get("why", ""))
            if _st != "weak":
                continue
            _last = float(_e.get("last") or _e.get("first") or now)
            if now - _last > WEAK_TTL:
                _table.pop(_d, None)
                _diff.setdefault(_d, {"first": _e.get("first") or now, "last": now, "count": 0,
                                      "unbound": _e.get("bad", ""), "clean": _e.get("clean", ""),
                                      "ignored": False, "expired_weak": True})
                n += 1
    if n:
        with _lock:
            _stats["poison_expired"] = _stats.get("poison_expired", 0) + n
        log("WEXP 弱证据过期移出黑名单 %d 条（%d 天未再观察 → 转入待确认清单）"
            % (n, int(WEAK_TTL / 86400)))
        save_state()
        try:
            save_diff()
        except Exception as _e2:
            log("WEXP save_diff error: %s" % _e2)
    return n


def mark(name, why, bad, good):
    """记录判定。2026-10-05 P1-9：锁内只改内存，日志与整表落盘移到锁外
    （旧写法把 log+save_state 放在全局 _lock 里，每次学习都会阻塞所有并发查询）。"""
    is_new = False
    snap = None
    _st = _strength_of(why)          # 2026-10-09 问题2：按证据类型定强弱
    _promoted = False
    with _lock:
        e = _table.get(name)
        if e:
            e["hits"] = e.get("hits", 1) + 1
            e["why"] = why
            e["bad"] = bad
            e["clean"] = good
            e["last"] = time.time()
            e["strength"] = e.get("strength") or _strength_of(e.get("why", ""))
            # **只升不降**：弱证据之后再出现强证据（R1/R4/R6）⇒ 升级；降级只由过期/人工做
            if _st == "strong" and e["strength"] != "strong":
                e["strength"] = "strong"
                e["promoted"] = time.time()
                _promoted = True
        else:
            _table[name] = {"why": why, "bad": bad, "clean": good, "first": time.time(),
                            "last": time.time(), "hits": 1, "strength": _st}
            is_new = True
            snap = dict(_table)
    if _promoted:
        with _lock:
            _stats["poison_promoted"] = _stats.get("poison_promoted", 0) + 1
        log("PROMO %-40s 弱证据 → 强证据（%s）" % (name, why[:50]))
    # ★ 方案 §2 第 51 行：**后台发现 bogus 后阻止后续返回** ✓。
    # `mark()` 是后台核验（`verify_one()`）判定投毒/伪造的**唯一落点** ⇒ 这里不清缓存，
    # 后台刚判定的结论就无法阻止旧答案继续发出 ✗：准入缓存（答案）、`_corrob`
    # （R8 钉住窗口，生产 `GUARD_CORROB_TTL=3600s` ✗）、`_neg_cache`（否定结论）
    # 三者都还会照旧命中 ✓→✗。只在**新增/升级为强证据**时清 ✓（弱证据多是抖动，
    # 大量强制失效会把可用性打掉 ✗；而强证据是名字级结论，必须立即生效 ✓）。
    if is_new or _promoted or _st == "strong":
        try:
            _drop_caches_for(name, why="mark_strong" if _st == "strong" else "mark_new")
        except Exception:
            pass
    if is_new:
        log("LEARN %-40s %s  bad=%s  clean=%s" % (name, why, bad, good))
        if snap is not None:
            try:
                _atomic_json(STATE, {"updated": time.time(), "domains": snap},
                             ensure_ascii=False, indent=1)
            except Exception as e2:
                log("save_state error: %s" % e2)
    # 2026-10-09 问题2修复：**只有强证据才允许学习投毒 IP** ——
    # 否则一次抖动（R5）就会把合法 IP 推进"确认投毒地址"学习集，并借 ≥2 域名印证扩散。
    if _st == "strong":
        # P3：带上规则与干净答案，供注册域/窗口/依据/持续不一致判定与留证
        learn_bad_ips([x for x in (bad or "").split(",") if x], name, why=why,
                      clean_ips=[x for x in (good or "").split(",") if x])


# 允许的 B 消费者标签（第7步的分类口径）。guard 进程内部只产生 guard_cn；
# 其余标签是为"跨进程归类"预留的同一套命名，真值由 chainmon 反解，见 b_attrib。
B_CONSUMERS = ("guard_cn", "chainmon_probe", "cn_rules", "manual")


def resolve_cn_via_unbound_b(msg, name, consumer="guard_cn", timeout=None):
    """★ 2026-10-08 二档·第7步：**访问 unbound B（国内加密源）的唯一出口**。

    B 的职责已收敛为「CN 域名的国内兜底 / 核对源」，因此这里施加三重硬约束：

      1. **收口**：guard.py 里唯一一处"以 B 为目标"的 udp 查询就在本函数内。
         任何新增的 B 用法都必须走本函数，否则第 7 步的收口自检会立刻失败
         （判据：可执行代码里目标为 B 的查询调用点恰好一个）。
      2. **强制 CN 判定**：`is_cn_domain(name)` 为假 ⇒ **不构造、不发送任何报文**，
         只记 `unbound_b_noncn_attempt` 并返回 None。门控在函数内部、不依赖调用方自觉 ——
         这样即便未来有人在非 CN 路径上直接调用 bget()，也不会漏出一次 B 查询。
      3. **按消费者记账**：每发出一次都计入 `unbound_b_queries_total` 与
         `unbound_b_queries_<consumer>`，使"B 收到多少查询 = 谁打进来的"可对账。
    """
    if not is_cn_domain(name or ""):
        with _lock:
            _stats["unbound_b_noncn_attempt"] = _stats.get("unbound_b_noncn_attempt", 0) + 1
        return None
    _c = consumer if consumer in B_CONSUMERS else "manual"
    with _lock:
        _stats["unbound_b_queries_total"] = _stats.get("unbound_b_queries_total", 0) + 1
        _k = "unbound_b_queries_" + _c
        _stats[_k] = _stats.get(_k, 0) + 1
    try:
        return udp_query(UNBOUND_B, msg, timeout=(B_TIMEOUT if timeout is None else timeout))
    except Exception:
        return None


def domestic(msg, skip_a=False, name=None, qtype=None):
    # 2026-10-10 P34-Y（第二轮子代理审计发现 ✗）：`fallback_b`（A 超时 → 采用 B）此前只有 zone-pin，
    # **没有"否定存在否决"** ✗ ⇒ A 超时的那次查询里，B 的注入答案会不被核对地送出 ✗。
    # 本条路径需要一个 qtype 才能做族判定 ⇒ 由调用方传入（默认 None 时退化为只做 zone-pin ✓）。
    """国内两级源：unbound A 为主、unbound B（加密国内源，**仅供 CN 域名**）为兜底。
    返回 (应答, 来源, bget)。

    2026-10-07 二档·第10步：**B 的职责收敛为「CN 域名的国内出口/兜底」**。
    旧版把 B 的并发预发扩展到所有 A/AAAA，并在非 CN 域名的 R2 尾部采用 B 的答案 ——
    那让全链路最慢的一环（B：中位 584ms、队列峰值 1415）替境外域名作答，并污染同步核对的
    对照口径。现在：
      · 只有 CN 域名才并发预发 B（`GUARD_CN_OVERLAP` 为空则退回串行）；
      · A 无应答时的 B 兜底也只对 CN 域名生效；
      · B 的截止时间收紧为 B_TIMEOUT(0.9s)，不再用 1.2s。
    非 CN 域名在 A 无应答时交给加密认证通道（R2 / dot_query），不再回落到国内源。"""
    b = {"r": None, "started": False, "ev": threading.Event()}

    def _b_worker():
        _t_b = time.monotonic()
        try:
            # 2026-10-08 第7步：并发预发同样必须经过收口函数（内部做 CN 判定与记账）
            b["r"] = resolve_cn_via_unbound_b(msg, name, consumer="guard_cn")
        except Exception:
            b["r"] = None
        finally:
            _tr_note("b", (time.monotonic() - _t_b) * 1000.0, "ok" if b["r"] else "fail")
            _tr_flag("b_ok" if b["r"] else "b_fail")
            b["ev"].set()

    def bget():
        if b["started"]:
            b["ev"].wait(B_TIMEOUT + 0.3)
            return b["r"]
        # 2026-10-08 第7步：串行现查同样收口。非 CN 名字（若将来有人这样调用 bget）会在
        # 函数内部被挡住并返回 None，不会真的向 B 发包。
        _t_bs = time.monotonic()
        _rb_s = resolve_cn_via_unbound_b(msg, name, consumer="guard_cn")
        _tr_note("bget", (time.monotonic() - _t_bs) * 1000.0, "ok" if _rb_s else "fail")
        _tr_flag("b_ok" if _rb_s else "b_fail")
        return _rb_s

    # 2026-10-10 Patch18（P1 配套）：**CN 名优先用 B**（国内加密 DoT，geo 正确 ✓）。
    # P1 已把 unbound A 的递归出口改为经认证加密上游（本机 aghdq→DoQ→NextDNS），其解析位置
    # 在境外 ⇒ 经 A 解析 CN 名会拿到海外边缘（实测百度 18ms→178ms、抖音拉流 14ms→269ms ✗✗）。
    # B 成功即返回（src="B"），失败再回落 A 以保证可用性；非 CN 名行为完全不变 ✓。
    # 开关 GUARD_CN_PREFER_B（默认开）用于单键回退。
    if name and is_cn_domain(name) and not _cn_zone_denied(name):
        _tr_flag("cn_path")            # Step-1 §1：CN 路径占比
        if not _flag("GUARD_CN_PREFER_B", True):
            with _lock:
                _stats["cn_prefer_b_disabled"] = _stats.get("cn_prefer_b_disabled", 0) + 1
        else:
            # 2026-10-10 P34-F：**与 B 并发预发 A 见证**（Codex 方案里"恢复 CN_OVERLAP 的 A 预发"✓）。
            # 仅当模式非 off 且该名字未命中清洁缓存时预发 ⇒ **off 时零成本** ✓。
            _a_hint = None
            try:
                # ★ §3 第 70 行：见证**每请求最多启动一次** ✓ —— 槽位必须由**主线程**
                #   在 `_ta.start()` **之前**占用 ✗（放在 `_a_pre()` 内部会与主线程
                #   `_t.join()` 之后的 `_policy_cn_answer()` → `_retry_authenticated()`
                #   抢同一个槽位 ✗ ⇒ 竞态下"预发的这一次"被自己后面的路径判成重复 ✗）。
                #   `_veto_udp()` 现在把原始 wire 一起带回来 ✓ ⇒ 下游 `_policy_cn_answer()`
                #   直接用它 ✓，旧路径的 `udp_query(timeout=1.0)` 重复取数已删除 ✓。
                if (CN_EXIST_MODE != "off"
                        and not (CN_DOMESTIC_PRIMARY and CN_DOMESTIC_TRUST_B and is_cn_trusted(name))
                        and not _cn_clean_get(name) and _src_once("witness")):
                    _a_hint = {"v": None, "t": None}

                    def _a_pre():
                        try:
                            _t_ap = time.monotonic()
                            _a_hint["v"] = _veto_udp(name, parse_q(msg)[1], _witness_addr, CN_VETO_BUDGET)
                            _tr_note("a_pre", (time.monotonic() - _t_ap) * 1000.0,
                                     "ok" if _a_hint["v"] else "fail")
                            _src_mark("witness", "ok" if _a_hint["v"] else "fail")
                        except Exception:
                            _a_hint["v"] = None
                            _src_mark("witness", "fail")

                    _ta = threading.Thread(target=_a_pre)
                    _ta.daemon = True
                    _a_hint["t"] = _ta
                    _ta.start()
                elif (CN_EXIST_MODE != "off"
                      and not (CN_DOMESTIC_PRIMARY and CN_DOMESTIC_TRUST_B and is_cn_trusted(name))
                      and not _cn_clean_get(name)):
                    # 槽位已被占（例如 `_cn_sf` 合并路径或本请求早先的见证调用）⇒ 不重复预发 ✓
                    with _lock:
                        _stats["witness_dup_skipped"] = _stats.get("witness_dup_skipped", 0) + 1
            except Exception:
                _a_hint = None
            _rb = bget()
            if _rb is not None:
                with _lock:
                    _stats["cn_prefer_b_hit"] = _stats.get("cn_prefer_b_hit", 0) + 1
                # 2026-10-10 Patch34-B：CN 分路此前**完全绕过核对** ✗ ⇒ 先做"否定存在否决"。
                # 默认 off ⇒ 行为与今天完全一致 ✓；off 时连 _rb 都不动 ✓。
                # QTYPE is needed below even when trusted-CN mode skips witness work.
                # Parse it before the conditional so every route has the same question type.
                try:
                    _pq = parse_q(msg)
                    _qt = _pq[1] if _pq and len(_pq) > 1 and _pq[1] else (qtype or 1)
                except Exception:
                    _qt = qtype or 1
                if (CN_EXIST_MODE != "off"
                        and not (CN_DOMESTIC_PRIMARY and CN_DOMESTIC_TRUST_B
                                 and is_cn_trusted(name))):
                    # 修正（2026-10-10，单次归因实测发现）：domestic() 返回的第三个元素 `bget`
                    # 是"取**应答字节**"的函数 ✗，不是"取 IP 列表"的函数 —— 之前把它当 IP 列表用，
                    # 迭代 bytes 必然 TypeError 并被吞掉 ⇒ _bips 恒为空 ⇒ veto 从未生效 ✗。
                    # 注意：**本作用域内 `_rb` 就是应答字节**（domestic 返回的元组 (应答, 源, bget)
                    # 是由 `return _rb, "B", bget` 现场构造的）⇒ 这里必须用 `_rb`，不是 `_rb[0]` ✗。
                    try:
                        _rc_b, _bips, _cn_b, _ttl_b = parse_a(_rb)
                    except Exception:
                        _rc_b, _bips = None, []
                    if _bips and ((_qt == 1 and all(":" not in x for x in _bips))
                                  or (_qt == 28 and all(":" in x for x in _bips))):
                        # domestic() 内没有 handle() 的 deadline; compute a bounded local window
                        _dl = _dl_wall(max(0.5, CN_VETO_BUDGET))
                        _v = cn_exist_veto(name, _qt, _rb, _bips, _dl, w1_hint=_a_hint)
                        if _v is not None:
                            _tr_flag("veto_hit")
                            return _v, "CNV", (lambda: [])
                        _tr_flag("veto_none")
                # P34-AQ 修正：_a_hint 是**并发预发**的见证结果 ✗ ⇒ 当场可能还没写回
                # ⇒ 先等最多 0.35s（不占用太多预算 ✓），拿到就用，拿不到再退 alt ✓。
                _hint_a = None
                try:
                    if isinstance(_a_hint, dict):
                        _t = _a_hint.get("t")
                        if _t is not None:
                            # P34-BA（方案 5.2「取用顺序」）：见证通常 0.25~0.4s 就能回来 ✓，
                            # 固定等 0.35s 太短 ✗ ⇒ 改为**在剩余预算内等**（cap 1.0s，且为认证备用留 1.2s 余量 ✓）。
                            _left_w = _dl_left()
                            _t.join(0.35 if _left_w is None else max(0.1, min(1.0, _left_w - 1.2)))
                        _hint_a = _a_hint.get("v")
                except Exception:
                    _hint_a = None
                _pw = _policy_cn_answer(name, _qt, _hint_a, _rb,
                                        deadline=_dl_wall(3.0),
                                        query_id=(msg[:2] if len(msg) >= 2 else None))
                if _pw is not None and _pw.wire:
                    # P0-2：`_policy_cn_answer` 只给 `Answer` ✓ ⇒ 出口由 handle() 统一过闸 ✓
                    # （§6：国内认证源 ⇒ `_LABEL_MAP["CNB"]` = "local-cn" ✓；其余 ⇒ "POL" = "local-alt" ✓）
                    _tr_flag("policy_used")
                    return _pw.wire, _pol_label(_pw), bget
                if POLICY_MODE:
                    _tr_flag("fail_closed")
                    return mk_servfail(msg), "POL-SF", bget
                _tr_flag("b_used")
                return _rb, "B", bget
            with _lock:
                _stats["cn_prefer_b_miss"] = _stats.get("cn_prefer_b_miss", 0) + 1
    if not skip_a:
        # ==== 2026-10-07 二档·第10步：并发预发 B **只对 CN 域名** ====
        # 旧版（GUARD-OVERLAP-A4）把并发扩展到所有 A/AAAA，理由是"R8 里那句 bget() 会串行现查"
        # —— 但实测 **R8 块（2147-2273）不含任何 B 引用**，那句注释是过期的；真正会现查 B 的是
        # R2 尾部，而该分支本轮已整体移除（非 CN 域名不再用 B 作答）。
        # 于是"给非 CN 域名预发 B"失去唯一理由，只剩代价：多打一次全链路最慢的上游。
        _ovl_cn = bool(name and is_cn_domain(name))
        # ★ §3 第 70 行：**B 每请求最多启动一次** ✓ —— `bget()` 里已有 `b["started"]`
        #   复用逻辑 ✓（有 Future 就 `ev.wait` ✓），这里给启动点加统一闸门 ✗
        #   ⇒ "A 超时→再打一遍 B"这类重复取数结构上不可能 ✓，且被拦下的次数可见 ✓。
        if CN_OVERLAP and name and _ovl_cn and _src_once("b"):
            _upstream_executor.submit(_b_worker)
            b["started"] = True
            with _lock:
                _stats["cn_overlap"] += 1
        elif CN_OVERLAP and name and _ovl_cn:
            with _lock:
                _stats["b_dup_skipped"] = _stats.get("b_dup_skipped", 0) + 1
        elif name:
            with _lock:
                _stats["b_noncn_blocked"] += 1
        # ★ §3 第 70 行：**A 每请求最多启动一次** ✓ —— 本函数是 A 的唯一启动点，
        #   但 `_policy_cn_answer()` 的兜底路径历史上会另起一次 A ✗；用统一闸门收口 ✓。
        _a_ok = _src_once("a")
        if not _a_ok:
            _stats["a_dup_skipped"] = _stats.get("a_dup_skipped", 0) + 1
        _t_a = time.monotonic()
        r = udp_query(UNBOUND, msg, timeout=DOM_TIMEOUT) if _a_ok else None
        _tr_note("a", (time.monotonic() - _t_a) * 1000.0, "ok" if r else "fail")
        _tr_flag("a_ok" if r else "a_fail")
        _src_mark("a", "ok" if r else "fail")
        if _is_tc(r):
            # 2026-10-05：UDP 被截断 → 用 TCP 重查一次（只在 TC 时触发，不打扰正常/NODATA 路径）
            r2 = tcp_query(UNBOUND, msg, timeout=DOM_TIMEOUT)
            with _lock:
                _stats["tc_retry"] += 1
            if r2 is not None and not _is_tc(r2):
                with _lock:
                    _stats["tc_retry_ok"] += 1
                log("TC   %-38s UDP 截断 → TCP 重查成功（%d 字节）" % (name or "?", len(r2)))
                r = r2
        if r is not None:
            return r, "A", bget
    # 2026-10-07 二档·第10步：A 无应答时的 B 兜底 **仅限 CN 域名**。
    # 非 CN 域名的兜底交给加密认证通道（R2），不再让国内源替境外域名作答。
    # 2026-10-10 P34-W（第二轮扫描穷举发现 ✗）：这条"A 失败 → 采用 B"的兜底**此前只有**
    # `is_cn_domain` 一道门，连 `suspicious()` 都没有 ✗，而 CN 名的 R8 门控默认不跑
    # ⇒ B 的注入答案会从这里直接出 ✗。**被 pin 的 zone 一律不再采用 B** ✓。
    if is_cn_domain(name or "") and not _cn_zone_denied(name):
        rb = bget()
        if rb is not None:
            # P34-Y：补上"否定存在否决"（与 CN-prefer-B / CNB / R3B 三处一致 ✓）
            _fqt = qtype if qtype else 1
            _fbips = []
            try:
                _frc, _fbips, _fcn, _fttl = parse_a(rb)
            except Exception:
                _fbips = []
            if (CN_EXIST_MODE != "off"
                    and not (CN_DOMESTIC_PRIMARY and CN_DOMESTIC_TRUST_B and is_cn_trusted(name))
                    and _fbips):
                _fv = None
                try:
                    _fv = cn_exist_veto(name, _fqt, rb, _fbips,
                                        _dl_wall(max(0.5, CN_VETO_BUDGET)))
                except Exception:
                    _fv = None
                if _fv is not None:
                    return _fv, "CNV", (lambda: [])
            with _lock:
                _stats["fallback_b"] += 1
            _pw2 = _policy_cn_answer(name, _fqt, None, rb, deadline=_dl_wall(3.0),
                                     query_id=(msg[:2] if len(msg) >= 2 else None))
            if _pw2 is not None and _pw2.wire:
                _tr_flag("policy_used")
                return _pw2.wire, _pol_label(_pw2), bget
            if POLICY_MODE:
                _tr_flag("fail_closed")
                return mk_servfail(msg), "POL-SF", bget
            _tr_flag("b_used")
            return rb, "B", bget
    elif is_cn_domain(name or ""):
        with _lock:
            _stats["cn_zone_deny_hit"] = _stats.get("cn_zone_deny_hit", 0) + 1
        # ★ 方案 §2 第 51 行：**强否决时立即失效关联缓存** ✓ ——
        # zone 被 pin 意味着该 zone 的既有结论已被判定不可信 ✗；
        # 若继续用准入缓存里的旧答案答复，pin 就形同虚设 ✗。
        _drop_caches_for(name, why="zone_pin")
        log("CNZ  %-38s 该 zone 已被 pin → domestic 内不兜底 B" % (name or "")[:38])
    return None, None, bget




# ================= 2026-10-10 Patch34-B（Codex 方案 2′）：CN 路径"否定存在否决" =================
# 背景：guard 的"CN 名先走 B"分支（P18）**绕过 R8**，唯一防线是 R1 注入特征；Stage A 已证 B 的 6 家
# 国内 DoT **全部伪造**（~92%）⇒ 未命中特征的注入地址会直达客户端 ✗（P0）。
# 本机制只认"**存在性矛盾**"这一条（geo 无关的强信号），其余差异一律只计数 ✓。
# P34-AJ: default is now **enforce** (fail-closed). The protection used to live only in a
# drop-in file; if that file were lost or shadowed, the guard would silently fall back to
# fail-open "off" with no signal. Explicit opt-out is still possible via env.
CN_EXIST_MODE = (os.environ.get("GUARD_CN_EXIST_MODE", "enforce") or "enforce").strip().lower()

# P34-AW（方案任务3）：发布身份 —— 供两进程自证"读的是同一份不可变发布" ✓。
try:
    # P34-BJ：用 **realpath** 解析软链 ✓ —— 生产经 `/opt/dnsguard/current` 启动时，
    # abspath 不会解软链 ⇒ release_id 会显示成 'current' ✗（内容其实已由 sha256 自证 ✓）。
    _REL_DIR_SELF = os.path.dirname(os.path.realpath(__file__))
    _RELEASE_ID = os.path.basename(_REL_DIR_SELF) or "unknown"
    import hashlib as _hashlib
    _h = _hashlib.sha256()
    with open(os.path.abspath(__file__), "rb") as _f:
        for _chunk in iter(lambda: _f.read(65536), b""):
            _h.update(_chunk)
    _GUARD_SHA256 = _h.hexdigest()
except Exception as _e_relid:
    _RELEASE_ID = "unknown"
    _GUARD_SHA256 = "unavailable:%s" % _e_relid
if CN_EXIST_MODE not in ("off", "observe", "enforce"):
    CN_EXIST_MODE = "off"
CN_VETO_BUDGET = float(os.environ.get("GUARD_CN_VETO_BUDGET", "0.9"))
# 2026-10-10 P34-I：W2（第二家运营方）较慢（实测 Mullvad ~0.85s），给它单独、略宽的预算 ✓；
# 但它**只在 W1 没给出该族地址时**才被触发（条件触发 ⇒ 普通 CN 名不再付这笔成本 ✓）。
CN_VETO_W2_BUDGET = float(os.environ.get("GUARD_CN_VETO_W2_BUDGET", "1.1"))
# 2026-10-10 P34-O：裁决调试日志开关（CNVD），**默认关** ✓（排查时置 1 并重启即可 ✓）
CN_VETO_DEBUG = _flag("GUARD_CN_VETO_DEBUG", False)
CN_VETO_MAX_PER_MIN = int(os.environ.get("GUARD_CN_VETO_MAX_PER_MIN", "60"))
CN_ZONE_PIN_TTL = float(os.environ.get("GUARD_CN_ZONE_PIN_TTL", "21600"))
CN_VETO_ACTION = (os.environ.get("GUARD_CN_VETO_ACTION", "servfail") or "servfail").strip().lower()
CN_VETO_TTL_CAP = float(os.environ.get("GUARD_CN_VETO_TTL_CAP", "300"))
CN_ZONE_FILE = os.path.join(STATE_DIR, "cn_deny_zones.json")
# 2026-10-10 P34-E：**正向"清洁结论"缓存** —— Codex 只给了负向 zone pin；但绝大多数 CN 名是干净的，
# 若每次都打见证，干净名会**每次**付 ~0.9s ✗。这里给"已验证干净"的 zone 一个短期通行证 ✓，
# 它**只减少见证次数**，不改变任何判定（负向 pin / 否决逻辑完全不受影响 ✓）。
# ⚠ 安全权衡（我自己复核后收紧 ✗→✓）：**必须按"名字"缓存且 TTL 要短** ——
# 若按 zone 缓存 1h，则该 zone 内某个名字在被缓存期间若被 B 侧投毒，veto 会被跳过最长 1h ✗，
# 而 CN 名的 R8 门控只对"被 pin 的 zone"生效 ⇒ 这条路会真的失去核对 ✗。
# 因此：**name -> until**，默认 300s ✓（热重复名仍受益；曝光窗口受控 ✓）。
CN_CLEAN_TTL = float(os.environ.get("GUARD_CN_CLEAN_TTL", "300"))
_CN_CLEAN = {}                     # **name** -> until（仅内存 ✓）
_witness_addr = os.environ.get("GUARD_CN_VETO_WITNESS", "127.0.0.1:5353")   # W1 = unbound A（P1 后加密+验签）
_CN_ZONES = {}                     # zone(str) -> {"until": float, "reason": str}
_cn_zone_lock = threading.Lock()
_cn_veto_win = [0.0, 0]
_CN_MULTI = ("com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "co.jp", "co.kr", "com.hk",
             "com.tw", "co.uk", "com.au", "com.sg", "com.my", "com.br")


def _veto_zone(name):
    """取可注册域（够用的粗粒度）：末两段；已知多段后缀取末三段 ✓。"""
    p = (name or "").lower().rstrip(".").split(".")
    if len(p) <= 2:
        return ".".join(p)
    if ".".join(p[-2:]) in _CN_MULTI and len(p) >= 3:
        return ".".join(p[-3:])
    return ".".join(p[-2:])


def _cn_zone_load():
    """载入 zone pin（**损坏保留旧值** ✓；零网络 ✓）。"""
    global _CN_ZONES
    try:
        with open(CN_ZONE_FILE, encoding="utf-8") as f:
            d = json.load(f)
        z = d.get("zones") or {}
        now = time.time()
        out = {}
        for k, v in z.items():
            u = float((v or {}).get("until") or 0)
            if u > now:
                out[k] = {"until": u, "reason": (v or {}).get("reason") or ""}
        with _cn_zone_lock:
            _CN_ZONES = out
        with _lock:
            _stats["cn_zone_deny_set"] = len(out)
        log("CNVZ zone pin 已载入: %d 个（TTL %.0fs）" % (len(out), CN_ZONE_PIN_TTL))
    except Exception:
        pass                      # 损坏/缺失 ⇒ 保留旧值 ✓


def _cn_zone_denied(name):
    """该名字所属 zone 是否被 pin（命中 ⇒ 不走 B ✓）。"""
    if not _CN_ZONES or not name:
        return False
    z = _veto_zone(name)
    with _cn_zone_lock:
        e = _CN_ZONES.get(z)
    if not e:
        return False
    if e["until"] <= time.time():
        with _lock:
            _stats["cn_zone_deny_expired"] = _stats.get("cn_zone_deny_expired", 0) + 1
        return False
    return True


def _cn_zone_deny_add(name, reason):
    """把"该 zone 在 B 侧不诚实"写入 pin（原子替换 ✓）。"""
    z = _veto_zone(name)
    if not z:
        return
    until = time.time() + CN_ZONE_PIN_TTL
    with _cn_zone_lock:
        _CN_ZONES[z] = {"until": until, "reason": reason}
        snap = dict(_CN_ZONES)
    try:
        tmp = CN_ZONE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                       "note": "B 侧对不存在名字给出地址（CN 路径否定存在否决）；命中 zone 不再走 B ✓",
                       "zones": snap}, f, ensure_ascii=False, indent=1, sort_keys=True)
        os.replace(tmp, CN_ZONE_FILE)
    except Exception:
        pass
    with _lock:
        _stats["cn_zone_deny_set"] = len(snap)


def _cn_clean_rec(name):
    """返回清洁记录 dict 或 None ✓（P34-AT：记录 `(qtype, 来源, 验证状态, TTL, policy_version)` ✓）。

    兼容旧的"只存 until 的 float"形态 ✓（升级时进程内可能同时存在两种 ✓）。
    """
    if not _CN_CLEAN or not name:
        return None
    z = name.lower().rstrip(".")
    with _cn_zone_lock:
        u = _CN_CLEAN.get(z)
    if not u:
        return None
    if isinstance(u, dict):
        rec = u
        until = float(u.get("until") or 0)
    else:
        rec = {"until": float(u)}
        until = float(u)
    if until <= time.time():
        with _cn_zone_lock:
            _CN_CLEAN.pop(z, None)
        with _lock:
            _stats["cn_clean_expired"] = _stats.get("cn_clean_expired", 0) + 1
        return None
    return rec


def _cn_clean_get(name):
    """该名字所属 zone 是否已被判"清洁"（命中 ⇒ 短期内不再打见证 ✓）。**仍返回布尔** ✓（调用者语义不变 ✓）。"""
    return _cn_clean_rec(name) is not None


def _cn_clean_set(name, qtype=1, source="witness", verdict="existence-only", ttl=None):
    """把该 zone 记为"清洁"。

    P34-AT（方案任务2）：记录**五元组** `(qtype, source, verdict, TTL, policy_version)` ✓，
    以便审计"这条清洁标记到底凭什么下的" ✓。
    方案原话：**"只有存在性见证的标记不能授权采用 B 正地址"** ✓ —— 该规则在策略模式下是**结构性成立**的
    （B 永不参与裁决 ✓），此处把 `verdict` 记下来并新增计数，使该规则**可观测** ✓。
    """
    z = name.lower().rstrip(".") if name else ""
    if not z:
        return
    _t = CN_CLEAN_TTL if ttl is None else float(ttl)
    with _cn_zone_lock:
        _CN_CLEAN[z] = {"until": time.time() + _t, "qtype": int(qtype or 1),
                        "source": str(source), "verdict": str(verdict),
                        "ttl": _t, "policy_version": str(globals().get("_POLICY_VERSION", "n/a"))}
    with _lock:
        _stats["cn_clean_set"] = _stats.get("cn_clean_set", 0) + 1
        _k = "cn_clean_set_" + str(verdict)
        _stats[_k] = _stats.get(_k, 0) + 1


def _veto_allowed():
    now = time.time()
    with _cn_zone_lock:
        if now - _cn_veto_win[0] >= 60.0:
            _cn_veto_win[0] = now
            _cn_veto_win[1] = 0
        if _cn_veto_win[1] >= CN_VETO_MAX_PER_MIN:
            with _lock:
                _stats["cn_veto_ratelimited"] = _stats.get("cn_veto_ratelimited", 0) + 1
            return False
        _cn_veto_win[1] += 1
        return True


# ================= 快速透传（fast-pass）：上游明确 SERVFAIL 时不再空等 alt =================
# 背景（2026-10-20 现场取证）：
#   local-a 返回 rc=2 被 classify_response() 归为 Verdict.TRANSPORT（无 DNSSEC EDE）⇒
#   走 alt 救援（`_finalize_return` 的 `_dl_rem(3.0)`，单次上限 ALT_SOCKET_TIMEOUT_CAP=2.0s）。
#   而 ALT 通道（unbound-alt，两家欧洲 DoT）实测对正常域名 p50=816ms、12 个里 3 个直接超时
#   ⇒ 真 SERVFAIL 域名（如 CNAME 死链 ap-update-cdn-cloudflare-a2.haiteluo.com）每次白等
#   2000ms，客户端拿到 SERVFAIL 要 2006ms，而 unbound 990ms 就已给出结论。
#
# 本机制：local-a 给出 transport 失败时，先向一个**快速独立源**发一次带 DO 的 UDP 查询。
#   · 快速源也明确回 rc=2  ⇒ **两家独立运营方都拒绝** ⇒ 立即透传 SERVFAIL（不等 alt）；
#   · 其它任何结果（有答案 / 超时 / 无应答）⇒ **原样退回原逻辑**，行为与本机制不存在时一致。
# 为什么安全：
#   · 只透传 SERVFAIL —— 不输出任何答案字节，不引入 fail-open 风险；
#   · 快速源必须**明确给出 rc=2 的完整报文**才算数（超时不算），避免把网络问题当结论；
#   · 默认关闭（GUARD_FASTPASS 未设置 ⇒ 完全不走本分支）。
FASTPASS = _flag("GUARD_FASTPASS", False)
FASTPASS_ADDR = os.environ.get("GUARD_FASTPASS_ADDR", "127.0.0.1:5535")
FASTPASS_TIMEOUT = float(os.environ.get("GUARD_FASTPASS_TIMEOUT", "0.8"))
# P0（2026-10-22）：alt 救援的**独立硬上限**（默认 1.2s，与 FASTPASS_TIMEOUT 同量级）。
# 现场依据：alt 通道（unbound-alt，两家欧洲 DoT）对死链域名实测**永不返回**
#   （dig @5357 超时 12s 无应答），而调用处只钳在 `_dl_rem(3.0)` ⇒ 每个死链域名
#   白等 2.0s（ALT_SOCKET_TIMEOUT_CAP）甚至 3.0s。alt 能救回的场景实测是「有答案、
#   p50≈816ms」，所以 1.2s 足以覆盖真能救的那部分；超时即放弃，把预算还给客户端。
# 开关 `GUARD_ALT_HARD_CAP`（默认 1.2，设 0 表示不启用 ⇒ 回到旧行为）✓
ALT_HARD_CAP = float(os.environ.get("GUARD_ALT_HARD_CAP", "1.2"))


def _fastpass_servfail(name, qtype):
    """向快速源问一次；**仅**当它明确回 rc=2 时返回 True（其余一律 False）。

    超时 / 无应答 / 任何非 2 的 rcode ⇒ False（⇒ 调用方退回原 alt 逻辑）✓。
    每一毫秒都算在请求内，所以这里不做任何重试 ✓。
    """
    if not FASTPASS:
        return False
    try:
        _ip, _pt = FASTPASS_ADDR.rsplit(":", 1)
        _msg = mk_query_do(name, qtype)
        _t0 = time.monotonic()
        _data = udp_query((_ip, int(_pt)), _msg, FASTPASS_TIMEOUT)
        _ms = (time.monotonic() - _t0) * 1000.0
        if _data is None:
            with _lock:
                _stats["fastpass_timeout"] = _stats.get("fastpass_timeout", 0) + 1
            _tr_note("fastpass", _ms, "timeout")
            return False
        _rc = _data[3] & 0xF
        with _lock:
            _stats["fastpass_called"] = _stats.get("fastpass_called", 0) + 1
            if _rc == 2:
                _stats["fastpass_servfail"] = _stats.get("fastpass_servfail", 0) + 1
            else:
                _stats["fastpass_other"] = _stats.get("fastpass_other", 0) + 1
        _tr_note("fastpass", _ms, "rc%d" % _rc)
        return _rc == 2
    except Exception:
        with _lock:
            _stats["fastpass_error"] = _stats.get("fastpass_error", 0) + 1
        return False


def _veto_udp(name, qtype, addr, timeout):
    """W1：向 unbound A 发**带 DO** 的 UDP 查询（只当见证 ✓）。

    ★ 方案 §3 第 69 行（**本函数就是被点名者** ✗）：见证工作必须**一次返回原始 wire、
    解析结果、真实来源与验证状态** ✓ —— 旧实现只回 `(rcode, ips, proof)` 三元组、
    **把 `data` 丢掉** ✗，逼得 `_policy_cn_answer()` 再对着同一个见证源**重取一次原始字节** ✗
    （现场后果：同一次 CN 冷查询打两遍见证 ⇒ 多一跳 RTT + 多一份超时风险 ✗）。

    返回 dict（或 None）✓：
      `{"rc": int, "ips": [...], "proof": <denial_proof>, "wire": <原始应答 bytes>,
        "src": "witness", "addr": <见证源地址字符串>, "qtype": qtype, "ok": bool,
        "err": None|str}`
    ⇒ 调用方拿到 `wire` 就能直接分类 ✓，**不再二次取数** ✓。

    ★ 兼容性：返回类型从 tuple 变 dict ⇒ 所有调用点必须同步改 ✗；
    为了"旧调用点也能活"，dict 额外支持按旧三元组的**索引**读取（`d[0]/d[1]/d[2]`）
    ⇒ 万一有未改到的调用点，行为仍与旧版一致 ✓（不会静默返回 None ✗）。
    """
    _res = {"rc": None, "ips": [], "proof": None, "wire": None, "src": "witness",
            "addr": addr, "qtype": qtype, "ok": False, "err": None}
    try:
        ip, port = addr.rsplit(":", 1)
        msg = mk_query_do(name, qtype)
        data = udp_query((ip, int(port)), msg, timeout)
        if data is None:
            raise IOError("no matching witness response")
        rc, ips, _cn, _ttl = parse_a(data)      # guard 自带解析器（无 parse_msg）
        pr = denial_proof(data, qtype)   # ★ N2：否定判定必须按本次 qtype
        _res.update({"rc": rc, "ips": ips, "proof": pr, "wire": data, "ok": True})
    except Exception as _e:
        _res["err"] = str(_e)[:60]
    return _VetoHint(_res)


class _VetoHint(dict):
    """`_veto_udp()` 的返回载体 ✓：既是 dict（新接口 ✓），又支持旧三元组下标 ✓。

    `d[0] -> rc`、`d[1] -> ips`、`d[2] -> proof` ⇒ 未改到的调用点不会静默拿到 None ✗；
    `bool(hint)` 为 True 当且仅当**真的拿到了应答** ✓（旧 `if hint:` 语义保持 ✓）。
    """
    __slots__ = ()

    def __getitem__(self, k):
        if k == 0:
            return self.get("rc")
        if k == 1:
            return self.get("ips")
        if k == 2:
            return self.get("proof")
        return dict.__getitem__(self, k)

    def __bool__(self):
        return bool(self.get("wire"))

    __nonzero__ = __bool__


class _WitnessDone(object):
    """Completed witness handoff; waiting on it must be a no-op."""
    def join(self, *_args):
        return None

    def is_alive(self):
        return False


def _witness_box(hint):
    """Normalize completed and legacy W1 handoffs without duplicate lookup."""
    if isinstance(hint, _VetoHint):
        return {"v": hint}, _WitnessDone()
    if isinstance(hint, dict) and "v" in hint:
        return hint, hint.get("t") or _WitnessDone()
    return {"v": None}, _WitnessDone()


def _veto_w2_targets():
    """W2 目标：`_clean_channels()` 里 **非 NextDNS** 且 RTT 最小者（✗ 不用 CN_DOT，与 B 同源）。

    2026-10-10 修正：`_clean_channels()` 返回的是 **dict 列表**
    （`{'label','ip','port','sni'}` ✗ 不是元组）—— 之前按元组取 `item[0]` 会 KeyError 并被吞掉，
    导致 **W2 永远为 None** ✗（"两家不同运营方"规则结构上永不满足 ✗）。
    这里同时把非 `dot:` 前缀的通道（`doq`/`doq2`/`doq3`/`dnscrypt`）排除掉 ✓。
    """
    try:
        ch = _clean_channels() or []
    except Exception:
        return None
    # 2026-10-19 P2：解析 W1 端点，用于「同端点排除」。
    # 原规则是「W2 只认 dot: 前缀」，隐含前提是 W1 = aghdq→NextDNS（本机 doq 中继），
    # 所以必须排除本机全部 doq 才能保证「不同运营方」。今天 W1 已换成 aghcf→Cloudflare
    # ⇒ 正确判据应是「与 W1 同一端点」，不是「前缀是否 dot:」。
    _w1_ep = None
    try:
        _hp = str(_witness_addr or "").rsplit(":", 1)
        if len(_hp) == 2 and _hp[1].strip().isdigit():
            _w1_ep = (_hp[0].strip(), int(_hp[1]))
    except Exception:
        _w1_ep = None

    def _same_ep(a_ip, a_port):
        """判候选通道与 W1 是否同一端点（localhost 写法归一化）。"""
        if not _w1_ep:
            return False
        try:
            if int(a_port) != int(_w1_ep[1]):
                return False
        except Exception:
            return False
        _a = str(a_ip)
        _w = _w1_ep[0]
        _lo = ("127.0.0.1", "::1", "localhost", "0.0.0.0", "")
        return _a == _w or (_a in _lo and _w in _lo)

    best = None
    for it in ch:
        try:
            if isinstance(it, dict):
                lab = str(it.get("label") or "")
                rtt = it.get("rtt_ms")
                ip, port, sni = it.get("ip"), it.get("port"), it.get("sni")
            else:
                lab = str(it[2] if len(it) > 2 else "")
                rtt = it[0]
                ip, port, sni = it[1][0], it[1][1], (it[1][2] if len(it[1]) > 2 else None)
        except Exception:
            continue
        if not ip or not port:
            continue
        low = lab.lower()
        # 2026-10-10 P34-L（CNVD 实测定位）：W2 **只接受 `dot:` 前缀**的通道 ✓
        #   ✗ 排除 doq/doq2/doq3/nextdns（= 本机中继 ⇒ 与 W1 同源）
        #   ✗ 排除 `dnscrypt`（= FAST_UDP，dnscrypt-proxy 的 CN 规则**会转发给 unbound B** ⇒
        #      与"被质疑方"同源，且实测对它 TIMEOUT ✗ —— 这正是 veto 一直不触发的真因 ✓）
        #   ✔ 只留 `dot:<operator>`（境外认证 DoT，RTT 未知时也能被选到 ✓）
        # 2026-10-19 P2（本次修订）：原判据 `if not low.startswith("dot:")` 的前提已失效 ——
        # 它当年成立是因为 W1 = aghdq→NextDNS（本机 doq 中继），要排除本机全部 doq
        # 才能保证「两家不同运营方」。现在 W1 = aghcf→Cloudflare(doq3) ⇒ 该前缀判据
        # 反而把 W2 钉死在两家欧洲 DoT 上（实测 censurfridns 971ms / digitale 1056ms，
        # 而预算 CN_VETO_W2_BUDGET=1.1s ⇒ W2 有效率仅 27%，见 cn_veto_w2_started/used）。
        # 新判据（仍保证「不同源」）：
        #   ① ✗ 排除 dnscrypt —— 其 CN 转发规则指向 unbound B ⇒ 与被质疑方同源（原注释仍成立）
        #   ② ✗ 排除与 W1 **同一端点**的通道 —— 自我见证没有意义
        #   ③ ✓ 其余（doq/doq2/doq3/dot:<operator>）一律可作 W2，按 rtt 取最小
        if low.startswith("dnscrypt"):
            continue
        if _same_ep(ip, port):
            continue
        if "nextdns" in low:
            continue
        # 2026-10-26：`_clean_channels()` 返回的 dict **没有 rtt_ms 字段** ✗ ——
        # 上面 `rtt = it.get("rtt_ms")` 恒为 None ⇒ 全部兜底 9999.0 ⇒ 候选**全部打平**，
        # `best` 永远等于列表第一个（实测恒为 "doq"）⇒ "按 rtt 取最小"形同虚设 ✗。
        # 真值在 `_ch_stat[label]`（keepalive() 每 KEEPALIVE_S 实测写入：
        # {"rtt_ms": rtt if ok else None, "ok": ok, "ts", "err"}）⇒ 按同一把 _lock 读取。
        # 排序口径（优 → 劣）：
        #   ① 保活实测通过的通道 —— 用真实 rtt_ms；
        #   ② 从未测过的通道 —— 9999.0（**不排除**：首用时它可能反而是通的 ✓）；
        #   ③ 保活**明确失败**的通道 —— 1e6。此刻它多半已被 _channel_usable 熔断短路，
        #      但熔断 60s 后会半开 ⇒ 仍**不排除**，只是排在最后 ✓。
        if not isinstance(rtt, (int, float)):
            _cs = {}
            try:
                with _lock:
                    _cs = dict(_ch_stat.get(lab) or {})
            except Exception:
                _cs = {}
            _r = _cs.get("rtt_ms")
            if isinstance(_r, (int, float)) and _r > 0:
                rtt = float(_r)
            elif _cs.get("ok") is False:
                rtt = 1e6
            else:
                rtt = 9999.0
        if best is None or rtt < best[0]:
            best = (rtt, (ip, port, sni), lab or "dot")
    if not best:
        return None
    return [best[1]], best[2]


def cn_exist_veto(name, qtype, bresp, bips, deadline, w1_hint=None, deny_probe=False):
    """返回 **替换用的响应**（SERVFAIL / 否定答案）或 None（不否决 ⇒ 维持原答案 ✓）。

    `w1_hint`：调用方在**打 B 的同时**并发预发的 A 见证结果盒（可选 ✓）。
    有了它，W1 基本无需再等 ⇒ 首次 CN 查询的额外延迟从 ~0.8s 降到接近 0 ✓。

    只对**真否定应答** fail-closed；超时/过载/无证据 ⇒ 一律 None ✓。

    `deny_probe=True`（★ 2026-10-11 §6 新增，**默认 False ⇒ 既有调用方行为逐字节不变** ✓）：
    只回答"见证是否**否认**该名字存在"，返回 `True`（有否定）/ `False`（见证发过话且无否定）/
    `None`（无任何证据：超时、限流、退避、清洁缓存、pin、`CN_EXIST_MODE=off`）；
    **不产生终局响应、不写 zone pin、不记 fail_closed** ✓ —— 供 §6 的"国内源采纳"当**排除条件** ✓。
    排除比 fail-closed 便宜得多 ⇒ 这里的证据门槛刻意更低（**任一**见证否定即 `True` ✓）。
    """
    # P34-BB（方案 5.2 取用顺序的延伸）✓：**策略模式下 B 永远不会被采纳** ⇒
    # 本函数（W1+W2 见证 + zone pin）在策略模式下**已冗余** ✗ —— 实测 W2 常含 0.4~1.5s ✗，
    # 会让冷 CN 查询串行叠加到撞满 4s 总 deadline（实测 www.51job.com 3929ms ⇒ rc=2 ✗）。
    # 跳过它**不损失安全性** ✓：B 仍被 finalize_answer 结构性拒绝 ✓、A/alt 的准入不受影响 ✓。
    #
    # ★ 2026-10-11 §6（release-16）：`deny_probe=True` 时**不得**被下面的策略跳过拦住 ✓ ——
    #   否则 §6 的"国内源采纳"就失去了唯一的防伪依据 ✗（release-15 首次打开开关后 5 分钟内
    #   canary 即红：`zz-canary-*.googlevideo.com` / `*.tiktokcdn*.com` 在 B 侧得**伪造正答案**
    #   `rc=0 an=1`，而认证见证同名 `rc=3` ⇒ 被当作 ACCEPTED 下发到 AGH ✗ ⇒ `client_exposed=4`）。
    #   注意：**闸门仍只对 `deny_probe` 打开** ✓ —— 既有四个调用方（CN-prefer-B 出口 / 其
    #   fallback / R3 / CNB）走 `deny_probe=False` ⇒ 在策略模式下**照旧跳过** ⇒ 行为逐字节不变 ✓
    #   （也正因如此，本步**不会**给生产新增任何 fail-closed ✗：探测失败只意味着"不采纳国内源"、
    #    回落到切换前的既有链路 ✓）。
    if POLICY_MODE and not deny_probe:
        try:
            _stats["veto_skipped_policy"] = _stats.get("veto_skipped_policy", 0) + 1
        except Exception:
            pass
        return None
    if CN_EXIST_MODE == "off":
        return None                      # 自防御：off ⇒ 绝不改变任何东西 ✓
    t0 = time.time()
    with _lock:
        _stats["cn_veto_checked"] = _stats.get("cn_veto_checked", 0) + 1
    # ---- 前置：清洁缓存 / pin / allow / 退避 / 限流 / 预算 ----
    if _cn_clean_get(name):
        # P34-AT（方案）：**只有存在性见证的清洁标记，不得授权采用 B 的正地址** ✓。
        # 策略模式下 B 结构性永不参与裁决 ✓ ⇒ 此处把"命中但见证只证明存在"计数出来，
        # 使该规则在指标上可审计 ✓（若将来关掉策略模式，这里就是必须拦住的点 ✓）。
        try:
            _r = _cn_clean_rec(name) or {}
            if _r.get("verdict") != "positive-address":
                with _lock:
                    _stats["cn_clean_witnessonly_hit"] = _stats.get("cn_clean_witnessonly_hit", 0) + 1
                if POLICY_MODE:
                    with _lock:
                        _stats["cn_clean_witnessonly_blocked"] = _stats.get("cn_clean_witnessonly_blocked", 0) + 1
        except Exception:
            pass
        with _lock:
            _stats["cn_clean_hit"] = _stats.get("cn_clean_hit", 0) + 1
        # 2026-10-24：deny_probe 路径里 None 的语义是「无证据 ⇒ 否决回退 A/alt」✗。
        # 清洁标记表示「该 zone 已被见证确认存在」✓ ⇒ 必须返 False（可采纳），
        # 否则清洁缓存一旦命中反而把好域名打成 witness_nonev ✗。
        if deny_probe:
            return False
        return None
    if _r8_backoff_active(name, qtype):
        with _lock:
            _stats["cn_veto_backoff_skip"] = _stats.get("cn_veto_backoff_skip", 0) + 1
        return None
    pin = corrob_get(name, qtype)
    if pin is not None:
        with _lock:
            _stats["cn_veto_pin_hit"] = _stats.get("cn_veto_pin_hit", 0) + 1
        return None
    if name in _allow:
        with _lock:
            _stats["cn_veto_allow_skip"] = _stats.get("cn_veto_allow_skip", 0) + 1
        return None
    if not _veto_allowed():
        return None
    remain = deadline - time.time()
    if remain < 0.4:
        with _lock:
            _stats["cn_veto_budget_skip"] = _stats.get("cn_veto_budget_skip", 0) + 1
        return None
    budget = min(CN_VETO_BUDGET, max(0.4, remain - 0.1))

    # ---- W1 + W2 **真并发**（P34-E 原意；2026-10-19 P1 修复实现）----
    # 旧实现的隐患（本次实测定位）：下面 `_t1.join()` 先等 W1 用完 0.9s，
    # 然后才 `_tw.start()` 启动 W2 再等 1.1s ⇒ 两段**串行**叠加最多 2.0s。
    # 现场后果：P99 固定档 2906ms（= 0.9 + 1.1 + 回退 A/alt 约 0.9）。
    # 修正：W2 目标由 `_veto_w2_targets()` 独立选出、**不依赖 W1 结果** ⇒ 可与 W1 同时起跑，
    # 各自保留原预算（0.9s / 1.1s）但共享同一起点 t0 ⇒ 总耗时封顶 max(0.9,1.1)=1.1s。
    # 安全性不变：W1 超时仍早退（无证据不否决）；W1 有地址/强否定时 W2 结果**丢弃不采用**（原语义）。
    _w1b, _t1 = _witness_box(w1_hint)

    # 预先启动 W2（不等 W1）—— 目标选择不依赖 W1，因此可以提前跑。
    # 代价：W1 很快给出地址时，这一轮 W2 属于白跑（不阻塞、不影响延迟，但增加境外核验源调用量）。
    _wt_pre = _veto_w2_targets()
    _r2box = {"st": CORROB_TIMEOUT, "r": None}
    _tw = None
    if _wt_pre and _wt_pre[0]:
        def _w2_work():
            try:
                _r2box["st"], _r2box["r"] = _corrob_query_once(
                    mk_query_do(name, qtype), name, qtype, _wt_pre[0], CN_VETO_W2_BUDGET, pool="veto")
            except Exception:
                _r2box["st"], _r2box["r"] = CORROB_ERROR, None

        _tw = threading.Thread(target=_w2_work)
        _tw.daemon = True
        _tw.start()
        with _lock:
            _stats["cn_veto_w2_started"] = _stats.get("cn_veto_w2_started", 0) + 1

    # P34-G fix: the pre-send result is filled ASYNCHRONOUSLY, so we must WAIT for that thread
    # instead of re-issuing a fresh W1 just because the box looks empty right now (that would
    # duplicate the query and pay a second full budget ~0.9s).
    _w1_completed = isinstance(w1_hint, _VetoHint)
    if _w1b.get("v") is None and not _w1_completed:
        def _w1_work():
            _w1b["v"] = _veto_udp(name, qtype, _witness_addr, budget)

        _t1 = threading.Thread(target=_w1_work)
        _t1.daemon = True
        _t1.start()
    rc2 = ips2 = proof2 = None
    op2 = None
    # ---- 结算 W1（并发预发的结果；等到总预算为止 ✓）----
    _t1.join(max(0.15, (t0 + budget) - time.time()))
    _w1v = _w1b.get("v")
    # §3 第 69 行：`_veto_udp()` 现在返回 **dict**（含原始 wire ✓）而非三元组 ✗ ⇒
    # 判空必须按"是否有 wire"而不是 `is None` ✓（否则"超时的空盒"会被当成有结果 ✗）。
    if _t1.is_alive() or not _w1v:
        with _lock:
            _stats["cn_veto_timeout"] = _stats.get("cn_veto_timeout", 0) + 1
            _stats["cn_veto_noevidence"] = _stats.get("cn_veto_noevidence", 0) + 1
        return None
    if isinstance(_w1v, dict):
        rc1, ips1, proof1 = _w1v.get("rc"), (_w1v.get("ips") or ()), _w1v.get("proof")
    else:
        rc1, ips1, proof1 = _w1v[0], _w1v[1], _w1v[2]

    def _denial(rc, ips, pr):
        """判"否定存在"：返回 'strong' / 'weak' / None。**rc=2/5 与无回应一律 None** ✓。"""
        if rc is None:
            return None
        if rc == 3:
            return "strong" if pr else "weak"
        if rc == 0 and not ips:
            return "strong" if pr else None          # 无证明的 NODATA ⇒ 不否决 ✓（可能是 CNAME 链/CNAME 未展开）
        return None                                   # rc=2(SERVFAIL)/5(REFUSED)/有地址 ⇒ 不是否定 ✓

    # ---- 条件触发（P34-I）：只在"**需要第二家**"时才问 W2 ✓ ----
    #   · W1 已给出该族地址 ⇒ 名字存在、不存在存在性矛盾 ⇒ 跳过 W2 ✓
    #   · W1 是**强否定**（带 DNSSEC 证明）⇒ 按 Codex 规则**单见证即可否决** ⇒ 也跳过 W2 ✓
    _w1_has_addr = bool(ips1) and ((qtype == 1 and all(":" not in x for x in ips1))
                                   or (qtype == 28 and all(":" in x for x in ips1)))
    _w1_strong = (not _w1_has_addr) and bool(proof1) and (rc1 in (0, 3))
    # A1（2026-10-20）：deny_probe 的结论是 `_dn = (d1 is not None) or (d2 is not None)` ——
    # d1 一旦非 None，d2 就完全不参与返回值，却仍要 `_tw.join` 等满 CN_VETO_W2_BUDGET(1.1s)。
    # 实测（cold-cn 20 个不存在域名）：p50 1191ms，其中约 1.0s 是这段纯等待。
    # 这里提前判 d1 ⇒ 直接跳过 W2 等待。**返回值逐字节不变**：d2 本就不影响 _dn；
    # 已启动的 W2 daemon 线程照旧在后台跑完（不阻塞、不改任何缓存/统计语义）。
    _w1_denial = _denial(rc1, ips1, proof1)
    _short_w2 = bool(deny_probe) and (_w1_denial is not None)
    wt = None if (_w1_has_addr or _w1_strong or _short_w2) else _veto_w2_targets()
    if _short_w2:
        with _lock:
            _stats["cn_veto_w2_short"] = _stats.get("cn_veto_w2_short", 0) + 1
    if _w1_has_addr or _w1_strong:
        with _lock:
            _stats["cn_veto_w2_skipped"] = _stats.get("cn_veto_w2_skipped", 0) + 1
    if wt and wt[0]:
        with _lock:
            _stats["cn_veto_w2_used"] = _stats.get("cn_veto_w2_used", 0) + 1
        # 2026-10-19 P1：W2 线程已在上面与 W1 并发启动（_tw），此处只剩**结算**。
        # 截止时刻 = t0 + CN_VETO_W2_BUDGET（与 W1 共享起点），而非从现在再多等 1.1s。
        # 若 W2 没启动（_wt_pre 为空但这里 wt 有值）则退回同步补发，保持原行为。
        if _tw is None:
            def _w2_work():
                try:
                    _r2box["st"], _r2box["r"] = _corrob_query_once(
                        mk_query_do(name, qtype), name, qtype, wt[0], CN_VETO_W2_BUDGET, pool="veto")
                except Exception:
                    _r2box["st"], _r2box["r"] = CORROB_ERROR, None

            _tw = threading.Thread(target=_w2_work)
            _tw.daemon = True
            _tw.start()
        _tw.join(max(0.05, (t0 + CN_VETO_W2_BUDGET) - time.time()))
        if _tw.is_alive():
            # 2026-10-26：**此处不再计数** —— 紧接着 `if r2: ... else:` 的 else 分支必然看到
            # r2=None 且 st2=CORROB_TIMEOUT，会对**同一次**未完成再计一次（实测累计
            # cn_veto_timeout=2186 vs 结算 cn_veto_w2_used=1440 ⇒ 151.8%，超时率被虚报近一倍）。
            # 超时/过载的**唯一**计数点保留在下面的 else 分支（它同时区分 OVERLOAD，
            # 语义更完整 ✓）。判定值 st2 不变，只删重复计数。
            st2, r2 = CORROB_TIMEOUT, None
        else:
            st2, r2 = _r2box["st"], _r2box["r"]
        op2 = wt[1]
        if r2:
            rc2, ips2, _c2, _t2 = parse_a(r2)
            proof2 = denial_proof(r2, qtype)   # ★ N2：同上
        else:
            with _lock:
                if st2 == CORROB_OVERLOAD:
                    _stats["cn_veto_overload"] = _stats.get("cn_veto_overload", 0) + 1
                else:
                    _stats["cn_veto_timeout"] = _stats.get("cn_veto_timeout", 0) + 1

    d1 = _denial(rc1, ips1, proof1)
    d2 = _denial(rc2, ips2, proof2)
    if deny_probe:
        # ★ §6 采纳前探测（**排除式**）：任一见证给出"否定存在"即 `True` ✓。
        #   这里刻意**不**走后面的 clean/pin/fail_closed 分支 ✓（无副作用 ✓、无终局响应 ✓）。
        _dn = (d1 is not None) or (d2 is not None)
        _spoke = (rc1 in (0, 3)) or (rc2 in (0, 3))
        try:
            with _lock:
                if _dn:
                    _stats["cn_dom_witness_deny"] = _stats.get("cn_dom_witness_deny", 0) + 1
                elif _spoke:
                    _stats["cn_dom_witness_ok"] = _stats.get("cn_dom_witness_ok", 0) + 1
                else:
                    _stats["cn_dom_witness_nonev"] = _stats.get("cn_dom_witness_nonev", 0) + 1
        except Exception:
            pass
        # 2026-10-24：只缓存「见证明确确认存在」(_spoke 且无否定) 的结论 ✓ ——
        # 存在性是**域名自身属性**、不随 TTL 变化 ⇒ 300s 内复用不降低抗投毒强度 ✓；
        # 否决(_dn) 与无证据(超时/静默) 一律不写 ✓（保持 P34-AR 原判据不变）。
        if _spoke and not _dn:
            try:
                _cn_clean_set(name, qtype=qtype,
                              source=("w1+w2" if (rc1 is not None and rc2 is not None) else "w1"),
                              verdict="existence-only")
                with _lock:
                    _stats["cn_clean_witness_cached"] = _stats.get("cn_clean_witness_cached", 0) + 1
            except Exception:
                pass
        return True if _dn else (False if _spoke else None)
    # 2026-10-10 P34-K/L：裁决调试留痕 —— P34-O 起改为**默认关闭的开关** ✓
    #   （排查期它一次定位到"W2 被选成 dnscrypt"的真因 ✓；但常态下没必要刷日志 ✗）
    #   需要时：GUARD_CN_VETO_DEBUG=1 并重启 dnsguard ✓
    if CN_VETO_DEBUG and (d1 is not None or d2 is not None or ips2 is not None):
        try:
            log("CNVD %-30s W1(rc=%s ips=%d proof=%s) W2(op=%s st=%s rc=%s ips=%s proof=%s) d1=%s d2=%s"
                % (name[:30], rc1, len(ips1 or []), bool(proof1), op2, locals().get("st2"), rc2,
                   len(ips2 or []), bool(proof2), d1, d2))
        except Exception:
            pass
    if d1 is None and d2 is None:
        # 见证未给出"否定存在" ⇒ 该 zone 判为清洁（短期不再打见证 ✓，只是省成本 ✓）
        # P34-AR（方案任务2）：**去掉 TIMEOUT/无证据写 clean 的行为** ✗ ——
        # 只有在**某个见证确实正向解析出地址**（rc=0 且有该族地址）时才认为"名字存在 ⇒ 清洁" ✓；
        # 见证超时/无应答（rc=None）只能说明"没查到"，不能据此把 zone 记成清洁 ✗。
        _pos = bool((rc1 == 0 and ips1) or (rc2 == 0 and ips2))
        if POLICY_MODE and not _pos:
            with _lock:
                _stats["cn_clean_skipped_noev"] = _stats.get("cn_clean_skipped_noev", 0) + 1
        else:
            # P34-AT：只有"某见证**正向解析出地址**"才算 positive-address ✓；
            # 其余（两家都没给出否定、但也没地址）只能是 existence-only ✓。
            _cn_clean_set(name, qtype=qtype,
                          source=("w1+w2" if (rc1 is not None and rc2 is not None) else "w1"),
                          verdict=("positive-address" if _pos else "existence-only"))
        # 见证有地址（一致/不一致）⇒ 只计数 ✓
        with _lock:
            if ips1 and bips and set(ips1) & set(bips):
                _stats["cn_veto_agree"] = _stats.get("cn_veto_agree", 0) + 1
            else:
                _stats["cn_veto_notdenial"] = _stats.get("cn_veto_notdenial", 0) + 1
        return None
    # 强否定（DNSSEC 证明）⇒ 单见证即可；弱否定 ⇒ 必须**两家不同运营方**都 rc=3 ✓
    strong = (d1 == "strong") or (d2 == "strong")
    if strong:
        with _lock:
            _stats["cn_veto_proof"] = _stats.get("cn_veto_proof", 0) + 1
    else:
        weak_ops = 0
        if d1 == "weak":
            weak_ops += 1                              # W1 = unbound A（出口 operator=nextdns）
        if d2 == "weak":
            weak_ops += 1                              # W2 = 非 nextdns 运营方
        if weak_ops < 2:
            with _lock:
                _stats["cn_veto_weak1"] = _stats.get("cn_veto_weak1", 0) + 1
            # P34-AR（方案任务2）：**弱单否定不得写 clean** ✗ ——
            # 单家弱否定既不能授权否决、也不能把 zone 标成清洁（否则会掩盖后续的真实矛盾 ✗）。
            if POLICY_MODE:
                with _lock:
                    _stats["cn_clean_skipped_weak"] = _stats.get("cn_clean_skipped_weak", 0) + 1
            else:
                _cn_clean_set(name, qtype=qtype, source="w1",
                              verdict="weak-single")   # 证据不足 ⇒ 同样省成本（绝不据此否决 ✓）
            return None
        with _lock:
            _stats["cn_veto_neg3"] = _stats.get("cn_veto_neg3", 0) + 1
            _stats["cn_veto_two_op"] = _stats.get("cn_veto_two_op", 0) + 1
    with _lock:
        _stats["cn_veto_elapsed_ms"] = int(_stats.get("cn_veto_elapsed_ms", 0) + (time.time() - t0) * 1000)
    if CN_EXIST_MODE == "observe":
        with _lock:
            _stats["cn_veto_observe"] = _stats.get("cn_veto_observe", 0) + 1
        log("CNO  %-38s 否定存在否决(observe；见证 rc=%s/%s proof=%s/%s) → 仍按原答案返回"
            % (name, rc1, rc2, bool(proof1), bool(proof2)))
        return None
    # ---- enforce ----
    _ttl = CN_VETO_TTL_CAP
    try:
        _ttl = max(30.0, min(float(parse_a(bresp)[3] or 60), CN_VETO_TTL_CAP))
    except Exception:
        pass
    # no corrob pin here: corrob_put expects a real response; pinning None would feed
    # non-response objects to R8 pin consumers. Backoff below already suppresses re-checks.
    _cn_zone_deny_add(name, "B 对不存在名字给出地址（见证 rc=%s/%s）" % (rc1, rc2))
    _r8_backoff_record(name, qtype)
    with _lock:
        _stats["cn_veto_hit"] = _stats.get("cn_veto_hit", 0) + 1
        _stats["fail_closed"] = _stats.get("fail_closed", 0) + 1
    _fc_classify("cn_exist_veto")
    log("CNV  %-38s 否定存在 veto（我方 B=%s / 见证 rc=%s/%s proof=%s/%s）→ %s + zone pin"
        % (name, _ips_str(bips)[:20], rc1, rc2, bool(proof1), bool(proof2),
           "SERVFAIL" if CN_VETO_ACTION != "nxdomain" else "NXDOMAIN"))
    if CN_VETO_ACTION == "nxdomain":
        try:
            return _veto_nxdomain(bresp)
        except Exception:
            pass
    return mk_servfail(bresp)


def _veto_nxdomain(bresp):
    """下发否定（rcode=3、无答案）—— 语义与 P10 严格路径的"采纳否定"一致 ✓。"""
    d = bytearray(bresp)
    d[3] = (d[2] & 0xF0) | 3
    d[6] = d[7] = 0
    return bytes(d[:12])


def state_reloader():
    """监听状态文件变化，让 CLI / 看板的确认动作在 5 秒内生效"""
    last_s = last_d = last_b = last_x = 0.0
    last_zone = 0.0
    last_asn = 0.0
    while True:
        try:
            m = os.path.getmtime(STATE)
            if m != last_s:
                last_s = m
                load_state()
        except Exception:
            pass
        try:
            m = os.path.getmtime(DIFF_FILE)
            if m != last_d:
                last_d = m
                load_diff()
        except Exception:
            pass
        try:
            # 2026-10-09 范围修正⑤：bad_ips.json 变更（CLI 的 confirm/reject）也需热生效
            m = os.path.getmtime(BAD_IPS_FILE)
            if m != last_b:
                last_b = m
                load_bad_ips()
        except Exception:
            pass
        try:
            # 2026-10-10 Patch34-B：CN zone pin 热载（写入由本进程完成；mtime 变化即重载 ✓）
            _mz = os.path.getmtime(CN_ZONE_FILE)
            if _mz != last_zone:
                last_zone = _mz
                _cn_zone_load()
        except Exception:
            pass
        try:
            # 2026-10-10 Patch27：ASN 快照热载（离线生成，guard 只读；零网络 ✓）
            m = os.path.getmtime(ASN_SNAP_FILE)
            if m != last_asn:
                last_asn = m
                _asn_load()
        except Exception:
            pass
        try:
            # 2026-10-10 Patch9 缺口2：strict_hosts.json 热载（CLI 加/删条目无需重启）
            m = os.path.getmtime(STRICT_FILE)
            if m != last_x:
                last_x = m
                strict_reload_safe()
        except Exception:
            pass
        time.sleep(5)
# ---- fail-closed 原因分类：模块级状态（2026-10-08 12:35 补回）----
# 说明：这 5 个定义曾在"移除影子代码"时被误删（当时以 def _fc_classify 为删除边界，
# 把它之前的变量一并划走），导致 stats_writer 里 dict(_fc_by_reason) 抛 NameError
# 被静默吞掉 ⇒ stats.json 停止写入、fail_closed_by_reason 恒为空。此处补回。
FC_REASONS = ("dnssec_bogus", "r8_neg_cache", "strict_nodata", "r8_miss", "r8_timeout", "r8_overload",
              "budget_exhausted", "unbound_servfail", "known_poison", "admission_overload",
              # 2026-10-10 Patch34-B：CN 路径否定存在否决（P13 对账 sum(by_reason)==fail_closed 依赖此项）
              "cn_exist_veto")
_fc_by_reason = {}
_fc_last_log = {}
_fc_last_count = {}
_fc_lock = threading.Lock()


import threading as _threading

# ===== 2026-10-10 P34-AG: per-source-class accounting =====
# P34-AF: host-side self-tests (canary/chainmon) reach the USER listener (5355) and
# inflate user-facing metrics such as fail_closed (~+6/min). We classify the peer at
# recv time and carry the class to accounting points via threading.local().
# All increments are PLAIN dict updates (no _lock), matching _fc_classify's style
# (it holds its own _fc_lock).
_SRC = _threading.local()
_SRC_MAP = {"172.18.0.2": "client",       # household: via AdGuard Home -> 5355
            "172.18.0.1": "host",         # host-side monitors (canary/chainmon/probe 853 layer)
            "127.0.0.1": "loopback",      # host local self-checks
            "172.18.0.99": "probe"}       # dedicated probe source (if it uses the user port)
# 2026-10-10 §5：来源类别允许由环境注入 ✓ —— 唯一用途是让**完成门夹具**能以
# "业务客户端"身份打进来 ✗→✓（不注入时行为与之前**逐字节相同** ✓）。
# ★ 为什么不能让夹具用 `127.0.0.1` 冒充 client：`_SRC_MAP` 里 `127.0.0.1` 恒为
#   `loopback` ✗、且 `_host_ipv4_set()` 会把本机地址兜底成 `host` ✗ ⇒ 若为此把
#   loopback 改成 client，就会让**主机侧自检污染用户基线** ✗ —— 那正是 §1 刚修掉的病 ✗。
#   所以走"显式注入"这条路：生产不设这个变量 ⇒ 映射表原样 ✓。
for _pair in (os.environ.get("GUARD_SRC_MAP_EXTRA") or "").split(","):
    _pair = _pair.strip()
    if "=" in _pair:
        _k, _v = _pair.split("=", 1)
        if _k.strip() and _v.strip():
            _SRC_MAP[_k.strip()] = _v.strip()


def _host_ipv4_set():
    """枚举**本机**全部 IPv4 地址 ✓ —— 用于把主机侧自检归入 `host`（不污染用户侧基线）✗。

    为什么必须动态算：`eth0` 是 DHCP 的（本机实测是一个 /18 的私网地址），硬编码会随租约失效；
    而主机自检经 `eth0` 打 `docker0` 的 `172.18.0.1:5355` 时，**内核选的源地址是 eth0 的 IP**
    （`ip route get 172.18.0.1` → `local dev lo src 172.18.0.1`，但 UDP 实测源是 eth0）⇒ 必须
    按"是否本机地址"判定，而不是只查 `_SRC_MAP` ✓。

    纯 stdlib（`socket.if_nameindex()` + `SIOCGIFADDR` ioctl），无子进程、无依赖 ✓。
    """
    ips = set()
    try:
        import fcntl
        _SIOCGIFADDR = 0x8915
        for _i, _nm in socket.if_nameindex():
            try:
                _s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    _r = fcntl.ioctl(_s.fileno(), _SIOCGIFADDR,
                                     struct.pack("256s", _nm.encode("utf-8")[:15]))
                    ips.add(socket.inet_ntoa(_r[20:24]))
                finally:
                    _s.close()
            except Exception:
                continue
    except Exception:
        pass
    # 环境变量补充（接口枚举失败或需要额外归类时用）✓
    try:
        for _x in (os.environ.get("GUARD_HOST_IPS") or "").split(","):
            _x = _x.strip()
            if _x:
                ips.add(_x)
    except Exception:
        pass
    return ips


_HOST_IPS = _host_ipv4_set()


def _src_of(addr):
    try:
        ip = addr[0] if isinstance(addr, (tuple, list)) else str(addr)
    except Exception:
        ip = "?"
    # 先查显式映射（`172.18.0.99`→probe 等专用来源优先）✓，再按"是否本机地址"判 host ✓
    cls = _SRC_MAP.get(ip)
    if cls is None:
        cls = "host" if ip in _HOST_IPS else "other"
    return cls, ip


def _src_bump(addr):
    cls, _ip = _src_of(addr)
    try:
        _SRC.v = cls
    except Exception:
        pass
    k = "q_src_" + cls
    _stats[k] = _stats.get(k, 0) + 1
    return cls


def _fc_classify(reason):
    try:
        with _fc_lock:
            _fc_by_reason[reason] = _fc_by_reason.get(reason, 0) + 1
    except Exception:
        pass


def _r8_reason(st):
    """corrob 状态 → 原因标签（overload/timeout 可区分，其余归 r8_miss）。"""
    try:
        if st == CORROB_OVERLOAD:
            return "r8_overload"
        if st == CORROB_TIMEOUT:
            return "r8_timeout"
    except Exception:
        pass
    return "r8_miss"

def handle(msg):
    _t_handle = time.time()
    _dl_begin()          # P34-AS：建立**单调时钟**总 deadline（子阶段只取剩余 ✓）
    if len(msg) < 12:
        return None
    qid = struct.unpack("!H", msg[:2])[0]
    name, qtype = parse_q(msg)
    if not name:
        # 畸形查询（无 question 段）边角：无名字可判 ⇒ 走 `kind=None` 的**终局**出口 ✓
        # （`_finalize_return(..., None, ...)` 只重写 qid ⇒ 与旧 `return r` 逐字节一致 ✓）
        r, _, _ = domestic(msg, name=name)
        if not r:
            return None
        return _finalize_return(r, None, name, qtype, qid, msg)
    # 2026-10-10 Patch10（Codex Stage A）：严格清单**早路径** —— 放在 `_neg_cache` 之前，
    # 不进入明文查询/预算/CN 跳过/stable_fast 等任何分支 ⇒ 结构上不可绕过。
    # 严格名字跳过 `_neg_cache`（那是"我方验证器的否定"，对严格名字不是证据）。
    try:
        _st_ent = _strict_entry(name, qtype)
    except Exception:
        _st_ent = None
    if _st_ent is not None:
        with _lock:
            _stats["q"] += 1
            _stats["strict_hit"] = _stats.get("strict_hit", 0) + 1
        _sr = None
        try:
            _sr = _strict_serve(msg, name, qtype, qid)
        except Exception as _se:
            log("STR  %-38s 严格路径异常: %s" % (name, str(_se)[:70]))
            _sr = None
        if _sr is not None:
            return _finalize_return(_sr, "strict", name, qtype, qid, msg)
        with _lock:
            _stats["strict_servfail"] = _stats.get("strict_servfail", 0) + 1
            _stats["fail_closed"] += 1; _fc_classify("no_consensus")
        return mk_servfail(msg, qid)
    with _lock:
        neg = _neg_cache.get(_c_key(name, qtype))
    if neg and neg[0] > time.time():
        with _lock:
            _stats["neg_cache_hit"] += 1
        _neg_wire = _cache_replay(neg)
        if _neg_wire:
            return _finalize_return(rewrite_id(_neg_wire, qid), "negative-cache", name, qtype, qid, msg)
    if neg:
        with _lock:
            _neg_cache.pop(_c_key(name, qtype), None)
    # ★ A3（2026-10-20）：双源明确 SERVFAIL 的 15s 记忆 ⇒ 死链域名不再每次重走全链路 ✓。
    #   只回 SERVFAIL（不含任何答案字节）⇒ 既不扩大可信源、也不延长任何**答案**寿命 ✓。
    #   位置在 _neg_cache 之后 ⇒ 仍是"拒绝"语义，不放行任何候选 ✓。
    if _sf_get(name, qtype):
        with _lock:
            _stats["q"] += 1
            _stats["fail_closed"] += 1
            try:
                _fc_classify("sf_cache")
            except Exception:
                pass
        return mk_servfail(msg, qid)
    with _lock:
        _stats["q"] += 1
        known = name in _table or any(name.endswith("." + d) for d in _table)
    # R3：已知投毒域名。2026-10-09 问题2修复：按**证据强度**分流
    #   strong：干净优先；干净不可用且是 CN 域名 ⇒ 再走国内加密源 B（双路）；都不可用才 fail-closed
    #   weak  ：干净优先；干净不可用 ⇒ **回落普通路径**（不再 fail-closed —— 弱证据不足以牺牲可用性）
    if known:
        _ent = _poison_entry(name) or {}
        _st = _ent.get("strength") or _strength_of(_ent.get("why", ""))
        # 2026-10-09 P7：**CN + 弱证据 ⇒ 国内路径优先**。弱证据（R2/R5）多为我方瞬时失败或
        # CDN 抖动，不足以把大量国内域名送去境外；干净通道对它们只做异步核验/影子采样。
        # 只有升级为 strong 后才允许"干净优先"；strong + CN 干净不可用时仍 fail-closed（见下）。
        _cn_weak = (_st != "strong" and is_cn_domain(name))
        if _cn_weak:
            with _lock:
                _stats["r3_cn_weak_domestic"] = _stats.get("r3_cn_weak_domestic", 0) + 1
            log("R3D  %-38s CN+弱证据 → 国内路径优先（干净通道仅异步核验）" % name)
        else:
            # prefer_addr：空答案再多等一小会儿，优先挑带地址的干净答案（避免过滤/空回答抢赢真实地址）
            resp = dot_query(msg, name, qtype, prefer_addr=True)
            if resp:
                with _lock:
                    _stats["redirect"] += 1
                    _stats["r3"] += 1
                    _stats["r3_strong_clean" if _st == "strong" else "r3_weak_clean"] += 1
                return _finalize_return(rewrite_id(resp, qid), "clean-channel", name, qtype, qid, msg)
            if _st == "strong":
                if is_cn_domain(name):
                    # 双路第 2 支：国内加密源 B（自行过 suspicious() 判定，可疑则不用）
                    _rb = resolve_cn_via_unbound_b(msg, name, consumer="guard_cn")
                    if _rb:
                        _rc, _bips, _bcn, _btl = parse_a(_rb)
                        if _bips and not suspicious(_bips, name):
                            # 2026-10-10 P34-W（第二轮扫描穷举发现 ✗）：这是**第三条**采用 B 的路径，
                            # 此前只有 `suspicious()`（R1 特征）一道门 ✗ —— 而它恰恰在"该名字已被
                            # **强判可疑**"时才走，采用国内污染源的风险最高 ✗✗。
                            if _cn_zone_denied(name):
                                with _lock:
                                    _stats["cn_zone_deny_hit"] = _stats.get("cn_zone_deny_hit", 0) + 1
                                log("CNZ  %-38s 该 zone 已被 pin → R3B 不采用 B（转 fail-closed）"
                                    % name[:38])
                            else:
                                if (CN_EXIST_MODE != "off"
                                        and not (CN_DOMESTIC_PRIMARY and CN_DOMESTIC_TRUST_B
                                                 and is_cn_trusted(name))):
                                    _v = None
                                    try:
                                        _v = cn_exist_veto(name, qtype, _rb, _bips,
                                                           _dl_wall(max(0.5, CN_VETO_BUDGET)))
                                    except Exception:
                                        _v = None
                                    if _v is not None:
                                        # P1-1：CNV ⇒ **终局结论**（NXDOMAIN 否定 / SERVFAIL）
                                        # ⇒ 不过准入闸门 ✓（过闸会被 alt / 缓存"修复"✗）
                                        return _finalize_return(_v, _LABEL_MAP["CNV"],
                                                                name, qtype, qid, msg)
                                with _lock:
                                    _stats["redirect"] += 1
                                    _stats["r3"] += 1
                                    _stats["r3_cn_dual_b"] += 1
                                if POLICY_MODE:
                                    _pw3 = _policy_cn_answer(name, qtype, None, _rb,
                                                             deadline=_dl_wall(3.0),
                                                             query_id=(msg[:2] if len(msg) >= 2 else None))
                                    if _pw3 is None or not _pw3.wire:
                                        log("POL  %-38s R3B：B 只当见证且无认证答案 ⇒ SERVFAIL" % name[:38])
                                        with _lock:
                                            _stats["fail_closed"] += 1; _fc_classify("known_poison")
                                        return mk_servfail(msg, qid)
                                    # P0-2：**同一出口闸门** ✓（fin_* 记账 + 准入缓存 ✓）
                                    return _finalize_return(rewrite_id(_pw3.wire, qid),
                                                            _LABEL_MAP[_pol_label(_pw3)],
                                                            name, qtype, qid, msg)
                                log("R3B  %-38s 干净不可用 → 采用国内加密源(B) %s"
                                    % (name, ",".join(_bips)[:40]))
                                queue_verify(name, qtype, msg, _bips, _bcn)
                                return _finalize_return(rewrite_id(_rb, qid), "local-b", name, qtype, qid, msg)
                    with _lock:
                        _stats["r3_cn_dual_fail"] += 1
                # P0 fail-closed：强证据且所有可信通道都不可用 ⇒ 绝不回退到污染源
                log("FC   %-38s R3 已知投毒(strong%s)且干净不可用 → SERVFAIL(fail-closed)"
                    % (name, "+国内B" if is_cn_domain(name) else ""))
                with _lock:
                    _stats["fail_closed"] += 1; _fc_classify("known_poison")
                return mk_servfail(msg, qid)
            # weak（非 CN）：干净优先已失败 ⇒ 回落普通路径（继续走 domestic + R8 + suspicious）
            with _lock:
                _stats["r3_weak_fallback"] += 1
            log("R3W  %-38s 弱证据(证据不足)且干净不可用 → 回落普通路径（不 fail-closed）" % name)
    domestic_msg = mk_query_do(name, qtype, qid=qid) if DOMESTIC_DO else msg
    # ★ 方案 §3 第 73 行：**同 question/view/flags/policy 的并发请求必须合并** ✓。
    #   首轮实测缺口（⑤ `A=100/100`）：原实现**只对 CN 名**接入 ✗，且等待者只是
    #   "等锁 + 再探一次准入缓存"✗ —— 而准入缓存要到 `_finalize_return()` 才写入 ✗
    #   ⇒ 等待者醒来时缓存**通常还是空的** ⇒ 照样自己扇出 ✗（等于没合并 ✗）。
    #   现在改为**通用**且**结果贯穿** ✓：
    #   · **所有** name（含非 CN）都过单飞 ✓；键含 qtype/view/flags/policy ✓ ⇒
    #     不同 qtype 绝不共用答案 ✓（方案逐字要求 ✗）；
    #   · 领跑者做完 `domestic()` 后 `slot.publish((uresp, src))` ✓（**成败都发布** ✓，
    #     否则等待者会对"上游确实没答案"这件事再打一轮 ✗）；
    #   · 等待者 `slot.recv()/reuse()` 命中 ⇒ 零外部查询 ✓，并补一个同签名 `bget` ✓；
    #   · 等不到/领跑者也没答案 ⇒ **照旧自己查** ✓（绝不无限等、绝不放空 ✗）。
    _sf_lk = None
    _sf_slot = None
    _sf_owned = False
    _sf_entered = None
    uresp = None
    src = None
    try:
        if name:
            _sf_entered = time.monotonic()
            _sf_lk, _sf_slot, _sf_owned = _sf_enter(name, qtype)
            if not _sf_owned and _sf_slot is not None:
                # 等待者：先看领跑者结果 ✓（快于且准于"再探准入缓存"✓）
                _hit0 = None
                try:
                    _rem = _dl_rem()
                    _w = 2.0 if _rem is None else max(0.0, min(2.0, _rem - 0.6))
                    _hit0 = _sf_slot.recv(_w, _sf_entered)
                except Exception:
                    _hit0 = None
                if _hit0 is not None:
                    uresp, src = _hit0[0], _hit0[1]
                    _tr_flag("cn_sf_join")
                    with _lock:
                        _stats["cn_sf_served"] = _stats.get("cn_sf_served", 0) + 1
    except Exception:
        _sf_lk = None
        _sf_owned = False
    _t_dom = time.monotonic()
    # ★ 2026-10-18 批次 4：与明文递归**并发**发起 R8 核对，把冷查询从
    #   `unbound冷(≈323ms) + 核对冷(≈300ms)` 的 sum 压到 max。
    #   红线②守卫：这里只提前**发起**，不拿答案见 `_r8p_start()` 的注释；
    #   明文放行判定仍在本函数原 R8 位置等核对结论（见 `_r8p_fetch(...)` 调用点）。
    _fut8 = None
    try:
        if uresp is None:
            try:
                _fut8 = _r8p_start(msg, name, qtype)
            except Exception:
                _fut8 = None
            uresp, src, bget = domestic(domestic_msg, name=name, qtype=qtype)
            # 领跑者发布（**成败都发** ✓）⇒ 等待者据此复用/放行 ✓
            if _sf_owned and _sf_slot is not None:
                try:
                    _sf_slot.publish((uresp, src) if uresp is not None else ("__none__", None))
                except Exception:
                    pass
        else:
            # 单飞合并路径：本请求**未做任何外部取数** ✓ ⇒ 补一个同签名的 `bget`
            # （R8/后续段落会调它 ✓；它就是"串行现查 B"那条收口函数 ✓，不引入新路径 ✓）。
            bget = _cn_bget_lazy(domestic_msg, name)
            with _lock:
                _stats["cn_sf_merge"] = _stats.get("cn_sf_merge", 0) + 1
    finally:
        if _sf_owned and _sf_lk is not None:
            try:
                _sf_lk.release()
            except Exception:
                pass
    _tr_note("domestic", (time.monotonic() - _t_dom) * 1000.0, str(src) if src else "fail")
    if uresp is None:
        # P0-1 ①：`domestic()` 无答案 ⇒ `dot_query()` 的 clean-channel 字节**必须过闸** ✓
        # （此前直出 ✗ ⇒ 该路径既无 `fin_*` 记账也不吃准入缓存 ✗）
        r = dot_query(msg, name, qtype)
        if not r:
            return None
        return _finalize_return(rewrite_id(r, qid), "clean-channel", name, qtype, qid, msg)
    rcode, uips, ucn, _mt = parse_a(uresp)
    # 最终 DNSSEC 边界：Unbound A 是唯一可信验证器。
    # AD=1 的已验证正向答案不可被 dnscrypt/DoQ/DoT 辅助源覆盖；
    # Unbound SERVFAIL 也不可被辅助源“修复”，否则会绕过 bogus/验证失败结论。
    _rc_meta, _ad_meta, _ha_meta, _hc_meta, _types_meta, _optout_meta, _an_meta, _qh_meta = parse_meta(uresp, qtype)
    if rcode == 2:
        import alt_adapter
        if not alt_adapter.dnssec_bogus(uresp):
            return _finalize_return(uresp, _src_kind(src), name, qtype, qid, msg)
        with _lock:
            _stats["fail_closed"] += 1; _fc_classify("unbound_servfail")
            _stats["dnssec_bogus"] += 1        # 兼容旧键：语义实为"unbound SERVFAIL"，非验签 bogus
            _stats["fc_unbound_servfail"] += 1  # 2026-10-09 问题3：准确名称
        # ★ 方案 §2 第 51 行：**新观察到 bogus 时立即失效关联缓存** ✓ ——
        # 否则已采纳的旧答案会继续被命中放行，掩盖上游已翻转的事实 ✗。
        # 用 `_drop_caches_for()` 而不是只清准入缓存：本进程的 `_corrob`（R8 钉住窗口，
        # 生产上限 3600s ✗）与 `_neg_cache`（否定结论）同样会把"已被推翻的结论"继续放出去 ✗。
        _drop_caches_for(name, why="bogus")
        log("FC   %-38s Unbound A SERVFAIL → 禁止辅助源覆盖（最终 DNSSEC 边界）" % name)
        return mk_servfail(msg, qid)
    if _ad_meta and uips:
        with _lock:
            _stats["dnssec_validated"] += 1
        # P0-1 ②：AD=1 已验证答案**同门** ✓ —— `classify_response` 判 SECURE ⇒ 原样返回 ✓
        return _finalize_return(uresp, "local-a", name, qtype, qid, msg)
    # 只有 Unbound A 给出 DNSSEC 可验证的否定证明时才进入负缓存。
    # 未签名 NODATA/NXDOMAIN、SERVFAIL 和冲突结果绝不缓存为安全结论。
    proof = denial_proof(uresp)
    if proof and not uips:
        # §2-a：**否定有效期同样取自可信报文** ✓（RFC 2308：min(SOA.TTL, SOA.MINIMUM)）✗→✓
        # 现场问题：这里写死 `max(30, min(_mt or 60, 300))` ✗ ——
        #   · 强制 30s 下限 ✗ ⇒ 把 SOA 明示的 5s 否定延长了 6 倍 ✗；
        #   · `_mt` 取的是 **A/AAAA 记录的 TTL** ✗，而否定答案根本没有地址记录 ⇒
        #     实际恒落进 `else 60` ✗ ⇒ 完全没读 SOA，等于凭空 60s ✗。
        # 另按方案「只有 CNAME、没有 DNSSEC 证明 ⇒ 不算已证明 NODATA」✓：
        # `proven` 为假时**不入负缓存** ✗，只走本次过闸返回（下次查询重新判定 ✓）。
        _neg_ttl, _neg_det = 0.0, {}
        try:
            _neg_ttl, _neg_det = _ALT.rrset_validity(uresp)
        except Exception:
            _neg_ttl, _neg_det = 0.0, {"kind": "exc", "proven": False, "ttl": 0.0}
        if not isinstance(_neg_det, dict):
            _neg_det = {}
        try:
            _nk = "neg_ttl_" + str(_neg_det.get("kind") or "?")
            _stats[_nk] = _stats.get(_nk, 0) + 1
        except Exception:
            pass
        _proven = bool(_neg_det.get("proven"))
        ttl = max(0.0, float(_neg_ttl or 0.0))
        _neg_reason = ""
        if ttl > 0 and _proven:
            expiry = time.time() + min(ttl, 900.0)
        else:
            # 未证明 / 零 TTL ⇒ **不缓存** ✓（读侧因此不会命中它 ✓）
            expiry = 0.0
            _neg_reason = "unproven" if not _proven else "zero_ttl"
            try:
                _stats["neg_cache_skip_" + _neg_reason] = \
                    _stats.get("neg_cache_skip_" + _neg_reason, 0) + 1
            except Exception:
                pass
        try:
            _tr_note("negttl", 0.0, (_neg_reason or str(_neg_det.get("kind") or "ok")))
        except Exception:
            pass
        # P0-1 ③：负缓存的**写侧**同样必须过闸 ✓ —— **先过闸、再落缓存** ✗→✓
        # 此前先落缓存再直出 ✗ ⇒ 未过闸的字节会被 4539 的读侧反复直出 ✗。
        # 语义不变 ✓：`POLICY_MODE` 下 `denial_proof()` 只认 AD=1 ✓ ⇒ `classify_response`
        # 判 SECURE ⇒ 原样返回 ✓（只重写 qid ✓）。
        _out = _finalize_return(uresp, "local-a", name, qtype, qid, msg)
        with _lock:
            if len(_neg_cache) > 20000:
                now = time.time()
                for k in [k for k, v in list(_neg_cache.items()) if v[0] <= now]:
                    _neg_cache.pop(k, None)
            if expiry > 0:
                _neg_cache[_c_key(name, qtype)] = (expiry, uresp, _cache_stamp())
                _stats["neg_cache_store"] += 1
        return _out
    # R1：可疑答案 → 换干净上游
    why = suspicious(uips, name)
    if why:
        resp = dot_query(msg, name, qtype)
        if resp:
            rc2, cips, ccn, _t3 = parse_a(resp)
            if cips:
                with _lock:
                    _stats["redirect"] += 1
                    _stats["r1"] += 1
                mark(name, why, ",".join(uips), ",".join(cips))
                return _finalize_return(rewrite_id(resp, qid), "clean-channel", name, qtype, qid, msg)
        # P0 fail-closed：unbound B 只是"比较源"，不是作答源；已判可疑的答案绝不原样下发
        log("FC   %-38s R1 已判可疑(%s)且干净上游不可用 → SERVFAIL(fail-closed)" % (name, why))
        with _lock:
            _stats["fail_closed"] += 1; _fc_classify("known_poison")
        return mk_servfail(msg, qid)
    # R7：STRICT_RANGES（配角信号）——同步判据不看它，实测 174.132.167.0/24 上
    # www.youtube.com / facebook.com 的裸递归答案 10/10 命中。命中即改用干净上游，
    # 但**不 fail-closed**：该段可能真住着合法站点，证据强度不足以 SERVFAIL。
    shit = range_hit(uips, name, strict=True)
    if shit:
        resp = dot_query(msg, name, qtype)
        if resp:
            _rc7, cips7, _ccn7, _ct7 = parse_a(resp)
            uset = set(_norm_ip(x) for x in uips)
            cset = set(_norm_ip(x) for x in cips7)
            if cips7 and not (uset & cset):
                with _lock:
                    _stats["redirect"] += 1
                    _stats["r7"] += 1
                log("R7   %-38s STRICT 段 %s（%s）→ 改用干净上游（弱证据：不入黑名单，仅交异步取证）"
                    % (name, shit[1], shit[0]))
                queue_verify(name, qtype, msg, uips, ucn)
                return _finalize_return(rewrite_id(resp, qid), "clean-channel", name, qtype, qid, msg)
        with _lock:
            _stats["r7_soft"] += 1
        log("R7S  %-38s STRICT 段命中但无干净答案 → 保留原答案（不 fail-closed）" % name)
    # R2：unbound 给不出地址（被墙黑洞）→ 试干净上游
    if qtype == 1 and not uips:
        # R2-快路：若 unbound 的"给不出地址"带 DNSSEC 否定证明（AD=1 / NSEC 或非 opt-out NSEC3 + RRSIG），
        # 这个"不存在"是密码学证明过的（伪造的 NXDOMAIN 过不了 unbound 的验签，只会变成 SERVFAIL），
        # 就无需再去境外干净上游比对 —— 省掉 0.4~0.9s。NSEC3 opt-out 一律不走快路（见 denial_proof 注释）。
        proof = denial_proof(uresp, qtype)
        if not proof and not dnssec_material(uresp):
            # 上游没带 DO → unbound 不会回证明。本地用 DO=1 复问一次（命中 unbound 缓存，约 10ms）
            # 只为拿判据；返回给客户端的仍是原应答 uresp，与判据来源无关。
            alt = udp_query(UNBOUND, mk_query_do(name, qtype), timeout=DOM_TIMEOUT)
            if alt is not None:
                proof = denial_proof(alt, qtype)
        if proof:
            with _lock:
                _stats["fast_nx"] += 1
                _stats["fast_ad" if proof == "ad" else "fast_nsec"] += 1
            # P34-AV + Task3 P1-1：出口同门 ✓ —— src 由 `_LABEL_MAP` 折算 ✓（POL⇒local-alt ✓；CNV/POL-SF⇒终局结论，不过闸 ✓）
            return _finalize_return(uresp, _src_kind(src), name, qtype, qid, msg)
        if is_cn_domain(name):
            # P0-6：不再直接放过，用加密国内源（unbound B → 360/AliDNS DoT）核对
            # 2026-10-05：判据由 `.cn` TLD 后缀扩展为 CN 域名集合；否则 qq.com/taobao.com
            # 这类 .com 中国域名的 NXDOMAIN 会去境外干净通道比对（实测 +300~560ms）。
            # 注意：只改这一处"核对源选择"；R4/R5/R6 的 foreign 统计与 R8 门控保持不变，
            # 以免缩小 CN 域名的 R8 覆盖（那是降低抗投毒）。
            rb = bget()          # 复用 domestic() 里已并发发出的 B 结果
            if rb is not None:
                rcb, bips, bcn, _ = parse_a(rb)
                if bips:
                    # 2026-10-05 P0-2：与姐妹路径（R2 尾部采用 B 的答案）对齐 —— B 只是
                    # "比较源"不是"作答源"；未过 suspicion 判据就下发等于放大未验证采用面。
                    bwhy = suspicious(bips, name)
                    if bwhy:
                        with _lock:
                            _stats["fail_closed"] += 1; _fc_classify("known_poison")
                            _stats["cn_b_denied"] += 1
                        log("FC   %-38s R2-B 国内源答案可疑(%s) → SERVFAIL(fail-closed)"
                            % (name, bwhy))
                        return mk_servfail(msg, qid)
                    with _lock:
                        _stats["cn_verify_b"] += 1
                    # 2026-10-10 P34-N：与 CN-prefer-B 分支**对齐** —— 这条支路也必须
                    # ① 尊重 zone pin（被 pin 的 zone 一律不再采用 B ✓）
                    # ② 过"否定存在否决"（否则 B 的注入答案会从这里直接下发 ✗)
                    # 这正是 canary v2 抓到的残留客户端泄漏 ✓（日志标记 CNB）。
                    if _cn_zone_denied(name):
                        with _lock:
                            _stats["cn_zone_deny_hit"] = _stats.get("cn_zone_deny_hit", 0) + 1
                            _stats["cn_skip"] += 1
                        log("CNZ  %-38s 该 zone 已被 pin（B 侧不可信）→ 不采用 B，回 A 侧否定答案"
                            % name[:38])
                        # P34-AV + Task3 P1-1：出口同门 ✓ —— src 由 `_LABEL_MAP` 折算 ✓（POL⇒local-alt ✓；CNV/POL-SF⇒终局结论，不过闸 ✓）
                        return _finalize_return(uresp, _src_kind(src), name, qtype, qid, msg)
                    if (CN_EXIST_MODE != "off"
                            and not (CN_DOMESTIC_PRIMARY and CN_DOMESTIC_TRUST_B
                                     and is_cn_trusted(name))):
                        _v = None
                        try:
                            _v = cn_exist_veto(name, qtype, rb, bips,
                                               _dl_wall(max(0.5, CN_VETO_BUDGET)))
                        except Exception:
                            _v = None
                        if _v is not None:
                            # P1-1：CNV ⇒ **终局结论**，不过准入闸门 ✓
                            return _finalize_return(_v, _LABEL_MAP["CNV"], name, qtype, qid, msg)
                    if POLICY_MODE:
                        _pw4 = _policy_cn_answer(name, qtype, uresp, rb,
                                                 deadline=_dl_wall(3.0),
                                                 query_id=(msg[:2] if len(msg) >= 2 else None))
                        if _pw4 is None or not _pw4.wire:
                            log("POL  %-38s CNB：B 只当见证且无认证答案 ⇒ SERVFAIL" % name[:38])
                            with _lock:
                                _stats["fail_closed"] += 1; _fc_classify("known_poison")
                            return mk_servfail(msg, qid)
                        # P0-2：**同一出口闸门** ✓（fin_* 记账 + 准入缓存 ✓）
                        return _finalize_return(rewrite_id(_pw4.wire, qid),
                                                _LABEL_MAP[_pol_label(_pw4)],
                                                name, qtype, qid, msg)
                    log("CNB  %-38s unbound A 无地址 → 采用加密国内源(B)答案 %s"
                        % (name, ",".join(bips)[:40]))
                    queue_verify(name, qtype, msg, bips, bcn)
                    return _finalize_return(rewrite_id(rb, qid), "local-b", name, qtype, qid, msg)
            with _lock:
                _stats["cn_skip"] += 1
            # P34-AV + Task3 P1-1：出口同门 ✓ —— src 由 `_LABEL_MAP` 折算 ✓（POL⇒local-alt ✓；CNV/POL-SF⇒终局结论，不过闸 ✓）
            return _finalize_return(uresp, _src_kind(src), name, qtype, qid, msg)
        # 2026-10-07 二档·第10步：**非 CN 域名不再使用 unbound B**。
        # 旧版在这里并发预发 B，并在"干净上游也没给出地址"时采用 B 的答案（fallback_b）——
        # 那让国内源替境外域名作答，且 B 的队列/高 RTT 会污染同步核对的对照口径。
        # 现在：A 无地址 + 干净侧也无地址 ⇒ 直接返回原应答（见下方 return uresp），语义更干净。
        resp = dot_query(msg, name, qtype)
        if resp:
            rc2, cips, ccn, _t3 = parse_a(resp)
            if cips:
                with _lock:
                    _stats["redirect"] += 1
                    _stats["r2"] += 1
                if any(":" not in x for x in cips):
                    # 2026-10-09 清理修复 A：干净答案若**全是私网/保留地址**，不能作为投毒证据。
                    # 取证：7120.com→10.10.10.11、samsungcloud.tv→10.10.10.10、
                    #       cdn.edge.susercontent.com→10.111.6.40、tk.7086.in→10.255.255.254、
                    #       xfeng.me→192.168.2.200（独立 AliDNS 与干净通道一致）⇒ 权威记录本就是私网，
                    #       unbound A 因 private-address 过滤剥掉 ⇒"我方无地址"是我们自己的过滤所致。
                    if _all_private(cips):
                        with _lock:
                            _stats["r2_private_skipped"] = _stats.get("r2_private_skipped", 0) + 1
                        log("R2P  %-38s 干净答案仅私网地址(%s) → 不作为投毒证据"
                            % (name, ",".join(cips)[:40]))
                    else:
                        mark(name, "R2 unbound 无地址(fail/NXDOMAIN) 而干净上游有", ",".join(uips), ",".join(cips))
                else:
                    with _lock:
                        _stats["geo_skipped"] += 1
                    log("SKIP %-38s 干净上游只有 IPv6 地址，不作为投毒证据" % name)
                return _finalize_return(rewrite_id(resp, qid), "clean-channel", name, qtype, qid, msg)
        # 2026-10-07 二档·第10步：两方一致（A 无地址 + 加密侧也无地址）⇒ 返回原应答是正确的。
        # 旧版此处还有"采用 unbound B 的答案"与"B 可疑则 SERVFAIL"两支，已随"非 CN 去 B"一并移除。
        with _lock:
            _stats["r2_no_b"] += 1
        # P34-AV + Task3 P1-1：出口同门 ✓ —— src 由 `_LABEL_MAP` 折算 ✓（POL⇒local-alt ✓；CNV/POL-SF⇒终局结论，不过闸 ✓）
        return _finalize_return(uresp, _src_kind(src), name, qtype, qid, msg)
    # R4/R5/R6：后台核验（含 DIFF 待确认清单）
    if qtype == 1 and uips:
        flags = [is_cn_ip(i) for i in uips]
        if flags and all(f is True for f in flags):
            foreign = not name.endswith(CN_SUFFIX)
            with _lock:
                _stats["cn_local"] += 1
                if foreign:
                    _stats["cn_foreign"] += 1
            # P0 盲区：纯国内 IP 是"未核验放行"路径。CDN 边缘与注入无法用 is_cn_ip 区分，
            # 故不自动改道（避免误伤 CDN），但非 .cn 域名必须留痕供离线复核。
            # 实例：crl.pki.goog 被注入 180.163.151.162（上海电信段）。
            if foreign and name not in _cn_seen and len(_cn_seen) < 500:
                _cn_seen.add(name)
                log("CNX  %-38s 非 .cn 域名返回纯国内 IP %s（留痕，不自动改道）"
                    % (name, ",".join(uips)[:46]))
        else:
            queue_verify(name, qtype, msg, uips, ucn)
    # ===== 2026-10-05 方案1+2：类型化核对（非 A/AAAA 类型；默认 observe）=====
    # 放在 R8 之前、且只接管 qtype ∉ {1,28}，因此**完全不碰**已验证的 A/AAAA 路径。
    # 之所以这里也要管 CN 名：CN 名的非 A 类型同样零覆盖（qq.com MX/TXT 实测走国内链路）。
    if CORROB_TYPES_MODE and qtype in R8T_MAP and qtype not in (1, 28):
        _is_cn = is_cn_domain(name) or name.endswith(CN_SUFFIX)
        _uvals = _type_vals(uresp, qtype)
        _cvals = _r8t_get(name, qtype)
        _cresp_t = None
        if _cvals is None:
            with _lock:
                _stats["r8t_checked"] += 1
            _st_t, _cresp_t = corrob_query(msg, name, qtype, targets_override=(CN_DOT if _is_cn else None))
            if _cresp_t is None:
                _cvals = set()
                with _lock:
                    _stats["r8t_none"] += 1
            else:
                _cvals = _type_vals(_cresp_t, qtype)
                _r8t_put(name, qtype, _cvals, parse_typed(_cresp_t)[2])
        _extra = _uvals - _cvals
        _want = None
        if not _uvals and _cvals and qtype != 6:
            _want = "empty"
        elif _extra:
            _want = "extra"
        if _want is None:
            with _lock:
                _stats["r8t_agree"] += 1
        else:
            with _lock:
                _stats["r8t_empty" if _want == "empty" else "r8t_extra"] += 1
            # 日志只在"真做了实时核对"或 enforce 模式打，避免持续不匹配把日志刷满
            if _cresp_t is not None or CORROB_TYPES_MODE == "enforce":
                _act = "采用核对答案" if CORROB_TYPES_MODE == "enforce" else "observe 留痕"
                if _want == "empty":
                    log("R8T  %-38s qtype=%d 明文为空但核对通道有 %d 条 → %s"
                        % (name, qtype, len(_cvals), _act))
                else:
                    log("R8T  %-38s qtype=%d 明文含核对集没有的 %d 条（%s）→ %s"
                        % (name, qtype, len(_extra), ",".join(sorted(_extra)[:2])[:46], _act))
            if CORROB_TYPES_MODE == "enforce" and _cvals:
                if _cresp_t is None:
                    _st_t, _cresp_t = corrob_query(msg, name, qtype, targets_override=(CN_DOT if _is_cn else None))
                if _cresp_t is not None:
                    with _lock:
                        _stats["redirect"] += 1
                        _stats["r8t_adopt"] += 1
                    return _finalize_return(rewrite_id(_cresp_t, qid), "clean-channel", name, qtype, qid, msg)
    # R8：同步单路核对 —— 未知特征注入的同步防线（P0-A）
    # 只处理纯 IPv4 答案：is_cn_ip() 对 IPv6 返回 None，无法判断"国内就近解析"，
    # 若对 IPv6 也改道，会把国内服务的 V6 答案换成境外边缘（实测 api.nrd.nie.163.com）。
    _is_v4 = bool(uips) and all(":" not in x for x in uips)
    _is_v6 = bool(uips) and all(":" in x for x in uips)
    if CORROB_ENABLED and qtype not in (1, 28):
        with _lock:
            _stats["qtype_other"] += 1
    if (CORROB_ENABLED and ((qtype == 1 and _is_v4) or (qtype == 28 and _is_v6))
            and (not is_cn_domain(name) or _cn_zone_denied(name))):   # Patch34-B：被 zone pin 摘掉的 CN 名仍需 R8 覆盖 ✓
        uset8 = set(_norm_ip(x) for x in uips)
        pin = corrob_get(name, qtype)
        if pin is not None:
            # 2026-10-10 Patch16：这才是"钉住窗口命中"的**真实**位置（原自增点在 corrob_query
            # 内部、结构上不可达 ✗）。与 r8_pinned（仅"冲突改道"计数）不同，这里统计所有命中。
            with _lock:
                _stats["corrob_cache_hit"] += 1
            presp, pips = pin
            if not (uset8 & set(_norm_ip(x) for x in pips)):
                # 窗口内明文答案与已核对集合不符 → 明文路径不可信，改发已核对答案
                with _lock:
                    _stats["redirect"] += 1
                    _stats["r8_pinned"] += 1
                log("R8P  %-38s 明文答案 %s 不在已核对集合内 → 改发已核对答案"
                    % (name, ",".join(uips)[:36]))
                return _finalize_return(rewrite_id(presp, qid), "clean-channel", name, qtype, qid, msg)
        else:
            flags8 = [is_cn_ip(i) for i in uips]
            stable_key = (name, qtype)
            with _lock:
                last_stable = _r8_stable.get(stable_key, 0.0)
            # 只有已经成功认证过、且本次仍有 DNSSEC 证明的稳定域名才跳过实时 R8。
            # 未签名域名、首次出现域名、可疑地址和冲突域名仍走同步核对。
            stable_fast = (last_stable and time.time() - last_stable < REVERIFY_AFTER
                           and (_ad_meta or dnssec_material(uresp)))
            if stable_fast:
                with _lock:
                    _stats["r8_event_skip"] += 1
                queue_verify(name, qtype, msg, uips, ucn)
                # P34-AV + Task3 P1-1：出口同门 ✓ —— src 由 `_LABEL_MAP` 折算 ✓（POL⇒local-alt ✓；CNV/POL-SF⇒终局结论，不过闸 ✓）
                return _finalize_return(uresp, _src_kind(src), name, qtype, qid, msg)
            # 2026-10-10 Patch14：CN-IP 豁免改为按 `is_cn_domain` 门控。
            #   纯国内答案 + （CN 名单名 或 门控关闭）⇒ 保持原语义豁免；
            #   纯国内答案 + 非名单名（**攻击面**）⇒ 落入下面的 R8 块（observe/enforce）。
            _cnip_exempt = bool(flags8 and all(f is True for f in flags8))
            if _cnip_exempt:
                with _lock:
                    _stats["cnip_candidate"] += 1
                    if is_cn_domain(name):
                        _stats["cnip_in_cnlist"] += 1
                    else:
                        _stats["cnip_outside_cnlist"] += 1
            if _cnip_exempt and (CNIP_MODE == "off" or is_cn_domain(name)):
                pass          # 纯国内答案：CN 就近解析，改走境外源会劣化访问，不核对
            else:
                # Patch14 observe：非名单 CN-IP 在观察档下"照做核对、记冲突率与耗时，但不改道"。
                if _cnip_exempt and not is_cn_domain(name) and CNIP_MODE == "observe":
                    with _lock:
                        _stats["cnip_r8_entered"] += 1
                    _ct0 = time.time()
                    _ost, _oresp = corrob_query(msg, name, qtype,
                                                budget=min(CORROB_DOT_TIMEOUT, QUERY_DEADLINE - (time.time() - _t_handle) - 0.2))
                    _oel = int((time.time() - _ct0) * 1000)
                    with _lock:
                        _stats["cnip_elapsed_ms"] = _oel
                    if _oresp:
                        try:
                            _orc, _oips, _ocn, _ottl = parse_a(_oresp)
                        except Exception:
                            _orc, _oips = None, []
                        _oset = set(_norm_ip(x) for x in (_oips or []))
                        if _oset and _oset & uset8:
                            with _lock:
                                _stats["cnip_r8_agree"] += 1
                        elif _oset or _orc in (0, 3):
                            with _lock:
                                _stats["cnip_r8_conflict"] += 1
                                _stats["cnip_observe_conflict"] += 1
                            log("CIP  %-38s 非名单 CN-IP 与加密源不一致（明 %s / 密 %s）→ 观察档不改道"
                                % (name, ",".join(sorted(x for x in uset8 if isinstance(x, str)))[:26],
                                   ",".join(sorted(x for x in _oset if isinstance(x, str)))[:26]))
                    uresp = _failopen_cap_ttl(uresp)   # 2026-10-28 R-2+: CIP observe-only branch capped too
                    # P34-AV + Task3 P1-1：出口同门 ✓ —— src 由 `_LABEL_MAP` 折算 ✓（POL⇒local-alt ✓；CNV/POL-SF⇒终局结论，不过闸 ✓）
                    return _finalize_return(uresp, _src_kind(src), name, qtype, qid, msg)
                with _lock:
                    _stats["r8_checked"] += 1
                _elapsed8 = time.time() - _t_handle
                _left8 = QUERY_DEADLINE - _elapsed8
                if _elapsed8 > SYNC_BUDGET or _left8 < 0.8:
                    with _lock:
                        _stats["budget_skip"] += 1
                    _tr_flag("budget_skip")   # Step-1 §1：预算门跳过
                    _tr_flag("fail_closed" if CORROB_STRICT_FAIL_CLOSED else "budget_keep")
                    if CORROB_STRICT_FAIL_CLOSED:
                        with _lock:
                            _stats["fail_closed"] += 1; _fc_classify("budget_exhausted")
                        log("FC   %-38s 同步预算已用尽(%.2fs, 余 %.2fs) → SERVFAIL(strict R8)"
                            % (name, _elapsed8, _left8))
                        return mk_servfail(msg, qid)
                    log("BGT  %-38s 同步预算已用尽(%.2fs, 余 %.2fs) → 无证据，保留明文 %s（留痕+异步取证）"
                        % (name, _elapsed8, _left8, ",".join(uips)[:40]))
                    # P34-AV + Task3 P1-1：出口同门 ✓ —— src 由 `_LABEL_MAP` 折算 ✓（POL⇒local-alt ✓；CNV/POL-SF⇒终局结论，不过闸 ✓）
                    uresp = _failopen_cap_ttl(uresp)   # 2026-10-28 R-2: unify TTL cap before _finalize_return writes adm cache
                    return _finalize_return(uresp, _src_kind(src), name, qtype, qid, msg)
                # Patch13（Codex Q7）：命中退避 ⇒ 跳过本次同步核对（省下 900ms 慢通道，把
                # 槽位让给“从未核对过”的名字）；**答案语义不变**（仍按下面的原逻辑保留明文）。
                if CORROB_STRICT_NODATA and _r8_neg_get(name, qtype):
                    with _lock:
                        _stats["r8_neg_fastfail"] = _stats.get("r8_neg_fastfail", 0) + 1
                        _stats["fail_closed"] += 1
                        _fc_classify("r8_neg_cache")
                    log("R8N+ %-38s 负结论缓存命中 → SERVFAIL(免核对，不改结论)" % name)
                    return mk_servfail(msg, qid)
                if _r8_backoff_active(name, qtype):
                    with _lock:
                        _stats["r8_backoff_skip"] += 1
                    log("R8K  %-38s 核对退避中 → 跳过同步核对（不改答案）" % name)
                    # 2026-10-28 R-2：退避命中同样是"无证据保留明文" ⇒ 一样做 TTL 收口
                    uresp = _failopen_cap_ttl(uresp)
                    # P34-AV + Task3 P1-1：出口同门 ✓ —— src 由 `_LABEL_MAP` 折算 ✓（POL⇒local-alt ✓；CNV/POL-SF⇒终局结论，不过闸 ✓）
                    return _finalize_return(uresp, _src_kind(src), name, qtype, qid, msg)
                _cstat, cresp = _r8p_fetch(_fut8, msg, name, qtype,
                                           min(CORROB_DOT_TIMEOUT, _left8))
                # 2026-10-10 Patch8（Codex ⑦）：严格清单门控 —— **必须放在 `cresp is None` 之前**。
                # 否则核对失败时会落到 CORROB_STRICT_FAIL_CLOSED=0 的"保留明文"分支，
                # 使"禁明文回退"静默失效 ✗。此处两条出口都 return，绝不再下发明文。
                if _strict_entry(name, qtype) is not None:
                    with _lock:
                        _stats["strict_hit"] = _stats.get("strict_hit", 0) + 1
                    _cons = _strict_consensus(msg, name, qtype, min(CORROB_DOT_TIMEOUT, _left8))
                    if _cons is not None:
                        _cresp2, _cinter2, _cttl2 = _cons
                        with _lock:
                            _stats["strict_consensus_ok"] = _stats.get("strict_consensus_ok", 0) + 1
                            _stats["redirect"] += 1
                            _stats["r8_adopt"] += 1
                        log("STR  %-38s 严格清单：多运营方共识 → 采用认证答案 %s"
                            % (name, ",".join(sorted(_cinter2))[:36]))
                        corrob_put(name, qtype, _cresp2, sorted(_cinter2), _cttl2)
                        queue_verify(name, qtype, msg, uips, ucn)
                        return _finalize_return(rewrite_id(_cresp2, qid), "clean-channel", name, qtype, qid, msg)
                    with _lock:
                        _stats["strict_no_consensus"] = _stats.get("strict_no_consensus", 0) + 1
                        _stats["fail_closed"] += 1; _fc_classify("no_consensus")
                    log("FC   %-38s 严格清单：多运营方无共识 → SERVFAIL(fail-closed)" % name)
                    return mk_servfail(msg, qid)
                if cresp is None:
                    with _lock:
                        _stats["r8_miss"] += 1
                    # Patch13：登记退避（只抑制后续重试，不改变本次答案选择）
                    _bw = _r8_backoff_record(name, qtype)
                    log("R8B  %-38s 核对未成功(%s) → 退避 %.0fs（本次仍按原语义保留明文）"
                        % (name, _cstat, _bw))
                    if CORROB_STRICT_FAIL_CLOSED:
                        with _lock:
                            _stats["fail_closed"] += 1; _fc_classify(_r8_reason(_cstat))
                        log("FC   %-38s 核对未成功(%s) → SERVFAIL(strict R8)" % (name, _cstat))
                        return mk_servfail(msg, qid)
                    log("R8M  %-38s 核对未成功(%s) → 无证据，保留明文 %s（留痕+异步取证）"
                        % (name, _cstat, ",".join(uips)[:40]))
                    # 2026-10-28 R-2：无证据答案的 TTL 收口（只压滞留窗口，不改判定）
                    uresp = _failopen_cap_ttl(uresp)
                else:
                    _rc8, cips8, _ccn8, ctt8 = parse_a(cresp)
                    cset8 = set(_norm_ip(x) for x in cips8)
                    # 2026-10-09 DNSCrypt 影子核验：只记录一致率与 DNSSEC 证据，
                    # 不参与下面的任何判定（不 return、不写 corrob、不影响 fail_closed）
                    shadow_note(msg, name, qtype, uset8, cset8)
                    # 2026-10-10 Patch28：旁路登记一次异步审计（默认关闭；**绝不改答案** ✓）
                    try:
                        audit_note(msg, name, qtype, uset8)
                    except Exception:
                        pass
                    if cset8 and (uset8 & cset8):
                        _extra = uset8 - cset8
                        if _extra and qtype == 1:
                            # 2026-10-05 P0-3：旧逻辑"只要干净通道没返回就丢地址"，实测把
                            # pool.ntp.org / www.nginx.org 这类**合法轮转/CDN 边缘**也丢了
                            # （R5 把这类明确算"天然轮转"，R8 却是另一套更严的标准）。
                            # 现在只在"额外地址本身被可疑判据命中"时才丢弃。
                            _xstr = sorted(x for x in _extra if isinstance(x, str))
                            _xwhy = suspicious(_xstr, name) if _xstr else None
                            if _xwhy:
                                with _lock:
                                    _stats["r8_extra"] += 1
                                    _stats["redirect"] += 1
                                    _stats["r8_adopt"] += 1
                                log("R8X  %-38s 明文含可疑未佐证地址 %s(%s) → 采用干净答案"
                                    % (name, ",".join(_xstr)[:30], _xwhy))
                                corrob_put(name, qtype, cresp, cips8, ctt8)
                                queue_verify(name, qtype, msg, uips, ucn)
                                return _finalize_return(rewrite_id(cresp, qid), "clean-channel", name, qtype, qid, msg)
                            with _lock:
                                _stats["r8_extra_soft"] += 1
                            log("R8S  %-38s 明文含未佐证但不可疑地址 %s → 保留明文（留痕+异步取证）"
                                % (name, ",".join(_xstr)[:30]))
                            queue_verify(name, qtype, msg, uips, ucn)
                        with _lock:
                            _stats["r8_agree"] += 1
                        corrob_put(name, qtype, uresp, uips, ctt8)
                    elif cset8 and qtype == 28 and not CORROB_V6:
                        # G-2：AAAA 路径原先从未核对。此处核对但默认只告警、并把明文钉进窗口
                        # 以摊销成本（否则每个 AAAA 查询都要付一次认证 DoT 往返）。
                        with _lock:
                            _stats["r8_v6_miss"] += 1
                        log("R8V6 %-38s AAAA 不一致（明文 %s / 加密 %s）→ 仅告警不改道"
                            % (name, ",".join(uips)[:28], ",".join(cips8)[:28]))
                        corrob_put(name, qtype, uresp, uips, ctt8)
                    elif cset8:
                        # 2026-10-10 Patch27（Codex GO）：运营商级门控。**默认关闭** ⇒ 与今天一致 ✓
                        if ASN_GATE and qtype == 1:
                            _au = _side_asn(uset8)
                            _ac = _side_asn(cset8)
                            _D = bool(_au is not None and _ac is not None and _au != _ac)
                            _K = bool(_au is not None and _ac is not None and _au == _ac) or \
                                 (_au is None or _ac is None)
                            if not _D:
                                # K：同运营商（属 CDN/geo 轮转 ✓）或任一未知 ⇒ 保留明文 + 短 pin + 退避
                                with _lock:
                                    _stats["r8_asn_gate_k"] = _stats.get("r8_asn_gate_k", 0) + 1
                                    if _K and (_au is None or _ac is None):
                                        _stats["r8_asn_gate_unknown"] = _stats.get("r8_asn_gate_unknown", 0) + 1
                                _bw25 = _r8_backoff_record(name, qtype)
                                try:
                                    # ★ 方案 §2 第 49 行：**禁止固定 300 秒覆盖短 TTL** ✗。
                                    # 这里原本写死 `300` ✗ ⇒ 哪怕报文自己说 30s，pinned 窗口
                                    # 也按 300s 算（比运营方授权长 10 倍 ✗）。改传**该应答自己**
                                    # 的最小剩余 TTL ✓（同函数内其它 `corrob_put` 调用点口径一致 ✓）。
                                    corrob_put(name, qtype, uresp, uips, ctt8)
                                except Exception:
                                    pass
                                log("R8K  %-38s 同运营商或归属未知（明文 ASN=%s / 加密 ASN=%s）→ 保留明文（退避 %.0fs）"
                                    % (name, _au, _ac, _bw25))
                                # P34-AV + Task3 P1-1：出口同门 ✓ —— src 由 `_LABEL_MAP` 折算 ✓（POL⇒local-alt ✓；CNV/POL-SF⇒终局结论，不过闸 ✓）
                                uresp = _failopen_cap_ttl(uresp)   # 2026-10-28 R-2: unify TTL cap before _finalize_return writes adm cache
                                return _finalize_return(uresp, _src_kind(src), name, qtype, qid, msg)
                            with _lock:
                                _stats["r8_asn_gate_d"] = _stats.get("r8_asn_gate_d", 0) + 1
                        # 2026-10-10 Patch25（Codex 测量项）：只加计数、不改判据 ✓
                        # 同前缀 ⇒ 同一网络内轮转（正常 ✓）；跨前缀 ⇒ 可能是把 CDN 轮转当不一致 ✗。
                        _pfx25 = _prefix_class_agree(uset8, cset8)
                        with _lock:
                            _stats["redirect"] += 1
                            _stats["r8_adopt"] += 1
                            if _pfx25:
                                _stats["r8_adopt_same_pfx"] = _stats.get("r8_adopt_same_pfx", 0) + 1
                            elif uset8 and cset8:
                                _stats["r8_adopt_diff_pfx"] = _stats.get("r8_adopt_diff_pfx", 0) + 1
                            else:
                                _stats["r8_adopt_nopfx"] = _stats.get("r8_adopt_nopfx", 0) + 1
                        _tr_flag("r8_conflict")
                        log("R8   %-38s 单路核对不一致（明文 %s / 加密 %s；同前缀=%s）→ 采用加密答案"
                            % (name, ",".join(uips)[:30], ",".join(cips8)[:30], _pfx25 or "-"))
                        corrob_put(name, qtype, cresp, cips8, ctt8)
                        queue_verify(name, qtype, msg, uips, ucn)
                        return _finalize_return(rewrite_id(cresp, qid), "clean-channel", name, qtype, qid, msg)
                    else:
                        # G-4：干净侧有应答但无地址（NODATA/NXDOMAIN）是最强不一致证据，旧逻辑静默放行
                        with _lock:
                            _stats["r8_noans"] += 1
                        if CORROB_STRICT_NODATA:
                            with _lock:
                                _stats["fail_closed"] += 1; _fc_classify("strict_nodata")
                                _r8_neg[(name, qtype)] = time.time() + R8_NEG_TTL
                                _stats["r8_neg_store"] = _stats.get("r8_neg_store", 0) + 1
                            log("FC   %-38s R8 明文有地址但干净侧无地址 → SERVFAIL(fail-closed，负缓存 %.0fs)" % (name, R8_NEG_TTL))
                            return mk_servfail(msg, qid)
                        log("R8N  %-38s 明文有地址但干净侧无地址（仅告警，未 fail-closed）" % name)
    # P34-AU（方案任务2）：普通出口**同门** ✓ —— 这里 src 可能是 "B" ✗，
    # B 的候选只能当见证 ⇒ 策略模式下经 finalize_answer（不可采纳则 SERVFAIL）✓。
    return _finalize_return(uresp, _src_kind(src), name, qtype, qid, msg)


if SHADOW_TARGET and not os.environ.get("VERIFIER_SLOTS"):
    # 只在主服务启动：verifier 也 import 本模块，但它从不调用 shadow_note，
    # 且有自己的 STATE_DIR，起 writer 只会产出恒为 0 的噪声文件。
    threading.Thread(target=shadow_writer, daemon=True).start()


def _client_udp_limit(msg):
    """客户端查询声明的 UDP 响应上限（RFC 1035 4.2.1 / RFC 6891）。

    无 EDNS0 ⇒ 512 字节；带 OPT(41) ⇒ 取其 CLASS 字段（payload size），clamp 到 [512, 65535]。
    解析不出 ⇒ 保守 512。2026-10-28 为修 AGH 'dns: overflowing header size' 而加：
    AGH 转发上游时剥掉 OPT，按 512 缓冲区读响应，而本进程透传了 748 字节 DNSSEC 大响应。
    """
    try:
        if len(msg) < 12:
            return 512
        qd = struct.unpack('!H', msg[4:6])[0]
        an = struct.unpack('!H', msg[6:8])[0]
        ns = struct.unpack('!H', msg[8:10])[0]
        ar = struct.unpack('!H', msg[10:12])[0]
        if ar <= 0 or an or ns:
            return 512
        o = 12
        for _ in range(qd):
            while o < len(msg) and msg[o] != 0:
                if (msg[o] & 0xC0) == 0xC0:
                    o += 1
                    break
                o += 1 + msg[o]
            o += 1 + 4
        if o >= len(msg) or msg[o] != 0 or o + 5 > len(msg):
            return 512
        t, cls = struct.unpack('!HH', msg[o + 1:o + 5])
        if t == 41:
            return max(512, min(65535, int(cls)))
        return 512
    except Exception:
        return 512


def _udp_fit(msg, resp):
    """UDP 响应必须适配客户端声明的缓冲；超限则截断为 header+question 并置 TC=1，
    让客户端改走 TCP（本进程在 LISTEN_PORT 上同时监听 TCP，完整答案在那里给）。"""
    try:
        if not resp:
            return resp
        lim = _client_udp_limit(msg)
        if len(resp) <= lim:
            return resp
        qd = struct.unpack('!H', resp[4:6])[0]
        o = 12
        for _ in range(qd):
            while o < len(resp) and resp[o] != 0:
                if (resp[o] & 0xC0) == 0xC0:
                    o += 1
                    break
                o += 1 + resp[o]
            o += 1 + 4
        if o < 12 or o > len(resp):
            return resp
        head = bytearray(resp[:o])
        flags = struct.unpack('!H', head[2:4])[0] | 0x0200
        struct.pack_into('!H', head, 2, flags)
        struct.pack_into('!H', head, 6, 0)
        struct.pack_into('!H', head, 8, 0)
        struct.pack_into('!H', head, 10, 0)
        with _lock:
            _stats['udp_tc_truncated'] = _stats.get('udp_tc_truncated', 0) + 1
        return bytes(head)
    except Exception:
        return resp


def udp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((LISTEN_HOST, LISTEN_PORT))
    log("dnsguard UDP listening on %s:%d (unbound=%s, clean=%d 个 DoT, churn=%s)"
        % (LISTEN_HOST, LISTEN_PORT, UNBOUND[0], len(CLEAN_DOT), "on" if CHURN_ENABLED else "off"))
    while True:
        try:
            msg, addr = s.recvfrom(65535)
            # 2026-10-07：两道门都在 **submit 之前**。
            # _dispatch_sem 是"请求级"上限；submit_limited 是"在飞+排队"的硬上限。
            # 任一失败 → 立刻 SERVFAIL，绝不把任务丢进无界队列静默排队。
            _adm_ok = _dispatch_sem.acquire(False)
            if _adm_ok:
                _adm_ok = submit_limited(_dispatch_udp, s, msg, addr, time.monotonic())
                if not _adm_ok:
                    _dispatch_sem.release()
            if not _adm_ok:
                with _lock:
                    _stats["overload_drop"] += 1
                    _stats["admission_reject"] += 1 ; _fc_classify("admission_overload")
                    _nrej = _stats["admission_reject"]
                if _nrej % 200 == 1:
                    log("ADM  udp 有界队列已满（累计 %d）→ 通道堵塞应答 rcode=%d ede=%d"
                        % (_nrej, OVERLOAD_RCODE, OVERLOAD_EDE))
                resp = mk_servfail(msg, rcode=OVERLOAD_RCODE, ede=(OVERLOAD_EDE or None))
                if resp:
                    s.sendto(resp, addr)
                continue
        except Exception as e:
            log("udp loop error: %s" % e)


def _dispatch_udp(s, msg, addr, t_arr=None):
    try:
        _reply_udp(s, msg, addr, t_arr)
    finally:
        _dispatch_sem.release()

def _reply_udp(s, msg, addr, t_arr=None):
    global _pending_count
    with _pending_lock:
        if _pending_count >= MAX_PENDING or not _inflight_sem.acquire(False):
            with _lock:
                _stats["overload_drop"] += 1
            resp = mk_servfail(msg)
            if resp:
                s.sendto(resp, addr)
            return
        _pending_count += 1
    try:
        _scls = _src_bump(addr)  # P34-AG: count by source class
        # Step-1 §1：建立请求追踪上下文（无锁、零 I/O ✓）+ **显式**带上来源类别
        # （处理跑在 executor worker 线程，`_SRC` 是 threading.local ⇒ worker 读不到 ✗）。
        _tr_begin(msg, "udp", _scls)
        if t_arr is not None:
            try:
                _tr()["wait_ms"] = (time.monotonic() - t_arr) * 1000.0
            except Exception:
                pass
        resp = handle(msg)
        # ★ 方案 §3 第 67 行：`left≤0` **立即结束** ✓，但"结束"必须给出**明确结论** ✗。
        #   现场缺陷（§3 完成门首轮实测 ③④ 暴露）：上游全部超时时 `handle()` 走到
        #   `if uresp is None: r = dot_query(...); if not r: return None` ⇒ 这里 `if resp:`
        #   为假 ⇒ **一个字节都不发** ✗ ⇒ 客户端只能等自己的 i/o timeout（实测 9s/10s/15s）。
        #   这不是"慢"✗，是"静默丢包"✗：对上层是黑盒超时，无法重试/降级，比 SERVFAIL 更糟 ✗。
        #   修法：**任何"有结论但无字节"的出口一律回 SERVFAIL** ✓ ——
        #   `mk_servfail()` 对畸形/无 question 的报文返回 None ✓（那类请求本就该静默丢弃 ✓），
        #   所以拿不到应答只可能是"上游确实全失败" ⇒ SERVFAIL 是唯一正确结论 ✓。
        if not resp:
            resp = mk_servfail(msg)
            if resp:
                with _lock:
                    _stats["resp_servfail_built"] = _stats.get("resp_servfail_built", 0) + 1
        # `once=True`：本路径每请求恰好收口一次 ⇒ `q_*` 与 `base_q` 同口径、可直接互校 ✓
        _tr_finish(msg, resp, once=True, ignore_cls=("probe",))
        resp = _udp_fit(msg, resp)
        if resp:
            s.sendto(resp, addr)
    except Exception as e:
        log("handle error: %s\n%s" % (e, traceback.format_exc()))
    finally:
        with _pending_lock:
            _pending_count -= 1
        _inflight_sem.release()


def _tcp_overload_servfail(conn):
    """过载快速拒绝：尽量把查询读回来并回 SERVFAIL，而不是静默断连。

    2026-10-07：静默断连时客户端看到的是"连接被关且无应答"，上游（AGH）只能等
    i/o timeout（实测日志里是 10.00s）；回 rcode=2 能让调用方立刻失败/重试/降级。
    只等 0.3s 读查询体：读不完整就直接关，不让"拒绝"路径本身变成新的等待。
    """
    try:
        conn.settimeout(0.3)
        hdr = conn.recv(2)
        if len(hdr) == 2:
            ln = struct.unpack("!H", hdr)[0]
            if 0 < ln <= 4096:
                msg = b""
                while len(msg) < ln:
                    c = conn.recv(ln - len(msg))
                    if not c:
                        break
                    msg += c
                if len(msg) == ln:
                    resp = mk_servfail(msg, rcode=OVERLOAD_RCODE, ede=(OVERLOAD_EDE or None))
                    if resp:
                        conn.sendall(struct.pack("!H", len(resp)) + resp)
                        with _lock:
                            _stats["overload_servfail"] += 1
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def tcp_client(conn):
    acquired = _inflight_sem.acquire(False)
    if not acquired:
        with _lock:
            _stats["overload_drop"] += 1
        _tcp_overload_servfail(conn)
        return
    msg = b""
    resp = None
    try:
        _scls = _src_of(conn.getpeername())[0]
    except Exception:
        _scls = "loopback"
    try:
        with _lock:
            _stats["q_src_" + _scls] = _stats.get("q_src_" + _scls, 0) + 1
        conn.settimeout(5)
        hdr = conn.recv(2)
        if len(hdr) < 2:
            return
        ln = struct.unpack("!H", hdr)[0]
        while len(msg) < ln:
            c = conn.recv(ln - len(msg))
            if not c:
                return
            msg += c
        # Step-1 §1：TCP 入口也纳入基线（entry=tcp）
        _tr_begin(msg, "tcp", _scls)
        resp = handle(msg)
        # ★ 与 UDP 同一条不变式（方案 §3 第 67 行）：**有结论 ⇒ 必须有字节** ✗。
        #   TCP 若静默关连接，上游（AGH）同样只能等 i/o timeout ✗（与 `_tcp_overload_servfail`
        #   注释里记的"静默断连"是同一个病 ✗）⇒ 统一回 SERVFAIL ✓。
        if not resp:
            resp = mk_servfail(msg)
            if resp:
                with _lock:
                    _stats["resp_servfail_built"] = _stats.get("resp_servfail_built", 0) + 1
        if resp:
            conn.sendall(struct.pack("!H", len(resp)) + resp)
    except Exception:
        resp = None
    finally:
        try:
            _tr_finish(msg, resp)
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass
        _inflight_sem.release()


def _dispatch_tcp(conn):
    try:
        tcp_client(conn)
    finally:
        _dispatch_sem.release()

def _probe_reply_udp(s, msg, addr):
    """探针通道的请求处理：只走 handle()，不触碰任何用户侧信号量/计数。"""
    global _probe_pending
    with _pending_lock:
        if _probe_pending >= MAX_PROBE_PENDING or not _probe_inflight_sem.acquire(False):
            with _lock:
                _stats["probe_overload_drop"] += 1
            resp = mk_servfail(msg, rcode=OVERLOAD_RCODE, ede=(OVERLOAD_EDE or None))
            if resp:
                s.sendto(resp, addr)
            return
        _probe_pending += 1
    try:
        with _lock:
            _stats["probe_q"] += 1
        try:
            _SRC.v = "probe"
        except Exception:
            pass
        _tr_begin(msg, "probe", "probe")   # Step-1 §1：业务与 5356 探针**分开统计** ✓
        resp = handle(msg)
        _tr_finish(msg, resp, ignore_cls=("probe",))   # 探针**不计入**用户侧基线 ✓
        if resp:
            s.sendto(resp, addr)
    except Exception as e:
        log("probe handle error: %s" % e)
    finally:
        with _pending_lock:
            _probe_pending -= 1
        _probe_inflight_sem.release()


def _probe_submit_limited(s, msg, addr):
    if not _probe_executor_slots.acquire(False):
        return False

    def wrapped():
        try:
            _probe_reply_udp(s, msg, addr)
        finally:
            _probe_executor_slots.release()
            _probe_dispatch_sem.release()

    try:
        _probe_executor.submit(wrapped)
    except Exception:
        _probe_executor_slots.release()
        return False
    return True


def probe_udp_server():
    """探针专用 UDP 监听（阶段3）。失败不影响主监听：捕获异常后退出该线程。"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((PROBE_LISTEN_HOST, PROBE_LISTEN_PORT))
    except Exception as e:
        log("探针通道未启用（bind %s:%d 失败: %s）" % (PROBE_LISTEN_HOST, PROBE_LISTEN_PORT, e))
        return
    log("dnsguard PROBE UDP listening on %s:%d（独立闸门 %d 槽 / 排队 %d；用户侧 %d 槽不受影响）"
        % (PROBE_LISTEN_HOST, PROBE_LISTEN_PORT, MAX_PROBE_INFLIGHT, MAX_PROBE_PENDING, MAX_INFLIGHT))
    while True:
        try:
            msg, addr = s.recvfrom(65535)
            ok = _probe_dispatch_sem.acquire(False)
            if ok:
                ok = _probe_submit_limited(s, msg, addr)
                if not ok:
                    _probe_dispatch_sem.release()
            if not ok:
                with _lock:
                    _stats["probe_overload_drop"] += 1
                    _stats["probe_admission_reject"] += 1
                    _prej = _stats["probe_admission_reject"]
                if _prej % 200 == 1:
                    log("PADM 探针通道队列已满（累计 %d）→ 通道堵塞应答 rcode=%d"
                        % (_prej, OVERLOAD_RCODE))
                resp = mk_servfail(msg, rcode=OVERLOAD_RCODE, ede=(OVERLOAD_EDE or None))
                if resp:
                    s.sendto(resp, addr)
                continue
        except Exception as e:
            log("probe udp loop error: %s" % e)


def tcp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((LISTEN_HOST, LISTEN_PORT))
    s.listen(64)
    while True:
        try:
            conn, _ = s.accept()
            # 2026-10-07：TCP 的过载门也必须放在 **submit 之前**。
            # 只改 tcp_client() 内部的 conn.close() 没用 —— 连接那时早已在主 executor 队列里排队。
            _adm_ok = _dispatch_sem.acquire(False)
            if _adm_ok:
                _adm_ok = submit_limited(_dispatch_tcp, conn)
                if not _adm_ok:
                    _dispatch_sem.release()
            if not _adm_ok:
                with _lock:
                    _stats["overload_drop"] += 1
                    _stats["admission_reject"] += 1 ; _fc_classify("admission_overload")
                _tcp_fast_reject(conn)
                continue
        except Exception:
            time.sleep(0.2)


def prewarm():
    def _warm_one(ip, port, sni, out, idx):
        try:
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(socket.create_connection((ip, port), timeout=8),
                                server_hostname=sni)
            _pool_give((ip, port, sni), s)
            out[idx] = True
        except Exception as e:
            out[idx] = str(e)[:50]

    for ip, port, sni in CLEAN_DOT:
        n = _POOL_N
        out = [None] * n
        ths = [threading.Thread(target=_warm_one, args=(ip, port, sni, out, i), daemon=True)
               for i in range(n)]
        for t in ths:
            t.start()
        for t in ths:
            t.join(15)
        okc = sum(1 for r in out if r is True)
        if okc:
            log("prewarm ok %s (%d/%d 条)" % (sni, okc, n))
        else:
            log("prewarm fail %s: %s" % (sni, out[0]))
    # DoQ 转发器（aghdq / aghdq2）各预热一次，避免首次使用付 QUIC 握手（实测冷启动 550ms~1.6s）
    for i, (ip, port) in enumerate(LOCAL_DOQ_LIST):
        tag = ("doq", "doq2", "doq3")[i] if i < 3 else "doq%d" % i
        try:
            r = _udp_raw(mk_query("example.com", qid=0x4242 + i), ip, port, 5)
            log("prewarm ok %s(:%d)" % (tag, port) if r
                else "prewarm fail %s(:%d): 无应答" % (tag, port))
        except Exception as e:
            log("prewarm fail %s(:%d): %s" % (tag, port, str(e)[:50]))


def keepalive():
    """干净通道保活：定期热一次并记录 RTT。

    动机：DoT 是新连接 TCP+TLS 两个来回 + 首查两个来回 ≈ 1.0~1.2s，空闲后连接被中间设备回收，
    下一次真正需要用干净通道时就要付这笔冷启动；常连接本身已复用（_dot_raw 连接池），
    再加保活就能把"首查"也压到 1 个 RTT（实测 ~250ms），并让看板看到每条通道的实时状态。"""
    if KEEPALIVE_S <= 0:
        return
    while True:
        time.sleep(KEEPALIVE_S)
        for c in _clean_channels():
            # 用一个全新的随机 .com 名字：确保量到的是"真的走了一趟上游"的 RTT，
            # 而不是上游缓存命中（用 example.com 时 aghdq 本地缓存只回 4ms，会误导）。
            q = mk_query("%s.com" % "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(12)),
                         qid=0x4343)
            t0 = time.time()
            b = _upstream_call(c["ip"], c["port"], c["sni"], q, 3.0)
            rtt = round((time.time() - t0) * 1000, 1)
            ok = bool(b) and parse_a(b)[0] is not None
            with _lock:
                prev = _ch_stat.get(c["label"], {}).get("ok")
                _ch_stat[c["label"]] = {"rtt_ms": rtt if ok else None, "ok": ok,
                                        "ts": int(time.time()), "err": "" if ok else "无应答/超时"}
                if c["label"] == "dnscrypt":
                    _stats["fast_dnscrypt_ms"] = (round(rtt, 1) if ok else None)
            if prev is not None and prev != ok:
                log("通道 %s %s (%.0f ms)" % (c["label"], "恢复" if ok else "异常", rtt))


def stats_writer():
    while True:
        # 2026-10-09 问题2：弱证据过期扫描（节流 WEAK_EXPIRE_INTERVAL；必须在 _lock 之外调用）
        try:
            _now_w = time.time()
            if _now_w - _WEAK_EXPIRE_LAST[0] > WEAK_EXPIRE_INTERVAL:
                _WEAK_EXPIRE_LAST[0] = _now_w
                _expire_weak_poison(_now_w)
                _expire_confirmed_ips(_now_w)
        except Exception as _ew:
            log("WEXP scan error: %s" % _ew)
        try:
            # §5：进程级资源（PSS）在**快照之前**采 ⇒ 与本次写出同周期可见 ✓
            #（放在 `dict(_stats)` 之后会晚一个周期才出现在 stats.json ✓⇒ 让人误以为
            # "PSS 没在采"✗）。
            _pss_sample()
            with _lock:
                st = dict(_stats)
                st["learned"] = len(_table)
                st["cache"] = len(_cache)
                st["learned_ips"] = len(_learned_bad_ips)
                st["pending"] = len([1 for v in _diff.values() if not v.get("ignored")])
                st["clean_ch"] = dict(_ch_stat)
                st["fail_closed_by_reason"] = dict(_fc_by_reason)
                # 2026-10-09 问题2：黑名单强弱分布（看板据此区分"真投毒"与"证据不足"）
                _ns = sum(1 for _v in _table.values()
                          if (_v.get("strength") or _strength_of(_v.get("why", ""))) == "strong")
                st["poison_strong"] = _ns
                st["poison_weak"] = len(_table) - _ns
                # Step-1 §1：业务基线**分桶**（定长，写进 stats.json ⇒ chainmon 可汇总 ✓）
                st["base"] = _bs_snapshot()
            st["updated"] = time.time()
            st["pid"] = os.getpid()
            # §5 第 2 项：把业务 QPS 的实际估计值一并留档 ⇒
            # "刷新速率是不是真的被压到 ≤业务 10%"事后**可核对** ✓
            # （否则只有一个静态阈值，无法证明它当时是"按业务比例"生效的 ✓）。
            try:
                _bq = float(_stats.get("base_q", 0) or 0)
                if _BOOT_BQ[0] <= 0:
                    _BOOT_BQ[0] = _bq
                    _BOOT_BQ[1] = time.time()
                _el_bq = max(1.0, time.time() - float(_BOOT_BQ[1] or 0))
                _stats["base_bqps_x1000"] = int(1000.0 * max(0.0, _bq - _BOOT_BQ[0]) / _el_bq)
            except Exception:
                pass
            _atomic_json(STATS_FILE, st)
            # Step-1 §1：明细样本**默认关闭**；开启时也只在统计周期里批量落盘 ✓
            if _BASE_SAMPLE:
                _bs_flush()
            # fail-closed 原因按分钟限流汇总（每种 reason 每分钟最多一行；首次立即写）
            try:
                _now = time.time()
                _due = []
                with _fc_lock:
                    for _r in FC_REASONS:
                        _n = _fc_by_reason.get(_r, 0)
                        # 仅在**计数有新增**且距上次汇总 >=60s 时输出；
                        # 否则停火的原因会每分钟重复刷一行（只记变更，才能真正降噪）
                        if _n > _fc_last_count.get(_r, 0) and (_now - _fc_last_log.get(_r, 0.0)) >= 60.0:
                            _fc_last_log[_r] = _now
                            _fc_last_count[_r] = _n
                            _due.append((_r, _n))
                for _r, _n in _due:
                    log("FCR  reason=%-17s 累计=%-7d" % (_r, _n))
            except Exception:
                pass
            if _r8_stable_dirty:
                save_r8_stable()
        except Exception:
            pass
        time.sleep(STATS_PERIOD)


def status():
    load_state()
    print("黑名单域名数: %d" % len(_table))
    for d, e in sorted(_table.items(), key=lambda x: -x[1].get("hits", 0))[:40]:
        print("  %-42s hits=%-4s %s | bad=%s clean=%s"
              % (d, e.get("hits"), e.get("why"), e.get("bad"), e.get("clean")))
    print("学习集 IP: %s" % (", ".join(sorted(_learned_bad_ips)) or "(空)"))
    print("统计:", json.dumps(_stats))


def prune_ips():
    """清理未获 ≥2 域名印证的存量学习 IP（v1 遗留脏数据）"""
    load_bad_ips()
    drop = []
    for ip in sorted(_learned_bad_ips):
        doms = _bad_ip_domains.get(ip, [])
        # P3：以注册域数为准（同注册域兄弟只计一票）
        if len(set(doms)) < 2:
            drop.append((ip, doms))
    for ip, doms in drop:
        _learned_bad_ips.discard(ip)
        _bad_ip_domains.pop(ip, None)
    save_bad_ips()
    for ip, doms in drop:
        print("  移除 %-16s 无交叉印证（域名=%s）" % (ip, ",".join(doms) or "无"))
    print("prune-ips: 移除 %d 条，剩余 %d 条" % (len(drop), len(_learned_bad_ips)))


def main_cli():
    """返回 True 表示已由 CLI 处理完毕（不应进入服务模式）"""
    args = sys.argv[1:]
    if not args:
        return False
    cmd = args[0]
    if cmd == "--status":
        status()
        return True
    if cmd == "--pending":
        load_diff()
        rows = [(d, v) for d, v in _diff.items() if not v.get("ignored")]
        rows.sort(key=lambda kv: -kv[1].get("count", 0))
        print("待确认 %d 条（另有已忽略 %d 条）"
              % (len(rows), sum(1 for v in _diff.values() if v.get("ignored"))))
        for d, v in rows[:60]:
            print("  %-40s x%-4s unbound=%-30s clean=%s"
                  % (d, v.get("count"), str(v.get("unbound"))[:30], str(v.get("clean"))[:30]))
        return True
    if cmd == "--prune-ips":
        prune_ips()
        return True
    if cmd == "--reclassify":
        load_state()
        _apply = "--apply" in args
        _chg = []
        for _d, _e in _table.items():
            _want = _strength_of(_e.get("why", ""))
            _cur = _e.get("strength") or "(无)"
            if _cur != _want:
                _chg.append((_d, _cur, _want, (_e.get("why") or "")[:44]))
                if _apply:
                    _e["strength"] = _want
                    # 迁移时补 last：hits==1 的条目"最后观察=first"（如实按 3 天 TTL 判定）；
                    # hits>1 说明后来又被观察到，给它一个新的 3 天窗口（不让历史条目被过早过期）。
                    if "last" not in _e:
                        _e["last"] = (time.time() if int(_e.get("hits") or 1) > 1
                                      else (_e.get("first") or time.time()))
        print("reclassify: 待变更 %d 条%s" % (len(_chg), "" if _apply else "（dry-run；加 --apply 才写回）"))
        for _d, _a, _b, _w in _chg[:80]:
            print("  %-44s %-9s -> %-7s %s" % (_d, _a, _b, _w))
        if _chg and len(_chg) > 80:
            print("  ...（其余 %d 条省略）" % (len(_chg) - 80))
        if _apply:
            save_state()
            print("已写回 poisoned.json（备份请自行留存）")
        return True
    if cmd == "--list-weak":
        load_state()
        _rows = [(_d, _e) for _d, _e in _table.items() if _strength_of(_e.get("why", "")) == "weak"]
        _rows.sort(key=lambda kv: -(kv[1].get("last") or kv[1].get("first") or 0))
        print("弱证据 %d 条（黑名单共 %d 条）：" % (len(_rows), len(_table)))
        for _d, _e in _rows[:80]:
            print("  %-44s hits=%-3s first=%s why=%s"
                  % (_d, _e.get("hits"), time.strftime("%m-%d %H:%M", time.localtime(_e.get("first") or 0)),
                     (_e.get("why") or "")[:34]))
        return True
    if cmd == "--ip-review":
        load_bad_ips()
        rows = [(k, v) for k, v in _ip_info.items() if v.get("status") in ("review", "candidate")]
        _expd = [(k, v) for k, v in _ip_info.items()
                 if v.get("status") == "confirmed" and v.get("expires")
                 and time.time() > float(v.get("expires") or 0)]
        if _expd:
            print("  !! 已过期但仍标 confirmed（应已被扫描转 review）: %s" % [x[0] for x in _expd][:6])
        rows.sort(key=lambda kv: -(kv[1].get("last") or 0))
        print("待人工复核 / 候选 IP: %d 个（确认集 %d）" % (len(rows), len(_learned_bad_ips)))
        for ip, e in rows[:60]:
            ok, why = _ip_eval(ip)
            print("  %-16s %-9s 注册域=%s 窗口=%d 规则=%s 依据=%s"
                  % (ip, e.get("status"), ",".join((e.get("regdomains") or [])[:3]),
                     len(set(e.get("windows") or [])), ",".join((e.get("rules") or [])[:3]),
                     ",".join(e.get("basis") or []) or "-"))
            print("      %s" % (why if not ok else "满足条件"))
        return True
    if cmd == "--ip-info" and len(args) > 1:
        load_bad_ips()
        ip = args[1]
        e = _ip_info.get(ip)
        if not e:
            print("未知 IP: %s（当前确认集 %d 个）" % (ip, len(_learned_bad_ips)))
            return True
        ok, why = _ip_eval(ip)
        print("IP %s" % ip)
        print("  status=%s  first=%s  last=%s  legacy=%s"
              % (e.get("status"), time.strftime("%m-%d %H:%M", time.localtime(e.get("first") or 0)),
                 time.strftime("%m-%d %H:%M", time.localtime(e.get("last") or 0)), e.get("legacy")))
        print("  注册域=%s" % ",".join(e.get("regdomains") or []))
        print("  域名=%s" % ",".join((e.get("domains") or [])[:8]))
        print("  规则=%s  依据=%s  窗口=%d 个" % (",".join(e.get("rules") or []), ",".join(e.get("basis") or []) or "-", len(set(e.get("windows") or []))))
        print("  我方答案=%s" % ",".join((e.get("ours") or [])[:6]))
        print("  干净答案=%s" % ",".join((e.get("clean") or [])[:6]))
        _doms, _regs = _ip_scope_of(e)
        print("  生效范围: domains=%s | regdomains=%s" % (",".join(_doms[:6]) or "-", ",".join(_regs[:6]) or "-"))
        print("  独立依据=%s  有效期至=%s" % (e.get("independent"),
              time.strftime("%Y-%m-%d %H:%M", time.localtime(e.get("expires") or 0)) if e.get("expires") else "-"))
        print("  clean 按来源=%s  merged=%s" % (str(e.get("clean_by_source"))[:80], e.get("merged")))
        print("  判定=%s（%s）  人工结论=%s" % ("可确认" if ok else "不可确认", why, e.get("note") or "-"))
        return True
    if cmd in ("--ip-confirm", "--ip-reject") and len(args) > 1:
        load_bad_ips()
        ip = args[1]
        e = _ip_info.setdefault(ip, {"status": "candidate", "first": time.time(), "last": time.time(),
                                     "windows": [], "domains": [], "regdomains": [], "rules": [],
                                     "ours": [], "clean": [], "basis": [], "note": ""})
        if cmd == "--ip-confirm":
            e["status"] = "confirmed"
            e["basis"] = sorted(set((e.get("basis") or []) + ["人工确认"]))
            e["independent"] = True
            # 范围修正⑥：必须带范围；--scope 显式指定，否则沿用记录推导的范围
            _sc = None
            if "--scope" in args:
                _i = args.index("--scope")
                if _i + 1 < len(args):
                    _sc = [x.strip().lower().rstrip(".") for x in args[_i + 1].split(",") if x.strip()]
            if _sc:
                e["scope"] = {"domains": sorted(set(_sc)), "regdomains": sorted(set(_regdom(x) for x in _sc))}
            elif not e.get("scope"):
                e["scope"] = {"domains": sorted(set(e.get("domains") or []))[:30],
                              "regdomains": sorted(set(e.get("regdomains") or []))[:30]}
            _ttl = IP_CONFIRM_TTL
            if "--ttl" in args:
                _i = args.index("--ttl")
                if _i + 1 < len(args):
                    try:
                        _ttl = int(float(args[_i + 1]) * 86400)
                    except Exception:
                        _ttl = IP_CONFIRM_TTL
            e["expires"] = time.time() + _ttl
            e["note"] = "人工确认 %s（范围=%s，有效 %d 天）" % (
                time.strftime("%Y-%m-%d %H:%M"), ",".join((e["scope"].get("domains") or [])[:4]) or "记录推导",
                int(_ttl / 86400))
            _learned_bad_ips.add(ip)
            log("IPMC 人工确认 %s（范围生效，%d 天有效）" % (ip, int(_ttl / 86400)))
            print("confirmed", ip, e["scope"])
        else:
            e["status"] = "rejected"
            e["note"] = "人工否决 %s" % time.strftime("%Y-%m-%d %H:%M")
            _learned_bad_ips.discard(ip)
            with _lock:
                _stats["ip_rejected"] = _stats.get("ip_rejected", 0) + 1
            log("IPMR 人工否决 %s（撤销，不再参与 R1）" % ip)
            print("rejected", ip)
        e["last"] = time.time()
        save_bad_ips()
        return True
    if cmd == "--strict-list":
        strict_load()
        print("严格清单: %d 条" % len(_strict))
        for k, e in sorted(_strict.items()):
            exp = e.get("expires")
            print("  %-52s by=%-10s exp=%s reason=%s" % (
                k[:52], str(e.get("by"))[:10],
                time.strftime("%m-%d %H:%M", time.localtime(exp)) if exp else "-",
                str(e.get("reason"))[:40]))
        return True
    if cmd == "--strict-add" and len(args) > 1:
        strict_load()
        host = args[1].lower().strip().rstrip(".")
        qt = 1
        if "--qtype" in args:
            try:
                qt = int(args[args.index("--qtype") + 1])
            except Exception:
                qt = 1
        days = 3.0
        if "--days" in args:
            try:
                days = float(args[args.index("--days") + 1])
            except Exception:
                days = 3.0
        reason = "manual"
        if "--reason" in args and args.index("--reason") + 1 < len(args):
            reason = args[args.index("--reason") + 1]
        # 2026-10-10 Patch11（Codex Stage B）：默认**同时加 A 与 AAAA**（AAAA 不对称风险：
        # 只列 A 时 AAAA 仍走明文，而 GFW 对 google 系注入过 2001::1）。`--qtype N` 可只加一种。
        _qts = [qt] if ("--qtype" in args) else [1, 28]
        _exp = time.time() + days * 86400
        for _q in _qts:
            _strict[_strict_key(host, _q)] = {"added": time.time(),
                                              "by": os.environ.get("USER") or "root",
                                              "reason": reason[:120], "expires": _exp}
        strict_save()
        print("strict-add %s（%s）有效 %.1f 天"
              % (host, ",".join("A" if q == 1 else ("AAAA" if q == 28 else "QTYPE%d" % q) for q in _qts), days))
        return True
    if cmd == "--strict-remove" and len(args) > 1:
        strict_load()
        host = args[1].lower().strip().rstrip(".")
        rm = [k for k in list(_strict) if k.startswith(host + "|")]
        for k in rm:
            _strict.pop(k, None)
        strict_save()
        print("strict-remove %s（移除 %d 条）" % (host, len(rm)))
        return True
    if cmd == "--r5-queue":
        load_r5()
        load_diff()
        with _lock:
            pend = dict((k, list(v)) for k, v in _R5_PENDING.items())
        print("R5 候选（窗口状态）: %d 个" % len(pend))
        for k, v in sorted(pend.items()):
            print("  %-42s 窗口=%d 首个=%s category=%s"
                  % (k[:42], len(v), time.strftime("%m-%d %H:%M", time.localtime((v[0].get("ts") or 0))),
                     _r5_category(k) or "-"))
        q = [(k, e) for k, e in _diff.items() if e.get("source") == "R5" and not e.get("ignored")]
        print("已进入待确认队列（source=R5）: %d 个" % len(q))
        for k, e in sorted(q, key=lambda kv: -(kv[1].get("last") or 0))[:40]:
            print("  %-42s 窗口=%s category=%-10s unbound=%s clean=%s"
                  % (k[:42], e.get("windows"), e.get("category") or "-",
                     str(e.get("unbound"))[:26], str(e.get("clean"))[:26]))
        return True
    if cmd == "--prune-weak":
        load_state()
        load_diff()
        _n = _expire_weak_poison()
        print("prune-weak: 按 %d 天 TTL 过期移出 %d 条" % (int(WEAK_TTL / 86400), _n))
        return True
    if cmd == "--churn" and len(args) > 1:
        load_cn_nets()
        q = mk_query(args[1])
        print("%s 抖动采样: %s" % (args[1], churn_samples(args[1], n=3)))
        print("  判定: %s" % jitter_verdict(args[1], q))
        return True
    if cmd == "--learned-ips":
        load_bad_ips()
        for ip in sorted(_learned_bad_ips):
            print("  %-16s <- %s" % (ip, ",".join(_bad_ip_domains.get(ip, []))))
        print("共 %d 条" % len(_learned_bad_ips))
        return True
    if cmd == "--recheck":
        load_diff()
        load_cn_nets()
        drop = []
        for d, v in list(_diff.items()):
            if v.get("ignored"):
                continue
            u = [x for x in (v.get("unbound") or "").split(",") if x]
            c = [x for x in (v.get("clean") or "").split(",") if x]
            flags = [is_cn_ip(x) for x in u]
            geo = bool(flags) and all(f is True for f in flags)
            if u and c and ":" in u[0] and ":" in c[0] and u[0].split(":")[:3] == c[0].split(":")[:3]:
                geo = True
            v4 = [x for x in u if ":" not in x]
            if not geo and not v4:
                geo = True                      # 纯 IPv6 差异不排队
            if not geo and v4:
                cv = cert_name_match(v4[0], d)
                if cv is True:
                    geo = True
                    print("  CDN 排除: %s (%s)" % (d, v4[0]))
                elif cv is False:
                    v4c = [x for x in c if ":" not in x]
                    vc = None
                    for x in v4c[:2]:
                        vc = cert_name_match(x, d)
                        if vc is not None:
                            break
                    if vc is True:
                        mark(d, "recheck R6 证书对照：%s 不持有该域名证书" % v4[0], ",".join(u), ",".join(c))
                        drop.append(d)
                        print("  🔴 判为投毒: %s (%s)" % (d, v4[0]))
                    else:
                        print("  ⏸ 无法判定（干净上游也拿不到证书）: %s" % d)
            if geo:
                drop.append(d)
        for d in drop:
            _diff.pop(d, None)
        save_diff()
        print("recheck: 移除 %d 条，剩余待确认 %d 条"
              % (len(drop), len([1 for v in _diff.values() if not v.get("ignored")])))
        return True
    if cmd == "--confirm" and len(args) > 1:
        load_state()
        load_diff()
        e = _diff.get(args[1], {})
        mark(args[1], "人工确认（DIFF 待确认清单）", e.get("unbound", ""), e.get("clean", ""))
        _diff.pop(args[1], None)
        save_diff()
        print("confirmed", args[1])
        return True
    if cmd == "--ignore" and len(args) > 1:
        load_state()
        load_diff()
        e = _diff.get(args[1], {"count": 0})
        e["ignored"] = True
        e["last"] = time.time()
        _diff[args[1]] = e
        with _lock:
            _table.pop(args[1], None)
        save_state()
        save_diff()
        print("ignored", args[1])
        return True
    if cmd == "--allow" and len(args) > 1:
        load_state()
        load_allow()
        d = args[1].lower().strip().rstrip(".")
        _allow.add(d)
        save_allow()
        with _lock:
            _table.pop(d, None)
        save_state()
        log("ALLOW %s （人工豁免：suspicious() 直接放行）" % d)
        print("allowed", d)
        return True
    if cmd == "--unallow" and len(args) > 1:
        load_allow()
        d = args[1].lower().strip().rstrip(".")
        _allow.discard(d)
        save_allow()
        log("UNALLOW %s" % d)
        print("unallowed", d)
        return True
    if cmd == "--forget" and len(args) > 1:
        load_state()
        load_bad_ips()
        with _lock:
            _table.pop(args[1], None)
            save_state()
        for ip in list(_bad_ip_domains):
            if args[1] in _bad_ip_domains[ip]:
                _bad_ip_domains[ip] = [x for x in _bad_ip_domains[ip] if x != args[1]]
                e = _ip_info.setdefault(ip, {})
                e["domains"] = sorted(set(x for x in (e.get("domains") or []) if x != args[1]))
                e["regdomains"] = sorted(set(_regdom(x) for x in e["domains"]))
                # P3：按注册域数与规则重判（不再只看域名个数）
                ok, _why = _ip_eval(ip)
                if not ok:
                    _learned_bad_ips.discard(ip)
                    if e.get("status") == "confirmed":
                        e["status"] = "candidate"
                        e["note"] = "forget 后重判不满足: %s" % _why
        save_bad_ips()
        print("forgotten", args[1])
        return True
    return False


if __name__ == "__main__":
    if CN_DOMESTIC_PRIMARY and CN_DOMESTIC_TRUST_B and _load_cn_veto() is None:
        raise RuntimeError("CN trust requires live/last-good/release veto policy")
    # F5：启动即自报发布指纹 ⇒ 事后可核对"这次重启到底跑的是哪份代码" ✓
    log("REL release_id=%s sha256=%s policy=%s verifier_proto=%d"
        % (_RELEASE_ID, _GUARD_SHA256, _POLICY_VERSION, VERIFIER_PROTO))
    log("CN trust split: mode=%s allow_file=%s exc_file=%s"
        % (CN_TRUST_MODE, CN_TRUST_ALLOW_FILE, CN_TRUST_EXC_FILE))
    load_state()
    load_r8_stable()
    load_counters()
    # 名单指标是「当前状态量」，而 load_counters() 会把 PERSIST_SKIP 内的键归零；
    # veto 守卫在模块导入时（早于此处）已载入过名单 ⇒ 这里重放一次，保证 stats.json
    # 里的 cn_typed_*/cn_veto_* 反映本次启动真实生效的名单规模。
    refresh_cn_list_metrics()
    load_bad_ips()
    load_allow()
    if main_cli():
        sys.exit(0)
    load_r5()
    strict_load()
    with _lock:
        _stats["strict_list_size"] = len(_strict)
    try:
        _cn_zone_load()
    except Exception:
        pass
    try:
        _asn_load()
    except Exception:
        pass
    log("STRICT list: %d entries" % len(_strict))
    log("ADOPT dnscrypt 采纳路径: %s（GUARD_DNSCRYPT_ADOPT=%s；FAST_UDP=%s）"
        % ("启用" if DNSCRYPT_ADOPT else "已禁用", os.environ.get("GUARD_DNSCRYPT_ADOPT", "未设"), FAST_UDP))
    threading.Thread(target=verifier).start()
    # 2026-10-10 P34-T（审计 P2"stats 口径混合"）：写一份**伴随元数据**，明确区分
    # "每次重启归零（per-boot）"与"跨重启累计（lifetime）"的计数 —— 纯附加 ✓，不改 stats.json 语义 ✓。
    # 背景：`PERSIST_SKIP` 里 97+ 项每次重启归零，而 `cn_skip`/`cold_overload`/`win_doq` 等是跨重启累计
    # ⇒ 同一文件里两类计数混用会让**任何比率失真** ✗（子代理审计已指出 ✓）。
    try:
        _meta = {"generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                 "boot_ts": _stats.get("boot_ts"), "pid": os.getpid(),
                 # P34-AW（方案任务3）：**发布指纹**与有效配置 —— 两进程必须能自证读的是同一版本 ✓
                 "release_id": _RELEASE_ID,
                 "guard_sha256": _GUARD_SHA256,
                 "policy_version": _POLICY_VERSION,
                 # F5：把 IPC 协议版本一起写盘 ⇒ release_consistency.py 可核验"同发布同协议" ✓
                 "verifier_proto": VERIFIER_PROTO,
                 "effective_deadline": QUERY_DEADLINE,
                 "effective_sync_budget": SYNC_BUDGET,
                 "effective_corrob_timeout": float(os.environ.get("GUARD_CORROB_DOT_TIMEOUT", "2.8")),
                 "active_operators": [x[2] for x in CLEAN_DOT_ALL],
                 "active_operators_count": len(CLEAN_DOT_ALL),
                 "note": "per_boot = PERSIST_SKIP 内、每次重启归零；lifetime = 其余、跨重启累计。\n"
                         "任何比率都必须**同类相除**，或改用两次快照的 delta ✓",
                 "per_boot": sorted(PERSIST_SKIP),
                 "lifetime_sample": sorted([k for k in _stats.keys() if k not in PERSIST_SKIP])[:80]}
        _mp = os.path.join(STATE_DIR, "stats_meta.json")
        _tmp = _mp + ".tmp"
        with open(_tmp, "w") as _f:
            json.dump(_meta, _f, ensure_ascii=False, indent=1, sort_keys=True)
        os.replace(_tmp, _mp)
        log("STATS per_boot=%d 项 / lifetime=%d 项 ⇒ 口径已写入 stats_meta.json ✓"
            % (len(PERSIST_SKIP), len(_stats) - len(set(PERSIST_SKIP) & set(_stats.keys()))))
    except Exception as _e:
        log("stats_meta 写入失败: %s" % _e)
    if AUDIT_ON:
        for _i in range(max(1, AUDIT_WORKERS)):
            threading.Thread(target=_audit_loop, daemon=True).start()
        log("AUDIT 异步审计已启用（抽样 %d%%、并发 %d、队列 %d、%d-%d/分钟）"
            % (AUDIT_PCT, AUDIT_WORKERS, AUDIT_QMAX, AUDIT_MIN_PER_MIN, AUDIT_MAX_PER_MIN))
    else:
        log("AUDIT 异步审计未启用（GUARD_R8_AUDIT 未设）——零行为变化 ✓")
    threading.Thread(target=stats_writer).start()
    # ★ 方案 §5（热命中与有界刷新）：**零新 daemon** ✓ —— 复用本进程的有界结构
    #   + **一个**调度线程 ✓。默认关闭（`GUARD_HOT_REFRESH` 不设 ⇒ `_HOT_ON=False`）⇒
    #   不设等于**零行为变化** ✓（线程照起，但每轮只 sleep 一次 ✓，无 I/O 无发包 ✓）。
    #   为什么线程要无条件起而不按开关决定起不起：让"开/关"只经一次进程内判断生效 ✓，
    #   避免"改了环境变量但忘了重启 ⇒ 行为说不清"✗（关闭时开销 = 1 次 sleep/5s ✓）。
    threading.Thread(target=hot_refresh, daemon=True).start()
    threading.Thread(target=prewarm).start()
    threading.Thread(target=keepalive).start()
    threading.Thread(target=r5_scheduler, daemon=True).start()
    threading.Thread(target=load_cn_nets).start()
    load_diff()
    threading.Thread(target=state_reloader).start()
    threading.Thread(target=probe_udp_server, daemon=True).start()   # 2026-10-09 阶段3：探针专用通道
    threading.Thread(target=tcp_server).start()
    udp_server()
