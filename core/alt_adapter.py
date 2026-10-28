# -*- coding: utf-8 -*-
"""alt_adapter.py —— 「批准的认证 A/alt 适配器」（方案任务2）

方案原文要求：**`ACCEPTED` 只能由批准的认证 A/alt 适配器产生；B=AD0 不能被适配器标成 ACCEPTED** ✓。
本模块就是这两个适配器：

  · `classify_response(wire)` —— **纯函数**：把一份 DNS 应答分类成 `answer_policy.Verdict`：
      AD=1                                    ⇒ SECURE   （本地验证器确认 ✓）
      rc=0 且 AN 段有 A/AAAA 且无 AD           ⇒ ACCEPTED （认证运营方、未签名、策略接受 ✓）
      rc=3（NXDOMAIN）无地址                   ⇒ ACCEPTED （认证运营方的否定 —— 也是"经认证的策略答案" ✓）
      rc=2（SERVFAIL/验证失败）                ⇒ BOGUS    （**不可被任何备用"修复"** ✓）
      其它 / 无法解析                          ⇒ UNKNOWN
    **绝不**把 AD=0 的 B 应答标成 SECURE ✓。

  · `query_alt(name, qtype, timeout)` —— 只查 `127.0.0.1:5357`（任务1 建立的 `unbound-alt`：
    Digitale Gesellschaft + UncensoredDNS，本地做 DNSSEC 验证 ✓），用 `answer_policy.make_answer()`
    生成带 `valid_until` 的 `Answer` ✓。

运行环境 **Python 3.6.8** ⇒ 只用 `NamedTuple`/`Optional`/`struct`/`socket`，无 dataclass、无 `X | None` ✓。
本模块不导入 guard ✓（避免把生产模块当库 import ✗），可离线单测 ✓。
"""
from __future__ import absolute_import

import os
import socket
import struct
import time
from typing import Optional, Tuple

from answer_policy import Answer, Verdict, make_answer

# 任务1 建立的独立加密旁路（只监听回环 ✓）
ALT_ADDR = os.environ.get("GUARD_ALT_ADDR", "127.0.0.1:5357")
ALT_ENABLED = os.environ.get("GUARD_ALT_ENABLE", "1") not in ("0", "no", "false", "")

_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

# ================= 方案 §4：alt readiness 门 + 运输断路器 =================
# §4 第 1 项：ready 记录绑定「容器 ID / 进程启动时间 / 配置哈希 / 最后检查时间」，原子写入；
#             **容器重启或配置变化后旧 ready 立即失效** ✓。
#   · 身份失效（boot_id / container_id / started_at 任一变化）在本模块**读侧**判定 ✓；
#     本模块**不**调 docker / journalctl（纯读小文件 ✓，热路径不能起子进程 ✗）。
#   · `config_hash` 由 `unbound-alt-readiness.py` 每轮重算并写入；哈希一变即把
#     `consecutive_ok` 归零（写侧已做 ✓），读侧再要求字段非空（防御性 ✓）。
# §4 第 2 项：readiness **有效期初值 90 秒**、低频检查 **60 秒** ✓（不是"承诺所有冷域名都快" ✗）。
# §4 第 3 项：已 ready 但**连续运输失败 3 次** ⇒ 断路 **15 秒**，期间只放 **1 个半开试探** ✓；
#             ★ **DNSSEC bogus 不计作运输故障** ✗ —— bogus 是"运输成功且拿到了安全结论" ✓，
#             把它算成故障会让攻击者用 bogus 名把整条 alt 通道关掉 ✗。
ALT_READY_STATE = os.environ.get("GUARD_ALT_READY_STATE", "/run/unbound-alt-ready.json")
ALT_READY_MAX_AGE = float(os.environ.get("GUARD_ALT_READY_MAX_AGE", "90"))
ALT_READY_POLL = float(os.environ.get("GUARD_ALT_READY_POLL", "1.0"))
ALT_SOCKET_TIMEOUT_CAP = float(os.environ.get("GUARD_ALT_SOCKET_CAP", "2.0"))
ALT_TIME_RESERVE = 0.05
ALT_BREAKER_FAILS = int(os.environ.get("GUARD_ALT_BREAKER_FAILS", "3"))
ALT_BREAKER_OPEN = float(os.environ.get("GUARD_ALT_BREAKER_OPEN", "15.0"))
ALT_CONFIG_HASH = os.environ.get("GUARD_ALT_CONFIG_HASH", "")
# ★ **容器重启的廉价读侧信号**（§4 第 1 项"重启后旧 ready 立即失效"）：
#   guard 的热路径不能起 docker 子进程 ✗，而状态文件里的 `container_id`/`started_at`
#   是**写侧**（`unbound-alt-readiness.py` 每 60 s 一次）填的 ⇒ 对**非托管重启**
#   （有人直接 `docker restart`，没走 `dnsguard-alt-restart.sh`）会留下最长 90 s 的
#   陈旧 ready ✗ —— guard 拿它去查一个正在重启的容器 ✗。
#   `/opt/unbound-alt/unbound.pid` 由 unbound 自己在启动时重写：
#     实测 `docker restart` ⇒ (inode, mtime_ns) 都变 ✓；
#     两个容器都**没有** `remote-control` ⇒ 生产不会发生"纯 reload" ⇒ 不会误判 ✓。
#   一次 `os.stat` 即可判定 ⇒ 放进 `read_ready_state()` ✓。
ALT_PIDFILE = os.environ.get("GUARD_ALT_PIDFILE", "/opt/unbound-alt/unbound.pid")
_READY_CACHE = {"t": 0.0, "ready": False, "reason": "uninit"}
_BOOT_ID = {"v": None}
# 运输断路器状态（§4 第 3 项）。`fails` 只统计**运输**失败 ✓；`open_until` 是单调时刻 ✓。
_BREAKER = {"fails": 0, "open_until": 0.0, "half_open": False,
            "trips": 0, "half_ok": 0, "half_fail": 0, "transport_fail": 0, "transport_ok": 0}


def _parse_header(wire):
    """返回 (id, flags, qd, an, ns, ar)；失败返回 None。"""
    if wire is None or len(wire) < 12:
        return None
    try:
        tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", wire[:12])
    except Exception:
        return None
    return tid, flags, qd, an, ns, ar


# ---- 方案 §2-a：由**可信报文**解析真实有效期（替换硬编码 ttl=300.0）✓ ----
_TYPE_CNAME = 5
_TYPE_SOA = 6
_TYPE_RRSIG = 46
_TYPE_NSEC = 47
_TYPE_NSEC3 = 50
_TYPE_OPT = 41
_TYPE_A = 1
_TYPE_AAAA = 28
# 「有地址」的判据（与 count_answers 一致，供否定判定复用）
_ADDR_TYPES = (_TYPE_A, _TYPE_AAAA)

# ★ 修复（§8 最终验收发现，release-17）：**未证明的 CNAME→NODATA 必须可用** ✓。
#   现场缺陷（客户可见）：`vip.115.com` / `learn.chaoxing.com` 的 AAAA 在上游是
#   `rc=0 an=1(CNAME) ns=1(SOA)` —— 即「CNAME 指向的目标没有该类型记录」，属**合法 NODATA** ✓。
#   旧规则把这种形态的 ttl 直接判 0 ⇒ 不是"新鲜答案" ⇒ 策略模式下 A/见证/国内源**全不可采纳**
#   ⇒ guard 合成 SERVFAIL（`FC … Unbound A SERVFAIL`）⇒ 客户端拿不到真实 NODATA ✗。
#   实测（同一批查询、隔离端口回放）：release-9 = rc=0 ✓、release-10 = rc=0（靠
#   `认证源重试成功` 兜底）✓、**release-12/14/16 = rc=2 SERVFAIL ✗** ⇒ 破窗在 release-12（§4 就绪门
#   关掉了兜底重试），而根因是 §2 引入的"仅 CNAME ⇒ ttl=0"。
#   修法（与"无 CNAME 的未证明否定"**完全一致**）：仍标 `proven=False`（诚实 ✓，绝不冒充已证明），
#   但用 RFC 2308 的 `min(SOA.TTL, SOA.MINIMUM)` 作为有效期，并**硬上限** `_NEG_UNPROVEN_TTL_CAP`
#   ⇒ 可采纳、可短期复用，同时**不延长**、不越界 ✓。
#   安全性：该形态 AN 段只有 CNAME、**不含任何 A/AAAA** ⇒ 不可能泄漏或缓存投毒地址 ✓；
#   与既有"无 CNAME 未证明否定用 SOA 有效期"的口径一致（内部一致性修复 ✓）。
_NEG_UNPROVEN_TTL_CAP = max(0.0, float(os.environ.get("GUARD_NEG_UNPROVEN_TTL_CAP", "300")))


def _read_name(d, off):
    """解析（可压缩的）名字 ⇒ (小写名字, 下一偏移)；失败 (None, None)。

    必须支持压缩指针 ✗ —— 上游应答的 Authority 段（SOA/NSEC）几乎总是压缩的，
    不支持会解析失败 ⇒ 有效期退化成 0 ⇒ 否定答案全不入缓存（过度保守，且掩盖真因）。
    """
    labels = []
    n = len(d)
    jumped = False
    next_off = off
    hops = 0
    while True:
        if off >= n or hops > 128:
            return None, None
        ln = d[off]
        if ln == 0:
            off += 1
            if not jumped:
                next_off = off
            break
        if (ln & 0xC0) == 0xC0:
            if off + 1 >= n:
                return None, None
            ptr = ((ln & 0x3F) << 8) | d[off + 1]
            if not jumped:
                next_off = off + 2
            jumped = True
            off = ptr
            hops += 1
            continue
        if ln > 63 or off + 1 + ln > n:
            return None, None
        labels.append(d[off + 1:off + 1 + ln].decode("ascii", "ignore"))
        off += 1 + ln
        if not jumped:
            next_off = off
    return ".".join(labels).lower(), next_off


def _parse_rrs(wire):
    """解析全部 RR ⇒ (header, question, {"an":[...], "ns":[...], "ar":[...]})；失败 None。

    每条 RR 是 dict：`{"name","type","class","ttl","rdata"}` ✓。
    """
    h = _parse_header(wire)
    if h is None:
        return None
    _tid, _flags, qd, an, ns, ar = h
    n = len(wire)
    off = 12
    question = None
    for i in range(qd):
        nm, off = _read_name(wire, off)
        if nm is None or off + 4 > n:
            return None
        if i == 0:
            _qt, _qc = struct.unpack("!HH", wire[off:off + 4])
            question = (nm, _qt, _qc)
        off += 4
    out = {"an": [], "ns": [], "ar": []}
    for sec, cnt in (("an", an), ("ns", ns), ("ar", ar)):
        for _ in range(cnt):
            nm, off = _read_name(wire, off)
            if nm is None or off + 10 > n:
                return (h, question, out)
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", wire[off:off + 10])
            # `off` 现在指向 **TTL 字段**（RR 头 = name + type(2) + class(2) + ttl(4) + rdlen(2)）✓
            _ttl_off = off + 4
            off += 10
            if off + rdlen > n:
                return (h, question, out)
            out[sec].append({"name": nm, "type": rtype, "class": rclass,
                             "ttl": int(ttl), "rdata": wire[off:off + rdlen],
                             # ★ 关键：留下 **rdata 在整报文中的绝对偏移** ✓。
                             # 现场 bug：CNAME 的 RDATA 含**压缩指针**（如 `c0 16`），
                             # 指针值是**相对整报文**的偏移 ✗ —— 只拿 `rdata` 切片去
                             # `_read_name(rdata, 0)` 必然越界 ⇒ 目标名解析失败 ⇒
                             # CNAME 链只走 1 跳 ⇒ 误判 `incomplete` ⇒ 有效期 0 ✗。
                             # 实测受害：www.baidu.com / www.taobao.com / www.bilibili.com
                             #（国内 CDN 主流形态，链上目标名都被压缩 ✓）。
                             "rd_off": off,
                             # TTL 字段的**绝对偏移** —— 供 `age_wire()` 原地改写 ✓
                             #（4 字节定长 ⇒ 原地改写不移动任何压缩指针 ✓）。
                             "ttl_off": _ttl_off})
            off += rdlen
    return (h, question, out)



def is_empty_nxdomain_one_shot_candidate(wire, qname, qtype, query_id=None):
    """Recognize one exact, non-cacheable empty NXDOMAIN candidate from trusted CN B.

    This validates wire shape and rejects EDE Stale Answer and Stale NXDOMAIN Answer (info-codes 3 and 19); it does
    not prove freshness by itself. The caller must gate it on the explicit trust
    switch and only enable it after Unbound B emits stale EDE markers.
    """
    if not wire or len(wire) < 12 or query_id is None or not qname:
        return False
    try:
        if isinstance(query_id, int):
            expected_id = struct.pack("!H", int(query_id) & 0xffff)
        else:
            expected_id = bytes(query_id)
        if len(expected_id) != 2 or bytes(wire[:2]) != expected_id:
            return False
        parsed = _parse_rrs(wire)
        if parsed is None:
            return False
        h, question, sections = parsed
        _tid, flags, qd, an, ns, ar = h
        if (not (flags & 0x8000) or (flags & 0x7800) or (flags & 0x0200)
                or (flags & 0x000f) != 3):
            return False
        if qd != 1 or an != 0 or ns != 0 or not question:
            return False
        _qn, _qt, _qc = question
        if (_qn != str(qname).lower().rstrip(".") or int(_qt) != int(qtype)
                or int(_qc) != 1):
            return False
        for sec, count in (("an", an), ("ns", ns), ("ar", ar)):
            if len(sections.get(sec) or []) != count:
                return False

        # Require a complete DNS message; _parse_rrs intentionally permits callers
        # to inspect partial responses, which is too permissive for this fast path.
        off = 12
        for _ in range(qd):
            _nm, off = _read_name(wire, off)
            if _nm is None or off + 4 > len(wire):
                return False
            off += 4
        for count in (an, ns, ar):
            for _ in range(count):
                _nm, off = _read_name(wire, off)
                if _nm is None or off + 10 > len(wire):
                    return False
                rdlen = struct.unpack("!H", wire[off + 8:off + 10])[0]
                off += 10
                if off + rdlen > len(wire):
                    return False
                off += rdlen
        if off != len(wire):
            return False

        # A request with EDNS must return one OPT so a configured Unbound B can
        # mark stale data. Any other additional RR is outside this narrow case.
        additionals = sections.get("ar") or []
        if len(additionals) != 1:
            return False
        opt = additionals[0]
        if int(opt.get("type") or 0) != 41 or opt.get("name") != "":
            return False
        data = bytes(opt.get("rdata") or b"")
        pos = 0
        while pos < len(data):
            if pos + 4 > len(data):
                return False
            code, size = struct.unpack("!HH", data[pos:pos + 4])
            pos += 4
            if pos + size > len(data):
                return False
            if code == 15:
                if size < 2:
                    return False
                info_code = struct.unpack("!H", data[pos:pos + 2])[0]
                if info_code in (3, 19):   # Stale Answer / Stale NXDOMAIN Answer
                    return False
            pos += size
        return True
    except Exception:
        return False

def _wire_name_key(wire, off):
    labels, seen, end, length = [], set(), None, 1
    for _ in range(128):
        if off >= len(wire) or off in seen:
            return None, None
        seen.add(off)
        size = wire[off]
        if size == 0:
            return tuple(labels), end if end is not None else off+1
        if size & 0xc0 == 0xc0:
            if off+1 >= len(wire):
                return None, None
            if end is None:
                end = off+2
            off = ((size & 63)<<8) | wire[off+1]
            continue
        if size > 63 or off+1+size > len(wire):
            return None, None
        length += size+1
        if length > 255:
            return None, None
        labels.append(bytes(wire[off+1:off+1+size]).lower())
        off += size+1
    return None, None


def response_matches(query, response):
    """Bind a complete response to one question; TC is only a TCP-retry signal."""
    try:
        qh, rh = _parse_header(query), _parse_header(response)
        if not qh or not rh or qh[2] != 1 or rh[2] != 1:
            return False
        if rh[0] != qh[0] or not (rh[1] & 0x8000) or (rh[1] & 0x7800) != (qh[1] & 0x7800):
            return False
        qn, qo = _wire_name_key(query, 12)
        rn, ro = _wire_name_key(response, 12)
        if qn is None or rn is None or qn != rn:
            return False
        if query[qo:qo+4] != response[ro:ro+4] or len(query[qo:qo+4]) != 4:
            return False
        if rh[1] & 0x0200:
            return True
        off = ro + 4
        for count in rh[3:]:
            for _ in range(count):
                nm, off = _read_name(response, off)
                if nm is None or off + 10 > len(response):
                    return False
                size = struct.unpack("!H", response[off+8:off+10])[0]
                off += 10 + size
                if off > len(response):
                    return False
        return off == len(response)
    except Exception:
        return False


def _read_exact(sock, count, deadline=None):
    data = b""
    while len(data) < count:
        if deadline is not None:
            left = deadline - time.monotonic()
            if left <= 0:
                raise IOError("DNS frame deadline")
            sock.settimeout(left)
        part = sock.recv(count-len(data))
        if not part:
            raise IOError("short DNS frame")
        data += part
    return data


def exchange_udp(server, query, timeout):
    """Connected peer plus question validation, bounded by one monotonic deadline."""
    deadline = time.monotonic() + max(0.0, float(timeout))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(server)
        sock.send(query)
        for _ in range(64):
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            sock.settimeout(left)
            response = sock.recv(65535)
            if not response_matches(query, response):
                continue
            if struct.unpack("!H", response[2:4])[0] & 0x0200:
                left = deadline - time.monotonic()
                if left <= 0:
                    return None
                with socket.create_connection(server, timeout=left) as tcp:
                    tcp.sendall(struct.pack("!H", len(query)) + query)
                    response = _read_exact(tcp, struct.unpack("!H", _read_exact(tcp,2,deadline))[0],deadline)
                if not response_matches(query,response) or response[2] & 2:
                    return None
            return response
    return None


def dnssec_bogus(wire):
    """Only explicit DNSSEC validation EDEs (6..12), never bare SERVFAIL."""
    try:
        parsed = _parse_rrs(wire)
        if parsed is None or parsed[0][1] & 15 != 2:
            return False
        for rr in parsed[2]["ar"]:
            if rr["type"] != 41:
                continue
            data, pos = rr["rdata"], 0
            while pos + 4 <= len(data):
                code, size = struct.unpack("!HH", data[pos:pos+4])
                pos += 4
                if pos+size > len(data):
                    return False
                if code == 15 and size >= 2 and struct.unpack("!H",data[pos:pos+2])[0] in range(6,13):
                    return True
                pos += size
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# §3.2 统一 stale 出口语义（2026-10-15）
#
# 背景：A/B 启用了 `serve-expired`，过期答案以 **TTL=0** 下发；Unbound B 另外用
#       EDE 明确标注（3 = Stale Answer，19 = Stale NXDOMAIN Answer）。
#       审计 §3.2 指出：`_finalize_return()` 的 SECURE/ACCEPTED 快路未做 freshness
#       判定 ⇒ "所有出口严格 freshness 校验"的注释不成立，且 TTL=0/AD=1 的包可出口。
#
# 统一策略（S1/S2/S3，实现分两处：本函数负责**识别**，`guard._finalize_return()`
# 负责**决策与记账**——含终局快路，见 `guard._stale_of()` / `guard._stale_note()`）：
#   S1 **显式 stale**（EDE 3/19）⇒ 允许出口（它可能是当下唯一可用答案，且过期不等于
#      伪造 ✓），但**不写准入缓存** ✗、**不延长 TTL** ✗、原样下发（含 AD —— AD 表示
#      "最近一次验证通过"，RFC 8767 §5.3 允许对已验证过的 stale 数据保留 AD ✓）。
#   S2 **隐式零 TTL**（无 EDE，最小 TTL==0）⇒ 按普通答案处理：不拒答 ✓，且因
#      `ttl<=0 不入缓存`（F1）天然不会被复用 ✓。
#   S3 **统一**：所有出口路径（可采纳快路 + 终局结论 + 备用救回）共用同一识别与记账，
#      计数 `stale_out` / `stale_out_<kind>` 可在 stats.json 观察 ✓。
#
# 明确**不做**的事：不因 TTL==0 笼统拒答 ✗（审计报告明确要求）；不改写下发字节 ✗
# （除 qid 外逐字节不变，与 P1-2 不变式一致）。
# ---------------------------------------------------------------------------
STALE_EDE_CODES = (3, 19)


def stale_flags(wire):
    """§3.2：返回 `(is_stale, ede_code, min_ttl)`。

    is_stale —— OPT 的 EDE info-code ∈ {3, 19}（显式 stale）✓
    ede_code —— 命中的 info-code（未命中 0）
    min_ttl  —— 除 OPT 外所有 RR 的最小 TTL（无法解析 ⇒ -1，与 0 区分，避免误判为"零 TTL 正常答案"）
    """
    _ede = 0
    try:
        parsed = _parse_rrs(wire)
    except Exception:
        return (False, 0, -1)
    if parsed is None:
        return (False, 0, -1)
    try:
        for rr in parsed[2]["ar"]:
            if rr["type"] != 41:
                continue
            data, pos = rr["rdata"], 0
            while pos + 4 <= len(data):
                code, size = struct.unpack("!HH", data[pos:pos + 4])
                pos += 4
                if pos + size > len(data):
                    break
                if code == 15 and size >= 2:
                    _info = struct.unpack("!H", data[pos:pos + 2])[0]
                    if _info in STALE_EDE_CODES:
                        _ede = _info
                pos += size
    except Exception:
        return (False, 0, -1)
    return (_ede != 0), _ede, min_rr_ttl(wire)


def age_wire(wire, elapsed, now=None, max_ttl=None):
    """方案 §2 第 50 行：重放缓存答案时**逐 RR 扣除经过秒数** ✓。

    · 处理 Answer / Authority / Additional **三段** ✓；
    · **OPT（type 41）不递减** ✗ —— 它的 "TTL" 字段装的是扩展 rcode/版本/flags，
      不是寿命（RFC 6891 §6.1.3）；当普通 TTL 扣减会破坏 EDNS0 语义 ✗；
    · **原地改写**（4 字节定长）⇒ 报文长度不变 ⇒ 所有压缩指针保持逐字节有效 ✓
      （绝不用"解析再重新序列化"的做法 —— 那会把压缩名字展开或错位 ✗）；
    · 扣到 ≤0 保留 0 ✓（**绝不下溢成负数** ✗）。
    无法解析的报文**原样返回** ✓（宁可不老化，也不产出畸形报文 ✗）。
    """
    if not wire or len(wire) < 12:
        return wire
    try:
        _el = int(float(elapsed))
    except Exception:
        return wire
    if _el <= 0 and max_ttl is None:
        return wire
    try:
        _h, _q, _out = _parse_rrs(wire)
    except Exception:
        return wire
    if _h is None:
        return wire
    _buf = bytearray(wire)
    _n = len(wire)
    _changed = 0
    for _sec in ("an", "ns", "ar"):
        for _rr in _out.get(_sec) or []:
            if _rr.get("type") == _TYPE_OPT:
                continue                     # OPT 不是寿命字段 ✗
            _to = _rr.get("ttl_off")
            if _to is None or _to + 4 > _n:
                continue
            _new = int(_rr.get("ttl") or 0) - _el
            if _new < 0:
                _new = 0                     # 绝不下溢 ✗
            if max_ttl is not None:
                _new = min(_new, max(0, int(max_ttl)))
            struct.pack_into("!I", _buf, _to, _new)
            _changed += 1
    if not _changed:
        return wire
    return bytes(_buf)


def min_rr_ttl(wire):
    """报文里**除 OPT 外**所有 RR 的最小剩余 TTL ✓（无法解析 ⇒ 0，即"不可复用" ✓）。"""
    try:
        _h, _q, _out = _parse_rrs(wire)
    except Exception:
        return 0
    if _h is None:
        return 0
    _v = []
    for _sec in ("an", "ns", "ar"):
        for _rr in _out.get(_sec) or []:
            if _rr.get("type") == _TYPE_OPT:
                continue
            _v.append(int(_rr.get("ttl") or 0))
    return min(_v) if _v else 0


def _cname_target(wire, rr):
    """取 CNAME RR 的目标名 —— **必须用整报文 + 绝对偏移** ✓（见 `rd_off` 注释）。

    回退：极少数上游可能把 RDATA 里的名字**不压缩**写成自包含形式 ⇒ 此时绝对偏移法
    同样正确（`_read_name` 从该处开始读完整名字 ✓）；若绝对偏移法失败，再退到切片法
    以兜住"rdata 自成一体"的异常实现 ✓。
    """
    off = rr.get("rd_off")
    if off is not None:
        tgt, _n = _read_name(wire, off)
        if tgt:
            return tgt
    tgt, _n = _read_name(rr.get("rdata") or b"", 0)
    return tgt


def _soa_minimum(wire, rr=None):
    """从 SOA 取 MINIMUM 字段（RFC 2308 §5 的否定缓存寿命依据）✓。

    签名兼容：老调用点传的是 `rdata` 字节 ✗；新调用点传 `(wire, rr)` ✓。
    两种都要认 —— SOA 的 MNAME/RNAME 在 Authority 段里**同样常被压缩** ✗，
    只拿 rdata 切片解析名字会失败 ⇒ MINIMUM 取不到 ⇒ 否定有效期凭空归零 ✗
    （与 CNAME 链同一个根因 ✓）。
    """
    if rr is None:
        d = wire or b""                       # 兼容：直接给了 rdata 切片
        base = 0
    else:
        d = wire
        base = rr.get("rd_off")
        if base is None:                      # 无绝对偏移（老结构）⇒ 退化到切片 ✓
            d = rr.get("rdata") or b""
            base = 0
    off = base
    for _ in range(2):                        # 跳过 MNAME / RNAME
        _nm, off = _read_name(d, off)
        if _nm is None:
            return None
    if off + 20 > len(d):
        return None
    # SERIAL/REFRESH/RETRY/EXPIRE/MINIMUM
    _serial, _refresh, _retry, _expire, minimum = struct.unpack("!IIIII", d[off:off + 20])
    return int(minimum)


def _sig_exps(rdata):
    """从 RRSIG rdata 取 (type_covered, 签名到期绝对秒)。失败 (None, None)。"""
    d = rdata or b""
    if len(d) < 18:
        return (None, None)
    try:
        covered = struct.unpack("!H", d[0:2])[0]
        exp = struct.unpack("!I", d[8:12])[0]
    except Exception:
        return (None, None)
    return (covered, exp)


def _rrsig_remaining(resp, used_type, now):
    """覆盖 `used_type` 的 RRSIG **最短剩余有效期**（秒）；无签名 ⇒ None ✓。

    方案 §2-a：「对使用的 DNSSEC 证明检查签名失效时间」✓ —— 只算真正被用过的那类，
    不去看 Additional 里无关的签名 ✗。
    """
    best = None
    hit = False
    _h, _q, secs = resp
    for sec in ("an", "ns"):
        for rr in secs.get(sec) or []:
            if rr["type"] != _TYPE_RRSIG:
                continue
            covered, exp = _sig_exps(rr["rdata"])
            if covered is None:
                continue
            if used_type is not None and covered != used_type:
                continue
            hit = True
            rem = float(exp) - float(now)
            if best is None or rem < best:
                best = rem
    return best if hit else None


def rrset_validity(wire, now=None):
    """方案 §2-a：**由可信报文求出真实有效期** ✓ ⇒ `(ttl_seconds, detail)`。

    正向：沿 CNAME 链取**整条链**（CNAME + 最终 RRset）的最小 TTL ✓，再与
    「覆盖最终类型的 RRSIG 剩余有效期」取最小 ✓。

    否定：用 Authority 段 SOA 的 `min(SOA.TTL, SOA.MINIMUM)`（RFC 2308）✓，
    并给出 `proven` 标记 —— **仅有 CNAME 不足以认定已证明 NODATA** ✓，
    必须另有 NSEC/NSEC3 或覆盖 SOA 的 RRSIG 才算已证明 ✓。

    ★ release-17 修正（§8 最终验收现场缺陷）：**"未证明"不等于"不可用"** ✗。
      `proven=False` 只表示"缺少 DNSSEC 证明"✓；有效期仍按 SOA 求（RFC 2308）✓，
      但加硬上限 `_NEG_UNPROVEN_TTL_CAP`（默认 300s）⇒ 可采纳、可短复用、**绝不延长** ✓。
      旧行为（仅 CNAME 时 ttl 直接判 0）会让合法的 CNAME→NODATA 变成 SERVFAIL（客户可见 ✗），
      与"无 CNAME 的未证明否定照样用 SOA 有效期"自相矛盾 ✗。

    `ttl_seconds == 0` ⇒ 调用方**不得入缓存**、**不得延长** ✗（零 TTL / 已过期 /
    无法解析出有效期一律按 0 处理，绝不补一个固定值 ✗）。
    """
    now = float(now if now is not None else time.time())
    resp = _parse_rrs(wire)
    if resp is None:
        return 0.0, {"kind": "unparseable", "ttl": 0.0, "proven": False, "reason": "parse"}
    h, question, secs = resp
    flags = h[1]
    rcode = flags & 0xF
    ad = bool(flags & 0x20)
    if rcode == 2:
        return 0.0, {"kind": "bogus" if dnssec_bogus(wire) else "transport",
                     "ttl": 0.0, "proven": False, "reason": "servfail"}
    qname, qtype, _qclass = question if question else (None, None, None)
    ans = secs.get("an") or []
    ns = secs.get("ns") or []

    has_addr = any(r["type"] in _ADDR_TYPES for r in ans)
    cnames = [r for r in ans if r["type"] == _TYPE_CNAME]
    # 终端记录：AN 段里**真正回答了 qtype** 的那条（CNAME 查询另有判据 ✓）。
    # 现场修正：原判据只看「有没有地址」，于是 qtype=A 而 AN 段只有 CNAME 时被误判成正向 ✗，
    # 走进链式循环后**用 CNAME 的 TTL 冒充了最终 RRset 的 TTL** ✗（凭空给了一个有效期）。
    has_term = (bool(cnames) if qtype == _TYPE_CNAME
                else any(r["type"] == qtype for r in ans))

    # ---- 否定分支：NXDOMAIN，或 AN 段没有回答 qtype 的终端记录 ----
    if rcode == 3 or not has_term:
        soa = [r for r in ns if r["type"] == _TYPE_SOA]
        nsec = [r for r in ns if r["type"] in (_TYPE_NSEC, _TYPE_NSEC3)]
        _sig_rem = _rrsig_remaining(resp, _TYPE_SOA if soa else None, now)
        proven = bool(nsec) or (_sig_rem is not None)
        detail = {"kind": "negative", "proven": proven, "ad": ad,
                  "n_nsec": len(nsec), "has_soa": bool(soa),
                  "sig_rem": _sig_rem}
        if not soa:
            detail["ttl"] = 0.0
            # 区分两种"没有终态记录"：
            #   · 有 CNAME 但**连 SOA 都没有** ⇒ 这是**残缺链路** ✗（既不是正向也不是否定 ✓）
            #   · 无 CNAME 也无 SOA ⇒ 无 SOA 的否定（无法定有效期 ✓）
            # 语义差别只影响日志与分桶；两者都**不给有效期** ✓（宁可不缓存 ✓）。
            if cnames:
                detail["kind"] = "incomplete"
                detail["reason"] = "chain_no_target_no_soa"
            else:
                detail["reason"] = "no_soa"
            return 0.0, detail
        soa_min = _soa_minimum(wire, soa[0])
        soa_ttl = min(int(soa[0]["ttl"]), soa_min or 0)
        soa_ttl = max(0, soa_ttl)
        ttl = float(soa_ttl)
        if _sig_rem is not None:
            ttl = min(ttl, max(0.0, _sig_rem))
        detail["soa_min"] = soa_min
        detail["soa_ttl"] = soa_ttl
        # release-17：仅 CNAME、无证明 ⇒ 仍标 proven=False（诚实 ✓）但**给出 SOA 有效期并加上限** ✓
        # （旧行为 ttl=0 ⇒ 合法 NODATA 被合成 SERVFAIL，客户可见 ✗）。
        if cnames and not proven:
            detail["kind"] = "negative_unproven"
            if ttl > 0.0 and _NEG_UNPROVEN_TTL_CAP > 0.0:
                capped = min(float(ttl), _NEG_UNPROVEN_TTL_CAP)
                detail["reason"] = "cname_only_soa_ttl"
                detail["cap"] = _NEG_UNPROVEN_TTL_CAP
                detail["capped"] = bool(capped < float(ttl))
                detail["ttl"] = capped
                return capped, detail
            detail["reason"] = "cname_only_no_proof"
            detail["ttl"] = 0.0
            return 0.0, detail
        detail["ttl"] = ttl
        return ttl, detail

    # ---- 正向分支：沿 CNAME 链走，取整条链的最小 TTL ----
    if not ans:
        return 0.0, {"kind": "empty", "ttl": 0.0, "proven": False, "reason": "no_answer"}
    by_name = {}
    for r in ans:
        by_name.setdefault(r["name"], []).append(r)
    chain = []
    cur = qname
    used_type = qtype
    guard_hops = 0
    ttls = []
    seen = set()
    got_terminal = False
    while cur is not None and guard_hops < 16:
        guard_hops += 1
        if cur in seen:
            break
        seen.add(cur)
        rrs = by_name.get(cur) or []
        nxt = [r for r in rrs if r["type"] == _TYPE_CNAME]
        fin = [r for r in rrs if r["type"] == used_type and r["type"] != _TYPE_CNAME]
        if fin:
            ttls.extend(int(r["ttl"]) for r in fin)
            chain.append(cur)
            got_terminal = True
            break
        if used_type == _TYPE_CNAME and nxt:
            ttls.extend(int(r["ttl"]) for r in nxt)
            chain.append(cur)
            got_terminal = True
            break
        if nxt:
            ttls.append(int(nxt[0]["ttl"]))
            chain.append(cur)
            # ★ 目标名必须按**整报文绝对偏移**解析 ⇒ 支持压缩指针 ✓（详见 `_cname_target`）
            tname = _cname_target(wire, nxt[0])
            if not tname:
                # 目标名解析不出 ⇒ 链**不可信** ⇒ 宁可给 0 有效期，绝不猜 ✗
                return 0.0, {"kind": "incomplete", "ttl": 0.0, "proven": False,
                             "reason": "cname_target_unresolved", "chain": chain}
            cur = tname
            continue
        break
    if not ttls or not got_terminal:
        # 有 CNAME 但走不到目标类型 ⇒ **不得凭空给有效期** ✗（宁可不缓存 ✓）
        return 0.0, {"kind": "incomplete", "ttl": 0.0, "proven": False,
                     "reason": "chain_no_target", "chain": chain}
    ttl = float(min(ttls))
    _sig_rem = _rrsig_remaining(resp, used_type, now)
    detail = {"kind": "forward", "proven": (_sig_rem is not None) or ad, "ad": ad,
              "rrset_ttl": min(ttls), "chain": chain, "sig_rem": _sig_rem,
              "used_type": used_type}
    if _sig_rem is not None:
        ttl = min(ttl, max(0.0, _sig_rem))
    detail["ttl"] = ttl
    if ttl <= 0:
        detail["reason"] = "expired_or_zero"
    return ttl, detail


def _skip_name(d, off):
    """跳过（可压缩的）名字，返回新偏移或 None。"""
    n = len(d)
    while True:
        if off >= n:
            return None
        ln = d[off]
        if ln == 0:
            return off + 1
        if (ln & 0xC0) == 0xC0:
            return off + 2 if off + 1 < n else None
        off += 1 + ln


def build_query(name, qtype=1, qid=None):
    """**自带**的标准查询构造（含 EDNS0 DO=1）—— 不依赖 verify_ip ✓。

    为什么自带：`verify_ip` 会在模块顶层 `import guard` ✗，在发布/旁路进程里
    那等于把 guard 当库再导入一份（带独立状态与副作用 ✗）。方案也明确禁止该做法 ✓。
    """
    if qid is None:
        qid = (int(time.time() * 1000) & 0xFFFF) or 1
    try:
        qn = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split(".") if p) + b"\x00"
    except Exception:
        return None
    if not qn:
        return None
    hdr = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 1)      # RD=1 / CD=0 ✓
    opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0x8000, 0)   # EDNS0 DO=1 ✓
    return hdr + qn + struct.pack("!HH", qtype, 1) + opt


def count_answers(wire):
    """粗略统计 AN 段里的 A/AAAA 记录数（足够判"是否给出地址"✓，不追求完整解析）。"""
    return count_answers_of(wire, None)


def count_answers_of(wire, qtype=None):
    """按**被问类型**统计 AN 段里"确实回答了该问题"的记录数 ✓。

    ★ 方案 §3 第 74 行：**禁止**用"必须有 A/AAAA 地址"当作**所有类型**的成功判据 ✗。
      现场后果（旧写法）：`count_answers()` 只认 type∈(1,28) ✗
        · `qtype=65`（HTTPS / SVCB）的**正常正向应答**被算成 0 条 ⇒ 落进
          `rcode==0 and naddr==0` ⇒ 被标 ACCEPTED 的同时**判据是假的** ✗；
        · `qtype=15`（MX）/16（TXT）/2（NS）同理 ⇒ "该类型有答案"这件事在指标里看不见 ✗。
      修法：按 `qtype` 统计**被问类型**的记录数 ✓；同时单独给出 CNAME 数 ✓
      （CNAME 链是合法中间态，既不是"有终态答案"也不是"否定"⇒ 必须能被区分 ✗）。
      `qtype=None` 时退化为旧口径（A/AAAA）✓ ⇒ 既有调用点行为不变 ✓。

    返回 `(n_qtype, n_cname)`：`n_qtype` = AN 段里 type==qtype 的条数；
    `n_cname` = AN 段里 type==5 的条数。
    """
    h = _parse_header(wire)
    if not h:
        return (0, 0) if qtype is not None else 0
    _tid, _flags, qd, an, _ns, _ar = h
    off = 12
    for _ in range(qd):
        off = _skip_name(wire, off)
        if off is None:
            return (0, 0) if qtype is not None else 0
        off += 4
    nq = 0
    ncn = 0
    for _ in range(an):
        off = _skip_name(wire, off)
        if off is None or off + 10 > len(wire):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", wire[off:off + 10])
        off += 10 + rdlen
        if qtype is None:
            if rtype in (1, 28):
                nq += 1
        else:
            if rtype == qtype:
                nq += 1
            elif rtype == _TYPE_CNAME:
                ncn += 1
    if qtype is None:
        return nq
    return (nq, ncn)


def _qtype_of(wire):
    """从应答**自身的 question 段**取 qtype（拿不到返回 None）✓。"""
    h = _parse_header(wire)
    if h is None:
        return None
    _tid, _flags, qd, _an, _ns, _ar = h
    if qd < 1:
        return None
    off = _skip_name(wire, 12)
    if off is None or off + 4 > len(wire):
        return None
    return struct.unpack("!H", wire[off:off + 2])[0]


def classify_kind(wire, qtype=None):
    """按**被问 RR 类型**判定应答形态 ✓ —— 方案 §3 第 74 行。

    ★ 旧写法的真实缺陷（本函数的立意）：判"成功"的唯一依据是 `count_answers()`，
      它只数 type∈(1,28) ✗。于是 `qtype=65`（HTTPS/SVCB）、`15`（MX）、`16`（TXT）、
      `2`（NS）的**正常正向应答**一律 `naddr==0` ⇒ 被塞进"裸 NODATA 采纳"分支 ⇒
      **"拿到了真答案"和"域名确实没有该记录"在指标里完全不可分辨** ✗。
      方案第 74 行要求按 RR 类型解析、禁止拿"必须有 A/AAAA 地址"当所有类型的成功判据 ✓。

    ★ 2026-10-11 新增 `"bare"`（**裸空壳**）—— §5 验收期现场定位的既有缺陷（非 §5 引入）：
      本机 UDP 转发器 `127.0.0.1:5533` 在并发下偶发把**查询原样回显**成
      `flags 0x0100→0x8180` 的 `rc=0 an=0 ns=0 ar=1`（唯一差别是 flags）✗，
      而常连接池也曾出现 qid 不符的陈旧帧 ✗。这类"**没有任何证据的空 NOERROR**"
      （`an=0` 且 `ns=0` 且 `ad=0`）不能被当成"认证源的否定结论 ⇒ 采纳" ✓。
      **为什么不会误伤 P34-BM**：实测所有真 NODATA 都带 SOA（`ns≥1`，权威段 type 6）
      或 `ad=1` —— 本域 apex 的 TXT/MX/SRV 均为 `ns=1 [6]`、`github.com` SRV `ns=1 [6]`、
      `isc.org`/`one.one.one.one` MX 为 `ns=4 [6,46,47,46] ad=1` ⇒ `ns==0 且 ad==0` 的
      "零证据空壳"在真实解析器上**不存在** ✓。

    返回：
      `"positive"` —— AN 段含**被问类型**的终态记录 ✓
      `"cname"`    —— AN 段只有 CNAME 链，没有终态记录（合法中间态，既非正也非否定）✓
      `"negative"` —— 无终态也无 CNAME，但**带了否定证据**（权威段有 RR / AD=1）✓
      `"bare"`     —— 无终态、无 CNAME、**且无任何否定证据**（零证据空壳，不可当结论）✗
      `"bogus"`    —— rcode==2（验证失败/服务失败，安全结论）✓
      `"unknown"`  —— 报文无法解析 ✓
    """
    h = _parse_header(wire)
    if h is None:
        return "unknown"
    _tid, flags, _qd, _an, _ns, _ar = h
    if (flags & 0xF) == 2:
        return "bogus" if dnssec_bogus(wire) else "transport"
    ad = bool(flags & 0x20)
    qt = qtype if qtype is not None else _qtype_of(wire)
    if qt is None:
        # 拿不到 qtype ⇒ 退化为旧口径（A/AAAA）；只为兼容，不承担新判定 ✓
        return "positive" if count_answers(wire) > 0 else "negative"
    nq, ncn = count_answers_of(wire, qt)
    if nq > 0:
        return "positive"
    if ncn > 0:
        return "cname"
    if (flags & 0xF) == 0 and _ns == 0 and not ad:
        return "bare"
    return "negative"


def is_conclusive(wire):
    """该字节是否**足以当作一条结论**（正向答案、CNAME 链、或带证据的否定）✓。

    供干净通道竞速与缓存门使用（§5 验收期既有缺陷的根因）：竞速里只有
    "可结论"的应答才配赢过别的通道，也才配被写进 `_cache` ✓；
    零证据空壳一律**不赢、不缓存** ✗（否则会被复用 10–600s ⇒ 60 秒的持续错误回答 ✗）。
    """
    k = classify_kind(wire)
    return k in ("positive", "cname", "negative")


_LOCAL_VERIFIED_SOURCES = ("local-a", "local-alt")


def _signature_state(wire, now=None):
    """N3（2026-10-16）：返回 `(state, rem)`。

    `state` ∈ `signed` / `signed_expired` / `unsigned` / `unparseable`；
    `rem` = 覆盖**被问类型**的 RRSIG 最短剩余秒（无签名 ⇒ None ✓）。
    """
    now = float(now if now is not None else time.time())
    try:
        resp = _parse_rrs(wire)
    except Exception:
        resp = None
    if resp is None:
        return "unparseable", None
    _h, question, _secs = resp
    _qname, qtype, _qclass = question if question else (None, None, None)
    try:
        rem = _rrsig_remaining(resp, qtype, now)
    except Exception:
        rem = None
    if rem is None:
        return "unsigned", None
    return ("signed" if rem > 0.0 else "signed_expired"), rem


AD_GRADE = {"local_ad": 0, "signed": 0, "ad_declared": 0, "sig_expired": 0}


def ad_grade(wire, source, now=None):
    """N3 精细分档：**只在报文 AD=1 时**才产生档位 ⇒ 返回 `(Verdict, why)`。

    why 四档（"运营方声明"与"本地/签名凭据"分开 ✓）：
      · `local_ad`    —— 本地验证通道（`local-a`/`local-alt`，我们自己的 Unbound）：
                          AD 位由**本地 DNSSEC 验证**产生 ⇒ `SECURE` ✓；
      · `signed`      —— 第三方通道，但报文带**覆盖被问类型且未过期**的 RRSIG ⇒ `SECURE` ✓；
      · `sig_expired` —— 有 RRSIG 但已过期 ⇒ `ACCEPTED` ✗（不延长、不按 900s 计）；
      · `ad_declared` —— 第三方通道仅凭 AD 位自称、报文里没有任何签名 ⇒ `ACCEPTED` ✗（核心改动）。

    非分档情形（档位返回 `None`，调用方**不得**计入 AD 分档统计 ✓）：
      · `ad_zero`     —— 报文 AD=0：本函数不适用（AD=0 的正常答案在 `classify_response()`
                          里走 positive/negative 分支 ⇒ ACCEPTED，与"仅凭 AD 声明"无关）；
      · `unparseable` —— 报文无法解析。

    （2026-10-16 修正：此前调用方若无条件调用本函数，会把 AD=0 的**普通** accepted
      答案误算成 `ad_declared` ⇒ 生产出现"仅凭 AD 声明"的假计数；现在由本函数自守。）
    """
    _h = _parse_header(wire)
    if _h is None:
        return None, "unparseable"
    if not (_h[1] & 0x20):
        return None, "ad_zero"
    if source in _LOCAL_VERIFIED_SOURCES:
        return Verdict.SECURE, "local_ad"
    st, _rem = _signature_state(wire, now)
    if st == "signed":
        return Verdict.SECURE, "signed"
    if st == "signed_expired":
        return Verdict.ACCEPTED, "sig_expired"
    return Verdict.ACCEPTED, "ad_declared"


def classify_response(wire, source, ttl=0.0, now=None, policy_version=None):
    """纯分类（可离线单测 ✓）。返回 `Answer` 或 None（无法解析）。

    `source` 必须是 `local-a` / `local-alt`（**绝不接受 local-b 标成 SECURE/ACCEPTED** ✓）。
    """
    h = _parse_header(wire)
    if h is None:
        return None
    _tid, flags, _qd, _an, _ns, _ar = h
    rcode = flags & 0xF
    ad = bool(flags & 0x20)
    # 方案 §3 第 74 行：按**被问类型**判定形态 ✓（旧代码只认 A/AAAA ✗）。
    _kind = classify_kind(wire)
    if source == "local-b":
        # B 的应答**只能**当见证：无论内容如何都不产生可采纳裁定 ✓
        return Answer(None, "local-b", Verdict.UNKNOWN, 0.0,
                      policy_version or "b-witness")
    if rcode == 2:
        v = Verdict.BOGUS if dnssec_bogus(wire) else Verdict.TRANSPORT
    elif ad:
        # N3 精细分档（2026-10-16）：AD 位只是**运营方声明**，不是本地可验凭据 ⇒
        # 档位按【通道可信度 + 报文里的签名证据】定 ✓（旧行为"AD=1 一律 SECURE"已废止）。
        v, _ad_why = ad_grade(wire, source, now)
        if v is None:
            # 防御：本分支已确知 AD=1 ⇒ 理论不会走到；真走到就按最保守档处理 ✓
            v, _ad_why = Verdict.ACCEPTED, "ad_declared"
        try:
            AD_GRADE[_ad_why] = AD_GRADE.get(_ad_why, 0) + 1
        except Exception:
            pass
    elif rcode == 0 and _kind in ("positive", "cname"):
        # `positive` = 被问类型有终态记录；`cname` = 只给了 CNAME 链（合法中间态）✓
        # ⇒ 两者都是"认证源确实回答了这个 qtype"，采纳 ✓（判据按类型，不再按 A/AAAA ✓）
        v = Verdict.ACCEPTED
    elif rcode == 3 and _kind != "positive":
        # 认证运营方的否定 ✓（NXDOMAIN 带 CNAME 链也是合法否定 ⇒ `cname` 一并接受 ✓；
        # 只有"NXDOMAIN 却给了被问类型的终态记录"这种自相矛盾的报文才落到 UNKNOWN ✓）。
        v = Verdict.ACCEPTED
    elif rcode == 0 and _kind == "negative":
        # P34-BM：**认证源的裸 NODATA 也应被采纳** ✓（方案："认证源给出经过本地验证的否定 ⇒
        # 返回认证源否定" ✓）。此前落进 else ⇒ UNKNOWN ⇒ 把"域名确实没有 A 记录"变成
        # SERVFAIL ✗（实测本域 apex 每分钟一次 ✓ —— 是本实现的不对称造成的真实回归 ✗）。
        # 安全边界不变 ✓：`local-b` 在上面已被拦成 UNKNOWN ✗（B 只是见证 ✓）。
        # ★ 2026-10-11：`"negative"` 现已要求**带否定证据**（权威段有 RR 或 AD=1）；
        #   零证据的"空壳"被单独归为 `"bare"` ⇒ 落到下面的 else ⇒ UNKNOWN ✓（不采纳 ✗）。
        v = Verdict.ACCEPTED
    else:
        v = Verdict.UNKNOWN
    if policy_version is None:
        return Answer(wire, source, v, 0.0, "n/a") if v == Verdict.BOGUS else make_answer(wire, source, v, ttl, now=now)
    return Answer(wire, source, v, (now or time.time()) + max(0.0, ttl), policy_version)


# ================= 方案 §4：readiness 读侧 + 运输断路器 =================
def _boot_id():
    """当前宿主 boot_id ✓（缓存；同一个 boot 内不会变）。"""
    if _BOOT_ID["v"] is not None:
        return _BOOT_ID["v"]
    bid = "unknown"
    try:
        with open("/proc/sys/kernel/random/boot_id", "r") as fh:
            bid = fh.read().strip()
    except Exception:
        bid = "unknown"
    _BOOT_ID["v"] = bid
    return bid


def read_ready_state(path=None, now_mono=None):
    """读 readiness 状态文件 ⇒ `(ready: bool, reason: str)`。**纯读**，不起子进程 ✓。

    一律判 not-ready 的情形（§4 第 1 项）：
      · 文件不存在 / 读失败 / JSON 坏 / 不是 dict；
      · `ready` 不为真，或 `consecutive_ok < 2`（连续两轮全部合格才算 ✓）；
      · `boot_id` 与当前宿主不一致 ⇒ **宿主重启后旧 ready 立即失效** ✓；
      · `container_id` / `started_at` 缺失 ⇒ **容器身份不可绑定** ⇒ 不信任 ✓；
      · `config_hash` 存在但与 `ALT_CONFIG_HASH` 不符 ⇒ **配置变化后旧 ready 失效** ✓
        （两侧都为空时不比，保持离线单测可用 ✓）；
      · `checked_monotonic` 缺失/非数值/比现在早超过 `ALT_READY_MAX_AGE`（默认 90 s ✓）
        ⇒ 状态过期 ✓（**不是**"容器在跑就算 ready" ✗）。
    """
    p = path or ALT_READY_STATE
    try:
        import json as _json
        with open(p, "r") as fh:
            raw = fh.read()
        st = _json.loads(raw)
    except Exception as exc:
        return False, "state_unreadable:%s" % type(exc).__name__
    if not isinstance(st, dict):
        return False, "state_not_object"
    if not st.get("ready"):
        return False, "not_ready:%s" % (st.get("reason") or "?")
    try:
        if int(st.get("consecutive_ok") or 0) < 2:
            return False, "consecutive_ok=%s" % (st.get("consecutive_ok"),)
    except Exception:
        return False, "consecutive_ok_bad"
    try:
        age = float(now_mono if now_mono is not None else time.monotonic()) - float(st["checked_monotonic"])
    except Exception:
        return False, "checked_monotonic_missing"
    if age > ALT_READY_MAX_AGE:
        return False, "state_stale:%.1fs" % age
    if age < -2.0:
        return False, "state_from_future:%.1fs" % age
    boot = st.get("boot_id") or ""
    if not boot or boot != _boot_id():
        return False, "boot_id_changed"
    if not st.get("container_id") or not st.get("started_at"):
        return False, "identity_missing"
    ch = st.get("config_hash") or ""
    if ALT_CONFIG_HASH and ch and ch != ALT_CONFIG_HASH:
        return False, "config_hash_changed"
    # ★ §4 第 1 项：**非托管重启**的兜底信号 —— 状态文件里记的 pid 文件指纹
    #   与此刻实际的不符（或此刻文件不存在：正在重启）⇒ 立刻 not-ready ✓。
    #   两侧都有值才比；写侧 stat 不到时（罕见）跳过，不让该字段变成"永远不 ready" ✗。
    try:
        rec_fp = st.get("pid_fp")
        if rec_fp:
            cur_fp = _pidfile_fp()
            if cur_fp is None:
                return False, "pidfile_gone"
            if (int(rec_fp[0]), int(rec_fp[1])) != cur_fp:
                return False, "pidfile_changed"
    except Exception:
        return False, "pidfile_uncomparable"
    return True, "ready"


def _pidfile_fp(path=None):
    """`(inode, mtime_ns)` 或 None（文件不存在/不可 stat）✓ —— 纯 `os.stat`，无子进程、无读盘 ✗。"""
    p = path or ALT_PIDFILE
    try:
        st = os.stat(p)
        return (int(st.st_ino), int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))))
    except Exception:
        return None


def alt_ready(now=None):
    """带**最多 1 秒一次**节流的 readiness 查询 ✓（热路径不能每请求读盘 ✗）。"""
    t = now if now is not None else time.monotonic()
    if t - _READY_CACHE["t"] < ALT_READY_POLL:
        return bool(_READY_CACHE["ready"])
    ready, reason = read_ready_state()
    _READY_CACHE["t"] = t
    _READY_CACHE["ready"] = bool(ready)
    _READY_CACHE["reason"] = reason
    return bool(ready)


def alt_ready_reason():
    return _READY_CACHE.get("reason") or "uninit"


# ---- 运输断路器（§4 第 3 项）----
def breaker_state(now=None):
    """返回 `(allowed, state)`；`allowed=False` 表示本次**不发包** ✓。"""
    t = now if now is not None else time.monotonic()
    if _BREAKER["open_until"] <= 0.0:
        return True, "closed"
    if t >= _BREAKER["open_until"]:
        if _BREAKER["half_open"]:
            # 已经放过 1 个半开试探，还没结算 ⇒ 继续挡 ✓（绝不放第二个 ✗）
            return False, "half_open_busy"
        _BREAKER["half_open"] = True
        return True, "half_open"
    return False, "open"


def breaker_note(transport_ok, now=None):
    """结算一次运输结果（**只由 `query_alt` 在真实发包后调用** ✓）。

    ★ `transport_ok=False` 只在**运输层失败**（无应答/超时才）时传 ⇒ 连续 3 次即断路 15 秒 ✓。
      DNSSEC bogus 是"运输成功 + 拿到安全结论" ⇒ 必须传 `transport_ok=True` ✗ 不计故障 ✓。
    """
    t = now if now is not None else time.monotonic()
    if transport_ok:
        _BREAKER["transport_ok"] += 1
        if _BREAKER["half_open"]:
            _BREAKER["half_ok"] += 1
        _BREAKER["fails"] = 0
        _BREAKER["open_until"] = 0.0
        _BREAKER["half_open"] = False
        return "closed"
    _BREAKER["transport_fail"] += 1
    _BREAKER["fails"] += 1
    if _BREAKER["half_open"]:
        _BREAKER["half_fail"] += 1
        _BREAKER["half_open"] = False
        _BREAKER["open_until"] = t + ALT_BREAKER_OPEN
        _BREAKER["trips"] += 1
        return "open"
    if _BREAKER["fails"] >= ALT_BREAKER_FAILS:
        _BREAKER["open_until"] = t + ALT_BREAKER_OPEN
        _BREAKER["half_open"] = False
        _BREAKER["trips"] += 1
        return "open"
    return "closed"


def breaker_snapshot():
    """给 guard/chainmon 看的观测快照（纯读 ✓）。"""
    return {"fails": _BREAKER["fails"], "trips": _BREAKER["trips"],
            "transport_ok": _BREAKER["transport_ok"],
            "transport_fail": _BREAKER["transport_fail"],
            "half_ok": _BREAKER["half_ok"], "half_fail": _BREAKER["half_fail"],
            "open": _BREAKER["open_until"] > 0.0}


def query_alt(name, qtype=1, timeout=4.0, now=None, deadline=None):
    """只查任务1 的 `unbound-alt`；返回 `Answer`（含 valid_until）或 None。

    §4 第 3 项：**UNKNOWN / NOT_READY 时不进入长时间 alt 尝试** ✓ —— 本函数开头即判
      readiness 与断路器，任一不通过就**立刻返回 None（不发包）** ✗，
      把"恢复"交给受限的后台探测（`unbound-alt-readiness.py` 的 timer）✓。
    §3 第 67/70 行：`deadline` = 同一请求的 monotonic 截止时间；剩余 ≤ 保留量 ⇒
      立刻返回 None（**不发包、不重发预算** ✓）。`timeout=` 仅保留给旧调用方/单测 ✓。
    """
    if not ALT_ENABLED:
        return None
    if deadline is None:
        if timeout is None:
            return None
        deadline = time.monotonic() + float(timeout)
    remaining = float(deadline) - time.monotonic()
    if remaining <= ALT_TIME_RESERVE:
        return None
    if not alt_ready():
        return None
    allowed, _bstate = breaker_state()
    if not allowed:
        return None
    socket_timeout = min(remaining - ALT_TIME_RESERVE, ALT_SOCKET_TIMEOUT_CAP)
    if socket_timeout <= 0.0:
        return None
    host, _, port = ALT_ADDR.partition(":")
    try:
        port = int(port or 53)
    except Exception:
        port = 53
    wire = build_query(name, qtype)
    if wire is None:
        return None
    try:
        data = exchange_udp((host, port), wire, socket_timeout)
        if data is None:
            raise IOError("no matching DNS response")
    except Exception:
        # ★ 运输层失败（含超时）⇒ 计入断路器 ✓。响应报文里的 rc=2 **不算**运输失败 ✗。
        breaker_note(False)
        return None
    breaker_note(True)
    # ★ 方案 §2 第 42/49 行：**这里也曾写死 `ttl=300.0`** ✗ ——
    # `query_alt()` 是 `_finalize_return()` 的救援通道与 `_retry_authenticated()` 的
    # 唯一来源 ⇒ 写死 300 就等价于"所有走备用的答案固定寿命 300s" ✗：
    #   · 短 TTL 的 CDN 名（30s/60s）被延长到 300s ⇒ 超出运营方授权时长 ✗；
    #   · 长 TTL 的稳定名每 300s 就被迫重查 ⇒ 白付延迟 ✗。
    # 改为从**这份报文自己**取有效期 ✓（与 guard 侧 `_alt_classify()` 同一口径 ✓）。
    _ttl, _det = rrset_validity(data, now=now)
    return classify_response(data, "local-alt", ttl=float(_ttl), now=now)


__all__ = ["ALT_ADDR", "ALT_ENABLED", "build_query", "classify_response", "query_alt",
           "count_answers", "count_answers_of", "classify_kind", "is_conclusive",
           "rrset_validity",
           "age_wire", "read_ready_state", "alt_ready", "alt_ready_reason",
           "breaker_state", "breaker_note", "breaker_snapshot"]
