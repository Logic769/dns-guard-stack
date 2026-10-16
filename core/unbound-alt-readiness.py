#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""unbound-alt-readiness.py —— alt 冷启动 readiness 门（方案 §2.1 / §2.2）

职责（只有这一件事）：判定 `unbound-alt` 是否**现在**处于"可用 + 已预热"状态，
把结论原子写进状态文件（默认 `/run/unbound-alt-ready.json`），供 guard 热路径读取。

逐条对应方案：
  §2.1 · 状态字段照方案 JSON；root 写；**临时文件 + os.replace** 原子替换 ✓。
       · 身份（boot_id / container_id / StartedAt）改变 ⇒ 等价"文件不存在" ⇒ not-ready ✓
         （`alt_adapter.read_ready_state()` 会判 not-ready，旧 ready 不会继续有效 ✓）。
       · 启动/重启事件监听器（`--event`）**立即写 not-ready 再预热**；10 s timer 兜底 ✓。
       · 托管重启脚本在 `docker restart` 前调 `--clear` ✓。
  §2.2 · **连续两轮全部合格才 ready**；单查询 2 s 上限；整轮 10 s 上限 ✓。
       · 严格校验 UDP 来源 / ID / QR / 问题 name·type·class / TC；TC=1 在剩余 deadline 内 TCP 重试 ✓。
       · 只用**完整**响应做分类；解析器复用 `alt_adapter`（既有可靠报文解析器）✓。
       · 随机标签只探"路由可达"：**不强制 NXDOMAIN、不把通配符当污染** ✓。

模式：
  （无参）       跑一轮检查并更新状态文件（timer 每 10 s 调用）✓
  --clear        只写 not-ready（mtime 刷新）—— 托管重启脚本在 restart 之前调用 ✓
  --event        常驻：监听 `docker events` ⇒ 容器 start 立即写 not-ready 再预热 ✓
  --mock <名>    五种 mock 场景（验收用；写 `--state` 指定的文件）✓

环境变量覆盖（隔离副本/测试；生产不设即用默认值）：
  ALT_READY_CONTAINER / ALT_READY_ADDR / ALT_READY_PORT / ALT_READY_STATE
"""
from __future__ import absolute_import

import argparse
import errno
import os
import socket
import struct
import subprocess
import sys
import time
from collections import namedtuple
from typing import Optional

# ---- 复用既有可靠报文解析器（§2.2 要求；不新增"只解析 12 字节头部"的检查）----
_RELEASE_DIR = os.environ.get("ALT_READY_RELEASE_DIR", "/opt/dnsguard/current")
if os.path.isdir(_RELEASE_DIR) and _RELEASE_DIR not in sys.path:
    sys.path.insert(0, _RELEASE_DIR)
try:
    import alt_adapter as _ALT
except Exception:                                    # pragma: no cover
    _ALT = None

DEFAULT_CONTAINER = os.environ.get("ALT_READY_CONTAINER", "unbound-alt")
DEFAULT_ADDR = os.environ.get("ALT_READY_ADDR", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("ALT_READY_PORT", "5357"))
DEFAULT_STATE = os.environ.get("ALT_READY_STATE", "/run/unbound-alt-ready.json")
# ★ §4 第 1 项：容器**自身**写出的 pid 文件 ⇒ 其 (inode, mtime_ns) 就是"容器身份"的
#   廉价指纹 ✓。实测 `docker restart` 后两者都变（`probe_pidfile.py`），
#   而两个容器都未配 `remote-control` ⇒ 不存在"纯 reload"路径 ⇒ 不会误判 ✓。
#
# ★★ 这里**不能**写死 `/opt/unbound-alt` ✗ —— 隔离副本（`alt-replica-unb`）挂在
#    `/opt/unbound-alt-replica`，写死生产路径会让副本的 10 轮冷启动门用**生产容器**的
#    pid 文件做判据 ⇒ 副本重启时它不变 ⇒ 门里出现 10/10"误报 ready"的假失败 ✗
#    （本块实测踩到 ✓）。正确做法：**从容器自己的 bind mount 反查**配置目录 ✓
#    （`docker inspect` 一次，本脚本本来就在起 docker ✓；guard 侧是纯 os.stat ✓）。
DEFAULT_PIDFILE = os.environ.get("ALT_READY_PIDFILE", "")

QUERY_BUDGET = 2.0        # §2.2 单查询 2 s 上限
ROUND_BUDGET = 10.0       # §2.2 整轮 10 s 上限
READY_ROUNDS = 2          # §2.2 连续两轮全部合格
# 启动/重启事件后的**短促预热窗口**（§2.1「立即写 not-ready 再预热」；timer 仍是兜底）✓
EVENT_WARM_WINDOW = float(os.environ.get("ALT_READY_EVENT_WINDOW", "20"))
EVENT_WARM_INTERVAL = float(os.environ.get("ALT_READY_EVENT_INTERVAL", "1.5"))
IPPROTO_TCP = getattr(socket, "IPPROTO_TCP", 6)
TRACE = os.environ.get("ALT_READY_TRACE", "") not in ("", "0")

# ================= 方案 §4 第 1 项：配置哈希 =================
# ready 记录必须绑定「配置哈希」⇒ **配置变化后旧 ready 立即失效** ✓。
# 哈希对象 = alt 容器的配置目录 + 密钥材料（bind mount 的宿主侧路径 ✓）：
#   /opt/unbound-alt/unbound.conf、root.key、var/root.key 等。
# 用内容哈希而非 mtime ⇒ 只有**实质变化**才失效 ✓（改注释也会失效，这是保守方向 ✓）。
#
# ★★ 现场血案（2026-10-10 首次在真机跑就炸）：`/opt/unbound-alt/dev/` 是**设备节点目录**
#   （`null` / `random` / `urandom` 三个字符设备）。原实现 `open(fp,"rb").read()` 读到 EOF
#   才停 ⇒ 读 `/dev/random` **永不返回**、内存无限增长 ⇒ 进程被 OOM killer 干掉
#   （dmesg 实测：`Out of memory: Killed process (python3) total-vm:806668kB anon-rss:532880kB`）
#   ✗✗。这条路径恰好在 `do_check()` / `do_clear()` 里被每轮调用 ⇒ **readiness 服务一启动
#   就自杀** ✗，且因为 `write_state()` 排在 `config_hash()` 之后 ⇒ **状态文件永远写不出去**
#   ⇒ guard 侧永远 not-ready ⇒ §4 的整个备用通道会静默失效 ✗（比报错更坏 ✗）。
#   修法：**只哈希常规文件**（`stat.S_ISREG`）+ **单个文件读取上限**（防超大水文件/日志 ✗）+ 跳过 `dev/`。
CONFIG_DIRS = [p.strip() for p in
               os.environ.get("ALT_READY_CONFIG_DIRS", "/opt/unbound-alt").split(os.pathsep)
               if p.strip()]
CONFIG_FILES = [p.strip() for p in
                os.environ.get("ALT_READY_CONFIG_FILES", "").split(os.pathsep) if p.strip()]
# 单文件哈希上限：超过就**不读内容**、只用 (路径, 大小, mtime) 参与哈希 ✓ ——
# 既不会失控读盘，也不会因为"跳过"而丢掉"这个文件变了"这件事 ✓。
CONFIG_FILE_MAX = int(os.environ.get("ALT_READY_CONFIG_FILE_MAX", str(1 << 20)))
# 整目录哈希的对象上限（防配置目录被塞进一堆文件 ✗）
CONFIG_ENTRY_MAX = int(os.environ.get("ALT_READY_CONFIG_ENTRY_MAX", "4096"))
# 目录白名单：`dev/` 是设备节点 ⇒ **结构性排除**（即便某天有人换成常规文件也不变哈希语义 ✓）
CONFIG_SKIP_DIRS = tuple(d for d in
                         os.environ.get("ALT_READY_CONFIG_SKIP_DIRS", "dev").split(":") if d)


def _hash_one(h, base, fp):
    """把一个**常规文件**按 (相对路径, 内容或大小/ mtime) 累加进哈希 ✓；返回是否计入。"""
    import stat as _stat
    try:
        st = os.stat(fp)
    except Exception:
        return False
    if not _stat.S_ISREG(st.st_mode):
        # 设备节点 / FIFO / socket / 目录 ⇒ **绝不 open** ✗（`/dev/random` 会读到死 ✗）
        return False
    rel = os.path.relpath(fp, base)
    h.update(rel.encode("utf-8", "replace"))
    h.update(b"\x00")
    if st.st_size <= CONFIG_FILE_MAX:
        try:
            with open(fp, "rb") as fh:
                blob = fh.read(CONFIG_FILE_MAX)
        except Exception:
            return False
        h.update(blob)
    else:
        # 太大 ⇒ 不读内容，退化为"元数据指纹"✓（仍能感知"它变了" ✓）
        h.update(("size=%d|mtime=%d" % (st.st_size, int(st.st_mtime))).encode("ascii"))
    h.update(b"\x00")
    return True


def config_hash():
    """对 alt 的配置/密钥材料做内容哈希 ⇒ 16 进制串（没有可哈希文件时返回 "unavailable"）。"""
    import hashlib
    h = hashlib.sha256()
    found = False
    entries = 0
    for base in CONFIG_DIRS:
        try:
            names = sorted(os.listdir(base))
        except Exception:
            continue
        for nm in names:
            if nm.endswith(".pid"):
                continue                       # 运行期文件，不属于配置 ✗
            if nm in CONFIG_SKIP_DIRS:
                continue                       # `dev/` 等设备节点目录 ⇒ 结构性排除 ✓
            p = os.path.join(base, nm)
            entries += 1
            if entries > CONFIG_ENTRY_MAX:
                break
            try:
                isdir = os.path.isdir(p)
            except Exception:
                continue
            if isdir:
                try:
                    sub = sorted(os.listdir(p))
                except Exception:
                    continue
                for s in sub:
                    if _hash_one(h, base, os.path.join(p, s)):
                        found = True
            else:
                if _hash_one(h, base, p):
                    found = True
    for fp in CONFIG_FILES:
        # 显式配置文件的 base 用其父目录 ⇒ 相对路径仍是文件名 ✓
        if _hash_one(h, os.path.dirname(fp) or ".", fp):
            found = True
    return h.hexdigest()[:32] if found else "unavailable"


_Check = namedtuple("_Check", "check name qtype rc rtt_ms detail")


def _trace(msg):
    if TRACE:
        sys.stderr.write("[readiness] %s\n" % msg)
        sys.stderr.flush()


def _chk(check, name, qtype, rc, rtt_ms, detail):
    return _Check(check, name, qtype, rc, rtt_ms, detail)


# ---------------------------------------------------------------- 身份
def _boot_id():
    try:
        with open("/proc/sys/kernel/random/boot_id", "r") as fh:
            return fh.read().strip()
    except Exception:
        return "unknown"


def _docker_inspect(container, fmt):
    out = subprocess.check_output(["docker", "inspect", container, "--format", fmt],
                                  stderr=subprocess.STDOUT, timeout=5.0)
    return out.decode("utf-8", "replace").strip()


def container_identity(container):
    """`docker inspect` ⇒ (container_id, started_at, error)。"""
    cid = ""
    try:
        cid = _docker_inspect(container, "{{.Id}}")
    except Exception as exc:
        return "", "", "inspect_id_failed:%s" % type(exc).__name__
    if not cid:
        return "", "", "inspect_empty_id"
    try:
        started = _docker_inspect(container, "{{.State.StartedAt}}")
    except Exception as exc:
        return cid, "", "inspect_started_failed:%s" % type(exc).__name__
    return cid, started, None


# ---------------------------------------------------------------- 解析（复用 alt_adapter 原语）
def _fallback_name_at(wire, off):
    """仅在 release 里缺 `parse_response` 时的保底实现（指针只向后跳，最多 16 跳）✓。"""
    n = len(wire)
    if off >= n:
        return None, None
    labels = []
    pos = off
    nxt = None
    hops = 0
    while True:
        if pos >= n:
            return None, None
        ln = wire[pos]
        if ln == 0:
            if nxt is None:
                nxt = pos + 1
            break
        if (ln & 0xC0) == 0xC0:
            if pos + 1 >= n:
                return None, None
            ptr = ((ln & 0x3F) << 8) | wire[pos + 1]
            if nxt is None:
                nxt = pos + 2
            if ptr >= pos:
                return None, None
            hops += 1
            if hops > 16:
                return None, None
            pos = ptr
            continue
        if (ln & 0xC0) != 0:
            return None, None
        pos += 1
        if pos + ln > n:
            return None, None
        labels.append(wire[pos:pos + ln].decode("ascii", "replace"))
        pos += ln
    return nxt, (".".join(labels).lower() if labels else ".")


def name_at(wire, off):
    if _ALT is not None and hasattr(_ALT, "_name_at"):
        return _ALT._name_at(wire, off)
    return _fallback_name_at(wire, off)


def parse_answer(wire, qname, qtype, qclass=1):
    """返回 (rc, ad, tc, ans, n_an) 或 None。`ans` = [(name, rtype, rclass, rdata)]。"""
    if _ALT is not None and hasattr(_ALT, "parse_response"):
        r = _ALT.parse_response(wire, qname, qtype, qclass)
        if r is None:
            return None
        return r.rc, r.ad, r.tc, r.ans, r.n_an
    # 保底：复用 alt_adapter 的头部/跳名原语
    h = _ALT._parse_header(wire) if _ALT is not None else None
    if not h:
        return None
    _qid, flags, _qd, an, _ns, _ar = h
    if not (flags & 0x8000):
        return None
    end, name = name_at(wire, 12)
    if end is None:
        return None
    want = "." if qname in ("", ".") else qname.lower()
    got = "." if name in ("", ".") else name
    if got != want or end + 4 > len(wire):
        return None
    rqtype, rqclass = struct.unpack("!HH", wire[end:end + 4])
    if rqtype != int(qtype) or rqclass != int(qclass):
        return None
    off = end + 4
    ans = []
    for _ in range(an):
        off, rname = name_at(wire, off)
        if off is None or off + 10 > len(wire):
            return None
        rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", wire[off:off + 10])
        off += 10
        if off + rdlen > len(wire):
            return None
        ans.append((rname, rtype, rclass, wire[off:off + rdlen]))
        off += rdlen
    return flags & 0xF, bool(flags & 0x20), bool(flags & 0x0200), ans, an


def _has_rrset(ans, qclass, qtypes):
    return any(rtype in qtypes and rclass == qclass for (_n, rtype, rclass, _d) in ans)


# ---------------------------------------------------------------- 传输（严格校验 + TC 重试）
class _Res(object):
    __slots__ = ("rc", "ad", "tc", "ans", "n_an", "detail", "rtt_ms", "via")

    def __init__(self, rc, ad, tc, ans, n_an, detail, rtt_ms, via):
        self.rc = rc
        self.ad = ad
        self.tc = tc
        self.ans = ans
        self.n_an = n_an
        self.detail = detail
        self.rtt_ms = rtt_ms
        self.via = via


def udp_exchange(addr, port, query, qname, qtype, qclass, round_deadline, start):
    """一轮 UDP 查询 + 严格校验；返回 `_Res`（失败 ⇒ rc=None）。"""
    left = round_deadline - time.monotonic()
    if left <= 0.05:
        return _Res(None, False, False, [], 0, "round_budget_exhausted", 0.0, "udp")
    expect_id = struct.unpack("!H", query[:2])[0]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(max(0.05, min(left - 0.02, QUERY_BUDGET)))
        sock.sendto(query, (addr, port))
        deadline = min(round_deadline, time.monotonic() + QUERY_BUDGET)
        while True:
            remain = deadline - time.monotonic()
            if remain <= 0:
                return _Res(None, False, False, [], 0, "udp_timeout",
                            (time.monotonic() - start) * 1000.0, "udp")
            sock.settimeout(remain)
            try:
                data, src = sock.recvfrom(4096)
            except socket.timeout:
                return _Res(None, False, False, [], 0, "udp_timeout",
                            (time.monotonic() - start) * 1000.0, "udp")
            except Exception as exc:
                return _Res(None, False, False, [], 0, "udp_error:%s" % type(exc).__name__,
                            (time.monotonic() - start) * 1000.0, "udp")
            rtt = (time.monotonic() - start) * 1000.0
            if len(data) < 12:
                return _Res(None, False, False, [], 0, "too_short", rtt, "udp")
            got_id = struct.unpack("!H", data[:2])[0]
            if got_id != expect_id:
                return _Res(None, False, False, [], 0, "qid_mismatch", rtt, "udp")
            if src[0] != addr or src[1] != port:
                return _Res(None, False, False, [], 0, "source_mismatch:%s" % (src[0],),
                            rtt, "udp")
            if not (struct.unpack("!H", data[2:4])[0] & 0x8000):
                return _Res(None, False, False, [], 0, "not_response", rtt, "udp")
            parsed = parse_answer(data, qname, qtype, qclass)
            if parsed is None:
                return _Res(None, False, False, [], 0, "question_mismatch", rtt, "udp")
            rc, ad, tc, ans, n_an = parsed
            return _Res(rc, ad, tc, ans, n_an, "ok", rtt, "udp")
    finally:
        try:
            sock.close()
        except Exception:
            pass


def tcp_exchange(addr, port, query, qname, qtype, qclass, hard_deadline, start):
    """TC=1 ⇒ 在**剩余 deadline 内**做一次 TCP 重试 ✓。"""
    left = hard_deadline - time.monotonic()
    if left <= 0.05:
        return _Res(None, False, False, [], 0, "tcp_budget_exhausted",
                    (time.monotonic() - start) * 1000.0, "tcp")
    expect_id = struct.unpack("!H", query[:2])[0]
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(max(0.05, min(left, QUERY_BUDGET)))
        sock.connect((addr, port))
        sock.sendall(struct.pack("!H", len(query)) + query)
        buf = b""
        while len(buf) < 2:
            chunk = sock.recv(2 - len(buf))
            if not chunk:
                return _Res(None, False, False, [], 0, "tcp_eof_len",
                            (time.monotonic() - start) * 1000.0, "tcp")
            buf += chunk
        want = struct.unpack("!H", buf[:2])[0]
        body = b""
        while len(body) < want:
            chunk = sock.recv(min(4096, want - len(body)))
            if not chunk:
                return _Res(None, False, False, [], 0, "tcp_eof_body",
                            (time.monotonic() - start) * 1000.0, "tcp")
            body += chunk
    except Exception as exc:
        return _Res(None, False, False, [], 0, "tcp_error:%s" % type(exc).__name__,
                    (time.monotonic() - start) * 1000.0, "tcp")
    finally:
        try:
            sock.close()
        except Exception:
            pass
    rtt = (time.monotonic() - start) * 1000.0
    if len(body) < 12 or struct.unpack("!H", body[:2])[0] != expect_id:
        return _Res(None, False, False, [], 0, "tcp_qid_mismatch", rtt, "tcp")
    parsed = parse_answer(body, qname, qtype, qclass)
    if parsed is None:
        return _Res(None, False, False, [], 0, "tcp_parse_fail", rtt, "tcp")
    rc, ad, tc, ans, n_an = parsed
    return _Res(rc, ad, tc, ans, n_an, "ok", rtt, "tcp")


def probe(addr, port, check, name, qtype, round_deadline, verdict):
    """单样本探测 ⇒ `_Check`。`verdict(res)` ⇒ (ok, detail)。"""
    start = time.monotonic()
    if _ALT is None:
        return _chk(check, name, qtype, None, 0.0, "parser_unavailable")
    query = _ALT.build_query(name, qtype)
    if query is None:
        return _chk(check, name, qtype, None, 0.0, "build_query_failed")
    res = udp_exchange(addr, port, query, name, qtype, 1, round_deadline, start)
    if res.rc is not None and res.tc:
        # TC=1 ⇒ 在**剩余 deadline 内** TCP 重试 ✓（上限仍是单查询 2 s ✓）
        hard = min(round_deadline, start + QUERY_BUDGET)
        tcp = tcp_exchange(addr, port, query, name, qtype, 1, hard, start)
        if tcp.rc is not None:
            res = tcp
        else:
            return _chk(check, name, qtype, None, tcp.rtt_ms, "tc_tcp_retry:%s" % tcp.detail)
    if res.rc is None:
        return _chk(check, name, qtype, None, res.rtt_ms, res.detail)
    ok, why = verdict(res)
    return _chk(check, name, qtype, res.rc, res.rtt_ms,
                ("ok" if ok else why) + ("" if res.via == "udp" else "#tcp"))


def _random_label():
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    raw = os.urandom(12)
    return "".join(alphabet[b % len(alphabet)] for b in raw) + ".example.com"


def run_round(addr, port, random_label):
    """跑一轮 §2.2 的四个样本 ⇒ (checks, all_ok, reason)。"""
    round_deadline = time.monotonic() + ROUND_BUDGET
    checks = []

    def _cf_ok(res):
        if res.rc != 0:
            return False, "rc_%d_expect_NOERROR" % res.rc
        if not _has_rrset(res.ans, 1, (1, 28)):
            return False, "no_A_AAAA_rrset"
        if not res.ad:
            return False, "AD_not_set"
        return True, "ok"

    def _bogus_ok(res):
        if res.rc != 2:
            return False, "rc_%d_expect_SERVFAIL" % res.rc
        return True, "ok"

    def _qq_ok(res):
        if res.rc != 0:
            return False, "rc_%d_expect_NOERROR" % res.rc
        if _has_rrset(res.ans, 1, (1,)):
            return True, "ok_A"
        # 有效 CNAME 链：本应答里出现了 CNAME，且某条 A 的名字出现在该链上
        cnames = set()
        addrs = set()
        for (rname, rtype, _rc, rdata) in res.ans:
            if rtype == 5:
                cnames.add((rname or "").lower())
                _e, tgt = name_at(rdata, 0)
                if tgt:
                    cnames.add(tgt)
            elif rtype == 1:
                addrs.add((rname or "").lower())
        if cnames and (addrs & cnames):
            return True, "ok_CNAME_chain"
        return False, "no_A_or_valid_cname_chain"

    def _rand_ok(res):
        # 只探"路由可达"：任何**结构完整且回答了问题**的应答都算可达 ✓
        # 不强制 NXDOMAIN ✗、不把通配符（answer 里带记录）当污染 ✗。
        return True, "ok_route_reachable_rc%d" % res.rc

    checks.append(probe(addr, port, "cloudflare_A", "cloudflare.com", 1, round_deadline, _cf_ok))
    checks.append(probe(addr, port, "cloudflare_AAAA", "cloudflare.com", 28, round_deadline, _cf_ok))
    checks.append(probe(addr, port, "bogus_servfail", "dnssec-failed.org", 1, round_deadline, _bogus_ok))
    checks.append(probe(addr, port, "www_qq_A", "www.qq.com", 1, round_deadline, _qq_ok))
    checks.append(probe(addr, port, "random_label_reach", random_label, 1, round_deadline, _rand_ok))

    bad = [c for c in checks if not c.detail.startswith("ok")]
    if not bad:
        return checks, True, "all_ok"
    return checks, False, "%s:%s" % (bad[0].check, bad[0].detail)


# ---------------------------------------------------------------- 状态文件
def _now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime())


def _pid_fp(path=None, container=None):
    """容器 pid 文件的 `[inode, mtime_ns]`；取不到 ⇒ None ✓（纯 `os.stat`，无子进程 ✓）。

    `path` 为空 ⇒ 走 `ALT_READY_PIDFILE`；若也为空 ⇒ 再由 `alt_pidfile(container)`
    从容器 bind mount 反查 ✓（★ 必须带 `container`：写侧要为**被测容器**取指纹，
    副本容器与生产容器的配置目录不同 ✗ —— 不带就会写进生产容器的指纹，
    副本的冷启动门永远假失败 ✗，本块实测踩到 ✓）。
    """
    p = path or DEFAULT_PIDFILE
    if not p:
        try:
            p = alt_pidfile(container)
        except Exception:
            p = None
    if not p:
        return None
    try:
        st = os.stat(p)
        return [int(st.st_ino), int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)))]
    except Exception:
        return None


_PIDFILE_CACHE = {"container": None, "path": None}


def alt_pidfile(container=None):
    """从容器自己的 **bind mount** 反查它的 `unbound.pid` 宿主路径 ✓。

    ★ 为什么必须反查而不是写死（本块实测踩到的假失败）：隔离副本容器
      （`alt-replica-unb`）的配置目录是 `/opt/unbound-alt-replica`，写死生产路径
      `/opt/unbound-alt/unbound.pid` 会让副本的冷启动门拿**生产容器**的指纹做判据 ⇒
      副本重启时它不变 ⇒ 门里报 10/10"误报 ready" ✗（是夹具假失败，不是产品缺陷 ✗）。
      反查依据：容器的 bind mount 里若有 `/opt/unbound/etc/unbound`（镜像内的配置目录）
      ⇒ 其宿主侧目录里的 `unbound.pid` 就是该容器自己写的 ✓。
    结果按容器名缓存（配置目录不会变 ✓）。
    """
    c = container or DEFAULT_CONTAINER
    if _PIDFILE_CACHE["container"] == c and _PIDFILE_CACHE["path"]:
        return _PIDFILE_CACHE["path"]
    p = None
    try:
        raw = subprocess.check_output(
            ["docker", "inspect", c, "--format",
             "{{range .Mounts}}{{.Source}}=>{{.Destination}}\n{{end}}"],
            stderr=subprocess.STDOUT, timeout=5.0).decode("utf-8", "replace")
        for ln in raw.splitlines():
            ln = ln.strip()
            if "=>" not in ln:
                continue
            src, _, dst = ln.partition("=>")
            src, dst = src.strip(), dst.strip()
            # unbound 镜像把配置放在 `/opt/unbound/etc/unbound`（`/etc/unbound` 是软链 ✓）
            if dst.rstrip("/") in ("/opt/unbound/etc/unbound", "/etc/unbound"):
                cand = os.path.join(src, "unbound.pid")
                if os.path.isfile(cand):
                    p = cand
                    break
                # pid 文件可能暂时不存在（正在重启）⇒ 也认这个目录 ✓
                _PIDFILE_CACHE["dir"] = src
                p = cand
                break
    except Exception:
        p = None
    if p:
        _PIDFILE_CACHE["container"] = c
        _PIDFILE_CACHE["path"] = p
    return p


def write_state(path, boot_id, cid, started, consecutive_ok, reason, checks, event=None,
                cfg_hash=None, container=None):
    """临时文件 + os.replace 原子替换 ✓；root 写 ✓；返回落盘的 dict。

    §4 第 1 项：记录里带 `config_hash` ✓ —— 配置一变，读侧（`alt_adapter.read_ready_state`）
    与写侧（`do_check` 的 `same_identity` 判定）都会让旧 ready 立即失效 ✓。
    """
    payload = {
        "ready": bool(consecutive_ok >= READY_ROUNDS),
        "boot_id": boot_id,
        "container_id": cid,
        "started_at": started,
        "config_hash": config_hash() if cfg_hash is None else cfg_hash,
        # ★ §4 第 1 项兜底：把容器**自身**写出的 pid 文件指纹一起记下来 ⇒ 读侧一次
        #   `os.stat` 就能发现"容器被非托管重启"（`dnsguard-alt-restart.sh` 之外的
        #   直接 `docker restart`）⇒ 旧 ready 立即失效，不必等 90 s 过期 ✓。
        "pid_fp": _pid_fp(container=container),
        "checked_monotonic": time.monotonic(),
        "checked_wall": time.time(),
        "generated_at": _now_iso(),
        "consecutive_ok": int(consecutive_ok),
        "reason": reason,
        "checks": [{"check": c.check, "name": c.name, "qtype": c.qtype, "rc": c.rc,
                    "rtt_ms": round(c.rtt_ms, 3), "detail": c.detail} for c in (checks or [])],
    }
    if event:
        payload["event"] = event
    try:
        import json as _json
        blob = _json.dumps(payload)
    except Exception:
        blob = ('{"ready":%s,"boot_id":"%s","container_id":"%s","started_at":"%s",'
                '"consecutive_ok":%d,"reason":"%s"}'
                % (str(payload["ready"]).lower(), boot_id, cid, started,
                   payload["consecutive_ok"], reason))
    directory = os.path.dirname(path) or "."
    try:
        os.makedirs(directory, mode=0o755, exist_ok=True)
    except OSError as exc:
        if exc.errno != errno.EEXIST:
            raise
    tmp = "%s.tmp.%d" % (path, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        os.write(fd, blob.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    return payload


def load_state(path):
    try:
        import json as _json
        with open(path, "r") as fh:
            return _json.loads(fh.read())
    except Exception:
        return None


# ---------------------------------------------------------------- 主流程
def identity_matches(old, boot, cid, started, cfg, pid_fp=None):
    """§4 第 1 项身份判定（生产路径 ⇔ mock 共用同一个函数 ⇒ 断言才有意义 ✓）。

    五项必须全部一致才允许沿用上一次的 `consecutive_ok`：
    `boot_id`（宿主重启）、`container_id`（容器被重建）、`started_at`（容器重启）、
    `config_hash`（**配置变化也必须失效** ✓ —— 这正是方案点名的第 4 项）、
    `pid_fp`（容器**自身**写的 pid 文件指纹 ⇒ 探不到 docker 也能发现重启 ✓）。

    ★ `pid_fp` 的比较用"**存在即严比、任一侧为 None 则跳过**"：
      写侧 `stat` 不到该文件时（罕见/路径不同）不让身份判定永远失败 ✗（那会让
      `consecutive_ok` 永远攒不起来 ⇒ alt 永远不可用 ✗，比不检查更坏 ✗）。
    """
    if not old:
        return False
    if not (old.get("boot_id") == boot
            and old.get("container_id") == cid
            and old.get("started_at") == started
            and (old.get("config_hash") or "") == cfg):
        return False
    old_fp = old.get("pid_fp")
    if old_fp and pid_fp:
        try:
            if [int(old_fp[0]), int(old_fp[1])] != [int(pid_fp[0]), int(pid_fp[1])]:
                return False
        except Exception:
            return False
    return True


def do_check(addr, port, state_path, container, random_label=None, reason_hint=None):
    """跑一轮并写状态文件 ⇒ payload。**身份或配置改变 ⇒ 连续成功数归零** ✓（§4 第 1 项）。"""
    boot = _boot_id()
    cid, started, err = container_identity(container)
    cfg = config_hash()
    pid_fp = _pid_fp(container=container)
    old = load_state(state_path)
    # ★ `config_hash` / `pid_fp` 也在同一个身份判定里 ✓：任一变化（即便容器没重启、或
    #   docker 身份字段巧合相同）`consecutive_ok` 都必须从 0 重新攒（旧 ready 立即失效 ✓）。
    same_identity = identity_matches(old, boot, cid, started, cfg, pid_fp)
    prev_ok = int(old.get("consecutive_ok") or 0) if same_identity else 0
    if not cid or err:
        return write_state(state_path, boot, cid, started, 0,
                           "identity_unavailable:%s" % (err or "empty"), [], cfg_hash=cfg,
                           container=container)
    checks, all_ok, why = run_round(addr, port, random_label or _random_label())
    if all_ok:
        consecutive = prev_ok + 1
        reason = "warming" if consecutive < READY_ROUNDS else "ready"
        if reason_hint:
            reason = reason_hint + ":" + reason
    else:
        consecutive = 0
        reason = "check_failed:%s" % why
    return write_state(state_path, boot, cid, started, consecutive, reason, checks,
                       cfg_hash=cfg, container=container)


def do_clear(state_path, container, note="restart_pending"):
    """写 not-ready 的**新**状态（mtime 刷新）⇒ guard 立刻看到 not-ready ✓。"""
    boot = _boot_id()
    cid, started, _err = container_identity(container)
    return write_state(state_path, boot, cid, started, 0, note, [], cfg_hash=config_hash(),
                       container=container)


def do_event_loop(state_path, container, addr, port):
    """监听 docker 事件：容器 start ⇒ **立即写 not-ready 再预热**；timer 兜底 ✓。"""
    _trace("event listener start container=%s" % container)
    backoff = 1.0
    while True:
        proc = None
        try:
            proc = subprocess.Popen(
                ["docker", "events", "--filter", "type=container",
                 "--filter", "event=start", "--filter", "event=restart",
                 "--format", "{{.Actor.Attributes.name}} {{.Action}}"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                universal_newlines=True)
            backoff = 1.0
            for line in proc.stdout:
                line = (line or "").strip()
                if not line:
                    continue
                parts = line.split()
                name = parts[0] if parts else ""
                if name != container:
                    continue
                do_clear(state_path, container, note="event_start")
                _trace("event %r ⇒ not-ready written; warming" % line)
                # 事件后的短促预热窗口：连续跑几轮直到 ready，把"启动收敛"压到远小于 10 s timer ✓
                t_ev = time.monotonic()
                while time.monotonic() - t_ev < EVENT_WARM_WINDOW:
                    try:
                        p = do_check(addr, port, state_path, container)
                        _trace("warm round ready=%s consecutive=%s reason=%s"
                               % (p["ready"], p["consecutive_ok"], p["reason"]))
                        if p["ready"]:
                            break
                    except Exception as exc:
                        _trace("warm check failed: %r" % (exc,))
                    time.sleep(EVENT_WARM_INTERVAL)
        except Exception as exc:
            _trace("events stream error: %r" % (exc,))
        finally:
            if proc is not None:
                try:
                    proc.kill()
                except Exception:
                    pass
        time.sleep(backoff)
        backoff = min(30.0, backoff * 2.0)


def _ok_checks():
    return [_chk("cloudflare_A", "cloudflare.com", 1, 0, 1.0, "ok"),
            _chk("cloudflare_AAAA", "cloudflare.com", 28, 0, 1.0, "ok"),
            _chk("bogus_servfail", "dnssec-failed.org", 1, 2, 1.0, "ok"),
            _chk("www_qq_A", "www.qq.com", 1, 0, 1.0, "ok"),
            _chk("random_label_reach", "abc.example.com", 1, 3, 1.0, "ok_route_reachable_rc3")]


def _ready(path):
    try:
        return bool(_ALT.read_ready_state(path)[0]), _ALT.read_ready_state(path)[1]
    except Exception as exc:
        return None, "no_adapter:%r" % (exc,)


def _max_age():
    """读侧的真实有效期（默认 90 s ✓）—— mock 必须按它造过期样本，不能写死 31 s ✗。"""
    return float(getattr(_ALT, "ALT_READY_MAX_AGE", 90.0))


def _mock(name, state_path, container, addr, port):
    """§2.4 / §4 mock 场景。**只写 `state_path`**（测试传 --state tmp）✓。"""
    boot = _boot_id()
    cid, started, _err = container_identity(container)
    cid = cid or "mockcid0000"
    started = started or "2026-10-10T00:00:00Z"
    cfg = config_hash()

    if name == "identity_change":
        # ① 文件仍是**新**的（mtime 刚写），但身份换成新容器/新 StartedAt
        write_state(state_path, boot, cid, started, 2, "ready", _ok_checks(), cfg_hash=cfg)
        pre = _ready(state_path)
        write_state(state_path, boot, cid + "NEWCONTAINERID", started + ".999", 0, "warming", [],
                    cfg_hash=cfg)
        after = _ready(state_path)
        # ② 旧文件原封不动（模拟"重启但守护脚本崩溃、文件没被重写"）：
        #    这里把 boot_id 改成"另一个宿主启动"等价形式来证明 boot 改变也判 not-ready
        write_state(state_path, boot, cid, started, 2, "ready", _ok_checks(), cfg_hash=cfg)
        st = load_state(state_path)
        st["boot_id"] = "00000000-0000-0000-0000-000000000000"
        _dump(state_path, st)
        bootchg = _ready(state_path)
        print("mock=identity_change ready_before_new_container=%s/%s "
              "ready_after_new_container_id=%s/%s ready_after_boot_change=%s/%s"
              % (pre[0], pre[1], after[0], after[1], bootchg[0], bootchg[1]))
        return 0

    if name == "config_change":
        # §4 第 1 项：**配置变化后旧 ready 立即失效** ✓
        #   ① 读侧：文件里的 config_hash 与守护侧期望不符 ⇒ config_hash_changed ✓
        #   ② 写侧：走 `identity_matches()`（生产同一函数）——配置哈希一变，身份即失效 ✓
        write_state(state_path, boot, cid, started, 2, "ready", _ok_checks(), cfg_hash=cfg)
        pre = _ready(state_path)
        # ① 读侧：把"守护侧期望的配置哈希"改错（模拟配置被改过）⇒ 必须 not-ready
        old_expect = getattr(_ALT, "ALT_CONFIG_HASH", "")
        try:
            _ALT.ALT_CONFIG_HASH = "deadbeefdeadbeefdeadbeefdeadbeef"
            _ALT._READY_CACHE["t"] = 0.0            # 绕过节流（1 s）以便立刻观测
            mism = _ready(state_path)
        finally:
            _ALT.ALT_CONFIG_HASH = old_expect
            _ALT._READY_CACHE["t"] = 0.0
        # ② 写侧：直接对 `identity_matches()` 造样本（不依赖本机是否存在配置目录 ✓）
        old_rec = {"boot_id": boot, "container_id": cid, "started_at": started,
                   "config_hash": cfg}
        same_cfg = identity_matches(old_rec, boot, cid, started, cfg)
        diff_cfg = identity_matches(old_rec, boot, cid, started, cfg + "X")
        diff_cid = identity_matches(old_rec, boot, cid + "NEW", started, cfg)
        diff_started = identity_matches(old_rec, boot, cid, started + "Z", cfg)
        diff_boot = identity_matches(old_rec, "OTHERBOOT", cid, started, cfg)
        print("mock=config_change ready_before=%s/%s ready_after_expected_hash_mismatch=%s/%s "
              "identity(same,cfg_changed,cid_changed,started_changed,boot_changed)=%s/%s/%s/%s/%s "
              "(期望 True/ready、False/config_hash_changed、True/False/False/False/False)"
              % (pre[0], pre[1], mism[0], mism[1],
                 same_cfg, diff_cfg, diff_cid, diff_started, diff_boot))
        return 0

    if name == "stale_state":
        write_state(state_path, boot, cid, started, 2, "ready", _ok_checks(), cfg_hash=cfg)
        fresh = _ready(state_path)
        st = load_state(state_path)
        st["checked_monotonic"] = time.monotonic() - (_max_age() + 1.0)   # 超过真实有效期
        _dump(state_path, st)
        stale = _ready(state_path)
        print("mock=stale_state max_age=%.0f ready_fresh=%s/%s ready_after_expiry=%s/%s"
              % (_max_age(), fresh[0], fresh[1], stale[0], stale[1]))
        return 0

    if name == "two_rounds":
        write_state(state_path, boot, cid, started, 1, "warming", _ok_checks(), cfg_hash=cfg)
        r1 = _ready(state_path)
        write_state(state_path, boot, cid, started, 2, "ready", _ok_checks(), cfg_hash=cfg)
        r2 = _ready(state_path)
        print("mock=two_rounds after_round1=%s/%s after_round2=%s/%s"
              % (r1[0], r1[1], r2[0], r2[1]))
        return 0

    if name == "one_failure":
        write_state(state_path, boot, cid, started, 2, "ready", _ok_checks(), cfg_hash=cfg)
        before = _ready(state_path)
        bad = list(_ok_checks())
        bad[2] = _chk("bogus_servfail", "dnssec-failed.org", 1, 0, 900.0,
                      "rc_0_expect_SERVFAIL")
        write_state(state_path, boot, cid, started, 0, "check_failed:bogus_servfail", bad,
                    cfg_hash=cfg)
        after = _ready(state_path)
        print("mock=one_failure ready_before=%s/%s ready_after_one_fail=%s/%s"
              % (before[0], before[1], after[0], after[1]))
        return 0

    if name == "daemon_crash":
        # 守护脚本崩溃 ⇒ 状态文件不再更新 ⇒ 超有效期必须 not-ready ✓
        write_state(state_path, boot, cid, started, 2, "ready", _ok_checks(), cfg_hash=cfg)
        before = _ready(state_path)
        st = load_state(state_path)
        st["checked_monotonic"] = time.monotonic() - (_max_age() + 1.0)
        _dump(state_path, st)
        after = _ready(state_path)
        print("mock=daemon_crash max_age=%.0f ready_before=%s/%s ready_after_expiry_no_update=%s/%s"
              % (_max_age(), before[0], before[1], after[0], after[1]))
        return 0

    if name == "missing_file":
        try:
            os.unlink(state_path)
        except Exception:
            pass
        r = _ready(state_path)
        print("mock=missing_file ready=%s/%s" % (r[0], r[1]))
        return 0

    if name == "identity_missing":
        # §4 第 1 项：container_id / started_at 缺失 ⇒ 身份不可绑定 ⇒ 不信任 ✓
        st = {"ready": True, "boot_id": boot, "container_id": "", "started_at": "",
              "config_hash": cfg, "checked_monotonic": time.monotonic(), "consecutive_ok": 2,
              "reason": "ready", "checks": []}
        _dump(state_path, st)
        r = _ready(state_path)
        print("mock=identity_missing ready=%s/%s (期望 False/identity_missing)" % (r[0], r[1]))
        return 0

    print("unknown mock %r" % name)
    return 2


def _dump(path, obj):
    import json as _json
    with open(path, "w") as fh:
        fh.write(_json.dumps(obj))


def main(argv=None):
    ap = argparse.ArgumentParser(description="unbound-alt readiness gate")
    ap.add_argument("--container", default=DEFAULT_CONTAINER)
    ap.add_argument("--addr", default=DEFAULT_ADDR)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--state", default=DEFAULT_STATE)
    ap.add_argument("--release-dir", default=None)
    ap.add_argument("--clear", action="store_true")
    ap.add_argument("--event", action="store_true")
    ap.add_argument("--mock", default=None)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    # 说明：解析器来源由环境变量 ALT_READY_RELEASE_DIR 决定（必须在 import 之前生效），
    # 因此这里**不**提供命令行覆盖；隔离副本用 `ALT_READY_RELEASE_DIR=<bundle>` 前缀 ✓。
    if _ALT is None:
        sys.stderr.write("[readiness] FATAL: alt_adapter unavailable (release dir %s)\n"
                         % _RELEASE_DIR)
        return 1
    if args.mock:
        return _mock(args.mock, args.state, args.container, args.addr, args.port)
    if args.clear:
        payload = do_clear(args.state, args.container)
        if not args.quiet:
            print("clear ready=%s reason=%s" % (payload["ready"], payload["reason"]))
        return 0
    if args.event:
        try:
            do_event_loop(args.state, args.container, args.addr, args.port)
        except KeyboardInterrupt:
            return 0
        return 0
    payload = do_check(args.addr, args.port, args.state, args.container)
    if not args.quiet:
        print("ready=%s consecutive_ok=%s reason=%s"
              % (payload["ready"], payload["consecutive_ok"], payload["reason"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
