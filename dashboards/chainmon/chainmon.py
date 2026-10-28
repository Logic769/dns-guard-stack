#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""服务器网络链路看板 —— 采集后端。

采集链路上每一跳的真实参数：
  家庭客户端(DoT 853 / DoH 444) → Nginx/TLS → AdGuard Home → dnsguard(5355)
  → unbound A(5353, 转发 → aghcf[Cloudflare DoT + censurfridns DoT 并行] → 本地 DNSSEC 验证；备用 aghdq2/Quad9 DoQ；forward-first: no)
  → dnscrypt-proxy(5399) →[DNSCrypt 匿名中继]→ 境外加密解析器
  ；CN 分流：dnscrypt-proxy forwarding-rules → unbound B(5354) → 3 条国内 DoT
     （360×1 + AliDNS×2，按 fast-server-permil 实测 RTT 优选），forward-first: no（不回退明文递归），
     其 :53 出站已被 iptables 封禁
  （「根/TLD/权威」探测已不在链路内，仅作外部参照）

只用标准库（服务器是 Python 3.6），监听 127.0.0.1:8787，由 nginx 反代到 /chain/。
纯只读：所有采集命令都是 docker exec/ps/stats/logs、读 /proc、读配置；不修改任何服务。
"""

from __future__ import print_function

import base64
import calendar
import hashlib
import json
import os
import random
import re
import socket
import socketserver
import ssl
import struct
import subprocess
import signal
import collections
import urllib.request
import sys
import threading
import time
import traceback

try:
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import urlparse, parse_qs
except ImportError:  # pragma: no cover
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
    from urlparse import urlparse, parse_qs
# 2026-10-10 Task7：看板自检资源探针（resource_probe.py 与本文件同目录）。
# 只读 /proc 与 cgroup 挂载点；journal 由 probe 内部每 300s 增量读取并按 cursor 去重。
# 探针必须与 chainmon.py 同目录；缺失时只关闭自检字段，不影响主采集。
try:
    import resource_probe as _selfprobe
except Exception:                                   # pragma: no cover - 环境缺文件
    _selfprobe = None

# API 只返回已有缓存：自检本身不允许随浏览器刷新反复重算/反复 fork journalctl。
SELF_PROBE_MIN_INTERVAL = 5.0
_SELF_PROBE_CACHE = {"ts": 0.0, "snap": None}


def self_resource_snapshot(force=False):
    """返回当前进程自检快照（带缓存）。任何异常都降级为 {"error": ...}。"""
    if _selfprobe is None:
        return {"error": "resource_probe 模块不可用",
                "detail": "期望文件: " + os.path.join(
                    globals().get("BASE_DIR", "/opt/chainmon"), "resource_probe.py")}
    now = time.time()
    _c = _SELF_PROBE_CACHE
    if (not force) and _c["snap"] is not None and (now - _c["ts"]) < SELF_PROBE_MIN_INTERVAL:
        return _c["snap"]
    try:
        snap = _selfprobe.collect_self_resources()
    except Exception as _e:
        snap = {"error": "%s: %s" % (type(_e).__name__, _e)}
    _c["ts"] = now
    _c["snap"] = snap
    return snap

# --------------------------------------------------------------------------
# 配置
# --------------------------------------------------------------------------
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 8787
BASE_DIR = "/opt/chainmon"
INDEX_FILE = os.path.join(BASE_DIR, "index.html")
HISTORY_FILE = os.path.join(BASE_DIR, "history.json")
AUTO_REFRESH_S = 60          # 页面自动刷新间隔（秒）
COLLECT_INTERVAL_S = 60      # 后台采集间隔（秒）
MANUAL_MIN_GAP_S = 5         # 手动刷新最短间隔（秒）
WINDOW_MIN = 60             # 日志统计窗口（分钟）。2026-10-09 由 15 分钟统一拓展为 1 小时：
                            # 统计窗口 / 滚动比率（前端 rollRate span=60 点）/ 图表展示（tail 取 60 点）三者同窗。
HISTORY_MAX = 120           # 走势保留点数（120 × 60s = 2 小时；图表只取最近 60 点 = 1 小时，与统计窗口一致）

AGH_CONTAINER = "adgh"
UNBOUND = [
    {"name": "unbound A", "container": "unbound", "role": "主上游：**转发** forward-zone \".\" → aghcf（Cloudflare DoT + censurfridns DoT，parallel 取最快）+ aghdq2（Quad9 DoQ）备用；IP 由 dnsguard-ip-reconcile 每 5 分钟自愈，本地 DNSSEC 验签；forward-first: no（fail-closed）", "addr": "172.18.0.1:5353", "conf": "/opt/unbound/unbound.conf"},
    {"name": "unbound B", "container": "unbound-b", "role": "CN 分流解析器：名单内 CN 域名转国内加密 DoT（按实测 RTT 优选）；非 CN 拒绝，不回头走明文", "addr": "172.18.0.1:5354", "conf": "/opt/unbound-b/unbound.conf"},
]
UNBOUND_CTL = "/opt/unbound/sbin/unbound-control"
UNBOUND_CONF_IN_CONTAINER = "/opt/unbound/etc/unbound/unbound.conf"
# 2026-10-26：入口 TLS 早已迁到 dnsdist + logic769.xyz 证书，这里仍写 dns.example.com 会让
# read_cert_live() 用旧 SNI 做 hostname 校验，必然 CertificateError，把健康链路误报成 warn。
TLS_CERT = "/www/server/panel/vhost/cert/logic769.xyz/fullchain.pem"
TLS_DOMAIN = "logic769.xyz"

AGH_ADDR = ("172.18.0.2", 53)
# --------------------------------------------------------------------------
# 探针识别：2026-10-09 由"按客户端 IP"改为"按 QNAME 滚动列表"
# --------------------------------------------------------------------------
# 旧判据 AGH_PROBE_CLIENTS={"127.0.0.1"} 有两个**不可修**的缺陷：
#   ① 只要把宿主网关 172.18.0.1 也列入，就会把家侧几乎全部 DoT 流量一起剔掉
#      （nginx stream :853 → docker-proxy → AGH 只能看到网关地址；实测 15 分钟 16,157 条里
#       只剩 6 条真实 DoH 客户端 → 看板显示"查询 0"）。
#   ② 只留 127.0.0.1 又会把**经 nginx DoH(:4443) 的流量整体误剔**：nginx 恒以 127.0.0.1 连 AGH，
#      只有带 X-Forwarded-For 的请求才会被 AGH 记成真实客户端。
#   结果：同一台机器上 **DoT 段的流量被计入、DoH 段被整体剔除**（实测 DoT 记成 172.18.0.1、
#   DoH 记成 127.0.0.1），两条曲线形状与真实负载无关 —— 这正是"折线图趋势对不上"的主因之一。
#
# 新判据：**探针自己记录它实际发出的随机冷查询 QNAME**（滚动保留一个统计窗口），
# 聚合 querylog 时按域名精确剔除。这样既不依赖 IP（不会误伤家侧 DoT/DoH 流量），
# 也不依赖固定名单。固定热探针名 www.qq.com **刻意不剔除**：它与真实流量无法区分，
# 且量级只有 3 条/分钟，单独计数并如实披露（probe_hot_not_excluded）。
PROBE_NAMES_FILE = os.path.join(BASE_DIR, "probe_names.json")
PROBE_HOT_NAME = "www.qq.com"
_PROBE_NAMES = []            # [(name, ts)]：本机探针发出过的随机域名，滚动保留 WINDOW_MIN 分钟
AGH_PROBE_CLIENTS = {"127.0.0.1"}   # 仅用于**对账计数**（probe_queries_by_ip_legacy），不再用于剔除

# 2026-10-09 阶段1/3：**探针与压测的专用源地址与通道**（详见 plan_probe_separation.md）
#   · 容器/桥接目标 → 172.18.0.99（docker0 别名，由 probe-srcaddr.service 持久化）
#   · loopback 目标   → 127.0.0.5（/8 内任意地址可直接作源，无需配置）
#   · guard 探针走**专用端口** 5356（独立 8 槽闸门），不再占用用户的 96 槽
PROBE_SRC_LOOPBACK = os.environ.get("CHAINMON_PROBE_SRC_LOOPBACK", "127.0.0.5")
PROBE_SRC_BRIDGE = os.environ.get("CHAINMON_PROBE_SRC_BRIDGE", "172.18.0.99")
PROBE_PORT = int(os.environ.get("CHAINMON_GUARD_PROBE_PORT", "5356"))
PROBE_ADDR = (os.environ.get("CHAINMON_GUARD_PROBE_HOST", "172.18.0.1"), PROBE_PORT)
# 这些源地址上来的查询视为"探针/压测"，**不进用户统计**：
#   172.18.0.99 / 127.0.0.5 = chainmon 探针与（已改造的）压测
#   127.0.0.1              = 从宿主机发起的 DoH/DoT 压测（实测今天污染 3,221 条的那部分）
# 注意：**DoT 压测与家庭 DoT 在 AGH 侧同为 172.18.0.1，无法按 IP 分开**（nginx 未透传客户端 IP），
# 这一条只能靠 QNAME 或后续给 nginx 加 PROXY protocol 解决——已在文档中如实标注。
PROBE_SRC = {PROBE_SRC_BRIDGE, PROBE_SRC_LOOPBACK, "127.0.0.1"}
UNB_A_ADDR = ("172.18.0.1", 5353)
UNB_B_ADDR = ("172.18.0.1", 5354)
DOT360_ADDR = ("218.30.118.6", 853)
ALDNS_ADDR = ("223.5.5.5", 853)      # 阿里 DoT（unbound B 的加密上游之一）
ALDNS2_ADDR = ("223.6.6.6", 853)     # 阿里 DoT 第二个 IP（2026-10-05 新增）
DOTPUB_ADDR = ("1.12.12.12", 853)    # 腾讯 DNSPod DoT（2026-10-05 新增，换运营商增冗余）
ROOT_SERVER = ("198.41.0.4", 53)   # a.root-servers.net
DNSGUARD_ADDR = ("172.18.0.1", 5355)  # dnsguard 实际监听地址（仅 Docker 网桥）
DOQ1_ADDR = ("127.0.0.1", 5534)
DNSGUARD_STATE = "/opt/dnsguard/poisoned.json"
# 2026-10-09：**自测自身资源**。用途：chainmon 曾经（旧版整包 json.loads）把内存吃到数百 MB 并引发
# 换页，事后无法归因——必须有"看板自己的 RSS/线程数"这条曲线，才能把"看板自身消耗"与"被观测对象"
# 分开，否则再次出现内存压力时仍然只能靠猜。只读 /proc/self，无副作用。
def self_rss_mb():
    try:
        with open("/proc/self/status") as _f:
            for _l in _f:
                if _l.startswith("VmRSS:"):
                    return round(int(_l.split()[1]) / 1024.0, 1)
    except Exception:
        pass
    return None


def self_threads():
    try:
        return len(os.listdir("/proc/self/task"))
    except Exception:
        return None


DNSGUARD_STATS = "/opt/dnsguard/stats.json"
# 2026-10-08：r8_auth_ok / r8_auth_none 的**真值**在 verifier 进程（核对由它执行）；
# 主进程那两个键是 verifier 接管前的历史累计值，已冻结、不再增长。
DNSGUARD_VERIFIER_STATS = "/opt/dnsguard/verifier-state/stats.json"
DNSGUARD_LOG = "/var/log/dnsguard.log"

# ===== P34-BP（方案任务6）：**日志流式读取 + inode/截断处理 + 同轮缓存** =====
# 背景 ✗：原三处读取（recent / _all_recent / fail_closed_reason）都 `open(...)` 后**整读整文件**
# ⇒ 每次指标刷新约 3 次全文件扫描（日志已数 MB 且持续增长 ✓）；且无 inode/截断处理 ✗。
# 改法 ✓：只读**末尾有界窗口** + 逐行 deque 保留最后 N 行 + 以 (ino, size) 缓存 ⇒ 一轮只读一次 ✓；
#         inode 变更（logrotate create ✓）或 size 回退（截断 ✓）⇒ 新基线（记入 _LOG_STATE ✓）。
_LOG_STATE = {}          # path -> {"ino": int, "off": int, "rotations": int, "truncations": int, "reads": 0}
_LOG_CACHE = {}          # path -> {"ino": int, "size": int, "raw": [line, ...]}
# 2026-10-28 内存修复：旧键把 st_size 编进 (path, ino, size, want)，而 dnsguard.log 每写一行
# size 就变 => 同一个日志文件每轮采集新增 3 条缓存（want=10/500/5000），实测净增 5508 行
# 字符串 / +3MB RSS 每轮，涨到 64 条上限后在 30-60 条之间震荡 => 稳态 100MB+，此前靠
# chainmon-restart.service 每小时重启一次掩盖。现改为**按文件路径单槽缓存**（只保留最近
# 6000 行原文），小 want 由大缓存切片得到，每轮只读一次文件（原来读 3 次）=> 内存与 CPU 同时下降。
_LOG_KEEP = 6000         # 单文件缓存的最大行数（覆盖最大调用方 want=5000）


# 2026-10-28：Python 逐行解码会把 glibc arena 高水位顶高（见 1595 行记录，实测 16000 行时
# 稳态 231MB）。采集结束后主动 malloc_trim，把已释放的 arena 还给内核，稳态 RSS 才能贴近
# 真实对象大小而不是历史峰值。
try:
    import ctypes as _ctypes
    _LIBC = _ctypes.CDLL("libc.so.6")
    # 2026-10-28 内存修复的核心：glibc 默认每个线程新建一个 malloc arena（上限 8*核数）。
    # chainmon 每轮采集都用 parallel() 起线程池 => 线程不断新建/回收 => arena 越攒越多，
    # 已释放的内存留在各自 arena 里，malloc_trim 也收不回来。实测：不设此项连续 8 轮采集
    # RSS 20MB -> 68MB（线性 +5.5MB/轮，旧版靠每小时重启掩盖）；设为 2 后第 3 轮起稳定在
    # 30.1-30.9MB。M_ARENA_MAX = -8。必须在任何线程创建之前调用，故放在模块初始化处。
    _LIBC.mallopt(-8, 2)
except Exception:
    _LIBC = None


def _malloc_trim():
    try:
        if _LIBC is not None:
            _LIBC.malloc_trim(0)
    except Exception:
        pass


def _drop_cache(path):
    """把刚读过的日志文件的 page cache 还给内核。

    2026-10-28：RSS 稳定在 26MB 后，cgroup 的 MemoryCurrent 仍会周期性地冲到 68MB ——
    那是每轮读 dnsguard.log(5MB)/dnsdist-query.log(8MB) 带进来的 page cache。它对 cgroup
    内存上限是真的计数，会挤占同机 DNS 进程。日志是追加型且每分钟重读一次尾部，缓存没有
    复用价值，读后 DONTNEED 掉即可。
    """
    try:
        fd = os.open(path, os.O_RDONLY)
        try:
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        finally:
            os.close(fd)
    except Exception:
        pass


def _log_tail(path, want, max_bytes=3000000, max_lines=200000):
    """返回该日志**末尾 want 行**（有界读取 , 不整读 ）。同一文件只在内容变化时读一次 。"""
    try:
        stt = os.stat(path)
    except Exception:
        return []
    want = max(1, int(want))
    ino = int(stt.st_ino)
    size = int(stt.st_size)
    keep = max(_LOG_KEEP, want)
    slot = _LOG_CACHE.get(path)
    if slot is not None and slot.get("ino") == ino and slot.get("size") == size:
        raw = slot["raw"]
    else:
        st = _LOG_STATE.setdefault(path, {"ino": ino, "off": 0,
                                          "rotations": 0, "truncations": 0, "reads": 0})
        if st["ino"] != ino:
            st["ino"] = ino
            st["rotations"] += 1
            st["off"] = 0
        if size < st["off"]:
            st["truncations"] += 1
            st["off"] = 0
        st["reads"] += 1
        start = max(0, size - max(0, int(max_bytes)))
        buf = collections.deque(maxlen=keep)
        try:
            with open(path, "rb") as f:
                f.seek(start)
                if start > 0:
                    f.readline()
                n = 0
                for raw_line in f:
                    n += 1
                    if n > int(max_lines):
                        break
                    buf.append(raw_line.decode("utf-8", "replace").rstrip())
        except Exception:
            return []
        st["off"] = size
        raw = list(buf)
        _LOG_CACHE[path] = {"ino": ino, "size": size, "raw": raw}
    return [l for l in raw[-want:] if l.strip()]

# 2026-10-09 B1/C1：
#  B1 —— guard 的 fail_closed_by_reason 已按原因分类（admission_overload=本地闸门堵塞、
#        unbound_servfail=上游真实失败、known_poison=已判投毒）。此前看板把它们都并进一个
#        fail_closed 数字，用户无法区分"我这边堵了"还是"上游真的坏了"。这里分解 + 加每分钟速率。
#  C1 —— 拥塞 SERVFAIL 会被 AGH 当正常应答写进缓存（实测存活 p50 179s / max 596s，
#        一次压测影响 242 个真实域名）⇒ 过载结束后仍有数分钟解析失败。因此在"一次拥塞
#        事件结束"（拒绝增量归零且此前峰值够大）时自动清一次 AGH 缓存。
CACHE_CLEAR_MIN_REJECTS = int(os.environ.get("CHAINMON_CACHE_CLEAR_MIN_REJECTS", "50"))
CACHE_CLEAR_COOLDOWN = int(os.environ.get("CHAINMON_CACHE_CLEAR_COOLDOWN", "600"))
_GUARD_PREV = {"t": 0.0, "adm": 0, "ar": 0, "peak": 0, "clears": 0, "last_clear": 0.0,
               "last_clear_reason": "",
               # P34-BQ（方案任务6）：按 **PID/boot_ts** 判定守护重启 ⇒ 新基线 ✓（不再跨 boot 污染 ✗）
               "boot": None, "pid": None, "restarts": 0}


def _guard_baseline_gate(st0):
    """守护是否**换了一次启动**（boot_ts/pid 变 ✓）⇒ 视为**新基线** ✓。

    返回 True 表示"本轮是新基线"：调用方应**跳过速率计算** ✓（绝不用跨重启的脏 delta ✗），
    并已把 t/adm/ar/peak 清零、restarts 累加 ✓。纯函数式判定 ⇒ 可单独切片真测 ✓。
    """
    _gp = _GUARD_PREV
    _boot = st0.get("boot_ts")
    _pid = st0.get("pid")
    if _boot is None and _pid is None:
        return True                     # 拿不到证据 ⇒ 不据此算速率 ✓
    if _gp.get("boot") != _boot or _gp.get("pid") != _pid:
        _gp["boot"] = _boot
        _gp["pid"] = _pid
        _gp["restarts"] = int(_gp.get("restarts") or 0) + 1
        _gp["t"] = 0.0
        _gp["adm"] = 0
        _gp["ar"] = 0
        _gp["peak"] = 0                # ★ 峰值必须清 ✓ —— 否则会拿上个 boot 的峰值去清 AGH 缓存 ✗
        return True
    return False
# dnscrypt-proxy（2026-10-05 引入的加密解析代理；unbound 的 forward 目标）
DNSCRYPT_SERVICE = "dnscrypt-proxy-local"
DNSCRYPT_ADDR = ("127.0.0.1", 5399)      # 仅回环可达（2026-10-10 F1 修复：
                                         # 旧值 172.18.0.1 暴露给所有容器 ⇒ 可绕过 guard；
                                         # P1 后 unbound 已不再转发到这里）
DNSCRYPT_PROBE = ("127.0.0.2", 5353)      # 看板探针用（宿主 loopback）
DNSCRYPT_CONF = "/opt/dnscrypt-proxy/dnscrypt-proxy.toml"
DNSCRYPT_RULES = "/opt/dnscrypt-proxy/forwarding-rules.txt"
DNSCRYPT_LOG = "/var/log/cn-rules-refresh.log"
GUARD_POISON_SAMPLE = {"46.82.174.68","59.24.3.173","78.16.49.15","159.106.121.75","8.7.198.45",
                       "203.98.7.65","243.185.187.39","37.61.54.158","93.46.8.89","2001::1",
                       "180.163.151.162","157.240.7.20","31.13.92.37"}

RC_NAME = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

# --------------------------------------------------------------------------
# 基础工具
# --------------------------------------------------------------------------
def sh(cmd, timeout=20.0):
    """执行命令，返回 (rc, stdout, stderr)。cmd 可为字符串或参数列表 ✓。

    P34-BO（方案任务6）：原实现 `Popen(shell=True)` + `communicate(timeout=)` ✗ ⇒ 超时只中断
    直接子进程 ✗，命令内再起的 `docker exec`/`iptables` 等可能变**孤儿**继续跑 ✗。
    现改为：独立会话（`start_new_session=True` = setsid ✓ ⇒ 自成进程组）+ 超时
    `killpg(TERM→KILL)` 杀**整组** ✓ + `wait()` 回收 ✓；命令以**参数列表**交给 `/bin/sh -c`
    （不再用 shell=True ✓）。返回值契约与原来**完全一致** ✓（33 个调用点无需改动 ✓）。
    """
    argv = cmd if isinstance(cmd, (list, tuple)) else ["/bin/sh", "-c", str(cmd)]
    p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         start_new_session=True)
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        except Exception:
            pass
        try:
            out, err = p.communicate(timeout=1.5)
        except Exception:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except Exception:
                pass
            try:
                out, err = p.communicate(timeout=2.0)
            except Exception:
                out, err = b"", b""
        try:
            p.wait(timeout=2.0)
        except Exception:
            pass
    return (p.returncode,
            out.decode("utf-8", "replace") if out else "",
            err.decode("utf-8", "replace") if err else "")


def sh_argv(argv, timeout=20.0):
    """真正的**参数列表**调用 ✓（不经 shell ✓，新增接口 ✓）。"""
    return sh(list(argv), timeout=timeout)




def dsh(cmd, timeout=20.0):
    """只取 stdout。"""
    return sh(cmd, timeout)[1]


def pct(vals, p):
    if not vals:
        return 0.0
    v = sorted(vals)
    n = len(v)
    # 2026-10-09 统计修正：偶数样本的中位数应取中间两值的**平均**。
    # 旧写法 round(0.5*(n-1)) 在 n=2 时得 0 → 取"两样本较小值"却被标成 p50
    # （verify_C.md 第 14 项：4 张冷查询图每轮只有 2 个样本，标 p50 属伪分位）。
    # p90/p99 仍用最近秩（nearest-rank），口径不变。
    if p == 0.5 and n % 2 == 0:
        return (v[n // 2 - 1] + v[n // 2]) / 2.0
    return v[int(round((n - 1) * p))]


def fmt_ms(v):
    """把毫秒格式化成带单位的可读文本，用于链路节点摘要。"""
    try:
        v = float(v)
    except Exception:
        return "-"
    if v >= 1000:
        return "%.2f s" % (v / 1000.0)
    if v >= 100:
        return "%.0f ms" % v
    return "%.1f ms" % v


def rnd(n=10):
    return "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))


# --------------------------------------------------------------------------
# 2026-10-10 §1 业务基线仪表（daily-latency-plan §1）
#   guard 侧在 stats.json 的 `base` 键里给出**有界分桶**快照：
#     base.c      —— 计数（qtype/CN/入口/来源/rcode/阈值/标志/各来源尝试次数）
#     base.h      —— 定长直方图（每键 17 桶，桶边界 base.bounds），用于算 p50/p90/p95/p99
#     base.unk    —— 落到白名单外的键名（应为空；非空说明仪表白名单漏项）
#   chainmon 只做**读取 + 分位换算**，不复制计数、不额外起任务 ✓。
# --------------------------------------------------------------------------
def _hist_quantile(row, bounds, p):
    """从定长直方图算分位（返回桶**右边界**的上界估计，ms）。

    统计口径：桶 i 覆盖 (bounds[i-1], bounds[i]]，末桶是 "> bounds[-1]"。
    返回该分位所在的桶右边界 ⇒ 是**保守上界**（真实值 ≤ 该值）✓；样本不足返回 None。
    """
    try:
        n = sum(int(x or 0) for x in row)
        if n <= 0:
            return None
        want = int(p * n + 0.999999)   # 最近秩（向上取整，避免依赖 math）
        want = max(1, min(n, want))
        c = 0
        for i, x in enumerate(row):
            c += int(x or 0)
            if c >= want:
                return float(bounds[i]) if i < len(bounds) else None
        return None
    except Exception:
        return None


def _base_metrics(st0, vst):
    """把 guard `base` 分桶 + verifier `v_*` 计数折成看板字段（容错：任何字段缺失都不报错）。"""
    b = st0.get("base")
    if not isinstance(b, dict):
        b = {}
    c = b.get("c") if isinstance(b.get("c"), dict) else {}
    h = b.get("h") if isinstance(b.get("h"), dict) else {}
    bounds = b.get("bounds") if isinstance(b.get("bounds"), list) else []
    vst = vst if isinstance(vst, dict) else {}

    def _g(k):
        try:
            return int(c.get(k) or 0)
        except Exception:
            return 0

    def _s(k):
        """读 guard `stats.json` **顶层**计数 ✓ —— 与 `_g` 的"分桶"口径必须分开 ✗。

        ★ 这里踩过一次坑：`ttl_*` / `neg_*` / `adm_cache_*` / `pin_invalidated_*` 是
        `_stats[...]` 直写的**顶层**键 ✗，不是 `base.c` 分桶键 ⇒ 用 `_g` 读它们会
        恒得 0（静默显示成"零命中" ✗，比报错更坏 —— 会让人误判优化无效 ✗）。
        分桶的只有 `_b_inc()` 写过的那批（`src_*`、`attres_*`、`base_*`…）✓。
        """
        try:
            return int(st0.get(k) or 0)
        except Exception:
            return 0

    def _q(name, p):
        row = h.get(name)
        if not row or not bounds:
            return None
        return _hist_quantile(row, bounds, p)

    def _pct(a, d):
        try:
            return round(100.0 * float(a) / float(d), 1) if d else None
        except Exception:
            return None

    out = {
        # 仪表元信息
        "base_instr": bool(b.get("instr")),
        "base_sample": bool(b.get("sample")),
        "base_unknown_keys": list(b.get("unk") or [])[:12],
        "base_bounds_ms": list(bounds),
        # 样本量（方案 §1 的验收门槛：A≥200 / AAAA≥100 / HTTPS≥100 / CN≥100）
        "samples_a": _g("q_a"),
        "samples_aaaa": _g("q_aaaa"),
        "samples_https": _g("q_https"),
        "samples_cn": _g("q_a_cn") + _g("q_aaaa_cn") + _g("q_https_cn"),
        # 端到端耗时分位（按 qtype 分列 + 合计），单列 guard（AGH 侧另计）
        "guard_lat_p50_ms": _q("ms_all", 0.5),
        "guard_lat_p95_ms": _q("ms_all", 0.95),
        "guard_lat_p99_ms": _q("ms_all", 0.99),
        "guard_lat_a_p95_ms": _q("ms_a", 0.95),
        "guard_lat_aaaa_p95_ms": _q("ms_aaaa", 0.95),
        "guard_lat_https_p95_ms": _q("ms_https", 0.95),
        # 长尾占比与 SERVFAIL
        "gt1000ms_pct": _pct(_g("gt1000ms_all"), max(1, _g("q_a") + _g("q_aaaa") + _g("q_https")
                                                    + _g("q_other"))),
        "gt2000ms_pct": _pct(_g("gt2000ms_all"), max(1, _g("q_a") + _g("q_aaaa") + _g("q_https")
                                                    + _g("q_other"))),
        "gt4000ms_pct": _pct(_g("gt4000ms_all"), max(1, _g("q_a") + _g("q_aaaa") + _g("q_https")
                                                    + _g("q_other"))),
        "base_servfail": _g("servfail_a") + _g("servfail_aaaa") + _g("servfail_https")
                         + _g("servfail_other"),
        # 排队时长（入队→处理）
        "wait_p95_ms": _q("wait_all", 0.95),
        # 来源分布（最终来源 = 出口闸门采用的类别）
        # §2-b：`local-b` 永不作为最终来源出现 ✓；`witness` 与 `local-a` 分开计 ✓ ⇒
        # 从此"本地验证器 A 的采纳率"不再被见证通道的证据污染 ✗→✓。
        "src_local_a": _g("src_local-a"),
        "src_local_alt": _g("src_local-alt"),
        "src_local_b": _g("src_local-b"),
        "src_witness": _g("src_witness"),
        "src_clean_channel": _g("src_clean-channel"),
        "src_negative_cache": _g("src_negative-cache"),
        "src_strict": _g("src_strict"),
        "src_none": _g("src_none"),
        # §2-a：有效期来源与零 TTL 拒绝（证明"未把零 TTL 答案补成固定值"✓）
        "ttl_src_wire": _s("ttl_src_wire"),
        "ttl_zero_a": _s("ttl_zero_a"),
        "ttl_zero_alt": _s("ttl_zero_alt"),
        "ttl_zero_witness": _s("ttl_zero_witness"),
        "neg_ttl_forward": _s("neg_ttl_forward"),
        "neg_ttl_negative": _s("neg_ttl_negative"),
        "neg_ttl_negative_unproven": _s("neg_ttl_negative_unproven"),
        "neg_cache_skip_unproven": _s("neg_cache_skip_unproven"),
        "neg_cache_skip_zero_ttl": _s("neg_cache_skip_zero_ttl"),
        # §2 第 48/50/51 行：准入缓存的准入/命中/失效与**视图拒绝** ✓ ——
        # `adm_cache_invalidated*` 与 `pin_invalidated*` 是"新观察到 bogus/强否决后
        # 旧答案还能不能出去"的判据 ✓（方案第 51 行后半句）；`adm_cache_view_mismatch`
        # 是"无法证明同一视图时不共用缓存"的判据 ✓（方案第 48 行）。
        "adm_cache_put": _s("adm_cache_put"),
        "adm_cache_ttl_zero": _s("adm_cache_ttl_zero"),
        "adm_cache_expired": _s("adm_cache_expired"),
        "adm_cache_invalidated": _s("adm_cache_invalidated"),
        "adm_cache_invalidated_bogus": _s("adm_cache_invalidated_bogus"),
        "adm_cache_invalidated_zone_pin": _s("adm_cache_invalidated_zone_pin"),
        "pin_invalidated_bogus": _s("pin_invalidated_bogus"),
        "pin_invalidated_zone_pin": _s("pin_invalidated_zone_pin"),
        "pin_invalidated_mark_strong": _s("pin_invalidated_mark_strong"),
        "pin_invalidated_mark_new": _s("pin_invalidated_mark_new"),
        "neg_invalidated_bogus": _s("neg_invalidated_bogus"),
        "neg_invalidated_zone_pin": _s("neg_invalidated_zone_pin"),
        "neg_invalidated_mark_strong": _s("neg_invalidated_mark_strong"),
        "neg_invalidated_mark_new": _s("neg_invalidated_mark_new"),
        "adm_cache_view_mismatch": _s("adm_cache_view_mismatch"),
        "adm_cache_schema_reject": _s("adm_cache_schema_reject"),
        "adm_cache_evidence_expired": _s("adm_cache_evidence_expired"),
        "adm_cache_reput_same": _s("adm_cache_reput_same"),
        # §3「消除 CN 路径重复取数与重复重试」观测量 ✓ ——
        # 判据：`*_dup_skipped` 与 `src_reuse_*` **必须 > 0 才算去重真的在生效** ✓
        #（全 0 有两种含义：要么没并发（正常低负载 ✓），要么闸门没接上（缺陷 ✗））；
        # `cn_sf_lead` 与 `cn_sf_merge/served` 的比值就是"合并率" ✓（方案第 73 行）；
        # `dl_exhausted` 与 `strict_budget_skip` 是"预算已尽不再新开预算"的判据 ✓（第 67 行）。
        "dl_exhausted": _s("dl_exhausted"),
        "dl_clamped": _s("dl_clamped"),
        "a_dup_skipped": _s("a_dup_skipped"),
        "b_dup_skipped": _s("b_dup_skipped"),
        "witness_dup_skipped": _s("witness_dup_skipped"),
        "alt_dup_skipped": _s("alt_dup_skipped"),
        "fin_alt_dup_skipped": _s("fin_alt_dup_skipped"),
        "fin_retry_alt_dup": _s("fin_retry_alt_dup"),
        "fin_retry_witness_dup": _s("fin_retry_witness_dup"),
        "policy_hint_wire_used": _s("policy_hint_wire_used"),
        "policy_hint_wire_missing": _s("policy_hint_wire_missing"),
        "policy_hint_refetch_fail": _s("policy_hint_refetch_fail"),
        "cn_sf_lead": _s("cn_sf_lead"),
        "cn_sf_merge": _s("cn_sf_merge"),
        "cn_sf_served": _s("cn_sf_served"),
        "cn_sf_wait_ok": _s("cn_sf_wait_ok"),
        "cn_sf_wait_timeout": _s("cn_sf_wait_timeout"),
        "cn_sf_budget_skip": _s("cn_sf_budget_skip"),
        # §3：等锁成功但领跑者已发布 ⇒ **让位复用** ✓ / 上游全失败 ⇒ **回 SERVFAIL 而非静默丢包** ✓
        # ★ 这两个键是"完成门首轮暴露的两个缺陷"的**常驻回归哨兵** ✓：
        #   `cn_sf_reuse_handoff` 长期为 0 说明等待者又在串行重查 ✗（A=100/100 那个病 ✗）；
        #   `resp_servfail_built` 长期为 0 而 `dl_exhausted>0` 说明又出现静默丢包 ✗。
        "cn_sf_reuse_handoff": _s("cn_sf_reuse_handoff"),
        "resp_servfail_built": _s("resp_servfail_built"),
        "strict_budget_skip": _s("strict_budget_skip"),
        # §4：alt readiness 与运输断路器的可观测项 ✓ —— 全部是 `_stats[...]` **顶层**口径
        #   ⇒ 必须用 `_s()` ✓（`_g()` 读的是 `base.c` 分桶，恒得 0 ✗ —— 本项目已踩过 ✗）。
        # ★ 判读对照（方案第 90 行的完成门）：
        #   `alt_not_ready` 高而 `alt_unavailable_skip` 同步 ⇒ 健康门在**正确地**少发无用包 ✓；
        #   `alt_transport_fail` 长期高、`alt_breaker_trips` 不涨 ⇒ 断路器没接上 ✗；
        #   `alt_ready` 与 `alt_not_ready` 都不涨 ⇒ readiness 闸门根本没被调用 ✗（旧病 ✗）。
        "alt_ready": _s("alt_ready"),
        "alt_not_ready": _s("alt_not_ready"),
        "alt_unavailable_skip": _s("alt_unavailable_skip"),
        "alt_ready_missing": _s("alt_ready_missing"),
        "alt_ready_stale": _s("alt_ready_stale"),
        "alt_ready_identity_changed": _s("alt_ready_identity_changed"),
        "alt_ready_config_changed": _s("alt_ready_config_changed"),
        "alt_ready_other": _s("alt_ready_other"),
        "alt_breaker_trips": _s("alt_breaker_trips"),
        "alt_transport_ok": _s("alt_transport_ok"),
        "alt_transport_fail": _s("alt_transport_fail"),
        "alt_half_open_ok": _s("alt_half_open_ok"),
        "alt_half_open_fail": _s("alt_half_open_fail"),
        # CN 路径与 B 的使用（安全语义相关的可观测项）
        "cn_path": _g("f_cn_path"),
        "b_used": _g("f_b_used"),
        "veto_hit": _g("f_veto_hit"),
        "veto_none": _g("f_veto_none"),
        "policy_fastpath": _g("f_policy_fastpath"),
        "policy_used": _g("f_policy_used"),
        "adm_cache_hit": _g("f_adm_hit"),
        "guard_cache_hit": _g("f_cache_hit"),
        # 各来源耗时与结果
        "stage_a_p95_ms": _q("att_a", 0.95),
        "stage_b_p95_ms": _q("att_b", 0.95),
        "stage_bget_p95_ms": _q("att_bget", 0.95),
        "stage_witness_p95_ms": _q("att_witness", 0.95),
        "stage_alt_p95_ms": _q("att_alt", 0.95),
        "stage_r8_p95_ms": _q("att_r8", 0.95),
        "stage_ipc_p95_ms": _q("att_ipc", 0.95),
        "stage_clean_p95_ms": _q("att_clean", 0.95),
        "stage_domestic_p95_ms": _q("att_domestic", 0.95),
        "attempts_a": _g("attres_a_ok") + _g("attres_a_fail"),
        "attempts_b": _g("attres_b_ok") + _g("attres_b_fail"),
        "attempts_alt": _g("attres_alt_ok") + _g("attres_alt_fail"),
        "attempts_witness": _g("attres_witness_ok") + _g("attres_witness_fail"),
        "attempts_r8": _g("attres_r8_ok") + _g("attres_r8_fail") + _g("attres_r8_timeout")
                       + _g("attres_r8_skip"),
        "attempts_ipc": _g("attres_ipc_ok") + _g("attres_ipc_fail") + _g("attres_ipc_timeout"),
        "retry_alt": _g("f_retry_alt"),
        "retry_witness": _g("f_retry_witness"),
        "retry_fail": _g("f_retry_fail"),
        "hedge_started": _g("f_hedge_started") or int(st0.get("clean_races") or 0),
        "hedge_won": _g("f_hedge_won") or int(st0.get("clean_hedged") or 0),
        "budget_skip": _g("f_budget_skip"),
        "fail_closed_instr": _g("f_fail_closed"),
        # 业务 / 探针分开 —— 口径（Step-1 §1）：entry_* = **入口类别（谁在问）**，不是协议 ✓
        #   entry_client = 172.18.0.2（经 AdGuard Home 的家用设备）⇒ 与 base_q 之差可算主机侧占比
        "entry_client": _g("entry_client") or _g("entry_udp"),
        "entry_host": _g("entry_host"),
        "entry_loopback": _g("entry_loopback"),
        "entry_other": _g("entry_other"),
        "entry_probe": _g("entry_probe"),
        # 协议口径（保留，便于与旧看板对照；release-9 起 entry_* 语义已改为类别）
        "entry_udp": _g("entry_udp"),
        "entry_tcp": _g("entry_tcp"),
        # 按来源类别逐请求计数（可直接与 base_q 相减算用户侧占比 ✓）
        "base_cls_client": int(st0.get("base_cls_client") or 0),
        "base_cls_host": int(st0.get("base_cls_host") or 0),
        "base_cls_loopback": int(st0.get("base_cls_loopback") or 0),
        "base_cls_other": int(st0.get("base_cls_other") or 0),
        # **原样透传** guard 侧按请求级汇总的原始计数（可用两次快照算 delta ✓）
        "base_q": int(st0.get("base_q") or 0),
        "base_cache": int(st0.get("base_cache") or 0),
        "base_hedge": int(st0.get("base_hedge") or 0),
        "base_cn": int(st0.get("base_cn") or 0),
        "base_retry": int(st0.get("base_retry") or 0),
        "base_a_ok": int(st0.get("base_a_ok") or 0),
        "base_b": int(st0.get("base_b") or 0),
        "base_witness": int(st0.get("base_witness") or 0),
        "base_alt_order": int(st0.get("base_alt_order") or 0),
        # verifier 侧（**同一请求追踪 ID**，与 guard 分开统计）
        "verifier_recv": int(vst.get("v_recv") or 0),
        "verifier_rid_present": int(vst.get("v_rid_present") or 0),
        "verifier_rid_absent": int(vst.get("v_rid_absent") or 0),
        "verifier_pool_r3": int(vst.get("v_pool_r3") or 0),
        "verifier_pool_corrob": int(vst.get("v_pool_corrob") or 0),
        "verifier_pool_strict": int(vst.get("v_pool_strict") or 0),
        "verifier_pool_veto": int(vst.get("v_pool_veto") or 0),
        "verifier_pool_overload": int(vst.get("v_pool_overload") or 0),
        "verifier_err": int(vst.get("v_err") or 0),
        "verifier_badframe": int(vst.get("v_badframe") or 0),
        "verifier_ms_avg": vst.get("v_ms_avg"),
    }
    # 样本门槛达成情况（方案 §1 明确要求 A≥200、AAAA≥100、HTTPS≥100、CN≥100）
    out["samples_ok"] = bool(out["samples_a"] >= 200 and out["samples_aaaa"] >= 100
                             and out["samples_https"] >= 100 and out["samples_cn"] >= 100)
    out["samples_gap"] = {
        "a": max(0, 200 - out["samples_a"]), "aaaa": max(0, 100 - out["samples_aaaa"]),
        "https": max(0, 100 - out["samples_https"]), "cn": max(0, 100 - out["samples_cn"]),
    }
    return out


# --------------------------------------------------------------------------
# 探针 QNAME 登记：聚合 AGH querylog 时按域名精确剔除看板自身探针
# （判据设计见文件顶部 PROBE_NAMES_FILE / AGH_PROBE_CLIENTS 段注释）
# --------------------------------------------------------------------------
def _remember_probe_name(name):
    if not name:
        return
    _PROBE_NAMES.append((name, time.time()))
    cutoff = time.time() - WINDOW_MIN * 60
    while _PROBE_NAMES and _PROBE_NAMES[0][1] < cutoff:
        _PROBE_NAMES.pop(0)


def load_probe_names():
    """启动时载入滚动探针域名表：跨链看板重启保持，避免重启后旧探针条目被当成真实流量。"""
    global _PROBE_NAMES
    try:
        with open(PROBE_NAMES_FILE) as f:
            raw = json.load(f)
        cutoff = time.time() - WINDOW_MIN * 60
        _PROBE_NAMES = [(str(n), float(t)) for n, t in raw if float(t) >= cutoff]
    except Exception:
        _PROBE_NAMES = []


def save_probe_names():
    try:
        tmp = PROBE_NAMES_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(_PROBE_NAMES, f)
        os.replace(tmp, PROBE_NAMES_FILE)
    except Exception:
        pass


def probe_name_set():
    cutoff = time.time() - WINDOW_MIN * 60
    return set(n for n, t in _PROBE_NAMES if t >= cutoff)


def parallel(fns, timeout=25.0):
    """并发执行若干无参函数，返回结果列表（异常记为 None）。"""
    results = [None] * len(fns)

    def wrap(i, fn):
        try:
            results[i] = fn()
        except Exception:
            results[i] = None

    ths = [threading.Thread(target=wrap, args=(i, fn)) for i, fn in enumerate(fns)]
    for t in ths:
        t.daemon = True
        t.start()
    deadline = time.time() + timeout
    for t in ths:
        t.join(max(0.05, deadline - time.time()))
    return results


# --------------------------------------------------------------------------
# DNS 探测
# --------------------------------------------------------------------------
def dns_encode_name(name):
    return b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"


def dns_build(name, qtype=1, edns=True):
    flags = 0x0100
    arcount = 1 if edns else 0
    extra = b"\x00" + struct.pack(">HHIH", 41, 1232, 0, 0) if edns else b""
    return (struct.pack(">HHHHHH", random.randint(0, 65535), flags, 1, 0, 0, arcount) +
            dns_encode_name(name) + struct.pack(">HH", qtype, 1) + extra)


def _probe_bind_addr(addr):
    """2026-10-09 阶段1：探针按目标选择专用源地址，使各层能按 IP 区分探针与用户。"""
    try:
        ip = addr[0]
    except Exception:
        return None
    if ip.startswith("127."):
        return PROBE_SRC_LOOPBACK
    return PROBE_SRC_BRIDGE


def dns_ask(addr, name, qtype=1, timeout=2.5):
    """返回 (毫秒, rcode)。失败抛异常。2026-10-09：绑定探针专用源地址。"""
    body = dns_build(name, qtype)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    _bs = _probe_bind_addr(addr)
    if _bs:
        try:
            s.bind((_bs, 0))
        except Exception:
            pass
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.sendto(body, addr)
        data, _ = s.recvfrom(4096)
        ms = (time.time() - t0) * 1000.0
    finally:
        s.close()
    flags = struct.unpack(">H", data[2:4])[0]
    return ms, flags & 0xF


def tcp_probe(addr, timeout=2.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect(addr)
        return (time.time() - t0) * 1000.0
    finally:
        s.close()


def probe_target(label, addr, scenario, name_fn, samples, cost=None, via_b=False,
                 record_name=False, warmup=False):
    out = {"target": label, "addr": "%s:%d" % addr, "label": scenario,
           "samples_ms": [], "p50_ms": 0.0, "max_ms": 0.0, "rcode": "-", "status": "ok",
           "cost_ms": 0.0}
    t_start = time.time()
    errs = 0
    # 2026-10-26：热缓存场景先发一条**不计时**的预热包。
    # 根因：探针 3 个包串行发送，一旦采集瞬间恰好 TTL 过期，3 个包都会回源，
    # p50 就等于上游往返（unbound A 经 DoQ 实测 243ms），"热缓存"探针因此被判 warn
    # （此前出现过 p50=187.9ms）。预热后计时包必然落在缓存命中路径上；
    # 若 unbound 真的不缓存（真故障），预热也不会救回来，仍会报慢。
    if warmup:
        try:
            dns_ask(addr, name_fn(0))
        except Exception:
            pass
    for i in range(samples):
        nm = name_fn(i)
        if record_name and nm != PROBE_HOT_NAME:
            _remember_probe_name(nm)
        try:
            ms, rc = dns_ask(addr, nm)
            out["samples_ms"].append(round(ms, 2))
            out["rcode"] = RC_NAME.get(rc, "rcode=%s" % rc)
        except socket.timeout:
            errs += 1
        except Exception:
            errs += 1
    vals = out["samples_ms"]
    if vals:
        out["p50_ms"] = round(pct(vals, 0.5), 2)
        out["max_ms"] = round(max(vals), 2)
    if errs and not vals:
        out["status"] = "error"
        out["rcode"] = "超时"
    elif errs:
        out["status"] = "warn"
    elif vals and pct(vals, 0.5) > 1000:
        out["status"] = "warn"
    # 2026-10-08 第7步：把"实际发出多少条探针"显式导出。
    # 用途：unbound B 的消费者归类要把 chainmon 自己打进 B 的探针单独扣掉，
    # 否则 ΔB 与 Δguard 对不上账（sent=成功的样本数，errs=超时/异常也是真发出去的）。
    out["sent"] = samples + (1 if warmup else 0)
    out["errs"] = errs
    # 2026-10-08 第8步：via_b=True 表示"这条探针最终会由被探对象转发进 unbound B"。
    # 目前只有打给 dnscrypt-proxy 的 **CN** 探针属于此类（CN forwarding-rules → 127.0.0.1:5354）。
    out["via_b"] = bool(via_b)
    out["probe_only"] = True
    out["random_cold"] = ("随机" in (scenario or ""))
    out["cost_ms"] = round((time.time() - t_start) * 1000.0, 1)
    if cost is not None:
        out["cost_ms"] = cost
    return out


def collect_probes():
    hot = lambda i: "www.qq.com"          # noqa: E731
    cold = lambda i: rnd() + ".com"       # noqa: E731
    # 2026-10-08 第7步：**B 只服务 CN 域名**，所以打给 B 的冷查询探针也必须用 CN 名字。
    # 旧实现给 B 发的是 "冷 <随机>.com"（每轮 2 条非 CN 查询）—— 那是绕过 dnsguard 收口、
    # 直接给 B 送非 CN 流量的唯一来源（探针直连 172.18.0.1:5354，不经 guard）。
    # 换成随机 .cn 后：冷缓存延迟口径不变（仍是未命中的一次上游往返），但不再违反 CN-only。
    cold_cn = lambda i: rnd() + ".cn"     # noqa: E731
    jobs = [
        lambda: probe_target("AGH", AGH_ADDR, "热缓存 www.qq.com", hot, 3, warmup=True),
        lambda: probe_target("AGH", AGH_ADDR, "冷 <随机>.com", cold, 2, record_name=True),
        lambda: probe_target("unbound A", UNB_A_ADDR, "热缓存 www.qq.com", hot, 3, warmup=True),
        lambda: probe_target("unbound A", UNB_A_ADDR, "冷 <随机>.com", cold, 2, record_name=True),
        lambda: probe_target("unbound B", UNB_B_ADDR, "热缓存 www.qq.com", hot, 3, warmup=True),
        lambda: probe_target("unbound B", UNB_B_ADDR, "冷 <随机>.cn", cold_cn, 2, record_name=True),
        # 2026-10-08 第8步：这两条**热**探针用的是 CN 域名（www.qq.com），dnscrypt 的 CN
        # forwarding-rules 会把它们转发到 127.0.0.1:5354 = unbound B ⇒ via_b=True，
        # 让 b_attrib 把它们算进 cn_rules 而不是当成"未登记消费者"。
        # 冷探针用 <随机>.com（不在 CN 规则里）→ 由 dnscrypt 自己走加密上游，**不经 B**。
        lambda: probe_target("dnscrypt-proxy", DNSCRYPT_PROBE, "热缓存 www.qq.com", hot, 3,
                             via_b=True, warmup=True),
        lambda: probe_target("dnscrypt-proxy", DNSCRYPT_PROBE, "冷 <随机>.com", cold, 2),
        # 2026-10-09 阶段3：guard 探针走**专用端口**（独立 8 槽闸门），不占用用户 96 槽
        lambda: probe_target("dnsguard", PROBE_ADDR, "真实域名分层", hot, 3),
        # 2026-10-09 口径修正：原来用 www.qq.com 打 aghdq:5533，量到的是 aghdq **本地缓存命中**
        # （实测 2.5ms），却被画进"链路诊断 → DoQ"并当作 DoQ 通道 RTT（真实约 280~310ms）。
        # 改为每轮全新随机域名，让它真的走 aghdq2 → Quad9 over QUIC 一趟上游。
        lambda: probe_target("aghdq", DOQ1_ADDR, "冷 <随机>.com（经 aghdq2 :5534：本机明文入口 → Quad9 over QUIC）", cold, 3, record_name=True),
    ]
    results = [r for r in parallel(jobs, timeout=30.0) if r]
    save_probe_names()      # 本轮的随机冷查询域名立即落盘：AGH 聚合时按此表精确剔除

    # 链尾：两条加密 DoT 上游（TCP 握手探测）与根服务器（UDP 查询）
    def dot_probe(addr, name):
        vals, errs = [], 0
        for _ in range(3):
            try:
                vals.append(round(tcp_probe(addr), 2))
            except Exception:
                errs += 1
        return {"target": name, "addr": "%s:%d" % addr, "label": "TCP 853 握手（加密上游）",
                "samples_ms": vals, "p50_ms": round(pct(vals, 0.5), 2) if vals else 0.0,
                "max_ms": round(max(vals), 2) if vals else 0.0,
                "rcode": "%d/%d 成功" % (len(vals), len(vals) + errs),
                "status": "ok" if vals and not errs else ("warn" if vals else "error"),
                "cost_ms": 0.0}

    def dot360():
        return dot_probe(DOT360_ADDR, "dot.360.cn")

    def aldns():
        return dot_probe(ALDNS_ADDR, "dns.alidns.com")

    def rootsrv():
        # 2026-10-26：原来只采 **2** 个样本且要求"零失败"（`ok if vals and not errs`）⇒
        # 跨洋 UDP（杭州→美东物理往返 ~180ms）丢一个包就 warn、丢两个就 error。实测同一时刻
        # ping 0% 丢包、裸 UDP 10/10 通，但探针 10 次里仍有 2 次超时 ⇒ roots 节点在
        # ok/warn/error 之间随机跳（20:38 那轮两发全超时被判 error，纯属采样不足的噪音 ✗）。
        # 改为采 3 个样本、**≥2 次成功**即判 ok；1 次成功 warn（线路变差）；全失败才 error。
        vals, errs = [], 0
        for _ in range(3):
            try:
                ms, rc = dns_ask(ROOT_SERVER, ".", qtype=2)
                vals.append(round(ms, 2))
            except Exception:
                errs += 1
        return {"target": "根服务器", "addr": "%s:%d" % ROOT_SERVER, "label": "a.root-servers.net NS · 外部基础设施（P1 后 A 已不直接与根/TLD 通信，仅在历史语义上作为对照）",
                "samples_ms": vals, "p50_ms": round(pct(vals, 0.5), 2) if vals else 0.0,
                "max_ms": round(max(vals), 2) if vals else 0.0,
                "rcode": ("%d/%d 成功" % (len(vals), len(vals) + errs)) if vals else "超时",
                "status": ("ok" if len(vals) >= 2 else ("warn" if vals else "error")),
                "cost_ms": 0.0}

    def aldns2():
        return dot_probe(ALDNS2_ADDR, "dns.alidns.com(备)")

    def dotpub():
        return dot_probe(DOTPUB_ADDR, "dns.pub")

    tail = parallel([dot360, aldns, aldns2, dotpub, rootsrv], timeout=24.0)
    for r in tail:
        if r:
            results.append(r)
    return results


# --------------------------------------------------------------------------
# AdGuard Home
# --------------------------------------------------------------------------
def agh_conf_raw():
    return dsh("docker exec %s cat /opt/adguardhome/conf/AdGuardHome.yaml" % AGH_CONTAINER, timeout=15)


def _yaml_scalar(val):
    val = val.strip()
    if val.startswith("[") and val.endswith("]"):
        inner = val[1:-1].strip()
        if not inner:
            return []
        return [_yaml_scalar(x) for x in inner.split(",") if x.strip()]
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
        val = val[1:-1]
    if val in ("true", "false"):
        return val == "true"
    if re.match(r"^-?\d+$", val):
        return int(val)
    return val


def _agh_dns_scalar(raw, key):
    """从 AGH 原始配置里按 2 空格缩进精确取一个 dns 段标量（绕开 parse_agh_config 的截断问题）。"""
    if not raw:
        return None
    m = re.search(r"^\s{2}" + re.escape(key) + r":\s*(.*?)\s*$", raw, re.M)
    return m.group(1).strip() if m else None


def parse_agh_config(raw):
    """只取 dns 段的配置项（列表 / 嵌套 map 都支持），绝不返回 password hash。"""
    cfg = {}
    if not raw:
        return cfg
    in_dns = False
    cur_key = None
    for ln in raw.split("\n"):
        if re.match(r"^[a-zA-Z_]", ln):          # 顶层 key
            in_dns = ln.startswith("dns:")
            cur_key = None
            continue
        if not in_dns:
            continue
        m = re.match(r"^\s{2}([a-z0-9_]+):\s*(.*)$", ln)
        if m:
            key, val = m.group(1), m.group(2).strip()
            if val == "":
                cfg[key] = {}                     # 后面按出现的内容决定是 list 还是 map
                cur_key = key
            else:
                cfg[key] = _yaml_scalar(val)
                cur_key = None
            continue
        if cur_key is None:
            continue
        m = re.match(r"^\s{4}-\s*(.+)$", ln)      # 列表项
        if m:
            if isinstance(cfg.get(cur_key), dict):
                cfg[cur_key] = []
            cfg[cur_key].append(_yaml_scalar(m.group(1)))
            continue
        m = re.match(r"^\s{4}([a-z0-9_]+):\s*(.*)$", ln)   # 嵌套 map 项
        if m:
            if not isinstance(cfg.get(cur_key), dict):
                cfg[cur_key] = {}
            cfg[cur_key][m.group(1)] = _yaml_scalar(m.group(2))
            continue
    # 嵌套 map 展平
    ecs = cfg.get("edns_client_subnet")
    if isinstance(ecs, dict):
        cfg["edns_client_subnet"] = bool(ecs.get("enabled", False))
    for k in list(cfg.keys()):
        if isinstance(cfg[k], dict):
            cfg[k] = bool(cfg[k].get("enabled", False))
    return cfg


def guard_ask(name, qtype=1, timeout=4.0):
    """向 dnsguard 发一次查询，返回 (毫秒, [A 记录])。"""
    body = dns_build(name, qtype)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.sendto(body, DNSGUARD_ADDR)
        data, _ = s.recvfrom(4096)
        ms = (time.time() - t0) * 1000.0
    finally:
        s.close()
    _, _, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
    o = 12
    ips = []
    for _ in range(qd):
        while data[o]:
            o += data[o] + 1
        o += 5
    for _ in range(an):
        if data[o] & 0xC0 == 0xC0:
            o += 2
        else:
            while data[o]:
                o += data[o] + 1
            o += 1
        t, c, ttl, ln = struct.unpack(">HHIH", data[o:o+10])
        o += 10
        rd = data[o:o+ln]
        o += ln
        if t == 1:
            ips.append(".".join(str(x) for x in rd))
    return ms, ips


# --------------------------------------------------------------------------
# 新增防护面（2026-10-05）
# --------------------------------------------------------------------------
PROT_UNB53_CHAIN = "UNBOUNDB_53"
PROT_WATCH_LOG = "/var/log/unbound-b-plain53.log"
PROT_AUDIT_ALERT = "/var/log/bypass-domain-audit-alerts.log"
PROT_AUDIT_STATE = "/var/lib/bypass-domain-audit.json"


def collect_protections():
    """两个新增防护面的**只读**采集：

    ① unbound-b 容器的全部 :53 出站被 iptables 链 UNBOUNDB_53 DROP（IP 由 dnsguard-fw
       按容器实时地址生成，不写死；容器重建/IP 漂移后由 reconcile 自动跟着变）。
       目的：让 unbound 的 forward-first 语义下"回退明文递归"结构上不可能（不是靠配置自觉）；
       同一条链的计数既是拦截量也是监控量。
    ② AGH 的 186 条域名白名单例外（直连 mullvad/nextdns/digitale，绕过 dnsguard 与 unbound）
       由独立抽查任务对照"匿名 DNSCrypt 路径"做背离/漂移检测。
    """
    out = {"plain53": {"udp": 0, "tcp": 0, "total": 0, "unit": "?", "timer": "?", "watch_tail": []},
           "audit": {"runs": 0, "baseline": 0, "alerts": 0, "timer": "?", "alert_tail": []}}
    try:
        raw = dsh("iptables -nL %s -v -x" % PROT_UNB53_CHAIN, timeout=10)
        udp = tcp = 0
        for line in raw.splitlines():
            q = line.split()
            if len(q) >= 4 and q[0].isdigit() and q[2] == "DROP":
                if q[3] == "udp":
                    udp += int(q[0])
                elif q[3] == "tcp":
                    tcp += int(q[0])
        out["plain53"].update({"udp": udp, "tcp": tcp, "total": udp + tcp})
    except Exception as e:
        out["plain53"]["error"] = str(e)[:60]
    try:
        out["plain53"]["unit"] = dsh("systemctl is-active unbound-b-53-block").strip()
        # 2026-10-08 第8步（残留监控项整理）：unbound-b-53-watch.timer 与它的 watcher 脚本
        # 已下线（单元 not-found、/var/log/unbound-b-plain53.log 最后写入 10-07 09:58），
        # 但旧代码仍原样显示它的 is-active ⇒ 看板上永远是一个吓人的 "failed" 假告警。
        # 现在把它显式标成"已下线"，并注明**权威证据是 iptables 的 DROP 计数**（同一份数据
        # 也正是第7步"B 的公网 UDP/TCP 53 出站为 0"的判据）。
        _t = dsh("systemctl is-active unbound-b-53-watch.timer").strip()
        out["plain53"]["timer"] = ("已下线（改用 iptables 计数为准）"
                                   if _t in ("failed", "unknown", "inactive", "") else _t)
        out["plain53"]["evidence"] = ("iptables UNBOUNDB_53 的 udp/tcp DROP 计数：B 出站到 :53 的"
                                      "每一次尝试都会命中并被计数（第7步验收判据）")
    except Exception:
        pass
    try:
        with open(PROT_WATCH_LOG) as f:
            out["plain53"]["watch_tail"] = [l.rstrip()[-112:] for l in f.readlines()[-3:] if l.strip()]
    except Exception:
        pass
    try:
        with open(PROT_AUDIT_STATE) as f:
            st = json.load(f) or {}
        out["audit"]["runs"] = st.get("runs", 0)
        out["audit"]["baseline"] = len(st.get("base") or {})
    except Exception:
        pass
    try:
        out["audit"]["timer"] = dsh("systemctl is-active bypass-domain-audit.timer").strip()
    except Exception:
        pass
    try:
        with open(PROT_AUDIT_ALERT) as f:
            al = [l.rstrip() for l in f if l.strip()]
        out["audit"]["alerts"] = len(al)
        out["audit"]["alert_tail"] = [l[-112:] for l in al[-3:]]
    except Exception:
        pass
    return out


def collect_dnsguard():
    """dnsguard（AGH 与 unbound 之间的投毒纠偏层）状态。"""
    out = {"active": False, "enabled": False, "listen": False, "mem_mb": None, "learned": 0,
           # 2026-10-08：真实监听地址（原来前端硬编码成 127.0.0.1:5355，与实际不符）
           "listen_addr": "%s:%d" % DNSGUARD_ADDR,
           "top": [], "stats": {}, "recent": [], "correct_ok": None, "test_domain": "",
           "probe_ms": 0.0, "probe_ips": [], "updated": 0,
           "pending": [], "pending_total": 0, "ignored_total": 0, "doq_ok": None, "doq_ms": 0.0,
           "b_consumers": {}}
    try:
        out["active"] = dsh("systemctl is-active dnsguard").strip() == "active"
        out["enabled"] = dsh("systemctl is-enabled dnsguard").strip() == "enabled"
    except Exception:
        pass
    try:
        pid = dsh("systemctl show -p MainPID --value dnsguard").strip()
        if pid and pid != "0":
            rss = dsh("ps -o rss= -p %s" % pid).strip()
            if rss:
                out["mem_mb"] = round(float(rss) / 1024.0, 1)
    except Exception:
        pass
    try:
        with open(DNSGUARD_STATS) as f:
            out["stats"] = json.load(f)
    except Exception:
        pass
    # 2026-10-08 数据源修正：R8 认证通道的计数由 verifier 进程产生。
    # 主 stats 里的 r8_auth_ok/r8_auth_none 是旧值（冻结），必须换成 verifier 的实时值，
    # 否则看板会把历史累计当成"当前认证成功率"。旧值保留为 *_main_frozen 以便审计。
    try:
        with open(DNSGUARD_VERIFIER_STATS) as vf:
            _vs = json.load(vf) or {}
        out["verifier_stats"] = _vs
        _st = out.get("stats") or {}
        if _vs:
            _st["r8_auth_ok_main_frozen"] = _st.get("r8_auth_ok")
            _st["r8_auth_none_main_frozen"] = _st.get("r8_auth_none")
            if _vs.get("r8_auth_ok") is not None:
                _st["r8_auth_ok"] = _vs.get("r8_auth_ok")
            if _vs.get("r8_auth_none") is not None:
                _st["r8_auth_none"] = _vs.get("r8_auth_none")
            _st["r8_auth_source"] = "verifier"
            out["stats"] = _st
    except Exception:
        pass
    # 2026-10-08 第7步：unbound B 的进程侧消费计数。
    # guard 的 resolve_cn_via_unbound_b() 是它自己唯一向 B 发包的地方，所以这三个值
    # 是"guard 打进 B 的查询量"的真值；chainmon 探针/CN 规则/人工流量不在这里，
    # 它们由 b_attrib() 用 B 自身的 num.queries 增量反解。
    try:
        _gs = out.get("stats") or {}
        out["b_consumers"] = {
            "unbound_b_queries_total": int(_gs.get("unbound_b_queries_total") or 0),
            "unbound_b_queries_guard_cn": int(_gs.get("unbound_b_queries_guard_cn") or 0),
            "unbound_b_noncn_attempt": int(_gs.get("unbound_b_noncn_attempt") or 0),
        }
    except Exception:
        out["b_consumers"] = {}
    try:
        with open(DNSGUARD_STATE) as f:
            raw = json.load(f) or {}
        doms = raw.get("domains", {})
        out["updated"] = raw.get("updated", 0)
        out["learned"] = len(doms)
        out["top"] = [dict(v, domain=k) for k, v in sorted(doms.items(), key=lambda kv: -kv[1].get("hits", 0))[:12]]
    except Exception:
        pass
    try:
        tail = _log_tail(DNSGUARD_LOG, 10)          # P34-BP：流式有界 ✓
        out["recent"] = [l[1:20] + " " + l.split("] ", 1)[-1][:110] for l in tail]
    except Exception:
        pass
    # 独立安全指标：不把“未发现异常”误报成“已验证安全”。
    # dnssec_validated 以 Unbound 返回 AD 的统计（fast_ad）+ dnsguard R8 认证成功为证据。
    st0 = out.get("stats") or {}
    # 将“CDN/Geo 差异”和“明确投毒”分开统计，避免把正常 CDN 调度误报为投毒。
    try:
        _recent_log = fl if 'fl' in locals() else []
    except Exception:
        _recent_log = []
    _all_recent = []
    try:
        _all_recent = _log_tail(DNSGUARD_LOG, 500)  # P34-BP：流式有界 ✓（原为整读+过滤 ✗）
    except Exception:
        pass
    _cdn_geo = [l for l in _all_recent if any(x in l for x in ("GEO  ", "CNX  ", "R8V6"))]
    # 仅 LEARN/R1/R3 代表明确投毒证据；FC 是安全拒答，不能直接归类为投毒。
    _poison = [l for l in _all_recent if any(x in l for x in ("LEARN ", "R1 ", "R3 "))]
    _fc = [l for l in _all_recent if "FC   " in l]
    out["anomaly_categories"] = {
        "cdn_geo_difference": len(_cdn_geo),
        "cross_source_conflict": int(out.get("pending_total", 0)),
        "explicit_poison": len(_poison),
        "fail_closed": len(_fc),
        # 2026-10-09 问题3 修正：guard 的这个计数**实为"unbound A 返回 SERVFAIL"**
        # （含上游不可达/DNSSEC 边界拒答），不是验签失败 ⇒ 改名为 unbound_servfail_fc。
        # 真实验签失败请看 unbound 的 num.rrset.bogus（HISTORY 里是 unbound_rrset_bogus）。
        "unbound_servfail_fc": int((out.get("stats") or {}).get(
            "fc_unbound_servfail", (out.get("stats") or {}).get("dnssec_bogus", 0)) or 0),
        "recent_examples": [{"category":"CDN/Geo 差异", "text":x[-180:]} for x in _cdn_geo[-3:]] + [{"category":"明确投毒", "text":x[-180:]} for x in _poison[-3:]] + [{"category":"安全拒答", "text":x[-180:]} for x in _fc[-3:]]
    }
    # R8/快速源观测指标，供看板直接展示（均为累计计数或最近通道 RTT）。
    _cc = st0.get("clean_ch") or {}
    out["guard_metrics"] = {
        "fast_source_doq_ms": (_cc.get("doq") or {}).get("rtt_ms"),
        "fast_source_doq_ok": (_cc.get("doq") or {}).get("ok"),
        # 2026-10-09：干净候选集合（实测 guard 首轮竞速 = 本机 DNSCrypt + DoQ1，慢源 = 认证 DoT）。
        # 旧前端只写"DoT×3 + DoQ"，漏了 DNSCrypt，也把 fast source 与 clean channel 混为一谈。
        "fast_dnscrypt_ms": st0.get("fast_dnscrypt_ms"),
        "fast_dnscrypt_ok": (_cc.get("dnscrypt") or {}).get("ok"),
        "clean_ch": _cc,
        "fast_dnscrypt_fail": int(st0.get("fast_dnscrypt_fail", 0)),
        "r8_check_time_budget_ms": int(float(os.environ.get("GUARD_CORROB_DOT_TIMEOUT", "2.8")) * 1000),
        "r8_miss": int(st0.get("r8_miss", 0)),
        "budget_skip": int(st0.get("budget_skip", 0)),
        "r8_checked": int(st0.get("r8_checked", 0)),
        "r8_auth_ok": int(st0.get("r8_auth_ok", 0)),
        "r8_auth_none": int(st0.get("r8_auth_none", 0)),
        # 2026-10-08：来源标注。上面两个值已被 verifier-state 覆盖（见 DNSGUARD_VERIFIER_STATS）；
        # 主进程的原值保留为 *_main_frozen，仅供审计，勿当实时认证成功率。
        "r8_auth_source": st0.get("r8_auth_source") or "main",
        "r8_auth_ok_main_frozen": st0.get("r8_auth_ok_main_frozen"),
        "r8_auth_none_main_frozen": st0.get("r8_auth_none_main_frozen"),
        "r8_conflict_adopt": int(st0.get("r8_adopt", 0)),
        "r8_event_skip": int(st0.get("r8_event_skip", 0)),
        "r8_circuit_skip": int(st0.get("r8_circuit_skip", 0)),
        "singleflight_wait": int(st0.get("singleflight_wait", 0)),
        "cold_drop": int(st0.get("cold_drop", 0)),
        "overload_drop": int(st0.get("overload_drop", 0)),
        "fail_closed": int(st0.get("fail_closed", 0)),
        "neg_cache_hit": int(st0.get("neg_cache_hit", 0)),
        "neg_cache_store": int(st0.get("neg_cache_store", 0)),
        "clean_races": int(st0.get("clean_races", 0)),
        "clean_hedged": int(st0.get("clean_hedged", 0)),
        "hedge_ratio": round(
            float(st0.get("clean_hedged", 0)) / max(1, float(st0.get("clean_races", 0))), 4
        ),
    }
    # ---- 2026-10-09 B1/C1：拥塞拒绝 vs 上游失败的分解 + 拥塞结束自动清缓存 ----
    _fbr = st0.get("fail_closed_by_reason")
    if not isinstance(_fbr, dict):
        _fbr = {}
    _g_adm = int(_fbr.get("admission_overload") or 0)
    _g_ups = int(_fbr.get("unbound_servfail") or 0)
    _g_poi = int(_fbr.get("known_poison") or 0)
    _g_tot = sum(int(v or 0) for v in _fbr.values())
    _g_oth = max(0, _g_tot - _g_adm - _g_ups - _g_poi)
    _g_ar = int(st0.get("admission_reject") or 0)
    _gp = _GUARD_PREV
    _now = time.time()
    _rate = _ar_rate = None
    # P34-BQ：先判"是否换了一次启动" ✓ —— 新基线则跳过速率（脏 delta 一律不用 ✗）
    _newbase = _guard_baseline_gate(st0)
    if _newbase:
        out["guard_restarts_seen"] = int(_gp.get("restarts") or 0)
    if (not _newbase) and _gp.get("t") and _now > _gp["t"]:
        _dt = _now - _gp["t"]
        _d_adm = _g_adm - int(_gp.get("adm") or 0)
        _d_ar = _g_ar - int(_gp.get("ar") or 0)
        if _dt > 0 and _d_adm >= 0:
            _rate = round(_d_adm * 60.0 / _dt, 2)
        if _dt > 0 and _d_ar >= 0:
            _ar_rate = round(_d_ar * 60.0 / _dt, 2)
        if _d_ar > 0:
            _gp["peak"] = max(int(_gp.get("peak") or 0), _d_ar)
        elif _gp.get("peak"):
            if (int(_gp["peak"]) >= CACHE_CLEAR_MIN_REJECTS
                    and (_now - float(_gp.get("last_clear") or 0)) >= CACHE_CLEAR_COOLDOWN):
                _st_code, _err = _agh_cache_clear()
                _gp["last_clear"] = _now
                _gp["clears"] = int(_gp.get("clears") or 0) + 1
                _gp["last_clear_reason"] = "拥塞结束（峰值 +%d 次拒绝）→ HTTP %s%s" % (
                    int(_gp["peak"]), _st_code, ("（%s）" % _err) if _err else "")
                try:
                    with open("/opt/chainmon/cache_clear.log", "a") as _cf:
                        _cf.write("%s %s\n" % (time.strftime("%F %T", time.localtime(_now)),
                                              _gp["last_clear_reason"]))
                except Exception:
                    pass
            _gp["peak"] = 0
    _gp["t"] = _now
    _gp["adm"] = _g_adm
    _gp["ar"] = _g_ar
    out["guard_metrics"].update({
        "fc_admission_overload": _g_adm,
        "fc_unbound_servfail": _g_ups,
        "fc_known_poison": _g_poi,
        "fc_other": _g_oth,
        "admission_reject": _g_ar,
        "fc_admission_rate": _rate,
        "admission_reject_rate": _ar_rate,
        "cache_clears": int(_gp.get("clears") or 0),
        "cache_clear_last": _gp.get("last_clear") or None,
        "cache_clear_reason": _gp.get("last_clear_reason") or "",
        "cache_clear_min_rejects": CACHE_CLEAR_MIN_REJECTS,
        "cache_clear_cooldown_s": CACHE_CLEAR_COOLDOWN,
        # 2026-10-09 阶段3：探针通道计数（与用户侧完全分开）；用户侧 q 用 q−probe_q 派生
        "probe_q": int(st0.get("probe_q") or 0),
        "probe_admission_reject": int(st0.get("probe_admission_reject") or 0),
        "probe_overload_drop": int(st0.get("probe_overload_drop") or 0),
        "guard_user_q": max(0, int(st0.get("q") or 0) - int(st0.get("probe_q") or 0)),
        "probe_port": PROBE_PORT,
        "probe_src": sorted(PROBE_SRC),
    })
    # ---- 2026-10-10 §1 业务基线仪表（daily-latency-plan §1）---------------------------------
    # 方案 §1 要求：记录客户端/入口/qtype/CN与否/cache 状态/排队时长/A·alt·B 各耗时/见证就绪/
    # retry/hedge started·won/最终来源/rcode/总耗时；guard 与 verifier **用同一请求追踪 ID 分开统计**；
    # 业务流量与 5356 探针**分开**；样本量按 A/AAAA/HTTPS/CN 分列并给出是否达标。
    # guard 侧把有界分桶快照写在 stats.json 的 `base` 键里（`_bs_snapshot()`）✓。
    try:
        out["guard_metrics"].update(_base_metrics(st0, out.get("verifier_stats") or {}))
    except Exception:
        pass
    out["security_metrics"] = {
        # 2026-10-09 修正：回退式原来把 r8_auth_ok（加密核对成功数，与 DNSSEC 无关）也算进
        # "DNSSEC 已验证"。DNSSEC 只能由 unbound 给出：优先 guard 的 dnssec_validated，
        # 缺失时退到 unbound 的 AD 计数 fast_ad。
        "dnssec_validated": int(st0.get("dnssec_validated") or 0) or int(st0.get("fast_ad", 0) or 0),
        # 2026-10-09 问题3：同上，guard 该键语义是"unbound SERVFAIL"而非 bogus
        "unbound_servfail_fc": int(st0.get("fc_unbound_servfail") or st0.get("dnssec_bogus") or 0),
        "cross_source_conflict": 0,
        "fail_closed_reason": [],
        # 2026-10-28 R-2 / N-2：无证据下发（fail-open）收口与通道去重的实测计数。
        # 这些出口语义是"核对没拿到独立佐证，但为可用性仍下发明文"，
        # 所以既要能看见它发生了多少次，也要能看见 TTL 是否真的被压到 60s。
        "failopen_ttl_capped": int(st0.get("failopen_ttl_capped") or 0),
        "failopen_r8_miss": int(st0.get("r8_miss") or 0),
        "failopen_backoff": int(st0.get("r8_backoff_skip") or 0),
        "failopen_asn_gate": int(st0.get("r8_asn_gate_k") or 0) + int(st0.get("r8_asn_gate_unknown") or 0),
        "failopen_budget": int(st0.get("budget_skip") or 0),
        "strict_endpoint_dedup": int(st0.get("strict_endpoint_dedup") or 0),
        "strict_operator_dedup": int(st0.get("strict_operator_dedup") or 0),
        "cnip_observe_conflict": int(st0.get("cnip_observe_conflict") or 0),
    }
    try:
        fl = [l for l in _log_tail(DNSGUARD_LOG, 5000)
              if "FC   " in l or "SERVFAIL" in l or "bogus" in l.lower()]   # P34-BP：同一轮复用缓存 ✓
        out["security_metrics"]["fail_closed_reason"] = [l[-180:] for l in fl[-8:]]
    except Exception:
        pass
    try:
        with open("/opt/dnsguard/diff.json") as f:
            dj = json.load(f) or {}
        dd = dj.get("diff") or {}
        items = [(k, v) for k, v in dd.items() if not v.get("ignored")]
        items.sort(key=lambda kv: -kv[1].get("count", 0))
        out["pending"] = [{"domain": k, "count": v.get("count", 0), "unbound": v.get("unbound", ""),
                           "clean": v.get("clean", ""), "last": v.get("last", 0)} for k, v in items[:30]]
        out["pending_total"] = len(items)
        out["ignored_total"] = sum(1 for v in dd.values() if v.get("ignored"))
        out.setdefault("security_metrics", {})["cross_source_conflict"] = len(items)
        # 2026-10-09 修正：anomaly_categories 在更早处读取 pending_total（当时还是 0），
        # 于是"跨源冲突"在安全页恒显示 0，而同名指标在明细里显示 300 —— 同一个数两处不同源。
        out.setdefault("anomaly_categories", {})["cross_source_conflict"] = len(items)
    except Exception:
        pass
    # 2026-10-09 口径修正：原来用 www.qq.com（aghdq 实例本地缓存命中 → 实测 4.5ms）当"DoQ RTT"，
    # 与 guard keepalive 不是一个量级（guard 每轮全新随机域名，实测 ~280ms）。
    # 改为同样口径，并优先采用 guard stats 里 clean_ch.doq 的保活 RTT（真正的上游往返）。
    _ch = (out.get("stats") or {}).get("clean_ch") or {}
    if isinstance(_ch.get("doq"), dict) and _ch["doq"].get("rtt_ms"):
        out["doq_ok"] = bool(_ch["doq"].get("ok"))
        out["doq_ms"] = _ch["doq"].get("rtt_ms")
    for port, key in ((5534, "doq"),):
        try:
            body = dns_build(rnd() + ".com", 1)
            ds = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ds.settimeout(4)
            t0 = time.time()
            ds.sendto(body, ("127.0.0.1", port))
            ds.recvfrom(4096)
            ds.close()
            out[key + "_ok"] = True
            out[key + "_ms"] = round((time.time() - t0) * 1000, 1)
        except Exception:
            out[key + "_ok"] = False
    # 固定使用已知正常且可验证 DNSSEC 的域名，避免从异常列表挑出
    # dnssec-failed.org，导致看板自检反复制造慢 SERVFAIL。
    test = "cloudflare.com"
    out["test_domain"] = test
    try:
        ms, ips = guard_ask(test)
        out["probe_ms"] = round(ms, 1)
        out["probe_ips"] = ips[:3]
        out["listen"] = True
        out["correct_ok"] = bool(ips) and not any(i in GUARD_POISON_SAMPLE for i in ips)
    except Exception:
        out["listen"] = False
        out["correct_ok"] = False
    return out


AGH_API_BASE = "http://127.0.0.1:3000"
AGH_API_LIMIT = 6000          # 2026-10-09 调研后定值：1 小时窗口实际只需约 2700–3300 条
                              # （实测 1000 条 ≈ 603KB），6000 留约 2 倍余量；
                              # 16000 会拉回 2.3–10 小时数据却只用 1 小时（≈80% 白拉）。
                              # 历史：12000 → 4000（内存紧张）→ 16000（探针占满样本）→ 6000。
# 旧值保留说明：
                              # 但探针/压测流量会占满样本（实测 83%），使**用户侧样本被压缩**
                              # （只剩 697 条、仅覆盖 18.8 分钟）⇒ 依赖样本的指标为空、前端
                              # spark() 因"非空点<2"隐藏折线。分离探针后上调到 16000 以留足用户样本。
                               # 原因：新增 collect_agh_stats() 后，**计数/比率/QPS 全部改由 AGH 窗口计数差分提供**，
                               # querylog 退化为"分类样本"（上游占比/延迟分位/域名明细）。样本量 4000 在 80 QPS 下
                               # 覆盖约 50 秒，对分位与占比足够；而单次解析 12000 条（含 base64 应答）峰值内存可达
                               # 数 MB~数十 MB，是 chainmon 撞 256M 硬限的重要原因之一。
                               # 窗口覆盖度仍由 window_covered_min / window_truncated 如实披露。          # 限制单轮解析量，避免监控高峰挤压 DNS 进程。
                               # 2026-10-09 实测（/control/querylog?limit=N）：当前速率约 45 条/分钟，
                               # limit=2500 只能覆盖 55 分钟 ⇒ 1 小时窗口会被静默截断。改成 12000 后
                               # 可覆盖 ~1 小时（按 ~200 条/分钟估）；**遇到更高突发仍可能截断**，
                               # 因此 overview 会同时给出 window_covered_min / window_truncated 如实披露。
AGH_CRED_FILE = "/root/.dsh-scripts/adg-stats.env"
_AGH_AUTH = {"done": False, "header": {}}


def _agh_auth_header():
    """AGH 管理 API 的 Basic 头（凭据沿用 devfp 同款只读 env 文件）；缺凭据返回空。"""
    if not _AGH_AUTH["done"]:
        hdr = {}
        try:
            env = {}
            with open(AGH_CRED_FILE, "r") as f:
                for raw in f:
                    raw = raw.strip()
                    if raw and not raw.startswith("#") and "=" in raw:
                        k, v = raw.split("=", 1)
                        env[k.strip()] = v.strip()
            if env.get("ADG_USER"):
                tok = base64.b64encode(("%s:%s" % (env["ADG_USER"], env.get("ADG_PASS", ""))).encode()).decode()
                hdr = {"Authorization": "Basic " + tok}
        except Exception:
            hdr = {}
        _AGH_AUTH["header"] = hdr
        _AGH_AUTH["done"] = True
    return _AGH_AUTH["header"]


def _agh_cache_clear():
    """C1（2026-10-09）：清空 AGH 缓存。返回 (http_status|None, err|None)。

    只在"一次拥塞事件结束"后调用：guard 闸门过载时回的是语法正常的 SERVFAIL，AGH 无法
    与"上游真的失败"区分 ⇒ 会缓存它（实测 p50 179s / max 596s）⇒ 过载结束后仍有余波。
    """
    hdr = _agh_auth_header()
    if not hdr:
        return None, "no-credentials"
    try:
        req = urllib.request.Request(AGH_API_BASE + "/control/cache_clear", headers=hdr, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, None
    except Exception as e:
        return None, str(e)[:80]


def _agh_ts(s):
    try:
        return calendar.timegm(time.strptime(s[:19], "%Y-%m-%dT%H:%M:%S"))
    except Exception:
        return None


def _agh_api_raw(_lim=None):
    """取 AGH querylog 原始文本。`_lim` 供增量模式按需取数（默认仍用 AGH_API_LIMIT）。"""
    """取 AGH querylog 的**原始 JSON 文本**（不解析）—— 流式改造的输入。"""
    hdr = _agh_auth_header()
    if not hdr:
        raise RuntimeError("缺少 AGH API 凭据")
    req = urllib.request.Request("%s/control/querylog?limit=%d" % (AGH_API_BASE, int(_lim or AGH_API_LIMIT)), headers=hdr)
    return urllib.request.urlopen(req, timeout=8).read().decode("utf-8")


def _agh_file_raw():
    """兜底原始文本：读磁盘上的 querylog.json 尾部。"""
    return dsh("docker exec %s tail -c 8000000 /opt/adguardhome/work/data/querylog.json" % AGH_CONTAINER, timeout=20)


def collect_agh_stats():
    """AGH 计数（/control/stats）—— **权威、无截断**的计数来源。

    为什么需要它：`/control/querylog?limit=N` 是按**条数**截取的，突发流量下 1 小时窗口根本
    拿不满（80 QPS 时 12,000 条只覆盖约 2.5 分钟），而 `queries` 这类"窗口累计值"就直接被
    取数上限钉死在 12,000 —— 与逐分钟波动的 `queries_1m` 画在同一张图上必然趋势不符。
    计数以 /control/stats 为准；querylog 退化为"分类样本"（上游占比/延迟/域名明细），
    并如实披露样本覆盖度。

    ⚠️ 2026-10-14 订正：原注释写"num_dns_queries 是 AGH 自启动以来的累计值"，**这是错的**。
    AGH 的统计保留窗口是**滚动 24 小时**，`num_dns_queries`/`num_blocked_filtering` 只是
    24 个小时桶 `dns_queries[]`/`blocked_filtering[]` 的**逐桶求和**（实测：逐桶之和与总量
    逐位相等，且 AGH 容器未重启）。所以整点最旧桶过期时总量会**下降**（实测 16:00:02 总量
    瞬降 q −985 / b −325 / 上游 −432，同时逐桶和仍与总量相等），两个采样点之差就不再是纯
    增量：可能为负，也可能被稀释到 Δ拦截 > Δ总查询 ⇒ 拦截率 >100%、放行 QPS 为负
    （实测 15:00:55 算出 568.33% 与 −17.03 QPS）。因此差分必须落在**同一个小时桶**内
    （见 bucket_* 字段），跨桶的那个区间要把换桶两侧拼起来。
    """
    hdr = _agh_auth_header()
    if not hdr:
        return {"error": "缺少 AGH API 凭据"}
    try:
        req = urllib.request.Request(AGH_API_BASE + "/control/stats", headers=hdr)
        d = json.loads(urllib.request.urlopen(req, timeout=8).read().decode("utf-8"))
    except Exception as e:
        return {"error": "%s: %s" % (type(e).__name__, e)}

    def _pairs(lst, cap):
        out = []
        for x in (lst or [])[:cap]:
            if isinstance(x, dict) and x:
                k = list(x.keys())[0]
                out.append((k, x[k]))
        return out

    # 2026-10-14：滚动 24 小时桶。dns_queries / blocked_filtering 按时间**升序**，
    # [-1] = 当前（部分）小时，[-2] = 上一个已完结小时（实测 16:07 只有 [-1] 在增长）。
    _hq = d.get("dns_queries") or []
    _hb = d.get("blocked_filtering") or []

    def _last_int(lst):
        """取列表最后一个元素并转 int；空列表或异常一律返回 None，由调用方降级。"""
        try:
            return int(lst[-1]) if lst else None
        except Exception:
            return None

    return {
        "q_total": int(d.get("num_dns_queries") or 0),
        "b_total": int(d.get("num_blocked_filtering") or 0),
        # 累计"上游应答数"：AGH 命中缓存时**不会**联系上游，所以 Δ上游/Δ总数 即**精确 miss 率**，
        # 1−它 即精确的 AGH 缓存命中率（无 querylog 条数截断、无样本偏差）。
        "up_total": sum(int(x.get(k) or 0) for x in (d.get("top_upstreams_responses") or [])
                        for k in (x.keys() if isinstance(x, dict) else [])),
        "upstreams": _pairs(d.get("top_upstreams_responses"), 10),
        # top_clients / top_queried_domains 是 AGH **保留期窗口**（24h 滚动）内的计数，
        # 与 q_total **同一基准**（两者都是滚动窗口，不是自启动累计）；仍只能做同源两点差分。
        # 整点最旧桶过期时单客户端计数同样会下降 ⇒ 负增量必须丢弃（见 clients_rate 守卫）。
        "clients": _pairs(d.get("top_clients"), 50),
        "top_domains": _pairs(d.get("top_queried_domains"), 30),
        "top_blocked": _pairs(d.get("top_blocked_domains"), 20),
        "avg_processing_time": d.get("avg_processing_time"),
        "time_units": d.get("time_units"),
        "hourly_queries": d.get("dns_queries") or [],
        "hourly_blocked": d.get("blocked_filtering") or [],
        # 差分用的"同桶"基准（见本函数 docstring 的 2026-10-14 订正）
        "bucket_q": _last_int(_hq),
        "bucket_b": _last_int(_hb),
        "bucket_q_prev_hour": _last_int(_hq[:-1]),
        "bucket_b_prev_hour": _last_int(_hb[:-1]),
    }


def _agh_hour_key(t):
    """采样时刻所属的自然小时桶序号。

    AGH 的小时桶按**自然小时**对齐（实测 16:00:02 换桶：总量瞬降 985 条），故用 t//3600
    作为桶标识，与 `dns_queries[]` 的最后一格一一对应。
    """
    try:
        return int(t // 3600) if t else None
    except Exception:
        return None


def _agh_window_delta(stats, prev, now):
    """算本区间的 AGH 增量，返回 (dq, db, crossed, src)；不可信时返回 None。

    为什么不能简单做"两个采样点的总量相减"：AGH 的 num_* 是**滚动 24 小时桶之和**，
    整点最旧桶过期会让总量下降、或把 Δ 稀释成 Δ拦截 > Δ总查询（2026-10-14 现场：
    15:00:55 得拦截率 568.33%、放行 QPS −17.03；16:00:02 总量瞬降 985 条）。

    - 桶路径（首选）：dq/db = 当前小时桶 − 上一采样点的同桶值。桶内计数不含已过期的小时，
      所以天然免疫"最旧桶过期"。整点那一个区间用「上一整点桶 − 上一采样点的桶值 + 当前桶」
      拼接，仍然精确（需要 AGH 数组按时间升序，已验证最后一格是当前部分小时）。
    - 总量路径（兜底）：仅在桶字段缺失时使用（例如刚升级、history.json 里还是旧条目），
      由调用方的不变量 `0 ≤ Δ拦截 ≤ Δ总查询` 把住。

    crossed=True 表示本区间跨过整点 —— 此时上游应答数（没有小时桶、只能做总量差分）不可信，
    调用方应跳过由它派生的 QPS/缓存命中率。
    """
    if not prev:
        return None
    _hk = _agh_hour_key(now)
    _phk = prev.get("agh_hour_key")
    if _phk is None and prev.get("t"):
        # 旧格式历史条目（升级前的 history.json）没有 agh_hour_key：用采样时间戳还原，
        # 否则会被当成"跨桶"而白白多牺牲一个区间的上游派生指标。
        _phk = _agh_hour_key(prev.get("t"))
    _bq, _bb = stats.get("bucket_q"), stats.get("bucket_b")
    _pbq, _pbb = prev.get("agh_bucket_q"), prev.get("agh_bucket_b")
    if None not in (_bq, _bb, _pbq, _pbb, _hk, _phk):
        if _phk == _hk:
            return (_bq - _pbq, _bb - _pbb, False, "agh_hour_bucket_delta")
        if _hk - _phk == 1:
            _oqb, _obb = stats.get("bucket_q_prev_hour"), stats.get("bucket_b_prev_hour")
            if None not in (_oqb, _obb) and _oqb >= _pbq and _obb >= _pbb:
                # 旧小时桶的剩余增量 + 新小时桶的头部增量
                return ((_oqb - _pbq) + _bq, (_obb - _pbb) + _bb, True,
                        "agh_hour_bucket_rollover")
        # 跨了不止一个整点（采样断档 > 1 小时）或桶值不自洽 → 不可信
        return None
    _pq, _pb = prev.get("agh_q_total"), prev.get("agh_b_total")
    if _pq is None:
        return None
    # 桶标识仍未知（无时间戳的旧条目）时按"跨桶"从严处理，只放弃上游派生指标
    _crossed = True if _phk is None else (_phk != _hk)
    return (stats.get("q_total", 0) - _pq,
            stats.get("b_total", 0) - (_pb or 0),
            _crossed, "agh_window_total_delta")


# ==========================================================================
# QLOG-INCR v1（2026-10-09）：查询日志**增量取数 + 滚动累积**
#
# 问题：折线来自落盘的 HISTORY，本与取数无关；但为算"最近 1 小时的分位/唯一域名/top-N"，
# 旧实现每 60 秒把同一小时整包重拉重聚合一次（limit=6000 ⇒ 3.1MB/轮、~2.2 小时数据、
# 单轮解码 ~0.35–0.9s），一小时里同一批数据被算约 60 遍；且每轮"分配 8MB 文本 + 上万条
# 解码对象再释放"会把 glibc arena 高水位顶高（实测 16000 时服务稳态 231MB）。
#
# 现为：每轮只取"新增的几十条"（limit 自适应），窗口内记录按（时间戳, 同秒序数）去重后
# 滚动保留最近 1 小时（常驻 ≤1MB），本地重算聚合，输出契约与全量口径**逐字段一致**
# （离线 A/B：连续 135 轮、断档 30 分钟回补、突发被截断后重取，13 项指标偏差全为 0.000）。
#
# 三态开关 CHAINMON_QLOG_MODE：
#   full（默认） 维持原全量路径，完全不变；
#   shadow       仍用全量结果对外，但同时跑增量并写对照日志（用于切换前取证）；
#   incr         直接用增量结果；任何异常自动回退全量并记日志。
# ==========================================================================
QLOG_MODE = os.environ.get("CHAINMON_QLOG_MODE", "full").strip().lower()
QLOG_WINDOW_FILE = os.path.join(BASE_DIR, "qlog_window.json")
QLOG_SHADOW_LOG = os.path.join(BASE_DIR, "qlog_shadow.log")
_QLOG_WIN = None
_QLOG_STATE = {"last_wall": 0.0, "last_incr_ms": None, "last_full_ms": None, "errors": 0}
QLOG_INCR_LOG = os.path.join(BASE_DIR, "qlog_incr.log")


def _qlog_log(msg):
    """**自带**日志出口：chainmon 没有全局 log()。

    ⚠️ 踩坑记录：v1 里直接调了 `log(...)`，而本模块并无该符号 ⇒ NameError ⇒ 在 shadow 模式下
    从 _qlog_incr_collect 抛出、又被 except 分支里的 log(...) 再次抛出 ⇒ **collect_agh_querylog
    每轮直接失败** ⇒ 看板 overview.queries 变 0（2026-10-09 现场故障根因）。
    故这里自带出口且**自身绝不抛异常**：同时写 stdout（systemd → journal）与专用文件。
    """
    line = "%s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    try:
        print("QLOG-INCR " + line)
    except Exception:
        pass
    try:
        with open(QLOG_INCR_LOG, "a", encoding="utf-8") as f:
            f.write(line + chr(10))
    except Exception:
        pass


def _qlog_window():
    """惰性加载并常驻（跨轮保留窗口数据；落盘以便重启后续用）。"""
    global _QLOG_WIN
    if _QLOG_WIN is None:
        try:
            import qlog_window as _qw
        except Exception as e:
            _qlog_log("QLOG-INCR 模块导入失败，回退全量: %s" % e)
            return None
        w = _qw.QlogWindow(QLOG_WINDOW_FILE, window_s=WINDOW_MIN * 60)
        w.load()
        _QLOG_WIN = w
        _qlog_log("QLOG-INCR 已启用: mode=%s 窗口文件=%s 载入=%s 条(水位=%s)"
            % (QLOG_MODE, QLOG_WINDOW_FILE, len(w.recs), w.max_ep))
    return _QLOG_WIN


def _qlog_incr_collect(now):
    """增量路径：取新增 → 去重入窗 → 本地聚合。失败抛异常（由调用方回退全量）。"""
    import qlog_window as _qw
    w = _qlog_window()
    if w is None:
        return None
    gap = max(0.0, now - (_QLOG_STATE["last_wall"] or now))
    limit = w.needed_limit(gap_s=max(60.0, gap))
    # 冷启动/窗口不足 ⇒ 先用**一次全量取数**把窗口灌满（此后长期只做增量）。
    # 为什么必须：新 store（首次部署或文件损坏）只有几轮数据，窗口聚合会**系统性偏小**
    # （实测首 3 轮 queries=295 vs 全量 2700）。落盘后此分支极少再触发。
    _span = (w.max_ep - w.recs[0][0]) if w.recs else 0
    if (not w.recs) or (_span < (WINDOW_MIN * 60) - 120):
        pl0 = _agh_api_raw(_lim=AGH_API_LIMIT)
        if pl0:
            w.ingest(_iter_records("api", pl0))
            _qlog_log("QLOG-INCR 冷启动灌窗: 取 %d 条 → store=%d 覆盖=%.1f 分钟"
                      % (AGH_API_LIMIT, len(w.recs), (w.max_ep - w.recs[0][0]) / 60.0 if w.recs else 0))
    # ⚠️ 必须**按自适应 limit 取数**：早期版本这里误调 _agh_fetch_raw()（内部固定用
    # AGH_API_LIMIT=6000），等于每轮仍白拉 6,000 条，优化失效且加重 AGH 负担。
    payload = _agh_api_raw(_lim=limit)
    if payload:
        kind, source = "api", "api"
    else:
        payload, kind, source = _agh_file_raw(), "file", "file"
    if not payload:
        raise RuntimeError("取数失败（api/file 均为空）")
    w.ingest(_iter_records(kind, payload))
    # 守卫：批次够不到水位（突发撑爆 limit）⇒ 放大重取，否则那批记录会永久丢失
    tries = 0
    while (not w.last_reached) and tries < 3:
        tries += 1
        big = min(20000, int(max(limit, 300) * 4 * tries))
        pl = _agh_api_raw(_lim=big)
        if not pl:
            break
        w.ingest(_iter_records("api", pl))
    w.save()
    _QLOG_STATE["last_wall"] = now
    out = w.aggregate(probe_names=probe_name_set(), probe_src=PROBE_SRC,
                      probe_clients=AGH_PROBE_CLIENTS, hot_name=PROBE_HOT_NAME,
                      window_min=WINDOW_MIN, now=now, source=(source or "api") + "+incr")
    out["incr"] = {"store": w.stats(), "limit": limit, "retries": tries}
    return out


def _qlog_shadow_log(full, incr, ms_full, ms_incr):
    """影子对照：把关键字段差异追加到日志（用于决定是否切到 incr）。"""
    try:
        import qlog_window as _qw
        rows = _qw.shadow_diff(full, incr)
        bad = [r for r in rows if r[4]]
        line = "%s mode=shadow full=%.0fms incr=%.0fms 超容差=%d | %s\n" % (
            time.strftime("%Y-%m-%d %H:%M:%S"), ms_full, ms_incr, len(bad),
            " ".join("%s:%s/%s(%s)" % (k, a, b, ("%.2f" % rel) if rel is not None else "-")
                     for k, a, b, rel, isbad in rows[:6]))
        with open(QLOG_SHADOW_LOG, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception as e:
        _qlog_log("影子对照写日志失败: %s" % e)


def _iter_records(kind, payload):
    """把原始输入**逐条**产出记录（生成器）。STREAM-AGG v1

    原来 _agh_api_records 先 json.loads 整包、再建一个最多 20000 元素的 dict 列表，
    峰值数百 MB（实测 chainmon 曾有 ~600MB 页被换出到 swap，把 1.8G 的机器拖到
    available ~150MB，连带 dnscrypt/dnsguard 被换出 → DNS 出现 5 秒级页换入卡顿）。
    现在用 JSONDecoder.raw_decode 逐条解码，只保留当前一条；文件源本来就是逐行 JSON。

    键名与单位口径完全不变（文件 Elapsed=**纳秒**、API elapsedMs=**毫秒**，均 ×1e6）。
    """
    if kind == "file":
        for i, ln in enumerate((payload or "").split("\n")):
            if i == 0:                     # tail 截断的首行
                continue
            ln = ln.strip()
            if not ln:
                continue
            try:
                yield json.loads(ln)
            except Exception:
                continue
        return
    dec = json.JSONDecoder()
    n = len(payload or "")
    if n == 0:
        return
    i = payload.find('"data"')
    if i < 0:
        return
    j = payload.find("[", i)
    if j < 0:
        return
    k = j + 1
    while k < n:
        while k < n and payload[k] in " \t\r\n,":
            k += 1
        if k >= n or payload[k] == "]":
            return
        try:
            it, k = dec.raw_decode(payload, k)
        except Exception:
            return
        if not isinstance(it, dict):
            continue
        q = it.get("question") or {}
        try:
            el = float(it.get("elapsedMs") or 0) * 1000000.0
        except Exception:
            el = 0.0
        yield {"T": it.get("time", ""), "QH": q.get("name", ""), "QT": q.get("type", ""),
               "IP": it.get("client", ""), "Upstream": it.get("upstream", ""),
               "Cached": bool(it.get("cached")), "Elapsed": el}


def _agh_api_records(limit=AGH_API_LIMIT):
    """兼容包装：需要整表时才用（内部已走流式）。"""
    return list(_iter_records("api", _agh_api_raw()))


def _agh_file_records():
    """兼容包装：需要整表时才用（内部已走流式）。"""
    return list(_iter_records("file", _agh_file_raw()))


def _agh_fetch_records(force_source=None):
    """兼容包装：返回 (records, source, error)（整表）。新代码请用 _agh_fetch_raw + _iter_records。"""
    kind, payload, source, err = _agh_fetch_raw(force_source)
    if not kind:
        return [], source, err
    got = list(_iter_records(kind, payload))
    if got:
        return got, source, err
    return [], source, (err + " " + kind + ":0 条").strip()


def _agh_fetch_raw(force_source=None):
    """返回 (kind, payload, source, error)。STREAM-AGG v1：只取**原始文本**，不解析。"""
    err = ""
    for src in ([force_source] if force_source else ["api", "file"]):
        try:
            payload = _agh_api_raw() if src == "api" else _agh_file_raw()
            if payload:
                return src, payload, src, err
            err = (err + " " + src + ":0 字节").strip()
        except Exception as e:
            err = (err + " " + src + ":" + str(e)[:70]).strip()
    return None, None, (force_source or "none"), err



# ══════════════════════════════════════════════════════════════════════════
# 2026-10-22：dnsdist 查询日志采集器
# 现状（2026-10-28 起）：DoT/DoH 已上移由 AGH 终结，dnsdist 退到内网只做 ECS 感知缓存，
#       它看到的客户端恒为 AGH 容器地址，逐条写盘已无分析价值 ⇒ /etc/dnsdist/dnsdist.conf
#       的 addAction(AllRule(), LuaAction(markQuery)) 已注释停用（锚点 [[dnsdist-disable-query-log]]）。
#       本采集器保留仅为兼容旧日志文件；客户端归因改由 AGH querylog 承担（那里现在是真实 IP）。
# 日志格式（dnsdist Lua 写入）：<epoch>.<usec>,<client_ip>,<qname>,<qtype>
# 用途：① 客户端归因（真实 IP）② 与 AGH querylog 按 qname 关联补齐延迟
# ══════════════════════════════════════════════════════════════════════════
DNSDIST_QLOG = "/var/log/dnsdist-query.log"
DNSDIST_QLOG_MAX_BYTES = 8 * 1024 * 1024   # 超过则只读尾部，避免读满整个文件



# ══════════════════════════════════════════════════════════════════════════
# 2026-10-22：dnsdist 统计采集（缓存命中率等）
# 缓存已从 AGH 迁移到 dnsdist 的 PacketCache，看板必须改读这里，
# 否则会错误显示 0% 命中。
# ══════════════════════════════════════════════════════════════════════════
DNSDIST_STATS_URL = os.environ.get(
    "CHAINMON_DNSDIST_STATS_URL",
    "http://127.0.0.1:18083/api/v1/servers/localhost/statistics")
# dnsdist 的 apiKey 由 install.sh 生成后写入本进程的环境变量，
# 仓库里不放真实口令；为空时统计接口会 401，看板显式提示而不是静默 0。
DNSDIST_API_KEY = os.environ.get("CHAINMON_DNSDIST_API_KEY", "")


def collect_dnsdist_stats():
    """读 dnsdist 的 HTTP 统计。返回 dict（失败时 error 字段说明原因）。"""
    out = {"ok": False, "error": None,
           "cache_hits": 0, "cache_misses": 0, "cache_hit_pct": None,
           "queries": 0, "servfail": 0, "nxdomain": 0,
           "latency_avg_us": None, "latency_p50_us": None}
    try:
        import urllib.request as _u
        req = _u.Request(DNSDIST_STATS_URL, headers={"X-API-Key": DNSDIST_API_KEY})
        raw = _u.urlopen(req, timeout=8).read().decode("utf-8")
        import json as _j
        items = _j.loads(raw) or []
        m = {}
        for it in items:
            if isinstance(it, dict) and it.get("name"):
                m[str(it["name"])] = it.get("value")
        out["cache_hits"] = int(m.get("cache-hits") or 0)
        out["cache_misses"] = int(m.get("cache-misses") or 0)
        tot = out["cache_hits"] + out["cache_misses"]
        if tot > 0:
            out["cache_hit_pct"] = round(100.0 * out["cache_hits"] / tot, 1)
        out["queries"] = int(m.get("queries") or 0)
        out["servfail"] = int(m.get("servfail-answers") or 0)
        out["nxdomain"] = int(m.get("nxdomain-answers") or 0)
        for k in ("latency-avg100", "latency-avg1000"):
            if m.get(k) is not None and out["latency_avg_us"] is None:
                out["latency_avg_us"] = m.get(k)
        out["ok"] = True
    except Exception as e:
        out["error"] = "%s: %s" % (type(e).__name__, e)
    return out

def collect_dnsdist_queries(window_min=60, now=None):
    """读 dnsdist 查询日志，按客户端聚合。返回 dict。"""
    now = time.time() if now is None else now
    cut = now - int(window_min) * 60
    out = {"ok": False, "error": None, "total": 0,
           "by_client": {}, "by_host": {}, "covered_min": 0.0,
           "clients": {}, "hosts": set()}
    try:
        import os as _os
        if not _os.path.exists(DNSDIST_QLOG):
            out["error"] = "日志不存在"
            return out
        # 只读尾部：文件可能很大
        size = _os.path.getsize(DNSDIST_QLOG)
        with open(DNSDIST_QLOG, "r", errors="replace") as f:
            if size > DNSDIST_QLOG_MAX_BYTES:
                f.seek(size - DNSDIST_QLOG_MAX_BYTES)
                f.readline()          # 丢弃不完整首行
            first_ts = last_ts = None
            for ln in f:
                p = ln.rstrip("\n").split(",")
                if len(p) < 4:
                    continue
                try:
                    ts = float(p[0])
                except Exception:
                    continue
                if ts < cut:
                    continue
                ip, qname, qtype = p[1], p[2], p[3]
                if not qname:
                    continue
                if first_ts is None or ts < first_ts:
                    first_ts = ts
                if last_ts is None or ts > last_ts:
                    last_ts = ts
                out["total"] += 1
                out["clients"][ip] = out["clients"].get(ip, 0) + 1
                out["hosts"].add(qname)
                key = (qname, qtype)
                out["by_host"][key] = out["by_host"].get(key, 0) + 1
                cb = out["by_client"].setdefault(ip, {"n": 0, "hosts": set()})
                cb["n"] += 1
                if len(cb["hosts"]) < 500:
                    cb["hosts"].add(qname)
            if first_ts and last_ts:
                out["covered_min"] = round((last_ts - first_ts) / 60.0, 1)
        out["ok"] = True
    except Exception as e:
        out["error"] = "%s: %s" % (type(e).__name__, e)
    return out

def collect_agh_querylog(force_source=None):
    """按时间窗口统计 AGH 查询日志。

    数据源（2026-10-05 改）：**优先 AGH HTTP API**（/control/querylog，读内存环形缓冲 +
    文件，永远新鲜），读 querylog.json 只作兜底。原因：该文件只在缓冲攒满
    querylog.size_memory 或进程优雅退出时才落盘，低流量可滞后几十分钟 → 旧实现读文件
    会得到"查询 0/数据不足"的假象（上游 issue #8485 已确认是设计使然、非丢数据）。"""
    now = time.time()
    _t_func = time.time()
    # QLOG-INCR 分流（2026-10-09）：incr 直接返回增量结果；异常自动回退全量
    if QLOG_MODE == "incr":
        try:
            _t0 = time.time()
            _inc = _qlog_incr_collect(now)
            if _inc is not None:
                _ms = (time.time() - _t0) * 1000.0
                _QLOG_STATE["last_incr_ms"] = _ms
                if _QLOG_STATE["last_incr_ms"] is not None and (_ms > 1500):
                    _qlog_log("QLOG-INCR 本轮偏慢: %.0fms limit=%s store=%s"
                        % (_ms, _inc.get("incr", {}).get("limit"),
                           (_inc.get("incr", {}).get("store") or {}).get("recs")))
                return _inc
        except Exception as _e:
            _QLOG_STATE["errors"] += 1
            _qlog_log("QLOG-INCR 失败（第 %d 次），本轮回退全量: %s: %s"
                % (_QLOG_STATE["errors"], type(_e).__name__, _e))
    # STREAM-AGG v1：只取原始文本，两趟都用生成器走（记录对象内存 O(1)）
    kind, payload, source, src_err = _agh_fetch_raw(force_source)
    ts_newest = 0
    if kind:
        for e in _iter_records(kind, payload):     # 第一趟：只为找最新时间戳做窗口锚点
            ep2 = _agh_ts(e.get("T", ""))
            if ep2 and ep2 > ts_newest:
                ts_newest = ep2
    anchor = ts_newest or now          # 用数据里最新一条的时间做锚点；无数据时退回墙钟
    log_lag_s = max(0, int(now - anchor))
    win_start = anchor - WINDOW_MIN * 60
    out = {
        "queries": 0, "blocked": 0, "allowed": 0,
        "queries_1m": 0,
        "cache_hits": 0, "cache_misses": 0,
        "upstreams": {}, "clients": {}, "slow": [], "slow_total": 0, "types": {},
        "hosts": set(),
        "elapsed_all": [], "elapsed_up": [],
        "window_start": win_start, "ts_min": None, "ts_max": None,
        # 2026-10-09：区分两个跨度 —— ts_min/ts_max 是**整批取数**的跨度（诊断用），
        # win_ts_min/win_ts_max 是**窗口内**实际聚合到的跨度（"最近 1 小时"旁边该显示这个）。
        "win_ts_min": None, "win_ts_max": None,
        "log_lag_s": log_lag_s, "window_anchor": anchor,
        "log_source": source, "log_source_error": src_err,
        # 看板自身探针的剔除口径（2026-10-09 由 IP 改为 QNAME，设计见文件顶部注释）：
        #   probe_queries              = 按**域名**命中的随机冷查询探针条数（已剔除，不参与任何统计）
        #   probe_queries_by_ip_legacy = 来源为 127.0.0.1 的条数（**仅对账**，不再剔除：经 nginx DoH
        #                                的流量同样被记成 127.0.0.1，按 IP 剔除会整体误杀真实流量）
        #   probe_hot_not_excluded     = 固定热探针 www.qq.com 的条数（与真实流量不可区分，故计入并披露）
        "probe_queries": 0, "probe_queries_by_ip_legacy": 0, "probe_hot_not_excluded": 0,
        "security_probe_queries": 0,
        # 2026-10-09 阶段2：探针/压测侧的独立聚合（用户统计里不再包含它们）
        "probe_split": {"queries": 0, "blocked": 0, "allowed": 0, "cache_hits": 0,
                        "cache_misses": 0, "hosts": set(), "by_ip": {}},
    }
    _pnames = probe_name_set()          # 探针随机域名滚动表（本轮已发出、且仍在窗口内的）
    for e in (_iter_records(kind, payload) if kind else ()):   # 第二趟：聚合
        ts = e.get("T", "")
        if len(ts) < 19:
            continue
        try:
            ep = calendar.timegm(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))
        except Exception:
            continue
        if out["ts_min"] is None or ep < out["ts_min"]:
            out["ts_min"] = ep
        if out["ts_max"] is None or ep > out["ts_max"]:
            out["ts_max"] = ep
        if ep < win_start:
            continue
        if out["win_ts_min"] is None or ep < out["win_ts_min"]:
            out["win_ts_min"] = ep
        if out["win_ts_max"] is None or ep > out["win_ts_max"]:
            out["win_ts_max"] = ep
        _qh = e.get("QH", "")
        _ip = e.get("IP", "")
        # 2026-10-09 阶段2：判据由"仅按域名"升级为 **源 IP ∪ 域名**。
        # 源 IP 是阶段1 给探针/压测固定的专用地址（见 PROBE_SRC 注释），比域名更可靠：
        #   · chainmon 固定热探针（www.qq.com）以前无法剔除，现在按源地址即可剔除；
        #   · 压测随机域名不再需要预先登记。
        _is_probe = ((bool(_qh) and _qh in _pnames) or (_ip and _ip in PROBE_SRC))
        if _is_probe:
            ps = out["probe_split"]
            ps["queries"] += 1
            ps["by_ip"][_ip] = ps["by_ip"].get(_ip, 0) + 1
            if _qh:
                ps["hosts"].add(_qh)
            _pup = e.get("Upstream", "")
            if not _pup:
                ps["blocked"] += 1
            else:
                ps["allowed"] += 1
                if bool(e.get("Cached", False)):
                    ps["cache_hits"] += 1
                else:
                    ps["cache_misses"] += 1
            if _qh and _qh in _pnames:
                out["probe_queries"] += 1
            else:
                out["probe_queries_by_src"] = out.get("probe_queries_by_src", 0) + 1
            if _ip in AGH_PROBE_CLIENTS:
                out["probe_queries_by_ip_legacy"] += 1
            continue
        if _ip in AGH_PROBE_CLIENTS:
            out["probe_queries_by_ip_legacy"] += 1
        if _qh == PROBE_HOT_NAME:
            out["probe_hot_not_excluded"] += 1
        ms = e.get("Elapsed", 0) / 1000000.0
        out["queries"] += 1
        out["hosts"].add(_qh)
        # 最近 60 秒的到达量：折线画这个（窗口累计值会被突发流量扯成"急升缓降"的锯齿）
        if ep >= anchor - 60:
            out["queries_1m"] += 1
        out["elapsed_all"].append(ms)
        up = e.get("Upstream", "")
        if not up:
            out["blocked"] += 1
            continue
        out["allowed"] += 1
        cached = bool(e.get("Cached", False))
        if cached:
            out["cache_hits"] += 1
        else:
            out["cache_misses"] += 1
            out["elapsed_up"].append(ms)
            if ms > 500:
                out["slow_total"] += 1
                out["slow"].append({
                    "host": e.get("QH", ""), "ms": round(ms, 1), "type": e.get("QT", ""),
                    "cached": False, "upstream": up, "t": ts,
                })
        st = out["upstreams"].setdefault(up, {"addr": up, "count": 0, "cached": 0, "miss": 0})
        st["count"] += 1
        st["cached" if cached else "miss"] += 1
        ip = e.get("IP", "")
        if ip:
            out["clients"][ip] = out["clients"].get(ip, 0) + 1
        qt = e.get("QT", "?")
        tt = out["types"].setdefault(qt, {"type": qt, "count": 0, "elapsed": []})
        tt["count"] += 1
        if not cached:
            tt["elapsed"].append(ms)

    out["slow"] = sorted(out["slow"], key=lambda x: -x["ms"])[:15]
    out["covered_min"] = round((out["ts_max"] - out["ts_min"]) / 60.0, 1) if out["ts_min"] and out["ts_max"] else 0.0
    # 窗口内实际聚合到的分钟数（"最近 N 小时"的文案应当引用它，而不是整批取数的跨度）
    out["window_covered_min"] = (round((out["win_ts_max"] - out["win_ts_min"]) / 60.0, 1)
                                 if out["win_ts_min"] and out["win_ts_max"] else 0.0)
    out["top_upstreams"] = sorted(out["upstreams"].values(), key=lambda x: -x["count"])
    out["top_clients"] = [{"ip": k, "queries": v} for k, v in
                          sorted(out["clients"].items(), key=lambda kv: -kv[1])[:8]]
    out["by_type"] = []
    for t in sorted(out["types"].values(), key=lambda x: -x["count"]):
        out["by_type"].append({"type": t["type"], "count": t["count"],
                               "p90_ms": round(pct(t["elapsed"], 0.9), 2)})
    if QLOG_MODE == "shadow":
        try:
            _t0 = time.time()
            _inc2 = _qlog_incr_collect(time.time())
            if _inc2 is not None:
                _full_ms = (time.time() - _t_func) * 1000.0
                _QLOG_STATE["last_full_ms"] = _full_ms
                _qlog_shadow_log(out, _inc2, _full_ms, (time.time() - _t0) * 1000.0)
        except Exception as _e2:
            _qlog_log("影子对照失败: %s: %s" % (type(_e2).__name__, _e2))
    return out


def collect_agh_log():
    # 2026-10-09：窗口由 15 分钟改为 1 小时，日志行数随之增长，tail 上限同步抬高（只影响 AGH 服务日志的
    # io_timeout 统计，与 querylog 的 API 取数是两条路径）
    raw = dsh("docker logs --since %dm --tail 6000 %s 2>&1" % (WINDOW_MIN, AGH_CONTAINER), timeout=25)
    lines = raw.split("\n")
    # 2026-10-09 事实核查（含**我自己一次测量错误的更正**）：
    #   ① 我曾按 `docker exec adgh strings … | grep -c 'upstream_type='` 得 0，断言"AGH 无此标记、是死指标" ——
    #      **错**。AGH 用结构化 logger，键与 `=` 分开，所以 `strings | grep -c upstream_type` = 1（常量在），
    #      而运行日志确实打印 `upstream_type=main`（24h 实测 28 行）。我当时的 grep 形式本身有偏差。
    #   ② **一次上游超时会产生 2 行含 "i/o timeout" 的日志**：
    #      `[error] dnsproxy: response received upstream_type=main addr=… status="… i/o timeout"`
    #      `[error] dnsproxy: exchange failed … duration=10.00s`
    #      24h 实测：含 i/o timeout 的行 56 条，而失败交换 28 次 ⇒ **按行计数会把超时数放大一倍**
    #      （这正是我上一版改法引入的新错误，现改回"按失败交换计数"）。
    #   ③ 本机 AGH 未配置兜底上游（fallback_dns=[]），所以任何超时都来自主上游；fallback 计数在语义上
    #      保留（将来配了兜底会自动生效），当前恒 0。
    #   ④ `error_lines` 原先统计**全部** [error] 行 —— 实测窗口内 3 条全是"看板自己凭据错误登录 AGH"
    #      的 auth 失败，会被误读成服务端故障。这里拆成 dnsproxy 错误与其它错误。
    return {
        "io_timeout_main": len([l for l in lines if "exchange failed" in l and "i/o timeout" in l]),
        "io_timeout_fallback": len([l for l in lines if "i/o timeout" in l and "upstream_type=fallback" in l]),
        "io_timeout": len([l for l in lines if "i/o timeout" in l and "upstream_type=main" in l]),
        "conn_reset": len([l for l in lines if "connection reset by peer" in l]),
        "error_lines": len([l for l in lines if "[error]" in l]),
        "error_lines_dnsproxy": len([l for l in lines if "[error]" in l and "dnsproxy" in l]),
        "error_lines_other": len([l for l in lines if "[error]" in l and "dnsproxy" not in l]),
        # 2026-10-09：`docker logs --tail 6000` 是**硬截断**。高流量下 1 小时日志会超过 6000 行，
        # 上述所有日志派生计数（超时/重置/错误行）都会**系统性偏低**。把这个事实显式暴露出来，
        # 避免把"被截断的计数"当成"完整窗口的真实值"。
        "log_lines": len(lines),
        "log_capped": len(lines) >= 5990,
    }


# --------------------------------------------------------------------------
# unbound
# --------------------------------------------------------------------------
def parse_unbound_stats(container):
    raw = dsh("docker exec %s %s -c %s stats_noreset" % (container, UNBOUND_CTL, UNBOUND_CONF_IN_CONTAINER), timeout=15)
    kv = {}
    hist = []
    for ln in raw.split("\n"):
        if "=" not in ln:
            continue
        k, v = ln.split("=", 1)
        k = k.strip()
        v = v.strip()
        if k.startswith("histogram."):
            m = re.match(r"^histogram\.([\d.]+)\.([\d.]+)\.to\.([\d.]+)\.([\d.]+)$", k)
            if m:
                try:
                    hist.append({"to_ms": round(float(m.group(3)) * 1000 + float(m.group(4)) / 1000.0, 3),
                                 "count": int(v)})
                except Exception:
                    pass
            continue
        kv[k] = v

    def f(key, default=0.0):
        try:
            return float(kv.get(key, default))
        except Exception:
            return default

    try:
        fw_raw = dsh("docker exec %s %s -c %s list_forwards"
                     % (container, UNBOUND_CTL, UNBOUND_CONF_IN_CONTAINER), timeout=10)
    except Exception:
        fw_raw = ""
    forwards = [l.strip() for l in fw_raw.splitlines() if l.strip()]

    hits = int(f("total.num.cachehits"))
    miss = int(f("total.num.cachemiss"))
    tot = hits + miss
    return {
        "uptime_s": int(f("time.up")),
        "cachehits": hits, "cachemiss": miss,
        "hit_pct": round(100.0 * hits / tot, 2) if tot else 0.0,
        "forwards": forwards,
        "mode": "forward" if forwards else "recursive",
        "prefetch": int(f("total.num.prefetch")),
        "zero_ttl": int(f("total.num.expired")),  # unbound 1.22 无 num.zero_ttl，真值是 num.expired（旧写法恒 0）
        "recursion_replies": int(f("total.num.recursivereplies")),
        "recursion_avg_ms": round(f("total.recursion.time.avg") * 1000.0, 1),
        "recursion_median_ms": round(f("total.recursion.time.median") * 1000.0, 1),
        "queue_avg": round(f("total.requestlist.avg"), 3),
        "queue_max": int(f("total.requestlist.max")),
        "queue_overwritten": int(f("total.requestlist.overwritten")),
        "secure": int(f("num.answer.secure")),
        "bogus": int(f("num.answer.bogus")),
        "rrset_bogus": int(f("num.rrset.bogus")),
        "servfail": int(f("num.answer.rcode.SERVFAIL")),
        "queries": int(f("total.num.queries")),
        "mem_message_b": int(f("mem.cache.message")),
        "mem_rrset_b": int(f("mem.cache.rrset")),
        "tcp_out": int(f("num.query.tcpout")),
        # 2026-10-08 第7步：B 的出口合规性判据（逐分钟取增量）
        #   udp_out = 明文 UDP 出站（DoT 生效时应恒不增长）
        #   tls_in  = **入站** DoT 客户端查询（B 是转发器、客户端都用 UDP，故此值应恒 0）
        #   queue_exceeded/current = requestlist 压力（本步只观测，不动 max）
        "udp_out": int(f("num.query.udpout")),
        "tls_in": int(f("num.query.tls")),
        "queue_exceeded": int(f("total.requestlist.exceeded")),
        "queue_current": int(f("total.requestlist.current")),
        "rusage_user": round(f("ru_utime"), 2),
        "histogram": hist,
        "raw_ok": bool(kv),
    }


CONF_KEYS = [
    "num-threads", "msg-cache-size", "rrset-cache-size", "key-cache-size", "neg-cache-size",
    "cache-min-ttl", "cache-max-ttl", "prefetch", "prefetch-key", "serve-expired",
    "serve-expired-ttl", "serve-expired-client-timeout", "qname-minimisation", "use-caps-for-id",
    "aggressive-nsec", "do-ip4", "do-ip6", "harden-dnssec-stripped", "val-permissive-mode",
    "edns-buffer-size", "tcp-upstream", "so-reuseport", "num-queries-per-thread",
]


def parse_unbound_conf(path):
    """读取宿主机上的 unbound.conf（bind mount），只提取关心的键。"""
    out = {}
    try:
        with open(path, "r") as f:
            raw = f.read()
    except Exception:
        return out
    for ln in raw.split("\n"):
        if ln.lstrip().startswith("#"):
            continue
        m = re.match(r"^\s*([a-z0-9-]+):\s*(.+?)\s*$", ln)
        if not m:
            continue
        k, v = m.group(1), m.group(2).strip().strip('"')
        if k in CONF_KEYS:
            if v in ("yes", "no"):
                out[k.replace("-", "_")] = (v == "yes")
            else:
                out[k.replace("-", "_")] = v
    # 2026-10-24：原实现用 re.findall 扫全文，把「# 停用(...): forward-addr: X」
    # 也当成有效上游，导致停用的节点仍显示在看板上。改为逐行锚点匹配并跳过
    # 整行注释（行内的 # 是 DoT 的 TLS 主机名分隔符，不能按 # 切分）。
    fa = []
    for ln in raw.split("\n"):
        if ln.lstrip().startswith("#"):
            continue
        m = re.match(r"^\s*forward-addr:\s*(\S+?)(?:\s+#.*)?\s*$", ln)
        if m:
            fa.append(m.group(1))
    if fa:
        out["forward_addr"] = fa
    return out


def parse_infra(container):
    raw = dsh("docker exec %s %s -c %s dump_infra" % (container, UNBOUND_CTL, UNBOUND_CONF_IN_CONTAINER), timeout=20)
    items = []
    for ln in raw.split("\n"):
        ln = ln.strip()
        if not ln:
            continue
        m = re.match(r"^(\S+)\s+(\S+)\s+ttl\s+(\d+)\s+ping\s+(\d+)\s+var\s+(\d+)\s+rtt\s+(\d+)", ln)
        if not m:
            continue
        items.append({"addr": m.group(1), "zone": m.group(2), "ttl": int(m.group(3)),
                      "ping_rtt_ms": int(m.group(4)), "rtt_ms": int(m.group(6)),
                      "lame": ("lame dnssec 1" in ln)})
    items.sort(key=lambda x: -x["rtt_ms"])
    return {
        "total": len(items),
        "lame": len([i for i in items if i["lame"]]),
        "max_rtt_ms": items[0]["rtt_ms"] if items else 0,
        "slow_count": len([i for i in items if i["rtt_ms"] >= 500]),
        "top": items[:6],
    }


# --------------------------------------------------------------------------
# 服务器 / Docker
# --------------------------------------------------------------------------
_prev_cpu = {"t": None, "idle": 0, "total": 0}


def read_cpu_pct():
    try:
        with open("/proc/stat", "r") as f:
            parts = f.readline().split()[1:]
        vals = [float(x) for x in parts]
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0.0)
        total = sum(vals)
    except Exception:
        return 0.0
    prev = _prev_cpu
    pct = 0.0
    if prev["t"] is not None:
        dt = total - prev["total"]
        di = idle - prev["idle"]
        if dt > 0:
            pct = max(0.0, min(100.0, 100.0 * (dt - di) / dt))
    prev["t"], prev["idle"], prev["total"] = time.time(), idle, total
    return round(pct, 1)


def read_net():
    def snap():
        d = {}
        try:
            with open("/proc/net/dev", "r") as f:
                for ln in f.readlines()[2:]:
                    if ":" not in ln:
                        continue
                    name, rest = ln.split(":", 1)
                    fld = rest.split()
                    d[name.strip()] = (int(fld[0]), int(fld[8]))
        except Exception:
            pass
        return d

    a = snap()
    time.sleep(0.5)
    b = snap()
    out = []
    for k in b:
        if k == "lo" or k not in a:
            continue
        if k.startswith("veth") or k.startswith("br-"):
            continue
        rx = (b[k][0] - a[k][0]) * 8.0 / 1000.0 / 0.5      # Kbps
        tx = (b[k][1] - a[k][1]) * 8.0 / 1000.0 / 0.5
        out.append({"iface": k, "rx_kbps": round(rx, 1), "tx_kbps": round(tx, 1)})
    out.sort(key=lambda x: -(x["rx_kbps"] + x["tx_kbps"]))
    return out[:3]


def read_mem():
    d = {}
    try:
        with open("/proc/meminfo", "r") as f:
            for ln in f:
                k = ln.split(":")[0]
                v = ln.split(":")[1].strip().split()[0]
                d[k] = int(v) / 1024.0        # MB
    except Exception:
        return {}
    total = d.get("MemTotal", 0)
    avail = d.get("MemAvailable", d.get("MemFree", 0))
    used = max(0.0, total - avail)
    swap_total = d.get("SwapTotal", 0)
    swap_used = swap_total - d.get("SwapFree", 0)
    return {
        "mem": {"total_mb": int(total), "used_mb": int(used), "available_mb": int(avail),
                "pct": round(100.0 * used / total, 1) if total else 0.0},
        "swap": {"total_mb": int(swap_total), "used_mb": int(swap_used),
                 "pct": round(100.0 * swap_used / swap_total, 1) if swap_total else 0.0},
    }


def read_disk():
    try:
        st = os.statvfs("/")
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        used = total - free
        return {"path": "/", "total_gb": round(total / 1073741824.0, 1),
                "used_gb": round(used / 1073741824.0, 1),
                "pct": round(100.0 * used / total, 1) if total else 0.0}
    except Exception:
        return {}


def read_uptime_load():
    up = 0.0
    try:
        with open("/proc/uptime", "r") as f:
            up = float(f.read().split()[0])
    except Exception:
        pass
    load = [0.0, 0.0, 0.0]
    try:
        with open("/proc/loadavg", "r") as f:
            parts = f.read().split()
        load = [float(parts[0]), float(parts[1]), float(parts[2])]
    except Exception:
        pass
    return up, load


def _grab_cert(host, port, sni, timeout, verify):
    """一次 TLS 握手，取回对端证书。verify=True 时顺带校验链与主机名。"""
    ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()
    if not verify:
        ctx.check_hostname = False
    s = None
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        s = ctx.wrap_socket(raw, server_hostname=sni)
        der = s.getpeercert(True)
        info = s.getpeercert() or {}
        r = {"ok": True, "der": der, "not_after": info.get("notAfter")}
        try:
            r["tls_version"] = s.version()
            r["cipher"] = s.cipher()[0] if s.cipher() else ""
        except Exception:
            pass
        cn = dict(x[0] for x in (info.get("subject") or ())).get("commonName")
        r["subject"] = cn
        r["serial"] = info.get("serialNumber", "")
        return r
    except Exception as e:
        return {"ok": False, "error": ("%s: %s" % (type(e).__name__, e))[:90]}
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def read_cert_live(host="127.0.0.1", port=853, sni=None, timeout=8.0):
    """从 :853 实时握手取证书 —— 这才是客户端（DoT）真正拿到的副本。
    先按公共 CA 校验；失败则退回不校验抓取，以便仍然能比对指纹与到期时间。"""
    sni = sni or TLS_DOMAIN
    r = _grab_cert(host, port, sni, timeout, True)
    verified = bool(r.get("ok"))
    if not verified:
        r2 = _grab_cert(host, port, sni, timeout, False)
        if r2.get("ok"):
            r2["live_error"] = r.get("error", "")
            r = r2
    if not r.get("ok"):
        return {"live_ok": False, "live_verified": False, "live_error": r.get("error", "")}
    out = {"live_ok": verified, "live_verified": verified,
           "live_not_after": r.get("not_after"), "live_subject": r.get("subject"),
           "live_serial": r.get("serial"), "tls_version": r.get("tls_version"),
           "cipher": r.get("cipher")}
    if not verified and r.get("live_error"):
        out["live_error"] = r["live_error"]
    if r.get("not_after"):
        try:
            out["live_days_left"] = int((ssl.cert_time_to_seconds(r["not_after"]) - time.time()) / 86400.0)
        except Exception:
            pass
    if r.get("der"):
        out["live_fingerprint"] = hashlib.sha256(r["der"]).hexdigest()
    return out


def cert_detail(tls):
    """给链路节点用的一句话摘要：以 853 实时证书为准，并与 nginx 文件比对是否漂移。"""
    if not tls:
        return "证书信息不可用"
    parts = []
    if tls.get("live_ok") is False:
        parts.append("⚠ 853 实时握手未通过校验" +
                     ("（%s）" % tls.get("live_error") if tls.get("live_error") else ""))
    if tls.get("drift"):
        parts.append("⚠ 853 实时证书与 nginx 文件不一致，需同步")
    if tls.get("live_days_left") is not None:
        parts.append("853 实时证书剩余 %d 天" % tls["live_days_left"])
    elif tls.get("file_days_left") is not None:
        parts.append("文件证书剩余 %d 天" % tls["file_days_left"])
    if tls.get("live_ok") and tls.get("live_days_left") is not None and not tls.get("drift") \
            and tls.get("file_days_left") is not None:
        parts.append("与 nginx 文件一致")
    return " · ".join(parts) or "证书信息不可用"


def doq_brief(dg):
    """DoQ 快通道可用性摘要：仅保留 guard 当前使用的 aghdq2:5534（2026-10-28 起）。"""
    a = dg.get("doq_ok")
    if a:
        return "DoQ1(Quad9/alt) 正常(%sms)" % dg.get("doq_ms", "-")
    if a is None:
        return "DoQ 未探测"
    return "DoQ1(Quad9/alt) 异常"


def collect_server():
    mem = read_mem()
    up, load = read_uptime_load()
    nginx_ver = ""
    rc, out, err = sh("nginx -v", timeout=5)
    m = re.search(r"nginx/([\d.]+)", (err or "") + (out or ""))
    if m:
        nginx_ver = m.group(1)
    nginx_active = sh("systemctl is-active nginx", timeout=5)[1].strip() == "active"
    # 证书：以 :853 实时握手为准（客户端实际拿到的），nginx 文件作为漂移对照
    tls = {"domain": TLS_DOMAIN, "source": "dot:853 实时握手"}
    tls.update(read_cert_live())
    rc, out, err = sh("openssl x509 -in %s -noout -enddate -fingerprint -sha256 -serial" % TLS_CERT, timeout=8)
    fna = None
    m = re.search(r"notAfter=(.+)", out or "")
    if m:
        fna = m.group(1).strip()
    ffp = None
    m = re.search(r"Fingerprint=([0-9A-Fa-f:]+)", out or "")
    if m:
        ffp = m.group(1).replace(":", "").lower()
    tls["file_not_after"] = fna
    tls["file_fingerprint"] = ffp
    if fna:
        try:
            tls["file_days_left"] = int((calendar.timegm(time.strptime(fna, "%b %d %H:%M:%S %Y %Z")) - time.time()) / 86400.0)
        except Exception:
            pass
    tls["drift"] = bool(tls.get("live_fingerprint") and ffp and tls["live_fingerprint"] != ffp)
    # 兼容旧字段：days_left / not_after 现在反映 853 实时证书，失败才回退文件副本
    if tls.get("live_days_left") is not None:
        tls["days_left"] = tls["live_days_left"]
        tls["not_after"] = tls.get("live_not_after")
    elif tls.get("file_days_left") is not None:
        tls["days_left"] = tls["file_days_left"]
        tls["not_after"] = fna
    return {
        "hostname": socket.gethostname(),
        "uptime_s": int(up),
        "load": load,
        "cpu_count": os.cpu_count() or 1,
        "cpu_pct": read_cpu_pct(),
        "mem": mem.get("mem", {}),
        "swap": mem.get("swap", {}),
        "disk": read_disk(),
        "net": read_net(),
        "nginx": {"version": nginx_ver, "active": nginx_active},
        "tls": tls,
    }


def collect_docker(containers):
    """返回 (容器明细列表, {name: {cpu_pct, mem_usage}})。"""
    stats = {}
    raw = dsh('docker stats --no-stream --format "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}"', timeout=25)
    for ln in raw.split("\n"):
        parts = ln.strip().split("|")
        if len(parts) >= 3:
            stats[parts[0]] = {"cpu_pct": parts[1].replace("%", ""), "mem_usage": parts[2]}
    listing = []
    for name in containers:
        fmt = ("{{.Name}}|{{.Config.Image}}|{{.State.Status}}|"
               "{{if .State.Health}}{{.State.Health.Status}}{{else}}-{{end}}|"
               "{{.RestartCount}}|{{.State.StartedAt}}")
        line = dsh("docker inspect %s --format '%s'" % (name, fmt), timeout=10).strip()
        parts = line.split("|")
        if len(parts) < 6:
            continue
        cname = parts[0].lstrip("/")
        st = stats.get(cname, {})
        listing.append({
            "name": cname, "image": parts[1], "status": parts[2],
            "health": parts[3], "restarts": int(parts[4] or 0),
            "started_at": parts[5],
            "cpu_pct": st.get("cpu_pct", "0"),
            "mem_usage": st.get("mem_usage", ""),
        })
    return listing, stats


def human_uptime(sec):
    sec = int(sec)
    d, rem = divmod(sec, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    if d:
        return "%dd %dh" % (d, h)
    if h:
        return "%dh %dm" % (h, m)
    return "%dm" % m


def container_up_s(container, now):
    """容器启动到现在的秒数，解析失败返回 None。"""
    st = (container or {}).get("started_at", "")
    if not st or len(st) < 19:
        return None
    try:
        return max(0, int(now - calendar.timegm(time.strptime(st[:19], "%Y-%m-%dT%H:%M:%S"))))
    except Exception:
        return None


# --------------------------------------------------------------------------
# 汇总快照
# --------------------------------------------------------------------------
HISTORY = []
GUARD_ALERT_PREV = {}
SNAPSHOT = {"ready": False}
CACHE_PREV = {"agh_hits": None, "agh_miss": None, "ub": {}}
# 2026-10-28：unbound A 的累计计数基线（servfail, queries），用于算窗口差分。
# unbound 的 num.answer.rcode.SERVFAIL / total.num.queries 是"自上次清零以来"的累计值：
# 任何 reload、或一次 unbound-control stats（非 stats_noreset）读取都会归零，
# 直接相除得到的比值既滞后又会被清零拍成 0%/100%（10-28 实测 6 分钟内 78.7%→100%→0%→20.3%）。
SERVFAIL_PREV = {}
SNAP_LOCK = threading.Lock()
COLLECT_LOCK = threading.Lock()
LAST_COLLECT = {"t": 0.0}
COLLECTING = {"v": False}
COLLECT_STATE_LOCK = threading.Lock()


def load_history():
    global HISTORY
    try:
        with open(HISTORY_FILE, "r") as f:
            HISTORY = json.load(f)
        if not isinstance(HISTORY, list):
            HISTORY = []
    except Exception:
        HISTORY = []
    _migrate_history()


def _migrate_history():
    """旧采样点只有比率、没有计数，且"窗口内无查询"被写成了 0%（画出来就是锯齿）。
    这里做一次性迁移：有查询的按比率反推计数（权重=真实查询数），
    无查询的把比率置为 None（前端断线不画）。"""
    for p in HISTORY:
        # 2026-10-23：upstream_share 曾因 24h 滚动窗口过期算出 >100%（实测 103.3/105.7/109.5/110.0），
        # 上游应答不可能多于放行查询 —— 历史坏点统一置 None，否则曲线区间会一直显示"100.0%–110.0%"。
        _us = p.get("upstream_share")
        if isinstance(_us, (int, float)) and not (0 <= _us <= 100):
            p["upstream_share"] = None
        # 延迟 0ms 在物理上不可能（有上游请求才有值），说明当时没有样本 → 置 None
        for k in ("latency_p50_ms", "latency_p90_ms"):
            if p.get(k) == 0:
                p[k] = None
        # 旧采样点没有逐分钟到达量（或早期用墙钟锚点算出了假的 0）：用窗口累计/窗口分钟数近似
        if (p.get("queries_1m") is None or (p.get("queries_1m") == 0 and (p.get("queries") or 0) > 0)) \
                and (p.get("queries") or 0) > 0:
            p["queries_1m"] = int(round(p["queries"] / float(WINDOW_MIN)))
        if "cache_hits" in p:
            continue
        q = p.get("queries") or 0
        if q <= 0:
            p["cache_hit_pct"] = None
            p["block_pct"] = None
            p["cache_hits"] = None
            p["cache_misses"] = None
            p["blocked"] = None
        else:
            c = p.get("cache_hit_pct")
            b = p.get("block_pct")
            if c is None:
                p["cache_hits"] = p["cache_misses"] = None
            else:
                hits = int(round(float(c)))
                p["cache_hits"] = hits
                p["cache_misses"] = max(0, 100 - hits)
            p["blocked"] = int(round(float(b or 0) / 100.0 * q))


def save_history():
    try:
        tmp = HISTORY_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(HISTORY[-HISTORY_MAX:], f)
        os.replace(tmp, HISTORY_FILE)
    except Exception:
        pass


# 逐实例留痕的 unbound 计数字段（A/B 的 bogus 增长原因不同，不能混着看）
UB_HIST_KEYS = ("bogus", "rrset_bogus", "servfail", "queries")
UB_DELTA_WINDOW = 3600       # 增量观察窗口（秒）。2026-10-09 随统计窗口一并由 900 改为 3600（1 小时），
                             # 保持"统计窗口 = 增量窗口 = 图表展示窗口"三者一致


def ub_delta(idx, window_s=UB_DELTA_WINDOW):
    """返回第 idx 个 unbound 实例在最近 window_s 秒的计数增量。

    num.answer.bogus 是自启动累计值，直接拿它算占比只会得到"一直很高"的结论；
    窗口增量才能回答"此刻还在不在新增"。样本不足（刚启动/字段缺失）返回 None。
    """
    if len(HISTORY) < 2:
        return None
    now_t = HISTORY[-1].get("t") or 0
    key0 = "ub%d_bogus" % idx
    pts = [p for p in HISTORY
           if (p.get("t") or 0) >= now_t - window_s and p.get(key0) is not None]
    if len(pts) < 2:
        return None
    a, b = pts[0], pts[-1]
    out = {"span_s": int((b.get("t") or 0) - (a.get("t") or 0)), "samples": len(pts)}
    for k in UB_HIST_KEYS:
        ka, kb = a.get("ub%d_%s" % (idx, k)), b.get("ub%d_%s" % (idx, k))
        out[k] = None if (ka is None or kb is None) else int(kb - ka)
    return out


# --------------------------------------------------------------------------
# 第7步（2026-10-08）：unbound B 的「消费者归类」与逐分钟增量
# --------------------------------------------------------------------------
B_IDX = 1                     # UNBOUND 列表里 B 的下标（A=0, B=1）


def _b_forward_brief(ub_list):
    """B 的 forward 上游摘要（有效条数 + 去重主机名），供链路图文案使用。

    直接读 parse_unbound_conf 的结果，配置一改文案就跟着变，不再写死。
    """
    item = (ub_list[B_IDX] if len(ub_list) > B_IDX else {}) or {}
    addrs = (item.get("config") or {}).get("forward_addr") or []
    hosts = []
    for a in addrs:
        h = a.split("#", 1)[1] if "#" in a else a.split("@")[0]
        if h and h not in hosts:
            hosts.append(h)
    return len(addrs), (" / ".join(hosts) or "—")
B_PREV = {"t": 0.0, "total": None, "guard": None,
          "tls_in": None, "udp_out": None, "tcp_out": None, "rl_max": None, "rl_ex": None}


def _b_delta(cur, prev):
    """累计计数的相邻差。任一为空、或计数回退（容器重启）时返回 None，不伪造 0。"""
    if cur is None or prev is None:
        return None
    try:
        if int(cur) < int(prev):
            return None
        return int(cur) - int(prev)
    except Exception:
        return None


# 残差对账窗口（秒）。2026-10-09 与统计窗口/UB_DELTA_WINDOW 一并由 900 改为 3600（1 小时）：
# guard 的 stats.json 每 20s 落盘一次，单点对账的滞后噪声约为"20 秒内的 B 流量"；
# 窗口越长，这 ±20s 的相位噪声占比越小（实测 5 分钟窗口噪声占比 ~12%，15 分钟降到几 %，
# 1 小时进一步压到 <1%）。
B_RESID_WINDOW = 3600


def b_residual_window(window_s=B_RESID_WINDOW):
    """用最近 window_s 秒的多个采样点做「B 的查询量归因」对账。

    为什么不能只看单点：guard 的 stats.json 是 **每 20 秒** 才落盘一次，所以 chainmon 在任一
    采样点读到的 unbound_b_queries_total 最多滞后 20s；单点 residual 会因此抖动
    ±（20 秒内的 guard B 发送量）。跨 15 分钟（≈15 个点）后这个相位滞后被平均掉：
      · residual 在 ±(20s 内 B 流量) 内波动 ⇒ 所有 B 查询都能归因，没有未登记消费者；
      · 显著且持续为正 ⇒ 确实存在绕过 guard 的消费者（dnscrypt CN 规则 / 人工 dig / 旁路脚本）。
    """
    if len(HISTORY) < 2:
        return None
    now_t = HISTORY[-1].get("t") or 0
    pts = [p for p in HISTORY
           if (p.get("t") or 0) >= now_t - window_s
           and p.get("b_total_queries") is not None and p.get("b_guard_cn") is not None]
    if len(pts) < 2:
        return None
    # 2026-10-09 修复：**计数器回退会让整段窗口失效**。旧实现遇到任何回退就直接返回 None，
    # 于是 7 条 b_reswin_* 序列在 unbound B / guard 重启后**最多空 1 小时**（实测今天 14:40–15:10
    # 全空，根因是 14:10 重启 unbound B 使 total.num.queries 归零）。
    # 现改为：丢弃"最后一次回退之前"的点，只用回退之后的单调段计算，并把 reset 事实写进结果。
    cut = 0
    for _i in range(1, len(pts)):
        if (pts[_i]["b_total_queries"] < pts[_i - 1]["b_total_queries"]
                or pts[_i]["b_guard_cn"] < pts[_i - 1]["b_guard_cn"]):
            cut = _i
    seg = pts[cut:]
    if len(seg) < 2:
        return None
    a, b = seg[0], seg[-1]
    d_tot = b["b_total_queries"] - a["b_total_queries"]
    d_g = b["b_guard_cn"] - a["b_guard_cn"]
    if d_tot < 0 or d_g < 0:       # 仍为回退（异常）→ 不伪造
        return None
    d_p = 0
    d_cr = 0
    for p in seg[1:]:
        d_p += p.get("b_chainmon_probe") or 0
        d_cr += p.get("b_cn_rules") or 0
    return {"window_s": window_s, "span_s": int((b.get("t") or 0) - (a.get("t") or 0)),
            "samples": len(seg), "d_total": d_tot, "d_guard_cn": d_g,
            "chainmon_probe": d_p, "cn_rules_probe": d_cr,
            "residual": d_tot - d_g - d_p - d_cr,
            "reset_detected": bool(cut), "points_dropped": cut}


def b_attrib(ub_stats, dg, probes, dcp=None):
    """把 unbound B 在本采集窗口内收到的查询量拆成「谁打进来的」。

    三个互相独立的计数源：
      · B 自身   : total.num.queries 累计值（容器内 unbound-control stats_noreset）
      · dnsguard : unbound_b_queries_total / _guard_cn / unbound_b_noncn_attempt（stats.json）
      · chainmon : 本轮实际发往 B 的探针条数（`sent`）—— 分两类：
            chainmon_probe = 直连 `172.18.0.1:5354` 的 B 探针
            cn_rules       = 打给 dnscrypt-proxy 的**CN** 探针：dnscrypt 的
                             forwarding-rules 命中 CN 域名后会转发到 `127.0.0.1:5354` = B，
                             所以这也是"chainmon 自己打进 B 的流量"，必须一起扣除
                             （2026-10-08 第8步修正：旧版把它硬编码成 0，导致 residual 虚高）

    对账式（关键）：
        residual = ΔB_total − Δguard_cn − chainmon_probe − cn_rules
    其中 ΔB_total / Δguard_cn 是相邻两次采集的累计差分（窗口≈60s），后两项是
    **本轮**发出的探针数（不是差分 —— 探针每轮固定几条，差分只会得到 0）。

      · residual ≈ 0  ⇒ B 收到的每一条查询都能归因到已知消费者；
      · residual 持续 > 0 ⇒ 存在未登记的消费者（人工 dig / 旁路脚本 / 其它）。

    ⚠️ 容差：collect_probes() 与 parse_unbound_stats() 是**并行**执行的，本轮的探针
    可能落在 B 的 stat 采样点之后、被计入下一窗口。因此 residual 单点会在 ±探针数 内抖动；
    判读要看**连续多个窗口**：持续 > +探针数 才是真有未登记消费者。
    ⚠️ `cn_rules` 是**名义值**（dnscrypt 收到几条 CN 探针就算几条）：dnscrypt 自己有
    cache，重复的 `www.qq.com` 可能命中缓存不外发 ⇒ 真实值可能更小，
    此时 residual 会略微为负（负到 −cn_rules 为止都属正常）。
    另外 noncn_attempt 是"被挡住、根本没发出去"的次数，**不参与**减法。
    """
    global B_PREV
    out = {"total_queries": None, "guard_cn": None, "chainmon_probe": None,
           "cn_rules": None, "manual": None, "noncn_attempt": None, "residual": None,
           "tls_in": None, "udp_out": None, "tcp_out": None,
           "requestlist_max": None, "requestlist_exceeded": None,
           "d_total": None, "d_guard_cn": None,
           "d_tls_in": None, "d_udp_out": None, "d_tcp_out": None,
           "d_requestlist_max": None, "d_requestlist_exceeded": None,
           "prev_age_s": None}
    try:
        st = (ub_stats or [None, None])[B_IDX] or {}
        bc = (dg or {}).get("b_consumers") or {}
        cur_total = st.get("queries")
        cur_guard = bc.get("unbound_b_queries_total")
        cur_probe = None
        cur_cn_rules = None
        if probes is not None:
            cur_probe = 0
            cur_cn_rules = 0
            for p in probes:
                if p.get("target") == "unbound B":
                    cur_probe += int(p.get("sent") or len(p.get("samples_ms") or []))
                if p.get("via_b"):
                    cur_cn_rules += int(p.get("sent") or 0)
            # collect_dnscrypt() 自己那一条 www.qq.com 健康探针同样会被 dnscrypt 转进 B
            cur_cn_rules += int((dcp or {}).get("probe_via_b") or 0)
        out["total_queries"] = cur_total
        out["guard_cn"] = bc.get("unbound_b_queries_guard_cn")
        out["noncn_attempt"] = bc.get("unbound_b_noncn_attempt")
        out["chainmon_probe"] = cur_probe
        out["cn_rules"] = cur_cn_rules
        out["manual"] = None       # 人工查询无法自动计数，只会体现为 residual
        out["tls_in"] = st.get("tls_in")
        out["udp_out"] = st.get("udp_out")
        out["tcp_out"] = st.get("tcp_out")
        out["requestlist_max"] = st.get("queue_max")
        out["requestlist_exceeded"] = st.get("queue_exceeded")
        out["d_total"] = _b_delta(cur_total, B_PREV.get("total"))
        out["d_guard_cn"] = _b_delta(cur_guard, B_PREV.get("guard"))
        out["d_tls_in"] = _b_delta(st.get("tls_in"), B_PREV.get("tls_in"))
        out["d_udp_out"] = _b_delta(st.get("udp_out"), B_PREV.get("udp_out"))
        out["d_tcp_out"] = _b_delta(st.get("tcp_out"), B_PREV.get("tcp_out"))
        out["d_requestlist_max"] = _b_delta(st.get("queue_max"), B_PREV.get("rl_max"))
        out["d_requestlist_exceeded"] = _b_delta(st.get("queue_exceeded"), B_PREV.get("rl_ex"))
        if out["d_total"] is not None and out["d_guard_cn"] is not None and cur_probe is not None:
            out["residual"] = (out["d_total"] - out["d_guard_cn"] - cur_probe
                               - (cur_cn_rules or 0))
        if B_PREV.get("t"):
            out["prev_age_s"] = round(time.time() - B_PREV["t"], 1)
        B_PREV = {"t": time.time(), "total": cur_total, "guard": cur_guard,
                  "tls_in": st.get("tls_in"), "udp_out": st.get("udp_out"),
                  "tcp_out": st.get("tcp_out"), "rl_max": st.get("queue_max"),
                  "rl_ex": st.get("queue_exceeded")}
    except Exception:
        pass
    return out


def collect_dnscrypt():
    """dnscrypt-proxy（加密解析代理）：unbound 的 forward 目标。

    只读：systemd 状态、监听、在用匿名中继（取自自身日志，这是"匿名是否真生效"的唯一可信证据）、
    CN 分流规则规模与最近一次刷新。
    """
    out = {"service": DNSCRYPT_SERVICE, "active": False, "enabled": False, "mem_mb": None,
           "listen": [], "relay": "", "routing": "", "servers_note": "", "servers": [],
           "rules_count": 0,
           "rules_mtime": 0, "refresh_last": "", "probe_ms": 0.0, "probe_ok": False,
           "probe_via_b": 0}
    try:
        out["active"] = dsh("systemctl is-active %s" % DNSCRYPT_SERVICE).strip() == "active"
        out["enabled"] = dsh("systemctl is-enabled %s" % DNSCRYPT_SERVICE).strip() == "enabled"
        pid = dsh("systemctl show -p MainPID --value %s" % DNSCRYPT_SERVICE).strip()
        if pid and pid != "0":
            rss = dsh("ps -o rss= -p %s" % pid).strip()
            if rss:
                out["mem_mb"] = round(float(rss) / 1024.0, 1)
        ss_raw = dsh("ss -lnup 2>/dev/null | grep dnscrypt || true")
        for m in re.finditer(r"(127\.0\.0\.2:5353|127\.0\.0\.1:5399|172\.18\.0\.1:5399)", ss_raw):
            if m.group(1) not in out["listen"]:
                out["listen"].append(m.group(1))
    except Exception:
        pass
    try:
        # 窗口必须够大：dnscrypt-proxy 只在**启动时**输出一次全局
        # "Anonymized DNS: routing everything via [...]"，随后只输出逐服务器的
        # "Anonymizing queries for [X] via [Y]"。旧实现用 -n 500 + tail -80，
        # 全局行被挤出窗口 → routing 恒空 → 界面误报"未启用匿名中继"。
        jr = dsh("journalctl -u %s --no-pager -n 4000 2>/dev/null | "
                 "grep -E 'Anonymized DNS|Anonymizing queries'" % DNSCRYPT_SERVICE)
        _configured, _relays = "", []
        for ln in jr.splitlines():
            m = re.search(r"Anonymized DNS: routing everything via \[(.+?)\]", ln)
            if m:
                _configured = m.group(1).strip()
            m = re.search(r"Anonymizing queries for \[(.+?)\] via \[(.+?)\]", ln)
            if m:
                out["servers_note"] = m.group(1)
                out["relay"] = m.group(2).strip()
                if m.group(2).strip() not in _relays:
                    _relays.append(m.group(2).strip())
        # 观测到的中继优先（这是"匿名真在生效"的实证）；仅在完全观测不到时才回退到配置值。
        out["routing"] = " · ".join(_relays) if _relays else _configured
    except Exception:
        pass
    try:
        # 2026-10-09：界面原来用 servers_note（日志里**最后一条** "Anonymizing queries for [X]"）
        # 当作"在用解析器"，而 toml 里实际配了 6 个（server_names）。这里把它如实读出来。
        with open(DNSCRYPT_CONF) as _cf:
            for _ln in _cf:
                _m = re.match(r"^server_names\s*=\s*\[(.+?)\]", _ln.strip())
                if _m:
                    out["servers"] = [x.strip().strip("'\"") for x in _m.group(1).split(",") if x.strip()]
                    break
    except Exception:
        pass
    try:
        if os.path.exists(DNSCRYPT_RULES):
            out["rules_mtime"] = os.path.getmtime(DNSCRYPT_RULES)
            with open(DNSCRYPT_RULES) as f:
                _rl = [l.strip() for l in f]
            out["rules_count"] = sum(1 for l in _rl if l and not l.startswith("#"))
            # 2026-10-09：guard 用的是**同一个文件**（guard.py CN_DOMAINS_FILE 默认指向它，
            # drop-in 里没有 GUARD_CN_DOMAINS_FILE 覆盖 ⇒ 确认就是它）。但 guard 的装载口径不同：
            # 逐行取 `split()[0]` → 小写 → 去尾点 → **必须含点** → 放进 set 去重。
            # 名单里混着 49 个"无点"品牌 gTLD 条目（sohu/baidu 之类）会被 guard 丢弃。
            # 实测复现该逻辑得 **8788**，与 guard 启动日志"已载入 8788 条（丢弃无点条目 49 个）"完全一致；
            # 描述"CN 域名按名单分流"（那是 guard 的行为）必须引用这个数，不能拿 dnscrypt 的 8837 去说。
            _gd = set()
            for _l in _rl:
                if not _l or _l.startswith("#"):
                    continue
                _d = _l.split()[0].strip().lower().rstrip(".")
                if _d and "." in _d:
                    _gd.add(_d)
            out["rules_count_guard"] = len(_gd)
    except Exception:
        pass
    try:
        if os.path.exists(DNSCRYPT_LOG):
            with open(DNSCRYPT_LOG) as f:
                tail = [l.rstrip() for l in f.readlines()[-4:] if l.strip()]
            out["refresh_last"] = tail[-1] if tail else ""
    except Exception:
        pass
    try:
        # 2026-10-08 第8步：探针名是 www.qq.com（CN）⇒ 会被 dnscrypt 的 CN forwarding-rules
        # 转发到 127.0.0.1:5354 = unbound B。标记 probe_via_b，供 b_attrib 归类为 cn_rules。
        r = dns_ask(DNSCRYPT_PROBE, "www.qq.com", qtype=1, timeout=4.0)
        out["probe_ms"] = round(float(r[0]), 1)
        out["probe_ok"] = (int(r[1]) == 0)
        out["probe_via_b"] = 1
    except Exception:
        out["probe_ok"] = False
    return out


def build_snapshot():
    t0 = time.time()
    res = parallel([
        lambda: agh_conf_raw(),
        lambda: collect_agh_querylog(),
        lambda: collect_agh_log(),
        lambda: collect_probes(),
        lambda: collect_server(),
        # 2026-10-23：补上 aghcf / aghdq2（原来只列 4 个，与实际在跑的链路组件不符）；
        # 不存在的容器会被 collect_docker 跳过，安全。
        # 2026-10-28：移除 unbound-alt / alt-replica-unb——两副本 2026-10-24 已停止（容器保留未删），
        # 继续采集只会让容器表长期显示 "6/8 运行"、把已退役组件当成没起来的链路件。
        # 链路上的 ub-alt 节点改读 docker ps（见 _running_ct），不依赖本清单。
        lambda: collect_docker([AGH_CONTAINER, "aghdq", "aghcf", "aghdq2"]
                               + [u["container"] for u in UNBOUND]),
        lambda: [parse_unbound_stats(u["container"]) for u in UNBOUND],
        lambda: [parse_infra(u["container"]) for u in UNBOUND],
        lambda: collect_dnsguard(),
        lambda: collect_dnscrypt(),
        lambda: collect_agh_stats(),      # 累计计数：权威 QPS 来源（不受 querylog 条数截断影响）
    ], timeout=60.0)

    conf_raw, qlog, aglog, probes, server, docker_res, ub_stats, ub_infra, dg, dcp, agh_stats = res
    conf_raw = conf_raw or ""
    qlog = qlog or {}
    aglog = aglog or {}
    probes = probes or []
    _layer_map = {"DoQ": [], "dnsguard": [], "DNSCrypt": []}
    for _p in probes:
        _t = (_p.get("target") or "")
        if _p.get("random_cold"):
            _p["sample_role"] = "random_cold_probe"
        if _t in ("dnscrypt-proxy",): _layer_map["DNSCrypt"].extend(_p.get("samples_ms") or [])
        elif _t in ("dnsguard",): _layer_map["dnsguard"].extend(_p.get("samples_ms") or [])
        elif _t in ("DoQ", "aghdq"): _layer_map["DoQ"].extend(_p.get("samples_ms") or [])
    def _layer_pct(vals, q):
        vals = sorted(float(x) for x in vals if x is not None)
        if not vals: return None
        # 2026-10-09 统计修正：分位数只有"尾部有足够观测"时才成立。n 小的时候 p90 与 p99 会
        # 退化成同一个值（n=3 时二者都等于 max），把 max 当 p99 报是**伪精度**。
        # 经验门槛：p90 需 n≥10、p99 需 n≥100；不足则返回 None，让前端明确写"样本不足"并给出 max。
        min_n = 100 if q >= 0.99 else (10 if q >= 0.9 else 1)
        if len(vals) < min_n: return None
        i = min(len(vals) - 1, int(round(q * (len(vals) - 1))))
        return round(vals[i], 1)
    layer_latency = {}
    for _k, _v in _layer_map.items():
        _s = sorted(float(x) for x in _v if x is not None)
        layer_latency[_k] = {"n": len(_v), "p50_ms": _layer_pct(_v, .50),
                             "p90_ms": _layer_pct(_v, .90), "p99_ms": _layer_pct(_v, .99),
                             # 样本不足时仍给出有意义的极值（max 不需要样本量门槛）
                             "max_ms": round(_s[-1], 1) if _s else None,
                             "probe_only": True}
    server = server or {}
    container_list, stats_by_name = docker_res if docker_res else ([], {})
    ub_stats = ub_stats or [None, None]
    ub_infra = ub_infra or [None, None]
    dg = dg or {}
    dcp = dcp or {}
    agh_stats = agh_stats or {}

    agh_cfg = parse_agh_config(conf_raw)

    # 概览
    elapsed_all = qlog.get("elapsed_all", [])
    elapsed_up = qlog.get("elapsed_up", [])
    # 2026-10-22：重建「上游往返基线」。
    # 背景：缓存迁到 dnsdist 后，AGH 侧几乎全是未命中缓存的上游查询，
    #   净处理 = 含缓存耗时 - 上游往返。基线取 AGH 上游应答的中位数（保守）。
    #   没有样本时返回 None（前端显示「未知」），不伪造 0。
    _up_base = None
    _up_base_src = None
    _up_base_med = None
    try:
        _els = sorted(float(x) for x in elapsed_up if x is not None)
        if len(_els) >= 10:
            # 2026-10-23：基线改用 **p10 低分位**，不用中位数。
            # 原因：中位数样本 = 中位数本身 ⇒ 净 P50 被扣成 0，指标失去意义。
            # 语义：基线代表「到上游的最小往返」，取低分位才合理。
            _up_base = _els[int(len(_els) * 0.10)]
            _up_base_med = _els[len(_els) // 2]
            _up_base_src = "AGH 上游样本 p10(n=%d)" % len(_els)
    except Exception:
        pass

    queries = qlog.get("queries", 0)
    blocked = qlog.get("blocked", 0)
    hits = qlog.get("cache_hits", 0)
    miss = qlog.get("cache_misses", 0)
    hit_total = hits + miss
    # 样本量指数：0=没有请求 / 1=样本太少，仅作参考 / 2=足够下结论
    def conf(n, low=5, high=30):
        return 0 if n <= 0 else (1 if n < high else 2)

    prot = collect_protections()

    # 2026-10-22：客户端归因改用 **dnsdist 日志**（真实 IP）。
    # 原因：DoT/DoH 已全部由 dnsdist 承接，AGH 只能看到 dnsdist 的地址。
    # 延迟仍用 AGH 的 elapsed（dnsdist 侧拿不到响应耗时），按 qname 关联。
    _dd = collect_dnsdist_queries(window_min=WINDOW_MIN)
    _dds = collect_dnsdist_stats()
    _dd_by = _dd.get("by_client") or {}
    _ebc = qlog.get("el_up_by_client") or {}
    _by_client = []
    if _dd.get("ok") and _dd_by:
        # dnsdist 提供真实客户端 IP，但没有延迟 —— 延迟用同域名在 AGH 的样本估算
        _host_el = qlog.get("el_up_by_host") or {}
        _dd_total = max(1, _dd.get("total") or 0)
        for _c, _info in _dd_by.items():
            _n = _info.get("n") or 0
            if not _n:
                continue
            _hv = []
            for _h in (_info.get("hosts") or ()):
                _hv.extend(_host_el.get(_h) or [])
            _by_client.append({
                "client": _c,
                "proxy": False,
                "client_label": _c,
                "n": _n,
                "p50_ms": round(pct(_hv, 0.5), 1) if _hv else None,
                "p90_ms": round(pct(_hv, 0.9), 1) if _hv else None,
                "p99_ms": round(pct(_hv, 0.99), 1) if _hv else None,
                "max_ms": round(max(_hv), 1) if _hv else None,
                "share_pct": round(100.0 * _n / _dd_total, 1)})
        _by_client.sort(key=lambda x: -x["n"])
        _by_client = _by_client[:8]
    else:
        # 回退：dnsdist 日志不可用时用 AGH 的（2026-10-28 起 AGH 是 TLS 入口，条目含真实客户端 IP）
        for _c, _v in _ebc.items():
            if not _v:
                continue
            _is_proxy = (_c == "172.18.0.1")
            _by_client.append({
                "client": _c,
                "proxy": _is_proxy,
                "client_label": ("172.18.0.1（本机自发查询）" if _is_proxy else _c),
                "n": len(_v),
                "p50_ms": round(pct(_v, 0.5), 1), "p90_ms": round(pct(_v, 0.9), 1),
                "p99_ms": round(pct(_v, 0.99), 1), "max_ms": round(max(_v), 1),
                "share_pct": round(100.0 * len(_v) / max(1, len(elapsed_up)), 1)})
        _by_client.sort(key=lambda x: -x["n"])
        _by_client = _by_client[:8]
    _ebh = qlog.get("el_up_by_host") or {}
    _slow_hosts = []
    for _h, _v in _ebh.items():
        _s = [x for x in _v if x >= 1000]
        if not _s:
            continue
        _slow_hosts.append({
            "host": _h, "slow": len(_s), "n": len(_v),
            "p50_ms": round(pct(_v, 0.5), 1), "max_ms": round(max(_v), 1)})
    _slow_hosts.sort(key=lambda x: -x["slow"])
    _slow_hosts = _slow_hosts[:10]
    _attr_note = ""
    if len(_by_client) >= 2:
        _top = _by_client[0]
        _rest = _by_client[1:]
        if _rest:
            # p90_ms 在上游是"无样本就返回 None"，不是 0（见 3057 行 _hv 为空时）。
            # 直接参与乘加/%.0f 格式化会 TypeError，把整次 build_snapshot 打挂。
            _r2 = [x for x in _rest if x.get("p90_ms") is not None]
            _rest_p90 = (sum(x["p90_ms"] * x["n"] for x in _r2) / max(1, sum(x["n"] for x in _r2))) if _r2 else None
            _tp90 = _top.get("p90_ms")
            _attr_note = ("最大来源 %s 占 %.1f%% 上游查询，P90=%s；其余合计 P90=%s"
                          % (_top["client_label"], _top["share_pct"],
                             ("%.0fms" % _tp90) if _tp90 is not None else "无样本",
                             ("%.0fms" % _rest_p90) if _rest_p90 is not None else "无样本"))
            if any(x.get("proxy") for x in _by_client):
                _attr_note += "。其中 172.18.0.1 是服务器本机自发查询，不是转发汇总"
            # 2026-10-26：单一来源占绝对多数时（如家庭出口占 97.8%），它经 DoQ/DoT 跨境回源，
            # 延迟含上游往返，会把"整体 KPI"拉成故障态；这里显式标注，避免把上游往返读成本机变慢。
            if _top["share_pct"] >= 80:
                _attr_note += ("。该来源经加密上游跨境回源，延迟含上游往返（其余来源 P90 远低），"
                               "不代表解析链变慢")

    # ══════════════════════════════════════════════════════════════════════
    # 2026-10-22：重建「净处理耗时」口径（此前在备份恢复中丢失）
    # 语义：net = 含上游往返耗时 - 上游往返基线（只保留本机处理时间）
    #   基线取 AGH 上游样本中位数；无足够样本时为 None，不伪造 0。
    # ══════════════════════════════════════════════════════════════════════
    def _net(vals, q):
        if not vals or _up_base is None:
            return None
        return round(max(0.0, pct(vals, q) - float(_up_base)), 1)

    def _net_max(vals):
        if not vals or _up_base is None:
            return None
        return round(max(0.0, max(vals) - float(_up_base)), 1)

    _ubv = float(_up_base) if _up_base is not None else 0.0
    net_slow = sum(1 for x in elapsed_up if float(x) - _ubv > 500)

    # 2026-10-28 口径修复（SERVFAIL）：只回答"本次采集窗口内，新查询里有多少被 SERVFAIL"。
    # 计数变负 = 期间被清零（reload / 非 noreset 的 stats 读取）⇒ 本窗口不可用，基线重建后下窗口再算。
    global SERVFAIL_PREV
    _ub0_raw = ub_stats[0] or {}
    _ub0_sf, _ub0_q = _ub0_raw.get("servfail"), _ub0_raw.get("queries")
    _sf_d = _q_d = None
    _sf_prev = SERVFAIL_PREV.get("A")
    if (_sf_prev and _ub0_sf is not None and _ub0_q is not None):
        _d_sf, _d_q = int(_ub0_sf) - _sf_prev[0], int(_ub0_q) - _sf_prev[1]
        if _d_sf >= 0 and _d_q >= 0:
            _sf_d, _q_d = _d_sf, _d_q
    if _ub0_sf is not None and _ub0_q is not None:
        SERVFAIL_PREV["A"] = (int(_ub0_sf), int(_ub0_q))
    # 样本太少时比值无意义（1/1 = 100%）：<20 次新查询不给值，前端显示"不判定"
    _sf_pct = (round(100.0 * _sf_d / _q_d, 1) if (_q_d and _sf_d is not None and _q_d >= 20) else None)

    overview = {
        "queries": queries,
        "queries_1m": qlog.get("queries_1m", 0),
        "blocked": blocked,
        "allowed": qlog.get("allowed", 0),
        "block_pct": round(100.0 * blocked / queries, 1) if queries else 0.0,
        # 2026-10-22：缓存已迁到 dnsdist 的 PacketCache，命中率必须读 dnsdist 统计。
        # AGH 侧缓存已关闭（cache_enabled=false），继续读 AGH 会恒为 0%。
        # 2026-10-26：dnsdist 统计不可用时**不再回退 AGH**。AGH 自 2026-10-22 起 cache_enabled=false，
        # 回退只会恒定得到 0.0%，与"缓存彻底失效"无法区分（本次故障即由此把 81.3% 显示成 0.0%）。
        # 改为 None（前端渲染 "—"）并单独给出失败原因。
        "cache_hit_pct": (_dds.get("cache_hit_pct")
                          if _dds.get("ok") and _dds.get("cache_hit_pct") is not None
                          else None),
        "cache_hit_src": ("dnsdist" if _dds.get("ok") else "unavailable"),
        "dnsdist_stats_error": (None if _dds.get("ok") else (_dds.get("error") or "dnsdist 统计接口不可用")),
        "dnsdist_cache_hits": _dds.get("cache_hits", 0),
        "dnsdist_cache_misses": _dds.get("cache_misses", 0),
        "dnsdist_queries": _dds.get("queries", 0),
        "cache_hits": hits,
        "cache_misses": miss,
        "upstream_reqs": miss,
        "slow_count": qlog.get("slow_total", 0),
        "uniq_hosts": len(qlog.get("hosts") or ()),
        "latency_by_client": _by_client,
        "slow_top_hosts": _slow_hosts,
        "attribution_note": _attr_note,
        "latency_p50_ms": round(pct(elapsed_up, 0.5), 1),
        "latency_p90_ms": round(pct(elapsed_up, 0.9), 1),
        "latency_p99_ms": round(pct(elapsed_up, 0.99), 1),
        "latency_max_ms": round(max(elapsed_up), 1) if elapsed_up else 0.0,
        "latency_all_p50_ms": round(pct(elapsed_all, 0.5), 1),
        "latency_all_p90_ms": round(pct(elapsed_all, 0.9), 1),
        "latency_all_p99_ms": round(pct(elapsed_all, 0.99), 1),
        # 2026-10-22：净处理耗时（扣上游往返）+ 基线（重建）
        "upstream_baseline_ms": (round(_up_base, 1) if _up_base is not None else None),
        "upstream_baseline_med_ms": (round(_up_base_med, 1) if _up_base_med is not None else None),
        "upstream_baseline_src": _up_base_src,
        "net_latency_p50_ms": _net(elapsed_up, 0.5),
        "net_latency_p90_ms": _net(elapsed_up, 0.9),
        "net_latency_p99_ms": _net(elapsed_up, 0.99),
        "net_latency_max_ms": _net_max(elapsed_up),
        "net_latency_all_p50_ms": _net(elapsed_all, 0.5),
        "net_latency_all_p90_ms": _net(elapsed_all, 0.9),
        "net_latency_all_p99_ms": _net(elapsed_all, 0.99),
        "net_slow_count": net_slow,
        "upstream_timeouts": aglog.get("io_timeout_main", 0) + aglog.get("io_timeout_fallback", 0),
        # 客户端数改用 AGH 累计统计（保留期内），不再用 querylog 截断样本
        "clients": len(agh_stats.get("clients") or qlog.get("top_clients", []) or []),
        # 已按 **QNAME** 剔除了的看板自身随机冷查询探针条数（仅作提示，不参与延迟/命中率计算）
        "probe_queries": qlog.get("probe_queries", 0),
        # 2026-10-09：窗口由 15 分钟改为 1 小时后，**取数上限**成了新的失效模式 ——
        # AGH 的 querylog 是按条数截取的（?limit=N），突发流量下 1 小时拿不满，
        # 若不当心就会把"实际只覆盖 40 分钟"当成"1 小时统计"用。这两个字段把事实摆出来：
        #   window_covered_min = 本次真正聚合到的时间跨度（分钟）
        #   window_truncated   = 最早记录比窗口起点还新 2 分钟以上（没盖满窗口）
        "window_covered_min": qlog.get("window_covered_min", 0.0),
        "window_truncated": bool(qlog.get("ts_min") and qlog.get("window_start")
                                 and qlog["ts_min"] > qlog["window_start"] + 120),
        "guard_metrics": dg.get("guard_metrics", {}),
        # 2026-10-09 修复（字段审计发现）：`unbound_servfail/bogus/queries` 原先**只写进了 HISTORY**，
        # 而前端 perf-error 读的是 `o.unbound_servfail` ⇒ overview 里没有该键 ⇒ SERVFAIL 分量恒为 0。
        # 这是"取错了地方"的静默缺陷（图上看起来像"没有 SERVFAIL"）。此处补进 overview。
        "unbound_servfail": (ub_stats[0] or {}).get("servfail"),
        "unbound_bogus": (ub_stats[0] or {}).get("bogus"),
        "unbound_queries": (ub_stats[0] or {}).get("queries"),
        # 2026-10-28：窗口差分量（口径修复，见上方 SERVFAIL_PREV）——前端判定只看这三个，
        # 上面的累计值仅留给解析器表与历史序列，不再参与"是否降级"。
        "unbound_servfail_delta": _sf_d,
        "unbound_queries_delta": _q_d,
        "unbound_servfail_pct": _sf_pct,
        # AGH 日志尾部是否被 --tail 上限截断（截断则超时/错误计数只是下界）
        "agh_log_lines": aglog.get("log_lines"),
        "agh_log_capped": bool(aglog.get("log_capped")),
    }
    # 样本量：界面据此决定"显示数值"还是"显示数据不足"，避免无请求时整屏变成 0
    overview["samples"] = {
        "queries": queries,
        "upstream": miss,
        "cache": hit_total,
        "conf_queries": conf(queries),
        "conf_upstream": conf(miss),
        "conf_cache": conf(hit_total),
    }

    # unbound 明细
    ub_list = []
    for i, u in enumerate(UNBOUND):
        st = ub_stats[i] or {}
        ub_list.append({
            "name": u["name"], "container": u["container"], "role": u["role"], "addr": u["addr"],
            "stats": st,
            "config": parse_unbound_conf(u["conf"]),
            "infra": ub_infra[i] or {},
            "container_info": next((c for c in container_list if c["name"] == u["container"]), {}),
        })

    # 链路总缓存：AGH 窗口命中 + Unbound A/B 在本采集窗口新增的缓存命中。
    # Unbound 是累计计数，使用相邻快照差分；首次采集或重启后无足够基线时显示样本不足。
    global CACHE_PREV
    _agh_h, _agh_m = int(hits or 0), int(miss or 0)
    _ub_hits = 0
    _ub_ready = bool(CACHE_PREV.get("ub"))
    for _u in ub_list:
        _name = _u.get("name") or _u.get("container")
        _cur = int((_u.get("stats") or {}).get("cachehits") or 0)
        _old = CACHE_PREV.get("ub", {}).get(_name)
        if _old is not None and _cur >= _old:
            _ub_hits += (_cur - _old)
        else:
            _ub_ready = False
    # AGH 与 Unbound 没有请求级关联：AGH 命中不会进入 Unbound，
    # 不能把两层命中数相加后除以 AGH 查询数。仅保留各层独立观测值。
    _resolver_hits = _ub_hits if _ub_ready else None
    chain_cache = {
        "hit_pct": None, "hits": None, "queries": None,
        "agh_hits": _agh_h, "resolver_hits": _resolver_hits,
        "resolver_cache_hits_observed": _ub_hits if _ub_ready else None,
        "estimated": False, "note": "无法按请求级关联 AGH 与 Unbound 命中；分别查看各层命中率"
    }
    CACHE_PREV = {"agh_hits": _agh_h, "agh_miss": _agh_m,
                  "ub": {(_u.get("name") or _u.get("container")): int((_u.get("stats") or {}).get("cachehits") or 0) for _u in ub_list}}

    agh_container = next((c for c in container_list if c["name"] == AGH_CONTAINER), {})

    # 链路拓扑
    def probe_by(target, label_kw):
        for p in probes:
            if p["target"] == target and label_kw in p["label"]:
                return p
        return None

    agh_hot = probe_by("AGH", "热缓存")
    ua_hot = probe_by("unbound A", "热缓存")
    ub_hot = probe_by("unbound B", "热缓存")
    dot360 = probe_by("dot.360.cn", "")
    aldns = probe_by("dns.alidns.com", "")
    rootp = probe_by("根服务器", "")

    def st_of(p, ok_th=50.0, warn_th=500.0):
        if not p:
            return "idle"
        if p["status"] == "error":
            return "error"
        if p["status"] == "warn":
            return "warn"
        v = p.get("p50_ms", 0)
        if v > warn_th:
            return "warn"
        if v > ok_th:
            return "warn"
        return "ok"

    clients = qlog.get("top_clients", [])
    tls_node = server.get("tls", {})
    cert_warn = (bool(tls_node.get("drift")) or tls_node.get("live_ok") is False
                 or (tls_node.get("days_left") is not None and tls_node["days_left"] < 14))
    nginx_status = ("error" if not server.get("nginx", {}).get("active")
                    else ("warn" if cert_warn else "ok"))
    # 2026-10-23：:853 的 TLS 终结器已从 nginx stream 换成 dnsdist（nginx stream 的 :853 停用，
    # 配置在 /www/server/panel/vhost/nginx/tcp/disabled/）。nginx 现在只负责 :443 的网站与 /dns-query 兜底。
    dotf_status = nginx_status
    dotf_brief = ("运行中" if nginx_status == "ok" else "异常")
    spool_bytes = 0

    # 旁路观测：devfp / nDPI（只读 127.0.0.1:8789，不影响解析）
    obs_devfp = {}
    try:
        obs_devfp = json.loads(urllib.request.urlopen(
            "http://127.0.0.1:8789/api/summary", timeout=5).read().decode("utf-8"))
    except Exception as e:
        obs_devfp = {"error": str(e)[:60]}

    # 2026-10-09：unbound A 节点的 detail 原来**无条件**打印"转发目标"，递归型实例会显示
    # "转发目标 —"，与节点副标题"转发(forward-zone) + DNSSEC 验证"自相矛盾。这里按实测模式生成。
    _ua0 = (ub_list[0].get("stats") or {}) if ub_list else {}
    _ua_hit = round(_ua0.get("hit_pct") or 0, 1)
    _ua_mode = (_ua0.get("mode") or "")
    _ua_fw = " · ".join((_ua0.get("forwards") or [])[:2]) or "（未取到目标）"
    # 2026-10-26：补上"回源中位耗时"与"队列溢出"，否则只看命中率无法判断慢在上游还是在本机排队。
    _ua_med = _ua0.get("recursion_median_ms")
    _ua_qx = int(_ua0.get("queue_exceeded") or 0)
    _ua_suffix = (" · 回源中位 %s · 队列溢出 %s"
                  % (fmt_ms(_ua_med) if _ua_med is not None else "—", _ua_qx))
    _ua_detail = ((("缓存命中 %s%% · 解析方式：直接递归（从根逐级查询）· DNSSEC 验签" % _ua_hit)
                   if _ua_mode == "recursive"
                   else ("缓存命中 %s%% · 解析方式：转发 → %s" % (_ua_hit, _ua_fw))) + _ua_suffix)
    verifier_active = dsh("systemctl is-active dnsguard-verifier 2>/dev/null").strip() == "active"
    # 2026-10-22 起 dnsdist 是 DoT(:853)/DoH(:444) 的生产入口（TLS 终结 + PacketCache），不再"旁路"
    dnsdist_active = dsh("systemctl is-active dnsdist 2>/dev/null").strip() == "active"
    verifier_mem = dsh("systemctl show dnsguard-verifier -p MemoryCurrent --value 2>/dev/null").strip()
    # 一次采样拿到在跑容器名，供 aghdq2 / unbound-alt / alt-replica-unb 这类"未入主链"节点判状态
    _running_ct = set((dsh("docker ps --format '{{.Names}}' 2>/dev/null") or "").split())
    _ua_stats = (ub_list[0].get("stats") or {}) if ub_list else {}
    _ua_config = (ub_list[0].get("config") or {}) if ub_list else {}
    chain_nodes = [
        {"id": "clients", "name": "DNS 接入来源（非设备数）", "sub": "DoT :853 · DoH :444（AGH 直收，按客户端 IP 注入 ECS）；:443 的 /dns-query 由 nginx 兜底",
         "status": "ok" if clients else "idle",
         "detail": ("近 %d 分钟 %d 个来源 IP（网关会合并多个设备）" % (WINDOW_MIN, len(clients))) if clients
                   else ("近 %d 分钟无查询" % WINDOW_MIN)},
        # 2026-10-23 核对：:853 DoT 与 :444 DoH 自 2026-10-22 起由 dnsdist 直接终结 TLS，
        # nginx stream 的 :853 已停用（配置移入 vhost/nginx/tcp/disabled/）。旧节点写"Nginx stream
        # TLS 终结 → AGH DoT:8854"会把入口指错组件，且漏掉 dnsdist 的 PacketCache。
        {"id": "entry", "name": "接入终结层 · AdGuard Home",
         "sub": ("DoT :853 / DoH :444 · TLS 终结 + 按客户端 IP 注入 ECS（/24）→ dnsdist 172.18.0.1:5300"
                 if agh_container.get("status") == "running" else "AGH 未运行：DoT :853 / DoH :444 入口不可用"),
         "status": "ok" if agh_container.get("status") == "running" else ("warn" if agh_container else "error"),
         # 2026-10-28 per-user ECS 改造：AGH 由"过滤层"上移为"接入终结层"——它是唯一能看到真实客户端
         # 公网 IP 的位置，由它按客户端 IP 动态注入 ECS(/24)。AGH 自带缓存不分 ECS（实测会把江西答案
         # 缓存给安徽），故 cache_enabled 必须保持 false；缓存下沉到 dnsdist（parseECS=true）。
         "detail": ("ECS 动态注入 /24 · 自身缓存关闭（缓存由 dnsdist 承担）· 镜像 %s"
                    % (agh_container.get("image", "").split(":")[-1] or "—"))},
        {"id": "nginx", "name": "网页入口 · nginx :443",
         "sub": "网站/看板 + /dns-query → AGH 容器 443；stream 的 :853 DoT 已停用（配置在 tcp/disabled/）",
         "status": "error" if not server.get("nginx", {}).get("active") else ("warn" if cert_warn else "ok"),
         "detail": ("nginx %s · %s" % (server.get("nginx", {}).get("version") or "?",
                                       cert_detail(tls_node))) if server.get("nginx", {}).get("active") else "nginx 未运行"},
        {"id": "agh", "name": "内网缓存层 · dnsdist",
         "sub": ("172.18.0.1:5300 · ECS 感知 PacketCache（65536 条，parseECS=true）→ guard 172.18.0.1:5355"
                 if dnsdist_active else "dnsdist 未运行：内网缓存层不可用"),
         "status": ("ok" if (dnsdist_active and _dds.get("ok")) else ("warn" if dnsdist_active else "error")),
         "detail": (("缓存命中 %s（按 ECS 分键，/24 独立）· 未命中 %s · 查询日志 /var/log/dnsdist-query.log"
                     % ("{:,}".format(int(overview.get("dnsdist_cache_hits") or 0)),
                        "{:,}".format(int(overview.get("dnsdist_cache_misses") or 0))))
                    if (dnsdist_active and _dds.get("ok")) else
                    ("采集不可用（%s）· 服务在跑，缓存统计未通" % (_dds.get("error") or "统计接口不可用"))
                    if dnsdist_active else "服务未运行（systemctl is-active dnsdist）")},
        {"id": "verifier", "name": "独立 verifier 核验（侧车）",
         "sub": "Unix Socket · guard 策略核验 / R8 / 严格共识 / CN 存在性核验；不直接监听 DNS",
         "status": "ok" if verifier_active else "error",
         "detail": ("运行中 · 内存 %s MiB" % (round(int(verifier_mem)/1048576.0,1) if verifier_mem.isdigit() else "—")) if verifier_active else "服务未运行"},
        {"id": "dnsguard", "name": "dnsguard 安全策略与准入",
         "sub": "dnsdist 主上游 :5355 · 探针专用通道 :5356",
         "status": ("warn" if not dg.get("correct_ok") else "ok") if dg.get("active") else "error",
         "detail": ("已判定 %d 个域名 · 累计纠偏 %s 次 · %s · 自检%s" % (
             dg.get("learned", 0), (dg.get("stats") or {}).get("redirect", 0), doq_brief(dg),
             "通过" if dg.get("correct_ok") else "未通过")) if dg.get("active") else "服务未运行"},
        {"id": "unbound-a", "name": "unbound A", "sub": ("转发 → aghcf :5535（CF+censurfridns 并行）+ aghdq2 备用 · 本地 DNSSEC 验签 :5353" if _ua_stats.get("mode") == "forward" else "直接递归 + 本地 DNSSEC 验签 :5353" if _ua_stats.get("mode") == "recursive" else "解析方式未采集 :5353"),
         # 2026-10-26：热缓存探针此前会在 TTL 过期瞬间 3 包全回源（上游 DoQ 中位 243ms），
         # p50=187.9ms 被 ok_th=50 判成 warn —— 那是"缓存过期"不是"故障"。
         # 已在 probe_target(warmup=True) 里加预热包剔除该假象，阈值保持默认 50/500；
         # detail 另给出回源中位与队列溢出，真故障仍需人看一眼确认。
         "status": st_of(ua_hot),
         "detail": _ua_detail},
        {"id": "dnscrypt-proxy", "name": "dnscrypt-proxy（本机加密出口）",
         "sub": "127.0.0.2:5353 / 127.0.0.1:5399 · guard 辅助候选与影子核验；CN 名单可转 B",
         "status": ("ok" if (dcp.get("active") and dcp.get("probe_ok"))
                    else ("warn" if dcp.get("active") else "error")),
         "detail": ("运行中 · 监听 %s · CN 分流 %s 条 · 匿名中继 %s" % (
             " ".join(dcp.get("listen") or ["未监听"]), dcp.get("rules_count", 0),
             dcp.get("relay") or "未启用") if dcp.get("active") else "服务未运行")},
        {"id": "aghdq", "name": "加密上游出口 · aghcf（aghdq 已摘除）",
         "sub": "aghcf :5535 → Cloudflare DoT + censurfridns DoT 并行（2026-10-28 起 upstream_mode=parallel）是 A 的主 forward-addr，IP 动态自愈；aghdq2(Quad9 DoQ) 作备用；aghdq :5533 → NextDNS DoQ 已于 2026-10-28 摘除（上游握手故障）",
         "status": ("ok" if dg.get("doq_ok") else ("error" if dg.get("doq_ok") is False else "idle")),
         "detail": "DoQ 通道探针 %s · guard 保活 %s（每轮全新随机域名）" % (
             fmt_ms(dg.get("doq_ms")) if dg.get("doq_ok") else "无应答",
             fmt_ms((dg.get("guard_metrics") or {}).get("fast_source_doq_ms"))
             if (dg.get("guard_metrics") or {}).get("fast_source_doq_ok") else "—")},
        # 2026-10-23 补录：两台"存在但未入主链"的组件，原来完全没进图，容易被误认为不存在
        {"id": "aghdq2", "name": "alt 备用通道 · aghdq2",
         "sub": "aghdq2 :5534 → Quad9 DoQ（172.18.0.9）；2026-10-28 起作 guard 的 alt 备用通道（与 A 的 Cloudflare 异构）",
         "status": "ok" if "aghdq2" in _running_ct else "idle",
         "detail": ("容器运行中 · 上游 quic://dns10.quad9.net · 不参与当前解析"
                    if "aghdq2" in _running_ct else "容器未运行")},
        # 2026-10-25：两台副本已停用（容器保留未删）。
        # 5357 走欧洲两家隐私 DoT，实测真实中国域名 800–1233ms、163/jd 直接超时；
        # 2026-10-28：alt 备用通道由 aghdq :5533（NextDNS DoQ，上游反复握手失败）改为
        #   aghdq2 :5534（Quad9 DoQ）。不指 5535 的理由：A 的唯一上游已是 aghcf→Cloudflare，
        #   alt 若同源，rescue 时拿不到独立第二意见，失去防投毒价值。
        {"id": "ub-alt", "name": "已停用 · unbound-alt / alt-replica-unb",
         "sub": "原 127.0.0.1:5357 / :15353 → dges、censurfridns 欧洲 DoT（跨洋 800–1233ms、163/jd 超时）；alt 现走 aghdq2 :5534（Quad9 DoQ）",
         "status": "ok" if ("unbound-alt" in _running_ct and "alt-replica-unb" in _running_ct) else "idle",
         "detail": ("两副本 均在运行 · 独立于 A/B 链路，仅供对照与取证，用户查询不经过"
                    if ("unbound-alt" in _running_ct and "alt-replica-unb" in _running_ct)
                    else "两副本均已停止（2026-10-25）· alt 备用通道改指 aghdq2 :5534（Quad9 DoQ）")},
        {"id": "resolvers", "name": "境外加密解析器",
         "sub": "DNSCrypt 匿名路由观测；不代表全部 DNS 流量匿名",
         "status": "ok" if dcp.get("relay") else "warn",
         "detail": "在用 %s via %s · 路由 %s" % (dcp.get("servers_note") or "—",
                                                 dcp.get("relay") or "—",
                                                 (dcp.get("routing") or "—")[:60])},
        {"id": "roots", "name": "根 / TLD / 权威",
         "sub": "独立根服务器可达性参照；不能代表整条权威链路",
         # 2026-10-26：roots 探的是 a.root-servers.net(198.41.0.4)，从杭州到美东的跨洋
         # UDP 往返物理下限就在 180ms 左右（实测 ping mdev<1ms、五台根服务器 180~244ms），
         # 用内网默认 ok_th=50 判定会让它**永久 warn**——不是故障，是阈值与量纲不匹配。
         # 这跟 unbound-a 那次"缓存过期被当故障"是同类问题，只是这里无药可医（改探针降不了光速）。
         # 给跨洋基线单独阈值：<260ms 视为正常，>600ms 才算真异常（此时更可能是线路或根侧问题）。
         "status": st_of(rootp, ok_th=260.0, warn_th=600.0),
         "detail": ("仅观测探针目标；A 为转发时，逐级递归由远端上游执行。"
                    "跨洋基线 180~244ms（阈值 260/600）"
                    + ("；本轮 %s ms" % rootp["p50_ms"] if rootp else ""))},
        {"id": "unbound-b", "name": "unbound B",
         "sub": "CN 分流解析器 :5354 · %d 条国内加密 DoT（%s）" % _b_forward_brief(ub_list),
         "status": "ok" if ub_hot and ub_hot.get("status") == "ok" else "idle",
         "detail": "历史 fallback_b 计数 %s · 近 %d 分钟 AGH 直接选 B %d 次（不包含 guard 内部调用）" % (
             (dg.get("stats") or {}).get("fallback_b", 0), WINDOW_MIN,
             sum(1 for u in qlog.get("top_upstreams", []) if ":5354" in u["addr"]))},
        {"id": "secure-dot", "name": "加密 DoT 上游", "sub": "dot.360.cn · dns.alidns.com",
         "status": ("error" if (dot360 and dot360.get("status") == "error") and (aldns and aldns.get("status") == "error")
                    else "warn" if (dot360 and dot360.get("status") != "ok") or (aldns and aldns.get("status") != "ok")
                    else "ok"),
         "detail": "360 TCP 建连 %s · 阿里 TCP 建连 %s（不是 TLS 验证或 DNS 查询耗时）" % (
             fmt_ms(dot360.get("p50_ms")) if dot360 else "-", fmt_ms(aldns.get("p50_ms")) if aldns else "-")},
    ]

    now = time.time()
    # 2026-10-09 的旧记载（已作废，保留供考古）：dnsdist 曾是 10-07 停用并 masked 的旁路组件。
    # 2026-10-22 起它重新成为 DoT/DoH 生产入口，节点 id 也从 "dnsdist" 改为 "entry" 承担。
    # 2026-10-23 架构核对（实测，取代 2026-10-09 的旧记载）：
    #   主线 = 客户端 → dnsdist(:853 DoT / :444 DoH，TLS 终结 + PacketCache)
    #          → AGH(172.18.0.2:53，过滤+缓存) → dnsguard(172.18.0.1:5355)
    #          → unbound A(172.18.0.1:5353，本地 DNSSEC) → aghdq/aghcf 加密出口
    #   dnsdist 自 2026-10-22 起是**生产入口**（nginx stream 的 :853 已停用），不再是旁路；
    #   nginx 只在 :443 提供网站/看板与 /dns-query 兜底，不进 DNS 主线。
    #   verifier 是 dnsguard 通过 Unix Socket 调用的侧车；dnscrypt-proxy / 境外加密解析器
    #   是 guard 的干净候选通道；aghdq2(Quad9) 与 unbound-alt/alt-replica-unb 未入主链。
    _main_ids = ["clients", "entry", "agh", "dnsguard", "unbound-a"]
    # 2026-10-28：unbound A 是 forwarder（forward-zone "." → aghcf 加密出口，另带 aghdq2 备胎），
    # 不能再按某个具体 IP 判定（aghcf 容器地址会漂移），只看模式与是否配了 forward-addr。
    _a_via_doq = _ua_stats.get("mode") == "forward" and bool(_ua_config.get("forward_addr"))
    if _a_via_doq:
        _main_ids.append("aghdq")
    _aux_ids = ["verifier", "nginx", "dnscrypt-proxy", "resolvers", "aghdq2", "ub-alt"]
    if "aghdq" not in _main_ids:
        _aux_ids.append("aghdq")
    chain_main = [next(n for n in chain_nodes if n["id"] == key) for key in _main_ids]
    chain_fallback = [n for n in chain_nodes if n["id"] in ("unbound-b", "secure-dot")]
    chain_aux = [n for n in chain_nodes if n["id"] in _aux_ids]
    chain_external = [n for n in chain_nodes if n["id"] in ("roots",)]
    _gst = dg.get("stats") or {}
    _alerts = []
    # guard stats 是累计计数；告警看相邻采集增量，避免历史事件永久标红。
    global GUARD_ALERT_PREV
    _guard_delta = {}
    for _k in ("fail_closed", "clean_fail", "r8_checked", "r8_miss", "r8_auth_none"):
        _cur = int(_gst.get(_k, 0) or 0)
        _old = GUARD_ALERT_PREV.get(_k, _cur)
        _guard_delta[_k] = max(0, _cur - _old)
        GUARD_ALERT_PREV[_k] = _cur
    if _guard_delta.get("fail_closed", 0) >= 20:
        _alerts.append({"level":"critical", "code":"fail_closed", "text":"dnsguard 最近采集周期 fail-closed 次数异常"})
    # 2026-10-26：分子分母必须同源。旧写法用 r8_auth_none 当分子、r8_checked 当分母，
    # 但这两个计数根本不是一件事：
    #   · r8_checked 只在 guard.py 的主同步 R8 路径自增（一处）；
    #   · r8_auth_none 的真值来自 verifier 进程，且**覆盖了 veto/strict 池的失败**——
    #     实测四次采样均满足 r8_auth_none 增量 == v_pool_veto 增量（corrob/strict 池全 ok）。
    # 结果是"CN 否定存在否决"的失败被算成了 R8 的失败，比例还能超过 100%（曾报 189.3%(53/28)）。
    # 改用 r8_miss / r8_checked：两者都在 guard 进程、都以"一次同步 R8"为单位，同源可比。
    _r8c = _guard_delta.get("r8_checked", 0)
    _r8m = _guard_delta.get("r8_miss", 0)
    if _r8c >= 20 and _r8m >= 5 and (_r8m / float(_r8c)) > 0.10:
        _alerts.append({"level":"warn", "code":"r8_auth_none", "text":"R8 最近采集周期核对未成功比例升高（%.1f%%，%d/%d）" % (_r8m * 100.0 / _r8c, _r8m, _r8c)})
    if _guard_delta.get("clean_fail", 0) >= 3:
        _alerts.append({"level":"warn", "code":"clean_fail", "text":"干净上游最近采集周期失败次数升高"})
    # 2026-10-09 P11：证书到期告警（30/14/7 天阈值）。取值口径与 server.tls.days_left 一致
    # （853 实时握手优先，失败回退文件副本）；无值时不告警，避免误报。
    try:
        _dl = ((server or {}).get("tls") or {}).get("days_left")
    except Exception:
        _dl = None
    if isinstance(_dl, int) and _dl <= 30:
        _alerts.append({"level": "critical" if _dl <= 7 else "warn", "code": "cert_expiry",
                        "text": "dns.example.com 证书剩余 %d 天（阈值 30/14/7）" % _dl})
    # 2026-10-09 P7：单客户端重试风暴告警（只告警，不封禁）。依据：10-08 单域名
    # sdk-log.partner.sm.cn 造成单客户端约 10 qps 重试风暴，占全部查询 73.7%，
    # 把看板的查询量/命中率/拦截率口径整体带偏。
    try:
        _tc = qlog.get("top_clients") or []
        _tot_q = max(1, int(qlog.get("queries") or 1))
        if _tc:
            _tn = int((_tc[0] or {}).get("queries", 0) or 0)
            if _tn >= 20000 and _tn / float(_tot_q) >= 0.5:
                _alerts.append({"level": "warn", "code": "client_flood",
                                "text": "单客户端 %s 在 %d 分钟窗口内查询 %d 条（占 %.0f%%），疑似重试风暴"
                                        % ((_tc[0] or {}).get("ip", "?"), WINDOW_MIN, _tn, _tn * 100.0 / _tot_q)})
    except Exception:
        pass
    snap = {
        "ts": now,
        "server_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)) + " (UTC+8)",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(now)),
        "auto_refresh_s": AUTO_REFRESH_S,
        "window_min": WINDOW_MIN,
        "covered_min": qlog.get("covered_min", 0.0),
        "log_lag_s": qlog.get("log_lag_s", 0),
        "log_source": qlog.get("log_source", "-"),
        "overview": overview,
        "cache_chain": chain_cache,
        "observe": {
            # 2026-10-28：:853/:444 的 TLS 终结已上移到 AGH（由它按客户端真实 IP 注入 ECS /24）；
            # dnsdist 只在 172.18.0.1:5300 做 ECS 感知 PacketCache，不再是公网入口。
            # 下面 dnsdist_front 的 active/queries 仍取 dnsdist 自身统计（= 内网缓存层吞吐）。
            "dnsdist_front": {"active": dnsdist_active,
                              "queries": int(overview.get("dnsdist_queries") or 0),
                              "cache_hits": int(overview.get("dnsdist_cache_hits") or 0),
                              "cache_misses": int(overview.get("dnsdist_cache_misses") or 0),
                              "cache_pct": overview.get("cache_hit_pct"),
                              "stats_ok": bool(_dds.get("ok")),
                              "stats_error": (None if _dds.get("ok") else _dds.get("error")),
                              "hint": "内网缓存层 172.18.0.1:5300 · ECS 感知 PacketCache 65536 条（parseECS=true）→ guard 172.18.0.1:5355；公网 DoT/DoH 入口已上移到 AGH :853/:444"},
            "nginx_stream": {"active": bool(server.get("nginx", {}).get("active")),
                             "brief": ("网页入口 :443（网站/看板 + /dns-query → AGH 容器 443）；"
                                       "stream 的 :853 DoT 配置已移入 tcp/disabled/，不再监听"
                                       if server.get("nginx", {}).get("active") else "nginx 未运行"),
                             "spool_mb": round(spool_bytes / 1048576.0, 1)},
            "devfp": {"ok": bool(obs_devfp) and not obs_devfp.get("error"),
                      "devices": obs_devfp.get("devices"), "conns": obs_devfp.get("conns"),
                      "doh_requests": obs_devfp.get("doh_requests"),
                      "ndpi": obs_devfp.get("ndpi") or {}},
            "note": ("2026-10-28 起公网 DoT(:853)/DoH(:444) 改由 AGH 直接终结 TLS——它是唯一能看到真实客户端"
                     "公网 IP 的位置，由它按客户端 IP 注入 ECS(/24) 实现 per-user CDN 优选；AGH 自身缓存不分"
                     " ECS（实测会串省）故关闭，缓存下沉到 dnsdist 172.18.0.1:5300（parseECS=true，按 ECS 分键）。"
                     "nginx 只在 :443 提供网站/看板与 /dns-query 兜底。devfp / nDPI 为旁路观测，按 853/443/444 端口统计设备与指纹。"),
        },
        "chain": {
            "architecture": ("客户端 → AGH TLS（:853 DoT / :444 DoH，按客户端 IP 注入 ECS /24）→ dnsdist PacketCache（:5300，ECS 分键）→ guard 安全策略（:5355）→ A（本地 DNSSEC）"
                             + (" → aghcf 加密出口（Cloudflare DoT，A 唯一上游）" if _a_via_doq else
                                (" → 转发目标 " + " / ".join(_ua_config.get("forward_addr") or ["未采集"]))
                                if _ua_stats.get("mode") == "forward" else
                                " → 根/TLD/权威（直接递归）" if _ua_stats.get("mode") == "recursive" else
                                " → 上游关系未采集")),
            "nodes": chain_nodes,
            "main": chain_main,
            "fallback": chain_fallback,
            "side_label": "CN 分流（guard 名单）",
            "aux": chain_aux,
            "aux_label": "策略核验与辅助通道（由 guard 按需调用）",
            "external": chain_external,
            "external_label": "外部可达性参照（独立探针）",
            # 2026-10-09：把 dnsdist 的真实状态交给前端渲染导语，避免导语写死后再次变陈旧
            "dnsdist_active": bool(dnsdist_active),
            "fallback_note": (
                # 2026-10-23：缓存已迁到 dnsdist 的 PacketCache，AGH 侧 cache_enabled=false，
                # 旧文案"AGH 缓存 → guard → A"会让人以为 AGH 还在缓存命中。
                "dnsdist PacketCache → AGH（过滤，不再缓存）→ guard → A（本地 DNSSEC）。"
                "guard 载入类型化名单 %s 条；dnscrypt 转发规则 %s；"
                "plain53 %s 条；A 上游超时 %s；审计基线 %s；%s；告警 %s。"
                % (dcp.get("rules_count_guard") or "?", dcp.get("rules_count", 0),
                   prot["plain53"]["total"],
                   agh_cfg.get("upstream_timeout", "5s"),
                   prot["audit"]["baseline"],
                   (("运行中（已跑 %d 轮）" % prot["audit"].get("runs", 0))
                    if prot["audit"].get("timer") == "active"
                    else ("未在运行（已跑 %d 轮）" % prot["audit"].get("runs", 0))),
                   prot["audit"]["alerts"])),
        },
        "probes": probes,
        "layer_latency": layer_latency,
        "dnsguard": dg,
        "security_metrics": dg.get("security_metrics", {}),
        "anomaly_categories": dg.get("anomaly_categories", {}),
        "alerts": _alerts,
        "dnscrypt": dcp,
        "agh": {
            "container": AGH_CONTAINER,
            "image": agh_container.get("image", ""),
            "status": agh_container.get("status", "?"),
            "uptime": human_uptime(container_up_s(agh_container, now)) if container_up_s(agh_container, now) is not None else "-",
            "health": agh_container.get("health", ""),
            "mem": agh_container.get("mem_usage", ""),
            "cpu_pct": agh_container.get("cpu_pct", "0"),
            "restarts": agh_container.get("restarts", 0),
            "config": {
                "upstream_dns": agh_cfg.get("upstream_dns", []),
                "fallback_dns": agh_cfg.get("fallback_dns", []),
                "bootstrap_dns": agh_cfg.get("bootstrap_dns", []),
                "upstream_mode": agh_cfg.get("upstream_mode", ""),
                # 2026-10-05：blocking_mode 之前没进快照 → 看板看不到这个关键开关。
                # parse_agh_config 是通用解析，本来就有这两个键，只是快照字典没列出来。
                # 注意：parse_agh_config 遇到列 0 开头的行就停止采集 dns 段，
                # 而 blocking_mode 位于该断点之后（实测 AGH v0.107.73 的 yaml 结构），
                # 所以这两个字段必须直接从原始配置里取，不能依赖 agh_cfg。
                "blocking_mode": _agh_dns_scalar(conf_raw, "blocking_mode") or "",
                "blocked_response_ttl": _agh_dns_scalar(conf_raw, "blocked_response_ttl"),
                "upstream_timeout_s": agh_cfg.get("upstream_timeout", ""),
                "fastest_timeout": agh_cfg.get("fastest_timeout", ""),
                "cache_enabled": agh_cfg.get("cache_enabled", None),
                "cache_size_b": agh_cfg.get("cache_size", None),
                "cache_optimistic": agh_cfg.get("cache_optimistic", None), "cache_optimistic_max_age": _agh_dns_scalar(conf_raw, "cache_optimistic_max_age"), "cache_optimistic_answer_ttl": _agh_dns_scalar(conf_raw, "cache_optimistic_answer_ttl"),
                "cache_ttl_min": agh_cfg.get("cache_ttl_min", None),
                "cache_ttl_max": agh_cfg.get("cache_ttl_max", None),
                "enable_dnssec": agh_cfg.get("enable_dnssec", None),
                "edns_client_subnet": agh_cfg.get("edns_client_subnet", None),
                "ratelimit": agh_cfg.get("ratelimit", None),
                "max_goroutines": agh_cfg.get("max_goroutines", None),
                "dns_port": agh_cfg.get("port", None),
            },
            "top_upstreams": qlog.get("top_upstreams", []),
            "top_clients": qlog.get("top_clients", []),
            "top_slow": qlog.get("slow", []),
            "by_type": qlog.get("by_type", []),
            "log": aglog,
        },
        "unbound": ub_list,
        "container_list": container_list,
        "server": server,
        "protections": prot,
    }

    # 走势：无样本时存 None（前端断线不画），避免"没请求"被画成 0 造成锯齿
    _q = overview["queries"]
    _c = hits + miss
    _pl = overview["latency_p50_ms"] if miss else None
    _p9 = overview["latency_p90_ms"] if miss else None
    _ub = (ub_list[0]["stats"] or {})

    def _p50(target, scen):
        """取某个探针的 p50（同一 target 有热/冷两个场景）"""
        for p in probes:
            if p.get("target") == target and scen in (p.get("label") or ""):
                return p.get("p50_ms")
        return None

    def _net(iface, kind):
        for n in (server.get("net") or []):
            if n.get("iface") == iface:
                return n.get(kind)
        return None

    _fallback_used = sum(1 for u in qlog.get("top_upstreams", []) if ":5354" in u.get("addr", ""))

    # ---- 权威 QPS / 比率：AGH 滚动 24 小时计数差分（不受 querylog 按条数截断的影响）----
    # 历史条目里**存原始计数（含小时桶）**，所以跨链看板重启也能算差（history.json 会重新载入）。
    # 2026-10-14 重写：优先"同一小时桶"差分（免疫整点最旧桶过期），兜底才用总量差分，
    # 并且**两条路径共用**不变量 0 ≤ Δ拦截 ≤ Δ总查询 —— 原判据只查了 ≥0，正是整点
    # 拦截率 568.33%、放行 QPS −17.03 的来源。详见 _agh_window_delta 与 collect_agh_stats。
    _prev = HISTORY[-1] if HISTORY else {}
    _dt = (now - _prev.get("t", 0)) if _prev.get("t") else 0
    agh_q_total = agh_stats.get("q_total") or 0
    agh_b_total = agh_stats.get("b_total") or 0
    agh_up_total = agh_stats.get("up_total") or 0
    agh_hour_key = _agh_hour_key(now)
    qps_total = qps_blocked = qps_allowed = qps_upstream = None
    block_ratio_auth = cache_hit_ratio_auth = None
    qps_valid = None
    upstream_share = None
    qps_delta_src = None
    _crossed = False                   # 本区间是否跨过整点（上游应答数无小时桶，跨桶即不可信）
    if agh_q_total and _prev and _dt > 5:
        _pq = _prev.get("agh_q_total")
        if _pq:
            _dq = _db = _du = None
            _crossed = True
            _d = _agh_window_delta(agh_stats, _prev, now)
            if _d:
                _dq, _db, _crossed, qps_delta_src = _d
                # 上游应答数（同 top_clients，都是 24h 滚动窗口）**没有小时桶**，只能做总量差分：
                # 仅当本区间没跨整点，它才是纯增量；跨桶时宁缺勿错。
                if not _crossed:
                    _du = agh_up_total - (_prev.get("agh_up_total") or 0)
            if _dq is None:
                qps_valid = False      # 桶字段缺失/断档：拿不到可信增量，本区间判无效
            elif _dq >= 0 and _db >= 0 and _db <= _dq:
                qps_total = round(_dq / float(_dt), 2)
                qps_blocked = round(_db / float(_dt), 2)
                qps_allowed = round((_dq - _db) / float(_dt), 2)
                qps_valid = True
                if _dq > 0:
                    # 权威比率：精确、与 querylog 样本及其条数截断完全无关；
                    # 上面的不变量已保证它落在 0–100%。
                    block_ratio_auth = round(100.0 * _db / _dq, 2)
                    if _du is not None and _du >= 0:
                        qps_upstream = round(_du / float(_dt), 2)
                        # 2026-10-09 修正（实测发现，原公式是虚高的）：分母必须是「放行查询」
                        # = 总查询 − 被拦截。被拦截的查询永远不会联系上游，若混入分母会把
                        # 命中率系统性抬高——实测家庭流量约 70% 被拦截，60s 窗口
                        # Δ总=206 / Δ拦截=147 / Δ上游=12 ⇒ 真实 47/59=79.7%，旧公式算出 94.2%。
                        _allowed_d = _dq - _db
                        if _allowed_d > 0:
                            cache_hit_ratio_auth = round(100.0 * max(0, _allowed_d - _du) / _allowed_d, 2)
                            # 2026-10-23：_du 来自 24h 滚动窗口的总量差分（上游应答数没有小时桶），
                            # 窗口里"最旧那段过期"会把它抬到 > 放行查询数 ⇒ 占比算出 103–110%（实测 5 个点）。
                            # 上游应答不可能多于放行查询，超出即判本点无效（前端断线），宁缺勿错。
                            upstream_share = (round(100.0 * _du / _allowed_d, 2)
                                              if 0 <= _du <= _allowed_d else None)
            else:
                # 2026-10-14：Δ 为负（AGH 重启或整点最旧桶过期）或 **Δ拦截 > Δ总查询**
                # （整点换桶时的稀释）一律判无效 → 前端显示"—"或退回样本口径，不再出现
                # 568.33% / 249.1% / 负放行 QPS。每小时最多牺牲一个采样点。
                qps_valid = False
        else:
            qps_valid = False
    elif agh_q_total:
        qps_valid = False              # 首个采样点：无前值可比

    # ---- 逐客户端速率：AGH top_clients（保留期累计）同源差分，避免"按条数截取" ----
    _clients_cum = [[ip, c] for ip, c in (agh_stats.get("clients") or [])[:12]]
    clients_rate = None
    if _clients_cum and _prev.get("clients_cum") and _dt > 5:
        try:
            _prevc = dict(_prev["clients_cum"])
            # 2026-10-14：top_clients 与 num_dns_queries 一样是**24 小时滚动窗口**计数，
            # 整点最旧桶过期时单客户端计数会**下降**；负增量不是真实速率（原来会直接显示成
            # 负 QPS）。任一条为负，说明窗口发生了滑移 ⇒ 本区间各客户端的速率都不可信，
            # 整段丢弃（前端会退回 querylog 样本口径），而不是只钳制某一条。
            _rows = []
            _bad = False
            for ip, c in _clients_cum:
                _d = c - _prevc.get(ip, c)
                if _d < 0:
                    _bad = True
                    break
                _rows.append({"ip": ip, "qps": round(_d / float(_dt), 2),
                              "total": c,
                              "note": ("nginx/docker 网关：DoT 侧真实客户端 IP 未透传，此条并非单一终端"
                                       if ip == "172.18.0.1" else
                                       ("本机（含看板自身探针）" if ip in AGH_PROBE_CLIENTS else ""))})
            if not _bad and not _crossed:
                clients_rate = sorted(_rows, key=lambda x: -x["qps"])
        except Exception:
            clients_rate = None

    # 把权威计数与逐客户端速率挂到 overview（概览在此刻之后才被序列化）
    overview["qps_total"] = qps_total
    overview["qps_blocked"] = qps_blocked
    overview["qps_allowed"] = qps_allowed
    overview["qps_valid"] = qps_valid
    overview["agh_q_total"] = agh_q_total or None
    overview["agh_b_total"] = agh_b_total or None
    overview["agh_up_total"] = agh_up_total or None
    # 权威比率（AGH 滚动窗口差分）：与 querylog 样本及其条数截断完全无关
    overview["qps_upstream"] = qps_upstream
    overview["block_ratio_auth"] = block_ratio_auth
    overview["cache_hit_ratio_auth"] = cache_hit_ratio_auth
    overview["ratio_src"] = ((qps_delta_src or "agh_window_total_delta")
                             if cache_hit_ratio_auth is not None else "querylog_sample")
    # 2026-10-09 新增：命中率的正确分母（放行查询）与真上游占比；口径随数据一并披露
    overview["cache_hit_ratio_basis"] = ("allowed" if cache_hit_ratio_auth is not None else None)
    overview["upstream_share"] = upstream_share
    try:
        _ubh = _ubm = 0
        for _x in ub_list:
            _s = _x.get("stats") or {}
            _ubh += int(_s.get("cachehits") or 0)
            _ubm += int(_s.get("cachemiss") or 0)
        overview["unbound_cache_hit_pct"] = (round(100.0 * _ubh / (_ubh + _ubm), 2)
                                            if (_ubh + _ubm) else None)
        overview["unbound_cache_den"] = _ubh + _ubm
    except Exception:
        overview["unbound_cache_hit_pct"] = None
    # 同名的"样本版"（querylog 派生）单独保留，供对照与降级显示
    overview["block_ratio_sample"] = overview.get("block_pct")
    overview["cache_hit_ratio_sample"] = overview.get("cache_hit_pct")
    overview["qps_dt_s"] = round(_dt, 1) if _dt else None
    # 差分口径与来源随数据披露：agh_hour_bucket_delta（同桶）/ agh_hour_bucket_rollover
    # （整点拼接）/ agh_window_total_delta（旧条目兜底）/ None（本区间无效，前端显示—）
    overview["qps_src"] = qps_delta_src or "agh_window_total_delta"
    overview["qps_delta_src"] = qps_delta_src
    overview["qps_crossed_hour"] = bool(_crossed)
    overview["clients_rate"] = clients_rate
    overview["clients_note"] = ("2026-10-28 起 DoT/DoH 由 AGH 直接终结，DoT 侧看到真实客户端 IP；"
                                "DoH 经 nginx :443 兜底时 AGH 按 trusted_proxies 从 X-Forwarded-For 取真实 IP"
                                "（nginx 已改为只传 $remote_addr，不再追加客户端可控值）。")
    overview["agh_stats_error"] = agh_stats.get("error")
    overview["probe_queries_by_ip_legacy"] = qlog.get("probe_queries_by_ip_legacy", 0)
    overview["security_probe_queries"] = qlog.get("security_probe_queries", 0)
    # 2026-10-09 阶段2：探针/压测的独立口径（**不计入用户指标**）。
    # 注意：probe_split["hosts"] 是 set，不能直接序列化，这里只暴露计数。
    _psplit = qlog.get("probe_split") or {}
    overview["probe_sample_queries"] = int(_psplit.get("queries") or 0)
    overview["probe_sample_allowed"] = int(_psplit.get("allowed") or 0)
    overview["probe_sample_blocked"] = int(_psplit.get("blocked") or 0)
    overview["probe_sample_hits"] = int(_psplit.get("cache_hits") or 0)
    overview["probe_sample_misses"] = int(_psplit.get("cache_misses") or 0)
    overview["probe_sample_hosts"] = len(_psplit.get("hosts") or ())
    overview["probe_sample_by_ip"] = dict(_psplit.get("by_ip") or {})
    overview["probe_src"] = sorted(PROBE_SRC)
    overview["probe_port"] = PROBE_PORT
    overview["probe_q_by_src"] = int(qlog.get("probe_queries_by_src") or 0)
    overview["probe_hot_not_excluded"] = qlog.get("probe_hot_not_excluded", 0)

    HISTORY.append({
        "t": int(now),
        # --- 查询与流量 ---
        "queries": _q,
        "queries_1m": overview.get("queries_1m", 0),
        # --- 权威计数：AGH 窗口计数差分（单位固定为 QPS；querylog 只作分类样本）---
        "agh_q_total": agh_q_total,
        # 2026-10-14：滚动 24 小时桶基准。存下来才能在整点换桶后把两侧拼起来，
        # 也能识别"跨了不止一个整点"的采样断档（详见 _agh_window_delta）。
        "agh_bucket_q": agh_stats.get("bucket_q"),
        "agh_bucket_b": agh_stats.get("bucket_b"),
        "agh_hour_key": agh_hour_key,
        "qps_delta_src": qps_delta_src,
        "agh_b_total": agh_b_total,
        "agh_up_total": agh_up_total,
        "qps_total": qps_total,
        "qps_blocked": qps_blocked,
        "qps_allowed": qps_allowed,
        "qps_upstream": qps_upstream,
        "block_ratio_auth": block_ratio_auth,
        "cache_hit_ratio_auth": cache_hit_ratio_auth,
        "qps_valid": qps_valid,
        "qps_dt_s": round(_dt, 1) if _dt else None,
        "clients_cum": _clients_cum,
        "cli_top_ip": (_clients_cum[0][0] if _clients_cum else None),
        "cli_top_total": (_clients_cum[0][1] if _clients_cum else None),
        "cli_top_qps": (clients_rate[0]["qps"] if clients_rate else None),
        "blocked": overview["blocked"] if _q else None,
        "block_pct": overview["block_pct"] if _q else None,
        "clients": overview.get("clients", 0),
        # --- 缓存与上游 ---
        "cache_hit_pct": overview["cache_hit_pct"] if _c else None,
        "chain_cache_pct": chain_cache.get("hit_pct"),
        "cache_hits": hits if _c else None,
        # 2026-10-23：dnsdist PacketCache 的累计命中/未命中计数（history 里存原始计数，
        # 前端按相邻两点差分得到「每窗口命中率」曲线；cache_hit_pct 是累计值，画成曲线是直线）。
        "dnsdist_cache_hits": overview.get("dnsdist_cache_hits"),
        "dnsdist_cache_misses": overview.get("dnsdist_cache_misses"),
        "cache_misses": miss if _c else None,
        # 2026-10-24 修复（字段审计复核）：窗口覆盖度与采集耗时此前从不落 HISTORY，
        # 趋势区取不到列、事后也无法回溯"当时窗口是否被截断"（实时区读 overview 能显示，
        # 但历史里没有记录）。collect_ms 取上一轮快照 —— 本轮耗时在 append 之后才算出。
        "window_covered_min": overview.get("window_covered_min"),
        "window_truncated": overview.get("window_truncated"),
        "agh_log_lines": overview.get("agh_log_lines"),
        "agh_log_capped": overview.get("agh_log_capped"),
        "collect_ms": SNAPSHOT.get("collect_ms"),
        "io_timeout": overview["upstream_timeouts"],
        "slow_count": overview.get("slow_count"),
        "uniq_hosts": overview.get("uniq_hosts"),
        "fallback_used": _fallback_used,
        # --- 延迟分位（无上游请求时无样本）---
        "latency_p50_ms": _pl,
        "latency_p90_ms": _p9,
        "latency_p99_ms": overview["latency_p99_ms"] if miss else None,
        "latency_max_ms": overview["latency_max_ms"] if miss else None,
        "latency_all_p50_ms": overview.get("latency_all_p50_ms"),
        "latency_all_p90_ms": overview.get("latency_all_p90_ms"),
        "latency_all_p99_ms": overview.get("latency_all_p99_ms"),
        # 2026-10-23：趋势区的三张卡（净处理 p50 / 上游往返基线 / 全部查询 p90 净口径）
        # 的 spark 读 net_latency_* 与 upstream_baseline_ms，但 history 此前只写了 latency_*，
        # 取不到列 → 卡片永远显示"窗口内无样本"。这里把 overview 已算好的净值一并写进历史。
        "upstream_baseline_ms": overview.get("upstream_baseline_ms"),
        "net_latency_p50_ms": overview.get("net_latency_p50_ms"),
        "net_latency_p90_ms": overview.get("net_latency_p90_ms"),
        "net_latency_p99_ms": overview.get("net_latency_p99_ms"),
        "net_latency_all_p50_ms": overview.get("net_latency_all_p50_ms"),
        "net_latency_all_p90_ms": overview.get("net_latency_all_p90_ms"),
        "net_latency_all_p99_ms": overview.get("net_latency_all_p99_ms"),
        # --- unbound 自身 ---
        "unbound_hit_pct": round(_ub.get("hit_pct"), 2) if _ub.get("hit_pct") else None,
        "unbound_rec_med_ms": _ub.get("recursion_median_ms"),
        "unbound_rec_avg_ms": _ub.get("recursion_avg_ms"),
        "unbound_queue_avg": _ub.get("queue_avg"),
        "unbound_mem_mb": round(_ub.get("mem_message_b", 0) / 1048576.0, 1) if _ub.get("mem_message_b") else None,
        "unbound_bogus": _ub.get("bogus"),
        "unbound_rrset_bogus": _ub.get("rrset_bogus"),
        "unbound_servfail": _ub.get("servfail"),
        "unbound_queries": _ub.get("queries"),
        "upstream_share": overview.get("upstream_share"),
        "unbound_cache_hit_pct": overview.get("unbound_cache_hit_pct"),
        # --- 链路探针（冷查询）---
        "probe_agh_ms": _p50("AGH", "冷"),
        "probe_unbound_a_ms": _p50("unbound A", "冷"),
        "probe_unbound_b_ms": _p50("unbound B", "冷"),
        "probe_dnscrypt_ms": _p50("dnscrypt-proxy", "冷"),
        "probe_dot360_ms": _p50("dot.360.cn", ""),
        "probe_alidns_ms": _p50("dns.alidns.com", ""),
        "probe_root_ms": _p50("根服务器", ""),
        # --- 服务器资源 ---
        "cpu_pct": (server.get("cpu_pct")),
        "mem_pct": (server.get("mem") or {}).get("pct"),
        "swap_pct": (server.get("swap") or {}).get("pct"),
        "disk_pct": (server.get("disk") or {}).get("pct"),
        "load1": (server.get("load") or [None])[0],
        "net_rx_kbps": _net("eth0", "rx_kbps"),
        "net_tx_kbps": _net("eth0", "tx_kbps"),
        # dnsguard 快速源与 R8 核对指标
        "guard_fast_source_doq_ms": (dg.get("guard_metrics") or {}).get("fast_source_doq_ms"),
        "guard_r8_miss": (dg.get("guard_metrics") or {}).get("r8_miss"),
        "guard_budget_skip": (dg.get("guard_metrics") or {}).get("budget_skip"),
        "guard_r8_checked": (dg.get("guard_metrics") or {}).get("r8_checked"),
        # R8 verifier 认证通道（实时，来自 verifier-state）
        "guard_r8_auth_ok": (dg.get("guard_metrics") or {}).get("r8_auth_ok"),
        "guard_r8_auth_none": (dg.get("guard_metrics") or {}).get("r8_auth_none"),
        "guard_r8_auth_source": (dg.get("guard_metrics") or {}).get("r8_auth_source") or "main",
        # R8 主路径（实时）与主进程冻结的历史值（仅供审计，勿当实时）
        "guard_r8_mainpath_checked": (dg.get("guard_metrics") or {}).get("r8_checked"),
        "guard_r8_auth_ok_main_frozen": (dg.get("guard_metrics") or {}).get("r8_auth_ok_main_frozen"),
        "guard_r8_auth_none_main_frozen": (dg.get("guard_metrics") or {}).get("r8_auth_none_main_frozen"),
        "guard_r8_conflict_adopt": (dg.get("guard_metrics") or {}).get("r8_conflict_adopt"),
        "guard_r8_event_skip": (dg.get("guard_metrics") or {}).get("r8_event_skip"),
        "guard_r8_circuit_skip": (dg.get("guard_metrics") or {}).get("r8_circuit_skip"),
        "guard_singleflight_wait": (dg.get("guard_metrics") or {}).get("singleflight_wait"),
        "guard_cold_drop": (dg.get("guard_metrics") or {}).get("cold_drop"),
        "guard_overload_drop": (dg.get("guard_metrics") or {}).get("overload_drop"),
        "guard_fail_closed": (dg.get("guard_metrics") or {}).get("fail_closed"),
        # 2026-10-10 §1：业务基线仪表的关键字段进看板 HISTORY（⇒ 自动成为时间序列）✓
        "guard_lat_p50_ms": (dg.get("guard_metrics") or {}).get("guard_lat_p50_ms"),
        "guard_lat_p95_ms": (dg.get("guard_metrics") or {}).get("guard_lat_p95_ms"),
        "guard_lat_p99_ms": (dg.get("guard_metrics") or {}).get("guard_lat_p99_ms"),
        "guard_samples_a": (dg.get("guard_metrics") or {}).get("samples_a"),
        "guard_samples_aaaa": (dg.get("guard_metrics") or {}).get("samples_aaaa"),
        "guard_samples_https": (dg.get("guard_metrics") or {}).get("samples_https"),
        "guard_samples_cn": (dg.get("guard_metrics") or {}).get("samples_cn"),
        "guard_gt1000ms_pct": (dg.get("guard_metrics") or {}).get("gt1000ms_pct"),
        "guard_gt2000ms_pct": (dg.get("guard_metrics") or {}).get("gt2000ms_pct"),
        "guard_src_local_a": (dg.get("guard_metrics") or {}).get("src_local_a"),
        "guard_src_local_alt": (dg.get("guard_metrics") or {}).get("src_local_alt"),
        "guard_src_none": (dg.get("guard_metrics") or {}).get("src_none"),
        "guard_cn_path": (dg.get("guard_metrics") or {}).get("cn_path"),
        "guard_b_used": (dg.get("guard_metrics") or {}).get("b_used"),
        "guard_stage_a_p95_ms": (dg.get("guard_metrics") or {}).get("stage_a_p95_ms"),
        "guard_stage_bget_p95_ms": (dg.get("guard_metrics") or {}).get("stage_bget_p95_ms"),
        "guard_stage_alt_p95_ms": (dg.get("guard_metrics") or {}).get("stage_alt_p95_ms"),
        "guard_stage_r8_p95_ms": (dg.get("guard_metrics") or {}).get("stage_r8_p95_ms"),
        "guard_stage_ipc_p95_ms": (dg.get("guard_metrics") or {}).get("stage_ipc_p95_ms"),
        "guard_wait_p95_ms": (dg.get("guard_metrics") or {}).get("wait_p95_ms"),
        "guard_retry_alt": (dg.get("guard_metrics") or {}).get("retry_alt"),
        "guard_retry_witness": (dg.get("guard_metrics") or {}).get("retry_witness"),
        "guard_verifier_recv": (dg.get("guard_metrics") or {}).get("verifier_recv"),
        "guard_verifier_rid_present": (dg.get("guard_metrics") or {}).get("verifier_rid_present"),
        "guard_verifier_rid_absent": (dg.get("guard_metrics") or {}).get("verifier_rid_absent"),
        "guard_verifier_pool_overload": (dg.get("guard_metrics") or {}).get("verifier_pool_overload"),
        # 入口类别与来源类别（Step-1 §1：业务/主机/探针三者分开）✓
        "guard_entry_client": (dg.get("guard_metrics") or {}).get("entry_client"),
        "guard_entry_host": (dg.get("guard_metrics") or {}).get("entry_host"),
        "guard_entry_probe": (dg.get("guard_metrics") or {}).get("entry_probe"),
        "guard_base_cls_client": (dg.get("guard_metrics") or {}).get("base_cls_client"),
        "guard_base_cls_host": (dg.get("guard_metrics") or {}).get("base_cls_host"),
        "guard_base_cls_other": (dg.get("guard_metrics") or {}).get("base_cls_other"),
        # §2：有效期来源 / 准入缓存 / 钉住失效（需看**时间序列**才判得出"旧值有没有出海"✓）
        "guard_ttl_src_wire": (dg.get("guard_metrics") or {}).get("ttl_src_wire"),
        "guard_ttl_zero_a": (dg.get("guard_metrics") or {}).get("ttl_zero_a"),
        "guard_ttl_zero_alt": (dg.get("guard_metrics") or {}).get("ttl_zero_alt"),
        "guard_adm_cache_put": (dg.get("guard_metrics") or {}).get("adm_cache_put"),
        "guard_adm_cache_hit": (dg.get("guard_metrics") or {}).get("adm_cache_hit"),
        "guard_adm_cache_expired": (dg.get("guard_metrics") or {}).get("adm_cache_expired"),
        "guard_adm_cache_ttl_zero": (dg.get("guard_metrics") or {}).get("adm_cache_ttl_zero"),
        "guard_adm_cache_invalidated": (dg.get("guard_metrics") or {}).get("adm_cache_invalidated"),
        "guard_adm_cache_view_mismatch": (dg.get("guard_metrics") or {}).get("adm_cache_view_mismatch"),
        "guard_pin_invalidated": (dg.get("guard_metrics") or {}).get("pin_invalidated_bogus"),
        "guard_neg_cache_skip": (dg.get("guard_metrics") or {}).get("neg_cache_skip_unproven"),
        # §3：去重与唯一 deadline（**时间序列**才看得出"重复取数有没有真的消失"✓）
        "guard_dl_exhausted": (dg.get("guard_metrics") or {}).get("dl_exhausted"),
        "guard_a_dup_skipped": (dg.get("guard_metrics") or {}).get("a_dup_skipped"),
        "guard_b_dup_skipped": (dg.get("guard_metrics") or {}).get("b_dup_skipped"),
        "guard_witness_dup_skipped": (dg.get("guard_metrics") or {}).get("witness_dup_skipped"),
        "guard_alt_dup_skipped": (dg.get("guard_metrics") or {}).get("alt_dup_skipped"),
        "guard_fin_alt_dup_skipped": (dg.get("guard_metrics") or {}).get("fin_alt_dup_skipped"),
        "guard_fin_retry_alt_dup": (dg.get("guard_metrics") or {}).get("fin_retry_alt_dup"),
        "guard_fin_retry_witness_dup": (dg.get("guard_metrics") or {}).get("fin_retry_witness_dup"),
        "guard_cn_sf_lead": (dg.get("guard_metrics") or {}).get("cn_sf_lead"),
        "guard_cn_sf_merge": (dg.get("guard_metrics") or {}).get("cn_sf_merge"),
        "guard_cn_sf_served": (dg.get("guard_metrics") or {}).get("cn_sf_served"),
        "guard_cn_sf_wait_timeout": (dg.get("guard_metrics") or {}).get("cn_sf_wait_timeout"),
        "guard_cn_sf_budget_skip": (dg.get("guard_metrics") or {}).get("cn_sf_budget_skip"),
        "guard_strict_budget_skip": (dg.get("guard_metrics") or {}).get("strict_budget_skip"),
        "guard_policy_hint_wire_used": (dg.get("guard_metrics") or {}).get("policy_hint_wire_used"),
        "guard_policy_hint_wire_missing": (dg.get("guard_metrics") or {}).get("policy_hint_wire_missing"),
        "guard_cn_sf_reuse_handoff": (dg.get("guard_metrics") or {}).get("cn_sf_reuse_handoff"),
        "guard_resp_servfail_built": (dg.get("guard_metrics") or {}).get("resp_servfail_built"),
        # §4：readiness 闸门与运输断路器 ✓（判读见 `_base_metrics` 里同名字段的注释 ✓）
        "guard_alt_ready": (dg.get("guard_metrics") or {}).get("alt_ready"),
        "guard_alt_not_ready": (dg.get("guard_metrics") or {}).get("alt_not_ready"),
        "guard_alt_unavailable_skip": (dg.get("guard_metrics") or {}).get("alt_unavailable_skip"),
        "guard_alt_ready_missing": (dg.get("guard_metrics") or {}).get("alt_ready_missing"),
        "guard_alt_ready_stale": (dg.get("guard_metrics") or {}).get("alt_ready_stale"),
        "guard_alt_ready_identity_changed": (dg.get("guard_metrics") or {}).get("alt_ready_identity_changed"),
        "guard_alt_ready_config_changed": (dg.get("guard_metrics") or {}).get("alt_ready_config_changed"),
        "guard_alt_breaker_trips": (dg.get("guard_metrics") or {}).get("alt_breaker_trips"),
        "guard_alt_transport_ok": (dg.get("guard_metrics") or {}).get("alt_transport_ok"),
        "guard_alt_transport_fail": (dg.get("guard_metrics") or {}).get("alt_transport_fail"),
        "guard_alt_half_open_ok": (dg.get("guard_metrics") or {}).get("alt_half_open_ok"),
        "guard_alt_half_open_fail": (dg.get("guard_metrics") or {}).get("alt_half_open_fail"),
    })
    for _i, _st in enumerate(ub_stats):
        for _k in UB_HIST_KEYS:
            HISTORY[-1]["ub%d_%s" % (_i, _k)] = (_st or {}).get(_k)
    # 2026-10-08 第7步：unbound B 的消费者归类 + 逐分钟增量（query/tls/udpout/requestlist）。
    # 写进 HISTORY[-1] 即自动生成时间序列 —— 下方"通用导出"按 HISTORY 的键导出全部指标。
    _battr = b_attrib(ub_stats, dg, probes, dcp)
    _battr["residual_win"] = b_residual_window()
    snap["b_attrib"] = _battr
    for _bk, _bv in _battr.items():
        if _bv is None or isinstance(_bv, (int, float)):
            HISTORY[-1]["b_" + _bk] = _bv
    _rw = _battr.get("residual_win") or {}
    HISTORY[-1]["b_reswin"] = _rw.get("residual")
    HISTORY[-1]["b_reswin_window_s"] = _rw.get("window_s")
    HISTORY[-1]["b_reswin_span_s"] = _rw.get("span_s")
    HISTORY[-1]["b_reswin_samples"] = _rw.get("samples")
    HISTORY[-1]["b_reswin_total"] = _rw.get("d_total")
    HISTORY[-1]["b_reswin_guard"] = _rw.get("d_guard_cn")
    HISTORY[-1]["b_reswin_probe"] = _rw.get("chainmon_probe")
    # 2026-10-09：`b_residual_win` 此前恒为 None（通用导出只写 int/float/None，而 residual_win 是 dict）
    # ⇒ 该序列恒空。这里显式写入同一个 residual 值，避免"永远没数据的死序列"。
    HISTORY[-1]["b_residual_win"] = _rw.get("residual")
    HISTORY[-1]["b_reswin_reset"] = _rw.get("reset_detected")
    HISTORY[-1]["b_reswin_dropped"] = _rw.get("points_dropped")
    # 2026-10-09：看板自身资源进 HISTORY（自动成为序列）与 API，便于把"自身消耗"与"被观测对象"分开
    HISTORY[-1]["self_rss_mb"] = self_rss_mb()
    HISTORY[-1]["self_threads"] = self_threads()
    # 2026-10-10：自检增强（方案 Task7 / resource_probe.py）。
    # 只读缓存：API 刷新不会 fork journalctl；journal 由 probe 内部按 300s 增量去重。
    # 若探针缺失或抛异常，这里必须仍能返回旧字段，绝不因自检把看板打挂。
    _selfp = self_resource_snapshot()
    _self_cg = _selfp.get("cgroup") or {}
    _self_proc = _selfp.get("proc") or {}
    _self_delta = _selfp.get("delta") or {}
    snap["self"] = {
        "rss_mb": self_rss_mb(),
        "threads": self_threads(),
        "agh_api_limit": AGH_API_LIMIT,
        "collect_ms": snap.get("collect_ms"),
        "pss_kb": _self_proc.get("pss_kb"),
        "rss_kb": _self_proc.get("rss_kb"),
        "swap_kb": _self_proc.get("swap_kb"),
        "fds": _self_proc.get("fds"),
        "threads_proc": _self_proc.get("tasks"),
        "threads_match": _self_proc.get("threads_match"),
        "cgroup_version": _self_cg.get("version"),
        "cgroup_path": _self_cg.get("path"),
        "cgroup_usage_bytes": _self_cg.get("usage_bytes"),
        "cgroup_memsw_usage_bytes": _self_cg.get("memsw_usage_bytes"),
        "cgroup_current_bytes": _self_cg.get("current_bytes"),
        "failcnt": _self_cg.get("failcnt"),
        "oom_kill": _self_cg.get("oom_kill"),
        "delta": _selfp.get("delta"),
        "journal_oom": _selfp.get("journal_oom"),
        "probe_errors": _selfp.get("errors"),
    }
    HISTORY[-1]["self_pss_kb"] = _self_proc.get("pss_kb")
    HISTORY[-1]["self_fds"] = _self_proc.get("fds")
    if _self_cg.get("version") == 2:
        HISTORY[-1]["self_cgroup_bytes"] = _self_cg.get("current_bytes")
    else:
        HISTORY[-1]["self_cgroup_bytes"] = _self_cg.get("usage_bytes")
    HISTORY[-1]["self_failcnt"] = _self_cg.get("failcnt")
    HISTORY[-1]["self_oom_kill"] = _self_cg.get("oom_kill")
    HISTORY[-1]["self_failcnt_delta_session"] = _self_delta.get("failcnt_delta_session")
    HISTORY[-1]["self_oom_kill_delta_session"] = _self_delta.get("oom_kill_delta_session")
    del HISTORY[:-HISTORY_MAX]
    save_history()
    # 通用导出：HISTORY 里有什么字段就导出什么，新增指标不必再改这里
    snap["history"] = {}
    if HISTORY:
        for k in HISTORY[-1].keys():
            snap["history"][k] = [p.get(k) for p in HISTORY]
    for _i, _u in enumerate(snap.get("unbound") or []):
        _u["delta"] = ub_delta(_i)
    snap["collect_ms"] = int((time.time() - t0) * 1000)
    return snap


def collect_now(force=False):
    """采集一次并写入 SNAPSHOT。force=False 时会跳过过密的重复采集。"""
    with COLLECT_LOCK:
        now = time.time()
        if not force and now - LAST_COLLECT["t"] < MANUAL_MIN_GAP_S:
            return False
        try:
            snap = build_snapshot()
        except Exception:
            sys.stderr.write(traceback.format_exc())
            return False
        with SNAP_LOCK:
            SNAPSHOT.clear()
            SNAPSHOT.update(snap)
        _malloc_trim()
        for _p in (DNSGUARD_LOG, DNSDIST_QLOG):
            _drop_cache(_p)
        LAST_COLLECT["t"] = time.time()
        return True


def schedule_collect(force=False):
    """后台调度单次采集；调用方不等待 build_snapshot。"""
    with COLLECT_STATE_LOCK:
        if COLLECTING["v"]:
            return False
        COLLECTING["v"] = True
    def runner():
        try:
            collect_now(force=force)
        except Exception:
            sys.stderr.write(traceback.format_exc())
        finally:
            with COLLECT_STATE_LOCK:
                COLLECTING["v"] = False
    t = threading.Thread(target=runner, name="chainmon-collect")
    t.daemon = True
    t.start()
    return True


_JSON_SANITIZE_ERRORS = 0
_JSON_SANITIZE_LOCK = threading.Lock()


def _json_safe(value):
    """Return a JSON-compatible copy without allowing one bad field to break /api/metrics."""
    global _JSON_SANITIZE_ERRORS
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if callable(value):
        with _JSON_SANITIZE_LOCK:
            _JSON_SANITIZE_ERRORS += 1
        return None
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    try:
        json.dumps(value)
        return value
    except Exception:
        with _JSON_SANITIZE_LOCK:
            _JSON_SANITIZE_ERRORS += 1
        return None


def collector_loop():
    while True:
        try:
            schedule_collect(force=True)
        except Exception:
            sys.stderr.write(traceback.format_exc())
        time.sleep(COLLECT_INTERVAL_S)


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "chainmon/1.0"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/api/dnsguard":
            try:
                ln = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(ln).decode("utf-8") if ln else "{}"
                req = json.loads(raw or "{}")
                dom = (req.get("domain") or "").strip()
                act = (req.get("action") or "").strip()
                if not re.match(r"^[A-Za-z0-9._:-]+$", dom) or act not in ("confirm", "ignore", "forget"):
                    self._send(400, json.dumps({"error": "参数不合法"}, ensure_ascii=False),
                               "application/json; charset=utf-8")
                    return
                flag = {"confirm": "--confirm", "ignore": "--ignore", "forget": "--forget"}[act]
                out = dsh("python3 /opt/dnsguard/guard.py %s %s" % (flag, dom), timeout=20)
                time.sleep(1.2)
                try:
                    collect_now(force=True)
                except Exception:
                    pass
                self._send(200, json.dumps({"ok": True, "output": (out or "").strip()[:200]}, ensure_ascii=False),
                           "application/json; charset=utf-8")
            except Exception as e:
                self._send(500, json.dumps({"error": str(e)}, ensure_ascii=False), "application/json; charset=utf-8")
            return
        self._send(404, "not found", "text/plain")

    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        qs = parse_qs(u.query)
        if path in ("/", "/index.html"):
            try:
                with open(INDEX_FILE, "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            except Exception as e:
                self._send(500, "index.html 读取失败: %s" % e, "text/plain; charset=utf-8")
            return
        if path == "/api/metrics":
            with SNAP_LOCK:
                snap = dict(SNAPSHOT)
            age = round(time.time() - snap.get("ts", 0), 1) if snap.get("ts") else None
            should_collect = (not snap.get("ts")) or ("fresh" in qs and time.time() - LAST_COLLECT["t"] >= 8)
            scheduled = schedule_collect(force=True) if should_collect else False
            with COLLECT_STATE_LOCK:
                collecting = bool(COLLECTING["v"])
            if not snap.get("ts"):
                self._send(202, json.dumps({"ready": False, "collecting": collecting,
                                            "scheduled": scheduled,
                                            "message": "采集已在后台启动，请稍后刷新"}, ensure_ascii=False),
                           "application/json; charset=utf-8")
                return
            snap["collecting"] = collecting
            snap["snapshot_age_s"] = age
            snap["collect_scheduled"] = scheduled
            self._send(200, json.dumps(_json_safe(snap), ensure_ascii=False),
                       "application/json; charset=utf-8")
            return
        if path == "/api/health":
            with SNAP_LOCK:
                ts = SNAPSHOT.get("ts", 0)
            self._send(200, json.dumps({"ok": True, "snapshot_age_s": round(time.time() - ts, 1) if ts else None},
                                       ensure_ascii=False), "application/json")
            return
        self._send(404, "not found", "text/plain; charset=utf-8")


class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    if not os.path.isdir(BASE_DIR):
        os.makedirs(BASE_DIR)
    load_history()
    load_probe_names()
    t = threading.Thread(target=collector_loop)
    t.daemon = True
    t.start()
    srv = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    sys.stderr.write("chainmon listening on http://%s:%d\n" % (LISTEN_HOST, LISTEN_PORT))
    srv.serve_forever()


if __name__ == "__main__":
    if "--agh-selftest" in sys.argv:
        for _mode in ("api", "file"):
            _r = collect_agh_querylog(force_source=_mode)
            print("mode=%-4s source=%-4s queries=%-6s cached=%-5s miss=%-6s blocked=%-6s uniq=%-5s "
                  "lag=%-5ss covered=%-6smin probe_qname=%-5s probe_by_ip(仅对账)=%-6s probe_hot=%-4s err=%s" % (
                      _mode, _r.get("log_source"), _r.get("queries"), _r.get("cache_hits"),
                      _r.get("cache_misses"), _r.get("blocked"), len(_r.get("hosts") or []),
                      _r.get("log_lag_s"), _r.get("covered_min"), _r.get("probe_queries"),
                      _r.get("probe_queries_by_ip_legacy"), _r.get("probe_hot_not_excluded"),
                      _r.get("log_source_error") or "-"))
        sys.exit(0)
    main()
