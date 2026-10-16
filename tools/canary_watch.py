#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""canary 看门狗 v2：覆盖**整条链路（含 unbound B 与 dnscrypt）**，并按"客户端是否真被暴露"定红绿。

为什么重写（P34-M 的教训）：P0（CN 路径投毒穿透到客户端）存在期间，本看门狗一直是"全绿" ✗，
根因是它**只探 unbound A 与经 AGH 的客户端路径**，完全不覆盖**真正伪造的那一层 unbound B** ✗。

判据升级（Codex 规格）：
  1. **跨源判据**：随机不存在标签是否算"伪造"，要看**认证源**（unbound A，P1 后出口是加密+验签的
     aghdq→DoQ→NextDNS）怎么答：只有"认证源 rc=3（NXDOMAIN）而目标 rc=0 且带地址"才算伪造 ✓。
     这样合法通配符/既有域不会被误报 ✓。
  2. **维度拆分**：
     · `ok` = （**客户端侧**未暴露伪造：`client(agh)`、`guard` 两个目标）∧ servfail_ok ∧ ad_ok ✓
     · `upstream_tainted` = **中间层**（`unbound-b`、`dnscrypt`）出现伪造的条数 ⇒ 只作**黄灯告警** ✓
       （它们是国内上游，被注入是已知事实 ✓；是否构成客户端风险取决于 guard 的否决是否生效 ✓）。
  3. **正对照**：`www.taobao.com` / `www.baidu.com` 在中层与客户端都必须 **rc=0 且有地址** ✓
     ⇒ 避免"中层整体挂掉/乱答"时看门狗仍报绿 ✗。
输出 `/opt/dnsguard/verify/canary_state.json`（新增 `infra_ok`/`client_exposed`/`upstream_tainted`/`positive_ok`）。
"""
import io
import json
import os
import random
import socket
import ssl
import struct
import subprocess
import sys
import time

sys.path.insert(0, "/opt/dnsguard")
import verify_ip as V

OUT = "/opt/dnsguard/verify/canary_state.json"
LOGF = "/var/log/dnsguard-canary.log"
ZONES = ["googlevideo.com", "tiktokcdn.com", "tiktokcdn-us.com", "example.com"]
FIXED_LABELS = ["zz-canary-1", "zz-canary-2", "zz-canary-3"]
SIGNED = ["cloudflare.com", "www.iana.org"]
POSITIVE = ["www.taobao.com", "www.baidu.com"]
AUTH = ("unbound-a(auth)", ("172.18.0.1", 5353))          # 认证源（跨源判据的基准）
# (标签, 地址, 是否"客户端侧"目标)
TARGETS = [("client(agh)", ("172.18.0.2", 53), True),
           ("guard-probe", ("172.18.0.1", 5356), True),
           ("unbound-b", ("172.18.0.1", 5354), False),
           ("dnscrypt", ("127.0.0.2", 5353), False)]


def q(addr, name, qtype=1, to=8, retries=1):
    # P34-AH: 非应答（超时）不能直接当成“不是 SERVFAIL”的证据 ✗
    # —— 2026-10-10 07:19 就因一次超时把 servfail_ok 误判为 False ✗。这里重试一次。
    # ★ 2026-10-10 判据修正（二）：**必须校验问题段**。
    #   只按 socket/qid 匹配时，**前一次查询的迟到响应会被算到本次头上**（Task1 子代理已证实），
    #   后果是"假的 rc=0 / 假的瞬时 SERVFAIL"，例如 dnssec-failed.org 被判 bad_rcode=0 而拉红。
    #   verify_ip.parse_msg 已给出 qname/qtype ⇒ 这里比对；不匹配则丢弃并重试。
    d = el = st = None
    _want = name.rstrip(".").lower()
    for _i in range(retries + 1):
        for _try in range(3):
            d, el, st, _ = V.q_udp(addr, V.mk_query(name, qtype), to)
            if not d:
                break
            try:
                _m = V.parse_msg(d)
            except Exception:
                _m = None
            if _m is None:
                break                      # 解析失败：保持旧行为（上层按无法分类处理）
            _got = (_m.get("qname") or "").rstrip(".").lower()
            if _got and _got == _want:
                break                      # ✓ 问题段匹配
            d = None                       # ✗ 迟到/串台响应 ⇒ 丢弃重试
        if d:
            break
    if not d:
        return {"st": st, "ms": round(el * 1000)}
    m = V.parse_msg(d)
    return {"st": st, "ms": round(el * 1000), "rcode": m["rcode"], "ad": m["ad"],
            "types": [x["type_name"] for x in m["sections"]["an"]],
            "ips": [x["rdata"] for x in m["sections"]["an"] if x["type"] in (1, 28)]}


# 2026-10-10 P34-AA（子代理第二轮审计指出 ✗）：判据此前**只锚定 unbound A** ⇒ A 被投毒/超时即「假绿」 ✗。
# 这里加**第二家独立运营方**（境外认证 DoT，Mullvad）做交叉校验 ✓，并自带一个极简 DoT 客户端
#（不依赖 verify_ip 的 q_dot 参数约定 ✓，避免猜 API ✗）。
AUTH2 = {"id": "dot:mullvad(auth2)", "ip": "194.242.2.2", "port": 853, "sni": "base.dns.mullvad.net"}


def dot_query(name, r=AUTH2, to=6.0):
    """极简 DoT 查询（带 DO 位），返回 (rcode, n_ips) 或 None。"""
    try:
        msg = V.mk_query(name, 1)          # verify_ip 的 mk_query 已含 EDNS0 DO ✓
        ctx = ssl.create_default_context()
        raw = socket.create_connection((r["ip"], r["port"]), timeout=to)
        raw.settimeout(to)
        ss = ctx.wrap_socket(raw, server_hostname=r["sni"])
        ss.sendall(struct.pack("!H", len(msg)) + msg)
        ln = struct.unpack("!H", ss.recv(2))[0]
        b = b""
        while len(b) < ln:
            ch = ss.recv(ln - len(b))
            if not ch:
                break
            b += ch
        ss.close()
        m = V.parse_msg(b)
        return (m["rcode"], len([x for x in m["sections"]["an"] if x["type"] in (1, 28)]))
    except Exception:
        return None


def sh_iptables(args):
    """只读执行 iptables 并返回 -S 文本（零写操作 ✓）。"""
    try:
        r = subprocess.run('iptables ' + args, shell=True, stdout=subprocess.PIPE,
                           universal_newlines=True, timeout=10)
        return (r.stdout or '')
    except Exception:
        return ''


def infra_check():
    """F3 并入（2026-10-10 P34-O）：确认"unbound-b 明文 :53 封堵"与 F2 的容器访问控制在位 ✓。

    背景：原先有一条 `unbound-b-53-watch.timer` 专盯这件事，但它**已不存在** ✗
    （`systemctl status` ⇒ Unit could not be found）；而保护是否在位直接决定链路能否被旁路 ✓。
    """
    out = {"unboundb_chain": 0, "docker_user_jump": 0, "input_f2_rules": 0}
    try:
        r = subprocess.run("iptables -S UNBOUNDB_53 2>/dev/null", shell=True, stdout=subprocess.PIPE,
                           universal_newlines=True, timeout=10)
        out["unboundb_chain"] = sum(1 for ln in (r.stdout or "").split("\n") if "DROP" in ln)
        r = subprocess.run("iptables -S DOCKER-USER 2>/dev/null", shell=True, stdout=subprocess.PIPE,
                           universal_newlines=True, timeout=10)
        out["docker_user_jump"] = sum(1 for ln in (r.stdout or "").split("\n") if "UNBOUNDB_53" in ln)
        r = subprocess.run("iptables -S INPUT 2>/dev/null", shell=True, stdout=subprocess.PIPE,
                           universal_newlines=True, timeout=10)
        out["input_f2_rules"] = sum(1 for ln in (r.stdout or "").split("\n") if "f2-20261010" in ln)
    except Exception as e:
        out["error"] = str(e)[:80]
    # 2026-10-10 P34-AA：**只数条数会被绕过** ✗（阈值 2/1/10，实际 2/1/12 ⇒ 掉 2 条 INPUT 仍绿 ✗）
    # ⇒ 改为"计数 + **关键规则指纹与顺序**"双校验 ✓
    ip = sh_iptables("-S INPUT")
    du = sh_iptables("-S DOCKER-USER")
    ub = sh_iptables("-S UNBOUNDB_53")
    need_input = ["-s 172.18.0.1/32 -p udp", "-s 127.0.0.0/8 -p udp",
                  "-s 172.18.0.2/32 -p udp", "--dport 5356", "--dport 5355", "5353,5354,5356"]
    missing = [x for x in need_input if x not in ip]
    i_allow = du.find("-s 172.18.0.4/32 -d 172.18.0.6/32")
    i_deny = du.find("-d 172.18.0.5/32")
    order_ok = (0 <= i_allow < i_deny) if (i_allow >= 0 and i_deny >= 0) else False
    # 2026-10-10 P34-AD：**固化本次 P0 事故** —— aghdq 的 bootstrap 若指向内网（尤其 unbound A），
    # 就与 A 的 forward-addr(→aghdq) 构成**环** ✗：A 一重启清缓存，aghdq 便无法引导解析 nextdns，
    # A 也随之 `failed to prime trust anchor` ⇒ 境外全 SERVFAIL。此项零成本，必须常驻检查 ✓。
    boot_ok = True
    boot_seen = []
    try:
        y = io.open("/opt/aghdq/AdGuardHome.yaml", encoding="utf-8").read()
        import re as _re
        m = _re.search(r"bootstrap_dns:\n((?:\s*- .*\n)+)", y)
        if m:
            boot_seen = [ln.strip("- ").strip() for ln in m.group(1).strip().split("\n")]
            boot_ok = not any(x.startswith(("172.1", "172.18", "127.", "10.", "192.168")) for x in boot_seen)
        else:
            boot_ok = False
    except Exception:
        boot_ok = False
    ub_ok = ("--dport 53" in ub) and (ub.count("DROP") >= 2)
    out["missing_input_rules"] = missing
    out["docker_user_order_ok"] = order_ok
    out["unboundb_ok"] = ub_ok
    # 泛化（P34-AE）：**任何引导点都不得指向本链**（172.18.0.x / 127.* / 本机 53xx）✗
    # —— 这是 2026-10-10 P0（aghdq.bootstrap → unbound A）的通用形态。
    loop_hits = []
    try:
        dcy = io.open("/opt/dnscrypt-proxy/dnscrypt-proxy.toml", encoding="utf-8").read()
        for _m in re.finditer(r"bootstrap_resolvers\s*=\s*\[([^\]]+)\]", dcy):
            for _ip in re.findall(r"[\x27\"]([^\x27\"]+)[\x27\"]", _m.group(1)):
                if _ip.startswith(("172.18.", "172.19.", "127.", "10.", "192.168.")):
                    loop_hits.append("dnscrypt:" + _ip)
    except Exception:
        pass
    for _c in ("adgh", "aghdq", "unbound", "unbound-b"):
        try:
            _rf = subprocess.run("docker exec %s sh -c \x27grep nameserver /etc/resolv.conf\x27" % _c,
                                 shell=True, stdout=subprocess.PIPE, universal_newlines=True,
                                 timeout=8).stdout or ""
            for _ln in _rf.split("\n"):
                _v = _ln.split()[-1] if _ln.split() else ""
                if _v.startswith(("172.18.", "172.19.", "127.")):
                    loop_hits.append("%s:%s" % (_c, _v))
        except Exception:
            pass
    out["chain_loop_hits"] = loop_hits
    out["chain_loop_ok"] = (len(loop_hits) == 0)
    out["aghdq_bootstrap"] = boot_seen
    out["aghdq_bootstrap_ok"] = boot_ok
    out["ok"] = ((out["unboundb_chain"] >= 2) and (out["docker_user_jump"] >= 1)
                 and (out["input_f2_rules"] >= 10) and (not missing) and order_ok and ub_ok and boot_ok and (len(loop_hits) == 0))
    return out


def log(line):
    try:
        with io.open(LOGF, "a", encoding="utf-8") as f:
            f.write("[%s] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), line))
    except Exception:
        pass


def run():
    res = {"ts": int(time.time()), "time": time.strftime("%Y-%m-%d %H:%M:%S"), "targets": {}, "auth": {}}
    client_exposed = 0
    upstream_tainted = 0
    servfail_ok = True
    servfail_unknown = 0
    ad_ok = 0
    signed_tried = 0
    positive_bad = []

    # ① 先问认证源：不存在的标签应 rc=3（NXDOMAIN）或无地址
    names = ["%s.%s" % (l, ZONES[i % len(ZONES)]) for i, l in enumerate(FIXED_LABELS)]
    names.append("zz%d.tiktokcdn-us.com" % random.randrange(10 ** 9))
    auth_ok_names = []
    for n in names:
        r = q(AUTH[1], n)
        res["auth"][n] = {"rcode": r.get("rcode"), "n_ips": len(r.get("ips") or [])}
        # 认证源认为"不存在"（rc=3 且无地址）
        if r.get("rcode") == 3 and not (r.get("ips") or []):
            auth_ok_names.append(n)
    # 第二家独立运营方（未就绪 ⇒ 视为"无证据"，不改变 A 的判定 ✓）
    auth2_names = []
    probe2 = dot_query("www.iana.org")
    auth2_ok = bool(probe2 and probe2[0] == 0 and probe2[1] > 0)
    if auth2_ok:
        for n in names:
            r2 = dot_query(n)
            if r2 is None:
                continue
            res["auth"][n]["auth2_rcode"] = r2[0]
            if r2[0] == 3 and r2[1] == 0:
                auth2_names.append(n)
    res["auth2_ok"] = auth2_ok
    res["auth2_nonexistent"] = auth2_names
    # 合并：**任一可信源**说"不存在"即视为不存在（标签本身都不该存在 ⇒ 无假阳性 ✓）
    auth_ok_names = sorted(set(auth_ok_names) | set(auth2_names))
    res["auth_nonexistent"] = auth_ok_names

    # ② 逐目标：跨源判据
    for tag, addr, is_client in TARGETS:
        t = {"checked": 0, "fabricated": 0, "servfail_ok": None, "ad_ok": 0, "signed_tried": 0,
             "positive_bad": [], "details": []}
        for n in names:
            r = q(addr, n)
            t["checked"] += 1
            fab = (n in auth_ok_names) and r.get("rcode") == 0 and bool(r.get("ips"))
            if fab:
                t["fabricated"] += 1
                if is_client:
                    client_exposed += 1
                else:
                    upstream_tainted += 1
                t["details"].append({"name": n, "verdict": "FABRICATED", "ips": r.get("ips")})
            else:
                t["details"].append({"name": n, "verdict": "ok", "rcode": r.get("rcode")})
        # DNSSEC 边界（仅客户端侧目标参与红绿裁决）
        r = q(addr, "dnssec-failed.org")
        _rc = r.get("rcode")
        # ★ 2026-10-10 判据修正（用户批准方案 b）：
        #   把"**超时/无应答**"与"**明确的非 SERVFAIL 应答**"分开。
        #   · 明确收到 rcode 且 != 2 ⇒ 真·DNSSEC 边界失败 ⇒ 拉红 ✓
        #   · 无应答（rcode is None）⇒ 探针超时，**不是安全结论** ⇒ 记 unknown，不拉红 ✓
        #   安全性仍由 client_exposed / fabricated 兜底；gate 无应答的长尾已单独量化（1–3%，不可按需复现）。
        if _rc is None:
            t["servfail_ok"] = None
            t["servfail_unknown"] = 1
            if is_client:
                servfail_unknown += 1
        else:
            t["servfail_ok"] = (_rc == 2)
            if is_client and _rc != 2:
                t["servfail_bad_rcode"] = _rc
                servfail_ok = False
        # 已签名名 AD/RRSIG
        for n in SIGNED:
            r = q(addr, n)
            t["signed_tried"] += 1
            good = bool(r.get("ad")) and "RRSIG" in (r.get("types") or [])
            if good:
                t["ad_ok"] += 1
            if is_client:
                signed_tried += 1
                if good:
                    ad_ok += 1
        # 正对照：必须解析出地址
        for n in POSITIVE:
            r = q(addr, n)
            if not (r.get("rcode") == 0 and (r.get("ips") or [])):
                t["positive_bad"].append({"name": n, "rcode": r.get("rcode")})
                positive_bad.append("%s@%s" % (n, tag))
        res["targets"][tag] = t

    res["client_exposed"] = client_exposed
    res["upstream_tainted"] = upstream_tainted
    res["servfail_ok"] = servfail_ok
    res["servfail_unknown"] = servfail_unknown
    res["ad_ok"] = "%d/%d" % (ad_ok, signed_tried)
    res["positive_ok"] = (len(positive_bad) == 0)
    res["positive_bad"] = positive_bad[:8]
    ok = (client_exposed == 0) and servfail_ok and (ad_ok == signed_tried) and res["positive_ok"]
    infra = infra_check()
    res["infra"] = infra
    res["infra_ok"] = bool(infra.get("ok"))
    ok = ok and res["infra_ok"]
    res["ok"] = ok

    try:
        prev = {}
        if os.path.exists(OUT):
            prev = json.load(io.open(OUT, encoding="utf-8"))
        hist = prev.get("history") or []
        hist.append({"ts": res["ts"], "ok": ok, "client_exposed": client_exposed,
                     "upstream_tainted": upstream_tainted})
        hist = hist[-288:]
        res["history"] = hist
        res["fail_count"] = int(prev.get("fail_count") or 0) + (0 if ok else 1)
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with io.open(OUT, "w", encoding="utf-8") as f:
            json.dump(res, f, ensure_ascii=False, indent=1)
    except Exception as e:
        log("state write error: %s" % e)

    if ok:
        log("CANARY OK  client_exposed=0 servfail_ok=%s ad=%s positive=%s infra=%s | upstream_tainted=%d(黄灯)" % (
            servfail_ok, res["ad_ok"], res["positive_ok"], res["infra_ok"], upstream_tainted))
    else:
        log("CANARY FAIL client_exposed=%d servfail_ok=%s ad=%s positive_ok=%s bad=%s upstream_tainted=%d" % (
            client_exposed, servfail_ok, res["ad_ok"], res["positive_ok"],
            json.dumps(res["positive_bad"], ensure_ascii=False), upstream_tainted))
    if upstream_tainted and ok:
        log("CANARY WARN 中层伪造 %d 条（unbound-b/dnscrypt 被注入，属已知事实）——客户端侧 0 条 ⇒ 仍绿 ✓" % upstream_tainted)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(run())
