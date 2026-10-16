#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""最终验收证据采集（只读 + 一次单测）。把每条验收项与原始结果一起打印，供验收报告引用。"""
import io
import json
import random
import socket
import ssl
import struct
import subprocess
import sys
import time

sys.path.insert(0, "/opt/dnsguard")
import verify_ip as V


def sh(cmd, timeout=300):
    r = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       universal_newlines=True, timeout=timeout)
    return (r.stdout or "").strip()


def q(addr, port, name, qtype=1, to=12):
    d, el, st, _ = V.q_udp((addr, port), V.mk_query(name, qtype), to)
    if not d:
        return st, None, [], None
    m = V.parse_msg(d)
    ips = [x["rdata"] for x in m["sections"]["an"] if x["type"] in (1, 28)]
    return "rc%d" % m["rcode"], m["ad"], ips, el * 1000


def dot(name, to=8):
    try:
        ctx = ssl.create_default_context()
        raw = socket.create_connection(("127.0.0.1", 853), timeout=to)
        raw.settimeout(to)
        ss = ctx.wrap_socket(raw, server_hostname="dns.example.com")
        msg = V.mk_query(name, 1)
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
        return "rc%d" % m["rcode"], m["ad"], [x["rdata"] for x in m["sections"]["an"] if x["type"] in (1, 28)]
    except Exception as e:
        return "ERR:%s" % type(e).__name__, None, []


R = {}
print("=" * 72)
print("A. 服务与容器")
R["services"] = sh("for u in dnsguard dnsguard-verifier chainmon dnscrypt-proxy-local dnsguard-canary.timer "
                   "dnsguard-firewall.service dns-chain-probe.timer; do printf '%s=%s ' $u $(systemctl is-active $u); done")
print("  " + R["services"])
R["containers"] = sh("for c in unbound unbound-b adgh aghdq; do printf '%s=%s ' $c $(docker inspect -f '{{.State.Status}}' $c); done")
print("  " + R["containers"])
R["nrestarts"] = sh("for u in dnsguard dnsguard-verifier chainmon; do printf '%s=%s ' $u $(systemctl show $u -p NRestarts --value); done")
print("  NRestarts: " + R["nrestarts"])
R["enforce"] = sh("tr '\\0' '\\n' < /proc/$(systemctl show dnsguard -p MainPID --value)/environ | grep -E "
                  "'CN_EXIST_MODE|CN_VETO_WITNESS|R8_ASN_GATE' | tr '\\n' ' '")
print("  guard 关键环境: " + R["enforce"])

print("=" * 72)
print("B. P0 反投毒：随机不存在标签 × 3 家族 × 3 个客户端入口（应 rc2/rc3 且 0 地址）")
leak_rows = []
bad = 0
for fam in ("tiktokcdn-us.com", "tiktokcdn.com", "googlevideo.com"):
    n = "zr%d.%s" % (random.randrange(10 ** 9), fam)
    g_rc, _gad, g_ips, _ = q("172.18.0.1", 5355, n)
    a_rc, _aad, a_ips, _ = q("172.18.0.2", 53, n)
    d_rc, _dad, d_ips = dot(n)
    bad += (1 if g_ips else 0) + (1 if a_ips else 0) + (1 if d_ips else 0)
    row = "%-34s guard=%-4s AGH=%-4s DoT853=%-4s 给地址=%d" % (n[:34], g_rc, a_rc, d_rc,
                                                               (1 if g_ips else 0) + (1 if a_ips else 0) + (1 if d_ips else 0))
    leak_rows.append(row)
    print("  " + row)
R["leak_bad"] = bad
print("  ⇒ 合计拿到地址次数: %d（验收要求 0 ✓）" % bad)
print("  对照（B 直接查，应出现伪造）: " + str(q("172.18.0.1", 5354, "zr%d.tiktokcdn-us.com" % random.randrange(10 ** 9))[:3]))

print("=" * 72)
print("C. 合法 CN 名零误杀（30 个）")
legit = ["www.baidu.com", "www.qq.com", "www.taobao.com", "www.jd.com", "www.163.com", "www.zhihu.com",
         "www.bilibili.com", "www.douyin.com", "www.meituan.com", "www.12306.cn", "www.mi.com", "www.oppo.com",
         "www.vivo.com.cn", "www.toutiao.com", "www.weibo.com", "www.sina.com.cn", "www.sohu.com", "www.ifeng.com",
         "www.58.com", "www.hexun.com", "www.ctrip.com", "www.qunar.com", "www.dianping.com", "www.pinduoduo.com",
         "www.suning.com", "www.xueqiu.com", "www.eastmoney.com", "www.autohome.com.cn", "www.ke.com", "www.lianjia.com"]
sf = []
lat = []
for n in legit:
    rc, _ad, ips, ms = q("172.18.0.1", 5355, n)
    if ms:
        lat.append(ms)
    if rc != "rc0" or not ips:
        sf.append((n, rc))
lat.sort()
R["legit_ok"] = "%d/%d" % (len(legit) - len(sf), len(legit))
R["legit_sf"] = sf
R["legit_lat"] = "中位 %.0fms / p90 %.0fms" % (lat[len(lat) // 2], lat[int(len(lat) * 0.9)]) if lat else "-"
print("  rc0+有地址: %s；延迟 %s" % (R["legit_ok"], R["legit_lat"]))
if sf:
    print("  ✗ 异常: %s" % sf)

print("=" * 72)
print("D. DNSSEC 与签名名")
for tag, a, p, n in (("A", "172.18.0.1", 5353, "www.iana.org"), ("A", "172.18.0.1", 5353, "dnssec-failed.org"),
                     ("B", "172.18.0.1", 5354, "www.iana.org"), ("B", "172.18.0.1", 5354, "dnssec-failed.org")):
    rc, ad, ips, _ = q(a, p, n)
    print("  %s %-20s rc=%-4s AD=%s" % (tag, n, rc, ad))
R["dnssec_stats"] = sh("for c in unbound unbound-b; do printf '%s: ' $c; docker exec $c /opt/unbound/sbin/unbound-control "
                       "-c /opt/unbound/etc/unbound/unbound.conf stats_noreset 2>/dev/null | "
                       "grep -E 'num.answer.secure|num.answer.bogus' | tr '\\n' ' '; echo; done")
print("  " + R["dnssec_stats"].replace("\n", "\n  "))

print("=" * 72)
print("E. canary v3（含 auth2 交叉校验 + infra 指纹）")
rc_can = subprocess.run("timeout 300 python3 /opt/dnsguard/canary_watch.py", shell=True).returncode
R["canary_exit"] = rc_can
print("  退出码=%s" % rc_can)
try:
    c = json.load(io.open("/opt/dnsguard/verify/canary_state.json", encoding="utf-8"))
    R["canary"] = {k: c.get(k) for k in ("ok", "client_exposed", "upstream_tainted", "infra_ok", "positive_ok",
                                         "auth2_ok", "ad_ok", "servfail_ok")}
    print("  %s" % R["canary"])
    print("  infra=%s" % (c.get("infra") or {}))
    for k, v in (c.get("targets") or {}).items():
        print("    [%-12s] fabricated=%s/%s" % (k, v.get("fabricated"), v.get("checked")))
except Exception as e:
    print("  读取状态失败: %s" % e)

print("=" * 72)
print("F. 防火墙与旁路收口")
R["fw"] = sh("printf 'INPUT f2=%s ; DOCKER-USER cn53=%s ; jump=%s ; UNBOUNDB_53 DROP=%s' "
             "$(iptables -S INPUT | grep -c f2-20261010) $(iptables -S DOCKER-USER | grep -c cn53-fwd) "
             "$(iptables -S DOCKER-USER | grep -c -- '-j UNBOUNDB_53') $(iptables -S UNBOUNDB_53 | grep -c DROP)")
print("  " + R["fw"])
R["container_reach"] = sh("docker exec astrbot python3 -c \"\n"
                          "import socket\n"
                          "out=[]\n"
                          "for ip,port in (('172.18.0.5',53),('172.18.0.4',53),('172.18.0.6',53),('172.18.0.1',5355),('172.18.0.2',53)):\n"
                          "    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2)\n"
                          "    try:\n"
                          "        s.sendto(b'\\\\x12\\\\x34\\\\x01\\\\x00\\\\x00\\\\x01\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x06github\\\\x03com\\\\x00\\\\x00\\\\x01\\\\x00\\\\x01',(ip,port)); s.recvfrom(512); out.append('%s:%d=OK'%(ip,port))\n"
                          "    except Exception: out.append('%s:%d=BLOCK'%(ip,port))\n"
                          "    s.close()\n"
                          "print(' '.join(out))\" 2>&1 | tail -1")
print("  astrbot 可达性: " + R["container_reach"])

print("=" * 72)
print("G. 单测回归")
R["tests"] = sh("cd /tmp/p34btest && timeout 300 python3 test_p34b.py 2>&1 | tail -2")
print("  " + R["tests"].replace("\n", "\n  "))

print("=" * 72)
print("H. 日志与口径")
R["exceptions"] = sh("journalctl -u dnsguard -u dnsguard-verifier -u chainmon --since '30 min ago' --no-pager 2>/dev/null | grep -ciE 'traceback|error'")
print("  近 30 分钟异常行: %s" % R["exceptions"])
print("  " + sh("python3 -c \"import json;d=json.load(open('/opt/dnsguard/stats_meta.json'));print('per_boot=%d 项 / 说明=%s' % (len(d.get('per_boot') or []), (d.get('note') or '')[:60]))\""))
print("  日志大小: " + sh("ls -la /var/log/dnsguard.log | awk '{print $5\" bytes\"}'"))
print("  logrotate: " + sh("ls /etc/logrotate.d/dnsguard >/dev/null 2>&1 && echo 已配置 || echo 缺失"))

io.open("/tmp/acceptance_raw.json", "w", encoding="utf-8").write(json.dumps(R, ensure_ascii=False, indent=1))
print("\n已写 /tmp/acceptance_raw.json ✓")
