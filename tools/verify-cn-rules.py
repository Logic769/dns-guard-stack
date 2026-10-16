#!/usr/bin/env python3
"""CN 分流自检：经 dcp(127.0.0.2:5353) 抽查 CN 与境外域名。退出码 0=通过"""
import sys, socket
sys.path.insert(0, '/opt/dnsguard')
import guard as G
G.load_cn_nets()
def ask(n, h='127.0.0.2', p=5353):
    q = G.mk_query(n, 1); s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(8)
    try:
        s.sendto(q, (h, p)); rc, ips, _c, _t = G.parse_a(s.recvfrom(4096)[0]); return rc, ips
    except Exception: return None, []
    finally: s.close()
def bad(name, ips):
    for ip in ips or []:
        n = G._norm_ip(ip)
        if n in G._POISON_IPS_NORM or n == G._norm_ip('2001::1'): return '已知注入'
        if G.range_hit([ip], name, strict=False): return '跨族段'
    return None
fails = []; cn_ok = 0
for d in ('www.baidu.com', 'www.qq.com', 'www.jd.com'):
    rc, ips = ask(d); f = [G.is_cn_ip(x) for x in ips]
    ok = bool(f) and all(x is True for x in f); cn_ok += 1 if ok else 0
    print('  %-16s rcode=%s %-38s %s' % (d, rc, ','.join(ips[:2]) if ips else '(无)', 'CN' if ok else '非CN'))
for d in ('www.google.com', 'github.com'):
    rc, ips = ask(d); b = bad(d, ips)
    print('  %-16s rcode=%s %-38s %s' % (d, rc, ','.join(ips[:2]) if ips else '(无)', b or '干净'))
    if b: fails.append('%s %s' % (d, b))
if cn_ok < 2: fails.append('CN 命中 %d/3' % cn_ok)
print('RESULT %s' % ('FAIL ' + str(fails) if fails else 'PASS'))
sys.exit(1 if fails else 0)
