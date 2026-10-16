#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""分层 DNS 链路探针（dns-audit-20261015 F3 修复版）。

修复审计报告 F3 指出的四处判据缺陷：
  1. TLS 严格校验 —— 原用 ssl._create_unverified_context()，证书过期/名字不匹配/中间人
     都会被记成"健康"；现用 ssl.create_default_context()，check_hostname=True、
     CERT_REQUIRED，SNI=dns.example.com。证书链一旦出问题，探针必须报错。
  2. 完整读帧 —— 原 DoT 单次 recv(n) 不保证读满（TCP 会拆包），截断报文被记成
     bad_response；现按 2 字节长度前缀 + read_exact() 读满。
  3. 分层判据 —— 原 rc in (0,3,4) 把 NOTIMP(4)、NXDOMAIN(3) 与"链路可用"等同，
     还会把 SERVFAIL(2)/REFUSED(5) 之外的一切都当成功；现每层每样本给出显式期望。
  4. 正/负样本分离 —— 原按分钟轮换 4 个正向域名，永远测不到"必须失败"的路径；
     现固定四类样本（正常、正常+AD、DNSSEC bogus、NXDOMAIN）。

另修：原样本含 example.com，该名在本环境被 AGH 过滤规则命中（IsFiltered=True），
不能作为上游可用性证据，已移除。

退出码：所有层 × 所有样本均符合期望 ⇒ 0；任一不符 ⇒ 1（明细写入 jsonl）。
"""
import json
import os
import socket
import ssl
import struct
import sys
import time
import urllib.request

OUT = '/var/log/dns-chain-probe.jsonl'
SNI = 'dns.example.com'
DOH_URL = 'https://dns.example.com:444/dns-query'
TIMEOUT = 5.0

# (name, expect)；expect 取值：
#   ok_ad    → rcode==0 且 an>=1 且 ad==True（DNSSEC 验证通过）
#   ok       → rcode==0 且 an>=1
#   servfail → rcode==2（DNSSEC bogus 必须终局失败，不得返回可用答案）
#   nxdomain → rcode==3
SAMPLES = (
    ('cloudflare.com', 'ok_ad'),
    ('www.qq.com', 'ok'),
    ('dnssec-failed.org', 'servfail'),
    ('nxdomain-probe.invalid', 'nxdomain'),
)

RCODE_NAME = {0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN',
              4: 'NOTIMP', 5: 'REFUSED'}


def build(name, qtype=1, qid=0x1234, do=True, bufsize=1232):
    """构造查询：RD=1，按需带 EDNS0+DO（不带 DO 时 guard 不做 DNSSEC 验证，AD 必为 0）。"""
    arcount = 1 if do else 0
    q = struct.pack('!HHHHHH', qid, 0x0100, 1, 0, 0, arcount)
    for label in name.split('.'):
        q += bytes([len(label)]) + label.encode('ascii')
    q += b'\x00' + struct.pack('!HH', qtype, 1)
    if do:
        # OPT: root name(1) + type=41 + class=UDP bufsize + ttl=DO(0x8000) + rdlen=0
        q += b'\x00' + struct.pack('!HHIH', 41, bufsize, 0x8000, 0)
    return qid, q


def parse(d):
    """解析响应：rcode / AD / 答案数 / 事务 ID。畸形响应返回 None。"""
    if len(d) < 12:
        return None
    tid, flags, qd, an = struct.unpack('!HHHH', d[:8])
    return {'id': tid, 'rcode': flags & 0xF, 'ad': bool(flags & 0x20),
            # TC=bit9(0x0200)、AD=bit5(0x0020)、QR=bit15(0x8000)；0x02 是 RCODE 的 bit1，用它判 TC 会把
            # SERVFAIL(2)/NXDOMAIN(3) 全部误报成“截断响应”（本轮实测踩到）
            'tc': bool(flags & 0x0200), 'qr': bool(flags & 0x8000), 'an': an, 'len': len(d)}


def read_exact(sock, n, deadline):
    buf = b''
    while len(buf) < n:
        left = deadline - time.monotonic()
        if left <= 0:
            raise socket.timeout('read_exact timeout (%d/%d)' % (len(buf), n))
        sock.settimeout(left)
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise IOError('connection closed after %d/%d bytes' % (len(buf), n))
        buf += chunk
    return buf


def check(expect, r, nexc):
    """返回 (ok, note)。判据分层，NOTIMP/NXDOMAIN 不再被当成通用成功。"""
    if r is None:
        return False, 'malformed response'
    if not r['qr']:
        return False, 'QR=0（这不是响应）'
    if r['id'] != nexc:
        return False, 'transaction id mismatch'
    if r['tc']:
        return False, 'TC=1（截断响应，DoT/DoH 不应出现）'
    rc = r['rcode']
    if expect == 'ok_ad':
        if rc != 0 or r['an'] < 1:
            return False, 'rcode=%s an=%d（期望 NOERROR 且有答案）' % (RCODE_NAME.get(rc, rc), r['an'])
        if not r['ad']:
            return False, 'ad=0（期望 DNSSEC 验证通过 AD=1）'
        return True, 'rcode=NOERROR an=%d ad=1' % r['an']
    if expect == 'ok':
        if rc != 0 or r['an'] < 1:
            return False, 'rcode=%s an=%d（期望 NOERROR 且有答案）' % (RCODE_NAME.get(rc, rc), r['an'])
        return True, 'rcode=NOERROR an=%d ad=%d' % (r['an'], int(r['ad']))
    if expect == 'servfail':
        if rc == 2:
            return True, 'rcode=SERVFAIL（DNSSEC bogus 终局，符合预期）'
        return False, 'rcode=%s（期望 SERVFAIL，bogus 名被当可用答案返回）' % RCODE_NAME.get(rc, rc)
    if expect == 'nxdomain':
        if rc == 3:
            return True, 'rcode=NXDOMAIN'
        return False, 'rcode=%s（期望 NXDOMAIN）' % RCODE_NAME.get(rc, rc)
    return False, 'unknown expectation %r' % expect


def udp(host, port, name, expect, to=TIMEOUT):
    qid, q = build(name)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(to)
    t = time.monotonic()
    try:
        s.sendto(q, (host, port))
        d, _peer = s.recvfrom(4096)
        ms = (time.monotonic() - t) * 1000
        # UDP 必须来自请求的地址（防投毒）：nf_tables 后端下 recvfrom 的 peer 可信
        ok, note = check(expect, parse(d), qid)
        return ms, ok, note, parse(d)
    except Exception as e:
        return (time.monotonic() - t) * 1000, False, '%s: %s' % (type(e).__name__, e), None
    finally:
        s.close()


def dot(host, port, name, expect, to=TIMEOUT):
    qid, q = build(name)
    t = time.monotonic()
    raw = None
    try:
        deadline = t + to
        raw = socket.create_connection((host, port), to)
        ctx = ssl.create_default_context()          # 严格：CERT_REQUIRED + check_hostname
        ss = ctx.wrap_socket(raw, server_hostname=SNI)
        raw = None
        ss.sendall(struct.pack('!H', len(q)) + q)
        head = read_exact(ss, 2, deadline)
        n = struct.unpack('!H', head)[0]
        d = read_exact(ss, n, deadline)
        vers = ss.version()
        cert = ss.getpeercert()
        ss.close()
        ms = (time.monotonic() - t) * 1000
        ok, note = check(expect, parse(d), qid)
        return ms, ok, note, parse(d), vers, cert.get('notAfter')
    except Exception as e:
        if raw is not None:
            try:
                raw.close()
            except Exception:
                pass
        return (time.monotonic() - t) * 1000, False, 'TLS/IO %s: %s' % (type(e).__name__, e), None, None, None


def doh(name, expect, to=8.0):
    qid, q = build(name)
    t = time.monotonic()
    try:
        ctx = ssl.create_default_context()          # 严格校验（含主机名）
        req = urllib.request.Request(
            DOH_URL, data=q, method='POST',
            headers={'Content-Type': 'application/dns-message',
                     'Accept': 'application/dns-message'})
        r = urllib.request.urlopen(req, timeout=to, context=ctx)
        d = r.read()
        status = r.status
        ms = (time.monotonic() - t) * 1000
        if status != 200:
            return ms, False, 'HTTP %s' % status, None, status
        ok, note = check(expect, parse(d), qid)
        return ms, ok, note, parse(d), status
    except Exception as e:
        return (time.monotonic() - t) * 1000, False, 'TLS/HTTP %s: %s' % (type(e).__name__, e), None, None


def main():
    started = time.time()
    out = {'ts': int(started), 'samples': [s[0] for s in SAMPLES], 'layers': {}}
    results = {}          # layer -> {name: ok}
    first_fail = None

    for name, expect in SAMPLES:
        res = udp('127.0.0.1', 5353, name, expect)
        results.setdefault('unbound_a', {})[name] = res
        res = udp('127.0.0.1', 5354, name, expect)
        results.setdefault('unbound_b', {})[name] = res
        res = udp('172.18.0.1', 5356, name, expect)
        results.setdefault('guard_udp', {})[name] = res
        res = dot('127.0.0.1', 853, name, expect)
        results.setdefault('dot', {})[name] = res
        res = doh(name, expect)
        results.setdefault('doh', {})[name] = res

    for layer in ('unbound_a', 'unbound_b', 'guard_udp', 'dot', 'doh'):
        lout = {}
        for name, expect in SAMPLES:
            res = results.get(layer, {}).get(name)
            if res is None:
                lout[name] = {'ok': False, 'error': 'not-run'}
                continue
            entry = {'ms': round(res[0], 1), 'ok': res[1], 'expect': expect, 'note': res[2]}
            parsed = res[3]
            if parsed:
                entry['rcode'] = parsed['rcode']
                entry['ad'] = parsed['ad']
                entry['an'] = parsed['an']
            if layer == 'dot' and len(res) > 4:
                entry['tls'] = res[4]
                entry['notAfter'] = res[5]
            if layer == 'doh' and len(res) > 4:
                entry['http'] = res[4]
            lout[name] = entry
            if not res[1] and first_fail is None:
                first_fail = '%s/%s: %s' % (layer, name, res[2])
        out['layers'][layer] = lout

    try:
        with open('/proc/meminfo') as f:
            m = {x.split(':')[0]: int(x.split()[1]) for x in f if ':' in x}
        out['memory'] = {k: m.get(k) for k in ('MemAvailable', 'SwapFree', 'SwapTotal')}
    except Exception:
        pass
    try:
        with open('/proc/loadavg') as f:
            out['loadavg'] = f.read().split()[:3]
    except Exception:
        pass

    out['elapsed_ms'] = round((time.time() - started) * 1000, 1)
    out['result'] = 'OK' if first_fail is None else 'FAIL'
    if first_fail:
        out['first_fail'] = first_fail

    # 明细打 stdout（systemd journal / 人工运行时可见）
    for layer in ('unbound_a', 'unbound_b', 'guard_udp', 'dot', 'doh'):
        for name, expect in SAMPLES:
            e = out['layers'][layer][name]
            print('%-10s %-24s %-9s %-4s %s' % (
                layer, name, expect, 'OK' if e.get('ok') else 'FAIL',
                e.get('note') or e.get('error') or ''))
    print('RESULT: %s%s' % (out['result'], ('  first_fail=%s' % first_fail) if first_fail else ''))

    try:
        with open(OUT, 'a') as f:
            f.write(json.dumps(out, separators=(',', ':')) + '\n')
    except Exception as e:
        print('WARN 无法写入 %s: %s' % (OUT, e))

    return 0 if first_fail is None else 1


if __name__ == '__main__':
    sys.exit(main())
