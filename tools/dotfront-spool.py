#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dotfront-spool：抓 DoT 的明文内腿（nginx 853 -> adgh 容器 53，走 docker 网桥），
把 DNS 查询明文字段写成 JSONL，供 devfp 的 dotf_loop 消费。

只读、零第三方依赖（AF_PACKET + 标准库；适配 Python 3.6）。
环境变量：
  DOTF_IFACE  抓包网卡；auto = 按 DOTF_GW 的 IP 自动找网桥（默认 auto）
  DOTF_GW     网桥网关 IP（默认 172.18.0.1）
  DOTF_DST    只收 dst 为该 IP 的包（默认 172.18.0.2，即 adgh 容器）
  DOTF_DPORT  目的端口（默认 53）
  DOTF_SPOOL  输出文件（默认 /var/log/dotfront.jsonl）
输出每行一条 ev="q" 记录：
  {"ev":"q","ip":"172.18.0.1","sport":<nginx 本地端口>,"t":<int 秒>,"tf":<float 秒>,
   "qname":"...","qt":"A","edns":{"cookie_client":"...","ecs":"1.2.3.0/24","padding":468},
   "do":1,"udp_size":1232,"mixed_case":false,"cookie_echo":false}
注意：ip/sport 是内腿的（连接方是 nginx），真实客户端由 devfp 侧按
「DoT 请求事件」时间对齐找回（_align_plain_event）。
"""
import json
import os
import socket
import struct
import sys
import time

SPOOL = os.environ.get("DOTF_SPOOL", "/var/log/dotfront.jsonl")
IFACE = os.environ.get("DOTF_IFACE", "auto")
GW = os.environ.get("DOTF_GW", "172.18.0.1")
DST = os.environ.get("DOTF_DST", "172.18.0.2")
DPORT = int(os.environ.get("DOTF_DPORT", "53"))
MAXBUF = 16384
BUF_MAX = 512

QT = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
      28: "AAAA", 33: "SRV", 41: "OPT", 43: "DS", 46: "RRSIG", 47: "NSEC",
      48: "DNSKEY", 64: "SVCB", 65: "HTTPS", 255: "ANY", 257: "CAA"}

_n = [0]
_first = [False]


def log(m):
    sys.stderr.write("[%s] %s\n" % (time.strftime("%F %T"), m))
    sys.stderr.flush()


def find_iface_by_ip(ip):
    """按 IP 找网卡名（读 /sys 与 ioctl，不用外部命令）。"""
    import fcntl
    for name in os.listdir("/sys/class/net"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            r = fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", name[:15].encode()))
            addr = socket.inet_ntoa(r[20:24])
            s.close()
        except Exception:
            continue
        if addr == ip:
            return name
    return None


def name_at(msg, o):
    labels = []
    jumps = False
    start = o
    while True:
        if o >= len(msg):
            raise ValueError("name out of range")
        l = msg[o]
        if l == 0:
            o += 1
            break
        if l & 0xC0 == 0xC0:
            if o + 1 >= len(msg):
                raise ValueError("ptr out of range")
            o = ((l & 0x3F) << 8) | msg[o + 1]
            if not jumps:
                start = o + 2
                jumps = True
            continue
        o += 1
        labels.append(msg[o:o + l].decode("utf-8", "replace"))
        o += l
    return ".".join(labels), (start if jumps else o)


def parse_query(msg):
    """返回 (qname, qt, edns, do, udp_size, mixed_case)。"""
    if len(msg) < 12:
        raise ValueError("short")
    qd = struct.unpack_from("!H", msg, 4)[0]
    ar = struct.unpack_from("!H", msg, 10)[0]
    o = 12
    qname = ""
    qt = "?"
    if qd:
        qname, o = name_at(msg, o)
        if o + 4 > len(msg):
            raise ValueError("question truncated")
        qtype_raw = struct.unpack_from("!H", msg, o)[0]
        qt = QT.get(qtype_raw, "other")
        o += 4  # qtype + qclass
    letters = [ch for ch in qname if ch.isalpha()]
    mixed = bool(letters) and any(c.islower() for c in letters) and any(c.isupper() for c in letters)
    edns = {}
    do = 0
    udp_size = None
    for _ in range(ar):
        if o + 1 > len(msg):
            break
        _rr, o = name_at(msg, o)
        if o + 10 > len(msg):
            break
        rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", msg, o)
        o += 10
        rdata = msg[o:o + rdlen]
        o += rdlen
        if rtype != 41:
            continue
        udp_size = rclass
        do = 1 if (ttl & 0x8000) else 0
        p = 0
        while p + 4 <= len(rdata):
            code, clen = struct.unpack_from("!HH", rdata, p)
            p += 4
            val = rdata[p:p + clen]
            p += clen
            if code == 10 and clen >= 8:
                edns["cookie_client"] = val[:8].hex()
            elif code == 8 and clen >= 4:
                fam = struct.unpack_from("!H", val, 0)[0]
                slen = val[2]
                addr = val[4:]
                if fam == 1 and len(addr) >= 4:
                    edns["ecs"] = "%d.%d.%d.%d/%d" % (addr[0], addr[1], addr[2], addr[3], slen)
                elif fam == 2 and len(addr) >= 16:
                    edns["ecs"] = "v6/%d" % slen
                else:
                    edns["ecs"] = "fam%d/%d" % (fam, slen)
            elif code == 12:
                edns["padding"] = clen
    return qname, qt, edns, do, udp_size, mixed


def emit(f, ip, sport, qname, qt, edns, do, udp_size, mixed, t):
    rec = {"ev": "q", "ip": ip, "sport": sport, "t": int(t), "tf": round(t, 3),
           "qname": qname, "qt": qt, "edns": edns, "do": do,
           "udp_size": udp_size, "mixed_case": mixed, "cookie_echo": False}
    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    _n[0] += 1
    if _n[0] % 200 == 0:
        f.flush()
        log("已写 %d 条查询" % _n[0])


def main():
    iface = IFACE
    if iface in ("auto", ""):
        iface = find_iface_by_ip(GW)
        if not iface:
            log("找不到 IP=%s 的网卡，退出" % GW)
            sys.exit(1)
    log("启动：iface=%s dst=%s:%d spool=%s" % (iface, DST, DPORT, SPOOL))
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind((iface, 0))
    f = open(SPOOL, "a", buffering=1)
    bufs = {}
    while True:
        try:
            pkt = s.recv(65535)
        except Exception as e:
            log("recv 异常: %s" % e)
            time.sleep(0.5)
            continue
        t = time.time()
        if len(pkt) < 54:
            continue
        if struct.unpack_from("!H", pkt, 12)[0] != 0x0800:
            continue
        ip = pkt[14:]
        if (ip[0] >> 4) != 4:
            continue
        ihl = (ip[0] & 0x0F) * 4
        if ip[9] != 6:
            continue
        tot = struct.unpack_from("!H", ip, 2)[0]
        tcp = ip[ihl:tot]
        if len(tcp) < 20:
            continue
        sport, dport, seq = struct.unpack_from("!HHI", tcp, 0)
        if dport != DPORT:
            continue
        sip = socket.inet_ntoa(ip[12:16])
        dip = socket.inet_ntoa(ip[16:20])
        if DST and dip != DST:
            continue
        doff = (tcp[12] >> 4) * 4
        payload = tcp[doff:]
        if not payload:
            continue
        if not _first[0]:
            _first[0] = True
            log("首个明文包：%s:%d -> %s:%d payload=%d" % (sip, sport, dip, dport, len(payload)))
        b = bufs.get(sport)
        if b is None:
            bufs[sport] = [seq + len(payload), bytearray(payload)]
        else:
            nxt, buf = b
            if seq == nxt:
                buf.extend(payload)
                b[0] = seq + len(payload)
            elif seq + len(payload) <= nxt:
                continue
            else:
                b[0] = seq + len(payload)
                b[1] = bytearray(payload)
        nxt, buf = bufs[sport]
        while len(buf) >= 2:
            ln = struct.unpack_from("!H", buf, 0)[0]
            if ln == 0 or ln > MAXBUF:
                del buf[:]
                break
            if len(buf) < 2 + ln:
                break
            msg = bytes(buf[2:2 + ln])
            del buf[:2 + ln]
            try:
                qname, qt, edns, do, udp_size, mixed = parse_query(msg)
            except Exception:
                continue
            if qname:
                emit(f, sip, sport, qname, qt, edns, do, udp_size, mixed, t)
        if len(bufs) > BUF_MAX:
            for k in list(bufs.keys())[:len(bufs) - BUF_MAX]:
                bufs.pop(k, None)


if __name__ == "__main__":
    main()
