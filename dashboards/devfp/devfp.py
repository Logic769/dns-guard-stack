#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""devfp —— DoT/DoH 设备指纹看板（服务器侧采集后端）

三路采集，全部只读、不改动任何 DNS 链路：
  1) 被动抓包（AF_PACKET，eth0，仅处理 tcp dport 853/444/443 与回包）
     - TLS ClientHello → JA3 / JA4 / SNI / ALPN / 版本 / 密码套件 / 扩展 / 曲线 / 签名算法 / GREASE
     - TLS ServerHello → 协商版本 / 套件 / ALPN / 证书字节数
     - TCP SYN → p0f 式指纹（TTL 跳数、窗口、MSS、WScale、SACK、TS、选项顺序、DF、IP-ID）
     - 每连接字节/包/时长；QUIC(UDP 853/444) 仅计数
  2) AdGuardHome querylog.json 增量 tail → 每设备查询行为（协议 dot/doh、qtype 分布、ECS、
     过滤命中、上游、时延、Top 域名、最近查询）
  3) nginx DoH 访问日志增量 tail（log_format 由 nginx 配置提供）→ HTTP 层指纹
     （UA、Accept 系、HTTP 版本、方法、TLS 套件/曲线/ALPN/session 复用）
  4) 路由侧 agent 通过 POST /api/router 推送家庭内网设备（MAC/IP/主机名/厂商/无线/行为）

仅标准库（服务器是 Python 3.6）。监听 127.0.0.1:8789，由 nginx 反代到 /devices/。
"""

from __future__ import print_function

import base64
import calendar
import hashlib
import json
import os
import re
import socket
import socketserver
import sqlite3
import struct
import sys
import threading
import time
import traceback

try:
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import urlparse, parse_qs, unquote
except ImportError:  # pragma: no cover
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
    from urlparse import urlparse, parse_qs
    from urllib import unquote

HERE = os.path.dirname(os.path.abspath(__file__))

DEFAULT_CFG = {
    "iface": "eth0",
    "http_host": "127.0.0.1",
    "http_port": 8789,
    "db": os.path.join(HERE, "data.db"),
    "ui": os.path.join(HERE, "index.html"),
    "state": os.path.join(HERE, "state.json"),
    "agh_querylog": "/opt/adgh/work/data/querylog.json",
    "doh_log": "/www/wwwlogs/doh-devices.log",
    "resolver": "127.0.0.1:5353",
    # 本机 unbound 对 TXT 查询不回（本地策略所致），ASN/国家走公网解析器兜底
    "asn_resolvers": ["8.8.8.8:53", "119.29.29.29:53", "127.0.0.1:5353"],
    "sniff": True,
    "tls_ports": [853, 444, 443],
    "dns_ports": [853, 444],          # 认定为 DNS-over-TLS/HTTPS 直连端口
    "web_port": 443,                  # 经 nginx 的 DoH 端口（需与访问日志/路径联合认定）
    "local_nets": ["127.0.0.0/8", "172.17.0.0/18", "172.18.0.0/16", "172.19.0.0/16"],
    "conn_idle_flush": 25.0,
    "sock_rcvbuf": 8388608,
    # nDPI：定时抓一小段包做协议/分类/风险判定（离线分析，不常驻）
    "ndpi_enable": True, "ndpi_bin": "/opt/ndpi/ndpiReader", "ndpi_interval": 1800,
    "ndpi_first_delay": 300, "ndpi_capture_sec": 15, "ndpi_max_packets": 3000,
    "ndpi_ports": "853 443 444",
    "max_conns": 8192,
    "dns_recent_rows": 40000,
    # 2026-10-05：原来 2160h(90 天)。按实测速率(≈542 连接/小时 × ~2.3KB/行)，90 天 conns 会到
    # ~117 万行 ≈ 2.7GB，doh_requests 更多。改为 7 天(连接)/14 天(DoH 请求)：稳定在 ~300MB。
    "keep_conns_hours": 168,
    "keep_doh_hours": 336,       # 14 天
    "enrich": True,
    "enrich_interval": 120,
}

CFG = dict(DEFAULT_CFG)


def load_cfg():
    p = os.path.join(HERE, "config.json")
    if os.path.exists(p):
        try:
            with open(p) as f:
                CFG.update(json.load(f))
        except Exception as e:
            log("config.json 解析失败，用默认值: %s" % e)


def log(msg):
    sys.stdout.write("[%s] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()), msg))
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------

GREASE = set([0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
              0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA])


def is_grease(v):
    return v in GREASE


def _u8(b, o):
    return b[o]


def _u16(b, o):
    return (b[o] << 8) | b[o + 1]


def _u24(b, o):
    return (b[o] << 16) | (b[o + 1] << 8) | b[o + 2]


def _u32(b, o):
    return (b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]


def ip2int(ip):
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except Exception:
        return None


_NET_CACHE = {}


def in_nets(ip, nets):
    key = (ip, tuple(nets))
    if key in _NET_CACHE:
        return _NET_CACHE[key]
    v = ip2int(ip)
    r = False
    if v is not None:
        for n in nets:
            try:
                a, bits = n.split("/")
                m = (0xFFFFFFFF << (32 - int(bits))) & 0xFFFFFFFF
                if (v & m) == (ip2int(a) & m):
                    r = True
                    break
            except Exception:
                continue
    if len(_NET_CACHE) < 5000:
        _NET_CACHE[key] = r
    return r


def is_local(ip):
    return in_nets(ip, CFG["local_nets"])


def hops(ttl):
    """按常规初始 TTL 阶梯（64 / 128 / 255）推算跳数。"""
    if ttl <= 0:
        return None
    if ttl <= 64:
        return 64 - ttl, 64
    if ttl <= 128:
        return 128 - ttl, 128
    return 255 - ttl, 255


def now():
    return int(time.time())


def jdump(o):
    return json.dumps(o, ensure_ascii=False, separators=(",", ":"))


def jload(s, default=None):
    if not s:
        return default
    try:
        return json.loads(s)
    except Exception:
        return default


def sha1(s):
    return hashlib.sha1(s.encode("utf-8", "replace")).hexdigest()


def trim(s, n):
    s = s if isinstance(s, str) else str(s)
    return s if len(s) <= n else s[: n - 1] + "…"


# ---------------------------------------------------------------------------
# TLS 解析
# ---------------------------------------------------------------------------

_TLS_VERSIONS = {
    0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3",
    0x0002: "s2", 0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3",
}
_TLS_VER_NAME = {
    0x0304: "TLS1.3", 0x0303: "TLS1.2", 0x0302: "TLS1.1", 0x0301: "TLS1.0",
    0x0300: "SSL3.0", 0x0002: "SSL2.0",
}
_CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256", 0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256", 0xC02B: "ECDHE_ECDSA_AES128_GCM_SHA256",
    0xC02C: "ECDHE_ECDSA_AES256_GCM_SHA384", 0xC02F: "ECDHE_RSA_AES128_GCM_SHA256",
    0xC030: "ECDHE_RSA_AES256_GCM_SHA384", 0xCCA8: "ECDHE_RSA_CHACHA20_POLY1305",
    0xCCA9: "ECDHE_ECDSA_CHACHA20_POLY1305", 0x009C: "RSA_AES128_GCM_SHA256",
    0x009D: "RSA_AES256_GCM_SHA384", 0x002F: "RSA_AES128_SHA", 0x0035: "RSA_AES256_SHA",
    0xC013: "ECDHE_RSA_AES128_SHA", 0xC014: "ECDHE_RSA_AES256_SHA",
}
_EXT_NAMES = {
    0x0000: "server_name", 0x0001: "max_fragment_length", 0x0005: "status_request",
    0x000A: "supported_groups", 0x000B: "ec_point_formats", 0x000D: "signature_algorithms",
    0x0010: "ALPN", 0x0012: "signed_certificate_timestamp", 0x0015: "padding",
    0x0016: "encrypt_then_mac", 0x0017: "extended_master_secret", 0x001B: "certificate_authorities",
    0x001C: "record_size_limit", 0x0021: "padding(0x21)", 0x0022: "delegated_credentials",
    0x0023: "extended_master_secret(0x23)", 0x0029: "pre_shared_key", 0x002A: "early_data",
    0x002B: "supported_versions", 0x002D: "psk_key_exchange_modes", 0x0033: "key_share",
    0x0039: "compress_certificate", 0x002F: "session_ticket?", 0x5500: "compress_certificate(5500)",
    0x4469: "application_settings(ALPS)", 0xFF01: "renegotiation_info",
    0x0011: "application_layer_protocol_settings?", 0x0020: "padding?", 0x0028: "record_size_limit?",
}
_GROUP_NAMES = {
    0x001D: "x25519", 0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1",
    0x001E: "x448", 0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x0102: "ffdhe4096",
    0x0011: "secp256r1?", 0x0A0A: "GREASE", 0x6399: "x25519kyber768", 0x639A: "x25519kyber768draft00",
    0x11EC: "x25519mlkem768", 0x0808: "x25519?", 0x0029: "x25519?", 0x002A: "x448?",
}
_ALPN_NAMES = {"h2": "HTTP/2", "h3": "HTTP/3", "http/1.1": "HTTP/1.1", "dot": "DoT", "doq": "DoQ",
               "http/1.0": "HTTP/1.0", "acme-tls/1": "ACME-TLS"}


def _extension_desc(et, data):
    try:
        if et == 0x0000 and len(data) >= 2:
            l = _u16(data, 0)
            return data[2:2 + l].decode("idna", "replace")
        if et == 0x000A:
            out = []
            n = _u16(data, 0) // 2
            for i in range(n):
                g = _u16(data, 2 + i * 2)
                if is_grease(g):
                    continue
                out.append(_GROUP_NAMES.get(g, "0x%04x" % g))
            return out
        if et == 0x000B:
            return list(data[1:])
        if et == 0x000D:
            out = []
            n = _u16(data, 0) // 2
            for i in range(n):
                s = _u16(data, 2 + i * 2)
                if is_grease(s):
                    continue
                out.append("0x%04x" % s)
            return out
        if et == 0x0010:
            out = []
            if len(data) >= 2:
                n = _u16(data, 0)
                o = 2
                end = 2 + n
                while o < len(data) and o < end:
                    l = data[o]
                    proto = data[o + 1:o + 1 + l]
                    try:
                        out.append(proto.decode("ascii"))
                    except Exception:
                        out.append(proto.hex())
                    o += 1 + l
            return out
        if et == 0x002B:
            out = []
            if len(data) >= 1:
                n = data[0]
                for i in range(n):
                    if 1 + i * 2 + 1 < len(data):
                        v = _u16(data, 1 + i * 2)
                        if is_grease(v):
                            continue
                        out.append(_TLS_VER_NAME.get(v, "0x%04x" % v))
            return out
        if et == 0x002D:
            return list(data[1:])
        if et == 0x0033:
            out = []
            if len(data) >= 2:
                o = 2
                while o + 4 <= len(data):
                    g = _u16(data, o)
                    kl = _u16(data, o + 2)
                    if not is_grease(g):
                        out.append(_GROUP_NAMES.get(g, "0x%04x" % g))
                    o += 4 + kl
            return out
        if et == 0x0001 and len(data) >= 1:
            return data[0]
        if et in (0x0015, 0x0021, 0x0020):
            return len(data)
    except Exception:
        return None
    return None


def parse_client_hello(payload):
    """payload = TLS record 起始字节。返回 (info, consumed_record_bytes) 或 (None, 0)。"""
    if len(payload) < 6 or payload[0] != 0x16:
        return None, 0
    rec_len = _u16(payload, 3)
    total = 5 + rec_len
    if len(payload) < total:
        return None, total          # 需要更多字节（分片）
    hs = payload[5:total]
    if len(hs) < 4 or hs[0] != 0x01:
        return None, total
    body = hs[4:]
    try:
        legacy_ver = _u16(body, 0)
        o = 2 + 32
        sid_len = body[o]; o += 1 + sid_len
        cs_len = _u16(body, o); o += 2
        ciphers = [_u16(body, o + i * 2) for i in range(cs_len // 2)]
        o += cs_len
        comp_len = body[o]; o += 1
        comps = list(body[o:o + comp_len]); o += comp_len
        exts = []
        sig_algs = []
        if o + 2 <= len(body):
            exts_len = _u16(body, o); o += 2
            end = o + exts_len
            while o + 4 <= len(body) and o < end:
                et = _u16(body, o); el = _u16(body, o + 2)
                ed = body[o + 4:o + 4 + el]
                exts.append((et, ed))
                if et == 0x000D:
                    try:
                        n = _u16(ed, 0) // 2
                        sig_algs = [_u16(ed, 2 + i * 2) for i in range(n)]
                    except Exception:
                        pass
                o += 4 + el
    except Exception:
        return None, total

    ci = [c for c in ciphers if not is_grease(c)]
    ei = [e for e, _ in exts if not is_grease(e)]

    # 版本：优先 supported_versions 的最高值
    ver = legacy_ver
    for et, ed in exts:
        if et == 0x002B and ed:
            n = ed[0]
            vals = [_u16(ed, 1 + i * 2) for i in range(n) if 1 + i * 2 + 1 < len(ed)]
            vals = [v for v in vals if not is_grease(v)]
            if vals:
                ver = max(vals)
    ver_code = _TLS_VERSIONS.get(ver, "00")

    sni = None
    alpn = []
    curves = []
    for et, ed in exts:
        if et == 0x0000 and len(ed) >= 5:
            try:
                nl = _u16(ed, 3)
                sni = ed[5:5 + nl].decode("idna", "replace")
            except Exception:
                try:
                    sni = ed[5:5 + _u16(ed, 3)].decode("utf-8", "replace")
                except Exception:
                    sni = None
        elif et == 0x0010 and len(ed) >= 2:
            n = _u16(ed, 0); p = 2; stop = 2 + n
            while p < len(ed) and p < stop:
                l = ed[p]
                try:
                    alpn.append(ed[p + 1:p + 1 + l].decode("ascii"))
                except Exception:
                    alpn.append(ed[p + 1:p + 1 + l].hex())
                p += 1 + l
        elif et == 0x000A:
            n = _u16(ed, 0) // 2
            for i in range(n):
                g = _u16(ed, 2 + i * 2)
                if not is_grease(g):
                    curves.append(g)

    # JA3: version,ciphers,extensions,curves,ec_point_formats
    # 注意：JA3 的 version 用 ClientHello 的 legacy_version（不是 supported_versions）
    ecpf = [0]
    for et, ed in exts:
        if et == 0x000B and ed:
            ecpf = list(ed[1:])
            break
    ja3_str = "%d,%s,%s,%s,%s" % (
        legacy_ver, "-".join(str(c) for c in ci), "-".join(str(e) for e in ei),
        "-".join(str(c) for c in curves), "-".join(str(p) for p in ecpf))
    ja3 = hashlib.md5(ja3_str.encode()).hexdigest()

    # JA4
    alpn_a = first_last_alpn(alpn)
    ja4_a = "t%s%s%02d%02d%s" % (ver_code, "d" if sni else "i",
                                 min(len(ci), 99), min(len(ei), 99), alpn_a)
    if ci:
        sorted_c = sorted("%04x" % c for c in ci)
        ja4_b = hashlib.sha256(",".join(sorted_c).encode()).hexdigest()[:12]
    else:
        ja4_b = "000000000000"
    ext_sorted = sorted("%04x" % e for e, _ in exts
                        if not is_grease(e) and e not in (0x0000, 0x0010))
    sigs = [s for s in sig_algs if not is_grease(s)]
    if ext_sorted or sigs:
        s = ",".join(ext_sorted)
        if sigs:
            s += "_" + ",".join("%04x" % x for x in sigs)
        ja4_c = hashlib.sha256(s.encode()).hexdigest()[:12]
    else:
        ja4_c = "000000000000"
    ja4 = "%s_%s_%s" % (ja4_a, ja4_b, ja4_c)
    ja4_ro = "%s_%s_%s_%s" % (
        ja4_a,
        ",".join("%04x" % c for c in ciphers if not is_grease(c)) or "0",
        ",".join("%04x" % e for e, _ in exts if not is_grease(e)) or "0",
        ",".join("%04x" % x for x in sigs) or "0")

    info = {
        "kind": "client_hello",
        "legacy_version": _TLS_VER_NAME.get(legacy_ver, "0x%04x" % legacy_ver),
        "version": _TLS_VER_NAME.get(ver, "0x%04x" % ver),
        "version_code": ver_code,
        "sni": sni,
        "alpn": alpn,
        "ciphers": ["0x%04x %s" % (c, _CIPHER_NAMES.get(c, "")) for c in ciphers],
        "cipher_count": len(ci),
        "extensions": [{"type": "0x%04x" % e, "name": _EXT_NAMES.get(e, ""),
                        "len": len(d),
                        "value": _extension_desc(e, d)} for e, d in exts],
        "extension_count": len(ei),
        "curves": [_GROUP_NAMES.get(c, "0x%04x" % c) for c in curves],
        "sig_algs": ["0x%04x" % s for s in sig_algs],
        "compression": comps,
        "session_id_len": sid_len,
        "grease_ciphers": len(ciphers) - len(ci),
        "grease_exts": len(exts) - len(ei),
        "record_len": rec_len,
        "ja3": ja3,
        "ja3_str": ja3_str,
        "ja4": ja4,
        "ja4_a": ja4_a,
        "ja4_b": ja4_b,
        "ja4_c": ja4_c,
        "ja4_o": ja4_ro,
    }
    return info, total


def first_last_alpn(alpn):
    """JA4_a 的 ALPN 两位：首尾 ASCII 字母数字，否则用十六进制首尾。"""
    if not alpn:
        return "00"
    v = alpn[0]
    if not v:
        return "00"
    b = v.encode("utf-8", "replace")
    out = []
    for by in (b[0], b[-1]):
        if 0x30 <= by <= 0x39 or 0x41 <= by <= 0x5A or 0x61 <= by <= 0x7A:
            out.append(chr(by))
        else:
            out.append("%02x" % by)
    return "".join(out)


def parse_server_hello(payload):
    if len(payload) < 6 or payload[0] != 0x16:
        return None, 0
    rec_len = _u16(payload, 3)
    total = 5 + rec_len
    if len(payload) < total:
        return None, total
    hs = payload[5:total]
    if len(hs) < 4 or hs[0] != 0x02:
        return None, total
    body = hs[4:]
    out = {}
    try:
        ver = _u16(body, 0)
        o = 2 + 32
        sid_len = body[o]; o += 1 + sid_len
        cs = _u16(body, o); o += 2
        comp = body[o]; o += 1
        out["version"] = _TLS_VER_NAME.get(ver, "0x%04x" % ver)
        out["cipher"] = "0x%04x %s" % (cs, _CIPHER_NAMES.get(cs, ""))
        out["compression"] = comp
        out["session_id_len"] = sid_len
        if o + 2 <= len(body):
            exts_len = _u16(body, o); o += 2
            end = o + exts_len
            exts = []
            while o + 4 <= len(body) and o < end:
                et = _u16(body, o); el = _u16(body, o + 2)
                ed = body[o + 4:o + 4 + el]
                exts.append((et, ed))
                if et == 0x002B and len(ed) >= 2:
                    v = _u16(ed, 0)
                    out["version"] = _TLS_VER_NAME.get(v, out["version"])
                if et == 0x0010 and len(ed) >= 3:
                    l = ed[0]
                    try:
                        out["alpn"] = ed[1:1 + l].decode("ascii")
                    except Exception:
                        pass
                if et == 0x0029:
                    out["resumed_psk"] = True
                o += 4 + el
            out["extensions"] = ["0x%04x" % e for e, _ in exts]
    except Exception:
        return out or None, total
    return out, total


def parse_tls_cert_size(payload):
    """粗略统计 Certificate 消息里的证书总字节数。"""
    if len(payload) < 6 or payload[0] != 0x16:
        return None
    rec_len = _u16(payload, 3)
    total = 5 + rec_len
    if len(payload) < total:
        return None
    hs = payload[5:total]
    if len(hs) < 4 or hs[0] != 0x0B:
        return None
    try:
        body = hs[4:]
        o = 0
        if len(body) >= 4 and hs[0] == 0x0B:
            # TLS1.3 有 certificate_request_context
            cl = body[0]
            o = 1 + cl
        total_len = _u24(body, o); o += 3
        n = 0
        end = o + total_len
        while o + 3 <= len(body) and o < end:
            l = _u24(body, o); o += 3 + l
            n += 1
        return {"cert_bytes": total_len, "cert_count": n}
    except Exception:
        return None


# ---------------------------------------------------------------------------
# TCP / IP 指纹
# ---------------------------------------------------------------------------

def parse_tcp_options(o):
    order = []
    kinds = []
    mss = ws = 0
    sack = ts = 0
    tsval = tsecr = None
    i = 0
    while i < len(o):
        k = o[i]
        if k == 0:
            while i < len(o) and o[i] == 0:      # 连续 0x00 都是 EOL 选项（含尾部填充）
                order.append("EOL")
                kinds.append(0)
                i += 1
            break
        if k == 1:
            order.append("NOP")
            kinds.append(1)
            i += 1
            continue
        if i + 1 >= len(o):
            break
        l = o[i + 1]
        if l < 2 or i + l > len(o):
            break
        if k == 2:
            mss = _u16(o, i + 2)
            order.append("MSS")
        elif k == 3:
            ws = o[i + 2] if i + 2 < len(o) else 0
            order.append("WS")
        elif k == 4:
            sack = 1
            order.append("SACK")
        elif k == 8:
            ts = 1
            if i + 10 <= len(o):
                tsval = _u32(o, i + 2)     # 客户端 TCP 时间戳时钟（毫秒）
                tsecr = _u32(o, i + 6)
            order.append("TS")
        elif k == 5:
            order.append("SOK")
        elif k == 30:
            order.append("MPTCP")
        else:
            order.append(str(k))
        kinds.append(k)
        i += l
    return {"order": order, "kinds": kinds, "mss": mss, "ws": ws, "sack": sack,
            "ts": ts, "tsval": tsval, "tsecr": tsecr, "raw": o.hex()}


_OS_TABLE = [
    # (条件函数, OS 猜测, 置信度)
    (lambda f: f["init_ttl"] == 128 and f["win"] == 65535 and f["ts"] == 0 and f["sack"] == 1,
     "Windows 7/8/10/11", "中"),
    (lambda f: f["init_ttl"] == 128 and f["ts"] == 1,
     "Windows Server / 旧版 Windows", "低"),
    (lambda f: f["init_ttl"] == 128 and f["win"] == 8192,
     "Windows (老版本)", "低"),
    (lambda f: f["init_ttl"] == 64 and f["order"][:4] == ["MSS", "NOP", "WS", "NOP"]
     and f["ws"] == 6,
     "Apple iOS / macOS", "中"),
    (lambda f: f["init_ttl"] == 64 and f["order"][:4] == ["MSS", "NOP", "SACK", "WS"],
     "Apple iOS / macOS", "中"),
    (lambda f: f["init_ttl"] == 64 and f["ws"] == 0 and f["win"] == 65535,
     "嵌入式 Linux（BusyBox/uClibc，如路由器）", "中"),
    (lambda f: f["init_ttl"] == 64 and f["win"] in (29200, 28960, 64240) and f["sack"] == 1,
     "Linux (Android/桌面)", "中"),
    (lambda f: f["init_ttl"] == 64 and f["sack"] == 1 and f["ts"] == 1,
     "Linux 系 (Android/OpenWrt/桌面)", "低"),
    (lambda f: f["init_ttl"] == 255,
     "网络设备 / 扫描器 / 中间盒", "低"),
]


def tcp_fingerprint(ttl, win, opts, ip_id, df, mss_pkt):
    h = hops(ttl)
    init_ttl = h[1] if h else ttl
    kinds = [k for k in opts.get("kinds", [])]
    while kinds and kinds[-1] == 0:          # 去掉尾部 EOL 填充（官方示例不含）
        kinds.pop()
    ja4t = "%d_%s_%d_%d" % (win, "-".join(str(k) for k in kinds), opts["mss"], opts["ws"])
    f = {
        "ja4t": ja4t,
        "ttl": ttl, "init_ttl": init_ttl, "hops": h[0] if h else None,
        "win": win, "mss": opts["mss"], "ws": opts["ws"], "sack": opts["sack"],
        "ts": opts["ts"], "tsval": opts.get("tsval"), "order": opts["order"],
        "opts_raw": opts["raw"], "ip_id": ip_id, "df": df,
    }
    guess, conf = None, None
    for cond, name, c in _OS_TABLE:
        try:
            if cond(f):
                guess, conf = name, c
                break
        except Exception:
            continue
    f["os_guess"] = guess
    f["os_confidence"] = conf
    f["sig"] = "%s:%s:%s:%s:%s:%s:%s" % (
        init_ttl, win, opts["mss"], opts["ws"], opts["sack"], opts["ts"],
        ",".join(opts["order"]))
    # JA4T 风格：window_options_mss_windowscale（选项按类别号顺序）
    f["ja4t_like"] = "%d_%s_%d_%s" % (
        win, "-".join(str(k) for k in opts.get("kinds", [])) or "0",
        opts["mss"], ("%02d" % opts["ws"]) if opts["ws"] == 0 else str(opts["ws"]))
    return f


def parse_packet(buf, linktype=1):
    """返回 dict（以太网/IPv4/IPv6 + TCP/UDP 概要）或 None。linktype 见 pcap LINKTYPE_*。"""
    if linktype == 113:            # Linux cooked (SLL)
        if len(buf) < 16:
            return None
        et = _u16(buf, 14)
        off = 16
    elif linktype == 276:          # Linux cooked v2 (SLL2)
        if len(buf) < 20:
            return None
        et = _u16(buf, 0)
        off = 20
    elif linktype == 101:          # raw IP
        if len(buf) < 20:
            return None
        v = buf[0] >> 4
        et = 0x0800 if v == 4 else (0x86DD if v == 6 else 0)
        off = 0
    else:
        if len(buf) < 34:
            return None
        et = _u16(buf, 12)
        off = 14
        while et in (0x8100, 0x88A8, 0x9100):
            if len(buf) < off + 4:
                return None
            et = _u16(buf, off + 2)
            off += 4
    if et == 0x0800:
        ipoff = off
        if len(buf) < ipoff + 20:
            return None
        ihl = (buf[ipoff] & 0x0F) * 4
        proto = buf[ipoff + 9]
        ttl = buf[ipoff + 8]
        ip_id = _u16(buf, ipoff + 4)
        frag = _u16(buf, ipoff + 6)
        df = 1 if (frag & 0x4000) else 0
        if frag & 0x1FFF:
            return None
        total_len = _u16(buf, ipoff + 2)
        src = socket.inet_ntoa(buf[ipoff + 12:ipoff + 16])
        dst = socket.inet_ntoa(buf[ipoff + 16:ipoff + 20])
        l4 = ipoff + ihl
        fam = 4
        end = ipoff + (total_len if total_len else len(buf) - ipoff)
    elif et == 0x86DD:
        ipoff = off
        if len(buf) < ipoff + 40:
            return None
        proto = buf[ipoff + 6]
        ttl = buf[ipoff + 7]
        df = 0
        ip_id = 0
        payload_len = _u16(buf, ipoff + 4)
        src = socket.inet_ntop(socket.AF_INET6, buf[ipoff + 8:ipoff + 24])
        dst = socket.inet_ntop(socket.AF_INET6, buf[ipoff + 24:ipoff + 40])
        l4 = ipoff + 40
        fam = 6
        end = ipoff + 40 + payload_len
    else:
        return None
    if len(buf) < l4 + 8:
        return None
    if proto == 6:
        sport = _u16(buf, l4)
        dport = _u16(buf, l4 + 2)
        seq = _u32(buf, l4 + 4)
        ack = _u32(buf, l4 + 8)
        doff = (buf[l4 + 12] >> 4) * 4
        flags = buf[l4 + 13]
        win = _u16(buf, l4 + 14)
        if doff < 20 or len(buf) < l4 + doff:
            return None
        optb = buf[l4 + 20:l4 + doff]
        payload = buf[l4 + doff:min(end, len(buf))]
        return {"fam": fam, "proto": "tcp", "src": src, "dst": dst, "ttl": ttl,
                "ip_id": ip_id, "df": df, "sport": sport, "dport": dport,
                "seq": seq, "ack": ack, "flags": flags, "win": win,
                "opts": parse_tcp_options(optb), "payload": payload,
                "plen": len(payload)}
    if proto == 17:
        sport = _u16(buf, l4)
        dport = _u16(buf, l4 + 2)
        payload = buf[l4 + 8:min(end, len(buf))]
        return {"fam": fam, "proto": "udp", "src": src, "dst": dst, "ttl": ttl,
                "ip_id": ip_id, "df": df, "sport": sport, "dport": dport,
                "payload": payload, "plen": len(payload), "flags": 0, "win": 0}
    return None


# ---------------------------------------------------------------------------
# 数据库
# ---------------------------------------------------------------------------

DB_LOCK = threading.RLock()
_CONN = None
_DIRTY = [False]

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices(
  id INTEGER PRIMARY KEY,
  fp_key TEXT UNIQUE NOT NULL,
  source TEXT DEFAULT 'server',
  label TEXT, note TEXT, tags TEXT,
  first_seen INTEGER, last_seen INTEGER,
  src_ips TEXT, protos TEXT, variants TEXT,
  ja3 TEXT, ja4 TEXT, ja3_str TEXT, ja4_a TEXT, ja4_b TEXT, ja4_c TEXT, ja4_o TEXT,
  tls_json TEXT, tcp_json TEXT, http_json TEXT, tcp_sig TEXT,
  ua TEXT, http_ver TEXT, sni TEXT, alpn TEXT,
  os_guess TEXT, os_confidence TEXT, app_guess TEXT,
  vendor TEXT, device_class TEXT, role TEXT, confidence TEXT,
  infer_ts INTEGER, infer_json TEXT, top_domains TEXT,
  uptime_s INTEGER, skew_ppm INTEGER, ipid_class TEXT, retrans_rate REAL,
  os_version_hint TEXT, model TEXT, edns_profile TEXT, dot_queries INTEGER, behavior TEXT, behavior_json TEXT,
  dns_cookie TEXT, ddr_count INTEGER, cluster_id INTEGER, probe_class TEXT,
  asn TEXT, as_org TEXT, country TEXT, rdns TEXT, ip_prefix TEXT,
  conn_count INTEGER DEFAULT 0, bytes_in INTEGER DEFAULT 0, bytes_out INTEGER DEFAULT 0,
  linked_to INTEGER,
  obs_count INTEGER DEFAULT 0, updated INTEGER
);
CREATE TABLE IF NOT EXISTS conns(
  id INTEGER PRIMARY KEY,
  device_id INTEGER, ts INTEGER, end_ts INTEGER, src_ip TEXT, sport INTEGER,
  dport INTEGER, kind TEXT, ja3 TEXT, ja4 TEXT, tls_ver TEXT, cipher TEXT,
  alpn TEXT, sni TEXT, resumed INTEGER, cert_bytes INTEGER, cert_count INTEGER,
  in_bytes INTEGER, out_bytes INTEGER, in_pkts INTEGER, out_pkts INTEGER,
  duration_ms INTEGER, rtt_ms REAL, probe INTEGER DEFAULT 0,
  req_rec INTEGER, resp_rec INTEGER, resp_bytes INTEGER, q_est INTEGER, q_rtt_ms REAL,
  partial INTEGER DEFAULT 0, tsval INTEGER, retrans INTEGER DEFAULT 0, skew_ppm INTEGER,
  psk INTEGER, ticket_age INTEGER, psk_ident TEXT,
  ja4t TEXT, ja4l_c TEXT, ja4l_s TEXT,
  tcp_sig TEXT, tcp_json TEXT, tls_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_conns_ts ON conns(ts);
CREATE INDEX IF NOT EXISTS idx_conns_dev ON conns(device_id, ts);
CREATE INDEX IF NOT EXISTS idx_conns_ip ON conns(src_ip, ts);
CREATE TABLE IF NOT EXISTS dns_hour(
  id INTEGER PRIMARY KEY, device_id INTEGER, ip TEXT, hour INTEGER, proto TEXT,
  n INTEGER DEFAULT 0, nx INTEGER DEFAULT 0, filtered INTEGER DEFAULT 0,
  a INTEGER DEFAULT 0, aaaa INTEGER DEFAULT 0, https INTEGER DEFAULT 0,
  ptr INTEGER DEFAULT 0, other INTEGER DEFAULT 0,
  sum_ms INTEGER DEFAULT 0, max_ms INTEGER DEFAULT 0,
  upstreams TEXT, top_json TEXT, ecs_json TEXT, UNIQUE(ip, hour, proto)
);
CREATE INDEX IF NOT EXISTS idx_dns_hour_h ON dns_hour(hour);
CREATE TABLE IF NOT EXISTS dns_recent(
  id INTEGER PRIMARY KEY, ts INTEGER, ip TEXT, qh TEXT, qt TEXT, cp TEXT,
  filtered INTEGER, elapsed_ms INTEGER, upstream TEXT, answer TEXT, device_id INTEGER,
  match_ms INTEGER, src TEXT, sport INTEGER, do_bit INTEGER, udp_size INTEGER,
  mixed INTEGER, edns TEXT, rcode INTEGER, rule TEXT
);
CREATE TABLE IF NOT EXISTS clusters(
  id INTEGER PRIMARY KEY, name TEXT, member_ids TEXT, n_members INTEGER, n_conns INTEGER,
  ips TEXT, evidence TEXT, probe_class TEXT, first_seen INTEGER, last_seen INTEGER,
  sw_guess TEXT, updated INTEGER, n_q INTEGER, active INTEGER, noise INTEGER, conf TEXT
);
CREATE TABLE IF NOT EXISTS fp_dict(
  kind TEXT, key TEXT, label TEXT, conf INTEGER, source TEXT, basis TEXT,
  hits INTEGER DEFAULT 0, created INTEGER, updated INTEGER, PRIMARY KEY(kind, key)
);
CREATE TABLE IF NOT EXISTS ndpi_flows(
  id INTEGER PRIMARY KEY, run_ts INTEGER, ip TEXT, sport INTEGER, dport INTEGER,
  proto TEXT, category TEXT, risks TEXT, bytes INTEGER, pkts INTEGER,
  device_id INTEGER, first_seen REAL
);
CREATE INDEX IF NOT EXISTS idx_ndpi_run ON ndpi_flows(run_ts);
CREATE INDEX IF NOT EXISTS idx_dns_recent_ts ON dns_recent(ts);
CREATE TABLE IF NOT EXISTS doh_requests(
  id INTEGER PRIMARY KEY, ts INTEGER, ip TEXT, device_id INTEGER, method TEXT,
  uri TEXT, http_ver TEXT, status INTEGER, rt REAL, tls_proto TEXT, cipher TEXT,
  cipher_list TEXT, curves TEXT, alpn TEXT, sni TEXT, resumed INTEGER, ua TEXT,
  headers TEXT, xff TEXT, qname TEXT, ch_model TEXT, ch_platform TEXT, ch_ua_full TEXT
);
CREATE INDEX IF NOT EXISTS idx_doh_ts ON doh_requests(ts);
CREATE TABLE IF NOT EXISTS ip_info(
  ip TEXT PRIMARY KEY, rdns TEXT, asn TEXT, as_org TEXT, country TEXT,
  prefix TEXT, updated INTEGER
);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY, ts INTEGER, kind TEXT, device_id INTEGER, detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);

CREATE TABLE IF NOT EXISTS enrollments(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  fp_id TEXT, name TEXT, note TEXT,
  fp TEXT, ua TEXT, model TEXT, platform TEXT, platform_ver TEXT, arch TEXT,
  ja4 TEXT, ja4_list TEXT, tcp_sig TEXT,
  src_ip TEXT, matched_device INTEGER, created REAL, updated REAL,
  hash_stable TEXT, hash_net TEXT, pids TEXT, hdr TEXT, fp2 TEXT,
  ua_full TEXT, seen INTEGER DEFAULT 0, obs_count INTEGER DEFAULT 0, matched_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_enroll_updated ON enrollments(updated);
CREATE UNIQUE INDEX IF NOT EXISTS idx_enroll_fpid ON enrollments(fp_id) WHERE fp_id IS NOT NULL;

-- 2026-10-15：每次 /join 访问一行（时间序列），既存全量指纹也存当次的 DoT/DoH 保护判定
CREATE TABLE IF NOT EXISTS enroll_obs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL, fp_id TEXT, ip TEXT, ja4 TEXT, tcp_sig TEXT,
  ua TEXT, hdr TEXT, fp_json TEXT, hash_stable TEXT, hash_net TEXT, pids TEXT,
  matched_device INTEGER, matched_by TEXT, protected INTEGER, protect_by TEXT,
  protect_proto TEXT, protect_age INTEGER, probed INTEGER
);
CREATE INDEX IF NOT EXISTS idx_enroll_obs_ts ON enroll_obs(ts);
CREATE INDEX IF NOT EXISTS idx_enroll_obs_fp ON enroll_obs(fp_id, ts);
CREATE INDEX IF NOT EXISTS idx_enroll_obs_hs ON enroll_obs(hash_stable);
"""


def db():
    global _CONN
    if _CONN is None:
        _CONN = sqlite3.connect(CFG["db"], timeout=30, check_same_thread=False)
        _CONN.row_factory = sqlite3.Row
        _CONN.execute("PRAGMA journal_mode=WAL")
        _CONN.execute("PRAGMA synchronous=NORMAL")
        _CONN.execute("PRAGMA busy_timeout=15000")
    return _CONN


def init_db():
    with DB_LOCK:
        c = db()
        c.executescript(SCHEMA)
        # ==== PIN-PATCH v1 ==== SQLite 没有 ADD COLUMN IF NOT EXISTS，所以先查 PRAGMA 再补。
        for _t, _c, _d in (("enrollments", "pinned", "INTEGER DEFAULT 0"),
                           ("enrollments", "hash_stable", "TEXT"),
                           ("enrollments", "hash_net", "TEXT"),
                           ("enrollments", "pids", "TEXT"),
                           ("enrollments", "hdr", "TEXT"),
                           ("enrollments", "fp2", "TEXT"),
                           ("enrollments", "ua_full", "TEXT"),
                           ("enrollments", "seen", "INTEGER DEFAULT 0"),
                           ("enrollments", "obs_count", "INTEGER DEFAULT 0"),
                           ("enrollments", "matched_by", "TEXT"),
                           ("devices", "browser_fp", "TEXT"),
                           ("devices", "browser_pids", "TEXT"),
                           ("devices", "browser_seen", "REAL")):
            try:
                if _c not in [r[1] for r in c.execute("PRAGMA table_info(%s)" % _t).fetchall()]:
                    c.execute("ALTER TABLE %s ADD COLUMN %s %s" % (_t, _c, _d))
            except Exception:
                pass
        # 2026-10-05：加索引。/api/devices 每台设备要跑 5 个相关子查询（dns24/conns24/probes24/qest24/qrtt），
        # 没有索引时 300 台 × 扫 conns 1.8 万行 ≈ 2.2 秒。加索引后应降到百毫秒级。
        for _ix, _col in (("ix_conns_dev_ts", "conns(device_id, ts)"),
                          ("ix_conns_ts", "conns(ts)"),
                          ("ix_conns_tsip", "conns(ts, src_ip)"),
                          ("ix_dnshour_ip_hour", "dns_hour(ip, hour)"),
                          ("ix_dohreq_ts", "doh_requests(ts)"),
                          ("ix_dnsrecent_ts", "dns_recent(ts)"),
                          ("ix_devices_lastseen", "devices(last_seen)"),
                          # 2026-10-15：新列索引必须等 ALTER 补列之后再建，否则老库启动即报
                          # "no such column: hash_stable"（executescript 在补列之前跑）
                          ("ix_enroll_hs", "enrollments(hash_stable)")):
            try:
                c.execute("CREATE INDEX IF NOT EXISTS %s ON %s" % (_ix, _col))
            except Exception as _e:
                log("索引 %s 创建失败: %s" % (_ix, _e))
        # 2026-10-05：路由器采集那一路早已下线（README 也写明移除），这三张表恒为 0 行 → 一次性清掉
        for _t in ("router_devices", "router_runs", "opcounters"):
            try:
                c.execute("DROP TABLE IF EXISTS %s" % _t)
            except Exception:
                pass
        try:
            c.execute("PRAGMA wal_checkpoint(TRUNCATE)")   # 启动时把 WAL 收干净
        except Exception:
            pass
        for table, col, decl in (
                ("devices", "tcp_sig", "TEXT"),
                ("conns", "rtt_ms", "REAL"), ("conns", "probe", "INTEGER DEFAULT 0"),
                ("conns", "req_rec", "INTEGER"), ("conns", "resp_rec", "INTEGER"),
                ("conns", "resp_bytes", "INTEGER"), ("conns", "q_est", "INTEGER"),
                ("conns", "q_rtt_ms", "REAL"), ("conns", "partial", "INTEGER DEFAULT 0"),
                ("conns", "tsval", "INTEGER"), ("conns", "retrans", "INTEGER DEFAULT 0"),
                ("conns", "skew_ppm", "INTEGER"),
                ("devices", "uptime_s", "INTEGER"), ("devices", "skew_ppm", "INTEGER"),
                ("devices", "ipid_class", "TEXT"), ("devices", "retrans_rate", "REAL"),
                ("devices", "os_version_hint", "TEXT"), ("devices", "model", "TEXT"),
                ("doh_requests", "qname", "TEXT"), ("doh_requests", "ch_model", "TEXT"),
                ("doh_requests", "ch_platform", "TEXT"), ("doh_requests", "ch_ua_full", "TEXT"),
                ("dns_recent", "match_ms", "INTEGER"), ("dns_recent", "src", "TEXT"),
                ("dns_recent", "sport", "INTEGER"), ("dns_recent", "do_bit", "INTEGER"),
                ("dns_recent", "udp_size", "INTEGER"), ("dns_recent", "mixed", "INTEGER"),
                ("dns_recent", "edns", "TEXT"), ("dns_recent", "rcode", "INTEGER"),
                ("devices", "edns_profile", "TEXT"), ("devices", "dot_queries", "INTEGER"),
                ("devices", "behavior", "TEXT"), ("devices", "behavior_json", "TEXT"), ("dns_recent", "rule", "TEXT"),
                ("conns", "psk", "INTEGER"), ("conns", "ticket_age", "INTEGER"),
                ("conns", "ja4t", "TEXT"), ("conns", "ja4l_c", "TEXT"), ("conns", "ja4l_s", "TEXT"),
                ("conns", "psk_ident", "TEXT"), ("devices", "dns_cookie", "TEXT"),
                ("devices", "ddr_count", "INTEGER"),
                ("ip_info", "province", "TEXT"), ("ip_info", "city", "TEXT"), ("ip_info", "geo_src", "TEXT"),
                ("devices", "province", "TEXT"), ("devices", "city", "TEXT"), ("devices", "geo_src", "TEXT"),
                ("conns", "ip_id", "INTEGER"),
                ("devices", "cluster_id", "INTEGER"),
                ("clusters", "conf", "TEXT"),
                ("clusters", "noise", "INTEGER"),
                ("clusters", "active", "INTEGER"),
                ("clusters", "n_q", "INTEGER"), ("devices", "probe_class", "TEXT"),
                ("devices", "ndpi_risk", "TEXT"),
                ("devices", "ndpi_category", "TEXT"),
                ("devices", "ndpi_proto", "TEXT"),
                ("devices", "ja4_o", "TEXT"), ("devices", "source", "TEXT DEFAULT 'server'"),
                ("devices", "vendor", "TEXT"), ("devices", "device_class", "TEXT"),
                ("devices", "role", "TEXT"), ("devices", "confidence", "TEXT"),
                ("devices", "infer_ts", "INTEGER"), ("devices", "infer_json", "TEXT"),
                ("devices", "top_domains", "TEXT")):
            try:
                cols = [r[1] for r in c.execute("PRAGMA table_info(%s)" % table)]
                if col not in cols:
                    c.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, col, decl))
                    log("数据库迁移：%s.%s 已添加" % (table, col))
            except Exception as e:
                log("数据库迁移失败 %s.%s: %s" % (table, col, e))
        c.commit()


def qall(sql, args=()):
    with DB_LOCK:
        return db().execute(sql, args).fetchall()


def qone(sql, args=()):
    with DB_LOCK:
        return db().execute(sql, args).fetchone()


def xrun(sql, args=()):
    with DB_LOCK:
        db().execute(sql, args)
        _DIRTY[0] = True


def mark_dirty():
    _DIRTY[0] = True


def commit_loop():
    while True:
        time.sleep(1.0)
        if _DIRTY[0]:
            with DB_LOCK:
                try:
                    db().commit()
                    _DIRTY[0] = False
                except Exception as e:
                    log("commit 失败: %s" % e)


COUNTERS = {}
COUNTERS_LOCK = threading.Lock()


def bump(k, n=1):
    with COUNTERS_LOCK:
        COUNTERS[k] = COUNTERS.get(k, 0) + n


def kv_get(k, d=None):
    r = qone("SELECT v FROM kv WHERE k=?", (k,))
    return r["v"] if r else d


def kv_set(k, v):
    xrun("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))


# ---------------------------------------------------------------------------
# 设备写入
# ---------------------------------------------------------------------------

_DEV_CACHE = {}
_DEV_LOCK = threading.Lock()


def _dev_load(fp_key):
    r = qone("SELECT * FROM devices WHERE fp_key=?", (fp_key,))
    return dict(r) if r else None


def device_for(fp_key, seed=None):
    """按指纹键取/建设备，返回 (device_id, row_dict)。"""
    with _DEV_LOCK:
        d = _DEV_CACHE.get(fp_key)
        if d is None:
            d = _dev_load(fp_key)
            if d is None:
                ts = now()
                src = (seed or {}).get("source", "server")
                xrun("INSERT INTO devices(fp_key,source,first_seen,last_seen,src_ips,protos,variants,updated,obs_count) VALUES(?,?,?,?,?,?,?,?,0)",
                     (fp_key, src, ts, ts, "[]", "{}", "[]", ts))
                d = dict(qone("SELECT * FROM devices WHERE fp_key=?", (fp_key,)))
                if src == "server":
                    xrun("INSERT INTO events(ts,kind,device_id,detail) VALUES(?,?,?,?)",
                         (ts, "new_device", d["id"], "发现新指纹设备"))
            _DEV_CACHE[fp_key] = d
        return d["id"], d


def dev_touch(fp_key, patch, inc_conn=0, inc_bytes_in=0, inc_bytes_out=0,
              proto_kind=None, variant=None, ip=None, event=None):
    """更新设备聚合字段（读改写 JSON 字段）。"""
    did, d = device_for(fp_key, patch)
    with _DEV_LOCK:
        src_ips = jload(d.get("src_ips"), {}) or {}
        if isinstance(src_ips, list):        # 兼容旧形状
            src_ips = dict((x, 1) for x in src_ips)
        if ip:
            src_ips[ip] = int(src_ips.get(ip, 0)) + 1
            if len(src_ips) > 24:
                for k in sorted(src_ips, key=lambda x: -src_ips[x])[20:]:
                    src_ips.pop(k, None)
        protos = jload(d.get("protos"), {}) or {}
        if proto_kind:
            protos[proto_kind] = int(protos.get(proto_kind, 0)) + 1
        variants = jload(d.get("variants"), []) or []
        if variant:
            hit = None
            for v in variants:
                if v.get("fp") == variant.get("fp"):
                    hit = v
                    break
            if hit:
                hit["n"] = int(hit.get("n", 0)) + 1
                hit["last"] = variant.get("last")
            else:
                variants.append(variant)
            variants = sorted(variants, key=lambda v: -int(v.get("n", 0)))[:14]
        fields = {
            "last_seen": now(),
            "src_ips": jdump(src_ips),
            "protos": jdump(protos),
            "variants": jdump(variants),
            "conn_count": int(d.get("conn_count") or 0) + inc_conn,
            "bytes_in": int(d.get("bytes_in") or 0) + inc_bytes_in,
            "bytes_out": int(d.get("bytes_out") or 0) + inc_bytes_out,
            "obs_count": int(d.get("obs_count") or 0) + 1,
            "updated": now(),
        }
        for k, v in (patch or {}).items():
            if v is not None and v != "":
                fields[k] = v
        cols = ",".join("%s=?" % k for k in fields)
        xrun("UPDATE devices SET %s WHERE id=?" % cols, list(fields.values()) + [did])
        d.update(fields)
        if event:
            xrun("INSERT INTO events(ts,kind,device_id,detail) VALUES(?,?,?,?)",
                 (now(), event, did, ""))
    return did


def fp_key_for(ja3, ja4, tcp_sig, ip):
    if ja4 or ja3:
        base = "%s|%s|%s" % (ja4 or "-", ja3 or "-", tcp_sig or "-")
        return sha1(base)
    # 无 ClientHello 的连接（TCP 探测、会话复用、抓包起点错过握手）：
    # 优先并入「同源 IP + 同 TCP 指纹」的已有带 TLS 设备，避免同一台设备被拆成两个。
    if tcp_sig:
        r = qone("SELECT fp_key FROM devices WHERE tcp_sig=? AND ja4 IS NOT NULL AND source='server'"
                 " AND src_ips LIKE ? ORDER BY last_seen DESC LIMIT 1",
                 (tcp_sig, '%"' + ip + '"%'))
        if r:
            return r["fp_key"]
        return sha1("notls|%s|%s" % (tcp_sig, ip or "-"))
    # 既没有 ClientHello 也没有 TCP 指纹（例如 devfp 重启前就建立的长连接中段数据）：
    # 无法指纹化 → 不建虚拟设备，conn 记为未归属，查询靠 IP 级兜底归属。
    return None


def app_guess_from(ua, alpn, tls_ver, sni, port):
    """完全基于证据的应用猜测，不做无根据的断言。"""
    ev = []
    u = (ua or "").lower()
    if u:
        for key, name in (("curl", "curl"), ("dnscrypt", "dnscrypt-proxy"), ("adguard", "AdGuard"),
                          ("okhttp", "Android OkHttp"), ("dart", "Dart/Flutter"),
                          ("python", "Python"), ("go-http", "Go 程序"), ("windows", "Windows 客户端"),
                          ("mozilla", "浏览器/Mozilla 系"), ("chrome", "Chrome/Chromium 系"),
                          ("safari", "Safari/Apple 系"), ("edge", "Edge"), ("firefox", "Firefox"),
                          ("quic", "QUIC 客户端"), ("intra", "Intra"), ("rethink", "RethinkDNS"),
                          ("cloudflared", "cloudflared"), ("doh", "DoH 客户端")):
            if key in u:
                ev.append(name)
                break
    if not ua:
        ev.append("无 UA（裸 DoH 客户端/库）")
    if alpn:
        ev.append("ALPN=" + "/".join(alpn))
    if port == 853:
        ev.append("DoT")
    elif port == 444:
        ev.append("DoH(直连)")
    elif port == 443:
        ev.append("DoH(经 nginx)")
    if sni and sni != "dns.example.com":
        ev.append("SNI=" + sni)
    return "；".join(ev) if ev else None


# ---------------------------------------------------------------------------
# 设备推断引擎
#   原则：跨 NAT + TLS 加密 → 读不到 MAC/型号；只能用「TLS 栈结构 + TCP/IP 特征 +
#   查询域名 + HTTP 层 + 行为」组合推断厂商/OS/设备角色，并把每条证据摊开给人复核。
# ---------------------------------------------------------------------------

# (标签, 权重, 说明, [域名正则])
_DOMAIN_RULES = [
    ("Apple", 3, "Apple 服务域名（iCloud/推送/更新）",
     [r"(^|\.)apple\.com$", r"(^|\.)icloud\.com$", r"(^|\.)mzstatic\.com$",
      r"^gs-loc\.apple\.com$", r"\.push\.apple\.com$", r"^mesu\.apple\.com$",
      r"^captive\.apple\.com$", r"^swscan\.apple\.com$", r"^gateway\.icloud\.com$"]),
    ("Android/Google", 3, "Google/Android 系统服务域名",
     [r"^connectivitycheck\.gstatic\.com$", r"^mtalk\.google\.com$", r"\.gcm\.googleapis\.com$",
      r"^android\.clients\.google\.com$", r"^play\.googleapis\.com$", r"^play\.google\.com$",
      r"^clients3\.google\.com$", r"^www\.google\.com$"]),
    ("Windows", 3, "Windows NCSI/更新/遥测域名",
     [r"^www\.msftconnecttest\.com$", r"^www\.msftncsi\.com$", r"^dns\.msftncsi\.com$",
      r"\.windowsupdate\.com$", r"^settings-win\.data\.microsoft\.com$",
      r"\.events\.data\.microsoft\.com$", r"\.windows\.com$"]),
    ("小米 Xiaomi", 3, "小米系统/统计域名",
     [r"(^|\.)miui\.com$", r"(^|\.)xiaomi\.com$", r"^api\.mifitness\.com$", r"(^|\.)mi\.com$"]),
    ("华为/荣耀", 3, "华为/荣耀云与推送域名",
     [r"(^|\.)hicloud\.com$", r"(^|\.)huawei\.com$", r"(^|\.)hihonor\.com$", r"(^|\.)honor\.com$"]),
    ("OPPO/一加/realme", 3, "OPPO 系系统服务域名",
     [r"(^|\.)heytapmobi\.com$", r"(^|\.)oppomobile\.com$", r"(^|\.)oppo\.com$",
      r"(^|\.)oneplus\.(com|net)$", r"(^|\.)realme\.com$", r"(^|\.)allawnos\.com$"]),
    ("vivo/iQOO", 3, "vivo 系系统服务域名",
     [r"(^|\.)vivo\.com\.cn$", r"(^|\.)vivoglobal\.com$", r"(^|\.)iqoo\.com$"]),
    ("三星 Samsung", 3, "三星云/应用商店域名",
     [r"(^|\.)samsungcloud\.com$", r"(^|\.)samsungapps\.com$", r"(^|\.)samsung\.com$"]),
    ("Firefox/Mozilla", 3, "Mozilla DoH 探测/服务域名",
     [r"^use-application-dns\.net$", r"(^|\.)mozilla\.(org|com|net)$", r"(^|\.)firefox\.com$"]),
    ("亚马逊 Amazon", 2, "Amazon 设备/服务域名",
     [r"(^|\.)a2z\.com$", r"(^|\.)amazon\.com$", r"(^|\.)amazonaws\.com$"]),
    ("智能电视/盒子", 3, "电视/机顶盒系统域名",
     [r"(^|\.)smarttv\.com$", r"(^|\.)roku\.com$", r"(^|\.)firetv\.amazon\.com$",
      r"(^|\.)hisense\.com$", r"(^|\.)toshiba\.com$", r"(^|\.)skyworth\.com$"]),
    ("游戏主机", 3, "PlayStation/Xbox/任天堂域名",
     [r"(^|\.)playstation\.(net|com)$", r"(^|\.)nintendo\.net$", r"(^|\.)xboxlive\.com$"]),
    ("IoT/智能家居", 2, "IoT 云平台域名（插座/摄像头/家电）",
     [r"(^|\.)tuya(cn|eu|us|com)?\.com$", r"(^|\.)meross\.com$", r"(^|\.)tplinkcloud\.com$",
      r"(^|\.)espressif\.com$", r"(^|\.)micloud\.(com|cn)$", r"(^|\.)aqara\.com$"]),
    ("中国广告/统计 SDK", 2, "国产 App 广告与统计 SDK（说明该设备装了大量国产 App）",
     [r"\.gdt\.qq\.com$", r"^v2mi\.gdt\.qq\.com$", r"ugdtimg\.com$", r"^sdk-log\.partner\.sm\.cn$",
      r"\.beacon\.qq\.com$", r"\.pangolin-sdk-toutiao\.com$", r"\.beizi\.biz$"]),
    ("代理/DNS 客户端基建", 2, "机场节点域名（说明该客户端本身在跑代理/转发）",
     [r"\.ulfmwcyp\.lol$"]),
    # 高信号「特征域名」：能直接说明客户端软件/隐私档位
    ("iCloud 私密转发", 4, "查询 mask.icloud.com → 该设备开启了 iCloud Private Relay（iOS/macOS 设备级功能）",
     [r"^mask(-h2)?\.icloud\.com$"]),
    ("Firefox DoH 策略探测", 4, "查询 use-application-dns.net → Firefox 的 DoH 策略探测域名",
     [r"^use-application-dns\.net$"]),
    ("DDR 解析器发现", 4, "查询 _dns.resolver.arpa / resolver.arpa → 客户端在自动发现指定解析器（较新系统/浏览器）",
     [r"(^|\.)resolver\.arpa$", r"^_dns\.resolver\.arpa$"]),
    ("Windows NCSI 探测", 3, "dns.msftncsi.com / www.msftconnecttest.com → Windows 网络连通性探测",
     [r"^dns\.msftncsi\.com$", r"^www\.msftconnecttest\.com$", r"^www\.msftncsi\.com$"]),
    ("Apple 网络探测", 3, "captive.apple.com / gs-loc.apple.com → Apple 设备的连通性与定位服务",
     [r"^captive\.apple\.com$", r"^gs-loc\.apple\.com$", r"^time(-[a-z0-9]+)?\.apple\.com$"]),
    ("Chrome/Edge 安全 DNS", 3, "chrome.cloudflare-dns.com / doh.opendns.com 等浏览器 DoH 探测",
     [r"^chrome\.cloudflare-dns\.com$", r"^doh\.opendns\.com$", r"^dns\.google$", r"^doh\.dns\.apple\.com$",
      r"^dns\.nextdns\.io$", r"^doh\.mullvad\.net$", r"^cloudflare-dns\.com$"]),
    ("mDNS/内网服务发现", 2, "wpad / _ldap._tcp / _sips._tcp 等内网发现域名（操作系统与企业配置痕迹）",
     [r"^wpad$", r"^wpad\.", r"^_ldap\._tcp", r"^_sips\._tcp", r"^_kerberos\._udp", r"^_smb\._tcp"]),
    ("NTP 对时", 2, "pool.ntp.org / time.* 等对时域名（说明是常在线设备）",
     [r"^pool\.ntp\.org$", r"^time(\.[a-z0-9-]+)*\.(com|net|org|cn)$", r"^ntp[0-9]*\.", r"\.ntp\.org$"]),
]

# TLS 栈结构规则：先匹配「结构特征」，匹配不上就如实写「未识别」
def tls_stack_guess(tls):
    if not tls:
        return None, None, []
    ext = [e["type"].lower().replace("0x", "") for e in (tls.get("extensions") or [])]
    cip = [x.split()[0].lower().replace("0x", "") for x in (tls.get("ciphers") or [])]
    ev = []
    grease = (tls.get("grease_ciphers") or 0) + (tls.get("grease_exts") or 0)
    alpn = tls.get("alpn") or []
    ver = tls.get("version_code") or ""
    prefix = lambda p: ext[:len(p)] == p
    startswith = lambda p: cip[:len(p)] == p

    # Go crypto/tls：扩展顺序非常有辨识度（EMS→reneg→groups→ecpf→ticket→sigalg→key_share→psk→versions）
    if prefix(["0000", "0017", "ff01", "000a", "000b", "0023", "000d", "0033", "002d", "002b"]) or \
       prefix(["0017", "ff01", "000a", "000b", "0023", "000d", "0033", "002d", "002b"]):
        ev.append("扩展顺序 = Go crypto/tls 特征序列（%s…）" % "-".join(ext[:6]))
        if not grease:
            ev.append("无 GREASE")
        if startswith(["1301", "1302", "1303", "c02b", "c02f"]):
            ev.append("套件顺序 = Go 默认（1301,1302,1303,c02b,c02f…）")
        return "Go crypto/tls 系", "高", ev
    # OpenSSL 3.x：套件 AES256 优先 + renegotiation_info 打头 + encrypt_then_mac/post_handshake_auth
    if startswith(["1303", "1302", "1301", "cca9", "cca8"]) and ext[:2] == ["ff01", "0000"]:
        ev.append("套件 AES256 优先（1303,1302,1301,cca9,cca8…）")
        ev.append("扩展以 renegotiation_info+server_name 打头")
        if "0016" in ext:
            ev.append("含 encrypt_then_mac（OpenSSL 特征）")
        return "OpenSSL 3.x 系", "中", ev
    # Apple：套件以 c02c,c02b / 含 ALPS(4469)
    if startswith(["c02c", "c02b"]) or ("4469" in ext and grease):
        ev.append("套件/扩展组合偏 Apple（%s）" % ",".join(cip[:3]))
        if "4469" in ext:
            ev.append("含 ALPS(0x4469)")
        return "Apple 安全栈（iOS/macOS）", "中", ev
    # BoringSSL（Chrome/Android）：GREASE + BoringSSL 套件序 + ALPN h2
    if grease and startswith(["1301", "1302", "1303", "c02b", "c02f", "c02c", "c030"]):
        ev.append("有 GREASE + 套件序为 BoringSSL/Chrome 系（%s…）" % ",".join(cip[:4]))
        if alpn:
            ev.append("ALPN=%s" % "/".join(alpn))
        return "BoringSSL（Chrome/Android）", "中", ev
    if ver in ("10", "11", "s3", "s2") or len(cip) > 40:
        ev.append("协议版本过旧或套件数异常（v=%s，套件 %d 个）" % (tls.get("version"), len(cip)))
        return "TLS 扫描/探测工具", "中", ev
    if not grease and not alpn and not tls.get("sni"):
        ev.append("无 GREASE、无 ALPN、无 SNI")
        if any(c.startswith("11e") or c == "6399" for c in cip):
            ev.append("含 ML-KEM 混合曲线（较新的无 GREASE 栈：Go/rustls/OpenSSL 3.5+）")
        return "无 GREASE 的现代 TLS 栈", "低", ev
    return None, None, ev


def os_from_tcp(tcp):
    if not tcp:
        return None, None, []
    ev = []
    ttl = tcp.get("init_ttl")
    order = tcp.get("order") or []
    ts = tcp.get("ts")
    mss = tcp.get("mss")
    if ttl == 128:
        ev.append("初始 TTL 128")
        if ts == 0:
            ev.append("SYN 不带时间戳（Windows 默认）")
        return "Windows", "中", ev
    if ttl == 64:
        ev.append("初始 TTL 64")
        if order[:3] == ["MSS", "SACK", "TS"] and "WS" in order:
            ev.append("选项顺序 MSS,SACK,TS,…,WS（Linux 内核默认）")
            return "Linux/Android", "中", ev
        if order[:2] == ["MSS", "NOP"] and "SACK" in order:
            ev.append("选项顺序 MSS,NOP,…（Apple Darwin 特征）")
            return "Apple (Darwin)", "中", ev
        if order[:1] == ["MSS"] and not ts:
            ev.append("无时间戳的极简选项（嵌入式/老内核）")
            return "嵌入式 Linux", "低", ev
        return "Linux 系", "低", ev
    if ttl in (255, 254):
        ev.append("初始 TTL %s（网络设备/扫描器）" % ttl)
        return "网络设备/扫描器", "低", ev
    if mss in (1212, 1444, 1420, 1400):
        ev.append("MSS=%s（链路/隧道 MTU 偏小）" % mss)
    return None, None, ev


# 「TLS 时代/版本线索」：靠密钥交换组与结构特征推断客户端栈的代际（不是硬件型号）
_PQ_GROUPS = {
    "x25519kyber768": ("2023H2–2024", "X25519Kyber768Draft00（Chromium 116–130 时代引入）"),
    "x25519kyber768draft00": ("2023H2–2024", "X25519Kyber768Draft00"),
    "x25519mlkem768": ("2024Q4+", "X25519MLKEM768（Chrome 131+/Firefox 135+/Go 1.24+/OpenSSL 3.5+ 起）"),
    "0x11eb": ("2024Q4+", "SecP256r1MLKEM768（OpenSSL 3.5+/Go 1.24+）"),
    "0x11ed": ("2024Q4+", "SecP384r1MLKEM768（OpenSSL 3.5+）"),
}
_ALPS_EXT = "4469"          # application_settings（Chrome/Safari 系特征）


def tls_version_hint(tls, stack_label=None, uses_https_rr=False):
    """由 ClientHello 结构推断「客户端栈代际/系统版本区间」。产出的永远是区间与线索，不是型号。"""
    out = {"era": None, "hint": None, "evidence": []}
    if not tls:
        return out
    ev = out["evidence"]
    curves = tls.get("curves") or []
    exts = [e["type"].lower().replace("0x", "") for e in (tls.get("extensions") or [])]
    ciphers = [x.split()[0].lower().replace("0x", "") for x in (tls.get("ciphers") or [])]
    alpn = tls.get("alpn") or []
    grease = (tls.get("grease_ciphers") or 0) + (tls.get("grease_exts") or 0)
    tls12_only = (tls.get("version_code") == "12")
    eras = []
    for g in curves:
        if g in _PQ_GROUPS:
            era, note = _PQ_GROUPS[g]
            eras.append(era)
            ev.append("含 PQ 混合组：%s → %s" % (note, era))
    if not eras:
        out["era"] = "pre-2023"
        ev.append("不含任何 PQ 混合密钥交换组（2023 下半年之前普遍如此）")
    else:
        out["era"] = "2024Q4+" if "2024Q4+" in eras else "2023H2–2024"
    # 结构家族特征（补充线索，不单独下结论）
    if _ALPS_EXT in exts and grease:
        ev.append("含 ALPS(0x4469) + GREASE → Chrome/Safari 系浏览器栈")
    if "0016" in exts:
        ev.append("含 encrypt_then_mac(0x16) → OpenSSL/BoringSSL 系")
    if "0031" in exts:
        ev.append("含 post_handshake_auth(0x31) → OpenSSL/Schannel 系")
    if "0032" in exts:
        ev.append("含 signature_algorithms_cert(0x32) → 较新的 OpenSSL/Go 系")
    if tls12_only and "002b" not in exts:
        ev.append("只支持到 TLS1.2 且无 supported_versions → 老栈（Android 4.x/Win7 时代）")
    if not alpn and not tls.get("sni"):
        ev.append("无 ALPN、无 SNI → 按 IP 直连的解析器/网关客户端（多为自建 DNS 转发）")
    if len(ciphers) > 40:
        ev.append("套件数异常多（%d）→ 扫描器特征" % len(ciphers))
    if uses_https_rr:
        ev.append("客户端查询过 HTTPS/SVCB 记录 → 支持 HTTPS RR 的较新客户端（iOS 14+/Android 12+/新版浏览器）")
    parts = [x for x in (stack_label, out["era"]) if x]
    out["hint"] = " · ".join(parts) if parts else None
    return out


def infer_device(dev, tls, tcp, http, domains, cstats, dom_shared=None, own_domains=None,
                 tcp_extras=None, version_hint=None):
    """返回推断结果。dom_shared: 该设备来源 IP 是否被多个指纹共用（共用时 IP 级域名证据不可归属）。
    own_domains: 该设备自己的 DoH 查询域名（来自 nginx 日志，逐设备可归属）。"""
    scores = {}
    evidence = []
    caveats = []

    def add(label, w, why):
        scores[label] = scores.get(label, 0) + w
        evidence.append({"k": label, "w": w, "why": why})

    def apply_rules(doms, tag):
        for lab, w, note, pats in _DOMAIN_RULES:
            hit = []
            for d, n in doms:
                for p in pats:
                    if re.search(p, d):
                        hit.append(d)
                        break
            if hit:
                add(lab, w + min(len(hit), 3),
                    "%s：%s%s" % (tag, "、".join(hit[:3]),
                                 ("（等 %d 个）" % len(hit) if len(hit) > 3 else "")))

    # ① 该设备自己的 DoH 查询域名：永远可归属（不管出口 IP 是否共用）
    if own_domains:
        apply_rules(own_domains, "命中该设备自己的 DoH 查询域名")
    # ② 出口 IP 级域名：只在独占 IP 时用于归属
    if domains and dom_shared:
        caveats.append("该设备来源 IP 被 %s 个指纹共用（NAT/同一出口）：出口 IP 上的「查询域名整体」无法归属到单一设备，"
                       "已排除这部分域名证据；上表的域名线索只来自该设备自己的 DoH 请求（可归属）。"
                       "查询「次数与时延」用该指纹自己的 TLS 记录估算。" % dom_shared)
        evidence.append({"k": "归属", "w": 0,
                         "why": "共用 IP 的全量查询样本（不可归属，仅参考）：%s" % "、".join(d for d, _ in domains[:8])})
    elif domains:
        apply_rules(domains, "命中域名")

    if dev.get("rdns"):
        evidence.append({"k": "网络", "w": 0, "why": "rDNS %s" % dev["rdns"]})
    if dev.get("as_org"):
        evidence.append({"k": "网络", "w": 0,
                         "why": "%s（AS%s %s）" % (dev["as_org"], dev.get("asn"), dev.get("country"))})

    stack, stack_conf, stack_ev = tls_stack_guess(tls)
    for e in stack_ev:
        evidence.append({"k": "TLS 栈", "w": 0, "why": e})
    osx, os_conf, os_ev = os_from_tcp(tcp)
    for e in os_ev:
        evidence.append({"k": "TCP/IP", "w": 0, "why": e})
    if stack:
        add(stack, 5 if stack_conf == "高" else (4 if stack_conf == "中" else 2),
            "TLS 结构判定（%s置信，逐设备证据）" % stack_conf)
    if osx and not (stack and stack in ("TLS 扫描/探测工具",) and osx == "网络设备/扫描器"):
        add(osx, 2 if os_conf == "中" else 1, "TCP/IP 结构判定（%s置信，逐设备证据）" % os_conf)
    if http and http.get("ua"):
        ua = http["ua"]
        evidence.append({"k": "HTTP", "w": 0, "why": "User-Agent: %s" % ua[:120]})
        ua_map = (("windows nt", "Windows"), ("android", "Android 系"), ("iphone", "Apple"),
                  ("ipad", "Apple"), ("macintosh", "Apple"), ("curl", "OpenSSL 3.x 系"),
                  ("dnscrypt", "dnscrypt-proxy"), ("adguard", "AdGuard"),
                  ("go-http", "Go crypto/tls 系"), ("python", "OpenSSL 3.x 系"))
        for key, lab in ua_map:
            if key in ua.lower():
                add(lab, 4, "UA 命中 %r" % key)
                break
    elif http and not http.get("ua"):
        evidence.append({"k": "HTTP", "w": 0, "why": "DoH 请求未带 User-Agent（裸客户端/库）"})

    # 行为角色：只用「逐设备可归属」的事实（协议种类、探测比例、连接时长、会话复用）
    protos = {}
    try:
        protos = json.loads(dev.get("protos") or "{}")
    except Exception:
        pass
    n_conn = cstats.get("n") or 0
    n_query = cstats.get("queries") or 0            # 按出口 IP
    n_query_fp = cstats.get("queries_est") or 0     # 按该指纹的 TLS 记录（可归属）
    probe = cstats.get("probes") or 0
    resumed = cstats.get("resumed") or 0
    dur = cstats.get("avg_dur_ms") or 0
    is_dns = bool(protos.get("dot") or protos.get("doh443") or protos.get("doh444") or protos.get("doq"))
    role, role_conf = None, None
    rtt_note = ("，查询往返中位 %s ms（TLS 记录配对）" % cstats.get("q_rtt_avg")
                if cstats.get("q_rtt_avg") is not None else "")
    if probe and n_query_fp == 0 and n_query == 0:
        role, role_conf = "端口探测/扫描（只握手不发数据）", "高"
        evidence.append({"k": "行为", "w": 0, "why": "%d 条连接全为无载荷探测、AGH 无查询记录" % probe})
    elif protos.get("tls443") and not is_dns:
        role, role_conf = "非 DNS 设备（仅 443 网页/面板访问）", "高"
        evidence.append({"k": "行为", "w": 0, "why": "只有 443 握手，没用过 /dns-query，也无 DoT"})
    elif not is_dns and n_conn:
        role, role_conf = "无 DNS 协议记录", "低"
    elif n_query_fp and n_conn and n_query_fp / max(1, n_conn) >= 5:
        role, role_conf = "DNS 网关/转发器（为整网转发查询）", "中"
        evidence.append({"k": "行为", "w": 0,
                         "why": "按 TLS 记录估算：%d 次查询 / %d 条连接（每连接约 %.0f 次），"
                                "逐指纹可归属%s" % (n_query_fp, n_conn, n_query_fp / n_conn, rtt_note)})
    elif n_query_fp:
        role, role_conf = "DNS 客户端（长连接复用，逐指纹估算 %d 次查询）" % n_query_fp, "中"
        evidence.append({"k": "行为", "w": 0, "why": "按 TLS 记录估算%s" % (rtt_note or "（无往返样本）")})
    elif dom_shared:
        role, role_conf = "DoT/DoH 客户端（共用出口 IP，TLS 记录未解出查询计数）", "低"
        evidence.append({"k": "行为", "w": 0, "why": "协议种类可归属：%s；未采到应用数据记录" % protos})
    elif n_query and n_conn and n_query / max(1, n_conn) > 20:
        role, role_conf = "DNS 网关/转发器（按出口 IP 查询量推断）", "低"
        evidence.append({"k": "行为", "w": 0,
                         "why": "查询/连接 ≈ %.0f（%d 次查询 / %d 条连接，按 IP 统计）" % (n_query / n_conn, n_query, n_conn)})
    elif n_query and dur and dur < 800 and n_conn > 30:
        role, role_conf = "DNS 客户端（逐查询建连）", "中"
        evidence.append({"k": "行为", "w": 0, "why": "平均连接时长 %dms、%d 条连接" % (dur, n_conn)})
    elif n_query:
        role, role_conf = "DNS 客户端（长连接复用）", "中"
        evidence.append({"k": "行为", "w": 0,
                         "why": "%d 条连接 / %d 次查询（按 IP）/ 会话复用 %d" % (n_conn, n_query, resumed)})
    elif n_conn:
        role, role_conf = "未产生本地查询记录（探测或抓包中途接入）", "低"

    # ① 先查本地指纹字典（命中就用它，并标注来源/命中次数）
    dh = None
    try:
        dh = dict_lookup(tls, (tcp or {}).get("sig"), ja3_from_tls(tls))
    except Exception:
        dh = None
    if dh and (dh.get("conf") or 0) >= 2:
        add(dh["label"], (dh["conf"] or 1) * 2,
            "本地指纹字典命中（%s，来源 %s，累计命中 %s 次）：%s" % (
                dh["kind"], dh["source"], dh["hits"], (dh.get("basis") or "")[:80]))

    if not tls and not domains:
        evidence.append({"k": "限制", "w": 0, "why": "未抓到 ClientHello（探测/复用会话），且无查询记录"})

    # 版本线索（ClientHello 结构推出的栈代际；不参与厂商打分，单独展示）
    if version_hint:
        for e in (version_hint.get("evidence") or []):
            evidence.append({"k": "版本线索", "w": 0, "why": e})

    # TCP 层附加指纹（不参与打分，只作为证据展示）
    if tcp_extras:
        te = tcp_extras
        if te.get("ipid_class"):
            evidence.append({"k": "IP-ID", "w": 0,
                             "why": "%s（最近值 %s）" % (te["ipid_class"], te.get("ipid_last"))})
        if te.get("skew_ppm") is not None:
            evidence.append({"k": "时钟", "w": 0,
                             "why": "TCP 时间戳时钟漂移 %+d ppm（同连接内 %d 次测量的中位；可作设备时钟指纹）"
                                    % (te["skew_ppm"], te.get("skew_samples", 1))})
        if te.get("uptime_reliable"):
            evidence.append({"k": "在线时长", "w": 0,
                             "why": "约 %.1f 天（该栈以启动时刻为 TSval 基准，如 Windows）"
                                    % (te["uptime_s"] / 86400.0)})
        if te.get("reboots"):
            evidence.append({"k": "重启", "w": 0, "why": "观察到 TCP 时间戳回退 %d 次（疑似设备重启）" % te["reboots"]})
        if te.get("retrans_rate") is not None:
            evidence.append({"k": "重传", "w": 0, "why": "入向重传率 %.2f%%" % te["retrans_rate"]})
        if dev.get("ndpi_proto"):
            evidence.append({"k": "nDPI", "w": 0, "why": "nDPI 判定：%s%s%s" % (
                dev.get("ndpi_proto"), ("（" + dev.get("ndpi_category") + "）") if dev.get("ndpi_category") else "",
                ("；风险：" + dev.get("ndpi_risk")) if dev.get("ndpi_risk") else "")})
        if te.get("ja4t"):
            evidence.append({"k": "JA4T", "w": 0, "why": "TCP 指纹（官方格式）%s%s" % (
                te["ja4t"], ("；另有 %s" % te["ja4t_alt"]) if te.get("ja4t_alt") else "")})
        if te.get("ja4l_c"):
            evidence.append({"k": "网络距离", "w": 0,
                             "why": "JA4L-C %s（单程约 %.1f ms；观测 TTL %s → 推定初始 %s、约 %s 跳）" % (
                                 te["ja4l_c"], te.get("lat_c_us_med", 0) / 1000.0, te.get("ttl_obs"),
                                 64 if te.get("ttl_obs", 64) <= 64 else (128 if te.get("ttl_obs", 128) <= 128 else 255),
                                 te.get("hops_est"))})

    top = sorted(scores.items(), key=lambda kv: -kv[1])
    label = top[0][0] if top else None
    conf = None
    if top:
        margin = top[0][1] - (top[1][1] if len(top) > 1 else 0)
        if top[0][1] >= 8 and margin >= 3:
            conf = "高"
        elif top[0][1] >= 4 and margin >= 2:
            conf = "中"
        else:
            conf = "低"
    cls = coarse_class(label, role)
    _evidence = sum(1 for x in (tls, tcp, http, domains, cstats) if x)
    _drift = "stable" if _evidence >= 3 else ("watch" if _evidence == 2 else "unknown")
    return {"label": label, "confidence": conf, "evidence_count": _evidence, "drift_state": _drift, "class": cls, "scores": top[:8],
            "stack": stack, "stack_conf": stack_conf, "os": osx, "os_conf": os_conf,
            "role": role, "role_conf": role_conf, "evidence": evidence[:60],
            "caveats": caveats,
            "version_hint": (version_hint or {}).get("hint"),
            "version_era": (version_hint or {}).get("era")}


def coarse_class(label, role):
    if role and "扫描" in role:
        return "扫描/探测"
    if role and "非 DNS" in role:
        return "非 DNS 设备（仅网页访问）"
    if label and "Go crypto/tls" in label:
        return "DNS 网关/客户端程序"
    if label in ("Windows", "OpenSSL 3.x 系", "Apple 安全栈（iOS/macOS）", "Apple"):
        return "电脑/通用客户端"
    if label in ("小米 Xiaomi", "华为/荣耀", "OPPO/一加/realme", "vivo/iQOO", "三星 Samsung",
                 "Android 系", "Android/Google"):
        return "手机/平板（厂商线索）"
    if label in ("智能电视/盒子",):
        return "电视/机顶盒"
    if label in ("游戏主机",):
        return "游戏主机"
    if label in ("IoT/智能家居",):
        return "IoT/智能家居"
    if label in ("TLS 扫描/探测工具",):
        return "扫描/探测"
    if label:
        return "待确认"
    return "未识别"


def device_tcp_extras(dev):
    """TCP 层附加指纹：IP ID 类别、时间戳时钟漂移/在线时长/重启、重传率。"""
    out = {"ipid_class": None, "ipid_last": None, "skew_ppm": None,
           "uptime_s": None, "uptime_reliable": False, "reboots": 0,
           "ts_samples": 0, "retrans_rate": None}
    # 取该设备最近 60 条连接：三项（ip_id/tcp_json/tsval）任一为空都不影响其余指标的累计，
    # 因此不再做前置过滤（旧版用 tcp_json IS NOT NULL 过滤，2026-10-09 瘦身后全表为空）。
    rows = qall("SELECT ts, tcp_json, ip_id, retrans, in_pkts, tsval, skew_ppm FROM conns"
                " WHERE device_id=? AND (in_pkts > 0 OR ip_id IS NOT NULL"
                " OR skew_ppm IS NOT NULL) ORDER BY ts DESC LIMIT 60", (dev["id"],))
    ipids = []
    skews = []
    synvals = []
    retr = pkts = 0
    for r in rows:
        f = {}
        if r["tcp_json"]:
            try:
                f = json.loads(r["tcp_json"]) or {}
            except Exception:
                f = {}
        if r["ip_id"] is not None:
            ipids.append(int(r["ip_id"]))
        elif f.get("ip_id") is not None:
            ipids.append(int(f["ip_id"]))
        if r["skew_ppm"] is not None:
            skews.append(int(r["skew_ppm"]))          # 同连接内测得的时钟漂移
        if r["tsval"]:
            synvals.append(int(r["tsval"]))           # SYN 里的 TSval（Windows 是启动后毫秒数）
        retr += r["retrans"] or 0
        pkts += r["in_pkts"] or 0
    if ipids:
        out["ipid_last"] = ipids[0]
        if all(v == 0 for v in ipids):
            out["ipid_class"] = "全 0（DF=1；现代 Linux/移动端/Chrome 常见）"
        else:
            srt = sorted(ipids)
            inc = sum(1 for a, b in zip(srt, srt[1:]) if 0 <= b - a <= 1000)
            out["ipid_class"] = ("递增（全局计数器；老 Windows/部分嵌入式）" if inc >= max(2, len(srt) // 2)
                                 else "随机/其它（现代 Linux 内核常见）")
    if pkts:
        out["retrans_rate"] = round(float(retr) / pkts * 100.0, 3)
    jt = qall("SELECT ja4t, COUNT(*) n FROM conns WHERE device_id=? AND ja4t IS NOT NULL"
              " GROUP BY ja4t ORDER BY n DESC LIMIT 2", (dev["id"],))
    if jt:
        out["ja4t"] = jt[0]["ja4t"]
        out["ja4t_alt"] = jt[1]["ja4t"] if len(jt) > 1 else None
    lats = []
    for r in qall("SELECT ja4l_c FROM conns WHERE device_id=? AND ja4l_c IS NOT NULL"
                  " ORDER BY id DESC LIMIT 60", (dev["id"],)):
        try:
            us, ttl = (r["ja4l_c"] or "").split("_")
            lats.append((int(us), int(ttl)))
        except Exception:
            continue
    if lats:
        lats.sort()
        med_us, ttl_obs = lats[len(lats) // 2]
        out["lat_c_us_med"] = med_us
        out["ttl_obs"] = ttl_obs
        init = 64 if ttl_obs <= 64 else (128 if ttl_obs <= 128 else 255)
        out["hops_est"] = init - ttl_obs
        out["ja4l_c"] = "%d_%d" % (med_us, ttl_obs)
    if skews:
        skews.sort()
        out["skew_ppm"] = skews[len(skews) // 2]      # 中位（同连接内测量才有效）
        out["skew_samples"] = len(skews)
    # 在线时长：只有 TCP 时间戳以「启动时刻」为基准的栈才能由 TSval 推出来。
    # 实测依据：Windows（TTL 128、SYN 不带 TS? 实际带 TS 且 TSval 从 0 起算）可推；
    # Linux 的时间戳偏移是每连接随机化，无法推算 → 不给出结论。
    stack_is_win = bool((jload(dev.get("tcp_json")) or {}).get("init_ttl") == 128)
    if stack_is_win and synvals:
        v = max(synvals)
        up = v / 1000.0
        if 0 < up < 365 * 86400:
            out["uptime_s"] = int(up)
            out["uptime_reliable"] = True
    out["ts_samples"] = len(synvals)
    return out


def device_domains(dev, limit=300):
    """返回 (出口 IP 级域名, 共用该 IP 的指纹台数或 None, 该设备自己的 DoH 查询域名)。"""
    agg = {}
    own = {}
    ips = list((jload(dev.get("src_ips"), {}) or {}).keys())
    if ips:
        ph = ",".join("?" * len(ips))
        for r in qall("SELECT top_json FROM dns_hour WHERE ip IN (%s)" % ph, tuple(ips)):
            try:
                for item in (json.loads(r["top_json"] or "[]") or []):
                    if isinstance(item, list) and len(item) == 2:
                        agg[item[0]] = agg.get(item[0], 0) + int(item[1] or 0)
            except Exception:
                continue
        if not agg:
            for r in qall("SELECT qh, COUNT(*) n FROM dns_recent WHERE ip IN (%s) GROUP BY qh" % ph,
                          tuple(ips)):
                agg[r["qh"]] = agg.get(r["qh"], 0) + (r["n"] or 0)
    # 该设备自己的 DoH 请求（来自 nginx 日志，含查询名）→ 逐设备可归属
    for r in qall("SELECT qname, COUNT(*) n FROM doh_requests WHERE device_id=? AND qname IS NOT NULL"
                  " AND qname<>'' GROUP BY qname ORDER BY n DESC LIMIT ?", (dev["id"], limit)):
        own[r["qname"]] = own.get(r["qname"], 0) + (r["n"] or 0)
    # 该设备自己的 DoT 查询（AGH querylog 经 TLS 记录时间对齐归属）→ 同样逐设备可归属
    dot_aligned = 0
    for r in qall("SELECT qh, COUNT(*) n FROM dns_recent WHERE device_id=? AND qh<>''"
                  " GROUP BY qh ORDER BY n DESC LIMIT ?", (dev["id"], limit)):
        own[r["qh"]] = own.get(r["qh"], 0) + (r["n"] or 0)
        dot_aligned += r["n"] or 0
    # 该 IP 上是否还有别的指纹设备（NAT 共用出口）
    shared = 0
    for ip in ips:
        r = qone("SELECT COUNT(*) c FROM devices WHERE source='server' AND src_ips LIKE ?",
                 ('%"' + ip + '"%',))
        shared = max(shared, (r["c"] if r else 0))
    return (sorted(agg.items(), key=lambda kv: -kv[1])[:limit],
            (shared if shared > 1 else None),
            sorted(own.items(), key=lambda kv: -kv[1])[:limit])


def device_conn_stats(dev):
    ips = list((jload(dev.get("src_ips"), {}) or {}).keys())
    if not ips:
        return {}
    ph = ",".join("?" * len(ips))
    r = qone("SELECT COUNT(*) n, SUM(probe) probes, SUM(resumed) resumed,"
             " CAST(AVG(duration_ms) AS INTEGER) avg_dur_ms, MIN(ts) t0, MAX(ts) t1,"
             " SUM(q_est) q_est, SUM(resp_bytes) resp_bytes,"
             " CAST(AVG(q_rtt_ms) AS INTEGER) q_rtt_avg FROM conns WHERE device_id=?",
             (dev["id"],))
    out = dict(r) if r else {}
    q = qone("SELECT SUM(n) queries FROM dns_hour WHERE ip IN (%s)" % ph, tuple(ips))
    out["queries"] = (q["queries"] if q else 0) or 0      # 按出口 IP 统计（多指纹共用时不可归属）
    out["queries_est"] = out.get("q_est") or 0            # 按该指纹的 TLS 记录估算（可归属）
    kind = qall("SELECT kind, COUNT(*) n FROM conns WHERE device_id=? GROUP BY kind", (dev["id"],))
    out["kinds"] = dict((x["kind"], x["n"]) for x in kind)
    doh = qone("SELECT COUNT(*) n, SUM(CASE WHEN method='POST' THEN 1 ELSE 0 END) post FROM"
               " doh_requests WHERE device_id=?", (dev["id"],))
    out["doh"] = dict(doh) if doh else {}
    return out


# ---------------------------------------------------------------------------
# ① 本地指纹字典（零外传）：把「指纹 → 客户端软件」固化下来，新设备先查表
#    来源：seed（本网实测 + 已验证的栈规则）/ rule（推断置信中以上自动固化）/ manual（人工命名，最强）
# ---------------------------------------------------------------------------
_DICT_SEED = [
    # (kind, key, label, conf, basis)
    ("ja4_b", "8daaf6152771", "Chrome/BoringSSL 系 TLS 栈", 3,
     "FoxIO JA4 官方示例向量用的套件哈希（Chrome 系）"),
    ("ja4_b", "2b729b4bf6f3", "Windows Schannel（系统解析器/浏览器栈）", 3,
     "本网实测：TTL128、无 TCP 时间戳的 Windows 客户端专用该套件哈希"),
    ("ja4_b", "f57a46abbacb6", "Go crypto/tls 系", 3,
     "本网实测：Go 系客户端（含 ALPN=dot 变体）共用该套件哈希"),
    ("ja4_b", "5b57614c22b0", "Go crypto/tls 系（另一构建）", 2, "本网实测：Go 构建变体"),
    ("ja4_b", "1d37bd780c83", "OpenSSL 3.x 系", 2, "本网实测：OpenSSL 风格的扩展组合"),
    ("ja4_b", "e8a523a41297", "华为/荣耀系客户端栈", 2, "本网实测：该栈的查询域名族指向华为/荣耀生态"),
]


def dict_seed():
    """种子条目有明确依据，遇到同级或更低置信的规则条目时应当覆盖（种子优先）。"""
    for kind, key, label, conf, basis in _DICT_SEED:
        try:
            xrun("INSERT INTO fp_dict(kind,key,label,conf,source,basis,hits,created,updated)"
                 " VALUES(?,?,?,?,?,?,COALESCE((SELECT hits FROM fp_dict WHERE kind=? AND key=?),0),?,?)"
                 " ON CONFLICT(kind,key) DO UPDATE SET label=excluded.label,"
                 " conf=MAX(fp_dict.conf, excluded.conf), source=excluded.source,"
                 " basis=excluded.basis, updated=excluded.updated"
                 " WHERE fp_dict.conf <= excluded.conf",
                 (kind, key, label, conf, "seed", basis, kind, key, now(), now()))
        except Exception as e:
            log("种子写入失败 %s/%s: %s" % (kind, key, e))


def ja3_from_tls(tls):
    tls = tls or {}
    return tls.get("ja3")


def dict_lookup(tls, tcp_sig, ja3):
    """按精确度从高到低查：整条 JA4 → JA4 套件哈希 → JA3 → TCP 指纹。"""
    tls = tls or {}
    cands = []
    if tls.get("ja4"):
        cands.append(("ja4", tls["ja4"]))
        p = str(tls["ja4"]).split("_")
        if len(p) >= 2:
            cands.append(("ja4_b", p[1]))
    if ja3:
        cands.append(("ja3", ja3))
    if tcp_sig:
        cands.append(("tcp", tcp_sig))
    for kind, key in cands:
        if not key:
            continue
        r = qone("SELECT label, conf, source, basis, hits FROM fp_dict WHERE kind=? AND key=?",
                 (kind, key))
        if r and r["label"]:
            xrun("UPDATE fp_dict SET hits=COALESCE(hits,0)+1, updated=? WHERE kind=? AND key=?",
                 (now(), kind, key))
            return {"kind": kind, "key": key, "label": r["label"], "conf": r["conf"] or 1,
                    "source": r["source"], "basis": r["basis"], "hits": (r["hits"] or 0) + 1}
    return None


def dict_learn(tls, ja3, tcp_sig, label, conf, source, basis):
    """把（指纹 → 标签）写进字典；conf 越高越可信。整条 JA4 记得最全，ja4_b/ja3 次之。"""
    if not label or conf < 1:
        return
    tls = tls or {}
    items = []
    if tls.get("ja4"):
        items.append(("ja4", tls["ja4"], conf))
        p = str(tls["ja4"]).split("_")
        if len(p) >= 2:
            items.append(("ja4_b", p[1], max(1, conf - 1)))
    if ja3:
        items.append(("ja3", ja3, max(1, conf - 1)))
    for kind, key, c in items:
        try:
            xrun("INSERT INTO fp_dict(kind,key,label,conf,source,basis,hits,created,updated)"
                 " VALUES(?,?,?,?,?,?,0,?,?)"
                 " ON CONFLICT(kind,key) DO UPDATE SET label=excluded.label, conf=excluded.conf,"
                 " source=excluded.source, basis=excluded.basis, updated=excluded.updated"
                 " WHERE excluded.conf > fp_dict.conf",
                 (kind, key, trim(label, 120), c, source, trim(basis or "", 300), now(), now()))
        except Exception:
            # 老 SQLite 不支持 UPSERT 语法时退回「先查再写」
            r = qone("SELECT conf FROM fp_dict WHERE kind=? AND key=?", (kind, key))
            if r and (r["conf"] or 0) > c:
                continue
            xrun("INSERT OR REPLACE INTO fp_dict(kind,key,label,conf,source,basis,hits,created,updated)"
                 " VALUES(?,?,?,?,?,?,COALESCE((SELECT hits FROM fp_dict WHERE kind=? AND key=?),0),?,?)",
                 (kind, key, trim(label, 120), c, source, trim(basis or "", 300), kind, key, now(), now()))


# ---------------------------------------------------------------------------
# nDPI 接入：定时抓 15 秒 pcap（只抓 853/443/444）→ ndpiReader 离线判定协议/分类/风险
#   价值：它原生认 DoH_DoT / TLS.Mullvad 等协议并给出风险标签，是自研指纹之外的一层
# ---------------------------------------------------------------------------
def ndpi_run_once():
    """抓一段包跑一次 ndpiReader，把「入向客户端流」入库并归属到设备。返回处理条数。"""
    import subprocess
    binp = CFG.get("ndpi_bin") or "/opt/ndpi/ndpiReader"
    if not os.path.exists(binp):
        return 0, "未找到 ndpiReader（%s）" % binp
    ports = CFG.get("ndpi_ports", "853 443 444").split()
    bpf = " or ".join("tcp port %s" % p for p in ports)
    cap = "/tmp/ndpi-cap.pcap"
    out = "/tmp/ndpi-out.json"
    try:
        for f in (cap, out):
            if os.path.exists(f):
                os.remove(f)
    except Exception:
        pass
    tcp = "timeout %d tcpdump -i %s -w %s -s 0 -c %d '%s'" % (
        int(CFG.get("ndpi_capture_sec", 15)) + 5, CFG.get("iface", "eth0"), cap,
        int(CFG.get("ndpi_max_packets", 3000)), bpf)
    try:
        subprocess.call(tcp, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        return 0, "抓包失败: %s" % e
    if not os.path.exists(cap) or os.path.getsize(cap) < 100:
        return 0, "抓到 0 包"
    try:
        subprocess.call("%s -i %s -K json -k %s" % (binp, cap, out), shell=True,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=120)
    except Exception as e:
        return 0, "ndpiReader 失败: %s" % e
    if not os.path.exists(out):
        return 0, "没有 JSON 输出"
    ports_i = set(int(p) for p in ports)
    run_ts = int(now())
    n = 0
    try:
        with open(out) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    x = jload(line) or {}
                except Exception:
                    continue
                nd = x.get("ndpi") or {}
                dp, sp = x.get("dst_port"), x.get("src_port")
                if dp in ports_i:
                    cip, cport, svcport = x.get("dest_ip"), None, dp
                    cip = x.get("src_ip")
                    cport = x.get("src_port")
                elif sp in ports_i:
                    cip, cport, svcport = x.get("dest_ip"), x.get("dst_port"), sp
                else:
                    continue
                if cip == CFG.get("server_ip"):
                    continue
                risks = "、".join((r.get("risk") if isinstance(r, dict) else str(r))
                                 for r in (nd.get("flow_risk") or {}).values()) if isinstance(
                    nd.get("flow_risk"), dict) else ""
                fr = x.get("xfer")
                reqb = int(fr) if isinstance(fr, (int, float)) else 0
                pk = x.get("pktlen")
                did = None
                try:
                    r = qone("SELECT device_id FROM conns WHERE src_ip=? AND sport=? AND dport=?"
                             " ORDER BY ABS(ts-?) LIMIT 1", (cip, cport, svcport, run_ts))
                    if r and r["device_id"]:
                        did = r["device_id"]
                    else:
                        did = _ip_single_device(cip)
                except Exception:
                    did = None
                xrun("INSERT INTO ndpi_flows(run_ts,ip,sport,dport,proto,category,risks,bytes,pkts,"
                     "device_id,first_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                     (run_ts, cip, cport if cport is not None else -1, svcport,
                      trim(str(nd.get("proto") or "?"), 40), trim(str(nd.get("category") or ""), 40),
                      trim(risks, 200), reqb, int(pk) if isinstance(pk, (int, float)) else 0,
                      did, x.get("first_seen") or 0))
                n += 1
    except Exception as e:
        return n, "解析失败: %s" % e
    # 归属：给设备写上最常见的协议/分类/风险
    try:
        for r in qall("SELECT device_id, proto, COUNT(*) c FROM ndpi_flows WHERE device_id IS NOT NULL"
                      " GROUP BY device_id, proto ORDER BY c DESC"):
            pass
        for r in qall("SELECT DISTINCT device_id FROM ndpi_flows WHERE device_id IS NOT NULL"):
            did = r["device_id"]
            pr = qone("SELECT proto, COUNT(*) c FROM ndpi_flows WHERE device_id=? GROUP BY proto"
                      " ORDER BY c DESC LIMIT 1", (did,))
            ca = qone("SELECT category, COUNT(*) c FROM ndpi_flows WHERE device_id=? AND category<>''"
                      " GROUP BY category ORDER BY c DESC LIMIT 1", (did,))
            ri = qone("SELECT risks FROM ndpi_flows WHERE device_id=? AND risks<>'' LIMIT 1", (did,))
            xrun("UPDATE devices SET ndpi_proto=?, ndpi_category=?, ndpi_risk=? WHERE id=?",
                 (pr["proto"] if pr else None, ca["category"] if ca else None,
                  ri["risks"] if ri else None, did))
    except Exception as e:
        log("nDPI 归属失败: %s" % e)
    # 清理旧记录（保留 7 天）
    try:
        xrun("DELETE FROM ndpi_flows WHERE run_ts < ?", (run_ts - 7 * 86400,))
    except Exception:
        pass
    mark_dirty()
    return n, None


def ndpi_loop():
    time.sleep(int(CFG.get("ndpi_first_delay", 300)))
    while True:
        try:
            if CFG.get("ndpi_enable"):
                t0 = time.time()
                n, err = ndpi_run_once()
                if err:
                    log("nDPI：%s" % err)
                else:
                    log("nDPI：本轮入库 %d 条流（耗时 %.0fs）" % (n, time.time() - t0))
        except Exception as e:
            log("nDPI 循环异常: %s" % e)
        time.sleep(max(300, int(CFG.get("ndpi_interval", 1800))))


def device_behavior(dev):
    """行为指纹：全部来自已有数据（最近查询样本 + 连接记录），零新采集。
    输出人类可读摘要 + 结构化 JSON，用于区分「流水线大户 / 每查询建连 / 高重复重试」等客户端类型。"""
    out = {}
    rows = qall("SELECT ts,qh,filtered,rule FROM dns_recent WHERE device_id=? AND qh<>''"
                " ORDER BY id DESC LIMIT 3000", (dev["id"],))
    if rows:
        rows.sort(key=lambda r: r["ts"])
        n = len(rows)
        doms = set(r["qh"] for r in rows)
        last = {}
        rep = 0
        for r in rows:
            p = last.get(r["qh"])
            if p is not None and r["ts"] - p <= 3:
                rep += 1
            last[r["qh"]] = r["ts"]
        gaps = sorted(b["ts"] - a["ts"] for a, b in zip(rows, rows[1:]))
        cnt = {}
        for r in rows:
            cnt[r["qh"]] = cnt.get(r["qh"], 0) + 1
        top = max(cnt.values()) if cnt else 1
        filt = [r for r in rows if r["filtered"]]
        out["queries"] = n
        out["domains"] = len(doms)
        out["repeat3s_pct"] = round(100.0 * rep / n, 1)
        out["top_dom_share_pct"] = round(100.0 * top / n, 1)
        out["gap_med_s"] = gaps[len(gaps) // 2] if gaps else 0
        out["gap_p95_s"] = gaps[int(len(gaps) * 0.95)] if gaps else 0
        out["filtered_pct"] = round(100.0 * len(filt) / n, 1)
        if filt:
            rc = {}
            for r in filt:
                k = (r["rule"] or "未标注规则")[:70]
                rc[k] = rc.get(k, 0) + 1
            out["top_rules"] = sorted(rc.items(), key=lambda kv: -kv[1])[:3]
    cc = qall("SELECT req_rec,duration_ms,resumed FROM conns WHERE device_id=?"
              " AND kind IN ('dot','doh443','doh444') ORDER BY id DESC LIMIT 200", (dev["id"],))
    if cc:
        p = sorted((x["req_rec"] or 0) for x in cc)
        out["conns"] = len(cc)
        out["q_per_conn_med"] = p[len(p) // 2]
        out["q_per_conn_max"] = p[-1]
        out["long_conn_pct"] = round(100.0 * sum(1 for x in cc if (x["duration_ms"] or 0) > 60000) / len(cc), 1)
        out["resume_pct"] = round(100.0 * sum(1 for x in cc if x["resumed"]) / len(cc), 1)
    tk = qone("SELECT psk_ident, COUNT(*) n FROM conns WHERE device_id=? AND psk_ident IS NOT NULL"
              " AND ticket_age IS NOT NULL GROUP BY psk_ident ORDER BY n DESC LIMIT 1", (dev["id"],))
    if tk and tk["n"]:
        out["ticket_reuse"] = tk["n"]
        # 同一张票的 obfuscated_ticket_age 差值 = 真实流逝毫秒（ticket_age_add 抵消），
        # 但它是 32 位计数器会回绕 → 必须按时间顺序取首尾并模 2^32
        smp = qall("SELECT ts,ticket_age FROM conns WHERE device_id=? AND psk_ident=?"
                   " AND ticket_age IS NOT NULL ORDER BY ts LIMIT 40", (dev["id"], tk["psk_ident"]))
        if len(smp) >= 2:
            span = (int(smp[-1]["ticket_age"]) - int(smp[0]["ticket_age"])) % (2 ** 32)
            if 0 < span < 30 * 86400 * 1000:
                out["ticket_span_s"] = int(span / 1000)
    if dev.get("dns_cookie"):
        out["dns_cookie"] = dev["dns_cookie"]
    if dev.get("ddr_count"):
        out["ddr"] = dev["ddr_count"]
    parts = []
    if out.get("ticket_reuse"):
        s = "TLS 会话票复用 %s 次" % out["ticket_reuse"]
        sp = out.get("ticket_span_s")
        if sp is not None and sp > 0:
            if sp < 60:
                s += "（同一张票观测跨度 %s 秒）" % sp
            elif sp < 7200:
                s += "（同一张票观测跨度 %s 分钟，可视为客户端会话持续时长）" % round(sp / 60.0, 1)
            else:
                s += "（同一张票观测跨度 %s 小时）" % round(sp / 3600.0, 1)
        parts.append(s)
    if out.get("dns_cookie"):
        parts.append("已采纳 DNS COOKIE 稳定 ID")
    if out.get("ddr"):
        parts.append("做过 DDR(RFC9462) 探测 %s 次" % out["ddr"])
    if out.get("q_per_conn_med") is not None:
        if out["q_per_conn_med"] >= 50:
            parts.append("单连接深度流水线（中位 %d 条/连接，最多 %d）" % (out["q_per_conn_med"], out.get("q_per_conn_max", 0)))
        elif out["q_per_conn_med"] <= 4:
            parts.append("每查询建连型（中位 %d 条/连接）" % out["q_per_conn_med"])
        else:
            parts.append("混合连接模型（中位 %d 条/连接）" % out["q_per_conn_med"])
        if out.get("long_conn_pct"):
            parts.append("长连接占 %s%%" % out["long_conn_pct"])
        if out.get("resume_pct"):
            parts.append("会话复用 %s%%" % out["resume_pct"])
    if out.get("repeat3s_pct") is not None:
        parts.append("3 秒内重复查询 %s%%" % out["repeat3s_pct"])
        parts.append("域名集中度 Top1 %s%%" % out["top_dom_share_pct"])
        parts.append("查询间隔中位 %ss（p95 %ss）" % (out.get("gap_med_s"), out.get("gap_p95_s")))
    if out.get("filtered_pct") is not None:
        parts.append("拦截率 %s%%" % out["filtered_pct"])
    if out.get("top_rules"):
        parts.append("Top 拦截规则：" + "、".join("%s×%s" % (k, v) for k, v in out["top_rules"]))
    out["summary"] = "；".join(parts)
    return out


_TEST_QH = (".dotprobe.cn", ".dotbatch.cn", ".dfp-align", ".doffprobe", ".chtest",
             ".dfp-aligntest")


def device_probe_class(dev, dot_conns=None):
    """识别「扫描器」与「自测探针」——这两类不该计入「用了 DoT/DoH 的设备」。"""
    ips = list((jload(dev.get("src_ips"), {}) or {}).keys())
    conns = dev.get("conn_count") or 0
    qn = qone("SELECT COUNT(*) c FROM dns_recent WHERE device_id=?", (dev["id"],))
    nq = (qn["c"] if qn else 0) or 0
    # 自测探针：查询名带测试标记
    t = qone("SELECT COUNT(*) c FROM dns_recent WHERE device_id=? AND (qh LIKE '%.dotprobe.cn'"
             " OR qh LIKE '%.dotbatch.cn' OR qh LIKE '%.dfp-align%' OR qh LIKE '%.doffprobe%'"
             " OR qh LIKE '%.chtest%' OR qh LIKE '%.dfp-aligntest%')", (dev["id"],))
    if t and (t["c"] or 0) > 0:
        return "self_test"
    # 扫描器：连接很少、几乎没查询、无 SNI/ALPN，且同一 IP 下出现多个 TLS 版本家族
    if conns <= 10 and nq == 0:
        ja4 = dev.get("ja4") or ""
        no_sni = (not ja4) or ("i" == ja4[4:5])
        if no_sni and ips:
            fams = set()
            rows = qall("SELECT ja4 FROM devices WHERE source='server' AND src_ips LIKE ?"
                        " AND ja4 IS NOT NULL AND ja4<>''", ('%"' + ips[0] + '"%',))
            for r in rows:
                j = r["ja4"] or ""
                if len(j) >= 5:
                    fams.add(j[1:5])
            if len(fams) >= 2:
                return "scanner"
    return None


def _ja4_parts(ja4):
    """(a, b, c) —— b 是套件哈希，c 是扩展+签名哈希，a 含版本/SNI/ALPN。"""
    p = (ja4 or "").split("_")
    return (p + ["", "", ""])[:3]


def cluster_devices():
    """把指纹合并成「物理客户端」：强证据（同一张会话票 / 同 IP+同套件哈希+同 TCP 指纹 / 同 IP+同栈家族）。
    扫描器与自测探针被单独归类，不参与合并。"""
    devs = [dict(r) for r in qall("SELECT * FROM devices WHERE source='server'")]
    pc = {}
    for d in devs:
        try:
            pc[d["id"]] = device_probe_class(d)
            xrun("UPDATE devices SET probe_class=? WHERE id=?", (pc[d["id"]], d["id"]))
        except Exception:
            pc[d["id"]] = None
    parent = {d["id"]: d["id"] for d in devs}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    ev = {}

    def union(a, b, why):
        ra, rb = find(a), find(b)
        if ra == rb:
            return
        parent[max(ra, rb)] = min(ra, rb)
        ev.setdefault(min(ra, rb), []).append(why)

    byid = {d["id"]: d for d in devs}
    # 证据①：同一张会话票出现在多个指纹 → 同一客户端进程
    for r in qall("SELECT psk_ident, group_concat(distinct device_id) ids FROM conns"
                  " WHERE psk_ident IS NOT NULL GROUP BY psk_ident HAVING COUNT(distinct device_id)>1"):
        ids = [int(x) for x in (r["ids"] or "").split(",") if x.strip().isdigit()]
        for i in range(1, len(ids)):
            if pc.get(ids[0]) is not None or pc.get(ids[i]) is not None:
                continue
            # 必须同 IP（同一张票跨 IP 更可能是 NAT 迁移或重放，不作为合并依据）
            ia = set(jload(byid[ids[0]].get("src_ips"), {}) or {})
            ib = set(jload(byid[ids[i]].get("src_ips"), {}) or {})
            if ia & ib:
                union(ids[0], ids[i], "同一张 TLS 会话票 %s…（同客户端进程）" % r["psk_ident"][:12])
    # 证据②③④：同 IP 下按 TCP 指纹 + 套件哈希 + 栈家族
    byip = {}
    for d in devs:
        if pc.get(d["id"]):
            continue
        for ip in (jload(d.get("src_ips"), {}) or {}):
            byip.setdefault(ip, []).append(d)
    for ip, lst in byip.items():
        for i in range(len(lst)):
            for j in range(i + 1, len(lst)):
                a, b = lst[i], lst[j]
                if find(a["id"]) == find(b["id"]):
                    continue
                sa, sb = a.get("tcp_sig"), b.get("tcp_sig")
                if not sa or sa != sb:
                    continue
                _, ab, _ = _ja4_parts(a.get("ja4"))
                _, bb, _ = _ja4_parts(b.get("ja4"))
                aa, bb2 = (a.get("ja4") or ""), (b.get("ja4") or "")
                if ab and ab == bb:
                    union(a["id"], b["id"], "同 IP + 同 TCP 指纹 + 同套件哈希 %s（同一 TLS 库的两个入口）" % ab[:8])
                elif len(aa) >= 5 and len(bb2) >= 5 and aa[1:5] == bb2[1:5]:
                    union(a["id"], b["id"], "同 IP + 同 TCP 指纹 + 同栈家族 %s" % aa[1:5])
    # 落库
    groups = {}
    for d in devs:
        groups.setdefault(find(d["id"]), []).append(d)
    xrun("DELETE FROM clusters")
    n = 0
    for root, members in groups.items():
        n += 1
        members.sort(key=lambda x: -(x.get("conn_count") or 0))
        ids = [m["id"] for m in members]
        tot = sum((m.get("conn_count") or 0) for m in members)
        ips = sorted(set(k for m in members for k in (jload(m.get("src_ips"), {}) or {})))
        klass = pc.get(members[0]["id"]) or None
        best = members[0]
        sw = []
        j0 = best.get("ja4") or ""
        if j0.startswith("t13d") or j0.startswith("t13i"):
            sw.append("TLS1.3")
        if klass == "scanner":
            sw.append("扫描/探测")
        elif klass == "self_test":
            sw.append("自测探针")
        nm = "%s%s" % ((best.get("vendor") or "未识别"), ("（%d 个指纹）" % len(ids)) if len(ids) > 1 else "")
        nq = 0
        try:
            ph = ",".join("?" * len(ids))
            rr = qone("SELECT COUNT(*) c FROM dns_recent WHERE device_id IN (%s)" % ph, tuple(ids))
            nq = (rr["c"] if rr else 0) or 0
        except Exception:
            nq = 0
        active = 1 if (tot >= 20 or nq >= 20) else 0
        noisy = 1 if (tot <= 3 and nq == 0) else 0
        evs = " ".join(ev.get(root, []))
        conf = "high" if "会话票" in evs else ("mid" if "套件哈希" in evs else ("low" if "栈家族" in evs else None))
        xrun("INSERT INTO clusters(id,name,member_ids,n_members,n_conns,ips,evidence,probe_class,"
             "first_seen,last_seen,sw_guess,updated,n_q,active,noise,conf)"
             " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
             (n, nm, jdump(ids), len(ids), tot, jdump(ips),
              jdump(ev.get(root, []))[:4000], klass,
              min((m.get("first_seen") or 0) for m in members),
              max((m.get("last_seen") or 0) for m in members),
              "、".join(sw), now(), nq, active, noisy, conf))
        for m in members:
            xrun("UPDATE devices SET cluster_id=? WHERE id=?", (n, m["id"]))
    try:
        CLUSTER_MAP.clear()
        for r in qall("SELECT * FROM clusters"):
            CLUSTER_MAP[r["id"]] = dict(r)
    except Exception:
        pass
    mark_dirty()
    return n


def reinfer_device(dev_row):
    dev = dict(dev_row)
    tls = jload(dev.get("tls_json")) or {}
    tcp = jload(dev.get("tcp_json")) or {}
    http = jload(dev.get("http_json")) or {}
    doms, shared, own = device_domains(dev)
    cs = device_conn_stats(dev)
    tex = device_tcp_extras(dev)
    # 版本线索：TLS 栈结构 + 是否查过 HTTPS/SVCB 记录
    stack0, _sc, _sev = tls_stack_guess(tls)
    uses_h3 = False
    ips0 = list((jload(dev.get("src_ips"), {}) or {}).keys())
    if ips0:
        ph0 = ",".join("?" * len(ips0))
        r0 = qone("SELECT SUM(https) h FROM dns_hour WHERE ip IN (%s)" % ph0, tuple(ips0))
        uses_h3 = bool(r0 and (r0["h"] or 0) > 0)
    vh = tls_version_hint(tls, stack0, uses_h3)
    res = infer_device(dev, tls, tcp, http, doms, cs, dom_shared=shared, own_domains=own,
                       tcp_extras=tex, version_hint=vh)
    # 行为指纹（零新采集）
    try:
        beh = device_behavior(dev)
    except Exception as e:
        beh = {"summary": None, "error": str(e)[:80]}
    res["behavior"] = beh
    if beh.get("summary"):
        res["evidence"] = (res.get("evidence") or []) + [
            {"k": "行为", "w": 0, "why": beh["summary"]}]
    try:
        _cf = {"高": 3, "中": 2, "低": 1}.get(res.get("confidence") or "", 0)
        # 指纹（JA4/JA3）级条目用**协议栈标签**（软件指纹，稳定）；厂商/域名推断标签最多 conf 2
        _stk = res.get("stack")
        if _stk:
            dict_learn(tls, ja3_from_tls(tls), None, _stk, 3, "rule",
                       "TLS 栈结构判定（%s）" % (res.get("stack_conf") or "?"))
        if _cf >= 2 and res.get("label") and "未识别" not in res["label"]:
            dict_learn(tls, ja3_from_tls(tls), (tcp or {}).get("sig"), res["label"],
                       min(_cf, 2), "rule", "推断引擎给出（%s 置信）" % res.get("confidence"))
    except Exception as e:
        log("字典固化失败 device#%s: %s" % (dev["id"], e))
    res["top_domains"] = [d for d, _ in (own or doms)[:15]]
    res["own_domains"] = [d for d, _ in own[:20]]
    res["dom_shared"] = shared
    _da = qone("SELECT COUNT(*) c FROM dns_recent WHERE device_id=?", (dev["id"],))
    dcs = {"dot_aligned": (_da["c"] if _da else 0) or 0}
    res["dot_aligned_queries"] = dcs["dot_aligned"]
    res["domains_source"] = ("device-doh+dot" if own and dcs["dot_aligned"]
                             else ("device-doh" if own and not dcs["dot_aligned"]
                                   else ("device-dot" if dcs["dot_aligned"]
                                         else ("shared-ip" if shared else "ip"))))
    res["tcp_extras"] = tex
    res["ts"] = now()
    # DoT 明文画像（来自 dotfront 前置终结器）：EDNS 选项、DO 位、UDP 缓冲、0x20、qtype 分布
    prof = []
    ep = qone("SELECT COUNT(*) n, SUM(do_bit) dos, SUM(mixed) mx,"
              " SUM(CASE WHEN edns LIKE '%PAD%' THEN 1 ELSE 0 END) pad,"
              " SUM(CASE WHEN edns LIKE '%COOKIE%' THEN 1 ELSE 0 END) ck,"
              " SUM(CASE WHEN edns LIKE '%ECS%' THEN 1 ELSE 0 END) ecs,"
              " SUM(CASE WHEN udp_size>=4096 THEN 1 ELSE 0 END) big"
              " FROM dns_recent WHERE device_id=? AND src LIKE 'dotfront%'", (dev["id"],))
    dotq = (ep["n"] if ep else 0) or 0
    _dq = qone("SELECT COUNT(*) n FROM dns_recent WHERE device_id=? AND cp='dot'", (dev["id"],))
    dotq_tls = (_dq["n"] if _dq else 0) or 0
    if dotq:
        prof.append("明文查询样本 %d 条" % dotq)
        if ep["dos"]:
            prof.append("DO 位 %.0f%%" % (100.0 * ep["dos"] / dotq))
        if ep["pad"]:
            prof.append("EDNS PADDING %.0f%%" % (100.0 * ep["pad"] / dotq))
        if ep["ck"]:
            prof.append("EDNS COOKIE %.0f%%" % (100.0 * ep["ck"] / dotq))
        if ep["ecs"]:
            prof.append("ECS %.0f%%" % (100.0 * ep["ecs"] / dotq))
        if ep["big"]:
            prof.append("宣称 UDP≥4096 %.0f%%" % (100.0 * ep["big"] / dotq))
        if ep["mx"]:
            prof.append("0x20 随机化 %.0f%%" % (100.0 * ep["mx"] / dotq))
        qt = qall("SELECT qt, COUNT(*) n FROM dns_recent WHERE device_id=? AND src LIKE 'dotfront%'"
                  " GROUP BY qt ORDER BY n DESC LIMIT 5", (dev["id"],))
        if qt:
            prof.append("qtype " + "、".join("%s×%s" % (x["qt"], x["n"]) for x in qt))
        padsz = qall("SELECT edns FROM dns_recent WHERE device_id=? AND src LIKE 'dotfront%'"
                     " AND edns LIKE '%\"padding\":%' LIMIT 20", (dev["id"],))
        if padsz:
            pvals = []
            for x in padsz:
                try:
                    pv = json.loads(x["edns"] or "{}").get("padding")
                except Exception:
                    pv = None
                if pv and str(pv) not in pvals:
                    pvals.append(str(pv))
            if pvals:
                prof.append("padding 值 " + "、".join(pvals[:5]))
    edns_profile = "；".join(prof) if prof else None
    res["edns_profile"] = edns_profile
    res["dot_queries"] = dotq_tls
    if edns_profile:
        res["evidence"] = (res.get("evidence") or []) + [
            {"k": "DoT 明文", "w": 0, "why": edns_profile}]
    xrun("UPDATE devices SET vendor=?, device_class=?, role=?, confidence=?, infer_ts=?,"
         " infer_json=?, top_domains=?, uptime_s=?, skew_ppm=?, ipid_class=?, retrans_rate=?,"
         " os_version_hint=?, edns_profile=?, dot_queries=?, behavior=?, behavior_json=?"
         " WHERE id=?",
         (res.get("label"), res.get("class"), res.get("role"),
          res.get("confidence"), res["ts"], jdump(res), jdump(res["top_domains"]),
          tex.get("uptime_s"), tex.get("skew_ppm"), tex.get("ipid_class"),
          tex.get("retrans_rate"), res.get("version_hint"), res.get("edns_profile"),
          res.get("dot_queries"), beh.get("summary"), jdump(beh), dev["id"]))
    mark_dirty()
    return res


_CLUSTER_TS = [0]


def reinfer_all(limit=None, force=False):
    """force=False 时只重算数据有变化的设备（增量）；force=True 时全量重算。"""
    _post = True
    if force:
        rows = qall("SELECT * FROM devices WHERE source='server' ORDER BY last_seen DESC LIMIT ?",
                    (limit or 500,))
    else:
        rows = qall("SELECT * FROM devices WHERE source='server'"
                    " AND (infer_ts IS NULL OR last_seen > infer_ts)"
                    " ORDER BY last_seen DESC LIMIT ?", (limit or 500,))
    n = 0
    for r in rows:
        try:
            reinfer_device(r)
            n += 1
        except Exception as e:
            log("推断失败 device#%s: %s" % (r["id"], e))
    if _post and (force or n):
        gap = int(CFG.get("cluster_min_interval", 300))
        if force or (time.time() - _CLUSTER_TS[0] >= gap):
            try:
                nc = cluster_devices()
                _CLUSTER_TS[0] = time.time()
                log("物理客户端聚合完成：%d 个簇" % nc)
            except Exception as e:
                log("聚合失败: %s" % e)
    return n


def reinfer_loop():
    time.sleep(20)          # 启动后先等采集跑一会儿再推断
    try:
        log("首次全量推断完成：%d 台设备" % reinfer_all(force=True))
    except Exception as e:
        log("首次推断异常: %s" % e)
    k = 0
    full_every = max(1, int(CFG.get("reinfer_full_every", 12)))
    while True:
        time.sleep(int(CFG.get("reinfer_interval", 600)))
        k += 1
        try:
            f = (k % full_every == 0)
            n = reinfer_all(force=f)
            log("%s推断完成：%d 台设备" % ("全量" if f else "增量", n))
        except Exception as e:
            log("推断异常: %s" % e)


# ---------------------------------------------------------------------------
# 抓包 + 连接跟踪
# ---------------------------------------------------------------------------

CONNS = {}
CONNS_LOCK = threading.Lock()
SNIFF_STATS = {"packets": 0, "tcp": 0, "tls": 0, "udp": 0, "errors": 0,
               "syn_in": 0, "new_conn": 0, "ch_seed": 0, "ch_fail": 0, "retrans": 0}
DBG = [0]


def dbg(msg):
    if DBG[0] < 400:
        DBG[0] += 1
        log("DBG " + msg)


def kind_of(dport):
    if dport == 853:
        return "dot"
    if dport == 444:
        return "doh444"
    if dport == 443:
        return "tls443"
    return "other"


def scan_tls_records(buf, want=0x17):
    """统计 TLS 记录：返回 (条数, 字节数)。只数 want 类型（0x17=application_data）。
    DoT/DoH 里一条 DNS 消息≈一条应用数据记录，因此可按指纹估算「查询次数/应答大小」。"""
    n = b = 0
    o = 0
    ln_buf = len(buf)
    while o + 5 <= ln_buf:
        typ = buf[o]
        ln = (buf[o + 3] << 8) | buf[o + 4]
        if o + 5 + ln > ln_buf:
            break
        if typ == want:
            n += 1
            b += ln
        o += 5 + ln
    return n, b


def _count_app_data(c, buf, t_now):
    """累计 TLS 应用数据记录（≈ DNS 查询条数），并记下「还在等应答」的时刻。"""
    if not buf:
        return
    n17, b17 = scan_tls_records(buf)
    if n17:
        c["req_rec"] = c.get("req_rec", 0) + n17
        c["req_bytes"] = c.get("req_bytes", 0) + b17
        if not c.get("t_lastreq"):
            c["t_lastreq"] = t_now
        # 记事件：供 AGH querylog 的查询做时间对齐归属（每条查询记录一条）
        try:
            key = c.get("device_key") or fp_key_for(c.get("ja3"), c.get("ja4"),
                                                    (c.get("tcp") or {}).get("sig"), c["src_ip"])
            if key:
                for _ in range(min(n17, 4)):
                    _note_req(c["src_ip"], key, c.get("sport"), t_now,
                              is_dot=(c.get("dport") in (853, 8854)))
        except Exception:
            pass


def _flush_conn(c, segment=False):
    if c.get("flushed") and not segment:
        return
    if not segment:
        c["flushed"] = True
    ja3 = c.get("ja3")
    ja4 = c.get("ja4")
    tcp = c.get("tcp") or {}
    tcp_sig = tcp.get("sig")
    ip = c["src_ip"]
    key = fp_key_for(ja3, ja4, tcp_sig, ip)
    kind = c["kind"]
    if kind == "tls443" and not c.get("confirmed_doh"):
        # 443 上无法区分 DoH 与普通网页访问，先记为待定；由 nginx 日志确认后提升
        kind_store = "tls443"
    else:
        kind_store = kind
    patch = {}
    if c.get("tls"):
        patch["tls_json"] = jdump(c["tls"])
        patch["ja3"] = ja3
        patch["ja4"] = ja4
        patch["ja3_str"] = trim(c["tls"].get("ja3_str"), 900)
        patch["ja4_a"] = c["tls"].get("ja4_a")
        patch["ja4_b"] = c["tls"].get("ja4_b")
        patch["ja4_c"] = c["tls"].get("ja4_c")
        patch["ja4_o"] = trim(c["tls"].get("ja4_o"), 900)
        patch["sni"] = c["tls"].get("sni")
        patch["alpn"] = ",".join(c["tls"].get("alpn") or []) or None
        patch["app_guess"] = app_guess_from(c.get("ua"), c["tls"].get("alpn"),
                                           c["tls"].get("version"), c["tls"].get("sni"),
                                           c["dport"])
    if tcp:
        patch["tcp_json"] = jdump(tcp)
        patch["tcp_sig"] = tcp.get("sig")
        patch["os_guess"] = tcp.get("os_guess")
        patch["os_confidence"] = tcp.get("os_confidence")
    if c.get("tls") is None and c["dport"] in (853, 444):
        c["probe"] = 1
    if DBG[0] < 400 and CFG.get("debug"):
        dbg("FLUSH %s:%d→%d rtt=%s in_pkts=%d out_pkts=%d t_first=%s t_synack=%s" % (
            ip, c["sport"], c["dport"],
            ("%.3f" % c["rtt_ms"]) if c.get("rtt_ms") is not None else "None",
            c.get("in_pkts", 0), c.get("out_pkts", 0),
            ("%.6f" % c["t_first"]) if c.get("t_first") else None,
            ("%.6f" % c["t_synack"]) if c.get("t_synack") else None))
    variant = {"fp": (ja4 or ja3 or tcp_sig or "?"), "kind": kind_store,
               "first": c["first_ts"], "last": c["last_ts"], "n": 1}
    if key is None:
        # 无法指纹化（重启前建立的长连接中段数据）→ 只落连接记录，不建虚拟设备
        SNIFF_STATS["unfingerprinted"] = SNIFF_STATS.get("unfingerprinted", 0) + 1
        did = None
    else:
        did = dev_touch(key, patch, inc_conn=1, inc_bytes_in=c.get("in_bytes", 0),
                        inc_bytes_out=c.get("out_bytes", 0), proto_kind=kind_store,
                        variant=variant, ip=ip)
    if not c.get("tcp"):
        SNIFF_STATS["no_syn"] = SNIFF_STATS.get("no_syn", 0) + 1
    if (c.get("tls") or {}).get("ja3") is None and c.get("dport") in (853, 444):
        SNIFF_STATS["no_ch"] = SNIFF_STATS.get("no_ch", 0) + 1
    alpn_store = None
    if (c.get("sh") or {}).get("alpn"):
        alpn_store = c["sh"]["alpn"]
    elif (c.get("tls") or {}).get("alpn"):
        alpn_store = ",".join(c["tls"]["alpn"])
    # JA4L（官方格式：微秒_TTL）。C=客户端 ACK 到达，B=本机发出 SYN-ACK，A=收到 SYN
    ja4l_c = ja4l_s = None
    if c.get("rtt_ms") is not None:
        try:
            lat_c = int(c["rtt_ms"] * 1000 / 2)
            ttl_c = (tcp or {}).get("ttl")
            ja4l_c = "%d_%s" % (lat_c, ttl_c if ttl_c else "0")
        except Exception:
            ja4l_c = None
    try:
        if c.get("t_synack") and c.get("t_first"):
            ja4l_s = "%d_64" % int((c["t_synack"] - c["t_first"]) * 1000000 / 2)
    except Exception:
        ja4l_s = None
    req_rec = c.get("req_rec", 0)
    resp_rec = c.get("resp_rec", 0)
    q_est = min(req_rec, resp_rec) if (req_rec and resp_rec) else (req_rec or 0)
    c_skew = None
    if c.get("tsv_t0") and c.get("tsv_t1") and c["tsv_t1"] - c["tsv_t0"] >= 5.0:
        dw = c["tsv_t1"] - c["tsv_t0"]
        dv = c["tsv_v1"] - c["tsv_v0"]
        # 只接受合理范围内的结果：真实晶振漂移在 ±几百 ppm，超出说明样本被混了（重连/复用）
        if dv > 0:
            ratio = dv / (dw * 1000.0)
            if 0.998 <= ratio <= 1.002:
                c_skew = int(round((ratio - 1.0) * 1000000))
    rtts = c.get("rtts") or []
    q_rtt = None
    if rtts:
        srt = sorted(rtts)
        q_rtt = round(srt[len(srt) // 2], 2)
    xrun("INSERT INTO conns(device_id,ts,end_ts,src_ip,sport,dport,kind,ja3,ja4,tls_ver,"
         "cipher,alpn,sni,resumed,cert_bytes,cert_count,in_bytes,out_bytes,in_pkts,out_pkts,"
         "duration_ms,rtt_ms,probe,tcp_sig,tcp_json,tls_json,req_rec,resp_rec,resp_bytes,q_est,q_rtt_ms,"
         "partial,tsval,retrans,skew_ppm,psk,ticket_age,psk_ident,ja4t,ja4l_c,ja4l_s,ip_id)"
         " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
         (did, c["first_ts"], c["last_ts"], ip, c["sport"], c["dport"], kind_store, ja3, ja4,
          (c.get("sh") or {}).get("version"), (c.get("sh") or {}).get("cipher"),
          alpn_store, (c.get("tls") or {}).get("sni"),
          1 if (c.get("sh") or {}).get("resumed_psk") else 0,
          (c.get("cert") or {}).get("cert_bytes"), (c.get("cert") or {}).get("cert_count"),
          c.get("in_bytes", 0), c.get("out_bytes", 0), c.get("in_pkts", 0), c.get("out_pkts", 0),
          int((c["last_ts"] - c["first_ts"]) * 1000),
          round(c["rtt_ms"], 2) if c.get("rtt_ms") is not None else None,
          1 if c.get("probe") else 0, tcp_sig,
          # 2026-10-09 大字段瘦身：tcp_json(14.8MB)/tls_json(82.4MB) 不再写入。
          # tls_json 全库无读取方；tcp_json 的读取方 device_tcp_extras() 用
          # "tcp_json IS NOT NULL" + try/except，写 NULL 后新行自然排除。
          # 归一化列 ja3/ja4/ja4t/ja4l_c/ja4l_s/tcp_sig/tls_ver/cipher/alpn/sni/resumed 保留；
          # 同函数 (tcp or {}).get("tsval"/"ja4t") 仍照常计算。
          None, None,
          req_rec, resp_rec, c.get("resp_bytes", 0), q_est, q_rtt, 1 if segment else 0,
          (tcp or {}).get("tsval"), c.get("retrans", 0), c_skew,
         1 if c.get("psk") else 0, c.get("ticket_age"), (c.get("psk_ident") or None),
          (tcp or {}).get("ja4t"), ja4l_c, ja4l_s, (tcp or {}).get("ip_id")))
    if segment:
        # 长连接分段落库：保留连接跟踪，只把计数器清零，下一段继续累计
        for k in ("req_rec", "resp_rec", "resp_bytes", "in_bytes", "out_bytes",
                  "in_pkts", "out_pkts", "t_lastreq"):
            c[k] = 0
        c["rtts"] = []
        c["first_ts"] = c["last_ts"]
    c["device_key"] = key
    c["device_id"] = did


def reaper_loop():
    while True:
        time.sleep(0.7)
        t = time.time()
        with CONNS_LOCK:
            dead = [k for k, c in CONNS.items()
                    if t - c["last_seen"] > CFG["conn_idle_flush"]
                    or (c.get("fin") and t - c["last_seen"] > 0.3)]
            items = [CONNS.pop(k) for k in dead]
            # 长连接分段落库：活跃但已经跑了很久的连接，先把累计的查询/记录落库，
            # 否则「带查询的长连接」要等到断开才可见
            seg = int(CFG.get("long_conn_segment", 300))
            segs = [c for c in CONNS.values()
                    if (c.get("req_rec") or c.get("resp_rec")) and t - c.get("t_first", t) > seg]
            if len(CONNS) > CFG["max_conns"]:
                oldest = sorted(CONNS.items(), key=lambda kv: kv[1]["last_seen"])
                for k, _ in oldest[:200]:
                    items.append(CONNS.pop(k))
        for c in items:
            try:
                _flush_conn(c)
            except Exception:
                log("flush 连接失败: %s" % traceback.format_exc().splitlines()[-1])
        for c in segs:
            try:
                _flush_conn(c, segment=True)
            except Exception:
                log("分段 flush 失败: %s" % traceback.format_exc().splitlines()[-1])


def _conn_get(src_ip, sport, dport, ttl, win, ip_id, df, opts, first_ts=None):
    with CONNS_LOCK:
        c = CONNS.get((src_ip, sport, dport))
        if c is None:
            c = {"src_ip": src_ip, "sport": sport, "dport": dport,
                 "kind": kind_of(dport), "first_ts": first_ts or now(),
                 "last_ts": first_ts or now(), "last_seen": time.time(),
                 "in_bytes": 0, "out_bytes": 0, "in_pkts": 0, "out_pkts": 0,
                 "ch_buf": b"", "ch_done": False, "ch_need": 0, "sh_done": False}
            CONNS[(src_ip, sport, dport)] = c
        return c


def sniff_loop():
    iface = CFG["iface"]
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        # 内核 socket 缓冲尽量拉大，避免高频短连接时丢 SYN（丢一个 SYN 就少一条 TCP 指纹）
        try:
            want = int(CFG.get("sock_rcvbuf", 8388608))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, want)
        except Exception as e:
            log("设置 SO_RCVBUF 失败: %s" % e)
        # 用内核到达时间戳，否则 RTT 只反映"我们的处理间隔"
        # 注意：本机内核只回 SO_TIMESTAMP(29) 的 cmsg（timeval64），SO_TIMESTAMPNS(35) 不生效，
        # 两个都开、按 cmsg 类型解析。
        for opt in (getattr(socket, "SO_TIMESTAMPNS", 35), 29):
            try:
                s.setsockopt(socket.SOL_SOCKET, opt, 1)
            except Exception as e:
                log("启用时间戳选项 %s 失败: %s" % (opt, e))
        s.bind((iface, 0))
        s.settimeout(2.0)
    except Exception as e:
        log("抓包套接字打开失败（%s）：%s" % (iface, e))
        return
    rb = s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    log("开始被动抓包 iface=%s ports=%s 内核缓冲=%d 字节" % (iface, CFG["tls_ports"], rb))
    ports = set(CFG["tls_ports"])
    _MEMINFO = getattr(socket, "SO_MEMINFO", 55)
    last_mem = [0.0]
    while True:
        try:
            data, ancdata, flags, saddr = s.recvmsg(65535, 128)
        except socket.timeout:
            continue
        except Exception as e:
            SNIFF_STATS["errors"] += 1
            log("抓包错误: %s" % e)
            time.sleep(0.5)
            continue
        t_arr = None
        for level, ctype, cmsg in ancdata:
            if level != socket.SOL_SOCKET:
                continue
            if ctype == 35 and len(cmsg) >= 16:            # timespec64
                sec, nsec = struct.unpack("qq", cmsg[:16])
                t_arr = sec + nsec / 1e9
                SNIFF_STATS["arrival_ts"] = 1
                break
            if ctype == 29 and len(cmsg) >= 16:            # timeval64
                sec, usec = struct.unpack("qq", cmsg[:16])
                t_arr = sec + usec / 1e6
                SNIFF_STATS["arrival_ts"] = 1
                break
        t_now = t_arr if t_arr else time.time()
        # 每 5 秒读一次套接字丢包计数（SO_MEMINFO 第 6 项 = drops）
        if t_now - last_mem[0] > 5:
            last_mem[0] = t_now
            try:
                mi = s.getsockopt(socket.SOL_SOCKET, _MEMINFO, 32)
                vals = struct.unpack("IIIIIIII", mi)
                SNIFF_STATS["sock_drops"] = vals[5]
            except Exception:
                pass
        pkttype = saddr[2] if len(saddr) > 2 else 0
        SNIFF_STATS["packets"] += 1
        try:
            p = parse_packet(data)
        except Exception:
            p = None
        if not p:
            continue
        if p["proto"] == "udp":
            if p["dport"] in ports and not is_local(p["src"]):
                SNIFF_STATS["udp"] += 1
                c = _conn_get(p["src"], p["sport"], p["dport"], p["ttl"], 0, 0, 0, {},
                              int(t_now))
                c["kind"] = "quic"
                c["last_seen"] = t_now
                c["last_ts"] = int(t_now)
                c["in_bytes"] = c.get("in_bytes", 0) + p["plen"] + 8
                c["in_pkts"] = c.get("in_pkts", 0) + 1
            continue
        # TCP
        SNIFF_STATS["tcp"] += 1
        src, dst = p["src"], p["dst"]
        ts = int(t_now)
        if not is_local(src):
            # 入向：客户端 → 本机端口
            if p["dport"] not in ports:
                continue
            is_syn = bool(p["flags"] & 0x02) and not (p["flags"] & 0x10)
            starts_tls = p["plen"] > 0 and p["payload"][:1] == b"\x16"
            # 中段的应用数据（长连接在 devfp 重启前就建立、之后没有新 SYN/ClientHello）：
            # 也必须建档，否则这条连接上的 DoT 明文（dotfront 记录）就永远无法归属。
            starts_app = p["plen"] > 0 and p["payload"][:1] == b"\x17"
            with CONNS_LOCK:
                known = (src, p["sport"], p["dport"]) in CONNS
            if not known and not is_syn and not starts_tls and not starts_app:
                # 既不建连、也不发 ClientHello、也不是应用数据的零散包（尾随 ACK/RST）：
                # 没有可提取的指纹信息，不单独建档，避免虚增设备
                SNIFF_STATS["stray"] = SNIFF_STATS.get("stray", 0) + 1
                continue
            c = _conn_get(src, p["sport"], p["dport"], p["ttl"], p["win"],
                          p["ip_id"], p["df"], p["opts"], ts)
            if starts_app and "tcp" not in c:
                c["midstream"] = True        # 没抓到握手，只能靠 IP 级归属/后续明文
            if c.get("in_pkts", 0) == 0:
                SNIFF_STATS["new_conn"] = SNIFF_STATS.get("new_conn", 0) + 1
                c["t_first"] = t_now
            c["last_seen"] = t_now
            c["last_ts"] = ts
            c["in_plen"] = c.get("in_plen", 0) + p["plen"]
            if (p["flags"] & 0x02) and not (p["flags"] & 0x10):
                SNIFF_STATS["syn_in"] += 1
                if "tcp" not in c:
                    c["tcp"] = tcp_fingerprint(p["ttl"], p["win"], p["opts"],
                                               p["ip_id"], p["df"], 0)
                    c["t_syn"] = t_now          # RTT 只从真正的 SYN 起算
                    c["syn_seq"] = p["seq"]
                else:
                    SNIFF_STATS["retrans"] += 1
                    if p["seq"] != c.get("syn_seq"):
                        # 同一 4 元组被复用成新连接：时间戳偏移也随之改变，重置采样窗
                        c["tsv_t0"] = c["tsv_v0"] = c["tsv_t1"] = c["tsv_v1"] = None
                        c["syn_seq"] = p["seq"]
            # 真正的客户端 RTT：SYN-ACK 发出 → 客户端的下一个包（ACK/数据/RST）到达
            if not is_syn and c.get("t_synack") and c.get("rtt_ms") is None:
                c["rtt_ms"] = (t_now - c["t_synack"]) * 1000.0
            c["in_pkts"] = c.get("in_pkts", 0) + 1
            c["in_bytes"] = c.get("in_bytes", 0) + p["plen"] + 40
            if p["plen"] > 0:
                pay = p["payload"]
                if not c["ch_done"]:
                    if pay[:1] == b"\x16":
                        if not c["ch_buf"]:
                            c["ch_need"] = 5 + _u16(pay, 3) if len(pay) >= 5 else 0
                            SNIFF_STATS["ch_seed"] += 1
                        c["ch_buf"] += pay
                    elif c["ch_buf"]:
                        c["ch_buf"] += pay
                    if c["ch_need"] and len(c["ch_buf"]) >= c["ch_need"]:
                        info, used = parse_client_hello(c["ch_buf"])
                        if info:
                            c["tls"] = info
                            c["ja3"] = info["ja3"]
                            c["ja4"] = info["ja4"]
                            SNIFF_STATS["tls"] += 1
                            c["ch_done"] = True
                            _count_app_data(c, c["ch_buf"][used:], t_now)   # 同包内的首个查询
                        elif used and len(c["ch_buf"]) >= used:
                            SNIFF_STATS["ch_fail"] += 1
                            c["ch_done"] = True
                    elif not c["ch_need"]:
                        c["ch_done"] = True
                    if len(c["ch_buf"]) > 16384:
                        c["ch_done"] = True        # 防呆：别为异常连接无限攒缓冲
                if pay[:1] == b"\x17":             # 应用数据 = DNS 查询/应答（不管握手是否抓到）
                    _count_app_data(c, pay, t_now)
                # 同一连接内采样 TCP 时间戳 → 才能算时钟漂移（偏移是每连接随机的，跨连接比没意义）
                tsv = p["opts"].get("tsval")
                if tsv is not None:
                    if not c.get("tsv_t0"):
                        c["tsv_t0"] = t_now
                        c["tsv_v0"] = tsv
                    c["tsv_t1"] = t_now
                    c["tsv_v1"] = tsv
                # 重传计数：同一 (seq, 长度) 再次出现即视为重传
                if p["plen"] > 0:
                    seen = c.get("seen")
                    if seen is None:
                        seen = c["seen"] = set()
                    k2 = (p["seq"], p["plen"])
                    if k2 in seen:
                        c["retrans"] = c.get("retrans", 0) + 1
                    elif len(seen) < 128:
                        seen.add(k2)
            if p["flags"] & (0x01 | 0x04):
                c["fin"] = True
        else:
            # 回向：本机 → 客户端（用于 ServerHello / 字节统计）
            key = (dst, p["dport"], p["sport"])
            with CONNS_LOCK:
                c = CONNS.get(key)
            if not c:
                continue
            if c.get("t_synack") is None and c.get("t_syn"):
                c["t_synack"] = t_now
            c["last_seen"] = t_now
            c["last_ts"] = ts
            c["out_pkts"] = c.get("out_pkts", 0) + 1
            c["out_bytes"] = c.get("out_bytes", 0) + p["plen"] + 40
            if p["plen"] > 1:
                pay = p["payload"]
                if not c.get("sh_done") and pay[:1] == b"\x16":
                    if len(pay) >= 6:
                        hl = pay[5] if len(pay) > 5 else 0
                        if hl == 0x02:
                            sh, _ = parse_server_hello(pay)
                            if sh:
                                c["sh"] = sh
                                c["sh_done"] = True
                        elif hl == 0x0B:
                            cert = parse_tls_cert_size(pay)
                            if cert:
                                c["cert"] = cert
                if pay[:1] == b"\x17":
                    n17, b17 = scan_tls_records(pay)
                    if n17:
                        c["resp_rec"] = c.get("resp_rec", 0) + n17
                        c["resp_bytes"] = c.get("resp_bytes", 0) + b17
                        if c.get("t_lastreq"):
                            rl = c.get("rtts")           # 注意：别用 s 命名，会覆盖抓包 socket
                            if rl is None:
                                rl = c["rtts"] = []
                            if len(rl) < 40:
                                rl.append((t_now - c["t_lastreq"]) * 1000.0)
                            c["t_lastreq"] = 0
            if p["flags"] & (0x01 | 0x04):
                c["fin"] = True


# ---------------------------------------------------------------------------
# AGH querylog tail
# ---------------------------------------------------------------------------

_AGH_OFF = [0]
_AGH_INO = [0]


def dns_first_name(raw):
    """从 DNS 报文里取第一个 QNAME（用于 DoH 请求的 URL/POST body 解码）。"""
    try:
        if len(raw) < 13 or _u16(raw, 4) < 1:
            return None
        name, _ = _read_name(raw, 12)
        return name or None
    except Exception:
        return None


def unescape_nginx(s):
    """还原 nginx 日志里的 \\xXX 转义（$request_body 是二进制）。"""
    out = bytearray()
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c == "\\" and i + 1 < n:
            if s[i + 1] == "x" and i + 3 < n:
                try:
                    out.append(int(s[i + 2:i + 4], 16))
                    i += 4
                    continue
                except Exception:
                    pass
            out.append(ord(s[i + 1]))
            i += 2
            continue
        out.append(ord(c))
        i += 1
    return bytes(out)


def _ngx_text(s):
    """还原 nginx 转义、去掉外层引号（Client Hints 的值形如 \\x22Pixel 8 Pro\\x22）。"""
    if s in (None, "", "-"):
        return None
    t = s
    try:
        t = unescape_nginx(s).decode("utf-8", "replace")
    except Exception:
        pass
    t = t.strip()
    while len(t) >= 2 and t[0] == t[-1] and t[0] in ('"', "'"):
        t = t[1:-1].strip()
    return t or None


def doh_qname(arg_dns, body):
    """DoH 查询名：GET 用 ?dns=<base64url>，POST 用请求体里的 DNS 明文。"""
    if arg_dns and arg_dns not in ("-", ""):
        try:
            s = arg_dns.encode()
            pad = b"=" * (-len(s) % 4)
            raw = base64.urlsafe_b64decode(s + pad)
            nm = dns_first_name(raw)
            if nm:
                return nm
        except Exception:
            pass
    if body and body not in ("-", ""):
        try:
            return dns_first_name(unescape_nginx(body))
        except Exception:
            pass
    return None


def _redirect_ok(resp):
    return isinstance(resp, list) and resp and resp[0].startswith("0.0.0.0")


def decode_dns_answer(b64):
    """把 AGH 的 base64 DNS 响应解成简短可读文本。"""
    try:
        raw = base64.b64decode(b64)
    except Exception:
        return ""
    try:
        qd = _u16(raw, 4); an = _u16(raw, 6)
        o = 12
        for _ in range(qd):
            _, o = _read_name(raw, o)
            o += 4
        out = []
        ttls = []
        for _ in range(min(an, 8)):
            name, o = _read_name(raw, o)
            if o + 10 > len(raw):
                break
            typ = _u16(raw, o); ttl = _u32(raw, o + 4); rdlen = _u16(raw, o + 8)
            o += 10
            rd = raw[o:o + rdlen]
            o += rdlen
            if typ == 1 and len(rd) == 4:
                out.append("A %s(TTL%d)" % (socket.inet_ntoa(rd), ttl))
            elif typ == 28 and len(rd) == 16:
                out.append("AAAA %s(TTL%d)" % (socket.inet_ntop(socket.AF_INET6, rd), ttl))
            elif typ == 5:
                n, _ = _read_name(raw, o - rdlen)
                out.append("CNAME %s" % n)
            elif typ == 16 and rd:
                l = rd[0]
                out.append("TXT %s" % rd[1:1 + l].decode("utf-8", "replace"))
            elif typ == 12:
                n, _ = _read_name(raw, o - rdlen)
                out.append("PTR %s" % n)
            elif typ in (64, 65):        # SVCB / HTTPS：看是否带 ECH 与端口/地址提示
                flags = 0
                if len(rd) >= 4:
                    flags = _u16(rd, 2)
                ech = "ech" if (flags & 0x0004) else ""
                out.append(("HTTPS" if typ == 65 else "SVCB") + ("(%s)" % ech if ech else ""))
            elif typ == 41:
                out.append("OPT")
            if ttl:
                ttls.append(ttl)
        if ttls:
            out.append("TTL %d~%d" % (min(ttls), max(ttls)))
        return trim("; ".join(out), 400)
    except Exception:
        return ""


def _read_name(msg, o):
    labels = []
    jumps = 0
    start_off = o
    while o < len(msg) and jumps < 12:
        l = msg[o]
        if l == 0:
            o += 1
            break
        if l & 0xC0 == 0xC0:
            ptr = _u16(msg, o) & 0x3FFF
            if not labels:
                start_off = o + 2
            o = ptr
            jumps += 1
            continue
        labels.append(msg[o + 1:o + 1 + l].decode("utf-8", "replace"))
        o += 1 + l
    return ".".join(labels), (start_off if jumps else o)


def _agh_time(t):
    try:
        return calendar.timegm(time.strptime(t[:19], "%Y-%m-%dT%H:%M:%S"))
    except Exception:
        return now()


CLUSTER_MAP = {}
DNS_BUF = {}
DNS_BUF_LOCK = threading.Lock()
# 最近「客户端发出一条 DNS 请求记录」的事件（TLS 应用数据到达时刻），用于把 AGH querylog
# 的查询按毫秒时间对齐归属到具体指纹——DoT 的查询名在 AGH 侧只能按出口 IP 归属，
# 这样就能逐指纹归属，而且完全不动 DNS 链路。
RECENT_REQ = []
RECENT_REQ_LOCK = threading.Lock()
RECENT_REQ_MAX = 150000       # 条数上限（紧凑存储：ip/key 用 int，约 15MB）
RECENT_REQ_KEEP = 150.0       # 秒：AGH 批量刷盘可延迟数十秒
RECENT_REQ_WIN = 1.2          # 秒：对齐窗口
REQ_KEYMAP = {}               # fp_key -> 小整数（省内存）
REQ_KEYREV = []               # 小整数 -> fp_key
REQ_IPMAP = {}
ALIGN_DBG = [0]


def _key_id(key):
    i = REQ_KEYMAP.get(key)
    if i is None:
        i = len(REQ_KEYREV)
        REQ_KEYMAP[key] = i
        REQ_KEYREV.append(key)
    return i


def _ip_id(ip):
    i = REQ_IPMAP.get(ip)
    if i is None:
        i = ip2int(ip) or 0
        REQ_IPMAP[ip] = i
    return i


def _note_req(ip, key, sport, t, is_dot=False):
    with RECENT_REQ_LOCK:
        RECENT_REQ.append((t, _ip_id(ip), _key_id(key), 1 if is_dot else 0))
        if len(RECENT_REQ) > RECENT_REQ_MAX:
            del RECENT_REQ[:len(RECENT_REQ) - RECENT_REQ_MAX]


def _prune_recent_req(now_t=None):
    """按时间淘汰旧事件（AGH 批量刷盘可能延迟几十秒，所以保留 150 秒）。"""
    cutoff = (now_t or time.time()) - RECENT_REQ_KEEP
    with RECENT_REQ_LOCK:
        if RECENT_REQ and RECENT_REQ[0][0] < cutoff:
            i = 0
            for i, x in enumerate(RECENT_REQ):
                if x[0] >= cutoff:
                    break
            del RECENT_REQ[:i]


IP_DEVCOUNT = {}


def _ip_shared(ip):
    """该出口 IP 上是否有多个指纹设备（缓存 60 秒）。共用时时间对齐不可靠。"""
    v = IP_DEVCOUNT.get(ip)
    t0 = time.time()
    if v and t0 - v[0] < 60:
        return v[1] > 1
    r = qone("SELECT COUNT(*) c FROM devices WHERE source='server' AND src_ips LIKE ?",
             ('%"' + ip + '"%',))
    n = (r["c"] if r else 0) or 0
    IP_DEVCOUNT[ip] = (t0, n)
    return n > 1


CONTAINER_GW_IPS = ("172.18.0.1", "172.19.0.1", "127.0.0.1")
SELF_IP_LIST = ("127.0.0.1", "127.0.0.2", "172.18.0.1", "172.19.0.1")
GW_FALLBACK_WIN = 0.35
SELF_IP_IDS = None


def _match_recent_req(ip, t, win=RECENT_REQ_WIN, shared=None):
    """在同 IP 的请求事件里找时间上最贴近的指纹。
    共用出口 IP 且有多个指纹在窗口内时**一律不归属**（宁缺勿错：最近邻在密集流量下会认错）。
    注意：AGH 的 querylog 里 DoT 客户端 IP 恒为容器网关（AGH 没编 PROXY protocol），
    真实客户端 IP 只存在于抓包侧。此时退化为「同时间窗口内跨 IP 的请求事件」匹配，
    窗口收紧到 GW_FALLBACK_WIN 并强制走保守规则（窗口内出现多个指纹就不归属）。"""
    global SELF_IP_IDS
    iip = _ip_id(ip)
    with RECENT_REQ_LOCK:
        cands = [x for x in RECENT_REQ if x[1] == iip and abs(x[0] - t) <= win]
    if not cands and ip in CONTAINER_GW_IPS:
        if SELF_IP_IDS is None:
            SELF_IP_IDS = set(_ip_id(x) for x in SELF_IP_LIST)
        with RECENT_REQ_LOCK:
            # 只允许「DoT 连接的请求事件」参与跨 IP 兜底匹配：443 上的普通 TLS/DoH 事件
            # 若被用来对齐 DoT 查询，会把查询挂到浏览器类设备上（实测出现过）。
            cands = [x for x in RECENT_REQ
                     if abs(x[0] - t) <= GW_FALLBACK_WIN and x[1] not in SELF_IP_IDS and x[3]]
        shared = True
        win = GW_FALLBACK_WIN
    if not cands:
        return None, None
    per_key = {}
    for ts, _iip, kid, _isdot in cands:
        d = abs(ts - t)
        if kid not in per_key or d < per_key[kid]:
            per_key[kid] = d
    ranked = sorted(per_key.items(), key=lambda kv: kv[1])
    if len(ranked) > 1 and (shared or ranked[1][1] < ranked[0][1] * 2):
        return None, None
    best_kid, best_d = ranked[0]
    if best_d > win:
        return None, None
    try:
        key = REQ_KEYREV[best_kid]
    except Exception:
        return None, None
    return key, int(round(best_d * 1000))
# 环形缓存限速采样：实测有设备能每秒上千次查询，全量写库会拖垮采集。
# 全量计数仍然进 dns_hour 聚合，统计不受影响；环形缓存只保留样本。
RECENT_BUDGET = {"sec": 0, "n": 0, "limit": 40}


def _recent_allow():
    s = int(time.time())
    if RECENT_BUDGET["sec"] != s:
        RECENT_BUDGET["sec"] = s
        RECENT_BUDGET["n"] = 0
    RECENT_BUDGET["n"] += 1
    return RECENT_BUDGET["n"] <= RECENT_BUDGET["limit"]


def agh_process(rec):
    ip = rec.get("IP") or "?"
    cp = rec.get("CP") or ""
    proto = {"dot": "dot", "doh": "doh", "doq": "doq", "quic": "doq"}.get(cp, cp or "other")
    t = _agh_time(rec.get("T", ""))
    hour = t - (t % 3600)
    qh = rec.get("QH") or ""
    qt = rec.get("QT") or ""
    res = rec.get("Result") or {}
    filt = 1 if isinstance(res, dict) and res.get("IsFiltered") else 0
    # 命中的拦截规则（AGH querylog 里一直有，之前没入库）：Result.Rules[].Text 形如
    # "sdk-log.partner.sm.cn # From: 海哥"，FilterListID 是列表 ID
    rule_txt = None
    if filt and isinstance(res, dict):
        rs = res.get("Rules") or []
        if isinstance(rs, list) and rs and isinstance(rs[0], dict):
            rule_txt = trim(str(rs[0].get("Text") or ""), 190) or None
            rid = rs[0].get("FilterListID")
            if rule_txt and rid:
                rule_txt = rule_txt + " @" + str(rid)
    elapsed = int(rec.get("Elapsed") or 0) // 1000
    up = rec.get("Upstream") or ""
    # 「最近查询」环形缓存限速采样（突发时每秒上千条也不拖垮采集）；拦截与已归属记录必留
    did = mms = src = None
    if proto == "dot":
        # DoT 的查询在 AGH 侧只能按出口 IP 归属 —— 用「TLS 请求记录到达时间」对齐到具体指纹
        key, mms = _match_recent_req(ip, t, shared=_ip_shared(ip))
        if key:
            try:
                did, _dv = device_for(key, {"source": "server"})
                src = "dot-tls-align"
            except Exception:
                did = None
        elif CFG.get("debug_align") or ALIGN_DBG[0] < 300:
            with RECENT_REQ_LOCK:
                near = [abs(x[0] - t) for x in RECENT_REQ if x[1] == _ip_id(ip)]
                tot = len(RECENT_REQ)
            ALIGN_DBG[0] += 1
            log("对齐未命中 %s %s：窗口内候选=%d 最近偏差=%s ms（事件总数 %d）" % (
                ip, trim(qh, 40), len([d for d in near if d <= RECENT_REQ_WIN]),
                ("%.0f" % (min(near) * 1000)) if near else "无", tot))
    if _recent_allow() or filt or did:
        xrun("INSERT INTO dns_recent(ts,ip,qh,qt,cp,filtered,elapsed_ms,upstream,answer,device_id,"
             "match_ms,src,rule) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
             (t, ip, trim(qh, 200), qt, cp, filt, elapsed, trim(up, 60),
              decode_dns_answer(rec.get("Answer") or ""), did, mms, src, rule_txt))
    with DNS_BUF_LOCK:
        k = (ip, hour, proto)
        b = DNS_BUF.get(k)
        if b is None:
            b = {"n": 0, "nx": 0, "filtered": 0, "a": 0, "aaaa": 0, "https": 0,
                 "ptr": 0, "other": 0, "sum": 0, "max": 0, "up": {}, "dom": {}, "ecs": {}}
            DNS_BUF[k] = b
        b["n"] += 1
        if qt == "A":
            b["a"] += 1
        elif qt == "AAAA":
            b["aaaa"] += 1
        elif qt == "HTTPS":
            b["https"] += 1
        elif qt == "PTR":
            b["ptr"] += 1
        else:
            b["other"] += 1
        b["filtered"] += filt
        b["sum"] += elapsed
        b["max"] = max(b["max"], elapsed)
        if up:
            b["up"][up] = b["up"].get(up, 0) + 1
        if qh:
            d = qh[:-1] if qh.endswith(".") else qh
            b["dom"][d] = b["dom"].get(d, 0) + 1
        e = rec.get("ECS")
        if e:
            b["ecs"][e] = b["ecs"].get(e, 0) + 1


def dns_flush_loop():
    while True:
        time.sleep(3.0)
        with DNS_BUF_LOCK:
            items = list(DNS_BUF.items())
            DNS_BUF.clear()
        for (ip, hour, proto), b in items:
            try:
                dev = qone("SELECT id FROM devices WHERE src_ips LIKE ? ORDER BY last_seen DESC LIMIT 1",
                           ('%"' + ip + '"%',))
                did = dev["id"] if dev else None
                top = sorted(b["dom"].items(), key=lambda kv: -kv[1])[:12]
                ups = sorted(b["up"].items(), key=lambda kv: -kv[1])[:6]
                ecs = sorted(b["ecs"].items(), key=lambda kv: -kv[1])[:4]
                xrun("INSERT INTO dns_hour(device_id,ip,hour,proto,n,nx,filtered,a,aaaa,https,ptr,"
                     "other,sum_ms,max_ms,upstreams,top_json,ecs_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
                     " ON CONFLICT(ip,hour,proto) DO UPDATE SET n=n+?, nx=nx+?, filtered=filtered+?,"
                     " a=a+?, aaaa=aaaa+?, https=https+?, ptr=ptr+?, other=other+?, sum_ms=sum_ms+?,"
                     " max_ms=MAX(max_ms,?), upstreams=?, top_json=?, ecs_json=?, device_id=?",
                     (did, ip, hour, proto, b["n"], b["nx"], b["filtered"], b["a"], b["aaaa"],
                      b["https"], b["ptr"], b["other"], b["sum"], b["max"], jdump(dict(ups)),
                      jdump(top), jdump(dict(ecs)),
                      b["n"], b["nx"], b["filtered"], b["a"], b["aaaa"], b["https"], b["ptr"],
                      b["other"], b["sum"], b["max"], jdump(dict(ups)), jdump(top), jdump(dict(ecs)), did))
                if did:
                    xrun("UPDATE devices SET last_seen=MAX(COALESCE(last_seen,0),?) WHERE id=?", (hour, did))
            except Exception as e:
                log("dns_hour 写入失败(%s/%s/%s): %s" % (ip, hour, proto, e))
        if items:
            mark_dirty()


def agh_loop():
    path = CFG["agh_querylog"]
    try:
        _AGH_OFF[0] = int(kv_get("agh_off") or 0)
    except Exception:
        _AGH_OFF[0] = 0
    log("AGH querylog 采集启动: %s（续读偏移 %d）" % (path, _AGH_OFF[0]))
    while True:
        try:
            if not os.path.exists(path):
                time.sleep(5)
                continue
            st = os.stat(path)
            if st.st_ino != _AGH_INO[0]:
                if _AGH_INO[0] != 0 and st.st_size < _AGH_OFF[0]:
                    _AGH_OFF[0] = 0
                if _AGH_INO[0] == 0 and not kv_get("agh_off"):
                    # 首次启动：从文件末尾开始，避免灌入全部历史
                    _AGH_OFF[0] = st.st_size
                _AGH_INO[0] = st.st_ino
            # 积压保护：停机久了不让补课把 CPU 打满，最多回溯 4MB，其余跳过
            backlog = st.st_size - _AGH_OFF[0]
            if backlog > int(CFG.get("agh_max_backlog", 4 * 1024 * 1024)):
                log("AGH querylog 积压 %.1fMB，跳过旧数据只读最后 1MB（聚合不中断）" % (backlog / 1048576.0))
                _AGH_OFF[0] = st.st_size - 1024 * 1024
            start = _AGH_OFF[0]
            if st.st_size < start:
                start = 0
            if st.st_size == start:
                kv_set("agh_off", start)
                time.sleep(1.0)
                continue
            with open(path, "r") as f:
                f.seek(start)
                n = 0
                for line in f:
                    if not line.endswith("\n"):
                        break
                    n += 1
                    try:
                        rec = json.loads(line)
                        agh_process(rec)
                    except Exception:
                        pass
                    if n % 400 == 0:
                        mark_dirty()
                _AGH_OFF[0] = f.tell()
            kv_set("agh_off", _AGH_OFF[0])
            mark_dirty()
            bump("agh_lines", n)
        except Exception as e:
            log("AGH 采集异常: %s" % e)
            time.sleep(3)


# ---------------------------------------------------------------------------
# nginx DoH 日志 tail
# ---------------------------------------------------------------------------

_DOH_OFF = [0]
_DOH_INO = [0]


def _nginx_time(t):
    """解析 nginx $time_iso8601（本地时间**带时区偏移**，如 2026-10-04T17:51:45+08:00）。
    注意不能当 UTC 解析，否则时间戳会偏掉整个时区差，DoH 请求就对不上抓包连接了。"""
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?([+-])(\d\d):?(\d\d)", t or "")
    if m:
        base = calendar.timegm(time.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S"))
        off = int(m.group(3)) * 3600 + int(m.group(4)) * 60
        return base - off if m.group(2) == "+" else base + off
    try:
        return calendar.timegm(time.strptime((t or "")[:19], "%Y-%m-%dT%H:%M:%S"))
    except Exception:
        return now()


def doh_parse(line):
    parts = line.rstrip("\n").split("|")
    arg_dns = body = None
    if len(parts) >= 30:          # 新格式（30 字段，含 Client Hints）
        head = parts[:25]
        ch_model, ch_plat, ch_full = parts[25], parts[26], parts[27]
        ua, body = parts[28], "|".join(parts[29:])
        arg_dns = head[24]
    elif len(parts) >= 27:        # 27 字段（无 Client Hints）
        head, ua, body = parts[:25], parts[25], "|".join(parts[26:])
        arg_dns, ch_model, ch_plat, ch_full = head[24], None, None, None
    elif len(parts) >= 25:        # 25 字段（最老格式）
        head, ua = parts[:24], parts[24]
        arg_dns = body = ch_model = ch_plat = ch_full = None
    else:
        return None
    (t, ip, xff, method, uri, proto, status, bsent, rt, tls_proto, cipher, clist,
     curves, alpn, reused, sni, acc, accl, acce, ctype, dnt, prio, te, host) = head[:24]
    ts = _nginx_time(t)
    ch_model = _ngx_text(ch_model)
    ch_plat = _ngx_text(ch_plat)
    ch_full = _ngx_text(ch_full)
    headers = {"Accept": acc, "Accept-Language": accl, "Accept-Encoding": acce,
               "Content-Type": ctype, "DNT": dnt, "Priority": prio, "TE": te,
               "Host": host, "X-Forwarded-For": xff}
    return {"ts": ts, "ip": ip, "xff": xff, "method": method, "uri": uri,
            "http_ver": proto, "status": int(status or 0), "rt": float(rt or 0),
            "tls_proto": tls_proto, "cipher": cipher, "cipher_list": clist,
            "curves": curves, "alpn": alpn, "resumed": 1 if reused == "r" else 0,
            "sni": sni, "ua": ua, "headers": headers, "arg_dns": arg_dns,
            "qname": doh_qname(arg_dns, body),
            "ch_model": ch_model, "ch_platform": ch_plat, "ch_ua_full": ch_full}


def doh_process(rec):
    ip = rec["ip"]
    # 把这条 DoH 请求挂到「同 IP + 时间窗内」的抓包连接所属设备；
    # 443 的握手先记为 tls443，确认是 /dns-query 后再提升为 doh443；444 本来就是 doh444。
    did = None
    # ① 先看内存里还在跟踪的连接（长连接常常还没落库，等落库就太晚了）
    live = None
    with CONNS_LOCK:
        for c in CONNS.values():
            if c.get("src_ip") != ip:
                continue
            ls = c.get("last_seen") or 0
            if abs(ls - rec["ts"]) > 300:
                continue
            if live is None or ls > (live.get("last_seen") or 0):
                live = c
    if live is not None:
        if live.get("device_id"):
            did = live["device_id"]
        else:
            tcp_l = live.get("tcp") or {}
            key = fp_key_for(live.get("ja3"), live.get("ja4"), tcp_l.get("sig"), ip)
            if key:
                did, _ = device_for(key, {"source": "server"})
        if live.get("kind") in ("tls443", "doh443"):
            live["confirmed_doh"] = True          # 落库时按 doh443 记
    # ② 再看已落库的连接
    rows = [] if did else qall(
        "SELECT id,device_id,kind FROM conns WHERE src_ip=? AND "
        "ts BETWEEN ? AND ? AND kind IN ('tls443','doh443','doh444')"
        " ORDER BY (kind='doh444' OR kind='doh443') DESC, ts DESC LIMIT 4",
        (ip, rec["ts"] - 300, rec["ts"] + 120))
    if rows:
        did = rows[0]["device_id"]
        for r in rows:
            if r["kind"] in ("tls443", "doh443"):
                xrun("UPDATE conns SET kind='doh443' WHERE id=?", (r["id"],))
    if did is None:
        # 还没匹配上：如果这个 IP 近期有抓包连接（只是还没落库/时间窗差一点），先挂空，
        # 由 reattribute_doh() 稍后回溯归属，避免伪造出一个「兜底设备」；
        # 只有「确实从没抓到过该 IP 的连接」时才建兜底设备（例如本机回环测试或抓包盲区）。
        any_conn = qone("SELECT id FROM conns WHERE src_ip=? AND ts > ? LIMIT 1",
                        (ip, rec["ts"] - 3600))
        if not any_conn:
            key = "dohhttp:" + sha1(ip)
            did = dev_touch(key, {"src_ips": None}, proto_kind="doh443", ip=ip)
            dev = qone("SELECT fp_key FROM devices WHERE id=?", (did,))
            if dev:
                xrun("UPDATE devices SET label=COALESCE(NULLIF(label,''), ?) WHERE id=?",
                     ("DoH 客户端（未匹配到抓包指纹）", did))
    patch = {"http_json": jdump({"ua": rec["ua"], "http_ver": rec["http_ver"],
                                 "headers": rec["headers"], "tls": {
                                     "protocol": rec["tls_proto"], "cipher": rec["cipher"],
                                     "client_ciphers": trim(rec["cipher_list"], 900),
                                     "curves": trim(rec["curves"], 300),
                                     "alpn": rec["alpn"], "session_reused": rec["resumed"],
                                     "sni": rec["sni"]}}),
             "ua": trim(rec["ua"], 400), "http_ver": rec["http_ver"]}
    dev = qone("SELECT fp_key, protos FROM devices WHERE id=?", (did,))
    if dev:
        dev_touch(dev["fp_key"], patch, proto_kind=None, ip=None)
        # 该设备确实发过 DoH 请求 → 补上 doh443 标记（否则会被判成「仅网页访问」的非 DNS 设备）
        if '"doh443"' not in (dev["protos"] or ""):
            p = jload(dev["protos"], {}) or {}
            p["doh443"] = int(p.get("doh443", 0)) + 1
            xrun("UPDATE devices SET protos=? WHERE id=?", (jdump(p), did))
            _DEV_CACHE.clear()
        # 浏览器 Client Hints 直接给了型号 → 最硬的一条「型号」证据
        if rec.get("ch_model"):
            xrun("UPDATE devices SET model=?, http_json=COALESCE(http_json,'{}') WHERE id=?",
                 (trim(rec["ch_model"], 80), did))
            xrun("UPDATE doh_requests SET ch_model=?, ch_platform=?, ch_ua_full=? WHERE device_id=?"
                 " AND ts=?", (rec["ch_model"], rec.get("ch_platform"),
                               trim(rec.get("ch_ua_full") or "", 200), did, rec["ts"]))
    xrun("INSERT INTO doh_requests(ts,ip,device_id,method,uri,http_ver,status,rt,tls_proto,cipher,cipher_list,curves,alpn,sni,resumed,ua,headers,xff,qname,ch_model,ch_platform,ch_ua_full) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
         (rec["ts"], ip, did, rec["method"], trim(rec["uri"], 80), rec["http_ver"],
          rec["status"], rec["rt"], rec["tls_proto"], rec["cipher"],
          # 2026-10-09 大字段瘦身·阶段一（只改写入侧，不删旧历史）：
          # cipher_list/curves/headers 约 118MB（占库 34%），与 devices.http_json 里已存的
          # 每设备快照冗余；前端对 headers 有 r.headers||"{}" 保护。归一化列
          # cipher/tls_proto/alpn/sni/resumed/ua 全部保留。
          None, None, rec["alpn"], rec["sni"],
          rec["resumed"], trim(rec["ua"], 400), None, rec["xff"],
          trim(rec.get("qname") or "", 255) or None, rec.get("ch_model"),
          rec.get("ch_platform"), trim(rec.get("ch_ua_full") or "", 200) or None))


def doh_loop():
    path = CFG["doh_log"]
    try:
        _DOH_OFF[0] = int(kv_get("doh_off") or 0)
    except Exception:
        _DOH_OFF[0] = 0
    log("DoH 日志采集启动: %s（续读偏移 %d）" % (path, _DOH_OFF[0]))
    while True:
        try:
            if not os.path.exists(path):
                time.sleep(10)
                continue
            st = os.stat(path)
            if st.st_ino != _DOH_INO[0]:
                if _DOH_INO[0] == 0 and not kv_get("doh_off"):
                    _DOH_OFF[0] = st.st_size
                _DOH_INO[0] = st.st_ino
            if st.st_size - _DOH_OFF[0] > int(CFG.get("doh_max_backlog", 2 * 1024 * 1024)):
                _DOH_OFF[0] = st.st_size - 256 * 1024
            start = _DOH_OFF[0]
            if st.st_size < start:
                start = 0
            if st.st_size == start:
                time.sleep(2.0)
                continue
            with open(path, "r") as f:
                f.seek(start)
                n = 0
                for line in f:
                    if not line.endswith("\n"):
                        break
                    n += 1
                    r = doh_parse(line)
                    if r:
                        doh_process(r)
                _DOH_OFF[0] = f.tell()
            kv_set("doh_off", _DOH_OFF[0])
            mark_dirty()
            bump("doh_lines", n)
        except Exception as e:
            log("DoH 日志采集异常: %s" % e)
            time.sleep(3)


# ---------------------------------------------------------------------------
# dotfront（DoT 前置终结器）明文 spool 采集
#   按 (ip, sport) 精确归属到设备——不是时间猜测，而是同一连接号的直接对应。
# ---------------------------------------------------------------------------
_DOTF_OFF = [0]
_DOTF_INO = [0]
DOTF_DBG = [0]


def _ip_single_device(ip):
    """该出口 IP 上只有一个指纹设备时返回其 id（独占出口 IP，可安全按 IP 归属）。"""
    rows = qall("SELECT id FROM devices WHERE source='server' AND src_ips LIKE ? LIMIT 3",
                ('%"' + ip + '"%',))
    if len(rows) == 1:
        return rows[0]["id"]
    return None


def _dotf_device(ip, sport, rec):
    """按抓包侧 853 连接的五元组找设备；找不到就退回「独占出口 IP」归属。"""
    diag = None
    try:
        with CONNS_LOCK:
            c = CONNS.get((ip, int(sport), 853))
        if c is None:
            diag = "内存无此连接"
        elif c.get("device_id"):
            return c["device_id"], "dotfront-plain"
        else:
            tcp = c.get("tcp") or {}
            key = fp_key_for(c.get("ja3"), c.get("ja4"), tcp.get("sig"), ip)
            if key:
                did, _ = device_for(key, {"source": "server"})
                if did:
                    return did, "dotfront-plain"
            diag = "内存有连接但无法指纹化 (ja4=%s)" % (c.get("ja4") or "-")
    except Exception as e:
        diag = "内存路径异常: %s" % e
    try:
        r = qone("SELECT device_id FROM conns WHERE src_ip=? AND sport=? AND dport=853"
                 " AND device_id IS NOT NULL ORDER BY ts DESC LIMIT 1", (ip, int(sport)))
        if r and r["device_id"]:
            return r["device_id"], "dotfront-plain"
        diag = (diag or "") + "；库里" + ("有行但device为空" if r else "无此行")
    except Exception as e:
        diag = (diag or "") + "；库路径异常: %s" % e
    # 兜底：独占出口 IP（只有一台设备）→ 可按 IP 归属
    did = _ip_single_device(ip)
    if did:
        return did, "dotfront-ip"
    if DOTF_DBG[0] < 25:
        DOTF_DBG[0] += 1
        log("dotfront 归属未命中 %s:%s（%s；该 IP 设备数>1）" % (ip, sport, diag))
    return None, None


def _align_plain_event(ip, t):
    """明文内腿（nginx -> adgh 127.0.0.1:8854）的查询：连接方是 nginx 而不是访客，
    用「DoT 连接的请求事件」按毫秒时间对齐找回真实连接与设备（与 AGH querylog 同一套机制）。
    返回 (device_id, client_ip, sport, how)，未命中返回 (None, None, None, None)。"""
    key, _ms = _match_recent_req(ip, t, shared=True)
    if not key:
        return None, None, None, None
    did = None
    try:
        did, _ = device_for(key, {"source": "server"})
    except Exception:
        did = None
    cands = []
    try:
        with CONNS_LOCK:
            for (a, b, d), c in CONNS.items():
                if d != 853:
                    continue
                k2 = c.get("device_key") or c.get("req_key")
                if k2 is None:
                    try:
                        k2 = fp_key_for(c.get("ja3"), c.get("ja4"),
                                        (c.get("tcp") or {}).get("sig"), a)
                    except Exception:
                        k2 = None
                if k2 != key:
                    continue
                tl = c.get("t_lastreq") or 0
                cands.append((abs(tl - t) if tl else 9e9, a, b))
    except Exception:
        pass
    cip = csport = None
    if cands:
        cands.sort()
        _d, cip, csport = cands[0]
    if not did:
        return None, cip, csport, None
    return did, cip, csport, "dotfront-align"


def dotf_process(rec):
    ev = rec.get("ev")
    if ev == "hello":
        # B：前端自抓 ClientHello —— 回灌给「抓包侧没抓到握手」的连接，并补会话票信息
        ip = rec.get("ip")
        sport = rec.get("sport")
        c = None
        try:
            with CONNS_LOCK:
                c = CONNS.get((ip, int(sport), 853))
        except Exception:
            c = None
        if c is not None:
            if not c.get("ja4") and rec.get("ja4"):
                c["ja4"] = rec["ja4"]
                c["ja3"] = rec.get("ja3")
            t = c.get("tls") or {}
            if rec.get("sni") and not t.get("sni"):
                t["sni"] = rec["sni"]
            if rec.get("alpn") and not t.get("alpn"):
                t["alpn"] = rec["alpn"]
            if t:
                c["tls"] = t
            c["psk"] = 1 if rec.get("psk") else 0
            c["ticket_age"] = rec.get("ticket_age")
            c["psk_ident"] = rec.get("psk_ident")
        else:
            row = qone("SELECT id FROM conns WHERE src_ip=? AND sport=? AND dport=853"
                       " AND (ja4 IS NULL OR ja4='') ORDER BY id DESC LIMIT 1",
                       (ip, int(sport) if sport is not None else 0))
            if row and rec.get("ja4"):
                xrun("UPDATE conns SET ja4=?, ja3=? WHERE id=?",
                     (rec["ja4"], rec.get("ja3"), row["id"]))
                mark_dirty()
        bump("dotf_hello", 1)
        return
    if ev == "ddr":
        did, _how = _dotf_device(rec.get("ip"), rec.get("sport"), rec)
        if did:
            xrun("UPDATE devices SET ddr_count=COALESCE(ddr_count,0)+1 WHERE id=?", (did,))
            mark_dirty()
        bump("dotf_ddr", 1)
        return
    if ev == "q":
        ip = rec.get("ip") or "?"
        sport = rec.get("sport")
        t = int(rec.get("t") or now())
        tf = float(rec.get("tf") or t)
        did = how = None
        if ip in CONTAINER_GW_IPS:
            # 明文内腿（lo -> 8854）的本地端口属于 nginx，不能按端口归属；先做时间对齐
            did, aip, asport, how = _align_plain_event(ip, tf)
            if aip:
                ip = aip
            if asport is not None:
                sport = asport
        else:
            did, how = _dotf_device(ip, sport, rec)
        if did and rec.get("cookie_echo"):
            ck = (rec.get("edns") or {}).get("cookie_client")
            if ck:
                xrun("UPDATE devices SET dns_cookie=? WHERE id=?", (ck, did))
                bump("dotf_cookie_echo", 1)
        edns = rec.get("edns") or {}
        prof = []
        if edns.get("cookie_client"):
            prof.append("COOKIE")
        if edns.get("ecs"):
            prof.append("ECS=" + str(edns["ecs"]))
        if edns.get("padding"):
            prof.append("PAD=%s" % edns["padding"])
        if rec.get("do"):
            prof.append("DO")
        if rec.get("udp_size"):
            prof.append("UDP=%s" % rec["udp_size"])
        xrun("INSERT INTO dns_recent(ts,ip,qh,qt,cp,filtered,elapsed_ms,upstream,answer,device_id,match_ms,src,sport,do_bit,udp_size,mixed,edns,rcode) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
             (t, ip, trim(rec.get("qname") or "", 200), rec.get("qt") or "", "dot",
              0, None, "sport:%s" % sport, trim("、".join(prof), 120), did,
              None, how or "dotfront-plain", int(sport) if sport is not None else None,
              1 if rec.get("do") else 0, rec.get("udp_size"),
              1 if rec.get("mixed_case") else 0, jdump(edns), None))
    elif ev == "r":
        # 用 (ip,sport,id) 回填最近一条同连接同 ID 的查询行 → 应答码与耗时
        pass
    elif ev == "tls_fail":
        log("dotfront：TLS 握手失败 %s:%s %s" % (rec.get("ip"), rec.get("sport"), rec.get("err")))
    elif ev == "conn":
        pass


def dotf_loop():
    path = CFG.get("dotfront_spool", "/var/log/dotfront.jsonl")
    try:
        _DOTF_OFF[0] = int(kv_get("dotf_off") or 0)
    except Exception:
        _DOTF_OFF[0] = 0
    log("dotfront 明文 spool 采集启动：%s（续读偏移 %d）" % (path, _DOTF_OFF[0]))
    while True:
        try:
            if not os.path.exists(path):
                time.sleep(10)
                continue
            st = os.stat(path)
            if st.st_ino != _DOTF_INO[0]:
                if _DOTF_INO[0] != 0 and st.st_size < _DOTF_OFF[0]:
                    _DOTF_OFF[0] = 0
                if _DOTF_INO[0] == 0 and not kv_get("dotf_off"):
                    _DOTF_OFF[0] = st.st_size
                _DOTF_INO[0] = st.st_ino
            start = _DOTF_OFF[0]
            if st.st_size < start:
                start = 0
            if st.st_size == start:
                kv_set("dotf_off", start)
                time.sleep(1.5)
                continue
            n = 0
            with open(path, "r") as f:
                f.seek(start)
                for line in f:
                    if not line.endswith("\n"):
                        break
                    n += 1
                    try:
                        dotf_process(json.loads(line))
                    except Exception:
                        pass
                    if n % 200 == 0:
                        mark_dirty()
                _DOTF_OFF[0] = f.tell()
            kv_set("dotf_off", _DOTF_OFF[0])
            mark_dirty()
            bump("dotf_lines", n)
        except Exception as e:
            log("dotfront 采集异常: %s" % e)
            time.sleep(3)


# ---------------------------------------------------------------------------
# 反查：rDNS / ASN / 国家
# ---------------------------------------------------------------------------

def dns_query(name, qtype, server=None):
    server = server or CFG["resolver"]
    host, _, port = server.partition(":")
    port = int(port or 53)
    qid = int(time.time()) & 0xFFFF
    q = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for lab in name.split("."):
        if lab:
            try:
                b = lab.encode("idna")
            except Exception:      # Python 3.6 的 idna 编解码器不支持 errors= 参数
                b = lab.encode("ascii", "replace")
            q += bytes([len(b)]) + b
    q += b"\x00" + struct.pack("!HH", qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(4.0)
    try:
        s.sendto(q, (host, port))
        data, _ = s.recvfrom(4096)
    except Exception:
        return []
    finally:
        s.close()
    try:
        an = _u16(data, 6)
        o = 12
        _, o = _read_name(data, o)
        o += 4
        out = []
        for _ in range(an):
            _, o = _read_name(data, o)
            if o + 10 > len(data):
                break
            typ = _u16(data, o); rdlen = _u16(data, o + 8)
            o += 10
            rd = data[o:o + rdlen]
            o += rdlen
            if typ == 12:
                n, _ = _read_name(data, o - rdlen)
                out.append(("PTR", n))
            elif typ == 16 and rd:
                l = rd[0]
                out.append(("TXT", rd[1:1 + l].decode("utf-8", "replace")))
            elif typ == 1 and len(rd) == 4:
                out.append(("A", socket.inet_ntoa(rd)))
    except Exception:
        return []
    return out


def _dns_txt(name, servers):
    for srv in servers:
        try:
            for t, v in dns_query(name, 16, srv):
                if t == "TXT":
                    return v
        except Exception:
            continue
    return None


GEO_DB = "/root/ech-build/geo/ip2region_v4.xdb"
GEO_STATE = {"s": None, "tried": False}


def geo_lookup(ip):
    if not GEO_STATE["tried"]:
        GEO_STATE["tried"] = True
        try:
            import sys as _sys
            _sys.path.insert(0, "/root/ech-build/geo/py")
            from ip2region import util as _u, searcher as _s
            _vi = _u.load_vector_index_from_file(GEO_DB)
            GEO_STATE["s"] = _s.new_with_vector_index(_u.IPv4, GEO_DB, _vi)
        except Exception as e:
            log("geo 库加载失败: %s" % e)
    if not GEO_STATE["s"]:
        return None
    try:
        r = GEO_STATE["s"].search(ip)
    except Exception:
        return None
    if not r:
        return None
    f = (str(r).split("|") + [""] * 5)[:5]
    prov = f[1] if f[1] not in ("0", "") else None
    city = f[2] if f[2] not in ("0", "") else None
    return (prov, city)


def enrich_one(ip):
    info = {"ip": ip, "rdns": None, "asn": None, "as_org": None, "country": None,
            "prefix": None, "province": None, "city": None, "geo_src": None}
    try:
        _g = geo_lookup(ip)
        if _g:
            info["province"], info["city"], info["geo_src"] = _g[0], _g[1], "ip2region"
    except Exception:
        pass
    try:
        rev = ".".join(reversed(ip.split(".")))
        for t, v in dns_query(rev + ".in-addr.arpa", 12):
            if t == "PTR":
                info["rdns"] = v
                break
    except Exception:
        pass
    try:
        v = ip2int(ip)
        rev = "%d.%d.%d.%d" % (v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF)
        txt = _dns_txt(rev + ".origin.asn.cymru.com", CFG.get("asn_resolvers") or [CFG["resolver"]])
        if txt:
            f = [x.strip() for x in txt.split("|")]
            if len(f) >= 5:
                info["asn"] = f[0].split()[0] if f[0] else None
                info["prefix"] = f[1]
                info["country"] = f[2]
        if info["asn"]:
            t2 = _dns_txt("AS%s.asn.cymru.com" % info["asn"], CFG.get("asn_resolvers") or [CFG["resolver"]])
            if t2:
                f = [x.strip() for x in t2.split("|")]
                info["as_org"] = f[-1]
    except Exception:
        pass
    xrun("INSERT INTO ip_info(ip,rdns,asn,as_org,country,prefix,province,city,geo_src,updated)"
         " VALUES(?,?,?,?,?,?,?,?,?,?)"
         " ON CONFLICT(ip) DO UPDATE SET rdns=excluded.rdns,asn=excluded.asn,as_org=excluded.as_org,"
         "country=excluded.country,prefix=excluded.prefix,province=excluded.province,"
         "city=excluded.city,geo_src=excluded.geo_src,updated=excluded.updated",
         (ip, info["rdns"], info["asn"], info["as_org"], info["country"], info["prefix"],
          info["province"], info["city"], info["geo_src"], now()))
    mark_dirty()
    return info


def enrich_loop():
    log("反查线程启动（rDNS/ASN/国家）")
    while True:
        try:
            if CFG.get("enrich"):
                rows = qall("SELECT DISTINCT src_ip AS ip FROM conns WHERE ts > ? UNION "
                            "SELECT DISTINCT ip FROM dns_hour WHERE hour > ?", (now() - 86400 * 7, now() - 86400 * 7))
                need = []
                for r in rows:
                    ip = r["ip"]
                    if not ip or is_local(ip):
                        continue
                    old = qone("SELECT updated, rdns, asn FROM ip_info WHERE ip=?", (ip,))
                    if old and now() - (old["updated"] or 0) < 86400 * 3 and (old["rdns"] or old["asn"]):
                        continue      # 已有结果且 3 天内查过；全空的记录允许重试
                    need.append(ip)
                for ip in need[:6]:
                    e = enrich_one(ip)
                    log("反查 %s → %s %s %s" % (ip, e.get("rdns"), e.get("asn"), e.get("country")))
                    iprow = e
                    xrun("UPDATE devices SET rdns=COALESCE(?,rdns), asn=COALESCE(?,asn),"
                         "as_org=COALESCE(?,as_org), country=COALESCE(?,country),"
                         "ip_prefix=COALESCE(?,ip_prefix), province=COALESCE(?,province),"
                         "city=COALESCE(?,city), geo_src=COALESCE(?,geo_src) WHERE src_ips LIKE ?",
                         (iprow.get("rdns"), iprow.get("asn"), iprow.get("as_org"),
                          iprow.get("country"), iprow.get("prefix"), iprow.get("province"),
                          iprow.get("city"), iprow.get("geo_src"), '%"' + ip + '"%'))
                    _DEV_CACHE.clear()
        except Exception as e:
            log("反查异常: %s" % e)
        time.sleep(int(CFG.get("enrich_interval", 120)))


# ---------------------------------------------------------------------------
# 维护线程：裁剪 & 滚动统计
# ---------------------------------------------------------------------------

def reattribute_doh(limit=3000):
    """把还没归属的 DoH 请求按 IP+时间窗回溯归属（抓包连接常常比 nginx 日志晚落库）。"""
    rows = qall("SELECT id, ip, ts FROM doh_requests WHERE device_id IS NULL"
                " ORDER BY id DESC LIMIT ?", (limit,))
    n = 0
    for r in rows:
        c = qone("SELECT device_id FROM conns WHERE src_ip=? AND ts BETWEEN ? AND ?"
                 " AND kind IN ('tls443','doh443','doh444')"
                 " ORDER BY (kind='doh444' OR kind='doh443') DESC, ts DESC LIMIT 1",
                 (r["ip"], r["ts"] - 300, r["ts"] + 120))
        if c and c["device_id"]:
            xrun("UPDATE doh_requests SET device_id=? WHERE id=?", (c["device_id"], r["id"]))
            n += 1
    if n:
        mark_dirty()
    return n


def reattribute_dotf(limit=4000):
    """dotfront 明文行若当时还没匹配到设备（连接尚在内存/未落库），这里按 (ip, sport) 回溯归属。"""
    rows = qall("SELECT id, ip, sport, ts FROM dns_recent WHERE src='dotfront-plain' AND device_id IS NULL"
                " AND sport IS NOT NULL ORDER BY id DESC LIMIT ?", (limit,))
    n = 0
    for r in rows:
        c = qone("SELECT device_id FROM conns WHERE src_ip=? AND sport=? AND dport=853"
                 " AND device_id IS NOT NULL ORDER BY ABS(ts-?) LIMIT 1", (r["ip"], r["sport"], r["ts"]))
        if c and c["device_id"]:
            xrun("UPDATE dns_recent SET device_id=? WHERE id=?", (c["device_id"], r["id"]))
            n += 1
            continue
        did = _ip_single_device(r["ip"])
        if did:
            xrun("UPDATE dns_recent SET device_id=?, src='dotfront-ip' WHERE id=?", (did, r["id"]))
            n += 1
    if n:
        mark_dirty()
    return n


def _vacuum_weekly():
    """每周日凌晨 4 点做一次 VACUUM（回收 DELETE 留下的空洞）+ PRAGMA optimize。
    库是 WAL 模式，VACUUM 期间读不阻塞；109MB 级别耗时数秒，只在低峰做。"""
    try:
        row = qone("SELECT v FROM kv WHERE k='last_vacuum'")
        last = int(row["v"]) if row and str(row["v"] or "").isdigit() else 0
        if now() - last < 7 * 86400:
            return
        if time.localtime().tm_hour != 4:
            return
        with DB_LOCK:
            db().commit()
            db().execute("VACUUM")
            try:
                db().execute("PRAGMA optimize")
            except Exception:
                pass
            db().execute("INSERT INTO kv(k,v) VALUES('last_vacuum',?)"
                         " ON CONFLICT(k) DO UPDATE SET v=excluded.v", (str(int(now())),))
            db().commit()
        log("维护: VACUUM 完成（回收碎片）")
    except Exception as e:
        log("维护: VACUUM 失败 %s" % e)


def maintain_loop():
    while True:
        try:
            html = now()
            _prune_recent_req()
            reattribute_doh()
            reattribute_dotf()
            xrun("DELETE FROM dns_recent WHERE id <= (SELECT MAX(id)-? FROM dns_recent)",
                 (int(CFG["dns_recent_rows"]),))
            xrun("DELETE FROM conns WHERE ts < ?", (html - int(CFG["keep_conns_hours"]) * 3600,))
            xrun("DELETE FROM doh_requests WHERE ts < ?", (html - int(CFG["keep_doh_hours"]) * 3600,))
            xrun("DELETE FROM events WHERE id <= (SELECT MAX(id)-5000 FROM events)")
            _vacuum_weekly()
            mark_dirty()
            with DB_LOCK:
                db().commit()
                _DIRTY[0] = False
                try:
                    db().execute("PRAGMA wal_checkpoint(PASSIVE)")   # 别让 WAL 无限长
                except Exception:
                    pass
        except Exception as e:
            log("维护异常: %s" % e)
        time.sleep(60)


def guarded_loop(fn, name):
    """任何一路采集线程崩了都自动重启，避免「看板看着正常、其实某路早死了」。"""
    while True:
        try:
            fn()
            log("%s 线程自行退出，10 秒后重启" % name)
            time.sleep(10)
        except Exception:
            log("%s 线程异常，5 秒后重启：%s" % (name, traceback.format_exc().splitlines()[-1]))
            time.sleep(5)


# ---------------------------------------------------------------------------
# HTTP API
# ---------------------------------------------------------------------------

SUMMARY_CACHE = {"t": 0, "v": None}
SUMMARY_LOCK = threading.Lock()


def api_clusters():
    rows = [dict(r) for r in qall("SELECT * FROM clusters ORDER BY active DESC, n_conns DESC LIMIT 400")]
    for r in rows:
        try:
            r["member_ids_list"] = jload(r.get("member_ids"), []) or []
        except Exception:
            r["member_ids_list"] = []
        r.pop("member_ids", None)
        try:
            r["evidence_list"] = jload(r.get("evidence"), []) or []
        except Exception:
            r["evidence_list"] = []
        r.pop("evidence", None)
        r["ips_list"] = jload(r.get("ips"), []) or []
        r.pop("ips", None)
    return {"clusters": rows, "count": len(rows)}


def api_summary():
    t0 = now() - 86400
    out = {}
    out["ts"] = now()
    DNS_PROTO_SQL = ("(protos LIKE '%\"dot\"%' OR protos LIKE '%\"doh444\"%'"
                     " OR protos LIKE '%\"doh443\"%' OR protos LIKE '%\"doq\"%'"
                     " OR protos LIKE '%\"quic\"%')")
    out["devices"] = qone("SELECT COUNT(*) c FROM devices WHERE source='server' AND linked_to IS NULL"
                          " AND " + DNS_PROTO_SQL)["c"]
    out["devices_all"] = qone("SELECT COUNT(*) c FROM devices WHERE source='server'"
                              " AND linked_to IS NULL")["c"]
    out["devices_active"] = qone("SELECT COUNT(*) c FROM devices WHERE source='server' AND last_seen > ?"
                                 " AND " + DNS_PROTO_SQL, (now() - 3600,))["c"]
    out["devices_web_only"] = out["devices_all"] - out["devices"]
    out["devices_new24"] = qone("SELECT COUNT(*) c FROM devices WHERE source='server' AND first_seen > ?"
                                " AND " + DNS_PROTO_SQL, (t0,))["c"]
    # ==== BOUND-ONLY-PATCH v1 ====
    # 已绑定设备 = 有登记记录指向它的设备簇（enrollments.matched_device）。
    # 用户口径：设备页只显示通过绑定的设备，未绑定的是猜测，不进列表。
    out["bound_devices"] = qone("SELECT COUNT(*) c FROM devices WHERE source='server' AND linked_to IS NULL"
                                " AND EXISTS (SELECT 1 FROM enrollments e WHERE e.matched_device = devices.id)")["c"]
    out["conns"] = qone("SELECT COUNT(*) c FROM conns")["c"]
    out["dns_queries"] = qone("SELECT SUM(n) s FROM dns_hour WHERE hour > ?", (t0,))["s"] or 0
    out["doh_requests"] = qone("SELECT COUNT(*) c FROM doh_requests WHERE ts > ?", (t0,))["c"]
    out["probes"] = qone("SELECT COUNT(*) c FROM conns WHERE ts > ? AND probe=1", (t0,))["c"]
    rr = qone("SELECT CAST(AVG(rtt_ms) AS INTEGER) v FROM conns WHERE ts > ? AND"
              " rtt_ms IS NOT NULL", (t0,))
    out["rtt_avg"] = rr["v"] if rr else None
    out["by_kind"] = [dict(r) for r in qall(
        "SELECT kind, COUNT(*) n, COUNT(DISTINCT device_id) devs FROM conns WHERE ts > ? GROUP BY kind ORDER BY n DESC",
        (t0,))]
    out["by_ip"] = [dict(r) for r in qall(
        "SELECT src_ip ip, COUNT(*) n, COUNT(DISTINCT device_id) devs, MAX(ts) last_ts FROM conns"
        " WHERE ts > ? GROUP BY src_ip ORDER BY n DESC LIMIT 12", (t0,))]
    out["by_proto_dns"] = [dict(r) for r in qall(
        "SELECT proto, SUM(n) n, COUNT(DISTINCT ip) ips FROM dns_hour WHERE hour > ? GROUP BY proto ORDER BY n DESC",
        (t0,))]
    out["top_domains"] = [dict(r) for r in qall(
        "SELECT qh, COUNT(*) n FROM dns_recent WHERE ts > ? GROUP BY qh ORDER BY n DESC LIMIT 15",
        (now() - 3600,))]
    out["top_devices"] = [dict(r) for r in qall(
        "SELECT d.id, d.label, d.os_guess, d.ja4, d.ua, d.conn_count, d.last_seen, d.protos,"
        " d.src_ips FROM devices d WHERE d.source='server'"
        " ORDER BY d.last_seen DESC LIMIT 10")]
    out["hourly"] = [dict(r) for r in qall(
        "SELECT (ts/3600)*3600 h, COUNT(*) conns, COUNT(DISTINCT device_id) devs FROM conns"
        " WHERE ts > ? GROUP BY h ORDER BY h", (now() - 86400,))]
    out["hourly_dns"] = [dict(r) for r in qall(
        "SELECT hour h, SUM(n) n FROM dns_hour WHERE hour > ? GROUP BY hour ORDER BY hour",
        (now() - 86400,))]
    out["events"] = [dict(r) for r in qall(
        "SELECT e.ts, e.kind, e.device_id, d.label, d.fp_key, d.os_guess, d.ja4 FROM events e"
        " LEFT JOIN devices d ON d.id=e.device_id ORDER BY e.id DESC LIMIT 20")]
    # 2026-10-05：两个新指标
    #  · q_per_conn = 24h 内「非探测连接」平均每条连接携带多少查询 —— 客户端是否复用连接的直接信号。
    #    实测参考：家庭 IP ≈12（正常复用）；若掉到 ~1 说明变成"一次查询一次 TLS 握手"，延迟与 CPU 都会跳。
    #  · unfingerprinted = 抓包看得见但指纹不出来的连接数（代表"看不清的流量"）
    _qc = qone("SELECT COUNT(*) n, SUM(COALESCE(q_est,0)) q FROM conns WHERE ts > ?"
               " AND COALESCE(probe,0)=0 AND kind IN ('dot','doh444','doh443')", (t0,))
    out["q_per_conn"] = round(float(_qc["q"] or 0) / _qc["n"], 2) if _qc and _qc["n"] else None
    out["q_per_conn_n"] = _qc["n"] if _qc else 0
    out["unfingerprinted"] = SNIFF_STATS.get("unfingerprinted")
    out["sniff"] = dict(SNIFF_STATS)
    out["counters"] = dict(COUNTERS)
    out["doh_log_on"] = os.path.exists(CFG["doh_log"])
    alerts = []
    if out.get("q_per_conn") is not None and out["q_per_conn"] < 2:
        alerts.append({"level":"warn","code":"low_q_per_conn","text":"DoT/DoH 连接复用率偏低，可能增加握手延迟和 CPU 负载"})
    if out.get("unfingerprinted") and out["unfingerprinted"] > 20:
        alerts.append({"level":"warn","code":"unfingerprinted","text":"存在较多未完成设备指纹的连接"})
    if out.get("ndpi") and out["ndpi"].get("last_run"):
        if now() - out["ndpi"]["last_run"] > max(7200, int(CFG.get("ndpi_interval",3600))*2):
            alerts.append({"level":"warn","code":"ndpi_stale","text":"nDPI 最近一次采样已过期"})
    out["alerts"] = alerts
    out["tail"] = {"agh_off": _AGH_OFF[0], "doh_off": _DOH_OFF[0]}
    # nDPI（旁路判定）：协议占比 / 分类 / 风险 / 逐设备
    try:
        last = qone("SELECT MAX(run_ts) m, COUNT(*) n FROM ndpi_flows")
        out["ndpi_risk_policy"] = "风险信号：单项 nDPI 标签不等于异常；需与设备指纹漂移、目的 ASN 新出现和重复连接组合判断。"
        out["ndpi"] = {
            "last_run": (last["m"] if last else None),
            "flows": (last["n"] if last else 0) or 0,
            "attributed": (qone("SELECT COUNT(*) c FROM ndpi_flows WHERE device_id IS NOT NULL")["c"] or 0),
            "protos": [dict(r) for r in qall(
                "SELECT proto, COUNT(*) n, COUNT(DISTINCT device_id) devs FROM ndpi_flows"
                " GROUP BY proto ORDER BY n DESC LIMIT 8")],
            "categories": [dict(r) for r in qall(
                "SELECT category, COUNT(*) n FROM ndpi_flows WHERE category<>''"
                " GROUP BY category ORDER BY n DESC LIMIT 6")],
            "risks": [dict(r) for r in qall(
                "SELECT risks, COUNT(*) n FROM ndpi_flows WHERE risks<>''"
                " GROUP BY risks ORDER BY n DESC LIMIT 6")],
            "devices": [dict(r) for r in qall(
                "SELECT d.id, COALESCE(NULLIF(d.vendor,''),'未识别') label,"
                " GROUP_CONCAT(DISTINCT f.proto) protos, COUNT(*) n"
                " FROM ndpi_flows f JOIN devices d ON d.id=f.device_id"
                " GROUP BY d.id ORDER BY n DESC LIMIT 8")],
        }
    except Exception:
        out["ndpi"] = {}
    out["live_conns"] = len(CONNS)
    out["db_bytes"] = os.path.getsize(CFG["db"]) if os.path.exists(CFG["db"]) else 0
    # 分层口径：指纹 → 物理客户端簇 → 活跃客户端；扫描器/自测/噪声单列
    try:
        out["clusters"] = {
            "all": qone("SELECT COUNT(*) c FROM clusters")["c"] or 0,
            "active": qone("SELECT COUNT(*) c FROM clusters WHERE active=1")["c"] or 0,
            "real": qone("SELECT COUNT(*) c FROM clusters WHERE active=1 AND probe_class IS NULL")["c"] or 0,
            "scanner": qone("SELECT COUNT(*) c FROM clusters WHERE probe_class='scanner'")["c"] or 0,
            "self_test": qone("SELECT COUNT(*) c FROM clusters WHERE probe_class='self_test'")["c"] or 0,
            "noise": qone("SELECT COUNT(*) c FROM clusters WHERE noise=1")["c"] or 0,
            "fingerprints": qone("SELECT COUNT(*) c FROM devices WHERE source='server'")["c"] or 0,
            "fingerprints_dns": qone("SELECT COUNT(*) c FROM devices WHERE source='server' AND"
                                     " (protos LIKE '%dot%' OR protos LIKE '%doh%')")["c"] or 0,
        }
    except Exception:
        out["clusters"] = {}
    return out


def api_devices(params):
    q = (params.get("q", [""])[0] or "").strip()
    # 2026-10-05 修：原来把 dns 当布尔（== "1"），而前端传的是种类名（dns=dot / dns=doh…）
    # → 判定恒为 False → 后端不过滤，每个标签都返回全量（实测 dot/doh 两份 2,310,604 字节完全相同）。
    _dns_p = (params.get("dns", ["1"])[0] or "").strip()
    only_dns = _dns_p == "1"
    # 前端 devUrl() 传的是**页面分类**（dev/dot/doh），不是 proto 名（dot/doh444/doh443）。
    # 2026-10-05：这里做映射；之前把它当布尔（=="1"）→ 判定恒 False → 完全不过滤。
    _KIND_SQL = {
        "dot":    ("d.protos LIKE ?", ('%"dot"%',)),
        "doh444": ("d.protos LIKE ?", ('%"doh444"%',)),
        "doh443": ("d.protos LIKE ?", ('%"doh443"%',)),
        "doh":    ("(d.protos LIKE ? OR d.protos LIKE ?)", ('%"doh444"%', '%"doh443"%')),
        "doq":    ("d.protos LIKE ?", ('%"doq"%',)),
        "quic":   ("d.protos LIKE ?", ('%"quic"%',)),
    }
    _KIND_PROTOS = {"dot": ("dot",), "doh": ("doh444", "doh443"),
                    "doh444": ("doh444",), "doh443": ("doh443",),
                    "doq": ("doq",), "quic": ("quic",)}
    kind_sql, kind_args = _KIND_SQL.get(_dns_p, ("", ()))
    kind_f = _dns_p if _dns_p in _KIND_PROTOS else ""
    _bound_only = params.get("bound", [""])[0] == "1"     # 只看已绑定设备（设备页默认）
    include_router = params.get("src", [""])[0] == "all"
    limit = min(int(params.get("limit", ["200"])[0]), 500)
    where = ["d.source='server'"] if not include_router else ["1=1"]
    args = []
    if _bound_only:
        where.append("EXISTS (SELECT 1 FROM enrollments e WHERE e.matched_device = d.id)")
    if kind_sql:
        # 在 SQL 里就过滤，LIMIT 才是"该类的前 N 台"（否则先取全量再在 Python 里丢，白付序列化）
        where.append(kind_sql)
        args.extend(kind_args)
    if q:
        where.append("(d.fp_key LIKE ? OR d.label LIKE ? OR d.src_ips LIKE ? OR d.ja3 LIKE ?"
                     " OR d.ja4 LIKE ? OR d.ua LIKE ? OR d.os_guess LIKE ? OR d.rdns LIKE ?"
                     " OR d.as_org LIKE ?)")
        for _ in range(9):
            args.append("%" + q + "%")
    rows = qall("SELECT d.*, (SELECT SUM(n) FROM dns_hour h WHERE h.ip IN"
                " (SELECT key FROM json_each(d.src_ips)) AND h.hour > ?) dns24,"
                " (SELECT COUNT(*) FROM conns c WHERE c.device_id=d.id AND c.ts > ?) conns24,"
                " (SELECT COUNT(*) FROM conns c WHERE c.device_id=d.id AND c.ts > ? AND c.probe=1) probes24,"
                " (SELECT SUM(c.q_est) FROM conns c WHERE c.device_id=d.id AND c.ts > ?) qest24,"
                " (SELECT CAST(AVG(c.q_rtt_ms) AS INTEGER) FROM conns c WHERE c.device_id=d.id"
                "   AND c.ts > ? AND c.q_rtt_ms IS NOT NULL) qrtt,"
                " (SELECT CAST(AVG(c.rtt_ms) AS INTEGER) FROM conns c WHERE c.device_id=d.id"
                "   AND c.ts > ? AND c.rtt_ms IS NOT NULL) rtt_ms,"
                " i.asn i_asn, i.as_org i_org, i.country i_cc, i.rdns i_rdns"
                " FROM devices d LEFT JOIN ip_info i ON i.ip ="
                " (SELECT key FROM json_each(d.src_ips) ORDER BY CAST(value AS INTEGER) DESC LIMIT 1)"
                " WHERE " + " AND ".join(where) + " ORDER BY d.last_seen DESC LIMIT ?",
                [now() - 86400] * 6 + args + [limit])
    out = []
    for r in rows:
        d = dict(r)
        protos = jload(d.get("protos"), {}) or {}
        if kind_f and not (set(protos) & set(_KIND_PROTOS[kind_f])):
            continue                      # SQL 已过滤，这里做双保险
        if only_dns and (d.get("source") != "server" or not (
                set(protos) & set(["dot", "doh444", "doh443", "doq", "quic"]))):
            continue      # 只看真正走 DoT/DoH 的设备；家庭内网设备在独立页签
        d["src_ips_list"] = list((jload(d.get("src_ips"), {}) or {}).keys())
        d["protos_obj"] = protos
        d["infer"] = jload(d.get("infer_json"))
        d.pop("infer_json", None)
        cl = CLUSTER_MAP.get(d.get("cluster_id")) if d.get("cluster_id") else None
        if cl:
            d["cluster_name"] = cl.get("name")
            d["cluster_conf"] = cl.get("conf")
            d["cluster_active"] = cl.get("active")
            d["cluster_noise"] = cl.get("noise")
            d["cluster_n"] = cl.get("n_members")
        d["probe_class"] = d.get("probe_class")
        # 2026-10-05 列表接口减肥：实测每台 ~9KB，大头是 infer(3.6KB)/tls_json(2.3KB)/http_json(0.8KB)。
        # 其中 tls_json/http_json/behavior_json 在前端**引用 0 次**（原始块只有详情接口 /api/device 才用），
        # infer 列表只用到 label/confidence/role。删掉后可显著降低传输与客户端 JSON.parse。
        for _h in ("tls_json", "http_json", "behavior_json"):
            d.pop(_h, None)
        _inf = d.get("infer")
        if isinstance(_inf, dict):
            d["infer"] = {_k: _inf[_k] for _k in ("label", "confidence", "evidence_count", "drift_state", "role", "os", "vendor", "category")
                          if _inf.get(_k) is not None}
        out.append(d)
    return {"devices": out, "count": len(out)}


def api_device(params):
    did = int(params.get("id", ["0"])[0])
    d = qone("SELECT * FROM devices WHERE id=?", (did,))
    if not d:
        return {"error": "not found"}
    dev = dict(d)
    dev["src_ips_list"] = list((jload(dev.get("src_ips"), {}) or {}).keys())
    dev["protos_obj"] = jload(dev.get("protos"), {}) or {}
    dev["variants_list"] = jload(dev.get("variants"), []) or []
    dev["tls"] = jload(dev.get("tls_json"))
    dev["tcp"] = jload(dev.get("tcp_json"))
    dev["http"] = jload(dev.get("http_json"))
    dev["tags_list"] = jload(dev.get("tags"), []) or []
    dev["infer"] = jload(dev.get("infer_json"))
    dev["top_domains_list"] = jload(dev.get("top_domains"), []) or []
    conns = [dict(r) for r in qall(
        "SELECT id,ts,end_ts,src_ip,sport,dport,kind,ja3,ja4,tls_ver,cipher,alpn,sni,resumed,"
        "cert_bytes,cert_count,in_bytes,out_bytes,in_pkts,out_pkts,duration_ms,rtt_ms,probe,"
        "tcp_sig,tcp_json FROM conns WHERE device_id=? ORDER BY ts DESC LIMIT 120", (did,))]
    dns_hours = [dict(r) for r in qall(
        "SELECT hour,proto,SUM(n) n,SUM(filtered) filt,SUM(a) a,SUM(aaaa) aaaa,SUM(https) https,"
        "SUM(ptr) ptr,SUM(other) other,SUM(sum_ms) ms,MAX(max_ms) mmax FROM dns_hour WHERE device_id=?"
        " GROUP BY hour,proto ORDER BY hour DESC LIMIT 200", (did,))]
    recent = [dict(r) for r in qall(
        "SELECT ts,qh,qt,cp,filtered,elapsed_ms,upstream,answer,src,edns,do_bit,udp_size,sport,rcode,rule FROM dns_recent WHERE device_id=?"
        " ORDER BY id DESC LIMIT 120", (did,))]
    if not recent and dev["src_ips_list"]:
        recent = [dict(r) for r in qall(
            "SELECT ts,qh,qt,cp,filtered,elapsed_ms,upstream,answer,src,edns,do_bit,udp_size,sport,rcode,rule FROM dns_recent WHERE ip IN"
            " (%s) ORDER BY id DESC LIMIT 120" % ",".join("?" * len(dev["src_ips_list"])),
            tuple(dev["src_ips_list"]))]
    doh = [dict(r) for r in qall(
        "SELECT ts,ip,method,uri,qname,http_ver,status,rt,tls_proto,cipher,cipher_list,curves,alpn,"
        "sni,resumed,ua,headers,xff FROM doh_requests WHERE device_id=? ORDER BY id DESC LIMIT 80",
        (did,))]
    ipinfo = [dict(r) for r in qall(
        "SELECT * FROM ip_info WHERE ip IN (%s)" % ",".join("?" * max(1, len(dev["src_ips_list"]))),
        tuple(dev["src_ips_list"] or ["-"]))]
    router = []
    linked = [dict(r) for r in qall(
        "SELECT id,label,fp_key,os_guess,ja4,last_seen FROM devices WHERE linked_to=?", (did,))]
    tl = [dict(r) for r in qall(
        "SELECT (ts/3600)*3600 h, COUNT(*) n FROM conns WHERE device_id=? GROUP BY h ORDER BY h", (did,))]
    return {"device": dev, "conns": conns, "dns_hours": dns_hours, "recent": recent,
            "doh": doh, "ip_info": ipinfo, "router": router, "linked": linked, "timeline": tl}


def api_router_list(params):
    rows = [dict(r) for r in qall(
        "SELECT r.*, d.fp_key d_fp, d.label d_label, d.os_guess d_os FROM router_devices r"
        " LEFT JOIN devices d ON d.id=r.device_id ORDER BY r.last_seen DESC LIMIT 300")]
    runs = [dict(r) for r in qall("SELECT * FROM router_runs ORDER BY id DESC LIMIT 20")]
    return {"devices": rows, "runs": runs}


def _mac_norm(m):
    m = (m or "").strip().upper().replace("-", ":")
    return m if len(m) == 17 else (m or "")


def router_sections(body):
    """解析 agent 推来的 @@SECTION 分段原始载荷。"""
    sec, cur, buf = {}, None, []
    for line in body.split("\n"):
        if line.startswith("@@"):
            if cur:
                sec[cur] = "\n".join(buf)
            cur = line[2:].strip().upper()
            buf = []
        elif cur:
            buf.append(line)
    if cur:
        sec[cur] = "\n".join(buf)
    return sec


def router_parse_raw(body):
    """把路由器侧「原样采集」的 JSON/文本汇总成设备清单（聚合逻辑全在服务器侧）。"""
    sec = router_sections(body)
    meta = {}
    for line in (sec.get("META") or "").split("\n"):
        if "=" in line:
            k, _, v = line.partition("=")
            meta[k.strip()] = v.strip()

    hints = {}
    try:
        hints = json.loads(sec.get("HOSTHINTS") or "{}") or {}
    except Exception:
        pass

    leases = {}
    for line in (sec.get("LEASES") or "").split("\n"):
        f = line.split()
        if len(f) >= 4 and f[1].count(":") == 5:
            try:
                exp = int(f[0])
            except Exception:
                exp = 0
            leases[_mac_norm(f[1])] = {"ip": f[2], "hostname": (f[3] if f[3] != "*" else ""),
                                       "expiry": exp}

    neigh = {}
    ip2mac = {}
    for line in (sec.get("NEIGH") or "").split("\n"):
        f = line.split()
        if len(f) >= 5 and f[1] == "dev":
            ip, iface, mac, state = f[0], f[2], "", f[-1]
            for i, tok in enumerate(f):
                if tok == "lladdr" and i + 1 < len(f):
                    mac = _mac_norm(f[i + 1])
            neigh[ip] = {"iface": iface, "mac": mac, "state": state}
            if mac:
                ip2mac[ip] = mac

    wifi = {}
    try:
        wj = json.loads(sec.get("WIFI") or "{}") or {}
        for r in (wj.get("results") or []):
            m = _mac_norm(r.get("mac"))
            if m:
                wifi[m] = {"signal": r.get("signal"), "connected_time": r.get("connected_time"),
                           "inactive": r.get("inactive"),
                           "rx_bytes": (r.get("rx") or {}).get("bytes"),
                           "tx_bytes": (r.get("tx") or {}).get("bytes"),
                           "rx_rate": (r.get("rx") or {}).get("rate"),
                           "tx_rate": (r.get("tx") or {}).get("rate"),
                           "rx_mhz": (r.get("rx") or {}).get("mhz")}
    except Exception:
        pass

    iw = {}
    try:
        ij = json.loads(sec.get("IWINFO") or "{}") or {}
        iw = {"ssid": ij.get("ssid"), "channel": ij.get("channel"),
              "band": ("5GHz" if (ij.get("channel") or 0) > 14 else "2.4GHz") if ij.get("channel") else None}
    except Exception:
        pass

    clash = {"by_ip": {}, "total_ul": 0, "total_dl": 0, "n": 0}
    try:
        cj = json.loads(sec.get("CLASH") or "{}") or {}
        clash["total_ul"] = int(cj.get("uploadTotal") or 0)
        clash["total_dl"] = int(cj.get("downloadTotal") or 0)
        for c in (cj.get("connections") or []):
            md = c.get("metadata") or {}
            cip = md.get("sourceIP") or ""
            if not cip:
                continue
            a = clash["by_ip"].get(cip)
            if a is None:
                a = {"n": 0, "ul": 0, "dl": 0, "hosts": {}, "apps": {}, "chains": {},
                     "rules": {}, "dests": {}, "net": {}, "dns_mode": ""}
                clash["by_ip"][cip] = a
            a["n"] += 1
            clash["n"] += 1
            a["ul"] += int(c.get("upload") or 0)
            a["dl"] += int(c.get("download") or 0)
            h = (md.get("host") or md.get("sniffHost") or "").strip()
            if h:
                a["hosts"][h] = a["hosts"].get(h, 0) + 1
            nm = (md.get("process") or "").strip()
            if not nm:
                pp = (md.get("processPath") or "").strip()
                nm = pp.split("/")[-1] if pp else ""
            if nm:
                a["apps"][nm] = a["apps"].get(nm, 0) + 1
            ch = ",".join(c.get("chains") or [])
            if ch:
                a["chains"][ch] = a["chains"].get(ch, 0) + 1
            rl = (md.get("rule") or "").strip()
            if md.get("rulePayload"):
                rl = "%s:%s" % (rl, md.get("rulePayload"))
            if rl:
                a["rules"][rl] = a["rules"].get(rl, 0) + 1
            dst = (md.get("destinationIP") or "").strip()
            if dst:
                a["dests"][dst] = a["dests"].get(dst, 0) + 1
            net = (md.get("network") or "").strip()
            if net:
                a["net"][net] = a["net"].get(net, 0) + 1
            a["dns_mode"] = md.get("dnsMode") or a["dns_mode"]
    except Exception as e:
        log("CLASH 段解析失败: %s" % e)

    # 汇成设备清单
    devs = []
    seen_mac = set()
    for mac in sorted(set(list(hints.keys()) + list(leases.keys()) + list(wifi.keys())), key=lambda x: _mac_norm(x)):
        m = _mac_norm(mac)
        if not m or m in seen_mac:
            continue
        seen_mac.add(m)
        h = hints.get(mac) or hints.get(m) or {}
        le = leases.get(m)
        ips = [x for x in (h.get("ipaddrs") or []) if x]
        if le and le["ip"] not in ips:
            ips.insert(0, le["ip"])
        ip6 = [x for x in (h.get("ip6addrs") or []) if x and not x.startswith("fe80")]
        nm = (le.get("hostname") if le else "") or ((h.get("name") or "").split(".")[0])
        w = wifi.get(m) or {}
        cl = None
        for ip in list(ips) + list(ip6):
            if ip in clash["by_ip"]:
                cl = clash["by_ip"][ip]
                break
        st = None
        ifc = None
        for ip in ips:
            if ip in neigh:
                st = neigh[ip]["state"]
                ifc = neigh[ip]["iface"]
                break
        devs.append({"mac": m, "ip": ips[0] if ips else None, "ipv6": ip6[0] if ip6 else None,
                     "hostname": nm or None, "iface": ifc, "essid": iw.get("ssid"),
                     "band": iw.get("band"),
                     "neigh": st, "dhcp_until": (le or {}).get("expiry"),
                     "is_wifi": 1 if w else 0, "signal": w.get("signal"),
                     "channel": iw.get("channel"),
                     "queries": (cl or {}).get("n"), "conns": (cl or {}).get("n"),
                     "ul_bytes": (cl or {}).get("ul"), "dl_bytes": (cl or {}).get("dl"),
                     "apps": sorted((cl or {}).get("apps", {}).items(), key=lambda kv: -kv[1])[:20],
                     "top_domains": sorted((cl or {}).get("hosts", {}).items(), key=lambda kv: -kv[1])[:25],
                     "chains": (cl or {}).get("chains") or {},
                     "rules": (cl or {}).get("rules") or {},
                     "protos": {"clash_conn": (cl or {}).get("n", 0),
                                "direct": sum(v for k, v in ((cl or {}).get("chains") or {}).items() if "DIRECT" in k),
                                "proxy": sum(v for k, v in ((cl or {}).get("chains") or {}).items() if "DIRECT" not in k)},
                     "wifi_raw": w, "ips_all": ips + ip6,
                     "src": "hosthints/leases/wifi"})

    # 只出现在 Clash 连接表里的 IP（没有 MAC 归属）
    known_ips = set()
    for d in devs:
        known_ips.update(d.get("ips_all") or [])
    for cip, a in clash["by_ip"].items():
        if cip in known_ips:
            continue
        if cip in ip2mac:      # 有 MAC 但不在 hosthints 里
            continue
        devs.append({"mac": "ip:" + cip, "ip": cip, "hostname": None, "is_wifi": 0,
                     "queries": a["n"], "conns": a["n"], "ul_bytes": a["ul"], "dl_bytes": a["dl"],
                     "apps": sorted(a["apps"].items(), key=lambda kv: -kv[1])[:20],
                     "top_domains": sorted(a["hosts"].items(), key=lambda kv: -kv[1])[:25],
                     "chains": a["chains"], "rules": a["rules"],
                     "protos": {"clash_conn": a["n"]}, "src": "clash-only", "ips_all": [cip]})
    return meta, devs, clash, iw


def router_upsert(devs, agent, ts, nbytes, note):
    n = 0
    for it in devs:
        mac = _mac_norm(it.get("mac"))
        if not mac:
            continue
        ip = it.get("ip") or None
        host = it.get("hostname") or None
        key = "router:" + mac
        did = dev_touch(key, {"source": "router"}, proto_kind=None, ip=ip)
        if host:
            try:
                xrun("UPDATE devices SET label=? WHERE id=? AND (label IS NULL OR label='')",
                     (trim(host, 80), did))
            except Exception:
                pass
        xrun("INSERT INTO router_devices(mac,device_id,ip,ipv6,hostname,vendor,iface,essid,band,"
             "neigh,dhcp_until,is_wifi,first_seen,last_seen,agent_ts,queries,protos,qtypes,"
             "top_json,apps,raw,signal,channel,conns,ul_bytes,dl_bytes,chains,rules,src)"
             " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
             " ON CONFLICT(mac) DO UPDATE SET device_id=excluded.device_id,ip=excluded.ip,"
             "ipv6=excluded.ipv6,hostname=COALESCE(excluded.hostname,router_devices.hostname),"
             "iface=COALESCE(excluded.iface,router_devices.iface),essid=COALESCE(excluded.essid,router_devices.essid),"
             "band=COALESCE(excluded.band,router_devices.band),neigh=excluded.neigh,"
             "dhcp_until=excluded.dhcp_until,is_wifi=excluded.is_wifi,last_seen=excluded.last_seen,"
             "agent_ts=excluded.agent_ts,queries=excluded.queries,protos=excluded.protos,"
             "top_json=excluded.top_json,apps=excluded.apps,raw=excluded.raw,signal=excluded.signal,"
             "channel=excluded.channel,conns=excluded.conns,ul_bytes=excluded.ul_bytes,"
             "dl_bytes=excluded.dl_bytes,chains=excluded.chains,rules=excluded.rules,src=excluded.src",
             (mac, did, ip, it.get("ipv6"), host, it.get("vendor"), it.get("iface"),
              it.get("essid"), it.get("band"), it.get("neigh"), it.get("dhcp_until"),
              1 if it.get("is_wifi") else 0, ts, ts, ts,
              it.get("queries"), jdump(it.get("protos") or {}), "{}",
              jdump(it.get("top_domains") or []), jdump(it.get("apps") or []),
              jdump(it)[:6000], it.get("signal"), it.get("channel"), it.get("conns"),
              it.get("ul_bytes"), it.get("dl_bytes"), jdump(it.get("chains") or {}),
              jdump(it.get("rules") or {}), it.get("src")))
        n += 1
    xrun("INSERT INTO router_runs(ts,agent,n_devices,bytes,note) VALUES(?,?,?,?,?)",
         (ts, agent, n, nbytes, trim(str(note or ""), 200)))
    mark_dirty()
    _DEV_CACHE.clear()
    return n


def api_router_ingest(body, token):
    if not CFG.get("router_token") or token != CFG["router_token"]:
        return {"error": "unauthorized"}, 401
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception as e:
        return {"error": "bad json: %s" % e}, 400
    devs = payload.get("devices") or []
    ts = int(payload.get("ts") or now())
    n = router_upsert(devs, payload.get("agent") or "router", ts, len(body),
                      payload.get("note"))
    return {"ok": True, "devices": n, "ts": ts}


def api_router_raw(body, token, ctype):
    if not CFG.get("router_token") or token != CFG["router_token"]:
        return {"error": "unauthorized"}, 401
    raw_len = len(body)
    if body[:2] == b"\x1f\x8b":
        import gzip as _gz
        try:
            body = _gz.decompress(body)
        except Exception as e:
            return {"error": "gunzip failed: %s" % e}, 400
    try:
        text = body.decode("utf-8", "replace")
    except Exception as e:
        return {"error": "decode: %s" % e}, 400
    meta, devs, clash, iw = router_parse_raw(text)
    ts = int(meta.get("ts") or now())
    note = "host=%s uptime=%ss clash_conns=%d ul=%d dl=%d ssid=%s" % (
        meta.get("hostname"), meta.get("uptime"), clash.get("n", 0),
        clash.get("total_ul", 0), clash.get("total_dl", 0), iw.get("ssid"))
    n = router_upsert(devs, meta.get("agent") or "router", ts, raw_len, note)
    return {"ok": True, "devices": n, "ts": ts, "clash_conns": clash.get("n", 0),
            "parsed": len(devs)}, 200


def api_label(params, body):
    did = int(params.get("id", ["0"])[0])
    try:
        b = json.loads(body.decode("utf-8"))
    except Exception:
        b = {}
    sets, args = [], []
    for k in ("label", "note"):
        if k in b:
            sets.append("%s=?" % k)
            args.append(b[k])
    if "tags" in b:
        sets.append("tags=?")
        args.append(jdump(b["tags"]))
    if "linked_to" in b:
        sets.append("linked_to=?")
        args.append(int(b["linked_to"] or 0) or None)
    if not sets:
        return {"error": "nothing to update"}
    args.append(did)
    xrun("UPDATE devices SET %s WHERE id=?" % ",".join(sets), args)
    # 同一指纹（JA4 或 JA3 相同）的其它未命名条目同步命名：指纹相同即同一客户端软件/设备类型
    if b.get("label"):
        row = qone("SELECT ja4, ja3 FROM devices WHERE id=?", (did,))
        if row and (row["ja4"] or row["ja3"]):
            xrun("UPDATE devices SET label=? WHERE id<>? AND (label IS NULL OR label='')"
                 " AND ((ja4 IS NOT NULL AND ja4=?) OR (ja3 IS NOT NULL AND ja3=?))",
                 (b["label"], did, row["ja4"], row["ja3"]))
        try:
            d2 = qone("SELECT ja4, ja3, tcp_sig, tls_json FROM devices WHERE id=?", (did,))
            if d2:
                dict_learn(jload(d2.get("tls_json"), {}) or {}, d2.get("ja3"), d2.get("tcp_sig"),
                           b["label"], 3, "manual", "人工命名（最强证据）")
        except Exception as e:
            log("人工命名写字典失败: %s" % e)
    mark_dirty()
    _DEV_CACHE.clear()
    return {"ok": True, "id": did}


def api_router_token(params):
    return {"token_set": bool(CFG.get("router_token"))}



# ==== ENROLL PATCH v1 ====
def enroll_client_ip(handler):
    """nginx 已注入 X-Real-IP / X-Forwarded-For，取真实客户端出口 IP。"""
    try:
        xr = handler.headers.get("X-Real-IP")
        if xr:
            return xr.strip()
        xff = handler.headers.get("X-Forwarded-For") or ""
        if xff:
            return xff.split(",")[0].strip()
        return handler.client_address[0] if handler.client_address else ""
    except Exception:
        return ""


def enroll_recent_ja4(ip, window=25):
    """本 IP 在最近 window 秒内的 TLS 连接指纹（去重，按出现次数降序）。
    登记页加载本身会产生若干 :443 连接，抓包侧解析出的 ja4 即这台设备的浏览器指纹。"""
    if not ip:
        return []
    rows = qall("SELECT ja4, tcp_sig, COUNT(*) n FROM conns WHERE src_ip=? AND ts>? AND ja4 IS NOT NULL"
                " GROUP BY ja4 ORDER BY n DESC LIMIT 8", (ip, int(now()) - window))
    return [{"ja4": r["ja4"], "tcp_sig": r["tcp_sig"], "n": r["n"]} for r in rows]


def enroll_match(ja4, ip):
    """自动匹配已有簇：①同出口 IP 且 ja4 精确命中；②退一步，同出口 IP 的 DNS 簇里最近活跃的。"""
    if ja4:
        r = qone("SELECT id FROM devices WHERE ja4=? ORDER BY last_seen DESC LIMIT 1", (ja4,))
        if r:
            return r["id"], "ja4"
    if ip:
        r = qone("SELECT id FROM devices WHERE src_ips LIKE ? AND (protos LIKE '%\"dot\"%'"
                 " OR protos LIKE '%\"doh443\"%' OR protos LIKE '%\"doh444\"%')"
                 " ORDER BY last_seen DESC LIMIT 1", ('%"' + ip + '"%',))
        if r:
            return r["id"], "ip"
    return None, None


def api_enroll_create(body, ip):
    try:
        b = json.loads(body.decode("utf-8"))
    except Exception:
        b = {}
    # 2026-10-15 修复：ss 只在 api_join_register 内部定义过，这里引用会 NameError
    # → do_POST 兜底成 500 "internal error"（用户在设备指纹看板点「登记这台设备」看到的报错）。
    def ss(k, n):
        v = b.get(k)
        return v.strip()[:n] if isinstance(v, str) else ""

    name = (b.get("name") or "").strip()[:60]
    if not name:
        return {"error": "name required"}
    fp_id = (b.get("fp_id") or "").strip()[:64]
    fp = b.get("fp") or {}
    ja = enroll_recent_ja4(ip, int(b.get("window") or 25))
    _m = join_sni_probe(ss("sni", 24))      # 首选：SNI 标记证明过的"本次请求自己的 ja4"
    if _m and _m.get("ja4"):
        ja4, tcp_sig = _m["ja4"], _m.get("tcp_sig")
    else:
        ja4 = ja[0]["ja4"] if ja else None
        tcp_sig = ja[0]["tcp_sig"] if ja else None
    did, how = enroll_match(ja4, ip)
    nowt = now()
    row = qone("SELECT id FROM enrollments WHERE fp_id=?", (fp_id,)) if fp_id else None
    vals = (fp_id, name, (b.get("note") or "")[:200], jdump(fp),
            (b.get("ua") or "")[:400], (b.get("model") or "")[:80],
            (b.get("platform") or "")[:60], (b.get("platform_ver") or "")[:40], (b.get("arch") or "")[:40],
            ja4, jdump([x["ja4"] for x in ja]), tcp_sig, ip, None, nowt)
    if row:
        xrun("UPDATE enrollments SET fp_id=?,name=?,note=?,fp=?,ua=?,model=?,platform=?,platform_ver=?,arch=?,"
             "ja4=?,ja4_list=?,tcp_sig=?,src_ip=?,matched_device=?,updated=? WHERE id=?", vals + (row["id"],))
        eid = row["id"]
    else:
        xrun("INSERT INTO enrollments(fp_id,name,note,fp,ua,model,platform,platform_ver,arch,ja4,ja4_list,"
             "tcp_sig,src_ip,matched_device,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
             vals[:-1] + (nowt, nowt))
        r2 = qone("SELECT id FROM enrollments ORDER BY id DESC LIMIT 1")
        eid = r2["id"] if r2 else None
    # 2026-10-15（用户要求）：取消自动绑定 —— 上面算出的 did/how 只当「建议」返回给页面，
    # 登记记录不写 matched_device、也不写设备标签；绑定关系一律由人在登记列表里手动选择。
    return {"ok": True, "id": eid, "name": name, "client_ip": ip, "ja4": ja4, "tcp_sig": tcp_sig,
            "recent_ja4": ja, "suggest_device": did, "suggest_by": how,
            "matched_device": None, "matched_by": None}


def api_enroll_list():
    out = []
    _retry = 0
    for r in qall("SELECT * FROM enrollments ORDER BY updated DESC LIMIT 200"):
        d = dict(r)
        # 延迟补匹配：抓包侧写入有延迟，登记当刻的 25 秒窗口经常还没看到这次连接（手机那次就是这样丢的）。
        # 对"未绑定 + 最近 45 分钟登记"的记录，用更宽窗口(180s) + 严格唯一性再做一次尝试。
        # pinned=1 表示人工钉住（含人工选"未关联"），自动补匹配必须绕开
        if not d.get("matched_device") and not d.get("pinned") and _retry < 8:
            try:
                ip0 = d.get("src_ip") or ""
                if ip0 and (now() - (d.get("created") or 0)) < 2700:
                    _retry += 1
                    # ==== JOIN-CHECK-PATCH v4 ====
                    # ==== 2026-10-15（用户要求）：取消自动绑定 ====
                    # 这里原本会「延迟补匹配」——自己把登记绑到某个指纹簇并写设备标签。
                    # 现在整段停用：登记记录保持未绑定，绑定由人在列表里手动选择；
                    # 下面的 candidates（候选簇）仍然照常返回，供人参考。
                    _cands = []
                    if d.get("ja4"):
                        _cands.append(d["ja4"])
                    for _it in enroll_recent_ja4(ip0, 180):
                        _j = _it.get("ja4") if isinstance(_it, dict) else None
                        if _j and _j not in _cands:
                            _cands.append(_j)
                    d["ja4_cands"] = _cands
            except Exception:
                pass
        d["fp"] = jload(d.get("fp"), {})
        d["ja4_list"] = jload(d.get("ja4_list"), [])
        # 列表响应裁剪（2026-10-15）：fp2/hdr 是给观测表用的重字段（每条约 3–4KB），
        # 200 条会把响应撑到近 1MB、拖慢每次打开看板 ⇒ 列表只回长度摘要，明细仍在库里。
        for _bg in ("fp2", "hdr"):
            d[_bg + "_len"] = len(d.get(_bg) or "")
            d.pop(_bg, None)
        m = qone("SELECT id,label,os_guess,ja4,src_ips,conn_count,last_seen FROM devices WHERE id=?",
                 (d.get("matched_device") or 0,))
        d["matched"] = dict(m) if m else None
        cands = []
        ip = d.get("src_ip") or ""
        if ip:
            cands = [dict(x) for x in qall(
                "SELECT id,label,os_guess,ja4,conn_count,last_seen FROM devices WHERE src_ips LIKE ?"
                " ORDER BY (CASE WHEN ja4=? THEN 0 ELSE 1 END), last_seen DESC LIMIT 15",
                ('%"' + ip + '"%', d.get("ja4") or ""))]
        d["candidates"] = cands
        out.append(d)
    return {"enrollments": out, "ts": now()}


def api_enroll_link(body):
    """手动绑定 —— 2026-10-15 起这是唯一的绑定入口（自动绑定已按用户要求取消）。

    · {id, device_id}  绑定到指定指纹簇（device_id=0 表示明确「未关联」）
    · {id, auto:1}     解除绑定（不再有"自动路径"可交回，人解除即最终态）
    绑定成功后把这个登记记着的浏览器稳定指纹 / 持久 ID 回写到目标设备 —— 设备页据此认出同一台机器。
    """
    try:
        b = json.loads(body.decode("utf-8"))
    except Exception:
        b = {}
    eid = int(b.get("id") or 0)
    did = int(b.get("device_id") or 0)
    if not eid:
        return {"error": "id required"}
    if b.get("auto"):
        # 解除绑定：pinned=1 保留（"人解除"也是明确决定，自动路径不许再改）
        xrun("UPDATE enrollments SET matched_device=NULL, matched_by=NULL, pinned=1, updated=? WHERE id=?",
             (now(), eid))
        return {"ok": True, "id": eid, "device_id": None, "pinned": 1}
    # 人工关联 / 人工解除（选"未关联"）都是明确决定 → pinned=1（历史上缺 pinned 时会被自动路径改回去）
    xrun("UPDATE enrollments SET matched_device=?, matched_by=?, pinned=1, updated=? WHERE id=?",
         (did or None, ("manual" if did else None), now(), eid))
    if did:
        # 注意：sqlite3.Row 没有 .get()。历史 bug：写成 r.get("name") → AttributeError → 500
        # → 页面上表现为「保存失败：internal error」。
        r = qone("SELECT name, model, hash_stable, pids FROM enrollments WHERE id=?", (eid,))
        nm = (r["name"] if r else "") or ""
        md = (r["model"] if r else "") or ""
        hs = (r["hash_stable"] if r else None) or None
        pids = (r["pids"] if r else None) or None
        if nm and md:            # 只有浏览器报了真实型号才写设备标签（与登记口径一致）
            xrun("UPDATE devices SET label=? WHERE id=? AND (label IS NULL OR label='')", (nm[:60], did))
        # 绑定是"人确认过"的关系 ⇒ 此刻才把浏览器侧指纹 / 持久 ID 记到设备上
        xrun("UPDATE devices SET browser_fp=COALESCE(?,browser_fp), browser_pids=COALESCE(?,browser_pids),"
             " browser_seen=? WHERE id=?", (hs, pids, now(), did))
    return {"ok": True, "id": eid, "device_id": did, "pinned": 1}


def api_enroll_delete(params):
    eid = int((params.get("id") or ["0"])[0])
    if eid:
        xrun("DELETE FROM enrollments WHERE id=?", (eid,))
    return {"ok": True, "id": eid}



# ==== JOIN PATCH v1 ====
JOIN_FP_MAX = 32768         # 单个登记请求体上限（2026-10-15：全量指纹约 6–12KB ⇒ 8K 提到 32K）
JOIN_FP2_MAX = 24576        # 深度指纹 JSON 上限
JOIN_HDR_MAX = 4096         # 请求头 JSON 上限
JOIN_PIDS_MAX = 1024        # 持久 ID JSON 上限
ACCEPT_CH = ("Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform-Version, Sec-CH-UA-Arch, "
             "Sec-CH-UA-Bitness, Sec-CH-UA-Model, Sec-CH-UA-WoW64, Sec-CH-UA-Form-Factors, "
             "Sec-CH-Device-Memory, Sec-CH-Prefers-Color-Scheme, Sec-CH-Prefers-Reduced-Motion, "
             "Sec-CH-Viewport-Width, Sec-CH-Viewport-Height")
JOIN_RL_PER_MIN = 6         # 每 IP 每分钟最多登记次数
_JOIN_RL = {}


def join_rate_ok(ip):
    """极简内存令牌桶：按来源 IP 限速，且自身容量有界（防被刷成内存泄漏）。"""
    nowt = now()
    k = ip or "-"
    arr = _JOIN_RL.get(k)
    if arr is None:
        if len(_JOIN_RL) > 500:
            for kk in list(_JOIN_RL.keys())[:200]:
                _JOIN_RL.pop(kk, None)
        arr = _JOIN_RL[k] = []
    arr[:] = [x for x in arr if nowt - x < 60]
    if len(arr) >= JOIN_RL_PER_MIN:
        return False
    arr.append(nowt)
    return True


_CHAIN_MEMO = {"ts": 0, "level": "ok", "cts": 0}


def join_chain_level():
    """只回三态与时间戳，绝不回节点名/IP/容器名。读不动时给 warn + stale，不冒充正常。
    30 秒记忆：这个页面会被家里多台设备反复打开，不该每次都去打 chainmon（它一轮采集要几十秒）。"""
    _n = now()
    if _CHAIN_MEMO["ts"] and _n - _CHAIN_MEMO["ts"] < 30:
        return _CHAIN_MEMO["level"], _CHAIN_MEMO["cts"], False
    try:
        import urllib.request as _u
        raw = _u.urlopen("http://127.0.0.1:8787/api/metrics", timeout=4).read().decode("utf-8", "ignore")
        d = json.loads(raw)
        st = [n.get("status") for n in (((d.get("chain") or {}).get("nodes")) or [])]
        cts = int(d.get("ts") or now())
        if not st:
            lvl = "warn"
        elif "error" in st:
            lvl = "err"
        elif "warn" in st:
            lvl = "warn"
        else:
            lvl = "ok"
        _CHAIN_MEMO.update(ts=_n, level=lvl, cts=cts)
        return lvl, cts, False
    except Exception:
        return "warn", int(now()), True


def api_join_status():
    """公开只读接口：键集严格等于白名单，多一个都不返回。"""
    nowt = int(now())
    r = qone("SELECT COALESCE(SUM(n),0) n, COALESCE(SUM(filtered),0) f FROM dns_hour WHERE hour>?", (nowt - 86400,))
    q = int((r and r["n"]) or 0)
    f = int((r and r["f"]) or 0)
    lvl, cts, stale = join_chain_level()
    return {
        "v": 1,
        "blocked24h": f,                       # 过去 24h AGH 阻断的 DNS 查询数（小时聚合，口径无断档）
        "queries24h": q,                       # 同期总查询数
        "blockedPct": round(100.0 * f / q, 1) if q else 0,
        "chain_level": lvl,                    # ok / warn / err
        "chain_ts": cts,
        "stale": bool(stale),
        "updated": nowt,
    }


def api_join_register(body, ip, headers=None):
    """2026-10-15（用户要求：留尽可能多的信息 + 持久 ID + 打开即采集 + 自动绑定 + 验证 DoT/DoH 保护）：
      · 落库扩展到深度指纹 fp2 / 请求头 hdr / 持久 ID pids / 浏览器稳定指纹 hash_stable / 网络指纹 hash_net；
      · 归因顺序：SNI 标记证明过的"本次请求"ja4 → 该出口聚合 ja4 → 浏览器稳定指纹反查 → 持久 ID 反查；
      · 每次访问追加一行 enroll_obs（时间序列），并把 DoT/DoH 保护判定一并存档；
      · 设备侧回写 browser_fp / browser_pids，看板即可自动绑定显示。
    返回值只有 {ok, matched, how, protected, proto, by, seen} —— 不回显 client_ip / ja4 / 设备 id / 名称。"""
    if not body or len(body) > JOIN_FP_MAX:
        return {"ok": False, "matched": False}
    if not join_rate_ok(ip):
        return {"ok": False, "matched": False}
    try:
        b = json.loads(body.decode("utf-8", "ignore"))
    except Exception:
        return {"ok": False, "matched": False}
    if not isinstance(b, dict):
        return {"ok": False, "matched": False}

    def ss(k, n):
        v = b.get(k)
        return v.strip()[:n] if isinstance(v, str) else ""

    def js(o, n, dflt="{}"):
        try:
            return jdump(o)[:n]
        except Exception:
            return dflt

    fp = b.get("fp") if isinstance(b.get("fp"), dict) else {}
    fp2 = b.get("fp2") if isinstance(b.get("fp2"), dict) else {}
    pids = b.get("pids") if isinstance(b.get("pids"), dict) else {}
    fps, fp2s = js(fp, 4000), js(fp2, JOIN_FP2_MAX)
    pids_s = js(pids, JOIN_PIDS_MAX) if pids else ""
    hdr = {}
    try:
        for _k, _v in (headers or {}).items():
            if _k.lower() in ("authorization", "cookie", "proxy-authorization", "set-cookie"):
                hdr[_k] = "<redacted:%d chars>" % len(_v or "")
            else:
                hdr[_k] = (_v or "")[:400]
    except Exception:
        hdr = {}
    hdr_s = js(hdr, JOIN_HDR_MAX)

    model, plat, pver, arch = ss("model", 60), ss("platform", 40), ss("platform_ver", 20), ss("arch", 20)
    ua_full = ss("ua_full", 400) or ((headers or {}).get("User-Agent") or "")[:400]
    # MODEL-ONLY-LABEL：只有浏览器明确报了硬件型号（Sec-CH-UA-Model）才用它命名设备。
    name = model or (plat + (" " + pver if pver else "")).strip() or "未识别设备"
    auto_label = bool(model)
    fp_id = ss("k", 64) or ss("fp_id", 64) or ("ip:" + (ip or "-"))

    # ① 归因：SNI 标记证明过的"本次请求"优先，否则退回该出口的聚合指纹
    sni_tok = ss("sni", 24)
    m = join_sni_probe(sni_tok) if sni_tok else None
    ip_eff = (m or {}).get("ip") or ip
    ja = enroll_recent_ja4(ip_eff, 60)
    if m and m.get("ja4"):
        ja4, tcp_sig = m["ja4"], m.get("tcp_sig")
    else:
        ja4, tcp_sig = (ja[0]["ja4"], ja[0]["tcp_sig"]) if ja else (None, None)
    hash_stable = ss("hs", 64)
    # 稳定指纹"首次为准"（2026-10-15）：无头/虚拟化环境下 canvas/audio 会抖动，
    # 同 fp_id 的 hash 不再被覆盖；漂移本身仍逐次记进 enroll_obs，可见但不破坏跨会话归并。
    if hash_stable:
        _ph = qone("SELECT hash_stable FROM enrollments WHERE fp_id=? AND hash_stable IS NOT NULL LIMIT 1",
                   (fp_id,))
        if _ph and _ph["hash_stable"]:
            hash_stable = _ph["hash_stable"]
    hash_net = ss("hn", 64) or (hashlib.sha256(("%s|%s" % (ja4 or "", tcp_sig or "")).encode("utf-8")).hexdigest()[:32]
                                if (ja4 or tcp_sig) else None)
    # 归因顺序（2026-10-15 调整）：持久 ID 优先 —— Chrome 会对 TLS 扩展做随机化，同一台机的
    # JA4 每次连接都可能不同（实测同机两次访问落到两台 devices 行），所以"最稳的锚点"排前面。
    did, how = None, None
    if pids:                             # ① 四通道持久 ID（localStorage/IndexedDB/Cookie/Cache）
        for _pk in ("ls", "idb", "ck", "ca"):
            _pv = pids.get(_pk)
            if not _pv:
                continue
            r = qone("SELECT id FROM devices WHERE browser_pids LIKE ? ORDER BY last_seen DESC LIMIT 1",
                     ('%"' + str(_pv)[:80] + '"%',))
            if r:
                did, how = r["id"], "pid-" + _pk
                break
    if not did:                          # ② 本次抓包实测指纹（JA4/JA3 → 设备；JA4 抖动时自然会 miss）
        did, how = enroll_match(ja4, ip_eff)
    if not did and hash_stable:          # ③ 稳定浏览器指纹（跨会话 / 跨出口 IP）
        r = qone("SELECT id FROM devices WHERE browser_fp=? ORDER BY last_seen DESC LIMIT 1", (hash_stable,))
        if r:
            did, how = r["id"], "bfp"
    # 完整性闸门：只有该 IP 真的属于这台设备，才允许写它的标签/浏览器指纹
    safe = None
    if did:
        row = qone("SELECT id FROM devices WHERE id=? AND src_ips LIKE ?", (did, '%"' + (ip_eff or "-") + '"%'))
        safe = row["id"] if row else None

    # ④ DoT/DoH 保护判定，随登记一起存档（用户要求"同时验证设备是否受保护"）
    try:
        _p_ok, _p_by, _p_proto, _p_age, _p_probed = join_protect(ip_eff, sni_tok)
    except Exception:
        _p_ok, _p_by, _p_proto, _p_age, _p_probed = False, None, None, None, False

    nowt = now()
    jl = jdump([x["ja4"] for x in ja])
    ex = qone("SELECT id, COALESCE(pinned,0) p, COALESCE(seen,0) s, COALESCE(obs_count,0) o"
              " FROM enrollments WHERE fp_id=?", (fp_id,))
    _pinned = bool(ex and ex["p"])
    _seen = (int(ex["s"]) + 1) if ex else 1
    _obs = (int(ex["o"]) + 1) if ex else 1
    if ex:
        if _pinned:
            # 人工钉住过：元数据照更新，绑定与标签一个字都不改
            xrun("UPDATE enrollments SET name=?,fp=?,fp2=?,hdr=?,pids=?,ua_full=?,model=?,platform=?,"
                 "platform_ver=?,arch=?,ja4=?,ja4_list=?,tcp_sig=?,hash_stable=?,hash_net=?,src_ip=?,"
                 "seen=?,obs_count=?,updated=? WHERE id=?",
                 (name, fps, fp2s, hdr_s, pids_s or None, ua_full, model, plat, pver, arch,
                  ja4, jl, tcp_sig, hash_stable or None, hash_net, ip_eff, _seen, _obs, nowt, ex["id"]))
        else:
            # 2026-10-15：取消自动绑定 —— 元数据照更新，但 matched_device/matched_by 一个字都不写
            xrun("UPDATE enrollments SET name=?,fp=?,fp2=?,hdr=?,pids=?,ua_full=?,model=?,platform=?,"
                 "platform_ver=?,arch=?,ja4=?,ja4_list=?,tcp_sig=?,hash_stable=?,hash_net=?,src_ip=?,"
                 "seen=?,obs_count=?,updated=? WHERE id=?",
                 (name, fps, fp2s, hdr_s, pids_s or None, ua_full, model, plat, pver, arch,
                  ja4, jl, tcp_sig, hash_stable or None, hash_net, ip_eff, _seen, _obs, nowt, ex["id"]))
        eid = ex["id"]
    else:
        xrun("INSERT INTO enrollments(fp_id,name,note,fp,ua,model,platform,platform_ver,arch,ja4,ja4_list,"
             "tcp_sig,src_ip,matched_device,created,updated,fp2,hdr,pids,ua_full,hash_stable,hash_net,"
             "seen,obs_count,matched_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
             (fp_id, name, "", fps, "", model, plat, pver, arch, ja4, jl, tcp_sig, ip_eff, None, nowt, nowt,
              fp2s, hdr_s, pids_s or None, ua_full, hash_stable or None, hash_net, 1, 1, None))
        xrun("DELETE FROM enrollments WHERE id NOT IN (SELECT id FROM enrollments ORDER BY updated DESC LIMIT 500)")
        r2 = qone("SELECT id FROM enrollments WHERE fp_id=?", (fp_id,))
        eid = r2["id"] if r2 else None
    # 2026-10-15（用户要求）：取消自动绑定 —— 设备侧（标签、浏览器指纹、持久 ID）一律不再由登记自动回写。
    # 「safe」（本次访问的 IP 是否属于候选簇）仍然作为建议写在下面的 enroll_obs 里，供人在看板里判断。
    # 观测时间序列（每次访问一行）
    try:
        xrun("INSERT INTO enroll_obs(ts,fp_id,ip,ja4,tcp_sig,ua,hdr,fp_json,hash_stable,hash_net,pids,"
             "matched_device,matched_by,protected,protect_by,protect_proto,protect_age,probed)"
             " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
             (nowt, fp_id, ip_eff, ja4, tcp_sig, ua_full, hdr_s, fp2s, hash_stable or None, hash_net,
              pids_s or None, safe, how, 1 if _p_ok else 0, _p_by, _p_proto, _p_age, 1 if _p_probed else 0))
    except Exception:
        pass
    # 不自动绑定：matched 恒为 False，只回「建议」；绑定由人在登记列表里选择
    return {"ok": True, "matched": False, "suggest": safe, "suggest_by": (how if safe else None),
            "protected": bool(_p_ok), "proto": _p_proto, "by": _p_by, "seen": _seen}



# ==== JOIN-CHECK-PATCH v1 ====
_JOIN_CHECK_RL = {}
DNS_KINDS = ("dot", "doh443", "doh444")


def join_check_rate_ok(ip, limit=40):
    nowt = now()
    k = ip or "-"
    arr = _JOIN_CHECK_RL.get(k)
    if arr is None:
        if len(_JOIN_CHECK_RL) > 500:
            for kk in list(_JOIN_CHECK_RL.keys())[:200]:
                _JOIN_CHECK_RL.pop(kk, None)
        arr = _JOIN_CHECK_RL[k] = []
    arr[:] = [x for x in arr if nowt - x < 60]
    if len(arr) >= limit:
        return False
    arr.append(nowt)
    return True


# ==== JOIN-CHECK-PATCH v2 ====
DNS_KINDS_SQL = "('dot','doh443','doh444')"


# ==== JOIN-CHECK-PATCH v3 ====


def join_sni_probe(token, window=120):
    """SNI 标记探针：页面请求 https://<token>.dns.example.com/… 时，ClientHello 里的 SNI
       **在证书校验之前**就发出，所以抓包侧一定记录到这一行；即使随后握手因证书不匹配而失败也不影响。
       作用：把"该出口最近的指纹集合"(聚合，不可归因) 换成"本次请求自己的 ja4"(可归因)。
       这是本架构下唯一能做到真正设备级的通道 —— DNS 探针在 fake-ip Clash 下不成立（已实测）。"""
    if not token or not re.match(r"^[a-z0-9]{8,24}$", token or ""):
        return None
    r = qone("SELECT src_ip, ja4, tcp_sig, ts FROM conns WHERE sni=? AND ts>? ORDER BY ts DESC LIMIT 1",
             (token + ".dns.example.com", int(now()) - window))
    if not r:
        return None
    return {"ip": r["src_ip"], "ja4": r["ja4"], "tcp_sig": r["tcp_sig"], "ts": r["ts"]}


def join_protect(ip, sni_tok=None, window=600):
    """是否在用本机的加密 DNS。证据级别严格按实际强度命名，不把聚合当设备级：
       sni-ja4 —— 用 SNI 标记证明"本次请求"自己的 ja4，且该 ja4 在同 IP 的 DoT/DoH 连接上出现
                  = **设备级（已证明）**
       dns-now —— 被标记的出口 IP 最近 15 秒就有 DoT/DoH 连接 = **时间相关**
       dns     —— 被标记的出口 IP 在 window 秒内有 DoT/DoH 连接 = **网络级**
       返回 (protected, by, proto, age_s, probed)"""
    if not ip:
        return False, None, None, None, False
    nowt = now()
    m = join_sni_probe(sni_tok) if sni_tok else None
    probed = bool(m)
    if m and m.get("ip"):
        ip = m["ip"]                      # 用被标记证明过的出口 IP，不再用 X-Real-IP 猜
    if m and m.get("ja4"):
        r = qone("SELECT 1 FROM conns WHERE src_ip=? AND ts>? AND ja4=? AND kind IN " + DNS_KINDS_SQL +
                 " LIMIT 1", (ip, nowt - 1800, m["ja4"]))
        if r:
            return True, "sni-ja4", None, None, True
    r = qone("SELECT kind, ts FROM conns WHERE src_ip=? AND ts>? AND kind IN " + DNS_KINDS_SQL +
             " ORDER BY ts DESC LIMIT 1", (ip, nowt - window))
    if not r:
        return False, None, None, None, probed
    proto = "dot" if r["kind"] == "dot" else "doh"
    age = max(0, int(nowt - (r["ts"] or nowt)))
    fresh = qone("SELECT 1 FROM conns WHERE src_ip=? AND ts>? AND kind IN " + DNS_KINDS_SQL + " LIMIT 1",
                 (ip, nowt - 15))
    return True, ("dns-now" if fresh else "dns"), proto, age, probed


def api_join_check(params, ip):
    """公开只读接口，只回 {protected, by, proto, age_s, probed}。
       不带 IP、不带 JA4、不带设备名 —— by/proto/probed 都只是关于"请求者自己这条连接"的粗粒度枚举。"""
    if not join_check_rate_ok(ip):
        return {"protected": False, "by": None, "proto": None, "age_s": None, "probed": False}
    tok = (params.get("sni") or [""])[0]
    ok, by, proto, age, probed = join_protect(ip, tok)
    return {"protected": bool(ok), "by": by, "proto": proto, "age_s": age, "probed": bool(probed)}


def enroll_rematch(ja4, ip):
    """延迟补匹配用的**严格**判定：ja4 精确命中 AND 该 IP 确实在这台设备的 src_ips 里 AND 唯一。
       不唯一就返回 None —— 宁可留给人工，也不乱绑（错绑比不绑更难发现）。"""
    if not ja4 or not ip:
        return None
    rows = qall("SELECT id FROM devices WHERE ja4=? AND src_ips LIKE ?", (ja4, '%"' + ip + '"%'))
    if len(rows) == 1:
        return rows[0]["id"]
    return None


class Handler(BaseHTTPRequestHandler):
    server_version = "devfp/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, (dict, list)):
            body = jdump(body).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        # 2026-10-05：原来只有 Cache-Control: no-store —— 浏览器每轮都要整份重传+重解析
        # （/api/devices 单次 2.3MB，JSON.parse 在手机上很贵）。改成「可缓存但必须校验」+ ETag，
        # 内容没变时直接 304（无 body）。注意：必须是 no-cache 而不是 no-store，否则 ETag 永远用不上。
        etag = None
        if code == 200 and body:
            etag = '"%s"' % hashlib.md5(body).hexdigest()[:20]
            if (self.headers.get("If-None-Match") or "") == etag:
                self.send_response(304)
                self.send_header("ETag", etag)
                self.send_header("Cache-Control", "private, no-cache")
                self.end_headers()
                return
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "private, no-cache")
        if etag:
            self.send_header("ETag", etag)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def do_GET(self):
        u = urlparse(self.path)
        p = u.path.rstrip("/") or "/"
        prm = parse_qs(u.query)
        try:
            if p in ("/", "/index.html"):
                path = CFG["ui"]
                if os.path.exists(path):
                    with open(path, "rb") as f:
                        return self._send(200, f.read(), "text/html; charset=utf-8")
                return self._send(404, "ui missing", "text/plain")
            if p == "/api/ndpi":
                rows = [dict(r) for r in qall(
                    "SELECT run_ts,ip,sport,dport,proto,category,risks,bytes,device_id FROM ndpi_flows"
                    " ORDER BY id DESC LIMIT 200")]
                return self._send(200, {"flows": rows, "count": len(rows)})
            if p == "/api/dict":
                return self._send(200, {"dict": [dict(r) for r in qall(
                "SELECT kind,key,label,conf,source,hits,updated FROM fp_dict"
                " ORDER BY conf DESC, hits DESC LIMIT 300")]})
            if p == "/api/clusters":
                return self._send(200, api_clusters())
            if p == "/api/summary":
                return self._send(200, api_summary())
            if p == "/api/devices":
                return self._send(200, api_devices(prm))
            if p == "/api/device":
                return self._send(200, api_device(prm))
            if p == "/api/health":
                return self._send(200, {"ok": True, "ts": now(), "sniff": SNIFF_STATS,
                                        "counters": COUNTERS, "dev_cache": len(_DEV_CACHE),
                                        "conns": len(CONNS)})
            if p in ("/join", "/join/"):
                jp = os.path.join(os.path.dirname(CFG["ui"] or "/opt/devfp/index.html"), "join.html")
                if os.path.exists(jp):
                    with open(jp, "rb") as jf:
                        return self._send(200, jf.read(), "text/html; charset=utf-8",
                                          {"Accept-CH": ACCEPT_CH})
                return self._send(404, "not found", "text/plain")
            if p == "/api/join/check":
                return self._send(200, api_join_check(prm, enroll_client_ip(self)))
            if p == "/api/join/status":
                return self._send(200, api_join_status())
            if p == "/api/enroll":
                return self._send(200, api_enroll_list())
            if p == "/api/export":
                return self.export(prm)
            if p == "/api/events":
                rows = [dict(r) for r in qall(
                    "SELECT e.*, d.label, d.fp_key FROM events e LEFT JOIN devices d ON d.id=e.device_id"
                    " ORDER BY e.id DESC LIMIT 500")]
                return self._send(200, {"events": rows})
        except Exception as e:
            log("API 异常 %s: %s" % (p, traceback.format_exc().splitlines()[-1]))
            return self._send(500, {"error": str(e)})
        return self._send(404, {"error": "no route"})

    def do_POST(self):
        u = urlparse(self.path)
        p = u.path.rstrip("/") or "/"
        prm = parse_qs(u.query)
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else b""
            if p == "/api/enroll":
                return self._send(200, api_enroll_create(body, enroll_client_ip(self)))
            if p == "/api/enroll/link":
                return self._send(200, api_enroll_link(body))
            if p == "/api/enroll/delete":
                return self._send(200, api_enroll_delete(prm))
            if p == "/api/join/register":
                return self._send(200, api_join_register(body, enroll_client_ip(self), self.headers),
                                 "application/json; charset=utf-8", {"Accept-CH": ACCEPT_CH})
            if p == "/api/reinfer":
                _fv = prm.get("full")
                _f = _fv[0] if isinstance(_fv, (list, tuple)) else _fv
                full = str(_f or "").lower() in ("1", "true", "yes")
                return self._send(200, {"ok": True, "full": full,
                                        "devices": reinfer_all(force=full)})
            if p == "/api/device/label":
                return self._send(200, api_label(prm, body))
        except Exception as e:
            sys.stderr.write("[err] %s\\n" % str(e))
            return self._send(500, {"error": "internal error"})
        return self._send(404, {"error": "no route"})

    def export(self, prm):
        fmt = prm.get("fmt", ["json"])[0]
        what = prm.get("what", ["devices"])[0]
        if what == "conns":
            rows = [dict(r) for r in qall("SELECT * FROM conns ORDER BY ts DESC LIMIT 50000")]
        elif what == "dns":
            rows = [dict(r) for r in qall("SELECT * FROM dns_hour ORDER BY hour DESC LIMIT 50000")]
        elif what == "router":
            rows = [dict(r) for r in qall("SELECT * FROM router_devices ORDER BY last_seen DESC")]
        else:
            rows = [dict(r) for r in qall("SELECT * FROM devices ORDER BY last_seen DESC")]
        if fmt == "csv":
            if not rows:
                return self._send(200, "", "text/csv; charset=utf-8")
            cols = list(rows[0].keys())
            out = [",".join(cols)]
            for r in rows:
                vals = []
                for c in cols:
                    v = r.get(c)
                    s = "" if v is None else str(v)
                    vals.append('"' + s.replace('"', '""').replace("\n", " ") + '"')
                out.append(",".join(vals))
            return self._send(200, "\n".join(out), "text/csv; charset=utf-8",
                              {"Content-Disposition": "attachment; filename=devfp-%s.csv" % what})
        return self._send(200, {"items": rows, "count": len(rows)})


class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ---------------------------------------------------------------------------
# selftest：用 JA4 官方 pcap 校验解析器
# ---------------------------------------------------------------------------

def pcap_iter(path):
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            return
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            endian = "<"
        elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
            endian = ">"
        else:
            raise ValueError("不是经典 pcap（可能是 pcapng）")
        linktype = struct.unpack(endian + "I", hdr[20:24])[0]
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                return
            _, _, incl, _ = struct.unpack(endian + "IIII", ph)
            data = f.read(incl)
            if len(data) < incl:
                return
            yield linktype, data


def build_client_hello(ciphers, exts, sni="example.com", alpn=("h2",),
                       sig_algs=(), groups=(), legacy=0x0303, sup_vers=(0x0304,)):
    """按给定密码套件/扩展顺序合成一个合法 ClientHello（TLS 记录 + 握手），用于自检。"""
    def ext_sni(v):
        b = v.encode()
        return struct.pack("!H", len(b) + 3) + b"\x00" + struct.pack("!H", len(b)) + b

    def ext_alpn(vs):
        inner = b"".join(bytes([len(v)]) + v.encode() for v in vs)
        return struct.pack("!H", len(inner)) + inner

    def ext_sigalgs(vs):
        return struct.pack("!H", len(vs) * 2) + b"".join(struct.pack("!H", v) for v in vs)

    def ext_groups(vs):
        return struct.pack("!H", len(vs) * 2) + b"".join(struct.pack("!H", v) for v in vs)

    def ext_supvers(vs):
        return bytes([len(vs) * 2]) + b"".join(struct.pack("!H", v) for v in vs)

    bodies = {0x0000: ext_sni(sni), 0x0010: ext_alpn(alpn), 0x000D: ext_sigalgs(sig_algs),
              0x000A: ext_groups(groups), 0x000B: b"\x01\x00",
              0x002B: ext_supvers(sup_vers), 0x0017: b"", 0x0023: b"",
              0x0005: b"\x01\x00\x00\x00\x00", 0x0012: b"", 0x002D: b"\x01\x01",
              0x0033: b"\x00\x02\x00\x1d", 0x4469: b"", 0xFF01: b"\x00", 0x0015: b"\x00" * 4,
              0x001B: b"", 0x0021: b"\x00" * 4, 0x0001: b"\x04"}
    extbytes = b""
    for et in exts:
        body = bodies.get(et, b"\x00")
        extbytes += struct.pack("!HH", et, len(body)) + body
    body = struct.pack("!H", legacy) + b"\x11" * 32
    body += b"\x00"  # session id len
    body += struct.pack("!H", len(ciphers) * 2) + b"".join(struct.pack("!H", c) for c in ciphers)
    body += b"\x01\x00"  # compression: null
    body += struct.pack("!H", len(extbytes)) + extbytes
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def selftest():
    print("=== 1) JA4 规范向量（来自 FoxIO JA4.md 示例，期望 t13d1516h2_8daaf6152771_e5627efa2ab1）===")
    ciphers = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,
               0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]
    exts = [0x001B, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002D, 0x000D, 0x0005,
            0x0023, 0x0012, 0x002B, 0xFF01, 0x000B, 0x000A, 0x0015]
    sigs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    ch = build_client_hello(ciphers, exts, sig_algs=sigs, groups=[0x001D])
    info, _ = parse_client_hello(ch)
    want = "t13d1516h2_8daaf6152771_e5627efa2ab1"
    print("  解析成功: %s" % bool(info))
    if info:
        print("  计算 JA4: %s" % info["ja4"])
        print("  期望 JA4: %s" % want)
        print("  结果: %s" % ("OK ✔" if info["ja4"] == want else "MISMATCH ✘"))
        print("  JA4_a=%s b=%s c=%s" % (info["ja4_a"], info["ja4_b"], info["ja4_c"]))
        print("  JA3=%s" % info["ja3"])
        print("  JA3 原串=%s" % info["ja3_str"])
    bad = 0
    for alpn, exp in ((["h2"], "h2"), (["http/1.1"], "h1"), ([], "00"), (["x"], "xx"),
                      (["h2", "h3"], "h2")):
        got = first_last_alpn(alpn)
        if got != exp:
            print("  ALPN 规则失败 %s → %s（期望 %s）" % (alpn, got, exp))
            bad += 1
    print("  ALPN 规则: %s" % ("OK ✔" if not bad else "FAIL"))
    print("\n=== 2) 真实 pcap 冒烟测试（确认能解析真流量）===")
    pcap_dir = sys.argv[2] if len(sys.argv) > 2 else "/tmp/ja4src/ja4-main/pcap"
    exp_dir = "/tmp/ja4src/ja4-main/wireshark/test/testdata"
    if not os.path.isdir(pcap_dir):
        print("  pcap 目录不存在，跳过: %s" % pcap_dir)
        return
    for fn in sorted(os.listdir(pcap_dir)):
        if not fn.endswith(".pcap"):
            continue
        got = []
        ja4t = []
        try:
            for lt, data in pcap_iter(os.path.join(pcap_dir, fn)):
                p = parse_packet(data, lt)
                if not p or p["proto"] != "tcp":
                    continue
                if p["flags"] & 0x02 and not (p["flags"] & 0x10):
                    ja4t.append(tcp_fingerprint(p["ttl"], p["win"], p["opts"], p["ip_id"],
                                                p["df"], 0)["ja4t_like"])
                if p["plen"] >= 6:
                    info, _ = parse_client_hello(p["payload"])
                    if info:
                        got.append(info["ja4"])
        except Exception as e:
            print("  %-30s SKIP (%s)" % (fn, e))
            continue
        want_t = set()
        exp = os.path.join(exp_dir, fn + ".json")
        if os.path.exists(exp):
            with open(exp) as f:
                blob = f.read()
            want_t = set(re.findall(r'"ja4\.ja4t"\s*:\s*\[\s*"([^"]+)"', blob))
        note = ""
        if want_t:
            hit = len(want_t & set(ja4t))
            note = "  JA4T: 命中 %d/%d 期望" % (hit, len(want_t))
            if hit < len(want_t):
                note += "  例: 期望 %s / 得到 %s" % (sorted(want_t)[:1], sorted(set(ja4t))[:1])
        print("  %-30s ClientHello=%d%s" % (fn, len(got), note))


def main():
    load_cfg()
    init_db()
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        selftest()
        return
    threads = [threading.Thread(target=guarded_loop, args=(commit_loop, "commit"), name="commit"),
               threading.Thread(target=guarded_loop, args=(reaper_loop, "reaper"), name="reaper"),
               threading.Thread(target=guarded_loop, args=(maintain_loop, "maint"), name="maint")]
    if CFG.get("sniff"):
        threads.append(threading.Thread(target=guarded_loop, args=(sniff_loop, "sniff"), name="sniff"))
    else:
        log("抓包已禁用（config.sniff=false）")
    threads.append(threading.Thread(target=guarded_loop, args=(agh_loop, "agh"), name="agh"))
    threads.append(threading.Thread(target=guarded_loop, args=(doh_loop, "doh"), name="doh"))
    threads.append(threading.Thread(target=guarded_loop, args=(dotf_loop, "dotf"), name="dotf"))
    threads.append(threading.Thread(target=guarded_loop, args=(ndpi_loop, "ndpi"), name="ndpi"))
    threads.append(threading.Thread(target=guarded_loop, args=(dns_flush_loop, "dnsflush"), name="dnsflush"))
    if CFG.get("enrich"):
        threads.append(threading.Thread(target=guarded_loop, args=(enrich_loop, "enrich"), name="enrich"))
    threads.append(threading.Thread(target=guarded_loop, args=(reinfer_loop, "reinfer"), name="reinfer"))
    for t in threads:
        t.daemon = True
        t.start()
    srv = ThreadedHTTPServer((CFG["http_host"], int(CFG["http_port"])), Handler)
    try:
        dict_seed()
    except Exception as e:
        log("指纹字典种子失败: %s" % e)

    log("devfp 已启动：http://%s:%d  设备缓存=%d  数据库=%s" %
        (CFG["http_host"], CFG["http_port"], len(_DEV_CACHE), CFG["db"]))
    srv.serve_forever()


if __name__ == "__main__":
    if "--ndpi-once" in sys.argv:
        load_cfg()
        init_db()
        n, err = ndpi_run_once()
        with DB_LOCK:
            try:
                db().commit()
            except Exception as e:
                print("提交失败: %s" % e)
        print("nDPI 本轮：入库 %d 条流%s" % (n, ("，错误：" + err) if err else ""))
        rows = qall("SELECT ip, sport, dport, proto, category, risks, device_id FROM ndpi_flows"
                    " ORDER BY id DESC LIMIT 12")
        for r in rows:
            print("   %-16s:%-6s → :%-4s %-14s %-10s dev=%s %s" % (
                r["ip"], r["sport"], r["dport"], r["proto"] or "-", r["category"] or "-",
                r["device_id"], (r["risks"] or "")[:40]))
        sys.exit(0)
    main()
