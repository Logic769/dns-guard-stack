#!/usr/bin/env python3
# verify_online.py —— 20261015-audit-fixes-01 上线后的端到端验收（服务器本地跑）
#   A) F5 握手自证：错身份 / 旧协议 必须被拒（status=0x05），对身份必须放行
#   B) 端到端 UDP 解析：国内名 + 国外名都要正常出应答
import json, os, socket, struct, sys, time

REL_DIR = os.environ.get("REL_DIR", "/opt/dnsguard/releases/20261015-audit-fixes-01")
SOCK = os.environ.get("DNS_VERIFIER_SOCKET", "/run/dnsguard/verifier.sock")
sys.path.insert(0, REL_DIR)
import guard

SHA, REL, PROTO = guard._GUARD_SHA256, guard._RELEASE_ID, guard.VERIFIER_PROTO
BYTES = guard._VSTATUS_BYTE
WM = BYTES[guard.CORROB_VERSION_MISMATCH]
print("参考身份: release=%s sha=%s proto=%s" % (REL, SHA, PROTO))
print("状态字节表: %s" % {k: v.hex() for k, v in BYTES.items()})


def qwire(name, qtype=1, rid=0x4321):
    w = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", rid, 0x0100, 1, 0, 0, 0) + w + struct.pack("!HH", qtype, 1)


def handshake(meta, name, qtype=1, timeout=6.0):
    msg = qwire(name, qtype)
    payload = json.dumps(meta).encode()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(SOCK)
    s.sendall(struct.pack("!HH", len(payload), len(msg)) + payload + msg)
    hdr = b""
    while len(hdr) < 2:
        x = s.recv(2 - len(hdr))
        if not x:
            raise IOError("short frame")
        hdr += x
    n = struct.unpack("!H", hdr)[0]
    body = b""
    while len(body) < n:
        x = s.recv(n - len(body))
        if not x:
            raise IOError("short frame")
        body += x
    s.close()
    return body[0:1], body[1:]


def udp_query(name, qtype=1, timeout=5.0):
    """对 guard 的 UDP 入口发一次真实查询；返回 (addr, port, rcode, ancount, 字节数)"""
    last = None
    for addr in ("127.0.0.1", "172.18.0.2", "172.17.0.1"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(qwire(name, qtype), (addr, 53))
            d, _ = s.recvfrom(4096)
            s.close()
            return addr, 53, d[3] & 0x0F, struct.unpack("!H", d[6:8])[0], len(d)
        except Exception as e:
            last = "%s:%s → %s" % (addr, 53, e)
    return None, 53, None, None, last


NAME = "www.baidu.com"
print("\n=== A) F5 握手自证 ===")
bad = {"name": NAME, "qtype": 1, "timeout": 3.0, "prefer_addr": False, "op": "dot", "rid": 9001,
       "rel": REL, "sha": "deadbeef" + "0" * 56, "proto": PROTO}
try:
    st, body = handshake(bad, NAME)
    print("① 错身份(sha 造假) → status=0x%s wire=%d字节  期望 0x%s  ⇒ %s"
          % (st.hex(), len(body), WM.hex(), "PASS" if st == WM else "FAIL"))
except Exception as e:
    print("① 错身份 → 异常 %s ⇒ FAIL" % e)

bad2 = dict(bad); bad2["sha"] = SHA; bad2["proto"] = 1; bad2["rid"] = 9002
try:
    st2, body2 = handshake(bad2, NAME)
    print("② 旧协议 proto=1 → status=0x%s wire=%d字节  期望 0x%s ⇒ %s"
          % (st2.hex(), len(body2), WM.hex(), "PASS" if st2 == WM else "FAIL"))
except Exception as e:
    print("② 旧协议 → 异常 %s ⇒ FAIL" % e)

good = {"name": NAME, "qtype": 1, "timeout": 4.0, "prefer_addr": False, "op": "dot", "rid": 9003,
        "rel": REL, "sha": SHA, "proto": PROTO}
try:
    st3, body3 = handshake(good, NAME)
    print("③ 对身份 → status=0x%s wire=%d字节  期望非 0x%s ⇒ %s"
          % (st3.hex(), len(body3), WM.hex(), "PASS" if st3 != WM else "FAIL"))
except Exception as e:
    print("③ 对身份 → 异常 %s ⇒ FAIL" % e)

print("\n=== B) 端到端 UDP 解析 ===")
for n in ("www.baidu.com", "www.qq.com", "example.com"):
    a, p, rc, an, extra = udp_query(n)
    if rc is None:
        print("%-16s ⇒ 无应答：%s" % (n, extra))
    else:
        print("%-16s ⇒ 来自 %s:%s rcode=%s ancount=%s 报文=%s字节  %s"
              % (n, a, p, rc, an, extra, "PASS" if rc == 0 and an >= 1 else "CHECK"))
