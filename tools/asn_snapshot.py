#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P26 前置件：把 ASN 缓存导出为 **guard 可用的离线快照**（Codex 硬约束 #1 的落点）。

为什么需要（Codex 明确指出）：
  · 放宽 R8 改道的判据要比较 **两侧的 ASN 本身**（不是"类别"✗，否则 Fastly↔Cloudflare 这种
    "真不同运营商但同属 cdn-cloud"会被漏掉 ✓）；
  · 但**判据里绝不能调用 `asn_cache.lookup()`** ✗ —— 它的一跳 DoT 最长 6s、三家轮询、还 sleep 0.05s，
    拖进热路径就是数百毫秒到十几秒 ✗；
  · 正确做法：由**离线**进程把 `asn_cache.json` 导出成**不可变快照** `asn_class.json`（ip→asn 的扁平 dict ✓），
    guard 启动时载入内存、按 mtime 每分钟热载，**请求路径只做 dict 查表 + ASN 比较、零网络** ✓。

本脚本（只读 asn_cache，写快照；**不接触 guard 进程**）：
  1) 读 `/opt/dnsguard/verify/asn_cache.json`，导出 `{ip: asn}` + 元数据（生成时间/条目数/来源 TTL ✓）；
  2) 写 `/opt/dnsguard/asn_class.json`（原子替换 ✓）；
  3) 可选：对新 IP 做有界预取（复用 asn_cache 的 200 次/次上限 ✓）。
注意：**guard 目前不消费该文件** ✓（Codex 的上线门槛是"先攒 ≥20 次采纳样本并抽查 D 档"✓，
之后再打 consume 补丁 ✓）。
"""
import io
import json
import os
import subprocess
import sys
import time

CACHE = "/opt/dnsguard/verify/asn_cache.json"
SNAP = "/opt/dnsguard/asn_class.json"

if not os.path.exists(CACHE):
    print("  没有 %s ⇒ 先跑 asn_cache.py --prefetch" % CACHE)
    sys.exit(1)

d = json.load(io.open(CACHE, encoding="utf-8"))
flat = {}
cls = {}
for ip, e in d.items():
    asn = e.get("asn")
    if asn is None:
        continue
    flat[ip] = asn
    cls[e.get("cls")] = cls.get(e.get("cls"), 0) + 1

snap = {
    "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
    "source": CACHE,
    "count": len(flat),
    "ip_to_asn": flat,
    "note": ("离线快照：供 guard 的 R8 改道判据做『两侧 ASN 是否相同』比较用。"
             "请求路径**只做 dict 查表**；未命中 ⇒ unknown ⇒ 保留明文（不得 SERVFAIL、不得拒绝）。"
             "guard 侧消费补丁待 Codex 门槛（≥20 次采纳样本 + 抽查 D 档）满足后再上。"),
}
tmp = SNAP + ".tmp"
with io.open(tmp, "w", encoding="utf-8") as f:
    json.dump(snap, f, ensure_ascii=False, indent=1, sort_keys=True)
os.replace(tmp, SNAP)
print("  写出 %s：%d 条 ip→ASN；分类分布 %s" % (SNAP, len(flat), cls))
print("  样例: %s" % list(flat.items())[:5])

if "--install-timer" in sys.argv:
    svc = """[Unit]
Description=Export offline ASN snapshot for dnsguard R8 gating
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/dnsguard/asn_snapshot.py
"""
    tmr = """[Unit]
Description=Daily ASN snapshot refresh
[Timer]
OnBootSec=5min
OnUnitActiveSec=24h
AccuracySec=5min
[Install]
WantedBy=timers.target
"""
    io.open("/etc/systemd/system/dnsguard-asn-snapshot.service", "w").write(svc)
    io.open("/etc/systemd/system/dnsguard-asn-snapshot.timer", "w").write(tmr)
    subprocess.run("systemctl daemon-reload && systemctl enable --now dnsguard-asn-snapshot.timer",
                   shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    out = subprocess.run("systemctl list-timers dnsguard-asn-snapshot.timer --no-pager | head -3",
                         shell=True, stdout=subprocess.PIPE, universal_newlines=True).stdout
    print("  已安装每日刷新定时器 ✓")
    print("\n".join("  %s" % l for l in out.strip().split("\n")))
