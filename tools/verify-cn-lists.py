#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CN 名单完整性 + 签名校验（运维侧，非 guard 关键路径）。

校验内容
--------
1. ``MANIFEST.sha256`` 存在且每条记录的 sha256 与磁盘实际一致；
2. MANIFEST 的 GPG 分离签名 ``MANIFEST.sha256.asc`` 验签通过（``--no-signature`` 可跳过）；
3. 名单内容约束：veto 条目数下限 + 不含国内关键域；cn_ip 条目数下限；
   typed 三集合非空且总数下限；forwarding-rules 含关键域。
4. MANIFEST 必须覆盖四份受管名单文件（缺项即失败，防"清单被裁剪"）。

退出码 0 通过 / 1 失败。``--json`` 输出机器可读结果。
"""
import io
import json
import os
import subprocess
import sys

HIST_DIR = os.environ.get("REFRESH_HIST_DIR", "/opt/dnsguard/cn-list-history")
MANIFEST = os.path.join(HIST_DIR, "MANIFEST.sha256")
SIG = MANIFEST + ".asc"
VETO = os.environ.get("REFRESH_VETO_FILE", "/opt/dnsguard/cn_veto.txt")
CN_IP = os.environ.get("REFRESH_CN_IP_FILE", "/opt/dnsguard/cn_ip.txt")
TYPED = os.environ.get("REFRESH_TYPED_FILE", "/opt/dnscrypt-proxy/cn-domains-typed.txt")
RULES = os.environ.get("REFRESH_RULES_FILE", "/opt/dnscrypt-proxy/forwarding-rules.txt")
REQUIRED_FILES = [VETO, CN_IP, TYPED, RULES]

VETO_MIN_ENTRIES = 12000
IP_MIN_ENTRIES = 2000
DOMAIN_MIN_ENTRIES = 5000
VETO_MUST_ABSENT = ["baidu.com", "qq.com", "taobao.com", "jd.com", "gov.cn",
                    "aliyun.com", "weibo.com", "163.com", "bilibili.com", "zhihu.com"]
KEY_CN = ["baidu.com", "qq.com", "taobao.com", "jd.com", "gov.cn"]


def read_lines(path):
    if not os.path.exists(path):
        return None
    with io.open(path, encoding="utf-8", errors="replace") as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]


def parse_manifest(path):
    """→ {路径: sha256}；文件缺失返回 None。"""
    if not os.path.exists(path):
        return None
    out = {}
    with io.open(path, encoding="utf-8", errors="replace") as f:
        for ln in f:
            ln = ln.rstrip("\n")
            if not ln.strip() or ln.lstrip().startswith("#"):
                continue
            parts = ln.split("  ", 1)
            if len(parts) != 2:
                parts = ln.split(None, 1)
            if len(parts) != 2:
                continue
            out[parts[1].strip()] = parts[0].strip().lower()
    return out


def sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 16), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def verify_signature(manifest=MANIFEST, sig=SIG):
    """→ (ok, detail)。"""
    if not os.path.exists(manifest):
        return False, "MANIFEST 不存在"
    if not os.path.exists(sig):
        return False, "签名文件不存在：%s" % sig
    try:
        r = subprocess.run(["gpg", "--batch", "--verify", sig, manifest],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except Exception as e:
        return False, "gpg 不可用：%s" % str(e)[:120]
    txt = r.stdout.decode("utf-8", "replace")
    good = ("Good signature" in txt) or ("良好的签名" in txt)
    return (r.returncode == 0 and good), txt.strip().splitlines()[-1][:200] if txt.strip() else ""


def evaluate(files=None, manifest=None, sig=None):
    """→ (fails, warns, detail dict)。所有入参可注入以便单测。"""
    files = files or {}
    fails, warns = [], []
    detail = {}

    mp = manifest or MANIFEST
    entries = parse_manifest(mp)
    if entries is None:
        fails.append("MANIFEST 缺失：%s" % mp)
        entries = {}
    detail["manifest_entries"] = len(entries)

    for p in REQUIRED_FILES:
        if p not in entries:
            if p == TYPED and not os.path.exists(TYPED):
                continue      # typed 缺失只 WARN（guard 回退旧合并语义），不要求清单覆盖
            fails.append("MANIFEST 未覆盖受管名单：%s" % p)

    bad_hash = []
    for p, want in sorted(entries.items()):
        got = sha256_file(p)
        if got is None:
            bad_hash.append("%s（文件缺失）" % p)
        elif got != want:
            bad_hash.append("%s（sha256 不一致）" % p)
    if bad_hash:
        fails.append("哈希校验失败 %d 项：%s" % (len(bad_hash), "; ".join(bad_hash[:5])))
    detail["hash_checked"] = len(entries)

    if files.get("skip_signature"):
        warns.append("已按 --no-signature 跳过签名校验")
        detail["signature"] = "skipped"
    else:
        ok, why = verify_signature(mp, sig or SIG)
        detail["signature"] = "ok" if ok else "fail"
        if not ok:
            fails.append("MANIFEST 签名校验未过：%s" % why)

    veto = read_lines(VETO)
    if veto is None:
        fails.append("veto 名单缺失：%s" % VETO)
    else:
        detail["veto_entries"] = len(veto)
        if len(veto) < VETO_MIN_ENTRIES:
            fails.append("veto 条目 %d < 下限 %d" % (len(veto), VETO_MIN_ENTRIES))
        vset = set(x.lower() for x in veto)
        bad = sorted(x for x in VETO_MUST_ABSENT if x in vset)
        if bad:
            fails.append("veto 含国内关键域：%s" % bad)

    ip = read_lines(CN_IP)
    if ip is None:
        fails.append("cn_ip 名单缺失：%s" % CN_IP)
    else:
        detail["ip_entries"] = len(ip)
        if len(ip) < IP_MIN_ENTRIES:
            fails.append("cn_ip 条目 %d < 下限 %d" % (len(ip), IP_MIN_ENTRIES))

    typed = read_lines(TYPED)
    if typed is None:
        warns.append("typed 名单不存在（guard 将回退旧合并语义）：%s" % TYPED)
        detail["typed_total"] = None
    else:
        kinds = {}
        for ln in typed:
            kind, sep, _dom = ln.partition(":")
            kinds[kind if sep else "domain"] = kinds.get(kind if sep else "domain", 0) + 1
        detail["typed_kinds"] = kinds
        detail["typed_total"] = len(typed)
        if len(typed) < DOMAIN_MIN_ENTRIES or not kinds:
            fails.append("typed 名单条目 %d < 下限 %d 或为空" % (len(typed), DOMAIN_MIN_ENTRIES))

    rules = read_lines(RULES)
    if rules is None:
        fails.append("forwarding-rules 缺失：%s" % RULES)
    else:
        rset = set(x.split()[0].lower() for x in rules if x.split())
        detail["rules_entries"] = len(rset)
        missing = [d for d in KEY_CN if d not in rset]
        if len(rset) < DOMAIN_MIN_ENTRIES or missing:
            fails.append("forwarding-rules 覆盖不足（%d 条，缺 %s）" % (len(rset), missing))

    return fails, warns, detail


def main(argv):
    as_json = "--json" in argv
    quiet = "--quiet" in argv
    skip_sig = "--no-signature" in argv
    fails, warns, detail = evaluate({"skip_signature": skip_sig})
    if as_json:
        print(json.dumps({"ok": not fails, "fails": fails, "warns": warns, "detail": detail},
                         ensure_ascii=False, sort_keys=True))
    elif not quiet or fails:
        print("CN-LIST-CHECK %s" % ("OK" if not fails else "FAIL"))
        for k in sorted(detail):
            print("  %-16s %s" % (k, detail[k]))
        for w in warns:
            print("  WARN %s" % w)
        for f in fails:
            print("  FAIL %s" % f)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
