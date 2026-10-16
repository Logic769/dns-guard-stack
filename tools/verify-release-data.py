#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify-release-data.py —— F7：发布数据文件的清单覆盖与内容约束校验。

审计 2026-10-15 §F7：guard 在在线 CN veto 名单不可读时按
「last-good → 发布目录 cn-veto.snapshot.txt → 保守拒绝国内信任」回退（方向正确），
但该快照不在 RELEASE.sha256 的七个校验项中 ⇒ 发布代码一致并不能保证这份安全策略
数据完整。

本脚本检查两件事：

  1) 清单覆盖：`.files` 的每一项都必须在 `RELEASE.sha256` 里有记录且实际哈希一致；
     **`cn-veto.snapshot.txt` 必须出现在 `.files` 中**（F7 的核心要求）。
  2) 内容约束：快照必须是"可用策略数据" —— 条目数 ≥ MIN_ENTRIES、无空条目/无点条目、
     不含国内样本（否则会把国内站否决成境外，导致国内分流回退）、
     含来源与语义声明注释（防止被任意文件顶替）。

用法：verify-release-data.py [发布目录]（默认 /opt/dnsguard/current）[--quiet] [--json]
退出码：0 全部通过；1 任一不通过。
"""
import hashlib
import io
import json
import os
import sys

DEFAULT_REL = "/opt/dnsguard/current"
SNAPSHOT = "cn-veto.snapshot.txt"
MIN_ENTRIES = 1000
# 国内样本出现在「否决名单」里意味着国内站被判成境外 ⇒ 关键分流回退，必须拒绝
DOMESTIC_MUST_ABSENT = ["qq.com", "baidu.com", "taobao.com", "jd.com", "aliyun.com",
                        "weibo.com", "163.com", "gov.cn"]
REQUIRED_COMMENT_MARKERS = ["# 来源", "# 语义"]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def read_text(path):
    with io.open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def parse_manifest(text):
    """RELEASE.sha256 → {文件名: sha256}（容忍 `sha  name` / `sha *name`）"""
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        sha, name = parts[0].strip(), parts[1].strip().lstrip("*").strip()
        out[name] = sha.lower()
    return out


def evaluate(rel):
    """→ (checks, fails)；checks = [(ok, 描述)]，fails = [描述]"""
    checks, fails = [], []

    def rec(ok, msg):
        checks.append((bool(ok), msg))
        if not ok:
            fails.append(msg)
        return ok

    files_path = os.path.join(rel, ".files")
    manifest_path = os.path.join(rel, "RELEASE.sha256")
    if not os.path.isfile(files_path):
        rec(False, "缺少 %s" % files_path)
        return checks, fails
    if not os.path.isfile(manifest_path):
        rec(False, "缺少 %s" % manifest_path)
        return checks, fails

    listed = []
    for raw in read_text(files_path).splitlines():
        n = raw.strip()
        if not n or n.startswith("#"):
            continue
        if n.startswith("./"):
            n = n[2:]
        listed.append(n)
    manifest = parse_manifest(read_text(manifest_path))

    rec(bool(listed), "`.files` 非空（%d 项）" % len(listed))

    missing_manifest = [n for n in listed if n not in manifest]
    rec(not missing_manifest, "`.files` 每一项都在 RELEASE.sha256 中：缺失 %s"
        % (missing_manifest or "无"))

    mismatched, unreadable = [], []
    for n in listed:
        p = os.path.join(rel, n)
        if not os.path.isfile(p):
            unreadable.append(n)
            continue
        if n in manifest and sha256_file(p) != manifest[n]:
            mismatched.append(n)
    rec(not unreadable, "清单文件全部存在：缺失 %s" % (unreadable or "无"))
    rec(not mismatched, "清单文件 sha256 与 RELEASE.sha256 一致：不一致 %s"
        % (mismatched or "无"))

    rec(SNAPSHOT in listed, "F7：`%s` 已纳入发布清单 `.files`" % SNAPSHOT)

    snap_path = os.path.join(rel, SNAPSHOT)
    if not os.path.isfile(snap_path):
        rec(False, "缺少策略数据 %s" % snap_path)
        return checks, fails

    text = read_text(snap_path)
    entries, nodot, empties = [], [], 0
    for line in text.splitlines():
        s = line.strip()
        if not s:
            empties += 1
            continue
        if s.startswith("#"):
            continue
        dom = s.split()[0].strip().lower().rstrip(".")
        if not dom:
            continue
        entries.append(dom)
        if "." not in dom:
            nodot.append(dom)

    rec(len(entries) >= MIN_ENTRIES,
        "策略数据条目数 %d ≥ %d" % (len(entries), MIN_ENTRIES))
    rec(not nodot, "策略数据无『无点』条目：异常 %s" % (sorted(set(nodot))[:5] or "无"))

    leaked = sorted(set(d for d in DOMESTIC_MUST_ABSENT if d in set(entries)))
    rec(not leaked, "策略数据不含国内样本（否决名单误纳即国内分流回退）：命中 %s"
        % (leaked or "无"))

    absent_markers = [m for m in REQUIRED_COMMENT_MARKERS if m not in text]
    rec(not absent_markers, "策略数据含来源/语义声明注释：缺失 %s"
        % (absent_markers or "无"))

    return checks, fails


def main(argv):
    quiet = "--quiet" in argv
    as_json = "--json" in argv
    args = [a for a in argv[1:] if not a.startswith("--")]
    rel = args[0] if args else os.environ.get("RELEASE_DIR", DEFAULT_REL)
    checks, fails = evaluate(rel)

    if as_json:
        print(json.dumps({"release_dir": rel,
                          "checks": [{"ok": ok, "msg": m} for ok, m in checks],
                          "fails": fails, "ok": not fails}, ensure_ascii=False))
        return 1 if fails else 0

    if not quiet:
        for ok, msg in checks:
            print("  %s %s" % ("OK  " if ok else "FAIL", msg))
    if fails:
        for m in fails:
            print("FAIL %s" % m)
        print("RELEASE-DATA FAIL release_dir=%s fails=%d" % (rel, len(fails)))
        return 1
    print("RELEASE-DATA OK release_dir=%s checks=%d" % (rel, len(checks)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
