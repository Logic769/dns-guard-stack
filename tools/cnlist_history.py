#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CN 名单变更归档与签名（refresh-cn-rules.py / refresh-cn-veto-ip.py 共用）。

设计要点
--------
* 归档：每次刷新把「旧集合 -> 新集合」的差异落盘到
  ``$REFRESH_HIST_DIR/YYYYMMDD/<list>-<ts>.json``（计数 + 样例 + 当前文件 sha256 + 上游身份），
  完整明细另存 ``<list>-<ts>.added.txt.gz`` / ``.removed.txt.gz``（gzip，避免上万行膨胀）。
* 清单：``$REFRESH_HIST_DIR/MANIFEST.sha256`` 汇总受管名单文件与保留期内所有归档产物的 sha256。
* 签名：对 MANIFEST 做 GPG 分离签名（``MANIFEST.sha256.asc``）；密钥无口令。
  无 gpg / 签名失败只记 WARN —— 刷新不应因为签名链路故障而不更新名单，验签是运维侧职责。
* 保留：默认 30 天（``REFRESH_HIST_RETENTION_DAYS=0`` 表示永久）。
* 唯一联网函数是 ``upstream_v2fly()``（取上游 commit sha，用于来源钉扎），失败只记 WARN、
  不影响刷新；其余逻辑只读本地文件算哈希，不改动名单文件本身。
"""
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import time

HIST_DIR = os.environ.get("REFRESH_HIST_DIR", "/opt/dnsguard/cn-list-history")
RETENTION_DAYS = int(os.environ.get("REFRESH_HIST_RETENTION_DAYS", "30") or "0")
MANAGED = [p for p in os.environ.get(
    "REFRESH_MANAGED_FILES",
    "/opt/dnsguard/cn_veto.txt:"
    "/opt/dnsguard/cn_ip.txt:"
    "/opt/dnscrypt-proxy/forwarding-rules.txt:"
    "/opt/dnscrypt-proxy/cn-domains-typed.txt").split(os.pathsep) if p]
SAMPLE = 20
LOG = os.environ.get("REFRESH_LOG", "/var/log/cn-rules-refresh.log")
DAY_RE = re.compile(r"^\d{8}$")


def log(msg):
    line = "[%s] [hist] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line)
    try:
        with io.open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def upstream_v2fly(repo="v2fly/domain-list-community", timeout=20):
    """取上游 master 的 commit sha（来源钉扎）。失败返回 {"pinned": False, ...}，不抛异常。"""
    url = "https://api.github.com/repos/%s/commits/master" % repo
    out = {"pinned": False, "source_url": url}
    try:
        from urllib.request import Request, urlopen
        req = Request(url, headers={"User-Agent": "dnsguard-cn-list-refresh"})
        with urlopen(req, timeout=timeout) as r:
            obj = json.loads(r.read(1 << 20).decode("utf-8", "replace"))
        sha = obj.get("sha")
        if sha:
            out["v2fly_commit"] = sha
            out["v2fly_commit_date"] = (obj.get("commit") or {}).get("committer", {}).get("date")
            out["pinned"] = True
    except Exception as e:
        out["error"] = str(e)[:120]
        log("WARN 上游 commit 探测失败：%s" % str(e)[:120])
    return out


def http_source_meta(url, timeout=20):
    """取 URL 的 ETag / Last-Modified（来源一致性锚点）；失败返回空 dict。"""
    try:
        from urllib.request import Request, urlopen
        req = Request(url, headers={"User-Agent": "dnsguard-cn-list-refresh"})
        with urlopen(req, timeout=timeout) as r:
            return {"etag": r.headers.get("ETag"),
                    "last_modified": r.headers.get("Last-Modified"),
                    "content_length": r.headers.get("Content-Length")}
    except Exception as e:
        return {"head_error": str(e)[:100]}


def sha256_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 16), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def write_gz(path, items):
    tmp = path + ".tmp"
    with gzip.open(tmp, "wt", encoding="utf-8") as f:
        for it in items:
            f.write(it + "\n")
    os.replace(tmp, path)
    return path


def _ensure_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path, 0o755)
    return path


def record(list_name, old, new, path, upstream=None, gate="ok", extra=None):
    """把 old -> new 的差异写成归档，返回摘要 dict。

    ``old`` / ``new`` 是任意可比较元素集合；``path`` 是受管名单文件路径。
    """
    ts = time.strftime("%Y%m%d-%H%M%S")
    day = _ensure_dir(os.path.join(HIST_DIR, time.strftime("%Y%m%d")))
    base = os.path.join(day, "%s-%s" % (list_name, ts))
    old_s, new_s = set(old), set(new)
    added = sorted(new_s - old_s)
    removed = sorted(old_s - new_s)
    info = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "list": list_name,
        "file": path,
        "file_sha256": sha256_file(path),
        "old_count": len(old_s),
        "new_count": len(new_s),
        "added": len(added),
        "removed": len(removed),
        "added_sample": added[:SAMPLE],
        "removed_sample": removed[:SAMPLE],
        "unchanged": (old_s == new_s),
        "gate": gate,
        "upstream": upstream or {},
    }
    if extra:
        info.update(extra)
    if added:
        info["added_file"] = write_gz(base + ".added.txt.gz", added)
    if removed:
        info["removed_file"] = write_gz(base + ".removed.txt.gz", removed)
    jf = base + ".json"
    tmp = jf + ".tmp"
    with io.open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(info, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, jf)
    log("归档 %s：%s -> %s（新增 %d / 移除 %d）%s"
        % (list_name, info["old_count"], info["new_count"], info["added"], info["removed"], jf))
    return info


def manifest_entries():
    ents = []
    for p in MANAGED:
        s = sha256_file(p)
        if s:
            ents.append((s, p))
    if os.path.isdir(HIST_DIR):
        for root, _dirs, files in os.walk(HIST_DIR):
            for fn in sorted(files):
                if fn.endswith(".json") or fn.endswith(".txt.gz"):
                    p = os.path.join(root, fn)
                    s = sha256_file(p)
                    if s:
                        ents.append((s, p))
    return sorted(ents, key=lambda x: x[1])


def update_manifest():
    ents = manifest_entries()
    mp = os.path.join(_ensure_dir(HIST_DIR), "MANIFEST.sha256")
    tmp = mp + ".tmp"
    with io.open(tmp, "w", encoding="utf-8", newline="\n") as f:
        for s, p in ents:
            f.write("%s  %s\n" % (s, p))
    os.replace(tmp, mp)
    return mp, len(ents)


def sign_manifest():
    mp = os.path.join(HIST_DIR, "MANIFEST.sha256")
    asc = mp + ".asc"
    if not os.path.exists(mp):
        return None
    try:
        r = subprocess.run(["gpg", "--batch", "--yes", "--armor", "--detach-sign",
                            "--output", asc, mp],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if r.returncode != 0:
            log("WARN gpg 签名失败(rc=%d)：%s"
                % (r.returncode, r.stdout.decode("utf-8", "replace").strip()[:200]))
            return None
        return asc
    except Exception as e:
        log("WARN gpg 不可用（跳过签名）：%s" % str(e)[:120])
        return None


def cleanup(retention_days=None):
    days = RETENTION_DAYS if retention_days is None else retention_days
    if not days or days <= 0:
        return 0
    cutoff = time.time() - days * 86400
    n = 0
    if not os.path.isdir(HIST_DIR):
        return 0
    for name in sorted(os.listdir(HIST_DIR)):
        p = os.path.join(HIST_DIR, name)
        if os.path.isdir(p) and DAY_RE.match(name) and os.path.getmtime(p) < cutoff:
            shutil.rmtree(p, ignore_errors=True)
            n += 1
    return n


def finalize(note=None):
    """更新 MANIFEST -> 签名 -> 清理过期归档。返回摘要 dict。"""
    mp, n = update_manifest()
    asc = sign_manifest()
    cleaned = cleanup()
    log("归档收尾：MANIFEST %d 项；签名 %s；清理过期目录 %d 个%s"
        % (n, "OK" if asc else "跳过", cleaned, ("；%s" % note) if note else ""))
    return {"manifest": mp, "entries": n, "signature": asc, "cleaned": cleaned}
