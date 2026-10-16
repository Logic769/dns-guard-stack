#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""release_consistency.py —— 2026-10-15 审计 F5 门禁：两进程必须跑同一份不可变发布。

背景：dnsguard.service 与 dnsguard-verifier.service 的 ExecStart 都写 `.../current/...`，
但**切换软链不会替换已加载的模块** ⇒ 两个进程可以长期分属不同发布，且此前没有任何信号
（实测 guard 在 20261012-cn-zero-ttl-candidate、verifier 在 20261012-client-stage-metrics-01，
本脚本的首次预演就复现了这个错配）。

判定项：
  ① 两份 stats_meta.json 的 release_id / guard_sha256 / verifier_proto 必须一致；
  ② 两个 pid 必须存活，且 /proc/<pid>/cwd 必须相同；
  ③ 该 cwd 必须等于 current 软链的真实目标；
  ④ 磁盘上 <cwd>/guard.py 的 sha256 必须等于元数据里的 guard_sha256（防"路径一致、文件被换"）；
  ⑤ 元数据新鲜度：verifier 每 60s 落盘 ⇒ 15 分钟没更新即 WARN；
     guard 侧为**启动写一次** ⇒ 只对超过一周告警（陈旧本身已由"pid 不存活"覆盖）。

退出码：0 = 一致；1 = 不一致；2 = 环境不完整。**只读，不修改任何状态** ✓。
用法：python3 /opt/dnsguard/release_consistency.py [--json] [--quiet]
"""
from __future__ import absolute_import

import hashlib
import json
import os
import sys
import time

BASE = os.environ.get("GUARD_BASE", "/opt/dnsguard")
GUARD_META = os.path.join(os.environ.get("GUARD_STATE_DIR", BASE), "stats_meta.json")
VER_META = os.path.join(os.environ.get("VERIFIER_STATE_DIR", BASE + "/verifier-state"),
                        "stats_meta.json")
CURRENT = os.path.join(BASE, "current")
VER_STALE_WARN_SEC = float(os.environ.get("REL_CONSISTENCY_STALE_SEC", "900"))
GUARD_STALE_WARN_SEC = float(os.environ.get("REL_CONSISTENCY_GUARD_STALE_SEC", "604800"))


def evaluate(gm, vm, gproc, vproc, current, disk_sha, gage=None, vage=None):
    """纯判定（无 I/O）：返回 (fails, warns)。

    gproc / vproc = (alive, cwd_realpath, cmdline)；current = current 软链的真实目标；
    disk_sha = guard 进程 cwd 下 guard.py 的 sha256（不可读为 None）。
    """
    fails = []
    warns = []
    broken = False
    for tag, m in (("guard", gm), ("verifier", vm)):
        if not isinstance(m, dict) or "__error__" in m:
            why = m.get("__error__") if isinstance(m, dict) else "not a dict"
            fails.append("%s 元数据不可读/不可解析: %s" % (tag, why))
            broken = True
    if broken:
        return fails, warns

    if gm.get("release_id") != vm.get("release_id"):
        fails.append("release_id 不一致: guard=%r verifier=%r"
                     % (gm.get("release_id"), vm.get("release_id")))
    if gm.get("guard_sha256") != vm.get("guard_sha256"):
        fails.append("guard_sha256 不一致: guard=%r verifier=%r"
                     % (gm.get("guard_sha256"), vm.get("guard_sha256")))
    gp = gm.get("verifier_proto")
    vp = vm.get("verifier_proto")
    if gp is not None and vp is not None and gp != vp:
        fails.append("verifier_proto 不一致: guard=%r verifier=%r" % (gp, vp))

    ga, gcwd, gcmd = gproc
    va, vcwd, vcmd = vproc
    if not ga:
        fails.append("guard pid %r 不存活（元数据陈旧或进程已退）" % (gm.get("pid"),))
    if not va:
        fails.append("verifier pid %r 不存活（元数据陈旧或进程已退）" % (vm.get("pid"),))
    if ga and va and gcwd != vcwd:
        fails.append("两进程 cwd 不同: guard=%s verifier=%s" % (gcwd, vcwd))
    if ga and gcmd and "guard.py" not in gcmd:
        fails.append("guard pid 命令行不像 guard.py: %s" % gcmd)
    if va and vcmd and "verifier.py" not in vcmd:
        fails.append("verifier pid 命令行不像 verifier.py: %s" % vcmd)
    if current is None:
        fails.append("current 软链缺失: %s" % CURRENT)
    elif ga and gcwd and current != gcwd:
        fails.append("current=%s 与进程 cwd 不符（guard cwd=%s）" % (current, gcwd))
    if ga and gcwd:
        if disk_sha is None:
            fails.append("磁盘 %s/guard.py 不可读" % gcwd)
        elif disk_sha != gm.get("guard_sha256"):
            fails.append("磁盘 guard.py sha256=%s ≠ 元数据 %s（路径对但文件被换）"
                         % (disk_sha, gm.get("guard_sha256")))

    if gage is not None and gage > GUARD_STALE_WARN_SEC:
        warns.append("guard 元数据已 %.0fs 未更新（> %.0fs；guard 侧为启动写一次，通常属正常）"
                     % (gage, GUARD_STALE_WARN_SEC))
    if vage is not None and vage > VER_STALE_WARN_SEC:
        warns.append("verifier 元数据已 %.0fs 未更新（> %.0fs）" % (vage, VER_STALE_WARN_SEC))
    return fails, warns


def _read_json(path):
    try:
        with open(path, "rb") as f:
            return json.loads(f.read().decode("utf-8"))
    except Exception as e:
        return {"__error__": "%s: %s" % (type(e).__name__, e)}


def _sha256_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def _proc_info(pid):
    """返回 (alive, cwd_realpath, cmdline)；pid 缺失/进程不存在 ⇒ (False, None, "")"""
    if not pid:
        return False, None, ""
    try:
        with open("/proc/%d/cmdline" % int(pid), "rb") as f:
            cmd = f.read().decode("utf-8", "replace").replace("\0", " ").strip()
    except OSError:
        return False, None, ""
    try:
        cwd = os.path.realpath("/proc/%d/cwd" % int(pid))
    except OSError:
        cwd = None
    return True, cwd, cmd


def _age(path):
    try:
        return time.time() - os.path.getmtime(path)
    except OSError:
        return None


def main(argv):
    as_json = "--json" in argv
    quiet = "--quiet" in argv
    gm = _read_json(GUARD_META)
    vm = _read_json(VER_META)
    gproc = _proc_info(gm.get("pid")) if isinstance(gm, dict) else (False, None, "")
    vproc = _proc_info(vm.get("pid")) if isinstance(vm, dict) else (False, None, "")
    disk_sha = _sha256_file(os.path.join(gproc[1], "guard.py")) if gproc[1] else None
    current = os.path.realpath(CURRENT) if os.path.exists(CURRENT) else None
    fails, warns = evaluate(gm, vm, gproc, vproc, current, disk_sha,
                            _age(GUARD_META), _age(VER_META))
    ok = not fails
    out = {"ok": ok,
           "release_id": gm.get("release_id") if isinstance(gm, dict) else None,
           "guard_sha256": gm.get("guard_sha256") if isinstance(gm, dict) else None,
           "verifier_proto": gm.get("verifier_proto") if isinstance(gm, dict) else None,
           "guard": {"pid": gm.get("pid") if isinstance(gm, dict) else None,
                     "meta": GUARD_META, "age_s": _age(GUARD_META)},
           "verifier": {"pid": vm.get("pid") if isinstance(vm, dict) else None,
                        "meta": VER_META, "age_s": _age(VER_META)},
           "current": current, "fails": fails, "warns": warns}
    if as_json:
        print(json.dumps(out, ensure_ascii=False, sort_keys=True))
    elif not quiet:
        print("RELEASE-CONSISTENCY %s release=%s sha=%s proto=%s"
              % ("OK" if ok else "FAIL", out["release_id"],
                 str(out["guard_sha256"])[:12], out["verifier_proto"]))
        for f in fails:
            print("  FAIL %s" % f)
        for w in warns:
            print("  WARN %s" % w)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
