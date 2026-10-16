#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""单元依赖自检：deploy/systemd/** 里 Exec* 指向的可执行文件，必须能由本仓库提供。

为什么需要：systemd 单元的 ExecStart/ExecStartPost 指向缺失的脚本时，单元会直接进入
failed —— 这类问题在部署前就能离线发现。历史上踩过一次：dnsguard 的 ExecStartPost
指向 /usr/local/sbin/set-service-memory-swappiness.sh，而该脚本没随仓库发布。

判定规则：绝对路径且不在系统二进制白名单里的，其 basename 必须
  ① 存在于仓库任意位置，或 ② 出现在 install.sh 里（表示由安装脚本写入）。
"""
from __future__ import print_function

import glob
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# 系统自带二进制：不需要仓库提供
SKIP = {
    "/bin/sh", "/bin/bash", "/usr/bin/env", "/usr/bin/python3", "/usr/bin/systemctl",
    "/usr/sbin/ip", "/usr/bin/docker", "/usr/bin/rm", "/usr/bin/printf", "/usr/bin/sleep",
    "/usr/sbin/iptables", "/usr/sbin/iptables-restore", "/usr/bin/kill", "/usr/bin/cp",
}


def repo_basenames():
    names = set()
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for fn in filenames:
            names.add(fn)
    return names


def main():
    names = repo_basenames()
    install_txt = ""
    p = os.path.join(ROOT, "install.sh")
    if os.path.exists(p):
        with open(p, encoding="utf-8", errors="replace") as f:
            install_txt = f.read()

    fails = []
    checked = 0
    for f in sorted(glob.glob(os.path.join(ROOT, "deploy", "systemd", "**", "*"), recursive=True)):
        if not os.path.isfile(f) or not re.search(r"\.(service|conf|timer)$", f):
            continue
        with open(f, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = re.match(r"\s*Exec[A-Za-z]*=(-?)(\S+)", line)
                if not m:
                    continue
                prog = m.group(2)
                if not prog.startswith("/") or prog in SKIP:
                    continue
                checked += 1
                base = os.path.basename(prog)
                if base in names or base in install_txt:
                    continue
                fails.append((os.path.relpath(f, ROOT), prog))

    for rel, prog in fails:
        print("FAIL %s: Exec 依赖未随仓库提供 -> %s" % (rel, prog))
    print("检查了 %d 条 Exec 绝对路径" % checked)
    if fails:
        print("UNIT-DEPS FAILED (%d)" % len(fails))
        return 1
    print("UNIT-DEPS OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
