#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dnsguard-fw-table.py — dnsguard 防火墙规则的「整表生成 / 校验」工具（审计 2026-10-15 F1/F2）。

为什么需要它
  /usr/local/sbin/dnsguard-fw.sh 原先用逐条 `iptables -D ...` / `-I ...` / `-F ...` 收敛规则：
    · 先删后加之间存在真实空窗 —— 本机防护（INPUT 白名单）与容器间 53 约束短暂缺失；
    · 子链 `-F` 之后逐条 `-A` 重建，中途该链是空的；
    · `--check` 分支写在所有写操作之后，于是「只读检查」也会先真改生产规则（审计 F1）。
  本工具把「期望规则长什么样」与「怎么提交」彻底分离：它只做 文本 -> 文本 变换，产出一份
  完整的 filter 表文本，由 bash 侧用**单次** `iptables-restore` 提交 —— 全表原子替换，
  不存在「先删后加」的空窗，也不存在「check 顺手改生产」。

用法
  iptables-save -c -t filter | dnsguard-fw-table.py --a-ip 172.18.0.4 --ag-ip 172.18.0.6 \
      --b-ip 172.18.0.5 --alt-ip 172.18.0.8 --adgh-ip 172.18.0.2 --gw 172.18.0.1 \
      --probe-src 172.18.0.99 > new-filter.rules
  iptables-restore -c new-filter.rules                     # 原子提交

  iptables-save -c -t filter | dnsguard-fw-table.py --verify   # 只读校验（exit 0 通过 / 1 失败）

保证与边界
  · 纯函数：不调用 iptables，不读写任何系统状态；同输入必然同输出（幂等）。
  · 只触碰「我们管理的对象」：
      INPUT       : --comment 以 TAG 开头的规则（默认 14 条）
      DOCKER-USER : --comment 以 TAG53- 开头、等于 JTAG，或 -j CHAIN / -j CHAIN_A 的规则（13 条）
      CHAIN       : 整链内容（自建链，2 条）
      CHAIN_A     : 整链内容（自建链，5 条）
    其余规则（docker 生成、其它运维脚本生成、DOCKER-USER 末尾的 -j RETURN）原样保留。
  · 规则里出现的地址全部来自命令行参数 ⇒ 容器 IP / docker0 网关漂移时，同一份代码即产出正确表，
    不需要改脚本（对应审计 F4「同一事实多处引用」的统一事实源要求）。
"""

from __future__ import print_function

import argparse
import re
import sys

COUNTER_RE = re.compile(r"^\[\d+:\d+\]\s+")
COMMENT_RE = re.compile(r'--comment\s+(?:"([^"]*)"|(\S+))')


# ---------------------------------------------------------------- 期望规则 ---
def expected_input(o):
    """INPUT 链期望规则，按链内真实先后顺序（链首优先级从高到低）。"""
    t = o["tag"]
    gw = o["gw"]
    net = o["net"]
    return [
        '-A INPUT -i lo -p udp -m comment --comment "%s-allow-lo-udp" -j ACCEPT' % t,
        '-A INPUT -i lo -p tcp -m comment --comment "%s-allow-lo-tcp" -j ACCEPT' % t,
        '-A INPUT -s %s/32 -p udp -m comment --comment "%s-allow-host-local-udp" -j ACCEPT' % (gw, t),
        '-A INPUT -s %s/32 -p tcp -m comment --comment "%s-allow-host-local-tcp" -j ACCEPT' % (gw, t),
        '-A INPUT -s 127.0.0.0/8 -p udp -m comment --comment "%s-allow-loopback-udp" -j ACCEPT' % t,
        '-A INPUT -s 127.0.0.0/8 -p tcp -m comment --comment "%s-allow-loopback-tcp" -j ACCEPT' % t,
        '-A INPUT -s %s/32 -p udp -m udp --dport 5355 -m comment --comment "%s-allow-adgh" -j ACCEPT' % (o["adgh_ip"], t),
        '-A INPUT -s %s/32 -p tcp -m tcp --dport 5355 -m comment --comment "%s-allow-adgh-tcp" -j ACCEPT' % (o["adgh_ip"], t),
        '-A INPUT -s %s/32 -p udp -m udp --dport 5356 -m comment --comment "%s-allow-probe" -j ACCEPT' % (o["probe_src"], t),
        '-A INPUT -s %s/32 -p tcp -m tcp --dport 5356 -m comment --comment "%s-allow-probe-tcp" -j ACCEPT' % (o["probe_src"], t),
        '-A INPUT -s %s -p udp -m udp --dport 5355 -m comment --comment "%s-deny-guard-others" -j DROP' % (net, t),
        '-A INPUT -s %s -p tcp -m tcp --dport 5355 -m comment --comment "%s-deny-guard-others-tcp" -j DROP' % (net, t),
        '-A INPUT -s %s -p udp -m multiport --dports 5353,5354,5356 -m comment --comment "%s-deny-internal" -j DROP' % (net, t),
        '-A INPUT -s %s -p tcp -m multiport --dports 5353,5354,5356 -m comment --comment "%s-deny-internal-tcp" -j DROP' % (net, t),
    ]


def expected_docker_user(o):
    """DOCKER-USER 链期望规则（13 条，链首段）。"""
    t53 = o["tag53"]
    jt = o["jtag"]
    a, ag, b, alt = o["a_ip"], o["ag_ip"], o["b_ip"], o["alt_ip"]
    return [
        '-A DOCKER-USER -s %s/32 -d %s/32 -p udp -m udp --dport 53 -m comment --comment "%s-allow-a-to-aghdq@%s>%s" -j ACCEPT' % (a, ag, t53, a, ag),
        '-A DOCKER-USER -s %s/32 -d %s/32 -p tcp -m tcp --dport 53 -m comment --comment "%s-allow-a-to-aghdq-tcp@%s>%s" -j ACCEPT' % (a, ag, t53, a, ag),
        '-A DOCKER-USER -d %s/32 -p udp -m udp --dport 53 -m comment --comment "%s-deny-a@%s" -j DROP' % (a, t53, a),
        '-A DOCKER-USER -d %s/32 -p tcp -m tcp --dport 53 -m comment --comment "%s-deny-a-tcp@%s" -j DROP' % (a, t53, a),
        '-A DOCKER-USER -d %s/32 -p udp -m udp --dport 53 -m comment --comment "%s-deny-b@%s" -j DROP' % (b, t53, b),
        '-A DOCKER-USER -d %s/32 -p tcp -m tcp --dport 53 -m comment --comment "%s-deny-b-tcp@%s" -j DROP' % (b, t53, b),
        '-A DOCKER-USER -d %s/32 -p udp -m udp --dport 53 -m comment --comment "%s-deny-alt@%s" -j DROP' % (alt, t53, alt),
        '-A DOCKER-USER -d %s/32 -p tcp -m tcp --dport 53 -m comment --comment "%s-deny-alt-tcp@%s" -j DROP' % (alt, t53, alt),
        '-A DOCKER-USER -d %s/32 -p udp -m udp --dport 53 -m comment --comment "%s-deny-aghdq@%s" -j DROP' % (ag, t53, ag),
        '-A DOCKER-USER -d %s/32 -p tcp -m tcp --dport 53 -m comment --comment "%s-deny-aghdq-tcp@%s" -j DROP' % (ag, t53, ag),
        '-A DOCKER-USER -s %s/32 -m comment --comment %s-unboundb53 -j %s' % (b, jt, o["chain"]),
        '-A DOCKER-USER -s %s/32 -m comment --comment %s-unboundb53 -j %s' % (alt, jt, o["chain"]),
        '-A DOCKER-USER -s %s/32 -m comment --comment %s-dns-a-egress -j %s' % (a, jt, o["chain_a"]),
    ]


def expected_chain(o):
    """自建链 CHAIN（禁止 unbound-b 之外的明文 53）。"""
    c = o["chain"]
    return [
        '-A %s -p udp -m udp --dport 53 -m comment --comment "unbound-b-plain53-udp" -j DROP' % c,
        '-A %s -p tcp -m tcp --dport 53 -m comment --comment "unbound-b-plain53-tcp" -j DROP' % c,
    ]


def expected_chain_a(o):
    """自建链 CHAIN_A（A 容器只允许向上游 ag 的明文 53）。"""
    c = o["chain_a"]
    ag = o["ag_ip"]
    return [
        '-A %s -d %s/32 -p udp -m udp --dport 53 -j RETURN' % (c, ag),
        '-A %s -d %s/32 -p tcp -m tcp --dport 53 -j RETURN' % (c, ag),
        '-A %s -p udp -m udp --dport 53 -m comment --comment "DNS_A_EGRESS-drop-udp" -j DROP' % c,
        '-A %s -p tcp -m tcp --dport 53 -m comment --comment "DNS_A_EGRESS-drop-tcp" -j DROP' % c,
        '-A %s -j RETURN' % c,
    ]


# ---------------------------------------------------------------- 解析/提交 ---
def comment_of(rule):
    m = COMMENT_RE.search(rule)
    if not m:
        return None
    return m.group(1) if m.group(1) is not None else m.group(2)


def norm(rule):
    """规范化用于比较：去掉计数器前缀、统一 comment 引号（iptables-save 只对含特殊字符的
    comment 加引号，同一规则可能两种形态出现）。"""
    r = COUNTER_RE.sub("", rule)
    r = re.sub(r'--comment\s+"([^"]*)"', r'--comment \1', r)
    return r


def requote(rule):
    """与 iptables-save 的规范化对齐：comment 值只含安全字符时去掉引号，含特殊字符
    （如 `@A>AG` 里的 `>`、空格）时保留引号。这样 apply 之后 `iptables-save` 的输出与
    我们生成的文本逐字符一致，人工核对不会看到无意义的引号差异。"""
    def repl(m):
        v = m.group(1)
        if re.match(r"^[A-Za-z0-9_-]+$", v):
            return "--comment %s" % v
        return '--comment "%s"' % v
    return re.sub(r'--comment\s+"([^"]*)"', repl, rule)


def owner_of(rule, o):
    """返回该规则的「归属」：'input' | 'docker-user' | 'chain' | 'chain_a' | None。

    判据全部基于 comment 与目标链，不依赖规则在链中的位置 —— 所以「按规则号删除」那类
    易错逻辑（旧脚本 137-153 行）不再需要。
    """
    m = re.match(r"^-A\s+(\S+)\s", rule)
    if not m:
        return None
    chain = m.group(1)
    c = comment_of(rule)
    if chain == "INPUT":
        return "input" if (c and c.startswith(o["tag"])) else None
    if chain == "DOCKER-USER":
        if c and (c.startswith(o["tag53"] + "-") or c == o["jtag"] or c.startswith(o["jtag"])):
            return "docker-user"
        if re.search(r"-j\s+%s(\s|$)" % re.escape(o["chain"]), rule) or re.search(r"-j\s+%s(\s|$)" % re.escape(o["chain_a"]), rule):
            return "docker-user"          # 旧式无 tag 跳转，也归我们清理
        return None
    if chain == o["chain"]:
        return "chain"
    if chain == o["chain_a"]:
        return "chain_a"
    return None


def parse(text):
    """把 iptables-save 输出拆成 (前导行, 链定义行, 链顺序, {链: [原始规则行]})。

    注意 iptables-save -c 的规则行带计数器前缀 `[pkts:bytes] `，必须先剥掉前缀再判链。
    """
    prefix, defs, order, rules = [], [], [], {}
    for raw in text.splitlines():
        if not raw.strip():
            continue
        if raw.startswith("COMMIT"):
            continue
        if raw.startswith(":") and " " in raw:
            name = raw[1:].split()[0]
            defs.append(raw)
            if name not in order:
                order.append(name)
            rules.setdefault(name, [])
            continue
        body = COUNTER_RE.sub("", raw)
        if body.startswith("-A "):
            name = body.split()[1]
            if name not in order:
                order.append(name)
            rules.setdefault(name, []).append(raw)
            continue
        if raw.startswith("#") and "Completed" in raw:
            continue            # 结束注释行由输出侧重新生成
        prefix.append(raw)      # '# ...' / '*filter' / 其它未知行
    return prefix, defs, order, rules


def build(text, o):
    prefix, defs, order, rules = parse(text)
    have = set(d[1:].split()[0] for d in defs)

    managed = {name: [] for name in order}
    keep = {}
    for name in order:
        for raw in rules.get(name, []):
            body = COUNTER_RE.sub("", raw)
            if owner_of(body, o):
                managed[name].append(body)
            else:
                keep.setdefault(name, []).append(raw)

    # CHAIN / CHAIN_A 缺失时补链定义
    for extra in (o["chain"], o["chain_a"]):
        if extra not in have:
            defs.append(":%s - [0:0]" % extra)
            have.add(extra)
            order.append(extra)
            keep.setdefault(extra, [])

    new_input = [requote(r) for r in expected_input(o)]
    new_du = [requote(r) for r in expected_docker_user(o)]
    new_chain = [requote(r) for r in expected_chain(o)]
    new_chain_a = [requote(r) for r in expected_chain_a(o)]

    out_rules = {}
    for name in order:
        if name == "INPUT":
            out_rules[name] = new_input + keep.get(name, [])
        elif name == "DOCKER-USER":
            out_rules[name] = new_du + keep.get(name, [])
        elif name == o["chain"]:
            out_rules[name] = new_chain
        elif name == o["chain_a"]:
            out_rules[name] = new_chain_a
        else:
            out_rules[name] = keep.get(name, [])

    lines = list(prefix) + list(defs)
    for name in order:
        lines.extend(out_rules.get(name, []))
    lines.append("COMMIT")
    return "\n".join(lines) + "\n", managed


# ------------------------------------------------------------------- 校验 ---
def verify(text, o):
    """只读校验：期望规则齐全、相对顺序正确、无重复、无旧式残留。返回 (errors, warnings)。"""
    errors, warnings = [], []
    _prefix, _defs, order, rules = parse(text)
    chains = {name: [norm(r) for r in rules.get(name, [])] for name in order}

    plan = [
        ("INPUT", expected_input(o), "input"),
        ("DOCKER-USER", expected_docker_user(o), "docker-user"),
        (o["chain"], expected_chain(o), "chain"),
        (o["chain_a"], expected_chain_a(o), "chain_a"),
    ]
    for name, want, _owner in plan:
        want = [norm(r) for r in want]
        got = chains.get(name)
        if got is None:
            errors.append("链 %s 不存在" % name)
            continue
        ours = [r for r in got if owner_of(r, o)]
        if name in (o["chain"], o["chain_a"]):
            ours = got
        missing = [r for r in want if r not in got]
        if missing:
            errors.append("链 %s 缺少 %d 条期望规则，例如: %s" % (name, len(missing), missing[0]))
        extra = [r for r in ours if r not in want]
        if extra:
            errors.append("链 %s 有 %d 条非期望的管理规则，例如: %s" % (name, len(extra), extra[0]))
        for r in want:
            if got.count(r) > 1:
                errors.append("链 %s 规则重复: %s" % (name, r))
        idx = [got.index(r) for r in want if r in got]
        if idx != sorted(idx):
            errors.append("链 %s 管理规则顺序错乱" % name)
        if idx and idx[0] != 0 and name in ("INPUT", "DOCKER-USER"):
            warnings.append("链 %s 的管理规则不在链首（首条位于位置 %d）—— 可能有其它组件插入规则" % (name, idx[0]))

    # 旧式残留：DOCKER-USER 里指向自建链但没有我们 comment 的跳转
    for r in chains.get("DOCKER-USER", []):
        if re.search(r"-j\s+%s(\s|$)" % re.escape(o["chain"]), r) or re.search(r"-j\s+%s(\s|$)" % re.escape(o["chain_a"]), r):
            c = comment_of(r)
            if not (c and c.startswith(o["jtag"])):
                errors.append("DOCKER-USER 存在无 tag 的旧式跳转: %s" % r)
    return errors, warnings


# --------------------------------------------------------------------- CLI ---
def add_common(p):
    p.add_argument("--a-ip", default="172.18.0.4")
    p.add_argument("--ag-ip", default="172.18.0.6")
    p.add_argument("--b-ip", default="172.18.0.5")
    p.add_argument("--alt-ip", default="172.18.0.8")
    p.add_argument("--adgh-ip", default="172.18.0.2")
    p.add_argument("--gw", default="172.18.0.1")
    p.add_argument("--net", default="172.16.0.0/12")
    p.add_argument("--probe-src", default="172.18.0.99")
    p.add_argument("--tag", default="f2-20261010")
    p.add_argument("--tag53", default="cn53-fwd")
    p.add_argument("--jtag", default="dnsguard-jump")
    p.add_argument("--chain", default="UNBOUNDB_53")
    p.add_argument("--chain-a", default="DNS_A_EGRESS")


def opts(a):
    return dict(a_ip=a.a_ip, ag_ip=a.ag_ip, b_ip=a.b_ip, alt_ip=a.alt_ip, adgh_ip=a.adgh_ip,
                gw=a.gw, net=a.net, probe_src=a.probe_src, tag=a.tag, tag53=a.tag53,
                jtag=a.jtag, chain=a.chain, chain_a=a.chain_a)


def main(argv=None):
    ap = argparse.ArgumentParser(description="dnsguard 防火墙整表生成/校验")
    add_common(ap)
    ap.add_argument("--verify", action="store_true", help="只读校验 stdin 的表（exit 0/1）")
    args = ap.parse_args(argv)
    o = opts(args)
    text = sys.stdin.read()
    if not text.strip():
        sys.stderr.write("ERROR: stdin 为空（应传入 `iptables-save -c -t filter` 的输出）\n")
        return 2
    if args.verify:
        errors, warnings = verify(text, o)
        for w in warnings:
            print("WARN %s" % w)
        for e in errors:
            print("FAIL %s" % e)
        if errors:
            print("FW-TABLE VERIFY FAIL (%d 项)" % len(errors))
            return 1
        print("FW-TABLE VERIFY OK")
        return 0
    out, _managed = build(text, o)
    # 生成物自检：同一份文本必须能通过校验，否则拒绝输出（防止把坏表交给 restore）
    errors, warnings = verify(out, o)
    if errors:
        for e in errors:
            sys.stderr.write("SELFTEST FAIL %s\n" % e)
        sys.stderr.write("拒绝输出未经自检的新表\n")
        return 1
    for w in warnings:
        sys.stderr.write("SELFTEST WARN %s\n" % w)
    sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
