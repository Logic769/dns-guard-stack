#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CN 域名单刷新（可安全自动化）—— 2026-10-15 F5 增强版

流程：并行拉取 v2fly CN 名单 → **保留匹配类型**（full:/domain:/suffix:）→
      生成 forwarding-rules（dnscrypt-proxy 用）+ cn-domains-typed（guard 用）→
      覆盖率 / 境外反例 / 变更幅度门禁 → 与现有文件比对（只比规则行）→ 未变则退出 0 →
      有变则备份 + 原子替换 + 重启 dcp + 功能自检，自检失败自动回滚。

F5（审计 2026-10-15 报告 §F5）：
  · 旧版对 full:/domain:/suffix: 一律去前缀 ⇒ 匹配类型丢失；guard 随后对所有条目按
    「精确 + 子域」匹配 ⇒ `full:host` 会连 `child.host` 一起判国内，而国内 B 是允许
    直接采纳的信任源 ⇒ 分类范围扩大 = 信任范围扩大。本版额外产出类型化名单，
    guard 侧按类型分别判定（guard.py: _load_cn_typed / _match_cn_typed）。
  · 新增门禁：境外反例不得进入 CN 集合；新增/移除幅度超限时拒绝更新（--force 越过）。
  · **分流行为不变**：仍旧「国内域名走国内 B」；forwarding-rules.txt 的格式与语义不变。

退出码：0=成功（含"无变化"），1=失败（已回滚或未改）
参数：--dry-run 只统计与门禁判定、不写任何文件；--force 越过大变更幅度门禁
数据源：首选 codeload 全量 tar；回退 jsdelivr 多镜像逐文件。
日志：/var/log/cn-rules-refresh.log
"""
import collections
import io
import ipaddress
import os
import re
import socket
import subprocess
import sys
import tarfile
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.request import urlopen

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import cnlist_history as hist
except Exception:          # 归档模块缺失时刷新仍可运行（只失去归档/签名能力）
    hist = None

RULES = "/opt/dnscrypt-proxy/forwarding-rules.txt"
LAST_TAR_SHA = {"sha256": None, "bytes": None}   # 本次上游 tar 内容指纹（来源钉扎用）
TYPED = "/opt/dnscrypt-proxy/cn-domains-typed.txt"
LOG = "/var/log/cn-rules-refresh.log"
TARGET = "127.0.0.1:5354"
# 数据源（F5 修正）：cdn.jsdelivr.net 在批量并发下会出现 HTTP 000（实测 93/315 抖动），
# 而 fastly/gcore/testingcf 三个 jsdelivr 边缘域可用 ⇒ 逐文件模式按镜像顺序回退。
BASES = [
    "https://fastly.jsdelivr.net/gh/v2fly/domain-list-community@master/data/",
    "https://gcore.jsdelivr.net/gh/v2fly/domain-list-community@master/data/",
    "https://testingcf.jsdelivr.net/gh/v2fly/domain-list-community@master/data/",
    "https://cdn.jsdelivr.net/gh/v2fly/domain-list-community@master/data/",
]
# 首选：一次性拉全量 tar 包（实测 codeload 可达，340KB/0.85s）⇒ 完全没有逐文件抖动。
TARBALL = "https://codeload.github.com/v2fly/domain-list-community/tar.gz/refs/heads/master"
MAX_TAR_BYTES = 50 * 1024 * 1024
SEEDS = ["geolocation-cn", "tld-cn"]
KEY_CN = ["baidu.com", "qq.com", "taobao.com", "jd.com", "gov.cn", "163.com", "aliyun.com"]
MIN_DOMAINS = 5000

# F5 门禁参数
MAX_CHANGE_PCT = 15.0     # 单侧（新增或移除）相对旧集合的最大比例
MIN_ABS_CHANGE = 200      # 比例门禁生效所需的最小绝对条数（少量抖动不触发）
FAIL_TOLERANCE = 0.25     # 子名单拉取失败占比容忍上限（jsdelivr 抖动实测约 12%）
MIN_FAIL_TOLERANCE = 10   # 绝对容忍条数下限：小批量拉取时不因个别抖动整体放弃
FOREIGN_GUARD = ["google.com", "youtube.com", "facebook.com", "twitter.com",
                 "amazon.com", "microsoft.com", "apple.com", "cloudflare.com",
                 "github.com", "example.org"]
FORCE = "--force" in sys.argv
DRY = "--dry-run" in sys.argv


def log(msg):
    line = "[%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line)
    try:
        with open(LOG, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def fetch_net(name):
    """逐文件模式：按镜像顺序 + 每镜像 2 次重试。"""
    for base in BASES:
        for attempt in range(2):
            try:
                with urlopen(base + name, timeout=25) as r:
                    return name, r.read().decode("utf-8", "replace")
            except Exception:
                time.sleep(0.5 + attempt)
    return name, ""


def fetch_tarball():
    """首选数据源：一次拉全量 tar 包 → {子名单名: 文本}；失败返回 (None, 0)。

    为什么不用逐文件：实测逐文件模式在 8 并发下，jsdelivr 对 93/315 个子名单返回
    HTTP 000（网络抖动，单独重试又 200），会让"域名数"少一千多条并触发幅度门禁。
    全量 tar 只有一次请求，内容与 @master 一致，解包后本地查表 ⇒ 零抖动。
    """
    for attempt in range(2):
        try:
            t0 = time.time()
            with urlopen(TARBALL, timeout=120) as r:
                raw = r.read(MAX_TAR_BYTES + 1)
            if len(raw) > MAX_TAR_BYTES:
                log("WARN tar 包 %d 字节 > 上限 %d，拒绝" % (len(raw), MAX_TAR_BYTES))
                return None, 0
            src = {}
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
                for m in tf.getmembers():
                    if not m.isfile():
                        continue
                    parts = m.name.split("/")
                    if len(parts) >= 3 and parts[1] == "data":
                        f = tf.extractfile(m)
                        if f is None:
                            continue
                        src[parts[2]] = f.read().decode("utf-8", "replace")
            if len(src) < 50:
                log("WARN tar 包只解出 %d 个名单，视为异常" % len(src))
                return None, 0
            if hist is not None:
                LAST_TAR_SHA["sha256"] = hist.sha256_bytes(raw)
                LAST_TAR_SHA["bytes"] = len(raw)
            log("全量 tar：%d 字节 / %d 个名单 / %.1fs" % (len(raw), len(src), time.time() - t0))
            return src, len(raw)
        except Exception as e:
            log("WARN tar 拉取失败(第 %d 次): %s" % (attempt + 1, e))
            time.sleep(2 + attempt * 3)
    return None, 0


def collect(sources=None):
    """→ (typed, failed, nfiles)；typed = {"full":set,"domain":set,"suffix":set"}

    sources=None → 逐文件多镜像拉取（回退路径）；sources=dict → 用全量 tar 的本地查表。
    """
    seen = set()
    typed = {"full": set(), "domain": set(), "suffix": set()}
    pending, failed = set(SEEDS), []
    while pending:
        batch = sorted(pending - seen)
        if not batch:
            break
        seen.update(batch)
        pending = set()
        if sources is not None:
            got = [(n, sources.get(n, "")) for n in batch]
        else:
            with ThreadPoolExecutor(max_workers=4) as ex:
                got = list(ex.map(fetch_net, batch))
        if True:
            for name, txt in got:
                if not txt:
                    failed.append(name)
                    continue
                for line in txt.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # v2fly 行尾可能带 "@属性" 或 "# 注释"，都必须先剥掉，
                    # 否则会被当成文件名/域名（实测导致 douyin/bilibili 等 18 个 include 失败）
                    if "#" in line:
                        line = line.split("#", 1)[0].strip()
                    if "@" in line:
                        line = line.split("@", 1)[0].strip()
                    if not line:
                        continue
                    if line.startswith("include:"):
                        pending.add(line.split(":", 1)[1].strip())
                        continue
                    if line.startswith(("keyword:", "regexp:")):
                        continue
                    # F5：无前缀 = domain 语义（自身 + 子域）；前缀决定精确/子域/后缀
                    kind = "domain"
                    for pre, k in (("full:", "full"), ("domain:", "domain"), ("suffix:", "suffix")):
                        if line.startswith(pre):
                            kind = k
                            line = line[len(pre):]
                            break
                    line = line.strip().rstrip(".")
                    if line.startswith("*."):
                        line = line[2:]
                        kind = "domain"          # 通配写法 = 含子域
                    if line and re.match(r"^[a-zA-Z0-9._-]+$", line):
                        typed[kind].add(line.lower())
    return typed, sorted(failed), len(seen)


def all_domains(typed):
    return set().union(typed["full"], typed["domain"], typed["suffix"])


def rule_lines(domains):
    return ["%s %s" % (d, TARGET) for d in sorted(domains)]


def typed_lines(typed):
    out = []
    for kind in ("full", "domain", "suffix"):
        for d in sorted(typed[kind]):
            out.append("%s:%s" % (kind, d))
    return out


def read_rules():
    try:
        txt = io.open(RULES, encoding="utf-8").read()
    except Exception:
        return []
    return [l for l in txt.splitlines() if l.strip() and not l.startswith("#")]


def read_rules_domains():
    out = set()
    for l in read_rules():
        parts = l.split()
        if parts:
            out.add(parts[0].strip().lower().rstrip("."))
    return out


def read_typed_domains():
    """回读类型化文件的域名集合（用于写入后一致性自检）"""
    out = set()
    try:
        txt = io.open(TYPED, encoding="utf-8").read()
    except Exception:
        return out
    for line in txt.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        _k, sep, d = line.partition(":")
        d = (d if sep else line).strip().lower().rstrip(".")
        if d:
            out.add(d)
    return out


def check_cn(names=("www.baidu.com", "www.qq.com", "www.jd.com")):
    """经 dcp 查 CN 域名，返回命中的 CN 个数"""
    sys.path.insert(0, "/opt/dnsguard")
    import guard as G
    G.load_cn_nets()
    ok = 0
    for n in names:
        q = G.mk_query(n, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(8)
        try:
            s.sendto(q, ("127.0.0.2", 5353))
            rc, ips, _c, _t = G.parse_a(s.recvfrom(4096)[0])
            f = [G.is_cn_ip(x) for x in ips]
            if f and all(x is True for x in f):
                ok += 1
        except Exception:
            pass
        finally:
            s.close()
    return ok


t0 = time.time()
src, tar_bytes = fetch_tarball()
if src is None:
    log("WARN 全量 tar 不可用 ⇒ 回退逐文件多镜像拉取")
    try:
        typed, failed, nfiles = collect(None)
    except Exception as e:
        log("FAIL 拉取异常: %s" % e)
        sys.exit(1)
else:
    try:
        typed, failed, nfiles = collect(src)
    except Exception as e:
        log("FAIL 解析异常: %s" % e)
        sys.exit(1)

domains = all_domains(typed)
log("拉取完成：文件=%d 域名=%d（full=%d domain=%d suffix=%d）拉取失败=%d 耗时=%.0fs"
    % (nfiles, len(domains), len(typed["full"]), len(typed["domain"]),
       len(typed["suffix"]), len(failed), time.time() - t0))
if failed:
    # F5 修正：任一失败即整体放弃太脆 —— 实测 jsdelivr 对个别子名单会 HTTP 000（网络抖动，
    # 同一名字稍后重试即 200）。改为**比例容忍**：少量失败只记 WARN 并继续（失败的子名单
    # 域名本次不进名单 ⇒ 该域退回国际严格通道，方向是更保守，不是扩大信任），
    # 失败面过大才整体放弃。
    log("WARN 子名单拉取失败 %d/%d（网络抖动，本次不含这些子名单的域名）：%s"
        % (len(failed), nfiles, ",".join(failed)))
    if len(failed) > max(MIN_FAIL_TOLERANCE, int(FAIL_TOLERANCE * nfiles)):
        log("FAIL 失败比例超过容忍上限（%d/%d > %d%%）→ 保留旧规则，不更新"
            % (len(failed), nfiles, int(FAIL_TOLERANCE * 100)))
        sys.exit(1)

missing = [d for d in KEY_CN if d not in domains]
if len(domains) < MIN_DOMAINS or missing:
    log("FAIL 覆盖率门控未过（域名=%d 阈值=%d 缺失关键域=%s）→ 不改动"
        % (len(domains), MIN_DOMAINS, missing))
    sys.exit(1)

# F5：境外反例门禁 —— 上游数据把境外域归入 CN 说明分类异常，宁可不动名单
bad = [d for d in FOREIGN_GUARD if d in domains]
if bad:
    log("FAIL 境外反例门禁未过（境外域被判入 CN: %s）→ 保留旧规则，不更新" % bad)
    sys.exit(1)

old_domains = read_rules_domains()
new = rule_lines(domains)
old = read_rules()
added_set = domains - old_domains
removed_set = old_domains - domains
pct_add = 100.0 * len(added_set) / max(1, len(old_domains))
pct_del = 100.0 * len(removed_set) / max(1, len(old_domains))
log("变化：新增 %d 条(%.1f%%) / 移除 %d 条(%.1f%%)（旧集合 %d 条，typed 回读 %d 条）"
    % (len(added_set), pct_add, len(removed_set), pct_del, len(old_domains),
       len(read_typed_domains())))

oversize = ((pct_add > MAX_CHANGE_PCT and len(added_set) > MIN_ABS_CHANGE)
            or (pct_del > MAX_CHANGE_PCT and len(removed_set) > MIN_ABS_CHANGE))
if oversize and not FORCE:
    log("FAIL 变更幅度门禁未过（阈值 %.0f%% 且 >%d 条）→ 保留旧规则，不更新；"
        "确认无误后用 --force 重跑" % (MAX_CHANGE_PCT, MIN_ABS_CHANGE))
    sys.exit(1)
if oversize:
    log("WARN 变更幅度超过阈值，但显式 --force ⇒ 继续")

typed_now = typed_lines(typed)
typed_prev = (io.open(TYPED, encoding="utf-8").read() if os.path.exists(TYPED) else "")
rules_same = (new == old)
typed_same = (typed_now == typed_prev)
if rules_same and typed_same:
    log("OK 名单无变化（%d 条），不重启 dcp" % len(new))
    sys.exit(0)
if rules_same:
    log("规则无变化，但类型化文件缺失/过期 ⇒ 只重生 typed（guard 按 mtime 热重载，不重启 dcp）")

if DRY:
    log("OK --dry-run：未写任何文件（将写 %d 条规则 + %d 条类型化条目）"
        % (len(new), len(typed_lines(typed))))
    sys.exit(0)

ts = time.strftime("%Y%m%d-%H%M%S")
bak = RULES + ".bak-%s" % ts
bak_typed = TYPED + ".bak-%s" % ts
had_typed = os.path.exists(TYPED)
try:
    if os.path.exists(RULES):
        io.open(bak, "w", encoding="utf-8").write(io.open(RULES, encoding="utf-8").read())
    if had_typed:
        io.open(bak_typed, "w", encoding="utf-8").write(io.open(TYPED, encoding="utf-8").read())
    tmp = RULES + ".tmp"
    io.open(tmp, "w", encoding="utf-8").write(
        "# generated %s by refresh-cn-rules.py (v2fly geosite CN)\n" % time.strftime("%Y-%m-%d %H:%M:%S")
        + "\n".join(new) + "\n")
    os.replace(tmp, RULES)
    tmp_t = TYPED + ".tmp"
    io.open(tmp_t, "w", encoding="utf-8").write(
        "# generated %s by refresh-cn-rules.py (typed: full=exact domain=with-subdomains suffix=label-boundary)\n"
        % time.strftime("%Y-%m-%d %H:%M:%S")
        + "# guard 读取本文件；缺失/为空/不可解析时回退旧合并语义（精确 + 子域）\n"
        + "\n".join(typed_lines(typed)) + "\n")
    os.replace(tmp_t, TYPED)
except Exception as e:
    log("FAIL 写文件失败: %s → 未生效" % e)
    sys.exit(1)


def rollback(reason):
    log("FAIL %s → 回滚旧规则并重启" % reason)
    try:
        if os.path.exists(bak):
            io.open(RULES, "w", encoding="utf-8").write(io.open(bak, encoding="utf-8").read())
        if had_typed and os.path.exists(bak_typed):
            io.open(TYPED, "w", encoding="utf-8").write(io.open(bak_typed, encoding="utf-8").read())
        elif not had_typed and os.path.exists(TYPED):
            os.remove(TYPED)     # 首次生成 ⇒ 回滚即回到"无类型化文件"（guard 回退旧语义）
    except Exception as e:
        log("  回滚写回失败: %s" % e)
    subprocess.run(["systemctl", "restart", "dnscrypt-proxy-local"], stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)
    time.sleep(8)
    log("  回滚后 CN 命中=%d/3" % check_cn())
    sys.exit(1)


# 写入后一致性自检：类型化文件回读必须等于本次域名总数
back = read_typed_domains()
if len(back) != len(domains):
    rollback("类型化文件回读不一致（%d != %d）" % (len(back), len(domains)))
log("自检：类型化文件回读 %d 条 = 本次域名 %d 条 ✓" % (len(back), len(domains)))

try:
    snap = os.path.join(os.path.dirname(TYPED), "cn-domains-typed.snapshot.txt")
    tmp_s = snap + ".tmp"
    _hdr = ("# snapshot %s by refresh-cn-rules.py（自检通过的最后有效类型化名单；guard F4 回退用）"
            % time.strftime("%Y-%m-%d %H:%M:%S"))
    _body = chr(10).join(typed_lines(typed)) + chr(10)
    io.open(tmp_s, "w", encoding="utf-8").write(_hdr + chr(10) + _body)
    os.replace(tmp_s, snap)
    log("快照：已更新 %s（%d 条）" % (snap, len(typed_lines(typed))))
except Exception as e:
    log("WARN 快照写入失败（不影响本次刷新，guard 仍用 live 名单）: %s" % e)

# ★ 第三份审计 F4：自检通过后才更新“最后有效的类型化名单快照”。
#   guard 在 live 文件缺失/不可解析/为空时吃快照；快照也没有则判“非国内”
#   （旧行为会回退“精确 + 所有子域”宽匹配 = 扩大国内信任）。
# 变更归档 + 来源钉扎 + 签名（失败不影响刷新；验签是运维侧 verify-cn-lists.py 的职责）
if hist is not None:
    try:
        up_info = hist.upstream_v2fly()
        if up_info.get("pinned"):
            log("上游钉扎：v2fly commit=%s（%s）"
                % (str(up_info.get("v2fly_commit"))[:12], up_info.get("v2fly_commit_date")))
        hist.record("forwarding-rules", old_domains, domains, RULES,
                    upstream=dict(up_info, tar_sha256=LAST_TAR_SHA["sha256"],
                                  tar_bytes=LAST_TAR_SHA["bytes"]),
                    gate="force" if oversize else "ok",
                    extra={"files_scanned": nfiles, "fetch_failed": len(failed),
                           "backup": bak})
        old_typed_set = set(x for x in typed_prev.splitlines()
                            if x.strip() and not x.startswith("#"))
        new_typed_set = set(x for x in typed_now.splitlines()
                            if x.strip() and not x.startswith("#"))
        hist.record("cn-domains-typed", old_typed_set, new_typed_set, TYPED,
                    upstream=dict(up_info, tar_sha256=LAST_TAR_SHA["sha256"]),
                    gate="force" if oversize else "ok",
                    extra={"full": len(typed["full"]), "domain": len(typed["domain"]),
                           "suffix": len(typed["suffix"]), "backup": bak_typed})
        hist.finalize()
    except Exception as e:
        log("WARN 变更归档失败（不影响名单更新）：%s" % str(e)[:120])

if rules_same:
    # 只重生 typed：guard 的 _load_cn_typed() 按 mtime 检测变化后热重载，
    # 而 dcp 只消费 forwarding-rules（本次未变）⇒ 不重启，避免无谓的国内通道中断。
    log("自检：规则未变 ⇒ 未重启 dcp；等 guard 热重载 typed")
    time.sleep(2)
    log("OK 已更新类型化名单（规则 %d 条 / 类型化 %d 条；备份 %s）"
        % (len(new), len(typed_now), bak))
    sys.exit(0)

subprocess.run(["systemctl", "restart", "dnscrypt-proxy-local"], stdout=subprocess.DEVNULL,
               stderr=subprocess.DEVNULL)
time.sleep(10)
active = subprocess.run(["systemctl", "is-active", "dnscrypt-proxy-local"],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().strip()
cn_ok = check_cn()
log("自检：dcp=%s CN 命中=%d/3" % (active, cn_ok))
if active != "active" or cn_ok < 2:
    rollback("服务自检未过（dcp=%s CN=%d/3）" % (active, cn_ok))

log("OK 已更新并生效（规则 %d 条 / 类型化 %d 条；备份 %s）"
    % (len(new), len(typed_now), bak))
sys.exit(0)
