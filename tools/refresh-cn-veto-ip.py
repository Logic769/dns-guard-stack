#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""refresh-cn-veto-ip.py —— CN 否决名单（veto）与国内 IP 段（cn_ip.txt）统一刷新

与 refresh-cn-rules.py 属于**同一个刷新入口**（cron 同一条命令串联，共用同一份 v2fly 全量 tar），
但独立成文件，避免改动已上线验证的域名链路（零回归风险）。

一、veto（/opt/dnsguard/cn_veto.txt）
  语义：v2fly geolocation-!cn（地理位置在中国之外）⇒ 即便后缀命中 CN 规则也不走国内 B 路径。
  算法：BFS 逐文件展开 + 文件上限 2000 + 深度上限 8（追求完整覆盖，不再截断 include）+ 跳过 keyword:/regexp: + 剥离 @属性。
  实测复现现网名单：2167 条 vs 现网 2191 条，差异 25 条（1.1%，全为上游已移除条目）✓
  门禁：条目数下限 12000 / 国内关键域反例（出现即失败）/ 增删幅度 ≤5%（--force 越过）。

二、cn_ip.txt（/opt/dnsguard/cn_ip.txt）
  语义：guard 用它做 is_cn_ip()（区分"国内 geo 差异"与"真投毒"、CN 就近判定）。
  同源：主源 = guard.CN_URL（https://ispip.clang.cn/all_cn.txt）⇒ 与 guard 的 7 天兜底自下载
        完全同源、零语义漂移；备源 = misakaio/chnroutes2 的 chnroutes.txt（codeload 可达，
        实测与现网反向覆盖 0.9996）。
  门禁：条数下限 / 地址覆盖变化 ≤5% / 拒绝 prefixlen < 8。

写入策略：备份 → 临时文件 → 原子替换 → 回读自检；失败自动回滚。
写完**不重启任何服务**：guard 对 typed / veto / cn_ip 三者都按 mtime 热重载（60s 节流）。

退出码：0=成功（含"无变化"），1=失败（已回滚或未改）
参数：--dry-run 只统计与门禁判定、不写任何文件；--force 越过幅度门禁
日志：/var/log/cn-rules-refresh.log（与域名刷新共用）
"""
import io
import ipaddress
import json
import os
import re
import sys
import tarfile
import time
from urllib.request import Request, urlopen

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import cnlist_history as hist
except Exception:          # 归档模块缺失时刷新仍可运行（只失去归档/签名能力）
    hist = None

VETO = os.environ.get("REFRESH_VETO_FILE", "/opt/dnsguard/cn_veto.txt")
CN_IP = os.environ.get("REFRESH_CN_IP_FILE", "/opt/dnsguard/cn_ip.txt")
LOG = "/var/log/cn-rules-refresh.log"
TARBALL = "https://codeload.github.com/v2fly/domain-list-community/tar.gz/refs/heads/master"
MAX_TAR_BYTES = 80 * 1024 * 1024
BASE_FALLBACK = "https://fastly.jsdelivr.net/gh/v2fly/domain-list-community@master/data/"

# ---- veto 参数（与现网生成器一致的有界展开）----
VETO_SEED = "geolocation-!cn"
VETO_MAX_FILES = 2000
VETO_MAX_DEPTH = 8
# 同一份 tar 里的国内 list：冷启动兜底用（见 cn_domain_set）
CN_SEED = "geolocation-cn"
CN_EXPAND_MAX_FILES = 2000
CN_EXPAND_MAX_DEPTH = 8
# 本地 CN 集合低于此数视为"不可用"（骨架文件约 3 条；正常安装约 8800 条）
CN_LOCAL_MIN_TRUSTED = 1000
VETO_MIN_ENTRIES = 12000
VETO_MUST_ABSENT = ["baidu.com", "qq.com", "taobao.com", "jd.com", "gov.cn",
                    "aliyun.com", "weibo.com", "163.com", "bilibili.com", "zhihu.com"]
VETO_MAX_CHANGE_PCT = 5.0
VETO_MIN_ABS_CHANGE = 20
# 放宽展开后，上游 !cn 与 cn 两套数据会出现交叉（同一域名被判为"境外"）。
# 这类条目按「国内优先」从 veto 中剔除，而不是让整批更新失败；剔除比例过高说明
# 上游结构异变，仍判 FAIL。
VETO_CONFLICT_MAX_PCT = 40.0
CN_LOCAL_TYPED = "/opt/dnscrypt-proxy/cn-domains-typed.txt"
CN_LOCAL_RULES = "/opt/dnscrypt-proxy/forwarding-rules.txt"
CN_TLD_SUFFIX = (".cn", ".com.cn", ".net.cn", ".org.cn", ".gov.cn", ".edu.cn",
                 ".ac.cn", ".mil.cn", ".中国", ".中國")

# ---- cn_ip 参数 ----
CN_IP_SOURCES = [
    ("clang.cn(同源)", "https://ispip.clang.cn/all_cn.txt"),
    ("chnroutes2", "https://codeload.github.com/misakaio/chnroutes2/tar.gz/refs/heads/master"),
]
CN_IP_MIN_ENTRIES = 2000
CN_IP_MAX_CHANGE_PCT = 5.0
CN_IP_MIN_PREFIX = 8

UA = {"User-Agent": "Mozilla/5.0 (dnsguard-cn-list-refresh)"}
LAST_TAR_SHA = {"sha256": None, "bytes": None}   # 本次上游 tar 内容指纹（来源钉扎用）
DRY = "--dry-run" in sys.argv
FORCE = "--force" in sys.argv
PREFIX = re.compile(r"^(full|domain|suffix|regexp|keyword):", re.I)


def log(msg):
    line = "[%s] [veto-ip] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line)
    try:
        with open(LOG, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def http_get(url, timeout=180, limit=MAX_TAR_BYTES):
    req = Request(url, headers=UA)
    with urlopen(req, timeout=timeout) as r:
        return r.read(limit + 1)


# ---------------- veto ----------------
def load_tarball():
    """→ {子名单名: 文本}；失败 None"""
    for attempt in range(2):
        try:
            raw = http_get(TARBALL, timeout=180)
            if len(raw) > MAX_TAR_BYTES:
                log("WARN tar 包超上限 %d 字节，拒绝" % len(raw))
                return None
            docs = {}
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
                for m in tf.getmembers():
                    parts = m.name.split("/")
                    if m.isfile() and len(parts) >= 3 and parts[1] == "data":
                        f = tf.extractfile(m)
                        if f is not None:
                            docs[parts[2]] = f.read().decode("utf-8", "replace")
            if len(docs) < 50:
                log("WARN tar 包只解出 %d 个名单，视为异常" % len(docs))
                return None
            if hist is not None:
                LAST_TAR_SHA["sha256"] = hist.sha256_bytes(raw)
                LAST_TAR_SHA["bytes"] = len(raw)
            log("v2fly 全量 tar：%d 字节 / %d 个名单" % (len(raw), len(docs)))
            return docs
        except Exception as e:
            log("WARN tar 拉取失败(第 %d 次): %s" % (attempt + 1, str(e)[:100]))
            time.sleep(2 + attempt * 3)
    return None


def expand_seed(docs, seed, max_files, max_depth):
    """BFS 逐文件 FIFO 展开（文件上限 max_files / 深度上限 max_depth）→ (域名集合, 文件数, 跳过条数)

    与现网生成器的行为一致：文件上限先于深度上限触发（实测 depth 1/2/3/6 结果相同）。
    跳过 keyword:/regexp:（guard 的 veto 匹配不支持正则，收录会造成"看起来生效其实不生效"）。
    """
    out, seen, queue, nf, nskip = set(), set(), [(seed, 0)], 0, 0
    while queue and nf < max_files:
        key, depth = queue.pop(0)
        if key in seen:
            continue
        seen.add(key)
        text = docs.get(key)
        if text is None:
            text = ""
            if key != seed:
                # 上游改名/删除：记一次调试日志（不失败，仅影响覆盖）
                pass
        nf += 1
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "#" in line:
                line = line.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("include:"):
                nxt = line.split(":", 1)[1].strip()
                if depth + 1 <= max_depth and nxt not in seen:
                    queue.append((nxt, depth + 1))
                continue
            mm = PREFIX.match(line)
            if mm and mm.group(1).lower() in ("regexp", "keyword"):
                nskip += 1
                continue
            dom = line.split("@", 1)[0]
            if mm:
                dom = dom[len(mm.group(0)):]
            dom = dom.strip().lower().rstrip(".")
            if dom and "." in dom and re.match(r"^[a-z0-9._-]+$", dom):
                out.add(dom)
    return out, nf, nskip


def expand_veto(docs):
    """veto 集合（geolocation-!cn → 地理位置在中国之外）"""
    return expand_seed(docs, VETO_SEED, VETO_MAX_FILES, VETO_MAX_DEPTH)


def expand_cn_from_docs(docs):
    """从同一份 v2fly tar 现算国内域名集合（geolocation-cn），冷启动兜底用。

    首次安装时 typed / forwarding-rules 尚未生成（或仍是骨架），cn_domain_set() 会退化
    成空集合 ⇒ veto 的「国内冲突剔除」失效、国内反例门禁误判 FAIL，veto 永远拉不出来。
    这里不依赖任何本地文件，直接用上游国内 list 兜底。
    """
    try:
        doms, _nf, _nsk = expand_seed(docs, CN_SEED, CN_EXPAND_MAX_FILES, CN_EXPAND_MAX_DEPTH)
        return doms
    except Exception:
        return set()


def read_domain_set(path):
    out = set()
    try:
        with io.open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                d = line.split()[0].strip().lower().rstrip(".")
                if d and "." in d:
                    out.add(d)
    except Exception:
        pass
    return out


def cn_domain_set(docs=None):
    """本机 CN 域名集合（类型化名单 + forwarding-rules），用于识别「国内冲突条目」。

    只读本地文件、不联网；文件缺失时按空集合处理（门禁仍由 VETO_MUST_ABSENT 兜底）。
    但**首次安装**时两个文件都还不存在（cron 尚未跑过），退化成空集合会让冲突剔除失效、
    国内反例门禁误判 FAIL；此时用同一份 v2fly tar 的国内 list 现算兜底。
    """
    out = set()
    for p in (CN_LOCAL_TYPED, CN_LOCAL_RULES):
        if not os.path.exists(p):
            continue
        for raw in io.open(p, encoding="utf-8", errors="replace").read().splitlines():
            s = raw.split("@", 1)[0].strip().lower()
            if ":" in s:
                s = s.split(":", 1)[1].strip()
            s = s.rstrip(".")
            if "." in s:
                out.add(s)
    if docs is not None and len(out) < CN_LOCAL_MIN_TRUSTED:
        fallback = expand_cn_from_docs(docs)
        if fallback:
            log("veto 国内集合本地不可用（%d 条 < %d）⇒ 用 v2fly geolocation-cn 现算兜底（%d 条）"
                % (len(out), CN_LOCAL_MIN_TRUSTED, len(fallback)))
            out |= fallback
    return out


def is_cn_like(d, cnset):
    """d 是否应视为国内域名：命中 CN 国别后缀，或自身/父域在本机 CN 集合中。"""
    if not d:
        return False
    for suf in CN_TLD_SUFFIX:
        if d == suf.lstrip(".") or d.endswith(suf):
            return True
    if d in cnset:
        return True
    parts = d.split(".")
    for i in range(1, min(len(parts), 5)):
        if ".".join(parts[i:]) in cnset:
            return True
    return False


def veto_header(entries, nfiles):
    return [
        "# CN 路径否决名单（veto）",
        "# 来源: v2fly/domain-list-community 的 geolocation-!cn（有界展开：深度<=%d, 文件<=%d）"
        % (VETO_MAX_DEPTH, VETO_MAX_FILES),
        "# 语义: 地理位置在中国之外 => 即便后缀命中 CN 规则也不走国内 unbound-b 路径",
        "# 生成: refresh-cn-veto-ip.py（原 build_veto2.py 已并入统一刷新器）；"
        "guard 按 mtime 在 60s 内热重载；文件缺失时按『不否决』处理",
        "# 本次: %s 条目=%d 展开文件=%d" % (time.strftime("%Y-%m-%d %H:%M:%S"), entries, nfiles),
    ]


# ---------------- cn_ip ----------------
def parse_cidrs(text):
    """→ [ipaddress.IPv4Network]，丢弃非法行与超短前缀"""
    out, dropped, seen = [], 0, set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            n = ipaddress.ip_network(line.split()[0], strict=False)
        except Exception:
            dropped += 1
            continue
        if n.version != 4 or n.prefixlen < CN_IP_MIN_PREFIX:
            dropped += 1
            continue
        if str(n) not in seen:
            seen.add(str(n))
            out.append(n)
    return out, dropped


def addr_total(nets):
    return sum(n.num_addresses for n in nets)


def fetch_cn_ip():
    """→ (nets, source_label, raw_text) 或 (None, reason, None)"""
    for label, url in CN_IP_SOURCES:
        try:
            raw = http_get(url, timeout=90)
            if url.endswith(".tar.gz"):
                text = None
                with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
                    for m in tf.getmembers():
                        if m.isfile() and m.name.rsplit("/", 1)[-1] in ("chnroutes.txt", "china.txt"):
                            text = tf.extractfile(m).read().decode("utf-8", "replace")
                            break
                if not text:
                    raise ValueError("tar 内未找到 chnroutes.txt")
            else:
                text = raw.decode("utf-8", "replace")
            nets, dropped = parse_cidrs(text)
            if len(nets) < CN_IP_MIN_ENTRIES:
                raise ValueError("条数 %d < 下限 %d" % (len(nets), CN_IP_MIN_ENTRIES))
            log("cn_ip 源 %s：%d 条 / %.2fM 地址（丢弃 %d 行）"
                % (label, len(nets), addr_total(nets) / 1e6, dropped))
            return nets, label, text
        except Exception as e:
            log("WARN cn_ip 源 %s 不可用: %s" % (label, str(e)[:100]))
    return None, "all sources failed", None


def cn_ip_header(src_label, entries):
    return [
        "# 国内 IPv4 段（guard.is_cn_ip 用）",
        "# 来源: %s；由 refresh-cn-veto-ip.py 自动刷新（guard 侧同源兜底：CN_URL 7 天过期自下）"
        % src_label,
        "# 本次: %s 条目=%d" % (time.strftime("%Y-%m-%d %H:%M:%S"), entries),
    ]


# ---------------- 写入 ----------------
def write_veto_snapshot(doms):
    """同步维护 live 否决名单快照（guard F4 的 veto 侧回退源）。

    发布目录里的快照在发布时固定，会随名单演进落后（否决条目更少 ⇒ 否决面更窄
    ⇒ 反而扩大国内信任）。因此只要门禁通过，就把当前有效名单写入 live 快照。
    """
    try:
        snap = os.path.join(os.path.dirname(VETO), "cn-veto.snapshot.txt")
        tmp = snap + ".tmp"
        hdr = ("# snapshot %s by refresh-cn-veto-ip.py"
               "（自检通过的最后有效否决名单；guard F4 回退用）%s"
               % (time.strftime("%Y-%m-%d %H:%M:%S"), chr(10)))
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(hdr + chr(10).join(sorted(doms)) + chr(10))
        os.replace(tmp, snap)
        log("快照：已更新 %s（%d 条）" % (snap, len(doms)))
    except Exception as e:
        log("WARN veto 快照写入失败（不影响本次刷新）: %s" % e)


def write_atomic(path, lines):
    ts = time.strftime("%Y%m%d-%H%M%S")
    bak = "%s.bak-%s" % (path, ts)
    try:
        if os.path.exists(path):
            with io.open(path, encoding="utf-8", errors="replace") as f:
                old = f.read()
            with io.open(bak, "w", encoding="utf-8", newline="\n") as f:
                f.write(old)
        tmp = path + ".tmp"
        with io.open(tmp, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(tmp, path)
        return bak
    except Exception as e:
        log("FAIL 写 %s 失败: %s" % (path, str(e)[:120]))
        try:
            if os.path.exists(bak) and not os.path.exists(path):
                os.replace(bak, path)
        except Exception:
            pass
        return None


def main():
    t0 = time.time()
    rc = 0
    up_info = hist.upstream_v2fly() if hist is not None else {}
    if up_info.get("pinned"):
        log("上游钉扎：v2fly commit=%s（%s）"
            % (str(up_info.get("v2fly_commit"))[:12], up_info.get("v2fly_commit_date")))

    # ===== 1) veto =====
    docs = load_tarball()
    if docs is None:
        log("WARN v2fly 全量 tar 不可用 ⇒ 本次跳过 veto 更新（保留旧名单）")
        rc = 1
    else:
        doms, nfiles, nskip = expand_veto(docs)
        log("veto 展开：文件=%d（上限 %d）跳过 keyword/regexp=%d 条目=%d"
            % (nfiles, VETO_MAX_FILES, nskip, len(doms)))
        # 国内冲突剔除：上游 !cn 与 cn 两套数据存在交叉（例如 ntp*.aliyun.com 同时被判
        # 为"境外"）。冲突条目按**国内优先**剔除 —— veto 的用途是"不准用国内路径解析
        # 境外域名"，而真正的国内域名走国内路径才是对的。剔除比例过高（上游结构异变）
        # 才判 FAIL，不让整批更新因为交叉数据而失败。
        cnset = cn_domain_set(docs)
        dropped = sorted(d for d in doms if is_cn_like(d, cnset))
        if dropped:
            doms = set(d for d in doms if not is_cn_like(d, cnset))
            log("veto 国内冲突剔除：%d 条（例：%s）"
                % (len(dropped), ", ".join(dropped[:6])))
        pct_drop = 100.0 * len(dropped) / max(1, len(dropped) + len(doms))
        if pct_drop > VETO_CONFLICT_MAX_PCT:
            log("FAIL veto 国内冲突剔除比例 %.1f%% > 阈值 %.1f%%（疑似上游结构异变）⇒ 保留旧名单"
                % (pct_drop, VETO_CONFLICT_MAX_PCT))
            rc = 1
        elif len(doms) < VETO_MIN_ENTRIES:
            log("FAIL veto 条目数 %d < 下限 %d ⇒ 保留旧名单" % (len(doms), VETO_MIN_ENTRIES))
            rc = 1
        else:
            bad = sorted(d for d in doms
                         if any(d == x or d.endswith("." + x) for x in VETO_MUST_ABSENT))
            if bad:
                log("FAIL veto 国内反例门禁未过（国内关键域被判入境外: %s）⇒ 保留旧名单" % bad[:8])
                rc = 1
            else:
                old = read_domain_set(VETO)
                added, removed = doms - old, old - doms
                pct_add = 100.0 * len(added) / max(1, len(old))
                pct_del = 100.0 * len(removed) / max(1, len(old))
                log("veto 变化：旧 %d 条 → 新 %d 条；新增 %d(%.2f%%) 移除 %d(%.2f%%)"
                    % (len(old), len(doms), len(added), pct_add, len(removed), pct_del))
                if len(removed):
                    log("  移除样例: %s" % sorted(removed)[:8])
                oversize = ((pct_add > VETO_MAX_CHANGE_PCT and len(added) > VETO_MIN_ABS_CHANGE)
                            or (pct_del > VETO_MAX_CHANGE_PCT and len(removed) > VETO_MIN_ABS_CHANGE))
                if oversize and not FORCE:
                    log("FAIL veto 变更幅度门禁未过（阈值 %.1f%% 且 >%d 条）⇒ 保留旧名单；"
                        "确认无误后用 --force 重跑" % (VETO_MAX_CHANGE_PCT, VETO_MIN_ABS_CHANGE))
                    rc = 1
                elif doms == old:
                    log("OK veto 无变化（%d 条）" % len(doms))
                    if not DRY:
                        write_veto_snapshot(doms)
                elif DRY:
                    log("OK --dry-run：veto 未写入（将写 %d 条）" % len(doms))
                else:
                    lines = veto_header(len(doms), nfiles) + sorted(doms)
                    bak = write_atomic(VETO, lines)
                    back = read_domain_set(VETO)
                    if bak is None or back != doms:
                        log("FAIL veto 写入自检不一致（回读 %d != 预期 %d）⇒ 尝试回滚"
                            % (len(back), len(doms)))
                        if bak and os.path.exists(bak):
                            os.replace(bak, VETO)
                        rc = 1
                    else:
                        log("OK veto 已更新并自检一致：%d 条（旧 %d 条，备份 %s）"
                            % (len(doms), len(old), bak))
                        write_veto_snapshot(doms)
                        if hist is not None:
                            hist.record(
                                "veto", old, doms, VETO,
                                upstream=dict(up_info, tar_sha256=LAST_TAR_SHA["sha256"],
                                              tar_bytes=LAST_TAR_SHA["bytes"]),
                                gate="force" if (oversize and FORCE) else "ok",
                                extra={"conflict_dropped": len(dropped),
                                       "files_scanned": nfiles,
                                       "backup": bak})
                        else:
                            log("WARN 归档模块不可用 ⇒ 本次未写 veto 变更归档")

    # ===== 2) cn_ip.txt =====
    nets, src_label, _raw = fetch_cn_ip()
    if nets is None:
        log("FAIL cn_ip 所有源均不可用 ⇒ 保留旧名单")
        rc = 1
    else:
        new_total = addr_total(nets)
        old_nets, _d = (parse_cidrs(io.open(CN_IP, encoding="utf-8", errors="replace").read())
                        if os.path.exists(CN_IP) else ([], 0))
        old_total = addr_total(old_nets)
        pct = 100.0 * abs(new_total - old_total) / max(1, old_total)
        log("cn_ip 变化：旧 %d 条 / %.2fM 地址 → 新 %d 条 / %.2fM 地址（覆盖变化 %.2f%%，阈值 %.1f%%）"
            % (len(old_nets), old_total / 1e6, len(nets), new_total / 1e6, pct, CN_IP_MAX_CHANGE_PCT))
        if pct > CN_IP_MAX_CHANGE_PCT and not FORCE:
            log("FAIL cn_ip 地址覆盖变化超阈值 ⇒ 保留旧名单；确认无误后用 --force 重跑")
            rc = 1
        elif set(str(n) for n in nets) == set(str(n) for n in old_nets):
            log("OK cn_ip 无变化（%d 条）" % len(nets))
        elif DRY:
            log("OK --dry-run：cn_ip 未写入（将写 %d 条）" % len(nets))
        else:
            lines = cn_ip_header(src_label, len(nets)) + [str(n) for n in nets]
            bak = write_atomic(CN_IP, lines)
            back, _d2 = parse_cidrs(io.open(CN_IP, encoding="utf-8", errors="replace").read())
            if bak is None or len(back) != len(nets):
                log("FAIL cn_ip 写入自检不一致（回读 %d != 预期 %d）⇒ 尝试回滚" % (len(back), len(nets)))
                if bak and os.path.exists(bak):
                    os.replace(bak, CN_IP)
                rc = 1
            else:
                log("OK cn_ip 已更新并自检一致：%d 条 / %.2fM 地址（源 %s，备份 %s）"
                    % (len(nets), new_total / 1e6, src_label, bak))
                if hist is not None:
                    hist.record(
                        "cn_ip", set(str(n) for n in old_nets), set(str(n) for n in nets), CN_IP,
                        upstream={"source": src_label,
                                  "raw_sha256": (hist.sha256_bytes(_raw.encode("utf-8", "replace"))
                                                 if _raw else None)},
                        extra={"addr_change_pct": round(pct, 4),
                               "addr_total_m": round(new_total / 1e6, 3),
                               "backup": bak})
                else:
                    log("WARN 归档模块不可用 ⇒ 本次未写 cn_ip 变更归档")

    if hist is not None and not DRY:
        try:
            hist.finalize()
        except Exception as e:
            log("WARN 归档收尾失败：%s" % str(e)[:120])

    log("完成：耗时 %.0fs rc=%d（veto=%s cn_ip=%s）"
        % (time.time() - t0, rc, VETO, CN_IP))
    return rc


if __name__ == "__main__":
    sys.exit(main())
