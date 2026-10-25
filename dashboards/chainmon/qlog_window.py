#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AGH 查询日志：**增量取数 + 滚动累积**（QLOG-INCR v1）

## 为什么需要它
看板折线来自**落盘的 HISTORY**（逐轮标量），与"单轮取数覆盖多少分钟"无关；
而现行实现为了算"最近 1 小时的分位 / 唯一域名 / top-N"，**每 60 秒把同一小时的数据整包
重拉、重聚合一次**。实测（2026-10-09）：
  · 1 小时窗口约 2,700–2,900 条（45–48 条/分钟）
  · **单轮真正新增只有约 27–48 条**
  · limit=6000 ⇒ 实拉约 2.2 小时数据、3.1MB/轮、解码 4.6s
  ⇒ 按条数冗余 12–20×，按"重复计算次数"冗余约 60×（一小时里把同一批数据算了 60 遍）。
  · 每轮"分配 8.3MB 文本 + 上万条解码对象再释放"还会把 glibc arena 高水位顶高
    （实测 AGH_API_LIMIT=16000 时服务稳态 231MB；6000 时 63–76MB）。

## 本模块怎么做
每轮只取**新增的那几十条**（limit 自适应，含断档回补），把窗口内记录按
**（时间戳, 同秒序数）** 去重后滚动保留最近 `window_s + pad_s` 秒（约 3,000 条微小元组，
常驻 ≤1MB），每轮在**本地**重算窗口聚合。

输出契约与 `chainmon.collect_agh_querylog()` **逐字段一致**（同字段名、同口径、同分位算法），
因此调用方（overview/HISTORY/前端）无需任何改动。

## 与全量口径的两处**有意差异**（调用方需知）
1. `ts_min/ts_max/covered_min`：全量版是"本次整批取数"的跨度（诊断用）；增量版是
   **滚动窗口内**的跨度。语义都是"我们手上数据的时间跨度"，仍然自洽。
2. `log_source`：全量版为 `api`/`file`；增量版为 `api+incr`。

## 去重规则（关键）
AGH 的 `/control/querylog` 按**时间倒序**返回、追加写因而同秒内顺序稳定。因此：
  · 若 `ep > max_ep` ⇒ 新记录，收下；
  · 若 `ep == max_ep` ⇒ 跳过前 `count_at_max` 条（上一轮已收的同秒记录），其后的才算新增；
  · 若 `ep < max_ep` ⇒ 后续都更旧，停止。
断档回补：`needed_limit()` 按实测速率 × 断档时长 × 2 + 基数，上限 `cap`；若仍覆盖不到
窗口起点，则如实反映在 `window_covered_min`/`window_truncated`（调用方判定）上，不伪造。
"""

import calendar
import io
import json
import os
import time

# 与 chainmon 同口径的字段（只需要这些，其余不保留以省内存）
FIELDS = ("QH", "QT", "IP", "Upstream", "Cached", "Elapsed")


def _ep(ts):
    """AGH 时间戳 → epoch 秒（取前 19 字符，与 chainmon._agh_ts 完全一致）。"""
    try:
        return calendar.timegm(time.strptime((ts or "")[:19], "%Y-%m-%dT%H:%M:%S"))
    except Exception:
        return None


def _pct(vals, p):
    """与 chainmon.pct 逐字等价：先排序；偶数样本的 p50 取中间两值平均；其余最近秩。"""
    if not vals:
        return 0.0
    v = sorted(vals)
    n = len(v)
    if p == 0.5 and n % 2 == 0:
        return (v[n // 2 - 1] + v[n // 2]) / 2.0
    return v[int(round((n - 1) * p))]


class QlogWindow(object):
    def __init__(self, path=None, window_s=3600, pad_s=900, max_records=60000,
                 save_min_interval_s=300):
        self.path = path
        self.window_s = int(window_s)
        self.pad_s = int(pad_s)
        self.max_records = int(max_records)
        # 2026-10-09：落盘节流。原来每轮都整份重写窗口（约 4,000 条 / ~470KB JSON），
        # 属"每轮固定的大块分配"，会把 glibc arena 高水位一点点顶高（实测采集器斜率 +0.46MB/轮）。
        # 窗口自带 pad_s=900s 余量，最多丢 5 分钟最旧数据不影响 1 小时窗口，故 300s 一存足够。
        self.save_min_interval_s = int(save_min_interval_s)
        self._last_save = 0.0
        # recs: [(ep, ts_str, qh, qt, ip, up, cached, ms)]，按 ep 递增
        self.recs = []
        self.max_ep = 0
        self.count_at_max = 0          # 上一轮以 max_ep 结尾的同秒记录条数（去重用）
        self.ingest_rounds = 0
        self.last_new = 0
        self.last_limit = 0
        self.last_reached = True       # 上一轮批次是否够到水位（False = 需放大 limit 重取）
        self.dropped = 0
        self.loaded_from = None

    # ---------------- 持久化 ----------------
    def load(self):
        if not self.path or not os.path.exists(self.path):
            return False
        try:
            with io.open(self.path, "r", encoding="utf-8") as f:
                d = json.load(f)
            self.recs = [(int(r[0]), r[1], r[2], r[3], r[4], r[5],
                          bool(r[6]), float(r[7])) for r in (d.get("recs") or [])]
            self.max_ep = int(d.get("max_ep") or 0)
            self.count_at_max = int(d.get("count_at_max") or 0)
            self.ingest_rounds = int(d.get("rounds") or 0)
            self.loaded_from = d.get("saved_at")
            return True
        except Exception:
            # 损坏就当空窗重来（宁可少样本，也不要抛异常拖垮采集）
            self.recs = []
            self.max_ep = 0
            self.count_at_max = 0
            return False

    def save(self, force=False):
        if not self.path:
            return False
        # 节流：默认最多每 save_min_interval_s 秒落一次（避免每轮重写 470KB 的大块分配）
        now = time.time()
        if (not force) and self.save_min_interval_s and (now - self._last_save) < self.save_min_interval_s:
            return False
        try:
            tmp = self.path + ".tmp"
            with io.open(tmp, "w", encoding="utf-8") as f:
                json.dump({"v": 1, "window_s": self.window_s, "max_ep": self.max_ep,
                           "count_at_max": self.count_at_max, "rounds": self.ingest_rounds,
                           "saved_at": int(now), "recs": self.recs}, f,
                          ensure_ascii=False, separators=(",", ":"))
            os.replace(tmp, self.path)
            self._last_save = now
            return True
        except Exception:
            return False

    # ---------------- 取数规模 ----------------
    def rate_per_min(self, default=60.0):
        """用窗口内记录数估算到达速率（条/分钟）；样本不足时给保守默认。"""
        if not self.recs or len(self.recs) < 2:
            return default
        span_min = max(1.0, (self.recs[-1][0] - self.recs[0][0]) / 60.0)
        return max(1.0, len(self.recs) / span_min)

    def needed_limit(self, gap_s, base=200, cap=8000):
        """覆盖 `gap_s` 秒的新增所需条数（含 2 倍余量），并给出基数与上限保护。

        基数 200 只是"低流量下限"；真正的安全网是 `ingest()` 的 `last_reached`——
        一旦发现批次够不到水位（突发把 limit 撑爆），调用方必须放大 limit 重取，
        否则那批记录会**永久丢失**（下一轮只会返回更新的 limit 条）。
        """
        r = self.rate_per_min()
        need = int(r * (max(0.0, float(gap_s)) / 60.0) * 2.0) + int(base)
        self.last_limit = min(int(cap), max(int(base), need))
        return self.last_limit

    # ---------------- 写入（去重 + 剪枝） ----------------
    def ingest(self, records):
        """`records`：AGH 返回顺序（时间倒序）的 dict 可迭代对象。返回新增条数。

        只保留契约需要的字段；`Elapsed` 统一换算为**毫秒**（AGH API 为 elapsedMs）。

        同时维护 `last_reached`：**批次是否够到了上一轮水位**。
        · True  = 遇到了 <= 水位的旧记录 ⇒ 中间没有缺口；
        · False = 整批都比水位新 ⇒ 可能被 limit 截断 ⇒ 调用方**必须放大 limit 重取**。
        """
        new = []
        same_skipped = 0
        reached = False
        for e in records:
            ep = _ep(e.get("T"))
            if ep is None:
                continue
            if ep > self.max_ep:
                new.append(self._row(e, ep))
                continue
            if ep == self.max_ep and same_skipped < self.count_at_max:
                same_skipped += 1          # 上一轮已收的同秒记录
                reached = True
                continue
            reached = True                 # 更旧（或同秒多出来）的边界 ⇒ 已接上水位
            break
        self.last_reached = bool(reached) or (self.max_ep == 0 and bool(new))
        if not new:
            self.last_new = 0
            return 0
        # 倒序收下的 new 反过来，保证 recs 按 ep 递增
        new.reverse()
        self.recs.extend(new)
        if new:
            last_ep = new[-1][0]
            if last_ep > self.max_ep:
                self.max_ep = last_ep
                self.count_at_max = sum(1 for r in new if r[0] == last_ep)
            else:
                self.count_at_max += sum(1 for r in new if r[0] == self.max_ep)
        self.last_new = len(new)
        self.ingest_rounds += 1
        self._prune()
        return len(new)

    def _row(self, e, ep):
        ms = float(e.get("Elapsed") or 0) / 1000000.0   # AGH API: elapsedMs(微秒)
        return (ep, e.get("T") or "", e.get("QH") or "", e.get("QT") or "?",
                e.get("IP") or "", e.get("Upstream") or "", bool(e.get("Cached", False)), ms)

    def _prune(self):
        if not self.recs:
            return
        cut = self.max_ep - self.window_s - self.pad_s
        i = 0
        n = len(self.recs)
        while i < n and self.recs[i][0] < cut:
            i += 1
        if i:
            self.recs = self.recs[i:]
            self.dropped += i
        if len(self.recs) > self.max_records:          # 兜底上限（异常流量保护）
            over = len(self.recs) - self.max_records
            self.recs = self.recs[over:]
            self.dropped += over

    # ---------------- 聚合（与 collect_agh_querylog 同契约） ----------------
    def aggregate(self, probe_names=(), probe_src=(), probe_clients=(), hot_name=None,
                  window_min=60, now=None, source="api+incr"):
        now = time.time() if now is None else now
        anchor = self.max_ep or int(now)
        win_start = anchor - int(window_min) * 60
        out = {
            "queries": 0, "blocked": 0, "allowed": 0,
            "queries_1m": 0,
            "cache_hits": 0, "cache_misses": 0,
            "upstreams": {}, "clients": {}, "slow": [], "slow_total": 0, "types": {},
            "hosts": set(),
            "elapsed_all": [], "elapsed_up": [],
            # ★ 2026-10-22 归因：同一批上游样本按客户端/域名各存一份
            "el_up_by_client": {}, "el_up_by_host": {},
            "window_start": win_start, "ts_min": None, "ts_max": None,
            "win_ts_min": None, "win_ts_max": None,
            "log_lag_s": max(0, int(now - anchor)),
            "window_anchor": anchor,
            "log_source": source, "log_source_error": "",
            "probe_queries": 0, "probe_queries_by_ip_legacy": 0, "probe_hot_not_excluded": 0,
            "probe_split": {"queries": 0, "blocked": 0, "allowed": 0, "cache_hits": 0,
                            "cache_misses": 0, "hosts": set(), "by_ip": {}},
        }
        _pnames = probe_names or ()
        p1m = anchor - 60
        for (ep, ts, qh, qt, ip, up, cached, ms) in self.recs:
            if out["ts_min"] is None or ep < out["ts_min"]:
                out["ts_min"] = ep
            if out["ts_max"] is None or ep > out["ts_max"]:
                out["ts_max"] = ep
            if ep < win_start:
                continue
            if out["win_ts_min"] is None or ep < out["win_ts_min"]:
                out["win_ts_min"] = ep
            if out["win_ts_max"] is None or ep > out["win_ts_max"]:
                out["win_ts_max"] = ep
            _is_probe = ((bool(qh) and qh in _pnames) or (bool(ip) and ip in probe_src))
            if _is_probe:
                ps = out["probe_split"]
                ps["queries"] += 1
                ps["by_ip"][ip] = ps["by_ip"].get(ip, 0) + 1
                if qh:
                    ps["hosts"].add(qh)
                if not up:
                    ps["blocked"] += 1
                else:
                    ps["allowed"] += 1
                    if cached:
                        ps["cache_hits"] += 1
                    else:
                        ps["cache_misses"] += 1
                if qh and qh in _pnames:
                    out["probe_queries"] += 1
                else:
                    out["probe_queries_by_src"] = out.get("probe_queries_by_src", 0) + 1
                if ip in probe_clients:
                    out["probe_queries_by_ip_legacy"] += 1
                continue
            if ip in probe_clients:
                out["probe_queries_by_ip_legacy"] += 1
            if hot_name and qh == hot_name:
                out["probe_hot_not_excluded"] += 1
            out["queries"] += 1
            out["hosts"].add(qh)
            if ep >= p1m:
                out["queries_1m"] += 1
            out["elapsed_all"].append(ms)
            if not up:
                out["blocked"] += 1
                continue
            out["allowed"] += 1
            if cached:
                out["cache_hits"] += 1
            else:
                out["cache_misses"] += 1
                out["elapsed_up"].append(ms)
                out["el_up_by_client"].setdefault(ip or "?", []).append(ms)
                out["el_up_by_host"].setdefault(qh or "?", []).append(ms)
                if ms > 500:
                    out["slow_total"] += 1
                    out["slow"].append({"host": qh, "ms": round(ms, 1), "type": qt,
                                        "cached": False, "upstream": up, "t": ts})
            st = out["upstreams"].setdefault(up, {"addr": up, "count": 0, "cached": 0, "miss": 0})
            st["count"] += 1
            st["cached" if cached else "miss"] += 1
            if ip:
                out["clients"][ip] = out["clients"].get(ip, 0) + 1
            tt = out["types"].setdefault(qt, {"type": qt, "count": 0, "elapsed": []})
            tt["count"] += 1
            if not cached:
                tt["elapsed"].append(ms)

        out["slow"] = sorted(out["slow"], key=lambda x: -x["ms"])[:15]
        out["covered_min"] = (round((out["ts_max"] - out["ts_min"]) / 60.0, 1)
                              if out["ts_min"] and out["ts_max"] else 0.0)
        out["window_covered_min"] = (round((out["win_ts_max"] - out["win_ts_min"]) / 60.0, 1)
                                     if out["win_ts_min"] and out["win_ts_max"] else 0.0)
        out["top_upstreams"] = sorted(out["upstreams"].values(), key=lambda x: -x["count"])
        out["top_clients"] = [{"ip": k, "queries": v} for k, v in
                              sorted(out["clients"].items(), key=lambda kv: -kv[1])[:8]]
        out["by_type"] = []
        for t in sorted(out["types"].values(), key=lambda x: -x["count"]):
            out["by_type"].append({"type": t["type"], "count": t["count"],
                                   "p90_ms": round(_pct(t["elapsed"], 0.9), 2)})
        return out

    def stats(self):
        return {"recs": len(self.recs), "max_ep": self.max_ep, "count_at_max": self.count_at_max,
                "rounds": self.ingest_rounds, "last_new": self.last_new,
                "last_limit": self.last_limit, "dropped": self.dropped,
                "rate_per_min": round(self.rate_per_min(), 1),
                "span_min": round((self.recs[-1][0] - self.recs[0][0]) / 60.0, 1) if self.recs else 0.0}


# 影子对照：把增量结果与全量结果的关键字段逐项比对，返回差异列表（供日志/审计）
SHADOW_KEYS = ("queries", "blocked", "allowed", "cache_hits", "cache_misses", "queries_1m",
               "slow_total", "probe_queries", "probe_hot_not_excluded", "win_ts_min", "win_ts_max")
SHADOW_NUM_TOL = {"queries": 0.02, "blocked": 0.02, "allowed": 0.02, "cache_hits": 0.02,
                  "cache_misses": 0.02, "queries_1m": 0.05, "slow_total": 0.05}


def shadow_diff(full, incr):
    """返回 [(字段, 全量, 增量, 相对偏差, 是否超容差)]；用于切换前的证据积累。"""
    rows = []
    for k in SHADOW_KEYS:
        a, b = full.get(k), incr.get(k)
        if a is None or b is None:
            rel = None
        else:
            base = float(a) if a else 1.0
            rel = abs(float(b) - float(a)) / base
        tol = SHADOW_NUM_TOL.get(k)
        bad = bool(tol is not None and rel is not None and rel > tol)
        rows.append((k, a, b, rel, bad))
    a, b = len(full.get("hosts") or ()), len(incr.get("hosts") or ())
    rel = abs(b - a) / float(a or 1)
    rows.append(("hosts(uniq)", a, b, rel, rel > 0.05))
    a, b = len(full.get("elapsed_all") or []), len(incr.get("elapsed_all") or [])
    rel = abs(b - a) / float(a or 1)
    rows.append(("elapsed_all(n)", a, b, rel, rel > 0.02))
    return rows
