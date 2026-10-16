# -*- coding: utf-8 -*-
"""chainmon 自检资源探针（只读；Python 3.6 兼容）。

接口：collect_self_resources(pid=None) -> dict
  - 默认探测当前进程（/proc/self）。
  - 不启动 HTTP、不启动后台线程、不做生产采集（无 write 到生产快照）。
  - 只做：/proc 读取 + cgroup 读取 + 每 5 分钟一次增量 journalctl（仅在内核日志中找 OOM 事件）。

契约要点（方案 §Task7）：
  * missing 不是 0：读不到一律 None，并附错误原因；绝不把缺失值输出成 0。
  * 重启 / PID / boot_id / cgroup 路径变化 → 重置 delta（不重置历史事件游标）。
  * failcnt 上涨 ≠ OOM：v1 的 failcnt 与 v2 的 oom_kill 分开呈现，语义字段显式说明。
  * OOM 事件按 journal cursor 去重，增量读取，不重复累计 10 分钟窗口。
  * API 侧只应读取已有缓存：collect_self_resources 不接受 force 以外的方式刷新 journal；
    浏览器刷新不会导致 fork journalctl（refresh_journal_events 内部按 300s 节流并加锁）。
"""

from __future__ import division, print_function

import errno
import hashlib
import json
import os
import re
import stat as stat_mod
import subprocess
import sys
import threading
import time

__all__ = [
    "collect_self_resources",
    "refresh_journal_events",
    "Collector",
    "DEFAULT_STATE_FILE",
    "JOURNAL_REFRESH_SEC",
    "SMAPS_SUMMARY_MIN_SEC",
]

VERSION = "1.0.0"

# ---------------------------------------------------------------- tunables
CGROUP_V1_MOUNT = "/sys/fs/cgroup/memory"
CGROUP_V2_MOUNT = "/sys/fs/cgroup"
JOURNAL_REFRESH_SEC = 300          # OOM 原因：每 5 分钟增量一次
SMAPS_SUMMARY_MIN_SEC = 60         # smaps_rollup 缺失时，最多每 60 秒汇总一次 smaps
JOURNAL_CURSOR_FILE = "/opt/chainmon/.resource_probe_journal_cursor"
# 演习/旁路用：让同一份模块在两个进程里各写各的状态，绝不互相污染。
#   CHAINMON_PROBE_STATE_FILE        -> delta/journal 状态文件
#   CHAINMON_PROBE_JOURNAL_CURSOR    -> journal cursor 文件
_ENV_STATE = "CHAINMON_PROBE_STATE_FILE"
_ENV_CURSOR = "CHAINMON_PROBE_JOURNAL_CURSOR"
JOURNAL_MAX_EVENTS = 50            # 状态文件里保留的 OOM 事件上限
JOURNAL_MAX_LINES = 400            # 单次 journalctl 读取的最大行数
JOURNALCTL_TIMEOUT = 20            # 秒
PROC_MOUNTS = "/proc/mounts"

# failcnt 上涨的原因不唯一，显式写清语义，避免误读成 OOM。
FAILCNT_MEANING_V1 = ("memory.failcnt 是 memory cgroup v1 的计数器：每次“访问内存因命中 "
                      "memory.limit_in_bytes/memsw 限制而被拒绝并触发回收/换出”都会 +1，"
                      "包含被成功回收后继续执行的场景。上涨 ≠ 发生 OOM。")
OOM_KILL_MEANING_V2 = ("memory.events 的 oom 是进入 OOM 状态的次数，oom_kill 是实际被杀的次数；"
                       "只有 oom_kill 上涨才代表进程被杀。")
OOM_KILL_MEANING_V1 = "cgroup v1 无 oom_kill 计数器；被杀事件只能从内核日志的 OOM 事件判定。"

_OOM_MARKERS = ("Out of memory", "oom-kill", "oom_reaper", "Killed process",
                "Memory cgroup out of memory", "Out of Memory")


# ---------------------------------------------------------------- 基础 IO
def _io_open(path, mode="r"):
    """Python 3.6 安全的文本读取（不做编码归一化，内核文件可能是非 UTF-8）。"""
    return open(path, mode, encoding="utf-8", errors="replace")


def _read_text(path):
    """返回 (text, err)。读不到 -> (None, "原因")，绝不返回空串冒充 0。"""
    try:
        with _io_open(path, "r") as fh:
            return fh.read(), None
    except (IOError, OSError) as exc:
        return None, "%s: %s" % (type(exc).__name__, exc.strerror or str(exc))
    except Exception as exc:                                  # pragma: no cover
        return None, "%s: %s" % (type(exc).__name__, exc)


def _is_int(tok):
    if not tok:
        return False
    if tok[0] in "+-":
        tok = tok[1:]
    return tok.isdigit()


def _as_int(tok):
    if _is_int(tok):
        try:
            return int(tok)
        except ValueError:                                    # pragma: no cover
            return None
    return None


def _kv_int_line(text):
    """解析单行 "<key> <int>" / "<key>: <int>"：空行/非整数一律跳过，不补 0。"""
    if not text:
        return {}
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if ":" in line:
            parts = line.split(":", 1)
        else:
            parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        val = _as_int(parts[1].strip())
        if val is not None:
            out[parts[0].strip()] = val
    return out


def _abs_mount(root, mount, relpath):
    mount = mount.rstrip("/")
    if root:
        mount = os.path.join(root, mount.lstrip("/"))
    rel = (relpath or "/").strip()
    if not rel:
        rel = "/"
    if rel == "/":
        return mount
    return mount + "/" + rel.lstrip("/")


# ---------------------------------------------------------------- /proc
def _proc_status(proc_dir="/proc/self"):
    path = os.path.join(proc_dir, "status")
    text, err = _read_text(path)
    if text is None:
        return {"status_error": err,
                "rss_kb": None, "swap_kb": None, "threads": None}
    out = {"status_error": None, "rss_kb": None, "swap_kb": None, "threads": None}
    for line in text.splitlines():
        if line.startswith("VmRSS:"):
            out["rss_kb"] = _as_int(line.split(None, 1)[1].split()[0]) if len(line.split()) > 1 else None
        elif line.startswith("VmSwap:"):
            out["swap_kb"] = _as_int(line.split(None, 1)[1].split()[0]) if len(line.split()) > 1 else None
        elif line.startswith("Threads:"):
            out["threads"] = _as_int(line.split(None, 1)[1].split()[0]) if len(line.split()) > 1 else None
    return out


def _count_dir(path):
    try:
        n = 0
        with os.scandir(path) as it:
            for _ in it:
                n += 1
        return n, None
    except (IOError, OSError) as exc:
        return None, "%s: %s" % (type(exc).__name__, exc.strerror or str(exc))
    except AttributeError:                                    # pragma: no cover
        try:
            return len(os.listdir(path)), None
        except (IOError, OSError) as exc:
            return None, "%s: %s" % (type(exc).__name__, exc.strerror or str(exc))


def _proc_counts(proc_dir="/proc/self"):
    fds, fd_err = _count_dir(os.path.join(proc_dir, "fd"))
    tasks, task_err = _count_dir(os.path.join(proc_dir, "task"))
    return {"fds": fds, "fds_error": fd_err,
            "tasks": tasks, "tasks_error": task_err}


# ---------------------------------------------------------------- PSS
def _pss_from_rollup(proc_dir="/proc/self"):
    path = os.path.join(proc_dir, "smaps_rollup")
    text, err = _read_text(path)
    if text is None:
        return None, err
    pss = None
    for line in text.splitlines():
        if line.startswith("Pss:"):
            toks = line.split()
            if len(toks) >= 2:
                pss = _as_int(toks[1])
            break
    if pss is None:
        return None, "smaps_rollup 中无 Pss 行"
    return pss, None


def _pss_from_smaps(proc_dir="/proc/self"):
    """兜底：汇总 smaps 的 Pss。返回 (pss_kb, err)。"""
    path = os.path.join(proc_dir, "smaps")
    text, err = _read_text(path)
    if text is None:
        return None, err
    total = 0
    seen = False
    for line in text.splitlines():
        if line.startswith("Pss:"):
            toks = line.split()
            if len(toks) >= 2:
                v = _as_int(toks[1])
                if v is not None:
                    total += v
                    seen = True
    if not seen:
        return None, "smaps 中无 Pss 行"
    return total, None


# ---------------------------------------------------------------- cgroup
def _find_v1_memory_mount(root=None):
    """从 /proc/mounts 找 memory 控制器挂载点；找不到返回 None。

    注意：root 非空（夹具）时不回退到宿主的 /proc/mounts —— 否则夹具会借宿主的
    挂载表“通过”检测，得到假阳性。
    """
    path = os.path.join(root, PROC_MOUNTS.lstrip("/")) if root else PROC_MOUNTS
    text, _err = _read_text(path)
    if text:
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 4 or parts[2] != "cgroup":
                continue
            opts = parts[3].split(",")
            if "memory" in opts:
                return parts[1]
    if root is None and os.path.isdir(_abs_mount(None, CGROUP_V1_MOUNT, "/")):
        return CGROUP_V1_MOUNT
    return None


def _detect_cgroup_version(root=None):
    """(version, mount, err)。v2: 统一层级（含 cgroup.controllers / cgroup.controllers 文件）。"""
    v2_mount = _abs_mount(root, CGROUP_V2_MOUNT, "/")
    if os.path.exists(os.path.join(v2_mount, "cgroup.controllers")):
        return 2, CGROUP_V2_MOUNT, None
    v1_mount = _find_v1_memory_mount(root)
    if v1_mount:
        return 1, v1_mount, None
    return None, None, "未找到 cgroup v1 memory 挂载点，也不是 cgroup v2 统一层级"


def _cgroup_relpath(pid_dir):
    """解析 /proc/<pid>/cgroup，返回 (v1_memory_relpath, v2_relpath, raw_text_error)。"""
    text, err = _read_text(os.path.join(pid_dir, "cgroup"))
    if text is None:
        return None, None, err
    v1 = None
    v2 = None
    for line in text.splitlines():
        parts = line.rstrip("\n").split(":", 2)
        if len(parts) != 3:
            continue
        ctrls, path = parts[1], parts[2]
        if ctrls == "":
            v2 = path or "/"
        elif "memory" in ctrls.split(","):
            v1 = path or "/"
    return v1, v2, None


def _read_cgroup_files(cdir, names):
    out = {}
    errs = {}
    for name in names:
        text, err = _read_text(os.path.join(cdir, name))
        if text is None:
            errs[name] = err
        out[name] = text
    return out, errs


def _collect_cgroup_v1(cdir):
    files, errs = _read_cgroup_files(cdir, [
        "memory.usage_in_bytes", "memory.memsw.usage_in_bytes", "memory.failcnt",
        "memory.oom_control", "memory.stat", "memory.limit_in_bytes",
        "memory.soft_limit_in_bytes", "memory.max_usage_in_bytes",
    ])
    res = {
        "version": 1,
        "path": cdir,
        "usage_bytes": None,
        "memsw_usage_bytes": None,
        "failcnt": None,
        "oom_control": {},
        "memory_stat": {},
        "limit_bytes": None,
        "soft_limit_bytes": None,
        "max_usage_bytes": None,
        "errors": errs,
        "failcnt_meaning": FAILCNT_MEANING_V1,
        "oom_kill_counter": None,
        "oom_kill_meaning": OOM_KILL_MEANING_V1 + " 本版本的 OOM 事件见 journal_oom。",
    }
    for key, fname, target in (
        ("usage_bytes", "memory.usage_in_bytes", "int"),
        ("memsw_usage_bytes", "memory.memsw.usage_in_bytes", "int"),
        ("failcnt", "memory.failcnt", "int"),
        ("limit_bytes", "memory.limit_in_bytes", "int"),
        ("soft_limit_bytes", "memory.soft_limit_in_bytes", "int"),
        ("max_usage_bytes", "memory.max_usage_in_bytes", "int"),
    ):
        text = files.get(fname)
        if text is None:
            continue
        res[key] = _as_int(text.strip().splitlines()[0] if text.strip() else "")
        if res[key] is None:
            res["errors"][fname] = "值不是整数"
    text = files.get("memory.oom_control")
    if text is not None:
        parsed = _kv_int_line(text)
        if not parsed:
            res["errors"]["memory.oom_control"] = "无可用键值"
        res["oom_control"] = parsed
    text = files.get("memory.stat")
    if text is not None:
        res["memory_stat"] = _kv_int_line(text)
    return res


def _collect_cgroup_v2(cdir):
    files, errs = _read_cgroup_files(cdir, [
        "memory.current", "memory.swap.current", "memory.events",
        "memory.events.local", "memory.stat", "memory.max", "memory.high",
    ])
    res = {
        "version": 2,
        "path": cdir,
        "current_bytes": None,
        "swap_current_bytes": None,
        "events": {},
        "events_local": {},
        "memory_stat": {},
        "max": None,
        "high": None,
        "oom_kill": None,
        "errors": errs,
        "oom_kill_meaning": OOM_KILL_MEANING_V2,
        "failcnt": None,
        "failcnt_meaning": "cgroup v2 无 failcnt 计数器（v1 才有）；两者分开显示，不可互相替代。",
    }
    for key, fname in (("current_bytes", "memory.current"),
                       ("swap_current_bytes", "memory.swap.current")):
        text = files.get(fname)
        if text is None:
            continue
        res[key] = _as_int(text.strip())
        if res[key] is None:
            res["errors"][fname] = "值不是整数"
    for key, fname in (("max", "memory.max"), ("high", "memory.high")):
        text = files.get(fname)
        if text is None:
            continue
        tok = (text or "").strip()
        res[key] = _as_int(tok) if _is_int(tok) else (None if tok == "" else tok)
    ev = _kv_int_line(files.get("memory.events"))
    res["events"] = ev
    res["events_local"] = _kv_int_line(files.get("memory.events.local"))
    res["memory_stat"] = _kv_int_line(files.get("memory.stat"))
    res["oom_kill"] = ev.get("oom_kill")
    res["oom"] = ev.get("oom")
    if files.get("memory.events") is None:
        res["errors"]["memory.events"] = errs.get("memory.events", "读取失败")
    return res


def _cgroup_skeleton():
    """统一形状：无论 v1/v2/无法判定，键都在，取不到一律 None。

    否则“没有该字段”与“读到了但是 null”在消费端无法区分，容易被误当成 0。
    """
    return {
        "version": None,
        "mount": None,
        "detect_error": None,
        "path": None,
        "method": None,
        "cgroup_file_error": None,
        # v1
        "usage_bytes": None,
        "memsw_usage_bytes": None,
        "failcnt": None,
        "oom_control": {},
        "limit_bytes": None,
        "soft_limit_bytes": None,
        "max_usage_bytes": None,
        "failcnt_meaning": FAILCNT_MEANING_V1,
        "oom_kill_meaning": OOM_KILL_MEANING_V1,
        # v2
        "current_bytes": None,
        "swap_current_bytes": None,
        "events": {},
        "events_local": {},
        "oom": None,
        "oom_kill": None,
        "oom_kill_counter": None,
        "max": None,
        "high": None,
        # 共用
        "memory_stat": {},
        "errors": {},
    }


def _collect_cgroup(root=None, proc_dir="/proc/self"):
    ver, mount, derr = _detect_cgroup_version(root)
    v1_rel, v2_rel, cerr = _cgroup_relpath(proc_dir)
    out = _cgroup_skeleton()
    out["cgroup_file_error"] = cerr
    out["version"] = ver
    out["mount"] = mount
    out["detect_error"] = derr
    if ver == 2:
        rel = v2_rel if v2_rel is not None else "/"
        cdir = (os.path.join(root, mount.lstrip("/"), rel.lstrip("/")) if root
                else _abs_mount(None, mount, rel))
        if not rel or rel == "/":
            cdir = os.path.join(root, mount.lstrip("/")) if root else mount
        out["method"] = "v2 统一层级：/proc/<pid>/cgroup 中控制器列为空的条目 + cgroup2 挂载点"
        out["path"] = cdir
        out.update(_collect_cgroup_v2(cdir))
        out["version"] = 2
    elif ver == 1:
        if v1_rel is None:
            out["detect_error"] = cerr or "未在 /proc/<pid>/cgroup 找到 memory 行"
            out["method"] = "v1：/proc/<pid>/cgroup 的 memory 行缺失"
            return out
        if root:
            cdir = os.path.join(root, mount.lstrip("/"), v1_rel.lstrip("/"))
        else:
            cdir = _abs_mount(None, mount, v1_rel)
        out["method"] = "v1：/proc/<pid>/cgroup memory 行 + 已确认 memory 挂载点拼接"
        out["path"] = cdir
        out.update(_collect_cgroup_v1(cdir))
        out["version"] = 1
    return out


# ---------------------------------------------------------------- journal / OOM
def _cursor_path(state_file):
    env = os.environ.get(_ENV_CURSOR)
    if env:
        return env
    base = os.path.dirname(state_file) or "."
    return os.path.join(base, ".resource_probe_journal_cursor")


def _load_cursor(state_file):
    try:
        with _io_open(_cursor_path(state_file), "r") as fh:
            cur = fh.read().strip()
            return cur or None
    except (IOError, OSError):
        return None


def _save_cursor(state_file, cursor):
    if not cursor:
        return
    path = _cursor_path(state_file)
    tmp = path + ".tmp"
    try:
        with _io_open(tmp, "w") as fh:
            fh.write(cursor + "\n")
        os.replace(tmp, path)
    except (IOError, OSError):
        pass


def _journal_decode(value):
    """journald JSON 字段解码：字节数组 -> str；单字节数组 -> 字符（journald 的 _COMM 形式）。"""
    if value is None:
        return None
    if isinstance(value, list):
        try:
            if value and all(isinstance(x, int) for x in value):
                if len(value) > 1:
                    return bytes(bytearray(value)).decode("utf-8", "replace")
                return chr(value[0])
        except (ValueError, TypeError):                       # pragma: no cover
            return None
        return None
    return value


_OOM_CONSTRAINT_RE = re.compile(r"constraint=([A-Za-z0-9_]+)")
_OOM_PID_RE = re.compile(r"(?:Killed process|oom_reaper:\s*reaped)\s+(\d+)\s*\(([^)]*)\)")
_OOM_TASK_RE = re.compile(r"Task in (.+?) killed as a result of")


def _parse_oom_line(obj):
    """从一行 journal JSON 里抽取 OOM 事件；非 OOM 返回 None。"""
    msg = _journal_decode(obj.get("MESSAGE"))
    if not isinstance(msg, str):
        msg = "" if msg is None else str(msg)
    low = msg.lower()
    if not any(m.lower() in low for m in _OOM_MARKERS):
        return None
    cursor = obj.get("__CURSOR") or obj.get("_CURSOR")
    key = cursor
    if not key:
        basis = "%s|%s|%s|%s|%s" % (obj.get("__REALTIME_TIMESTAMP"), obj.get("_PID"),
                                    obj.get("_COMM"), obj.get("_BOOT_ID"), msg)
        key = "sha1:" + hashlib.sha1(basis.encode("utf-8", "replace")).hexdigest()[:20]
    constraint = None
    m = _OOM_CONSTRAINT_RE.search(msg)
    if m:
        constraint = m.group(1)
    elif "Memory cgroup out of memory" in msg or "oom-kill" in low:
        constraint = "unknown"
    victim_pid = None
    victim_name = None
    m = _OOM_PID_RE.search(msg)
    if m:
        victim_pid = _as_int(m.group(1))
        victim_name = m.group(2) or None
    m = _OOM_TASK_RE.search(msg)
    if m and not victim_name:
        victim_name = m.group(1).strip()
    if victim_pid is None:
        victim_pid = _as_int(str(obj.get("_PID") or ""))
    if victim_name is None:
        victim_name = _journal_decode(obj.get("_COMM"))
    ts = obj.get("__REALTIME_TIMESTAMP")
    try:
        ts = int(ts)
        when = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts / 1000000.0))
    except (TypeError, ValueError):
        when = None
    return {
        "event_id": key,
        "time": when,
        "constraint": constraint,
        "victim_pid": victim_pid,
        "victim_name": victim_name,
        "unit": _journal_decode(obj.get("_SYSTEMD_UNIT")),
    }


def _read_journal_jsonl(after_cursor=None):
    """增量读取内核 journal。返回 (lines, err)。after_cursor 为 None 时只读最近窗口。"""
    argv = ["journalctl", "-k", "-o", "json", "--no-pager"]
    if after_cursor:
        argv += ["--after-cursor", after_cursor]
    else:
        argv += ["--since", "-10min", "--lines", "400"]
    argv += ["--lines", str(JOURNAL_MAX_LINES)] if after_cursor else []
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except (IOError, OSError) as exc:
        return None, "journalctl 启动失败: %s: %s" % (type(exc).__name__, exc.strerror or str(exc))
    try:
        out, errout = proc.communicate(timeout=JOURNALCTL_TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return None, "journalctl 超时(%ss)" % JOURNALCTL_TIMEOUT
    if proc.returncode != 0 and not out:
        return None, "journalctl 退出码 %s: %s" % (proc.returncode,
                                                   (errout or b"").decode("utf-8", "replace")[:200])
    lines = [ln for ln in (out or b"").decode("utf-8", "replace").splitlines() if ln.strip()]
    return lines, None


class _JournalState(object):
    """journal 增量状态：cursor 去重 + 有界事件环形缓冲。"""

    def __init__(self, state_file):
        self.state_file = state_file
        self.lock = threading.Lock()
        self.cursor = None
        self.events = []
        self.oom_kill_total = 0
        self.refresh_count = 0
        self.last_refresh_ts = None
        self.last_error = None
        self.persistence_error = None
        self.load()

    def load(self):
        try:
            with _io_open(self.state_file, "r") as fh:
                data = json.load(fh)
        except (IOError, OSError):
            return
        except ValueError as exc:
            self.last_error = "状态文件损坏: %s" % exc
            return
        if not isinstance(data, dict):
            return
        cur = (data.get("journal") or {}).get("cursor") or data.get("journal_cursor")
        self.cursor = cur or None
        ev = (data.get("journal") or {}).get("events") or data.get("journal_events") or []
        if isinstance(ev, list):
            self.events = [e for e in ev if isinstance(e, dict)][-JOURNAL_MAX_EVENTS:]
        tot = (data.get("journal") or {}).get("oom_kill_total")
        if isinstance(tot, int):
            self.oom_kill_total = tot

    def save(self):
        data = {
            "probe_version": VERSION,
            "saved_at": int(time.time()),
            "journal": {
                "cursor": self.cursor,
                "events": self.events[-JOURNAL_MAX_EVENTS:],
                "oom_kill_total": self.oom_kill_total,
                "refresh_count": self.refresh_count,
                "last_refresh_ts": self.last_refresh_ts,
                "persistence_error": self.persistence_error,
            },
        }
        tmp = self.state_file + ".tmp"
        try:
            with _io_open(tmp, "w") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, self.state_file)
            self.persistence_error = None
        except (IOError, OSError) as exc:
            # 与 journalctl 读取失败分开记录：否则"状态写不进去"会盖掉真正的读取错误。
            self.persistence_error = "状态写入失败: %s" % exc


_JOURNAL_STATES = {}
_JOURNAL_STATES_LOCK = threading.Lock()


def _get_journal_state(state_file):
    with _JOURNAL_STATES_LOCK:
        st = _JOURNAL_STATES.get(state_file)
        if st is None:
            st = _JournalState(state_file)
            _JOURNAL_STATES[state_file] = st
        return st


def refresh_journal_events(state_file=None, force=False, now=None,
                           min_interval=JOURNAL_REFRESH_SEC, reader=None):
    """每 min_interval 秒才真正 fork 一次 journalctl。返回 (summary, refreshed)。

    summary 只含：时间、constraint、victim PID/name、事件 ID；按 cursor 去重。
    """
    state_file = state_file or JOURNAL_CURSOR_FILE
    st = _get_journal_state(state_file)
    now = time.time() if now is None else now
    with st.lock:
        if (not force) and st.last_refresh_ts is not None and \
                (now - st.last_refresh_ts) < min_interval:
            return _journal_summary(st), False
        reader = reader or _read_journal_jsonl
        lines, err = reader(st.cursor)
        if lines is None:
            st.last_error = err
            st.last_refresh_ts = now
            st.save()
            return _journal_summary(st), False
        known = set()
        for ev in st.events:
            if isinstance(ev, dict) and ev.get("event_id"):
                known.add(ev["event_id"])
        new_events = []
        for line in lines:
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if not isinstance(obj, dict):
                continue
            ev = _parse_oom_line(obj)
            if ev is None:
                continue
            eid = ev.get("event_id")
            if eid and eid in known:
                continue
            if eid:
                known.add(eid)
            new_events.append(ev)
        if new_events:
            st.events = (st.events + new_events)[-JOURNAL_MAX_EVENTS:]
            st.oom_kill_total += len(new_events)
        new_cursor = None
        for line in lines:
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict) and obj.get("__CURSOR"):
                new_cursor = obj["__CURSOR"]
        if new_cursor:
            st.cursor = new_cursor
            _save_cursor(state_file, new_cursor)
        st.refresh_count += 1
        st.last_refresh_ts = now
        st.last_error = None
        st.save()
        return _journal_summary(st), True


def _journal_summary(st):
    since = None
    if st.events:
        since = st.events[0].get("time")
    return {
        "cursor": st.cursor,
        "cursor_present": bool(st.cursor),
        "events": [{"time": e.get("time"), "constraint": e.get("constraint"),
                    "victim_pid": e.get("victim_pid"), "victim_name": e.get("victim_name"),
                    "event_id": e.get("event_id")} for e in st.events[-JOURNAL_MAX_EVENTS:]],
        "event_count": len(st.events),
        "oom_kill_total": st.oom_kill_total,
        "refresh_count": st.refresh_count,
        "last_refresh_ts": st.last_refresh_ts,
        "last_error": st.last_error,
        "persistence_error": st.persistence_error,
        "oldest_event_time": since,
        "dedup": "按 journal cursor 去重；每次只读 cursor 之后的新行",
        "note": "仅内核日志中的 OOM 事件；不等价于 cgroup v1 的 failcnt（failcnt 上涨 ≠ OOM）",
    }


# ---------------------------------------------------------------- 状态 / delta
def _boot_id(root=None):
    """boot_id：PID 变化之外的第二重“已重启”证据。取不到 -> None（不编造）。"""
    candidates = []
    if root:
        candidates.append(os.path.join(root, "proc/sys/kernel/random/boot_id"))
    candidates.append("/proc/sys/kernel/random/boot_id")
    for path in candidates:
        text, _err = _read_text(path)
        if text:
            return text.strip()
    return None


def _load_state(state_file):
    try:
        with _io_open(state_file, "r") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (IOError, OSError):
        return {}
    except ValueError:
        return {}


def _save_state(state_file, data):
    tmp = state_file + ".tmp"
    try:
        with _io_open(tmp, "w") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=1)
        os.replace(tmp, state_file)
        return None
    except (IOError, OSError) as exc:
        return "状态写入失败: %s" % exc


def _delta(prev, cur):
    if prev is None or cur is None:
        return None
    return cur - prev


# ---------------------------------------------------------------- Collector
class Collector(object):
    """无后台线程的采集器；每次 collect() 做一次只读采样。"""

    def __init__(self, pid=None, root=None, state_file=None,
                 journal_state_file=None, journal_min_interval=JOURNAL_REFRESH_SEC,
                 refresh_journal=True):
        self.pid = pid
        self.root = root
        self.state_file = state_file or JOURNAL_CURSOR_FILE
        self.journal_state_file = journal_state_file or self.state_file
        self.journal_min_interval = journal_min_interval
        self.refresh_journal = refresh_journal
        self._smaps_cache = (None, None, 0.0)

    # -- helpers
    def _proc_dir(self):
        if self.pid is None:
            return "/proc/self"
        return "/proc/%d" % int(self.pid)

    def _pss(self, now, force=False):
        proc_dir = self._proc_dir()
        if self.root:
            proc_dir = os.path.join(self.root, proc_dir.lstrip("/"))
        pss, err = _pss_from_rollup(proc_dir)
        if pss is not None:
            self._smaps_cache = (pss, None, now)
            return {"pss_kb": pss, "pss_source": "smaps_rollup", "pss_error": None}
        rollup_err = err
        cached_val, cached_err, cached_ts = self._smaps_cache
        if (not force) and cached_val is not None and (now - cached_ts) < SMAPS_SUMMARY_MIN_SEC:
            return {"pss_kb": cached_val, "pss_source": "smaps_sum(缓存)",
                    "pss_error": rollup_err}
        if (not force) and cached_val is None and cached_err is not None and \
                (now - cached_ts) < SMAPS_SUMMARY_MIN_SEC:
            return {"pss_kb": None, "pss_source": None, "pss_error": cached_err}
        pss2, err2 = _pss_from_smaps(proc_dir)
        self._smaps_cache = (pss2, err2, now)
        if pss2 is None:
            return {"pss_kb": None, "pss_source": None,
                    "pss_error": "smaps_rollup: %s；smaps: %s" % (rollup_err, err2)}
        return {"pss_kb": pss2, "pss_source": "smaps_sum", "pss_error": rollup_err}

    # -- main
    def collect(self, now=None, refresh_journal=None):
        now = time.time() if now is None else now
        pid = self.pid if self.pid is not None else os.getpid()
        proc_dir = "/proc/self" if self.pid is None else "/proc/%d" % int(self.pid)
        real_proc = proc_dir if not self.root else os.path.join(self.root, proc_dir.lstrip("/"))

        t0 = time.time()
        status = _proc_status(real_proc)
        counts = _proc_counts(real_proc)
        pss = self._pss(now)
        cg = _collect_cgroup(root=self.root, proc_dir=real_proc)
        boot = _boot_id(self.root)
        t1 = time.time()

        # 计数器（None 一律保持 None）
        counters = {
            "usage_bytes": cg.get("usage_bytes"),
            "memsw_usage_bytes": cg.get("memsw_usage_bytes"),
            "failcnt": cg.get("failcnt"),
            "current_bytes": cg.get("current_bytes"),
            "oom_kill": cg.get("oom_kill"),
            "oom": cg.get("oom"),
            "fds": counts.get("fds"),
            "threads": status.get("threads"),
        }
        identity = {"pid": pid, "boot_id": boot, "cgroup_path": cg.get("path"),
                    "cgroup_version": cg.get("version")}

        state = _load_state(self.state_file)
        prev = state.get("last") if isinstance(state.get("last"), dict) else None
        session = state.get("session") if isinstance(state.get("session"), dict) else {}
        reset_reason = None
        if prev is None:
            reset_reason = "first_run"
        else:
            for k in ("pid", "boot_id", "cgroup_path", "cgroup_version"):
                if prev.get(k) != identity.get(k):
                    reset_reason = "%s_changed" % k
                    break
        if reset_reason:
            session = {"pid": pid, "boot_id": boot, "cgroup_path": cg.get("path"),
                       "since": int(now), "failcnt_delta_session": None,
                       "oom_kill_delta_session": None, "delta_reset_count":
                           int(session.get("delta_reset_count") or 0) + (0 if prev is None else 1),
                       "last_reset_reason": reset_reason}
        prev_counters = (prev or {}).get("counters") or {}

        def _d(name):
            return _delta(prev_counters.get(name), counters.get(name))

        delta = {
            "usage_bytes": _d("usage_bytes"),
            "memsw_usage_bytes": _d("memsw_usage_bytes"),
            "failcnt": _d("failcnt"),
            "current_bytes": _d("current_bytes"),
            "oom_kill": _d("oom_kill"),
            "oom": _d("oom"),
            "fds": _d("fds"),
            "threads": _d("threads"),
            "reset_reason": reset_reason,
            "baseline_ts": (prev or {}).get("ts"),
            "elapsed_s": (None if not prev else (now - (prev.get("ts") or now))),
            "semantics": ("identity（pid/boot_id/cgroup 路径/版本）变化时全部置空并重建基线；"
                          "missing 一律 null，不填 0；failcnt 上涨 ≠ OOM"),
        }
        if reset_reason:
            for k in list(delta.keys()):
                if k in ("reset_reason", "baseline_ts", "elapsed_s", "semantics"):
                    continue
                delta[k] = None
        for name in ("failcnt", "oom_kill"):
            if delta.get(name) is not None:
                cur_sess = session.get(name + "_delta_session")
                session[name + "_delta_session"] = (0 if cur_sess is None else cur_sess) + delta[name]
        delta["failcnt_delta_session"] = session.get("failcnt_delta_session")
        delta["oom_kill_delta_session"] = session.get("oom_kill_delta_session")
        delta["delta_reset_count"] = session.get("delta_reset_count")

        need_journal = self.refresh_journal if refresh_journal is None else refresh_journal
        journal_ms = 0.0
        if need_journal:
            jt0 = time.time()
            journal, _refreshed = refresh_journal_events(
                self.journal_state_file, now=now, min_interval=self.journal_min_interval)
            journal_ms = (time.time() - jt0) * 1000.0
        else:
            journal = _journal_summary(_get_journal_state(self.journal_state_file))

        out = {
            "probe_version": VERSION,
            "ts": now,
            "pid": pid,
            "pid_dir": proc_dir,
            "boot_id": boot,
            "proc": {
                "rss_kb": status.get("rss_kb"),
                "swap_kb": status.get("swap_kb"),
                "threads": status.get("threads"),
                "status_error": status.get("status_error"),
                "fds": counts.get("fds"),
                "fds_error": counts.get("fds_error"),
                "tasks": counts.get("tasks"),
                "tasks_error": counts.get("tasks_error"),
                "threads_match": (None if (status.get("threads") is None or
                                           counts.get("tasks") is None)
                                  else status.get("threads") == counts.get("tasks")),
                "pss_kb": pss.get("pss_kb"),
                "pss_source": pss.get("pss_source"),
                "pss_error": pss.get("pss_error"),
            },
            "cgroup": cg,
            "delta": delta,
            "session": session,
            "journal_oom": journal,
            "errors": _collect_errors(status, counts, pss, cg),
            "collect_ms": int((t1 - t0) * 1000),
            "journal_ms": int(journal_ms),
        }
        new_state = {
            "probe_version": VERSION,
            "updated_at": int(now),
            "last": {"ts": now, "pid": pid, "boot_id": boot,
                     "cgroup_path": cg.get("path"), "cgroup_version": cg.get("version"),
                     "counters": counters},
            "session": session,
            # journal 的 cursor/事件由 _JournalState 独立持久化；这里只留指针说明，
            # 避免同一份事件在状态文件里写两遍（300s 一次、最多 50 条）。
            "journal": {"cursor_file": _cursor_path(self.journal_state_file)},
        }
        werr = _save_state(self.state_file, new_state)
        if werr:
            out["errors"].append(werr)
        return out


def _collect_errors(status, counts, pss, cg):
    errs = []
    if status.get("status_error"):
        errs.append("status: " + status["status_error"])
    if counts.get("fds_error"):
        errs.append("fd: " + counts["fds_error"])
    if counts.get("tasks_error"):
        errs.append("task: " + counts["tasks_error"])
    if pss.get("pss_error"):
        errs.append("pss: " + pss["pss_error"])
    if cg.get("detect_error"):
        errs.append("cgroup: " + cg["detect_error"])
    if cg.get("cgroup_file_error"):
        errs.append("cgroup(/proc/<pid>/cgroup): " + cg["cgroup_file_error"])
    for name, msg in (cg.get("errors") or {}).items():
        errs.append("cgroup/%s: %s" % (name, msg))
    return errs


_DEFAULT_COLLECTOR = {"obj": None, "key": None}


def collect_self_resources(pid=None, root=None, state_file=None,
                           journal_state_file=None, refresh_journal=True,
                           journal_min_interval=JOURNAL_REFRESH_SEC, now=None):
    """方案要求的公开接口。默认当前进程；只读；不启动线程/HTTP/生产采集。

    生产（chainmon 内部）调用建议 refresh_journal=True 且不要传 now，
    节流与去重由 refresh_journal_events 负责，浏览器刷新只会读缓存（refresh_journal=False）。
    """
    if state_file is None:
        state_file = os.environ.get(_ENV_STATE) or JOURNAL_CURSOR_FILE
    if journal_state_file is None:
        journal_state_file = state_file
    key = (pid, root, state_file, journal_state_file)
    if _DEFAULT_COLLECTOR["obj"] is None or _DEFAULT_COLLECTOR["key"] != key:
        _DEFAULT_COLLECTOR["obj"] = Collector(
            pid=pid, root=root, state_file=state_file,
            journal_state_file=journal_state_file,
            journal_min_interval=journal_min_interval, refresh_journal=refresh_journal)
        _DEFAULT_COLLECTOR["key"] = key
    return _DEFAULT_COLLECTOR["obj"].collect(now=now, refresh_journal=refresh_journal)


# ---------------------------------------------------------------- CLI（仅独立进程）
def _cli_parser():
    import argparse
    p = argparse.ArgumentParser(
        description="chainmon 自检资源探针（只读，独立进程；不接入 chainmon 就绪前不写生产快照）")
    p.add_argument("--pid", type=int, default=None, help="目标 PID，默认当前进程")
    p.add_argument("--interval", type=float, default=10.0, help="采样间隔秒，默认 10")
    p.add_argument("--duration", type=float, default=0.0, help="总时长秒，0=无限")
    p.add_argument("--once", action="store_true", help="只采样一次并打印完整 JSON")
    p.add_argument("--jsonl", action="store_true", help="每行一个紧凑 JSON（含完整字段）")
    p.add_argument("--summary-only", action="store_true", help="stdout 只输出起止/斜率汇总")
    p.add_argument("--root", default=None, help="测试夹具根（模拟 /proc 与 cgroup 挂载）")
    p.add_argument("--state-file", default=None, help="delta/journal 状态文件")
    p.add_argument("--out", default=None, help="把样本 JSONL 追加写到该文件")
    p.add_argument("--no-journal", action="store_true", help="不读 journal（夹具/离线）")
    return p


def _slope(pairs):
    """最小二乘斜率（y 单位/秒），样本不足返回 None。"""
    n = len(pairs)
    if n < 2:
        return None
    sx = sum(x for x, _y in pairs)
    sy = sum(y for _x, y in pairs)
    sxx = sum(x * x for x, _y in pairs)
    sxy = sum(x * y for x, y in pairs)
    den = n * sxx - sx * sx
    if den == 0:
        return None
    return (n * sxy - sx * sy) / den


def _cli_main(argv=None):
    args = _cli_parser().parse_args(argv)
    st = args.state_file
    if st is None:
        st = os.environ.get(_ENV_STATE)
    if st is None:
        st = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          ".resource_probe_state.json")
        if not args.root and os.path.isdir("/opt/chainmon"):
            st = JOURNAL_CURSOR_FILE
    c = Collector(pid=args.pid, root=args.root, state_file=st,
                  journal_state_file=st, refresh_journal=not args.no_journal)
    if args.once:
        snap = c.collect()
        print(json.dumps(snap, ensure_ascii=False, indent=1))
        return 0
    out_fh = None
    if args.out:
        out_fh = _io_open(args.out, "a")
    samples = []
    start = time.time()
    stop = {"flag": False}

    def _on_term(_signum, _frame):
        stop["flag"] = True

    try:
        import signal
        signal.signal(signal.SIGTERM, _on_term)
        signal.signal(signal.SIGINT, _on_term)
    except (ImportError, ValueError, OSError):
        pass
    n = 0
    while not stop["flag"]:
        loop_t = time.time()
        snap = c.collect()
        n += 1
        row = {
            "n": n, "t": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(snap["ts"])),
            "elapsed_s": round(snap["ts"] - start, 1),
            "rss_kb": snap["proc"]["rss_kb"], "pss_kb": snap["proc"]["pss_kb"],
            "swap_kb": snap["proc"]["swap_kb"], "fds": snap["proc"]["fds"],
            "threads": snap["proc"]["threads"], "tasks": snap["proc"]["tasks"],
            "threads_match": snap["proc"]["threads_match"],
            "collect_ms": snap["collect_ms"], "journal_ms": snap["journal_ms"],
            "cgroup_version": snap["cgroup"].get("version"),
            "usage_bytes": snap["cgroup"].get("usage_bytes"),
            "memsw_usage_bytes": snap["cgroup"].get("memsw_usage_bytes"),
            "failcnt": snap["cgroup"].get("failcnt"),
            "oom_kill": snap["cgroup"].get("oom_kill"),
            "delta": snap["delta"],
            "errors": snap["errors"],
        }
        samples.append((snap["ts"], row))
        line = json.dumps(row, ensure_ascii=False)
        if out_fh:
            out_fh.write(line + "\n")
            out_fh.flush()
        if args.jsonl:
            print(line)
            sys.stdout.flush()
        if args.duration and (time.time() - start) >= args.duration:
            break
        sleep = args.interval - (time.time() - loop_t)
        if sleep > 0:
            end = time.time() + sleep
            while time.time() < end and not stop["flag"]:
                time.sleep(min(0.5, end - time.time()))
    if out_fh:
        out_fh.close()
    summary = _summarize(samples, start)
    print(json.dumps(summary, ensure_ascii=False, indent=1))
    return 0


def _summarize(samples, start):
    def series(key):
        out = []
        for ts, row in samples:
            v = row.get(key)
            if isinstance(v, int):
                out.append((ts - start, v))
        return out

    res = {"samples": len(samples),
           "start": (samples[0][1]["t"] if samples else None),
           "end": (samples[-1][1]["t"] if samples else None),
           "elapsed_s": round(samples[-1][0] - start, 1) if samples else 0,
           "metrics": {}}
    for key, unit in (("rss_kb", "kB"), ("pss_kb", "kB"), ("swap_kb", "kB"),
                      ("fds", "count"), ("threads", "count"),
                      ("usage_bytes", "B"), ("memsw_usage_bytes", "B"), ("failcnt", "count")):
        vals = series(key)
        if not vals:
            res["metrics"][key] = {"unit": unit, "samples": 0,
                                   "note": "无有效样本（null 未被当作 0）"}
            continue
        first = vals[0][1]
        last = vals[-1][1]
        sl = _slope(vals)
        res["metrics"][key] = {
            "unit": unit, "samples": len(vals), "first": first, "last": last,
            "change": last - first, "min": min(v for _x, v in vals),
            "max": max(v for _x, v in vals),
            "slope_per_s": (None if sl is None else round(sl, 6)),
            "slope_per_hour": (None if sl is None else round(sl * 3600.0, 2)),
        }
    errs = {}
    for _ts, row in samples:
        for e in row.get("errors") or []:
            errs[e] = errs.get(e, 0) + 1
    res["errors"] = errs
    return res


if __name__ == "__main__":
    sys.exit(_cli_main())
