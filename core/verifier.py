#!/usr/bin/env python3
# dnsguard 旁路核验 sidecar
# 2026-10-07 大改：
#   ① **按 pool 意图分池**（r3=12 / corrob=4）：R8 同步核对与 R3 取干净答案不再互相饿死；
#      以前两者共用一个池，任何一批慢查询就能把所有域名变成"干净上游不可用"。
#   ② 应答帧加 **1 字节状态**（OK/NODATA/TIMEOUT/OVERLOAD/ERROR），让主进程能区分
#      "权威侧 NODATA"（有证据）与"我们排队超时/过载"（没证据）——方案 B 的语义前提。
#   ③ **独立 STATE_DIR + 自己落盘统计**：以前它跑在主进程的 state 目录里却从不落盘
#      （保存线程只在 guard 的 main() 里启动），所以 r8_auth_none 这类计数永远看不到。
#   ④ 并发下调（64→24）、超时上限可配、socket 超时跟随本次查询预算。
#   ⑤ 2026-10-10 Step-1（方案 §1）：**与 guard 用同一请求追踪 ID（rid）分开统计** ——
#      meta 里带 `rid`，本进程按 rid 记 v_* 计数（收到数/带 rid 数/各池处理数/耗时），
#      guard 从不读这些键（两进程各自 _stats 各自落盘 ⇒ 天然分账 ✓）。
import os,socket,struct,json,threading,concurrent.futures,sys,time
# P34-AW（方案任务3）：按**自身目录**导入同发布版本的 guard —— 不固定插 /opt/dnsguard ✗，
# 保证 guard 与 verifier 永远读同一份不可变发布 ✓。
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import guard
path=os.environ.get('VERIFIER_SOCKET','/run/dnsguard/verifier.sock')
os.makedirs(os.path.dirname(path),exist_ok=True)
if os.path.exists(path):os.unlink(path)
SLOTS=int(os.environ.get('VERIFIER_SLOTS','24'))
R3_SLOTS=int(os.environ.get('VERIFIER_R3_SLOTS','12'))
CORROB_SLOTS=int(os.environ.get('VERIFIER_CORROB_SLOTS','4'))
TIMEOUT_CAP=float(os.environ.get('VERIFIER_TIMEOUT_CAP','2.8'))
pool=concurrent.futures.ThreadPoolExecutor(max_workers=SLOTS)
slots=threading.BoundedSemaphore(SLOTS)
_r3_sem=threading.BoundedSemaphore(R3_SLOTS)
_corrob_sem=threading.BoundedSemaphore(CORROB_SLOTS)
STRICT_SLOTS=int(os.environ.get('VERIFIER_STRICT_SLOTS','8'))
# 2026-10-10 P34-J: CN 路径"否定存在否决"的 W2 见证需要**独立池**，
# 否则会落到 _r3_sem（其有界等待仅 0.4s）⇒ 池忙时回 OVERLOAD ⇒ W2 无应答 ⇒ d2=None ⇒ 不否决 ✗
VETO_SLOTS=int(os.environ.get('VERIFIER_VETO_SLOTS','6'))
_strict_sem=threading.BoundedSemaphore(STRICT_SLOTS)
_veto_sem=threading.BoundedSemaphore(VETO_SLOTS)
_ST=guard._VSTATUS_BYTE
# 2026-10-15 审计 F5：本进程按**自身目录**导入 guard（见上）⇒ 下面三个指纹即"我这份代码"。
# 用它跟主进程随每次请求发来的指纹比对，不一致即**拒服务** ✓。
_MY_SHA=getattr(guard,'_GUARD_SHA256','unavailable')
_MY_REL=getattr(guard,'_RELEASE_ID','unknown')
_MY_PROTO=getattr(guard,'VERIFIER_PROTO',1)


def _vs(key,n=1):
    """Step-1 §1：verifier 侧计数（持 guard._lock ⇒ 与 guard 的 while-True 写盘一致 ✓）。"""
    try:
        with guard._lock:
            guard._stats[key]=guard._stats.get(key,0)+n
    except Exception:
        pass


def _write_meta():
    """F5：把『我是谁 / 我跑的是哪份发布』落盘。

    启动时立刻写一次，之后由 _stats_writer 每 60s 覆盖 —— 否则部署门禁会在重启后的
    60s 空窗里读到上一次运行遗留的旧 meta（旧 pid/旧 release_id）⇒ 假红灯误回滚 ✗"""
    try:
        import json as _json, time as _time
        _meta = {"generated": _time.strftime("%Y-%m-%d %H:%M:%S"),
                 "pid": os.getpid(),
                 "role": "verifier",
                 "release_id": _MY_REL,
                 "guard_sha256": _MY_SHA,
                 "policy_version": getattr(guard, "_POLICY_VERSION", "n/a"),
                 # F5：IPC 协议版本也要能自证（两侧必须一致）✓
                 "verifier_proto": _MY_PROTO,
                 "guard_script": getattr(guard, "__file__", "?"),
                 "state_dir": os.environ.get("GUARD_STATE_DIR", "(default)"),
                 "note": "verifier 自证：它按 __file__ 同目录导入 guard ⇒ 两进程必读同一发布 ✓"}
        _mp = os.path.join(os.path.dirname(guard.STATS_FILE), "stats_meta.json")
        _tmp = _mp + ".tmp"
        with open(_tmp, "w") as _f:
            _json.dump(_meta, _f, ensure_ascii=False, indent=1, sort_keys=True)
        os.replace(_tmp, _mp)
    except Exception:
        pass

def _stats_writer():
    while True:
        time.sleep(60)
        try:
            with guard._lock:
                st=dict(guard._stats)
                # 语义化派生量（都在锁内取，避免撕裂）
                _n=st.get('v_ms_n',0) or 0
                st['v_ms_avg']=round((st.get('v_ms',0) or 0)/float(_n),2) if _n else 0.0
                st['v_pool_total']=(st.get('v_pool_r3',0)+st.get('v_pool_corrob',0)
                                    +st.get('v_pool_strict',0)+st.get('v_pool_veto',0))
            st['pid']=os.getpid()
            st['updated']=time.time(); st['role']='verifier'
            guard._atomic_json(guard.STATS_FILE, st)
        except Exception:
            pass
        _write_meta()

def run(c):
 c.settimeout(3)          # 帧头/meta 的短超时；拿到 meta 后按查询预算放宽
 def readn(n):
  d=b''
  while len(d)<n:
   x=c.recv(n-len(d))
   if not x:raise IOError('short frame')
   d+=x
  return d
 sem=None; got=False
 _t0=time.monotonic()
 try:
  a,b=struct.unpack('!HH',readn(4))
  if a>1024 or b<12 or b>4096:
   _vs('v_badframe')
   return
  meta=json.loads(readn(a).decode());msg=readn(b)
  # 2026-10-28 N-1: establish per-request ECS context. Worker threads are reused;
  # without this _cur_ecs_key() is always None here, so rebuilt queries lose ECS and
  # the verification view diverges from the main process cache sharding.
  try:
   guard._tr_begin(msg, entry='verifier')
  except Exception:
   pass
  op=meta.get('op')
  # Step-1 §1：同一请求追踪 ID（guard 侧生成，verifier 侧按它分开统计 ✓）
  _vs('v_recv')
  _vs('v_rid_present' if meta.get('rid') is not None else 'v_rid_absent')
  # ---- 2026-10-15 审计 F5：发布/协议指纹不兼容 ⇒ **拒服务**（回 VERSION_MISMATCH）----
  # 语义：宁可不给核对证据（主进程会走"没查成"的保守路径），也不让两份不同代码互相喂结论 ✗。
  # 缺 sha（老 guard / 非本协议请求）⇒ 记 v_release_unverified 但继续 ⇒ 兼容性不静默 ✓。
  _rel=guard.release_compatible(meta,_MY_SHA,_MY_REL,_MY_PROTO)
  if _rel=='mismatch':
   _vs('v_release_mismatch')
   c.sendall(struct.pack('!H',1)+_ST[guard.CORROB_VERSION_MISMATCH])
   return
  if _rel=='unverified':
   _vs('v_release_unverified')
  # 2026-10-10 Patch11：严格路径用**独立池**（不与常规 R8 抢槽）
  _pool=('strict' if meta.get('pool')=='strict' else
         'veto' if meta.get('pool')=='veto' else
         ('corrob' if op=='corrob' else 'r3'))
  sem=(_strict_sem if _pool=='strict' else
      _veto_sem if _pool=='veto' else
      (_corrob_sem if op=='corrob' else _r3_sem))
  # 2026-10-10 Patch13（Codex）：有界等待 —— 本地槽位紧张应表现为“慢”，
  # 而不是被翻译成“没有证据”（后者在 strict_fail_closed=0 下会直接下发明文 ✗）。
  _bd=min(0.4,float(meta.get('timeout') or 0) or 0.4)
  if not sem.acquire(timeout=_bd):
   # 池满：立刻回 OVERLOAD，让主进程走自己的降级路径。**绝不在这里排队**。
   _vs('v_pool_overload')
   c.sendall(struct.pack('!H',1)+_ST[guard.CORROB_OVERLOAD])
   return
  got=True
  _vs('v_pool_'+_pool)
  if op=='corrob' or meta.get('pool') in ('strict','veto'):
   to=min(float(meta.get('timeout') or guard.CORROB_DOT_TIMEOUT),guard.CORROB_DOT_TIMEOUT)
   c.settimeout(to+0.5)
   st,r=guard._corrob_query_once(msg,meta['name'],meta['qtype'],meta.get('targets'),to)
  else:
   to=min(float(meta['timeout']),TIMEOUT_CAP)
   c.settimeout(to+0.3)
   r=guard.dot_query(msg,meta['name'],meta['qtype'],to,bool(meta['prefer_addr']))
   st=guard.CORROB_OK if r else guard.CORROB_TIMEOUT
  _vs('v_ms',(time.monotonic()-_t0)*1000.0); _vs('v_ms_n')
  c.sendall(struct.pack('!H',1+len(r or b''))+_ST.get(st,_ST[guard.CORROB_ERROR])+(r or b''))
 except Exception:
  _vs('v_err')
 finally:
  try:c.close()
  except Exception:pass
  if got and sem is not None:sem.release()
  slots.release()
guard.log("VERIFIER release=%s sha256=%s proto=%s" % (_MY_REL,_MY_SHA,_MY_PROTO))
_write_meta()   # F5：启动即自证（否则部署门禁会在 60s 空窗里读到旧 pid/旧发布 ⇒ 假红灯）✓
threading.Thread(target=_stats_writer).start()
# 2026-10-17 R8 压测：verifier 侧通道预热 + 保活（原先 _pool 无保活，
# 闲置后连接被回收 => 每次核对付约 600ms 的 TCP+TLS 冷启动）。
# 复用 guard 既有实现，不改任何判定逻辑 => 投毒防护强度不变。
threading.Thread(target=guard.prewarm, daemon=True).start()
threading.Thread(target=guard.keepalive, daemon=True).start()
# 2026-10-18 verifier concurrent keepalive: guard.keepalive walks 5 channels serially
# (cycle >2s) while CLEAN_DOT peers drop idle connections in ~1.5-2s => cold starts.
# One short thread per CLEAN_DOT channel, reusing guard.prewarm calls only;
# no change to verdict logic or channel set => poisoning resistance unchanged.
def _vk_touch(ip, port, sni):
    try:
        q = guard.mk_query("%s.com" % "".join(guard.random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(12)), qid=0x5A5A)
        guard._upstream_call(ip, port, sni, q, 3.0)
    except Exception:
        pass


def _vk_keepalive():
    while True:
        for _ip, _port, _sni in guard.CLEAN_DOT:
            try:
                threading.Thread(target=_vk_touch, args=(_ip, _port, _sni), daemon=True).start()
            except Exception:
                pass
        time.sleep(0.5)


threading.Thread(target=_vk_keepalive, daemon=True).start()
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.bind(path);os.chmod(path,0o600);s.listen(64)
while True:
 c,_=s.accept()
 if slots.acquire(False):pool.submit(run,c)
 else:c.close()
