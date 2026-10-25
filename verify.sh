#!/usr/bin/env bash
# =============================================================================
# dns-guard-stack 验收自检
#   ./verify.sh            # 全部检查
#   ./verify.sh --quick    # 只查容器/服务/指标
# 退出码：0 全通过 / 1 有失败项
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1

[ -f .env ] && { set -a; . ./.env; set +a; }
: "${DNS_DOMAIN:=dns.example.com}"
: "${CODE_DIR:=/opt/dnsguard}"
: "${LISTS_DIR:=/opt/dnscrypt-proxy}"
: "${STATE_DIR:=$CODE_DIR}"
: "${DOT_PORT:=853}"; : "${DOH_PORT:=444}"

C_OK=$'\033[32m'; C_ERR=$'\033[31m'; C_WARN=$'\033[33m'; C_0=$'\033[0m'
PASS=0; FAIL=0; WARN=0
ok()   { PASS=$((PASS+1)); printf '  %s✓%s %s\n' "$C_OK" "$C_0" "$*"; }
bad()  { FAIL=$((FAIL+1)); printf '  %s✗%s %s\n' "$C_ERR" "$C_0" "$*"; }
warn() { WARN=$((WARN+1)); printf '  %s!%s %s\n' "$C_WARN" "$C_0" "$*"; }
sec()  { printf '\n%s\n' "$*"; }

# ---------------------------------------------------------------- 1 容器与服务
sec "1. 容器"
for c in adgh aghdq aghdq2 aghcf unbound unbound-b unbound-alt; do
  st=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo missing)
  [ "$st" = running ] && ok "$c running" || bad "$c 状态=$st"
done
for c in alt-replica-unb dnscrypt-proxy; do
  st=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo missing)
  [ "$st" = "missing" ] && warn "$c 未部署（可选组件）" || ok "$c $st"
done

sec "2. 服务单元"
for u in dnsguard dnsguard-verifier; do
  st=$(systemctl is-active "$u" 2>/dev/null || true)
  [ "$st" = active ] && ok "$u active" || bad "$u 状态=$st"
done
for u in chainmon devfp; do
  st=$(systemctl is-active "$u" 2>/dev/null || true)
  [ "$st" = active ] && ok "$u active" || warn "$u 未运行（可选看板）"
done
if compgen -G "$CODE_DIR/*.log" >/dev/null 2>&1; then :; fi
tb=$(grep -c 'Traceback' /var/log/dnsguard.log 2>/dev/null || true); tb=${tb:-0}
[ "$tb" = 0 ] && ok "dnsguard.log 无 Traceback" || bad "dnsguard.log 有 $tb 处 Traceback"

# ---------------------------------------------------------------------- 3 指标
sec "3. 运行指标（$STATE_DIR/stats.json）"
if [ -s "$STATE_DIR/stats.json" ]; then
  python3 - "$STATE_DIR/stats.json" <<'PY' || true
import json,sys
st=json.load(open(sys.argv[1]))
keys=["cn_typed_total","cn_typed_full","cn_typed_domain","cn_typed_suffix","cn_typed_active",
      "cn_veto_entries","cn_ip_nets","cn_trust_allow_entries","cn_trust_exc_entries",
      "cn_trust_bypass","cn_trust_witness","cn_dom_exception","adm_cache_gen_mismatch",
      "dnssec_bogus","stale_out","hot_skip_stale","fc_unbound_servfail"]
for k in keys:
    if k in st: print("  %-28s %s" % (k, st[k]))
PY
  PUB=$(python3 -c "import json;print(json.load(open('$STATE_DIR/stats.json')).get('cn_typed_total',0))" 2>/dev/null || echo 0)
  [ "${PUB:-0}" -gt 0 ] 2>/dev/null && ok "类型化名单已载入（$PUB 条）" || warn "类型化名单为空（骨架名单；guard 会按未知不信任运行）"
else
  bad "读不到 $STATE_DIR/stats.json（guard 未启动或路径不符）"
fi

[ "$QUICK" = 1 ] && { printf '\nPASS=%d FAIL=%d WARN=%d\n' "$PASS" "$FAIL" "$WARN"; exit $((FAIL>0)); }

# --------------------------------------------------------------------- 4 解析
sec "4. 解析行为"
python3 - "$DNS_DOMAIN" "$DOT_PORT" "$DOH_PORT" "${GW_IP:-}" "${DNSGUARD_NET:-dnsnet}" <<'PY'
import socket, ssl, struct, sys, binascii, time, os, subprocess
DOMAIN, DOT_PORT, DOH_PORT = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
GW_OPT = sys.argv[4] if len(sys.argv) > 4 else ""
NET     = sys.argv[5] if len(sys.argv) > 5 else "dnsnet"
# 网关必须取**本栈的自定义网络**（compose 里的 dnsnet），guard 只监听在那里。
# 早前这里读的是 docker0 —— 那是 docker 默认 bridge（172.17.0.1），guard 并不监听，
# 于是所有默认安装都会让「解析行为」整段误报失败。
GW = (GW_OPT or os.environ.get("GW_IP", "")).strip()
if not GW:
    try:
        GW = subprocess.check_output(
            ["docker", "network", "inspect", NET,
             "-f", "{{range .IPAM.Config}}{{.Gateway}}{{end}}"],
            stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        GW = ""
if not GW or not GW[0].isdigit():
    GW = "172.18.0.1"
print("  网关：guard 监听 %s（网络 %s）" % (GW, NET))

def build(name, qtype=1, do=True):
    q = b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\x00'
    add = b''
    if do:
        add = b'\x00' + struct.pack('!HHIH', 41, 1232, 0x8000, 0)
    return struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, (1 if do else 0)) + q + struct.pack('!HH', qtype, 1) + add

def parse(r):
    if len(r) < 12: return None
    _id, flags, qd, an, ns, ar = struct.unpack('!HHHHHH', r[:12])
    return {'rcode': flags & 0xF, 'ad': bool(flags & 0x20), 'an': an, 'flags': flags}

def udp(host, port, name, timeout=4.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
    try:
        s.sendto(build(name), (host, port))
        r, _ = s.recvfrom(4096)
        return parse(r)
    except Exception as e:
        return {'error': type(e).__name__}
    finally:
        s.close()

def dot(host, port, name, sni, timeout=5.0):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as tls:
                q = build(name)
                tls.sendall(struct.pack('!H', len(q)) + q)
                hdr = tls.recv(2)
                if len(hdr) < 2: return {'error': 'short-header'}
                n = struct.unpack('!H', hdr)[0]
                buf = b''
                while len(buf) < n:
                    c = tls.recv(n - len(buf))
                    if not c: break
                    buf += c
                return parse(buf)
    except Exception as e:
        return {'error': type(e).__name__}

def show(tag, r):
    if not r: print("  %-34s %s" % (tag, "无响应")); return None
    if 'error' in r: print("  %-34s %s" % (tag, "错误：" + r['error'])); return r
    print("  %-34s rcode=%d an=%d ad=%s" % (tag, r['rcode'], r['an'], int(r['ad'])))
    return r

# 未接通 = 连接被拒/无监听：DoT/DoH 入口由 nginx 提供，属可选外部依赖，
# 不该让「验收」整体判 FAIL（install.sh 默认 INSTALL_NGINX=0，需人工 include 片段）。
UNWIRED = ("ConnectionRefusedError", "FileNotFoundError", "ConnectionResetError")

fails = []; warns = []

def udp_retry(host, port, name, tries=6, gap=4.0, need=None):
    """guard 的干净上游池是**异步预热**的：systemd 报 active 不等于已经能出答案，
    冷启动后头几次查询可能拿到 SERVFAIL（实测 0~30s 内都会）。验收不该把这种
    瞬时状态判成失败，所以按条件重试；始终命不中就把最后一次结果交回，由调用方判 FAIL。"""
    last = None
    for i in range(tries):
        last = udp(host, port, name)
        if last and 'rcode' in last and (need is None or need(last)):
            return last
        if i < tries - 1:
            time.sleep(gap)
    return last

def is_ok(x):       return x.get('rcode') == 0 and x.get('an', 0) >= 1
def is_servfail(x): return x.get('rcode') == 2

r = show("guard(%s:5355) cloudflare.com" % GW, udp_retry(GW, 5355, "cloudflare.com", need=is_ok))
if not (r and is_ok(r)): fails.append("guard 查询 cloudflare.com 失败")
r = show("guard(%s:5355) dnssec-failed.org" % GW, udp_retry(GW, 5355, "dnssec-failed.org", need=is_servfail))
if not (r and is_servfail(r)): fails.append("dnssec-failed.org 未返回 SERVFAIL（验签未生效？）")
r = show("DoT(%s:%d) cloudflare.com" % (DOMAIN, DOT_PORT), dot("127.0.0.1", DOT_PORT, "cloudflare.com", DOMAIN))
if r and r.get('rcode') == 0:
    pass
elif r and r.get('error') in UNWIRED:
    warns.append("DoT 入口未接（%s:%d %s）—— nginx 未安装/未 include dot-853.conf" % (DOMAIN, DOT_PORT, r['error']))
else:
    fails.append("DoT 入口查询失败（%s）" % (r.get('error') if r else '无响应'))
r = show("DoH(%s:%d) cloudflare.com" % (DOMAIN, DOH_PORT), None) if False else None
try:
    import http.client
    ctx = ssl.create_default_context()
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    q = build("cloudflare.com")
    b64 = binascii.b2a_base64(q).decode().strip().replace('+','-').replace('/','_').replace('=','')
    c = http.client.HTTPSConnection("127.0.0.1", DOH_PORT, context=ctx, timeout=6)
    c.request("GET", "/dns-query?dns=" + b64, headers={"Host": DOMAIN, "Accept": "application/dns-message"})
    resp = c.getresponse()
    body = resp.read()
    print("  %-34s http=%d len=%d" % ("DoH(%s:%d) cloudflare.com" % (DOMAIN, DOH_PORT), resp.status, len(body)))
    if resp.status != 200: fails.append("DoH 入口返回 HTTP %d" % resp.status)
except Exception as e:
    nm = type(e).__name__
    print("  %-34s 错误：%s" % ("DoH 入口", nm))
    if nm in UNWIRED:
        warns.append("DoH 入口未接（127.0.0.1:%d %s）—— nginx 未安装/未 include doh-444.conf" % (DOH_PORT, nm))
    else:
        fails.append("DoH 入口异常：" + nm)

for w in warns: print("  ! %s" % w)
print("\nRESULT: " + ("ALL OK" if not fails else "FAILED -> " + "; ".join(fails)))
sys.exit(1 if fails else 0)
PY
[ $? = 0 ] && ok "解析行为通过" || bad "解析行为未通过（见上）"

# -------------------------------------------------------------------- 5 防火墙
sec "5. 纵深防御（iptables）"
if command -v iptables >/dev/null 2>&1; then
  if iptables -S UNBOUNDB_53 >/dev/null 2>&1; then
    n=$(iptables -S UNBOUNDB_53 | grep -c DROP || true)
    [ "$n" -ge 2 ] && ok "UNBOUNDB_53 已封国内上游明文 53（$n 条）" || warn "UNBOUNDB_53 规则偏少（$n 条）"
  else
    warn "未找到 UNBOUNDB_53 链（--skip-firewall 部署？）"
  fi
else
  warn "无 iptables"
fi

# ----------------------------------------------------------------- 6 发布布局
# 为什么查这个：install.sh 的平铺布局与发布机制（releases/<id> + current）不是一回事。
# 没有 current 时，deploy_release.sh 的回滚与两道门禁全部不可用，但服务照样在跑 ——
# 这种"看起来正常、回滚却无处可回"的状态必须在验收时暴露，而不是等出事才发现。
sec "6. 发布布局（releases/<id> + current）"
if [ -L "$CODE_DIR/current" ]; then
  cur_t="$(readlink -f "$CODE_DIR/current" 2>/dev/null || true)"
  if [ -n "$cur_t" ] && [ -d "$cur_t" ]; then ok "current -> $cur_t"
  else bad "current 软链指向不存在的目录: $cur_t"; fi
  # RELEASE.sha256 自洽（文件被改过则会失败）
  if [ -f "$cur_t/RELEASE.sha256" ]; then
    if ( cd "$cur_t" && sha256sum -c RELEASE.sha256 >/dev/null 2>&1 ); then
      ok "发布清单自校验通过（$(wc -l < "$cur_t/RELEASE.sha256" 2>/dev/null || echo 0) 项）"
    else
      bad "发布清单自校验失败：$cur_t/RELEASE.sha256（文件被改动或清单过期）"
    fi
  else
    warn "当前发布缺 RELEASE.sha256（非 make-release.sh 生成？）"
  fi
  # 两道门禁
  if [ -f "$CODE_DIR/release_consistency.py" ]; then
    if python3 "$CODE_DIR/release_consistency.py" --quiet >/dev/null 2>&1; then
      ok "release_consistency.py 通过（两进程同发布）"
    else
      bad "release_consistency.py 未通过：两进程可能分属不同发布（见该脚本输出）"
    fi
  else
    warn "缺 release_consistency.py，跳过一致性门禁"
  fi
  if [ -f "$CODE_DIR/verify-release-data.py" ]; then
    if python3 "$CODE_DIR/verify-release-data.py" "$cur_t" --quiet >/dev/null 2>&1; then
      ok "verify-release-data.py 通过（F7 清单覆盖 + veto 快照）"
    else
      bad "verify-release-data.py 未通过（见该脚本输出）"
    fi
  else
    warn "缺 verify-release-data.py，跳过发布数据门禁"
  fi
elif [ -e "$CODE_DIR/current" ]; then
  bad "$CODE_DIR/current 存在但不是软链（发布布局被破坏）"
else
  warn "无 current 软链：当前是平铺布局，deploy_release.sh 的回滚/切换不可用"
  warn "  建立发布：sudo bash $CODE_DIR/tools/make-release.sh --migrate-units"
fi
# 发布脚本与门禁脚本是否就位。
# 注意两种布局：install.sh 会把 tools/* 同时铺到 $CODE_DIR/tools/ 与 $CODE_DIR/ 根，
# 而手工迁移的机器往往只有根目录那份 —— 两处都要认，否则会误报「缺少」。
for x in make-release.sh deploy_release.sh release_consistency.py verify-release-data.py; do
  if [ -f "$CODE_DIR/$x" ] || [ -f "$CODE_DIR/tools/$x" ]; then
    ok "存在 $x"
  else
    warn "缺少 $x（发布/回滚能力不完整）"
  fi
done

# --------------------------------------------------------------------- 7 汇总
sec "汇总"
printf '  PASS=%d  FAIL=%d  WARN=%d\n' "$PASS" "$FAIL" "$WARN"
[ "$FAIL" = 0 ] && { printf '  %s验收通过%s\n' "$C_OK" "$C_0"; exit 0; }
printf '  %s存在失败项，请按上面提示排查%s\n' "$C_ERR" "$C_0"
exit 1
