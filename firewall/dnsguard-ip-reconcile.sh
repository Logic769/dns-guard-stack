#!/bin/bash
# dnsguard-ip-reconcile.sh — 解析链路容器 IP / docker0 网关 漂移收敛（审计 §3.3）
# ============================================================================
# 审计 §3.3 原文：「防火墙已有动态 IP reconcile，不能误报成"完全没有 IP 漂移处理"。
# 但 Nginx DoT 仍直写 172.18.0.2:53，A 的转发仍直写 172.18.0.6@53，AGH 到 guard 也
# 固定 bridge 地址。容器重建导致 IP 改变时，重建防火墙不等于更新解析链路。」
#
# 本脚本负责**解析链路**（与负责 iptables 的 dnsguard-fw.sh 分工，互不覆盖）：
#   ① nginx DoT 853 → AGH 容器       : /www/server/panel/vhost/nginx/tcp/dns-example-dot-853.conf
#   ② unbound A 转发 → aghdq 容器    : /opt/unbound/unbound.conf
#   ③ dotfront-spool 目标/网关 → AGH : systemd drop-in（本脚本维护，不改主 unit）
#   ④ AGH 上游 guard / 宿主网关      : /opt/adgh/conf/AdGuardHome.yaml
#   ⑤ guard 监听地址 → docker0 网关  : dnsguard.service.d/zzzzzz-consolidated-20261010.conf
#   ⑥ docker0 探针源地址别名         : probe-srcaddr.service（<gw 网段>.0.99/16）
# 做法：把以上 6 处收敛到 docker **实际分配值**；无差异 ⇒ 零副作用退出 0 ✓
# F_* 语义：0=一致；1=有漂移（本次已/可自动收敛）；2=需人工（期望模式或文件缺失，不自动改写）
# 幂等：--check 与 --apply 共用同一段比对；apply 前一律备份，失败自动还原 ✓
#
# 用法：dnsguard-ip-reconcile.sh [--check|--apply|--print]
#   --check  只报告（exit 0 一致 / 1 有差异 / 2 前置条件不足）
#   --apply  备份 → 改写 → 语法校验 → 热重载（默认）
#   --print  只回显将执行的改写与重载命令（不落盘、不重载）
# 退出码：0 一致或已收敛；1 有差异（check 模式）；2 解析失败/前置条件不足（**不动任何文件**）
# ============================================================================
set -u

TS="$(date +%Y%m%d-%H%M%S)"
BASE=/opt/dnsguard
BK="$BASE/backups/ip-reconcile-$TS"
LOCK=/run/dnsguard-ip-reconcile.lock

NGX_CONF=/www/server/panel/vhost/nginx/tcp/dns-example-dot-853.conf
UNB_CONF=/opt/unbound/unbound.conf
AGH_YAML=/opt/adgh/conf/AdGuardHome.yaml
DOTF_DROPIN_DIR=/etc/systemd/system/dotfront-spool.service.d
DOTF_DROPIN="$DOTF_DROPIN_DIR/20-ip-reconcile.conf"
GUARD_DROPIN=/etc/systemd/system/dnsguard.service.d/zzzzzz-consolidated-20261010.conf
PROBE_UNIT=/etc/systemd/system/probe-srcaddr.service

MODE=apply
case "${1:-}" in
  --check) MODE=check ;;
  --apply) MODE=apply ;;
  --print) MODE=print ;;
  "")      MODE=apply ;;
  *) echo "dnsguard-ip-reconcile: 未知参数 ${1}" >&2; exit 2 ;;
esac

log() { printf '%s dnsguard-ip-reconcile[%s]: %s\n' "$(date '+%F %T')" "$$" "$*"; }

need() { command -v "$1" >/dev/null 2>&1 || { log "缺少命令 $1 ⇒ 退出"; exit 2; }; }
need docker
[ "$MODE" = print ] || need sed
[ "$MODE" = print ] || need ip

if [ "$MODE" != print ] && command -v flock >/dev/null 2>&1; then
  exec 9>"$LOCK" 2>/dev/null || true
  flock -n 9 || { log "已有实例在运行 ⇒ 退出"; exit 2; }
fi

# ---------- 事实源：docker 实际分配 ----------
resolve() {  # $1=容器名 → bridge 网络 IPv4（解析失败输出空）
  docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{if eq $k "bridge"}}{{$v.IPAddress}}{{end}}{{end}}' "$1" 2>/dev/null
}
valid4() { case "${1:-}" in 172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;; *) return 1 ;; esac; }

AGH_IP=$(resolve adgh)
AGHDQ_IP=$(resolve aghdq)
A_IP=$(resolve unbound)
GW_IP=$(ip -4 -o addr show docker0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)

for pair in "adgh:${AGH_IP:-}" "aghdq:${AGHDQ_IP:-}" "unbound:${A_IP:-}" "docker0:${GW_IP:-}"; do
  name="${pair%%:*}"; val="${pair#*:}"
  if ! valid4 "$val"; then
    log "FATAL 无法解析 ${name} 的 IPv4（得到 '${val:-<空>}'）⇒ **不改动任何文件**，退出 2"
    exit 2
  fi
done
log "解析结果：adgh=$AGH_IP aghdq=$AGHDQ_IP unbound(A)=$A_IP docker0-gw=$GW_IP（mode=$MODE）"

# ---------- 比对 ----------
F_NGX=0; F_UNB=0; F_DOTF=0; F_AGH=0; F_GL=0; F_PS=0
REP_NGX=""; REP_UNB=""; REP_DOTF=""; REP_AGH=""

# ① nginx DoT → adgh
if [ -f "$NGX_CONF" ]; then
  CUR=$(grep -oE 'proxy_pass[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:53;' "$NGX_CONF" 2>/dev/null \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  if [ -z "${CUR:-}" ]; then
    log "FAIL $NGX_CONF 未找到 'proxy_pass <ip>:53;' ⇒ 期望模式缺失，不自动改写（需人工）"
    F_NGX=2
  elif [ "$CUR" = "$AGH_IP" ]; then
    log "OK   ① nginx DoT proxy_pass = $CUR（= adgh）"
  else
    log "DIFF ① nginx DoT proxy_pass $CUR ≠ adgh($AGH_IP)"
    F_NGX=1
    REP_NGX="s#(proxy_pass[[:space:]]+)[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:53;)#\1${AGH_IP}\2#"
  fi
else
  log "FAIL 缺少 $NGX_CONF ⇒ 解析链路 ① 无法核对（需人工）"
  F_NGX=2
fi

# ② unbound A → aghdq
if [ -f "$UNB_CONF" ]; then
  CUR=$(grep -oE 'forward-addr:[[:space:]]*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+@53' "$UNB_CONF" 2>/dev/null \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  if [ -z "${CUR:-}" ]; then
    log "FAIL $UNB_CONF 未找到 'forward-addr: <ip>@53' ⇒ 期望模式缺失，不自动改写（需人工）"
    F_UNB=2
  elif [ "$CUR" = "$AGHDQ_IP" ]; then
    log "OK   ② unbound(A) forward-addr = $CUR@53（= aghdq）"
  else
    log "DIFF ② unbound(A) forward-addr $CUR@53 ≠ aghdq($AGHDQ_IP)"
    F_UNB=1
    REP_UNB="s#(forward-addr:[[:space:]]*)[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(@53)#\1${AGHDQ_IP}\2#"
  fi
else
  log "FAIL 缺少 $UNB_CONF ⇒ 解析链路 ② 无法核对（需人工）"
  F_UNB=2
fi

# ③ dotfront-spool drop-in → adgh / 网关
if [ -f "$DOTF_DROPIN" ]; then
  CD=$(grep -oE '^Environment=DOTF_DST=.*' "$DOTF_DROPIN" | head -1 | cut -d= -f3)
  CG=$(grep -oE '^Environment=DOTF_GW=.*'  "$DOTF_DROPIN" | head -1 | cut -d= -f3)
  if [ "${CD:-}" = "$AGH_IP" ] && [ "${CG:-}" = "$GW_IP" ]; then
    log "OK   ③ dotfront-spool drop-in DOTF_DST=$CD DOTF_GW=$CG"
  else
    log "DIFF ③ dotfront-spool drop-in DOTF_DST=${CD:-<无>} DOTF_GW=${CG:-<无>} ≠ adgh($AGH_IP)/gw($GW_IP)"
    F_DOTF=1
  fi
else
  log "DIFF ③ dotfront-spool drop-in 不存在 ⇒ 将创建（DOTF_DST=$AGH_IP DOTF_GW=$GW_IP）"
  F_DOTF=1
fi

# ④ AGH 上游 guard（宿主网关:5355）
if [ -f "$AGH_YAML" ]; then
  CUR=$(grep -oE '^[[:space:]]+-[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:5355' "$AGH_YAML" 2>/dev/null \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  if [ -z "${CUR:-}" ]; then
    log "FAIL $AGH_YAML 未找到 '<ip>:5355' 上游 ⇒ 期望模式缺失，不自动改写（需人工）"
    F_AGH=2
  elif [ "$CUR" = "$GW_IP" ]; then
    log "OK   ④ AGH 上游 = $CUR:5355（= docker0 网关）"
  else
    log "DIFF ④ AGH 上游 $CUR:5355 ≠ docker0 网关($GW_IP)"
    F_AGH=1
  fi
else
  log "FAIL 缺少 $AGH_YAML ⇒ 解析链路 ④ 无法核对（需人工）"
  F_AGH=2
fi

# ⑤ dnsguard 监听地址 → docker0 网关
GUARD_DROPIN_IP=$(grep -oE '^Environment=GUARD_LISTEN_HOST=[0-9.]+' "$GUARD_DROPIN" 2>/dev/null | tail -1 | cut -d= -f3)
if [ ! -f "$GUARD_DROPIN" ]; then
  log "FAIL ⑤ 缺少 $GUARD_DROPIN ⇒ guard 监听地址无法核对（需人工）"
  F_GL=2
elif [ -z "${GUARD_DROPIN_IP:-}" ]; then
  log "FAIL ⑤ $GUARD_DROPIN 未找到 'Environment=GUARD_LISTEN_HOST=<ip>'（期望 $GW_IP）⇒ 不自动改写（需人工）"
  F_GL=2
elif [ "$GUARD_DROPIN_IP" = "$GW_IP" ]; then
  log "OK   ⑤ dnsguard GUARD_LISTEN_HOST = $GUARD_DROPIN_IP（= docker0 网关）"
else
  log "DIFF ⑤ dnsguard GUARD_LISTEN_HOST $GUARD_DROPIN_IP ≠ docker0 网关($GW_IP)"
  F_GL=1
  REP_GL="s#^Environment=GUARD_LISTEN_HOST=[0-9.]+#Environment=GUARD_LISTEN_HOST=${GW_IP}#"   # 零反向引用：避免 \1 后紧跟数字被 sed 解析为 \1172 之类
fi

# ⑥ docker0 探针源地址别名（probe-srcaddr.service）
PROBE_EXPECT="${GW_IP%.*}.99"
PROBE_ADDRS=$(grep -oE 'ip addr (replace|del) [0-9.]+/16' "$PROBE_UNIT" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u)
if [ ! -f "$PROBE_UNIT" ]; then
  log "FAIL ⑥ 缺少 $PROBE_UNIT ⇒ 探针源地址无法核对（需人工）"
  F_PS=2
elif [ -z "${PROBE_ADDRS:-}" ]; then
  log "FAIL ⑥ $PROBE_UNIT 未找到 'ip addr replace|del <ip>/16'（期望 $PROBE_EXPECT）⇒ 不自动改写（需人工）"
  F_PS=2
elif [ "$PROBE_ADDRS" = "$PROBE_EXPECT" ]; then
  log "OK   ⑥ probe-srcaddr 源地址 = $PROBE_ADDRS/16"
else
  log "DIFF ⑥ probe-srcaddr 源地址 $(printf '%s ' $PROBE_ADDRS)≠ 期望 $PROBE_EXPECT（跟随 docker0 网段）"
  F_PS=1
REP_PS="s#^ExecStart=/usr/sbin/ip addr replace [0-9.]+/16( .*)?\$#ExecStart=/usr/sbin/ip addr replace ${PROBE_EXPECT}/16\1#; s#^ExecStop=/usr/sbin/ip addr del [0-9.]+/16( .*)?\$#ExecStop=/usr/sbin/ip addr del ${PROBE_EXPECT}/16\1#"
fi

TOTAL=$((F_NGX + F_UNB + F_DOTF + F_AGH + F_GL + F_PS))
if [ "$TOTAL" -eq 0 ]; then
  log "结果：解析链路 6 项全部与 docker 实际分配一致 ⇒ 无需动作"
  exit 0
fi
log "结果：发现 $TOTAL 处待处理（nginx=$F_NGX unbound=$F_UNB dotfront=$F_DOTF agh=$F_AGH guard=$F_GL probe=$F_PS；值 2=需人工、不自动改写）"

if [ "$MODE" = check ]; then
  log "check 模式：只报告不修改 ⇒ 退出 1"
  exit 1
fi

# ---------- print 模式：只回显 ----------
if [ "$MODE" = print ]; then
  [ "$F_NGX" = 1 ]  && printf 'sed -i -E "%s" %s\n' "$REP_NGX" "$NGX_CONF"
  [ "$F_UNB" = 1 ]  && printf 'sed -i -E "%s" %s\n' "$REP_UNB" "$UNB_CONF"
  [ "$F_DOTF" = 1 ] && printf 'write %s (DOTF_DST=%s DOTF_GW=%s)\nsystemctl daemon-reload && systemctl restart dotfront-spool\n' "$DOTF_DROPIN" "$AGH_IP" "$GW_IP"
  [ "$F_AGH" = 1 ]  && printf 'python3 改 %s: <ip>:5355 → %s:5355 && docker restart adgh\n' "$AGH_YAML" "$GW_IP"
  [ "$F_GL" = 1 ]   && printf 'sed -i -E "%s" %s && systemctl daemon-reload && systemctl restart dnsguard\n' "$REP_GL" "$GUARD_DROPIN"
  [ "$F_PS" = 1 ]   && printf 'sed -i -E "%s" %s && systemctl daemon-reload && systemctl restart probe-srcaddr\n' "$REP_PS" "$PROBE_UNIT"
  exit 0
fi

# ---------- apply ----------
mkdir -p "$BK" || { log "FATAL 无法创建备份目录 $BK"; exit 2; }
log "备份目录：$BK"

rollback() {  # $1=文件 $2=说明
  if [ -f "$BK/$(basename "$1")" ]; then
    cp -a "$BK/$(basename "$1")" "$1" && log "已还原 $1（$2）"
  fi
}

# ① nginx
if [ "$F_NGX" = 1 ]; then
  cp -a "$NGX_CONF" "$BK/" && sed -i -E "$REP_NGX" "$NGX_CONF"
  if nginx -t >/dev/null 2>&1; then
    if nginx -s reload; then log "① nginx proxy_pass 已收敛为 $AGH_IP:53 并 reload 成功"; F_NGX=0
    else rollback "$NGX_CONF" "reload 失败"; nginx -s reload 2>/dev/null; fi
  else
    log "FATAL nginx -t 失败 ⇒ 还原配置"
    rollback "$NGX_CONF" "nginx -t 失败"
  fi
fi

# ② unbound A
if [ "$F_UNB" = 1 ]; then
  cp -a "$UNB_CONF" "$BK/" && sed -i -E "$REP_UNB" "$UNB_CONF"
  ok=0
  if docker exec unbound unbound-checkconf >/dev/null 2>&1; then ok=1
  else
    rc=$?
    case "$rc" in
      125|126|127) log "FAIL ② unbound-checkconf 无法执行（docker exec rc=$rc，容器不可用）⇒ 拒绝热重载并还原" ;;
      *)           log "FAIL ② unbound-checkconf 语法校验失败（rc=$rc）⇒ 拒绝热重载并还原" ;;
    esac
    ok=0
  fi
  if [ "$ok" = 1 ]; then
    if docker exec unbound unbound-control reload >/dev/null 2>&1; then
      log "② unbound(A) forward-addr 已收敛为 ${AGHDQ_IP}@53（unbound-control reload）"; F_UNB=0
    elif docker kill -s HUP unbound >/dev/null 2>&1; then
      log "② unbound(A) forward-addr 已收敛为 ${AGHDQ_IP}@53（SIGHUP）"; F_UNB=0
    else
      log "WARN 热重载失败 ⇒ 改用 docker restart unbound"
docker restart unbound >/dev/null 2>&1 && { log "② unbound(A) 已重启生效"; F_UNB=0; } || rollback "$UNB_CONF" "restart 失败"
    fi
  else
    rollback "$UNB_CONF" "配置语法失败"
  fi
fi

# ③ dotfront-spool drop-in
if [ "$F_DOTF" = 1 ]; then
  mkdir -p "$DOTF_DROPIN_DIR"
  [ -f "$DOTF_DROPIN" ] && cp -a "$DOTF_DROPIN" "$BK/"
  cat > "$DOTF_DROPIN" <<EOF
# §3.3 解析链路容器 IP 漂移收敛（dnsguard-ip-reconcile.sh 维护，生成于 $TS）
# 覆盖主 unit 的 DOTF_DST / DOTF_GW：容器 IP 或 docker0 网关变化时由该脚本改写
[Service]
Environment=DOTF_DST=$AGH_IP
Environment=DOTF_GW=$GW_IP
EOF
  systemctl daemon-reload
  if systemctl restart dotfront-spool && systemctl is-active --quiet dotfront-spool; then
    log "③ dotfront-spool 已按 DOTF_DST=$AGH_IP 重启并处于 active"; F_DOTF=0
  else
    log "WARN dotfront-spool 重启后未 active ⇒ 还原 drop-in"
    rm -f "$DOTF_DROPIN"; systemctl daemon-reload; systemctl restart dotfront-spool >/dev/null 2>&1
  fi
fi

# ④ AGH 上游
if [ "$F_AGH" = 1 ]; then
  cp -a "$AGH_YAML" "$BK/"
  python3 - "$AGH_YAML" "$GW_IP" <<'PY'
import io, re, sys
path, gw = sys.argv[1], sys.argv[2]
data = io.open(path, encoding="utf-8").read()
new = re.sub(r"(^[ \t]*-[ \t]+)\d+\.\d+\.\d+\.\d+(:5355)", r"\g<1>%s\g<2>" % gw, data, flags=re.M)
io.open(path, "w", encoding="utf-8").write(new)
sys.exit(0 if new != data else 3)
PY
  rc=$?
  if [ "$rc" = 0 ]; then
    if docker restart adgh >/dev/null 2>&1; then
      log "④ AGH 上游已收敛为 ${GW_IP}:5355 并重启容器"; F_AGH=0
    else
      rollback "$AGH_YAML" "adgh restart 失败"
    fi
  else
    log "WARN ④ AGH yaml 未发生预期替换 ⇒ 还原"
    rollback "$AGH_YAML" "替换失败"
  fi
fi

# ⑤ dnsguard 监听地址（需重启 guard ⇒ 顺带复核发布一致性门禁）
if [ "$F_GL" = 1 ]; then
  cp -a "$GUARD_DROPIN" "$BK/" && sed -i -E "$REP_GL" "$GUARD_DROPIN"
  systemctl daemon-reload
  if systemctl restart dnsguard && sleep 2 && systemctl is-active --quiet dnsguard; then
    if grep -qE "^Environment=GUARD_LISTEN_HOST=${GW_IP}$" "$GUARD_DROPIN"; then
      log "⑤ dnsguard 已按 GUARD_LISTEN_HOST=$GW_IP 重启并 active（文件校验通过）"; F_GL=0
    else
      log "FAIL ⑤ 改写后 $GUARD_DROPIN 未收敛为 $GW_IP（sed 未匹配）⇒ 还原 drop-in 并重启"
      rollback "$GUARD_DROPIN" "sed 未生效"; systemctl daemon-reload; systemctl restart dnsguard >/dev/null 2>&1
    fi
    if [ -x /opt/dnsguard/release_consistency.py ] && ! python3 /opt/dnsguard/release_consistency.py --quiet >/dev/null 2>&1; then
      log "WARN ⑤ dnsguard 重启后发布一致性门禁未通过 ⇒ 请查看 release_consistency.py 输出"
    fi
  else
    log "FAIL ⑤ dnsguard 重启后未 active ⇒ 还原 drop-in 并重启"
    rollback "$GUARD_DROPIN" "dnsguard 重启失败"; systemctl daemon-reload; systemctl restart dnsguard >/dev/null 2>&1
  fi
fi

# ⑥ probe-srcaddr（oneshot：restart = ExecStop 删旧地址 + ExecStart 加新地址）
if [ "$F_PS" = 1 ]; then
  cp -a "$PROBE_UNIT" "$BK/" && sed -i -E "$REP_PS" "$PROBE_UNIT"
  systemctl daemon-reload
  if systemctl restart probe-srcaddr && systemctl is-active --quiet probe-srcaddr; then
    if grep -qE "ip addr (replace|del) ${PROBE_EXPECT}/16" "$PROBE_UNIT"; then
      log "⑥ probe-srcaddr 已按 $PROBE_EXPECT/16 生效（文件校验通过）"; F_PS=0
    else
      log "FAIL ⑥ 改写后 $PROBE_UNIT 仍无 $PROBE_EXPECT/16（sed 未匹配）⇒ 还原 unit"
      rollback "$PROBE_UNIT" "sed 未生效"; systemctl daemon-reload; systemctl restart probe-srcaddr >/dev/null 2>&1
    fi
  else
    log "FAIL ⑥ probe-srcaddr 重启后未 active ⇒ 还原 unit"
    rollback "$PROBE_UNIT" "probe-srcaddr 重启失败"; systemctl daemon-reload; systemctl restart probe-srcaddr >/dev/null 2>&1
  fi
fi

# F_* = 1 表示仍有未收敛漂移；= 2 表示需人工（不自动改写）；成功收敛或本身就一致时为 0
LEFT=$((F_NGX + F_UNB + F_DOTF + F_AGH + F_GL + F_PS))
if [ "$LEFT" -gt 0 ]; then
  log "结果：仍有 $LEFT 处未收敛（留有备份 $BK）⇒ 退出 1"
  exit 1
fi
# 复检 ⑥：docker0 上的 /16 别名只允许「网关」与「探针源」
EXTRA_ALIAS=$(ip -4 addr show docker0 2>/dev/null | grep -oE 'inet [0-9.]+/16' | awk '{print $2}' | grep -v -e "^${GW_IP}/16$" -e "^${PROBE_EXPECT}/16$" || true)
if [ -n "${EXTRA_ALIAS:-}" ]; then
  log "FAIL 复检 ⑥ docker0 存在意外别名：$(printf '%s ' $EXTRA_ALIAS)⇒ 不自动删除（需人工 ip addr del）"
  LEFT=$((LEFT + 1))
else
  log "复检 ⑥ docker0 别名仅 ${GW_IP}/16 与 ${PROBE_EXPECT}/16 ✓"
fi

log "结果：全部漂移已收敛并通过语法/服务校验（备份 $BK）"
exit 0
