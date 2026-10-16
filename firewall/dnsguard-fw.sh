#!/bin/bash
# dnsguard-fw.sh — DNS 容器间明文 :53 管控 + 宿主 INPUT 白名单（审计 2026-10-15 F1/F2 重构版）
# ============================================================================
# 相对上一版（sha256 8d4766affa73bee3a10583138e68be3fb0669cf4845f1d01aed6fcf5ce3fdfbb）的改动：
#   F1「只读检查会真改生产规则」：参数解析后**立即**分流；check/print/status 三个只读模式
#      在任何事实收集之前就确定，且写命令统一经 write_guard() 把关（只读模式下调用即 FATAL
#      exit 3）。check 分支不再位于写操作之后。
#   F2「收敛非原子」：放弃逐条 -D/-I/-F/-A，改为
#        iptables-save -c → dnsguard-fw-table.py（纯文本变换 + 生成物自检）→ **单次**
#        iptables-restore -c  → 提交后再校验（失败自动回滚）
#      全表原子替换 ⇒ 不存在「先删后加」的空窗，也不存在子链中途为空。
#   另：地址（容器 IP / docker0 网关）全部来自运行时解析并注入同一份模板，规则文本中不再
#       出现容器 IP 字面量（审计 F4「同一事实多处引用」的统一事实源）。
#
# 用法：
#   dnsguard-fw.sh              # 默认 = --apply（幂等收敛）
#   dnsguard-fw.sh --check      # 只读断言，exit 0/1（2=事实不可得，3=只读模式被越权写）
#   dnsguard-fw.sh --print      # 只回显将要提交的表与命令，不落盘
#   dnsguard-fw.sh --status     # 只读：当前状态 + 最近 5 次历史
#   dnsguard-fw.sh --rollback [备份目录|latest]
# ============================================================================
set -u

TAG="f2-20261010"
CHAIN="UNBOUNDB_53"
CHAIN_A="DNS_A_EGRESS"
TAG53="cn53-fwd"
J_TAG="dnsguard-jump"
PROBE_SRC="172.18.0.99"          # docker0 别名（**非容器 IP**），由 probe-srcaddr.service 施加
NET="172.16.0.0/12"
GW_DEFAULT="172.18.0.1"          # docker0 网关兜底值；正常从内核读取
# 以下路径均可用环境变量覆盖（便于离线 mock 测试与异机演练）
LOCK=${DNSGW_FW_LOCK:-/run/dnsguard-fw.lock}
TABLE_TOOL=${DNSGW_FW_TABLE_TOOL:-/usr/local/sbin/dnsguard-fw-table.py}
BACKUP_ROOT=${DNSGW_FW_BACKUP_ROOT:-/opt/dnsguard/backups/fw}
HIST=${DNSGW_FW_HIST:-/var/log/dnsguard-fw.jsonl}
LOG=${DNSGW_FW_LOG:-/var/log/dnsguard-fw.log}

MODE=apply
RB_ARG=""
case "${1:-}" in
  --check)    MODE=check ;;
  --print)    MODE=print ;;
  --status)   MODE=status ;;
  --apply|"") MODE=apply ;;
  --rollback) MODE=rollback; RB_ARG="${2:-latest}" ;;
  *) echo "dnsguard-fw: 未知参数 ${1}" >&2; exit 2 ;;
esac

log() { printf '[%s] %s\n' "$(date -Is)" "$*"; printf '[%s] %s\n' "$(date -Is)" "$*" >>"$LOG" 2>/dev/null || true; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "dnsguard-fw: 缺少命令 $1" >&2; exit 2; }; }

# 只读模式禁止一切写命令（唯一的写出口都从这里过闸）
write_guard() {
  case "$MODE" in
    check|print|status)
      echo "dnsguard-fw: FATAL 只读模式($MODE)下试图执行写命令：$*" >&2
      echo "dnsguard-fw: 这是实现缺陷（只读检查不得改动生产规则）" >&2
      exit 3 ;;
  esac
  return 0
}

need iptables
need python3
[ -r "$TABLE_TOOL" ] || { echo "dnsguard-fw: 缺少 $TABLE_TOOL" >&2; exit 2; }
case "$MODE" in check|print|apply|status) need docker ;; esac

if [ "$MODE" = apply ] || [ "$MODE" = rollback ]; then
  exec 9>"$LOCK" 2>/dev/null || true
  if command -v flock >/dev/null 2>&1; then
    flock -n 9 || { echo "dnsguard-fw: 已有实例在运行" >&2; exit 2; }
  fi
fi

# ---------- 动态解析（本栈网络 + IPv4 校验）----------
# ⚠️ 容器连的是 docker-compose.yml 里的**自定义 bridge 网络**（默认名 dnsnet），
#    不是 docker 默认的 `bridge` 网络。早先这里写死 `eq $k "bridge"`：只有当 docker0
#    恰好被配成同一网段（生产机历史上如此）时才碰巧可用；任何干净机器上都会解析到
#    空串，导致整表收敛直接 ABORT。现在按网络名解析，并回退到"任意网络里的私网 IPv4"。
DNS_NET=${DNSGUARD_NET:-dnsnet}
A_IP=""; AG_IP=""; B_IP=""; ADGH_IP=""; ALT_IP=""; DCP_IP=""
resolve_into() { # $1=目标变量 $2=容器名 $3=1 必需/0 可选
  local var="$1" name="$2" req="$3" ip
  ip=$(docker inspect -f "{{range \$k,\$v := .NetworkSettings.Networks}}{{if eq \$k \"$DNS_NET\"}}{{\$v.IPAddress}}{{end}}{{end}}" "$name" 2>/dev/null)
  case "$ip" in
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) printf -v "$var" '%s' "$ip"; return 0 ;;
  esac
  # 网络名不一致（或容器多网卡）时的回退：该容器任意一个私网 IPv4
  ip=$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{println $v.IPAddress}}{{end}}' "$name" 2>/dev/null \
       | grep -E '^172\.(1[6-9]|2[0-9]|3[01])\.' | head -1)
  case "$ip" in
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) printf -v "$var" '%s' "$ip"; return 0 ;;
  esac
  if [ "$req" = 1 ]; then
    echo "dnsguard-fw: FATAL 无法解析容器 $name 在 $DNS_NET 网络的 IPv4（得到 '${ip:-<空>}'）⇒ 不改动任何规则" >&2
    return 2
  fi
  echo "dnsguard-fw: WARN 可选容器 $name 解析失败（得到 '${ip:-<空>}'）⇒ 本次不生成其规则" >&2
  return 0
}

resolve_all() {
  local rc=0
  resolve_into A_IP    unbound     1 || rc=2
  resolve_into B_IP    unbound-b   1 || rc=2
  resolve_into AG_IP   aghdq       1 || rc=2
  resolve_into ADGH_IP adgh        1 || rc=2
  # dnscrypt-proxy 必需：CN 分流的 forwarding-rules 把它指向 unbound-b，
  # 缺了这条 allow，deny-b 会把内腿一起丢掉（自检表现为 CN 命中 0/3）。
  resolve_into DCP_IP  dnscrypt-proxy 1 || rc=2
  resolve_into ALT_IP  unbound-alt 0 || true
  # 网关 = guard 的监听地址：优先取本栈网络的网关（容器经它访问宿主上的 guard），
  # 再退 docker0，最后用编译期兜底值。绝不默认信任 docker0（那常是 172.17.0.1）。
  GW_IP=$(docker network inspect "$DNS_NET" -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}' 2>/dev/null || true)
  case "$GW_IP" in 172.1[6-9].*|172.2[0-9].*|172.3[01].*) : ;; *) GW_IP="" ;; esac
  if [ -z "$GW_IP" ]; then
    GW_IP=$(ip -4 -o addr show docker0 2>/dev/null | awk '{split($4,a,"/"); print a[1]; exit}')
  fi
  case "$GW_IP" in 172.1[6-9].*|172.2[0-9].*|172.3[01].*) : ;; *) GW_IP="$GW_DEFAULT" ;; esac
  return $rc
}

table_args() {
  printf -- '--a-ip %s --ag-ip %s --b-ip %s --alt-ip %s --dcp-ip %s --adgh-ip %s --gw %s --net %s --probe-src %s --tag %s --tag53 %s --jtag %s --chain %s --chain-a %s' \
    "$A_IP" "$AG_IP" "$B_IP" "${ALT_IP:-$B_IP}" "${DCP_IP:-172.18.0.9}" "$ADGH_IP" "$GW_IP" "$NET" "$PROBE_SRC" \
    "$TAG" "$TAG53" "$J_TAG" "$CHAIN" "$CHAIN_A"
}

# ============================== --check（只读） ==============================
if [ "$MODE" = check ]; then
  P=0; F=0; W=0
  say(){ printf '  [%s] %s\n' "$1" "$2"; }
  if ! resolve_all; then
    say FAIL "容器 IP 解析失败（$DNS_NET 网络）⇒ 期望规则不可得"
    echo "SUMMARY PASS=0 FAIL=1 WARN=0"
    exit 2
  fi
  # 主判据：整表校验（齐全 / 顺序 / 无重复 / 无旧式残留）
  out=$(iptables-save -c -t filter 2>/dev/null | python3 "$TABLE_TOOL" $(table_args) --verify 2>&1); vrc=$?
  nf=$(printf '%s\n' "$out" | grep -c '^FAIL')
  nw=$(printf '%s\n' "$out" | grep -c '^WARN')
  if [ "$vrc" = 0 ]; then say PASS "整表校验通过（14+15+2+5 条期望规则齐全且顺序正确）"; P=$((P+1))
  else say FAIL "整表校验失败（$nf 项）：$(printf '%s' "$out" | grep -a '^FAIL' | head -3 | tr '\n' ';')"; F=$((F+1)); fi
  [ "$nw" -gt 0 ] && { say WARN "整表校验有 $nw 条告警"; W=$((W+nw)); }
  # 语义层断言（与上一版一致的口径，便于既有运维习惯延续）
  n=$(iptables -S INPUT 2>/dev/null | grep -c -- "$TAG")
  if [ "$n" = "14" ]; then say PASS "INPUT 组完整性：14 条"; P=$((P+1)); else say FAIL "INPUT 组完整性：实际 $n 条（期望 14）"; F=$((F+1)); fi
  la=$(iptables -S DOCKER-USER 2>/dev/null | grep -n -- "$TAG53-allow-a-to-aghdq@" | head -1 | cut -d: -f1)
  ld=$(iptables -S DOCKER-USER 2>/dev/null | grep -n -- "$TAG53-deny-" | head -1 | cut -d: -f1)
  if [ -n "$la" ] && [ -n "$ld" ] && [ "$la" -lt "$ld" ]; then say PASS "顺序：cn53 allow($la) 在 deny($ld) 之前"; P=$((P+1)); else say FAIL "顺序：allow=${la:-无} deny=${ld:-无}"; F=$((F+1)); fi
  miss=""
  for c in "$TAG53-allow-a-to-aghdq@$A_IP>$AG_IP" "$TAG53-allow-dcp-to-b@$DCP_IP>$B_IP" "$TAG53-deny-a@$A_IP" "$TAG53-deny-b@$B_IP" "$TAG53-deny-aghdq@$AG_IP" "$TAG53-deny-alt@$ALT_IP"; do
    iptables -S DOCKER-USER 2>/dev/null | grep -qF -- "$c" || miss="$miss [$c]"
  done
  if [ -z "$miss" ]; then say PASS "期望 IP 与规则一致（漂移检测）"; P=$((P+1)); else say FAIL "漂移：缺$miss"; F=$((F+1)); fi
  nu=$(iptables -S DOCKER-USER 2>/dev/null | grep -cE -- "-j $CHAIN_A( |\$)")
  if [ "$nu" = "1" ]; then say PASS "DNS_A_EGRESS 跳转唯一"; P=$((P+1)); else say FAIL "DNS_A_EGRESS 跳转数=$nu"; F=$((F+1)); fi
  cb=$(iptables -S "$CHAIN" 2>/dev/null | grep -c DROP)
  if [ "$cb" = "2" ]; then say PASS "$CHAIN 2 条 DROP"; P=$((P+1)); else say FAIL "$CHAIN DROP=$cb"; F=$((F+1)); fi
  jb=$(iptables -S DOCKER-USER 2>/dev/null | grep -c -- "$J_TAG-unboundb53")
  if [ "$jb" = "2" ] && [ -n "$ALT_IP" ]; then say PASS "$CHAIN 跳转覆盖 B 与 alt（2 条）"; P=$((P+1))
  elif [ -z "$ALT_IP" ]; then say WARN "alt IP 未解析 ⇒ 其明文 53 出向无约束"; W=$((W+1))
  else say FAIL "$CHAIN 跳转数=$jb（期望 2：B + alt）"; F=$((F+1)); fi
  last=$(iptables -S DOCKER-USER 2>/dev/null | grep '^-A' | tail -1)
  case "$last" in *"-j RETURN") say PASS "DOCKER-USER 末条为 RETURN"; P=$((P+1)) ;; *) say FAIL "DOCKER-USER 末条不是 RETURN：$last"; F=$((F+1)) ;; esac
  gwd=$(ip -4 -o addr show docker0 2>/dev/null | awk '{print $4}')
  say PASS "动态事实：A=$A_IP B=$B_IP aghdq=$AG_IP adgh=$ADGH_IP alt=${ALT_IP:-<无>} docker0=$gwd"
  echo "SUMMARY PASS=$P FAIL=$F WARN=$W"
  [ "$F" -gt 0 ] && exit 1
  exit 0
fi

# ============================== --status（只读） =============================
if [ "$MODE" = status ]; then
  resolve_all || { echo "dnsguard-fw: 容器 IP 解析失败"; exit 2; }
  echo "== dnsguard-fw 状态 =="
  iptables-save -c -t filter 2>/dev/null | python3 "$TABLE_TOOL" $(table_args) --verify 2>&1
  echo "-- 最近 5 次收敛历史（$HIST）--"
  tail -5 "$HIST" 2>/dev/null || echo "(无历史)"
  echo "-- 备份（$BACKUP_ROOT）--"
  ls -1t "$BACKUP_ROOT" 2>/dev/null | head -5 || echo "(无备份)"
  exit 0
fi

# ============================== --print（只读回显） ==========================
if [ "$MODE" = print ]; then
  resolve_all || exit 2
  echo "# 生成新表（纯文本变换，不落盘）："
  echo "#   iptables-save -c -t filter | python3 $TABLE_TOOL $(table_args) > new-filter.rules"
  echo "# 原子提交："
  echo "#   iptables-restore -c new-filter.rules"
  echo "# ---- 我们管理的规则（期望形态）----"
  iptables-save -c -t filter 2>/dev/null | python3 "$TABLE_TOOL" $(table_args) 2>/dev/null | grep -E -- "^-A (INPUT|DOCKER-USER|$CHAIN|$CHAIN_A)" | sed -E 's/^-A /iptables -A /'
  exit 0
fi

# ============================== --rollback ==================================
if [ "$MODE" = rollback ]; then
  if [ "$RB_ARG" = "latest" ]; then
    RB_ARG=$(ls -1dt "$BACKUP_ROOT"/*/ 2>/dev/null | head -1)
  fi
  [ -n "$RB_ARG" ] && [ -f "$RB_ARG/filter.before.rules" ] || { echo "dnsguard-fw: 找不到可回滚的备份（参数='$RB_ARG'）" >&2; exit 2; }
  write_guard iptables-restore
  if iptables-restore -c "$RB_ARG/filter.before.rules"; then
    log "ROLLBACK OK 来源 $RB_ARG/filter.before.rules"
    echo "dnsguard-fw: 已回滚到 $RB_ARG/filter.before.rules"
    exit 0
  fi
  log "ROLLBACK FAIL 来源 $RB_ARG/filter.before.rules"
  echo "dnsguard-fw: 回滚失败" >&2
  exit 1
fi

# ============================== --apply（事务式原子收敛） ====================
resolve_all || { log "ABORT 容器 IP 解析失败，未改动任何规则"; exit 2; }

TMPD=$(mktemp -d /tmp/dnsguard-fw.XXXXXX) || exit 2
trap 'rm -rf "$TMPD"' EXIT
BEFORE="$TMPD/filter.before.rules"; AFTER="$TMPD/filter.after.rules"
TS=$(date +%Y%m%d-%H%M%S)
BK="$BACKUP_ROOT/$TS"

iptables-save -c -t filter >"$BEFORE" 2>/dev/null
[ -s "$BEFORE" ] || { log "ABORT 无法读取当前 filter 表"; exit 2; }

if ! python3 "$TABLE_TOOL" $(table_args) <"$BEFORE" >"$AFTER" 2>"$TMPD/gen.err"; then
  log "ABORT 新表生成/自检失败，规则未改动：$(tr '\n' ' ' <"$TMPD/gen.err")"
  cat "$TMPD/gen.err" >&2
  exit 1
fi
[ -s "$AFTER" ] || { log "ABORT 生成的新表为空"; exit 1; }

mkdir -p "$BK" || { log "ABORT 无法创建备份目录 $BK"; exit 2; }
cp "$BEFORE" "$BK/filter.before.rules"
cp "$AFTER"  "$BK/filter.after.rules"
printf '%s\n' "$BK" >"$BACKUP_ROOT/latest.txt" 2>/dev/null || true

write_guard iptables-restore
if ! iptables-restore -c "$AFTER"; then
  log "COMMIT FAIL iptables-restore 拒绝新表（内核表保持原样）备份=$BK"
  echo "dnsguard-fw: 提交失败；生产规则未改变（备份 $BK）" >&2
  exit 1
fi
log "COMMIT OK 原子替换完成（备份 $BK）"

if ! iptables-save -c -t filter 2>/dev/null | python3 "$TABLE_TOOL" $(table_args) --verify >/dev/null 2>&1; then
  log "POSTCHECK FAIL 提交后校验未通过 ⇒ 自动回滚到 $BK/filter.before.rules"
  echo "dnsguard-fw: 提交后校验失败，正在自动回滚" >&2
  if iptables-restore -c "$BK/filter.before.rules"; then
    log "ROLLBACK OK 已恢复到收敛前状态"
    echo "dnsguard-fw: 已回滚"
  else
    log "ROLLBACK FAIL 需人工介入：iptables-restore -c $BK/filter.before.rules"
    echo "dnsguard-fw: 回滚失败，需人工介入（$BK/filter.before.rules）" >&2
  fi
  exit 1
fi

{
  rh=$(iptables-save -c -t filter 2>/dev/null | sha256sum | cut -d' ' -f1)
  printf '{"ts":"%s","trigger":"%s","rc":0,"mode":"atomic-restore","ips":{"unbound":"%s","unbound-b":"%s","aghdq":"%s","adgh":"%s","unbound-alt":"%s","gw":"%s"},"backup":"%s","rules_sha256":"%s"}\n' \
    "$(date -Is)" "${DNSGW_FW_TRIGGER:-manual}" "$A_IP" "$B_IP" "$AG_IP" "$ADGH_IP" "$ALT_IP" "$GW_IP" "$BK" "$rh" \
    >>"$HIST" 2>/dev/null || true
}
echo "dnsguard-fw: 原子收敛完成 INPUT $(iptables -S INPUT 2>/dev/null | grep -c -- "$TAG") 条 / $CHAIN $(iptables -S "$CHAIN" 2>/dev/null | grep -c DROP) 条 DROP / 跳转 $(iptables -S DOCKER-USER 2>/dev/null | grep -c -- "$J_TAG") 条 / 容器间:53 $(iptables -S DOCKER-USER 2>/dev/null | grep -c -- "$TAG53") 条 / 备份 $BK"
exit 0
