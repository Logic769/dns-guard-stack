#!/bin/bash
# deploy_release.sh —— 2026-10-15 审计 F5：**发布切换 + 一致性门禁 + 失败自动回滚**
#
# 为什么需要它：两份 unit 的 ExecStart 都是 `.../current/...`，而 `systemctl restart`
# 必须在**同一条命令**里重启两者，并且切换软链后必须**证明**两个进程真的落在同一发布上，
# 否则就退回上一个发布（审计 F5：此前的 quarantine 只靠人工，长期错配无人发现）。
#
# 用法：
#   deploy_release.sh <release-id>      # 切换到 releases/<release-id> 并重启 + 门禁
#   deploy_release.sh --rollback <id>   # 同语义（显式回滚）
#   deploy_release.sh --status          # 只跑门禁，不动任何状态
#   deploy_release.sh --list            # 列出可用发布
set -euo pipefail

BASE="${GUARD_BASE:-/opt/dnsguard}"
RELROOT="$BASE/releases"
GATE="$BASE/release_consistency.py"
UNITS="dnsguard dnsguard-verifier"
SLEEP_AFTER_RESTART="${SLEEP_AFTER_RESTART:-8}"
GATE_WAIT_SEC="${GATE_WAIT_SEC:-90}"
GATE_POLL_SEC="${GATE_POLL_SEC:-5}"

log() { echo "[deploy $(date '+%F %T')] $*"; }

# 轮询等待门禁通过。为什么不只用固定 sleep：2026-10-15 首次切换实测，verifier 的
# stats_meta 当时只在 _stats_writer 的 sleep(60) 之后才写 ⇒ 8s 时读到的是**上一轮运行
# 遗留的旧 meta**（旧 pid / 旧 release_id）⇒ 门禁假红灯、误触发自动回滚。
# 现已让 verifier 启动即写 meta；这里再加轮询，容忍进程启动与落盘的秒级延迟。
wait_gate() {
  local i=0 n=$(( GATE_WAIT_SEC / GATE_POLL_SEC ))
  while [ "$i" -lt "$n" ]; do
    if python3 "$GATE" --json >/dev/null 2>&1; then return 0; fi
    sleep "$GATE_POLL_SEC"; i=$((i+1))
  done
  return 1
}

usage() {
  sed -n '2,15p' "$0"
  exit 2
}

gate() {
  if [ ! -x "$GATE" ] && [ ! -f "$GATE" ]; then
    log "门禁脚本缺失：$GATE"
    return 2
  fi
  python3 "$GATE"
}

case "${1:-}" in
  --status)  gate; exit $? ;;
  --list)    ls -1 "$RELROOT"; exit 0 ;;
  --rollback) shift; REL_ID="${1:-}"; [ -n "$REL_ID" ] || usage ;;
  -h|--help|"") usage ;;
  *) REL_ID="$1" ;;
esac

SRC="$RELROOT/$REL_ID"
[ -d "$SRC" ] || { log "发布目录不存在：$SRC"; exit 2; }
[ -f "$SRC/RELEASE.sha256" ] || { log "缺 RELEASE.sha256（拒绝切换未校验的发布）"; exit 2; }

log "① 校验发布内容 sha256（$REL_ID）"
( cd "$SRC" && sha256sum -c RELEASE.sha256 ) || { log "校验失败 ⇒ 不切换"; exit 2; }

VDR="$BASE/verify-release-data.py"
if [ -f "$VDR" ]; then
  log "①b 发布数据校验（F7：清单覆盖 + CN veto 快照内容约束）"
  python3 "$VDR" "$SRC" || { log "发布数据校验未过 ⇒ 不切换"; exit 2; }
else
  log "①b 跳过：缺 $VDR（F7 校验脚本未安装）"
fi

PREV="$(readlink -f "$BASE/current" || true)"
TS="$(date '+%Y%m%d-%H%M%S')"
BK="$BASE/backups/deploy-$TS"
mkdir -p "$BK"
printf '%s\n' "$PREV" > "$BK/prev_current.txt"
printf '%s\n' "$REL_ID" > "$BK/new_release.txt"
log "② 备份当前指向：$PREV → $BK/prev_current.txt"

log "③ 切换 current → $SRC"
ln -sfn "$SRC" "$BASE/current"

log "④ 一条命令重启两个 unit（保证两者都从同一 current 加载）：$UNITS"
systemctl restart $UNITS

log "⑤ 轮询一致性门禁（最多 ${GATE_WAIT_SEC}s，每 ${GATE_POLL_SEC}s 一次，直到两侧 stats_meta 都自证同一发布）"
set +e
if wait_gate; then GATE_RC=0; else GATE_RC=1; fi
gate                       # 无论成败都打印完整门禁报告（失败细节进日志，便于复盘）
set -e
if [ "$GATE_RC" -ne 0 ]; then
  log "门禁未通过（${GATE_WAIT_SEC}s 内未收敛）⇒ 自动回滚到 $PREV"
  ln -sfn "$PREV" "$BASE/current"
  systemctl restart $UNITS
  if wait_gate; then
    log "回滚后门禁已收敛（两侧回到同一发布）"
  else
    log "回滚后门禁未在 ${GATE_WAIT_SEC}s 内收敛；若目标是旧发布，其 verifier meta 最长需 60s 才刷新（已知空窗），可稍后跑 $0 --status 复核"
  fi
  log "回滚完成；请查看 /var/log/dnsguard-guard.log 与 journalctl -u $UNITS"
  exit 1
fi

log "OK 已部署 $REL_ID（上一发布：$PREV；回滚：$0 --rollback $(basename "$PREV")）"
