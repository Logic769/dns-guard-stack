#!/usr/bin/env bash
# =============================================================================
# make-release.sh —— 构建可切换 / 可回滚的发布目录
# -----------------------------------------------------------------------------
# 为什么需要它：deploy_release.sh 与两道门禁（release_consistency.py /
# verify-release-data.py）都要求 releases/<id>/ 下已存在自洽的
# RELEASE.sha256 与 .files，而仓库原先没有任何脚本生成这套布局 ——
# 全新安装后 install.sh 提示的 `deploy_release.sh --rollback <release-id>`
# 必然报「发布目录不存在」。本脚本补上这一环。
#
# 用法：
#   tools/make-release.sh [release-id] [选项]
#
#   release-id            省略则用 UTC+本地时间戳 <YYYYMMDD-HHMMSS>
#   --code-dir DIR        代码来源（默认 $CODE_DIR，即 install.sh 的平铺结果）
#   --lists-dir DIR       名单目录（默认 $LISTS_DIR）
#   --base DIR            发布根（默认 $CODE_DIR；生成 $BASE/releases/<id>）
#   --no-switch           只构建，不切换 current 软链
#   --migrate-units       把两个 unit 的 ExecStart/WorkingDirectory 从平铺路径
#                         改写到 <base>/current（install.sh 默认是平铺布局；
#                         不改写的话 current 软链对服务不生效，发布机制形同虚设）
#   --dry-run             只打印动作
#
# 生成内容（与生产发布一致）：
#   code : guard.py verifier.py alt_adapter.py answer_policy.py
#          unbound-alt-readiness.py upstreams.json
#   list : cn-trust-allow.txt cn-trust-exceptions.txt cn-veto.snapshot.txt
#   meta : .files  RELEASE.sha256  RELEASE
#
# 退出码：0 成功；1 前置缺失；2 校验未过
# =============================================================================
set -Eeuo pipefail

C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_DIM=$'\033[2m'; C_0=$'\033[0m'
step() { printf '\n%s==> %s%s\n' "$C_OK" "$*" "$C_0"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '%s[warn]%s %s\n' "$C_WARN" "$C_0" "$*"; }
die()  { printf '%s[error]%s %s\n' "$C_ERR" "$C_0" "$*" >&2; exit 1; }

# 本栈默认与 .env 一致；全部可用参数覆盖，便于测试环境
: "${CODE_DIR:=/opt/dnsguard}"
: "${LISTS_DIR:=/opt/dnscrypt-proxy}"

REL_ID=""
BASE="${CODE_DIR}"
SRC_CODE="${CODE_DIR}"
SRC_LISTS="${LISTS_DIR}"
SWITCH=1
DRY=0
MIGRATE_UNITS=0

while [ $# -gt 0 ]; do
  case "$1" in
    --code-dir)      SRC_CODE="${2:?}"; shift 2 ;;
    --lists-dir)     SRC_LISTS="${2:?}"; shift 2 ;;
    --base)          BASE="${2:?}"; shift 2 ;;
    --no-switch)     SWITCH=0; shift ;;
    --migrate-units) MIGRATE_UNITS=1; shift ;;
    --dry-run)       DRY=1; shift ;;
    -h|--help)   sed -n '2,30p' "$0"; exit 0 ;;
    -*)          die "未知参数：$1（-h 看用法）" ;;
    *)           [ -z "$REL_ID" ] || die "只接受一个 release-id（已有 $REL_ID）"; REL_ID="$1"; shift ;;
  esac
done

# 发布 ID：默认时间戳；路径安全字符校验（它会成为目录名，也会显示在看板与元数据里）
[ -n "$REL_ID" ] || REL_ID="$(date +%Y%m%d-%H%M%S)"
case "$REL_ID" in
  *[!A-Za-z0-9._-]*|.*|*..*|*/*) die "release-id 含不安全字符：$REL_ID" ;;
esac

REL="$BASE/releases/$REL_ID"
CUR="$BASE/current"

# 清单：与生产发布逐字一致（顺序也保持，便于人工比对）
CODE_FILES="guard.py verifier.py alt_adapter.py answer_policy.py unbound-alt-readiness.py upstreams.json"
LIST_FILES="cn-trust-allow.txt cn-trust-exceptions.txt cn-veto.snapshot.txt"

run() { if [ "$DRY" = 1 ]; then printf '    %s$ %s%s\n' "$C_DIM" "$*" "$C_0"; else eval "$@"; fi; }

step "前置检查"
[ -f "$SRC_CODE/guard.py" ]   || die "找不到 $SRC_CODE/guard.py（用 --code-dir 指定已部署的代码目录）"
[ -f "$SRC_CODE/verifier.py" ] || die "找不到 $SRC_CODE/verifier.py"
# cn-veto.snapshot.txt 是 F7 的硬要求：它由 refresh-cn-veto-ip.py 写在 veto 文件同目录
if [ ! -s "$SRC_CODE/cn-veto.snapshot.txt" ]; then
  warn "缺少 $SRC_CODE/cn-veto.snapshot.txt"
  warn "先跑：python3 $SRC_CODE/tools/refresh-cn-veto-ip.py --force"
  die "缺否决策略快照，拒绝构建发布（防发布门禁形同虚设）"
fi
for f in cn-trust-allow.txt cn-trust-exceptions.txt; do
  [ -f "$SRC_LISTS/$f" ] || die "找不到 $SRC_LISTS/$f（用 --lists-dir 指定名单目录）"
done
info "release-id  $REL_ID"
info "代码来源    $SRC_CODE"
info "名单来源    $SRC_LISTS"
info "发布目录    $REL"

step "组装发布目录"
run "install -d -m 0755 '$REL'"
for f in $CODE_FILES; do
  run "install -m 0644 '$SRC_CODE/$f' '$REL/$f'"
done
for f in $LIST_FILES; do
  case "$f" in
    cn-veto.snapshot.txt) run "install -m 0644 '$SRC_CODE/$f' '$REL/$f'" ;;
    *)                    run "install -m 0644 '$SRC_LISTS/$f' '$REL/$f'" ;;
  esac
done
run "printf '%s\\n' '$REL_ID' > '$REL/RELEASE'"

step "生成清单 .files 与 RELEASE.sha256"
# 注意：run() 走 eval，故这里不使用它 —— 单引号会阻止 $REL 展开，
# 曾实测生成出字面名为 "$REL/.files" 的文件。以下用直接 shell + DRY 分支。
if [ "$DRY" = 1 ]; then
  info "将写入 .files（$(printf '%s\n' $CODE_FILES $LIST_FILES | wc -l) 个代码/名单项 + .files 自身）"
  info "将写入 RELEASE.sha256 与 RELEASE"
else
  # .files 必须早于 RELEASE.sha256 生成：它自身也进清单。
  # 顺序与生产发布逐字一致（LC_ALL=C 排序后 .files 落在 cn-* 之前）。
  {
    for f in $CODE_FILES $LIST_FILES; do printf '%s\n' "$f"; done
    printf '%s\n' '.files'
  } | LC_ALL=C sort > "$REL/.files"
  printf '%s\n' "$REL_ID" > "$REL/RELEASE"
  # 只对清单里列出的文件求哈希（顺序按 .files，便于人工比对）
  ( cd "$REL" && LC_ALL=C xargs -a .files sha256sum > RELEASE.sha256 )
  info ".files 与 RELEASE.sha256 已生成（$(wc -l < "$REL/RELEASE.sha256") 项）"
fi

step "校验发布"
if [ "$DRY" = 1 ]; then
  info "（dry-run：跳过校验）"
else
  ( cd "$REL" && sha256sum -c RELEASE.sha256 >/dev/null ) || die "RELEASE.sha256 自校验失败"
  info "RELEASE.sha256 自校验 OK（$(wc -l < "$REL/RELEASE.sha256") 项）"
  # 数据门禁：清单覆盖 + CN veto 快照内容约束（F7）
  VDR="$BASE/verify-release-data.py"
  [ -f "$VDR" ] || VDR="$(dirname "$0")/verify-release-data.py"
  if [ -f "$VDR" ]; then
    python3 "$VDR" "$REL" --quiet || die "发布数据校验未过（见上方输出）"
    info "发布数据校验 OK（verify-release-data.py）"
  else
    warn "缺 verify-release-data.py，跳过 F7 数据校验"
  fi
fi

# ---------------------------------------------------------------- units 迁移
# install.sh 默认把 unit 写成平铺路径（ExecStart=/opt/dnsguard/guard.py）。
# 只要 unit 还指平铺路径，current 软链就不会被任何进程使用 —— 发布/回滚/门禁全部空转。
# 这里把两份 unit（含 drop-in）里的 <base> 平铺路径改写到 <base>/current。
migrate_units() {
  # 判定必须看**最终生效值**，不能只看基础单元：
  # drop-in 里常写「ExecStart=（清空）+ ExecStart=...current/guard.py」，
  # 基础单元那段平铺 ExecStart 会被覆盖 —— 此时再改基础单元是多余动作，
  # 且会掩盖真正的布局问题（实测生产就是这种形态）。
  local unit f flat=""
  for unit in dnsguard dnsguard-verifier; do
    local eff
    eff="$(systemctl show "$unit" -p ExecStart 2>/dev/null | grep -o 'argv\[\]=[^;]*' || true)"
    if printf '%s' "$eff" | grep -q "current/"; then
      info "$unit 已指向 current 布局（ExecStart 生效值），跳过迁移"
      continue
    fi
    if printf '%s' "$eff" | grep -qE "$BASE/(guard|verifier)\.py"; then
      flat="$flat $unit"
    fi
  done
  if [ -z "$flat" ]; then
    if [ "$DRY" = 1 ]; then
      info "无需迁移（两个 unit 均已是 current 布局，或未安装）"
    fi
    return 0
  fi
  info "需要迁移的 unit：$flat"
  for f in /etc/systemd/system/dnsguard.service /etc/systemd/system/dnsguard-verifier.service \
           /etc/systemd/system/dnsguard.service.d/*.conf \
           /etc/systemd/system/dnsguard-verifier.service.d/*.conf; do
    [ -f "$f" ] || continue
    if grep -qE "ExecStart=.*$BASE/(guard|verifier)\.py|^WorkingDirectory=$BASE\$" "$f" 2>/dev/null; then
      if [ "$DRY" = 1 ]; then
        info "将把 $f 的路径改写为 $BASE/current/..."
      else
        # 先折叠可能已存在的 /current/current（重复执行幂等），再改写平铺路径
        sed -i -e "s|$BASE/current/current/|$BASE/current/|g" \
               -e "s|$BASE/guard\.py|$BASE/current/guard.py|g" \
               -e "s|$BASE/verifier\.py|$BASE/current/verifier.py|g" \
               -e "s|^WorkingDirectory=$BASE\$|WorkingDirectory=$BASE/current|" "$f"
        info "已改写 $f"
      fi
    fi
  done
}

if [ "$MIGRATE_UNITS" = 1 ]; then
  step "迁移 systemd unit 到 current 布局"
  if [ "$DRY" = 1 ]; then
    migrate_units
  else
    # 迁移前留档：unit 里含内存限额与全部 Environment，改坏了服务起不来
    BK="$BASE/backups/units-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BK"
    for f in /etc/systemd/system/dnsguard.service /etc/systemd/system/dnsguard-verifier.service \
             /etc/systemd/system/dnsguard.service.d/*.conf \
             /etc/systemd/system/dnsguard-verifier.service.d/*.conf; do
      [ -f "$f" ] && cp -p "$f" "$BK/$(basename "$(dirname "$f")")-$(basename "$f")" 2>/dev/null || true
    done
    info "unit 备份：$BK"
    migrate_units
    systemctl daemon-reload
    info "已 daemon-reload"
  fi
fi

# -------------------------------------------------------------- current 自检
if [ "$SWITCH" = 1 ] && [ "$DRY" != 1 ]; then
  step "current 布局自检"
  if [ -e "$CUR" ] && [ ! -L "$CUR" ]; then
    die "$CUR 存在但不是软链 —— current 布局被破坏，拒绝继续（先修好再用发布机制）"
  fi
  info "current -> $(readlink -f "$CUR" 2>/dev/null || echo '(不存在)')"
fi

if [ "$SWITCH" = 1 ]; then
  step "切换 current -> $REL_ID"
  if [ "$DRY" = 1 ]; then
    info "（dry-run：不切换）"
  else
    PREV="$(readlink -f "$CUR" 2>/dev/null || true)"
    [ -n "$PREV" ] && info "上一发布 $PREV"
    ln -sfn "$REL" "$CUR"
    info "current -> $(readlink -f "$CUR")"
    # 切换软链不会替换已加载模块：必须重启两个 unit 才会真正生效
    warn "current 已切换；重启服务生效：systemctl restart dnsguard dnsguard-verifier"
  fi
else
  step "完成（未切换 current）"
  info "切换：ln -sfn '$REL' '$CUR' && systemctl restart dnsguard dnsguard-verifier"
fi

step "完成"
cat <<EOF
    发布 ID      $REL_ID
    发布目录     $REL
    current      $( [ "$SWITCH" = 1 ] && readlink -f "$CUR" 2>/dev/null || echo "(未切换)" )

    回滚到上一发布：$BASE/deploy_release.sh --rollback <release-id>
    列出现有发布：  $BASE/deploy_release.sh --list
EOF
