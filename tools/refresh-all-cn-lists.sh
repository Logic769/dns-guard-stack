#!/bin/bash
# 统一 CN 名单刷新入口（cron 调用）：域名名单 + 否决名单 + cn_ip.txt + 完整性/签名校验 + 策略撤销
# 步骤 1/2 各自带门禁（幅度/关键域/条目下限），失败时保留旧文件并留旧名单可用。
# 步骤 3 校验 MANIFEST 哈希、GPG 签名与内容约束（清单被裁剪/被篡改/内容越界即失败）。
# 步骤 4 例外清单/信任白名单**发生变化**时受控清一次 AGH 缓存（策略收紧即时生效；无变化零副作用）。
# 退出码：至少一个刷新成功 **且** 校验通过 → 0；否则 1（便于 cron 告警）。步骤 4 只在日志里记 rc，
#         不改变主退出码（清缓存失败属可重试的运维动作，见 /var/log/cn-trust-revoke.log）。
PY=/usr/bin/python3
LOG=/var/log/cn-rules-refresh.log
# 刷新器与校验器都在本脚本同一目录（install.sh 会把它和它们一起装到 $CODE_DIR/tools/）。
# 用 HERE 而不是绝对路径：旧生产布局曾把刷新器与名单文件放在同一目录
# （/opt/dnscrypt-proxy/），照抄绝对路径会让安装后的脚本去名单目录里找 .py 而全部失败
# （can't open file '/opt/dnscrypt-proxy/refresh-cn-rules.py'）。
HERE=$(cd "$(dirname "$0")" && pwd)
TYPED=${REFRESH_TYPED_FILE:-/opt/dnscrypt-proxy/cn-domains-typed.txt}
# 首次启用时名单文件还是骨架（0 条有效），此时新增幅度必然接近 100%，会撞上刷新器的
# 幅度门禁（15%）而整轮失败 ⇒ 名单永远停在骨架、CN 分流永远不生效。故此处先判一次：
# 有效条目 <1000 就带 --force 跳过门禁 —— 门禁防的是「已有 8000 条被误替换成 200 条」，
# 而 0 → 8837 条没有可被破坏的既有集合。已有有效名单时保持门禁生效。
n_typed=$(grep -vc '^[[:space:]]*#' "$TYPED" 2>/dev/null) || n_typed=0
[ -z "$n_typed" ] && n_typed=0
FORCE=""
[ "$n_typed" -lt 1000 ] && FORCE="--force"
# 签名策略放在调用方，校验器本身保持严格（默认必须验签，未签名即 FAIL）。
# 本机还没有 GPG 私钥（首次安装、未启用签名归档）时，MANIFEST 必然没有 .asc 签名，
# 此时每轮刷新都带一个假 FAIL 会让 cron 告警疲劳，真正的篡改告警被淹没。
# 所以这里先探测私钥：没有就显式跳过签名校验，哈希与条目数照常校验。
SIGOPT=""
if ! command -v gpg >/dev/null 2>&1 || ! gpg --list-secret-keys 2>/dev/null | grep -q '^sec'; then
  SIGOPT="--no-signature"
fi
{
  echo "=== $(date '+%F %T') 域名名单 refresh-cn-rules.py ==="
  "$PY" "$HERE/refresh-cn-rules.py" $FORCE; r1=$?
  echo "=== $(date '+%F %T') 否决/IP 名单 refresh-cn-veto-ip.py ==="
  "$PY" "$HERE/refresh-cn-veto-ip.py"; r2=$?
  echo "=== $(date '+%F %T') 完整性 + 签名校验 verify-cn-lists.py ${SIGOPT:+（本机无 GPG 私钥 ⇒ 跳过签名）} ==="
  "$PY" "$HERE/verify-cn-lists.py" $SIGOPT; r3=$?
  r4=skip
  if [ -x "$HERE/cn-trust-revoke.sh" ]; then
    echo "=== $(date '+%F %T') 策略撤销 cn-trust-revoke.sh ==="
    "$HERE/cn-trust-revoke.sh"; r4=$?
  fi
  echo "=== $(date '+%F %T') 汇总 rc: domain=$r1 veto_ip=$r2 verify=$r3 revoke=$r4 ==="
} >> "$LOG" 2>&1
{ [ "$r1" -eq 0 ] || [ "$r2" -eq 0 ]; } && [ "$r3" -eq 0 ]
