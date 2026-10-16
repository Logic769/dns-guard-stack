#!/bin/bash
# 例外清单 / 信任白名单发生变化时，受控清除 AGH 缓存（第四份审计 F2 的 AGH 侧闭环）。
#
# 为什么单独做：guard 的准入缓存已按名单代次（typed|veto|exc|trust）自动失效，但 AGH 缓存不受
# guard 控制。只有「策略收紧」类变化（例外清单、信任白名单）需要连带撤销 AGH 里的旧记录；
# 普通名单增补（域名/否决/IP 大幅变化）不触发，避免每天一次全量清缓存拖垮命中率。
#
# 记录：状态文件 $STATE/last.sha 保存上次撤销时的「例外+白名单」联合 sha256；
#       日志 /var/log/cn-trust-revoke.log（每次运行写一行，无论是否变化）。
# 退出码：0 无变化或已成功撤销；1 有变化但撤销失败（保留旧 last.sha 以便下次重试）。
set -u

BASE=${CN_TRUST_BASE:-/opt/dnsguard}
EXC=${CN_TRUST_EXC:-/opt/dnscrypt-proxy/cn-trust-exceptions.txt}
ALLOW=${CN_TRUST_ALLOW:-/opt/dnscrypt-proxy/cn-trust-allow.txt}
STATE=$BASE/agh-cache-state
CLEAR=${AGH_CLEAR:-/opt/dnsguard/agh-cache-clear.sh}
LOG=${CN_TRUST_REVOKE_LOG:-/var/log/cn-trust-revoke.log}

mkdir -p "$STATE"
cur=$(cat "$EXC" "$ALLOW" 2>/dev/null | sha256sum | awk '{print $1}')
[ -n "$cur" ] || cur=none
last=$(cat "$STATE/last.sha" 2>/dev/null || echo none)
ts=$(date '+%F %T %z')

if [ "$cur" = "$last" ]; then
  echo "$ts 例外/白名单无变化（$cur）⇒ 不清 AGH 缓存" >> "$LOG"
  exit 0
fi

echo "$ts 检测到例外/白名单变化：$last → $cur" >> "$LOG"
if [ ! -x "$CLEAR" ]; then
  echo "$ts 但 $CLEAR 不可执行 ⇒ 需人工在 AGH 面板清缓存" >> "$LOG"
  exit 1
fi
if "$CLEAR" >> "$LOG" 2>&1; then
  echo "$cur" > "$STATE/last.sha"
  echo "$ts 已撤销 AGH 缓存（策略收紧即时生效）" >> "$LOG"
  exit 0
fi
echo "$ts 撤销失败（见上），保留旧 last.sha 以便下次重试" >> "$LOG"
exit 1
