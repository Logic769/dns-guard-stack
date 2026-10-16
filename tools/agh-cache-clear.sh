#!/bin/bash
# 受控清除 AdGuard Home 的 DNS 缓存（用于「安全策略撤销」后的即时生效）。
#
# 背景（第四份审计 F2 剩余边界）：guard 的准入缓存会按名单代次自动失效，但 **AGH 的独立缓存
# 不会** —— 把域名移出例外/信任集合后，AGH 里那条旧记录仍会按自身剩余 TTL 继续下发。
# 本脚本提供受控、可记录的撤销动作（全量清 AGH 缓存），由 `cn-trust-revoke.sh` 在
# 「例外清单或信任白名单确实发生变化」时调用 ⇒ 不必把普通名单增补也变成全量清缓存。
#
# 凭据：/etc/dnsguard/agh-api.env（0600，root），内容形如
#   AGH_URL=http://127.0.0.1:3000
#   AGH_USER=dns-example
#   AGH_PASS=<AGH 面板密码明文>
# 退出码：0 成功；1 调用失败；2 未配置凭据（此时需人工在 AGH 面板清缓存）。
set -u

ENVF=${AGH_API_ENV:-/etc/dnsguard/agh-api.env}
URL_DEF="http://127.0.0.1:3000"
TMO=${AGH_TIMEOUT:-10}

if [ ! -r "$ENVF" ]; then
  echo "agh-cache-clear: 未配置凭据文件 $ENVF（需要 AGH_USER/AGH_PASS）⇒ 请在 AGH 面板手动清缓存" >&2
  exit 2
fi
# shellcheck disable=SC1090
. "$ENVF"
U=${AGH_USER:-}; P=${AGH_PASS:-}; U0=${AGH_URL:-$URL_DEF}
if [ -z "$U" ] || [ -z "$P" ]; then
  echo "agh-cache-clear: $ENVF 中 AGH_USER/AGH_PASS 为空 ⇒ 未执行" >&2
  exit 2
fi

_tmp=$(mktemp /tmp/agh-clear.XXXXXX)
code=$(curl -s -o "$_tmp" -w '%{http_code}' --max-time "$TMO" -u "$U:$P" \
        -H 'Content-Type: application/json' -X POST -d '{}' \
        "$U0/control/cache_clear" 2>/dev/null || echo 000)
body=$(head -c 200 "$_tmp" 2>/dev/null | tr -d '\n')
rm -f "$_tmp"

if [ "$code" = "200" ]; then
  echo "agh-cache-clear: OK（http 200，$U0）"
  logger -t agh-cache-clear "AGH DNS cache cleared via API ($U0)"
  exit 0
fi
echo "agh-cache-clear: 失败 http=$code body=$body" >&2
exit 1
