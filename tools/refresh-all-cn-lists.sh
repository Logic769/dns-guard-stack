#!/bin/bash
# 统一 CN 名单刷新入口（cron 调用）：域名名单 + 否决名单 + cn_ip.txt + 完整性/签名校验 + 策略撤销
# 步骤 1/2 各自带门禁（幅度/关键域/条目下限），失败时保留旧文件并留旧名单可用。
# 步骤 3 校验 MANIFEST 哈希、GPG 签名与内容约束（清单被裁剪/被篡改/内容越界即失败）。
# 步骤 4 例外清单/信任白名单**发生变化**时受控清一次 AGH 缓存（策略收紧即时生效；无变化零副作用）。
# 退出码：至少一个刷新成功 **且** 校验通过 → 0；否则 1（便于 cron 告警）。步骤 4 只在日志里记 rc，
#         不改变主退出码（清缓存失败属可重试的运维动作，见 /var/log/cn-trust-revoke.log）。
PY=/usr/bin/python3
LOG=/var/log/cn-rules-refresh.log
{
  echo "=== $(date '+%F %T') 域名名单 refresh-cn-rules.py ==="
  "$PY" /opt/dnscrypt-proxy/refresh-cn-rules.py; r1=$?
  echo "=== $(date '+%F %T') 否决/IP 名单 refresh-cn-veto-ip.py ==="
  "$PY" /opt/dnscrypt-proxy/refresh-cn-veto-ip.py; r2=$?
  echo "=== $(date '+%F %T') 完整性 + 签名校验 verify-cn-lists.py ==="
  "$PY" /opt/dnscrypt-proxy/verify-cn-lists.py; r3=$?
  r4=skip
  if [ -x /opt/dnsguard/cn-trust-revoke.sh ]; then
    echo "=== $(date '+%F %T') 策略撤销 cn-trust-revoke.sh ==="
    /opt/dnsguard/cn-trust-revoke.sh; r4=$?
  fi
  echo "=== $(date '+%F %T') 汇总 rc: domain=$r1 veto_ip=$r2 verify=$r3 revoke=$r4 ==="
} >> "$LOG" 2>&1
{ [ "$r1" -eq 0 ] || [ "$r2" -eq 0 ]; } && [ "$r3" -eq 0 ]
