#!/bin/bash
# 生产状态快照（只读采集：不修改任何服务、不重启、不改配置）
# 目标：/root/dns-snapshot-20261015/ + /root/dns-snapshot-20261015.tar.gz
set -u
SNAP=/root/dns-snapshot-20261015
mkdir -p "$SNAP"
TS=$(date -Is)
REL=$(readlink -f /opt/dnsguard/current)
{
  echo "# 生产状态快照（只读采集）"
  echo "- 采集时间: $TS"
  echo "- current 发布: $REL"
  echo "- 说明: 本目录为当时状态的留档，采集过程不修改任何服务或配置。"
} > "$SNAP/README.md"

echo "$REL" > "$SNAP/release.txt"
cat "$REL/RELEASE" >> "$SNAP/release.txt" 2>/dev/null
( cd "$REL" && sha256sum -c RELEASE.sha256 ) > "$SNAP/release-verify.txt" 2>&1
python3 /opt/dnsguard/release_consistency.py > "$SNAP/consistency.txt" 2>&1
echo "rc=$?" >> "$SNAP/consistency.txt"
systemctl show dnsguard dnsguard-verifier -p MainPID -p ActiveState -p MemoryHigh -p MemoryMax -p NRestarts > "$SNAP/units.txt"
cat /etc/systemd/system/dnsguard.service.d/*.conf /etc/systemd/system/dnsguard-verifier.service.d/*.conf > "$SNAP/sd-dropins.txt" 2>/dev/null
iptables-save -c -t filter > "$SNAP/iptables-filter.txt"
cp -p /www/server/panel/vhost/nginx/tcp/dns-example-dot-853.conf "$SNAP/" 2>/dev/null
cp -p /www/server/panel/vhost/nginx/9.devfp-doh444.conf "$SNAP/" 2>/dev/null
cp -p /www/server/panel/vhost/nginx/dns.example.com.conf "$SNAP/" 2>/dev/null
docker exec adgh cat /opt/adguardhome/conf/AdGuardHome.yaml > "$SNAP/AdGuardHome.yaml" 2>/dev/null
cp -p /opt/unbound/unbound.conf "$SNAP/unbound-A.conf" 2>/dev/null
cp -p /opt/unbound-b/unbound.conf "$SNAP/unbound-B.conf" 2>/dev/null
cp -p /opt/unbound-alt/unbound.conf "$SNAP/unbound-alt.conf" 2>/dev/null
crontab -l > "$SNAP/crontab-root.txt" 2>/dev/null
sha256sum /opt/dnsguard/cn_veto*.txt /opt/dnsguard/cn_ip.txt /opt/dnsguard/cn_tlds.txt \
  /opt/dnsguard/cn-veto.snapshot.txt /opt/dnscrypt-proxy/cn-domains-typed.txt \
  /opt/dnscrypt-proxy/cn-domains-typed.snapshot.txt /opt/dnscrypt-proxy/cn-trust-exceptions.txt \
  /opt/dnscrypt-proxy/cn-trust-allow.txt \
  /opt/dnscrypt-proxy/forwarding-rules.txt > "$SNAP/cn-lists.sha256" 2>/dev/null
# 名单变更归档 + 本地签名（§16）：清单、归档产物、验签结论、签名密钥指纹
cp -p /opt/dnsguard/cn-list-history/MANIFEST.sha256 "$SNAP/cn-list-MANIFEST.sha256" 2>/dev/null
ls -l /opt/dnsguard/cn-list-history/*/*.json > "$SNAP/cn-list-archive.txt" 2>&1
python3 /opt/dnscrypt-proxy/verify-cn-lists.py > "$SNAP/cn-list-verify.txt" 2>&1; echo "rc=$?" >> "$SNAP/cn-list-verify.txt"
gpg --list-keys --with-colons 2>/dev/null | grep '^pub:' > "$SNAP/gpg-pubkeys.txt" 2>/dev/null
free -m > "$SNAP/mem.txt"; uptime >> "$SNAP/mem.txt"
python3 /opt/dnsguard/dns-entry-probe.py > "$SNAP/probe-entry.txt" 2>&1; echo "rc=$?" >> "$SNAP/probe-entry.txt"
python3 /usr/local/sbin/dns-chain-probe.py > "$SNAP/probe-chain.txt" 2>&1; echo "rc=$?" >> "$SNAP/probe-chain.txt"
/usr/local/sbin/dnsguard-fw.sh --check > "$SNAP/fw-check.txt" 2>&1; echo "rc=$?" >> "$SNAP/fw-check.txt"
/usr/local/sbin/dnsguard-ip-reconcile.sh --check > "$SNAP/ip-reconcile-check.txt" 2>&1; echo "rc=$?" >> "$SNAP/ip-reconcile-check.txt"
tar czf /root/dns-snapshot-20261015.tar.gz -C /root dns-snapshot-20261015
echo "--- 快照文件 ---"; ls -l /root/dns-snapshot-20261015.tar.gz; du -sh "$SNAP"
echo "--- 校验结果摘要 ---"
grep -c "OK" "$SNAP/release-verify.txt"; tail -2 "$SNAP/consistency.txt"; tail -2 "$SNAP/probe-entry.txt"; tail -2 "$SNAP/probe-chain.txt"
