#!/bin/bash
# cgroup v1 内存策略（单一来源原则）
#  - unit 硬限(MemoryMax)、slice 硬限(MemoryMax)：由 systemd drop-in 声明，本脚本不重复
#  - systemd v219 不支持的能力，在此补足：
#      * slice 的 MemoryHigh（soft_limit）—— v219 只把 MemoryHigh 用在 service 上
#      * MemorySwapMax（换出上限）—— v231+ 才有；v219 下 memsw==limit 等于禁止换出
set -u
M=$((1024*1024))

apply() { # base high max memsw
  base="$1"; high="$2"; max="$3"; memsw="$4"
  [ -d "$base" ] || return 0
  if [ -n "$high" ]; then echo "$high" > "$base/memory.soft_limit_in_bytes" 2>/dev/null || true; fi
  if [ -n "$max" ];  then echo "$max"  > "$base/memory.limit_in_bytes"      2>/dev/null || true; fi
  if [ -n "$memsw" ]; then echo "$memsw" > "$base/memory.memsw.limit_in_bytes" 2>/dev/null || true; fi
}

# --- docker 容器总预算（容器 cgroup 挂在 /docker，systemd 不管理）---
# 实测常驻约 405MiB；历史峰值 1475MiB 无界增长 ⇒ 硬限兜住
apply /sys/fs/cgroup/memory/docker $((896*M)) $((1152*M)) $((1408*M))

# --- system.slice 软限（促内核回收 page cache；不设硬限以免误杀 DNS 链路）---
apply /sys/fs/cgroup/memory/system.slice $((1280*M)) "" ""

# --- 非关键服务：允许有限换出，把"被杀"换成"换出"（v219 下必须显式写 memsw）---
apply /sys/fs/cgroup/memory/system.slice/chainmon.service "" "" $((384*M))   # 256M 常驻 + 128M 换出
echo 40 > /sys/fs/cgroup/memory/system.slice/chainmon.service/memory.swappiness 2>/dev/null || true
apply /sys/fs/cgroup/memory/system.slice/devfp.service "" "" $((240*M))      # 176M 常驻 + 64M 换出
echo 40 > /sys/fs/cgroup/memory/system.slice/devfp.service/memory.swappiness 2>/dev/null || true

# --- 关键 DNS 服务：禁止换出（memsw = limit），低延迟优先 ---
for u in dnsguard dnsguard-verifier dnscrypt-proxy-local; do
  b=/sys/fs/cgroup/memory/system.slice/$u.service
  [ -d "$b" ] || continue
  lim=$(cat $b/memory.limit_in_bytes 2>/dev/null) || continue
  [ -n "$lim" ] || continue
  echo "$lim" > $b/memory.memsw.limit_in_bytes 2>/dev/null || true
  echo 0 > $b/memory.swappiness 2>/dev/null || true
done

# --- 遗留：非 systemd 托管的 dotfront ---
if [ -d /sys/fs/cgroup/memory/system.slice/dotfront.service ]; then
  echo $((64*M)) > /sys/fs/cgroup/memory/system.slice/dotfront.service/memory.limit_in_bytes 2>/dev/null || true
fi
