#!/bin/sh
set -eu
unit=${1:?unit}
cg=$(systemctl show -p ControlGroup --value "$unit")
base="/sys/fs/cgroup/memory${cg}"
if [ -w "$base/memory.swappiness" ]; then echo 0 > "$base/memory.swappiness"; fi
if [ -r "$base/memory.limit_in_bytes" ] && [ -w "$base/memory.memsw.limit_in_bytes" ]; then
  limit=$(cat "$base/memory.limit_in_bytes")
  echo "$limit" > "$base/memory.memsw.limit_in_bytes" 2>/dev/null || true
fi
