#!/usr/bin/env bash
# =============================================================================
# dns-guard-stack 一键部署
# -----------------------------------------------------------------------------
#   sudo ./install.sh                 # 按 .env 部署（幂等，可重复执行）
#   sudo ./install.sh --dry-run       # 只打印将要执行的动作
#   sudo ./install.sh --skip-firewall # 不改 iptables
#   sudo ./install.sh --fetch-lists   # 安装时立即拉取社区名单（默认只放骨架）
#
# 默认部署布局与参考实现一致（可用 .env 覆盖）：
#   /opt/dnsguard            guard/verifier/运维脚本 + 状态
#   /opt/dnscrypt-proxy      名单与刷新器
#   /opt/chainmon /opt/devfp 看板
#   /opt/dns-guard-stack/runtime   容器配置与数据
#   /usr/local/sbin          防火墙 / 探针 / 回收脚本
# =============================================================================
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRY=0
SKIP_FW=0
FETCH=0
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    --skip-firewall) SKIP_FW=1 ;;
    --fetch-lists) FETCH=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "未知参数：$a（-h 看用法）" >&2; exit 2 ;;
  esac
done

# ------------------------------------------------------------------ 日志与工具
C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_DIM=$'\033[2m'; C_0=$'\033[0m'
step() { printf '\n%s==> %s%s\n' "$C_OK" "$*" "$C_0"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '%s[warn]%s %s\n' "$C_WARN" "$C_0" "$*"; }
die()  { printf '%s[error]%s %s\n' "$C_ERR" "$C_0" "$*" >&2; exit 1; }
run()  { if [ "$DRY" = 1 ]; then printf '    %s$ %s%s\n' "$C_DIM" "$*" "$C_0"; else eval "$@"; fi; }
need() { command -v "$1" >/dev/null 2>&1; }

# ------------------------------------------------------------------ 载入配置
cd "$HERE"
if [ ! -f .env ]; then
  warn ".env 不存在，从 .env.example 复制一份（请按需修改后重跑）"
  [ "$DRY" = 1 ] || cp -n .env.example .env
fi
set -a; . ./.env; set +a

: "${DNS_DOMAIN:=dns.example.com}"
: "${RUNTIME_DIR:=/opt/dns-guard-stack/runtime}"
: "${CODE_DIR:=/opt/dnsguard}"
: "${LISTS_DIR:=/opt/dnscrypt-proxy}"
: "${STATE_DIR:=$CODE_DIR}"
: "${VERIFIER_STATE_DIR:=$CODE_DIR/verifier-state}"
: "${BACKUP_DIR:=$CODE_DIR/backups}"
: "${DOCKER_SUBNET:=172.18.0.0/16}"
: "${AGH_IP:=172.18.0.2}"; : "${AGHDQ_IP:=172.18.0.6}"
: "${UNBOUND_A_IP:=172.18.0.4}"; : "${UNBOUND_B_IP:=172.18.0.5}"; : "${UNBOUND_ALT_IP:=172.18.0.8}"
: "${DOT_PORT:=853}"; : "${DOH_PORT:=444}"; : "${AGH_UI_PORT:=3000}"
: "${AGH_HTTPS_PORT:=4443}"; : "${AGHDQ_DNS_PORT:=5533}"
: "${CHAINMON_PORT:=8787}"; : "${DEVFP_PORT:=8789}"
: "${CN_TRUST_MODE:=known}"; : "${CN_EXIST_MODE:=enforce}"
: "${GUARD_MEMORY_MAX:=192}"; : "${GUARD_MEMORY_HIGH:=160}"
: "${VERIFIER_MEMORY_MAX:=128}"; : "${VERIFIER_MEMORY_HIGH:=100}"
: "${CHAINMON_MEMORY_MAX:=256}"; : "${DEVFP_MEMORY_MAX:=176}"
: "${INSTALL_NGINX:=0}"; : "${NGINX_VHOST_DIR:=/www/server/panel/vhost/nginx}"
: "${NGINX_BIN:=nginx}"; : "${TZ:=Asia/Shanghai}"
# 名单档位：minimal=只放骨架（默认，不联网）/ fetch=安装时立即拉社区名单
: "${LISTS_PROFILE:=minimal}"
[ "$LISTS_PROFILE" = "fetch" ] && FETCH=1

# ------------------------------------------------------------------ 前置检查
step "前置检查"
[ "$(id -u)" = 0 ] || die "需要 root（$ sudo ./install.sh）"
need docker || die "缺少 docker"
docker compose version >/dev/null 2>&1 || die "缺少 docker compose 插件"
need python3 || die "缺少 python3"
PYV=$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')
python3 -c 'import sys; sys.exit(0 if sys.version_info>=(3,6) else 1)' || die "需要 python3 >= 3.6（当前 $PYV）"
need systemctl || die "缺少 systemd"
info "docker $(docker --version | awk '{print $3}' | tr -d ,) / python3 $PYV / systemd ok"

# docker0 网关（guard 监听地址）
if [ -z "${GW_IP:-}" ]; then
  GW_IP=$(ip -4 -o addr show docker0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1 || true)
  [ -n "$GW_IP" ] || GW_IP=172.18.0.1
fi
info "GW_IP=$GW_IP  DNS_DOMAIN=$DNS_DOMAIN  RUNTIME_DIR=$RUNTIME_DIR"

step "建立目录"
for d in "$CODE_DIR" "$LISTS_DIR/backups" "$STATE_DIR" "$VERIFIER_STATE_DIR" "$BACKUP_DIR" \
         "$RUNTIME_DIR"/{unbound-a,unbound-b,unbound-alt,unbound-alt-replica} \
         "$RUNTIME_DIR"/adgh/{conf,work} "$RUNTIME_DIR"/aghdq "$RUNTIME_DIR"/dnscrypt-proxy \
         "$CODE_DIR/cn-list-history" /run/dnsguard /var/log; do
  run "install -d -m 0755 '$d'"
done

# 渲染：把模板里的默认值换成 .env 里的实际值（sed 失败率极低：都是定值替换）
render() { # render <tpl> <out>
  run "sed -e 's|dns\\.example\\.com|$DNS_DOMAIN|g' \
        -e 's|172\\.18\\.0\\.1|$GW_IP|g' \
        -e 's|172\\.18\\.0\\.6|$AGHDQ_IP|g' \
        -e 's|172\\.18\\.0\\.2|$AGH_IP|g' \
        -e 's|172\\.18\\.0\\.4|$UNBOUND_A_IP|g' \
        -e 's|172\\.18\\.0\\.5|$UNBOUND_B_IP|g' \
        -e 's|172\\.18\\.0\\.8|$UNBOUND_ALT_IP|g' \
        '$1' > '$2'"
}

step "部署代码到 $CODE_DIR"
run "install -d -m 0755 '$CODE_DIR/core' '$CODE_DIR/tools' '$CODE_DIR/probes' '$CODE_DIR/firewall'"
run "cp -f '$HERE'/core/*.py '$HERE'/core/*.json '$CODE_DIR'/"
run "cp -f '$HERE'/core/*.py '$HERE'/core/*.json '$CODE_DIR/core/'"
run "cp -f '$HERE'/tools/* '$CODE_DIR/tools/'"
run "cp -f '$HERE'/probes/* '$CODE_DIR/probes/'"
run "cp -f '$HERE'/firewall/* /usr/local/sbin/ 2>/dev/null || true"
run "chmod 0755 '$CODE_DIR'/*.py '$CODE_DIR/tools'/*.py '$CODE_DIR/tools'/*.sh '$CODE_DIR/probes'/*.py /usr/local/sbin/dnsguard-*.sh /usr/local/sbin/dnsguard-*.py 2>/dev/null || true"
# 让 tools/probes 里的默认路径跟随 .env（默认值与仓库一致时是 no-op）。
# 必须在这里做：后面的「初始化名单」步骤会直接调用 tools/ 里的刷新器。
run "sed -i -e 's|/opt/dnscrypt-proxy|$LISTS_DIR|g' \
      -e 's|/opt/chainmon|${CHAINMON_DIR:-/opt/chainmon}|g' \
      -e 's|/opt/devfp|${DEVFP_DIR:-/opt/devfp}|g' \
      -e 's|/opt/dnsguard/current|$CODE_DIR|g' \
      -e 's|/opt/dnsguard|$CODE_DIR|g' '$CODE_DIR'/tools/* '$CODE_DIR'/probes/* 2>/dev/null || true"
run "python3 -m py_compile '$CODE_DIR'/guard.py '$CODE_DIR'/verifier.py '$CODE_DIR'/alt_adapter.py '$CODE_DIR'/answer_policy.py"
info "代码就位：$CODE_DIR/（guard.py verifier.py alt_adapter.py answer_policy.py …）"

step "渲染容器配置"
for pair in "unbound-a.conf.tpl:unbound-a/unbound.conf" \
            "unbound-b.conf.tpl:unbound-b/unbound.conf" \
            "unbound-alt.conf.tpl:unbound-alt/unbound.conf" \
            "unbound-alt-replica.conf.tpl:unbound-alt-replica/unbound.conf"; do
  tpl=${pair%%:*}; out=${pair##*:}
  render "$HERE/deploy/containers/$tpl" "$RUNTIME_DIR/$out"
done
if [ "${UPSTREAM_B:-}" ]; then
  BADDR=""; IFS=','; for u in $UPSTREAM_B; do BADDR="$BADDR
    forward-addr: $u"; done; unset IFS
  if [ "$DRY" != 1 ]; then
    python3 - "$RUNTIME_DIR/unbound-b/unbound.conf" "$BADDR" <<'PY'
import io,sys,re
p,addrs=sys.argv[1],sys.argv[2]
s=io.open(p,encoding='utf-8').read()
s=re.sub(r'(forward-zone:\n    name: "."\n    forward-tls-upstream: yes\n)((    forward-addr: .*\n)+)',
         lambda m: m.group(1)+addrs.lstrip('\n')+'\n', s)
io.open(p,'w',encoding='utf-8',newline='\n').write(s)
PY
  fi
fi
render "$HERE/deploy/containers/aghdq.AdGuardHome.yaml.tpl" "$RUNTIME_DIR/aghdq/AdGuardHome.yaml"
render "$HERE/deploy/containers/adgh.AdGuardHome.yaml.tpl"  "$RUNTIME_DIR/adgh/conf/AdGuardHome.yaml"
# dnscrypt-proxy：容器内监听 5353
run "sed -e \"s|listen_addresses = .*|listen_addresses = ['0.0.0.0:5353']|\" \
        -e \"s|server_names = .*|server_names = ['$(echo "${DNSCRYPT_SERVERS:-cs-nl}" | sed "s/,/','/g")']|\" \
        '$HERE/deploy/containers/dnscrypt-proxy.toml.tpl' > '$RUNTIME_DIR/dnscrypt-proxy/dnscrypt-proxy.toml'"

# AGH 面板账号（bcrypt 由 httpd 镜像生成；留空则首次访问 UI 时创建）
if [ -n "${AGH_ADMIN_PASSWORD:-}" ]; then
  HASH=$(docker run --rm httpd:2-alpine htpasswd -nbB "${AGH_ADMIN_USER:-admin}" "$AGH_ADMIN_PASSWORD" | cut -d: -f2 | tr -d '\n' || true)
  if [ -n "$HASH" ]; then
    run "sed -i 's|^    password: .*|    password: $HASH|' '$RUNTIME_DIR/adgh/conf/AdGuardHome.yaml' '$RUNTIME_DIR/aghdq/AdGuardHome.yaml'"
    info "已写入 AGH 面板密码（用户 ${AGH_ADMIN_USER:-admin}）"
  else
    warn "bcrypt 生成失败，AGH 首次访问时请在 UI 里创建账号"
  fi
fi

step "生成 unbound 信任锚与管理证书"
run "docker pull mvance/unbound:latest >/dev/null 2>&1 || true"
run "docker run --rm -v '$RUNTIME_DIR/unbound-a:/opt/unbound/etc/unbound' mvance/unbound:latest unbound-anchor -a /opt/unbound/etc/unbound/root.key >/dev/null 2>&1 || true"
for u in unbound-b unbound-alt unbound-alt-replica; do
  run "cp -f '$RUNTIME_DIR/unbound-a/root.key' '$RUNTIME_DIR/$u/root.key' 2>/dev/null || true"
done
run "docker run --rm -v '$RUNTIME_DIR/unbound-a:/opt/unbound/etc/unbound' --entrypoint unbound-control-setup mvance/unbound:latest >/dev/null 2>&1 || true"
run "cp -f '$RUNTIME_DIR/unbound-a'/unbound_*.key '$RUNTIME_DIR/unbound-a'/unbound_*.pem '$RUNTIME_DIR/unbound-b/' 2>/dev/null || true"
run "cp -f '$RUNTIME_DIR/unbound-a'/unbound_*.key '$RUNTIME_DIR/unbound-a'/unbound_*.pem '$RUNTIME_DIR/unbound-alt/' 2>/dev/null || true"
info "root.key 与 unbound-control 证书就绪"

step "初始化名单（LISTS_PROFILE=${LISTS_PROFILE:-fetch}）"
run "install -d -m 0755 '$LISTS_DIR'"
run "cp -f '$HERE/deploy/lists/cn-trust-allow.txt' '$LISTS_DIR/cn-trust-allow.txt'"
run "cp -f '$HERE/deploy/lists/cn-trust-exceptions.txt' '$LISTS_DIR/cn-trust-exceptions.txt'"
run "cp -f '$HERE/deploy/lists/cn-trust-allow.txt' '$CODE_DIR/core/cn-trust-allow.txt' 2>/dev/null || true"
run "install -m 0755 '$HERE/tools/refresh-all-cn-lists.sh' '$CODE_DIR/tools/' 2>/dev/null || true"
skeleton_lists() { # 无外网/拉取失败时的兜底：写骨架文件，guard 会按“未知即不信任”运行
  for f in cn-domains-typed.txt forwarding-rules.txt cn_veto.txt cn_ip.txt; do
    if [ ! -s "$LISTS_DIR/$f" ]; then
      run "printf '# 骨架：执行 %s/tools/refresh-all-cn-lists.sh 拉取真实名单\\n' '$CODE_DIR' > '$LISTS_DIR/$f'"
    fi
  done
}
if [ "$FETCH" = 1 ] || [ "${LISTS_PROFILE:-fetch}" = "fetch" ]; then
  info "拉取真实名单：v2fly 域名（typed）→ clang.cn/chnroutes2 国内 IP → 否决名单（需要外网）"
  run "python3 '$CODE_DIR/tools/refresh-cn-rules.py' --force 2>&1 | tail -4 || true"
  run "python3 '$CODE_DIR/tools/refresh-cn-veto-ip.py' --force 2>&1 | tail -4 || true"
  if [ "$DRY" != 1 ]; then
    typed_n=$(wc -l < "$LISTS_DIR/cn-domains-typed.txt" 2>/dev/null || echo 0)
    ip_n=$(wc -l < "$LISTS_DIR/cn_ip.txt" 2>/dev/null || echo 0)
    veto_n=$(wc -l < "$LISTS_DIR/cn_veto.txt" 2>/dev/null || echo 0)
    info "名单条数：typed=${typed_n:-0}  cn_ip=${ip_n:-0}  veto=${veto_n:-0}"
    if [ "${typed_n:-0}" -lt 1000 ] || [ "${ip_n:-0}" -lt 500 ] || [ "${veto_n:-0}" -lt 100 ]; then
      warn "名单不完整（多半是没有外网）。安装继续；guard 会按“未知即不信任”运行。"
      warn "稍后重试：sudo bash $CODE_DIR/tools/refresh-all-cn-lists.sh"
      skeleton_lists
    else
      info "名单拉取完成（真实名单，不是骨架）"
    fi
  fi
else
  warn "LISTS_PROFILE=$LISTS_PROFILE：使用骨架名单，guard 按“未知即不信任”运行。"
  warn "稍后拉真名单：sudo bash $CODE_DIR/tools/refresh-all-cn-lists.sh"
  skeleton_lists
fi

step "证书"
CERT="${TLS_CERT:-}"; KEY="${TLS_KEY:-}"
if [ -z "$CERT" ] || [ -z "$KEY" ]; then
  CERT="$RUNTIME_DIR/tls/fullchain.pem"; KEY="$RUNTIME_DIR/tls/privkey.pem"
  run "install -d -m 0755 '$RUNTIME_DIR/tls'"
  if [ ! -s "$CERT" ]; then
    run "openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes \
          -keyout '$KEY' -out '$CERT' -subj '/CN=$DNS_DOMAIN' \
          -addext 'subjectAltName=DNS:$DNS_DOMAIN'"
  fi
  warn "使用自签证书（$CERT）。生产请填 TLS_CERT/TLS_KEY 或 ACME_EMAIL。"
else
  info "使用已有证书：$CERT"
fi

step "启动容器"
run "docker compose --project-directory '$HERE' up -d"
if [ "$DRY" != 1 ]; then
  for i in $(seq 1 30); do
    n=$(docker ps --filter name=aghdq --filter status=running -q | wc -l)
    [ "$n" = 1 ] && break; sleep 1
  done
  info "容器状态："; docker ps --format '    {{.Names}}\t{{.Status}}' 2>/dev/null | sed 's/^/  /' | head -12
fi

if [ "$SKIP_FW" = 0 ]; then
  step "防火墙规则（unbound-b 明文 53 出站封堵 + 容器间 53 收口）"
  if [ -x /usr/local/sbin/dnsguard-fw.sh ]; then
    run "/usr/local/sbin/dnsguard-fw.sh --check || true"
    run "/usr/local/sbin/dnsguard-fw.sh --apply"
  else
    warn "未找到 dnsguard-fw.sh，跳过（DoT/DoH 仍可用，但缺一层纵深防御）"
  fi
else
  warn "按 --skip-firewall 跳过防火墙规则"
fi

step "安装 systemd 单元"
run "install -m 0644 '$HERE/deploy/systemd/dnsguard.service' /etc/systemd/system/dnsguard.service"
run "install -m 0644 '$HERE/deploy/systemd/dnsguard-verifier.service' /etc/systemd/system/dnsguard-verifier.service"
run "install -m 0644 '$HERE/deploy/systemd/chainmon.service' /etc/systemd/system/chainmon.service"
run "install -m 0644 '$HERE/deploy/systemd/devfp.service' /etc/systemd/system/devfp.service"
run "install -d -m 0755 /etc/systemd/system/dnsguard.service.d /etc/systemd/system/dnsguard-verifier.service.d"
run "install -m 0644 '$HERE/deploy/systemd/dnsguard.service.d/zzzzzz-consolidated-20261010.conf' /etc/systemd/system/dnsguard.service.d/"
run "install -m 0644 '$HERE/deploy/systemd/dnsguard-verifier.service.d/zzzzzz-consolidated-20261010.conf' /etc/systemd/system/dnsguard-verifier.service.d/"

# DoT 明文内腿采集器（dotfront-spool）：给 devfp 提供 EDNS/COOKIE/PADDING/DO/0x20 明文画像。
# 前置：DoT stream 的内腿必须是明文（deploy/nginx/tcp/dnsguard-dot-853.conf 里 proxy_pass 直连 adgh:53）。
run "install -d -m 0755 /etc/systemd/system/dotfront-spool.service.d"
render "$HERE/deploy/systemd/dotfront-spool.service" "$RUNTIME_DIR/dotfront-spool.service"
run "sed -i -e 's|/opt/dnsguard|$CODE_DIR|g' -e 's|^Environment=DOTF_SPOOL=.*|Environment=DOTF_SPOOL=${DOTF_SPOOL:-/var/log/dotfront.jsonl}|' '$RUNTIME_DIR/dotfront-spool.service'"
run "install -m 0644 '$RUNTIME_DIR/dotfront-spool.service' /etc/systemd/system/dotfront-spool.service"
render "$HERE/deploy/systemd/dotfront-spool.service.d/20-ip-reconcile.conf" "$RUNTIME_DIR/dotfront-spool-ip.conf"
run "install -m 0644 '$RUNTIME_DIR/dotfront-spool-ip.conf' /etc/systemd/system/dotfront-spool.service.d/20-ip-reconcile.conf"

# 栈内路径与档位：单一 drop-in（渲染后写入，避免污染上面的原件）
PATHS_CONF=/etc/systemd/system/dnsguard.service.d/zzzzzzzzz-stack-paths.conf
if [ "$DRY" != 1 ]; then
  cat > "$PATHS_CONF" <<EOF
# 由 install.sh 生成（$(date -Iseconds)）—— 路径与档位
[Service]
Environment=GUARD_STATE_DIR=$STATE_DIR
Environment=GUARD_CN_DOMAINS_FILE=$LISTS_DIR/forwarding-rules.txt
Environment=GUARD_CN_TYPED_FILE=$LISTS_DIR/cn-domains-typed.txt
Environment=GUARD_CN_VETO_FILE=$LISTS_DIR/cn_veto.txt
Environment=GUARD_CN_TRUST_ALLOW_FILE=$LISTS_DIR/cn-trust-allow.txt
Environment=GUARD_CN_TRUST_EXC_FILE=$LISTS_DIR/cn-trust-exceptions.txt
Environment=GUARD_CN_TRUST_MODE=$CN_TRUST_MODE
Environment=GUARD_CN_EXIST_MODE=$CN_EXIST_MODE
Environment=GUARD_CN_VETO_WITNESS=127.0.0.1:${AGHDQ_DNS_PORT:-5533}
Environment=GUARD_FAST_UDP=127.0.0.1:5399
Environment=GUARD_CN_DOMESTIC_PRIMARY=1
Environment=GUARD_CN_DOMESTIC_TRUST_B=1
Environment=GUARD_CN_DOMESTIC_ZERO_TTL_ONESHOT=1
Environment=TZ=$TZ
MemoryHigh=${GUARD_MEMORY_HIGH}M
MemoryMax=${GUARD_MEMORY_MAX}M
EOF
  cat > /etc/systemd/system/dnsguard-verifier.service.d/zzzzzzzzz-stack-paths.conf <<EOF
[Service]
Environment=GUARD_STATE_DIR=$VERIFIER_STATE_DIR
Environment=TZ=$TZ
MemoryHigh=${VERIFIER_MEMORY_HIGH}M
MemoryMax=${VERIFIER_MEMORY_MAX}M
EOF
fi
# 把默认路径改写为 .env 里的实际路径（默认值与仓库一致时是 no-op）
rewrite_paths() { # rewrite_paths <file...>
  run "sed -i -e 's|/opt/dnsguard/current|$CODE_DIR|g' \
        -e 's|/opt/dnsguard|$CODE_DIR|g' \
        -e 's|/opt/dnscrypt-proxy|$LISTS_DIR|g' \
        -e 's|/opt/chainmon|${CHAINMON_DIR:-/opt/chainmon}|g' \
        -e 's|/opt/devfp|${DEVFP_DIR:-/opt/devfp}|g' $* 2>/dev/null || true"
}
run "sed -i 's|/opt/dnsguard/current|$CODE_DIR|g' /etc/systemd/system/dnsguard.service /etc/systemd/system/dnsguard-verifier.service /etc/systemd/system/dnsguard.service.d/*.conf /etc/systemd/system/dnsguard-verifier.service.d/*.conf 2>/dev/null || true"
rewrite_paths "'$CODE_DIR'/tools/* '$CODE_DIR'/probes/* /opt/chainmon/* /opt/devfp/*"
run "systemctl daemon-reload"
run "systemctl enable --now dnsguard.service dnsguard-verifier.service"
run "systemctl enable --now dotfront-spool.service" || warn "dotfront-spool 未启动（需 DoT 明文内腿 + CAP_NET_RAW）；不影响 DNS 解析"
if [ "$DRY" != 1 ]; then sleep 3; systemctl --no-pager --lines=0 status dnsguard.service dnsguard-verifier.service 2>&1 | sed -n '1,12p' || true; fi

step "看板（可选）"
if [ -d "$HERE/dashboards/chainmon" ]; then
  run "install -d -m 0755 /opt/chainmon /opt/devfp"
  run "cp -f '$HERE/dashboards/chainmon/'* /opt/chainmon/ && cp -f '$HERE/dashboards/devfp/'* /opt/devfp/"
  info "看板文件已放入 /opt/chainmon 与 /opt/devfp（启动前请在 nginx 里加 Basic Auth）"
  warn "看板未自动启动：需先确认链路上的 nginx 日志路径与容器名与本机一致"
fi

step "nginx 片段"
run "install -d -m 0755 '$RUNTIME_DIR/nginx'"
render "$HERE/deploy/nginx/tcp/dnsguard-dot-853.conf" "$RUNTIME_DIR/nginx/dot-853.conf"
render "$HERE/deploy/nginx/9.devfp-doh444.conf"      "$RUNTIME_DIR/nginx/doh-444.conf"
if [ "$INSTALL_NGINX" = 1 ] && [ -d "$NGINX_VHOST_DIR" ]; then
  run "install -d -m 0755 '$NGINX_VHOST_DIR/tcp'"
  run "install -m 0644 '$RUNTIME_DIR/nginx/dot-853.conf' '$NGINX_VHOST_DIR/tcp/dnsguard-dot-853.conf'"
  run "install -m 0644 '$RUNTIME_DIR/nginx/doh-444.conf' '$NGINX_VHOST_DIR/9.dnsguard-doh444.conf'"
  run "$NGINX_BIN -t && $NGINX_BIN -s reload" || warn "nginx 校验/重载失败，请手动检查"
else
  info "nginx 片段已生成到 $RUNTIME_DIR/nginx/（设 INSTALL_NGINX=1 可自动安装）"
  info "  需保证：tcp 段 include 该目录里的 dot-853.conf；http 段 include doh-444.conf"
  info "  并把证书路径指向 $CERT / $KEY"
fi

step "完成"
cat <<EOF
    DNS_DOMAIN      $DNS_DOMAIN
    代码目录        $CODE_DIR
    名单目录        $LISTS_DIR
    运行时目录      $RUNTIME_DIR
    guard 监听      $GW_IP:5355(udp/tcp) / :5356(udp, 探针通道)

    验收：./verify.sh
    回滚：$CODE_DIR/tools/deploy_release.sh --rollback <release-id>
EOF
