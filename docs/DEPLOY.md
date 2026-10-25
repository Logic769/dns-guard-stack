# 部署

## 1. 前置条件

| 项 | 要求 |
|---|---|
| 系统 | Linux + systemd（Ubuntu 20.04+/Debian 11+/Alpine 3.18+/CentOS 7+/Rocky 9 均可） |
| 权限 | root（要写 systemd 单元、容器、iptables、nginx） |
| 依赖 | `docker`（含 compose 插件）、`dnsdist`（853/444 入口）、`python3` ≥ 3.6、`git`、`iptables`、`openssl`、`curl`；`nginx` 仅在跑不了 dnsdist 的 legacy 场景需要 |
| 网络 | 能出 443/853 到公网（拉镜像、DoT 上游）；对公网服务还需放行 853/443/444 |
| 端口 | 853（dnsdist DoT）、444（dnsdist DoH，路径 `/dns-query`）、443（nginx：看板/站点）、80（仅 ACME HTTP-01 用），以及各回环端口（`127.0.0.1:5199` dnsdist 控制台、`127.0.0.1:18083` 统计端点） |

```bash
# Debian / Ubuntu
apt-get update && apt-get install -y docker.io docker-compose-v2 dnsdist nginx python3 git iptables openssl curl
# Alpine
apk add docker docker-cli-compose dnsdist nginx python3 git iptables openssl curl
# CentOS / Rocky（dnsdist 在 EPEL）
yum install -y docker docker-compose-plugin epel-release dnsdist nginx python3 git iptables openssl curl
```

## 2. 三步开始

```bash
git clone https://github.com/<you>/dns-guard-stack.git
cd dns-guard-stack
cp .env.example .env          # 至少设置 DNS_DOMAIN；其余默认值已可用
sudo ./install.sh --dry-run   # 先看会做什么（不写系统）
sudo ./install.sh             # 真正执行（幂等，可重复运行）
sudo ./verify.sh              # 端到端验收
```

也可以完全非交互地跑：

```bash
sudo DNS_DOMAIN=dns.mydomain.net LISTS_PROFILE=fetch ./install.sh
```

`install.sh` 是幂等的：重复运行只会把配置重新渲染并对齐，名单、看板数据、容器卷都不会被清掉。

## 3. `.env` 变量（全部有默认值，只有 `DNS_DOMAIN` 建议显式设置）

### 站点与证书

| 变量 | 默认 | 说明 |
|---|---|---|
| `DNS_DOMAIN` | `dns.example.com` | DoT/DoH 对外域名，必须与证书 CN/SAN 一致 |
| `TLS_CERT` / `TLS_KEY` | 空 | 证书与私钥路径；两者留空 ⇒ 自动生成**自签**证书（内网/验证够用） |
| `ACME_EMAIL` | 空 | 填了就用 `acme.sh` 签真实证书（HTTP-01，需 80 端口可达） |
| `ACME_CRON` | `48 8 * * *` | ACME 续期定时（仅当用 ACME 时写入 root crontab） |

### 目录

| 变量 | 默认 | 说明 |
|---|---|---|
| `CODE_DIR` | `/opt/dnsguard` | 代码、状态、releases、backups |
| `LISTS_DIR` | `/opt/dnscrypt-proxy` | 名单与刷新器 |
| `CHAINMON_DIR` / `DEVFP_DIR` | `/opt/chainmon` / `/opt/devfp` | 两块看板 |
| `RUNTIME_DIR` | `/opt/dns-guard-stack/runtime` | 渲染后的配置文件（便于 diff 排查） |
| `STATE_DIR` / `VERIFIER_STATE_DIR` / `BACKUP_DIR` | 空 ⇒ 推导 | 留空即用 `CODE_DIR` 及其子目录 |

### 网络（**改网段必须成组改**）

| 变量 | 默认 | 说明 |
|---|---|---|
| `DOCKER_SUBNET` | `172.18.0.0/16` | 容器网段；与宿主已有网络冲突时改这里 |
| `ALTREPLICA_SUBNET` | `10.99.0.0/24` | alt 副本网段 |
| `GW_IP` | 空 ⇒ 自动探测 docker0 | guard 监听地址；**必须**与 AdGuard Home 里的上游地址一致 |
| `AGH_IP` / `AGHDQ_IP` | `172.18.0.2` / `172.18.0.6` | 两个 AdGuard Home 容器 |
| `UNBOUND_A_IP` / `UNBOUND_B_IP` / `UNBOUND_ALT_IP` | `.4` / `.5` / `.8` | 三个 Unbound |
| `ALTREPLICA_IP` / `DNSCRYPT_IP` | `10.99.0.2` / `172.18.0.9` | alt 副本 / dnscrypt-proxy |

### 宿主端口

`AGH_UI_PORT=3000`、`AGH_HTTPS_PORT=4443`（容器 443 → 回环，供 nginx DoH 反代）、`AGH_DOT_PORT=8854`（容器 853 → 回环）、`AGHDQ_UI_PORT=13000`、`AGHDQ_DNS_PORT=5533`（guard 见证通道）、`DOT_PORT=853`、`DOH_PORT=444`、`CHAINMON_PORT=8787`、`DEVFP_PORT=8789`。

端口冲突时只改这里，`install.sh` 会把 nginx 片段与 AGH 上游一起改掉。

### 上游

| 变量 | 默认 | 说明 |
|---|---|---|
| `UPSTREAM_A_QUIC` | `quic://dns.nextdns.io` | 境外主源（DoQ，需自行注册 NextDNS 可换成自己的 profile） |
| `UPSTREAM_A_BOOTSTRAP` | `223.5.5.5,223.6.6.6` | DoQ bootstrap 用的明文解析器 |
| `UPSTREAM_B` | 6 家国内 DoT | 格式 `ip@853#hostname`，逗号分隔 |
| `UPSTREAM_ALT` | 2 家第三方 DoT | 交叉见证用；请选与 A/B 不同运营方 |
| `DNSCRYPT_SERVERS` | `cs-nl,cs-fr,...` | dnscrypt-proxy 匿名中继（影子对比通道） |
| `DNSCRYPT_CACHE_UID` | `65532` | cache 目录属主 uid。镜像以 distroless 的 nonroot(65532) 运行而目录由 root 建立 ⇒ 不改属主会 `Couldn't write cache file ...: permission denied`，源列表缓存永久失效 |
| `DNSCRYPT_FORCE_TCP` | `false` | 容器默认走 UDP 443。部分网络丢弃出站 UDP 443，表现为日志刷 `[cs-*] TIMEOUT` + `waiting for at least one server to be reachable`（容器 Up 却不解析）⇒ 此时设 `true` 改走 TCP 443 |

### 名单

| 变量 | 默认 | 说明 |
|---|---|---|
| `LISTS_PROFILE` | `fetch` | `fetch`=安装时立即拉真实名单（v2fly 域名 / clang.cn 国内 IP / 否决名单；需要外网，失败自动退回骨架）；`minimal`=只写空骨架不联网 |
| `LISTS_CRON` | `35 4 * * *` | 每日自动刷新 |

### 安全与资源

| 变量 | 默认 | 说明 |
|---|---|---|
| `CN_TRUST_MODE` | `known` | `none` 最严（全部要见证）/ `known` 国别后缀+白名单免见证 / `all` 旧行为 |
| `CN_EXIST_MODE` | `enforce` | 是否启用存在性见证 |
| `GUARD_MEMORY_MAX` / `GUARD_MEMORY_HIGH` | `192` / `160`（MiB） | guard 内存上限 |
| `VERIFIER_MEMORY_MAX` / `VERIFIER_MEMORY_HIGH` | `128` / `100` | verifier 内存上限 |
| `CHAINMON_MEMORY_MAX` / `DEVFP_MEMORY_MAX` | `256` / `176` | 看板上限 |
| `DOTF_SPOOL` | `/var/log/dotfront.jsonl` | DoT 明文内腿 spool：`dotfront-spool` 写、devfp 的 `dotfront_spool` 读，两者必须一致 |
| `AGH_ADMIN_USER` / `AGH_ADMIN_PASSWORD` | `admin` / 空 | AGH 面板账号；密码留空则安装后首次登录自行设置 |
| `DASH_USER` / `DASH_PASSWORD` | `admin` / 空 | 看板 Basic Auth；留空则不启用鉴权 |
| `INSTALL_NGINX` | `0` | legacy 开关：默认 853/444 交给 dnsdist；设 1 才安装 nginx 的 DoT/DoH 片段（两者端口互斥） |
| `NGINX_VHOST_DIR` / `NGINX_BIN` | 宝塔默认 | nginx 站点目录与二进制 |
| `TZ` | `Asia/Shanghai` | 容器与时区 |

## 4. `install.sh` 都做了什么

1. **依赖检查**：`docker`/`nginx`/`python3` 缺失即报错；无 systemd 则跳过服务安装并打印手动启动方式
2. **渲染配置**：`deploy/**/*.tpl` 用 `.env` 渲染到 `RUNTIME_DIR`，并把 `/opt/<服务>` 路径统一改写为 `.env` 里的真实路径
3. **部署代码**：`core/`、`tools/`、`probes/`、`firewall/` → `CODE_DIR`；`dashboards/` → 两块看板目录
4. **名单**：默认 `LISTS_PROFILE=fetch` —— 立即拉真实名单（域名 → 否决/IP → 完整性校验）；条数不足（多半没外网）会自动退回骨架并告警，不阻断安装
5. **容器**：`docker compose up -d`；按需等待 AdGuard Home 面板就绪并设置管理员密码、AGH 上游指向 guard
6. **证书**：自签 / ACME / 复用你给的路径
7. **dnsdist 入口**：渲染 `deploy/dnsdist/dnsdist.conf.tpl` → `/etc/dnsdist/dnsdist.conf`（口令自动生成、权限 0640），装单元并 `enable --now`；查询日志 `/var/log/dnsdist-query.log` + logrotate；把统计端点与 apiKey 写进 `chainmon.service.d/30-dnsdist-stats.conf`。缺 dnsdist 时告警并退化到 legacy 的 nginx 片段（`INSTALL_NGINX=1`）
8. **systemd**：安装单元与 timer（含 DoT 明文内腿采集器 `dotfront-spool`），`daemon-reload` + `enable --now`；写入内存限额
9. **防火墙**：`firewall/dnsguard-fw.sh --apply`（先算目标表 → 自检 → 单次 `iptables-restore`，失败回滚）
10. **验收**：`tools/release_consistency.py` + 回环探针；失败会打印诊断命令（不阻断安装）

`--dry-run` 只打印动作；`--skip-firewall`、`--fetch-lists` 见脚本 `--help`。

## 5. 证书

**自签（默认）**：`TLS_CERT`/`TLS_KEY` 留空即生成到 `CODE_DIR/certs/`，客户端需手动信任。

**ACME**：

```bash
ACME_EMAIL=you@example.com
# 需要 80 端口可达；安装后自动写 ACME_CRON 续期
```

**手动**：直接填 `TLS_CERT` 与 `TLS_KEY`。

> DoH 客户端会校验 SNI 与证书链，`DNS_DOMAIN` 必须与证书一致。

## 6. 名单

| 档 | 内容 | 何时用 |
|---|---|---|
| `fetch`（默认） | 从上游生成（v2fly 全量 tar / clang.cn / chnroutes2） | 生产使用；需要外网 |
| `minimal` | 空骨架 + 国别后缀 | 先跑通链路、或做隔离复现；guard 按"未知即不信任"运行（更安全但多一次见证） |

```bash
sudo $CODE_DIR/tools/refresh-all-cn-lists.sh    # 域名 → 否决/IP → 完整性校验
tail -5 /var/log/cn-lists-refresh.log
```

名单更新**不需要重启服务**（guard 按 mtime 热重载，60 秒内生效）。

## 7. 不同环境的差异

**宝塔面板**：默认 `NGINX_VHOST_DIR=/www/server/panel/vhost/nginx`。面板重写站点配置时可能覆盖直接写在站点里的 `location`，所以本项目把片段放进 `extension/<站点>/` 子目录。

**Docker 网段冲突**：改 `DOCKER_SUBNET` 与各 `*_IP`，重新 `./install.sh`，然后 `firewall/dnsguard-ip-reconcile.sh --check` 确认 6 处（nginx proxy_pass、unbound A forward-addr、dotfront drop-in、AGH 上游、guard 监听、探针源别名）都与 `docker inspect` 一致。

**没有 systemd**（容器里跑）：install.sh 会跳过单元安装，打印 `python3 core/guard.py &` 之类的手动启动命令；功能可用，但没有内存限额与自动重启。

**已有 nginx 站点**：本项目用独立 `server_name` 与 stream 片段，不会覆盖其它站点。

## 8. 常见故障

| 症状 | 排查 |
|---|---|
| 容器起来又退出 | `docker logs <容器>`；多是 `.env` 的 IP 与 `DOCKER_SUBNET` 不匹配，或端口被占 |
| guard 起来但 `5355` 连不上 | `journalctl -u dnsguard -n 50`；确认 `GW_IP` 等于 `ip -4 addr show docker0` 的地址 |
| DoT 连不上 | `openssl s_client -connect <ip>:853 -servername $DNS_DOMAIN`；`systemctl status dnsdist`、`journalctl -u dnsdist -n 50`（端口被 nginx 占 / 证书不可读最常见）；legacy 场景再查 stream include 与 `nginx -t` |
| DoH 返回 502 / 证书错误 | 先看 dnsdist 日志与 `/etc/dnsdist/dnsdist.conf` 的证书路径；legacy 场景看 `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:${AGH_HTTPS_PORT}/` 与 `limit_conn/limit_req` |
| Chainmon 缓存命中率恒为 0% | `CHAINMON_DNSDIST_API_KEY` 与 `/etc/dnsdist/dnsdist.conf` 的 `apiKey` 是否一致；`curl -H "X-API-Key: ..." http://127.0.0.1:18083/api/v1/servers/localhost/statistics` |
| 国内域名变慢/失败 | `python3 $CODE_DIR/probes/probe-cand.py www.qq.com` 对比 A/B/guard 的答案 |
| 全部 SERVFAIL | 看 `stats.json` 的 `fc_*`；`dig @127.0.0.1 -p 5353 cloudflare.com` 检查 A 侧 |
| 门禁红灯 | `python3 $CODE_DIR/tools/release_consistency.py`；两服务重启一次 |
| 宿主 OOM | `systemctl show dnsguard -p MemoryMax -p MemoryCurrent`；按 `docs/OPERATIONS.md` 调限额 |

## 9. 卸载

安装脚本不提供自动卸载（避免误删生产数据）。手动步骤：

```bash
# 1) 停服务与容器
systemctl disable --now dnsguard dnsguard-verifier chainmon devfp 2>/dev/null
docker compose -f "$RUNTIME_DIR/docker-compose.yml" down

# 2) 移走单元（含 dnsdist）与 nginx 片段
systemctl disable --now dnsdist 2>/dev/null
rm -f /etc/systemd/system/dnsdist.service
rm -rf /etc/systemd/system/dnsdist.service.d
rm -f /etc/logrotate.d/dnsdist-query
rm -f /etc/systemd/system/dnsguard.service /etc/systemd/system/dnsguard-verifier.service
rm -rf /etc/systemd/system/dnsguard.service.d /etc/systemd/system/dnsguard-verifier.service.d
rm -f "$NGINX_VHOST_DIR/tcp/dnsguard-dot-853.conf" "$NGINX_VHOST_DIR/extension/dnsguard/"*.conf
systemctl daemon-reload && nginx -t && nginx -s reload

# 3) 防火墙：从备份恢复，或直接清掉本项目加的链
/usr/local/sbin/dnsguard-fw.sh --rollback 2>/dev/null || true
```

数据目录（`CODE_DIR`、`LISTS_DIR`、`RUNTIME_DIR` 里的容器卷）**不会**被删除，确认不需要后再自行清理。
