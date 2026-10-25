# DNS 解析系统详解 · dns.example.com

> 编写时间：2026-10-15 23:30（Asia/Shanghai）
> 对应线上状态：发布 `20261015-audit-fixes-11`（guard 于 22:54:56 启动，PID 1765985）
> 依据：对一台已部署实例（`SERVER_IP`）的**只读**勘察结果（systemd/容器/端口/配置/名单/脚本清单），以及历次审计与修复记录。
>
> 本文按默认路径叙述（`/opt/dnsguard` = `.env` 的 `CODE_DIR`，`/opt/dnscrypt-proxy` = `LISTS_DIR`，域名写作 `dns.example.com`）。你改了 `.env` 的路径或域名时，把文中对应路径/域名替换即可。
> 原则：只写实际存在的东西；凡是未能亲眼核实的，都在正文里注明「未展开核实」。

---

## 0. 一分钟速览

这套系统是**一套自建的、带防投毒与防污染能力的 DNS 解析服务**，同时服务两类用户：

1. **家里/自己人**：通过 AdGuard Home 的 DoT(853)/DoH(443,444) 加密入口使用；
2. **公网任意客户端**：同一个加密入口对公网开放（客观事实：入口没有客户端认证）。

它要解决的问题有三个，按重要性排序：

| 要防的东西 | 通俗解释 | 主要防线 |
|---|---|---|
| **投毒 / 篡改** | 路上有人把假 IP 塞进答案，把你带到钓鱼站 | 全程加密上游（DoT/DoQ）、DNSSEC 验证、**双源交叉核对**、防伪造报文校验 |
| **单一来源被骗** | 某个上游自己撒谎或被人控制 | 境外主源 + 独立认证备用源 + 第三方核验进程（verifier）互相印证 |
| **国内分流被滥用** | 国内线路快，但如果把它当"可信"用，境外域名被国内源给出错答案就会漏给客户端 | **国内路由**与**国内可信授权**拆成两层判据 + 否决名单 + 例外清单 + 白名单 |

一句话概括数据流（正常路径）：

```
客户端 ──DoT:853 / DoH:444──▶ dnsdist（TLS 终结 + 真实客户端 IP + PacketCache + 限速）
       ──▶ AdGuard Home（adgh，过滤 + 缓存）
       ──▶ guard（唯一上游 172.18.0.1:5355，防投毒决策中枢）
              ├─ 境外主源：unbound A ──▶ aghdq ──▶ NextDNS（DoQ）+ 本地 DNSSEC 验证
              ├─ 国内分流：unbound B ──▶ 6 条国内加密 DoT（360 / 阿里 / dns.pub）
              ├─ 认证备用：unbound-alt（境外 DoT）
              └─ 独立核验：verifier 进程（Unix socket）
```

**这台机器上没有任何一环是"多余"的**：每一层解决一个具体问题，也各自制造了一个新的失败面（第 7 章如实列出）。

---

## 1. 全局地图

### 1.1 分层结构（从上到下）

| 层 | 位置 | 角色 | 说明 |
|---|---|---|---|
| ① 接入层 | `dnsdist` `0.0.0.0:853 / 444`（控制台 5199、统计 18083 只在回环）；nginx `0.0.0.0:443` | TLS 终结、限速、缓存、按 SNI 拒绝 | 公网唯一入口。**2026-10-22 起 853/444 由 dnsdist 直接终结**（此前是 nginx stream/http 反代，后端只能看到 127.0.0.1）；443 仍是 nginx，承载看板与站点 |
| ② 过滤缓存层 | 容器 `adgh`（172.18.0.2:53，另映射 127.0.0.1:4443/8854/3000） | AdGuard Home v0.107.73：过滤规则、DNS 缓存、查询日志 | **唯一上游**只有 guard，`fallback_dns: []` |
| ③ 决策层 | 宿主进程 `guard`（172.18.0.1:5355 udp+tcp；5356 探针通道） | 防投毒核心：分流、判定、缓存、见证 | systemd `dnsguard.service`，发布 13 |
| ④ 核验层 | 宿主进程 `verifier`（Unix socket `/run/dnsguard/verifier.sock`） | 独立进程做二次核验，隔离资源池 | systemd `dnsguard-verifier.service` |
| ⑤ 上游层 | 容器 `unbound`(A, 172.18.0.4:5353)、`unbound-b`(B, 172.18.0.5:5354)、`unbound-alt`(alt, 172.18.0.8:5357)、`aghdq`(172.18.0.6:53)、`aghdq2`(172.18.0.9:53)、`aghcf`(172.18.0.10:53)、`alt-replica-unb`(15353) | 三个 Unbound 实例 + 三个上游 AGH 出口（NextDNS / Quad9 / Cloudflare）+ 一个副本 | 全部 mvance/unbound:latest 或 adguard/adguardhome:v0.107.73 |
| ⑥ 独立解析器 | 宿主进程 `dnscrypt-proxy`（127.0.0.2:5353、127.0.0.1:5399） | DNSCrypt/DoH 匿名中继出口 + 国内名单文件搬运 | systemd `dnscrypt-proxy-local.service` |
| ⑦ 数据层 | `/opt/dnsguard/*.txt`、`/opt/dnscrypt-proxy/*.txt` | 六份名单 + 三份快照 | 见第 5 章 |
| ⑧ 运维层 | systemd timers + cron + 脚本 | 部署门禁、IP 对账、防火墙对账、探针、看门狗、快照 | 见第 6 章 |

### 1.2 端口与监听（实测 `ss -lntup`）

| 端口 | 监听方 | 用途 |
|---|---|---|
| `0.0.0.0:853` (tcp) | dnsdist | DoT 公网入口（`addTLSLocal`，直接终结 TLS，拿得到真实 `remoteaddr`） |
| `0.0.0.0:443` (tcp) | nginx | HTTPS：各看板、宝塔等（legacy 的 DoH `/dns-query` 也在这里） |
| `0.0.0.0:444` (tcp) | dnsdist | DoH 专用端口（`addDOHLocal`，**仅**放行 `/dns-query`） |
| `127.0.0.1:5199` (tcp) | dnsdist | 控制台（`dnsdist -c` 连接；`setKey` 保护） |
| `127.0.0.1:18083` (tcp) | dnsdist | 只读 HTTP 统计端点（chainmon 读 `cache-hits` / `cache-misses`） |
| `172.18.0.1:5355` (udp+tcp) | python3 = guard | AGH 的唯一上游（宿主 docker0 网关地址） |
| `172.18.0.1:5356` (udp) | python3 = guard | 探针/自检通道（本机探针走这里，不占 5355 主路径） |
| `127.0.0.2:5353` (udp+tcp) | dnscrypt-proxy | 匿名中继本地入口（verifier 的"快速 UDP 源"） |
| `127.0.0.1:5399` (udp+tcp) | dnscrypt-proxy | DNSCrypt 本地入口（供域名名单生成等使用） |
| `127.0.0.1:5353` / `172.18.0.1:5353` | docker-proxy → unbound A | 境外主源 |
| `127.0.0.1:5354` / `172.18.0.1:5354` | docker-proxy → unbound B | 国内分流源 |
| `127.0.0.1:5357` | docker-proxy → unbound-alt | 认证备用源 |
| `127.0.0.1:15353` | docker-proxy → alt-replica-unb | alt 的副本/演练用 |
| `127.0.0.1:5533` | docker-proxy → aghdq | 上游 AGH 的回环映射（guard 的 DoQ 主通道） |
| `127.0.0.1:5534` | docker-proxy → aghdq2 | DoQ2（Quad9 dns10）通道 |
| `127.0.0.1:5535` | docker-proxy → aghcf | CN 见证源 + SERVFAIL 快速透传源（Cloudflare 1.1.1.1 DoT） |
| `127.0.0.1:4443` | docker-proxy → adgh:443 | AGH 自己的 DoH（nginx 443/444 的 `/dns-query` 反代到它） |
| `127.0.0.1:8854` | docker-proxy → adgh:853 | AGH 自己的 DoT（**nginx 853 的 DoT 实际走到 172.18.0.2:53，不是这里**） |
| `127.0.0.1:3000` | docker-proxy → adgh:3000 | AGH 管理面板 |
| `127.0.0.1:8787` | python3 = chainmon | 链路看板后端（nginx `/chain/` 反代） |
| `127.0.0.1:8789` | python3 = devfp | 设备指纹看板后端（nginx `/devices/`、`/join`） |

> ⚠️ 有两个「53 端口」概念要分清：**adgh 容器的 53**（`172.18.0.2:53`，是 DoT 的落地目标）与 **unbound 的 53**（容器内 53，被映射到宿主 5353/5354/5357）。

### 1.3 容器清单（`docker ps`）

| 容器 | 镜像 | 网络位置 | 角色 | 状态 |
|---|---|---|---|---|
| `adgh` | adguard/adguardhome:v0.107.73 | 172.18.0.2 | 主入口：过滤 + 缓存 + 查询日志 | Up 2 days |
| `aghdq` | adguard/adguardhome:v0.107.73 | 172.18.0.6 | 上游 AGH：转发到 `quic://dns.nextdns.io` | Up 4 days |
| `aghdq2` | adguard/adguardhome:v0.107.73 | 172.18.0.9 | 第二条 DoQ 出口：`quic://dns10.quad9.net`（guard 的 slow 列表 / DoQ2） | Up 4 days |
| `aghcf` | adguard/adguardhome:v0.107.73 | 172.18.0.10 | Cloudflare 1.1.1.1 DoT：CN 存在性见证 + SERVFAIL 快速透传 | Up 4 days |
| `unbound` | mvance/unbound:latest | 172.18.0.4 | 境外主源 A（本地 DNSSEC 验证） | Up 5 days (healthy) |
| `unbound-b` | mvance/unbound:latest | 172.18.0.5 | 国内分流 B（6 条国内加密 DoT） | Up 5 days (healthy) |
| `unbound-alt` | mvance/unbound:latest | 172.18.0.8 | 认证备用（境外 DoT，独立 TCB） | Up 5 days (healthy) |
| `alt-replica-unb` | mvance/unbound:latest | 10.99.0.2（altreplica0） | alt 的副本，用于演练/灰度 | Up 5 days (healthy) |
| `openlist` | openlistteam/openlist | 172.19.0.2（baota_net） | 与本 DNS 链路**无关**（文件列表服务） | Up 9 days |

> 全部容器都在 Docker **默认 bridge `172.18.0.0/16`**（不是自定义网络）⇒ **容器名不能互相解析**，所以所有容器间通信都靠**写死的 IP**，并由对账脚本守着（见 6.3）。

### 1.4 内存与资源限额（systemd cgroup，实测）

| 单元 | MemoryHigh | MemoryMax | 其它 |
|---|---|---|---|
| `dnsguard` | 160 MiB | 192 MiB | TasksMax=512、Nice=-2、OOMScoreAdjust=-200 |
| `dnsguard-verifier` | 100 MiB | 128 MiB | MemorySwapMax=0 |
| `chainmon` | — | 256 MiB | timer 每 30 分钟重启一次（防长期泄漏） |
| `devfp` | 128 MiB | 176 MiB | — |
| `dnscrypt-proxy-local` | — | 64 MiB | — |
| `unbound-alt-readiness` | — | 64 MiB | oneshot，每分钟跑一次 |
| `adgh` / `aghdq` 容器 | 无 cgroup 限额（`infinity`） | — | 由容器自身与宿主内存约束 |
| 宿主合计 | — | **1870 MiB 总内存**，swap 3 GiB | 常态可用内存约 500–650 MiB |

> 这是**单机单出口**：所有入口、决策、上游、监控都在这台 2 GiB 的轻量服务器上（审计 F5 已登记，见第 7 章）。

### 1.5 文件清单（谁在哪里）

**宿主进程单元（systemd）**

| 单元 | ExecStart | 作用 |
|---|---|---|
| `dnsguard.service` | `/usr/bin/python3 /opt/dnsguard/current/guard.py` | 决策中枢 |
| `dnsguard-verifier.service` | `/usr/bin/python3 /opt/dnsguard/current/verifier.py` | 独立核验 sidecar |
| `dnscrypt-proxy-local.service` | `/usr/bin/dnscrypt-proxy -config /opt/dnscrypt-proxy/dnscrypt-proxy.toml` | 匿名中继 |
| `chainmon.service` | `/usr/bin/python3 /opt/chainmon/chainmon.py` | 链路看板后端 |
| `devfp.service` | `/usr/bin/python3 /opt/devfp/devfp.py` | 设备指纹看板后端 |
| `dotfront-spool.service` | `/usr/bin/python3 $CODE_DIR/tools/dotfront-spool.py` | DoT 明文内腿采集（给 devfp，见 3.2） |
| `probe-srcaddr.service` | `/usr/sbin/ip addr replace 172.18.0.99/16 dev docker0` | 给探针准备一个独立源地址 |
| `unbound-b-53-block.service` | iptables 封 unbound-b 的明文 53 出站 | 配合 6.4 防火墙 |
| `dnsguard-firewall.service` | `/usr/local/sbin/dnsguard-fw.sh --apply` | 一次性应用防火墙（oneshot，exited） |
| `cgroup-memsw-limits.service` | 设置内存/swap 限额 | 资源治理 |

**定时器（systemd timers）**

| Timer | 周期 | 作用 |
|---|---|---|
| `dnsguard-canary.timer` | 每 5 分钟 | canary 看门狗：整链路自检，判断"客户端是否真被投毒暴露" |
| `dnsguard-alt-warmup.timer` | 每 1 分钟 | 预热 unbound-alt（root/TLD DNSKEY + bogus 样本常驻缓存） |
| `unbound-alt-readiness.timer` | 每 1 分钟 | alt 就绪门：产出 `/run/unbound-alt-ready.json` 供 guard 判断 |
| `dns-chain-probe.timer` | 每 5 分钟 | 分层探针（A / B / guard / DoT / DoH 五层） |
| `dnsguard-ip-reconcile.timer` | 每 5 分钟 | 容器 IP 漂移对账（nginx/unbound/dotfront/AGH） |
| `dnsguard-fw-reconcile.timer` | 每 5 分钟 | 防火墙规则对账（原子收敛） |
| `chainmon-restart.timer` | 每 30 分钟 | 重启 chainmon（防长期内存增长） |
| `dnsguard-asn-snapshot.timer` | 每日 03:05 | ASN 快照（供 ASN 门判据使用） |

**cron**

| 时间 | 命令 | 作用 |
|---|---|---|
| `35 4 * * *` | `/bin/bash $CODE_DIR/tools/refresh-all-cn-lists.sh` | **统一名单刷新**（域名名单 → 否决+IP → 校验三步） |
| `48 8 * * *` | `/root/.acme.sh/acme.sh --cron` | 证书自动续期（含部署钩子，会同步 nginx 与 AGH） |
| `*/5 * * * *` | `/root/dsh-scripts/adg-stats.py` | AGH 统计采集（与本链路弱相关） |
| `26 22 * * *` | 宝塔面板自身任务 | 与本链路无关 |

**关键脚本（按目录）**

`/opt/dnsguard/`（决策与运维）：

| 文件 | 大小 | 作用 |
|---|---|---|
| `current/guard.py` | 254466 B | 决策中枢（发布 11） |
| `current/verifier.py` | 4319 B | 核验 sidecar |
| `deploy_release.sh` | 4187 B | 发布切换 + 门禁 + 自动回滚 |
| `release_consistency.py` | 7619 B | F5 门禁：两进程必须同一发布 |
| `verify-release-data.py` | 6227 B | F7：发布数据清单与内容约束校验 |
| `make-snapshot.sh` | 3477 B | 生产状态快照 |
| `canary_watch.py` | 16719 B | canary 看门狗 v2（全链路） |
| `acceptance_check.py` | 8506 B | 验收证据采集 |
| `asn_snapshot.py` / `asn_cache.py` | 3675 / 7661 B | ASN 归类缓存与快照 |
| `agh-cache-clear.sh` | 1887 B | 调 AGH API 清缓存（撤销闭环） |
| `cn-trust-revoke.sh` | 1891 B | 撤销某域名的国内信任（改例外 + 清 AGH 缓存） |
| `dns-entry-probe.py` / `external-probe.py` | 4195 / 4836 B | 入口探针 / 外部探针 |
| `probe-n1n2n3.py` / `probe-ad-declared.py` | 3895 / 3294 B | 针对 N1/N2/N3 与 AD 声明的专项探针 |
| `stats.json` / `stats_meta.json` | 14116 / 8720 B | 运行指标 / 发布指纹 |
| `poisoned.json` / `bad_ips.json` / `asn_class.json` | 140033 / 115230 / 9943 B | 投毒记录 / 坏 IP 库 / ASN 分类 |

`/opt/dnscrypt-proxy/`（名单与刷新）：

| 文件 | 大小 | 作用 |
|---|---|---|
| `refresh-cn-rules.py` | 20367 B | 域名名单生成（typed + forwarding-rules + 快照） |
| `refresh-cn-veto-ip.py` | 22053 B | 否决名单 + IP 段生成 |
| `refresh-all-cn-lists.sh` | 1556 B | 统一入口（顺序调上面两个 + 校验） |
| `verify-cn-lists.py` | 7442 B | 名单完整性 + 签名校验 |
| `cnlist_history.py` | 8207 B | 变更归档 + GPG 签名（MODULE） |
| `dnscrypt-proxy.toml` | — | 匿名中继配置 |
| 六份名单 | 见第 5 章 | 数据 |

`/usr/local/sbin/`（系统级）：

| 文件 | 大小 | 作用 |
|---|---|---|
| `dnsguard-fw.sh` | 13005 B | 防火墙原子收敛脚本 |
| `dnsguard-fw-table.py` | 16372 B | 纯文本表变换工具（生成新规则表） |
| `dnsguard-ip-reconcile.sh` | 16605 B | 容器 IP 漂移对账 |
| `unbound-alt-readiness.py` | 42160 B | alt 就绪门（含启动验证） |
| `dnsguard-alt-warmup.py` | 2284 B | alt 缓存预热 |
| `dns-chain-probe.py` | 10712 B | 分层探针（严格 TLS） |
| `dnsguard-alt-restart.sh` | 1108 B | 重启 alt 并等就绪 |

`/opt/chainmon/`、`/opt/devfp/`（看板）：`chainmon.py`（采集后端，127.0.0.1:8787）、`qlog_window.py`（AGH 查询日志窗口统计）、`resource_probe.py`（资源探针）、`devfp.py`（指纹后端，127.0.0.1:8789）、`index.html`（两个看板前端）、`join.html`（/join 采集页，**每次请求读盘，改它不用重启**）。

---

## 2. 一次查询的完整旅程

下面用「我的手机查 `www.qq.com`」和「查一个境外域名 `www.google.com`」两条真实路径，把这条链走一遍。

### 2.1 第 0 步：客户端选路

- 支持 DoT 的设备（Android 私人 DNS、自建客户端）：连 `dns.example.com:853`；
- 支持 DoH 的：`https://dns.example.com/dns-query`（443）或 `https://dns.example.com:444/dns-query`（444）；
- 明文 53：**本机不对外提供**（宿主公网 53 未监听；adgh 的 53 只在容器网络与 docker 内部）。

> 大白话：门只有两个 —— 加密的 853 和加密的 443/444。没有明文门。

### 2.2 第 1 步：dnsdist 接入（TLS 终结 + 真实客户端 IP + 缓存 + 限速）

**为什么换**：nginx 反代到 `127.0.0.1` 之后，后端只看得到 `127.0.0.1`，真实客户端 IP 在内腿里丢失，只能靠 `dotfront-spool` 去抓明文慢慢补。dnsdist 自己终结 TLS，`dq.remoteaddr` 就是真实来源；顺带把 PacketCache 和限速放在这一层。

配置模板 `deploy/dnsdist/dnsdist.conf.tpl` → 安装后落在 `/etc/dnsdist/dnsdist.conf`，要点：

```lua
setACL({"0.0.0.0/0", "::/0"})                       -- 默认 ACL 只含内网，不放开会拒绝所有公网客户端
newServer({address="172.18.0.2:53", name="agh", checkInterval=10})
pc = newPacketCache(32768, {maxTTL=86400, minTTL=0, temporaryFailureTTL=60, staleTTL=60, dontAge=false})
getPool(""):setCache(pc)
addTLSLocal("0.0.0.0:853", .../fullchain.pem, .../privkey.pem, {provider="openssl"})
addDOHLocal("0.0.0.0:444", .../fullchain.pem, .../privkey.pem, {"/dns-query"}, {provider="openssl"})
dbr:setQueryRate(200, 10, "Exceeded query rate", 10, DNSAction.Refused)
```

- 缓存**在这一层**（不是 AGH）⇒ chainmon 的命中率必须读 `127.0.0.1:18083` 的统计接口，否则永远显示 0%；
- 查询日志 `/var/log/dnsdist-query.log` 由 `markQuery` 以 append 方式写（`pcall` 包住，写日志失败绝不影响解析），chainmon 的 qlog 窗口读它；
- 853/444 与 nginx 片段**端口互斥**：切换时先禁用 nginx 的 `tcp/dnsguard-dot-853.conf` 与 `9.dnsguard-doh444.conf`。

**legacy：nginx 的 DoT :853**（2026-10-22 之前的入口，现只作退路；配置 `/www/server/panel/vhost/nginx/tcp/dns-example-dot-853.conf`，1470 B，stream 块）：

```
limit_conn_zone $binary_remote_addr zone=dot_perip:10m;   # 每源地址一桶
limit_conn_zone $server_port      zone=dot_total:1m;      # 全端口一桶
server {
    listen 853 ssl;
    limit_conn dot_perip 32;       # 单源最多 32 条并发 DoT 连接
    limit_conn dot_total 512;      # :853 全部来源合计最多 512 条
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_certificate     .../cert/dns.example.com/fullchain.pem;
    proxy_pass 172.18.0.2:53;      # 直接打到 adgh 容器的 53
    proxy_connect_timeout 5s;
    proxy_timeout 30s;
}
```

- 这里 nginx **只做 TLS 终结与限流**，不解析 DNS；
- `proxy_pass 172.18.0.2:53` 是**写死的容器 IP**，由对账脚本守着（6.3）；
- 因为走 stream 代理，adgh 看到的是 **docker 网关 172.18.0.1**，不是真实客户端。真实来源由 `dotfront-spool` 补（3.2）。

**DoH :443 / :444**（`9.devfp-doh444.conf` 与 `dns.example.com.conf`）：

```
location = /dns-query {
    limit_conn perip 32;                    # 每源 32 并发
    limit_req  zone=doh_req burst=200 nodelay;   # 每源 200 r/s，突发 200
    add_header Accept-CH "Sec-CH-UA-Model, ..." always;   # UA-CH 高熵请求（/join 用）
    proxy_pass https://agh_doh;             # 反代 adgh:443（keepalive 池，直连绕 docker-proxy）
    proxy_ssl_server_name on;
}
```

- 443 的 server 里 `location = /dns-query` 精确匹配优先于其它反代，所以 DoH 与"看板/宝塔"等共存互不影响；
- 另外有一份 `00.reject-unknown-sni.conf`：**SNI 不是已知域名的连接一律被拒**（防止用 IP 直连或乱 SNI 扫端口）；
- `1.ech-cover.conf`：ECH 相关覆盖配置（让不支持 ECH 的客户端不至于异常）。

### 2.3 第 2 步：AdGuard Home（`adgh` 容器）——过滤与缓存

配置 `/opt/adgh/conf/AdGuardHome.yaml` 关键项：

| 项 | 值 | 含义 |
|---|---|---|
| `port` | 53 | 容器内 DNS 端口 |
| `upstream_dns` | **只有一个** `172.18.0.1:5355` | 唯一上游 = guard |
| `bootstrap_dns` / `fallback_dns` | `[]` | **没有兜底**：guard 挂了就真的解析不了（刻意如此，避免绕过防线） |
| `upstream_mode` | `load_balance` | 只有一个上游，实为直连 |
| `fastest_timeout` | `1s` | 也只有一个上游，影响小 |
| `refuse_any` | `true` | 拒绝 ANY 查询（防放大） |
| `ratelimit` | `200`（每 `/24` 子网） | 第二道限流（在 nginx 之后） |
| `cache_size` | 64 MiB | 缓存条数上限 |
| `cache_ttl_min` / `cache_ttl_max` | `0` / **86400** | **不缩短也不延长**，TTL 在 0–86400 之间原样使用 |
| `filtering_enabled` | `true` | 过滤规则开启（含订阅列表） |
| `protection_enabled` | `true` | 保护（含安全浏览开关是 false，但过滤生效） |
| `parental_enabled` / `safebrowsing_enabled` | `false` / `false` | 家长控制与安全浏览未开 |
| `port_https` / `port_dns_over_tls` / `port_dns_over_quic` | 443 / 853 / 853 | AGH 自身监听（容器内），再映射到宿主 4443/8854 |
| `blocked_hosts` | `version.bind`, `id.server` | 阻止版本探测 |
| `allowed_clients` / `disallowed_clients` | `[]` / `[]` | **不限制客户端**（审计 F3 登记的入口无认证） |
| 查询日志 | 开启 | 供 devfp 采集行为 |

**这一步做了什么**：
1. 按过滤规则决定"拦截"（返回 0.0.0.0 或 NXDOMAIN）还是"放行"；
2. 命中缓存则直接回（**此时不会走到 guard**）；
3. 未命中则把查询转给 **guard**（唯一上游）。

> ⚠️ 两个重要副作用（第 7 章会再提）：
> ① AGH 缓存最长 24 小时，guard 侧撤销某个域名的授权后，**AGH 里已有的旧答案不会自动失效**（需要显式清缓存，见 6.5）；
> ② `example.com` 这类域名可能被订阅过滤规则命中（`IsFiltered=True`），所以**不能拿它当"上游可用性"的探针样本**。

### 2.4 第 3 步：guard ——决策中枢（核心）

guard 收到的是 AGH 转来的 DNS 查询（UDP/TCP 到 `172.18.0.1:5355`）。它做的事按顺序：

**A. 前置处理（不涉及上游）**
1. 解析报文、校验问题段（QNAME/QTYPE/QCLASS）；
2. 查**准入缓存**（`_adm_cache`，只存"安全/可接受"答案，见 4.10）——命中就直接回；
3. 查**热缓存**（hot cache，短 TTL 预取与热点加速，`GUARD_HOT_MIN_TTL=30`）；
4. 判断是否属于"国内域名"（`is_cn_domain`，见 4.5）：决定后续**要不要优先问国内源 B**；
5. 判断是否属于"可信国内域名"（`is_cn_trusted`，见 4.6）：决定国内源 B 的答案**能不能免去交叉见证**。

**B. 上游并行/对冲（hedged）**
6. 主问**境外主源 A**（unbound A → aghdq → NextDNS）；
7. 若是国内域名，同时/优先问**国内源 B**（unbound B → 6 条国内 DoT）；
8. 必要时用**认证备用 alt**（unbound-alt，独立进程/缓存）核对；
9. 用 `GUARD_HEDGE_MS=280` 做对冲：先到的先看，慢的继续但不无限等（`GUARD_SYNC_BUDGET=3.8` 秒总预算）。

**C. 判定与交叉核对（这套系统的灵魂）**
10. 每个上游答案都被打上一个**策略档位**（SECURE / ACCEPTED / BOGUS / TRANSPORT / UNKNOWN，见 4.1）；
11. 看 DNSSEC：有有效签名 ⇒ SECURE；没有签名但看起来正常 ⇒ ACCEPTED；签名坏了（含带 EDE 15 的 SERVFAIL）⇒ BOGUS；网络层失败 ⇒ TRANSPORT；
12. **可疑 IP 判定**：答案里的 IP 若命中坏 IP 库 / 与域名分类矛盾（`suspicious`），直接不采信；
13. **见证**（witness）：对"采纳国内源答案""采纳没有 DNSSEC 的答案"这类高风险动作，向另一个独立来源再问一次，确认它也说"存在/是这个答案"（见 4.3）；
14. **存在性见证**（`cn_exist_veto`）：专门确认"这个域名到底存在吗"——因为投毒最常见的手法就是**给一个不存在的域名返回假 IP**（见 4.4）；
15. **否决名单**（veto 25025 条）：名单里的域名，**一律不走国内可信路径**（见 4.8）；
16. **例外清单**（5 条）与**白名单**（19 条）：例外让某些域彻底不走国内（连路由都不走）；白名单让明确的国内大站免见证（见 4.7）。

**D. 缓存与返回**
17. 采纳的答案写入准入缓存（SECURE ≤900s、ACCEPTED ≤300s 的内部有效期）；
18. **出口前逐 RR 老化 TTL**：按"报文生成时刻 → 现在"的真实流逝裁剪每条记录的 TTL（`age_wire`）；
19. 出口 TTL 若被上游标成 stale（EDE 3/19）则**不写缓存、不延长 TTL**（`_stale_of`/`_stale_note`，见 4.11）；
20. 校验返回报文的"身份"（ID/QR/opcode/问题段/各段计数/长度），不匹配的丢弃（`response_matches`，见 4.13）；
21. 发回 AGH → AGH 按自己的缓存策略回给客户端。

**E. 旁路核验（verifier）**
22. 在高风险路径上，guard 通过 Unix socket 把查询交给 `verifier` 进程，让它用**独立的资源池与连接**再问一遍（40 槽位：strict 8 / veto 8 / corrob 8 / R3 16）；
23. 这样即使 guard 主进程的上游通道被污染/被打满，核验通道仍独立（两进程必须跑**同一份发布**，F5 门禁强制，见 6.2）。

### 2.5 第 4 步：三个上游到底是什么

**A（境外主源，`unbound` 容器 / `172.18.0.4` / 宿主 5353）**
- 配置 `/opt/unbound/unbound.conf`：`forward-zone "."` → `forward-addr: 172.18.0.6@53`（即 aghdq 容器）；
- `forward-first: no` ⇒ **fail-closed**：转发失败绝不明文递归回退；
- 本地 DNSSEC：`auto-trust-anchor-file` + `harden-dnssec-stripped: yes` + `val-permissive-mode: no`（严格验证，验证不过就是 SERVFAIL）；
- 加固项：`qname-minimisation: yes`（最小化查询）、`use-caps-for-id: yes`、`aggressive-nsec: yes`、`harden-glue/below-nxdomain`、`deny-any: yes`、`edns-buffer-size: 1232`；
- `local-data` 固定了 5 个境外解析器的 IP（避免"解析上游域名时又依赖上游"的鸡生蛋问题）；
- 上游链末端：`aghdq`（AGH）→ `quic://dns.nextdns.io`（DoQ，加密，带 bootstrap `223.5.5.5 / 223.6.6.6`）。

**B（国内分流，`unbound-b` 容器 / `172.18.0.5` / 宿主 5354）**
- `forward-tls-upstream: yes` + 6 条国内加密 DoT：
  `218.30.118.6@853#dot.360.cn`、`101.226.4.6@853#dot.360.cn`、`123.125.81.6@853#dot.360.cn`、`223.5.5.5@853#dns.alidns.com`、`223.6.6.6@853#dns.alidns.com`、`1.12.12.12@853#dns.pub`；
- `forward-first: no`（同上 fail-closed）；
- 特色：`ede: yes` + `ede-serve-expired: yes`（把"过期答案"标记成 EDE 送到 guard，供 stale 判定）、`prefetch-key: yes`（预取 DNSKEY，减少验证延迟）、`serve-expired-client-timeout: 300`；
- `private-address: 10/8, 172.16/12, 192.168/16`：**国内源若返回内网地址会被过滤**（防投毒给内网 IP）；
- `use-caps-for-id: no`（与 A 相反：国内源兼容性优先）；
- 它的**明文 53 出站被 iptables 封死**（只能走 DoT）。

**alt（认证备用，`unbound-alt` 容器 / `172.18.0.8` / 宿主 5357）**
- `forward-tls-upstream: yes` → `185.95.218.42@853#dns.digitale-gesellschaft.ch`、`89.233.43.71@853#unicast.censurfridns.dk`；
- **故意与 A 完全不同的上游与较小缓存**（`msg-cache 4m`、`rrset 8m`、`serve-expired: no`、单线程）；
- 它存在的意义是：当 A 与 B 说法不一致时，有**第三个独立声音**（不同网络路径、不同运营方）；
- 配套：`unbound-alt-readiness.py`（每分钟检查就绪，产出 `/run/unbound-alt-ready.json`，90 秒有效）+ `dnsguard-alt-warmup.py`（每分钟预热 root/TLD DNSKEY 与"坏签名样本"，让第一次真查询就有正确判断）；
- 熔断：连续失败 3 次（`ALT_BREAKER_FAILS`）则打开 15 秒（`ALT_BREAKER_OPEN`），避免拖慢主路径。

### 2.6 第 5 步：答案返回与"出口"细节

- guard 返回给 AGH 的报文，TTL 已按真实流逝老化；
- AGH 再按 `cache_ttl_min/max`（0/86400）缓存后回客户端；
- 若答案是"过期但被上游标记可用"的（stale），guard 会**标记来源、不写自己的缓存、不延长 TTL**；
- 客户端最终拿到的答案，TTL 语义与上游一致（不做"人为缩短"）。

### 2.7 两条真实路径对比

| 步骤 | `www.qq.com`（国内域） | `www.google.com`（境外域） |
|---|---|---|
| 是否国内域 | 是（typed 名单命中 `qq.com` 的 domain 语义，或白名单） | 否 |
| 是否可信国内域 | 白名单里有 `qq.com` ⇒ 免见证（若不在白名单则要见证） | 不适用 |
| 主上游 | 并行问 A 与 B，B 优先（更快） | 问 A |
| 交叉核对 | 采纳 B 答案前：见证或存在性见证（白名单命中则免） | A 的答案走 DNSSEC 验证；无签名则见证 |
| DNSSEC | 通常无签名 ⇒ ACCEPTED（内部有效期 ≤300s） | 通常有签名 ⇒ SECURE（≤900s） |
| 实测（2026-10-15） | guard 与 B 答案一致（如 `101.91.x.x`） | guard 与 A 一致，`ad=1`（客户端要求 DO 时） |

---
## 3. 每个模块逐个讲

> 每个模块统一用 4 个问题回答：**它是什么 / 它干什么 / 关键配置 / 它坏了会怎样**。

### 3.1 nginx —— 大门与交通管制

**是什么**：宝塔面板装的 nginx（1.31.6），是公网唯一入口。

**干什么**：
1. **DoT :853**（stream 模块）：TLS 终结后把 TCP 流原样转给 `172.18.0.2:53`（AGH）；
2. **DoH :443**：443 上同时有宝塔面板、看板、`/dns-query`；`location = /dns-query` 精确匹配，反代到 `https://agh_doh`（直连 adgh:443，keepalive 池）；
3. **DoH :444**：专用端口，只有 `/dns-query` 一个 location，其余走 `location / { return 404; }`；
4. **限流**：DoT 每源 32 并发 / 全端口 512 并发；DoH 每源 32 并发 + 200 r/s（突发 200）；
5. **SNI 白名单**：`00.reject-unknown-sni.conf` 把"SNI 不是已知域名"的连接拒掉；
6. **站点反代**：`/chain/` → 127.0.0.1:8787（Basic Auth）、`/devices/` → 127.0.0.1:8789（Basic Auth）、`/join` → 127.0.0.1:8789（公开，仅 5 并发）。

**关键配置**：`/www/server/panel/vhost/nginx/tcp/dns-example-dot-853.conf`（stream）、`9.devfp-doh444.conf`、`dns.example.com.conf`、`extension/dns.example.com/{chainmon,devfp,join,site_total}.conf`。

**坏了会怎样**：所有加密入口立刻不可用（明文 53 本来就没开）⇒ 家庭与公网客户端全部解析失败。这是**第一位的单点**。

**为什么不用 nginx 做 DNS**：nginx 不懂 DNS 语义，只做"搬运"；它也看不到 DNS 内容，所以过滤/判定只能交给后面的 AGH 与 guard。

---

### 3.2 `dotfront-spool` —— 把"真实来源"与明文画像补回来

**是什么**：宿主上的一个只读采集进程（仓库里是 `tools/dotfront-spool.py`，安装后位于 `CODE_DIR/tools/`），systemd 单元 `dotfront-spool.service`。

**为什么需要**：DoT 经 nginx stream 终结 TLS 后，内腿是**明文 DNS**（`proxy_pass adgh:53`）。AGH 侧只看到 docker 网关 `172.18.0.1`，真实客户端 IP 在内腿里丢失；同时 EDNS/COOKIE/ECS/PADDING/DO 位/0x20 大小写这些明文特征在 AGH 之后也不再可见。这个进程把这段内腿抓下来交给 devfp。

**干什么**：AF_PACKET 被动抓包（`DOTF_IFACE=auto` 时按 `DOTF_GW` 的 IP 自动找网桥），只收 `dst=DOTF_DST` 且 `dport=DOTF_DPORT` 的 TCP；按源端口重组流，按 DNS 的 2 字节长度前缀切帧，解析出 `qname/qtype`、EDNS（client cookie、ECS、padding 长度）、DO 位、UDP 大小、0x20 混合大小写，写成 JSONL（`DOTF_SPOOL`，默认 `/var/log/dotfront.jsonl`）。

**谁消费**：devfp 的 `dotf_loop()`（读 `config.json` 的 `dotfront_spool`，默认同一路径）。它按时间把"内腿明文包"与"DoT 请求事件"对齐（`_align_plain_event`），给连接补上真实来源与明文画像。**两侧路径必须一致**。

**前置条件**：① DoT 内腿必须是明文（见 `deploy/nginx/tcp/dnsguard-dot-853.conf`；若改成"nginx 再加密到 AGH:8854"，本采集收不到任何数据）；② 需要 `CAP_NET_RAW`（默认以 root 运行）；③ 单元里的 `DOTF_GW/DOTF_DST` 必须与容器实际 IP 一致 —— 由 `dnsguard-ip-reconcile.sh` 维护的 drop-in 自动收敛。

**坏了会怎样**：DoH 侧带 `X-Forwarded-For`，仍能拿到真实 IP；DoT 侧退化为"只看到网关"，devfp 的 DoT 设备区分度下降、明文特征缺失。**DNS 解析本身不受影响**。

**另有一条相关事实**：`probe-srcaddr.service` 给 docker0 加了别用地址 `172.18.0.99/16`，专门给本机探针用（避免探针与真实客户端混在一起）。对账脚本会检查它（见 6.3）。

---

### 3.3 AdGuard Home（`adgh` 容器）—— 过滤与缓存

**是什么**：AdGuard Home v0.107.73，Docker 容器，网络位置 `172.18.0.2`，配置 `/opt/adgh/conf/AdGuardHome.yaml`。

**干什么**：
1. **过滤**：按订阅规则拦截广告/跟踪域名（命中即回 0.0.0.0 或 NXDOMAIN，不走上游）；
2. **缓存**：`cache_size 64 MiB`、`cache_ttl_min 0`、`cache_ttl_max 86400`——TTL 原样使用，命中缓存不经 guard；
3. **查询日志**：写 `querylog.json`，供 devfp 做行为分析；
4. **限流**：`ratelimit 200`（每 /24 子网），是第二道闸；
5. **唯一上游**：`upstream_dns: [172.18.0.1:5355]`，`fallback_dns: []`、`bootstrap_dns: []`。

**为什么"不设兜底"是刻意设计**：如果给 AGH 配一个"备用上游"（比如直接写 8.8.8.8），那么 guard 一挂，所有防护瞬间失效且**没人察觉**。现在的行为是"guard 挂了就解析失败"——痛，但不会静默降级。

**它也是**：AGH 自身监听 443（DoH）、853（DoT）、853/UDP（DoQ）——但这些是**容器内**，对外只通过 nginx（宿主 4443 → 容器 443；853 的 DoT 走的是容器 53，不是 8854）。

**坏了会怎样**：容器停止 ⇒ DoT 入口（853 → 172.18.0.2:53）立刻失败、DoH（→ agh_doh）失败。恢复命令：`docker restart adgh`（IP 若变化，对账脚本会修 nginx/AGH 配置）。

---

### 3.4 guard —— 决策中枢（本文档的主角）

**是什么**：宿主 Python 3.6 进程（`/opt/dnsguard/current/guard.py`，254466 B，约 9550 行），systemd `dnsguard.service`，监听 `172.18.0.1:5355`（udp+tcp）+ `172.18.0.1:5356`（udp 探针通道）。

**它是什么角色**：AGH 的**唯一上游**，也是"是否相信某个答案"的唯一决策者。整个系统的安全语义都集中在这个进程里。

**内部结构（按代码组织）**：

| 部分 | 代表符号（guard.py 行号，发布 11） | 作用 |
|---|---|---|
| 策略引擎 | `answer_policy.py`（`POLICY_VERSION`、`Verdict`、`Answer`、`make_answer`、`is_fresh`、`choose_answer`、`finalize_answer`） | 给每个答案打档位、算有效期、选优 |
| DNSSEC 适配 | `alt_adapter.py`：`dnssec_bogus`(384)、`stale_flags`(431)、`age_wire`(465)、`min_rr_ttl`(512)、`response_matches`(311)、`exchange_udp`(357)、`_parse_rrs`(152) | 报文解析、签名坏判定、TTL 老化、报文身份校验、有界收发 |
| 国内判定 | `_load_cn_typed`(2687)、`_match_cn_typed`、`is_cn_domain`(3079)、`is_cn_trusted`(2652)、`_in_cn_veto`(3064)、`_load_cn_veto`(2967)、`_in_cn_trust_exc`、`_in_cn_trust_allow`、`load_cn_nets`(4121)、`is_cn_ip`(4191) | 六份名单的载入与匹配 |
| 国内决策 | `_policy_cn_answer`(119) | 国内路由 vs 国内信任的采纳闸门 |
| 见证 | `cn_exist_veto`(7452)、`_witness_box`(7395)、`_veto_udp`(7329)、`_veto_zone`(7191)、`_cn_zone_denied`(7223) | "再问一次"与"域名存在吗" |
| 交叉核对 | `corrob_query`(6186)、`corrob_get`(6252)、`corrob_put`(6265)、`_corrob_query_once`(6056) | 多源比对缓存 |
| 准入缓存 | `_adm_cache_get`(446)、`_adm_cache_put`(755)、`_adm_cache_answer`(556)、`_drop_caches_for`(615) | 只存安全/可接受答案 + 代次失效 |
| 备用通道 | `_alt_gate`(887)、`_alt_classify`(977)、`_verifier_dot`(5488) | alt 与 verifier 的使用 |
| 热点加速 | `_hot_key`/`_hot_note`/`_hot_decide`/`_hot_refresh_one`(1678–1873) | 热缓存与预取（`GUARD_HOT_MIN_TTL=30`） |
| 出口闸门 | `_finalize_return`(1125)、`_stale_of`(1095)、`_stale_note`(1108) | 唯一出口：TTL 老化 + stale 处理 |
| 判定辅助 | `suspicious`(6352)、`denial_proof`(4482)、`dnssec_material`(4523) | 可疑 IP、否认证明、DNSSEC 素材 |
| 网络 I/O | `_dot_raw`(5038)、`_udp_raw`(5079)、`_dot_query_once`(5342)、`_cache_replay`(4660) | 加密/明文收发与缓存重放 |
| R8/ASN | `GUARD_R8_ASN_GATE`、`asn_cache.py`、`asn_snapshot.py` | ASN 归属门（按自治域判断答案是否合理） |

**环境变量开关（13 个 `_flag`，行号=定义处）**：

| 开关 | 行号 | 默认 | 含义 |
|---|---|---|---|
| `GUARD_BASE_INSTR` | 1344 | 关 | 基础线路探测（对固定域做对照） |
| `GUARD_BASE_SAMPLE` | 1345 | 关 | 基础样本采集 |
| `GUARD_HOT_REFRESH` | 1597 | 关 | 热缓存主动刷新 |
| `GUARD_CN_DOMESTIC_PRIMARY` | 2435 | **开（环境设为 1）** | 国内域名优先进国内源 |
| `GUARD_CN_DOMESTIC_TRUST_B` | 2436 | **开** | 允许国内源答案进入"可信"路径（**受 is_cn_trusted 约束**） |
| `GUARD_CN_DOMESTIC_ZERO_TTL_ONESHOT` | 2438 | **开** | 国内可信答案单次返回、不入长期缓存 |
| `GUARD_DOMESTIC_DO` | 3123 | **开** | 对国内源查询带 DO 位（要 DNSSEC 记录） |
| `GUARD_CN_OVERLAP` | 3154 | 关 | 国内/境外重叠统计 |
| `GUARD_CORROB_STRICT_NODATA` | 3158 | **开** | 交叉核对时把"无数据"当严格不一致 |
| `GUARD_CORROB_STRICT_FAIL_CLOSED` | 3160 | 关 | 核对失败时是否一律拒绝（当前关=保守但不激进） |
| `GUARD_R8_ASN_GATE` | 3730 | 关 | ASN 门（实验/灰度） |
| `GUARD_R8_AUDIT` | 5715 | 关 | R8 审计日志 |
| `GUARD_CN_VETO_DEBUG` | 7168 | 关 | veto 调试日志 |

**运行时参数（systemd Environment，实测现网值）**：

| 变量 | 值 | 含义 |
|---|---|---|
| `GUARD_MAX_INFLIGHT` | 96 | 同时在途的上游查询上限 |
| `GUARD_MAX_PENDING` | 96 | 排队等待上限 |
| `GUARD_MAX_QUEUE` | 16 | 每客户端/队列上限 |
| `GUARD_COLD_MAX` | 48 | 冷查询（无缓存）并发上限 |
| `GUARD_UPSTREAM_WORKERS` | 16 | 上游线程池 |
| `GUARD_HEDGE_MS` | 280 | 对冲等待（毫秒） |
| `GUARD_SYNC_BUDGET` | 3.8 | 单次同步预算（秒） |
| `GUARD_CORROB_TTL` | 300 | 交叉核对结果缓存时间（秒） |
| `GUARD_CORROB_DOT_TIMEOUT` | 1.8 | 核对用的 DoT 超时 |
| `GUARD_DISABLE_DOQ2` | 1 | 关闭某条 DoQ 备用通道（避免重复/冲突） |
| `GUARD_LISTEN_HOST` | 172.18.0.1 | 只监听 docker 网关（不暴露公网） |
| `GUARD_VERIFIER_SOCKET` | `/run/dnsguard/verifier.sock` | 与 verifier 的 IPC |
| `GUARD_CN_VETO_FILE` | `/opt/dnsguard/cn_veto.txt` | 否决名单路径（发布 06 起切到统一刷新的文件） |
| `GUARD_CN_DOMESTIC_TRUST_B` 等 | 1 | 见上表 |

**它的关键"设计哲学"**：
- **宁慢不乱**：不确定就不采信（`GUARD_CORROB_STRICT_NODATA=1`）；
- **fail-closed 优先**：所有上游都 `forward-first: no`、guard 不配明文回退；
- **两个独立进程**：主决策与核验分离，避免单点被单点污染；
- **所有"信任"都要有约束**：白名单、例外、否决、代次、TTL 上限，一个都不少（见第 4 章）。

**坏了会怎样**：`systemctl restart dnsguard`（门禁会立刻校验两进程是否同一发布）。guard 挂 ⇒ AGH 无上游 ⇒ 全部解析失败（不会静默降级）。

---

### 3.5 `verifier` —— 独立的第二个声音

**是什么**：宿主 Python 进程（`/opt/dnsguard/current/verifier.py`，4319 B），systemd `dnsguard-verifier.service`，只通过 Unix socket `/run/dnsguard/verifier.sock` 与 guard 通信（**不监听 TCP/UDP**）。

**干什么**：
1. 从 socket 读 4 字节长度帧 + JSON 元数据（`op/name/qtype/timeout/prefer_addr/targets/pool/rid`）+ DNS 报文；
2. 按池子执行：`strict`(8 槽) / `veto`(8) / `corrob`(8) / `r3`(16)，共 **40 槽位**（`VERIFIER_SLOTS=40`）；
3. 用**独立的上游连接与资源**（`GUARD_FAST_UDP=127.0.0.2:5353`，走 dnscrypt-proxy）再问一遍；
4. 返回状态字节：`\x00` OK / `\x01` NODATA / `\x02` TIMEOUT / `\x03` OVERLOAD / `\x04` ERROR / `\x05` VERSION_MISMATCH；
5. 每 60 秒写自己的 `stats_meta.json`（release_id/guard_sha256/verifier_proto/pid）——供门禁比对。

**为什么需要它**：如果只用 guard 一个进程做所有核对，那么"核对通道"和"主通道"共享同一份资源与同一份配置；一个被污染/被打满，两个都废。分开后：**主进程可以慢，核验必须独立**。

**版本门禁（F5 修复）**：握手时双方交换 `release_id + guard.py 的 sha256 + 协议号(proto=2)`；不匹配时 verifier 返回 `\x05`，guard 把它折成 `CORROB_ERROR` 并计数告警 —— 防止"两个进程跑不同发布"这种最隐蔽的错配。

**坏了会怎样**：核验通道不可用 ⇒ guard 的交叉核对退化为单源（有日志与计数 `v_err`/`v_badframe`），主解析仍可用。`systemctl restart dnsguard-verifier`。

---

### 3.6 `unbound`（A）—— 境外主源

**是什么**：`mvance/unbound:latest` 容器，网络 `172.18.0.4`，宿主映射 5353（127.0.0.1 与 172.18.0.1 都映射），配置 `/opt/unbound/unbound.conf`。

**干什么**：
1. 接收 guard 的转发查询，转发到 `172.18.0.6@53`（aghdq）→ DoQ → NextDNS；
2. **本地做 DNSSEC 验证**（`auto-trust-anchor-file` + `harden-dnssec-stripped: yes` + `val-permissive-mode: no`）——即"签名不对就 SERVFAIL"，不把假答案放过去；
3. 加固：`qname-minimisation`（只问必要层级）、`use-caps-for-id`（随机大小写抗欺骗）、`aggressive-nsec`、`harden-glue`、`harden-below-nxdomain`、`deny-any`、`edns-buffer-size 1232`（防分片放大）；
4. `access-control`：只允许 127/8、172.16/12、10/8、192.168/16，其余 refuse（它只服务本机与容器网络）。

**坏了会怎样**：境外解析全部失败（fail-closed，不回退明文）。恢复：`docker restart unbound`；`unbound-control` 在容器内可用（宿主路径 `/opt/unbound/sbin/unbound-control`）。

> ✅ 已核实的设计要点：`forward-first: no` 是"绝不明文递归回退"的保证——早年"明文递归到权威"的老问题（最后一跳可被注入）已通过这一条根治。

---

### 3.7 `aghdq` —— NextDNS 的 DoQ 通道

**是什么**：第二个 AdGuard Home 容器，网络 `172.18.0.6`，配置在 `/opt/aghdq/AdGuardHome.yaml`（容器内 `/opt/adguardhome/conf`）。

**干什么**：
1. 上游只有一个：`quic://dns.nextdns.io`（DoQ，加密）；
2. bootstrap：`223.5.5.5`、`223.6.6.6`（解析 NextDNS 域名的引导，避免自举死锁）；
3. `cache_size 16 MiB`；
4. `allowed_clients`：`127.0.0.0/8`、`::1/128`（**只允许本机**，即只被 unbound A 使用，不对内网/公网开放）；
5. 它跑在**自己的 veth 与 IP**，因此"境外这一跳"与"国内那一跳"在网络上分开。

**为什么要多这一跳**：NextDNS 提供 DoQ（HTTP/3 上的 DNS），比 DoT/DoH 更省握手；同时把"上游供应商"与"本地验证"解耦——NextDNS 负责可用性，本机 Unbound 负责 DNSSEC 正确性。

**坏了会怎样**：境外主源整体失败（A 的 forward 目标不可用）。重启 `docker restart aghdq`；对账脚本会检查它的 IP（172.18.0.6）有没有写对。

---

### 3.8 `unbound-b` —— 国内分流源

**是什么**：第三个 Unbound 容器，网络 `172.18.0.5`，宿主 5354，配置 `/opt/unbound-b/unbound.conf`。

**干什么**：
1. `forward-tls-upstream: yes` 转发给 **6 条国内加密 DoT**（360 ×3、阿里 ×2、dns.pub ×1）；
2. `forward-first: no`（同上：**绝不回退明文**）；
3. 打上 EDE：`ede: yes`、`ede-serve-expired: yes`——当它给出"过期缓存"时，会在响应里标注，让 guard 知道"这是陈旧的"；
4. `prefetch-key: yes`：预取 DNSKEY，减少验证等待；
5. `private-address` 过滤内网地址；
6. `num-threads: 2`、`outgoing-num-tcp: 100`（国内源并发需求比境外高，因为是"就近"查询）；
7. 它的**明文 53 出站被 iptables DROP**（`UNBOUNDB_53` 链），只能走 DoT——防止"加密进、明文出"的降级。

**为什么它危险**：国内递归源本身是"快速、可被影响"的：
- 它可能给出**错误 IP 但格式正常**（`NOERROR + an=1`）；
- 它可能对**不存在的域名**返回假 IP（投毒典型手法）；
- 因此系统规定：**国内源只在"路由"意义上被优先，只有在 `is_cn_trusted()` 通过时才可能被"信任"**（这正是第三份审计 F1 的修复核心，见 4.5/4.6）。

---

### 3.9 `unbound-alt` + readiness + warmup —— 第三意见与它的"体检"

**是什么**：
- 容器 `unbound-alt`（172.18.0.8，宿主 5357，配置 `/opt/unbound-alt/unbound.conf`）；
- `unbound-alt-readiness.py`（42160 B，每分钟）：检查 alt 是否"真的可用且配置正确"，产出 `/run/unbound-alt-ready.json`（90 秒有效）；
- `dnsguard-alt-warmup.py`（2284 B，每分钟）：预热 root/TLD 的 DS/DNSKEY 与一个"故意坏签名"的样本，让 alt 第一次真查询就能正确判 bogus；
- 容器 `alt-replica-unb`（10.99.0.2:15353）：alt 的副本，用于演练/灰度（不参与主链路）。

**干什么**：给系统一个**独立的第三意见**——当 A（境外主源）与 B（国内源）不一致时，或当需要"非国内、非 NextDNS"的角度时使用。

**它的特点（和 A 明显不同）**：单线程、小缓存（4m/8m）、`serve-expired: no`（不给过期答案）、上游是 digitale-gesellschaft.ch 与 censurfridns.dk（不同运营方）。

**熔断**：连续失败 3 次打开熔断 15 秒（`ALT_BREAKER_FAILS=3`、`ALT_BREAKER_OPEN=15`），避免每次查询都等一个已经挂掉的上游。

**坏了会怎样**：少了"第三意见"，交叉核对降级（有指标可看）。`/usr/local/sbin/dnsguard-alt-restart.sh` 可重启并等就绪。

---

### 3.10 `dnscrypt-proxy` —— 匿名中继与"名单搬运工"

**是什么**：宿主进程 `dnscrypt-proxy -config /opt/dnscrypt-proxy/dnscrypt-proxy.toml`，监听 `127.0.0.2:5353`（udp+tcp）与 `127.0.0.1:5399`。

**干什么**：
1. **匿名中继出口**：`server_names = ['cs-nl','cs-fr','dct-de2','cs-dus','cs-london','cs-swe']`，经 DNSCrypt 匿名中继（如 `anon-cs-berlin`）出网——即"上游不知道是谁在问"；
2. 严格策略：`require_dnssec = true`、`require_nolog = true`、`require_nofilter = true`（只选满足这三个条件的服务器）；
3. 缓存：`cache_size 8192`、`cache_min_ttl 60`、`cache_max_ttl 600`（**注意：这里会改 TTL**——60–600 区间）；
4. `bootstrap_resolvers`：`223.5.5.5`、`119.29.29.29`（引导用）；
5. **国内名单文件维护**：它自己会周期性拉取并更新 `/opt/dnscrypt-proxy/forwarding-rules.txt`（这也是"CN 分流"数据的原始来源之一）。

**它在本链路里的位置**：guard 的 verifier（`GUARD_FAST_UDP=127.0.0.2:5353`）与部分核对路径会用到它——即"一个走匿名中继、与 A/B/alt 都不同的第四条路"。

**⚠️ TTL 语义差异（重要坑）**：dnscrypt-proxy 有 `cache_min_ttl 60 / cache_max_ttl 600`，会让经过它的答案 TTL 变成 60–600 之间（其他上游不会）。所以"同一域名在不同路径上 TTL 不同"是**预期现象**，不是 bug。

**坏了会怎样**：核验路径少一条（`GUARD_FAST_UDP` 目标不可用）；另外**国内名单文件（forwarding-rules.txt）会自动停更**——这是历史遗留的双通道（现在由统一刷新器负责，见 3.12）。

---

### 3.11 名单体系（六份文件，两种格式，三层语义）

系统用**六份文件**描述"哪些域名/IP 与中国有关"，它们的用途完全不同，混用会出事故：

| 文件 | 位置 | 行数/大小 | 用途（谁用） | 语义 |
|---|---|---|---|---|
| `cn-domains-typed.txt` | `/opt/dnscrypt-proxy/` | 8839 行 / 180102 B | guard 的 `is_cn_domain` **首选**（带类型） | `full:域名`=仅精确；`domain:域名`=自身+子域 |
| `forwarding-rules.txt` | `/opt/dnscrypt-proxy/` | 8838 行 / 250808 B | dnscrypt-proxy 的 CN 分流 + guard 的**回落** | 纯域名列表（无类型） |
| `cn_veto.txt` | `/opt/dnsguard/` | 25030 行 / 384144 B | guard 的**否决**名单（`_in_cn_veto`） | 命中即"不走国内可信路径" |
| `cn_ip.txt` | `/opt/dnsguard/` | 4316 行 / 67372 B | guard 的 `is_cn_ip`（IP 归属） | CIDR 列表（含 clang.cn 同源刷新） |
| `cn-trust-exceptions.txt` | `/opt/dnscrypt-proxy/` | 24 行 / 1653 B | guard 的**例外清单**（最高优先） | 命中即"既不走国内路由、也不信任国内" |
| `cn-trust-allow.txt` | `/opt/dnscrypt-proxy/` | 46 行 / 2327 B | guard 的**信任白名单** | 命中的国内域可**免见证**采用国内源答案 |

**三份快照（防"冷启动空名单"）**：
- `/opt/dnsguard/cn-veto.snapshot.txt`（25026 行）：否决名单的上次有效副本；
- `/opt/dnscrypt-proxy/cn-domains-typed.snapshot.txt`（8838 行）：类型化名单的上次有效副本；
- 两者都在刷新器**写出正式文件时同步更新**；guard 启动时若正式文件缺失/损坏，会先读快照，避免"名单空 ⇒ 误判"。

**两层语义（本系统最重要的概念，第三份审计 F1 的产物）**：

| 层 | 判据 | 决定什么 | 数据来源 |
|---|---|---|---|
| **国内路由** | `is_cn_domain(name)` | 这条查询**优先问国内源**（快） | typed 名单（社区数据，自动更新，8837 条） |
| **国内可信授权** | `is_cn_trusted(name)` | 国内源的答案**能不能免交叉见证**（信） | 国别/品牌后缀 + 白名单（19 条，人工维护） |

只有**两层都通过**，国内答案才能"免见证"被采用；否则必须至少有一次独立见证。这套拆分把"社区名单错了"的后果从"错误答案被信任并发给客户端"降级为"只影响走哪条链路"。

**否决名单（veto）的来历**：`geolocation-!cn`（v2fly 社区数据）的**有界展开**——深度 ≤8、文件 ≤2000，展开后剔除 724 条"其实是国内域"的冲突项，得到 25020 条，用于"这些域不许走国内可信路径"。

---

### 3.12 名单刷新器（4 个脚本 + 1 个归档模块）

**设计原则：数据分散但流程统一；任何一次更新都必须可回滚、可审计、可验证。**

| 脚本 | 作用 | 关键门禁 |
|---|---|---|
| `refresh-cn-rules.py`（20367 B） | 生成 `cn-domains-typed.txt`（带类型）+ `forwarding-rules.txt` + typed 快照 | 域名数 ≥5000；变化 ≤15%（绝对 200）；**境外域黑名单**（10 个）命中即失败；拉取失败容忍 25% |
| `refresh-cn-veto-ip.py`（22053 B） | 生成 `cn_veto.txt`（否决）+ `cn_ip.txt`（IP 段）+ veto 快照 | 否决条目 ≥12000；国内冲突剔除 ≤40%；**关键国内域不得出现**；变化 ≤5%（绝对 20） |
| `verify-cn-lists.py`（7442 B） | 校验：哈希清单、GPG 签名、条目数、关键域不在否决里 | 任一项不过 ⇒ 非零退出 |
| `cnlist_history.py`（8207 B，模块） | 每次更新写归档（added/removed）+ 更新 `MANIFEST.sha256` + GPG 签名 | 归档目录 `cn-list-history/` |
| `refresh-all-cn-lists.sh`（1556 B） | **统一入口**：域名名单 → 否决+IP → 校验，汇总 rc | 由 cron 每日 04:35 调用 |

**变更归档与签名**：每次名单变化都会留下"改了什么"（新增/删除）与一份 GPG 签名（无口令密钥，RSA 3072，指纹 `E1B5F51A...`）。**注意边界**：上游数据本身没有官方签名，所以这里保证的是"落盘之后没被改过"，而不是"来源绝对可信"。

**统一刷新流程图**：

```
cron 04:35
  └─ refresh-all-cn-lists.sh
       ├─ 1) refresh-cn-rules.py       → typed + forwarding-rules + typed 快照
       │      门禁：域数/幅度/境外域黑名单 → 失败保留旧文件
       ├─ 2) refresh-cn-veto-ip.py     → cn_veto + cn_ip + veto 快照
       │      门禁：条目数/国内冲突/关键域/幅度 → 失败保留旧文件
       └─ 3) verify-cn-lists.py        → 哈希 + 签名 + 关键域校验
     （guard 全程无需重启：按 mtime 60 秒内热重载）
```

**手工操作**：清 AGH 缓存 `${BASE}/agh-cache-clear.sh`；撤销某域国内信任 `${BASE}/cn-trust-revoke.sh`。

---

### 3.13 防火墙（iptables）—— 防"降级泄漏"

**是什么**：`/usr/local/sbin/dnsguard-fw.sh`（13005 B）+ `dnsguard-fw-table.py`（16372 B）生成并原子应用 iptables 规则。

**当前实际规则（filter 表，实测）**：

| 链 | 规则 | 目的 |
|---|---|---|
| `DOCKER-USER` | `-s 172.18.0.5 -j UNBOUNDB_53`、`-s 172.18.0.8 -j UNBOUNDB_53` | 国内源 B 与 alt 的**明文 53 出站**入链 |
| `DOCKER-USER` | `-s 172.18.0.4 -j DNS_A_EGRESS` | 境外主源 A 的出站入链 |
| `UNBOUNDB_53` | `dport 53 udp DROP`、`dport 53 tcp DROP` | **封死国内源的明文 DNS 出站**（只能 DoT） |
| `DNS_A_EGRESS` | 到 `172.18.0.6:53` RETURN；其余 `dport 53` DROP；末尾 RETURN | A **只能**走 aghdq，不能自己直连别的 53 |
| `FORWARD` 默认 | `DROP` | 容器间/出站默认拒绝 |

**为什么这是必要的**：Unbound 若配置被改坏或被人加一行"明文回退"，就会把加密链路降级成明文——防火墙从**网络层**堵死这条退路，配置错了也跑不起来。

**原子性（F1/F2 修复）**：脚本不再"逐条删了再加"，而是：
1. 生成**完整的新表**（`dnsguard-fw-table.py` 纯文本变换，便于离线测试）；
2. 与当前表**逐字节比对**；
3. 用**一次 `iptables-restore`** 原子替换（失败自动回滚）。

**对账定时器**：`dnsguard-fw-reconcile.timer` 每 5 分钟跑一次（容器重建后 IP 变了也能自动修）。

---

### 3.14 探针（4 个）—— 让"看起来正常"变成"可验证"

| 探针 | 位置 | 检查什么 | 判据（严格） |
|---|---|---|---|
| `dns-entry-probe.py` | `/opt/dnsguard/` | 三个公网入口：DoT:853、DoH:444、DoH:443 | 严格 TLS（验证证书、SNI=dns.example.com）；带 EDNS0+DO；`cloudflare.com` 必须 `rcode=0 an≥1 ad=1`；`www.qq.com` 必须 `rcode=0` |
| `dns-chain-probe.py` | `/usr/local/sbin/` | 五层：A(5353)/B(5354)/guard(5355)/DoT(853)/DoH(444) | 四类样本：`cloudflare.com`(ok_ad)、`www.qq.com`(ok)、`dnssec-failed.org`(必须 SERVFAIL)、`nxdomain-probe.invalid`(必须 NXDOMAIN) |
| `external-probe.py` | `/opt/dnsguard/` | 从**家庭网络**经公网访问三个入口 | 与入口探针同判据（证明"外面看也正常"） |
| `canary_watch.py` | `/opt/dnsguard/` | 随机 canary 域名全链路对照 | 判"客户端是否真被投毒暴露"（红/绿） |

**教训（已修）**：探针早期版本曾"自己把关掉"——`CERT_NONE`（不验证证书）、把 NOTIMP(4) 当健康、DoH 只看 HTTP 200、读 AD 但查询没带 DO、DoT 只 `recv` 一次不读满帧。这些都已修正为**严格模式**（严格证书 + 带 DO + 读满帧 + 明确判据）。

---

### 3.15 部署与门禁 —— 「改错了会自己退回去」

| 脚本 | 做什么 |
|---|---|
| `deploy_release.sh` | ① 校验 `RELEASE.sha256`；② 调 `verify-release-data.py` 校验发布数据；③ 备份旧指向；④ 切换 `current` 软链；⑤ **一条命令**重启 guard+verifier；⑥ 轮询门禁（最长 90s）；⑦ 失败自动回滚 + 非零退出 |
| `release_consistency.py` | 比对两进程的 `stats_meta.json`：release_id、guard.py 的 sha256、协议号；pid 存活；`/proc/<pid>/cwd`；`current` 指向；磁盘 guard.py 实际哈希 |
| `verify-release-data.py` | `.files` 每项必须在 `RELEASE.sha256` 里有记录且实际哈希一致；否决快照必须入清单；快照内容约束（条目数下限、无单标签、不含国内关键域先例） |

**发布目录约定**：`/opt/dnsguard/releases/<RELEASE_ID>/`（不可变），`/opt/dnsguard/current` 软链指向其中一个；回滚就是"把软链指回上一版 + 同一条命令重启"。

**发布 11 的现状**：`current → releases/20261015-audit-fixes-11`，guard 启动日志会打印 `release_id / sha256 / policy / verifier_proto`，两侧 `stats_meta.json` 必须一致。

---

### 3.16 定时任务与看门狗（"系统自己检查自己"）

| 任务 | 周期 | 检查什么 | 不合格的表现 |
|---|---|---|---|
| `dnsguard-canary.timer` | 5 min | 随机 canary 全链路 | 日志告警 + 计数（曾经用 `client_exposed` 判断"客户端真被暴露"） |
| `dns-chain-probe.timer` | 5 min | 五层 × 四样本 | 写 `/var/log/dns-chain-probe.jsonl`，失败 rc=1 |
| `dnsguard-ip-reconcile.timer` | 5 min | 4+2 处容器 IP 引用是否与 `docker inspect` 一致 | 自动修 + 备份 + reload（失败回滚） |
| `dnsguard-fw-reconcile.timer` | 5 min | 防火墙规则是否与期望一致 | 原子重放 + 回滚 |
| `unbound-alt-readiness.timer` | 1 min | alt 是否就绪且配置正确 | 写 readiness 文件（90s 有效） |
| `dnsguard-alt-warmup.timer` | 1 min | alt 缓存是否热 | — |
| `chainmon-restart.timer` | 30 min | 重启看板进程（防内存增长） | — |
| `dnsguard-asn-snapshot.timer` | 每日 03:05 | ASN 归属快照 | — |

**IP 对账修哪些地方（6 处）**：① nginx `proxy_pass`（DoT → adgh）；② unbound A 的 `forward-addr`（→ aghdq）；③ `dotfront-spool` 的 drop-in；④ AGH 上游；⑤ guard 的 `GUARD_LISTEN_HOST`（= docker0 网关）；⑥ `probe-srcaddr` 的别名地址。任何一处与实际容器 IP 不符都会被修正，且**修正前先备份**。
> ⚠️ **dnsdist 的 `newServer({address="...:53"})` 也是写死的容器 IP，但对账脚本（`firewall/dnsguard-ip-reconcile.sh` 的 6 处）目前**尚未覆盖它**：容器 IP 变化后需要重跑 `./install.sh` 重新渲染 `/etc/dnsdist/dnsdist.conf` 并 `systemctl restart dnsdist`。这是已知缺口。


---

### 3.17 `chainmon` —— 链路看板（`https://dns.example.com/chain/`）

**是什么**：`/opt/chainmon/chainmon.py`（监听 127.0.0.1:8787，nginx 加 Basic Auth 反代到 `/chain/`），配套 `qlog_window.py`（AGH 查询日志窗口统计）、`resource_probe.py`（资源探针）。

**干什么**（只读采集，源码注释明确"纯只读"）：
1. 采集链路上每一跳的真实参数（nginx、AGH、guard、三个 Unbound、dnscrypt-proxy、容器状态、内存、证书有效期）；
2. `COLLECT_INTERVAL_S=60`（后台每 60 秒采一次）、`WINDOW_MIN=60`（统计窗口 1 小时）、`HISTORY_MAX=120`（保留 120 个点）；
3. 前端 `index.html` 每 60 秒拉一次 `api/metrics`，展示：架构图、节点状态、缓存链、探针、AGH/guard/Unbound/dnscrypt 明细、CPU/内存、容器、走势；
4. 提供 `api/dnsguard`（POST confirm/ignore/forget）用于人工确认投毒告警。

**它同时也是**：`devfp.py` 的 `join_chain_level()` 会读 chainmon 判断"链路等级"。

**坏了会怎样**：只是看不到看板，不影响解析。`chainmon-restart.timer` 每 30 分钟重启一次。

---

### 3.18 `devfp` + `/join` —— 设备指纹与「打开即采集」

**是什么**：`/opt/devfp/devfp.py`（监听 127.0.0.1:8789，反代 `/devices/`，Basic Auth），`join.html`（公开页 `/join`）。

**四路采集（源码注释）**：
1. **被动抓包**（AF_PACKET，eth0，只看 tcp 853/444/443 及其回包）：TLS ClientHello → JA3/JA4/SNI/ALPN/版本/密码套件/扩展/曲线/GREASE；ServerHello → 协商结果与证书字节数；TCP SYN → p0f 式指纹（TTL/窗口/MSS/选项顺序/IP-ID）；每连接的字节/包/时长；QUIC 仅计数；
2. **AGH querylog 增量 tail**：每设备查询行为（协议、qtype 分布、ECS、过滤命中、上游、时延、Top 域名）；
3. **nginx DoH 访问日志增量 tail**：HTTP 层指纹（UA、Accept 系、HTTP 版本、TLS 套件/曲线/ALPN/会话复用）；
4. **路由侧 agent**（`POST /api/router`）：家庭内网设备（MAC/IP/主机名/厂商/无线/行为）。

**`/join` 页面（用户打开即自动采集，零交互）**：
- 采集：UA-CH 高熵值（9 字段）、Canvas 深度、WebGL 向量、AudioContext、字体探测、屏幕/视口全量、时区+1/7 月偏移+Intl、权限矩阵、编解码矩阵、storage 配额、WebRTC host candidates、反自动化痕迹、特性矩阵；
- **持久 ID 四通道**：localStorage（`dvn`）、Cookie（`dvnid`）、IndexedDB（`dvn/k`）、Cache API；
- 稳定指纹 `hs`（FNV-1a 64 位，剔除会抖动的 canvas/audio）用于跨会话归并；
- SNI 探针：请求 `https://<随机token>.dns.example.com/p.gif`，让抓包侧用 SNI 精确锁定"这次请求的首个连接"；
- 后端把这次访问写进 `enroll_obs`（含当次 DoT/DoH 保护判定）与 `enrollments`（元数据、fp2、pids、hdr、hash 稳定指纹）。

**⚠️ 一个容易误解的点：自动绑定已被取消。** 按用户 2026-10-15 的要求，登记路径**不再自动把设备绑上去**：

- `devfp.py:4690-4694`：算出的候选匹配（`did/how`）只当作**建议**返回给页面，登记记录**不写** `matched_device`、**不写** 设备标签；
- `devfp.py:4989-4990`、`devfp.py:5005-5010`：`/join` 登记时"元数据照更新，但 `matched_device`/`matched_by` 一个字都不写"，设备侧（标签、浏览器指纹、持久 ID）也不再由登记自动回写；
- `devfp.py:4748` 起的**手动绑定**才是唯一绑定入口（把建议值交给人在登记列表里点选，写入时置 `pinned=1`）。

所以现在完整链条是：**打开 `/join` → 自动采集并落库（观测 + 登记元数据）→ 人在设备看板里手动把它绑到某台设备**。

**自动化程度（诚实说明）**：`/join` 页本身**每次请求都重新读盘**（`devfp.py` 读 `join.html`），所以改文案不用重启；但改 `devfp.py` 必须 `systemctl restart devfp`。另外 `/join` 的公开路径有 `limit_conn 5`（每源 5 并发），配合页面内的重试逻辑。

---

### 3.19 资源限额与内存治理

- guard 160/192 MiB、verifier 100/128 MiB（F3 修复后的实际值）；
- chainmon 256 MiB、devfp 176 MiB、dnscrypt-proxy 64 MiB、alt-readiness 64 MiB；
- `MemorySwapMax=0`（verifier 不使用 swap）；
- 宿主 1870 MiB 内存 + 3 GiB swap，常态可用 500–650 MiB；
- 看门狗式的"自愈"：chainmon 每 30 分钟重启、canary 每 5 分钟自检。

**为什么"限额"是安全设计的一部分**：如果 guard 被内存打爆（比如某个上游返回超大响应），最坏结果是**整个宿主 OOM**，连带把其它服务杀掉。限额让"被打爆"局限在单个进程内（代价是进程可能被杀并重启）。

---
## 4. 每种判断方式（逐个讲清）

> 这一章是全文的"技术核心"。每种判断给 4 项：**判据 / 什么时候触发 / 判成什么 / 留下的计数**。
> 计数都在 guard 的 `stats.json` 里（键名与实测一致）。

### 4.1 五档策略判定（`answer_policy.Verdict`）

| 档位 | 判据 | 含义 | 后果 |
|---|---|---|---|
| **SECURE** | 有**可核验凭据**：本机 Unbound 验证通过（AD=1，通道 `local-a`/`local-alt`），或第三方报文带**未过期的 RRSIG**（细则见 4.4） | 这份答案有密码学保证，或被本地验证器背书 | 可入准入缓存，内部有效期 ≤ **900s**（`ACCEPT_MAX_TTL`） |
| **ACCEPTED** | 无 DNSSEC 但响应正常（rcode=0 且有数据） | "看起来没问题"，但没密码学保证 | 可入准入缓存，内部有效期 ≤ **300s**（`ACCEPTED_MAX_TTL`） |
| **BOGUS** | 签名坏了（RRSIG 验证失败；或带 EDE 15 且 info-code ∈ 6..12 的 SERVFAIL） | 这份答案**确定有问题** | 丢弃 + 清掉该名字的相关缓存（`_drop_caches_for(why="bogus")`） |
| **TRANSPORT** | 网络层失败（超时、连接重置、格式错、普通 SERVFAIL） | "没拿到"，不是"答案错" | 允许换源/备用修复（**不会**误判成投毒） |
| **UNKNOWN** | 其它情况 | 兜底 | 不采信 |

**大白话**：SECURE = "有公章"；ACCEPTED = "没公章但看着正常"；BOGUS = "公章是假的"；TRANSPORT = "信没送到"。
**被修过的坑**：早期版本把所有 `rcode=2`（SERVFAIL）都当 BOGUS ⇒ 一个普通超载的 SERVFAIL 会被误判成"投毒"，导致备用修复被禁用。现在只有"明确带 DNSSEC 失败标记"的 SERVFAIL 才算 BOGUS。

### 4.2 DNSSEC 假签名判定（`alt_adapter.dnssec_bogus`，alt_adapter.py:384）

- **判据**：响应里 OPT 的 EDE（Extended DNS Error）**code = 15（DNSSEC Bogus）**，且 info-code ∈ **6..12**（这些是"签名过期/被拒/缺 RRSIG 等"的标准码）；
- **触发**：上游明确告诉你"我验签失败了"；
- **判成**：BOGUS（跟随 4.1 的后果：丢弃 + 清该名字缓存）；
- **计数**：`dnssec_bogus`（实测 0 是正常的——说明当前实际流量里没遇到坏签名；`dnssec-failed.org` 会走 SERVFAIL 终局路径）。

### 4.3 见证（witness）

- **判据**：凡是"高风险采纳"都要先满足一次**独立见证**——向**另一个来源**再问一次同一问题，要求它也说"这个域名存在、答案同类"；
- **什么时候触发**：① 采信国内源 B 的答案，而该域名**没有**通过 `is_cn_trusted()`；② 采信任何"无 DNSSEC 保护"的答案（ACCEPTED 档）；③ 交叉核对（`corrob_query`）路径；
- **判成**：见证通过 ⇒ 允许采纳，档位按 4.4 的分档规则给（**只有报文带有效 RRSIG 才算 SECURE**，其余是 ACCEPTED）；不通过 ⇒ 拒绝（回退到 A/alt）；
- **计数**：`cn_trust_witness`（未通过信任白名单而必须见证的次数）、`cn_trust_bypass`（免见证）、`cn_dom_witness_bypass`（历史计数，记录"国内源答案跳过见证"的次数）。

### 4.4 见证答案的"档位"语义（N3：已实施**精细分档**）

- **判据（2026-10-16 起）**：AD 位只是**上游的自我声明**，不算密码学证据 ⇒ 档位由「通道可信度 + 报文里到底有没有签名」共同决定：

  | 通道 | 报文证据 | 档位 | 计数键 |
  |---|---|---|---|
  | `local-a` / `local-alt`（**本机自己的 Unbound**，AD 由本地验证产生） | AD=1 | **SECURE** | `ad_grade_local_ad` |
  | 第三方（见证 `witness`、国内源 `local-cn`） | AD=1 **且**带覆盖被问类型、未过期的 **RRSIG** | **SECURE** | `ad_grade_signed` |
  | 第三方 | AD=1 但签名**已过期** | **ACCEPTED** | `ad_grade_sig_expired` |
  | 第三方 | AD=1 但**没有任何签名** | **ACCEPTED** | `ad_grade_ad_declared`（核心变更） |

- **口径**：只降不升 ✓；被降级的答案内部有效期从 900s 收到 300s（撤销更快）；**AD=0 的普通答案不进入分档** —— `ad_grade()` 直接返回 `(None, "ad_zero")`，既不计入也不建桶（否则会把"没要验证"误算成"仅凭 AD 声明"）；
- **为什么这么分**：本机 Unbound 的 AD 是"我们自己的验证器说的"；第三方带 RRSIG 是"可独立复核的凭据"；第三方只报 AD 是"运营方口头保证"——三者证据强度不同，混为一谈等于让上游的夸大直接变成我们的"已验签"；
- **计数**：`cn_witness_secure_ad_declared`（历史口径，分档后应恒 0）、`cn_witness_ad_declared_accepted`（见证通道被降级的次数）、四档分布 `ad_grade_local_ad` / `ad_grade_signed` / `ad_grade_ad_declared` / `ad_grade_sig_expired`；
- **实测**：隔离验证脚本 `probe-ad-declared.py` 覆盖「AD=1 无签名 / AD=0 / SERVFAIL+EDE15」三类；生产四档分布中 `local_ad` 有值、`ad_declared` 为 0（线上 AD=1 的报文要么来自本机通道、要么带 RRSIG）。

### 4.5 存在性见证（`cn_exist_veto`，guard.py:7452）

- **判据**：对"否决/澄清域名是否存在"这个问题，必须有一份独立答案；
- **为什么需要**：投毒最常见手法是**给不存在的域名返回一个假 IP**（"NXDOMAIN 变 NOERROR"）。所以"这个域名到底存在不存在"必须单独核对，不能只看一个源；
- **触发**：采纳国内源答案前、或答案本身是"空答案（NOERROR、无数据）/NXDOMAIN"时；
- **判成**：核对一致 ⇒ 放行；不一致 ⇒ 否决（回退 A/alt）；
- **计数**：`cn_b_denied`（国内源答案被否决次数）、`cn_dom_witness_bypass`。

### 4.6 国内路由判定（`is_cn_domain`，guard.py:3079）

**判定顺序（严格按代码）**：

1. 名字为空 ⇒ False；
2. 命中**例外清单**（`_in_cn_trust_exc`）⇒ **False**，计数 `cn_dom_exception`（"这些域不走国内路"）；
3. 命中**否决名单**（`_in_cn_veto`）⇒ **False**（"境外域即使后缀像 CN 也不走国内路"）；
4. 命中国别后缀（`CN_SUFFIX`：`.cn`、`.com.cn`、`.net.cn`、`.org.cn`、`.gov.cn`、`.edu.cn`、`.ac.cn` 等）⇒ **True**；
5. 类型化名单可用 ⇒ 按条目类型匹配（`full:` 精确；`domain:` 自身+子域）⇒ 命中 True；
6. 类型化名单不可用（且无快照）⇒ **False**，计数 `cn_typed_fallback_denied`（**关键修复**：过去会回退"精确+所有子域"的宽匹配，把 `full:host` 悄悄放大成子域信任）。

**它只决定"路由"**：即"要不要优先问国内源"，**不决定"信不信"**。

### 4.7 国内信任判定（`is_cn_trusted`，guard.py:2652）

**判定顺序（严格按代码）**：

1. 命中**例外清单** ⇒ **False**（计数 `cn_trust_class_exception`）；
2. **不是**国内路由域（`is_cn_domain` 为假）⇒ **False**（"信任只在国内域里谈"）；
3. 档位 `GUARD_CN_TRUST_MODE == "none"` ⇒ **False**（最严档：连 `.cn` 也要求见证）；
4. 命中**国别/品牌后缀**（`CN_TRUST_SUFFIX`：`.cn`、`.com.cn`、`.net.cn`、`.org.cn`、`.gov.cn`、`.edu.cn`、`.ac.cn`，以及 `.alibaba`、`.alipay`、`.anquan`、`.baidu`、`.citic`、`.icbc`、`.shouji`、`.sina`、`.sohu`、`.taobao`、`.tmall`、`.unicom`、`.weibo`、`.xihuan`、`.yun`）⇒ **True**（计数 `cn_trust_class_suffix`）；
5. 命中**人工白名单**（19 条）⇒ **True**（计数 `cn_trust_class_allow`）；
6. 档位 `mode == "all"` ⇒ **True**（恢复旧行为，计数 `cn_trust_class_mode_all`）；
7. 否则 ⇒ **False**，计数 `cn_trust_class_witness`（必须走见证）。

**三个档位**：`none`（最严）/ `known`（**当前默认**）/ `all`（最松，等于"所有国内域都信任"）。

**为什么这个判定是必要的（第三份审计 F1 的根因）**：过去"是不是国内域"直接等于"信不信国内源"。社区名单（8837 条，自动更新）一旦把某个境外 CDN 域（如 `tiktokcdn-us.com`）归成"国内"，国内源给出的**错误 IP 就会被当成可信答案发给公网客户端**（实测复现：`zz-*.tiktokcdn-us.com` 在 B/AGH/公网 DoT/DoH 上都返回假 IP，而独立境外源与 unbound A 都说 NXDOMAIN）。现在"路由"与"信任"分开后，同样的情况只会"走错链路"，不会"把错答案当权威"。

### 4.8 例外清单（`cn-trust-exceptions.txt`，24 行 / 5 条）

- **当前 5 条**：`tiktokcdn.com`、`tiktokcdn-us.com`、`tiktokcdn-eu.com`、`tiktokminis.us`、`analytics.tiktok.com`；
- **作用**：命中即 `is_cn_domain` = False 且 `is_cn_trusted` = False ⇒ **既不走国内路由，也不信任**（最高优先级）；
- **怎么加的**：只加"有实测污染证据"的域名（每条在文件里带一行证据注释），不按品牌猜；同时如实登记"复核过的、**不**入清单"的反例（Cloudflare/AWS 中国等真实国内加速域，加进去反而误伤）；
- **计数**：`cn_trust_exc_entries`、`cn_trust_exc_missing`（文件缺失）、`cn_dom_exception`。

### 4.9 信任白名单（`cn-trust-allow.txt`，46 行 / 19 条）

- **当前 19 条**（apex）：`qq.com`、`baidu.com`、`taobao.com`、`tmall.com`、`alipay.com`、`jd.com`、`163.com`、`weibo.com`、`bilibili.com`、`zhihu.com`、`douyin.com`、`xiaomi.com`、`huawei.com`、`meituan.com`、`pinduoduo.com`、`tencent.com`、`aliyun.com`、`toutiao.com`、`kuaishou.com`；
- **怎么定的**：探针实测"A 与 B 都能正常回答"（`probe-allow.py`），并**排除**了 `sohu.com`（它的 apex 在 A 上 SERVFAIL，进白名单会掩盖问题）；
- **作用**：命中的国内域 ⇒ 国内源答案**免见证**直接采用（减少一次往返、降低延迟）；
- **计数**：`cn_trust_allow_entries`、`cn_trust_allow_missing`、`cn_trust_bypass`。

### 4.10 否决名单（`cn_veto.txt`，25030 行 / 25025 条）

- **来源**：v2fly 社区 `geolocation-!cn`（"非中国"地理集合）的**有界展开**（深度 ≤8、文件 ≤2000），展开后**剔除 724 条"其实是国内域"的冲突项**（如 `aboutamazon.cn`、`4008-517-517.cn`）得到；
- **作用**：命中 ⇒ `is_cn_domain` = False（"这些域不该走国内路径"）；
- **门禁**：条目数 ≥12000、国内冲突剔除比例 ≤40%、**关键国内域不得出现在否决里**（否则失败）、变化幅度 ≤5%（超限需 `--force`）；
- **快照**：`cn-veto.snapshot.txt`（25026 行）——guard 在正式文件缺失时用快照，避免"名单空 ⇒ 全部否决/全不否决"的极端。

### 4.11 IP 归属判定（`is_cn_ip`，guard.py:4191 + `load_cn_nets`，guard.py:4121）

- **数据**：`cn_ip.txt`（4316 行 CIDR，约 286M 地址空间），由刷新器从 **clang.cn（ispip.clang.cn/all_cn.txt）同源**更新（这是 guard 历史上下载的同一个源，保证语义零漂移）；
- **判据**：答案里的 IP 是否落在这些网段里；
- **用途**：判断"这个答案像国内的还是像境外的"——若一个本该境外的域名返回了国内 IP，会被标为可疑（`suspicious`）；
- **计数**：`cn_ip_nets`（载入条数）；热重载按 mtime（最长 60 秒延迟）。

### 4.12 准入缓存（`_adm_cache`：`_adm_cache_get` 446 / `_adm_cache_put` 755）

- **存什么**：只存 SECURE / ACCEPTED 的答案（BOGUS/TRANSPORT 永不入缓存）；
- **上限**：SECURE ≤900s、ACCEPTED ≤300s；`ttl <= 0` 直接不入；
- **键的构成（决定"什么变了就该失效"）**：名字 + qtype + 视图键（DO 位 / CD 位 / ECS / qclass）+ `policy_version` + `schema` + **`cn_gen`（名单代次）**；
- **名单代次（F2 修复）**：typed / veto / 例外 / 白名单 四份名单各自的内容指纹（sha256 前 16 位）拼成 `_cn_gen_id()`，写进每条缓存；命中时若代次不一致 ⇒ 视为未命中并删除（`_adm_drop`），计数 `adm_cache_gen_mismatch`；
- **为什么必须这样**：把某个域名移出信任集合后，**旧缓存里那条"按旧分类采纳的答案"会继续被下发**——这是"撤销不生效"的根因。代次比对是**结构性保证**，不依赖"清理任务有没有跑到"。
- **其它计数**：`adm_cache_invalidated_bogus`、`hot_skip_stale`（热缓存因 stale 跳过）、`hot_skip_ttl`。

### 4.13 TTL 老化（`alt_adapter.age_wire` 465 + `guard._cache_replay` 4660）

- **问题**：缓存里存的是**原始报文**，它的 TTL 是"生成那一刻"的值。如果不处理，客户端会拿到"TTL 没有随时间减少"的答案（等于缓存永不过期）；
- **做法**：取出缓存时，用 `age_wire(wire, elapsed, max_ttl=剩余期限)` **逐条 RR** 把 TTL 减去真实流逝秒数；减到 ≤0 的按 0/不入缓存处理；
- **写入时**：TTL 取 `min(600, 上游 rrset 最小 TTL)`，`ttl<=0` 不入；
- **计数**：`ttl_src_wire`、`hot_skip_ttl`。

### 4.14 stale（过期答案）判定（`stale_flags`，alt_adapter.py:431）

- **判据**：响应里 OPT 的 EDE info-code ∈ **{3, 19}**（3 = "过期答案可用"；19 = "陈旧/过期数据"）；
- **动作**：`_stale_of()` 识别 + `_stale_note()` 记录；**出口时标记来源、不写准入缓存、不延长 TTL**（`stale_out` 计数）；
- **上游行为**：unbound B 开了 `ede-serve-expired`（会给过期答案并标 EDE），unbound A 的 `serve-expired` 相关参数控制其是否给过期答案；alt 明确 **不给**（`serve-expired: no`）；
- **实测**：`stale_out` 已出现真实计数（来源 `local-cn`）⇒ 该路径确实在工作，不是"只存在于代码里"。

### 4.15 负缓存（NXDOMAIN 等）

- **存什么**："这个域名/类型不存在"的结论（NXDOMAIN、NODATA），带证据期限；
- **老化**：与正缓存一样按真实流逝裁剪（曾出现"负缓存不老化"的缺陷，已修）；
- **失效**：遇到 bogus 或分类变化时，`_drop_caches_for` 会连同负缓存一起清（计数 `neg_invalidated_bogus`）。

### 4.16 否认证明判定（`denial_proof`，guard.py:4482；N2 修复）

- **背景**：DNSSEC 里"域名不存在"要靠 NSEC/NSEC3 的否认证明；早期实现只按"有没有 RRSIG"判断，导致**一个带签名的正答案（有 A 记录）被误当成"否定证明"**；
- **现在的判据**：解析时统计 `an_total`（answer 段记录数）与 `qhits`（与问题匹配的记录数）；**`an_total > 0` ⇒ 这不是否认证明**（计数 `denial_proof_answered`）；
- **效果**：避免把"正常答案"误判为"不存在"，也避免把"假的否定"当成真的。

### 4.17 报文身份校验（`response_matches`，alt_adapter.py:311）

- **判据**（全部满足才算"这是我等的那份答案"）：事务 ID 一致、QR 位=1（是响应）、opcode 一致、QDCOUNT=1、问题段 QNAME/QTYPE/QCLASS 一致、各段 RR 计数与报文实际长度自洽；
- **为什么重要**：UDP 上任何人都能往你的端口发包。没有这套校验，一个伪造的"看起来合法的响应"就能被当成上游答案（历史缺陷，已修）；
- **相关**：`_read_exact`（342）保证"读满一帧"而不是读一半；`exchange_udp`（357）把套接字 `connect` 到固定对端（内核层丢弃其它来源）；`TC=1` 只作为"换 TCP 重试"的信号；
- **计数**：`udp_qid_mismatch`（ID 不符的丢弃次数，实测 0）。

### 4.18 可疑 IP 判定（`suspicious`，guard.py:6352）

- **判据**：答案 IP 命中"坏 IP 库"（`bad_ips.json`，115 KB），或与域名分类/ASN 归类矛盾；
- **动作**：该答案不采信（触发否决/回退），并可写入 `poisoned.json`（140 KB 的投毒记录）；
- **配合**：`asn_class.json`（ASN 分类，9.9 KB，每日 03:05 快照）。

### 4.19 备用熔断（alt breaker，alt_adapter.py:54-70）

- **参数**：连续失败 3 次（`ALT_BREAKER_FAILS=3`）⇒ 打开熔断 15 秒（`ALT_BREAKER_OPEN=15`），期间**不再尝试** alt；
- **理由**：一个已经挂掉的上游，每次去试都是"白等一个超时"，会把主路径拖慢。

### 4.20 备用就绪门（`unbound-alt-readiness.py`）

- **做什么**：每分钟检查 alt 是否"真的可用且配置正确"（不只是端口开着），把结果写 `/run/unbound-alt-ready.json`；
- **有效期**：90 秒（`ALT_READY_MAX_AGE`）——过期就当作"未就绪"，避免用一个"状态未知"的备用源；
- **为什么**：冷启动时 alt 的 TZ 链可能还没热，直接用会导致"所有验证都慢半拍"；有门之后就变成"没准备好就不用"。

### 4.21 发布一致性门（`release_consistency.py` + verifier 握手）

- **判据**：两进程的 `release_id` 一致、`guard.py` 的 sha256 一致、`verifier_proto` 一致、两侧 pid 都活着、`/proc/<pid>/cwd` 指向同一发布目录、`current` 软链指向该目录、磁盘上 guard.py 的实际哈希与元数据一致；
- **触发**：每次部署后自动跑；也可手工 `python3 /opt/dnsguard/release_consistency.py`；
- **结果**：不通过 ⇒ 退出码 1 ⇒ 部署脚本自动回滚。

### 4.22 零 TTL 单次返回（`CN_DOMESTIC_ZERO_TTL_ONESHOT`）

- **做什么**：对"可信国内域"的答案，只**单次**直接返回，不留长期缓存（避免"国内源曾经给过一个答案，就被长期信任"）；
- **条件**：`CN_DOMESTIC_PRIMARY` 且 `CN_DOMESTIC_TRUST_B` 且 `is_cn_trusted()` 且事务 ID 可用；
- **意义**：把"信任"的持续时间压到最短——每次查询都重新决策。

---

## 5. 名单体系（生成 → 使用 → 校验 → 归档）

### 5.1 一张图看清六份文件

```
                    ┌─ v2fly geolocation-cn + tld-cn（社区数据，tar 全量）
refresh-cn-rules.py ┤        │
                    │        ├─▶ cn-domains-typed.txt（带 full:/domain: 类型）──▶ guard 路由判定
                    │        └─▶ forwarding-rules.txt（纯域名，供 dnscrypt-proxy）──▶ guard 的兜底
                    └─ 同步写 cn-domains-typed.snapshot.txt（快照）

refresh-cn-veto-ip.py ┌─ v2fly geolocation-!cn（有界展开 + 国内冲突剔除）──▶ cn_veto.txt（否决）
                      ├─ clang.cn all_cn.txt（同源）──────────────────────▶ cn_ip.txt（IP 段）
                      └─ 同步写 cn-veto.snapshot.txt（快照）

人工维护：cn-trust-exceptions.txt（例外，最高优先）
          cn-trust-allow.txt（白名单，免见证）
```

### 5.2 每日刷新流程与门禁（cron 04:35）

| 步骤 | 脚本 | 门禁（不过就保留旧文件并 rc=1） |
|---|---|---|
| 1 | `refresh-cn-rules.py` | 域名数 ≥5000；相对变化 ≤15% 且绝对变化 ≥200 才需要 `--force`；**10 个境外域黑名单**命中即失败；源失败容忍 25% |
| 2 | `refresh-cn-veto-ip.py` | veto 条目 ≥12000；国内冲突剔除 ≤40%；**关键国内域不得出现**；变化 ≤5%（绝对 20）；IP 条目 ≥2000、覆盖变化 ≤5% |
| 3 | `verify-cn-lists.py` | 哈希清单逐项一致；GPG 签名有效；条目数与关键域约束 |
| — | `refresh-all-cn-lists.sh` | 汇总 rc（三项全过才 0），日志 `/var/log/cn-lists-refresh.log` |

**guard 侧**：所有名单按 mtime **60 秒内热重载**，刷新**不需要重启任何服务**。

### 5.3 变更归档与签名（`cnlist_history.py`）

- 每次名单变化写一条归档（谁变了、增删了什么、时间、来源）；
- 更新 `cn-list-history/MANIFEST.sha256` 并 **GPG 签名**（无口令 RSA 3072，指纹 `E1B5F51A55B5F4EFED052DC7326F7CD740F03309`）；
- 归档保留 30 天（超期清理）；
- **能证明什么**：清单**落盘之后**没被改过；**不能证明**上游数据本身可信（上游没有官方签名）。

### 5.4 手工运维命令

```bash
# 统一刷新（等于 cron 干的事，可加 --dry-run / --force）
bash $CODE_DIR/tools/refresh-all-cn-lists.sh

# 单独校验名单完整性 + 签名
python3 $CODE_DIR/tools/verify-cn-lists.py

# 撤销某域名的国内信任（改例外清单 + 清 AGH 缓存）
$CODE_DIR/tools/cn-trust-revoke.sh <域名>

# 清 AGH 缓存
$CODE_DIR/tools/agh-cache-clear.sh
```

---

## 6. 运维与自保

### 6.1 发布与回滚

```bash
# 部署（自动：校验 → 备份 → 切链 → 重启两进程 → 门禁 → 失败回滚）
bash $CODE_DIR/tools/deploy_release.sh 20261015-audit-fixes-11

# 回滚到上一版
bash $CODE_DIR/tools/deploy_release.sh --rollback 20261015-audit-fixes-10

# 只看状态
bash $CODE_DIR/tools/deploy_release.sh --status
```

发布目录不可变；`current` 是软链；每版都有 `RELEASE`（发布号）、`RELEASE.sha256`（逐文件哈希）、`.files`（文件清单）。

### 6.2 门禁三件套（部署脚本里自动跑）

1. `RELEASE.sha256` 校验（发布文件没被改）；
2. `verify-release-data.py`（`.files` 与哈希清单一致、快照入清单、快照内容约束）；
3. `release_consistency.py`（两进程同发布、cwd 一致、pid 活、磁盘哈希一致）。

### 6.3 IP 对账（`dnsguard-ip-reconcile.sh`，每 5 分钟）

**修 6 处**：① nginx DoT `proxy_pass`；② unbound A 的 `forward-addr`（aghdq）；③ `dotfront-spool` 的 drop-in；④ AGH 上游；⑤ guard 的 `GUARD_LISTEN_HOST`（= docker0 网关）；⑥ `probe-srcaddr` 的 `172.18.0.99/16` 别名。

> ⚠️ 同上：`/etc/dnsdist/dnsdist.conf` 的上游地址不在对账范围内，IP 变更后需重跑 `./install.sh`。

**安全设计**：解析不出合法容器 IP（不在 `172.16–172.31`）就**整体不动任何文件**（退出码 2）；零漂移时零副作用；每项修改前备份到 `$CODE_DIR/backups/ip-reconcile-<时间>/`；改完做语法/服务校验，失败回滚。

### 6.4 防火墙原子收敛（`dnsguard-fw.sh` + `dnsguard-fw-table.py`，每 5 分钟）

- 生成完整新表 → 与当前逐字节比对 → **一次 `iptables-restore`** 原子替换 → 失败回滚；
- `--check` 是**真只读**（任何写操作都会先被分流拦掉）；
- 每次应用前备份到 `$CODE_DIR/backups/fw/<时间>`，应用历史写 `/var/log/dnsguard-fw.jsonl`。

### 6.5 AGH 缓存与"撤销闭环"

**这是本系统唯一需要"人工参与最后一步"的地方**：
- guard 侧撤销（改例外清单/白名单）会立刻生效（代次让 guard 自己的缓存失效）；
- 但 **AGH 里已经缓存的旧答案最长会活 24 小时**（`cache_ttl_max=86400`）；
- 所以完整撤销 = guard 侧改动 **+** `agh-cache-clear.sh`（调 AGH API 清缓存）。

### 6.6 探针与验收证据

日常自检：`dns-chain-probe.timer`（5 分钟，五层 × 四样本）、`dnsguard-canary.timer`（5 分钟，canary 对照）。

需要人工验收时：

```bash
python3 /opt/dnsguard/dns-entry-probe.py      # 三个入口（严格 TLS + DO）
python3 /usr/local/sbin/dns-chain-probe.py    # 五层
python3 /opt/dnsguard/external-probe.py       # 从外部网络看
python3 /opt/dnsguard/acceptance_check.py     # 汇总验收证据
```

### 6.7 快照与恢复

```bash
bash $CODE_DIR/tools/make-snapshot.sh   # → /root/dns-snapshot-<日期>/（+ tar.gz）
```

快照内容：发布校验结果、一致性门禁、单元状态、drop-in、防火墙规则、nginx 站点、AGH 配置、三个 Unbound 配置、crontab、名单哈希（10 项含两份快照与两份人工清单）、GPG 公钥、名单校验输出、内存、探针结果。

**单机重建的最短路径**：恢复 `/opt/dnsguard`（含 releases 与 current）、`/opt/dnscrypt-proxy`、`/opt/{unbound,unbound-b,unbound-alt,adgh,aghdq}` 配置 → 起容器 → 起 guard/verifier → 跑门禁与探针 → 跑 IP 对账与防火墙对账。

### 6.8 内存限额与自愈

- 每个进程有 cgroup 上限（见 1.4）；
- chainmon 每 30 分钟自动重启；canary 每 5 分钟自检；
- 宿主曾有 OOM 记录（2026-10-14 两次），F3 修复后各单元限额收紧（guard 160/192 MiB 等）。

---

## 7. 已知边界与"不做的事"（诚实清单）

> 这一章是"这套系统的自我批评"。**没有一项是猜测**——都出自历次审计与实测。

### 7.1 单机单出口（审计 F5，已登记）

所有入口、决策、上游、监控都在**一台 2 GiB 的服务器**上。这台机器挂了，家里和公网的解析全挂。**当前没有第二台入口或异机恢复方案**（文档 `HOST-SPOF-20261015.md` 列出了 11 个共享单点与恢复路径，但没建高可用）。

### 7.2 公网入口没有客户端认证（审计 F3，用户决定不动）

- AGH `allowed_clients: []`、`disallowed_clients: []` ⇒ 任何能连上 853/443/444 的人都能用这套解析；
- 限流有：DoT 每源 32 并发/全端口 512；DoH 每源 32 并发 + 200 r/s；AGH `ratelimit 200`（每 /24）——但这些都是**防滥用**，不是**身份认证**；
- nginx→AGH 没有 PROXY protocol ⇒ AGH 看到的是网关地址（DoT 侧）⇒"按客户端计量"能力有限；
- guard 的准入池是**共享**的（96 在途 + 96 排队）⇒ 一个客户端刷查询会影响所有人。

### 7.3 AGH 缓存不随名单代次失效

见 6.5：guard 侧是结构化的（代次），AGH 侧是时间性的（最长 24 小时）。**撤销必须成对操作**。

### 7.4 上游数据没有官方签名

v2fly（社区名单）、clang.cn（IP 段）都**不提供签名**。所以：
- 能保证"落盘后没被改"（GPG + 清单）；
- **不能**保证"来源本身正确"——这也正是"路由/信任分离 + 例外清单 + 白名单 + 见证"这四层存在的理由。

### 7.5 本文档中"未展开核实"的部分

为不捏造，以下内容我没有读源码，只按配置与作用描述：
- `chainmon.py` / `devfp.py` 的采集细节（源码顶部的 docstring 说明了四路/多路采集，但**具体解析逻辑未逐行核实**）；
- `alt-replica-unb` 的用途细节（只知它是 alt 的副本，在独立网络 `altreplica0`）；
- `dnscrypt-proxy.toml` 仅核对了关键项（服务器名、监听、缓存、require_* 策略）。

> 说明：`dotfront-spool.py` 已随本项目一并发布（`tools/dotfront-spool.py`），其行为已在 3.2 按源码逐项写清。

### 7.6 明文 53 完全关闭（这是特性，不是缺陷）

- 宿主公网不监听 53；
- 国内源 B 的明文 53 出站被防火墙 DROP；
- 上游全部 `forward-first: no`。
⇒ **任何"降级到明文"的路径在网络层就被堵死**。代价：一旦加密上游全挂，没有明文兜底（本轮设计选择"可用性让位于防投毒"）。

### 7.7 历史上修过的严重缺陷（作为教训保留）

| 缺陷 | 后果 | 修复 |
|---|---|---|
| 缓存不老化 TTL | 客户端拿到"永不过期"的答案 | 逐 RR 老化 + 按剩余期限裁剪 |
| 所有 SERVFAIL 当投毒 | 备用修复被误禁用 | 只有 EDE 15 才算 BOGUS |
| UDP 响应不校验来源/ID/问题 | 可能接受伪造响应 | `response_matches` + `connect` 固定对端 + 读满帧 |
| 名单读失败按"不否决" | 冷启动扩大国内信任 | 失败即"一律否决" + 启动守卫拒绝起服务 |
| 两进程跑不同发布 | 行为不可解释、门禁失效 | 原子切换 + 握手版本校验 + 一致性门禁 |
| "路由=信任"耦合 | 境外 CDN 被国内源污染答案下发公网（**已复现**） | 拆成 `is_cn_domain` / `is_cn_trusted` + 例外清单 |
| 名单热更新不撤销缓存授权 | 撤销后旧答案继续下发 | 名单代次写进缓存键 |
| 探针自己"关掉安全检查" | 探针永远绿，问题看不见 | 严格 TLS + 带 DO + 明确判据 |
| 防火墙"先删后加"非原子 | 定时任务执行期间有规则空窗 | 生成整表 + 一次 `iptables-restore` |
| 名单生成丢匹配类型 | `full:` 被当成子域信任 | 保留 `full:/domain:` 类型 + 类型化匹配 |

---

## 8. 附录

### 8.1 命令速查

```bash
# —— 状态 ——
systemctl status dnsguard dnsguard-verifier chainmon devfp dnscrypt-proxy-local
docker ps --format '{{.Names}}\t{{.Status}}\t{{.Ports}}'
bash $CODE_DIR/tools/deploy_release.sh --status
python3 /opt/dnsguard/release_consistency.py

# —— 指标 ——
python3 -c "import json;d=json.load(open('$CODE_DIR/stats.json'));print(json.dumps({k:v for k,v in d.items() if isinstance(v,(int,float))},indent=1))"

# —— 名单 ——
python3 $CODE_DIR/tools/verify-cn-lists.py
bash $CODE_DIR/tools/refresh-all-cn-lists.sh --dry-run

# —— 探针 ——
python3 /opt/dnsguard/dns-entry-probe.py
python3 /usr/local/sbin/dns-chain-probe.py
python3 /opt/dnsguard/external-probe.py

# —— 对账 ——
/usr/local/sbin/dnsguard-ip-reconcile.sh --check
/usr/local/sbin/dnsguard-fw.sh --check

# —— 快照 ——
bash $CODE_DIR/tools/make-snapshot.sh
```

### 8.2 关键数值速查（截至 2026-10-15 23:3x）

| 项 | 值 |
|---|---|
| 发布 | `20261015-audit-fixes-11`（guard PID 1765985，22:54:56 启动） |
| guard 监听 | `172.18.0.1:5355`（udp+tcp）、`172.18.0.1:5356`（udp） |
| 类型化域名名单 | 8839 行（`full:` 77 / `domain:` 8760，guard 实际载入 8788 条） |
| forwarding-rules | 8838 行 |
| 否决名单 | 25030 行（25025 条） |
| IP 段 | 4316 行（约 286M 地址） |
| 例外清单 | 5 条 |
| 信任白名单 | 19 条 |
| AGH 缓存 | 64 MiB，TTL 0–86400 |
| 证书 | dns.example.com，有效期至 2026-12-09 22:27:52 CST（当日剩 55 天） |
| 宿主内存 | 1870 MiB（常态可用 500–650 MiB），swap 3 GiB |

### 8.3 指标怎么看（`stats.json` 常用键）

| 键 | 含义 |
|---|---|
| `cn_typed_total` / `_full` / `_domain` | 类型化名单载入情况 |
| `cn_typed_snapshot_used` | 是否用了快照（>0 说明正式文件缺失过） |
| `cn_typed_fallback_denied` | 因名单不可用而拒绝宽匹配的次数（>0 值得关注） |
| `cn_veto_entries` / `cn_veto_fail` | 否决名单条数 / 载入失败次数 |
| `cn_ip_nets` | IP 段条数 |
| `cn_trust_exc_entries` / `cn_trust_exc_missing` | 例外清单条数 / 是否缺失 |
| `cn_trust_allow_entries` / `cn_trust_allow_missing` | 白名单条数 / 是否缺失 |
| `cn_trust_bypass` / `cn_trust_witness` | 免见证 / 必须见证的次数 |
| `cn_witness_ad_declared_accepted` | 见证通道仅凭 AD 声明 ⇒ 降级 ACCEPTED 的次数 |
| `ad_grade_local_ad` / `_signed` / `_ad_declared` / `_sig_expired` | AD=1 报文的四档分布（本机通道 / 带签名 / 仅声明 / 签名过期） |
| `cn_dom_exception` | 例外命中次数 |
| `cn_b_denied` | 国内源答案被否决次数 |
| `dnssec_bogus` | 明确坏签名次数 |
| `stale_out`（及 `stale_out_<来源>`） | 出口 stale 答案次数 |
| `hot_skip_stale` / `hot_skip_ttl` | 热缓存跳过次数 |
| `udp_qid_mismatch` | 报文 ID/身份不符丢弃次数（应为 0） |
| `adm_cache_gen_mismatch` | 因名单代次变化而失效的缓存条数 |
| `v_err` / `v_badframe` | verifier 错误 / 坏帧 |
| `pss_kb` / `pss_peak_kb` | 进程内存足迹 |

### 8.4 名词表

| 名词 | 通俗解释 |
|---|---|
| **投毒 / 污染** | 有人把假 IP 塞进 DNS 答案，把你引到错误（钓鱼）地址 |
| **DNSSEC** | 给 DNS 答案加"数字签名"，让你能验证答案没被改 |
| **AD 位** | 响应里的"我已经验证过签名"标志（**上游的自我声明**；只有本机 Unbound 给出的 AD 或随报文一起给的 RRSIG 才算凭据，见 4.4） |
| **DoT / DoH / DoQ** | DNS over TLS / HTTPS / QUIC：把 DNS 装进加密通道 |
| **DoT 前缀** | DoT 报文前面有 2 字节长度（RFC 7858），解析时必须先剥掉 |
| **EDE** | 扩展错误码：让上游能告诉你"为什么失败"（如 15 = DNSSEC 坏签名，3/19 = 过期数据） |
| **见证 (witness)** | "再找一个人问一遍，看他说的一样不一样" |
| **存在性见证** | 专门确认"这个域名到底存不存在"（防止假 IP 冒充存在） |
| **准入缓存** | 只存"够安全"的答案的小仓库（SECURE ≤900s / ACCEPTED ≤300s） |
| **代次 (generation)** | 名单内容的指纹；名单一变，指纹就变，旧缓存自然失效 |
| **否决名单 (veto)** | "这些域名不许走国内可信路径"的名单 |
| **例外清单** | "这些域名连国内路由都不要走"（最高优先） |
| **白名单** | "这些明确的国内大站，国内源答案可以不核对" |
| **fail-closed** | 出问题就失败，绝不偷偷降级（如不明文回退） |
| **熔断** | 某条路连着失败就先关掉一段时间，不再白等 |
| **门禁** | 部署后自动检查"两个进程是否同一发布、指标是否正常" |
| **快照** | 名单/系统的"上次有效副本"，防止坏数据把系统带偏 |

---

**文档结束。**

> 这份文档描述的是 **2026-10-15 23:3x** 的实际状态。系统每天都在按 timer 自检、按 cron 刷新名单，所以具体数值（条目数、计数、PID）会变；**结构、判据与流程不会变**——它们才是这份文档的重点。
