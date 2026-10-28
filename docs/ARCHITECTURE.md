# 架构

## 1. 分层与端口

| 层 | 组件 | 监听 | 作用 |
|---|---|---|---|
| 入口 | 主 AdGuard Home 容器 `adgh` | 宿主 `0.0.0.0:853`(DoT) → 容器 `853`；`0.0.0.0:444`(DoH) → 容器 `443`；`127.0.0.1:3000`(UI) / `4443`(HTTPS) / `8854`(DoT) | TLS 终结、规则过滤、按客户端真实 IP 注入 ECS `/24`。**DNS 缓存必须关闭**：AGH 缓存是域名单键，不按 ECS 分片（实测把 A 省答案返回给 B 省） |
| 缓存层 | `dnsdist`（宿主 systemd） | 内网 `172.18.0.1:5300`(udp+tcp)、控制台 `127.0.0.1:5199`、统计 `127.0.0.1:18083` | ECS 感知 PacketCache（131072 条，`parseECS=true`）、单来源限速（1000 qps / 10s）；上游唯一 = guard `172.18.0.1:5355`。2026-10-28 起不再终结公网 TLS |
| 入口（legacy） | nginx（宿主） | DoT `853/tcp`、DoH `443`、`444/tcp` | 2026-10-22 之前的入口。生产实例 `:443` 仍可经 nginx 反代到 `adgh:4443`；853 / 444 已由 AGH 承接 |
| 策略 | `guard`（宿主 systemd） | `dnsnet` 网关 `:5355`(udp+tcp，默认 `172.18.0.1`) + `:5356`(udp，探针通道) | 准入、共识、见证、否决、缓存代次、失败语义 |
| 策略 | `verifier`（宿主 systemd） | `/run/dnsguard/verifier.sock`（AF_UNIX） | 独立进程做交叉验证，隔离慢查询 |
| 上游 | `unbound`（A） | 宿主 `127.0.0.1:5353`、`172.18.0.1:5353` | forward-zone 双上游：`aghcf`（主，Cloudflare + censurfridns DoT）与 `aghdq2`（备，Quad9 DoQ）；**本机验 DNSSEC**，`forward-first: no`（fail-closed）；`num-threads: 8` |
| 上游 | `unbound-b`（B） | 宿主 `127.0.0.1:5354`、`172.18.0.1:5354` | 转发 → 三家国内 DoT（`dot.360.cn`、`dns.alidns.com` ×2）；`module-config: subnetcache validator iterator` + `client-subnet-always-forward: yes`（按 ECS 分片缓存）；本地验签开启、`num-threads: 16` |
| 上游 | `unbound-alt` | 宿主 `127.0.0.1:5357` | 独立第三方 DoT，用于交叉见证 |
| 备用副本 | `alt-replica-unb` | 宿主 `127.0.0.1:15353` | alt 的独立网络副本（`10.99.0.0/24`），用于演练/灰度，不参与主链路 |
| 出口 | AdGuard Home 容器 `aghdq` | 宿主 `127.0.0.1:5533` | 唯一上游 `quic://dns.nextdns.io`，`bootstrap` 走明文 223.5.5.5。2026-10-28 起上游握手持续失败（每条查询阻塞十几分钟），**已从 A 的 forward-addr 摘除** |
| 出口 | AdGuard Home 容器 `aghdq2` | 宿主 `127.0.0.1:5534` | Quad9 DoQ（`quic://dns10.quad9.net`）：A 的**备用 forward-addr**；同时是 guard 的认证备用 / 救援通道（`GUARD_ALT_ADDR=127.0.0.1:5534`）与 DoQ 核对通道（`GUARD_DOQ_PORT=5534`） |
| 出口 | AdGuard Home 容器 `aghcf` | 宿主 `127.0.0.1:5535` | `parallel` 双上游：`tls://1.1.1.1`（裸 IP DoT，不带域名 SNI，抗按域名封锁）+ `tls://unicast.censurfridns.dk`；A 的**主 forward-addr** 兼国内域名存在性见证源 |
| 影子 | `dnscrypt-proxy` | 宿主 `127.0.0.1:5399` | 给 guard 做影子对比（`GUARD_SHADOW_*`） |
| 观测 | `chainmon` / `devfp` | `127.0.0.1:8787` / `:8789` | 链路看板 / 设备指纹看板（Basic Auth 后置于 nginx） |

> 模板里容器都在 Compose 自定义网络 `dnsnet` 里（默认 `172.18.0.0/16`）并用**固定 IP**（`adgh=.2`、`unbound=.4`、`unbound-b=.5`、`aghdq=.6`、`unbound-alt=.8`、`dnscrypt=.9`、`aghdq2=.11`、`aghcf=.12`）；guard 监听网络网关（默认 `172.18.0.1`，由 `install.sh` 按 `GW_IP` 注入）。
>
> **生产实例用的是 Docker 默认 bridge（`172.18.0.0/16`）且未固定 IP** ⇒ 容器重启后地址会漂移（2026-10-28 实测 aghcf 从 `.10` 漂到 `.5`、unbound-b 从 `.5` 漂到 `.3`）。当前实际分配：`adgh=.2`、`unbound=.4`、`unbound-b=.3`、`aghdq=.6`、`aghdq2=.9`、`aghcf=.5`。下游引用没有写死 IP 的由 `dnsguard-ip-reconcile.sh` 每 5 分钟收敛，写死的由 `dnsguard-fw-reconcile.sh` 整表重建 —— 这是生产实例与模板的主要偏差之一（见第 8 节）。
> 修改 `.env` 里的网段/IP 后必须重新 `./install.sh`（并跑 `firewall/dnsguard-ip-reconcile.sh --check`）。

## 2. 一次查询的旅程

### 境外域名（例如 `www.google.com`）

1. 客户端 DoT/DoH → **AdGuard Home**（`adgh`，公网 `853` / `444`）终结 TLS，拿到真实 `remoteaddr`，并按客户端公网 IP 注入 ECS `/24`（私有/保留地址不注入）
2. AGH → dnsdist `172.18.0.1:5300`（内网缓存层）。`parseECS=true` 的 PacketCache（131072 条）按 `/24` 分片，命中即返回；AGH 自己的缓存**必须关闭**（域名单键，不按 ECS 分片）
3. 未命中 → guard `172.18.0.1:5355`
4. guard 并行/对冲地问 A（境外，验签）与 alt；必要时用 verifier 做隔离验证
5. 采纳判定：`secure`（验签通过）＞ `accepted`（可信但未验签）；`bogus`/`transport` 不采纳
6. guard → dnsdist → AGH → 客户端。TTL 由上游 RRset 剩余期限决定；**无独立佐证的 fail-open 出口统一压到 60 秒**（`GUARD_FAILOPEN_TTL_CAP`），把污染自愈窗口从策略上限（300/900s）压到分钟级

### 国内域名（例如 `www.qq.com`）

1–3 同上
4. guard 判定路由：`is_cn_domain(name)` 为真 → **优先问 B**（国内路径，更快）
5. 采纳前依次检查：
   - 否决名单命中 → 不采纳
   - 特征可疑（`suspicious`）→ 不采纳
   - `is_cn_trusted(name)` 为真（国别后缀/人工白名单）→ 免存在性见证直接采纳
   - 否则：与 A/alt **交叉见证**（`cn_exist_veto`），一致才采纳，不一致则回退 A/alt 或 SERVFAIL
6. 采纳结果写入准入缓存（`accepted` ≤300s、`secure` ≤900s），并携带**名单代次**；名单变化即失效

### 名单不可用时

- typed 名单缺失 → 尝试同目录快照；再失败 → **判为非国内**（绝不扩大国内信任）
- 否决名单缺失 → 尝试 live 快照 → 发布目录快照；全失败 → **一律否决**（保守）
- 国内可信白名单缺失 → 空集（等于"所有国内域名都要见证"）

## 3. 每一处判断的依据

| 判断 | 依据 | 失败时行为 |
|---|---|---|
| 应答是否属于本次查询 | ID/QR/opcode/QDCOUNT、QNAME+QTYPE+QCLASS 三元组、各段 RR 计数、报文尾长 | 丢弃并重收（有界），否则视为超时 |
| 来源是否正确 | UDP `connect()` 固定对端；AF_UNIX 校验对端身份 | 丢弃 |
| 是否被投毒（DNSSEC） | 本机验签结果 + OPT EDE code（仅 `15` 且 value ∈ 6..12 视为 DNSSEC 失败） | 普通 SERVFAIL 视为**传输问题**，允许备用通道修复 |
| 国内可信 | `is_cn_trusted()`：例外清单 → 路由判国内 → 档位 → 国别后缀 → 白名单 | 无语义扩展：宁严不宽 |
| 见证是否通过 | B 的答案与 A/alt 或签名证据一致 | 回退 A/alt；仍不行则 SERVFAIL（fail-closed） |
| 缓存是否可用 | `policy_version` + `schema` + 视图(DO/CD/ECS) + `evidence_until` + **名单代次**（2026-10-28 起 ECS 是实装维度：准入缓存键与单飞键均含 `/24`） | 任一不符即丢弃（并计数 `adm_cache_gen_mismatch`） |
| stale 应答 | OPT EDE 3/19 | 允许单次出口，但**不写准入缓存、不延长 TTL** |
| 发布是否一致 | 两进程 `stats_meta.json` 的 `release_id`/`guard_sha256`/`verifier_proto` + 存活 + `/proc/<pid>/cwd` | 门禁退出码 1；握手不匹配直接拒绝执行查询 |

## 4. 组件职责

- `core/guard.py`：全部解析策略的唯一实现（准入缓存、共识与见证、名单、失败语义、指标）
- `core/verifier.py`：从 guard 导入模块但**独立进程**运行，通过 AF_UNIX 收任务、分池并发、有界等待
- `core/alt_adapter.py`：报文层工具（解析、应答绑定校验、UDP 交换、RRSIG/EDE 判定、逐 RR 老化、AD 位分档）
- `core/unbound-alt-readiness.py`：alt 就绪门（探 5 项判据，绑定容器身份与配置哈希，写 `/run/unbound-alt-ready.json`；脚本装在 `/usr/local/sbin`，适配器仍从当前发布 import）
- `core/answer_policy.py`：档位定义（`SECURE`/`ACCEPTED`/`BOGUS`/`TRANSPORT`）与版本号；版本变化即让准入缓存失效
- `tools/*`：名单刷新与归档验签、发布门禁与回滚、快照、看门狗、缓存撤销、DoT 明文内腿采集（`dotfront-spool.py`）
- `firewall/*`：把 iptables 收敛变成"单次原子替换"（先算好目标表 → 自检 → 一次 restore，失败自动回滚）
- `dashboards/*`：只读观测（链路参数 / 设备指纹），不参与解析决策

## 5. 数据流与状态文件

| 路径 | 内容 |
|---|---|
| `<CODE_DIR>/stats.json` | guard 运行指标（含名单载入、见证、缓存、失败语义计数） |
| `<CODE_DIR>/stats_meta.json` | guard 发布指纹（release/sha/policy/proto/pid） |
| `<CODE_DIR>/verifier-state/stats_meta.json` | verifier 发布指纹 |
| `<LISTS_DIR>/cn-domains-typed.txt` | 类型化名单（`full:` 精确 / `domain:` 自身+子域） |
| `<LISTS_DIR>/forwarding-rules.txt` | dnscrypt-proxy 用扁平名单（与上面同源，语义不同） |
| `<LISTS_DIR>/cn_veto.txt` | 否决名单（地理上在中国之外的域） |
| `<LISTS_DIR>/cn_ip.txt` | 国内 IP 段（判断"答案是否国内"） |
| `<LISTS_DIR>/cn-trust-allow.txt` | 人工白名单（免见证） |
| `<LISTS_DIR>/cn-trust-exceptions.txt` | 强制例外（**不**走国内路径、**不**信任） |
| `<CODE_DIR>/cn-list-history/` | 每次名单变更的归档 + `MANIFEST.sha256` + GPG 签名 |
| `/run/unbound-alt-ready.json` | alt 就绪门结果（`unbound-alt-readiness.timer` 每分钟写，90 s 有效；缺失或过期 ⇒ guard 关闭 alt 通道） |

## 6. 开关速查

| 环境变量 | 默认 | 含义 |
|---|---|---|
| `GUARD_CN_DOMESTIC_PRIMARY` | 1 | 允许国内路径优先 |
| `GUARD_CN_DOMESTIC_TRUST_B` | 1 | 国内可信集合内的答案可免见证 |
| `GUARD_CN_TRUST_MODE` | `known` | `none` 最严 / `known` 国别后缀+白名单免见证 / `all` 旧行为 |
| `GUARD_CN_EXIST_MODE` | `enforce` | 是否启用存在性见证 |
| `GUARD_MAX_INFLIGHT` / `MAX_PENDING` | 96 / 96 | 并发与排队上限 |
| `GUARD_QUERY_DEADLINE` | 4.0 | 单次查询总预算（秒） |
| `GUARD_SHADOW_DNSCRYPT` / `SHADOW_PCT` | 127.0.0.1:5399 / 10 | 影子对比通道与采样率 |

完整清单见 `deploy/systemd/dnsguard.service.d/zzzzzz-consolidated-20261010.conf`。

## 8. 生产实例与模板的差异（2026-10-28）

本仓库的 `deploy/` 与 `docker-compose.yml` 描述的仍是「dnsdist 直接终结公网 TLS」的形态。生产实例（logic769.xyz）已在 2026-10-28 迁移为「AdGuard Home 做公网入口 + 按客户端 IP 注入 ECS，dnsdist 退到内网做 ECS 感知缓存层」。差异清单与**原因**如下 —— 原因比差异本身重要，它决定了这套形态不是可以随意换回去的。

| 项 | 模板（deploy/） | 生产实例 | 原因 |
|---|---|---|---|
| 公网 TLS 入口 | `dnsdist` 的 `addTLSLocal("0.0.0.0:853")` + `addDOHLocal("0.0.0.0:444")` | AdGuard Home 容器 `adgh`：`0.0.0.0:853 -> 853`、`0.0.0.0:444 -> 443` | 只有 AGH 能按客户端真实 IP 注入 ECS。dnsdist 2.1.3 的 `SetECSAction` 四种写法（含 `dq.ecs` 直接赋值）实测全部失效，抓包后端查询里只有 COOKIE、没有 ECS option |
| dnsdist 监听 | 公网 `0.0.0.0:853` / `0.0.0.0:444` | 内网 `setLocal("172.18.0.1:5300")` | 缓存下沉到 dnsdist（`parseECS=true`，131072 条）。AGH 的 `cache_enabled` 必须为 false —— 实测 AGH 缓存是域名单键，会把 A 省的 ECS 答案返回给 B 省 |
| `setACL` | `{"0.0.0.0/0","::/0"}` | `{"127.0.0.0/8","172.16.0.0/12","10.0.0.0/8","192.168.0.0/16"}` | 缓存层只对内网开放，公网只到 AGH |
| `adgh` 端口映射 | 仅 `127.0.0.1:${AGH_UI_PORT}:3000`、`127.0.0.1:${AGH_HTTPS_PORT}:443`、`127.0.0.1:${AGH_DOT_PORT}:853` | 追加 `0.0.0.0:853 -> 853`、`0.0.0.0:444 -> 443` | 公网入口。DoH 容器内固定是 `443`，公网侧必须映射到 **`:444`** —— devfp 按端口号判定（853→`dot`、444→`doh444`、443→`tls443`），映射到 `:443` 会被记成普通网页流量，设备指纹看板就失效 |
| `adgh` DNS 缓存 | `cache_enabled: true` | `cache_enabled: false` | 同上：AGH 缓存不按 ECS 分片，多用户场景必然串味 |
| `adgh` ECS | `edns_client_subnet.enabled: false` | `enabled: true`，`custom_ip` 留空 | `custom_ip` 留空 = 按客户端真实公网 IP 自动生成 `/24`；`use_custom: true` 则所有用户共用同一个固定 ECS，失去 per-user 意义 |
| 容器 IP | compose 的 `ipv4_address` 固定 | Docker 默认 bridge 动态分配（**会漂移**） | 生产容器不是 compose 起的。2026-10-28 实测 aghcf 从 `.10` 漂到 `.5`、unbound-b 从 `.5` 漂到 `.3`。当前实际分配：`adgh=.2`、`unbound=.4`、`unbound-b=.3`、`aghdq=.6`、`aghdq2=.9`、`aghcf=.5` |
| `unbound-b`（国内腿） | 未开 ECS | `module-config: "subnetcache validator iterator"` + `client-subnet-always-forward: yes` | 不按 ECS 分片的话，上游按不同省份返回的 CDN 地址会互相覆盖；两项都加才既有转发又有缓存分片（只验证过两者同时开的组合） |

生产实例上多出来的自动收敛单元（不在本仓库 `deploy/` 里）：

| 单元 | 周期 | 职责 |
|---|---|---|
| `dnsguard-ip-reconcile.timer` | 5 min | 把 unbound A 的 forward-addr / AGH 上游 / guard 监听地址 / probe 源地址收敛到 docker 实际分配。**注意它只管第一条 `forward-addr`**（2026-10-28 修 bug 前的整文件替换会把备用上游覆盖掉） |
| `agh-watchdog.timer` | 60 s | 核对 dnsdist 上游 IP 与 AGH 实际 IP；内存超兜底阈值时**只有 DNS 探测同时失败才重启**；探测是三级判据（dig 退出码 + `status:` + A 段非空），只看退出码会把 NXDOMAIN 误判成健康 |
| `dns-channel-selfheal.timer` | 60 s | 国外腿被封锁后上游已恢复、但 unbound 负缓存里仍是 SERVFAIL 时，自动 `flush_negative` + `flush_bogus`。两条上游都不通时不动作（防误清） |
| `dnsguard-fw-reconcile.timer` | 6 min | 整表重建 `DOCKER-USER` / `INPUT` 规则（容器 IP 漂移后自动跟随，`iptables-save` → 生成 → 自检 → 单次 `iptables-restore`，失败自动回滚） |

> 这些差异**尚未回灌**到 `deploy/`：改成模板形态需要同时改 `docker-compose.yml`、`deploy/dnsdist/dnsdist.conf.tpl`、`deploy/containers/adgh.AdGuardHome.yaml.tpl`、`install.sh` 与 `firewall/` 的 5300 端口放行，属于一次完整的部署形态迁移，按改动分级单独进行。本文件如实记录生产现状，不假装模板与生产一致。
