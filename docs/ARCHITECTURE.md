# 架构

## 1. 分层与端口

| 层 | 组件 | 监听 | 作用 |
|---|---|---|---|
| 入口 | nginx（宿主） | DoT `853/tcp`、DoH `443`、`444/tcp` | TLS 终结；DoT 内腿明文转 `adgh:53`，DoH 反代 `agh_doh`（直连 adgh 容器 443，keepalive 池）；按源限流 |
| 过滤/缓存 | AdGuard Home 容器 `adgh` | `53`（融合）、宿主 `127.0.0.1:3000`(UI) / `4443`(HTTPS) / `8854`(DoT) | 规则过滤、缓存、唯一上游 = guard |
| 策略 | `guard`（宿主 systemd） | `docker0 网关:5355`(udp+tcp) + `:5356`(udp，探针通道) | 准入、共识、见证、否决、缓存代次、失败语义 |
| 策略 | `verifier`（宿主 systemd） | `/run/dnsguard/verifier.sock`（AF_UNIX） | 独立进程做交叉验证，隔离慢查询 |
| 上游 | `unbound`（A） | 宿主 `127.0.0.1:5353` | 转发 → `aghdq:53` → NextDNS(DoQ)；**本机验 DNSSEC**，`forward-first: no` |
| 上游 | `unbound-b`（B） | 宿主 `127.0.0.1:5354` | 转发 → 6 家国内 DoT；不验签，答案须经 guard 约束 |
| 上游 | `unbound-alt` | 宿主 `127.0.0.1:5357` | 独立第三方 DoT，用于交叉见证 |
| 出口 | AdGuard Home 容器 `aghdq` | 宿主 `127.0.0.1:5533` | 唯一上游 `quic://dns.nextdns.io`，`bootstrap` 走明文 223.5.5.5 |
| 影子 | `dnscrypt-proxy` | 宿主 `127.0.0.1:5399` | 给 guard 做影子对比（`GUARD_SHADOW_*`） |
| 观测 | `chainmon` / `devfp` | `127.0.0.1:8787` / `:8789` | 链路看板 / 设备指纹看板（Basic Auth 后置于 nginx） |

> 容器都在同一个 bridge 网络里，用**固定 IP**（默认 `172.18.0.0/16`）：`adgh=.2`、`unbound=.4`、`unbound-b=.5`、`aghdq=.6`、`unbound-alt=.8`。guard 用 docker0 网关地址监听，AdGuard Home 通过网关访问 guard。
> 修改 `.env` 里的网段/IP 后必须重新 `./install.sh`（并跑 `firewall/dnsguard-ip-reconcile.sh --check`）。

## 2. 一次查询的旅程

### 境外域名（例如 `www.google.com`）

1. 客户端 DoT/DoH → nginx 终结 TLS（限流：每源 32 并发 / DoT 全端口 512；DoH 每源 200 r/s，burst 200）
2. nginx → `adgh:53`：先查 AGH 本地缓存；命中即返回（此处**不**做 DNSSEC 判断）
3. 未命中 → AGH 唯一上游 → guard `5355`
4. guard 并行/对冲地问 A（境外，验签）与 alt；必要时用 verifier 做隔离验证
5. 采纳判定：`secure`（验签通过）＞ `accepted`（可信但未验签）；`bogus`/`transport` 不采纳
6. 交回 AGH → 客户端。答案的 TTL 由上游 RRset 剩余期限决定（guard 不改出口 TTL）

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
| 缓存是否可用 | `policy_version` + `schema` + 视图(DO/CD/ECS) + `evidence_until` + **名单代次** | 任一不符即丢弃（并计数 `adm_cache_gen_mismatch`） |
| stale 应答 | OPT EDE 3/19 | 允许单次出口，但**不写准入缓存、不延长 TTL** |
| 发布是否一致 | 两进程 `stats_meta.json` 的 `release_id`/`guard_sha256`/`verifier_proto` + 存活 + `/proc/<pid>/cwd` | 门禁退出码 1；握手不匹配直接拒绝执行查询 |

## 4. 组件职责

- `core/guard.py`：全部解析策略的唯一实现（准入缓存、共识与见证、名单、失败语义、指标）
- `core/verifier.py`：从 guard 导入模块但**独立进程**运行，通过 AF_UNIX 收任务、分池并发、有界等待
- `core/alt_adapter.py`：报文层工具（解析、应答绑定校验、UDP 交换、RRSIG/EDE 判定、逐 RR 老化、AD 位分档）
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
