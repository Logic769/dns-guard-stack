# 系统原理与模块详解

如果你希望从头理解 `dns-guard-stack` 每个组件为什么存在、一次查询在内部经过了哪些判断，以及各种名单和策略是如何配合的，可以参考这份指南。日常部署和命令速查请直接看 [`DEPLOY.md`](DEPLOY.md) 与 [`OPERATIONS.md`](OPERATIONS.md)。

---

## 1. 这套系统要解决什么问题？

自建 DNS 解析器通常有三个痛点：

1. **普通转发不防投毒**：上游返回什么就信什么，一旦上游被污染或路径被劫持，客户端就会拿到假 IP。
2. **纯境外递归导致国内 CDN 绕路**：全走 Cloudflare / Quad9 等境外 DNSSEC 上游虽然安全，但国内网站经常解析到海外或跨省节点，访问变慢。
3. **简单的国内外分流容易误放行**：社区域名名单并不完美，一旦某个境外域名或已被污染的域名被误判为"国内域名"，如果直接信任国内上游的结果，就会把假答案交给客户端。

`dns-guard-stack` 的做法是把**路由**和**信任**拆开：

* 境外或默认流量强制走本地 DNSSEC 验签，拿不到可信签名或核对不过就返回 `SERVFAIL`。
* 国内流量只代表"允许先问国内上游（以拿到就近 CDN 地址）"，但是否采纳国内上游的结果，还要经过**否决名单、特征检查、信任档位和境外存在性交叉见证**四道关卡。

---

## 2. 全链路数据流

```text
客户端 (DoT :853 / DoH :444)
  │
  ▼
AdGuard Home (adgh)
  │  · 终结公网 TLS，拿到客户端真实 IP
  │  · 注入 ECS /24（私有 IP 不注入）
  │  · 关闭自身缓存（避免多省结果串味）
  ▼  172.18.0.1:5300
dnsdist
  │  · 内网 ECS 感知 PacketCache (131,072 条, parseECS=true)
  │  · 单来源限速 (1000 qps / 10s)
  ▼  172.18.0.1:5355
guard (策略中枢) ◀──AF_UNIX──▶ verifier (独立核验侧车)
  │
  ├──▶ Unbound A (127.0.0.1:5353) ──▶ aghcf (1.1.1.1 裸IP + censurfridns) / aghdq2 (Quad9 DoQ)
  ├──▶ Unbound B (127.0.0.1:5354) ──▶ 国内 DoT (360 / 阿里 ×2, 开启 subnetcache 分片)
  └──▶ Unbound alt (127.0.0.1:5357) ──▶ 独立第三方 DoT (受 /run/unbound-alt-ready.json 门禁控制)
```

---

## 3. 各模块职责拆解

### 接入与缓存层

* **主 AdGuard Home (`adgh`)**：负责公网 `:853`（DoT）与 `:444`（DoH，容器内 `:443`）的 TLS 终结、广告/规则过滤，以及按客户端真实公网 IP 生成 `/24` ECS。`cache_enabled` 必须设为 `false`，因为 AGH 的内置缓存只按域名做键，会把 A 省用户的 ECS 答案返回给 B 省用户。
* **dnsdist**：在生产形态中退居内网 `172.18.0.1:5300`，承担全栈主缓存（`PacketCache` 开启 `parseECS=true`）与单源限速，只接受来自 `adgh` 的内网请求。
* **Nginx（legacy）**：2026-10-22 之前的旧入口；现在仅作无法安装 `dnsdist` 时的兜底方案，或用于 `:443` 复用反代及给看板提供 Basic Auth。

### 策略与核验层

* **`guard` (`core/guard.py`)**：整套策略的唯一实现。负责分流判定、上游并发/对冲调度、报文合法性校验、存在性见证、准入缓存管理与 fail-closed 兜底。
* **`verifier` (`core/verifier.py`)**：独立进程运行的核验侧车，通过 `/run/dnsguard/verifier.sock` 与 `guard` 通信，把耗时的交叉比对与隔离验证拆出主事件循环，避免拖慢常规查询。启动和握手时会强制校验双方 `release_id` 与代码哈希指纹，确保版本一致。
* **`alt_adapter` (`core/alt_adapter.py`)**：封装 DNS 报文编解码、UDP `connect()` 绑定、响应三元组与 RR 计数校验、OPT EDE 解析、逐 RR TTL 老化以及 AD 位可信度分级。
* **`answer_policy` (`core/answer_policy.py`)**：定义四类裁决结果——`SECURE`（本机 DNSSEC 验签通过）、`ACCEPTED`（来源可信或见证通过，但无本机验签）、`BOGUS`（DNSSEC 失败）与 `TRANSPORT`（传输超时或常规网络失败）。

### 上游解析与出口容器

* **Unbound A (`unbound`)**：境外主递归/转发器，强制开启本机 DNSSEC 验签且 `forward-first: no`（禁止在加密上游不可达时偷偷回退明文 UDP 53）。主上游为 `aghcf`，备上游为 `aghdq2`。
* **Unbound B (`unbound-b`)**：国内专用上游，转发至国内三家 DoT。配置中同时启用 `module-config: "subnetcache validator iterator"` 与 `client-subnet-always-forward: yes`，使不同省份客户端的 ECS 查询各自独立缓存、互不覆盖。
* **Unbound alt (`unbound-alt`)**：独立第三方 DoT 通道，主要参与交叉见证与备用兜底。由 `unbound-alt-readiness.timer` 每分钟检查 5 项健康与配置哈希，写入 `/run/unbound-alt-ready.json`（90 秒有效）；就绪文件过期或缺失时，`guard` 自动摘除 `alt` 通道。
* **出口容器 (`aghcf` / `aghdq2` / `aghdq`)**：
  * `aghcf`：并行请求 Cloudflare 裸 IP DoT（`tls://1.1.1.1`，不带 SNI 以抗按域名 SNI 阻断）与 `censurfridns`。同时充当国内域名的"存在性见证源"。
  * `aghdq2`：Quad9 DoQ（`quic://dns10.quad9.net`），兼作 `Unbound A` 备用上游与 `guard` 的独立 DoQ 救援通道。
  * `aghdq`：NextDNS DoQ，因上游握手长期阻塞已从主链路摘除。
* **影子通道 (`dnscrypt-proxy`)**：默认按 10% 采样率做影子查询对比，其结果不直接作为 DNSSEC 证据，也不影响主链路响应。

### 观测与防线

* **防火墙对账 (`firewall/`)**：使用 `iptables-restore` 单次原子替换规则，收紧容器 DNS 访问并封堵不被允许的明文 53 端口出站。
* **链路与指纹看板 (`dashboards/`)**：`chainmon` 每 60 秒抓取链路延迟与 `dnsdist` 缓存命中率；`devfp` 结合 `/join` 登记页与 `dotfront-spool` 采集的请求特征辅助识别接入设备（以持久 ID 为主锚点，JA4 仅作辅助，避免浏览器随机化 TLS 扩展造成误判）。两者均为只读，不参与解析决策。

---

## 4. 核心判定逻辑详解

### 1. 国内分流与信任分离

* **路由判定 `is_cn_domain()`**：读取 `cn-domains-typed.txt`（支持 `full:` 精确匹配与 `domain:` 域及子域匹配）。命中仅代表允许优先询问 `Unbound B`。
* **例外拦截 `cn-trust-exceptions.txt`**：最高优先级黑名单。命中的域名强制不走国内路径，即使它同时出现在其他国内名单里。
* **否决名单 `cn_veto.txt`**：包含已知实际位于境外的域名。`Unbound B` 返回的结果若命中否决名单或包含可疑特征（`suspicious`），直接拒绝采纳。
* **信任档位 `is_cn_trusted()`**：
  * `none`：最严格，所有国内结果都必须经过境外源交叉见证。
  * `known`（默认）：仅 `.cn` 等国别/品牌后缀及 `cn-trust-allow.txt` 人工白名单免见证，其余国内路由域名必须经过存在性见证。
  * `all`：全量免见证（不推荐）。

### 2. 存在性见证 (`cn_exist_veto`)

对于不在免见证集合中的国内域名，`guard` 在拿到 `Unbound B` 的候选答案后，会同时向境外见证源（`aghcf` / `alt`）核对：该域名在公网根区下是否真实存在（而非国内上游对不存在域名强行劫持返回广告或假 IP）。

* 见证确认存在且语义不冲突 → 放行 `Unbound B` 的就近 CDN 地址。
* 见证返回 `NXDOMAIN` 或核对冲突 → 否决 `B` 的答案，回退采用 `A` / `alt` 或返回 `SERVFAIL`。

### 3. DNSSEC 失败与传输失败区分

早期的粗粒度判断会把所有 `rcode=2` (`SERVFAIL`) 都当作 DNSSEC 验签失败，导致网络抖动时无法切换备用通道。现行策略严格检查报文中的 **OPT EDE (Extended DNS Error)**：

* 仅当 `EDE code = 15` 且 `value ∈ 6..12`（或本机明确检出签名失效）时，判定为 `BOGUS`（DNSSEC 失败），直接返回 `SERVFAIL`，绝不重试其他路径。
* 其余 `SERVFAIL` 归类为 `TRANSPORT`（传输或上游临时故障），允许 `guard` 调度备用路径修复。

### 4. 准入缓存与代次失效

`guard` 内部准入缓存的键由以下维度共同组成：

```text
(QNAME, QTYPE, QCLASS, DO位, CD位, ECS /24前缀, policy_version, schema, 名单代次)
```

* 缓存下发时执行**逐 RR 老化**：如果一条 300 秒的记录已在缓存中驻留 200 秒，下发给客户端的 TTL 会被精确裁剪为 100 秒，绝不重新放大 TTL。
* 当任何名单文件刷新或修改后，名单代次哈希发生变化，所有受影响的旧缓存条目会在下次匹配时立即失效（计入 `adm_cache_gen_mismatch`）。
* 针对无独立佐证的 fail-open 出口应答，TTL 统一压顶至 60 秒（`GUARD_FAILOPEN_TTL_CAP`），把潜在异常的自愈时间控制在分钟级。

---

## 5. 常用命令与数值速查

### 默认关键参数

| 参数 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `dnsdist` PacketCache | 131,072 条 | 开启 `parseECS=true`，单源限速 `1000 qps / 10s` |
| `guard` 并发 / 排队上限 | `96` / `96` | 可通过 `GUARD_MAX_INFLIGHT` / `MAX_PENDING` 调整 |
| 单次查询总预算 | `4.0 s` | `GUARD_QUERY_DEADLINE` |
| 准入缓存 TTL 上限 | `ACCEPTED ≤ 300s` / `SECURE ≤ 900s` | 实际下发取剩余寿命与上限的较小值 |
| `unbound-alt` 就绪有效期 | `90 s` | 由每分钟运行一次的 timer 刷新 |
| 历史名单保留周期 | `30 天` | `cnlist_history.py` 自动清理 |

### 高频排错命令

```bash
# 1. 全栈一键体检
sudo ./verify.sh

# 2. 对比单个域名在各层解析器的返回差异（排查污染或 CDN 调度）
python3 /opt/dnsguard/probes/probe-cand.py <域名>

# 3. 核对双进程版本指纹
python3 /opt/dnsguard/tools/release_consistency.py --json

# 4. 修改白名单或例外后强制刷新两级缓存
sudo /opt/dnsguard/tools/cn-trust-revoke.sh
sudo /opt/dnsguard/tools/agh-cache-clear.sh
```
