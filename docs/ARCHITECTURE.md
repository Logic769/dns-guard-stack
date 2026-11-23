# 系统架构说明

本文档说明 `dns-guard-stack` 的分层结构、单次查询的数据流、核心判定逻辑、状态文件与环境变量，以及当前生产实例与仓库默认模板之间的差异。

---

## 1. 分层与监听端口

| 层级 | 组件 | 监听地址与端口 | 职责说明 |
| :--- | :--- | :--- | :--- |
| 公网入口 | `adgh` (AdGuard Home 容器) | `0.0.0.0:853` (DoT) → `853`<br>`0.0.0.0:444` (DoH) → `443`<br>`127.0.0.1:3000` (UI) / `4443` / `8854` | 终结公网 TLS、执行过滤规则、按客户端真实 IP 注入 ECS `/24`。**必须关闭自身 DNS 缓存**（AGH 缓存不按 ECS 分片）。 |
| 内网缓存层 | `dnsdist` (systemd) | `172.18.0.1:5300` (UDP/TCP)<br>`127.0.0.1:5199` (控制台)<br>`127.0.0.1:18083` (只读统计) | ECS 感知的 PacketCache（131,072 条，`parseECS=true`）与单来源限速（1000 qps / 10s）；唯一上游为 `guard`。 |
| 入口 (legacy) | `nginx` (宿主) | `853/tcp`, `443/tcp`, `444/tcp` | 2026-10-22 之前的旧入口；仅在无法运行 `dnsdist` 时作退路，或用于 `:443` 反代至 `adgh:4443`。 |
| 策略中枢 | `guard` (systemd) | `172.18.0.1:5355` (UDP/TCP)<br>`172.18.0.1:5356` (UDP 探针) | 路由判定、候选获取、交叉见证、否决检查、准入缓存与失败语义控制。 |
| 独立核验 | `verifier` (systemd) | `/run/dnsguard/verifier.sock` (AF_UNIX) | 独立进程运行，通过 Unix socket 接收交叉验证任务，隔离慢查询。 |
| 境外上游 (A) | `unbound` (容器) | `127.0.0.1:5353`, `172.18.0.1:5353` | 本机 DNSSEC 验签，`forward-first: no`（fail-closed），`num-threads: 8`。上游为 `aghcf`（主）与 `aghdq2`（备）。 |
| 国内上游 (B) | `unbound-b` (容器) | `127.0.0.1:5354`, `172.18.0.1:5354` | 转发至三家国内 DoT（`dot.360.cn`、`dns.alidns.com` ×2）。开启 `subnetcache validator iterator` 与 `client-subnet-always-forward: yes`，`num-threads: 16`。 |
| 备用上游 (alt) | `unbound-alt` (容器) | `127.0.0.1:5357` | 独立第三方 DoT，参与交叉见证与受就绪门禁控制的备用解析。 |
| 演练副本 | `alt-replica-unb` (容器) | `127.0.0.1:15353` (`10.99.0.0/24`) | 独立网络中的 `alt` 副本，仅用于灰度与演练，不参与主链路。 |
| 出口容器 | `aghcf` | `127.0.0.1:5535` | Parallel 双上游：`tls://1.1.1.1`（裸 IP 无 SNI）+ `tls://unicast.censurfridns.dk`。`unbound` 主上游兼国内域名存在性见证源。 |
| 出口容器 | `aghdq2` | `127.0.0.1:5534` | Quad9 DoQ（`quic://dns10.quad9.net`）。`unbound` 备用上游，同时作 `guard` 认证救援通道（`GUARD_ALT_ADDR` / `GUARD_DOQ_PORT`）。 |
| 出口容器 | `aghdq` | `127.0.0.1:5533` | NextDNS DoQ（`quic://dns.nextdns.io`）。因上游握手长期阻塞，已从 `unbound` 摘除，容器保留待修。 |
| 影子通道 | `dnscrypt-proxy` (容器) | `127.0.0.1:5399` | 供 `guard` 做影子对比采样（`GUARD_SHADOW_*`）。 |
| 观测看板 | `chainmon` / `devfp` | `127.0.0.1:8787` / `:8789` | 只读链路统计与设备指纹看板，经 Nginx Basic Auth 暴露，不参与解析决策。 |

### 网络与 IP 说明

* **模板形态**：容器全部位于 Compose 自定义网络 `dnsnet`（默认 `172.18.0.0/16`），使用静态 IP（`adgh=.2`、`unbound=.4`、`unbound-b=.5`、`aghdq=.6`、`unbound-alt=.8`、`dnscrypt=.9`、`aghdq2=.11`、`aghcf=.12`），`guard` 监听网关 `172.18.0.1`。
* **生产实例**：容器运行在默认桥接网络上未固定 IP，重启后可能漂移（如 `aghcf`、 `unbound-b` 等）。生产侧通过 `dnsguard-ip-reconcile.timer`（每 5 分钟）与 `dnsguard-fw-reconcile.timer`（每 6 分钟）自动收敛下游引用与 `iptables` 规则。修改 `.env` 网段后需重跑 `install.sh` 并执行 `firewall/dnsguard-ip-reconcile.sh --check`。

---

## 2. 一次查询的数据流

### 境外域名（例如 `www.google.com`）

1. **接入与 ECS 注入**：客户端通过 DoT（`:853`）或 DoH（`:444`）连入 `adgh`。`adgh` 终结 TLS，获取客户端真实公网 IP 并注入 ECS `/24`（私有/保留地址不注入），跳过自身缓存后转发至 `dnsdist`（`172.18.0.1:5300`）。
2. **ECS 缓存查找**：`dnsdist` 开启 `parseECS=true`，按域名 + `/24` ECS 查找 PacketCache；命中则直接返回，未命中转发给 `guard`（`172.18.0.1:5355`）。
3. **并行解析与核验**：`guard` 并行或对冲查询 `Unbound A`（本机 DNSSEC 验签）与 `alt`，必要时交由 `verifier` 在独立进程中核对。
4. **采纳与缓存**：优先级为 `SECURE`（本机验签通过）> `ACCEPTED`（可信但未签名）；`BOGUS` 与 `TRANSPORT` 不采纳。无独立佐证的 fail-open 出口 TTL 统一压至 60 秒（`GUARD_FAILOPEN_TTL_CAP`），缩短污染自愈窗口。

### 国内域名（例如 `www.qq.com`）

1. 步骤 1–2 同上（`adgh` → `dnsdist` → `guard`）。
2. **路由判定**：`is_cn_domain(name)` 为真，优先向 `Unbound B` 发起查询（`Unbound B` 按 ECS `/24` 转发并分片缓存，以匹配客户端所在省份的国内 CDN）。
3. **安全检查与见证**：
   * 命中 `cn_veto.txt` 或响应特征可疑（`suspicious`）→ 拒绝采纳。
   * 命中 `is_cn_trusted(name)`（默认为国别后缀或 `cn-trust-allow.txt` 白名单）→ 免存在性见证直接采纳。
   * 其余国内域名 → 通过 `A` / `alt` 交叉见证（`cn_exist_veto`），确认存在且一致后采纳，否则回退至 `A` / `alt` 或返回 `SERVFAIL`。
4. **写入准入缓存**：`ACCEPTED` 上限 300 秒、`SECURE` 上限 900 秒，缓存条目绑定当前名单代次，名单变更即自动失效。

### 名单缺失时的降级行为

* **`cn-domains-typed.txt` 缺失**：尝试读取同目录快照；仍失败则一律判为非国内域名（绝不扩大国内路由范围）。
* **`cn_veto.txt` 缺失**：依次尝试 live 快照 → 发布目录快照；全部失败则一律否决国内答案。
* **`cn-trust-allow.txt` 缺失**：视为空集（所有国内域名均须经过存在性见证）。

---

## 3. 核心判定依据

| 判定项 | 检查依据 | 失败 / 异常行为 |
| :--- | :--- | :--- |
| 报文归属 | ID / QR / opcode / QDCOUNT、`QNAME+QTYPE+QCLASS` 三元组、各段 RR 计数、报文尾长 | 丢弃并有界重收，超时则判失败 |
| 对端来源 | UDP `connect()` 绑定对端；`AF_UNIX` 校验对端凭证 | 直接丢弃 |
| DNSSEC 投毒 | 本机验签结果 + OPT EDE（仅 `code=15` 且 `value ∈ 6..12` 判定为 DNSSEC 失败） | 普通 `SERVFAIL` 视为传输故障，允许备用通道修复 |
| 国内免见证 | `is_cn_trusted()`：例外清单 → 路由判国内 → 信任档位 → 国别后缀 → 人工白名单 | 宁严不宽，无语义自动扩展 |
| 存在性见证 | `B` 的应答与 `A` / `alt` 或签名证据是否一致 | 回退 `A` / `alt`；仍失败则返回 `SERVFAIL` |
| 准入缓存有效性 | `policy_version` + `schema` + 查询视图（DO/CD/ECS `/24`）+ `evidence_until` + 名单代次 | 任一字段不匹配即失效（计入 `adm_cache_gen_mismatch`） |
| Stale 应答 | OPT EDE `3` / `19` | 允许单次下发，但不写入准入缓存、不延长 TTL |
| 双进程一致性 | `guard` 与 `verifier` 的 `release_id`、`guard_sha256`、`verifier_proto`、进程存活及 `/proc/<pid>/cwd` | 门禁退出码 1；握手不匹配拒绝执行查询 |

---

## 4. 模块职责

* `core/guard.py`：解析策略的唯一实现（准入缓存、共识与见证、名单加载、失败语义、运行指标）。
* `core/verifier.py`：复用 `guard` 模块逻辑的独立进程，通过 `/run/dnsguard/verifier.sock` 分池并发处理核验请求。
* `core/alt_adapter.py`：底层报文工具（编解码、应答绑定校验、UDP 收发、RRSIG/EDE 解析、逐 RR 老化、AD 位分级）。
* `core/unbound-alt-readiness.py`：安装于 `/usr/local/sbin`，每分钟探测 5 项指标并绑定容器身份与配置哈希，写入 `/run/unbound-alt-ready.json`（有效期 90 秒）。
* `core/answer_policy.py`：定义 `SECURE` / `ACCEPTED` / `BOGUS` / `TRANSPORT` 档位及策略版本号。
* `tools/*`：名单刷新与 GPG 归档验签、原子发布与回滚、全量快照、缓存撤回及 DoT 内腿采集（`dotfront-spool.py`）。
* `firewall/*`：根据当前容器 IP 计算目标规则并自检，通过单次 `iptables-restore` 原子替换规则（失败自动回滚）。
* `dashboards/*`：`chainmon` 与 `devfp`，只读观测组件。

---

## 5. 关键状态与名单文件

| 路径 | 作用 |
| :--- | :--- |
| `<CODE_DIR>/stats.json` | `guard` 实时统计（名单条目、见证计数、缓存命中/失效、fail-closed 分支） |
| `<CODE_DIR>/stats_meta.json` | `guard` 发布指纹（`release_id` / `sha` / `policy` / `proto` / `pid`） |
| `<CODE_DIR>/verifier-state/stats_meta.json` | `verifier` 发布指纹 |
| `<LISTS_DIR>/cn-domains-typed.txt` | 类型化国内域名名单（`full:` 精确匹配 / `domain:` 自身及子域） |
| `<LISTS_DIR>/forwarding-rules.txt` | 同源生成的扁平格式名单，供 `dnscrypt-proxy` 使用 |
| `<LISTS_DIR>/cn_veto.txt` | 否决名单（实际位于境外的域名） |
| `<LISTS_DIR>/cn_ip.txt` | 国内 IP 段，用于判断应答地址归属 |
| `<LISTS_DIR>/cn-trust-allow.txt` | 人工白名单（命中的国内域名免见证） |
| `<LISTS_DIR>/cn-trust-exceptions.txt` | 强制例外名单（不走国内路径、不信任） |
| `<CODE_DIR>/cn-list-history/` | 名单变更归档、`MANIFEST.sha256` 及 GPG 签名 |
| `/run/unbound-alt-ready.json` | `alt` 就绪状态文件；过期或缺失时 `guard` 自动关闭 `alt` 通道 |

---

## 6. 核心环境变量

完整列表见 `deploy/systemd/dnsguard.service.d/zzzzzz-consolidated-20261010.conf`。

| 变量 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `GUARD_CN_DOMESTIC_PRIMARY` | `1` | 允许国内域名优先走 `Unbound B` |
| `GUARD_CN_DOMESTIC_TRUST_B` | `1` | 允许可信集合内的国内应答免见证 |
| `GUARD_CN_TRUST_MODE` | `known` | `none`（全部见证）/ `known`（国别后缀 + 白名单免见证）/ `all`（全部免见证，不推荐） |
| `GUARD_CN_EXIST_MODE` | `enforce` | 是否启用存在性交叉见证 |
| `GUARD_MAX_INFLIGHT` / `MAX_PENDING` | `96` / `96` | 并发与排队上限 |
| `GUARD_QUERY_DEADLINE` | `4.0` | 单次查询总超时预算（秒） |
| `GUARD_SHADOW_DNSCRYPT` / `SHADOW_PCT` | `127.0.0.1:5399` / `10` | 影子对比通道与采样百分比 |

---

## 7. 架构图维护

交互式架构图源码位于 `docs/assets/architecture.archify.json`。修改节点或连线后，使用 `archify` 重新生成 HTML 与浅/深色 PNG（勿直接手改生成的 HTML）：

```bash
node <archify 包>/bin/archify.mjs finalize architecture \
  docs/assets/architecture.archify.json docs/assets/architecture.html \
  --quality showcase --json
```

---

## 8. 生产实例与模板形态差异

`deploy/` 与 `docker-compose.yml` 目前保留 `dnsdist` 直面公网 TLS（853/444）的模板形态，而生产实例自 2026-10-28 起已切换为 `AdGuard Home (adgh)` 入口 + ECS 分片缓存形态。两者差异及原因如下：

| 对比项 | 仓库模板（`deploy/`） | 生产实例（2026-10-28） | 变更原因 |
| :--- | :--- | :--- | :--- |
| 公网 TLS 入口 | `dnsdist` (`addTLSLocal` / `addDOHLocal`) | `adgh` 容器 (`0.0.0.0:853`、`0.0.0.0:444->443`) | 实测 `dnsdist 2.1.3` 的 `SetECSAction` 四种写法均未能向下游写入 ECS option，只有 `adgh` 能按客户端真实 IP 注入 `/24` ECS。 |
| `dnsdist` 监听与 ACL | 公网 `0.0.0.0:853` / `444`，全网 ACL | 内网 `172.18.0.1:5300`，仅内网网段 ACL | `dnsdist` 退为纯粹的 ECS 感知缓存层，公网不直接触达。 |
| `adgh` 端口与缓存 | 仅环回管理端口；`cache_enabled: true` | 暴露 `853` / `444`；`cache_enabled: false` | `adgh` 缓存为域名单键，会导致 A 省结果串给 B 省；DoH 需映射 `:444` 以配合 `devfp` 按端口区分流量来源（`:443` 会被混入普通 HTTPS）。 |
| `adgh` ECS 配置 | `edns_client_subnet.enabled: false` | `enabled: true`，`custom_ip` 留空 | `custom_ip` 留空才会按客户端真实 IP 自动生成 `/24`；填固定 IP 会使多用户失去分省调度效果。 |
| `unbound-b` 配置 | 未开启 ECS 模块 | `module-config: "subnetcache validator iterator"` + `client-subnet-always-forward: yes` | 必须同时开启转发与分片缓存，否则不同省份的 CDN 结果会互相覆盖。 |
| 容器 IP 分配 | Compose 静态 `ipv4_address` | 默认 bridge 动态分配 | 生产容器非 Compose 拉起，依赖宿主机定时任务动态收敛。 |

生产实例额外运行的 4 个自动收敛单元（暂未合入 `deploy/`）：

* `dnsguard-ip-reconcile.timer`（5 min）：将 `unbound` 第一条 `forward-addr`、`adgh` 上游、`guard` 监听及探针目标地址收敛到当前 Docker 容器实际 IP。
* `agh-watchdog.timer`（60 s）：校验 `dnsdist` 上游 IP，并在内存超阈值且三级 DNS 探测（`dig` 退出码 + `status:` + 非空 `A` 记录）同时失败时重启容器。
* `dns-channel-selfheal.timer`（60 s）：当境外上游恢复但 `unbound` 负缓存仍残留 `SERVFAIL` 时自动执行 `flush_negative` + `flush_bogus`（双上游均不通时不触发）。
* `dnsguard-fw-reconcile.timer`（6 min）：容器 IP 漂移后原子重建 `DOCKER-USER` / `INPUT` 规则。
