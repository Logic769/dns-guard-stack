# dns-guard-stack

自建抗投毒 DNS 解析栈：全加密上游、本机 DNSSEC 验签、国内分流与信任分离、多源交叉见证。

本项目将 **AdGuard Home**、**dnsdist**、**Unbound**、**DNSCrypt** 与自研策略层 **guard / verifier** 组合在一台 Linux 主机上，对公网提供 DoT（`:853`）与 DoH（`:444`）服务。核心目标很简单：**不无条件信任任何单一上游**——境外流量强制本机 DNSSEC 验签，国内流量只在路由层分流，非国别后缀或白名单域名必须经境外源存在性核对后才放行。

---

## 架构概览

> 交互式架构图位于 [`docs/assets/architecture.html`](docs/assets/architecture.html)（克隆仓库后用浏览器打开，支持深浅主题切换、路径高亮与导出），静态预览图见同目录下的浅色 / 深色 PNG。

```text
客户端 (DoT :853 / DoH :444)
  │
  ▼
主 AdGuard Home (adgh)
  │  TLS 终结 · 规则过滤 · 按客户端公网 IP 注入 ECS /24（关闭自身缓存）
  ▼  UDP 172.18.0.1:5300
dnsdist
  │  内网 ECS 感知 PacketCache (131,072 条, parseECS=true) · 单来源限速
  ▼  UDP 172.18.0.1:5355
guard (策略中枢) ──▶ verifier (AF_UNIX 独立核验进程)
  │
  ├── 境外 / 默认路径 ──▶ Unbound A (本机 DNSSEC, fail-closed)
  │                        ├── 主: aghcf (1.1.1.1 裸 IP DoT + censurfridns)
  │                        └── 备: aghdq2 (Quad9 DoQ)
  │
  ├── 国内分流路径   ──▶ Unbound B (开启 subnetcache 按 ECS 分片)
  │                        └── 三家国内 DoT (360 / 阿里 ×2)
  │
  ├── 备用 / 见证    ──▶ Unbound alt (受就绪门禁控制) & aghdq2 (DoQ 救援)
  │
  └── 旁路观测       ──▶ DNSCrypt 影子采样 · Chainmon (:8787) · devfp (:8789)
```

### 为什么这么分层？

* **ECS 注入与缓存分离**：国内 CDN 依赖 EDNS Client Subnet（ECS）按省份就近调度。主 `adgh` 负责按客户端真实 IP 注入 `/24` ECS 并关闭自身缓存（AGH 缓存不按 ECS 分片，多用户会串省）；缓存下沉到 `dnsdist`（`parseECS=true`）和 `guard` 准入缓存。
* **路由与信任分离**：`is_cn_domain()` 只决定"能不能问国内上游"，不代表国内上游的答案直接可信。默认 `CN_TRUST_MODE=known` 下，只有 `.cn` 等国别后缀和人工白名单免见证，其余命中国内名单的域名仍需经 `aghcf` / `alt` 交叉确认存在性，防止把不存在或被污染的域名放行给客户端。
* **Fail-Closed**：`Unbound A` 关闭 `forward-first`，验签失败或无合格候选时宁可返回 `SERVFAIL`，也不回退明文递归；主 `adgh` 不设置绕过 `guard` 的备用上游。

> **关于部署形态的说明**：仓库中 `install.sh` 与 `deploy/` 模板目前渲染的是 `dnsdist` 直接终结公网 853/444 的经典形态；上方架构图展示的是 2026-10-28 迁入 `adgh` 入口 + ECS 分片的生产形态。两种形态的核心防护逻辑一致，具体配置差异与原因见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#8-生产实例与模板形态差异)。

---

## 快速开始

### 环境要求

* **系统**：Linux（需 `systemd` 与 `root` 权限）
* **运行时**：Docker + Docker Compose 插件（支持 `up --wait`）、`python3 >= 3.6`
* **组件**：`dnsdist`（缺失时 `install.sh` 会警告并可退回 legacy Nginx 入口）、`iptables`、`openssl`、`curl`
* **域名与证书**：自备解析到本机的域名及匹配的 TLS 证书

### 1. 克隆并配置 `.env`

```bash
git clone https://github.com/Logic769/dns-guard-stack.git
cd dns-guard-stack
cp .env.example .env
```

编辑 `.env`，至少替换以下关键项（切勿将含密码或私钥路径的 `.env` 提交到仓库）：

```ini
DNS_DOMAIN=dns.example.com
TLS_CERT=/absolute/path/to/fullchain.pem
TLS_KEY=/absolute/path/to/privkey.pem
LISTS_PROFILE=fetch
CN_TRUST_MODE=known
INSTALL_NGINX=0
```

### 2. 预检与安装

```bash
# 先预览安装动作，确认网段、端口与路径无冲突
sudo bash install.sh --dry-run

# 正式安装并拉取真实分流/否决名单
sudo bash install.sh --fetch-lists
```

常用参数：`--dry-run`（仅预览）、`--fetch-lists`（拉取真实名单，不加则仅生成骨架）、`--skip-firewall`（跳过 `iptables` 规则应用）。

> **安装脚本当前限制**：`install.sh` 目前只将 `.env` 中的 `UPSTREAM_B` 写入模板，`UPSTREAM_A_QUIC`、`UPSTREAM_A_BOOTSTRAP` 与 `UPSTREAM_ALT` 需直接修改 `deploy/containers/` 或 `deploy/` 对应模板；ACME 自动续期与看板（`chainmon` / `devfp`）默认不自动启用，详见 [`docs/DEPLOY.md`](docs/DEPLOY.md)。

### 3. 验收

```bash
# 快速状态检查
sudo bash verify.sh --quick

# 完整链路与 DNSSEC 探针验收
sudo bash verify.sh
```

验收通过后，在客户端填入你的服务地址：

* **Android 私人 DNS**：`dns.example.com`
* **DoT 客户端**：`tls://dns.example.com:853`
* **DoH 客户端**：`https://dns.example.com:444/dns-query`（若经已有 HTTPS 站点反代 `:443`，则为 `https://dns.example.com/dns-query`）

---

## 常用运维速查

```bash
# 查看核心服务与容器状态
systemctl is-active dnsguard dnsguard-verifier dnsdist
docker compose ps

# 查看运行日志（guard 主日志在 /var/log/dnsguard.log）
tail -n 80 /var/log/dnsguard.log
journalctl -u dnsguard -u dnsguard-verifier -n 50 --no-pager

# 刷新分流/否决名单并校验归档签名
sudo bash /opt/dnsguard/tools/refresh-all-cn-lists.sh
python3 /opt/dnsguard/tools/verify-cn-lists.py

# 若修改了白名单或例外名单，触发两级缓存失效
sudo bash /opt/dnsguard/tools/cn-trust-revoke.sh

# 运行离线单元测试（可指定目标环境 Python 版本）
PYTHON=python3.6 bash tests/run.sh
```

---

## 仓库结构与文档索引

| 目录 / 文档 | 说明 |
| :--- | :--- |
| `core/` | 解析核心 `guard.py`、独立核验进程 `verifier.py`、报文适配与就绪检查 |
| `deploy/` | Docker 容器配置模板、`dnsdist` / `systemd` 单元、宿主辅助脚本与 legacy Nginx 片段 |
| `tools/` | 名单刷新与 GPG 归档校验、发布门禁与回滚、快照与缓存撤回脚本 |
| `probes/` | 公网入口探针、五层链路探针、单域名候选对比工具 |
| `firewall/` | 容器地址对账与原子化 `iptables` 规则生成 |
| `dashboards/` | 链路监控看板 `chainmon` 与设备指纹看板 `devfp` |
| `tests/` | 离线回归测试套件 |

详细文档：

* [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — 分层设计、查询流程、判定依据、环境变量与生产形态差异
* [`docs/DEPLOY.md`](docs/DEPLOY.md) — 完整前置要求、`.env` 参数说明、证书接入与安装排障
* [`docs/OPERATIONS.md`](docs/OPERATIONS.md) — 日常检查、名单维护、发布回滚、内存限额与故障处置
* [`docs/SECURITY.md`](docs/SECURITY.md) — 威胁模型、信任边界、历史缺陷修复与安全验证
* [`docs/MIGRATION.md`](docs/MIGRATION.md) — 整机迁移、更换域名/网段/上游与发布布局迁移
* [`docs/DNS-SYSTEM-GUIDE.md`](docs/DNS-SYSTEM-GUIDE.md) — 从零理解整套解析栈的模块拆解与判定细节
* [`docs/LOADTEST-2026-10-17.md`](docs/LOADTEST-2026-10-17.md) — 历史压测记录与 `verifier` 保活优化数据（旧版 Nginx 入口架构）

---

## 许可证

本仓库自研代码采用 [MIT License](LICENSE)。AdGuard Home、Unbound、DNSCrypt、外部域名名单及架构页内嵌字体等第三方组件遵循其各自许可证。
