# 部署说明

本文档覆盖前置条件、`.env` 配置、`install.sh` 执行流程、证书接入、旧版环境适配与部署排障。

> **形态说明**：`install.sh` 目前部署的是 `dnsdist` 直接终结公网 853/444 TLS 的模板形态（防投毒与核心策略完整，但不包含按客户端 IP 注入 ECS 及按省分片缓存）。若需迁移为 `AdGuard Home` 入口 + 内网 `dnsdist` ECS 缓存形态，请对照 [`ARCHITECTURE.md` 第 8 节](ARCHITECTURE.md#8-生产实例与模板形态差异) 调整对应配置。

---

## 1. 前置条件

* **系统与权限**：Linux（Ubuntu 20.04+ / Debian 11+ / CentOS 7+ / Rocky 9 等），需具备 `systemd` 与 `root` 权限。
* **必要软件**：`docker`（含 `docker compose` 插件，支持 `up --wait`）、`dnsdist`、`python3 >= 3.6`、`git`、`iptables`、`openssl`、`curl`。仅在无法安装 `dnsdist` 时才需要 `nginx`（需同时支持 `http` 与 `stream` TLS）。
* **端口规划**：
  * 公网按需开放：`853/tcp`（DoT）、`444/tcp`（DoH，路径 `/dns-query`）；若需使用标准 `443` 端口或 ACME HTTP-01 签发，需额外预留 `443/tcp` / `80/tcp`。
  * 环回端口：`127.0.0.1:5199`（dnsdist 控制台）、`127.0.0.1:18083`（dnsdist 只读统计）以及各容器映射端口。

---

## 2. 安装步骤

### 第一步：准备配置

```bash
git clone https://github.com/Logic769/dns-guard-stack.git
cd dns-guard-stack
cp .env.example .env
```

编辑 `.env`，至少修改以下配置（管理账号密码也在 `.env` 中设置，勿提交至版本库）：

```ini
DNS_DOMAIN=dns.example.com
TLS_CERT=/absolute/path/to/fullchain.pem
TLS_KEY=/absolute/path/to/privkey.pem
LISTS_PROFILE=fetch
CN_TRUST_MODE=known
INSTALL_NGINX=0
```

### 第二步：预检与执行安装

```bash
# 预览将要写入的文件、容器配置与服务单元
sudo bash install.sh --dry-run

# 执行安装并拉取真实名单（脚本幂等，重复执行不会清空已有的白名单与看板数据）
sudo bash install.sh --fetch-lists
```

安装参数说明：
* `--dry-run`：仅输出检查与预览动作，不落盘（仍需存在可加载的 `.env`）。
* `--fetch-lists`：安装时联网下载真实分流、否决与国内 IP 名单；不加此参数且未配置环境变量时，仅生成最小骨架。
* `--skip-firewall`：跳过 `iptables` 规则应用，后续需自行配置并验收放行策略。

### 第三步：验收

```bash
sudo bash verify.sh --quick
sudo bash verify.sh
```

---

## 3. `.env` 关键变量说明

| 分类 | 变量 | 说明 |
| :--- | :--- | :--- |
| 域名与证书 | `DNS_DOMAIN`、`TLS_CERT`、`TLS_KEY` | 公网接入域名及对应 PEM 证书路径。脚本会读取本机证书并写入四份 AGH 配置（权限 `0600`）。 |
| 安装目录 | `CODE_DIR` (`/opt/dnsguard`)、`LISTS_DIR` (`/opt/dnscrypt-proxy`)、`CHAINMON_DIR`、`DEVFP_DIR`、`RUNTIME_DIR` | 代码、名单、看板与渲染配置的落盘位置。 |
| 网络与网段 | Docker 子网（默认 `172.18.0.0/16`，`alt` 副本 `10.99.0.0/24`） | 若与宿主现有网段冲突，需同步修改 `.env` 中的网段、网关 `GW_IP` 及各容器固定 IP。 |
| 上游设置 | `UPSTREAM_B` 等 | **注意**：当前 `install.sh` 仅读取并替换 `UPSTREAM_B`；`UPSTREAM_A_QUIC`、`UPSTREAM_A_BOOTSTRAP` 与 `UPSTREAM_ALT` 尚未接入渲染，修改这些上游需直接编辑 `deploy/` 对应模板。 |
| 名单与策略 | `LISTS_PROFILE` (`fetch` \| `minimal`)、`CN_TRUST_MODE` (`known`)、`CN_EXIST_MODE` (`enforce`) | 生产环境务必使用 `fetch` 拉取完整名单；`minimal` 仅生成骨架，缺失有效否决名单时 `guard` 可能拒绝启动。 |
| 内存限额 | `GUARD_MEMORY_MAX` (`192`)、`VERIFIER_MEMORY_MAX` (`128`)、`CHAINMON_MEMORY_MAX` (`256`)、`DEVFP_MEMORY_MAX` (`176`) | 单位 MiB，适用于小内存宿主机（≤2 GiB）的 systemd drop-in 限制。 |

---

## 4. `install.sh` 执行流程

1. 检查基础依赖、`python3` 版本与 `.env` 合法性。
2. 渲染模板至 `RUNTIME_DIR`（含容器配置、`dnsdist.conf`、legacy Nginx 片段）。
3. 复制核心代码与看板文件至目标目录。
4. 拉取或初始化域名/IP 名单；名单就绪时自动初始化 `releases/` + `current` 发布布局。
5. 启动 Docker Compose 容器组，并将主 `adgh` 上游锁定为 `guard`。
6. 写入证书至容器配置目录（当前未实现自动 ACME 签发/续期，需外部签发好再填入路径）。
7. 安装 `/etc/dnsdist/dnsdist.conf` 并校验语法，启用日志轮转。
8. 安装并启动 `dnsguard`、`dnsguard-verifier`、`unbound-alt-readiness.timer`、`cgroup-memsw-limits` 等 systemd 单元（看板 `chainmon` / `devfp` 仅复制文件，需按需手动启用并配置鉴权）。
9. 应用 `iptables` 防火墙规则（除非传入 `--skip-firewall`）。
10. 运行发布一致性门禁与基础探针检查。

---

## 5. 入口校验与特殊环境适配

### 校验 `dnsdist`（默认模板入口）

```bash
sudo dnsdist --check-config -C /etc/dnsdist/dnsdist.conf
sudo systemctl status dnsdist
```

### 退回 legacy Nginx（仅当机器无法运行 `dnsdist` 时）

1. 停用 `dnsdist` 以释放 `853` / `444` 端口。
2. 在 `.env` 中设置 `INSTALL_NGINX=1`，将生成的 DoT 片段放入 `stream` 上下文、DoH 片段放入 `http` 上下文（默认按宝塔目录习惯生成，其他环境按实际 `conf.d` 路径调整）。
3. 执行 `sudo nginx -t` 校验无误后重载 Nginx。

### 自签证书与已有站点反代

* **自签证书**：仅适合客户端已手动导入根证书的测试环境；普通公网客户端（如 Android 私人 DNS）会拒绝连接。
* **复用已有 `443` 端口**：在现有 HTTPS 站点的 `server` 块中将 `/dns-query` 反代至 DoH 后端，同时确保管理 UI 端口（`3000` / `13000` 等）仅监听 `127.0.0.1` 并通过 SSH 隧道访问。

---

## 6. 常见部署问题

| 现象 | 排查方向 |
| :--- | :--- |
| 安装后 `guard` 反复重启 | 查看 `/var/log/dnsguard.log`，常见原因为未使用 `--fetch-lists` 导致缺乏有效 `cn_veto.txt`、状态目录权限异常。 |
| `verify.sh` 提示 DoT/DoH 警告 | 检查云防火墙/安全组是否放行 `853/444`、证书域名与 `DNS_DOMAIN` 是否一致、以及 `adgh` / `dnsdist` 监听状态。 |
| Docker 网段与内网冲突 | 修改 `.env` 中的网段与容器 IP 后重新运行 `install.sh`，并用 `firewall/dnsguard-ip-reconcile.sh --check` 核对规则。 |
| 看板安装后无法访问或无数据 | 安装脚本不自动拉起 `chainmon` / `devfp`，需手动启用对应 systemd 服务并核对 Basic Auth 与 `stats.json` / 日志路径；不要仅因 `.env` 填了 `DASH_PASSWORD` 就认为鉴权已自动开启。 |
