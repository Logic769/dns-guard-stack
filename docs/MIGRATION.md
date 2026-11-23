# 迁移与重建说明

本文档说明如何将 `dns-guard-stack` 迁移到新主机、变更域名/网段/上游，以及如何从早期平铺安装迁移到可回滚的发布布局。

---

## 1. 迁移到新主机

### 旧机导出（只读操作）

1. 生成运行状态与配置快照：

```bash
sudo /opt/dnsguard/tools/make-snapshot.sh
```

2. 打包需要保留的数据：
   * `/opt/dnsguard/cn-list-history`（名单历史归档与 GPG 签名）
   * `/opt/dnscrypt-proxy/cn-trust-allow.txt` 与 `cn-trust-exceptions.txt`（人工白名单与例外）
   * `/opt/chainmon`、`/opt/devfp`（看板数据库，如需保留历史统计）
   * `/etc/dnsguard`（含 `agh-api.env` 等凭据文件）

### 新机重建

1. 克隆仓库并填写 `.env`，将域名与证书路径指向新机配置。
2. 执行基础安装与验收：

```bash
sudo bash install.sh --fetch-lists
sudo bash verify.sh
```

3. 导入旧机打包的 `cn-trust-*.txt`，随后运行刷新与缓存撤回以同步名单代次：

```bash
sudo bash /opt/dnsguard/tools/refresh-all-cn-lists.sh
sudo bash /opt/dnsguard/tools/cn-trust-revoke.sh
```

4. 按需恢复看板数据与 `/etc/dnsguard/agh-api.env`（确保权限为 `0600`）。
5. 切换客户端或路由器 DNS 指向新机；建议保留旧机运行 24 小时以便随时回退。

---

## 2. 变更域名、网段与上游

### 更换域名或证书

修改 `.env` 中的 `DNS_DOMAIN`、`TLS_CERT` 与 `TLS_KEY`，重新运行 `sudo bash install.sh` 与 `sudo bash verify.sh`，并同步更新客户端的 DoT SNI 与 DoH URL。

### 更换 Docker 网段或容器 IP

1. 修改 `.env` 中的网段与各容器固定 IP 后，重跑 `sudo bash install.sh`。
2. 执行 `firewall/dnsguard-ip-reconcile.sh --check` 检查 6 处 IP 引用是否一致。
3. **注意**：`dnsguard-ip-reconcile.sh` 不会自动修改 `/etc/dnsdist/dnsdist.conf` 中的上游地址，更换网关或 `guard` 监听 IP 后需重跑 `install.sh` 或手动更新配置并重启 `dnsdist`。

### 更换上游解析器

| 上游角色 | 对应模板 / 配置方式 |
| :--- | :--- |
| 境外主出口 (`aghcf`) | `deploy/containers/aghcf.AdGuardHome.yaml.tpl` |
| 境外备用 DoQ (`aghdq2`) | `deploy/containers/aghdq2.AdGuardHome.yaml.tpl` |
| 国内上游 (`unbound-b`) | `deploy/containers/unbound-b.conf.tpl`（由 `.env` 的 `UPSTREAM_B` 渲染） |
| 第三方备用 (`unbound-alt`) | `deploy/containers/unbound-alt.conf.tpl` |

> 当前 `install.sh` 仅自动替换 `UPSTREAM_B`；`UPSTREAM_A_QUIC` 与 `UPSTREAM_ALT` 需直接修改上述对应模板文件。

---

## 3. 季度整机重建演练

建议每季度在干净的测试环境演练一次完整重建，重点验证：

1. `release_consistency.py` 返回 `0`。
2. `dnssec-failed.org` 稳定返回 `SERVFAIL`，`cloudflare.com` 返回 `NOERROR` 且带 `ad=1`。
3. `probes/dns-entry-probe.py` 与 `probes/dns-chain-probe.py` 全项通过。
4. 执行 `deploy_release.sh --rollback <release-id>` 验证版本回滚链路可用。

### 重建后必然发生变化的项目

以下内容不会（也不应）与旧机保持一致：Docker 动态分配的容器 IP 与网桥地址、冷启动内存缓存、看板实时序列、自签证书指纹以及新拉取的外部名单版本。

---

## 4. 从平铺安装迁移至 `releases/ + current` 布局

早期平铺安装将文件直接放在 `/opt/dnsguard` 下，无法直接进行原子回滚。`install.sh` 在名单就绪时会自动完成迁移；若此前跳过了该步骤，可手动补齐：

```bash
# 创建发布目录、改写 systemd unit 指向 $CODE_DIR/current/ 并切换软链
sudo /opt/dnsguard/tools/make-release.sh --migrate-units

# 验收门禁与整体状态
python3 /opt/dnsguard/tools/release_consistency.py
python3 /opt/dnsguard/tools/verify-release-data.py
sudo bash verify.sh
```

脚本会自动备份原有的 systemd 单元文件，迁移后即可使用 `deploy_release.sh` 进行标准升级与回滚。
