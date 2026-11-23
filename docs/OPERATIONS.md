# 运维手册

以下路径均以 `.env` 默认值为准：`CODE_DIR=/opt/dnsguard`、`LISTS_DIR=/opt/dnscrypt-proxy`、`CHAINMON_DIR=/opt/chainmon`、`DEVFP_DIR=/opt/devfp`。

---

## 1. 一键健康检查

```bash
sudo ./verify.sh
```

脚本依次检查：容器状态、systemd 服务、`guard` 监听、双进程发布一致性、名单完整性、DoT/DoH 三入口探针、五层链路探针、DNSSEC 正反样本、日志异常堆栈以及宿主内存，最终输出 `RESULT: OK` 或具体失败项。

单项排查命令：

```bash
docker ps --format '{{.Names}}\t{{.Status}}'
systemctl status dnsguard dnsguard-verifier adgh 2>/dev/null | head -40
python3 $CODE_DIR/tools/release_consistency.py --json | head -30
python3 $CODE_DIR/tools/verify-cn-lists.py
python3 $CODE_DIR/probes/dns-entry-probe.py
python3 $CODE_DIR/probes/dns-chain-probe.py
```

---

## 2. 服务与容器操作

```bash
# 重启策略层（必须同时重启，单独重启会触发发布一致性门禁告警）
sudo systemctl restart dnsguard dnsguard-verifier

# 仅重启国内上游或主入口容器
sudo systemctl restart unbound-b
docker restart adgh

# 查看日志与定时任务
tail -n 80 /var/log/dnsguard.log
journalctl -u dnsguard -u dnsguard-verifier -n 80 --no-pager
systemctl list-timers | grep dnsguard
```

---

## 3. 名单维护与缓存撤回

### 刷新上游名单

```bash
# 下载、校验、原子替换并归档（自动生成 SHA256 与 GPG 签名）
sudo $CODE_DIR/tools/refresh-all-cn-lists.sh
tail -n 5 /var/log/cn-lists-refresh.log

# 仅预览变更，不落盘
sudo python3 $CODE_DIR/tools/refresh-cn-rules.py --dry-run
sudo python3 $CODE_DIR/tools/refresh-cn-veto-ip.py --dry-run

# 校验归档完整性
ls -lt $CODE_DIR/cn-list-history/ | head
python3 $CODE_DIR/tools/verify-cn-lists.py
```

> **变更幅度门禁**：如果新名单导致信任范围扩大超过阈值（默认域名或 IP 覆盖变化 ≥ 5%），脚本会拦截更新。此时请先检查 `cn-trust-review.txt` 确认无误后，再显式使用 `--force` 执行。

### 人工白名单与例外清单

* **强制不走国内路径**：编辑 `${LISTS_DIR}/cn-trust-exceptions.txt`
* **国内免见证白名单**：编辑 `${LISTS_DIR}/cn-trust-allow.txt`

### 缓存撤回（修改信任名单后必做）

`guard` 准入缓存靠"名单代次"自动失效，但 `adgh`（若启用缓存）或 `dnsdist` 侧需显式清理：

```bash
sudo $CODE_DIR/tools/cn-trust-revoke.sh      # 名单变化时触发失效（幂等）
sudo $CODE_DIR/tools/agh-cache-clear.sh       # 清理 AGH 缓存（依赖 /etc/dnsguard/agh-api.env）
python3 $CODE_DIR/tools/release_consistency.py
```

> `/etc/dnsguard/agh-api.env` 包含管理面板凭据（权限 `0600`），勿将其纳入外部备份仓库。

---

## 4. 发布升级与回滚

```bash
# 查看当前发布状态
sudo $CODE_DIR/tools/deploy_release.sh --status

# 切换至指定版本（校验 SHA256 与发布数据 -> 备份软链 -> 切换 -> 同时重启双进程 -> 90s 门禁轮询 -> 失败自动回滚）
sudo $CODE_DIR/tools/deploy_release.sh <release-id>

# 手动回滚至指定版本
sudo $CODE_DIR/tools/deploy_release.sh --rollback <release-id>
```

回滚记录保存在 `${CODE_DIR}/backups/deploy-<时间戳>/prev_current.txt`。

---

## 5. 探针工具

| 探针脚本 | 检查范围 | 正常预期 |
| :--- | :--- | :--- |
| `probes/dns-entry-probe.py` | 3 个入口（`853` / `444` / `443`）× 2 个测试域 | `cloudflare.com` 返回 `ad=1`；`www.qq.com` 正常解析 |
| `probes/dns-chain-probe.py` | 五层链路（`A`/`B`/`guard`/DoT/DoH）× 4 类样本 | `dnssec-failed.org` = `SERVFAIL`；`nxdomain-probe.invalid` = `NXDOMAIN` |
| `probes/probe-cand.py <域名>` | 单域名在 `A`/`B`/`guard`/`AGH` 的应答对比 | 用于定位某域名是否被国内上游污染 |
| `probes/external-probe.py` | 从外部网络探测公网入口 | 验证公网链路与 TLS 证书真实可达 |

---

## 6. 观测看板

看板均为只读组件，停掉不影响 DNS 解析：

* **链路看板 (`chainmon`)**：`https://<DOMAIN>/chain/`（默认 Basic Auth，用户名 `chain`，每 60 秒采集一次链路统计）
* **设备指纹看板 (`devfp`)**：`https://<DOMAIN>/devices/`（Basic Auth）
* **设备登记页**：`https://<DOMAIN>/join`（无鉴权，打开即采集特征，需管理员在看板手动确认绑定）

---

## 7. 内存预算与 cgroup 限额

适用于 ≤ 2 GiB 内存的小型宿主机：

| 服务单元 | `MemoryHigh` | `MemoryMax` |
| :--- | :--- | :--- |
| `dnsguard` | 160 MiB | 192 MiB |
| `dnsguard-verifier` | 100 MiB | 128 MiB |
| `chainmon` / `devfp`（各） | 128–192 MiB | 176–256 MiB |
| `unbound-alt-readiness` | — | 64 MiB（oneshot，每分钟运行） |
| `cgroup-memsw-limits` | 由脚本施加（Docker 896/1152/1408 MiB，`system.slice` 软限 1280 MiB） | — |

检查内存与 OOM 记录：

```bash
systemctl show dnsguard -p MemoryHigh -p MemoryMax -p MemoryCurrent
journalctl -k --since -2h | grep -i 'oom\|killed process'
```

> **cgroup v2 注意事项**：`cgroup-memsw-limits.service` 仅写入 cgroup v1 路径（`memory.memsw.limit_in_bytes` 等），在纯 cgroup v2 宿主上会跳过。请通过 `systemctl status cgroup-memsw-limits` 确认实际是否生效。出现 OOM 时优先调低 `GUARD_MAX_INFLIGHT` / `MAX_PENDING` 或降低看板采集频次。

---

## 8. 备份与全量快照

```bash
sudo $CODE_DIR/tools/make-snapshot.sh
```

会在 `/root/` 下生成 `dns-snapshot-<日期>/` 与 `.tar.gz`，包含 systemd 单元、iptables `filter` 表、Nginx 站点、容器配置、Unbound 配置、crontab、名单哈希、内存状态、各探针结果与门禁状态。

---

## 9. 故障处置速查

| 故障现象 | 优先排查步骤 |
| :--- | :--- |
| 客户端全部解析失败 | 跑 `verify.sh`，查看 `journalctl -u dnsguard -n 80` 及 `stats.json` 中的 `fc_*` 计数。 |
| 仅 DoT (`:853`) 失败 | 执行 `openssl s_client -connect <ip>:853 -servername $DOMAIN`。AGH 入口看 `docker logs --tail 50 adgh`；模板形态看 `systemctl status dnsdist` 及证书配置。 |
| 仅 DoH (`:444`) 失败 | 执行 `curl -sv "https://$DOMAIN:444/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"` 检查状态码与证书。 |
| 国内域名被解析到境外 CDN | 用 `probe-cand.py <域名>` 对比 `A`/`B`/`guard`；若 `B` 返回异常且被误采纳，加入 `cn-trust-exceptions.txt`。 |
| 境外域名误报 `NXDOMAIN` | 检查是否被误收入否决名单：`grep -i <域名> ${LISTS_DIR}/cn_veto.txt`。 |
| 发布一致性门禁报错 | 运行 `release_consistency.py`；重启 `dnsguard` 与 `dnsguard-verifier`；排查是否有人手工修改了 `$CODE_DIR` 下的 `guard.py`。 |
| 名单刷新失败 | 查看 `/var/log/cn-rules-refresh.log`，确认本机可访问 `codeload.github.com` 与 `ispip.clang.cn`。 |
| 磁盘空间不足 | 检查 `${CODE_DIR}/cn-list-history` 与 Docker 容器日志体积（`cnlist_history.py` 默认保留 30 天归档）。 |
| Chainmon 缓存命中率恒为 0% | 核对 `/etc/systemd/system/chainmon.service.d/30-dnsdist-stats.conf` 中的 `CHAINMON_DNSDIST_API_KEY` 是否与 `/etc/dnsdist/dnsdist.conf` 的 `apiKey` 一致，以及 `127.0.0.1:18083` 是否可达。 |

---

## 10. `stats.json` 关键指标

| 指标键 | 含义 |
| :--- | :--- |
| `cn_typed_total` / `cn_typed_full` / `cn_typed_domain` | 类型化名单总条目与精确/后缀两类匹配数 |
| `cn_typed_snapshot_used` / `cn_typed_fallback_denied` | 冷启动是否使用了快照 / 是否因名单缺失而拒绝国内判定 |
| `cn_veto_entries` / `cn_veto_fail` | 否决名单条目数与拦截次数 |
| `cn_ip_nets` | 国内 IP 段数量 |
| `cn_trust_allow_entries` / `cn_trust_exc_entries` | 白名单与例外清单条目数 |
| `cn_trust_bypass` / `cn_trust_witness` | 免见证直接放行 / 触发交叉见证次数 |
| `cn_dom_witness_bypass` / `cn_dom_witness_ok` / `cn_dom_witness_nonev` | 国内路径免见证 / 见证通过 / 无证据回退次数 |
| `ad_grade_local_ad` / `signed` / `ad_declared` / `sig_expired` | AD 位分级统计（本机验签 / 有签名 / 仅上游声明 / 签名过期） |
| `adm_cache_gen_mismatch` | 因名单代次变更触发的准入缓存失效次数 |
| `stale_out` | 出口下发 stale 应答（EDE 3/19）次数（不写缓存） |
| `udp_qid_mismatch` | 应答绑定校验失败次数（正常应长期为 0 或极低） |
| `fc_unbound_servfail` / `fc_*` | fail-closed 各分支拦截计数 |

---

## 11. 定期维护建议

* **每天**：查看 `verify.sh` 结果与 `/var/log/cn-lists-refresh.log` 汇总行。
* **每周**：检查 `stats.json` 异常计数（`*_fail`、`udp_qid_mismatch`、`adm_cache_gen_mismatch`）与宿主机内存余量。
* **每月**：复核 `cn-trust-allow.txt` 与 `cn-trust-exceptions.txt` 是否需要精简，确认 TLS 证书到期时间。
* **每季**：参考 [`MIGRATION.md`](MIGRATION.md) 演练一次整机重建与版本回滚。
