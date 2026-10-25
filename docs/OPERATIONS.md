# 运维手册

> 下面的路径以默认 `.env` 为准：`CODE_DIR=/opt/dnsguard`、`LISTS_DIR=/opt/dnscrypt-proxy`、`CHAINMON_DIR=/opt/chainmon`、`DEVFP_DIR=/opt/devfp`。

## 1. 一条命令看健康

```bash
sudo ./verify.sh
```

它依次检查：容器、systemd 服务、guard 监听、发布一致性、名单完整性、三入口探针、链路探针、DNSSEC 正反样本、日志里的 Traceback、内存与 OOM，最后打印 `RESULT: OK` 或失败项。

单项检查也可以直接跑：

```bash
docker ps --format '{{.Names}}\t{{.Status}}'
systemctl status dnsguard dnsguard-verifier adgh 2>/dev/null | head -40
python3 $CODE_DIR/tools/release_consistency.py --json | head -30
python3 $CODE_DIR/tools/verify-cn-lists.py
python3 $CODE_DIR/probes/dns-entry-probe.py        # DoT 853 / DoH 444 / DoH 443
python3 $CODE_DIR/probes/dns-chain-probe.py        # 五层链路 + 4 类样本
```

## 2. 服务与容器

```bash
systemctl restart dnsguard dnsguard-verifier     # 策略层（会清空内存缓存，几秒不可用）
systemctl restart unbound-b                       # 仅重启国内上游
docker restart adgh                               # AGH（会丢 AGH 自己的缓存）
docker logs --tail 50 agghdq                      # 注意：容器名按 .env 生成
systemctl list-timers | grep dnsguard             # 定时任务一览
```

> guard 与 verifier 必须**同时**重启（GUI 侧一次命令：`systemctl restart dnsguard dnsguard-verifier`）。只重启一个会让版本门禁报警。

## 3. 名单

```bash
# 刷新（域名名单 + 否决/IP 名单 + 校验，见日志汇总行）
sudo $CODE_DIR/tools/refresh-all-cn-lists.sh
tail -5 /var/log/cn-lists-refresh.log

# 只看会做什么（不写盘）
sudo python3 $CODE_DIR/tools/refresh-cn-rules.py --dry-run
sudo python3 $CODE_DIR/tools/refresh-cn-veto-ip.py --dry-run

# 变更归档与验签
ls -lt $CODE_DIR/cn-list-history/ | head
python3 $CODE_DIR/tools/verify-cn-lists.py        # 哈希 + GPG 签名 + 条目数
```

名单变成"更宽"的变更会被幅度门禁拦住（默认域名 ≥5% 变化或 IP 覆盖 ≥5% 变化即失败），需要用 `--force` 显式越过 —— 越过前先看 `cn-trust-review.txt` 待审清单。

**例外（强制不走国内路径）**：`${LISTS_DIR}/cn-trust-exceptions.txt`
**白名单（免见证信任）**：`${LISTS_DIR}/cn-trust-allow.txt`

改完这两个文件后：

```bash
sudo $CODE_DIR/tools/cn-trust-revoke.sh      # 名单变化则清 guard 侧缓存
python3 $CODE_DIR/tools/release_consistency.py
```

## 4. 升级与回滚

```bash
# 发布一个新版本
sudo $CODE_DIR/tools/deploy_release.sh <release-id>

# 回滚
sudo $CODE_DIR/tools/deploy_release.sh --rollback <release-id>
sudo $CODE_DIR/tools/deploy_release.sh --status
```

`deploy_release.sh` 做的事：校验 `RELEASE.sha256` → 校验发布数据（清单/快照/例外）→ 备份当前软链指向 → 切软链 → **一条命令**同时重启两个服务 → 轮询门禁（最多 90s）→ 失败自动回滚并保留日志。

回滚点保存在 `${CODE_DIR}/backups/deploy-<时间戳>/prev_current.txt`。

## 5. 探针

| 探针 | 用途 | 期望 |
|---|---|---|
| `probes/dns-entry-probe.py` | 三个入口（853/444/443）× 两个域名 | `cloudflare.com` 有 `ad=1`；`www.qq.com` 正常 |
| `probes/dns-chain-probe.py` | 五层链路（A/B/guard/DoT/DoH）× 4 类样本 | 含 `dnssec-failed.org` = SERVFAIL、`nxdomain-probe.invalid` = NXDOMAIN |
| `probes/probe-cand.py <域名>` | 单域名在 A/B/guard/AGH 的答案对比 | 用于判断某域名是否被国内上游污染 |
| `probes/external-probe.py` | 从**外部**网络访问公网入口 | 证明对外服务真的通（不是本机自测） |

## 6. 看板

- 链路看板：`https://<DOMAIN>/chain/`（Basic Auth，用户名默认 `chain`）
- 设备指纹看板：`https://<DOMAIN>/devices/`（同上）
- 设备登记页：`https://<DOMAIN>/join`（无鉴权；打开即采集，绑定由人在看板手动确认）

看板是**只读观测**：链路线参数（chainmon，60s 一轮）与 DoT/DoH 设备指纹（devfp，旁路抓包 + 日志 tail）。它们不参与解析决策，停掉不影响 DNS。

## 7. 内存与限额

宿主很小时（≤2GiB）按这个预算分配：

| 单元 | MemoryHigh | MemoryMax |
|---|---|---|
| `dnsguard` | 160 MiB | 192 MiB |
| `dnsguard-verifier` | 100 MiB | 128 MiB |
| 看板（各） | 128–192 MiB | 176–256 MiB |

```bash
systemctl show dnsguard -p MemoryHigh -p MemoryMax -p MemoryCurrent
journalctl -k --since -2h | grep -i 'oom\|killed process'
```

出现 OOM 时优先：降低 `GUARD_MAX_INFLIGHT` / `MAX_PENDING`、减少看板采集频率、给宿主加 swap（本项目不依赖 swap，只做兜底）。

## 8. 缓存撤销（重要）

guard 与 AGH 有**两套独立缓存**。名单变化时 guard 靠"代次"自动失效，AGH 需要显式清：

```bash
sudo $CODE_DIR/tools/cn-trust-revoke.sh        # 名单变化才清（幂等）
sudo $CODE_DIR/tools/agh-cache-clear.sh        # 只清 AGH 缓存
```

`agh-cache-clear.sh` 需要 AGH 面板凭据（`/etc/dnsguard/agh-api.env`，0600）。不要把该文件放进任何备份仓库。

## 9. 备份与快照

```bash
# 一次性快照（配置 + 状态 + 名单哈希 + 探针结果 + 门禁结果）
sudo $CODE_DIR/tools/make-snapshot.sh          # → /root/dns-snapshot-<日期>/ 与 .tar.gz
```

快照含：systemd 单元与 drop-in、iptables filter 表、nginx 站点、容器配置、三个 unbound 配置、crontab、名单哈希、内存、三入口探针、链路探针、门禁、名单校验。

## 10. 故障处置速查

| 症状 | 先做 |
|---|---|
| 客户端全部解析失败 | `verify.sh`；再看 `journalctl -u dnsguard -n 80`、`stats.json` 的 `fc_*` |
| 只有 DoT 失败 | `openssl s_client -connect <ip>:853 -servername $DOMAIN`；`systemctl status dnsdist` + 证书（legacy 场景再查 stream 片段） |
| 只有 DoH 失败 | `curl -sv https://$DOMAIN:444/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB` |
| 国内域名被解析到境外 CDN | `probe-cand.py <域名>`；若 B 给的是污染答案而 guard 采纳了 → 加入 `cn-trust-exceptions.txt` |
| 某个境外域名解析不到（NXDOMAIN） | 检查是否误入否决名单：`grep -i <域名> ${LISTS_DIR}/cn_veto.txt` |
| 门禁红灯 | `release_consistency.py`；两服务重启一次；仍红灯看是不是手工改了 `CODE_DIR` 下的 `guard.py` |
| 名单刷新失败 | `tail -50 /var/log/cn-rules-refresh.log`；确认能出网到 `codeload.github.com`/`ispip.clang.cn` |
| 磁盘满 | `du -sh ${CODE_DIR}/cn-list-history` 与容器日志；`cnlist_history.py` 默认保留 30 天 |

## 11. 关键指标（`${CODE_DIR}/stats.json`）

| 键 | 含义 |
|---|---|
| `cn_typed_total` / `cn_typed_full` / `cn_typed_domain` | 类型化名单载入量与两类匹配数 |
| `cn_typed_snapshot_used` / `cn_typed_fallback_denied` | 冷启动是否用快照 / 是否因名单不可用而拒绝国内判定 |
| `cn_veto_entries` / `cn_veto_fail` | 否决名单条目数与失败次数 |
| `cn_ip_nets` | 国内 IP 段数量 |
| `cn_trust_allow_entries` / `cn_trust_exc_entries` | 白名单 / 例外清单条目数 |
| `cn_trust_bypass` / `cn_trust_witness` | 免见证采纳 / 走见证的次数 |
| `cn_dom_witness_bypass` / `cn_dom_witness_ok` / `cn_dom_witness_nonev` | 国内路径免见证 / 见证通过 / 无证据 |
| `ad_grade_local_ad` / `ad_grade_signed` / `ad_grade_ad_declared` / `ad_grade_sig_expired` | AD 位分档（本机验签 / 有签名 / 仅声明 / 签名过期） |
| `adm_cache_gen_mismatch` | 因名单代次变化而失效的缓存数 |
| `stale_out` | 出口下发 stale（EDE 3/19）的次数（**不**写缓存） |
| `udp_qid_mismatch` | 应答绑定校验失败次数（应长期为 0 或极低） |
| `fc_unbound_servfail` / `fc_*` | fail-closed 各分支计数 |

## 12. 定期维护建议

| 周期 | 动作 |
|---|---|
| 每天 | 看 `verify.sh` 结果与 `cn-lists-refresh.log` 汇总行 |
| 每周 | 看 `stats.json` 异常计数（`*_fail`、`udp_qid_mismatch`、`adm_cache_gen_mismatch`）与宿主内存 |
| 每月 | 复核 `cn-trust-allow.txt`（是否还需要那么多免见证）/ `cn-trust-exceptions.txt`（是否可移除）/ 证书到期 |
| 每季 | 演练一次整机重建（见 MIGRATION.md）与一次回滚 |
