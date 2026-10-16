# 迁移与重建

## 1. 从旧部署迁移到新机器

**旧机器上（只读导出）**

```bash
# 一键快照：单元、容器、nginx、unbound、crontab、名单哈希、探针结果
sudo $CODE_DIR/tools/make-snapshot.sh
ls -l /root/dns-snapshot-*/ ; tar tzf /root/dns-snapshot-*.tar.gz | head -40

# 单独导出需要带走的东西
tar czf /root/migrate.tgz \
  /opt/dnsguard/cn-list-history /opt/dnscrypt-proxy/cn-trust-*.txt \
  /opt/chainmon /opt/devfp /etc/dnsguard 2>/dev/null
scp /root/migrate.tgz <new-host>:/root/
```

**新机器上**

```bash
git clone https://github.com/<you>/dns-guard-stack.git && cd dns-guard-stack
cp .env.example .env && vi .env      # 域名、IP、网段、路径
sudo ./install.sh                    # 默认会拉取真实名单（无外网会自动退回骨架）
sudo ./verify.sh                     # 确认链路 OK
```

**再导入数据**

```bash
# 名单（让新机器与旧机器同一份数据）
sudo cp /root/migrate-extract/cn-trust-*.txt /opt/dnscrypt-proxy/
sudo $CODE_DIR/tools/refresh-all-cn-lists.sh    # 或直接拷 cn-domains-typed.txt / cn_veto.txt / cn_ip.txt

# 看板历史（可选）
sudo systemctl stop chainmon devfp
sudo cp -a /root/migrate-extract/chainmon/. /opt/chainmon/ && sudo cp -a /root/migrate-extract/devfp/. /opt/devfp/
sudo systemctl start chainmon devfp

# 撤销凭据与生成册（可选）
sudo cp /root/migrate-extract/dnsguard/agh-api.env /etc/dnsguard/ && sudo chmod 600 /etc/dnsguard/agh-api.env
```

**切换流量**：把上游（路由器 / 客户端 / DHCP 选项）从旧 IP 指到新 IP，旧机器保留 24h 便于回退。

## 2. 换域名

```bash
vi .env            # DOMAIN、CERT_*（ACME 邮箱、证书路径）
sudo ./install.sh  # 幂等：只重渲染 nginx/证书相关部分
sudo ./verify.sh
```

客户端侧要同步：DoT 的 SNI、DoH 的 URL/Host 都得改成新域名。

## 3. 换网段 / 容器 IP

```bash
vi .env            # NET_SUBNET、IP_*、GUARD_LISTEN_HOST 会自动跟随 docker0 网关
sudo ./install.sh
sudo $CODE_DIR/tools/dnsguard-ip-reconcile.sh --check   # 应报 4~6 项全部一致
```

`dnsguard-ip-reconcile.sh` 会把"写死容器 IP"的 6 个位置（nginx stream 的 `proxy_pass`、unbound A 的 `forward-addr`、dotfront drop-in、AGH 上游、guard 监听地址、探针源地址别名）按 `docker inspect` 的**实际分配**对齐，并带漂移巡检 timer。

## 4. 换上游

| 想换的东西 | 改哪里 |
|---|---|
| 境外主源 | `deploy/containers/aghdq/AdGuardHome.yaml` 的 `upstream_dns`（默认 `quic://dns.nextdns.io`） |
| 国内上游 | `deploy/containers/unbound-b/unbound.conf` 的 `forward-addr` 列表（DoT + `#hostname`） |
| 交叉见证源 | `deploy/containers/unbound-alt/unbound.conf` |
| 影子对比源 | `.env` 的 `SHADOW_DNSCRYPT`（默认走 dnscrypt-proxy） |

改完 `./install.sh`（会重渲染并重启对应容器），然后用 `probes/dns-chain-probe.py` 验收。

## 5. 整机重建演练（建议每季一次）

```bash
# 1) 记录当前状态
sudo ./verify.sh | tee /root/verify-before.txt
python3 $CODE_DIR/tools/release_consistency.py --json > /root/release-before.json

# 2) 在干净机器上按第 1 节流程重建

# 3) 对比验收：这些必须一致
#   - release_consistency.py rc=0
#   - dnssec-failed.org = SERVFAIL；cloudflare.com = NOERROR + ad=1
#   - 三入口探针 RESULT: ALL OK
#   - 链路探针 RESULT: OK
#   - stats.json 中 *_fail / udp_qid_mismatch 接近 0
#   - 国内代表域（qq.com、baidu.com、taobao.com）走国内路径且可解析

# 4) 演练回滚
sudo $CODE_DIR/tools/deploy_release.sh --rollback <上一个 release-id>
```

## 6. 已知的"重建后会不一样"的地方

| 项 | 说明 |
|---|---|
| 容器 IP | 若宿主已有其它 Docker 网络占用同网段，重建后 IP 会变 —— 用 `dnsguard-ip-reconcile.sh` 收敛 |
| docker0 网关 | 同上；guard 监听地址跟随网关，不要手工写死 |
| 缓存 | guard/AGH 缓存为空，前几分钟命中率低、上游 QPS 略高，属正常 |
| 看板历史 | 不迁移则从零开始（数据在 SQLite 与 jsonl 里） |
| 证书 | 自签模式每次重建都会生成新证书，客户端需重新信任；用 ACME 则复用 |
| 名单 | 默认 `LISTS_PROFILE=fetch` 会在安装时生成真实名单；若没外网则退回骨架（只保证 `.cn`），此时 guard 按"未知即不信任"运行，稍后跑 `tools/refresh-all-cn-lists.sh` 补齐 |
