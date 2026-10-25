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
sudo ./install.sh  # 幂等：只重渲染 dnsdist/nginx/证书相关部分
sudo ./verify.sh
```

客户端侧要同步：DoT 的 SNI、DoH 的 URL/Host 都得改成新域名。

## 3. 换网段 / 容器 IP

```bash
vi .env            # DOCKER_SUBNET、*_IP 会自动生效；GUARD_LISTEN_HOST 跟随 dnsnet 网关（默认 172.18.0.1）
sudo ./install.sh
sudo /usr/local/sbin/dnsguard-ip-reconcile.sh --check   # 应报 4~6 项全部一致
```

`dnsguard-ip-reconcile.sh` 会把"写死容器 IP"的 6 个位置（nginx stream 的 `proxy_pass`、unbound A 的 `forward-addr`、dotfront drop-in、AGH 上游、guard 监听地址、探针源地址别名）按 `docker inspect` 的**实际分配**对齐，并带漂移巡检 timer。

**注意**：这 6 处不包含 dnsdist。`/etc/dnsdist/dnsdist.conf` 里的 `newServer({address="<AGH_IP>:53"})` 是渲染时写死的，改网段后要重跑 `./install.sh`（或手改该文件）再 `systemctl restart dnsdist`。

## 4. 换上游

| 想换的东西 | 改哪里 |
|---|---|
| 境外主源 | `deploy/containers/aghdq.AdGuardHome.yaml.tpl` 的 `upstream_dns`（默认 `quic://dns.nextdns.io`；`.env` 的 `UPSTREAM_A_QUIC` **当前未被 install.sh 读取**，要改就改模板） |
| 第二条境外 DoQ | `deploy/containers/aghdq2.AdGuardHome.yaml.tpl`（默认 `quic://dns10.quad9.net`） |
| 国内上游 | `deploy/containers/unbound-b.conf.tpl` 的 `forward-addr` 列表（DoT + `#hostname`，可用 `.env` 的 `UPSTREAM_B`） |
| 交叉见证 / fastpass | `deploy/containers/aghcf.AdGuardHome.yaml.tpl`（默认 Cloudflare `tls://1.1.1.1`） |
| alt 备用源 | `deploy/containers/unbound-alt.conf.tpl`（`.env` 的 `UPSTREAM_ALT` 同样未接入，直接改模板） |
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
| `dnsnet` 网关 | 同上；guard 监听地址跟随该网关（默认 `172.18.0.1`），不要手工写死；它不是 `docker0` 的地址 |
| 缓存 | guard/AGH 缓存为空，前几分钟命中率低、上游 QPS 略高，属正常 |
| 看板历史 | 不迁移则从零开始（数据在 SQLite 与 jsonl 里） |
| 证书 | 自签模式每次重建都会生成新证书，客户端需重新信任；用 ACME 则复用 |
| 名单 | 默认 `LISTS_PROFILE=fetch` 会在安装时生成真实名单；若没外网则退回骨架（只保证 `.cn`），此时 guard 按"未知即不信任"运行，稍后跑 `tools/refresh-all-cn-lists.sh` 补齐 |

## 7. 发布布局：平铺 → releases/<id> + current

### 7.1 为什么需要这一步

`install.sh` 部署出来的是**平铺布局**（`$CODE_DIR/guard.py`），而发布机制
（`deploy_release.sh`、`release_consistency.py`、`verify-release-data.py`）
要求 **`releases/<id>/` + `current` 软链**。两者不是一回事：

- 平铺布局下，`deploy_release.sh --rollback` 会报「发布目录不存在」；
- `release_consistency.py` 会报「current 软链缺失」；
- 也就是说：**服务在跑，但回滚无处可回**。

`install.sh` 从本版起会自动建立首个发布（若名单已就绪），也可手动执行。

### 7.2 建立发布

```bash
# 名单就绪后（cn-veto.snapshot.txt 存在），一步到位：建发布 + 迁移 unit + 切换 current
sudo $CODE_DIR/tools/make-release.sh --migrate-units

# 只建不切换（演练）
sudo $CODE_DIR/tools/make-release.sh --no-switch --dry-run
```

`--migrate-units` 的作用：把两个 unit 的 `ExecStart`/`WorkingDirectory` 从
平铺路径改写到 `$CODE_DIR/current/`。**不改写的话 current 软链对服务不生效**。
判定依据是 `systemctl show <unit> -p ExecStart` 的**生效值**：
若 drop-in 里已经写了 `ExecStart=.../current/guard.py`，则跳过，不做多余改动。
改写前会把全部 unit 与 drop-in 备份到 `$CODE_DIR/backups/units-<时间戳>/`。

### 7.3 校验

```bash
# 两道门禁
python3 $CODE_DIR/release_consistency.py
python3 $CODE_DIR/verify-release-data.py $CODE_DIR/current

# 或直接跑验收（第 6 节已包含发布布局检查）
sudo ./verify.sh
```

`make-release.sh` 自己也会在构建后跑一遍 `sha256sum -c` 与 `verify-release-data.py`，
不通过直接失败退出（rc=2），不会留下半成品发布。

### 7.4 回滚

```bash
$CODE_DIR/deploy_release.sh --list          # 看有哪些发布
sudo $CODE_DIR/deploy_release.sh --rollback <release-id>
```

`deploy_release.sh` 会在切换后轮询一致性门禁（默认最多 90 秒），
门禁不过就**自动切回上一发布**。

### 7.5 边界（如实登记）

- **发布目录不是不可变的**：`make-release.sh` 生成后若有人改了其中的 `guard.py`，
  `sha256sum -c` 会失败，`verify.sh` 会报「发布清单自校验失败」。这是刻意的检测，不是 bug。
- **切换软链不会替换已加载模块**：必须 `systemctl restart dnsguard dnsguard-verifier`
  才会真正加载新发布。`deploy_release.sh` 已内置这一步，手工 `ln -sfn` 时别忘。
- **`cn-veto.snapshot.txt` 是硬前置**：它由 `refresh-cn-veto-ip.py` 生成，
  缺失时 `make-release.sh` 直接拒绝构建（防止发布门禁形同虚设）。
- **名单不在发布内自动更新**：发布固化的是「构建那一刻」的策略快照；
  日常名单热更新仍走 `tools/refresh-all-cn-lists.sh`，不产生新发布。

