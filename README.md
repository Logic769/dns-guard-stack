# dns-guard-stack

**一台机器就能跑起来的抗投毒 DNS 解析栈。** 上游全部走加密通道、出口强制 DNSSEC 优先、"国内路径"与"国内信任"分离，并带发布一致性门禁、名单自动化与两块运维看板。

```
客户端 ──DoT 853 / DoH 443,444──> nginx(TLS 终结) ──> AdGuard Home(过滤+缓存)
                                                        │
                                                        └─> guard(准入与共识) ──┬─> unbound A ─> aghdq ─> NextDNS(DoQ)   境外路径
                                                                                ├─> unbound B ─> 国内 6 家 DoT          国内路径
                                                                                ├─> unbound alt ─> 第三方独立 DoT       认证备用
                                                                                └─> verifier(独立进程，交叉验证)
```

### 解析链路全景

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/architecture-dark.png">
  <img src="docs/assets/architecture-light.png" alt="dns-guard-stack 解析链路架构：家庭客户端经 nginx 的 DoT 853 / DoH 444 入口进入 AdGuard Home 主，再由 guard 策略引擎分流至境外（unbound-a 本机 DNSSEC → aghdq DoQ 出口 → NextDNS）、国内（unbound-b 六家国内 DoT，不验签）、第三方（unbound-alt 交叉见证 / dnscrypt-proxy 影子采样）三条解析链与一个 DoQ 出口；旁路部分是 dotfront-spool 采集 DoT 明文内腿、verifier 独立进程经 AF_UNIX 交叉验证、chainmon 与 devfp 只读 stats、名单目录与名单刷新器、防火墙原子收敛">
</picture>

实线是主解析路径，虚线是旁路、只读与异步关系。四条方框标出了真实的隔离边界（宿主 systemd、境外解析链、国内解析链、第三方解析链），每个节点都对应仓库里的真实文件与 systemd 单元。

## 它解决什么问题

| 威胁 | 常见家用/小规模部署的弱点 | 本栈的做法 |
|---|---|---|
| 路径投毒（伪造应答抢先返回） | 明文 53 只做端口校验 | 上游全部 TLS（DoT/DoQ）；UDP 应答校验 ID/问题/QNAME/报文形状；来源地址固定 |
| 上游不验 DNSSEC | 直接信上游的答案 | 本机 Unbound 验签；验签失败返回 SERVFAIL；底层用 EDE + RRSIG 精确判定，不把普通 SERVFAIL 误判为污染 |
| 缓存被污染答案 | 命中即用，TTL 不老化 | 逐 RR 老化 + 按剩余期限裁剪；stale 应答不写准入缓存；名单代次变化即让准入缓存失效 |
| 社区名单把境外 CDN 归为"国内" | 用一份名单同时决定"走哪条路"和"信谁" | **两份判据分离**：`is_cn_domain()`（路由）/ `is_cn_trusted()`（信任），默认只对国别后缀与人工白名单免见证，其余国内答案必须与 A/alt 交叉见证一致 |
| 两个进程跑不同版本 | 软链切换不影响已加载模块 | 握手带发布指纹 + `release_consistency.py` 门禁 + `deploy_release.sh` 原子切换与失败回滚 |
| 名单长期不更新 / 被篡改 | 手工维护、无签名 | 统一刷新入口（同步拉取 + 门禁 + 原子替换 + 变更归档 + GPG 签名 + `verify-cn-lists.py` 校验） |

## 快速开始

**前置**：Linux + systemd、Docker（含 compose 插件）、Python ≥ 3.6、root 权限、一个指向本机的域名（DoT/DoH 用；内网可先用自签证书）。

```bash
git clone https://github.com/<you>/dns-guard-stack.git
cd dns-guard-stack
cp .env.example .env          # 至少设置 DNS_DOMAIN（DoT/DoH 用；内网可先用自签证书）
sudo ./install.sh --dry-run   # 先看会做什么（不写系统）
sudo ./install.sh             # 幂等：装代码 / 渲染配置 / 起容器 / 装单元 / 生成 nginx 片段
sudo ./verify.sh              # 验收：容器、服务、指标、解析行为、防火墙
```

安装完成后：

```bash
dig @<本机IP> -p 853 +tls +dnssec cloudflare.com   # 期望 NOERROR 且 ad: 1
dig @<本机IP> -p 853 +tls dnssec-failed.org        # 期望 SERVFAIL（验签失败不放行）
```

`install.sh` 常用开关：`--dry-run`（只打印动作）、`--skip-firewall`、`--fetch-lists`（安装时即拉取社区名单）。

## 目录结构

```
core/        guard.py verifier.py alt_adapter.py answer_policy.py unbound-alt-readiness.py   ← 策略与解析核心
tools/       名单刷新/归档验签/发布门禁/快照/看门狗/缓存撤销/DoT 明文内腿采集            ← 运维自动化
probes/      入口探针 / 链路探针 / 外部探针 / 分档与 N1-N3 验证探针
firewall/    iptables 原子收敛脚本与表生成器（含 5 分钟巡检 timer）
dashboards/  chainmon（链路看板）与 devfp（设备指纹看板）
deploy/      容器配置模板、systemd 单元、nginx 片段、信任名单样例
tests/       400+ 项离线回归（含审计用例：缓存老化、失败语义、应答绑定、名单分层）
docs/        架构、部署、运维、安全边界、迁移
```

## 关键运维

```bash
# 名单刷新（域名名单 → 否决+IP 名单 → 完整性校验，三步一体）
sudo $CODE_DIR/tools/refresh-all-cn-lists.sh

# 名单变更历史与验签
python3 $CODE_DIR/tools/verify-cn-lists.py          # 清单哈希 + GPG 签名校验
ls $CODE_DIR/cn-list-history/                       # 每次变更的归档（含 MANIFEST.sha256）

# 发布升级 / 回滚（同发布原子切换 + 双进程指纹门禁）
sudo $CODE_DIR/tools/deploy_release.sh <release-id>
sudo $CODE_DIR/tools/deploy_release.sh --rollback <release-id>

# 名单代次变化后撤销 AdGuard Home 侧缓存
sudo $CODE_DIR/tools/cn-trust-revoke.sh && sudo $CODE_DIR/tools/agh-cache-clear.sh
```

## 测试

```bash
tests/run.sh                  # 496 项离线回归：缓存老化、失败语义、应答绑定、名单分层、AD 位分档、发布门禁…
PYTHON=python3.6 tests/run.sh # 服务器跑的是 3.6；CI 里另有 3.6 容器做语法检查
```

测试不需要网络、不需要 root、不触碰生产路径（全部在 tempdir 里 pin 住路径）。因为测试是按"发布目录布局"
（所有 .py 与 tests/ 同级）写的，`tests/run.sh` 会先把 `core/ tools/ probes/` 摊平到临时目录再执行。

## 可靠性与自检

- `verify.sh`：一键验收（容器 / 服务 / 指标 / 三类解析 / iptables）
- `tools/release_consistency.py`：guard 与 verifier 是否同发布、同 cwd、指纹一致（退出码即结论）
- `tools/canary_watch.py`：持续金丝雀，按"客户端是否真被暴露"判定红绿
- `tools/make-snapshot.sh`：把当前状态（单元、规则、名单哈希、探针结果、内存）打成一份可回溯快照

## 已知边界（不做的事）

- **单机部署**：这是纵深防御，不是高可用。宿主、公网出口、nginx、Docker 网络都是单点。
- **公网入口无客户端认证**：默认按"公共 DoT/DoH 服务"设计（有按源限流与共享准入池），不提供用户级鉴权。
- **上游数据无官方签名**：v2fly / clang.cn 等来源自身不带签名，本栈只能保证"落盘后未被篡改"。
- **国内域名普遍无 DNSSEC**：国内路径的答案靠"交叉见证 + 否定存在否决 + 人工白名单"约束，不等价于加密保证。
- **土壤决定上限**：若你的上游网络本身被劫持到路径内，能做的只是"宁可 SERVFAIL 也不给假地址"。

详见 [`docs/SECURITY.md`](docs/SECURITY.md)。

## 文档

| 文档 | 内容 |
|---|---|
| [docs/DNS-SYSTEM-GUIDE.md](docs/DNS-SYSTEM-GUIDE.md) | **整套系统的通俗详解**：每个模块、每个脚本、每种判断方式（含大量对照表） |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 分层、端口、一次查询的完整旅程、每一处判断的依据 |
| [docs/DEPLOY.md](docs/DEPLOY.md) | 部署细节、各发行版差异、常见故障排查 |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | 日常运维：名单、发布、探针、看板、内存与限额 |
| [docs/SECURITY.md](docs/SECURITY.md) | 威胁模型、修复过的缺陷类别、诚实边界 |
| [docs/MIGRATION.md](docs/MIGRATION.md) | 从既有部署迁移，或整机重建 |

## 许可

MIT，见 [LICENSE](LICENSE)。
