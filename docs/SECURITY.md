# 安全模型与边界
> **入口形态提示（2026-10-28）**：生产实例的公网 853 / 444 已交给 AdGuard Home（按客户端真实 IP 注入 ECS `/24`），dnsdist 退到内网 `172.18.0.1:5300` 做 ECS 感知缓存。本文件里与 `install.sh` / `dnsdist` 相关的步骤仍对应**模板形态**，用它们部署出来的是模板形态（功能可用，但不含 per-user ECS 与按省分片的缓存）。两种形态的完整差异表、每项差异的原因，以及生产侧额外的自动收敛单元，见 [ARCHITECTURE.md 第 8 节](ARCHITECTURE.md)。


## 1. 威胁模型

**假设的攻击者能力**

- 能在你的上游网络路径上注入/抢先投递伪造 DNS 应答（典型：路径投毒、DNS 劫持）
- 控制或影响某个"国内上游"（国内 DoT 运营方不保证端到端 DNSSEC 语义，实测存在对不存在标签伪造地址的行为）
- 能污染社区名单数据源（v2fly 等镜像/CDN）
- 能触达你的公网 DoT/DoH 入口（扫描、暴力、资源耗尽）

**不假设**

- 攻击者已在宿主上取得 root（此时任何本机防护都失效）
- 攻击者能破解 TLS（TLS 1.2+/1.3，证书校验开启）
- 攻击者能改写权威侧的签名（DNSSEC 私钥安全）

**目标（按优先级）**

1. **不把假答案交给客户端**——宁可 SERVFAIL
2. 不因单点数据错误把整类域名整体改道到低可信路径
3. 任何自动更新都能被发现、可追溯、可回滚

## 2. 设计原则

| 原则 | 落地 |
|---|---|
| 宁失败不给假 | `forward-first: no`（不回退明文递归）；验签失败 SERVFAIL；见证不过回退 A/alt 或 SERVFAIL |
| 只降不升 | 上游自称 AD=1 但没有可验证签名 → 只能进 `ACCEPTED` 档（内部 300s），不能进 `SECURE`（900s）；本机自验或有 RRSIG 才 `SECURE` |
| 最小信任 | 国内可信集合默认只含国别后缀 + 人工白名单；其余国内答案必须交叉见证 |
| 数据变化即失效 | 准入缓存记录名单代次（typed/veto/exc/allow 的 sha 前缀），任一变化即让相关缓存失效 |
| 原子与可回滚 | 发布切换用软链 + 一次 `systemctl restart` + 门禁；iptables 用"算好再单次 restore"；名单用 tmp + `os.replace` |
| 可观测 | 每次跳过见证/降级/失效都有独立计数；快照把状态、名单哈希、探针结果一并留档 |
| 纵深防御 | 上游 TLS + 应答绑定校验 + iptables 封国内上游明文 53 + 按源限流 + 独立 verifier 进程 |

## 3. 实现中修正过的缺陷类别

这些是开发过程中真实出现并被审计/自测抓到的类别，也是这个栈"为什么会写成现在这样"的原因：

| 类别 | 症状 | 修法 |
|---|---|---|
| 缓存不老化 | 驻留 299s 的 300s 条目，剩余寿命仍按 300s 下发 | 逐 RR 老化 + 按剩余期限裁剪 `max_ttl`；零 TTL 不入可复用缓存 |
| 失败语义过粗 | 任意 `rcode=2` 被判为 DNSSEC 失败，"普通 SERVFAIL"永远无法被备用通道修复 | 只认 OPT EDE code 15 且 value ∈ 6..12 为 DNSSEC 失败；其余为传输问题 |
| 应答绑定缺失 | UDP 回包不校验 ID/问题/QNAME，可能被抢先注入 | 校验 ID/QR/opcode/QDCOUNT/三元组/RR 计数/尾长；`connect()` 固定对端 + 有界重收 |
| 发布错配 | 两个进程跑在不同发布，代码语义不一致 | 握手携带发布指纹；不匹配拒绝执行；门禁校验 cwd/pid/指纹 |
| 名单与信任耦合 | 一份社区名单同时决定"路由"和"是否信任"，导致境外 CDN 被国内化后答案直达公网客户端 | 拆成 `is_cn_domain()` / `is_cn_trusted()` 两层；默认只对国别后缀与白名单免见证；例外清单兜底 |
| 缓存不随名单撤销 | 把域名移出信任名单后，旧答案仍在缓存里继续下发 | 缓存带名单代次；代次变化即失效（并可用 `cn-trust-revoke.sh` + `agh-cache-clear.sh` 清 AGH 侧） |
| 冷启动降级过宽 | typed 名单不可用时回退到"自身 + 所有子域"匹配，等于扩大信任 | 优先读同目录快照；都不可用则判**非**国内（拒绝宽匹配） |
| 快照口径比 live 更窄 | 否决名单快照固定在发布时（2167 条），live 已放宽到 2.5 万条，回退时否决面反而变窄 | 快照跟随刷新器同步生成，优先级 = live 快照 > 发布快照；两者都缺 → 一律否决 |
| 只读检查有副作用 | "只读验收"会真的重建防火墙规则 | check 分支在任何写操作之前返回；`ipt()` 在只读模式直接 FATAL |
| 探针自身不可信 | 探针关掉证书校验、把 NOTIMP 当健康、读 AD 但不带 DO | 严格 TLS + 显式 SNI；按样本类型断言（含 `dnssec-failed.org` 必须 SERVFAIL）；DoT 处理 2 字节长度前缀 |
| 指纹抖动被当成设备变更 | Chrome 随机化 TLS 扩展顺序，同一台机每次 JA4 都不同；无头环境下 canvas/audio 会抖 | 绑定以持久 ID（localStorage/IndexedDB/Cookie/Cache）为主锚点，JA4 只作辅助；稳定指纹取"首次为准" |

## 4. 诚实的边界

1. **单机**。宿主、公网出口、dnsdist、nginx、Docker 网络、证书都是单点（生产实例中公网 TLS 入口是 AdGuard Home 容器，dnsdist 已退为内网缓存层；容器还是单点）。这是纵深防御，不是高可用。要抗整机故障必须做第二台 + 双入口。
2. **公网入口无客户端认证**。默认按公共解析服务设计：有按源限流、有共享准入池，但没有用户级鉴权。若只服务自己家，请改用上游白名单或隧道（`AGH allowed_clients` + 防火墙）。
3. **上游数据无官方签名**。v2fly / clang.cn 自身不签名，本栈能保证的只是"落盘后未被篡改"（哈希清单 + GPG 归档）。哈希清单不抗已取得 root 的攻击者。
4. **国内域名普遍没有 DNSSEC**。国内路径的答案只能靠交叉见证、否定存在否决、人工白名单与特征检查约束，**不等价于**密码学保证。这也是 `known` 档位存在的理由：把免见证范围压到最小。
5. **不检测"上游整体说谎且与 A/alt 一致"**。如果多个独立运营方同时给出同一个假答案，本栈会采纳它（这正是共识模型的固有边界）。
6. **不在本栈解决的事**：客户端侧的 DNS over HTTPS 策略、终端恶意软件、账号安全。

## 5. 如何验证防护真的在工作

```bash
# 1) 验签路径：应当 SERVFAIL
dig @127.0.0.1 -p 853 +tls +dnssec dnssec-failed.org

# 2) 阳性路径：应当 NOERROR 且 ad: 1
dig @127.0.0.1 -p 853 +tls +dnssec cloudflare.com

# 3) 国内路径可用性（不应被误伤）
dig @127.0.0.1 -p 853 +tls www.qq.com

# 4) 名单指标与见证计数
python3 -c "import json;print({k:v for k,v in json.load(open('$CODE_DIR/stats.json')).items() if k.startswith(('cn_trust','cn_dom','cn_typed','cn_veto'))})"

# 5) 发布一致性门禁
python3 $CODE_DIR/tools/release_consistency.py; echo "rc=$?"

# 6) 名单完整性 + 变更归档验签
python3 $CODE_DIR/tools/verify-cn-lists.py
```

更多细节见 [OPERATIONS.md](OPERATIONS.md) 与 [DNS-SYSTEM-GUIDE.md](DNS-SYSTEM-GUIDE.md)。
