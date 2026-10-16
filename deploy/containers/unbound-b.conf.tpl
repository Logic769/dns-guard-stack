# Unbound 配置：给本机 AdGuard Home 当「会验证 DNSSEC 的上游」
#
# 工作方式（2026-10-10 更正为与行为一致）：**转发**给 6 家国内 DoT，不做本地递归。
#   forward-zone "." → 360×3 / AliDNS×2 / dns.pub；forward-tls-upstream: yes；forward-first: no（fail-closed）。
#   ⚠ 重要事实：这些国内上游**不提供端到端 DNSSEC 保证**，且**实测六家全部对不存在标签伪造地址**；
#     因此本实例的答案**必须**经上层 dnsguard 的"否定存在否决"（CN 路径）与 R1 特征检查才能下发。
#     其 :53 出站已被 iptables（UNBOUNDB_53）封堵；容器间 :53 亦已收口。
#   更正原因：此前文件头写"自己递归、不做转发"，与底部实际配置**矛盾**（该头注释恰好警告过它现在正犯的错）。
#
# 为什么不能转发给不验证的上游（实测教训）：
#   转发给 360 DoH 时，它自己不验证 DNSSEC，会把 GFW 伪造的应答原样转达——
#   包括伪造的「这个域没有 DS」应答。Unbound 因此认为该域未签名，直接把投毒地址
#   交给客户端（实测 www.google.com、telegram.org 就是这样漏过去的，
#   应答 AD=False）。自己递归时 DS/DNSKEY 都取自真实权威服务器并逐级验签，
#   伪造应答过不了校验（youtube/wikipedia/twitter 实测被正确判为 SERVFAIL）。
#
# 其余要点：
#  1. auto-trust-anchor + harden-dnssec-stripped：验签失败 → SERVFAIL，
#     宁可解析失败也不给假地址；
#  2. tcp-upstream: 对权威服务器的查询走 TCP，躲开针对 UDP 的路径注入
#     （代价是首次解析略慢，缓存后无感）；
#  3. 只允许内网/Docker 网段访问，避免成为公网开放解析器；
#  4. 内存吃紧（可用仅 322Mi），缓存压到 16m/32m、单线程。

server:
    ede: yes
    ede-serve-expired: yes
    prefetch-key: yes
    serve-expired-client-timeout: 300
    infra-keep-probing: yes
    verbosity: 1
    interface: 0.0.0.0
    port: 53
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    prefer-ip4: yes
    # tcp-upstream 实测会让被墙域名（TCP 到权威服务器）超时，改用 UDP + 本地验签
    # 容器内不 chroot、不降权：镜像里的 unbound 用户写不了挂载目录的 root.key
    # （实测会 fatal: could not open autotrust file for writing ... Permission denied）
    username: ""
    chroot: ""
    directory: "/opt/unbound/etc/unbound"
    logfile: ""
    use-syslog: no

    # —— 访问控制：只有内网/Docker 网段可用 ——
    access-control: 127.0.0.0/8 allow
    access-control: 172.16.0.0/12 allow
    access-control: 10.0.0.0/8 allow
    access-control: 192.168.0.0/16 allow
    access-control: 0.0.0.0/0 refuse

    # —— DNSSEC ——
    auto-trust-anchor-file: "/opt/unbound/etc/unbound/root.key"
    harden-dnssec-stripped: yes
    val-clean-additional: yes
    val-permissive-mode: no
    aggressive-nsec: yes

    # —— 加固 ——
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-below-nxdomain: yes
    qname-minimisation: yes
    use-caps-for-id: no
    edns-buffer-size: 1232
    unwanted-reply-threshold: 10000000
    deny-any: yes
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16

    # —— 性能 / 内存（内存吃紧，压小缓存）——
    num-threads: 2
    # 2026-10-09 阶段A：DoT 转发是 TCP，出向并发由该值决定（原为默认 10）
    #   实测 CN 路径吞吐 16 QPS = 10 / 0.611s，正是被它卡住；unbound-b 自身 CPU 仅 p90 9%。
    outgoing-num-tcp: 100
    # 2026-10-09 阶段A：requestlist.exceeded 累计 28740，单线程队列长期打顶
    num-queries-per-thread: 2048
    so-reuseport: yes
    msg-cache-size: 12m
    rrset-cache-size: 24m
    key-cache-size: 4m
    neg-cache-size: 4m
    cache-min-ttl: 0
    cache-max-ttl: 86400
    prefetch: yes
    prefetch-key: no
    serve-expired: yes
    serve-expired-ttl: 300
    serve-expired-reply-ttl: 0
    # TLS 证书链（容器内 Alpine 路径）
    tls-cert-bundle: "/etc/ssl/certs/ca-certificates.crt"
    extended-statistics: yes

# 递归模式：不需要 forward-zone（见文件头说明）

forward-zone:
    name: "."
    forward-tls-upstream: yes
    forward-addr: 218.30.118.6@853#dot.360.cn
    forward-addr: 101.226.4.6@853#dot.360.cn
    forward-addr: 123.125.81.6@853#dot.360.cn
    forward-addr: 223.5.5.5@853#dns.alidns.com
    # 2026-10-05：补两个**实测可用**的国内 DoT 上游（AliDNS 备 IP 21ms；DNSPod/腾讯 1.12.12.12 129ms，
    # 换运营商增加冗余）。注：腾讯 119.29.29.29 与百度 180.76.76.76 的 853 实测 timeout，不加。
    forward-addr: 223.6.6.6@853#dns.alidns.com
    forward-addr: 1.12.12.12@853#dns.pub
    # 2026-10-05：**forward-first 改为 no（fail-closed）**。原来 yes 会在 DoT 上游失败时 "回退"，
    # 而 unbound 的迭代器继承了 forward-tls-upstream，导致它去对**根服务器的 53 端口做 TLS 握手**
    # （日志：ssl handshake failed 198.41.0.4/192.112.36.4 port 53）—— 必然失败，是"坏回退"：
    # 既拿不到答案（CN 域名 SERVFAIL/超时），又隐含"离开加密路径"的意图。改 no 后行为明确。
    # 另：unbound-b 的全部 :53 出站已被 iptables 链 UNBOUNDB_53 DROP（防未来任何明文递归），
    # 并有 unbound-b-53-watch.timer 计数告警。
    forward-first: no

# ---- unbound-control 管理通道（仅容器内 loopback 127.0.0.1，2026-10-02 添加）----
remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
    control-port: 8953
    server-key-file: "/opt/unbound/etc/unbound/unbound_server.key"
    server-cert-file: "/opt/unbound/etc/unbound/unbound_server.pem"
    control-key-file: "/opt/unbound/etc/unbound/unbound_control.key"
    control-cert-file: "/opt/unbound/etc/unbound/unbound_control.pem"
