# Unbound 配置：给本机 AdGuard Home 当「会验证 DNSSEC 的上游」
#
# 工作方式（2026-10-10 更正为与行为一致）：**转发**，不做本地递归。
#   P1 起 forward-zone "." → forward-addr 172.18.0.6@53（容器 aghdq）→ DoQ → NextDNS；
#   forward-first: no（**fail-closed**：绝不在转发失败时回退明文递归）。
#   本机仍执行 DNSSEC 验证（auto-trust-anchor + harden-dnssec-stripped + val-permissive-mode: no）。
#   更正原因：此前文件头写"自己递归、不做转发"，与底部实际配置**矛盾**，曾误导评审。
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
    local-data: "ordns.he.net. 3600 IN A 74.82.42.42"
    local-data: "dns.digitale-gesellschaft.ch. 3600 IN A 185.95.218.42"
    local-data: "base.dns.mullvad.net. 3600 IN A 194.242.2.2"
    local-data: "unicast.censurfridns.dk. 3600 IN A 89.233.43.71"
    local-data: "dns.nextdns.io. 3600 IN A 45.11.104.186"
    local-data: "dns.nextdns.io. 3600 IN A 37.252.249.233"
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
    use-caps-for-id: yes
    harden-large-queries: yes
    edns-buffer-size: 1232
    unwanted-reply-threshold: 10000000
    deny-any: yes
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16

    # —— 性能 / 内存（内存吃紧，压小缓存）——
    num-threads: 2
    so-reuseport: yes
    outbound-msg-retry: 2
    infra-keep-probing: yes
    msg-cache-size: 24m
    rrset-cache-size: 48m
    key-cache-size: 8m
    neg-cache-size: 8m
    cache-min-ttl: 0
    cache-max-ttl: 86400
    prefetch: yes
    prefetch-key: yes
    serve-expired: yes
    serve-expired-client-timeout: 300
    serve-expired-ttl: 300
    serve-expired-reply-ttl: 0

    # TLS 证书链（容器内 Alpine 路径）
    tls-cert-bundle: "/etc/ssl/certs/ca-certificates.crt"
    extended-statistics: yes

# 递归模式：不配置 forward-zone；Unbound 直接访问根/TLD/权威并执行 DNSSEC 验证。

# ---- unbound-control 管理通道（仅容器内 loopback 127.0.0.1，2026-10-02 添加）----
remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
    control-port: 8953
    server-key-file: "/opt/unbound/etc/unbound/unbound_server.key"
    server-cert-file: "/opt/unbound/etc/unbound/unbound_server.pem"
    control-key-file: "/opt/unbound/etc/unbound/unbound_control.key"
    control-cert-file: "/opt/unbound/etc/unbound/unbound_control.pem"


# ---- 2026-10-10 P1：递归出口改为经认证加密上游（本机 aghdq → DoQ→NextDNS）----
# 目的：去掉明文递归到权威（最后一跳注入）。forward-first: no = fail-closed，绝不明文回退。
forward-zone:
    name: "."
    forward-addr: 172.18.0.6@53
    forward-first: no
