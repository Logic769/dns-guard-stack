# unbound-alt（任务1）：独立运营方 DoT 备用认证路径，本地做 DNSSEC 验证。
# 只用两家既有可达 DoT：Digitale Gesellschaft、UncensoredDNS。
# 暂不启用 stale（serve-expired: no）—— 避免把过期命中当作"备用当前可用"。
server:
    username: ""
    chroot: ""
    directory: "/opt/unbound/etc/unbound"
    interface: 0.0.0.0
    port: 53
    access-control: 127.0.0.0/8 allow
    access-control: 172.16.0.0/12 allow
    access-control: 0.0.0.0/0 refuse
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    num-threads: 1
    num-queries-per-thread: 256
    outgoing-num-tcp: 16
    msg-cache-size: 4m
    rrset-cache-size: 8m
    key-cache-size: 4m
    neg-cache-size: 2m
    cache-min-ttl: 0
    cache-max-ttl: 86400
    prefetch: yes
    serve-expired: no
    edns-buffer-size: 1232
    auto-trust-anchor-file: "/opt/unbound/etc/unbound/root.key"
    val-permissive-mode: no
    harden-dnssec-stripped: yes
    tls-cert-bundle: "/etc/ssl/certs/ca-certificates.crt"
    hide-identity: yes
    hide-version: yes
    extended-statistics: yes
    use-syslog: no
    verbosity: 1
forward-zone:
    name: "."
    forward-tls-upstream: yes
    forward-first: no
    forward-addr: 185.95.218.42@853#dns.digitale-gesellschaft.ch
    forward-addr: 89.233.43.71@853#unicast.censurfridns.dk

# ===== Task 1（2026-10-10 20261010-105202）=====
# 目标：把"冷 DNSSEC bogus 首触 5–9 s"收进守护层 deadline（4 s）/ 健康检查上限（2 s）。
# 机制：val-max-restart 默认 5 ⇒ 校验失败时最多重跑 5 轮，每轮串行问两家 DoT（各 ~0.9–1.2 s）。
# 只改这一项。未动：DNSSEC 验签、forward-first: no、serve-expired: no、两家 forwarder、缓存大小。
server:
    val-max-restart: 1
