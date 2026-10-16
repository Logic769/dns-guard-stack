# 隔离副本：只用于验证 readiness 门（§2.2/§2.4），与生产 /opt/unbound-alt 完全独立。
server:
    username: ""
    chroot: ""
    directory: "/opt/unbound/etc/unbound"
    interface: 0.0.0.0
    port: 53
    access-control: 10.99.0.0/24 allow
    access-control: 10.99.0.1/32 allow
    access-control: 127.0.0.0/8 allow
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
server:
    val-max-restart: 1
