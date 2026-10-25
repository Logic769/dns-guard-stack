proxy_cache_path /www/dk_project/sites/dns.example.com/proxy_cache_dir levels=1:2 keys_zone=dns-example_xyz_cache:20m inactive=1d max_size=5g;
server {
    listen 80;
    listen 443 ssl;
    http2 on;

    server_name dns.example.com;
    index index.php index.html index.htm default.php default.htm default.html;
    root /www/dk_project/wwwroot/dns.example.com;
    include /www/server/panel/vhost/nginx/extension/dns.example.com/*.conf;
    

    #CERT-APPLY-CHECK--START
    # 用于SSL证书申请时的文件验证相关配置 -- 请勿删除
    include /www/server/panel/vhost/nginx/well-known/dns.example.com.conf;
    #CERT-APPLY-CHECK--END

    #SSL-START SSL相关配置，请勿删除或修改下一行带注释的404规则
    #error_page 404/404.html;
    ssl_certificate    /www/server/panel/vhost/cert/dns.example.com/fullchain.pem;
    ssl_certificate_key    /www/server/panel/vhost/cert/dns.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!3DES:!RC4:!DSS;
    ssl_prefer_server_ciphers on;
    ssl_session_tickets on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    add_header Strict-Transport-Security "max-age=31536000";
    add_header Alt-Svc 'quic=":443"; h3=":443"; h3-29=":443"; h3-27=":443";h3-25=":443"; h3-T050=":443"; h3-Q050=":443";h3-Q049=":443";h3-Q048=":443"; h3-Q046=":443"; h3-Q043=":443"';
    error_page 497  https://$host$request_uri;

    #SSL-END
    #REDIRECT START
    
    
    #REDIRECT END

    #ERROR-PAGE-START  错误页配置，可以注释、删除或修改
    error_page 404 /404.html;
    error_page 502 503 504 /dsh-offline.html;
    #error_page 502 /502.html;
    #ERROR-PAGE-END

    #PHP-INFO-START  PHP引用配置，可以注释或修改
    
    
    #PHP-INFO-END
    
    #REWRITE-START URL重写规则引用,修改后将导致面板设置的伪静态规则失效
    
    #REWRITE-END

    #IP-RESTRICT-START 限制访问ip的配置，IP黑白名单
    
    #IP-RESTRICT-END

    #BASICAUTH START
    
    #BASICAUTH END

    #SUB_FILTER START
    
    #SUB_FILTER END

    #GZIP START
    
    #GZIP END

    #GLOBAL-CACHE START
    
    #GLOBAL-CACHE END

    #WEBSOCKET-SUPPORT START
    proxy_http_version 1.1;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection $connection_upgrade;
    #WEBSOCKET-SUPPORT END

    # AdGuard Home DoH：把 443 上的 /dns-query 转给容器（宿主 444 → 容器 443）。
    # 精确匹配优先于下面的 `location ^~ /`（DSH 反代），两条互不影响。
    location = /dns-query {
        # §3.1 入口容量：与 444 同一 zone（doh_req 由按字母序先加载的 9.devfp-doh444.conf 定义）
        limit_conn perip 32;
        limit_req zone=doh_req burst=200 nodelay;
        proxy_pass https://agh_doh;
        proxy_ssl_session_reuse on;
        proxy_next_upstream error timeout;
        proxy_ssl_server_name on;
        proxy_ssl_name dns.example.com;
        proxy_ssl_trusted_certificate /etc/pki/tls/certs/ca-bundle.crt;
        proxy_ssl_verify on;
        proxy_ssl_verify_depth 3;
        proxy_http_version 1.1;
        proxy_set_header Host dns.example.com;
        proxy_set_header Connection "";
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 30s;
        proxy_send_timeout 30s;
        proxy_cache off;
        proxy_buffering off;
        add_header Accept-CH "Sec-CH-UA-Model, Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Arch" always;

# DEBUGFP-START
        # 设备指纹：额外记一份带 TLS/HTTP 细节的日志（保留原有两条日志，行为不变）
        access_log /www/wwwlogs/doh-devices.log dohfrag;
        access_log /www/wwwlogs/dns.example.com.log;
        access_log syslog:server=unix:/tmp/site_total.sock,nohostname,tag=1000002__access site_total;
# DEBUGFP-END
    }

    # ===== REMOTE-ADMIN-START (远程管理隧道：SSH 反向隧道 → 家中路由器 / CPE) =====
    # --- 额外密码网关：basic-auth 只在此处生效；通过后下发 cookie ---
    # --- 原因：CPE/路由页面 JS 会自带 Authorization: Bearer，与 basic-auth 同头冲突导致 401 ---
    location = /vg-gate { if ($scheme = http) { return 301 https://$host$request_uri; }
        # auth_basic 必须在 access 阶段生效：这里不能用 return（return 运行在 rewrite 阶段，会绕过密码校验），
        # 所以走 try_files -> 命名 location，先在 access 阶段校验密码，再在 precontent 阶段发 Cookie 并跳回。
        auth_basic "Logic769 Remote Admin";
        auth_basic_user_file /www/server/nginx/conf/remote-admin.htpasswd;
        try_files /__vg_gate_only__ @vg_gate_ok;
    }

    location @vg_gate_ok {
        add_header Set-Cookie "vg_adm=eeb1e38b392a929ce923083accfa92bf104fd16f610d8433; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax" always;
        return 302 https://$host$arg_next;
    }

    location = /router { if ($scheme = http) { return 301 https://$host$request_uri; } return 302 /cgi-bin/luci/; }

    # --- 路由器 LuCI 管理界面（10.0.0.1，经远程隧道 127.0.0.1:18080）---
    location ^~ /cgi-bin/ { if ($scheme = http) { return 301 https://$host$request_uri; }
        if ($cookie_vg_adm != "eeb1e38b392a929ce923083accfa92bf104fd16f610d8433") { return 302 /vg-gate?next=$uri; }
        proxy_pass http://127.0.0.1:18080;
        proxy_http_version 1.1;
        proxy_set_header Host 10.0.0.1;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 300s;
        proxy_buffering off;
        add_header X-Robots-Tag "noindex, nofollow" always;
    }
    location ^~ /luci-static/ { if ($scheme = http) { return 301 https://$host$request_uri; }
        if ($cookie_vg_adm != "eeb1e38b392a929ce923083accfa92bf104fd16f610d8433") { return 302 /vg-gate?next=$uri; }
        proxy_pass http://127.0.0.1:18080;
        proxy_set_header Host 10.0.0.1;
        proxy_read_timeout 120s;
        add_header X-Robots-Tag "noindex, nofollow" always;
    }
    location = /ubus { if ($scheme = http) { return 301 https://$host$request_uri; }
        if ($cookie_vg_adm != "eeb1e38b392a929ce923083accfa92bf104fd16f610d8433") { return 302 /vg-gate?next=$uri; }
        proxy_pass http://127.0.0.1:18080;
        proxy_http_version 1.1;
        proxy_set_header Host 10.0.0.1;
        proxy_read_timeout 600s;
        proxy_buffering off;
    }

    # --- 上游 CPE 管理后台（192.168.0.1:9527，经远程隧道 127.0.0.1:18081）---
    location = /cpe { if ($scheme = http) { return 301 https://$host$request_uri; } return 302 /cpe/; }
    location ^~ /cpe/ { if ($scheme = http) { return 301 https://$host$request_uri; }
        if ($cookie_vg_adm != "eeb1e38b392a929ce923083accfa92bf104fd16f610d8433") { return 302 /vg-gate?next=$uri; }
        proxy_pass http://127.0.0.1:18081/;
        proxy_http_version 1.1;
        proxy_set_header Host 192.168.0.1:9527;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        # WebSocket 升级（ttyd 终端）：缺这两行时上游只收到普通 GET，CPE 会返回 404（实测）
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Accept-Encoding "";
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
        proxy_redirect / /cpe/;
        proxy_redirect http://192.168.0.1:9527/ /cpe/;
        proxy_redirect ~^https?://192\.168\.0\.1(:9527)?(/.*)?$ /cpe$2;
        subs_filter_types application/javascript text/javascript application/json text/css;
        subs_filter '"/api/' '"/cpe/api/' g;
        subs_filter "'/api/" "'/cpe/api/" g;
        subs_filter '"/api"' '"/cpe/api"' g;
        subs_filter 'window.location.href="/"' 'window.location.href="/cpe/"' g;
        subs_filter '"/"!==e' '"/cpe/"!==e' g;
        subs_filter '"/index.html"!==e' '"/cpe/index.html"!==e' g;
        subs_filter 'http://192.168.0.1:9527/' '/cpe/' g;
        add_header X-Robots-Tag "noindex, nofollow" always;
    }

    # --- 上游 CPE 标准管理界面（192.168.0.1:80，经远程隧道 127.0.0.1:18082）---
    location = /cpe-std { if ($scheme = http) { return 301 https://$host$request_uri; } return 302 /cpe-std/; }
    location ^~ /cpe-std/ { if ($scheme = http) { return 301 https://$host$request_uri; }
        if ($cookie_vg_adm != "eeb1e38b392a929ce923083accfa92bf104fd16f610d8433") { return 302 /vg-gate?next=$uri; }
        proxy_pass http://127.0.0.1:18082/;
        proxy_http_version 1.1;
        proxy_set_header Host 192.168.0.1;
        proxy_set_header Referer http://192.168.0.1/;
        proxy_set_header Origin http://192.168.0.1;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Accept-Encoding "";
        proxy_read_timeout 300s;
        proxy_buffering off;
        proxy_redirect / /cpe-std/;
        proxy_redirect http://192.168.0.1/ /cpe-std/;
        proxy_redirect ~^https?://192\.168\.0\.1(:9527)?(/.*)?$ /cpe-std$2;
        subs_filter_types application/javascript text/javascript application/json text/css;
        subs_filter '"/ubus/' '"/cpe-std/ubus/' g;
        subs_filter "'/ubus/" "'/cpe-std/ubus/" g;
        subs_filter '"/ubus"' '"/cpe-std/ubus"' g;
        subs_filter '"/goform/' '"/cpe-std/goform/' g;
        subs_filter "'/goform/" "'/cpe-std/goform/" g;
        subs_filter 'http://192.168.0.1/' '/cpe-std/' g;
        add_header X-Robots-Tag "noindex, nofollow" always;
    }
    # ===== REMOTE-ADMIN-END =====
    #PROXY-CONF-START
    location ^~ / {
      
      
      proxy_pass http://127.0.0.1:19388;
      # --- DSH remote-web-ui relay ---
      proxy_intercept_errors on;
      proxy_cache off;
      proxy_buffering off;
      client_max_body_size 200m;
      proxy_set_header Host $http_host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Real-Port $remote_port;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
      proxy_set_header X-Forwarded-Host $host;
      proxy_set_header X-Forwarded-Port $server_port;
      proxy_set_header REMOTE-HOST $remote_addr;
      
      
      proxy_connect_timeout 60s;
      proxy_send_timeout 3600s;
      proxy_read_timeout 3600s;
      proxy_http_version 1.1;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection $connection_upgrade;
      
      
      
      
      
    }
    #PROXY-CONF-END

    #SERVER-BLOCK START
    
    #SERVER-BLOCK END

    location = /dsh-offline.html {
        internal;
        root /www/dk_project/wwwroot/dns.example.com;
        add_header Cache-Control "no-store" always;
    }

    #禁止访问的文件或目录
    location ~ ^/(\.user.ini|\.htaccess|\.git|\.env|\.svn|\.project|LICENSE|README.md)
    {
        return 404;
    }

    #一键申请SSL证书验证目录相关设置
    location /.well-known{
        allow all;
    }

    #禁止在证书验证目录放入敏感文件
    if ( $uri ~ "^/\.well-known/.*\.(php|jsp|py|js|css|lua|ts|go|zip|tar\.gz|rar|7z|sql|bak)$" ) {
        return 403;
    }

    #LOG START
    
access_log  /www/wwwlogs/dns.example.com.log;
    error_log  /www/wwwlogs/dns.example.com.error.log;
    
    #LOG END
}
