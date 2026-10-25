-- dnsdist 配置模板（install.sh 渲染到 RUNTIME_DIR/dnsdist/dnsdist.conf）
--
-- 角色（2026-10-22 起）：公网 DoT(853) 与 DoH(444) 的唯一入口。
--   · 之前由 nginx stream(dot-853.conf) + nginx http(doh-444.conf) 承接，
--     但 nginx 反代到 127.0.0.1 后后端只看得到 127.0.0.1，拿不到真实客户端 IP；
--   · dnsdist 直接监听 853/444，既能拿到真实 remoteaddr，又能内置 PacketCache。
--   ⇒ nginx 的 dot-853.conf / doh-444.conf 已转为 legacy（deploy/nginx/tcp/disabled/）。
--
-- 缓存位置：PacketCache 在 dnsdist 这一层（不再是 AGH），所以 chainmon 的
--   命中率必须从 dnsdist 的 HTTP 统计接口读（webserver 段 + CHAINMON_DNSDIST_API_KEY）。
--
-- 渲染期由 install.sh 替换的占位符：
--   dns.example.com  → $DNS_DOMAIN（同时改写下面两处证书路径）
--   172.18.0.2       → $AGH_IP（上游 AdGuard Home）
--   0.0.0.0:853/444  → $DOT_PORT / $DOH_PORT
--   change-me-dnsdist-control-key / -web-password / -web-apikey → .env 的 DNSDIST_* 值
-- 证书路径若显式设定 TLS_CERT/TLS_KEY，install.sh 会把整段路径一起改写。

-- 允许公网客户端（dnsdist 默认 ACL 只含内网，不放开会拒绝所有外部 DoT/DoH）
setACL({"0.0.0.0/0", "::/0"})

setServerPolicy(firstAvailable)

-- 唯一上游：AdGuard Home（过滤 + 分流）
newServer({address="172.18.0.2:53", name="agh", checkInterval=10})

-- 查询缓存。temporaryFailureTTL 让 SERVFAIL 只缓存 60s（上游抖动时不至于长时间毒化），
-- staleTTL 让过期条目在回源失败时还能顶 60s。
pc = newPacketCache(32768, {maxTTL=86400, minTTL=0, temporaryFailureTTL=60, staleTTL=60, dontAge=false})
getPool(""):setCache(pc)

-- 记录客户端 IP（简化：只在查询阶段记录，不依赖 tags）。
-- 行格式：<epoch>.<微秒>,<client_ip>,<qname>,<qtype>；chainmon 的 qlog 窗口读这个文件。
-- 整体包在 pcall 里：写日志失败绝不能影响解析。
function markQuery(dq)
  local ok, err = pcall(function()
    local t = os.time()
    local line = string.format("%d.%06d,%s,%s,%d\n",
      math.floor(t), 0,
      tostring(dq.remoteaddr),
      dq.qname:toString():gsub("%.$",""), dq.qtype)
    local fh = io.open("/var/log/dnsdist-query.log", "a")
    if fh then fh:write(line); fh:close() end
  end)
  if not ok then io.stderr:write("QLOG_ERR " .. tostring(err) .. "\n") end
  return DNSAction.None
end
addAction(AllRule(), LuaAction(markQuery))

-- 限速：单客户端 200 qps / 10s 窗口，超限 REFUSED 10s
local dbr = dynBlockRulesGroup()
dbr:setQueryRate(200, 10, "Exceeded query rate", 10, DNSAction.Refused)
function maintenance()
  dbr:apply()
end

-- DoT 公网入口
addTLSLocal("0.0.0.0:853",
  "/www/server/panel/vhost/cert/dns.example.com/fullchain.pem",
  "/www/server/panel/vhost/cert/dns.example.com/privkey.pem",
  {provider="openssl"})

-- DoH 公网入口（/dns-query）
addDOHLocal("0.0.0.0:444",
  "/www/server/panel/vhost/cert/dns.example.com/fullchain.pem",
  "/www/server/panel/vhost/cert/dns.example.com/privkey.pem",
  {"/dns-query"}, {provider="openssl"})

-- 本地控制台（dnsdist -c 连接用；只监听回环）
controlSocket("127.0.0.1:5199")
setKey("change-me-dnsdist-control-key")

-- 只读 HTTP 统计端点：chainmon 从这里读 cache-hits / cache-misses 等
webserver("127.0.0.1:18083")
setWebserverConfig({password="change-me-dnsdist-web-password", apiKey="change-me-dnsdist-web-apikey"})
