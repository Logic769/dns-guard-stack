#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dns-guard-stack 解析链架构图生成器（纯 Python 标准库，不联网，不引用外部字体/CDN）。

唯一真源：改图只改本脚本，禁止手改生成的 SVG / HTML。

用法:
    py -3 gen-architecture.py            # 生成 architecture-light.svg / architecture-dark.svg / architecture.html
    py -3 gen-architecture.py --png      # 额外用 playwright(本机已装) 渲染 1600px 宽 PNG
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent

W, H = 1600, 1000
FONT = "system-ui, 'Segoe UI', 'Microsoft YaHei', sans-serif"

# ---------------------------------------------------------------- 调色板
# 只允许这里随主题变化；布局常量与 NODES / EDGES 全局共享，保证两版布局一致。
PALETTES = {
    "light": dict(
        bg="#f7f9fc",
        band="#eef3fa",
        band_stroke="#d8e1ed",
        band_label="#6b7c92",
        card="#ffffff",
        card_stroke="#ccd7e5",
        hl_card="#f2f7ff",
        hl_stroke="#1a6fd0",
        title="#0f1826",
        text="#1b2533",
        muted="#5c6b7e",
        ip="#0b62c4",
        warn="#a2521a",
        tag="#7a8a9e",
        req="#12518f",
        cond="#c07a12",
        byp="#98a4b6",
        note_bg="#fffaf0",
        note_stroke="#e2cc9c",
        legend_bg="#ffffff",
    ),
    "dark": dict(
        bg="#0d131f",
        band="#131d2c",
        band_stroke="#25334a",
        band_label="#8ba0ba",
        card="#18212f",
        card_stroke="#2c3c54",
        hl_card="#1a2740",
        hl_stroke="#5aa2ff",
        title="#f2f7fd",
        text="#dbe5f2",
        muted="#94a5ba",
        ip="#74bbff",
        warn="#ffb26b",
        tag="#7f93ab",
        req="#5aa2ff",
        cond="#e8a33d",
        byp="#7d8ca1",
        note_bg="#1d1a12",
        note_stroke="#5a4a26",
        legend_bg="#131d2c",
    ),
}

# ---------------------------------------------------------------- 节点（18 个）
# lines: (文本, 样式) 样式 ∈ ip / muted / warn / sub
NODES = [
    # 公网侧
    dict(id="client", x=40, y=400, w=156, h=96, name="公网客户端",
         lines=[("198.51.100.10", "ip"), ("dns.example.com", "sub"), ("外部查询入口", "muted")]),
    # 入口层
    dict(id="dnsdist", x=220, y=300, w=200, h=215, name="dnsdist 入口层",
         lines=[("0.0.0.0:853 DoT", "ip"),
                ("0.0.0.0:444 DoH /dns-query", "ip"),
                ("openssl provider 终结 TLS", "muted"),
                ("PacketCache 本地缓存", "muted"),
                ("限流 200 次/10s", "muted"),
                ("超限 REFUSED 10s", "muted"),
                ("控制 127.0.0.1:5199", "ip"),
                ("统计 127.0.0.1:18083", "ip")],
         tag="宿主 systemd 服务（非容器）"),
    # 主 AGH
    dict(id="adgh", x=460, y=380, w=190, h=140, name="adgh 主 AdGuard Home",
         lines=[("172.18.0.2:53", "ip"),
                ("宿主 3000 / 4443 / 8854", "ip"),
                ("过滤 + 本地缓存", "muted"),
                ("上游只指向 guard", "muted"),
                ("无绕过 guard 的 fallback", "warn")],
         tag="容器 · dnsnet"),
    # 决策层
    dict(id="guard", x=686, y=300, w=200, h=215, name="guard 决策层", highlight=True,
         lines=[("172.18.0.1:5355", "ip"),
                ("探针通道 172.18.0.1:5356", "ip"),
                ("① 国内路由判定", "muted"),
                ("② 候选解析", "muted"),
                ("③ 安全检查", "muted"),
                ("④ 答案准入", "muted")],
         tag="宿主 systemd 服务"),
    # 候选源层（guard 下游）
    dict(id="unbound", x=960, y=108, w=240, h=58, name="unbound · A 侧",
         lines=[("172.18.0.4", "ip"), ("本机 DNSSEC 验证", "muted")]),
    dict(id="unbound-b", x=960, y=174, w=240, h=58, name="unbound-b · B 侧",
         lines=[("172.18.0.5", "ip"), ("国内 6 家加密 DoT", "muted")]),
    dict(id="aghdq", x=960, y=240, w=240, h=58, name="aghdq · DoQ 主",
         lines=[("172.18.0.6 · 宿主 5533", "ip"), ("NextDNS DoQ 主通道", "muted")]),
    dict(id="aghdq2", x=960, y=306, w=240, h=58, name="aghdq2 · DoQ 次",
         lines=[("172.18.0.11 · 宿主 5534", "ip"), ("Quad9，hedge 后并发", "muted")]),
    dict(id="aghcf", x=960, y=372, w=240, h=58, name="aghcf · 见证 / 透传",
         lines=[("172.18.0.12 · 宿主 5535", "ip"), ("见证 + SERVFAIL 透传", "muted")]),
    dict(id="unbound-alt", x=960, y=438, w=240, h=58, name="unbound-alt · 核对",
         lines=[("172.18.0.8 · 独立 TCB", "ip"), ("第三方 DoT，备用核对", "muted")]),
    dict(id="dnscrypt", x=960, y=504, w=240, h=58, name="dnscrypt-proxy · 影子",
         lines=[("172.18.0.9 · 宿主 5399", "ip"), ("仅采样，非 DNSSEC 证据", "muted")]),
    dict(id="alt-replica", x=1256, y=562, w=288, h=88, name="alt-replica-unb · 副本",
         lines=[("10.99.0.2 · 宿主 15353", "ip"), ("alt 的独立网络副本", "muted")]),
    # 上游
    dict(id="upstream", x=1250, y=230, w=310, h=240, name="上游互联网",
         lines=[("NextDNS · DoQ", "muted"),
                ("Quad9 · DoQ", "muted"),
                ("Cloudflare · DoT", "muted"),
                ("国内 6 家 · 加密 DoT", "muted"),
                ("外部权威 / 递归", "muted"),
                ("经候选源出网，不可直连", "warn")]),
    # 旁路与管理（非查询必经）
    dict(id="probes", x=40, y=800, w=268, h=160, name="探针",
         lines=[("入口 / 链路 / 外部三路", "muted"),
                ("主动探测可用性", "muted"),
                ("异常汇入 Chainmon", "muted")],
         tag="宿主 systemd timer"),
    dict(id="ops", x=322, y=800, w=300, h=160, name="采集与看板",
         lines=[("Chainmon 127.0.0.1:8787", "ip"),
                ("devfp 127.0.0.1:8789", "ip"),
                ("dotfront-spool 采集内腿", "muted"),
                ("命中率读自 18083", "muted")],
         tag="只读观测"),
    dict(id="verifier", x=636, y=800, w=268, h=160, name="verifier",
         lines=[("本机 Unix socket", "ip"),
                ("核对发布配置一致性", "muted"),
                ("与 guard 协作审计", "muted")],
         tag="按需运行"),
    dict(id="refresh", x=918, y=800, w=268, h=160, name="名单刷新",
         lines=[("cn 名单定时更新", "muted"),
                ("归档名单验签", "muted"),
                ("变更后 reload guard", "muted")],
         tag="cron / timer"),
    dict(id="firewall", x=1200, y=800, w=352, h=160, name="防火墙与地址对账",
         lines=[("iptables 收口规则", "muted"),
                ("6 处容器地址对账", "muted"),
                ("dnsnet 固定 IP 一致性", "muted")],
         tag="启动 + 定时"),
]

NODE_BY_ID = {n["id"]: n for n in NODES}


def cy(nid: str) -> float:
    n = NODE_BY_ID[nid]
    return n["y"] + n["h"] / 2.0


# ---------------------------------------------------------------- 连线（23 条）
# kind: req = 必经（实线加粗） / cond = 条件（hedge、见证） / byp = 旁路（管理、采样）
EDGES = [
    # 主链：客户端 → dnsdist → adgh → guard
    dict(kind="req", pts=[(196, 450), (220, 450)]),
    dict(kind="req", pts=[(420, 450), (460, 450)]),
    dict(kind="req", pts=[(650, 450), (686, 450)]),
    # guard → 候选源（右侧扇出）
    dict(kind="req", curve=(886, 318, 960, cy("unbound"))),
    dict(kind="req", curve=(886, 344, 960, cy("unbound-b"))),
    dict(kind="req", curve=(886, 370, 960, cy("aghdq"))),
    dict(kind="cond", curve=(886, 396, 960, cy("aghdq2"))),
    dict(kind="cond", curve=(886, 422, 960, cy("aghcf"))),
    dict(kind="cond", curve=(886, 448, 960, cy("unbound-alt"))),
    dict(kind="byp", curve=(886, 474, 960, cy("dnscrypt"))),
    # 候选源 → 上游
    dict(kind="req", curve=(1200, cy("unbound"), 1250, 258)),
    dict(kind="req", curve=(1200, cy("unbound-b"), 1250, 292)),
    dict(kind="req", curve=(1200, cy("aghdq"), 1250, 326)),
    dict(kind="cond", curve=(1200, cy("aghdq2"), 1250, 360)),
    dict(kind="cond", curve=(1200, cy("aghcf"), 1250, 394)),
    dict(kind="cond", curve=(1200, cy("unbound-alt"), 1250, 428)),
    # alt 副本
    dict(kind="byp", curve=(1200, 478, 1256, 606)),
    # 管理/旁路（虚线/点线，连到被管理对象）
    dict(kind="byp", pts=[(770, 800), (770, 515)]),
    dict(kind="byp", pts=[(690, 800), (690, 620), (620, 620), (620, 520)]),
    dict(kind="byp", pts=[(1052, 800), (1052, 690), (850, 690), (850, 515)]),
    dict(kind="byp", pts=[(1230, 800), (1230, 660), (876, 660), (876, 515)]),
    dict(kind="byp", pts=[(120, 800), (120, 762), (300, 762), (300, 515)]),
    dict(kind="byp", pts=[(472, 800), (472, 720), (400, 720), (400, 515)]),
]

EDGE_STYLE = {
    "req": dict(width=2.6, dash=None),
    "cond": dict(width=1.9, dash="7 5"),
    "byp": dict(width=1.7, dash="2.5 5"),
}

# 画布上的辅助文本
NOTE = dict(x=220, y=176, w=200, h=96,
            lines=["旁注：legacy 退路 nginx", "与 dnsdist 的 853/444", "端口互斥，二选一"])
LAYER_LABEL = (456, 118, "docker 网络 dnsnet 172.18.0.0/16")
LAYER_LABEL2 = (456, 137, "全部容器固定 IP · guard 位于宿主侧网关 172.18.0.1")
ALT_LABEL = (1246, 543, "10.99.0.0/24 · altreplica0")
BAND_TITLE = (44, 790, "旁路与管理 · 非查询必经（虚线连向被管理对象）")
TITLE = (40, 46, "dns-guard-stack 解析链架构")
SUBTITLE = (40, 70, "公网客户端 → dnsdist 入口层 → AdGuard Home → guard 决策层 → 候选源 → 上游互联网")


# ---------------------------------------------------------------- 绘制原语
def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def text(x, y, s, size, fill, weight="400", anchor="start", ls=None):
    extra = ""
    if ls is not None:
        extra += ' letter-spacing="%s"' % ls
    return (
        '<text x="%.1f" y="%.1f" font-family="%s" font-size="%s" font-weight="%s" '
        'fill="%s" text-anchor="%s"%s>%s</text>'
        % (x, y, FONT, size, weight, fill, anchor, extra, esc(s))
    )


def rect(x, y, w, h, fill, stroke, sw=1.2, rx=10, dash=None):
    d = ' stroke-dasharray="%s"' % dash if dash else ""
    return (
        '<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="%s" fill="%s" '
        'stroke="%s" stroke-width="%s"%s/>' % (x, y, w, h, rx, fill, stroke, sw, d)
    )


def node_svg(n, P):
    out = []
    hl = n.get("highlight")
    out.append(rect(n["x"], n["y"], n["w"], n["h"],
                    P["hl_card"] if hl else P["card"],
                    P["hl_stroke"] if hl else P["card_stroke"],
                    2.0 if hl else 1.2))
    x = n["x"] + 14
    if n["h"] <= 62:
        name_y, line_y, step = n["y"] + 19, n["y"] + 34, 15
        name_size = 13.6
    elif n["h"] <= 140:
        name_y, line_y, step = n["y"] + 23, n["y"] + 43, 17
        name_size = 14.0
    else:
        name_y, line_y, step = n["y"] + 25, n["y"] + 45, 18
        name_size = 14.0
    out.append(text(x, name_y, n["name"], name_size, P["title"], "600"))
    for i, (s, style) in enumerate(n["lines"]):
        color = {"ip": P["ip"], "muted": P["muted"], "warn": P["warn"], "sub": P["muted"]}[style]
        size = {"ip": 10.6, "muted": 10.2, "warn": 10.2, "sub": 9.8}[style]
        out.append(text(x, line_y + i * step, s, size, color))
    if n.get("tag"):
        out.append(text(x, n["y"] + n["h"] - 11, n["tag"], 9.4, P["tag"]))
    return "".join(out)


def edge_svg(e, P):
    st = EDGE_STYLE[e["kind"]]
    color = P[e["kind"]]
    if "curve" in e:
        x1, y1, x2, y2 = e["curve"]
        dx = (x2 - x1) * 0.45
        d = "M %.1f %.1f C %.1f %.1f %.1f %.1f %.1f %.1f" % (
            x1, y1, x1 + dx, y1, x2 - dx, y2, x2, y2)
    else:
        pts = e["pts"]
        d = "M %.1f %.1f " % pts[0] + " ".join("L %.1f %.1f" % p for p in pts[1:])
    dash = ' stroke-dasharray="%s"' % st["dash"] if st.get("dash") else ""
    return (
        '<path d="%s" fill="none" stroke="%s" stroke-width="%.1f" '
        'stroke-linecap="round" stroke-linejoin="round"%s marker-end="url(#a-%s)"/>'
        % (d, color, st["width"], dash, e["kind"])
    )


def legend_svg(P):
    x, y, w, h = 1250, 96, 310, 100
    out = [rect(x, y, w, h, P["legend_bg"], P["card_stroke"], 1.2)]
    out.append(text(x + 14, y + 22, "图例", 12.5, P["title"], "600"))
    rows = [(y + 46, "req", "必经路径（加粗实线）"),
            (y + 68, "cond", "条件路径（hedge / 见证）"),
            (y + 90, "byp", "旁路路径（管理 / 采样）")]
    for ry, kind, label in rows:
        st = EDGE_STYLE[kind]
        dash = ' stroke-dasharray="%s"' % st["dash"] if st.get("dash") else ""
        out.append(
            '<path d="M %.1f %.1f L %.1f %.1f" fill="none" stroke="%s" stroke-width="%.1f"%s/>'
            % (x + 14, ry - 4, x + 54, ry - 4, P[kind], st["width"], dash))
        out.append(text(x + 64, ry, label, 10.6, P["text"]))
    return "".join(out)


def render_svg(P):
    s = []
    s.append(
        '<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" '
        'role="img" aria-label="dns-guard-stack 解析链架构图">' % (W, H, W, H))
    s.append("<title>dns-guard-stack 解析链架构</title>")
    s.append("<defs>")
    for kind in ("req", "cond", "byp"):
        s.append(
            '<marker id="a-%s" viewBox="0 0 10 10" refX="9.2" refY="5" markerWidth="10" '
            'markerHeight="10" markerUnits="userSpaceOnUse" orient="auto-start-reverse">'
            '<path d="M0,0.6 L10,5 L0,9.4 z" fill="%s"/></marker>' % (kind, P[kind]))
    s.append("</defs>")

    # 背景
    s.append('<rect x="0" y="0" width="%d" height="%d" fill="%s"/>' % (W, H, P["bg"]))

    # 标题
    s.append(text(TITLE[0], TITLE[1], TITLE[2], 22, P["title"], "600"))
    s.append(text(SUBTITLE[0], SUBTITLE[1], SUBTITLE[2], 11.5, P["muted"]))

    # 容器网络分区
    s.append(rect(440, 92, 772, 548, P["band"], P["band_stroke"], 1.2, rx=14, dash="4 6"))
    s.append(text(LAYER_LABEL[0], LAYER_LABEL[1], LAYER_LABEL[2], 11, P["band_label"], "600"))
    s.append(text(LAYER_LABEL2[0], LAYER_LABEL2[1], LAYER_LABEL2[2], 10, P["band_label"]))
    # alt 副本独立网络
    s.append(rect(1240, 550, 320, 112, "none", P["byp"], 1.4, rx=12, dash="4 5"))
    s.append(text(ALT_LABEL[0] + 6, ALT_LABEL[1], ALT_LABEL[2], 9.6, P["byp"]))

    # 管理带
    s.append(rect(28, 770, 1544, 196, P["band"], P["band_stroke"], 1.2, rx=14, dash="4 6"))
    s.append(text(BAND_TITLE[0], BAND_TITLE[1], BAND_TITLE[2], 11, P["band_label"], "600"))

    # 连线（先画，卡片覆盖其上）
    for e in EDGES:
        s.append(edge_svg(e, P))

    # 节点
    for n in NODES:
        s.append(node_svg(n, P))

    # 旁注（nginx legacy 退路）
    s.append(rect(NOTE["x"], NOTE["y"], NOTE["w"], NOTE["h"], P["note_bg"], P["note_stroke"], 1.1,
                  rx=9, dash="3 4"))
    for i, line in enumerate(NOTE["lines"]):
        s.append(text(NOTE["x"] + 12, NOTE["y"] + 26 + i * 20, line, 9.8, P["muted"]))

    # 图例
    s.append(legend_svg(P))

    s.append("</svg>")
    return "\n".join(s) + "\n"


HTML_TMPL = """<!doctype html>
<html lang="zh-CN" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>dns-guard-stack 解析链架构</title>
<style>
  :root { color-scheme: light dark; }
  html[data-theme="light"] body { background:#f7f9fc; color:#0f1826; }
  html[data-theme="dark"] body { background:#0d131f; color:#f2f7fd; }
  * { box-sizing: border-box; }
  body { margin:0; font-family: system-ui, 'Segoe UI', 'Microsoft YaHei', sans-serif; }
  header { position:sticky; top:0; z-index:5; display:flex; gap:8px; align-items:center;
           flex-wrap:wrap; padding:10px 16px; border-bottom:1px solid rgba(128,128,128,.28);
           backdrop-filter: blur(6px); background: inherit; }
  header h1 { font-size:15px; margin:0 12px 0 0; font-weight:600; }
  header .hint { font-size:12px; opacity:.7; margin-left:auto; }
  button { font: inherit; font-size:13px; padding:5px 11px; border-radius:8px; cursor:pointer;
           border:1px solid rgba(128,128,128,.45); background: rgba(128,128,128,.10); color: inherit; }
  button:hover { background: rgba(128,128,128,.22); }
  #stage { overflow:auto; padding:18px; height: calc(100vh - 52px); }
  #canvas { width:1600px; height:1000px; transform-origin: top left; margin:0 auto; }
  .layer svg { display:block; width:1600px; height:1000px; border-radius:12px; }
  html[data-theme="light"] .l-dark { display:none; }
  html[data-theme="dark"] .l-light { display:none; }
  #zooml { font-size:12px; opacity:.75; min-width:44px; text-align:center; }
</style>
</head>
<body>
<header>
  <h1>dns-guard-stack 解析链架构</h1>
  <button id="bt" type="button">切换深 / 浅主题</button>
  <button id="zi" type="button">放大 +</button>
  <button id="zo" type="button">缩小 −</button>
  <button id="zr" type="button">重置 100%</button>
  <span id="zooml">100%</span>
  <span class="hint">滚轮或按钮缩放 · 由 gen-architecture.py 生成，请勿手改</span>
</header>
<main id="stage">
  <div id="canvas">
    <div class="layer l-light">__LIGHT__</div>
    <div class="layer l-dark">__DARK__</div>
  </div>
</main>
<script>
(function () {
  var root = document.documentElement;
  var canvas = document.getElementById('canvas');
  var stage = document.getElementById('stage');
  var label = document.getElementById('zooml');
  var scale = 1;
  function fitScale() {
    var avail = stage.clientWidth - 36;
    return Math.min(1, Math.max(0.3, avail / 1600));
  }
  function apply() {
    canvas.style.transform = 'scale(' + scale + ')';
    canvas.style.width = (1600 * scale) + 'px';
    canvas.style.height = (1000 * scale) + 'px';
    label.textContent = Math.round(scale * 100) + '%';
  }
  function zoom(f) {
    scale = Math.min(3, Math.max(0.3, scale * f));
    apply();
  }
  document.getElementById('bt').addEventListener('click', function () {
    root.dataset.theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
  });
  document.getElementById('zi').addEventListener('click', function () { zoom(1.15); });
  document.getElementById('zo').addEventListener('click', function () { zoom(1 / 1.15); });
  document.getElementById('zr').addEventListener('click', function () { scale = fitScale(); apply(); });
  stage.addEventListener('wheel', function (e) {
    e.preventDefault();
    zoom(e.deltaY < 0 ? 1.08 : 1 / 1.08);
  }, { passive: false });
  scale = fitScale();
  apply();
  window.addEventListener('resize', function () { scale = fitScale(); apply(); });
})();
</script>
</body>
</html>
"""


def render_html(light_svg: str, dark_svg: str) -> str:
    return HTML_TMPL.replace("__LIGHT__", light_svg).replace("__DARK__", dark_svg)


def render_png(svg_path: Path, png_path: Path) -> None:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page(viewport={"width": W, "height": H}, device_scale_factor=1)
        pg.goto(svg_path.as_uri())
        pg.wait_for_timeout(200)
        # 注意：对 SVG 文档用 full_page=True 会挂住 playwright，改为定尺 viewport 截图（正好 1600x1000）。
        pg.screenshot(path=str(png_path))
        b.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="生成 dns-guard-stack 架构图（SVG / HTML / 可选 PNG）")
    ap.add_argument("--png", action="store_true", help="同时用 playwright 渲染 1600px 宽 PNG")
    args = ap.parse_args()

    out = {}
    for theme in ("light", "dark"):
        svg = render_svg(PALETTES[theme])
        path = OUT_DIR / ("architecture-%s.svg" % theme)
        path.write_text(svg, encoding="utf-8")
        out[theme] = path
        print("wrote %s (%d bytes)" % (path.name, path.stat().st_size))

    html_path = OUT_DIR / "architecture.html"
    html_path.write_text(render_html(render_svg(PALETTES["light"]), render_svg(PALETTES["dark"])),
                         encoding="utf-8")
    print("wrote %s (%d bytes)" % (html_path.name, html_path.stat().st_size))

    if args.png:
        for theme in ("light", "dark"):
            png_path = OUT_DIR / ("architecture-%s.png" % theme)
            render_png(out[theme], png_path)
            print("wrote %s (%d bytes)" % (png_path.name, png_path.stat().st_size))
    return 0


if __name__ == "__main__":
    sys.exit(main())
