"""ProxyDog 抓取 / 订阅解析 / 验证 / 归属地。

能力概览：
- 订阅同时支持纯文本、base64、Clash YAML、JSON 数组；
- 解析时保留账号密码，支持 IPv6；
- 验证并发与超时可控，默认值按家用网络调低。
"""

import asyncio
import base64
import ipaddress
import json
import re
import ssl
import time
from urllib.parse import unquote, urlsplit

import aiohttp
import yaml
from aiohttp_socks import ProxyConnector

SUPPORTED = ("http", "https", "socks5")

# ── 抓取源注册表 ───────────────────────────────────────────────────────────
# 收录原则：
#   - 优先每天自动更新、头部即最近检测结果的仓库，取头部比随机抽样准得多；
#   - 只收纯文本 / JSON 这类好解析的清单，HTML 表格与需要登录的接口不收；
#   - 同一仓库的不同协议文件算作不同源，各自独立计上限。
#
# 每条：name（入库来源标签）/ url / protocol（行内没有 scheme 时的默认协议）
#       / cap（单源上限：清单头部的条数，按“最近检测”排序，取头比随机抽样更准）
SOURCES = [
    # —— 大型仓库，更新频繁，头部即最新检测结果 ——
    {"name": "ercin-http", "protocol": "http", "cap": 2000,
     "url": "https://cdn.jsdelivr.net/gh/ErcinDedeoglu/proxies@main/proxies/http.txt"},
    {"name": "ercin-socks5", "protocol": "socks5", "cap": 1500,
     "url": "https://cdn.jsdelivr.net/gh/ErcinDedeoglu/proxies@main/proxies/socks5.txt"},
    {"name": "aliilapro-http", "protocol": "http", "cap": 1500,
     "url": "https://cdn.jsdelivr.net/gh/ALIILAPRO/Proxy@main/http.txt"},
    {"name": "aliilapro-socks5", "protocol": "socks5", "cap": 1500,
     "url": "https://cdn.jsdelivr.net/gh/ALIILAPRO/Proxy@main/socks5.txt"},
    {"name": "proxy4parsing-http", "protocol": "http", "cap": 1500,
     "url": "https://cdn.jsdelivr.net/gh/proxy4parsing/proxy-list@main/http.txt"},
    {"name": "iplocate-http", "protocol": "http", "cap": 1200,
     "url": "https://cdn.jsdelivr.net/gh/iplocate/free-proxy-list@main/protocols/http.txt"},
    {"name": "iplocate-socks5", "protocol": "socks5", "cap": 1200,
     "url": "https://cdn.jsdelivr.net/gh/iplocate/free-proxy-list@main/protocols/socks5.txt"},
    # —— 带国家列（ip:port:Country），解析时只取前两段 ——
    {"name": "hideip-http", "protocol": "http", "cap": 800,
     "url": "https://cdn.jsdelivr.net/gh/zloi-user/hideip.me@main/http.txt"},
    {"name": "hideip-socks5", "protocol": "socks5", "cap": 1500,
     "url": "https://cdn.jsdelivr.net/gh/zloi-user/hideip.me@main/socks5.txt"},
    {"name": "hideip-https", "protocol": "https", "cap": 800,
     "url": "https://cdn.jsdelivr.net/gh/zloi-user/hideip.me@main/https.txt"},
    # —— 行内自带 scheme（http:// 或 https://），由 parse_line 识别 ——
    {"name": "anon1221-https", "protocol": "https", "cap": 1500,
     "url": "https://cdn.jsdelivr.net/gh/Anonym0usWork1221/Free-Proxies@main/proxy_files/http_proxies.txt"},
    # —— 非 GitHub 的公开接口，网络路径与上面完全独立 ——
    {"name": "openproxylist-http", "protocol": "http", "cap": 1500,
     "url": "https://api.openproxylist.xyz/http.txt"},
    {"name": "openproxylist-socks5", "protocol": "socks5", "cap": 1500,
     "url": "https://api.openproxylist.xyz/socks5.txt"},
    # —— 小型精选清单，量小但干净，用于补 diversity ——
    {"name": "rdavydov-http", "protocol": "http", "cap": 600,
     "url": "https://cdn.jsdelivr.net/gh/rdavydov/proxy-list@main/proxies/http.txt"},
    {"name": "themiralay-http", "protocol": "http", "cap": 800,
     "url": "https://cdn.jsdelivr.net/gh/themiralay/Proxy-List-World@master/data.txt"},
    {"name": "prxchk-http", "protocol": "http", "cap": 200,
     "url": "https://cdn.jsdelivr.net/gh/prxchk/proxy-list@main/http.txt"},
    {"name": "zaeem20-http", "protocol": "http", "cap": 300,
     "url": "https://cdn.jsdelivr.net/gh/Zaeem20/FREE_PROXIES_LIST@master/http.txt"},
    # —— 三张“更新最快、头部最干净”的大表：单源量大，配合严格验证能捞出更多好节点 ——
    {"name": "speedx-http", "protocol": "http", "cap": 2500,
     "url": "https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List@master/http.txt"},
    {"name": "speedx-socks5", "protocol": "socks5", "cap": 1500,
     "url": "https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List@master/socks5.txt"},
    {"name": "monosans-http", "protocol": "http", "cap": 2000,
     "url": "https://cdn.jsdelivr.net/gh/monosans/proxy-list@main/proxies/http.txt"},
    {"name": "monosans-socks5", "protocol": "socks5", "cap": 1200,
     "url": "https://cdn.jsdelivr.net/gh/monosans/proxy-list@main/proxies/socks5.txt"},
    {"name": "clarketm-http", "protocol": "http", "cap": 1500,
     "url": "https://cdn.jsdelivr.net/gh/clarketm/proxy-list@master/proxy-list-raw.txt"},
]

# 需要时可在设置里打开（GeoNode 接口默认关，按需开启）
GEONODE_API = ("https://proxylist.geonode.com/api/proxy-list"
               "?limit=500&page={page}&sort_by=lastChecked&sort_type=desc")
GEONODE_PAGES = 2

# ── 内置源运行时覆盖（面板上可 停用 / 编辑 / 删除，配置存 settings）─────────
# disabled：停用名单（自动/定时抓取跳过，单源「立即抓取」不受限）
# deleted ：删除名单（清单里彻底不出现，可整体恢复）
# edited  ：{源名: {url, cap}} 编辑覆盖（url / 条数上限）
OVERRIDES = {"disabled": [], "deleted": [], "edited": {}}


def apply_overrides(o):
    """app 启动 / 修改设置时灌入覆盖配置。"""
    OVERRIDES["disabled"] = [str(x) for x in (o or {}).get("disabled") or []]
    OVERRIDES["deleted"] = [str(x) for x in (o or {}).get("deleted") or []]
    OVERRIDES["edited"] = dict((o or {}).get("edited") or {})


def builtin_sources():
    """应用覆盖后的内置源清单（删除的不出现，编辑的换 url/cap）。"""
    out = []
    for s in SOURCES:
        if s["name"] in OVERRIDES["deleted"]:
            continue
        t = dict(s)
        ed = OVERRIDES["edited"].get(s["name"]) or {}
        if str(ed.get("url") or "").strip():
            t["url"] = str(ed["url"]).strip()
        try:
            t["cap"] = max(1, int(ed.get("cap") or t["cap"]))
        except (TypeError, ValueError):
            pass
        out.append(t)
    return out

# ── 抓取范围：内置国家 / 地区清单 ────────────────────────────────────────
# 代码用 ISO 3166-1 alpha-2：databay 的分国目录、GeoNode 的 country 参数都用它。
# 中文名统一从 geoip.COUNTRY_CN 取，保证和入库后的归属地标签字面一致（否则筛不上）。
COUNTRY_CODES = [
    # 中国及港澳台（单独列，方便只抓其中一个）
    "CN", "HK", "TW", "MO",
    # 亚太
    "JP", "KR", "SG", "MY", "TH", "VN", "PH", "ID", "IN", "PK", "BD", "LK",
    "NP", "MN", "KH", "LA", "MM", "BN", "MV", "AU", "NZ", "GU", "FJ",
    # 中东 / 中亚
    "AE", "SA", "IL", "TR", "IR", "IQ", "JO", "LB", "KW", "QA", "OM", "BH",
    "YE", "SY", "AF", "KZ", "UZ", "KG", "TJ", "AZ", "GE", "AM",
    # 欧洲
    "RU", "UA", "BY", "MD", "PL", "DE", "FR", "GB", "NL", "BE", "CH", "AT",
    "SE", "NO", "FI", "DK", "IE", "IT", "ES", "PT", "GR", "CZ", "SK", "HU",
    "RO", "BG", "RS", "HR", "SI", "BA", "MK", "ME", "AL", "LT", "LV", "EE",
    "CY", "MT", "IS", "LU",
    # 美洲
    "US", "CA", "MX", "BR", "AR", "CL", "CO", "PE", "VE", "EC", "UY", "PY",
    "BO", "CR", "PA", "GT", "DO", "PR",
    # 非洲
    "ZA", "EG", "NG", "KE", "MA", "TN", "DZ", "GH", "ET", "TZ", "MU", "SC",
]

# 分国清单：databay-labs 每个国家一个目录，http / socks5 两个文件
DATABAY_CC = ("https://cdn.jsdelivr.net/gh/databay-labs/free-proxy-list@master/"
              "by-country/{cc}/{proto}.txt")
# 一次最多按几个国家抓（每个国家 2 个清单，太多会拖慢一轮抓取）
MAX_SCOPE_COUNTRIES = 8
# 中国大陆/港澳台：判定「国内」用 CN，判定「国外」时把这四个都排除
CN_AREA = {"CN", "HK", "MO", "TW"}

_NAME2CODE = {}


def country_list():
    """给面板用的内置国家清单：[{code, name}]，name 与归属地标签同源。"""
    import geoip
    out = []
    for c in COUNTRY_CODES:
        out.append({"code": c, "name": geoip.COUNTRY_CN.get(c) or c})
    return out


def _name2code():
    if not _NAME2CODE:
        for item in country_list():
            _NAME2CODE[item["name"]] = item["code"]
    return _NAME2CODE


def ip_code(ip):
    """IP -> ISO 国家代码（查不到返回空串）。归属地库没就绪时一律返回空。"""
    try:
        import geoip
        label = geoip.lookup(ip)
    except Exception:
        return ""
    head = (label or "").split("-")[0].strip()
    if not head:
        return ""
    # 注意：中文也算 isalpha()，必须限定 ASCII 才当成 ISO 代码
    if len(head) == 2 and head.isascii() and head.isalpha():
        return head.upper()
    return _name2code().get(head, "")


def country_sources(codes):
    """按国家生成 databay 分国清单源（每个国家 http + socks5 两个）。"""
    out = []
    for cc in list(codes or [])[:MAX_SCOPE_COUNTRIES]:
        cc = str(cc or "").strip().lower()
        if not cc or not cc.isalpha():
            continue
        for proto in ("http", "socks5"):
            out.append({"name": f"databay-{cc}-{proto}", "protocol": proto, "cap": 800,
                        "url": DATABAY_CC.format(cc=cc, proto=proto)})
    return out


def filter_by_scope(rows, scope, countries=None):
    """按归属地把候选分成 国内 / 国外 / 指定国家。

    返回 (kept_rows, note)。note 非空时写进抓取报告，提示为什么没筛或筛掉多少。
    归属地库没就绪（一条都判定不了）时不筛，避免「过滤完 0 条」的误伤。
    """
    if scope in (None, "", "all"):
        return rows, ""
    import geoip
    if not geoip.ready():
        return rows, "归属地库未就绪，本次没有按国家筛选（去设置里下载地区库后再试）"
    codes = [str(c or "").strip().upper() for c in (countries or []) if str(c or "").strip()]
    if scope == "country" and not codes:
        return rows, "没有选择国家，本次按全部抓取"
    kept, unknown = [], 0
    for r in rows:
        code = ip_code(r.get("host", ""))
        if not code:
            unknown += 1
            if scope == "global":
                kept.append(r)          # 国外：判不了的先留下，交给后面的验证淘汰
            continue
        if scope == "cn":
            if code == "CN":
                kept.append(r)
        elif scope == "global":
            if code not in CN_AREA:
                kept.append(r)
        elif code in codes:
            kept.append(r)
    note = f"范围筛选后 {len(kept)}/{len(rows)} 条"
    if unknown:
        note += f"（{unknown} 条归属地未知）"
    return kept, note


# 实测不可达 / 已失效，留档备查（别再加回来）：
#   proxyscrape.com、proxy-list.download（301 到不了）、openproxy.space（521）、
#   free-proxy-list.net（HTML 表格）、mmpx12（返回 "error code: 502" 文本）、
#   mertguvencli / Mr8SAS / StKali / hpthai / ObcbO（jsDelivr 404）、
#   sunny9577（只有混合协议总表，无法区分 http/socks5）
DEAD_SOURCES = []

LAST_REPORT = []        # 最近一次抓取的逐源结果，供面板展示

_PROTO_RE = re.compile(r"^(?P<proto>[a-zA-Z][a-zA-Z0-9+.-]*)://(?P<rest>.+)$")
_HOST_PORT_RE = re.compile(r"^(?P<host>\[[0-9a-fA-F:]+\]|[^:\[\]]+):(?P<port>\d{1,5})")


def proxy_url(d):
    """把库里的记录拼成可用的上游地址。"""
    host = d["host"]
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if d.get("username"):
        auth = f"{d['username']}:{d.get('password') or ''}@"
        return f"{d['protocol']}://{auth}{host}:{d['port']}"
    return f"{d['protocol']}://{host}:{d['port']}"


def parse_line(line, default_protocol="http", source=""):
    """解析一行纯文本代理。支持：
    1.2.3.4:8080 / 1.2.3.4:8080:US / http://u:p@1.2.3.4:8080 / [2001:db8::1]:8080
    """
    line = (line or "").strip().strip("\ufeff")
    if not line or line.startswith("#") or line.startswith("//"):
        return None
    protocol = default_protocol
    rest = line
    m = _PROTO_RE.match(line)
    if m:
        protocol = m.group("proto").lower()
        rest = m.group("rest")
        if protocol not in SUPPORTED:
            return None
    # 去掉可能的路径 / 参数
    rest = rest.split("/")[0].split("?")[0]
    username = password = ""
    if "@" in rest:
        auth, rest = rest.rsplit("@", 1)
        if ":" in auth:
            username, password = auth.split(":", 1)
            username, password = unquote(username), unquote(password)
        else:
            username = unquote(auth)
    m = _HOST_PORT_RE.match(rest)
    if not m:
        return None
    host = m.group("host").strip("[]")
    try:
        port = int(m.group("port"))
    except ValueError:
        return None
    if not (1 <= port <= 65535):
        return None
    try:
        ipaddress.ip_address(host)          # 只收 IP，域名交给上游解析没意义
    except ValueError:
        return None
    return {"host": host, "port": port, "protocol": protocol,
            "username": username, "password": password, "source": source}


def parse_blob(text, source="import", report=None):
    """解析任意粘贴内容：纯文本 / base64 / Clash YAML / JSON / V2Ray JSON。

    report 传 dict 时带回统计：skipped（vmess/ss/trojan 等无法当 HTTP/SOCKS5
    上游的节点数）、clash、json（哪几种格式被识别）。
    """
    text = (text or "").strip()
    if not text:
        return []
    rows = []

    def note(k, n=1):
        if report is not None:
            report[k] = report.get(k, 0) + n

    # V2Ray / v2rayN 导出配置：outbounds 里的 socks / http 服务器
    if text[:1] == "{" and '"outbounds"' in text:
        try:
            data = json.loads(text)
            for ob in (data or {}).get("outbounds") or []:
                if not isinstance(ob, dict):
                    continue
                proto = str(ob.get("protocol", "")).lower()
                if proto == "socks":
                    proto = "socks5"
                if proto not in SUPPORTED:
                    continue
                for srv in ((ob.get("settings") or {}).get("servers") or []):
                    host = str(srv.get("address", "")).strip("[]")
                    try:
                        port = int(srv.get("port") or 0)
                    except (TypeError, ValueError):
                        continue
                    if host and 0 < port <= 65535:
                        users = srv.get("users") or [{}]
                        rows.append({
                            "host": host, "port": port, "protocol": proto,
                            "username": str(users[0].get("username", "") or "") if users else "",
                            "password": str(users[0].get("password", "") or "") if users else "",
                            "source": source})
            rows = [r for r in rows if r["host"] and 0 < r["port"] <= 65535]
            if rows:
                note("v2ray_json")
                return rows
        except Exception:
            pass

    # Clash / Mihomo
    if "proxies:" in text:
        try:
            data = yaml.safe_load(text)
            for item in (data or {}).get("proxies") or []:
                if not isinstance(item, dict):
                    continue
                ptype = str(item.get("type", "")).lower()
                if ptype not in SUPPORTED:
                    continue
                rows.append({
                    "host": str(item.get("server", "")).strip("[]"),
                    "port": int(item.get("port", 0)),
                    "protocol": ptype,
                    "username": str(item.get("username", "") or ""),
                    "password": str(item.get("password", "") or ""),
                    "source": source,
                })
            rows = [r for r in rows if r["host"] and 0 < r["port"] <= 65535]
            if rows:
                note("clash")
                return rows
        except Exception:
            pass

    # JSON：["1.2.3.4:8080", ...] 或 [{"ip":..,"port":..}]
    if text[:1] in "[{":
        try:
            data = json.loads(text)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, str):
                        r = parse_line(item, source=source)
                    elif isinstance(item, dict):
                        host = item.get("ip") or item.get("host") or item.get("server")
                        port = item.get("port")
                        proto = str(item.get("protocol") or item.get("type") or "http").lower()
                        if proto == "socks5h":
                            proto = "socks5"
                        r = {"host": str(host).strip("[]"), "port": int(port or 0),
                             "protocol": proto if proto in SUPPORTED else "http",
                             "username": item.get("username", "") or "",
                             "password": item.get("password", "") or "",
                             "source": source} if host and port else None
                    else:
                        r = None
                    if r:
                        rows.append(r)
            if rows:
                note("json")
                return rows
        except Exception:
            pass

    # base64（v2ray 订阅常见）
    compact = re.sub(r"\s+", "", text)
    if len(compact) > 32 and re.fullmatch(r"[A-Za-z0-9+/=_\-]+", compact):
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = decoder(compact + "=" * (-len(compact) % 4)).decode("utf-8", "ignore")
            except Exception:
                continue
            if "://" in decoded or ":" in decoded:
                for line in decoded.splitlines():
                    if line.strip().startswith(
                            ("vmess://", "vless://", "trojan://", "ss://",
                             "ssr://", "hysteria2://", "hysteria://", "tuic://")):
                        note("skipped")   # 这类不是 HTTP/SOCKS5 上游，无法直接当出口
                        continue
                    r = parse_line(line, source=source)
                    if r:
                        rows.append(r)
                if rows:
                    return rows
                if report is not None and report.get("skipped"):
                    return []

    for line in text.splitlines():
        if line.strip().startswith(
                ("vmess://", "vless://", "trojan://", "ss://", "ssr://",
                 "hysteria2://", "hysteria://", "tuic://")):
            note("skipped")
            continue
        r = parse_line(line, source=source)
        if r:
            rows.append(r)
    return rows


async def fetch_text(session, src, timeout=30, retries=1):
    """抓一个纯文本清单，解析到 cap 条就停（省流量也省验证配额）。

    openproxylist.xyz 这类接口时快时慢（实测 7s ~ 40s+），失败重试一次再判死。
    """
    url = src["url"]
    cap = int(src.get("cap") or 0)
    body, err = None, ""
    for attempt in range(retries + 1):
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                if resp.status != 200:
                    return [], f"HTTP {resp.status}"
                body = await resp.text(errors="ignore")
            break
        except Exception as exc:
            err = f"{exc.__class__.__name__}: {exc}"
            if attempt < retries:
                await asyncio.sleep(1.5)
    if body is None:
        return [], err
    rows = []
    for line in body.splitlines():
        r = parse_line(line, src["protocol"], src["name"])
        if r:
            rows.append(r)
            if cap and len(rows) >= cap:
                break
    return rows, None


async def fetch_geonode(session, countries=None):
    """GeoNode 公开接口。countries 非空时按国家查（接口原生支持 country 参数）。"""
    rows = []
    ccs = [str(c or "").strip().upper() for c in (countries or []) if str(c or "").strip()]
    targets = ccs[:MAX_SCOPE_COUNTRIES] or [None]
    pages = max(1, GEONODE_PAGES // len(targets)) if ccs else GEONODE_PAGES
    for cc in targets:
        for page in range(1, pages + 1):
            url = GEONODE_API.format(page=page) + (f"&country={cc}" if cc else "")
            try:
                async with session.get(url,
                                       timeout=aiohttp.ClientTimeout(total=25)) as resp:
                    if resp.status != 200:
                        continue
                    data = await resp.json(content_type=None)
            except Exception:
                continue
            for item in data.get("data") or []:
                proto = str(item.get("protocols") or item.get("protocol") or "http").lower()
                if proto == "socks5h":
                    proto = "socks5"
                if proto not in SUPPORTED:
                    continue
                rows.append({"host": item.get("ip", ""), "port": int(item.get("port") or 0),
                             "protocol": proto, "username": "", "password": "",
                             "source": "geonode"})
    return rows


async def fetch_all(max_total=6000, use_geonode=False, custom=None, only=None,
                    skip_builtin=False, scope="all", countries=None):
    """并发抓取全部源，返回 (rows, report)。report 每条：name/url/count/error。

    custom：自定义源配置列表（GitHub 仓库 / 空间测绘 API），为 None 时不跑自定义。
    only：只抓指定名称的内置源（列表页「立即抓取」按钮用），None 抓全部。
    skip_builtin：跳过全部内置源（单抓一个测绘 API 源时用，避免顺带跑内置清单）。
    scope / countries：抓取范围（all / cn / global / country），country 时用 ISO 代码。
        选了国家就额外跑该国的分国清单，并在抓完后按归属地复核一遍（兜住全球清单混进来的）。
    """
    global LAST_REPORT
    rows, report = [], []
    scope = scope or "all"
    ccs = [str(c or "").strip().upper() for c in (countries or []) if str(c or "").strip()]
    # 停用的内置源在常规抓取里跳过；单源「立即抓取」（only 指定）属明确意图，照跑
    src_list = [s for s in builtin_sources()
                if only or s["name"] not in OVERRIDES["disabled"]]
    src_list = [s for s in src_list if not only or s["name"] == only]
    if skip_builtin:
        # 单抓一个测绘源时不该顺带跑几十个内置清单：那样既慢，又会把一堆
        # 无关的免费节点灌进库，把「这个源到底抓到多少」的统计冲掉
        src_list = []
    if not only:
        # 分国清单：把「国内 / 指定国家」落到具体的国家级清单上，命中率比全球清单高得多
        if scope == "cn":
            src_list = src_list + country_sources(["CN"])
        elif scope == "country" and ccs:
            src_list = src_list + country_sources(ccs)
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ProxyDog/1.4"}
    async with aiohttp.ClientSession(headers=headers) as session:
        results = await asyncio.gather(
            *(fetch_text(session, src) for src in src_list), return_exceptions=True)
        for src, res in zip(src_list, results):
            if isinstance(res, Exception):
                report.append({"name": src["name"], "url": src["url"],
                               "count": 0, "error": res.__class__.__name__})
                continue
            items, err = res
            report.append({"name": src["name"], "url": src["url"],
                           "count": len(items), "error": err or ""})
            rows.extend(items)
        if use_geonode:
            geo_cc = ["CN"] if scope == "cn" else (ccs if scope == "country" else None)
            try:
                geo = await fetch_geonode(session, geo_cc)
                report.append({"name": "geonode", "url": GEONODE_API.split("?")[0],
                               "count": len(geo), "error": ""})
                rows.extend(geo)
            except Exception as exc:
                report.append({"name": "geonode", "url": GEONODE_API.split("?")[0],
                               "count": 0, "error": str(exc)})
        # 抓取插件（plugins/*.py）：目录里丢一个文件就多一个源，热重载由 plugins 自己盯
        try:
            import plugins as _pl
            if _pl._GLOBAL_ON and not skip_builtin:
                p_rows, p_rep = await _pl.fetch_plugin_rows(session)
                rows.extend(p_rows)
                report.extend(p_rep)
        except Exception as exc:
            report.append({"name": "插件目录", "url": "", "count": 0,
                           "error": f"{exc.__class__.__name__}: {exc}"})
        # 自定义源（延迟导入，避免与 apisources 循环依赖）
        if custom:
            from apisources import fetch_custom
            try:
                items, rep = await fetch_custom(session, custom)
                rows.extend(items)
                report.extend(rep)
            except Exception as exc:
                report.append({"name": "自定义源", "url": "", "count": 0,
                               "error": f"{exc.__class__.__name__}: {exc}", "custom": True})

    seen, uniq = set(), []
    for r in rows:
        key = (r["host"], r["port"], r["protocol"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(r)
    if scope != "all":
        uniq, note = filter_by_scope(uniq, scope, ccs)
        report.append({"name": "范围筛选", "url": "", "count": len(uniq), "error": note})
    if max_total and len(uniq) > max_total:
        import random
        uniq = random.sample(uniq, max_total)
    LAST_REPORT = report
    return uniq, report


def source_catalog():
    """给面板用：源清单（应用停用/编辑/删除后）+ 停用标记。"""
    return [{"name": s["name"], "url": s["url"], "protocol": s["protocol"],
             "cap": s["cap"], "enabled": s["name"] not in OVERRIDES["disabled"]}
            for s in builtin_sources()]


async def check_one(d, test_url, timeout, anon_echo_url="", probe_https=True,
                    test_keyword="", public_ip=""):
    """真发一次请求判断可用性。

    返回 (ok, delay_ms, anon, https_ok)：
    - anon: elite / anonymous / transparent / ''（未知）
    - https_ok: 1/0，出口能否 CONNECT https 目标
    anon_echo_url 非空且请求成功时，一次请求同时得到匿名度与 https 结论
    （echo 用 https 地址，能通就说明出口支持 CONNECT 443）。
    test_keyword 非空时，响应体必须包含该字符串才算可用（防"能通但被劫持"）。
    public_ip 是本机公网出口 IP（匿名判断的基准）：echo 返回的来源 IP 等于它
    就是透明代理；不知道本机 IP 时只能靠 X-Forwarded-For 头判断。
    """
    url = proxy_url(d)
    t0 = time.perf_counter()
    ok = False
    body = b""
    try:
        if d["protocol"] == "socks5":
            connector = ProxyConnector.from_url(url, rdns=True)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(test_url,
                                       timeout=aiohttp.ClientTimeout(total=timeout),
                                       ssl=False) as resp:
                    body = await resp.read()
                    ok = resp.status < 400
        elif d["protocol"] == "https":
            ok = await _check_https_proxy(d, test_url, timeout)
        else:
            async with aiohttp.ClientSession() as session:
                async with session.get(test_url, proxy=url,
                                       timeout=aiohttp.ClientTimeout(total=timeout),
                                       ssl=False) as resp:
                    body = await resp.read()
                    ok = resp.status < 400
    except Exception:
        return False, None, "", 0, ""
    if ok and test_keyword and test_keyword not in body.decode("utf-8", "ignore"):
        ok = False                  # 能通但内容对不上：劫持/防火墙页面，按失败算
    delay = round((time.perf_counter() - t0) * 1000, 1)
    anon, https_ok, real_ip = "", 0, ""
    if ok:
        if anon_echo_url:
            try:
                anon, https_ok, real_ip = await _probe_anon(d, anon_echo_url, timeout,
                                                            public_ip=public_ip)
            except Exception:
                anon, https_ok, real_ip = "", 0, ""
        if not https_ok and probe_https:
            try:
                https_ok = 1 if await _probe_https(d, timeout) else 0
            except Exception:
                https_ok = 0
    return ok, delay, anon, https_ok, real_ip


async def _session_for(d):
    """按出口协议造一个 aiohttp 会话（http 代理用 proxy=，socks5 用 connector）。"""
    if d["protocol"] == "socks5":
        return aiohttp.ClientSession(
            connector=ProxyConnector.from_url(proxy_url(d), rdns=True))
    return aiohttp.ClientSession()


async def _req_via(session, d, url, timeout):
    """带出口发一次 GET；https 协议出口要手工 TLS+CONNECT，不能直接 proxy=。"""
    if d["protocol"] == "https":
        okc = await _check_https_proxy(d, url, timeout)
        return okc, b""
    kwargs = dict(timeout=aiohttp.ClientTimeout(total=timeout), ssl=False)
    if d["protocol"] == "http":
        kwargs["proxy"] = proxy_url(d)
    async with session.get(url, **kwargs) as resp:
        return resp.status < 400, await resp.read()


def _exit_ip(text):
    """从 echo 响应里取「目标实际看到的出口 IP」。

    httpbin 系返回 {"origin": "1.2.3.4, 5.6.7.8"}：origin 链最后一跳才是真正
    到达目标的地址；纯 IP 回显站点（icanhazip / ipinfo 纯文本）整个响应就是 IP。
    """
    m = re.search(r'"origin"\s*:\s*"([^"]*)"', text)
    if m:
        chain = re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", m.group(1))
        if chain:
            return chain[-1]
    ips = re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text)
    return ips[0] if ips else ""


async def _probe_anon(d, echo_url, timeout, public_ip=""):
    """通过出口访问 echo 服务：判匿名程度 + 顺手取出口真实 IP。

    elite        —— 看不出任何代理痕迹
    anonymous    —— 有 Via/Forwarded 这类头，但没暴露客户端真实 IP
    transparent  —— 暴露了真实 IP（X-Forwarded-For 或返回的来源 IP == 本机公网 IP）
    返回 (anon, https_ok, real_ip)；real_ip 是目标看到的出口 IP（取不到为空）。
    """
    async with await _session_for(d) as session:
        ok, body = await _req_via(session, d, echo_url, timeout)
    if not ok:
        return "", 0, ""
    https_ok = 1 if echo_url.lower().startswith("https://") else 0
    text = body.decode("utf-8", "ignore")
    low = text.lower()
    real_ip = _exit_ip(text)
    # 本机公网 IP 已知时：echo 回显的来源 IP == 本机 IP => 一眼穿透（透明代理）
    if public_ip:
        m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text)
        if m and m.group(1) == public_ip:
            return "transparent", https_ok, real_ip
    # httpbin 返回 JSON 的 "headers": {...}；azenv 之类是纯文本头，都按字符串找
    xff = ""
    for key in ("x-forwarded-for", "forwarded", "client-ip", "via", "proxy-connection",
                "x-proxy-id", "proxy-agent"):
        if key in low:
            if key in ("x-forwarded-for", "client-ip", "forwarded"):
                xff = key
    if xff:
        return "transparent", https_ok, real_ip
    if "via" in low or "proxy-agent" in low or "proxy-connection" in low:
        return "anonymous", https_ok, real_ip
    return "elite", https_ok, real_ip


async def _probe_https(d, timeout):
    """出口能否 CONNECT 到 443（http/socks5 用 https GET 验证）。"""
    async with await _session_for(d) as session:
        ok, _ = await _req_via(session, d, "https://www.baidu.com", timeout)
    return ok


async def _check_https_proxy(d, test_url, timeout):
    """https:// 出口：先与代理做 TLS，再发 CONNECT 看是否 2xx。

    aiohttp 的 proxy= 只认 http://，https 出口会被误判成不可用，所以单独走一遍。
    """
    target = urlsplit(test_url)
    thost = target.hostname or ""
    tport = target.port or (443 if target.scheme == "https" else 80)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(d["host"], int(d["port"]), ssl=ctx), timeout)
    try:
        head = f"CONNECT {thost}:{tport} HTTP/1.1\r\nHost: {thost}:{tport}\r\n"
        if d.get("username"):
            auth = f"{d['username']}:{d.get('password') or ''}".encode()
            head += "Proxy-Authorization: Basic " + base64.b64encode(auth).decode() + "\r\n"
        writer.write((head + "\r\n").encode("latin1"))
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout)
        parts = line.split()
        return len(parts) >= 2 and parts[1][:1] == b"2"
    finally:
        writer.close()


# 检测节流（照 ProxyCat 三参数）的进程级状态
_CHECK_CACHE = {}      # (host, port, proto) -> (ts, ok, delay, anon, hok)
_CHECK_LAST = {}       # (host, port, proto) -> 上次开始检测的时间戳
_CHECK_HOST_LAST = {}  # host -> 上次开始检测的时间戳（重复出口最小间隔）


async def validate_many(items, test_url, timeout=8, concurrency=80,
                        anon_echo_url="", probe_https=True, test_keyword="",
                        public_ip="", cache_s=0, min_iv=0, dup_iv=0):
    """items: [(id, dict)]，返回 [(id, ok, delay, anon, https_ok, real_ip)]

    检测节流三参数（照 ProxyCat，都传 0 = 不启用）：
    - cache_s  检测结果缓存秒数：缓存期内直接复用上次结果，不发请求
    - min_iv   同一出口两次检测的最小间隔（秒），太早的顺延
    - dup_iv   重复出口（同 host）两次检测的最小间隔（秒），错峰防打爆同一台机器
    """
    sem = asyncio.Semaphore(max(1, concurrency))
    out = []

    async def worker(pid, d):
        key = (str(d.get("host")), int(d.get("port") or 0), str(d.get("protocol")))
        now = time.time()
        if cache_s and cache_s > 0:
            cached = _CHECK_CACHE.get(key)
            if cached and now - cached[0] < cache_s:
                out.append((pid,) + cached[1])
                return
        async with sem:
            wait = 0.0
            la = _CHECK_LAST.get(key)
            if min_iv and la is not None:
                wait = max(wait, la + min_iv - time.time())
            lh = _CHECK_HOST_LAST.get(key[0])
            if dup_iv and lh is not None:
                wait = max(wait, lh + dup_iv - time.time())
            if wait > 0:
                await asyncio.sleep(min(wait, 20))
            _CHECK_LAST[key] = time.time()
            _CHECK_HOST_LAST[key[0]] = time.time()
            ok, delay, anon, hok, real_ip = await check_one(
                d, test_url, timeout, anon_echo_url, probe_https, test_keyword,
                public_ip)
            if cache_s and cache_s > 0:
                _CHECK_CACHE[key] = (time.time(), (ok, delay, anon, hok, real_ip))
            out.append((pid, ok, delay, anon, hok, real_ip))

    await asyncio.gather(*(worker(pid, d) for pid, d in items))
    return out
