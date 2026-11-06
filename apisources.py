"""自定义抓取源：GitHub 仓库发现 + 空间测绘 API。

为什么单独一个模块：
- sources.py 里那批源是"已知的纯文本清单地址"，抓下来按行解析就行；
- 这里的源形态完全不同——
  · GitHub 仓库要先**发现**仓库里哪个文件是清单（不同仓库命名五花八门）；
  · 空间测绘（FOFA / 鹰图 / Quake / Shodan / ZoomEye）要凭证、要查询语法，
    返回的是"疑似在跑代理的 IP:端口"，还得反推协议。

统一出口都是 [(host, port, protocol, ...)]，交给 store.add_many 入库，
再由验证环节筛掉绝大多数误报——空间测绘的准确率天然不高，这是它的工作方式。
"""

import asyncio
import base64
import datetime
import json
import math
import re
from urllib.parse import quote, urlsplit

import aiohttp

from sources import SUPPORTED, parse_blob

# ── 提供商元信息：前端据此渲染表单，后端据此校验 ──────────────────────────
PROVIDERS = {
    "github": {
        "label": "GitHub 仓库",
        "kind": "repo",
        "desc": "填 owner/repo 或仓库地址，自动发现 http.txt / socks5.txt 等清单文件",
        "creds": [],
        "sample": "ErcinDedeoglu/proxies",
        "hint": "走 jsDelivr 镜像，国内可直连，不消耗 GitHub API 配额",
    },
    "url": {
        "label": "自定义清单地址",
        "kind": "url",
        "desc": "任意纯文本 / base64 / Clash YAML / JSON 订阅地址",
        "creds": [],
        "sample": "https://example.com/proxies.txt",
        "hint": "支持 http://、https:// 开头的直链",
    },
    "fofa": {
        "label": "FOFA",
        "kind": "api",
        "desc": "fofa.info 空间测绘，用 base64 查询语法搜代理特征",
        "creds": ["key"],
        "optional_creds": ["email"],
        "sample": 'protocol="http" && (header="Proxy-Agent" || body="Proxy")',
        "hint": "新账号只用 key 即可；老账号若报「email 不能为空」再补上邮箱。免费账号每次 100 条",
        "console": "https://fofa.info/userInfo",
    },
    "hunter": {
        "label": "鹰图 Hunter",
        "kind": "api",
        "desc": "hunter.qianxin.com 奇安信空间测绘",
        "creds": ["key"],
        "sample": 'protocol=="http" && web.body="Proxy"',
        "hint": "每页 20 条，消耗积分；时间窗口默认最近 30 天",
        "console": "https://hunter.qianxin.com/home/userInfo",
    },
    "quake": {
        "label": "Quake 360",
        "kind": "api",
        "desc": "quake.360.net 网络空间测绘",
        "creds": ["key"],
        "sample": 'response:"Proxy-Agent"',
        "hint": "单次最多 500 条，免费账号有额度限制",
        "console": "https://quake.360.net/quake/#/personalInfo",
    },
    "shodan": {
        "label": "Shodan",
        "kind": "api",
        "desc": "shodan.io 设备搜索引擎",
        "creds": ["key"],
        "sample": '"Proxy-Agent" http',
        "hint": "免费 key 仅 100 结果/月，建议只做补充",
        "console": "https://account.shodan.io/",
    },
    "zoomeye": {
        "label": "ZoomEye 钟馗之眼",
        "kind": "api",
        "desc": "zoomeye.org 知道创宇空间测绘",
        "creds": ["key"],
        "sample": '"Proxy-Agent"',
        "hint": "用 API-KEY 请求头认证，免费账号有查询额度",
        "console": "https://www.zoomeye.org/profile",
    },
}

# 空间测绘的常见误报提醒（面板上给用户看）
PROVIDER_NOTICE = (
    "空间测绘返回的是「疑似在跑代理的 IP:端口」，准确率通常只有个位数百分比，"
    "所有结果都会走一次真实请求验证后才算有效出口。查询语句建议带上代理特征"
    "（Proxy-Agent、Proxy-Authenticate 等），能显著提高命中率。"
)

# ── GitHub 仓库：怎么从一堆文件里认出哪个是清单 ────────────────────────────
EXACT_HINTS = (
    "http.txt", "https.txt", "socks5.txt", "all.txt",
    "proxies.txt", "proxy.txt", "proxy_list.txt", "proxylist.txt",
    "http_proxies.txt", "https_proxies.txt", "socks5_proxies.txt",
    "http_proxy.txt", "socks5_proxy.txt",
)
KEYWORD_HINTS = ("proxy", "proxies", "socks", "http")
BAD_EXT = (".md", ".go", ".py", ".js", ".ts", ".html", ".png", ".jpg", ".gif",
           ".svg", ".ico", ".zip", ".tar", ".gz", ".exe", ".mod", ".sum",
           ".yml.example", ".lock")
GOOD_EXT = (".txt", ".json", ".yaml", ".yml", ".csv")

MAX_REPO_FILES = 6          # 一个仓库最多抓几个清单文件
MAX_FILE_BYTES = 3_000_000  # 单个文件超过 3MB 不抓（有的仓库塞了几十万行）

_IP_PORT = re.compile(r"^(?P<host>\[[0-9a-fA-F:]+\]|[^:\[\]]+):(?P<port>\d{1,5})$")


def _norm_proto(value):
    """把各家五花八门的协议名收敛到 SUPPORTED 里的三种。"""
    v = str(value or "").strip().lower()
    if not v:
        return ""
    if "socks" in v:
        return "socks5"
    if v in ("https", "http-ssl", "http/ssl", "ssl", "tls"):
        return "https"
    if "http" in v:
        return "http"
    return ""


def _split_addr(addr):
    """'1.2.3.4:8080' / '[2001:db8::1]:8080' → (host, port)"""
    m = _IP_PORT.match(str(addr or "").strip())
    if not m:
        return None, 0
    try:
        port = int(m.group("port"))
    except ValueError:
        return None, 0
    if not 1 <= port <= 65535:
        return None, 0
    return m.group("host").strip("[]"), port


def _apply_auto(rows, cfg, known_proto):
    """cfg=auto 且路径判断不出协议时，同一地址生成 http + socks5 两条。

    目录已经能判定（例如 /socks5/ 下）就保留原判定，不要凭空多出一条。
    """
    if (cfg.get("protocol") or "").lower() != "auto" or known_proto:
        return rows
    out = []
    for r in rows:
        out.append(dict(r, protocol="http"))
        out.append(dict(r, protocol="socks5"))
    return out


def _row(host, port, proto, source):
    if not host or not port:
        return None
    proto = _norm_proto(proto) or "http"
    if proto not in SUPPORTED:
        return None
    return {"host": str(host).strip("[]"), "port": int(port), "protocol": proto,
            "username": "", "password": "", "source": source}


def _expand(host, port, proto_hint, cfg):
    """按配置决定生成几条候选。

    protocol=auto 时同时塞 http 和 socks5 两条——同一端口可能就是两种服务之一，
    让验证环节去判定比猜更靠谱（代价是验证量翻倍，所以默认不是 auto）。
    """
    want = (cfg.get("protocol") or "http").lower()
    out = []
    if want == "auto":
        inferred = _norm_proto(proto_hint)
        if inferred:
            out.append(_row(host, port, inferred, cfg["name"]))
        else:
            out.append(_row(host, port, "http", cfg["name"]))
            out.append(_row(host, port, "socks5", cfg["name"]))
    else:
        out.append(_row(host, port, _norm_proto(proto_hint) or want, cfg["name"]))
    return [r for r in out if r]


# ── GitHub ────────────────────────────────────────────────────────────────
def parse_repo_spec(spec):
    """'owner/repo' / 'https://github.com/owner/repo' / '.../tree/branch/sub' →
    (owner, repo, branch, subdir)"""
    spec = (spec or "").strip().rstrip("/")
    if not spec:
        return None, None, "", ""
    if spec.startswith("http"):
        parts = urlsplit(spec)
        seg = [s for s in parts.path.split("/") if s]
        if len(seg) < 2:
            return None, None, "", ""
        owner, repo = seg[0], seg[1].replace(".git", "")
        branch, sub = "", ""
        if len(seg) >= 4 and seg[2] in ("tree", "blob"):
            branch = seg[3]
            sub = "/".join(seg[4:])
        return owner, repo, branch, sub
    seg = [s for s in spec.split("/") if s]
    if len(seg) < 2:
        return None, None, "", ""
    if len(seg) >= 4 and seg[2] in ("tree", "blob"):
        return seg[0], seg[1].replace(".git", ""), seg[3], "/".join(seg[4:])
    return seg[0], seg[1].replace(".git", ""), "", ""


async def _list_repo(session, owner, repo, branch=""):
    """用 jsDelivr 的数据接口列文件（不消耗 GitHub API 配额，国内可直连）。"""
    refs = [branch] if branch else ["main", "master", "HEAD"]
    last = ""
    for ref in refs:
        url = (f"https://data.jsdelivr.com/v1/packages/gh/"
               f"{owner}/{repo}@{quote(ref)}?structure=flat")
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                if resp.status != 200:
                    last = f"仓库或分支不存在（HTTP {resp.status}）"
                    continue
                data = await resp.json(content_type=None)
        except Exception as exc:
            last = f"{exc.__class__.__name__}: {str(exc)[:80]}"
            continue
        files = [f.get("name", "") for f in (data.get("files") or []) if f.get("name")]
        if files:
            return files, ref, ""
    return [], "", last or "无法读取仓库文件列表"


def _pick_files(files, subdir=""):
    """从仓库文件树里挑出可能是清单的文件，按可能性排序。"""
    scored = []
    for path in files:
        low = path.lower()
        if subdir and not low.lstrip("/").startswith(subdir.lower().lstrip("/")):
            continue
        if low.endswith(BAD_EXT):
            continue
        if "socks4" in low and "socks5" not in low:
            continue          # socks4 不是受支持的出口类型
        base = low.rsplit("/", 1)[-1]
        score = 0
        if base in EXACT_HINTS:
            score += 100
        elif any(k in base for k in KEYWORD_HINTS):
            score += 45
        if any(k in low for k in KEYWORD_HINTS):
            score += 20
        if low.endswith(GOOD_EXT):
            score += 15
        if "/proxies/" in low or "/protocols/" in low:
            score += 20
        if score <= 0:
            continue
        scored.append((score, path))
    scored.sort(key=lambda x: (-x[0], len(x[1])))   # 同分优先浅路径
    return [p for _, p in scored[:MAX_REPO_FILES]]


def _proto_from_path(path, fallback=""):
    """按文件路径猜协议；猜不出来返回 ""（交给 cfg 的兜底逻辑决定）。"""
    low = path.lower()
    if "socks5" in low:
        return "socks5"
    if "https" in low:
        return "https"
    if "http" in low:
        return "http"
    return fallback


async def fetch_github(session, cfg):
    owner, repo, branch, subdir = parse_repo_spec(cfg.get("target"))
    if not owner or not repo:
        return [], "仓库格式应为 owner/repo"
    files, ref, err = await _list_repo(session, owner, repo, branch)
    if err:
        return [], err
    picks = _pick_files(files, subdir)
    if not picks:
        return [], "仓库里没找到清单文件（需要 http.txt / socks5.txt / proxies.txt 之类）"

    cap = max(1, int(cfg.get("cap") or 300))
    per = max(50, cap // len(picks))
    rows = []
    errors = []
    for path in picks:
        url = f"https://cdn.jsdelivr.net/gh/{owner}/{repo}@{ref}{path}"
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=40)) as resp:
                if resp.status != 200:
                    errors.append(f"{path}: HTTP {resp.status}")
                    continue
                body = await resp.text(errors="ignore")
        except Exception as exc:
            errors.append(f"{path}: {exc.__class__.__name__}")
            continue
        if len(body) > MAX_FILE_BYTES:
            body = body[:MAX_FILE_BYTES]
        inferred = _proto_from_path(path)
        proto = inferred or (cfg.get("protocol") or "http")
        if proto == "auto":
            proto = "http"
        items = parse_blob(body, source=cfg["name"]) if path.lower().endswith(
            (".json", ".yaml", ".yml")) else _parse_lines(body, proto, cfg["name"])
        # 先按配额截断再展开，否则 auto 会把配额吃掉一半
        rows.extend(_apply_auto(items[:per], cfg, bool(inferred)))
    if not rows and errors:
        return [], "；".join(errors[:2])
    return rows[:cap * 2], ""


def _parse_lines(body, proto, source):
    """纯文本清单：逐行解析，兼容 ip:port:country 这种多列格式。"""
    from sources import parse_line
    out = []
    for line in body.splitlines():
        r = parse_line(line, proto, source)
        if r:
            out.append(r)
    return out


# ── 空间测绘：通用请求工具 ────────────────────────────────────────────────
def _clean_err(text):
    """接口报错时经常回一整页 HTML，剥成一句话再看。"""
    t = str(text or "")
    t = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", t, flags=re.S | re.I)
    t = re.sub(r"<[^>]+>", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t[:140]


async def _get_json(session, url, params=None, headers=None, timeout=25):
    async with session.get(url, params=params, headers=headers,
                           timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
        text = await resp.text(errors="ignore")
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status}: {_clean_err(text)}")
        try:
            return json.loads(text)
        except ValueError:
            raise RuntimeError(f"返回不是 JSON: {_clean_err(text)}")


async def _post_json(session, url, payload, headers=None, timeout=25):
    async with session.post(url, json=payload, headers=headers,
                            timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
        text = await resp.text(errors="ignore")
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status}: {_clean_err(text)}")
        try:
            return json.loads(text)
        except ValueError:
            raise RuntimeError(f"返回不是 JSON: {_clean_err(text)}")


def _need(creds, *names):
    missing = [n for n in names if not str(creds.get(n) or "").strip()]
    return missing


# ── FOFA ──────────────────────────────────────────────────────────────────
async def fetch_fofa(session, cfg):
    creds = cfg.get("creds") or {}
    miss = _need(creds, "key")
    if miss:
        return [], "缺少 FOFA key"
    query = (cfg.get("query") or "").strip() or 'protocol="http" && body="Proxy"'
    cap = max(1, int(cfg.get("cap") or 300))
    qbase64 = base64.b64encode(query.encode()).decode()
    rows = []
    masked = 0                 # 免费账号返回的 IP 是打码的（164.*.*.*），没法用
    page = 1
    while len(rows) < cap and page <= 20:
        size = min(100, cap - len(rows))
        params = {"qbase64": qbase64, "key": str(creds["key"]).strip(),
                  "page": page, "size": size, "fields": "host,protocol"}
        if creds.get("email"):
            params["email"] = str(creds["email"]).strip()
        try:
            data = await _get_json(session, "https://fofa.info/api/v1/search/all", params)
        except RuntimeError as exc:
            if page == 1:
                return rows, str(exc)
            break
        if data.get("error"):
            msg = data.get("errmsg") or "FOFA 返回错误"
            # 免费账号不允许 protocol 字段：降级为只取 host 再试一次
            if "field" in msg.lower() and "protocol" in params["fields"]:
                params["fields"] = "host"
                try:
                    data = await _get_json(session, "https://fofa.info/api/v1/search/all", params)
                    msg = data.get("errmsg") or msg
                except RuntimeError as exc:
                    return rows, str(exc)
                if not data.get("error"):
                    for item in data.get("results") or []:
                        host, port = _split_addr(item if isinstance(item, str) else item[0])
                        rows.extend(_expand(host, port, "", cfg))
                    break
            return rows, msg
        results = data.get("results") or []
        if not results:
            break
        for item in results:
            if isinstance(item, list):
                addr = item[0]
                hint = item[1] if len(item) > 1 else ""
            else:
                addr, hint = item, ""
            host, port = _split_addr(addr)
            if "*" in host or not host:
                masked += 1          # FOFA 对免费账号打码 IP：164.*.*.*
                continue
            rows.extend(_expand(host, port, hint, cfg))
        page += 1
        await asyncio.sleep(0.4)          # 免费账号有 QPS 限制
    if rows:
        return rows[:cap * 2], ""
    if masked:
        return [], (f"FOFA 返回的 {masked} 条结果 IP 全是打码的（如 164.*.*.*），"
                    "免费账号拿不到完整 IP；到 fofa.info 注册并充值会员（或用会员 key）才能用")
    return [], "没有解析到可用的 http/socks5 地址"


# ── 鹰图 Hunter ───────────────────────────────────────────────────────────
async def fetch_hunter(session, cfg):
    creds = cfg.get("creds") or {}
    if _need(creds, "key"):
        return [], "缺少 Hunter key"
    query = (cfg.get("query") or "").strip() or 'protocol=="http" && web.body="Proxy"'
    cap = max(1, int(cfg.get("cap") or 300))
    search = base64.urlsafe_b64encode(query.encode()).decode().rstrip("=")
    today = datetime.date.today()
    start = (today - datetime.timedelta(days=29)).isoformat()
    end = today.isoformat()
    rows, page = [], 1
    pages = min(10, math.ceil(cap / 20))
    while page <= pages:
        params = {"api-key": str(creds["key"]).strip(), "search": search,
                  "page": page, "page_size": 20, "is_web": 3,
                  "start_time": start, "end_time": end}
        try:
            data = await _get_json(session, "https://hunter.qianxin.com/openApi/search", params)
        except RuntimeError as exc:
            if page == 1:
                return rows, str(exc)
            break
        if int(data.get("code") or 0) != 200:
            msg = data.get("message") or f"Hunter code={data.get('code')}"
            if page == 1:
                return rows, msg
            break
        arr = ((data.get("data") or {}).get("arr")) or []
        if not arr:
            break
        for item in arr:
            host = item.get("ip") or ""
            port = item.get("port") or 0
            try:
                port = int(port)
            except (TypeError, ValueError):
                continue
            rows.extend(_expand(host, port, item.get("protocol"), cfg))
        page += 1
        await asyncio.sleep(1.0)          # 积分敏感，别打太快
    return rows[:cap * 2], ""


# ── Quake 360 ─────────────────────────────────────────────────────────────
async def fetch_quake(session, cfg):
    creds = cfg.get("creds") or {}
    if _need(creds, "key"):
        return [], "缺少 Quake key"
    query = (cfg.get("query") or "").strip() or 'response:"Proxy-Agent"'
    cap = max(1, int(cfg.get("cap") or 300))
    rows, start = [], 0
    while len(rows) < cap and start < 1000:
        size = min(100, cap - len(rows))
        payload = {"query": query, "start": start, "size": size, "ignore_cache": False}
        try:
            data = await _post_json(
                session, "https://quake.360.net/api/v3/search/quake_service", payload,
                headers={"X-QuakeToken": str(creds["key"]).strip()})
        except RuntimeError as exc:
            if start == 0:
                return rows, str(exc)
            break
        if int(data.get("code") or 0) != 0:
            msg = data.get("message") or f"Quake code={data.get('code')}"
            if start == 0:
                return rows, msg
            break
        items = data.get("data") or []
        if not items:
            break
        for item in items:
            host = item.get("ip") or (item.get("location") or {}).get("ip")
            try:
                port = int(item.get("port") or 0)
            except (TypeError, ValueError):
                continue
            svc = item.get("service") or {}
            hint = svc.get("name") if isinstance(svc, dict) else ""
            rows.extend(_expand(host, port, hint, cfg))
        start += len(items)
        await asyncio.sleep(0.6)
    return rows[:cap * 2], ""


# ── Shodan ────────────────────────────────────────────────────────────────
async def fetch_shodan(session, cfg):
    creds = cfg.get("creds") or {}
    if _need(creds, "key"):
        return [], "缺少 Shodan key"
    query = (cfg.get("query") or "").strip() or '"Proxy-Agent" http'
    cap = max(1, int(cfg.get("cap") or 100))
    rows, page = [], 1
    while len(rows) < cap and page <= 5:
        params = {"key": str(creds["key"]).strip(), "query": query, "page": page}
        try:
            data = await _get_json(session, "https://api.shodan.io/shodan/host/search", params)
        except RuntimeError as exc:
            if page == 1:
                return rows, str(exc)
            break
        if data.get("error"):
            if page == 1:
                return rows, str(data["error"])[:150]
            break
        for item in data.get("matches") or []:
            rows.extend(_expand(item.get("ip_str"), item.get("port"), "", cfg))
        if not data.get("matches"):
            break
        page += 1
        await asyncio.sleep(1.0)
    return rows[:cap * 2], ""


# ── ZoomEye ───────────────────────────────────────────────────────────────
async def fetch_zoomeye(session, cfg):
    creds = cfg.get("creds") or {}
    if _need(creds, "key"):
        return [], "缺少 ZoomEye API-KEY"
    query = (cfg.get("query") or "").strip() or '"Proxy-Agent"'
    cap = max(1, int(cfg.get("cap") or 200))
    rows, page = [], 1
    while len(rows) < cap and page <= 10:
        params = {"query": query, "page": page, "pagesize": min(100, cap - len(rows))}
        try:
            data = await _get_json(session, "https://api.zoomeye.org/host/search", params,
                                   headers={"API-KEY": str(creds["key"]).strip()})
        except RuntimeError as exc:
            if page == 1:
                return rows, str(exc)
            break
        if isinstance(data, dict) and data.get("error"):
            if page == 1:
                return rows, str(data["error"])[:150]
            break
        for item in (data.get("matches") if isinstance(data, dict) else []) or []:
            info = item.get("portinfo") or {}
            rows.extend(_expand(item.get("ip"), info.get("port"), info.get("service"), cfg))
        if not (data.get("matches") if isinstance(data, dict) else None):
            break
        page += 1
        await asyncio.sleep(0.8)
    return rows[:cap * 2], ""


# ── 自定义清单地址 ────────────────────────────────────────────────────────
async def fetch_url(session, cfg):
    url = (cfg.get("target") or "").strip()
    if not url.lower().startswith(("http://", "https://")):
        return [], "地址必须以 http:// 或 https:// 开头"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=40)) as resp:
            if resp.status != 200:
                return [], f"HTTP {resp.status}"
            body = await resp.text(errors="ignore")
    except Exception as exc:
        return [], f"{exc.__class__.__name__}: {str(exc)[:100]}"
    if len(body) > MAX_FILE_BYTES:
        body = body[:MAX_FILE_BYTES]
    rows = parse_blob(body, source=cfg["name"])
    cap = max(1, int(cfg.get("cap") or 300))
    want = (cfg.get("protocol") or "http").lower()
    if want == "auto":
        rows = _apply_auto(rows, cfg, False)
    elif want != "http":
        for r in rows:
            r["protocol"] = want
    return rows[:cap], ""


_HANDLERS = {
    "github": fetch_github,
    "url": fetch_url,
    "fofa": fetch_fofa,
    "hunter": fetch_hunter,
    "quake": fetch_quake,
    "shodan": fetch_shodan,
    "zoomeye": fetch_zoomeye,
}


async def fetch_source(session, cfg):
    """抓一个自定义源，返回 (rows, error)。异常一律转成 error 文本，不炸整批。"""
    provider = (cfg.get("provider") or "").lower()
    handler = _HANDLERS.get(provider)
    if not handler:
        return [], f"未知的源类型：{provider}"
    name = cfg.get("name") or provider
    try:
        rows, err = await handler(session, cfg)
    except Exception as exc:
        return [], f"{exc.__class__.__name__}: {str(exc)[:120]}"
    for r in rows:
        r["source"] = name
    return rows, err or ""


async def fetch_custom(session, sources):
    """并发抓一批自定义源，返回 (rows, report)。"""
    if not sources:
        return [], []
    results = await asyncio.gather(
        *(fetch_source(session, s) for s in sources), return_exceptions=True)
    rows, report = [], []
    for cfg, res in zip(sources, results):
        if isinstance(res, Exception):
            report.append({"id": cfg.get("id"), "name": cfg.get("name"),
                           "provider": cfg.get("provider"), "count": 0,
                           "error": res.__class__.__name__, "custom": True})
            continue
        items, err = res
        report.append({"id": cfg.get("id"), "name": cfg.get("name"),
                       "provider": cfg.get("provider"), "count": len(items),
                       "error": err, "custom": True})
        rows.extend(items)
    return rows, report


# ── 试抓（面板「测试」按钮）：只取少量，不入库 ────────────────────────────
async def test_source(cfg, limit=10):
    probe = dict(cfg)
    probe["cap"] = min(int(cfg.get("cap") or 20), 20)
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ProxyDog/1.4"}
    async with aiohttp.ClientSession(headers=headers) as session:
        rows, err = await fetch_source(session, probe)
    sample = []
    seen = set()
    for r in rows:
        key = (r["host"], r["port"], r["protocol"])
        if key in seen:
            continue
        seen.add(key)
        if len(sample) < limit:
            sample.append(f"{r['protocol']}://{r['host']}:{r['port']}")
    return {"count": len(rows), "unique": len(seen), "error": err, "sample": sample}
