"""ProxyDog 主程序：Flask 面板 + 后台 asyncio 代理服务。

启动：python app.py  （默认面板 http://127.0.0.1:5002 ，代理端口 127.0.0.1:2080）
"""

import asyncio
import base64
import csv
import io
import json
import logging
import logging.handlers
import os
import re
import socket
import threading
import time
import urllib.request
from urllib.parse import quote

from flask import (Flask, Response, g, jsonify, redirect, request,
                   send_from_directory, session)

import apisources
import auth
import geoip
import ipclass
import plugins
import sources
import tasks
from netproxy import ProxyServer
from store import BASE_DIR, DATA_DIR, MODE_KEYS, MODES, Store

# ---------------- 版本与更新检查 ----------------
VERSION = "1.8.1"
ABOUT = {
    "name": "ProxyDog",
    "version": VERSION,
    "author": "Deep-webs",
    "repo": "https://github.com/Deep-webs/ProxyDog",
    "releases": "https://github.com/Deep-webs/ProxyDog/releases/latest",
    "releases_api": "https://api.github.com/repos/Deep-webs/ProxyDog/releases/latest",
}
UPDATE = {"checked": 0.0, "latest": "", "url": "", "notes": "", "err": "还没检查过"}


def _version_gt(a, b):
    """比较 a 是否比 b 新：v1.10.0 > v1.9.9，别按字符串比。"""
    def nums(x):
        out = []
        for p in re.split(r"[.\-+_]", str(x or "").lstrip("vV")):
            m = re.match(r"(\d+)", p)
            if m:
                out.append(int(m.group(1)))
        return out
    return nums(a) > nums(b)


def _check_update(force=False):
    """问 GitHub 最新 release。6 小时缓存；网络不通就记一句，别打扰用户。"""
    now = time.time()
    if not force and now - UPDATE["checked"] < 6 * 3600:
        return
    UPDATE["checked"] = now
    try:
        req = urllib.request.Request(
            ABOUT["releases_api"],
            headers={"Accept": "application/vnd.github+json",
                     "User-Agent": "ProxyDog/" + VERSION})
        with urllib.request.urlopen(req, timeout=8) as r:
            d = json.loads(r.read().decode("utf-8", "ignore"))
        latest = str(d.get("tag_name") or "").lstrip("vV")
        UPDATE["latest"] = latest
        UPDATE["url"] = d.get("html_url") or ABOUT["releases"]
        UPDATE["notes"] = (d.get("name") or "")[:200]
        UPDATE["err"] = ""
        if _version_gt(latest, VERSION):
            log.warning("发现新版本 ProxyDog %s（当前 %s）：%s",
                        latest, VERSION, UPDATE["url"])
    except Exception as exc:
        UPDATE["err"] = f"{exc.__class__.__name__}: {str(exc)[:60]}"


# 本机公网出口 IP（匿名判断基准）：设置里手动填优先，否则每 30 分钟自动探测一次
PUBIP = {"ip": "", "ip6": "", "ts": 0.0, "tried": 0.0}


def public_ip(s=None):
    """手动填了就用手动的；否则用探测结果。"""
    manual = str((s or store.settings()).get("public_ip") or "").strip()
    return manual or PUBIP.get("ip") or ""

LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "proxydog.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
log = logging.getLogger("proxydog")
plog = logging.getLogger("proxydog.plugin")     # 插件级抓取日志（运行日志「插件」页签）
logging.getLogger("werkzeug").setLevel(logging.WARNING)


def setup_logging():
    """日志级别过滤 + 文件大小轮转（照 ProxyCat：级别/上限/份数都可在设置里调）。

    在 Store 初始化后调用，按设置重建 handlers。
    """
    s = store.settings()
    level = getattr(logging, str(s.get("log_level") or "INFO").upper(), logging.INFO)
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
        try:
            h.close()
        except Exception:
            pass
    root.setLevel(logging.INFO)
    fmax = max(1, int(s.get("log_file_max_mb") or 10)) * 1024 * 1024
    fh = logging.handlers.RotatingFileHandler(
        LOG_FILE, encoding="utf-8", maxBytes=fmax,
        backupCount=max(1, int(s.get("log_backups") or 3)))
    fh.setLevel(level)                      # 低于该级别不写入文件
    sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    fh.setFormatter(fmt)
    sh.setFormatter(fmt)
    root.addHandler(fh)
    root.addHandler(sh)

store = Store()
server = ProxyServer(store)
# 池空时由 netproxy 直接催一次补货：不等后台 60 秒巡检，也不用等扩容冷却
server.pool_empty_hook = lambda: bool(_auto_scale_once(reason="池空即时补货"))
loop = None
loop_ready = threading.Event()
busy = {"validating": False, "fetching": False, "progress": ""}
# 调度状态，供面板「任务」展示
SCHED = {
    "fetch": {"label": "抓取源清单", "last": 0, "next": 0, "ok": None, "note": ""},
    "validate": {"label": "池内重验证", "last": 0, "next": 0, "ok": None, "note": ""},
    "scenario": {"label": "场景验证(2分钟)", "last": 0, "next": 0, "ok": None, "note": ""},
    "prune": {"label": "日志清理", "last": 0, "next": 0, "ok": None, "note": ""},
    "backup": {"label": "数据库备份", "last": 0, "next": 0, "ok": None, "note": ""},
}

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["JSON_AS_ASCII"] = False
app.secret_key = auth.load_or_create_secret(os.path.join(DATA_DIR, "secret.key"))
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  PERMANENT_SESSION_LIFETIME=86400 * 7)

login_guard = auth.LoginGuard()


# ---------------- 内置免费源覆盖（停用 / 编辑 / 删除） ----------------
def _builtin_overrides(s=None):
    """从 settings 读出覆盖配置并灌进 sources 模块，返回解析结果。"""
    s = s or store.settings()

    def _csv(key):
        return [x.strip() for x in str(s.get(key) or "").split(",") if x.strip()]

    try:
        edited = json.loads(s.get("builtin_overrides") or "{}")
    except (TypeError, ValueError):
        edited = {}
    if not isinstance(edited, dict):
        edited = {}
    ov = {"disabled": _csv("builtin_disabled"),
          "deleted": _csv("builtin_deleted"),
          "edited": edited}
    sources.apply_overrides(ov)
    return ov


def _save_builtin_overrides(ov):
    store.save_settings({
        "builtin_disabled": ",".join(ov["disabled"]),
        "builtin_deleted": ",".join(ov["deleted"]),
        "builtin_overrides": json.dumps(ov["edited"], ensure_ascii=False),
    })
    _builtin_overrides()


_builtin_overrides()          # 启动时灌一次


# ---------------- 认证 ----------------
PUBLIC_PATHS = {"/login", "/api/health", "/favicon.ico", "/metrics"}

LOCAL_IDENTITY = {"kind": "local", "name": "本机", "id": 0}


def _panel_auth_on():
    return bool(store.settings().get("panel_auth"))


def current_identity():
    """返回 {'kind': local|user|key|token, 'name': ...}；未认证返回 None。

    panel_auth 关闭（本地自用默认）时一律视为本机身份，不再要求登录。
    """
    uid = session.get("uid")
    if uid:
        user = store.get_user_by_id(uid)
        if user:
            return {"kind": "user", "name": user["username"], "id": user["id"]}
        session.clear()
    key = request.headers.get("X-API-Key") or request.args.get("key") or ""
    if key:
        row = store.key_by_value(key)
        if row and row["enabled"]:
            return {"kind": "key", "name": row["name"], "id": row["id"]}
        if _panel_auth_on():
            return None          # 带了错 key 就别放行
    token = str(store.settings().get("token") or "")
    if token and (request.args.get("token") == token or request.headers.get("X-Token") == token):
        return {"kind": "token", "name": "legacy-token", "id": 0}
    if not _panel_auth_on():
        return dict(LOCAL_IDENTITY)
    return None


def _ip_allowed(ip, whitelist, blacklist=""):
    """白/黑名单支持精确 IP 与 CIDR；本机回环永远放行，免得把自己锁在门外。

    黑名单优先：命中黑名单直接拒绝；白名单非空时只放行名单内的。
    """
    import ipaddress
    ip = ip or ""
    if ip in ("127.0.0.1", "::1") or ip.startswith("127."):
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    def _hit(cidrs):
        for part in str(cidrs).split(","):
            part = part.strip()
            if not part:
                continue
            try:
                if addr in ipaddress.ip_network(part, strict=False):
                    return True
            except ValueError:
                if addr == part:      # 写了非法网段就当精确 IP 比对
                    return True
        return False

    if _hit(blacklist):
        return False
    return (not str(whitelist or "").strip()) or _hit(whitelist)


def _is_loopback(ip):
    ip = (ip or "").strip()
    return ip in ("::1", "localhost") or ip.startswith("127.")


@app.before_request
def _guard():
    path = request.path
    if (path in PUBLIC_PATHS or path.startswith("/static/")
            or path.startswith("/sub/")):
        return None
    wl = str(store.settings().get("ip_whitelist") or "").strip()
    bl = str(store.settings().get("ip_blacklist") or "").strip()
    if (wl or bl) and not _ip_allowed(request.remote_addr, wl, bl):
        if path.startswith("/api/"):
            return jsonify({"ok": False, "error": "来源 IP 不在白名单内"}), 403
        return "来源 IP 不在白名单内", 403
    ident = current_identity()
    g.identity = ident
    if ident is None:
        if path.startswith("/api/"):
            return jsonify({"ok": False, "error": "未认证，请先登录", "auth": False}), 401
        return redirect("/login?next=" + quote(path))
    # 未启用面板密码时，只允许本机（或白名单）访问，避免关掉密码后对整个局域网裸奔
    if ident["kind"] == "local" and not _is_loopback(request.remote_addr) and not wl:
        msg = ("面板未开启登录保护，只允许本机访问。"
               "如需远程使用，请在「维护 → 设置」打开「面板登录保护」或配置 IP 白名单。")
        if path.startswith("/api/"):
            return jsonify({"ok": False, "error": msg, "auth": False}), 403
        return msg, 403
    # API Key 的配额只对「对外取用」计费，面板操作不消耗
    if ident["kind"] == "key" and path.startswith("/api/pool/"):
        row = store.get_key(ident["id"]) or {}
        quota = int(row.get("daily_quota") or 0)
        allowed, used = store.key_consume(ident["id"], quota)
        if not allowed:
            return jsonify({"ok": False, "error": f"API Key 今日配额已用完（{used}/{quota}）",
                            "quota": quota, "used": used}), 429
        g.key_used = used
    return None


@app.route("/login", methods=["GET", "POST"])
def login():
    if not _panel_auth_on():
        return redirect("/")          # 未启用面板密码：不存在登录页
    if request.method == "GET":
        if current_identity():
            return redirect("/")
        return send_from_directory(os.path.join(BASE_DIR, "templates"), "login.html")
    data = request.get_json(silent=True) or request.form
    ip = request.remote_addr or "-"
    left = login_guard.locked(ip)
    if left:
        return jsonify({"ok": False, "error": f"失败次数过多，请 {left // 60 + 1} 分钟后再试"}), 429
    username = (data.get("username") or "").strip()
    user = store.get_user(username) if username else None
    if not user or not auth.verify_password(data.get("password") or "",
                                            user["pwd_hash"], user["salt"]):
        login_guard.fail(ip)
        log.warning("登录失败: user=%s ip=%s", username, ip)
        return jsonify({"ok": False, "error": "用户名或密码错误"}), 401
    login_guard.reset(ip)
    session.permanent = True
    session["uid"] = user["id"]
    session["name"] = user["username"]
    store.touch_login(user["username"])
    log.info("登录成功: %s ip=%s", user["username"], ip)
    return jsonify({"ok": True, "redirect": request.args.get("next") or "/"})


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login" if _panel_auth_on() else "/")


def require_user():
    """修改密码、管理 Key 这类操作只允许登录用户，不接受 API Key。

    未启用面板密码时，面板本身就是管理员，直接放行。
    """
    if not _panel_auth_on():
        return dict(LOCAL_IDENTITY)
    ident = getattr(g, "identity", None) or current_identity()
    if not ident or ident["kind"] != "user":
        return None
    return ident


# ---------------- 工具 ----------------
def run_coro(coro, timeout=600):
    if loop is None:
        raise RuntimeError("事件循环尚未就绪")
    return asyncio.run_coroutine_threadsafe(coro, loop).result(timeout)


def need_token():
    token = str(store.settings().get("token") or "")
    if not token:
        return True
    given = request.args.get("token") or request.headers.get("X-Token") or ""
    return given == token


def ok(**kw):
    kw.setdefault("ok", True)
    return jsonify(kw)


def err(msg, code=400):
    return jsonify({"ok": False, "error": str(msg)}), code


def _rows_by_ids(ids):
    out = []
    for pid in ids:
        row = store.get(pid)
        if row:
            out.append(row)
    return out


def _validate_opts(s):
    """验证强度三档（照 ProxyCat）。

    fast     只测 HTTP 连通，不测 HTTPS、不看匿名、不校验特征串 —— 最快、最省
    standard HTTP + HTTPS 探测，按设置决定是否验匿名，校验特征串
    strict   再加匿名强校验：代理必须能被识别为高匿，且响应必须包含特征串
    """
    lvl = str(s.get("validate_level") or "standard").lower()
    probe_https = lvl != "fast"
    want_anon = bool(s.get("verify_anonymity")) or lvl == "strict"
    anon_url = (s.get("anon_echo_url") or "") if want_anon else ""
    keyword = "" if lvl == "fast" else str(s.get("test_keyword") or "").strip()
    return probe_https, anon_url, keyword


def _check_kwargs(s):
    """传给 sources.validate_many 的公共参数：公网 IP + 检测节流三参数。"""
    want_anon = bool(s.get("verify_anonymity")) or \
        str(s.get("validate_level") or "") == "strict"
    return {
        "public_ip": public_ip(s) if want_anon else "",
        "cache_s": int(s.get("check_cache_seconds") or 0),
        "min_iv": int(s.get("check_min_interval") or 0),
        "dup_iv": int(s.get("check_dup_interval") or 0),
    }


# 回显站点：国内站点排前面（国外接口在国内经常被墙/超时），失败就换下一个
ECHO_V4 = ("https://4.ipw.cn", "https://myip.ipip.net", "https://api.ipify.org",
           "http://members.3322.org/dyndns/getip", "https://ifconfig.me/ip",
           "https://ipinfo.io/ip", "https://ident.me")
ECHO_V6 = ("https://6.ipw.cn", "https://api64.ipify.org", "https://ipv6.ident.me")
RE_V4 = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")
IPv6_RE = re.compile(r"\b((?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4})\b")


def _ip_usable(ip):
    """过滤私网/回环/链路本地地址——本机公网 IP 只认真正的公网地址。"""
    if not ip:
        return False
    if ":" in ip:
        low = ip.lower()
        return not (low.startswith(("fe80", "fc", "fd", "::1", "::")))
    parts = ip.split(".")
    try:
        a, b = int(parts[0]), int(parts[1])
    except Exception:
        return False
    if a in (0, 10, 127):
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 169 and b == 254:
        return False
    return True


async def _echo_first(ses, urls, pattern):
    """按顺序试一组回显站点，返回 (公网地址, 原始响应文本)。

    文本一并带回：myip.ipip.net 这类站点的响应里自带归属地，省一次查询。
    """
    import aiohttp
    for url in urls:
        try:
            async with ses.get(url, timeout=aiohttp.ClientTimeout(total=6),
                               headers={"User-Agent": "curl/8.0"}) as r:
                if r.status != 200:
                    continue
                txt = (await r.text(errors="ignore"))[:300]
        except Exception:
            continue
        for m in pattern.finditer(txt):
            if _ip_usable(m.group(1)):
                return m.group(1), txt
    return "", ""


# myip.ipip.net 的响应形如「当前 IP：x.x.x.x  来自于：中国 河南 郑州 联通」
RE_IPIP_REGION = re.compile(r"来自于[：:]\s*([^\r\n]{2,60})")


async def _ip_geo(ses, ip):
    """查 IP 归属地（中文，含运营商）。走 ip-api 免费接口，失败就空着。"""
    import aiohttp
    url = ("http://ip-api.com/json/" + ip +
           "?lang=zh-CN&fields=status,country,regionName,city,isp")
    try:
        async with ses.get(url, timeout=aiohttp.ClientTimeout(total=6)) as r:
            d = await r.json(content_type=None)
        if d.get("status") == "success":
            out = " ".join(b for b in (d.get("country") or "",
                                       d.get("regionName") or "",
                                       d.get("city") or "",
                                       d.get("isp") or "") if b)
            return out
    except Exception:
        pass
    return ""


async def _detect_public_ip():
    """直接（不走代理）问回显服务拿本机公网 IP，v4 / v6 两条线并发探。

    返回 (v4, v6, 地区v4, 地区v6)。IPv6 探不到很正常（运营商没给公网 v6）。
    归属地优先用回显站自带的（ipip），否则查 ip-api 兜底。
    """
    import aiohttp
    async with aiohttp.ClientSession() as ses:
        (v4, t4), (v6, t6) = await asyncio.gather(
            _echo_first(ses, ECHO_V4, RE_V4),
            _echo_first(ses, ECHO_V6, IPv6_RE),
        )
        v4, v6 = v4 or "", v6 or ""
        m = RE_IPIP_REGION.search(t4 or "")
        geo = " ".join(m.group(1).split()) if m else \
            (await _ip_geo(ses, v4) if v4 else "")
        if v6:
            m6 = RE_IPIP_REGION.search(t6 or "")
            geo6 = " ".join(m6.group(1).split()) if m6 else await _ip_geo(ses, v6)
        else:
            geo6 = ""
    return v4, v6, geo or "", geo6 or ""


@app.route("/api/pubip/refresh", methods=["POST"])
def api_pubip_refresh():
    """立即重新检测本机公网出口 IP（匿名判定基准，也是默认直连出口）。

    平时每 30 分钟自动探测一次；这里是面板上的手动触发，探测结果不写设置，
    设置里的 public_ip 仍然是「手动优先」的那一项。
    """
    manual = str(store.settings().get("public_ip") or "").strip()
    try:
        v4, v6, geo, geo6 = run_coro(_detect_public_ip(), 45)
    except Exception as exc:
        return err(f"检测失败: {exc}")
    if not v4 and not v6:
        return err("探测失败：几个回显站点都没返回可用 IP（可能是本机断网/被拦截）")
    PUBIP["ip"] = v4 or PUBIP.get("ip", "")
    PUBIP["ip6"] = v6 or PUBIP.get("ip6", "")
    PUBIP["geo"] = geo or PUBIP.get("geo", "")
    PUBIP["geo6"] = geo6 or PUBIP.get("geo6", "")
    PUBIP["ts"] = PUBIP["tried"] = time.time()
    log.info("手动检测本机公网出口 IP: v4=%s（%s） v6=%s（%s）",
             PUBIP["ip"] or "-", PUBIP["geo"] or "-",
             PUBIP["ip6"] or "-", PUBIP["geo6"] or "-")
    return ok(ip=PUBIP["ip"], ip6=PUBIP["ip6"], geo=PUBIP["geo"],
              geo6=PUBIP["geo6"], manual=bool(manual),
              note="已更新（手动填写优先于自动探测）" if manual else "已更新")


def validate_rows(rows, chunk=25):
    """验证一批出口并落库。

    分块跑：每块验完立刻写库，池子马上就能用上这批。
    整批一次性验证时，要等最后一条出结果才有第一条可用——池子空的时候
    这几十秒的差别就是「代理不可用」和「代理可用」的差别。
    """
    if not rows:
        return {"checked": 0, "valid": 0, "slow": 0}
    s = store.settings()
    cap = int(s.get("max_delay_ms") or 0)
    items = [(r["id"], r) for r in rows]
    probe_https, anon_url, keyword = _validate_opts(s)
    valid = slow = checked = 0
    for i in range(0, len(items), max(1, int(chunk))):
        part = items[i:i + max(1, int(chunk))]
        results = run_coro(sources.validate_many(
            part, s["test_url"], int(s["validate_timeout"]),
            int(s["validate_concurrency"]), anon_url, probe_https, keyword,
            **_check_kwargs(s)))
        for pid, good, delay, anon, hok, rip in results:
            state = store.set_result(pid, good, delay, source="check", anon=anon,
                                     https_ok=hok, max_delay_ms=cap, real_ip=rip)
            valid += 1 if state == "ok" else 0
            slow += 1 if state == "slow" else 0
        checked += len(results)
    dropped = 0
    if slow and s.get("auto_drop_slow"):
        dropped = store.purge_slow(cap, only_marked=True)
    return {"checked": checked, "valid": valid, "slow": slow, "dropped": dropped}


# ---------------- 页面 ----------------
@app.route("/")
def index():
    resp = send_from_directory(os.path.join(BASE_DIR, "templates"), "index.html")
    resp.headers["Cache-Control"] = "no-store"      # 面板改版后别让浏览器拿旧页面
    return resp


# ---------------- 订阅输出 ----------------
@app.route("/sub/<token>")
def sub_export(token):
    """把池子变成订阅链接，给 SwitchyOmega / Clash / 其他代理工具拉取。

    /sub/<token>?format=base64|txt|clash&protocol=http|socks5&https=1&limit=500
    token 用「维护 → 设置」里的 token；链接即密码，别外传。
    """
    want = str(store.settings().get("token") or "")
    if not want or token != want:
        return Response("订阅 token 无效", 403, mimetype="text/plain")
    fmt = (request.args.get("format") or "base64").lower()
    protocol = request.args.get("protocol") or None
    https_only = request.args.get("https") in ("1", "true")
    limit = int(request.args.get("limit") or 500)
    # 订阅同样受延迟上限约束：拉过去就是为了能用，慢节点给了也是超时
    cap = int(store.settings().get("max_delay_ms") or 0)
    want = int(request.args.get("max_delay") or 0)
    rows = store.sub_list(protocol=protocol, https_only=https_only,
                          max_delay=min([v for v in (cap, want) if v] or [0]),
                          limit=limit)

    if fmt == "txt":
        body = "\n".join(rows)
        mime = "text/plain; charset=utf-8"
    elif fmt == "clash":
        proxies = []
        for r in rows:
            scheme, _, addr = r.partition("://")
            host, _, port = addr.rpartition(":")
            name = f"pd-{host}-{port}"
            if scheme == "socks5":
                proxies.append({"name": name, "type": "socks5",
                                "server": host, "port": int(port)})
            else:
                proxies.append({"name": name, "type": "http",
                                "server": host, "port": int(port)})
        lines = ["port: 0", "socks-port: 0", "allow-lan: false", "mode: rule",
                 "proxies:"]
        for p in proxies:
            lines.append(f"  - name: \"{p['name']}\"")
            lines.append(f"    type: {p['type']}")
            lines.append(f"    server: {p['server']}")
            lines.append(f"    port: {p['port']}")
        body = "\n".join(lines) + "\n"
        mime = "text/yaml; charset=utf-8"
    else:                                  # base64，订阅工具的默认格式
        body = base64.b64encode("\n".join(rows).encode()).decode()
        mime = "text/plain; charset=utf-8"

    resp = Response(body, 200, mimetype=mime)
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Content-Disposition"] = \
        f"inline; filename=proxydog-{fmt}.{'yaml' if fmt == 'clash' else 'txt'}"
    return resp


def sub_urls():
    """面板展示用的订阅地址（含三种格式）。"""
    tok = str(store.settings().get("token") or "")
    if not tok:
        return {}
    base = f"http://127.0.0.1:{store.settings().get('web_port')}/sub/{tok}"
    return {"base64": base + "?format=base64", "txt": base + "?format=txt",
            "clash": base + "?format=clash"}


@app.route("/api/state")
def api_state():
    snap = server.snapshot()
    snap["stats_pool"] = store.stats()
    snap["settings"] = {k: v for k, v in store.settings().items()
                        if k not in ("auth_password",)}
    snap["modes"] = MODES
    snap["countries"] = sources.country_list()
    snap["busy"] = busy
    snap["proxy_auth"] = server.auth_required()
    snap["proxy_users"] = {"total": store.count_proxy_users(enabled_only=False),
                           "enabled": store.count_proxy_users()}
    snap["identity"] = getattr(g, "identity", None) or current_identity()
    snap["panel_auth"] = _panel_auth_on()
    snap["sub"] = sub_urls()
    snap["logs"] = store.log_summary(60)
    snap["sched"] = SCHED
    gs = geoip.status()
    snap["geoip"] = {k: gs.get(k) for k in
                     ("ready", "segments", "label_count", "provider", "built",
                      "size_mb", "running", "phase", "got", "total", "msg", "error")}
    snap["alerts"] = _alerts()
    cap = int(snap["settings"].get("max_delay_ms") or 0)
    snap["slow"] = {"limit": cap, "count": store.count_slow(cap)}
    pi = public_ip(snap["settings"])
    manual = bool(str(snap["settings"].get("public_ip") or "").strip())
    # 归属地是跟着自动探测的那个 IP 查的；手动填的另一个 IP 时归属地不适用
    geo_ok = (not manual) or pi == (PUBIP.get("ip") or "")
    snap["pubip"] = {"ip": pi, "known": bool(pi), "manual": manual,
                     "ip6": PUBIP.get("ip6") or "",
                     "geo": (PUBIP.get("geo") or "") if geo_ok else "",
                     "geo6": PUBIP.get("geo6") or "",
                     "ts": round(PUBIP.get("ts") or 0),
                     "tried": round(PUBIP.get("tried") or 0)}
    snap["domains_total"] = store.domain_stats(limit=1)[1]
    snap["exit_speeds"] = store.exit_speeds()
    # 任务中心 / 插件目录 / 出口 IP 类型分布
    snap["tasks"] = tasks.listing(30)
    snap["task_summary"] = tasks.summary()
    snap["plugins"] = plugins.status()
    snap["ipclass"] = {"stats": store.ip_kind_stats(), "info": ipclass.stats()}
    snap["about"] = about_snapshot()
    return ok(state=snap)


def _alerts():
    """给面板顶部的健康告警，返回 [{level, text}]。"""
    out = []
    s = store.settings()
    stats = store.stats()
    logs = store.log_summary(15)
    if not server.running:
        out.append({"level": "error", "text": "代理端口未运行，外部请求会全部失败"})
    if stats["valid"] == 0:
        out.append({"level": "error", "text": "池内没有有效出口，点「自动抓取」或导入订阅"})
    elif stats["valid"] < 5:
        out.append({"level": "warn",
                    "text": f"有效出口只有 {stats['valid']} 条，轮换容易撞到坏代理"})
    if logs["total"] >= 10 and logs["rate"] < 60:
        out.append({"level": "warn",
                    "text": f"最近 15 分钟成功率 {logs['rate']}%（{logs['ok']}/{logs['total']}）"})
    if s.get("listen_host") == "0.0.0.0" and not store.count_proxy_users():
        out.append({"level": "error",
                    "text": "监听 0.0.0.0 且入站账号表为空，同网段任何人都能当跳板"})
    if s.get("mode") == "exclusive" and not int(s.get("exclusive_id") or 0):
        out.append({"level": "warn", "text": "独占模式未指定出口 ID，实际会退化为轮换"})
    if not s.get("panel_auth") and str(s.get("web_host") or "") not in ("127.0.0.1", "::1", "localhost"):
        out.append({"level": "error",
                    "text": f"面板监听 {s.get('web_host')} 且未开登录保护，同网段任何人都能改配置"})
    if server._mode_note:
        out.append({"level": "warn", "text": server._mode_note})
    if s.get("verify_anonymity") and not public_ip(s):
        out.append({"level": "warn",
                    "text": "匿名度判断依赖本机公网出口 IP，尚未获知；"
                            "可在「设置 → 代理验证」里手动填，或等自动探测"})
    try:
        if store.resolved_mismatches():
            out.append({"level": "warn",
                        "text": "有域名出口的解析结果待复核，可在「维护」页做解析一致性检测"})
    except Exception:
        pass
    if stats.get("quarantined"):
        out.append({"level": "info",
                    "text": f"{stats['quarantined']} 个出口在冷却隔离中，到期自动恢复"})
    sizes = store.file_sizes()
    if sizes.get("proxydog.db-wal", 0) > 8 * 1024 * 1024:
        out.append({"level": "warn", "text": "WAL 文件超过 8MB，建议在维护页做一次检查点"})
    return out


def public_settings():
    s = store.settings()
    if s.get("auth_password"):
        s["auth_password"] = "******"
    return s


def apply_env_settings():
    """容器部署用（照 ProxyCat 的 Docker 实践）：环境变量覆盖监听地址/端口。

    容器里默认 127.0.0.1 会让端口映射失效，这里允许 .env / docker-compose
    直接指定 PROXYDOG_LISTEN_HOST=0.0.0.0，省得进面板改一次配置。
    """
    specs = {
        "PROXYDOG_LISTEN_HOST": ("listen_host", str),
        "PROXYDOG_LISTEN_PORT": ("listen_port", int),
        "PROXYDOG_SOCKS_PORT": ("socks_port", int),
        "PROXYDOG_SOCKS_SHARED": ("socks_shared", lambda v: str(v).lower() in ("1", "true", "yes", "on")),
        "PROXYDOG_WEB_HOST": ("web_host", str),
        "PROXYDOG_WEB_PORT": ("web_port", int),
        "PROXYDOG_PANEL_AUTH": ("panel_auth", lambda v: str(v).lower() in ("1", "true", "yes", "on")),
    }
    patch = {}
    for env, (key, cast) in specs.items():
        raw = os.environ.get(env)
        if raw is None or raw == "":
            continue
        try:
            patch[key] = cast(raw)
        except (TypeError, ValueError):
            log.warning("环境变量 %s 的值不合法：%r", env, raw)
    if patch:
        store.save_settings(patch)
        log.info("已按环境变量覆盖设置: %s", ", ".join(patch))


@app.route("/api/mode", methods=["GET", "POST"])
def api_mode():
    """轮换模式的读写入口。面板上的模式切换器直接打这个接口，改完立刻生效。"""
    if request.method == "GET":
        s = store.settings()
        return ok(mode=s["mode"], modes=MODES,
                  snapshot=server.snapshot(),
                  settings={k: s[k] for k in ("rotate_count", "rotate_seconds",
                                              "sticky_ttl", "keyword_list",
                                              "keyword_mode", "keyword_site",
                                              "scenario_site", "scenario_keyword",
                                              "scenario_drop_invalid",
                                              "exclusive_id")})
    data = request.get_json(force=True) or {}
    mode = str(data.get("mode") or "").strip()
    if mode not in MODE_KEYS:
        return err("未知模式：" + (mode or "(空)"))

    patch = {"mode": mode}
    for k in ("rotate_count", "rotate_seconds", "sticky_ttl"):
        if k in data:
            try:
                patch[k] = max(1, min(int(data[k]), 86400))
            except (TypeError, ValueError):
                return err(f"{k} 需要正整数")
    if "keyword_list" in data:
        patch["keyword_list"] = str(data["keyword_list"]).strip()
    if "keyword_mode" in data:
        patch["keyword_mode"] = "white" if data["keyword_mode"] == "white" else "black"
    if "keyword_site" in data:
        patch["keyword_site"] = str(data["keyword_site"]).strip()
    if "scenario_site" in data:
        # 支持多个验证网站：逗号 / 分号 / 换行分隔（半角全角都可以）
        sites = [u for u in re.split(r"[,;，；\n\r]+", str(data["scenario_site"]))
                 if u.strip()]
        patch["scenario_site"] = " ".join(u.strip() for u in sites)
    if "scenario_keyword" in data:
        patch["scenario_keyword"] = str(data["scenario_keyword"]).strip()
    if "scenario_drop_invalid" in data:
        patch["scenario_drop_invalid"] = bool(data["scenario_drop_invalid"])
    if "exclusive_id" in data:
        try:
            patch["exclusive_id"] = max(0, int(data["exclusive_id"] or 0))
        except (TypeError, ValueError):
            return err("独占出口 ID 需要整数")

    cur = store.settings()
    if mode == "exclusive":
        eid = int(patch.get("exclusive_id", cur.get("exclusive_id") or 0) or 0)
        if not eid:
            # 0 = 自动：固定使用延时最短的可用出口，不需要指定 ID
            pass
        else:
            row = store.get(eid)
            if not row:
                return err(f"出口 #{eid} 不存在")
            if not row.get("is_valid"):
                return err(f"出口 #{eid} 当前无效，请先验证通过再设为独占")
        patch["exclusive_id"] = eid
    if mode == "keyword" and not (patch.get("keyword_list") or cur.get("keyword_list")):
        return err("关键词模式至少要填一个关键词")

    store.save_settings(patch)
    server.reset_rotation()
    s = store.settings()
    meta = MODES[mode]
    note = {
        "round_robin": "已切换：每个请求换出口，加权开启时快出口优先。",
        "by_count": f"已切换：同一出口连用 {s['rotate_count']} 次后换下一个。",
        "by_time": f"已切换：同一出口用满 {max(1, s['rotate_seconds'] // 60)} 分钟后换下一个。",
        "scenario": "已切换：每 2 分钟用场景验证网站测一遍池子，验证失败自动切换。",
        "sticky": f"已切换：同一客户端访问同一站点 {s['sticky_ttl']} 秒内固定同一出口。",
        "keyword": "已切换：命中关键词走直连，其余继续轮换。",
        "exclusive": "已切换：固定代理" + (
            f"#{s['exclusive_id']}" if s.get("exclusive_id") else "，使用延时最短的出口"),
    }[mode]
    log.info("轮换模式 -> %s (%s)", mode, meta["label"])
    return ok(mode=mode, label=meta["label"], note=note,
              snapshot=server.snapshot(), settings=s)


def _socks_port(s):
    """实际生效的 SOCKS5 端口。

    开了「同端口」开关就返回 0 —— 表示 SOCKS5 与 HTTP 共用 listen_port，
    监听侧用首字节嗅探区分协议；关掉才用独立的 socks_port。
    """
    if s.get("socks_shared"):
        return 0
    return int(s.get("socks_port") or 0)


@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    if request.method == "GET":
        return ok(settings=public_settings())
    data = request.get_json(force=True) or {}
    if "mode" in data and data["mode"] not in MODE_KEYS:
        return err("未知模式")
    if data.get("auth_password") == "******":      # 前端脱敏值，别把星号存成真密码
        data.pop("auth_password", None)
    for k in ("listen_port", "web_port", "socks_port"):
        if k in data:
            try:
                data[k] = int(data[k])
            except (TypeError, ValueError):
                return err(f"{k} 需要整数")
            if not 1 <= data[k] <= 65535:
                return err("端口范围 1-65535")
    old = store.settings()
    # 兼容旧接口：还按 auth_username/auth_password 提交的，落到账号表里
    _au = str(data.pop("auth_username", "") or "").strip()
    _ap = data.pop("auth_password", "") if "auth_password" in data else None
    if _au and _ap:
        row = store.get_proxy_user_by_name(_au)
        if row:
            store.update_proxy_user(row["id"], password=_ap, enabled=True)
        else:
            store.add_proxy_user(_au, _ap, "从设置页保存", True)
        server.invalidate_creds()
    store.save_settings(data)
    new = store.settings()
    if old.get("mode") != new.get("mode"):
        server.reset_rotation()
    cap = int(new.get("max_delay_ms") or 0)
    if int(old.get("max_delay_ms") or 0) != cap:
        # 上限变了，正在用的出口可能已经不合格，让它下次请求重新挑
        server.reset_rotation()
    if (bool(old.get("prefer_fast")) != bool(new.get("prefer_fast"))
            or int(old.get("fast_window_ms") or 0) != int(new.get("fast_window_ms") or 0)):
        # 延迟优先策略变了，重新按新窗口挑出口
        server.reset_rotation()
    if (int(old.get("pool_keep") or 0) != int(new.get("pool_keep") or 0)
            or int(old.get("life_seconds") or 0) != int(new.get("life_seconds") or 0)):
        # 存池上限/出口寿命变了，立即按新参数重挑
        server.reset_rotation()
    if (str(old.get("log_level")) != str(new.get("log_level"))
            or int(old.get("log_file_max_mb") or 0) != int(new.get("log_file_max_mb") or 0)
            or int(old.get("log_backups") or 0) != int(new.get("log_backups") or 0)):
        setup_logging()
        log.info("日志设置已更新（级别 %s / 上限 %sMB / 保留 %s 份）",
                 new.get("log_level"), new.get("log_file_max_mb"), new.get("log_backups"))
    if old.get("upstream_source") != new.get("upstream_source"):
        # 代理来源切换（照 ProxyCat）：立即换候选，不等缓存过期
        server.reset_rotation("来源已切换")
    if new.get("auto_drop_slow") and (int(old.get("max_delay_ms") or 0) != cap):
        # 上限调低时立刻把已经超线的条目清掉，不必等下一轮验证
        threading.Thread(target=store.purge_slow, args=(cap,), kwargs={"only_marked": True},
                             daemon=True).start()
    if (old.get("listen_host"), int(old.get("listen_port")),
            _socks_port(old)) != \
       (new.get("listen_host"), int(new.get("listen_port")),
            _socks_port(new)):
        try:
            run_coro(_restart_listener(new), 30)
        except Exception as exc:
            return err(f"端口变更失败: {exc}")
    if (old.get("web_host"), int(old.get("web_port"))) != \
       (new.get("web_host"), int(new.get("web_port"))):
        log.warning("面板端口已改，需要重启进程才生效")
    if bool(old.get("plugin_enabled")) != bool(new.get("plugin_enabled")):
        plugins.set_global_enabled(bool(new.get("plugin_enabled")))
    if bool(new.get("plugin_hot_reload")) and \
            not bool(old.get("plugin_hot_reload")):
        plugins.start_watch()
    if (str(old.get("theme")) != str(new.get("theme"))
            or str(old.get("lang")) != str(new.get("lang"))):
        log.info("界面偏好已更新：主题 %s / 语言 %s", new.get("theme"), new.get("lang"))
    return ok(settings=public_settings())


async def _restart_listener(s):
    await server.stop()
    await server.start(s["listen_host"], int(s["listen_port"]), _socks_port(s))


@app.route("/api/service", methods=["POST"])
def api_service():
    action = (request.get_json(force=True) or {}).get("action")
    s = store.settings()
    try:
        if action == "start":
            if not server.running:
                run_coro(server.start(s["listen_host"], int(s["listen_port"]),
                                      _socks_port(s)), 30)
        elif action == "stop":
            if server.running:
                run_coro(server.stop(), 30)
        else:
            return err("未知操作")
    except Exception as exc:
        return err(exc)
    return ok(state=server.snapshot())


@app.route("/api/proxies")
def api_proxies():
    args = request.args
    rows, total = store.list(
        status=args.get("status") or None,
        protocol=args.get("protocol") or None,
        q=args.get("q") or None,
        enabled=None if args.get("enabled") in (None, "", "all")
        else args.get("enabled") in ("1", "true"),
        https=args.get("https") == "1",
        anon=args.get("anon") or None,
        limit=min(int(args.get("limit", 500)), 2000),
        offset=int(args.get("offset", 0)),
        sort=args.get("sort", "delay"),
        max_delay=int(args.get("maxdelay") or 0) or None,
        source=args.get("source") or None,
        favorite=args.get("favorite") == "1",
    )
    return ok(rows=rows, total=total)


@app.route("/api/proxies/sources")
def api_proxy_sources():
    """池里出现过的入库来源，给筛选下拉用。"""
    return ok(sources=store.sources_distinct())


@app.route("/api/proxies/<int:pid>/favorite", methods=["POST"])
def api_favorite(pid):
    """星标/取消星标。收藏的节点在「收藏优先」排序与导出里排前面。"""
    data = request.get_json(force=True) or {}
    fav = bool(data.get("favorite"))
    store.set_favorite(pid, fav)
    return ok(id=pid, favorite=fav)


@app.route("/api/proxies", methods=["POST"])
def api_add():
    data = request.get_json(force=True) or {}
    text = data.get("text", "")
    rows = sources.parse_blob(text, source=data.get("source") or "manual")
    if not rows:
        return err("没有解析到有效代理（需要 ip:port 或 proto://ip:port）")
    _added, ids = store.add_many(rows)
    if ids:
        _geo_fill()
    if store.settings().get("validate_on_add") and ids:
        validate_rows(_rows_by_ids(ids))
    return ok(added=len(ids), parsed=len(rows))


@app.route("/api/proxies/<int:pid>", methods=["GET", "PUT", "DELETE"])
def api_proxy_one(pid):
    if request.method == "GET":
        row = store.get(pid)
        return ok(row=row) if row else err("不存在", 404)
    if request.method == "DELETE":
        return ok(deleted=store.delete([pid]))
    data = request.get_json(force=True) or {}
    if "protocol" in data and data["protocol"] not in sources.SUPPORTED:
        return err("协议只支持 http / https / socks5")
    return ok(updated=store.update(pid, data))


@app.route("/api/proxies/<int:pid>/toggle", methods=["POST"])
def api_toggle(pid):
    data = request.get_json(force=True) or {}
    enabled = bool(data.get("enabled"))
    return ok(updated=store.set_enabled([pid], enabled))


@app.route("/api/proxies/<int:pid>/test", methods=["POST"])
def api_test_one(pid):
    """即时单条测试：不等定时验证，点一下就知道这条代理现在的状态。"""
    row = store.get(pid)
    if not row:
        return err("代理不存在")
    s = store.settings()
    t0 = time.time()
    try:
        res = run_coro(sources.check_one(
            row, s["test_url"], int(s["validate_timeout"]),
            s.get("anon_echo_url") or "" if s.get("verify_anonymity") else "",
            bool(s.get("verify_anonymity"))), 60)
    except Exception as exc:
        return err(f"测试失败: {exc}")
    good, delay, anon, hok, rip = res
    cap = int(s.get("max_delay_ms") or 0)
    state = store.set_result(pid, good, delay, source="check", anon=anon,
                             https_ok=hok, max_delay_ms=cap, real_ip=rip)
    if state == "slow":
        return ok(id=pid, valid=False, slow=True, delay=delay, anon=anon or "unknown",
                  https=bool(hok), ms=round(time.time() - t0, 1),
                  msg=f"延迟 {int(delay or 0)}ms，超过上限 {cap}ms，已按慢节点处理")
    return ok(id=pid, valid=bool(good), delay=delay, anon=anon or "unknown",
              https=bool(hok), real_ip=rip, ms=round(time.time() - t0, 1))


@app.route("/api/proxies/batch", methods=["POST"])
def api_batch():
    data = request.get_json(force=True) or {}
    ids = [int(i) for i in (data.get("ids") or [])]
    action = data.get("action")
    if action in ("enable_all", "disable_all"):
        return ok(updated=store.set_enabled_all(action == "enable_all"))
    if action == "delete_all":
        if not data.get("confirm"):
            return err("删除所有是不可恢复操作，请二次确认")
        return ok(deleted=store.delete_all(only_invalid=bool(data.get("only_invalid"))))
    if action == "delete_all_invalid":
        return ok(deleted=store.delete_all(only_invalid=True))
    if not ids:
        return err("没有选中代理")
    if action == "delete":
        return ok(deleted=store.delete(ids))
    if action == "enable":
        return ok(updated=store.set_enabled(ids, True))
    if action == "disable":
        return ok(updated=store.set_enabled(ids, False))
    if action == "validate":
        return ok(result=validate_rows(_rows_by_ids(ids)))
    return err("未知操作")


@app.route("/api/validate", methods=["POST"])
def api_validate():
    data = request.get_json(force=True) or {}
    scope = data.get("scope", "invalid")
    if busy["validating"]:
        return err("已有验证任务在跑")
    rows, _ = store.list(status=None if scope == "all" else ("valid" if scope == "valid" else "invalid"),
                         limit=3000, sort="new")
    if data.get("only_enabled", True):
        rows = [r for r in rows if r["enabled"]]
    busy["validating"] = True
    busy["progress"] = f"验证 {len(rows)} 条"

    def work():
        try:
            result = validate_rows(rows)
            extra = f"，{result['slow']} 条超延迟" if result.get("slow") else ""
            SCHED["validate"].update(last=time.time(), ok=True,
                                     note=f"{result['checked']} 条，{result['valid']} 有效{extra}")
        finally:
            busy["validating"] = False
            busy["progress"] = ""
            store.checkpoint()

    threading.Thread(target=work, daemon=True).start()
    return ok(started=True, count=len(rows))


@app.route("/api/fetch/scope", methods=["POST"])
def api_fetch_scope():
    """保存抓取范围：all / cn / global / country(配合国家代码)。"""
    data = request.get_json(force=True) or {}
    scope = str(data.get("scope") or "all")
    if scope not in ("all", "cn", "global", "country"):
        return err("未知的抓取范围")
    valid = {c["code"]: c["name"] for c in sources.country_list()}
    codes = [str(c or "").strip().upper() for c in (data.get("countries") or [])]
    codes = [c for c in dict.fromkeys(codes) if c]
    bad = [c for c in codes if c not in valid]
    if bad:
        return err("不支持的地区：" + ",".join(bad))
    if len(codes) > sources.MAX_SCOPE_COUNTRIES:
        return err(f"最多一次选 {sources.MAX_SCOPE_COUNTRIES} 个国家/地区")
    if scope == "country" and not codes:
        return err("请至少选择一个国家/地区")
    store.save_settings({"fetch_scope": scope,
                         "fetch_countries": ",".join(codes) if scope == "country" else ""})
    label = {"all": "全部", "cn": "仅国内（中国大陆）", "global": "仅国外（排除大陆及港澳台）",
             "country": "、".join(valid[c] for c in codes)}[scope]
    log.info("抓取范围 -> %s", label)
    return ok(scope=scope, countries=codes, label=label)


@app.route("/api/fetch", methods=["POST"])
def api_fetch():
    if busy["fetching"]:
        return err("已有抓取任务在跑")
    s = store.settings()
    # 自动爬取弹窗（照无影）：可勾选免费代理 / 指定测绘 API 源，带数量与协议过滤；
    # 不带 body 时保持原行为（全部内置源 + 全部已配置自定义源）
    data = request.get_json(silent=True) or {}
    free = bool(data.get("free", True))
    proto = (data.get("protocol") or "").strip().lower()
    if proto not in ("", "http", "https", "socks5"):
        return err("代理类型只支持 http / https / socks5")
    try:
        max_total = int(data.get("max_total") or 0) or int(s["max_fetch_total"])
    except (TypeError, ValueError):
        max_total = int(s["max_fetch_total"])
    api_ids = []
    for sid in (data.get("api_ids") or []):
        try:
            api_ids.append(int(sid))
        except (TypeError, ValueError):
            pass
    custom = None
    if api_ids:
        picked = []
        for sid in api_ids:
            src = store.get_api_source(sid)
            if not src:
                continue
            pub = _public_api_source(src)
            if pub["configured"]:
                picked.append(pub)
        if not picked and not free:
            return err("勾选的测绘源都还没配好 Key，先填 Key 或勾上免费代理")
        custom = picked or None
    busy["fetching"] = True
    busy["progress"] = "抓取源清单中"

    def work():
        try:
            rows, report = run_coro(sources.fetch_all(
                max_total, bool(s.get("fetch_geonode")) and free,
                _custom_sources() if custom is None and free else custom,
                scope=s.get("fetch_scope") or "all",
                countries=_scope_countries(s),
                skip_builtin=not free), 600)
            if proto:
                rows = [r for r in rows if (r.get("protocol") or "").lower() == proto]
            busy["progress"] = f"抓取到 {len(rows)} 条，入库中"
            _added, ids = store.add_many(rows)
            _geo_fill()
            busy["progress"] = f"新入库 {len(ids)} 条，验证中"
            if s.get("validate_on_add") and ids:
                validate_rows(_rows_by_ids(ids))
            _merge_custom_report(report)
            SCHED["fetch"].update(last=time.time(), ok=True,
                                  next=time.time() + int(s["fetch_interval_minutes"]) * 60,
                                  note=f"候选 {len(rows)}，新增 {len(ids)}")
            log.info("抓取完成: %s 条候选, 新增 %s", len(rows), len(ids))
            return report
        except Exception as exc:
            SCHED["fetch"].update(last=time.time(), ok=False, note=str(exc)[:60])
            log.error("抓取失败: %s", exc)
        finally:
            busy["fetching"] = False
            busy["progress"] = ""
            store.checkpoint()

    t = threading.Thread(target=work, daemon=True)
    t.start()
    return ok(started=True)


@app.route("/api/apisources/<int:sid>/fetch", methods=["POST"])
def api_api_source_fetch(sid):
    """单源立即抓取（自定义源版）：只跑指定的测绘 API / 仓库源。"""
    row = store.get_api_source(sid)
    if not row:
        return err("源不存在")
    pub = _public_api_source(row)
    if not pub["configured"]:
        return err("该源还没配好（缺 key 或语法），先点「配置」补全")
    if busy["fetching"]:
        return err("已有抓取任务在跑")
    s = store.settings()
    busy["fetching"] = True
    busy["progress"] = f"抓取源：{pub['name']}"

    def work():
        try:
            rows, rep = run_coro(sources.fetch_all(
                0, False, custom=[pub], skip_builtin=True), 300)
            got = sum(r.get("count", 0) for r in rep)
            busy["progress"] = f"「{pub['name']}」抓到 {got} 条，入库中"
            _added, ids = store.add_many(rows)
            _geo_fill()
            busy["progress"] = f"「{pub['name']}」新入库 {len(ids)} 条，验证中"
            if s.get("validate_on_add") and ids:
                validate_rows(_rows_by_ids(ids))
            _merge_custom_report(rep)
            SCHED["fetch"].update(last=time.time(), ok=True,
                                  note=f"单源 {pub['name']}：候选 {got}，新增 {len(ids)}")
            log.info("单源抓取 %s: %s 条候选, 新增 %s", pub["name"], got, len(ids))
        except Exception as exc:
            store.touch_api_source(sid, error=str(exc))
            log.error("单源抓取失败 %s: %s", pub["name"], exc)
        finally:
            busy["fetching"] = False
            busy["progress"] = ""
            store.checkpoint()

    threading.Thread(target=work, daemon=True).start()
    return ok(started=True)


@app.route("/api/fetch/source", methods=["POST"])
def api_fetch_source():
    """单源立即抓取：只跑指定的内置源，走同一套入库+验证流程。"""
    name = (request.get_json(force=True) or {}).get("name") or ""
    if not name:
        return err("缺少源名称")
    if busy["fetching"]:
        return err("已有抓取任务在跑")
    s = store.settings()
    busy["fetching"] = True
    busy["progress"] = f"抓取源：{name}"

    def work():
        try:
            rows, _rep = run_coro(sources.fetch_all(
                int(s["max_fetch_total"]), False, None, only=name,
                scope=s.get("fetch_scope") or "all", countries=_scope_countries(s)), 300)
            busy["progress"] = f"「{name}」抓到 {len(rows)} 条，入库中"
            _added, ids = store.add_many(rows)
            _geo_fill()
            busy["progress"] = f"「{name}」新入库 {len(ids)} 条，验证中"
            if s.get("validate_on_add") and ids:
                validate_rows(_rows_by_ids(ids))
            SCHED["fetch"].update(last=time.time(), ok=True,
                                  note=f"单源 {name}：候选 {len(rows)}，新增 {len(ids)}")
            log.info("单源抓取 %s: %s 条候选, 新增 %s", name, len(rows), len(ids))
        except Exception as exc:
            log.error("单源抓取失败 %s: %s", name, exc)
        finally:
            busy["fetching"] = False
            busy["progress"] = ""
            store.checkpoint()

    threading.Thread(target=work, daemon=True).start()
    return ok(started=True)


def _mask(value):
    """凭证脱敏：只留首 2 位与末 4 位，够用户确认是哪一把 key。"""
    v = str(value or "")
    if not v:
        return ""
    if len(v) <= 6:
        return "****"
    return v[:2] + "****" + v[-4:]


def _api_source_ready(row):
    """这个源是否具备被抓取的条件（缺仓库地址或缺 key 都不跑）。"""
    meta = apisources.PROVIDERS.get((row.get("provider") or "").lower())
    if not meta:
        return False
    if meta["kind"] in ("repo", "url"):
        return bool((row.get("target") or "").strip())
    creds = row.get("creds") or {}
    return all(str(creds.get(c) or "").strip() for c in meta["creds"])


def _public_api_source(row):
    d = {k: row.get(k) for k in ("id", "name", "provider", "target", "query",
                                 "protocol", "cap", "enabled", "created_at",
                                 "last_run", "last_count", "last_error", "interval")}
    creds = row.get("creds") or {}
    d["creds_masked"] = {k: _mask(v) for k, v in creds.items()}
    d["has_creds"] = any(str(v or "").strip() for v in creds.values())
    d["configured"] = _api_source_ready(row)
    return d


def _custom_sources():
    """真正参与抓取的自定义源：总开关开 + 单源启用 + 配置齐全。"""
    if not store.settings().get("fetch_custom", True):
        return []
    return [s for s in store.api_sources(enabled_only=True) if _api_source_ready(s)]


def _scope_countries(s):
    """设置里的国家代码（逗号分隔）-> 大写代码列表。范围不是 country 时返回空。"""
    if (s.get("fetch_scope") or "all") != "country":
        return []
    return [c.strip().upper() for c in str(s.get("fetch_countries") or "").split(",")
            if c.strip()]


def _merge_custom_report(report):
    """把每个自定义源的抓取结果写回库（面板显示「上次抓到 N 条 / 报错」）。"""
    for r in report or []:
        if r.get("custom") and r.get("id"):
            store.touch_api_source(int(r["id"]), int(r.get("count") or 0),
                                   r.get("error") or "")


@app.route("/api/apisources", methods=["GET", "POST"])
def api_apisources():
    if request.method == "GET":
        rows = [_public_api_source(s) for s in store.api_sources()]
        return ok(sources=rows, providers=apisources.PROVIDERS,
                  notice=apisources.PROVIDER_NOTICE,
                  enabled=bool(store.settings().get("fetch_custom", True)),
                  active=len(_custom_sources()))

    data = request.get_json(force=True) or {}
    provider = (data.get("provider") or "").strip().lower()
    meta = apisources.PROVIDERS.get(provider)
    if not meta:
        return err("未知的源类型")
    target = (data.get("target") or "").strip()
    creds = data.get("creds") or {}
    if meta["kind"] in ("repo", "url"):
        if not target:
            return err("请填写仓库地址" if meta["kind"] == "repo" else "请填写清单地址")
    else:
        missing = [c for c in meta["creds"] if not str(creds.get(c) or "").strip()]
        if missing:
            return err("缺少凭证：" + "、".join(missing))
    if meta["kind"] == "repo" and not apisources.parse_repo_spec(target)[0]:
        return err("仓库格式应为 owner/repo，例如 ErcinDedeoglu/proxies")

    # 同一个仓库 / 同一条查询语句只允许配一次，否则会重复抓、重复占验证配额
    query = (data.get("query") or "").strip() or meta.get("sample", "")
    for old in store.api_sources():
        if old["provider"] != provider:
            continue
        if meta["kind"] in ("repo", "url"):
            if (old.get("target") or "").strip().lower() == target.lower():
                return err(f"「{old['name']}」已经用过这个地址了")
        elif (old.get("query") or "").strip() == query:
            return err(f"「{old['name']}」已经用过这条查询语句了")

    name = (data.get("name") or "").strip()
    if not name:
        name = meta["label"]
        if meta["kind"] == "repo":
            name = target.rstrip("/").split("/")[-1] or meta["label"]
    sid = store.add_api_source({
        "name": name, "provider": provider, "target": target,
        "query": query,
        "protocol": data.get("protocol") or "http",
        "creds": creds, "cap": data.get("cap") or 300, "enabled": True,
    })
    log.info("新增自定义源: %s (%s)", name, provider)
    return ok(id=sid, name=name)


@app.route("/api/apisources/<int:sid>", methods=["PUT", "DELETE"])
def api_api_source(sid):
    cur = store.get_api_source(sid)
    if not cur:
        return err("源不存在")
    if request.method == "DELETE":
        store.delete_api_source(sid)
        log.info("删除自定义源: %s", cur["name"])
        return ok(deleted=True)

    data = request.get_json(force=True) or {}
    if "creds" in data:
        merged = dict(cur.get("creds") or {})
        for k, v in (data.get("creds") or {}).items():
            v = str(v or "").strip()
            if v and not v.startswith("****"):
                merged[k] = v        # 留空或仍是掩码 → 保持原值
        data["creds"] = merged
    store.update_api_source(sid, data)
    return ok(updated=True)


@app.route("/api/apisources/<int:sid>/toggle", methods=["POST"])
def api_api_source_toggle(sid):
    cur = store.get_api_source(sid)
    if not cur:
        return err("源不存在")
    enabled = not bool(cur.get("enabled"))
    store.update_api_source(sid, {"enabled": enabled})
    return ok(enabled=enabled)


@app.route("/api/apisources/test", methods=["POST"])
def api_api_source_test():
    """试抓：只取前 20 条，不入库，用来验证 key / 仓库地址 / 查询语句是否有效。"""
    data = request.get_json(force=True) or {}
    cfg = None
    if data.get("id"):
        cfg = store.get_api_source(int(data["id"]))
        if not cfg:
            return err("源不存在")
    if data.get("provider"):
        base = dict(cfg or {})
        base.update({k: data[k] for k in
                     ("provider", "target", "query", "protocol", "cap", "name")
                     if k in data})
        if data.get("creds"):
            merged = dict(base.get("creds") or {})
            for k, v in (data["creds"] or {}).items():
                v = str(v or "").strip()
                if v and not v.startswith("****"):
                    merged[k] = v
            base["creds"] = merged
        cfg = base
    if not cfg:
        return err("缺少源配置")
    cfg.setdefault("name", "test")
    try:
        res = run_coro(apisources.test_source(cfg, 10), 120)
    except Exception as exc:
        return err(f"试抓失败：{exc}")
    return ok(**res)


@app.route("/api/sources")
def api_sources():
    """抓取源清单 + 最近一次逐源结果。"""
    s = store.settings()
    result = {r["name"]: r for r in sources.LAST_REPORT}
    rows = []
    for src in sources.source_catalog():
        hit = result.get(src["name"]) or {}
        rows.append(dict(src, count=hit.get("count", 0), error=hit.get("error", ""),
                         ran=bool(hit)))
    ov = _builtin_overrides(s)
    return ok(sources=rows, geonode=bool(s.get("fetch_geonode")),
              last_run=bool(result), quality=store.source_stats(),
              custom=[_public_api_source(x) for x in store.api_sources()],
              custom_active=len(_custom_sources()),
              custom_enabled=bool(s.get("fetch_custom", True)),
              deleted=ov["deleted"])


@app.route("/api/sources/test", methods=["POST"])
def api_source_test():
    """试抓一个内置免费源：只下载解析不入库（照自定义源「测试」的行为）。"""
    data = request.get_json(force=True) or {}
    name = str(data.get("name") or "").strip()
    src = next((x for x in sources.builtin_sources() if x["name"] == name), None)
    if not src:
        return err("源不存在（可能已被删除，先恢复再试）")

    async def _run():
        import aiohttp
        async with aiohttp.ClientSession(
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ProxyDog/1.4"}) as ses:
            items, terr = await sources.fetch_text(ses, src, timeout=30, retries=1)
        return items, terr

    try:
        items, terr = run_coro(_run(), 60)
    except Exception as exc:
        return err(f"试抓失败: {exc}")
    uniq, seen = [], set()
    for r in items:
        key = (r.get("host"), r.get("port"), r.get("protocol"))
        if key not in seen:
            seen.add(key)
            uniq.append(f"{r.get('host')}:{r.get('port')}")
    return ok(name=name, count=len(items), unique=len(uniq),
              sample=uniq[:15], error=terr or "")


@app.route("/api/sources/toggle", methods=["POST"])
def api_source_toggle():
    """停用 / 启用内置源：停用后自动与定时抓取跳过它，单源「立即抓取」仍可用。"""
    name = str((request.get_json(force=True) or {}).get("name") or "").strip()
    if not any(x["name"] == name for x in sources.builtin_sources()):
        return err("源不存在")
    ov = _builtin_overrides()
    if name in ov["disabled"]:
        ov["disabled"].remove(name)
        note = "已启用"
    else:
        ov["disabled"].append(name)
        note = "已停用，自动抓取将跳过该源"
    _save_builtin_overrides(ov)
    return ok(enabled=name not in ov["disabled"], note=note)


@app.route("/api/sources/edit", methods=["POST"])
def api_source_edit():
    """编辑内置源的清单地址 / 条数上限（与默认一致时自动清除覆盖）。"""
    data = request.get_json(force=True) or {}
    name = str(data.get("name") or "").strip()
    orig = next((x for x in sources.SOURCES if x["name"] == name), None)
    if not orig:
        return err("源不存在")
    url = str(data.get("url") or "").strip()
    if url and not url.lower().startswith(("http://", "https://")):
        return err("清单地址必须是 http(s):// 开头")
    try:
        cap = max(1, min(50000, int(data.get("cap") or orig["cap"])))
    except (TypeError, ValueError):
        return err("条数上限不合法")
    ov = _builtin_overrides()
    if url == orig["url"] and cap == orig["cap"]:
        ov["edited"].pop(name, None)
    else:
        ov["edited"][name] = {"url": url or orig["url"], "cap": cap}
    _save_builtin_overrides(ov)
    return ok(note="已保存")


@app.route("/api/sources/delete", methods=["POST"])
def api_source_delete():
    """删除内置源（可整体恢复）。"""
    name = str((request.get_json(force=True) or {}).get("name") or "").strip()
    if not any(x["name"] == name for x in sources.SOURCES):
        return err("源不存在")
    ov = _builtin_overrides()
    if name not in ov["deleted"]:
        ov["deleted"].append(name)
    ov["disabled"] = [x for x in ov["disabled"] if x != name]
    ov["edited"].pop(name, None)
    _save_builtin_overrides(ov)
    return ok(note=f"已删除「{name}」，之后可在「恢复内置源」里找回来")


@app.route("/api/sources/restore", methods=["POST"])
def api_source_restore():
    """恢复被删除的内置源：带 name 恢复单个，不带则全部恢复。"""
    name = str((request.get_json(force=True) or {}).get("name") or "").strip()
    ov = _builtin_overrides()
    if name:
        ov["deleted"] = [x for x in ov["deleted"] if x != name]
    else:
        ov["deleted"] = []
    _save_builtin_overrides(ov)
    return ok(note="已恢复")


@app.route("/api/import", methods=["POST"])
def api_import():
    data = request.get_json(force=True) or {}
    text = data.get("text") or ""
    url = (data.get("url") or "").strip()
    if url:
        try:
            text = run_coro(_download(url), 60)
        except Exception as exc:
            return err(f"下载失败: {exc}")
    report = {}
    rows = sources.parse_blob(text, source=data.get("source") or "subscription",
                              report=report)
    if not rows:
        skipped = report.get("skipped", 0)
        if skipped:
            return err(f"解析到 {skipped} 个节点，但都是 vmess/ss/trojan 这类"
                       "隧道协议，无法直接当 HTTP/SOCKS5 上游，已跳过")
        return err("没有解析到可用节点（支持 ip:port、协议链接、Clash YAML、V2Ray JSON）")
    _added, ids = store.add_many(rows)
    if ids:
        _geo_fill()
    if data.get("validate", True) and ids:
        validate_rows(_rows_by_ids(ids))
    extra = (f"，跳过 {report['skipped']} 个 vmess/ss 等隧道节点"
             if report.get("skipped") else "")
    return ok(parsed=len(rows), added=len(ids), skipped=report.get("skipped", 0),
              note=extra)


async def _download(url):
    import aiohttp
    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=40)) as resp:
            if resp.status != 200:
                raise RuntimeError(f"HTTP {resp.status}")
            return await resp.text(errors="ignore")


@app.route("/api/geoip")
def api_geoip_status():
    """离线归属地库状态（含下载进度）。"""
    return ok(**geoip.status())


@app.route("/api/geoip/download", methods=["POST"])
def api_geoip_download():
    if geoip.PROGRESS.get("running"):
        return ok(started=False, note="已经在下载中")
    prefer = (request.get_json(force=True) or {}).get("provider")
    geoip.update(blocking=False, prefer=prefer)
    return ok(started=True)


@app.route("/api/geoip/fill", methods=["POST"])
def api_geoip_fill():
    """手动触发一次补全（正常情况下后台会自动补，这里只是兜底）。"""
    if not geoip.ready():
        return err("离线库还没下载，先点「下载离线库」")
    n = _geo_fill(50000)
    return ok(updated=n)


def _geo_fill(limit=3000):
    """用本地离线库给缺归属地的代理补上。纯本地计算，几十条基本无感。"""
    if not geoip.ready():
        return 0
    rows = store.missing_region(limit)
    if not rows:
        return 0
    pairs = []
    for r in rows:
        label = geoip.lookup(r["host"])
        if label:
            pairs.append((r["id"], label))
    return store.set_regions(pairs)


@app.route("/api/export")
def api_export():
    fmt = request.args.get("format", "txt")
    cap = int(store.settings().get("max_delay_ms") or 0) if \
        (request.args.get("status") or "valid") == "valid" else None
    rows, _ = store.list(status=request.args.get("status") or "valid",
                         protocol=request.args.get("protocol") or None,
                         limit=5000, sort="delay", max_delay=cap)
    if fmt == "json":
        payload = [{k: r[k] for k in ("host", "port", "protocol", "username", "password",
                                      "region", "delay_ms", "is_valid", "source")}
                   for r in rows]
        return Response(json.dumps(payload, ensure_ascii=False, indent=2),
                        mimetype="application/json",
                        headers={"Content-Disposition": "attachment; filename=proxydog.json"})
    if fmt == "xlsx":
        from openpyxl import Workbook
        wb = Workbook()
        ws = wb.active
        ws.title = "proxies"
        ws.append(["Num", "Host", "Port", "Type", "账号", "密码",
                   "地区", "延时", "状态", "来源"])
        for i, r in enumerate(rows, 1):
            ws.append([i, r["host"], r["port"], r["protocol"], r["username"],
                       r["password"], r["region"], r["delay_ms"],
                       "启用" if r["is_valid"] else "失败", r["source"]])
        buf = io.BytesIO()
        wb.save(buf)
        filename = "Proxy-" + time.strftime("%Y%m%d-%H%M%S") + ".xlsx"
        return Response(
            buf.getvalue(),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f"attachment; filename={filename}"})
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["host", "port", "protocol", "username", "password",
                    "region", "delay_ms", "valid", "source"])
        for r in rows:
            w.writerow([r["host"], r["port"], r["protocol"], r["username"], r["password"],
                        r["region"], r["delay_ms"], r["is_valid"], r["source"]])
        return Response(buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=proxydog.csv"})
    body = "\n".join(sources.proxy_url(r) for r in rows)
    return Response(body, mimetype="text/plain",
                    headers={"Content-Disposition": "attachment; filename=proxydog.txt"})


@app.route("/api/cleanup", methods=["POST"])
def api_cleanup():
    s = store.settings()
    cap = int(s.get("max_delay_ms") or 0)
    before = store.count_invalid()
    slow = store.purge_slow(cap)
    # 保留保护：只删连续判死 3 次以上的，刚失败一两次的先观察
    dead = store.cleanup(0)
    remain = max(0, before - dead)
    return ok(deleted=slow + dead, slow=slow, dead=dead, remain=remain)


# ---------------- 统计 / 日志 ----------------
@app.route("/api/series")
def api_series():
    minutes = max(5, min(int(request.args.get("minutes", 60)), 1440))
    return ok(series=store.log_series(minutes), summary=store.log_summary(minutes))


@app.route("/api/logs")
def api_logs():
    args = request.args
    ok_flag = args.get("ok")
    rows, total = store.logs(
        limit=min(int(args.get("limit", 100)), 1000),
        offset=int(args.get("offset", 0)),
        ok=None if ok_flag in (None, "", "all") else int(ok_flag == "1"),
        proto=args.get("proto") or None,
        q=args.get("q") or None,
        since=(time.time() - int(args["minutes"]) * 60) if args.get("minutes") else None,
    )
    return ok(rows=rows, total=total)


@app.route("/api/logs/export")
def api_logs_export():
    rows, _ = store.logs(limit=10000, offset=0,
                         ok=None if request.args.get("ok") in (None, "", "all")
                         else int(request.args.get("ok") == "1"),
                         proto=request.args.get("proto") or None,
                         q=request.args.get("q") or None)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["time", "client", "proto", "target", "exit_proto", "exit_host",
                "exit_port", "ok", "ms", "bytes", "note"])
    for r in rows:
        w.writerow([time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"] or 0)),
                    r["client"], r["proto"], r["target"], r["exit_proto"],
                    r["exit_host"], r["exit_port"], "ok" if r["ok"] else "fail",
                    r["ms"], r["nbytes"], r["note"]])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=proxydog-access.csv"})


@app.route("/api/logs/clear", methods=["POST"])
def api_logs_clear():
    if not require_user():
        return err("需要登录用户操作", 403)
    return ok(deleted=store.clear_logs())


# ---------------- 域名统计（照 ProxyCat：按「条数×出口」汇总，保留 30 天） ----------------
@app.route("/api/domains")
def api_domains():
    args = request.args
    rows, total = store.domain_stats(limit=int(args.get("limit", 50)),
                                     q=args.get("q") or None)
    return ok(rows=rows, total=total)


@app.route("/api/domains/clear", methods=["POST"])
def api_domains_clear():
    if not require_user():
        return err("需要登录用户操作", 403)
    return ok(deleted=store.clear_domains())


# ---------------- 运行日志（主程序日志文件的分页签查看） ----------------
_RUN_LOGGERS = {
    "main": {"proxydog"},
    "proxy": {"proxydog.proxy"},
    "plugin": {"proxydog.plugin"},
    "werkzeug": {"werkzeug"},
}


@app.route("/api/runlog")
def api_runlog():
    """读主程序日志文件尾部；filter 按 logger 名精确匹配，附级别统计。"""
    import html as _html
    want = request.args.get("filter", "all")
    lines_want = max(10, min(int(request.args.get("lines", 300)), 2000))
    raw = []
    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as fh:
            raw = fh.readlines()[-(lines_want * 4):]      # 多读点，过滤后再截
    except OSError:
        pass
    needles = _RUN_LOGGERS.get(want)
    rows, counts = [], {"ERROR": 0, "WARNING": 0, "INFO": 0}
    for ln in raw:
        ln = ln.rstrip("\n")
        if not ln:
            continue
        parts = ln.split(" - ", 3)         # 时间 - logger - 级别 - 内容
        logger = parts[1].strip() if len(parts) >= 3 else ""
        if needles and logger not in needles:
            continue
        rows.append(ln)
        if len(parts) >= 3:
            lv = parts[2].strip()
            if lv in counts:
                counts[lv] += 1
    return ok(rows=[_html.escape(x) for x in rows[-lines_want:]],
              counts=counts, file=LOG_FILE)


@app.route("/api/runlog/export")
def api_runlog_export():
    return send_from_directory(LOG_DIR, "proxydog.log", as_attachment=True)


@app.route("/api/runlog/clear", methods=["POST"])
def api_runlog_clear():
    if not require_user():
        return err("需要登录用户操作", 403)
    try:
        with open(LOG_FILE, "w", encoding="utf-8") as fh:
            fh.write("")
        log.info("运行日志已清空")
    except OSError as exc:
        return err(f"清空失败: {exc}")
    return ok(cleared=True)


# ---------------- 多用户管理 ----------------
@app.route("/api/users", methods=["GET"])
def api_users():
    if not require_user():
        return err("需要登录用户操作", 403)
    return ok(users=store.list_users())


@app.route("/api/users", methods=["POST"])
def api_user_add():
    ident = require_user()
    if not ident:
        return err("需要登录用户操作", 403)
    data = request.get_json(force=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    if not re.match(r"^[\w.\-]{2,32}$", username):
        return err("用户名 2-32 位，限字母数字 ._ -")
    if len(password) < 6:
        return err("密码至少 6 位")
    role = "admin" if data.get("role") == "admin" else "viewer"
    pwd_hash, salt = auth.hash_password(password)
    if not store.create_user(username, pwd_hash, salt, role):
        return err("用户名已存在")
    log.info("新增面板用户: %s (%s) by %s", username, role, ident.get("name"))
    return ok(username=username, role=role)


@app.route("/api/users/<int:uid>", methods=["DELETE"])
def api_user_del(uid):
    ident = require_user()
    if not ident:
        return err("需要登录用户操作", 403)
    user = store.get_user_by_id(uid)
    if not user:
        return err("用户不存在", 404)
    if len(store.list_users()) <= 1:
        return err("至少保留一个账号")
    if user["username"] == ident.get("name"):
        return err("不能删除当前登录的账号")
    with store._lock:
        store._conn.execute("DELETE FROM users WHERE id=?", (uid,))
        store._conn.commit()
    log.info("删除面板用户: %s by %s", user["username"], ident.get("name"))
    return ok(deleted=True)


@app.route("/api/users/<int:uid>/password", methods=["POST"])
def api_user_pwd(uid):
    ident = require_user()
    if not ident:
        return err("需要登录用户操作", 403)
    user = store.get_user_by_id(uid)
    if not user:
        return err("用户不存在", 404)
    new = (request.get_json(force=True) or {}).get("password") or ""
    if len(new) < 6:
        return err("密码至少 6 位")
    pwd_hash, salt = auth.hash_password(new)
    store.set_password(user["username"], pwd_hash, salt)
    log.info("重置用户密码: %s by %s", user["username"], ident.get("name"))
    return ok(message="密码已更新")


# ---------------- 入站认证账号（代理端口多用户） ----------------
_PROXY_USER_RE = re.compile(r"^[\w.\-@]{1,32}$")


@app.route("/api/proxy-users", methods=["GET"])
def api_proxy_users():
    if not require_user():
        return err("需要登录用户操作", 403)
    rows = store.list_proxy_users(with_pwd=bool(request.args.get("pwd")))
    s = store.settings()
    return ok(users=rows,
              auth=bool(store.count_proxy_users()),
              listen={"host": s.get("listen_host") or "127.0.0.1",
                      "port": int(s.get("listen_port") or 2080),
                      "socks": int(s.get("listen_port") or 2080) if s.get("socks_shared")
                               else int(s.get("socks_port") or 2081),
                      "shared": bool(s.get("socks_shared"))})


@app.route("/api/proxy-users", methods=["POST"])
def api_proxy_user_add():
    ident = require_user()
    if not ident:
        return err("需要登录用户操作", 403)
    data = request.get_json(force=True) or {}
    name = (data.get("username") or "").strip()
    pwd = data.get("password") or ""
    if not _PROXY_USER_RE.match(name):
        return err("用户名 1-32 位，限字母数字 ._ - @")
    if len(pwd) < 1:
        return err("密码不能为空")
    if len(pwd) > 128:
        return err("密码太长了（128 字以内）")
    if store.get_proxy_user_by_name(name):
        return err("账号已存在")
    uid = store.add_proxy_user(name, pwd, (data.get("note") or "").strip()[:60],
                               bool(data.get("enabled", True)))
    if not uid:
        return err("添加失败，账号可能已存在")
    server.invalidate_creds()
    log.info("新增代理账号: %s by %s", name, ident.get("name"))
    return ok(id=uid, username=name)


@app.route("/api/proxy-users/<int:uid>", methods=["PATCH", "POST"])
def api_proxy_user_update(uid):
    ident = require_user()
    if not ident:
        return err("需要登录用户操作", 403)
    row = store.get_proxy_user(uid)
    if not row:
        return err("账号不存在", 404)
    data = request.get_json(force=True) or {}
    pwd = data.get("password")
    note = data.get("note")
    enabled = data.get("enabled")
    if pwd is not None:
        pwd = str(pwd)
        if not pwd:
            return err("密码不能为空")
        if len(pwd) > 128:
            return err("密码太长了（128 字以内）")
    store.update_proxy_user(
        uid,
        password=pwd if pwd is not None else None,
        note=(str(note).strip()[:60] if note is not None else None),
        enabled=(bool(enabled) if enabled is not None else None))
    server.invalidate_creds()
    log.info("修改代理账号: %s by %s", row["username"], ident.get("name"))
    return ok(updated=True)


@app.route("/api/proxy-users/<int:uid>", methods=["DELETE"])
def api_proxy_user_del(uid):
    ident = require_user()
    if not ident:
        return err("需要登录用户操作", 403)
    row = store.get_proxy_user(uid)
    if not row:
        return err("账号不存在", 404)
    store.delete_proxy_user(uid)
    server.invalidate_creds()
    log.info("删除代理账号: %s by %s", row["username"], ident.get("name"))
    return ok(deleted=True)


@app.route("/api/proxy-users/<int:uid>/reveal", methods=["GET"])
def api_proxy_user_reveal(uid):
    """按需取明文密码：列表默认不下发密码，点「显示/复制」才取一次。"""
    if not require_user():
        return err("需要登录用户操作", 403)
    row = store.get_proxy_user(uid)
    if not row:
        return err("账号不存在", 404)
    return ok(password=row["password"], username=row["username"])


# ---------------- 账号 / API Key ----------------
@app.route("/api/account/password", methods=["POST"])
def api_password():
    ident = require_user()
    if not ident:
        return err("需要登录用户操作", 403)
    data = request.get_json(force=True) or {}
    user = store.get_user(ident["name"])
    if not user or not auth.verify_password(data.get("old") or "", user["pwd_hash"], user["salt"]):
        return err("原密码不正确", 403)
    new = (data.get("new") or "").strip()
    if len(new) < 6:
        return err("新密码至少 6 位")
    pwd_hash, salt = auth.hash_password(new)
    store.set_password(user["username"], pwd_hash, salt)
    log.info("修改密码: %s", user["username"])
    return ok(message="密码已更新")


@app.route("/api/keys", methods=["GET", "POST"])
def api_keys():
    if request.method == "GET":
        return ok(keys=[{k: v for k, v in r.items() if k != "key"} | {"key_tail": r["key"][-6:]}
                       for r in store.list_keys()])
    if not require_user():
        return err("需要登录用户操作", 403)
    data = request.get_json(force=True) or {}
    key = auth.new_api_key()
    try:
        quota = max(0, int(data.get("daily_quota") or 0))
    except (TypeError, ValueError):
        return err("每日配额需要整数（0 = 不限）")
    store.add_key((data.get("name") or "").strip() or "未命名", key, quota)
    log.info("新建 API Key: %s 配额=%s", data.get("name"), quota or "不限")
    return ok(key=key, daily_quota=quota)


@app.route("/api/keys/<int:kid>/reveal", methods=["GET"])
def api_key_reveal(kid):
    """查看完整 Key：列表里只给末尾 6 位，点「复制/显示」才按需取一次。"""
    if not require_user():
        return err("需要登录用户操作", 403)
    row = store.get_key(kid)
    if not row:
        return err("Key 不存在")
    return ok(key=row["key"], name=row["name"])


@app.route("/api/keys/<int:kid>", methods=["DELETE"])
def api_key_delete(kid):
    if not require_user():
        return err("需要登录用户操作", 403)
    return ok(deleted=store.delete_key(kid))


@app.route("/api/keys/<int:kid>/toggle", methods=["POST"])
def api_key_toggle(kid):
    if not require_user():
        return err("需要登录用户操作", 403)
    enabled = bool((request.get_json(force=True) or {}).get("enabled"))
    return ok(updated=store.set_key_enabled(kid, enabled))


# ---------------- 对外取用（给别的程序调用） ----------------
@app.route("/api/pool/get")
def pool_get():
    args = request.args
    try:
        count = max(1, min(int(args.get("count", 1)), 200))
    except ValueError:
        return err("count 必须是数字")
    # 默认按面板设置的延迟上限出节点；调用方传了更严格的就按调用方的
    cap = int(store.settings().get("max_delay_ms") or 0)
    try:
        want = int(args.get("max_delay") or 0)
    except ValueError:
        return err("max_delay 必须是数字")
    rows = store.pick_public(count,
                             protocol=args.get("protocol") or None,
                             max_delay=min([v for v in (cap, want) if v] or [0]),
                             region=args.get("region") or None)
    fmt = (args.get("format") or "text").lower()
    if fmt == "json":
        return jsonify([{"host": r["host"], "port": r["port"], "protocol": r["protocol"],
                         "username": r["username"], "password": r["password"],
                         "region": r["region"], "delay_ms": r["delay_ms"],
                         "url": sources.proxy_url(r)} for r in rows])
    if not rows:
        return Response("", mimetype="text/plain", status=404)     # 无可用出口 = 404
    return Response("\n".join(sources.proxy_url(r) for r in rows), mimetype="text/plain")


@app.route("/api/pool/random")
def pool_random():
    return pool_get()


@app.route("/api/pool/count")
def pool_count():
    stats = store.stats()
    return jsonify({"total": stats["total"], "valid": stats["valid"],
                    "enabled": stats["enabled"], "protocols": stats["protocols"]})


@app.route("/api/pool/report", methods=["POST"])
def pool_report():
    """客户端回传一次真实使用结果，让池子知道哪个出口在实战里能通。

    只影响健康度/隔离，不直接改 is_valid——外部上报的可信度低于本地验证。
    """
    data = request.get_json(force=True, silent=True) or {}
    row = None
    if data.get("id"):
        row = store.get(int(data["id"]))
    if row is None and data.get("host"):
        row = store.find(str(data["host"]).strip(), data.get("port"),
                         data.get("protocol") or "http")
    if not row:
        return err("找不到这个出口", 404)
    good = bool(data.get("ok"))
    try:
        ms = float(data["ms"]) if data.get("ms") is not None else None
    except (TypeError, ValueError):
        ms = None
    s = store.settings()
    store.set_result(row["id"], good, ms, source="proxy",
                     quarantine_after=int(s.get("fail_quarantine") or 4),
                     quarantine_secs=int(s.get("quarantine_seconds") or 600))
    return ok(id=row["id"], ok_result=good)


@app.route("/metrics")
def metrics():
    """Prometheus 文本格式。只暴露聚合数字，不含代理 IP，可匿名抓取。"""
    st = store.stats()
    snap = server.snapshot()
    logs = store.log_summary(15)
    lines = [
        "# HELP proxydog_pool_total 池内代理总数",
        "# TYPE proxydog_pool_total gauge",
        f"proxydog_pool_total {st['total']}",
        "# HELP proxydog_pool_valid 当前有效出口数",
        "# TYPE proxydog_pool_valid gauge",
        f"proxydog_pool_valid {st['valid']}",
        "# HELP proxydog_pool_quarantined 隔离冷却中的出口数",
        "# TYPE proxydog_pool_quarantined gauge",
        f"proxydog_pool_quarantined {st['quarantined']}",
        "# HELP proxydog_pool_avg_delay_ms 有效出口平均延迟",
        "# TYPE proxydog_pool_avg_delay_ms gauge",
        f"proxydog_pool_avg_delay_ms {st['avg_delay']}",
        "# HELP proxydog_proxy_running 代理端口是否在监听",
        "# TYPE proxydog_proxy_running gauge",
        f"proxydog_proxy_running {1 if snap['running'] else 0}",
        "# HELP proxydog_uptime_seconds 代理运行时长",
        "# TYPE proxydog_uptime_seconds counter",
        f"proxydog_uptime_seconds {snap['uptime']}",
        "# HELP proxydog_connections_total 累计接入连接数",
        "# TYPE proxydog_connections_total counter",
        f"proxydog_connections_total {snap['stats']['connections']}",
        "# HELP proxydog_requests_ok 成功请求数",
        "# TYPE proxydog_requests_ok counter",
        f"proxydog_requests_ok {snap['stats']['success']}",
        "# HELP proxydog_requests_fail 失败请求数",
        "# TYPE proxydog_requests_fail counter",
        f"proxydog_requests_fail {snap['stats']['fail']}",
        "# HELP proxydog_bytes_in_total 下行字节",
        "# TYPE proxydog_bytes_in_total counter",
        f"proxydog_bytes_in_total {snap['stats']['bytes_in']}",
        "# HELP proxydog_bytes_out_total 上行字节",
        "# TYPE proxydog_bytes_out_total counter",
        f"proxydog_bytes_out_total {snap['stats']['bytes_out']}",
        "# HELP proxydog_active_connections 当前并发连接",
        "# TYPE proxydog_active_connections gauge",
        f"proxydog_active_connections {snap['conn_open']}",
        "# HELP proxydog_sticky_sessions 粘性会话数",
        "# TYPE proxydog_sticky_sessions gauge",
        f"proxydog_sticky_sessions {snap['rotate']['sessions']}",
        "# HELP proxydog_success_rate_15m 近 15 分钟成功率",
        "# TYPE proxydog_success_rate_15m gauge",
        f"proxydog_success_rate_15m {logs['rate']}",
        "# HELP proxydog_mode 当前轮换模式（值为 1 表示启用）",
        "# TYPE proxydog_mode gauge",
    ]
    for key in MODE_KEYS:
        lines.append(f'proxydog_mode{{mode="{key}"}} {1 if snap["mode"] == key else 0}')
    lines.append("# HELP proxydog_valid_by_protocol 按协议的有效出口数")
    lines.append("# TYPE proxydog_valid_by_protocol gauge")
    for proto, count in st["protocols"].items():
        lines.append(f'proxydog_valid_by_protocol{{protocol="{proto}"}} {count}')
    return Response("\n".join(lines) + "\n", mimetype="text/plain; version=0.0.4")


# ---------------- 维护 ----------------
BACKUP_DIR = os.path.join(DATA_DIR, "backups")


@app.route("/api/maintenance")
def api_maintenance():
    backups = []
    if os.path.isdir(BACKUP_DIR):
        for name in sorted(os.listdir(BACKUP_DIR), reverse=True)[:20]:
            if name.endswith(".db"):
                p = os.path.join(BACKUP_DIR, name)
                backups.append({"name": name, "size": os.path.getsize(p),
                                "time": time.strftime("%Y-%m-%d %H:%M",
                                                      time.localtime(os.path.getmtime(p)))})
    return ok(sizes=store.file_sizes(), counts=store.counts(),
              backups=backups, sched=SCHED,
              paths={"db": os.path.join(DATA_DIR, "proxydog.db"),
                     "logs": LOG_DIR, "backups": BACKUP_DIR})


@app.route("/api/maintenance/backup", methods=["POST"])
def api_backup():
    try:
        path = store.backup(BACKUP_DIR)
    except Exception as exc:
        return err(f"备份失败: {exc}")
    SCHED["backup"].update(last=time.time(), ok=True,
                           note=os.path.basename(path))
    return ok(file=os.path.basename(path), size=os.path.getsize(path))


@app.route("/api/maintenance/backup/<name>")
def api_backup_download(name):
    safe = os.path.basename(name)
    if not safe.endswith(".db"):
        return err("文件名不合法")
    return send_from_directory(BACKUP_DIR, safe, as_attachment=True)


@app.route("/api/maintenance/restore", methods=["POST"])
def api_backup_restore():
    """从备份恢复数据库（在线恢复，不用重启进程）。"""
    if not require_user():
        return err("需要登录用户操作", 403)
    name = os.path.basename((request.get_json(force=True) or {}).get("name") or "")
    if not name.endswith(".db"):
        return err("文件名不合法")
    path = os.path.join(BACKUP_DIR, name)
    if not os.path.exists(path):
        return err("备份文件不存在")
    try:
        # 恢复前先做一次当前库的备份，恢复错了还能退回来
        cur = store.backup(BACKUP_DIR)
        store.restore(path)
    except Exception as exc:
        return err(f"恢复失败: {exc}")
    server.reset_rotation("数据库已从备份恢复")
    log.warning("数据库已从备份恢复: %s（恢复前自动备份 %s）",
                name, os.path.basename(cur))
    return ok(restored=name, safety=os.path.basename(cur))


# ---------------- 出口域名解析一致性检测 ----------------
async def _dns_resolve_all(hosts):
    import aiohttp
    loop = asyncio.get_event_loop()
    out = {}
    for h in hosts:
        try:
            out[h] = await loop.run_in_executor(
                None, lambda hh=h: socket.gethostbyname(hh))
        except OSError:
            out[h] = ""
    return out


@app.route("/api/proxies/dnscheck", methods=["POST"])
def api_dns_check():
    """域名出口解析一致性：域名解析出来的 IP 和上次记录不一样就标出来。"""
    hosts_rows = store.domain_hosts(1000)
    if not hosts_rows:
        return ok(checked=0, changed=[])
    try:
        resolved = run_coro(_dns_resolve_all(sorted({r["host"] for r in hosts_rows})), 60)
    except Exception as exc:
        return err(f"解析失败: {exc}")
    changed, same = [], 0
    pairs = []
    for r in hosts_rows:
        ip = resolved.get(r["host"]) or ""
        pairs.append((r["id"], ip))
        old = (store.get(r["id"]) or {}).get("resolved_ip") or ""
        if ip and old and ip != old:
            changed.append({"id": r["id"], "host": r["host"], "old": old, "new": ip})
        elif ip:
            same += 1
    store.set_resolved(pairs)
    return ok(checked=len(hosts_rows), changed=changed, same=same)


@app.route("/api/proxies/dnsfix", methods=["POST"])
def api_dns_fix():
    """一键纠正：把域名出口的 host 换成解析出来的 IP（绕过 DNS 污染/漂移）。"""
    if not require_user():
        return err("需要登录用户操作", 403)
    ids = [int(i) for i in ((request.get_json(force=True) or {}).get("ids") or [])]
    fixed = 0
    for pid in ids:
        row = store.get(pid)
        if not row or row["host"].isdigit():
            continue
        try:
            ip = socket.gethostbyname(row["host"])
        except OSError:
            continue
        if ip and ip != row["host"] and not store.find(ip, row["port"], row["protocol"]):
            if store.update(pid, {"host": ip}):
                fixed += 1
    return ok(fixed=fixed)


# ---------------- 粘贴内容解析预览（本地代理「检测代理」用） ----------------
@app.route("/api/parse", methods=["POST"])
def api_parse():
    """只解析不入库：返回各协议条数与样例，给「检测代理」按钮用。"""
    data = request.get_json(force=True) or {}
    text = data.get("text") or ""
    if not text.strip():
        return err("没有内容可解析")
    report = {}
    rows = sources.parse_blob(text, source=data.get("source") or "manual",
                              report=report)
    protos = {}
    for r in rows:
        protos[r.get("protocol") or "http"] = protos.get(r.get("protocol") or "http", 0) + 1
    sample = [sources.proxy_url(r) for r in rows[:5]]
    return ok(parsed=len(rows), protocols=protos, sample=sample,
              skipped=report.get("skipped", 0))


@app.route("/api/maintenance/vacuum", methods=["POST"])
def api_vacuum():
    if not require_user():
        return err("需要登录用户操作", 403)
    store.vacuum()
    return ok(sizes=store.file_sizes(), message="已 VACUUM 并截断 WAL")


@app.route("/api/maintenance/prune", methods=["POST"])
def api_prune():
    days = int((request.get_json(force=True) or {}).get("days")
               or store.settings().get("access_log_days") or 7)
    deleted = store.prune_logs(days) + store.cleanup(
        int(store.settings().get("max_delay_ms") or 0))
    SCHED["prune"].update(last=time.time(), ok=True, note=f"清理 {deleted} 条")
    return ok(deleted=deleted)


@app.route("/api/config/export")
def api_config_export():
    payload = {"version": 1, "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
               "settings": public_settings(), "sources": sources.source_catalog()}
    return Response(json.dumps(payload, ensure_ascii=False, indent=2),
                    mimetype="application/json",
                    headers={"Content-Disposition": "attachment; filename=proxydog-config.json"})


@app.route("/api/config/import", methods=["POST"])
def api_config_import():
    if not require_user():
        return err("需要登录用户操作", 403)
    data = (request.get_json(force=True) or {}).get("settings") or {}
    # 白名单在 Store.save_settings 里按 DEFAULTS 过滤；密码与旧 token 不跟着导入
    payload = {k: v for k, v in data.items() if k not in ("auth_password", "token")}
    store.save_settings(payload)
    return ok(applied=len(payload))


@app.route("/api/health")
def api_health():
    """无需认证，给监控/守护脚本探活用。"""
    stats = store.stats()
    body = {
        "status": "ok" if server.running and stats["valid"] > 0 else "degraded",
        "proxy_running": server.running,
        "pool_valid": stats["valid"],
        "uptime": int(time.time() - server.started_at) if server.started_at else 0,
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    return jsonify(body), (200 if body["status"] == "ok" else 503)



# ---------------- 自动扩容 ----------------
SCALE = {"last": 0.0, "count": 0, "last_note": ""}


def _auto_scale_once(s=None, force=False, reason=""):
    """池子不够就自己补货：有效出口低于 scale_min 时抓一批回来。

    返回本次抓取的数量上限；0 表示没启动（还没到点 / 已经够用 / 正在抓）。
    """
    s = s or store.settings()
    now = time.time()
    if busy["fetching"]:
        return 0
    stats = store.stats()
    valid = int(stats.get("valid") or 0)
    if not force:
        if not s.get("auto_scale"):
            return 0
        need = int(s.get("scale_min") or 0)
        if need <= 0 or valid >= need:
            return 0
        # 池子彻底空了属于「不可用」级别：冷却压到 20 秒
        cool = 20 if valid == 0 else int(s.get("scale_cooldown") or 300)
        if now - SCALE["last"] < cool:
            return 0
        # 上限按「有效出口数」算，不按池内总数：总数里全是死节点时早就到顶了，
        # 按总数卡的话就再也补不进来（这正是池子变不可用的经典死法）
        cap = int(s.get("scale_max_pool") or 0)
        if cap and valid >= cap:
            return 0
    max_total = int(s.get("scale_batch") or 300)
    SCALE["last"] = now
    label = "自动扩容" if not force else "手动补货"
    tid = tasks.start("scale", f"{label} · 目标 {max_total} 条")
    busy["fetching"] = True
    busy["progress"] = f"{label}抓取中"

    def work():
        try:
            rows, rep = run_coro(sources.fetch_all(
                max_total, bool(s.get("fetch_geonode")), _custom_sources(),
                scope=s.get("fetch_scope") or "all",
                countries=_scope_countries(s)), 600)
            _merge_custom_report(rep)
            tasks.update(tid, total=max(1, len(rows)))
            _n, ids = store.add_many(rows)
            tasks.update(tid, done=max(1, len(rows)))
            if ids:
                _geo_fill()
                # 池子本来是空的：这一批必须当场验证出结果，否则新节点全是
                # is_valid=0，代理照样不可用，还得再等下一轮定时验证
                if s.get("validate_on_add") or valid == 0:
                    validate_rows(_rows_by_ids(ids))
                left = store.usable_count()
                SCALE["last_note"] = (f"{label}：候选 {len(rows)}，新增 {len(ids)}"
                                      f"，补后可用 {left}")
                if left == 0:
                    log.warning("%s：抓来 %s 条候选但没有一条验证通过，稍后重试",
                                label, len(ids))
            else:
                SCALE["last_note"] = f"{label}：源没返回可用候选"
            SCALE["last"] = time.time()
            SCALE["count"] += 1
            tasks.finish(tid, True, note=SCALE["last_note"])
            SCHED["fetch"].update(last=time.time(), ok=True,
                                  note=f"{label} +{len(ids)}")
            log.info("%s：候选 %s，新增 %s（%s）", label, len(rows), len(ids), reason or "-")
        except Exception as exc:
            tasks.finish(tid, False, error=exc)
            log.warning("%s失败：%s", label, exc)
        finally:
            busy["fetching"] = False
            busy["progress"] = ""

    threading.Thread(target=work, daemon=True).start()
    return max_total


# ---------------- 版本 / 关于 ----------------
def about_snapshot():
    has = bool(UPDATE["latest"]) and _version_gt(UPDATE["latest"], VERSION)
    return {"name": ABOUT["name"], "version": VERSION,
            "author": ABOUT["author"], "repo": ABOUT["repo"],
            "latest": UPDATE["latest"], "update": has, "url": UPDATE["url"],
            "notes": UPDATE["notes"], "checked": UPDATE["checked"],
            "err": UPDATE["err"]}


@app.route("/api/version")
def api_version():
    """当前版本 + GitHub 最新 release；?force=1 立即重查。"""
    if request.args.get("force") == "1":
        _check_update(force=True)
    else:
        _check_update()
    return ok(about=about_snapshot())


# ---------------- 任务中心 ----------------
@app.route("/api/tasks")
def api_tasks():
    try:
        limit = min(200, max(1, int(request.args.get("limit") or 50)))
    except (TypeError, ValueError):
        limit = 50
    kind = request.args.get("kind") or None
    return ok(tasks=tasks.listing(limit, kind=kind), summary=tasks.summary())


@app.route("/api/tasks/<tid>")
def api_task_one(tid):
    t = tasks.get(tid)
    return ok(task=t) if t else err("任务不存在", 404)


@app.route("/api/tasks/<tid>/cancel", methods=["POST"])
def api_task_cancel(tid):
    return ok(cancelled=tasks.cancel(tid))


# ---------------- 抓取插件目录 ----------------
@app.route("/api/plugins")
def api_plugins():
    return ok(plugins=plugins.list_plugins(), status=plugins.status())


@app.route("/api/plugins/reload", methods=["POST"])
def api_plugins_reload():
    ps = plugins.scan(force=True)
    log.info("插件目录已重载：%s 个插件", len(ps))
    return ok(count=len(ps), status=plugins.status())


@app.route("/api/plugins/<key>", methods=["POST"])
def api_plugin_op(key):
    data = request.get_json(silent=True) or {}
    act = str(data.get("action") or "")
    if act == "toggle":
        if not plugins.set_enabled(key, bool(data.get("enabled", True))):
            return err("插件不存在", 404)
        return ok()
    if act == "test":
        return ok(result=plugins.test(key))
    return err("未知操作")


# ---------------- 出口带宽测速 ----------------
def _exit_url(row):
    """把出口拼成 aiohttp_socks 能认的代理 URL（https 出口按 http 代理处理）。"""
    proto = str(row.get("protocol") or "http").lower()
    if proto not in ("http", "socks5", "socks4"):
        proto = "http"
    auth = ""
    if row.get("username"):
        auth = f"{quote(str(row['username']))}:{quote(str(row.get('password') or ''))}@"
    return f"{proto}://{auth}{row['host']}:{int(row['port'])}"


async def _speed_one(row, url, timeout=20):
    import aiohttp
    from aiohttp_socks import ProxyConnector

    t0 = time.perf_counter()
    try:
        connector = ProxyConnector.from_url(_exit_url(row))
        async with aiohttp.ClientSession(connector=connector) as ses:
            async with ses.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                if r.status >= 400:
                    return 0.0, f"HTTP {r.status}"
                n = 0
                while True:
                    chunk = await r.content.read(65536)
                    if not chunk:
                        break
                    n += len(chunk)
        sec = max(0.001, time.perf_counter() - t0)
        if n <= 0:
            return 0.0, "没读到数据"
        return round(n / 1024.0 / sec, 1), ""
    except Exception as exc:
        return 0.0, f"{exc.__class__.__name__}: {str(exc)[:80]}"


async def _speed_many(rows, url, timeout, tid=None):
    sem = asyncio.Semaphore(4)

    async def one(r):
        if tid and tasks.cancelled(tid):
            return None
        async with sem:
            kbps, e = await _speed_one(r, url, timeout)
        if kbps:
            store.set_speed(r["id"], kbps)
        if tid:
            tasks.bump(tid)
            if e:
                tasks.log(tid, f"{r['host']}:{r['port']} 失败：{e}")
        return (r["id"], kbps, e)

    return [x for x in await asyncio.gather(*(one(r) for r in rows)) if x]


@app.route("/api/proxies/<int:pid>/speed", methods=["POST"])
def api_speed_one(pid):
    row = store.get(pid)
    if not row:
        return err("代理不存在", 404)
    s = store.settings()
    url = str(s.get("speed_url") or "").strip()
    if not url:
        return err("还没配置测速地址（设置 → 出口测速）")
    kbps, e = run_coro(_speed_one(row, url, int(s.get("speed_timeout") or 20)), 90)
    if e:
        return err(e)
    store.set_speed(pid, kbps)
    return ok(speed=kbps)


@app.route("/api/proxies/speed", methods=["POST"])
def api_speed_many():
    data = request.get_json(silent=True) or {}
    s = store.settings()
    url = str(s.get("speed_url") or "").strip()
    if not url:
        return err("还没配置测速地址（设置 → 出口测速）")
    try:
        limit = max(1, min(200, int(data.get("limit") or 20)))
    except (TypeError, ValueError):
        limit = 20
    ids = []
    for i in (data.get("ids") or []):
        try:
            ids.append(int(i))
        except (TypeError, ValueError):
            pass
    rows = _rows_by_ids(ids)[:limit] if ids else store.candidates(0, limit=limit)
    if not rows:
        return err("没有可测速的出口")
    tid = tasks.start("speed", f"出口测速 · {len(rows)} 条", total=len(rows))
    timeout = int(s.get("speed_timeout") or 20)

    def work():
        try:
            res = run_coro(_speed_many(rows, url, timeout, tid), 900)
            okn = sum(1 for _p, k, _e in res if k > 0)
            tasks.finish(tid, True, note=f"{okn}/{len(res)} 条测出速率")
        except Exception as exc:
            tasks.finish(tid, False, error=exc)

    threading.Thread(target=work, daemon=True).start()
    return ok(task=tid)


# ---------------- 出口 IP 类型（机房 / 住宅）----------------
async def _classify_rows(rows, online=True, tid=None):
    pairs = []
    for r in rows:
        if tid and tasks.cancelled(tid):
            break
        ip = str(r.get("real_ip") or "").strip()
        if not ip and ipclass_like(r.get("host")):
            ip = str(r.get("host"))
        if ip:
            info = await asyncio.to_thread(ipclass.lookup, ip, online)
            pairs.append((r["id"], info.get("kind") or "unk",
                          info.get("org") or info.get("isp") or "",
                          info.get("asn") or info.get("as") or ""))
            if tid:
                tasks.log(tid, f"{ip} → {info.get('kind')} {info.get('reason') or ''}")
        if tid:
            tasks.bump(tid)
    if pairs:
        store.set_ip_classes(pairs)
    return len(pairs)


def ipclass_like(host):
    try:
        import ipaddress
        ipaddress.ip_address(str(host or "").strip("[]"))
        return True
    except ValueError:
        return False


@app.route("/api/proxies/classify", methods=["POST"])
def api_classify():
    data = request.get_json(silent=True) or {}
    s = store.settings()
    online = bool(s.get("ipclass_online"))
    ids = []
    for i in (data.get("ids") or []):
        try:
            ids.append(int(i))
        except (TypeError, ValueError):
            pass
    if ids:
        rows = _rows_by_ids(ids)
    else:
        rows = [r for r in (dict(x) for x in store.needs_ip_class(300))
                if r.get("real_ip") or ipclass_like(r.get("host"))]
    if not rows:
        return err("没有需要判定的出口")
    tid = tasks.start("classify", f"IP 类型判定 · {len(rows)} 条", total=len(rows))

    def work():
        try:
            n = run_coro(_classify_rows(rows, online, tid), 900)
            tasks.finish(tid, True, note=f"已判定 {n} 条")
        except Exception as exc:
            tasks.finish(tid, False, error=exc)

    threading.Thread(target=work, daemon=True).start()
    return ok(task=tid)


# ---------------- 健康分 ----------------
@app.route("/api/health/scores")
def api_health_scores():
    s = store.settings()
    return ok(scores=store.health_scores(int(s.get("health_window") or 200)))


@app.route("/api/health/refresh", methods=["POST"])
def api_health_refresh():
    s = store.settings()
    scores = store.health_scores(int(s.get("health_window") or 200), apply=True)
    avg = round(sum(scores.values()) / len(scores), 1) if scores else 0
    return ok(count=len(scores), avg=avg)


# ---------------- 手动扩容（补货）----------------
@app.route("/api/pool/scale", methods=["POST"])
def api_pool_scale():
    if busy["fetching"]:
        return err("已有抓取任务在跑")
    s = store.settings()
    n = _auto_scale_once(s, force=True)
    return ok(started=bool(n), max_total=n)


# ---------------- 后台任务 ----------------
async def _log_flusher():
    """把 netproxy 攒下的审计日志批量落库，避免每条请求都同步写盘。

    照 ProxyCat：批量写库 + 条数上限（access_log_max，超出删最老），
    同时按批次聚合域名统计（保留 30 天，每天清一次）。
    """
    n = 0
    while True:
        await asyncio.sleep(5)
        batch = []
        while server.log_queue and len(batch) < 500:
            try:
                batch.append(server.log_queue.popleft())
            except IndexError:
                break
        if batch:
            try:
                store.add_logs(batch)
                store.bump_domains(batch)
            except Exception as exc:
                log.warning("写访问日志失败: %s", exc)
        # 入站账号的使用次数/最近使用时间：攒 5 秒批量落库
        try:
            hits = server.flush_user_hits()
            if hits:
                store.touch_proxy_users(hits)
        except Exception as exc:
            log.warning("写账号使用统计失败: %s", exc)
        # 条数上限：每 20 批（约 100 秒）检查一次，别每次都 COUNT
        n += 1
        if batch and n % 20 == 0:
            try:
                store.trim_logs(int(store.settings().get("access_log_max") or 0))
            except Exception:
                pass


async def _background():
    last_revalidate = 0.0
    last_fetch = 0.0
    last_checkpoint = time.time()
    last_prune = time.time()
    last_backup = time.time()
    last_geo = 0.0
    last_sweep = 0.0
    last_scenario = 0.0
    scenario_idx = 0          # 多个验证网站轮流用（照无影支持配置多个 URL）
    last_src_api = 0.0        # 代理来源：API 接口上次刷新（照 ProxyCat）
    last_src_remote = 0.0     # 代理来源：远程代理池上次刷新
    last_plugin_scan = 0.0    # 插件级抓取频率：逐源调度扫描
    last_domain_prune = time.time()
    last_health = 0.0         # 健康分重算
    last_ipclass = 0.0        # 出口 IP 类型判定
    last_scale = 0.0          # 自动扩容检查
    await asyncio.sleep(5)
    while True:
        try:
            now = time.time()
            s = store.settings()
            # 本机公网出口 IP（匿名判断基准）：手动填了就不探测；没填每 30 分钟试一次
            if not str(s.get("public_ip") or "").strip() and \
                    now - PUBIP.get("tried", 0) > 1800:
                PUBIP["tried"] = now
                v4, v6, geo, geo6 = await _detect_public_ip()
                if v4:
                    PUBIP["ip"] = v4
                    PUBIP["ts"] = now
                if v6:
                    PUBIP["ip6"] = v6
                    PUBIP["ts"] = now
                if geo:
                    PUBIP["geo"] = geo
                if geo6:
                    PUBIP["geo6"] = geo6
                if v4 or v6:
                    log.info("已获知本机公网出口 IP: v4=%s（%s） v6=%s（%s）",
                             v4 or "-", geo or "-", v6 or "-", geo6 or "-")
            # 归属地：本地离线库，60 秒扫一次，补齐新入库/漏掉的，永不联网
            if s.get("geo_auto") and geoip.ready() and now - last_geo > 60:
                last_geo = now
                filled = _geo_fill(5000)
                if filled:
                    log.info("归属地自动补全: %s 条", filled)
            # 出口健康分：每分钟按最近访问记录重算一次并落库（轮换权重直接用它）
            if s.get("health_on") and now - last_health > 60:
                last_health = now
                try:
                    scores = store.health_scores(int(s.get("health_window") or 200),
                                                 apply=True)
                    if scores:
                        avg = sum(scores.values()) / len(scores)
                        SCHED.setdefault("health", {"label": "出口健康分", "last": 0,
                                                    "next": 0, "ok": None, "note": ""})
                        SCHED["health"].update(last=now, next=now + 60, ok=True,
                                               note=f"{len(scores)} 条，均分 {avg:.0f}")
                except Exception as exc:
                    log.debug("健康分计算失败: %s", exc)
            # 出口 IP 类型（机房 / 住宅）：离线库为主，在线 ASN 补充，分批慢慢标
            if now - last_ipclass > 120:
                last_ipclass = now
                try:
                    pend = [r for r in (dict(x) for x in store.needs_ip_class(80))
                            if r.get("real_ip") or ipclass_like(r.get("host"))]
                    if pend:
                        n = await _classify_rows(
                            pend, bool(s.get("ipclass_online")))
                        if n:
                            log.info("IP 类型判定: %s 条", n)
                except Exception as exc:
                    log.debug("IP 类型判定失败: %s", exc)
            # 自动扩容：有效出口不够就补货（自带冷却，不会连环抓）
            if now - last_scale > 60:
                last_scale = now
                try:
                    _auto_scale_once(s, reason="池内有效出口不足")
                except Exception as exc:
                    log.debug("自动扩容检查失败: %s", exc)
            # 版本检查：每 6 小时问一次 GitHub，有新版只提示不强更
            if now - UPDATE["checked"] > 6 * 3600:
                try:
                    await asyncio.to_thread(_check_update)
                except Exception as exc:
                    log.debug("版本检查失败: %s", exc)
            if now - last_checkpoint > 3600:
                store.checkpoint()
                last_checkpoint = now
            if s.get("auto_fetch") and now - last_fetch > int(s["fetch_interval_minutes"]) * 60:
                last_fetch = now
                SCHED["fetch"].update(last=now,
                                      next=now + int(s["fetch_interval_minutes"]) * 60)
                rows, _rep = await sources.fetch_all(int(s["max_fetch_total"]),
                                                     bool(s.get("fetch_geonode")),
                                                     _custom_sources(),
                                                     scope=s.get("fetch_scope") or "all",
                                                     countries=_scope_countries(s))
                _merge_custom_report(_rep)
                _n, ids = store.add_many(rows)
                if ids:
                    _geo_fill()
                SCHED["fetch"].update(ok=True, note=f"候选 {len(rows)}，新增 {len(ids)}")
                log.info("自动抓取: 候选 %s, 新增 %s", len(rows), len(ids))
            # 代理来源（照 ProxyCat 三种来源）：api / remote 定时拉取，入库打来源标记，
            # 转发侧按来源过滤候选，切换来源即时生效
            src = s.get("upstream_source") or "pool"
            if src in ("api", "remote"):
                is_api = src == "api"
                url = str(s.get("source_api_url" if is_api else "source_remote_url") or "").strip()
                iv = int(s.get("source_api_interval" if is_api else "source_remote_interval") or 5) * 60
                last = last_src_api if is_api else last_src_remote
                if url and now - last > iv:
                    if is_api:
                        last_src_api = now
                    else:
                        last_src_remote = now
                    try:
                        text = await _download(url)
                        report = {}
                        rows = sources.parse_blob(text, source=src, report=report)
                        if is_api:
                            limit = max(1, int(s.get("source_api_limit") or 200))
                            rows = rows[:limit]
                        _n, ids = store.add_many(rows)
                        if ids:
                            _geo_fill()
                            if s.get("validate_on_add"):
                                results = await sources.validate_many(
                                    [(r["id"], r) for r in _rows_by_ids(ids)],
                                    s["test_url"], int(s["validate_timeout"]),
                                    int(s["validate_concurrency"]), **_check_kwargs(s))
                                for pid, good, delay, anon, hok, rip in results:
                                    store.set_result(
                                        pid, good, delay, source="check", anon=anon,
                                        https_ok=hok, real_ip=rip,
                                        max_delay_ms=int(s.get("max_delay_ms") or 0))
                        log.info("来源刷新(%s): 解析 %s，新增 %s", src, len(rows), len(ids))
                    except Exception as exc:
                        log.warning("来源刷新失败(%s): %s", src, exc)
            # 插件级抓取频率（照 ProxyCat）：每个自定义源可设独立周期（分钟），
            # 0 = 跟随全局；到点就单独跑这个源，入库+验证走同一套流程
            if now - last_plugin_scan > 60:
                last_plugin_scan = now
                for src_row in store.api_sources(enabled_only=True):
                    iv = int(src_row.get("interval") or 0)
                    if iv <= 0:
                        continue
                    pub = _public_api_source(src_row)
                    if not pub["configured"] or busy["fetching"]:
                        continue
                    last_run = src_row.get("last_run") or 0
                    if now - last_run < iv * 60:
                        continue
                    try:
                        rows, rep = await sources.fetch_all(
                            0, False, custom=[pub], skip_builtin=True)
                        _merge_custom_report(rep)
                        _added, ids = store.add_many(rows)
                        if ids:
                            _geo_fill()
                            if s.get("validate_on_add"):
                                res = await sources.validate_many(
                                    [(r["id"], r) for r in _rows_by_ids(ids)],
                                    s["test_url"], int(s["validate_timeout"]),
                                    int(s["validate_concurrency"]), **_check_kwargs(s))
                                for pid, good, delay, anon, hok, rip in res:
                                    store.set_result(pid, good, delay, anon=anon,
                                                     https_ok=hok, real_ip=rip,
                                                     max_delay_ms=int(s.get("max_delay_ms") or 0))
                        plog.info("插件抓取 %s: 候选 %s，新增 %s",
                                  pub["name"], len(rows), len(ids))
                    except Exception as exc:
                        store.touch_api_source(src_row["id"], error=str(exc))
                        plog.warning("插件抓取失败 %s: %s", pub.get("name"), exc)
            rv_iv = max(120, int(s.get("revalidate_interval") or 600))
            if now - last_revalidate > rv_iv:
                last_revalidate = now
                SCHED["validate"].update(last=now, next=now + rv_iv)
                # 不带延迟过滤：超限的也要重测一次，否则它会永远停在「有效」却选不到
                rows = store.candidates(0, limit=600)
                if rows:
                    _ph, _au, _kw = _validate_opts(s)
                    results = await sources.validate_many(
                        [(r["id"], r) for r in rows], s["test_url"],
                        int(s["validate_timeout"]), int(s["validate_concurrency"]),
                        _au, _ph, _kw, **_check_kwargs(s))
                    for pid, good, delay, anon, hok, rip in results:
                        store.set_result(pid, good, delay, anon=anon, https_ok=hok, real_ip=rip,
                                         max_delay_ms=int(s.get("max_delay_ms") or 0))
                    if s.get("auto_drop_slow"):
                        store.purge_slow(int(s.get("max_delay_ms") or 0), only_marked=True)
                    SCHED["validate"].update(ok=True, note=f"验证 {len(results)} 条")
                    log.info("自动重验证: %s 条", len(results))
                # 失效队列也要轮着验一遍：否则一旦被判死就再也没机会翻身，
                # 池子只能靠不停抓新的来续命（免费源经常抓不到）
                dead = store.invalid_rows(limit=150)
                if dead:
                    _ph, _au, _kw = _validate_opts(s)
                    res = await sources.validate_many(
                        [(r["id"], r) for r in dead], s["test_url"],
                        int(s["validate_timeout"]), int(s["validate_concurrency"]),
                        _au, _ph, _kw, **_check_kwargs(s))
                    revived = 0
                    for pid, good, delay, anon, hok, rip in res:
                        store.set_result(pid, good, delay, anon=anon, https_ok=hok,
                                         real_ip=rip,
                                         max_delay_ms=int(s.get("max_delay_ms") or 0))
                        revived += 1 if good else 0
                    if revived:
                        log.info("失效队列复验: %s 条里救回 %s 条", len(res), revived)
            # 场景模式（学无影）：每 2 分钟验证一遍池子，支持配置多个验证网站轮流用；
            # 验证要求 HTTP 响应包含特征字符串（scenario_keyword），失败的出口按
            # 「删除无效代理」开关决定是累计三次后剔除还是只记失败
            if s.get("mode") == "scenario" and now - last_scenario > 120:
                last_scenario = now
                SCHED["scenario"].update(last=now, next=now + 120)
                sites = [u for u in re.split(r"[,;，；\s]+",
                                             str(s.get("scenario_site") or ""))
                         if u.strip()]
                url = sites[scenario_idx % len(sites)] if sites else s["test_url"]
                scenario_idx += 1
                _ph, _au, _kw = _validate_opts(s)
                # 场景自己的特征串优先，其次才是全局的「包含字符串」
                kw = str(s.get("scenario_keyword") or "").strip() or _kw
                # 删除无效代理（照无影）：启用后累计 3 次无效才判死剔除；
                # 关闭则只记失败统计，不删除
                invalid_after = 3 if s.get("scenario_drop_invalid") else 10**9
                rows = store.candidates(0, limit=300)
                if rows:
                    results = await sources.validate_many(
                        [(r["id"], r) for r in rows], url,
                        int(s["validate_timeout"]), int(s["validate_concurrency"]),
                        _au, _ph, kw, **_check_kwargs(s))
                    bad = sum(1 for _, good, *_ in results if not good)
                    for pid, good, delay, _anon, _hok, _rip in results:
                        store.set_result(pid, good, delay, source="check",
                                         invalid_after=invalid_after,
                                         max_delay_ms=int(s.get("max_delay_ms") or 0))
                    SCHED["scenario"].update(
                        ok=True, note=(f"用 {url[:40]} 验证 {len(results)} 条，"
                                       f"失败 {bad} 条"
                                       + (f"，含字符串「{kw[:16]}」" if kw else "")))
                    log.info("场景验证: %s 条，失败 %s（url=%s kw=%s）",
                             len(results), bad, url, kw or "-")
            # 慢节点不留在池子里：上限调低后旧数据也能在一个周期内自动清掉
            if s.get("auto_drop_slow") and now - last_sweep > 600:
                last_sweep = now
                gone = store.purge_slow(int(s.get("max_delay_ms") or 0), only_marked=True)
                if gone:
                    log.info("清理超延迟出口: %s 条", gone)
            if now - last_prune > 86400:
                last_prune = now
                deleted = store.prune_logs(int(s.get("access_log_days") or 7))
                # 域名统计照 ProxyCat 保留 30 天
                store.prune_domains(30)
                # 顺手清掉判死多次的条目，免费池每天都会进来一批死代理，不清会一直涨
                dead = store.cleanup(0)
                SCHED["prune"].update(last=now, next=now + 86400, ok=True,
                                      note=f"清理 {deleted} 条日志、{dead} 条失效代理")
                store.checkpoint()
            if now - last_backup > max(1, int(s.get("backup_interval_hours") or 24)) * 3600:
                last_backup = now
                try:
                    path = store.backup(BACKUP_DIR)
                    # 备份保留份数：超出删最老
                    keep = max(1, int(s.get("backup_keep") or 7))
                    olds = sorted(os.listdir(BACKUP_DIR))
                    for old in olds[:-keep] if len(olds) > keep else []:
                        try:
                            os.remove(os.path.join(BACKUP_DIR, old))
                        except OSError:
                            pass
                    SCHED["backup"].update(last=now, ok=True,
                                           next=now + max(1, int(s.get("backup_interval_hours") or 24)) * 3600,
                                           note=os.path.basename(path))
                except Exception as exc:
                    SCHED["backup"].update(last=now, next=now + 3600, ok=False,
                                           note=str(exc)[:60])
        except Exception as exc:
            log.warning("后台任务异常: %s", exc)
        await asyncio.sleep(60)


async def _boot():
    s = store.settings()
    await server.start(s["listen_host"], int(s["listen_port"]), _socks_port(s))
    asyncio.create_task(_log_flusher())
    asyncio.create_task(_background())


def _quiet_loop_errors(loop, context):
    """过滤 Windows 事件循环的噪音异常。

    Proactor 在「对端先断开」时一定会走 _call_connection_lost 抛 10054，
    这类客户端提前关闭/探测超时的情况每天都在发生，且已经从业务层处理过，
    打完整 traceback 只会把日志刷花。其余异常照常上报。
    """
    exc = context.get("exception")
    if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return
    if isinstance(exc, OSError) and "_call_connection_lost" in (context.get("message") or ""):
        return
    loop.default_exception_handler(context)


def _loop_thread():
    global loop
    loop = asyncio.new_event_loop()
    loop.set_exception_handler(_quiet_loop_errors)
    asyncio.set_event_loop(loop)
    loop.run_until_complete(_boot())
    loop_ready.set()
    loop.run_forever()


def bootstrap_account():
    """首次启动创建 admin，密码随机；同时写 data/first-login.txt 方便查看。"""
    if store.user_count() > 0:
        return
    pwd = auth.random_password(12)
    pwd_hash, salt = auth.hash_password(pwd)
    store.create_user("admin", pwd_hash, salt)
    note = os.path.join(DATA_DIR, "first-login.txt")
    with open(note, "w", encoding="utf-8") as fh:
        fh.write(f"ProxyDog 初始账号\n用户名: admin\n密码: {pwd}\n"
                 f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                 "登录后请到「维护 → 修改密码」改掉，并删除本文件。\n")
    log.warning("已创建初始账号 admin，密码 %s（同时写入 %s），登录后请立即修改",
                pwd, note)


def reset_password(username="admin"):
    pwd = auth.random_password(12)
    pwd_hash, salt = auth.hash_password(pwd)
    if store.get_user(username):
        store.set_password(username, pwd_hash, salt)
    else:
        store.create_user(username, pwd_hash, salt)
    print(f"账号 {username} 的新密码: {pwd}")
    log.warning("已重置账号 %s 的密码", username)
    return pwd


def main():
    import sys
    if "--reset-password" in sys.argv:
        bootstrap_account()
        reset_password()
        return
    bootstrap_account()
    setup_logging()                      # 日志级别/轮转按设置来
    apply_env_settings()
    # 抓取插件目录：启动即扫描一遍，开着热重载就盯住目录
    _s0 = store.settings()
    plugins.set_global_enabled(bool(_s0.get("plugin_enabled")))
    try:
        _ps = plugins.scan()
        if _ps:
            log.info("插件目录已加载 %s 个：%s", len(_ps),
                     "、".join(p.get("name") or p["key"] for p in _ps))
    except Exception as exc:
        log.warning("插件目录加载失败: %s", exc)
    if _s0.get("plugin_hot_reload"):
        plugins.start_watch()
    try:
        store.migrate_proxy_auth()       # 老的单账号入站认证 → 账号表（多用户）
    except Exception as exc:
        log.warning("入站账号迁移失败: %s", exc)
    # 订阅链接需要 token：老库没配过就生成一个，省得用户手工想
    if not str(store.settings().get("token") or "").strip():
        import secrets
        store.save_settings({"token": secrets.token_urlsafe(12)})
    threading.Thread(target=_loop_thread, daemon=True).start()
    loop_ready.wait(15)
    s = store.settings()
    socks_note = (" | HTTP+SOCKS5 共用端口" if s.get("socks_shared")
                  else f" | SOCKS5 :{s['socks_port']}"
                  if int(s.get("socks_port") or 0)
                  and int(s["socks_port"]) != int(s["listen_port"]) else "")
    log.info("ProxyDog 已启动 | 代理 %s:%s%s | 面板 http://%s:%s",
             s["listen_host"], s["listen_port"], socks_note,
             s["web_host"], s["web_port"])
    from werkzeug.serving import make_server
    try:
        srv = make_server(s["web_host"], int(s["web_port"]), app, threaded=True)
    except OSError as exc:
        log.error("面板端口 %s 无法监听：%s（可能已被占用，请在设置里改端口）",
                  s["web_port"], exc)
        raise SystemExit(1)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log.info("收到 Ctrl+C，正在退出")
    finally:
        try:
            run_coro(server.stop(), 5)
        except Exception:
            pass
        store.close()


if __name__ == "__main__":
    main()
