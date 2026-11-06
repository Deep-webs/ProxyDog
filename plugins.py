"""抓取插件目录：往 plugins/ 里丢一个 .py 就多一个源，改完存盘自动热重载。

为什么要有它：内置源是写死在 sources.py 里的，自定义源只能配 URL / 测绘接口。
想抓某个冷门站点、想走自己的接口、想做点预处理，就得能写代码。

插件契约（最小可用，两个常量二选一）：
    NAME = "我的源"              # 面板上显示的名字，不填用文件名
    URLS = ["https://..."]        # 方式一：静态清单地址（纯文本/base64/Clash 都认）
    def fetch():                 # 方式二：自己返回 ["1.2.3.4:8080", ...]
        return [...]

可选：
    PROTOCOL = "socks5"           # 行内没写 scheme 时的默认协议
    ENABLED  = False              # 临时停用
    def check():                  # 面板上「测试」按钮调用，返回 (ok, 说明)
        return True, "样例说明"

安全：插件跑在本进程内，等同本机代码执行权限。只有你自己往目录里放文件才会加载，
面板不提供上传入口（避免把 Web 面板变成远程代码执行入口）。
"""

import importlib.util
import os
import threading
import time
import traceback

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PLUGIN_DIR = os.path.join(BASE_DIR, "plugins")

_LOCK = threading.Lock()
_PLUGINS = {}        # key=文件名 -> {name, path, mtime, enabled, error, module, at}
_WATCH = {"thread": None, "stop": False, "last_scan": 0.0, "reloads": 0, "errors": 0}
_GLOBAL_ON = True          # 设置页「启用插件目录」的总闸


def set_global_enabled(on):
    global _GLOBAL_ON
    _GLOBAL_ON = bool(on)


def _iter_files():
    try:
        names = sorted(os.listdir(PLUGIN_DIR))
    except OSError:
        return []
    return [n for n in names
            if n.endswith(".py") and not n.startswith("_")]


def _load_one(path):
    """加载单个插件文件，返回 (info, module)。异常不抛出，记在 info['error']。"""
    fn = os.path.basename(path)
    key = fn[:-3]
    info = {"key": key, "file": fn, "path": path, "name": key, "protocol": "",
            "enabled": True, "error": "", "ok": None,
            "urls": 0, "has_fetch": False, "has_urls": False, "at": time.time(),
            "mtime": 0.0, "desc": ""}
    try:
        info["mtime"] = os.path.getmtime(path)
    except OSError:
        pass
    try:
        spec = importlib.util.spec_from_file_location("pd_plugin_" + key, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)        # 执行模块顶层代码
        info["name"] = str(getattr(mod, "NAME", "") or key)
        info["protocol"] = str(getattr(mod, "PROTOCOL", "") or "").lower()
        info["enabled"] = bool(getattr(mod, "ENABLED", True))
        info["desc"] = str(getattr(mod, "DESC", "") or "")
        urls = getattr(mod, "URLS", None) or []
        if isinstance(urls, str):
            urls = [urls]
        info["urls"] = len([u for u in urls if str(u).strip()])
        info["has_urls"] = info["urls"] > 0
        info["has_fetch"] = callable(getattr(mod, "fetch", None))
        if not (info["has_urls"] or info["has_fetch"]):
            info["error"] = "没有 URLS 也没有 fetch()，这个插件不会产出任何代理"
        return info, mod
    except Exception as exc:
        info["error"] = f"{exc.__class__.__name__}: {exc}"
        info["trace"] = traceback.format_exc(limit=3)
        return info, None


def scan(force=False):
    """扫描目录，新增/变更的重新加载；返回已加载插件列表。"""
    global _PLUGINS
    with _LOCK:
        files = _iter_files()
        seen = set()
        for fn in files:
            path = os.path.join(PLUGIN_DIR, fn)
            try:
                mt = os.path.getmtime(path)
            except OSError:
                continue
            old = _PLUGINS.get(fn)
            if old and not force and abs(old.get("mtime", 0) - mt) < 1e-6:
                seen.add(fn)
                continue
            info, mod = _load_one(path)
            if mod is None and old and old.get("module") is not None:
                # 新版本语法错误时保留上一份能跑的，面板上看得到错误
                keep = dict(old)
                keep.update({"error": info["error"], "trace": info.get("trace", ""),
                             "mtime": mt, "at": time.time()})
                _PLUGINS[fn] = keep
                _WATCH["errors"] += 1
            else:
                info["module"] = mod
                _PLUGINS[fn] = info
                _WATCH["reloads"] += 1
            seen.add(fn)
        for fn in list(_PLUGINS):
            if fn not in seen:
                _PLUGINS.pop(fn, None)      # 文件删了，源也跟着下线
        _WATCH["last_scan"] = time.time()
        return list(_PLUGINS.values())


_PUB_KEYS = ("key", "file", "name", "protocol", "enabled", "error", "desc",
             "urls", "has_urls", "has_fetch", "at", "mtime", "ok")


def _public(p):
    """对外只给可序列化的字段：module 是模块对象，trace 太长，都不出面板。"""
    return {k: p.get(k) for k in _PUB_KEYS}


def list_plugins():
    return sorted((_public(p) for p in scan()), key=lambda x: x.get("name") or "")


def get(key):
    scan()
    for fn, p in _PLUGINS.items():
        if fn[:-3] == key or fn == key:
            return p
    return None


def set_enabled(key, enabled):
    p = get(key)
    if not p:
        return False
    p["enabled"] = bool(enabled)
    return True


def _norm_row(item, proto):
    """把插件返回的各种形式统一成 (host, port, protocol) 或交给 parse_line。"""
    if isinstance(item, dict):
        h = str(item.get("host") or "").strip()
        p = item.get("port")
        pr = str(item.get("protocol") or proto or "http").lower()
        if h and p:
            return {"host": h, "port": int(p), "protocol": pr}
        return None
    s = str(item or "").strip()
    if not s:
        return None
    return s


def rows_from_plugin(p):
    """执行插件，拿到原始行（不校验、不去重，交给上层 parse_blob / parse_line）。"""
    mod = p.get("module")
    if not mod or not p.get("enabled", True):
        return []
    out = []
    urls = getattr(mod, "URLS", None) or []
    if isinstance(urls, str):
        urls = [urls]
    for u in urls:
        u = str(u or "").strip()
        if u:
            out.append(("url", u))
    fn = getattr(mod, "fetch", None)
    if callable(fn):
        try:
            items = fn() or []
        except TypeError:
            items = fn(timeout=12) or []
        if isinstance(items, (str, dict)):
            items = [items]
        for it in items:
            row = _norm_row(it, p.get("protocol") or "")
            if row:
                out.append(("row", row) if not isinstance(row, str) else ("line", row))
    return out


async def fetch_plugin_rows(session=None, timeout=20):
    """并发抓插件源（静态 URL 走 aiohttp；fetch() 在线程池里跑，避免阻塞事件循环）。"""
    import asyncio
    import sources as S

    if not _GLOBAL_ON:
        return [], []
    ps = [p for p in scan() if p.get("enabled", True) and not p.get("error")]
    if not ps:
        return [], []

    async def one(p):
        rows, err = [], ""
        try:
            jobs = rows_from_plugin(p)
            for kind, val in jobs:
                if kind == "url":
                    src = {"name": "plugin:" + p["key"], "url": val,
                           "protocol": p.get("protocol") or "http", "cap": 2000}
                    if session is None:
                        import aiohttp
                        async with aiohttp.ClientSession(
                                headers={"User-Agent": "ProxyDog/plugin"}) as ses:
                            items, e = await S.fetch_text(ses, src)
                    else:
                        items, e = await S.fetch_text(session, src)
                    rows.extend(items)
                    err = err or (e or "")
                elif kind == "row":
                    r = dict(val)
                    rows.append({"host": r["host"], "port": int(r["port"]),
                                 "protocol": r.get("protocol") or "http",
                                 "username": "", "password": "",
                                 "source": "plugin:" + p["key"]})
                else:
                    got = S.parse_blob(val, source="plugin:" + p["key"])
                    rows.extend(got)
        except Exception as exc:
            err = f"{exc.__class__.__name__}: {exc}"
        for r in rows:
            r.setdefault("source", "plugin:" + p["key"])
        return rows, {"name": "插件 · " + p["name"], "url": p.get("file", ""),
                      "count": len(rows), "error": err, "plugin": p["key"]}

    res = await asyncio.gather(*(one(p) for p in ps), return_exceptions=True)
    rows, report = [], []
    for r in res:
        if isinstance(r, Exception):
            report.append({"name": "插件", "url": "", "count": 0,
                           "error": f"{r.__class__.__name__}: {r}"})
            continue
        rows.extend(r[0])
        report.append(r[1])
    return rows, report


def test(key):
    """面板「测试」按钮：只跑插件、不写库，返回条数与样例。"""
    p = get(key)
    if not p:
        return {"ok": False, "msg": "插件不存在"}
    if p.get("error"):
        return {"ok": False, "msg": p["error"]}
    mod = p.get("module")
    fn = getattr(mod, "check", None) if mod else None
    if callable(fn):
        try:
            ok, msg = fn()
            return {"ok": bool(ok), "msg": str(msg or ("通过" if ok else "未通过"))}
        except Exception as exc:
            return {"ok": False, "msg": f"{exc.__class__.__name__}: {exc}"}
    try:
        jobs = rows_from_plugin(p)
    except Exception as exc:
        return {"ok": False, "msg": f"{exc.__class__.__name__}: {exc}"}
    return {"ok": True, "msg": f"共 {len(jobs)} 条待处理任务（静态地址 {p.get('urls', 0)} 个）"}


def _watch_loop(interval=2.0):
    last = {}
    while not _WATCH["stop"]:
        time.sleep(interval)
        try:
            for fn in _iter_files():
                path = os.path.join(PLUGIN_DIR, fn)
                try:
                    mt = os.path.getmtime(path)
                except OSError:
                    continue
                if last.get(fn) != mt:
                    last[fn] = mt
                    scan()
        except Exception:
            pass


def start_watch(interval=2.0):
    if _WATCH["thread"] and _WATCH["thread"].is_alive():
        return
    _WATCH["stop"] = False
    t = threading.Thread(target=_watch_loop, args=(interval,), daemon=True,
                         name="plugin-watch")
    _WATCH["thread"] = t
    t.start()


def stop_watch():
    _WATCH["stop"] = True


def status():
    ps = list_plugins()
    return {"dir": PLUGIN_DIR,
            "count": len(ps),
            "enabled": sum(1 for p in ps if p.get("enabled", True)),
            "errors": sum(1 for p in ps if p.get("error")),
            "reloads": _WATCH["reloads"],
            "last_scan": round(_WATCH["last_scan"]),
            "watching": bool(_WATCH["thread"] and _WATCH["thread"].is_alive())}
