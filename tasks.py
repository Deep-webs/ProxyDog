"""任务中心：把抓取、验证、测速、下载、扩容这些后台活都挂到一处。

以前面板只有 busy 一个布尔值和 SCHED 里的几个时间戳，长任务跑起来看不见进度，
失败了也只剩一行日志。这里统一登记：谁在跑、跑到第几、用了多久、报了什么错。

只在内存里存（重启即清空），保留最近 200 条；任务本身跑在线程/协程里，
这里只负责记账，不负责调度。
"""

import threading
import time
import uuid

MAX_TASKS = 200
_LOCK = threading.RLock()
_TASKS = {}          # id -> dict
_ORDER = []          # 按创建顺序，老的在前


def _now():
    return time.time()


def start(kind, name, total=0, note="", parent=""):
    tid = uuid.uuid4().hex[:12]
    t = {"id": tid, "kind": kind, "name": name, "status": "running",
         "done": 0, "total": int(total or 0), "progress": 0,
         "note": note or "", "error": "", "created": _now(), "started": _now(),
         "ended": 0.0, "logs": [], "cancel": False, "parent": parent}
    with _LOCK:
        _TASKS[tid] = t
        _ORDER.append(tid)
        while len(_ORDER) > MAX_TASKS:
            old = _ORDER.pop(0)
            _TASKS.pop(old, None)
    return tid


def update(tid, **kw):
    with _LOCK:
        t = _TASKS.get(tid)
        if not t:
            return
        for k, v in kw.items():
            if k in ("done", "total", "progress", "status", "note", "error", "name"):
                t[k] = v
        total, done = t.get("total") or 0, t.get("done") or 0
        if total > 0 and "progress" not in kw:
            t["progress"] = int(min(99, done * 100.0 / total))


def bump(tid, n=1):
    with _LOCK:
        t = _TASKS.get(tid)
        if not t:
            return
        t["done"] = (t.get("done") or 0) + n
        total = t.get("total") or 0
        if total > 0:
            t["progress"] = int(min(99, t["done"] * 100.0 / total))


def log(tid, text):
    with _LOCK:
        t = _TASKS.get(tid)
        if not t:
            return
        t["logs"].append((round(_now(), 1), str(text)[:300]))
        if len(t["logs"]) > 60:
            del t["logs"][:20]


def finish(tid, ok=True, note="", error=""):
    with _LOCK:
        t = _TASKS.get(tid)
        if not t:
            return
        t["status"] = "done" if ok else "error"
        t["ended"] = _now()
        t["progress"] = 100 if ok else t.get("progress", 0)
        if note:
            t["note"] = note
        if error:
            t["error"] = str(error)[:400]


def cancel(tid):
    with _LOCK:
        t = _TASKS.get(tid)
        if t and t["status"] == "running":
            t["cancel"] = True
            t["note"] = (t.get("note") or "") + " · 正在取消"
    return True


def cancelled(tid):
    with _LOCK:
        t = _TASKS.get(tid)
        return bool(t and t.get("cancel"))


def get(tid):
    with _LOCK:
        t = _TASKS.get(tid)
        return _dump(t) if t else None


def _dump(t):
    d = dict(t)
    d["elapsed"] = round((t.get("ended") or _now()) - (t.get("started") or _now()), 1)
    d["logs"] = [{"ts": ts, "text": tx} for ts, tx in (t.get("logs") or [])]
    return d


def listing(limit=50, kind=None, active_only=False):
    with _LOCK:
        ids = list(reversed(_ORDER))
        out = []
        for i in ids:
            t = _TASKS.get(i)
            if not t:
                continue
            if kind and t["kind"] != kind:
                continue
            if active_only and t["status"] != "running":
                continue
            out.append(_dump(t))
            if len(out) >= limit:
                break
        return out


def summary():
    with _LOCK:
        running = [t for t in _TASKS.values() if t["status"] == "running"]
        done = sum(1 for t in _TASKS.values() if t["status"] == "done")
        err = sum(1 for t in _TASKS.values() if t["status"] == "error")
    return {"running": len(running), "done": done, "error": err,
            "total": len(_TASKS),
            "names": [t["name"] for t in running][:4]}
