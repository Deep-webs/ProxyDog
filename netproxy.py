"""ProxyDog 本地代理服务：同一端口同时接受 HTTP 与 SOCKS5。

设计要点：
- SOCKS5 认证按 RFC 1928 处理：客户端没提供 02 方法时回 `05 FF`，而不是强行回 `05 02`；
- 出站总预算可配（默认 30s），不会因为第一个慢出口把重试时间吃光；
- 入站认证独立于业务，关掉就是真关掉，不会出现“HTTP 能用 SOCKS5 不能用”；
- 轮换模式六种：round_robin / by_count / by_time / sticky / keyword / exclusive。
"""

import asyncio
import base64
import fnmatch
import functools
import hmac
import ipaddress
import logging
import random
import re
import ssl
import struct
import time
from collections import deque

MAX_HEADER = 128 * 1024
DIAL_TIMEOUT = 8.0
log = logging.getLogger("proxydog.proxy")


def _split_list(value):
    """逗号 / 分号 / 空白分隔的名单（域名、IP、关键词都按这个切）。"""
    return [x for x in re.split(r"[,;\s，；]+", str(value or "")) if x]


def _rule_hit(pattern, target):
    """绕过名单单条匹配（照 ProxyCat 支持通配）。

    - `*.baidu.com` / `192.168.1.*`  通配符，fnmatch 匹配 host
    - `baidu.com`                    等于该域或是其子域
    - `.gov.cn`                      任意以 .gov.cn 结尾
    - `192.168.`                     IP 前缀（以点结尾的纯数字串按前缀匹配）
    """
    p = str(pattern or "").strip().lower().rstrip("/")
    t = str(target or "").lower()
    host = t.rsplit(":", 1)[0] if t.count(":") == 1 else t.split(":")[0] or t
    if not p:
        return False
    if "*" in p:
        return fnmatch.fnmatch(host, p) or fnmatch.fnmatch(t, p)
    if p.startswith("."):
        return host.endswith(p)
    if p.endswith(".") and re.match(r"^[\d.]+\.$", p):
        return host.startswith(p)          # IP 前缀：192.168. 命中 192.168.x.x
    if re.match(r"^[\d.]+$", p):           # 纯 IP / 网段数字串：精确或前缀
        return host == p or host.startswith(p + ".")
    return host == p or host.endswith("." + p)


class ExitUnavailable(Exception):
    pass


def _basic(user, pwd):
    return "Basic " + base64.b64encode(f"{user}:{pwd}".encode()).decode()


class ProxyServer:
    def __init__(self, store):
        self.store = store
        self.loop = None
        self.servers = []
        self._idx = 0
        self._cur = None
        self._cur_used = 0
        self._cur_since = 0.0
        self._pool = []
        self._pool_at = 0.0
        self._conn_open = {}                 # 出口 id -> 当前并发连接数
        self._sessions = {}                  # 粘性会话: key -> (exit_id, expire)
        self._mode_note = ""                 # 模式退化/异常的一句话说明，面板直接显示
        self._pick_reason = ""               # 上一次选择原因，便于排查
        self._last_reval = 0.0               # 无限模式全池重验证的节流时间戳
        self._last_pull = 0.0                # 外部来源按需拉取的节流时间戳
        self._recent = {}                    # 出口 id -> 最近结果滑动窗口（失败占比淘汰）
        self._global_sem = None              # 全局并发闸门（照 ProxyCat，超出排队等待）
        self._global_cap = 0
        self._replenish = None               # 池空等待补货：{"until","since"}；None=没在等
        self._last_revive = 0.0              # 池空自愈（复活失效出口）的节流时间戳
        self._last_heal_kick = 0.0           # 池空时催抓取的节流时间戳
        self.pool_empty_hook = None          # 由 app 注入：池空时立刻触发一次补货
        self._creds = {}                     # 入站认证账号表 {用户名: 密码}，3 秒缓存
        self._creds_at = 0.0
        self._user_hits = {}                 # 用户名 -> [次数, 最近使用]，由主线程定时落库
        self.started_at = None
        self.stats = {
            "connections": 0, "success": 0, "fail": 0,
            "bytes_in": 0, "bytes_out": 0,
        }
        self.recent = deque(maxlen=60)
        self.log_queue = deque(maxlen=8000)      # 待落库的审计日志，由主线程定时刷
        self._log_on = True
        self._flags_at = 0.0
        self._ssl = ssl.create_default_context()
        self._ssl.check_hostname = False
        self._ssl.verify_mode = ssl.CERT_NONE

    # ---------------- 生命周期 ----------------
    async def start(self, host, port, socks_port=0):
        """双监听：HTTP 走 port；socks_port 与其不同时，SOCKS5 单独一个端口。

        同端口时保持老的「首字节嗅探」混合模式。
        """
        self.loop = asyncio.get_running_loop()
        self.servers = [await asyncio.start_server(self._handle, host, port, limit=MAX_HEADER)]
        if socks_port and int(socks_port) != int(port):
            self.servers.append(await asyncio.start_server(
                functools.partial(self._handle, forced="socks5"),
                host, int(socks_port), limit=MAX_HEADER))
        self.started_at = time.time()
        log.info("代理监听已启动 %s:%s%s", host, port,
                 "" if not socks_port or int(socks_port) == int(port)
                 else f"（SOCKS5 :{socks_port}）")
        return self.servers[0]

    async def stop(self):
        servers, self.servers = self.servers, []
        for srv in servers:
            srv.close()
        for srv in servers:
            try:
                await srv.wait_closed()
            except Exception:
                pass
        self.started_at = None

    @property
    def running(self):
        return bool(self.servers)

    # ---------------- 出口选择 ----------------
    def _settings(self):
        return self.store.settings()

    # ---------------- 入站认证（账号表，可多用户） ----------------
    def proxy_creds(self):
        """启用中的账号表 {用户名: 密码}；3 秒缓存，面板改完不用重启服务。"""
        now = time.time()
        if now - self._creds_at > 3:
            try:
                self._creds = self.store.proxy_creds()
            except Exception as exc:            # 库忙也不能把代理打挂
                log.warning("读入站账号失败: %s", exc)
                self._creds = self._creds or {}
            self._creds_at = now
        return self._creds

    def invalidate_creds(self):
        """账号增删改后调用，下个连接立即用新表。"""
        self._creds_at = 0.0

    def auth_required(self):
        return bool(self.proxy_creds())

    def check_proxy_user(self, username, password):
        """任一启用账号匹配即放行；用 compare_digest 挡掉时序侧信道。"""
        username = username or ""
        real = self.proxy_creds().get(username)
        if real is None:
            return False
        if not hmac.compare_digest(str(real), str(password or "")):
            return False
        rec = self._user_hits.get(username)
        if rec is None:
            self._user_hits[username] = [1, time.time()]
        else:
            rec[0] += 1
            rec[1] = time.time()
        return True

    def flush_user_hits(self):
        """取走并清空账号使用计数，由主线程批量写库。"""
        if not self._user_hits:
            return {}
        out = {k: (v[0], v[1]) for k, v in self._user_hits.items()}
        self._user_hits = {}
        return out

    def _candidates(self, s=None):
        s = s or self._settings()
        now = time.time()
        if now - self._pool_at > 5 or not self._pool:
            keep = int(s.get("pool_keep") or 0)
            pool = self.store.candidates(
                int(s.get("max_delay_ms") or 0),
                limit=keep if keep > 0 else 500,
                dedupe=bool(s.get("dedupe_exit")))
            # 代理来源（照 ProxyCat）：pool 只用内置池，api / remote 只用来外部拉来的
            src = s.get("upstream_source") or "pool"
            if src in ("api", "remote"):
                pool = [d for d in pool if (d.get("source") or "") == src]
                if not pool:
                    self._kick_source_pull(src, s)
            else:
                pool = [d for d in pool if (d.get("source") or "") not in ("api", "remote")]
            # 健康分下限：明确低于这条线的出口不参与轮换（0=不设限）
            hmin = int(s.get("health_min") or 0)
            if s.get("health_on") and hmin > 0:
                kept = [d for d in pool if float(d.get("health") or 0) >= hmin]
                pool = kept or pool
            self._pool = pool
            self._pool_at = now
        return self._pool

    def _kick_source_pull(self, src, s):
        """外部来源池空时按需拉一次（照 ProxyCat：收到请求才去取代理）。"""
        now = time.time()
        if now - self._last_pull < 60:
            return
        self._last_pull = now
        url = str(s.get("source_api_url" if src == "api" else "source_remote_url") or "").strip()
        if not url:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        limit = max(1, int(s.get("source_api_limit") or 200)) if src == "api" else 0

        async def _job():
            import aiohttp
            import sources
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                        if resp.status != 200:
                            return
                        text = await resp.text(errors="ignore")
                rows = sources.parse_blob(text, source=src)
                if limit:
                    rows = rows[:limit]
                self.store.add_many(rows)
                self._pool_at = 0
            except Exception:
                pass

        loop.create_task(_job())

    def reset_rotation(self, note=""):
        """切换模式时清空轮换状态，否则新模式的“已用次数/已用时长”是上一个模式留下的。"""
        self._cur = None
        self._idx = 0
        self._cur_used = 0
        self._cur_since = 0.0
        self._pool_at = 0
        self._mode_note = note

    def _capacity_ok(self, d, s):
        cap = int(s.get("max_conn_per_exit") or 0)
        if cap <= 0:
            return True
        return self._conn_open.get(d["id"], 0) < cap

    def _fit(self, pool, s):
        """过滤掉并发已满的出口；全满时挑当前并发最小的四分之一，避免一个都不给。"""
        if int(s.get("max_conn_per_exit") or 0) <= 0:
            return pool
        free = [d for d in pool if self._capacity_ok(d, s)]
        if free:
            return free
        ranked = sorted(pool, key=lambda d: self._conn_open.get(d["id"], 0))
        return ranked[:max(1, len(ranked) // 4)]

    def _weight(self, d):
        """出口权重：延迟越低、历史成功率越高，被选中概率越大（0.2 ~ 4.2）。

        地区偏好：命中 preferred_regions 的出口权重再翻 4 倍（geo targeting）。
        """
        delay = float(d.get("delay_ms") or 5000)
        speed = max(0.15, min(1.0, 1500.0 / max(delay, 150.0)))
        ok = d.get("success_count") or 0
        bad = d.get("fail_count") or 0
        rate = (ok / (ok + bad)) if (ok + bad) else 0.6
        w = 0.2 + speed * max(0.15, rate) * 4.0
        # 健康分（0~100）当乘数：90 分 ≈ 1.56，30 分 ≈ 0.72，不搞一刀切
        if self._settings().get("health_on"):
            h = float(d.get("health") or 0)
            if h > 0:
                w *= 0.3 + (h / 100.0) * 1.4
        pref = str(self._settings().get("preferred_regions") or "")
        if pref:
            region = str(d.get("region") or "").upper()
            if any(p.strip().upper() and p.strip().upper() in region
                   for p in pref.split(",")):
                w *= 4.0
        return w

    def _empty_msg(self, s):
        """空池提示要说人话：多数时候不是没代理，而是全被延迟上限或失效挡掉了。"""
        cap = int((s or {}).get("max_delay_ms") or 0)
        if cap:
            return f"池内没有 {cap}ms 以内的可用出口：先抓取一批，或到设置里放宽延迟上限"
        return "池内没有可用出口"

    def _fast_subset(self, pool, s):
        """延迟优先：只在“最快的一批”出口里挑。

        候选池本身按延迟升序；这里取「最快值 + fast_window_ms」且不超过池子前 25%
        的子集，既保证基本只用低延迟节点，又不会把同一条最快出口反复打爆。
        无限模式（无限轮询）时不裁剪：整个有效池从延时最小开始依次轮流。
        """
        if not s.get("prefer_fast") or s.get("infinite_mode") or len(pool) <= 2:
            return pool
        window = max(120, int(s.get("fast_window_ms") or 500))
        ranked = sorted(pool, key=lambda d: float(d.get("delay_ms") or 99999))
        fastest = float(ranked[0].get("delay_ms") or 0)
        cap_n = max(3, int(len(ranked) * 0.25))
        out = [d for d in ranked[:cap_n]
               if float(d.get("delay_ms") or 99999) <= fastest + window]
        return out or ranked[:2]

    def _weighted_pick(self, pool, s):
        if not pool:
            raise ExitUnavailable(self._empty_msg(s))
        if not s.get("weight_health") or len(pool) == 1:
            return random.choice(pool)
        weights = [self._weight(d) for d in pool]
        total = sum(weights)
        r = random.uniform(0, total)
        acc = 0.0
        for d, w in zip(pool, weights):
            acc += w
            if r <= acc:
                return d
        return pool[-1]

    def _use(self, d, reason):
        """占一个并发位并记录选择原因。释放由 _record 统一做。"""
        self._conn_open[d["id"]] = self._conn_open.get(d["id"], 0) + 1
        self._pick_reason = reason
        return d

    def _rotate(self, pool, s=None):
        """换一个出口。加权开启时按健康度加权随机，否则纯轮流。

        用“上一次用的出口”定位下一个，而不是死下标：池子按延迟排序，
        成功一次延迟就变、顺序也变，用下标会出现连着好几次同一个出口。
        """
        s = s or self._settings()
        pool = self._fit(pool, s)
        if not pool:
            raise ExitUnavailable(self._empty_msg(s))
        pick_pool = self._fast_subset(pool, s)   # 延迟优先：只在最快的一批里挑
        if s.get("infinite_mode") and len(pick_pool) > 1:
            # 无限轮询：按延迟从低到高依次轮流，循环往复用遍全池
            i = self._idx % len(pick_pool)
            if self._cur is not None and pick_pool[i]["id"] == self._cur["id"]:
                i = (i + 1) % len(pick_pool)
            d = pick_pool[i]
            self._idx = i + 1
        elif len(pick_pool) == 1:
            d = pick_pool[0]
        else:
            d = self._weighted_pick(pick_pool, s)
            # 避免连续两次撞同一个，池子够大时重抽一次
            if self._cur is not None and d["id"] == self._cur["id"] and len(pick_pool) > 2:
                d = self._weighted_pick(
                    [x for x in pick_pool if x["id"] != self._cur["id"]], s)
        self._cur = d
        self._idx = pool.index(d) if d in pool else self._idx
        self._cur_used = 1              # 选中即算第 1 次，否则 by_count 会多跑一轮
        self._cur_since = time.time()
        reason = "rotate-infinite" if s.get("infinite_mode") else (
            "rotate-fast" if pick_pool is not pool else "rotate")
        return self._use(d, reason)

    def _sticky_key(self, client, target, session):
        if session:
            return "h:" + session[:64]
        host = (target or "").split(":")[0]
        return f"{client or '-'}|{host}"

    def _sweep_sessions(self, now):
        if len(self._sessions) < 4000:
            return
        self._sessions = {k: v for k, v in self._sessions.items() if v[1] > now}

    async def _pick_or_replenish(self, tgt, client="", session=None, exclude=None):
        """选出口；池空且配置了等待秒数时，排队等补货而不是立刻报错（照 ProxyCat）。

        等待期间每秒重试一次，外部来源会主动触发拉取、内置池触发重验证；
        状态写进 self._replenish，面板顶部有补货进度条。
        """
        s = self._settings()
        wait = max(0, int(s.get("wait_pool_seconds") or 0))
        deadline = time.time() + wait
        while True:
            try:
                row = self.pick(tgt, client=client, session=session, exclude=exclude)
                self._replenish = None
                return row
            except ExitUnavailable:
                if exclude or wait <= 0 or time.time() >= deadline:
                    raise
                first = self._replenish is None
                self._replenish = {"until": deadline, "since": time.time(),
                                   "note": "池空等待补货中"}
                if first:
                    log.info("池内无可用出口，开始等待补货（最多 %ss）", wait)
                src = s.get("upstream_source") or "pool"
                if src in ("api", "remote"):
                    self._last_pull = 0          # 解除节流，立刻拉一次
                    self._kick_source_pull(src, s)
                else:
                    self._kick_revalidate()      # 内部自带 60s 节流
                # 池空别干等：立刻催一次抓取（不等后台 60s 巡检、不受扩容冷却限制）
                if self.pool_empty_hook and time.time() - self._last_heal_kick > 15:
                    self._last_heal_kick = time.time()
                    try:
                        started = self.pool_empty_hook()
                        if started:
                            log.info("池空：已立即触发补货抓取")
                    except Exception as exc:
                        log.debug("触发补货失败: %s", exc)
                await asyncio.sleep(1.0)

    def pick(self, target, client="", session=None, exclude=None):
        """返回出口 dict；None 表示直连（关键词命中时）。

        exclude: 已试失败、本轮不再碰的出口 id 集合（自动重试用）。
        """
        s = self._settings()
        mode = s.get("mode", "round_robin")
        now = time.time()
        if mode != "exclusive":
            self._mode_note = ""

        # 目标绕过名单（照 ProxyCat）：命中就直接本机直连，不占用任何出口，
        # 与轮换模式无关，任何时候都生效；支持通配（*.baidu.com / 192.168.*）
        bl = [x for x in _split_list(s.get("bypass_list")) if x.strip()]
        if bl and any(_rule_hit(x, target) for x in bl):
            self._pick_reason = "bypass-direct"
            return None

        if mode == "keyword":
            kws = [k.strip().lower() for k in
                   str(s.get("keyword_list", "")).split(",") if k.strip()]
            hit = kws and any(k in (target or "").lower() for k in kws)
            white = str(s.get("keyword_mode") or "black") == "white"
            # 目标站点（学无影）：填了就只对该站点生效，其它请求照常走代理
            site = str(s.get("keyword_site") or "").strip().lower()
            scoped = (not site) or (site in (target or "").lower())
            # 黑名单：命中关键词直连；白名单：只有命中的才走代理，其余直连
            if kws and scoped and (hit if not white else not hit):
                self._pick_reason = "keyword-white-direct" if white else "keyword-direct"
                return None

        pool = self._candidates(s)
        if not pool and (s.get("infinite_mode") or s.get("empty_heal", True)):
            # 池空自愈：先把最久没验过的一小批失效出口捞回来顶着用
            # （原来只有无限模式会复活）。免费池经常整批同时死掉，等下一轮
            # 抓取得好几分钟——宁可让请求撞几条死出口（有自动重试换下一个），
            # 也别让整条代理链直接不可用。
            now = time.time()
            if now - self._last_revive > 20:
                self._last_revive = now
                if s.get("infinite_mode"):
                    n = self.store.revive_all()          # 无限模式：全量复活
                else:
                    n = self.store.revive_stale(12)      # 普通模式：只捞一小批
                self._pool_at = 0
                if n:
                    log.warning("池内无可用出口，已临时捞回 %s 条失效出口顶上，"
                                "同时后台重验证 + 触发补货", n)
            self._kick_revalidate()
            pool = self._candidates(s)
            if pool:
                self._mode_note = "池空自愈：已捞回失效出口继续轮询，后台正在重验证与补货"
                # 捞回来的只是「先顶着」的死节点，必须同时催补货，否则池子
                # 一直靠这几条烂节点撑着，永远等不到新血
                if self.pool_empty_hook and time.time() - self._last_heal_kick > 15:
                    self._last_heal_kick = time.time()
                    try:
                        if self.pool_empty_hook():
                            log.info("池空：已立即触发补货抓取")
                    except Exception as exc:
                        log.debug("触发补货失败: %s", exc)
        if exclude:
            filtered = [d for d in pool if d["id"] not in exclude]
            if not filtered:
                # 重试时本轮候选已全部试过：宁可报错也别再撞同一个坏出口
                raise ExitUnavailable("候选出口已全部试过")
            pool = filtered
        if not pool:
            raise ExitUnavailable(self._empty_msg(s))

        if mode == "exclusive":
            want = int(s.get("exclusive_id") or 0)
            if want == 0:
                # 固定代理·自动：固定用延时最短的可用出口（池按延迟升序）
                d = next((x for x in pool if self._capacity_ok(x, s)), None)
                if d:
                    self._mode_note = ""
                    self._cur = d
                    return self._use(d, "exclusive-fastest")
                self._mode_note = "独占·自动：可用出口并发已满，本次回退轮流"
                return self._rotate(pool, s)
            for d in pool:
                if d["id"] == want:
                    if self._capacity_ok(d, s):
                        self._mode_note = ""
                        self._cur = d
                        return self._use(d, "exclusive")
                    self._mode_note = f"独占出口 #{want} 并发已满，本次回退轮流"
                    return self._rotate(pool, s)
            self._mode_note = f"独占出口 #{want} 不在可用池（失效/隔离/已删），已回退轮流"
            return self._rotate(pool, s)

        if mode == "sticky":
            ttl = max(10, int(s.get("sticky_ttl") or 300))
            key = self._sticky_key(client, target, session)
            hit = self._sessions.get(key)
            if hit and hit[1] > now:
                d = next((x for x in pool if x["id"] == hit[0]), None)
                if d and self._capacity_ok(d, s):
                    self._cur = d
                    return self._use(d, "sticky-hit")
            d = self._rotate(pool, s)
            self._sessions[key] = (d["id"], now + ttl)
            self._sweep_sessions(now)
            return d

        life = max(0, int(s.get("life_seconds") or 0))   # 出口寿命（秒），0=不限

        if mode == "by_count":
            limit = max(1, int(s.get("rotate_count") or 20))
            # 寿命双条件（照 ProxyCat）：次数与时间同时生效，谁先到换谁
            life_hit = life and now - self._cur_since >= life
            if (self._cur is None or self._cur_used >= limit or life_hit
                    or self._cur["id"] not in {x["id"] for x in pool}
                    or not self._capacity_ok(self._cur, s)):
                if life_hit and self._cur is not None and self._cur_used < limit:
                    self._pick_reason = "life-time-hit"
                return self._rotate(pool, s)
            self._cur_used += 1
            return self._use(self._cur, "by-count")

        if mode == "by_time":
            limit = max(5, int(s.get("rotate_seconds") or 180))
            # 寿命双条件：时间到换；次数上限（rotate_count）也同时生效，谁先到换谁
            cnt = max(0, int(s.get("rotate_count") or 0))
            cnt_hit = cnt and self._cur_used >= cnt
            if (self._cur is None or now - self._cur_since >= limit or cnt_hit
                    or self._cur["id"] not in {x["id"] for x in pool}
                    or not self._capacity_ok(self._cur, s)):
                if cnt_hit and self._cur is not None:
                    self._pick_reason = "life-count-hit"
                return self._rotate(pool, s)
            return self._use(self._cur, "by-time")

        return self._rotate(pool, s)          # round_robin

    def _mark(self, exit_row, ok, delay=None):
        if not exit_row:
            return
        s = self._settings()
        # 无限模式（学无影）：代理失效后不隔离、不因超延迟判死，等下个循环还会被调用；
        # 坏代理只记失败统计，由“池空时复活重轮询”兜底
        inf = bool(s.get("infinite_mode"))
        self.store.set_result(
            exit_row["id"], ok, delay, source="proxy",
            quarantine_after=(10**9 if inf else int(s.get("fail_quarantine") or 4)),
            quarantine_secs=int(s.get("quarantine_seconds") or 600),
            max_delay_ms=(0 if inf else int(s.get("max_delay_ms") or 0)))
        self._pool_at = 0                  # 结果变化后下次重新取候选

        # 失败占比淘汰（照 ProxyCat）：看滑动窗口里的失败占比，而不是连续失败次数，
        # 把「一次网络抖动」和「这个出口就是坏的」区分开
        if s.get("fail_ratio_on") and not inf:
            win = max(5, int(s.get("fail_window") or 20))
            dq = self._recent.get(exit_row["id"])
            if dq is None or dq.maxlen != win:
                dq = deque((self._recent.get(exit_row["id"]) or ()), maxlen=win)
                self._recent[exit_row["id"]] = dq
            dq.append(1 if ok else 0)
            if len(dq) >= max(5, win // 2):
                bad = sum(1 for x in dq if not x)
                ratio = bad / len(dq) * 100
                if ratio >= float(s.get("fail_ratio") or 60):
                    self.store.quarantine(exit_row["id"],
                                          int(s.get("quarantine_seconds") or 600))
                    dq.clear()
                    self._mode_note = (f"出口 #{exit_row['id']} 失败占比 "
                                       f"{ratio:.0f}%，已隔离")
                    log.warning("出口 #%s 失败占比 %.0f%%，已隔离",
                                exit_row["id"], ratio)
                    self._pool_at = 0

    def _kick_revalidate(self):
        """池空时的后台重验证：把候选重测一遍，顺手救回失效的。

        以前只验 `candidates()`，可池空时它返回空，等于什么都没干——池子空到底
        也等不来救兵。现在多兜一层：没有有效候选就去验失效队列，通过的自动转有效。
        节流 60s，避免客户端高频请求时触发验证风暴。
        """
        now = time.time()
        if now - self._last_reval < 60:
            return
        self._last_reval = now
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return

        async def _job():
            import sources
            try:
                s = self.store.settings()
                rows = self.store.candidates(0, limit=1000)
                if not rows:
                    rows = self.store.invalid_rows(limit=300)
                if not rows:
                    return
                infinite = bool(s.get("infinite_mode"))
                results = await sources.validate_many(
                    [(r["id"], r) for r in rows], s["test_url"],
                    int(s["validate_timeout"]), int(s["validate_concurrency"]))
                for pid, good, delay, _anon, _hok in results:
                    if infinite:
                        # 无限模式：验证只刷延迟，不判死
                        self.store.set_result(pid, good, delay, source="heal",
                                              invalid_after=10 ** 9,
                                              quarantine_after=10 ** 9, max_delay_ms=0)
                    else:
                        # 普通模式：连续两次不通就退场，免得死节点长期占着候选位
                        self.store.set_result(
                            pid, good, delay, source="heal", invalid_after=2,
                            max_delay_ms=int(s.get("max_delay_ms") or 0))
                log.info("池空自愈：重验证 %s 条，通过 %s 条",
                         len(results), sum(1 for r in results if r[1]))
            except Exception:
                pass

        loop.create_task(_job())

    # ---------------- 出口连接（含自动重试） ----------------
    async def _connect_exit(self, host, port, client="", session=None, target="",
                            tunnel=True):
        """选出口并拨号；失败自动换下一个出口重试。

        商业轮换代理的标准行为：撞到坏代理不该把错误丢给客户端，
        而是悄悄换下一个出口再试，直到用完重试额度。
        只在"还没向客户端写过任何字节"的阶段适用——所以只包住选出口+拨号。
        返回 (exit_row, up_r, up_w)；直连时 exit_row 为 None。
        """
        s = self._settings()
        retries = int(s.get("max_retries") or 0)
        if not s.get("auto_switch", True):
            # 代理无效时自动切换：关掉后失败不重试，直接报给客户端
            retries = 0
        if retries < 0:
            # 无限重试：换着出口把整个候选池试一遍（上限 60 防御性兜底）
            tries = 60
        else:
            tries = 1 + max(0, retries)
        tried = set()
        last_err = ""
        tgt = target or f"{host}:{port}"
        precheck = bool(s.get("precheck_exit"))
        for _ in range(tries):
            exit_row = None
            try:
                exit_row = await self._pick_or_replenish(
                    tgt, client=client, session=session, exclude=tried or None)
                # 取前抢先验（照 ProxyCat）：把选中的出口先预检一次再交给客户端，
                # 不合格的丢掉换下一条，避免把第一次失败甩给用户
                if precheck and exit_row is not None:
                    try:
                        pc_r, pc_w = await asyncio.wait_for(
                            asyncio.open_connection(exit_row["host"],
                                                    int(exit_row["port"])), 4.0)
                        pc_w.close()
                    except Exception:
                        self._mark(exit_row, False, None)
                        tried.add(exit_row["id"])
                        self._pick_reason = f"precheck-fail#{len(tried)}"
                        log.info("取前预检失败，已换下一条：#%s", exit_row["id"])
                        continue
                up_r, up_w = await self._dial(exit_row, host, port, tunnel=tunnel)
                if tried:
                    self._pick_reason = f"retry#{len(tried)}"
                return exit_row, up_r, up_w
            except Exception as exc:
                if exit_row is not None:
                    tried.add(exit_row["id"])
                last_err = str(exc) or exc.__class__.__name__
        self._replenish = None
        raise ExitUnavailable(last_err or "拨号失败")

    # ---------------- 入口 ----------------
    @staticmethod
    def _acl_ok(ip, whitelist, blacklist, priority="black"):
        """入站客户端白/黑名单；回环永远放行。支持 CIDR。

        priority="black"（默认）黑名单优先；"white" 白名单优先——白名单非空时
        不在名单内一律拒绝，即便也没进黑名单。
        """
        ip = ip or ""
        if ip in ("127.0.0.1", "::1") or ip.startswith("127."):
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False

        def hit(cidrs):
            for part in str(cidrs).split(","):
                part = part.strip()
                if not part:
                    continue
                try:
                    if addr in ipaddress.ip_network(part, strict=False):
                        return True
                except ValueError:
                    if addr == part:
                        return True
            return False

        if str(priority or "black") == "white" and str(whitelist or "").strip() \
                and not hit(whitelist):
            return False
        if hit(blacklist):
            return False
        return (not str(whitelist or "").strip()) or hit(whitelist)

    def _global_gate(self, s):
        """全局并发闸门：超出的连接在这里排队等待（照 ProxyCat 排队而不是拒绝）。"""
        cap = int(s.get("max_conns_global") or 0)
        if cap <= 0:
            self._global_sem = None
            self._global_cap = 0
            return None
        if self._global_sem is None or self._global_cap != cap:
            self._global_sem = asyncio.Semaphore(cap)
            self._global_cap = cap
        return self._global_sem

    async def _handle(self, reader, writer, forced=None):
        sem = self._global_gate(self._settings())
        if sem is None:
            await self._handle_inner(reader, writer, forced)
        else:
            async with sem:                     # 满了就在这里排队
                await self._handle_inner(reader, writer, forced)

    async def _handle_inner(self, reader, writer, forced=None):
        self.stats["connections"] += 1
        try:
            peer = writer.get_extra_info("peername") or ("", 0)
            client = str(peer[0]) if isinstance(peer, (tuple, list)) and peer else ""
        except Exception:
            client = ""
        try:
            first = await asyncio.wait_for(reader.readexactly(1), 15)
        except Exception:
            writer.close()
            return
        # 入站 ACL：优先级可配（黑名单优先/白名单优先）；名单为空等于不限
        _s = self._settings()
        _wl = str(_s.get("ip_whitelist") or "")
        _bl = str(_s.get("ip_blacklist") or "")
        if (_wl.strip() or _bl.strip()) and not self._acl_ok(
                client, _wl, _bl, _s.get("acl_priority") or "black"):
            self.stats["rejected"] = self.stats.get("rejected", 0) + 1
            writer.close()
            return
        # 单独的 SOCKS 端口是「强制 SOCKS5」，但首字节是 0x04 时仍按 SOCKS4 处理，
        # 否则老客户端连 SOCKS 端口会收到 05 05 FF，报 "wrong version"
        if first == b"\x05" or (forced == "socks5" and first != b"\x04"):
            await self._socks5(reader, writer, client)
        elif first == b"\x04" and _s.get("socks4_enabled", True):
            # SOCKS4 / SOCKS4a（老客户端、部分爬虫框架还在用）
            await self._socks4(reader, writer, client)
        else:
            await self._http(reader, writer, first, client)

    # ---------------- SOCKS4 / 4a 入站 ----------------
    async def _socks4(self, reader, writer, client=""):
        """RFC 1928 之前的 SOCKS4；4a 允许客户端传域名（DSTIP=0.0.0.x）。"""
        try:
            cd = (await asyncio.wait_for(reader.readexactly(1), 10))[0]
            port = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), 10))[0]
            raw_ip = await asyncio.wait_for(reader.readexactly(4), 10)
            # USERID：读到 \0 为止（长度不可信，给个上限防被撑爆）
            user = b""
            while len(user) < 256:
                b = await asyncio.wait_for(reader.readexactly(1), 10)
                if b == b"\x00":
                    break
                user += b
            host = ".".join(str(x) for x in raw_ip)
            # 4a：DSTIP 前三个字节为 0、最后一个非 0，表示后面跟域名
            if raw_ip[:3] == b"\x00\x00\x00" and raw_ip[3] != 0:
                dom = b""
                while len(dom) < 255:
                    b = await asyncio.wait_for(reader.readexactly(1), 10)
                    if b == b"\x00":
                        break
                    dom += b
                host = dom.decode("utf-8", "ignore") or host
            if cd != 0x01:                       # 只支持 CONNECT
                writer.write(b"\x00\x5b" + b"\x00" * 6)
                await writer.drain()
                return
            target = f"{host}:{port}"
            t0 = time.perf_counter()
            exit_row = None
            try:
                exit_row, up_r, up_w = await self._connect_exit(
                    host, port, client=client, target=target)
            except Exception as exc:
                self.stats["fail"] += 1
                self._record(client, "socks4", target, exit_row, False, t0, str(exc))
                writer.write(b"\x00\x5b" + b"\x00" * 6)   # 91 = 请求被拒绝
                await writer.drain()
                return
            writer.write(b"\x00\x5a" + b"\x00" * 6)       # 90 = 成功
            await writer.drain()
            est_ms = round((time.perf_counter() - t0) * 1000, 1)
            ok, nbytes = await self._relay(reader, writer, up_r, up_w)
            self._mark(exit_row, ok, est_ms if ok else None)
            self._record(client, "socks4", target, exit_row, ok, t0, "socks4", nbytes)
        except (asyncio.IncompleteReadError, ConnectionResetError, asyncio.TimeoutError):
            pass
        except Exception:
            log.debug("SOCKS4 处理异常", exc_info=True)
        finally:
            try:
                writer.close()
            except Exception:
                pass

    # ---------------- SOCKS5 入站 ----------------
    async def _socks5(self, reader, writer, client=""):
        s = self._settings()
        need_auth = self.auth_required()
        try:
            nmethods = (await asyncio.wait_for(reader.readexactly(1), 10))[0]
            methods = await asyncio.wait_for(reader.readexactly(nmethods), 10)
            if need_auth:
                if 0x02 not in methods:
                    writer.write(b"\x05\xff")          # RFC 1928: 无可用方法
                    await writer.drain()
                    return
                writer.write(b"\x05\x02")
                await writer.drain()
                ver = (await asyncio.wait_for(reader.readexactly(1), 10))[0]
                if ver != 0x01:
                    return
                ulen = (await asyncio.wait_for(reader.readexactly(1), 10))[0]
                user = (await asyncio.wait_for(reader.readexactly(ulen), 10)).decode("utf-8", "ignore")
                plen = (await asyncio.wait_for(reader.readexactly(1), 10))[0]
                pwd = (await asyncio.wait_for(reader.readexactly(plen), 10)).decode("utf-8", "ignore")
                if not self.check_proxy_user(user, pwd):
                    writer.write(b"\x01\x01")
                    await writer.drain()
                    log.info("SOCKS5 认证失败：账号 %s 来自 %s", user or "-", client or "-")
                    self.stats["auth_fail"] = self.stats.get("auth_fail", 0) + 1
                    return
                writer.write(b"\x01\x00")
                await writer.drain()
            else:
                if 0x00 not in methods:
                    writer.write(b"\x05\xff")
                    await writer.drain()
                    return
                writer.write(b"\x05\x00")
                await writer.drain()

            ver, cmd, _, atyp = struct.unpack("!BBBB",
                                              await asyncio.wait_for(reader.readexactly(4), 10))
            if cmd != 0x01:
                writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)
                await writer.drain()
                return
            host, port, atyp_out = await self._read_socks_addr(reader, atyp)
            target = f"{host}:{port}"
            t0 = time.perf_counter()
            exit_row = None
            try:
                exit_row, up_r, up_w = await self._connect_exit(
                    host, port, client=client, target=target)
            except Exception as exc:
                self.stats["fail"] += 1
                self._record(client, "socks5", target, exit_row, False, t0, str(exc))
                writer.write(b"\x05\x01\x00\x01" + b"\x00" * 6)
                await writer.drain()
                return

            writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
            await writer.drain()
            # 延迟只算建立隧道的时间；把整个连接的生命周期算进去，
            # 浏览器一个长连接就会给节点记上几十秒的假延迟
            est_ms = round((time.perf_counter() - t0) * 1000, 1)
            ok, nbytes = await self._relay(reader, writer, up_r, up_w)
            self._mark(exit_row, ok, est_ms if ok else None)
            self._record(client, "socks5", target, exit_row, ok, t0, "socks5", nbytes)
        except (asyncio.IncompleteReadError, ConnectionResetError, asyncio.TimeoutError):
            pass
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _read_socks_addr(self, reader, atyp):
        if atyp == 0x01:
            host = ".".join(str(b) for b in await reader.readexactly(4))
            return host, struct.unpack("!H", await reader.readexactly(2))[0], atyp
        if atyp == 0x03:
            n = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(n)).decode("utf-8", "ignore")
            return host, struct.unpack("!H", await reader.readexactly(2))[0], atyp
        if atyp == 0x04:
            raw = await reader.readexactly(16)
            host = ":".join(f"{raw[i]:02x}{raw[i + 1]:02x}" for i in range(0, 16, 2))
            return host, struct.unpack("!H", await reader.readexactly(2))[0], atyp
        raise ExitUnavailable("不支持的地址类型")

    # ---------------- HTTP 入站 ----------------
    async def _http(self, reader, writer, first, client=""):
        try:
            buf = first + await self._read_until_headers(reader)
            head, _, rest = buf.partition(b"\r\n\r\n")
            lines = head.split(b"\r\n")
            method, target, version = lines[0].decode("latin1").split(" ", 2)
            headers = [ln.decode("latin1") for ln in lines[1:] if ln]
            session = None
            for h in headers:
                if h.lower().startswith("x-proxy-session:"):
                    session = h.split(":", 1)[1].strip()
                    break
            t0 = time.perf_counter()
            exit_row = None
            nbytes = 0
            # 入站账号校验（多用户）：任一启用账号匹配即放行；
            # 没配账号 = 不校验，保持本机自用免密。
            if self.auth_required():
                au, ap = "", ""
                for h in headers:
                    low = h.lower()
                    if low.startswith("proxy-authorization:"):
                        raw = h.split(":", 1)[1].strip()
                        if raw[:6].lower() == "basic ":
                            try:
                                dec = base64.b64decode(raw[6:]).decode("utf-8", "ignore")
                                au, _, ap = dec.partition(":")
                            except Exception:
                                au, ap = "", ""
                        break
                if not self.check_proxy_user(au, ap):
                    self.stats["auth_fail"] = self.stats.get("auth_fail", 0) + 1
                    body = ("需要账号密码：请把用户名密码填进代理设置，"
                            "或使用 http://用户:密码@主机:端口").encode("utf-8")
                    writer.write(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                        b'Proxy-Authenticate: Basic realm="ProxyDog"\r\n'
                        b"Content-Type: text/plain; charset=utf-8\r\n"
                        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                        b"Connection: close\r\n\r\n" + body)
                    await writer.drain()
                    log.info("HTTP 认证失败：账号 %s 来自 %s 目标 %s",
                             au or "-", client or "-", target[:60])
                    self._record(client, "http", target, None, False, t0, "代理认证失败")
                    return
            try:
                if method.upper() == "CONNECT":
                    host, _, port_s = target.rpartition(":")
                    host = host.strip("[]")
                    port = int(port_s)
                    exit_row, up_r, up_w = await self._connect_exit(
                        host, port, client=client, session=session)
                    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    await writer.drain()
                    ok, nbytes = await self._relay(reader, writer, up_r, up_w)
                else:
                    host, port, path = self._split_url(target)
                    # 明文请求能在看到上游状态码后再决定写不写给客户端，
                    # 所以撞到 403/407/502 这类坏出口响应时也能重试换出口
                    s2 = self._settings()
                    attempts = (1 + max(0, int(s2.get("max_retries") or 0))
                                if s2.get("auto_switch", True) else 1)
                    tried = set()
                    for attempt in range(attempts):
                        origin_form = method.upper() in ("GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH")
                        # 先只选出口看协议，确定请求形态后再拨号（tunnel 与协议相关）
                        exit_row = await self._pick_or_replenish(
                            f"{host}:{port}", client=client,
                            session=session, exclude=tried or None)
                        use_absolute = exit_row is not None and exit_row["protocol"] in ("http", "https")
                        new_target = target if use_absolute else path
                        req_head = f"{method} {new_target} {version}\r\n"
                        for h in headers:
                            low = h.lower()
                            if low.startswith(("proxy-connection:", "proxy-authorization:")):
                                continue
                            if low.startswith("connection:"):
                                continue
                            req_head += h + "\r\n"
                        if use_absolute and exit_row.get("username"):
                            req_head += f"Proxy-Authorization: {_basic(exit_row['username'], exit_row.get('password') or '')}\r\n"
                        req_head += "Connection: keep-alive\r\n\r\n"
                        try:
                            up_r, up_w = await self._dial(exit_row, host, port,
                                                          tunnel=not use_absolute)
                            up_w.write(req_head.encode("latin1") + rest)
                            await up_w.drain()
                        except Exception as exc:
                            # 拨号/写请求失败：还没碰客户端，换下一个出口再来
                            if exit_row is not None:
                                self._mark(exit_row, False, None)
                                tried.add(exit_row["id"])
                            last_err = str(exc) or exc.__class__.__name__
                            continue
                        bad_status = False
                        early = 0
                        first_resp = b""
                        if use_absolute:
                            # 明文请求能看到上游的第一段响应，顺手识别 403/407/502 这类坏出口
                            first_resp = await asyncio.wait_for(
                                self._read_until_headers(up_r), DIAL_TIMEOUT)
                            status_line = first_resp.split(b"\r\n", 1)[0].decode("latin1", "ignore")
                            bad_status = any(code in status_line
                                             for code in (" 400", " 403", " 407", " 429",
                                                          " 500", " 502", " 503", " 504"))
                            _, _, early_body = first_resp.partition(b"\r\n\r\n")
                            early = len(early_body)
                        if bad_status and attempt < attempts - 1:
                            self._mark(exit_row, False, None)
                            tried.add(exit_row["id"])
                            self._pick_reason = f"bad-status-retry#{len(tried)}"
                            try:
                                up_w.close()
                            except Exception:
                                pass
                            continue
                        if use_absolute:
                            writer.write(first_resp)
                            await writer.drain()
                        # 只记建立隧道的时间，连接后续时长不算节点延迟
                        est_ms = round((time.perf_counter() - t0) * 1000, 1)
                        ok, nbytes = await self._relay(reader, writer, up_r, up_w, early)
                        ok = ok and not bad_status
                        break
                    else:
                        # 重试额度用完仍然连不上上游：交给外层统一回 502
                        raise ExitUnavailable(last_err or "所有出口均不可用")
                self._mark(exit_row, ok, est_ms if ok else None)
                self._record(client, "http", target, exit_row, ok, t0, method.upper(), nbytes)
            except Exception as exc:
                self.stats["fail"] += 1
                self._record(client, "http", target, exit_row, False, t0, str(exc), nbytes)
                body = b"ProxyDog: upstream failed"
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: "
                             + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    @staticmethod
    def _split_url(url):
        from urllib.parse import urlsplit
        if "://" not in url:
            url = "http://" + url
        parts = urlsplit(url)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        return parts.hostname or "", port, path

    async def _read_until_headers(self, reader):
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = await asyncio.wait_for(reader.read(4096), 15)
            if not chunk:
                break
            buf += chunk
            if len(buf) > MAX_HEADER:
                raise ExitUnavailable("请求头过大")
        return buf

    # ---------------- 上游拨号 ----------------
    async def _dial(self, exit_row, host, port, tunnel=True, resolve=True):
        if exit_row is None:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, limit=MAX_HEADER), DIAL_TIMEOUT)
            return reader, writer

        s = self._settings()
        if resolve:
            host = await self._resolve_target(exit_row, host)
        # 多跳上游链：池里的出口当第一跳，后面按 chain_hops 依次串 SOCKS5
        hops = self._chain_hops() if s.get("chain_enabled") else []
        if hops:
            return await self._dial_chain(exit_row, hops, host, port)

        proto = exit_row["protocol"]
        ctx = self._ssl if proto == "https" else None
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(exit_row["host"], int(exit_row["port"]),
                                    ssl=ctx, limit=MAX_HEADER), DIAL_TIMEOUT)
        try:
            if proto == "socks5":
                await self._socks5_upstream(reader, writer, exit_row, host, port)
            elif tunnel:
                await self._http_connect(reader, writer, exit_row, host, port)
            return reader, writer
        except Exception:
            writer.close()
            raise

    @staticmethod
    def _is_ip(host):
        try:
            ipaddress.ip_address(str(host or "").strip("[]"))
            return True
        except ValueError:
            return False

    async def _resolve_target(self, exit_row, host):
        """按 dns_mode 决定域名在哪解析。

        remote（默认）：原样把域名交给上游——真正的不泄漏，上游自己解析；
        local        ：本地系统解析成 IP 再连（兼容不认域名的上游，但会暴露查询）；
        proxy        ：走隧道向 dns_server 发 TCP DNS 查询（DNS over SOCKS），
                       本机不发任何明文 DNS，也不依赖上游的解析器。
        """
        if not host or self._is_ip(host):
            return host
        s = self._settings()
        mode = str(s.get("dns_mode") or "remote").lower()
        if mode == "local":
            try:
                infos = await asyncio.wait_for(
                    asyncio.get_running_loop().getaddrinfo(host, None), 5.0)
                for info in infos:
                    if info[0] == 2:                 # AF_INET
                        return info[4][0]
                if infos:
                    return infos[0][4][0]
            except Exception:
                pass
            return host
        if mode == "proxy":
            server = str(s.get("dns_server") or "1.1.1.1").strip()
            if self._is_ip(server):
                ip = await self._dns_via_tunnel(exit_row, server, host)
                if ip:
                    return ip
            return host
        return host                          # remote：交给上游解析

    async def _dns_via_tunnel(self, exit_row, server, name, timeout=5.0):
        """在已建立的代理隧道里发一条 TCP DNS 查询，取第一条 A 记录。"""
        try:
            r, w = await self._dial(exit_row, server, 53, tunnel=True, resolve=False)
        except Exception:
            return ""
        try:
            q = _build_dns_query(name)
            w.write(struct.pack("!H", len(q)) + q)
            await w.drain()
            n = struct.unpack("!H", await asyncio.wait_for(r.readexactly(2), timeout))[0]
            data = await asyncio.wait_for(r.readexactly(n), timeout)
            return _first_a_record(data)
        except Exception:
            return ""
        finally:
            try:
                w.close()
            except Exception:
                pass

    def _chain_hops(self):
        """解析 chain_hops：socks5://user:pass@host:port,host2:port2"""
        raw = str(self._settings().get("chain_hops") or "")
        out = []
        for part in raw.replace("\n", ",").split(","):
            part = part.strip()
            if not part:
                continue
            proto, user, pwd, hp = "socks5", "", "", part
            if "://" in part:
                proto, _, hp = part.partition("://")
            if "@" in hp:
                cred, _, hp = hp.rpartition("@")
                user, _, pwd = cred.partition(":")
            host, _, port = hp.rpartition(":")
            if not host or not port.isdigit():
                continue
            out.append({"protocol": proto.lower() or "socks5", "host": host.strip("[]"),
                        "port": int(port), "username": user, "password": pwd})
        return out[:5]                            # 最多 5 跳，再多纯属自虐

    async def _dial_chain(self, exit_row, hops, host, port):
        """client → 池出口 → hop1 → hop2 → … → 目标；每跳之间用 SOCKS5 级联。"""
        first = hops[0]
        proto = exit_row["protocol"]
        ctx = self._ssl if proto == "https" else None
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(exit_row["host"], int(exit_row["port"]),
                                    ssl=ctx, limit=MAX_HEADER), DIAL_TIMEOUT)
        try:
            # 池出口 → 第一跳
            if proto == "socks5":
                await self._socks5_handshake(reader, writer, exit_row)
                await self._socks5_request(reader, writer, first["host"], first["port"])
            else:
                await self._http_connect(reader, writer, exit_row, first["host"], first["port"])
            await self._socks5_handshake(reader, writer, first)
            cur = first
            for hop in hops[1:]:
                await self._socks5_request(reader, writer, hop["host"], hop["port"])
                await self._socks5_handshake(reader, writer, hop)
                cur = hop
            await self._socks5_request(reader, writer, host, port)
            return reader, writer
        except Exception:
            try:
                writer.close()
            except Exception:
                pass
            raise


    async def _http_connect(self, reader, writer, exit_row, host, port):
        req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        if exit_row.get("username"):
            req += f"Proxy-Authorization: {_basic(exit_row['username'], exit_row.get('password') or '')}\r\n"
        req += "Proxy-Connection: keep-alive\r\n\r\n"
        writer.write(req.encode("latin1"))
        await writer.drain()
        head = await asyncio.wait_for(self._read_until_headers(reader), DIAL_TIMEOUT)
        first_line = head.split(b"\r\n", 1)[0].decode("latin1", "ignore")
        parts = first_line.split()
        if len(parts) < 2 or not parts[1].startswith("2"):
            raise ExitUnavailable(f"上游拒绝 CONNECT: {first_line}")

    async def _socks5_upstream(self, reader, writer, exit_row, host, port):
        """完整的上游 SOCKS5：方法协商 + 认证 + CONNECT。"""
        await self._socks5_handshake(reader, writer, exit_row)
        await self._socks5_request(reader, writer, host, port)

    async def _socks5_handshake(self, reader, writer, creds):
        """与一个 SOCKS5 服务端完成方法协商与用户名密码认证。"""
        need_auth = bool(creds.get("username"))
        writer.write(b"\x05\x02\x00\x02" if need_auth else b"\x05\x01\x00")
        await writer.drain()
        resp = await asyncio.wait_for(reader.readexactly(2), DIAL_TIMEOUT)
        if resp[0] != 0x05:
            raise ExitUnavailable("上游不是 SOCKS5")
        if resp[1] == 0x02:
            user = str(creds.get("username", "")).encode()
            pwd = str(creds.get("password") or "").encode()
            writer.write(b"\x01" + bytes([len(user)]) + user + bytes([len(pwd)]) + pwd)
            await writer.drain()
            auth = await asyncio.wait_for(reader.readexactly(2), DIAL_TIMEOUT)
            if auth[1] != 0:
                raise ExitUnavailable("上游 SOCKS5 认证失败")
        elif resp[1] != 0x00:
            raise ExitUnavailable("上游 SOCKS5 无可接受方法")

    async def _socks5_request(self, reader, writer, host, port):
        """在当前 SOCKS5 连接上发 CONNECT（域名原样发，由上游解析）。"""
        try:
            ip = ipaddress.ip_address(str(host).strip("[]"))
        except ValueError:
            ip = None
        if ip is None:
            raw = str(host).encode()
            req = b"\x05\x01\x00\x03" + bytes([len(raw)]) + raw
        elif ip.version == 4:
            req = b"\x05\x01\x00\x01" + ip.packed
        else:
            req = b"\x05\x01\x00\x04" + ip.packed
        req += struct.pack("!H", int(port))
        writer.write(req)
        await writer.drain()
        rep = await asyncio.wait_for(reader.readexactly(4), DIAL_TIMEOUT)
        if rep[1] != 0:
            raise ExitUnavailable(f"上游 SOCKS5 连接失败 rep={rep[1]}")
        if rep[3] == 0x01:
            await reader.readexactly(4 + 2)
        elif rep[3] == 0x03:
            n = (await reader.readexactly(1))[0]
            await reader.readexactly(n + 2)
        elif rep[3] == 0x04:
            await reader.readexactly(16 + 2)

    # ---------------- 中继 ----------------
    async def _relay(self, cli_r, cli_w, up_r, up_w, pre_bytes=0, s=None):
        """双向中继。pre_bytes 是已经写给客户端、但没走 pipe 的字节数。

        明文 HTTP 的响应头经常和 body 一起被首包读走，如果只统计 pipe 里的字节，
        会把「其实成功」的请求记成 0 字节失败，进而把好出口标成失效。

        连接层三参数（照 ProxyCat）：
        - relay_buffer          写缓冲阈值：客户端读得慢（写缓冲超阈值）就暂停转发
        - conn_idle_timeout     客户端侧空闲回收秒数；0=不回收
        - upstream_idle_timeout 上游无数据超时秒数；0=关闭（首个响应也受它约束）
        """
        s = s or self._settings()
        inbound = pre_bytes
        buf_threshold = max(4096, int(s.get("relay_buffer") or 8192))
        idle = float(s.get("conn_idle_timeout") or 0) or None
        up_idle = float(s.get("upstream_idle_timeout") or 0) or idle

        async def pipe(src, dst, is_inbound):
            nonlocal inbound
            to = idle if not is_inbound else up_idle     # is_inbound: 上游->客户端
            try:
                while True:
                    if to:
                        data = await asyncio.wait_for(src.read(65536), to)
                    else:
                        data = await src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    # 客户端读得慢就先别从上游读：避免把内存吃爆
                    if dst.transport is not None:
                        waited = 0.0
                        while dst.transport.get_write_buffer_size() > buf_threshold:
                            await asyncio.sleep(0.02)
                            waited += 0.02
                            if waited > 30:
                                break
                    await dst.drain()
                    if is_inbound:
                        inbound += len(data)
                        self.stats["bytes_in"] += len(data)
                    else:
                        self.stats["bytes_out"] += len(data)
            except (asyncio.TimeoutError, asyncio.exceptions.TimeoutError):
                # 空闲/上游无数据超时：正常回收（这两个参数就是干这个的）
                if is_inbound and up_idle:
                    log.info("上游 %.0fs 无数据，回收连接", up_idle)
                elif idle:
                    log.debug("连接空闲 %.0fs，回收", idle)
            except Exception:
                pass
            finally:
                try:
                    dst.close()
                except Exception:
                    pass

        await asyncio.gather(pipe(up_r, cli_w, True), pipe(cli_r, up_w, False))
        self.stats["success" if inbound else "fail"] += 1
        return inbound > 0, inbound

    def _record(self, client, proto, target, exit_row, ok, t0, note, nbytes=0):
        if exit_row:
            pid = exit_row["id"]
            self._conn_open[pid] = max(0, self._conn_open.get(pid, 0) - 1)
        ms = round((time.perf_counter() - t0) * 1000)
        item = {
            "time": time.strftime("%H:%M:%S"),
            "client": client or "-",
            "proto": proto,
            "target": target[:80],
            "exit": (f"{exit_row['protocol']}://{exit_row['host']}:{exit_row['port']}"
                     if exit_row else "直连"),
            "ok": ok,
            "ms": ms,
            "note": (note or "")[:80],
            "nbytes": nbytes,
        }
        self.recent.appendleft(item)
        now = time.time()
        if now - self._flags_at > 5:          # 每 5 秒取一次开关，避免每请求读库
            self._log_on = bool(self._settings().get("log_access", True))
            self._flags_at = now
        if self._log_on:
            self.log_queue.append({
                "ts": time.time(), "client": client or "", "proto": proto,
                "target": target[:200],
                "exit_proto": exit_row["protocol"] if exit_row else "",
                "exit_host": exit_row["host"] if exit_row else "",
                "exit_port": exit_row["port"] if exit_row else 0,
                "ok": ok, "ms": ms, "nbytes": nbytes,
                "note": (note or "")[:120],
            })

    def snapshot(self):
        s = self._settings()
        mode = s.get("mode") or "round_robin"
        used, limit, next_in = 0, 0, 0
        if mode == "by_count":
            limit = max(1, int(s.get("rotate_count") or 20))
            used, next_in = self._cur_used, max(0, limit - self._cur_used)
        elif mode == "by_time":
            limit = max(5, int(s.get("rotate_seconds") or 180))
            age = int(time.time() - self._cur_since) if self._cur_since else 0
            used, next_in = age, max(0, limit - age)
        elif mode == "sticky":
            limit = max(10, int(s.get("sticky_ttl") or 300))
            used = len(self._sessions)
        socks_port = int(s.get("socks_port") or 0)
        if s.get("socks_shared"):
            # 同端口开关打开：HTTP 与 SOCKS5 都走 listen_port，首字节嗅探区分
            listen = (f"{s.get('listen_host')}:{s.get('listen_port')}"
                      f" · HTTP+SOCKS5 共用")
        elif socks_port and socks_port != int(s.get("listen_port") or 0):
            listen = (f"{s.get('listen_host')}:{s.get('listen_port')}"
                      f" · SOCKS5 {socks_port}")
        else:
            listen = f"{s.get('listen_host')}:{s.get('listen_port')}"
        return {
            "running": self.running,
            "listen": listen,
            "auth": {"required": self.auth_required(), "users": len(self.proxy_creds())},
            "mode": mode,
            "mode_note": self._mode_note,
            "pick_reason": self._pick_reason,
            "uptime": int(time.time() - self.started_at) if self.started_at else 0,
            "current": (f"{self._cur['protocol']}://{self._cur['host']}:{self._cur['port']}"
                        if self._cur else ""),
            "current_id": self._cur["id"] if self._cur else 0,
            "current_delay": self._cur.get("delay_ms") if self._cur else None,
            "current_region": (self._cur.get("region") or ""
                               if self._cur else ""),
            "rotate": {"used": used, "limit": limit, "next_in": next_in,
                       "sessions": len(self._sessions)},
            "conn_open": sum(self._conn_open.values()),
            "stats": dict(self.stats),
            "recent": list(self.recent)[:20],
            "pool_size": len(self._pool),
            "pool_refreshed": int(self._pool_at),
            "pending_logs": len(self.log_queue),
            "replenish": self._replenish if self._replenish else None,
            "conn_waiting": (self._global_cap - self._global_sem._value
                             if self._global_sem is not None else 0),
        }


# ---------------- 隧道内 DNS（DNS over SOCKS 用） ----------------
def _build_dns_query(name, qtype=1):
    """构造一条最小 DNS 查询（单问题、递归请求、无 EDNS）。"""
    tid = random.randint(0, 0xFFFF)
    head = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    q = b""
    for part in str(name).strip(".").split("."):
        try:
            raw = part.encode("idna")
        except UnicodeError:
            raw = part.encode("utf-8", "ignore")
        if not raw or len(raw) > 63:
            continue
        q += bytes([len(raw)]) + raw
    q += b"\x00" + struct.pack("!HH", qtype, 1)
    return head + q


def _skip_dns_name(data, off):
    """跳过（可能被压缩的）域名，返回紧随其后的偏移。"""
    n = len(data)
    while off < n:
        ln = data[off]
        if ln & 0xC0 == 0xC0:
            return off + 2
        if ln == 0:
            return off + 1
        off += 1 + ln
    return n


def _first_a_record(data):
    """从 DNS 响应里取第一条 A 记录，取不到返回空串。"""
    try:
        if len(data) < 12:
            return ""
        _tid, _flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
        off = 12
        for _ in range(qd):
            off = _skip_dns_name(data, off) + 4
        for _ in range(an):
            off = _skip_dns_name(data, off)
            if off + 10 > len(data):
                return ""
            rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
            off += 10
            if rtype == 1 and rdlen == 4:
                return ".".join(str(b) for b in data[off:off + 4])
            off += rdlen
    except (struct.error, IndexError):
        return ""
    return ""
