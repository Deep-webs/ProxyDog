"""ProxyDog 存储层：SQLite(WAL) + 设置项。

设计要点：
- WAL 打开时设置 wal_autocheckpoint，避免运行期 -wal 无限增长；
- 代理按 (host, port, protocol) 唯一，重复导入不会产生重复行；
- 每条代理都有 enabled 开关，可单独停用；
- 成功/失败计数落库，供健康度与自动淘汰使用；
- 失败分两类：主动验证失败（判 is_valid）与转发失败（只降权 + 隔离），
  避免一个客户端主动断开就把好出口判死，这是免费池能维持规模的关键。
"""

import json
import logging
import os
import sqlite3
import threading
import time

log = logging.getLogger("proxydog.store")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "proxydog.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS proxies (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    host          TEXT    NOT NULL,
    port          INTEGER NOT NULL,
    protocol      TEXT    NOT NULL DEFAULT 'http',
    username      TEXT    DEFAULT '',
    password      TEXT    DEFAULT '',
    region        TEXT    DEFAULT '',
    delay_ms      REAL,
    is_valid      INTEGER DEFAULT 0,
    enabled       INTEGER DEFAULT 1,
    success_count INTEGER DEFAULT 0,
    fail_count    INTEGER DEFAULT 0,
    ok_streak     INTEGER DEFAULT 0,
    fail_streak   INTEGER DEFAULT 0,
    quarantine_until REAL DEFAULT 0,
    avg_ms        REAL,
    last_check    REAL,
    last_used     REAL,
    source        TEXT    DEFAULT '',
    created_at    REAL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_proxies_uniq ON proxies(host, port, protocol);
CREATE INDEX IF NOT EXISTS idx_proxies_pick ON proxies(is_valid, enabled, delay_ms);
CREATE TABLE IF NOT EXISTS settings (
    k TEXT PRIMARY KEY,
    v TEXT
);
CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT UNIQUE NOT NULL,
    pwd_hash   TEXT NOT NULL,
    salt       TEXT NOT NULL,
    role       TEXT DEFAULT 'admin',
    created_at REAL,
    last_login REAL
);
CREATE TABLE IF NOT EXISTS proxy_users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT UNIQUE NOT NULL,
    password   TEXT NOT NULL,
    note       TEXT DEFAULT '',
    enabled    INTEGER DEFAULT 1,
    created_at REAL,
    last_used  REAL DEFAULT 0,
    hits       INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS api_keys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    key        TEXT UNIQUE NOT NULL,
    enabled    INTEGER DEFAULT 1,
    calls      INTEGER DEFAULT 0,
    daily_quota INTEGER DEFAULT 0,
    day_calls  INTEGER DEFAULT 0,
    day_stamp  TEXT DEFAULT '',
    created_at REAL,
    last_used  REAL
);
CREATE TABLE IF NOT EXISTS access_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL,
    client     TEXT,
    proto      TEXT,
    target     TEXT,
    exit_proto TEXT,
    exit_host  TEXT,
    exit_port  INTEGER,
    ok         INTEGER,
    ms         INTEGER,
    nbytes     INTEGER,
    note       TEXT
);
CREATE INDEX IF NOT EXISTS idx_log_ts ON access_log(ts);
CREATE INDEX IF NOT EXISTS idx_log_ok ON access_log(ok, ts);
CREATE TABLE IF NOT EXISTS domain_stat (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    domain     TEXT UNIQUE NOT NULL,
    hits       INTEGER DEFAULT 0,
    ok         INTEGER DEFAULT 0,
    nbytes     INTEGER DEFAULT 0,
    last_ts    REAL
);
CREATE TABLE IF NOT EXISTS api_sources (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    provider   TEXT NOT NULL DEFAULT 'github',
    target     TEXT DEFAULT '',
    query      TEXT DEFAULT '',
    protocol   TEXT DEFAULT 'http',
    creds      TEXT DEFAULT '{}',
    cap        INTEGER DEFAULT 300,
    enabled    INTEGER DEFAULT 1,
    created_at REAL,
    last_run   REAL,
    last_count INTEGER DEFAULT 0,
    last_error TEXT DEFAULT ''
);
"""

DEFAULTS = {
    # 网络：默认只对本机开放，需要局域网访问时再改监听地址
    "listen_host": "127.0.0.1",
    "listen_port": 2080,
    # SOCKS5 独立端口；0 或等于 HTTP 端口 = 同端口混合监听（自动识别协议）
    "socks_port": 2081,
    # 同端口开关：true = HTTP 与 SOCKS5 共用 listen_port（2080），false = 用两个端口
    "socks_shared": False,
    "web_host": "127.0.0.1",
    "web_port": 5002,
    # 出口轮换：round_robin / by_count / by_time / sticky / keyword / exclusive
    "mode": "round_robin",
    "rotate_count": 20,
    "rotate_seconds": 180,
    "keyword_list": "bank,pay,login,mail",
    "exclusive_id": 0,
    # 粘性会话：同一客户端 + 同一目标在 TTL 内固定用同一个出口
    "sticky_ttl": 300,
    # 出口质量：加权（快/稳的出口被选中概率更高）、单出口并发上限、同 IP 去重
    "weight_health": True,
    "max_conn_per_exit": 8,
    "dedupe_exit": True,
    # 延迟优先：只在“最快的一批”出口里挑（最快值 + 窗口 ms，且不超过池子的前 25%），
    # 避免总用同一条被打爆，同时基本不碰慢节点
    "prefer_fast": True,
    "fast_window_ms": 300,
    # 无限模式（无限轮询）：轮换范围扩大到整个有效池，从延时最小开始依次轮流、循环往复
    "infinite_mode": False,
    # 场景模式：验证网站（空 = 用上面的 test_url），每 2 分钟验证一次，失败即换
    "scenario_site": "",
    "scenario_keyword": "",          # 场景验证：HTTP 响应需包含的特征字符串（照无影「包含字符串」）
    "scenario_drop_invalid": False,  # 场景验证：累计三次无效后删除代理（照无影「删除无效代理」）
    # 关键词模式：目标站点（空 = 对所有请求生效）
    "keyword_site": "",
    # 代理无效时自动切换：转发失败自动换下一个出口重试；关闭后失败直接报给客户端
    "auto_switch": True,
    # 转发失败累计到 N 次先隔离（冷却后自动复活），而不是直接判死
    "fail_quarantine": 4,
    "quarantine_seconds": 600,
    # 转发失败自动换出口重试（商业代理标配）；0 = 不重试
    "max_retries": 2,
    # 验证时顺带检测匿名度与 HTTPS 支持（每条代理多 1~2 个请求，稍慢）
    "verify_anonymity": True,
    "anon_echo_url": "https://httpbin.org/get",
    # 地区偏好：逗号分隔，命中（如 CN,US）的出口选择权重翻 4 倍；空 = 不偏好
    "preferred_regions": "",
    # 入站认证（默认关闭；开启后 HTTP 与 SOCKS5 都必须带凭据）
    "auth_username": "",
    "auth_password": "",
    "token": "",
    # 验证
    "test_url": "https://www.baidu.com",
    # 验证时响应体必须包含的字符串（空=按测试地址自动推，例如 baidu -> 百度一下）
    "test_keyword": "",
    # 自动推特征串的总开关：关掉后 test_keyword 为空就真的只看状态码
    "test_keyword_auto": True,
    "validate_concurrency": 160,          # 并发验证：免费池 95% 是死的，串行验根本追不上节点死亡速度
    "validate_timeout": 5,
    "validate_on_add": True,
    # 延迟上限：超过这条线的出口不进候选池，验证后直接判为不可用
    "max_delay_ms": 2000,
    # 验证结束后直接删掉超延迟的条目，而不是留在列表里占位
    "auto_drop_slow": True,
    # 清理「从没成功过」的死条目：保留小时数（0=只保留，不自动删）
    "dead_purge_hours": 2,
    "drop_transparent": False,
    # 抓取
    "auto_fetch": False,
    "fetch_interval_minutes": 30,
    "max_fetch_total": 2000,
    # GeoNode 接口默认关，按需开启
    "fetch_geonode": False,
    # 抓取范围：all=全部 / cn=仅国内 / global=仅国外（排除中国大陆及港澳台）
    #          / country=指定国家（配合 fetch_countries 的 ISO 代码，逗号分隔）
    "fetch_scope": "all",
    "fetch_countries": "",
    # 自定义源（GitHub 仓库 / 空间测绘 API）总开关
    "fetch_custom": True,
    # 审计日志
    "log_access": True,
    "access_log_days": 7,
    # 归属地：用本地离线库，入库/验证后自动补，不用手动点
    "geo_auto": True,
    # 面板登录保护：本地自用默认关闭，打开后回到 admin/密码登录
    # 只在面板监听 127.0.0.1 时才是安全的，改成 0.0.0.0 前先想清楚
    "panel_auth": False,
    # 面板：登录失败锁定
    "login_max_fail": 5,
    "login_lock_minutes": 10,
    # 安全：允许使用代理/面板的来源网段（逗号分隔，空=不限）
    "ip_whitelist": "",
    # 安全：拒绝使用代理/面板的来源网段（逗号分隔）；黑名单优先于白名单
    "ip_blacklist": "",
    # 关键词模式：black=黑名单（命中关键词直连），white=白名单（仅命中走代理）
    "keyword_mode": "black",
    # ---- 代理来源（照 ProxyCat 三种来源）----
    "upstream_source": "pool",      # pool 内置池 / api 实时接口 / remote 远程代理池
    "source_api_url": "",           # api：返回代理列表的接口地址
    "source_api_interval": 5,       # api：刷新间隔（分钟）
    "source_api_limit": 200,        # api：单次最多取几条
    "source_remote_url": "",        # remote：远程代理池订阅地址（如另一台 ProxyDog 的 /api/export）
    "source_remote_interval": 5,    # remote：刷新间隔（分钟）
    # ---- 失败占比淘汰（照 ProxyCat：看滑动窗口失败占比，而不是连续失败次数）----
    "fail_ratio_on": True,
    "fail_window": 15,              # 窗口样本数
    "fail_ratio": 50,               # 失败占比阈值（%）
    # ---- 自动重验证：定期把池内有效出口重测一遍，坏掉尽快踢出候选 ----
    "revalidate_interval": 300,     # 重验证周期（秒）：免费节点“半小时新鲜度”根本不够，5 分钟一轮
    # ---- 目标绕过名单（照 ProxyCat：命中的目标强制直连）----
    "bypass_list": "",
    # ---- 验证强度（照 ProxyCat 三档）----
    "validate_level": "standard",   # fast 快速 / standard 标准 / strict 严格
    # ---- 自动爬取弹窗（照无影）：区域参数 + 自定义语法预设 ----
    "crawl_region": "cn",           # cn 国内 / global 国外 / all 全部
    "crawl_presets": "[]",          # 用户自存的常用语法（JSON：[{engine,name,q}]）
    # ---- 全局并发与池空等待（照 ProxyCat）----
    "max_conns_global": 3000,       # 全局并发上限，超出排队等待；0=不限
    "wait_pool_seconds": 30,        # 池空时持续补货等待的秒数，超时才报错；0=不等待
    "precheck_exit": True,          # 取前抢先验：把选中的出口先预检一次再交给客户端（智能版：只检不新鲜的）
    "precheck_fresh": 60,           # 预检新鲜期（秒）：一分钟内拨通过的出口才免检
    "dial_timeout": 5,              # 拨号超时（秒）：免费出口建连慢的直接淘汰
    # ---- 检测节流三参数（照 ProxyCat）----
    "check_cache_seconds": 30,      # 检测结果缓存：缓存期内不重复发请求
    "check_min_interval": 5,        # 同一出口两次检测的最小间隔（秒）
    "check_dup_interval": 1,        # 重复出口（同 host）两次检测的最小间隔（秒）
    # ---- 连接层三参数（照 ProxyCat）----
    "relay_buffer": 8192,           # 转发缓冲阈值（字节）：客户端读得慢就暂停转发
    "conn_idle_timeout": 30,        # 连接空闲回收（秒）；0=不回收
    "upstream_idle_timeout": 10,    # 上游无数据超时（秒）；0=关闭
    # ---- 出口寿命双条件（照 ProxyCat：时间与次数同时生效，谁先到换谁）----
    "life_seconds": 60,             # 出口寿命（秒）；0=不限，只按次数换
    "pool_keep": 0,                 # 存池上限：候选池维持多少条在用出口；0=不限
    # ---- 本机公网出口 IP（匿名判断的基准；留空则自动探测）----
    "public_ip": "",
    # ---- 日志 ----
    "log_level": "INFO",            # 低于该级别不写入日志文件
    "log_file_max_mb": 10,          # 单个日志文件上限（MB），超过轮转
    "log_backups": 3,               # 日志保留份数
    "access_log_max": 200000,       # 访问记录条数上限，超出自动删最老
    # ---- 黑白名单优先级 ----
    "acl_priority": "black",        # black=黑名单优先 / white=白名单优先
    # ---- 备份 ----
    "backup_interval_hours": 24,    # 自动备份间隔（小时）
    "backup_keep": 7,               # 备份保留份数
    # ---- API 凭据库（多套 API 地址保存，下拉切换）----
    "api_cred_lib": "[]",           # JSON: [{name, url}]
    # ---- 内置免费源覆盖（面板可 停用/编辑/删除）----
    "builtin_disabled": "",         # 逗号分隔的停用源名
    "builtin_deleted": "",          # 逗号分隔的已删除源名
    "builtin_overrides": "{}",      # JSON: {源名: {url, cap}} 编辑覆盖
    # ---- 外观：主题与语言（前端只读这里，存 localStorage 也行）----
    "theme": "dark",                # dark / light
    "lang": "zh",                   # zh / en
    # ---- 出口健康分 ----
    "health_on": True,              # 计算健康分并参与轮换权重
    "health_min": 20,               # 低于该分数的出口不参与轮换（0=不设下限；全不达标时回退整池）
    "health_window": 200,           # 计算成功率用的最近访问记录条数
    # ---- 自动扩容（池子不够就自己补货）----
    "auto_scale": True,
    "scale_min": 15,                # 有效出口低于这个数就触发扩容
    "scale_batch": 300,             # 单次扩容最多新增多少条原始代理
    "scale_cooldown": 300,          # 两次自动扩容的最小间隔（秒）
    "scale_max_pool": 5000,         # 池内总数上限，到了就不再加
    "empty_heal": True,             # 池空自愈：临时捞回少量失效出口顶上 + 立刻补货
    # ---- DNS 解析策略 ----
    # remote：域名交给上游代理解析（不泄漏本地 DNS，推荐）
    # local ：本地解析成 IP 再连（兼容不认域名的上游）
    # 注意：local 会暴露你查询过哪些域名
    "dns_mode": "remote",
    "dns_server": "1.1.1.1",        # dns_mode=proxy 时用的 DNS（必须是 IP）
    # ---- 入站协议 ----
    "socks4_enabled": True,         # 允许 SOCKS4 / SOCKS4a 客户端连入站端口
    # ---- 多跳上游链（proxy chain）----
    "chain_enabled": False,
    "chain_hops": "",               # 形如 socks5://user:pass@1.2.3.4:1080,socks5://5.6.7.8:1080
    # ---- 出口带宽测速 ----
    "speed_url": "https://speed.cloudflare.com/__down?bytes=2097152",
    "speed_timeout": 20,
    # ---- 机房 IP 判定（在线 ASN 补充；关掉就只用离线库）----
    "ipclass_online": True,
    # ---- 抓取插件目录 ----
    "plugin_enabled": True,
    "plugin_hot_reload": True,
}


# 老库升级：缺哪列补哪列，不重建表、不丢数据
MIGRATIONS = [
    ("proxies", "ok_streak", "INTEGER DEFAULT 0"),
    ("proxies", "fail_streak", "INTEGER DEFAULT 0"),
    ("proxies", "quarantine_until", "REAL DEFAULT 0"),
    ("proxies", "avg_ms", "REAL"),
    ("proxies", "anon", "TEXT DEFAULT ''"),          # elite / anonymous / transparent
    ("proxies", "https_ok", "INTEGER DEFAULT 0"),    # 出口能否 CONNECT https 目标
    ("api_keys", "daily_quota", "INTEGER DEFAULT 0"),
    ("api_keys", "day_calls", "INTEGER DEFAULT 0"),
    ("api_keys", "day_stamp", "TEXT DEFAULT ''"),
    ("proxies", "note", "TEXT DEFAULT ''"),          # 最近一次判定说明（如延迟超限）
    ("proxies", "favorite", "INTEGER DEFAULT 0"),    # 星标收藏，轮换与导出可优先
    ("proxies", "resolved_ip", "TEXT DEFAULT ''"),   # 域名出口最近一次解析到的 IP（一致性检测）
    ("api_sources", "interval", "INTEGER DEFAULT 0"),# 插件级抓取频率（分钟），0=跟随全局
    ("proxies", "real_ip", "TEXT DEFAULT ''"),       # 出口真实 IP（目标实际看到的地址）
    ("proxies", "health", "REAL DEFAULT 0"),         # 出口健康分 0~100（成功率/延迟/稳定性/匿名度）
    ("proxies", "health_ts", "REAL DEFAULT 0"),      # 健康分最近一次计算时间
    ("proxies", "ip_kind", "TEXT DEFAULT ''"),       # dc=机房 / res=住宅 / unk=未知
    ("proxies", "ip_org", "TEXT DEFAULT ''"),        # ASN 组织名（如 DigitalOcean, LLC）
    ("proxies", "speed", "REAL DEFAULT 0"),          # 最近一次实测带宽 KB/s
    ("proxies", "speed_ts", "REAL DEFAULT 0"),       # 测速时间
    ("proxies", "asn", "TEXT DEFAULT ''"),           # AS 号（如 AS14061）
]


MODES = {
    "round_robin": {
        "label": "轮询代理模式", "short": "轮询",
        "desc": "抽取高可用代理，代理无效时自动切换下一个；配合「失效自动切换」「无限模式」使用。",
        "needs": [],
    },
    "by_count": {
        "label": "根据次数更换", "short": "按次数",
        "desc": "每个代理IP使用设定的次数后切换下一个。",
        "needs": ["rotate_count"],
    },
    "by_time": {
        "label": "根据时间切换", "short": "按时间",
        "desc": "设置每隔几分钟更换一次代理。",
        "needs": ["rotate_seconds"],
    },
    "scenario": {
        "label": "根据场景切换", "short": "场景",
        "desc": "配置合适的验证网站后，当验证失败时切换下个代理。该模式会每隔2分钟验证一次代理是否可用。",
        "needs": ["scenario_site"],
    },
    "keyword": {
        "label": "根据关键词", "short": "关键词",
        "desc": "黑名单：目标命中关键词时不走代理（直连）；白名单：只有命中才走代理，其余直连。",
        "needs": ["keyword_list"],
    },
    "exclusive": {
        "label": "固定代理", "short": "固定",
        "desc": "每次固定使用延时最短的代理地址，不切换；也可手工固定到某一条。",
        "needs": [],
    },
    "sticky": {
        "label": "粘性会话", "short": "粘性",
        "desc": "同一客户端访问同一站点时固定同一个出口，TTL 内不变——保登录态、防风控必需。",
        "needs": ["sticky_ttl"],
    },
}
MODE_KEYS = tuple(MODES)


def _now():
    return time.time()


class Store:
    def __init__(self, path=DB_PATH):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False, timeout=15)
        self._conn.row_factory = sqlite3.Row
        self.version = 0                      # 供运行期缓存失效
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA wal_autocheckpoint=256")
            self._migrate()
            self._conn.commit()
            try:
                self._tune_quality()
            except sqlite3.Error:
                pass

    def _migrate(self):
        """给老库补列。SQLite 的 ALTER TABLE 没有 IF NOT EXISTS，只能先查表结构。"""
        for table, col, decl in MIGRATIONS:
            cols = {r["name"] for r in
                    self._conn.execute(f"PRAGMA table_info({table})")}
            if col not in cols:
                try:
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
                except sqlite3.Error:
                    pass

    # ---------------- 设置 ----------------
    def _tune_quality(self):
        """v1.8.1 一次性质量调参（老库升级时执行一次）。

        只调那些还停在上一个默认值上的项，用户自己调过的保持原样；调完写标记，
        以后不再动。想恢复宽松可以随时在设置页改回去。
        """
        cur = self.settings()
        try:
            done = self._conn.execute(
                "SELECT v FROM settings WHERE k='quality_tuned_v181'").fetchone()
        except sqlite3.Error:
            done = None
        if done and str(done["v"]) == "1":
            return
        want = {}
        if int(cur.get("max_delay_ms") or 0) >= 3000:
            want["max_delay_ms"] = 2000        # 3 秒的出口实际体验就是“卡”
        if int(cur.get("health_min") or 0) == 0:
            want["health_min"] = 20            # 低分节点退出轮换（全不达标仍回退整池）
        if not cur.get("precheck_exit"):
            want["precheck_exit"] = True       # 智能预检：只检不新鲜的出口
        if int(cur.get("fast_window_ms") or 0) >= 500:
            want["fast_window_ms"] = 300
        if int(cur.get("fail_ratio") or 0) >= 60:
            want["fail_ratio"] = 50            # 失败占比过半就下场
        if int(cur.get("fail_window") or 0) >= 20:
            want["fail_window"] = 15
        if int(cur.get("revalidate_interval") or 0) >= 600:
            want["revalidate_interval"] = 300
        if int(cur.get("precheck_fresh") or 0) >= 90:
            want["precheck_fresh"] = 60
        if int(cur.get("validate_concurrency") or 0) < 120:
            want["validate_concurrency"] = 160
        if int(cur.get("validate_timeout") or 0) > 5:
            want["validate_timeout"] = 5
        for k, v in want.items():
            self._conn.execute(
                "INSERT INTO settings(k, v) VALUES(?, ?) "
                "ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                (k, "true" if v is True else str(v)))
        self._conn.execute(
            "INSERT INTO settings(k, v) VALUES('quality_tuned_v181', '1') "
            "ON CONFLICT(k) DO UPDATE SET v='1'")
        self._conn.commit()
        self.version += 1

    def settings(self):
        out = dict(DEFAULTS)
        with self._lock:
            for row in self._conn.execute("SELECT k, v FROM settings"):
                out[row["k"]] = row["v"]
        for k, v in DEFAULTS.items():
            if isinstance(v, bool):
                out[k] = str(out.get(k, v)).lower() in ("1", "true", "yes")
            elif isinstance(v, int):
                try:
                    out[k] = int(out[k])
                except (TypeError, ValueError):
                    out[k] = v
        return out

    def save_settings(self, data):
        with self._lock:
            for k, v in data.items():
                if k not in DEFAULTS:
                    continue
                if isinstance(v, bool):
                    v = "true" if v else "false"
                self._conn.execute(
                    "INSERT INTO settings(k, v) VALUES(?, ?) "
                    "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))
            self._conn.commit()
        self.version += 1

    # ---------------- 代理读写 ----------------
    def add_many(self, rows):
        """rows: [{host, port, protocol, username, password, source}]
        返回 (新增条数, 新增的 id 列表)。冲突（同 host+port+protocol）不插入。
        """
        ids = []
        with self._lock:
            for r in rows:
                try:
                    cur = self._conn.execute(
                        "INSERT INTO proxies(host, port, protocol, username, password, source, created_at) "
                        "VALUES(?,?,?,?,?,?,?) ON CONFLICT(host, port, protocol) DO NOTHING "
                        "RETURNING id",
                        (r["host"], int(r["port"]), r.get("protocol", "http"),
                         r.get("username", ""), r.get("password", ""),
                         r.get("source", ""), _now()))
                except sqlite3.Error:
                    continue
                row = cur.fetchone()
                if row:
                    ids.append(row["id"])
            self._conn.commit()
        if ids:
            self.version += 1
        return len(ids), ids

    def get(self, pid):
        with self._lock:
            row = self._conn.execute("SELECT * FROM proxies WHERE id=?", (pid,)).fetchone()
        return dict(row) if row else None

    def find(self, host, port, protocol="http"):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM proxies WHERE host=? AND port=? AND protocol=?",
                (host, int(port), protocol)).fetchone()
        return dict(row) if row else None

    def update(self, pid, fields):
        allowed = {"host", "port", "protocol", "username", "password", "region",
                   "enabled", "is_valid", "delay_ms", "exclusive"}
        sets, vals = [], []
        for k, v in fields.items():
            if k not in allowed:
                continue
            sets.append(f"{k}=?")
            vals.append(int(v) if k in ("enabled", "is_valid") else v)
        if not sets:
            return False
        vals.append(pid)
        with self._lock:
            cur = self._conn.execute(f"UPDATE proxies SET {', '.join(sets)} WHERE id=?", vals)
            self._conn.commit()
        self.version += 1
        return cur.rowcount > 0

    def delete(self, ids):
        if not ids:
            return 0
        marks = ",".join("?" * len(ids))
        with self._lock:
            cur = self._conn.execute(f"DELETE FROM proxies WHERE id IN ({marks})", list(ids))
            self._conn.commit()
        self.version += 1
        return cur.rowcount

    def set_enabled(self, ids, enabled):
        if not ids:
            return 0
        marks = ",".join("?" * len(ids))
        with self._lock:
            cur = self._conn.execute(
                f"UPDATE proxies SET enabled=? WHERE id IN ({marks})",
                [1 if enabled else 0] + list(ids))
            self._conn.commit()
        self.version += 1
        return cur.rowcount

    def set_enabled_all(self, enabled):
        with self._lock:
            cur = self._conn.execute(
                "UPDATE proxies SET enabled=?", (1 if enabled else 0,))
            self._conn.commit()
        self.version += 1
        return cur.rowcount

    def delete_all(self, only_invalid=False):
        """删除所有代理（only_invalid=True 只删失效的）。批量管理弹窗用。"""
        sql = "DELETE FROM proxies" + (" WHERE is_valid=0" if only_invalid else "")
        with self._lock:
            cur = self._conn.execute(sql)
            self._conn.commit()
        self.version += 1
        return cur.rowcount

    def set_result(self, pid, ok, delay_ms=None, invalid_after=3, source="check",
                   quarantine_after=4, quarantine_secs=600, anon=None, https_ok=None,
                   max_delay_ms=0, real_ip=None):
        """记录一次出口结果。

        source="check" 是主动验证：失败够次数就判 is_valid=0，退出候选池；
        source="proxy" 是转发结果：客户端断开、目标超时都会落到这里，只累计
        fail_streak 并做隔离冷却，不直接判死——否则免费池会在几分钟内被误杀干净。

        max_delay_ms 是延迟上限：能通但太慢的出口同样没有使用价值，直接判失效
        并记下原因，免得它一直躺在池子里被反复验证。
        real_ip 是这次测到的出口真实 IP：只在本轮确实拿到时写库（粘性），
        没测到就保留上次的值，一次失败不该把已知的出口 IP 抹掉。
        返回 "ok" / "fail" / "slow"。
        """
        now = _now()
        with self._lock:
            row = self._conn.execute(
                "SELECT delay_ms, avg_ms, fail_streak FROM proxies WHERE id=?",
                (pid,)).fetchone()
            if row is None:
                return "fail"
            if ok and max_delay_ms and delay_ms and delay_ms > max_delay_ms:
                self._conn.execute(
                    "UPDATE proxies SET delay_ms=?, avg_ms=?, is_valid=0, ok_streak=0, "
                    "note=?, last_check=? WHERE id=?",
                    (delay_ms, delay_ms,
                     f"延迟 {int(delay_ms)}ms，超过上限 {int(max_delay_ms)}ms",
                     now, pid))
                self._conn.commit()
                self.version += 1
                return "slow"
            if ok:
                d, a = row["delay_ms"], row["avg_ms"]
                if delay_ms is not None:
                    d = delay_ms if d is None else round(d * 0.6 + delay_ms * 0.4, 1)
                    a = delay_ms if a is None else round(a * 0.8 + delay_ms * 0.2, 1)
                    # 历史延迟很高、这次测下来已经达标的，按这次的结果记，
                    # 否则「有效」列表里会一直挂着超过上限的数字
                    if max_delay_ms and d > max_delay_ms:
                        d = delay_ms
                self._conn.execute(
                    "UPDATE proxies SET is_valid=1, ok_streak=ok_streak+1, fail_streak=0, "
                    "quarantine_until=0, delay_ms=?, avg_ms=?, last_check=?, last_used=?, "
                    "anon=COALESCE(?, anon), https_ok=COALESCE(?, https_ok), "
                    "real_ip=COALESCE(NULLIF(?, ''), real_ip), note='', "
                    "success_count=success_count+1 WHERE id=?",
                    (d, a, now, now, anon, https_ok, str(real_ip or ""), pid))
            else:
                streak = (row["fail_streak"] or 0) + 1
                if source == "check":
                    # 本来就超过延迟上限（不参与轮换）的，验证再失败一次就没
                    # 任何价值了，直接判失效，不用按普通节点等满 3 次
                    over = (max_delay_ms and row["delay_ms"] is not None
                            and row["delay_ms"] > max_delay_ms)
                    self._conn.execute(
                        "UPDATE proxies SET fail_count=fail_count+1, fail_streak=?, "
                        "last_check=?, is_valid=CASE WHEN ?>=? OR ? THEN 0 ELSE is_valid END, "
                        "note=CASE WHEN ? THEN '超限且验证失败，剔除' ELSE note END "
                        "WHERE id=?",
                        (streak, now, streak, max(1, int(invalid_after)),
                         1 if over else 0, 1 if over else 0, pid))
                else:
                    # 升级式隔离：超过隔离线的连续失败每多一次，冷却时长翻倍
                    # （600s → 20min → 40min → …上限 24h），惯犯不再每 10 分钟
                    # 准时复活来污染轮换；真正临时挂掉的节点复活一次就回池
                    mult = min(2 ** max(0, streak - max(1, int(quarantine_after))), 64)
                    until = (now + min(86400, max(30, int(quarantine_secs)) * mult)
                             if streak >= max(1, int(quarantine_after)) else 0)
                    self._conn.execute(
                        "UPDATE proxies SET fail_count=fail_count+1, fail_streak=?, "
                        "last_check=?, quarantine_until=CASE WHEN ?>0 THEN ? "
                        "ELSE quarantine_until END WHERE id=?",
                        (streak, now, until, until, pid))
            self._conn.commit()
        self.version += 1
        return "ok" if ok else "fail"

    def quarantine(self, pid, seconds=600):
        with self._lock:
            self._conn.execute("UPDATE proxies SET quarantine_until=? WHERE id=?",
                               (_now() + max(30, int(seconds)), pid))
            self._conn.commit()
        self.version += 1

    def revive(self, pid):
        with self._lock:
            self._conn.execute(
                "UPDATE proxies SET quarantine_until=0, fail_streak=0, fail_count=0 "
                "WHERE id=?", (pid,))
            self._conn.commit()
        self.version += 1

    def revive_all(self):
        """无限模式：把失效/隔离中的代理全部捞回候选池，重新轮询、无限循环。

        is_valid=0 的也一并复活（含验证判死和超延迟判死的）——无限模式的语义
        就是“池子空了就从头再轮一遍”；真正死的代理会在下次请求时被换掉，
        且验证任务很快会再次给出结论。
        """
        with self._lock:
            n = self._conn.execute(
                "UPDATE proxies SET is_valid=1, quarantine_until=0, fail_streak=0 "
                "WHERE is_valid=0 OR quarantine_until>0 OR fail_streak>0").rowcount
            self._conn.commit()
        self.version += 1
        return n

    def set_region(self, pid, region):
        with self._lock:
            self._conn.execute("UPDATE proxies SET region=? WHERE id=?", (region, pid))
            self._conn.commit()

    def missing_region(self, limit=3000):
        """还没归属地的条目，新的优先。"""
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, host FROM proxies WHERE COALESCE(region,'')='' "
                "ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()
        return [dict(r) for r in rows]

    def set_regions(self, pairs):
        """pairs: [(id, region)] —— 一次事务写完，避免逐条 commit。"""
        if not pairs:
            return 0
        with self._lock:
            self._conn.executemany(
                "UPDATE proxies SET region=? WHERE id=?", [(r, i) for i, r in pairs])
            self._conn.commit()
        self.version += 1
        return len(pairs)

    def touch_used(self, pid):
        with self._lock:
            self._conn.execute("UPDATE proxies SET last_used=? WHERE id=?", (_now(), pid))

    def list(self, status=None, protocol=None, q=None, enabled=None,
             https=False, anon=None, limit=500, offset=0, sort="delay",
             max_delay=None, source=None, favorite=False):
        where, vals = [], []
        if status == "valid":
            where.append("is_valid=1")
        elif status == "invalid":
            where.append("is_valid=0")
        if protocol:
            where.append("protocol=?")
            vals.append(protocol)
        if q:
            where.append("(host LIKE ? OR region LIKE ? OR username LIKE ?)")
            vals += [f"%{q}%"] * 3
        if enabled is not None:
            where.append("enabled=?")
            vals.append(1 if enabled else 0)
        if https:
            where.append("https_ok=1")
        if anon:
            where.append("anon=?")
            vals.append(anon)
        if max_delay:
            where.append("delay_ms IS NOT NULL AND delay_ms<=?")
            vals.append(int(max_delay))
        if source:
            where.append("source=?")
            vals.append(source)
        if favorite:
            where.append("favorite=1")
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        order = {"delay": "CASE WHEN delay_ms IS NULL THEN 1 ELSE 0 END, delay_ms ASC",
                 "new": "id DESC",
                 # 收藏优先：星标的排前面，其余按健康度
                 "fav": "favorite DESC, is_valid DESC, fail_count ASC, "
                        "success_count DESC, "
                        "CASE WHEN delay_ms IS NULL THEN 999999 ELSE delay_ms END ASC",
                 # 健康度：有效优先，再看失败少、成功多、延迟低
                 "health": "is_valid DESC, fail_count ASC, success_count DESC, "
                           "CASE WHEN delay_ms IS NULL THEN 999999 ELSE delay_ms END ASC",
                 }.get(sort, "id ASC")
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM proxies {clause} ORDER BY {order} LIMIT ? OFFSET ?",
                vals + [limit, offset]).fetchall()
            total = self._conn.execute(
                f"SELECT COUNT(*) c FROM proxies {clause}", vals).fetchone()["c"]
        return [dict(r) for r in rows], total

    def candidates(self, max_delay_ms=0, limit=500, dedupe=False):
        """候选出口：有效、启用、不在隔离冷却期，按延迟升序。

        dedupe=True 时同一 (host, protocol) 只保留最快的那一条端口，
        免费池里同一台机器开一整段端口的情况非常多，不去重会反复撞同一出口 IP。
        """
        now = _now()
        sql = ("SELECT * FROM proxies WHERE enabled=1 AND is_valid=1 "
               "AND (quarantine_until IS NULL OR quarantine_until<=?)")
        vals = [now]
        if max_delay_ms:
            sql += " AND (delay_ms IS NULL OR delay_ms<=?)"
            vals.append(max_delay_ms)
        sql += (" ORDER BY CASE WHEN delay_ms IS NULL THEN 1 ELSE 0 END, "
                "delay_ms ASC LIMIT ?")
        vals.append(max(1, int(limit)) * (5 if dedupe else 1))
        with self._lock:
            rows = self._conn.execute(sql, vals).fetchall()
        out = [dict(r) for r in rows]
        if dedupe:
            seen, uniq = set(), []
            for r in out:
                key = (r["host"], r["protocol"])
                if key in seen:
                    continue
                seen.add(key)
                uniq.append(r)
            out = uniq
        return out[:max(1, int(limit))]

    def revive_stale(self, limit=12):
        """池空自愈：只临时捞回「最久没验过」的一小批失效出口，不全量复活。

        全量复活会把几千条死节点塞回候选，既拖慢轮换，又会让扩容误以为池子够用。
        捞一小批够顶上几秒就行，真正能不能用由紧接着的重验证判定。
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT id FROM proxies WHERE enabled=1 AND is_valid=0 "
                "ORDER BY COALESCE(last_check,0) ASC, fail_streak ASC LIMIT ?",
                (max(1, int(limit)),)).fetchall()
            ids = [r["id"] for r in rows]
            if ids:
                self._conn.execute(
                    "UPDATE proxies SET is_valid=1, quarantine_until=0, fail_streak=0 "
                    "WHERE id IN (" + ",".join("?" * len(ids)) + ")", ids)
                self._conn.commit()
        if ids:
            self.version += 1
        return len(ids)

    def stale_rows(self, limit=600, max_delay_ms=0):
        """「最久没验过」的有效出口：定期重验证用。

        以前用 candidates() 取，它按延迟升序——结果每轮都在验最快的那几条，
        慢的、放久了的永远排不上队，池子里就攒着一堆「看起来有效、其实早死了」
        的节点，这正是池子越大越不好用的原因。改成按 last_check 升序轮一遍。
        """
        sql = "SELECT * FROM proxies WHERE enabled=1 AND is_valid=1"
        vals = []
        if max_delay_ms:
            sql += " AND (delay_ms IS NULL OR delay_ms<=?)"
            vals.append(int(max_delay_ms))
        sql += " ORDER BY COALESCE(last_check,0) ASC LIMIT ?"
        vals.append(max(1, int(limit)))
        with self._lock:
            rows = self._conn.execute(sql, vals).fetchall()
        return [dict(r) for r in rows]

    def invalid_rows(self, limit=300):
        """失效但还启用着的出口：池空自愈时用。

        优先挑「最久没验过」的——刚被验死的多半还是死的，冻了很久的反而
        可能已经活了（免费代理池的常态）。排除用户手动停用的。
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM proxies WHERE enabled=1 AND is_valid=0 "
                "ORDER BY COALESCE(last_check,0) ASC, fail_streak ASC LIMIT ?",
                (max(1, int(limit)),)).fetchall()
        return [dict(r) for r in rows]

    def usable_count(self):
        """有效且启用的条数（扩容/自愈判断用，比 stats() 轻）。"""
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) c FROM proxies WHERE enabled=1 AND is_valid=1").fetchone()
        return int(row["c"] or 0)

    def source_stats(self):
        """每个抓取源的贡献：入库总数、当前有效、平均延迟。"""
        with self._lock:
            rows = self._conn.execute(
                "SELECT COALESCE(NULLIF(source,''),'(手动/未知)') src, COUNT(*) total, "
                "SUM(is_valid) valid, AVG(CASE WHEN is_valid=1 THEN delay_ms END) delay "
                "FROM proxies GROUP BY src ORDER BY valid DESC, total DESC").fetchall()
        return [{"source": r["src"], "total": r["total"], "valid": r["valid"] or 0,
                 "delay": round(r["delay"] or 0), "rate": round(
                     (r["valid"] or 0) / r["total"] * 100, 1) if r["total"] else 0}
                for r in rows]

    def quarantined(self, limit=200):
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM proxies WHERE quarantine_until>? "
                "ORDER BY quarantine_until ASC LIMIT ?", (_now(), limit)).fetchall()
        return [dict(r) for r in rows]

    def set_favorite(self, pid, fav):
        with self._lock:
            self._conn.execute(
                "UPDATE proxies SET favorite=? WHERE id=?",
                (1 if fav else 0, pid))
            self._conn.commit()
        self.version += 1

    def sources_distinct(self):
        """池里出现过的入库来源，给来源筛选下拉用。"""
        with self._lock:
            rows = self._conn.execute(
                "SELECT DISTINCT source FROM proxies WHERE source<>'' "
                "ORDER BY source").fetchall()
        return [r["source"] for r in rows]

    def stats(self):
        with self._lock:
            c = self._conn.execute(
                "SELECT COUNT(*) total, SUM(is_valid) valid, SUM(enabled) enabled, "
                "SUM(CASE WHEN quarantine_until>? THEN 1 ELSE 0 END) quarantined, "
                "AVG(CASE WHEN is_valid=1 THEN delay_ms END) avg_delay FROM proxies",
                (_now(),)).fetchone()
            protos = {r["protocol"]: r["c"] for r in self._conn.execute(
                "SELECT protocol, COUNT(*) c FROM proxies GROUP BY protocol")}
            extra = self._conn.execute(
                "SELECT SUM(CASE WHEN is_valid=1 AND https_ok=1 THEN 1 ELSE 0 END) https_ok, "
                "SUM(CASE WHEN is_valid=1 AND anon='elite' THEN 1 ELSE 0 END) elite, "
                "SUM(CASE WHEN is_valid=1 AND anon='anonymous' THEN 1 ELSE 0 END) anon, "
                "SUM(favorite) fav "
                "FROM proxies").fetchone()
            used = self._conn.execute(
                "SELECT SUM(success_count) s, SUM(fail_count) f FROM proxies").fetchone()
            # 分布图按国家聚合（标签是「国家-省-市」，按整串分组会碎成两三条一组）
            regions = [(r["country"] or "未知", r["c"]) for r in self._conn.execute(
                "SELECT substr(region,1,instr(region||'-','-')-1) country, COUNT(*) c "
                "FROM proxies WHERE is_valid=1 GROUP BY country ORDER BY c DESC LIMIT 8")]
        total = c["total"] or 0
        return {
            "total": total,
            "valid": c["valid"] or 0,
            "enabled": c["enabled"] or 0,
            "quarantined": c["quarantined"] or 0,
            "avg_delay": round(c["avg_delay"] or 0),
            "protocols": protos,
            "regions": regions,
            "https_ok": extra["https_ok"] or 0,
            "elite": extra["elite"] or 0,
            "anonymous": extra["anon"] or 0,
            "favorites": extra["fav"] or 0,
            # 出口实战成功率 = 转发成功次数 / (成功+失败)，比"有效率"更接近真实体验
            "success_rate": round(
                (used["s"] or 0) * 100.0 / max(1, (used["s"] or 0) + (used["f"] or 0)), 1),
        }

    def count_invalid(self):
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) c FROM proxies WHERE is_valid=0").fetchone()["c"]

    def cleanup(self, max_delay_ms=0, only_repeated=True):
        """清理失效条目。

        only_repeated=True（默认）只删连续判死 3 次以上的，避免把刚失败
        一两次、可能只是网络抖动的节点误删光；
        only_repeated=False 才是删掉全部失效，需要调用方明确指定。
        """
        sql = "DELETE FROM proxies WHERE is_valid=0"
        if only_repeated:
            sql += " AND fail_count>=3"
        vals = []
        if max_delay_ms:
            sql += " OR (delay_ms>?)"
            vals.append(max_delay_ms)
        with self._lock:
            cur = self._conn.execute(sql, vals)
            self._conn.commit()
        self.version += 1
        return cur.rowcount

    def purge_never_worked(self, hours=4, limit=5000):
        """删掉从来没成功过一次、且最后一次验证已过去 N 小时的条目。

        免费池每次抓取都是几千条候选，绝大多数一次都连不上。它们会以
        is_valid=0 / fail_count=1 的身份永远躺在库里——cleanup() 只删
        fail_count>=3 的，于是一天下來库能涨到上万条死数据：统计被稀释、
        自动扩容判断失真、备份也变大。这里按「从没成功过 + 已经放了几小时」
        直接清掉，跟无影的「删除无效代理」是一个意思。
        """
        cutoff = time.time() - max(1, int(hours)) * 3600
        sql = ("DELETE FROM proxies WHERE id IN (SELECT id FROM proxies "
               "WHERE is_valid=0 AND success_count=0 AND fail_count>=1 "
               "AND COALESCE(last_check, created_at, 0)<? LIMIT ?)")
        with self._lock:
            cur = self._conn.execute(sql, (cutoff, max(1, int(limit))))
            self._conn.commit()
        if cur.rowcount:
            self.version += 1
        return cur.rowcount

    # 常见代理端口：就算历史样本一次没成功，也不能进黑名单——这些端口上
    # 真代理很多，0 成功更可能是「样本本身都是公开清单里的死节点」造成的。
    COMMON_PROXY_PORTS = {
        22, 53, 80, 443, 1080, 1081, 1087, 3128, 3129, 4145, 7070, 8000, 8001,
        8008, 8080, 8081, 8085, 8118, 8888, 8889, 9000, 9090, 9999,
        10808, 10809, 10811, 7890, 7891, 7892, 3000, 5000, 6000,
    }

    def dead_ports(self, min_samples=150, limit=30):
        """返回「样本足够多、却一次都没成功过」的非主流端口集合。

        Quake / FOFA 这类测绘数据里，很多端口是批量部署的假代理（6363、49667、
        9444 这类），一次都连不通，却占掉几百个验证名额。命中率数据本来就在库里，
        直接拿来做黑名单。但 80 / 443 / 8080 这些常见代理端口不参与判断——
        它们 0 成功通常是因为历史样本来自公开清单（几乎全是死的），而不是端口本身有问题。
        """
        sql = ("SELECT port, COUNT(*) n, SUM(CASE WHEN is_valid=1 THEN 1 ELSE 0 END) ok "
               "FROM proxies GROUP BY port HAVING n>=? AND ok=0 ORDER BY n DESC LIMIT ?")
        with self._lock:
            rows = self._conn.execute(sql, (max(10, int(min_samples)),
                                            max(1, int(limit)))).fetchall()
        return {int(r["port"]) for r in rows
                if r["port"] and int(r["port"]) not in self.COMMON_PROXY_PORTS}

    def purge_slow(self, max_delay_ms=0, only_marked=False):
        """删掉超过延迟上限的条目（能通也不留，太慢没有使用价值）。

        only_marked=True 只删「刚刚验证判定超限」的条目，避免拿很久以前的
        旧延迟数字直接删库——那种情况先重测，再按新结果处理。
        """
        if not max_delay_ms:
            return 0
        sql = ("DELETE FROM proxies WHERE (delay_ms IS NOT NULL AND delay_ms>?)")
        vals = [int(max_delay_ms)]
        if only_marked:
            sql += " AND is_valid=0 AND note LIKE '延迟%'"
        with self._lock:
            cur = self._conn.execute(sql, vals)
            self._conn.commit()
        if cur.rowcount:
            self.version += 1
        return cur.rowcount

    def count_slow(self, max_delay_ms=0):
        """当前池里超过延迟上限的条数，用于面板提示。"""
        if not max_delay_ms:
            return 0
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) c FROM proxies WHERE delay_ms IS NOT NULL AND delay_ms>?",
                (int(max_delay_ms),)).fetchone()["c"]

    # ---------------- 用户 ----------------
    def user_count(self):
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]

    def get_user(self, username):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(row) if row else None

    def get_user_by_id(self, uid):
        with self._lock:
            row = self._conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        return dict(row) if row else None

    def create_user(self, username, pwd_hash, salt, role="admin"):
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO users(username, pwd_hash, salt, role, created_at) "
                    "VALUES(?,?,?,?,?)", (username, pwd_hash, salt, role, _now()))
                self._conn.commit()
            except sqlite3.IntegrityError:
                return False
        self.version += 1
        return True

    def set_password(self, username, pwd_hash, salt):
        with self._lock:
            cur = self._conn.execute(
                "UPDATE users SET pwd_hash=?, salt=? WHERE username=?",
                (pwd_hash, salt, username))
            self._conn.commit()
        self.version += 1
        return cur.rowcount > 0

    def touch_login(self, username):
        with self._lock:
            self._conn.execute("UPDATE users SET last_login=? WHERE username=?",
                               (_now(), username))
            self._conn.commit()

    def list_users(self):
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, username, role, created_at, last_login FROM users").fetchall()
        return [dict(r) for r in rows]

    # ---------------- 代理端口账号（入站认证，可多用户） ----------------
    def list_proxy_users(self, with_pwd=False):
        """入站认证账号表。默认不带密码，面板要显示/复制时再单独取。"""
        cols = "id, username, note, enabled, created_at, last_used, hits"
        if with_pwd:
            cols += ", password"
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {cols} FROM proxy_users ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    def proxy_creds(self):
        """{用户名: 密码}，只含启用的账号；代理服务按这个表校验。"""
        with self._lock:
            rows = self._conn.execute(
                "SELECT username, password FROM proxy_users WHERE enabled=1").fetchall()
        return {r["username"]: r["password"] for r in rows}

    def get_proxy_user(self, uid):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM proxy_users WHERE id=?", (uid,)).fetchone()
        return dict(row) if row else None

    def get_proxy_user_by_name(self, username):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM proxy_users WHERE username=?", (username,)).fetchone()
        return dict(row) if row else None

    def add_proxy_user(self, username, password, note="", enabled=True):
        with self._lock:
            try:
                cur = self._conn.execute(
                    "INSERT INTO proxy_users(username, password, note, enabled, created_at) "
                    "VALUES(?,?,?,?,?)",
                    (username, password, note, 1 if enabled else 0, _now()))
                self._conn.commit()
            except sqlite3.IntegrityError:
                return 0
        return cur.lastrowid

    def update_proxy_user(self, uid, password=None, note=None, enabled=None):
        sets, vals = [], []
        if password is not None:
            sets.append("password=?")
            vals.append(password)
        if note is not None:
            sets.append("note=?")
            vals.append(note)
        if enabled is not None:
            sets.append("enabled=?")
            vals.append(1 if enabled else 0)
        if not sets:
            return False
        vals.append(uid)
        with self._lock:
            cur = self._conn.execute(
                f"UPDATE proxy_users SET {', '.join(sets)} WHERE id=?", vals)
            self._conn.commit()
        return cur.rowcount > 0

    def delete_proxy_user(self, uid):
        with self._lock:
            cur = self._conn.execute("DELETE FROM proxy_users WHERE id=?", (uid,))
            self._conn.commit()
        return cur.rowcount > 0

    def touch_proxy_users(self, stats):
        """stats: {用户名: (新增次数, 最近使用时间)}，批量累加，避免每请求写库。"""
        if not stats:
            return 0
        with self._lock:
            for name, (hits, last) in stats.items():
                self._conn.execute(
                    "UPDATE proxy_users SET hits=hits+?, last_used=MAX(last_used,?) "
                    "WHERE username=?", (int(hits), float(last), name))
            self._conn.commit()
        return len(stats)

    def count_proxy_users(self, enabled_only=True):
        sql = "SELECT COUNT(*) FROM proxy_users"
        if enabled_only:
            sql += " WHERE enabled=1"
        with self._lock:
            return self._conn.execute(sql).fetchone()[0]

    def migrate_proxy_auth(self):
        """把老的单账号设置（auth_username/auth_password）迁进账号表。

        只在账号表为空、且老设置里两样都有时迁一次；迁完把老字段清空，
        免得面板显示一个「已设置但不生效」的密码。
        """
        s = self.settings()
        name = str(s.get("auth_username") or "").strip()
        pwd = str(s.get("auth_password") or "")
        if not name or not pwd:
            return 0
        if self.count_proxy_users(enabled_only=False):
            return 0
        uid = self.add_proxy_user(name, pwd, note="从旧版单账号设置迁移")
        if uid:
            self.save_settings({"auth_username": "", "auth_password": ""})
            log.info("入站认证：旧单账号 %s 已迁移到多用户表", name)
        return 1

    # ---------------- 自定义抓取源（GitHub / 空间测绘 API） ----------------
    API_FIELDS = ("name", "provider", "target", "query", "protocol",
                  "creds", "cap", "enabled", "interval")

    def api_sources(self, enabled_only=False):
        sql = "SELECT * FROM api_sources"
        if enabled_only:
            sql += " WHERE enabled=1"
        sql += " ORDER BY id"
        with self._lock:
            rows = self._conn.execute(sql).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["creds"] = json.loads(d.get("creds") or "{}")
            except (TypeError, ValueError):
                d["creds"] = {}
            out.append(d)
        return out

    def get_api_source(self, sid):
        with self._lock:
            row = self._conn.execute("SELECT * FROM api_sources WHERE id=?", (sid,)).fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["creds"] = json.loads(d.get("creds") or "{}")
        except (TypeError, ValueError):
            d["creds"] = {}
        return d

    def add_api_source(self, d):
        creds = d.get("creds")
        if not isinstance(creds, str):
            creds = json.dumps(creds or {}, ensure_ascii=False)
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO api_sources(name, provider, target, query, protocol,"
                " creds, cap, enabled, created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                ((d.get("name") or "未命名").strip(), (d.get("provider") or "github").strip(),
                 (d.get("target") or "").strip(), (d.get("query") or "").strip(),
                 (d.get("protocol") or "http").strip(), creds,
                 max(1, min(int(d.get("cap") or 300), 20000)),
                 1 if d.get("enabled", True) else 0, _now()))
            self._conn.commit()
            sid = cur.lastrowid
        self.version += 1
        return sid

    def update_api_source(self, sid, d):
        sets, vals = [], []
        for k in self.API_FIELDS:
            if k not in d:
                continue
            v = d[k]
            if k == "creds":
                v = v if isinstance(v, str) else json.dumps(v or {}, ensure_ascii=False)
            if k == "cap":
                v = max(1, min(int(v or 300), 20000))
            if k == "enabled":
                v = 1 if v else 0
            if k == "interval":
                v = max(0, min(int(v or 0), 10080))
            if k in ("name", "provider", "target", "query", "protocol") and isinstance(v, str):
                v = v.strip()
            sets.append(f"{k}=?")
            vals.append(v)
        if not sets:
            return 0
        vals.append(sid)
        with self._lock:
            cur = self._conn.execute(
                f"UPDATE api_sources SET {', '.join(sets)} WHERE id=?", vals)
            self._conn.commit()
        self.version += 1
        return cur.rowcount

    def delete_api_source(self, sid):
        with self._lock:
            cur = self._conn.execute("DELETE FROM api_sources WHERE id=?", (sid,))
            self._conn.commit()
        self.version += 1
        return cur.rowcount

    def touch_api_source(self, sid, count=None, error=None):
        if count is None and error is None:
            return
        sets, vals = ["last_run=?"], [_now()]
        if count is not None:
            sets.append("last_count=?")
            vals.append(int(count))
        if error is not None:
            sets.append("last_error=?")
            vals.append(str(error)[:200])
        vals.append(sid)
        with self._lock:
            self._conn.execute(f"UPDATE api_sources SET {', '.join(sets)} WHERE id=?", vals)
            self._conn.commit()

    # ---------------- API Key ----------------
    def list_keys(self):
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM api_keys ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    def get_key(self, kid):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM api_keys WHERE id=?", (int(kid),)).fetchone()
        return dict(row) if row else None

    def add_key(self, name, key, quota=0):
        with self._lock:
            self._conn.execute(
                "INSERT INTO api_keys(name, key, created_at, daily_quota) VALUES(?,?,?,?)",
                (name or "未命名", key, _now(), max(0, int(quota or 0))))
            self._conn.commit()
        self.version += 1

    def set_key_quota(self, kid, quota):
        with self._lock:
            cur = self._conn.execute(
                "UPDATE api_keys SET daily_quota=? WHERE id=?",
                (max(0, int(quota or 0)), kid))
            self._conn.commit()
        self.version += 1
        return cur.rowcount

    def delete_key(self, kid):
        with self._lock:
            cur = self._conn.execute("DELETE FROM api_keys WHERE id=?", (kid,))
            self._conn.commit()
        self.version += 1
        return cur.rowcount

    def set_key_enabled(self, kid, enabled):
        with self._lock:
            cur = self._conn.execute("UPDATE api_keys SET enabled=? WHERE id=?",
                                     (1 if enabled else 0, kid))
            self._conn.commit()
        self.version += 1
        return cur.rowcount

    def key_by_value(self, key):
        with self._lock:
            row = self._conn.execute("SELECT * FROM api_keys WHERE key=?", (key,)).fetchone()
        return dict(row) if row else None

    def get_key(self, kid):
        with self._lock:
            row = self._conn.execute("SELECT * FROM api_keys WHERE id=?", (kid,)).fetchone()
        return dict(row) if row else None

    def touch_key(self, kid):
        with self._lock:
            self._conn.execute(
                "UPDATE api_keys SET last_used=?, calls=calls+1 WHERE id=?", (_now(), kid))
            self._conn.commit()

    def key_consume(self, kid, quota=0):
        """消耗一次配额，返回 (是否放行, 今日已用)。quota<=0 表示不限额。"""
        today = time.strftime("%Y-%m-%d")
        with self._lock:
            row = self._conn.execute(
                "SELECT day_stamp, day_calls FROM api_keys WHERE id=?", (kid,)).fetchone()
            if row is None:
                return True, 0
            used = 0 if row["day_stamp"] != today else (row["day_calls"] or 0)
            if quota and used >= int(quota):
                self._conn.execute(
                    "UPDATE api_keys SET day_stamp=?, day_calls=? WHERE id=?",
                    (today, used, kid))
                self._conn.commit()
                return False, used
            used += 1
            self._conn.execute(
                "UPDATE api_keys SET day_stamp=?, day_calls=?, last_used=?, "
                "calls=calls+1 WHERE id=?", (today, used, _now(), kid))
            self._conn.commit()
        return True, used

    # ---------------- 访问日志 ----------------
    def add_logs(self, rows):
        if not rows:
            return 0
        with self._lock:
            self._conn.executemany(
                "INSERT INTO access_log(ts, client, proto, target, exit_proto, exit_host, "
                "exit_port, ok, ms, nbytes, note) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                [(r.get("ts"), r.get("client", ""), r.get("proto", ""), r.get("target", ""),
                  r.get("exit_proto", ""), r.get("exit_host", ""), r.get("exit_port") or 0,
                  1 if r.get("ok") else 0, r.get("ms") or 0, r.get("nbytes") or 0,
                  r.get("note", "")) for r in rows])
            self._conn.commit()
        return len(rows)

    def trim_logs(self, max_rows):
        """访问记录条数上限：超出自动删最老的，防止库无限膨胀。"""
        if not max_rows or int(max_rows) <= 0:
            return 0
        with self._lock:
            n = self._conn.execute("SELECT COUNT(*) c FROM access_log").fetchone()["c"]
            if n <= int(max_rows):
                return 0
            cutoff = self._conn.execute(
                "SELECT ts FROM access_log ORDER BY id DESC LIMIT 1 OFFSET ?",
                (int(max_rows),)).fetchone()
            if not cutoff or not cutoff["ts"]:
                return 0
            deleted = self._conn.execute(
                "DELETE FROM access_log WHERE ts<=?", (cutoff["ts"],)).rowcount
            self._conn.commit()
        return deleted

    def bump_domains(self, rows):
        """域名统计（照 ProxyCat）：按批次聚合入库，host 从 target 里拆出来。"""
        agg = {}
        now = _now()
        for r in rows:
            target = str(r.get("target") or "")
            host = target.rsplit(":", 1)[0].strip().lower() if ":" in target else target.strip().lower()
            if not host or " " in host or len(host) > 200:
                continue
            a = agg.setdefault(host, [0, 0, 0])
            a[0] += 1
            a[1] += 1 if r.get("ok") else 0
            a[2] += r.get("nbytes") or 0
        if not agg:
            return 0
        with self._lock:
            for host, (hits, ok, nb) in agg.items():
                self._conn.execute(
                    "INSERT INTO domain_stat(domain, hits, ok, nbytes, last_ts) "
                    "VALUES(?,?,?,?,?) ON CONFLICT(domain) DO UPDATE SET "
                    "hits=hits+excluded.hits, ok=ok+excluded.ok, "
                    "nbytes=nbytes+excluded.nbytes, last_ts=excluded.last_ts",
                    (host, hits, ok, nb, now))
            self._conn.commit()
        return len(agg)

    def domain_stats(self, limit=50, q=None):
        where, vals = [], []
        if q:
            where.append("domain LIKE ?")
            vals.append(f"%{q}%")
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM domain_stat {clause} ORDER BY hits DESC LIMIT ?",
                vals + [max(1, min(int(limit), 500))]).fetchall()
            total = self._conn.execute("SELECT COUNT(*) c FROM domain_stat").fetchone()["c"]
        return [dict(r) for r in rows], total

    def prune_domains(self, days=30):
        cutoff = _now() - max(1, int(days)) * 86400
        with self._lock:
            cur = self._conn.execute("DELETE FROM domain_stat WHERE last_ts<?", (cutoff,))
            self._conn.commit()
        return cur.rowcount

    def clear_domains(self):
        with self._lock:
            cur = self._conn.execute("DELETE FROM domain_stat")
            self._conn.commit()
        return cur.rowcount

    def exit_speeds(self):
        """按出口聚合近 2000 条访问记录的真实速率（KB/s）与成功率，池页「速率」列用。

        只用有字节数且耗时>0 的样本，避免 0 字节失败请求把速率拉成 0。
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT exit_host, exit_port, SUM(nbytes) nb, SUM(ms) ms, "
                "COUNT(*) c, SUM(ok) ok FROM access_log "
                "WHERE exit_host<>'' AND nbytes>0 AND ms>0 "
                "GROUP BY exit_host, exit_port ORDER BY rowid DESC LIMIT 2000").fetchall()
        out = {}
        for r in rows:
            kb = (r["nb"] or 0) / 1024.0
            sec = (r["ms"] or 1) / 1000.0
            out[f"{r['exit_host']}:{r['exit_port']}"] = {
                "speed": round(kb / sec, 1),
                "ok_rate": round((r["ok"] or 0) * 100.0 / max(1, r["c"]), 0)}
        return out

    def health_scores(self, window=200, apply=False):
        """出口健康分 0~100：成功率 50 + 延迟 25 + 连续成功 10 + 匿名度 10 + HTTPS 5。

        只统计最近 window 条访问记录（默认 200），避免老数据把新故障稀释掉。
        没有样本的新出口给 55 分中性值——不能让它凭空白压老出口，也不能一进来就被淘汰。
        """
        out = {}
        with self._lock:
            stats = {}
            try:
                rows = self._conn.execute(
                    "SELECT exit_host, exit_port, COUNT(*) c, SUM(ok) ok, "
                    "AVG(CASE WHEN ok=1 AND ms>0 THEN ms END) ams FROM ("
                    "  SELECT exit_host, exit_port, ok, ms FROM access_log "
                    "  WHERE exit_host<>'' ORDER BY id DESC LIMIT ?"
                    ") GROUP BY exit_host, exit_port", (max(20, int(window)),)).fetchall()
                for r in rows:
                    stats[f"{r['exit_host']}:{r['exit_port']}"] = (
                        r["c"] or 0, r["ok"] or 0, r["ams"])
            except sqlite3.Error:
                stats = {}
            rows = self._conn.execute(
                "SELECT id, host, port, success_count, fail_count, ok_streak, fail_streak,"
                " avg_ms, anon, https_ok, delay_ms, is_valid FROM proxies").fetchall()
        for r in rows:
            key = f"{r['host']}:{r['port']}"
            c, ok, ams = stats.get(key, (0, 0, None))
            ms = ams or r["avg_ms"] or r["delay_ms"] or 0
            if c >= 3:
                sr = ok / float(c)
            else:
                sc = (r["success_count"] or 0) + (r["fail_count"] or 0)
                sr = ((r["success_count"] or 0) / float(sc)) if sc else 0.6
            score = 50.0 * sr
            if ms:
                if ms <= 300:
                    score += 25
                elif ms <= 800:
                    score += 20
                elif ms <= 1500:
                    score += 12
                elif ms <= 3000:
                    score += 5
            else:
                score += 10                      # 没测过延迟，给中间值
            score += min(10, (r["ok_streak"] or 0) * 2)
            score -= min(25, (r["fail_streak"] or 0) * 5)
            anon = str(r["anon"] or "").lower()
            score += 10 if anon == "elite" else (7 if anon == "anonymous" else 0)
            score += 5 if r["https_ok"] else 0
            if not r["is_valid"]:
                score = min(score, 20)           # 已知失效的出口压在低位，别抢轮换
            out[int(r["id"])] = round(max(0.0, min(100.0, score)), 1)
        if apply and out:
            now = _now()
            with self._lock:
                self._conn.executemany(
                    "UPDATE proxies SET health=?, health_ts=? WHERE id=?",
                    [(v, now, k) for k, v in out.items()])
                self._conn.commit()
        return out

    def set_ip_class(self, pid, kind, org="", asn=""):
        with self._lock:
            self._conn.execute(
                "UPDATE proxies SET ip_kind=?, ip_org=?, asn=? WHERE id=?",
                (str(kind or ""), str(org or "")[:120], str(asn or "")[:40], int(pid)))
            self._conn.commit()

    def set_ip_classes(self, pairs):
        """pairs: [(pid, kind, org, asn)]"""
        with self._lock:
            self._conn.executemany(
                "UPDATE proxies SET ip_kind=?, ip_org=?, asn=? WHERE id=?",
                [(str(k or ""), str(o or "")[:120], str(a or "")[:40], int(p))
                 for p, k, o, a in pairs])
            self._conn.commit()

    def needs_ip_class(self, limit=200):
        with self._lock:
            return [dict(r) for r in self._conn.execute(
                "SELECT id, host, port, real_ip, region FROM proxies "
                "WHERE ip_kind='' OR ip_kind IS NULL LIMIT ?", (int(limit),))]

    def set_speed(self, pid, kbps):
        with self._lock:
            self._conn.execute(
                "UPDATE proxies SET speed=?, speed_ts=? WHERE id=?",
                (float(kbps or 0), _now(), int(pid)))
            self._conn.commit()

    def ip_kind_stats(self):
        with self._lock:
            rows = self._conn.execute(
                "SELECT COALESCE(NULLIF(ip_kind,''),'unk') k, COUNT(*) c FROM proxies "
                "WHERE is_valid=1 GROUP BY k").fetchall()
        out = {"dc": 0, "res": 0, "unk": 0}
        for r in rows:
            out[r["k"] or "unk"] = r["c"]
        return out

    def logs(self, limit=100, offset=0, ok=None, proto=None, q=None, since=None):
        where, vals = [], []
        if ok in (0, 1):
            where.append("ok=?")
            vals.append(ok)
        if proto:
            where.append("proto=?")
            vals.append(proto)
        if since:
            where.append("ts>=?")
            vals.append(float(since))
        if q:
            where.append("(target LIKE ? OR exit_host LIKE ? OR note LIKE ?)")
            vals += [f"%{q}%"] * 3
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM access_log {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
                vals + [limit, offset]).fetchall()
            total = self._conn.execute(
                f"SELECT COUNT(*) c FROM access_log {clause}", vals).fetchone()["c"]
        return [dict(r) for r in rows], total

    def log_series(self, minutes=60):
        """按分钟聚合：[{ts, total, ok, avg_ms}]，用于趋势图。"""
        since = _now() - minutes * 60
        with self._lock:
            rows = self._conn.execute(
                "SELECT CAST(ts/60 AS INTEGER)*60 AS m, COUNT(*) total, "
                "SUM(ok) ok, AVG(ms) avg_ms FROM access_log WHERE ts>=? "
                "GROUP BY m ORDER BY m", (since,)).fetchall()
        buckets = {int(r["m"]): (r["total"], r["ok"], r["avg_ms"]) for r in rows}
        out, now_m = [], int(_now() // 60 * 60)
        for m in range(now_m - (minutes - 1) * 60, now_m + 60, 60):
            total, good, avg = buckets.get(m, (0, 0, None))
            out.append({"ts": m, "total": total, "ok": good or 0,
                        "avg_ms": round(avg or 0)})
        return out

    def log_summary(self, minutes=60):
        since = _now() - minutes * 60
        with self._lock:
            r = self._conn.execute(
                "SELECT COUNT(*) total, SUM(ok) ok, AVG(ms) avg_ms, SUM(nbytes) bytes "
                "FROM access_log WHERE ts>=?", (since,)).fetchone()
            top = self._conn.execute(
                "SELECT exit_host, exit_port, COUNT(*) c FROM access_log "
                "WHERE ts>=? AND ok=1 AND exit_host<>'' GROUP BY exit_host, exit_port "
                "ORDER BY c DESC LIMIT 5", (since,)).fetchall()
        total = r["total"] or 0
        return {
            "total": total,
            "ok": r["ok"] or 0,
            "fail": total - (r["ok"] or 0),
            "rate": round((r["ok"] or 0) / total * 100, 1) if total else 0,
            "avg_ms": round(r["avg_ms"] or 0),
            "bytes": r["bytes"] or 0,
            "top_exits": [(f"{x['exit_host']}:{x['exit_port']}", x["c"]) for x in top],
        }

    def prune_logs(self, days=7):
        cutoff = _now() - max(1, int(days)) * 86400
        with self._lock:
            cur = self._conn.execute("DELETE FROM access_log WHERE ts<?", (cutoff,))
            self._conn.commit()
        return cur.rowcount

    def clear_logs(self):
        with self._lock:
            cur = self._conn.execute("DELETE FROM access_log")
            self._conn.commit()
        return cur.rowcount

    # ---------------- 对外取用 ----------------
    def sub_list(self, protocol=None, https_only=False, max_delay=0, limit=2000):
        """订阅导出：返回有效出口的 URI 列表（http://host:port / socks5://...）。"""
        sql = ("SELECT host, port, protocol, delay_ms FROM proxies "
               "WHERE enabled=1 AND is_valid=1 "
               "AND (quarantine_until IS NULL OR quarantine_until<=?)")
        vals = [_now()]
        if protocol:
            sql += " AND protocol=?"
            vals.append(protocol)
        if https_only:
            sql += " AND https_ok=1"
        if max_delay:
            sql += " AND (delay_ms IS NULL OR delay_ms<=?)"
            vals.append(int(max_delay))
        sql += (" ORDER BY CASE WHEN delay_ms IS NULL THEN 1 ELSE 0 END, "
                "delay_ms ASC LIMIT ?")
        vals.append(max(1, min(int(limit), 5000)))
        with self._lock:
            rows = self._conn.execute(sql, vals).fetchall()
        return [f"{r['protocol']}://{r['host']}:{r['port']}" for r in rows]

    def pick_public(self, count=1, protocol=None, max_delay=0, region=None):
        sql = ("SELECT * FROM proxies WHERE enabled=1 AND is_valid=1 "
               "AND (quarantine_until IS NULL OR quarantine_until<=?)")
        vals = [_now()]
        if protocol:
            sql += " AND protocol=?"
            vals.append(protocol)
        if max_delay:
            sql += " AND (delay_ms IS NULL OR delay_ms<=?)"
            vals.append(int(max_delay))
        if region:
            sql += " AND region LIKE ?"
            vals.append(f"%{region}%")
        sql += (" ORDER BY RANDOM() LIMIT ?")
        vals.append(max(1, min(int(count), 200)))
        with self._lock:
            rows = self._conn.execute(sql, vals).fetchall()
        return [dict(r) for r in rows]

    # ---------------- 维护 ----------------
    def restore(self, src_path):
        """从备份文件恢复数据库（在线恢复：备份 -> 当前连接，不重启进程）。

        恢复后所有缓存凭 version 失效，调用方记得 reset_rotation。
        """
        if not os.path.exists(src_path):
            raise FileNotFoundError(src_path)
        with self._lock:
            src = sqlite3.connect(src_path)
            try:
                src.backup(self._conn)
            finally:
                src.close()
            self._conn.commit()
        self.version += 1

    def domain_hosts(self, limit=500):
        """host 是域名（不是 IP）的出口，解析一致性检测用。"""
        import re as _re
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, host FROM proxies WHERE is_valid=1 LIMIT ?",
                (max(1, int(limit)),)).fetchall()
        pat = _re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        return [{"id": r["id"], "host": r["host"]}
                for r in rows if r["host"] and not pat.match(r["host"])]

    def set_resolved(self, pairs):
        """pairs: [(id, ip)] 记录域名出口最近一次解析结果；IP 为空则清掉标记。"""
        if not pairs:
            return 0
        with self._lock:
            self._conn.executemany(
                "UPDATE proxies SET resolved_ip=? WHERE id=?",
                [(ip, pid) for pid, ip in pairs])
            self._conn.commit()
        return len(pairs)

    def resolved_mismatches(self):
        """解析一致性候选：域名出口 + 已记录的解析结果（是否真的变了由检测端比对）。"""
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, host, port, protocol, resolved_ip FROM proxies "
                "WHERE is_valid=1 AND COALESCE(resolved_ip,'')<>'' LIMIT 500").fetchall()
        return [dict(r) for r in rows]

    def file_sizes(self):
        out = {}
        for name in ("proxydog.db", "proxydog.db-wal", "proxydog.db-shm"):
            p = os.path.join(DATA_DIR, name)
            out[name] = os.path.getsize(p) if os.path.exists(p) else 0
        return out

    def counts(self):
        with self._lock:
            out = {}
            for t in ("proxies", "access_log", "api_keys", "users"):
                out[t] = self._conn.execute(f"SELECT COUNT(*) c FROM {t}").fetchone()["c"]
        return out

    def backup(self, dest_dir):
        os.makedirs(dest_dir, exist_ok=True)
        name = time.strftime("proxydog-%Y%m%d-%H%M%S.db")
        dest = os.path.join(dest_dir, name)
        with self._lock:
            target = sqlite3.connect(dest)
            try:
                self._conn.backup(target)
            finally:
                target.close()
        return dest

    def vacuum(self):
        with self._lock:
            self._conn.execute("VACUUM")
            self._conn.commit()
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._conn.commit()

    def checkpoint(self):
        with self._lock:
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._conn.commit()

    def close(self):
        with self._lock:
            try:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                self._conn.commit()
            except Exception:
                pass
            self._conn.close()
