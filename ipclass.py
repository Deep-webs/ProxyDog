"""出口 IP 类型判定：住宅 IP / 数据中心 IP。

为什么需要：住宅出口在风控眼里天然比机房出口"干净"，同一个池子里混着
AWS 段和家宽带，用户挑出口时得能一眼分出来。

判定策略（离线优先，联网补充）：
1. 内置机房关键词表：把 ISP / ORG / AS 名称里出现 cloud、hosting、server 的归为机房；
   国内三大运营商、Comcast 这类家宽关键词归为住宅。
2. 内置云厂商 CIDR 段：AWS / GCP / Azure / DO / Vultr / Hetzner / OVH / 阿里云 / 腾讯云
   等高频段，命中即机房（离线也能用，不依赖网络）。
3. 在线兜底：ip-api.com 查 ASN/ISP/ORG（结果落盘缓存 7 天），
   只在离线判不出来时才发请求，避免每条代理都联网。
"""

import ipaddress
import json
import re
import os
import threading
import time
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CACHE_PATH = os.path.join(BASE_DIR, "data", "ipclass_cache.json")
CACHE_TTL = 7 * 86400

# ---- 机房关键词：命中即"数据中心"，权重最高的那一类 ----
DC_KEYWORDS = [
    "amazon", "aws", "google", "microsoft", "azure", "oracle", "alibaba", "aliyun",
    "tencent", "huawei cloud", "ucloud", "kingsoft", "baidu cloud", "jd cloud",
    "digitalocean", "vultr", "linode", "akamai", "hetzner", "ovh", "contabo",
    "scaleway", "leaseweb", "m247", "datacamp", "cdn77", "psychz", "colocrossing",
    "choopa", "serverius", "hosthatch", "frantech", "buyvm", "racknerd", "quadranet",
    "kaopu", "zenlayer", "cogent", "gcore", "upcloud", "hostinger", "ionos",
    "1&1", "strato", "serverhub", "hostwinds", "sharktech", "dedipath", "spartanhost",
    "cloudflare", "fastly", "stackpath", "alibaba cloud", "tencent cloud",
    "hosting", "host ", "server", "datacenter", "data center", "vps", "cloud",
    "colocation", "colo ", "idc", "机房", "数据中心", "云计算", "云服务",
]
# ---- 家宽关键词：优先判住宅（防止 "China Telecom Cloud" 这类误判，先匹配住宅再看机房）----
RES_KEYWORDS = [
    "chinanet", "china telecom", "china unicom", "china mobile", "cernet",
    "comcast", "verizon", "at&t", "att internet", "spectrum", "cox", "centurylink",
    "frontier", "charter", "bt ", "virgin media", "sky broadband", "talktalk",
    "deutsche telekom", "telefonica", "orange", "free sas", "proxad",
    "kddi", "ntt", "softbank", "docomo", "sk broadband", "kt corp", "lg u+",
    "nuro", "chinamobile", "cmcc", "cbn", "wasel", "etisalat", "stc",
    "宽带", "电信", "联通", "移动", "广电",
]

# ---- 云厂商高频段（离线兜底；不追求全量，只覆盖最常见的出口来源）----
DC_CIDRS = [
    # AWS / Amazon
    "3.0.0.0/9", "13.32.0.0/11", "15.0.0.0/8", "18.128.0.0/9", "23.20.0.0/14",
    "34.192.0.0/10", "35.72.0.0/13", "52.0.0.0/8", "54.0.0.0/8", "99.77.0.0/16",
    "176.32.0.0/12",
    # Google Cloud / Google
    "34.0.0.0/9", "35.184.0.0/13", "35.192.0.0/11", "104.154.0.0/15",
    "104.196.0.0/14", "130.211.0.0/16", "146.148.0.0/17", "162.222.176.0/21",
    # Microsoft Azure
    "13.64.0.0/11", "20.0.0.0/8", "40.64.0.0/10", "51.104.0.0/13", "52.96.0.0/12",
    "65.52.0.0/14", "104.40.0.0/13", "168.61.0.0/16",
    # DigitalOcean
    "45.55.0.0/16", "64.225.0.0/16", "68.183.0.0/16", "104.131.0.0/16",
    "104.236.0.0/16", "138.68.0.0/16", "138.197.0.0/16", "142.93.0.0/16",
    "143.110.0.0/16", "157.245.0.0/16", "159.65.0.0/16", "159.89.0.0/16",
    "159.203.0.0/16", "161.35.0.0/16", "164.90.0.0/16", "165.22.0.0/16",
    "167.71.0.0/16", "174.138.0.0/16", "178.62.0.0/16", "188.166.0.0/16",
    "206.189.0.0/16", "207.154.192.0/18",
    # Vultr / Choopa
    "45.32.0.0/16", "45.63.0.0/16", "45.76.0.0/16", "66.42.0.0/16",
    "95.179.0.0/16", "108.61.0.0/16", "139.180.0.0/16", "149.28.0.0/16",
    "207.246.0.0/16", "216.128.128.0/17",
    # Hetzner
    "5.9.0.0/16", "78.46.0.0/15", "88.198.0.0/16", "116.202.0.0/16",
    "128.140.0.0/17", "135.181.0.0/16", "138.201.0.0/16", "142.132.0.0/16",
    "159.69.0.0/16", "168.119.0.0/16", "176.9.0.0/16", "188.40.0.0/16",
    # OVH
    "51.38.0.0/16", "51.68.0.0/16", "51.75.0.0/16", "51.79.0.0/16",
    "51.83.0.0/16", "54.36.0.0/14", "137.74.0.0/16", "145.239.0.0/16",
    "147.135.0.0/16", "149.202.0.0/16", "151.80.0.0/16", "158.69.0.0/16",
    "167.114.0.0/16", "178.32.0.0/15", "188.165.0.0/16",
    # Contabo
    "5.189.0.0/16", "38.242.0.0/16", "144.91.0.0/16", "173.212.0.0/16",
    "207.180.0.0/16", "209.126.0.0/16",
    # Linode / Akamai
    "45.33.0.0/16", "45.56.0.0/16", "45.79.0.0/16", "50.116.0.0/16",
    "96.126.0.0/16", "139.162.0.0/16", "172.104.0.0/15", "173.255.192.0/18",
    # Oracle Cloud
    "129.146.0.0/16", "130.35.0.0/16", "132.145.0.0/16", "138.1.0.0/16",
    "140.91.0.0/16", "150.136.0.0/16", "152.67.0.0/16", "158.101.0.0/16",
    # 阿里云
    "8.128.0.0/10", "47.52.0.0/14", "47.88.0.0/14", "47.96.0.0/12",
    "59.110.0.0/16", "101.37.0.0/16", "112.124.0.0/14", "116.62.0.0/16",
    "118.178.0.0/16", "120.24.0.0/14", "121.40.0.0/14", "121.196.0.0/16",
    # 腾讯云
    "1.12.0.0/14", "43.128.0.0/12", "49.51.0.0/16", "81.68.0.0/14",
    "106.52.0.0/14", "119.29.0.0/16", "129.204.0.0/16", "132.232.0.0/16",
    "175.24.0.0/16", "193.112.0.0/16",
    # 华为云 / UCloud / 金山云
    "114.115.0.0/16", "121.36.0.0/14", "122.112.0.0/16", "139.159.0.0/16",
    "117.78.0.0/16", "123.58.0.0/16", "36.110.0.0/16",
]

_cache = {}
_cache_lock = threading.Lock()
_cache_dirty = False


def _ip_int(ip):
    return int(ipaddress.ip_address(ip))


_PREFIX_CACHE = []


def _prefixes():
    global _PREFIX_CACHE
    if _PREFIX_CACHE:
        return _PREFIX_CACHE
    out = []
    for c in DC_CIDRS:
        try:
            net = ipaddress.ip_network(c, strict=False)
            out.append((int(net.network_address), int(net.broadcast_address), c))
        except ValueError:
            continue
    _PREFIX_CACHE = out
    return out


def _load_cache():
    global _cache
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            now = time.time()
            _cache = {k: v for k, v in data.items()
                      if isinstance(v, dict) and now - float(v.get("ts") or 0) < CACHE_TTL}
    except (OSError, ValueError):
        _cache = {}


def _save_cache():
    global _cache_dirty
    if not _cache_dirty:
        return
    try:
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        tmp = CACHE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_cache, f, ensure_ascii=False)
        os.replace(tmp, CACHE_PATH)
        _cache_dirty = False
    except OSError:
        pass


def _kw_kind(text):
    """按关键词判断：住宅关键词优先（家宽运营商经常带 cloud 品牌名）。"""
    low = " " + str(text or "").lower() + " "
    for k in RES_KEYWORDS:
        if k in low:
            return "res", k
    for k in DC_KEYWORDS:
        if k in low:
            return "dc", k
    return "", ""


def _short_asn(*vals):
    """从 "AS15169 Google LLC" 里抠出 "AS15169"。"""
    for v in vals:
        m = re.match(r"\s*(AS\d+)", str(v or ""), re.I)
        if m:
            return m.group(1).upper()
    return ""


def _cidr_kind(ip):
    try:
        n = _ip_int(ip)
    except ValueError:
        return ""
    for lo, hi, cidr in _prefixes():
        if lo <= n <= hi:
            return cidr
    return ""


def classify(ip, isp="", org="", asn=""):
    """返回 {kind: dc/res/unk, reason, isp, org, asn, online}。

    先看已有文本（ISP/ORG/AS 名称），再看 CIDR，最后（可选）联网查。
    """
    text = " ".join(x for x in (org, isp, asn) if x)
    if text:
        kind, hit = _kw_kind(text)
        if kind:
            return {"kind": kind, "reason": f"关键词 {hit}", "isp": isp, "org": org,
                    "asn": _short_asn(asn, org, isp), "online": False}
    cidr = _cidr_kind(ip)
    if cidr:
        return {"kind": "dc", "reason": f"云厂商网段 {cidr}", "isp": isp, "org": org,
                "asn": _short_asn(asn, org, isp), "online": False}
    return {"kind": "unk", "reason": "", "isp": isp, "org": org,
            "asn": _short_asn(asn, org, isp), "online": False}


def lookup(ip, online=True, timeout=4.0):
    """带缓存的完整判定；online=False 时纯离线。"""
    ip = str(ip or "").strip()
    if not ip:
        return {"kind": "unk", "reason": "", "isp": "", "org": "", "asn": "", "online": False}
    with _cache_lock:
        hit = _cache.get(ip)
    if hit:
        return dict(hit, cached=True)
    res = classify(ip)
    if res["kind"] != "unk" or not online:
        _remember(ip, res)
        return res
    info = _online(ip, timeout)
    if info:
        res = classify(ip, info.get("isp", ""), info.get("org", ""), info.get("as", ""))
        res["online"] = True
        if res["kind"] == "unk":
            res["kind"] = "dc" if _looks_hosting(info) else "unk"
            if res["kind"] == "dc":
                res["reason"] = "在线 ASN 判定为托管商"
        _remember(ip, res)
    return res


def _looks_hosting(info):
    """在线结果兜底：AS 名里没有任何家宽特征，且带有托管常见词。"""
    blob = " ".join(str(info.get(k) or "") for k in ("isp", "org", "as")).lower()
    return any(w in blob for w in ("host", "cloud", "server", "colo", "datacenter",
                                   "data center", "vps", "dedicated", "cdn"))


def _get_json(url, timeout=4.0):
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 ProxyDog/1.5", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "ignore"))
    except Exception:
        return None


def _ipinfo(ip, timeout=4.0):
    """ipinfo.io：org 字段形如 "AS15169 Google LLC"，一条就够判断。"""
    d = _get_json(f"https://ipinfo.io/{ip}/json", timeout)
    if not d or d.get("bogon"):
        return None
    org = str(d.get("org") or "")
    asn = org.split(" ", 1)[0] if org.upper().startswith("AS") else ""
    if not org:
        return None
    return {"isp": org, "org": org, "as": org, "asn": asn,
            "region": " ".join(x for x in (d.get("country"), d.get("region"),
                                           d.get("city")) if x)}


def _ipsb(ip, timeout=4.0):
    """api.ip.sb：字段最全，带 asn / isp / organization。"""
    d = _get_json(f"https://api.ip.sb/geoip/{ip}", timeout)
    if not d or not isinstance(d, dict) or d.get("error"):
        return None
    asn = d.get("asn")
    return {"isp": str(d.get("isp") or d.get("organization") or ""),
            "org": str(d.get("organization") or d.get("asn_organization") or ""),
            "as": (f"AS{asn} {d.get('asn_organization') or ''}".strip() if asn else ""),
            "asn": f"AS{asn}" if asn else "",
            "region": " ".join(x for x in (d.get("country"), d.get("region"),
                                           d.get("city")) if x)}


def _ipapi(ip, timeout=4.0):
    """ip-api.com 兜底（部分网络不可达，放最后）。"""
    d = _get_json("http://ip-api.com/json/" + ip +
                  "?lang=zh-CN&fields=status,isp,org,as,country,regionName,city", timeout)
    if not d or d.get("status") != "success":
        return None
    org = str(d.get("org") or d.get("isp") or "")
    return {"isp": str(d.get("isp") or ""), "org": org, "as": str(d.get("as") or ""),
            "asn": (str(d.get("as") or "").split(" ", 1)[0]
                    if str(d.get("as") or "").upper().startswith("AS") else ""),
            "region": " ".join(x for x in (d.get("country"), d.get("regionName"),
                                           d.get("city")) if x)}


def _online(ip, timeout=4.0):
    """在线兜底：多个源依次试，第一个成功的就用。"""
    for fn in (_ipinfo, _ipsb, _ipapi):
        try:
            info = fn(ip, timeout)
        except Exception:
            info = None
        if info and (info.get("org") or info.get("isp") or info.get("as")):
            return info
    return None


def _remember(ip, res):
    global _cache_dirty
    with _cache_lock:
        _cache[ip] = dict(res, ts=time.time())
        if len(_cache) > 5000:
            for k in list(_cache)[:1000]:
                _cache.pop(k, None)
        _cache_dirty = True
    _save_cache()


def flush():
    _save_cache()


def stats():
    with _cache_lock:
        n = len(_cache)
    return {"cached": n, "prefixes": len(_prefixes()), "keywords": len(DC_KEYWORDS)}


_load_cache()
