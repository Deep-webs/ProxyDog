"""离线归属地查询。

设计：
- 数据一次性下载到 data/geoip/，之后**纯本地查询**，不发任何请求、不受限速影响；
- 原始数据是管道分隔的文本（ip2region）或 CSV（DB-IP），首次下载后立刻转成
  紧凑二进制索引（约 5 MB），原始文件删掉，查询走 bisect，单条约 1 微秒；
- 索引只保留 IP 段起点 + 标签下标，内存占用 5 MB 左右，几十万条也不慢；
- 内网/保留地址直接本地判定，不进库。
"""

from __future__ import annotations

import array
import bisect
import ipaddress
import json
import os
import struct
import threading
import time

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "geoip")
BIN_PATH = os.path.join(DATA_DIR, "geo.bin")
TMP_PATH = os.path.join(DATA_DIR, "geo.raw")

MAGIC = b"PDGEO2\n"
FORMAT_VERSION = 2

# 数据源：先试城市级中文库，失败再退到国家级轻量库
PROVIDERS = [
    {
        "key": "ip2region",
        "label": "ip2region 城市级（中文省市）",
        "urls": [
            "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ipv4_source.txt",
            "https://cdn.jsdelivr.net/gh/lionsoul2014/ip2region@master/data/ipv4_source.txt",
            "https://ghproxy.net/https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ipv4_source.txt",
        ],
        "size_mb": 35,
        "kind": "pipe",
    },
    {
        "key": "dbip",
        "label": "DB-IP 国家级（轻量）",
        "urls": [
            "https://cdn.jsdelivr.net/gh/sapics/ip-location-db@main/dbip-country/dbip-country-ipv4.csv",
            "https://fastly.jsdelivr.net/gh/sapics/ip-location-db@main/dbip-country/dbip-country-ipv4.csv",
            "https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-country/dbip-country-ipv4.csv",
        ],
        "size_mb": 11,
        "kind": "csv",
    },
]

# 常见国家的中文名；未收录的保留原样（英文），不影响使用
COUNTRY_CN = {
    "CN": "中国", "HK": "中国香港", "MO": "中国澳门", "TW": "中国台湾",
    "US": "美国", "CA": "加拿大", "MX": "墨西哥", "BR": "巴西", "AR": "阿根廷",
    "CL": "智利", "PE": "秘鲁", "CO": "哥伦比亚", "VE": "委内瑞拉", "EC": "厄瓜多尔",
    "BO": "玻利维亚", "PY": "巴拉圭", "UY": "乌拉圭", "PA": "巴拿马", "CR": "哥斯达黎加",
    "GT": "危地马拉", "DO": "多米尼加", "CU": "古巴", "JM": "牙买加", "PR": "波多黎各",
    "JP": "日本", "KR": "韩国", "KP": "朝鲜", "SG": "新加坡", "MY": "马来西亚",
    "TH": "泰国", "VN": "越南", "ID": "印度尼西亚", "PH": "菲律宾", "IN": "印度",
    "PK": "巴基斯坦", "BD": "孟加拉国", "LK": "斯里兰卡", "NP": "尼泊尔", "MM": "缅甸",
    "KH": "柬埔寨", "LA": "老挝", "BN": "文莱", "MN": "蒙古", "KZ": "哈萨克斯坦",
    "UZ": "乌兹别克斯坦", "KG": "吉尔吉斯斯坦", "TJ": "塔吉克斯坦", "TM": "土库曼斯坦",
    "AF": "阿富汗", "IR": "伊朗", "IQ": "伊拉克", "IL": "以色列", "SA": "沙特阿拉伯",
    "AE": "阿联酋", "QA": "卡塔尔", "KW": "科威特", "BH": "巴林", "OM": "阿曼",
    "JO": "约旦", "LB": "黎巴嫩", "SY": "叙利亚", "TR": "土耳其", "GE": "格鲁吉亚",
    "AM": "亚美尼亚", "AZ": "阿塞拜疆", "CY": "塞浦路斯",
    "RU": "俄罗斯", "UA": "乌克兰", "BY": "白俄罗斯", "MD": "摩尔多瓦", "PL": "波兰",
    "CZ": "捷克", "SK": "斯洛伐克", "HU": "匈牙利", "RO": "罗马尼亚", "BG": "保加利亚",
    "GR": "希腊", "RS": "塞尔维亚", "HR": "克罗地亚", "SI": "斯洛文尼亚", "BA": "波黑",
    "MK": "北马其顿", "AL": "阿尔巴尼亚", "ME": "黑山", "LT": "立陶宛", "LV": "拉脱维亚",
    "EE": "爱沙尼亚", "FI": "芬兰", "SE": "瑞典", "NO": "挪威", "DK": "丹麦",
    "IS": "冰岛", "IE": "爱尔兰", "GB": "英国", "FR": "法国", "DE": "德国",
    "NL": "荷兰", "BE": "比利时", "LU": "卢森堡", "CH": "瑞士", "AT": "奥地利",
    "IT": "意大利", "ES": "西班牙", "PT": "葡萄牙", "MT": "马耳他",
    "AU": "澳大利亚", "NZ": "新西兰", "FJ": "斐济", "PG": "巴布亚新几内亚",
    "ZA": "南非", "EG": "埃及", "MA": "摩洛哥", "DZ": "阿尔及利亚", "TN": "突尼斯",
    "LY": "利比亚", "SD": "苏丹", "ET": "埃塞俄比亚", "KE": "肯尼亚", "TZ": "坦桑尼亚",
    "UG": "乌干达", "NG": "尼日利亚", "GH": "加纳", "CI": "科特迪瓦", "SN": "塞内加尔",
    "CM": "喀麦隆", "ZW": "津巴布韦", "ZM": "赞比亚", "MZ": "莫桑比克", "AO": "安哥拉",
    "MU": "毛里求斯", "MG": "马达加斯加", "RW": "卢旺达", "NA": "纳米比亚",
    "BW": "博茨瓦纳", "SC": "塞舌尔", "RE": "留尼汪", "TZ": "坦桑尼亚",
}

# 英文国名 → 中文（ip2region 里是英文国名）
NAME_CN = {
    "China": "中国", "Hong Kong": "中国香港", "Macau": "中国澳门", "Taiwan": "中国台湾",
    "United States": "美国", "United States of America": "美国", "Japan": "日本",
    "Korea": "韩国", "South Korea": "韩国", "Singapore": "新加坡", "Malaysia": "马来西亚",
    "Thailand": "泰国", "Vietnam": "越南", "Viet Nam": "越南", "Indonesia": "印度尼西亚",
    "Philippines": "菲律宾", "India": "印度", "Pakistan": "巴基斯坦",
    "Bangladesh": "孟加拉国", "Sri Lanka": "斯里兰卡", "Nepal": "尼泊尔",
    "Myanmar": "缅甸", "Cambodia": "柬埔寨", "Laos": "老挝", "Mongolia": "蒙古",
    "Kazakhstan": "哈萨克斯坦", "Russia": "俄罗斯", "Russian Federation": "俄罗斯",
    "Ukraine": "乌克兰", "Poland": "波兰", "Czechia": "捷克", "Czech Republic": "捷克",
    "Hungary": "匈牙利", "Romania": "罗马尼亚", "Bulgaria": "保加利亚", "Greece": "希腊",
    "Serbia": "塞尔维亚", "Croatia": "克罗地亚", "Slovenia": "斯洛文尼亚",
    "Lithuania": "立陶宛", "Latvia": "拉脱维亚", "Estonia": "爱沙尼亚",
    "Finland": "芬兰", "Sweden": "瑞典", "Norway": "挪威", "Denmark": "丹麦",
    "Iceland": "冰岛", "Ireland": "爱尔兰", "United Kingdom": "英国", "France": "法国",
    "Germany": "德国", "Netherlands": "荷兰", "The Netherlands": "荷兰",
    "Belgium": "比利时", "Luxembourg": "卢森堡", "Switzerland": "瑞士",
    "Austria": "奥地利", "Italy": "意大利", "Spain": "西班牙", "Portugal": "葡萄牙",
    "Malta": "马耳他", "Cyprus": "塞浦路斯", "Turkey": "土耳其", "Israel": "以色列",
    "Saudi Arabia": "沙特阿拉伯", "United Arab Emirates": "阿联酋", "Qatar": "卡塔尔",
    "Kuwait": "科威特", "Iran": "伊朗", "Iraq": "伊拉克", "Jordan": "约旦",
    "Lebanon": "黎巴嫩", "Georgia": "格鲁吉亚", "Armenia": "亚美尼亚",
    "Azerbaijan": "阿塞拜疆", "Canada": "加拿大", "Mexico": "墨西哥", "Brazil": "巴西",
    "Argentina": "阿根廷", "Chile": "智利", "Peru": "秘鲁", "Colombia": "哥伦比亚",
    "Venezuela": "委内瑞拉", "Ecuador": "厄瓜多尔", "Bolivia": "玻利维亚",
    "Paraguay": "巴拉圭", "Uruguay": "乌拉圭", "Panama": "巴拿马",
    "Costa Rica": "哥斯达黎加", "Cuba": "古巴", "Jamaica": "牙买加",
    "Puerto Rico": "波多黎各", "Australia": "澳大利亚", "New Zealand": "新西兰",
    "South Africa": "南非", "Egypt": "埃及", "Morocco": "摩洛哥", "Algeria": "阿尔及利亚",
    "Tunisia": "突尼斯", "Nigeria": "尼日利亚", "Kenya": "肯尼亚",
    "Ethiopia": "埃塞俄比亚", "Ghana": "加纳", "Tanzania": "坦桑尼亚",
    "Uganda": "乌干达",     "Reserved": "保留地址", "Unknown": "未知",
    # 中文别名统一
    "印尼": "印度尼西亚", "南韩": "韩国", "胡志明市": "胡志明市",
}

_PRIVATE = [
    (ipaddress.ip_network("10.0.0.0/8"), "局域网"),
    (ipaddress.ip_network("172.16.0.0/12"), "局域网"),
    (ipaddress.ip_network("192.168.0.0/16"), "局域网"),
    (ipaddress.ip_network("127.0.0.0/8"), "本机"),
    (ipaddress.ip_network("169.254.0.0/16"), "链路本地"),
    (ipaddress.ip_network("100.64.0.0/10"), "运营商内网"),
    (ipaddress.ip_network("0.0.0.0/8"), "保留地址"),
    (ipaddress.ip_network("224.0.0.0/4"), "组播地址"),
    (ipaddress.ip_network("240.0.0.0/4"), "保留地址"),
]

_lock = threading.Lock()
_idx = {"mtime": 0.0, "starts": None, "labels": None, "meta": {}}

# 下载/构建进度（前端轮询展示）
PROGRESS = {"running": False, "phase": "", "got": 0, "total": 0,
            "msg": "", "error": "", "started": 0.0}


# ---------------------------------------------------------------- 基础工具
def _ip2int(ip: str) -> int:
    try:
        return int(ipaddress.IPv4Address(ip))
    except Exception:
        return -1


def _clean(part: str) -> str:
    part = (part or "").strip()
    if not part or part in ("0", "Reserved", "-", "None", "null"):
        return ""
    return part


def _label_of(country: str, province: str = "", city: str = "") -> str:
    country = _clean(country)
    province = _clean(province)
    city = _clean(city)
    # 国家名统一成中文（ip2region 里中英混排；同样是中文的则原样保留）
    mapped = NAME_CN.get(country) or (COUNTRY_CN.get(country) if country.isalpha() and
                                      len(country) == 2 else None) or \
        (COUNTRY_CN.get(country.upper()) if country.isalpha() and len(country) == 2 else None)
    country = mapped or country
    parts = [country]
    # 省份/城市里也可能带英文，保留原样即可（信息量比丢掉大）
    if province and province != country:
        parts.append(province)
    if city and city not in (province, country):
        parts.append(city)
    label = "-".join(p for p in parts if p)
    return label or "未知"


# ---------------------------------------------------------------- 索引读写
def _write_index(starts, label_idx, labels, meta):
    os.makedirs(DATA_DIR, exist_ok=True)
    meta = dict(meta, segments=len(starts), labels=len(labels),
                built=time.strftime("%Y-%m-%d %H:%M"))
    blob = json.dumps(meta, ensure_ascii=False).encode("utf-8")
    tmp = BIN_PATH + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(MAGIC)
        fh.write(struct.pack("<I", len(blob)))
        fh.write(blob)
        fh.write(struct.pack("<I", len(starts)))
        fh.write(array.array("I", starts).tobytes())
        fh.write(array.array("I", label_idx).tobytes())
        fh.write(struct.pack("<I", len(labels)))
        for item in labels:
            raw = item.encode("utf-8")
            fh.write(struct.pack("<H", len(raw)))
            fh.write(raw)
    os.replace(tmp, BIN_PATH)


def _read_index():
    with open(BIN_PATH, "rb") as fh:
        if fh.read(len(MAGIC)) != MAGIC:
            raise RuntimeError("索引文件格式不匹配，请重新下载离线库")
        meta_len = struct.unpack("<I", fh.read(4))[0]
        meta = json.loads(fh.read(meta_len).decode("utf-8"))
        n = struct.unpack("<I", fh.read(4))[0]
        starts = array.array("I")
        starts.frombytes(fh.read(n * 4))
        label_idx = array.array("I")
        label_idx.frombytes(fh.read(n * 4))
        m = struct.unpack("<I", fh.read(4))[0]
        labels = []
        for _ in range(m):
            ln = struct.unpack("<H", fh.read(2))[0]
            labels.append(fh.read(ln).decode("utf-8"))
    return starts, label_idx, labels, meta


def _index():
    """按 mtime 懒加载，更新库后无需重启服务。"""
    if not os.path.exists(BIN_PATH):
        return None, None, {}
    mtime = os.path.getmtime(BIN_PATH)
    with _lock:
        if _idx["mtime"] != mtime:
            starts, label_idx, labels, meta = _read_index()
            _idx.update(mtime=mtime, starts=starts, label_idx=label_idx, meta=meta)
            _idx["labels"] = (labels, label_idx)
        return _idx["starts"], _idx["labels"], _idx["meta"]


def ready() -> bool:
    return os.path.exists(BIN_PATH)


def status() -> dict:
    st = dict(PROGRESS)
    if not ready():
        st.update(ready=False)
        return st
    try:
        starts, (labels, _li), meta = _index()
    except Exception as exc:
        st.update(ready=False, error=str(exc))
        return st
    st.update(ready=True, segments=len(starts), label_count=len(labels),
              provider=meta.get("provider", ""), built=meta.get("built", ""),
              size_mb=round(os.path.getsize(BIN_PATH) / 1048576, 2),
              updated_at=time.strftime("%Y-%m-%d %H:%M",
                                       time.localtime(os.path.getmtime(BIN_PATH))))
    return st


# ---------------------------------------------------------------- 解析与构建
def _parse_pipe(path):
    """ip2region：start|end|国家|省|市|运营商|CC"""
    starts, idx, labels, seen = [], [], [], {}
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line or "|" not in line:
                continue
            parts = line.split("|")
            if len(parts) < 3:
                continue
            s = _ip2int(parts[0])
            if s < 0:
                continue
            country = parts[2] if len(parts) > 2 else ""
            province = parts[3] if len(parts) > 3 else ""
            city = parts[4] if len(parts) > 4 else ""
            label = _label_of(country, province, city)
            pos = seen.get(label)
            if pos is None:
                pos = seen[label] = len(labels)
                labels.append(label)
            starts.append(s)
            idx.append(pos)
    return starts, idx, labels, {"provider": "ip2region 城市级"}


def _parse_csv(path):
    """DB-IP：start,end,CC（无表头）"""
    starts, idx, labels, seen = [], [], [], {}
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            parts = line.strip().split(",")
            if len(parts) < 3:
                continue
            s = _ip2int(parts[0])
            if s < 0:
                continue
            cc = _clean(parts[2]).upper()
            label = COUNTRY_CN.get(cc, cc or "未知")
            pos = seen.get(label)
            if pos is None:
                pos = seen[label] = len(labels)
                labels.append(label)
            starts.append(s)
            idx.append(pos)
    return starts, idx, labels, {"provider": "DB-IP 国家级"}


def build(raw_path, kind):
    if kind == "csv":
        starts, idx, labels, meta = _parse_csv(raw_path)
    else:
        starts, idx, labels, meta = _parse_pipe(raw_path)
    if not starts:
        raise RuntimeError("数据源里没有解析出任何网段")
    # 数据源基本有序，保险起见排一次（同时保持 start 与标签一一对应）
    order = sorted(range(len(starts)), key=starts.__getitem__)
    starts = [starts[i] for i in order]
    idx = [idx[i] for i in order]
    # 压缩相邻同标签段：查询只看起点，合并后索引能小一半
    cs, ci = [], []
    for s, li in zip(starts, idx):
        if ci and ci[-1] == li:
            continue
        cs.append(s)
        ci.append(li)
    _write_index(cs, ci, labels, meta)
    return len(cs)


# ---------------------------------------------------------------- 下载
def _fetch(url, dest, timeout=30):
    """优先 urllib，失败退到系统 curl（Windows 10+ 自带），两者都不行才算失败。"""
    try:
        _fetch_urllib(url, dest, timeout)
    except Exception as first:
        try:
            _fetch_curl(url, dest, timeout)
        except Exception:
            raise first
    if os.path.getsize(dest) < 1024 * 512:
        raise RuntimeError("下载内容过小，可能是错误页")


def _fetch_urllib(url, dest, timeout):
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 ProxyDog/1.6"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        total = int(resp.headers.get("Content-Length") or 0)
        PROGRESS.update(total=total, got=0)
        with open(dest, "wb") as out:
            while True:
                chunk = resp.read(262144)
                if not chunk:
                    break
                out.write(chunk)
                PROGRESS["got"] += len(chunk)


def _fetch_curl(url, dest, timeout):
    import subprocess
    exe = "curl"
    if os.name == "nt":
        cand = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "curl.exe")
        if os.path.exists(cand):
            exe = cand
    PROGRESS.update(total=0, got=0, msg="正在用 curl 重试下载")
    proc = subprocess.run([exe, "-sL", "--fail", "--retry", "2", "--retry-delay", "1",
                           "--max-time", str(int(timeout * 3)), "-o", dest, url],
                          capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError("curl 退出码 %s" % proc.returncode)
    PROGRESS["got"] = os.path.getsize(dest)


def update(blocking=True, prefer=None):
    """下载 + 转索引。blocking=False 时丢到线程里跑。

    prefer: "ip2region"（城市级，35MB）或 "dbip"（国家级，11MB），
    不传则先试城市级，失败自动退到国家级。
    """
    if blocking:
        return _update_inner(prefer)
    t = threading.Thread(target=_update_inner, args=(prefer,), daemon=True)
    t.start()
    return True


def _update_inner(prefer=None):
    if PROGRESS["running"]:
        return False
    PROGRESS.update(running=True, phase="download", got=0, total=0,
                    msg="", error="", started=time.time())
    os.makedirs(DATA_DIR, exist_ok=True)
    errors = []
    order = list(PROVIDERS)
    if prefer:
        order.sort(key=lambda p: 0 if p["key"] == prefer else 1)
    try:
        for prov in order:
            for url in prov["urls"]:
                for attempt in (1, 2):
                    try:
                        PROGRESS.update(msg="正在下载 " + prov["label"], phase="download")
                        _fetch(url, TMP_PATH, timeout=60)
                        PROGRESS.update(phase="build", msg="正在生成索引")
                        n = build(TMP_PATH, prov["kind"])
                        PROGRESS.update(running=False, phase="done", total=0,
                                        msg=f"完成：{n} 个网段（{prov['label']}）")
                        return True
                    except Exception as exc:
                        errors.append(f"{url.split('/')[2]}: {exc}")
                        if attempt == 1:
                            time.sleep(1)
        PROGRESS.update(running=False, phase="error",
                        error="；".join(errors[-3:]) or "全部下载源都失败")
        return False
    finally:
        PROGRESS["running"] = False
        try:
            if os.path.exists(TMP_PATH):
                os.remove(TMP_PATH)
        except OSError:
            pass


# ---------------------------------------------------------------- 查询
def lookup(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip) if ip else None
    except ValueError:
        return ""          # 打码 IP（如 164.*.*.*）、域名等非合法地址，查不了归属地
    if addr is None:
        return ""
    if addr.version == 6:
        return "IPv6"
    for net, label in _PRIVATE:
        if addr in net:
            return label
    starts, packed, _meta = _index()
    if not starts:
        return ""
    pos = bisect.bisect_right(starts, int(addr)) - 1
    if pos < 0:
        return ""
    labels, label_idx = packed
    return labels[label_idx[pos]] if pos < len(label_idx) else ""


def lookup_many(ips):
    return {ip: lookup(ip) for ip in dict.fromkeys(ips) if ip}


if __name__ == "__main__":                      # 手动预热：python geoip.py
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "update":
        print(update())
    print(json.dumps(status(), ensure_ascii=False, indent=2))
    for test in ("8.8.8.8", "1.1.1.1", "193.176.84.34", "114.114.114.114", "192.168.1.1"):
        print(test, "->", lookup(test))
