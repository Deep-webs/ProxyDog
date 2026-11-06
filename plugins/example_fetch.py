"""示例插件二：自己写代码抓（返回 host:port 列表）。

fetch() 是同步函数，跑在线程池里，可以直接用 requests / urllib / 自己解析 HTML。
返回值的三种写法都支持：
    ["1.2.3.4:8080", "http://5.6.7.8:3128"]
    [{"host": "1.2.3.4", "port": 8080, "protocol": "socks5"}]
    ["<一大段纯文本或 base64>"]        # 会走通用解析器
"""

import json
import urllib.request

NAME = "示例 · 代码抓取"
PROTOCOL = "socks5"
DESC = "演示 fetch()：请求一个 JSON 接口并取字段"
ENABLED = False

API = ""   # 填一个返回 JSON 列表的地址


def fetch(timeout=12):
    if not API:
        return []
    req = urllib.request.Request(API, headers={"User-Agent": "ProxyDog/plugin"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read().decode("utf-8", "ignore"))
    out = []
    for it in data if isinstance(data, list) else data.get("data") or []:
        host = it.get("ip") or it.get("host")
        port = it.get("port")
        if host and port:
            out.append({"host": host, "port": int(port),
                        "protocol": (it.get("protocol") or PROTOCOL).lower()})
    return out


def check():
    return True, "示例插件，填好 API 再把 ENABLED 改成 True 即可"
