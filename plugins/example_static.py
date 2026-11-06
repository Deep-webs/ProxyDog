"""示例插件一：静态清单地址。

把它当模板复制一份改名即可。URLS 里可以放纯文本、base64、Clash YAML 或 JSON，
解析器会自动认格式。
"""

NAME = "示例 · 静态清单"
PROTOCOL = "http"
DESC = "从若干个公开清单地址拉代理，最简单的一种插件"
ENABLED = False          # 示例默认关闭，省得每次抓取都白跑一趟

URLS = [
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt",
]


def check():
    """面板「测试」按钮会调它；不写也行，不写就按条数报结果。"""
    return bool(URLS), f"配置了 {len(URLS)} 个地址"
