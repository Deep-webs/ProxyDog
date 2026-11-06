# ProxyDog · 容器镜像
# 单容器同时跑：HTTP 代理 2080 / SOCKS5 2081 / 管理面板 5002
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    TZ=Asia/Shanghai \
    PROXYDOG_LISTEN_HOST=0.0.0.0 \
    PROXYDOG_WEB_HOST=0.0.0.0

WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY . .

# 数据（代理库/设置）与日志挂出来，容器重建不丢池子
RUN useradd -m -u 10001 dog \
    && mkdir -p /app/data /app/logs \
    && chown -R dog:dog /app

USER dog
VOLUME ["/app/data", "/app/logs"]

EXPOSE 2080 2081 5002

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:5002/login',timeout=4)" || exit 1

CMD ["python", "app.py"]
