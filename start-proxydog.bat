@echo off
setlocal
cd /d "%~dp0"
title ProxyDog - 代理池

set "PY="
if exist "E:\Python314\python.exe" set "PY=E:\Python314\python.exe"
if not defined PY if exist "%~dp0venv\Scripts\python.exe" set "PY=%~dp0venv\Scripts\python.exe"
if not defined PY (
    where python >nul 2>nul
    if not errorlevel 1 set "PY=python"
)
if not defined PY (
    echo [错误] 没有找到 Python，请先安装 Python 3.10 以上版本
    pause
    exit /b 1
)

echo [1/3] 解释器: %PY%
"%PY%" -c "import flask, aiohttp, aiohttp_socks, yaml" >nul 2>nul
if errorlevel 1 (
    echo [2/3] 缺少依赖，正在安装（清华源）...
    "%PY%" -m pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
    if errorlevel 1 (
        echo [错误] 依赖安装失败，请手动执行 pip install -r requirements.txt
        pause
        exit /b 1
    )
) else (
    echo [2/3] 依赖检查通过
)

echo [3/3] 面板 http://127.0.0.1:5002   代理 127.0.0.1:2080
echo       关闭本窗口或按 Ctrl+C 停止服务
echo.
start "" /min powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 3; Start-Process 'http://127.0.0.1:5002'"
"%PY%" app.py

echo.
echo 服务已退出
pause
