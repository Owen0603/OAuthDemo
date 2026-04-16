@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul
echo ========================================
echo   OAuth 2.0 Demo - 一键启动
echo ========================================
echo.

:: 检测 Python 命令
set PYTHON_CMD=
where python >nul 2>&1 && set PYTHON_CMD=python
if "!PYTHON_CMD!"=="" (where python3 >nul 2>&1 && set PYTHON_CMD=python3)
if "!PYTHON_CMD!"=="" (where py >nul 2>&1 && set PYTHON_CMD=py)
if "!PYTHON_CMD!"=="" (
    echo [错误] 未找到 Python，请先安装 Python 3 并添加到 PATH
    echo 下载地址: https://www.python.org/downloads/
    pause
    exit /b 1
)
echo 使用 Python: !PYTHON_CMD!

echo.
echo [1/2] 启动模拟 OAuth 服务器...
start "OAuth Server" !PYTHON_CMD! "%~dp0mock_oauth_server.py"

:: 等待服务器就绪（最多等 10 秒）
echo 等待服务器启动...
set READY=0
for /L %%i in (1,1,10) do (
    if !READY!==0 (
        timeout /t 1 /nobreak >nul
        curl -s -o nul http://localhost:8089/ >nul 2>&1 && set READY=1
    )
)
if !READY!==0 (
    echo [警告] OAuth 服务器可能未就绪，仍尝试启动应用...
) else (
    echo OAuth 服务器已就绪!
)

echo.
echo [2/2] 启动 Windows 应用...
cd /d "%~dp0OAuth2WinApp"
dotnet run

:: 应用关闭后，关闭服务器
echo.
echo 正在关闭 OAuth 服务器...
taskkill /FI "WINDOWTITLE eq OAuth Server" /F >nul 2>&1
echo 已全部退出。
pause
