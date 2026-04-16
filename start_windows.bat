@echo off
chcp 65001 >nul
echo ========================================
echo   OAuth 2.0 Demo - 一键启动
echo ========================================
echo.

echo [1/2] 启动模拟 OAuth 服务器...
start "OAuth Server" cmd /c "python mock_oauth_server.py"

:: 等待服务器就绪
timeout /t 2 /nobreak >nul

echo [2/2] 启动 Windows 应用...
cd OAuth2WinApp
dotnet run

:: 应用关闭后，关闭服务器
echo.
echo 正在关闭 OAuth 服务器...
taskkill /FI "WINDOWTITLE eq OAuth Server" /F >nul 2>&1
echo 已全部退出。
