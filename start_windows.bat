@echo off
chcp 65001 >nul 2>nul
echo ========================================
echo   OAuth 2.0 Demo - 一键启动
echo ========================================
echo.
echo  应用启动后会自动运行 OAuth 模拟服务器
echo  无需手动启动 Python 后端
echo.
echo ----------------------------------------

cd /d "%~dp0OAuth2WinApp"

where dotnet >nul 2>&1
if errorlevel 1 (
    echo [错误] 未找到 dotnet 命令
    echo 请安装 .NET 8 SDK: https://dotnet.microsoft.com/download/dotnet/8.0
    echo.
    pause
    exit /b 1
)

echo 正在编译并启动应用...
echo.
dotnet run
echo.
echo 应用已退出。
pause
pause
