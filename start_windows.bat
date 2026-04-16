@echo off
echo ========================================
echo   OAuth 2.0 Demo - Start
echo ========================================
echo.

cd /d "%~dp0OAuth2WinApp"

echo Checking dotnet...
where dotnet >nul 2>&1
if errorlevel 1 (
    echo [ERROR] dotnet not found.
    echo Please install .NET 8 SDK:
    echo https://dotnet.microsoft.com/download/dotnet/8.0
    echo.
    pause
    exit /b 1
)

for /f "tokens=*" %%v in ('dotnet --version 2^>nul') do set DOTNET_VER=%%v
echo dotnet version: %DOTNET_VER%
echo.
echo Building and starting app...
echo.

dotnet run 2>&1

echo.
echo App exited.
pause
