@echo off
title AI Network Security Scanner
cd /d "%~dp0"
setlocal

if "%GEMINI_API_KEY%"=="" (
    for /f "usebackq tokens=*" %%k in (`powershell -NoProfile -Command "[Environment]::GetEnvironmentVariable('GEMINI_API_KEY','User')"`) do set "GEMINI_API_KEY=%%k"
)

if "%GEMINI_API_KEY%"=="" (
    echo [!] GEMINI_API_KEY is not set.
    echo     Run this once:  setx GEMINI_API_KEY "your-key"
    echo.
    pause
    exit /b 1
)

python Ai_scan.py %*

echo.
echo =======================================================
echo  Done. Press any key to close this window.
echo =======================================================
pause >nul
