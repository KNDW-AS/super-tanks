@echo off
title Super Tanks
echo.
echo   Super Tanks - Starting...
echo.

:: Check Docker
docker --version >nul 2>&1
if errorlevel 1 (
    echo   Docker not found. Installing...
    echo   Please wait — this only happens once.
    winget install Docker.DockerDesktop --accept-package-agreements --accept-source-agreements
    echo.
    echo   Docker installed. Please restart your computer and run this again.
    pause
    exit /b
)

:: Start containers
cd /d "%~dp0"
docker compose up -d --build

:: Wait for ready
echo   Waiting for system...
:wait_loop
timeout /t 2 /nobreak >nul
curl -sf http://localhost:8765/api/health >nul 2>&1
if errorlevel 1 goto wait_loop

:: Open browser
echo.
echo   Super Tanks is ready!
start http://localhost:8765/setup
echo.
echo   Cockpit: http://localhost:8765
echo   Close this window to keep running in background.
echo.
pause
