@echo off
title Super Tanks - developer install
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-dev.ps1" %*
echo.
pause
