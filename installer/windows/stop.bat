@echo off
echo Stopping Super Tanks...
cd /d "%~dp0"
docker compose down
echo Super Tanks stopped.
pause
