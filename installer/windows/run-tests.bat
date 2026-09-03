@echo off
cd /d "%~dp0..\.."
call .venv\Scripts\activate.bat
python -m pytest -q --no-cov -p no:cacheprovider
python -m scripts.zef_baseline --tier local-dev --report-only
pause
