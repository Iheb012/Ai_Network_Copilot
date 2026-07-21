@echo off
title AI Network Copilot - Launcher
color 0B

echo.
echo  ================================================
echo   AI NETWORK COPILOT - Starting all services...
echo  ================================================
echo.

:: ── Check venv exists ──────────────────────────
if not exist "venv\Scripts\activate.bat" (
    echo  [ERROR] Virtual environment not found.
    echo  Run this first:  python -m venv venv
    echo                   venv\Scripts\activate
    echo                   pip install -r api\requirements.txt
    echo                   pip install -r dashboard\requirements.txt
    pause
    exit /b 1
)

echo  [1/3] Starting Data Simulator...
start "AI Copilot - Simulator" cmd /k "cd /d %~dp0 && venv\Scripts\activate && cd collector && python simulator_v2.py"
timeout /t 2 /nobreak >nul

echo  [2/3] Starting API (FastAPI)...
start "AI Copilot - API" cmd /k "cd /d %~dp0 && venv\Scripts\activate && cd api && uvicorn main:app --reload --port 8000"
timeout /t 3 /nobreak >nul

echo  [3/3] Starting Dashboard (Streamlit)...
start "AI Copilot - Dashboard" cmd /k "cd /d %~dp0 && venv\Scripts\activate && cd dashboard && streamlit run app.py --server.port 8501"
timeout /t 3 /nobreak >nul

echo.
echo  ================================================
echo   All services launched!
echo.
echo   Dashboard  →  http://localhost:8501
echo   API Docs   →  http://localhost:8000/docs
echo   API Health →  http://localhost:8000/health
echo  ================================================
echo.

:: ── Open dashboard in browser ──────────────────
rem Streamlit auto-opens browser; no need for start command
rem start http://localhost:8501

echo.
echo  Close this window or press any key to exit launcher.
echo  (The 3 service windows stay open independently)
pause >nul
