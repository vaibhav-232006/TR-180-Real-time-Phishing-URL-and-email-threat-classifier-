@echo off
echo ========================================================
echo       🛡️ Starting Phishing Classifier Web App 🛡️
echo ========================================================

echo 1. Installing any missing requirements...
pip install -r requirements.txt -q

echo.
echo 2. Starting FastAPI Backend (Port 8000)...
start cmd /k "echo Starting Backend Server... && uvicorn backend.main:app --reload --port 8000"

echo.
echo 3. Starting Frontend Web Server (Port 3000)...
start cmd /k "echo Starting Frontend Server... && python -m http.server 3000 --directory frontend"

echo.
echo ========================================================
echo ✅ All Servers Starting Successfully!
echo.
echo 👉 VIEW YOUR APP HERE: http://localhost:3000
echo 👉 API DOCS: http://localhost:8000/docs
echo ========================================================
pause
