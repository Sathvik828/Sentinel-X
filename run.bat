@echo off
cd /d "%~dp0"

call venv\Scripts\activate.bat

echo.
echo ==========================================
echo     SENTINEL-X EMAIL THREAT INTELLIGENCE
echo ==========================================
echo.
echo Server starting...
echo.
echo Open: http://127.0.0.1:8080
echo.
echo Press CTRL+C to stop the server.
echo.

uvicorn main:app --host 0.0.0.0 --port 8080

pause