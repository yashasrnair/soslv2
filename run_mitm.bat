@echo off
echo =====================================================
echo   Zero Trust MITM Setup ^& Launcher (Windows)
echo =====================================================
echo.

:: ── Check Python ──
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python not found. Download from https://www.python.org/downloads/
    pause & exit /b 1
)

:: ── Install deps if needed ──
python -c "import mitmproxy" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [INFO] Installing mitmproxy...
    pip install mitmproxy
)

echo.
echo ==========================================================
echo  IMPORTANT — Do this ONCE before running the proxy:
echo ==========================================================
echo.
echo  1. Open Windows Settings ^> Network ^& Internet ^> Proxy
echo     ^> Manual proxy setup ^> Turn ON
echo     HTTP  Proxy: 127.0.0.1   Port: 8888
echo     HTTPS Proxy: 127.0.0.1   Port: 8888
echo     "Don't use proxy for": localhost;127.0.0.1
echo.
echo  2. HTTPS Certificate (first time only):
echo     - With proxy ON, visit http://mitm.it in Chrome/Firefox
echo     - Click "Windows" to download the cert
echo     - Double-click it ^> Install ^> Local Machine
echo     - Choose "Trusted Root Certification Authorities"
echo     - Restart your browser
echo.
echo ==========================================================
echo.

set /p ready="Press ENTER when the Rust API is running (cargo run --release -- api)..."

echo.
echo [ZeroTrust] Starting MITM proxy on port 8888...
echo [ZeroTrust] Approval dashboard will open at http://localhost:9091
echo.
echo Press Ctrl+C to stop.
echo.

:: Open the dashboard in the browser after a short delay
start /b cmd /c "timeout /t 2 >nul && start http://localhost:9091"

:: Run mitmproxy in dump mode (no interactive UI, just logs to console)
mitmdump -s mitm/interceptor.py --listen-port 8888

pause