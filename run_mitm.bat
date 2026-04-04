@echo off
echo =====================================================
echo   Zero Trust AI Firewall v5 — MITM Launcher
echo =====================================================
echo.

:: ── Check Python ──
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python not found. Download from https://www.python.org/downloads/
    pause & exit /b 1
)

:: ── Install mitmproxy if needed ──
python -c "import mitmproxy" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [INFO] Installing mitmproxy...
    pip install mitmproxy
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Failed to install mitmproxy.
        pause & exit /b 1
    )
)

:: ── Install brotli for brotli-compressed responses (optional but recommended) ──
python -c "import brotli" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [INFO] Installing brotli (optional, for brotli-compressed responses)...
    pip install brotli >nul 2>&1
)

echo.
echo =================================================================
echo  SETUP (do this ONCE before running — skip if already done)
echo =================================================================
echo.
echo  STEP 1 — Configure Windows proxy:
echo    Settings ^> Network ^& Internet ^> Proxy
echo    ^> Manual proxy setup ^> Turn ON
echo    HTTP/HTTPS Proxy: 127.0.0.1   Port: 8888
echo    Bypass:           localhost;127.0.0.1
echo.
echo  STEP 2 — Install HTTPS certificate (first time only):
echo    a) With proxy ON, open Chrome and visit:  http://mitm.it
echo    b) Click "Windows" to download the cert
echo    c) Double-click ^> Install Certificate ^> Local Machine
echo    d) Select "Trusted Root Certification Authorities"
echo    e) Finish, then RESTART your browser
echo.
echo  STEP 3 — Install the Chrome extension:
echo    a) Open Chrome ^> Settings ^> Extensions ^> Developer mode ON
echo    b) Click "Load unpacked" and select the "extension" folder
echo       in this project directory
echo.
echo =================================================================
echo.

set /p ready="Press ENTER when the Rust API is running (run.bat ^> option 3)..."

echo.
echo [ZeroTrust v5] Starting MITM proxy on port 8888...
echo [ZeroTrust v5] Python approval dashboard  ^> http://localhost:9091
echo [ZeroTrust v5] Rust engine dashboard      ^> http://localhost:9090
echo [ZeroTrust v5] Chrome extension           ^> Install from ./extension/
echo.
echo Press Ctrl+C to stop.
echo.

:: Open the dashboard in the browser after short delay
start /b cmd /c "timeout /t 3 >nul && start http://localhost:9091"

:: Run mitmproxy in dump mode (logs to console, no interactive UI)
mitmdump -s mitm/interceptor.py --listen-port 8888 --ssl-insecure

pause
