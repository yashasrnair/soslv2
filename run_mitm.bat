@echo off
echo =====================================================
echo   Zero Trust MITM Setup ^& Launcher (Windows)
echo =====================================================
echo.

:: ── Check Python ──
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python not found.
    echo Download from https://www.python.org/downloads/
    pause & exit /b 1
)

:: ── Install mitmproxy if needed ──
python -c "import mitmproxy" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [INFO] Installing mitmproxy...
    pip install mitmproxy requests
)

python -c "import requests" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    pip install requests
)

echo.
echo [STEP 1] Build the Rust engine first (if not already built)
echo          Run:  cargo build --release
echo.
echo [STEP 2] In a SEPARATE terminal, start the Rust API:
echo          cargo run --release -- api
echo.
echo [STEP 3] This script will now start the MITM proxy on port 8888
echo          AND the approval dashboard on http://localhost:9091
echo.

set /p ready="Press ENTER when the Rust API is running on port 5000..."

echo.
echo [ZeroTrust] Starting mitmproxy on port 8888...
echo [ZeroTrust] Approval dashboard will be at http://localhost:9091
echo.
echo ── IMPORTANT: Configure Windows proxy settings ──
echo    Settings ^> Network ^& Internet ^> Proxy ^> Manual proxy setup
echo    HTTP:  127.0.0.1   Port: 8888
echo    HTTPS: 127.0.0.1   Port: 8888
echo    Toggle "Use a proxy server" ON
echo.
echo ── HTTPS Certificate (first-time only) ──
echo    With proxy enabled, visit:  http://mitm.it
echo    Click Windows → Download certificate
echo    Double-click it → Install → "Local Machine"
echo    → "Place all certificates in: Trusted Root Certification Authorities"
echo    Restart your browser after installing.
echo.

:: Start mitmproxy (non-interactive mode, addon only)
mitmdump -s mitm/interceptor.py --listen-port 8888 --ssl-insecure

pause