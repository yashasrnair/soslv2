@echo off
echo ================================================
echo   Zero Trust AI Firewall v5 — Rust Engine
echo ================================================
echo.

:: Check if Rust is installed
where cargo >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Rust/Cargo not found. Please install from https://rustup.rs
    pause
    exit /b 1
)

echo [1/2] Building project (release mode)...
cargo build --release
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Build failed. Check errors above.
    pause
    exit /b 1
)

echo.
echo [2/2] Build successful!
echo.
echo ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo  Choose a mode:
echo.
echo   1. Run CLI prompt test
echo   2. Start API only        (port 5000)  ← start this first for MITM
echo   3. Start Rust Dashboard  (port 9090)
echo   4. Start HTTP Proxy      (port 8080)
echo   5. Start ALL services    (API + Dashboard + Proxy)
echo   6. Run test scenarios
echo   7. View logs
echo ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo.
set /p choice="Enter choice (1-7): "

if "%choice%"=="1" (
    set /p prompt="Enter your prompt: "
    cargo run --release -- run %prompt%
) else if "%choice%"=="2" (
    echo.
    echo Starting Rust API on port 5000...
    echo Then run run_mitm.bat in a second window.
    echo.
    cargo run --release -- api
) else if "%choice%"=="3" (
    cargo run --release -- dashboard
) else if "%choice%"=="4" (
    cargo run --release -- proxy
) else if "%choice%"=="5" (
    echo Starting all services...
    echo  - API:       http://localhost:5000/check
    echo  - Dashboard: http://localhost:9090  (Rust engine blocks)
    echo  - Proxy:     http://localhost:8080
    echo  - MITM dash: http://localhost:9091  (run run_mitm.bat separately)
    cargo run --release -- all
) else if "%choice%"=="6" (
    cargo run --release -- test
) else if "%choice%"=="7" (
    cargo run --release -- logs
) else (
    echo Invalid choice.
)

pause
