@echo off
echo ================================================
echo   Zero Trust AI Execution Framework - Windows
echo ================================================
echo.

:: Check if Rust is installed
where cargo >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Rust/Cargo not found. Please install from https://rustup.rs
    pause
    exit /b 1
)

echo [1] Building project...
cargo build --release
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Build failed. Check errors above.
    pause
    exit /b 1
)

echo.
echo [2] Build successful!
echo.
echo Choose a mode to run:
echo   1. Run CLI prompt test
echo   2. Start ALL services (API + Dashboard + Proxy)
echo   3. Start API only (port 5000)
echo   4. Start Dashboard only (port 9090)
echo   5. Start Proxy only (port 8080)
echo   6. View logs
echo.
set /p choice="Enter choice (1-6): "

if "%choice%"=="1" (
    set /p prompt="Enter your prompt: "
    cargo run --release -- run %prompt%
) else if "%choice%"=="2" (
    echo Starting all services...
    echo  - API:       http://localhost:5000/check
    echo  - Dashboard: http://localhost:9090
    echo  - Proxy:     http://localhost:8080
    cargo run --release -- all
) else if "%choice%"=="3" (
    cargo run --release -- api
) else if "%choice%"=="4" (
    cargo run --release -- dashboard
) else if "%choice%"=="5" (
    cargo run --release -- proxy
) else if "%choice%"=="6" (
    cargo run --release -- logs
) else (
    echo Invalid choice.
)

pause