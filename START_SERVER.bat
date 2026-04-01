@echo off
title TQS ERP Server (PO + WO)
echo ==========================================
echo   TQS ERP - Merged Tracker Server
echo   Port 3000 - Single DB: tqs_erp.db
echo ==========================================
echo.

:: Kill any existing Node.js process on port 3000 first
echo Checking for existing server on port 3000...
for /f "tokens=5" %%a in ('netstat -ano 2^>nul ^| findstr ":3000 " ^| findstr "LISTENING"') do (
  echo Found existing process (PID: %%a) - stopping it...
  taskkill /PID %%a /F >nul 2>&1
  timeout /t 2 /nobreak >nul
)
echo Port 3000 is free. Starting server...
echo.

:: Check for node_modules
if not exist "node_modules" (
  echo node_modules not found - running npm install...
  npm install
  echo.
)

echo Current folder: %CD%
echo.

:: Start the server
node server.js
pause
