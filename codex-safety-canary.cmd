@echo off
setlocal EnableExtensions
chcp 65001 >nul 2>nul
set "SCRIPT_DIR=%~dp0"
set "APP=%SCRIPT_DIR%bin\codex-safety-canary.mjs"
set "CODEX_NODE=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe"

where node.exe >nul 2>nul
if %ERRORLEVEL%==0 (
  set "NODE_EXE=node.exe"
  set "CANARY_NODE_SOURCE=PATH"
) else if exist "%CODEX_NODE%" (
  set "NODE_EXE=%CODEX_NODE%"
  set "CANARY_NODE_SOURCE=Codex bundled runtime"
) else (
  echo.
  echo Node.js was not found.
  echo Install Node.js 18 or newer, then run this launcher again.
  echo.
  pause
  exit /b 1
)

"%NODE_EXE%" -e "process.exit(Number(process.versions.node.split('.')[0]) >= 18 ? 0 : 1)" >nul 2>nul
if errorlevel 1 (
  echo.
  echo Node.js 18 or newer is required.
  echo Detected executable: "%NODE_EXE%"
  echo.
  pause
  exit /b 1
)

"%NODE_EXE%" "%APP%" %*
set "EXIT_CODE=%ERRORLEVEL%"
if not "%EXIT_CODE%"=="0" (
  echo.
  echo The Canary stopped with exit code %EXIT_CODE%.
  echo No real project files were used by its live probes.
  echo.
  pause
)
exit /b %EXIT_CODE%
