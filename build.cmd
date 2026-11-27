@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
pushd "%SCRIPT_DIR%" >nul || exit /b 1

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%developer_tools\BuildLog.ps1" -ScriptPath ".\build\BuildPipeline.ps1" %*
set "RC=%ERRORLEVEL%"
if "%RC%"=="1" (
  echo.
  echo ###########################################################
  echo  BUILD FAILED - nothing was published.
  echo  Scroll up for the first ERROR line, or read .\developer_tools\build.log
  echo ###########################################################
)
popd >nul
exit /b %RC%
