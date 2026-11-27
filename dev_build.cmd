@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
pushd "%SCRIPT_DIR%" >nul || exit /b 1

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%developer_tools\BuildLog.ps1" -ScriptPath ".\build\BuildPipeline.ps1" --dev %*
set "RC=%ERRORLEVEL%"
popd >nul
exit /b %RC%
