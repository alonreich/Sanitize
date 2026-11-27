@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
pushd "%SCRIPT_DIR%" >nul || exit /b 1

rem Local dev build: unit tests + NativeAOT compile into .\Compiled. No git tags, no GitHub release,
rem and .\Compiled is not wiped first. Output mirrored to .\developer_tools\build.log (first line = verdict).
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%developer_tools\BuildLog.ps1" -ScriptPath ".\build\BuildPipeline.ps1" --dev %*
set "RC=%ERRORLEVEL%"
popd >nul
exit /b %RC%
