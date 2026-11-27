@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
pushd "%SCRIPT_DIR%" >nul || exit /b 1

rem Official release entrypoint.   Usage: build.cmd [--no-publish]
rem   build.cmd               preflight (clean, pushed, default branch, changelog) -> tests -> NativeAOT -> privacy gate
rem                           -> release commit + tag -> GitHub release with the zipped .\Compiled folder.
rem   build.cmd --no-publish  clean local release build into .\Compiled, nothing touches git or GitHub.
rem Exit codes: 0 = OK, 1 = build failed / refused, 2 = built but GitHub release incomplete.
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
