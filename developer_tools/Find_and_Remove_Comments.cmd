@echo off
setlocal
pushd "%~dp0.." || exit /b 1
dotnet run --project "%~dp0CommentRemover\CommentRemover.csproj" -c Release -- %*
set "SAN_RESULT=%ERRORLEVEL%"
popd
echo %CMDCMDLINE% | find /i "%~nx0" >nul && pause
exit /b %SAN_RESULT%
