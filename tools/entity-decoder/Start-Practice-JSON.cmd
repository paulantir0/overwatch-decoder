@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-Practice-JSON.ps1" %*
exit /b %ERRORLEVEL%
