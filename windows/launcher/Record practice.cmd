@echo off
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0"
if not exist "overwatch-decoder-observer.exe" goto missing
if not exist "private-recipe.json" goto missing
set "OVERWATCH_DECODER_LAUNCH_SECONDS=600"
if not "%~1"=="" set "OVERWATCH_DECODER_LAUNCH_SECONDS=%~1"
set "OVERWATCH_DECODER_LAUNCH_PID="
set "OVERWATCH_DECODER_LAUNCH_ID="
for /f "tokens=1-3 delims=," %%A in ('powershell.exe -NoProfile -NonInteractive -Command "$ErrorActionPreference='Stop';try{$seconds=0;if(-not [int]::TryParse($env:OVERWATCH_DECODER_LAUNCH_SECONDS,[ref]$seconds) -or $seconds -lt 1 -or $seconds -gt 600){throw 'Duration must be an integer from 1 to 600 seconds.'};$recipe=Get-Content -Raw -LiteralPath './private-recipe.json' | ConvertFrom-Json;$name=[IO.Path]::GetFileNameWithoutExtension($recipe.target.image_name);$targets=@(Get-Process | Where-Object {$_.ProcessName -ceq $name});if($targets.Count -ne 1){throw 'Start the supported game first. Exactly one matching process must be running.'};[Console]::WriteLine(('{0},{1},{2}' -f $targets[0].Id,$seconds,[Guid]::NewGuid().ToString('N')))}catch{[Console]::Error.WriteLine($_.Exception.Message);exit 1}"') do (
  set "OVERWATCH_DECODER_LAUNCH_PID=%%A"
  set "OVERWATCH_DECODER_LAUNCH_SECONDS=%%B"
  set "OVERWATCH_DECODER_LAUNCH_ID=%%C"
)
if not defined OVERWATCH_DECODER_LAUNCH_PID goto failed
if not defined OVERWATCH_DECODER_LAUNCH_ID goto failed
set "OVERWATCH_DECODER_LAUNCH_ROOT=%LOCALAPPDATA%\OverwatchDecoder\recordings"
if not exist "%OVERWATCH_DECODER_LAUNCH_ROOT%" mkdir "%OVERWATCH_DECODER_LAUNCH_ROOT%"
if not exist "%OVERWATCH_DECODER_LAUNCH_ROOT%" goto failed
set "OVERWATCH_DECODER_LAUNCH_OUT=%OVERWATCH_DECODER_LAUNCH_ROOT%\practice-%OVERWATCH_DECODER_LAUNCH_ID%"
echo Recording the supported Practice Range recipe for up to %OVERWATCH_DECODER_LAUNCH_SECONDS% seconds.
echo Live JSON: %OVERWATCH_DECODER_LAUNCH_OUT%.live.jsonl
echo Full recording: %OVERWATCH_DECODER_LAUNCH_OUT%
echo Press Ctrl+C to stop early. Gaps and unknown values remain in the recording.
echo.
"%~dp0overwatch-decoder-observer.exe" observe-fields --pid %OVERWATCH_DECODER_LAUNCH_PID% --recipe "%~dp0private-recipe.json" --out "%OVERWATCH_DECODER_LAUNCH_OUT%" --seconds %OVERWATCH_DECODER_LAUNCH_SECONDS% --interval-ms 20 --jsonl true > "%OVERWATCH_DECODER_LAUNCH_OUT%.live.jsonl" 2> "%OVERWATCH_DECODER_LAUNCH_OUT%.stderr.txt"
set "OVERWATCH_DECODER_LAUNCH_RESULT=%errorlevel%"
echo.
echo Recorder finished with exit code %OVERWATCH_DECODER_LAUNCH_RESULT%.
echo Live JSON: %OVERWATCH_DECODER_LAUNCH_OUT%.live.jsonl
echo Session status: %OVERWATCH_DECODER_LAUNCH_OUT%\manifest.json
if not "%OVERWATCH_DECODER_LAUNCH_RESULT%"=="0" type "%OVERWATCH_DECODER_LAUNCH_OUT%.stderr.txt"
goto finish
:missing
echo Keep overwatch-decoder-observer.exe and the supported private-recipe.json beside this launcher.
goto failed
:failed
set "OVERWATCH_DECODER_LAUNCH_RESULT=1"
:finish
if not "%OVERWATCH_DECODER_LAUNCH_NO_PAUSE%"=="1" pause
exit /b %OVERWATCH_DECODER_LAUNCH_RESULT%
