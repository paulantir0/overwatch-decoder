param([ValidateRange(20,60)][int]$Seconds=45)
$ErrorActionPreference='Stop'
$bundle=$PSScriptRoot
$config=Get-Content -Raw -LiteralPath (Join-Path $bundle 'config.json') | ConvertFrom-Json
if ([string]::IsNullOrWhiteSpace($config.python_relative_path) -or [IO.Path]::IsPathRooted($config.python_relative_path)) { throw 'A relative embedded Python path is required' }
$python=Join-Path $env:LOCALAPPDATA $config.python_relative_path
if (-not (Test-Path -LiteralPath $python)) { throw 'Pinned embedded Python is unavailable' }
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $python).Hash.ToLowerInvariant() -ne $config.python_sha256) { throw 'Python SHA256 changed' }
if ([string]::IsNullOrWhiteSpace($config.target_process_name)) { throw 'Target process name is required' }
$targets=@(Get-Process -Name $config.target_process_name -ErrorAction SilentlyContinue)
if ($targets.Count -ne 1) { throw 'Exactly one configured target process is required' }
$recordings=Join-Path $env:LOCALAPPDATA 'OverwatchDecoder\recordings'
New-Item -ItemType Directory -Path $recordings -Force | Out-Null
$leaf='practice-json-'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff')+'-'+([Guid]::NewGuid().ToString('N').Substring(0,8))
$output=Join-Path $recordings $leaf
$runner=Join-Path $bundle 'run_selected_roster.py'
Write-Host 'Controlled Practice Range JSON observation. No game input or focus changes.'
Write-Host ('Output: '+$output)
$arguments='"'+$runner+'" --pid '+$targets[0].Id+' --seconds '+$Seconds+' --interval-ms 50 --practice-range --output "'+$output+'"'
# Retain the native process handle before waiting. Start-Process wrappers can
# lose ExitCode after a short-lived child has already exited.
$startInfo=New-Object System.Diagnostics.ProcessStartInfo
$startInfo.FileName=$python
$startInfo.Arguments=$arguments
$startInfo.WorkingDirectory=$bundle
$startInfo.UseShellExecute=$false
$process=New-Object System.Diagnostics.Process
$process.StartInfo=$startInfo
try {
 if (-not $process.Start()) { throw 'Could not start selected JSON parent' }
 $null=$process.Handle
 try { $process.PriorityClass='BelowNormal' } catch { Write-Host ('Priority assignment failed: '+$_.Exception.Message) }
 $process.WaitForExit()
 $code=$process.ExitCode
 if ($null -eq $code) { throw 'Child exit code unavailable; completion cannot be reported' }
 Write-Host ('Finished with exit code '+$code+'. Output: '+$output)
} finally {
 $process.Dispose()
}
exit $code
