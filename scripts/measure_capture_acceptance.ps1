# Run from PowerShell on Windows. This starts only the configured recorder.
# The selected game is already running; no focus, game input or matchmaking occurs here.
param(
    [Parameter(Mandatory=$true)][string]$PackageDirectory,
    [Parameter(Mandatory=$true)][string]$ExpectedExecutableSha256,
    [ValidateRange(30,300)][int]$Seconds = 85,
    [string]$OutputRoot = 'C:\OverwatchDecoder-Recorder-Acceptance'
)
$ErrorActionPreference = 'Stop'
$package = [IO.Path]::GetFullPath($PackageDirectory)
$root = [IO.Path]::GetFullPath($OutputRoot).TrimEnd('\')
if ($root.Contains('"') -or $root.EndsWith(':')) { throw 'Choose an ordinary output folder, not a drive root.' }
$executable = Join-Path $package 'Overwatch Decoder Recorder.exe'
if ((Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ExpectedExecutableSha256.ToLowerInvariant()) { throw 'Recorder executable digest mismatch.' }
$settings = Get-Content -LiteralPath (Join-Path $package 'capture-settings.json') -Raw | ConvertFrom-Json
if ($null -eq $settings.Observations) { throw 'An explicitly configured and pinned observation plan is required.' }
if (@($settings.Memory).Count -ne 0 -or $null -ne $settings.Roster) { throw 'This focused acceptance run requires Memory=[] and Roster=null.' }
if ($settings.Observations.MaximumWindows -ne 1 -or $settings.Observations.WindowSeconds -ne 20) { throw 'First acceptance uses one 20-second producer window.' }
New-Item -ItemType Directory -Path $root -Force | Out-Null
$runId = [Guid]::NewGuid().ToString('N')
$log = Join-Path $root ('resource-acceptance-' + $runId + '.jsonl')
$frequency = [Diagnostics.Stopwatch]::Frequency
$writer = New-Object IO.StreamWriter($log, $false, (New-Object Text.UTF8Encoding($false)))
$target = @(Get-Process -Name $settings.TargetProcess -ErrorAction SilentlyContinue)
if ($target.Count -ne 1) { $writer.Dispose(); throw 'Exactly one configured game process must already be running.' }
$selectedTargetPid = $target[0].Id
$before = [Diagnostics.Stopwatch]::GetTimestamp()
# The root cannot contain a quote and has no trailing slash, so the quoted native
# argument remains one path. There is no shell command or arbitrary child command.
$arguments = '--auto-record-seconds ' + $Seconds + ' --output-root "' + $root + '"'
$recorder = Start-Process -FilePath $executable -WorkingDirectory $package -ArgumentList $arguments -PassThru
try {
    $writer.WriteLine((@{ kind='acceptance_start'; recorder_pid=$recorder.Id; target_pid=$selectedTargetPid; qpc_ticks=$before; qpc_frequency=$frequency; executable_sha256=$ExpectedExecutableSha256; capture_scope=$settings.Observations.CaptureScope; capture_seconds=$Seconds; producer_seconds=20; sampler='CIM parent graph and Process cumulative counters; no frame-rate or zero-overhead claim' } | ConvertTo-Json -Compress))
    $writer.Flush()
    while (-not $recorder.HasExited) {
        $qpcBefore = [Diagnostics.Stopwatch]::GetTimestamp()
        if (($qpcBefore-$before)/$frequency -gt $Seconds+120) {
            $writer.WriteLine((@{kind='acceptance_timeout';qpc_ticks=$qpcBefore;recorder_pid=$recorder.Id;action='Use the recorder Stop and save UI; this sampler does not force-kill it or the game.'} | ConvertTo-Json -Compress)); $writer.Flush()
            throw ('Recorder exceeded acceptance deadline; owned recorder PID ' + $recorder.Id + ' remains tracked for normal Stop and save.')
        }
        $inventory = @(Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId)
        $owned = New-Object 'System.Collections.Generic.HashSet[int]'
        [void]$owned.Add($recorder.Id)
        do {
            $added = $false
            foreach ($node in $inventory) {
                if ($owned.Contains([int]$node.ParentProcessId) -and $owned.Add([int]$node.ProcessId)) { $added=$true }
            }
        } while ($added)
        $samples = @()
        foreach ($processId in @($owned) + @($selectedTargetPid, $PID)) {
            try {
                $process = Get-Process -Id $processId -ErrorAction Stop
                $samples += @{ pid=$process.Id; name=$process.ProcessName; role=$(if ($process.Id -eq $selectedTargetPid) {'selected_game'} elseif ($process.Id -eq $PID) {'sampler'} else {'owned_recorder_tree'}); cpu_seconds=$process.TotalProcessorTime.TotalSeconds; working_set_bytes=$process.WorkingSet64; start_utc=$process.StartTime.ToUniversalTime().ToString('o') }
            } catch { $samples += @{pid=$processId;status="unavailable";error_type=$_.Exception.GetType().FullName} }
        }
        $writer.WriteLine((@{kind='acceptance_resources';qpc_before=$qpcBefore;qpc_after=[Diagnostics.Stopwatch]::GetTimestamp();processes=$samples} | ConvertTo-Json -Depth 5 -Compress)); $writer.Flush()
        Start-Sleep -Milliseconds 1000
        $recorder.Refresh()
    }
    $writer.WriteLine((@{kind='acceptance_exit';qpc_ticks=[Diagnostics.Stopwatch]::GetTimestamp();recorder_exit_code=$recorder.ExitCode} | ConvertTo-Json -Compress)); $writer.Flush()
} finally { $writer.Dispose() }
Write-Output ('Resource evidence: ' + $log)
Write-Output ('Capture folders: ' + $root)
