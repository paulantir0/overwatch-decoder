#requires -Version 5.1
# Runs one private, pinned recorder in the caller's interactive Windows session.
# The only UI action is InvokePattern on that recorder's FinishDataChunk button.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$PackageDirectory,
    [Parameter(Mandatory=$true)][string]$OutputRoot,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedExecutableSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedSettingsSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedPackageInventorySha256,
    [Parameter(Mandatory=$true)][ValidateSet('0','8')][int]$ExpectedLeadSeconds
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-LocalPath([string]$Path) {
    if ($Path -notmatch '^[A-Za-z]:[\\/]' -or $Path.Substring(2) -match '[\x00-\x1f<>:"|?*\[\]]') {
        throw 'Use a full ordinary local drive path.'
    }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd([char[]]@('\','/'))
    if ($full.Length -le 3) { throw 'A drive root cannot be used.' }
    foreach ($segment in ($full.Substring(3) -split '[\\/]')) {
        if ($segment -match '[. ]$') { throw 'Use unambiguous path components.' }
    }
    return $full
}

function Assert-PlainPath([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse points are forbidden.' }
        $item = if ($item -is [IO.FileInfo]) { $item.Directory } else { $item.Parent }
    }
}

function Test-Inside([string]$Path, [string]$Parent) {
    return $Path.Equals($Parent, [StringComparison]::OrdinalIgnoreCase) -or
        $Path.StartsWith($Parent + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Read-BoundedJson([string]$Path, [long]$Limit) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item -isnot [IO.FileInfo] -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Invalid bounded JSON file.'
    }
    # The recorder replaces session.json atomically. A reader must allow the
    # writer's rename and retain a consistent handle to the original bytes.
    $share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, $share)
    try {
        $length = $stream.Length
        if ($length -le 0 -or $length -gt $Limit) { throw 'Bounded JSON length mismatch.' }
        $bytes = [byte[]]::new([int]$length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -eq 0) { throw 'JSON file truncated during read.' }
            $offset += $read
        }
        if ($stream.ReadByte() -ne -1) { throw 'JSON file grew during read.' }
        return [Text.UTF8Encoding]::new($false, $true).GetString($bytes) | ConvertFrom-Json
    } finally { $stream.Dispose() }
}

function Read-SealedPackage([string]$Package, [string]$InventoryHash) {
    $inventoryPath = Join-Path $Package 'package-inventory.json'
    Assert-PlainPath $inventoryPath
    if ((Get-FileHash -LiteralPath $inventoryPath -Algorithm SHA256).Hash -ine $InventoryHash) { throw 'Package inventory digest mismatch.' }
    $inventory = Read-BoundedJson $inventoryPath 4MB
    if ($inventory.schema -cne 'overwatch-decoder.private.match-capture-package/1' -or
        $inventory.files.Count -lt 1 -or $inventory.files.Count -gt 4096) { throw 'Unsupported package inventory.' }

    $listed = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    [long]$declaredBytes = 0
    foreach ($row in $inventory.files) {
        $name = $row.path
        if ($name -isnot [string] -or $name -match '[\\:\x00-\x1f<>"|?*\[\]]' -or
            @($name.Split('/') | Where-Object { $_ -eq '' -or $_ -match '[. ]$' }).Count -ne 0 -or
            $row.sha256 -isnot [string] -or $row.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            ($row.size -isnot [int] -and $row.size -isnot [long]) -or $row.size -lt 0 -or
            $listed.ContainsKey($name) -or $name -ieq 'package-inventory.json') { throw 'Invalid inventory entry.' }
        $declaredBytes += $row.size
        if ($declaredBytes -gt 1GB) { throw 'Package size bound.' }
        $listed.Add($name, $row)
    }

    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $folders = [Collections.Generic.Stack[string]]::new()
    $folders.Push($Package)
    $entries = 0
    while ($folders.Count -gt 0) {
        foreach ($item in Get-ChildItem -LiteralPath ($folders.Pop()) -Force) {
            $entries++
            if ($entries -gt 8192 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Package entry bound or link.' }
            if ($item.PSIsContainer) { $folders.Push($item.FullName); continue }
            $relative = $item.FullName.Substring($Package.Length + 1).Replace('\','/')
            if ($relative -ieq 'package-inventory.json') { continue }
            if (-not $listed.ContainsKey($relative) -or -not $seen.Add($relative) -or
                $item.Length -ne $listed[$relative].size -or
                (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash -ine $listed[$relative].sha256) {
                throw "Package file mismatch: $relative"
            }
        }
    }
    if ($seen.Count -ne $listed.Count) { throw 'Package inventory has missing files.' }
    return ,$listed
}

function Get-ProcessSample([int]$ProcessId, [long]$ExpectedStart, [string]$Role, [int]$ParentId = 0) {
    $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($null -eq $process) { return [pscustomobject]@{ pid=$ProcessId; role=$Role; state='exited' } }
    try {
        if ($process.HasExited) { return [pscustomobject]@{ pid=$ProcessId; role=$Role; state='exited' } }
        $started = $process.StartTime.ToUniversalTime()
        if ($ExpectedStart -ne 0 -and $started.Ticks -ne $ExpectedStart) {
            return [pscustomobject]@{ pid=$ProcessId; role=$Role; state='replaced' }
        }
        return [pscustomobject]@{
            pid=$ProcessId; name=$process.ProcessName; role=$Role; state='alive'; parent_pid=$ParentId
            session_id=$process.SessionId; start_utc_ticks=$started.Ticks; start_utc=$started.ToString('o')
            cpu_seconds=$process.TotalProcessorTime.TotalSeconds; working_set_bytes=$process.WorkingSet64
        }
    } catch {
        return [pscustomobject]@{ pid=$ProcessId; role=$Role; state='unavailable'; error_type=$_.Exception.GetType().Name }
    } finally { $process.Dispose() }
}

function Get-OwnedSamples($Tracked, [int]$SessionId) {
    $observed = [Collections.Generic.List[object]]::new()
    $parents = @{}
    foreach ($lifetime in @($Tracked.Values)) {
        $sample = Get-ProcessSample $lifetime.pid $lifetime.start_utc_ticks 'owned_recorder_tree' $lifetime.parent_pid
        if ($sample.state -eq 'alive') { $parents[$sample.pid] = $sample; $observed.Add($sample) }
        elseif ($sample.state -eq 'unavailable') { $observed.Add($sample) }
    }
    $graph = @(Get-CimInstance Win32_Process -Filter "SessionId = $SessionId" -Property ProcessId,ParentProcessId,CreationDate -OperationTimeoutSec 5)
    if ($graph.Count -gt 2048) { throw 'Resource process graph bound.' }
    $checked = [Collections.Generic.HashSet[int]]::new()
    do {
        $added = $false
        foreach ($node in $graph) {
            $childId = [int]$node.ProcessId
            $parentId = [int]$node.ParentProcessId
            if ($parents.ContainsKey($childId) -or -not $parents.ContainsKey($parentId) -or -not $checked.Add($childId)) { continue }
            $sample = Get-ProcessSample $childId 0 'owned_recorder_tree' $parentId
            if ($sample.state -ne 'alive') { $observed.Add($sample); continue }
            # CIM CreationDate has lower precision than GetProcessTimes. This
            # comparison excludes a reused PID from a stale graph snapshot.
            if ($sample.session_id -ne $SessionId -or $sample.start_utc_ticks -lt $parents[$parentId].start_utc_ticks -or
                $node.CreationDate -isnot [datetime] -or
                [Math]::Abs($sample.start_utc_ticks - $node.CreationDate.ToUniversalTime().Ticks) -gt 10000) { continue }
            $key = '{0}/{1}' -f $childId,$sample.start_utc_ticks
            $Tracked[$key] = $sample
            if ($Tracked.Count -gt 256) { throw 'Owned lifetime tracking bound.' }
            $parents[$childId] = $sample
            $observed.Add($sample)
            $added = $true
        }
    } while ($added)
    return $observed.ToArray()
}

function Get-RecorderWindow($Recorder, [long]$RecorderStart) {
    $Recorder.Refresh()
    if ($Recorder.HasExited -or $Recorder.StartTime.ToUniversalTime().Ticks -ne $RecorderStart -or
        $Recorder.MainWindowHandle -eq [IntPtr]::Zero) { return $null }
    $window = [System.Windows.Automation.AutomationElement]::FromHandle($Recorder.MainWindowHandle)
    if ($window.Current.ProcessId -ne $Recorder.Id -or $window.Current.Name -cne 'Overwatch Decoder Recorder') { return $null }
    return $window
}

function Get-RecorderButton($Window, [int]$ProcessId, [string]$AutomationId) {
    $condition = [System.Windows.Automation.AndCondition]::new([System.Windows.Automation.Condition[]]@(
        [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $ProcessId),
        [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::AutomationIdProperty, $AutomationId),
        [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)
    ))
    $elements = $Window.FindAll([System.Windows.Automation.TreeScope]::Descendants, $condition)
    if ($elements.Count -gt 1) { throw "Ambiguous recorder button: $AutomationId" }
    if ($elements.Count -eq 1) { return $elements[0] }
    return $null
}

function Get-UiSnapshot($Window, [int]$ProcessId, [string]$Phase) {
    $buttons = [ordered]@{}
    foreach ($id in @('StartRecording','FinishDataChunk','StopRecording')) {
        $button = Get-RecorderButton $Window $ProcessId $id
        if ($null -eq $button) { $buttons[$id] = $null; continue }
        $buttons[$id] = @{ name=$button.Current.Name; enabled=$button.Current.IsEnabled; offscreen=$button.Current.IsOffscreen }
    }
    $textCondition = [System.Windows.Automation.PropertyCondition]::new(
        [System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Text)
    $texts = $Window.FindAll([System.Windows.Automation.TreeScope]::Descendants, $textCondition)
    if ($texts.Count -gt 128) { throw 'Recorder UI snapshot bound.' }
    $labels = @(foreach ($element in $texts) {
        $label = $element.Current.Name
        if ($element.Current.ProcessId -eq $ProcessId -and -not [string]::IsNullOrWhiteSpace($label)) {
            $label.Substring(0, [Math]::Min(512, $label.Length))
        }
    })
    return [ordered]@{
        kind='acceptance_ui'; phase=$Phase; recorder_pid=$ProcessId; qpc_ticks=[Diagnostics.Stopwatch]::GetTimestamp()
        title=$Window.Current.Name; buttons=$buttons; text=$labels
        recording_text=@($labels | Where-Object { $_ -match '^Recording' })
        progress_text=@($labels | Where-Object { $_ -match 'verified windows' })
    }
}

function Get-FreshSession([string]$Root) {
    $folders = @(Get-ChildItem -LiteralPath $Root -Directory -Force)
    if ($folders.Count -eq 0) { return $null }
    if ($folders.Count -ne 1 -or $folders[0].Name -cnotmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2}_[a-f0-9]{8}$') {
        throw 'Ambiguous fresh recorder session.'
    }
    Assert-PlainPath $folders[0].FullName
    return $folders[0].FullName
}

function Read-SessionManifest([string]$Session, $Target, [string]$Revision, [long]$LaunchTick) {
    $path = Join-Path $Session 'session.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    $manifest = Read-BoundedJson $path 4MB
    if ($manifest.schema -cne 'overwatch-decoder.capture-session/1' -or $manifest.revision -cne $Revision -or
        $manifest.target_pid -ne $Target.pid -or [long]$manifest.target_start_utc_ticks -ne $Target.start_utc_ticks -or
        $manifest.qpc_frequency -ne [Diagnostics.Stopwatch]::Frequency -or $manifest.qpc_origin -lt $LaunchTick -or
        $manifest.qpc_origin -gt [Diagnostics.Stopwatch]::GetTimestamp()) { throw 'Recorder session identity or clock mismatch.' }
    return $manifest
}

function Write-Row($Value) {
    $writer.WriteLine(($Value | ConvertTo-Json -Depth 12 -Compress))
    $writer.Flush()
}

function Save-UiSnapshot([string]$Name, $Snapshot) {
    $path = Join-Path $root $Name
    $file = [IO.FileStream]::new($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Snapshot | ConvertTo-Json -Depth 12) + "`n")
        $file.Write($bytes, 0, $bytes.Length)
    } finally { $file.Dispose() }
    Write-Row $Snapshot
}

$package = Get-LocalPath $PackageDirectory
$root = Get-LocalPath $OutputRoot
if ((Test-Inside $root $package) -or (Test-Inside $package $root) -or (Test-Path -LiteralPath $root)) {
    throw 'Output must be a new directory outside the sealed package.'
}
Assert-PlainPath $package
Assert-PlainPath ([IO.Path]::GetDirectoryName($root))
$listed = Read-SealedPackage $package $ExpectedPackageInventorySha256
$exePath = Join-Path $package 'Overwatch Decoder Recorder.exe'
$settingsPath = Join-Path $package 'capture-settings.json'
foreach ($pair in @(@('Overwatch Decoder Recorder.exe',$ExpectedExecutableSha256), @('capture-settings.json',$ExpectedSettingsSha256))) {
    if (-not $listed.ContainsKey($pair[0]) -or $listed[$pair[0]].sha256 -ine $pair[1]) { throw 'Expected executable/settings pin differs from inventory.' }
}
$settings = Read-BoundedJson $settingsPath 64KB
$revisions = Read-BoundedJson (Join-Path $package 'package-revisions.json') 64KB
$plan = $settings.Observations
if ($null -eq $plan) { throw 'A pinned observation plan is required.' }
$lead = if ($null -eq $plan.PSObject.Properties['SuccessorLeadSeconds']) { 0 } else { $plan.SuccessorLeadSeconds }
if ($settings.TargetProcess -cne 'Overwatch' -or $settings.MaximumMinutes -ne 4 -or
    $settings.Memory -isnot [Array] -or $settings.Memory.Count -ne 0 -or $null -ne $settings.Roster -or
    $plan.CaptureScope -cne 'read_only_user_gameplay' -or $plan.StorageFormat -cne 'cohorts_v1' -or
    $plan.ContinueObservationWindows -isnot [bool] -or -not $plan.ContinueObservationWindows -or
    $plan.WindowSeconds -ne 45 -or $plan.MaximumWindows -ne 3 -or $plan.MaximumOutputMiB -ne 16384 -or
    $plan.StorageCohortMiB -ne 4 -or $lead -ne $ExpectedLeadSeconds) { throw 'Settings do not match the bounded serial/overlap trial.' }
if ($revisions.recorder_revision -cnotmatch '^[a-f0-9]{40}$' -or $revisions.recorder_sha256 -ine $ExpectedExecutableSha256 -or
    $revisions.settings_sha256 -ine $ExpectedSettingsSha256 -or $plan.InventorySha256 -cne $revisions.producer_inventory_sha256 -or
    $plan.PythonSha256 -cne $revisions.python_sha256 -or -not $listed.ContainsKey($plan.PythonExecutable) -or
    $listed[$plan.PythonExecutable].sha256 -cne $plan.PythonSha256 -or
    -not $listed.ContainsKey($plan.BundleDirectory + '/inventory.json') -or
    $listed[$plan.BundleDirectory + '/inventory.json'].sha256 -cne $plan.InventorySha256 -or
    -not $listed.ContainsKey($plan.BundleDirectory + '/' + $plan.Entrypoint) -or
    -not $listed.ContainsKey($settings.FfmpegPath) -or $listed[$settings.FfmpegPath].sha256 -cne $revisions.ffmpeg_sha256 -or
    -not $listed.ContainsKey($plan.BundleDirectory + '/sources/roster/native/overwatch-decoder-observer.exe') -or
    $listed[$plan.BundleDirectory + '/sources/roster/native/overwatch-decoder-observer.exe'].sha256 -cne $revisions.native_sha256) {
    throw 'Recorder, runtime, settings or producer package pins disagree.'
}

$caller = Get-ProcessSample $PID 0 'sampler'
if (-not [Environment]::UserInteractive -or $caller.state -ne 'alive' -or $caller.session_id -eq 0) {
    throw 'Use the interactive Windows desktop session.'
}
$targets = @(Get-Process -Name Overwatch -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $caller.session_id -and -not $_.HasExited })
if ($targets.Count -ne 1) { throw 'Exactly one Overwatch process must already be running in this session.' }
$target = Get-ProcessSample $targets[0].Id 0 'selected_game'
if ($target.state -ne 'alive' -or $target.session_id -ne $caller.session_id) { throw 'Cannot verify the selected target lifetime.' }
if (@(Get-Process -Name 'Overwatch Decoder Recorder' -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $caller.session_id }).Count -ne 0) {
    throw 'An existing Overwatch Decoder Recorder process already owns this desktop.'
}
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
# No -Force. Both the root and log must be new, and the source is never changed.
New-Item -ItemType Directory -Path $root | Out-Null
Assert-PlainPath $root
$log = Join-Path $root 'resource-acceptance.jsonl'
$writer = [IO.StreamWriter]::new([IO.FileStream]::new($log, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write), [Text.UTF8Encoding]::new($false))

$tracked = @{}
$recorder = $null
$session = $null
$initialSnapshot = $false
$finishAttempted = $false
$finishReturned = $false
$timedOut = $false
$failure = $null
$frequency = [Diagnostics.Stopwatch]::Frequency
$launchTick = [Diagnostics.Stopwatch]::GetTimestamp()
try {
    $recorderArgs = '--auto-record-seconds 180 --output-root "{0}"' -f $root
    $recorder = Start-Process -FilePath $exePath -WorkingDirectory $package -ArgumentList $recorderArgs -PassThru
    $ownedRoot = Get-ProcessSample $recorder.Id 0 'owned_recorder_tree'
    if ($ownedRoot.state -ne 'alive' -or $ownedRoot.session_id -ne $caller.session_id) { throw 'Cannot verify the launched recorder lifetime.' }
    $recorderStart = $ownedRoot.start_utc_ticks
    $tracked[('{0}/{1}' -f $ownedRoot.pid,$recorderStart)] = $ownedRoot
    Write-Row @{
        kind='acceptance_start'; recorder_pid=$ownedRoot.pid; recorder_start_utc_ticks=$recorderStart
        target_pid=$target.pid; target_start_utc_ticks=$target.start_utc_ticks
        qpc_ticks=$launchTick; qpc_frequency=$frequency; revision=$revisions.recorder_revision
        executable_sha256=$ExpectedExecutableSha256.ToLowerInvariant(); settings_sha256=$ExpectedSettingsSha256.ToLowerInvariant()
        package_inventory_sha256=$ExpectedPackageInventorySha256.ToLowerInvariant()
        capture_scope='read_only_user_gameplay'; capture_seconds=180; producer_seconds=45; producer_windows=3
        successor_lead_seconds=$ExpectedLeadSeconds; maximum_output_bytes=16GB; maximum_window_output_bytes=4GB
        sampler='CIM parent graph checked against process lifetimes and cumulative process counters'
    }
    while (-not $recorder.HasExited) {
        $before = [Diagnostics.Stopwatch]::GetTimestamp()
        if (($before - $launchTick) / $frequency -gt 225) {
            $timedOut = $true
            $failure = 'Recorder is still alive past the bounded acceptance deadline.'
            Write-Row @{ kind='acceptance_timeout'; qpc_ticks=$before; recorder_pid=$recorder.Id; recorder_start_utc_ticks=$recorderStart }
            break
        }
        $targetNow = Get-ProcessSample $target.pid $target.start_utc_ticks 'selected_game'
        $sampleError = $null
        $owned = @()
        try { $owned = @(Get-OwnedSamples $tracked $caller.session_id) }
        catch { $sampleError = $_.Exception.Message }
        Write-Row @{
            kind='acceptance_resources'; qpc_before=$before; qpc_after=[Diagnostics.Stopwatch]::GetTimestamp()
            processes=@($owned) + @($targetNow, (Get-ProcessSample $PID $caller.start_utc_ticks 'sampler')); sample_error=$sampleError
        }
        if ($targetNow.state -ne 'alive' -and $null -eq $failure) { $failure = 'Selected target lifetime could not be confirmed.' }
        if ($null -eq $failure -and -not $finishAttempted) {
            try {
                $candidate = Get-FreshSession $root
                if ($null -ne $candidate) {
                    if ($null -ne $session -and $candidate -cne $session) { throw 'The fresh session directory changed.' }
                    $session = $candidate
                    $manifest = Read-SessionManifest $session $target $revisions.recorder_revision $launchTick
                    if ($null -ne $manifest -and $manifest.status -ceq 'recording') {
                        $window = Get-RecorderWindow $recorder $recorderStart
                        if ($null -ne $window) {
                            if (-not $initialSnapshot) {
                                $snapshot = Get-UiSnapshot $window $recorder.Id 'after_start'
                                if ($null -ne $snapshot.buttons['FinishDataChunk'] -and $snapshot.buttons['FinishDataChunk'].enabled) {
                                    Save-UiSnapshot 'ui-after-start.json' $snapshot
                                    $initialSnapshot = $true
                                }
                            }
                            $third = Join-Path $session 'observations\window-0003'
                            if ($initialSnapshot -and (Test-Path -LiteralPath $third -PathType Container)) {
                                Assert-PlainPath $third
                                $button = Get-RecorderButton $window $recorder.Id 'FinishDataChunk'
                                if ($null -ne $button -and $button.Current.IsEnabled) {
                                    Save-UiSnapshot 'ui-before-finish.json' (Get-UiSnapshot $window $recorder.Id 'before_finish')
                                    $currentWindow = Get-RecorderWindow $recorder $recorderStart
                                    if ($null -eq $currentWindow) { throw 'The recorder lifetime changed before Finish.' }
                                    $button = Get-RecorderButton $currentWindow $recorder.Id 'FinishDataChunk'
                                    $pattern = $null
                                    if ($null -eq $button -or -not $button.Current.IsEnabled -or
                                        $button.Current.ProcessId -ne $recorder.Id -or $button.Current.AutomationId -cne 'FinishDataChunk' -or
                                        -not $button.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$pattern)) {
                                        throw 'The exact enabled FinishDataChunk button has no InvokePattern.'
                                    }
                                    $finishAttempted = $true
                                    Write-Row @{ kind='acceptance_finish_attempt'; window=3; automation_id='FinishDataChunk'; recorder_pid=$recorder.Id; qpc_ticks=[Diagnostics.Stopwatch]::GetTimestamp() }
                                    $pattern.Invoke()
                                    $finishReturned = $true
                                    Write-Row @{ kind='acceptance_finish_returned'; recorder_pid=$recorder.Id; qpc_ticks=[Diagnostics.Stopwatch]::GetTimestamp() }
                                }
                            }
                        }
                    }
                }
            } catch [System.Windows.Automation.ElementNotAvailableException] {
                if ($finishAttempted) { $failure = 'Finish invocation returned an unavailable element.' }
                Write-Row @{ kind='acceptance_ui_unavailable'; qpc_ticks=[Diagnostics.Stopwatch]::GetTimestamp(); finish_attempted=$finishAttempted }
            } catch {
                $failure = $_.Exception.Message
                Write-Row @{ kind='acceptance_observer_error'; qpc_ticks=[Diagnostics.Stopwatch]::GetTimestamp(); error=$failure }
            }
        }
        $wait = [int][Math]::Ceiling(1000 * ($before + $frequency - [Diagnostics.Stopwatch]::GetTimestamp()) / $frequency)
        if ($wait -gt 0) { Start-Sleep -Milliseconds $wait }
        $recorder.Refresh()
    }
} catch {
    $failure = $_.Exception.Message
} finally {
    try {
        $recorderExited = $null -ne $recorder -and $recorder.HasExited
        $exitCode = if ($recorderExited) { $recorder.ExitCode } else { $null }
        $cleanup = @(foreach ($lifetime in $tracked.Values) {
            $sample = Get-ProcessSample $lifetime.pid $lifetime.start_utc_ticks 'owned_recorder_tree' $lifetime.parent_pid
            @{ pid=$lifetime.pid; start_utc_ticks=$lifetime.start_utc_ticks; name=$lifetime.name; state=$sample.state }
        })
        $targetFinal = Get-ProcessSample $target.pid $target.start_utc_ticks 'selected_game'
        $saved = $null
        if ($null -ne $session) {
            try { $saved = Read-SessionManifest $session $target $revisions.recorder_revision $launchTick }
            catch { if ($null -eq $failure) { $failure = $_.Exception.Message } }
        }
        $remaining = @($cleanup | Where-Object { $_.state -in @('alive','unavailable') })
        if ($null -eq $failure -and (-not $finishReturned -or -not $recorderExited -or $exitCode -ne 0 -or
            $remaining.Count -ne 0 -or $targetFinal.state -ne 'alive' -or $null -eq $saved -or
            $saved.status -notin @('finished','finished_with_gaps') -or $saved.stop_reason -cne 'user_finish_data_chunk')) {
            $failure = 'Graceful Finish, recorder exit, or process cleanup was not verified.'
        }
        if ($null -eq $failure) {
            $observations = $saved.observations
            $mode = $observations.PSObject.Properties['overlapping_windows']
            if ($observations.attempted_windows -ne 3 -or $observations.maximum_windows -ne 3 -or
                $observations.maximum_output_bytes -ne 16GB -or $observations.maximum_window_output_bytes -ne 4GB -or
                ($ExpectedLeadSeconds -eq 8 -and ($null -eq $mode -or -not $mode.Value -or $observations.successor_lead_seconds -ne 8)) -or
                ($ExpectedLeadSeconds -eq 0 -and $null -ne $mode -and $mode.Value)) { $failure = 'Final observation plan receipt mismatch.' }
        }
        Write-Row @{
            kind='acceptance_exit'; qpc_ticks=[Diagnostics.Stopwatch]::GetTimestamp(); recorder_exit_code=$exitCode
            recorder_exited=$recorderExited; timed_out=$timedOut; finish_attempted=$finishAttempted; finish_returned=$finishReturned
            session=$session; manifest_status=$(if ($null -ne $saved) { $saved.status } else { $null })
            stop_reason=$(if ($null -ne $saved) { $saved.stop_reason } else { $null })
            target=$targetFinal; tracked_lifetimes=$cleanup; remaining_or_unverified=$remaining.Count; error=$failure
        }
    } finally {
        if ($null -ne $recorder) { $recorder.Dispose() }
        $writer.Dispose()
    }
}
Write-Output ('Resource evidence: ' + $log)
if ($null -ne $failure) { throw $failure }
