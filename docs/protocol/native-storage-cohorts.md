# Native storage cohorts (opt-in)

`observe-fields` and `record-fields` accept `--storage-cohort-bytes N`
(65,536 through 1,073,741,824) and `--max-storage-cohorts K` (1 through
4,096; default 256). The byte option defaults to zero/off. Supplying a cohort
count while disabled is invalid. Default recording and live schemas are unchanged.

A cohort is a storage boundary inside the same guarded `FieldStream` invocation.
It does not reacquire the profile, restart the sampler, reset a frame sequence,
change the QPC origin, manufacture a gap, or establish identity continuity.
Guard failures, explicit unknowns, cancellation, target exit and background
acquisition keep their existing behavior. Identical background refresh can keep
one active segment across multiple storage cohorts.

## Files and hash domains

The opted-in segment manifest is `overwatch-decoder.field-recording/2`. `profile.json` remains
one immutable profile for the segment. These replace the old `samples_file` and
`index_file` properties:

| Property | Meaning |
| --- | --- |
| `storage_index_file` | Literal `storage-index.jsonl` |
| `storage_cohort_bytes` | Strict compressed samples cap per cohort |
| `maximum_storage_cohorts` | Remaining session-wide allowance when segment begins |
| `storage_cohorts` | Number of successfully published seals |
| `storage_index_bytes` | Exact catalog bytes including LF delimiters |
| `storage_index_sha256` | Catalog digest when terminal summary was published, else null |
| `durable_storage_index_prefix_sha256` | Catalog digest captured on close |

Each new `storage-NNNNNN` directory has only `samples.jsonl.gz` and `chunks.jsonl`.
Ordinals start at 1 within each segment. Paths must be these literal generated
relative names, without links/reparse points. No arbitrary paths are followed.

Chunk records retain `overwatch-decoder.field-recording-chunk/1`. Their `sequence` and
`first_line` start at zero and continue across all cohorts in the segment.
`offset` starts at zero **within each cohort**. Original frame/summary JSONL bytes
are unchanged. Root `samples_sha256`/`durable_samples_prefix_sha256` hash the
concatenated compressed cohort files in ordinal order; root
`index_sha256`/`durable_index_prefix_sha256` hash the concatenated chunk index
files. Root `index_bytes` counts chunk index bytes only. Catalog bytes are a
separate domain, but **both** consume the cumulative index budget.

Each catalog line is one UTF-8 JSON object plus LF, with exactly:

```
schema: "overwatch-decoder.field-storage-cohort/1"
ordinal: integer >= 1
directory: "storage-NNNNNN"
profile_sha256: lowercase SHA-256
previous_record_sha256: null first, otherwise prior exact catalog line SHA-256
first_chunk, chunks, first_line, lines: integers
compressed_bytes, json_bytes, index_bytes: integers
samples_sha256, index_sha256: lowercase SHA-256 of this cohort's files
terminal_summary_included: boolean
```

`first_chunk` and `first_line` begin at zero. Counts/byte lengths are positive.
The terminal summary is the sole final JSONL line, in the last cohort only.
The hash chain includes each line's LF byte. No canonical JSON reserialization
is used to verify its hash.

The writer closes old cohort files, appends and flushes its seal, then opens the
next generated directory. It keeps no growing cohort list: one catalog stream,
two active output streams, incremental hashes and current counters. Compressed
chunks are preflighted before writing; an individual frame that cannot fit with
the terminal reserve stops with `storage_cohort_chunk_limit`. No compressed file
overshoots N. Conservative raw-byte reserves may rotate early. Total cohort cap
is shared across all guarded segments, not reset by reacquisition. Exhaustion
stops with `storage_cohort_limit` and an ordinary stopped summary when writable.
A failed close/write/seal/open stops closed; disposal never retries publication.

## Live protocol

Only enabled sessions add `storage_rotation` to `session_start` and the root
result. Its fields are `schema: "overwatch-decoder.field-storage-options/1"`, `cohort_bytes`,
`maximum_cohorts`, `sealed_cohorts` (zero at start),
`recording_schema: "overwatch-decoder.field-recording/2"`, `semantic_epoch_reset: false`.
Disabled sessions omit the property.

A normal globally sequenced live event has `kind: "storage_cohort_sealed"` and:

```
segment, acquisition, profile_sha256
storage_cohort_ordinal       # session-global, starts at 1
index_record                # exact catalog object above
index_record_sha256         # SHA-256 of exact UTF-8 catalog line including LF
```

It is emitted after catalog publication, before the next cohort opens. The final
seal is emitted before `segment_end`. Storage events consume the normal event
cursor but do not advance the frame watermark, replace active adapters, reset
baselines or establish a new semantic epoch. Consumers must validate the active
segment/acquisition/profile pins and all global/local ordinal/hash links. A live
notification alone is not independent disk verification or delivery proof.

## Verification and limits

`verify-fields`, export and other existing strict consumers accept `/2` with one
continuous frame validation state. The verifier checks catalog ranges, profile,
chain, caps, generated paths, whole cohort file hashes, individual compressed and
raw chunk hashes, frame/timing/guard semantics and the sole terminal summary.
Opted-in results use `overwatch-decoder.field-recording-verification/2` and add `storage` with
`cohorts` (declared count, not a verified-prefix count), `storage_index_bytes`,
`storage_index_sha256`, `maximum_cohort_bytes`, and a descriptive `hash_domain`.
Verified prefix counters retain their existing meaning. Catalog metadata is
bounded by 4,096 rows of at most 4,096 bytes; file hashing uses a 64 KiB buffer.

Recovery never claims complete evidence from an unsealed, unannounced or
truncated continuation. After a valid catalog, an invalid later cohort can
preserve previously verified chunks. A malformed catalog, stale initial
manifest, missing seal, or extra unsealed directory fails before prefix replay;
this implementation does not salvage every interrupted recording.

Existing cumulative duration, read calls/bytes, acquisition attempts, profile,
evidence, JSON, compressed, index, live-output and free-space limits remain in
force. Files are bounded; total storage is not an infinite rotating deletion
buffer. This primitive alone does not enable a full-match session. Compression,
hashing and flush I/O remain synchronous and can skip scheduled slots; original
frame accounting reports those skips. The writer requests file-buffer flushes with `FileStream.Flush(true)`; this
does not guarantee cross-file crash consistency or atomicity. There is no
crash-free, zero-skip or real-time guarantee. Platform-native fixture validation is separate from the
portable synthetic tests; no gameplay validation is implied.

## Owned Windows fixture procedure

Build/publish with `OVERWATCH_DECODER_DOTNET=/path/to/dotnet scripts/build_windows_observer.sh`
and transfer the resulting executable and hash inventory using the project's
existing deployment process. On Windows, verify its hash/revision and run
`overwatch-decoder-observer.exe self-test`. The following PowerShell plan then uses only the
existing owned fixture. It requires neither elevation nor page-protection
changes. Set `$exe` to the freshly verified executable and `$root` to a new
private output directory; generated addresses/recipes remain private.

```powershell
$ErrorActionPreference = 'Stop'
$exe = (Resolve-Path '.\overwatch-decoder-observer.exe').Path
$root = Join-Path $PWD ('storage-fixture-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$start = [Diagnostics.ProcessStartInfo]::new()
$start.FileName = $exe
$start.Arguments = 'fixture --seconds 60'
$start.UseShellExecute = $false
$start.RedirectStandardOutput = $true
$fixture = [Diagnostics.Process]::Start($start)
$observer = $null
try {
    $readyTask = $fixture.StandardOutput.ReadLineAsync()
    if (-not $readyTask.Wait(10000)) { throw 'Fixture readiness timeout' }
    $ready = ($readyTask.Result | ConvertFrom-Json).result
    if ($ready.pid -ne $fixture.Id -or $ready.decoder -ne 'overwatch-decoder.windows-fixture/1') {
        throw 'Owned fixture descriptor mismatch'
    }
    $address = [UInt64]$ready.address
    $magic = [BitConverter]::ToUInt64([Text.Encoding]::ASCII.GetBytes('OWDWIN01'), 0)
    $recipe = @{
        schema = 'overwatch-decoder.acquisition-recipe/1'
        target = @{ image_name = [IO.Path]::GetFileName($exe)
            executable_sha256 = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant()
            architecture = 'x64' }
        seconds = 10; constants = @{}; functions = @{}; global_guards = 'g'
        stages = @(@{ name = 'header'; steps = @(
            @{ op = 'read'; name = 'header'; address = $address; size = 8 },
            @{ op = 'require'; test = @('eq', @('load', @('var','header'),0,8), $magic) },
            @{ op = 'guard'; set = 'g'; value = @('var','header') }
        ) })
        fields = @(0..31 | ForEach-Object {
            @{ name = ('value' + $_); type = 'i32'; address = ($address + 16); min = 51; max = 100 }
        })
    }
    $recipePath = Join-Path $root 'owned-recipe.json'
    [IO.File]::WriteAllText($recipePath, ($recipe | ConvertTo-Json -Depth 30), [Text.UTF8Encoding]::new($false))
    $capture = Join-Path $root 'capture'
    $observer = Start-Process -FilePath $exe -PassThru -NoNewWindow -ArgumentList @(
        'observe-fields','--pid',$fixture.Id,'--recipe',('"' + $recipePath + '"'),
        '--out',('"' + $capture + '"'),'--interval-ms','10','--seconds','30',
        '--jsonl','true','--live-evidence','true','--storage-cohort-bytes','65536',
        '--max-storage-cohorts','4'
    ) -RedirectStandardOutput (Join-Path $root 'live.jsonl') -RedirectStandardError (Join-Path $root 'stderr.txt')
    if (-not $observer.WaitForExit(45000)) { throw 'Observer bounded wait expired' }
    $manifest = Get-Content (Join-Path $capture 'manifest.json') -Raw | ConvertFrom-Json
    if ($manifest.acquisitions.Count -ne 1 -or $manifest.segments.Count -ne 1 -or
        $manifest.storage_rotation.sealed_cohorts -ne 4 -or
        $manifest.stop_reason -ne 'storage_cohort_limit') { throw 'Expected three rolls in one acquisition/segment' }
    $segment = Join-Path $capture $manifest.segments[0].directory
    $verification = & $exe verify-fields --from $segment
    [IO.File]::WriteAllText((Join-Path $root 'verification.json'), ($verification -join "`n"))
    $v = ($verification | ConvertFrom-Json).result
    if (-not $v.valid -or $v.complete -or $v.schema -ne 'overwatch-decoder.field-recording-verification/2' -or
        -not $v.terminal_summary_verified) { throw 'Strict stopped recording verification failed' }
    Get-Content (Join-Path $segment 'storage-index.jsonl') | ForEach-Object {
        if (($_ | ConvertFrom-Json).compressed_bytes -gt 65536) { throw 'Cohort byte cap exceeded' }
    }
    # Retain manifests, profiles, original live bytes, catalog, all cohort files,
    # verification output, executable SHA and tracked PIDs as private evidence.
} finally {
    foreach ($tracked in @($observer, $fixture)) {
        if ($null -ne $tracked) {
            if (-not $tracked.HasExited) { $tracked.Kill(); [void]$tracked.WaitForExit(5000) }
            $tracked.Dispose()
        }
    }
}
```

The procedure alone is not runtime evidence; executed acceptance is recorded below.
The executable's exit status for a deliberately capped observation does not
replace the strict verifier's stopped/complete distinction. Only the two process
objects launched by this procedure are cleaned up; no name-wide process killing
or unrelated settings changes are involved.

## Windows owned-fixture acceptance, 2026-11-05

The lead built source `d3ab03a59eaef3224c14e57ec9637f602bb00cb5` and verified
the Windows executable SHA-256
`6a3719c5073fdc71453465194718d8def4309393305da460fe877c3bcef5617d`.
The full Windows self-test reports 11,366 passing assertions, including its
ordinary native child-read tests. A separate run of the owned fixture above
then produced four storage cohorts within one acquisition and one guarded
segment: 205 frames, zero unknown fields, two skipped intervals and one terminal
summary. It stopped explicitly at `storage_cohort_limit`.

All 21 captured files matched their Windows SHA-256/size receipts after local
transfer. Windows and local strict verification accepted 62 chunks / 206 lines,
175,795 compressed bytes and 1,226,035 JSON bytes, with zero unverified bytes.
The four compressed files measured 43,374, 43,318, 44,529 and 44,574 bytes, each
below 65,536. All 217 live event sequences remained contiguous; all four seal
objects and exact line hashes matched the catalog, and the terminal seal
preceded `segment_end`. Both owned processes exited and no observer remained.

This is verified stopped fixture evidence, not a complete-duration recording or
a gameplay/whole-match result. It used ordinary reads, without elevation or
page-protection changes. Rolling storage remains opt-in and the production
combined recorder still uses its existing bounded windows.
