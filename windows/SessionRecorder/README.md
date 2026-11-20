# Overwatch Decoder Recorder

A visible Windows x64 recorder for a user-directed session. It saves desktop video,
system sound, foreground-scoped keyboard/mouse events and optional private research
memory streams in one folder. Intel and AMD x64 CPUs use the same reader. Video
encoding separately selects AMD AMF, NVIDIA NVENC or Intel Quick Sync; a configured
backend is not a claim that its hardware path has been tested.

Run `Overwatch Decoder Recorder.exe`, select the display and matching video encoder, and click
**Start recording**. **Ctrl+Shift+F9** starts/stops; **Ctrl+Shift+F10** marks a moment.
The tray menu can stop and save. Capture is visible, starts only on request and has
no startup service. Closing during startup cancels it. Keep the package together.
The default recording directory is `%LOCALAPPDATA%\OverwatchDecoder\sessions`.

The entire selected display is recorded, including other windows. System sound
means the default output device, including other applications, with no microphone.
Raw key scan codes and mouse movement/buttons/wheel are retained only while the
selected original process is foreground. A focus transition clears held-key state
and suppresses queued events near the transition; exact hardware-time focus is not
reconstructed. No text reconstruction, target hooks, injection, debugger attachment,
instruction trace, target-memory writes or privilege elevation is implemented.

## Files and timing

| File | Contents |
| --- | --- |
| `desktop.mkv` | Hardware H.264 video, native display size, requested 30 FPS and 6 Mbps |
| `system-audio.wav` | Default render-device loopback; optional |
| `events.jsonl.gz` | Keyboard, mouse, focus, marker, calibration, audio-offset and recorder-performance events |
| `video-frames.jsonl`, `video-progress.jsonl` | Source PTS and encoding progress with QPC receipt bounds |
| `memory/<name>/` | Configured guarded recordings, acquisition evidence and explicit unknown values |
| `session.json` | Process lifetime, build revision, stream status, error/gap counts and timing limitations |
| `code-reference/` | Optional historical static reference files; never an executed CPU-instruction trace |

Each source retains its own timestamps. A visible startup tile supports matching
video frames with QPC paint intervals. Paint submission is not exact compositor
presentation; audio callback arrival differs from WASAPI device time. Memory reads
are non-atomic. The recorder does not claim millisecond-perfect alignment or hard
realtime delivery. See [video timing details](VIDEO.md).

Memory is private research data, not public gameplay truth. Optional recipes must
validate the observed executable hash and ownership dependencies. Unknown fields,
unsupported states, lost guards and reacquisition gaps remain explicit. Raw field
counts are not counts of decoded abilities, and actor positions do not establish
team membership, identity across respawns or visibility. No game-specific recipe,
offset, binary or capture is committed here. The distributed example configuration
has memory disabled until an independently reviewed private plan is supplied.

The recorder uses bounded input/audio queues, background writing, hardware encoding
with CPU color conversion on the tested AMD path,
and a lower-priority encoding child. It requires 5 GiB free at start and stops below
3 GiB free; recording duration is capped at 4 hours. These bounds do not prove zero
gameplay lag. Record measured overhead separately for the actual configured memory
streams and hardware. At a sustained 6 Mbps, video alone is approximately 2.7 GB/hour;
audio, memory and metadata add storage. No full-address-space dump runs by default.

## Build and test

Use a .NET 10 SDK and `OVERWATCH_DECODER_DOTNET=/path/to/dotnet scripts/build_windows_capture.sh`.
The result is a self-contained Windows x64 executable under ignored `.runs/`.
Supply a trusted FFmpeg build with `ddagrab` and the desired hardware encoder.
Keep the FFmpeg build's license and provenance in the private installation.

Create `capture-settings.json` next to the executable:

```json
{
  "TargetProcess": "Overwatch",
  "Encoder": "h264_amf",
  "FfmpegPath": "ffmpeg.exe",
  "MaximumMinutes": 120,
  "SystemAudio": true,
  "Memory": []
}
```

For native verification without a game, run
`"Overwatch Decoder Recorder.exe" --demo --auto-record-seconds 30`.
This owns a visible synthetic child with known values and a temporary private
profile; only that child's memory is sampled. The child exits with the recorder.
Confirm that the synthetic label is visible on the selected display before using
the demo for visual correlation; unattended launches may not show that window.
Native video decoding, hardware
availability, device audio and physical-input/focus behavior require separate
verification; portable tests do not establish those capabilities.

Portable suites cover raw packet decoding, focus-time boundaries, audio queue
overflow/finalization, video child-process failure/stop behavior, event journal
roundtrip/error reporting and configuration confinement. CI builds the Windows
executable and runs those suites. It does not certify GPU performance.

The relevant API contracts are [Microsoft Raw Input](https://learn.microsoft.com/en-us/windows/win32/inputdev/about-raw-input)
and [FFmpeg desktop duplication](https://ffmpeg.org/ffmpeg-filters.html#ddagrab).

Synthetic, first user-directed match and follow-up session recordings measured
capture integrity, overhead and remaining gameplay-decoding gaps. The follow-up
recorded both memory streams and diagnoses a registry-filtering limit; complete
match coverage and enemy identification remain unverified.

A general entity checkpoint recorded removal of
the private Tracer-only selection gate, preservation of positions when health
pools are absent, and validation limits for the additional entity fields.
A Ramattra recording audit verified the next
recording, recovered sparse evidence from failed acquisitions and recorded the
general-entity and audio-file ownership corrections.
The first completed general-reader match
verified 21,711 saved memory frames, including 21,691 fully observed frames while
playing Ramattra, and recorded the remaining gaps and entity-identification limits.
The object identity decoder now associates those
fields with guarded object identities and adds the same mapping to future live
JSON. It resolves list reordering and selected-self association; player names,
teams and identity through respawns remain unvalidated.

## Optional fresh-roster JSON

`Roster` is absent/null by default. It does not change existing video, input, audio
or `Memory` recordings. A deployment can explicitly configure a reviewed private
bootstrap bundle and Python runtime, each with a SHA-256-pinned `inventory.json`:

```json
{
  "Roster": {
    "PythonDirectory": "roster/python",
    "PythonExecutable": "python.exe",
    "PythonInventorySha256": "<inventory SHA-256>",
    "BundleDirectory": "roster/input-bundle",
    "BundleInventorySha256": "<inventory SHA-256>",
    "Entrypoint": "tools/entity-decoder/bootstrap_raw_roster.py",
    "EntrypointSha256": "<script SHA-256>",
    "Config": "bootstrap-config.json",
    "SliceSeconds": 60,
    "MaximumSlices": 1,
    "MaximumConsecutiveFailures": 3,
    "RetryDelaySeconds": 5,
    "IntervalMs": 50,
    "MaximumOutputMiB": 4096
  }
}
```

The two directories must be inside the recorder package. Inventories use the
runtime bundle's `{ "relative/path": { "bytes": 123, "sha256": "..." } }` format;
the inventory does not list itself. Every file is checked, unexpected files and
links are rejected, and the entrypoint is pinned separately. Each inventory is
limited to 4,096 files/512 MiB. No game layouts, name/team map or private assets are
included in this repository. Configuration is an explicit trusted-code choice,
not a sandbox for untrusted Python. A bundle with an incompatible build or stale
native dependencies fails visibly rather than receiving new permissions.

The pinned bootstrap must support `--target-creation-file-time` and check it
against its verified census before building or recording. The recorder supplies
the selected original process lifetime and monitors it throughout each slice.
It never adopts a replacement process with the same PID. The optional stream
starts only with recording; there is no new auto-start or background service.

Each slice runs fresh copies of the pinned Python and input bundle in
`roster/slice-NNNN/`. The child is created suspended, assigned to a recorder-owned
kill-on-close Windows job, then resumed. Incompatible job assignment fails closed.
Cleanup checks the owned job has no active descendants before claiming success.
The game is never assigned to that job. Stop, startup failure, target exit, a
330-second wall deadline, log overflow or an output-cap breach terminate only that
owned child tree. Native/runtime nested jobs retain their own cleanup behavior.
Stopping mid-slice preserves a partial tail and explicit incomplete receipt; it
does not manufacture final native manifests. When a bootstrap child exits with a
nonzero status and its owned job closes successfully, the recorder can start a
fresh census after `RetryDelaySeconds`. This uses the next configured slice attempt;
`MaximumSlices` includes failed attempts. The default single-slice plan therefore
still stops after one attempt. Consecutive failures stop at
`MaximumConsecutiveFailures`; a verified successful slice resets that count.
Setting the failure limit to one retains immediate-stop behavior.

Retries preserve the failed evidence and announce an unknown gap. They recheck
the original process lifetime and pinned inputs, use separate fresh input copies
and output directories, and never carry old actor values. Cancellation, target
exit, changed inputs, invalid successful-result evidence, timeout, storage/log
bounds and failed owned-job cleanup stop the stream immediately. Video/input and
earlier slices remain saved. These retries do not establish cross-slice player
continuity or make unavailable observations complete.

`roster/status.json`, `slice-NNNN/slice.json` and session events retain status,
QPC bounds, original process identity, pins and owned-job cleanup results. The
status and UI distinguish verified complete slices from attempted slices;
`incomplete_slices` remains nonzero after a successful recovery. Detailed
native evidence, acquisitions and JSON stay under `slice-NNNN/output/`; compact
JSON is `output/recording/compact-roster.jsonl`. Python/input copies are retained as
source provenance. No archive, deletion, upload, semantic promotion or visibility
filter is added. Each slice has its own fresh census/admission. Between slices,
during acquisition and after the configured slice limit, JSON coverage is unknown;
there is no cross-slice value carry or continuity claim. Native source timestamps
remain authoritative; recorder receipt QPC is not an atomic video/memory sample.

Allowed limits are 15–120 seconds/slice, 1–64 slices, 20–1,000 ms sample interval
and 128–8,192 MiB for the entire roster directory (including copied assets).
Consecutive-failure limits are 1–8, with a retry delay of 1–30 seconds. UI and
session metadata expose measured bytes, verified finalized-window counts, slice
limits and failure reasons. Launched collectors remain explicitly unverified
until final receipts and compact-output hashes pass. The
output cap, 32 MiB bootstrap log cap and 262,144 filesystem-entry cap are polled
while the child runs. Size accounting is throttled to about once a second with
forced checks at slice boundaries; target/cancellation checks retain the 250 ms
loop. Concurrent writes can overshoot before termination.
Existing session disk-space checks remain active. No evidence is silently dropped
to stay below the limit. The default single slice limits storage deliberately:
a tested standalone ten-source 30-second capture used about 557 MB before
compression. That is not a rate guarantee for another configuration. Overhead
alongside game/video/audio is unmeasured; no zero-lag claim is made.

Portable core tests cover inventory mutation/confinement, exact lifetime command
binding, independent slice boundaries, pinned master-copy isolation, cancellation,
target exit, wrong result identity, nonzero exit, zero JSON/wrong source/compact corruption, wall/output/log bounds and failed
owned cleanup. The integrated build passed 1,075 core, 58 input/audio and 58 video
checks and produced the self-contained Windows executable.

The later recovery regression additionally covers failed-then-successful slices,
consecutive-failure limits and resets, fresh input/output copies, cancellation
during retry, target exit, input mutation and cleanup failure. These are portable
tests with synthetic child processes; a new Windows game-session recovery trial
is still required. They establish no new identity, hero, team or health semantics.

On 2026-11-01, a headless Windows fixture compiled the exact production
`RosterCapture.cs` from commit `de5d0e6`. Its 21 checks verified argument quoting,
active root/grandchild cleanup, grandchild cleanup after the root exited naturally,
normal empty-job cleanup, idempotent disposal and missing-executable failure.
All three launched fixture trees ended; no game reads or desktop inputs occurred.
The saved result SHA-256 is
`f6c8122e181e36dc0cbc196a26b8c5fae31300ca8c82908b7b45c8fb043ebe92`.
The completion verifier also accepted two unchanged earlier Windows bootstrap
recordings with 279 and 811 finalized windows, checking their recorded process
identity, receipts and compact hashes. These checks establish lifecycle handling
and compatibility with saved results.

A separate headless Windows check ran the same production child wrapper around
the pinned Python builder and its nested owned worker. It verified all 148 staged
package files before and after execution, built ten controller partitions from
saved census evidence, checked the generated inventory hash, and confirmed both
owned jobs closed successfully. The lead downloaded and verified the result,
builder receipts and inventory. The result SHA-256 is
`dac450c2642fa4f7d41815d0a22fc1acdabcbb9dfe552e97526d03c19b67a642`.
This establishes compatibility of the two Windows job layers on a successful
saved-data run; it does not test cancellation during nested work. No game reads
or desktop inputs occurred. An actual GUI recording and simultaneous
video/game/JSON performance still require controlled Windows acceptance before
distributing a configured package.

## Optional entity/event producer

`Observations` is opt-in and separate from the older, expensive roster bootstrap.
The recorder owns a pinned external Python producer job, follows its compact JSONL
and adds only line hashes, offsets and receipt QPCs to the event journal. Original
source evidence stays once in `observations/window-NNNN/`; it is never copied into
every event. Stop/cancellation closes the recorder's owned producer tree. The
selected game process is never enrolled in that job.

A private package can configure:

```json
{
  "Observations": {
    "PythonExecutable": "python/python.exe",
    "PythonSha256": "<exact executable SHA-256>",
    "BundleDirectory": "combined",
    "InventorySha256": "<inventory.json SHA-256>",
    "Entrypoint": "run_combined.py",
    "CaptureScope": "controlled_practice",
    "WindowSeconds": 45,
    "MaximumWindows": 1,
    "MaximumOutputMiB": 4096,
    "StorageFormat": "flat_v1",
    "StorageCohortMiB": 16
  }
}
```

The producer inventory has `files:[{path,size,sha256}]`; it must include the entry
script. The producer separately verifies its own configuration/source/runtime pins.
Each window invokes `--pid`, `--seconds`, an exact scope flag, and `--output`
directly, without a shell. `CaptureScope` is `controlled_practice` by default and
selects `--practice-range`. With the frozen v2 producer, explicitly choosing
`read_only_user_gameplay` selects `--read-only-user-gameplay`; this mode sends no
game input or focus changes. The UI names both modes, retains the configured
initial choice and locks it during recording. A user-gameplay result must include
that matching scope receipt; absent or mismatched scope fails verification.
Practice remains compatible with earlier flat producers that omit scope metadata.
The default `flat_v1` mode retains the producer's 20–60 second window bounds. A
configured repeat starts a fresh window after a one-second gap; it never asserts
continuity, complete event counts or a whole current roster. Video remains one
continuous recording. Output/log bytes and directory entries are polled with
cooperative bounds and may overshoot between checks. Full-match capture, concurrent
video/game overhead and sustained stability need actual Windows acceptance.
The default is one window; configuring repetitions is an explicit package choice.
A partial producer exit or cancellation is saved with unknown tails and gaps.
Completed windows require matching combined result row count, byte count, digest
and successful owned cleanup. Failures stop observation windows while retaining the
video and other recording sources; the saved session reports the problem.

Convert a saved session with
`python3 tools/entity-replay/prepare_compact.py SESSION_DIR OUTPUT.json`, then use
the existing entity replay server. This is offline conversion, not a recording-time
full-evidence rewrite. Raw native words and paths are omitted from replay. Candidate
outgoing feedback stays candidate; incoming attackers remain unknown. Health loss
never manufactures a damage event or attacker.


`scripts/measure_capture_acceptance.ps1` is a short Windows acceptance check:
one 20-second producer window inside an 85-second recording, with a
cumulative-resource sampler. `scripts/verify_capture_observations.py` then
verifies the saved artifacts. The check requires reviewed private v2 pins for
user-gameplay mode and makes no whole-session or performance claim.

Input discard records now separate the first failed focus/age gate, unreadable
native input, invalid packets, read exceptions and callback failures. Each bounded
reason group retains count, actual first/last discard QPC and allowlisted timing
context. The record's top-level QPC remains notification time, which can be later
than the discard. The existing 50 ms focus-settling and 250 ms message-age policies
are unchanged; their discards remain counted gaps. Hardware-time focus is still
unknown. Older recordings with the combined generic reason cannot retrospectively
identify the precise branch from notification timing alone.

### Opt-in finite producer with rotating storage

Explicitly setting `StorageFormat` to `cohorts_v1` selects
`ObservationStorageTail` and the opt-in
`overwatch-decoder.private.combined-storage/1` open/seal index. It follows fixed
`cohort-NNNNNN` directories, preserves original JSONL byte receipts and global
combined sequences, and verifies both output and delivery-receipt files before
switching cohorts. A live receipt is provisional: it does not claim sealed
acceptance or durable storage. Rotation represents a file boundary, not a new
observation, player identity or clock epoch.

By default this mode requires `MaximumWindows=1`. One owned producer runs through
storage rotations within each window. The repeat option below starts a fresh
producer at the next window. `StorageCohortMiB` defaults to 16 and
permits 1–256 MiB. The command adds `--storage-cohort-bytes` and
`--maximum-total-bytes` as separate byte-valued arguments. The latter is the
128–65,536 MiB budget for the **entire** observations directory, including native
evidence, provenance, compact output, delivery receipts, index and logs. Storage
rotation never deletes evidence or resets this accounting. Existing periodic
directory/log/entry checks, cancellation and selected-target lifetime checks stay
active; polling can overshoot a quota before termination.

The recorder accepts a finite `WindowSeconds` range of 20–1,800 for this opt-in
mode, with a `WindowSeconds+50` wall deadline. That configuration allowance does
not extend a pinned producer's own supported duration, worker output limits or
native acquisition capabilities. A matching producer must independently support
the requested duration and these flags; existing frozen producers may still
support only 20–60 seconds and retain smaller per-worker budgets. The recorder
does not upgrade them. The matching producer also requires its own pinned
`combined_storage_contract=1` configuration. There is no installed cohort candidate or new Windows
acceptance implied by this code. Video/recorder stop limits can still end a
producer early, leaving an explicitly incomplete tail.

The reader enforces finite line, cohort, total-byte, index and cohort-count
bounds. It rejects broken seal chains, duplicate properties, unsafe paths,
truncated or altered data, sequence changes and receipts linked to different
source bytes. Completion rechecks historical seals/files with bounded memory;
the `/2` result must match exact concatenated output and index hashes, counts,
scope and cleanup status. An empty failed-start cohort cannot be reported as a
successful recording. Hash checks establish content agreement, not an atomic
filesystem snapshot or a disk-durability guarantee.

Live rows use the existing `observation_receipt` envelope with the window number, a
cohort-relative `source_path`, per-file offset, original-byte digest, global
`combined_sequence` and `sealed_acceptance=false`. Original source fields are not
copied into the journal. `sealed_storage_cohorts` counts seals checked so far;
final window acceptance additionally rechecks historical seals/files and the
matching `/2` result. A verified partial producer result (exit 7) retains a gap.
The owned job is closed before final draining and verification, so descendants
cannot continue writing after the root exits. Draining follows `MadeProgress`,
including polls that consume metadata without returning rows. Tail handles are
disposed on success, cancellation and failure. No-row results fail acceptance.

Flat mode still uses its original files and `/1` result. Existing flat-only
offline replay/verifier tools need cohort-aware integration before a cohort
recording is delivered through them. Continuous capture still requires matched
native/Python integration, coordinated limits and actual Windows acceptance;
file rotation alone establishes no acquisition continuity or whole-match coverage.

The portable core suite covers interrupted writes and malformed storage, and an
independent Python writer's three-cohort fixture passes the C# reader and exact
result check. Set `OVERWATCH_DECODER_STORAGE_FIXTURE` to that synthetic fixture directory when
running `SessionRecorder.CoreTests` to repeat cross-language verification.
Set `OVERWATCH_DECODER_STORAGE_PRODUCER_PYTHON` to an existing local Python executable to run the
additional finite process fixture. It writes multiple cohorts while the recorder
follows live provisional rows, then tests complete/partial results, cancellation,
corrupt/missing seals, wrong scope/digest/schema, missing result, no rows, nonzero
exit and whole-directory overflow. This injected portable launcher is a synthetic
lifecycle test, not validation of Windows job APIs, a deployed Python runtime,
real-game duration, throughput or storage performance.
`OVERWATCH_DECODER_STORAGE_CAPTURE_FIXTURE` can separately point to an offline rotated `/2`
repack to exercise the complete capture adapter and its byte-limited final drain.
That saved-data test does not establish live producer rotation or Windows capture.


### Repeated observation windows during user gameplay

Use a pinned producer that supports read-only gameplay and cohort storage. In
`capture-settings.json`, keep the producer paths and hashes and set these
observation options.

| Setting | Suggested value |
| --- | --- |
| `CaptureScope` | `read_only_user_gameplay` |
| `StorageFormat` | `cohorts_v1` |
| `ContinueObservationWindows` | `true` |
| `WindowSeconds` | `45` |
| `MaximumWindows` | `240` |
| `MaximumOutputMiB` | `16384` |
| `StorageCohortMiB` | `4` |

Set the top-level `MaximumMinutes` to 60 for a one-hour media limit. Repeat
mode accepts 20–60 seconds per observation window. `MaximumWindows` counts
attempts, including source-unavailable windows. The total observation quota is
16 GiB with the example settings. Each producer receives the smaller of its
4 GiB ceiling and the remaining allowance after reserving its launcher log.
The recorder reports source state and verified window counts. Media continues
if the observation quota or attempt limit is reached.

Start recording from the menu before playing. The recorder uses the original
game process lifetime. A verified source-unavailable window records a gap and
waits 15 seconds before retrying on that process. Successful windows leave a
one-second pause before the next window. Acquisition, menu transitions and
unsupported fields can create additional gaps. A game-process exit ends the
recording and saves the session.

After playing, use **Finish data chunk and save** in the recorder or tray
menu. The status reads **Finishing current data chunk** while video continues
through the active window's seal. The wait is bounded by the requested window
duration plus 50 seconds and respects the recording's existing duration and
disk limits. **Stop now and save**, **Ctrl+Shift+F9** during recording and
closing the recorder stop immediately. An unfinished observation tail stays
unknown. Earlier verified windows remain available in the saved session.

When the recorder says **Saved** or **Saved with gaps**, use **Open recordings**
to find the session. With the package's replay launcher, select that session
folder and open the printed loopback URL. For a manual export, use the local
[replay tools](../../tools/entity-replay/README.md) with the session directory
and a fresh output path. The final manifest lists the accepted observation
window numbers. Replay uses their original clocks and exposes gaps across
windows. The recorder keeps the original media and private evidence in the
session folder.

#### Opt-in early successor

`SuccessorLeadSeconds` defaults to zero and retains serial window behavior. A
positive value is accepted only for repeated read-only gameplay cohort plans
with at least two attempts. The value must be smaller than `WindowSeconds`.
The recorder can start one successor while its predecessor is still running.
The predecessor must first deliver an original compact row with a position.
The recorder uses its own launch QPC plus the configured window duration minus
the lead. This marker does not measure the native source's deadline.

At most two owned jobs run at once. Each keeps its existing 4 GiB ceiling and
its own output, seal and result checks. The recorder reserves both producers'
caps and launcher logs within the session quota. It waits for serial completion
if there is insufficient reserve for a successor. Source-unavailable results
retain the 15-second retry delay. **Finish data chunk and save** finishes all
active windows without starting another. Immediate stop and target exit close
the owned jobs and record a gap for each unfinished window.

The opt-in manifest declares `overlapping_windows`, `successor_lead_seconds`
and `successor_timing_basis`. Each start records its launch QPC and the active
predecessor when present. Acceptance remains independent and the final manifest
lists accepted window numbers in numeric order. Original data can overlap in
QPC time. Replay must verify and cut the windows on their source clocks without
carrying identities or filling any uncovered interval. Enable this mode only
with a replay importer that understands the overlap and after measuring live
resource use and rollover coverage on the target Windows host.
