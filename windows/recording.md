# Private candidate recording

`ResearchRecorder.Record(source, candidateDirectory, outDirectory, intervalMs,
duration, cancellation)` records previously discovered numeric candidate bytes.
It does not identify entities, actions, positions, visibility, or HUD fields.
Every recording is marked research with `public_state_eligible: false`.

The input is a `overwatch-decoder.memory-candidates/1` directory. Its digest, declared count,
address ordering/alignment, target PID, creation time, executable hash, image
name and architecture are checked before recording. The destination must be
new. The recorder neither owns nor disposes the caller's memory source.

## Files and reconstruction

- `dictionary.jsonl` maps integer candidate IDs to private virtual addresses,
  original candidate bytes and original sample ticks. Original bytes are
  historical evidence; they are never the recording's initial current values.
- `samples.jsonl.gz` contains one JSON line per sampling batch, compressed as
  concatenated gzip members. Each member is finished before it is appended.
  Standard gzip readers supporting concatenated members (including .NET and
  Python) read the complete stream. Completed members can be recovered if an
  abrupt termination damages the last member.
- `manifest.json` describes origin timestamps, requested interval, actual timing,
  skipped intervals, read gaps, limits, completion status and SHA-256 hashes.
  It initially says `recording`; clean completion/cancellation writes `finished`.
  A manifest left in `recording` means the final summary was not written.

The first batch and roughly every second thereafter are `keyframe` records.
Clear the reconstruction state on a keyframe; apply its values for every ID.
For a `delta`, replace only the listed IDs. `available: false` and
`bytes_hex: null` explicitly replace any previously known value with unknown.
An unchanged value omitted from a delta was re-read in that batch; each page
still has a timing/status record. An unreadable page produces unknown
transitions, and recovery emits values even if they equal earlier values.
State has validity only at its recorded sample interval, never indefinitely
after a recording stops. No decoded numbers are emitted: even a matching
numeric candidate can be an unrelated copy or coincidental bit pattern.

Each page has monotonic read start/end ticks; each batch has scheduled, start
and end ticks, scheduling jitter and skipped intervals. Batch sequence counts
stored records; scheduled slot numbers can have gaps. Ticks use the manifest's
Stopwatch frequency and origin. The UTC origin is bracketed by two monotonic
samples. Reads are sequential and the target continues running; timestamps do
not make a batch atomic. Slow work skips missed slots without queued catchup
reads. A 10 ms requested interval is supported, with no hard realtime promise.

## Windows wakeup scheduling

On Windows, each recording attempts to create its own unnamed, non-inheritable
high-resolution waitable timer. Microsoft documents the high-resolution flag
on Windows 10 version 1803 and later. The timer requests only synchronization
and modify-state access; no privilege or system setting is changed.
See [CreateWaitableTimerExW](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createwaitabletimerexw)
and [synchronization access rights](https://learn.microsoft.com/en-us/windows/win32/sync/synchronization-object-security-and-access-rights).

Each wait arms a one-shot timer with a negative relative due time in 100 ns
units. The recorder waits for either the timer or cancellation signal. The
timer signal determines wakeup; a 200 ms timeout guards against a malfunction.
Long waits use at most 100 ms timer chunks, and every wakeup rechecks the
monotonic deadline. There is no busy-spin loop, global timer-resolution change,
process-priority change or wake-from-suspend request. Timer accuracy still
depends on hardware and OS scheduling. See
[SetWaitableTimer](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-setwaitabletimer)
and [WaitHandle.WaitAny](https://learn.microsoft.com/en-us/dotnet/api/system.threading.waithandle.waitany?view=net-10.0).

The manifest's `scheduler` object records initial/final backend, wait counts,
and any fallback reason, native error code and transition ticks. Non-Windows
systems and unavailable/failing native timers use `managed_wait_handle`, whose
timeout granularity may miss short sampling periods. Selecting the Windows
backend does not establish a measured 100 Hz sampling rate; inspect batch
timestamps and skipped intervals. Cancellation stops the pending timer, and
disposal closes its owned safe handle without closing the caller's cancellation
handle. [CancelWaitableTimer](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-cancelwaitabletimer)
does not itself wake a waiting thread, so cancellation has a separate signal.

## Bounds and interruption

Inputs are limited to 16,384 candidates, 4,096 distinct 4 KiB pages, an 8 MiB
candidate file and a 1 MiB manifest. A batch reads each candidate page once,
at most 16 MiB. Interval must be 10..10,000 ms; duration is positive and at most
10 hours. Runtime ceilings are 512 GiB attempted reads, 4 GiB uncompressed JSON
and 2 GiB compressed samples. Disk free space is checked every second against
a 32 MiB reserve. These are explicit stop/error conditions, never silent
candidate truncation. Output includes bounded dictionary/manifest overhead.

Cancellation is checked between reads and while waiting. Permission denial,
process exit or identity mismatch stops further reads. Other page failures
are explicit gaps and later batches retry those pages. A single in-flight OS
read cannot be interrupted; its actual duration is recorded. A normally
completed duration can contain read gaps (`all_reads_succeeded: false`).
Cancelled, capped and failed runs preserve their already-written data and
report `complete: false`. Disk I/O failures can also prevent the final manifest
from being saved. This is private research data: do not upload it to GitHub.

`RecordingTests.Run()` performs portable synthetic tests and returns its
assertion count. It neither connects to Windows nor reads a game process.
