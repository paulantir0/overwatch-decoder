# Optional background profile preparation

`observe-fields --reacquire-ms 1000 --background-prepare true` prepares one
replacement profile while the current profile continues its normal guarded
reads. The default is `false`; synchronous observation remains available.
The interval is still bounded to 1,000–30,000 ms. Preparation starts when the
current segment reaches that age; activation follows completion, so this is not
a guaranteed discovery deadline or a promise of zero recording gaps.

Only one preparation task and one ready candidate may exist. Each preparation
reserves the next normal acquisition attempt. Retryable failures remain recorded
attempts and consume the existing consecutive-failure allowance. The worker owns
its acquisition directory and never writes the live stream, session manifest or
coverage. All shared source operations are individually serialized; read calls
and bytes are charged under that same lock before access. No lock spans a full
acquisition or its file writes. The backing source/handle remains owned by the
caller until the worker is joined.

Acquisition evidence uses the remaining session evidence allowance. Current
recording JSON, compression and index output retain their separate remaining
session limits. Activation proof also consumes the session evidence allowance;
256 KiB of remaining allowance must be available before validation. Metadata
failures charge the worker's entire evidence reservation rather than releasing
an unverified remainder. No field, guard, per-frame read or output limits grow.

The opt-in session also advertises `identical_profile_refresh: true`. A completed
candidate can be consumed without adoption when its actual bounded profile bytes
and rehashed digest exactly equal the active profile, and its manifest still
matches the preparation pin. This is allowed only while that originating segment
is active with no known guard/terminal failure, cancellation or output error.
The current epoch, contract and original acquisition source pins stay unchanged.
Its next frames still perform the usual current reads and guards. No activation
proof is needed because nothing is adopted. Candidate acquisition evidence is
retained and the attempt is charged normally; this is not a claim of complete
roster census or absence of arrivals. The next preparation is scheduled one
configured interval after this decision, preventing an already-aged segment from
spinning through preparations.

`preparation_no_change` records the candidate ordinal, `origin_segment`,
`active_acquisition`, shared `profile_sha256`, candidate `manifest_sha256`, exact
`preparation_end_sha256`, comparison start/end ticks and `profile_adopted: false`.
These diagnostics also appear in the session manifest's bounded
`unchanged_preparations` array. A strict consumer must verify the candidate files
and active epoch pins without rebuilding or replacing its current projector.

For a genuinely changed candidate, after the old recording closes, activation checks target identity, current main
module for native sources, the acquisition manifest hash and actual profile byte
hash, then rereads every normalized global/field-local guard. Identity/module are
checked again afterward. The private `acquisition-NNNN/activation.json` contains
exact guard bytes, addresses and read intervals, source profile/target, validation
interval and success/error. Its SHA256 is pinned in the activation event. A stale
candidate is explicitly discarded; a new synchronous acquisition is attempted.
The next recording also performs its usual per-frame before/after guard checks.
No candidate values or prior entity values are used as observations.

Live protocol opt-in is `session_start.background_preparation: true`:

1. `preparation_start`: reserved acquisition ordinal, `origin_segment`, actual
   `start_ticks`, `observation_gap_open: false`. No gap-start timestamp is invented.
2. `preparation_end`: original acquisition attempt and `ready`, `failed` or
   `cancelled` outcome. Old frames may surround these diagnostics. Completion may
   also occur after the old segment closes; `origin_segment` remains unchanged.
3. Successful handoff: old `segment_end` (`prepared_reacquisition`, or an actual
   guard invalidation), then original `acquisition_end` with `prepared: true`,
   original worker attempt timestamps, `origin_segment`, SHA256 of the exact
   newline-terminated preparation-end event, and activation proof metadata.
4. New `segment_start` has `prepared: true`. Only its own frames supply values.
   Actual gaps still appear in the usual events and recordings.
5. Failed activation or unused ready candidates produce `preparation_discard`.
   Failed preparations never become accepted epochs. Cleanup reports completion
   and discards any unused ready candidate before terminal publication.

Cancellation/deadlines cancel and join the worker; fatal preparation failures
wake the current reader and remain terminal errors rather than clean duration
completion. Cancellation is cooperative: an in-flight synchronous OS read, file
flush, or output write cannot be forcibly interrupted safely. Join time therefore
has no hard wall-clock guarantee, and this mode makes no hard-real-time claim.

Validation:

```text
dotnet build windows/Observer/Observer.csproj -c Release
dotnet windows/Observer/bin/Release/net10.0/overwatch-decoder-observer.dll self-test
```

Managed tests cover continued sampling during preparation; fresh profile values
only after activation; stale/modified candidate rejection; invalid old guards;
retryable and fatal failures; cancellation during preparation and activation;
deadlines; output failures; shared budgets; attempt bounds; and strict recording
verification. On Windows the same self-test additionally uses an owned child and
reports `native_prepared_segments: 1` and `native_no_change_refreshes: 1` on
success for the unchanged owned-child fixture. Changed-profile activation remains
covered by the managed relocation fixture. Linux tests do not establish
Windows native behavior or application performance. The strict Python consumer
must support this opt-in protocol before enabling live delivery.

## Bounded acquisition retry delay

`observe-fields --acquisition-retry-ms N` accepts 250–5000 milliseconds; omission
preserves the 250 ms default. The public `ObserveFields.Run` argument is
`acquisitionRetryMs`. The effective value appears in the session manifest's
`limits.retry_delay_ms` and the live `session_start.acquisition_retry_ms`.

The interval applies to existing retryable acquisition failures, including a
rejected prepared activation and a failed preparation joined after a segment
ends. It does not change which failures are retryable. While an old guarded
reader remains valid, it continues sampling; the next preparation is scheduled
no earlier than the retry deadline. With no active reader, waiting is bounded
and wakes on cancellation or the original total-duration deadline.

Attempt/failure counts, read/byte/output limits and the original session deadline
are unchanged. Permission, identity, process-lifetime and other terminal errors
still stop without a retry delay. Longer retries do not authorize reuse of a
previous owner, world or profile, guarantee recovery after a server disconnect,
or establish a cause for a failed acquisition. Every resumed profile must pass
fresh acquisition and its ordinary source/guard checks.

Managed fixtures cover CLI/public API bounds and provenance, a failed predicate
followed by a fresh successful acquisition, cancellation/deadline during a
five-second requested wait, terminal permission failure, attempt exhaustion,
background retry while old frames continue, rejected activation, and a failed
worker joined after old guard invalidation. These are synthetic timing proofs,
not measurements of game transition duration.
