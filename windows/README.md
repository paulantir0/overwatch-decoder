# Windows observer

This is a standalone Windows x64 console application for ordinary, read-only
process inspection and private memory snapshots. It does not inject code, attach
a debugger, modify target memory, enable debug privileges, or bypass denied access.

Everything in this repository reads memory only through ordinary
`OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)` and `ReadProcessMemory`.
It contains no tool that changes page protections in the target.

The native commands provide generic acquisition and typed recording. The separate
[private semantic launcher](../tools/entity-decoder/selected-live-runners.md)
combines them with validated private inputs to emit current health, hero,
relation and position observations.
The executable itself embeds no game recipes or hero mappings. `probe` reports measured
capabilities; `snapshot` records raw research bytes with provenance and read gaps.
`scan` and `refine` find numeric candidates for subsequent controlled validation.
`record-candidates` saves their changing bytes with actual timing and explicit gaps.
`stream-fields` emits typed fields from a private profile with before/after guards,
explicit unknowns and timing. Names remain profile-declared research semantics;
`record-fields` saves the same named frames in bounded compressed chunks with an
index for interrupted-file recovery. `verify-fields` checks a stable saved recording
and reports an explicitly bounded recoverable prefix when requested. `export-fields`
strictly verifies a saved recording and creates a compact private JSONL timeline,
preserving every frame, field value, unknown and timestamp.
`timeline-fields` emits sparse numeric comparisons with explicit unknown, gap and
verified storage-route resets. `summarize-fields` reports numeric ranges, unknown
coverage and read timing without retaining the full timeline in memory. These
commands do not infer gameplay events. Opt-in v4 profiles additionally support a
fixed calculated timer codec with raw state/counter operands, separate read
intervals and exact serial guard checks. Formula parameters remain private
profile data; calculated values do not establish game semantics. See
[field-streaming.md](field-streaming.md).
`acquire-fields` executes a bounded private, exact-build recipe to derive a fresh
v1 or v4 profile with explicit selection, dependency guards and read evidence. The
executable bundles no application recipes or gameplay meaning. See
[acquisition.md](acquisition.md) for its contract and limits.
`observe-fields` combines that acquisition with finite named recording. A failed
identity guard is saved before bounded reacquisition starts a new profile and
recording segment. Its session manifest retains segment boundaries, observation
gaps, failures and coverage; it never continues using an invalid profile.
The default limits are eight acquisitions and three consecutive acquisition
failures. Longer finite experiments can explicitly set `--max-acquisitions`
(1–128) and `--max-consecutive-acquisition-failures` (1–16). These settings do not
raise read/output/duration budgets or change fatal identity and permission stops;
the manifest records the effective limits.
Optional `--reacquire-ms` refreshes discovery even when existing guards remain
valid: `0` is the default (off), or choose 1,000–30,000 milliseconds. The last
accepted frame remains recorded before a `periodic_reacquisition` boundary.
Periodic refresh consumes the same acquisition count and read/output budgets;
it does not bridge the resulting observation gaps or override terminal failures.
Optional `--background-prepare true` prepares one replacement profile while the
active profile continues its guarded reads. Fresh activation validates the target,
module, profile and every guard before a changed profile is used. The explicit
live consumer must support these events; see
[background preparation](Observer/background-preparation.md). Cancellation is
cooperative and handoff can still leave a measured gap. An exactly byte-identical
prepared profile produces a verified no-change refresh and retains the active
epoch; it does not relabel existing evidence as newly acquired data.
Add `--jsonl true` to emit compact private frames and explicit session/segment/gap
boundaries on stdout as samples are accepted. The full raw recordings remain the
audit source; live output does not assert recording durability or gameplay meaning.
For a local decoder that needs the exact dependency evidence, also pass
`--live-evidence true`. Each live frame then includes `recording_frame`, the exact
serialized frame accepted by the recording sink, including guard checks, field
dependencies and read intervals. This option requires `--jsonl true` and defaults
to false. Acceptance is not a durability guarantee; verify the saved recording
separately. The embedded data is private and may include source addresses in v2+
profiles. The existing 256 KiB line and 512 MiB stream limits still apply; an
oversized frame fails without emitting a truncated JSON line. No extra process
reads or background queue are introduced.
Profiles with guarded `self_handle_candidate_i32` and
`actor_NNNN_handle_candidate_i32` declarations also emit `entity_identity` in live
frames and verified `export-fields` output. This maps ordinal field names to
process-object keys and a nullable self association without exporting source
addresses. It does not establish participant identity, team or visibility.
By default reacquisition stops with `field_shape_changed` when declared names or
types differ. Add `--allow-field-shape-changes true` to allow names to appear or
disappear between separately numbered segments. Each live `segment_start` carries
that segment's exact profile hash and field schema; frames contain only its fields.
Reusing a declared name with a different type stops with `field_type_changed`,
including after a name was absent from an intervening segment. Coverage is a
bounded union of declared names (at most acquisition attempts times 128); counts
aggregate those names, not persistent entity identities. A field absent from a
segment accrues neither observed nor unknown samples. Ordinal collection names
can refer to different actors after reorder or reacquisition. Segment recordings
still require independent strict verification, and gaps remain unobserved.
Session manifest replacement makes at most five attempts for Windows error codes
5, 32 and 33, with four 25 ms waits, using the same complete pending file. Access denied
alone does not prove a sharing conflict; persistent denial still fails, without
changing permissions or attributes. Cancellation stops checkpoint retry waits;
terminal publication has its own bounded window. Synchronous file calls can
overrun that window. Status readers should permit `FileShare.ReadWrite | Delete`
so that they do not prevent replacement of the observer's owned manifest.
If final publication fails, `stop_reason` is `manifest_publication_failed` and
`manifest_publication` records the underlying error/code and preceding operation
stop reason. `final_manifest_saved` means a finished snapshot was saved;
`current_result_saved` states whether the current returned summary was saved.
An earlier saved snapshot can remain valid while a later refresh fails. Live
`session_end` reports first-publication failures; a failed refresh after that
event attempts `session_finalization_error` while the writer remains available.
Neither event establishes downstream receipt. Failed pending/staging files stay
private evidence; an old `running` manifest does not establish that work continues.
`search-snapshot` searches previously captured bytes without opening a live process.
The included child fixture is explicitly synthetic. Successful fixture tests are
not evidence of Overwatch support.

## Build

Use a .NET 10 SDK. All executable outputs, restored dependencies, and test artifacts
stay in ignored directories. The executable includes its runtime; Python and .NET
do not need to be installed on the Windows target.

```sh
OVERWATCH_DECODER_DOTNET=/path/to/dotnet scripts/build_windows_observer.sh
```

The build runs the portable self-tests and produces a self-contained
`overwatch-decoder-observer.exe`, `REVISION`, and `SHA256SUMS` in `.runs/windows-observer/`.
The revision is marked dirty when observer sources differ from the commit.
Run native verification on Windows as well:

```powershell
.\overwatch-decoder-observer.exe version
.\overwatch-decoder-observer.exe self-test
.\overwatch-decoder-observer.exe probe --process Overwatch
.\overwatch-decoder-observer.exe snapshot --process Overwatch --out .\private-snapshots\run-01 --max-bytes 2147483648 --seconds 120
```

`self-test` on Windows starts our own bounded child fixture, reads its changing
memory using the native API, checks field consistency, records/replays changing
named fields, and tests process exit and invalid reads. On another OS the native
check is explicitly reported as not run.

## Snapshot interpretation

- Output directories must be new; existing snapshots are never overwritten.
- Reads are limited to one readable committed region and at most 1 MiB per call.
  Guard pages and inaccessible regions are excluded. Permission failures stop the
  operation and remain explicit in the result.
- The process handle and creation time bind reads to one process instance.
- `chunks.jsonl` maps source addresses to offsets in `memory.bin`, with individual
  hashes and sample times. Failed chunks have no corresponding bytes.
- Each attempted read has `read_start_ticks` immediately before `source.Read` and
  `read_end_ticks` immediately after it returns or at entry to its failure handler,
  before file writes, hashing or reporting. Both use `Stopwatch.GetTimestamp` and
  the manifest's `monotonic_frequency`. The existing `monotonic_ticks` remains an
  alias of the start. These bounds enclose the read call; they do not make its
  bytes atomic. `sampled_utc` is a later record-construction time, not an exact
  read boundary. Older snapshots have no end marker, so their read duration is
  unknown. These additive fields retain the `overwatch-decoder.memory-snapshot/1` schema.
- `manifest.json` identifies the executable hash, byte/time limits, and whether
  every byte of the initially enumerated readable regions was captured.
- A complete capture is still **not atomic**: the game continues running while
  pages are copied. It does not imply that values sampled at different times form
  a consistent frame. Later decoders must validate that separately.
- An incomplete snapshot returns exit code 7. Other failures use JSON errors;
  denied access uses exit code 4. No raw memory is emitted to stdout.

Keep snapshots and screenshots private. Commit source and sanitized aggregate
measurements only. Public JSON gameplay output still requires validated decoders
and a validated player-visibility filter.

## Offline named-field review

```powershell
.\overwatch-decoder-observer.exe summarize-fields --from .\private-recordings\run-01
.\overwatch-decoder-observer.exe export-fields --from .\private-recordings\run-01 --out .\research\timeline-01.jsonl
.\overwatch-decoder-observer.exe timeline-fields --from .\private-recordings\run-01 --out .\research\changes-01.jsonl
```

These commands accept v1/v2/v3/v4 named recordings, strictly verify the saved profile,
chunks, frame evidence and terminal manifest, and use those same validated buffers.
They never open a target process or modify the recording. Valid stopped captures
remain labeled `verified_stopped`; interrupted or corrupt artifacts produce an
error without a partial successful report. `summarize-fields` writes only its JSON
command result, with process/build and artifact provenance, per-field known/unknown
counts, component ranges, recorded read timing and numeric-change counts. Unknown
frames and missed scheduled slots break change comparisons. Numeric changes are
observations, not game events, and no units or game meaning are assigned. These
outputs remain private research: profile names, values and reasons are preserved.
`timeline-fields` writes a new sparse JSONL file with exact before/after values and
read brackets, fresh baselines after unknown/missed-slot/full-route changes, and
final state plus trailing-gap evidence. Comparisons are sampling observations,
not event times. It publishes only after strict verification succeeds; interrupted
or cancelled exports leave no final output. Runtime address/guard traces are omitted,
but arbitrary candidate names and values remain private research data.
See [field-streaming.md](field-streaming.md) for exact metrics, schema and bounds.

The separate [local field replay viewer](../tools/field-replay/README.md) is intended
to open a compact `export-fields` JSONL file through a local browser file picker.
Keep its four web files together, open `index.html`, then choose the export. It
shows recorded values and raw vector projections, with no map or event decoder.
Raw recording folders and sparse `timeline-fields` output are not viewer inputs.
The portable parser has been tested against saved v1/v2 recordings; browser
interaction is still unverified.

## Offline text search

```powershell
.\overwatch-decoder-observer.exe search-snapshot --from .\private-snapshots\run-01 --out .\research\text-01 --text example --encoding utf8
```

This command checks each visited chunk's SHA-256 before searching its saved bytes.
It supports UTF-8 and naturally aligned UTF-16 little-endian text, with exact case
and a default limit of 1,000 matches (`--max-matches`, up to 100,000). Each private
match includes its original address, chunk provenance and read interval.
`sampled_ticks` remains the read-start alias, alongside `read_start_ticks` and
`read_end_ticks`. For older snapshots, the start comes from `monotonic_ticks`
and the end is explicitly `null`; no duration is inferred. The original
`sampled_utc` remains a later record-construction time. The
manifest records coverage, original capture gaps and search limits. Text crossing
chunk boundaries is excluded. Completing a search does not make an incomplete
snapshot complete or establish the gameplay meaning of a match. No live process
access is performed, so offline searches also work on other supported .NET hosts.

## Candidate discovery

```powershell
.\overwatch-decoder-observer.exe scan --process Overwatch --type i32 --value 29 --out .\research\scan-01
.\overwatch-decoder-observer.exe refine --from .\research\scan-01 --value 27 --out .\research\scan-02
```

These example numbers have no bundled gameplay meaning. Search types are `i32`,
`f32`, and `f64`, with natural alignment and exact bit comparison. By default the
scan visits readable writable regions; `--scope readable` includes read-only
regions too. The default limits are 100,000 candidates and 120 seconds. Override
with `--max-candidates` (up to 1,000,000) and `--seconds` (up to 3,600).

Candidate files contain private process addresses. Their manifests identify the
process instance, executable hash, value, scope, timing, byte coverage, errors,
and candidate-file digest. Refinement checks that identity and digest, reads the
provided candidates again, and retains exact matches. It does not discover new
addresses. Refinement completion means that the supplied candidates were checked;
it does not establish exhaustive initial discovery. Incomplete operations return
exit code 7 with the reason recorded. No output directory is overwritten.

Correlate candidates with independently timestamped observations across several
changes, unchanged controls, respawns, hero changes, and process restarts before
assigning gameplay meaning. A numeric match alone is not validation. User actions
and operator inputs must be distinguished in research notes.

## Match recording target

The intended recording is an append-only timeline of validated fields and events,
with a target sampling period of 10 ms and actual monotonic timing on every sample.
Whole-process dumps support discovery; the recorder samples the identified fields.
Sampling must preserve read gaps and distinguish
direct observations from derived velocity, inferred events, and tactical analysis.
The current commands do not reconstruct a match or establish a game update rate.

```powershell
.\overwatch-decoder-observer.exe record-candidates --from .\research\scan-02 --out .\research\recording-01 --interval-ms 10 --seconds 600
```

The recorder includes compressed JSONL, a private address dictionary, hashes,
keyframes/deltas, and per-page read timing. A requested 10 ms interval is a target;
late samples skip missed slots and report them instead of fabricating frames.
For discovery across many candidate pages, start with a slower interval such as
100 ms and inspect measured timings. See [recording.md](recording.md) for the
format, replay rules, and resource limits. Candidate recordings remain research
bytes with unvalidated meaning.


### Opt-in version 3 guard batching

`stream-fields` and `record-fields` also accept private `overwatch-decoder.field-profile/3`
profiles with the explicit `absolute_guard_reads` policy (default 128-byte span,
32-byte maximum gap). Only consecutive absolute guards with identical field and
path-root dependencies are batched; pointer hops and fields retain their own reads.
All requested gap bytes count against the existing read budgets. Physical batch
intervals and logical slices are separate evidence, and a failed/partial batch
never supplies a usable prefix. V1/v2 behavior and wire formats remain unchanged.

The offline verify, recovery, export, summary and timeline commands support v3.
Published-frame read totals are reconstructed from evidence; any output-refused
terminal frame's counters are explicitly observer-declared, bounded, and not
trace-verified. See [field-streaming.md](field-streaming.md#version-3-explicit-bounded-absolute-guard-batches)
for the exact policy, limits, failure semantics and private-data qualifications.
Windows `self-test` reports separate `native_batch_*` own-child results; portable
success does not claim native performance or game validation.
