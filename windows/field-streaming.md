# Guarded named-field research stream

`overwatch-decoder-observer.exe stream-fields --pid PID --profile PRIVATE_PROFILE --interval-ms 10 --seconds 600` writes UTF-8 newline-delimited JSON frames to standard output, followed by one summary. Redirect standard output to a new file to retain a session. An incomplete run exits with code 7; startup failures use the regular error envelope. Ctrl+C stops between operations and writes the summary when the output remains writable.

The underlying `FieldStream.Run(IMemorySource source, string profilePath, int intervalMs, TimeSpan duration, TextWriter output, CancellationToken token)` API returns the same summary. It uses the existing ordinary read-only memory source and `PreciseWait`. Version-1 profiles do not follow pointers. Version-2 profiles can follow explicitly declared bounded plain-pointer paths, described below. Version 3 explicitly opts into bounded absolute-guard batches, described below. No version discovers addresses or validates gameplay semantics.

Every line identifies the exact process/build and profile SHA-256, declares `interpretation: "profile_declared_research"`, `runtime_semantics_validated: false`, `public_state_eligible: false`, and `atomic: false`. A label such as `position_candidate` is the profile author's interpretation. Successful byte guards do not establish active-player ownership, visibility, or gameplay meaning.

See [bounded field and transport capacity](field-capacity.md) for the current
160-field/512-KiB limits, unchanged physical budgets and offline capacity evidence.

## Profile

A profile binds the PID, process creation time, image name, executable digest and x64 architecture. All profile versions support `u8`, `i32`, `i32x4`, `f32`, `f64`, `f32x3`, and `f32x4`; multibyte types use little-endian bytes. `u8` reads exactly one byte and emits an unsigned JSON integer from 0 through 255, with the same optional range and exact-guard checks. It does not mask bits, interpret flags, read neighboring bytes, or imply any gameplay meaning. Its address and read budgets use one byte, including at the last permitted address. Each field requires at least one effective exact-byte guard. Root guards apply to every field; a field's own guards apply only to that field. Duplicate shared guards are read once per pass.

`i32x4` reads one contiguous 16-byte range and emits four exact signed 32-bit JSON
integers. It does not reinterpret the words as floating-point values. Range
checks apply to every component; a short read or invalid component makes the
whole vector unknown. Strict recording verification rejects fractional,
out-of-range and incorrectly sized integer arrays. One read is not an atomic
snapshot guarantee, and a range crossing an unreadable boundary can fail even
where some separate scalar reads would succeed. Acquisition, pointer profiles,
recording/export, summaries and change timelines support the same type.

This example uses synthetic fixture addresses and an illustrative identity; replace all identity and address values using evidence from the intended source:

```json
{
  "schema": "overwatch-decoder.field-profile/1",
  "target": {
    "pid": 321,
    "image_name": "fixture.exe",
    "creation_file_time": 9,
    "executable_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "architecture": "x64"
  },
  "guards": [{"address": 4096, "bytes_hex": "01000000"}],
  "fields": [
    {"name": "counter_candidate", "type": "i32", "address": 4128, "min": 0, "max": 100},
    {
      "name": "vector_candidate",
      "type": "f32x3",
      "address": 4160,
      "min": -100,
      "max": 100,
      "guards": [{"address": 4100, "bytes_hex": "02000000"}]
    }
  ]
}
```

Names must be unique and contain 1–64 ASCII letters, digits, underscores, hyphens or periods. Optional `min`/`max` are finite inclusive bounds, applied to each vector component. Floating values must always be finite. Any invalid component makes the whole vector unknown. Unknown properties, duplicate JSON keys, unknown types, unguarded fields, invalid identity data and contradictory guards at the same address within one field are rejected. Profile identity mismatches fail before streaming or memory reads.

## Sampling and failure behavior

Each frame checks target identity, reads all guards, reads eligible fields, reads all guards again, and rechecks target identity. An applicable failed pre-guard prevents the field read. An applicable failed post-guard invalidates the sampled value. Fields always contain either a fresh value with `status: "observed"`, or `value: null` with `status: "unknown"` and a reason. There is no cached-value fallback.

A guard mismatch or ordinary read gap affects its dependent fields and permits later recovery. Non-finite or out-of-range values become unknown. Permission denial, target exit, target identity change, cancellation and exhausted resource budgets stop the stream. A fatal event during a frame invalidates every field in that frame. No subsequent memory reads are scheduled after a fatal read failure. On a late or cancelled frame, unattempted guard entries carry the stop reason; their timestamps do not imply a native read occurred.

Guards are sampled sequentially, not atomically. Their before/after checks can miss reuse that changes and restores the same bytes between checks. Static tags, plausible ranges and readable pages are insufficient to prove object lifetime or identity. Profiles need evidence-backed lifetime/ownership guards, and still must treat this stream as research.

Frames expose per-field and per-guard monotonic read start/end times, batch start/end, scheduled slot, jitter, skipped intervals, timestamp frequency and a bracketed UTC origin. Shared guard IDs index the before/after arrays. Identity and digest are repeated on every line; private executable paths and memory addresses are omitted from version-1 output. Version-2 output includes explicitly labeled private pointer evidence. The profile remains private.

Version-2 frame timestamps may use a literal `+` in the UTC offset where earlier
writers escaped it as `\u002B`. The decoded timestamp, field values, nulls, guard
and path evidence, and property names are unchanged. Version-1 serialization is
unchanged. New v2 wire bytes and hashes can therefore differ; limits and hashes
always use the exact bytes written. Existing saved recordings still use their
original bytes and hashes and remain supported by the same verifier.

Intervals are 10–10,000 ms, with a positive duration up to 10 hours. Late sampling and slow output skip elapsed slots; there are no queued catch-up reads. The actual timer backend and summary diagnostics report Windows high-resolution waitable timer availability or its managed fallback. No global timer resolution or process priority changes are made. There is no hard realtime guarantee. Synchronous source reads and writer calls cannot be interrupted mid-call; cancellation and duration checks occur between operations, with actual overruns reported.

## Bounds and output handling

- Profile: at most 256 KiB, 160 fields, 256 guard declarations, and 64 bytes per guard.
- Planned memory reads: at most 32 KiB per frame, counting both guard passes and all field reads; 8 GiB total attempted reads.
- Output: at most 512 MiB measured as UTF-8 serialized JSON bytes including newlines and a reserved summary. Use a UTF-8 writer when that must also be the on-disk byte budget. An individual frame is capped at 512 KiB.

Caps fail explicitly rather than dropping fields or truncating a profile. The summary's `complete` means the requested duration ended; it does not mean every field was available. `unknown_fields` counts unknown values in emitted frames. Read statistics also include attempted samples that could not fit the remaining output budget. Each complete line is flushed, so prior frames remain usable after interruption. Output I/O exceptions propagate to the caller; a hard interruption or failed write can leave an incomplete final line, which a replay consumer should reject. The writer and memory source remain owned by the caller.

`FieldStreamTests.Run()` returns its assertion count. Portable tests use generated byte arrays and sample-driven cancellation, with a generous timeout only as a failure watchdog. They cover decoding, guard bracketing, allocation reuse during a read, field-local invalidation, failures and recovery, target changes, process exit, non-finite vectors, strict profile/resource limits, cancellation and skipped scheduling slots under slow reads/output. They do not provide live-game validation.


## Compressed named recordings

```powershell
.\overwatch-decoder-observer.exe record-fields --pid 1234 --profile .\private-profile.json --out .\new-recording --interval-ms 10 --seconds 1800
```

The destination must not exist. The command prints one final manifest envelope to
stdout and returns 7 for an incomplete recording. `stream-fields` continues to
print each live frame directly to stdout with its original output limit.

For a profile that represents one entity lifetime, add `--stop-on-unknown true`.
The recorder retains the first frame containing an unknown field, then permanently
ends that invocation with `stop_reason: first_unknown` and `complete: false`.
Matching guards later cannot resume the expired recording. Reacquire dependencies
and start a new recording before interpreting later values. The switch defaults
to false; ordinary unknown/recovery recording remains available. An earlier caller
cancellation or an explicit terminal source failure keeps its own stop reason.
The saved summary, manifest and returned result use the same terminal reason.

`FieldRecording.Record(IMemorySource source, string profilePath, string outDirectory, int intervalMs, TimeSpan duration, CancellationToken token)` uses the same field sampler and returns a `overwatch-decoder.field-recording/1` manifest. The destination must not exist. Identity and profile validation occur before creating it. The ordinary `FieldStream.Run` stdout contract and its 512 MiB budget are unchanged.

The recording directory contains the exact private `profile.json`, `samples.jsonl.gz`, `chunks.jsonl`, and `manifest.json`. Every decompressed line is the selected profile version's `overwatch-decoder.field-stream/1`, `/2`, `/3` or `/4` JSONL contract, byte-for-byte as serialized, including all read times, unknowns, target identity, profile digest and the terminal summary. Compression does not remove repeated metadata or rewrite values. The profile contains private addresses and must remain private.

Whole JSONL lines are grouped into complete gzip members of at most 1 MiB of uncompressed data. The writer commits after roughly one second of active sampling or when a chunk fills. Each member is compressed in memory, appended and flushed to disk before its index entry is appended and flushed. Index entries record compressed offsets and lengths, line numbers/counts, compressed and uncompressed SHA-256 digests, and checkpoint ticks/frequency. OS flush requests do not guarantee storage-hardware behavior. Synchronous read or output stalls can delay checkpoints; measured write time and skipped intervals expose this cost.

Clean cancellation, read/identity stops, duration completion and budget exhaustion finish the accepted lines and a terminal summary. The manifest distinguishes `complete` from a stopped or failed recording and embeds the stream summary. A failed physical write can prevent a final summary or manifest; recovery uses the original manifest, saved profile and complete index entries. Hard termination may lose the in-memory chunk and leave an unindexed or incomplete suffix. Replay only the contiguous indexed prefix: verify each member digest, decompress exactly its indexed byte range, verify the JSON digest/size/line count, and reject any gap, mismatch or partial index line. Ignore unindexed sample bytes. Individual chunks are independently decompressible. On a clean finish, full-file hashes are provided; durable-prefix hashes remain separately identified for failure analysis.

Recording budgets are 32 GiB of serialized UTF-8 JSON, 2 GiB of compressed samples, 64 MiB of chunk index, a 256 KiB profile and a small manifest. The existing 8 GiB attempted-read, frame/profile limits and 10-hour duration limit still apply. The writer checks for at least 32 MiB of free disk during active recording and reserves room for a terminal summary. Near the compressed or index cap it can stop conservatively before the exact byte ceiling. No accepted frames are silently discarded to fit a cap. These bounds allow longer recordings when compression helps; they do not promise a particular duration for every profile.

The integrated self-test verifies unknown/recovery preservation, exact UTF-8 replay, per-member and full-file hashes, interruption recovery, summary reserves under JSON/compressed/index limits, identity/profile rejection, output overwrite rejection, cancellation and duration completion. On Windows it also records and replays changing fields from our own child fixture through native memory access. These tests provide no game semantics or native scheduler benchmark.

For a finite acquire/record/reacquire session, `observe-fields` accepts a private
recipe and writes separate standard recording segments after guard invalidation.
The triggering unknown frame is retained. Its session manifest records profile
changes and observation gaps; it does not join field values across those gaps or
replace per-segment verification. See [acquisition.md](acquisition.md#finite-acquisition-and-observation)
for completion semantics, retry/resource limits and the command. Its optional
`--jsonl true` emits a separate compact live format on stdout, with explicit
accepted-but-not-durability-verified frames and session/segment/gap boundaries;
full proof stays in the ordinary recording segments.

## Offline verification and indexed-prefix recovery

`verify-fields` reads the four fixed artifact filenames without opening a target process or writing any files. It emits a compact `overwatch-decoder.field-recording-verification/1` result inside the normal command envelope:

```powershell
overwatch-decoder-observer.exe verify-fields --from PRIVATE_RECORDING_DIRECTORY
overwatch-decoder-observer.exe verify-fields --from INTERRUPTED_RECORDING_DIRECTORY --recover-indexed-prefix true
```

Exit 0 means the complete artifact verifies, including a valid recording that stopped early; inspect `complete` and `status` to distinguish these cases. Exit 7 means verification failed or only a prefix could be recovered. The underlying API is `FieldRecordingVerification.Verify(directory, recoverIndexedPrefix: false, cancellationToken)`. Its portable tests are included in `self-test`.

Strict mode checks the exact profile hash and schema, target/source identity on every line, contiguous index offsets/line numbers/sequences, each compressed and decoded SHA-256, gzip trailer CRC/size, complete JSONL member boundaries, and final manifest/full-file hashes. It also validates named field types/ranges, guard IDs, before/after guard and field read order, null unknowns, frame sequence/scheduling/skipped-slot accounting, consistent timestamp origins and summary counts/timing. Read totals may include a sampled frame refused by the output budget, so the verifier checks their bounds and the minimum implied by emitted observations rather than inventing exact unrecorded reads. Duplicate JSON keys are rejected. Hashes establish internal consistency, not authenticity against an actor able to replace all artifact files.

Result statuses distinguish `verified_complete`, `verified_stopped`, `recoverable_prefix`, `invalid` and `cancelled`. `valid` is true only when the entire artifact and its terminal manifest verify. `complete` additionally requires the recording's duration-completion result; a verified cancellation or budget stop remains incomplete. Reports contain counts, prefix digests and fixed error codes, without profile addresses, field values or target paths.

Pass `recoverIndexedPrefix: true` explicitly to inspect an interrupted artifact. The verifier stops at the first invalid, partial, missing, gapped or corrupt index/member and reports only earlier **fully validated chunks**. It never resynchronizes beyond an error or accepts part of a damaged chunk. An unindexed sample suffix is rejected in strict mode; recovery reports its byte count and excludes it. A partial index line similarly excludes that entry and everything after it. A valid terminal line with a stale or mismatched manifest does not establish completion. Even a terminal prefix followed by an unindexed tail has `valid: false` and `complete: false`. The result identifies the verified compressed/index byte lengths for a consumer that chooses to replay that prefix; this API does not extract or rewrite data.

Hard limits match the writer: 256 KiB each for profile and manifest, 64 MiB index, 2 GiB compressed input, 32 GiB decoded total, 1 MiB decoded per member, and 512 KiB per JSONL line (8 KiB summary). An index entry is at most 4 KiB; a compressed member is at most 1 MiB plus 8 KiB overhead. Verification also bounds work to 200,000 chunks, 3,600,001 lines and 15 minutes checked between operations. The declared recording budgets are checked as well. Decompression stops after the indexed decoded size plus one byte, so a high-ratio gzip payload cannot expand beyond the per-member bound. Cancellation is checked during chunk decompression and line validation. Synchronous file calls may block beyond a cancellation or time deadline; no hard wall-clock guarantee is made. Copying a recording while another process mutates it is unsupported; use a stable saved artifact.

Synthetic tests cover clean duration completion and cancellation, no-write behavior, every prefix/hash/count layer, forged semantic data with recomputed hashes, unknown retention and guard failures, malformed profiles and path redirection, torn members/index lines, stale manifests, unindexed tails, missing/extra summaries, corrupt CRC/trailers, an 8 MiB high-ratio decompression fixture, explicit input/work limits and cancellation. They use no game data or live processes.

## Compact offline timeline export

`export-fields` creates a research-only JSONL timeline from a saved v1, v2, v3 or v4 named recording. It performs no process access, playback pacing, networking or discovery:

```powershell
overwatch-decoder-observer.exe export-fields --from PRIVATE_RECORDING_DIRECTORY --out NEW_TIMELINE.jsonl
```

The output parent directory must already exist, and the destination must be new and outside the recording directory. API: `FieldExport.Export(directory, outputPath, cancellationToken)`. Exit 0 means the export was published; inspect `source_status` and `source_complete` to distinguish a `verified_complete` recording from a valid `verified_stopped` recording. A stopped source retains its stop reason and all its recorded frames. Interrupted/recoverable prefixes, stale manifests, unindexed tails and corrupt artifacts are rejected; the exporter has no recovery override.

The `overwatch-decoder.field-timeline/1` file has one metadata line, every recorded frame in its original order, and one summary line. Metadata includes process/build identity, exact profile and manifest SHA-256, source compressed/index hashes, recording revision, field names/types/ranges and the UTC/monotonic origin mapping. Frames retain sequence and scheduled slot, scheduled/start/end/jitter ticks, skipped intervals, scheduler backend, and every field's value, status, unknown reason and read start/end ticks. V2 also retains `read_attempted`. Numeric values and integer timestamps are copied as JSON values without floating-point conversion; consumers must use integer-capable parsing for large ticks. No interpolation, resampling, stale-value retention or gameplay interpretation is added. Summary timing/counts/stop reason remain source measurements; `source_json_sha256` identifies the exact original decoded stream.

Runtime addresses, pointer paths, guard IDs, pointer bytes and guard traces are omitted through an explicit property allowlist. Their private source recording remains necessary for detailed evidence review. Field names and scalar/vector values are intentionally preserved, so this is not a general-purpose privacy scrubber or public-state projection. Metadata explicitly retains `profile_declared_research`, `visibility: research`, `runtime_semantics_validated: false`, `public_state_eligible: false`, and non-atomic/non-realtime labels. An observed candidate does not become a validated game field through export.

The strict verifier validates and delivers the **same in-memory decoded chunk** to the exporter; there is no later reopen/replay of samples or profile after validation. Profile/manifest provenance comes from the exact byte snapshots used by that verifier. Whole-source hashes, ordered frames, summaries and v2 path proofs must all pass before publication. This binds the export to the validated bytes, not to a claim that files remain unchanged after the operation. Use stable source files; concurrent mutation is unsupported, and integrity hashes are not authenticity signatures.

Export uses bounded memory (metadata, one decoded member and one output line), the verifier's input/decompression/work limits above, a 512 KiB output-line cap and an 8 GiB total UTF-8 output cap. A limit stops the entire export without dropping frames. Cancellation is checked between operations and output lines. Synchronous I/O can delay cancellation. Only a uniquely named `.overwatch-decoder-export-*.partial` sibling is written until validation completes; it is flushed and renamed without overwriting an existing destination. Errors/cancellation remove that temporary file; abrupt process termination can leave an explicitly named partial file, never a completed-looking destination. The source recording is read only. The final CLI result reports export counts, byte length and SHA-256; it does not contain private paths or addresses.

Portable self-tests cover byte-preserved timing/value/null projections for both versions, guard-failure unknowns, zero-frame stopped sources, duration completion, strict corruption and truncation rejection, pointer-proof forgery with recomputed hashes, trace redaction, input/output bounds, cancellation before/during/finalizing output, existing destinations and a publication race. They also confirm the source files remain byte-identical and output errors are not misreported as input corruption.

`u8` retains its type and exact integer value in recordings and compact exports. Strict verification rejects negative, above-255, fractional, floating-notation, string and null values marked observed, even when an artifact's hashes have been recomputed. Null values remain valid only for explicit unknown observations. Existing field types and the recording container schema are unchanged; an older reader without `u8` support rejects such a profile. Synthetic tests cover byte endpoints, partial/unreadable bytes, range/guard failures, exact byte budgets and fixed/pointer final-address arithmetic. Windows self-test additionally observes bytes already present in the owned fixtures; their established layouts are unchanged.

## Offline numeric summary

```powershell
overwatch-decoder-observer.exe summarize-fields --from PRIVATE_RECORDING_DIRECTORY
```

API: `FieldSummary.Summarize(directory, cancellationToken)`. The command emits one `overwatch-decoder.field-summary/1` JSON result, inside the normal command envelope, after the entire v1/v2/v3/v4 recording passes strict verification. It uses the verifier's exact decoded buffers and metadata snapshots, with no validation-then-reread step, file output, live process access or source modification. A valid stopped recording is supported and remains `source_status: verified_stopped`, `source_complete: false`; report `complete: true` means analysis finished, not that recording ran for its requested duration. Invalid/truncated/recoverable-prefix input, cancellation or exceeded bounds yields an error without a partial successful report.

The report retains target process/build identity, profile and stream schema versions, exact profile/manifest/compressed/index/decoded SHA-256, source revision when available, stop reasons, frame/missed-slot totals and the UTC/monotonic origin mapping. It omits structural addresses and guard traces. Its per-field entries preserve the declared name/type/range and report:

- `observed_count`, `unknown_count`, and exact unknown-reason counts.
- `components`, with zero-based component index and observed numeric minimum/maximum. A scalar has one component. No observations means null bounds, not zero.
- `first_read`/`last_read` start/end ticks for any recorded field-read interval, including failed reads, and separate `first_observed_read`/`last_observed_read` for observed values. A field never read has null times. Version 1 may retain a measured interval for an unattempted read on a terminal control stop; no stronger native-read claim is made.
- `observed_numeric_changes`, counting one change when any scalar/vector component differs between two consecutive observed frames with consecutive scheduled slots. `eligible_adjacent_observed_pairs` is the number of comparisons actually made. Unknown frames and missing scheduled slots break adjacency; unchanged observed values count as an eligible pair but not a change. Equality is numeric, including equal positive/negative zero.
- `largest_observed_sampling_gap_ticks`, the greatest start-to-start gap between consecutive observed samples, including gaps across unknowns or missed slots. Fewer than two observed samples gives null. This measures coverage gaps, not continuous valid sampling. `largest_read_duration_ticks` is the maximum end-minus-start of recorded read intervals, including failures; no read interval gives null. Divide tick durations by the reported monotonic frequency to obtain seconds.

Numeric changes are observations, **not game events**. The report derives no velocity, units, hero labels, visibility, ownership or gameplay state. Labels, numeric values and unknown reasons remain private research data, not anonymized/public output. A zero-frame stopped recording retains all declared fields with zero counts and null ranges/times.

Memory retains only bounded metadata, one decoded chunk/line, and per-field aggregates. Existing verifier limits apply, including its 15-minute checked work bound; the summary additionally allows at most 64 distinct unknown reasons per field, 1,024 reason entries across all fields, and a 1 MiB UTF-8 report payload. Exceeding a bound rejects the whole summary without truncating reasons or ranges. Cancellation is checked during verification and aggregation and before returning the report; synchronous input calls can delay cancellation. As with verification, use stable files and directories; matching hashes establish consistency of the consumed bytes, not authenticity or future file immutability.

Portable tests use synthetic v1/v2 recordings with a deterministic saved clock to verify byte endpoints, vector ranges, unknown and missed-slot adjacency breaks, first/last and largest-gap/read-duration metrics, all-unknown and never-read fields, zero-frame stops and duration completion. They also exercise late corruption after aggregate work, truncation, cancellation and explicit reason/report/input limits, and check byte-for-byte source immutability.


## Guarded pointer paths (version 2)

A `overwatch-decoder.field-profile/2` profile opts into `overwatch-decoder.field-stream/2`. Existing commands and API signatures accept both versions; version-1 profile validation, output shape and fixed-address behavior remain unchanged. Version 2 follows only explicitly declared plain little-endian 64-bit pointers and fixed nonnegative offsets. It has no scanning, encoded-pointer transforms, module discovery, collection search, count predicates, or game constants. Process/build identity remains exact, so a process restart requires a fresh profile.

**Version-2 frames and recordings contain private runtime addresses and pointer/guard bytes.** Frames, summaries and recording manifests carry `private_address_trace: true`. Keep these artifacts private, just like their profiles. Do not treat them as a public gameplay projection or upload them as evidence. Verifier results still report only counts, hashes and error codes.

This complete example describes synthetic fixture storage only:

```json
{
  "schema": "overwatch-decoder.field-profile/2",
  "target": {
    "pid": 321,
    "image_name": "fixture.exe",
    "creation_file_time": 9,
    "executable_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "architecture": "x64"
  },
  "paths": [{
    "name": "storage",
    "root_address": 4096,
    "root_guards": [{"offset": 0, "bytes_hex": "01000000"}],
    "hops": [{
      "pointer_offset": 16,
      "destination_guards": [{"offset": 0, "bytes_hex": "02000000"}]
    }]
  }],
  "fields": [{
    "name": "sample_candidate",
    "type": "i32",
    "path": "storage",
    "offset": 8,
    "min": 0,
    "max": 100
  }]
}
```

Each named path begins at its fixed `root_address`. Nonempty `root_guards` check exact bytes relative to that root. A hop reads eight bytes at the current base plus `pointer_offset`, checks the resulting address range, then verifies its nonempty `destination_guards` relative to the destination. Only a fully guarded destination can supply another hop or a field. A field specifies either `address`, or `path` plus `offset`, never both. The existing absolute top-level and field-local `guards` remain available; a path's root guards apply only to fields using that path, while top-level guards apply to all fields. Every declared path must be used. Contradictory overlapping exact guards within a relative guard set or effective absolute field/root guard set are rejected.

A frame checks target identity and absolute/root guards, resolves each eligible path once, reads fields, then checks paths in reverse order before the absolute/root post-pass and final identity check. For each path, destination guards and pointer slots are reread from leaf to root at their **original sampled addresses**. The post-pass never follows a newly changed pointer. Any changed pointer or failed destination/root guard makes dependent fields unknown for that frame. Unrelated fields remain independent unless a fatal error stops the entire frame. There is no cached path/value fallback and no within-frame retry. The next scheduled frame can observe relocated storage if all its guards pass.

Null pointers, unreadable/partial reads, invalid arithmetic, cycles, guard failures and nonfinite/out-of-range field values produce explicit unknowns. Permission denial, process exit, identity mismatch, cancellation, duration and aggregate budgets retain the existing terminal behavior. Every pointer/relative-guard read records `attempted`, address hex, exact successful bytes, monotonic start/end and error. Unattempted reads have null addresses/bytes/timestamps. Absolute guard timing keeps the version-1 convention described above. Fields add `path_id` (null for fixed fields), `read_attempted`, and `read_address_hex`. `path_traces` contains path IDs/status/reasons and each hop's `pointer_before`, `guards_before`, `guards_after`, and `pointer_after`. Addresses are fixed-width hex strings, avoiding JSON integer precision loss.

Limits add at most 32 paths, four hops per path and a 1 MiB maximum fixed offset. Checked arithmetic covers the whole requested width. All root/destination/absolute guard declarations share the existing 256-declaration cap; each guard remains at most 64 bytes. The planned cost includes both pointer passes and both guard passes, with at most 32 KiB and 1,024 native read calls per frame, plus the existing 8 GiB total attempted-read limit. A conservative trace-size check rejects oversized plans; the actual 512 KiB line cap still applies. Profile, scheduling, duration, output, compression and disk budgets remain unchanged. Additional reads and serialization can increase jitter and skipped slots; there is no promised sample rate.

The recording container/index stay at version 1 because chunk framing and exact UTF-8 line preservation are unchanged. Version-2 manifests additionally identify `profile_schema` and `stream_schema`. `verify-fields` selects validation from the saved profile, requires the matching stream version/private label, recomputes pointer arithmetic and resolved field addresses, checks exact guard evidence and pre/post pointer equality, and validates actual operation order, unknowns and read-count minima. All evidence stays inside the same hashed compressed chunks, so indexed-prefix recovery does not depend on a separate address sidecar. Older verifiers reject version-2 profiles.

A stable root and matching tags do not independently prove ownership, lifetime, visibility or gameplay meaning. Profiles need evidence-backed lifetime/membership guards. Exact count guards intentionally fail when counts change; this version does not weaken them into range predicates. Reallocation between frames is supported only when the new route satisfies the declared guards. Before/after sampling cannot detect an ABA transition that changes and restores identical bytes between reads. Reads remain non-atomic.

`PointerPathTests.Run()` is included in `self-test`. Its controlled sources test stable/shared/four-hop paths, relocation and recovery, intermediate changes retaining the same leaf, changed allocation guards, independent fields, nulls, read gaps, range overflow/cycles, finite vectors, identity/fatal/cancellation/budget stops and late-frame skipping. It also records and verifies compressed v2 traces, rejects trace tampering even after hashes are rebuilt, and recovers only a complete indexed prefix after truncation. A synthetic ABA case explicitly demonstrates the detection limit. These portable tests do not establish native Windows timing or game semantics.


### Native pointer fixture

On Windows, `self-test` also launches the separate `fixture-pointers --seconds 60` child. The established `fixture` command and its memory layout are unchanged. The new fixture owns a small guarded root and two guarded allocations containing known values 7 and 42, plus an independent value 99. It accepts at most 64 stdin commands, each at most 16 characters: `a`, `b`, `null`, `bad`, and `stop`. These switch its own pointer/storage state; the observer still uses ordinary query/read access only. With no input, the fixture exits at its declared deadline. The fixture descriptor contains private synthetic addresses.

The native test advances only after observing the expected state: first allocation, relocated second allocation, null unknown, destination-guard unknown, and recovery to the first allocation. It checks that the independent field remains 99 throughout. It then makes a compressed v2 recording, cancels after three actual value reads, and verifies its saved profile/chunks/trace and final unknown fields offline. Generous deadlines are watchdogs, not minimum-sample assumptions. All child processes and temporary recordings are cleaned up by the test.

The self-test report includes `native_pointer_frames`, `native_pointer_unknown_frames`, `native_pointer_relocations`, `native_pointer_recording_frames`, and `native_pointer_recording_verified`. Non-Windows runs explicitly report zero/false with `native_windows_test: "not_run_on_this_platform"`. Portable fixture command/shutdown checks do not count as native memory evidence; a passing Windows run is required for that claim.

## Sparse comparison timeline

```powershell
overwatch-decoder-observer.exe timeline-fields --from PRIVATE_RECORDING_DIRECTORY --out NEW_CHANGES.jsonl
```

API: `FieldTimeline.Export(directory, outputPath, cancellationToken)`. This offline command accepts only `--from` and `--out`. It consumes strictly verified v1/v2/v3/v4 recordings through the verifier's same decoded-buffer sink. A valid stopped capture remains `verified_stopped`, including a capture with zero frames; complete sources retain `verified_complete`. Recoverable prefixes, corrupt frames or path proofs, unfinished manifests and unindexed tails are rejected. It never opens a target process.

The `overwatch-decoder.field-change-timeline/1` JSONL file is sparse:

- `metadata` pins the target/build, recording revision, exact profile/manifest/compressed/index hashes, declared fields and UTC/monotonic origin mapping. Fields remain private, profile-declared research candidates.
- `frame` rows appear for a baseline, numeric change, status/reason transition, comparison reset or missed-slot gap. Each observation carries a field/type, comparison-segment number, reset reasons, and `before`/`after` samples with the original sequence, scheduled slot/ticks, actual frame bracket, read bracket, status, reason and value. V2/v3 retain `read_attempted`; v1 reports it as null because the format does not consistently distinguish unattempted control-stop reads. Numeric values retain their original JSON number tokens; ticks remain integer numbers, including values above JavaScript's exact-integer range.
- `summary` retains source completion/stop information and the decoded-stream hash, total and emitted frame counts, numeric-change counts, all field coverage/reason counts, the last actual frame/sample, and the final status run. `trailing_gap` explicitly records skipped slots reported only by the source summary. No final value is presented as current after its read interval.

Comparisons require two consecutive recorded frames in consecutive scheduled slots, with both samples observed. An unknown sample, changed unknown reason or missed slot starts a new comparison segment. The next known sample is a baseline even when it equals the last known value. For v2/v3, a change in any pointer-slot address or destination along the full verified route, or in the final field read address, also resets the affected fields. This detects intermediate relocation even if the final field address stays the same; independent fields keep their continuity. Route bytes and runtime addresses are used privately for this comparison and omitted from output. Fixed v1 addresses and unchanged v2/v3 routes cannot prove allocation identity when reuse passes every recorded guard.

`numeric_change` uses numeric equality without epsilon: integer values compare exactly, floating values compare their finite recorded numeric values, and a vector changes once if any component differs. Positive and negative zero compare equal. Both complete vectors are retained. The optional `sampling_comparison_envelope` extends from the preceding read start to the current read end and is explicitly sampling evidence, **not an event occurrence time or duration**. Both original read intervals remain separately available. No units, interpolation, velocity, hero labels or gameplay events are inferred.

Unchanged frames are omitted, but unknowns are not filled with stale values. `closed_status_run` and `final_status_run` identify the first/last samples and count of recorded samples having the same status/reason within one comparison segment. Every missing-slot boundary closes the run, even for an unchanged unknown reason. Runs describe recorded samples only; they do not establish continuous observation between reads. Use `export-fields` when every individual frame/read interval is needed. Arbitrary profile labels, values and reasons remain private data; removal of structural traces is not anonymization or a visibility determination.

Publication follows the existing exporter contract: a new destination outside the source recording, an existing parent directory, a unique `.overwatch-decoder-timeline-*.partial` sibling, durable flush, and rename without overwrite only after full verification and final summary creation. Normal failure/cancellation removes the temporary output; abrupt termination may leave an explicitly named partial file. There is no verification-then-reread window. Source hashes identify the exact validated buffers, not a promise that files remain unchanged afterward or an authenticity signature.

Bounds are the strict verifier's existing input/decompression/work limits, all **160** supported fields, one previous sample/status-run boundary per field, one validated chunk, a 512 KiB output-line cap and an 8 GiB total UTF-8 cap. Unknown-reason counters are limited to 64 distinct reasons per field and 1,024 entries overall. Any exceeded bound rejects the whole timeline without dropping fields, resampling or publishing a truncated result. Cancellation is checked while consuming input and emitting output; synchronous I/O may delay it. The CLI success result includes output counts, exact UTF-8 byte length and SHA-256, separate from the source's complete/stopped status. Its `complete: true` means publication succeeded; the timeline summary's `complete` is copied from the source stream and describes that stream's completion. Use `source_recording_complete` and `source_verification_status` for the verified recording outcome. A valid wide profile can exceed the 512 KiB boundary-row cap because before/after and status-run endpoints are retained; this fails explicitly with `timeline_byte_limit`, never by dropping fields.


## Version 3: explicit bounded absolute-guard batches

Version 3 is opt-in through `schema: "overwatch-decoder.field-profile/3"` and a required
`absolute_guard_reads` object. Existing v1/v2 profiles and their wire formats
keep their prior execution and serialization. Use the same target, fields and
plain-pointer declarations as v2; `paths: []` supports fixed-address-only v3
profiles. The policy below uses the defaults; either numeric option may be omitted.

```json
"absolute_guard_reads": {
  "algorithm": "consecutive_same_dependencies_v1",
  "maximum_span_bytes": 128,
  "maximum_gap_bytes": 32
}
```

The planner groups only consecutive deduplicated absolute guard IDs in their
original first-occurrence order, with nondecreasing addresses and identical
sets of dependent fields **and direct path roots**. It never sorts or skips IDs
to find a better group. A batch has at most 32 logical guards and a bounding span
of 64–512 configured bytes; every internal uncovered gap is at most 0–32 configured
bytes. Every absolute guard and resulting batch must fit inside one 4,096-byte
boundary. A straddling absolute guard is rejected, not split. Overlapping bytes
are read once per batch and checked independently against each predicate.

Only absolute guards are combined. Before and after passes use the same ordered
plan, with fresh reads. Pointer hops, destination guards and fields retain their
individual operations and dependencies; reverse path postchecks still precede
the absolute after pass. There is no cross-page/phase reuse, cache or retry. Gap
bytes are read but not interpreted or saved. The full requested span, including
gaps and failed/partial attempts, counts against the unchanged 32 KiB/frame and
8 GiB session read limits. The profile and frame evidence retain the existing
256 KiB profile bound, 512 KiB frame bound, 160-field limit and 256 guard-declaration limit. An additional
conservative evidence-size check can reject a wide profile; runtime output caps
still fail explicitly without dropping logical guards or fields.

`overwatch-decoder.field-stream/3` retains private research labeling and the v2 pointer traces.
Its `guard_batches_before/after` arrays contain physical batch ID, attempted flag,
actual read address, requested byte count, logical guard count, returned byte
count when known, read start/end ticks and error. For an attempted v3 operation,
the bracket directly encloses `source.Read`; it includes implementation and OS
work inside that call and is not a measurement of pure native memory-copy CPU
time. V1/v2 brackets retain their previous surrounding control/check overhead.
An unattempted batch has null address, returned count and read timestamps. A
source exception leaves returned count null unless a return was actually received;
zero is not invented.

Logical `guards_before/after` contain guard ID, batch ID, exact slice offset and
length, observed slice bytes, match result and error. They have **no separate read
timestamps**: all slices refer to their batch's real interval. A buffer is usable
only when its length equals the full requested span. Any read failure or short
return makes every slice in that batch unknown, even if an individual prefix was
readable. A successful buffer may match some slices and mismatch others. Because
batched guards share dependency sets, read faults do not widen their field/path
scope; gap reads can nevertheless introduce faults that unbatched reads avoid.
Fatal failures stop subsequent calls and invalidate the whole frame. Cancellation
is checked before each operation; a synchronous call already in progress cannot
be interrupted or made hard realtime. The frame's `terminal_reason` identifies a
terminal stop, and v3 fields preserve `read_error` separately from their final
reason, which can be superseded by a later frame-wide failure.

`physical_read_calls`, `physical_read_bytes` and `guard_gap_read_bytes` describe
attempted operations in each published frame. The verifier reconstructs these
counts exactly from the batch, pointer, destination-guard and field evidence.
The summary records the physical plan, comparable unbatched call and byte plan
(`unbatched_planned_read_calls_per_frame` and `unbatched_planned_read_bytes_per_frame`),
published counts and total requested bytes. A frame can be sampled and then refused by an
output/chunk/disk limit. Its counts are reported separately with
`unpublished_frames` (0 or 1) and the mandatory qualification
`unpublished_read_accounting: "observer_declared_bounded_not_trace_verified"`.
That qualification is also in the recording manifest. No unpublished values or
read trace are recoverable. The verifier checks the refusal reason, one-frame
bounds and provable mandatory-prefix constraints; it cannot independently
reconstruct those tail counts. Overall totals including such a tail must not be
called fully trace-verified. `export-fields` carries this qualification alongside
all published/unpublished counters and retains v3 field `read_error` values.

The compressed recording/index containers remain version 1. Their manifest pins
profile/stream version 3, and the strict verifier recomputes the batch plan from
saved profile bytes. It rejects missing or reordered mappings, false match flags,
inconsistent overlapping slices, partial-buffer acceptance, fabricated serial
slice intervals, incorrect physical totals, impossible control transitions and
frames after a terminal stop. Recovery accepts only the same whole indexed prefix
as before; no invalid batch is rescued by recomputing a looser plan.

`verify-fields`, `export-fields`, `summarize-fields` and `timeline-fields` accept
v3 through the same validated-buffer path. Their private numeric observations,
unknowns, gaps, publication safety and hash provenance remain unchanged. Compact
outputs omit batch addresses and raw guard bytes. Timeline comparisons still reset
on any verified pointer-route change, even when the final value stays equal.
Numeric summary/timeline reports do not expose aggregate read-call totals.

Portable tests use bounded synthetic sources, including faults in gaps, partial
returns, cancellation, root/path dependency boundaries, rehashed malicious records,
output-refused zero-frame recordings and existing v1/v2 serialization fixtures.
Windows self-test additionally exercises v3 reads and gap-byte accounting against
the owned pointer child, relocation/null/bad-destination recovery, compressed
recording verification and offline consumers. `native_batch_*` result fields are
zero/false on non-Windows runs; native success requires an actual Windows run.
These tests do not establish game semantics, player visibility, atomic snapshots,
or a latency benefit. Before/after checks can still miss changes that restore the
same guarded bytes between observations.


## Version 4: fixed calculated timer fields

A `overwatch-decoder.field-profile/4` profile produces `overwatch-decoder.field-stream/4`. It supports ordinary
absolute-address fields plus 1–16 fields using the fixed
`elapsed_i64_f32_v1` codec. It has no pointer paths, expressions, automatic
relocation, rounded display count, or application-specific constants. Addresses,
scale and exact guards are private profile inputs. Existing v1–v3 parsing,
serialization and read behavior remain unchanged.

A synthetic timer declaration is:

```json
{
  "name": "remaining_duration_candidate",
  "type": "f32",
  "codec": "elapsed_i64_f32_v1",
  "address": 65536,
  "clock_address": 65600,
  "counter_scale_f32_hex": "0000803f",
  "min": 0
}
```

The surrounding profile has the existing exact target identity and nonempty
effective guards. `address` identifies a 16-byte little-endian state block:
signed i64 stamp at offset 0, f32 base at 8, and f32 rate at 12. `clock_address`
identifies a separate signed i64 counter. `counter_scale_f32_hex` is exactly four
little-endian bytes encoding a finite, strictly positive f32. It is not a decimal
string or a unit declaration. The example scale is 1, not a game-derived value.

The codec computes wrapping signed `counter - stamp`, converts that signed i64
directly to f32, multiplies by scale, then by rate, subtracts from base, and clamps
negative results to positive zero. Each conversion/arithmetic stage uses binary32
rounding; multiplication and subtraction remain separate operations, without FMA.
Equality retains the source result, including negative zero. This assumes the
observer's default nearest-even floating-point environment; it does not measure
or reproduce an external process's floating-point control register. Nonfinite
base/rate or any nonfinite intermediate produces unknown. Optional `min`/`max`
bounds apply to the final clamped result only. Counter backsteps and residual
changes remain visible; the reader never smooths, makes the counter monotonic,
extrapolates across gaps or infers successful actions.

V4 checks each absolute guard in declaration/deduplication order, reads each
field, then checks every guard again. Its `single_guard_v1` plan makes one exact
physical read per guard per pass, with no gaps, merging, caching or retries.
Cross-page guards remain intact. Consistent overlapping guards, including
different widths at the same address, are retained separately; conflicting bytes
within an effective field guard set are rejected. A successful guard only proves
a sampled byte comparison, not continuous lifetime or atomicity.

Each timer reads its state block first and its counter second. A failed state
read prevents the counter read. Two timer fields sharing a counter still make
separate counter reads. Every guard has one nested physical `read` record, and
every timer retains `operands.state` and `operands.clock`: attempted flag,
requested width, actual address, returned count when known, complete raw bytes,
actual start/end ticks and error. Unattempted reads have null address/count/bytes/
times; failed or partial reads retain no partial bytes. Intervals bracket the
actual source call, including any work inside the source implementation.

The timer's ordinary `read_start_ticks`/`read_end_ticks` enclose its attempted
operand reads and are explicitly labeled `read_kind: "operand_envelope"`.
**This envelope is not one physical read, an atomic sample, or an event time.**
Pre-guard failures prevent operands; read gaps, post-guard failures, identity
changes and terminal stops make the calculated value null. Already captured raw
operands remain evidence even when the final result is unknown. Ordinary fields
remain independent of nonfatal timer-local errors.

V4 permits at most 1,536 guard declarations, deduplicated to at most 256 exact
physical checks. Repeating a check on two field-local dependency lists preserves
both dependencies without making that check global. This lets a failed timer
collection check invalidate its timers while an independent movement field
remains observed. Versions 1–3 retain their 256-declaration limit.

The 160-field, 64-byte-per-guard, 256 KiB profile and 512 KiB line,
32 KiB planned-read-per-frame, 1,024-call-per-frame and total read/output
budgets remain in force. Timer state/counter widths count in full, including
failed attempts. Evidence admission measures a padded serialized frame using the
profile's actual names, guard widths and dependency IDs. Its envelope covers
built-in ASCII error codes up to 64 bytes and the native success, unknown and
read-failure shapes; it is not a bound for arbitrary custom-provider error
strings. The actual 512 KiB serialized-line check remains authoritative and can
refuse a sampled frame without publishing it. Large dependency lists may still
reject a profile below the field or guard ceiling. Both planned and actual published read totals
include the separate operands. As in v3, a refused terminal frame's counts are
explicitly observer-declared and bounded, not independently trace-verified.

Recording container/index framing remains version 1. Strict verification selects
v4 from the saved profile, verifies every serial guard and operand proof, exact
widths/counts, operation order, unknown reasons and terminal accounting, then
recomputes the binary32 formula and compares the exact result, including signed
zero. Recovery accepts only complete indexed members under the same rules.
`export-fields`, `summarize-fields` and `timeline-fields` consume these same
validated buffers. Compact export/timeline omit operand addresses but retain raw
numeric operand bytes, their physical brackets, codec/scale and envelope label;
these remain **private research data**, not anonymized or public gameplay state.
Summary read-duration/gap statistics for timers describe operand envelopes and
are labeled accordingly. Timeline values remain calculated observations, without
an inferred event time. The separate browser replay viewer has no claimed v4
compatibility.

Portable tests exercise wrapping/direct conversion, rounding, negative zero,
backsteps, finite/range failures, full guard coverage, cancellation/read budgets,
unknown independence, exact raw provenance, corrupted/rehashed operand and guard
proofs, indexed recovery and all three offline products. Windows self-test adds
a bounded owned child (`fixture-timer --seconds 1..60`) with a deliberately
cross-page guard, a controlled counter backstep and guard invalidation. It checks
native operand bytes and a three-frame stopped recording through strict
verification/export/summary/timeline. The report's `native_timer_frames` and
`native_timer_recording_verified` remain zero/false off Windows. Synthetic proof
establishes this codec implementation, not any application's field semantics.
