# Bounded selected observation runners

`run_selected_live.py` and `run_selected_roster.py` are source-controlled entrypoints
for privately assembled, relocatable Windows bundles. They ship no game offsets,
resource IDs, executable hashes or reviewed category bit assignments. They read
only caller-pinned bundle data. Source checkout execution requires an explicitly
assembled bundle; the repository does not supply the private configuration.

Place the entrypoints and `Start-Practice-JSON.cmd`/`.ps1` at the bundle root.
Dependencies belong in `lib/entity_decoder/` and `lib/overwatch_decoder/`. An `inventory.json`
contains each relative file path, byte size and SHA256. The external archive hash
pins the inventory. `config.json` supplies `python_sha256`, `native_sha256`,
`native_extra_args`, `maximum_bytes`, explicit `batches` (1–8 unique IDs), and launcher-only `python_relative_path`
(relative to LOCALAPPDATA) and `target_process_name`. The executable is
`native/overwatch-decoder-observer.exe`. Capabilities/extra CLI arguments must match that pinned
native version. The runner starts exactly one native child, below normal
priority, preserves original native events, and verifies Windows QPC frequency
before reporting capture-to-output latency. It accepts an optional inherited
`--job-handle`, enrolls before native spawn and immediately closes its handle copy.

Private inputs:

- `private/recipes/batch<ID>.json` and corresponding `.bindings.json` files
  for every configured ID (letters/digits/underscore/hyphen, bounded length). Binding metadata provides `local_context` and bounded
  actor templates; undeclared controllers are omitted, declared controller-only
  acquisitions retain explicit body-unknown observations.
- `private/catalog.json`, SHA-addressed `private/artifacts/*.bin`, and
  `selected-review.sha256`, `native-review.sha256`, `practice-calibration.sha256`.
  Original evidence bytes remain immutable. Operational paths are bundle-relative.
- `private/selected-template.json`, schema `overwatch-decoder.selected-runner-template/1`, with
  `local_validation_status`, `binding_validation_status`,
  `health_validation_status`, and a caller-reviewed `category_rule` object.
  The latter supplies ordered bits, mode mask, supported categories, route
  conditions, validation status and the explicitly reviewed label mapping.
  The pinned native review must match the configured rule. Fresh per-acquisition
  target/profile/source pins and the separate label review are generated from
  actual acquisition files. Template data never bypasses `SelectedEntityView`
  source, field, guard, codec or review validation.

The configured-window parent uses existing `runtime_jobs.spawn_producer` and
`runtime_roster.cleanup_owned`: each producer owns one Windows job tree, and all
owned jobs are terminated/closed and descendants checked on finish or error.
The observed target is never enrolled. Each child retains its normal recordings,
raw events, full provenance, compact updates and QPC receipts. The parent tails
bounded lines at a bounded interval, checks source order/clock, preserves original
entity values/timestamps/epochs/scope, and adds only source batch, input-line hash
and arrival order. It never caches entity values into a combined snapshot.

Single-child completion requires native exit 0 and a complete accepted native
terminal. Clean incomplete terminals remain partial (CLI 7, preserving native
fatal 2/4); runner/admission errors remain failed. Parent completion requires all
configured children complete/exit 0 and successful job cleanup. Partial or failed
children and cleanup failures remain explicit. Finite scope, byte bounds,
unknown visibility, private-research qualification and controlled-Practice label
scope are preserved.

The launcher requires one configured target process and a pinned Python runtime,
creates a new timestamped LOCALAPPDATA recording directory, and sends no game
input or focus changes. It uses a retained `System.Diagnostics.Process` handle,
waits for that exact process and propagates a non-null `ExitCode`; it does not
interpret a missing exit code as success. The CMD entrypoint uses a scoped
PowerShell execution-policy bypass rather than changing host policy.

Tests use synthetic profiles, fake processes and owned-job helpers. Package
validation must additionally check all pins, standalone imports, unchanged
contract generation and actual Windows process/launcher behavior. Saved-frame
replay proves projection equivalence, not current capture-to-output latency.


Explicit empty partitions

Zero bindings remain rejected by default. A source-bound empty contract opts in
with `allow_empty_bindings: true`, `partition_id` and
`empty_partition_review_sha256`. The reviewed artifact uses schema
`overwatch-decoder.selected-empty-partition-review/1`, exact target/profile/source pins and
partition ID, plus `collection: {rows, prefix, event_sha256}`. Manifest, complete
recipe and native acquisition evidence bytes must resolve under their pins.
The existing acquisition-proof validator checks native process source, final
actual guard bytes, completed stages and final profile validation. The exact
pinned native field-collection event must declare an allowed empty top-level
collection with zero retained/expanded fields. The profile must contain exactly
the nine configured local-context/reference declarations. Nonlocal fields,
unchecked guards, absent opt-in, wrong collection/recipe or provided-memory
fixture sources cannot masquerade as an acquired empty process partition.

Runner binding metadata must explicitly set `allow_empty_partition: true` and
supply `empty_collection: {rows, prefix}`. Only then may the runner generate the
review from actual complete acquisition bytes; it never turns an acquisition
failure/capacity rejection into an empty epoch. No extra approval flow is added.
An admitted empty frame still checks current target/profile/context guards and
gaps. It emits `entities: []` and `empty_partition` provenance marking
`acquisition_empty: true`, `current_occupancy: unknown`, and current context
status/reason. It does not claim the partition stayed empty after acquisition.
Compact updates and the parent merge preserve this metadata without a fake actor.

The parent owns one job per configured ID, at most eight, while retaining the
same 1.5 GiB global disk, 512 MiB merged-output and finite duration/cleanup caps.
All configured IDs must complete successfully before the parent reports complete.
Periodic native refresh options belong in version-matched pinned configuration;
this orchestration does not silently add flags to an older observer.


The private template may explicitly opt into `gap_policy: current_frame_only`.
This projects only fresh valid reads after skipped intervals; strict remains the
projector default. Compact and full output preserve policy/gap metadata and keep
no-history/no-carry qualification. Every identity, guard, read bracket, numeric
and codec check still applies. The policy does not fill an observation gap.
