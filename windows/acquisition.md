# Private field acquisition

`acquire-fields` executes a finite, private data recipe through the existing
ordinary read-only memory source. It derives a new v1 or v4 named-field profile for one
process instance. The executable contains no application layout, field selector,
decoder constants or bundled game recipe. A recipe is trusted research input;
its field names and successful predicates do not establish gameplay meaning,
player identity or visibility.

```powershell
.\overwatch-decoder-observer.exe acquire-fields --pid 1234 --recipe .\private\recipe.json --out .\private\acquired-01
.\overwatch-decoder-observer.exe record-fields --pid 1234 --profile .\private\acquired-01\profile.json --out .\private\recording-01 --interval-ms 10 --seconds 60
```

The recipe pins the exact executable SHA-256, image name and x64 architecture.
The CLI obtains the main module of the opened process; module-relative reads
must remain within its reported image size. The generated profile binds the
current PID and creation time as well as the build. A later process needs a new
acquisition. Different builds require independently supported recipes. There is
no automatic process selection, broad address scan, retry, permission escalation,
script execution, plugin loading or target write.

## Recipe contract

The UTF-8 JSON schema is `overwatch-decoder.acquisition-recipe/1`. Its required root keys are
`schema`, `target`, `seconds`, `constants`, `functions`, `stages`,
`global_guards` and `fields`. Optional `profile_schema` selects
`overwatch-decoder.field-profile/1` (default) or `overwatch-decoder.field-profile/4`. Optional
`field_collections` expands retained rows into named fields as described below. Unknown and duplicate object keys are rejected where
a fixed schema applies. `target` contains only `image_name`,
`executable_sha256` and `architecture`; `constants` maps identifiers to unsigned
64-bit integers. A function has `parameters` and an `expression`; recursive
function graphs are rejected. A stage has a unique `name` and `steps`.

Expressions are unsigned integer literals or prefix arrays. For example,
`["rva", 0, 8]` describes eight bytes at the main module base;
`["load", ["var", "header"], 0, 8]` reads an unsigned little-endian integer from
an already captured block. Expressions cannot execute arbitrary code.

| Expression | Meaning |
| --- | --- |
| `var(name)`, `get(row, name)` | Scope value or retained row value |
| `call(name, arguments...)` | Pure, nonrecursive recipe function |
| `rva(offset, size)` | Checked main-module-relative address |
| `load(block, offset, width)` | Little-endian unsigned 1/2/4/8-byte integer |
| `slice(block, offset, size)` | Saved bytes with original read ID and offset |
| `count(rows)`, `popcount(integer)` | Row count or set-bit count |
| `add`, `sub`, `mul` | Checked unsigned arithmetic |
| `wrap_add`, `wrap_sub` | Explicit modulo-2^64 arithmetic |
| `and`, `or`, `xor`, `shl`, `shr`, `ror` | Bit operations; shifts must be below 64 |
| `eq`, `ne`, `lt`, `le`, `not`, `both`, `either` | 0/1 predicates; the last two short-circuit |
| `same(block, block)` | Exact byte equality |

Instruction objects have these exact keys:

| `op` | Other keys | Effect |
| --- | --- | --- |
| `let` | `name`, `value` | Assign evaluated scope value |
| `read` | `name`, `address`, `size` | One complete ordinary read or failure |
| `require` | `test` | Fail the whole acquisition on zero |
| `filter` | `test` | Reject this bounded scan row on zero |
| `guard` | `set`, `value` | Capture a block or slice as an exact-byte guard |
| `check` | `set` | Freshly reread every guard in the named set |
| `scan` | `name`, exactly one of `count`/`rows`, `index`, `keep`, `steps` | Evaluate a finite row set and retain only named values |
| `one` | `rows` | Require exactly one retained row and import its values |
| `collect_guards` | `rows`, `from`, `set` | Merge retained row guard sets into a parent set |

A `scan` uses a separate scope per row. `filter` is permitted only inside scans;
read errors are fatal rather than silently treated as filtered rows. A recipe
must place `check` instructions before following dependencies when required by
its evidence. The engine does not infer ownership from arbitrary pointer values.

`global_guards` names a required captured set. Each field has `name`, `type`, an
`address` expression, and optional `guards` (a captured set), `min` and `max`.
Types are `u8`, `i32`, `i32x4`, `f32`, `f64`, `f32x3` and `f32x4`. The generated profile
passes its selected profile parser and all its limits. No declared guard is dropped to
fit a limit, including guards crossing a page boundary. Before publication, every
distinct global or field guard is freshly reread and compared with its captured
bytes. Sequential checks can miss change-and-reversion or same-byte allocation
reuse: this is not an atomic snapshot or a lifetime guarantee.

## Bounds and output

The limits are 1 MiB recipe, 32 stages, 32 functions with at most eight parameters,
512 instructions per list, eight nested scans, 65,536 enumerated rows per scan,
4,096 retained rows per scan, 64 retained names per row, 256 scope variables,
50,000 validated syntax nodes, 2,000,000 executed instructions and 20,000,000
expression evaluations. Expression nesting is at most 64. Native reads are at
most 1 MiB each, 200,000 calls and 64 MiB requested bytes in total; copied slices
are separately capped at 64 MiB. Evidence is capped at 128 MiB, with trace space
reserved before each read. Recipe duration is 1–30 seconds with cooperative
cancellation and process/identity checks. An already executing OS read cannot be
preempted by this timer. These are work and storage bounds, not a hard RSS limit.

The 65,536 enumeration ceiling applies to each scan's visited rows, not its
retained output: the 4,096-row retention bound remains independent. A table of
65,536 fixed 16-byte entries occupies exactly the existing 1 MiB single-read
allowance. The loop visits indices 0–65,535 and rejects 65,537 before entering
it. Checked buffer/address arithmetic, per-row cancellation and all other work,
read, field/guard, evidence and duration limits remain unchanged.

An owned sparse-table fixture retains entries in the upper half and at the last
index, emitting two fields and three distinct guards. At 65,536 entries it makes
five physical reads requesting 1,048,600 bytes total; the table read is 1,048,576
bytes. One Linux Release fixture run measured 356 ms wall / 363 ms process CPU
and 94,449,808 current-thread allocated bytes, including transient scope copies,
rejected-row exceptions and evidence serialization. These are local fixture
measurements, not target-process latency or a peak-RSS bound. Root buffers are
shared by reference between transient scopes, not copied once per enumerated row.

Boundary/resource tests reject 65,537, excess retained rows, oversized single
reads, read-budget refusal, a 200,001st physical read, and work exceeding the
unchanged two-million-instruction limit. Cancellation is exercised during the
full scan. Limits above 64 MiB / 200,000 calls reject before acquisition starts;
a smaller byte budget also rejects the table before issuing its physical read.
Full hex evidence can exhaust its independent 128 MiB allowance before a recipe
can successfully consume all 64 MiB of requested reads; these coupled limits are
not relaxed to make a boundary fixture succeed.


A new output directory contains the exact `recipe.json`, private `evidence.jsonl`,
`manifest.json` (`overwatch-decoder.acquisition-result/1`) and, only on success, `profile.json`.
The manifest hashes the recipe, evidence and successful profile and records the
build/revision, current process identity, main module, counts, elapsed time and
completion/error status. Stdout returns that same manifest through the normal
command envelope, whose usual serialization may omit null properties. It never
prints captured read bytes. The module address remains in the command result as
explicit acquisition provenance, so the result also remains private research data.

The attempt is assembled in a new sibling `.overwatch-decoder-acquisition-*` directory. Its
manifest is flushed before the directory is published with an exclusive rename.
Existing destinations are never overwritten. A failed read or predicate publishes
a failure manifest with partial evidence and no final profile. Early parsing,
identity or cancellation failures may create no attempt. Publication/I/O failure
can leave the private sibling directory for inspection; it is not a completed
output. Neither a `profile_validated` trace line nor a `profile.partial` file is
publication proof. Require the successful manifest and matching profile hash.

Each attempted read records the actual `source.Read` start/end monotonic ticks,
requested bytes, returned count when known, error and complete bytes only when
successful. Read exceptions have an unknown returned count; partial buffers are
rejected. No attempt is invented for pre-read cancellation or budget refusal.
The trace includes UTC/monotonic origins and frequency, recipe/source provenance,
stage/selection records and guard links to original and repeated read IDs. Read
brackets enclose source calls, not necessarily just native-copy time. A supplied
replay source is labeled separately from native process memory.

The generated profile is immediately usable by existing streaming/recording commands.
Those commands still perform their own before/after guards and process checks;
acquisition does not make stale profiles valid or provide relocation during a
recording. The existing record verifier does not verify acquisition recipes or
their trace semantics. Keep the acquisition artifacts with the recording as
separate provenance.

Portable tests cover selection, relocation, exact identity, guard reuse/change,
cross-page coverage, bounds, cancellation, failures and exclusive publication.
Windows self-test additionally uses our bounded native pointer fixture: its
descriptor supplies the synthetic root, two acquisitions follow a controlled
relocation, and bad identity/cancellation/process exit reject. That fixture does
not prove automatic root discovery for an external application. Saved-byte
replay can test an actual private recipe, but missing final reads must remain
missing or be explicitly labeled historical composition, never fresh checks.


## Timer profiles and retained-row guards

A v4 recipe field uses `type: "f32"`, `codec: "elapsed_i64_f32_v1"`, an
`address` expression for the 16-byte state, a separate `clock_address` expression
for the 8-byte counter, and literal `counter_scale_f32_hex`. Optional `min`/`max`
constrain only the final calculated result. Acquisition resolves both expressions
and emits the existing [v4 profile contract](field-streaming.md#version-4-fixed-calculated-timer-fields);
it does not evaluate the timer or infer its semantics. Invalid codec/scale and
v1 recipes containing timer declarations are rejected before source reads. The
separate recording still captures raw operands and checks all guards per frame.

`collect_guards` consumes only already retained scan rows. For example:

```json
{"op":"collect_guards","rows":"choices","from":"row_guards","set":"global"}
```

It visits the existing parent set first, then each retained row's named guard set
in order. Exact `(address, bytes)` duplicates keep their first read provenance;
distinct consistent overlaps remain separate. Conflicting overlapping bytes fail
with `acquisition_guard_conflict`. A missing row list, missing named member or
non-guard member fails explicitly. There is no traversal, new read or expression
extension. At most 4,096 retained rows and 256 distinct guards are accepted;
guard visits charge the existing instruction budget and check cancellation.
Collection trace records identify every retained guard's original read ID and
slice offset. V4 profiles allow at most 1,536 guard declarations across field
dependencies while retaining at most 256 distinct checks. Repeated dependencies
do not add physical reads or become globals; v1 keeps its 256-declaration cap.
Final profile read/output caps still apply, so complete
proof sets that do not fit fail without pruning. A recipe must explicitly retain
and collect every alternative's required checks if its unique-selection evidence
depends on those alternatives remaining unchanged.


## Finite acquisition and observation

```powershell
.\overwatch-decoder-observer.exe observe-fields --pid 1234 --recipe .\private\recipe.json --out .\private\observation-01 --seconds 600 --interval-ms 10
```

`ObserveFields.Run(source, module, recipePath, outputDirectory, intervalMs,
duration, cancellation)` performs acquisition and recording under one finite
wall-time window. The CLI opens one explicit PID and holds that process handle;
it does not follow a replacement process. The recipe bytes are read once, hashed,
and saved. Each attempt uses those same bytes and the same build/process identity.
No external script or transport helper is required. This command consumes a
separately supplied private recipe; no application recipe is bundled.

The new directory contains `recipe.json`, a `overwatch-decoder.field-observation/1`
`manifest.json`, numbered `acquisition-0001` directories with the standard
acquisition artifacts, and numbered `segment-0001` directories with standard
named recordings. A checkpoint identifies the active operation/directory before
it starts. Closed entries link exact profile and manifest hashes. Profiles and
recordings are never rewritten to conceal an earlier failure.

A before/after identity-guard failure in a sink-accepted frame ends that segment.
The original unknown fields, guard evidence and read brackets remain in it; the
ordinary recording is flushed with its terminal summary before reacquisition.
The segment summary normally says `cancelled` because the controller requested
that stop; the session entry separately identifies `guard_invalidation` and the
trigger sequence/read envelope. A new acquisition and profile are required for
another segment. Nothing weakens a guard, caches an old value, or carries numeric
continuity across segments. Local frame sequences and timestamp origins restart;
absolute monotonic ticks and per-segment UTC mappings remain available.

The session lists initial, inter-segment and final intervals without recorded
frames, including acquisition/retry/flush time. Missed scheduled slots inside a
segment remain in its original frames and summary. Frame/field counts in the
session describe frames accepted by the recording sink, not independently
reconstructed durable counts. Physical output failure can leave only a durable
indexed prefix. Strictly verify each segment with `verify-fields` before analysis;
the session manifest is a linking/checkpoint format, not a new verification or
merged-export format. Export, summary and timeline commands still take one
segment directory at a time.

At most eight acquisition attempts and eight segments are allowed. Acquisition
predicate/selection/guard mismatches and unreadable/partial reads can retry after
a cancellation-aware 250 ms wait; three consecutive acquisition failures stop.
Permission denial, process exit, identity/module mismatch, malformed recipes and
other non-retryable failures stop immediately. Guard invalidation starts the next
attempt without that retry delay. Two seconds of sampled all-field unknowns for
other reasons stops without pointless reacquisition. Time is checked around
operations; synchronous native/file calls cannot be forcibly interrupted and can
overrun cancellation or the requested deadline.

The interval is 10–10,000 ms (default 10), and the CLI duration is 1–36,000 seconds
(default 600). Shared across the session are at most 128,000,000 forwarded source
reads, 8 GiB requested source bytes, 128 MiB acquisition evidence, 32 GiB decoded
recording JSON, 2 GiB compressed samples and 64 MiB index data. Existing
per-acquisition, profile, frame, chunk and free-disk limits still apply. Eight
bounded recipe/profile copies and manifests plus those storage caps fit under a
3 GiB artifact envelope; no existing directory contents are scanned or deleted.
These ceilings do not guarantee that a large profile can fill the requested
window. A stopped session is not automatically resumed.

`complete: true` means the finite window ended and every declared field was
observed at least once. It does not mean continuous availability, correct gameplay
semantics, player visibility or atomic snapshots. A field never observed makes
duration completion `fields_never_observed`; a retry/budget/error/cancellation stop
also remains incomplete. A successful session can contain intentionally stopped
segments. CLI exit codes are 0 for this session completion, 4 for permission
denial, 2 for target identity/process exit, and 7 for other incomplete sessions;
argument/open failures retain their existing command error handling.

Global guards couple all fields: one changing collection guard can invalidate
otherwise stable fields in the same profile. Reacquisition preserves that
dependency declaration rather than pruning it. Use independently justified
field-local guards in the private recipe when appropriate. Wrapped native reads
retain `native_process_memory` acquisition provenance, and the session explicitly
labels its budget wrapper; fixture sources remain `provided_memory_source`.

Portable tests exercise changed collection counts, the saved invalid frame,
fresh-profile recovery, bounded failed acquisition, all-unknown stops, fatal
identity/permission/exit, shared budgets, cancellation, non-overwrite and finite
completion. The Windows self-test additionally relocates our own bounded child
allocation, saves the failed guard frame, reacquires it, and strictly verifies
both segments. Synthetic tests do not establish game support.


## Live compact JSONL

```powershell
.\overwatch-decoder-observer.exe observe-fields --pid 1234 --recipe .\private\recipe.json --out .\private\observation-02 --seconds 600 --interval-ms 10 --jsonl true
```

`--jsonl true` replaces the usual final command-result envelope with
`overwatch-decoder.field-live/1` JSONL on UTF-8 stdout. The default `false` retains the previous
interface. The API's optional `liveOutput` takes a caller-owned `TextWriter`; use
UTF-8 when its physical byte size must match the reported UTF-8 budget. This live
projection is additional output; the full raw recording, guards, timer operands,
unknowns and read evidence remain unchanged. There is no network service or
background daemon.

Every line has a session ID, ordered event sequence, emitted monotonic tick and
frequency. Event kinds are:

- `session_start`: process/build, recipe hash, revision, timing origin and research
  qualifications. The saved observation manifest carries the same session ID.
- `acquisition_start` and `acquisition_end`: explicit open observation gap and
  bounded acquisition result, including profile/manifest hashes when available.
- `segment_start`: new segment number, profile hash, declared field types/ranges
  and codec parameters. Profiles never silently change within a segment.
- `gap`: an exact initial, inter-segment or final interval without recorded frames.
- `frame`: segment-local sequence, target/profile identity, scheduled and actual
  frame ticks, UTC mapping, skipped slots and compact per-field observations.
- `segment_end`: closed segment result, terminal-summary presence and manifest
  hash. It is still not an independent verification result.
- `session_end`: the final session snapshot, explicitly named
  `result_before_this_write`. Its live counters exclude this final write; the saved
  manifest is updated afterward with returned-write counts or delivery failure.

Each field retains its type, exact numeric value or null, status, reason, read
bracket, attempt marker and read error. `source` is `process_memory` for scalars
and vectors or `calculated_process_memory` for timer calculations. Timers also
retain the codec, scale, raw operand bytes and separate state/counter read
brackets; their outer bracket remains an operand envelope. Legacy v1 attempts
remain null rather than inferred from a timestamp. Runtime addresses, guard bytes
and pointer traces are omitted from the live projection. Arbitrary profile names
and numerical values can still be sensitive: this is **private research data**,
not anonymized or public output. Source labels do not validate gameplay meaning,
units, player visibility or atomicity.

A live frame is emitted only after the raw sink accepts that full frame. Its
`recording_state` is `accepted_not_durability_verified`; that frame can still be in
the pending gzip member. A live writer flush does not prove downstream receipt,
consumption or disk durability. Use the ordinary per-segment strict verifier on
closed recordings. Hard termination may leave a partial final live line and a
non-durable raw tail; consumers must reject incomplete JSONL lines and must not
invent a terminal summary.

Live output is bounded to 512 MiB of UTF-8 bytes including newlines, with a 512 KiB
line ceiling and 256 KiB reserved for end evidence. There is no asynchronous frame
queue, resampling or catch-up. Synchronous serialization/write/flush time delays
sampling, and subsequent missed slots expose that backpressure. Live write timing
is reported separately in the session manifest. A blocked synchronous writer
cannot be forcibly cancelled; it can overrun the requested deadline until the
write returns. These are bounded data volumes, not a hard delivery-latency promise.

A byte cap or broken/closed/denied pipe stops the observation rather than silently
dropping live frames while capture continues. The already accepted raw frame is
retained and the segment is closed normally where storage permits. Pipe failure
can leave a partial or unconfirmed live line, so completed-write counters exclude
that attempted line and the manifest explicitly marks uncertainty. No further
writes are attempted after a physical sink failure; an output-size stop can use
its reserved end space. The exit status remains incomplete, and the saved
manifest records the delivery error even when the terminal live line cannot be
sent. Errors before live startup use the existing command error envelope.

Tests compare exact live values and read metadata with saved frames, including
unknowns and segment invalidation. Calculated timer projections are checked
against a strictly verified compact export. They also cover output caps,
unconfirmed/broken writes, cancellation and a short synthetic backpressure gap.
The native owned-child lifecycle additionally checks four live frames spanning
the observed relocation and one unknown. No live-game validation is implied.


## Fields from retained collections

An optional `field_collections` array emits existing field templates for each row
of a named retained scan result. For example, after a scan retains `address` and
`entity_guards` in `entities`:

```json
{
  "fields": [],
  "field_collections": [
    {
      "rows": "entities",
      "prefix": "entity",
      "fields": [
        {
          "name": "value",
          "type": "i32",
          "address": ["add", ["var", "address"], 8],
          "guards": "entity_guards"
        }
      ]
    }
  ]
}
```

This is a root-key excerpt; all other required recipe keys still apply. Ordinary
`fields` are emitted first, unchanged. Collections follow declaration order;
within each collection, rows follow retained order and templates follow their
listed order. Expressions and named field guard sets resolve in the root scope
overlaid with that row's retained values. The root `global_guards` set still
applies to every field. No ownership or row guards are inferred: recipes must
capture and retain the dependencies their observations require.

Generated names are `prefix_0000_name`, `prefix_0001_name`, and so on, using a
zero-based four-digit decimal ordinal. Names must fit the existing 64-character
field-name limit and be unique across ordinary fields and every collection.
These ordinals identify positions in one acquisition's retained list only. A
reordered list can give the same name a different observed object on the next
acquisition; neither a prefix nor an ordinal supplies persistent entity identity.
Keep segment/acquisition provenance with every value. `observe-fields` retains
its default field-shape checks: if a later acquisition changes the field count,
names or types, observation ends with `field_shape_changed`. The separate
`--allow-field-shape-changes true` option permits name additions/removals between
segments; it does not make ordinal names persistent identities.

The `fields` array may be empty only when a nonempty `field_collections` array
is present. Every collection requires `rows`, `prefix`, and a `fields` template
array, and may additionally contain a nonempty `field_collections` array of the
same collection nodes. Direct `fields` may be empty only when children are present.
Unknown/duplicate keys, empty child declarations and fieldless leaves reject.
Missing or non-row scope values fail with
`acquisition_missing_rows`; an empty retained list fails with
`acquisition_empty_field_collection` unless that collection declares
`"allow_empty": true`. This optional boolean defaults to false. An admitted empty
collection emits no fields, preserves sibling fields and records a zero-row
collection trace; it does not invent unknown values or weaken parent/global
guards. A missing row list still fails, and the final profile must contain at
least one field. More than 160 total expanded fields fails
with `acquisition_field_limit`; generated name collisions and excessive name
length fail with `acquisition_duplicate_field_name` and
`acquisition_field_name_limit`. Missing explicitly requested guard sets retain
the existing `acquisition_missing_guard_set` error. No partial output profile is
published on these failures.

Expansion adds no process reads, executes within the existing instruction,
expression, elapsed-time and cancellation limits, and cannot increase the profile
field, guard or physical read-byte limits. Existing profile parsing remains the
final admission check, including its declaration accounting for the selected
profile version. Every distinct captured global or per-field guard is reread
before publication using the normal read/evidence budgets. A `field_collection`
evidence row records the retained-list name, prefix, row count, first output
index and expanded field count; it labels identity as acquisition-local ordinals.
The `field_collection_output` stage notification permits cancellation before
expansion without publishing a profile. All resulting fields remain private
research, with no new gameplay or visibility interpretation.

Nested collections support retained rows such as actors with differing numbers
of occupied pools. For example, this collection emits each actor's position and
then its own retained pool scalars:

```json
{
  "rows": "actors",
  "prefix": "actor",
  "fields": [
    {"name":"position","type":"f32x3","address":["var","position_address"],"guards":"actor_guards"}
  ],
  "field_collections": [
    {
      "rows": "pools",
      "prefix": "pool",
      "allow_empty": true,
      "fields": [
        {"name":"value","type":"f32","address":["var","scalar_address"],"guards":"pool_guards"}
      ]
    }
  ]
}
```

The acquisition scan must explicitly retain each actor's `pools` row list and
required values/guards. At every level, the parent merged scope is copied and
overlaid with the current retained row; child row-list lookup, expressions and
named guard sets use that merged scope. Child values override parent values of
the same name, without leaking into siblings. Guards are not automatically
inherited as dependencies: a child template must name a guard set containing its
required actor/pool checks, or those checks must be declared global.

Ordinary fields come first. Each collection visits retained rows in order,
emits that row's direct templates in order, and expands its child collections
before advancing to the next row. Names concatenate the full ordinal path:
`actor_0000_position`, `actor_0000_pool_0000_value`, and
`actor_0001_pool_0000_value`. All names still share one 64-character/uniqueness
check; nesting can collide with an explicitly named direct or ordinary field.
No missing rows are padded with unknown fields. Missing nested row lists still
fail. The example explicitly permits an actor to have no occupied pools while
retaining its position; empty required collections still fail as described above.

At most four collection levels are permitted, counting the root collection as
level one; excess depth rejects with `acquisition_field_collection_depth` before
source reads. Collection syntax charges the existing validation-node budget.
Each expanded collection node, retained row and direct field charges the shared
instruction budget and checks cancellation/identity/time. Nesting adds no reads
and does not multiply the 160-field ceiling, guard-declaration limits or physical
profile/frame byte ceilings. Every collection trace includes its full parent
ordinal prefix and depth, and its expanded range includes descendants. These
paths identify one acquisition's traversal, not actors across acquisitions or
player-visible state.
