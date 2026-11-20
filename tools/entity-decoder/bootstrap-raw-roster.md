# Fresh-census raw recording

`bootstrap_raw_roster.py` prepares a fresh raw roster recording on Windows from
an explicit PID and a pinned private input bundle. It runs a native controller
census, verifies its evidence, generates disjoint exact-controller recipes and
health layouts, then starts the tracked finite raw runtime. No saved participant
map, names, teams, self anchor or prebuilt plan is needed.

```text
python -I BUNDLE/tools/entity-decoder/bootstrap_raw_roster.py \
  --bundle BUNDLE --inventory-sha256 INPUT_INVENTORY_SHA256 \
  --pid EXPLICIT_PID --output NEW_PRIVATE_OUTPUT \
  --seconds 60 --interval-ms 50
```

An optional pinned `partial_sources: true` enables the separate
[partial-source stream](runtime-partial.md). Failed partitions remain explicit
unknowns while other sources publish; this is not a complete aggregate roster.

The pinned input inventory includes the tracked `overwatch_decoder` package and decoder modules,
this entrypoint, `bootstrap-config.json` and three caller-owned inputs. The config
has schema `overwatch-decoder.raw-roster-bootstrap-config/1` and these required fields:

- `native_exe`, its `native_sha256`, and `native_revision`;
- bundle-relative `census_recipe`, `roster_template`, `health_layout_seed`;
- `partition_size` and `maximum_partitions` (at most sixteen);
- `private_controlled_fixture_reviewed: true`, `public_state_eligible: false`.

The roster template uses the [planner's existing schema](plan_live_roster.py).
The layout seed uses `overwatch-decoder.health-layout/1` and must declare exactly one ordered
actor prefix per partition slot. The caller asserts that this order matches its
template's retained rows. Generated layouts preserve every declared extent,
offset, stride, slot and field suffix; only the generated recipe hash and a prefix
slice for a smaller final partition change. The bootstrap does not discover a
layout or establish its gameplay meaning. Every partition subsequently needs its
own fresh native acquisition and health-contract validation.

The process's exact build must match all supplied inputs. A process replacement
between census and recording is rejected by the runtime's full identity checks.
A caller that already selected a process lifetime can also pass
`--target-creation-file-time FILETIME`. The owner forwards this positive Windows
creation timestamp to its worker. The verified census must match both the PID
and that timestamp before any bundle builder or recording runtime starts. A
mismatch preserves the failed census evidence and reports
`census_target_creation_mismatch`; it never records the replacement process.
This check follows the bounded census acquisition, not the first native read.
A changed controller roster requires a new bootstrap. No game inputs, injection,
permission changes, process discovery or writes to target memory occur.

The output contains `census/`, a separately pinned `runtime-bundle/`, bootstrap
receipts and the runtime's `recording/` directory. Read
`recording/compact-roster.jsonl` while it runs. Its candidates retain unknown
names, teams, self identity and visibility; all sampled fields remain in the
native evidence. Output is private and is never uploaded automatically.

The owner launches a worker using the existing inherited-handle job gate. The
worker enrolls before creating the census or runtime child. Its descendants,
including the runtime's separately owned collectors, stay within the outer
kill-on-close job. The target game is never assigned to either job. Acquisition
has a 45-second subprocess timeout; runtime has a 180-second bound; the outer
worker has a 240-second bound followed by bounded owned-job cleanup. Failed
acquisition, changed inputs, invalid evidence, runtime failure or incomplete
cleanup produce failure receipts and preserve partial local evidence. This is a
finite recorder, not an unbounded background daemon or whole-match launcher.

Portable tests cover generated identity coverage, a smaller final partition,
unchanged layout semantics, deterministic inventories, input mutation, build and
recipe pins, output collisions and explicit worker-job enrollment. A portable
test does not establish actual Windows nested-job behavior or fresh live capture.
Separate Windows trials verified the
fresh census/plan, nested-job cleanup, unavailable-to-present body recovery and
explicit final invalidation after successful producer completion. Logical-roster
uncertainty remains.

## Optional pinned private bundle builder

The legacy template/layout packaging path above is unchanged. A caller can
instead provide `bundle_builder` in the same bootstrap config:

```json
{
  "schema": "overwatch-decoder.raw-roster-bootstrap-config/1",
  "native_exe": "<explicit native executable>",
  "native_sha256": "<executable SHA-256>",
  "native_revision": "<observer revision>",
  "census_recipe": "private/census-recipe.json",
  "maximum_partitions": 10,
  "private_controlled_fixture_reviewed": true,
  "public_state_eligible": false,
  "bundle_builder": {
    "entrypoint": "private/build-runtime.py",
    "inputs": "private/builder-inputs.json",
    "timeout_seconds": 45
  }
}
```

In this branch the old `roster_template`, `health_layout_seed` and
`partition_size` inputs are not required. The census recipe, private entrypoint,
inputs, code dependencies and static assets must belong to the already verified
input inventory. There is no shell-command string or arbitrary argument list.
The extension does not put application layouts or offsets in tracked code.

After taking and verifying a fresh native census, the already-enrolled worker
runs this finite child using its Python interpreter:

```text
python -I -B PINNED_ENTRYPOINT \
  --input-bundle VERIFIED_INPUT_BUNDLE \
  --input-inventory-sha256 INPUT_INVENTORY_SHA256 \
  --inputs PINNED_INPUTS \
  --census-acquisition NEW_VERIFIED_CENSUS_DIRECTORY \
  --output NEW_RUNTIME_BUNDLE \
  --receipt NEW_BUILDER_RECEIPT_JSON
```

The child must use the measured target from that census, including its new PID
and creation time. A historical expected-target asset is not a current process
identity. Private factories remain responsible for checking allowed executable
build/name/architecture and reviewed native recipe/layout semantics. The tracked
parent checks exact census identity and provenance again after packaging.

The child returns a receipt with schema
`overwatch-decoder.raw-roster-bundle-builder-result/1`, `complete: true`, exact
`input_inventory_sha256`, `target`, `census_source`, generated
`inventory_sha256`, `plan_sha256`, `controllers` and `partitions`. The output uses
`roster-plan.json`, `census/`, `p1.json` through `pN.json`, and an exhaustive
`inventory.json`. Its generic plan still has schema `overwatch-decoder.live-roster-plan/1` and
requires fresh native acquisition; it does not contain saved epoch profiles.
A failed child may retain a bounded receipt with `complete: false` and `error`.

Before starting the runtime, the parent independently verifies:

- the generated runtime inventory and entrypoints, with at most 4,096 inventoried
  files and 512 MiB of content;
- unchanged copies of all original inventoried inputs, and exactly the original
  fresh census bytes/guards/source hashes;
- the existing `raw_roster_inputs` controller and primary-once coverage checks,
  no fixed self/actor anchor, and the configured partition bound;
- every producer's raw mode, exact target/native pins, recipe, reviewed health
  layout build/recipe pin and inventoried asset paths;
- no unlisted output, symlink or saved acquisition/profile outside `census/`;
- every output code file's byte identity with a verified input code asset, and
  the same requirement for configured context- or ammunition-composer code even
  if renamed.

Generated recipe/layout/admission-input data may change only through the pinned
private builder. Generating a new inventory cannot authorize changed original
inputs, newly manufactured code or a roster from an old census. Optional cached
labels or neutral context candidates do not introduce name/team/self semantics.
The runtime still takes a new native acquisition and builds its own health and
context admissions for every epoch.

The extension child inherits the outer worker's kill-on-close job. It has a
1–45 second timeout. Stdout/stderr are discarded; a bounded result receipt and
small parent-written command receipt retain the outcome. The outer worker wait
is the legacy 240 seconds plus the explicit extension timeout, at most 285
seconds, followed by the same bounded owned-job cleanup. It does not become a
match-long supervisor. No extension is executed on the legacy path.

Portable tests exercise a real local extension child and reject changed census
bytes, stale profiles, duplicate/foreign primaries, changed copied inputs,
unlisted output, newly generated code, wrong receipt pins, nonzero exit and
child timeout. A private implementation also reproduced a ten-controller
context/cache bundle from saved native census evidence, then passed a synthetic
new-PID/creation-time test with entirely new opaque controller keys. These are
packaging checks, not new Windows collection, native cache acceptance or evidence
that an old saved census is current.

A Windows check subsequently ran the pinned private builder against that saved
ten-controller census inside an owned, enrolled child. It generated and admitted
all ten partitions in 5.40 seconds, exited successfully and closed the owned job.
The parent independently checked the generated inventory, exact copied census,
primary-controller coverage, recipe/layout pins and copied executable code. The
result receipt SHA-256 was
`0d9da39aec08ce4c728528321e781c76948819584492bf3a1dbec05c14b6fd45`.
This verifies Windows packaging and process ownership. It performed no game
inputs or native process reads; fresh live bootstrap acceptance remains pending.

A later private builder generates one combined reciprocal/forward-owner recipe
per census controller, with pinned optional-owner bindings, health/category
templates and controller-hero assets. This keeps the eleven-controller saved
roster within the sixteen-source runtime bound and samples each health payload
only once. Explicit empty collections retain unknown owners rather than aborting
the source. The actual bootstrap parent admitted all eleven generated partitions
on Linux, and every producer config and recipe/template comparison passed. This
used saved census evidence; it did not run the Windows observer. The generated
bundle still requires a new native acquisition for every player source.
