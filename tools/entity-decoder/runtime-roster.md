# Finite local roster runtime

`runtime_roster.py` makes the tested producer/coordinator orchestration reproducible
from tracked source. It launches only an explicitly pinned read-only native
observer through finite owned producer processes. It does not discover processes,
launch or control a game, infer a roster, identify self, review a mode, or supply
memory layouts. The caller supplies those reviewed inputs.

The runtime uses `LiveSession`, `LiveRelations`, `LiveRosterEpochs` and
`CompactLiveRoster` without changing their admission rules. It consumes each
accepted semantic line once. A replacement epoch requires its actual new first
frame, acquisition evidence and contract; an unknown transition clears pending
values. EOF does not flush historical samples or fabricate recovery. Output stays
private research with unknown visibility and accepted-not-durability-verified
provenance. Visibility filtering is not performed.

For independent delivery when some sources fail startup, see the explicit
[partial-source mode](runtime-partial.md). It emits a separate schema and never
substitutes an unadmitted source into the strict aggregate.

## Bundle and invocation

Place the tracked decoder modules at `tools/entity-decoder/` and the tracked `overwatch_decoder`
package at the bundle root. Copy the required private review assets separately.
Forward-owner support also requires `forward_roster_projection.py` and
`forward_owner_validation.py` in that inventory. Source admission reads the fresh
epoch's forward contract and artifact map; the roster preserves a separate owner
list with qualified position, health and controller hero values.
Optional category output also needs `forward_owner_categories.py`. Admission
verifies `forward-category-contract.json` and `forward-category-artifacts.json`
from the fresh epoch, then pins the category contract and native review. These
group candidates do not establish local ownership or friend/foe.
Include `projection_copy.py` for the live, forward-owner and context projections.
Repeated acquisition checks may share a proof only inside one explicitly scoped
factory with identical immutable evidence and checked inputs. Changed inputs,
validation failure or scope exit prevent reuse. Frame output remains detached
from both source data and later results.
Each entrypoint bootstraps only these two paths, including under isolated embedded
Python; it does not modify `_pth`, global settings or the calling directory.

The bundle contains `p1.json` through `pN.json`, matching the supplied plan's
contiguous partition ordinals. `inventory.json` maps bundle-relative file names to
`{"bytes": size, "sha256": digest}`. Include all code, producer configs, recipes,
layouts, composer and review/catalog assets. The caller independently pins this
inventory. Paths escaping the bundle and mismatched files are rejected. The two
entrypoints and `runtime_jobs.py` actually executed must match the inventory; execute the parent from
that bundle, not another checkout.

```text
python tools/entity-decoder/runtime_roster.py \
  --bundle BUNDLE --inventory-sha256 INVENTORY_SHA256 \
  --plan PRIVATE_PLAN_JSON --role-map PRIVATE_CURRENT_ROLE_MAP_JSON \
  --output NEW_PRIVATE_OUTPUT --seconds 120 --interval-ms 50 \
  --ready-timeout 10 --cleanup-seconds 30
```

The existing plan schema is `overwatch-decoder.live-roster-plan/1`. The current-role map uses
`overwatch-decoder.private.current-controller-roster/1`, with the exact target, explicit self key,
`public_state_eligible: false`, and one row per controller. Rows supply the reviewed
cached-label candidate, relative role and initial hero resource; optionally they
also supply full handle/creation words. This runtime checks initial fresh body
bindings, not a historical body reference. Replacement bodies/resources require
fresh admission while controller and reviewed role/label identity remain fixed.
A changed roster or process requires a new bootstrap, not inferred continuity.

The planner/coordinator bounds allow 1–16 partitions and 1–128 supplied controllers.
The anchor must occur in every partition, with one primary owner per controller;
non-anchor controllers occur in one partition. These are input bounds, not a claim
that every such layout fits native field/guard budgets or works at a given rate.
Only five partitions and ten players have been observed in the Windows experiment.

Each producer configuration retains these explicit fields:

- `target`, `native_revision`, `native_exe`, `native_sha256`;
- `recipe`, `recipe_sha256`, `health_layout`;
- `composer`, `composer_sha256`;
- `native_review`, `roster_review`, `category_artifacts`, `reviewed_mode_sources`;
- `hero_catalog`, `hero_artifacts`;
- `private_controlled_fixture_reviewed: true`, `public_state_eligible: false`.

`seconds`, `interval_ms` and the new output directory are set by the parent.
Relative asset paths resolve from the bundle. Every listed asset except the native
executable must be in the pinned inventory; the executable has its own mandatory
hash. Artifact maps still carry their original content-hash checks. The native
session must match the exact configured target, recipe and observer revision.

## Caller composer interface

A private composer remains necessary for the currently proven bundle. Its source
contains recipe-specific derivation and is deliberately not published here. This
is not yet a zero-private-source launcher.

The producer executes the SHA-pinned composer as a separate owned Python process,
through its own bootstrap shim, with a maximum 30-second timeout. The composer CLI
receives `--acquisition`, `--recipe`, `--session-start`, `--segment-start`,
`--native-review`, `--roster-review`, `--artifacts`, `--output-prefix` and repeated
`--reviewed-mode-source` arguments. It must write the existing
`category.contract.json`, `category.artifacts.json`, `category.mode-review.json`,
`category.session-start.json` and `category.segment-start.json` artifacts under that
epoch. Native raw event hashes and pretty artifact hashes remain distinct; parsed
metadata must agree exactly. The parent verifies both provenance chains.

A caller can replace this composer with a wrapper around tracked
`compose_live_categories`, supplying its required explicit reviewed epoch/layout
inputs. The runtime must not manufacture those reviews or copy private offsets
into source. Health descriptors are rebuilt by tracked `build_health_contracts`
from each epoch's own acquisition.

Optional ammunition composition uses `ammunition_composer`,
`ammunition_composer_sha256`, `ammunition_inputs` and `ammunition_inputs_sha256`
together in either observation mode. The producer rechecks these pins, passes
the original session/acquisition-end/segment event bytes to an owned composer,
and admits its three fixed output artifacts through `LiveRelations`. Each epoch
is composed independently; a failed composer stops this configured producer.
No ammunition configuration is inferred or enabled by default. See
[the ammunition interface](ammunition-candidates.md) for the CLI and the current
private composer's exact-profile reuse limit. Full `entities.jsonl` carries the
optional projection. The parent explicitly admits configured ammunition from
the epoch's verified contract, artifacts and original native metadata, then
retains it through aggregation and compact roster output. Include
`ammunition_projection_validation.py` in the pinned runtime inventory; configured
ammunition checks that module before starting its producer. Default output
remains unchanged.

A standalone `raw-candidates` producer may set `include_health_candidates: false`
for an ability-only recipe with no health pool reads. It must omit both ordinary
and forward-owner health layouts. The producer still verifies the fresh native
acquisition and every declared guard before composing other fields; health stays
unknown. This option does not apply to the full-entity bootstrap, which continues
to require health layouts and candidates. The default remains enabled.

## Bounds, failure and evidence

Each producer has a 32-line queue (16 MiB maximum queued payload), 512-KiB native line cap, 512-MiB native byte cap,
100,000-event cap, 1-MiB semantic line cap and 1-GiB semantic output cap. It checks a
finite total deadline; malformed/truncated transport, composer timeout, failed
native exit or missing native session end produce a failed result. The raw log is
flushed before its derived semantic line is published. Each producer tree belongs to a parent-owned Windows Job Object configured only
with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. The original parent handle is not
inherited. A temporary inheritable duplicate passes through an explicit handle list;
the producer must enroll its own current process and close its duplicate before
launching any native or composer child. Assignment denial fails without a child
or bypass. Descendants inherit membership, not the job handle. A direct Windows
composer invocation also requires existing job membership and cannot start capture.
No target PID or process-image cleanup is performed.
The parent retains its finite readiness/total/cleanup deadlines and coordinator
byte/window limits. On normal and fallback cleanup, it joins the owned producer,
terminates its owned job, verifies zero active job processes within the shared
cleanup deadline, and closes every retained job handle even when another cleanup
fails. A missing job or unsuccessful shutdown is a failed cleanup, never success.
If a producer fails before roster admission, the parent saves the incomplete
aggregate receipt and immediately enters bounded owned-job cleanup. Launch and
readiness failures also skip the remaining capture window. Partial native and
semantic files remain incomplete; they are not promoted to a successful roster.
The recorder can then use its configured finite retry to start a fresh census.
Successful and already-admitted runs retain time to finish their finite native
children before fallback cleanup. OS-level termination failures are reported,
not treated as successful cleanup. The Windows fixture described below tests both
forced cleanup and abrupt owner exit; unit tests alone do not establish Windows
scheduler or OS termination behavior.

The parent retains exact input order, admission pins, detailed windows, explicit
transition events, compact output and receipt/output-order hashes. After 20 full
windows in each revision it attempts a bounded, throttled check that every native
source is still recording the expected segment. Successful checks preserve the
exact manifest bytes and identify sequential, non-atomic observations. A missing
revision proof fails the parent completion criterion without rewriting valid
saved output. A finite-stop cancellation may correctly leave a final unknown
transition open with no pending values.

Successful finite completion also explicitly ends the live roster when the native
last frame is still observed. After every producer reaches EOF, the runtime
checks its successful native session end, exact consumed frame count, projection
hash, and final admitted segment/profile. It then calls `end_input` with the
current host QPC and pinned producer results. The stop tick must be at least every
accepted source read end. This records the number and bytes of discarded pending
observations, clears them, and emits an all-unknown transition without advancing
the watermark or publishing a leftover window. Further input or resumption is
rejected. An already-open unknown interval stays open without a duplicate event.

The terminal `input_end` metadata explicitly describes caller-verified producer
completion, not a native sample. Its trigger references the last accepted source
frame; its separately recorded stop tick describes runtime completion. Compact
output preserves this qualification and has no candidate values. Ordinary
`LiveRosterEpochs.close()` keeps its existing offline behavior; only explicit
`end_input` invalidates a successfully completed runtime. Failed or incomplete
producer results cannot authorize the completion path.

## Migration and validation scope

Replace the two private runner scripts with these tracked entrypoints and include
`runtime_jobs.py` in the pinned inventory. The parent passes `--job-handle` to each
producer; callers must not launch a capturing producer without this enrollment gate. Add the
explicit composer path/hash to every producer config, regenerate the inventory,
and pass its digest to the parent. Keep private recipes, current-mode reviews,
account/roster keys, catalogs and artifact maps out of version control. The
producer/parent result schemas are now `overwatch-decoder.local-live-producer-result/1` and
`overwatch-decoder.local-roster-runtime-result/1`; gameplay projection schemas are unchanged.

Focused tests cover isolated imports from an unrelated directory, exact-once
admission dispatch, raw-versus-pretty metadata, input bounds, malformed pipe
failure, pinned composer timeout invocation, inventory mutation/path escape,
readiness failure, fresh-body requirements, snapshot retention, proof throttling
bounded owned-handle cleanup, pre-spawn enrollment failure, explicit inheritance,
active descendant-count verification, and cleanup continuation after errors. An optional private saved-run test is enabled by
`OVERWATCH_DECODER_RUNTIME_SAVED_RUN`; it replays recorded input order and checks all fresh
admissions plus byte-identical windows/transitions, without process access.

That migration replay passed on the complete saved five-source, three-epoch run:
11,203 accepted inputs, 1,140 windows and five transition records, including the
honest terminal unknown. The independently audited original Windows run had
three fresh self bodies with health 175 → 250 → 175, 15 raw active-native manifest
proofs, and no values carried across its recovery barriers. These observations
validate the preserved orchestration semantics. They do not claim that this new
packaging works for an arbitrary human match or discovers its own private inputs.

The tracked entrypoints at `2fe8b66d7ae34f54fa5bcb00ae621b71f8d25bd8` subsequently
passed a fresh 30-second Windows smoke with five partitions, ten players and
isolated embedded Python. The private composer ran through the new owned
subprocess interface. All 2,607 native frames were consumed; the five saved native
segments and 187 chunks verified with terminal summaries and no unverified bytes.
Independent replay reproduced all 271 windows, one terminal unknown transition
and the complete compact output exactly. There were 220 complete windows and
five retained raw native manifests proving concurrent collection. Median delay
from the latest source read was 123.737 ms; p95 was 2,954.657 ms including startup.
The final cancellation kept an honest open unknown barrier. All owned processes
exited normally.

Consume `compact-roster.jsonl` in the new output directory while the runner is
active; each line is flushed after publication. The detailed stream and evidence
references remain beside it. Completion does not turn these non-atomic research
observations into a visibility or canonical human-identity guarantee.

| Smoke evidence | SHA-256 |
|---|---|
| Frozen runtime inventory | `916587a6cf77b1c5c2bf493e8a64db3334a4d200f20721bbd477cc5d1be68385` |
| Full independent replay | `8af5f4e2d0a7a31f5b2cbd1a10f59b711db9e1b47dfb14bea3f1669fa728dba1` |
| Native segment verification | `b5ec433031a4886d771c0719c2a98aac22648a20054405a51c8df62e551336eb` |
| Exact compact output | `f31d96a9264f7410c3da9ff23fd5a086d40e251d3bb5741f4f9a816e75bb254b` |

### Owned descendant cleanup on Windows

The job ownership change at `1efd8ff678f656a509d81b37b42a72bc11616307`
passed two Windows tests using only disposable fixture processes. Each fixture
created a producer, its native-like child and a grandchild. Forced runtime cleanup
reached zero active job processes and all three retained process handles signaled
termination. In the second test, the owner exited through `os._exit(0)` without
running Python cleanup; closing its last job handle also terminated all three
descendants. The original owner handle was noninheritable in both cases. No game
process was opened or terminated by these tests.

A subsequent 30-second, five-source Windows game capture consumed all 2,634
native frames and produced 279 windows, including 218 complete windows and 2,474
observed player rows. The five native segments and 191 chunks verified with
terminal summaries and zero unverified bytes. Independent replay reproduced every
window, transition and compact event exactly, with ten stable controllers and no
unconsumed source suffix. All five producers exited normally,
and all five owned jobs closed successfully. The final cancellation left one
explicit unknown transition with no pending values. Publication delay from the
latest source read had a 112.755 ms median and a 3,542.187 ms p95 including startup;
this packaging check does not establish a faster steady-state rate.

| Cleanup evidence | SHA-256 |
|---|---|
| Disposable Windows fixture source | `f498355726c15c2ae5002d8f1c449ccf70f18e72cd3db3b0e7699f83f91605cb` |
| Both Windows cleanup results | `2382a9e97729424daa823eab226d1cd31f22cf5935ec19ca84f8878633691ad3` |
| Frozen runtime inventory | `043539130fce3f45ae2bf6f74e5f1551a99b3c7be76168e521a695b1647ed9ba` |
| Native segment verification | `f9775ba4e25eee0c4f14dbb98dfbd020eec0db0b6f0c5f73001762e9328ca116` |
| Independent full replay | `380d1694bbe7a90eb4a8e746766f0484d3d6f94695779e4375f9350945834ff0` |
| Independent owned-job receipt audit | `8edee0395c1e68327ee91d5a60aab755a332091c9182a90b91339d62e6a2adc2` |
| Exact compact output | `0d16e112dba320187994a06a9ed74e8bab1bec68e4a1418ca4080285797b38aa` |
| Coverage and delivery measurements | `a09e83b95cb03c2569d55388d60db974b82278e831c0becfb9bcad1ffaa263fc` |

## Raw position and health without reviewed roster labels

`runtime_roster.py --mode raw-candidates` uses a verified native census and its
planner output instead of a reviewed name/team map. Supply `--census-acquisition`
and omit `--role-map`. The plan and the census's `manifest.json`, `profile.json`,
`recipe.json` and `evidence.jsonl` must be inside the hash-pinned bundle inventory.
The runtime rechecks the census, its exact process/build and source hashes, every
selected full controller identity, and complete partition/primary coverage. A
saved census only establishes the supplied roster: each partition still needs a
fresh native acquisition and exact reciprocal controller/body admission. Reusing
a plan after controller replacement fails; there is no replacement inference.

```text
python -I BUNDLE/tools/entity-decoder/runtime_roster.py \
  --bundle BUNDLE --inventory-sha256 INVENTORY_SHA256 \
  --mode raw-candidates --plan BUNDLE/plan.json \
  --census-acquisition BUNDLE/census --output NEW_OUTPUT \
  --seconds 30 --interval-ms 50
```

Each inventory-pinned `pN.json` sets `"observation_mode": "raw-candidates"`.
Required inputs remain `native_exe`/`native_sha256`, `native_revision`, exact
`target`, `recipe`/`recipe_sha256`, `health_layout`/`health_layout_sha256`, plus
`private_controlled_fixture_reviewed: true` and `public_state_eligible: false`.
The parent supplies the output path and finite timing. Do not include composer,
category reviews or `reviewed_mode_sources` in a raw configuration. Existing
reviewed mode remains the default and retains its separate requirements.

No anchor is required. If the planner repeats an anchor, it is only a controller
used across partitions; this mode does not identify it as self. Names, teams and
allegiance stay unknown. `include_cached_labels: true` optionally enables private
cache candidates, and `hero_catalog` plus `hero_artifacts` optionally enables the
existing reviewed hero catalog. Incomplete or invalid supplied configuration is
rejected before native capture. A missing, malformed or unrecognized per-frame
cache/resource candidate yields qualified unknown enrichment through the existing
projector; it does not remove valid position or health. Raw completeness metrics
require only position and health, never labels or categories.

The producer retains the complete original `native.jsonl`, acquired profiles and
native recording files. This preserves every sampled field and its source even
when the semantic projection has no interpretation for it. Semantic JSON keeps
exact controller/body keys, guards/read evidence, acquisition and raw event pins.
As before, output is private, non-atomic research accepted for delivery rather
than certified durable at emission. Unknown visibility does not suppress these
requested raw candidates. Epoch invalidation clears pending observations; fresh
body/health admission and owned-job cleanup are unchanged. Raw mode does not
establish arbitrary participant names, native local ownership, or complete
coverage beyond the supplied census.


The initial raw-mode validation replayed all 11,203 original native frames from a
saved five-source, ten-controller Tracer→Ana→Tracer experiment. It regenerated
31,323 relation rows without category/hero-label/cache configuration. All 30,568
health candidates, 755 health unknowns, controller/body identities, positions and
supporting evidence matched the reviewed projection exactly. Replaying the
original interleaving through raw admission produced 1,140 windows and five
transition records, with fresh bodies across three epochs and no pending suffix.
This is an offline preservation test; it does not establish live runtime recovery. The default reviewed smoke replay also remained
byte-identical for all 2,634 accepted inputs.

Raw replay report SHA-256:
`720268be70d9605244314415edabc7e2470fbf00e395086454072869963b616a`.

Raw mode also accepts an acquired controller whose profile declares no body
fields. It records a null body binding with the exact controller identity fields,
body lookup field, profile/evidence hashes and effective guard-set hash. This
means the body is unresolved in that profile; it does not assert that no body
exists. Any partially declared body still fails admission. Reviewed mode still
requires complete reciprocal body bindings.

For this case only, the producer derives the health-layout presence subset from
that same acquired profile. It verifies the source and all final guards, builds
contracts for every declared body, and records both requested and effective
layout pins. A wholly unresolved partition has an empty contract list but keeps
its guarded controller fields and every native guard. A present body with missing
health fields remains an error. No health contract is copied from another epoch.

A changed source epoch opens the existing whole-roster transition and clears
pending observations. After the shared grid barrier, explicitly raw epochs may
publish known-present actors alongside null-body unknown rows for controllers
whose current guarded profile declares no body. Initial raw admission also allows
these unresolved bindings. Repeated controller observations must agree on both
presence and body binding before resuming. Controller replacement still requires
a new roster bootstrap. The caller's native recipe must retain
its body-appearance checks so the native observer reacquires when the body
becomes available; this wrapper does not discover or invent those dependencies.

Live proof cannot require complete windows while a body remains unresolved. Raw mode
retains an actual matching active native manifest for each explicitly unresolved
source epoch. After at least 20 accepted controller frames per current source,
it can also retain the usual all-source active snapshot for that roster revision,
with an explicit absence trigger instead of a complete-window count.
These checks are bounded and require the current session and segment. A completed
producer's last manifest is not accepted as live proof. Missing proof remains a
reported failure; unknown intervals are not silently exempted.

Regression checks cover full body → unresolved body → fresh body through the
native-event adapter and roster coordinator, all-unresolved health construction,
retained-guard failures, partial body/health metadata, stale-value rejection and
live snapshot identity. The saved default reviewed replay remains byte-identical.
An actual Windows acquisition that previously failed `missing_actor_pool_fields`
now constructs one 48-slot health contract and one unresolved controller from
its own evidence, with every final guard verified. That failed producer emitted
no frames, so this establishes acquisition handling, not a completed live recovery.
Its private proof report SHA-256 is
`f4525297aae7823fd5fdffa3306e9f870b9077b7bfcbba2a444c9081da6b7212`.


Partial raw windows retain `unresolved_body_sources` and
`unresolved_body_observations` for each null-body row. These identify the exact
profile, acquisition evidence, effective guard set, native event, semantic frame,
and the controller identity read brackets. The compact form keeps hash-bound JSON
pointers and read spans to the same evidence. These are unavailable body bindings,
not assertions of death or physical absence. No position, health, hero, name or
team candidate is attached to an unresolved row, and supporting sources never
fill it. If its primary frame is missing or skipped, the reason and evidence
reflect that gap rather than reusing an earlier controller read.

Only the expected undeclared-body result can establish this raw readiness. A
controller, lookup, guard or read failure still opens a whole-roster unknown
transition. A later fresh body acquisition clears pending data again and passes
the same epoch barrier before publication. Tests exercise changing values on
independent present actors, unavailable and restored bodies, repeated-controller
presence disagreement, compact evidence tampering and ordinary read failures.
Reviewed output and existing full-body raw output retain their previous bytes.

A second saved Windows bootstrap supplied 5,580 accepted inputs across seven
source segments, including one controller whose body remained unavailable. The
partial-publication replay consumed every input and produced 502 windows: 4,439
observed position/health rows, 502 explicit null-body rows, and 484 windows with
all nine available bodies. All ten controller identities remained distinct; the
five transition events retained their barriers, and finite cancellation ended
with an open unknown interval and zero pending values. Detailed and compact
observations were checked against their exact original semantic source frames.
This is offline replay of actual unavailable-body evidence; a live
unavailable-to-present experiment remains separate validation. Report SHA-256:
`7edc5761c819bac9c73295a1e0efd6e576a2b586e15b27b58b6aee973019da7d`.

A later actual unavailable-to-present capture consumed all 8,591 source frames.
Exact replay reproduced 811 windows and four transitions: 301 windows retained
all nine available bodies before Continue, and 488 windows contained all ten
bodies afterwards. The same controller progressed from unavailable to a freshly
acquired body with health 175. The original finite run retained 12 unpublished
windows (437,985 bytes), with no terminal invalidation; these were not emitted or
carried forward. Replaying the new explicit completion method preserves that
entire original output prefix and appends one all-unknown terminal event,
discarding the suffix. This is a saved-run regression, not Windows execution of
the new completion path. Report SHA-256:
`5ae7ffb00bbea10d500f3545d106791f47408007e4d47db86d8d30fa9e052f77`.

Raw producers can optionally add the source-bound context projection described
in `docs/context-live-projection.md`. Supply `context_composer`,
`context_composer_sha256`, `context_inputs` and `context_inputs_sha256` together.
The composer and input file are pinned private caller assets in the runtime
inventory. Each fresh acquisition invokes the composer in an owned, bounded
child with that acquisition's actual session and segment metadata. It produces
fixed contract, admission and artifact filenames in the new epoch directory.
An explicit `include_groups` option controls the additional finite group
contract; unconfigured comparisons do not remove available raw categories.
The existing health and position contracts remain independent. This plumbing
does not supply game layouts, infer a participant name, or extend a group
review into another epoch. Its fresh Windows execution is a separate check.
