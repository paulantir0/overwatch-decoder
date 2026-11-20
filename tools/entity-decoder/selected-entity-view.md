# Selected current-context entity

`SelectedEntityView(raw_profile, raw_contract, source=..., artifacts=...,
hero_catalog=...)` projects one frame with `project(frame, gap=False)`. Callers
verify their recording/acquisition first. The separate CLI performs complete
native recording verification, acquisition hash verification, and full reopened
prefix rehash before publishing the output. There are no offsets, labels or game
identifiers in the implementation.

Contract schema `overwatch-decoder.selected-entity-contract/1` requires:

- `profile_sha256`, exact `target`, and `source` with `manifest_sha256`,
  `recipe_sha256`, `evidence_sha256` from the acquisition.
- `bindings`: 1–16 unique `binding_id` objects. Each supplies `fields` mapping
  `controller_handle`, `controller_key`, `selector`, `ref_first`, `ref_third`,
  `body_handle`, `body_key`, `position`, `hero_low`, `hero_high` to profile names.
  All are direct `i32` except `position` (`f32x3`). Identity words require exact
  byte guards; every bound field depends on all identity guard dependencies.
- Each binding requires `review_sha256` and explicit `validation_status`. Supply
  the reviewed document bytes as `artifacts[sha256]`. `is_local` is an optional
  reviewed Boolean declaration; omitted means unknown. The implementation does
  not derive player allegiance, visibility, or local-player identity.
- Optional `health` requires `review_sha256`, `validation_status`, and exactly 48
  `slots` in the intended accumulation order. Slot indices must appear in exact order
  0–47; every slot has a unique `current` field (`f32`), distinct current scalar
  address, distinct `membership_address`, and
  `membership_u32`. The complete membership words must be covered by matching
  profile guards. Every health field must depend on all membership and identity
  guards, including empty slot membership guards. Every current field must be
  observed and finite; occupied slots (`membership_u32 != 0`) accumulate in
  declared order with binary32 rounding after every addition. Missing data
  invalidates health; it never supplies a zero or previous value.

The caller's verified source is `{profile_sha256, acquisition: { ...pins }}`;
additional acquisition provenance keys are accepted. Review pins preserve the
configured semantic claims and do not independently prove them. An optional
`HeroAssetCatalog` supplies build-scoped labels from SHA-pinned current typed
asset reports. Unknown GUIDs retain a null label. All projections remain private
research (`public_state_eligible: false`), have explicit unknown values, per-field
read ticks, frame time origin and build/profile/contract/source pins. Guarded
reads do not imply atomic snapshots. Duplicate controller or body handles
invalidate all projected fields for the ambiguous bindings.

CLI example (one executable verifier, complete recordings only):

```sh
python3 tools/entity-decoder/selected_entity_view.py \
  --recording PRIVATE_RECORDING --acquisition PRIVATE_ACQUISITION \
  --contract PRIVATE_CONTRACT --artifact PRIVATE_REVIEW \
  --verifier FIELD_VERIFIER --output NEW_OUTPUT.jsonl
```

Repeat `--artifact` for additional review documents and typed asset reports;
`--hero-catalog` accepts the catalog JSON. The API accepts a verifier command list
through `export_verified` if a launcher needs multiple arguments.

Profile v4 is an explicit API opt-in (`allow_profile4=True`) or CLI flag
`--allow-profile4`; `GuardedRelations` retains its v1-only default. A v4 binding
may instead supply `health: {sum_field, review_sha256, validation_status}`. The
named profile field must be a guarded `f32` with `codec: pool_sum_f32`, bounded
span and ordered nonoverlapping membership/scalar offsets. Health recomputes the
native sum from both complete same-address read envelopes, requires unchanged
membership for every slot, finite occupied A scalars, binary32 addition, matching
signed-zero result, optional bounds, matching layout, and guard brackets. Empty
slot scalar bytes and B scalar values are not interpreted, matching the native
codec. Output identifies calculated process memory and pins both operand buffers
by hash and read ticks; it omits private addresses and raw buffers. This remains
an offline/verified-frame consumer; callers must adapt live events separately.

`allow_stopped=True` / `--allow-stopped` additionally accepts a native
`verified_stopped` segment only when it is valid, has a verified terminal
summary, is not recoverable, has no verifier error and has zero unverified sample
and index bytes. This does not accept recovered prefixes. Each output records
`recording_status` including complete versus explicitly accepted stopped state.

## Nonlocal targets relative to the current local body

Set contract `mode` to `target_vs_local`. Target binding `fields` omit `selector`
and add `flags_low`/`flags_high` (`i32`). The target controller's first and third
references must equal its body key. A separate `local_context` supplies `fields`
for all seven ordinary identity roles, plus `flags_low`/`flags_high`, and its own
`review_sha256` and `validation_status`. Its selector must equal its controller
key, and both local body references must match its body key. No field-name prefix
has semantic significance.

`category_rule` supplies `ordered_bits`, `mode_mask`, `supported_categories`,
`review_sha256`, `validation_status`, and explicit reviewed `route_conditions`:
`unlinked_both_owners`, `null_override_argument`, `controlled_player_context`.
The review artifact must be reviewed, match the observed executable build, and
have an `ordinary_branch` whose `ordered_category_bits`, `supported_categories`
and `excluded_mode_bit` agree with the configured rule. The source-bound route
conditions admit the private recipe's native ownership/override/local-context
proof; the projector does not reconstruct those native control-flow proofs.

Flag halves compose unsigned low/high words. The first configured set bit selects
the category. Both categories must be supported and both mode masks clear.
Nonzero guarded unsigned body creation keys provide the native equality operand;
handles remain identity evidence. Equality emits `self`; unequal keys yield
`same_group` or `different_group`. A special/missing category or mode remains
unknown. Category and local-context failures leave independently valid target
hero, position and health observations available. Each target requires only its
own identity dependencies; unrelated actors introduce no additional dependencies.
An acquisition profile may still explicitly declare shared guards.

Mapping groups to `ally`/`enemy` additionally requires configured
`same_group_label: ally`, `different_group_label: enemy`, and
`label_review_sha256`. That separate artifact has schema
`overwatch-decoder.selected-relation-label-review/1`, `reviewed: true`, exact `target`,
`profile_sha256`, acquisition `source`, both matching label mappings, and
`sources` listing one or more SHA-pinned evidence artifacts (for example the
controlled practice UI/current recording review). Native group comparison alone
never supplies allegiance labels. No hero name, position or visibility heuristic
participates in the mapping. Visibility remains unknown.

Admitted v4 profiles require raw `overwatch-decoder.field-stream/4` frames; v1 profiles require
stream v1. V4 serial guards retain their actual nested `read` envelope. The
projector checks the guard ID, attempted read, exact address/byte extent/content,
error state and nested timing; a flat v1-style guard is not accepted for v4.
Each identity word validates its own guards independently. Data fields still
require the full relevant controller/body identity dependency set; controller
identity reads do not require reverse dependencies on body-only guards.

For an explicitly acquired controller whose body was absent, a target binding may
set `body_absent: true`. Keep the full template `fields` mapping: the constructor
requires its four controller/reference declarations to exist and be independently
guarded, and every configured body/component declaration to be absent from the
exact profile. Omit `health` and `is_local`. This emits the current controller ID
and timestamped `controller_reference` first/third unsigned words, with null body
ID, local status, hero, health, position and relation, reason `body_not_acquired`.
Zero or unequal references are permitted; they do not imply death or spectator
status. This form never substitutes for a failed complete-body read, never
carries values forward and preserves source/profile/build pins. If the template's
controller itself was not acquired, omit that template binding entirely.


An empty acquired partition requires explicit `allow_empty_bindings: true`, a
source-bound `partition_id`, and `empty_partition_review_sha256`; it remains
rejected by default. The review resolves actual acquisition manifest/recipe/
evidence pins, native process source and completed final guard/profile proof,
and a SHA-pinned allowed empty collection event. Only the exact nine configured
local-context fields may be declared. Empty frames recheck those context guards
and gaps, emit no actor, and retain acquisition-empty provenance with current
occupancy unknown. See selected-live-runners.md for the review/metadata schema.


Gap policy defaults to `strict`, preserving existing gap suppression. An explicit
`gap_policy: current_frame_only` contract may emit independently guarded current
reads after skipped intervals; it never carries previous values. Invalid gap
metadata, target/profile/identity mismatches, bad brackets, missing fields and
codec failures remain invalid. Output includes policy and original gap metadata;
this opt-in establishes no continuity across missing frames.

An explicitly acquisition-empty **local body** is a separate opt-in. Keep the full
`local_context.fields` mapping and set `local_context.acquisition_empty: true`
with `empty_review_sha256`. The five selector/controller/reference fields must
remain declared and byte-guarded; all four local body/category fields must be
absent. A source-bound `overwatch-decoder.selected-empty-local-review/1` review pins the target,
profile, acquisition `source`, and `collection: {rows, prefix, event_sha256}`.
The original native acquisition must be complete, pass final guard/profile
verification, and contain exactly one pinned top-level `allow_empty` collection
with zero retained rows and zero expanded fields. That recipe collection,
including its nested fields, must describe exactly the four omitted local
fields. A partial payload or unrelated empty collection is rejected.

The selected controller's current words are checked on every frame. This narrow
path still requires selector/key equality and equal first/third body references.
Equal zero references are accepted only with the explicit acquisition-empty proof;
they establish neither a body nor local-relative identity. Divergent references
remain invalid. A caller recipe must exclude zero from body matching and retain
the complete guarded reference payload.
Other actors retain independently validated identity, hero, position and health.
Their `is_local` and relative `relation` stay null with reason
`local_body_not_acquired`; no previous context is reused. The additional
`local_context_status` reports acquisition-empty provenance, current body
presence **unknown**, and that a fresh acquisition is required. A later body
appearance is not inferred from this old profile. Finite/live projection and
compact output preserve this status. Normal complete-context output is unchanged.

The private runner enables this only through binding metadata
`allow_empty_local_context: true` plus
`local_empty_collection: {rows, prefix}`. It reads the exact collection event and
original source artifacts to build a fresh contract. A recipe must independently
implement a bounded optional collection; reader configuration cannot turn an
acquisition exception into absence. The generic native recipe engine already
supports this mechanism, so no collector change is required. Validation covers
synthetic reader/provenance fixtures and saved positive-profile parity; an actual
successful gameplay acquisition with an empty local body remains necessary.

## Optional raw orientation storage

A binding may explicitly add `raw_quaternion_candidate: {field,
review_sha256}`. Its SHA-pinned `overwatch-decoder.selected-raw-quaternion-review/1` artifact
must pin the exact target, profile, acquisition source, identity field mapping,
original position and quaternion declarations, and semantics
`raw_owned_component_four_float_candidate`. The candidate must be an absolute
`f32x4` declaration with every effective position guard dependency, including
controller/body/component ancestry. No offsets or game layout are built into the
projector. A finite near-unit vector is reported as `raw_orientation_candidate`,
with its own original read bracket, build/profile/contract/review and acquisition
pins. This is a raw owned-component candidate, not validated camera aim, pitch,
FOV, visibility, or a universal facing rule. No Euler conversion is performed.

Candidate read, type, finite/norm, guard or bracket failure nulls only that field.
Identity/profile failure and duplicate identity null it with the other fields.
There is no historical carry. The existing explicit `current_frame_only` gap
policy can still accept an independently guarded current sample; it does not
establish continuity across a missed interval. Without the optional binding,
existing projection and compact output are unchanged.

The private runner accepts an actor's `raw_quaternion_candidate` field name and
metadata `raw_quaternion_review_sha256`. The latter pins an explicit
`overwatch-decoder.selected-raw-quaternion-recipe-review/1` artifact with `reviewed: true`, exact
`build_sha256`/`recipe_sha256`, `position_suffix`, `quaternion_suffix`,
`relative_address_bytes`, and the raw semantics above. It generates a fresh
profile/source-bound review per acquired actor and saves the exact review bytes
in `segment-NNNN.quaternion-artifacts.json`. The field must retain the complete
position ancestry; caller review does not bypass runtime guards. Ordinary absent
body bindings do not acquire an orientation value.

Selected compact output retains the optional candidate and its field evidence.
Session normalization keeps qualified samples and nulls malformed/unpinned
orientation independently. Compact replay emits `rotations` in original
four-component order and `rotation_reads` with the exact source QPC bracket.
Rotations are emitted only for that input's current sample, never a held sample
from another partition. Unknowns and new windows do not inherit old orientation.
Acquisition-only bytes cannot be inserted into subsequent stream frames.

The implementation has synthetic contract/transport tests and unchanged saved
hero-switch projection parity. The new current-build orientation recipe still
requires native capture and controlled orientation validation; older-build yaw
experiments are not a current-build semantic review.
