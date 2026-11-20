# Memory-field reference

This is a reference for the decoder source in this repository. Field roles describe
what a supplied profile/contract must bind. They are not a list of fixed memory
addresses. Historical observations are summarized separately in
[research findings](research-findings.md).

## Bytes, types and object identity

The native reader supports the following primitive storage types. Multibyte
values use little-endian order. Type declarations do not establish gameplay meaning.

| Type | Bytes | Interpretation |
| --- | ---: | --- |
| `u8` | 1 | Unsigned integer, 0–255; useful for an individual byte or raw flags. |
| `i32` | 4 | Signed 32-bit integer; identity/resource code reconstructs unsigned word bits where required. |
| `i32x4` | 16 | Four contiguous signed words; can preserve a complete 16-byte token. |
| `f32` | 4 | One binary32 floating-point value. |
| `f64` | 8 | One binary64 floating-point value. |
| `f32x3` | 12 | Three binary32 values, such as an XYZ candidate. |
| `f32x4` | 16 | Four binary32 values, such as an orientation candidate. |

See [field streaming](../windows/field-streaming.md) and
[FieldStream.cs](../windows/Observer/FieldStream.cs).

A controller is a game object carrying controller-related state. A body is the
associated world object. A component supplies one part of an object's data. A
manager/creation key distinguishes an object generation, so reuse of the same
address or registry slot does not automatically reuse its identity.

`controller_object_key` and `body_object_key` are decoder-generated opaque keys.
Their inputs include the process lifetime, executable identity and guarded object
words/storage. They are not account IDs. Equal endpoints do not prove continuity
through an unobserved interval.

## Identity, body association and local context

[SelectedEntityView](../tools/entity-decoder/selected_entity_view.py) accepts these
contract roles:

| Role | Type | Purpose |
| --- | --- | --- |
| `controller_handle` | `i32` | Controller's full sampled handle word. |
| `controller_key` | `i32` | Controller's sampled manager/creation key. |
| `selector` | `i32` | Reviewed current-context selector. In current-context mode it must equal the controller key. |
| `ref_first`, `ref_third` | `i32` each | Controller reference words required by the selected route; supported complete-body bindings require the relevant body-key equalities. |
| `body_handle`, `body_key` | `i32` each | Body identity words. |
| `position` | `f32x3` | Body/component position read under the identity dependencies. |
| `hero_low`, `hero_high` | `i32` each | Two words forming the hero-resource GUID. |
| `flags_low`, `flags_high` | `i32` each | Additional category words for target-versus-local relation mode. |

The acquisition must already have established component ownership and the actual
native reference route. Matching integers by themselves do not establish those
relationships. Missing bodies and explicitly acquired empty partitions have
separate contracts; the decoder does not infer death from absence.

The older [GuardedRelations](../tools/entity-decoder/relations.py) interface uses
these literal profile-name patterns, where `NNNN` is an acquisition-local ordinal:

```text
controller_NNNN_handle_candidate_i32
controller_NNNN_manager_key_candidate_i32
controller_NNNN_part51_0000_body_key_candidate_i32
controller_NNNN_body_0000_handle_candidate_i32
controller_NNNN_body_0000_manager_key_candidate_i32
```

`part51` is preserved here as a field-name tag, not an address or a claim that
byte offset 51 contains a body pointer. Ordinals are not persistent player IDs.
Newer selected-entity contracts map explicit roles and do not depend on that naming
pattern. See [selected-entity contracts](../tools/entity-decoder/selected-entity-view.md)
and [context_controller.py](../tools/entity-decoder/context_controller.py).

Forward-only associations use the roles `controller_handle_field`,
`controller_key_field`, `reference_field`, `owner_handle_field` and
`owner_key_field`. They remain distinct from reciprocal player bodies. An
associated object could be auxiliary; the source does not classify every such
object as another player. See [forward_owner_relations.py](../tools/entity-decoder/forward_owner_relations.py)
and [forward_owner_projection.py](../tools/entity-decoder/forward_owner_projection.py).

## Position and orientation

Position is a fresh finite `f32x3` value. Earlier movement experiments also sampled
velocity and two rotation-like records. These do not give every later profile a
velocity field or a calibrated camera.

An optional binding supplies `raw_quaternion_candidate: {field, review_sha256}`.
The field is `f32x4`, must retain the position's ownership dependencies, and must
pass finite/near-unit checks. The semantic validation status is
`raw_orientation_candidate`. The decoder preserves the original four-component
order; it does not establish a universal Euler conversion, exact aim or FOV.

## Hero resources, names and label candidates

The two resource words are combined as:

```text
resource_guid = unsigned(low) | (unsigned(high) << 32)
```

The legacy hero-label path compares fresh controller and body GUIDs before using
a catalogue. Its profile suffixes include:

```text
_part83_0000_hero_resource_low_candidate_i32
_part83_0000_hero_resource_high_candidate_i32
_body_0000_hero_resource_low_candidate_i32
_body_0000_hero_resource_high_candidate_i32
```

[hero_labels.py](../tools/entity-decoder/hero_labels.py) handles reviewed
build/resource/locale mappings. [hero_asset_labels.py](../tools/entity-decoder/hero_asset_labels.py)
keeps typed-asset label candidates separate from runtime-UI-validated labels.
Unknown resources remain unlabeled. A hero GUID does not identify a person.

The account-name path in [names.py](../tools/entity-decoder/names.py) reads four
contiguous guarded words named
`controller_NNNN_part36_0000_account_word0_candidate_i32` through `word3`.
It separately consumes acquired `controller_NNNN_name_NNNN_byte_NNNN_value`
declarations, checks contiguous UTF-8 bytes and a bounded NUL terminator, and can
remove a terminal numeric discriminator for display. The complete token is
16 bytes; it is not a pointer to a name by itself.

[controller_metadata.py](../tools/entity-decoder/controller_metadata.py) can emit
`account_token_candidate_hex` and `cached_label_candidate` without claiming a
canonical human identity. [cached_labels.py](../tools/entity-decoder/cached_labels.py)
handles independently acquired cache strings. A cached label does not replace
a missing account-name read.

## Health, ratios and changes

The explicit selected-body health layout enumerates **48 possible pool slots**.
Each slot binds an index, current `f32` field, membership address and expected
membership word. Membership checks include empty slots. Occupied current values
are added in declared order, rounding to binary32 after each addition.

The v4 `pool_sum_f32` codec instead reads the declared pool span twice and checks
membership stability across those two reads. Its output preserves operand read
evidence. A changed membership or invalid occupied scalar makes health unknown.
This is still sequential sampling, not an atomic health getter call.

Relevant implementations are [PoolSumCodec.cs](../windows/Observer/PoolSumCodec.cs),
[health_projection.py](../overwatch_decoder/health_projection.py),
[build_health_contracts.py](../tools/entity-decoder/build_health_contracts.py) and
[selected_entity_view.py](../tools/entity-decoder/selected_entity_view.py).

`health_ratio_candidate` needs separately recorded, reviewed numerator and
denominator operands. Ordinary current-health captures do not automatically
contain the denominator. [health_ratio.py](../overwatch_decoder/health_ratio.py)
preserves the arithmetic and evidence qualifications; it does not rename the
denominator as universal maximum health or assign armor/shield roles.

`health_change_candidate` is a signed difference between two eligible consecutive
health samples with matching identity, source epoch, layout and clock. It clears
its baseline on gaps or replacement. It does not identify damage, healing,
death, respawn or an attacker. See [health_changes.py](../tools/entity-decoder/health_changes.py)
and its [contract notes](../tools/entity-decoder/health-changes.md).

## Categories and relative relations

Raw flag words feed reviewed ordered-bit and mode-exclusion rules. The actual
bits and supported categories are supplied by the contract/native review; the
generic module does not contain a universal team-number map.

[raw_categories.py](../tools/entity-decoder/raw_categories.py) preserves raw
categories. [categories.py](../tools/entity-decoder/categories.py) and the selected
view can emit a local-relative relation only for their reviewed route conditions.
Unknown modes, missing local context and failed ownership checks remain unknown.
Hero name, screen color, proximity and position are not substitute team evidence.

## Ammunition and timers

[ammunition_candidates.py](../tools/entity-decoder/ammunition_candidates.py) uses
these explicit storage roles:

```text
expression_count, base_bits, base_type,
cached_bits, cached_type, cached_tick, flags
```

An inactive expression selects base storage. An active expression exposes the
sampled cache; it does not execute the game evaluator. Optional tick roles are
`direct_tick`, `direct_branch` and `virtual_tick`.

The optional callback reconstruction binds:

```text
count_after, capacity, descriptor_child_low, descriptor_child_high,
descriptor_selector, descriptor_operand_count, descriptor_value_count,
clock_low, clock_high, timestamp_a_low, timestamp_a_high,
timestamp_b_low, timestamp_b_high, integer_base, integer_multiplier,
integer_offset, curve_base_bits, curve_slope_bits, enabled_flags
```

Only the reviewed zero-slope branch is reconstructed. Original sampled counts
remain separate from callback candidates. `is_firing` and `reloading` remain
null. See [ammunition contracts](../tools/entity-decoder/ammunition-candidates.md).

The native `elapsed_i64_f32_v1` timer codec binds a 16-byte state containing a
timestamp/base/rate and a separate 8-byte signed clock counter. A profile supplies
`clock_address` and `counter_scale_f32_hex`. It preserves the fixed integer and
binary32 operation sequence and returns a calculated `f32` plus operand evidence.
In ordinary mathematical notation, the calculation is approximately
`max(0, base - (clock - timestamp) × scale × rate)`. The actual implementation
wraps the signed counter subtraction and rounds each floating-point step
separately. See [TimerCodec.cs](../windows/Observer/TimerCodec.cs). These generic operands are
not intrinsically Recall, Blink or ultimate charge; those labels require their
own controlled evidence.

## Outgoing records and incoming context

The neutral ring input in [event_ring.py](../tools/entity-decoder/event_ring.py)
contains matching before/after `{head, count}` metadata and owned slots with:

```text
index, key_u32, tick_u32, amount_i32, flags_u8,
read_start_ticks, read_end_ticks, evidence_sha256
```

`head` means the most recently written slot. The generic capacity is configured;
the historical local-feedback experiment used 32 slots. Changed versions require
two consecutive valid snapshots. Existing initial contents are a baseline, not
new events. Wraps and missed versions remain possible, so complete event counts
are not claimed. Integer amounts and raw flag bytes are not automatically exact
health loss or damage-type labels.

[event_entity_join.py](../tools/entity-decoder/event_entity_join.py) and
[event_join_stream.py](../tools/entity-decoder/event_join_stream.py) associate
already admitted events with time-scoped entity labels. They do not establish
the native event's gameplay meaning.

The incoming research instead used a guarded health-component context vector:
allocation/capacity/count metadata and source-body/controller words in the active
payload. It is a separate path. Its private native binding/live adapter is not
present as a complete runnable bundle here. Repeated active samples must not
be counted as distinct hits. See the [controlled findings](research-findings.md#combat-observations).

## Source and timing fields

`pid`, `creation_file_time`, `executable_sha256`, `image_name` and `architecture`
bind the process. `profile_sha256`, acquisition manifest/recipe/evidence hashes,
contract hashes and review hashes bind the interpretation and supporting bytes.

`sequence`, scheduled slots, skipped intervals, `start_ticks`, `end_ticks`,
`read_start_ticks`, `read_end_ticks`, clock frequency and time origin preserve
when observations occurred. `guards_before` and `guards_after` carry the declared
dependency checks. A SHA alone is not the missing evidence file, and matching
guard endpoints cannot rule out every intervening change.

This checkout uses `overwatch-decoder.*` schemas. Inputs from an earlier schema
namespace need an explicit, verified migration; editing names alone changes
content hashes and does not preserve the original evidence chain.
