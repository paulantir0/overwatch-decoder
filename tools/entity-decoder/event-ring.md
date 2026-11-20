# Neutral circular-record changes

`EventRingProjector` accepts caller-validated snapshots and emits neutral
`new_record` observations when an owned slot's raw version changes and remains
the same in **two consecutive valid snapshots**. It ships no application offsets,
record meanings, or damage rules. It does not establish that records are shots,
exact health loss, attacks, kills, or player-visible events.

```python
from event_ring import EventRingProjector
view = EventRingProjector(capacity=32, owned_indices=range(16))
result = view.consume(snapshot)
```

Capacity is 1–128. Each view has a fixed, unique set of owned slot indices. A
second half-ring profile uses another independent projector. Their observations
can be interleaved with their own provenance; they are not an atomic combined
snapshot and their transport sequences are not interchangeable.

## Caller normalization

Input schema `overwatch-decoder.event-ring-snapshot/1` has exactly these fields:

- `source`: exact `target`, `controller`, `epoch`, `build_sha256`,
  `profile_sha256`. Target includes `pid`, `creation_file_time`, and matching
  `executable_sha256`, optionally `image_name` and `architecture`. Controller is
  `{handle_u32, creation_key_u32}`; it must include the full generation identity.
- `sequence`: nonnegative sampling sequence. Use the scheduled sampling slot when
  available so missed sampling intervals remain explicit.
- `frame_sha256`: SHA256 of original evidence, not a synthetic gameplay claim.
- `start_ticks`, `end_ticks`, `monotonic_frequency`: original sampler bracket.
- `guards_valid`: true only when all required source, owner, component and field
  dependencies were validated for this snapshot.
- `metadata_before`, `metadata_after`: each `{head, count}`. **Head means the most
  recently written slot**, not the next free slot. Count is occupancy, 0 through
  capacity. Metadata must match before and after the slot reads.
- `slots`: exactly the owned indices. Each has `index`, `key_u32`, `tick_u32`,
  `amount_i32`, `flags_u8`, `read_start_ticks`, `read_end_ticks`,
  `evidence_sha256`. A composite record may use the enclosing interval of its
  separate field reads; that interval must remain inside the frame. Hashes are
  lowercase hexadecimal SHA256.

The caller must validate original source hashes and guard evidence before
normalizing. This module checks normalized shape, bounds, identity, sequence,
metadata and timing; it cannot independently reconstruct native proof from a
hash. The caller must establish that slots represent committed records whose
payload changes correspond to slot versions. No claim of atomicity follows from
unchanged metadata: a modulo cursor can make an entire turn during sampling.

## Baselines, gaps and ambiguity

The first valid snapshot is baseline-only, including after any source, process,
build, controller, profile or epoch change. It never replays preexisting slots.
Occupancy regression also establishes a new baseline and reports a gap. Empty
slots do not become records until they are occupied and confirmed.

Invalid guards or changing metadata emit no records and clear pending
confirmations. Last-confirmed versions remain bounded comparison evidence, not
values published as current gameplay state. A changed payload first seen after
such a gap may later produce `observed_slot_version_changed_after_gap`; it is
explicitly continuity-unknown. An unchanged valid slot establishes a new
comparison baseline for subsequent changes. Missing sequence intervals break
confirmation too. Malformed inputs raise `InvalidRingSnapshot` and clear pending
confirmation. Repeated identical frames emit nothing; altered replays, backward
sequences and incompatible clocks fail closed.

A modulo head and capped occupancy cannot distinguish an advance of `d` from
`d + capacity`, or an unchanged cursor from one or more full turns. Full rings
therefore carry `modulo_cursor_ambiguous`. A changed owned slot outside the
shortest cursor suffix reports `possible_wrap_or_overrun`; cursor/count
contradictions also remain explicit. These do not erase observed changed-slot
evidence, but **`complete_event_count` is always false** and
`producer_write_count` is null. Identical rewrites at the same index can be
unobservable. Versions overwritten between samples or before confirmation can
be missed. No cursor-derived count or missing event is invented.

Equal payloads in different slots remain distinct. Record IDs hash source,
slot, first-seen/confirmation sequences and raw payload. Every emitted record
retains its exact slot, raw values, source identity, original frame/evidence
hashes, and both observation intervals. Amounts and flags stay raw; a private
reviewed adapter may add a build-bound candidate label without changing this
neutral evidence.

State is bounded by the owned slot count: confirmed versions, latest observed
versions, pending confirmations and small identity/clock metadata. There is no
history queue. `state_size()` exposes diagnostic counts. Returned objects are
independent copies; callers may stream or discard them.

Tests cover baseline suppression, two-frame confirmation, duplicate tuples at
different indices, identical replays, source resets, gaps and metadata races,
wrap/overrun ambiguity, partial views, invalid input, empty rings and bounded
state over repeated updates. Synthetic correctness does not validate application
semantics; controlled current-build observations require their own provenance.
