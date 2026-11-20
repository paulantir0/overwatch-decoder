# Ordered event joins

`EventJoinStream` synchronously orders already validated evidence for the unchanged
`EventEntityJoin`. It performs no acquisition, native provenance validation,
waiting, thread creation, or gameplay interpretation.

Construct with one existing join `scope`, a fixed list of source IDs and
`maximum_age_ticks`. Scope includes exact target identity, world epoch, QPC clock
ID and frequency. A scope change requires aborting and constructing a new stream.

- `submit(source, tick, observations=[(observation, proofs)], events=[{"event": event, "payload": JSON}])`
- `invalidate(source, tick, reason)` invalidates current labels owned by the source,
  advances its progress, and leaves it open.
- `finish(source, tick)` invalidates current source-owned labels at the actual
  terminal timestamp and permanently closes that source.
- `abort(reason)` returns all queued events unresolved and clears retained labels.

Every source timestamp must strictly increase. Submit all that source's rows at
one timestamp together. Observation `observed_ticks` and event `qpc_ticks` must
match the batch tick. Proof intervals retain their original timestamps. Empty
batches advance progress. Event payloads preserve opaque original evidence,
including first-observation time when the event join uses confirmation time.

Each method returns newly released event results. Results have schema
`overwatch-decoder.event-join-stream-result/1`, `source`, `tick`, `event_index`, original `event`
and `payload`, `status` (`resolved` or `unresolved`), `label` (existing join output
or null), and `reason` (null, `no_valid_label`, or `aborted:<reason>`).

`watermark` is null until every open source has progress, then the minimum open
source timestamp. After all sources finish it is the maximum terminal timestamp.
Only groups at or below this watermark are processed. All observations at one
timestamp precede events, without synthetic increments; events are ordered by
source ID then their original index. Identical duplicate claims coalesce;
conflicting same-key claims invalidate that key. Source invalidation wins over
same-time observations for keys currently owned by that source. A newer claim
solely owned by another source is not invalidated by an older source's termination.
Unknown/removal observations replace prior labels. No historical fallback occurs.

Limits: 1–16 sources, 1–256 retained keys, 1–4096 pending rows (default 1024),
1–64 MiB serialized pending batch bytes (default 8 MiB), JSON nesting depth 32.
Empty/control batches count as one row. At most 256 distinct observation updates,
including generated invalidations, may occur at a shared timestamp, matching the
existing join's atomic batch limit. Bounds are checked before releasing the batch;
overflow and malformed inputs raise `ValueError` without advancing any state.
The coordinator uses a bounded private cache copy for transactional processing;
this trades CPU for atomic failure and has not been benchmarked on live captures.
Input and output objects are copied. Serialized-byte bounds are not an exact
Python heap-size bound, but all retained structures also have finite count/depth
bounds. Callers must impose deadlines: a silent open source intentionally stalls
release. If no authentic terminal timestamp is available, abort rather than
inventing a timestamp. After an abort the instance cannot be reused.

Tests use synthetic evidence and enumerate all interleavings of two ordered
source streams against a chronological `EventEntityJoin` oracle. They do not
establish runtime meanings or player visibility.
