# Independent partial source observations

`runtime_roster.py --mode raw-candidates --partial-sources` is a separate finite
output path. A pinned bootstrap configuration can enable it with
`"partial_sources": true`. The default strict aggregate is unchanged.

The runner writes `partial-entities.jsonl`, `partial-source-admissions.json`,
`partial-performance.json` and `partial-result.json`. It does not write a common-time aggregate or compact
roster. Existing consumers of those aggregate formats must not treat this stream
as their replacement without explicitly implementing its schema.

Each `overwatch-decoder.partial-roster-observation/1` observation event contains one unchanged,
independently validated `source_observation`, its exact source-line SHA-256 and
fresh source admission. Its `relations` list retains every census primary.
An observed row points into that event's source observation using
`observation_pointer`; other rows have null body and pointer. They are unknown,
including when another source sampled them earlier. Support actors are never
promoted to authoritative primaries. Native sample timestamps and read brackets
stay unchanged. Raw native fields remain accessible through the original source
artifacts. The embedded source frame retains its original qualifications; it is
not a common-time roster snapshot.

Publication QPC/frequency identify the instant **before serialization, write and
flush**. They do not prove post-flush delivery time or refresh a sample timestamp.
Offline saved-source replay emits null publication QPC and explicitly identifies
its mode. Only current-event observations may be displayed as observed: readers
must not merge successive events into an apparently current snapshot.

Each source must pass the existing exact recipe/build/process/acquisition and
first-frame admission. Every subsequent frame passes the existing field,
identity, timing, guard-evidence and provenance validator. A fresh epoch requires
fresh admission, the same session/controller scope, ordered acquisition/segment,
and exact previous-epoch end. Guard-unknown frames and sample gaps produce no
observed roster pointers; malformed input permanently makes that source
unavailable for this run. No earlier health, position or identity payload is
filled into a new event.

A failed source emits `source_unavailable`, retaining its recipe/census pins and
available result/native-manifest file hashes. This does **not** assert that its
actors are nonexistent, dead or absent. Good sources continue. Completed sources
emit `source_end`; normal finite completion emits a final `input_end` with every
body/pointer null and no source observation. There is no EOF flush of old values.

Source count, input/output bytes, frame count and deadlines remain bounded.
The parent serializes each complete event once, including publication metadata.
Both output checks use those same immutable bytes. Encoding, budget, write or
flush failure stops all further event output, including `input_end`; a failed
write may already have left a truncated line. The separate fatal result is saved
where storage remains writable. Its output counters cover only successful
write/flush calls, while its file hash also covers any failed partial write.
Consumers must honor that failure receipt. Owned jobs use the existing cleanup
path. Standalone `PartialSources` callers retain the dictionary-return API.

The performance file records bounded wall/thread-CPU counters for parsing,
admission, validation, serialization, write/flush and idle time. These counters
measure parent processing costs; they do not certify per-event delivery or disk
durability. The internal parent path parses each input once and scopes repeated
acquisition-proof reuse to one admission. All semantic checks remain active;
public byte-consuming entry points retain their strict JSON parser. Serialization
is nested inside the coordinator for observation events; the performance file
declares that nesting so the costs are not added twice. Terminal-event encoding
does not run inside a coordinator call.

The result distinguishes `capture_finished`, `all_sources_verified`,
`unavailable_sources`, `fatal_error`, accepted `frames` and
`published_observations`. `complete` is false and the process returns nonzero if
any source is unavailable, preserving the existing recorder's retry behavior.
A finished partial capture is useful evidence, but it is not full-roster success.
No recorder retry-policy change is included here.

Saved-data validation consumed 3,891 original source frames from seven sources,
including fresh epoch admission, while two failed sources remained unknown.
All source-frame objects and exact input-line hashes were preserved. A separate
failed startup capture had no semantic frames; its unavailable evidence produced
no invented observations. These are offline replay results. The subsequent
fresh Windows acceptance run
retained 1,998 source frames despite two unavailable sources, with strict native
verification and exact replay. Its measured parent delay remains too high for a
dependable live feed; it does not establish complete roster coverage.

## Surviving original controller subsets

`--allow-controller-subsets` is an additional explicit opt-in, valid only with
`--partial-sources --mode raw-candidates`. The plan must pin
`context_controller_object_key`. Every producer must enable the same flag and
carry an exact `controller_subset_policy` with `expected_controller_keys`,
`expected_primary_controller_keys` and `required_context_controller_key`.
The expected keys come from the original verified partition, not field ordinals.
The portable inventory must also pin `controller_subset_projection.py`.

Fresh admission may contain a nonempty subset of that partition's original
primary controllers, together with its original support controllers. Foreign or
replacement keys are rejected. The exact required context must have an observed,
source-validated controller projection; an empty or missing context does not
qualify. A context body may remain unknown. Every present actor retains the
existing native, identity, guard, read-time and binding checks.

Source configuration and admission pins contain `controller_subset`, including
original expected keys, actual acquired keys, required context and omitted
primaries with reason `not_in_acquired_subset`. These omitted census rows remain
in every event with null body and pointer. This means unavailable in the acquired
subset; it is not a claim of death or nonexistence. Shrinkage or restoration
requires a fresh ordered epoch admission. A new field ordinal cannot transfer
another controller's values, and no old values fill an omitted row.

The result adds `omitted_controller_keys`, `all_census_primaries_acquired` and
`coverage_scope: latest_admitted_profiles_only_not_continuous_coverage`.
`complete` remains false if the latest admitted profiles omit any original
primary, even when all producers completed and verified. A final restoration
does not establish uninterrupted coverage earlier in the capture.

Tests cover either paired primary disappearing, original-key restoration,
foreign and duplicate keys, stale epoch/profile, and missing context rejection.
The unchanged default mode exactly replays 1,956 original source frames and
1,966 events from a saved partial capture, excluding publication metadata.
Subset admission tests use explicitly identified source-bound fixtures; they do
not establish fresh Windows subset acquisition. The matching producer and
private native recipe must support guarded subset acquisition: this parent
option alone cannot rescue a recipe that still requires the old exact count.

The producer materializes health and optional-owner templates anew for each
verified acquisition. A private `controller-subset-projection.json` receipt pins
the requested and effective templates, current prefix/full-key bindings and
omitted keys. It rejects undeclared partial controller prefixes and missing
identity words. Optional category enrichment covering only omitted controllers
is explicitly unavailable for that epoch; it cannot stop independently verified
survivors. No empty category contract or inherited category value is emitted.
This opt-in currently requires a context-aware private bootstrap builder and
does not accept cross-binding `reference_groups` templates. Default producers
continue using their original contracts without subset materialization.
