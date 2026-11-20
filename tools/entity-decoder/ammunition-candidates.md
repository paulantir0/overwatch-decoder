# Reviewed ammunition candidates

`GuardedAmmunitionCandidates(profile_bytes, contract_bytes, artifacts_by_sha)`
projects one verified native frame. The contract binds a reviewed storage
selection to an exact process lifetime/build, controller, reciprocal body,
acquisition and source profile. The original admission path uses a HUD review
that pins the exact scalar storage bindings. Another actor, body or storage
layout needs a fresh contract. The optional empirical template path described
below can bind new storage without claiming a new HUD calibration.
The module contains no application offsets and performs no process access.

Selection uses the reviewed expression count and each value's own numeric type.
An inactive expression selects base storage. An active expression selects the
sampled cache and always retains `sampled_cache_not_recomputed` and
`engine_evaluation_validated: false`. Optional direct/virtual tick inputs describe
whether the sampled native cache condition calls for recomputation. They never
recompute the value or make sequential reads atomic.

A separately reviewed optional callback binding can also emit
`callback_reconstruction_candidate` inside the full ammunition projection.
It supports only the reviewed zero-slope calculation and keeps the original
sampled ammunition candidate unchanged. The binding pins the descriptor target,
capacity, scalar roles and native source review. Both expression-count reads
must be one and bracket every callback input read. Unsupported descriptors,
changed ownership, nonzero slopes and exceptional numeric states yield a
separate callback null and reason.

This reconstruction uses sequential clock and operand reads. It explicitly
retains its binary32 rounding assumption, unverified split-qword consistency,
single sampled clock read and `engine_evaluation_validated: false`. It does not
execute game code, establish an atomic engine value, or prove a shot occurred.

Missing reads, failed dependencies, unsupported types, nonintegral or out-of-review
values, foreign identities and explicit gaps yield null. Each candidate retains
all scalar read intervals, guard IDs, reviewed source hashes and original frame
timing. `is_firing` and `reloading` remain null. The reviewed range is an observed
bound, not a decoded maximum-ammunition field. Visibility remains unknown.

The existing finite exporter accepts two optional arguments:

```sh
python3 tools/entity-decoder/export_relations.py \
  --recording "$RECORDING_DIR" \
  --acquisition "$ACQUISITION_DIR" \
  --output "$OUTPUT_JSONL" \
  --observer "$OBSERVER_DLL" --dotnet "$DOTNET" \
  --ammunition-contract "$AMMUNITION_CONTRACT" \
  --ammunition-artifacts "$AMMUNITION_ARTIFACT_MAP"
```

The artifact map explicitly maps SHA-256 values to local evidence files. Existing
native recording verification, acquisition hashes and durable-chunk checks still
apply. The exporter additionally rejects an ammunition contract from another
acquisition and joins candidates only by both full controller and body keys in
the same frame. Each relation has an `ammunition_candidate`, qualification reason
and JSON pointer into the complete `ammunition_projection` evidence in that line.
Without these options, existing output remains unchanged.

The live adapter also accepts an explicit contract, artifact map and admission:

```sh
python3 tools/entity-decoder/live_relations.py \
  --acquisition "$ACQUISITION_DIR" --recipe "$ROOT_RECIPE" \
  --session-id "$SESSION_ID" --segment "$SEGMENT_NUMBER" \
  --ammunition-contract "$AMMUNITION_CONTRACT" \
  --ammunition-artifacts "$AMMUNITION_ARTIFACT_MAP" \
  --ammunition-admission "$AMMUNITION_ADMISSION" \
  < "$NATIVE_EVENTS_JSONL" > "$OUTPUT_JSONL"
```

Admission binds the exact native session, completed acquisition and segment
metadata to the reviewed contract. Native events must include recording evidence
(`--jsonl true --live-evidence true`). Events without it are rejected. Each
acquisition needs a fresh adapter and admission even if its profile is unchanged.
The full projection retains actual transport hashes separately from metadata
artifact hashes, with same-frame joins and explicit gap nulls. Default output is
unchanged. Replaying saved native events validates the adapter; it does not by
itself prove that semantic output was produced before the live recorder exited.

The finite Windows producer accepts four optional configuration fields together:
`ammunition_composer`, `ammunition_composer_sha256`, `ammunition_inputs` and
`ammunition_inputs_sha256`. Both files must belong to the pinned bundle. At every
new acquisition it invokes the pinned private composer with `--acquisition`,
`--recipe`, `--session-start`, `--acquisition-end`, `--segment-start`, `--inputs`
and `--output-prefix`. The three metadata files preserve the original native
event bytes. A composer must write `ammunition.contract.json`,
`ammunition.artifacts.json` and `ammunition.admission.json` under that epoch.
The producer validates these through the live adapter before publishing frames.
An invalid review or failed composer rejects that configured producer; it cannot
continue using an earlier epoch's ammunition. Omission leaves existing output
unchanged. Composer execution remains owned and bounded to 30 seconds.

An ability-only raw producer can explicitly disable health composition with
`include_health_candidates: false` and omit health layout inputs. Fresh native
acquisition/guard verification still runs; it does not create health values from
the ammunition recipe. Full-roster bootstrap continues to require health inputs.

This is an explicit integration point, not an automatic review generator.
The current private composer can reuse an approved review only for the exact
same process, controller, body, storage, recipe and profile, while replacing
acquisition and metadata pins with freshly verified evidence. New identities or
layouts require supported review inputs. Neither a replay nor the portable
producer tests establish successful installed Windows collection. The actual capture
separated the successful Tracer count validation from unresolved enemy-firing
and remaining active-calculation limits. In the controlled callback trial, full
export independently preserves all 2,130 frames across two acquisitions, with
2,116 ammunition candidates, 14 explicit nulls and 77 separate reconstructions
matching the sampled cache. Each acquisition retains its own reviewed contract.
Synthetic tests cover source and storage relocation, identity replacement,
wrong joins, timing, failed guards, gaps, stale cache selection, callback read
ordering, integer wrapping, binary32 rounding and unsupported numeric values.

## Roster propagation

Finite and live source configurations opt in with an `ammunition` declaration
produced by `ammunition_projection_validation.source_admission(projector)`.
Supply `live_adapter=adapter` for live sources. These inputs must already be
verified `GuardedAmmunitionCandidates` and `LiveRelations` instances; candidate
frames cannot authorize their own interpretation. The runtime parent constructs
the declaration from each configured producer's fresh epoch artifacts and checks
all three native metadata events against the events actually consumed.

Aggregate JSON retains `ammunition_sources` and `ammunition_projections`, including
the complete original projection, exact semantic-line hash, admission, storage
and callback operands, identities, acquisition pins and read intervals. Compact
players expose separate `ammunition_candidate` and `ammunition_callback_candidate`
wrappers. Their values retain the upstream cache/clock qualifications; evidence
pointers resolve into the aggregate's original projection. The callback never
replaces the sampled count. Firing and reload booleans remain unknown.

Unconfigured projections are rejected. Missing sources, gaps, failed identity
checks and epoch/terminal transitions do not reuse old counts. Aggregation keeps
its existing latest-sample-per-window behavior and does not flush the final
pending window at EOF. The detailed entity stream retains every admitted frame.
The saved native Tracer replay verifies this complete path for 1,375 frames;
this is an offline delivery check, not a new Windows deployment.
Contracts without callback bindings keep their existing output unchanged.

## Optional empirical template admission

A contract may provide both `semantic_review_sha256` and
`participant_review_sha256`, and omit the binding's `hud_review_sha256`.
The artifact map must supply both reviews and their original supporting sources.
This mode is explicit; legacy contracts and their output remain unchanged.

The semantic review binds the build, native route review, whole acquisition
recipe, scalar/callback field roles, two hero-resource words, observed range,
and distinct training/independent-body HUD evidence. Only explicitly declared
controller-selector integer leaves may differ in the new recipe. Other recipe
changes, missing route guards or unverified acquisition transcripts reject the
contract. The provider's generic scalar getter alone is not an ammunition label.

The participant review identifies the exact process and controlled local
controller, supporting evidence, and a finite monotonic interval of at most
180 seconds. It is not inferred from a reciprocal body or screen position.
A new controller needs a new participant review. Current storage and full body
identity are derived from the new acquisition; historical HUD reviews are not
rewritten. Include `forward_owner_relations.py` in runtime bundles for its
acquisition transcript verifier.

Every frame must stay inside the reviewed interval and independently observe
both guarded hero words. A changed/unknown hero, replaced identity, failed read,
gap or unsupported expression count yields unknown. Sequential-read, sampled
cache and callback qualifications still apply. Optional output adds the two
review hashes, hero read evidence and
`semantic_validation: empirical_controlled_participant_template`;
`hud_review_sha256` is null for this path.

Actual support is presently controlled Tracer primary ammunition on one build:
3,505 saved frames across two distinct bodies, including an independent holdout.
All 3,429 candidates and 76 unknowns retain their previously reviewed values and
read provenance. This does not establish enemy ammunition, arbitrary modes,
process-restart behavior or native firing/reload flags. The private helper
prepares a contract from explicit reviews; automated live participant selection
and enabled recorder installation remain separate work.
