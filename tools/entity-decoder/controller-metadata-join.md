# Historical controller metadata beside compact roster JSON

`controller_metadata_join.py` adds a separate metadata attachment to observed
compact roster players. It requires no name/team map, application offsets,
process access or runtime changes. Existing position, health, identity, status
and evidence fields remain unchanged. The output has a new schema so it cannot
be mistaken for the original compact event bytes.

```python
join = ControllerMetadataJoin(raw_metadata_set_manifest, export_artifacts)
joined = join.project(raw_compact_jsonl_line)
```

The metadata set schema is `overwatch-decoder.controller-metadata-set/1`, containing:

| Field | Meaning |
|---|---|
| `target` | Exact process/build object: PID, creation time, image name, architecture and executable digest |
| `clock_domain_id` | Caller-supplied clock domain of the original metadata collection |
| `monotonic_frequency` | Frequency of its recorded sample times |
| `exports` | Unique SHA-256 digests of supplied controller-metadata export files |

`export_artifacts` maps those exact digests to original export bytes. The CLI
instead takes an explicit digest-to-local-path JSON map. It does not search,
fetch, infer participant labels or manufacture a native/UI review. A bootstrap
can generate the set automatically from its verified per-partition receipts.

```text
python controller_metadata_join.py --metadata-set SET.json --metadata-artifacts PATH_MAP.json --input COMPACT.jsonl --output NEW_JOINED.jsonl
```

## Source and evidence boundary

Inputs are completed `overwatch-decoder.controller-metadata-candidates/1` exports from the
tracked metadata projector. The join checks file hashes, schema, exact target,
sample timing, guard brackets and IDs, complete identity/account/cache evidence,
token width/digest and cache text bounds. Malformed, contradictory, incomplete
or unqualified exports fail. Duplicate controller/sample times are rejected
rather than resolved by input order. Original source pins, qualifications and
sample times remain attached.

This is **not** an independent native acquisition verifier. Its attachment says
`hash_pinned_export_candidate_not_native_reverification`; it preserves the
exporter's original `complete_native_evidence_verified` qualification as source
provenance. Callers must supply previously verified exports and validated
compact events. The join cannot derive a controller key from the exported
evidence alone, because public exports deliberately omit raw storage addresses.
Hash pins and the existing upstream verification chain remain necessary.

The set is bounded to 64 export files, 16 MiB per file, 64 MiB total, 4,096
metadata frames and 8,192 metadata rows. The finite file CLI accepts at most
256 MiB of compact input and 10,000 events; output is bounded to 512 MiB and
4 MiB per event. Output requires a new filename. An exception may leave a
partial output file without a successful result summary. The CLI does not tail
a stream, watch a process or start a daemon.

## Exact join and historical qualification

Both the complete process/build target and the opaque full controller key must
match. The key is scoped by upstream process, storage and generation binding;
names, heroes, body identity, scan ordinal and numeric similarity never join
rows. A different process/build or controller generation gets unknown metadata.
A new body or roster session with the same exact controller can retain its
historical controller sample, without asserting that its text is still current.

The caller clock domain and frequency must also match. For each metadata kind,
the join selects the latest sample whose end time is no later than the player's
actual primary observation end time. A later sample is excluded even if it falls
inside the same aggregate window. Future samples are not attached retroactively. Each attachment
retains its original clock origin, sample interval and an age in ticks. There
is no assumed expiry or promotion to current state: even a recent matching
sample remains explicitly historical. A later unknown metadata sample is kept
as unknown; the join never searches backward for earlier observed text.

Unknown roster players and transition events receive no account or cache data.
They retain their original status and cannot be filled by metadata. Successful
joins appear only under `player.controller_metadata_candidates`. Cached strings
stay `cached_label_candidate`; sixteen-byte tokens stay raw account candidates.
Canonical name and team remain null, self is never inferred, and public-state
eligibility is never promoted. Missing component/token/cache values stay unknown.

## Output references

Schemas are `overwatch-decoder.compact-live-roster-metadata/1` and
`overwatch-decoder.compact-live-roster-metadata-transition/1`. The root
`controller_metadata_join` retains the exact original compact-line digest,
original compact schema and metadata-set digest. Existing original aggregate
references are unchanged. Output is private research with unknown visibility.

Each account/cache sample contains its original candidate row and read evidence,
sample timing, source export digest, line and row indexes, exact metadata-line
digest, profile/context/native-frame digests, acquisition recipe/evidence/manifest
digests and recording manifest digest. Complete guard result arrays remain in
the original hash-pinned export line, referenced by `/guard_brackets`. Those
original exports must remain available; references do not replace source evidence.
This avoids duplicating full guard arrays in every emitted roster player.

## Tested scope

Synthetic tests cover exact joins, process/build/controller replacement, changed
bodies, other clock domains, future samples, latest-unknown behavior, roster
unknowns/transitions, malformed tokens/cache/guard evidence, source tampering,
duplicate sample times and detached outputs. They also verify that original
position/health fields remain unchanged.

The completed private bootstrap and a separate raw Windows roster recording
provide the actual replay test: the metadata was sampled earlier, so every match
is historical. The fixture has one account-bearing local player and nine bots.
Matching cache strings or tokens does not validate ten-human capacity, canonical
peer names, current display names, team membership or native local ownership.

In that replay, 581 roster windows and one transition contain 5,820 player rows.
All 5,708 observed rows match exact controller keys and receive historical cache
candidates; 580 receive the local token candidate and 5,128 retain explicit
missing-component account samples. All 112 unknown/transition rows remain
unfilled. Original roster fields remain identical, and a second projection
reproduces the joined bytes. The source metadata is several minutes older than
the roster observations; the join does not describe it as a current name cache.
