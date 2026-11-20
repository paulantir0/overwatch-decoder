`EventEntityJoin` joins caller-validated private events to timestamped roster labels.
It performs no acquisition or application-specific decoding and never returns health.

Call `observe(observation, proofs)` in observation-time order, then `join(event)`.
Each instance enforces one clock ID/frequency and a constant-size global timestamp
watermark, including across process/world changes and cache eviction. New cache keys
require a timestamp strictly greater than that watermark; retained keys may receive
equal-time updates (conflicts become unknown). Older inputs return `False`. Changing
the ingestion clock raises `ValueError`. Use `observe_many([(observation, proofs), ...])` to atomically admit multiple new
entities sharing one validated frame timestamp. Batches contain at most256 distinct
scope/key pairs, use one clock and timestamp, and must be newer than the pre-batch
watermark. Duplicate keys, mixed timestamps/clocks or malformed rows raise `ValueError`
without partial cache changes. A valid delayed batch returns `False`. Cache capacity
still applies, so a batch larger than the configured cache evicts its earliest rows.
Do not invent ordering by incrementing timestamps. Event lookup itself does not advance this watermark.
The shared `scope` contains the exact process `target` (PID, creation time, build
hash, image and architecture), an independently validated `world_epoch`, QPC
`clock_id` and `frequency`. A source sampler epoch is not a shared world epoch.
If a caller cannot establish that common scope, it must leave the target unresolved.

An event supplies `scope`, `body_key_u32` (the full generation identity, never a
truncated index), `qpc_ticks` and bounded string `provenance`. It need not already
know the target's body lifetime or entity ID.

An observation supplies that scope/key, `observed_ticks`, `valid_until_ticks`,
`status`, `provenance`, and, when observed, `body_lifetime`, `entity_id`,
`controller_id`, `hero` and `relation`. Each independently validated proof explicitly
binds scope/key to those three identity strings over `valid_from_ticks` through
`valid_until_ticks`, with its own provenance. Compact entity JSON alone is not a
full-key proof. Callers must retain removal/unknown observations and supply complete
proof claims, rather than selecting a convenient identity from an ambiguous set.

The cache stores only the latest observation per scope/key, with at most32 overlapping
proofs. Limits are caller-configured (at most4,096 keys); insertion evicts the oldest
updated key. Historical event queries older than the latest observation return null.
Unknown, invalid or removed observations block prior labels. Proof overflow blocks labels until the conflicting interval expires. Delayed observations
cannot undo them. Conflicting overlapping identity claims fail closed. Expiry uses
both the explicit validity interval and `maximum_age_ticks`; all intervals are inclusive.

A successful result includes event/observation/proof provenance and observation age.
It is non-atomic, private, visibility-unknown and describes labels observed before
the event timestamp. It does not establish exact damage, complete event coverage,
server event time, attacker attribution or current health. Invalid input contracts
raise `ValueError`; valid contracts with no safe match return `None`.
