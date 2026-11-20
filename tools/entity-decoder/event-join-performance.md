# Transactional join copy cost

A supplied anonymous Opus review was **static**: its visit counts and timing
estimates were hypotheses, not executed results. The changes here independently
verify its proposed container-copy optimization against baseline
`3005818b5b2c51ea7708c41813aa268e2781bb72`. The anonymized schema was mapped back
to the existing `overwatch_decoder` schemas; no anonymous fixtures or review artifacts are shipped.

A fork copies the join object and its ordered cache container. Stored observation /
proof rows are replaced, never mutated; owner sets are also replaced. Private
proof copies and a newly returned label need no second deep copy. Caller-owned
observations, pending batches, events and payloads still receive their original
isolation. JSON validation, ordering, watermarks, bounds and label semantics are
unchanged. Future update paths must preserve the no-in-place-mutation invariant.

## Measured synthetic workload

Linux x86_64, CPython 3.12.3, three sequential runs per version/pattern. Each run
has 900 frames, seven sources, 32 observations plus proofs, 32 events and five
empty source heartbeats per frame. Interleaved source ticks use `7 * frame + i`;
lockstep uses one shared tick. Source finish drains the final pending group.
Timing includes generation, submission and complete output JSON hashing.

| Arrival | Before CPU seconds (three runs) | After CPU seconds (three runs) | Median speedup |
| --- | --- | --- | --- |
| Lockstep | 14.785, 14.844, 17.518 | 5.277, 5.388, 5.315 | 2.79x |
| Interleaved | 18.825, 14.395, 14.381 | 5.226, 5.216, 5.142 | 2.76x |

All twelve runs emitted and resolved **28,800 / 28,800** events, leaving no pending
batches. Full JSON fingerprints, including key order, matched before/after:

- Lockstep: `af28609647f7219e03a76c1e0008d34bbdd8b6d4e812e85200489d690dd041d7`
- Interleaved: `09a6ccf3e4482b48b4801ba5efe3ca5fcd5d42d13d4a82cf1cc3ed1303d0977d`

Separate cProfile runs with 120 lockstep frames observed 5,166,575 recursive
`deepcopy` calls before and 1,306,136 after, consistent with the review's rough
43k-to-11k visits/frame model. Their output fingerprints also matched. Profile
instrumentation is excluded from the timing table. The workload is unpaced and
includes fixed harness overhead: it does not establish a Windows service budget,
180 fps, live observation freshness, or resolution of transport/backpressure issues.

## Reproduce and regression coverage

Run these from `tools/entity-decoder` on baseline and optimized versions, copying
the identical new benchmark test into the baseline checkout:

```sh
python3 -m unittest test_event_entity_join test_event_join_stream test_event_journal test_event_join_performance
python3 test_event_join_performance.py --benchmark --frames 900 --repeat 3
python3 test_event_join_performance.py --benchmark --frames 900 --repeat 3 --interleaved
```

The 45 tests pass on both versions, including rejected batches after an existing
row/proof update and rejected submissions after an earlier group changes a row,
owner and tentative output. They check cache, owner, queue and progress rollback;
nested caller/result isolation; independent returned labels; and preservation of
intentional event/payload sharing. The optimized version also passes the two
combined core/runtime modules, **55 tests total**:

```sh
python3 -m unittest test_event_entity_join test_event_join_stream test_event_journal test_event_join_performance test_combined_live_core test_combined_live_runtime
```
