# Owned native event decoding

`LiveSession.consume(raw)` and `LiveRelations.consume(raw)` retain their bounded,
strict raw-byte interfaces. They return detached mutable projections. Clock,
epoch, profile, field, guard, unknown/gap and output-budget validators remain in
place; original bytes still supply provenance hashes and journals.

A `NativeEventEnvelope` strictly decodes one original JSONL byte string. Its
internal dict/list-compatible containers are read-only under ordinary container
operations. Borrowing requires the active, single-use envelope and matching raw
bytes. Dictionaries, expired envelopes and mismatched raw bytes are rejected.
There is no global parsed-event cache and no reuse between public consume calls.
Duplicate keys and NaN/Infinity remain errors. Past epoch admission artifacts
are independently validated rather than resurrected from an old envelope.

This is an internal ownership API, **not a security boundary against hostile
Python code**. Explicit base-class mutation such as `dict.__setitem__` can bypass
a Python subclass; doing so violates the owned consumer contract. Normal callers
receive detached snapshots and cannot mutate the cached graph through them.

Owned workers should use `coordinator.consume_owned(raw, consumer)`. The
synchronous callback receives the detached projection (or None) and the current
read-only event while its envelope is active. Do not mutate or retain the borrow
as a live lease. Callback failure latches the coordinator closed. For callers
requiring a mutable event copy, `consume_with_event(raw)` returns
`(projection, detached_event)`; that convenience copy costs CPU.

Pass `with_projection_bytes=True` to receive
`(projection, event, projection_bytes)` in the owned callback. The third argument
is the immutable JSONL serialization already used to enforce the projection byte
bound, including its trailing LF. The coordinator checks the bound before calling
the consumer. Events without a projection receive `None` as the third argument.
These bytes represent the admitted projection at callback entry. Mutating the
detached projection has no effect on the bytes.

Adapters extending the optimized path override `_consume_event(raw, envelope)`
and use `borrowed_event(envelope, raw)` after/beside the superclass hook. The hook
accepts an opaque active envelope, never an arbitrary dictionary paired with raw
bytes. Existing subclasses overriding public `consume(raw)` retain a compatibility
fallback and their override is not bypassed; that path may decode separately.
Current segment metadata can share the active envelope during admission. No
sampled values, guard successes or parsed graphs are reused across input calls.

## Verification

Focused tests cover nested mutation rejection, detached snapshots/results,
previous-output isolation, envelope copy rejection, mismatch/dictionary/expired-envelope rejection,
duplicate keys, non-finite JSON, input types/bounds, fresh decoding each call,
callback failure latching, protected extensions and legacy adapter dispatch.
The opt-in callback tests cover exact projection bytes, detachment, a missing
projection and output-bound rejection before the callback.
Selected-live and the existing live/session suites retain their rejection checks.
From `tools/entity-decoder`:

```sh
PYTHONPATH=../.. python3 -m unittest test_native_event_envelope test_native_event_reuse test_selected_live test_selected_entity_view test_selected_empty_partition
PYTHONPATH=../.. python3 -m unittest discover -p 'test_live_*.py'
```

These commands pass 60 and 129 tests respectively (189 total).

A separate private overlay updates the owned roster/damage worker wrappers and
regenerates truthful code inventories. Frozen V5 occupied replays on Linux
CPython 3.12.3 used two runs/version/case. Baselines came from the preceding
interleaved series; final candidates were rerun after adding envelope copy
rejection. Mean unprofiled CPU seconds include unchanged journal compression,
corpus decompression and exact-output checks:

| Saved case | Frames/run | Before CPU s | After CPU s | Reduction |
| --- | ---: | ---: | ---: | ---: |
| Window 1 damage | 1,654 | 9.952329 | 8.838500 | 11.19% |
| Window 2 damage | 1,553 | 9.307410 | 8.420403 | 9.53% |
| Window 1 occupied roster | 859 | 6.571323 | 5.691111 | 13.39% |
| Window 2 occupied roster | 814 | 6.275310 | 5.463717 | 12.93% |

The roster case has three entity rows per frame. All full/compact/normalized
projection bytes and native journal data match the originals; baseline/candidate
native gzip containers also match byte-for-byte. Attestations preserve every
observation, guard/source pin, unknown and timestamp; only the explicitly
regenerated worker inventory hash differs. Timing line links change only as a
consequence of that attestation hash. Private receipts retain before/after hashes
and the exact pin mapping; no other fields are normalized.

The full mutable-event snapshot path initially erased the CPU gain, so optimized
workers use the owned callback. No compression, field semantics or native code
changed. This is offline Python CPU evidence, not measured Windows improvement,
end-to-end recorder overhead, or a continuous-coverage guarantee.
