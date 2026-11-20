# JSON copies in event joins

Four existing ownership copies use `projection_copy.detached_copy`: new proofs,
retained prior proofs and stored observations in `EventEntityJoin._observe`, and
the pending input batch in `EventJoinStream._accept`. Every copy remains. The
helper fast-paths exact built-in JSON containers/scalars, preserves internal
aliases with a memo and retains `deepcopy` fallback for custom objects. Public
results, trial-cache rollback, validation, bounds and ordering remain unchanged.
Packages importing these modules must include the existing `projection_copy.py`.

A saved parent replay first identified 4,180,802 recursive `deepcopy` calls
(5.040 s cumulative under profiling). Direct hot callers were `_observe`
(40,588 top-level copies, 2.245 s) and `_accept` (6,562 copies, 1.051 s).
A separate private packet verifier retained 6,662 copies/1.611 s; it is outside
this source change. These caller-attributed copy costs are portions of the total.

Unprofiled Linux CPython 3.12.3 replay used the same saved inputs and original
accepted source order/QPC markers, three runs per version/case, alternating
version order. It retained validators, stat/hash checks, merge, serialization,
output flushes and byte-parity checks:

| Saved case | Accepted packets | Before CPU s | After CPU s | Mean reduction |
| --- | ---: | ---: | ---: | ---: |
| Window 1 | 6,669 | 6.396161 | 6.093919 | 4.73% |
| Window 2 | 7,028 | 6.814136 | 6.310087 | 7.40% |

All 10,176 combined rows, delivery receipts and merge-diagnostic bytes match the
saved originals exactly; no timestamps, pins or other fields were normalized.
Window 1 had one essentially flat/slightly slower pair; private receipts retain
every run and source hash. Profiler overhead amplifies recursive-copy savings,
so the profiled percentage is not a runtime speed claim.

The replay excludes worker/native CPU, startup verification, idle polls, live
publication scheduling and Windows I/O behavior. It does not establish the cause
or removal of a multi-second live tail, nor a continuous-coverage improvement.
Ownership/alias tests cover nested input/result mutation, payload shared aliases,
custom-list copy fallback and rejected batches after an earlier trial mutation;
existing transaction/validation tests remain active.
