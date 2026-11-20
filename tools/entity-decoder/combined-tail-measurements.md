# Bounded append-tail experiment

The parent now keeps one read-only, non-inheritable append handle per source tail, with one fresh path stat on every poll, including polls satisfied from buffered lines. It rejects observed truncation, disappearance, inode/device replacement, and an opening race between stat and handle acquisition. It does not cache liveness. Completion and exceptions close handles; the parent closes every input after owned-process cleanup, including failure paths. The caller adapter supplies close() for its two tails. There are at most two such handles per source; existing line/cache/queue/output/duration limits remain unchanged.

This does not establish that bytes cannot change between checks, that a truncate-and-regrow occurring wholly between polls is detectable, or that a file can never be replaced and restored between polls. Original per-line SHA/projection/admission validation remains mandatory and unchanged.

## Offline observations

Three saved finite windows were replayed before and after the tail change. Every data and epoch row exactly matched its actual captured output, excluding only parent wrapper fields and source-start/end lifecycle messages: 2,002, 2,216, and 2,219 rows. Data fingerprints matched across all repeated runs. No labels, source timestamps, guard decisions, source ordering, or watermark behavior changed. A separate saved window with six resolved events retains its previously validated labels and payloads; this patch does not extend their semantics.

Linux CPython 3.12 warm saved-gameplay replay, three repetitions each:

| Metric | Before | After |
|---|---:|---:|
| Median CPU seconds | 1.2381 | 1.1547 |
| Median wall seconds | 1.2384 | 1.1549 |
| newfstatat calls (one traced whole replay) | 12,737 | 6,832 |
| openat | 642 | 238 |
| lseek | 1,124 | 302 |
| close | 610 | 206 |
| read | 761 | 747 |
| Sum of these syscall counts | 15,874 | 8,325 |

Counts include the same Python process startup and unchanged acquisition reads. The measured selected syscall count falls 47.55%; median gameplay replay CPU falls 6.74%. Other saved windows also matched exactly; measurements are a local experiment and do not establish Windows latency improvement. The actual Windows timing motivating this experiment showed substantial time between already-published worker output and parent reading, while parent polling wall time greatly exceeded its thread CPU time. Those clocks do not individually identify file IO, host scheduling, security scanning, or other contention.

Windows file identity/sharing behavior and end-to-end latency require a new owned acceptance run. Read-only handles introduce no game input, write, administrator access, refresh scheduling, recorder change, or source evidence reduction.

## Windows follow-up

The V4 bounded foreground run verifies Windows file identity/read-sharing behavior
for this artifact: no tail errors, all 14 retained handles closed, exact replay of
1,886 data/epoch rows, and all 2,558 stage timing links match. Entity source-to-file
latency is median 118.23 ms, p95 151.64 ms, maximum 569.87 ms. Already-published
worker output reaches the parent in median 9.40 ms and p95 24.56 ms. Poll wall time
is 3.601 seconds and thread CPU is 2.578 seconds. These improve on the observed V3
run, but different state/counts and a separate audio diagnostic helper prevent an
isolated causal A/B conclusion. Startup tails remain, including damage-worker
stages above 1.6 seconds.
