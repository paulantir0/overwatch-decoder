# Combined storage foundation (inactive)

`combined_storage.py` implements the agreed `overwatch-decoder.private.combined-storage/1`
index. It is an integrity/storage helper, not a new observation source or a
continuous-capture capability. `CAPABILITIES['continuous_capture']` remains false.
No existing runner imports or activates it. Native/decode/worker/parent/recorder
capabilities and a finite whole-capture policy must all be composed and verified
before activation; current duration/acquisition/byte caps are not solved by this
primitive.

An index alternates exact UTF-8/LF open and seal records. Each identity is an
ordinal starting1, generated directory `cohort-NNNNNN`, and previous seal's exact
raw-line SHA256 (null first). A seal lists exactly two ordered files:
`game-state.jsonl`, `delivery-receipts.jsonl`, with bytes/rows/SHA256. It binds
first/last **global** combined_sequence. An empty seal has null ranges and is
allowed only as the sole failed-start terminal; no next cohort may follow.
Caller lifecycle verification must also prevent an empty failed capture from
claiming success. No files are truncated, deleted or reused.

`CombinedStorageWriter` requires explicit finite cohort/total/index/count
budgets. `write_compact(original_bytes, sequence)` writes/flushes a complete
original line; the caller samples its after-QPC marker and calls
`commit_receipt(original_receipt_bytes)`. Receipts must already be formed by the
owned producer's existing clock/hash validation. The writer reserves receipt and
seal capacity before writing data. `close()` seals complete pairs; only a failed
start may call `close(failed_start=True)` without rows. `abort()` retains an
unsealed provisional prefix. Flush is not an fsync/durability guarantee.

`CombinedStorageIndex.consume(exact_index_line)` strictly validates generated
paths, sequence/hash chain and whole files. Seal verification streams both files
with bounded line buffers and checks each receipt's sequence/SHA against the
original compact bytes. It rejects duplicate keys, nonfinite JSON, links,
truncation, extra/missing receipt lines and combined data+receipt cohort overflow.
Each read is bounded by the declared remaining bytes plus one detection byte;
final handle/path lengths must still match. Acceptance describes the seal-read
interval, not historical immutability after acceptance. Reader state commits
only after the entire seal verifies. An active open prefix
is observable but not sealed acceptance; `complete()` requires no active prefix
and forbids subsequent appends. External owned-process/package/lifecycle/result
trust checks remain required; a self-asserted checksum does not authorize data.

Writer/reader keep one active cohort and incremental hashes/counters, with no
historical row or cohort list. Helper ceilings:4096cohorts,256MiBcombined files
per cohort,64GiBtotal data+receipts+index,64MiBindex,2MiBcompact lines,
4096-byte receipt/index lines. Lower pinned policies are required at call sites;
these upper bounds are not a default storage allocation.

The root result proposal is `overwatch-decoder.private.combined-run/2`: storage_index_sha256,
storage_index_bytes,storage_index_records,storage_cohorts and existing
output_rows/output_bytes/output_sha256 over concatenated ORIGINAL compact bytes;
error/cleanup/scope/CLI distinctions remain unchanged. No source epoch, native
sampler, identity, watermark, baseline, field guard or clock is reset by storage.
No across-gap continuity or full-match semantic coverage is claimed.

The generic `run_combined_live.py` runner accepts the opt-in pair
`--storage-cohort-bytes` (1..256 MiB, expressed in bytes) and
`--maximum-total-bytes` (128 MiB..64 GiB). Both are required together, with an
explicit `combined_storage_contract: 1` in the pinned configuration. With no
flags, flat output, result schema `/1`, 256 MiB compact/receipt cap and 3 GiB
sampled tree cap remain unchanged. The configured roster count may be 1..6;
the runner starts that count plus one owned damage worker and reports the
actual count. This does not introduce a new default package topology.

Cohort output uses `overwatch-decoder.private.combined-run/2` and adds the helper's index/count/
hash fields and `provisional_tail`. Original compact and receipt bytes keep one
global sequence. The before-write QPC marker precedes `write_compact`, including
any necessary previous-cohort seal; the after-flush marker follows it, then the
original receipt is committed. A concurrent reader can observe complete bytes
before the writer samples its after-flush marker. No durability claim is added.

The explicit total is the bound checked over the **whole producer output tree**:
worker native/provenance/diagnostic files, compact data, receipts and indices.
A 1 MiB result reserve is withheld from the writer and tree scans; the final
result must fit that reserve. The writer uses the remaining total as a necessary
upper bound for its own files.
The tree scan is sampled, as in the old mode, not an atomic shared filesystem
quota. An added final scan rejects an oversized cohort-mode result. Index cap is
64 MiB and cohort count cap is4096. Failure with an unpaired write retains a
provisional/unsealed prefix and failed status; successful complete-pair rows may
seal even when a source later fails, but the failed lifecycle remains explicit.

Storage never restarts native/worker processes or resets source identities,
watermarks, joins, guards or clocks. Producer duration remains20..60 seconds;
worker/session/acquisition limits remain unchanged. This is output rotation,
not a continuous/full-match capability. Native cohort notifications and longer
capture require separately validated protocol and capacity changes.

## Roster-only gameplay windows

A pinned package may set `roster_only: true` with exactly one configured roster
batch and one roster source bundle. It requires `--read-only-user-gameplay` and
both cohort flags. Each launch retains the 20–60 second producer bound and
publishes the existing compact entity and source-status schemas. Its result
reports `entity_rows`, `source_stop_reason` and `source_unavailable`.

Exit 7 remains partial for a cleanly closed roster window whose native
acquisition attempt or retry limit was reached, or whose duration expired
without observing every declared field. `source_unavailable` is true only
when that window has no entity rows. Other noncomplete source stops fail
the window. A recorder may start a fresh bounded producer in a new directory
while media capture continues. Window and acquisition boundaries carry no
identity continuity, and gaps remain unknown.
