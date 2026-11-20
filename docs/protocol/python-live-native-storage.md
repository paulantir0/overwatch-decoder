# Python live storage notifications

`LiveSession` and `LiveRelations` accept the opt-in native
`storage_cohort_sealed` event described in
[Native storage cohorts](native-storage-cohorts.md). Flat recordings retain
their existing behavior and projection bytes. Storage notifications return no
projection and consume the ordinary event cursor and event/input budgets.

The shared `native_storage.py` validator requires the session's explicit
`overwatch-decoder.field-storage-options/1` declaration. It checks active segment, acquisition,
profile and clock pins; session-global seal ordinals; segment-local generated
directory names, ordinals, previous-record hashes and chunk/line ranges; declared
byte and cohort bounds; and terminal ordering. Each record digest covers the
original embedded UTF-8 object bytes followed by LF, rather than a reconstructed
JSON object. File digests in that record are validated as metadata, not read back
from disk.

Native rotation happens inside the sink's next `WriteFrame` call, after that
frame's memory reads and before its accepted-frame callback. A nonterminal seal
therefore accounts for exactly the frames already delivered; the next frame's
read end must precede that seal's emission. The final seal accounts for all
delivered frames plus the terminal summary and must be followed by
`segment_end`. A segment claiming a written terminal summary without that seal
is rejected. An explicit output failure may end an unsealed prefix, but does not
establish complete storage evidence. EOF without `session_end` remains partial.

Storage events do not replace the adapter, re-admit the profile, change identity,
reset frame/sampler sequences, update frame watermarks, or carry values over an
unknown or sampling gap. The session coordinator and its active adapter each
validate an independent bounded metadata cursor. At a real new epoch, the
coordinator seeds the new adapter from its validated global prefix. A direct
adapter admitted sparsely into a later segment cannot reconstruct earlier seals
and rejects storage notifications; use `LiveSession` for multi-epoch sessions.

Opted-in session receipts add `storage_notifications` with the observed seal
count, `metadata_only: true`, `independent_file_verification: false` and
`durability_verified: false`. The native strict recording verifier remains
necessary to check actual files, chunk bytes and hashes, guards, summaries and
truncation. Live acceptance is neither independent durability proof nor crash
consistency proof.

This change does not extend capture duration or budgets. The existing limits of
100,000 events, 512 MiB input/output, 128 epochs, 512 KiB live lines and 256 KiB
local profile/manifest artifacts remain. Storage metadata state has a fixed number of scalar
counters and pins; it does not retain a growing seal list. Native cumulative
storage and acquisition limits continue to apply separately.

Validation includes malformed policies, pins, hashes, paths, ranges, caps and
terminal ordering; real identity changes and sampling gaps; direct/coordinated
cursor parity; and unchanged flat projections. A saved owned Windows fixture
replayed 217 events, 205 frames and four seals with one acquisition and one
adapter factory call. A separate saved two-window flat capture replayed all
1,351 roster projections with byte-exact full and compact output and unchanged
session receipts. These observations establish decoder compatibility, not new
gameplay semantics or unlimited capture support.
