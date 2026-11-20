# Exact-read setup reduction

`NativeMemory.Read` still performs a fresh `VirtualQueryEx` for every requested
range, rejects unreadable/guard/executable-only pages and region crossings, and
issues the same exact `ReadProcessMemory`. It admits returned bytes only after a
full `EnsureAlive` check (`GetExitCodeProcess` and `GetProcessTimes` against the
retained process identity). A failed query/read also checks lifetime before
propagating its error; no bytes are returned from a failed lifetime check.

The redundant *pre-query* lifetime check is removed from this read path. The open
process handle cannot change to a replacement process with the same PID. Public
`Query`/`Regions` still perform their original pre-query lifetime checks. There is
no protection, memory-map, value, or lifetime cache, within or between frames.
Every read still has its own actual timing bracket and byte evidence. Read counts,
read-byte budgets, guard comparisons, profile hashes and wire formats are unchanged.

V4 reads were deliberately not coalesced using the v3 batch mechanism: v4's
serialized evidence describes individual physical reads. Slicing a larger read
and claiming separate original reads would misrepresent the evidence. Caching
region protections would also weaken the existing fresh permission check.

The deterministic self-test runs the production read pipeline against counted
fake OS calls and compares a full 81-field, 128-guard v4 frame against the former
setup order. It preserves 343 independent physical reads and 343 region queries.
Including outer frame identity checks, lifetime checks drop from 689 to 346;
modeled native calls drop from 2,064 to 1,378 (686 fewer, 33.24%). The complete
non-timing evidence hashes match, and every original timing bracket is checked
independently. A second frame pair verifies exact unknown/read-evidence equality
on a guard mismatch. Other cases cover protection changes between adjacent reads,
region crossings, partial reads, permission failures and process exit.

`self-test` emits `native_read_setup_benchmark`, explicitly marked synthetic.
These counts demonstrate setup-path reduction, not measured Windows CPU/RSS or
wall-time improvement. Actual timestamps necessarily differ across benchmark runs;
the test does not claim identical recording-file hashes. Existing Windows owned-
child native tests exercise this path when the lead runs the same self-test there.

Build/test with `dotnet build windows/Observer/Observer.csproj -c Release` and
`dotnet windows/Observer/bin/Release/net10.0/overwatch-decoder-observer.dll self-test`.
