# Lossless event journals

`open_event_journal_writer(path, compression='gzip')` creates a new binary journal
using level-1 gzip. `compression='none'` retains ordinary JSONL. It never overwrites
an existing file or embeds the private filename in the gzip header. `write()` and
`flush()` preserve the original line bytes; flush is not a durable-storage claim.
Existing callers must keep their uncompressed line, total-byte and time budgets.

`iter_event_journal(path, ...)` reads either format from a stopped, immutable file.
It yields the original JSONL bytes, with bounded decompression, line length, stored
size and total uncompressed bytes. Exhaust the iterator: CRC/trailer checks and
file-change detection occur before successful completion. A yielded prefix alone
is not proof of a complete recording. Truncated members, corruption, partial final
lines, changed files and exceeded limits raise; recovery is not silently applied.
The native event validator and per-segment recording verifier remain separate.

The selected live runner accepts `native_journal_compression: "gzip"` in its pinned
configuration. Its default remains plain JSONL. Its receipt declares the path,
format and accepted uncompressed byte count; ordinary artifact hashes cover the
stored file. No read, acquisition, attempt, uncompressed-output or runtime limit
changes with this option. Consumers can use this reader instead of assuming that
`native-events.jsonl` always exists. Full provenance and compact live outputs are
unchanged.

## Measured saved-data check

Seven complete native journals from a simultaneous sixty-second damage/roster
trial contained 844,974,481 bytes. Writing every original line with a flush after
each line produced 80,945,933 gzip bytes, a 90.4% reduction for these journals.
All seven decompressed byte streams matched their original SHA-256 values. This
preserves each original event's formatting and evidence hashes, including raw
recording-frame bytes; it does not discard duplicate evidence.

Writing, hashing and strict round-trip reading took 11.38 seconds wall time and
8.42 seconds CPU on the Linux analysis host. This is an offline storage experiment,
not a measurement of Windows recorder CPU or gameplay latency. Compression of
these files alone does not establish full-match storage or recovery guarantees.
