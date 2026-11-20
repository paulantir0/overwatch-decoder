# Startup delivery boundary

The Windows raw-candidate runtime validates each source as soon as its fresh
native admission is complete. It drains at most two complete lines per source
per pass while later sources finish admission. Every drained line receives the
normal source, epoch, guard-evidence, identity and ordering checks. Source JSONL
files and compact source files remain complete for later offline replay.

Live aggregate publication starts when every configured source has a validated
frame within 150 ms of the same Windows clock. The next 100 ms grid boundary is
the resume point. Only ordering and clock state are transferred; no startup
candidate row or pending bucket survives.

The first detailed event is `overwatch-decoder.live-roster-startup/1`. It marks the excluded
startup interval as unknown, records its start/end and resume boundary, and
contains the requested controller roster with null bodies and candidate values.
Its compact form is `overwatch-decoder.compact-live-roster-startup/1`. Subsequent ordinary
windows retain their original grid indices and start at the resume boundary.
This event records an interval; it does not claim it was published at its start.

`startup-input-order.jsonl` records every validated prefix line's source,
sequence, time span and exact JSONL hash. `startup-validation.json` and the final
result pin each prefix's frame count, byte hash and time span. The ordinary
`aggregate-input-order.jsonl` covers frames consumed after this boundary;
`total_validated_input_frames` includes both phases. Hashing and final producer
frame accounting include the complete source streams, including startup.

The readiness deadline, 100,000-frame and 512 MiB limits still apply. At most one
latest line per source is retained, across at most 16 sources. A failed guard or
changed source epoch during startup fails closed with an explicit restart reason;
no old binding is promoted. Ordinary multi-epoch recovery remains available after
startup admission. EOF still invalidates output and never flushes historical
candidate windows. Visibility remains unknown and public eligibility false.

Receipt latency should be reported after this boundary as well as for the whole
run. A shorter live aggregate now means an explicitly excluded startup interval,
not missing raw observations or evidence that collection began later.
