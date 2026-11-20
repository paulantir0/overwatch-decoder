# Native fixture scheduling

Two self-test cases previously shared their intended behavior with short setup
and scheduling margins. Windows CI exposed those assumptions: a successful retry
had only 1.2 seconds for setup, publication, its required 600 ms wait and recording;
a pending-preparation test allowed only 150 ms between the earliest possible
refresh and the session deadline, then relied on a fixed 300 ms worker pause.

`AcquisitionRetryTests` now stops deliberately on its first delivered frame. The
public observer call has a 30-second ceiling and a separate 20-second watchdog;
normal completion of the fixture still takes the actual retry delay. It requires
exactly two attempts, the first predicate failure, a fresh successful acquisition,
one observed sample with the expected value and a strictly verified recording.
The recorded inter-attempt interval must still be at least 600 ms. The intentional
terminal reason is cancellation, rather than claiming a short timed window
completed before the machine could finish its setup.

The two deadline preparation cases use a five-second real session deadline. A
manual event holds the worker until the recording thread publishes `segment_end`.
The test records that the worker is still active at that boundary, checks its QPC
is at or after the actual session deadline, and requires worker completion and
`preparation_end` before `session_end`. A frame callback waits across the deadline
between accepted reads so the case targets joining, rather than which individual
read happens to see cancellation. Other cases retain the active-reader overlap
checks.

The released deadline fixture reports cooperative cancellation; its fatal variant
reports permission denial and must preserve that fatal outcome. Actual linked-token
propagation is checked separately: the cancellation case cancels before releasing
the worker and now explicitly requires its acquisition to report cancellation.
The event wait has a 15-second failure timeout and the deadline cases have a
20-second outer watchdog. These are finite failure bounds, not latency assertions.

Only fixture code changes. Observer deadlines, retry scheduling, cancellation,
read/output limits and worker lifecycle code remain unchanged. Portable checks do
not replace a fresh Windows CI run or guarantee success under arbitrary host stalls.
