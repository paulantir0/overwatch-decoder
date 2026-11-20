# Guarded health changes

Both compact readers add `health_change_candidate` to ordinary player rows.
Its signed `value` is the current guarded pool sum minus the previous sum. A
negative number is an observed decrease, a positive number an observed increase,
and zero means these two sums are equal. It does not identify damage, healing,
firing, alive/dead state, respawn, maximum health, or the source of a change.
Existing health values and their qualifications are unchanged. Forward-owner
objects remain separate and do not receive this field.

A candidate requires the same full controller and reciprocal body identities,
process lifetime/build, source profile, acquisition pins, source epoch, clock,
and membership contract/scalar declarations. Native frame sequences must be
consecutive. Both samples must be observed and ungapped, and the earlier frame
and all its scalar reads must end before or at the next frame/read start. The
value remains a non-atomic research candidate, not an instantaneous event.

Each candidate retains both raw sums, scalar values/read intervals, native frame
timings, full object keys, source/acquisition scope, semantic-line SHA, native
event SHA, and the hash plus JSON pointer of its evidence container. Source
compact pointers resolve in the original semantic line; roster pointers resolve
in the original aggregate line. The source semantic hash is retained separately
in roster candidates. Keep those original lines and their native evidence.

Unknown health, missing actors, explicit gaps and roster transitions clear the
baseline. Changed identity, source epoch or pool declarations starts a new
baseline without a delta. A nonconsecutive selected source sequence also yields
unknown; the next consecutive valid sample may use it as a new baseline. No old
value fills an unknown. A lifecycle reset explicitly represented by a new source
epoch or transition therefore cannot produce a cross-reset delta. No hidden
lifecycle is inferred from health alone.

The roster uses only its authoritative observation. Since a roster window may
select every second native frame, adjacent roster windows often cannot produce
a change candidate. Supporting observations never fill this gap. An aggregate
config/epoch and source ID pin the upstream session admission; the compact
reader does not independently reverify native source admission.

`health_changes.sample(...)` normalizes an already validated semantic actor;
`HealthChanges.project(samples)` consumes one complete actor batch. The adapters
run their existing validators first. State is bounded to 128 actors and 128
scalar contributions per actor, retaining one detached sample each. Invalid
inputs latch the compact reader's existing failure state. This is not a new
native guard verifier.

Saved controlled capture validation replayed 4,171 accepted source frames from
ten actors: 3,581 eligible comparisons, including 311 nonzero changes. Three
stable controller/body pairs supplied positive-to-zero and zero-to-250 changes.
Gaps and their first following valid samples stayed unknown. Video separately
shows elimination notices around the corresponding zero periods; the change
field makes no causal or respawn claim. The 260 recorded aggregate events yielded
108 eligible comparisons, 13 nonzero, with 2,492 unknown row results. Removing
only the new field reproduced every original compact output byte from the prior
reader for both streams. These are saved-capture results, not a new live trial.
