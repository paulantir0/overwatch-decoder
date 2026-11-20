# Shared guard prefixes within one frame

Selected player fields share global guard dependencies. The scoped relation
projector now summarizes that exact ID prefix once, then combines it with each
field's remaining dependencies. Every guard is still validated against current
read bytes and timestamps. No sampled value or successful check survives the
frame scope; unrelated ID sequences use the original path. Failed summaries and
field-specific bracket failures retain the original ordered error checks.

Validation: 81 focused relation/selected-player tests and 129 live-decoder tests
pass. Replaying a saved 939-frame, three-epoch empty-local-to-present recording
through the candidate reproduces full projections, compact rows and callback
attestations byte for byte. Tests include shared-prefix failures, field-specific
time brackets, changed bytes in a later scope and nonmatching dependencies.

The saved Windows run has 191 skipped slots. Of those missed-slot thresholds,
190 occur after the preceding native emission timestamp. Synchronous live-output
writes total 25.155 seconds; durable chunk commits total 1.754 seconds. These
measurements support reducing downstream work, but do not isolate CPU work from
pipe blocking and scheduling. Offline timing comparisons vary enough that no
end-to-end speedup is claimed. The candidate has not been installed or measured
on Windows, and does not fill missing samples or prove gap-free recording.

Private timing-report SHA256:
`1b0051041b8795ffbeda31bb6a28f98a082145e779e45b48c98cc2eee7695298`.
