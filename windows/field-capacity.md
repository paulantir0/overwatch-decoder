# Bounded field and transport capacity

The observer accepts at most **160 fields** per profile and **512 KiB per native
frame/live-event line**, including its newline. These two limits are coupled:
a field-count increase alone does not admit a profile whose complete evidence
exceeds the serialized-frame envelope. Profile versions and wire properties do
not change. Existing 128-field/256-KiB recordings remain accepted.

The native sampler, acquisition expansion, pointer/codec admission, strict
recording verifier, field export/timeline, Python native transports/journal
readers and browser field-replay importer use the expanded limits. Profile and
metadata limits remain separate from event-line limits.

| Limit | Current maximum |
| --- | ---: |
| Fields per profile | 160 |
| Native frame/event and field export/timeline line | 512 KiB |
| Profile; ordinary manifest/contract metadata | 256 KiB each |
| Distinct exact guards; bytes per guard | 256; 64 |
| Guard declarations, versions 1–3; version 4 | 256; 1,536 |
| Physical requested read bytes; calls per frame | 32 KiB; 1,024 |
| Decoded recording chunk | 1 MiB |

Cumulative input/output/read/storage byte budgets, event counts, deadlines,
compression, cancellation, guard/field validators and unknown behavior remain
unchanged. Larger lines consume the existing byte allowances sooner. The generic
producer queue changes from 64 to 32 lines at the new maximum line size, retaining
its 16-MiB maximum queued payload. The selected producer changes from 16 to eight
lines, retaining 4 MiB. Neither queue drops lines to meet its bound.

Independent products keep their existing bounds: compact entity output is
256 KiB per line, semantic projection rows are 1 MiB, and aggregate compact rows
have their existing larger cap. The browser still permits at most 128 MiB input,
one million field samples and 32 MiB retained numeric payload. A consumer rejects
its whole operation when its own limit is exceeded; it never prunes fields.
Packages must update every relevant consumer and regenerate truthful code pins.

## Capacity evidence

An offline reconstruction from two saved capture windows had identical shared
context and ten declared groups. Keeping every group field and dependency,
renaming only acquisition-local ordinals, produced the same capacity plan:

| Quantity | Measured plan |
| --- | ---: |
| Fields; guard declarations; distinct guards | 129; 1,483; 211 |
| Profile bytes | 144,476 |
| Requested physical bytes; calls per frame | 29,536; 561 |
| Native conservative frame envelope | 320,153 bytes |

The old field and line limits both reject that plan. Its source profiles were
sampled asynchronously: their union establishes capacity feasibility, not a
coherent acquisition or simultaneous observation.

A separate supplied-memory fixture ran the native dynamic collector over ten
synthetic groups. It published all 129 fields, passed strict recording verification
and produced a 329,911-byte live event with full recording evidence. An eleventh
group failed the explicit recipe capacity predicate before profile publication.
This is engine/transport proof; a fresh coherent acquisition and runtime validation
are still required before changing an actual recorder's topology.

Generic regression tests exercise 128/129/160 fields and reject 161; admit the old
and new line ceilings and reject a byte over; retain every guard and null unknown;
and preserve profile, guard, declaration, physical-read and independent call
limits. The 1,024/1,025-call test constructs internal plans to isolate that hard
guard, since public profiles can hit other admission limits first. Existing saved
projection parity is tested independently of any topology change. No throughput,
sample-rate or continuous-coverage improvement is established by these caps.
