# Guarded raw controller metadata

`controller_metadata.py` projects complete account-token candidates and cached
string candidates from fresh guarded profiles. It contains no application
addresses, layout offsets, participant names, team mappings or mode admission.
Acquisition recipe construction remains a separate caller responsibility.

Raw candidates do not require manual participant or team review. A cache string
is a `cached_label_candidate`, not a canonical display name. Sixteen account
bytes are an `account_token_candidate_hex`, not proof of human identity, local
ownership, global uniqueness or a canonical account name. Missing components
are explicit unknowns. No hero name, ordinal, previous value or zero padding
fills a missing value. Visibility remains unknown and does not filter rows.

## API and context

```python
projector = GuardedControllerMetadata(raw_profile_bytes, raw_context_bytes)
result = projector.project(native_frame, gap=False)
```

The context schema is `overwatch-decoder.controller-metadata-context/1`:

| Field | Required content |
|---|---|
| `target` | Exact profile process/build identity, including process creation time |
| `profile_sha256` | Digest of the original profile bytes |
| `partition_id` | Caller identifier of 1–64 letters, digits, underscores or hyphens |
| `kind` | `accounts` or `cache` |
| `controller_object_keys` | Unique exact selected controller keys |
| `roster_controller_object_keys` | Unique exact census controller keys |
| `source_acquisition` | Exact `manifest_sha256`, `recipe_sha256`, `evidence_sha256` |

Keys come automatically from a fresh guarded census; the context is source scope,
not a semantic review. Each list has 1–64 keys. Both complete controller words
must be frozen in profile guards. Keys include process, build, storage and
generation; labels, heroes and scan order never join identities. Account
partitions must contain the complete roster. Cache partitions require separate
`roster_NNNN_{handle,manager_key}_candidate_i32` fields for its complete census
context. A different roster/profile/process requires a fresh context; constructor
mismatches fail rather than silently rebinding old keys.
Every selected controller must also belong to that exact guarded roster; two
independently valid but disjoint identity lists are rejected.

The projector uses existing `GuardedRelations`, `GuardedCachedLabels` and
`account_words` validation. It samples the four declared contiguous account
words, preserving all sixteen bytes, or leaves the token unknown. Missing,
partial, zero, noncontiguous or unsupported declarations never produce a token.
Optional component absence preserves other controllers. Metadata does not
require a body reference or reciprocal body relation. The caller should supply
body-independent acquisition recipes; the projector never drops guards from a
profile that does include unrelated lifecycle dependencies.

The API validates frame/profile/target binding, typed reads, every declared
dependency and both guard brackets. It does **not** independently verify an
acquisition transcript or native recording merely because source digests were
supplied. Its output says `acquisition_validation=caller_verified_required`.
Callers must verify those sources separately, or use the recording exporter.

## Recording exporter

```text
python controller_metadata.py --acquisition ACQUISITION_DIR --recording RECORDING_DIR --context CONTEXT.json --verifier-command COMMAND.json --output NEW.jsonl
```

`COMMAND.json` is a JSON array containing an explicit local native verifier
command, such as the observer executable, or dotnet followed by its observer DLL.
The exporter invokes only `verify-fields` on saved files; it never reads a live
process or controls an application.

Before writing values, `export_recording` independently verifies acquisition
hashes, target/build, every final acquisition guard recheck, exact recipe and
source pins, native recording acceptance and the identical recording profile.
The existing recording iterator independently checks chunk bytes, indexes and
frames. Inputs are bounded to 1,000 frames and 64 MiB compressed samples; output
is bounded to 64 MiB and requires a new filename. Failed/incomplete sources are
rejected. An exception during iteration can leave a partial output file, which
has no successful export summary and must not be treated as complete.

## Output and unknowns

`overwatch-decoder.controller-metadata-candidates/1` retains exact context/profile/source
digests, target/build, native sequence and clock metadata, sampled read spans,
guard IDs and complete before/after guard result timing. Its frame digest is
SHA-256 of canonical parsed JSON with a trailing LF, explicitly labeled
`canonical_parsed_frame_including_lf`; it is not a claim about transport bytes.
The verified exporter additionally pins the recording manifest and marks
`acquisition_validation=complete_native_evidence_verified`.

Each row retains the requested exact controller key. A guard, target, dependency,
read bracket or gap failure nulls affected current identities and values; nothing
is carried from earlier frames. A missing account declaration or invalid cache
string leaves that candidate unknown while preserving its independently guarded
controller identity. Returned evidence is detached from inputs and past results.
Raw addresses are omitted. `body_object_key`, canonical name and team remain
null; human identity, mode admission, native local ownership and public-state
eligibility remain false. These qualifications do not prevent raw candidates
from being emitted.

## Validated scope

Synthetic tests exercise ten complete tokens, optional/partial/zero/noncontiguous
tokens, longest supported UTF-8 cache text, malformed cache bytes, full roster
changes, generation/process binding, guards, dependencies, gaps and detached
results. Export tests reject mismatched source pins, failed native verification
and oversized recordings before output creation.

Two actual production smoke recordings each contained 20 frames with no skipped
slots: ten controller rows produced one complete account token per frame and
nine explicit missing-component rows; the independently keyed cache partition
produced one guarded string per frame. All prior private candidate values,
unknown reasons, source pins, timestamps and frame hashes matched the extracted
projector. Its new schema/context envelope and explicit guard evidence are
additional. This was one account-bearing local player plus bots. Ten simultaneous
human tokens, canonical peer names and arbitrary-mode allegiance remain untested.

The separate private bounded acquisition strategy fits ten full tokens in
60 fields / 95 guard declarations, with each individually retryable longest
cache partition at 86 fields / 67 guards. Native profile parsing accepted these
synthetic capacity cases. This is capacity evidence, not human identity semantics.
