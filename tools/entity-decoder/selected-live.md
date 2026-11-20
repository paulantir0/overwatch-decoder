# Selected-only live projection

`LiveRelations(..., selected_only=True, selected_contract=path,
selected_artifacts={sha256: original_bytes}, selected_hero_catalog=catalog)`
opts into `SelectedEntityView` for profile v1 or v4. Defaults remain legacy v1.
Selected mode excludes legacy projection options; no target offsets, hero names,
or labels are bundled. The catalog is optional and supplied by the caller.

Use this adapter as a `LiveSession` factory result. The factory receives the
original session, completed acquisition and segment objects, and must construct a
fresh adapter from that acquisition's actual local files and matching contract.
`LiveSession` verifies acquisition/segment ordering and calls `begin_epoch` with
the original metadata. Selected adapters require this admission before frames.
Factory arguments are detached copies; never choose files from unchecked remote
path strings. Resolve the validated ordinal under the caller's observation root.
A single-epoch manual caller may use `begin_epoch`, but is responsible for checking
intervening events; `LiveSession` is preferred for the full lifecycle.

Acquisition admission reads bounded regular profile, manifest, recipe and evidence
files, verifies their hashes, target and completed-stage count, and pins the
contract's source hashes. Evidence hashing checks file metadata before and after
reading. Files are ordinary local files on Windows as well as Linux; this module
performs no process reads, acquisition, SSH, or subprocess launch.

The original `recording_frame` is passed intact to the selected projector. V4
requires native nested guard read evidence, fixed scalar or pool fields, and
matching public live-envelope samples. Pool operand envelopes must exactly match
the raw samples after removing private operand addresses. The selected projector
recomputes the bounded pool sum. Guard failures or changed pool membership produce
unknown fields; rejected envelopes latch the adapter closed. No earlier value is
cached across frames, skipped slots, acquisition gaps, or replaced epochs.

Outputs use `overwatch-decoder.selected-entity-live/1`. They include profile/contract/source pins,
event hash, native timing, gap metadata and `accepted_not_durability_verified`.
`durability_verified` and `public_state_eligible` stay false, even after a native
session-end event. Visibility remains unknown. Live acceptance does not replace
the separate finite recording verifier or establish atomic snapshots.

For one configured epoch, the CLI adds `--selected-only --selected-contract FILE`
and optional `--selected-artifacts FILE`, `--selected-hero-catalog FILE`, and
`--selected-hero-artifacts FILE`. Artifact files use the existing SHA256-to-local-
file manifest format. Supply the usual `--acquisition`, `--session-id`, `--segment`
and optional `--recipe`; pipe original native `--live-evidence true` JSONL to
stdin. The CLI uses `LiveSession` and rejects a subsequent epoch because one
contract was configured. Multi-epoch applications supply their own factory.

Tests: `python -m unittest test_selected_live test_live_relations test_live_sessions`
with `tools/entity-decoder` and the repository root on `PYTHONPATH`. Requires the
selected projector's actual-native-v4 schema/serial-guard support. Tests exercise
pool output, envelope tampering, source-hash mismatch, skipped frames, unknown
membership, epoch closure, and unchanged legacy/session behavior.
