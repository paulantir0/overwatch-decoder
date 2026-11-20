# Private object replay

Replay the saved multi-object coordinates as selectable 3D blocks on a local
grid beside optional recorded gameplay video. The viewer reads saved files; it does
not access the game. It highlights the self association in each sample. Available
validated native observations add hero, current health and friend/foe
labels. Optional video evidence adds names and teams to exact object keys within
reviewed time spans; other records keep neutral IDs. Video hero sightings remain
timestamped historical observations. Visibility and general cross-match identity
remain unknown.

The existing `tools/field-replay` remains available for individual raw fields.
This viewer is separate from the public observation server.

## Run locally

Python 3.11+ and a modern browser suffice; no npm install or external services.
Keep recordings and generated exports in an ignored directory.

```bash
python3 tools/entity-replay/prepare.py \
  .runs/your-capture/entities-decoded.jsonl .runs/entity-replay/latest.json
python3 tools/entity-replay/serve.py .runs/entity-replay/latest.json \
  --port 8787 --pid-file .runs/entity-replay/server.pid
```

Open `http://127.0.0.1:8787`. Ctrl-C stops the foreground server. A supervised
background launch should save its log and use the optional PID file; stop that
specific PID when finished. No automatic startup or background service is installed.

To include browser-compatible video, pass an explicit MP4 and its estimated start
time relative to the coordinate session. The offset is adjustable in the viewer:

```bash
python3 tools/entity-replay/serve.py .runs/entity-replay/latest.json \
  --video .runs/entity-replay/gameplay.mp4 --video-offset 1.9 \
  --video-uncertainty 1.68 --port 8787
```

For reviewed evidence, add `--labels .runs/entity-replay/video-labels.json` and
`--alignment .runs/entity-replay/calibration.json`. A calibration has schema
`overwatch-decoder.replay-alignment/1`, `source_sha256` matching the prepared replay's source,
`video_sha256` matching the selected MP4, `offset_seconds`,
`uncertainty_seconds`, and optional `method`/`scope` text. Mismatched source or
video is rejected; a calibrated offset overrides the estimated CLI offset.

For an existing H.264 MKV, an optional local FFmpeg remux preserves compressed
video without re-encoding. This command deliberately creates a video-only file:

```bash
ffmpeg -nostdin -n -i .runs/your-capture/desktop.mkv \
  -map 0:v:0 -c:v copy -an -movflags +faststart .runs/entity-replay/gameplay.mp4
```

The server binds only to `127.0.0.1`. It accepts loopback Host/same-origin requests
and serves the allowlisted UI, selected replay, optional explicit MP4, and
allowlisted media metadata. Video supports byte-range seeking.
For reviewed Workshop surface samples, pass `--environment ENVIRONMENT.json`.
The sidecar must bind its surveys to this replay source, with a matching build,
map, and mode and an evidence hash for controlled identity registration. It
appears as a Map surfaces toggle in the overlay controls. Hit points and local
patches describe sparse samples with unknown visibility and collision coverage.
It provides no directory listing, wildcard file access, uploads or external API.
Raw data must not be committed or deployed publicly. The local exports contain
process evidence and are not website assets. For an explicitly authorized shared
excerpt, `share.py` produces an allowlisted display export: window-scoped display
IDs, positions, candidate rotations, mapped heroes, current HP and relations,
plus their validation status and build attribution. It excludes addresses, raw
bytes, machine paths, process identifiers and source object keys. Unknown names
and visibility stay unknown; publishing does not promote research semantics.

`share.py` verifies the index/chunk hashes and the exact calibrated source/video
pair before trimming outer intervals with no usable positions. Internal gaps and
window boundaries remain. `stage_share.py` stages only this export, the allowlisted UI
assets and an explicitly supplied trimmed MP4. It checks every retained video
presentation timestamp against the source, records the resulting video offset,
and includes a version/file-hash receipt. The public JSON is gzip-compressed for
transfer; the browser receives the normal replay JSON through the static rewrite.
Generated data and video belong in ignored storage, never this repository.

The viewer provides system, light and dark themes. The preference persists in
the browser; scene colors and the timeline follow the same theme as the controls.

## Controls

- Shared video/replay play/pause, 0.25×–4× speed, timeline scrubbing and sample stepping.
- Click the scene, then **WASD** to move; **Q/E** down/up; **Shift** to move faster.
- **Right-drag** to look from the camera position, **middle-drag** to pan, wheel to
  zoom. Left-drag orbits, Shift-drag also pans, and **F** fits current objects.
- Expand either the 3D view or video; return with Split view.
- Switch top/3D view, toggle two-second trails, or follow the current self object.
- **Hero / HP** labels cubes with the current hero and rounded-up current health
  when available. Exact health remains in the inspector and JSON; no maximum
  health is inferred for a percentage bar.
- **Shatter at 0 HP** adds a brief fragment effect when adjacent validated samples
  of the same controller/body reach zero health. It hides that zero-health marker
  and its cone/trail until positive or unknown health returns. The object remains
  inspectable in the list. This is a display effect, not a confirmed death or kill
  attribution. Missing samples, body replacements, skipped slots, gaps over 200 ms
  and recording-window boundaries do not trigger it. Seeking replays the same
  effect and pausing freezes it; raw JSON is unchanged.
- Set **Cones** to **Off**, **Only yours**, or **Everyone**, and adjust the
  illustrative cone angle (15°–120°). Only saved rotation candidates are drawn.
- Each page load starts in **Your POV preview**, following the current self position.
  **Exit your POV** returns to the fitted free camera.
  A recorded facing candidate supplies the preview direction when available;
  drag to look manually. Eye height and FOV are illustrative. Fit, WASD or pan
  returns to the free camera. Camera choice persists across recording windows.
- Select any cube or roster row and click **View from this cube** for its
  recorded facing preview. The same button returns to the free camera. The
  viewed cube and its cone are hidden, and nearby markers use fixed small world
  dimensions. A selected opponent's POV returns to free camera at a new window
  because object IDs are window-scoped; your own POV can follow the next self
  association. Neither view establishes actual camera aim or visibility.
- Click a block or list entry for XYZ. Expand provenance for unrounded values,
  structural key, acquisition epoch, sequence and exact position-read ticks.
- In a gap, jump directly to the next recorded sample. Previous/next stepping can
  also visit unknown-only frames. Space/arrow keys work when the canvas is focused.
- Click evidence times to review an identity match or a hero sighting in the video.
- **Frame JSON** downloads the active saved sample, exact positions/read ticks,
  scoped identities, candidates and last video sightings. A gap exports no objects.
  **Labels JSON** downloads the source-bound observations and binding intervals.

Player markers use cylinder bodies, round heads and short tapered noses. Dimensions
are illustrative. A nose is drawn only when the current sample supplies a valid
rotation candidate; its direction uses normalized xyzw, +Y up and +Z forward.
POV remains a facing preview, not decoded camera aim or measured FOV. No view cones
are drawn. The dedicated Your POV button toggles the self camera; Your sightline
draws one self-only forward ray when the current self rotation is available, with
a small center marker in self POV. This remains a facing preview, not terrain
visibility, a hit test or validated camera pitch. Allies are blue, enemies red,
self cyan and unknown relations gray.

Health bars accompany the recorded HP value. Their stable display scale is the
highest validated health observed for the same object, controller, body, hero,
build and acquisition epoch in the loaded recording. This is not a decoded maximum
health field; the inspector labels the scale as highest recorded HP. Missing or
invalid health stays unknown. Bars never establish damage attribution.

Height labels show `Y - reference floor Y`, in raw coordinate units. The reference
floor is the loaded recording's minimum Y; optional map surfaces do not change it. The labels show
vertical changes but do not establish airborne state or clearance above platforms.
Foot rings and dashed guides remain anchored to that reference plane. Original
positions, health and rotation tuples in Frame JSON are unchanged.

Optional `--annotations` accepts a local JSON document with `source_sha256`,
`context` and `objects: [{"key": "structural-key", "label": "suggested role"}]`.
Suggestions appear only when the source hash matches. They remain explicitly
unverified, separate from hero/team/name fields and object colors. A note about a
poor network connection does not establish the cause of any acquisition gap.

## Video observations and object identity

The optional `overwatch-decoder.replay-evidence/1` document is bound to the decoded source SHA-256.
Its `observations` contain `player_name`, `hero`, `team`, `video_seconds`, evidence
text, and optional `retrospective:true` for an end-match card. The roster shows all
reviewed sightings; the inspector's **Last seen hero** uses only non-retrospective
observations at or before the current video time. Exact switch times are unknown.

`bindings` require an exact object `key` (or `target:"self"`), inclusive
`start_seconds`, exclusive `end_seconds`, a `status` of `video_matched` or
`candidate`, identity `fields`, and evidence entries with `video_seconds` and
`note`. These interval times use the coordinate session clock. A self binding
also requires the active sample's guarded self flag. No binding applies to a
missing position, a different key, or a time outside its scope. Candidate values
are displayed separately and do not fill identity fields. Conflicting values
become unknown. Source mismatch or invalid labels leaves coordinates usable and
shows an explicit labels-unavailable message.

These are reviewed associations for saved captures, not an automatic memory
identity decoder. A known video roster alone never assigns names to blocks.
No name or hero is silently transferred to a new acquisition or another recording.

## Evidence semantics

The converter accepts `overwatch-decoder.private-entity-timeline/1` with an explicit
`public_state_eligible:false` classification and emits `overwatch-decoder.entity-replay/1`.
It preserves every frame, exact XYZ values, raw observed quaternion tuples,
nullable self association and decimal read-tick strings. It includes source
SHA-256 and allowlisted epoch/build provenance,
without copying raw memory addresses, participant names or filesystem paths.

Only guarded, currently observed position records become blocks. Unknown reads
produce no position. A repeated structural key is not proof of a person's
identity or uninterrupted lifetime across an acquisition gap or respawn.

There is **no interpolation**. Within a contiguous run a sample is held until the
next one, at most 50 ms. At an interruption it is held for only the typical sample
interval, capped at 50 ms. Missing frames remain blank. Trails stop at an absent
object, unknown read, skipped slot or acquisition boundary. Position reads within
a frame are sequential, not an atomic snapshot of all objects. Slider and display
time are rounded for presentation; exact read ticks remain in provenance.

The timeline begins at session time zero and covers both the coordinate export
and loaded video. The mapping is `video_time = session_time - video_start_offset`.
Video is the playback clock while available, including during buffering/seeking;
positions remain blank outside their own recorded coverage. This keeps the controls
linked, but does not prove exact historical alignment. The checked recording now
uses `session_seconds = video_seconds + 3.57`, with a practical ±0.10 s allowance.
The former startup-bracket midpoint was about 1.67 s early. Horizontal video motion
and saved self yaw agree across nine separated intervals spanning video 25–495 s;
mouse input provides another cross-check. Five intervals were used for the final
fit and four for validation, although those four were inspected during exploration
and are not pristine unseen holdouts. No drift correction is supported. The
allowance is practical, not a statistical confidence interval or exact frame-time
claim. Reset restores this calibration; a manual change is marked unverified,
including in exported JSON. No audio has been added to the checked local demo.

Default bounds: 100,000 frames, 4,096 distinct objects, 2,000,000 observed
positions, 128 MiB prepared JSON, 2 MiB per input line, 8 GiB input. Conversion is
streamed through temporary files and replaces the output atomically only after
validation. The browser loads the compact export into memory. Explicitly raising
Python conversion limits does not raise browser/server limits.

## Current verification

The saved match export contains 21,711 frames across 20 acquisition epochs,
45 structural object records, 360,452 observed positions and 369 unknown object
samples. It retains 103 reported skipped timer intervals. The typical interval
is about 20.00 ms (50 Hz). There are 16–23 observed objects per usable frame;
this is not proof that every match participant or object was captured.

The 72,793,805-byte orientation-inclusive export was compared with every source
frame: all 360,452 raw quaternion tuples and their read brackets match, alongside
the previously verified positions, object keys, self flags and timing. The local
561.775-second video remux preserves all 16,814 compressed video packets exactly
(packet hashes matched). No recording data is included in this repository.

Automated checks:

```bash
python3 -m unittest discover -s tools/entity-replay -p 'test_*.py'
node --test tools/entity-replay/model.test.js tools/entity-replay/evidence.test.js
```

26 Python tests and 30 JavaScript test groups cover source identity/timing,
atomic output failures, bounds, unknowns, ordinal changes, gaps, trail breaks,
rotation candidates, video time mapping, range seeking, loopback serving,
source/video-bound calibration, scoped identities, conflicting/candidate labels,
retrospective observations and future-sighting exclusion.
Complete declared self pools retain exact raw values and read brackets. Their sum
and ceiling appear as a private self-health candidate; extra/missing pools, stale
reads, mismatched profiles and absent self never yield a partial or carried value.
Browser QA exercised linked playback, alignment adjustment, camera movement,
cones, expanded views, legacy data and video failure. Desktop and phone layouts
were visually reviewed. See [QA inventory](QA.md).

Video review identified ten participant names in the latest capture. Within the
first reviewed acquisition, self plus four allies and five opponents now have
distinct named track associations. The remaining extra Brigitte-like record is
an associated barrier candidate. The private evidence sidecar has 170 timestamped
observations and 48 scopes (43 matched, five candidates), including separately
reviewed later hero changes. These scopes are not 48 people, and the full recording
is not continuously labeled.

The newer 76,019,595-byte export also retains complete declared self pools in
21,691 frames and null in 20 unknown frames. All values/read brackets match an
independent extraction of the original stream. A sum-and-ceiling candidate agrees
with 24 reviewed HUD anchors, including zero and a three-pool alternate-form
sample. Maximum health, individual pool roles and other-player health remain
unvalidated. Near video-frame boundaries, the HUD and candidate can differ within
the stated timing allowance; no exact render synchronization is claimed.

The archive audit found four unique Overwatch videos totaling 64m19.824s. All four
were reviewed at selected anchors, not continuously frame by frame. Two include
entity trajectories, one has self-field recordings only, and one has no accepted
memory frames. The longer videos span multiple heroes and matches. Earlier health
and self-position comparisons are useful corroboration, but cannot manufacture
missing entity trajectories or carry this recording's labels into another match.
The saved-video findings covered
the full audit, body/auxiliary distinction, additional Blink/health checks,
post-Recall cooldown model and rejected ammo/ultimate interpretations.
The five suspected environmental records form a separate sampled component
class: one stays stationary and four move through similar spatial bounds. Their
specific roles remain unknown. Labels JSON retains these structural observations
as review context without promoting them to participant identities.

## Iteration loop toward correctly labeled players

1. **Use this replay as the reference.** Compare selected trajectories with the
   existing video around known actions. Verify the coordinate axes and self
   binding. Mark objects whose gameplay role remains unknown. Keep the measured
   alignment allowance when comparing event timing.
2. **Resolve one label relationship at a time.** Start with the hero resource
   associated with an already guarded object, then team and participant name.
   Use exact ownership relationships, build/lifetime guards and recorded evidence.
   Text appearing in memory or two objects moving together is not a verified join.
   Record only the extra fields needed to test the particular missing relationship.
3. **Prove one other participant in a short controlled test.** With known heroes
   and teams, have one actor move while the other stays still. Repeat with a hero
   change and a death/respawn. Save the expected event labels and read provenance.
   Use new tests only when the existing captures lack required bytes or events.
4. **Try to break the association on held-out data.** Check ordinal reordering,
   generation reuse, hero changes, respawns, a new match and process restart.
   Accept a mapping only when it matches the controlled labels and becomes unknown
   when its guards fail. Never attach an old person's name to reused object storage.
5. **Promote only validated fields and repeat.** Attach label, status, source,
   timestamp, build and supporting test to JSON. Publish a tested reader checkpoint,
   replay it here and inspect errors. Expand from self + one known other participant
   to the full observed roster, then abilities/status. Validate current player
   visibility separately before any live player-facing output.

The next milestone is broader reviewed lifetime coverage and an independently
validated automatic identity relationship. The current manual saved-video matches
do not establish a named full-roster decoder for arbitrary matches.

## Combined compact recorder sessions

`prepare_compact.py SESSION_DIRECTORY OUTPUT.json` reads the recorder's
`observations/window-*/game-state.jsonl` with its `session.json` QPC origin.
A standalone combined `game-state.jsonl` also works and starts at its first source
bracket. This adapter retains source-qualified structural lifetimes, per-field
validation/build/read evidence and nullable hero/health/relation/name/team values.
It does not create names from a hero, treat relative relation as a validated team,
or infer any attacker from health loss. The converter accepts only the reviewed
compact schemas and removes arbitrary native fields and paths.

The input may also be a sealed combined-storage window directory. Recorder
session discovery accepts either a flat file or `storage-index.jsonl` per window,
and rejects ambiguous or missing formats. The importer verifies the ordered
open/seal chain, original data/receipt hashes and sequence links, and the matching
`overwatch-decoder.private.combined-run/2` result. Complete and explicitly partial results are
distinct; unsealed, failed or inconsistent captures are rejected. Consumed data
is rehashed before publication, and a failure leaves the previous output intact.
Storage cohorts stay within one logical observation epoch: rotation does not
reset player keys, timestamps or the partition hold policy. This is stored-data
integrity verification, not independent confirmation of gameplay semantics or
capture durability.

Saved ten-actor windows containing 627 and 724 updates were losslessly repacked
into seven and eight cohorts. The importer reproduces every original replay
value, frame, object key and event, apart from added storage metadata. Those are
offline repacks of recorded data, not evidence of a live rotated Windows capture.
The existing per-export memory/output bounds below remain active; multiple
storage files do not bypass them or imply continuous gameplay coverage.

Independent partition updates are combined for display with their individual
source timestamps. A partition's latest observation expires after 50 ms, unknown
updates clear its partition, acquisition windows clear every partition, and there
is no interpolation or invented continuity. Field evidence is deduplicated in a
source-sample table. The default existing viewer limits (100,000 frames, 4,096
objects, 2,000,000 positions and 128 MiB JSON) remain active. Long recordings may
need separate bounded replay exports; the adapter fails without replacing an
existing output when a limit is exceeded.

Orange timeline ticks show recorded outgoing feedback candidates, with truncated
amount and nullable target. Purple ticks show separately validated incoming source
observations, preserving the source hero/relation and both timestamped position
samples. These source observations are not unique hits or exact impact times.
The **Damage and source observations** list excludes future records and idle
inactive-context rows; all source records remain in the exported evidence.
Other unresolved incoming records display no source identity. Clicking a record
seeks its observation time and selects its exact source or target only when that
entity is present in the current roster sample. The inspector
shows compact health/hero/relation with the source's validation status; the full
allowlisted source evidence is in provenance and Frame JSON. No facing cone is
invented when the compact producer has no source-bound raw rotation candidate. Video
remux and explicit calibration still use the existing server options; recording
all sources on one QPC clock does not establish exact video presentation timing.


For a complete recorder session containing multiple native windows, use a bounded
index instead of one growing browser document:

```bash
python3 tools/entity-replay/prepare_compact.py SESSION_DIRECTORY OUTPUT_INDEX.json --chunks
python3 tools/entity-replay/serve.py OUTPUT_INDEX.json --video EXPLICIT_REMUX.mp4
```

Each original window converts separately under the unchanged 128 MiB, frame,
object and position bounds. The small index binds every chunk's byte count,
SHA-256 and time range. The server exposes only this explicit confined set of
chunk URLs; the browser verifies each fetched digest and replaces its single
loaded window when scrubbing or playback enters another. No full recording is
loaded into browser memory. Dark intervals between windows remain unknown and
identities are not carried between windows. The current window's damage ticks
and field values remain source-bound. Conversion publishes the index only after
all chunks pass; an earlier index survives a failed conversion. Unreferenced
partial conversion files may remain for diagnosis. This bounds per-window
payloads, not total storage or browser object overhead.

The local server allows a normal top-level navigation into the empty UI shell.
Cross-site requests for replay/chunks/media, subframes, foreign Origin headers and
non-loopback Host headers remain rejected. This enables opening a local replay
from another page without granting cross-origin data access.

### Open a finalized full-session recording locally

Use the original recorder session directory and a separate output directory.
A repeat-window recording uses the final manifest's `accepted_window_numbers`
and matching `observation_window_start`/accepted `observation_window_end` journal
records. The importer checks the finalized session clock and journal footer, then
verifies each admitted window's seals, result, source bytes and timestamp bounds.
By default it never reads unaccepted window contents. Missing acceptance, failed
verification, status-only windows and cancelled tails remain gaps. An empty accepted set can
still open the full video. Older recordings keep their existing strict import.

```text
python -I -S -B tools/entity-replay/prepare_compact.py SESSION_DIRECTORY OUTPUT_DIRECTORY/replay.json --chunks
ffmpeg -copyts -i SESSION_DIRECTORY/desktop.mkv -map 0:v:0 -c:v copy -an -avoid_negative_ts disabled -movflags +faststart -n OUTPUT_DIRECTORY/video.mp4
python -I -S -B tools/entity-replay/serve.py OUTPUT_DIRECTORY/replay.json --video OUTPUT_DIRECTORY/video.mp4 --port 0
```

Open the loopback URL announced on stdout. Pass the MP4 remuxed from this same
session; do not pair the index with a different clip. For a repeat recording,
the importer recomputes the conditional source-clock bracket from this session's
launch and frame receipt log. The viewer shows this bracket separately from a
source/video-bound `--alignment` calibration. An unavailable bracket leaves the
video on its own clock until the offset is adjusted. Neither an estimated bracket
nor the frame receipt establishes exact presentation or game input latency. A
separately measured offset from an earlier recording does not apply here.

One chunk is prepared per accepted native window. The normal replay caps remain
128 MiB, 100,000 frames and 2,000,000 positions **per chunk**, with a 1 MiB index
and at most 240 windows. The browser fetches and verifies only the needed chunk;
seeking cancels obsolete requests. No object, label or event is drawn from a
previous chunk while a different window or gap is selected. The original video
continues through leading, intervening and terminal gaps. Raw sampling and Frame JSON retain the 50 ms in-window hold rule and original
source timestamps. The default Smooth motion view may hold a display position
for at most 200 ms and interpolate short moves only within the same observed
entity and window. Moves greater than three units snap, and an explicit unknown
frame clears the object. This is display only; it does not add observations or
bridge window gaps. Horizontal follow uses X/Z so height changes stay visible;
height guides show the vertical difference from the reference grid. Camera
controls and rotation candidates remain available when supported by the sample. User gameplay windows
admit roster observations only; no exact camera, visibility, damage, or full
match coverage is inferred.

Two-source roster recordings expose a **Recorded roster source** selector. Each
source has its own session, segment and original QPC bracket, also present in
Frame JSON. The displayed source is independent of the other source. The source
slots may change membership on reacquisition, so two source samples do not
establish a simultaneous or complete census. A source without a valid sample
shows a gap even when the other source has observations. Repeat-window handoff
uses the latest verified predecessor read across both sources as a conservative
cutoff, and preserves the original per-source proof and rejected-sample counts.
Shared excerpts currently require a single roster source.

Saved ten-actor windows exported at 21.64 MB for 627 frames and 25.01 MB for
724 frames. For sizing, a 45-second window at 20 Hz is about 900 frames and 9,000
positions for ten actors; the measured larger window scales to about 31 MB at
that count. A 20–30 minute session has roughly 27–40 such windows and may take
time and disk space to verify/export. This is per-window evidence and sizing,
not runtime acceptance of uninterrupted full-match capture.

The portable viewer requires Python 3.11+ with its standard library, the local
FFmpeg binary, and a browser that can play H.264 MP4. There are no pip packages,
external fonts, CDNs, or remote JS dependencies. Keep the repository-relative
paths for `tools/entity-replay/{prepare_compact.py,session_windows.py,serve.py,chunks.py,index.html,app.js,model.js,evidence.js,environment.js,theme.js,style.css}`,
`tools/entity-decoder/combined_storage.py`, and `overwatch_decoder/{__init__.py,session_observations.py}`.
The original recording folder is never modified by repeat-session export.


### Recover a sealed prefix from a cancelled window

For a finalized repeat recording only, add `--recover-sealed-prefixes` to the
export command. This is an explicit offline recovery mode. It never edits the
original session, creates a missing producer `result.json`, or changes the
recorder's acceptance record. A cancelled window must have matching final
journal evidence and a completed source worker with verified inventory,
selected receipts, target build/lifetime and original QPC scope.

The exporter verifies each original open/seal pair and its exact compact and
receipt bytes, then matches the selected source row and original entity payload.
It stops before the first unsealed, truncated or mismatched cohort; later bytes
are not promoted. A verified prefix appears as **Recovered sealed prefix** in
the viewer, separate from accepted windows, with its own evidence hashes and
original timestamps. The open cohort and remainder stay unknown. This verifies
stored evidence and does not re-decode gameplay semantics or certify full-window
completion. Without the flag, cancelled windows remain gaps as before.
