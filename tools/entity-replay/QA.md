# Replay QA inventory

Required claims: all recorded object positions render as blocks; exact raw XYZ
can be inspected; current self association is distinct; neutral object IDs do
not imply a player roster; gaps remain blank; replay is localhost only. New claims:
video and coordinates share playback; alignment remains adjustable/estimated;
WASD and mouse navigation work; saved quaternion candidates drive illustrative cones.

## Workshop surfaces checkpoint, 2026-11-06 UTC

- 67 replay Python tests, 57 JavaScript tests and 11 geometry Python tests passed.
  The environment validator rejects source/registration/scope mismatches and
  invalid rays or patches. The server exposes only the explicit environment file.
- Actual Workshop Chamber output supplied 245 surface hits and 126 small patches.
  Four noncoplanar controlled position pairs established identity registration;
  the fifth held-out pair matched at the Inspector log's two-decimal precision.
  All 895 native frames passed strict verification and reproduced their saved
  projections. The local viewer loaded all 895 converted frames.
- Chromium rendered the real sampled wall/floor alongside the recorded local
  player. At replay time 16 seconds, the inspector displayed `(0,3,0)` and 175 HP.
  Map surfaces changed canvas pixels when toggled. Light and dark renders were
  visually inspected. Fit includes sampled surfaces when their overlay is on,
  keeping the player and surveyed area in the frame after seeking.
- Source logs, registration evidence, converted replay and browser screenshots
  remain private. The existing data-URL favicon is blocked by the local server's
  image CSP; no map-loading or rendering errors were observed.
- Coverage is a partial schematic in one map/build. This does not establish
  complete collision/visibility geometry or automatic map capture in ordinary
  matches. No geometry was added to previously recorded matches or the website.

## Scoped video evidence and calibrated alignment checks

### Extended evidence and self-pool checks

| Claim | Functional check | Visual state |
| --- | --- | --- |
| Ten initial player matches | Inspect/download a first-acquisition frame | Ten distinct names; auxiliary shield stays a candidate |
| Later labels are scoped | Seek named Sigma, Widowmaker, Lúcio and ally switches; leave each reviewed span | Correct historical hero, unknown outside its span |
| Self health candidate | Compare damaged, zero and three-pool alternate-form anchors; download JSON | Candidate value matches reviewed HUD; raw pool/read provenance retained |
| Missing health stays missing | Seek recording gap, unknown-self frame and select another object | No carried-forward health and no enemy-health inference |
| Layout | Inspect new health row on desktop and phone | Label/value readable, no horizontal overflow |

Exploratory cases: scrub from alternate form across an acquisition break while
self is selected; jump from a later enemy anchor back to the initial hero. These
checks supplement the existing navigation/playback inventory below.

Verified results for this extension:

- 26 Python tests and 30 JavaScript test groups pass. New cases cover a third
  declared pool, valid zero, missing/extra/stale pool fields, wrong self/profile,
  declaration mismatches, exact read brackets and clearing across gaps.
- Independent full-source comparison retains all 21,711 frames, 360,452 positions
  and rotations, and 21,691 complete self-pool candidates with 20 nulls.
- 25 additional browser assertions pass: ten unique initial player names,
  auxiliary candidate separation, later Sigma/Widowmaker/Lúcio and ally switches,
  identity clearing outside reviewed spans, self-only health, zero, three pools,
  gaps, JSON provenance and the 170-observation/48-binding download. The five
  structural-object summaries survive download without filling player identity.
- All 119 binding evidence references have a matching recorded object within the
  declared span and the alignment allowance. Eight references land nominally in
  short gaps; the nearest supported sample differs by 0.7–21.0 ms. The viewer
  preserves the blank gap. Next-sample navigation restores the applicable label.
- The alternate-form video boundary is retained: at video 299.999 s the rendered
  prior frame shows 745 while the candidate shows 752; at 300.035 s both show 752.
  This fits the practical ±0.10 s allowance and is not treated as exact render sync.
- Desktop 1440×1000 and phone 390×844 show the health candidate and provenance
  clearly, without horizontal overflow. New screenshots and downloaded evidence
  remain private. No browser JavaScript errors were observed.

| Area | Functional check | Visual state / evidence |
| --- | --- | --- |
| Calibration | Load a source/video-matched offset; edit it and reset | Calibrated offset and practical uncertainty; manual change is unverified |
| Identity | Seek a reviewed match, an unreviewed epoch, and a recording gap | Name/team appear only within exact-key active scopes; candidates leave fields unknown |
| Roster | Review timestamped hero changes and retrospective cards | Ten observed names do not imply ten object matches; no future hero appears as last seen |
| Evidence | Click a selected object's anchor and a roster hero button | Playback pauses at the corresponding video time; evidence remains reviewable |
| JSON | Download labels and current frame, including a gap and manual offset | Source, scope, provenance, candidates and historical observations preserved; gap objects empty |
| Failure | Inject a wrong-source label document | Visible labels-unavailable state; coordinates and video remain usable |
| Layout | Inspect matched/unmatched/candidate states at desktop and phone widths | No clipped names, JSON buttons accessible, no horizontal overflow |

Exploratory checks: switch between scoped matches while scrubbing; cross an
acquisition gap; change the offset then download a frame; follow a hero's sequence
of sightings in both directions. These checks validate saved-capture annotations,
not a universal identity decoder or current player visibility.

### Calibrated evidence checkpoint

- 23 Python tests and 28 JavaScript test groups passed. Tests cover source/video
  mismatch, invalid calibration, bounded documents, exact-key/time scopes,
  candidate/conflicting labels, inactive gaps and retrospective/future sightings.
- 29 browser assertions passed against the saved recording. Evidence buttons seek
  the corresponding footage; named enemies/allies, ambiguous records, historical
  heroes and unreviewed later epochs show their different states correctly.
- Frame JSON preserved nine distinct reviewed identities plus two ambiguous
  records at the checked first-epoch sample. Exact position-read ticks survive.
  Gap JSON contains no objects/sample; a manually changed offset is unverified.
  Labels JSON retained all 88 reviewed observations and 15 scoped bindings in
  this checkpoint's private sidecar. These counts describe that sidecar version.
- A wrong-source label document shows a visible error while coordinate playback
  remains usable. No JavaScript errors or external requests were observed.
- Desktop 1440×1000 and phone 390×844 were visually inspected. Phone controls wrap
  without horizontal overflow, including Frame JSON; roster cards remain readable.
- During 92 seconds of exploratory playback, map expansion, movement, facing
  toggles and view changes worked. The sampled shared-clock difference was below
  1 ms; this measures UI linkage, not historical alignment accuracy.
- Private screenshots, downloaded JSON and machine-readable browser results stay
  in the ignored local QA folder. No player names or recording bytes are committed.

## Video, orientation and navigation checks

| Area | Functional check | Visual state / evidence |
| --- | --- | --- |
| Video | Decode real footage; play/pause from both buttons; all speeds; seek both directions | Gameplay pixels beside the matching replay time; expand and split modes |
| Alignment | Edit offset and reset; inspect shared and video clocks | Estimated timing bracket and manual-unverified note; no exact-sync claim |
| Coverage | Seek video-only startup, internal position gap and video tail | Footage continues; no stale blocks or cones |
| Facing | Toggle cones; change aperture; select self and another object | Candidate label; rotation provenance; illustrative aperture |
| Navigation | WASD, Q/E, Shift speed, right-drag look, left orbit, middle pan, zoom, F fit | Camera moves consistently; selection still works; no movement after blur |
| Suggestions | Select user-labeled objects | Tentative suggestion shown separately from unknown team/hero/name |
| Layout | Desktop split, expanded video, narrow desktop, phone | Video and controls visible without horizontal overflow |
| Errors | Missing/invalid video; no media configured; missing rotations | Coordinate replay remains usable and missing facing remains unavailable |
| Delivery | MP4 range/HEAD/suffix/invalid ranges; metadata exposure | Only the explicitly configured private media is served |

Exploratory scenarios: scrub repeatedly during playback and buffering; alter camera
while playback runs; zoom close to objects then fit; expand video during a gap;
change offset near either recording boundary. Record results after verification.

| Area | Functional check | Visual state / evidence |
| --- | --- | --- |
| Source fidelity | Independently compare every position, self flag, key and tick to decoded source | Sample counts and selected XYZ match the source |
| Playback | Play, observe time and coordinate changes, pause, change every speed | Moving blocks and trails track the selected object |
| Timeline | Seek forward/back, previous/next sample, start/end | Playhead, time and object list stay aligned |
| Missing data | Seek startup gap, internal acquisition gap, unknown-only terminal frame; jump to next data | Empty scene and unavailable XYZ; no retained blocks |
| Object selection | Select self and another object in list and canvas | Selected marker and XYZ correspond; hero/team/name stay unknown |
| View | Orbit, Shift-pan, wheel zoom, fit, top/3D cycle | Blocks remain legible; no clipped primary controls |
| Options | Trails on/off/on; follow on/off | Trails vanish/reappear, self remains centered only when enabled |
| Details | Open object provenance and replay explanation | Raw source values, timing and limitations readable |
| Layout | Desktop, narrow desktop, phone | Initial viewport, dense sample and gap inspected separately |
| Errors | Malformed export and failed response | Visible error; playback disabled |
| Local delivery | Host/origin/traversal tests; no external requests | Only explicit replay and UI are available |

Exploratory cases: scrub through a disappearance while an object is selected;
switch views/follow/zoom during playback; select an unknown-only last frame then
step backward; very narrow viewport with details expanded. Tests are evidence
of this private viewer, not validation of named-player or map reconstruction.

## Video and navigation checkpoint

- 20 Python tests and 10 JavaScript test groups passed. Converter parity covers
  all 360,452 saved quaternion tuples/read brackets without changing source values.
- The browser decodes the real 1920×1200 H.264 footage. Remux comparison found
  exactly the same 16,814 compressed packet hashes and start/end PTS.
- Both play buttons, pause, all five speeds, forward/backward scrubbing, offset
  editing/reset, full video end/restart and both expanded views were exercised.
  Shared-clock differences in the sampled playback checks were below 120 ms;
  this checks the UI linkage, not the historical alignment estimate.
- Startup, the long internal position gap and video-only tail show no blocks or
  cones; video continues through the internal gap. Missing video keeps coordinate
  playback usable. A legacy export with no rotations or media still opens.
- WASD and Q/E changed camera position; Shift increased travel speed; right-drag
  changed direction while preserving camera position; middle-drag translated it;
  wheel zoom and F fit worked. Blurring the canvas stops held-key movement.
- Cone toggle/aperture, unverified user suggestions, top/3D, trails and follow
  controls were exercised. No player labels or FOV were promoted to validated data.
- A 30.5-second exploratory run combined playback with camera/layout changes.
  No JavaScript errors or external requests occurred. Desktop 1440×1000 split and
  expanded views fit their primary controls; 1024×800 and 390×844 stack vertically
  without horizontal overflow, with video play accessible at the top.
- Private screenshots, browser results and remux proof are retained only in the
  ignored local QA folder. Source and sanitized measurements alone are published.

## Original coordinate-only checkpoint

- 15 Python tests and 7 JavaScript test groups passed.
- Independent full-source comparison: 21,711 frames, 360,452 positions and their
  read brackets, exact object keys/self flags, 369 unknowns; no mismatches.
- Chromium 151: real playback at all five speeds, pause, sample stepping, scrubbing,
  object/canvas selection, camera controls, option cycles and provenance verified.
- Startup/internal/terminal gaps clear blocks and coordinates. The 23-object sample,
  top/3D views and selected-object state were visually inspected.
- Desktop 1440×1000, narrow desktop 1024×800 and phone 390×844 inspected; no horizontal
  overflow, clipped playback controls or unreadable coordinate fields found.
- Malformed and missing exports show a load error with playback disabled.
- 33 seconds of exploratory playback covered changing camera modes, following self,
  trails and speed while time advanced. No JavaScript page errors or external
  network requests were observed. Close-up blocks can naturally overlap when the
  recorded coordinates are close; the list remains available for selection.
- Private screenshots and machine-readable results stay with the ignored local
  replay artifact. The demo server is intentionally left running with a PID/log;
  verification browser sessions are closed after delivery.
