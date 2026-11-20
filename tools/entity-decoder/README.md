# Guarded controller/body relations

`relations.py` projects a research-only relationship from a verified v1 native
field-stream frame and its exact profile bytes. It does no process access and
contains no application offsets. It emits opaque process-object keys, evidence
field names, sampled words, read brackets, and frame timing. It emits no player
names, teams, hero labels, health, or positions.

The acquisition recipe must independently establish the relationship. In the
current private experiment it resolves the controller's body creation key,
requires an exact body key and the same manager, and checks a reverse body-to-
controller lookup. All component types, owners, registry entries, map nodes,
and relationship words remain dependencies of the sampled fields. Merely
naming five fields or finding equal integers does not establish this route.
This helper is not an acquisition verifier or a public gameplay-state decoder.

Callers must verify recording and acquisition provenance before passing data:
recipe/build identity, complete native acquisition, profile hash, durable chunk
hashes and ordering, and the recorded target. The helper additionally requires
matching profile/target identity, direct guarded i32 bindings, all declared
before/after checks, ordered read brackets, observed values equal to the guarded
words, matching body keys, and unambiguous handles. Unsupported or missing
bindings produce `unknown`; no previous value is carried forward.

```python
from relations import GuardedRelations

projector = GuardedRelations(verified_profile_bytes)
research_result = projector.project(verified_native_frame)
```

The controller key excludes body storage, allowing a newly validated body to
retain its controller key. Keys include process creation, executable identity,
full generation-bearing words, and their source addresses. They are neither
account identifiers nor evidence of continuous lifetime across a gap. A new
body binding requires fresh acquisition; the old profile should fail its guards.
Sequential reads and before/after checks cannot exclude every intervening reuse.

## Verified checkpoint

A same-build saved capture yielded nine reciprocal controller/body associations.
For those nine, the controller hero resource equaled the corresponding body's
resource. A separate controller carrying a 16-byte account-like token had no
body while the player was selecting a hero. The recovered helper returned that
inline token, not display-name text. The earlier generic UI text pool is not a
participant-name decoder.

A subsequent native Practice Range capture after spawning resolved the account-
bearing controller to a body. Its position source address exactly matched the
independent selected-player acquisition route. Both hero resource words matched
between controller and body. A three-second native recording produced 149 frames:
all 149 passed the relation projector, with one controller key and one body key.
Recording/profile/index/chunk hashes were verified. This establishes the sampled
structural association; it does not yet establish continuity through respawn,
other-player account names, team, or visibility.

A full live collection exceeded the existing 256-guard limit. The successful
capture covers one controller and retains all dependencies (14 fields, 32 guard
declarations). Broader coverage needs separately bounded captures with separate
timestamps; no guard-budget increase or dropped dependency is justified.

## Controlled removal checkpoint

A targeted Practice Range bot capture recorded 557 frames before stopping on the
first unknown. The relation projector accepted frames 0–555 and rejected frame
556 after the body registry, component, and reverse-map dependencies changed.
The controller guards still matched at that final boundary, but the combined
profile correctly emitted unknown for its fields. All profile, sample, index,
and individual chunk hashes were verified, including the terminal summary of
the intentionally stopped recording.

A later fresh acquisition using the exact old controller identity found no
matching controller. Its registry slot was free with an advanced generation.
This disproves treating that process-object key as a persistent bot participant
identifier. A replacement at the same position cannot be joined by location.
The experiment establishes invalidation and removal; it does not establish a
participant identity across respawn or make the unobserved interval continuous.

A subsequent controlled self death and respawn produced 1,490 observed frames
in a thirty-second recording. Every frame passed both the relation and account-
name projectors, retaining one controller key, one body key, the same guarded
account token, and one exact account name. The health transition to zero and
restoration occurred at frames 492 and 646; separate visual observations
confirmed death and return to spawn. This experiment retained the body object;
it does not test a changed body binding. Ten skipped sample intervals remain
gaps. Hash verification covered the profile, index, samples, and all chunks.
The sampled profile SHA-256 is
`ce7fb3bed8ce2fbe92fbd0a4f3d02f9142df5588ef084dbffaf37f9aadd21cae`.
A separate native acquisition after respawn independently rebuilt identical
profile bytes. Its 147-frame recording again retained the same controller,
body, and account name, with three skipped sample slots. The interval between
recordings remains unobserved; matching endpoints do not fill it.

## Tests

```sh
python3 -m unittest discover -s tools/entity-decoder -v
```

The synthetic tests cover signed words, body replacement, generation/storage/
process changes, gaps, contradictory or missing guards, dependency and bracket
failures, ambiguous handles, and exact source/profile binding. They contain no
private capture data and do not establish application semantics.

## Guarded account names

`GuardedNames(profile_bytes).project(frame)` in `names.py` handles the separate
verified account-name route. It requires an observed controller, four contiguous
guarded account-token words, contiguous observed UTF-8 bytes, a bounded NUL
terminator, and every declared before/after dependency check. Its private result
contains `private_name` and `display_name`; the latter removes a terminal numeric
`#` discriminator. Exact text is preserved otherwise. A missing body does not
invalidate an independently observed controller/name relation. Missing names are
never filled from prior frames, a text pool, or manually supplied labels.

The private native recipe computes the account map's CRC bucket from the full
16-byte token, follows at most eight native collision links, compares the full
node token and the repeated record token, and guards the string-pointer route.
Every visited node remains a dependency. A new insertion can invalidate a
profile even while the account remains present; reacquire instead of dropping
that dependency. The body reverse lookup has the same bounded-chain extension.

The first live attempt correctly rejected a different account at the bucket
head. After adding collision traversal, a native acquisition produced 78 fields
and 74 guard declarations. All 149 frames in a subsequent three-second recording
passed the account-name projector and yielded one identical name. The display
portion matched the separately captured HUD name under case-insensitive
comparison. Full account text and screenshots remain private. The native name
recipe SHA-256 is
`2126488fbf8c3eff1b86a11e7a6b5211e9f5078411b29ad03b19954e9312f1b8`;
the successful sampled profile SHA-256 is
`fce54fa3e28262de0964151efa46729d95f7df21327ba58410f33f1691d08829`.

This establishes the sampled local controller/account-name route for this build.
Other-player names remain unproven. The controlled self lifecycle below tests
identity retention; it does not prove continuity inside unsampled intervals.
Name output remains private research with unknown visibility and no public-state
eligibility. It must not be promoted merely because these parsing checks pass.

## Export a verified recording

The offline exporter requires the native recording verifier and the corresponding
completed acquisition. Set `RECORDING_DIR`, `ACQUISITION_DIR`, `OUTPUT_JSONL`, and
`DOTNET` to your local evidence directories, output file, and .NET executable:

```sh
python3 tools/entity-decoder/export_relations.py \
  --recording "$RECORDING_DIR" \
  --acquisition "$ACQUISITION_DIR" \
  --output "$OUTPUT_JSONL" \
  --observer windows/Observer/bin/Release/net10.0/overwatch-decoder-observer.dll \
  --dotnet "$DOTNET" \
  --include-display-names \
  --name-recipe-sha256 2126488fbf8c3eff1b86a11e7a6b5211e9f5078411b29ad03b19954e9312f1b8
```

Display-name export requires the exact verified name recipe and observed matching
controller/body keys in the same frame. It omits the full BattleTag and raw name
hash. `--include-private-battletags` explicitly opts into those private fields.
`--allow-partial` accepts only a verified durable prefix of a partial recording;
it does not bridge gaps or reuse previous names. Exported rows remain private
research; this command does not publish gameplay state.

Saved diagnostic streams that captured both health operands in the same guarded
vector can add `--health-ratio-contract PRIVATE_RATIO_CONTRACT_JSON` and
`--health-ratio-native-review PRIVATE_NATIVE_REVIEW_JSON`. Each contract pins the
profile and exact acquisition, embeds the complete owned health layout and
selects numerator/denominator components. The result attaches a sampled native
ratio candidate to the current body, returning null on gaps or invalid reads.
The native review is caller-supplied evidence; the exporter does not prove the
interpretation or identify universal HUD maximum health.

Saved exports can also include raw actor categories and the neutral selected
controller alongside health, typed hero candidates and forward-owner rows. Supply
all three options together:

```text
--raw-category-contract RAW_CATEGORY_CONTRACT_JSON
--context-controller-contract CONTEXT_CONTROLLER_CONTRACT_JSON
--context-projection-artifacts LOCAL_ARTIFACT_MAP_JSON
```

Both contracts must match that recording's acquisition evidence. These finite
options do not require live session-start events and cannot be combined with the
legacy `--category-contract` projection. The output includes a separate
`context_group_projection` and per-actor raw/context candidates; canonical teams,
global groups and relative allegiance stay null. Finite partition manifests can
retain the projection using `context_source_from_frame(frame)['context_projection']`
as the source's `context_projection`, plus its exact acquisition pins. The live
compact CLI still accepts live records only.

## Add verified hero labels to an export

Pass both a build-scoped hero catalog and an explicit local artifact map to the
same exporter. Set `HERO_CATALOG` and `HERO_ARTIFACTS` to those JSON files:

```sh
python3 tools/entity-decoder/export_relations.py \
  --recording "$RECORDING_DIR" \
  --acquisition "$ACQUISITION_DIR" \
  --output "$OUTPUT_JSONL" \
  --observer windows/Observer/bin/Release/net10.0/overwatch-decoder-observer.dll \
  --dotnet "$DOTNET" \
  --hero-catalog "$HERO_CATALOG" \
  --hero-artifacts "$HERO_ARTIFACTS" \
  --hero-locale enUS
```

The artifact map is a JSON object mapping SHA-256 digests to local file paths;
relative paths resolve from the map file's directory. The loader checks hashes
and reads only bounded regular files: at most 256 entries, 16 MiB per artifact,
and 64 MiB total. It performs no network access or artifact discovery. The locale
defaults to `enUS`. Existing name and health options can be combined with these
flags.

Hero annotation requires matching fresh resource GUIDs and the exact controller
and body keys in the same frame. Cached labels never supply a hero name. The
controlled self-lifecycle export retained 1,490 guarded relation/position/resource
frames; 1,482 received the combined name, health, and hero annotations. Eight
frames following ten skipped sample slots remained unknown for those derived
annotations. Matching later observations do not fill a gap. Exported rows retain
their research-only public-state restriction.

## Keyed cache string candidates

`GuardedCachedLabels(profile_bytes).project(frame)` in `cached_labels.py` decodes
an independently verified controller-keyed string cache. It uses the same exact
profile, identity, dependency, scalar, and read-bracket checks as the other
projectors. It additionally requires a contiguous bounded byte sequence with one
terminal NUL and valid UTF-8 without control characters. Missing cache entries
remain unknown for that controller; no label is copied from another row or frame.

The private native route resolves a global service, traverses its bounded hash
chain using the full controller creation key, and guards the string record's
length, capacity, and pointer where applicable. Saved native code establishes
this map's constructor/destructor extent, service getter, exact-key lookup, and
a caller that copies its result into a generic value formatter. Those facts do
not establish the ordinary HUD meaning of every cached string.

Two live recordings yielded 149 and 148 observed candidate labels respectively.
The first matched the independently decoded local account's display name; the
second belonged to a distinct controller and body. All recording hashes and
per-frame checks passed. One and two skipped sample slots remain gaps. Another
four-controller acquisition correctly failed when a registry entry was freed
during collection. The output remains `candidate_cached_label`, private, with
unknown visibility and `gameplay_semantics_validated=false`. It is not a fallback
participant name, hero label, team, or account identifier.

A controlled invite-only warmup then discovered exactly three controllers without
fixed handle, name, or position selectors. Its native profile contained 53 fields
and 89 guard declarations. All 248 frames passed the relation and cache parsers,
producing 744 observed rows, three distinct controller/body pairs, and three
stable cached strings. Controller and body hero resources agreed for every
sampled pair. Two skipped slots remain gaps. The strings were consistent with
the configured local player and two different AI heroes; the cache output still
does not independently establish a team, hero label, account, or world visibility.
The sampled profile SHA-256 is
`13b63767c87004f6fb647f67fe094fd1975a4aaf227986234fc1293cb3735137`.

A later held-scoreboard capture overlaps three frames of the same guarded
three-controller recording. The native cached strings match the displayed local
name and two AI participant labels after case folding. The scoreboard places the
local player and one AI in the friendly section and the other AI in the opposing
section. This validates the display-label correspondence for those observed
controllers in this controlled warmup. It does not establish a universal account
identifier, hero-name fallback, or visibility of their world positions.

That recording contains 1,498 frames and 4,494 observed relation/cache rows. Its
profile SHA-256 is
`3be13e1ce03a3a5a7b2c92f0b30ffeb476aea3e8f3dd4230b314a51efadf7c1c`.
The exporter retains 4,488 cache and health annotations; two frames following
skipped slots leave all three derived rows unknown. To include the separate
research cache field, add these options to the export command:

```sh
  --include-cached-labels \
  --cached-label-recipe-sha256 "$CACHED_LABEL_RECIPE_SHA256"
```

The explicit recipe digest must match the completed acquisition. The default is
off. `cached_label_candidate` and `cached_label_evidence` remain separate from
account display names and hero labels, with private research status and no public
eligibility. Missing entries, failed guards, mismatched controller/body keys, or
gaps never borrow another row's or earlier frame's label.

The same controlled scoreboard trial also validates two additional build-scoped
hero mappings through typed hero assets and reviewed distinct hero portraits,
with overlapping fresh controller/body resource reads. These checks are separate
from cached participant strings. A private three-entry catalog projects Tracer,
Ana, and Ashe for 1,496 frames each; six rows after the two skipped slots remain
unknown. Unlisted heroes, builds, and locales remain unmapped. The catalog
SHA-256 is
`49d47de84e086497443967c706d8153f4a14e212fccdf59b07d99e148f99ae0f`.

A subsequent controlled team-move holdout distinguishes participant labels from
hero resources. The changed AI appears as `Ana 2` in both the native cache and
held scoreboard, while the previously frozen typed-asset catalog still yields
hero `Ana`. Both its controller and body keys differ from the prior roster; the
local player and the other AI retain their exact controller/body pairs. The
comparison records a removed controller and an added controller, without merging
them into a persistent person identity by name, hero, or position.

The pre-move recording has 1,728 observed frames followed by a terminal unknown
frame. Its cache bucket-head guard passes before sampling and fails afterward,
so that frame is rejected. The fresh recording has 1,498 observed frames and
4,494 cache/relation rows. Its held-scoreboard image overlaps four frames; the
moved AI is in the opposing section. The unchanged catalog produces 1,497 labels
for each of the three heroes. Two skipped slots precede one frame, leaving three
hero rows unknown. The fresh profile SHA-256 is
`5663b7e2f30e039d8624efd923b52c4ee11c55a292776b2507262e558f17c800`.
This holdout validates the sampled replacement and separate label/resource
routes; it does not bridge the unsampled interval or establish world visibility.

## Add scoped category and team research

The exporter accepts an explicit category contract and its local artifact map:

```sh
  --category-contract "$CATEGORY_CONTRACT" \
  --category-artifacts "$CATEGORY_ARTIFACTS"
```

Both options are required together and use the same bounded, hash-checked local
artifact loading as hero catalogs. The contract pins its native recipe and
acquisition evidence, recording manifest, reviewed roster and observer identity,
and finite frame/time scope. The exporter joins exact controller/body keys within
each frame and retains actor and observer read evidence. It emits separate
`raw_category_candidate`, `team_candidate`, and `relative_allegiance_candidate`
research fields; ordinary team and participant-name fields remain unknown.
Missing bindings, out-of-scope frames, and gaps remain null.

Two complete combined exports exercise these options with health, hero, and
cached-label annotations. A separate 1,499-frame baseline has 4,497 relation rows
and 4,494 annotations of each kind. The 1,498-frame team-move holdout has 4,494
relation rows and 4,491 annotations of each kind. Each recording has one gap
frame, following one and two skipped slots respectively. The reviewed baseline AI
is friendly and the replacement AI is opposing; their hero label remains `Ana`
while their controller/body keys and cached participant strings differ. These
scoped research results do not establish public world visibility.

## Automatic reacquisition after body creation

A live transition exposed an incomplete-profile case: acquisition found a new
controller with a nonzero guarded body key, but its earlier object enumeration
missed the body. That profile could remain valid while omitting the body's
fields. The decoder correctly kept the missing relationship unknown, but the
recorder had no dependency that would trigger a fresh acquisition on appearance.

The corrected private recipe watches the exact requested key's native lookup
bucket and examined records when no body was collected. If the target exists
without the body component, its component membership is guarded. If the exact
target is already a ready body that the earlier enumeration missed, acquisition
is rejected and the existing recorder retries. All existing linked-body fields
and dependencies remain unchanged. Eight native fixture cases cover absent
buckets, collisions, appearance, ready-body rejection, and bounded traversal.

A 180-second controlled live run exercised the ready-body rejection directly.
Its third acquisition found the requested key and a ready body after enumeration
had omitted it; no incomplete profile was published. The fourth acquisition
then succeeded with all three body links. The three recording segments contain
8,843 frames, with six unknown relation rows at the two transition frames. All
successful profiles include three body links. Acquisition gaps remain explicit.
The corrected recipe SHA-256 is
`5eaa879679de72673c56f5b14cae9a6b5c0c2f8b4a2b43cb1174a3ac32b0d665`.

The two team moves produce distinct controller/body pairs and updated cached
participant strings. The frozen hero catalog continues to resolve Ana; the
local player's and the other AI's exact pairs remain unchanged. A held scoreboard
capture overlaps two frames of the final segment and agrees with its participant
labels. These observations do not bridge acquisition gaps, identify a persistent
person by a reused address or name, or establish world visibility.

## Ten-controller identical-hero roster checkpoint

A controlled ten-player roster contains the local Tracer and nine AI participants
using Ana. A lightweight native profile samples controller identities, guarded
body-key references, controller resource candidates, and cached participant
strings. It retains the controller and string-lookup dependencies while omitting
body, health, position, and category fields. Its 116 fields and 133 guard
declarations fit the existing native limits.

The first acquisition correctly failed its exact-ten requirement because an
inherited three-row filter retained only three of ten candidates. Changing that
filter to ten, with all dependencies unchanged, produced a complete acquisition.
The corrected private recipe SHA-256 is
`2885b417feca3173a0053d5e4c7ee7428145ca3a3c247ad9840c800ea245bfbe`.
A subsequent 30-second recording at 50 ms contains 600 frames and 6,000 observed
cached-label rows, with no unknown fields or skipped slots. All ten controller
keys remain distinct and stable. The nine Ana controller resource candidates
agree, while their participant strings and full controller keys differ.

A held scoreboard capture overlaps frame 74 and agrees with all ten participant
strings, including the numbered AI suffixes. It shows four Ana participants with
the local player and five on the opposing side. This validates the displayed
strings for that controlled roster; native identity comes from full guarded
controller keys rather than names, hero labels, or roster order. The lightweight
profile leaves every body object key unknown. Health, position, matching body
resources, and native team categories require separately acquired body-linked
profiles and exact-key joins with their own timing evidence. No world visibility
or atomic combined roster is established by this checkpoint.

Five concurrent bounded profiles subsequently recorded all ten controller/body
pairs, including the local player in every partition. Their 5,803 frames contain
16,243 guarded relation, cached-label, matching hero-label, and position
observations. All five durable segments verify successfully, with no unknown
fields or skipped slots. The combined set contains exactly ten distinct full
controller/body pairs. The duplicated local pair, participant string, and Tracer
resource agree across all five profiles. Its row prefix differs between profiles,
so the comparison joins full object keys rather than ordinals.

Both held scoreboard captures overlap every partition and agree with the same
roster. Each partition records the local position changing during forward input
and reversing during backward input. A diagnostic comparison pairs local position
reads whose midpoints differ by at most 25 ms: 4,398 pairs qualify, 4,057 have
identical coordinates, and the largest difference is about 0.104 native coordinate
units. The largest actual timestamp skew is about 23.984 ms. These measurements
preserve each read bracket; they neither establish an atomic roster snapshot nor
make unseen world positions eligible for public output. Health and team semantics
require their separate source contracts in the combined export.

## Aggregate bounded partitions

`aggregate_partitions.py` combines saved, hash-pinned semantic exports into
private research windows. Each input must have passed the exporter’s native
recording/acquisition checks. The aggregate retains source hashes, object keys,
read brackets and recording status; it remains `atomic: false`, with unknown
visibility and `public_state_eligible: false`.

```sh
python3 tools/entity-decoder/aggregate_partitions.py \
  --manifest "$PARTITION_MANIFEST" \
  --output "$AGGREGATE_JSONL"
```

The local JSON manifest has schema `overwatch-decoder.partition-research-manifest/1`:

| Field | Required content |
| --- | --- |
| `epoch_id`, `clock_domain_id` | Explicit capture epoch and common QPC clock domain. |
| `target`, `monotonic_frequency` | Exact native target object and counter frequency shared by every input. |
| `window_ticks` | Width of fixed, nonoverlapping output windows. |
| `maximum_skew_ticks` | Maximum admitted span from the earliest selected read start to the latest read end; at least the window width. |
| `maximum_origin_offset_ticks` | Allowed disagreement between each source’s UTC-to-QPC origin mapping. |
| `window_origin_ticks` | Optional grid origin; defaults to zero. |
| `roster[]` | Exact `controller_object_key`, `body_object_key` and authoritative `primary_source_id` for each object. |
| `sources[]` | Unique `source_id`, local `path`, semantic-file `sha256`, `profile_sha256`, `recording_manifest_sha256`, `acquisition_manifest_sha256`, and `objects[]` containing its exact controller/body pairs. |
| `sources[].allow_partial` | Optional, defaults to false. Explicitly admits exported native-verified `verified_stopped` or `recoverable_prefix` sources. |

Paths resolve relative to the manifest, or may be absolute local paths. Source
hashes are checked before ingestion and again while reading. An incomplete
source needs `allow_partial: true` on that source; its stopped/prefix status
stays explicit in every contributing observation. Output publishes atomically
without overwriting an existing file. The default output limit is 2 GiB;
`--maximum-output-bytes` may lower it. The limit includes empty windows and
repeated contributor evidence, and a rejected export leaves no final output.

A source frame belongs to exactly one window, selected by its end tick. If
several frames from one source land in that window, the latest is selected and
the discarded count is reported. Values never carry between windows. A missing,
gapped or stale primary stays unknown even if another partition observed the
same object. Repeated local-player rows can support each partition’s category
calculation without becoming authoritative for position or health. Dynamic
values from different read times remain separate observations. Object keys must
match the declared epoch; conflicting label, hero or team assertions produce an
unknown conflict.
Nested read brackets, profile/build bindings, health body/epoch bindings and
finite category scope must agree with their parent source frame.

Result `observed_rows` counts available primary relationships, not complete
optional state. `authoritative_field_coverage` separately counts each non-null
position, health, hero, cached label, category, team and allegiance candidate.
Verified participant names have their own count and are never filled from cache
labels. Keep those coverage counts and source timestamps when consuming a row.

### Measured ten-object checkpoint

Five concurrent bounded profiles at 50 ms yielded 5,803 frames and 16,243 input
observations. Each native segment verified as a finite stopped prefix after the
session deadline; the session duration completed separately. The aggregate has
1,260 windows, including 1,067 windows with all ten primary relationships
available (53.35 seconds of windows). Its 11,595 authoritative rows each contain
position,
health, hero, cached-label, category, team and allegiance candidates; verified
participant-name coverage is zero. Another 1,005 rows remain unknown because
that window has no primary frame. Five earlier frames were discarded within
windows, with no frame reused across windows and no static conflicts.

The configured skew bound was 100 ms; the maximum measured read span was
53.6492 ms. UTC/QPC anchor disagreement was four counter ticks (0.4 microseconds).
The JSONL artifact is 248,867,835 bytes with SHA-256
`23673b053dedfed703021b134f01fc264606ecbb17b001c1a6507e19d8ac0416`.
These are sequential, epoch-bound research observations. They establish neither
an atomic ten-object snapshot, continuity across gaps, nor player visibility.

## Project accepted live frames

`live_relations.py` consumes native `observe-fields --jsonl true --live-evidence
true` JSONL on stdin and writes one `overwatch-decoder.entity-relations-live/1` row per accepted
frame. The native option is off by default and includes the exact serialized
recording frame, including field dependencies and before/after guard checks.

Configure one explicit acquired epoch before feeding its events:

```sh
python3 tools/entity-decoder/live_relations.py \
  --acquisition "$ACQUISITION_DIRECTORY" \
  --recipe "$PRIVATE_RECIPE" \
  --session-id "$NATIVE_SESSION_ID" --segment 1 \
  --health-contract "$HEALTH_CONTRACT" \
  --cached-label-recipe-sha256 "$RECIPE_SHA256" \
  --hero-catalog "$HERO_CATALOG" --hero-artifacts "$HERO_ARTIFACT_PATHS" \
  > "$LIVE_RELATIONS_JSONL"
```

Supply stdin through the configured native event transport. Redirecting a saved
native JSONL file into the same command instead performs replay. The caller must
make the completed acquisition's profile, manifest and evidence available before
constructing the adapter; `--recipe` supplies the exact recipe when it resides
outside that directory. The consumer does not acquire files or read a process.
Health contracts must bind this acquisition's evidence, even when an earlier
acquisition produced identical profile bytes. Health, cached labels and hero
catalog arguments are optional; health accepts repeated `--health-contract`.

The current adapter supports v1 field profiles and recording frames. It checks
acquisition hashes, target, session, segment, ordered events, frame sequences,
clock anchors, exact envelope/frame agreement, field dependencies and read/guard
brackets. A different epoch requires a newly configured adapter; a rejected event
latches failure. No value carries across a gap or unknown frame. It accepts
legitimate cancellation unknowns and emits null semantics. Category contracts for
finite recordings are not accepted as live authorization.

Processing is synchronous and bounded: 512 KiB input lines, at most 100,000 events,
512 MiB total input and output, and 1 MiB output rows. Budget failures stop rather
than truncate a row; already delivered rows remain delivered. There is no
unbounded queue or automatic epoch discovery. EOF and a native terminal event do
not establish recording durability. Every output remains private,
`atomic: false`, `public_state_eligible: false`, and
`accepted_not_durability_verified`, with source hashes and read timestamps.

Optional live category composition requires both
`--live-category-contract "$LIVE_CATEGORY_CONTRACT"` and
`--live-category-artifacts "$LIVE_CATEGORY_ARTIFACT_PATHS"`. The explicit local
SHA-to-path map uses the same bounded, hash-checked artifact loading as hero
catalogs. The separate live contract pins the completed acquisition, actual
session/segment start events, native algorithm review, current roster/self review
and explicit review of the controlled mode for that epoch. The consumed start
events must match those reviewed objects. Finite recording contracts cannot be
substituted, and a new session or segment requires new admission.

Categories join by exact controller and body keys. Actor and self read evidence,
review hashes, source hashes, raw event hash and embedded-frame digest accompany
`raw_category_candidate`, `team_candidate` and `relative_allegiance_candidate`.
The ordinary `team` field stays null. Missing same-frame self evidence clears all
team/allegiance candidates; gaps and cancellation do not carry earlier values.
The feature is disabled unless both live category arguments are supplied.

### Connected runtime checkpoint

A controlled 45-second native observation at a requested 50 ms interval produced
871 decoded frames from 879 live events, with no unknown fields or skipped slots.
The first decoded row arrived 4.99 seconds after the transport wrapper started,
after the fresh acquisition was downloaded and checked. Following the twentieth
projection, a separate native status read still reported active recording of the
same target. This establishes projection during active native recording; the 4.99
seconds include startup and acquisition and are not per-frame latency.

All 871 rows contain an exact controller/body pair, position, health candidate,
cached label and independently mapped hero. Replaying the captured native events
reproduces the connected output byte for byte. All embedded recording frames
also match the independently hash-checked 42 saved chunks. The output is
8,987,631 bytes with SHA-256
`63d3d9375bd8314310d642590c448a66c7773a540f30219ba8b124a4cbefdf7f`.
The session duration completed; its finite recording segment stopped on deadline
cancellation. These later checks do not change the live rows' non-durable
qualification. This single-object checkpoint does not establish public visibility,
team inference, seamless epoch reconfiguration or an atomic roster stream.


### Connected three-actor checkpoint

A fresh controlled player epoch ran for 60 seconds at a requested 50 ms interval.
It produced 1,171 decoded frames from 1,179 native events: 3,513 observed relations
covering three distinct controller/body pairs, with no unknown fields or skipped
slots. Every row contains a cached label, mapped hero, position, health candidate,
raw category, team candidate and relative allegiance candidate. Self, friendly
and enemy each appear 1,171 times; the ordinary participant-name and team fields
remain unknown.

Fresh health descriptors and a separate live category contract were composed
from the completed acquisition during startup. The category review uses current
full actor keys, current roster/self evidence and the actual live start events.
The first decoded row arrived after 4.84 seconds, including startup and
acquisition. A separate status read after twenty projections confirmed that the
native observer was still recording the same target.

The self health candidate stayed at 175. The friendly candidate ranged from
227.5 to 250, and the enemy candidate from 0 to 250. Recorded position vectors
changed for all three actors: 53 distinct self positions, 1,059 friendly positions
and 768 enemy positions. These are guarded source observations; a zero sum alone
does not establish a death event, and a coordinate does not establish visibility.

Independent replay reproduces all 50,783,821 output bytes exactly, with SHA-256
`f078f7a1cf8939b85fe905575eb8b8f83b5c2e6279ec7e8132e4721d63fc16c7`.
All 1,171 embedded recording frames match the 91 hash-checked saved chunks, and
receipt sequences and timestamps reconcile with the live event stream. The
session duration completed while its recording segment stopped on deadline
cancellation. The output remains private, sequential and explicitly
`accepted_not_durability_verified`; this checkpoint does not establish seamless
reconfiguration, arbitrary-hero label coverage or public player visibility.

## Aggregate accepted live partitions

`aggregate_live_partitions.py` combines explicitly configured
`overwatch-decoder.entity-relations-live/1` sources into fixed windows. It consumes projected
JSON only; the upstream live decoder remains responsible for native guard
admission. The configuration is reviewed caller input, not native proof. The
finite manifest format and stopped-prefix exporter above remain separate.

```sh
python3 tools/entity-decoder/aggregate_live_partitions.py \
  --config "$REVIEWED_LIVE_PARTITION_CONFIG" \
  < "$INTERLEAVED_PROJECTION_JSONL" \
  > "$LIVE_WINDOW_JSONL" 2> "$LIVE_AGGREGATE_RESULT"
```

Each input line is either `{"kind":"frame","source_id":"p1","projection":{...}}`
containing a complete projected frame, or an explicit
`{"kind":"watermark","ticks":...}`. A saved input file runs replay; use a
tracked transport feeding current projections to establish connected operation.
The CLI canonicalizes each projection before hashing it. Direct API callers can
preserve the exact original projection line bytes:

```python
from aggregate_live_partitions import LivePartitions, canonical

adapter = LivePartitions(reviewed_config_bytes)
for source_id, projected_line_bytes in transport:
    adapter.consume(source_id, projected_line_bytes)
    watermark = adapter.automatic_watermark
    if watermark is not None:
        for window in adapter.advance(watermark):
            output.write(canonical(window) + b"\n")
            output.flush()
summary = adapter.close()  # Call only after transport ends; does not flush a tail.
```

The `overwatch-decoder.live-partition-config/1` contract requires:

| Field | Required meaning |
| --- | --- |
| `epoch_id`, `clock_domain_id` | Reviewed labels for this finite configuration and common host clock. |
| `target`, `monotonic_frequency` | Exact process/build target and native counter frequency. |
| `window_origin_ticks`, `window_ticks`, `maximum_skew_ticks`, `maximum_origin_offset_ticks` | Explicit window grid, read-span limit and UTC/QPC anchor tolerance. |
| `roster[]` | Exact controller/body keys and one `primary_source_id` per pair. |
| `sources[]` | Unique `source_id`, exact `session_id`, `segment`, `profile_sha256`, `acquisition` manifest/recipe/evidence hashes, allowed `objects[]`, and native `fields[]` name/type declarations. |
| `sources[].live_category` | Required when publishing category/team/allegiance candidates: contract/native/roster/mode review hashes, mode ID, exact self controller, and full reviewed `live_scope` including session/segment start hashes. |

The automatic watermark is the minimum latest accepted frame end among all
configured sources. No window finalizes until every source has supplied a frame;
a stalled source then stalls this watermark. An optional explicit common-clock
watermark can finalize missing rows as unknown, but cannot establish that an
unreceived source finished. Late frames for a closed window reject the instance.
EOF and `close()` leave the pending tail unfinalized. A changed source session,
segment, profile or roster requires a new whole aggregate configuration.

A frame belongs only to the window containing its end tick. The latest frame from
a source wins within that window, and any source gap in it makes that source
unavailable. A missing, gapped or stale primary never falls back to a support
source. Repeated self rows can support local category evidence without owning
position or health. Dynamic observations at different read times may differ;
conflicting static label/hero/team assertions produce unknown conflict rows.
Nested object, profile/build, read brackets, field declarations, health binding
and live category admission must match their source frame and configuration.

Output is `overwatch-decoder.partition-research-live/1`, private, non-atomic and
`accepted_not_durability_verified`. Each observation retains source timing,
acquisition/event/projection hashes and primary ownership. Summary
`observed_rows` counts available primary relations; `authoritative_field_coverage`
counts each non-null candidate separately. Partial windows, unknown reasons and
pending windows/bytes remain explicit. Verified names never fall back to cache
labels, and these candidates establish no player visibility.

Bounds include 16 sources, 128 roster pairs, 1 MiB input lines, 16 MiB output
lines, a 256-window pending horizon, 16 MiB pending encoded source bytes, 100,000
input events/windows, and 2 GiB input/output. Generated empty windows also count
against output bounds. A rejection leaves only an already delivered accepted
prefix; it does not certify that prefix as durable or complete.

An eight-object checkpoint
recorded connected measurements and a separately labeled offline window-size
comparison. A subsequent connected 100 ms run has complete candidate coverage in
532 of 533 common-interval windows; its one genuine source gap stays unknown.
Independent saved-order replay reproduces the connected bytes exactly.

## Recover across accepted live epochs

`live_sessions.py` coordinates the exact native `overwatch-decoder.field-live/1` event stream
across guard invalidation and reacquisition. A caller-supplied factory must build
a fresh `LiveRelations` from each completed acquisition's own files and optional
contracts. The library performs no acquisition, file transfer or process access.

```python
from live_relations import LiveRelations
from live_sessions import LiveSession, stream

def factory(session_start, completed_acquisition, segment_start):
    paths = supplied_epochs[(completed_acquisition["ordinal"], segment_start["segment"])]
    return LiveRelations(
        paths["acquisition"], session_start["session_id"], segment_start["segment"],
        recipe_path=paths["recipe"], health_contracts=paths["health_contracts"],
        cached_label_recipe_sha256=session_start["recipe_sha256"],
        hero_catalog=paths["hero_catalog"], hero_artifacts=paths["hero_artifacts"],
        live_category_contract=paths["live_category_contract"],
        live_category_artifacts=paths["live_category_artifacts"])

coordinator = LiveSession(factory)
summary = stream(coordinator, native_binary_input, semantic_binary_output)
```

`supplied_epochs` represents the caller's explicitly supplied current files;
constructing it or waiting for those files belongs to the transport. Annotation
arguments are optional. Completed acquisition ordinals and segment ordinals are
independent, since acquisition attempts can fail. Health evidence and live
category admission must bind the new acquisition/session/segment even if some
profile bytes or controller keys recur. The factory receives detached copies of
the original native objects. It must return a pristine decoder without feeding
metadata into it; the coordinator performs the epoch admission itself.

For incremental transport, call `coordinator.consume(exact_native_jsonl_bytes)`
and write its result only when non-null. The coordinator requires the original
session start, ordered acquisition start/end, completed acquisition pins and
segment start. It preserves every native event sequence and checks global
session, frequency, monotonic order, lifecycle and frame brackets. The first
native gap must agree with the new epoch's first frame. There are no fabricated
start events or renumbered frames.

Guard invalidation closes the old decoder. Gaps and failed acquisitions emit no
semantic frames; subsequent frames require fresh admission. Reused controllers
can retain their independently observed object keys while acquiring different
body keys, but old body values never transfer. Each output retains its native
sequence, timing and source qualification, and adds `session_epoch` with exact
metadata hashes, acquisition
ordinal, previous epoch's last frame end and `previous_values_carried: false`.
Native terminal unknown frames remain unknown rather than being dropped.

Bounds are 128 acquisition attempts/epochs, 100,000 native events, 512 MiB total
input/output, 512 KiB input lines and 1 MiB output lines. Constructor limit
arguments can lower these caps. Metadata mismatch, stale contracts, factory
failure or budget rejection latch the coordinator closed. `close()` and EOF
report the accepted prefix and whether a native session-end event was seen;
they do not synthesize terminal events or certify recording durability. Already
delivered accepted rows retain their private, non-atomic, non-public qualification.

A session recovery checkpoint
separated a three-epoch saved replay from a connected two-epoch transition and
recorded the measured acquisition gap and exact output hash.

Current generic native profile/transport limits are 160 fields and 512 KiB per
JSONL line; profile/contract metadata stays capped at 256 KiB. See
[capacity evidence and independent limits](../../windows/field-capacity.md).
