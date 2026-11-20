# Workshop surface samples

`surface_samples.build_sidecar` validates one complete single-origin ray survey and produces `overwatch-decoder.environment-surface-samples/1`. The caller supplies the observed map, mode and game executable SHA-256 and retains the original Inspector capture and rule text. The sidecar binds both original byte streams with SHA-256. Keep it separate from per-frame entity data.

Each ordered sample retains the Workshop-space ray origin, endpoint, returned position and returned normal. A position near the endpoint remains `miss_or_endpoint` because Workshop returns that endpoint on a miss. A normal does not resolve the ambiguity. Near-origin results remain `origin_ambiguous`. An on-segment hit beyond both margins is `surface_hit`. Set the positional tolerance from the source's actual numeric precision, up to 0.25 Workshop units. The validator checks normal length within 0.05 of one and keeps the reported components unchanged.

The sidecar describes sparse first-hit samples. It leaves replay registration unset and visibility unknown. The entity replay viewer can show the points and optional patches when a separate replay envelope binds the build, map, mode and validated coordinate registration. Unsampled space stays unfilled. Repeated controlled surveys are needed to qualify samples as stable environment surfaces.

Run the tests with `python3 -m unittest discover -s tools/environment-geometry`.

## Inspector import

After the match ends and closes the file, keep the original log bytes. Import the exact two-decimal English Inspector format with:

```sh
python3 tools/environment-geometry/import_inspector.py LOG RULE OUTPUT.json \
  --map "Workshop Chamber" --mode Skirmish --build-sha256 GAME_EXE_SHA256
```

The output is an array of survey sidecars. Each survey retains the Inspector elapsed clock at whole-second precision, including separate position and normal log markers. This is not a replay clock. The parser supports one OWD1 smoke record, one 49-ray OWD2 grid, or up to six indexed 49-ray OWD3 grids. It rejects incomplete surveys, unexpected IDs, invalid timestamps, and mismatched map labels. Mode and executable build are supplied from the session evidence. The CLI reserves 0.025 Workshop units for rounding error in the logged endpoints and positions.

## Private Workshop presets

The `presets` directory includes full Custom Game Settings clipboard text for the one-ray smoke test and the repeatable survey. Import one preset into a fresh, invite-only lobby. Both select Skirmish and Workshop Chamber, with one Team 1 slot and zero Team 2 slots. Inspector file logging is a separate client option.

Spawn as host and press Interact while aiming toward the survey area. The repeatable rule captures a 7×7 grid around the initial aim, with 10-degree spacing, 25-unit rays, and a 100 ms wait between ray pairs. It allows six manual activations per match and waits for an Interact release before rearming. Each survey has its own ID. The two ray queries exclude players and player-owned objects. Keep the exact imported preset text with the source log for provenance.

The smoke preset SHA-256 is
`0dc13220dc86348076dba5f53e3562891dc2448b4a1dde415c7b873c5b53556d` and the
repeatable preset SHA-256 is
`9feb5be817c0b6816314c6a48f295a125d2a3689f30a93efbde8c0e01c6f23c1`.
These exact files, with their `OWD` log markers, have not yet been run in-game.
For an existing capture, hash the exact preset bytes used in that match.

### Optional planar patches

Pass `--planar-patches` to add quads referencing existing ray indices in
perimeter order. Each quad uses four adjacent interior hits of a single 7×7
survey. All normalized normals must point in the same direction within a dot
product of 0.999. Pairwise plane errors must stay within 0.03 Workshop units
and the maximum span between any two vertices is 5 Workshop units. Degenerate
or concave cells are omitted. The importer preserves the original rays.

Each quad is labeled `derived_between_samples`. It interpolates only between
those four samples and may still span a small unsampled opening. Treat these
patches as a display schematic with unknown visibility and collision coverage.

### Coordinate registration fixture

The separate `chamber-registration-full.ws.txt` preset is for a controlled,
invite-only registration match. Run the guarded position recorder before
pressing Interact. The rule temporarily forces the host's position and holds
five targets for four seconds each. It logs actual Workshop feet and eye
positions halfway through each hold. The points span all three axes. Keep
the fifth separate as a check on any transform estimated from the other four.

Use the actual logged positions and guarded plateaus to identify pairs. The
`OWDR1 DONE 5` marker follows the action that releases the forced position.
Stay still during the fixture. The player may fall from the last elevated
point after release. End or restart the private match if it must be interrupted.
The rule runs once per match and leaves gravity settings alone.

An earlier version of this fixture passed an exact decompile, compile, and
decompile round trip in OverPy 9.7.20. The current file renames its identifiers
and log markers and has not been re-checked. The registration preset SHA-256 is
`37e0b6b27005d9f3c490499369af352413660605ed21125cd3603dffe276f753`.

## Captured checkpoint, 2026-11-06 UTC

The tested executable SHA-256 was
`5afa5dd173d6c5358c3da6de89b87036c05bc38e8fe9857bf82b40edd80cd096`.
Five completed Workshop Chamber surveys yielded 245 interior surface hits and
126 bounded planar patches. The source Inspector log SHA-256 is
`cd47519af9a7c9f08011174466d4c703370442ea1ee9c9b10f96fd112e6726d1`.
The surveys cover part of a wall and floor, not the whole room.

A separate captured registration run matched the guarded local Tracer position
to the Workshop position at `(0,0,0)`, `(5,0,0)`, `(0,0,5)`, `(0,3,0)` and
`(5,3,5)`. The first four noncoplanar points gave the identity transform. The
held-out fifth point had zero residual at the log's two-decimal precision.
All 895 native frames passed strict verification, and saved full/compact
projections reproduced byte for byte. The private registration evidence SHA-256
is `a0248927149f9545ba5c41e21caf1abd2a4864556d6b71039809cdb5c29fc2c1`.

This validates a sparse schematic in this map on this build. It does not establish
complete geometry, other maps, moving obstacles, destructible state, visibility
or projectile collision. The ordinary match recorder does not automatically
survey maps. Survey in a controlled custom match, retain the map file separately,
and attach it only to a replay with reviewed map/build correspondence.

## Replay attachment

The optional `overwatch-decoder.replay-environment/1` envelope has `replay_source_sha256`,
`observed_build_sha256`, `map`, `mode`, `surveys` (the imported sidecar array),
and `registration`. A reviewed identity registration is represented by
`{"kind":"identity","validation":"controlled_coordinate_pairs","evidence_sha256":"…"}`.
Use the actual retained evidence digest; a hash-shaped string is not validation.

Serve the prepared replay with `tools/entity-replay/serve.py REPLAY.json
--environment ENVIRONMENT.json`. The viewer exposes **Map surfaces** only after
accepting the source-bound file. It draws the recorded hit points and small
patches between adjacent samples without treating them as an occlusion mesh.
