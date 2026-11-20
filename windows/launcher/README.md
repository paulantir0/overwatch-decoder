# Windows practice recorder launcher

Put `Record practice.cmd` beside the standalone `overwatch-decoder-observer.exe` and a supported
private acquisition recipe named `private-recipe.json`. The repository supplies
the generic launcher, not a game recipe. A desktop delivery must identify the
specific build, hero and fields its private recipe supports.

Start the supported Practice Range session, then double-click the launcher. It
selects exactly one process matching the recipe's image name and records for up
to ten minutes at a requested 20 ms interval. The executable checks the actual
process identity and exact build before reading fields. The launcher does not
start the game, send inputs, infer a hero or change permissions.

The console prints the new recording directory and the adjacent `.live.jsonl`
file under `%LOCALAPPDATA%\OverwatchDecoder\recordings`. JSON lines are written there while the
recorder runs. The directory contains the session manifest, acquisitions and
guarded recording segments. Unknowns, missed slots and reacquisition gaps remain
explicit. Check the session manifest for completion or failure, and strictly
verify each segment before treating saved samples as intact.

For a shorter run, use a duration from 1 to 600 seconds:

```bat
"Record practice.cmd" 30
```

`OVERWATCH_DECODER_LAUNCH_NO_PAUSE=1` disables the final console pause for scripted invocation.
It does not change recording duration or validation. Ctrl+C requests an early
stop; forcibly closing the window can lose the pending recording chunk.

The live stream is private research, not a complete game-state reconstruction.
See the
[live JSON contract](../acquisition.md).

The launcher entry point was exercised through Windows `cmd.exe`: a two-second
game observation wrote 64 frames to both the live file and a strictly verified
segment, then exited successfully. An invalid duration rejected before starting
the observer. This checks command execution and output, not an interactive
Explorer double-click or general support for other private recipes.

The later desktop delivery at source revision
`51405a2f9aa30f2bc9a68435f7c3221836c81bd6` contains the Ana-gated fourteen-field
private recipe. Its installed launcher was invoked through Windows `cmd.exe` for
three seconds: 99 live/raw frames, one terminal unknown per field, two missed
scheduled slots, strict segment verification and successful exit. All delivered
file hashes were read back and checked.
