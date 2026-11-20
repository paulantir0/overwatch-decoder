# Chamber outgoing-hit control

Import `chamber-outgoing-hit-full.ws.txt` into a fresh invite-only Custom
Game lobby. Select Tracer on Team 1. After spawning, press the Interact
binding once. The rule creates one Team 2 Ashe dummy, disables both of
her fire buttons, and holds both players three units apart. It logs
`OWDH1 READY` with actual positions after the dummy spawns.

Start any validation collectors before firing. Wait for collector readiness
and confirm the target visually. Fire a short burst with Tracer's normal
weapon. Ashe has ordinary health, so avoid killing her during the control.
The preset supplies no attack inputs or scripted damage.

The Inspector records a pair of lines for each qualifying Player Dealt Damage
or Player Took Damage event, with separate counters for each event kind.
The lines carry event damage, attacker and victim references, hero labels,
and positions. These are Workshop references rather than native full keys.
Inspector timestamps use its own elapsed clock. The two event kinds may
report the same damage and must not be counted as distinct hits. Each counter
caps at 64, at which point the log may omit later events.

The fixture ends 60 seconds after READY. It stops forcing the host position
and destroys the dummy, then logs `OWDH1 DONE` with both counts. End or
restart the private match to interrupt or reset the test. Enable Inspector
file logging separately, and retain the original private log after the match
closes it.

An earlier version of this preset decompiled, compiled, and decompiled back to
identical source under OverPy 9.7.20. The current file renames its identifiers
and has not been re-checked. SHA-256
`65e061cea1de7768976ba1b760ea5de6ccd423eb064f24da73ea1e19c1c16d59`.
In-game operation must be verified from the READY, event and DONE records.
