# Historical findings and targeted identifiers

These findings summarize surviving project research notes from October 31 through
November 6, 2026, plus the earlier serialized-asset experiment. They describe the
recorded builds and trials. Original captures, screenshots, native-code slices
and complete acquisition recipes are not included in this checkout; this document
does not claim a fresh verification of those unavailable artifacts.

The [field reference](memory-fields.md) describes the implementation that remains.

## Which native code paths were investigated

| Native path | What the investigation was trying to establish |
| --- | --- |
| Entity registry and manager lookup | Locate the current object and check its complete generation-bearing identity. |
| Component membership and owner resolution | Establish that a component belongs to the intended object; readable memory alone was insufficient. |
| Controller/body lookup and reverse lookup | Connect the participant controller to the correct current world body. |
| Current-context selector | Identify the reviewed local context independently of hero name or scan order. |
| Account-token map, collision chain and string route | Resolve an exact 16-byte account token to the associated name record. |
| Hero-resource storage and typed hero assets | Connect fresh resource words to a build-scoped hero label. |
| Health pool getter/accumulation | Determine which occupied pool values contribute to sampled current health and how additions round. |
| Category classifier and its override/mode branches | Interpret category flags only when the reviewed control-flow conditions apply. |
| Resource providers, tagged scalar getters and callbacks | Distinguish base storage, sampled caches and calculated timer/ammunition candidates. |
| Registered key lookup and embedded dispatch | Investigate possible action/state identifiers without assuming they represent firing. |
| Local feedback ring append/lookup/amount consumers | Interpret owned feedback records and associate their full target keys. |
| Health-component incoming context | Test source/recipient identity roles with distinct-actor controls. |

The generic acquisition engine can express supplied address calculations,
lookups and checks. Its [recipe format](../windows/acquisition.md) documents those
mechanics. The corresponding game-specific function addresses, RVAs, component
pointer transforms and complete recipe bytes are absent here. A getter's name or
an observed constant is not enough to recreate that missing route.

## Identifiers preserved in source and notes

### Profile field-name tags

| Tag | Where it survives | Targeted role |
| --- | --- | --- |
| `part36` | [names.py](../tools/entity-decoder/names.py), [account_anchor.py](../tools/entity-decoder/account_anchor.py) | Four-word account-token family. |
| `part51` | [relations.py](../tools/entity-decoder/relations.py), [context_controller.py](../tools/entity-decoder/context_controller.py) | Controller's body-key reference family. |
| `part83` | [hero_labels.py](../tools/entity-decoder/hero_labels.py), [hero_asset_validation.py](../tools/entity-decoder/hero_asset_validation.py) | Controller hero-resource word family. |

These are literal tags retained in the legacy profile naming convention. They
are not byte offsets or portable native-function identifiers. The newer selected
view uses explicit contract-role mappings instead.

### Hero resources and asset codes

The historical reviewed enUS catalogue recorded these mappings:

| Resource GUID | Hero |
| --- | --- |
| `0x02E0000000000003` | Tracer |
| `0x02E0000000000200` | Ashe |
| `0x02E000000000013B` | Ana |

The notes identify runtime dataset `2.25.0.1-154504`, executable SHA-256
`e4472f75a11f035c5854f8eed41c1388878b517ec4f64258316bdcc132e49cd5`, and
separately sourced asset dataset `2.25.0.0-154088`. The differing datasets retain
their own provenance. The Tracer decoded-asset hash was
`fc68c1fc7d9b85c4980b096fec35af9a6740f048bd774f75ee58e0da9308e1aa`.

`0x075` is the decoded asset type checked for a `STUHero` root. The inspected
asset reader followed `m_0EDCE350` to obtain localized hero-name text. That is an
asset reference field, not a live player-name pointer. The catalogue validator
checks the resource's stored type-bit encoding; it does not infer hero names from
small numeric indices. See [hero_labels.py](../tools/entity-decoder/hero_labels.py).

Later notes describe broader typed-asset candidates and additional current-build
calibrations. They do not preserve a complete runnable all-hero catalogue in this
checkout. These three documented GUIDs should not be treated as current-build
compatibility evidence by themselves.

### Serialized movement-field hashes

The separate on-disk component experiment inspected library-decoded
`STUCharacterMoverComponent`, `STUHealthComponent`, `STUWeaponComponent` and
`STUStatescriptComponent` data. Its movement comparison included:

| Serialized field hash | Tracer | Mercy | Reinhardt | Established meaning |
| --- | ---: | ---: | ---: | --- |
| `CFD3E635` | 6 | 5.5 | 5.5 | Unknown. |
| `61D6B4E9` | 5.4 | 4.95 | 4.95 | Unknown. |
| `19452F15` | 6 | 5.5 | 5.5 | Unknown. |
| `1972C687` | 2 | 2 | 2.3 | Unknown. |

The asset build was `2.25.0.0.154088`. These hashes identify serialized fields;
they are not process-memory addresses. Similarity to familiar movement statistics
did not establish speed, direction, units or current player motion. Library
defaults were kept separate from fields actually present in serialized bytes.

### Rejected firing identifiers and raw feedback flags

On executable SHA-256
`4ee4a0dd0798ac8544c74c2a6f771d4e4c4cbe018abeac23f94f2af63b9df0c1`,
one controlled Tracer sequence retained the identifier pair **127 and -4** in all
1,739 frames through idle, firing, reload and melee controls. A registration count
was usually 26 and briefly 27 around melee. Neither scalar distinguished firing.
They were rejected as general firing/shot-count fields.

Separate outgoing-feedback trials observed raw flag bytes **0, 1, 2 and 32**.
Their gameplay meanings were not validated. In one trial the integer record
amounts summed to 201 and differed from the observed target-health decrease.
The decoder must preserve the raw amount/flags rather than invent exact damage,
headshot or kill labels from them.

## What the controlled field experiments established

| Area | Historical evidence | Practical limit |
| --- | --- | --- |
| Identity and body association | Guarded forward/reverse relationships, controlled removal and selected death/respawn trials. Reused storage could carry a different generation. | A matching address, position or repeated endpoint does not establish persistent participant identity. |
| Position | Controlled movement changed the associated XYZ while identity checks held. Later acquisitions covered multiple actors. | Independently sampled partitions are not a simultaneous complete roster. |
| Health | Local HUD comparisons included 175 → 0 → 175. Later pool sums handled changing memberships and additional heroes. | Maximum health, pool roles and causes of changes were not universally resolved. |
| Hero labels | Typed asset roots were paired with separately reviewed HUD/scoreboard evidence. | Unknown resources and unsupported build mappings stay unknown. |
| Categories | Controlled roster/team configurations corroborated the reviewed ordinary native branch. | Other modes, overrides and missing local context need separate evidence. |
| Names | The account-bearing local controller's complete token/string route matched the HUD in a controlled trial. | Bots may lack that component; arbitrary remote-human names were not established generally. |
| Ammunition | A later controlled Tracer template reproduced candidates from two distinct bodies. Ana also had historical numeric copies matching HUD anchors. | A constant capacity-like 40 was rejected as current Tracer ammo. Refills do not establish a reload flag. |

The saved results are evidence for their stated sources and conditions. They do
not establish that every current decoder output has been validated in live games.

## Ability research

| Target | What the notes preserve | Remaining boundary |
| --- | --- | --- |
| Tracer Blink | One guarded-session float matched ten HUD anchors, including charges 3 → 2 → 1 → 0 → 1 → 2 → 3; replenishment was about three seconds. | No portable resource signature or general continuous recharge decoder was established. |
| Tracer Recall | Synchronized trials showed health/ammo restoration; saved-data countdown models were investigated. | Historical fits are not a general current-build cooldown, activation or can-use field. |
| Tracer ultimate / Pulse Bomb | Ready/reset/partial-charge controls rejected direct scalar candidates; resource-provider operands and action pulses were investigated. | A state pulse after an input is not a validated throw, stick, explosion or charge percentage. |
| Ana timers | A recovered counter/timestamp/base/rate formula matched 22 independent HUD countdown checks. A native v4 trial reproduced 10,366 values from 5,183 frames, including attachment during active timers. | This was a particular reviewed layout/build; it had sampling gaps and needed reacquisition after collection changes. |
| Other hero experiments | Earlier Soldier: 76, Zenyatta, Reinhardt and Mercy trials examined movement, ammo, health, ability-associated state and selected resource responses. | Those observations are not additional complete hero implementations in the current decoder. Session-specific conversions do not become universal rules. |

The timer arithmetic remains in [TimerCodec.cs](../windows/Observer/TimerCodec.cs).
The guarded ammunition projection remains in
[ammunition_candidates.py](../tools/entity-decoder/ammunition_candidates.py).
The omitted hero-specific acquisition recipes cannot be recreated merely from
these arithmetic helpers.

## Combat observations

The local outgoing-feedback experiment followed controller-owned circular
storage and the native full-key lookup that consumed its records. Controlled
primary-fire and Pulse Bomb trials supported scoped associations to other bodies.
The integer amount could differ from remaining health, and missed/overwritten
versions remained possible. One record was not promoted to one exact hit.

Incoming research used a separate local health-component context vector. Initial
self-damage controls could not distinguish source and recipient roles. Subsequent
distinct-actor and outgoing-only controls supplied narrower direction evidence.
Supported observations could carry an opposing source's guarded identity, hero,
relative relation and sampled position; unresolved cases stayed unknown.

A health drop, nearby actor, direction cue or retained identity word is
insufficient to identify an attacker. Repeated active context samples are not a
hit count. The repository's generic event/identity transport does not by itself
reconstruct the missing private native adapter or establish general-match damage
attribution.

## Build changes and unavailable inputs

The notes explicitly record a change from executable version `2.25.1.23833` to
`2.25.1.24212`. The old package rejected the new build; later work re-established
specific routes and tested them again. Changing only an expected executable hash
was not a port.

What survives here is the decoder implementation, naming conventions, contracts,
generic reader/codec source and documented findings. What is absent is a complete
ready-to-run build recipe/bundle with its raw route evidence and calibrations.
Content hashes identify those missing artifacts; they do not contain the bytes
needed to recover them.

The historical Windows installation is no longer an available dependency for
this documentation effort. Studying and testing the retained Python source on
Ubuntu does not require it. Any future live-game port needs new build-specific
acquisition and validation work.
