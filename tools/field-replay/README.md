# Local field replay

Open `index.html` directly in a browser, including by double-clicking it on Windows. Keep `index.html`, `style.css`, `model.js` and `app.js` together. No server, installation, network requests, external libraries or telemetry are used. Choose a **compact `overwatch-decoder.field-timeline/1` JSONL export** with the local file picker. Raw recording archives and sparse change timelines are different formats and are rejected.

Playback follows actual frame-start timestamps. Display refresh can skip rendered frames, but every accepted frame remains available through previous/next or the frame slider. The displayed value always belongs to the selected recorded sample; no intermediate value is estimated. A missed scheduled slot or an unknown field breaks the plotted trace. Lines merely connect adjacent observed samples. The full trace is visible, with a marker for the selected sample. Projection axes fit independently; raw units and coordinate meaning are unknown.

Select any declared `f32x3` field and XY, XZ or YZ projection. Scalar and other vector fields remain visible in the sample table. Field names are displayed verbatim as text. No map, entity, hero, view, ability or visibility interpretation is added. Compact exports omit guard and pointer-route evidence: connecting samples does not prove unchanged object identity. Source hashes and exporter labels are shown as provenance, not independently verified raw-recording evidence.

## Bounds and rejection

The parser streams UTF-8 lines and retains every accepted frame. Bounds are 128 MiB input, 512 KiB per line including its newline, 100,000 frames, 160 fields, 1,000,000 field samples, and 32 MiB of retained numeric payload. Object/string overhead is additional and the browser controls total heap memory. Metadata strings, unknown-reason kinds and JSON nesting are also bounded. The entire import fails on a limit; it is never silently truncated or downsampled.

Malformed JSON, duplicate keys, nonfinite numbers, schema/field mismatches, unsafe playback ticks, inconsistent frame/slot/read intervals, count mismatches, missing summary and missing final newline are rejected. All playback/read ticks must be safe JavaScript integers. Legacy v1 exports omit the read-attempt marker; omission is retained as unknown (`null`), even when a timestamp bracket exists. An explicit attempted read requires a bracket. Completion and verification labels must agree; a complete stream inside a failed enclosing recording remains partial. The target's FILETIME identity metadata is not used or retained as a playback tick. Observed finite values are retained without rounding; source hashes identify the raw evidence needed for independent verification. A stopped recording with a valid terminal summary is displayed as partial. An incomplete JSONL file is rejected.

`model.js` exposes pure parsing/model functions as `FieldReplay` in a browser or CommonJS in Node. `parseChunks(asyncIterableOfUint8Array, options)` supports abort, progress and tighter test limits. `Builder`, `frameAtTime`, `joins` and `projection` support portable tests without DOM or file access. No recording data is bundled.

Run tests with an existing Node installation:

```sh
node --test tools/field-replay/model.test.js
```
