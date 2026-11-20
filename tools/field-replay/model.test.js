'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const R = require('./model.js');
function metadata() { return { schema: R.SCHEMA, kind: 'metadata', source: 'process_memory', interpretation: 'profile_declared_research', atomic: false, public_state_eligible: false, address_traces_included: false, monotonic_frequency: 1000, monotonic_origin_ticks: 1000, utc_origin_before_ticks: 999, requested_interval_ms: 10, utc_origin: '2026-01-01T00:00:00Z', source_manifest_sha256: 'a'.repeat(64), profile_sha256: 'b'.repeat(64), exporter_revision: 'test', target: { image_name: '<script>unsafe</script>', executable_sha256: 'c'.repeat(64), creation_file_time: 123456789012345678 }, fields: [{ name: 'raw μ vector', type: 'f32x3', min: -100, max: 100 }] }; }
function frame(sequence, slot = sequence, skipped = 0, unknown = false) {
  const t = 1000 + slot * 10;
  return { schema: R.SCHEMA, kind: 'frame', sequence, scheduled_slot: slot, scheduled_ticks: t, start_ticks: t + 1, end_ticks: t + 2, jitter_ticks: 1, skipped_intervals_before: skipped, skipped_intervals_total: slot - sequence, fields: { 'raw μ vector': { type: 'f32x3', status: unknown ? 'unknown' : 'observed', value: unknown ? null : [sequence, -0, 3], reason: unknown ? 'guard_failed' : null, read_attempted: !unknown, read_start_ticks: unknown ? null : t + 1, read_end_ticks: unknown ? null : t + 2 } } };
}
function summary(frames) { return { schema: R.SCHEMA, kind: 'summary', frames: frames.length, unknown_fields: frames.filter(x => x.fields['raw μ vector'].status === 'unknown').length, skipped_intervals: frames.at(-1)?.skipped_intervals_total || 0, complete: true, source_recording_complete: true, stop_reason: 'duration_elapsed', source_verification_status: 'verified_complete' }; }
function bytes(rows) { return new TextEncoder().encode(rows.map(x => JSON.stringify(x)).join('\n') + '\n'); }
async function* chunks(data, size = 7) { for (let i = 0; i < data.length; i += size) yield data.subarray(i, i + size); }
async function load(frames, options = {}, meta = metadata()) { return R.parseChunks(chunks(bytes([meta, ...frames, summary(frames)])), options); }
function reject(rows, pattern, options) { return assert.rejects(R.parseChunks(chunks(bytes(rows)), options), pattern); }

test('retains every frame, exact brackets, signed zero and raw names; UTF8 split across chunks', async () => {
  const m = await load([frame(0), frame(1)]);
  assert.equal(m.frames.length, 2); assert.equal(m.frames[1].fields['raw μ vector'].start, 1011);
  assert.equal(m.metadata.targetName, '<script>unsafe</script>');
  assert.equal(R.parseJSON('-0'), -0); assert.equal(m.metadata.origin, 1000);
});
test('unknowns and missed slots break joins; no interpolation and all samples accessible', async () => {
  const frames = [frame(0), frame(1, 1, 0, true), frame(2, 2), frame(3, 5, 2), frame(4, 6)];
  const m = await load(frames), p = R.projection(m, 'raw μ vector', 'XZ');
  assert.deepEqual(p.points.map(x => x && x.join), [false, null, false, false, true]);
  assert.equal(R.frameAtTime(m, .049), 2); assert.equal(R.frameAtTime(m, .051), 3); assert.equal(R.frameAtTime(m, 100), 4);
  assert.equal(m.summary.skipped, 2); assert.equal(m.summary.unknownFields, 1);
});
test('stopped/partial and empty exports retain their status', async () => {
  const s = summary([]); s.complete = false; s.source_recording_complete = false; s.stop_reason = 'cancelled'; s.source_verification_status = 'verified_stopped';
  const m = await R.parseChunks(chunks(bytes([metadata(), s])));
  assert.equal(m.summary.complete, false); assert.equal(R.frameAtTime(m, 0), -1);
});
test('all projection planes and constant axes', async () => {
  const m = await load([frame(0), frame(1)]);
  assert.deepEqual(R.projection(m, 'raw μ vector', 'XY').bounds, [0, 1, 0, 0]);
  assert.deepEqual(R.projection(m, 'raw μ vector', 'YZ').points[0], { x: 0, y: 3, join: false });
});
test('rejects duplicate JSON keys, nonfinite numbers, invalid syntax and deep nesting', () => {
  for (const s of ['{"a":1,"a":2}', '1e400', 'NaN', '{"a":}', '[1,]', 'true false', '"bad\nstring"', '['.repeat(30) + '0' + ']'.repeat(30)]) assert.throws(() => R.parseJSON(s));
  assert.equal(R.parseJSON('{"__proto__":{"x":1}}').__proto__.x, 1); assert.equal({}.x, undefined);
});
test('rejects schema/type/field-set/count mismatches and duplicate metadata', async () => {
  let f = frame(0); f.schema = 'other'; await reject([metadata(), f, summary([f])], /schema/);
  f = frame(0); f.fields['raw μ vector'].type = 'f32x4'; await reject([metadata(), f, summary([f])], /type/);
  f = frame(0); f.fields.extra = f.fields['raw μ vector']; await reject([metadata(), f, summary([f])], /Field set/);
  const s = summary([frame(0)]); s.frames = 2; await reject([metadata(), frame(0), s], /counts/);
  await reject([metadata(), metadata(), summary([])], /Metadata/);
  const meta = metadata(); meta.fields.push(meta.fields[0]); await reject([meta, summary([])], /Duplicate/);
});
test('rejects unsafe ticks, missing read evidence, wrong slot accounting and numeric ranges', async () => {
  let f = frame(0); f.start_ticks = 9007199254740992; await reject([metadata(), f, summary([f])], /Unsafe/);
  f = frame(0); f.fields['raw μ vector'].read_start_ticks = null; await reject([metadata(), f, summary([f])], /Incomplete/);
  f = frame(0); f.fields['raw μ vector'].read_end_ticks = 9000; await reject([metadata(), f, summary([f])], /outside/);
  f = frame(0); f.skipped_intervals_before = 1; await reject([metadata(), f, summary([f])], /slot/);
  f = frame(0); f.fields['raw μ vector'].value[0] = 101; await reject([metadata(), f, summary([f])], /range/);
  f = frame(0, 0, 0, true); f.fields['raw μ vector'].value = [0, 0, 0]; await reject([metadata(), f, summary([f])], /Unknown/);
});
test('file, line, frame, field-sample and numeric retention bounds reject whole import', async () => {
  await assert.rejects(load([frame(0)], { limits: { fileBytes: 50 } }), /File byte/);
  await assert.rejects(load([frame(0)], { limits: { lineBytes: 50 } }), /Line/);
  await assert.rejects(load([frame(0), frame(1)], { limits: { frames: 1 } }), /Frame limit/);
  await assert.rejects(load([frame(0)], { limits: { fieldSamples: 0 } }), /Field-sample/);
  await assert.rejects(load([frame(0)], { limits: { numericBytes: 56 } }), /numeric-data/);
  await assert.rejects(load([], { limits: { fields: 0 } }), /Field limit/);
});
test('truncation, invalid UTF8, extra records and cancellation reject', async () => {
  await assert.rejects(R.parseChunks(chunks(bytes([metadata(), frame(0)]))), /Truncated/);
  const complete = bytes([metadata(), summary([])]); await assert.rejects(R.parseChunks(chunks(complete.subarray(0, complete.length - 1))), /newline/);
  await assert.rejects(R.parseChunks(chunks(new Uint8Array([255, 10]))), /encoded data|encoding/i);
  await reject([metadata(), summary([]), frame(0)], /after terminal/);
  const c = new AbortController(); c.abort(); await assert.rejects(load([], { signal: c.signal }), /cancelled/);
});

test('u8 supports exact byte fields and rejects fractional/out-of-range values', async () => {
  const meta = metadata(); meta.fields[0] = { name: 'raw μ vector', type: 'u8', min: 0, max: 255 };
  const f = frame(0); f.fields['raw μ vector'].type = 'u8'; f.fields['raw μ vector'].value = 255;
  assert.deepEqual((await load([f], {}, meta)).frames[0].fields['raw μ vector'].values, [255]);
  for (const value of [-1, 256, 1.5]) { f.fields['raw μ vector'].value = value; await assert.rejects(load([f], {}, meta), /u8/); }
});
test('preserves signed zero in the complete import and rejects rounded fractional tick tokens', async () => {
  const rows = [metadata(), frame(0), summary([frame(0)])];
  const data = new TextDecoder().decode(bytes(rows)).replace('[0,0,3]', '[0,-0,3]');
  const m = await R.parseChunks(chunks(new TextEncoder().encode(data)));
  assert.ok(Object.is(m.frames[0].fields['raw μ vector'].values[1], -0));
  assert.throws(() => R.parseJSON('9007199254740991.1'), /Lossy/);
  assert.throws(() => R.parseJSON('1e-999'), /Lossy/);
  assert.equal(R.parseJSON('1.000e3'), 1000);
});

test('legacy v1 omitted attempt marker remains unknown for observed and timed terminal-unknown fields', async () => {
  const meta = metadata(); meta.source_profile_schema = 'overwatch-decoder.field-profile/1'; meta.source_stream_schema = 'overwatch-decoder.field-stream/1';
  const observed = frame(0), terminal = frame(1, 1, 0, true);
  delete observed.fields['raw μ vector'].read_attempted; delete terminal.fields['raw μ vector'].read_attempted;
  terminal.fields['raw μ vector'].reason = 'cancelled';
  terminal.fields['raw μ vector'].read_start_ticks = 1011; terminal.fields['raw μ vector'].read_end_ticks = 1012;
  const end = summary([observed, terminal]); end.complete = false; end.source_recording_complete = false; end.stop_reason = 'cancelled'; end.source_verification_status = 'verified_stopped';
  const m = await R.parseChunks(chunks(bytes([meta, observed, terminal, end])));
  assert.equal(m.frames[0].fields['raw μ vector'].attempted, null);
  assert.equal(m.frames[1].fields['raw μ vector'].attempted, null);
  assert.equal(m.frames[1].fields['raw μ vector'].start, 1011);
  assert.equal(m.frames[1].fields['raw μ vector'].status, 'unknown');
  assert.deepEqual(R.projection(m, 'raw μ vector').points.map(p => p && p.join), [false, null]);
  for (const invalid of [0, 1, 'true', {}, []]) { observed.fields['raw μ vector'].read_attempted = invalid; await reject([meta, observed, summary([observed])], /read-attempt/); }
});
test('rejects impossible attempted-read and completion declarations; retains enclosing-recording failure', async () => {
  const f = frame(0, 0, 0, true); f.fields['raw μ vector'].read_attempted = true; await reject([metadata(), f, summary([f])], /lacks an interval/);
  const good = frame(0); let end = summary([good]); end.source_verification_status = 'verified_stopped'; await reject([metadata(), good, end], /Verification/);
  end = summary([good]); end.stop_reason = 'cancelled'; await reject([metadata(), good, end], /stop reason/);
  // A complete stream can belong to a failed enclosing recording; exporter uses the verifier's label.
  end = summary([good]); end.source_recording_complete = false; end.source_verification_status = 'verified_stopped';
  const m = await R.parseChunks(chunks(bytes([metadata(), good, end]))); assert.equal(m.summary.sourceComplete, false); assert.equal(m.summary.complete, true);
});

test('reviewed field and line capacities retain all data and reject one over', async () => {
  for (const count of [128, 129, 160]) {
    const meta = metadata(); meta.fields = Array.from({ length: count }, (_, i) => ({ name: 'field_' + i, type: 'i32' }));
    const model = await R.parseChunks(chunks(bytes([meta, summary([])]), 65536));
    assert.equal(model.metadata.fields.length, count);
  }
  const meta = metadata(); meta.fields = Array.from({ length: 161 }, (_, i) => ({ name: 'field_' + i, type: 'i32' }));
  await reject([meta, summary([])], /Field limit/);
  for (const length of [256 * 1024 + 1, 512 * 1024]) {
    const first = JSON.stringify(metadata()); const line = first + ' '.repeat(length - 1 - new TextEncoder().encode(first).length);
    const data = new TextEncoder().encode(line + '\n' + JSON.stringify(summary([])) + '\n');
    const model = await R.parseChunks(chunks(data, 65536));
    assert.equal(model.frames.length, 0);
    await assert.rejects(R.parseChunks(chunks(data, 65536), { limits: { fileBytes: data.length - 1 } }), /File byte/);
  }
  const first = JSON.stringify(metadata());
  await assert.rejects(R.parseChunks(chunks(new TextEncoder().encode(first + ' '.repeat(512 * 1024 - new TextEncoder().encode(first).length) + '\n'), 65536)), /Line/);
});
