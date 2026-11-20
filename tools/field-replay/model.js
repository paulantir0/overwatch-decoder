/* Local compact-export parser and sample model. No I/O or dependencies. */
(function (root) {
  'use strict';
  const SCHEMA = 'overwatch-decoder.field-timeline/1';
  const LIMITS = Object.freeze({ fileBytes: 128 * 1024 * 1024, lineBytes: 512 * 1024,
    frames: 100000, fields: 160, fieldSamples: 1000000, numericBytes: 32 * 1024 * 1024,
    reasonKinds: 256, textLength: 512, depth: 24 });
  const WIDTH = Object.freeze({ u8: 1, i32: 1, f32: 1, f64: 1, f32x3: 3, f32x4: 4 });
  function check(ok, message) { if (!ok) throw new Error(message); }
  function integer(x, name, min = 0) { check(Number.isSafeInteger(x) && x >= min, `Unsafe or invalid ${name}`); return x; }
  function text(x, name, limit = LIMITS.textLength) { check(typeof x === 'string' && x.length <= limit, `Invalid ${name}`); return x; }
  function object(x) { return x !== null && typeof x === 'object' && !Array.isArray(x); }
  // Reject duplicate keys, invalid JSON and nonfinite numbers before schema validation.
  // Do not treat ignored FILETIME identity metadata as a playback tick.
  function parseJSON(source) {
    let at = 0;
    const ws = () => { while (at < source.length && /[\t\r\n ]/.test(source[at])) at++; };
    function string() {
      const start = at++; let escaped = false;
      while (at < source.length) {
        const ch = source[at++];
        if (!escaped && ch === '"') return JSON.parse(source.slice(start, at));
        if (!escaped && ch === '\\') escaped = true; else escaped = false;
      }
      throw new Error('Unterminated JSON string');
    }
    function value(depth) {
      check(depth <= LIMITS.depth, 'JSON nesting limit exceeded'); ws(); const ch = source[at];
      if (ch === '"') return string();
      if (ch === '{' || ch === '[') {
        const map = ch === '{', end = map ? '}' : ']'; at++; ws();
        const result = map ? Object.create(null) : [];
        if (source[at] === end) { at++; return result; }
        while (true) {
          ws(); let key;
          if (map) { check(source[at] === '"', 'Expected JSON key'); key = string(); ws();
            check(source[at++] === ':', 'Expected colon'); check(!Object.hasOwn(result, key), 'Duplicate JSON key'); }
          const item = value(depth + 1); if (map) result[key] = item; else result.push(item);
          ws(); const next = source[at++]; if (next === end) return result;
          check(next === ',', 'Expected JSON separator');
        }
      }
      for (const [literal, result] of [['true', true], ['false', false], ['null', null]]) {
        if (source.startsWith(literal, at)) { at += literal.length; return result; }
      }
      const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(source.slice(at));
      check(match, 'Invalid JSON value'); check(match[0].length <= 128, 'Numeric token limit exceeded'); at += match[0].length; const number = Number(match[0]);
      check(Number.isFinite(number), 'Nonfinite JSON number');
      // A decimal just beyond the safe integer lattice must not round into a valid tick.
      if (Number.isSafeInteger(number)) {
        const [mantissa, exponent = '0'] = match[0].toLowerCase().split('e');
        const fractional = (mantissa.split('.')[1] || '').length; const power = Number(exponent) - fractional;
        check(Number.isSafeInteger(power) && Math.abs(power) <= 400, 'Lossy integer numeric token');
        const digits = BigInt(mantissa.replace('.', ''));
        const exact = power >= 0 ? digits * (10n ** BigInt(power)) === BigInt(number) : digits === BigInt(number) * (10n ** BigInt(-power));
        check(exact, 'Lossy integer numeric token');
      }
      return number;
    }
    const result = value(0); ws(); check(at === source.length, 'Trailing JSON content'); return result;
  }
  class Builder {
    constructor(limits = LIMITS) {
      this.limits = { ...LIMITS, ...limits }; this.metadata = null; this.frames = []; this.summary = null;
      this.numericBytes = 0; this.unknowns = 0; this.reasons = new Set(); this.lines = 0;
    }
    addNumbers(n) { this.numericBytes += n * 8; check(this.numericBytes <= this.limits.numericBytes, 'Retained numeric-data limit exceeded'); }
    accept(row) {
      this.lines++; check(object(row) && row.schema === SCHEMA, 'Unsupported or mismatched schema');
      check(!this.summary, 'Data after terminal summary');
      if (row.kind === 'metadata') {
        check(!this.metadata && !this.frames.length, 'Metadata must occur exactly once, first');
        check(row.source === 'process_memory' && row.interpretation === 'profile_declared_research' && row.atomic === false && row.public_state_eligible === false, 'Unsupported observation classification');
        check(row.address_traces_included === false, 'Use a compact export without address traces');
        integer(row.monotonic_frequency, 'monotonic frequency', 1); integer(row.monotonic_origin_ticks, 'monotonic origin');
        integer(row.utc_origin_before_ticks, 'UTC bracket'); check(row.utc_origin_before_ticks <= row.monotonic_origin_ticks, 'Invalid UTC bracket');
        check(Number.isFinite(row.requested_interval_ms) && row.requested_interval_ms > 0, 'Invalid requested interval');
        const interval = row.requested_interval_ms * row.monotonic_frequency / 1000;
        integer(interval, 'scheduled tick interval', 1);
        check(Array.isArray(row.fields) && row.fields.length > 0 && row.fields.length <= this.limits.fields, 'Field limit exceeded');
        const names = new Set();
        const fields = row.fields.map(f => {
          check(object(f) && Object.hasOwn(WIDTH, f.type), 'Unsupported field type'); text(f.name, 'field name', 160);
          check(f.name.length > 0 && !names.has(f.name), 'Duplicate or empty field name'); names.add(f.name);
          check((f.min == null || Number.isFinite(f.min)) && (f.max == null || Number.isFinite(f.max)) && (f.min == null || f.max == null || f.min <= f.max), 'Invalid field range');
          return { name: f.name, type: f.type, min: f.min, max: f.max };
        });
        text(row.utc_origin, 'UTC origin'); check(Number.isFinite(Date.parse(row.utc_origin)), 'Invalid UTC origin');
        this.metadata = { fields, frequency: row.monotonic_frequency, origin: row.monotonic_origin_ticks,
          utcBefore: row.utc_origin_before_ticks, utcOrigin: row.utc_origin, interval,
          sourceManifest: text(row.source_manifest_sha256, 'source manifest hash', 64),
          profileHash: text(row.profile_sha256, 'profile hash', 64),
          buildHash: text(row.target?.executable_sha256, 'observed build hash', 64),
          targetName: text(row.target?.image_name, 'target name'),
          exporterRevision: text(row.exporter_revision, 'exporter revision', 128) };
        for (const key of ['sourceManifest', 'profileHash', 'buildHash']) check(/^[a-f0-9]{64}$/i.test(this.metadata[key]), 'Invalid provenance hash');
        this.addNumbers(5 + fields.length * 2); return;
      }
      check(this.metadata, 'Missing metadata');
      if (row.kind === 'summary') {
        integer(row.frames, 'summary frame count'); integer(row.unknown_fields, 'summary unknown count'); integer(row.skipped_intervals, 'summary missed slots');
        check(row.frames === this.frames.length && row.unknown_fields === this.unknowns, 'Summary counts disagree');
        const skipped = this.frames.at(-1)?.skippedTotal || 0;
        check(row.skipped_intervals >= skipped, 'Summary missed slots disagree');
        check(typeof row.complete === 'boolean' && typeof row.source_recording_complete === 'boolean', 'Invalid completeness');
        check(row.complete === (row.stop_reason === 'duration_elapsed'), 'Completion and stop reason disagree');
        check(!row.source_recording_complete || row.complete, 'Source completeness disagrees');
        check(row.source_verification_status === (row.source_recording_complete ? 'verified_complete' : 'verified_stopped'), 'Verification and completeness disagree');
        this.summary = { complete: row.complete, sourceComplete: row.source_recording_complete,
          frames: row.frames, unknownFields: row.unknown_fields, skipped: row.skipped_intervals,
          trailingSkipped: row.skipped_intervals - skipped, stopReason: text(row.stop_reason, 'stop reason'),
          verification: text(row.source_verification_status, 'source verification label') };
        this.addNumbers(5); return;
      }
      check(row.kind === 'frame', 'Unexpected record kind');
      check(this.frames.length < this.limits.frames, 'Frame limit exceeded');
      check((this.frames.length + 1) * this.metadata.fields.length <= this.limits.fieldSamples, 'Field-sample limit exceeded');
      for (const key of ['sequence', 'scheduled_slot', 'scheduled_ticks', 'start_ticks', 'end_ticks', 'jitter_ticks', 'skipped_intervals_before', 'skipped_intervals_total']) integer(row[key], key);
      const previous = this.frames.at(-1), m = this.metadata;
      check(row.sequence === this.frames.length, 'Nonconsecutive frame sequence');
      check(row.scheduled_slot === (previous ? previous.slot + 1 : 0) + row.skipped_intervals_before, 'Missed-slot discontinuity');
      check(row.skipped_intervals_total === row.scheduled_slot - row.sequence, 'Incorrect cumulative missed slots');
      const scheduled = m.origin + row.scheduled_slot * m.interval; integer(scheduled, 'computed scheduled ticks');
      check(row.scheduled_ticks === scheduled && row.start_ticks >= scheduled && row.end_ticks >= row.start_ticks && row.jitter_ticks === row.start_ticks - scheduled, 'Invalid frame timing');
      check(Math.floor((row.start_ticks - m.origin) / m.interval) === row.scheduled_slot && (!previous || row.start_ticks >= previous.end), 'Frame timing order mismatch');
      check(object(row.fields) && Object.keys(row.fields).length === m.fields.length, 'Field set mismatch');
      const fields = Object.create(null);
      for (const def of m.fields) {
        const f = row.fields[def.name]; check(object(f) && f.type === def.type, 'Field type or name mismatch');
        check(f.status === 'observed' || f.status === 'unknown', 'Invalid field status');
        // Legacy v1 exports omit this marker. Timing alone does not prove a source.Read attempt.
        const attempted = f.read_attempted === undefined ? null : f.read_attempted;
        check(attempted === true || attempted === false || attempted === null, 'Invalid read-attempt marker');
        const a = f.read_start_ticks, b = f.read_end_ticks;
        if (a === null || b === null) check(a === null && b === null, 'Incomplete read interval');
        else { integer(a, 'read start'); integer(b, 'read end'); check(row.start_ticks <= a && a <= b && b <= row.end_ticks, 'Read outside frame'); }
        check(attempted !== true || a !== null, 'Attempted read lacks an interval');
        let reason = null, values = null;
        if (f.status === 'observed') {
          check(f.reason === null && a !== null && attempted !== false, 'Observed field lacks read evidence');
          check(f.read_error === undefined || f.read_error === null, 'Observed field has read error');
          values = WIDTH[def.type] === 1 ? [f.value] : f.value;
          check(Array.isArray(values) && values.length === WIDTH[def.type] && values.every(x => typeof x === 'number' && Number.isFinite(x)), 'Invalid numeric field value');
          if (def.type === 'u8') check(Number.isInteger(values[0]) && values[0] >= 0 && values[0] <= 255, 'Invalid u8 value');
          if (def.type === 'i32') check(Number.isInteger(values[0]) && values[0] >= -2147483648 && values[0] <= 2147483647, 'Invalid i32 value');
          check(values.every(x => (def.min == null || x >= def.min) && (def.max == null || x <= def.max)), 'Observed value outside declared range');
        } else {
          check(f.value === null, 'Unknown field contains a value'); reason = text(f.reason, 'unknown reason', 256); check(reason.length, 'Missing unknown reason');
          this.reasons.add(reason); check(this.reasons.size <= this.limits.reasonKinds, 'Unknown-reason limit exceeded'); this.unknowns++;
        }
        fields[def.name] = { status: f.status, values, reason, start: a, end: b, attempted };
        this.addNumbers(2 + (values?.length || 0));
      }
      this.frames.push({ sequence: row.sequence, slot: row.scheduled_slot, scheduled: row.scheduled_ticks,
        start: row.start_ticks, end: row.end_ticks, jitter: row.jitter_ticks,
        skippedBefore: row.skipped_intervals_before, skippedTotal: row.skipped_intervals_total, fields });
      this.addNumbers(8);
    }
    finish() { check(this.metadata && this.summary, 'Truncated export: metadata and summary required'); return { metadata: this.metadata, frames: this.frames, summary: this.summary, numericBytes: this.numericBytes }; }
  }
  async function parseChunks(chunks, options = {}) {
    const limits = { ...LIMITS, ...options.limits }; const builder = new Builder(limits);
    const decoder = new TextDecoder('utf-8', { fatal: true }); let pending = '', bytes = 0, line = 0;
    function consume(part, final = false) {
      pending += part;
      let end;
      while ((end = pending.indexOf('\n')) !== -1) {
        const raw = pending.slice(0, end); pending = pending.slice(end + 1); line++;
        check(new TextEncoder().encode(raw).length + 1 <= limits.lineBytes, `Line ${line}: byte limit exceeded`);
        check(raw.trim().length, `Line ${line}: blank lines are not supported`);
        try { builder.accept(parseJSON(raw)); } catch (e) { throw new Error(`Line ${line}: ${e.message}`); }
      }
      check(pending.length <= limits.lineBytes && new TextEncoder().encode(pending).length <= limits.lineBytes, 'Line byte limit exceeded');
      if (final) check(!pending.length, 'Truncated export: final newline required');
    }
    for await (const chunk of chunks) {
      check(!options.signal?.aborted, 'Import cancelled'); check(chunk instanceof Uint8Array, 'Expected byte stream');
      bytes += chunk.byteLength; check(bytes <= limits.fileBytes, 'File byte limit exceeded');
      // Slice unusually large caller chunks so pending decoded text remains bounded.
      for (let at = 0; at < chunk.length; at += 65536) consume(decoder.decode(chunk.subarray(at, at + 65536), { stream: true }));
      options.onProgress?.({ bytes, frames: builder.frames.length });
    }
    consume(decoder.decode(), true); check(!options.signal?.aborted, 'Import cancelled'); return builder.finish();
  }
  function elapsed(model, frame) { return (frame.start - model.metadata.origin) / model.metadata.frequency; }
  function frameAtTime(model, seconds) {
    const frames = model.frames; if (!frames.length) return -1;
    let lo = 0, hi = frames.length;
    while (lo < hi) { const mid = Math.floor((lo + hi) / 2); if (elapsed(model, frames[mid]) <= seconds) lo = mid + 1; else hi = mid; }
    return Math.max(0, lo - 1);
  }
  function joins(previous, current, field) {
    return !!previous && current.slot === previous.slot + 1 && current.skippedBefore === 0 && previous.fields[field]?.status === 'observed' && current.fields[field]?.status === 'observed';
  }
  function projection(model, name, plane = 'XZ') {
    const def = model.metadata.fields.find(x => x.name === name); check(def?.type === 'f32x3', 'Projection requires f32x3');
    const axes = { XY: [0, 1], XZ: [0, 2], YZ: [1, 2] }[plane]; check(axes, 'Invalid projection plane');
    let xmin = Infinity, xmax = -Infinity, ymin = Infinity, ymax = -Infinity;
    const points = model.frames.map((frame, i) => {
      const f = frame.fields[name]; if (f.status !== 'observed') return null;
      const x = f.values[axes[0]], y = f.values[axes[1]]; xmin = Math.min(xmin, x); xmax = Math.max(xmax, x); ymin = Math.min(ymin, y); ymax = Math.max(ymax, y);
      return { x, y, join: joins(model.frames[i - 1], frame, name) };
    });
    return { points, axes, bounds: Number.isFinite(xmin) ? [xmin, xmax, ymin, ymax] : null };
  }
  const api = { LIMITS, SCHEMA, parseJSON, Builder, parseChunks, elapsed, frameAtTime, joins, projection };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.FieldReplay = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
