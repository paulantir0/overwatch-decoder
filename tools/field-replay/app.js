(function () {
  'use strict';
  const R = window.FieldReplay, $ = id => document.getElementById(id);
  let model = null, selected = 0, projection = null, background = null, playing = false;
  let playWall = 0, playSeconds = 0, raf = 0, importNumber = 0, controller = null;
  const canvas = $('plot'), ctx = canvas.getContext('2d');
  const controls = ['field', 'plane', 'previous', 'play', 'next', 'speed', 'scrub'];
  const format = n => Object.is(n, -0) ? '-0' : String(n);
  const seconds = n => `${n.toFixed(3)} s`;
  function status(message, error = false) { $('message').textContent = message; $('message').classList.toggle('error', error); }
  function pause() { playing = false; cancelAnimationFrame(raf); $('play').textContent = 'Play'; }
  function setControls(enabled) { controls.forEach(id => { $(id).disabled = !enabled; }); }
  function position(point) {
    const [xmin, xmax, ymin, ymax] = projection.bounds;
    const sx = Math.max(1, Math.abs(xmin), Math.abs(xmax)), sy = Math.max(1, Math.abs(ymin), Math.abs(ymax));
    const dx = (xmax / sx - xmin / sx), dy = (ymax / sy - ymin / sy);
    const normx = dx ? (point.x / sx - xmin / sx) / dx : .5;
    const normy = dy ? (point.y / sy - ymin / sy) / dy : .5;
    return [34 + normx * (canvas.width - 68), canvas.height - 34 - normy * (canvas.height - 68)];
  }
  function preparePlot() {
    const ratio = window.devicePixelRatio || 1, box = canvas.getBoundingClientRect();
    canvas.width = Math.max(100, Math.round(box.width * ratio)); canvas.height = Math.max(100, Math.round(box.height * ratio));
    background = document.createElement('canvas'); background.width = canvas.width; background.height = canvas.height;
    const g = background.getContext('2d'); g.fillStyle = '#0d1620'; g.fillRect(0, 0, canvas.width, canvas.height);
    g.strokeStyle = '#1c2c39'; g.lineWidth = 1;
    for (let n = 1; n < 8; n++) { g.beginPath(); g.moveTo(n * canvas.width / 8, 0); g.lineTo(n * canvas.width / 8, canvas.height); g.stroke(); }
    for (let n = 1; n < 6; n++) { g.beginPath(); g.moveTo(0, n * canvas.height / 6); g.lineTo(canvas.width, n * canvas.height / 6); g.stroke(); }
    if (model && $('field').value) {
      projection = R.projection(model, $('field').value, $('plane').value);
      if (projection.bounds) {
        g.strokeStyle = '#4b9b90'; g.lineWidth = 1.5 * ratio; g.beginPath();
        for (const p of projection.points) if (p) { const [x, y] = position(p); if (p.join) g.lineTo(x, y); else g.moveTo(x, y); }
        g.stroke();
        // Isolated observations stay visible even when no path can join them.
        g.fillStyle = '#64b0a1';
        for (const p of projection.points) if (p && !p.join) { const [x, y] = position(p); g.fillRect(x - ratio, y - ratio, ratio * 2, ratio * 2); }
      }
      $('axes').textContent = `${$('plane').value[0]} / ${$('plane').value[1]} raw components · independent axis fit · units unknown`;
    } else projection = null;
    draw();
  }
  function draw() {
    if (background) ctx.drawImage(background, 0, 0);
    const point = projection?.points[selected];
    if (point) { const [x, y] = position(point), ratio = window.devicePixelRatio || 1;
      ctx.beginPath(); ctx.arc(x, y, 7 * ratio, 0, Math.PI * 2); ctx.fillStyle = '#d2ffed'; ctx.fill();
      ctx.strokeStyle = '#18483f'; ctx.lineWidth = 3 * ratio; ctx.stroke(); }
    $('empty').hidden = !!projection?.bounds;
    $('empty').textContent = model ? 'No observed vector samples to project' : 'Your recorded trace appears here';
  }
  function render() {
    if (!model?.frames.length) { draw(); return; }
    const frame = model.frames[selected], f = frame.fields[$('field').value];
    $('scrub').value = selected; $('frame-label').textContent = `${selected + 1} / ${model.frames.length.toLocaleString()}`;
    $('sample-time').textContent = seconds(R.elapsed(model, frame)); $('sample-id').textContent = `Sequence ${frame.sequence} · scheduled slot ${frame.slot}`;
    $('frame-interval').textContent = `${frame.start} → ${frame.end}`;
    $('vector-value').textContent = f?.values ? `[${f.values.map(format).join(', ')}]` : 'Unknown';
    $('vector-status').textContent = f ? (f.status === 'unknown' ? `Unknown · ${f.reason}` : 'Observed sample') : 'No f32x3 field';
    $('read-interval').textContent = f?.start != null ? `${f.start} → ${f.end}\n${((f.end - f.start) * 1000 / model.metadata.frequency).toFixed(4)} ms bracket · attempt flag: ${f.attempted === null ? 'unknown' : String(f.attempted)}` : 'No recorded read interval';
    const next = model.frames[selected + 1];
    const notes = ['Showing this recorded sample only; no value is estimated between reads.'];
    if (frame.skippedBefore) notes.push(`${frame.skippedBefore} missed slots before this sample: trace disconnected.`);
    if (next?.skippedBefore) notes.push(`${next.skippedBefore} missed slots before the next sample (${seconds(R.elapsed(model, next) - R.elapsed(model, frame))} between frame starts).`);
    if (f?.status === 'unknown') notes.push('Unknown value: trace disconnected.');
    $('gap').textContent = notes.join(' ');
    $('previous').disabled = selected === 0; $('next').disabled = selected === model.frames.length - 1;
    $('values').replaceChildren();
    for (const def of model.metadata.fields) {
      const value = frame.fields[def.name], tr = document.createElement('tr');
      for (const content of [def.name, value.status === 'unknown' ? `Unknown · ${value.reason}` : 'Observed', value.values ? `[${value.values.map(format).join(', ')}]` : '—']) {
        const td = document.createElement('td'); td.textContent = content; tr.append(td);
      }
      $('values').append(tr);
    }
    draw();
  }
  function seek(index) { selected = Math.max(0, Math.min(model.frames.length - 1, index)); render(); }
  function tick(now) {
    if (!playing) return;
    const t = playSeconds + (now - playWall) / 1000 * Number($('speed').value);
    const index = R.frameAtTime(model, t); if (index !== selected) seek(index);
    if (t >= R.elapsed(model, model.frames.at(-1))) { pause(); return; }
    raf = requestAnimationFrame(tick);
  }
  $('play').addEventListener('click', () => {
    if (playing) { pause(); return; }
    if (selected === model.frames.length - 1) seek(0);
    playing = true; playWall = performance.now(); playSeconds = R.elapsed(model, model.frames[selected]); $('play').textContent = 'Pause'; raf = requestAnimationFrame(tick);
  });
  $('previous').addEventListener('click', () => { pause(); seek(selected - 1); });
  $('next').addEventListener('click', () => { pause(); seek(selected + 1); });
  $('scrub').addEventListener('input', () => { pause(); seek(Number($('scrub').value)); });
  $('speed').addEventListener('change', pause);
  $('field').addEventListener('change', () => { pause(); preparePlot(); render(); });
  $('plane').addEventListener('change', () => { preparePlot(); render(); });
  window.addEventListener('resize', preparePlot);
  $('file').addEventListener('change', async () => {
    const file = $('file').files[0]; if (!file) return;
    pause(); controller?.abort(); controller = new AbortController(); const ticket = ++importNumber;
    model = null; selected = 0; projection = null; setControls(false); $('field').replaceChildren();
    for (const id of ['sample-time', 'sample-id', 'vector-value', 'vector-status', 'read-interval', 'frame-interval', 'frame-label', 'begin', 'end', 'count', 'missed', 'unknowns', 'completion']) $(id).textContent = '—';
    $('values').replaceChildren(); $('provenance').replaceChildren(); $('scrub').value = 0; $('scrub').max = 0;
    $('gap').textContent = 'Recorded samples only. No interpolation or estimated values.'; preparePlot();
    try {
      if (file.size > R.LIMITS.fileBytes) throw new Error('File exceeds the 128 MiB import limit');
      status(`Reading ${file.name} locally…`); let lastProgress = 0;
      const loaded = await R.parseChunks(file.stream(), { signal: controller.signal, onProgress: p => {
        if (ticket === importNumber && performance.now() - lastProgress > 150) { status(`Reading locally · ${(p.bytes / 1024 / 1024).toFixed(1)} MiB · ${p.frames.toLocaleString()} frames`); lastProgress = performance.now(); }
      } });
      if (ticket !== importNumber) return; model = loaded;
      for (const def of model.metadata.fields.filter(x => x.type === 'f32x3')) { const option = document.createElement('option'); option.value = def.name; option.textContent = def.name; $('field').append(option); }
      setControls(model.frames.length > 0); $('field').disabled = $('plane').disabled = !$('field').options.length;
      $('scrub').max = Math.max(0, model.frames.length - 1); $('scrub').value = 0;
      $('count').textContent = model.frames.length.toLocaleString(); $('missed').textContent = model.summary.skipped.toLocaleString(); $('unknowns').textContent = model.summary.unknownFields.toLocaleString();
      $('completion').textContent = model.summary.complete && model.summary.sourceComplete ? 'Complete export' : 'Stopped / partial';
      $('begin').textContent = model.frames.length ? seconds(R.elapsed(model, model.frames[0])) : 'No frames';
      $('end').textContent = model.frames.length ? seconds(R.elapsed(model, model.frames.at(-1))) : 'No frames';
      $('provenance').replaceChildren();
      const m = model.metadata;
      for (const [key, value] of Object.entries({ File: file.name, Target: m.targetName, 'Observed build SHA256': m.buildHash, 'Source manifest SHA256': m.sourceManifest, 'Profile SHA256': m.profileHash, 'Exporter revision': m.exporterRevision, 'UTC origin': m.utcOrigin, 'Monotonic origin / Hz': `${m.origin} / ${m.frequency}`, 'UTC bracket ticks': `${m.utcBefore} → ${m.origin}`, 'Export verification label': model.summary.verification, 'Stop reason': model.summary.stopReason, 'Trailing missed slots': model.summary.trailingSkipped, 'Retained numeric payload': `${model.numericBytes.toLocaleString()} bytes` })) {
        const dt = document.createElement('dt'), dd = document.createElement('dd'); dt.textContent = key; dd.textContent = String(value); $('provenance').append(dt, dd);
      }
      status(`${file.name} · ${model.frames.length.toLocaleString()} frames retained · no network access`); preparePlot(); render();
    } catch (e) { if (ticket === importNumber) { model = null; setControls(false); status(`Import rejected: ${e.message}`, true); } }
  });
  preparePlot();
})();
