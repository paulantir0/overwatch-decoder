/* Dependency-free canvas renderer for local, private recorded-object research. */
"use strict";
const $ = (id) => document.getElementById(id);
const canvas = $("scene"),
  ctx = canvas.getContext("2d"),
  coverage = $("coverage");
const M = globalThis.OverwatchDecoderReplay;
const E = globalThis.OverwatchDecoderReplayEvidence;
const G = globalThis.OverwatchDecoderReplayEnvironment;
let evidence = null,
  evidenceError = "";
let environment = null;
let chunkIndex = null, loadedChunk = -1, loadingChunk = -1, chunkRequest = 0, chunkAbort = null;
const failedChunks = new Set();
let rosterModel = null;
let model,
  time = 0,
  playing = false,
  speed = 1,
  selected = null,
  dirty = true;
let lastTick = 0,
  lastUI = 0,
  listSignature = "",
  width = 1,
  height = 1,
  hitTargets = [],
  labels = [],
  figureBounds = [];
const camera = {
  yaw: -0.5,
  pitch: 0.73,
  scale: 3,
  center: [0, 0, 0],
  top: false,
};
let CYAN = "#62e8d0";
const video = $("gameplay"),
  keys = new Set();
let videoConfig = null,
  videoError = false,
  playPending = false,
  initialOffset = 0;
let videoOffset = 0,
  userLabels = new Map();
let gridY = -5;
let lastActiveState = null;
let selectedController = null, selectedSelf = false;
let povManualLook = false, freeCamera = null, activePov = null;
let healthBursts=[], healthScales=new Map();
let ALLY_BLUE="#64aaff", ENEMY_RED="#ff6477", UNKNOWN_GRAY="#8995a7";
const sceneTheme = {};
function refreshTheme() {
  const css = getComputedStyle(document.documentElement);
  const value = (name, fallback) => {
    const color = css.getPropertyValue(name).trim();
    return /^#[a-f0-9]{6}$/i.test(color) ? color : fallback;
  };
  CYAN = value("--team-self", "#62e8d0");
  ALLY_BLUE = value("--team-ally", "#64aaff");
  ENEMY_RED = value("--team-enemy", "#ff6477");
  UNKNOWN_GRAY = value("--team-unknown", "#8995a7");
  for (const [name, fallback] of Object.entries({
    bg: "#0b1017", grid: "#1d2936", "grid-major": "#314653",
    text: "#e5f5ff", muted: "#577184", selection: "#e9fffc", "block-fill": "#1d2c40",
  })) sceneTheme[name] = value(`--scene-${name}`, fallback);
  sceneTheme.gap = value("--timeline-gap", "#080e15");
  sceneTheme.window = value("--timeline-window", "#1b2c3a");
  sceneTheme.recorded = value("--timeline-recorded", "#345d60");
  dirty = true;
  listSignature = "";
  if (model) { updateUI(true); drawCoverage(); }
}
document.addEventListener("overwatch-decoder-theme-change", refreshTheme);
refreshTheme();
function cameraPov(state) {
  const mode=$("camera-mode").value;
  return mode==="self" ? M.povPreview(state) : mode==="selected" && selected!==null ? M.povPreview(state,1.6,selected) : null;
}
function videoReady() {
  return !!videoConfig && !videoError && Number.isFinite(video.duration);
}
function replayEnd() {
  // A shared excerpt is deliberately cut to usable observations. Encoded video
  // may include one extra frame interval; it must not restore the removed tail.
  if (model?.data.shared_excerpt === true) return model.data.end_seconds;
  return Math.max(
    chunkIndex?.end_seconds ?? model?.end ?? 0,
    videoReady() ? video.duration + videoOffset : 0,
  );
}
function updateDuration() {
  if (!model) return;
  $("time").max = replayEnd();
  $("duration").textContent = "/ " + M.formatTime(replayEnd(), 0);
  $("timeline-end").textContent = M.formatTime(replayEnd(), 0);
  drawCoverage();
}
function syncVideo(seek = false) {
  if (!videoReady() || !model) return;
  const target = M.videoTime(time, videoOffset, video.duration);
  $("video-message").hidden = target.available;
  $("video-message").textContent =
    time < videoOffset
      ? "Video has not started at this time"
      : "End of recorded video";
  video.playbackRate = speed;
  if (!playing || !target.available) video.pause();
  if (seek && Math.abs(video.currentTime - target.t) > 0.001)
    video.currentTime = target.t;
  if (playing && target.available && video.paused && !playPending) {
    playPending = true;
    video
      .play()
      .catch((error) => {
        if (error.name !== "AbortError") {
          playing = false;
          $("video-message").hidden = false;
          $("video-message").textContent =
            "Video playback paused. Press Play to retry.";
          updateUI(true);
        }
      })
      .finally(() => {
        playPending = false;
      });
  }
}
video.addEventListener("loadedmetadata", () => {
  updateDuration();
  syncVideo(true);
  dirty = true;
  updateUI(true);
});
video.addEventListener("ended", () => {
  time = Math.min(replayEnd(), videoOffset + video.duration);
  if (time >= replayEnd()) playing = false;
  dirty = true;
  updateUI(true);
});
video.addEventListener("error", () => {
  videoError = true;
  $("video-message").hidden = false;
  $("video-message").textContent =
    "Video could not be decoded. Coordinate replay is still available.";
  updateDuration();
});
$("video-offset").onchange = () => {
  const value = Number($("video-offset").value);
  if (!Number.isFinite(value) || Math.abs(value) > 3600) {
    $("video-offset").value = videoOffset;
    return;
  }
  videoOffset = value;
  updateDuration();
  setTime(time);
  $("sync-note").textContent =
    "Manual offset · alignment has not been independently verified.";
};
$("reset-sync").onclick = () => {
  videoOffset = initialOffset;
  $("video-offset").value = videoOffset.toFixed(3);
  updateDuration();
  setTime(time);
  showSyncNote();
};
$("expand-map").onclick = () => {
  const expanded = $("comparison").classList.toggle("map-expanded");
  $("expand-map").textContent = expanded ? "Split view" : "Expand";
  $("expand-map").setAttribute("aria-pressed", String(expanded));
  resize();
};
function showSyncNote() {
  const kind = videoConfig?.alignment;
  const name = kind === "motion_calibrated" ? "Calibrated to the video" :
    kind === "recorder_clock_bounded" ? "Conditional recorder clock" :
    kind === "unavailable" ? "Alignment unavailable" : "Estimated alignment";
  $("sync-note").textContent = name +
    (Number.isFinite(videoConfig?.uncertainty_seconds)
      ? ` · ${kind === "motion_calibrated" ? "practical uncertainty" : "source-clock bracket"} ±${videoConfig.uncertainty_seconds.toFixed(2)} s`
      : "") + ". Adjust to compare the same movement.";
  $("sync-note").title = [videoConfig?.method, videoConfig?.scope].filter(Boolean).join(" · ");
}
async function loadEnvironment(config) {
  if (config?.url !== "/environment.json" || !G) return;
  try {
    const response = await fetch(config.url, { cache: "no-store" });
    if (!response.ok || Number(response.headers.get("Content-Length")) > G.MAX_DOCUMENT_BYTES) return;
    const reader = response.body.getReader();
    const decoder = new TextDecoder("utf-8", { fatal: true });
    let size = 0, json = "";
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > G.MAX_DOCUMENT_BYTES) {
          await reader.cancel();
          return;
        }
        json += decoder.decode(value, { stream: true });
      }
      json += decoder.decode();
    } finally {
      reader.releaseLock();
    }
    const data = G.create(JSON.parse(json), chunkIndex?.source_sha256 ?? model.data.source_sha256);
    if (!data.points.length) return;
    environment = data;
    $("map-surfaces-control").hidden = false;
    $("map-surfaces-note").hidden = false;
    const patchNote = data.patches.length ? " Shaded patches span nearby hits." : "";
    $("map-surfaces-note").textContent = `${data.map} · ${data.points.length} sampled hits.${patchNote} Visibility and collision coverage are unknown.`;
    dirty = true;
  } catch (error) {
    console.warn("Map surfaces unavailable", error.message);
  }
}
async function loadMedia() {
  try {
    const response = await fetch("/media.json", { cache: "no-store" });
    if (!response.ok) return;
    const metadata = await response.json();
    void loadEnvironment(metadata.environment);
    if (metadata.labels) {
      try {
        evidence = E.create(metadata.labels, chunkIndex?.source_sha256 ?? model.data.source_sha256);
        buildRoster();
      } catch (error) {
        evidenceError = `Labels unavailable: ${error.message}`;
        $("roster-panel").hidden = false;
        $("roster-title").textContent = evidenceError;
        $("save-labels").disabled = true;
      }
    }
    const notes = metadata.annotations;
    if (notes?.source_sha256 === (chunkIndex?.source_sha256 ?? model.data.source_sha256)) {
      userLabels = new Map(notes.objects.map((o) => [o.key, o.label]));
    }
    if (
      metadata.video?.url === "/gameplay.mp4" &&
      Number.isFinite(metadata.video.start_seconds)
    ) {
      videoConfig = metadata.video;
      videoOffset = initialOffset = videoConfig.start_seconds;
      $("video-offset").value = videoOffset.toFixed(3);
      $("video-panel").hidden = false;
      $("comparison").classList.add("has-video");
      showSyncNote();
      video.src = videoConfig.url;
      video.load();
      resize();
      fit();
    }
    updateUI(true);
  } catch {
    /* Optional media never prevents opening the coordinates. */
  }
}
function identityFor(p, state = current()) {
  return E.identityAt(
    evidence,
    model.data.objects[p?.[0]]?.key,
    p?.[4] === true,
    time,
    !!p && state.active,
  );
}
function sampleHero(p, state = current()) {
  if (!p) return null;
  const hero = M.observationFields(state, p[0])?.hero;
  return typeof hero?.value === "string" && hero.validation_status &&
    hero.validation_status !== "unknown" ? hero.value : null;
}
function objectTitle(p, state = current()) {
  if (!p) return null;
  const identity = identityFor(p, state);
  if (identity.fields.player_name)
    return `${String(p[0] + 1).padStart(2, "0")} · ${identity.fields.player_name}`;
  const hero = sampleHero(p, state);
  return (p[4] ? "You · " : "") + (hero ? `${hero} · ` : "") + model.data.objects[p[0]].label;
}
function lastSeen(identity) {
  if (!evidence || !identity.fields.player_name) return null;
  return (
    E.rosterAt(evidence, time - videoOffset).find(
      (row) =>
        row.player_name.toLowerCase() ===
        identity.fields.player_name.toLowerCase(),
    ) ?? null
  );
}
function downloadJSON(value, name) {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(value, null, 2) + "\n"], {
      type: "application/json",
    }),
  );
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function reviewLink(videoSeconds, label, title) {
  const button = document.createElement("button");
  button.textContent = label;
  button.title = title;
  button.onclick = () => setTime(videoSeconds + videoOffset);
  return button;
}
function buildRoster() {
  const groups = new Map();
  for (const row of evidence.observations) {
    const key = row.player_name.toLowerCase();
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(row);
  }
  $("roster-title").textContent =
    `${groups.size} players identified in the video`;
  $("roster-panel").hidden = false;
  $("roster-list").replaceChildren();
  for (const rows of groups.values()) {
    rows.sort((a, b) => a.video_seconds - b.video_seconds);
    const card = document.createElement("div");
    card.className = "roster-card";
    const title = document.createElement("strong");
    title.textContent = rows[0].player_name;
    const team = document.createElement("span");
    team.textContent = rows.some((r) => r.team === "self")
      ? "You"
      : rows[0].team;
    team.className = "roster-team " + rows[0].team;
    card.append(title, team);
    const changes = document.createElement("div");
    changes.className = "evidence-links";
    let lastHero = null;
    for (const row of rows) {
      if (row.hero === lastHero && !row.retrospective) continue;
      changes.append(
        reviewLink(
          row.video_seconds,
          `${row.hero} · ${M.formatTime(row.video_seconds, 0)}${row.retrospective ? " (recap)" : ""}`,
          typeof row.evidence === "string" ? row.evidence : "Video observation",
        ),
      );
      if (!row.retrospective) lastHero = row.hero;
    }
    card.append(changes);
    $("roster-list").append(card);
  }
}
$("save-labels").onclick = () =>
  downloadJSON(evidence, "replay-video-labels.json");
$("save-frame").onclick = () => {
  const state = rawCurrent();
  downloadJSON(
    {
      schema: "overwatch-decoder.private-labeled-frame/1",
      public_state_eligible: false,
      source_sha256: hasCurrentWindow() ? model.data.source_sha256 : chunkIndex?.source_sha256,
      session_seconds: time,
      video: {
        seconds: time - videoOffset,
        offset_seconds: videoOffset,
        alignment:
          videoOffset === initialOffset
            ? (videoConfig?.alignment ?? "unavailable")
            : "manual_unverified",
        initial_calibration: videoConfig,
      },
      sample: state.active
        ? {
            epoch: state.frame.epoch,
            sequence: state.frame.sequence,
            seconds: state.frame.t,
            ...(state.frame.roster_source_id && {
              roster_source_id: state.frame.roster_source_id,
              roster_source_tick: state.frame.roster_source_tick,
              source_session_id: state.frame.source_session_id,
              source_segment: state.frame.source_segment,
              source_read_bracket: state.frame.source_read_bracket,
              multi_source_snapshot: false,
            }),
            provenance: model.data.epochs.find(
              (e) => e.id === state.frame.epoch,
            ),
          }
        : null,
      objects: state.objects.map((p) => ({
        key: model.data.objects[p[0]].key,
        object_id: p[0] + 1,
        self_association: p[4],
        position: { x: p[1], y: p[2], z: p[3] },
        identity: identityFor(p, state),
        recorded_fields: M.observationFields(state, p[0]),
        last_video_observation: lastSeen(identityFor(p, state)),
        self_health_candidate:
          p[4] === true ? M.selfHealthCandidate(state) : null,
        rotation_candidate:
          state.rotations.find((q) => q[0] === p[0])?.slice(1) ?? null,
        position_read_ticks:
          state.frame.reads?.find((r) => r[0] === p[0])?.slice(1) ?? null,
      })),
      note: "Original recorded samples only; display smoothing is not exported as an observation. Names require scoped video matches; hero observations are historical. No visibility inferred.",
    },
    `replay-frame-${time.toFixed(3)}.json`,
  );
};
function color(p) {
  const team = M.relationCategory(current(),p[0]) ?? identityFor(p).fields.team;
  return p[4] === true
    ? CYAN
    : team === "ally"
      ? ALLY_BLUE
      : team === "opponent" || team === "enemy"
        ? ENEMY_RED
        : UNKNOWN_GRAY;
}
function currentHealth(state, objectIndex) {
  const health = M.observationFields(state, objectIndex)?.health;
  return health?.validation_status === "current_build_native_current_health_pool_sum" &&
    Number.isFinite(health.value) ? health.value : null;
}
function playerLabel(p) {
  const id = p[4] ? "You" : String(p[0] + 1).padStart(2, "0");
  if (!$("player-labels").checked) return id;
  const health = currentHealth(current(), p[0]);
  return [p[4] ? id : sampleHero(p) ?? id, health === null ? null : `${Math.ceil(health)} HP`]
    .filter(Boolean).join(" · ");
}
function cancelChunkLoad() {
  if (loadingChunk < 0) return;
  chunkRequest++;
  loadingChunk = -1;
  chunkAbort?.abort();
  chunkAbort = null;
}
function hasCurrentWindow() {
  return !chunkIndex || (loadedChunk >= 0 && M.chunkAt(chunkIndex, time) === loadedChunk);
}
async function requestChunk(atTime, initial = false) {
  if (!chunkIndex) return;
  const index = initial ? 0 : M.chunkAt(chunkIndex, atTime);
  if (index < 0 || index === loadedChunk || failedChunks.has(index)) {
    if (loadingChunk !== index) cancelChunkLoad();
    return;
  }
  if (index === loadingChunk) return;
  cancelChunkLoad();
  const request = ++chunkRequest;
  loadingChunk = index;
  chunkAbort = new AbortController();
  try {
    const entry = chunkIndex.chunks[index];
    const response = await fetch(entry.url, {cache:"no-store", signal:chunkAbort.signal});
    if (!response.ok) throw new Error(`Chunk unavailable (${response.status}).`);
    const bytes = await response.arrayBuffer();
    if (bytes.byteLength !== entry.bytes || bytes.byteLength > 128*1024*1024) throw new Error("Chunk byte bound or size mismatch.");
    const actual = [...new Uint8Array(await crypto.subtle.digest("SHA-256",bytes))].map((b)=>b.toString(16).padStart(2,"0")).join("");
    if (actual !== entry.sha256) throw new Error("Replay chunk digest mismatch.");
    const next = M.create(JSON.parse(new TextDecoder().decode(bytes)));
    if (chunkIndex.repeat_windows === true && (next.data.source_sha256 !== entry.source_sha256 ||
        next.data.epochs.length !== 1 || next.data.epochs[0].id !== `window-${String(entry.recorder_window).padStart(4,"0")}`))
      throw new Error("Replay chunk source or window mismatch.");
    if (chunkIndex.overlapping_windows === true) M.validateOverlapChunk(chunkIndex, entry, next.data);
    if (request !== chunkRequest || (!initial && M.chunkAt(chunkIndex, time) !== index)) return;
    loadedChunk = index;
    useRosterModel(next);
    healthBursts=M.healthDepletions(model);
    healthScales=M.observedHealthScales(model);
    // Window-scoped IDs cannot identify a selected opponent in the next window.
    if ($("camera-mode").value === "selected") leavePov();
    gridY = model.data.bounds?.min?.[1] ?? -5;
    selected = model.data.frames[0]?.objects.find((p)=>p[4]===true)?.[0] ?? model.data.frames[0]?.objects[0]?.[0] ?? model.data.objects[0]?.index;
    selectedController = null;
    selectedSelf = model.data.frames[0]?.objects.find((p)=>p[0]===selected)?.[4] === true;
    listSignature = "";
    $("total-objects").textContent=modelObjectCount();
    $("total-frames").textContent=model.data.frames.length.toLocaleString();
    $("sample-rate").textContent = model.updateInterval ? `${Math.round(1 / model.updateInterval)} Hz` : "Unknown";
    $("damage-events").dataset.key="";
    dirty=true; drawCoverage();
    if (!initial) { fit(); updateUI(true); }
  } catch(error) {
    if (request !== chunkRequest || error.name === "AbortError") return;
    failedChunks.add(index);
    if (initial) throw error;
    dirty = true;
  } finally {
    if (request === chunkRequest) { loadingChunk=-1; chunkAbort=null; }
  }
}
function useRosterModel(next) {
  rosterModel = next.data.multi_source_snapshot === false ? next : null;
  $("roster-source-control").hidden = !rosterModel;
  model = rosterModel ? M.selectRoster(rosterModel, $("roster-source").value) : next;
}
function modelObjectCount() {
  if (!rosterModel) return model.data.objects.length;
  return model.data.objects.filter(o=>o.roster_source_id===$("roster-source").value).length;
}
$("roster-source").onchange = () => {
  if (!rosterModel) return;
  model = M.selectRoster(rosterModel, $("roster-source").value);
  if ($("camera-mode").value === "selected") leavePov();
  selected = null;
  selectedController = null;
  selectedSelf = false;
  healthBursts = M.healthDepletions(model);
  healthScales = M.observedHealthScales(model);
  listSignature = "";
  $("total-objects").textContent = modelObjectCount();
  $("total-frames").textContent = model.data.frames.length.toLocaleString();
  $("sample-rate").textContent = model.updateInterval ? `${Math.round(1 / model.updateInterval)} Hz` : "Unknown";
  dirty = true;
  fit();
  drawCoverage();
  updateUI(true);
};
function nextAvailable() {
  const current = hasCurrentWindow() ? M.nextObserved(model,time) : null;
  const nextWindow = chunkIndex?.chunks.find((chunk,i)=>chunk.start_seconds>time && !failedChunks.has(i))?.start_seconds;
  return current===null ? nextWindow ?? null : Math.min(current,nextWindow ?? Infinity);
}
function rawCurrent() {
  return chunkIndex ? M.indexSample(chunkIndex, loadedChunk, model, time) : M.sampleAt(model, sampleTime());
}
function sampleTime() {
  // Keep the final recorded sample inspectable after a trimmed clip finishes.
  // Exported sample timestamps continue to identify its actual acquisition.
  return model?.data.shared_excerpt === true && time >= replayEnd()
    ? model.data.frames.at(-1).t : time;
}
function maintainSelection(state) {
  // Preserve the user's selection preference, never an old actor's fields.
  const chosen = state.objects.find((p) => p[0] === selected);
  if (chosen) {
    selectedSelf = chosen[4] === true;
    selectedController = M.observationFields(state, chosen[0])?.controller_id ?? null;
    return;
  }
  const matches = state.objects.filter((p) => selectedSelf ? p[4] === true :
    selectedController && M.observationFields(state, p[0])?.controller_id === selectedController);
  if (matches.length === 1) selected = matches[0][0];
}
function current() {
  const at = sampleTime();
  return $("smooth-motion").checked && hasCurrentWindow() ? M.playbackAt(model, at) :
    at !== time ? M.sampleAt(model, at) : rawCurrent();
}
function setTime(t, pause = true) {
  time = Math.max(0, Math.min(replayEnd(), t));
  void requestChunk(time);
  if (pause) playing = false;
  syncVideo(true);
  dirty = true;
  updateUI(true);
}
function project(pos) {
  const dx = pos[0] - camera.center[0],
    dy = pos[1] - camera.center[1],
    dz = pos[2] - camera.center[2];
  const cs = Math.cos(camera.yaw),
    sn = Math.sin(camera.yaw);
  const sx = dx * cs - dz * sn,
    depth = dx * sn + dz * cs;
  const pitch = camera.top ? Math.PI / 2 : camera.pitch;
  const focal = height / (2 * Math.tan(Math.PI / 6));
  const distance = focal / camera.scale;
  const z = distance - (depth * Math.cos(pitch) + dy * Math.sin(pitch));
  const scale = camera.top ? camera.scale : focal / Math.max(0.25, z);
  return [
    width / 2 + sx * scale,
    height / 2 + (depth * Math.sin(pitch) - dy * Math.cos(pitch)) * scale,
    depth * Math.cos(pitch) + dy * Math.sin(pitch),
    camera.top ? distance : z,
  ];
}
function line3D(a, b, stroke, lineWidth = 1) {
  let pa = project(a),
    pb = project(b);
  const near = 0.26;
  if (pa[3] < near && pb[3] < near) return;
  if (pa[3] < near) {
    const t = (near - pa[3]) / (pb[3] - pa[3]);
    a = a.map((v, i) => v + (b[i] - v) * t);
    pa = project(a);
  } else if (pb[3] < near) {
    const t = (near - pb[3]) / (pa[3] - pb[3]);
    b = b.map((v, i) => v + (a[i] - v) * t);
    pb = project(b);
  }
  path([pa, pb], stroke, lineWidth);
}
function eyePosition() {
  const distance = height / (2 * Math.tan(Math.PI / 6)) / camera.scale,
    pitch = camera.top ? Math.PI / 2 : camera.pitch;
  return [
    camera.center[0] + Math.sin(camera.yaw) * Math.cos(pitch) * distance,
    camera.center[1] + Math.sin(pitch) * distance,
    camera.center[2] + Math.cos(camera.yaw) * Math.cos(pitch) * distance,
  ];
}
function lookFrom(eye) {
  const distance = height / (2 * Math.tan(Math.PI / 6)) / camera.scale;
  camera.center = [
    eye[0] - Math.sin(camera.yaw) * Math.cos(camera.pitch) * distance,
    eye[1] - Math.sin(camera.pitch) * distance,
    eye[2] - Math.cos(camera.yaw) * Math.cos(camera.pitch) * distance,
  ];
}
function panCamera(dx, dy) {
  const pitch = camera.top ? Math.PI / 2 : camera.pitch,
    s = camera.scale;
  camera.center[0] +=
    (-dx * Math.cos(camera.yaw) - dy * Math.sin(camera.yaw) * Math.sin(pitch)) /
    s;
  camera.center[2] +=
    (dx * Math.sin(camera.yaw) - dy * Math.cos(camera.yaw) * Math.sin(pitch)) /
    s;
  camera.center[1] += (dy * Math.cos(pitch)) / s;
  $("follow").checked = false;
}
function resize() {
  const box = canvas.getBoundingClientRect(),
    dpr = Math.min(devicePixelRatio || 1, 2);
  width = box.width;
  height = box.height;
  canvas.width = Math.round(width * dpr);
  canvas.height = Math.round(height * dpr);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  dirty = true;
  drawCoverage();
}
function fit(userAction = false) {
  if ($("camera-mode").value !== "free") {
    if (userAction) leavePov(); else return;
  }
  if (!model) return;
  if (Math.abs(Math.sin(camera.pitch)) < 0.2) camera.pitch = 0.55;
  const state = current(),
    points = state.objects.map((p) => p.slice(1, 4));
  if (environment && $("map-surfaces").checked) points.push(...environment.points);
  if (!points.length) return;
  camera.center = [0, 1, 2].map((axis) => {
    const vals = points.map((p) => p[axis]).sort((a, b) => a - b);
    return axis === 1
      ? vals[Math.floor(vals.length / 2)]
      : (vals[0] + vals.at(-1)) / 2;
  });
  camera.scale = 1;
  const projected = points.map(project);
  const xs = projected.map((p) => p[0]),
    ys = projected.map((p) => p[1]);
  const extentX = Math.max(...xs) - Math.min(...xs) + 16;
  const extentY = Math.max(...ys) - Math.min(...ys) + 18;
  const horizontal = (Math.min(...xs) + Math.max(...xs)) / 2 - width / 2;
  const depth =
    ((Math.min(...ys) + Math.max(...ys)) / 2 - height / 2) /
    Math.sin(camera.top ? Math.PI / 2 : camera.pitch);
  camera.center[0] +=
    horizontal * Math.cos(camera.yaw) + depth * Math.sin(camera.yaw);
  camera.center[2] +=
    -horizontal * Math.sin(camera.yaw) + depth * Math.cos(camera.yaw);
  camera.scale = Math.max(
    0.4,
    Math.min(16, (width - 110) / extentX, (height - 125) / extentY),
  );
  // Perspective can widen near objects; fit their actual projected extents.
  for (let i = 0; i < 16; i++) {
    const screen = points.map(project);
    if (
      screen.every(
        (p) =>
          p[3] > 1 &&
          p[0] > 40 &&
          p[0] < width - 40 &&
          p[1] > 55 &&
          p[1] < height - 55,
      )
    )
      break;
    camera.scale *= 0.85;
  }
  $("follow").checked = false;
  dirty = true;
}
function path(points, stroke, lineWidth = 1, fill = null) {
  if (points.some((p) => p.length >= 4 && p[3] < 0.25)) return;
  ctx.beginPath();
  points.forEach((p, i) =>
    i ? ctx.lineTo(p[0], p[1]) : ctx.moveTo(p[0], p[1]),
  );
  if (fill) {
    ctx.closePath();
    ctx.fillStyle = fill;
    ctx.fill();
  }
  if (stroke) {
    ctx.strokeStyle = stroke;
    ctx.lineWidth = lineWidth;
    ctx.stroke();
  }
}
function drawMapSurfaces() {
  if (!environment || !$("map-surfaces").checked) return;
  const color = sceneTheme.muted;
  for (const patch of environment.patches) path(patch.map(project), color + "60", 1, color + "22");
  ctx.fillStyle = color + "a0";
  for (const hit of environment.points) {
    const [x, y, , depth] = project(hit);
    if (depth >= 0.25 && x >= 0 && x <= width && y >= 0 && y <= height)
      ctx.fillRect(x - 1, y - 1, 2, 2);
  }
}
function grid() {
  const plane = gridY;
  const radius = Math.min(2000, Math.max(80, width / camera.scale));
  const spacing = camera.scale < 1 ? 50 : camera.scale < 2.5 ? 20 : 10;
  const x0 = Math.floor((camera.center[0] - radius) / spacing) * spacing;
  const z0 = Math.floor((camera.center[2] - radius) / spacing) * spacing;
  const endX = camera.center[0] + radius,
    endZ = camera.center[2] + radius;
  for (let x = x0; x <= endX; x += spacing)
    line3D([x, plane, z0], [x, plane, endZ], x === 0 ? sceneTheme["grid-major"] : sceneTheme.grid);
  for (let z = z0; z <= endZ; z += spacing)
    line3D([x0, plane, z], [endX, plane, z], z === 0 ? sceneTheme["grid-major"] : sceneTheme.grid);
  ctx.font = "11px ui-monospace, monospace";
  ctx.fillStyle = sceneTheme.muted;
  ctx.fillText(`Reference grid · Y ${gridY.toFixed(1)} · ${spacing} units`, 18, height - 72);
  const origin = [width - 48, height - 69],
    base = project(camera.center);
  const axes = [
    [12, 0, 0, "X", ENEMY_RED],
    [0, 12, 0, "Y", CYAN],
    [0, 0, 12, "Z", ALLY_BLUE],
  ];
  for (const [x, y, z, label, c] of axes) {
    const endpoint = project(camera.center.map((v, i) => v + [x, y, z][i]));
    let ex = ((endpoint[0] - base[0]) / camera.scale) * 1.8,
      ey = ((endpoint[1] - base[1]) / camera.scale) * 1.8;
    if (camera.top && label === "Y") {
      ex = 3;
      ey = -4;
    }
    path([origin, [origin[0] + ex, origin[1] + ey]], c, 1.5);
    ctx.fillStyle = c;
    ctx.fillText(label, origin[0] + ex + 4, origin[1] + ey + 3);
  }
}
function figure(p, selectedNow, state) {
  const pos = p.slice(1, 4), c = color(p);
  // Illustrative dimensions; modest enlargement keeps distant figures legible.
  const r = activePov ? 0.36 : Math.max(0.55, Math.min(1.6, 6 / camera.scale));
  const headCenter = [pos[0], pos[1] + r * 2.95, pos[2]], headRadius = r * 0.72;
  const center = project(pos), top = project([pos[0], pos[1] + r * 3.7, pos[2]]);
  if (center[3] < 0.3 || top[3] < 0.3) return;
  const faces = [], sides = 12;
  const addFace = (points, shade) => {
    const projected = points.map(project);
    if (projected.some(v => v[3] < 0.3)) return;
    faces.push({points:projected, depth:projected.reduce((sum,v)=>sum+v[2],0)/projected.length, shade});
  };
  const ring = (y, radius) => Array.from({length:sides}, (_,i) => {
    const a=i*Math.PI*2/sides;
    return [pos[0]+Math.cos(a)*radius, y, pos[2]+Math.sin(a)*radius];
  });
  const base=ring(pos[1]+r*0.08,r), shoulder=ring(pos[1]+r*2.2,r*0.82);
  for(let i=0;i<sides;i++) {
    const j=(i+1)%sides;
    addFace([base[i],base[j],shoulder[j],shoulder[i]],0.62+0.2*Math.cos(i*Math.PI*2/sides-0.7));
  }
  addFace(shoulder,0.93);
  const sphere=(lat,lon)=>[headCenter[0]+headRadius*Math.cos(lat)*Math.cos(lon),
    headCenter[1]+headRadius*Math.sin(lat),headCenter[2]+headRadius*Math.cos(lat)*Math.sin(lon)];
  for(let row=0;row<6;row++) for(let i=0;i<sides;i++) {
    const a=-Math.PI/2+row*Math.PI/6,b=a+Math.PI/6,l=i*Math.PI*2/sides,m=(i+1)*Math.PI*2/sides;
    addFace([sphere(a,l),sphere(a,m),sphere(b,m),sphere(b,l)],0.76+0.18*Math.sin(b)+0.06*Math.cos(l));
  }
  const rotation=state.rotations.find(q=>q[0]===p[0]);
  const forward=rotation ? M.candidateForward(rotation.slice(1)) : null;
  if(forward) {
    let right=[forward[2],0,-forward[0]],norm=Math.hypot(...right);
    right=norm<0.01 ? [1,0,0] : right.map(v=>v/norm);
    const up=[forward[1]*right[2]-forward[2]*right[1],forward[2]*right[0]-forward[0]*right[2],forward[0]*right[1]-forward[1]*right[0]];
    const noseRing=(distance,radius)=>Array.from({length:8},(_,i)=>headCenter.map((v,j)=>
      v+forward[j]*distance+(right[j]*Math.cos(i*Math.PI/4)+up[j]*Math.sin(i*Math.PI/4))*radius));
    const start=noseRing(headRadius*0.8,r*0.24),tip=noseRing(r*1.45,r*0.045);
    for(let i=0;i<8;i++){const j=(i+1)%8;addFace([start[i],start[j],tip[j],tip[i]],1.12);}
    addFace(tip,1.22);
    canvas.dataset.facingCount=String(Number(canvas.dataset.facingCount)+1);
  }
  const shadeColor=(shade)=>{
    const rgb=[1,3,5].map(i=>parseInt(c.slice(i,i+2),16));
    return '#'+rgb.map(v=>Math.round(Math.max(0,Math.min(255,v*shade))).toString(16).padStart(2,'0')).join('');
  };
  if ($("height-guides").checked) {
    const foot=[pos[0],gridY,pos[2]];
    ctx.setLineDash([3,4]);line3D(foot,pos,c+"88",1);ctx.setLineDash([]);
    const rim=Array.from({length:17},(_,i)=>[pos[0]+Math.cos(i*Math.PI/8)*r,gridY,pos[2]+Math.sin(i*Math.PI/8)*r]);
    for(let i=0;i<16;i++)line3D(rim[i],rim[i+1],c+"44");
  }
  if(selectedNow || p[4]) {
    const rim=Array.from({length:25},(_,i)=>[pos[0]+Math.cos(i*Math.PI/12)*r*1.4,pos[1]+0.02,pos[2]+Math.sin(i*Math.PI/12)*r*1.4]);
    for(let i=0;i<24;i++)line3D(rim[i],rim[i+1],selectedNow ? sceneTheme.selection : c,1.5);
  }
  for(const face of faces.sort((a,b)=>a.depth-b.depth))path(face.points,null,0,shadeColor(face.shade));
  const silhouette=faces.flatMap(face=>face.points);
  if(silhouette.length) figureBounds.push({
    left:Math.min(...silhouette.map(v=>v[0]))-6,
    right:Math.max(...silhouette.map(v=>v[0]))+6,
    top:Math.min(...silhouette.map(v=>v[1]))-6,
    bottom:Math.max(...silhouette.map(v=>v[1]))+6,
  });
  const health=$("player-labels").checked ? M.healthBar(state,p[0],healthScales) : null;
  const elevation=$("height-guides").checked ? M.referenceHeight(p,gridY) : null;
  labels.push({text:playerLabel(p),health,elevation,x:top[0],y:top[1],
    priority:p[4] ? 2 : selectedNow ? 1 : 0,color:c});
  hitTargets.push({index:p[0],x:(center[0]+top[0])/2,y:(center[1]+top[1])/2,
    radius:Math.max(13,Math.abs(top[1]-center[1])*0.55,r*camera.scale*1.5)});
  canvas.dataset.figureCount=String(Number(canvas.dataset.figureCount)+1);
}
function drawHealthBurst(event) {
  const age=time-event.time;if(age<0 || age>=0.9)return;
  const fade=1-age/0.9,c=event.point[4] ? CYAN : event.relation==="ally" ? ALLY_BLUE : event.relation==="enemy" ? ENEMY_RED : UNKNOWN_GRAY;
  ctx.save();ctx.globalAlpha=fade;
  const base=event.point.slice(1,4);
  for(let i=0;i<18;i++) {
    const angle=i*2.3999632297+event.object, speed=2+(i%5)*0.65;
    const pos=[base[0]+Math.cos(angle)*age*speed,base[1]+0.8+age*(2+i%3)-3*age*age,base[2]+Math.sin(angle)*age*speed];
    const projected=project(pos);if(projected[3]<0.3)continue;
    const size=Math.min(12,Math.max(2,height*0.12/projected[3]))*fade;
    ctx.save();ctx.translate(projected[0],projected[1]);ctx.rotate(angle+age*(i%2?5:-5));
    ctx.fillStyle=c;ctx.fillRect(-size/2,-size/2,size,size);ctx.restore();
  }
  const label=project([base[0],base[1]+2.3+age,base[2]]);
  if(label[3]>0.3){ctx.fillStyle=c;ctx.font="600 12px system-ui";ctx.textAlign="center";ctx.fillText("0 HP",label[0],label[1]);}
  ctx.restore();
}
function drawSelfSightline(state) {
  canvas.dataset.sightlineCount="0";
  canvas.dataset.sightlineMode="off";
  if($("self-sightline").getAttribute("aria-pressed")!=="true")return;
  const samples=M.facingSamples(state,"self");
  if(samples.length!==1)return;
  const {point,forward}=samples[0];
  const selfPov=activePov?.object===point[0];
  const radius=activePov ? 0.36 : Math.max(0.55,Math.min(1.6,6/camera.scale));
  const eye=[point[1],point[2]+(selfPov ? 1.6 : radius*2.95),point[3]];
  const distance=Math.min(100,Math.max(35,...state.objects.map(p=>Math.hypot(p[1]-point[1],p[2]-point[2],p[3]-point[3])+8)));
  const start=eye.map((v,i)=>v+forward[i]*radius*1.45);
  const end=eye.map((v,i)=>v+forward[i]*distance);
  ctx.save();ctx.lineCap="round";
  if(selfPov){
    // Show the recorded direction without introducing a false muzzle offset.
    // It projects to the center in tracked POV and moves when manually looking.
    const target=project(end);
    if(target[3]>0.26){
      ctx.beginPath();ctx.arc(target[0],target[1],3,0,Math.PI*2);
      ctx.strokeStyle=sceneTheme.bg;ctx.lineWidth=3;ctx.stroke();
      ctx.fillStyle=CYAN;ctx.fill();
      canvas.dataset.sightlineCount="1";
      canvas.dataset.sightlineMode="pov-dot";
    }
  }else{
    line3D(start,end,sceneTheme.bg+"cc",5);
    line3D(start,end,CYAN,2.5);
    canvas.dataset.sightlineCount="1";
    canvas.dataset.sightlineMode="world-ray";
  }
  ctx.restore();
}
function render() {
  if (width < 1 || height < 1) return;
  ctx.clearRect(0, 0, width, height);
  hitTargets = [];
  labels = [];
  figureBounds = [];
  if (!model) return;
  const state = current(),
    self = state.objects.find((p) => p[4] === true);
  maintainSelection(state);
  const pov = cameraPov(state);
  activePov=pov;
  canvas.dataset.povObject=pov ? String(pov.object) : "";
  if (pov) {
    camera.top=false;
    if (pov.forward && !povManualLook) {
      camera.yaw=Math.atan2(-pov.forward[0],-pov.forward[2]);
      camera.pitch=-Math.asin(Math.max(-1,Math.min(1,pov.forward[1])));
    }
    lookFrom(pov.eye);
  }
  // Follow horizontally: following Y too would cancel the visible jump.
  if (!pov && $("follow").checked && self) { camera.center[0] = self[1]; camera.center[2] = self[3]; }
  canvas.dataset.displayObjects = JSON.stringify(state.objects);
  canvas.dataset.heightGuideCount = $("height-guides").checked ? String(state.objects.length) : "0";
  grid();
  drawMapSurfaces();
  canvas.dataset.facingCount = "0";
  canvas.dataset.figureCount = "0";
  canvas.dataset.healthBarCount = "0";
  canvas.dataset.healthBurstCount="0";
  canvas.dataset.sightlineCount="0";
  canvas.dataset.sightlineMode="off";
  if (!state.active) return;
  const displayed = state.objects.filter(p => !$("health-bursts").checked || currentHealth(state, p[0]) !== 0);
  if ($("trails").checked)
    for (const p of displayed) {
      const points = M.trail(model, state.index, p[0], 2).map(project);
      if (points.length > 1)
        path(
          points,
          color(p) + (p[0] === selected || p[4] ? "b0" : "50"),
          p[4] ? 1.8 : 1,
        );
    }
  displayed
    .slice()
    .sort((a, b) => project(a.slice(1, 4))[2] - project(b.slice(1, 4))[2])
    .filter((p)=>!pov || p[0]!==pov.object)
    .forEach((p) => figure(p, p[0] === selected, state));
  if($("health-bursts").checked){
    const bursts=healthBursts.filter(event=>time>=event.time && time<event.time+0.9);
    bursts.forEach(drawHealthBurst);canvas.dataset.healthBurstCount=String(bursts.length);
  }
  if(!pov || pov.object!==self?.[0])drawSelfSightline(state);
  const placed = [];
  for (const label of labels.sort((a, b) => b.priority - a.priority)) {
    ctx.font=label.priority ? "600 11px system-ui" : "11px system-ui";
    const elevation=label.elevation===null ? null : `${label.elevation>=0 ? "+" : ""}${label.elevation.toFixed(1)} u`;
    const bar=label.health?.fraction!==null && label.health?.fraction!==undefined;
    const labelWidth=Math.max(ctx.measureText(label.text).width,bar ? 72 : 0,elevation ? 48 : 0)+10;
    const boxHeight=17+(bar ? 10 : 0)+(elevation ? 15 : 0);
    const offsets=[];
    for(const row of [0,-1,1,-2,2]) for(const column of [0,1,-1,2,-2])
      offsets.push([column*(labelWidth+12),row*(boxHeight+6)]);
    offsets.sort((a,b)=>Math.hypot(...a)-Math.hypot(...b));
    for (const [dx, dy] of offsets) {
      const x=label.x+dx,y=label.y-8-boxHeight+dy;
      if(x-labelWidth/2<8 || x+labelWidth/2>width-8 || y<35 || y+boxHeight>height-28)continue;
      // Labels must clear every projected head, nose and body, including their
      // own figure when a crowded view moves the label below its first choice.
      if(figureBounds.some(b=>x-labelWidth/2<b.right && x+labelWidth/2>b.left &&
        y<b.bottom && y+boxHeight>b.top))continue;
      if(placed.some(p=>Math.abs(p.x-x)<(p.w+labelWidth)/2+5 && y<p.y+p.h+4 && y+boxHeight+4>p.y))continue;
      path([[label.x,label.y-2],[x,y+boxHeight]],label.color+"66",0.7);
      ctx.fillStyle=sceneTheme.bg+"dc";ctx.fillRect(x-labelWidth/2,y,labelWidth,boxHeight);
      ctx.textAlign="center";ctx.fillStyle=label.color;
      ctx.fillText(label.text,x,y+12);
      let nextY=y+19;
      if(bar){
        const w=72;ctx.fillStyle=sceneTheme["grid-major"];ctx.fillRect(x-w/2,nextY,w,5);
        ctx.fillStyle=label.color;ctx.fillRect(x-w/2,nextY,w*label.health.fraction,5);
        ctx.strokeStyle=label.color+"99";ctx.lineWidth=0.5;ctx.strokeRect(x-w/2,nextY,w,5);
        nextY+=13;canvas.dataset.healthBarCount=String(Number(canvas.dataset.healthBarCount)+1);
      }
      if(elevation){ctx.font="10px ui-monospace,monospace";ctx.fillStyle=sceneTheme.muted;ctx.fillText(elevation,x,nextY+7);}
      ctx.textAlign="left";placed.push({x,y,w:labelWidth,h:boxHeight});break;
    }
  }
  canvas.dataset.figureBounds=JSON.stringify(figureBounds);
  canvas.dataset.labelBounds=JSON.stringify(placed);
  if(pov && pov.object===self?.[0])drawSelfSightline(state);
}
function drawCoverage() {
  if (!model) return;
  const rect = coverage.getBoundingClientRect(),
    dpr = Math.min(devicePixelRatio || 1, 2);
  coverage.width = Math.round(rect.width * dpr);
  coverage.height = Math.round(rect.height * dpr);
  const c = coverage.getContext("2d");
  c.scale(dpr, dpr);
  c.fillStyle = sceneTheme.gap;
  c.fillRect(0, 0, rect.width, rect.height);
  if (chunkIndex) {
    c.fillStyle=sceneTheme.window;
    for (const chunk of chunkIndex.chunks) c.fillRect((chunk.start_seconds/replayEnd())*rect.width,0,((chunk.end_seconds-chunk.start_seconds)/replayEnd())*rect.width,rect.height);
  }
  for (const s of $("smooth-motion").checked ? M.playbackSegments(model) : model.segments) {
    c.fillStyle = sceneTheme.recorded;
    c.fillRect(
      (s.start / replayEnd()) * rect.width,
      0,
      Math.max(0.2, ((s.end - s.start) / replayEnd()) * rect.width),
      rect.height,
    );
  }
  for (const event of model.data.events ?? []) {
    if (event.kind === "incoming_source" && event.status !== "observed") continue;
    c.fillStyle = M.eventPresentation(event).color;
    c.fillRect((event.t / replayEnd()) * rect.width, 0, 2, rect.height);
  }
}
function renderDamageEvents() {
  const root = $("damage-events");
  if (!root) return;
  const events = hasCurrentWindow() ? M.eventsAt(model, time) : [];
  const signature = events.map((e) => `${e.t}:${e.kind}:${e.record_id ?? e.observation_id}:${e.status}:${e.reason}`).join("|");
  if (root.dataset.key === signature) return;
  root.dataset.key = signature;
  root.replaceChildren();
  if (!events.length) {
    root.textContent = "No recorded outgoing feedback or incoming source observations at or before this time.";
    return;
  }
  for (const event of events.reverse()) {
    const button = document.createElement("button");
    button.type = "button";
    const display = M.eventPresentation(event);
    button.textContent = `${M.formatTime(event.t)} · ${display.label}`;
    button.title = display.detail;
    button.style.borderLeft = `3px solid ${display.color}`;
    button.onclick = () => {
      setTime(event.t);
      if (display.entityId) {
        const state=current();
        const matches=state.recordedFields.filter((row)=>row.entity_id===display.entityId && state.objects.some((p)=>p[0]===row.object));
        if (matches.length===1) selected=matches[0].object;
      }
      dirty=true;updateUI(true);
    };
    root.append(button);
  }
}
function rebuildList(state) {
  const signature =
    state.objects
      .map(
        (p) =>
          `${p[0]}:${p[4]}:${JSON.stringify(identityFor(p, state).fields)}:${sampleHero(p, state)}`,
      )
      .join(",") + `/${selected}`;
  if (signature === listSignature) return;
  listSignature = signature;
  const oldScroll = $("object-list").scrollTop;
  $("object-list").replaceChildren();
  if (!state.objects.length) {
    const p = document.createElement("p");
    p.className = "empty-list";
    p.textContent = "No usable object positions at this time.";
    $("object-list").append(p);
    return;
  }
  const sorted = state.objects
    .slice()
    .sort((a, b) => (b[4] === true) - (a[4] === true) || a[0] - b[0]);
  for (const p of sorted) {
    const button = document.createElement("button");
    button.className =
      "object-row" +
      (p[4] ? " self" : "") +
      (p[0] === selected ? " selected" : "");
    button.dataset.index = p[0];
    button.setAttribute("aria-pressed", String(p[0] === selected));
    const dot = document.createElement("i");
    dot.className = "swatch";
    dot.style.background = color(p);
    const name = document.createElement("span");
    name.textContent = objectTitle(p, state);
    const status = document.createElement("small");
    status.textContent = p[0] === selected ? "Selected" : "XYZ";
    button.append(dot, name, status);
    button.onclick = () => {
      selected = p[0];
      povManualLook = false;
      dirty = true;
      updateUI(true);
    };
    $("object-list").append(button);
  }
  $("object-list").scrollTop = oldScroll;
}
function updateUI(force = false) {
  if (!model) return;
  const now = performance.now();
  const state = current();
  maintainSelection(state);
  if (!force && now - lastUI < 80 && lastActiveState === state.active) return;
  lastUI = now;
  lastActiveState = state.active;
  const p = state.objects.find((p) => p[0] === selected),
    meta = p ? model.data.objects[selected] : null;
  const identity = identityFor(p, state),
    seen = lastSeen(identity);
  const pov=cameraPov(state);
  const aimDot=$("camera-mode").value==="self" || (pov && state.objects.some(p=>p[0]===pov.object && p[4]));
  $("self-sightline").dataset.marker=aimDot ? "dot" : "line";
  $("self-sightline").textContent=`Aim ${aimDot ? "dot" : "line"}: ${$("self-sightline").getAttribute("aria-pressed")==="true" ? "On" : "Off"}`;
  $("your-pov").setAttribute("aria-pressed",String($("camera-mode").value==="self"));
  $("your-pov").textContent=$("camera-mode").value==="self" ? "Exit your POV" : "Your POV";
  $("your-pov").disabled=!M.povPreview(state) && $("camera-mode").value!=="self";
  $("view-selected").disabled=!p;
  $("view-selected").textContent=$('camera-mode').value==='selected' ? "Return to free camera" : "View from this player";
  $("view-note").textContent=$('camera-mode').value!=='free'
    ? !pov ? "This player's position is unavailable at this time."
      : pov.forward && !povManualLook ? "Recorded facing preview · drag to look."
      : "Recorded position · drag to look."
    : "Noses show facing · heights are above the reference floor, in raw units.";
  $("play").textContent = playing ? "Pause" : "Play";
  $("play").setAttribute("aria-pressed", String(playing));
  $("clock").textContent = M.formatTime(time);
  $("time").value = time;
  $("time").setAttribute("aria-valuetext", M.formatTime(time));
  $("active-count").textContent = state.objects.length;
  $("sample-state").textContent = state.active
    ? `${state.presentation_only ? "Playback" : "Recorded"} · ${state.objects.length} objects`
    : "No recorded sample";
  $("sample-state").classList.toggle("gap", !state.active);
  $("epoch-label").textContent = state.active
    ? `${chunkIndex?.chunks[loadedChunk]?.recovery_status === "verified_sealed_prefix" ? "Recovered · " : ""}Sample ${state.index + 1} / ${model.data.frames.length}`
    : "";
  $("scene-message").hidden = state.active;
  if (!state.active) {
    const n = chunkIndex ? M.chunkAt(chunkIndex,time) : -1;
    const window = chunkIndex ? M.recorderWindowAt(chunkIndex,time) : null;
    const reason = {
      source_unavailable: "The recorder could not acquire the roster here.",
      cancelled: "The recorder cancelled this window before acceptance.",
      failed: "This window failed before acceptance.",
      missing_journal_acceptance: "A matching recorder acceptance record is missing.",
      accepted_window_verification_failed: "This accepted window failed saved-data verification.",
      accepted_no_entity_frames: "This verified window contains no entity frames.",
      not_accepted: "This window was not accepted by the recorder.",
    }[window?.reason];
    $("message-title").textContent = n === loadingChunk && n >= 0 ? "Loading recorded window" : "A gap in the recording";
    const next = nextAvailable();
    $("message-detail").textContent = reason ?? (n >= 0 && failedChunks.has(n)
      ? "This window could not be loaded. Coordinates remain unknown."
      : next !== null
        ? "No usable positions were saved here. Figures return when recorded data resumes."
        : "No further usable positions were saved in this export.");
    $("next-data").hidden = next === null;
  }
  $("prev").disabled = $("next").disabled = !hasCurrentWindow() || !model.data.frames.length;
  rebuildList(state);
  renderDamageEvents();
  $("selected-label").textContent = objectTitle(p, state) ?? meta?.label ?? "Select a player";
  $("selected-description").textContent =
    identity.status === "video_matched"
      ? "Saved object track matched to named video evidence. This is a recording-specific association."
      : p?.[4]
        ? "Matched to your controlled object in this sample."
        : meta
          ? "Structural object ID. Player identity is not established."
          : "Each ID describes a captured object, not a verified player.";
  for (const [i, axis] of ["x", "y", "z"].entries())
    $("pos-" + axis).textContent = p ? p[i + 1].toFixed(3) : "—";
  const display = state.displaySamples?.find((row) => row.object === selected);
  $("position-status").textContent = p ? display
    ? `${display.mode === "interpolated" ? "Smoothed playback" : "Last recorded"} · sample ${Math.round(display.age_seconds*1000)} ms ago`
    : "Recorded" : "Unavailable";
  const health = p?.[4] === true ? M.selfHealthCandidate(state) : null;
  const recorded = p ? M.observationFields(state, p[0]) : null;
  $("health-label").textContent = health ? "Self health candidate" : "Health observation";
  const recordedValue = (field) => recorded?.[field]?.value != null
    ? typeof recorded[field].value === "number"
      ? recorded[field].value.toLocaleString(undefined, {maximumFractionDigits:2})
      : String(recorded[field].value)
    : null;
  for (const [id, field] of [["health-candidate","health"],["identity-hero","hero"],["identity-team","relation"],["identity-name","username"]])
    $(id).title = recorded?.[field]?.validation_status ?? "Unknown";
  $("health-candidate").textContent = health
    ? `${health.display_ceil_candidate} · ${health.declared_pool_count} pools`
    : recordedValue("health") ?? "Unavailable";
  const bar=p ? M.healthBar(state,p[0],healthScales) : null;
  $("selected-health-bar").hidden=bar?.fraction==null;
  $("selected-health-bar").value=bar?.fraction ?? 0;
  $("selected-health-bar").style.accentColor=p ? color(p) : UNKNOWN_GRAY;
  $("health-scale").hidden=bar?.reference==null;
  $("health-scale").textContent=bar?.reference ? `Bar scale: ${Math.ceil(bar.reference)} HP · highest recorded` : "";
  const elevation=p ? M.referenceHeight(p,gridY) : null;
  $("reference-height").textContent=elevation===null ? "—" : `${elevation.toFixed(2)} units`;
  $("identity-name").textContent = identity.fields.player_name ?? recordedValue("username") ?? "Unknown";
  $("identity-team").textContent = identity.fields.team ?? recordedValue("team") ?? (recordedValue("relation") ? "Relation: " + recordedValue("relation") : "Unknown");
  $("identity-hero").textContent =
    identity.fields.hero ?? recordedValue("hero") ??
    (seen
      ? `${seen.hero} · seen ${M.formatTime(seen.observed_at.hero, 0)}`
      : "Unknown");
  $("identity-status").textContent =
    evidenceError ||
    (identity.status === "video_matched"
      ? "Matched to named video evidence within this reviewed span."
      : identity.status === "candidate"
        ? "Candidate association only: " +
          identity.candidates
            .map(
              (c) =>
                [c.fields.kind, c.fields.player_name]
                  .filter(Boolean)
                  .join(" · ") || "unknown",
            )
            .join(", ")
        : identity.status === "conflict"
          ? "Conflicting labels remain unknown."
          : evidence
            ? "No reviewed identity match at this time."
            : "");
  const evidenceKey = JSON.stringify(identity.evidence);
  if ($("identity-evidence").dataset.key !== evidenceKey) {
    $("identity-evidence").dataset.key = evidenceKey;
    $("identity-evidence").replaceChildren(
      ...identity.evidence.map((e) =>
        reviewLink(e.video_seconds, M.formatTime(e.video_seconds, 0), e.note),
      ),
    );
  }
  const rotation = state.rotations.find((q) => q[0] === selected);
  $("facing-status").textContent =
    rotation && M.candidateForward(rotation.slice(1))
      ? "Candidate"
      : "Unavailable";
  const suggestion = meta ? userLabels.get(meta.key) : null;
  $("user-suggestion").hidden = !suggestion;
  $("user-suggestion").textContent = suggestion
    ? `Your suggestion: ${suggestion} · unverified`
    : "";
  if (videoConfig)
    $("video-clock").textContent = videoReady()
      ? `Video ${M.formatTime(video.currentTime)}`
      : "Loading…";
  const read = state.frame?.reads?.find((r) => r[0] === selected);
  $("provenance").textContent = meta
    ? `${meta.key}\n\n${p ? `Epoch: ${state.frame.epoch}\nSequence: ${state.frame.sequence}\nDisplayed XYZ: ${p.slice(1, 4).join(", ")}\nRead ticks: ${read ? read.slice(1).join(" – ") : "unavailable"}\n${display ? "Display-only interpolation/hold up to 200 ms. Health and labels retain the preceding source sample; Frame JSON retains raw observations." : "No interpolation."} Serial reads; not an atomic world snapshot.` : "No current position. Previous values are not shown."}`
    : "Choose an object.";
  if (recorded) $("provenance").textContent += `\nRecorded fields: ${JSON.stringify(recorded)}\nVisibility unknown. Source validation is preserved; names are never inferred from hero or health.`;
  if (rotation)
    $("provenance").textContent +=
      `\nRaw rotation: ${rotation.slice(1).join(", ")}\nDisplay: normalize xyzw, +Y up, +Z forward. Camera aim/FOV unvalidated.`;
  if (health)
    $("provenance").textContent +=
      `\nSelf pool sum: ${health.raw_sum}; ceiling: ${health.display_ceil_candidate}.\n${health.note}\nPool reads: ${JSON.stringify(health.pools)}`;
}
function animate(now) {
  const dt = Math.min((now - lastTick) / 1000, 0.1);
  if (model && keys.size) {
    leavePov();
    const step =
      dt *
      (height / (2 * Math.tan(Math.PI / 6)) / camera.scale) *
      0.35 *
      (keys.has("ShiftLeft") || keys.has("ShiftRight") ? 3 : 1);
    const forward = (keys.has("KeyW") ? 1 : 0) - (keys.has("KeyS") ? 1 : 0),
      side = (keys.has("KeyD") ? 1 : 0) - (keys.has("KeyA") ? 1 : 0);
    camera.center[0] +=
      (-Math.sin(camera.yaw) * forward + Math.cos(camera.yaw) * side) * step;
    camera.center[2] +=
      (-Math.cos(camera.yaw) * forward - Math.sin(camera.yaw) * side) * step;
    camera.center[1] +=
      ((keys.has("KeyE") ? 1 : 0) - (keys.has("KeyQ") ? 1 : 0)) * step;
    $("follow").checked = false;
    dirty = true;
  }
  if (model && playing) {
    const target = videoReady()
      ? M.videoTime(time, videoOffset, video.duration)
      : null;
    if (target?.available) {
      if (!video.seeking && !video.paused && video.readyState >= 2)
        time = video.currentTime + videoOffset;
      else if (video.paused) syncVideo();
    } else {
      time += dt * speed;
      if (
        videoReady() &&
        M.videoTime(time, videoOffset, video.duration).available
      )
        syncVideo(true);
    }
    if (time >= replayEnd()) {
      time = replayEnd();
      playing = false;
      video.pause();
    }
    if (videoReady()) syncVideo();
    dirty = true;
  }
  if (chunkIndex && model) void requestChunk(time);
  lastTick = now;
  if (dirty) {
    render();
    dirty = false;
    updateUI();
  }
  requestAnimationFrame(animate);
}
$("play").onclick = () => {
  if (time >= replayEnd() - 0.001) setTime(chunkIndex?.repeat_windows ? 0 : chunkIndex?.chunks[0]?.start_seconds ?? model.data.start_seconds);
  playing = !playing;
  syncVideo(true);
  lastTick = performance.now();
  updateUI(true);
};
$("prev").onclick = () => {
  if (!model?.data.frames.length || !hasCurrentWindow()) return;
  const index = M.indexAt(model, time);
  setTime(
    model.data.frames[
      Math.max(
        0,
        index -
          (Math.abs(time - model.data.frames[Math.max(0, index)].t) < 1e-7
            ? 1
            : 0),
      )
    ].t,
  );
};
$("next").onclick = () => {
  if (!model?.data.frames.length || !hasCurrentWindow()) return;
  setTime(
    model.data.frames[
      Math.min(model.data.frames.length - 1, M.indexAt(model, time) + 1)
    ].t,
  );
};
$("time").oninput = () => setTime(Number($("time").value));
$("speed").onchange = () => {
  speed = Number($("speed").value);
  syncVideo();
};
$("next-data").onclick = () => {
  const next = nextAvailable();
  if (next !== null) setTime(next);
};
$("fit").onclick = () => fit(true);
$("view").onclick = () => {
  leavePov();
  camera.top = !camera.top;
  $("view").textContent = camera.top ? "3D view" : "Top view";
  $("view").setAttribute("aria-pressed", String(camera.top));
  dirty = true;
};
$("trails").onchange = () => {
  dirty = true;
};
$("smooth-motion").onchange = () => { dirty=true; updateUI(true); drawCoverage(); };
$("height-guides").onchange = () => { dirty=true; };
$("map-surfaces").onchange = () => { dirty=true; };
$("health-bursts").onchange = () => { dirty=true; };
$("player-labels").onchange = () => { dirty=true; };
$("follow").onchange = () => {
  dirty = true;
};
function leavePov() {
  if (!freeCamera && $("camera-mode").value === "free") return;
  $("camera-mode").value="free";
  if (freeCamera) Object.assign(camera,freeCamera,{center:[...freeCamera.center]});
  freeCamera=null; povManualLook=false; $("follow").disabled=false;
  $("view").textContent=camera.top ? "3D view" : "Top view";
  $("view").setAttribute("aria-pressed",String(camera.top));
  dirty=true;
}
$("camera-mode").onchange = () => {
  if ($("camera-mode").value!=="free") {
    if (!freeCamera) freeCamera={...camera,center:[...camera.center]};
    povManualLook=false;
    $("follow").checked=false;$("follow").disabled=true;camera.top=false;
    $("view").textContent="Top view";$("view").setAttribute("aria-pressed","false");
  } else { leavePov(); }
  dirty=true;updateUI(true);
};
$("your-pov").onclick=()=>{
  $("camera-mode").value=$("camera-mode").value==="self" ? "free" : "self";
  $("camera-mode").onchange();
};
$("self-sightline").onclick=()=>{
  const enabled=$("self-sightline").getAttribute("aria-pressed")!=="true";
  $("self-sightline").setAttribute("aria-pressed",String(enabled));
  dirty=true;updateUI(true);
};
$("view-selected").onclick=()=>{
  if ($("camera-mode").value==="selected") leavePov();
  else { $("camera-mode").value="selected"; $("camera-mode").onchange(); }
  dirty=true;updateUI(true);
};
let pointer = null;
canvas.onpointerdown = (e) => {
  e.preventDefault();
  canvas.focus();
  pointer = {
    x: e.clientX,
    y: e.clientY,
    startX: e.clientX,
    startY: e.clientY,
    moved: false,
    pan: e.button === 1 || e.shiftKey,
    look: e.button === 2,
  };
  canvas.setPointerCapture(e.pointerId);
};
canvas.onpointermove = (e) => {
  if (!pointer) return;
  const dx = e.clientX - pointer.x,
    dy = e.clientY - pointer.y;
  if (Math.hypot(e.clientX - pointer.startX, e.clientY - pointer.startY) > 4)
    pointer.moved = true;
  if (pointer.moved) {
    if (pointer.pan) {
      leavePov();
      panCamera(dx, dy);
    } else {
      const pov=$('camera-mode').value!=='free';
      if (pov) povManualLook=true;
      const eye = pointer.look || pov ? eyePosition() : null;
      camera.yaw += dx * (pointer.look ? -0.006 : 0.006);
      camera.pitch = Math.max(-1.45, Math.min(1.45, camera.pitch + dy * 0.006));
      if (eye) {
        camera.top = false;
        $("view").textContent = "Top view";
        $("view").setAttribute("aria-pressed", "false");
        lookFrom(eye);
        $("follow").checked = false;
      }
    }
    dirty = true;
  }
  pointer.x = e.clientX;
  pointer.y = e.clientY;
};
canvas.onpointerup = (e) => {
  if (pointer && !pointer.moved && e.button === 0) {
    const box = canvas.getBoundingClientRect(),
      x = e.clientX - box.left,
      y = e.clientY - box.top;
    const hit = hitTargets
      .slice()
      .reverse()
      .find((h) => Math.hypot(x - h.x, y - h.y) < h.radius);
    if (hit) {
      selected = hit.index;
      povManualLook = false;
      dirty = true;
      updateUI(true);
    }
  }
  pointer = null;
};
canvas.onpointercancel = () => {
  pointer = null;
};
canvas.oncontextmenu = (e) => e.preventDefault();
canvas.addEventListener(
  "wheel",
  (e) => {
    e.preventDefault();
    camera.scale = Math.max(
      0.2,
      Math.min(60, camera.scale * Math.exp(-e.deltaY * 0.001)),
    );
    dirty = true;
  },
  { passive: false },
);
canvas.onkeydown = (e) => {
  if (!model) return;
  if (e.ctrlKey || e.altKey || e.metaKey) return;
  if (
    [
      "KeyW",
      "KeyA",
      "KeyS",
      "KeyD",
      "KeyQ",
      "KeyE",
      "ShiftLeft",
      "ShiftRight",
    ].includes(e.code)
  ) {
    e.preventDefault();
    keys.add(e.code);
    return;
  }
  if (e.code === "KeyF") {
    e.preventDefault();
    fit(true);
    return;
  }
  if (e.code === "Space") {
    e.preventDefault();
    $("play").click();
  } else if (e.key === "ArrowRight") {
    e.preventDefault();
    $("next").click();
  } else if (e.key === "ArrowLeft") {
    e.preventDefault();
    $("prev").click();
  }
};
canvas.onkeyup = (e) => keys.delete(e.code);
canvas.onblur = () => keys.clear();
window.addEventListener("blur", () => keys.clear());
document.addEventListener("visibilitychange", () => {
  if (document.hidden) keys.clear();
});
new ResizeObserver(resize).observe($("canvas-wrap"));
requestAnimationFrame(animate);
(async () => {
  try {
    const response = await fetch("/replay.json", { cache: "no-store" });
    if (!response.ok)
      throw new Error(`Could not load recording (${response.status}).`);
    const length = Number(response.headers.get("Content-Length"));
    if (length > 128 * 1024 * 1024)
      throw new Error("Replay file exceeds 128 MiB.");
    const raw = await response.text();
    if (raw.length > 128 * 1024 * 1024)
      throw new Error("Replay file exceeds 128 MiB.");
    const document = JSON.parse(raw);
    if (document.schema === "overwatch-decoder.entity-replay-index/1") {
      chunkIndex=M.createIndex(document);
      if (chunkIndex.repeat_windows) model = M.emptyIndexModel(chunkIndex);
      else await requestChunk(0,true);
    } else useRosterModel(M.create(document));
    healthBursts=M.healthDepletions(model);
    healthScales=M.observedHealthScales(model);
    gridY = model.data.bounds?.min?.[1] ?? -5;
    time = model.data.start_seconds;
    selected = model.data.frames[0]?.objects.find((p)=>p[4]===true)?.[0] ?? model.data.frames[0]?.objects[0]?.[0] ?? model.data.objects[0]?.index;
    selectedController = null;
    selectedSelf = model.data.frames[0]?.objects.find((p)=>p[0]===selected)?.[4] === true;
    $("total-objects").textContent = modelObjectCount();
    $("total-frames").textContent = model.data.frames.length.toLocaleString();
    $("sample-rate").textContent = model.updateInterval ? `${Math.round(1 / model.updateInterval)} Hz` : "Unknown";
    $("duration").textContent = "/ " + M.formatTime(model.end, 0);
    $("timeline-end").textContent = M.formatTime(model.end, 0);
    $("time").max = replayEnd();
    $("time").disabled = false;
    $("play").disabled = false;
    $("save-frame").disabled = false;
    resize();
    // Seed the exit camera, then start every load in the recorded self POV.
    $("camera-mode").value = "free";
    fit();
    $("camera-mode").value = "self";
    $("camera-mode").onchange();
    updateDuration();
    await loadMedia();
  } catch (error) {
    $("message-title").textContent = "The recording could not be opened";
    $("message-detail").textContent = error.message;
    $("sample-state").textContent = "Unable to load replay";
    $("sample-state").classList.add("gap");
  }
})();
