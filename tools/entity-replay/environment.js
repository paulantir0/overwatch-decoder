/* Validate registered Workshop samples for a sparse, display-only overlay. */
(function (root) {
  "use strict";
  const MAX_DOCUMENT_BYTES = 1024 * 1024;
  const MAX_SURVEYS = 16;
  const MAX_RAYS = 500;
  const MAX_TOTAL_RAYS = 4096;
  const MAX_COORDINATE = 1_000_000;
  const GRID = 7;

  function check(ok, reason) {
    if (!ok) throw new Error(reason);
  }
  const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
  const digest = (value) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
  const text = (value) => typeof value === "string" && value.length > 0 && value.length <= 120 &&
    !/[\u0000-\u001f\u007f-\u009f]/u.test(value);
  const coordinate = (value) => Number.isFinite(value) && Math.abs(value) <= MAX_COORDINATE;
  const vector = (value) => Array.isArray(value) && value.length === 3 && value.every(coordinate);
  const subtract = (a, b) => a.map((v, i) => v - b[i]);
  const dot = (a, b) => a.reduce((sum, v, i) => sum + v * b[i], 0);
  const length = (v) => Math.hypot(...v);
  const cross = ([x, y, z], [u, v, w]) => [y * w - z * v, z * u - x * w, x * v - y * u];
  const elapsed = (value) => Number.isSafeInteger(value) && value >= 0;

  function keys(value, required, optional = []) {
    return object(value) && required.every((key) => Object.hasOwn(value, key)) &&
      Object.keys(value).every((key) => required.includes(key) || optional.includes(key));
  }

  function rayShape(ray, index, origin, tolerance, surveyClock) {
    check(keys(ray, ["index", "origin", "end", "returned_hit", "returned_normal", "status"],
      ["hit_elapsed_seconds", "normal_elapsed_seconds"]) && ray.index === index &&
      vector(ray.origin) && ray.origin.every((v, i) => v === origin[i]) &&
      vector(ray.end) && vector(ray.returned_hit) && vector(ray.returned_normal), "Invalid survey ray.");
    if (surveyClock) {
      check(elapsed(ray.hit_elapsed_seconds) && elapsed(ray.normal_elapsed_seconds) &&
        surveyClock.start <= ray.hit_elapsed_seconds && ray.hit_elapsed_seconds <= ray.normal_elapsed_seconds &&
        ray.normal_elapsed_seconds <= surveyClock.end, "Invalid survey ray clock.");
    } else check(!Object.hasOwn(ray, "hit_elapsed_seconds") && !Object.hasOwn(ray, "normal_elapsed_seconds"),
      "Survey ray timestamps lack a clock.");

    const direction = subtract(ray.end, origin);
    const rayLength = length(direction);
    check(rayLength > 2 * tolerance && Math.abs(length(ray.returned_normal) - 1) <= 0.05,
      "Invalid ray length or normal.");
    const unit = direction.map((v) => v / rayLength);
    const offset = subtract(ray.returned_hit, origin);
    const along = dot(unit, offset);
    const deviation = length(offset.map((v, i) => v - along * unit[i]));
    check(deviation <= tolerance && along >= -tolerance && along <= rayLength + tolerance, "Hit falls outside its ray.");
    let status;
    if (length(subtract(ray.returned_hit, ray.end)) <= tolerance) status = "miss_or_endpoint";
    else if (length(offset) <= tolerance) status = "origin_ambiguous";
    else if (along > 0 && along < rayLength) status = "surface_hit";
    check(status !== undefined && ray.status === status, "Invalid ray classification.");
  }

  function patchVertices(patch, rays, used) {
    const indices = patch?.ray_indices;
    check(keys(patch, ["kind", "ray_indices"]) && patch.kind === "derived_between_samples" &&
      rays.length === GRID ** 2 && Array.isArray(indices) && indices.length === 4 &&
      indices.every((i) => Number.isSafeInteger(i) && i >= 0 && i < rays.length), "Invalid surface patch.");
    const i = indices[0];
    check(i % GRID < GRID - 1 && i < GRID * (GRID - 1) &&
      indices[1] === i + 1 && indices[2] === i + GRID + 1 && indices[3] === i + GRID &&
      !used.has(i) && indices.every((index) => rays[index].status === "surface_hit"), "Invalid surface patch corners.");
    used.add(i);

    const vertices = indices.map((index) => rays[index].returned_hit.slice());
    const normals = indices.map((index) => {
      const normal = rays[index].returned_normal;
      const magnitude = length(normal);
      return normal.map((v) => v / magnitude);
    });
    for (let j = 0; j < 4; j++) {
      for (let k = 0; k < j; k++) {
        const delta = subtract(vertices[j], vertices[k]);
        check(length(delta) <= 5 && dot(normals[j], normals[k]) >= 0.999 &&
          Math.max(Math.abs(dot(delta, normals[j])), Math.abs(dot(delta, normals[k]))) <= 0.03,
          "Surface patch exceeds interpolation bounds.");
      }
    }
    const edges = vertices.map((v, j) => subtract(vertices[(j + 1) % 4], v));
    const turns = edges.map((edge, j) => dot(cross(edges[(j + 3) % 4], edge), normals[0]));
    check(turns.every((v) => v > 1e-6) || turns.every((v) => v < -1e-6), "Degenerate or concave surface patch.");
    return vertices;
  }

  function create(data, expectedSource) {
    check(keys(data, ["schema", "replay_source_sha256", "observed_build_sha256", "map", "mode", "registration", "surveys"]) &&
      data.schema === "overwatch-decoder.replay-environment/1" && digest(expectedSource) && data.replay_source_sha256 === expectedSource &&
      digest(data.observed_build_sha256) && text(data.map) && text(data.mode), "Map surfaces do not match this replay.");
    const registration = data.registration;
    check(keys(registration, ["kind", "validation", "evidence_sha256"]) && registration.kind === "identity" &&
      registration.validation === "controlled_coordinate_pairs" && digest(registration.evidence_sha256),
      "Map surfaces require verified coordinate registration.");
    check(Array.isArray(data.surveys) && data.surveys.length > 0 && data.surveys.length <= MAX_SURVEYS,
      "Invalid survey count.");
    const points = [], patches = [];
    let total = 0;
    for (const survey of data.surveys) {
      check(keys(survey, ["schema", "map", "mode", "observed_build_sha256", "coordinate_space",
        "replay_registration", "visibility", "coverage", "source", "rays"], ["survey", "planar_patches"]) &&
        survey.schema === "overwatch-decoder.environment-surface-samples/1" &&
        survey.map === data.map && survey.mode === data.mode && survey.observed_build_sha256 === data.observed_build_sha256 &&
        survey.coordinate_space === "workshop_world" && survey.replay_registration === null &&
        survey.visibility === "unknown" && survey.coverage === "sparse_first_hit_rays", "Survey scope mismatch.");
      const source = survey.source;
      check(keys(source, ["kind", "sha256", "rule_sha256", "position_tolerance"]) &&
        ["inspector_log_file", "inspector_clipboard"].includes(source.kind) && digest(source.sha256) && digest(source.rule_sha256) &&
        Number.isFinite(source.position_tolerance) && source.position_tolerance > 0 && source.position_tolerance <= 0.25,
        "Invalid survey provenance.");
      const clock = survey.survey;
      if (Object.hasOwn(survey, "survey")) {
        check(keys(clock, ["index", "player_position", "clock", "start", "end"]) &&
          elapsed(clock.index) && vector(clock.player_position) && clock.clock === "inspector_elapsed_seconds" &&
          elapsed(clock.start) && elapsed(clock.end) && clock.start <= clock.end, "Invalid Inspector survey clock.");
      }
      const rays = survey.rays;
      check(Array.isArray(rays) && rays.length > 0 && rays.length <= MAX_RAYS &&
        (total += rays.length) <= MAX_TOTAL_RAYS && vector(rays[0]?.origin), "Invalid survey ray count or origin.");
      for (const [i, ray] of rays.entries()) {
        rayShape(ray, i, rays[0].origin, source.position_tolerance, clock);
        if (ray.status === "surface_hit") points.push(ray.returned_hit.slice());
      }
      if (Object.hasOwn(survey, "planar_patches")) {
        check(Array.isArray(survey.planar_patches) && survey.planar_patches.length <= (GRID - 1) ** 2,
          "Invalid surface patch count.");
        const used = new Set();
        for (const patch of survey.planar_patches) patches.push(patchVertices(patch, rays, used));
      }
    }
    return { map: data.map, mode: data.mode, points, patches };
  }

  const api = { create, MAX_DOCUMENT_BYTES };
  if (typeof module !== "undefined") module.exports = api;
  else root.OverwatchDecoderReplayEnvironment = api;
})(globalThis);
