const assert = require("node:assert/strict");
const { test } = require("node:test");
const { readFileSync } = require("node:fs");
const { runInNewContext } = require("node:vm");
const G = require("./environment.js");

const SOURCE = "a".repeat(64), BUILD = "b".repeat(64), HASH = "c".repeat(64);
function fixture() {
  const rays = Array.from({ length: 49 }, (_, index) => {
    const returned_hit = [index % 7, Math.floor(index / 7), 10];
    return { index, origin: [0, 0, 0], end: returned_hit.map((v) => 2 * v),
      returned_hit, returned_normal: [0, 0, -1], status: "surface_hit" };
  });
  rays[2].returned_hit = rays[2].end.slice();
  rays[2].status = "miss_or_endpoint";
  rays[3].returned_hit = rays[3].origin.slice();
  rays[3].status = "origin_ambiguous";
  return {
    schema: "overwatch-decoder.replay-environment/1", replay_source_sha256: SOURCE, observed_build_sha256: BUILD,
    map: "Workshop Chamber", mode: "Skirmish",
    registration: { kind: "identity", validation: "controlled_coordinate_pairs", evidence_sha256: HASH },
    surveys: [{
      schema: "overwatch-decoder.environment-surface-samples/1", observed_build_sha256: BUILD, map: "Workshop Chamber", mode: "Skirmish",
      coordinate_space: "workshop_world", replay_registration: null, visibility: "unknown", coverage: "sparse_first_hit_rays",
      source: { kind: "inspector_log_file", sha256: HASH, rule_sha256: HASH, position_tolerance: 0.025 },
      rays, planar_patches: [{ kind: "derived_between_samples", ray_indices: [0, 1, 8, 7] }],
    }],
  };
}

test("browser and module expose the same bounded validator", () => {
  const browser = {};
  runInNewContext(readFileSync(require.resolve("./environment.js"), "utf8"), browser);
  assert.deepEqual(Object.keys(browser.OverwatchDecoderReplayEnvironment), Object.keys(G));
  assert.equal(G.MAX_DOCUMENT_BYTES, 1048576);
});

test("uses only interior hits and copies the quad vertices in original order", () => {
  const data = fixture();
  const out = G.create(data, SOURCE);
  assert.equal(out.points.length, 47);
  assert.equal(out.patches.length, 1);
  assert.deepEqual(out.patches[0], [[0, 0, 10], [1, 0, 10], [1, 1, 10], [0, 1, 10]]);
  data.surveys[0].rays[0].returned_hit[2] = 100;
  assert.deepEqual(out.points[0], [0, 0, 10]);
  assert.deepEqual(out.patches[0][0], [0, 0, 10]);
});

test("requires exact replay, registration and survey scope", () => {
  assert.throws(() => G.create(fixture(), "d".repeat(64)), /do not match/);
  for (const edit of [
    (data) => { data.registration.kind = "similar"; },
    (data) => { data.registration.validation = "manual"; },
    (data) => { data.registration.evidence_sha256 = "unknown"; },
    (data) => { data.registration.offset = [1, 2, 3]; },
  ]) {
    const data = fixture();
    edit(data);
    assert.throws(() => G.create(data, SOURCE), /require verified/);
  }
  for (const edit of [
    (survey) => { survey.observed_build_sha256 = "d".repeat(64); },
    (survey) => { survey.map = "Lijiang Tower"; },
    (survey) => { survey.mode = "Control"; },
    (survey) => { survey.visibility = "all_visible"; },
    (survey) => { survey.replay_registration = { kind: "identity" }; },
  ]) {
    const data = fixture();
    edit(data.surveys[0]);
    assert.throws(() => G.create(data, SOURCE), /scope mismatch/);
  }
});

test("bounds ray count, coordinates, normals, geometric status and clock", () => {
  for (const edit of [
    (data, survey) => { data.surveys = Array(17).fill(survey); },
    (_data, survey) => { survey.rays = Array(501).fill(survey.rays[0]); },
    (_data, survey) => { survey.rays[0].origin[0] = NaN; },
    (_data, survey) => { survey.rays[0].end[0] = 1000001; },
    (_data, survey) => { survey.rays[4].origin[1] = 0.001; },
    (_data, survey) => { survey.rays[4].index = 3; },
    (_data, survey) => { survey.rays[2].status = "surface_hit"; },
    (_data, survey) => { survey.rays[3].status = "surface_hit"; },
    (_data, survey) => { survey.rays[0].returned_hit[0] = 0.1; },
    (_data, survey) => { survey.rays[0].returned_normal[2] = -0.7; },
    (_data, survey) => { survey.source.position_tolerance = 1; },
    (_data, survey) => { survey.rays[0].hit_elapsed_seconds = 10; },
  ]) {
    const data = fixture();
    edit(data, data.surveys[0]);
    assert.throws(() => G.create(data, SOURCE));
  }
  const data = fixture(), survey = data.surveys[0];
  survey.survey = { index: 0, player_position: [1, 2, 3], clock: "inspector_elapsed_seconds", start: 10, end: 12 };
  for (const ray of survey.rays) {
    ray.hit_elapsed_seconds = 10;
    ray.normal_elapsed_seconds = 11;
  }
  assert.equal(G.create(data, SOURCE).points.length, 47);
  survey.rays[0].normal_elapsed_seconds = 9;
  assert.throws(() => G.create(data, SOURCE), /clock/);
});

test("rejects invalid, duplicate and unsupported quad corners", () => {
  for (const indices of [[0, 1, 8, -1], [0, 1, 8, 7.5], [0, 1, 7, 8],
    [1, 2, 9, 8], [2, 3, 10, 9], [6, 7, 14, 13], [0, 1, 49, 7], [0, 1, 8, 8]]) {
    const data = fixture();
    data.surveys[0].planar_patches[0].ray_indices = indices;
    assert.throws(() => G.create(data, SOURCE), /surface patch/);
  }
  const data = fixture(), survey = data.surveys[0];
  survey.planar_patches.push(survey.planar_patches[0]);
  assert.throws(() => G.create(data, SOURCE), /corners/);
  survey.planar_patches.pop();
  survey.rays[7].returned_normal = [0, 1, 0];
  assert.throws(() => G.create(data, SOURCE), /interpolation bounds/);
});

test("preserves sparse hits when no quad fits", () => {
  const data = fixture();
  delete data.surveys[0].planar_patches;
  const out = G.create(data, SOURCE);
  assert.equal(out.points.length, 47);
  assert.deepEqual(out.patches, []);
});

test("enforces the total budget across individually bounded surveys", () => {
  const data = fixture(), survey = data.surveys[0];
  delete survey.planar_patches;
  survey.rays = Array.from({ length: 500 }, (_, index) => ({ ...survey.rays[0], index }));
  data.surveys = Array(9).fill(survey);
  assert.throws(() => G.create(data, SOURCE), /count/);
});
