"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const E = require("./evidence.js");
const SHA = "ab".repeat(32);
const key = "epoch-a:object-001";
function binding(more = {}) {
  return {
    key,
    start_seconds: 10,
    end_seconds: 20,
    status: "video_matched",
    fields: { player_name: "Maple", hero: "Tracer", team: "ally" },
    evidence: [{ video_seconds: 12, note: "Controlled isolated association." }],
    ...more,
  };
}
function observation(more = {}) {
  return {
    player_name: "Maple",
    hero: "Tracer",
    team: "ally",
    video_seconds: 12,
    evidence: "Name and hero observed together in video.",
    ...more,
  };
}
function fixture(more = {}) {
  return {
    schema: "overwatch-decoder.replay-evidence/1",
    source_sha256: SHA,
    observations: [observation()],
    bindings: [binding()],
    ...more,
  };
}
function emptyIdentity() {
  return { fields: {}, status: "unknown", candidates: [], evidence: [] };
}
test("CommonJS and standalone browser global expose the same pure API", () => {
  const sandbox = {};
  vm.runInNewContext(
    fs.readFileSync(require.resolve("./evidence.js"), "utf8"),
    sandbox,
  );
  assert.deepEqual(Object.keys(sandbox.OverwatchDecoderReplayEvidence), Object.keys(E));
  assert.equal(typeof sandbox.OverwatchDecoderReplayEvidence.create, "function");
});
test("requires the expected source digest and canonicalizes its casing", () => {
  assert.throws(() => E.create(fixture(), "cd".repeat(32)), /mismatch/);
  assert.throws(() => E.create(fixture()), /digest/);
  assert.throws(
    () => E.create(fixture({ source_sha256: "not-a-digest" }), SHA),
    /digest/,
  );
  assert.equal(
    E.create(fixture({ source_sha256: SHA.toUpperCase() }), SHA).source_sha256,
    SHA,
  );
});
test("scope is half-open, exact, current, and never carried across a gap", () => {
  const m = E.create(
    fixture({
      bindings: [binding(), binding({ start_seconds: 30, end_seconds: 40 })],
    }),
    SHA,
  );
  assert.equal(E.identityAt(m, key, false, 10).fields.hero, "Tracer");
  assert.equal(E.identityAt(m, key, false, 19.99).status, "video_matched");
  assert.equal(E.identityAt(m, key, false, 30).status, "video_matched");
  for (const time of [0, 9.99, 20, 25, 29.99, 40, 100])
    assert.deepEqual(
      E.identityAt(m, key, false, time),
      emptyIdentity(),
      `${time}`,
    );
  for (const otherKey of [
    "object-001",
    "epoch-b:object-001",
    `${key} `,
    "EPOCH-A:OBJECT-001",
    null,
  ])
    assert.deepEqual(E.identityAt(m, otherKey, false, 12), emptyIdentity());
  assert.deepEqual(E.identityAt(m, key, true, 12, false), emptyIdentity());
});
test("self bindings follow only current self and exact keys are not implied self", () => {
  const self = binding({
    target: "self",
    fields: { player_name: "Cedar", team: "self" },
  });
  delete self.key;
  const m = E.create(fixture({ bindings: [self] }), SHA);
  assert.equal(
    E.identityAt(m, "epoch-b:object-003", true, 12).fields.player_name,
    "Cedar",
  );
  for (const isSelf of [false, null, undefined, 1])
    assert.deepEqual(E.identityAt(m, key, isSelf, 12), emptyIdentity());
  const keyed = E.create(fixture(), SHA);
  assert.deepEqual(E.identityAt(keyed, "other-key", true, 12), emptyIdentity());
});
test("video observations and context never become object links", () => {
  const m = E.create(
    fixture({
      bindings: [],
      context: { player_name: "Pine", hero: "Mercy", key },
    }),
    SHA,
  );
  assert.equal(E.rosterAt(m, 12)[0].player_name, "Maple");
  assert.deepEqual(E.identityAt(m, key, true, 12), emptyIdentity());
  assert.throws(
    () => E.create(fixture({ observations: [observation({ key })] }), SHA),
    /Unsupported/,
  );
});
test("candidate-only associations retain evidence but never fill true fields", () => {
  const m = E.create(
    fixture({ bindings: [binding({ status: "candidate" })] }),
    SHA,
  );
  const result = E.identityAt(m, key, false, 12);
  assert.deepEqual(result.fields, {});
  assert.equal(result.status, "candidate");
  assert.equal(result.candidates[0].fields.hero, "Tracer");
  assert.equal(result.evidence[0].video_seconds, 12);
});
test("conflicts clear only affected matched fields and are order-independent", () => {
  const a = binding(),
    b = binding({
      fields: { player_name: "Birch", hero: "Tracer", kind: "player" },
    }),
    c = binding({
      status: "candidate",
      fields: { hero: "Mercy", team: "opponent" },
    });
  for (const bindings of [
    [a, b, c],
    [c, b, a],
  ]) {
    const result = E.identityAt(
      E.create(fixture({ bindings }), SHA),
      key,
      false,
      12,
    );
    assert.equal(result.status, "conflict");
    assert.deepEqual(result.fields, {
      hero: "Tracer",
      team: "ally",
      kind: "player",
    });
    assert.equal(result.candidates.length, 1);
    assert.equal(result.evidence.length, 3);
  }
});
test("current self and exact-key matched bindings can conflict", () => {
  const self = binding({ target: "self", fields: { hero: "Mercy" } });
  delete self.key;
  const m = E.create(fixture({ bindings: [binding(), self] }), SHA);
  const result = E.identityAt(m, key, true, 12);
  assert.equal(result.status, "conflict");
  assert.equal(result.fields.hero, undefined);
  assert.equal(result.fields.player_name, "Maple");
  assert.equal(E.identityAt(m, key, false, 12).fields.hero, "Tracer");
});
test("matching duplicate values remain matched and candidates cannot override them", () => {
  const m = E.create(
    fixture({
      bindings: [
        binding(),
        binding(),
        binding({ status: "candidate", fields: { hero: "Mercy" } }),
      ],
    }),
    SHA,
  );
  const result = E.identityAt(m, key, false, 12);
  assert.equal(result.status, "video_matched");
  assert.equal(result.fields.hero, "Tracer");
  assert.equal(result.candidates.length, 1);
});
test("roster uses video time, keeps last casing, and excludes retrospective hero leakage", () => {
  const m = E.create(
    fixture({
      bindings: [],
      observations: [
        observation({ player_name: "MAPLE", hero: "Mercy", video_seconds: 50 }),
        observation({
          player_name: "maple",
          hero: "Ana",
          video_seconds: 25,
          retrospective: true,
        }),
        observation({ player_name: "Maple", video_seconds: 10 }),
        observation({
          player_name: "Cedar",
          hero: "Winston",
          team: "opponent",
          video_seconds: 15,
        }),
      ],
    }),
    SHA,
  );
  assert.deepEqual(E.rosterAt(m, 9.99), []);
  const past = E.rosterAt(m, 25);
  assert.equal(past.length, 2);
  const maple = past.find((row) => row.player_name.toLowerCase() === "maple");
  assert.equal(maple.player_name, "Maple");
  assert.equal(maple.hero, "Tracer");
  assert.equal(maple.video_seconds, 10);
  assert.deepEqual(maple.observed_at, { player_name: 10, hero: 10, team: 10 });
  const later = E.rosterAt(m, 50).find((row) => row.player_name === "MAPLE");
  assert.equal(later.hero, "Mercy");
  assert.equal(later.observed_at.hero, 50);
  assert.equal(m.observations.length, 4);
  assert.equal(m.observations[1].retrospective, true);
});
test("a roster can have only retrospective review evidence without any live identity", () => {
  const m = E.create(
    fixture({
      observations: [observation({ retrospective: true })],
      bindings: [],
    }),
    SHA,
  );
  assert.deepEqual(E.rosterAt(m, 100), []);
  assert.equal(m.observations[0].hero, "Tracer");
});
test("video proof timestamps are not binding session-time bounds", () => {
  const m = E.create(
    fixture({
      bindings: [
        binding({
          evidence: [{ video_seconds: 100, note: "Review video offset." }],
        }),
      ],
    }),
    SHA,
  );
  assert.equal(E.identityAt(m, key, false, 12).status, "video_matched");
  assert.equal(E.identityAt(m, key, false, 100).status, "unknown");
});
test("unavailable models and invalid query times return unknown without throwing", () => {
  const m = E.create(fixture(), SHA);
  for (const absent of [null, undefined, {}, fixture(), 5, "evidence"])
    assert.deepEqual(E.identityAt(absent, key, true, 12), emptyIdentity());
  for (const time of [-1, NaN, Infinity, "12", null]) {
    assert.deepEqual(E.identityAt(m, key, true, time), emptyIdentity());
    assert.deepEqual(E.rosterAt(m, time), []);
  }
  assert.deepEqual(E.rosterAt(null, 12), []);
});
test("normalized evidence is copied, immutable, and independent from caller mutations", () => {
  const data = fixture({ context: { notes: ["review-only"] } });
  const m = E.create(data, SHA);
  data.bindings[0].fields.hero = "Ana";
  data.observations[0].hero = "Mercy";
  data.context.notes[0] = "changed";
  assert.equal(E.identityAt(m, key, false, 12).fields.hero, "Tracer");
  assert.equal(E.rosterAt(m, 12)[0].hero, "Tracer");
  assert.deepEqual(m.context.notes, ["review-only"]);
  assert.throws(() => {
    m.bindings[0].fields.hero = "Winston";
  }, TypeError);
  const identity = E.identityAt(m, key, false, 12);
  identity.fields.hero = "Winston";
  identity.evidence.length = 0;
  assert.equal(E.identityAt(m, key, false, 12).fields.hero, "Tracer");
  assert.equal(E.identityAt(m, key, false, 12).evidence.length, 1);
});
test("requires nonempty proof, valid scopes, known statuses and supported fields", () => {
  const invalid = [
    { evidence: [] },
    { evidence: "video proof" },
    { evidence: [{ video_seconds: -1, note: "bad time" }] },
    { evidence: [{ video_seconds: 12, note: " " }] },
    { evidence: [{ video_seconds: 12, note: "proof", key }] },
    { fields: {} },
    { fields: { visible: true } },
    { fields: { team: "enemy" } },
    { fields: { hero: " " } },
    { start_seconds: NaN },
    { start_seconds: -1 },
    { end_seconds: Infinity },
    { end_seconds: 10 },
    { end_seconds: 9 },
    { status: "verified" },
    { target: "self" },
    { key: " " },
  ];
  for (const patch of invalid)
    assert.throws(() => E.create(fixture({ bindings: [binding(patch)] }), SHA));
  const noSelector = binding();
  delete noSelector.key;
  assert.throws(() => E.create(fixture({ bindings: [noSelector] }), SHA));
  assert.throws(() =>
    E.create(fixture({ bindings: [{ ...noSelector, target: "allies" }] }), SHA),
  );
});
test("validates video observation proof, teams, timestamps and retrospective flags", () => {
  for (const patch of [
    { video_seconds: -1 },
    { video_seconds: Infinity },
    { video_seconds: "12" },
    { player_name: "" },
    { hero: null },
    { team: "enemy" },
    { evidence: [] },
    { evidence: "" },
    { retrospective: "true" },
  ])
    assert.throws(() =>
      E.create(fixture({ observations: [observation(patch)] }), SHA),
    );
  const m = E.create(
    fixture({
      observations: [
        observation({
          evidence: [{ video_seconds: 12, note: "Visible nameplate." }],
        }),
      ],
    }),
    SHA,
  );
  assert.equal(m.observations[0].evidence[0].note, "Visible nameplate.");
});
test("bounds array counts and text, including aggregate proof and nested context", () => {
  const invalid = [
    fixture({
      observations: Array(E.LIMITS.observations + 1).fill(observation()),
    }),
    fixture({ bindings: Array(E.LIMITS.bindings + 1).fill(binding()) }),
    fixture({ bindings: [binding({ key: "k".repeat(E.LIMITS.key + 1) })] }),
    fixture({
      bindings: [binding({ fields: { hero: "h".repeat(E.LIMITS.label + 1) } })],
    }),
    fixture({
      bindings: [
        binding({
          evidence: Array(E.LIMITS.evidencePerBinding + 1).fill({
            video_seconds: 1,
            note: "proof",
          }),
        }),
      ],
    }),
    fixture({
      observations: [observation({ evidence: "e".repeat(E.LIMITS.note + 1) })],
    }),
    fixture({ context: "x".repeat(E.LIMITS.contextText + 1) }),
    fixture({ context: [[[[["too deep"]]]]] }),
    fixture({ context: Array(65).fill(null) }),
    fixture({ context: { value: Infinity } }),
    fixture({ context: JSON.parse('{"__proto__":{"hero":"Ana"}}') }),
  ];
  for (const data of invalid) assert.throws(() => E.create(data, SHA));
  const proof = Array(E.LIMITS.evidencePerBinding).fill({
    video_seconds: 1,
    note: "proof",
  });
  assert.throws(
    () =>
      E.create(
        fixture({
          bindings: Array(
            Math.floor(E.LIMITS.evidenceTotal / proof.length) + 1,
          ).fill(binding({ evidence: proof })),
        }),
        SHA,
      ),
    /Total evidence/,
  );
});
test("empty valid evidence remains unknown and accepts zero-time sightings", () => {
  const m = E.create(fixture({ bindings: [], observations: [] }), SHA);
  assert.deepEqual(E.identityAt(m, key, true, 0), emptyIdentity());
  assert.deepEqual(E.rosterAt(m, 0), []);
  const zero = E.create(
    fixture({ observations: [observation({ video_seconds: 0 })] }),
    SHA,
  );
  assert.equal(E.rosterAt(zero, 0)[0].hero, "Tracer");
});
