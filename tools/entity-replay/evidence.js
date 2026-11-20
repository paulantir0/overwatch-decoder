/* Private replay labels: a video sighting is never an object association. */
(function (root, factory) {
  "use strict";
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.OverwatchDecoderReplayEvidence = api;
})(typeof globalThis === "object" ? globalThis : this, function () {
  "use strict";
  const LIMITS = Object.freeze({
    observations: 10000,
    bindings: 10000,
    evidencePerBinding: 32,
    evidenceTotal: 100000,
    label: 100,
    key: 512,
    note: 2000,
    contextText: 8192,
  });
  const models = new WeakSet();
  const teams = new Set(["self", "ally", "opponent", "unknown"]);
  const fieldNames = ["player_name", "hero", "team", "kind"];
  const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
  const finiteTime = (value) =>
    typeof value === "number" && Number.isFinite(value) && value >= 0;
  const plain = (value) =>
    value !== null &&
    typeof value === "object" &&
    (Object.getPrototypeOf(value) === Object.prototype ||
      Object.getPrototypeOf(value) === null);
  function assert(ok, message) {
    if (!ok) throw new Error(message);
  }
  function keys(value, allowed, label) {
    assert(plain(value), `Invalid ${label}.`);
    assert(
      Object.keys(value).every((key) => allowed.includes(key)),
      `Unsupported ${label} field.`,
    );
  }
  function text(value, max, label, trim = true) {
    assert(
      typeof value === "string" &&
        value.length <= max &&
        value.trim().length > 0 &&
        !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value),
      `Invalid or oversized ${label}.`,
    );
    return trim ? value.trim() : value;
  }
  function sha(value) {
    assert(
      typeof value === "string" && /^[a-f\d]{64}$/i.test(value),
      "A SHA-256 source digest is required.",
    );
    return value.toLowerCase();
  }
  function fields(value) {
    keys(value, fieldNames, "identity fields");
    assert(Object.keys(value).length > 0, "Empty identity fields.");
    const result = {};
    for (const name of fieldNames) {
      if (!own(value, name)) continue;
      result[name] = text(value[name], LIMITS.label, name);
      if (name === "team") assert(teams.has(result[name]), "Invalid team.");
    }
    return result;
  }
  function freeze(value) {
    if (value && typeof value === "object") {
      Object.values(value).forEach(freeze);
      Object.freeze(value);
    }
    return value;
  }
  // Context is review-only JSON metadata; it cannot supply identity fields.
  function context(value) {
    let count = 0,
      characters = 0;
    function copy(item, depth) {
      assert(depth <= 4 && ++count <= 256, "Oversized context.");
      if (item === null || typeof item === "boolean") return item;
      if (typeof item === "number") {
        assert(Number.isFinite(item), "Invalid context number.");
        return item;
      }
      if (typeof item === "string") {
        characters += item.length;
        assert(characters <= LIMITS.contextText, "Oversized context text.");
        return item;
      }
      if (Array.isArray(item)) {
        assert(item.length <= 64, "Oversized context array.");
        return item.map((entry) => copy(entry, depth + 1));
      }
      assert(plain(item), "Invalid context.");
      const entries = Object.entries(item);
      assert(entries.length <= 64, "Oversized context object.");
      const result = {};
      for (const [key, entry] of entries) {
        assert(
          key.length <= LIMITS.label &&
            !["__proto__", "constructor", "prototype"].includes(key),
          "Invalid context key.",
        );
        characters += key.length;
        assert(characters <= LIMITS.contextText, "Oversized context text.");
        result[key] = copy(entry, depth + 1);
      }
      return result;
    }
    return copy(value, 0);
  }
  function create(data, expectedSourceSha) {
    keys(
      data,
      ["schema", "source_sha256", "observations", "bindings", "context"],
      "evidence document",
    );
    assert(
      data.schema === "overwatch-decoder.replay-evidence/1",
      "Unsupported evidence schema.",
    );
    const source = sha(data.source_sha256);
    assert(
      source === sha(expectedSourceSha),
      "Evidence source SHA-256 mismatch.",
    );
    for (const name of ["observations", "bindings"]) {
      assert(
        Array.isArray(data[name]) && data[name].length <= LIMITS[name],
        `Invalid or oversized ${name}.`,
      );
    }
    let evidenceCount = 0;
    function evidenceRecords(value) {
      assert(
        Array.isArray(value) &&
          value.length > 0 &&
          value.length <= LIMITS.evidencePerBinding,
        "A bounded, nonempty evidence list is required.",
      );
      evidenceCount += value.length;
      assert(
        evidenceCount <= LIMITS.evidenceTotal,
        "Total evidence limit exceeded.",
      );
      return value.map((entry) => {
        keys(entry, ["video_seconds", "note"], "evidence record");
        assert(finiteTime(entry.video_seconds), "Invalid evidence video time.");
        return {
          video_seconds: entry.video_seconds,
          note: text(entry.note, LIMITS.note, "evidence note"),
        };
      });
    }
    const observations = data.observations.map((observation) => {
      keys(
        observation,
        [
          "player_name",
          "hero",
          "team",
          "video_seconds",
          "evidence",
          "retrospective",
        ],
        "video observation",
      );
      assert(
        finiteTime(observation.video_seconds),
        "Invalid observation video time.",
      );
      assert(
        observation.retrospective === undefined ||
          typeof observation.retrospective === "boolean",
        "Invalid retrospective flag.",
      );
      const identity = fields({
        player_name: observation.player_name,
        hero: observation.hero,
        team: observation.team,
      });
      return {
        ...identity,
        video_seconds: observation.video_seconds,
        evidence:
          typeof observation.evidence === "string"
            ? text(observation.evidence, LIMITS.note, "observation evidence")
            : evidenceRecords(observation.evidence),
        retrospective: observation.retrospective === true,
      };
    });
    const bindings = data.bindings.map((binding) => {
      keys(
        binding,
        [
          "key",
          "target",
          "start_seconds",
          "end_seconds",
          "status",
          "fields",
          "evidence",
        ],
        "object binding",
      );
      const hasKey = own(binding, "key"),
        hasTarget = own(binding, "target");
      assert(
        hasKey !== hasTarget,
        "Binding requires exactly one key or self target.",
      );
      assert(
        !hasTarget || binding.target === "self",
        "Only self is a valid target.",
      );
      assert(
        finiteTime(binding.start_seconds) &&
          finiteTime(binding.end_seconds) &&
          binding.end_seconds > binding.start_seconds,
        "Invalid binding time interval.",
      );
      assert(
        ["video_matched", "candidate"].includes(binding.status),
        "Invalid binding validation status.",
      );
      return {
        ...(hasKey
          ? { key: text(binding.key, LIMITS.key, "object key", false) }
          : { target: "self" }),
        start_seconds: binding.start_seconds,
        end_seconds: binding.end_seconds,
        status: binding.status,
        fields: fields(binding.fields),
        evidence: evidenceRecords(binding.evidence),
      };
    });
    const result = {
      schema: data.schema,
      source_sha256: source,
      observations,
      bindings,
      ...(own(data, "context") ? { context: context(data.context) } : {}),
    };
    freeze(result);
    models.add(result);
    return result;
  }
  function unknown() {
    return { fields: {}, status: "unknown", candidates: [], evidence: [] };
  }
  // sessionTime is acquisition-session time; evidence video times are review links.
  function identityAt(evidence, objectKey, isSelf, sessionTime, active = true) {
    if (!models.has(evidence) || active !== true || !finiteTime(sessionTime))
      return unknown();
    const result = unknown(),
      values = new Map(fieldNames.map((name) => [name, new Set()]));
    let matched = false;
    for (const binding of evidence.bindings) {
      if (
        sessionTime < binding.start_seconds ||
        sessionTime >= binding.end_seconds ||
        !(own(binding, "key") ? binding.key === objectKey : isSelf === true)
      )
        continue;
      result.evidence.push(...binding.evidence);
      if (binding.status === "candidate") {
        result.candidates.push(binding);
        continue;
      }
      matched = true;
      for (const [name, value] of Object.entries(binding.fields))
        values.get(name).add(value);
    }
    let conflict = false;
    for (const [name, choices] of values) {
      if (choices.size === 1)
        result.fields[name] = choices.values().next().value;
      else if (choices.size > 1) conflict = true;
    }
    result.status = conflict
      ? "conflict"
      : matched
        ? "video_matched"
        : result.candidates.length
          ? "candidate"
          : "unknown";
    return result;
  }
  // A roster is independent video evidence, never a map of memory-object keys.
  function rosterAt(evidence, videoTime) {
    if (!models.has(evidence) || !finiteTime(videoTime)) return [];
    const latest = new Map();
    for (const observation of evidence.observations) {
      if (observation.retrospective || observation.video_seconds > videoTime)
        continue;
      const name = observation.player_name.toLowerCase(),
        previous = latest.get(name);
      if (!previous || observation.video_seconds >= previous.video_seconds)
        latest.set(name, observation);
    }
    return [...latest.values()].map((observation) => ({
      player_name: observation.player_name,
      hero: observation.hero,
      team: observation.team,
      video_seconds: observation.video_seconds,
      observed_at: {
        player_name: observation.video_seconds,
        hero: observation.video_seconds,
        team: observation.video_seconds,
      },
      evidence: observation.evidence,
    }));
  }
  return Object.freeze({ create, identityAt, rosterAt, LIMITS });
});
