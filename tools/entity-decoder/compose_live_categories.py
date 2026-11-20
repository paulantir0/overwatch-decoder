"""Compose private live category admission from explicitly reviewed inputs.

No process access, game layout, automatic roster/mode review, or future-session
admission is provided. The caller supplies complete native acquisition bytes,
actual session/segment start artifacts, and a overwatch-decoder.live-category-composition-review/1.
That review pins the exact target/profile/acquisition/start-event hashes plus:

* native_review_sha256 and roster_review_sha256: existing semantic reviews;
* current_roster_review_sha256: overwatch-decoder.live-controller-roster-review/1, reviewed by
  manual_current_controller_roster, with target/build/mode/self, complete=true,
  sources and controllers [{controller_object_key, role}];
* layout_review_sha256: overwatch-decoder.live-category-layout-review/1, reviewed by
  manual_recipe_native_layout, bound to build/profile/recipe/native review;
* sources: explicitly reviewed current-mode evidence artifact hashes.

The layout supplies controllers (four identity field names), bindings (the live
contract binding fields/guard IDs/conditions), and each binding's initial_read:
{purpose, stage, requested_bytes, flags_byte_offset}. Conditions use an explicit
address, or {base_field, byte_offset}; no offsets or masks are defaulted. Only the
protocol's direct i32 word width and GuardedRelations field conventions are known.
The epoch review must use review_method=manual_current_live_epoch and pin every
input hash, mode and self. Its public_state_eligible must be false and visibility
unknown. Reviews validate evidence scope; this tool cannot verify screenshots or
turn an unreviewed input into runtime/UI proof.

compose_live_categories returns contract/mode_review/preflight bytes and a hash to
bytes artifact map. The mode review pins the caller's epoch/layout/current-roster
reviews. The existing GuardedLiveCategories constructor and guarded preflight run
before output. A factory may then load the contract with the unchanged live
adapter; accepted frame envelopes and lifecycle sequencing remain its job.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import re

from categories import InvalidCategoryEvidence, _digest, _int, _need, _parse, _sha
from live_categories import GuardedLiveCategories
from relations import GuardedRelations

MAX_ARTIFACT = 16 * 1024 * 1024
MAX_EVIDENCE = 64 * 1024 * 1024


def _json(raw, maximum=262144):
    _need(isinstance(raw, bytes) and len(raw) <= maximum, "composition_input_size")
    try:
        value = _parse(raw)
    except (UnicodeDecodeError, ValueError) as error:
        raise InvalidCategoryEvidence("composition_invalid_json") from error
    _need(isinstance(value, dict), "composition_json_object")
    return value


def _encode(value):
    return (json.dumps(value, indent=2, allow_nan=False) + "\n").encode()


def compose_live_categories(*, profile, acquisition_manifest, evidence, recipe,
                            session_start, segment_start, composition_review, artifacts):
    """Validate one caller-reviewed epoch and return portable admission artifacts.

    All arguments except artifacts are raw bytes. No artifact paths are inferred.
    Native strict acquisition/source verification remains a caller prerequisite;
    these byte/source checks and preflight do not replace that verification.
    """
    r = GuardedRelations(profile)
    manifest = _json(acquisition_manifest)
    session, segment, review = map(_json, (session_start, segment_start, composition_review))
    _need(isinstance(evidence, bytes) and len(evidence) <= MAX_EVIDENCE
          and isinstance(recipe, bytes) and len(recipe) <= MAX_ARTIFACT, "composition_source_size")
    source = dict(recipe_sha256=_sha(recipe), evidence_sha256=_sha(evidence))
    _need(manifest.get("schema") == "overwatch-decoder.acquisition-result/1" and manifest.get("complete") is True
          and manifest.get("target") == r.target and manifest.get("profile_sha256") == r.hash
          and all(manifest.get(k) == v for k, v in source.items()), "composition_acquisition_mismatch")
    _need(review.get("schema") == "overwatch-decoder.live-category-composition-review/1"
          and review.get("reviewed") is True and review.get("review_method") == "manual_current_live_epoch"
          and review.get("public_state_eligible") is False and review.get("visibility") == "unknown",
          "composition_current_epoch_review_required")
    _need(not {"recording_manifest_sha256", "frame_scope"} & set(review), "composition_not_finite_recording")
    pins = dict(target=r.target, profile_sha256=r.hash, build_sha256=r.target["executable_sha256"],
                acquisition_manifest_sha256=_sha(acquisition_manifest), session_start_sha256=_sha(session_start),
                segment_start_sha256=_sha(segment_start), **source)
    _need(all(review.get(k) == v for k, v in pins.items()), "composition_epoch_pin_mismatch")
    _need(isinstance(artifacts, dict) and len(artifacts) <= 256, "composition_artifacts_required")
    available = dict(artifacts)
    used, total = set(), 0

    def artifact(digest):
        nonlocal total
        digest = _digest(digest)
        raw = available.get(digest)
        _need(isinstance(raw, bytes) and len(raw) <= MAX_ARTIFACT and _sha(raw) == digest,
              "composition_artifact_hash_or_size")
        if digest not in used:
            used.add(digest); total += len(raw)
            _need(total <= 64 * 1024 * 1024, "composition_artifact_total_size")
        return raw

    def add(raw):
        digest = _sha(raw)
        _need(digest not in available or available[digest] == raw, "composition_artifact_conflict")
        available[digest] = raw
        artifact(digest)
        return digest

    def sources(obj, minimum=1):
        values = obj.get("sources")
        _need(isinstance(values, list) and minimum <= len(values) <= 32
              and all(isinstance(v, str) for v in values)
              and len(set(values)) == len(values), "composition_review_sources")
        for value in values:
            artifact(value)
        return values

    native_hash = _digest(review.get("native_review_sha256"))
    roster_hash = _digest(review.get("roster_review_sha256"))
    native = _json(artifact(native_hash))
    roster = _json(artifact(roster_hash))
    layout_hash = _digest(review.get("layout_review_sha256"))
    current_hash = _digest(review.get("current_roster_review_sha256"))
    layout, current = _json(artifact(layout_hash)), _json(artifact(current_hash))
    build = r.target["executable_sha256"]
    mode, self_key = review.get("mode_id"), review.get("self_controller_object_key")
    _need(native.get("build_sha256") == roster.get("build_sha256") == build
          and roster.get("mode_id") == mode and roster.get("self_controller_object_key") == self_key,
          "composition_semantic_review_scope")
    _need(layout.get("schema") == "overwatch-decoder.live-category-layout-review/1" and layout.get("reviewed") is True
          and layout.get("review_method") == "manual_recipe_native_layout"
          and all(layout.get(k) == v for k, v in dict(build_sha256=build, profile_sha256=r.hash,
              recipe_sha256=source["recipe_sha256"], native_review_sha256=native_hash).items()),
          "composition_layout_review_scope")
    sources(layout)
    _need(current.get("schema") == "overwatch-decoder.live-controller-roster-review/1" and current.get("reviewed") is True
          and current.get("review_method") == "manual_current_controller_roster" and current.get("complete") is True
          and all(current.get(k) == v for k, v in dict(target=r.target, build_sha256=build,
              mode_id=mode, self_controller_object_key=self_key).items()), "composition_current_roster_scope")
    sources(current, 2)
    members = current.get("controllers")
    _need(isinstance(members, list) and 1 <= len(members) <= 128, "composition_current_roster_members")
    by_controller = {}
    for member in members:
        _need(isinstance(member, dict), "composition_current_roster_member")
        ck, role = member.get("controller_object_key"), member.get("role")
        _need(isinstance(ck, str) and re.fullmatch(r"controller:[0-9a-f]{64}", ck) is not None
              and ck not in by_controller and role in ("self", "friendly", "enemy"),
              "composition_current_roster_member")
        by_controller[ck] = role
    _need([k for k, v in by_controller.items() if v == "self"] == [self_key], "composition_current_roster_self")
    for anchor in roster.get("anchors", []):
        ck = anchor.get("controller_object_key")
        _need(ck not in by_controller or by_controller[ck] == anchor.get("role"),
              "composition_current_roster_anchor_conflict")
    mode_sources = sources(review)
    bindings = layout.get("bindings")
    _need(isinstance(bindings, list) and 1 <= len(bindings) <= 32, "composition_layout_bindings")
    resolved = []
    for binding in bindings:
        _need(isinstance(binding, dict), "composition_layout_binding")
        item = {k: copy.deepcopy(binding.get(k)) for k in (
            "body_handle_field", "body_creation_key_field", "flags_field", "required_guard_ids")}
        conditions = binding.get("conditions")
        _need(isinstance(conditions, list), "composition_layout_conditions")
        item["conditions"] = []
        for condition in conditions:
            _need(isinstance(condition, dict), "composition_layout_condition")
            out = {k: condition.get(k) for k in ("role", "width", "mask", "equals")}
            if "address" in condition:
                _need(not {"base_field", "byte_offset"} & set(condition), "composition_condition_address_ambiguous")
                out["address"] = condition["address"]
            else:
                base, offset = condition.get("base_field"), condition.get("byte_offset")
                _need(isinstance(base, str) and base in r.fields and _int(offset), "composition_condition_layout_missing")
                address = r.fields[base].get("address")
                _need(_int(address), "composition_condition_base_address")
                out["address"] = address + offset
            item["conditions"].append(out)
        resolved.append(item)
    scope = dict(session_id=session.get("session_id"), segment=segment.get("segment"),
                 start_ticks=segment.get("start_ticks"), monotonic_frequency=session.get("monotonic_frequency"),
                 session_start_sha256=add(session_start), segment_start_sha256=add(segment_start))
    review_hash = add(composition_review)
    add(acquisition_manifest)
    mode_review = dict(schema="overwatch-decoder.live-category-mode-review/1", reviewed=True,
        review_method="manual_controlled_live_epoch", mode_id=mode, target=r.target,
        profile_sha256=r.hash, acquisition_manifest_sha256=pins["acquisition_manifest_sha256"],
        self_controller_object_key=self_key, live_scope=scope, native_review_sha256=native_hash,
        roster_review_sha256=roster_hash,
        sources=list(dict.fromkeys([review_hash, layout_hash, current_hash] + mode_sources)))
    _need(len(mode_review["sources"]) <= 32, "composition_mode_source_limit")
    mode_raw = _encode(mode_review)
    contract = dict(schema="overwatch-decoder.live-category-contract/1", profile_sha256=r.hash, target=r.target,
        build_sha256=build, mode_id=mode, self_controller_object_key=self_key, source=source,
        observer_revision=session.get("revision"), acquisition_manifest_sha256=pins["acquisition_manifest_sha256"],
        session_start_sha256=scope["session_start_sha256"], segment_start_sha256=scope["segment_start_sha256"],
        native_review_sha256=native_hash, roster_review_sha256=roster_hash,
        mode_review_sha256=add(mode_raw), bindings=resolved)
    contract_raw = _encode(contract)
    projector = GuardedLiveCategories(profile, contract_raw, available)

    def key(role, names):
        words = []
        for name in names:
            address, value = r._binding(name)
            words.append(dict(address=address, value=value))
        return r._key(role, words)

    declared = layout.get("controllers")
    _need(isinstance(declared, list) and len(declared) == len(r.prefixes), "composition_selected_controllers")
    selected, bodies, names = set(), {}, set()
    for entry in declared:
        _need(isinstance(entry, dict), "composition_controller_protocol")
        handle, creation = entry.get("controller_handle_field"), entry.get("controller_creation_key_field")
        _need(isinstance(handle, str) and handle.endswith("_handle_candidate_i32"), "composition_controller_protocol")
        prefix = handle[:-len("_handle_candidate_i32")]
        _need(prefix in r.prefixes and creation == prefix + "_manager_key_candidate_i32"
              and prefix not in names, "composition_controller_protocol")
        names.add(prefix)
        bh, bk = entry.get("body_handle_field"), entry.get("body_creation_key_field")
        _need(isinstance(bh, str) and re.fullmatch(re.escape(prefix) + r"_body_[0-9]{4}_handle_candidate_i32", bh)
              and bk == bh[:-len("_handle_candidate_i32")] + "_manager_key_candidate_i32",
              "composition_body_protocol")
        ck = key("controller", [handle, creation]); body = key("body", [bh, bk])
        _need(ck in by_controller and ck not in selected and body not in bodies,
              "composition_unreviewed_or_duplicate_current_object")
        selected.add(ck); bodies[body] = ck
    _need(self_key in selected, "composition_selected_self_missing")
    try:
        reads = [_json(line, MAX_ARTIFACT) for line in evidence.splitlines() if line.strip()]
    except InvalidCategoryEvidence as error:
        raise InvalidCategoryEvidence("composition_evidence_json") from error
    self_anchors = [a for a in roster.get("anchors", []) if a.get("role") == "self"]
    _need(len(self_anchors) == 1, "composition_self_category_missing")
    self_category = self_anchors[0]["category"]
    rows = []
    for binding, layout_binding in zip(projector.bindings, bindings):
        body = key("body", [binding["body_handle_field"], binding["body_creation_key_field"]])
        _need(body in bodies, "composition_unselected_category_body")
        ck = bodies[body]; address = r.fields[binding["flags_field"]]["address"]
        selector = layout_binding.get("initial_read", {})
        _need(isinstance(selector, dict), "composition_initial_read_layout")
        size, offset = selector.get("requested_bytes"), selector.get("flags_byte_offset")
        _need(_int(size) and 4 <= size <= 64 and _int(offset) and 0 <= offset <= size - 4
              and all(isinstance(selector.get(k), str) and selector[k] for k in ("purpose", "stage")),
              "composition_initial_read_layout")
        candidates = [read for read in reads if read.get("kind") == "read"
            and all(read.get(k) == selector[k] for k in ("purpose", "stage", "requested_bytes"))
            and read.get("address") == address - offset]
        _need(len(candidates) == 1, "composition_initial_read_missing_or_ambiguous")
        read = candidates[0]
        try:
            data = bytes.fromhex(read.get("bytes_hex", ""))
        except (TypeError, ValueError) as error:
            raise InvalidCategoryEvidence("composition_initial_read_bytes") from error
        _need(read.get("attempted") is True and read.get("returned_bytes") == size
              and read.get("error") is None and len(data) == size
              and _int(read.get("id")) and read["id"] >= 0, "composition_initial_read_failed")
        value = int.from_bytes(data[offset:offset + 4], "little")
        categories = [n for n, bit in enumerate(projector.ordered_bits) if value & (1 << bit)]
        _need(not any(value & (1 << bit) for bit in projector.clear_bits)
              and len(categories) == 1 and categories[0] in projector.supported, "composition_initial_category_unsupported")
        category = categories[0]; role = by_controller[ck]
        _need((category == self_category) == (role in ("self", "friendly")) and category in projector.teams,
              "composition_initial_category_roster_conflict")
        rows.append(dict(controller_object_key=ck, body_object_key=body, role=role, category=category,
                         flags_field=binding["flags_field"], acquisition_read_id=read.get("id")))
    _need(len(rows) == len(selected) and {row["controller_object_key"] for row in rows} == selected,
          "composition_category_coverage")
    preflight = dict(schema="overwatch-decoder.live-category-composition-preflight/1", composition_review_sha256=review_hash,
        current_roster_review_sha256=current_hash, layout_review_sha256=layout_hash, profile_sha256=r.hash,
        acquisition_manifest_sha256=pins["acquisition_manifest_sha256"], live_scope=scope,
        self_controller_object_key=self_key, rows=rows, public_state_eligible=False, visibility="unknown",
        durability_verified=False)
    preflight_raw = _encode(preflight)
    return dict(contract=contract_raw, mode_review=mode_raw, preflight=preflight_raw, artifacts=available)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("profile", "acquisition-manifest", "evidence", "recipe", "session-start", "segment-start",
                 "composition-review", "artifacts", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args(argv)
    paths = _json(args.artifacts.read_bytes(), 1024 * 1024)
    _need(len(paths) <= 256, "composition_artifact_path_limit")
    artifacts = {}
    total_input_bytes = 0
    for digest, path in paths.items():
        _digest(digest)
        _need(isinstance(path, str), "composition_artifact_path")
        location = Path(path).resolve()
        _need(location.stat().st_size <= MAX_ARTIFACT, "composition_artifact_file_size")
        data = location.read_bytes()
        total_input_bytes += len(data)
        _need(total_input_bytes <= 64 * 1024 * 1024, "composition_artifact_total_size")
        _need(_sha(data) == digest, "composition_artifact_hash_or_size")
        artifacts[digest] = data; paths[digest] = str(location)
    inputs = {}
    for name in ("profile", "acquisition_manifest", "evidence", "recipe", "session_start", "segment_start", "composition_review"):
        path = getattr(args, name)
        _need(path.stat().st_size <= (MAX_EVIDENCE if name == "evidence" else MAX_ARTIFACT), "composition_input_file_size")
        inputs[name] = path.read_bytes()
    result = compose_live_categories(**inputs, artifacts=artifacts)
    args.output.mkdir(parents=True, exist_ok=False)
    directory = args.output.resolve(); generated = directory / "artifacts"; generated.mkdir()
    for digest, data in result["artifacts"].items():
        if digest not in paths:
            location = generated / (digest + ".json"); location.write_bytes(data); paths[digest] = str(location)
    for name in ("contract", "mode_review", "preflight"):
        (directory / (name + ".json")).write_bytes(result[name])
    (directory / "artifacts.json").write_bytes(_encode(paths))
    print(json.dumps(dict(contract_sha256=_sha(result["contract"]), preflight_sha256=_sha(result["preflight"]),
                         public_state_eligible=False, visibility="unknown", durability_verified=False)))


if __name__ == "__main__":
    main()
