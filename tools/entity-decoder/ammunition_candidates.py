"""Guarded, reviewed ammunition candidates from explicitly named scalar words.

No process access, application offsets, calls into the target, firing detector,
or target-code execution. Native acquisition verification is a caller prerequisite.
An active expression exposes a sampled cache. An optional separately reviewed
callback reconstruction retains its sequential-read and floating-point assumptions.
Optional empirical template reviews admit fresh storage only inside an explicit
controlled-participant/hero scope; generic getter identity alone is not ammo proof.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import struct

from relations import GuardedRelations, InvalidBinding, _unique_object


class InvalidAmmunitionEvidence(ValueError):
    pass


def _need(value, reason):
    if not value:
        raise InvalidAmmunitionEvidence(reason)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _parse(raw):
    try:
        return json.loads(raw, object_pairs_hook=_unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, TypeError, UnicodeError) as error:
        raise InvalidAmmunitionEvidence("invalid_json") from error


ROLES = ("expression_count", "base_bits", "base_type", "cached_bits", "cached_type",
         "cached_tick", "flags")
CALLBACK_ROLES = ("count_after", "capacity", "descriptor_child_low", "descriptor_child_high",
                  "descriptor_selector", "descriptor_operand_count", "descriptor_value_count",
                  "clock_low", "clock_high", "timestamp_a_low", "timestamp_a_high",
                  "timestamp_b_low", "timestamp_b_high", "integer_base", "integer_multiplier",
                  "integer_offset", "curve_base_bits", "curve_slope_bits", "enabled_flags")


def _storage_pin(raw_profile, fields, roles, schema):
    relation = GuardedRelations(raw_profile)
    _need(isinstance(fields, dict) and set(fields) == set(roles)
          and all(isinstance(n, str) and n in relation.fields for n in fields.values()), "scalar_bindings")
    description = dict(schema=schema, fields={
        role: dict(name=name, type=relation.fields[name].get("type"),
                   address=relation.fields[name].get("address")) for role, name in fields.items()})
    return _sha(json.dumps(description, sort_keys=True, separators=(",", ":"), allow_nan=False).encode())


def ammunition_storage_binding_sha256(raw_profile: bytes, fields: dict[str, str]) -> str:
    """HUD storage pin; adding tick fields preserves it, moving a scalar cannot."""
    return _storage_pin(raw_profile, fields, ROLES, "overwatch-decoder.ammunition-storage-binding/1")


def ammunition_tick_binding_sha256(raw_profile: bytes, fields: dict[str, str]) -> str:
    """Native-review pin for the direct/virtual tick-role assignment."""
    return _storage_pin(raw_profile, fields, ("direct_tick", "direct_branch", "virtual_tick"),
                        "overwatch-decoder.ammunition-tick-binding/1")


def ammunition_callback_binding_sha256(raw_profile: bytes, callback: dict) -> str:
    """Pin role addresses and the reviewed descriptor target/capacity together."""
    _need(isinstance(callback, dict) and set(callback) == {
        "fields", "expected_child_pointer", "expected_capacity"}, "callback_binding")
    child, capacity = callback["expected_child_pointer"], callback["expected_capacity"]
    _need(type(child) is int and 0 < child < (1 << 47) and child % 8 == 0
          and type(capacity) is int and capacity == 1, "callback_target_or_capacity")
    storage = _storage_pin(raw_profile, callback["fields"], CALLBACK_ROLES,
                           "overwatch-decoder.ammunition-callback-storage/1")
    return _sha(json.dumps(dict(storage_sha256=storage, expected_child_pointer=child,
                               expected_capacity=capacity), sort_keys=True,
                           separators=(",", ":")).encode())


def _recipe_selector(document, pointer):
    """Resolve only a caller-reviewed JSON leaf; never evaluate recipe code."""
    _need(isinstance(pointer, str) and pointer.startswith("/") and len(pointer) <= 512,
          "semantic_selector_pointer")
    parts = pointer[1:].split("/")
    current = document
    try:
        for part in parts[:-1]:
            token = part.replace("~1", "/").replace("~0", "~")
            current = current[int(token)] if isinstance(current, list) else current[token]
        token = parts[-1].replace("~1", "/").replace("~0", "~")
        key = int(token) if isinstance(current, list) else token
        return current, key, current[key]
    except (KeyError, IndexError, TypeError, ValueError) as error:
        raise InvalidAmmunitionEvidence("semantic_selector_pointer") from error


def _signed(value, bits):
    return (value + (1 << (bits - 1))) % (1 << bits) - (1 << (bits - 1))


def _float_bits(bits):
    return struct.unpack("<f", (bits & 0xffffffff).to_bytes(4, "little"))[0]


def _f32(value):
    try:
        result = struct.unpack("<f", struct.pack("<f", value))[0]
    except (OverflowError, struct.error) as error:
        raise InvalidBinding("unsupported_callback_numeric_state") from error
    if not math.isfinite(result) or 0 < abs(result) < 2 ** -126:
        raise InvalidBinding("unsupported_callback_numeric_state")
    return result


def _i64_to_f32(value):
    # Avoid int64 -> binary64 -> binary32 double rounding at halfway integers.
    magnitude = abs(value)
    shift = max(magnitude.bit_length() - 24, 0)
    upper = magnitude >> shift
    if shift:
        tail, halfway = magnitude & ((1 << shift) - 1), 1 << (shift - 1)
        upper += tail > halfway or tail == halfway and bool(upper & 1)
    return math.ldexp(-upper if value < 0 else upper, shift)


def _callback_integer(values, algorithm):
    """Only the reviewed zero-slope branch, with separate native f32 rounding."""
    def qword(role):
        return _signed((values[role + "_low"] & 0xffffffff)
                       | (values[role + "_high"] & 0xffffffff) << 32, 64)
    clock, a, b = [qword(role) for role in ("clock", "timestamp_a", "timestamp_b")]
    elapsed = _signed((0 if clock < a else _signed(clock - a, 64)) - b, 64)
    slope, rate = [_float_bits(values[role]) for role in ("curve_slope_bits", "curve_base_bits")]
    if not math.isfinite(slope) or slope != 0:
        raise InvalidBinding("unsupported_callback_curve")
    if not math.isfinite(rate) or rate < 0 or 0 < rate < 2 ** -126:
        raise InvalidBinding("unsupported_callback_numeric_state")
    seconds = _f32(_i64_to_f32(elapsed) * _float_bits(algorithm["clock_scale_f32_bits"]))
    if seconds < 0:
        index = -1
    else:
        integral = _f32(seconds * rate)
        # Exceptional CVTTSS2SI results are deliberately unsupported.
        if not -(1 << 31) <= integral < (1 << 31):
            raise InvalidBinding("unsupported_callback_integer_conversion")
        index = math.floor(integral)
    product = _signed(_signed(values["integer_offset"] + index, 32)
                      * values["integer_multiplier"], 32)
    result = max(_signed(values["integer_base"] - product, 32), 0)
    return result, elapsed, index


class GuardedAmmunitionCandidates:
    """One exact acquired profile; stateless, private, visibility unknown.

    The reviewed contract names fields and pins native/HUD evidence for the
    exact process, controller and reciprocal body. Different epochs need fresh
    acquisition pins. This helper does not admit live sessions or verify native
    transports. It cannot establish cache freshness by observing a number.
    """

    def __init__(self, raw_profile: bytes, raw_contract: bytes, artifacts: dict[str, bytes]):
        self.relations = GuardedRelations(raw_profile)
        _need(isinstance(raw_contract, bytes) and len(raw_contract) <= 262144, "contract_size")
        self.contract_sha256 = _sha(raw_contract)
        c = _parse(raw_contract)
        _need(isinstance(c, dict) and c.get("schema") == "overwatch-decoder.ammunition-candidate-contract/1",
              "contract_schema")
        _need(c.get("profile_sha256") == self.relations.hash
              and c.get("target") == self.relations.target
              and c.get("build_sha256") == self.relations.target["executable_sha256"],
              "profile_target_build_mismatch")
        seen, total = set(), 0

        def artifact(digest):
            nonlocal total
            _need(isinstance(digest, str) and len(digest) == 64
                  and all(x in "0123456789abcdef" for x in digest), "artifact_digest")
            data = artifacts.get(digest)
            _need(isinstance(data, bytes) and len(data) <= 16 * 1024 * 1024
                  and _sha(data) == digest, "artifact_hash_or_size")
            if digest not in seen:
                seen.add(digest)
                total += len(data)
                _need(total <= 64 * 1024 * 1024, "artifact_total_size")
            return data

        source = c.get("source")
        _need(isinstance(source, dict), "source_missing")
        self.source = {key: source.get(key) for key in ("recipe_sha256", "evidence_sha256")}
        for digest in self.source.values():
            artifact(digest)
        self.acquisition_manifest_sha256 = c.get("acquisition_manifest_sha256")
        manifest = _parse(artifact(self.acquisition_manifest_sha256))
        _need(isinstance(manifest, dict) and manifest.get("schema") == "overwatch-decoder.acquisition-result/1"
              and manifest.get("complete") is True and manifest.get("error") is None
              and manifest.get("target") == self.relations.target
              and manifest.get("profile_sha256") == self.relations.hash
              and all(manifest.get(k) == v for k, v in self.source.items()), "acquisition_scope")
        self.native_review_sha256 = c.get("native_review_sha256")
        semantic_keys = ("semantic_review_sha256", "participant_review_sha256")
        _need(all(k in c for k in semantic_keys) or not any(k in c for k in semantic_keys),
              "semantic_review_pair_required")
        self.semantic = None
        native = _parse(artifact(self.native_review_sha256))
        _need(isinstance(native, dict) and native.get("schema") == "overwatch-decoder.native-scalar-node-review/1"
              and native.get("reviewed") is True
              and native.get("review_method") == "native_consumer_trace"
              and native.get("build_sha256") == self.relations.target["executable_sha256"]
              and (all(k in c for k in semantic_keys)
                   or native.get("recipe_sha256") == self.source["recipe_sha256"]),
              "native_review")
        algorithm = native.get("algorithm", {})
        _need(isinstance(algorithm, dict)
              and algorithm.get("selection") == "base_if_zero_expression_count_else_sampled_cache"
              and algorithm.get("active_cache_policy") == "sampled_not_recomputed",
              "unsupported_selection_or_cache_policy")
        self.int_type, self.float_type = [algorithm.get(k) for k in ("int32_type", "float32_type")]
        _need(all(type(n) is int and 0 <= n < (1 << 31) for n in (self.int_type, self.float_type))
              and self.int_type != self.float_type, "native_numeric_types")
        freshness = algorithm.get("cache_freshness")
        if freshness is not None:
            _need(isinstance(freshness, dict) and set(freshness) == {
                "force_recompute_mask", "tick_check_mask"}, "cache_freshness_algorithm")
            masks = [freshness[k] for k in ("force_recompute_mask", "tick_check_mask")]
            _need(all(type(n) is int and 0 < n <= 0xffffffff for n in masks)
                  and not masks[0] & masks[1], "cache_freshness_masks")
            freshness = freshness.copy()
        self.cache_freshness = freshness
        callback_algorithm = native.get("callback_algorithm")
        if callback_algorithm is not None:
            _need(isinstance(callback_algorithm, dict) and set(callback_algorithm) == {
                "selection", "selector", "enabled_mask", "clock_scale_f32_bits", "rounding_assumption"}
                and callback_algorithm["selection"] == "signed_i64_elapsed_zero_slope_i32_depletion"
                and type(callback_algorithm["selector"]) is int
                and 0 <= callback_algorithm["selector"] < (1 << 31)
                and type(callback_algorithm["enabled_mask"]) is int
                and 0 < callback_algorithm["enabled_mask"] <= 0xffffffff
                and type(callback_algorithm["clock_scale_f32_bits"]) is int
                and 0 <= callback_algorithm["clock_scale_f32_bits"] <= 0xffffffff
                and callback_algorithm["rounding_assumption"] == "binary32_nearest_even_no_flush_to_zero",
                "callback_algorithm")
            scale = _float_bits(callback_algorithm["clock_scale_f32_bits"])
            _need(math.isfinite(scale) and scale >= 2 ** -126, "callback_clock_scale")
            callback_algorithm = callback_algorithm.copy()
        self.callback_algorithm = callback_algorithm
        sources = native.get("sources")
        _need(isinstance(sources, list) and 1 <= len(sources) <= 32, "native_sources")
        for digest in sources:
            artifact(digest)
        if all(k in c for k in semantic_keys):
            self._configure_semantic(c, native, artifact, manifest)
        bindings = c.get("bindings")
        _need(isinstance(bindings, list) and 1 <= len(bindings) <= 32, "bindings")
        self.bindings, prefixes, used = [], set(), set()
        for binding in bindings:
            _need(isinstance(binding, dict), "binding")
            prefix = binding.get("controller_prefix")
            _need(prefix in self.relations.prefixes and prefix not in prefixes, "controller_binding")
            prefixes.add(prefix)
            fields = binding.get("fields")
            _need(isinstance(fields, dict) and set(fields) == set(ROLES)
                  and all(isinstance(n, str) and n in self.relations.fields for n in fields.values())
                  and len(set(fields.values())) == len(ROLES)
                  and not set(fields.values()) & used, "scalar_bindings")
            used.update(fields.values())
            if self.semantic is not None:
                _need(fields == self.semantic["fields"] and "hud_review_sha256" not in binding
                      and binding.get("tick_fields") is None, "semantic_scalar_roles")
            required = binding.get("required_guard_ids")
            _need(isinstance(required, list) and required
                  and all(type(n) is int and 0 <= n < len(self.relations.guards) for n in required)
                  and len(set(required)) == len(required), "route_guard_ids")
            if self.semantic is not None:
                _need(set(required) == set(range(len(self.relations.guards))),
                      "semantic_complete_route_guards")
            for name in fields.values():
                field = self.relations.fields[name]
                _need(field.get("type") == "i32" and type(field.get("address")) is int
                      and 0 < field["address"] < (1 << 63) - 3
                      and not any(k in field for k in ("path", "path_id", "codec"))
                      and set(required).issubset(self.relations.guard_ids[name]), "scalar_route_dependencies")
            tick_fields = binding.get("tick_fields")
            if tick_fields is not None:
                _need(self.cache_freshness is not None and isinstance(tick_fields, dict)
                      and set(tick_fields) == {"direct_tick", "direct_branch", "virtual_tick"}
                      and all(isinstance(n, str) and n in self.relations.fields for n in tick_fields.values())
                      and len(set(tick_fields.values())) == 3
                      and not set(tick_fields.values()) & set(fields.values()), "tick_bindings")
                for role, name in tick_fields.items():
                    declaration = self.relations.fields[name]
                    width = 1 if role == "direct_branch" else 4
                    _need(declaration.get("type") == ("u8" if width == 1 else "i32")
                          and type(declaration.get("address")) is int
                          and 0 < declaration["address"] <= (1 << 63) - width
                          and not any(k in declaration for k in ("path", "path_id", "codec"))
                          and set(required).issubset(self.relations.guard_ids[name]), "tick_route_dependencies")
                approved = native.get("tick_storage_bindings_sha256")
                _need(isinstance(approved, list) and 1 <= len(approved) <= 32
                      and ammunition_tick_binding_sha256(raw_profile, tick_fields) in approved,
                      "native_tick_binding_mismatch")
            callback = binding.get("callback")
            if callback is not None:
                _need(self.callback_algorithm is not None, "missing_callback_algorithm")
                digest = ammunition_callback_binding_sha256(raw_profile, callback)
                names = callback["fields"]
                _need(len(set(names.values())) == len(CALLBACK_ROLES)
                      and not set(names.values()) & (set(fields.values()) | set((tick_fields or {}).values())),
                      "callback_bindings")
                for name in names.values():
                    declaration = self.relations.fields[name]
                    _need(declaration.get("type") == "i32"
                          and type(declaration.get("address")) is int
                          and 0 < declaration["address"] < (1 << 63) - 3
                          and not any(k in declaration for k in ("path", "path_id", "codec"))
                          and set(required).issubset(self.relations.guard_ids[name]),
                          "callback_route_dependencies")
                approved = native.get("callback_storage_bindings_sha256")
                _need(self.semantic is not None or (isinstance(approved, list)
                      and 1 <= len(approved) <= 32 and digest in approved),
                      "native_callback_binding_mismatch")
                if self.semantic is not None:
                    rule = self.semantic["callback"]
                    _need(rule is not None, "semantic_callback_rule")
                    anchor = self.relations.fields.get(rule["child_anchor_field"], {})
                    _need(names == rule["fields"] and anchor.get("type") == "i32"
                          and type(anchor.get("address")) is int
                          and callback["expected_child_pointer"] == anchor["address"] - rule["child_anchor_offset"]
                          and callback["expected_capacity"] == rule["expected_capacity"],
                          "semantic_callback_provider")
                callback = dict(callback, fields=names.copy(), binding_sha256=digest)
            if self.semantic is not None:
                _need((callback is None) == (self.semantic["callback"] is None),
                      "semantic_callback_required")
                _need(binding.get("controller_object_key") == self.semantic["controller"]
                      and binding.get("body_object_key") == self.semantic["body"],
                      "semantic_current_full_pair")
                self.bindings.append(dict(prefix=prefix, fields=fields.copy(),
                    controller=self.semantic["controller"], body=self.semantic["body"],
                    maximum=self.semantic["maximum"], hud_review_sha256=None,
                    tick_fields=None, callback=callback))
                continue
            review_sha = binding.get("hud_review_sha256")
            review = _parse(artifact(review_sha))
            _need(isinstance(review, dict) and review.get("schema") == "overwatch-decoder.ammunition-hud-review/1"
                  and review.get("reviewed") is True and review.get("target") == self.relations.target
                  and review.get("readout") == "ammunition_current"
                  and review.get("native_review_sha256") == self.native_review_sha256,
                  "hud_review")
            _need(review.get("storage_binding_sha256") == ammunition_storage_binding_sha256(raw_profile, fields),
                  "hud_storage_binding_mismatch")
            references = review.get("sources")
            _need(isinstance(references, list) and 1 <= len(references) <= 32, "hud_sources")
            for digest in references:
                artifact(digest)
            ck, bk = binding.get("controller_object_key"), binding.get("body_object_key")
            _need(isinstance(ck, str) and ck.startswith("controller:")
                  and isinstance(bk, str) and bk.startswith("body:")
                  and review.get("controller_object_key") == ck and review.get("body_object_key") == bk,
                  "hud_object_scope")
            maximum = review.get("observed_maximum")
            _need(type(maximum) is int and 0 < maximum < (1 << 31), "reviewed_ammunition_range")
            self.bindings.append(dict(prefix=prefix, fields=fields.copy(), controller=ck, body=bk,
                                      maximum=maximum, hud_review_sha256=review_sha,
                                      tick_fields=None if tick_fields is None else tick_fields.copy(),
                                      callback=callback))

    def _configure_semantic(self, contract, native, artifact, manifest):
        """A reviewed empirical template and a finite current participant scope.

        The generic getter does not establish an ammunition identity. This mode
        pins the whole acquisition program and independent body/HUD evidence;
        it never rewrites an old HUD object's identity into a new HUD review.
        """
        from forward_owner_relations import _verify_acquisition
        r = self.relations
        review = _parse(artifact(contract["semantic_review_sha256"]))
        _need(isinstance(review, dict)
              and review.get("schema") == "overwatch-decoder.ammunition-semantic-template-review/1"
              and review.get("reviewed") is True
              and review.get("review_method") == "native_route_and_independent_body_holdout"
              and review.get("scope") == "controlled_local_participant_standard_primary"
              and review.get("readout") == "ammunition_current"
              and review.get("build_sha256") == r.target["executable_sha256"]
              and review.get("native_review_sha256") == self.native_review_sha256,
              "semantic_review")
        maximum = review.get("observed_maximum")
        _need(type(maximum) is int and 0 < maximum < 2**31, "semantic_range")
        bindings = contract.get("bindings")
        _need(isinstance(bindings, list) and len(bindings) == 1 and isinstance(bindings[0], dict)
              and len(r.prefixes) == 1, "semantic_one_participant")
        binding = bindings[0]
        prefix = binding.get("controller_prefix")
        _need(prefix in r.prefixes, "semantic_controller_prefix")
        def identity(projector, actor_prefix, role):
            words = []
            for suffix in ("_handle_candidate_i32", "_manager_key_candidate_i32"):
                address, value = projector._binding(actor_prefix + suffix)
                words.append(dict(address=address, value=value))
            return projector._key(role, words), words
        try:
            controller, controller_words = identity(r, prefix, "controller")
            body, _ = identity(r, prefix + "_body_0000", "body")
        except (InvalidBinding, KeyError, TypeError) as error:
            raise InvalidAmmunitionEvidence("semantic_current_identity") from error
        participant = _parse(artifact(contract["participant_review_sha256"]))
        _need(isinstance(participant, dict)
              and participant.get("schema") == "overwatch-decoder.ammunition-controlled-participant-review/1"
              and participant.get("reviewed") is True
              and participant.get("review_method") == "controlled_input_and_guarded_controller"
              and participant.get("role") == "controlled_local_participant"
              and participant.get("target") == r.target
              and participant.get("controller_object_key") == controller,
              "semantic_participant_scope")
        interval = participant.get("frame_scope", {})
        _need(isinstance(interval, dict), "semantic_finite_frame_scope")
        frequency, start, end = [interval.get(k) for k in
                                  ("monotonic_frequency", "start_ticks", "end_ticks")]
        _need(set(interval) == {"monotonic_frequency", "start_ticks", "end_ticks"}
              and all(type(v) is int for v in (frequency, start, end))
              and 0 < frequency <= 10**12 and 0 <= start < end
              and end - start <= frequency * 180, "semantic_finite_frame_scope")
        for item in (review, participant):
            sources = item.get("sources")
            _need(isinstance(sources, list) and 1 <= len(sources) <= 32, "semantic_sources")
            for pin in sources:
                artifact(pin)
        recipe = _parse(artifact(self.source["recipe_sha256"]))
        approved = _parse(artifact(review.get("approved_recipe_sha256")))
        _need(review.get("approved_recipe_sha256") == native.get("recipe_sha256")
              and isinstance(recipe, dict) and isinstance(approved, dict)
              and recipe.get("schema") == approved.get("schema") == "overwatch-decoder.acquisition-recipe/1"
              and recipe.get("target") == approved.get("target") == {
                  k: r.target[k] for k in ("image_name", "executable_sha256", "architecture")},
              "semantic_recipe_scope")
        try:
            _verify_acquisition(artifact(self.source["evidence_sha256"]), manifest, recipe, r)
        except (ValueError, KeyError, TypeError) as error:
            raise InvalidAmmunitionEvidence("semantic_acquisition_guard_evidence:" + str(error)) from error
        expected = review.get("approved_controller_words", {})
        roles = ("full_handle_u32", "creation_key_u32")
        _need(isinstance(expected, dict) and set(expected) == set(roles)
              and all(type(expected[k]) is int and 0 <= expected[k] < 2**32 for k in roles),
              "semantic_approved_controller_words")
        relocations = review.get("selector_relocations")
        _need(isinstance(relocations, list) and 2 <= len(relocations) <= 16,
              "semantic_selector_relocations")
        recipe, approved = copy.deepcopy(recipe), copy.deepcopy(approved)
        seen, seen_roles = set(), set()
        current = dict(zip(roles, (w["value"] for w in controller_words)))
        for relocation in relocations:
            _need(isinstance(relocation, dict) and set(relocation) == {"pointer", "role"}
                  and relocation.get("role") in roles
                  and isinstance(relocation.get("pointer"), str)
                  and relocation["pointer"] not in seen, "semantic_selector_relocations")
            pointer, role = relocation["pointer"], relocation["role"]
            seen.add(pointer); seen_roles.add(role)
            new_parent, new_key, new = _recipe_selector(recipe, pointer)
            old_parent, old_key, old = _recipe_selector(approved, pointer)
            _need(type(new) is int and type(old) is int
                  and new == current[role] and old == expected[role], "semantic_selector_identity")
            new_parent[new_key] = old_parent[old_key] = {"reviewed_controller_word": role}
        _need(seen_roles == set(roles) and recipe == approved, "semantic_recipe_structure_changed")
        fields = review.get("fields")
        _need(isinstance(fields, dict) and set(fields) == set(ROLES)
              and all(isinstance(n, str) and n in r.fields for n in fields.values()),
              "semantic_scalar_roles")
        hero = review.get("hero", {})
        _need(isinstance(hero, dict), "semantic_hero_roles")
        hero_names = hero.get("fields", {})
        _need(set(hero) == {"fields", "low_u32", "high_u32"}
              and isinstance(hero_names, dict) and set(hero_names) == {"low", "high"}
              and all(isinstance(n, str) for n in hero_names.values())
              and len(set(hero_names.values())) == 2
              and all(n in r.fields and r.fields[n].get("type") == "i32"
                      and type(r.fields[n].get("address")) is int
                      and 0 < r.fields[n]["address"] < (1 << 63) - 3
                      and set(r.guard_ids[n]) == set(range(len(r.guards)))
                      and not any(k in r.fields[n] for k in ("path", "path_id", "codec"))
                      for n in hero_names.values())
              and not set(hero_names.values()) & set(fields.values())
              and all(type(hero.get(k)) is int and 0 <= hero[k] < 2**32
                      for k in ("low_u32", "high_u32")), "semantic_hero_roles")
        callback = review.get("callback")
        if callback is not None:
            _need(isinstance(callback, dict) and set(callback) == {
                "fields", "expected_capacity", "child_anchor_field", "child_anchor_offset"}
                and isinstance(callback["fields"], dict) and set(callback["fields"]) == set(CALLBACK_ROLES)
                and all(isinstance(n, str) for n in callback["fields"].values())
                and not set(hero_names.values()) & set(callback["fields"].values())
                and type(callback.get("expected_capacity")) is int
                and callback["expected_capacity"] == 1
                and type(callback.get("child_anchor_offset")) is int
                and 0 <= callback["child_anchor_offset"] <= 1048576
                and callback.get("child_anchor_field") in callback["fields"].values(),
                "semantic_callback_rule")
        validations = review.get("validations")
        _need(isinstance(validations, list) and 2 <= len(validations) <= 8, "semantic_body_validations")
        bodies, kinds = set(), set()
        for validation in validations:
            _need(isinstance(validation, dict) and validation.get("kind") in {
                "training", "independent_body_holdout"}, "semantic_body_validation")
            validation_profile = artifact(validation.get("profile_sha256"))
            vr = GuardedRelations(validation_profile)
            hud = _parse(artifact(validation.get("hud_review_sha256")))
            vp = validation.get("controller_prefix")
            _need(isinstance(vp, str) and vp in vr.prefixes, "semantic_validation_identity")
            try:
                vc, _ = identity(vr, vp, "controller")
                vb, _ = identity(vr, vp + "_body_0000", "body")
            except (InvalidBinding, KeyError, TypeError) as error:
                raise InvalidAmmunitionEvidence("semantic_validation_identity") from error
            _need(vr.target["executable_sha256"] == r.target["executable_sha256"]
                  and isinstance(hud, dict) and hud.get("schema") == "overwatch-decoder.ammunition-hud-review/1"
                  and hud.get("reviewed") is True and hud.get("target") == vr.target
                  and hud.get("readout") == "ammunition_current"
                  and hud.get("controller_object_key") == vc
                  and hud.get("body_object_key") == vb
                  and hud.get("observed_maximum") == maximum
                  and hud.get("storage_binding_sha256") == ammunition_storage_binding_sha256(
                      validation_profile, validation.get("fields")), "semantic_validation_hud")
            validation_native = _parse(artifact(hud.get("native_review_sha256")))
            _need(isinstance(validation_native, dict)
                  and validation_native.get("schema") == "overwatch-decoder.native-scalar-node-review/1"
                  and validation_native.get("reviewed") is True
                  and validation_native.get("review_method") == "native_consumer_trace"
                  and validation_native.get("build_sha256") == r.target["executable_sha256"]
                  and validation_native.get("algorithm") == native.get("algorithm"),
                  "semantic_validation_native")
            sources = hud.get("sources")
            _need(isinstance(sources, list) and 1 <= len(sources) <= 32, "semantic_validation_sources")
            for pin in sources:
                artifact(pin)
            bodies.add(vb); kinds.add(validation["kind"])
        _need(len(bodies) >= 2 and kinds == {"training", "independent_body_holdout"},
              "semantic_independent_body_holdout_required")
        self.semantic = dict(review_sha256=contract["semantic_review_sha256"],
            participant_sha256=contract["participant_review_sha256"], fields=fields.copy(),
            callback=copy.deepcopy(callback), hero=copy.deepcopy(hero), interval=interval.copy(),
            controller=controller, body=body, maximum=maximum)

    def project(self, frame, *, relation_projection=None, gap=False):
        with self.relations._frame_checks(frame):
            base = self.relations.project(frame)
            mismatch = relation_projection is not None and relation_projection != base
            skipped = frame.get("skipped_intervals_before", 0)
            gap = gap or type(skipped) is not int or skipped != 0
            by_prefix = {r["controller_prefix"]: r for r in base["relations"]}
            rows = []
            for binding in self.bindings:
                relation = by_prefix[binding["prefix"]]
                row = dict(controller_object_key=relation["controller_object_key"],
                           body_object_key=relation["body_object_key"], status="unknown", reason=None,
                           ammunition_candidate=None, storage_candidate=None, evidence=[],
                           is_firing=None, reloading=None, public_state_eligible=False, visibility="unknown")
                if self.semantic is not None:
                    row.update(semantic_review_sha256=self.semantic["review_sha256"],
                               participant_review_sha256=self.semantic["participant_sha256"],
                               semantic_evidence=[])
                try:
                    if gap or mismatch:
                        raise InvalidBinding("gap_before_frame" if gap else "relation_projection_mismatch")
                    if relation["relation_status"] != "observed":
                        raise InvalidBinding(relation["reason"] or "relation_unknown")
                    if (row["controller_object_key"] != binding["controller"]
                            or row["body_object_key"] != binding["body"]):
                        raise InvalidBinding("reviewed_object_mismatch")
                    if self.semantic is not None:
                        scope = self.semantic["interval"]
                        if (frame.get("monotonic_frequency") != scope["monotonic_frequency"]
                                or frame.get("start_ticks", -1) < scope["start_ticks"]
                                or frame.get("end_ticks", scope["end_ticks"] + 1) > scope["end_ticks"]):
                            raise InvalidBinding("outside_controlled_participant_scope")
                        hero = self.semantic["hero"]
                        samples = {role: self.relations.sample_scalar(name, frame, "i32")
                                   for role, name in hero["fields"].items()}
                        row["semantic_evidence"] = [dict(field=s["field"], value=s["value"],
                            read_start_ticks=s["read_start_ticks"], read_end_ticks=s["read_end_ticks"],
                            guard_ids=self.relations.guard_ids[s["field"]].copy())
                            for s in samples.values()]
                        if any(samples[role]["value"] & 0xffffffff != hero[role + "_u32"]
                               for role in ("low", "high")):
                            raise InvalidBinding("semantic_hero_mismatch")
                    samples = {role: self.relations.sample_scalar(name, frame, "i32")
                               for role, name in binding["fields"].items()}
                    values = {role: s["value"] for role, s in samples.items()}
                    count = values["expression_count"]
                    if count < 0:
                        raise InvalidBinding("invalid_expression_count")
                    if self.semantic is not None and count > 1:
                        raise InvalidBinding("unsupported_semantic_expression_count")
                    selected = "base" if count == 0 else "cached"
                    freshness = "not_selected" if count == 0 else "unknown_without_tick_bindings"
                    tick_samples = {}
                    if count != 0 and binding["tick_fields"] is not None:
                        tick_samples = {role: self.relations.sample_scalar(
                            name, frame, "u8" if role == "direct_branch" else "i32")
                            for role, name in binding["tick_fields"].items()}
                        tick = tick_samples["direct_tick" if tick_samples["direct_branch"]["value"]
                                            else "virtual_tick"]["value"]
                        flags = values["flags"] & 0xffffffff
                        policy = self.cache_freshness
                        recompute = (flags & policy["force_recompute_mask"]
                                     or flags & policy["tick_check_mask"] and values["cached_tick"] != tick)
                        freshness = "native_recompute_required" if recompute else "native_reuse_condition_observed"
                    tag, bits = values[selected + "_type"], values[selected + "_bits"]
                    if tag == self.int_type:
                        value, number_type = bits, "i32"
                    elif tag == self.float_type:
                        value = struct.unpack("<f", (bits & 0xffffffff).to_bytes(4, "little"))[0]
                        number_type = "f32"
                    else:
                        raise InvalidBinding("unsupported_numeric_type")
                    if not math.isfinite(value) or value != int(value) or not 0 <= value <= binding["maximum"]:
                        raise InvalidBinding("unsupported_ammunition_value")
                    row.update(status="observed", ammunition_candidate=dict(
                        value=int(value), numeric_type=number_type, selection=selected,
                        freshness="base_storage_read" if count == 0 else "sampled_cache_not_recomputed",
                        native_cache_condition=freshness,
                        engine_evaluation_validated=False), storage_candidate=values,
                        evidence=[dict(field=s["field"], value=s["value"],
                                       read_start_ticks=s["read_start_ticks"], read_end_ticks=s["read_end_ticks"],
                                       guard_ids=self.relations.guard_ids[s["field"]].copy())
                                  for s in list(samples.values()) + list(tick_samples.values())])
                except InvalidBinding as error:
                    row["reason"] = str(error)
                if binding["callback"] is not None:
                    self._project_callback(row, binding, frame)
                row["hud_review_sha256"] = binding["hud_review_sha256"]
                rows.append(row)
            result = dict(schema="overwatch-decoder.guarded-ammunition-candidates/1", target=base["target"],
                        profile_sha256=self.relations.hash, contract_sha256=self.contract_sha256,
                        native_review_sha256=self.native_review_sha256,
                        source_evidence=dict(self.source, acquisition_manifest_sha256=self.acquisition_manifest_sha256),
                        timing=base["timing"], rows=rows, source="process_memory", atomic=False,
                        durability_verified=False, continuity_across_gaps=False,
                        public_state_eligible=False, visibility="unknown")
            if self.semantic is not None:
                result.update(semantic_review_sha256=self.semantic["review_sha256"],
                              participant_review_sha256=self.semantic["participant_sha256"],
                              semantic_validation="empirical_controlled_participant_template",
                              controlled_participant_frame_scope=self.semantic["interval"].copy())
            return result

    def _project_callback(self, row, binding, frame):
        row.update(callback_reconstruction_candidate=None, callback_reconstruction_reason=None,
                   callback_reconstruction_evidence=[])
        try:
            if row["status"] != "observed":
                raise InvalidBinding(row["reason"] or "ammunition_unknown")
            count = row["storage_candidate"]["expression_count"]
            if count == 0:
                raise InvalidBinding("inactive_expression_descriptor")
            if count != 1:
                raise InvalidBinding("unsupported_expression_count")
            callback = binding["callback"]
            samples = {role: self.relations.sample_scalar(name, frame, "i32")
                       for role, name in callback["fields"].items()}
            values = {role: s["value"] for role, s in samples.items()}
            if values["count_after"] != 1:
                raise InvalidBinding("descriptor_count_changed")
            if values["capacity"] != callback["expected_capacity"]:
                raise InvalidBinding("descriptor_capacity_changed")
            child = ((values["descriptor_child_low"] & 0xffffffff)
                     | (values["descriptor_child_high"] & 0xffffffff) << 32)
            if child != callback["expected_child_pointer"]:
                raise InvalidBinding("descriptor_child_mismatch")
            algorithm = self.callback_algorithm
            if values["descriptor_selector"] != algorithm["selector"]:
                raise InvalidBinding("unsupported_callback_selector")
            if values["descriptor_operand_count"] != 0 or values["descriptor_value_count"] != 0:
                raise InvalidBinding("unsupported_callback_operands")
            if not values["enabled_flags"] & algorithm["enabled_mask"]:
                raise InvalidBinding("callback_child_disabled")
            before = self.relations.sample_scalar(binding["fields"]["expression_count"], frame, "i32")
            after = samples["count_after"]
            inputs = [s for role, s in samples.items() if role != "count_after"]
            if (before["read_end_ticks"] > min(s["read_start_ticks"] for s in inputs)
                    or after["read_start_ticks"] < max(s["read_end_ticks"] for s in inputs)):
                raise InvalidBinding("callback_input_count_bracket")
            result, elapsed, index = _callback_integer(values, algorithm)
            if not 0 <= result <= binding["maximum"]:
                raise InvalidBinding("unsupported_reconstructed_ammunition_value")
            row["callback_reconstruction_candidate"] = dict(
                value=result, numeric_type="i32", selection="active_descriptor_callback",
                freshness="sequential_operand_reconstruction", sampled_cache_value=row["ammunition_candidate"]["value"],
                sampled_cache_equal=result == row["ammunition_candidate"]["value"],
                elapsed_i64=elapsed, integrated_index_i32=index, binding_sha256=callback["binding_sha256"],
                rounding_assumption=algorithm["rounding_assumption"],
                split_qwords=True, split_qword_consistency_validated=False, clock_reads_atomic=False,
                engine_clock_read_policy="first_compare_then_optional_second_read",
                sampled_clock_read_count=1, engine_evaluation_validated=False)
            row["callback_reconstruction_evidence"] = [dict(
                field=s["field"], value=s["value"], read_start_ticks=s["read_start_ticks"],
                read_end_ticks=s["read_end_ticks"], guard_ids=self.relations.guard_ids[s["field"]].copy())
                for s in samples.values()]
        except InvalidBinding as error:
            row["callback_reconstruction_reason"] = str(error)
