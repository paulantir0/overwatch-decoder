"""Source-bound raw category candidates without roster, account or self inputs.

The caller verifies native acquisition/transport evidence and supplies a reviewed
recipe contract. This module checks its pins and every sampled dependency; it
does not prove that an arbitrary recipe implements the reviewed native route.
No process access, application offsets, team maps or durable/live admission are
provided here. Sequential flag halves are explicitly non-atomic.
"""
from __future__ import annotations

from collections import Counter
import re

from categories import InvalidCategoryEvidence, _need, _sha, _digest, _parse, _int
from relations import GuardedRelations, InvalidBinding


class GuardedRawCategories:
    """Stateless category projection for one exact acquisition and profile.

    As with GuardedRelations, native recipe/source verification is a caller
    prerequisite. A fresh epoch requires a fresh contract, even if some object
    keys survive. Output never establishes visibility or relative allegiance.
    """

    def __init__(self, raw_profile: bytes, raw_contract: bytes, artifacts: dict[str, bytes]):
        self.relations = GuardedRelations(raw_profile)
        _need(isinstance(raw_contract, bytes) and len(raw_contract) <= 262144, "contract_size")
        self.contract_sha256 = _sha(raw_contract)
        c = _parse(raw_contract)
        _need(isinstance(c, dict) and c.get("schema") == "overwatch-decoder.raw-category-contract/1", "raw_contract_schema")
        _need(not any(k in c for k in ("self_controller_object_key", "roster_review_sha256", "mode_id",
                                      "category_teams")), "roster_semantics_not_raw")
        _need(c.get("profile_sha256") == self.relations.hash and c.get("target") == self.relations.target,
              "contract_profile_or_target_mismatch")
        self.build = self.relations.target["executable_sha256"]
        _need(c.get("build_sha256") == self.build, "contract_build_mismatch")
        _need(isinstance(c.get("source"), dict), "source_pins_missing")
        self.source = {k: _digest(c["source"].get(k)) for k in ("recipe_sha256", "evidence_sha256")}
        prefixes = c.get("additional_relation_prefixes", [])
        _need(isinstance(prefixes, list) and len(prefixes) <= 32
              and all(isinstance(p, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,127}", p) for p in prefixes)
              and len(set(prefixes)) == len(prefixes)
              and not set(prefixes) & set(self.relations.prefixes)
              and len(prefixes) + len(self.relations.prefixes) <= 32, "additional_relation_prefixes")
        for prefix in prefixes:
            for suffix in ("_handle_candidate_i32", "_manager_key_candidate_i32"):
                self.relations._binding(prefix + suffix)
            # Absent bodies remain representable: the normal relation projector
            # retains the guarded controller and leaves the body unknown.
            for suffix in ("_part51_0000_body_key_candidate_i32", "_body_0000_handle_candidate_i32",
                           "_body_0000_manager_key_candidate_i32"):
                if prefix + suffix in self.relations.fields:
                    self.relations._binding(prefix + suffix)
        self.relations.prefixes.extend(prefixes)
        seen, total = set(), 0

        def artifact(digest):
            nonlocal total
            digest = _digest(digest)
            value = artifacts.get(digest)
            _need(isinstance(value, bytes) and len(value) <= 16 * 1024 * 1024
                  and _sha(value) == digest, "artifact_hash_or_size")
            if digest not in seen:
                seen.add(digest)
                total += len(value)
                _need(total <= 64 * 1024 * 1024, "artifact_total_size")
            return value

        self.acquisition_manifest_sha256 = _digest(c.get("acquisition_manifest_sha256"))
        manifest = _parse(artifact(self.acquisition_manifest_sha256))
        _need(isinstance(manifest, dict) and manifest.get("schema") == "overwatch-decoder.acquisition-result/1"
              and manifest.get("complete") is True and manifest.get("error") is None
              and manifest.get("target") == self.relations.target
              and manifest.get("profile_sha256") == self.relations.hash
              and all(manifest.get(k) == v for k, v in self.source.items()), "acquisition_scope_mismatch")
        # Resolve the source pins, rather than trusting a manifest's digest text.
        for digest in self.source.values():
            artifact(digest)
        self.native_review_sha256 = _digest(c.get("native_review_sha256"))
        native = _parse(artifact(self.native_review_sha256))
        _need(isinstance(native, dict) and native.get("schema") == "overwatch-decoder.native-category-review/1"
              and native.get("reviewed") is True and native.get("review_method") == "native_consumer_trace"
              and native.get("build_sha256") == self.build, "native_review_mismatch")
        _need(native.get("required_conditions") == ["unlinked_owner", "zero_override"], "incomplete_route_conditions")
        sources = native.get("sources")
        _need(isinstance(sources, list) and 1 <= len(sources) <= 32, "native_sources_missing")
        for digest in sources:
            artifact(digest)
        algorithm = native.get("algorithm", {})
        _need(isinstance(algorithm, dict), "category_algorithm")
        self.ordered_bits = algorithm.get("ordered_bits")
        self.clear_bits = algorithm.get("clear_bits")
        self.supported = algorithm.get("supported_categories")
        for bits, reason in ((self.ordered_bits, "category_bit_specification"),
                             (self.clear_bits, "mode_bit_specification")):
            _need(isinstance(bits, list) and 1 <= len(bits) <= 32
                  and all(_int(n) and 0 <= n < 32 for n in bits)
                  and len(set(bits)) == len(bits), reason)
        _need(not set(self.ordered_bits) & set(self.clear_bits), "mode_bit_specification")
        _need(isinstance(self.supported, list) and self.supported
              and all(_int(n) and 0 <= n < len(self.ordered_bits) for n in self.supported)
              and len(set(self.supported)) == len(self.supported), "supported_category_specification")

        bindings = c.get("bindings")
        _need(isinstance(bindings, list) and len(bindings) <= 32, "binding_count")
        self.bindings = []
        names = set()
        bodies = set()
        for b in bindings:
            _need(isinstance(b, dict), "category_field_binding")
            handle, key, low, high = [b.get(k) for k in (
                "body_handle_field", "body_creation_key_field", "flags_low_field", "flags_high_field")]
            _need(all(isinstance(n, str) and n in self.relations.fields for n in (handle, key, low, high))
                  and len({handle, key, low, high}) == 4 and not {low, high} & names,
                  "category_field_binding")
            names.update((low, high))
            body_words = [self.relations._binding(n) for n in (handle, key)]
            identity = tuple(body_words)
            _need(identity not in bodies, "ambiguous_category_body")
            bodies.add(identity)
            for name in (low, high):
                field = self.relations.fields[name]
                _need(field.get("type") == "i32" and not any(k in field for k in ("path", "path_id", "codec"))
                      and _int(field.get("address")) and 0 < field["address"] < (1 << 63) - 3,
                      "category_word_type_or_address")
            _need(self.relations.fields[high]["address"] == self.relations.fields[low]["address"] + 4,
                  "flag_halves_not_contiguous")
            required = b.get("required_guard_ids")
            _need(isinstance(required, list) and required
                  and all(_int(n) and 0 <= n < len(self.relations.guards) for n in required)
                  and len(set(required)) == len(required)
                  and all(set(required).issubset(self.relations.guard_ids[n]) for n in (low, high)),
                  "route_guard_dependencies")
            conditions = b.get("conditions")
            _need(isinstance(conditions, list) and len(conditions) == 2
                  and all(isinstance(p, dict) for p in conditions)
                  and {p.get("role") for p in conditions} == {"unlinked_owner", "zero_override"},
                  "route_conditions_missing")
            for condition in conditions:
                address, width, mask, equals = [condition.get(k) for k in ("address", "width", "mask", "equals")]
                _need(_int(address) and 0 < address < (1 << 63) - 8 and _int(width) and 1 <= width <= 8
                      and _int(mask) and 0 < mask < 1 << (8 * width) and _int(equals) and equals == 0,
                      "invalid_route_condition")
                _need(condition["role"] != "zero_override"
                      or width in (4, 8) and mask == (1 << (8 * width)) - 1,
                      "nonzero_or_partial_override_condition")
                value, ids = self._guard_value(address, width)
                _need(set(ids).issubset(required) and value & mask == 0, "unsupported_route_condition")
            self.bindings.append(dict(handle=handle, key=key, low=low, high=high))

    def _guard_value(self, address, width):
        result, ids = {}, set()
        for index, guard in enumerate(self.relations.guards):
            start, data = guard["address"], bytes.fromhex(guard["bytes_hex"])
            for pos in range(max(address, start), min(address + width, start + len(data))):
                value = data[pos - start]
                _need(pos not in result or result[pos] == value, "conflicting_condition_guards")
                result[pos] = value
                ids.add(index)
        _need(len(result) == width, "unguarded_route_condition")
        return int.from_bytes(bytes(result[address + n] for n in range(width)), "little"), ids

    def sample_native_flags(self, binding, frame):
        """Sample validated identity/flags without choosing any object relation.

        The caller supplies a binding from this instance and holds its relation
        check scope. This performs no reciprocal-body projection or role join.
        """
        _need(binding in self.bindings, "undeclared_category_binding")
        words = [self.relations._observed(binding[n], frame) for n in ("handle", "key")]
        halves = [self.relations.sample_scalar(binding[n], frame, "i32") for n in ("low", "high")]
        low, high = [s["value"] & 0xffffffff for s in halves]
        selected = [n for n, bit in enumerate(self.ordered_bits) if low & (1 << bit)]
        error = ("unsupported_mode_bits" if any(low & (1 << b) for b in self.clear_bits)
                 else "absent_or_ambiguous_category" if len(selected) != 1
                 else "unsupported_category" if selected[0] not in self.supported else None)
        evidence = [{k: w[k] for k in ("field", "value", "read_start_ticks", "read_end_ticks")}
                    for w in words + halves]
        return words, low, high, selected, error, evidence

    def project(self, frame, *, relation_projection=None, gap=False):
        """Project one verified native frame; no values survive a missing read.

        Optional relation_projection must equal this profile's own projection.
        It cannot supply keys from another source or epoch. Transport ordering,
        source admission and durable verification remain the caller's job.
        """
        with self.relations._frame_checks(frame):
            base = self.relations.project(frame)
            reason = "relation_projection_mismatch" if relation_projection is not None and relation_projection != base else None
            skipped = frame.get("skipped_intervals_before", 0)
            gap = gap or not _int(skipped) or skipped != 0
            samples, failures = [], {}
            for binding in self.bindings:
                body = None
                try:
                    words = [self.relations._observed(binding[n], frame) for n in ("handle", "key")]
                    body = self.relations._key("body", words)
                    if gap or reason:
                        raise InvalidBinding("gap_before_frame" if gap else reason)
                    _, low, high, selected, error, evidence = self.sample_native_flags(binding, frame)
                    samples.append(dict(body_object_key=body, low_u32=low, high_u32=high,
                                        assembled_u64_hex=f"0x{high:08x}{low:08x}",
                                        selected_category_indices=selected, reason=error,
                                        category=None if error else selected[0], evidence=evidence))
                except InvalidBinding as error:
                    if body is not None:
                        failures[body] = str(error)
            counts = Counter(s["body_object_key"] for s in samples)
            by_body = {s["body_object_key"]: s for s in samples if counts[s["body_object_key"]] == 1}
            rows = []
            for relation in base["relations"]:
                ck, bk = relation["controller_object_key"], relation["body_object_key"]
                row = dict(controller_prefix=relation["controller_prefix"], controller_object_key=ck,
                           body_object_key=bk, status="unknown", raw_status="unknown",
                           reason=None, raw_flags_candidate=None, raw_category_candidate=None,
                           team_candidate=None, relative_allegiance_candidate=None, evidence=[],
                           public_state_eligible=False, visibility="unknown", atomic=False)
                error = ("gap_before_frame" if gap else reason
                         or (relation["reason"] or "relation_unknown" if relation["relation_status"] != "observed" else None)
                         or ("ambiguous_category_body" if counts[bk] > 1 else None)
                         or failures.get(bk))
                sample = by_body.get(bk)
                if error or sample is None:
                    row["reason"] = error or "category_body_binding_missing"
                else:
                    row.update(raw_status="observed", status="unknown" if sample["reason"] else "observed",
                               reason=sample["reason"], raw_category_candidate=sample["category"],
                               raw_flags_candidate={k: sample[k] for k in (
                                   "low_u32", "high_u32", "assembled_u64_hex", "selected_category_indices")},
                               evidence=sample["evidence"])
                rows.append(row)
        result = {k: v for k, v in base.items() if k != "relations"}
        result.update(schema="overwatch-decoder.guarded-raw-actor-categories/1", contract_sha256=self.contract_sha256,
                      native_review_sha256=self.native_review_sha256,
                      source_evidence=dict(self.source, acquisition_manifest_sha256=self.acquisition_manifest_sha256),
                      validation_scope="reviewed_unlinked_zero_override_branch", durability_verified=False,
                      rows=rows)
        return result
