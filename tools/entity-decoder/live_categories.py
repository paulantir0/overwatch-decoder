"""Epoch-bound category research from accepted native live frame evidence.

This is a separate admission path from finite recordings. It never fabricates a
recording manifest and never establishes durability, public eligibility or
visibility. The upstream adapter owns native-envelope sequencing and lifecycle;
this projector independently checks each frame's source binding and read guards.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter

from categories import InvalidCategoryEvidence, _need, _sha, _digest, _parse, _int
from relations import GuardedRelations, InvalidBinding

InvalidLiveCategoryEvidence = InvalidCategoryEvidence


def live_frame_sha256(frame):
    """Canonical semantic digest for the exact embedded recording-frame object."""
    return hashlib.sha256(json.dumps(frame, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True, allow_nan=False).encode()).hexdigest()


class GuardedLiveCategories:
    """Stateless, private candidates for one explicitly reviewed live epoch."""

    def __init__(self, raw_profile: bytes, raw_contract: bytes, artifacts: dict[str, bytes]):
        self.relations = GuardedRelations(raw_profile)
        _need(isinstance(raw_contract, bytes) and len(raw_contract) <= 262144, "contract_size")
        self.contract_sha256 = _sha(raw_contract)
        c = _parse(raw_contract)
        _need(isinstance(c, dict) and c.get("schema") == "overwatch-decoder.live-category-contract/1", "live_contract_schema")
        _need(c.get("profile_sha256") == self.relations.hash and c.get("target") == self.relations.target,
              "contract_profile_or_target_mismatch")
        _need(not any(k in c for k in ("recording_manifest_sha256", "frame_scope")), "finite_recording_scope_not_live")
        self.build = self.relations.target["executable_sha256"]
        _need(c.get("build_sha256") == self.build, "contract_build_mismatch")
        self.mode_id = c.get("mode_id")
        _need(isinstance(self.mode_id, str) and 1 <= len(self.mode_id) <= 128, "unknown_mode")
        self.source = {k: _digest(c.get("source", {}).get(k)) for k in ("recipe_sha256", "evidence_sha256")}
        self.self_controller_object_key = c.get("self_controller_object_key")
        _need(isinstance(self.self_controller_object_key, str)
              and re.fullmatch(r"controller:[0-9a-f]{64}", self.self_controller_object_key) is not None,
              "invalid_self_controller_key")
        seen_artifacts = set()
        total_bytes = 0
        def artifact(digest, maximum=16 * 1024 * 1024):
            nonlocal total_bytes
            digest = _digest(digest)
            raw = artifacts.get(digest)
            _need(isinstance(raw, bytes) and len(raw) <= maximum and _sha(raw) == digest, "artifact_hash_or_size")
            if digest not in seen_artifacts:
                seen_artifacts.add(digest)
                total_bytes += len(raw)
                _need(total_bytes <= 64 * 1024 * 1024, "artifact_total_size")
            return raw

        self.acquisition_manifest_sha256 = _digest(c.get("acquisition_manifest_sha256"))
        manifest = _parse(artifact(self.acquisition_manifest_sha256))
        _need(manifest.get("schema") == "overwatch-decoder.acquisition-result/1" and manifest.get("complete") is True
              and manifest.get("target") == self.relations.target
              and manifest.get("profile_sha256") == self.relations.hash
              and all(manifest.get(k) == v for k, v in self.source.items()), "acquisition_scope_mismatch")
        self.session_start_sha256 = _digest(c.get("session_start_sha256"))
        self.segment_start_sha256 = _digest(c.get("segment_start_sha256"))
        session = _parse(artifact(self.session_start_sha256))
        segment = _parse(artifact(self.segment_start_sha256))
        session_id = session.get("session_id")
        _need(session.get("schema") == "overwatch-decoder.field-live/1" and session.get("kind") == "session_start"
              and isinstance(session_id, str) and 1 <= len(session_id) <= 128
              and session.get("target") == self.relations.target
              and session.get("recipe_sha256") == self.source["recipe_sha256"]
              and type(session.get("event_sequence")) is int and session["event_sequence"] == 0
              and session.get("source_kind") == "native_process_memory"
              and session.get("recording_frame_included") is True
              and session.get("public_state_eligible") is False and session.get("atomic") is False,
              "live_session_scope_mismatch")
        _need(isinstance(c.get("observer_revision"), str) and c["observer_revision"]
              and c["observer_revision"] == session.get("revision"), "observer_revision_mismatch")
        number, start = segment.get("segment"), segment.get("start_ticks")
        frequency = session.get("monotonic_frequency")
        event_sequence = segment.get("event_sequence")
        _need(segment.get("schema") == "overwatch-decoder.field-live/1" and segment.get("kind") == "segment_start"
              and segment.get("session_id") == session_id
              and segment.get("profile_sha256") == self.relations.hash
              and segment.get("source_stream_schema") == "overwatch-decoder.field-stream/1"
              and _int(number) and number > 0 and _int(start) and start >= 0
              and _int(frequency) and frequency > 0 and segment.get("monotonic_frequency") == frequency
              and _int(event_sequence) and event_sequence > 0
              and _int(segment.get("emitted_ticks")) and start <= segment["emitted_ticks"],
              "live_segment_scope_mismatch")
        declarations = segment.get("fields")
        _need(isinstance(declarations, list)
              and [(d.get("name"), d.get("type")) for d in declarations]
                  == [(name, field.get("type")) for name, field in self.relations.fields.items()],
              "live_segment_field_shape_mismatch")
        self.live_scope = dict(session_id=session_id, segment=number, start_ticks=start,
                               monotonic_frequency=frequency, session_start_sha256=self.session_start_sha256,
                               segment_start_sha256=self.segment_start_sha256)
        self.segment_start_event_sequence = event_sequence
        # The native acquisition and manual review must admit this exact epoch,
        # rather than allowing a mode label to authorize future live sessions.
        self.mode_review_sha256 = _digest(c.get("mode_review_sha256"))
        mode = _parse(artifact(self.mode_review_sha256))
        _need(mode.get("schema") == "overwatch-decoder.live-category-mode-review/1" and mode.get("reviewed") is True
              and mode.get("review_method") == "manual_controlled_live_epoch"
              and mode.get("mode_id") == self.mode_id and mode.get("target") == self.relations.target
              and mode.get("profile_sha256") == self.relations.hash
              and mode.get("acquisition_manifest_sha256") == self.acquisition_manifest_sha256
              and mode.get("self_controller_object_key") == self.self_controller_object_key
              and mode.get("live_scope") == self.live_scope
              and mode.get("native_review_sha256") == c.get("native_review_sha256")
              and mode.get("roster_review_sha256") == c.get("roster_review_sha256"), "live_mode_review_mismatch")
        mode_sources = mode.get("sources")
        _need(isinstance(mode_sources, list) and 1 <= len(mode_sources) <= 32, "live_mode_sources_missing")
        for source in mode_sources:
            artifact(source)
        _digest(c.get("roster_review_sha256"))  # Live relative semantics require an explicit roster review.
        self.native_review_sha256 = _digest(c.get("native_review_sha256"))
        native = _parse(artifact(self.native_review_sha256))
        _need(native.get("schema") == "overwatch-decoder.native-category-review/1" and native.get("reviewed") is True
              and native.get("review_method") == "native_consumer_trace"
              and native.get("build_sha256") == self.build, "native_review_mismatch")
        _need(native.get("required_conditions") == ["unlinked_owner", "zero_override"], "incomplete_route_conditions")
        sources = native.get("sources")
        _need(isinstance(sources, list) and 1 <= len(sources) <= 32, "native_sources_missing")
        for source in sources:
            artifact(source)
        algorithm = native.get("algorithm", {})
        self.ordered_bits = algorithm.get("ordered_bits")
        self.clear_bits = algorithm.get("clear_bits")
        self.supported = algorithm.get("supported_categories")
        _need(isinstance(self.ordered_bits, list) and 1 <= len(self.ordered_bits) <= 32
              and all(_int(v) and 0 <= v < 32 for v in self.ordered_bits)
              and len(set(self.ordered_bits)) == len(self.ordered_bits), "category_bit_specification")
        _need(isinstance(self.clear_bits, list) and 1 <= len(self.clear_bits) <= 32
              and all(_int(v) and 0 <= v < 32 for v in self.clear_bits)
              and len(set(self.clear_bits)) == len(self.clear_bits)
              and not set(self.clear_bits) & set(self.ordered_bits), "mode_bit_specification")
        _need(isinstance(self.supported, list) and self.supported
              and all(_int(v) and 0 <= v < len(self.ordered_bits) for v in self.supported)
              and len(set(self.supported)) == len(self.supported), "supported_category_specification")

        self.roster_review_sha256 = c.get("roster_review_sha256")
        self.teams = {}
        if self.roster_review_sha256 is not None:
            roster = _parse(artifact(self.roster_review_sha256))
            _need(roster.get("schema") == "overwatch-decoder.category-roster-review/1" and roster.get("reviewed") is True
                  and roster.get("review_method") == "manual_visual_roster_with_full_native_keys"
                  and roster.get("build_sha256") == self.build and roster.get("mode_id") == self.mode_id
                  and roster.get("self_controller_object_key") == self.self_controller_object_key,
                  "roster_review_mismatch")
            roster_sources = roster.get("sources")
            _need(isinstance(roster_sources, list) and 2 <= len(roster_sources) <= 32, "roster_sources_missing")
            for source in roster_sources:
                artifact(source)
            mappings = roster.get("category_teams")
            _need(isinstance(mappings, list) and 2 <= len(mappings) <= 32, "roster_mapping_missing")
            for mapping in mappings:
                category, team = mapping.get("category"), mapping.get("team")
                _need(_int(category) and category in self.supported and category not in self.teams
                      and isinstance(team, str) and 1 <= len(team) <= 128, "invalid_or_conflicting_team_mapping")
                self.teams[category] = team
            _need(len(set(self.teams.values())) == len(self.teams), "roster_team_mapping_not_injective")
            anchors = roster.get("anchors")
            _need(isinstance(anchors, list) and len(anchors) >= 3, "roster_anchors_missing")
            keys, categories, roles = set(), set(), set()
            for anchor in anchors:
                ck, bk = anchor.get("controller_object_key"), anchor.get("body_object_key")
                cat, role = anchor.get("category"), anchor.get("role")
                _need(isinstance(ck, str) and re.fullmatch(r"controller:[0-9a-f]{64}", ck) is not None
                      and isinstance(bk, str) and re.fullmatch(r"body:[0-9a-f]{64}", bk) is not None
                      and (ck, bk) not in keys and _int(cat) and cat in self.teams
                      and anchor.get("team") == self.teams[cat]
                      and role in ("self", "friendly", "enemy"), "invalid_roster_anchor")
                if role == "self":
                    _need(ck == self.self_controller_object_key, "roster_self_mismatch")
                keys.add((ck, bk)); categories.add(cat); roles.add(role)
            _need(roles == {"self", "friendly", "enemy"} and len(categories) >= 2, "roster_anchor_roles_missing")
            self_anchors = [a for a in anchors if a["role"] == "self"]
            _need(len(self_anchors) == 1, "roster_self_anchor_count")
            self_category = self_anchors[0]["category"]
            for anchor in anchors:
                same_category = anchor["category"] == self_category
                _need((anchor["role"] in ("self", "friendly")) == same_category,
                      "roster_role_category_mismatch")
                _need(anchor["role"] == "self" or anchor["controller_object_key"] != self.self_controller_object_key,
                      "roster_self_role_conflict")

        bindings = c.get("bindings")
        _need(isinstance(bindings, list) and 1 <= len(bindings) <= 32, "binding_count")
        self.bindings = []
        names = set()
        for binding in bindings:
            handle, key, flags = [binding.get(k) for k in ("body_handle_field", "body_creation_key_field", "flags_field")]
            _need(all(isinstance(n, str) and n in self.relations.fields for n in (handle, key, flags))
                  and flags not in names, "category_field_binding")
            names.add(flags)
            # Guarded identity words must cover all four bytes. Semantic flags
            # deliberately do not need a constant-value guard.
            self.relations._binding(handle); self.relations._binding(key)
            _need(self.relations.fields[flags].get("type") == "i32", "category_word_type")
            required = binding.get("required_guard_ids")
            _need(isinstance(required, list) and required
                  and all(_int(n) and 0 <= n < len(self.relations.guards) for n in required)
                  and len(set(required)) == len(required)
                  and set(required).issubset(self.relations.guard_ids[flags]), "route_guard_dependencies")
            conditions = binding.get("conditions")
            _need(isinstance(conditions, list) and len(conditions) == 2
                  and {p.get("role") for p in conditions} == {"unlinked_owner", "zero_override"}, "route_conditions_missing")
            for condition in conditions:
                address, width, mask, equals = [condition.get(k) for k in ("address", "width", "mask", "equals")]
                _need(_int(address) and address > 0 and _int(width) and 1 <= width <= 8
                      and _int(mask) and 0 < mask < 1 << (8 * width)
                      and _int(equals) and 0 <= equals < 1 << (8 * width)
                      and equals & ~mask == 0, "invalid_route_condition")
                _need(equals == 0 and (condition["role"] != "zero_override"
                      or width in (4, 8) and mask == (1 << (8 * width)) - 1), "nonzero_or_partial_override_condition")
                value, ids = self._guard_value(address, width)
                _need(set(ids).issubset(required) and value & mask == equals, "unsupported_route_condition")
            self.bindings.append(dict(body_handle_field=handle, body_creation_key_field=key,
                                      flags_field=flags, required_guard_ids=required))

        matches = 0
        for prefix in self.relations.prefixes:
            words = []
            for suffix in ("_handle_candidate_i32", "_manager_key_candidate_i32"):
                address, value = self.relations._binding(prefix + suffix)
                words.append(dict(address=address, value=value))
            matches += self.relations._key("controller", words) == self.self_controller_object_key
        _need(matches == 1, "live_profile_self_binding_missing_or_ambiguous")

    def _guard_value(self, address, width):
        result, ids = {}, []
        for index, guard in enumerate(self.relations.guards):
            start = guard["address"]
            data = bytes.fromhex(guard["bytes_hex"])
            for pos in range(max(address, start), min(address + width, start + len(data))):
                value = data[pos - start]
                _need(pos not in result or result[pos] == value, "conflicting_condition_guards")
                result[pos] = value
                if index not in ids:
                    ids.append(index)
        _need(len(result) == width, "unguarded_route_condition")
        return int.from_bytes(bytes(result[address + n] for n in range(width)), "little"), ids

    def _admission_error(self, frame, admission):
        try:
            _need(isinstance(admission, dict)
                  and admission.get("schema") == "overwatch-decoder.live-category-frame-admission/1"
                  and admission.get("status") == "accepted_not_durability_verified"
                  and admission.get("durability_verified") is False, "live_frame_not_admitted")
            expected = dict(session_id=self.live_scope["session_id"], segment=self.live_scope["segment"],
                            profile_sha256=self.relations.hash,
                            acquisition_manifest_sha256=self.acquisition_manifest_sha256, **self.source)
            _need(all(admission.get(k) == v for k, v in expected.items())
                  and _int(admission.get("segment")), "live_frame_scope_mismatch")
            event_sequence = admission.get("event_sequence")
            _need(_int(event_sequence) and event_sequence > self.segment_start_event_sequence,
                  "live_frame_event_sequence")
            _digest(admission.get("event_sha256"))
            _need(admission.get("frame_sha256") == live_frame_sha256(frame), "live_frame_hash_mismatch")
            _need(all(_int(frame.get(k)) for k in ("sequence", "start_ticks", "end_ticks", "monotonic_frequency"))
                  and frame["sequence"] >= 0 and self.live_scope["start_ticks"] <= frame["start_ticks"] <= frame["end_ticks"]
                  and frame["monotonic_frequency"] == self.live_scope["monotonic_frequency"], "live_frame_clock_scope")
            _need(all(_int(admission.get("frame_" + key)) and admission["frame_" + key] == frame[key]
                      for key in ("sequence", "start_ticks", "end_ticks"))
                  and _int(admission.get("monotonic_frequency"))
                  and admission["monotonic_frequency"] == frame["monotonic_frequency"], "live_frame_timing_mismatch")
        except (InvalidCategoryEvidence, ValueError, TypeError, KeyError) as error:
            return str(error)
        return None

    def project(self, frame, *, admission, gap=False):
        base = self.relations.project(frame)
        result = {k: v for k, v in base.items() if k != "relations"}
        admission_error = self._admission_error(frame, admission)
        result.update(schema="overwatch-decoder.guarded-live-actor-categories/1", contract_sha256=self.contract_sha256,
                      native_review_sha256=self.native_review_sha256, roster_review_sha256=self.roster_review_sha256,
                      mode_review_sha256=self.mode_review_sha256, mode_id=self.mode_id,
                      source_evidence=dict(self.source, acquisition_manifest_sha256=self.acquisition_manifest_sha256),
                      self_controller_object_key=self.self_controller_object_key, live_scope=dict(self.live_scope),
                      recording_state="accepted_not_durability_verified", durability_verified=False,
                      admission_evidence=({key: admission[key] for key in (
                          "session_id", "segment", "event_sequence", "event_sha256", "frame_sha256",
                          "frame_sequence", "frame_start_ticks", "frame_end_ticks", "monotonic_frequency",
                          "profile_sha256", "acquisition_manifest_sha256", "recipe_sha256", "evidence_sha256")}
                          if admission_error is None else None), rows=[])
        samples, failures = [], []
        for binding in self.bindings:
            try:
                if gap:
                    raise InvalidBinding("gap_before_frame")
                if admission_error:
                    raise InvalidBinding(admission_error)
                words = [self.relations._observed(binding[n], frame)
                         for n in ("body_handle_field", "body_creation_key_field")]
                body_key = self.relations._key("body", words)
                flags = self.relations.sample_scalar(binding["flags_field"], frame, "i32")
                value = flags["value"] & 0xffffffff
                if any(value & (1 << bit) for bit in self.clear_bits):
                    raise InvalidBinding("unsupported_mode_bits")
                selected = [n for n, bit in enumerate(self.ordered_bits) if value & (1 << bit)]
                if len(selected) != 1:
                    raise InvalidBinding("absent_or_ambiguous_category")
                category = selected[0]
                if category not in self.supported:
                    raise InvalidBinding("unsupported_category")
                evidence = [{k: w[k] for k in ("field", "value", "read_start_ticks", "read_end_ticks")}
                            for w in words + [flags]]
                samples.append(dict(body_object_key=body_key, category=category, evidence=evidence))
            except InvalidBinding as error:
                # Preserve a reason keyed by a guarded body if identity still
                # resolves; never recover a key from an earlier frame.
                try:
                    words = [self.relations._observed(binding[n], frame)
                             for n in ("body_handle_field", "body_creation_key_field")]
                    failures.append((self.relations._key("body", words), str(error)))
                except InvalidBinding:
                    pass
        counts = Counter(s["body_object_key"] for s in samples)
        by_body = {s["body_object_key"]: s for s in samples if counts[s["body_object_key"]] == 1}
        errors = dict(failures)
        for key, count in counts.items():
            if count != 1:
                errors[key] = "ambiguous_category_body"
        rows = []
        for relation in base["relations"]:
            ck, bk = relation["controller_object_key"], relation["body_object_key"]
            row = dict(controller_object_key=ck, body_object_key=bk, status="unknown", reason=None,
                       raw_category_candidate=None, team_candidate=None, relative_allegiance_candidate=None,
                       evidence=[], public_state_eligible=False, visibility="unknown")
            row["mode_scope"] = dict(mode_id=self.mode_id, live_scope=dict(self.live_scope),
                                     mode_review_sha256=self.mode_review_sha256, roster_review_sha256=self.roster_review_sha256)
            sample = by_body.get(bk)
            if gap:
                row["reason"] = "gap_before_frame"
            elif admission_error:
                row["reason"] = admission_error
            elif relation["relation_status"] != "observed":
                row["reason"] = relation["reason"] or "relation_unknown"
            elif bk in errors:
                row["reason"] = errors[bk]
            elif sample is None:
                row["reason"] = "category_body_binding_missing"
            else:
                row.update(status="observed", raw_category_candidate=sample["category"],
                           evidence=sample["evidence"])
            rows.append(row)
        self_rows = [r for r in rows if r["controller_object_key"] == self.self_controller_object_key
                     and r["status"] == "observed"]
        self_row = self_rows[0] if len(self_rows) == 1 else None
        for row in rows:
            if row["status"] != "observed":
                continue
            if not self.teams or row["raw_category_candidate"] not in self.teams:
                row["reason"] = "unvalidated_roster_mapping"
            elif self_row is None or self_row["raw_category_candidate"] not in self.teams:
                row["reason"] = "self_relation_unknown"
            else:
                row["team_candidate"] = self.teams[row["raw_category_candidate"]]
                self_team = self.teams[self_row["raw_category_candidate"]]
                row["relative_allegiance_candidate"] = ("self" if row["controller_object_key"] == self.self_controller_object_key
                    else "friendly" if row["team_candidate"] == self_team else "enemy")
                row["self_evidence"] = self_row["evidence"]
        result["rows"] = rows
        return result
