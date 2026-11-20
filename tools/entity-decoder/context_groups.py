"""Finite, explicitly reviewed group comparisons within one native frame.

No roster, self key, game offsets or universal team semantics are supplied. Raw
category and neutral context projectors are evaluated on the same frame. The
caller still owns native source admission and the scope review's truth.
"""
from __future__ import annotations

import copy

from categories import _need, _sha, _digest, _parse, _int
from context_controller import GuardedContextController
from live_categories import live_frame_sha256
from raw_categories import GuardedRawCategories


class GuardedContextGroups:
    """Compare to the current context only in one reviewed player interval."""

    def __init__(self, raw_profile, raw_category_contract, raw_context_contract, raw_contract, artifacts):
        _need(isinstance(artifacts, dict) and len(artifacts) <= 128, "artifact_count")
        self.categories = GuardedRawCategories(raw_profile, raw_category_contract, artifacts)
        self.context = GuardedContextController(raw_profile, raw_context_contract, artifacts)
        r = self.categories.relations
        _need(self.categories.source == self.context.source
              and self.categories.acquisition_manifest_sha256 == self.context.acquisition_manifest_sha256,
              "projector_acquisition_mismatch")
        _need(isinstance(raw_contract, bytes) and len(raw_contract) <= 262144, "contract_size")
        self.contract_sha256 = _sha(raw_contract)
        c = _parse(raw_contract)
        _need(isinstance(c, dict) and c.get("schema") == "overwatch-decoder.context-group-contract/1", "group_contract_schema")
        _need(not any(k in c for k in ("self_controller_object_key", "account_token", "roster_review_sha256")),
              "fixed_identity_forbidden")
        self.scope_pins = dict(target=r.target.copy(), profile_sha256=r.hash, build_sha256=r.target["executable_sha256"],
                               source=self.categories.source.copy(),
                               acquisition_manifest_sha256=self.categories.acquisition_manifest_sha256,
                               category_contract_sha256=self.categories.contract_sha256,
                               context_contract_sha256=self.context.contract_sha256)
        _need(all(c.get(k) == v for k, v in self.scope_pins.items()), "group_source_scope_mismatch")
        self.interval = copy.deepcopy(c.get("frame_scope"))
        _need(isinstance(self.interval, dict), "frame_scope")
        first, last, start, end, frequency = [self.interval.get(k) for k in (
            "first_sequence", "last_sequence", "start_ticks", "end_ticks", "monotonic_frequency")]
        _need(all(_int(n) for n in (first, last, start, end, frequency))
              and 0 <= first <= last <= first + 100000 and 0 < frequency <= 1000000000
              and 0 <= start <= end <= start + frequency * 3600, "frame_scope")
        seen, total = set(), 0

        def artifact(digest):
            nonlocal total
            digest = _digest(digest)
            data = artifacts.get(digest)
            _need(isinstance(data, bytes) and len(data) <= 16 * 1024 * 1024 and _sha(data) == digest,
                  "artifact_hash_or_size")
            if digest not in seen:
                seen.add(digest)
                total += len(data)
                _need(total <= 64 * 1024 * 1024, "artifact_total_size")
            return data

        def sources(review):
            pins = review.get("sources")
            _need(isinstance(pins, list) and 1 <= len(pins) <= 32, "review_sources_missing")
            for pin in pins:
                artifact(pin)

        self.group_review_sha256 = _digest(c.get("two_group_review_sha256"))
        review = _parse(artifact(self.group_review_sha256))
        _need(isinstance(review, dict) and review.get("schema") == "overwatch-decoder.two-group-category-review/1"
              and review.get("reviewed") is True
              and review.get("review_method") == "controlled_two_group_context_holdout"
              and review.get("build_sha256") == r.target["executable_sha256"]
              and review.get("category_native_review_sha256") == self.categories.native_review_sha256
              and review.get("context_native_review_sha256") == self.context.native_review_sha256,
              "two_group_review_mismatch")
        self.mode_id = review.get("mode_id")
        _need(isinstance(self.mode_id, str) and 1 <= len(self.mode_id) <= 128, "mode_scope_missing")
        mappings = review.get("category_groups")
        _need(isinstance(mappings, list) and len(mappings) == 2, "two_group_mapping")
        self.groups = {}
        for mapping in mappings:
            _need(isinstance(mapping, dict), "two_group_mapping")
            category, group = mapping.get("category"), mapping.get("group")
            _need(_int(category) and category in self.categories.supported and category not in self.groups
                  and isinstance(group, str) and 1 <= len(group) <= 128, "two_group_mapping")
            self.groups[category] = group
        _need(len(set(self.groups.values())) == 2, "two_group_mapping")
        sources(review)
        self.context_scope_review_sha256 = _digest(c.get("context_scope_review_sha256"))
        scope = _parse(artifact(self.context_scope_review_sha256))
        _need(isinstance(scope, dict) and scope.get("schema") == "overwatch-decoder.context-group-epoch-review/1"
              and scope.get("reviewed") is True and scope.get("review_method") == "controlled_context_epoch"
              and all(scope.get(k) == v for k, v in self.scope_pins.items())
              and scope.get("two_group_review_sha256") == self.group_review_sha256
              and scope.get("frame_scope") == self.interval and scope.get("spectator_supported") is False,
              "context_epoch_review_mismatch")
        self.context_use = scope.get("context_use")
        _need(self.context_use in ("controlled_player_context", "spectator", "unknown"), "context_use_scope")
        sources(scope)

    def project(self, frame, *, gap=False):
        """No asynchronous projections, stale self keys or epoch carry accepted."""
        _need(isinstance(frame, dict), "invalid_frame")
        # Both concrete projectors consume this exact object; neither accepts a
        # cached key/value supplied by a caller or another source's timestamp.
        categories = self.categories.project(frame, gap=gap)
        context = self.context.project(frame, gap=gap)
        r = self.categories.relations
        expected_source = dict(self.scope_pins["source"],
                               acquisition_manifest_sha256=self.scope_pins["acquisition_manifest_sha256"])
        timing = {k: frame.get(k) for k in ("sequence", "start_ticks", "end_ticks", "monotonic_frequency")}
        sequence, start, end, frequency = [timing[k] for k in timing]
        error = None
        if (not all(_int(v) for v in timing.values())
                or not self.interval["first_sequence"] <= sequence <= self.interval["last_sequence"]
                or not self.interval["start_ticks"] <= start <= end <= self.interval["end_ticks"]
                or frequency != self.interval["monotonic_frequency"]):
            error = "outside_reviewed_frame_scope"
        elif gap or frame.get("skipped_intervals_before", 0) != 0:
            error = "gap_before_frame"
        elif self.context_use != "controlled_player_context":
            error = "unsupported_context_scope"
        elif (r._frame_error(frame) or r.target != self.scope_pins["target"]
              or r.hash != self.scope_pins["profile_sha256"] or context.get("profile_sha256") != r.hash
              or categories.get("profile_sha256") != r.hash or context.get("target") != r.target
              or categories.get("target") != r.target or context.get("timing") != timing
              or any(categories.get("timing", {}).get(k) != v for k, v in timing.items())
              or context.get("source_evidence") != expected_source
              or categories.get("source_evidence") != expected_source):
            error = "same_native_frame_scope_mismatch"
        elif context["status"] != "observed":
            error = "context_selector_unknown"
        elif context["body_status"] != "observed":
            error = "context_body_unknown"
        matches = [row for row in categories["rows"]
                   if row["controller_object_key"] == context["controller_object_key"]
                   and row["body_object_key"] == context["body_object_key"]]
        anchor = matches[0] if len(matches) == 1 else None
        if error is None and (anchor is None or anchor["status"] != "observed"
                              or anchor["raw_category_candidate"] not in self.groups):
            error = "context_category_unknown_or_ambiguous"
        context_group = self.groups[anchor["raw_category_candidate"]] if error is None else None
        rows = []
        for category in categories["rows"]:
            row = {k: category[k] for k in ("controller_prefix", "controller_object_key", "body_object_key")}
            row.update(status="unknown", reason=error, raw_category_candidate=category["raw_category_candidate"],
                       global_group_candidate=None, group_relation_candidate=None,
                       team_candidate=None, relative_allegiance_candidate=None,
                       public_state_eligible=False, visibility="unknown", atomic=False, evidence=[])
            if error is None:
                group = self.groups.get(category["raw_category_candidate"])
                if category["status"] != "observed" or group is None:
                    row["reason"] = category["reason"] or "actor_category_outside_reviewed_groups"
                else:
                    row.update(status="observed", global_group_candidate=group,
                               group_relation_candidate="same_group" if group == context_group else "opposing_group",
                               evidence=category["evidence"])
            rows.append(row)
        return dict(schema="overwatch-decoder.guarded-context-groups/1", profile_sha256=r.hash, target=r.target.copy(),
                    contract_sha256=self.contract_sha256, mode_id=self.mode_id,
                    two_group_review_sha256=self.group_review_sha256,
                    context_scope_review_sha256=self.context_scope_review_sha256,
                    source_evidence=categories["source_evidence"],
                    category_contract_sha256=self.categories.contract_sha256,
                    context_contract_sha256=self.context.contract_sha256,
                    native_frame_sha256=live_frame_sha256(frame), timing=timing,
                    status="unknown" if error else "observed", reason=error,
                    context_controller_object_key=context["controller_object_key"],
                    context_body_object_key=context["body_object_key"], context_group_candidate=context_group,
                    context_evidence=dict(selector=context["selector_evidence"], body=context["body_evidence"],
                                          category=None if anchor is None else anchor["evidence"]),
                    context_use=self.context_use, automatic_spectator_detection=False,
                    local_control_semantics_validated=False, playable_body_validated=False,
                    rows=rows, public_state_eligible=False, visibility="unknown", atomic=False,
                    durability_verified=False, previous_values_carried=False)
