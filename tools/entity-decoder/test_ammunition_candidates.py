"""Synthetic storage/identity counterexamples; no application layouts."""
import copy
import hashlib
import json
import struct
import unittest

from ammunition_candidates import (GuardedAmmunitionCandidates, InvalidAmmunitionEvidence, ROLES,
                                   CALLBACK_ROLES, ammunition_callback_binding_sha256,
                                   ammunition_storage_binding_sha256, ammunition_tick_binding_sha256,
                                   _callback_integer, _i64_to_f32)
from test_relations import fixture, prepare, change_word


def raw(value):
    return json.dumps(value).encode()


def ammunition_fixture():
    profile, values = fixture()
    initial = dict(zip(ROLES, (0, struct.unpack("<i", struct.pack("<f", 40))[0], 3,
                              12, 2, -1, 0)))
    fields = {}
    for index, (role, value) in enumerate(initial.items()):
        fields[role] = role
        profile["fields"].append(dict(name=role, type="i32", address=0x3000 + index * 8))
        values[role] = value
    relations, frame = prepare(profile, values)
    row = relations.project(frame)["relations"][0]
    artifacts = {}

    def add(value):
        data = value if isinstance(value, bytes) else raw(value)
        digest = hashlib.sha256(data).hexdigest()
        artifacts[digest] = data
        return digest

    source = dict(recipe_sha256=add(b"synthetic recipe"), evidence_sha256=add(b"synthetic evidence"))
    manifest = dict(schema="overwatch-decoder.acquisition-result/1", complete=True, error=None,
                    target=relations.target, profile_sha256=relations.hash, **source)
    native = dict(schema="overwatch-decoder.native-scalar-node-review/1", reviewed=True,
                  review_method="native_consumer_trace", build_sha256=relations.target["executable_sha256"],
                  recipe_sha256=source["recipe_sha256"],
                  sources=[add(b"synthetic native source")], algorithm=dict(
                      selection="base_if_zero_expression_count_else_sampled_cache",
                      active_cache_policy="sampled_not_recomputed", int32_type=2, float32_type=3))
    native_sha = add(native)
    hud = dict(schema="overwatch-decoder.ammunition-hud-review/1", reviewed=True, target=relations.target,
               readout="ammunition_current", native_review_sha256=native_sha,
               storage_binding_sha256=ammunition_storage_binding_sha256(raw(profile), fields),
               controller_object_key=row["controller_object_key"], body_object_key=row["body_object_key"],
               observed_maximum=40, sources=[add(b"synthetic HUD anchor")])
    contract = dict(schema="overwatch-decoder.ammunition-candidate-contract/1", profile_sha256=relations.hash,
                    target=relations.target, build_sha256=relations.target["executable_sha256"],
                    source=source, acquisition_manifest_sha256=add(manifest), native_review_sha256=native_sha,
                    bindings=[dict(controller_prefix="controller_0000", fields=fields,
                                   controller_object_key=row["controller_object_key"],
                                   body_object_key=row["body_object_key"],
                                   required_guard_ids=list(range(len(relations.guards))), hud_review_sha256=add(hud))])
    return profile, values, frame, contract, artifacts, manifest, native, hud


class AmmunitionTests(unittest.TestCase):
    def setUp(self):
        (self.profile, self.values, self.frame, self.contract, self.artifacts,
         self.manifest, self.native, self.hud) = ammunition_fixture()
        self.decoder = self.make()

    def make(self):
        return GuardedAmmunitionCandidates(raw(self.profile), raw(self.contract), self.artifacts)

    def row(self, frame=None, **kw):
        return self.decoder.project(self.frame if frame is None else frame, **kw)["rows"][0]

    def artifact(self, value):
        data = raw(value)
        digest = hashlib.sha256(data).hexdigest()
        self.artifacts[digest] = data
        return digest

    def test_base_float_ignores_stale_cached_integer(self):
        row = self.row()
        self.assertEqual(row["ammunition_candidate"], dict(value=40, numeric_type="f32", selection="base",
                         freshness="base_storage_read", native_cache_condition="not_selected",
                         engine_evaluation_validated=False))
        self.assertEqual(row["storage_candidate"]["cached_bits"], 12)
        self.assertIsNone(row["is_firing"])
        self.assertIsNone(row["reloading"])
        self.assertFalse(row["public_state_eligible"])
        self.assertEqual(row["visibility"], "unknown")

    def test_active_selects_cached_variant_not_old_base(self):
        self.frame["fields"]["expression_count"]["value"] = 1
        self.frame["fields"]["cached_bits"]["value"] = 26
        row = self.row()
        self.assertEqual(row["ammunition_candidate"]["value"], 26)
        self.assertEqual(row["ammunition_candidate"]["freshness"], "sampled_cache_not_recomputed")
        self.assertFalse(row["ammunition_candidate"]["engine_evaluation_validated"])
        self.frame["fields"]["flags"]["value"] = 2
        self.frame["fields"]["cached_tick"]["value"] = -1
        self.assertEqual(self.row()["ammunition_candidate"]["freshness"], "sampled_cache_not_recomputed")

    def test_inactive_integer_and_reload_return_to_float(self):
        self.frame["fields"]["base_bits"]["value"] = 14
        self.frame["fields"]["base_type"]["value"] = 2
        self.assertEqual(self.row()["ammunition_candidate"]["value"], 14)
        self.frame["fields"]["base_bits"]["value"] = self.values["base_bits"]
        self.frame["fields"]["base_type"]["value"] = 3
        self.assertEqual(self.row()["ammunition_candidate"]["value"], 40)

    def test_unsupported_type_fraction_nan_negative_and_range_are_unknown(self):
        for tag, value in [(9, 10), (2, -1), (2, 41), (3, 0x7fc00000),
                           (3, struct.unpack("<i", struct.pack("<f", 1.5))[0])]:
            with self.subTest(tag=tag, value=value):
                frame = copy.deepcopy(self.frame)
                frame["fields"]["base_type"]["value"] = tag
                frame["fields"]["base_bits"]["value"] = value
                self.assertIsNone(self.row(frame)["ammunition_candidate"])
        self.frame["fields"]["expression_count"]["value"] = -1
        self.assertEqual(self.row()["reason"], "invalid_expression_count")

    def test_failed_dependency_read_type_or_timestamp_never_carries(self):
        for name in ROLES:
            for patch in ({"status": "unknown", "value": None}, {"value": True},
                          {"guard_ids": []}, {"read_end_ticks": 99}, {"type": "f32"}):
                frame = copy.deepcopy(self.frame)
                frame["fields"][name].update(patch)
                self.assertIsNone(self.row(frame)["ammunition_candidate"], (name, patch))
        for phase in ("before", "after"):
            frame = copy.deepcopy(self.frame)
            frame["guards_" + phase][-1]["ok"] = False
            self.assertIsNone(self.row(frame)["ammunition_candidate"])
        self.assertEqual(self.row()["ammunition_candidate"]["value"], 40)

    def test_gaps_wrong_profile_target_and_foreign_relation_are_unknown(self):
        self.assertIsNone(self.row(gap=True)["ammunition_candidate"])
        self.assertIsNone(self.row(relation_projection={})["ammunition_candidate"])
        self.frame["skipped_intervals_before"] = 1
        self.assertEqual(self.row()["reason"], "gap_before_frame")
        for key in ("profile", "target"):
            frame = copy.deepcopy(self.frame)
            frame["skipped_intervals_before"] = 0
            if key == "profile": frame["profile_sha256"] = "00" * 32
            else: frame["target"]["creation_file_time"] += 1
            self.assertIsNone(self.row(frame)["ammunition_candidate"])

    def test_new_body_requires_new_review_even_if_controller_survives(self):
        for index, value in ((2, 0x80000100), (3, 0x80000101), (4, 0x80000100)):
            change_word(self.profile, self.values, index, value)
        relations, frame = prepare(self.profile, self.values)
        self.contract["profile_sha256"] = relations.hash
        self.manifest["profile_sha256"] = relations.hash
        self.contract["acquisition_manifest_sha256"] = self.artifact(self.manifest)
        self.decoder = self.make()
        self.assertEqual(self.row(frame)["reason"], "reviewed_object_mismatch")

    def test_same_actor_different_scalar_storage_cannot_reuse_hud_review(self):
        self.profile["fields"][-1]["address"] += 0x1000
        relations, _ = prepare(self.profile, self.values)
        self.contract["profile_sha256"] = relations.hash
        self.manifest["profile_sha256"] = relations.hash
        self.contract["acquisition_manifest_sha256"] = self.artifact(self.manifest)
        with self.assertRaisesRegex(InvalidAmmunitionEvidence, "hud_storage_binding_mismatch"):
            self.make()

    def test_artifact_corruption_build_unreviewed_cache_policy_rejected(self):
        for pin in ("recipe_sha256", "evidence_sha256"):
            bad = self.artifacts[self.contract["source"][pin]]
            self.artifacts[self.contract["source"][pin]] = b"corrupt"
            with self.assertRaises(InvalidAmmunitionEvidence): self.make()

    def test_native_review_must_approve_the_acquired_recipe(self):
        self.native["recipe_sha256"] = "00" * 32
        self.contract["native_review_sha256"] = self.artifact(self.native)
        with self.assertRaisesRegex(InvalidAmmunitionEvidence, "native_review"):
            self.make()
            self.artifacts[self.contract["source"][pin]] = bad
        for patch in ({"active_cache_policy": "fresh"}, {"int32_type": True}, {"float32_type": 2}):
            native = copy.deepcopy(self.native)
            native["algorithm"].update(patch)
            self.contract["native_review_sha256"] = self.artifact(native)
            with self.assertRaises(InvalidAmmunitionEvidence): self.make()

    def test_bad_binding_dependencies_duplicate_selection_and_review_rejected(self):
        for mutation in ("missing", "duplicate", "dependency", "type", "hud"):
            contract = copy.deepcopy(self.contract)
            profile = copy.deepcopy(self.profile)
            if mutation == "missing": contract["bindings"][0]["fields"].pop("flags")
            if mutation == "duplicate": contract["bindings"].append(copy.deepcopy(contract["bindings"][0]))
            if mutation == "dependency": contract["bindings"][0]["required_guard_ids"] = [999]
            if mutation == "type": profile["fields"][-1]["type"] = "f32"
            if mutation == "hud":
                hud = dict(self.hud, controller_object_key="controller:" + "00" * 32)
                contract["bindings"][0]["hud_review_sha256"] = self.artifact(hud)
            with self.assertRaises(InvalidAmmunitionEvidence, msg=mutation):
                GuardedAmmunitionCandidates(raw(profile), raw(contract), self.artifacts)

    def test_detached_outputs_keep_all_read_and_source_provenance(self):
        output = self.decoder.project(self.frame)
        self.assertEqual(len(output["rows"][0]["evidence"]), 7)
        self.assertEqual(output["source_evidence"]["recipe_sha256"], self.contract["source"]["recipe_sha256"])
        self.assertEqual(output["timing"]["start_ticks"], self.frame["start_ticks"])
        self.assertNotIn("address", json.dumps(output))
        output["rows"][0]["evidence"][0]["guard_ids"].clear()
        output["rows"][0]["storage_candidate"].clear()
        self.assertEqual(self.row()["ammunition_candidate"]["value"], 40)

    def tick_fixture(self):
        for role, value, kind in (("direct_tick", 20, "i32"), ("direct_branch", 0, "u8"),
                                  ("virtual_tick", 30, "i32")):
            self.profile["fields"].append(dict(name=role, type=kind, address=0x5000 + len(self.values) * 8))
            self.values[role] = value
        relations, self.frame = prepare(self.profile, self.values)
        self.frame["fields"]["direct_branch"]["type"] = "u8"
        self.native["algorithm"]["cache_freshness"] = dict(force_recompute_mask=1, tick_check_mask=2)
        self.native["tick_storage_bindings_sha256"] = [ammunition_tick_binding_sha256(
            raw(self.profile), {n: n for n in ("direct_tick", "direct_branch", "virtual_tick")})]
        pin = self.artifact(self.native)
        self.contract["native_review_sha256"] = pin
        self.hud["native_review_sha256"] = pin
        self.contract["bindings"][0]["hud_review_sha256"] = self.artifact(self.hud)
        self.contract["bindings"][0]["tick_fields"] = {n: n for n in (
            "direct_tick", "direct_branch", "virtual_tick")}
        self.contract["profile_sha256"] = relations.hash
        self.manifest["profile_sha256"] = relations.hash
        self.contract["acquisition_manifest_sha256"] = self.artifact(self.manifest)
        self.decoder = self.make()
        self.frame["fields"]["expression_count"]["value"] = 1

    def test_tick_checks_distinguish_reuse_from_recomputation_without_claiming_execution(self):
        self.tick_fixture()
        self.frame["fields"]["flags"]["value"] = 2
        self.assertEqual(self.row()["ammunition_candidate"]["native_cache_condition"], "native_recompute_required")
        self.frame["fields"]["cached_tick"]["value"] = 30
        self.assertEqual(self.row()["ammunition_candidate"]["native_cache_condition"], "native_reuse_condition_observed")
        self.frame["fields"]["direct_branch"]["value"] = 1
        self.assertEqual(self.row()["ammunition_candidate"]["native_cache_condition"], "native_recompute_required")
        self.frame["fields"]["cached_tick"]["value"] = 20
        self.assertEqual(self.row()["ammunition_candidate"]["native_cache_condition"], "native_reuse_condition_observed")
        self.frame["fields"]["flags"]["value"] = 3
        candidate = self.row()["ammunition_candidate"]
        self.assertEqual(candidate["native_cache_condition"], "native_recompute_required")
        self.assertEqual(candidate["freshness"], "sampled_cache_not_recomputed")
        self.assertFalse(candidate["engine_evaluation_validated"])

    def test_tick_failure_nulls_active_candidate_but_unused_tick_does_not_block_base(self):
        self.tick_fixture()
        self.frame["fields"]["virtual_tick"]["status"] = "unknown"
        self.assertIsNone(self.row()["ammunition_candidate"])
        self.frame["fields"]["expression_count"]["value"] = 0
        self.assertEqual(self.row()["ammunition_candidate"]["value"], 40)

    def test_overlapping_freshness_masks_rejected(self):
        self.tick_fixture()
        self.native["algorithm"]["cache_freshness"]["tick_check_mask"] = 1
        self.contract["native_review_sha256"] = self.artifact(self.native)
        with self.assertRaises(InvalidAmmunitionEvidence): self.make()

    def test_wrong_tick_declaration_cannot_bypass_sample_type(self):
        self.tick_fixture()
        self.profile["fields"][-2]["type"] = "i32"
        relations, _ = prepare(self.profile, self.values)
        self.contract["profile_sha256"] = relations.hash
        self.manifest["profile_sha256"] = relations.hash
        self.contract["acquisition_manifest_sha256"] = self.artifact(self.manifest)
        with self.assertRaisesRegex(InvalidAmmunitionEvidence, "tick_route_dependencies"):
            self.make()

    def test_reassigning_tick_roles_without_native_review_is_rejected(self):
        self.tick_fixture()
        fields = self.contract["bindings"][0]["tick_fields"]
        fields["direct_tick"], fields["virtual_tick"] = fields["virtual_tick"], fields["direct_tick"]
        with self.assertRaisesRegex(InvalidAmmunitionEvidence, "native_tick_binding_mismatch"):
            self.make()


class CallbackReconstructionTests(unittest.TestCase):
    def setUp(self):
        (self.profile, self.values, _, self.contract, self.artifacts,
         self.manifest, self.native, self.hud) = ammunition_fixture()
        bits = lambda value: struct.unpack("<i", struct.pack("<f", value))[0]
        self.values.update(expression_count=1, cached_bits=26)
        values = dict(count_after=1, capacity=1, descriptor_child_low=0x7000, descriptor_child_high=0,
                      descriptor_selector=0, descriptor_operand_count=0, descriptor_value_count=0,
                      clock_low=1300, clock_high=0, timestamp_a_low=1000, timestamp_a_high=0,
                      timestamp_b_low=0, timestamp_b_high=0, integer_base=40, integer_multiplier=2,
                      integer_offset=1, curve_base_bits=bits(20), curve_slope_bits=bits(0), enabled_flags=1)
        self.callback = dict(fields={role: "callback_" + role for role in CALLBACK_ROLES},
                             expected_child_pointer=0x7000, expected_capacity=1)
        for index, (role, value) in enumerate(values.items()):
            name = self.callback["fields"][role]
            self.profile["fields"].append(dict(name=name, type="i32", address=0x5000 + index * 8))
            self.values[name] = value
        relations, self.frame = prepare(self.profile, self.values)
        self.frame["fields"]["expression_count"].update(read_start_ticks=21, read_end_ticks=22)
        self.frame["fields"][self.callback["fields"]["count_after"]].update(
            read_start_ticks=60, read_end_ticks=61)
        self.contract["profile_sha256"] = relations.hash
        self.manifest["profile_sha256"] = relations.hash
        self.contract["acquisition_manifest_sha256"] = self.artifact(self.manifest)
        self.native["callback_algorithm"] = dict(
            selection="signed_i64_elapsed_zero_slope_i32_depletion", selector=0, enabled_mask=1,
            clock_scale_f32_bits=bits(.001), rounding_assumption="binary32_nearest_even_no_flush_to_zero")
        self.native["callback_storage_bindings_sha256"] = [
            ammunition_callback_binding_sha256(raw(self.profile), self.callback)]
        self.contract["native_review_sha256"] = self.artifact(self.native)
        self.hud["native_review_sha256"] = self.contract["native_review_sha256"]
        self.contract["bindings"][0].update(callback=copy.deepcopy(self.callback),
                                           hud_review_sha256=self.artifact(self.hud))
        self.decoder = self.make()

    def artifact(self, value):
        data = raw(value)
        digest = hashlib.sha256(data).hexdigest()
        self.artifacts[digest] = data
        return digest

    def make(self):
        return GuardedAmmunitionCandidates(raw(self.profile), raw(self.contract), self.artifacts)

    def set_value(self, role, value):
        self.frame["fields"][self.callback["fields"][role]]["value"] = value

    def row(self, **kwargs):
        return self.decoder.project(self.frame, **kwargs)["rows"][0]

    def test_separate_reconstruction_preserves_sampled_cache_and_assumptions(self):
        row = self.row()
        candidate = row["callback_reconstruction_candidate"]
        self.assertEqual(candidate["value"], 26)
        self.assertEqual(candidate["integrated_index_i32"], 6)
        self.assertTrue(candidate["sampled_cache_equal"])
        self.assertFalse(candidate["engine_evaluation_validated"])
        self.assertFalse(candidate["clock_reads_atomic"])
        self.assertTrue(candidate["split_qwords"])
        self.assertEqual(len(row["callback_reconstruction_evidence"]), len(CALLBACK_ROLES))
        self.frame["fields"]["cached_bits"]["value"] = 12
        row = self.row()
        self.assertEqual(row["ammunition_candidate"]["value"], 12)
        self.assertEqual(row["callback_reconstruction_candidate"]["value"], 26)
        self.assertFalse(row["callback_reconstruction_candidate"]["sampled_cache_equal"])
        self.assertIsNone(row["is_firing"])

    def test_unconfigured_output_is_exactly_unchanged(self):
        without = copy.deepcopy(self.contract)
        without["bindings"][0].pop("callback")
        legacy = GuardedAmmunitionCandidates(raw(self.profile), raw(without), self.artifacts).project(self.frame)
        enabled = self.decoder.project(self.frame)
        for key in ("callback_reconstruction_candidate", "callback_reconstruction_reason",
                    "callback_reconstruction_evidence"):
            enabled["rows"][0].pop(key)
        enabled["contract_sha256"] = legacy["contract_sha256"]
        self.assertEqual(raw(enabled), raw(legacy))

    def test_inactive_multiexpression_and_descriptor_counterexamples_keep_cache(self):
        for role, value, reason in [
                ("count_after", 0, "descriptor_count_changed"),
                ("capacity", 2, "descriptor_capacity_changed"),
                ("descriptor_child_low", 0x8000, "descriptor_child_mismatch"),
                ("descriptor_child_high", 1, "descriptor_child_mismatch"),
                ("descriptor_selector", 1, "unsupported_callback_selector"),
                ("descriptor_operand_count", 1, "unsupported_callback_operands"),
                ("descriptor_value_count", 1, "unsupported_callback_operands"),
                ("enabled_flags", 0, "callback_child_disabled"),
                ("curve_slope_bits", 0x3f800000, "unsupported_callback_curve"),
                ("curve_base_bits", 0x7fc00000, "unsupported_callback_numeric_state"),
                ("curve_base_bits", 1, "unsupported_callback_numeric_state"),
                ("curve_base_bits", 0x7f7fffff, "unsupported_callback_integer_conversion")]:
            frame = copy.deepcopy(self.frame)
            self.set_value(role, value)
            row = self.row()
            self.assertIsNone(row["callback_reconstruction_candidate"], role)
            self.assertEqual(row["callback_reconstruction_reason"], reason, role)
            self.assertEqual(row["ammunition_candidate"]["value"], 26, role)
            self.frame = frame
        for count, reason in [(0, "inactive_expression_descriptor"), (2, "unsupported_expression_count")]:
            self.frame["fields"]["expression_count"]["value"] = count
            self.assertEqual(self.row()["callback_reconstruction_reason"], reason)

    def test_missing_read_bad_guards_gaps_and_changed_controller_never_carry(self):
        for role in CALLBACK_ROLES:
            frame = copy.deepcopy(self.frame)
            self.frame["fields"][self.callback["fields"][role]]["guard_ids"] = []
            row = self.row()
            self.assertIsNone(row["callback_reconstruction_candidate"], role)
            self.assertIsNotNone(row["ammunition_candidate"], role)
            self.frame = frame
        self.assertIsNone(self.row(gap=True)["callback_reconstruction_candidate"])
        self.frame["guards_after"][0]["ok"] = False
        self.assertIsNone(self.row()["callback_reconstruction_candidate"])
        self.frame["guards_after"][0]["ok"] = True
        self.frame["target"]["creation_file_time"] += 1
        self.assertIsNone(self.row()["callback_reconstruction_candidate"])

    def test_equal_counts_must_bracket_all_current_callback_inputs(self):
        self.frame["fields"][self.callback["fields"]["count_after"]].update(
            read_start_ticks=35, read_end_ticks=40)
        row = self.row()
        self.assertIsNotNone(row["ammunition_candidate"])
        self.assertEqual(row["callback_reconstruction_reason"], "callback_input_count_bracket")
        self.assertIsNone(row["callback_reconstruction_candidate"])

    def test_binding_changes_missing_review_and_nonnative_declarations_reject(self):
        self.contract["bindings"][0]["callback"]["expected_child_pointer"] = 0x8000
        with self.assertRaisesRegex(InvalidAmmunitionEvidence, "native_callback_binding_mismatch"):
            self.make()
        self.contract["bindings"][0]["callback"] = copy.deepcopy(self.callback)
        self.contract["bindings"][0]["callback"]["fields"]["clock_low"] = "cached_bits"
        with self.assertRaisesRegex(InvalidAmmunitionEvidence, "callback_bindings"):
            self.make()
        self.contract["bindings"][0]["callback"] = copy.deepcopy(self.callback)
        self.profile["fields"][-1]["type"] = "f32"
        relations, _ = prepare(self.profile, self.values)
        self.contract["profile_sha256"] = self.manifest["profile_sha256"] = relations.hash
        self.contract["acquisition_manifest_sha256"] = self.artifact(self.manifest)
        with self.assertRaisesRegex(InvalidAmmunitionEvidence, "callback_route_dependencies"):
            self.make()

    def test_native_wrap_negative_time_and_direct_i64_rounding(self):
        self.set_value("timestamp_b_low", 400)
        row = self.row()["callback_reconstruction_candidate"]
        self.assertEqual((row["elapsed_i64"], row["integrated_index_i32"], row["value"]), (-100, -1, 40))
        self.set_value("timestamp_b_low", 0)
        self.set_value("integer_offset", 0x7fffffff)
        self.assertEqual(self.row()["callback_reconstruction_candidate"]["value"], 30)
        integer = (1 << 62) + (1 << 38) + 1
        self.assertEqual(_i64_to_f32(integer), (1 << 62) + (1 << 39))
        self.assertEqual(_i64_to_f32(-integer), -((1 << 62) + (1 << 39)))
        self.set_value("clock_low", -1)
        self.set_value("clock_high", 0x7fffffff)
        self.assertIsNone(self.row()["callback_reconstruction_candidate"])

    def test_same_controller_replacement_body_cannot_reuse_callback_review(self):
        for index, value in ((2, 0x80000100), (3, 0x80000101), (4, 0x80000100)):
            change_word(self.profile, self.values, index, value)
        relations, self.frame = prepare(self.profile, self.values)
        self.contract["profile_sha256"] = self.manifest["profile_sha256"] = relations.hash
        self.contract["acquisition_manifest_sha256"] = self.artifact(self.manifest)
        self.decoder = self.make()
        row = self.row()
        self.assertEqual(row["controller_object_key"], self.hud["controller_object_key"])
        self.assertNotEqual(row["body_object_key"], self.hud["body_object_key"])
        self.assertIsNone(row["ammunition_candidate"])
        self.assertIsNone(row["callback_reconstruction_candidate"])
        self.assertEqual(row["callback_reconstruction_reason"], "reviewed_object_mismatch")


def semantic_fixture():
    """Synthetic native transcript and two independently reviewed body objects."""
    profile, values, _, contract, artifacts, manifest, native, hud = ammunition_fixture()
    def add(value):
        data = value if isinstance(value, bytes) else raw(value)
        pin = hashlib.sha256(data).hexdigest(); artifacts[pin] = data; return pin
    for name, value in (("resource_low", 0x1234), ("resource_high", 0x5678)):
        profile["fields"].append(dict(name=name, type="i32", address=0x8000 + len(values)*8))
        values[name] = value
    relation, frame = prepare(profile, values)
    original = relation.project(frame)["relations"][0]
    words = {role: relation._binding("controller_0000"+suffix)[1] for role, suffix in
             (("full_handle_u32", "_handle_candidate_i32"), ("creation_key_u32", "_manager_key_candidate_i32"))}
    recipe = dict(schema="overwatch-decoder.acquisition-recipe/1", target={k:relation.target[k] for k in
                  ("image_name", "architecture", "executable_sha256")},
                  selector=dict(words), stages=[dict(name="synthetic", steps=[])])
    recipe_pin = add(recipe); native["recipe_sha256"] = recipe_pin
    native_pin = add(native); contract["native_review_sha256"] = native_pin
    validations = []
    for index in (0, 1):
        pp, vv = copy.deepcopy(profile), copy.deepcopy(values)
        if index:
            for i, v in ((2, 0x80000090), (3, 0x80000091), (4, 0x80000090)):
                change_word(pp, vv, i, v)
        rr, ff = prepare(pp, vv); row = rr.project(ff)["relations"][0]
        hh = dict(hud, target=rr.target, native_review_sha256=native_pin,
                  controller_object_key=row["controller_object_key"], body_object_key=row["body_object_key"])
        validations.append(dict(kind="training" if index == 0 else "independent_body_holdout",
            profile_sha256=add(raw(pp)), controller_prefix="controller_0000", fields=contract["bindings"][0]["fields"],
            hud_review_sha256=add(hh)))
    semantic = dict(schema="overwatch-decoder.ammunition-semantic-template-review/1", reviewed=True,
        review_method="native_route_and_independent_body_holdout",
        scope="controlled_local_participant_standard_primary", readout="ammunition_current",
        build_sha256=relation.target["executable_sha256"], native_review_sha256=native_pin,
        approved_recipe_sha256=recipe_pin, approved_controller_words=words,
        selector_relocations=[dict(pointer="/selector/"+role, role=role) for role in words],
        fields=contract["bindings"][0]["fields"], callback=None,
        hero=dict(fields=dict(low="resource_low", high="resource_high"), low_u32=0x1234, high_u32=0x5678),
        observed_maximum=40, validations=validations, sources=[add(b"synthetic controlled holdout audit")])
    participant = dict(schema="overwatch-decoder.ammunition-controlled-participant-review/1", reviewed=True,
        review_method="controlled_input_and_guarded_controller", role="controlled_local_participant",
        target=relation.target, controller_object_key=original["controller_object_key"],
        frame_scope=dict(monotonic_frequency=1000, start_ticks=0, end_ticks=1000),
        sources=[add(b"synthetic controlled input/controller witness")])
    contract["semantic_review_sha256"] = add(semantic)
    contract["participant_review_sha256"] = add(participant)
    contract["bindings"][0].pop("hud_review_sha256")
    data = dict(profile=profile, values=values, contract=contract, artifacts=artifacts,
                manifest=manifest, native=native, recipe=recipe, semantic=semantic, participant=participant)
    refresh_semantic_source(data)
    return data


def refresh_semantic_source(data):
    profile, values, c, artifacts = [data[k] for k in ("profile", "values", "contract", "artifacts")]
    def add(value):
        b = value if isinstance(value, bytes) else raw(value)
        h = hashlib.sha256(b).hexdigest(); artifacts[h] = b; return h
    rr, frame = prepare(profile, values); row = rr.project(frame)["relations"][0]
    c["profile_sha256"] = rr.hash
    c["bindings"][0].update(controller_object_key=row["controller_object_key"], body_object_key=row["body_object_key"])
    c["source"]["recipe_sha256"] = add(data["recipe"])
    events = [dict(schema="overwatch-decoder.acquisition-evidence/1", kind="start", source_kind="native_process_memory",
                   target=rr.target, recipe_sha256=c["source"]["recipe_sha256"], revision="synthetic")]
    for i, g in enumerate(rr.guards):
        events.append(dict(kind="read", id=i, address=g["address"], bytes_hex=g["bytes_hex"],
            requested_bytes=len(bytes.fromhex(g["bytes_hex"])), returned_bytes=len(bytes.fromhex(g["bytes_hex"])),
            attempted=True, error=None, read_start_ticks=1, read_end_ticks=2))
    for i, g in enumerate(rr.guards):
        events.append(dict(kind="read", id=i+len(rr.guards), address=g["address"], bytes_hex=g["bytes_hex"],
            requested_bytes=len(bytes.fromhex(g["bytes_hex"])), returned_bytes=len(bytes.fromhex(g["bytes_hex"])),
            attempted=True, error=None, read_start_ticks=3, read_end_ticks=4))
        events.append(dict(kind="guard_check", stage="final_guard_check", matches=True,
            expected_read_id=i, actual_read_id=i+len(rr.guards), expected_offset=0))
    events.append(dict(kind="profile_validated", profile_sha256=rr.hash, fields=len(rr.fields)))
    evidence = b"\n".join(raw(e) for e in events)+b"\n"
    c["source"]["evidence_sha256"] = add(evidence)
    m = data["manifest"];m.update(profile_sha256=rr.hash, stages_completed=1, revision="synthetic", **c["source"])
    c["acquisition_manifest_sha256"] = add(m)
    data["frame"] = frame


class SemanticTemplateTests(unittest.TestCase):
    def setUp(self):
        self.data = semantic_fixture()

    def make(self):
        d = self.data
        return GuardedAmmunitionCandidates(raw(d["profile"]), raw(d["contract"]), d["artifacts"])

    def artifact(self, key):
        d = self.data; b = raw(d[key]); h = hashlib.sha256(b).hexdigest();d["artifacts"][h] = b
        d["contract"][key+"_review_sha256" if key == "participant" else "semantic_review_sha256"] = h
        return h

    def test_optional_semantic_mode_has_distinct_review_and_no_new_hud_claim(self):
        result = self.make().project(self.data["frame"]); row = result["rows"][0]
        self.assertEqual(row["ammunition_candidate"]["value"], 40)
        self.assertEqual(result["semantic_validation"], "empirical_controlled_participant_template")
        self.assertIsNone(row["hud_review_sha256"])
        self.assertEqual(len(row["semantic_evidence"]), 2)
        self.assertFalse(result["public_state_eligible"])
        self.assertIsNone(row["is_firing"])

    def test_new_body_and_storage_bind_fresh_without_rewriting_any_hud_review(self):
        d = self.data; old = self.make().project(d["frame"])["rows"][0]
        reviews = {v["hud_review_sha256"]:d["artifacts"][v["hud_review_sha256"]]for v in d["semantic"]["validations"]}
        for i, value in ((2, 0x80000200), (3, 0x80000201), (4, 0x80000200)):
            change_word(d["profile"], d["values"], i, value, 0xA000+i*8 if i>=3 else None)
        d["profile"]["fields"][5]["address"] += 0x2000
        refresh_semantic_source(d); row = self.make().project(d["frame"])["rows"][0]
        self.assertEqual(row["ammunition_candidate"]["value"], 40)
        self.assertEqual(row["controller_object_key"], old["controller_object_key"])
        self.assertNotEqual(row["body_object_key"], old["body_object_key"])
        self.assertEqual(reviews, {h:d["artifacts"][h]for h in reviews})

    def test_changed_hero_unknown_gap_and_scope_never_carry(self):
        d = self.data; decoder = self.make()
        for change, reason in ((dict(value=9), "semantic_hero_mismatch"),
                               (dict(status="unknown", value=None), "identity_word_unobserved"),
                               (dict(guard_ids=[]), "guard_dependencies_mismatch")):
            f = copy.deepcopy(d["frame"]);f["fields"]["resource_low"].update(change)
            row = decoder.project(f)["rows"][0]
            self.assertIsNone(row["ammunition_candidate"]);self.assertEqual(row["reason"], reason)
        self.assertIsNone(decoder.project(d["frame"], gap=True)["rows"][0]["ammunition_candidate"])
        unsupported = copy.deepcopy(d["frame"])
        unsupported["fields"]["expression_count"]["value"] = 2
        self.assertEqual(decoder.project(unsupported)["rows"][0]["reason"],
                         "unsupported_semantic_expression_count")
        f = copy.deepcopy(d["frame"]);f["monotonic_frequency"] = 2000
        self.assertEqual(decoder.project(f)["rows"][0]["reason"], "outside_controlled_participant_scope")
        self.assertEqual(decoder.project(d["frame"])["rows"][0]["ammunition_candidate"]["value"], 40)

    def test_participant_key_role_target_and_review_scope_must_match(self):
        for key, value in (("role", "enemy"), ("role", "spectator"),
                           ("controller_object_key", "controller:"+"0"*64), ("reviewed", False)):
            with self.subTest(key=key, value=value):
                self.data = semantic_fixture();self.data["participant"][key] = value;self.artifact("participant")
                with self.assertRaisesRegex(InvalidAmmunitionEvidence, "semantic_participant_scope"): self.make()
        self.data = semantic_fixture();self.data["participant"]["target"]["pid"] += 1;self.artifact("participant")
        with self.assertRaisesRegex(InvalidAmmunitionEvidence, "semantic_participant_scope"): self.make()

    def test_frame_scope_is_finite_and_outside_rows_are_unknown(self):
        d = self.data; d["participant"]["frame_scope"]["end_ticks"] = 99;self.artifact("participant")
        self.assertEqual(self.make().project(d["frame"])["rows"][0]["reason"], "outside_controlled_participant_scope")
        d["participant"]["frame_scope"]["end_ticks"] = 180001;self.artifact("participant")
        with self.assertRaisesRegex(InvalidAmmunitionEvidence, "semantic_finite_frame_scope"): self.make()

    def test_recipe_role_remap_and_guard_removal_are_rejected(self):
        d = self.data; d["recipe"]["stages"][0]["steps"].append(dict(op="unreviewed"));refresh_semantic_source(d)
        with self.assertRaisesRegex(InvalidAmmunitionEvidence, "semantic_recipe_structure_changed"): self.make()
        self.data = semantic_fixture();fields = self.data["contract"]["bindings"][0]["fields"]
        fields["base_bits"], fields["cached_bits"] = fields["cached_bits"], fields["base_bits"]
        with self.assertRaisesRegex(InvalidAmmunitionEvidence, "semantic_scalar_roles"): self.make()
        self.data = semantic_fixture();self.data["contract"]["bindings"][0]["required_guard_ids"].pop()
        with self.assertRaisesRegex(InvalidAmmunitionEvidence, "semantic_complete_route_guards"): self.make()

    def test_fresh_controller_requires_a_new_explicit_participant_review(self):
        d = self.data
        change_word(d["profile"], d["values"], 0, 0x80000400)
        d["recipe"]["selector"]["full_handle_u32"] = 0x80000400;refresh_semantic_source(d)
        with self.assertRaisesRegex(InvalidAmmunitionEvidence, "semantic_participant_scope"): self.make()
        rr, f = prepare(d["profile"], d["values"]);d["participant"]["controller_object_key"] = rr.project(f)["relations"][0]["controller_object_key"]
        self.artifact("participant")
        self.assertEqual(self.make().project(f)["rows"][0]["ammunition_candidate"]["value"], 40)

    def test_same_body_is_not_an_independent_holdout(self):
        d = self.data; d["semantic"]["validations"][1] = dict(d["semantic"]["validations"][0], kind="independent_body_holdout")
        self.artifact("semantic")
        with self.assertRaisesRegex(InvalidAmmunitionEvidence, "semantic_independent_body_holdout_required"): self.make()

    def test_fresh_native_final_guard_evidence_is_checked(self):
        d = self.data
        events = [json.loads(line) for line in d["artifacts"][d["contract"]["source"]["evidence_sha256"]].splitlines()]
        next(e for e in events if e.get("kind") == "guard_check")["matches"] = False
        evidence = b"\n".join(raw(e) for e in events) + b"\n"
        pin = hashlib.sha256(evidence).hexdigest();d["artifacts"][pin] = evidence
        d["contract"]["source"]["evidence_sha256"] = d["manifest"]["evidence_sha256"] = pin
        manifest = raw(d["manifest"]);pin = hashlib.sha256(manifest).hexdigest();d["artifacts"][pin] = manifest
        d["contract"]["acquisition_manifest_sha256"] = pin
        with self.assertRaisesRegex(InvalidAmmunitionEvidence, "semantic_acquisition_guard_evidence"):
            self.make()

    def test_no_mixed_or_partial_legacy_semantic_admission(self):
        d = self.data;d["contract"]["bindings"][0]["hud_review_sha256"] = d["semantic"]["validations"][0]["hud_review_sha256"]
        with self.assertRaisesRegex(InvalidAmmunitionEvidence, "semantic_scalar_roles"): self.make()
        d["contract"].pop("participant_review_sha256")
        with self.assertRaisesRegex(InvalidAmmunitionEvidence, "semantic_review_pair_required"): self.make()

    def test_semantic_callback_requires_reviewed_roles_and_fresh_provider_anchor(self):
        d = self.data
        case = CallbackReconstructionTests();case.setUp()
        callback = copy.deepcopy(case.callback);callback["expected_child_pointer"] = 0x4000
        for field in case.profile["fields"]:
            if field["name"].startswith("callback_"):
                d["profile"]["fields"].append(copy.deepcopy(field))
                d["values"][field["name"]] = case.values[field["name"]]
        d["values"].update(expression_count=1, cached_bits=26)
        d["values"][callback["fields"]["descriptor_child_low"]] = 0x4000
        d["contract"]["bindings"][0]["callback"] = callback
        d["native"]["callback_algorithm"] = case.native["callback_algorithm"]
        native_raw = raw(d["native"]);pin = hashlib.sha256(native_raw).hexdigest();d["artifacts"][pin] = native_raw
        d["contract"]["native_review_sha256"] = d["semantic"]["native_review_sha256"] = pin
        anchor = callback["fields"]["integer_base"]
        address = next(f["address"]for f in d["profile"]["fields"]if f["name"]==anchor)
        d["semantic"]["callback"] = dict(fields=callback["fields"].copy(), expected_capacity=1,
            child_anchor_field=anchor, child_anchor_offset=address-0x4000)
        self.artifact("semantic");refresh_semantic_source(d)
        d["frame"]["fields"]["expression_count"].update(read_start_ticks=21, read_end_ticks=22)
        d["frame"]["fields"][callback["fields"]["count_after"]].update(read_start_ticks=60, read_end_ticks=61)
        decoder = self.make();row = decoder.project(d["frame"])["rows"][0]
        self.assertEqual(row["callback_reconstruction_candidate"]["value"], 26)
        bad = copy.deepcopy(d["frame"]);bad["fields"][callback["fields"]["descriptor_child_low"]]["value"] += 8
        row = decoder.project(bad)["rows"][0]
        self.assertEqual(row["ammunition_candidate"]["value"], 26)
        self.assertEqual(row["callback_reconstruction_reason"], "descriptor_child_mismatch")
        d["contract"]["bindings"][0]["callback"]["expected_child_pointer"] += 8
        with self.assertRaisesRegex(InvalidAmmunitionEvidence, "semantic_callback_provider"):self.make()


if __name__ == "__main__":
    unittest.main()
