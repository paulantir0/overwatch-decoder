import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("prepare", Path(__file__).with_name("prepare.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture():
    return [
        {"schema": "overwatch-decoder.private-entity-timeline/1", "kind": "metadata", "public_state_eligible": False},
        {"kind": "epoch_start", "epoch_id": "a", "qpc_frequency": 10,
         "session_qpc_origin": 9007199254741000, "actors": [{"ordinal": 0, "object_key": "key-A"}]},
        {"kind": "frame", "epoch_id": "a", "sequence": 0,
         "start_ticks": 9007199254741010, "end_ticks": 9007199254741019,
         "skipped_intervals_before": 0, "continuity_valid": True,
         "actors": [{"ordinal": 0, "declared_object_key": "key-A", "object_key": "key-A",
                     "identity_status": "guarded", "is_self": True,
                     "fields": {"position_candidate": {"type": "f32x3", "status": "observed",
                                "value": [1.0000000000000002, -2.5, 0.0],
                                "read_start_ticks": 9007199254741011,
                                "read_end_ticks": 9007199254741012}}}]},
        {"kind": "epoch_end", "epoch_id": "a", "frames": 1},
    ]


def pool_fixture(values=(425, 100, 226.377258)):
    rows = fixture()
    rows[1]["actors"][0]["is_self"] = True
    rows[1]["actors"][0]["pools"] = [
        {"ordinal": i, "pool_index": i * 16, "membership_u32": i + 1,
         "field_name": f"actor_0000_pool_{i:04d}_direct_candidate"}
        for i in range(len(values))]
    for i, value in enumerate(values):
        rows[2]["actors"][0]["fields"][f"pool_{i:04d}_direct_candidate"] = {
            "status": "observed", "type": "f32", "value": value,
            "read_start_ticks": 9007199254741013 + i,
            "read_end_ticks": 9007199254741014 + i}
    return rows


class PrepareTests(unittest.TestCase):
    def convert(self, rows, **limits):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source.jsonl"
            output = Path(temporary) / "out.json"
            raw = "".join(json.dumps(r) + "\n" for r in rows).encode()
            source.write_bytes(raw)
            summary = module.prepare(source, output, **limits)
            result = json.loads(output.read_text())
            self.assertEqual(result["source_sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(summary, result["summary"])
            return result

    def test_exact_values_ticks_and_neutral_labels(self):
        result = self.convert(fixture())
        self.assertEqual(result["frames"][0]["objects"], [[0, 1.0000000000000002, -2.5, 0.0, True]])
        self.assertEqual(result["frames"][0]["start_ticks"], "9007199254741010")
        self.assertEqual(result["frames"][0]["reads"], [[0, "9007199254741011", "9007199254741012"]])
        self.assertEqual(result["frames"][0]["t"], 1)
        self.assertEqual(result["objects"][0]["label"], "Object 001")
        self.assertFalse(result["frames"][0]["continuity_valid"])

    def test_complete_declared_self_pools_preserve_third_pool_and_zero(self):
        for values in ((425, 100, 226.377258), (0, 0)):
            result = self.convert(pool_fixture(values))
            pools = result["frames"][0]["self_pools"]
            self.assertEqual(pools["declared_count"], len(values))
            self.assertEqual([p[3] for p in pools["pools"]], list(values))
            self.assertEqual(pools["pools"][0][4:], ["9007199254741013", "9007199254741014"])
            self.assertEqual(result["summary"]["complete_self_pool_frames"], 1)

    def test_incomplete_stale_or_nonself_pools_never_yield_partial_sum(self):
        for mode in ("missing", "extra", "unknown", "stale", "negative", "nonself", "unguarded", "no_declarations", "undeclared_self", "ambiguous_self"):
            rows = pool_fixture()
            actor = rows[2]["actors"][0]
            field = actor["fields"]["pool_0002_direct_candidate"]
            if mode == "missing":
                del actor["fields"]["pool_0002_direct_candidate"]
            elif mode == "extra":
                actor["fields"]["pool_0003_direct_candidate"] = dict(field)
            elif mode == "unknown":
                field.update(status="unknown")
            elif mode == "stale":
                field.update(read_start_ticks=9007199254741000)
            elif mode == "negative":
                field.update(value=-1)
            elif mode == "nonself":
                actor.update(is_self=False)
            elif mode == "unguarded":
                actor.update(identity_status="unknown", object_key=None)
            elif mode == "no_declarations":
                del rows[1]["actors"][0]["pools"]
            elif mode == "ambiguous_self":
                rows[1]["actors"].append({"ordinal": 1, "object_key": "key-B", "is_self": False})
                rows[2]["actors"].append({"ordinal": 1, "declared_object_key": "key-B",
                    "object_key": None, "identity_status": "unknown", "is_self": True, "fields": {}})
            else:
                del rows[1]["actors"][0]["is_self"]
            with self.subTest(mode=mode):
                result = self.convert(rows)
                self.assertIsNone(result["frames"][0]["self_pools"])
                self.assertEqual(result["summary"]["complete_self_pool_frames"], 0)

    def test_pool_declaration_mismatch_or_duplicates_are_rejected(self):
        for mode in ("field", "duplicate", "physical"):
            rows = pool_fixture()
            pools = rows[1]["actors"][0]["pools"]
            if mode == "field":
                pools[0]["field_name"] = "actor_0009_pool_0000_direct_candidate"
            elif mode == "duplicate":
                pools.append(copy.deepcopy(pools[0]))
            else:
                pools[1]["pool_index"] = pools[0]["pool_index"]
            with self.subTest(mode=mode), self.assertRaises(module.InvalidRecording):
                self.convert(rows)
        rows = pool_fixture()
        rows[1]["profile_sha256"] = "a" * 64
        rows[2]["profile_sha256"] = "b" * 64
        with self.assertRaisesRegex(module.InvalidRecording, "frame profile"):
            self.convert(rows)

    def test_unknown_frame_is_not_dropped_or_carried_forward(self):
        rows = fixture()
        f = copy.deepcopy(rows[2])
        f.update(sequence=1, start_ticks=9007199254741020, end_ticks=9007199254741029)
        f["actors"][0].update(object_key=None, identity_status="unknown", is_self=None)
        f["actors"][0]["fields"]["position_candidate"].update(status="unknown", value=None)
        rows.insert(3, f)
        rows[-1]["frames"] = 2
        result = self.convert(rows)
        self.assertEqual(len(result["frames"]), 2)
        self.assertEqual(result["frames"][1]["objects"], [])
        self.assertEqual(result["frames"][1]["unknown_count"], 1)
        self.assertFalse(result["frames"][1]["continuity_valid"])

    def test_ordinal_reshuffle_and_epoch_gap(self):
        rows = fixture()
        second = copy.deepcopy(rows[1:])
        for row in second:
            row["epoch_id"] = "b"
        second[0]["actors"][0]["ordinal"] = 9
        second[1]["actors"][0]["ordinal"] = 9
        second[1].update(start_ticks=9007199254742010, end_ticks=9007199254742019, skipped_intervals_before=7)
        second[1]["actors"][0]["fields"]["position_candidate"].update(read_start_ticks=9007199254742011, read_end_ticks=9007199254742012)
        result = self.convert(rows + second)
        self.assertEqual(len(result["objects"]), 1)
        self.assertEqual(result["epochs"][1]["objects"], [[9, 0]])
        self.assertFalse(result["frames"][1]["continuity_valid"])
        self.assertEqual(result["summary"]["skipped_intervals"], 7)

    def test_metadata_does_not_copy_source_paths_or_names(self):
        rows = fixture()
        rows[1].update(acquisition="private/path/acquisition", target={"pid": 7, "image_name": "private-name", "path": "/private", "executable_sha256": "a" * 64})
        result = self.convert(rows)
        text = json.dumps(result)
        self.assertNotIn("private/path", text)
        self.assertNotIn("private-name", text)
        self.assertNotIn("/private", text)
        self.assertEqual(result["epochs"][0]["target"], {"pid": 7, "executable_sha256": "a" * 64})

    def test_all_unknown_bounds_are_null(self):
        rows = fixture()
        rows[2]["actors"][0].update(object_key=None, identity_status="unknown", is_self=None)
        result = self.convert(rows)
        self.assertEqual(result["bounds"], {"min": None, "max": None})

    def test_reject_nonfinite_and_wrong_identity(self):
        for mutation in [lambda r: r[2]["actors"][0]["fields"]["position_candidate"].update(value=[float("nan"), 0, 0]),
                         lambda r: r[2]["actors"][0].update(object_key="other"),
                         lambda r: r[2]["actors"].append(copy.deepcopy(r[2]["actors"][0])),
                         lambda r: r[2].update(actors=[]),
                         lambda r: r[2]["actors"][0]["fields"]["position_candidate"].update(read_end_ticks=9007199254749999)]:
            with self.subTest(mutation=mutation):
                rows = fixture()
                mutation(rows)
                with self.assertRaises(module.InvalidRecording):
                    self.convert(rows)

    def test_reject_truncated_epoch_and_clock_mismatch(self):
        with self.assertRaises(module.InvalidRecording):
            self.convert(fixture()[:-1])
        rows = fixture()
        second = copy.deepcopy(rows[1:])
        second[0].update(epoch_id="b", qpc_frequency=11)
        with self.assertRaises(module.InvalidRecording):
            self.convert(rows + second)

    def test_limits_and_failure_do_not_replace_existing_output(self):
        for limit in [dict(max_input_bytes=1), dict(max_line_bytes=1), dict(max_output_bytes=1)]:
            with self.assertRaises(module.InvalidRecording):
                self.convert(fixture(), **limit)
        with tempfile.TemporaryDirectory() as temporary:
            source, output = Path(temporary) / "in", Path(temporary) / "out"
            source.write_text("\n".join(json.dumps(r) for r in fixture()[:-1]))
            output.write_text("keep me")
            with self.assertRaises(module.InvalidRecording):
                module.prepare(source, output)
            self.assertEqual(output.read_text(), "keep me")
            self.assertEqual(sorted(p.name for p in Path(temporary).iterdir()), ["in", "out"])

    def test_equal_frame_timestamps_are_rejected(self):
        rows = fixture()
        second = copy.deepcopy(rows[2])
        second["sequence"] = 1
        rows.insert(3, second)
        rows[-1]["frames"] = 2
        with self.assertRaisesRegex(module.InvalidRecording, "strictly increase"):
            self.convert(rows)

    def test_source_classification_must_be_explicitly_private(self):
        for value in [True, None, 0, "false"]:
            rows = fixture()
            rows[0]["public_state_eligible"] = value
            with self.subTest(value=value), self.assertRaisesRegex(module.InvalidRecording, "private research"):
                self.convert(rows)
        rows = fixture()
        del rows[0]["public_state_eligible"]
        with self.assertRaises(module.InvalidRecording):
            self.convert(rows)

    def test_position_limit_rejects_instead_of_truncating(self):
        rows = fixture()
        second = copy.deepcopy(rows[2])
        second.update(sequence=1, start_ticks=9007199254741020, end_ticks=9007199254741029)
        second["actors"][0]["fields"]["position_candidate"].update(read_start_ticks=9007199254741021, read_end_ticks=9007199254741022)
        rows.insert(3, second)
        rows[-1]["frames"] = 2
        with self.assertRaisesRegex(module.InvalidRecording, "position limit"):
            self.convert(rows, max_positions=1)

    def test_raw_rotation_exact_components_and_read_times(self):
        rows = fixture()
        q = [0.12500000000000003, -0.25, 0.5, 0.75]
        rows[2]["actors"][0]["fields"]["raw_quaternion_candidate"] = {
            "type": "f32x4", "status": "observed", "value": q,
            "read_start_ticks": 9007199254741013, "read_end_ticks": 9007199254741014}
        result = self.convert(rows)
        self.assertEqual(result["frames"][0]["rotations"], [[0, *q]])
        self.assertEqual(result["frames"][0]["rotation_reads"], [[0, "9007199254741013", "9007199254741014"]])
        self.assertFalse(result["orientation"]["values_normalized"])
        self.assertFalse(result["orientation"]["camera_aim_validated"])

    def test_rotation_missing_unknown_stale_and_unguarded_are_omitted(self):
        for mode in ["missing", "unknown", "stale", "unguarded"]:
            rows = fixture()
            actor = rows[2]["actors"][0]
            if mode != "missing":
                actor["fields"]["raw_quaternion_candidate"] = {
                    "type": "f32x4", "status": "unknown" if mode == "unknown" else "observed",
                    "value": [0, 0, 0, 1], "read_start_ticks": 9007199254741001 if mode == "stale" else 9007199254741011,
                    "read_end_ticks": 9007199254741012}
            if mode == "unguarded":
                actor.update(object_key=None, identity_status="unknown")
            with self.subTest(mode=mode):
                result = self.convert(rows)
                self.assertEqual(result["frames"][0]["rotations"], [])
                self.assertEqual(result["frames"][0]["unknown_rotation_count"], 1)

    def test_frame_limit_never_silently_truncates(self):
        rows = fixture()
        second = copy.deepcopy(rows[2])
        second["sequence"] = 1
        rows.insert(3, second)
        rows[-1]["frames"] = 2
        with self.assertRaises(module.InvalidRecording):
            self.convert(rows, max_frames=1)


if __name__ == "__main__":
    unittest.main()
