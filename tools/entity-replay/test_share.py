import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from share import FIELD_RULES, RAW_ORIENTATION, encode, export_shared

BUILD = "a"*64
SECRET = "C:/Users/private/saved.raw"


def row(time, hp):
    stamp = str(1000 + round(time*1000))
    proof = {name: dict(source=source, validation_status=status, observed_build_sha256=BUILD,
                        address=SECRET, reads=[{"bytes": SECRET}])
             for name, (status, source) in FIELD_RULES.items()}
    proof["raw_quaternion_candidate"]["semantics"] = RAW_ORIENTATION
    fields = {"hero": "Genji", "health": hp, "relation": "enemy", "raw_quaternion_candidate": [0, 0, 0, 1]}
    return dict(object=0, controller_id="controller:"+"c"*64, entity_id="body:"+"b"*64,
                observed_build_sha256=BUILD, username={"value": SECRET}, team={"value": "player"},
                source_timestamp=dict(start_ticks=stamp, end_ticks=stamp, frequency=1000, clock="windows_qpc", private=SECRET),
                field_evidence=proof, source_sha256=SECRET, arbitrary=SECRET,
                **{k: dict(value=v, validation_status=FIELD_RULES[k][0], reason=SECRET) for k,v in fields.items()})


def chunk(times, *, empty=False):
    frames, fields = [], []
    for i, time in enumerate(times):
        stamp = str(1000 + round(time*1000))
        frames.append(dict(t=time, end=time, epoch=SECRET, start_ticks=stamp, end_ticks=stamp,
                           sequence=i, skipped=2 if i else 0, unknown_count=1 if empty else 0,
                           continuity_valid=bool(i), objects=[] if empty else [[0, 1, 2, 3, False]],
                           rotations=[] if empty else [[0, 0, 0, 0, 1]],
                           field_refs=[] if empty else [i], reads=[SECRET], source_read_bracket=[SECRET]))
        fields.append(row(time, 0 if i else 30))
    return dict(schema="overwatch-decoder.entity-replay/1", public_state_eligible=False, compact_observations=True,
                source_sha256="d"*64, frequency=1000, origin_ticks="1000",
                epochs=[{"id": SECRET, "evidence": SECRET}], objects=[{"index":0,"key":SECRET,"label":SECRET}],
                frames=frames, field_samples=fields, events=[{"raw":SECRET}])


class ShareTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.index, self.calibration, self.video = (self.root/name for name in ("index.json", "cal.json", "video.mp4"))
        self.video.write_bytes(b"bound video fixture")

    def fixture(self, *sources):
        chunks = []
        for i, source in enumerate(sources, 1):
            p = self.root/f"window-{i}.json"
            p.write_bytes(encode(source))
            chunks.append(dict(path=p.name, recorder_window=i, bytes=p.stat().st_size,
                               sha256=hashlib.sha256(p.read_bytes()).hexdigest(),
                               source_sha256=source["source_sha256"], start_seconds=source["frames"][0]["t"],
                               end_seconds=round(source["frames"][-1]["end"] + .05, 9), summary={"skipped_intervals":2}))
        gaps, previous = [], 0
        for c in chunks:
            if c["start_seconds"] > previous:
                gaps.append(dict(start_seconds=previous, end_seconds=c["start_seconds"]))
            previous = c["end_seconds"]
        gaps.append(dict(start_seconds=previous, end_seconds=previous+2))
        self.index.write_bytes(encode(dict(schema="overwatch-decoder.entity-replay-index/1", public_state_eligible=False,
                                           chunks=chunks, gaps=gaps, source_sha256="e"*64, frequency=1000,
                                           origin_ticks="1000", end_seconds=previous+2)))
        self.calibration.write_bytes(encode(dict(schema="overwatch-decoder.replay-alignment/1", source_sha256="e"*64,
                                                 replay_index_sha256=hashlib.sha256(self.index.read_bytes()).hexdigest(),
                                                 video_sha256=hashlib.sha256(self.video.read_bytes()).hexdigest(),
                                                 offset_seconds=1.25, uncertainty_seconds=.09)))

    def export(self):
        return export_shared(self.index, self.calibration, self.video)

    def test_rekeys_windows_strips_sensitive_content_and_retains_zero(self):
        self.fixture(chunk([2, 2.1]), chunk([3, 3.1]))
        result, plan = self.export()
        self.assertNotIn(SECRET.encode(), encode(result))
        self.assertNotIn(("controller:"+"c"*64).encode(), encode(result))
        self.assertNotIn(("body:"+"b"*64).encode(), encode(result))
        self.assertNotIn(b'"address"', encode(result))
        self.assertNotIn(b'"reads"', encode(result))
        self.assertTrue(result["shared_excerpt"])
        self.assertIs(result["public_state_eligible"], False)
        self.assertEqual([f["objects"][0][0] for f in result["frames"]], [0,0,1,1])
        self.assertEqual(result["frames"][2]["rotations"][0], [1,0,0,0,1])
        fields = [result["field_samples"][f["field_refs"][0]] for f in result["frames"]]
        self.assertEqual([f["health"]["value"] for f in fields], [30,0,30,0])
        self.assertEqual(fields[1]["health"]["validation_status"], FIELD_RULES["health"][0])
        self.assertEqual(fields[0]["controller_id"], fields[1]["controller_id"])
        self.assertNotEqual(fields[0]["controller_id"], fields[2]["controller_id"])
        self.assertNotEqual(fields[0]["entity_id"], fields[2]["entity_id"])
        self.assertIsNone(fields[0]["username"]["value"])
        self.assertEqual(result["frames"][1]["skipped"], 2)
        self.assertEqual(result["gaps"], [{"start_seconds":.15,"end_seconds":1}])
        self.assertEqual(result["events"], [])
        self.assertEqual(plan["video_start_seconds"], .75)
        self.assertEqual(plan["video_duration_seconds"], 1.15)
        self.assertEqual(result["bounds"], {"min": [1, 2, 3], "max": [1, 2, 3]})

    def test_tampered_chunk(self):
        self.fixture(chunk([2, 2.1]))
        p = self.root/"window-1.json"
        p.write_bytes(p.read_bytes().replace(b'"Genji"', b'"Tracer"'))
        with self.assertRaisesRegex(ValueError, "chunk"):
            self.export()

    def test_calibration_binding(self):
        self.fixture(chunk([2, 2.1]))
        self.video.write_bytes(b"wrong video")
        with self.assertRaisesRegex(ValueError, "calibration"):
            self.export()
        self.video.write_bytes(b"bound video fixture")
        self.index.write_bytes(self.index.read_bytes()+b" ")
        with self.assertRaisesRegex(ValueError, "calibration"):
            self.export()

    def test_no_data_rejected(self):
        self.fixture(chunk([2, 2.1], empty=True))
        with self.assertRaisesRegex(ValueError, "no usable positions"):
            self.export()

    def test_only_outer_no_data_removed(self):
        self.fixture(chunk([1,1.1], empty=True), chunk([2,2.1]), chunk([2.3], empty=True),
                     chunk([3,3.1]), chunk([4], empty=True))
        result, plan = self.export()
        self.assertEqual([f["t"] for f in result["frames"]], [0,.1,.3,1,1.1])
        self.assertEqual(result["frames"][2]["unknown_count"], 1)
        self.assertEqual(result["end_seconds"], 1.15)
        self.assertEqual(plan["original_source_start_seconds"], 2)
        self.assertEqual(plan["original_source_end_seconds"], 3.15)
        self.assertTrue(all(0 <= g["start_seconds"] < g["end_seconds"] <= result["end_seconds"]
                            for g in result["gaps"]))

    def test_malformed_references_or_bounds_fail_closed(self):
        src = chunk([2,2.1])
        invalid = copy.deepcopy(src)
        invalid["frames"][0]["objects"][0][0] = 2
        self.fixture(invalid)
        with self.assertRaisesRegex(ValueError, "object index"):
            self.export()
        invalid = copy.deepcopy(src)
        invalid["frames"][1]["t"] = 2.5
        self.fixture(invalid)
        with self.assertRaisesRegex(ValueError, "clock mismatch"):
            self.export()

    def test_unknown_field_and_orientation_proof_remain_unknown(self):
        src = chunk([2,2.1])
        src["field_samples"][0]["hero"]["value"] = SECRET
        src["field_samples"][0]["health"]["validation_status"] = "unknown"
        del src["field_samples"][0]["field_evidence"]["raw_quaternion_candidate"]
        self.fixture(src)
        result, _ = self.export()
        field = result["field_samples"][0]
        self.assertEqual([field[k]["value"] for k in ("hero","health","raw_quaternion_candidate")], [None,None,None])
        self.assertEqual(result["frames"][0]["rotations"], [])


if __name__ == "__main__":
    unittest.main()
