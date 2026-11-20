import hashlib
import unittest

from surface_samples import build_sidecar


class SidecarTests(unittest.TestCase):
    def make(self, **changes):
        options = dict(
            origin=[0, 0, 0],
            rays=[dict(index=0, end=[0, 0, 25], hit=[0, 0, 10], normal=[0, 0, -1])],
            expected_count=1,
            map_name="Synthetic Room",
            mode_name="Synthetic Survey",
            build_sha256="a" * 64,
            source_kind="inspector_log_file",
            source_bytes=b"synthetic inspector input",
            rule_bytes=b"synthetic rule",
            position_tolerance=0.02,
        )
        options.update(changes)
        return build_sidecar(**options)

    def ray(self, hit):
        return dict(index=0, end=[0, 0, 25], hit=hit, normal=[0, 0, -1])

    def test_hit_keeps_original_vectors_and_source_pins(self):
        row = self.make()
        self.assertEqual(row["rays"], [{
            "index": 0, "origin": [0, 0, 0], "end": [0, 0, 25],
            "returned_hit": [0, 0, 10], "returned_normal": [0, 0, -1],
            "status": "surface_hit",
        }])
        self.assertEqual(row["source"]["sha256"], hashlib.sha256(b"synthetic inspector input").hexdigest())
        self.assertIsNone(row["replay_registration"])
        self.assertEqual(row["visibility"], "unknown")

    def test_reverse_ray_normal_does_not_disambiguate_miss(self):
        for hit, status in [([0, 0, 25], "miss_or_endpoint"),
                            ([0, 0, 24.99], "miss_or_endpoint"),
                            ([0, 0, 0], "origin_ambiguous")]:
            with self.subTest(hit=hit):
                self.assertEqual(self.make(rays=[self.ray(hit)])["rays"][0]["status"], status)

    def test_rejects_off_ray_or_nonfinite_positions(self):
        for hit in [[0, 0, 26], [0, 0, -1], [1, 0, 10], [0, 0, float("nan")]]:
            with self.subTest(hit=hit), self.assertRaises(ValueError):
                self.make(rays=[self.ray(hit)])

    def test_rejects_missing_duplicate_or_over_budget_rows(self):
        ray = self.ray([0, 0, 5])
        for rows, count in [([], 1), ([ray, ray], 2), ([ray] * 501, 501)]:
            with self.subTest(count=count), self.assertRaises(ValueError):
                self.make(rays=rows, expected_count=count)

    def test_rejects_invalid_source_and_tolerance(self):
        for changes in [{"source_bytes": b""}, {"build_sha256": "wrong"},
                        {"source_kind": "invented"}, {"position_tolerance": 0},
                        {"position_tolerance": float("inf")}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.make(**changes)


if __name__ == "__main__":
    unittest.main()
