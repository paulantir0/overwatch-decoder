import unittest

from import_inspector import import_log


def read_log(raw):
    return import_log(raw, rule_bytes=b"test rule", map_name="Synthetic Room",
                      mode_name="Skirmish", build_sha256="0" * 64)


SMOKE = (
    b"[00:00:46] OWD1 MAP Synthetic Room PLAYER (16.01, 0.00, 2.48)\r\n"
    b"[00:00:46] OWD1 RAY (16.01, 1.25, 2.48) END (-8.99, 1.25, 2.48) HIT (-8.99, 1.25, 2.48)\r\n"
    b"[00:00:46] OWD1 NORMAL (1.00, 0.00, 0.00)\r\n"
)


def grid(version, survey_id=0):
    header = f"OWD{version}" + (f" ID {survey_id}" if version == 3 else "")
    lines = [f"{header} MAP Synthetic Room PLAYER (0.00, 0.00, 0.00) ORIGIN (0.00, 1.00, 0.00)"]
    for index in range(49):
        lines.append(f"OWD{version} RAY {index} END (0.00, 1.00, 25.00) HIT (0.00, 1.00, 10.00)")
        lines.append(f"OWD{version} NORMAL {index} (0.00, 0.00, -1.00)")
    lines.append(f"{header} DONE 49")
    return "".join(f"[00:00:46] {line}\r\n" for line in lines).encode()


class InspectorTests(unittest.TestCase):
    def test_smoke_miss_and_elapsed_clock(self):
        sample, = read_log(SMOKE)
        self.assertEqual(sample["rays"][0]["status"], "miss_or_endpoint")
        self.assertEqual(sample["survey"]["start"], 46)
        self.assertEqual(sample["survey"]["end"], 46)

    def test_grid_and_repeat(self):
        sample, = read_log(grid(2))
        self.assertEqual(len(sample["rays"]), 49)
        self.assertTrue(all(ray["status"] == "surface_hit" for ray in sample["rays"]))
        self.assertEqual([survey["survey"]["index"] for survey in read_log(grid(3) + grid(3, 1))], [0, 1])

    def test_rejects_wrong_map_truncation_order_and_timestamp(self):
        for raw in [
            SMOKE.replace(b"Synthetic Room", b"Other Room"),
            SMOKE.rsplit(b"[", 1)[0],
            SMOKE.replace(b"[00:00:46] OWD1 NORMAL", b"[00:00:45] OWD1 NORMAL"),
            SMOKE.replace(b"0.00)", b"0.0)"),
            grid(2).replace(b"NORMAL 10", b"NORMAL 11"),
            grid(3, 1),
            b"".join(grid(3, index) for index in range(7)),
        ]:
            with self.subTest(raw=raw[:80]), self.assertRaises(ValueError):
                read_log(raw)
