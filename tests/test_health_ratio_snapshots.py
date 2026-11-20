"""Saved-only native arithmetic and evidence binding; no game/process access."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

import pytest

from test_build_health_contracts import SavedAcquisition, encoded, digest


SCRIPT = Path(__file__).resolve().parents[1] / "tools/entity-decoder/export_health_ratio_snapshots.py"
SPEC = importlib.util.spec_from_file_location("health_ratio_snapshots", SCRIPT)
exporter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(exporter)


class RatioAcquisition(SavedAcquisition):
    def __init__(self, directory, numerators=(175, 125), denominators=(200, 200)):
        super().__init__(directory, active=tuple(range(len(numerators))))
        data = bytearray.fromhex(self.events[0]["bytes_hex"])
        for i, (numerator, denominator) in enumerate(zip(numerators, denominators, strict=True)):
            struct.pack_into("<ff", data, 16 * i + 4, numerator, denominator)
        self.events[0]["bytes_hex"] = data.hex()
        self.persist()
        self.review = directory / "native-review.json"
        self.review.write_bytes(encoded(dict(source="synthetic native arithmetic review")))
        self.ratio_layout = dict(schema="overwatch-decoder.private.health-ratio-layout/1",
            algorithm="occupied_pool_ratio_f32", health_layout_sha256=digest(encoded(self.layout)),
            build_sha256=self.target["executable_sha256"], native_review_sha256=digest(self.review.read_bytes()),
            denominator_offset=8)

    def export(self):
        return exporter.export_snapshots(self.directory, encoded(self.layout), encoded(self.ratio_layout),
                                         native_review_path=self.review)


def test_snapshot_uses_owned_extent_time_and_never_claims_maximum(tmp_path):
    saved = RatioAcquisition(tmp_path / "acquisition")
    result = saved.export()
    row, = result["observations"]
    assert (row["numerator_sum"], row["native_denominator_sum"], row["native_ratio_candidate"]) == (300, 400, .75)
    assert (row["read_start_ticks"], row["read_end_ticks"]) == (10, 20)
    assert row["supplied_layout_slots"] == 3 and row["occupied_pool_count"] == 2
    assert row["maximum_health"] is row["hud_ratio"] is row["pool_roles"] is None
    assert row["validation_status"] == "static_derived_not_runtime_validated"
    assert row["observation_scope"] == "acquisition_extent_only" and row["atomic"] is False
    assert result["acquisition_evidence_sha256"] == saved.manifest["evidence_sha256"]
    assert result["native_review_sha256"] == digest(saved.review.read_bytes())
    assert "address" not in json.dumps(result) and "path" not in json.dumps(result)


def test_native_f32_accumulation_is_not_double_precision_sum(tmp_path):
    saved = RatioAcquisition(tmp_path / "acquisition", (2 ** 24, 1, 1), (2 ** 24, 0, 0))
    row, = saved.export()["observations"]
    assert row["numerator_sum"] == 2 ** 24
    assert row["native_ratio_candidate"] == 1


def test_native_clock_is_preserved_only_with_matching_source(tmp_path):
    saved = RatioAcquisition(tmp_path / "acquisition")
    saved.events.insert(0, dict(kind="start", schema="overwatch-decoder.acquisition-evidence/1", target=saved.target,
        recipe_sha256=saved.manifest["recipe_sha256"], monotonic_frequency=10000000,
        monotonic_origin_ticks=0, utc_origin="2026-01-01T00:00:00Z"))
    saved.persist()
    result = saved.export()
    assert result["clock"] == dict(monotonic_frequency=10000000, monotonic_origin_ticks=0,
                                    utc_origin="2026-01-01T00:00:00Z")
    assert result["native_float_control_state_observed"] is False
    saved.events[0]["recipe_sha256"] = "f" * 64
    saved.persist()
    with pytest.raises(exporter.health.InvalidHealthAcquisition, match="clock_source_mismatch"):
        saved.export()


@pytest.mark.parametrize("numerator,denominator,expected", [(0, 200, 0), (1, 0, 0), (400, 200, 1), (1, 1e-45, 1)])
def test_native_zero_denominator_and_division_clamp(tmp_path, numerator, denominator, expected):
    saved = RatioAcquisition(tmp_path / "acquisition", (numerator,), (denominator,))
    assert saved.export()["observations"][0]["native_ratio_candidate"] == expected


def test_first_slot_signed_zero_is_loaded_then_later_slots_are_added(tmp_path):
    saved = RatioAcquisition(tmp_path / "acquisition", (-0.0,), (1,))
    row, = saved.export()["observations"]
    assert struct.pack("<f", row["numerator_sum"]) == b"\x00\x00\x00\x80"
    assert row["native_ratio_candidate"] == 0


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -1])
def test_unsupported_values_do_not_turn_into_zero_health(tmp_path, value):
    saved = RatioAcquisition(tmp_path / "acquisition", (1,), (value,))
    with pytest.raises(exporter.health.InvalidHealthAcquisition, match="unsupported_pool_operand"):
        saved.export()


def test_empty_slot_garbage_is_not_an_operand(tmp_path):
    saved = RatioAcquisition(tmp_path / "acquisition", (100,), (200,))
    data = bytearray.fromhex(saved.events[0]["bytes_hex"])
    struct.pack_into("<ff", data, 16 + 4, float("nan"), -10)
    saved.events[0]["bytes_hex"] = data.hex()
    saved.persist()
    assert saved.export()["observations"][0]["native_ratio_candidate"] == .5


def test_repeated_equal_reads_keep_separate_intervals(tmp_path):
    saved = RatioAcquisition(tmp_path / "acquisition")
    second = copy.deepcopy(saved.events[0])
    second.update(id=2, read_start_ticks=100, read_end_ticks=110)
    saved.events.append(second)
    saved.persist()
    rows = saved.export()["observations"]
    assert [(r["read_start_ticks"], r["read_end_ticks"]) for r in rows] == [(10, 20), (100, 110)]


def test_changed_denominator_is_not_merged_between_repeated_extents(tmp_path):
    saved = RatioAcquisition(tmp_path / "acquisition")
    second = copy.deepcopy(saved.events[0])
    data = bytearray.fromhex(second["bytes_hex"])
    struct.pack_into("<f", data, 8, 500)
    second["bytes_hex"] = data.hex()
    saved.events.append(second)
    saved.persist()
    with pytest.raises(exporter.health.InvalidHealthAcquisition, match="divergent_extent_reads"):
        saved.export()


@pytest.mark.parametrize("field,value,reason", [
    ("health_layout_sha256", "f" * 64, "ratio_layout_pin_mismatch"),
    ("build_sha256", "f" * 64, "ratio_layout_pin_mismatch"),
    ("native_review_sha256", "f" * 64, "native_review_pin_mismatch"),
    ("denominator_offset", 0, "denominator_operand_overlap"),
    ("denominator_offset", 4, "denominator_operand_overlap"),
    ("denominator_offset", 48, "denominator_outside_extent"),
])
def test_ratio_contract_cannot_rebind_or_read_outside_extent(tmp_path, field, value, reason):
    saved = RatioAcquisition(tmp_path / "acquisition")
    saved.ratio_layout[field] = value
    with pytest.raises(exporter.health.InvalidHealthAcquisition, match=reason):
        saved.export()


def test_cli_writes_real_snapshot_artifact_and_refuses_overwrite(tmp_path):
    saved = RatioAcquisition(tmp_path / "acquisition")
    layout, ratio, output = [tmp_path / name for name in ("layout.json", "ratio.json", "out.json")]
    layout.write_bytes(encoded(saved.layout))
    ratio.write_bytes(encoded(saved.ratio_layout))
    cmd = [sys.executable, str(SCRIPT), "--acquisition", str(saved.directory), "--health-layout", str(layout),
           "--ratio-layout", str(ratio), "--native-review", str(saved.review), "--out", str(output)]
    run = subprocess.run(cmd, cwd=tmp_path, capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    original = output.read_bytes()
    assert json.loads(original)["observations"][0]["native_ratio_candidate"] == .75
    run = subprocess.run(cmd, cwd=tmp_path, capture_output=True, text=True)
    assert run.returncode != 0 and output.read_bytes() == original
