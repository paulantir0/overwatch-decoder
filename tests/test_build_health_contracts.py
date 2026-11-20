import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

import pytest

from overwatch_decoder.health_projection import PoolHealthContract


SCRIPT = Path(__file__).resolve().parents[1] / "tools/entity-decoder/build_health_contracts.py"
SPEC = importlib.util.spec_from_file_location("build_health_contracts", SCRIPT)
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)
PREFIX = "controller_0000_body_0000_"


def encoded(value):
    return (json.dumps(value) + "\n").encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


class SavedAcquisition:
    """Synthetic saved producer evidence, with no process or game access."""

    def __init__(self, directory, active=(0, 1)):
        self.directory = directory
        directory.mkdir()
        self.base = 0x5000
        self.target = dict(pid=7, creation_file_time=8, image_name="fixture.exe",
                           executable_sha256="a" * 64, architecture="x64")
        self.recipe = dict(schema="fixture.recipe/1", target=self.target.copy())
        self.profile = dict(schema="overwatch-decoder.field-profile/1", target=self.target.copy(),
                            guards=[dict(address=0x2000, bytes_hex=struct.pack("<II", 17, 29).hex())],
                            fields=[dict(name=PREFIX + "handle_candidate_i32", type="i32", address=0x2000),
                                    dict(name=PREFIX + "manager_key_candidate_i32", type="i32", address=0x2004)])
        data = bytearray(48)
        for i in range(3):
            membership = i + 1 if i in active else 0
            struct.pack_into("<I", data, 16 * i, membership)
            struct.pack_into("<f", data, 16 * i + 4, 175.0 - 50 * i)
            self.profile["guards"].append(dict(address=self.base + 16 * i,
                                                bytes_hex=struct.pack("<I", membership).hex()))
            if membership:
                self.profile["fields"].append(dict(name=PREFIX + f"pool_{i:04d}_direct_candidate",
                                                   type="f32", address=self.base + 16 * i + 4))
        self.events = [dict(kind="read", purpose="recipe", stage="fixture_pool_extent", id=1,
                            attempted=True, address=self.base, requested_bytes=48, returned_bytes=48,
                            bytes_hex=data.hex(), error=None, read_start_ticks=10, read_end_ticks=20)]
        self.layout = dict(schema="overwatch-decoder.health-layout/1", executable_sha256="a" * 64,
                           recipe_sha256=digest(encoded(self.recipe)), extent_size=48,
                           read_stage="fixture_pool_extent", slot_count=3, slot_stride=16,
                           membership_offset=0, scalar_offset=4, actor_prefixes=[PREFIX],
                           scalar_field_suffix="_direct_candidate")
        self.persist()

    def persist(self):
        contents = {"recipe.json": encoded(self.recipe), "profile.json": encoded(self.profile),
                    "evidence.jsonl": b"".join(encoded(e) for e in self.events)}
        self.manifest = dict(schema="overwatch-decoder.acquisition-result/1", complete=True, error=None,
                             target=self.target.copy(), fields=len(self.profile["fields"]),
                             guard_declarations=len(self.profile["guards"])
                             + sum(len(f.get("guards", [])) for f in self.profile["fields"]),
                             **{name.removesuffix(".json").removesuffix(".jsonl") + "_sha256": digest(data)
                                for name, data in contents.items()})
        for name, data in contents.items():
            (self.directory / name).write_bytes(data)
        self.write_manifest()

    def write_manifest(self):
        (self.directory / "manifest.json").write_bytes(encoded(self.manifest))

    def build(self, **kwargs):
        return builder.build_contracts(self.directory, encoded(self.layout), **kwargs)


@pytest.fixture
def saved(tmp_path):
    return SavedAcquisition(tmp_path / "acquisition")


def test_fresh_source_includes_empty_memberships_without_semantics(saved):
    bundle = saved.build()
    assert bundle["layout_sha256"] == digest(encoded(saved.layout))
    assert bundle["public_state_eligible"] is False
    descriptor, = bundle["contracts"]
    assert [s["membership_u32"] for s in descriptor["slots"]] == [1, 2, 0]
    assert descriptor["slots"][2]["field_name"] is None
    assert descriptor["slots"][2]["scalar_address"] is None
    assert set(descriptor) == {"actor_prefix", "slots", "acquisition_evidence_sha256"}
    contract = PoolHealthContract.from_profile((saved.directory / "profile.json").read_bytes(), **descriptor)
    assert contract.acquisition_evidence_sha256 == saved.manifest["evidence_sha256"]
    assert len(contract.slots) == 3


def test_same_profile_new_evidence_requires_own_reconstruction(saved, tmp_path):
    old = saved.build()
    other = SavedAcquisition(tmp_path / "fresh")
    other.events[0]["id"] = 99
    other.persist()
    new = other.build()
    assert new["profile_sha256"] == old["profile_sha256"]
    assert new["acquisition_evidence_sha256"] != old["acquisition_evidence_sha256"]
    assert new["contracts"][0]["slots"] == old["contracts"][0]["slots"]
    assert new["contracts"][0]["acquisition_evidence_sha256"] == other.manifest["evidence_sha256"]


def test_two_actors_resolve_independent_complete_extents(saved):
    second = "controller_0001_body_0000_"
    fields = copy.deepcopy(saved.profile["fields"])
    for field in fields:
        field["name"] = field["name"].replace(PREFIX, second)
        field["address"] += 0x1000
    saved.profile["fields"].extend(fields)
    guards = copy.deepcopy(saved.profile["guards"])
    for guard in guards:
        guard["address"] += 0x1000
    saved.profile["guards"].extend(guards)
    event = copy.deepcopy(saved.events[0])
    event["address"] += 0x1000
    saved.events.append(event)
    saved.layout["actor_prefixes"].append(second)
    saved.persist()
    descriptors = saved.build()["contracts"]
    assert [d["actor_prefix"] for d in descriptors] == [PREFIX, second]
    assert all(len(d["slots"]) == 3 and d["slots"][-1]["membership_u32"] == 0 for d in descriptors)
    assert (descriptors[1]["slots"][0]["membership_address"]
            - descriptors[0]["slots"][0]["membership_address"]) == 0x1000


def test_one_extent_cannot_be_reused_for_two_declared_actors(saved):
    second = "controller_0001_body_0000_"
    for original in list(saved.profile["fields"]):
        field = copy.deepcopy(original)
        field["name"] = field["name"].replace(PREFIX, second)
        saved.profile["fields"].append(field)
    saved.layout["actor_prefixes"].append(second)
    saved.persist()
    with pytest.raises(builder.InvalidHealthAcquisition, match="extent_shared_by_actors"):
        saved.build()


def test_identical_repeated_extent_is_not_ambiguous(saved):
    saved.events.append(copy.deepcopy(saved.events[0]))
    saved.persist()
    assert len(saved.build()["contracts"]) == 1


def test_divergent_whole_extent_rejected_even_when_memberships_unchanged(saved):
    changed = copy.deepcopy(saved.events[0])
    raw = bytearray.fromhex(changed["bytes_hex"])
    struct.pack_into("<f", raw, 4, 22.0)
    changed["bytes_hex"] = raw.hex()
    saved.events.append(changed)
    saved.persist()
    with pytest.raises(builder.InvalidHealthAcquisition, match="divergent_extent_reads"):
        saved.build()


def test_multiple_complete_matching_extents_are_ambiguous(tmp_path):
    saved = SavedAcquisition(tmp_path / "ambiguous", active=(1,))
    other = copy.deepcopy(saved.events[0])
    other["address"] += 16
    raw = bytearray(48)
    struct.pack_into("<I", raw, 0, 2)
    struct.pack_into("<f", raw, 4, 125.0)
    other["bytes_hex"] = raw.hex()
    saved.events.append(other)
    saved.profile["guards"].append(dict(address=saved.base + 48, bytes_hex="00000000"))
    saved.persist()
    with pytest.raises(builder.InvalidHealthAcquisition, match="ambiguous_or_missing_actor_extent"):
        saved.build()


@pytest.mark.parametrize("change", ["missing_occupied", "wrong_scalar_address", "wrong_scalar_type"])
def test_occupied_field_set_must_exactly_match_the_extent(saved, change):
    if change == "missing_occupied":
        saved.profile["fields"].pop()
    elif change == "wrong_scalar_address":
        saved.profile["fields"][-1]["address"] += 4
    else:
        saved.profile["fields"][-1]["type"] = "i32"
    saved.persist()
    with pytest.raises(builder.InvalidHealthAcquisition):
        saved.build()


def test_missing_entire_declared_actor_is_rejected(saved):
    saved.layout["actor_prefixes"].append("controller_0001_body_0000_")
    with pytest.raises(builder.InvalidHealthAcquisition, match="missing_actor_pool_fields"):
        saved.build()


def test_scalar_fields_cannot_silently_belong_to_an_undeclared_actor(saved):
    saved.profile["fields"].append(dict(name="controller_0001_body_0000_pool_0000_direct_candidate",
                                         type="f32", address=0x9000))
    saved.persist()
    with pytest.raises(builder.InvalidHealthAcquisition, match="unassigned_pool_field"):
        saved.build()


@pytest.mark.parametrize("change", ["missing_empty_guard", "guard_value_mismatch"])
def test_all_empty_and_occupied_memberships_need_effective_guards(saved, change):
    if change == "missing_empty_guard":
        saved.profile["guards"].pop()
    else:
        saved.profile["guards"][-1]["bytes_hex"] = "01000000"
    saved.persist()
    with pytest.raises(builder.InvalidHealthAcquisition, match="invalid_health_contract"):
        saved.build()


@pytest.mark.parametrize("change", ["truncated", "failed", "missing_stage", "invalid_bracket"])
def test_extent_reads_must_be_exact_complete_own_stage_records(saved, change):
    if change == "truncated":
        saved.events[0]["bytes_hex"] = saved.events[0]["bytes_hex"][:-8]
    elif change == "failed":
        saved.events[0]["error"] = "denied"
    elif change == "missing_stage":
        saved.events[0]["stage"] = "different_stage"
    else:
        saved.events[0]["read_end_ticks"] = 9
    saved.persist()
    with pytest.raises(builder.InvalidHealthAcquisition):
        saved.build()


@pytest.mark.parametrize("filename", ["profile.json", "evidence.jsonl", "recipe.json"])
def test_tampered_source_file_rejected_before_interpretation(saved, filename):
    with (saved.directory / filename).open("ab") as stream:
        stream.write(b" ")
    with pytest.raises(builder.InvalidHealthAcquisition, match="source_hash_mismatch"):
        saved.build()


def test_build_pin_cannot_drift(saved):
    saved.layout["executable_sha256"] = "b" * 64
    with pytest.raises(builder.InvalidHealthAcquisition, match="build_pin_mismatch"):
        saved.build()


def test_recipe_target_must_agree_even_when_recipe_hash_is_updated(saved):
    saved.recipe["target"]["image_name"] = "different-fixture.exe"
    saved.layout["recipe_sha256"] = digest(encoded(saved.recipe))
    saved.persist()
    with pytest.raises(builder.InvalidHealthAcquisition, match="recipe_target_mismatch"):
        saved.build()


def test_recipe_pin_cannot_drift(saved):
    saved.recipe["different_recipe"] = True
    saved.persist()
    with pytest.raises(builder.InvalidHealthAcquisition, match="recipe_pin_mismatch"):
        saved.build()


@pytest.mark.parametrize("change", ["incomplete", "error", "target", "field_count", "guard_count"])
def test_manifest_completion_identity_and_counts_are_checked(saved, change):
    if change == "incomplete":
        saved.manifest["complete"] = False
    elif change == "error":
        saved.manifest["error"] = "acquisition_predicate_failed"
    elif change == "target":
        saved.manifest["target"]["creation_file_time"] += 1
    elif change == "field_count":
        saved.manifest["fields"] += 1
    else:
        saved.manifest["guard_declarations"] += 1
    saved.write_manifest()
    with pytest.raises(builder.InvalidHealthAcquisition):
        saved.build()


@pytest.mark.parametrize("key,value", [("slot_count", 257), ("slot_count", True),
                                       ("extent_size", 32769), ("slot_stride", 3),
                                       ("scalar_offset", 47), ("scalar_offset", 0)])
def test_layout_bounds_and_membership_scalar_separation(saved, key, value):
    saved.layout[key] = value
    with pytest.raises(builder.InvalidHealthAcquisition):
        saved.build()


def test_read_byte_bound_is_preserved_even_when_field_and_guard_counts_fit(saved):
    for i in range(252):
        saved.profile["guards"].append(dict(address=0x100000 + 64 * i, bytes_hex="00" * 64))
    for i in range(124):
        saved.profile["fields"].append(dict(name=f"extra_{i}", type="f32x4", address=0x200000 + 16 * i))
    saved.persist()
    assert len(saved.profile["fields"]) == 128
    assert len(saved.profile["guards"]) == 256
    with pytest.raises(builder.InvalidHealthAcquisition, match="profile_read_byte_bound"):
        saved.build()


def test_explicit_recipe_path_does_not_search_parent_directories(saved, tmp_path):
    recipe_path = tmp_path / "explicit-recipe.json"
    (saved.directory / "recipe.json").rename(recipe_path)
    with pytest.raises(builder.InvalidHealthAcquisition, match="unreadable_input"):
        saved.build()
    assert len(saved.build(recipe_path=recipe_path)["contracts"]) == 1


def test_cli_outside_checkout_and_refuses_output_overwrite(saved, tmp_path):
    layout = tmp_path / "layout.json"
    layout.write_bytes(encoded(saved.layout))
    output = tmp_path / "bundle.json"
    command = [sys.executable, str(SCRIPT), "--acquisition", str(saved.directory),
               "--layout", str(layout), "--out", str(output)]
    first = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True)
    assert first.returncode == 0, first.stderr
    original = output.read_bytes()
    second = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True)
    assert second.returncode != 0
    assert output.read_bytes() == original
