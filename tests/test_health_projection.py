import copy
import hashlib
import json
import math
import struct

import pytest

from overwatch_decoder.health_projection import InvalidHealthBinding, PoolHealthContract

PREFIX = "controller_0000_body_0000_"


def fixture(values=(175.0, 75.0), empty_slots=1):
    target = dict(pid=7, image_name="fixture.exe", creation_file_time=8,
                  executable_sha256="a" * 64, architecture="x64")
    fields = [dict(name=PREFIX + "handle_candidate_i32", type="i32", address=0x2000),
              dict(name=PREFIX + "manager_key_candidate_i32", type="i32", address=0x2004)]
    guards = [dict(address=0x2000, bytes_hex=struct.pack("<II", 17, 29).hex())]
    slots = []
    for i in range(len(values) + empty_slots):
        active = i < len(values)
        membership = i + 1 if active else 0
        address = 0x4000 + 16 * i
        name = PREFIX + f"pool_{i:04d}_direct_candidate" if active else None
        scalar = 0x8000 + 4 * i if active else None
        slots.append(dict(index=i, membership_address=address, membership_u32=membership,
                          field_name=name, scalar_address=scalar))
        guards.append(dict(address=address, bytes_hex=struct.pack("<I", membership).hex()))
        if active:
            fields.append(dict(name=name, type="f32", address=scalar))
    profile = dict(schema="overwatch-decoder.field-profile/1", target=target, guards=guards, fields=fields)
    raw = (json.dumps(profile) + "\n").encode()
    contract = PoolHealthContract.from_profile(raw, actor_prefix=PREFIX, slots=slots,
                                              acquisition_evidence_sha256="b" * 64)
    frame = dict(schema="overwatch-decoder.field-stream/1", kind="frame", source="process_memory",
                 target=target, profile_sha256=hashlib.sha256(raw).hexdigest(), start_ticks=0, end_ticks=100,
                 sequence=1, skipped_intervals_before=0, guards_before=[dict(ok=True, error=None, start_ticks=1, end_ticks=9)] * len(guards),
                 guards_after=[dict(ok=True, error=None, start_ticks=80, end_ticks=90)] * len(guards), fields={})
    for field, value in zip(fields, (17, 29, *values)):
        frame["fields"][field["name"]] = dict(type=field["type"], status="observed", value=value,
                                               read_start_ticks=20, read_end_ticks=30,
                                               guard_ids=list(range(len(guards))))
    relations = dict(schema="overwatch-decoder.guarded-object-relations/1", profile_sha256=contract.profile_sha256, target=target,
                     timing=dict(sequence=1, start_ticks=0, end_ticks=100),
                     relations=[dict(controller_prefix="controller_0000", relation_status="observed",
                                     body_object_key="body:" + "c" * 64)])
    return contract, frame, relations, profile, slots


def test_sums_every_occupied_pool_and_preserves_private_provenance():
    c, f, r, *_ = fixture()
    value = c.project(f, relation_projection=r)
    assert value["raw_sum"] == 250 and value["occupied_pool_count"] == 2
    assert value["supplied_layout_slots"] == 3 and len(value["contributions"]) == 2
    assert value["body_object_key"] == r["relations"][0]["body_object_key"]
    assert value["visibility"] == "unknown" and value["public_state_eligible"] is False
    assert value["maximum_health"] is None and value["pool_roles"] is None
    assert not value["atomic"] and not value["continuity_across_gaps"]
    assert "address" not in json.dumps(value)


def test_three_pool_form_and_zero_health_are_numeric_candidates_only():
    c, f, r, *_ = fixture((425, 100, 226.377258))
    assert c.project(f, relation_projection=r)["display_ceiling_candidate"] == 752
    for field in f["fields"].values():
        if field["type"] == "f32":
            field["value"] = 0
    assert c.project(f, relation_projection=r)["raw_sum"] == 0


@pytest.mark.parametrize("action", [
    lambda f: f["fields"].pop(PREFIX + "pool_0000_direct_candidate"),
    lambda f: f["fields"][PREFIX + "pool_0001_direct_candidate"].update(status="unknown", value=None),
    lambda f: f["fields"][PREFIX + "pool_0001_direct_candidate"].update(value=float("nan")),
    lambda f: f["fields"][PREFIX + "pool_0001_direct_candidate"].update(value=-1),
    lambda f: f["fields"][PREFIX + "pool_0001_direct_candidate"].update(read_end_ticks=101),
    lambda f: f["fields"][PREFIX + "pool_0001_direct_candidate"].update(guard_ids=[]),
    lambda f: f["fields"][PREFIX + "handle_candidate_i32"].update(value=18),
    lambda f: f.update(profile_sha256="different"),
    lambda f: f.update(skipped_intervals_before=1),
    lambda f: f["fields"].update({PREFIX + "pool_0002_direct_candidate": {}}),
])
def test_missing_malformed_gap_or_identity_never_becomes_partial_total(action):
    c, f, r, *_ = fixture()
    action(f)
    assert c.project(f, relation_projection=r) is None


def test_changed_previously_empty_membership_invalidates_entire_sum():
    c, f, r, *_ = fixture()
    f["guards_after"] = copy.deepcopy(f["guards_after"])
    f["guards_after"][-1]["ok"] = False
    assert c.project(f, relation_projection=r) is None
    c, f, r, *_ = fixture()
    assert c.project(f, relation_projection=r, gap=True) is None


@pytest.mark.parametrize("change", [
    lambda r: r["relations"][0].update(relation_status="unknown"),
    lambda r: r["relations"][0].update(body_object_key=None),
    lambda r: r["relations"].append(copy.deepcopy(r["relations"][0])),
    lambda r: r.update(profile_sha256="different"),
    lambda r: r.update(target={}),
    lambda r: r["timing"].update(sequence=0),
])
def test_relation_unknown_ambiguity_or_cross_profile_is_rejected(change):
    c, f, r, *_ = fixture()
    change(r)
    assert c.project(f, relation_projection=r) is None


def test_constructor_rejects_missing_empty_slot_guard_and_wrong_pool_set():
    _, _, _, p, slots = fixture()
    p["guards"].pop()
    with pytest.raises(InvalidHealthBinding, match="word_not_fully_guarded"):
        PoolHealthContract.from_profile(json.dumps(p).encode(), actor_prefix=PREFIX, slots=slots,
                                        acquisition_evidence_sha256="b" * 64)
    _, _, _, p, slots = fixture()
    slots[1]["field_name"] = PREFIX + "pool_0009_direct_candidate"
    with pytest.raises(InvalidHealthBinding):
        PoolHealthContract.from_profile(json.dumps(p).encode(), actor_prefix=PREFIX, slots=slots,
                                        acquisition_evidence_sha256="b" * 64)


def test_constructor_rejects_duplicate_slot_missing_identity_and_conflicts():
    for mutation in (lambda p, s: s[1].update(index=0),
                     lambda p, s: p["fields"].pop(0),
                     lambda p, s: p["guards"].append(dict(address=0x4000, bytes_hex="ff000000"))):
        _, _, _, p, slots = fixture()
        mutation(p, slots)
        with pytest.raises(InvalidHealthBinding):
            PoolHealthContract.from_profile(json.dumps(p).encode(), actor_prefix=PREFIX, slots=slots,
                                            acquisition_evidence_sha256="b" * 64)
