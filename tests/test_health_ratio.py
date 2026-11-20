import copy
import hashlib
import json
import struct

import pytest

from overwatch_decoder.health_ratio import PoolRatioContract, InvalidRatioBinding, calculate_bank_candidates
from test_health_projection import fixture as health_fixture, PREFIX


def raw(value):
    return (json.dumps(value) + "\n").encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def fixture(values=(175, 75), denominators=(200, 100)):
    old, frame, relation, profile, slots = health_fixture(values)
    pairs = []
    for i, (value, denominator) in enumerate(zip(values, denominators, strict=True)):
        current = slots[i]["field_name"]
        address = 0x8000 + 0x20 * i
        slots[i]["scalar_address"] = address
        next(field for field in profile["fields"] if field["name"] == current)["address"] = address
        name = PREFIX + f"pool_{i:04d}_paired"
        profile["fields"].append(dict(name=name, type="f32x3", address=address-8))
        pairs.append(dict(pool_index=i, field_name=name, numerator_component=2,
                          denominator_component=1, denominator_address=address-4))
        frame["fields"][name] = dict(type="f32x3", status="observed", value=[denominator+10, denominator, value],
            read_start_ticks=40+i, read_end_ticks=41+i, guard_ids=list(range(len(old.guards))))
    review = raw(dict(build_sha256="a"*64, finding="synthetic supplied review"))
    descriptor = dict(schema="overwatch-decoder.private.actor-health-ratio-contract/1", algorithm="occupied_pool_ratio_f32",
        profile_sha256=sha(raw(profile)), build_sha256="a"*64, native_review_sha256=sha(review),
        source=dict(manifest_sha256="c"*64, recipe_sha256="d"*64, evidence_sha256="b"*64),
        health_contract=dict(actor_prefix=PREFIX, slots=slots, acquisition_evidence_sha256="b"*64),
        paired_slots=pairs)
    frame["profile_sha256"] = relation["profile_sha256"] = descriptor["profile_sha256"]
    contract = PoolRatioContract.from_profile(raw(profile), raw(descriptor), review)
    return contract, frame, relation, profile, descriptor, review


def test_current_paired_read_ratio_has_body_time_and_source_proof():
    contract, frame, relation, *_ = fixture()
    result = contract.project(frame, relation_projection=relation)
    assert result["numerator_sum"] == 250 and result["native_denominator_sum"] == 300
    assert result["native_ratio_candidate"] == struct.unpack("<f", struct.pack("<f", 250/300))[0]
    assert result["body_object_key"] == relation["relations"][0]["body_object_key"]
    assert result["read_start_ticks"] == 40 and result["read_end_ticks"] == 42
    assert result["contract_sha256"] == contract.contract_sha256
    assert result["native_review_sha256"] == contract.native_review_sha256
    assert result["maximum_health"] is result["hud_ratio"] is result["pool_roles"] is None
    assert not result["atomic"] and not result["native_execution_observed"]
    assert result["supplied_layout_slots"] == 3 and result["complete_supplied_membership_guarding"]
    assert "address" not in json.dumps(result)


def test_numerator_comes_from_same_vector_not_later_direct_read():
    contract, frame, relation, *_ = fixture((100,), (200,))
    frame["fields"][contract.paired_slots[0]["field_name"]]["value"][2] = 50
    result = contract.project(frame, relation_projection=relation)
    assert result["numerator_sum"] == 50 and result["native_ratio_candidate"] == .25
    assert result["read_start_ticks"] == 40


def test_shortest_json_decimal_is_normalized_before_first_slot_load():
    contract, frame, relation, *_ = fixture((144.11047,), (250,))
    result = contract.project(frame, relation_projection=relation)
    assert result["numerator_sum"] == 144.1104736328125
    assert result["native_ratio_candidate"] == struct.unpack("<f", struct.pack("<f", 144.1104736328125/250))[0]


def test_f32_order_and_zero_denominator():
    contract, frame, relation, *_ = fixture((2**24, 1, 1), (2**24, 0, 0))
    assert contract.project(frame, relation_projection=relation)["numerator_sum"] == 2**24
    contract, frame, relation, *_ = fixture((0,), (0,))
    assert contract.project(frame, relation_projection=relation)["native_ratio_candidate"] == 0


@pytest.mark.parametrize("change", [
    lambda field:field.update(status="unknown", value=None),
    lambda field:field.update(value=[1, float("nan"), 5]),
    lambda field:field.update(value=[1, -1, 5]),
    lambda field:field.update(value=[1, True, 5]),
    lambda field:field.update(value=[1, 2]),
    lambda field:field.update(guard_ids=[]),
    lambda field:field.update(read_end_ticks=90),
])
def test_bad_paired_sample_never_reuses_a_previous_ratio(change):
    contract, frame, relation, *_ = fixture()
    assert contract.project(frame, relation_projection=relation) is not None
    change(frame["fields"][contract.paired_slots[0]["field_name"]])
    assert contract.project(frame, relation_projection=relation) is None


def test_gap_failed_membership_and_changed_body_return_null():
    contract, frame, relation, *_ = fixture()
    assert contract.project(frame, relation_projection=relation, gap=True) is None
    frame["guards_after"] = copy.deepcopy(frame["guards_after"])
    frame["guards_after"][-1]["ok"] = False
    assert contract.project(frame, relation_projection=relation) is None
    contract, frame, relation, *_ = fixture()
    relation["relations"][0]["relation_status"] = "unknown"
    assert contract.project(frame, relation_projection=relation) is None


@pytest.mark.parametrize("change", [
    lambda d:d["paired_slots"].pop(),
    lambda d:d["paired_slots"].reverse(),
    lambda d:d["paired_slots"][0].update(numerator_component=1),
    lambda d:d["paired_slots"][0].update(denominator_address=12),
    lambda d:d.update(profile_sha256="f"*64),
    lambda d:d.update(native_review_sha256="f"*64),
    lambda d:d["source"].update(evidence_sha256="f"*64),
])
def test_binding_must_cover_exact_owned_pools_and_source(change):
    _, _, _, profile, descriptor, review = fixture()
    change(descriptor)
    with pytest.raises(InvalidRatioBinding):
        PoolRatioContract.from_profile(raw(profile), raw(descriptor), review)


def test_vector_cannot_drop_direct_scalar_ownership_guards():
    _, _, _, profile, descriptor, review = fixture()
    guards = profile.pop("guards")
    for field in profile["fields"]:
        field["guards"] = copy.deepcopy(guards)
    profile["fields"][-1]["guards"].pop()
    descriptor["profile_sha256"] = sha(raw(profile))
    with pytest.raises(InvalidRatioBinding, match="ratio_pair_missing_guards"):
        PoolRatioContract.from_profile(raw(profile), raw(descriptor), review)


def test_source_is_bound_to_acquisition_not_just_reused_profile():
    contract, *_ = fixture()
    source = dict(profile_sha256=contract.storage.profile_sha256, acquisition=contract.source.copy())
    contract.verify_source(source)
    source["acquisition"]["manifest_sha256"] = "e"*64
    with pytest.raises(InvalidRatioBinding, match="ratio_source_mismatch"):
        contract.verify_source(source)


def bank_fixture():
    _, frame, relation, profile, descriptor, review = fixture()
    groups = [dict(bank_id=i, pool_indices=[i]) for i in range(3)]
    review = raw(dict(json.loads(review), bank_groups=groups))
    descriptor.update(bank_groups=groups, native_review_sha256=sha(review))
    contract = PoolRatioContract.from_profile(raw(profile), raw(descriptor), review)
    return contract, frame, relation, profile, descriptor, review


def test_banks_keep_paired_values_and_empty_membership_without_invented_reads():
    contract, frame, relation, *_ = bank_fixture()
    result = contract.project(frame, relation_projection=relation)
    banks = result['bank_candidates']
    assert [b['numerator_sum'] for b in banks] == [175, 75, 0]
    assert [b['native_denominator_sum'] for b in banks] == [200, 100, 0]
    assert [b['native_ratio_candidate'] for b in banks] == [.875, .75, 0]
    assert [b['operand_pool_indices'] for b in banks] == [[0], [1], []]
    assert banks[2]['operand_read_span_ticks'] is None
    assert all(b['pool_role'] is None for b in banks)
    assert result['numerator_sum'] == 250
    # A changed membership invalidates zero-valued empty banks as well.
    frame['guards_after'][-1]['ok'] = False
    assert contract.project(frame, relation_projection=relation) is None


def test_bank_arithmetic_preserves_its_own_reduction_order():
    parts = [dict(pool_index=i, numerator=v, denominator=1, read_start_ticks=i,
                  read_end_ticks=i+1) for i, v in enumerate((2**24, 1, 1))]
    groups = [dict(bank_id=8, pool_indices=[0]), dict(bank_id=2, pool_indices=[1, 2])]
    banks = calculate_bank_candidates(parts, groups)
    assert [b['numerator_sum'] for b in banks] == [2**24, 2]
    assert [b['native_ratio_candidate'] for b in banks] == [1, 1]
    contract, frame, relation, *_ = fixture((2**24, 1, 1), (1, 1, 1))
    assert contract.project(frame, relation_projection=relation)['numerator_sum'] == 2**24


@pytest.mark.parametrize('groups', [
    [], [dict(bank_id=0, pool_indices=[0, 1])],
    [dict(bank_id=0, pool_indices=[0, 2, 1])],
    [dict(bank_id=0, pool_indices=[0, 1]), dict(bank_id=1, pool_indices=[1, 2])],
    [dict(bank_id=0, pool_indices=[0]), dict(bank_id=0, pool_indices=[1, 2])],
    [dict(bank_id=True, pool_indices=[0, 1, 2])],
    [dict(bank_id=0, pool_indices=[False, 1, 2])],
    [dict(bank_id=0, pool_indices=[0, 1, 2], pool_role='armor')],
])
def test_bank_layout_must_cover_empty_slots_in_reviewed_order(groups):
    _, _, _, profile, descriptor, review = bank_fixture()
    descriptor['bank_groups'] = groups
    with pytest.raises(InvalidRatioBinding):
        PoolRatioContract.from_profile(raw(profile), raw(descriptor), review)


def test_valid_bank_partition_cannot_reinterpret_another_review():
    _, _, _, profile, descriptor, review = bank_fixture()
    descriptor['bank_groups'] = [dict(bank_id=0, pool_indices=[0, 1, 2])]
    with pytest.raises(InvalidRatioBinding, match='bank_groups_not_reviewed'):
        PoolRatioContract.from_profile(raw(profile), raw(descriptor), review)
