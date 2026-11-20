"""Source-bound pool ratios from paired, guarded vector reads.

No target offsets, process access or universal health semantics live here.
Caller-supplied contracts connect a complete owned pool layout to a reviewed
native calculation. The result is a sampled ratio candidate, not HUD maximum
health, a native function invocation, visibility, or a liveness assertion.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import struct

from .health_projection import PoolHealthContract, InvalidHealthBinding, _digest, _integer


class InvalidRatioBinding(InvalidHealthBinding):
    pass


def _need(condition, reason):
    if not condition:
        raise InvalidRatioBinding(reason)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _object(raw, limit):
    _need(isinstance(raw, bytes) and 0 < len(raw) <= limit, "ratio_input_size")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            _need(key not in result, "duplicate_ratio_key")
            result[key] = value
        return result
    try:
        result = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeDecodeError, RecursionError) as error:
        raise InvalidRatioBinding("invalid_ratio_json") from error
    _need(isinstance(result, dict), "ratio_object_required")
    return result


def _f32(value):
    try:
        return struct.unpack("<f", struct.pack("<f", value))[0]
    except OverflowError:
        return math.copysign(math.inf, value)


def calculate_ratio(operands, *, zero_initial_sum=False):
    """Reviewed finite/nonnegative arithmetic, assuming round-to-nearest f32.

    Native JSON may use shortest round-trip decimals. Normalize every operand
    back to binary32 before MOVSS/ADDSS emulation, including occupied slot zero.
    The native floating-point control state is not inferred by this function.
    """
    sums = {}
    for key in ("numerator", "denominator"):
        total = 0.0
        for part in operands:
            value = part[key]
            _need(type(value) in (int, float) and math.isfinite(value) and value >= 0,
                  "unsupported_pool_operand")
            value = _f32(value)
            total = value if part["pool_index"] == 0 and not zero_initial_sum else _f32(total + value)
            _need(math.isfinite(total), "unsupported_nonfinite_pool_sum")
        sums[key] = total
    numerator, denominator = sums["numerator"], sums["denominator"]
    ratio = max(0.0, min(1.0, _f32(numerator / denominator))) if denominator > 0 else 0.0
    return numerator, denominator, ratio


def validate_bank_groups(groups, slot_count):
    """Validate a reviewed ordered partition, including unoccupied slots.

    Bank numbers are caller-supplied structural labels, not armor/shield roles.
    The declaration must cover the complete supplied membership layout exactly.
    """
    _need(_integer(slot_count) and 0 < slot_count <= 128
          and isinstance(groups, list) and 0 < len(groups) <= slot_count,
          "invalid_bank_groups")
    result, ids, indices = [], set(), []
    for group in groups:
        _need(isinstance(group, dict) and set(group) == {"bank_id", "pool_indices"},
              "invalid_bank_group")
        bank_id, pools = group["bank_id"], group["pool_indices"]
        _need(_integer(bank_id) and 0 <= bank_id < 128 and bank_id not in ids
              and isinstance(pools, list) and 0 < len(pools) <= slot_count
              and all(_integer(index) for index in pools), "invalid_bank_membership")
        ids.add(bank_id)
        indices.extend(pools)
        result.append(dict(bank_id=bank_id, pool_indices=pools.copy()))
    _need(indices == list(range(slot_count)), "incomplete_or_reordered_bank_partition")
    return tuple(result)


def calculate_bank_candidates(operands, groups):
    """Reconstruct each reviewed bank separately from the same paired reads.

    The bank getters start with positive zero and ADDSS each occupied record.
    Do not reconstruct the whole-layout result by summing these subtotals: the
    changed floating-point reduction order can change its last bits.
    """
    result = []
    for group in groups:
        parts = [part for part in operands if part["pool_index"] in group["pool_indices"]]
        numerator, denominator, ratio = calculate_ratio(parts, zero_initial_sum=True)
        result.append(dict(bank_id=group["bank_id"], pool_role=None,
            occupied_pool_count=len(parts), operand_pool_indices=[part["pool_index"] for part in parts],
            numerator_sum=numerator, native_denominator_sum=denominator, native_ratio_candidate=ratio,
            operand_read_span_ticks=[min(part["read_start_ticks"] for part in parts),
                                     max(part["read_end_ticks"] for part in parts)] if parts else None))
    return result


@dataclass(frozen=True)
class PoolRatioContract:
    storage: PoolHealthContract
    paired_slots: tuple
    contract_sha256: str
    native_review_sha256: str
    source: dict
    bank_groups: tuple = ()

    @classmethod
    def from_profile(cls, profile_bytes, contract_bytes, native_review_bytes):
        contract = _object(contract_bytes, 262144)
        review = _object(native_review_bytes, 8 * 1024 * 1024)
        _need(contract.get("schema") == "overwatch-decoder.private.actor-health-ratio-contract/1"
              and contract.get("algorithm") == "occupied_pool_ratio_f32", "unsupported_ratio_contract")
        descriptor = contract.get("health_contract")
        _need(isinstance(descriptor, dict), "missing_ratio_health_contract")
        try:
            storage = PoolHealthContract.from_profile(profile_bytes, **descriptor)
        except (TypeError, ValueError) as error:
            raise InvalidRatioBinding("invalid_ratio_health_contract") from error
        _need(contract.get("profile_sha256") == storage.profile_sha256
              and contract.get("build_sha256") == storage.target["executable_sha256"], "ratio_profile_pin")
        _need(contract.get("native_review_sha256") == _sha(native_review_bytes)
              and review.get("build_sha256") == storage.target["executable_sha256"], "ratio_native_review_pin")
        source = contract.get("source")
        _need(isinstance(source, dict) and set(source) == {"manifest_sha256", "recipe_sha256", "evidence_sha256"}
              and all(_digest(value) for value in source.values())
              and source["evidence_sha256"] == storage.acquisition_evidence_sha256, "ratio_acquisition_pin")
        slots = contract.get("paired_slots")
        occupied = [slot for slot in storage.slots if slot["membership_u32"]]
        _need(isinstance(slots, list) and len(slots) == len(occupied)
              and all(isinstance(slot, dict) and _integer(slot.get("pool_index")) for slot in slots)
              and [slot.get("pool_index") for slot in slots] == [slot["index"] for slot in occupied],
              "incomplete_ratio_pairs")
        names, normalized = set(), []
        all_memberships = [slot["membership_address"] for slot in storage.slots]
        all_currents = [slot["scalar_address"] for slot in occupied]
        for pair, pool in zip(slots, occupied, strict=True):
            name = pair.get("field_name")
            _need(isinstance(name, str) and name in storage.fields and name not in names, "invalid_ratio_pair_field")
            names.add(name)
            field = storage.fields[name]
            kind = field.get("type")
            width = {"f32x3": 3, "f32x4": 4}.get(kind) if isinstance(kind, str) else None
            ni, di = pair.get("numerator_component"), pair.get("denominator_component")
            _need(width is not None and "codec" not in field
                  and _integer(ni) and _integer(di) and 0 <= ni < width and 0 <= di < width and ni != di,
                  "invalid_ratio_pair_components")
            base, denominator = field.get("address"), pair.get("denominator_address")
            _need(_integer(base) and base > 0 and _integer(denominator)
                  and base + ni * 4 == pool["scalar_address"]
                  and base + di * 4 == denominator, "ratio_pair_address_mismatch")
            _need(not any(denominator < at + 4 and at < denominator + 4
                          for at in all_memberships + all_currents), "ratio_denominator_overlap")
            # All ownership and complete-membership checks protecting the direct
            # scalar must also protect its paired vector, before and after reads.
            _need(set(storage.guard_ids[pool["field_name"]]) <= set(storage.guard_ids[name]),
                  "ratio_pair_missing_guards")
            normalized.append(dict(pool_index=pool["index"], field_name=name, type=field["type"],
                                   numerator_component=ni, denominator_component=di, width=width))
        groups = ()
        if "bank_groups" in contract:
            groups = validate_bank_groups(contract["bank_groups"], len(storage.slots))
            reviewed = validate_bank_groups(review.get("bank_groups"), len(storage.slots))
            _need(groups == reviewed, "bank_groups_not_reviewed")
        return cls(storage, tuple(normalized), _sha(contract_bytes), _sha(native_review_bytes), dict(source), groups)

    def verify_source(self, source):
        acquisition = source.get("acquisition", {})
        _need(source.get("profile_sha256") == self.storage.profile_sha256
              and all(acquisition.get(key) == value for key, value in self.source.items()),
              "ratio_source_mismatch")

    def project(self, frame, *, relation_projection, gap=False):
        health = self.storage.project(frame, relation_projection=relation_projection, gap=gap)
        if health is None:
            return None
        try:
            operands = []
            for slot in self.paired_slots:
                values, start, end = self.storage._observed(frame, slot["field_name"], slot["type"])
                _need(isinstance(values, list) and len(values) == slot["width"], "invalid_ratio_vector")
                operands.append(dict(pool_index=slot["pool_index"], field=slot["field_name"],
                    numerator=values[slot["numerator_component"]], denominator=values[slot["denominator_component"]],
                    numerator_component=slot["numerator_component"], denominator_component=slot["denominator_component"],
                    read_start_ticks=start, read_end_ticks=end))
            numerator, denominator, ratio = calculate_ratio(operands)
            result = dict(schema="overwatch-decoder.actor-pool-ratio/1", status="candidate", source="process_memory",
                validation_status="static_derived_sampled_operands", observation_scope="current_frame_paired_reads",
                body_object_key=health["body_object_key"], numerator_sum=numerator,
                native_denominator_sum=denominator, native_ratio_candidate=ratio, operands=operands,
                occupied_pool_count=len(operands), supplied_layout_slots=len(self.storage.slots),
                read_start_ticks=min(part["read_start_ticks"] for part in operands),
                read_end_ticks=max(part["read_end_ticks"] for part in operands),
                profile_sha256=self.storage.profile_sha256, build_sha256=self.storage.target["executable_sha256"],
                acquisition_evidence_sha256=self.storage.acquisition_evidence_sha256,
                contract_sha256=self.contract_sha256, native_review_sha256=self.native_review_sha256,
                membership_contract_sha256=self.storage.membership_sha256,
                maximum_health=None, hud_ratio=None, pool_roles=None,
                complete_supplied_membership_guarding=True, arithmetic_assumption="binary32_round_to_nearest_even",
                native_float_control_state_observed=False, native_execution_observed=False,
                atomic=False, continuity_across_gaps=False, visibility="unknown", public_state_eligible=False)
            if self.bank_groups:
                result["bank_candidates"] = calculate_bank_candidates(operands, self.bank_groups)
            return result
        except (InvalidHealthBinding, KeyError, TypeError, ValueError, OverflowError):
            return None
