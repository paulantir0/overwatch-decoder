"""Private sums over a complete, explicitly supplied actor pool layout.

No application offsets or target access occur here. A native recipe must prove
component ownership/class/layout; a strictly verified profile/frame and a separate
guarded controller/body relation supply identity. These sums establish neither
health semantics nor player visibility. Unknown inputs never become zero.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from dataclasses import dataclass


class InvalidHealthBinding(ValueError):
    pass


def _integer(value):
    return type(value) is int


def _digest(value):
    return isinstance(value, str) and re.fullmatch(r"[a-fA-F0-9]{64}", value) is not None


@dataclass(frozen=True)
class PoolHealthContract:
    """Profile-bound private contract; construct with from_profile, not directly."""

    profile_sha256: str
    target: dict
    actor_prefix: str
    controller_prefix: str
    slots: tuple
    fields: dict
    guards: tuple
    guard_ids: dict
    identities: dict
    acquisition_evidence_sha256: str
    membership_sha256: str

    @classmethod
    def from_profile(cls, profile_bytes: bytes, *, actor_prefix: str, slots: list,
                     acquisition_evidence_sha256: str) -> "PoolHealthContract":
        """Validate caller's full source-audited slot descriptor against guards.

        slots is the complete native-layout sequence, including zero memberships:
        {index, membership_address, membership_u32, field_name, scalar_address}.
        Empty slots require null field_name/scalar_address. The source recipe and
        acquisition evidence, not this generic arithmetic, establish layout size.
        Every occupied scalar must depend on every membership word. Local field
        guards and global guards use native parser ordering/deduplication.
        """
        return cls._from_profile(profile_bytes, actor_prefix=actor_prefix, slots=slots,
                                 acquisition_evidence_sha256=acquisition_evidence_sha256,
                                 controller_prefix=None)

    @classmethod
    def _from_profile(cls, profile_bytes, *, actor_prefix, slots,
                      acquisition_evidence_sha256, controller_prefix):
        """Shared storage validation; public constructors supply identity policy."""
        def need(condition, reason):
            if not condition:
                raise InvalidHealthBinding(reason)

        profile = json.loads(profile_bytes)
        need(profile.get("schema") == "overwatch-decoder.field-profile/1", "unsupported_profile_schema")
        need(_digest(acquisition_evidence_sha256), "missing_acquisition_evidence")
        if controller_prefix is None:
            match = re.fullmatch(r"(controller_\d{4})_body_0000_", actor_prefix)
            need(match is not None, "unsupported_actor_prefix")
            controller_prefix = match[1]
        target = profile.get("target", {})
        need(_integer(target.get("pid")) and target["pid"] > 0
             and _integer(target.get("creation_file_time")) and target["creation_file_time"] > 0
             and _digest(target.get("executable_sha256")) and target.get("architecture") == "x64",
             "missing_target_binding")
        guards, field_ids, fields = [], {}, {}

        def parse_guards(container):
            ids = []
            for guard in container.get("guards", []):
                try:
                    address, data = guard["address"], bytes.fromhex(guard["bytes_hex"])
                except (ValueError, KeyError, TypeError) as error:
                    raise InvalidHealthBinding("invalid_guard") from error
                need(_integer(address) and address > 0 and 1 <= len(data) <= 64, "invalid_guard")
                item = (address, data)
                if item not in guards:
                    guards.append(item)
                index = guards.index(item)
                if index not in ids:
                    ids.append(index)
            return ids

        global_ids = parse_guards(profile)
        for field in profile.get("fields", []):
            name = field.get("name")
            need(isinstance(name, str) and name not in fields, "duplicate_or_missing_field_name")
            fields[name] = dict(field)
            field_ids[name] = list(dict.fromkeys(global_ids + parse_guards(field)))
        need(0 < len(guards) <= 256 and 0 < len(fields) <= 160, "profile_bound")

        def expected_word(address, ids):
            need(_integer(address) and address > 0, "invalid_word_address")
            covered, word = False, {}
            for index in ids:
                at, data = guards[index]
                covered |= at <= address and address + 4 <= at + len(data)
                for source in range(max(at, address), min(at + len(data), address + 4)):
                    value = data[source - at]
                    need(source not in word or word[source] == value, "conflicting_guard_bytes")
                    word[source] = value
            need(covered and len(word) == 4, "word_not_fully_guarded")
            return int.from_bytes(bytes(word[address + i] for i in range(4)), "little")

        need(isinstance(slots, list) and 0 < len(slots) <= 256, "invalid_supplied_slot_layout")
        need([slot.get("index") for slot in slots] == list(range(len(slots))), "incomplete_or_duplicate_slot_indices")
        memberships, occupied_names, normalized = set(), set(), []
        for slot in slots:
            address, member = slot.get("membership_address"), slot.get("membership_u32")
            need(_integer(address) and address > 0 and address not in memberships, "duplicate_or_invalid_membership_address")
            need(_integer(member) and 0 <= member <= 0xffffffff, "invalid_membership_word")
            memberships.add(address)
            name, scalar = slot.get("field_name"), slot.get("scalar_address")
            if member == 0:
                need(name is None and scalar is None, "empty_slot_has_scalar")
            else:
                need(isinstance(name, str) and re.fullmatch(re.escape(actor_prefix) + r"pool_\d{4}_direct_candidate", name) is not None,
                     "wrong_actor_pool_field")
                need(name not in occupied_names, "duplicate_pool_field")
                field = fields.get(name, {})
                need(field.get("type") == "f32" and field.get("address") == scalar
                     and _integer(scalar) and scalar > 0 and "codec" not in field, "invalid_scalar_binding")
                occupied_names.add(name)
            normalized.append(dict(index=slot["index"], membership_address=address,
                                   membership_u32=member, field_name=name, scalar_address=scalar))
        need(bool(occupied_names), "no_occupied_pool")
        declared_names = {name for name in fields if re.fullmatch(re.escape(actor_prefix) + r"pool_\d{4}_direct_candidate", name)}
        need(declared_names == occupied_names, "declared_pool_set_mismatch")
        # All empty and occupied memberships must be effective dependencies of
        # every scalar, so new activation invalidates the entire total.
        for name in occupied_names:
            for slot in normalized:
                need(expected_word(slot["membership_address"], field_ids[name]) == slot["membership_u32"],
                     "membership_guard_value_mismatch")
        identities = {}
        for suffix in ("handle_candidate_i32", "manager_key_candidate_i32"):
            name = actor_prefix + suffix
            field = fields.get(name, {})
            need(field.get("type") == "i32", "missing_body_identity_field")
            identities[name] = expected_word(field.get("address"), field_ids[name])
        canonical = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
        return cls(hashlib.sha256(profile_bytes).hexdigest(), dict(target), actor_prefix, controller_prefix,
                   tuple(normalized), fields, tuple(guards), field_ids, identities,
                   acquisition_evidence_sha256, hashlib.sha256(canonical).hexdigest())

    def project(self, frame: dict, *, relation_projection: dict, gap: bool = False):
        """Return a private reciprocal-body candidate; never carry past values."""
        try:
            if (relation_projection.get("schema") != "overwatch-decoder.guarded-object-relations/1"
                    or relation_projection.get("profile_sha256") != self.profile_sha256
                    or any(relation_projection.get("target", {}).get(key) != value for key, value in self.target.items())
                    or any(relation_projection.get("timing", {}).get(key) != frame.get(key)
                           for key in ("sequence", "start_ticks", "end_ticks"))):
                return None
            rows = [row for row in relation_projection.get("relations", [])
                    if row.get("controller_prefix") == self.controller_prefix]
            if (len(rows) != 1 or rows[0].get("relation_status") != "observed"
                    or not isinstance(rows[0].get("body_object_key"), str) or not rows[0]["body_object_key"]):
                return None

            return self._project_storage(frame, gap=gap, key_name="body_object_key",
                                         object_key=rows[0]["body_object_key"], schema="overwatch-decoder.actor-pool-sum/1")
        except (KeyError, TypeError, ValueError, OverflowError):
            return None

    def _observed(self, frame, name, kind):
        start, end = frame["start_ticks"], frame["end_ticks"]
        field = frame.get("fields", {}).get(name, {})
        if field.get("type") != kind or field.get("status") != "observed":
            raise InvalidHealthBinding("field_unobserved")
        a, b = field.get("read_start_ticks"), field.get("read_end_ticks")
        if not _integer(a) or not _integer(b) or not start <= a <= b <= end:
            raise InvalidHealthBinding("invalid_field_bracket")
        ids = self.guard_ids[name]
        if field.get("guard_ids") != ids:
            raise InvalidHealthBinding("guard_dependencies_mismatch")
        for phase in ("before", "after"):
            checks = frame.get("guards_" + phase)
            if not isinstance(checks, list) or len(checks) != len(self.guards):
                raise InvalidHealthBinding("missing_guard_checks")
            for guard_id in ids:
                check = checks[guard_id]
                c, d = check.get("start_ticks"), check.get("end_ticks")
                if (check.get("ok") is not True or check.get("error") is not None
                        or not _integer(c) or not _integer(d) or not start <= c <= d <= end
                        or (phase == "before" and d > a) or (phase == "after" and c < b)):
                    raise InvalidHealthBinding("invalid_or_failed_guard_check")
        return field.get("value"), a, b

    def _project_storage(self, frame, *, gap, key_name, object_key, schema):
        """Validate one complete layout without assigning an ownership meaning."""
        try:
            if (gap or frame.get("skipped_intervals_before", 0) != 0
                    or frame.get("kind") != "frame" or frame.get("schema") != "overwatch-decoder.field-stream/1"
                    or frame.get("source") != "process_memory" or frame.get("profile_sha256") != self.profile_sha256
                    or any(frame.get("target", {}).get(key) != value for key, value in self.target.items())):
                return None
            start, end = frame.get("start_ticks"), frame.get("end_ticks")
            if not _integer(start) or not _integer(end) or start > end:
                return None

            for name, expected in self.identities.items():
                value, _, _ = self._observed(frame, name, "i32")
                if not _integer(value) or not -(1 << 31) <= value < 1 << 31 or value & 0xffffffff != expected:
                    return None
            declared_names = {slot["field_name"] for slot in self.slots if slot["membership_u32"] != 0}
            actual_names = {name for name in frame.get("fields", {})
                            if re.fullmatch(re.escape(self.actor_prefix) + r"pool_\d{4}_direct_candidate", name)}
            if actual_names != declared_names:
                return None
            contributions = []
            for slot in self.slots:
                if slot["membership_u32"] == 0:
                    continue
                value, a, b = self._observed(frame, slot["field_name"], "f32")
                if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value) or value < 0:
                    return None
                contributions.append(dict(pool_index=slot["index"], field=slot["field_name"],
                                          value=value, read_start_ticks=a, read_end_ticks=b))
            total = math.fsum(item["value"] for item in contributions)
            if not math.isfinite(total):
                return None
            return dict(schema=schema, status="candidate", source="process_memory",
                        **{key_name: object_key}, raw_sum=total,
                        display_ceiling_candidate=math.ceil(total), contributions=contributions,
                        occupied_pool_count=len(contributions), supplied_layout_slots=len(self.slots),
                        complete_supplied_membership_guarding=True, maximum_health=None, pool_roles=None,
                        read_start_ticks=min(item["read_start_ticks"] for item in contributions),
                        read_end_ticks=max(item["read_end_ticks"] for item in contributions),
                        profile_sha256=self.profile_sha256, build_sha256=self.target["executable_sha256"],
                        acquisition_evidence_sha256=self.acquisition_evidence_sha256,
                        membership_contract_sha256=self.membership_sha256, atomic=False,
                        continuity_across_gaps=False, public_state_eligible=False, visibility="unknown")
        except (KeyError, TypeError, ValueError, OverflowError):
            return None


@dataclass(frozen=True)
class ForwardOwnerHealthContract:
    """Complete pool candidate for an explicitly source-pinned forward owner.

    This never establishes that the referenced owner is the displayed body.
    The supplied projection must come from GuardedForwardOwners on this frame.
    Both identities and all membership words remain current dependencies.
    """

    storage: PoolHealthContract
    binding_id: str
    forward_contract_sha256: str
    recipe_sha256: str
    acquisition_manifest_sha256: str

    @property
    def profile_sha256(self):
        return self.storage.profile_sha256

    @property
    def target(self):
        return self.storage.target

    @property
    def guards(self):
        return self.storage.guards

    @property
    def owner_prefix(self):
        return self.storage.actor_prefix

    @classmethod
    def from_profile(cls, profile_bytes, *, owner_prefix, slots, acquisition_evidence_sha256,
                     forward_contract_sha256, binding_id, recipe_sha256, acquisition_manifest_sha256):
        if (not isinstance(owner_prefix, str) or re.fullmatch(r"[A-Za-z0-9_]{1,64}_", owner_prefix) is None
                or not isinstance(binding_id, str) or re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", binding_id) is None
                or any(not _digest(value) for value in (forward_contract_sha256, recipe_sha256,
                                                        acquisition_manifest_sha256))):
            raise InvalidHealthBinding("invalid_forward_owner_binding")
        if not isinstance(slots, list) or len(slots) != 48:
            raise InvalidHealthBinding("complete_forward_membership_requires_48_slots")
        storage = PoolHealthContract._from_profile(profile_bytes, actor_prefix=owner_prefix, slots=slots,
            acquisition_evidence_sha256=acquisition_evidence_sha256, controller_prefix="")
        # Every pool scalar must retain the owner's guarded full identity. The
        # forward projector separately verifies all five association words.
        for identity in storage.identities:
            if any(key in storage.fields[identity] for key in ("codec", "path", "path_id")):
                raise InvalidHealthBinding("unsupported_forward_identity_field")
            address = storage.fields[identity]["address"]
            for slot in storage.slots:
                if slot["membership_u32"]:
                    _guarded_word(storage, address, storage.guard_ids[slot["field_name"]],
                                  expected=storage.identities[identity])
        return cls(storage, binding_id, forward_contract_sha256, recipe_sha256, acquisition_manifest_sha256)

    def project(self, frame, *, forward_relation_projection, gap=False):
        try:
            p, storage = forward_relation_projection, self.storage
            if not isinstance(p, dict) or not isinstance(frame, dict):
                return None
            if (type(gap) is not bool or type(frame.get("skipped_intervals_before", 0)) is not int
                    or not _integer(frame.get("sequence")) or frame["sequence"] < 0
                    or not _integer(frame.get("monotonic_frequency")) or frame["monotonic_frequency"] <= 0):
                return None
            source = dict(recipe_sha256=self.recipe_sha256,
                          evidence_sha256=storage.acquisition_evidence_sha256,
                          acquisition_manifest_sha256=self.acquisition_manifest_sha256)
            if (p.get("schema") != "overwatch-decoder.guarded-forward-owner-relations/1"
                    or p.get("profile_sha256") != self.profile_sha256 or p.get("target") != self.target
                    or p.get("source") != "process_memory" or p.get("source_evidence") != source
                    or p.get("contract_sha256") != self.forward_contract_sha256
                    or p.get("current_displayed_body") is not None
                    or p.get("public_state_eligible") is not False or p.get("visibility") != "unknown"
                    or any(not _integer(p.get("timing", {}).get(k)) or p["timing"][k] != frame.get(k)
                           for k in ("sequence", "start_ticks", "end_ticks", "monotonic_frequency"))):
                return None
            rows = [row for row in p.get("relations", [])
                    if row.get("binding_id") == self.binding_id
                    or row.get("owned_field_prefix") == self.owner_prefix]
            if len(rows) != 1:
                return None
            row = rows[0]
            if (row.get("binding_id") != self.binding_id or row.get("owned_field_prefix") != self.owner_prefix
                    or row.get("relation_status") != "observed" or row.get("reason") is not None
                    or row.get("current_displayed_body") is not None
                    or not isinstance(row.get("controller_object_key"), str)
                    or re.fullmatch(r"controller:[a-f0-9]{64}", row["controller_object_key"]) is None
                    or not isinstance(row.get("forward_owner_object_key"), str)
                    or re.fullmatch(r"owner:[a-f0-9]{64}", row["forward_owner_object_key"]) is None):
                return None
            value = storage._project_storage(frame, gap=gap, key_name="forward_owner_object_key",
                object_key=row["forward_owner_object_key"], schema="overwatch-decoder.forward-owner-pool-sum/1")
            if value is None:
                return None
            identities = row.get("identity_evidence")
            if not isinstance(identities, list) or len(identities) != 5:
                return None
            names = [item["field"] for item in identities]
            if len(set(names)) != 5 or names[3:] != list(storage.identities):
                return None
            for item in identities:
                name = item["field"]
                if (storage.fields[name].get("type") != "i32"
                        or any(key in storage.fields[name] for key in ("codec", "path", "path_id"))):
                    return None
                observed, a, b = storage._observed(frame, name, "i32")
                if (not _integer(observed) or not -(1 << 31) <= observed < 1 << 31
                        or not _integer(item.get("value")) or item["value"] != (observed & 0xffffffff)
                        or item.get("read_start_ticks") != a or item.get("read_end_ticks") != b
                        or item.get("guard_ids") != storage.guard_ids[name]):
                    return None
                # All occupied scalars must depend on every association word,
                # including the controller's exact forward reference.
                for slot in storage.slots:
                    if slot["membership_u32"]:
                        _guarded_word(storage, storage.fields[name]["address"],
                            storage.guard_ids[slot["field_name"]], expected=observed & 0xffffffff)
            for role, indexes, key in (("controller", (0, 1), "controller_object_key"),
                                       ("owner", (3, 4), "forward_owner_object_key")):
                words = [(storage.fields[names[i]]["address"], identities[i]["value"]) for i in indexes]
                payload = ["overwatch-decoder.guarded-object-relation/1", role, self.target, words]
                expected_key = role + ":" + hashlib.sha256(json.dumps(
                    payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                if row[key] != expected_key:
                    return None
            if identities[2]["value"] != identities[4]["value"]:
                return None
            for contribution in value["contributions"]:
                name = contribution["field"]
                field = row.get("owned_fields", {}).get(name, {})
                if (field.get("status") != "observed" or field.get("type") != "f32"
                        or field.get("value") != contribution["value"]
                        or field.get("read_start_ticks") != contribution["read_start_ticks"]
                        or field.get("read_end_ticks") != contribution["read_end_ticks"]
                        or field.get("guard_ids") != storage.guard_ids[name]):
                    return None
            value.update(controller_object_key=row["controller_object_key"], owned_field_prefix=self.owner_prefix,
                         binding_id=self.binding_id, current_displayed_body=None,
                         forward_contract_sha256=self.forward_contract_sha256,
                         source_evidence=source, identity_evidence=copy.deepcopy(identities),
                         association_kind="native_forward_reference", privacy="private")
            return value
        except (KeyError, TypeError, ValueError, OverflowError, AttributeError):
            return None


def _guarded_word(storage, address, ids, *, expected):
    """Require one identical fully covered u32 dependency, without decoding it."""
    covered, word = False, {}
    for index in ids:
        at, data = storage.guards[index]
        covered |= at <= address and address + 4 <= at + len(data)
        for source in range(max(at, address), min(at + len(data), address + 4)):
            byte = data[source-at]
            if source in word and word[source] != byte:
                raise InvalidHealthBinding("conflicting_forward_identity_guards")
            word[source] = byte
    if (not covered or len(word) != 4
            or int.from_bytes(bytes(word[address+i] for i in range(4)), "little") != expected):
        raise InvalidHealthBinding("forward_identity_not_scalar_dependency")
