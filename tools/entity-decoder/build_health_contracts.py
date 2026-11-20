"""Build private pool contracts from a caller-declared layout and saved evidence.

The layout is an explicit, complete-layout assertion, not a layout discovery or
health-semantics claim. Its JSON schema is ``overwatch-decoder.health-layout/1`` with keys:
``executable_sha256``, ``recipe_sha256``, ``extent_size``, ``read_stage``,
``slot_count``, ``slot_stride``, ``membership_offset``, ``scalar_offset``,
``actor_prefixes`` and ``scalar_field_suffix``. Optional ``actor_read_stages``
maps every declared actor prefix to its exact acquisition read stage; otherwise
all actors use ``read_stage``. Offsets are relative to an extent;
slot i adds i * slot_stride. Memberships are u32 and occupied scalars are f32,
as required by PoolHealthContract. Names, stages, addresses and layouts come
from the caller; this module has no target access or application-specific route.

Every declared actor must have an exact occupied-field/extent match. All empty
slots remain in its descriptor. Optional ``supported_forward_owners`` is a list of
``{owner_prefix, binding_id, forward_contract_sha256}`` declarations whose prefixes
are included in ``actor_prefixes``. Only explicit ``allow_forward_owners=True``
(or CLI ``--allow-forward-owners``) admits them. Their descriptors are returned
separately under ``forward_owner_contracts`` and require all 48 memberships;
they do not establish a current displayed body. All identities, layouts and
contract hashes are caller-supplied evidence, never discovered semantics.

A build/recipe pin does not prove the caller's
class, ownership, layout completeness, gameplay meaning or player visibility.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

# Direct script invocation must also work outside the repository working folder.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from overwatch_decoder.health_projection import InvalidHealthBinding, PoolHealthContract, ForwardOwnerHealthContract


class InvalidHealthAcquisition(ValueError):
    """The saved source does not prove the supplied layout's full binding."""


MAX_PROFILE_BYTES = 256 * 1024
MAX_RECIPE_BYTES = 1024 * 1024
MAX_EVIDENCE_BYTES = 128 * 1024 * 1024
MAX_EXTENT_BYTES = 32 * 1024


def _need(condition, reason):
    if not condition:
        raise InvalidHealthAcquisition(reason)


def _integer(value):
    return type(value) is int


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _digest(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def _read(path, maximum):
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(maximum + 1)
    except OSError as error:
        raise InvalidHealthAcquisition("unreadable_input") from error
    _need(0 < len(data) <= maximum, "input_size_bound")
    return data


def _object(raw, *, unique_keys=False):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            _need(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    try:
        result = json.loads(raw, object_pairs_hook=unique if unique_keys else None)
    except (ValueError, UnicodeDecodeError, RecursionError) as error:
        raise InvalidHealthAcquisition("invalid_json") from error
    _need(isinstance(result, dict), "json_object_required")
    return result


def _layout(raw):
    _need(isinstance(raw, bytes) and 0 < len(raw) <= 64 * 1024, "layout_size_bound")
    layout = _object(raw)
    if "actor_read_stages" in layout:
        layout = _object(raw, unique_keys=True)
    _need(layout.get("schema") == "overwatch-decoder.health-layout/1", "unsupported_layout_schema")
    for name in ("executable_sha256", "recipe_sha256"):
        _need(_digest(layout.get(name)), "invalid_layout_pin")
    for name, minimum, maximum in (("extent_size", 4, MAX_EXTENT_BYTES),
                                   ("slot_count", 1, 256),
                                   ("slot_stride", 4, MAX_EXTENT_BYTES),
                                   ("membership_offset", 0, MAX_EXTENT_BYTES),
                                   ("scalar_offset", 0, MAX_EXTENT_BYTES)):
        value = layout.get(name)
        _need(_integer(value) and minimum <= value <= maximum, "invalid_layout_bound")
    for name in ("read_stage", "scalar_field_suffix"):
        value = layout.get(name)
        _need(isinstance(value, str) and 0 < len(value) <= 128, "invalid_layout_name")
    prefixes = layout.get("actor_prefixes")
    _need(isinstance(prefixes, list) and 0 < len(prefixes) <= 128
          and all(isinstance(p, str) and 0 < len(p) <= 128 for p in prefixes),
          "invalid_actor_prefixes")
    _need(len(set(prefixes)) == len(prefixes)
          and not any(a != b and b.startswith(a) for a in prefixes for b in prefixes),
          "overlapping_actor_prefixes")
    if "actor_read_stages" in layout:
        stages = layout["actor_read_stages"]
        _need(isinstance(stages, dict) and set(stages) == set(prefixes)
              and all(isinstance(stage, str) and 0 < len(stage) <= 128 for stage in stages.values()),
              "invalid_actor_read_stages")
    memberships, scalars = [], []
    for index in range(layout["slot_count"]):
        for name, offsets in (("membership_offset", memberships), ("scalar_offset", scalars)):
            offset = layout[name] + index * layout["slot_stride"]
            _need(offset + 4 <= layout["extent_size"], "slot_outside_extent")
            offsets.append(offset)
    _need(not any(a < b + 4 and b < a + 4 for a in memberships for b in scalars),
          "membership_scalar_overlap")
    return layout, memberships, scalars


def build_contracts(acquisition_directory, layout_bytes, *, recipe_path=None, allow_forward_owners=False):
    """Verify local acquisition artifacts and return a private descriptor bundle.

    Recipe bytes must be supplied explicitly when not in the acquisition folder;
    no parent-directory search or external process access occurs. Unrelated
    evidence reads are ignored. Every matching stage/size recipe read must be
    complete, and repeated reads of an extent within one stage must be byte-identical.
    Explicit per-actor stages may reuse storage; they remain separate observations.
    Different extents or stages are never merged into one memory snapshot.
    """
    layout, member_offsets, scalar_offsets = _layout(layout_bytes)
    _need(type(allow_forward_owners) is bool, "invalid_forward_owner_option")
    forward = layout.get("supported_forward_owners", [])
    _need(isinstance(forward, list) and len(forward) <= 128, "invalid_supported_forward_owners")
    _need(not forward or allow_forward_owners, "forward_owner_opt_in_required")
    forward_by_prefix, binding_ids = {}, set()
    for item in forward:
        _need(isinstance(item, dict), "invalid_supported_forward_owner")
        prefix, binding = item.get("owner_prefix"), item.get("binding_id")
        _need(prefix in layout["actor_prefixes"] and prefix not in forward_by_prefix
              and isinstance(binding, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", binding) is not None
              and binding not in binding_ids and _digest(item.get("forward_contract_sha256")),
              "invalid_supported_forward_owner")
        forward_by_prefix[prefix] = item
        binding_ids.add(binding)
    directory = Path(acquisition_directory)
    manifest_raw = _read(directory / "manifest.json", MAX_PROFILE_BYTES)
    profile_raw = _read(directory / "profile.json", MAX_PROFILE_BYTES)
    evidence_raw = _read(directory / "evidence.jsonl", MAX_EVIDENCE_BYTES)
    recipe_raw = _read(recipe_path if recipe_path is not None else directory / "recipe.json",
                       MAX_RECIPE_BYTES)
    manifest, profile, recipe = map(_object, (manifest_raw, profile_raw, recipe_raw))
    _need(manifest.get("schema") == "overwatch-decoder.acquisition-result/1"
          and manifest.get("complete") is True and manifest.get("error") is None,
          "incomplete_acquisition")
    for raw, key in ((profile_raw, "profile_sha256"), (evidence_raw, "evidence_sha256"),
                     (recipe_raw, "recipe_sha256")):
        _need(_digest(manifest.get(key)) and _sha(raw) == manifest[key], "source_hash_mismatch")
    _need(manifest["recipe_sha256"] == layout["recipe_sha256"], "recipe_pin_mismatch")
    target = profile.get("target")
    _need(isinstance(target, dict) and isinstance(manifest.get("target"), dict)
          and json.dumps(target, sort_keys=True) == json.dumps(manifest["target"], sort_keys=True),
          "target_mismatch")
    _need(_integer(target.get("pid")) and target["pid"] > 0
          and _integer(target.get("creation_file_time")) and target["creation_file_time"] > 0
          and target.get("architecture") == "x64" and _digest(target.get("executable_sha256"))
          and isinstance(target.get("image_name"), str) and bool(target["image_name"]),
          "invalid_target")
    _need(target["executable_sha256"] == layout["executable_sha256"], "build_pin_mismatch")
    declared_target = recipe.get("target")
    _need(isinstance(declared_target, dict)
          and all(declared_target.get(k) == target[k]
                  for k in ("image_name", "architecture", "executable_sha256")),
          "recipe_target_mismatch")
    fields = profile.get("fields")
    _need(profile.get("schema") == "overwatch-decoder.field-profile/1", "unsupported_profile_schema")
    _need(isinstance(fields, list) and 0 < len(fields) <= 160, "profile_field_bound")
    _need(_integer(manifest.get("fields")) and manifest["fields"] == len(fields),
          "manifest_field_count_mismatch")
    guards = profile.get("guards", [])
    _need(isinstance(guards, list), "invalid_profile_guards")
    declarations = len(guards)
    widths = {"u8": 1, "i32": 4, "f32": 4, "f64": 8, "f32x3": 12, "f32x4": 16}
    field_bytes = 0
    grouped = {prefix: {} for prefix in layout["actor_prefixes"]}
    seen_names = set()
    for field in fields:
        _need(isinstance(field, dict), "invalid_profile_field")
        name = field.get("name")
        _need(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name) is not None
              and name not in seen_names,
              "duplicate_or_invalid_field_name")
        seen_names.add(name)
        kind = field.get("type")
        _need(isinstance(kind, str), "invalid_profile_field")
        width = widths.get(kind)
        address = field.get("address")
        _need(width is not None and _integer(address) and 0 < address <= (1 << 64) - width,
              "invalid_profile_field")
        local_guards = field.get("guards", [])
        _need(isinstance(local_guards, list), "invalid_profile_guards")
        declarations += len(local_guards)
        field_bytes += width
        if not name.endswith(layout["scalar_field_suffix"]):
            continue
        matches = [p for p in grouped if name.startswith(p)]
        _need(len(matches) == 1, "unassigned_pool_field")
        address = field.get("address")
        _need(field.get("type") == "f32" and _integer(address) and address > 0
              and "codec" not in field, "invalid_pool_field")
        actor = grouped[matches[0]]
        _need(address not in actor, "duplicate_scalar_address")
        actor[address] = name
    _need(all(grouped.values()), "missing_actor_pool_fields")
    _need(0 < declarations <= 256 and _integer(manifest.get("guard_declarations"))
          and manifest["guard_declarations"] == declarations,
          "profile_guard_bound_or_count_mismatch")

    actor_stages = layout.get("actor_read_stages", {p: layout["read_stage"] for p in grouped})
    selected_stages = set(actor_stages.values())
    extents = {}
    for line in evidence_raw.splitlines():
        event = _object(line)
        stage = event.get("stage")
        if (event.get("kind") != "read" or event.get("purpose") != "recipe"
                or not isinstance(stage, str) or stage not in selected_stages
                or event.get("requested_bytes") != layout["extent_size"]):
            continue
        address = event.get("address")
        start, end = event.get("read_start_ticks"), event.get("read_end_ticks")
        _need(_integer(address) and 0 < address <= (1 << 64) - layout["extent_size"]
              and event.get("attempted") is True and event.get("error") is None
              and event.get("returned_bytes") == layout["extent_size"]
              and _integer(start) and _integer(end) and 0 <= start <= end,
              "incomplete_extent_read")
        try:
            encoded = event["bytes_hex"]
            _need(isinstance(encoded, str) and len(encoded) == 2 * layout["extent_size"],
                  "incomplete_extent_bytes")
            data = bytes.fromhex(encoded)
        except (KeyError, TypeError, ValueError) as error:
            raise InvalidHealthAcquisition("invalid_extent_bytes") from error
        _need(len(data) == layout["extent_size"], "incomplete_extent_bytes")
        key = (stage, address)
        _need(key not in extents or extents[key] == data, "divergent_extent_reads")
        extents[key] = data
    _need(bool(extents), "missing_extent_reads")

    descriptors, forward_descriptors, used_extents = [], [], set()
    membership_bytes = {}
    for prefix, scalar_fields in grouped.items():
        candidates = []
        stage = actor_stages[prefix]
        for (read_stage, base), data in extents.items():
            if read_stage != stage:
                continue
            words = [int.from_bytes(data[offset:offset + 4], "little") for offset in member_offsets]
            occupied = {base + scalar_offsets[i] for i, value in enumerate(words) if value != 0}
            if occupied == set(scalar_fields):
                candidates.append((base, words))
        _need(len(candidates) == 1, "ambiguous_or_missing_actor_extent")
        base, words = candidates[0]
        _need((stage, base) not in used_extents, "extent_shared_by_actors")
        used_extents.add((stage, base))
        if "actor_read_stages" in layout:
            # Stage separation admits independent scalar reads, not contradictory
            # membership assertions within this one complete guarded profile.
            for offset, word in zip(member_offsets, words):
                for index, value in enumerate(word.to_bytes(4, "little")):
                    address = base + offset + index
                    _need(address not in membership_bytes or membership_bytes[address] == value,
                          "divergent_membership_reads")
                    membership_bytes[address] = value
        slots = [dict(index=i, membership_address=base + member_offsets[i], membership_u32=value,
                      field_name=scalar_fields[base + scalar_offsets[i]] if value else None,
                      scalar_address=base + scalar_offsets[i] if value else None)
                 for i, value in enumerate(words)]
        descriptor = dict(actor_prefix=prefix, slots=slots,
                          acquisition_evidence_sha256=manifest["evidence_sha256"])
        try:
            if prefix in forward_by_prefix:
                reviewed = forward_by_prefix[prefix]
                descriptor = dict(owner_prefix=descriptor["actor_prefix"], slots=slots,
                    acquisition_evidence_sha256=manifest["evidence_sha256"],
                    forward_contract_sha256=reviewed["forward_contract_sha256"], binding_id=reviewed["binding_id"],
                    recipe_sha256=manifest["recipe_sha256"], acquisition_manifest_sha256=_sha(manifest_raw))
                contract = ForwardOwnerHealthContract.from_profile(profile_raw, **descriptor)
            else:
                contract = PoolHealthContract.from_profile(profile_raw, **descriptor)
        except InvalidHealthBinding as error:
            raise InvalidHealthAcquisition(f"invalid_health_contract: {error}") from error
        _need(2 * sum(len(data) for _, data in contract.guards) + field_bytes <= 32 * 1024,
              "profile_read_byte_bound")
        (forward_descriptors if prefix in forward_by_prefix else descriptors).append(descriptor)
    bundle = dict(schema="overwatch-decoder.private.actor-health-contracts/1", profile_sha256=_sha(profile_raw),
                acquisition_evidence_sha256=manifest["evidence_sha256"],
                acquisition_manifest_sha256=_sha(manifest_raw), recipe_sha256=_sha(recipe_raw),
                layout_sha256=_sha(layout_bytes), contracts=descriptors,
                public_state_eligible=False)
    if "actor_read_stages" in layout:
        bundle["actor_read_stages"] = actor_stages.copy()
    if forward_descriptors:
        bundle["forward_owner_contracts"] = forward_descriptors
        bundle["forward_owner_semantics"] = "native_forward_reference_current_displayed_body_unknown"
    return bundle


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acquisition", type=Path, required=True)
    parser.add_argument("--layout", type=Path, required=True)
    parser.add_argument("--recipe", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--allow-forward-owners", action="store_true",
                        help="enable caller-declared supported_forward_owners without body promotion")
    args = parser.parse_args(argv)
    try:
        bundle = build_contracts(args.acquisition, _read(args.layout, 64 * 1024),
                                 recipe_path=args.recipe, allow_forward_owners=args.allow_forward_owners)
        with args.out.open("xb") as output:
            output.write((json.dumps(bundle, indent=2) + "\n").encode())
    except (InvalidHealthAcquisition, OSError) as error:
        parser.exit(1, f"health contract construction failed: {error}\n")
    summary = dict(actors=len(bundle["contracts"]), profile_sha256=bundle["profile_sha256"],
                   layout_sha256=bundle["layout_sha256"], public_state_eligible=False)
    if bundle.get("forward_owner_contracts"):
        summary["forward_owners"] = len(bundle["forward_owner_contracts"])
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
