"""Project declared, guarded controller/body bindings from one verified frame.

This module does no process access and contains no application offsets. The
acquisition recipe must prove the relationship; matching integers alone do not.
Inputs must have passed the recorder's strict source/profile verification.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from contextlib import contextmanager

CONTROLLER = re.compile(r"controller_\d{4}_handle_candidate_i32\Z")
IDENTITY = ("pid", "creation_file_time", "executable_sha256", "architecture", "image_name")


class InvalidBinding(ValueError):
    pass


def _integer(value):
    return type(value) is int


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidBinding("duplicate_json_key")
        result[key] = value
    return result


class GuardedRelations:
    """Stateless projection; never carries an identity or value over a gap.

    Controller keys exclude body storage, so a new guarded body binding can
    retain the same controller key. That equality does not establish continuous
    lifetime, account identity, or a particular respawn event.
    """

    def __init__(self, raw_profile: bytes, *, allow_profile4=False):
        if not isinstance(raw_profile, bytes) or len(raw_profile) > 256 * 1024:
            raise InvalidBinding("invalid_profile")
        self.hash = hashlib.sha256(raw_profile).hexdigest()
        self.profile = json.loads(raw_profile, object_pairs_hook=_unique_object)
        if type(allow_profile4) is not bool:
            raise InvalidBinding("invalid_profile_schema_policy")
        accepted = {"overwatch-decoder.field-profile/1"} | ({"overwatch-decoder.field-profile/4"} if allow_profile4 else set())
        if self.profile.get("schema") not in accepted:
            raise InvalidBinding("unsupported_profile_schema")
        target = self.profile.get("target", {})
        if (not _integer(target.get("pid")) or target["pid"] <= 0
                or not _integer(target.get("creation_file_time")) or target["creation_file_time"] <= 0
                or target.get("architecture") != "x64"
                or not re.fullmatch(r"[0-9a-fA-F]{64}", target.get("executable_sha256", ""))
                or not isinstance(target.get("image_name"), str)):
            raise InvalidBinding("invalid_target")
        self.target = {key: target[key] for key in IDENTITY}
        self.fields = {}
        for field in self.profile.get("fields", []):
            name = field.get("name")
            if not isinstance(name, str) or name in self.fields:
                raise InvalidBinding("duplicate_or_invalid_field")
            self.fields[name] = field
        # Match v1 recorder guard IDs: globals first, then each field, deduplicated.
        self.guards = []
        self.guard_ids = {}
        guard_references = 0
        maximum_guard_references = 160 * 12 if self.profile["schema"] == "overwatch-decoder.field-profile/4" else 256
        def register(declarations):
            nonlocal guard_references
            ids = []
            for guard in declarations:
                # Count every declared dependency before exact-guard deduplication.
                guard_references += 1
                if guard_references > maximum_guard_references:
                    raise InvalidBinding("profile_guard_reference_bounds")
                if not isinstance(guard, dict):
                    raise InvalidBinding("invalid_guard")
                if guard not in self.guards:
                    self.guards.append(guard)
                index = self.guards.index(guard)
                if index not in ids:
                    ids.append(index)
            return ids
        globals_ = register(self.profile.get("guards", []))
        # A dependency prefix, not cached evidence. Its checks are recomputed
        # in each owned frame scope and reused only when IDs match exactly.
        self._shared_guard_prefix = tuple(globals_)
        for name, field in self.fields.items():
            self.guard_ids[name] = list(dict.fromkeys(globals_ + register(field.get("guards", []))))
        if len(self.fields) > 160 or len(self.guards) > 256:
            raise InvalidBinding("profile_bounds")
        self._binding_cache = {}
        self._unscoped_bindings = {}
        self._binding_layout = None
        self._active_checks = None
        self.prefixes = sorted(name[:-len("_handle_candidate_i32")]
                               for name in self.fields if CONTROLLER.fullmatch(name))

    @contextmanager
    def _frame_checks(self, frame):
        """Internal read-only projection scope for an owned, parsed live frame.

        The live adapter owns this frame throughout the scope; projectors must
        not mutate it. Only guard evidence results and summaries live here, never sampled values
        or successful fields. Every new scope rechecks all guard evidence. Static word plans
        additionally invalidate on any binding/guard-layout change.
        """
        def guards(items):
            return tuple((g.get("address"), g.get("bytes_hex")) for g in items)
        layout = (guards(self.profile.get("guards", [])), tuple(
            (name, f.get("type"), f.get("address"),
             tuple(k in f for k in ("path", "path_id", "codec")), guards(f.get("guards", [])))
            for name, f in self.fields.items()))
        if layout != self._binding_layout:
            self._binding_cache.clear()
            self._binding_layout = layout
        previous = self._active_checks
        current = (frame, {}, {})
        self._active_checks = current
        try:
            yield
        finally:
            current[1].clear()
            current[2].clear()
            self._active_checks = previous

    def _binding(self, name):
        if self._active_checks is None:
            return self._unscoped_binding(name)
        if name not in self._binding_cache:
            self._binding_cache[name] = self._uncached_binding(name)
        return self._binding_cache[name]

    def _unscoped_binding(self, name):
        """Reuse a static word plan only for the same exact typed declaration."""
        field = self.fields.get(name)
        if type(field) is not dict or field.get("type") != "i32" or "path" in field or "path_id" in field or "codec" in field:
            return self._uncached_binding(name)
        address = field.get("address")
        if type(address) is not int or not 0 < address < (1 << 63) - 3:
            return self._uncached_binding(name)
        global_guards, field_guards = self.profile.get("guards", []), field.get("guards", [])
        if type(global_guards) is not list or type(field_guards) is not list:
            return self._uncached_binding(name)
        layout = []
        for guard in global_guards + field_guards:
            if type(guard) is not dict:
                return self._uncached_binding(name)
            start, expected = guard.get("address"), guard.get("bytes_hex")
            # Only exact immutable primitives enter the plan key: True and 1.0
            # compare equal to 1 but cannot represent a declared address.
            if type(start) is not int or type(expected) is not str:
                return self._uncached_binding(name)
            layout.append((start, expected))
        entry = self._unscoped_bindings.get(name)
        if entry is not None and entry[0] == (address, layout):
            return entry[1]
        binding = self._uncached_binding(name)
        if len(self._unscoped_bindings) >= 160:
            self._unscoped_bindings.clear()
        self._unscoped_bindings[name] = ((address, layout), binding)
        return binding

    def _uncached_binding(self, name):
        field = self.fields.get(name)
        if not field or field.get("type") != "i32" or any(k in field for k in ("path", "path_id", "codec")):
            raise InvalidBinding("unsupported_word_binding")
        address = field.get("address")
        if not _integer(address) or not 0 < address < (1 << 63) - 3:
            raise InvalidBinding("invalid_word_address")
        guards = self.profile.get("guards", []) + field.get("guards", [])
        word, covered = {}, False
        for guard in guards:
            start = guard.get("address")
            if not _integer(start) or start < 0:
                raise InvalidBinding("invalid_guard")
            try:
                data = bytes.fromhex(guard["bytes_hex"])
            except (ValueError, KeyError, TypeError) as error:
                raise InvalidBinding("invalid_guard") from error
            if not 1 <= len(data) <= 64:
                raise InvalidBinding("invalid_guard")
            covered |= start <= address and address + 4 <= start + len(data)
            for offset in range(max(address, start), min(address + 4, start + len(data))):
                value = data[offset - start]
                if offset in word and word[offset] != value:
                    raise InvalidBinding("conflicting_identity_guards")
                word[offset] = value
        if not covered or len(word) != 4:
            raise InvalidBinding("identity_word_not_guarded")
        return address, int.from_bytes(bytes(word[address + i] for i in range(4)), "little")

    def _guard_times(self, check, index):
        if self.profile['schema'] != 'overwatch-decoder.field-profile/4':
            return check.get('start_ticks'),check.get('end_ticks')
        guard, read = self.guards[index],check.get('read')
        try:
            expected = bytes.fromhex(guard['bytes_hex'])
            valid = (type(check.get('guard_id')) is int and check['guard_id'] == index
                     and isinstance(read,dict) and read.get('attempted') is True
                     and read.get('address_hex') == f"{guard['address']:016x}"
                     and type(read.get('requested_bytes')) is int and read['requested_bytes'] == len(expected)
                     and type(read.get('returned_bytes')) is int and read['returned_bytes'] == len(expected)
                     and 'error' in read and read['error'] is None
                     and bytes.fromhex(read['bytes_hex']) == expected)
        except (ValueError,TypeError,KeyError):
            valid = False
        if not valid:
            raise InvalidBinding('invalid_serial_guard_read')
        return read.get('start_ticks'),read.get('end_ticks')

    def _validate_guard_check(self, check, index, frame):
        if not isinstance(check, dict) or check.get('ok') is not True or check.get('error') is not None:
            raise InvalidBinding('guard_check_failed')
        a, b = self._guard_times(check, index)
        if not _integer(a) or not _integer(b) or not frame['start_ticks'] <= a <= b <= frame['end_ticks']:
            raise InvalidBinding('invalid_guard_bracket')
        return a, b

    def _guard_check(self, check, index, phase, frame):
        """Memoize one exact guard record only inside its owning frame scope.

        A failure is cached as its original reason, not converted to success.
        Field-specific read brackets and ordered failure precedence stay at the
        call sites. Retaining the record reference prevents identity reuse.
        """
        active = self._active_checks
        if active is None or active[0] is not frame:
            return self._validate_guard_check(check, index, frame)
        cache, key = active[2], (phase, index)
        entry = cache.get(key)
        if entry is None or entry[0] is not check:
            try:
                result, error = self._validate_guard_check(check, index, frame), None
            except InvalidBinding as invalid:
                result, error = None, str(invalid)
            entry = (check, result, error)
            cache[key] = entry
        if entry[2] is not None:
            raise InvalidBinding(entry[2])
        return entry[1]

    def _guard_brackets_match(self, ids, frame, start, end):
        active = self._active_checks
        if active is None or active[0] is not frame:
            return False
        cache, key = active[1], tuple(ids)
        if key not in cache:
            self._guard_bracket_summary(key, frame, cache)
        summary = cache[key]
        # On failure use the original ordered checks below, including their
        # exact error precedence. A summary never converts a failure to success.
        return summary is not None and summary[0] <= start and summary[1] >= end

    def _guard_bracket_summary(self, key, frame, cache):
        if key not in cache:
            before_end, after_start, valid = frame["start_ticks"], frame["end_ticks"], True
            prefix = self._shared_guard_prefix
            remaining = key
            if prefix and len(key) > len(prefix) and key[:len(prefix)] == prefix:
                shared = self._guard_bracket_summary(prefix, frame, cache)
                if shared is None:
                    cache[key] = None
                    return None
                before_end, after_start = shared
                remaining = key[len(prefix):]
            for phase in ("before", "after"):
                checks = frame.get("guards_" + phase)
                if not isinstance(checks, list) or len(checks) != len(self.guards):
                    valid = False
                    break
                for index in remaining:
                    check = checks[index]
                    try:
                        a, b = self._guard_check(check, index, phase, frame)
                    except InvalidBinding:
                        valid = False
                        break
                    if phase == "before":
                        before_end = max(before_end, b)
                    else:
                        after_start = min(after_start, a)
                if not valid:
                    break
            cache[key] = (before_end, after_start) if valid else None
        return cache[key]

    def sample_scalar(self, name, frame, expected_type):
        """Read one direct scalar after exact target/profile and dependency checks."""
        if self._frame_error(frame):
            raise InvalidBinding(self._frame_error(frame))
        declaration = self.fields.get(name, {})
        field = frame.get("fields", {}).get(name, {})
        value = field.get("value")
        if (expected_type not in ("i32", "u8") or declaration.get("type") != expected_type
                or any(key in declaration for key in ("path", "path_id", "codec"))):
            raise InvalidBinding("unsupported_scalar_binding")
        address = declaration.get("address")
        width = 4 if expected_type == "i32" else 1
        if not _integer(address) or not 0 < address <= (1 << 63) - width:
            raise InvalidBinding("invalid_scalar_address")
        if field.get("status") != "observed" or field.get("type") != expected_type or not _integer(value):
            raise InvalidBinding("identity_word_unobserved")
        lower, upper = (-(1 << 31), 1 << 31) if expected_type == "i32" else (0, 256)
        if not lower <= value < upper:
            raise InvalidBinding("invalid_scalar_value")
        start, end = field.get("read_start_ticks"), field.get("read_end_ticks")
        if (not _integer(start) or not _integer(end)
                or not frame["start_ticks"] <= start <= end <= frame["end_ticks"]):
            raise InvalidBinding("invalid_read_bracket")
        ids = self.guard_ids[name]
        if not ids:
            raise InvalidBinding("missing_guard_dependencies")
        if field.get("guard_ids") != ids:
            raise InvalidBinding("guard_dependencies_mismatch")
        if self._guard_brackets_match(ids, frame, start, end):
            return dict(field=name, value=value, address=address, read_start_ticks=start, read_end_ticks=end)
        for phase in ("before", "after"):
            checks = frame.get("guards_" + phase)
            if not isinstance(checks, list) or len(checks) != len(self.guards):
                raise InvalidBinding("missing_guard_checks")
            for guard_id in ids:
                check = checks[guard_id]
                a, b = self._guard_check(check, guard_id, phase, frame)
                if ((phase == "before" and b > start)
                        or (phase == "after" and a < end)):
                    raise InvalidBinding("invalid_guard_bracket")
        return dict(field=name, value=value, address=address,
                    read_start_ticks=start, read_end_ticks=end)

    def _observed(self, name, frame):
        address, expected = self._binding(name)
        sample = self.sample_scalar(name, frame, "i32")
        if sample["value"] & 0xffffffff != expected:
            raise InvalidBinding("identity_word_guard_mismatch")
        return dict(sample, value=expected, address=address)

    def _frame_error(self, frame):
        expected_schema = "overwatch-decoder.field-stream/4" if self.profile["schema"] == "overwatch-decoder.field-profile/4" else "overwatch-decoder.field-stream/1"
        if frame.get("schema") != expected_schema or frame.get("kind") != "frame" or frame.get("source") != "process_memory":
            return "unsupported_frame"
        if frame.get("profile_sha256") != self.hash:
            return "profile_mismatch"
        if any(frame.get("target", {}).get(key) != value for key, value in self.target.items()):
            return "target_mismatch"
        if (not _integer(frame.get("start_ticks")) or not _integer(frame.get("end_ticks"))
                or frame["start_ticks"] > frame["end_ticks"]):
            return "invalid_frame_bracket"
        return None

    def _key(self, role, words):
        payload = ["overwatch-decoder.guarded-object-relation/1", role, self.target,
                   [(word["address"], word["value"]) for word in words]]
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return f"{role}:" + digest

    def project(self, frame):
        result = dict(schema="overwatch-decoder.guarded-object-relations/1", profile_sha256=self.hash,
                      target=self.target.copy(), source="process_memory", atomic=False,
                      identity_scope="profile_declared_process_objects",
                      participant_identity_validated=False, continuity_across_gaps=False,
                      public_state_eligible=False, visibility="unknown", relations=[],
                      timing={key: frame.get(key) for key in (
                          "sequence", "start_ticks", "end_ticks", "monotonic_frequency",
                          "utc_origin", "monotonic_origin_ticks")})
        reason = self._frame_error(frame)
        working = []
        for prefix in self.prefixes:
            row = dict(controller_prefix=prefix, controller_object_key=None, body_object_key=None,
                       relation_status="unknown", reason=reason, evidence=[])
            words = []
            try:
                if reason:
                    raise InvalidBinding(reason)
                for suffix in ("_handle_candidate_i32", "_manager_key_candidate_i32"):
                    words.append(self._observed(prefix + suffix, frame))
                row["controller_object_key"] = self._key("controller", words)
                row["evidence"] = [{k: v for k, v in word.items() if k != "address"} for word in words]
                for suffix in ("_part51_0000_body_key_candidate_i32", "_body_0000_handle_candidate_i32",
                               "_body_0000_manager_key_candidate_i32"):
                    words.append(self._observed(prefix + suffix, frame))
                if words[2]["value"] != words[4]["value"]:
                    raise InvalidBinding("body_key_mismatch")
                # The private recipe verifies same manager and reciprocal lookup.
                # The generic projector cannot prove arbitrary recipe semantics.
                row["body_object_key"] = self._key("body", words[3:])
                row["relation_status"], row["reason"] = "observed", None
                row["evidence"] = [{k: v for k, v in word.items() if k != "address"} for word in words]
            except InvalidBinding as error:
                row["reason"] = str(error)
            working.append((row, words))
        controller_counts = Counter(words[0]["value"] for row, words in working if len(words) >= 2)
        body_counts = Counter(words[3]["value"] for row, words in working if row["relation_status"] == "observed")
        for row, words in working:
            if len(words) >= 2 and controller_counts[words[0]["value"]] != 1:
                row.update(controller_object_key=None, body_object_key=None,
                           relation_status="unknown", reason="ambiguous_controller_handle")
            elif row["relation_status"] == "observed" and body_counts[words[3]["value"]] != 1:
                row.update(body_object_key=None, relation_status="unknown", reason="ambiguous_body_handle")
            result["relations"].append(row)
        return result
