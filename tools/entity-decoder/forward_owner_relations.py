"""Source-bound native forward-key associations, distinct from reciprocal bodies.

The caller's acquisition recipe establishes component ownership and the native
forward-reference interpretation. This module validates its pinned acquisition,
guarded full words and current reads; equal integers alone are not semantic proof.
There are no application offsets, process reads, role labels or historical fill.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from contextlib import contextmanager
from contextvars import ContextVar

from relations import GuardedRelations, InvalidBinding


class InvalidForwardOwnerEvidence(ValueError):
    pass


def _need(value, reason):
    if not value:
        raise InvalidForwardOwnerEvidence(reason)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _parse(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            _need(key not in result, 'duplicate_json_key')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: _need(False, 'nonfinite_json'))
    except (ValueError, TypeError, RecursionError) as error:
        raise InvalidForwardOwnerEvidence('invalid_json') from error


WORDS = ('controller_handle_field', 'controller_key_field', 'reference_field',
         'owner_handle_field', 'owner_key_field')


def reference_group_membership(groups, binding_ids):
    """Validate an explicit bounded partition of bindings; absent keeps legacy rules."""
    if groups is None:
        return {}
    _need(isinstance(groups, list) and 1 <= len(groups) <= 16, 'reference_group_count')
    membership, seen = {}, set()
    for group in groups:
        _need(isinstance(group, dict) and set(group) == {'group_id', 'binding_ids'}, 'reference_group_shape')
        ident, members = group['group_id'], group['binding_ids']
        _need(isinstance(ident, str) and re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,63}', ident)
              and ident not in seen, 'reference_group_id')
        seen.add(ident)
        _need(isinstance(members, list) and 2 <= len(members) <= 32
              and all(isinstance(n, str) and n in binding_ids for n in members)
              and len(set(members)) == len(members) and not set(members) & set(membership),
              'reference_group_members')
        membership.update((n, ident) for n in members)
    return membership


# A factory owns this short-lived scope; no proof survives its exit. Cache
# only an exact immutable evidence/source tuple, never a path or an object id.
_ACQUISITION_VALIDATION = ContextVar("forward_acquisition_validation", default=None)


@contextmanager
def acquisition_validation_scope(*, reuse_current=False):
    """Share repeated proof work within one explicitly owned acquisition factory.

    Nested constructors may join that scope. Distinct scopes never share data;
    a different source inside one scope is always checked independently.
    """
    if reuse_current and _ACQUISITION_VALIDATION.get() is not None:
        yield
        return
    state = dict(source=None, proofs={}, disabled=False)
    token = _ACQUISITION_VALIDATION.set(state)
    try:
        yield
    finally:
        state["proofs"].clear()
        _ACQUISITION_VALIDATION.reset(token)


def _verify_acquisition(evidence, manifest, recipe, relations):
    state = _ACQUISITION_VALIDATION.get()
    try:
        return _verify_acquisition_scoped(evidence, manifest, recipe, relations, state)
    except Exception:
        if state is not None:
            state["proofs"].clear()
            state["disabled"] = True
        raise


def _verify_acquisition_scoped(evidence, manifest, recipe, relations, state):
    if state is None or state["disabled"] or not isinstance(evidence, bytes):
        return _verify_acquisition_uncached(evidence, manifest, recipe, relations)
    try:
        source = (evidence, json.dumps(manifest, sort_keys=True, allow_nan=False),
                  json.dumps(recipe, sort_keys=True, allow_nan=False), relations.hash)
        proof = (json.dumps(relations.target, sort_keys=True, allow_nan=False),
                 json.dumps([(g["address"], g["bytes_hex"]) for g in relations.guards],
                            allow_nan=False),
                 len(relations.fields))
        hash(proof)
    except (KeyError, TypeError, ValueError):
        # Preserve the original validator's rejection ordering for bad inputs.
        return _verify_acquisition_uncached(evidence, manifest, recipe, relations)
    if (state["source"] is not None and state["source"] != source
            or state["proofs"] and proof not in state["proofs"]):
        # Once this owner sees another source/layout, do not resume an older
        # proof even if a caller later restores mutable arguments.
        state["proofs"].clear()
        state["disabled"] = True
        return _verify_acquisition_uncached(evidence, manifest, recipe, relations)
    if proof in state["proofs"]:
        return copy.deepcopy(state["proofs"][proof])
    result = _verify_acquisition_uncached(evidence, manifest, recipe, relations)
    if len(state["proofs"]) < 8:
        state["source"] = source
        state["proofs"][proof] = copy.deepcopy(result)
    return result


def _verify_acquisition_uncached(evidence, manifest, recipe, relations):
    """Check native transcript endpoints and actual final bytes, not just hashes."""
    _need(manifest.get('stages_completed') == len(recipe.get('stages', [])) > 0,
          'incomplete_acquisition_stages')
    required = set()
    for guard in relations.guards:
        try:
            address, data = guard['address'], bytes.fromhex(guard['bytes_hex'])
            _need(type(address) is int and 0 < address < 2**63
                  and 1 <= len(data) <= 64, 'invalid_guard')
            required.add((address, data))
        except (KeyError, ValueError, TypeError) as error:
            raise InvalidForwardOwnerEvidence('invalid_guard') from error
    reads, checked, size = {}, set(), 0
    last = None
    collections = []
    for index, line in enumerate(evidence.splitlines()):
        _need(index < 250000 and len(line) <= 4*1024*1024, 'evidence_bounds')
        event = _parse(line)
        _need(isinstance(event, dict), 'evidence_event')
        if index == 0:
            _need(event.get('schema') == 'overwatch-decoder.acquisition-evidence/1'
                  and event.get('kind') == 'start'
                  and event.get('source_kind') == 'native_process_memory'
                  and event.get('target') == relations.target
                  and event.get('recipe_sha256') == manifest['recipe_sha256']
                  and event.get('revision') == manifest.get('revision'), 'evidence_source_mismatch')
        if event.get('kind') == 'read':
            _need(type(event.get('id')) is int and event['id'] == len(reads), 'read_sequence')
            try:
                data = bytes.fromhex(event['bytes_hex'])
            except (KeyError, ValueError, TypeError) as error:
                raise InvalidForwardOwnerEvidence('invalid_read_bytes') from error
            size += len(data)
            _need(size <= 64*1024*1024, 'read_bytes_bound')
            reads[event['id']] = (event, data)
        elif event.get('kind') == 'guard_check':
            _need(event.get('matches') is True, 'failed_acquisition_guard')
            if event.get('stage') == 'final_guard_check':
                old, new, offset = (event.get(k) for k in
                                    ('expected_read_id', 'actual_read_id', 'expected_offset'))
                _need(type(old) is int and type(new) is int and old < new
                      and old in reads and new in reads and type(offset) is int
                      and offset >= 0, 'final_guard_reference')
                before, original = reads[old]
                after, actual = reads[new]
                width = after.get('requested_bytes')
                _need(type(width) is int and 1 <= width <= 64
                      and before.get('attempted') is True and before.get('error') is None
                      and before.get('returned_bytes') == len(original)
                      and after.get('attempted') is True and after.get('error') is None
                      and after.get('returned_bytes') == len(actual) == width
                      and type(before.get('address')) is int
                      and after.get('address') == before['address'] + offset
                      and original[offset:offset+width] == actual, 'final_guard_bytes')
                times = [before.get('read_start_ticks'), before.get('read_end_ticks'),
                         after.get('read_start_ticks'), after.get('read_end_ticks')]
                _need(all(type(t) is int for t in times)
                      and 0 <= times[0] <= times[1] <= times[2] <= times[3], 'final_guard_timing')
                checked.add((after['address'], actual))
        if event.get('kind') == 'field_collection':
            collections.append(event)
        last = event
    _need(last is not None and last.get('kind') == 'profile_validated'
          and last.get('profile_sha256') == relations.hash
          and last.get('fields') == len(relations.fields), 'missing_profile_validation')
    _need(required and required <= checked, 'unchecked_profile_guard')
    return collections


class GuardedForwardOwners:
    """Stateless associations and guarded raw owned fields from one native frame."""

    def __init__(self, raw_profile, raw_contract, artifacts):
        self.relations = r = GuardedRelations(raw_profile)
        _need(isinstance(raw_contract, bytes) and len(raw_contract) <= 262144, 'contract_size')
        contract = _parse(raw_contract)
        _need(isinstance(contract, dict)
              and contract.get('schema') == 'overwatch-decoder.forward-owner-contract/1', 'contract_schema')
        _need(contract.get('profile_sha256') == r.hash and contract.get('target') == r.target
              and contract.get('build_sha256') == r.target['executable_sha256'], 'contract_scope')
        _need(isinstance(artifacts, dict) and len(artifacts) <= 32, 'artifact_count')
        def artifact(digest, maximum):
            _need(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest), 'artifact_digest')
            raw = artifacts.get(digest)
            _need(isinstance(raw, bytes) and len(raw) <= maximum and _sha(raw) == digest,
                  'artifact_hash_or_size')
            return raw
        source = contract.get('source')
        _need(isinstance(source, dict), 'source_pins')
        self.source = {k: source.get(k) for k in ('recipe_sha256', 'evidence_sha256')}
        recipe = _parse(artifact(self.source['recipe_sha256'], 1048576))
        _need(isinstance(recipe, dict) and recipe.get('schema') == 'overwatch-decoder.acquisition-recipe/1'
              and all(recipe.get('target', {}).get(k) == r.target[k]
                      for k in ('image_name', 'architecture', 'executable_sha256')), 'recipe_scope')
        self.manifest_hash = contract.get('acquisition_manifest_sha256')
        manifest = _parse(artifact(self.manifest_hash, 262144))
        _need(isinstance(manifest, dict) and manifest.get('schema') == 'overwatch-decoder.acquisition-result/1'
              and manifest.get('complete') is True and manifest.get('error') is None
              and manifest.get('target') == r.target and manifest.get('profile_sha256') == r.hash
              and all(manifest.get(k) == v for k, v in self.source.items()), 'acquisition_scope')
        evidence = artifact(self.source['evidence_sha256'], 128*1024*1024)
        collections = _verify_acquisition(evidence, manifest, recipe, r)
        self.template_hash = contract.get('binding_template_sha256')
        template = _parse(artifact(self.template_hash, 262144))
        _need(isinstance(template, dict)
              and template.get('schema') == 'overwatch-decoder.forward-owner-binding-template/1'
              and template.get('build_sha256') == r.target['executable_sha256']
              and template.get('recipe_sha256') == self.source['recipe_sha256']
              and template.get('bindings') == contract.get('bindings')
              and ('reference_groups' in template) == ('reference_groups' in contract)
              and template.get('reference_groups') == contract.get('reference_groups'), 'binding_template_scope')
        bindings = contract.get('bindings')
        _need(isinstance(bindings, list) and 1 <= len(bindings) <= 32, 'binding_count')
        self.bindings, ids = [], set()
        for binding in bindings:
            _need(isinstance(binding, dict), 'binding_object')
            ident, prefix = binding.get('binding_id'), binding.get('owned_field_prefix')
            _need(isinstance(ident, str) and re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,63}', ident)
                  and ident not in ids, 'binding_id')
            ids.add(ident)
            _need(isinstance(prefix, str) and re.fullmatch('[A-Za-z][A-Za-z0-9_]{0,62}_', prefix),
                  'owned_field_prefix')
            names = [binding.get(k) for k in WORDS]
            _need(all(isinstance(n, str) for n in names) and len(set(names)) == 5, 'identity_fields')
            optional = binding.get('optional_owner_collection')
            empty = None
            if optional is not None:
                _need(isinstance(optional, dict) and set(optional) == {'recipe_pointer', 'rows', 'prefix', 'depth'},
                      'optional_collection_descriptor')
                pointer = optional['recipe_pointer']
                _need(isinstance(pointer, str) and re.fullmatch(r'(?:/field_collections/[0-9]+){1,4}', pointer),
                      'optional_collection_pointer')
                definition, declared = recipe, []
                parts = pointer.split('/')[1:]
                try:
                    for at in range(0, len(parts), 2):
                        definition = definition['field_collections'][int(parts[at+1])]
                        _need(isinstance(definition, dict), 'optional_collection_definition')
                        declared.append(definition['prefix'])
                except (KeyError, IndexError, TypeError):
                    raise InvalidForwardOwnerEvidence('optional_collection_pointer')
                _need(all(isinstance(n, str) and re.fullmatch('[A-Za-z][A-Za-z0-9_]*', n) for n in declared)
                      and optional['depth'] == len(declared) and type(optional['depth']) is int
                      and definition.get('allow_empty') is True and definition.get('rows') == optional['rows']
                      and isinstance(optional['prefix'], str) and re.fullmatch(
                          '_[0-9]{4}_'.join(re.escape(n) for n in declared), optional['prefix'])
                      and prefix == optional['prefix'] + '_0000_', 'optional_collection_scope')
                if len(declared) > 1:
                    parent = optional['prefix'][:-len('_'+declared[-1])]
                    _need(all(n.startswith(parent+'_') for n in names[:3]), 'optional_controller_collection_scope')
                templates = definition.get('fields', [])
                _need(all(sum(isinstance(f,dict) and f.get('name') == name[len(prefix):] and f.get('type') == 'i32'
                              for f in templates) == 1 for name in names[3:]), 'optional_owner_templates')
                traces = [e for e in collections if e.get('prefix') == optional['prefix']]
                _need(len(traces) == 1, 'optional_collection_trace_missing_or_duplicate')
                trace = traces[0]
                _need(trace.get('stage') == 'field_collection_output' and trace.get('rows') == optional['rows']
                      and type(trace.get('depth')) is int and trace.get('depth') == optional['depth'] and trace.get('allow_empty') is True
                      and trace.get('identity') == 'ordinal_within_acquisition_only'
                      and type(trace.get('first_field')) is int and 0 <= trace['first_field'] <= len(r.fields),
                      'optional_collection_trace_scope')
                missing = [n not in r.fields for n in names[3:]]
                owned = [n for n in r.fields if n.startswith(prefix)]
                if any(missing):
                    _need(all(missing) and not owned and trace.get('retained_rows') == 0
                          and type(trace.get('retained_rows')) is int and trace.get('expanded_fields') == 0
                          and type(trace.get('expanded_fields')) is int, 'optional_owner_partial_or_nonempty')
                    empty = dict(schema='overwatch-decoder.forward-owner-acquisition-empty/1', collection=copy.deepcopy(optional),
                        collection_event=copy.deepcopy(trace), source_evidence=dict(self.source, acquisition_manifest_sha256=self.manifest_hash))
                else:
                    _need(type(trace.get('retained_rows')) is int and trace['retained_rows'] > 0
                          and type(trace.get('expanded_fields')) is int and trace['expanded_fields'] > 0,
                          'optional_present_collection_trace')
            active_names = names[:3] if empty is not None else names
            _need(all(n in r.fields for n in active_names), 'identity_fields')
            words = [r._binding(n) for n in active_names]
            addresses = [x[0] for x in words]
            _need(all(abs(a-b) >= 4 for i, a in enumerate(addresses)
                      for b in addresses[i+1:]), 'identity_alias')
            _need(all(n.startswith(prefix) for n in names[3:]), 'owner_prefix_mismatch')
            if empty is not None:
                self.bindings.append(dict(binding_id=ident, owned_field_prefix=prefix, names=active_names,
                    words=words, owned=[], acquisition_empty_evidence=empty))
                continue
            required = set().union(*(r.guard_ids[n] for n in names))
            owned = sorted(n for n in r.fields if n.startswith(prefix))
            _need(owned, 'missing_owned_fields')
            for name in owned:
                field = r.fields[name]
                _need(field.get('type') in ('i32', 'u8', 'f32', 'f32x3')
                      and not any(k in field for k in ('codec', 'path', 'path_id'))
                      and type(field.get('address')) is int and 0 < field['address'] < 2**63-12,
                      'unsupported_owned_field')
                _need(required <= set(r.guard_ids[name]), 'owned_field_missing_identity_guards')
            self.bindings.append(dict(binding_id=ident, owned_field_prefix=prefix,
                                      names=names, words=words, owned=owned))
        _need(all(not a['owned_field_prefix'].startswith(b['owned_field_prefix'])
                  and not b['owned_field_prefix'].startswith(a['owned_field_prefix'])
                  for i, a in enumerate(self.bindings) for b in self.bindings[i+1:]),
              'overlapping_owned_prefixes')
        self.reference_groups = copy.deepcopy(contract.get('reference_groups'))
        _need('reference_groups' not in contract or self.reference_groups is not None, 'reference_group_count')
        self.group_membership = reference_group_membership(self.reference_groups, ids)
        by_id = {b['binding_id']: b for b in self.bindings}
        for group in self.reference_groups or []:
            members = [by_id[n] for n in group['binding_ids']]
            _need(all('acquisition_empty_evidence' not in b for b in members),
                  'reference_group_acquisition_empty_member')
            _need(all(b['words'][:2] == members[0]['words'][:2] for b in members),
                  'reference_group_controller_mismatch')
            references = [b['words'][2][0] for b in members]
            _need(all(abs(a-b) >= 4 for i,a in enumerate(references) for b in references[i+1:]),
                  'reference_group_reference_alias')
        self.contract_hash = _sha(raw_contract)

    def _owned(self, name, frame):
        r = self.relations
        field = frame.get('fields', {}).get(name, {})
        kind = r.fields[name]['type']
        if not isinstance(field, dict):
            raise InvalidBinding('invalid_owned_sample')
        a, b = field.get('read_start_ticks'), field.get('read_end_ticks')
        if (field.get('status') != 'observed' or field.get('type') != kind
                or type(a) is not int or type(b) is not int
                or not frame['start_ticks'] <= a <= b <= frame['end_ticks']
                or field.get('guard_ids') != r.guard_ids[name]
                or not r._guard_brackets_match(r.guard_ids[name], frame, a, b)):
            raise InvalidBinding('owned_field_unobserved_or_unguarded')
        value = field.get('value')
        if kind in ('i32', 'u8'):
            lower, upper = (-(2**31), 2**31) if kind == 'i32' else (0, 256)
            valid = type(value) is int and lower <= value < upper
        else:
            values = value if kind == 'f32x3' and isinstance(value, list) else [value]
            valid = (kind != 'f32x3' or isinstance(value, list) and len(value) == 3)
            valid = valid and all(type(v) in (int, float) and math.isfinite(v) for v in values)
        if not valid:
            raise InvalidBinding('invalid_owned_value')
        return dict(status='observed', type=kind, value=copy.deepcopy(value), reason=None,
                    read_start_ticks=a, read_end_ticks=b, guard_ids=r.guard_ids[name].copy())

    def project(self, frame, *, gap=False):
        _need(isinstance(frame, dict), 'invalid_frame')
        r = self.relations
        result = dict(schema='overwatch-decoder.guarded-forward-owner-relations/1', profile_sha256=r.hash,
                      target=r.target.copy(), source='process_memory', contract_sha256=self.contract_hash,
                      binding_template_sha256=self.template_hash,
                      source_evidence=dict(self.source, acquisition_manifest_sha256=self.manifest_hash),
                      timing={k: frame.get(k) for k in ('sequence', 'start_ticks', 'end_ticks',
                                                       'monotonic_frequency')}, relations=[],
                      association_kind='native_forward_reference', atomic=False,
                      continuity_across_gaps=False, previous_values_carried=False,
                      public_state_eligible=False, visibility='unknown', durability_verified=False)
        error = ('invalid_frame_shape' if not isinstance(frame.get('target'), dict)
                 or not isinstance(frame.get('fields'), dict) else r._frame_error(frame))
        skips = frame.get('skipped_intervals_before', 0)
        if type(skips) is not int or skips < 0:
            error = 'invalid_gap_metadata'
        elif gap or skips:
            error = 'scheduled_gap'
        if (type(frame.get('sequence')) is not int or frame['sequence'] < 0
                or type(frame.get('monotonic_frequency')) is not int
                or frame['monotonic_frequency'] <= 0):
            error = 'invalid_frame_timing'
        # Preserve ambiguity from expected identities even if a current read fails.
        # Only an explicitly source-pinned group permits one controller's references.
        duplicate = set()
        present = [b for b in self.bindings if 'acquisition_empty_evidence' not in b]
        for i, a in enumerate(present):
            for b in present[i+1:]:
                group = self.group_membership.get(a['binding_id'])
                grouped = group is not None and group == self.group_membership.get(b['binding_id'])
                for indexes in ((0,1),(3,4)):
                    collision = any(a['words'][j][1] == b['words'][j][1] for j in indexes)
                    exact = all(a['words'][j] == b['words'][j] for j in indexes)
                    if collision and not (grouped and exact):
                        duplicate.update((a['binding_id'],b['binding_id']))
        if self.reference_groups is not None:
            result['reference_groups'] = copy.deepcopy(self.reference_groups)
        with r._frame_checks(frame):
            for binding in self.bindings:
                row = dict(binding_id=binding['binding_id'], owned_field_prefix=binding['owned_field_prefix'],
                           controller_object_key=None, forward_owner_object_key=None, relation_status='unknown',
                           reason=error, identity_evidence=[], owned_fields={}, current_displayed_body=None)
                result['relations'].append(row)
                if 'acquisition_empty_evidence' in binding:
                    row['acquisition_empty_evidence'] = copy.deepcopy(binding['acquisition_empty_evidence'])
                if error:
                    continue
                try:
                    if any(not isinstance(frame['fields'].get(n), dict) for n in binding['names']):
                        raise InvalidBinding('invalid_identity_sample')
                    controller = [r._observed(n, frame) for n in binding['names'][:2]]
                    row['controller_object_key'] = r._key('controller', controller)
                    words = controller + [r._observed(n, frame) for n in binding['names'][2:]]
                    if 'acquisition_empty_evidence' in binding:
                        row.update(reason='acquisition_empty', identity_evidence=[dict(
                            field=w['field'], value=w['value'], read_start_ticks=w['read_start_ticks'],
                            read_end_ticks=w['read_end_ticks'], guard_ids=r.guard_ids[w['field']].copy())for w in words])
                        continue
                    if binding['binding_id'] in duplicate:
                        raise InvalidBinding('duplicate_controller_or_owner')
                    if words[2]['value'] != words[4]['value']:
                        raise InvalidBinding('forward_reference_owner_mismatch')
                    row.update(forward_owner_object_key=r._key('owner', words[3:]), relation_status='observed',
                               reason=None, identity_evidence=[dict(
                                   field=w['field'], value=w['value'], read_start_ticks=w['read_start_ticks'],
                                   read_end_ticks=w['read_end_ticks'], guard_ids=r.guard_ids[w['field']].copy())
                                   for w in words])
                    for name in binding['owned']:
                        try:
                            row['owned_fields'][name] = self._owned(name, frame)
                        except InvalidBinding as failure:
                            row['owned_fields'][name] = dict(status='unknown', type=r.fields[name]['type'],
                                                           value=None, reason=str(failure))
                except InvalidBinding as failure:
                    row['reason'] = str(failure)
        return result


def build_forward_owner_contract(acquisition_directory, template_bytes, *, recipe_path=None):
    """Bind a caller-pinned template to one complete saved native acquisition.

    Returns (serialized_contract, artifacts_by_sha256). No discovery, process
    reads, recipe edits, inferred roles or reuse of an earlier epoch occurs.
    """
    from pathlib import Path
    from plan_live_roster import read
    _need(isinstance(template_bytes, bytes) and len(template_bytes) <= 262144, 'template_size')
    template = _parse(template_bytes)
    _need(isinstance(template, dict)
          and template.get('schema') == 'overwatch-decoder.forward-owner-binding-template/1', 'template_schema')
    directory = Path(acquisition_directory)
    profile = read(directory / 'profile.json', 262144)
    manifest = read(directory / 'manifest.json', 262144)
    recipe = read(recipe_path or directory / 'recipe.json', 1048576)
    evidence = read(directory / 'evidence.jsonl', 128*1024*1024)
    r = GuardedRelations(profile)
    contract = dict(schema='overwatch-decoder.forward-owner-contract/1', target=r.target,
                    build_sha256=r.target['executable_sha256'], profile_sha256=_sha(profile),
                    acquisition_manifest_sha256=_sha(manifest),
                    binding_template_sha256=_sha(template_bytes),
                    source=dict(recipe_sha256=_sha(recipe), evidence_sha256=_sha(evidence)),
                    bindings=template.get('bindings'))
    if 'reference_groups' in template:
        contract['reference_groups'] = copy.deepcopy(template['reference_groups'])
    raw = (json.dumps(contract, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
    artifacts = {_sha(value): value for value in (manifest, recipe, evidence, template_bytes)}
    GuardedForwardOwners(profile, raw, artifacts)
    return raw, artifacts
