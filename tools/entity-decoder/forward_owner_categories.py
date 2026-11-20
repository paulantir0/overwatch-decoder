"""Native category candidates joined to guarded forward owners, never bodies."""
from __future__ import annotations

import copy
import json

from categories import _need, _parse, _sha
from forward_owner_relations import GuardedForwardOwners
from raw_categories import GuardedRawCategories
from relations import InvalidBinding


class GuardedForwardOwnerCategories:
    """One exact source/profile and frame; no team, self or current-body claims."""

    def __init__(self, raw_profile, raw_forward_contract, raw_category_contract, artifacts):
        self.forward = GuardedForwardOwners(raw_profile, raw_forward_contract, artifacts)
        _need(isinstance(raw_category_contract, bytes) and len(raw_category_contract) <= 262144,
              'contract_size')
        c = _parse(raw_category_contract)
        _need(isinstance(c, dict) and c.get('schema') == 'overwatch-decoder.forward-owner-category-contract/1',
              'forward_category_contract_schema')
        self.contract_sha256 = _sha(raw_category_contract)
        _need(c.get('forward_contract_sha256') == self.forward.contract_hash, 'forward_contract_mismatch')
        _need(c.get('source') == self.forward.source
              and c.get('acquisition_manifest_sha256') == self.forward.manifest_hash,
              'forward_category_source_mismatch')
        declared = c.get('bindings')
        _need(isinstance(declared, list) and len(declared) <= 32, 'binding_count')
        self.condition_bindings = copy.deepcopy(declared)
        by_id = {b['binding_id']: b for b in self.forward.bindings}
        empty=c.get('acquisition_empty_bindings',[])
        _need(isinstance(empty,list)and len(empty)<=32 and all(isinstance(n,str)and n in by_id
              and 'acquisition_empty_evidence'in by_id[n]for n in empty)and len(set(empty))==len(empty)
              and bool(declared or empty),'category_empty_bindings')
        ids, normalized, self.bindings = set(), [], []
        for b in declared:
            _need(isinstance(b, dict), 'category_binding')
            ident = b.get('binding_id')
            _need(isinstance(ident, str) and ident in by_id and ident not in ids and ident not in empty
                  and 'acquisition_empty_evidence'not in by_id[ident], 'forward_binding_id')
            ids.add(ident)
            native = copy.deepcopy(b)
            native.pop('binding_id')
            # Normalize descriptor keys for the existing field/condition validator.
            # Profile declarations and bytes remain original. No body row is made.
            native['body_handle_field'] = native.pop('owner_handle_field', None)
            native['body_creation_key_field'] = native.pop('owner_key_field', None)
            normalized.append(native)
            self.bindings.append(by_id[ident])
        validation = copy.deepcopy(c)
        validation['schema'] = 'overwatch-decoder.raw-category-contract/1'
        validation['bindings'] = normalized
        _need(not validation.get('additional_relation_prefixes'), 'no_extra_relation_prefixes')
        self.category_fields = GuardedRawCategories(raw_profile,
            json.dumps(validation, sort_keys=True, separators=(',', ':')).encode(), artifacts)
        r = self.category_fields.relations
        for forward, native in zip(self.bindings, self.category_fields.bindings):
            for index, key in ((3, 'handle'), (4, 'key')):
                _need(r._binding(native[key]) == forward['words'][index], 'category_owner_binding_mismatch')
            core = set().union(*(self.forward.relations.guard_ids[n] for n in forward['names']))
            _need(all(core <= set(r.guard_ids[native[half]]) for half in ('low', 'high')),
                  'category_missing_forward_dependencies')

    def project(self, frame, *, gap=False):
        # Compute the association internally on exactly this frame. External
        # projections cannot inject an earlier successful owner or identity.
        association = self.forward.project(frame, gap=gap)
        result = {k: copy.deepcopy(v) for k, v in association.items() if k != 'relations'}
        result.update(schema='overwatch-decoder.guarded-forward-owner-categories/1',
                      forward_contract_sha256=self.forward.contract_hash,
                      contract_sha256=self.contract_sha256,
                      native_review_sha256=self.category_fields.native_review_sha256,
                      validation_scope='reviewed_unlinked_zero_override_branch', rows=[])
        current = {r['binding_id']: r for r in association['relations']}
        r = self.category_fields.relations
        with r._frame_checks(frame):
            for binding, native in zip(self.bindings, self.category_fields.bindings):
                owner = current[binding['binding_id']]
                row = dict(binding_id=binding['binding_id'], owned_field_prefix=binding['owned_field_prefix'],
                           controller_object_key=owner['controller_object_key'],
                           forward_owner_object_key=owner['forward_owner_object_key'],
                           status='unknown', raw_status='unknown', reason=owner['reason'],
                           raw_flags_candidate=None, raw_category_candidate=None, evidence=[],
                           forward_identity_evidence=copy.deepcopy(owner['identity_evidence']),
                           current_displayed_body=None, team_candidate=None,
                           relative_allegiance_candidate=None, visibility='unknown',
                           public_state_eligible=False, atomic=False)
                result['rows'].append(row)
                if owner['relation_status'] != 'observed':
                    continue
                try:
                    if any(not isinstance(frame['fields'].get(native[k]), dict)
                           for k in ('handle', 'key', 'low', 'high')):
                        raise InvalidBinding('invalid_category_sample')
                    words, low, high, selected, error, evidence = self.category_fields.sample_native_flags(native, frame)
                    if r._key('owner', words) != owner['forward_owner_object_key']:
                        raise InvalidBinding('forward_owner_key_mismatch')
                    row.update(raw_status='observed', status='unknown' if error else 'observed', reason=error,
                               raw_category_candidate=None if error else selected[0],
                               raw_flags_candidate=dict(low_u32=low, high_u32=high,
                                   assembled_u64_hex=f'0x{high:08x}{low:08x}', selected_category_indices=selected),
                               evidence=[dict(e, guard_ids=r.guard_ids[e['field']].copy()) for e in evidence])
                except InvalidBinding as failure:
                    row['reason'] = str(failure)
        return result
