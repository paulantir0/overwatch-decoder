"""Finite, caller-reviewed current-context/body projection. No game constants.

Callers must verify the recording/acquisition with export_relations helpers before
passing frames and source pins. This API checks configured pins, current guarded
reads and explicit association equalities; it does not establish native semantics.
"""
from __future__ import annotations
import copy
import hashlib
import math
import re
import struct
from collections import Counter

from export_relations import parse
from relations import GuardedRelations, InvalidBinding


class InvalidSelectedEntity(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise InvalidSelectedEntity(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def f32(value):
    try:
        result = struct.unpack('<f', struct.pack('<f', value))[0]
    except (OverflowError, struct.error) as error:
        raise InvalidBinding('binary32_overflow') from error
    if not math.isfinite(result):
        raise InvalidBinding('nonfinite_binary32')
    return result


WORDS = ('controller_handle', 'controller_key', 'selector', 'ref_first', 'ref_third',
         'body_handle', 'body_key')
LOCAL_REFERENCE_WORDS = ('controller_handle', 'controller_key', 'selector', 'ref_first', 'ref_third')
PINS = ('manifest_sha256', 'recipe_sha256', 'evidence_sha256')


class SelectedEntityView:
    """Stateless API: project(frame, gap=False); no values survive failed reads.

    Contract bindings contain fields for WORDS plus position, hero_low, hero_high.
    Health is optional; if present it declares exactly 48 slots in accumulation
    order, each {index, current, membership_address, membership_u32}, and a
    SHA-pinned review artifact. Membership is a reviewed fixed layout hypothesis
    protected by all declared membership guards, never inferred from a zero.
    """
    def __init__(self, raw_profile, raw_contract, *, source, artifacts=None, hero_catalog=None, allow_profile4=False):
        self.relations = GuardedRelations(raw_profile, allow_profile4=allow_profile4)
        r = self.relations
        need(isinstance(raw_contract, bytes) and len(raw_contract) <= 262144, 'contract_size')
        c = parse(raw_contract)
        need(c.get('schema') == 'overwatch-decoder.selected-entity-contract/1', 'contract_schema')
        need(c.get('profile_sha256') == r.hash and c.get('target') == r.target, 'contract_target_or_profile')
        self.source = c.get('source')
        need(isinstance(self.source, dict) and set(self.source) == set(PINS)
             and all(isinstance(self.source[k], str) and re.fullmatch('[0-9a-f]{64}', self.source[k]) for k in PINS),
             'source_pins')
        self.verify_source(source)
        artifacts = artifacts or {}
        self.catalog, self.hash = hero_catalog, sha(raw_contract)
        self.locale = c.get('locale', 'enUS')
        self.gap_policy = c.get('gap_policy','strict')
        need(self.gap_policy in ('strict','current_frame_only'), 'unsupported_gap_policy')
        self.mode = c.get('mode','current_context')
        need(self.mode in ('current_context','target_vs_local'), 'unsupported_mode')
        self.word_roles = WORDS if self.mode == 'current_context' else tuple(k for k in WORDS if k != 'selector')
        self.local = self.rule = self.empty_local_review = None
        if self.mode == 'target_vs_local': self._configure_local(c,artifacts)
        self.bindings = copy.deepcopy(c.get('bindings'))
        need(type(c.get('allow_empty_bindings',False)) is bool, 'empty_binding_policy')
        self.empty_review = None
        if c.get('allow_empty_bindings'):
            need(self.mode == 'target_vs_local' and self.bindings == [], 'empty_binding_scope')
            self._configure_empty(c,artifacts)
        else:
            need(isinstance(self.bindings, list) and 1 <= len(self.bindings) <= 16, 'binding_count')
        ids = set()
        for b in self.bindings:
            need(isinstance(b, dict) and isinstance(b.get('binding_id'), str)
                 and b['binding_id'] not in ids, 'duplicate_binding')
            ids.add(b['binding_id'])
            fields = b.get('fields')
            expected = set(self.word_roles) | {'position','hero_low','hero_high'}
            if self.mode == 'target_vs_local': expected |= {'flags_low','flags_high'}
            need(isinstance(fields, dict) and set(fields) == expected, 'binding_fields')
            need(len(set(fields.values())) == len(fields), 'aliased_binding_fields')
            need(type(b.get('body_absent',False)) is bool, 'body_absent_policy')
            if b.get('body_absent'):
                need(self.mode == 'target_vs_local' and 'health' not in b, 'body_absent_scope')
                controller_roles = {'controller_handle','controller_key','ref_first','ref_third'}
                for role,name in fields.items():
                    if role in controller_roles:
                        self._declaration(name,'i32'); r._binding(name)
                    else:
                        need(name not in r.fields, 'body_absent_but_declared')
                self._artifact(b.get('review_sha256'),artifacts)
                need(isinstance(b.get('validation_status'),str) and b['validation_status'], 'binding_validation_status')
                need(b.get('is_local') is None, 'body_absent_local_unknown')
                need('raw_quaternion_candidate' not in b, 'absent_body_orientation')
                continue
            for role, name in fields.items():
                self._declaration(name, 'f32x3' if role == 'position' else 'i32')
                if role in self.word_roles:
                    r._binding(name)  # Full identity words must themselves be byte-guarded.
            identities = set().union(*(r.guard_ids[fields[k]] for k in self.word_roles))
            need(all(identities <= set(r.guard_ids[n]) for role,n in fields.items() if role not in self.word_roles), 'identity_dependencies_missing')
            need(b.get('is_local') is None or type(b.get('is_local')) is bool, 'local_flag')
            review = b.get('review_sha256')
            self._artifact(review, artifacts)
            need(isinstance(b.get('validation_status'), str) and b['validation_status'], 'binding_validation_status')
            if 'raw_quaternion_candidate' in b:
                self._configure_quaternion(b, artifacts)
            h = b.get('health')
            if h is not None:
                need(isinstance(h, dict), 'health_shape')
                self._artifact(h.get('review_sha256'), artifacts)
                need(isinstance(h.get('validation_status'), str) and h['validation_status'], 'health_validation_status')
                if 'sum_field' in h:
                    need(set(h) == {'sum_field','review_sha256','validation_status'}, 'health_sum_shape')
                    name = h['sum_field']
                    need(r.profile.get('schema') == 'overwatch-decoder.field-profile/4', 'pool_codec_requires_profile4')
                    self._pool_declaration(name)
                    need(identities <= set(r.guard_ids[name]), 'health_identity_dependencies')
                    continue
                need(isinstance(h.get('slots'), list) and len(h['slots']) == 48, 'complete_health_layout_required')
                names, indices, dependencies = [], [], set()
                for slot in h['slots']:
                    need(isinstance(slot, dict) and set(slot) == {'index','current','membership_address','membership_u32'},
                         'health_slot_shape')
                    address, expected = slot['membership_address'], slot['membership_u32']
                    need(type(slot['index']) is int and 0 <= slot['index'] < 48
                         and type(address) is int and 0 < address <= 2**63-4
                         and type(expected) is int and 0 <= expected < 2**32, 'health_membership_word')
                    indices.append(slot['index'])
                    covered = {}
                    for gid,g in enumerate(r.guards):
                        data = bytes.fromhex(g['bytes_hex']); start = g['address']
                        if start < address+4 and start+len(data) > address:
                            dependencies.add(gid)
                            for offset in range(max(start,address),min(start+len(data),address+4)):
                                byte = data[offset-start]
                                need(offset not in covered or covered[offset] == byte, 'conflicting_membership_guards')
                                covered[offset] = byte
                    need(len(covered) == 4 and int.from_bytes(bytes(covered[address+i] for i in range(4)), 'little') == expected,
                         'membership_word_not_guarded')
                    name = slot['current']; names.append(name)
                    self._declaration(name, 'f32')
                need(indices == list(range(48)), 'health_slot_order')
                need(len({slot['membership_address'] for slot in h['slots']}) == 48, 'duplicate_membership_address')
                need(len({r.fields[name]['address'] for name in names}) == 48, 'duplicate_health_scalar_address')
                need(all((dependencies | identities) <= set(r.guard_ids[n]) for n in names), 'health_membership_dependencies')
                need(len(set(names)) == 48, 'duplicate_health_slot')

    def _configure_quaternion(self, binding, artifacts):
        """Admit caller-reviewed raw storage, not camera or gameplay semantics."""
        r = self.relations; q = binding['raw_quaternion_candidate']
        need(isinstance(q, dict) and set(q) == {'field','review_sha256'}, 'quaternion_binding')
        self._declaration(q['field'], 'f32x4')
        position = binding['fields']['position']
        need(q['field'] not in binding['fields'].values(), 'quaternion_alias')
        need(set(r.guard_ids[position]) <= set(r.guard_ids[q['field']]), 'quaternion_position_dependencies')
        self._artifact(q['review_sha256'], artifacts)
        review = parse(artifacts[q['review_sha256']])
        need(isinstance(review, dict) and review.get('schema') == 'overwatch-decoder.selected-raw-quaternion-review/1'
             and review.get('reviewed') is True and review.get('target') == r.target
             and review.get('profile_sha256') == r.hash and review.get('source') == self.source
             and review.get('position_declaration') == r.fields[position]
             and review.get('quaternion_declaration') == r.fields[q['field']]
             and review.get('identity_fields') == {k:binding['fields'][k] for k in self.word_roles}
             and review.get('semantics') == 'raw_owned_component_four_float_candidate', 'quaternion_review_scope')

    def _configure_empty(self,c,artifacts):
        """Admit an acquired empty collection, never infer current absence."""
        from forward_owner_relations import _verify_acquisition
        r = self.relations
        pin = c.get('empty_partition_review_sha256');self._artifact(pin,artifacts)
        review = parse(artifacts[pin]);partition = c.get('partition_id')
        need(isinstance(partition,str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,31}',partition), 'empty_partition_id')
        need(isinstance(review,dict) and review.get('schema') == 'overwatch-decoder.selected-empty-partition-review/1'
             and review.get('reviewed') is True and review.get('partition_id') == partition
             and review.get('target') == r.target and review.get('profile_sha256') == r.hash
             and review.get('source') == self.source, 'empty_review_scope')
        local_names = set(self.local['fields'].values())
        if self.empty_local_review:
            local_names = {self.local['fields'][k] for k in LOCAL_REFERENCE_WORDS}
        need(set(r.fields) == local_names, 'empty_profile_has_nonlocal_fields')
        for source_pin in self.source.values():self._artifact(source_pin,artifacts)
        manifest = parse(artifacts[self.source['manifest_sha256']]);recipe = parse(artifacts[self.source['recipe_sha256']])
        need(isinstance(manifest,dict) and isinstance(recipe,dict), 'empty_source_objects')
        need(manifest.get('schema') == 'overwatch-decoder.acquisition-result/1' and manifest.get('complete') is True
             and manifest.get('error') is None and manifest.get('target') == r.target
             and manifest.get('profile_sha256') == r.hash
             and all(manifest.get(k) == self.source[k] for k in ('recipe_sha256','evidence_sha256')), 'empty_acquisition_scope')
        need(recipe.get('schema') == 'overwatch-decoder.acquisition-recipe/1' and isinstance(recipe.get('stages'),list)
             and recipe.get('target') == {k:r.target[k] for k in ('image_name','executable_sha256','architecture')}, 'empty_recipe_scope')
        collection = review.get('collection')
        need(isinstance(collection,dict) and set(collection) == {'rows','prefix','event_sha256'}
             and all(isinstance(collection.get(k),str) and collection[k] for k in collection), 'empty_collection_review')
        definitions = [x for x in recipe.get('field_collections',[]) if isinstance(x,dict)
                       and x.get('rows') == collection['rows'] and x.get('prefix') == collection['prefix']]
        need(len(definitions) == 1 and definitions[0].get('allow_empty') is True, 'empty_recipe_collection')
        evidence = artifacts[self.source['evidence_sha256']]
        try:_verify_acquisition(evidence,manifest,recipe,r)
        except ValueError as error:raise InvalidSelectedEntity('empty_acquisition_proof:'+str(error)) from error
        matches = [parse(line) for line in evidence.splitlines(keepends=True) if sha(line) == collection['event_sha256']]
        need(len(matches) == 1, 'empty_collection_event_hash')
        event = matches[0]
        need(event.get('kind') == 'field_collection' and event.get('stage') == 'field_collection_output'
             and type(event.get('depth')) is int and event['depth'] == 1
             and type(event.get('first_field')) is int and event['first_field'] == len(r.fields)
             and event.get('rows') == collection['rows']
             and event.get('prefix') == collection['prefix'] and event.get('allow_empty') is True
             and type(event.get('retained_rows')) is int and event['retained_rows'] == 0
             and type(event.get('expanded_fields')) is int and event['expanded_fields'] == 0,
             'empty_collection_not_empty')
        self.empty_review = dict(partition_id=partition,review_sha256=pin,collection_event_sha256=collection['event_sha256'])

    def _configure_local(self, c, artifacts):
        r = self.relations
        local, rule = c.get('local_context'), c.get('category_rule')
        need(isinstance(local,dict) and isinstance(rule,dict), 'local_context_and_rule_required')
        fields = local.get('fields')
        need(isinstance(fields,dict) and set(fields) == set(WORDS) | {'flags_low','flags_high'}
             and len(set(fields.values())) == len(fields), 'local_context_fields')
        empty = local.get('acquisition_empty', False)
        need(type(empty) is bool, 'local_empty_policy')
        for role,name in fields.items():
            if empty and role not in LOCAL_REFERENCE_WORDS:
                need(name not in r.fields, 'empty_local_payload_declared')
                continue
            self._declaration(name,'i32')
            if role in WORDS: r._binding(name)
        roles = LOCAL_REFERENCE_WORDS if empty else WORDS
        dependencies = set().union(*(r.guard_ids[fields[k]] for k in roles))
        if not empty:
            need(all(dependencies <= set(r.guard_ids[n]) for role,n in fields.items() if role not in WORDS), 'local_identity_dependencies')
        else:
            self._configure_empty_local(local, artifacts)
        self._artifact(local.get('review_sha256'),artifacts)
        need(isinstance(local.get('validation_status'),str) and local['validation_status'], 'local_validation_status')
        self._artifact(rule.get('review_sha256'),artifacts)
        native = parse(artifacts[rule['review_sha256']])
        need(isinstance(native,dict) and native.get('reviewed') is True
             and native.get('build_sha256') == r.target['executable_sha256'], 'category_native_review')
        branch = native.get('ordinary_branch',{})
        bits, mask, supported = rule.get('ordered_bits'), rule.get('mode_mask'), rule.get('supported_categories')
        need(isinstance(bits,list) and 1 <= len(bits) <= 64 and len(set(bits)) == len(bits)
             and all(type(bit) is int and 0 <= bit < 64 for bit in bits), 'category_bits')
        need(type(mask) is int and 0 < mask < 2**64 and not any(mask & (1<<bit) for bit in bits), 'category_mode_mask')
        need(isinstance(supported,list) and supported and len(set(supported)) == len(supported)
             and all(type(n) is int and 0 <= n < len(bits) for n in supported), 'category_supported')
        mode_bit = branch.get('excluded_mode_bit')
        need(branch.get('ordered_category_bits') == bits and branch.get('supported_categories') == supported
             and type(mode_bit) is int and 0 <= mode_bit < 64 and mask == 1<<mode_bit,
             'category_rule_review_mismatch')
        need(set(rule.get('route_conditions',[])) == {'unlinked_both_owners','null_override_argument','controlled_player_context'},
             'category_route_conditions')
        need(isinstance(rule.get('validation_status'),str) and rule['validation_status'], 'category_validation_status')
        if any(k in rule for k in ('same_group_label','different_group_label','label_review_sha256')):
            need(rule.get('same_group_label') == 'ally' and rule.get('different_group_label') == 'enemy', 'relation_label_mapping')
            self._artifact(rule.get('label_review_sha256'),artifacts)
            review = parse(artifacts[rule['label_review_sha256']])
            need(isinstance(review,dict) and review.get('schema') == 'overwatch-decoder.selected-relation-label-review/1'
                 and review.get('reviewed') is True and review.get('target') == r.target
                 and review.get('profile_sha256') == r.hash and review.get('source') == self.source
                 and all(review.get(k) == rule[k] for k in ('same_group_label','different_group_label')), 'relation_label_review')
            sources = review.get('sources')
            need(isinstance(sources,list) and 1 <= len(sources) <= 32, 'relation_label_sources')
            for pin in sources: self._artifact(pin,artifacts)
        self.local, self.rule = copy.deepcopy(local),copy.deepcopy(rule)

    def _configure_empty_local(self, local, artifacts):
        """An acquired zero-row local collection, not continuing body absence."""
        from forward_owner_relations import _verify_acquisition
        r = self.relations
        pin = local.get('empty_review_sha256'); self._artifact(pin, artifacts)
        review = parse(artifacts[pin])
        need(isinstance(review, dict) and review.get('schema') == 'overwatch-decoder.selected-empty-local-review/1'
             and review.get('reviewed') is True and review.get('target') == r.target
             and review.get('profile_sha256') == r.hash and review.get('source') == self.source,
             'empty_local_review_scope')
        for source_pin in self.source.values(): self._artifact(source_pin, artifacts)
        manifest = parse(artifacts[self.source['manifest_sha256']])
        recipe = parse(artifacts[self.source['recipe_sha256']])
        need(isinstance(manifest, dict) and manifest.get('schema') == 'overwatch-decoder.acquisition-result/1'
             and manifest.get('complete') is True and manifest.get('error') is None
             and manifest.get('target') == r.target and manifest.get('profile_sha256') == r.hash
             and all(manifest.get(k) == self.source[k] for k in ('recipe_sha256','evidence_sha256')),
             'empty_local_acquisition_scope')
        need(isinstance(recipe, dict) and recipe.get('schema') == 'overwatch-decoder.acquisition-recipe/1'
             and isinstance(recipe.get('stages'), list)
             and recipe.get('target') == {k:r.target[k] for k in ('image_name','executable_sha256','architecture')},
             'empty_local_recipe_scope')
        collection = review.get('collection')
        need(isinstance(collection, dict) and set(collection) == {'rows','prefix','event_sha256'}
             and all(isinstance(v, str) and v for v in collection.values()), 'empty_local_collection_review')
        definitions = [x for x in recipe.get('field_collections', []) if isinstance(x, dict)
                       and x.get('rows') == collection['rows'] and x.get('prefix') == collection['prefix']]
        need(len(definitions) == 1 and definitions[0].get('allow_empty') is True, 'empty_local_recipe_collection')
        # Pin the whole omitted collection, including nested payloads, to the four
        # absent local fields. An unrelated empty collection cannot authorize it.
        def names(definition, prefix, depth=0):
            need(depth <= 8 and isinstance(definition, dict), 'empty_local_collection_depth')
            here = prefix + definition['prefix'] + '_0000_'
            result = [here + f['name'] for f in definition.get('fields', [])]
            for child in definition.get('field_collections', []): result += names(child, here, depth+1)
            return result
        try: omitted = names(definitions[0], '')
        except (KeyError, TypeError) as error: raise InvalidSelectedEntity('empty_local_collection_fields') from error
        expected = {local['fields'][k] for k in ('body_handle','body_key','flags_low','flags_high')}
        need(len(omitted) == 4 and set(omitted) == expected, 'empty_local_collection_fields')
        need(not any(name.startswith(collection['prefix']+'_') for name in r.fields), 'empty_local_payload_declared')
        evidence = artifacts[self.source['evidence_sha256']]
        try: _verify_acquisition(evidence, manifest, recipe, r)
        except ValueError as error: raise InvalidSelectedEntity('empty_local_acquisition_proof:'+str(error)) from error
        matches = [parse(line) for line in evidence.splitlines(keepends=True) if sha(line) == collection['event_sha256']]
        need(len(matches) == 1, 'empty_local_collection_event_hash')
        event = matches[0]
        need(event.get('kind') == 'field_collection' and event.get('stage') == 'field_collection_output'
             and type(event.get('depth')) is int and event['depth'] == 1
             and type(event.get('first_field')) is int and 0 <= event['first_field'] <= len(r.fields)
             and event.get('rows') == collection['rows'] and event.get('prefix') == collection['prefix']
             and event.get('allow_empty') is True
             and type(event.get('retained_rows')) is int and event['retained_rows'] == 0
             and type(event.get('expanded_fields')) is int and event['expanded_fields'] == 0
             and event.get('identity') == 'ordinal_within_acquisition_only', 'empty_local_collection_not_empty')
        self.empty_local_review = dict(acquisition_empty=True, current_body_presence='unknown',
            requires_fresh_acquisition=True, review_sha256=pin, collection_event_sha256=collection['event_sha256'])

    def _local_words(self, frame):
        r = self.relations
        roles = LOCAL_REFERENCE_WORDS if self.empty_local_review else WORDS
        words = {role:r._observed(self.local['fields'][role],frame) for role in roles}
        if words['selector']['value'] != words['controller_key']['value']:
            raise InvalidBinding('local_selector_controller_mismatch')
        if self.empty_local_review:
            # An explicitly proved empty collection can accompany equal null
            # references. It still cannot establish a body or relative identity.
            if words['ref_first']['value'] != words['ref_third']['value']:
                raise InvalidBinding('local_body_reference_mismatch')
            raise InvalidBinding('local_body_not_acquired')
        if not (words['ref_first']['value'] == words['ref_third']['value'] == words['body_key']['value']):
            raise InvalidBinding('local_body_reference_mismatch')
        return words

    def _relative(self, binding, words, local, local_error, frame):
        if local_error: raise InvalidBinding(local_error)
        if not words['body_key']['value'] or not local['body_key']['value']:
            raise InvalidBinding('zero_body_key')
        samples = []
        categories = []
        for fields in (self.local['fields'],binding['fields']):
            halves = [self._read(fields[k],frame) for k in ('flags_low','flags_high')]
            samples.extend(halves)
            flags = (halves[0]['value'] & 0xffffffff) | ((halves[1]['value'] & 0xffffffff)<<32)
            if flags & self.rule['mode_mask']: raise InvalidBinding('unsupported_category_mode')
            category = next((n for n,bit in enumerate(self.rule['ordered_bits']) if flags & (1<<bit)),None)
            if category not in self.rule['supported_categories']: raise InvalidBinding('unsupported_category')
            categories.append(category)
        same = words['body_key']['value'] == local['body_key']['value']
        label = ('self' if same else self.rule.get('same_group_label','same_group')
                 if categories[0] == categories[1] else self.rule.get('different_group_label','different_group'))
        result = self._value(label,list(local.values())+list(words.values())+samples,self.rule['validation_status'])
        result.update(review_sha256=self.rule['review_sha256'],local_context_review_sha256=self.local['review_sha256'],
                      categories=dict(local=categories[0],target=categories[1]),comparison_scope='reviewed_native_ordinary_rule',
                      label_review_sha256=self.rule.get('label_review_sha256'))
        return result

    def _pool_declaration(self, name):
        r = self.relations
        d = r.fields.get(name, {})
        need(d.get('type') == 'f32' and d.get('codec') == 'pool_sum_f32'
             and not any(k in d for k in ('path','path_id')) and bool(r.guard_ids.get(name)), 'invalid_pool_field')
        span, slots = d.get('pool_span'), d.get('pool_slots')
        need(type(span) is int and 8 <= span <= 4096 and isinstance(slots,list)
             and 1 <= len(slots) <= 256 and type(d.get('address')) is int
             and 0 < d['address'] <= 2**63-span, 'invalid_pool_layout')
        used, previous = set(), -1
        for slot in slots:
            need(isinstance(slot,dict) and set(slot) == {'membership_offset','scalar_offset'}, 'invalid_pool_slot')
            member, scalar = slot['membership_offset'], slot['scalar_offset']
            need(type(member) is int and type(scalar) is int and previous < member <= span-4
                 and 0 <= scalar <= span-4, 'invalid_pool_slot_order')
            for offset in (member,scalar):
                region = set(range(offset,offset+4))
                need(not region & used, 'overlapping_pool_operands'); used.update(region)
            previous = member
        for bound in ('min','max'):
            need(bound not in d or type(d[bound]) in (int,float) and math.isfinite(d[bound]), 'invalid_pool_bound')
        need('min' not in d or 'max' not in d or d['min'] <= d['max'], 'invalid_pool_bounds')

    def _read_pool(self, name, frame):
        r = self.relations; d = r.fields[name]; sample = frame.get('fields',{}).get(name,{})
        start, end = sample.get('read_start_ticks'), sample.get('read_end_ticks')
        if (sample.get('status') != 'observed' or sample.get('type') != 'f32' or sample.get('reason') is not None
                or sample.get('codec') != 'pool_sum_f32' or type(sample.get('pool_span')) is not int or sample.get('pool_span') != d['pool_span']
                or sample.get('pool_slots') != d['pool_slots']
                or not isinstance(sample.get('pool_slots'),list)
                or not all(isinstance(s,dict) and all(type(v) is int for v in s.values()) for s in sample['pool_slots'])
                or sample.get('read_kind') != 'operand_envelope'
                or 'path_id' not in sample or sample['path_id'] is not None
                or sample.get('read_attempted') is not True or 'read_error' not in sample or sample['read_error'] is not None
                or sample.get('read_address_hex') != f"{d['address']:016x}"
                or type(start) is not int or type(end) is not int
                or not frame['start_ticks'] <= start <= end <= frame['end_ticks']
                or sample.get('guard_ids') != r.guard_ids[name]
                or not r._guard_brackets_match(r.guard_ids[name],frame,start,end)):
            raise InvalidBinding('pool_field_unobserved_or_unguarded')
        operands = sample.get('operands')
        if not isinstance(operands,dict) or set(operands) != {'snapshot_a','snapshot_b'}:
            raise InvalidBinding('pool_operand_shape')
        buffers, reads = [], []
        previous = start
        for key in ('snapshot_a','snapshot_b'):
            operand = operands[key]
            if not isinstance(operand,dict) or set(operand) != {'attempted','address_hex','requested_bytes','returned_bytes',
                    'bytes_hex','start_ticks','end_ticks','error'}:
                raise InvalidBinding('pool_operand_shape')
            a,b = operand['start_ticks'],operand['end_ticks']
            if (operand['attempted'] is not True or operand['address_hex'] != f"{d['address']:016x}"
                    or type(operand['requested_bytes']) is not int or operand['requested_bytes'] != d['pool_span']
                    or type(operand['returned_bytes']) is not int or operand['returned_bytes'] != d['pool_span']
                    or operand['error'] is not None or type(a) is not int or type(b) is not int
                    or not previous <= a <= b <= end):
                raise InvalidBinding('pool_operand_read_or_timing')
            try:
                data = bytes.fromhex(operand['bytes_hex'])
            except (TypeError,ValueError) as error:
                raise InvalidBinding('pool_operand_bytes') from error
            if len(data) != d['pool_span']: raise InvalidBinding('pool_operand_bytes')
            buffers.append(data); previous=b
            reads.append(dict(snapshot=key,sha256=sha(data),read_start_ticks=a,read_end_ticks=b))
        if start != operands['snapshot_a']['start_ticks'] or end != operands['snapshot_b']['end_ticks']:
            raise InvalidBinding('pool_operand_envelope')
        a,b = buffers
        for slot in d['pool_slots']:
            m=slot['membership_offset']
            if a[m:m+4] != b[m:m+4]: raise InvalidBinding('pool_membership_changed')
        total=f32(0)
        for slot in d['pool_slots']:
            m,n=slot['membership_offset'],slot['scalar_offset']
            if int.from_bytes(a[m:m+4],'little'):
                scalar=struct.unpack_from('<f',a,n)[0]
                if not math.isfinite(scalar): raise InvalidBinding('nonfinite_pool_operand')
                total=f32(total+scalar)
        if total < d.get('min',-math.inf) or total > d.get('max',math.inf): raise InvalidBinding('pool_out_of_range')
        actual=sample.get('value')
        if type(actual) not in (int,float) or not math.isfinite(actual) or struct.pack('<d',actual) != struct.pack('<d',total):
            raise InvalidBinding('pool_calculated_value_mismatch')
        return dict(field=name,value=total,read_start_ticks=start,read_end_ticks=end,operand_reads=reads)

    def _artifact(self, pin, artifacts):
        need(isinstance(pin, str) and re.fullmatch('[0-9a-f]{64}', pin)
             and isinstance(artifacts.get(pin), bytes) and 0 < len(artifacts[pin]) <= 8*1024*1024
             and sha(artifacts[pin]) == pin, 'review_artifact_hash')

    def _declaration(self, name, kind):
        r = self.relations
        d = r.fields.get(name, {})
        width = {'i32':4, 'f32':4, 'f32x3':12, 'f32x4':16}[kind]
        need(d.get('type') == kind and not any(k in d for k in ('path','path_id','codec'))
             and type(d.get('address')) is int and 0 < d['address'] <= 2**63-width
             and bool(r.guard_ids.get(name)), 'unsupported_field_declaration')

    def verify_source(self, source):
        need(isinstance(source, dict) and source.get('profile_sha256') == self.relations.hash
             and isinstance(source.get('acquisition'), dict)
             and all(source['acquisition'].get(k) == self.source[k] for k in PINS), 'source_mismatch')

    def _read(self, name, frame):
        r = self.relations; kind = r.fields[name]['type']
        if kind == 'i32':
            return r.sample_scalar(name, frame, kind)
        sample = frame.get('fields', {}).get(name, {})
        a, b = sample.get('read_start_ticks'), sample.get('read_end_ticks')
        if (sample.get('status') != 'observed' or sample.get('type') != kind
                or type(a) is not int or type(b) is not int
                or not frame['start_ticks'] <= a <= b <= frame['end_ticks']
                or sample.get('guard_ids') != r.guard_ids[name]
                or not r._guard_brackets_match(r.guard_ids[name], frame, a, b)):
            raise InvalidBinding('field_unobserved_or_unguarded')
        if kind == 'f32x4':
            expected_address = f"{r.fields[name]['address']:016x}"
            if ('read_address_hex' in sample and sample['read_address_hex'] != expected_address) or sample.get('read_attempted') is False or sample.get('read_error') is not None:
                raise InvalidBinding('quaternion_read_address_or_error')
        value = sample.get('value')
        vector_size = {'f32x3':3, 'f32x4':4}.get(kind)
        values = value if vector_size and isinstance(value, list) else [value]
        if ((vector_size and len(values) != vector_size)
                or any(type(v) not in (int,float) or not math.isfinite(v) for v in values)):
            raise InvalidBinding('nonfinite_or_invalid_numeric')
        values = [f32(v) for v in values]
        return dict(field=name, value=values if vector_size else values[0], read_start_ticks=a, read_end_ticks=b)

    def _value(self, value, samples, status):
        return dict(value=value, source='process_memory', validation_status=status,
                    reads=[{k:s[k] for k in ('field','read_start_ticks','read_end_ticks')} for s in samples])

    def project(self, frame, *, gap=False):
        r = self.relations
        result = dict(schema='overwatch-decoder.selected-entity-view/1', source='process_memory',
                      profile_sha256=r.hash, contract_sha256=self.hash, build_sha256=r.target['executable_sha256'],
                      source_evidence=copy.deepcopy(self.source), timestamp={k:frame.get(k) for k in
                      ('sequence','start_ticks','end_ticks','monotonic_frequency','utc_origin','monotonic_origin_ticks')},
                      visibility='unknown', atomic=False, previous_values_carried=False, public_state_eligible=False, entities=[])
        error = r._frame_error(frame)
        skipped = frame.get('skipped_intervals_before', 0)
        if error is None:
            if type(gap) is not bool or type(skipped) is not int or skipped < 0: error = 'invalid_gap_metadata'
            elif (gap or skipped) and self.gap_policy == 'strict': error = 'gap_before_frame'
        result['gap_policy'] = self.gap_policy
        result['frame_gap'] = dict(external_gap=gap if type(gap) is bool else None,
            skipped_intervals_before=skipped if type(skipped) is int and skipped >= 0 else None,
            previous_values_carried=False,continuity_across_gaps=False)
        working = []
        with r._frame_checks(frame):
            local, local_error = None,error
            if self.mode == 'target_vs_local' and not error:
                try: local = self._local_words(frame)
                except InvalidBinding as exc: local_error = str(exc)
            for b in self.bindings:
                row = dict(binding_id=b['binding_id'], entity_id=None, controller_id=None, is_local=None,
                           hero=dict(value=None,validation_status='unknown'), health=dict(value=None,validation_status='unknown'),
                           position=dict(value=None,validation_status='unknown'), relation=dict(value=None,validation_status='unknown'),
                           visibility='unknown', reason=error)
                if 'raw_quaternion_candidate' in b:
                    row['raw_quaternion_candidate'] = dict(value=None,validation_status='unknown',reason=error)
                words = None
                try:
                    if error: raise InvalidBinding(error)
                    roles = ('controller_handle','controller_key','ref_first','ref_third') if b.get('body_absent') else self.word_roles
                    words = {role:r._observed(b['fields'][role], frame) for role in roles}
                    if b.get('body_absent'):
                        row['controller_id'] = r._key('controller',[words[k] for k in ('controller_handle','controller_key')])
                        row['controller_reference'] = self._value({k:words[k]['value'] for k in ('ref_first','ref_third')},
                            [words[k] for k in ('ref_first','ref_third')],b['validation_status'])
                        row['reason'] = 'body_not_acquired'
                        for field in ('hero','health','position','relation'):
                            row[field] = dict(value=None,validation_status='unknown',reason='body_not_acquired')
                        working.append((row,words))
                        continue
                    if not (words['ref_first']['value'] == words['ref_third']['value'] == words['body_key']['value']):
                        raise InvalidBinding('body_reference_mismatch')
                    if self.mode == 'current_context' and words['selector']['value'] != words['controller_key']['value']:
                        raise InvalidBinding('selector_controller_mismatch')
                    row['controller_id'] = r._key('controller', [words[k] for k in ('controller_handle','controller_key')])
                    row['entity_id'] = r._key('body', [words[k] for k in ('body_handle','body_key')])
                    if self.mode == 'current_context':
                        row['is_local'] = b.get('is_local')
                        row['relation'] = self._value('context_to_body', list(words.values()), b['validation_status'])
                        row['relation']['review_sha256'] = b['review_sha256']
                    else:
                        row['is_local'] = words['body_key']['value'] == local['body_key']['value'] if local else None
                        try: row['relation'] = self._relative(b,words,local,local_error,frame)
                        except InvalidBinding as exc:
                            row['relation'] = dict(value=None,validation_status='unknown',reason=str(exc))
                    if 'raw_quaternion_candidate' in b:
                        q = b['raw_quaternion_candidate']
                        try:
                            sample = self._read(q['field'], frame)
                            if not 0.99 <= sum(v*v for v in sample['value']) <= 1.01:
                                raise InvalidBinding('nonunit_quaternion_candidate')
                            row['raw_quaternion_candidate'] = self._value(sample['value'], [sample], 'raw_orientation_candidate')
                            row['raw_quaternion_candidate'].update(review_sha256=q['review_sha256'],
                                semantics='raw_owned_component_four_float_candidate',
                                observed_build_sha256=r.target['executable_sha256'],profile_sha256=r.hash,
                                contract_sha256=self.hash,source_evidence=copy.deepcopy(self.source))
                        except InvalidBinding as exc:
                            row['raw_quaternion_candidate'] = dict(value=None,validation_status='unknown',reason=str(exc))
                    for role in ('position','hero','health'):
                        try:
                            if role == 'position':
                                s = self._read(b['fields']['position'], frame)
                                row[role] = self._value(s['value'], [s], b['validation_status'])
                            elif role == 'hero':
                                ss = [self._read(b['fields'][k], frame) for k in ('hero_low','hero_high')]
                                resource = f"0x{((ss[1]['value'] & 0xffffffff)<<32) | (ss[0]['value'] & 0xffffffff):016X}"
                                mapping = self.catalog.lookup(r.target['executable_sha256'], resource, self.locale) if self.catalog else None
                                row[role] = self._value(mapping['label'] if mapping else None, ss,
                                                        mapping['validation_status'] if mapping else 'unknown')
                                row[role].update(resource_guid=resource, mapping_evidence=mapping,
                                                 reason=None if mapping else 'unmapped_build_resource_or_locale')
                            else:
                                h = b.get('health')
                                if h is None: raise InvalidBinding('health_layout_not_configured')
                                if 'sum_field' in h:
                                    sample = self._read_pool(h['sum_field'], frame)
                                    row[role] = self._value(sample['value'], [sample], h['validation_status'])
                                    row[role].update(source='calculated_process_memory',codec='pool_sum_f32',
                                                     operand_reads=sample['operand_reads'],review_sha256=h['review_sha256'])
                                    continue
                                ss = [self._read(slot['current'], frame) for slot in h['slots']]
                                total = f32(0)
                                for slot,s in zip(h['slots'], ss):
                                    if slot['membership_u32'] != 0: total = f32(total+s['value'])
                                row[role] = self._value(total, ss, h['validation_status'])
                                row[role].update(review_sha256=h['review_sha256'], accumulation='binary32_declared_slot_order')
                        except InvalidBinding as exc:
                            row[role] = dict(value=None,validation_status='unknown',reason=str(exc))
                except InvalidBinding as exc:
                    row['reason'] = str(exc)
                    if 'raw_quaternion_candidate' in row:
                        row['raw_quaternion_candidate'] = dict(value=None,validation_status='unknown',reason=str(exc))
                working.append((row, words))
        for role in ('controller_handle','body_handle'):
            counts = Counter(w[role]['value'] for row,w in working if w is not None and role in w)
            for row,w in working:
                if w is not None and role in w and counts[w[role]['value']] > 1:
                    row.update(entity_id=None,controller_id=None,is_local=None,reason='duplicate_'+role)
                    for field in ('hero','health','position','relation'):
                        row[field] = dict(value=None,validation_status='unknown',reason=row['reason'])
                    if 'raw_quaternion_candidate' in row:
                        row['raw_quaternion_candidate'] = dict(value=None,validation_status='unknown',reason=row['reason'])
                    if 'controller_reference' in row:
                        row['controller_reference'] = dict(value=None,validation_status='unknown',reason=row['reason'])
        result['entities'] = [row for row,_ in working]
        if self.empty_local_review:
            result['local_context_status'] = dict(self.empty_local_review, status='unknown', reason=local_error)
        if self.empty_review is not None:
            result['empty_partition'] = dict(self.empty_review,acquisition_empty=True,current_occupancy='unknown',
                status='context_observed' if local_error is None else 'unknown',reason=local_error)
        return result


def export_verified(recording, acquisition, output, verifier_command, raw_contract, *, artifacts=None, hero_catalog=None, allow_profile4=False, allow_stopped=False):
    """Export only a complete native-verified recording; publish after full rehash."""
    import json
    import os
    from pathlib import Path
    import tempfile
    from export_relations import (bounded_local_bytes, acquisition_provenance, native_verify, iter_validated_frames)
    recording, output = Path(recording).resolve(), Path(output).resolve()
    need(not output.exists() and not output.is_relative_to(recording)
         and not output.is_relative_to(Path(acquisition).resolve()), 'unsafe_output')
    raw = bounded_local_bytes(recording/'profile.json',262144,'profile_size')
    r = GuardedRelations(raw, allow_profile4=allow_profile4)
    source = dict(profile_sha256=r.hash, acquisition=acquisition_provenance(acquisition,r.hash,r.target))
    view = SelectedEntityView(raw,raw_contract,source=source,artifacts=artifacts,hero_catalog=hero_catalog,allow_profile4=allow_profile4)
    raw_manifest = bounded_local_bytes(recording/'manifest.json',262144,'manifest_size')
    manifest = parse(raw_manifest)
    need(manifest.get('profile_sha256') == r.hash and manifest.get('target') == r.target, 'recording_scope')
    need(type(allow_stopped) is bool, 'invalid_stopped_policy')
    verification = native_verify(recording,verifier_command,allow_stopped)
    complete = verification.get('valid') is True and verification.get('complete') is True
    stopped = (allow_stopped and verification.get('valid') is True
               and verification.get('complete') is False and verification.get('status') == 'verified_stopped'
               and verification.get('terminal_summary_verified') is True
               and verification.get('recoverable') is False and verification.get('error_code') is None
               and verification.get('unverified_compressed_bytes') == 0
               and verification.get('unverified_index_bytes') == 0)
    need(complete or stopped, 'source_not_complete_or_verified_stopped')
    need(verification.get('profile_sha256') == r.hash, 'verified_profile_mismatch')
    output.parent.mkdir(parents=True,exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile('w',encoding='utf-8',dir=output.parent,delete=False) as file:
            temporary = Path(file.name)
            for frame,gap in iter_validated_frames(recording/'samples.jsonl.gz',recording/'chunks.jsonl',
                                                  verification,manifest,r):
                result = view.project(frame,gap=bool(gap['skipped_slots']))
                result['recording_status'] = dict(status=verification.get('status'),valid=verification['valid'],
                                                  complete=verification['complete'],accepted_stopped=bool(stopped))
                result['recording_evidence'] = {k:verification[k] for k in
                    ('samples_prefix_sha256','index_prefix_sha256')}
                result['recording_evidence']['manifest_sha256'] = sha(raw_manifest)
                file.write(json.dumps(result,separators=(',',':'),allow_nan=False)+'\n')
            file.flush(); os.fsync(file.fileno())
        need(sha(bounded_local_bytes(recording/'manifest.json',262144,'manifest_size')) == sha(raw_manifest), 'recording_manifest_changed')
        os.link(temporary,output)  # Refuse overwrite, including a concurrently created output.
    finally:
        if temporary is not None: temporary.unlink(missing_ok=True)


def main():
    import argparse
    from pathlib import Path
    from export_relations import bounded_local_bytes, load_local_artifacts
    from hero_asset_labels import HeroAssetCatalog
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('recording','acquisition','output','contract','verifier'):
        parser.add_argument('--'+name,required=True)
    parser.add_argument('--artifact',action='append',default=[])
    parser.add_argument('--hero-catalog')
    parser.add_argument('--allow-profile4',action='store_true')
    parser.add_argument('--allow-stopped',action='store_true')
    args = parser.parse_args()
    artifacts = load_local_artifacts(args.artifact,'selected_entity')
    catalog = HeroAssetCatalog(bounded_local_bytes(args.hero_catalog,65536,'catalog_size'),artifacts) if args.hero_catalog else None
    export_verified(args.recording,args.acquisition,args.output,[args.verifier],
                    bounded_local_bytes(args.contract,262144,'contract_size'),artifacts=artifacts,hero_catalog=catalog,allow_profile4=args.allow_profile4,allow_stopped=args.allow_stopped)


if __name__ == '__main__': main()
