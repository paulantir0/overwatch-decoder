"""Stateless validation of private enriched native forward-owner projections.

This checks accepted semantic evidence, not native process memory or artifact
contents. Retain the original hashed frames and acquisition/contract/catalog
sources. Forward owners never establish a current displayed body.
"""
import math
import re
import copy
import unicodedata


class InvalidForwardOwnerFrame(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise InvalidForwardOwnerFrame(reason)


def integer(value): return type(value) is int

def finite(value): return type(value) in (int, float) and math.isfinite(value)


def digest(value):
    need(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'invalid_digest')
    return value


def text(value, maximum=1024):
    need(isinstance(value, str) and 0 < len(value.encode()) <= maximum, 'invalid_candidate_text')


def object_key(value, role):
    need(value is None or isinstance(value, str) and re.fullmatch(role+':[0-9a-f]{64}', value), 'invalid_object_key')


def span(fields, timing):
    need(isinstance(fields, list) and fields and len(fields) <= 256, 'missing_read_evidence')
    starts, ends = [], []
    for field in fields:
        need(isinstance(field, dict), 'invalid_read_evidence')
        a, b = field.get('read_start_ticks'), field.get('read_end_ticks')
        need(integer(a) and integer(b) and timing['start_ticks'] <= a <= b <= timing['end_ticks'], 'read_outside_source_frame')
        starts.append(a); ends.append(b)
    return [min(starts), max(ends)]


def validate_acquisition_empty_evidence(proof, source=None):
    """Check the source-bound zero-expansion claim, never a physical absence."""
    need(isinstance(proof,dict)and proof.get('schema')=='overwatch-decoder.forward-owner-acquisition-empty/1', 'forward_empty_evidence')
    collection,event=proof.get('collection'),proof.get('collection_event')
    need(isinstance(collection,dict)and set(collection)=={'recipe_pointer','rows','prefix','depth'}
         and isinstance(collection['recipe_pointer'],str)and re.fullmatch(r'(?:/field_collections/[0-9]+){1,4}',collection['recipe_pointer'])
         and type(collection['depth'])is int and collection['depth']==collection['recipe_pointer'].count('/field_collections/')
         and isinstance(collection['rows'],str)and re.fullmatch('[A-Za-z][A-Za-z0-9_]*',collection['rows'])
         and isinstance(collection['prefix'],str)and re.fullmatch('[A-Za-z][A-Za-z0-9_]{0,62}',collection['prefix']), 'forward_empty_collection')
    need(isinstance(event,dict)and event.get('kind')=='field_collection'and event.get('stage')=='field_collection_output'
         and all(event.get(k)==collection[k]for k in ('rows','prefix','depth'))and type(event.get('depth'))is int and event.get('allow_empty')is True
         and type(event.get('retained_rows'))is int and event['retained_rows']==0
         and type(event.get('expanded_fields'))is int and event['expanded_fields']==0
         and type(event.get('first_field'))is int and 0<=event['first_field']<=128
         and event.get('identity')=='ordinal_within_acquisition_only', 'forward_empty_trace')
    pins=proof.get('source_evidence')
    need(isinstance(pins,dict)and set(pins)=={'recipe_sha256','evidence_sha256','acquisition_manifest_sha256'},'forward_empty_source')
    for pin in pins.values():digest(pin)
    need(source is None or pins==source,'forward_empty_source')
    return collection


CATEGORY_METADATA_KEYS = ('forward_category_output_enabled', 'forward_category_contract_sha256',
                          'forward_category_native_review_sha256')
CATEGORY_ROW_KEYS = ('raw_flags_candidate', 'raw_category_candidate', 'raw_category_evidence', 'raw_category_reason')


def _guard_id_sets():
    """Reuse checked contents only within one frame validation call.

    Keys are fresh immutable snapshots, never list identities. The fast type
    comparison also excludes bool/float values that compare equal to integers.
    A bounded cache holds only validated built-in integer lists; other inputs
    retain the ordinary validation and rejection path.
    """
    checked = {}
    def validate(value, reason, *, category=False):
        key = None
        if type(value) is list and 0 < len(value) <= 256:
            snapshot = tuple(value)
            if tuple(map(type, snapshot)) == (int,) * len(snapshot):
                key = snapshot
                known = checked.get(key)
                if known is not None:
                    return known
        if category:
            need(isinstance(value, list) and 0 < len(value) <= 256 and len(set(value)) == len(value)
                 and all(integer(i) and 0 <= i < 256 for i in value), reason)
        else:
            need(isinstance(value, list) and 0 < len(value) <= 256
                 and all(integer(i) and 0 <= i < 256 for i in value) and len(set(value)) == len(value), reason)
        result = frozenset(value)
        if key is not None and len(checked) < 256:
            checked[key] = result
        return result
    return validate


def _category_metadata(node):
    if not any(key in node for key in CATEGORY_METADATA_KEYS):
        return {}
    need(node.get('forward_category_output_enabled') is True
         and all(key in node for key in CATEGORY_METADATA_KEYS), 'forward_category_configuration')
    for key in CATEGORY_METADATA_KEYS[1:]: digest(node.get(key))
    return {key:node[key] for key in CATEGORY_METADATA_KEYS}


def _category_candidate(row, node, frame, source, timing, base, declarations, checked_guard_ids):
    configured = node.get('forward_category_output_enabled') is True
    if not configured:
        need(not any(key in row for key in CATEGORY_ROW_KEYS), 'forward_category_unconfigured_row')
        return None
    need(all(key in row for key in CATEGORY_ROW_KEYS), 'forward_category_partial_row')
    flags, category, evidence, reason = (row[key] for key in CATEGORY_ROW_KEYS)
    need(reason is None or isinstance(reason,str) and 0<len(reason)<=1024, 'forward_category_reason')
    result=dict(status='unknown',raw_status='unknown',value=None,reason=reason,read_span_ticks=None,evidence_ref=None,
                current_displayed_body=None,validation_scope='reviewed_unlinked_zero_override_branch')
    if reason is not None: result['reason_ref']=base+'/raw_category_reason'
    if flags is None:
        need(category is None and evidence is None and reason is not None, 'forward_category_unknown_has_values')
        return result
    need(row.get('relation_status')=='observed' and not frame['gap_before']['skipped_slots']
         and isinstance(flags,dict) and set(flags)=={'low_u32','high_u32','assembled_u64_hex','selected_category_indices'}
         and isinstance(evidence,dict), 'forward_category_without_current_owner')
    need(evidence.get('contract_sha256')==node['forward_category_contract_sha256']
         and evidence.get('forward_contract_sha256')==node['contract_sha256']
         and evidence.get('native_review_sha256')==node['forward_category_native_review_sha256']
         and evidence.get('profile_sha256')==frame['profile_sha256']
         and evidence.get('build_sha256')==frame['target']['executable_sha256']
         and evidence.get('source')==source and evidence.get('frame_timing')==timing
         and evidence.get('forward_identity_fields')==row.get('identity_evidence')
         and evidence.get('current_displayed_body')is None and evidence.get('public_state_eligible')is False
         and evidence.get('visibility')=='unknown', 'forward_category_source_mismatch')
    identities=row['identity_evidence']
    need(isinstance(identities,list)and len(identities)==5,'forward_category_identity')
    fields=evidence.get('fields');reads=span(fields,timing)
    need(len(fields)==4 and len({f.get('field')for f in fields})==4
         and all(isinstance(f.get('field'),str)and 0<len(f['field'])<=128 for f in fields), 'forward_category_fields')
    if declarations is not None:
        need(all(declarations.get(f['field'])=='i32'for f in fields),'forward_category_declaration')
    for index,field in enumerate(fields):
        number=field.get('value')
        need(integer(number)and(0<=number<=0xffffffff if index<2 else -(1<<31)<=number<(1<<31)),
             'forward_category_field_value')
    need([f['value']for f in fields[:2]]==[w['value']for w in identities[3:]], 'forward_category_owner_identity')
    def ids(value):
        return checked_guard_ids(value, 'forward_category_guard_ids', category=True)
    dependency=set().union(*(ids(w.get('guard_ids'))for w in identities))
    field_ids=[ids(field.get('guard_ids'))for field in fields]
    for index,field in enumerate(fields):
        sample=row.get('owned_fields',{}).get(field['field'])
        if sample is not None:
            value=sample.get('value') if isinstance(sample,dict) else None
            need(isinstance(sample,dict)and sample.get('status')=='observed'and sample.get('type')=='i32'
                 and integer(value)and (value&0xffffffff if index<2 else value)==field['value']
                 and all(sample.get(k)==field.get(k)for k in ('read_start_ticks','read_end_ticks','guard_ids')),
                 'forward_category_owned_sample_mismatch')
    need(all(dependency<=available for available in field_ids[2:]), 'forward_category_missing_identity_guards')
    low,high=(fields[i]['value']&0xffffffff for i in (2,3))
    selected=flags.get('selected_category_indices')
    need(flags.get('low_u32')==low and type(flags.get('low_u32'))is int
         and flags.get('high_u32')==high and type(flags.get('high_u32'))is int
         and flags.get('assembled_u64_hex')==f'0x{high:08x}{low:08x}'
         and isinstance(selected,list)and all(integer(n)for n in selected), 'forward_category_raw_flags')
    algorithm=evidence.get('algorithm')
    need(isinstance(algorithm,dict),'forward_category_algorithm')
    ordered,clear,supported=(algorithm.get(k)for k in ('ordered_bits','clear_bits','supported_categories'))
    for bits in (ordered,clear):
        need(isinstance(bits,list)and 1<=len(bits)<=32 and all(integer(bit)and 0<=bit<32 for bit in bits)
             and len(set(bits))==len(bits),'forward_category_mask_bits')
    need(not set(ordered)&set(clear)and isinstance(supported,list)and 1<=len(supported)<=len(ordered)
         and all(integer(n)and 0<=n<len(ordered)for n in supported)and len(set(supported))==len(supported),
         'forward_category_supported_indices')
    expected=[index for index,bit in enumerate(ordered)if low&(1<<bit)]
    need(selected==expected,'forward_category_selected_mask_mismatch')
    conditions=evidence.get('conditions')
    need(isinstance(conditions,list)and len(conditions)==2 and all(isinstance(c,dict)for c in conditions)
         and {c.get('role')for c in conditions}=={'unlinked_owner','zero_override'}, 'forward_category_conditions')
    for condition in conditions:
        width,mask,equals,guarded=(condition.get(k)for k in ('width','mask','equals','guarded_value'))
        need(integer(width)and 1<=width<=8 and integer(mask)and 0<mask<(1<<(8*width))
             and type(equals)is int and equals==0 and integer(guarded)and 0<=guarded<(1<<(8*width))
             and guarded&mask==equals,'forward_category_condition_value')
        if condition['role']=='zero_override':
            need(width in (4,8)and mask==(1<<(8*width))-1,'forward_category_override_mask')
        needed=ids(condition.get('guard_ids'))
        need(all(needed<=available for available in field_ids[2:]),'forward_category_condition_guards')
    error=('unsupported_mode_bits' if any(low&(1<<bit)for bit in clear)
           else 'absent_or_ambiguous_category' if len(expected)!=1
           else 'unsupported_category' if expected[0]not in supported else None)
    need(category is None if error else integer(category)and category==expected[0], 'forward_category_value_mismatch')
    need(reason==error,'forward_category_reason_mismatch')
    result.update(status='candidate'if error is None else'unknown',raw_status='observed',
        value=dict(raw_flags_candidate=flags,raw_category_candidate=category),read_span_ticks=reads,evidence_ref=base+'/raw_category_evidence')
    return result


def validate_forward_owner_frame(frame, declarations=None, controllers=None):
    """Project source-bound forward references without making body actors.

    Native guards, contracts and typed assets remain in the hashed original
    source. This validates accepted semantic claims and their same-frame
    dependency consistency; it does not re-read or attest those artifacts.
    """
    need(isinstance(frame, dict), 'forward_frame_object')
    checked_guard_ids = _guard_id_sets()
    if declarations is not None:
        need(isinstance(declarations, dict) and len(declarations) <= 160
             and all(isinstance(name, str) and isinstance(kind, str) for name, kind in declarations.items()),
             'forward_field_declarations')
    if controllers is not None:
        need(isinstance(controllers, (set, frozenset)) and len(controllers) <= 128, 'forward_controller_scope')
        for controller in controllers:
            object_key(controller, 'controller'); need(controller is not None, 'forward_controller_scope')
    node = frame.get('forward_owner_projection')
    if node is None:
        return None
    need(isinstance(node, dict) and node.get('schema') == 'overwatch-decoder.guarded-forward-owner-relations/1'
         and node.get('profile_sha256') == frame['profile_sha256'] and node.get('target') == frame['target']
         and node.get('source') == 'process_memory' and node.get('source_artifacts') == frame['source_artifacts'],
         'forward_projection_source_mismatch')
    for key in ('contract_sha256', 'binding_template_sha256'): digest(node.get(key))
    timing = {k: frame['timing'][k] for k in ('sequence', 'start_ticks', 'end_ticks', 'monotonic_frequency')}
    need(node.get('timing') == timing and node.get('association_kind') == 'native_forward_reference'
         and node.get('atomic') is False and node.get('continuity_across_gaps') is False
         and node.get('previous_values_carried') is False and node.get('public_state_eligible') is False
         and node.get('visibility') == 'unknown' and node.get('durability_verified') is False,
         'forward_projection_scope_mismatch')
    acquisition = frame['source_artifacts']['acquisition']
    source = dict(recipe_sha256=acquisition['recipe_sha256'], evidence_sha256=acquisition['evidence_sha256'],
                  acquisition_manifest_sha256=acquisition['manifest_sha256'])
    need(node.get('source_evidence') == source, 'forward_projection_acquisition_mismatch')
    category_metadata=_category_metadata(node)
    enabled = node.get('controller_hero_output_enabled')
    need(type(enabled) is bool, 'forward_controller_hero_option')
    catalog = node.get('controller_hero_asset_catalog_sha256')
    if enabled: digest(catalog)
    else: need(catalog is None, 'forward_unconfigured_hero_catalog')
    rows = node.get('relations')
    need(isinstance(rows, list) and 1 <= len(rows) <= 32 and all(isinstance(row, dict) for row in rows),
         'forward_relation_bound')
    from forward_owner_relations import reference_group_membership
    groups=node.get('reference_groups')
    need('reference_groups' not in node or groups is not None,'reference_group_count')
    membership=reference_group_membership(groups,[r.get('binding_id') for r in rows])
    ids, prefixes, output = set(), [], []
    for index, row in enumerate(rows):
        ident, prefix = row.get('binding_id'), row.get('owned_field_prefix')
        need(isinstance(ident, str) and re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,63}', ident)
             and ident not in ids and isinstance(prefix, str)
             and re.fullmatch('[A-Za-z][A-Za-z0-9_]{0,62}_', prefix)
             and all(not prefix.startswith(other) and not other.startswith(prefix) for other in prefixes),
             'forward_duplicate_binding_or_prefix')
        ids.add(ident); prefixes.append(prefix)
        controller, owner = row.get('controller_object_key'), row.get('forward_owner_object_key')
        object_key(controller, 'controller'); object_key(owner, 'owner')
        need(controller is None or controllers is None or controller in controllers, 'forward_controller_not_configured')
        status, reason = row.get('relation_status'), row.get('reason')
        need(status in ('observed', 'unknown') and (reason is None or isinstance(reason, str) and 0 < len(reason) <= 1024)
             and 'current_displayed_body' in row and row['current_displayed_body'] is None
             and row.get('body_object_key') is None, 'forward_invalid_relation')
        base = '/forward_owner_projection/relations/'+str(index)
        result = dict(binding_id=ident, owned_field_prefix=prefix, controller_object_key=controller,
            forward_owner_object_key=owner, relation_status=status, reason=reason, current_displayed_body=None,
            association_kind='native_forward_reference', source_ref=base, identity_evidence_ref=base+'/identity_evidence',
            identity_read_span_ticks=None, owned_fields={}, position_candidate=None, health_candidate=None,
            controller_hero_asset_label_candidate=None)
        def candidate(value, evidence_key, reads, why=None, validation='candidate'):
            answer = dict(status=validation if value is not None else 'unknown', value=value, reason=why,
                read_span_ticks=reads, evidence_ref=base+'/'+evidence_key if value is not None else None,
                current_displayed_body=None)
            return answer
        hero_reason = row.get('controller_hero_asset_label_reason')
        need(hero_reason is None or isinstance(hero_reason, str) and 0 < len(hero_reason) <= 1024,
             'forward_invalid_hero_reason')
        result['position_candidate'] = candidate(None, 'position_candidate', None, reason)
        result['health_candidate'] = candidate(None, 'health_candidate', None, reason)
        result['controller_hero_asset_label_candidate'] = candidate(None, 'controller_hero_asset_label_evidence', None,
                                                                   hero_reason, 'typed_asset_resource_match')
        result['controller_hero_asset_label_candidate'].update(binding_scope='controller_only', runtime_ui_validated=False)
        category_result=_category_candidate(row,node,frame,source,timing,base,declarations,checked_guard_ids)
        if category_result is not None:result['category_candidate']=category_result
        if status == 'unknown':
            empty=row.get('acquisition_empty_evidence')
            identities=row.get('identity_evidence')
            if empty is not None:
                collection=validate_acquisition_empty_evidence(empty,source)
                need(prefix==collection['prefix']+'_0000_'and owner is None,'forward_empty_owner_scope')
                result['acquisition_empty_evidence_ref']=base+'/acquisition_empty_evidence'
                if reason=='acquisition_empty':
                    need(controller is not None and not frame['gap_before']['skipped_slots']
                         and isinstance(identities,list)and len(identities)==3 and all(isinstance(w,dict)for w in identities)
                         and all(isinstance(w.get('field'),str)and integer(w.get('value'))and 0<=w['value']<=0xffffffff for w in identities)
                         and len({w['field']for w in identities})==3,
                         'forward_empty_current_identity')
                    for word in identities:
                        checked_guard_ids(word.get('guard_ids'), 'forward_empty_identity_guards')
                    if declarations is not None:need(all(declarations.get(w['field'])=='i32'for w in identities),'forward_empty_identity_declaration')
                    result['identity_read_span_ticks']=span(identities,timing)
                else:need(identities==[],'forward_empty_unchecked_identity')
            else:need(reason!='acquisition_empty'and identities==[],'forward_empty_missing_evidence')
            need(reason is not None and row.get('owned_fields') == {}
                 and all(row.get(k) is None for k in ('position_candidate', 'health_candidate',
                     'controller_hero_asset_label_candidate', 'controller_hero_asset_label_evidence')),
                 'forward_unknown_carried_values')
            output.append(result); continue
        need(row.get('acquisition_empty_evidence')is None,'forward_empty_cannot_be_observed')
        need(controller is not None and owner is not None and reason is None
             and not frame['gap_before']['skipped_slots'], 'forward_observed_without_current_binding')
        identities = row.get('identity_evidence')
        need(isinstance(identities, list) and len(identities) == 5 and all(isinstance(w, dict) for w in identities),
             'forward_identity_evidence')
        result['identity_read_span_ticks'] = span(identities, timing)
        if declarations is not None:
            need(all(declarations.get(word.get('field')) == 'i32' for word in identities), 'forward_identity_declaration')
        names = [w.get('field') for w in identities]
        need(all(isinstance(name, str) and 0 < len(name) <= 128 for name in names)
             and len(set(names)) == 5 and all(name.startswith(prefix) for name in names[3:])
             and all(integer(w.get('value')) and 0 <= w['value'] <= 0xffffffff for w in identities)
             and identities[2]['value'] == identities[4]['value'], 'forward_identity_reference_mismatch')
        def guard_ids(value):
            return checked_guard_ids(value, 'forward_invalid_guard_ids')
        required = set().union(*(guard_ids(w.get('guard_ids')) for w in identities))
        fields = row.get('owned_fields')
        need(isinstance(fields, dict) and 1 <= len(fields) <= 160, 'forward_owned_fields_bound')
        for name, field in fields.items():
            need(isinstance(name, str) and name.startswith(prefix) and re.fullmatch('[A-Za-z][A-Za-z0-9_.-]{0,127}', name)
                 and isinstance(field, dict) and field.get('status') in ('observed', 'unknown')
                 and field.get('type') in ('i32', 'u8', 'f32', 'f32x3'), 'forward_invalid_owned_field')
            if declarations is not None:
                need(declarations.get(name) == field['type'], 'forward_owned_declaration')
            value, field_reason = field.get('value'), field.get('reason')
            need(field_reason is None or isinstance(field_reason, str) and 0 < len(field_reason) <= 1024,
                 'forward_invalid_owned_reason')
            read_span = None
            if field['status'] == 'observed':
                kind = field['type']
                valid = (integer(value) and -(1 << 31) <= value < (1 << 31) if kind == 'i32'
                         else integer(value) and 0 <= value < 256 if kind == 'u8'
                         else isinstance(value, list) and len(value) == 3 and all(finite(v) for v in value) if kind == 'f32x3'
                         else finite(value))
                need(valid and field_reason is None and required <= guard_ids(field.get('guard_ids')),
                     'forward_owned_value_or_guards')
                read_span = span([field], timing)
            else: need(value is None and field_reason is not None, 'forward_unknown_owned_value')
            result['owned_fields'][name] = dict(status=field['status'], type=field['type'], value=value,
                reason=field_reason, read_span_ticks=read_span, source_ref=base+'/owned_fields/'+name)
        for word in identities[3:]:
            field = fields.get(word['field'], {})
            need(field.get('status') == 'observed' and field.get('type') == 'i32'
                 and field['value'] & 0xffffffff == word['value']
                 and all(field.get(k) == word.get(k) for k in ('read_start_ticks', 'read_end_ticks', 'guard_ids')),
                 'forward_owner_identity_sample_mismatch')
        position = row.get('position_candidate')
        if position is not None:
            name = prefix+'position_candidate'; sample = fields.get(name, {})
            need(isinstance(position, dict) and position.get('field') == name
                 and position.get('source') == 'process_memory' and position.get('type') == 'f32x3'
                 and position.get('status') == 'observed' and position.get('profile_sha256') == frame['profile_sha256']
                 and position.get('build_sha256') == frame['target']['executable_sha256']
                 and position.get('forward_owner_object_key') == owner
                 and position.get('validation_status') == 'guarded_forward_owned_field_research'
                 and position.get('current_displayed_body') is None and position.get('public_state_eligible') is False
                 and position.get('visibility') == 'unknown' and sample.get('status') == 'observed'
                 and all(position.get(k) == sample.get(k) for k in ('value', 'read_start_ticks', 'read_end_ticks', 'guard_ids')),
                 'forward_position_binding_mismatch')
            result['position_candidate'] = candidate(position['value'], 'position_candidate', span([position], timing),
                                                     validation='guarded_forward_owned_field_research')
        health = row.get('health_candidate')
        if health is not None:
            need(isinstance(health, dict) and health.get('schema') == 'overwatch-decoder.forward-owner-pool-sum/1'
                 and health.get('status') == 'candidate' and health.get('source') == 'process_memory'
                 and health.get('forward_owner_object_key') == owner and health.get('controller_object_key') == controller
                 and health.get('owned_field_prefix') == prefix and health.get('binding_id') == ident
                 and health.get('profile_sha256') == frame['profile_sha256']
                 and health.get('build_sha256') == frame['target']['executable_sha256']
                 and health.get('acquisition_evidence_sha256') == acquisition['evidence_sha256']
                 and health.get('source_evidence') == source and health.get('forward_contract_sha256') == node['contract_sha256']
                 and health.get('identity_evidence') == identities and health.get('current_displayed_body') is None
                 and health.get('association_kind') == 'native_forward_reference' and health.get('privacy') == 'private'
                 and health.get('atomic') is False and health.get('public_state_eligible') is False
                 and health.get('visibility') == 'unknown' and health.get('continuity_across_gaps') is False
                 and health.get('complete_supplied_membership_guarding') is True
                 and integer(health.get('supplied_layout_slots')) and health['supplied_layout_slots'] == 48
                 and health.get('maximum_health') is None and health.get('pool_roles') is None,
                 'forward_health_binding_mismatch')
            digest(health.get('membership_contract_sha256'))
            parts = health.get('contributions'); reads = span(parts, timing)
            need(len(parts) <= health['supplied_layout_slots'] and health.get('occupied_pool_count') == len(parts)
                 and len({part.get('pool_index') for part in parts}) == len(parts)
                 and all(integer(part.get('pool_index')) and 0 <= part['pool_index'] < health['supplied_layout_slots']
                         and finite(part.get('value')) and part['value'] >= 0 for part in parts), 'forward_health_pools')
            for part in parts:
                sample = fields.get(part.get('field'), {})
                need(sample.get('status') == 'observed' and sample.get('type') == 'f32'
                     and all(part.get(k) == sample.get(k) for k in ('value', 'read_start_ticks', 'read_end_ticks')),
                     'forward_health_owned_sample_mismatch')
            need(finite(health.get('raw_sum')) and health['raw_sum'] == math.fsum(part['value'] for part in parts)
                 and integer(health.get('display_ceiling_candidate'))
                 and health['display_ceiling_candidate'] == math.ceil(health['raw_sum'])
                 and span([health], timing) == reads, 'forward_health_sum_or_span')
            result['health_candidate'] = candidate({k:health[k] for k in ('raw_sum', 'display_ceiling_candidate')},
                                                  'health_candidate', reads)
        label, hero = row.get('controller_hero_asset_label_candidate'), row.get('controller_hero_asset_label_evidence')
        if label is None:
            need(hero is None, 'forward_unknown_hero_evidence')
        else:
            text(label, 512)
            need(len(label) <= 128 and not any(unicodedata.category(c).startswith('C') for c in label),
                 'forward_invalid_controller_hero_label')
            need(enabled and hero_reason is None and isinstance(hero, dict)
                 and hero.get('controller_object_key') == controller and hero.get('binding_scope') == 'controller_only'
                 and hero.get('catalog_sha256') == catalog and hero.get('profile_sha256') == frame['profile_sha256']
                 and hero.get('build_sha256') == frame['target']['executable_sha256'] and hero.get('frame_timing') == timing
                 and hero.get('source_artifacts') == frame['source_artifacts'] and hero.get('runtime_ui_validated') is False
                 and hero.get('current_displayed_body') is None and hero.get('public_state_eligible') is False
                 and hero.get('visibility') == 'unknown' and hero.get('body_object_key') is None,
                 'forward_controller_hero_binding_mismatch')
            words = hero.get('fields'); reads = span(words, timing)
            need(len(words) == 2 and all(isinstance(w.get('field'), str) and 0 < len(w['field']) <= 128
                 and integer(w.get('value')) and -(1 << 31) <= w['value'] < (1 << 31) for w in words)
                 and words[0]['field'] != words[1]['field'], 'forward_controller_hero_words')
            controller_prefix = names[0].removesuffix('_handle_candidate_i32')
            need(names[:2] == [controller_prefix+'_handle_candidate_i32', controller_prefix+'_manager_key_candidate_i32']
                 and [word['field'] for word in words] == [controller_prefix+'_part83_0000_hero_resource_low_candidate_i32',
                     controller_prefix+'_part83_0000_hero_resource_high_candidate_i32'], 'forward_controller_hero_fields')
            if declarations is not None:
                need(all(declarations.get(word['field']) == 'i32' for word in words), 'forward_hero_declaration')
            guid = f"0x{((words[0]['value'] & 0xffffffff) | ((words[1]['value'] & 0xffffffff) << 32)):016X}"
            mapping = hero.get('mapping', {})
            stored_type = (int(guid, 16) >> 48) & 0xfff
            need(int(f'{stored_type:012b}'[::-1], 2)+1 == 0x075 and isinstance(mapping, dict)
                 and mapping.get('label') == label and mapping.get('resource_guid') == guid
                 and mapping.get('build_sha256') == frame['target']['executable_sha256']
                 and mapping.get('mapping_scope') == 'caller_build_scoped_typed_asset'
                 and mapping.get('validation_status') == 'typed_asset_resource_match'
                 and mapping.get('runtime_ui_validated') is False and mapping.get('public_state_eligible') is False
                 and isinstance(mapping.get('locale'), str) and re.fullmatch('[a-z]{2}[A-Z]{2}', mapping['locale']),
                 'forward_controller_hero_mapping')
            for key in ('asset_report_sha256', 'asset_decoded_sha256'): digest(mapping.get(key))
            result['controller_hero_asset_label_candidate'] = candidate(label, 'controller_hero_asset_label_evidence', reads,
                                                                      validation='typed_asset_resource_match')
            result['controller_hero_asset_label_candidate'].update(binding_scope='controller_only', runtime_ui_validated=False,
                resource_guid=guid, mapping_ref=base+'/controller_hero_asset_label_evidence/mapping')
        output.append(result)
    for group in groups or []:
        members=[r for r in rows if r['binding_id'] in group['binding_ids']]
        need(all(r.get('acquisition_empty_evidence')is None for r in members),'forward_reference_group_empty_member')
        controllers_seen={r['controller_object_key'] for r in members if r['controller_object_key'] is not None}
        need(len(controllers_seen)<=1,'forward_reference_group_controller')
        checked=[r for r in members if r['relation_status']=='observed']
        if checked:
            first=checked[0]['identity_evidence']
            need(all([w['value'] for w in r['identity_evidence'][:2]]==[w['value'] for w in first[:2]] for r in checked),
                 'forward_reference_group_controller_words')
            need(len({r['identity_evidence'][2]['field'] for r in checked})==len(checked),
                 'forward_reference_group_reference_fields')
    observed=[r for r in rows if r['relation_status']=='observed']
    for i,a in enumerate(observed):
        for b in observed[i+1:]:
            group=membership.get(a['binding_id'])
            grouped=group is not None and group==membership.get(b['binding_id'])
            need(a['controller_object_key']!=b['controller_object_key'] or grouped,'forward_duplicate_controller')
            need(a['forward_owner_object_key']!=b['forward_owner_object_key'] or grouped,'forward_duplicate_owner')
            if grouped:
                aw,bw=a['identity_evidence'],b['identity_evidence']
                collision=any(aw[j]['value']==bw[j]['value'] for j in (3,4))
                exact=(a['forward_owner_object_key']==b['forward_owner_object_key']
                       and all(aw[j]['value']==bw[j]['value'] for j in (3,4)))
                need(not collision or exact,'forward_reference_group_partial_owner')
    metadata = {k:node[k] for k in ('schema', 'contract_sha256', 'binding_template_sha256', 'profile_sha256',
                                   'timing', 'source_evidence', 'association_kind')}
    metadata.update(source_ref='/forward_owner_projection', source_artifacts_ref='/forward_owner_projection/source_artifacts',
                    current_displayed_body=None, controller_hero_output_enabled=enabled)
    if enabled: metadata['controller_hero_asset_catalog_sha256'] = catalog
    metadata.update(category_metadata)
    if groups is not None:metadata['reference_groups']=copy.deepcopy(groups)
    return metadata, output

