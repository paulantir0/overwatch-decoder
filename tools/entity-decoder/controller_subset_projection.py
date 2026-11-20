"""Opt-in, same-acquisition controller subsets for private raw producers.

Names select storage declarations only. Identities always come from the complete
guarded keys in the new profile. Removed declarations never carry old values or
imply that an actor died. Context selection is independently checked by the
fresh context composer and parent admission before publication.
"""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import re

from build_health_contracts import _layout
from plan_live_roster import encoded, parse, read, verified_census
from relations import GuardedRelations


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def policy(config):
    enabled = config.get('allow_controller_subsets', False)
    need(type(enabled) is bool, 'controller_subset_boolean')
    if not enabled:
        need('controller_subset_policy' not in config, 'controller_subset_policy_without_opt_in')
        return None
    need(config.get('observation_mode') == 'raw-candidates'
         and config.get('include_health_candidates', True) is True
         and 'context_composer' in config, 'controller_subset_requires_raw_health_context')
    value = config.get('controller_subset_policy')
    need(isinstance(value, dict) and set(value) == {
        'expected_controller_keys', 'expected_primary_controller_keys',
        'required_context_controller_key'}, 'controller_subset_policy_shape')
    for name in ('expected_controller_keys', 'expected_primary_controller_keys'):
        keys = value[name]
        need(isinstance(keys, list) and 1 <= len(keys) <= 128
             and all(isinstance(k, str) and re.fullmatch('controller:[0-9a-f]{64}', k) for k in keys)
             and keys == sorted(set(keys)), 'controller_subset_policy_keys')
    context = value['required_context_controller_key']
    need(isinstance(context, str) and re.fullmatch('controller:[0-9a-f]{64}', context)
         and set(value['expected_primary_controller_keys']) <= set(value['expected_controller_keys']),
         'controller_subset_policy_scope')
    return value


def _filter_layout(layout, prefixes):
    result = copy.deepcopy(layout)
    result['actor_prefixes'] = [p for p in layout['actor_prefixes'] if p in prefixes]
    if 'actor_read_stages' in layout:
        result['actor_read_stages'] = {p: layout['actor_read_stages'][p]
                                      for p in result['actor_prefixes']}
    return result


def prepare(config, acquisition, epoch):
    """Return a new config with per-epoch templates; never alter pinned inputs."""
    declaration = policy(config)
    if declaration is None:
        return config
    acquisition, epoch = Path(acquisition), Path(epoch)
    census = verified_census(acquisition, config['recipe'], expected_target=config['target'])
    need(census['source']['recipe_sha256'] == config['recipe_sha256'], 'controller_subset_recipe_pin')
    profile_raw = read(acquisition/'profile.json', 262144)
    relations = GuardedRelations(profile_raw)
    objects = census['controllers']
    actual = {r['controller_object_key'] for r in objects}
    expected = set(declaration['expected_controller_keys'])
    need(len(actual) == len(objects) and actual <= expected
         and actual.intersection(declaration['expected_primary_controller_keys']),
         'controller_subset_fresh_identity_scope')
    effective = dict(config)
    requested_pins, effective_pins, unavailable = {}, {}, {}

    def asset(name, maximum):
        raw = read(config[name], maximum)
        pin = hashlib.sha256(raw).hexdigest()
        need(pin == config.get(name+'_sha256'), 'controller_subset_asset_changed:'+name)
        requested_pins[name] = pin
        return raw

    def materialize(name, value):
        raw = encoded(value)
        path = epoch/('controller-subset-'+name.replace('_', '-')+'.json')
        with path.open('xb') as file:
            file.write(raw)
        effective[name], effective[name+'_sha256'] = str(path), hashlib.sha256(raw).hexdigest()
        effective_pins[name] = effective[name+'_sha256']

    layout, _, _ = _layout(asset('health_layout', 65536))
    need(layout['recipe_sha256'] == config['recipe_sha256']
         and layout['executable_sha256'] == config['target']['executable_sha256'],
         'controller_subset_layout_scope')
    suffix = '_body_0000_'
    original = [p[:-len(suffix)] for p in layout['actor_prefixes'] if p.endswith(suffix)]
    need(len(original) == len(layout['actor_prefixes']) == len(expected)
         and len(set(original)) == len(original)
         and all(re.fullmatch(r'controller_[0-9]{4}', p) for p in original),
         'controller_subset_declared_prefixes')
    need(set(relations.prefixes) <= set(original), 'controller_subset_profile_prefixes')
    declared_prefixes = {match.group(1) for name in relations.fields
                         if (match := re.match(r'(controller_[0-9]{4})_', name))}
    need(declared_prefixes <= set(original), 'controller_subset_profile_prefixes')
    for prefix in original:
        names = [prefix+s for s in ('_handle_candidate_i32', '_manager_key_candidate_i32',
                                   '_part51_0000_body_key_candidate_i32')]
        present = [name in relations.fields for name in names]
        need(all(present) or not any(present), 'controller_subset_partial_identity_fields')
        if not any(present):
            need(not any(n.startswith(prefix+'_') for n in relations.fields),
                 'controller_subset_orphaned_fields')
    bindings = []
    for prefix in relations.prefixes:
        words = [dict(zip(('address', 'value'), relations._binding(prefix+s)))
                 for s in ('_handle_candidate_i32', '_manager_key_candidate_i32')]
        bindings.append(dict(prefix=prefix, controller_object_key=relations._key('controller', words)))
    need({b['controller_object_key'] for b in bindings} == actual,
         'controller_subset_prefix_identity_mismatch')
    present_prefixes = set(relations.prefixes)
    materialize('health_layout', _filter_layout(layout, {p+suffix for p in present_prefixes}))

    if 'forward_owner_bindings' in config:
        template = parse(asset('forward_owner_bindings', 262144))
        need(template.get('schema') == 'overwatch-decoder.forward-owner-binding-template/1'
             and template.get('build_sha256') == config['target']['executable_sha256']
             and template.get('recipe_sha256') == config['recipe_sha256']
             and 'reference_groups' not in template, 'controller_subset_forward_template_scope')
        rows = template.get('bindings')
        need(isinstance(rows, list) and 1 <= len(rows) <= 32
             and all(isinstance(b, dict) for b in rows), 'controller_subset_forward_bindings')
        kept, ids, owner_prefixes = [], set(), set()
        for row in rows:
            handle = row.get('controller_handle_field')
            need(isinstance(handle, str) and handle.endswith('_handle_candidate_i32'),
                 'controller_subset_forward_handle')
            prefix = handle.removesuffix('_handle_candidate_i32')
            owner = row.get('owned_field_prefix')
            bid = row.get('binding_id')
            need(prefix in original and row.get('controller_key_field') == prefix+'_manager_key_candidate_i32'
                 and row.get('reference_field') == prefix+'_part51_0000_body_key_candidate_i32'
                 and isinstance(owner, str) and owner.startswith(prefix+'_')
                 and isinstance(bid, str) and bid not in ids and owner not in owner_prefixes,
                 'controller_subset_forward_binding_scope')
            ids.add(bid); owner_prefixes.add(owner)
            if prefix in present_prefixes:
                kept.append(row)
        need(kept, 'controller_subset_no_forward_bindings')
        materialize('forward_owner_bindings', dict(template, bindings=kept))
        kept_ids = {b['binding_id'] for b in kept}
        kept_owners = {b['owned_field_prefix'] for b in kept}
        if 'forward_owner_health_layout' in config:
            forward_layout, _, _ = _layout(asset('forward_owner_health_layout', 65536))
            supported = forward_layout.get('supported_forward_owners')
            need(forward_layout['executable_sha256'] == template['build_sha256']
                 and forward_layout['recipe_sha256'] == template['recipe_sha256']
                 and set(forward_layout['actor_prefixes']) == owner_prefixes
                 and isinstance(supported, list) and len(supported) == len(rows)
                 and all(isinstance(d, dict) and set(d) == {'binding_id', 'owner_prefix'} for d in supported)
                 and {(d['binding_id'], d['owner_prefix']) for d in supported}
                     == {(b['binding_id'], b['owned_field_prefix']) for b in rows},
                 'controller_subset_forward_health_scope')
            filtered = _filter_layout(forward_layout, kept_owners)
            filtered['supported_forward_owners'] = [d for d in supported if d['binding_id'] in kept_ids]
            materialize('forward_owner_health_layout', filtered)
        if 'forward_owner_category_template' in config:
            from runtime_producer import validate_forward_category_template
            category = parse(asset('forward_owner_category_template', 262144))
            validate_forward_category_template(category, template)
            category_bindings = [b for b in category['bindings'] if b['binding_id'] in kept_ids]
            if category_bindings:
                materialize('forward_owner_category_template', dict(category, bindings=category_bindings))
            else:
                # An optional enrichment with no surviving owner does not make
                # another actor's independently guarded health/position invalid.
                # No empty category contract is produced; raw values stay unknown.
                unavailable['forward_owner_category'] = dict(reason='no_binding_in_acquired_controller_subset',
                    omitted_binding_ids=[b['binding_id'] for b in category['bindings']])
                for name in ('forward_owner_category_template', 'forward_owner_category_artifacts'):
                    effective.pop(name, None); effective.pop(name+'_sha256', None)

    receipt = dict(schema='overwatch-decoder.controller-subset-projection/1', target=census['target'],
        source_acquisition=census['source'], policy=copy.deepcopy(declaration),
        profile_bindings=bindings, omitted_controller_keys=sorted(expected-actual),
        requested_asset_sha256=requested_pins, effective_asset_sha256=effective_pins,
        unavailable_optional_projections=unavailable,
        basis='same_acquisition_guarded_full_keys', context_requires_independent_admission=True,
        previous_contracts_carried=False, public_state_eligible=False)
    with (epoch/'controller-subset-projection.json').open('xb') as file:
        file.write(encoded(receipt))
    return effective
