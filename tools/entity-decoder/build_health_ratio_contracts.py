"""Construct source-bound pool-ratio contracts from a fresh health bundle.

``overwatch-decoder.health-ratio-layout/1`` requires executable_sha256, recipe_sha256,
paired_field_suffix, vector_type (f32x3/f32x4), numerator_component,
denominator_component and signed denominator_offset_from_current. The suffix
replaces only ``direct_candidate`` on each occupied pool field. Addresses and
pool layout come from the current acquisition/health bundle, never this module.

The caller must freshly build the complete health bundle. Its supplied layout
is an assertion, not inferred completeness of an unknown target layout. This
constructor checks its source pins, every present reciprocal actor, occupied
pair, supplied membership and ownership dependencies. Forward-owner descriptors
are independently governed and are not promoted to reciprocal bodies. An empty
bundle is admitted only when the current profile declares no reciprocal bodies.
Generic finite construction permits x4; the live reader separately permits x3.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

from health_ratio_validation import load_ratio_contract, validate_bank_groups
from plan_live_roster import parse, read, verified_census
from relations import GuardedRelations


class InvalidHealthRatioAcquisition(ValueError):
    """The current saved acquisition cannot support the declared ratio pairs."""


def _need(ok, reason):
    if not ok:
        raise InvalidHealthRatioAcquisition(reason)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _digest(value):
    return isinstance(value, str) and re.fullmatch(r'[a-f0-9]{64}', value) is not None


def _encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def validate_layout(layout_bytes):
    """Validate configuration before any collector launches; perform no I/O."""
    _need(isinstance(layout_bytes, bytes) and 0 < len(layout_bytes) <= 65536,
          'ratio_layout_size')
    layout = parse(layout_bytes)
    keys = {'schema', 'executable_sha256', 'recipe_sha256', 'paired_field_suffix',
            'vector_type', 'numerator_component', 'denominator_component',
            'denominator_offset_from_current'}
    _need(isinstance(layout, dict) and set(layout) in (keys, keys | {'bank_groups'})
          and layout['schema'] == 'overwatch-decoder.health-ratio-layout/1', 'ratio_layout_schema')
    _need(all(_digest(layout[k]) for k in ('executable_sha256', 'recipe_sha256')),
          'ratio_layout_pin')
    suffix = layout['paired_field_suffix']
    _need(isinstance(suffix, str) and re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,63}', suffix),
          'ratio_layout_suffix')
    kind = layout['vector_type']
    width = {'f32x3': 3, 'f32x4': 4}.get(kind) if isinstance(kind, str) else None
    ni, di, offset = (layout[k] for k in ('numerator_component', 'denominator_component',
                                        'denominator_offset_from_current'))
    _need(width is not None and type(ni) is int and type(di) is int
          and 0 <= ni < width and 0 <= di < width and ni != di
          and type(offset) is int and offset == 4 * (di - ni), 'ratio_layout_components')
    if 'bank_groups' in layout:
        groups = layout['bank_groups']
        _need(isinstance(groups, list) and all(isinstance(g, dict)
              and isinstance(g.get('pool_indices'), list) for g in groups), 'ratio_layout_bank_groups')
        validate_bank_groups(groups, sum(len(g['pool_indices']) for g in groups))
    return layout


def build_contracts(acquisition, layout_bytes, native_review_bytes, health_bundle, *, recipe_path=None):
    """Return existing per-actor ratio contracts with fresh acquisition pins.

    This reads local files only and reuses the native transcript/final-guard
    verifier. No values or validation results are reused from another epoch.
    Recipe bytes may be supplied explicitly for observe-fields acquisitions.
    """
    try:
        return _build(acquisition, layout_bytes, native_review_bytes, health_bundle, recipe_path)
    except InvalidHealthRatioAcquisition:
        raise
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError) as error:
        raise InvalidHealthRatioAcquisition('ratio_construction_failed: ' + str(error)) from error


def _build(acquisition, layout_bytes, native_review_bytes, health_bundle, recipe_path):
    layout = validate_layout(layout_bytes)
    _need(isinstance(native_review_bytes, bytes) and 0 < len(native_review_bytes) <= 8*1024*1024,
          'ratio_native_review_size')
    review = parse(native_review_bytes)
    _need(isinstance(review, dict) and review.get('build_sha256') == layout['executable_sha256'],
          'ratio_native_review_build')
    if 'bank_groups' in layout:
        count = sum(len(g['pool_indices']) for g in layout['bank_groups'])
        _need(validate_bank_groups(layout['bank_groups'], count)
              == validate_bank_groups(review.get('bank_groups'), count), 'ratio_bank_groups_not_reviewed')
    # Snapshot caller data: neither validation nor returned contracts alias it.
    _need(isinstance(health_bundle, dict), 'ratio_health_bundle_required')
    health_raw = _encoded(health_bundle)
    _need(len(health_raw) <= 1024*1024, 'ratio_health_bundle_size')
    health = parse(health_raw)
    _need(health.get('schema') == 'overwatch-decoder.private.actor-health-contracts/1'
          and health.get('public_state_eligible') is False and _digest(health.get('layout_sha256')),
          'ratio_health_bundle_schema')
    verified = verified_census(acquisition, recipe_path)
    source = verified['source']
    profile_raw = read(Path(acquisition)/'profile.json', 262144)
    _need(_sha(profile_raw) == source['profile_sha256'], 'ratio_profile_changed')
    _need(verified['target']['executable_sha256'] == layout['executable_sha256']
          and source['recipe_sha256'] == layout['recipe_sha256'], 'ratio_layout_source_pin')
    for key, source_key in (('profile_sha256', 'profile_sha256'),
                            ('acquisition_manifest_sha256', 'manifest_sha256'),
                            ('acquisition_evidence_sha256', 'evidence_sha256'),
                            ('recipe_sha256', 'recipe_sha256')):
        _need(health.get(key) == source[source_key], 'ratio_health_bundle_source_pin:' + key)
    bindings = GuardedRelations(profile_raw)
    present = {}
    for controller in bindings.prefixes:
        body = controller + '_body_0000_'
        declared = [name for name in bindings.fields if name.startswith(controller + '_body_')]
        if not declared:
            continue
        _need(all(name.startswith(body) for name in declared), 'ratio_unsupported_body_prefix')
        identity = [controller+'_handle_candidate_i32', controller+'_manager_key_candidate_i32',
                    controller+'_part51_0000_body_key_candidate_i32',
                    body+'handle_candidate_i32', body+'manager_key_candidate_i32']
        words = [bindings._binding(name)[1] for name in identity]
        _need(words[2] == words[4], 'ratio_reciprocal_body_key')
        present[body] = set(i for name in identity for i in bindings.guard_ids[name])
    descriptors = health.get('contracts')
    _need(isinstance(descriptors, list) and len(descriptors) <= 128
          and all(isinstance(d, dict) for d in descriptors), 'ratio_health_contracts')
    prefixes = [d.get('actor_prefix') for d in descriptors]
    _need(all(isinstance(p, str) for p in prefixes) and len(set(prefixes)) == len(prefixes)
          and set(prefixes) == set(present), 'ratio_present_health_set_mismatch')
    if 'effective_actor_prefixes' in health:
        _need(isinstance(health['effective_actor_prefixes'], list)
              and sorted(health['effective_actor_prefixes']) == sorted(present),
              'ratio_effective_actor_set_mismatch')
    contracts = []
    for descriptor in descriptors:
        prefix = descriptor['actor_prefix']
        _need(descriptor.get('controller_prefix', prefix[:-len('_body_0000_')])
              == prefix[:-len('_body_0000_')], 'ratio_health_controller_prefix')
        _need(descriptor.get('acquisition_evidence_sha256') == source['evidence_sha256'],
              'ratio_health_descriptor_evidence')
        slots = descriptor.get('slots')
        _need(isinstance(slots, list) and slots and all(isinstance(s, dict) for s in slots),
              'ratio_health_slots')
        pairs = []
        for slot in slots:
            if slot.get('membership_u32') == 0:
                continue
            name, address = slot.get('field_name'), slot.get('scalar_address')
            _need(isinstance(name, str) and name.endswith('direct_candidate')
                  and type(address) is int, 'ratio_occupied_field')
            paired = name[:-len('direct_candidate')] + layout['paired_field_suffix']
            field = bindings.fields.get(paired, {})
            _need(field.get('type') == layout['vector_type'], 'ratio_missing_or_wrong_pair_type')
            _need(field.get('address') == address - 4*layout['numerator_component'],
                  'ratio_pair_current_address')
            _need(present[prefix] <= set(bindings.guard_ids[paired]), 'ratio_pair_ownership_guards')
            pairs.append(dict(pool_index=slot.get('index'), field_name=paired,
                numerator_component=layout['numerator_component'],
                denominator_component=layout['denominator_component'],
                denominator_address=address + layout['denominator_offset_from_current']))
        contract = dict(schema='overwatch-decoder.private.actor-health-ratio-contract/1',
            algorithm='occupied_pool_ratio_f32', profile_sha256=source['profile_sha256'],
            build_sha256=verified['target']['executable_sha256'],
            source={k: source[k] for k in ('manifest_sha256', 'recipe_sha256', 'evidence_sha256')},
            native_review_sha256=_sha(native_review_bytes), health_contract=descriptor, paired_slots=pairs)
        if 'bank_groups' in layout:
            contract['bank_groups'] = layout['bank_groups']
        load_ratio_contract(profile_raw, _encoded(contract), native_review_bytes)
        contracts.append(contract)
    return dict(schema='overwatch-decoder.private.actor-health-ratio-contracts/1',
        profile_sha256=source['profile_sha256'], acquisition_manifest_sha256=source['manifest_sha256'],
        acquisition_evidence_sha256=source['evidence_sha256'], recipe_sha256=source['recipe_sha256'],
        layout_sha256=_sha(layout_bytes), native_review_sha256=_sha(native_review_bytes),
        contracts=contracts, public_state_eligible=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--acquisition', type=Path, required=True)
    parser.add_argument('--layout', type=Path, required=True)
    parser.add_argument('--native-review', type=Path, required=True)
    parser.add_argument('--health-bundle', type=Path, required=True)
    parser.add_argument('--recipe', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = build_contracts(args.acquisition, read(args.layout, 65536),
            read(args.native_review, 8*1024*1024), parse(read(args.health_bundle, 1024*1024)),
            recipe_path=args.recipe)
        with args.out.open('xb') as stream:
            stream.write(_encoded(result))
    except (ValueError, OSError) as error:
        parser.exit(1, f'health ratio construction failed: {error}\n')
    print(json.dumps(dict(actors=len(result['contracts']), profile_sha256=result['profile_sha256'],
                         public_state_eligible=False)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
