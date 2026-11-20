"""Validate source-admitted paired pool ratios; never reinterpret them as HUD health.

This checks already projected semantic claims against caller-pinned finite source
metadata. Retain the original profile, contracts, native review and native reads;
this downstream check does not execute or re-verify native acquisition guards.
"""
import hashlib
import importlib
import importlib.util
import json
import math
import re
import sys
from pathlib import Path


class InvalidHealthRatio(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise InvalidHealthRatio(reason)


def digest(value):
    need(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'ratio_invalid_digest')


def integer(value):
    return type(value) is int


def bracket(value, timing):
    a, b = value.get('read_start_ticks'), value.get('read_end_ticks')
    need(integer(a) and integer(b) and timing['start_ticks'] <= a <= b <= timing['end_ticks'],
         'ratio_read_bracket')
    return a, b


def _ratio_module():
    """Load only this checkout/bundle's arithmetic, even if overwatch_decoder is pre-imported.

    A path-scoped package namespace avoids changing the caller's cached overwatch_decoder
    package or accidentally using an older installed distribution. Import is
    lazy: ratio-disabled aggregation has no overwatch_decoder dependency. This caches Python
    code only, never acquisition/operand validation or a projected value.
    """
    package = Path(__file__).resolve().parents[2]/'overwatch_decoder'
    need(all((package/name).is_file() for name in ('__init__.py', 'health_ratio.py', 'health_projection.py')),
         'ratio_pinned_package_missing')
    namespace = '_overwatch_decoder_ratio_projection_' + hashlib.sha256(str(package).encode()).hexdigest()
    if namespace not in sys.modules:
        spec = importlib.util.spec_from_file_location(namespace, package/'__init__.py',
            submodule_search_locations=[str(package)])
        module = importlib.util.module_from_spec(spec)
        sys.modules[namespace] = module
        spec.loader.exec_module(module)
    module = sys.modules[namespace]
    need(getattr(module, '__file__', None) == str(package/'__init__.py')
         and list(getattr(module, '__path__', [])) == [str(package)], 'ratio_package_origin_mismatch')
    arithmetic = importlib.import_module(namespace+'.health_ratio')
    storage = sys.modules[namespace+'.health_projection']
    need(getattr(arithmetic, '__file__', None) == str(package/'health_ratio.py')
         and getattr(storage, '__file__', None) == str(package/'health_projection.py'), 'ratio_module_origin_mismatch')
    return arithmetic


def calculate_ratio(operands):
    return _ratio_module().calculate_ratio(operands)


def validate_bank_groups(groups, slot_count):
    return _ratio_module().validate_bank_groups(groups, slot_count)


def load_ratio_contract(profile_bytes, contract_bytes, native_review_bytes):
    """Use the same pinned code for construction and downstream arithmetic."""
    return _ratio_module().PoolRatioContract.from_profile(profile_bytes, contract_bytes, native_review_bytes)


def validate_projection(projection, acquisition=None):
    """Validate explicit admission metadata, including the immutable review pins."""
    if projection is None:
        return
    need(isinstance(projection, dict) and projection.get('schema') == 'overwatch-decoder.health-ratio-projection/1',
         'ratio_projection_schema')
    contracts = projection.get('contracts')
    need(isinstance(contracts, list) and 1 <= len(contracts) <= 128, 'ratio_contract_count')
    prefixes, hashes = set(), set()
    for item in contracts:
        need(isinstance(item, dict), 'ratio_contract_metadata')
        for key in ('contract_sha256', 'native_review_sha256', 'membership_contract_sha256'):
            digest(item.get(key))
        prefix = item.get('actor_prefix')
        need(isinstance(prefix, str) and re.fullmatch(r'controller_\d{4}_body_0000_', prefix)
             and prefix not in prefixes and item['contract_sha256'] not in hashes, 'ratio_duplicate_or_invalid_actor')
        prefixes.add(prefix); hashes.add(item['contract_sha256'])
        source = item.get('source')
        need(isinstance(source, dict) and set(source) == {'manifest_sha256', 'recipe_sha256', 'evidence_sha256'},
             'ratio_acquisition_metadata')
        for value in source.values():
            digest(value)
        need(acquisition is None or all(acquisition.get(key) == pin for key, pin in source.items()), 'ratio_acquisition_mismatch')
        count = item.get('supplied_layout_slots')
        pairs = item.get('paired_slots')
        need(integer(count) and 1 <= count <= 128 and isinstance(pairs, list) and 1 <= len(pairs) <= count,
             'ratio_pair_count')
        indices, names = [], set()
        for pair in pairs:
            need(isinstance(pair, dict), 'ratio_pair_metadata')
            index, name, width = pair.get('pool_index'), pair.get('field_name'), pair.get('width')
            n, d = pair.get('numerator_component'), pair.get('denominator_component')
            need(integer(index) and 0 <= index < count and isinstance(name, str) and name.startswith(prefix)
                 and len(name) <= 256 and name not in names
                 and isinstance(pair.get('type'), str)
                 and integer(width) and width == {'f32x3': 3, 'f32x4': 4}.get(pair['type'])
                 and integer(n) and integer(d) and 0 <= n < width and 0 <= d < width and n != d,
                 'ratio_pair_metadata')
            indices.append(index); names.add(name)
        need(indices == sorted(set(indices)), 'ratio_pair_order')
        if 'bank_groups' in item:
            validate_bank_groups(item['bank_groups'], count)


def validate_candidate(row, frame, projection):
    """Return a current candidate, or None. Unknown/gap rows cannot carry one."""
    present = 'health_ratio_candidate' in row
    need(projection is not None or not present, 'ratio_not_admitted')
    if projection is None:
        return None
    need(present, 'ratio_enabled_row_missing')
    value = row['health_ratio_candidate']
    if value is None:
        return None
    need(isinstance(value, dict) and row.get('relation_status') == 'observed'
         and isinstance(row.get('body_object_key'), str)
         and not frame.get('gap_before', {}).get('skipped_slots'), 'ratio_without_current_body')
    need(isinstance(row.get('controller_prefix'), str), 'ratio_controller_prefix_missing')
    items = [item for item in projection['contracts']
             if item['actor_prefix'] == row.get('controller_prefix', '') + '_body_0000_']
    need(len(items) == 1, 'ratio_actor_not_admitted')
    item = items[0]
    for key in ('contract_sha256', 'native_review_sha256', 'membership_contract_sha256'):
        need(value.get(key) == item[key], 'ratio_' + key + '_mismatch')
    need(value.get('schema') == 'overwatch-decoder.actor-pool-ratio/1' and value.get('status') == 'candidate'
         and value.get('source') == 'process_memory'
         and value.get('validation_status') == 'static_derived_sampled_operands'
         and value.get('observation_scope') == 'current_frame_paired_reads'
         and value.get('body_object_key') == row['body_object_key']
         and value.get('profile_sha256') == frame['profile_sha256']
         and value.get('build_sha256') == frame['target']['executable_sha256']
         and all(frame['source_artifacts']['acquisition'].get(key) == pin for key, pin in item['source'].items())
         and value.get('acquisition_evidence_sha256') == item['source']['evidence_sha256'], 'ratio_source_or_body_mismatch')
    need(all(value.get(k) is False for k in ('atomic', 'continuity_across_gaps', 'public_state_eligible',
              'native_float_control_state_observed', 'native_execution_observed'))
         and value.get('visibility') == 'unknown'
         and value.get('complete_supplied_membership_guarding') is True
         and value.get('arithmetic_assumption') == 'binary32_round_to_nearest_even'
         and all(k in value and value[k] is None for k in ('maximum_health', 'hud_ratio', 'pool_roles')),
         'ratio_unsupported_semantics')
    operands, specs = value.get('operands'), item['paired_slots']
    need(isinstance(operands, list) and len(operands) == len(specs)
         and type(value.get('occupied_pool_count')) is int and value['occupied_pool_count'] == len(specs)
         and type(value.get('supplied_layout_slots')) is int
         and value['supplied_layout_slots'] == item['supplied_layout_slots'], 'ratio_incomplete_pairs')
    spans = []
    for operand, spec in zip(operands, specs):
        need(isinstance(operand, dict) and type(operand.get('pool_index')) is int
             and all(operand.get(k) == spec[k] for k in ('pool_index', 'numerator_component', 'denominator_component'))
             and all(type(operand.get(k)) is int for k in ('numerator_component', 'denominator_component'))
             and operand.get('field') == spec['field_name'], 'ratio_pair_binding_mismatch')
        spans.append(bracket(operand, frame['timing']))
    expected = calculate_ratio(operands)
    for key, number in zip(('numerator_sum', 'native_denominator_sum', 'native_ratio_candidate'), expected):
        actual = value.get(key)
        need(type(actual) in (int, float) and math.isfinite(actual) and actual == number, 'ratio_arithmetic_mismatch')
    need(bracket(value, frame['timing']) == (min(s[0] for s in spans), max(s[1] for s in spans)),
         'ratio_read_span_mismatch')
    if 'bank_groups' in item:
        groups = validate_bank_groups(item['bank_groups'], item['supplied_layout_slots'])
        banks = _ratio_module().calculate_bank_candidates(operands, groups)
        need(json.dumps(value.get('bank_candidates'), sort_keys=True, allow_nan=False)
             == json.dumps(banks, sort_keys=True, allow_nan=False), 'ratio_bank_arithmetic_or_evidence_mismatch')
    else:
        need('bank_candidates' not in value, 'ratio_banks_not_admitted')
    return value


def compact_candidate(row, frame, projection, base):
    value = validate_candidate(row, frame, projection)
    if projection is None:
        return None
    # The original evidence pointer retains paired operands, immutable pins and
    # exact read brackets. Numerical sums here are not maximum-health semantics.
    return dict(status='unknown' if value is None else 'static_derived_sampled_operands',
        value=None if value is None else {
            **{key: value[key] for key in ('numerator_sum', 'native_denominator_sum', 'native_ratio_candidate',
                                          'maximum_health', 'hud_ratio', 'pool_roles')},
            **({'bank_candidates': value['bank_candidates']} if 'bank_candidates' in value else {})},
        reason='ratio_unavailable_in_current_frame' if value is None else None,
        read_span_ticks=None if value is None else [value['read_start_ticks'], value['read_end_ticks']],
        evidence_ref=None if value is None else base + '/health_ratio_candidate')
