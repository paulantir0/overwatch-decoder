"""Finite Windows-local native transport; caller supplies reviewed private inputs.

This runs only the explicitly pinned observer executable. It has no game controls,
process discovery, recipe offsets or roster inference. A SHA-pinned caller composer
implements the existing CLI interface and writes reviewed epoch artifacts.
"""
from pathlib import Path
import argparse
import ctypes
import hashlib
import json
import re
import queue
import subprocess
import sys
import threading
import time
# Embeddable Python ignores script/cwd search paths: bootstrap this bundle only.
_RUNTIME_DIRECTORY = Path(__file__).resolve().parent
_BUNDLE_ROOT = _RUNTIME_DIRECTORY.parents[1]
sys.path[:0] = [str(_RUNTIME_DIRECTORY), str(_BUNDLE_ROOT)]
from aggregate_partitions import parse
from forward_owner_relations import acquisition_validation_scope
MAX_LINE = 512 * 1024
MAX_METADATA = 256 * 1024
MAX_BYTES = 512 * 1024 * 1024

def need(ok, reason):
    if not ok:
        raise ValueError(reason)

def digest(path):
    with Path(path).open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()

def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False) + '\n', encoding='utf-8')

def qpc():
    need(sys.platform == 'win32', 'windows_live_clock_required')
    tick = ctypes.c_longlong()
    need(bool(ctypes.windll.kernel32.QueryPerformanceCounter(ctypes.byref(tick))), 'qpc_failed')
    return tick.value

def validate_line(raw, total):
    need(isinstance(raw, bytes) and 0 < len(raw) <= MAX_LINE and raw.endswith(b'\n'), 'native_line_bound')
    need(type(total) is int and len(raw) <= total <= MAX_BYTES, 'native_total_byte_bound')

_NATIVE_CONTROL_EVENTS = frozenset((
    'session_start', 'acquisition_start', 'acquisition_end', 'segment_start',
    'segment_end', 'gap', 'session_end', 'session_finalization_error'))


def _write_native_event(output, raw, event):
    """Persist original control bytes before an epoch factory can block.

    Frame flushing remains at the existing successful projection boundary.
    This is buffered-file visibility, not fsync or durability attestation.
    """
    output.write(raw)
    if isinstance(event, dict) and event.get('kind') in _NATIVE_CONTROL_EVENTS:
        output.flush()


def _producer_stage(name, segment, frequency, operation):
    """Two small flushed log records per bounded epoch initialization stage."""
    def report(phase):
        print(json.dumps(dict(producer_stage=name, phase=phase, segment=segment,
                              qpc=qpc(), monotonic_frequency=frequency),
                         separators=(',', ':')), flush=True)
    report('start')
    try:
        result = operation()
    except Exception:
        report('failed')
        raise
    report('complete')
    return result


def asset_keys(config):
    """Explicit modes; a partial enrichment bundle never silently enables it."""
    if 'allow_controller_subsets' in config or 'controller_subset_policy' in config:
        from controller_subset_projection import policy
        policy(config)
    mode = config.get('observation_mode', 'reviewed')
    need(mode in ('reviewed', 'raw-candidates'), 'invalid_observation_mode')
    need(type(config.get('include_cached_labels', mode == 'reviewed')) is bool,
         'invalid_cached_label_option')
    health = config.get('include_health_candidates', True)
    need(type(health) is bool, 'invalid_health_candidate_option')
    need(health or mode == 'raw-candidates', 'disabled_health_requires_raw_mode')
    if not health:
        need(not any(key in config for key in ('health_layout', 'health_layout_sha256',
                                               'forward_owner_health_layout',
                                               'forward_owner_health_layout_sha256')),
             'disabled_health_has_layout_inputs')
    base = ['native_exe', 'recipe'] + (['health_layout'] if health else [])
    ratio = ('health_ratio_layout', 'health_ratio_layout_sha256',
             'health_ratio_native_review', 'health_ratio_native_review_sha256')
    ratio_present = [key in config for key in ratio]
    need(not any(ratio_present) or all(ratio_present),
         'complete_health_ratio_inputs_required')
    if all(ratio_present):
        need(health, 'health_ratio_requires_health_candidates')
        need('health_layout_sha256' in config, 'health_ratio_requires_health_layout_pin')
        base += ['health_ratio_layout', 'health_ratio_native_review']
    ammunition = ('ammunition_composer', 'ammunition_composer_sha256',
                  'ammunition_inputs', 'ammunition_inputs_sha256')
    ammunition_present = [key in config for key in ammunition]
    need(not any(ammunition_present) or all(ammunition_present),
         'complete_ammunition_projection_inputs_required')
    if all(ammunition_present):
        base += ['ammunition_composer', 'ammunition_inputs']
    asset_hero = ('hero_asset_catalog', 'hero_asset_artifacts')
    asset_hero_present = [key in config for key in asset_hero]
    need(not any(asset_hero_present) or all(asset_hero_present),
         'hero_asset_catalog_and_artifacts_required_together')
    if 'hero_asset_locale' in config:
        need(all(asset_hero_present), 'hero_asset_locale_requires_catalog')
        locale = config['hero_asset_locale']
        need(isinstance(locale, str) and re.fullmatch(r'[a-z]{2}[A-Z]{2}', locale) is not None,
             'invalid_hero_asset_locale')
    if all(asset_hero_present):
        base += list(asset_hero)
    if 'forward_owner_bindings' in config:
        base.append('forward_owner_bindings')
    if 'forward_owner_health_layout' in config:
        need('forward_owner_bindings' in config, 'forward_health_requires_bindings')
        base.append('forward_owner_health_layout')
    category_inputs = ('forward_owner_category_template', 'forward_owner_category_artifacts')
    need(all(k in config for k in category_inputs) or not any(k in config for k in category_inputs),
         'forward_category_template_and_artifacts_required_together')
    if all(k in config for k in category_inputs):
        need('forward_owner_bindings' in config, 'forward_category_requires_bindings')
        base += list(category_inputs)
    category = ['composer', 'native_review', 'roster_review', 'category_artifacts']
    context = ('context_composer', 'context_composer_sha256', 'context_inputs', 'context_inputs_sha256')
    context_present = [key in config for key in context]
    need(not any(context_present) or all(context_present), 'complete_context_projection_inputs_required')
    if mode == 'reviewed':
        need(not any(context_present), 'context_projection_requires_raw_mode')
        return base + category + ['hero_catalog', 'hero_artifacts']
    need(not any(key in config for key in category + ['composer_sha256', 'reviewed_mode_sources']),
         'raw_mode_category_review_not_supported')
    hero = [key in config for key in ('hero_catalog', 'hero_artifacts')]
    need(hero[0] == hero[1], 'hero_catalog_and_artifacts_required_together')
    return (base + (['hero_catalog', 'hero_artifacts'] if all(hero) else [])
            + (['context_composer', 'context_inputs'] if all(context_present) else []))


def validate_config(config, base):
    c = dict(config)
    keys = asset_keys(c)
    raw_mode = c.get('observation_mode') == 'raw-candidates'
    need(type(c.get('seconds')) is int and 10 <= c['seconds'] <= 180 and (type(c.get('interval_ms')) is int) and (20 <= c['interval_ms'] <= 1000), 'finite_producer_bounds')
    need(c.get('private_controlled_fixture_reviewed') is True and c.get('public_state_eligible') is False, 'explicit_private_fixture_review_required')
    need(isinstance(c.get('target'), dict) and isinstance(c.get('native_revision'), str), 'target_revision_required')
    for key in keys + ['output']:
        need(isinstance(c.get(key), str) and c[key], 'explicit_path_required:' + key)
        path = Path(c[key])
        c[key] = str((base / path).resolve() if not path.is_absolute() else path.resolve())
    sources = c.get('reviewed_mode_sources', [])
    need(isinstance(sources, list) and (not raw_mode and 1 <= len(sources) <= 32 or raw_mode and not sources), 'reviewed_mode_sources_required')
    if not raw_mode:
        c['reviewed_mode_sources'] = [str((base / Path(p)).resolve()) for p in sources]
    limits = dict(native_exe=512*1024*1024, recipe=1024*1024, composer=4*1024*1024,
                  health_layout=1024*1024, native_review=16*1024*1024, roster_review=16*1024*1024,
                  category_artifacts=1024*1024, hero_catalog=65536, hero_artifacts=262144,
                  hero_asset_catalog=65536, hero_asset_artifacts=262144,
                  forward_owner_bindings=262144, forward_owner_health_layout=1048576,
                  forward_owner_category_template=262144, forward_owner_category_artifacts=262144,
                  context_composer=4*1024*1024, context_inputs=1024*1024,
                  ammunition_composer=4*1024*1024, ammunition_inputs=1024*1024,
                  health_ratio_layout=65536, health_ratio_native_review=8*1024*1024)
    for key in keys:
        need(Path(c[key]).is_file() and Path(c[key]).stat().st_size <= limits[key], 'producer_asset_size:'+key)
    need(all(Path(path).is_file() and Path(path).stat().st_size <= 16*1024*1024
             for path in c.get('reviewed_mode_sources', [])), 'mode_source_size')
    need(sum(Path(path).stat().st_size for path in c.get('reviewed_mode_sources', [])) <= 64*1024*1024,
         'mode_sources_total_size')
    pins = [('native_exe', 'native_sha256'), ('recipe', 'recipe_sha256')]
    if not raw_mode:
        pins.append(('composer', 'composer_sha256'))
    elif c.get('include_health_candidates', True):
        pins.append(('health_layout', 'health_layout_sha256'))
    if 'context_composer' in c:
        pins += [('context_composer', 'context_composer_sha256'), ('context_inputs', 'context_inputs_sha256')]
    if 'ammunition_composer' in c:
        pins += [('ammunition_composer', 'ammunition_composer_sha256'),
                 ('ammunition_inputs', 'ammunition_inputs_sha256')]
    if 'health_ratio_layout' in c:
        pins += [('health_ratio_layout', 'health_ratio_layout_sha256'),
                 ('health_ratio_native_review', 'health_ratio_native_review_sha256')]
        if not raw_mode:
            pins.append(('health_layout', 'health_layout_sha256'))
    for key in ('forward_owner_bindings', 'forward_owner_health_layout',
                'forward_owner_category_template', 'forward_owner_category_artifacts'):
        if key in c:
            pins.append((key, key + '_sha256'))
    for path, pin in pins:
        need(digest(c[path]) == c.get(pin), 'pinned_file_mismatch:' + path)
    if 'health_ratio_layout' in c:
        # Fail before any native child starts; profiles still receive a separate
        # exact-acquisition check when their fresh contracts are constructed.
        health_ratio_inputs(c)
    if raw_mode and 'hero_catalog' in c:
        # Reject invalid supplied configuration before launching the native child.
        from export_relations import bounded_local_bytes, load_local_artifacts
        from hero_labels import HeroLabelCatalog
        HeroLabelCatalog(bounded_local_bytes(c['hero_catalog'], 65536, 'hero_catalog_size'),
                         load_local_artifacts(c['hero_artifacts'], 'hero'))
    if 'hero_asset_catalog' in c:
        from export_relations import bounded_local_bytes, load_local_artifacts
        from hero_asset_labels import HeroAssetCatalog
        HeroAssetCatalog(bounded_local_bytes(c['hero_asset_catalog'], 65536, 'hero_asset_catalog_size'),
                         load_local_artifacts(c['hero_asset_artifacts'], 'hero_asset'))
    if 'forward_owner_bindings' in c:
        template = parse(Path(c['forward_owner_bindings']).read_bytes())
        need(template.get('schema') == 'overwatch-decoder.forward-owner-binding-template/1'
             and template.get('build_sha256') == c['target'].get('executable_sha256')
             and template.get('recipe_sha256') == c['recipe_sha256'], 'forward_template_scope')
        if 'forward_owner_category_template' in c:
            category_template = parse(Path(c['forward_owner_category_template']).read_bytes())
            validate_forward_category_template(category_template, template)
            from export_relations import load_local_artifacts
            category_artifacts = load_local_artifacts(c['forward_owner_category_artifacts'], 'forward_category')
            review = parse(category_artifacts.get(category_template['native_review_sha256'], b'{}'))
            need(review.get('schema') == 'overwatch-decoder.native-category-review/1'
                 and review.get('reviewed') is True and review.get('review_method') == 'native_consumer_trace'
                 and review.get('build_sha256') == template['build_sha256'], 'forward_category_native_review')
        if 'forward_owner_health_layout' in c:
            layout = parse(Path(c['forward_owner_health_layout']).read_bytes())
            need(layout.get('schema') == 'overwatch-decoder.health-layout/1'
                 and layout.get('executable_sha256') == template['build_sha256']
                 and layout.get('recipe_sha256') == template['recipe_sha256'], 'forward_health_layout_scope')
            declarations = layout.get('supported_forward_owners')
            bindings = {(b.get('binding_id'), b.get('owned_field_prefix')) for b in template.get('bindings', [])}
            need(isinstance(declarations, list) and 1 <= len(declarations) <= 32
                 and all(isinstance(d, dict) and set(d) == {'binding_id', 'owner_prefix'}
                         and (d['binding_id'], d['owner_prefix']) in bindings for d in declarations),
                 'forward_health_layout_requires_epoch_neutral_bindings')
    return c


def adapter_options(config, descriptors):
    """Per-epoch options; absent/unknown enrichment cannot become a raw gate."""
    raw_mode = config.get('observation_mode') == 'raw-candidates'
    options = dict(health_contracts=descriptors, recipe_path=config['recipe'],
        cached_label_recipe_sha256=config['recipe_sha256'] if config.get('include_cached_labels', not raw_mode) else None,
        hero_catalog=config.get('hero_catalog'), hero_artifacts=config.get('hero_artifacts'))
    if 'hero_asset_catalog' in config:
        options.update(hero_asset_catalog=config['hero_asset_catalog'],
                       hero_asset_artifacts=config['hero_asset_artifacts'],
                       hero_asset_locale=config.get('hero_asset_locale', 'enUS'))
    return options


def validate_forward_category_template(template, forward_template):
    """Epoch-neutral locators only; no inherited profile/key/condition address."""
    need(isinstance(template, dict) and set(template) == {
        'schema', 'build_sha256', 'recipe_sha256', 'native_review_sha256', 'bindings'}
        and template['schema'] == 'overwatch-decoder.forward-owner-category-template/1'
        and all(template[k] == forward_template[k] for k in ('build_sha256', 'recipe_sha256')),
        'forward_category_template_scope')
    need(isinstance(template['native_review_sha256'], str)
         and re.fullmatch('[0-9a-f]{64}', template['native_review_sha256']) is not None,
         'forward_category_native_review_pin')
    bindings = template['bindings']; forward_ids = {b['binding_id'] for b in forward_template['bindings']}
    need(isinstance(bindings, list) and 1 <= len(bindings) <= 32, 'forward_category_binding_count')
    seen = set()
    for b in bindings:
        need(isinstance(b, dict) and set(b) == {'binding_id','owner_handle_field','owner_key_field',
             'flags_low_field','flags_high_field','conditions'}, 'forward_category_template_binding')
        need(isinstance(b['binding_id'], str) and b['binding_id'] in forward_ids
             and b['binding_id'] not in seen, 'forward_category_binding_id')
        seen.add(b['binding_id'])
        need(all(isinstance(b[k], str) and 1 <= len(b[k]) <= 128 for k in
                 ('owner_handle_field','owner_key_field','flags_low_field','flags_high_field')),
             'forward_category_field_names')
        conditions = b['conditions']
        need(isinstance(conditions, list) and len(conditions) == 2
             and all(isinstance(q, dict) for q in conditions)
             and {q.get('role') for q in conditions} == {'unlinked_owner','zero_override'},
             'forward_category_conditions')
        for q in conditions:
            common = {'role','width','mask','equals'}
            need(set(q) in (common|{'field_relative'},common|{'source_read'})
                 and type(q['width']) is int and 1 <= q['width'] <= 8
                 and type(q['mask']) is int and 0 < q['mask'] < 1 << (8*q['width'])
                 and type(q['equals']) is int and q['equals'] == 0, 'forward_category_condition_template')
            if 'field_relative' in q:
                d = q['field_relative']
                need(isinstance(d, dict) and set(d) == {'field','offset'}
                     and isinstance(d['field'], str) and 1 <= len(d['field']) <= 128
                     and type(d['offset']) is int and abs(d['offset']) <= 1048576,
                     'forward_category_field_locator')
            else:
                d = q['source_read']
                need(isinstance(d, dict) and set(d) == {'stage','requested_bytes','ordinal','expected_matches'}
                     and isinstance(d['stage'], str) and 1 <= len(d['stage']) <= 128
                     and type(d['requested_bytes']) is int and d['requested_bytes'] == q['width']
                     and type(d['ordinal']) is int and type(d['expected_matches']) is int
                     and 0 <= d['ordinal'] < d['expected_matches'] <= 256,
                     'forward_category_source_locator')


def forward_category_adapter_options(config, acquisition, epoch, raw_forward, artifacts, artifact_paths):
    """Materialize condition addresses/IDs from this verified acquisition only."""
    if 'forward_owner_category_template' not in config:
        return {}
    from export_relations import load_local_artifacts, bounded_local_bytes
    from forward_owner_categories import GuardedForwardOwnerCategories
    from relations import GuardedRelations
    template_path = Path(config['forward_owner_category_template'])
    paths_path = Path(config['forward_owner_category_artifacts'])
    for key, path in [('forward_owner_category_template', template_path),
                      ('forward_owner_category_artifacts', paths_path)]:
        need(digest(path) == config[key+'_sha256'], 'forward_category_input_changed')
    template = parse(bounded_local_bytes(template_path, 262144, 'forward_category_template_size'))
    fc = parse(raw_forward)
    validate_forward_category_template(template, dict(build_sha256=fc['build_sha256'],
        recipe_sha256=fc['source']['recipe_sha256'], bindings=fc['bindings']))
    supplied = load_local_artifacts(paths_path, 'forward_category')
    combined = dict(artifacts, **supplied)
    paths = parse(paths_path.read_bytes())
    combined_paths = dict(artifact_paths)
    for pin, path in paths.items():
        path = Path(path)
        combined_paths[pin] = str((paths_path.parent/path).resolve() if not path.is_absolute() else path.resolve())
    profile = bounded_local_bytes(Path(acquisition)/'profile.json', 262144, 'forward_category_profile_size')
    r = GuardedRelations(profile)
    events = [parse(line) for line in artifacts[fc['source']['evidence_sha256']].splitlines()]
    from forward_owner_relations import GuardedForwardOwners
    checked_forward=GuardedForwardOwners(profile,raw_forward,artifacts)
    empty_ids={b['binding_id']for b in checked_forward.bindings if 'acquisition_empty_evidence'in b}
    skipped=[]
    bindings = []
    for source in template['bindings']:
        if source['binding_id']in empty_ids:
            skipped.append(source['binding_id']);continue
        b = {k:v for k,v in source.items() if k != 'conditions'}
        b['conditions'] = []; ids = set()
        for q in source['conditions']:
            if 'field_relative' in q:
                d = q['field_relative']; declaration = r.fields.get(d['field'], {})
                need(type(declaration.get('address')) is int, 'forward_category_locator_field')
                address = declaration['address'] + d['offset']
            else:
                d = q['source_read']
                matches = [e for e in events if e.get('kind') == 'read' and e.get('purpose') == 'recipe'
                           and e.get('stage') == d['stage'] and e.get('requested_bytes') == d['requested_bytes']]
                need(len(matches) == d['expected_matches'], 'forward_category_source_read_shape')
                event = matches[d['ordinal']]
                need(event.get('attempted') is True and event.get('error') is None
                     and event.get('returned_bytes') == q['width'], 'forward_category_source_read_failed')
                address = event.get('address')
            need(type(address) is int and 0 < address < 2**63-8, 'forward_category_condition_address')
            values = {}
            for i, guard in enumerate(r.guards):
                data = bytes.fromhex(guard['bytes_hex']); start = guard['address']
                for pos in range(max(address,start), min(address+q['width'],start+len(data))):
                    value = data[pos-start]
                    need(pos not in values or values[pos] == value, 'forward_category_condition_conflict')
                    values[pos] = value; ids.add(i)
            need(len(values) == q['width'], 'forward_category_condition_not_guarded')
            b['conditions'].append(dict(role=q['role'], address=address, width=q['width'],
                                        mask=q['mask'], equals=q['equals']))
        b['required_guard_ids'] = sorted(ids); bindings.append(b)
    contract = dict(schema='overwatch-decoder.forward-owner-category-contract/1',
        **{k:fc[k] for k in ('target','build_sha256','profile_sha256','source','acquisition_manifest_sha256')},
        forward_contract_sha256=hashlib.sha256(raw_forward).hexdigest(),
        native_review_sha256=template['native_review_sha256'], bindings=bindings)
    if skipped:contract['acquisition_empty_bindings']=skipped
    contract_path = epoch/'forward-category-contract.json'
    raw = (json.dumps(contract, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode()
    GuardedForwardOwnerCategories(profile, raw_forward, raw, combined)
    contract_path.write_bytes(raw)
    artifact_path = epoch/'forward-category-artifacts.json'
    save(artifact_path, combined_paths)
    return dict(forward_owner_category_contract=contract_path, forward_owner_category_artifacts=artifact_path)


@acquisition_validation_scope(reuse_current=True)
def forward_adapter_options(config, acquisition, epoch):
    """Derive optional owner contracts from this acquisition, never an old epoch."""
    if 'forward_owner_bindings' not in config:
        return {}
    from forward_owner_relations import build_forward_owner_contract, GuardedForwardOwners
    from build_health_contracts import build_contracts
    template_path = Path(config['forward_owner_bindings'])
    need(digest(template_path) == config['forward_owner_bindings_sha256'], 'forward_template_changed')
    raw_contract, artifacts = build_forward_owner_contract(acquisition, template_path.read_bytes(),
                                                          recipe_path=config['recipe'])
    contract_path, artifacts_path = epoch/'forward-contract.json', epoch/'forward-artifacts.json'
    contract_path.write_bytes(raw_contract)
    paths = [Path(acquisition)/'manifest.json', Path(acquisition)/'evidence.jsonl',
             Path(config['recipe']), template_path]
    artifact_paths = {digest(path): str(path.resolve()) for path in paths}
    need(set(artifact_paths) == set(artifacts), 'forward_artifacts_changed')
    save(artifacts_path, artifact_paths)
    checked_forward=GuardedForwardOwners((Path(acquisition)/'profile.json').read_bytes(),raw_contract,artifacts)
    empty={b['binding_id']:b['owned_field_prefix']for b in checked_forward.bindings if 'acquisition_empty_evidence'in b}
    descriptors = []
    if 'forward_owner_health_layout' in config:
        layout_path = Path(config['forward_owner_health_layout'])
        need(digest(layout_path) == config['forward_owner_health_layout_sha256'], 'forward_health_layout_changed')
        from build_health_contracts import _layout
        layout,_,_ = _layout(layout_path.read_bytes())
        need(layout['slot_count']==48,'forward_health_requires_48_slots')
        for declaration in layout['supported_forward_owners']:
            need('forward_contract_sha256' not in declaration, 'forward_contract_must_be_fresh')
            declaration['forward_contract_sha256'] = hashlib.sha256(raw_contract).hexdigest()
        requested_layout_sha256=hashlib.sha256(layout_path.read_bytes()).hexdigest()
        absent=[d for d in layout['supported_forward_owners']if d['binding_id']in empty]
        need(all(empty[d['binding_id']]==d['owner_prefix']for d in absent),'forward_empty_health_prefix')
        if absent:
            removed={d['owner_prefix']for d in absent}
            layout['supported_forward_owners']=[d for d in layout['supported_forward_owners']if d['owner_prefix']not in removed]
            layout['actor_prefixes']=[p for p in layout['actor_prefixes']if p not in removed]
            if 'actor_read_stages' in layout:
                layout['actor_read_stages']={p:layout['actor_read_stages'][p]for p in layout['actor_prefixes']}
        materialized = epoch/'forward-health-layout.json'
        save(materialized, layout)
        if layout['actor_prefixes']:
            bundle = build_contracts(acquisition, materialized.read_bytes(), recipe_path=config['recipe'], allow_forward_owners=True)
        else:
            need(absent and not layout['supported_forward_owners'],'forward_empty_health_layout')
            bundle=dict(schema='overwatch-decoder.private.actor-health-contracts/1',profile_sha256=checked_forward.relations.hash,
                acquisition_manifest_sha256=checked_forward.manifest_hash,acquisition_evidence_sha256=checked_forward.source['evidence_sha256'],
                recipe_sha256=checked_forward.source['recipe_sha256'],layout_sha256=hashlib.sha256(materialized.read_bytes()).hexdigest(),
                contracts=[],forward_owner_contracts=[],public_state_eligible=False)
        if 'actor_read_stages' in layout:
            bundle['actor_read_stages']=layout['actor_read_stages'].copy()
        if absent:bundle.update(acquisition_empty_bindings=[d['binding_id']for d in absent],requested_layout_sha256=requested_layout_sha256)
        need(not bundle['contracts'], 'forward_layout_contains_reciprocal_bodies')
        save(epoch/'forward-health-bundle.json', bundle)
        for i, descriptor in enumerate(bundle['forward_owner_contracts']):
            path = epoch/f'forward-health-{i:04d}.json'
            save(path, descriptor)
            descriptors.append(path)
    return dict(forward_owner_contract=contract_path, forward_owner_artifacts=artifacts_path,
                forward_owner_health_contracts=descriptors,
                **forward_category_adapter_options(config, acquisition, epoch, raw_contract, artifacts, artifact_paths))


def context_adapter_options(prefix):
    """Read only fixed output filenames from the explicitly pinned composer."""
    from export_relations import bounded_local_bytes
    descriptor = parse(bounded_local_bytes(prefix.with_suffix('.options.json'), 4096, 'context_options_size'))
    need(descriptor.get('schema') == 'overwatch-decoder.context-projection-options/1'
         and type(descriptor.get('include_groups')) is bool
         and set(descriptor) == {'schema', 'include_groups'}, 'context_projection_options')
    names = dict(raw_category_contract='.category-contract.json',
                 context_controller_contract='.controller-contract.json',
                 context_projection_admission='.admission.json',
                 context_projection_artifacts='.artifacts.json')
    group = prefix.with_suffix('.group-contract.json')
    need(group.exists() == descriptor['include_groups'], 'context_group_output_mismatch')
    if descriptor['include_groups']:
        names['context_group_contract'] = '.group-contract.json'
    result = {key: prefix.with_suffix(suffix) for key, suffix in names.items()}
    need(all(path.is_file() and 0 < path.stat().st_size <= MAX_METADATA for path in result.values()),
         'context_projection_output_size')
    return result


def profile_body_bindings(profile_raw, *, allow_unresolved=False):
    """Describe guarded storage bindings; undeclared body fields are not a body."""
    from relations import GuardedRelations
    bindings = GuardedRelations(profile_raw)
    objects, unresolved = [], []
    for prefix in bindings.prefixes:
        identity = [prefix+'_handle_candidate_i32', prefix+'_manager_key_candidate_i32']
        words = [dict(zip(('address','value'), bindings._binding(name))) for name in identity]
        ck = bindings._key('controller', words)
        lookup = prefix+'_part51_0000_body_key_candidate_i32'
        lookup_value = bindings._binding(lookup)[1]
        body_prefix = prefix+'_body_'
        declared = [name for name in bindings.fields if name.startswith(body_prefix)]
        if not declared:
            need(allow_unresolved, 'fresh_reciprocal_body_fields_required')
            objects.append(dict(controller_object_key=ck, body_object_key=None))
            unresolved.append(dict(controller_object_key=ck, reason='body_fields_not_declared',
                controller_identity_fields=identity, body_lookup_key_field=lookup,
                body_field_prefix=body_prefix, profile_sha256=bindings.hash,
                profile_guards_sha256=hashlib.sha256(json.dumps(bindings.guards,sort_keys=True,separators=(',',':')).encode()).hexdigest()))
            continue
        body = [prefix+'_body_0000_handle_candidate_i32', prefix+'_body_0000_manager_key_candidate_i32']
        body_words = [dict(zip(('address','value'), bindings._binding(name))) for name in body]
        need(lookup_value == body_words[1]['value'], 'fresh_reciprocal_body_key')
        objects.append(dict(controller_object_key=ck, body_object_key=bindings._key('body',body_words)))
    return bindings, objects, unresolved


def build_present_health_contracts(acquisition, layout_raw, *, recipe_path):
    """Raw-only subset from this profile, never from previous actor contracts."""
    from build_health_contracts import build_contracts, _layout, _read
    from plan_live_roster import verified_census
    layout, _, _ = _layout(layout_raw)
    profile_raw = _read(Path(acquisition)/'profile.json', 262144)
    bindings, objects, unresolved = profile_body_bindings(profile_raw, allow_unresolved=True)
    expected = [prefix+'_body_0000_' for prefix in bindings.prefixes]
    need(set(expected) == set(layout['actor_prefixes']), 'health_layout_exact_controller_prefixes')
    if not unresolved:
        return build_contracts(acquisition, layout_raw, recipe_path=recipe_path)
    # A subset cannot bypass source identity, the pinned layout, or any final guard.
    census = verified_census(acquisition, recipe_path, expected_target=bindings.target)
    need(layout['recipe_sha256'] == census['source']['recipe_sha256']
         and layout['executable_sha256'] == bindings.target['executable_sha256'], 'health_layout_source_pin')
    absent = {item['body_field_prefix']+'0000_' for item in unresolved}
    present = [prefix for prefix in layout['actor_prefixes'] if prefix not in absent]
    effective = dict(layout, actor_prefixes=present)
    if 'actor_read_stages' in effective:
        effective['actor_read_stages']={p:effective['actor_read_stages'][p]for p in present}
    effective_raw = (json.dumps(effective,sort_keys=True,separators=(',',':'))+'\n').encode()
    if present:
        bundle = build_contracts(acquisition, effective_raw, recipe_path=recipe_path)
    else:
        # No pool extent exists to pass to the health builder. Keep its profile
        # count/shape/read-budget checks even though no health is projected.
        manifest=json.loads(_read(Path(acquisition)/'manifest.json',262144))
        fields=bindings.profile['fields'];guards=bindings.profile.get('guards',[])
        declarations=len(guards)+sum(len(f.get('guards',[]))for f in fields)
        widths={'u8':1,'i32':4,'f32':4,'f64':8,'f32x3':12,'f32x4':16}
        need(manifest.get('fields')==len(fields) and type(manifest.get('fields'))is int
             and 0<declarations<=256 and type(manifest.get('guard_declarations'))is int
             and manifest['guard_declarations']==declarations,'empty_health_profile_counts')
        for field in fields:
            width=widths.get(field.get('type'));address=field.get('address')
            need(re.fullmatch(r'[A-Za-z0-9_.-]{1,64}',field['name'])is not None and width is not None
                 and type(address)is int and 0<address<=(1<<64)-width,'empty_health_profile_field')
        need(2*sum(len(bytes.fromhex(g['bytes_hex']))for g in bindings.guards)
             +sum(widths[f['type']]for f in fields)<=32*1024,'empty_health_profile_read_bound')
        source=census['source']
        bundle=dict(schema='overwatch-decoder.private.actor-health-contracts/1', profile_sha256=bindings.hash,
            acquisition_evidence_sha256=source['evidence_sha256'],acquisition_manifest_sha256=source['manifest_sha256'],
            recipe_sha256=source['recipe_sha256'],layout_sha256=hashlib.sha256(effective_raw).hexdigest(),
            contracts=[],public_state_eligible=False)
    if 'actor_read_stages' in effective:
        bundle['actor_read_stages']=effective['actor_read_stages'].copy()
    bundle.update(requested_layout_sha256=hashlib.sha256(layout_raw).hexdigest(),
        effective_actor_prefixes=present,unresolved_bodies=unresolved,
        subset_basis='same_acquisition_profile_body_fields',previous_contracts_carried=False)
    return bundle

def verify_composer(path, expected):
    need(Path(path).stat().st_size <= 4*1024*1024 and digest(path)==expected, 'composer_hash_or_size')

def run_composer(path, expected, arguments, log, timeout):
    """One explicitly pinned CLI child; subprocess.run kills and joins on timeout."""
    need(0 < timeout <= 30, 'composer_timeout_bound')
    verify_composer(path, expected)
    subprocess.run([sys.executable, str(Path(__file__).resolve()), '--compose', str(path), expected, '--', *arguments], stdout=log, stderr=subprocess.STDOUT,
                   check=True, timeout=timeout)


def health_ratio_inputs(config):
    """Explicit, bounded caller inputs; never guess pair offsets or pool roles."""
    from build_health_ratio_contracts import validate_layout
    from export_relations import bounded_local_bytes
    result = {}
    for key, maximum in (('health_ratio_layout', 65536),
                         ('health_ratio_native_review', 8*1024*1024),
                         ('health_layout', 1024*1024)):
        raw = bounded_local_bytes(config[key], maximum, 'producer_asset_size:'+key)
        need(hashlib.sha256(raw).hexdigest() == config.get(key+'_sha256'),
             'pinned_file_mismatch:'+key)
        result[key] = raw
    layout = validate_layout(result['health_ratio_layout'])
    review = parse(result['health_ratio_native_review'])
    need(layout['executable_sha256'] == config['target'].get('executable_sha256')
         and layout['recipe_sha256'] == config['recipe_sha256'], 'health_ratio_layout_scope')
    need(layout['vector_type'] == 'f32x3', 'live_ratio_requires_f32x3')
    need(isinstance(review, dict)
         and review.get('build_sha256') == layout['executable_sha256'],
         'health_ratio_native_review_scope')
    return result


def health_ratio_adapter_options(config, acquisition, epoch, health_bundle):
    """Build new ratio contracts for this acquisition, including empty epochs."""
    if 'health_ratio_layout' not in config:
        return {}
    from build_health_ratio_contracts import build_contracts
    inputs = health_ratio_inputs(config)
    bundle = build_contracts(acquisition, inputs['health_ratio_layout'],
        inputs['health_ratio_native_review'], health_bundle, recipe_path=config['recipe'])
    # Keep the original complete layout so the parent can reconstruct membership
    # independently. A bundle hash alone cannot prove omitted empty pool slots.
    for key, name in (('health_layout', 'health-ratio-health-layout.json'),
                      ('health_ratio_layout', 'health-ratio-layout.json'),
                      ('health_ratio_native_review', 'health-ratio-native-review.json')):
        with (epoch/name).open('xb') as file:
            file.write(inputs[key])
    save(epoch/'health-ratio-bundle.json', bundle)
    paths = []
    for index, contract in enumerate(bundle['contracts']):
        path = epoch/f'health-ratio-contract-{index:04d}.json'
        save(path, contract)
        paths.append(path)
    if not paths:
        return {}
    return dict(health_ratio_contracts=paths,
                health_ratio_native_review=epoch/'health-ratio-native-review.json')


def ammunition_adapter_options(config, acquisition, epoch, session, admitted, segment,
                               metadata_raw, *, timeout):
    """Compose this epoch from original native metadata, never saved admission.

    LiveSession has already checked the event order. Preserve its exact transport
    bytes for the caller composer and compare them with the factory arguments so
    a previous acquisition cannot be substituted even when profiles are equal.
    The LiveRelations constructor validates all returned contracts and artifacts.
    """
    if 'ammunition_composer' not in config:
        return {}
    need(digest(config['ammunition_inputs']) == config['ammunition_inputs_sha256'],
         'pinned_file_mismatch:ammunition_inputs')
    need(isinstance(metadata_raw, tuple) and len(metadata_raw) == 3,
         'ammunition_original_metadata_required')
    decoded = []
    for raw in metadata_raw:
        validate_line(raw, len(raw) if isinstance(raw, bytes) else 0)
        decoded.append(parse(raw))
    need(all(isinstance(value, dict) for value in decoded)
         and decoded[0] == session and decoded[1].get('acquisition') == admitted
         and decoded[2] == segment
         and [value.get('kind') for value in decoded] ==
             ['session_start', 'acquisition_end', 'segment_start'],
         'ammunition_original_metadata_mismatch')
    paths = []
    for name, raw in zip(('session-start', 'acquisition-end', 'segment-start'), metadata_raw):
        path = epoch / ('ammunition-' + name + '.json')
        with path.open('xb') as file:
            file.write(raw)
        paths.append(path)
    prefix = epoch / 'ammunition'
    arguments = ['--acquisition', str(acquisition), '--recipe', config['recipe'],
                 '--session-start', str(paths[0]), '--acquisition-end', str(paths[1]),
                 '--segment-start', str(paths[2]), '--inputs', config['ammunition_inputs'],
                 '--output-prefix', str(prefix)]
    with (epoch / 'ammunition-composition.log').open('xb') as log:
        run_composer(config['ammunition_composer'], config['ammunition_composer_sha256'],
                     arguments, log, timeout)
    options = {}
    for key, suffix in (('ammunition_contract', '.contract.json'),
                        ('ammunition_artifacts', '.artifacts.json'),
                        ('ammunition_admission', '.admission.json')):
        path = prefix.with_suffix(suffix)
        need(path.is_file() and 0 < path.stat().st_size <= MAX_METADATA,
             'ammunition_composer_output_size:' + key)
        options[key] = path
    return options


def stop_owned(worker):
    """Only the Popen handle created by this producer; no image/PID discovery."""
    if worker.poll() is None:
        worker.terminate()
        try:
            worker.wait(timeout=10)
        except subprocess.TimeoutExpired:
            worker.kill()
            worker.wait(timeout=5)

def run(config_path, *, job_handle=None):
    from runtime_jobs import enroll_current_producer
    # This gate precedes imports/factories that can create native or composer children.
    enroll_current_producer(job_handle)
    from live_relations import LiveRelations
    from live_sessions import LiveSession
    from build_health_contracts import build_contracts
    from compact_live_entities import CompactLiveEntities, encode
    need(sys.platform == 'win32', 'windows_live_clock_required')
    need(config_path.stat().st_size <= 1024 * 1024, 'producer_config_size')
    config_raw = config_path.read_bytes()
    c = parse(config_raw)
    c = validate_config(c, config_path.parent)
    raw_mode = c.get('observation_mode') == 'raw-candidates'
    if not raw_mode:
        verify_composer(c['composer'], c['composer_sha256'])
    out = Path(c['output'])
    out.mkdir(parents=True, exist_ok=False)
    (out / 'config.json').write_bytes(config_raw)
    runtime = dict(python=sys.version, isolated=sys.flags.isolated, interpreter_sha256=digest(sys.executable), private_composer_sha256=None if raw_mode else digest(c['composer']), context_composer_sha256=c.get('context_composer_sha256'), owned_job_enrolled=True, public_state_eligible=False, start_qpc=qpc())
    if 'ammunition_composer' in c:
        runtime.update(ammunition_composer_sha256=c['ammunition_composer_sha256'],
                       ammunition_inputs_sha256=c['ammunition_inputs_sha256'])
    if 'health_ratio_layout' in c:
        runtime.update(health_ratio_layout_sha256=c['health_ratio_layout_sha256'],
                       health_ratio_native_review_sha256=c['health_ratio_native_review_sha256'])
    save(out / 'runtime.json', runtime)
    native = out / 'native'
    epochs = []

    @acquisition_validation_scope()
    def factory(session, admitted, segment):
        need(session['target'] == c['target'] and session['recipe_sha256'] == c['recipe_sha256'], 'producer_validation_failed')
        need(session['revision'] == c['native_revision'], 'producer_validation_failed')
        ordinal, number = (admitted['ordinal'], segment['segment'])
        need(admitted['directory'] == f'acquisition-{ordinal:04d}', 'producer_validation_failed')
        acq = native / admitted['directory']
        need(digest(acq / 'manifest.json') == admitted['manifest_sha256'], 'producer_validation_failed')
        epoch = out / f'epoch-{number:04d}'
        epoch.mkdir()
        def stage(name, operation):
            return _producer_stage(name, number, session['monotonic_frequency'], operation)
        epoch_config = c
        if c.get('allow_controller_subsets', False):
            from controller_subset_projection import prepare
            epoch_config = stage('controller_subset', lambda: prepare(c, acq, epoch))
        if c.get('include_health_candidates', True):
            builder = build_present_health_contracts if raw_mode else build_contracts
            contracts = stage('health_contracts', lambda: builder(
                acq, Path(epoch_config['health_layout']).read_bytes(), recipe_path=c['recipe']))
        else:
            # Ability-only recipes do not pretend to have health pool extents.
            # Retain independent fresh acquisition/guard verification even when
            # there are no health descriptors to build.
            from plan_live_roster import verified_census
            census = stage('source_verification', lambda: verified_census(
                acq, c['recipe'], expected_target=c['target']))
            contracts = dict(schema='overwatch-decoder.private.health-projection-disabled/1',
                contracts=[], reason='explicit_raw_producer_configuration',
                source=census['source'], public_state_eligible=False)
        save(epoch / 'health-bundle.json', contracts)
        descriptors = []
        for i, descriptor in enumerate(contracts['contracts']):
            path = epoch / f'health-contract-{i:04d}.json'
            save(path, descriptor)
            descriptors.append(path)
        save(epoch / 'session-start.json', session)
        save(epoch / 'segment-start.json', segment)
        options = adapter_options(c, descriptors)
        if 'health_ratio_layout' in c:
            options.update(stage('health_ratio_contracts', lambda: health_ratio_adapter_options(
                c, acq, epoch, contracts)))
        options.update(stage('forward_contracts', lambda: forward_adapter_options(epoch_config, acq, epoch)))
        if not raw_mode:
            prefix = epoch / 'category'
            command = ['compose', '--acquisition', str(acq), '--recipe', c['recipe'], '--session-start', str(epoch / 'session-start.json'), '--segment-start', str(epoch / 'segment-start.json'), '--native-review', c['native_review'], '--roster-review', c['roster_review'], '--artifacts', c['category_artifacts'], '--output-prefix', str(prefix)]
            for path in c['reviewed_mode_sources']:
                command += ['--reviewed-mode-source', path]
            with (epoch / 'composition.log').open('xb') as log:
                stage('category_composer', lambda: run_composer(
                    c['composer'], c['composer_sha256'], command[1:], log,
                    min(30, max(.001, deadline-time.perf_counter()))))
            options.update(live_category_contract=prefix.with_suffix('.contract.json'), live_category_artifacts=prefix.with_suffix('.artifacts.json'))
        if 'context_composer' in c:
            need(digest(c['context_inputs']) == c['context_inputs_sha256'], 'pinned_file_mismatch:context_inputs')
            prefix = epoch / 'context'
            command = ['--acquisition', str(acq), '--recipe', c['recipe'],
                       '--session-start', str(epoch / 'session-start.json'),
                       '--segment-start', str(epoch / 'segment-start.json'),
                       '--inputs', c['context_inputs'], '--output-prefix', str(prefix)]
            with (epoch / 'context-composition.log').open('xb') as log:
                stage('context_composer', lambda: run_composer(
                    c['context_composer'], c['context_composer_sha256'], command, log,
                    min(30, max(.001, deadline-time.perf_counter()))))
            options.update(context_adapter_options(prefix))
        if 'ammunition_composer' in c:
            options.update(stage('ammunition_composer', lambda: ammunition_adapter_options(
                c, acq, epoch, session, admitted, segment,
                (decoder.session_raw, decoder.completed_raw, raw),
                timeout=min(30, max(.001, deadline-time.perf_counter())))))
        adapter = stage('live_adapter', lambda: LiveRelations(
            acq, session['session_id'], number, **options))
        epochs.append(dict(segment=number, acquisition=ordinal, admitted_qpc=qpc(), frames=0, profile_sha256=segment['profile_sha256']))
        print(json.dumps({'admitted_epoch': number}), flush=True)
        return adapter
    decoder = LiveSession(factory)
    compact_decoder = CompactLiveEntities()
    command = [c['native_exe'], 'observe-fields', '--pid', str(c['target']['pid']), '--recipe', c['recipe'], '--out', str(native), '--seconds', str(c['seconds']), '--interval-ms', str(c['interval_ms']), '--jsonl', 'true', '--live-evidence', 'true', '--allow-field-shape-changes', 'true']
    start = time.perf_counter()
    deadline = start + c['seconds'] + 30
    worker = None
    reader = None
    pipe_stop = threading.Event()
    pending = queue.Queue(maxsize=16 * 1024 * 1024 // MAX_LINE)
    pipe_state = dict(received_bytes=0, events=0, maximum_queue_depth=0, queue_full_waits=0, error=None)
    error = None
    frames = events = native_bytes = output_bytes = 0
    delays = []

    def enqueue(value):
        while not pipe_stop.is_set():
            try:
                pending.put(value, timeout=0.1)
                pipe_state['maximum_queue_depth'] = max(pipe_state['maximum_queue_depth'], pending.qsize())
                return
            except queue.Full:
                pipe_state['queue_full_waits'] += 1

    def read_native():
        try:
            while not pipe_stop.is_set():
                raw = worker.stdout.readline(MAX_LINE + 1)
                if not raw:
                    break
                received = qpc()
                pipe_state['received_bytes'] += len(raw)
                pipe_state['events'] += 1
                validate_line(raw, pipe_state['received_bytes'])
                need(pipe_state['events'] <= 100000, 'producer_validation_failed')
                enqueue((raw, received))
        except Exception as exc:
            pipe_state['error'] = repr(exc)
        finally:
            enqueue(None)
    try:
        with (out / 'native-stderr.txt').open('xb') as stderr:
            worker = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=stderr)
            reader = threading.Thread(target=read_native, name='bounded-native-pipe', daemon=True)
            reader.start()
            with (out / 'native.jsonl').open('xb') as raw_output, (out / 'entities.jsonl').open('xb') as output, (out / 'compact.jsonl').open('xb') as compact_output, (out / 'receipts.jsonl').open('x') as receipts:
                while True:
                    need(time.perf_counter() < deadline, 'producer_total_deadline')
                    try:
                        item = pending.get(timeout=max(0.001, min(1, deadline - time.perf_counter())))
                    except queue.Empty:
                        continue
                    if item is None:
                        need(pipe_state['error'] is None, pipe_state['error'])
                        break
                    raw, received = item
                    native_bytes += len(raw)
                    validate_line(raw, native_bytes)
                    event = parse(raw)
                    events += 1
                    _write_native_event(raw_output, raw, event)
                    projected = decoder.consume(raw)
                    if projected is None:
                        continue
                    encoded = json.dumps(projected, separators=(',', ':'), allow_nan=False).encode() + b'\n'
                    need(len(encoded) <= 1024*1024, 'semantic_line_bound')
                    output_bytes += len(encoded)
                    need(output_bytes <= 1024*1024*1024, 'semantic_output_byte_bound')
                    raw_output.flush()
                    output.write(encoded)
                    output.flush()
                    compact_output.write(encode(compact_decoder.consume(encoded)))
                    compact_output.flush()
                    completed = qpc()
                    frames += 1
                    epochs[-1]['frames'] += 1
                    need(epochs[-1]['segment'] == event['segment'], 'producer_validation_failed')
                    delay = (completed - event['emitted_ticks']) / event['monotonic_frequency']
                    need(delay >= 0, 'producer_validation_failed')
                    delays.append(delay)
                    receipts.write(json.dumps(dict(event_sequence=event['event_sequence'], segment=event['segment'], frame_sequence=event['sequence'], emitted_ticks=event['emitted_ticks'], received_qpc=received, output_completed_qpc=completed, native_running=worker.poll() is None, emitted_to_projection_seconds=delay), separators=(',', ':')) + '\n')
                    if epochs[-1]['frames'] == 20:
                        need(worker.poll() is None, 'producer_validation_failed')
                        print(json.dumps({'native_running_after_twenty': event['segment'], 'delay_seconds': delay}), flush=True)
            code = worker.wait(timeout=15)
            summary = decoder.close()
            need(frames > 0 and code == 0 and summary['native_session_end_seen'] and (not summary['failed']), 'producer_validation_failed')
    except Exception as exc:
        error = repr(exc)
    finally:
        pipe_stop.set()
        if worker is not None and worker.poll() is None:
            try:
                stop_owned(worker)
            except (OSError, subprocess.TimeoutExpired) as exc:
                error = error or repr(exc)
        if reader is not None:
            reader.join(timeout=5)
            if reader.is_alive():
                error = error or 'owned_native_reader_did_not_stop'
        result = dict(schema='overwatch-decoder.local-live-producer-result/1', complete=error is None, error=error, native_exit=None if worker is None else worker.returncode, frames=frames, events=events, native_bytes=native_bytes, epochs=epochs, pipe=pipe_state, elapsed_seconds=time.perf_counter() - start, public_state_eligible=False, visibility='unknown')
        if error is None:
            ordered = sorted(delays)
            result.update(decoder=summary, entities_sha256=digest(out / 'entities.jsonl'), compact_sha256=digest(out / 'compact.jsonl'), compact_bytes=(out / 'compact.jsonl').stat().st_size, emitted_to_projection_seconds=dict(minimum=ordered[0], median=ordered[len(ordered) // 2], p95=ordered[int((len(ordered) - 1) * 0.95)], maximum=ordered[-1]))
        save(out / 'result.json', result)
        print(json.dumps(result, separators=(',', ':')), flush=True)
    return 1 if error else 0


def main(argv=None):
    values = list(sys.argv[1:] if argv is None else argv)
    if values and values[0] == '--compose':
        import runpy
        if sys.platform == 'win32':
            from runtime_jobs import require_current_job
            require_current_job()
        need(len(values) >= 4 and values[3] == '--', 'composer_invocation')
        path, pin = values[1:3]
        verify_composer(path, pin)
        # The owned bounded subprocess already has this bundle's import roots.
        sys.argv = [path, *values[4:]]
        runpy.run_path(path, run_name='__main__')
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config', type=Path)
    parser.add_argument('--job-handle', type=int, required=True)
    args = parser.parse_args(values)
    return run(args.config.resolve(), job_handle=args.job_handle)

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError) as error:
        print(json.dumps(dict(complete=False, error=str(error))), file=sys.stderr)
        raise SystemExit(2)
