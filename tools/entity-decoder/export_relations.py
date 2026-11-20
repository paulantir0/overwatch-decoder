#!/usr/bin/env python3
"""Export private, guarded entity research from saved native recordings only.

Example: python export_relations.py --recording .runs/recording --acquisition
.runs/acquisition --output .runs/entities.jsonl --observer observer.dll --dotnet dotnet
Default rejects incomplete sources. --allow-partial exports only a native-verified
durable prefix and labels its incompleteness. No process access or game controls.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import re
import stat
from pathlib import Path
import subprocess
import sys
import tempfile
import zlib

from relations import GuardedRelations


class InvalidRecording(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise InvalidRecording(reason)


def integer(value):
    return type(value) is int


def parse(raw):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            need(key not in out, 'duplicate_json_key')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(InvalidRecording('nonfinite_json')))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def file_digest(path):
    with Path(path).open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def bounded_local_bytes(path, limit, reason):
    """Read only an explicit regular file, including a bound on actual bytes read."""
    with os.fdopen(os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0)), 'rb') as file:
        metadata = os.fstat(file.fileno())
        need(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= limit, reason)
        raw = file.read(limit + 1)
        need(len(raw) <= limit, reason)
        return raw


def load_local_artifacts(artifact_paths, source_kind, *, maximum_artifact=16*1024*1024,
                         maximum_total=64*1024*1024):
    """Load an explicit local SHA-to-path map; never search or fetch evidence."""
    paths_file = Path(artifact_paths).resolve()
    paths = parse(bounded_local_bytes(paths_file, 262144, source_kind + '_artifact_map_size'))
    need(isinstance(paths, dict) and 1 <= len(paths) <= 256, source_kind + '_artifact_map_entries')
    artifacts, total = {}, 0
    for expected, supplied in paths.items():
        need(isinstance(expected, str) and re.fullmatch('[0-9a-f]{64}', expected)
             and isinstance(supplied, str) and supplied and '://' not in supplied,
             source_kind + '_artifact_map_entry')
        path = Path(supplied)
        if not path.is_absolute():
            path = paths_file.parent / path
        data = bounded_local_bytes(path, min(maximum_artifact, maximum_total-total), source_kind + '_artifact_size')
        need(digest(data) == expected, source_kind + '_artifact_hash')
        total += len(data)
        artifacts[expected] = data
    return artifacts


def load_hero_projector(profile_bytes, catalog_path, artifact_paths, locale='enUS'):
    from hero_labels import GuardedHeroLabels, HeroLabelCatalog
    catalog = bounded_local_bytes(catalog_path, 65536, 'hero_catalog_size')
    return GuardedHeroLabels(profile_bytes, HeroLabelCatalog(catalog, load_local_artifacts(artifact_paths, 'hero')), locale)


def load_hero_asset_projector(profile_bytes, catalog_path, artifact_paths, locale='enUS'):
    """Load caller-pinned typed assets, requiring a current reciprocal body."""
    from hero_asset_labels import GuardedHeroAssetLabels, HeroAssetCatalog
    catalog = bounded_local_bytes(catalog_path, 65536, 'hero_asset_catalog_size')
    return GuardedHeroAssetLabels(profile_bytes,
        HeroAssetCatalog(catalog, load_local_artifacts(artifact_paths, 'hero_asset')),
        locale, require_body=True)


def load_category_projector(profile_bytes, contract_path, artifact_paths):
    from categories import GuardedCategories
    contract = bounded_local_bytes(contract_path, 262144, 'category_contract_size')
    return GuardedCategories(profile_bytes, contract, load_local_artifacts(artifact_paths, 'category'))


def load_ammunition_projector(profile_bytes, contract_path, artifact_paths):
    from ammunition_candidates import GuardedAmmunitionCandidates
    return GuardedAmmunitionCandidates(profile_bytes,
        bounded_local_bytes(contract_path, 262144, 'ammunition_contract_size'),
        load_local_artifacts(artifact_paths, 'ammunition'))


def verify_ammunition_source(projector, source):
    acquisition = source.get('acquisition', {})
    need(projector.relations.hash == source.get('profile_sha256')
         and projector.acquisition_manifest_sha256 == acquisition.get('manifest_sha256')
         and all(projector.source.get(key) == acquisition.get(key)
                 for key in ('recipe_sha256', 'evidence_sha256')),
         'ammunition_acquisition_mismatch')


def verify_health_ratio_sources(contracts, source):
    need(len(contracts) <= 128, 'health_ratio_contract_bound')
    prefixes = set()
    for contract in contracts:
        contract.verify_source(source)
        prefix = contract.storage.actor_prefix
        need(prefix not in prefixes, 'duplicate_health_ratio_actor')
        prefixes.add(prefix)


def health_ratio_projection(contracts):
    """Offset-free declarations for independent downstream source admission."""
    return dict(schema='overwatch-decoder.health-ratio-projection/1', contracts=[
        dict(contract_sha256=contract.contract_sha256,
             native_review_sha256=contract.native_review_sha256,
             membership_contract_sha256=contract.storage.membership_sha256,
             actor_prefix=contract.storage.actor_prefix,
             source=contract.source.copy(),
             paired_slots=[dict(slot) for slot in contract.paired_slots],
             supplied_layout_slots=len(contract.storage.slots),
             **({'bank_groups': [dict(bank_id=g['bank_id'], pool_indices=g['pool_indices'].copy())
                                for g in contract.bank_groups]} if contract.bank_groups else {}))
        for contract in contracts])


def native_verify(directory, command, allow_partial):
    completed = subprocess.run([*command, 'verify-fields', '--from', str(directory),
                                '--recover-indexed-prefix', str(allow_partial).lower()],
                               capture_output=True, text=True, timeout=900)
    try:
        envelope = parse(completed.stdout)
        result = envelope['result']
    except (KeyError, ValueError) as error:
        raise InvalidRecording('native_verifier_failed') from error
    need(envelope.get('command') == 'verify-fields' and envelope.get('ok') is True,
         'native_verifier_failed')
    accepted = result.get('valid') is True and (result.get('complete') is True or allow_partial)
    recovered = allow_partial and result.get('status') == 'recoverable_prefix' and result.get('verified_chunks', 0) > 0
    need(accepted or recovered, 'native_source_rejected:' + str(result.get('error_code') or result.get('status')))
    return result


def acquisition_provenance(directory, profile_hash, target):
    directory = Path(directory)
    need((directory/'manifest.json').stat().st_size <= 262144 and (directory/'recipe.json').stat().st_size <= 1048576,
         'acquisition_metadata_size')
    manifest_bytes = (directory/'manifest.json').read_bytes()
    manifest = parse(manifest_bytes)
    need(manifest.get('schema') == 'overwatch-decoder.acquisition-result/1' and manifest.get('complete') is True
         and manifest.get('error') is None, 'incomplete_acquisition')
    need(manifest.get('target') == target and manifest.get('profile_sha256') == profile_hash,
         'acquisition_profile_or_target_mismatch')
    for filename, field in [('profile.json', 'profile_sha256'), ('recipe.json', 'recipe_sha256'),
                            ('evidence.jsonl', 'evidence_sha256')]:
        need(file_digest(directory/filename) == manifest.get(field), 'acquisition_hash_mismatch:' + filename)
    recipe = parse((directory/'recipe.json').read_bytes())
    need(recipe.get('target', {}).get('executable_sha256') == target['executable_sha256']
         and recipe['target'].get('image_name') == target['image_name']
         and recipe['target'].get('architecture') == target['architecture'], 'acquisition_build_mismatch')
    need(manifest.get('stages_completed') == len(recipe.get('stages', [])), 'incomplete_acquisition_stages')
    return dict(manifest_sha256=digest(manifest_bytes), recipe_sha256=manifest['recipe_sha256'],
                evidence_sha256=manifest['evidence_sha256'], relationship_semantics='profile_declared_research')


def observed_field(projector, frame, name, expected_type):
    """Validate sampled data dependencies without requiring its value be constant."""
    binding = projector.fields.get(name, {})
    field = frame.get('fields', {}).get(name, {})
    ids = projector.guard_ids.get(name)
    need(binding.get('type') == expected_type and field.get('type') == expected_type
         and field.get('status') == 'observed' and field.get('reason') is None,
         'field_unobserved:' + name)
    need(ids and field.get('guard_ids') == ids, 'field_dependencies_mismatch:' + name)
    start, end = field.get('read_start_ticks'), field.get('read_end_ticks')
    need(integer(start) and integer(end) and frame['start_ticks'] <= start <= end <= frame['end_ticks'],
         'invalid_field_bracket:' + name)
    if not projector._guard_brackets_match(ids, frame, start, end):
        for phase in ['before', 'after']:
            checks = frame.get('guards_' + phase)
            need(isinstance(checks, list) and len(checks) == len(projector.guards), 'missing_field_guards')
            for guard_id in ids:
                check = checks[guard_id]
                a, b = check.get('start_ticks'), check.get('end_ticks')
                need(check.get('ok') is True and check.get('error') is None and integer(a) and integer(b)
                     and frame['start_ticks'] <= a <= b <= frame['end_ticks']
                     and (b <= start if phase == 'before' else a >= end), 'field_guard_failed:' + name)
    value = field.get('value')
    if expected_type == 'i32':
        need(integer(value) and -(1 << 31) <= value < (1 << 31), 'invalid_i32:' + name)
    else:
        need(isinstance(value, list) and len(value) == 3
             and all(type(v) in (int, float) and math.isfinite(v) for v in value), 'invalid_position:' + name)
    return dict(field=name, type=expected_type, value=value, read_start_ticks=start, read_end_ticks=end,
                guard_ids=ids.copy(), source='process_memory', profile_sha256=projector.hash,
                build_sha256=projector.target['executable_sha256'], validation_status='guarded_research')


def project_frame(projector, frame, source, completeness, gap_before, health_contracts=(),
                  name_projector=None, include_private_battletags=False, hero_projector=None, cached_label_projector=None, category_projector=None,
                  hero_asset_projector=None, forward_owner_projector=None, finite_context_projector=None,
                  ammunition_projector=None, health_ratio_contracts=()):
    need(finite_context_projector is None or category_projector is None,
         'legacy_and_context_categories_mutually_exclusive')
    base_projection = projector.project(frame)
    health = {}
    for contract in health_contracts:
        candidate = contract.project(frame, relation_projection=base_projection,
                                     gap=bool(gap_before['skipped_slots']))
        if candidate is not None:
            key = candidate.get('body_object_key')
            health[key] = None if key in health else candidate
    verify_health_ratio_sources(health_ratio_contracts, source)
    ratios = {}
    for contract in health_ratio_contracts:
        candidate = contract.project(frame, relation_projection=base_projection,
                                     gap=bool(gap_before['skipped_slots']))
        if candidate is not None:
            key = candidate['body_object_key']
            ratios[key] = None if key in ratios else candidate
    result = dict(base_projection)
    if health_ratio_contracts:
        result['health_ratio_contract_sha256'] = [contract.contract_sha256 for contract in health_ratio_contracts]
        result['health_ratio_projection'] = health_ratio_projection(health_ratio_contracts)
    ammunition_rows = []
    if ammunition_projector is not None:
        verify_ammunition_source(ammunition_projector, source)
        ammunition = ammunition_projector.project(frame, relation_projection=base_projection,
                                                  gap=bool(gap_before['skipped_slots']))
        need(ammunition.get('schema') == 'overwatch-decoder.guarded-ammunition-candidates/1'
             and ammunition.get('profile_sha256') == projector.hash
             and ammunition.get('target') == projector.target
             and ammunition.get('timing') == base_projection.get('timing')
             and ammunition.get('contract_sha256') == ammunition_projector.contract_sha256
             and ammunition.get('native_review_sha256') == ammunition_projector.native_review_sha256
             and ammunition.get('source_evidence') == dict(ammunition_projector.source,
                 acquisition_manifest_sha256=ammunition_projector.acquisition_manifest_sha256)
             and ammunition.get('public_state_eligible') is False
             and ammunition.get('atomic') is False and ammunition.get('visibility') == 'unknown',
             'ammunition_projection_source_mismatch')
        ammunition_rows = ammunition.get('rows')
        need(isinstance(ammunition_rows, list) and len(ammunition_rows) <= 32
             and all(isinstance(row, dict) for row in ammunition_rows), 'ammunition_projection_rows')
        result['ammunition_projection'] = ammunition
    name_rows = []
    if name_projector is not None:
        name_projection = name_projector.project(frame)
        need(name_projection.get('schema') == 'overwatch-decoder.guarded-account-names/1'
             and name_projection.get('profile_sha256') == projector.hash
             and name_projection.get('target') == projector.target, 'name_projection_source_mismatch')
        name_rows = name_projection.get('names', [])
    hero_rows = []
    hero_projection = None
    if hero_projector is not None:
        hero_projection = hero_projector.project(frame, gap=bool(gap_before['skipped_slots']))
        need(hero_projection.get('schema') == 'overwatch-decoder.guarded-hero-labels/1'
             and hero_projection.get('profile_sha256') == projector.hash
             and hero_projection.get('target') == projector.target
             and hero_projection.get('timing') == base_projection.get('timing'),
             'hero_projection_source_mismatch')
        hero_rows = hero_projection.get('heroes', [])
        result['hero_catalog_sha256'] = hero_projection['catalog_sha256']
    asset_rows = []
    if hero_asset_projector is not None:
        need(hero_asset_projector.require_body is True, 'hero_asset_body_required')
        asset_projection = hero_asset_projector.project(frame, gap=bool(gap_before['skipped_slots']))
        need(asset_projection.get('schema') == 'overwatch-decoder.guarded-hero-asset-labels/1'
             and asset_projection.get('profile_sha256') == projector.hash
             and asset_projection.get('target') == projector.target
             and asset_projection.get('timing') == base_projection.get('timing')
             and asset_projection.get('runtime_ui_validated') is False
             and asset_projection.get('catalog_sha256') == hero_asset_projector.catalog.hash,
             'hero_asset_projection_source_mismatch')
        asset_rows = asset_projection.get('heroes')
        need(isinstance(asset_rows, list) and len(asset_rows) <= 256
             and all(isinstance(row, dict) for row in asset_rows), 'hero_asset_projection_rows')
        result.update(hero_asset_output_enabled=True,
                      hero_asset_catalog_sha256=asset_projection['catalog_sha256'])
    cached_rows = []
    if cached_label_projector is not None:
        cached_projection = cached_label_projector.project(frame)
        need(cached_projection.get('schema') == 'overwatch-decoder.guarded-cached-labels/1'
             and cached_projection.get('profile_sha256') == projector.hash
             and cached_projection.get('target') == projector.target
             and cached_projection.get('timing') == base_projection.get('timing')
             and cached_projection.get('privacy') == 'private'
             and cached_projection.get('gameplay_semantics_validated') is False
             and cached_projection.get('public_state_eligible') is False,
             'cached_label_projection_source_mismatch')
        cached_rows = cached_projection.get('labels', [])
    category_rows = []
    if category_projector is not None:
        category_projection = category_projector.project(frame, gap=bool(gap_before['skipped_slots']))
        need(category_projection.get('schema') == 'overwatch-decoder.guarded-actor-categories/1'
             and category_projection.get('profile_sha256') == projector.hash
             and category_projection.get('target') == projector.target
             and category_projection.get('timing') == base_projection.get('timing')
             and category_projection.get('public_state_eligible') is False
             and category_projection.get('visibility') == 'unknown'
             and category_projection.get('contract_sha256') == category_projector.contract_sha256
             and category_projection.get('source_evidence') == category_projector.source
             and category_projection.get('recording_manifest_sha256') == category_projector.recording_manifest_sha256
             and category_projection.get('self_controller_object_key') == category_projector.self_controller_object_key,
             'category_projection_source_mismatch')
        category_rows = category_projection.get('rows', [])
        result['category_contract_sha256'] = category_projection['contract_sha256']
    result['category_output_enabled'] = category_projector is not None
    result['cached_label_output_enabled'] = cached_label_projector is not None
    result['private_battletag_output_enabled'] = include_private_battletags
    result['schema'] = 'overwatch-decoder.entity-relations-export/1'
    result['source_artifacts'] = source
    result['recording'] = completeness
    result['gap_before'] = gap_before
    if forward_owner_projector is not None:
        result['forward_owner_projection'] = forward_owner_projector.project(
            frame, source, gap=bool(gap_before['skipped_slots']))
    for relation in result['relations']:
        relation.update(name=None, team=None, hero_label=None, visibility='unknown',
                        position_candidate=None, hero_resource_guid_candidate=None,
                        health_candidate=health.get(relation['body_object_key']))
        if health_ratio_contracts:
            relation['health_ratio_candidate'] = ratios.get(relation['body_object_key'])
        if ammunition_projector is not None:
            relation.update(ammunition_candidate=None, ammunition_evidence_ref=None,
                            ammunition_reason=relation.get('reason') or 'ammunition_not_bound')
            if relation['relation_status'] == 'observed':
                matches = [(i, row) for i, row in enumerate(ammunition_rows)
                           if row.get('controller_object_key') == relation['controller_object_key']
                           and row.get('body_object_key') == relation['body_object_key']]
                need(len(matches) <= 1, 'ambiguous_ammunition_join')
                if matches:
                    index, candidate = matches[0]
                    need(candidate.get('public_state_eligible') is False
                         and candidate.get('visibility') == 'unknown'
                         and candidate.get('is_firing') is None and candidate.get('reloading') is None,
                         'unsupported_ammunition_semantics')
                    relation.update(ammunition_candidate=candidate.get('ammunition_candidate'),
                        ammunition_reason=candidate.get('reason'),
                        ammunition_evidence_ref='/ammunition_projection/rows/'+str(index))
        if cached_label_projector is not None:
            relation['cached_label_candidate'] = None
        if category_projector is not None:
            relation.update(raw_category_candidate=None, team_candidate=None, relative_allegiance_candidate=None)
        if hero_asset_projector is not None:
            relation.update(hero_asset_label_candidate=None, hero_asset_label_evidence=None,
                            hero_asset_label_reason=relation.get('reason') or 'relation_unknown')
        if relation['relation_status'] != 'observed':
            continue
        if category_projector is not None:
            matches = [row for row in category_rows
                       if row.get('controller_object_key') == relation['controller_object_key']
                       and row.get('body_object_key') == relation['body_object_key']]
            if gap_before['skipped_slots']:
                relation['category_reason'] = 'gap_before_frame'
            elif len(matches) != 1:
                relation['category_reason'] = 'missing_or_ambiguous_category_for_exact_object_keys'
            elif matches[0].get('status') != 'observed':
                relation['category_reason'] = matches[0].get('reason') or 'category_projection_unknown'
            else:
                category = matches[0]
                if category.get('reason') is not None:
                    relation['category_reason'] = category['reason']
                relation.update(raw_category_candidate=category['raw_category_candidate'],
                    team_candidate=category['team_candidate'],
                    relative_allegiance_candidate=category['relative_allegiance_candidate'])
                relation['category_evidence'] = dict(fields=category['evidence'],
                    self_fields=category.get('self_evidence'), mode_id=category_projection.get('mode_id'),
                    mode_scope=category.get('mode_scope'),
                    self_controller_object_key=category_projection.get('self_controller_object_key'),
                    native_review_sha256=category_projection.get('native_review_sha256'),
                    roster_review_sha256=category_projection.get('roster_review_sha256'),
                    contract_sha256=category_projection['contract_sha256'], profile_sha256=projector.hash,
                    build_sha256=projector.target['executable_sha256'], acquisition=source.get('acquisition'),
                    validation_status='guarded_category_roster_research', public_state_eligible=False)
        if cached_label_projector is not None:
            matches = [row for row in cached_rows if row.get('status') == 'observed'
                       and row.get('controller_object_key') == relation['controller_object_key']
                       and row.get('body_object_key') == relation['body_object_key']]
            if gap_before['skipped_slots']:
                relation['cached_label_reason'] = 'gap_before_frame'
            elif len(matches) != 1:
                relation['cached_label_reason'] = 'missing_or_ambiguous_cached_label_for_exact_object_keys'
            else:
                cached = matches[0]
                relation['cached_label_candidate'] = cached['candidate_cached_label']
                relation['cached_label_evidence'] = dict(fields=cached['evidence'], privacy='private',
                    profile_sha256=projector.hash, build_sha256=projector.target['executable_sha256'],
                    acquisition=source.get('acquisition'), validation_status='guarded_native_cache_string_research',
                    gameplay_semantics_validated=False, public_state_eligible=False)
        if name_projector is not None:
            matches = [row for row in name_rows if row.get('status') == 'observed'
                       and row.get('controller_object_key') == relation['controller_object_key']
                       and row.get('body_object_key') == relation['body_object_key']]
            if gap_before['skipped_slots']:
                relation['name_reason'] = 'gap_before_frame'
            elif len(matches) != 1:
                relation['name_reason'] = 'missing_or_ambiguous_name_for_exact_object_keys'
            else:
                name = matches[0]
                relation['name'] = name['display_name']
                relation['name_evidence'] = dict(fields=name['evidence'], display_transform=name['display_transform'],
                    profile_sha256=projector.hash, build_sha256=projector.target['executable_sha256'],
                    validation_status='guarded_display_name_research', public_state_eligible=False)
                # Never serialize full-name bytes or their brute-forceable hash
                # in ordinary display-name output.
                if include_private_battletags:
                    relation['private_battletag'] = name['private_name']
                    relation['private_name_bytes_sha256'] = name.get('name_bytes_sha256')
        prefix = relation['controller_prefix']
        try:
            relation['position_candidate'] = observed_field(projector, frame, prefix + '_body_0000_position_candidate', 'f32x3')
        except InvalidRecording as error:
            relation['position_reason'] = str(error)
        try:
            words = [observed_field(projector, frame, prefix + suffix, 'i32') for suffix in (
                '_part83_0000_hero_resource_low_candidate_i32', '_part83_0000_hero_resource_high_candidate_i32',
                '_body_0000_hero_resource_low_candidate_i32', '_body_0000_hero_resource_high_candidate_i32')]
            controller = (words[0]['value'] & 0xffffffff) | ((words[1]['value'] & 0xffffffff) << 32)
            body = (words[2]['value'] & 0xffffffff) | ((words[3]['value'] & 0xffffffff) << 32)
            need(controller == body, 'controller_body_hero_resource_mismatch')
            relation['hero_resource_guid_candidate'] = dict(value=f'0x{body:016X}', controller_body_match=True,
                evidence=words, validation_status='matching_guarded_resource_research', hero_label=None,
                public_state_eligible=False)
        except InvalidRecording as error:
            relation['hero_resource_reason'] = str(error)
        if hero_projector is not None:
            # A resource number or controller ordinal alone never joins actors.
            matches = [row for row in hero_rows if row.get('status') == 'observed'
                       and row.get('controller_object_key') == relation['controller_object_key']
                       and row.get('body_object_key') == relation['body_object_key']]
            resource = relation['hero_resource_guid_candidate']
            if gap_before['skipped_slots']:
                relation['hero_label_reason'] = 'gap_before_frame'
            elif len(matches) != 1:
                relation['hero_label_reason'] = 'missing_or_ambiguous_hero_for_exact_object_keys'
            elif resource is None or matches[0].get('resource_guid') != resource['value']:
                relation['hero_label_reason'] = 'hero_projection_resource_mismatch'
            else:
                hero = matches[0]
                relation['hero_label'] = hero['hero_label']
                relation['hero_label_evidence'] = dict(mapping=hero['mapping_evidence'], fields=hero['evidence'],
                    catalog_sha256=hero_projection['catalog_sha256'], profile_sha256=projector.hash,
                    build_sha256=projector.target['executable_sha256'],
                    validation_status='guarded_build_resource_label_research', public_state_eligible=False)
        if hero_asset_projector is not None:
            matches = [row for row in asset_rows
                       if row.get('controller_object_key') == relation['controller_object_key']
                       and row.get('body_object_key') == relation['body_object_key']]
            resource = relation['hero_resource_guid_candidate']
            if gap_before['skipped_slots']:
                reason = 'gap_before_frame'
            elif len(matches) != 1:
                reason = 'missing_or_ambiguous_hero_asset_for_exact_object_keys'
            elif matches[0].get('status') != 'observed':
                reason = matches[0].get('reason') or 'hero_asset_projection_unknown'
            elif resource is None or matches[0].get('resource_guid') != resource['value']:
                reason = 'hero_asset_projection_resource_mismatch'
            else:
                hero = matches[0]
                need(hero.get('binding_scope') == 'controller_and_body'
                     and hero.get('runtime_ui_validated') is False
                     and isinstance(hero.get('hero_label_candidate'), str)
                     and isinstance(hero.get('mapping_evidence'), dict)
                     and hero['mapping_evidence'].get('label') == hero['hero_label_candidate']
                     and hero['mapping_evidence'].get('resource_guid') == resource['value']
                     and hero['mapping_evidence'].get('build_sha256') == projector.target['executable_sha256']
                     and hero['mapping_evidence'].get('runtime_ui_validated') is False
                     and hero['mapping_evidence'].get('public_state_eligible') is False,
                     'hero_asset_projection_candidate_mismatch')
                reason = None
                relation['hero_asset_label_candidate'] = hero['hero_label_candidate']
                relation['hero_asset_label_evidence'] = copy.deepcopy(dict(
                    mapping=hero['mapping_evidence'], fields=hero['evidence'],
                    catalog_sha256=asset_projection['catalog_sha256'], profile_sha256=projector.hash,
                    build_sha256=projector.target['executable_sha256'],
                    controller_object_key=relation['controller_object_key'], body_object_key=relation['body_object_key'],
                    source_target=projector.target, frame_timing=base_projection['timing'],
                    acquisition=source.get('acquisition'), resource_guid=resource['value'],
                    binding_scope='controller_and_body', validation_status='guarded_typed_asset_resource_candidate',
                    runtime_ui_validated=False, public_state_eligible=False, visibility='unknown'))
            relation['hero_asset_label_reason'] = reason
    if finite_context_projector is not None:
        finite_context_projector.compose(result, frame)
    return result


def iter_validated_frames(samples, index, verification, manifest, projector):
    """Consume precisely the native-verified prefix; rehash every reopened byte."""
    sample_hash, index_hash, json_hash = hashlib.sha256(), hashlib.sha256(), hashlib.sha256()
    offset = lines = frames = next_slot = skips = 0
    last_end = -1
    origin = None
    with Path(samples).open('rb') as sample_file, Path(index).open('rb') as index_file:
        for chunk in range(verification['verified_chunks']):
            entry_bytes = index_file.readline(4097)
            need(entry_bytes.endswith(b'\n') and len(entry_bytes) <= 4096, 'invalid_index_line')
            entry = parse(entry_bytes)
            need(entry.get('schema') == 'overwatch-decoder.field-recording-chunk/1' and entry.get('sequence') == chunk
                 and entry.get('offset') == offset and entry.get('first_line') == lines, 'chunk_order_or_gap')
            size, raw_size = entry['compressed_bytes'], entry['json_bytes']
            need(integer(size) and 18 <= size <= 1048576 + 8192 and integer(raw_size) and 0 < raw_size <= 1048576,
                 'chunk_size_bound')
            member = sample_file.read(size)
            need(len(member) == size and digest(member) == entry['compressed_sha256'], 'chunk_compressed_hash')
            decoder = zlib.decompressobj(31)
            raw = decoder.decompress(member, raw_size + 1)
            need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail, 'invalid_gzip_member')
            need(len(raw) == raw_size and digest(raw) == entry['json_sha256'], 'chunk_json_hash')
            raw_lines = raw.splitlines(keepends=True)
            need(len(raw_lines) == entry['lines'] and all(x.endswith(b'\n') and len(x) <= 512 * 1024 for x in raw_lines),
                 'chunk_line_count_or_boundary')
            for line in raw_lines:
                frame = parse(line)
                need(frame.get('profile_sha256') == projector.hash and frame.get('target') == projector.target,
                     'frame_profile_or_target_mismatch')
                if frame.get('kind') == 'summary':
                    continue
                need(frame.get('kind') == 'frame' and frame.get('source') == 'process_memory', 'unsupported_frame')
                timing = tuple(frame.get(k) for k in ['monotonic_origin_ticks', 'monotonic_frequency',
                                                    'requested_interval_ms', 'utc_origin'])
                if origin is None:
                    origin = timing
                need(timing == origin, 'changed_time_origin')
                missed, slot = frame.get('skipped_intervals_before'), frame.get('scheduled_slot')
                need(integer(missed) and missed >= 0 and frame.get('sequence') == frames
                     and slot == next_slot + missed and frame.get('skipped_intervals_total') == skips + missed,
                     'frame_order_or_skip_mismatch')
                start, end = frame.get('start_ticks'), frame.get('end_ticks')
                need(integer(start) and integer(end) and last_end <= start <= end, 'frame_time_order')
                interval = max(1, int(timing[2] * timing[1] / 1000))
                need(frame.get('scheduled_ticks') == timing[0] + slot * interval, 'scheduled_time_mismatch')
                gap = dict(skipped_slots=missed, previous_end_ticks=None if last_end < 0 else last_end,
                           current_start_ticks=start, previous_values_carried=False)
                yield frame, gap
                frames += 1
                next_slot, skips, last_end = slot + 1, skips + missed, end
            offset += size
            lines += len(raw_lines)
            sample_hash.update(member)
            index_hash.update(entry_bytes)
            json_hash.update(raw)
        need(offset == verification['verified_compressed_bytes'] and lines == verification['verified_lines']
             and frames == verification['frames'], 'verified_prefix_counts')
        need(sample_hash.hexdigest() == verification['samples_prefix_sha256']
             and index_hash.hexdigest() == verification['index_prefix_sha256']
             and json_hash.hexdigest() == verification['json_prefix_sha256'], 'verified_prefix_changed')


def export_recording(recording, acquisition, output, verifier_command, allow_partial=False,
                     expected_profile=None, expected_build=None, health_contracts=(),
                     name_projector=None, include_private_battletags=False, name_recipe_sha256=None, hero_projector=None,
                     cached_label_projector=None, cached_label_recipe_sha256=None, category_projector=None,
                     hero_asset_projector=None, hero_asset_catalog=None, hero_asset_artifacts=None,
                     hero_asset_locale='enUS', forward_owner_contract=None,
                     forward_owner_artifacts=None, forward_owner_health_contracts=(),
                     forward_owner_category_contract=None, forward_owner_category_artifacts=None,
                     raw_category_contract=None, context_controller_contract=None, context_projection_artifacts=None,
                     ammunition_projector=None, health_ratio_contracts=()):
    recording, output = Path(recording).resolve(), Path(output).resolve()
    need(not output.is_relative_to(recording), 'output_inside_source')
    need(not output.exists(), 'output_exists')
    need((recording/'profile.json').stat().st_size <= 262144 and (recording/'manifest.json').stat().st_size <= 262144,
         'recording_metadata_size')
    raw_profile, raw_manifest = (recording/'profile.json').read_bytes(), (recording/'manifest.json').read_bytes()
    need(bool(hero_asset_catalog) == bool(hero_asset_artifacts), 'hero_asset_catalog_and_artifacts_required_together')
    need(hero_asset_projector is None or not hero_asset_catalog, 'hero_asset_projector_and_paths_mutually_exclusive')
    if hero_asset_catalog:
        hero_asset_projector = load_hero_asset_projector(raw_profile, hero_asset_catalog, hero_asset_artifacts, hero_asset_locale)
    projector, manifest = GuardedRelations(raw_profile), parse(raw_manifest)
    need(manifest.get('profile_sha256') == projector.hash and manifest.get('target') == projector.target,
         'manifest_profile_or_target_mismatch')
    need(expected_profile is None or expected_profile == projector.hash, 'unexpected_profile')
    need(expected_build is None or expected_build == projector.target['executable_sha256'], 'unexpected_build')
    acquisition_refs = acquisition_provenance(acquisition, projector.hash, projector.target)
    verify_health_ratio_sources(health_ratio_contracts,
                                dict(profile_sha256=projector.hash, acquisition=acquisition_refs))
    if ammunition_projector is not None:
        verify_ammunition_source(ammunition_projector,
                                 dict(profile_sha256=projector.hash, acquisition=acquisition_refs))
    need(bool(forward_owner_contract) == bool(forward_owner_artifacts),
         'forward_contract_and_artifacts_required_together')
    need(bool(forward_owner_category_contract) == bool(forward_owner_category_artifacts),
         'forward_category_contract_and_artifacts_required_together')
    need(not forward_owner_category_contract or forward_owner_contract, 'forward_category_requires_owner')
    need(not forward_owner_health_contracts or forward_owner_contract,
         'forward_health_requires_forward_contract')
    forward = None
    if forward_owner_contract:
        from forward_owner_projection import load_forward_projection
        forward = load_forward_projection(raw_profile, forward_owner_contract, forward_owner_artifacts,
                                          forward_owner_health_contracts, hero_asset_projector,
                                          forward_owner_category_contract, forward_owner_category_artifacts)
        forward.verify_source(dict(profile_sha256=projector.hash, acquisition=acquisition_refs))
    need(not include_private_battletags or name_projector is not None, 'private_battletag_source_required')
    need(name_projector is None or (name_recipe_sha256 is not None
         and name_recipe_sha256 == acquisition_refs['recipe_sha256']), 'unverified_name_recipe')
    need(cached_label_projector is None or (cached_label_recipe_sha256 is not None
         and cached_label_recipe_sha256 == acquisition_refs['recipe_sha256']), 'unverified_cached_label_recipe')
    need(category_projector is None or
         all(category_projector.source.get(key) == acquisition_refs[key]
             for key in ('recipe_sha256', 'evidence_sha256')), 'category_acquisition_mismatch')
    need(category_projector is None or category_projector.recording_manifest_sha256 == digest(raw_manifest),
         'category_recording_mismatch')
    verification = native_verify(recording, verifier_command, allow_partial)
    need(allow_partial or (verification.get('valid') is True and verification.get('complete') is True),
         'partial_source_requires_opt_in')
    need(verification['profile_sha256'] == projector.hash, 'verified_profile_changed')
    completeness = dict(complete=verification['complete'] and verification['valid'], status=verification['status'],
        partial=not (verification['complete'] and verification['valid']), error_code=verification.get('error_code'),
        unverified_compressed_bytes=verification.get('unverified_compressed_bytes'),
        unverified_index_bytes=verification.get('unverified_index_bytes'), continuity_across_gaps=False)
    source = dict(profile_sha256=projector.hash, manifest_sha256=digest(raw_manifest),
                  samples_prefix_sha256=verification['samples_prefix_sha256'],
                  index_prefix_sha256=verification['index_prefix_sha256'], acquisition=acquisition_refs)
    context_options = (raw_category_contract, context_controller_contract, context_projection_artifacts)
    need(not any(context_options) or all(context_options), 'finite_context_inputs_required_together')
    need(not any(context_options) or category_projector is None, 'legacy_and_context_categories_mutually_exclusive')
    finite_context = None
    if all(context_options):
        from finite_context import FiniteContextProjection
        finite_context = FiniteContextProjection(raw_profile,
            bounded_local_bytes(raw_category_contract, 262144, 'raw_category_contract_size'),
            bounded_local_bytes(context_controller_contract, 262144, 'context_controller_contract_size'),
            load_local_artifacts(context_projection_artifacts, 'finite_context'))
        finite_context.source_pins(source)
    output.parent.mkdir(parents=True, exist_ok=True)
    count = relations = positions = heroes = gaps = skipped_slots = 0
    health_count = names_count = hero_labels_count = cached_labels_count = category_count = 0
    team_count = allegiance_count = asset_labels_count = 0
    ammunition_count = health_ratio_count = 0
    forward_counts = dict(observed_relations=0, observed_positions=0,
                         observed_health_candidates=0, observed_controller_hero_candidates=0)
    if forward is not None and forward.category is not None:
        forward_counts['observed_raw_category_candidates'] = 0
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=output.parent, prefix='.entity-export-',
                                         suffix='.partial', delete=False) as file:
            temporary = Path(file.name)
            for frame, gap in iter_validated_frames(recording/'samples.jsonl.gz', recording/'chunks.jsonl', verification, manifest, projector):
                result = project_frame(projector, frame, source, completeness, gap, health_contracts,
                                       name_projector, include_private_battletags, hero_projector, cached_label_projector, category_projector,
                                       hero_asset_projector=hero_asset_projector, forward_owner_projector=forward,
                                       finite_context_projector=finite_context, ammunition_projector=ammunition_projector,
                                       health_ratio_contracts=health_ratio_contracts)
                file.write(json.dumps(result, separators=(',', ':'), allow_nan=False) + '\n')
                count += 1
                gaps += gap['skipped_slots'] > 0
                skipped_slots += gap['skipped_slots']
                relations += sum(r['relation_status'] == 'observed' for r in result['relations'])
                positions += sum(r['position_candidate'] is not None for r in result['relations'])
                heroes += sum(r['hero_resource_guid_candidate'] is not None for r in result['relations'])
                health_count += sum(r['health_candidate'] is not None for r in result['relations'])
                health_ratio_count += sum(r.get('health_ratio_candidate') is not None for r in result['relations'])
                ammunition_count += sum(r.get('ammunition_candidate') is not None for r in result['relations'])
                names_count += sum(r['name'] is not None for r in result['relations'])
                asset_labels_count += sum(r.get('hero_asset_label_candidate') is not None for r in result['relations'])
                hero_labels_count += sum(r['hero_label'] is not None for r in result['relations'])
                cached_labels_count += sum(r.get('cached_label_candidate') is not None for r in result['relations'])
                category_count += sum(r.get('raw_category_candidate') is not None for r in result['relations'])
                team_count += sum(r.get('team_candidate') is not None for r in result['relations'])
                allegiance_count += sum(r.get('relative_allegiance_candidate') is not None for r in result['relations'])
                for row in result.get('forward_owner_projection', {}).get('relations', []):
                    forward_counts['observed_relations'] += row['relation_status'] == 'observed'
                    forward_counts['observed_positions'] += row['position_candidate'] is not None
                    forward_counts['observed_health_candidates'] += row['health_candidate'] is not None
                    forward_counts['observed_controller_hero_candidates'] += row['controller_hero_asset_label_candidate'] is not None
                    if forward.category is not None:
                        forward_counts['observed_raw_category_candidates'] += row['raw_category_candidate'] is not None
            need((recording/'profile.json').read_bytes() == raw_profile and (recording/'manifest.json').read_bytes() == raw_manifest,
                 'metadata_changed')
            file.flush()
            os.fsync(file.fileno())
        # Atomic create without overwriting a destination that appeared meanwhile.
        os.link(temporary, output)
        report = dict(schema='overwatch-decoder.entity-relations-export-result/1', frames=count, observed_relations=relations,
                    observed_positions=positions, matching_hero_resources=heroes, observed_health_candidates=health_count,
                    observed_display_names=names_count, observed_hero_labels=hero_labels_count,
                    observed_cached_label_candidates=cached_labels_count, observed_category_candidates=category_count,
                    observed_team_candidates=team_count, observed_relative_allegiance_candidates=allegiance_count,
                    frames_after_skipped_slots=gaps, skipped_slots=skipped_slots,
                    source_complete=completeness['complete'], source_status=completeness['status'],
                    output_sha256=file_digest(output), public_state_eligible=False)
        if hero_asset_projector is not None:
            report.update(observed_hero_asset_label_candidates=asset_labels_count,
                          hero_asset_catalog_sha256=hero_asset_projector.catalog.hash)
        if ammunition_projector is not None:
            report.update(observed_ammunition_candidates=ammunition_count,
                          ammunition_contract_sha256=ammunition_projector.contract_sha256)
        if health_ratio_contracts:
            report.update(observed_health_ratio_candidates=health_ratio_count,
                          health_ratio_contract_sha256=[c.contract_sha256 for c in health_ratio_contracts],
                          health_ratio_projection=health_ratio_projection(health_ratio_contracts))
        if finite_context is not None:
            report['context_projection_contract_sha256'] = finite_context.contracts.copy()
        if forward is not None:
            report['forward_owner_output'] = dict(forward_counts,
                contract_sha256=forward.projector.contract_hash, current_displayed_body=None)
            if forward.category is not None:
                report['forward_owner_output'].update(
                    forward_category_contract_sha256=forward.category.contract_sha256,
                    forward_category_native_review_sha256=forward.category.category_fields.native_review_sha256)
        return report
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['recording', 'acquisition', 'output', 'observer']:
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--dotnet', type=Path)
    parser.add_argument('--health-contract', type=Path, action='append', default=[],
                        help='optional separately validated PoolHealthContract descriptor JSON')
    parser.add_argument('--health-ratio-contract', type=Path, action='append', default=[],
                        help='optional source-pinned paired-vector pool-ratio contract JSON')
    parser.add_argument('--health-ratio-native-review', type=Path,
                        help='local build-bound native calculation review pinned by each ratio contract')
    parser.add_argument('--allow-partial', action='store_true')
    parser.add_argument('--include-display-names', action='store_true')
    parser.add_argument('--include-private-battletags', action='store_true',
                        help='explicitly opt in to full private BattleTags and name-byte hashes')
    parser.add_argument('--name-recipe-sha256', help='separately validated account/name acquisition recipe hash')
    parser.add_argument('--include-cached-labels', action='store_true',
                        help='opt in to private native cache strings with unvalidated gameplay semantics')
    parser.add_argument('--cached-label-recipe-sha256', help='separately validated keyed native cache acquisition recipe hash')
    parser.add_argument('--category-contract', type=Path, help='optional evidence-bound category/roster contract JSON')
    parser.add_argument('--category-artifacts', type=Path, help='explicit local SHA256-to-category-evidence-path JSON map')
    parser.add_argument('--ammunition-contract', type=Path, help='optional reviewed actor-bound sampled ammunition contract')
    parser.add_argument('--ammunition-artifacts', type=Path, help='explicit local SHA256-to-ammunition-evidence-path JSON map')
    parser.add_argument('--raw-category-contract', type=Path, help='finite source-bound raw category contract; no team inference')
    parser.add_argument('--context-controller-contract', type=Path, help='finite source-bound neutral controller selector contract')
    parser.add_argument('--context-projection-artifacts', type=Path, help='explicit local SHA256-to-evidence-path map for both finite contracts')
    parser.add_argument('--hero-catalog', type=Path, help='optional build-scoped reviewed hero mapping JSON')
    parser.add_argument('--hero-artifacts', type=Path, help='explicit local SHA256-to-artifact-path JSON map')
    parser.add_argument('--hero-locale', default='enUS')
    parser.add_argument('--hero-asset-catalog', type=Path, help='optional build-scoped typed hero asset candidates')
    parser.add_argument('--hero-asset-artifacts', type=Path, help='explicit local SHA256-to-asset-path JSON map')
    parser.add_argument('--hero-asset-locale', default='enUS')
    parser.add_argument('--forward-owner-contract', type=Path)
    parser.add_argument('--forward-owner-artifacts', type=Path)
    parser.add_argument('--forward-owner-health-contract', action='append', default=[], type=Path)
    parser.add_argument('--forward-owner-category-contract', type=Path)
    parser.add_argument('--forward-owner-category-artifacts', type=Path)
    parser.add_argument('--expect-profile-sha256')
    parser.add_argument('--expect-build-sha256')
    args = parser.parse_args()
    command = ([str(args.dotnet)] if args.dotnet else []) + [str(args.observer)]
    try:
        contracts = []
        if args.health_contract or args.forward_owner_contract:
            # Optional composition uses the independently tested health module.
            sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
            from overwatch_decoder.health_projection import PoolHealthContract
            profile_bytes = (args.recording/'profile.json').read_bytes()
            evidence_hash = parse((args.acquisition/'manifest.json').read_bytes())['evidence_sha256']
            for path in args.health_contract:
                need(path.stat().st_size <= 262144, 'health_descriptor_size')
                descriptor = parse(path.read_bytes())
                need(descriptor.get('acquisition_evidence_sha256') == evidence_hash, 'health_acquisition_mismatch')
                contracts.append(PoolHealthContract.from_profile(profile_bytes, **descriptor))
        need(bool(args.health_ratio_contract) == bool(args.health_ratio_native_review),
             'health_ratio_contract_and_review_required_together')
        ratio_contracts = []
        if args.health_ratio_contract:
            need(len(args.health_ratio_contract) <= 128, 'health_ratio_contract_bound')
            sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
            from overwatch_decoder.health_ratio import PoolRatioContract
            profile_bytes = bounded_local_bytes(args.recording/'profile.json', 262144, 'recording_profile_size')
            review_bytes = bounded_local_bytes(args.health_ratio_native_review, 8*1024*1024, 'health_ratio_review_size')
            for path in args.health_ratio_contract:
                ratio_contracts.append(PoolRatioContract.from_profile(profile_bytes,
                    bounded_local_bytes(path, 262144, 'health_ratio_contract_size'), review_bytes))
        name_projector = None
        if args.include_display_names or args.include_private_battletags:
            need(args.name_recipe_sha256 is not None, 'validated_name_recipe_hash_required')
            from names import GuardedNames
            name_projector = GuardedNames((args.recording/'profile.json').read_bytes())
        need(bool(args.hero_catalog) == bool(args.hero_artifacts), 'hero_catalog_and_artifacts_required_together')
        hero_projector = None
        if args.hero_catalog:
            hero_projector = load_hero_projector(
                bounded_local_bytes(args.recording/'profile.json', 262144, 'recording_profile_size'),
                args.hero_catalog, args.hero_artifacts, args.hero_locale)
        cached_label_projector = None
        if args.include_cached_labels:
            need(args.cached_label_recipe_sha256 is not None, 'validated_cached_label_recipe_hash_required')
            from cached_labels import GuardedCachedLabels
            cached_label_projector = GuardedCachedLabels(
                bounded_local_bytes(args.recording/'profile.json', 262144, 'recording_profile_size'))
        need(bool(args.category_contract) == bool(args.category_artifacts), 'category_contract_and_artifacts_required_together')
        category_projector = None
        if args.category_contract:
            category_projector = load_category_projector(
                bounded_local_bytes(args.recording/'profile.json', 262144, 'recording_profile_size'),
                args.category_contract, args.category_artifacts)
        need(bool(args.ammunition_contract) == bool(args.ammunition_artifacts),
             'ammunition_contract_and_artifacts_required_together')
        ammunition_projector = None
        if args.ammunition_contract:
            ammunition_projector = load_ammunition_projector(
                bounded_local_bytes(args.recording/'profile.json', 262144, 'recording_profile_size'),
                args.ammunition_contract, args.ammunition_artifacts)
        report = export_recording(args.recording, args.acquisition, args.output, command, args.allow_partial,
                                  args.expect_profile_sha256, args.expect_build_sha256, contracts,
                                  name_projector, args.include_private_battletags, args.name_recipe_sha256, hero_projector,
                                  cached_label_projector, args.cached_label_recipe_sha256, category_projector,
                                  hero_asset_catalog=args.hero_asset_catalog, hero_asset_artifacts=args.hero_asset_artifacts,
                                  hero_asset_locale=args.hero_asset_locale, forward_owner_contract=args.forward_owner_contract,
                                  forward_owner_artifacts=args.forward_owner_artifacts,
                                  forward_owner_health_contracts=args.forward_owner_health_contract,
                                  forward_owner_category_contract=args.forward_owner_category_contract,
                                  forward_owner_category_artifacts=args.forward_owner_category_artifacts,
                                  raw_category_contract=args.raw_category_contract,
                                  context_controller_contract=args.context_controller_contract,
                                  context_projection_artifacts=args.context_projection_artifacts,
                                  ammunition_projector=ammunition_projector, health_ratio_contracts=ratio_contracts)
    except (InvalidRecording, ValueError, KeyError, OSError, ImportError, subprocess.SubprocessError) as error:
        print(json.dumps(dict(schema='overwatch-decoder.entity-relations-export-result/1', complete=False, error=str(error))))
        return 2
    print(json.dumps(report))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
