#!/usr/bin/env python3
"""Aggregate hashed, verified semantic JSONL partitions as private research.

Each frame belongs to one fixed window by its end tick and is never carried to
another window. A declared primary owns each object's dynamic observations.
This tool reads saved local files only; it does not verify visibility or make an
atomic snapshot from asynchronous process-memory observations.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from fractions import Fraction
import hashlib
import heapq
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile

from ammunition_projection_validation import validate_source as validate_ammunition_source, validate_frame as validate_ammunition_frame, retain as retain_ammunition, attach_window as attach_ammunition_window
from health_ratio_validation import validate_projection as validate_ratio_projection, validate_candidate as validate_ratio_candidate

from hero_asset_validation import (validate_hero_asset_candidate, metadata as hero_asset_metadata, InvalidHeroAssetCandidate)
from forward_roster_projection import (validate_source as validate_forward_source,
    validate_frame as validate_forward_frame, attach_window as attach_forward_window)


MAX_SOURCE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_WINDOWS = 100000


class InvalidPartitions(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise InvalidPartitions(reason)


def integer(value):
    return type(value) is int


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def parse(raw):
    def unique(pairs):
        result = dict(pairs)
        need(len(result) == len(pairs), 'duplicate_json_key')
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(InvalidPartitions('nonfinite_json')))


def digest(value):
    need(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'invalid_digest')
    return value


def object_pair(value):
    need(isinstance(value, dict), 'invalid_object_pair')
    controller, body = value.get('controller_object_key'), value.get('body_object_key')
    need(isinstance(controller, str) and re.fullmatch('controller:[0-9a-f]{64}', controller)
         and isinstance(body, str) and re.fullmatch('body:[0-9a-f]{64}', body), 'invalid_object_pair')
    return controller, body


def configured_pair(row, allow_unresolved=False):
    if allow_unresolved and isinstance(row, dict) and row.get('body_object_key', 'absent') is None:
        controller = row.get('controller_object_key')
        need(isinstance(controller, str) and re.fullmatch('controller:[0-9a-f]{64}', controller),
             'invalid_unresolved_controller')
        return controller, None
    return object_pair(row)


def open_regular(path, maximum):
    file = os.fdopen(os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0)), 'rb')
    try:
        metadata = os.fstat(file.fileno())
        need(stat.S_ISREG(metadata.st_mode) and 0 < metadata.st_size <= maximum, 'source_size_or_type')
        return file, metadata.st_size
    except BaseException:
        file.close()
        raise


def origin_offset(timing, frequency):
    value = timing.get('utc_origin')
    need(isinstance(value, str), 'invalid_clock_anchor')
    try:
        utc = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as error:
        raise InvalidPartitions('invalid_clock_anchor') from error
    need(utc.tzinfo is not None, 'invalid_clock_anchor')
    delta = utc.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    micros = (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds
    return Fraction(micros * frequency, 1000000) - timing['monotonic_origin_ticks']


class Manifest:
    def __init__(self, path):
        self.path = Path(path).resolve()
        with open_regular(self.path, 262144)[0] as file:
            raw = file.read(262145)
        need(len(raw) <= 262144, 'manifest_size')
        self.hash = sha(raw)
        value = parse(raw)
        need(value.get('schema') == 'overwatch-decoder.partition-research-manifest/1', 'manifest_schema')
        for key in ('epoch_id', 'clock_domain_id'):
            need(isinstance(value.get(key), str) and 1 <= len(value[key]) <= 128, 'invalid_' + key)
        self.epoch, self.clock = value['epoch_id'], value['clock_domain_id']
        self.target = value.get('target', {})
        need(isinstance(self.target, dict) and integer(self.target.get('pid')) and self.target['pid'] > 0
             and integer(self.target.get('creation_file_time')) and self.target['creation_file_time'] > 0
             and self.target.get('architecture') == 'x64' and isinstance(self.target.get('image_name'), str), 'invalid_target')
        digest(self.target.get('executable_sha256'))
        self.frequency = value.get('monotonic_frequency')
        self.window = value.get('window_ticks')
        self.skew = value.get('maximum_skew_ticks')
        self.offset_tolerance = value.get('maximum_origin_offset_ticks')
        self.origin = value.get('window_origin_ticks', 0)
        need(all(integer(v) for v in (self.frequency, self.window, self.skew, self.offset_tolerance, self.origin))
             and 0 < self.frequency <= 10**12 and 0 < self.window <= self.skew <= 5 * self.frequency
             and 0 <= self.offset_tolerance <= self.frequency and self.origin >= 0, 'invalid_time_bounds')
        roster = value.get('roster')
        self.allow_unresolved = value.get('allow_unresolved_bodies', False)
        need(type(self.allow_unresolved) is bool and (not self.allow_unresolved
             or value.get('observation_mode') == 'raw-candidates'), 'invalid_unresolved_body_policy')
        need(isinstance(roster, list) and 1 <= len(roster) <= 128, 'invalid_roster')
        self.roster = {}
        controllers, bodies = set(), set()
        for row in roster:
            pair = configured_pair(row, self.allow_unresolved)
            need(pair not in self.roster and pair[0] not in controllers and (pair[1] is None or pair[1] not in bodies),
                 'ambiguous_roster_identity')
            need(isinstance(row.get('primary_source_id'), str), 'primary_source_required')
            self.roster[pair] = row['primary_source_id']
            controllers.add(pair[0]); bodies.add(pair[1])
        sources = value.get('sources')
        need(isinstance(sources, list) and 1 <= len(sources) <= 16, 'invalid_source_count')
        self.sources = {}
        total = 0
        for row in sources:
            source_id = row.get('source_id')
            need(isinstance(source_id, str) and re.fullmatch('[A-Za-z0-9_-]{1,64}', source_id)
                 and source_id not in self.sources, 'invalid_source_id')
            for key in ('sha256', 'profile_sha256', 'recording_manifest_sha256', 'acquisition_manifest_sha256'):
                digest(row.get(key))
            need(isinstance(row.get('path'), str) and row['path'] and '://' not in row['path'], 'invalid_source_path')
            path = Path(row['path'])
            if not path.is_absolute():
                path = self.path.parent / path
            path = path.resolve()
            with open_regular(path, MAX_SOURCE_BYTES)[0] as file:
                size = os.fstat(file.fileno()).st_size
                hashed, read = hashlib.sha256(), 0
                while True:
                    data = file.read(min(1048576, MAX_SOURCE_BYTES + 1 - read))
                    if not data:
                        break
                    read += len(data)
                    need(read <= MAX_SOURCE_BYTES, 'source_size_or_type')
                    hashed.update(data)
                observed = hashed.hexdigest()
            need(observed == row['sha256'], 'source_hash_mismatch')
            total += size
            need(total <= MAX_TOTAL_BYTES, 'total_source_size')
            objects = row.get('objects')
            need(isinstance(objects, list) and 1 <= len(objects) <= 32, 'invalid_source_objects')
            pairs = [configured_pair(obj, self.allow_unresolved) for obj in objects]
            need(len(set(pairs)) == len(pairs) and set(pairs).issubset(self.roster), 'undeclared_source_object')
            need(type(row.get('allow_partial', False)) is bool, 'invalid_partial_policy')
            validate_ratio_projection(row.get('health_ratio_projection'))
            validate_forward_source(row)
            validate_ammunition_source(row)
            forward_controllers = {b['controller_object_key']
                for b in (row.get('forward_owner_projection') or {}).get('bindings', [])}
            need(all(body is not None or controller in forward_controllers for controller, body in pairs),
                 'finite_unresolved_body_requires_forward_source')
            self.sources[source_id] = dict(row, resolved_path=path, object_pairs=set(pairs))
        for pair, source_id in self.roster.items():
            need(source_id in self.sources and pair in self.sources[source_id]['object_pairs'], 'invalid_primary_source')
        self.offset_min = self.offset_max = None

    def clock_anchor(self, timing):
        offset = origin_offset(timing, self.frequency)
        self.offset_min = offset if self.offset_min is None else min(offset, self.offset_min)
        self.offset_max = offset if self.offset_max is None else max(offset, self.offset_max)
        need(self.offset_max - self.offset_min <= self.offset_tolerance, 'clock_anchor_disagreement')



def read_bracket(value, timing):
    start, end = value.get('read_start_ticks'), value.get('read_end_ticks')
    need(integer(start) and integer(end)
         and timing['start_ticks'] <= start <= end <= timing['end_ticks'], 'nested_read_bracket')


def nested_scope(value, timing, profile, build, budget=None, depth=0, *, declarations=None, objects=None, context_reference=None):
    """Check all nested claims, counting primitive leaves without recursing into them.

    Optional declarations/object bindings add the live validator's checks to this
    same traversal. No value or successful validation survives the current call.
    Dictionary keys are not nodes, matching the original serialized-value budget.
    """
    if budget is None:
        budget = [0]
    budget[0] += 1
    need(depth <= 24 and budget[0] <= 100000, 'nested_evidence_bound')

    def container(item, level):
        if isinstance(item, dict):
            if 'profile_sha256' in item:
                need(item['profile_sha256'] == profile, 'nested_profile_mismatch')
            if 'build_sha256' in item:
                need(item['build_sha256'] == build, 'nested_build_mismatch')
            if 'read_start_ticks' in item or 'read_end_ticks' in item:
                read_bracket(item, timing)
            if declarations is not None and 'field' in item:
                name = item['field']
                need(name in declarations, 'undeclared_evidence_field')
                if 'type' in item:
                    need(item['type'] == declarations[name], 'evidence_field_type_mismatch')
            if objects is not None and item is not context_reference:
                for key in ('controller_object_key', 'body_object_key'):
                    if key in item:
                        need(item[key] == objects[key], 'nested_object_mismatch')
            children = item.values()
        else:
            children = item
        # Charge every child, including primitive guard IDs, before traversing
        # containers. A primitive child at level 25 is still a depth violation.
        count = len(item)
        budget[0] += count
        need(budget[0] <= 100000 and (not count or level < 24), 'nested_evidence_bound')
        for child in children:
            if isinstance(child, (dict, list)):
                container(child, level + 1)

    if isinstance(value, (dict, list)):
        container(value, depth)


def row_evidence(row, key, frame):
    evidence = row.get(key)
    need(isinstance(evidence, dict) and evidence.get('profile_sha256') == frame['profile_sha256']
         and evidence.get('build_sha256') == frame['target']['executable_sha256']
         and evidence.get('public_state_eligible') is False, 'missing_or_unbound_semantic_evidence')
    fields = evidence.get('fields')
    need(isinstance(fields, list) and fields and all(isinstance(field, dict) for field in fields),
         'missing_semantic_read_evidence')
    for field in fields:
        read_bracket(field, frame['timing'])
    return evidence


def validate_row(row, frame, source):
    nested_scope(row, frame['timing'], frame['profile_sha256'], frame['target']['executable_sha256'])
    _validate_row_values(row, frame, source)


def _validate_row_values(row, frame, source):
    """Value checks after the caller has completed the full nested-scope walk."""
    profile, build, timing = frame['profile_sha256'], frame['target']['executable_sha256'], frame['timing']
    try:
        validate_hero_asset_candidate(row, frame)
    except InvalidHeroAssetCandidate as error:
        raise InvalidPartitions(str(error)) from error
    asset_pin = (frame.get('hero_asset_output_enabled'), frame.get('hero_asset_catalog_sha256'))
    need('_hero_asset_epoch_pin' not in source or source['_hero_asset_epoch_pin'] == asset_pin,
         'asset_epoch_configuration_changed')
    source['_hero_asset_epoch_pin'] = asset_pin
    validate_ratio_candidate(row, frame, source.get('health_ratio_projection'))
    position, health = row.get('position_candidate'), row.get('health_candidate')
    if position is not None:
        need(isinstance(position, dict) and position.get('profile_sha256') == profile
             and position.get('build_sha256') == build and position.get('source') == 'process_memory'
             and position.get('type') == 'f32x3', 'position_source_mismatch')
        values = position.get('value')
        need(isinstance(values, list) and len(values) == 3
             and all(type(value) in (int, float) and math.isfinite(value) for value in values), 'invalid_position')
        read_bracket(position, timing)
    if health is not None:
        need(isinstance(health, dict) and health.get('schema') == 'overwatch-decoder.actor-pool-sum/1'
             and health.get('source') == 'process_memory' and health.get('profile_sha256') == profile
             and health.get('build_sha256') == build and health.get('body_object_key') == row['body_object_key']
             and health.get('acquisition_evidence_sha256') == frame['source_artifacts']['acquisition']['evidence_sha256']
             and health.get('public_state_eligible') is False and health.get('visibility') == 'unknown'
             and health.get('atomic') is False and health.get('complete_supplied_membership_guarding') is True,
             'health_source_or_body_mismatch')
        read_bracket(health, timing)
        contributions = health.get('contributions')
        need(isinstance(contributions, list) and 1 <= len(contributions) <= 128
             and all(isinstance(part, dict) and type(part.get('value')) in (int, float)
                     and math.isfinite(part['value']) and part['value'] >= 0 for part in contributions),
             'invalid_health_contributions')
        indices = [part.get('pool_index') for part in contributions]
        need(all(integer(index) and index >= 0 for index in indices) and len(set(indices)) == len(indices),
             'duplicate_health_pool')
        for part in contributions:
            read_bracket(part, timing)
        need(type(health.get('raw_sum')) in (int, float) and math.isfinite(health['raw_sum'])
             and health['raw_sum'] == sum(part['value'] for part in contributions)
             and health['read_start_ticks'] == min(part['read_start_ticks'] for part in contributions)
             and health['read_end_ticks'] == max(part['read_end_ticks'] for part in contributions), 'health_sum_or_span_mismatch')
    resource = row.get('hero_resource_guid_candidate')
    if resource is not None:
        need(isinstance(resource, dict) and isinstance(resource.get('value'), str)
             and re.fullmatch('0x[0-9A-Fa-f]{16}', resource['value'])
             and resource.get('controller_body_match') is True, 'invalid_resource_candidate')
        words = resource.get('evidence')
        need(isinstance(words, list) and len(words) == 4 and all(isinstance(word, dict) and integer(word.get('value'))
             and -(1 << 31) <= word['value'] < (1 << 31) for word in words), 'missing_resource_word_evidence')
        for word in words:
            read_bracket(word, timing)
        controller = (words[0]['value'] & 0xffffffff) | ((words[1]['value'] & 0xffffffff) << 32)
        body = (words[2]['value'] & 0xffffffff) | ((words[3]['value'] & 0xffffffff) << 32)
        need(controller == body == int(resource['value'], 16), 'resource_word_mismatch')
    if row.get('hero_label') is not None:
        evidence = row_evidence(row, 'hero_label_evidence', frame)
        mapping = evidence.get('mapping', {})
        need(resource is not None and mapping.get('label') == row['hero_label']
             and mapping.get('resource_guid') == resource['value'] and mapping.get('build_sha256') == build,
             'hero_mapping_mismatch')
    for value_key, evidence_key in [('name', 'name_evidence'), ('cached_label_candidate', 'cached_label_evidence')]:
        value = row.get(value_key)
        if value is not None:
            need(isinstance(value, str) and value, 'invalid_label_value')
            evidence = row_evidence(row, evidence_key, frame)
            if value_key == 'cached_label_candidate':
                need(evidence.get('privacy') == 'private' and evidence.get('gameplay_semantics_validated') is False
                     and evidence.get('acquisition') == frame['source_artifacts']['acquisition'], 'cached_label_source_mismatch')
    if any(row.get(key) is not None for key in ('raw_category_candidate', 'team_candidate', 'relative_allegiance_candidate')):
        evidence = row_evidence(row, 'category_evidence', frame)
        scope = evidence.get('mode_scope', {})
        bounds = scope.get('frame_scope', {})
        need(evidence.get('acquisition') == frame['source_artifacts']['acquisition']
             and scope.get('recording_manifest_sha256') == source['recording_manifest_sha256']
             and all(integer(bounds.get(key)) for key in ('first_sequence', 'last_sequence', 'start_ticks', 'end_ticks'))
             and bounds['first_sequence'] <= timing['sequence'] <= bounds['last_sequence']
             and bounds['start_ticks'] <= timing['start_ticks'] <= timing['end_ticks'] <= bounds['end_ticks'],
             'category_scope_mismatch')
        if row.get('relative_allegiance_candidate') is not None:
            self_fields = evidence.get('self_fields')
            need(row['relative_allegiance_candidate'] in ('self', 'friendly', 'enemy')
                 and evidence.get('self_controller_object_key') in {pair[0] for pair in source['object_pairs']}
                 and isinstance(self_fields, list) and self_fields, 'category_self_evidence_missing')
            for field in self_fields:
                need(isinstance(field, dict), 'category_self_evidence_missing')
                read_bracket(field, timing)


def source_frames(manifest, source_id):
    source = manifest.sources[source_id]
    hashed, total, sequence, previous_end, anchor = hashlib.sha256(), 0, 0, None, None
    provenance = None
    with open_regular(source['resolved_path'], MAX_SOURCE_BYTES)[0] as file:
        while True:
            raw = file.readline(MAX_LINE_BYTES + 1)
            if not raw:
                break
            total += len(raw)
            need(total <= MAX_SOURCE_BYTES and len(raw) <= MAX_LINE_BYTES and raw.endswith(b'\n'), 'source_line_bound')
            hashed.update(raw)
            frame = parse(raw)
            need(isinstance(frame, dict), 'invalid_semantic_frame')
            need(frame.get('schema') == 'overwatch-decoder.entity-relations-export/1' and frame.get('source') == 'process_memory'
                 and frame.get('target') == manifest.target and frame.get('profile_sha256') == source['profile_sha256']
                 and frame.get('atomic') is False and frame.get('public_state_eligible') is False
                 and frame.get('visibility') == 'unknown', 'semantic_source_mismatch')
            recording, artifacts = frame.get('recording', {}), frame.get('source_artifacts', {})
            complete = (recording.get('complete') is True and recording.get('partial') is False
                        and recording.get('status') == 'verified_complete')
            partial = (source.get('allow_partial', False) and recording.get('complete') is False
                       and recording.get('partial') is True
                       and recording.get('status') in ('verified_stopped', 'recoverable_prefix'))
            need(complete or partial, 'incomplete_semantic_source')
            need(artifacts.get('profile_sha256') == source['profile_sha256']
                 and artifacts.get('manifest_sha256') == source['recording_manifest_sha256']
                 and artifacts.get('acquisition', {}).get('manifest_sha256') == source['acquisition_manifest_sha256'],
                 'semantic_provenance_mismatch')
            if provenance is None:
                provenance = recording, artifacts
                source['source_recording'] = recording
            need((recording, artifacts) == provenance, 'changed_source_provenance')
            for key in ('samples_prefix_sha256', 'index_prefix_sha256'):
                digest(artifacts.get(key))
            for key in ('recipe_sha256', 'evidence_sha256'):
                digest(artifacts.get('acquisition', {}).get(key))
            timing, gap = frame.get('timing', {}), frame.get('gap_before', {})
            start, end = timing.get('start_ticks'), timing.get('end_ticks')
            need(integer(start) and integer(end) and 0 <= start <= end and integer(timing.get('sequence')) and timing.get('sequence') == sequence
                 and (previous_end is None or previous_end <= start)
                 and timing.get('monotonic_frequency') == manifest.frequency
                 and integer(timing.get('monotonic_origin_ticks')), 'source_time_order_or_frequency')
            current_anchor = timing['monotonic_origin_ticks'], timing.get('utc_origin')
            if anchor is None:
                manifest.clock_anchor(timing)
                anchor = current_anchor
            need(current_anchor == anchor, 'changed_clock_origin')
            need(integer(gap.get('skipped_slots')) and gap['skipped_slots'] >= 0
                 and gap.get('current_start_ticks') == start and gap.get('previous_end_ticks') == previous_end
                 and gap.get('previous_values_carried') is False, 'source_gap_mismatch')
            ratio_projection = source.get('health_ratio_projection')
            need(frame.get('health_ratio_projection') == ratio_projection, 'ratio_source_admission_mismatch')
            validate_ratio_projection(ratio_projection, artifacts['acquisition'])
            if ratio_projection is not None:
                need(frame.get('health_ratio_contract_sha256') == [item['contract_sha256'] for item in ratio_projection['contracts']],
                     'ratio_frame_contract_pins')
            else:
                need('health_ratio_contract_sha256' not in frame, 'ratio_unadmitted_contracts')
            relations = frame.get('relations')
            need(isinstance(relations, list) and len(relations) <= 128, 'invalid_semantic_rows')
            from context_projection_validation import validate_context_frame
            context_projection = validate_context_frame(frame, source, target=manifest.target)
            forward = validate_forward_frame(frame, source)
            ammunition = validate_ammunition_frame(frame, source)
            rows = {}
            for relation in relations:
                need(isinstance(relation, dict), 'invalid_semantic_row')
                validate_ratio_candidate(relation, frame, ratio_projection)
                if relation.get('relation_status') != 'observed':
                    continue
                pair = object_pair(relation)
                need(pair in source['object_pairs'] and pair not in rows, 'unexpected_or_duplicate_object')
                need(relation.get('visibility') == 'unknown', 'unexpected_visibility_claim')
                validate_row(relation, frame, source)
                rows[pair] = relation
            projected = dict(source_id=source_id, timing=timing, gap=gap, rows=rows, artifacts=artifacts, recording=recording,
                             semantic_source_sha256=source['sha256'])
            if ammunition is not None:
                projected['ammunition'] = retain_ammunition(frame, sha(raw))
            if ratio_projection is not None:
                projected['health_ratio_projection'] = ratio_projection
                projected['semantic_frame_sha256'] = sha(raw)
            if context_projection is not None:
                projected['context_group_projection'] = context_projection
            if forward is not None:
                projected.update(forward_owner_projection=forward, semantic_hash_scope='source_file')
            yield projected
            previous_end, sequence = end, sequence + 1
    need(sequence > 0 and hashed.hexdigest() == source['sha256'], 'source_changed_or_empty')
    source['observed_frames'] = sequence


def static_values(row):
    resource = row.get('hero_resource_guid_candidate')
    need(resource is None or isinstance(resource, dict), 'invalid_semantic_resource')
    return dict(name=row.get('name'), cached_label_candidate=row.get('cached_label_candidate'),
                hero_label=row.get('hero_label'), hero_asset_label_candidate=row.get('hero_asset_label_candidate'), hero_resource_guid=None if resource is None else resource.get('value'),
                team=row.get('team'), team_candidate=row.get('team_candidate'),
                relative_allegiance_candidate=row.get('relative_allegiance_candidate'))


def observation(frame, pair, primary=False):
    result = dict(source_id=frame['source_id'], source_timing=frame['timing'], source_artifacts=frame['artifacts'],
                source_recording=frame['recording'], semantic_source_sha256=frame['semantic_source_sha256'],
                authoritative=primary, relation=frame['rows'][pair])
    if frame.get('health_ratio_projection') is not None:
        result['health_ratio_projection'] = frame['health_ratio_projection']
        result['semantic_frame_sha256'] = frame['semantic_frame_sha256']
        result['semantic_frame_hash_scope'] = 'exact_semantic_jsonl_line_including_lf'
    asset = hero_asset_metadata(frame['rows'][pair])
    if asset is not None:
        result['hero_asset_projection'] = asset
    if frame.get('context_group_projection') is not None:
        result['context_group_projection_ref'] = '/context_group_projections/'+frame['source_id']+'/projection'
    return result


def project_window(manifest, index, bucket):
    start, end = manifest.origin + index * manifest.window, manifest.origin + (index + 1) * manifest.window
    usable, unavailable = {}, {}
    discarded = 0
    for source_id in manifest.sources:
        state = bucket.get(source_id)
        if state is None:
            unavailable[source_id] = 'missing_frame_in_window'
            continue
        frame = state['latest']
        discarded += state['count'] - 1
        if state['gap']:
            unavailable[source_id] = 'gap_in_window'
        elif end - frame['timing']['start_ticks'] > manifest.skew:
            unavailable[source_id] = 'stale_or_excessive_read_span'
        else:
            usable[source_id] = frame
    starts = [frame['timing']['start_ticks'] for frame in usable.values()]
    ends = [frame['timing']['end_ticks'] for frame in usable.values()]
    read_start, read_end = (min(starts), max(ends)) if starts else (None, None)
    measured = None if read_start is None else read_end - read_start
    need(measured is None or measured <= manifest.skew, 'aggregate_skew_invariant')
    rows = []
    for pair, primary in manifest.roster.items():
        contributors = [observation(frame, pair, source_id == primary) for source_id, frame in usable.items()
                        if pair in frame['rows']]
        selected = next((value for value in contributors if value['authoritative']), None)
        conflicts = []
        for key in static_values({}):
            values = {canonical(static_values(value['relation'])[key]) for value in contributors
                      if static_values(value['relation'])[key] is not None}
            if len(values) > 1:
                conflicts.append(key)
        reason = None
        if conflicts:
            reason = 'conflicting_static_observations'
        elif selected is None:
            reason = unavailable.get(primary, 'primary_relation_unobserved')
        row = dict(controller_object_key=pair[0], body_object_key=pair[1], primary_source_id=primary,
                   status='observed' if reason is None else 'unknown', reason=reason,
                   authoritative_observation=selected if reason is None else None,
                   contributor_evidence=[{key: value[key] for key in ('source_id', 'source_timing', 'source_artifacts', 'source_recording', 'semantic_source_sha256', 'authoritative')}
                                         | ({'context_group_projection_ref':value['context_group_projection_ref']} if 'context_group_projection_ref'in value else {})
                                         | ({key:value[key] for key in ('health_ratio_projection', 'semantic_frame_sha256', 'semantic_frame_hash_scope')} if 'health_ratio_projection'in value else {})
                                         | ({'hero_asset_projection':value['hero_asset_projection']} if 'hero_asset_projection'in value else {})
                                         for value in contributors],
                   supporting_observations=[value for value in contributors if not value['authoritative']],
                   conflicting_static_fields=conflicts, visibility='unknown', public_state_eligible=False)
        rows.append(row)
    result = dict(schema='overwatch-decoder.partition-research-aggregate/1', manifest_sha256=manifest.hash,
                epoch_id=manifest.epoch, clock_domain_id=manifest.clock, target=manifest.target,
                monotonic_frequency=manifest.frequency, window_index=index, window_start_ticks=start,
                window_end_ticks=end, maximum_skew_ticks=manifest.skew, observed_read_start_ticks=read_start,
                observed_read_end_ticks=read_end, observed_skew_ticks=measured,
                unavailable_sources=unavailable, discarded_earlier_frames_in_window=discarded,
                values_carried_between_windows=False, atomic=False, visibility='unknown',
                public_state_eligible=False, privacy='private', relations=rows)
    if any(source.get('context_projection')is not None for source in manifest.sources.values()):
        result['context_group_projections'] = {sid:dict(source_id=sid,source_timing=f['timing'],source_artifacts=f['artifacts'],
            semantic_projection_sha256=f['semantic_source_sha256'],source_admission=manifest.sources[sid]['context_projection'],
            source_recording=f['recording'],source_gap=f['gap'],
            projection=f['context_group_projection'])for sid,f in usable.items()if f.get('context_group_projection')is not None}
    attach_forward_window(result, manifest, usable)
    attach_ammunition_window(result, manifest, usable)
    return result


def aggregate(manifest_path, output, maximum_output_bytes=MAX_TOTAL_BYTES):
    need(integer(maximum_output_bytes) and 0 < maximum_output_bytes <= MAX_TOTAL_BYTES, 'invalid_output_byte_limit')
    manifest, output = Manifest(manifest_path), Path(output).resolve()
    need(not output.exists() and output != manifest.path
         and all(output != row['resolved_path'] for row in manifest.sources.values()), 'output_exists_or_is_source')
    output.parent.mkdir(parents=True, exist_ok=True)
    iterators = {key: iter(source_frames(manifest, key)) for key in manifest.sources}
    heap = []
    temporary = None
    count = observed = conflicts = unknown = discarded = complete_windows = 0
    maximum_observed_skew = output_bytes = 0
    coverage = Counter()
    def write_window(file, result):
        nonlocal output_bytes
        encoded = canonical(result) + b'\n'
        need(output_bytes + len(encoded) <= maximum_output_bytes, 'output_byte_limit')
        file.write(encoded)
        output_bytes += len(encoded)
        for row in result['relations']:
            selected = row['authoritative_observation']
            if selected is not None:
                for key in ('position_candidate', 'health_candidate', 'health_ratio_candidate', 'hero_resource_guid_candidate', 'hero_label',
                            'cached_label_candidate', 'name', 'raw_category_candidate', 'hero_asset_label_candidate', 'team_candidate',
                            'relative_allegiance_candidate'):
                    if key not in ('hero_asset_label_candidate', 'health_ratio_candidate') or key in selected['relation']:
                        coverage[key] += selected['relation'].get(key) is not None
    try:
        for source_id, iterator in iterators.items():
            frame = next(iterator)
            heapq.heappush(heap, (frame['timing']['end_ticks'], source_id, frame))
        with tempfile.NamedTemporaryFile(mode='wb', dir=output.parent,
                                         prefix='.partition-aggregate-', suffix='.partial', delete=False) as file:
            temporary = Path(file.name)
            current = (heap[0][0] - manifest.origin) // manifest.window
            need(current >= 0, 'frame_before_window_origin')
            bucket = {}
            while heap:
                ticks, source_id, frame = heapq.heappop(heap)
                index = (ticks - manifest.origin) // manifest.window
                need(count + index - current <= MAX_WINDOWS, 'window_count_limit')
                while current < index:
                    result = project_window(manifest, current, bucket)
                    write_window(file, result)
                    count += 1
                    complete_windows += all(row['status'] == 'observed' for row in result['relations'])
                    need(count <= MAX_WINDOWS, 'window_count_limit')
                    observed += sum(row['status'] == 'observed' for row in result['relations'])
                    conflicts += sum(bool(row['conflicting_static_fields']) for row in result['relations'])
                    unknown += sum(row['status'] != 'observed' for row in result['relations'])
                    discarded += result['discarded_earlier_frames_in_window']
                    maximum_observed_skew = max(maximum_observed_skew, result['observed_skew_ticks'] or 0)
                    current += 1
                    bucket = {}
                state = bucket.setdefault(source_id, dict(latest=frame, count=0, gap=False))
                state.update(latest=frame, count=state['count'] + 1,
                             gap=state['gap'] or frame['gap']['skipped_slots'] > 0)
                following = next(iterators[source_id], None)
                if following is not None:
                    heapq.heappush(heap, (following['timing']['end_ticks'], source_id, following))
            result = project_window(manifest, current, bucket)
            write_window(file, result)
            count += 1
            complete_windows += all(row['status'] == 'observed' for row in result['relations'])
            need(count <= MAX_WINDOWS, 'window_count_limit')
            observed += sum(row['status'] == 'observed' for row in result['relations'])
            conflicts += sum(bool(row['conflicting_static_fields']) for row in result['relations'])
            unknown += sum(row['status'] != 'observed' for row in result['relations'])
            discarded += result['discarded_earlier_frames_in_window']
            maximum_observed_skew = max(maximum_observed_skew, result['observed_skew_ticks'] or 0)
            file.flush()
            os.fsync(file.fileno())
        os.link(temporary, output)
        with output.open('rb') as file:
            output_hash = hashlib.file_digest(file, 'sha256').hexdigest()
        return dict(schema='overwatch-decoder.partition-research-aggregate-result/1', windows=count,
                    observed_rows=observed, unknown_rows=unknown, static_conflicts=conflicts,
                    all_primary_rows_observed_windows=complete_windows,
                    input_frames={key: value['observed_frames'] for key, value in manifest.sources.items()},
                    all_input_sources_complete=all(value['source_recording']['complete'] for value in manifest.sources.values()),
                    discarded_earlier_frames_in_window=discarded, maximum_observed_skew_ticks=maximum_observed_skew,
                    clock_anchor_spread_ticks=float(manifest.offset_max - manifest.offset_min),
                    output_sha256=output_hash, output_bytes=output_bytes, maximum_output_bytes=maximum_output_bytes,
                    observed_rows_meaning='primary_relation_available_not_all_optional_fields_present',
                    authoritative_field_coverage=dict(coverage), atomic=False, public_state_eligible=False)
    finally:
        for iterator in iterators.values():
            iterator.close()
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--maximum-output-bytes', type=int, default=MAX_TOTAL_BYTES,
                        help='atomic output byte admission limit; positive and at most2GiB')
    args = parser.parse_args()
    try:
        result = aggregate(args.manifest, args.output, args.maximum_output_bytes)
    except (InvalidPartitions, ValueError, KeyError, OSError, StopIteration, RecursionError) as error:
        print(json.dumps(dict(schema='overwatch-decoder.partition-research-aggregate-result/1', complete=False, error=str(error))))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
