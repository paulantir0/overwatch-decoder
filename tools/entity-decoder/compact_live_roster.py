#!/usr/bin/env python3
"""Compact accepted private live roster windows without native re-verification.

Retain each original aggregate JSONL line and its referenced semantic/native
sources. All JSON pointers below are rooted in that exact hashed original line.
Supporting observations stay references; they never fill a missing primary.
"""
import argparse
from collections import Counter
import copy
import hashlib
import math
import os
from pathlib import Path
import tempfile
import re
import sys

from compact_live_entities import (digest, encode, evidence, finite, integer,
    need, object_key, parse, span, text)
from health_changes import HealthChanges, sample as health_change_sample, unknown as health_change_unknown

from aggregate_partitions import static_values
from ammunition_projection_validation import validate_window as validate_ammunition_window, validate_observation as validate_ammunition_observation, compact_candidate as compact_ammunition
from health_ratio_validation import compact_candidate as compact_ratio, validate_projection as validate_ratio_projection, validate_candidate as validate_ratio_candidate
from forward_owner_validation import validate_forward_owner_frame, CATEGORY_METADATA_KEYS, validate_acquisition_empty_evidence
from forward_owner_relations import reference_group_membership
from hero_asset_validation import (compact_hero_asset, present as hero_asset_present, metadata as hero_asset_metadata)

from context_projection_validation import (validate_context_entry, validate_actor_context, compact_context, _compact_actor_context)

MAX_BYTES = 512 * 1024 * 1024
MAX_EVENTS = 100000
MAX_LINE = 16 * 1024 * 1024
MAX_OUTPUT_LINE = 2 * 1024 * 1024
MAX_EPOCHS = 128
CANDIDATES = ('position_candidate', 'health_candidate', 'hero_resource_candidate',
              'hero_label_candidate', 'cached_label_candidate', 'category_candidate')
TIME_KEYS = ('window_index', 'window_start_ticks', 'window_end_ticks',
             'monotonic_frequency', 'watermark_ticks', 'maximum_skew_ticks',
             'observed_read_start_ticks', 'observed_read_end_ticks', 'observed_skew_ticks')
SOURCE_TIME_KEYS = ('sequence', 'start_ticks', 'end_ticks', 'monotonic_frequency',
                    'utc_origin', 'monotonic_origin_ticks')


def source_id(value):
    need(isinstance(value, str) and re.fullmatch('[A-Za-z0-9_-]{1,64}', value), 'invalid_source_id')


def qualified(value):
    need(value.get('atomic') is False and value.get('privacy') == 'private'
         and value.get('public_state_eligible') is False and value.get('visibility') == 'unknown'
         and value.get('durability_verified') is False
         and value.get('recording_state') == 'accepted_not_durability_verified'
         and value.get('configuration_status') == 'reviewed_caller_input_not_native_proof',
         'invalid_roster_qualification')


def null_candidates(reason):
    return {key: dict(status='unknown', value=None, reason=reason,
                     read_span_ticks=None, evidence_ref=None) for key in CANDIDATES}


def validate_scope(value, timing, profile, build, identity=None, *, extra_nodes=0, context_reference=None):
    """One bounded walk of this row only; primitive leaves need no recursion.

    Count every value, including primitive guard-ID leaves, before skipping
    their Python calls. Container/leaf depth and the old 100,000-node bound stay
    unchanged. No validation result survives the current serialized row.
    """
    stack = [(value, 0)]; count = 1+extra_nodes; containers = (dict, list)
    while stack:
        node, depth = stack.pop()
        need(depth <= 24 and count <= 100000, 'nested_evidence_bound')
        if isinstance(node, dict):
            if 'profile_sha256' in node: need(node['profile_sha256'] == profile, 'nested_profile_mismatch')
            if 'build_sha256' in node: need(node['build_sha256'] == build, 'nested_build_mismatch')
            if 'read_start_ticks' in node or 'read_end_ticks' in node:
                a, b = node.get('read_start_ticks'), node.get('read_end_ticks')
                need(integer(a) and integer(b) and timing['start_ticks'] <= a <= b <= timing['end_ticks'], 'nested_read_bracket')
            if identity is not None and node is not context_reference:
                for key in ('controller_object_key', 'body_object_key'):
                    if key in node: need(node[key] == identity[key], 'nested_object_mismatch')
            children = node.values()
        else: children = node
        count += len(node)
        need(count <= 100000 and (not node or depth < 24), 'nested_evidence_bound')
        stack.extend((child, depth+1) for child in children if isinstance(child, containers))


def compact_candidates(row, frame, base, *, context_reference=None, finite_source=False):
    """Pure value/span projection, with no dependency on an earlier row."""
    profile, build, timing = frame['profile_sha256'], frame['target']['executable_sha256'], frame['timing']
    extra = sum(key not in row for key in ('name', 'raw_category_candidate', 'team_candidate', 'relative_allegiance_candidate'))
    validate_scope(row, timing, profile, build, row, extra_nodes=extra, context_reference=context_reference)
    body = row['body_object_key']
    def candidate(value, why, evidence_key, reads, status):
        reason_key = why if why in row else 'reason'
        reason = row.get(reason_key)
        need(reason is None or isinstance(reason, str) and len(reason) <= 1024, 'invalid_candidate_reason')
        result = dict(value=value, status=status if value is not None else 'unknown', reason=reason,
                      read_span_ticks=reads, evidence_ref=base+'/'+evidence_key if row.get(evidence_key) is not None else None)
        if reason is not None: result['reason_ref'] = base+'/'+reason_key
        return result
    timing = frame['timing']
    position = row.get('position_candidate'); ps = None
    if position is not None:
        need(isinstance(position, dict) and position.get('validation_status') == 'guarded_research'
             and position.get('profile_sha256') == profile and position.get('build_sha256') == build
             and position.get('source') == 'process_memory' and position.get('type') == 'f32x3'
             and isinstance(position.get('value'), list) and len(position['value']) == 3
             and all(finite(v) for v in position['value']), 'invalid_position_validation')
        ps = span([position], timing)
    health = row.get('health_candidate'); hs = hv = None
    if health is not None:
        need(isinstance(health, dict) and health.get('schema') == 'overwatch-decoder.actor-pool-sum/1' and health.get('status') == 'candidate'
             and health.get('source') == 'process_memory' and health.get('profile_sha256') == profile and health.get('build_sha256') == build
             and health.get('body_object_key') == body and health.get('acquisition_evidence_sha256') == frame['source_artifacts']['acquisition']['evidence_sha256']
             and health.get('public_state_eligible') is False and health.get('visibility') == 'unknown' and health.get('atomic') is False
             and health.get('complete_supplied_membership_guarding') is True, 'invalid_health_validation')
        parts = health.get('contributions')
        need(isinstance(parts, list) and 1 <= len(parts) <= 128 and all(isinstance(part, dict)
             and finite(part.get('value')) and part['value'] >= 0 for part in parts), 'invalid_health_contributions')
        indices = [part.get('pool_index') for part in parts]
        need(all(integer(i) and i >= 0 for i in indices) and len(set(indices)) == len(indices), 'duplicate_health_pool')
        hs = span(parts, timing)
        need(finite(health.get('raw_sum')) and health['raw_sum'] == sum(part['value'] for part in parts)
             and span([health], timing) == hs, 'health_sum_or_span_mismatch')
        ceiling = health.get('display_ceiling_candidate')
        need(ceiling is None or integer(ceiling) and ceiling == math.ceil(health['raw_sum']), 'invalid_health_ceiling')
        hv = {key: health.get(key) for key in ('raw_sum', 'display_ceiling_candidate')}
    resource = row.get('hero_resource_guid_candidate'); rs = None
    if resource is not None:
        need(isinstance(resource, dict) and resource.get('validation_status') == 'matching_guarded_resource_research'
             and isinstance(resource.get('value'), str) and re.fullmatch('0x[0-9A-Fa-f]{16}', resource['value'])
             and resource.get('controller_body_match') is True and resource.get('public_state_eligible') is False, 'invalid_resource_validation')
        words = resource.get('evidence')
        need(isinstance(words, list) and len(words) == 4 and all(isinstance(w, dict) and integer(w.get('value'))
             and -(1 << 31) <= w['value'] < (1 << 31) for w in words), 'invalid_resource_words')
        rs = span(words, timing)
        controller = (words[0]['value'] & 0xffffffff) | ((words[1]['value'] & 0xffffffff) << 32)
        body_resource = (words[2]['value'] & 0xffffffff) | ((words[3]['value'] & 0xffffffff) << 32)
        need(controller == body_resource == int(resource['value'], 16), 'resource_word_mismatch')
    label = row.get('hero_label'); ls = None
    if label is not None:
        text(label); e = row['hero_label_evidence']; ls = evidence(e, frame)
        need(e.get('validation_status') == 'guarded_build_resource_label_research' and resource is not None
             and e.get('mapping', {}).get('label') == label and e['mapping'].get('resource_guid') == resource['value']
             and e['mapping'].get('build_sha256') == build, 'invalid_hero_validation')
        digest(e.get('catalog_sha256'))
    cache = row.get('cached_label_candidate'); cs = None
    if cache is not None:
        text(cache); e = row['cached_label_evidence']; cs = evidence(e, frame, acquisition=True)
        need(e.get('validation_status') == 'guarded_native_cache_string_research'
             and e.get('privacy') == 'private' and e.get('gameplay_semantics_validated') is False, 'invalid_cache_validation')
    category = {key: row.get(key) for key in ('raw_category_candidate', 'team_candidate', 'relative_allegiance_candidate')}
    cat_span = None
    if any(value is not None for value in category.values()):
        need(category['raw_category_candidate'] is None or integer(category['raw_category_candidate'])
             and category['raw_category_candidate'] >= 0, 'invalid_category_value')
        if category['team_candidate'] is not None: text(category['team_candidate'])
        need(category['relative_allegiance_candidate'] in (None, 'self', 'friendly', 'enemy'), 'invalid_allegiance_candidate')
        e = row.get('category_evidence'); cat_span = evidence(e, frame, acquisition=True)
        if finite_source:
            need(e.get('validation_status') == 'guarded_category_roster_research', 'invalid_category_validation')
            scope = e.get('mode_scope', {})
            bounds = scope.get('frame_scope', {})
            need(scope.get('recording_manifest_sha256') == frame['source_artifacts']['manifest_sha256']
                 and all(integer(bounds.get(key)) for key in ('first_sequence', 'last_sequence', 'start_ticks', 'end_ticks'))
                 and bounds['first_sequence'] <= timing['sequence'] <= bounds['last_sequence']
                 and bounds['start_ticks'] <= timing['start_ticks'] <= timing['end_ticks'] <= bounds['end_ticks'],
                 'category_scope_mismatch')
            for key in ('native_review_sha256', 'roster_review_sha256', 'contract_sha256'): digest(e.get(key))
        else:
            need(e.get('validation_status') == 'guarded_live_category_roster_research'
                 and e.get('durability_verified') is False, 'invalid_category_validation')
            for key in ('native_review_sha256', 'roster_review_sha256', 'mode_review_sha256', 'contract_sha256'): digest(e.get(key))
            admission = e.get('admission', {}); scope = e.get('mode_scope', {}).get('live_scope', {})
            expected = dict(profile_sha256=frame['profile_sha256'], acquisition_manifest_sha256=frame['source_artifacts']['acquisition']['manifest_sha256'],
                recipe_sha256=frame['source_artifacts']['acquisition']['recipe_sha256'], evidence_sha256=frame['source_artifacts']['acquisition']['evidence_sha256'],
                event_sha256=frame['source_artifacts']['live_event_sha256'], frame_sequence=timing['sequence'],
                frame_start_ticks=timing['start_ticks'], frame_end_ticks=timing['end_ticks'], monotonic_frequency=timing['monotonic_frequency'])
            need(all(admission.get(key) == value for key, value in expected.items())
                 and all(scope.get(key) == admission.get(key) for key in ('session_id', 'segment'))
                 and scope.get('monotonic_frequency') == timing['monotonic_frequency']
                 and integer(scope.get('start_ticks')) and scope['start_ticks'] <= timing['start_ticks'], 'invalid_category_source_scope')
            digest(admission.get('frame_sha256'))
            for key in ('session_start_sha256', 'segment_start_sha256'): digest(scope.get(key))
        if category['relative_allegiance_candidate'] is not None:
            object_key(e.get('self_controller_object_key'), 'controller')
            need(e.get('self_controller_object_key') is not None, 'missing_category_self')
            self_span = span(e.get('self_fields'), timing)
            cat_span = [min(cat_span[0], self_span[0]), max(cat_span[1], self_span[1])]
    else: category = None
    result = dict(
        position_candidate=candidate(None if position is None else position['value'], 'position_reason', 'position_candidate', ps, 'guarded_research'),
        health_candidate=candidate(hv, 'health_reason', 'health_candidate', hs, 'candidate'),
        hero_resource_candidate=candidate(None if resource is None else resource['value'], 'hero_resource_reason', 'hero_resource_guid_candidate', rs, 'matching_guarded_resource_research'),
        hero_label_candidate=candidate(label, 'hero_label_reason', 'hero_label_evidence', ls, 'guarded_build_resource_label_research'),
        cached_label_candidate=candidate(cache, 'cached_label_reason', 'cached_label_evidence', cs, 'guarded_native_cache_string_research'),
        category_candidate=candidate(category, 'category_reason', 'category_evidence', cat_span, 'guarded_category_roster_research' if finite_source else 'guarded_live_category_roster_research'))
    ratio_projection = frame.get('health_ratio_projection')
    validate_ratio_projection(ratio_projection, frame['source_artifacts']['acquisition'])
    ratio = compact_ratio(row, frame, ratio_projection, base)
    if ratio is not None:
        result['health_ratio_candidate'] = ratio
    asset = compact_hero_asset(row, frame, base, detached=True)
    if asset is not None:
        result['hero_asset_label_candidate'] = asset
    return result


class CompactLiveRoster:
    def __init__(self, *, maximum_input_bytes=MAX_BYTES, maximum_output_bytes=MAX_BYTES, maximum_events=MAX_EVENTS):
        for value, bound in ((maximum_input_bytes, MAX_BYTES), (maximum_output_bytes, MAX_BYTES), (maximum_events, MAX_EVENTS)):
            need(integer(value) and 0 < value <= bound, 'invalid_compact_limit')
        self.max_input, self.max_output, self.max_events = maximum_input_bytes, maximum_output_bytes, maximum_events
        self.input_bytes = self.output_bytes = self.events = self.windows = self.players = self.unknown = 0
        self.input_hash, self.output_hash = hashlib.sha256(), hashlib.sha256()
        self.coverage = Counter(); self.previous = None; self.bindings = {}; self.source_pins = {}
        self.epochs = set(); self.epoch_ids = set(); self.failed = False; self.transition = None; self.resume = None
        self.transition_controllers = None; self.last_revision = None; self.context = None; self.unresolved_pins={};self.context_pins={};self.context_enabled=False;self.input_ended=False;self.startup_expected=None
        self.hero_asset_enabled=False;self.hero_asset_pins={}
        self.forward_sources=None;self.forward_config=None;self.forward_pins={}
        self.health_changes = HealthChanges()
        self.ammunition_sources = None
        self.window_ammunition = {}
        self.ratio_sources = None

    def consume(self, raw):
        return self._consume_decoded(raw, None)

    def _consume_decoded(self, raw, value):
        """Internal unchanged coordinator object just canonically serialized as raw.

        All candidate/provenance/epoch/resource checks run. This only skips a
        redundant strict parse inside the trusted coordinator-to-writer path;
        callers receiving external bytes must continue to use consume().
        """
        decoded = value is not None
        need(not self.failed and not self.input_ended, 'compact_roster_failed')
        try:
            need(isinstance(raw, bytes) and 0 < len(raw) <= MAX_LINE and raw.endswith(b'\n'), 'compact_roster_line_bound')
            need(self.events < self.max_events and self.input_bytes+len(raw) <= self.max_input, 'compact_roster_input_bound')
            value = parse(raw) if value is None else value
            need(isinstance(value, dict), 'invalid_roster_object'); qualified(value)
            if value.get('schema') == 'overwatch-decoder.live-roster-startup/1': result = self._startup(value)
            elif value.get('schema') == 'overwatch-decoder.live-roster-transition/1': result = self._transition(value)
            else: result = self._window(value)
            result.update(privacy='private', source='process_memory_projected_research', atomic=False,
                public_state_eligible=False, visibility='unknown', participant_identity_validated=False,
                values_are_candidates=True, continuity_across_gaps=False, durability_verified=False,
                recording_state='accepted_not_durability_verified',
                validation_scope='accepted_aggregate_projection_not_native_reverification',
                source_frame=dict(sha256=hashlib.sha256(raw).hexdigest(), hash_scope='exact_aggregate_jsonl_line_including_lf',
                    evidence_root='original_aggregate_line', original_evidence_required=True))
            if decoded:
                # canonical(value) sorts source mappings before public consume
                # parses them. Preserve that exact order only for copied output
                # mappings; never traverse/reparse the large guard evidence here.
                def ordered(node):
                    if isinstance(node,dict):return {k:ordered(node[k])for k in sorted(node)}
                    if isinstance(node,list):return [ordered(v)for v in node]
                    return node
                if 'unavailable_sources'in result:result['unavailable_sources']=ordered(result['unavailable_sources'])
                if 'context_group_projections'in result:
                    result['context_group_projections']={k:result['context_group_projections'][k]for k in sorted(result['context_group_projections'])}
                    for entry in result['context_group_projections'].values():
                        entry['projection']['contract_sha256']=ordered(entry['projection']['contract_sha256'])
                for player in result['players']:
                    if 'context_group_candidate'in player:player['context_group_candidate']['value']=ordered(player['context_group_candidate']['value'])
                if 'input_end'in result:result['input_end']=ordered(result['input_end'])
                if 'health_ratio_sources' in result:result['health_ratio_sources']=ordered(result['health_ratio_sources'])
                if 'forward_owner_sources' in result:
                    result['forward_owner_sources']=ordered(result['forward_owner_sources'])
                if 'forward_owner_projections' in result:
                    result['forward_owner_projections']={sid:result['forward_owner_projections'][sid]for sid in sorted(result['forward_owner_projections'])}
                    for entry in result['forward_owner_projections'].values():
                        for key in ('source_timing','source_gap'):entry[key]=ordered(entry[key])
                        for key in ('timing','source_evidence'):entry['projection'][key]=ordered(entry['projection'][key])
                for owner in result.get('forward_owners',[]):
                    owner['owned_fields']={name:owner['owned_fields'][name]for name in sorted(owner['owned_fields'])}
                    if 'category_candidate'in owner and owner['category_candidate']['value']is not None:
                        owner['category_candidate']['value']['raw_flags_candidate']=ordered(owner['category_candidate']['value']['raw_flags_candidate'])
            if self.hero_asset_enabled:
                for player in result['players']:
                    player.setdefault('hero_asset_label_candidate', dict(status='unknown', value=None, reason=player.get('reason'), read_span_ticks=None, evidence_ref=None, runtime_ui_validated=False))
            if result['schema'] == 'overwatch-decoder.compact-live-roster/1':
                samples = []
                for i, row in enumerate(value['relations']):
                    selected = row.get('authoritative_observation')
                    if row['status'] != 'observed' or selected is None:
                        samples.append(dict(controller_object_key=row['controller_object_key'], sample=None))
                    else:
                        samples.append(health_change_sample(selected['relation'], target=value['target'],
                            timing=selected['source_timing'], artifacts=selected['source_artifacts'],
                            epoch=dict(config_sha256=value['config_sha256'], epoch_id=value['epoch_id'], source_id=selected['source_id']),
                            source_sha256=selected['semantic_projection_sha256'], evidence_container_sha256=result['source_frame']['sha256'],
                            evidence_ref='/relations/'+str(i)+'/authoritative_observation/relation/health_candidate'))
                changes = self.health_changes.project(samples)
                for row, change in zip(result['players'], changes): row['health_change_candidate'] = change
            else:
                self.health_changes.clear()
                for row in result['players']: row['health_change_candidate'] = health_change_unknown('roster_transition')
            encoded = encode(result)
            need(len(encoded) <= MAX_OUTPUT_LINE and self.output_bytes+len(encoded) <= self.max_output, 'compact_roster_output_bound')
            if result['schema'] == 'overwatch-decoder.compact-live-roster/1':
                self.windows += 1; self.players += len(result['players'])
                self.unknown += sum(row['status'] == 'unknown' for row in result['players'])
                for row in result['players']:
                    for key in CANDIDATES: self.coverage[key] += row[key]['value'] is not None
                    if 'health_ratio_candidate'in row:self.coverage['health_ratio_candidate'] += row['health_ratio_candidate']['value']is not None
                    if 'hero_asset_label_candidate'in row:self.coverage['hero_asset_label_candidate'] += row['hero_asset_label_candidate']['value']is not None
                    if 'context_group_candidate'in row:self.coverage['context_group_candidate'] += row['context_group_candidate']['value']is not None
            self.events += 1; self.input_bytes += len(raw); self.output_bytes += len(encoded)
            self.input_hash.update(raw); self.output_hash.update(encoded)
            return result
        except (ValueError, KeyError, TypeError, AttributeError, RecursionError, OverflowError):
            self.failed = True; raise

    def _context(self, value):
        target = value.get('target', {})
        need(integer(target.get('pid')) and target['pid'] > 0 and integer(target.get('creation_file_time'))
             and target['creation_file_time'] > 0 and target.get('architecture') == 'x64', 'invalid_roster_target')
        text(target.get('image_name'), 256); digest(target.get('executable_sha256'))
        text(value.get('clock_domain_id'), 128)
        need(integer(value.get('monotonic_frequency')) and 0 < value['monotonic_frequency'] <= 10**12, 'invalid_roster_frequency')
        target = {key: target[key] for key in ('pid', 'creation_file_time', 'executable_sha256', 'architecture', 'image_name')}
        context = dict(target=target, clock_domain_id=value['clock_domain_id'], monotonic_frequency=value['monotonic_frequency'])
        need(self.context is None or self.context == context, 'changed_roster_clock_or_target')
        self.context = context
        return target

    def _startup(self,value):
        need(self.previous is None and self.transition is None and self.startup_expected is None,'startup_after_live_values')
        target=self._context(value);digest(value.get('next_config_sha256'));text(value.get('epoch_id'),128)
        start,end=value.get('start_ticks'),value.get('end_ticks')
        need(value.get('status')=='unknown'and value.get('revision')==1 and integer(start)and integer(end)and 0<=start<=end
             and value.get('resume_boundary_ticks')==end and value.get('previous_values_carried')is False
             and value.get('pending_observations_discarded')is True and value.get('reason')=='startup_observations_saved_not_published_live','invalid_startup_boundary')
        evidence=value.get('startup_validation',{})
        need(evidence.get('schema')=='overwatch-decoder.live-startup-validation/1'and evidence.get('all_source_json_frames_preserved')is True
             and evidence.get('observations_published_in_live_aggregate')is False and evidence.get('previous_values_carried')is False
             and evidence.get('failed')is False and integer(evidence.get('validated_frames'))and 0<evidence['validated_frames']<=MAX_EVENTS
             and integer(evidence.get('input_bytes'))and 0<evidence['input_bytes']<=MAX_BYTES,'invalid_startup_evidence')
        sources=evidence.get('sources');need(isinstance(sources,dict)and 1<=len(sources)<=16,'invalid_startup_sources')
        need(evidence.get('maximum_retained_source_lines')==len(sources)and integer(evidence.get('retained_bytes'))
             and 0<evidence['retained_bytes']<=16*1024*1024,'startup_retained_bound')
        total=0
        for sid,pin in sources.items():
            source_id(sid);digest(pin.get('source_prefix_sha256'));digest(pin.get('profile_sha256'))
            need(integer(pin.get('validated_frames'))and pin['validated_frames']>0
                 and integer(pin.get('first_start_ticks'))and integer(pin.get('last_end_ticks'))and start<=pin['first_start_ticks']<=pin['last_end_ticks']<=end
                 and pin.get('hash_scope')=='exact_source_jsonl_prefix_including_lf','invalid_startup_source_span')
            need(isinstance(pin.get('session_id'),str)and re.fullmatch('[0-9a-f]{32}',pin['session_id'])
                 and integer(pin.get('segment'))and 1<=pin['segment']<=MAX_EPOCHS,'startup_source_epoch')
            total+=pin['validated_frames']
        need(total==evidence['validated_frames'],'startup_frame_accounting')
        rows=value.get('relations');need(isinstance(rows,list)and 1<=len(rows)<=128,'invalid_startup_roster')
        players=[];owners={}
        for i,row in enumerate(rows):
            ck=row.get('controller_object_key');object_key(ck,'controller');sid=row.get('primary_source_id');source_id(sid)
            need(ck is not None and ck not in owners and sid in sources and row.get('body_object_key')is None and row.get('status')=='unknown'
                 and row.get('reason')=='startup_not_published'and row.get('authoritative_observation')is None
                 and row.get('supporting_observations')==[]and row.get('contributor_evidence')==[],'startup_carried_values')
            need(all(row.get(k)is None for k in ('position_candidate','health_candidate','hero_resource_guid_candidate','hero_label',
                 'cached_label_candidate','context_group_candidate','context_group_evidence','raw_category_candidate','team_candidate','relative_allegiance_candidate')),'startup_carried_values')
            owners[ck]=sid
            player=dict(controller_object_key=ck,body_object_key=None,primary_source_id=sid,status='unknown',reason='startup_not_published',source_ref='/relations/'+str(i),**null_candidates('startup_not_published'))
            if value.get('raw_context_output_enabled')is True:player['context_group_candidate']=dict(status='unknown',value=None,reason='startup_not_published',read_span_ticks=None,evidence_ref=None,context_projection_ref=None)
            players.append(player)
        self.bindings={ck:(None,sid)for ck,sid in owners.items()}
        self.context_enabled=value.get('raw_context_output_enabled')is True
        self.startup_expected=dict(config=value['next_config_sha256'],epoch=value['epoch_id'],boundary=end,owners=owners)
        return dict(schema='overwatch-decoder.compact-live-roster-startup/1',status='unknown',target=target,clock_domain_id=value['clock_domain_id'],
            monotonic_frequency=value['monotonic_frequency'],start_ticks=start,end_ticks=end,resume_boundary_ticks=end,next_config_sha256=value['next_config_sha256'],
            values_carried_between_windows=False,startup_evidence_ref='/startup_validation',validated_startup_frames=total,players=players)

    def _window(self, value):
        need(value.get('schema') == 'overwatch-decoder.partition-research-live/1' and value.get('values_carried_between_windows') is False,
             'invalid_live_roster_source')
        target = self._context(value); digest(value.get('config_sha256')); text(value.get('epoch_id'), 128)
        t = {key: value.get(key) for key in TIME_KEYS}
        need(all(integer(t[key]) for key in TIME_KEYS[:6]) and t['window_index'] >= 0
             and 0 <= t['window_start_ticks'] < t['window_end_ticks'] <= t['watermark_ticks']
             and 0 < t['window_end_ticks']-t['window_start_ticks'] <= t['maximum_skew_ticks'] <= 5*t['monotonic_frequency'], 'invalid_roster_window_time')
        a, b, skew = (t[key] for key in TIME_KEYS[6:])
        need(all(v is None for v in (a, b, skew)) or integer(a) and integer(b) and integer(skew)
             and 0 <= a <= b < t['window_end_ticks'] and skew == b-a <= t['maximum_skew_ticks'], 'invalid_roster_read_span')
        old = self.previous; changed = old is None or value['config_sha256'] != old['config_sha256']
        need(self.transition is None, 'roster_window_during_open_transition')
        need(self.resume is None or changed, 'stale_window_after_transition_closure')
        if old:
            width = t['window_end_ticks']-t['window_start_ticks']
            need(t['window_index'] > old['window_index'] and t['window_start_ticks'] >= old['window_end_ticks']
                 and t['watermark_ticks'] >= old['watermark_ticks']
                 and width == old['window_end_ticks']-old['window_start_ticks']
                 and t['window_start_ticks']-t['window_index']*width == old['grid_origin'], 'roster_window_order_or_grid')
            if not changed:
                need(value['epoch_id'] == old['epoch_id'] and t['window_index'] == old['window_index']+1, 'roster_config_boundary_required')
            else: need(value['epoch_id'] != old['epoch_id'], 'roster_epoch_boundary_required')
        if changed:
            need(value['config_sha256'] not in self.epochs and value['epoch_id'] not in self.epoch_ids and len(self.epochs) < MAX_EPOCHS, 'reused_or_excessive_roster_epoch')
            self.epochs.add(value['config_sha256']); self.epoch_ids.add(value['epoch_id']); self.source_pins = {}; self.unresolved_pins={};self.context_pins={};self.hero_asset_enabled=False;self.hero_asset_pins={}
            if self.resume:
                need(value['config_sha256'] == self.resume['next_config_sha256'] and t['window_start_ticks'] == self.resume['end_ticks'], 'roster_resume_mismatch')
                self.resume = None
        self.window_ammunition = validate_ammunition_window(value)
        ammunition_sources = value.get('ammunition_sources')
        need(changed or ammunition_sources == self.ammunition_sources, 'ammunition_changed_without_epoch')
        self.ammunition_sources = copy.deepcopy(ammunition_sources)
        rows = value.get('relations'); need(isinstance(rows, list) and 1 <= len(rows) <= 128, 'invalid_roster_rows')
        self.hero_asset_enabled = self.hero_asset_enabled or any(
            hero_asset_present(node.get('relation', {})) for row in rows
            for node in ([row.get('authoritative_observation') or {}] + row.get('supporting_observations', [])))
        pairs = {}; bodies = set()
        for row in rows:
            ck, bk = row.get('controller_object_key'), row.get('body_object_key')
            object_key(ck, 'controller'); object_key(bk, 'body'); source_id(row.get('primary_source_id'))
            need(ck is not None and ck not in pairs and (bk is None or bk not in bodies), 'duplicate_or_missing_roster_identity')
            if bk is None:
                need(value.get('observation_mode')=='raw-candidates' and value.get('unresolved_body_policy')=='same_profile_declared_body_fields_absent', 'nullable_body_requires_raw_policy')
            pairs[ck] = (bk, row['primary_source_id']); bodies.add(bk)
        if self.transition_controllers is not None:
            need(set(pairs) == self.transition_controllers, 'resumed_controller_set_changed')
        if self.bindings:
            need(set(pairs) == set(self.bindings) and all(pairs[k][1] == self.bindings[k][1] for k in pairs), 'changed_roster_primary_ownership')
            if not changed: need(pairs == self.bindings, 'roster_body_changed_without_epoch')
        if self.startup_expected is not None:
            expected=self.startup_expected
            need(value['config_sha256']==expected['config']and value['epoch_id']==expected['epoch']and t['window_start_ticks']==expected['boundary']
                 and {ck:p[1]for ck,p in pairs.items()}==expected['owners'],'startup_resume_mismatch')
            self.startup_expected=None
        self.bindings = pairs
        unavailable = value.get('unavailable_sources'); need(isinstance(unavailable, dict) and len(unavailable) <= 16, 'invalid_unavailable_sources')
        for sid, why in unavailable.items(): source_id(sid); text(why)
        discarded = value.get('discarded_earlier_frames_in_window')
        need(integer(discarded) and discarded >= 0, 'invalid_discarded_count')
        entries = value.get('context_group_projections')
        self.window_context = {}
        enabled=entries is not None
        need(changed or enabled==self.context_enabled,'context_projection_toggle_without_epoch')
        self.context_enabled=enabled
        if entries is not None:
            need(isinstance(entries,dict)and len(entries)<=16,'compact_context_count')
            for sid,entry in entries.items():
                source_id(sid);need(entry.get('source_id')==sid,'compact_context_source_id')
                need(sid not in unavailable,'unavailable_context_source')
                top=validate_context_entry(entry,value['target']);digest(entry.get('semantic_projection_sha256'))
                pin=(top['session_id'],top['segment'],top['profile_sha256'],entry['source_artifacts']['acquisition'],entry['source_admission'])
                need(sid not in self.context_pins or self.context_pins[sid]==pin,'context_source_changed_without_epoch')
                self.context_pins[sid]=pin
                time=entry['source_timing']
                need(time['monotonic_frequency']==value['monotonic_frequency'] and value['window_start_ticks']<=time['end_ticks']<value['window_end_ticks']
                     and value['window_end_ticks']-time['start_ticks']<=value['maximum_skew_ticks']
                     and value['observed_read_start_ticks'] is not None
                     and value['observed_read_start_ticks']<=time['start_ticks']<=time['end_ticks']<=value['observed_read_end_ticks'],'context_outside_roster_window')
                self.window_context[sid] = top
        self._ratio_window(value, changed)
        players = [self._row(row, index, value) for index, row in enumerate(rows)]
        self.previous = dict(target=target, clock_domain_id=value['clock_domain_id'], epoch_id=value['epoch_id'],
            config_sha256=value['config_sha256'], grid_origin=t['window_start_ticks']-t['window_index']*(t['window_end_ticks']-t['window_start_ticks']), **t)
        result = dict(schema='overwatch-decoder.compact-live-roster/1', epoch_id=value['epoch_id'], config_sha256=value['config_sha256'],
            clock_domain_id=value['clock_domain_id'], configuration_status=value['configuration_status'], target=target, timing=t,
            unavailable_sources=unavailable, discarded_earlier_frames_in_window=discarded, values_carried_between_windows=False, players=players)
        if entries is not None:
            result['context_group_projections']={sid:dict(source_id=sid,semantic_projection_sha256=entries[sid]['semantic_projection_sha256'],
                source_ref='/context_group_projections/'+sid,projection=compact_context(top,'/context_group_projections/'+sid+'/projection'))for sid,top in self.window_context.items()}
        if self.ratio_sources is not None:
            result['health_ratio_sources'] = copy.deepcopy(self.ratio_sources)
        if self.ammunition_sources is not None:
            result['ammunition_sources'] = copy.deepcopy(self.ammunition_sources)
            result['ammunition_projection_refs'] = {sid:dict(semantic_frame_sha256=e['semantic_frame_sha256'],
                source_ref='/ammunition_projections/'+sid) for sid,e in self.window_ammunition.items()}
        self._forward_window(value, result)
        return result

    def _ratio_window(self, value, changed):
        sources = value.get('health_ratio_sources')
        need(changed or sources == self.ratio_sources, 'ratio_sources_changed_without_epoch')
        if sources is not None:
            need(isinstance(sources, dict) and 1 <= len(sources) <= 16, 'ratio_source_count')
            for sid, source in sources.items():
                source_id(sid)
                need(isinstance(source, dict) and set(source) ==
                     {'session_id', 'segment', 'profile_sha256', 'acquisition', 'projection'}, 'ratio_source_metadata')
                need(isinstance(source['session_id'], str) and re.fullmatch('[0-9a-f]{32}', source['session_id'])
                     and integer(source['segment']) and 1 <= source['segment'] <= 128, 'ratio_source_epoch')
                digest(source['profile_sha256'])
                acquisition = source['acquisition']
                need(isinstance(acquisition, dict), 'ratio_acquisition_metadata')
                for key in ('manifest_sha256', 'recipe_sha256', 'evidence_sha256'): digest(acquisition.get(key))
                need(source['projection'] is not None, 'ratio_projection_missing')
                validate_ratio_projection(source['projection'], acquisition)
        self.ratio_sources = copy.deepcopy(sources)

    @staticmethod
    def _unknown_ratio(reason):
        return dict(status='unknown', value=None, reason=reason, read_span_ticks=None, evidence_ref=None)

    def _forward_window(self, value, result):
        keys = ('forward_owner_sources', 'forward_owner_projections', 'forward_owners')
        configured = any(key in value for key in keys)
        changed = self.forward_config != value['config_sha256']
        if not configured:
            need(changed or self.forward_sources is None, 'forward_roster_disabled_without_epoch')
            self.forward_sources=None;self.forward_config=value['config_sha256'];self.forward_pins={}
            return
        need(all(key in value for key in keys), 'forward_roster_partial_envelope')
        sources, projections, owners = (value[key] for key in keys)
        need(isinstance(sources,dict) and 1<=len(sources)<=16 and isinstance(projections,dict)
             and set(projections)<=set(sources) and isinstance(owners,list) and len(owners)<=128,
             'forward_roster_envelope_bound')
        need(changed or self.forward_sources == sources, 'forward_roster_admission_changed_without_epoch')
        if changed:self.forward_pins={}
        expected={}
        for sid, admission in sources.items():
            source_id(sid)
            need(isinstance(admission,dict) and admission.get('schema')=='overwatch-decoder.forward-owner-source/1', 'forward_source_schema')
            for key in ('contract_sha256','binding_template_sha256'):digest(admission.get(key))
            enabled=admission.get('controller_hero_output_enabled');catalog=admission.get('controller_hero_asset_catalog_sha256')
            need(type(enabled)is bool, 'forward_source_hero_option')
            if enabled:digest(catalog)
            else:need(catalog is None,'forward_source_unconfigured_hero')
            if any(key in admission for key in CATEGORY_METADATA_KEYS):
                need(admission.get('forward_category_output_enabled')is True and all(key in admission for key in CATEGORY_METADATA_KEYS),
                     'forward_source_category_option')
                for key in CATEGORY_METADATA_KEYS[1:]:digest(admission.get(key))
            bindings=admission.get('bindings');need(isinstance(bindings,list) and 1<=len(bindings)<=32,'forward_source_bindings')
            ids=set();prefixes=[]
            for binding in bindings:
                need(isinstance(binding,dict),'forward_source_binding')
                ident,prefix=binding.get('binding_id'),binding.get('owned_field_prefix')
                need(isinstance(ident,str) and re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,63}',ident)and ident not in ids
                     and isinstance(prefix,str)and re.fullmatch('[A-Za-z][A-Za-z0-9_]{0,62}_',prefix)
                     and all(not prefix.startswith(p)and not p.startswith(prefix)for p in prefixes),'forward_source_binding_identity')
                ids.add(ident);prefixes.append(prefix)
                controller,owner=binding.get('controller_object_key'),binding.get('forward_owner_object_key')
                object_key(controller,'controller');object_key(owner,'owner')
                empty=binding.get('acquisition_empty_evidence')
                if empty is not None:
                    collection=validate_acquisition_empty_evidence(empty)
                    need(prefix==collection['prefix']+'_0000_'and owner is None,'forward_source_empty_payload')
                need(controller is not None and (owner is not None or empty is not None)and controller in self.bindings,'forward_source_roster_controller')
                names=binding.get('identity_fields')
                need(isinstance(names,list)and len(names)==(3 if empty is not None else 5) and all(isinstance(n,str)and 0<len(n)<=128 for n in names)
                     and len(set(names))==len(names) and all(n.startswith(prefix)for n in names[3:]),'forward_source_identity_fields')
                if self.bindings[controller][1]==sid:expected[(sid,ident)]=binding
            groups=admission.get('reference_groups')
            need('reference_groups' not in admission or groups is not None,'reference_group_count')
            reference_group_membership(groups,ids)
            by_id={b['binding_id']:b for b in bindings}
            for group in groups or []:
                members=[by_id[n] for n in group['binding_ids']]
                need(all(b.get('acquisition_empty_evidence')is None for b in members)
                     and len({b['controller_object_key'] for b in members})==1
                     and len({b['identity_fields'][2] for b in members})==len(members),
                     'forward_source_reference_group_scope')
        compact_projections={};validated={}
        for sid,entry in projections.items():
            need(isinstance(entry,dict)and entry.get('source_id')==sid
                 and entry.get('source_admission')==sources[sid]and sid not in value['unavailable_sources']
                 and entry.get('semantic_hash_scope')=='projection_line', 'forward_projection_admission')
            time=entry.get('source_timing',{});gap=entry.get('source_gap',{})
            need(all(integer(time.get(k))for k in ('sequence','start_ticks','end_ticks','monotonic_frequency','monotonic_origin_ticks'))
                 and time['sequence']>=0 and time['monotonic_origin_ticks']>=0 and time['monotonic_frequency']==value['monotonic_frequency']
                 and value['window_start_ticks']<=time['end_ticks']<value['window_end_ticks']
                 and value['window_end_ticks']-time['start_ticks']<=value['maximum_skew_ticks']
                 and value['observed_read_start_ticks'] is not None
                 and value['observed_read_start_ticks']<=time['start_ticks']<=time['end_ticks']<=value['observed_read_end_ticks'],
                 'forward_projection_outside_window')
            text(time.get('utc_origin'),128)
            need(type(gap.get('skipped_slots'))is int and gap['skipped_slots']==0
                 and gap.get('current_start_ticks')==time['start_ticks']and gap.get('previous_values_carried')is False,
                 'forward_projection_gap')
            previous=gap.get('previous_end_ticks')
            need(previous is None or integer(previous)and 0<=previous<=time['start_ticks'],'forward_projection_gap')
            artifacts=entry.get('source_artifacts',{});digest(artifacts.get('profile_sha256'));digest(artifacts.get('live_event_sha256'))
            for key in ('manifest_sha256','recipe_sha256','evidence_sha256'):digest(artifacts.get('acquisition',{}).get(key))
            digest(entry.get('semantic_projection_sha256'))
            recording=entry.get('source_recording',{})
            need(recording.get('complete')is False and recording.get('partial')is True and recording.get('durability_verified')is False
                 and recording.get('continuity_across_gaps')is False and recording.get('status')=='accepted_not_durability_verified',
                 'forward_projection_recording')
            pin=(artifacts['profile_sha256'],artifacts['acquisition'])
            need((sid not in self.forward_pins or self.forward_pins[sid]==pin)
                 and (sid not in self.source_pins or self.source_pins[sid]==pin),'forward_projection_source_changed_without_epoch')
            self.forward_pins[sid]=copy.deepcopy(pin)
            frame=dict(profile_sha256=artifacts['profile_sha256'],target=value['target'],timing=time,gap_before=gap,
                       source_artifacts=artifacts,forward_owner_projection=entry.get('projection'))
            projection=validate_forward_owner_frame(frame,controllers=set(self.bindings))
            need(projection is not None,'forward_projection_missing')
            metadata,rows=projection;admission=sources[sid]
            need(all(metadata.get(k)==admission.get(k)for k in ('contract_sha256','binding_template_sha256',
                'controller_hero_output_enabled','controller_hero_asset_catalog_sha256',*CATEGORY_METADATA_KEYS)),'forward_projection_contract_mismatch')
            need(('reference_groups' in metadata)==('reference_groups' in admission)
                 and metadata.get('reference_groups')==admission.get('reference_groups'),'forward_projection_reference_groups')
            bindings={b['binding_id']:b for b in admission['bindings']}
            need(len(rows)==len(bindings)and {r['binding_id']for r in rows}==set(bindings),'forward_projection_binding_set')
            for index,row in enumerate(rows):
                binding=bindings[row['binding_id']];original=entry['projection']['relations'][index]
                need(row['owned_field_prefix']==binding['owned_field_prefix']and all(row[k]is None or row[k]==binding[k]
                     for k in ('controller_object_key','forward_owner_object_key')),'forward_projection_object_mismatch')
                need(original.get('acquisition_empty_evidence')==binding.get('acquisition_empty_evidence'),'forward_projection_empty_proof')
                if row['relation_status']=='observed' or original.get('reason')=='acquisition_empty':
                    need([w['field']for w in original['identity_evidence']]==binding['identity_fields'],'forward_projection_identity_fields')
            base='/forward_owner_projections/'+sid+'/projection'
            def relocate(node):
                if isinstance(node,dict):
                    return {key:(base+child[len('/forward_owner_projection'):]if key.endswith('_ref')and isinstance(child,str)
                                 and child.startswith('/forward_owner_projection')else relocate(child))for key,child in node.items()}
                if isinstance(node,list):return [relocate(child)for child in node]
                return node
            metadata=relocate(metadata);rows=relocate(rows);validated[sid]=rows
            compact_projections[sid]=dict(source_id=sid,source_timing=time,source_gap=gap,
                semantic_projection_sha256=entry['semantic_projection_sha256'],semantic_hash_scope=entry['semantic_hash_scope'],
                source_ref='/forward_owner_projections/'+sid,
                source_artifacts_ref='/forward_owner_projections/'+sid+'/source_artifacts',
                source_recording_ref='/forward_owner_projections/'+sid+'/source_recording',
                source_admission_ref='/forward_owner_projections/'+sid+'/source_admission',projection=metadata)
        compact_owners=[];seen=set()
        for index,row in enumerate(owners):
            need(isinstance(row,dict),'forward_roster_row')
            sid,ident=row.get('primary_source_id'),row.get('binding_id');key=(sid,ident)
            need(key in expected and key not in seen,'forward_roster_nonprimary_or_duplicate');seen.add(key);binding=expected[key]
            need(all(row.get(k)==binding[k]for k in ('binding_id','owned_field_prefix','controller_object_key','forward_owner_object_key'))
                 and 'current_displayed_body'in row and row['current_displayed_body']is None,'forward_roster_configured_identity')
            status,reason=row.get('status'),row.get('reason')
            need(status in ('observed','unknown')and(reason is None or isinstance(reason,str)and 0<len(reason)<=1024),'forward_roster_status')
            result_row=self._unknown_forward_row(binding,sid,reason,category_enabled=sources[sid].get('forward_category_output_enabled')is True)
            result_row.update(status=status,source_ref='/forward_owners/'+str(index))
            if status=='observed':
                ref='/forward_owner_projections/'+sid+'/projection';i=row.get('relation_index')
                need(reason is None and row.get('projection_ref')==ref and sid in validated and integer(i)
                     and 0<=i<len(validated[sid]),'forward_roster_projection_reference')
                observed=validated[sid][i]
                need(observed['relation_status']=='observed'and all(observed[k]==binding[k]
                     for k in ('binding_id','owned_field_prefix','controller_object_key','forward_owner_object_key')),
                     'forward_roster_observed_binding')
                result_row.update(observed,status='observed',source_ref='/forward_owners/'+str(index),projection_ref=ref,relation_index=i)
            else:
                need(reason is not None and row.get('projection_ref')is None and row.get('relation_index')is None,'forward_roster_unknown_reference')
            compact_owners.append(result_row)
        need(seen==set(expected),'forward_roster_missing_primary_binding')
        self.forward_sources=copy.deepcopy(sources);self.forward_config=value['config_sha256']
        result.update(forward_owner_sources=copy.deepcopy(sources),forward_owner_projections=compact_projections,forward_owners=compact_owners)

    @staticmethod
    def _unknown_forward_row(binding, sid, reason, *, category_enabled=False):
        def unknown():return dict(status='unknown',value=None,reason=reason,read_span_ticks=None,evidence_ref=None,current_displayed_body=None)
        row={key:binding[key]for key in ('binding_id','owned_field_prefix','controller_object_key','forward_owner_object_key')}
        row.update(primary_source_id=sid,status='unknown',relation_status='unknown',reason=reason,current_displayed_body=None,
            association_kind='native_forward_reference',projection_ref=None,relation_index=None,identity_evidence_ref=None,
            identity_read_span_ticks=None,owned_fields={},position_candidate=unknown(),health_candidate=unknown(),controller_hero_asset_label_candidate=unknown())
        row['controller_hero_asset_label_candidate'].update(binding_scope='controller_only',runtime_ui_validated=False)
        if category_enabled:
            row['category_candidate']=unknown()
            row['category_candidate'].update(raw_status='unknown',validation_scope='reviewed_unlinked_zero_override_branch')
        return row

    def _observation(self, node, base, value, *, authoritative=None):
        need(isinstance(node, dict), 'invalid_roster_observation'); source_id(node.get('source_id'))
        need(type(node.get('authoritative')) is bool and (authoritative is None or node['authoritative'] is authoritative), 'invalid_observation_ownership')
        digest(node.get('semantic_projection_sha256')); artifacts = node.get('source_artifacts', {})
        digest(artifacts.get('profile_sha256')); digest(artifacts.get('live_event_sha256'))
        for key in ('manifest_sha256', 'recipe_sha256', 'evidence_sha256'): digest(artifacts.get('acquisition', {}).get(key))
        pin = (artifacts['profile_sha256'], artifacts['acquisition'])
        sid = node['source_id']; need(sid not in self.source_pins or self.source_pins[sid] == pin, 'source_profile_changed_without_roster_epoch')
        self.source_pins[sid] = pin
        recording = node.get('source_recording', {})
        need(recording.get('complete') is False and recording.get('partial') is True
             and recording.get('durability_verified') is False and recording.get('continuity_across_gaps') is False
             and recording.get('status') == 'accepted_not_durability_verified', 'invalid_observation_recording')
        timing = node.get('source_timing', {})
        need(all(integer(timing.get(key)) for key in ('sequence', 'start_ticks', 'end_ticks', 'monotonic_frequency', 'monotonic_origin_ticks'))
             and timing['sequence'] >= 0 and timing['monotonic_frequency'] == value['monotonic_frequency']
             and 0 <= timing['start_ticks'] <= timing['end_ticks']
             and value['window_start_ticks'] <= timing['end_ticks'] < value['window_end_ticks']
             and value['window_end_ticks']-timing['start_ticks'] <= value['maximum_skew_ticks']
             and value['observed_read_start_ticks'] is not None
             and value['observed_read_start_ticks'] <= timing['start_ticks'] <= timing['end_ticks'] <= value['observed_read_end_ticks'], 'observation_outside_roster_window')
        text(timing.get('utc_origin'), 128)
        result = dict(source_id=sid, authoritative=node['authoritative'], semantic_projection_sha256=node['semantic_projection_sha256'],
            profile_sha256=artifacts['profile_sha256'], source_timing={key: timing[key] for key in SOURCE_TIME_KEYS}, source_ref=base,
            source_artifacts_ref=base+'/source_artifacts', source_recording_ref=base+'/source_recording')
        validate_ammunition_observation(node, self.window_ammunition, self.ammunition_sources or {})
        ratio = (self.ratio_sources or {}).get(sid)
        projection = None if ratio is None else ratio['projection']
        need(node.get('health_ratio_projection') == projection, 'ratio_observation_metadata_mismatch')
        if ratio is not None:
            need(artifacts['profile_sha256'] == ratio['profile_sha256']
                 and all(artifacts['acquisition'].get(key) == ratio['acquisition'][key]
                         for key in ('manifest_sha256', 'recipe_sha256', 'evidence_sha256')),
                 'ratio_observation_source_mismatch')
            need(node.get('semantic_frame_sha256') == node['semantic_projection_sha256']
                 and node.get('semantic_frame_hash_scope') == 'exact_semantic_jsonl_line_including_lf',
                 'ratio_observation_frame_hash')
            result['health_ratio_projection_ref'] = base+'/health_ratio_projection'
        if 'relation' in node:
            validate_ratio_candidate(node['relation'], dict(profile_sha256=artifacts['profile_sha256'],
                source_artifacts=artifacts, target=value['target'], timing=timing), projection)
            result['relation_ref'] = base+'/relation'
            need(node.get('hero_asset_projection') == hero_asset_metadata(node['relation']), 'asset_observation_metadata_mismatch')
        if 'hero_asset_projection' in node:
            metadata = node['hero_asset_projection']
            need(isinstance(metadata, dict) and set(metadata) == {'output_enabled', 'catalog_sha256'}
                 and metadata['output_enabled'] is True, 'asset_observation_metadata_mismatch')
            if metadata['catalog_sha256'] is not None:
                pin = digest(metadata['catalog_sha256'])
                need(sid not in self.hero_asset_pins or self.hero_asset_pins[sid] == pin, 'asset_catalog_changed_without_epoch')
                self.hero_asset_pins[sid] = pin
            result['hero_asset_projection_ref'] = base+'/hero_asset_projection'
        if sid in self.window_context:
            entry=value['context_group_projections'][sid];ref='/context_group_projections/'+sid+'/projection'
            need(node.get('context_group_projection_ref')==ref and node['semantic_projection_sha256']==entry['semantic_projection_sha256']
                 and node['source_timing']==entry['source_timing']and node['source_artifacts']==entry['source_artifacts'],'compact_context_observation_scope')
            result['context_group_projection_ref']=ref
        else:need(node.get('context_group_projection_ref')is None,'compact_missing_context_projection')
        return result

    def _unresolved(self,row,index,value):
        """Keep only unknown candidates and pointers to this window's evidence."""
        base='/relations/'+str(index);ck=row['controller_object_key']
        need(row.get('status')=='unknown' and row.get('authoritative_observation')is None
             and row.get('supporting_observations')==[] and row.get('contributor_evidence')==[]
             and row.get('conflicting_static_fields')==[], 'unresolved_roster_carried_observations')
        declarations=row.get('unresolved_body_sources');nodes=row.get('unresolved_body_observations')
        need(isinstance(declarations,list) and 1<=len(declarations)<=16 and isinstance(nodes,list) and len(nodes)<=16,'unresolved_roster_evidence_bound')
        declared={};declaration_refs=[]
        for i,item in enumerate(declarations):
            need(isinstance(item,dict) and set(item)=={'source_id','controller_object_key','reason','controller_identity_fields',
                'body_lookup_key_field','body_field_prefix','profile_sha256','acquisition_evidence_sha256','profile_guards_sha256'},'invalid_unresolved_declaration')
            sid=item.get('source_id');source_id(sid)
            names=item.get('controller_identity_fields');prefix=item.get('body_field_prefix')
            need(sid not in declared and item.get('controller_object_key')==ck
                 and item.get('reason')=='body_fields_not_declared' and isinstance(names,list)
                 and len(names)==2 and len(set(names))==2,'invalid_unresolved_declaration')
            for name in names:text(name,256)
            text(item.get('body_lookup_key_field'),256);text(prefix,128)
            need(prefix.endswith('_body_'),'invalid_unresolved_declaration')
            for key in ('profile_sha256','acquisition_evidence_sha256','profile_guards_sha256'):digest(item.get(key))
            declared[sid]={k:v for k,v in item.items()if k!='source_id'}
            pin=(ck,sid);need(pin not in self.unresolved_pins or self.unresolved_pins[pin]==declared[sid],'unresolved_declaration_changed_without_epoch')
            self.unresolved_pins[pin]=declared[sid]
            declaration_refs.append(dict(source_id=sid,profile_sha256=item['profile_sha256'],
                acquisition_evidence_sha256=item['acquisition_evidence_sha256'],profile_guards_sha256=item['profile_guards_sha256'],
                source_ref=base+'/unresolved_body_sources/'+str(i)))
        need(row['primary_source_id']in declared,'unresolved_primary_declaration_missing')
        refs=[];seen=set()
        for i,node in enumerate(nodes):
            ref=self._observation(node,base+'/unresolved_body_observations/'+str(i),value)
            sid=node['source_id'];relation=node.get('relation',{});declaration=node.get('declaration')
            need(sid in declared and sid not in seen and declaration==declared[sid]
                 and node['authoritative']==(sid==row['primary_source_id'])
                 and declaration['profile_sha256']==node['source_artifacts']['profile_sha256']
                 and declaration['acquisition_evidence_sha256']==node['source_artifacts']['acquisition']['evidence_sha256'], 'unresolved_observation_binding')
            seen.add(sid)
            need(relation.get('controller_object_key')==ck and relation.get('body_object_key')is None
                 and relation.get('relation_status')=='unknown' and relation.get('reason')=='unsupported_word_binding'
                 and relation.get('visibility')=='unknown','unresolved_relation_binding')
            need(all(relation.get(k)is None for k in ('name','team','position_candidate','health_candidate',
                'hero_resource_guid_candidate','hero_label','hero_asset_label_candidate','hero_asset_label_evidence','cached_label_candidate','raw_category_candidate',
                'team_candidate','relative_allegiance_candidate','category_evidence')), 'unresolved_relation_carried_values')
            words=relation.get('evidence');need(isinstance(words,list)and len(words)==2
                and [w.get('field')for w in words]==declaration['controller_identity_fields']
                and all(integer(w.get('value'))and 0<=w['value']<=0xffffffff for w in words),'unresolved_controller_evidence')
            validate_scope(relation,node['source_timing'],declaration['profile_sha256'],value['target']['executable_sha256'],
                identity=dict(controller_object_key=ck,body_object_key=None))
            ref.update(controller_read_span_ticks=span(words,node['source_timing']),declaration_ref=base+'/unresolved_body_observations/'+str(i)+'/declaration')
            refs.append(ref)
        primary=any(ref['authoritative']for ref in refs)
        need((row['reason']=='body_binding_unresolved')==primary,'unresolved_primary_reason')
        return dict(declaration_refs=declaration_refs,observation_refs=refs,
                    meaning='body_not_bound_in_current_profile_not_physical_absence')

    def _row(self, row, index, value):
        base = '/relations/'+str(index); ck, bk = row['controller_object_key'], row['body_object_key']
        status, reason = row.get('status'), row.get('reason')
        need(status in ('observed', 'unknown') and (reason is None or isinstance(reason, str) and len(reason) <= 1024)
             and row.get('visibility') == 'unknown' and row.get('public_state_eligible') is False, 'invalid_roster_row_status')
        conflicts = row.get('conflicting_static_fields'); need(isinstance(conflicts, list) and len(conflicts) <= 16, 'invalid_static_conflicts')
        for field in conflicts: text(field, 128)
        contributors = row.get('contributor_evidence'); supports = row.get('supporting_observations')
        need(isinstance(contributors, list) and len(contributors) <= 16 and isinstance(supports, list) and len(supports) <= 16, 'observation_count_bound')
        contributor_refs = [self._observation(node, base+'/contributor_evidence/'+str(i), value) for i, node in enumerate(contributors)]
        need(len({r['source_id'] for r in contributor_refs}) == len(contributor_refs), 'duplicate_source_contributor')
        def match(node):
            expected = next((item for item in contributors if item['source_id'] == node['source_id']), None)
            need(expected is not None and all(node[key] == expected[key] for key in expected), 'observation_contributor_mismatch')
        supporting_refs = []
        for i, node in enumerate(supports):
            match(node); supporting_refs.append(self._observation(node, base+'/supporting_observations/'+str(i), value, authoritative=False))
            relation = node.get('relation', {})
            need(relation.get('controller_object_key') == ck and relation.get('body_object_key') == bk
                 and relation.get('relation_status') == 'observed' and relation.get('visibility') == 'unknown', 'supporting_object_mismatch')
            top=self.window_context.get(node['source_id'])
            if top is not None:validate_actor_context(relation,top,profile_sha256=node['source_artifacts']['profile_sha256'],build_sha256=value['target']['executable_sha256'],timing=node['source_timing'])
            else:need(relation.get('context_group_candidate')is None and relation.get('context_group_evidence')is None,'unconfigured_support_context')
            validate_scope(relation, node['source_timing'], node['source_artifacts']['profile_sha256'], value['target']['executable_sha256'])
            compact_hero_asset(relation, dict(profile_sha256=node['source_artifacts']['profile_sha256'], target=value['target'],
                source_artifacts=node['source_artifacts'], timing=node['source_timing']), base+'/supporting_observations/'+str(i)+'/relation', detached=True)
        need({r['source_id'] for r in supporting_refs} == {r['source_id'] for r in contributor_refs if not r['authoritative']}
             and len(supporting_refs) == len({r['source_id'] for r in supporting_refs}), 'supporting_reference_mismatch')
        selected = row.get('authoritative_observation'); primary_ref = None; candidates = null_candidates(reason)
        if self.hero_asset_enabled:
            candidates['hero_asset_label_candidate'] = dict(status='unknown', value=None, reason=reason, read_span_ticks=None, evidence_ref=None, runtime_ui_validated=False)
        if row['primary_source_id'] in (self.ratio_sources or {}):
            candidates['health_ratio_candidate'] = self._unknown_ratio(reason)
        ammo_enabled = row['primary_source_id'] in (self.ammunition_sources or {})
        if ammo_enabled: candidates.update(compact_ammunition(None, None, reason))
        has_context = 'context_group_projections'in value
        if has_context:candidates['context_group_candidate']=dict(status='unknown',value=None,reason=reason,read_span_ticks=None,evidence_ref=None,context_projection_ref=None)
        if status == 'observed':
            need(reason is None and not conflicts and isinstance(selected, dict) and selected.get('source_id') == row['primary_source_id'], 'invalid_selected_primary')
            match(selected); primary_ref = self._observation(selected, base+'/authoritative_observation', value, authoritative=True)
            relation = selected.get('relation', {})
            need(relation.get('controller_object_key') == ck and relation.get('body_object_key') == bk
                 and relation.get('relation_status') == 'observed' and relation.get('reason') is None and relation.get('visibility') == 'unknown', 'primary_object_mismatch')
            for support in supports:
                left, right = static_values(relation), static_values(support['relation'])
                need(all(left[key] is None or right[key] is None or left[key] == right[key] for key in left), 'observed_static_conflict')
            frame = dict(profile_sha256=selected['source_artifacts']['profile_sha256'], target=value['target'],
                source_artifacts=selected['source_artifacts'], timing=selected['source_timing'])
            if selected.get('health_ratio_projection') is not None:
                frame['health_ratio_projection'] = selected['health_ratio_projection']
            asset_metadata = selected.get('hero_asset_projection')
            if asset_metadata is not None:
                frame.update(hero_asset_output_enabled=True, hero_asset_catalog_sha256=asset_metadata['catalog_sha256'])
            top=self.window_context.get(selected['source_id'])
            reference=validate_actor_context(relation,top,profile_sha256=frame['profile_sha256'],build_sha256=value['target']['executable_sha256'],timing=frame['timing']) if top is not None else None
            if top is None:need(relation.get('context_group_candidate')is None and relation.get('context_group_evidence')is None,'unconfigured_compact_actor_context')
            candidates = compact_candidates(relation, frame, base+'/authoritative_observation/relation',context_reference=reference)
            if ammo_enabled:
                candidates.update(compact_ammunition(relation, self.window_ammunition.get(selected['source_id']),
                    base='/ammunition_projections/'+selected['source_id']))
            if self.hero_asset_enabled and 'hero_asset_label_candidate' not in candidates:
                candidates['hero_asset_label_candidate'] = dict(status='unknown', value=None, reason='asset_primary_unconfigured', read_span_ticks=None, evidence_ref=None, runtime_ui_validated=False)
            if has_context:
                candidates['context_group_candidate']=_compact_actor_context(relation,top,base+'/authoritative_observation/relation','/context_group_projections/'+selected['source_id']+'/projection',reference) if top is not None else dict(status='unknown',value=None,reason='context_projection_unavailable',read_span_ticks=None,evidence_ref=None,context_projection_ref=None)
        else:
            need(selected is None and reason is not None and row.get('health_ratio_candidate') is None
                 and row.get('ammunition_candidate') is None and row.get('ammunition_callback_candidate') is None,
                 'unknown_roster_has_primary_values')
        result=dict(controller_object_key=ck, body_object_key=bk, primary_source_id=row['primary_source_id'], status=status, reason=reason,
            conflicting_static_fields=conflicts, source_ref=base, primary_observation=primary_ref,
            supporting_observation_refs=supporting_refs, contributor_refs=contributor_refs, **candidates)
        if bk is None:result['unresolved_body']=self._unresolved(row,index,value)
        return result

    def _transition(self, value):
        target = self._context(value); status = value.get('status'); digest(value.get('previous_config_sha256'))
        if self.startup_expected is not None:
            need(value['previous_config_sha256']==self.startup_expected['config']and value.get('start_ticks',-1)>=self.startup_expected['boundary'],'startup_transition_mismatch')
            self.startup_expected=None
        need(status in ('unknown', 'resumed_without_carried_values') and integer(value.get('revision')) and 1 <= value['revision'] <= MAX_EPOCHS
             and integer(value.get('start_ticks')) and value['start_ticks'] >= 0
             and value.get('previous_values_carried') is False and value.get('pending_observations_discarded') is True, 'invalid_roster_transition')
        if self.previous:
            expected_config = (self.transition['previous_config_sha256'] if self.transition else
                self.resume['next_config_sha256'] if self.resume else self.previous['config_sha256'])
            earliest = self.resume['end_ticks'] if self.resume else self.previous['window_end_ticks']
            need(value['previous_config_sha256'] == expected_config
                 and value['start_ticks'] >= earliest, 'transition_previous_scope_mismatch')
        trigger = value.get('trigger', {}); source_id(trigger.get('source_id'))
        for key in ('semantic_projection_sha256', 'live_event_sha256'): digest(trigger.get(key))
        need(integer(trigger.get('read_start_ticks')) and integer(trigger.get('read_end_ticks'))
             and 0 <= trigger['read_start_ticks'] <= trigger['read_end_ticks'], 'invalid_transition_read_span')
        rows = value.get('relations'); need(isinstance(rows, list) and 1 <= len(rows) <= 128, 'invalid_transition_roster')
        players = []
        for i, row in enumerate(rows):
            object_key(row.get('controller_object_key'), 'controller')
            need(row.get('controller_object_key') is not None and row.get('body_object_key') is None and row.get('status') == 'unknown'
                 and row.get('reason') == 'roster_epoch_transition' and row.get('authoritative_observation') is None
                 and row.get('supporting_observations') == [] and row.get('contributor_evidence') == []
                 and row.get('health_ratio_candidate') is None and row.get('ammunition_candidate') is None
                 and row.get('ammunition_callback_candidate') is None, 'transition_has_candidate_values')
            players.append(dict(controller_object_key=row['controller_object_key'], body_object_key=None, status='unknown',
                reason=row['reason'], source_ref='/relations/'+str(i), **null_candidates(row['reason'])))
        if self.ratio_sources is not None:
            for row in players:
                if self.bindings.get(row['controller_object_key'], (None, None))[1] in self.ratio_sources:
                    row['health_ratio_candidate'] = self._unknown_ratio('roster_epoch_transition')
        if self.ammunition_sources is not None:
            for row in players:
                if self.bindings.get(row['controller_object_key'], (None, None))[1] in self.ammunition_sources:
                    row.update(compact_ammunition(None, None, 'roster_epoch_transition'))
        if self.context_enabled:
            for row in players:row['context_group_candidate']=dict(status='unknown',value=None,reason='roster_epoch_transition',read_span_ticks=None,evidence_ref=None,context_projection_ref=None)
        keys = [row['controller_object_key'] for row in players]
        need(len(set(keys)) == len(keys) and (not self.bindings or set(keys) == set(self.bindings))
             and (self.transition_controllers is None or set(keys) == self.transition_controllers), 'transition_controller_mismatch')
        self.transition_controllers = set(keys)
        if status == 'unknown':
            need(self.transition is None and value.get('end_ticks') is None
                 and (self.last_revision is None or value['revision'] == self.last_revision), 'duplicate_open_transition')
            self.resume = None
            self.transition = dict(start_ticks=value['start_ticks'], revision=value['revision'], trigger=trigger,
                                   previous_config_sha256=value['previous_config_sha256'], target=value['target'],
                                   clock_domain_id=value['clock_domain_id'], monotonic_frequency=value['monotonic_frequency'])
        else:
            need(self.transition is not None and all(value.get(key) == old for key, old in self.transition.items() if key != 'revision')
                 and value['revision'] == self.transition['revision']+1 and integer(value.get('end_ticks')) and value['end_ticks'] >= value['start_ticks'], 'unmatched_transition_closure')
            digest(value.get('next_config_sha256')); need(value['next_config_sha256'] != value['previous_config_sha256'], 'stale_transition_config')
            admissions = value.get('source_admissions'); need(isinstance(admissions, dict) and 1 <= len(admissions) <= 16, 'missing_transition_admissions')
            self.last_revision = value['revision']
            self.transition = None; self.resume = dict(next_config_sha256=value['next_config_sha256'], end_ticks=value['end_ticks'])
        result = dict(schema='overwatch-decoder.compact-live-roster-transition/1', configuration_status=value['configuration_status'], status=status, revision=value['revision'], target=target,
            clock_domain_id=value['clock_domain_id'], monotonic_frequency=value['monotonic_frequency'],
            start_ticks=value['start_ticks'], end_ticks=value.get('end_ticks'), previous_config_sha256=value['previous_config_sha256'],
            next_config_sha256=value.get('next_config_sha256'), previous_values_carried=False, pending_observations_discarded=True,
            trigger_ref='/trigger', source_admissions_ref='/source_admissions' if 'source_admissions' in value else None, players=players)

        if self.forward_sources is not None:
            result['forward_owner_sources']=copy.deepcopy(self.forward_sources)
            result['forward_owners']=[self._unknown_forward_row(binding,sid,'roster_epoch_transition',category_enabled=admission.get('forward_category_output_enabled')is True)
                for sid,admission in self.forward_sources.items()for binding in admission['bindings']
                if self.bindings.get(binding['controller_object_key'],(None,None))[1]==sid]

        if 'input_end' in value:
            ending=value['input_end']
            need(status=='unknown' and isinstance(ending,dict)
                 and set(ending)=={'reason','evidence_kind','stop_ticks','discarded_pending_windows','discarded_pending_bytes','source_result_sha256'}
                 and ending['reason']=='finite_sources_completed' and trigger.get('reason')==ending['reason']
                 and ending['evidence_kind']=='caller_verified_producer_eof_not_native_sample'
                 and integer(ending['stop_ticks']) and ending['stop_ticks']>=trigger['read_end_ticks'], 'invalid_runtime_completion')
            for key in ('discarded_pending_windows','discarded_pending_bytes'):
                need(integer(ending[key]) and 0<=ending[key]<=MAX_BYTES,'invalid_runtime_completion')
            pins=ending['source_result_sha256'];need(isinstance(pins,dict) and 1<=len(pins)<=16,'invalid_runtime_completion')
            for sid,pin in pins.items():source_id(sid);digest(pin)
            result['input_end']=dict(ending,source_result_sha256=dict(pins))
            self.input_ended=True
        return result

    def summary(self):
        return dict(schema='overwatch-decoder.compact-live-roster-result/1', events=self.events, windows=self.windows, players=self.players,
            unknown_primary_rows=self.unknown, candidate_coverage=dict(self.coverage), aggregate_epochs=len(self.epochs),
            open_transition=self.transition is not None, awaiting_resumed_window=self.resume is not None,
            input_bytes=self.input_bytes, output_bytes=self.output_bytes, input_sha256=self.input_hash.hexdigest(),
            output_sha256=self.output_hash.hexdigest(), failed=self.failed, privacy='private', atomic=False,
            public_state_eligible=False, durability_verified=False)


def stream(projector, source, output):
    while True:
        raw = source.readline(MAX_LINE+1)
        if not raw: break
        output.write(encode(projector.consume(raw))); output.flush()
    return projector.summary()


def compact_finite_roster(manifest_path, aggregate_path, output_path, *, maximum_output_bytes=MAX_BYTES):
    """Compact a saved finite aggregate against its original hashed manifest.

    Re-use the finite aggregator for admission and exact aggregate-byte replay.
    No live session, watermark, durability state or epoch event is invented.
    Output pointers refer to each original finite aggregate JSONL line. Native
    acquisition verification remains the finite exporter's responsibility.
    Owner/context projections and other unsupported enrichments reject explicitly;
    this entry point does not silently recast them as ordinary body candidates.
    """
    from aggregate_partitions import aggregate, Manifest, open_regular
    need(integer(maximum_output_bytes) and 0 < maximum_output_bytes <= MAX_BYTES, 'invalid_compact_limit')
    aggregate_path, output_path = Path(aggregate_path).resolve(), Path(output_path).resolve()
    manifest = Manifest(manifest_path)
    need(all(source.get('forward_owner_projection') is None and source.get('context_projection') is None
             for source in manifest.sources.values()), 'finite_compact_unsupported_owner_or_context_projection')
    need(not output_path.exists() and output_path != manifest.path and output_path != aggregate_path
         and all(output_path != source['resolved_path'] for source in manifest.sources.values()), 'output_exists_or_is_source')
    with open_regular(aggregate_path, MAX_BYTES)[0] as file:
        original_hash = hashlib.file_digest(file, 'sha256').hexdigest()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.TemporaryDirectory(prefix='finite-roster-validation-') as directory:
            replay_path = Path(directory)/'aggregate.jsonl'
            report = aggregate(manifest.path, replay_path, MAX_BYTES)
            need(report['output_sha256'] == original_hash, 'finite_aggregate_replay_mismatch')
            windows = players = ratios = unknown = output_bytes = 0
            output_hash = hashlib.sha256()
            with replay_path.open('rb') as source, tempfile.NamedTemporaryFile(mode='wb', dir=output_path.parent,
                    prefix='.compact-finite-roster-', suffix='.partial', delete=False) as file:
                temporary = Path(file.name)
                for line in source:
                    value = parse(line)
                    need(value['manifest_sha256'] == manifest.hash, 'finite_manifest_changed')
                    ammunition_entries = validate_ammunition_window(value)
                    compact_rows = []
                    for index, row in enumerate(value['relations']):
                        base = '/relations/'+str(index)
                        selected = row['authoritative_observation']
                        for observation in ([selected] if selected is not None else []) + row['supporting_observations']:
                            relation = observation['relation']
                            need(relation.get('name') is None and not any(key in relation for key in
                                ('context_group_candidate',
                                 'context_group_evidence', 'raw_flags_candidate', 'private_battletag', 'private_name_bytes_sha256')),
                                'finite_compact_unsupported_enrichment')
                        declared = manifest.sources[row['primary_source_id']]
                        enabled = declared.get('health_ratio_projection') is not None
                        if selected is None:
                            candidates = null_candidates(row['reason'])
                            if enabled:
                                candidates['health_ratio_candidate'] = dict(status='unknown', value=None,
                                    reason=row['reason'], read_span_ticks=None, evidence_ref=None)
                            observation = None
                        else:
                            frame = dict(profile_sha256=selected['source_artifacts']['profile_sha256'],
                                target=value['target'], source_artifacts=selected['source_artifacts'],
                                timing=selected['source_timing'], health_ratio_projection=selected.get('health_ratio_projection'))
                            candidates = compact_candidates(selected['relation'], frame,
                                base+'/authoritative_observation/relation', finite_source=True)
                            observation = dict(source_id=selected['source_id'], source_timing=selected['source_timing'],
                                source_artifacts=selected['source_artifacts'], source_recording=selected['source_recording'],
                                semantic_source_sha256=selected['semantic_source_sha256'],
                                evidence_ref=base+'/authoritative_observation')
                            if enabled:
                                observation.update(semantic_frame_sha256=selected['semantic_frame_sha256'],
                                    semantic_frame_hash_scope=selected['semantic_frame_hash_scope'])
                        if declared.get('ammunition') is not None:
                            candidates.update(compact_ammunition(None if selected is None else selected['relation'],
                                ammunition_entries.get(row['primary_source_id']), row['reason'],
                                '/ammunition_projections/'+row['primary_source_id']))
                        result = dict(controller_object_key=row['controller_object_key'], body_object_key=row['body_object_key'],
                            primary_source_id=row['primary_source_id'], status=row['status'], reason=row['reason'],
                            source_ref=base, primary_observation=observation,
                            supporting_observations_ref=base+'/supporting_observations',
                            conflicting_static_fields=row['conflicting_static_fields'], **candidates)
                        compact_rows.append(result)
                        players += 1; unknown += row['status'] == 'unknown'
                        ratios += result.get('health_ratio_candidate', {}).get('value') is not None
                    compact = dict(schema='overwatch-decoder.compact-finite-roster/1', manifest_sha256=value['manifest_sha256'],
                        epoch_id=value['epoch_id'], clock_domain_id=value['clock_domain_id'], target=value['target'],
                        **{key:value[key] for key in TIME_KEYS if key in value}, players=compact_rows,
                        unavailable_sources=value['unavailable_sources'], values_carried_between_windows=False,
                        privacy='private', atomic=False, visibility='unknown', public_state_eligible=False,
                        validation_scope='replayed_finite_manifest_not_native_reverification',
                        source_frame=dict(sha256=hashlib.sha256(line).hexdigest(),
                            hash_scope='exact_aggregate_jsonl_line_including_lf', evidence_root='original_aggregate_line',
                            original_evidence_required=True))
                    encoded = encode(compact)
                    need(len(encoded) <= MAX_OUTPUT_LINE and output_bytes+len(encoded) <= maximum_output_bytes,
                         'compact_roster_output_bound')
                    file.write(encoded); output_hash.update(encoded); output_bytes += len(encoded); windows += 1
                file.flush(); os.fsync(file.fileno())
            # Recheck the user's retained aggregate before publishing the result.
            with open_regular(aggregate_path, MAX_BYTES)[0] as file:
                need(hashlib.file_digest(file, 'sha256').hexdigest() == original_hash, 'finite_aggregate_changed')
            with open_regular(manifest.path, 262144)[0] as file:
                need(hashlib.file_digest(file, 'sha256').hexdigest() == manifest.hash, 'finite_manifest_changed')
            os.link(temporary, output_path)
            return dict(schema='overwatch-decoder.compact-finite-roster-result/1', windows=windows, players=players,
                unknown_primary_rows=unknown, health_ratio_candidates=ratios, input_sha256=original_hash,
                output_sha256=output_hash.hexdigest(), output_bytes=output_bytes, atomic=False,
                public_state_eligible=False, native_reverified=False, all_input_sources_complete=report['all_input_sources_complete'])
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--finite-manifest', type=Path, help='explicit saved finite aggregate manifest; no live admission')
    parser.add_argument('--finite-aggregate', type=Path)
    parser.add_argument('--finite-output', type=Path)
    parser.add_argument('--maximum-input-bytes', type=int, default=MAX_BYTES)
    parser.add_argument('--maximum-output-bytes', type=int, default=MAX_BYTES)
    args = parser.parse_args()
    try:
        if args.finite_manifest is not None:
            need(args.finite_aggregate is not None and args.finite_output is not None, 'finite_paths_required')
            result = compact_finite_roster(args.finite_manifest, args.finite_aggregate, args.finite_output,
                maximum_output_bytes=args.maximum_output_bytes)
            print(encode(result).decode(), end='', file=sys.stderr)
            return 0
        need(args.finite_aggregate is None and args.finite_output is None, 'finite_manifest_required')
        result = stream(CompactLiveRoster(maximum_input_bytes=args.maximum_input_bytes,
            maximum_output_bytes=args.maximum_output_bytes), sys.stdin.buffer, sys.stdout.buffer)
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError, OverflowError, OSError) as error:
        print(encode(dict(schema='overwatch-decoder.compact-live-roster-result/1', failed=True, error=str(error), public_state_eligible=False)).decode(), end='', file=sys.stderr)
        return 2
    print(encode(result).decode(), end='', file=sys.stderr); return 0


if __name__ == '__main__': raise SystemExit(main())
