#!/usr/bin/env python3
"""Bounded aggregation of reviewed, configured live semantic partitions.

Configuration is trusted caller input, not native observation proof. This module
validates projected evidence consistency; upstream LiveRelations admits native
bytes. Epoch changes require a new whole configuration. Delivery is private,
non-atomic and never certifies recording durability.
"""
from collections import Counter
import copy
import argparse
import json
from pathlib import Path
import re
import sys

from aggregate_partitions import (MAX_LINE_BYTES, MAX_TOTAL_BYTES, InvalidPartitions,
    canonical, digest, integer, need, nested_scope, object_pair, configured_pair, origin_offset,
    parse, project_window, read_bracket, sha, _validate_row_values)

from ammunition_projection_validation import validate_source as validate_ammunition_source, validate_frame as validate_ammunition_frame, retain as retain_ammunition
from health_ratio_validation import validate_projection as validate_ratio_projection, validate_candidate as validate_ratio_candidate

from context_projection_validation import validate_context_source, validate_context_frame
from forward_roster_projection import validate_source as validate_forward_source, validate_frame as validate_forward_frame

MAX_PENDING_BYTES = 16 * 1024 * 1024
MAX_OPEN_WINDOWS = 256
MAX_WINDOWS = 100000
MAX_EVENTS = 100000
MAX_OUTPUT_LINE_BYTES = 16 * 1024 * 1024
FIELDS = ('position_candidate', 'health_candidate', 'hero_resource_guid_candidate',
          'hero_label', 'cached_label_candidate', 'name', 'raw_category_candidate',
          'team_candidate', 'relative_allegiance_candidate')


def unresolved_row_matches(row, declaration):
    """Upstream relation stopped at an undeclared body, not a failed read."""
    return (isinstance(declaration,dict) and row.get('relation_status')=='unknown'
            and row.get('controller_object_key')==declaration.get('controller_object_key')
            and row.get('body_object_key')is None and row.get('reason')=='unsupported_word_binding'
            and [w.get('field')for w in row.get('evidence',[]) if isinstance(w,dict)]
                ==declaration.get('controller_identity_fields'))

class LivePartitions:
    def __init__(self, raw_config, *, maximum_output_bytes=MAX_TOTAL_BYTES):
        need(isinstance(raw_config, bytes) and 0 < len(raw_config) <= 262144, 'live_config_size')
        value = parse(raw_config)
        need(value.get('schema') == 'overwatch-decoder.live-partition-config/1', 'live_config_schema')
        self.hash = sha(raw_config)
        for key in ('epoch_id', 'clock_domain_id'):
            need(isinstance(value.get(key), str) and 1 <= len(value[key]) <= 128, 'invalid_' + key)
        self.epoch, self.clock = value['epoch_id'], value['clock_domain_id']
        self.target = value.get('target', {})
        need(isinstance(self.target, dict) and integer(self.target.get('pid')) and self.target['pid'] > 0
             and integer(self.target.get('creation_file_time')) and self.target['creation_file_time'] > 0
             and self.target.get('architecture') == 'x64' and isinstance(self.target.get('image_name'), str), 'invalid_target')
        digest(self.target.get('executable_sha256'))
        self.frequency, self.origin, self.window, self.skew, self.tolerance = [value.get(key) for key in (
            'monotonic_frequency', 'window_origin_ticks', 'window_ticks', 'maximum_skew_ticks', 'maximum_origin_offset_ticks')]
        need(all(integer(n) for n in (self.frequency, self.origin, self.window, self.skew, self.tolerance))
             and 0 < self.frequency <= 10**12 and self.origin >= 0
             and 0 < self.window <= self.skew <= 5 * self.frequency
             and 0 <= self.tolerance <= self.frequency, 'invalid_time_bounds')
        self.allow_unresolved=value.get('allow_unresolved_bodies',False)
        need(type(self.allow_unresolved)is bool and (not self.allow_unresolved or value.get('observation_mode')=='raw-candidates'),'invalid_unresolved_body_policy')
        rows = value.get('roster')
        need(isinstance(rows, list) and 1 <= len(rows) <= 128, 'invalid_roster')
        self.roster = {}
        for row in rows:
            pair = configured_pair(row,self.allow_unresolved)
            need(pair not in self.roster and not any(pair[0] == p[0] or pair[1] is not None and pair[1] == p[1] for p in self.roster), 'ambiguous_roster_identity')
            self.roster[pair] = row.get('primary_source_id')
        sources = value.get('sources')
        need(isinstance(sources, list) and 1 <= len(sources) <= 16, 'invalid_source_count')
        self.sources = {}
        for source in sources:
            sid = source.get('source_id')
            need(isinstance(sid, str) and re.fullmatch('[A-Za-z0-9_-]{1,64}', sid) and sid not in self.sources, 'invalid_source_id')
            need(isinstance(source.get('session_id'), str) and re.fullmatch('[0-9a-f]{32}', source['session_id'])
                 and integer(source.get('segment')) and 1 <= source['segment'] <= 128, 'invalid_source_epoch')
            digest(source.get('profile_sha256'))
            acquisition = source.get('acquisition', {})
            for key in ('manifest_sha256', 'recipe_sha256', 'evidence_sha256'):
                digest(acquisition.get(key))
            validate_ammunition_source(source)
            ratio_projection = source.get('health_ratio_projection')
            validate_ratio_projection(ratio_projection, acquisition)
            if ratio_projection is not None:
                need(all(pair['type'] == 'f32x3' for item in ratio_projection['contracts'] for pair in item['paired_slots']),
                     'live_ratio_requires_f32x3')
            objects = source.get('objects')
            need(isinstance(objects, list) and 1 <= len(objects) <= 32, 'invalid_source_objects')
            pairs = [configured_pair(obj,self.allow_unresolved) for obj in objects]
            need(len(set(pairs)) == len(pairs) and set(pairs).issubset(self.roster), 'undeclared_source_object')
            fields = source.get('fields')
            need(isinstance(fields, list) and 1 <= len(fields) <= 160, 'invalid_field_declarations')
            declarations = {}
            for field in fields:
                name, kind = field.get('name'), field.get('type')
                need(isinstance(name, str) and 1 <= len(name) <= 256 and name not in declarations
                     and kind in ('u8', 'i32', 'f32', 'f32x3'), 'invalid_field_declarations')
                declarations[name] = kind
            unresolved=source.get('unresolved_bodies',[])
            need(isinstance(unresolved,list) and len(unresolved)<=len(pairs) and all(isinstance(r,dict)for r in unresolved),'invalid_unresolved_body_evidence')
            keys={c for c,b in pairs if b is None}
            need(len(unresolved)==len(keys) and {r.get('controller_object_key')for r in unresolved}==keys,'missing_unresolved_body_evidence')
            if keys:need(self.allow_unresolved and source.get('live_category')is None,'unresolved_body_requires_raw_mode')
            for item in unresolved:
                names=item.get('controller_identity_fields');prefix=item.get('body_field_prefix')
                need(item.get('reason')=='body_fields_not_declared' and item.get('profile_sha256')==source['profile_sha256']
                     and item.get('acquisition_evidence_sha256')==acquisition['evidence_sha256']
                     and isinstance(names,list) and len(names)==2 and len(set(names))==2
                     and all(declarations.get(n)=='i32'for n in names)
                     and declarations.get(item.get('body_lookup_key_field'))=='i32'
                     and isinstance(prefix,str) and prefix.endswith('_body_') and len(prefix)<=128
                     and not any(n.startswith(prefix)for n in declarations),'invalid_unresolved_body_evidence')
                digest(item.get('profile_guards_sha256'))
            if ratio_projection is not None:
                need(all(declarations.get(pair['field_name']) == pair['type']
                         for item in ratio_projection['contracts'] for pair in item['paired_slots']),
                     'ratio_field_declaration_mismatch')
            validate_context_source(source)
            validate_forward_source(source)
            need(source.get('context_projection')is None or source.get('live_category')is None,'context_legacy_config_conflation')
            self.sources[sid] = dict(source, object_pairs=set(pairs), declarations=declarations,
                                     sequence=0, previous_end=None, event_sequence=None, anchor=None)
        for pair, primary in self.roster.items():
            need(primary in self.sources and pair in self.sources[primary]['object_pairs'], 'invalid_primary_source')
        for source in self.sources.values():
            category = source.get('live_category')
            if category is not None:
                need(isinstance(category, dict), 'invalid_live_category_config')
                for key in ('contract_sha256', 'native_review_sha256', 'roster_review_sha256', 'mode_review_sha256'):
                    digest(category.get(key))
                scope = category.get('live_scope', {})
                need(isinstance(category.get('mode_id'), str) and category['mode_id']
                     and category.get('self_controller_object_key') in {pair[0] for pair in source['object_pairs']}
                     and all(scope.get(k) == source[k] for k in ('session_id', 'segment'))
                     and scope.get('monotonic_frequency') == self.frequency
                     and integer(scope.get('start_ticks')) and scope['start_ticks'] >= 0, 'invalid_live_category_config')
                for key in ('session_start_sha256', 'segment_start_sha256'):
                    digest(scope.get(key))
        need(integer(maximum_output_bytes) and 0 < maximum_output_bytes <= MAX_TOTAL_BYTES, 'invalid_output_byte_limit')
        self.maximum_output = maximum_output_bytes
        self.next_window = 0
        self.watermark = self.origin
        self.pending = {}
        self.pending_bytes = self.input_bytes = self.events = self.output_bytes = self.windows = 0
        self.offset_min = self.offset_max = None
        self.coverage = Counter({key: 0 for key in FIELDS})
        self.counts = Counter(observed_rows=0, unknown_rows=0, full_windows=0, partial_windows=0)
        self.reasons = Counter()
        self.failed = self.closed = False

    @property
    def automatic_watermark(self):
        """A stalled/unstarted source stalls this watermark; EOF proves nothing."""
        ends = [source['previous_end'] for source in self.sources.values()]
        return min(ends) if all(value is not None for value in ends) else None

    def consume(self, source_id, raw_projection, *, retain=True, context=False, minimum_start_ticks=None):
        """Validate a frame; retain=False advances ordering without window data.

        Recovery can discard frames before its future publication boundary.
        Native/source/semantic checks and input limits still apply in that mode;
        only pending-window placement and storage are skipped. A minimum start
        can discard a frame crossing a resume boundary. Optional context returns
        detached admission/identity metadata, never references to retained rows.
        """
        return self._consume_decoded(source_id, raw_projection, None, retain=retain,
                                     context=context, minimum_start_ticks=minimum_start_ticks)

    def _consume_decoded(self, source_id, raw_projection, frame, *, retain=True, context=False, minimum_start_ticks=None):
        """Trusted parse-once path: frame must be the unchanged parse of these bytes.

        Only an in-process caller that just parsed raw_projection may use this.
        Every semantic/order/evidence/budget check still runs; this does not admit
        decoded objects received from an external transport or prior frame.
        """
        need(not self.failed and not self.closed, 'live_aggregate_closed')
        try:
            need(frame is None or isinstance(frame,dict),'invalid_decoded_projection')
            need(type(retain) is bool, 'invalid_retention_mode')
            need(type(context) is bool, 'invalid_context_mode')
            need(minimum_start_ticks is None or integer(minimum_start_ticks)
                 and minimum_start_ticks >= self.origin, 'invalid_retention_boundary')
            return self._consume(source_id, raw_projection, retain=retain,
                                 context=context, minimum_start_ticks=minimum_start_ticks, decoded_frame=frame)
        except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
            self.failed = True
            raise

    def _consume(self, source_id, raw_projection, *, retain=True, context=False, minimum_start_ticks=None, decoded_frame=None):
        need(source_id in self.sources, 'unconfigured_source')
        need(isinstance(raw_projection, bytes) and 0 < len(raw_projection) <= MAX_LINE_BYTES
             and raw_projection.endswith(b'\n'), 'live_projection_line_bound')
        self.events += 1
        self.input_bytes += len(raw_projection)
        need(self.events <= MAX_EVENTS and self.input_bytes <= MAX_TOTAL_BYTES, 'live_input_bound')
        frame = parse(raw_projection) if decoded_frame is None else decoded_frame
        source = self.sources[source_id]
        need(frame.get('schema') == 'overwatch-decoder.entity-relations-live/1' and frame.get('source') == 'process_memory'
             and frame.get('target') == self.target and frame.get('profile_sha256') == source['profile_sha256']
             and frame.get('session_id') == source['session_id'] and integer(frame.get('segment'))
             and frame.get('segment') == source['segment'],
             'live_source_epoch_mismatch_reconfigure_required')
        need(frame.get('atomic') is False and frame.get('public_state_eligible') is False
             and frame.get('visibility') == 'unknown' and frame.get('privacy') == 'private'
             and frame.get('durability_verified') is False
             and frame.get('recording_state') == 'accepted_not_durability_verified', 'live_qualification_mismatch')
        recording, artifacts = frame.get('recording', {}), frame.get('source_artifacts', {})
        need(recording.get('complete') is False and recording.get('partial') is True
             and recording.get('status') == 'accepted_not_durability_verified'
             and recording.get('durability_verified') is False and recording.get('continuity_across_gaps') is False,
             'live_recording_qualification_mismatch')
        need(artifacts.get('profile_sha256') == source['profile_sha256']
             and all(artifacts.get('acquisition', {}).get(key) == source['acquisition'][key]
                     for key in ('manifest_sha256', 'recipe_sha256', 'evidence_sha256')), 'live_provenance_mismatch')
        digest(artifacts.get('live_event_sha256'))
        event_sequence = frame.get('event_sequence')
        need(integer(event_sequence) and event_sequence >= 0
             and (source['event_sequence'] is None or event_sequence > source['event_sequence']), 'live_event_order')
        timing, gap = frame.get('timing', {}), frame.get('gap_before', {})
        start, end = timing.get('start_ticks'), timing.get('end_ticks')
        need(integer(start) and integer(end) and self.origin <= start <= end
             and timing.get('sequence') == source['sequence'] and integer(timing.get('sequence'))
             and (source['previous_end'] is None or source['previous_end'] <= start)
             and timing.get('monotonic_frequency') == self.frequency
             and integer(timing.get('monotonic_origin_ticks')), 'live_source_time_order')
        anchor = timing['monotonic_origin_ticks'], timing.get('utc_origin')
        need(source['anchor'] is None or source['anchor'] == anchor, 'changed_clock_origin')
        offset = origin_offset(timing, self.frequency)
        lo = offset if self.offset_min is None else min(self.offset_min, offset)
        hi = offset if self.offset_max is None else max(self.offset_max, offset)
        need(hi - lo <= self.tolerance, 'clock_anchor_disagreement')
        need(integer(gap.get('skipped_slots')) and gap['skipped_slots'] >= 0
             and gap.get('current_start_ticks') == start and gap.get('previous_end_ticks') == source['previous_end']
             and gap.get('previous_values_carried') is False, 'source_gap_mismatch')
        index = (end - self.origin) // self.window
        retain = retain and (minimum_start_ticks is None or start >= minimum_start_ticks)
        if retain:
            need(index >= self.next_window, 'late_frame_for_closed_window')
            need(index - self.next_window < MAX_OPEN_WINDOWS, 'pending_window_bound')
        ratio_projection = source.get('health_ratio_projection')
        need(frame.get('health_ratio_projection') == ratio_projection, 'ratio_source_admission_mismatch')
        if ratio_projection is not None:
            need(frame.get('health_ratio_contract_sha256') == [item['contract_sha256'] for item in ratio_projection['contracts']],
                 'ratio_frame_contract_pins')
        else:
            need('health_ratio_contract_sha256' not in frame, 'ratio_unadmitted_contracts')
        relations = frame.get('relations')
        need(isinstance(relations, list) and len(relations) <= 128, 'invalid_semantic_rows')
        context_projection = validate_context_frame(frame, source, target=self.target)
        forward_projection = validate_forward_frame(frame, source)
        ammunition = validate_ammunition_frame(frame, source)
        rows = {};unresolved_rows={};seen_controllers=set();unresolved_declarations={item['controller_object_key']:item for item in source.get('unresolved_bodies',[])}
        for row in relations:
            need(isinstance(row, dict) and row.get('visibility') == 'unknown', 'invalid_semantic_row')
            validate_ratio_candidate(row, frame, ratio_projection)
            if row.get('relation_status') != 'observed':
                need(row.get('relation_status') == 'unknown', 'invalid_relation_status')
                if self.allow_unresolved:
                    need(row.get('body_object_key')is None and all(row.get(k)is None for k in (*FIELDS,'name','team','category_evidence')), 'unresolved_row_carried_values')
                    ck=row.get('controller_object_key')
                    if ck is not None:
                        need(ck not in seen_controllers,'duplicate_controller_row');seen_controllers.add(ck)
                        need(ck in {p[0]for p in source['object_pairs']},'unknown_row_controller_mismatch')
                        evidence=row.get('evidence');need(isinstance(evidence,list)and len(evidence)==2,'unresolved_identity_evidence')
                        nested_scope(row,timing,source['profile_sha256'],self.target['executable_sha256'],declarations=source['declarations'],objects=row)
                        need(all(source['declarations'].get(w.get('field'))=='i32'and integer(w.get('value'))and 0<=w['value']<=0xffffffff for w in evidence),'unresolved_identity_evidence')
                        for word in evidence:read_bracket(word,timing)
                        declaration=unresolved_declarations.get(ck)
                        if unresolved_row_matches(row,declaration):
                            unresolved_rows[(ck,None)]=dict(relation=row,declaration=copy.deepcopy(declaration))
                continue
            pair = object_pair(row)
            need(pair[0] not in seen_controllers,'duplicate_controller_row');seen_controllers.add(pair[0])
            need(pair in source['object_pairs'] and pair not in rows, 'unexpected_or_duplicate_object')
            self._validate_row(row, frame, source)
            rows[pair] = row
        if retain:
            projected = dict(source_id=source_id, timing=timing, gap=gap, rows=rows, artifacts=artifacts,
                             recording=recording, semantic_source_sha256=sha(raw_projection))
            if ammunition is not None:
                projected['ammunition'] = retain_ammunition(frame, sha(raw_projection))
            if ratio_projection is not None:
                projected.update(health_ratio_projection=ratio_projection, semantic_frame_sha256=sha(raw_projection))
            if context_projection is not None:projected['context_group_projection']=context_projection
            if forward_projection is not None:
                projected.update(forward_owner_projection=forward_projection, semantic_hash_scope='projection_line')
            if unresolved_rows:projected['unresolved_rows']=unresolved_rows
            bucket = self.pending.setdefault(index, {})
            old = bucket.get(source_id)
            new_size = self.pending_bytes - (old['bytes'] if old else 0) + len(raw_projection)
            need(new_size <= MAX_PENDING_BYTES, 'pending_byte_bound')
            bucket[source_id] = dict(latest=projected, count=(old['count'] if old else 0) + 1,
                                    gap=bool(gap['skipped_slots']) or bool(old and old['gap']), bytes=len(raw_projection))
            self.pending_bytes = new_size
        source.update(previous_end=end, sequence=source['sequence'] + 1, event_sequence=event_sequence, anchor=anchor)
        self.offset_min, self.offset_max = lo, hi
        if context:
            result = copy.deepcopy({key: frame.get(key) for key in ('session_id', 'segment', 'event_sequence',
                                   'source_artifacts', 'timing', 'session_epoch')})
            result['relations'] = [dict({key: row.get(key) for key in ('relation_status',
                                   'controller_object_key', 'body_object_key')},
                                   unresolved_body_validated=(row.get('controller_object_key'),None) in unresolved_rows) for row in relations]
            return result

    def _validate_row(self, row, frame, source):
        # The finite validator's category branch has a different admission model.
        # All nested scopes still run on the original live row.
        nested_scope(row, frame['timing'], frame['profile_sha256'], self.target['executable_sha256'],
                     declarations=source['declarations'], objects=row,
                     context_reference=(row.get('context_group_evidence')or{}).get('context_reference') if frame.get('context_group_projection')is not None else None)
        common = dict(row)
        for key in ('raw_category_candidate', 'team_candidate', 'relative_allegiance_candidate'):
            common[key] = None
        _validate_row_values(common, frame, source)
        position, health = row.get('position_candidate'), row.get('health_candidate')
        if position is not None:
            need(source['declarations'].get(position.get('field')) == 'f32x3', 'position_field_declaration_mismatch')
        if health is not None:
            need(all(source['declarations'].get(part.get('field')) == 'f32'
                     for part in health['contributions']), 'health_field_declaration_mismatch')
        resource = row.get('hero_resource_guid_candidate')
        if resource is not None:
            need(all(source['declarations'].get(word.get('field')) == 'i32'
                     for word in resource['evidence']), 'resource_field_declaration_mismatch')
        evidence = row.get('evidence')
        need(isinstance(evidence, list) and len(evidence) == 5
             and all(isinstance(word, dict) and integer(word.get('value')) and 0 <= word['value'] <= 0xffffffff for word in evidence),
             'missing_identity_word_evidence')
        need(len({word.get('field') for word in evidence}) == 5
             and all(source['declarations'][word['field']] == 'i32' for word in evidence), 'identity_word_declaration_mismatch')
        for word in evidence: read_bracket(word, frame['timing'])
        if any(row.get(key) is not None for key in ('raw_category_candidate', 'team_candidate', 'relative_allegiance_candidate')):
            category = source.get('live_category')
            need(isinstance(category, dict), 'live_category_config_required')
            need(integer(row.get('raw_category_candidate')) and row['raw_category_candidate'] >= 0
                 and isinstance(row.get('team_candidate'), str) and row['team_candidate']
                 and row.get('relative_allegiance_candidate') in ('self', 'friendly', 'enemy'), 'invalid_live_category_values')
            e = row.get('category_evidence', {})
            need(all(e.get(k) == category[k] for k in ('contract_sha256', 'native_review_sha256',
                 'roster_review_sha256', 'mode_review_sha256', 'mode_id', 'self_controller_object_key'))
                 and e.get('mode_scope', {}).get('live_scope') == category['live_scope']
                 and e.get('mode_scope') == dict(mode_id=category['mode_id'], live_scope=category['live_scope'],
                     mode_review_sha256=category['mode_review_sha256'], roster_review_sha256=category['roster_review_sha256'])
                 and frame.get('live_category_output_enabled') is True
                 and frame.get('live_category_contract_sha256') == category['contract_sha256'], 'live_category_config_mismatch')
            admission, scope = e.get('admission', {}), e.get('mode_scope', {}).get('live_scope', {})
            need(e.get('profile_sha256') == source['profile_sha256']
                 and e.get('build_sha256') == self.target['executable_sha256']
                 and e.get('public_state_eligible') is False and e.get('durability_verified') is False
                 and e.get('acquisition') == frame['source_artifacts']['acquisition']
                 and all(scope.get(k) == source[k] for k in ('session_id', 'segment'))
                 and scope.get('monotonic_frequency') == self.frequency
                 and integer(scope.get('start_ticks')) and scope['start_ticks'] <= frame['timing']['start_ticks'], 'live_category_scope_mismatch')
            for key in ('native_review_sha256', 'roster_review_sha256', 'mode_review_sha256', 'contract_sha256'):
                digest(e.get(key))
            for key in ('session_start_sha256', 'segment_start_sha256'): digest(scope.get(key))
            expected = dict(session_id=source['session_id'], segment=source['segment'], profile_sha256=source['profile_sha256'],
                acquisition_manifest_sha256=source['acquisition']['manifest_sha256'], recipe_sha256=source['acquisition']['recipe_sha256'],
                evidence_sha256=source['acquisition']['evidence_sha256'], event_sequence=frame['event_sequence'],
                event_sha256=frame['source_artifacts']['live_event_sha256'], frame_sequence=frame['timing']['sequence'],
                frame_start_ticks=frame['timing']['start_ticks'], frame_end_ticks=frame['timing']['end_ticks'], monotonic_frequency=self.frequency)
            need(all(admission.get(k) == v for k, v in expected.items()), 'live_category_admission_mismatch')
            digest(admission.get('frame_sha256'))
            need(admission == dict(expected, frame_sha256=admission['frame_sha256']), 'live_category_admission_mismatch')
            for key in ('fields', 'self_fields'):
                words = e.get(key)
                need(isinstance(words, list) and words and all(isinstance(word, dict) for word in words), 'live_category_read_evidence')
                for word in words: read_bracket(word, frame['timing'])
            need(e.get('self_controller_object_key') in {pair[0] for pair in source['object_pairs']}
                 and row.get('relative_allegiance_candidate') in ('self', 'friendly', 'enemy'), 'live_category_self_mismatch')

    def advance(self, watermark_ticks):
        """Finalize windows ending at/before the explicit common-clock watermark."""
        need(not self.failed and not self.closed, 'live_aggregate_closed')
        try:
            need(integer(watermark_ticks) and watermark_ticks >= self.watermark, 'watermark_order')
            limit = (watermark_ticks - self.origin) // self.window
            need(0 <= limit <= MAX_WINDOWS, 'window_count_limit')
            while self.next_window < limit:
                bucket = self.pending.get(self.next_window, {})
                result = project_window(self, self.next_window, bucket)
                ratio_sources = {sid:dict(session_id=source['session_id'], segment=source['segment'],
                    profile_sha256=source['profile_sha256'], acquisition=copy.deepcopy(source['acquisition']),
                    projection=copy.deepcopy(source['health_ratio_projection']))
                    for sid, source in self.sources.items() if source.get('health_ratio_projection') is not None}
                if ratio_sources:
                    result['health_ratio_sources'] = ratio_sources
                result.pop('manifest_sha256')
                result.update(schema='overwatch-decoder.partition-research-live/1', config_sha256=self.hash,
                    configuration_status='reviewed_caller_input_not_native_proof', durability_verified=False,
                    recording_state='accepted_not_durability_verified', watermark_ticks=watermark_ticks)
                if self.allow_unresolved and any(body is None for _,body in self.roster):
                    result['observation_mode']='raw-candidates'
                    result['unresolved_body_policy']='same_profile_declared_body_fields_absent'
                    for row in result['relations']:
                        if row['body_object_key'] is not None:continue
                        ck=row['controller_object_key'];observations=[]
                        row['unresolved_body_sources']=[dict(source_id=sid,**copy.deepcopy(item))
                            for sid,source in self.sources.items()for item in source.get('unresolved_bodies',[])
                            if item['controller_object_key']==ck]
                        for sid,state in bucket.items():
                            if sid in result['unavailable_sources']:continue
                            frame=state['latest'];item=frame.get('unresolved_rows',{}).get((ck,None))
                            if item is None:continue
                            observations.append(dict(source_id=sid,source_timing=frame['timing'],
                                source_artifacts=frame['artifacts'],source_recording=frame['recording'],
                                semantic_projection_sha256=frame['semantic_source_sha256'],
                                authoritative=sid==row['primary_source_id'],relation=item['relation'],
                                declaration=item['declaration'],
                                **({key:copy.deepcopy(frame[key]) for key in ('health_ratio_projection','semantic_frame_sha256')}
                                   | {'semantic_frame_hash_scope':'exact_semantic_jsonl_line_including_lf'}
                                   if frame.get('health_ratio_projection') is not None else {})))
                        row['unresolved_body_observations']=observations
                        if any(item['authoritative']for item in observations):row['reason']='body_binding_unresolved'
                coverage = Counter()
                for row in result['relations']:
                    for observed in [row['authoritative_observation'], *row['supporting_observations'], *row['contributor_evidence']]:
                        if observed is not None:
                            observed['semantic_projection_sha256'] = observed.pop('semantic_source_sha256')
                    selected = row['authoritative_observation']
                    if selected:
                        for key in FIELDS: coverage[key] += selected['relation'].get(key) is not None
                        if ratio_sources:
                            coverage['health_ratio_candidate'] += selected['relation'].get('health_ratio_candidate') is not None
                encoded = canonical(result) + b'\n'
                need(len(encoded) <= MAX_OUTPUT_LINE_BYTES, 'output_line_bound')
                need(self.output_bytes + len(encoded) <= self.maximum_output, 'output_byte_limit')
                self.output_bytes += len(encoded)
                self.coverage.update(coverage)
                self.windows += 1
                observed_count = sum(row['status'] == 'observed' for row in result['relations'])
                self.counts['observed_rows'] += observed_count
                self.counts['unknown_rows'] += len(self.roster) - observed_count
                self.counts['full_windows' if observed_count == len(self.roster) else 'partial_windows'] += 1
                for row in result['relations']:
                    if row['reason']: self.reasons[row['reason']] += 1
                self.pending_bytes -= sum(state['bytes'] for state in bucket.values())
                self.pending.pop(self.next_window, None)
                self.next_window += 1
                yield result
            self.watermark = watermark_ticks
        except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
            self.failed = True
            raise

    def close(self):
        self.closed = True
        return dict(schema='overwatch-decoder.live-partition-result/1', config_sha256=self.hash, windows=self.windows,
            input_frames={sid: source['sequence'] for sid, source in self.sources.items()}, **self.counts,
            authoritative_field_coverage=dict(self.coverage), unknown_reasons=dict(self.reasons),
            observed_rows_meaning='primary_relation_available_not_all_optional_fields_present',
            pending_windows=len(self.pending), pending_bytes=self.pending_bytes,
            automatic_watermark_ticks=self.automatic_watermark, finalized_watermark_ticks=self.watermark,
            output_bytes=self.output_bytes, failed=self.failed, all_sources_complete=False,
            atomic=False, public_state_eligible=False, durability_verified=False,
            recording_state='accepted_not_durability_verified')


def stream(adapter, source, output):
    """Bounded interleaved JSONL transport; each frame advances the common watermark."""
    total = events = 0
    while True:
        line = source.readline(MAX_LINE_BYTES + 1)
        if not line: break
        total += len(line); events += 1
        need(len(line) <= MAX_LINE_BYTES and line.endswith(b'\n') and total <= MAX_TOTAL_BYTES and events <= MAX_EVENTS,
             'live_transport_bound')
        envelope = parse(line)
        if envelope.get('kind') == 'frame':
            adapter.consume(envelope.get('source_id'), canonical(envelope.get('projection')) + b'\n')
            watermark = adapter.automatic_watermark
        else:
            need(envelope.get('kind') == 'watermark', 'live_transport_kind')
            watermark = envelope.get('ticks')
        if watermark is not None:
            for result in adapter.advance(watermark):
                output.write(canonical(result) + b'\n')
                output.flush()
    return adapter.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    try:
        with args.config.open('rb') as file: config = file.read(262145)
        summary = stream(LivePartitions(config), sys.stdin.buffer, sys.stdout.buffer)
    except (InvalidPartitions, ValueError, KeyError, OSError, RecursionError, TypeError, AttributeError) as error:
        print(json.dumps(dict(schema='overwatch-decoder.live-partition-result/1', failed=True, error=str(error), durability_verified=False)), file=sys.stderr)
        return 2
    print(json.dumps(summary), file=sys.stderr)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
