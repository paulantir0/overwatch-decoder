#!/usr/bin/env python3
"""Compact private live candidates with pointers into the hashed source JSONL.

This is a projection of accepted semantic frames, not native guard verification.
Keep the original source frames (and their referenced native evidence). No
process access, visibility inference, participant naming or historical fill.
"""
import argparse
import copy
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
import re
import sys

from health_changes import HealthChanges, sample as health_change_sample
from hero_asset_validation import compact_hero_asset
from forward_owner_validation import validate_forward_owner_frame, CATEGORY_METADATA_KEYS

from context_projection_validation import (context_source_from_frame, validate_context_frame, compact_context, _compact_actor_context)

MAX_BYTES = 512 * 1024 * 1024
MAX_FRAMES = 100000
MAX_LINE = 1024 * 1024
MAX_OUTPUT_LINE = 256 * 1024


class InvalidCompact(ValueError):
    pass


def need(ok, reason):
    if not ok: raise InvalidCompact(reason)


def integer(value): return type(value) is int


def encode(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode() + b'\n'


def parse(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            need(key not in value, 'duplicate_json_key'); value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(InvalidCompact('nonfinite_json')))


def digest(value):
    need(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'invalid_digest')
    return value


def object_key(value, role):
    need(value is None or isinstance(value, str) and re.fullmatch(role+':[0-9a-f]{64}', value), 'invalid_object_key')


def finite(value): return type(value) in (int, float) and math.isfinite(value)


def text(value, maximum=1024):
    need(isinstance(value, str) and 0 < len(value.encode()) <= maximum, 'invalid_candidate_text')


def span(fields, timing):
    need(isinstance(fields, list) and fields and len(fields) <= 256, 'missing_read_evidence')
    starts, ends = [], []
    for field in fields:
        need(isinstance(field, dict), 'invalid_read_evidence')
        a, b = field.get('read_start_ticks'), field.get('read_end_ticks')
        need(integer(a) and integer(b) and timing['start_ticks'] <= a <= b <= timing['end_ticks'], 'read_outside_source_frame')
        starts.append(a); ends.append(b)
    return [min(starts), max(ends)]


def evidence(node, frame, *, acquisition=False):
    need(isinstance(node, dict) and node.get('profile_sha256') == frame['profile_sha256']
         and node.get('build_sha256') == frame['target']['executable_sha256']
         and node.get('public_state_eligible') is False, 'unbound_candidate_evidence')
    if acquisition:
        need(node.get('acquisition') == frame['source_artifacts']['acquisition'], 'candidate_acquisition_mismatch')
    return span(node.get('fields'), frame['timing'])


class CompactLiveEntities:
    def __init__(self, *, maximum_input_bytes=MAX_BYTES, maximum_output_bytes=MAX_BYTES, maximum_frames=MAX_FRAMES):
        for value, bound in ((maximum_input_bytes, MAX_BYTES), (maximum_output_bytes, MAX_BYTES), (maximum_frames, MAX_FRAMES)):
            need(integer(value) and 0 < value <= bound, 'invalid_compact_limit')
        self.max_input, self.max_output, self.max_frames = maximum_input_bytes, maximum_output_bytes, maximum_frames
        self.input_bytes = self.output_bytes = self.frames = self.players = self.unknown = 0
        self.input_hash, self.output_hash = hashlib.sha256(), hashlib.sha256()
        self.coverage = Counter()
        self.previous = None
        self.bindings = {}
        self.failed = False
        self.context_source = None
        self.hero_asset_source = None
        self.forward_source = None
        self.forward_bindings = {}
        self.health_changes = HealthChanges()

    def consume(self, raw):
        need(not self.failed, 'compact_projection_failed')
        try:
            need(isinstance(raw, bytes) and 0 < len(raw) <= MAX_LINE and raw.endswith(b'\n'), 'compact_input_line_bound')
            need(self.frames < self.max_frames and self.input_bytes+len(raw) <= self.max_input, 'compact_input_bound')
            source = parse(raw)
            self._frame(source)
            if self.previous is None or source['segment'] != self.previous['segment']:
                self.context_source = context_source_from_frame(source)
            context_projection = validate_context_frame(source, self.context_source, target=source['target'])
            asset_source = (source.get('hero_asset_output_enabled'), source.get('hero_asset_catalog_sha256'))
            if self.previous is not None and source['segment'] == self.previous['segment']:
                need(asset_source == self.hero_asset_source, 'asset_epoch_configuration_changed')
            self.hero_asset_source = asset_source
            rows = source['relations']
            known = {row.get('controller_object_key') for row in rows if row.get('relation_status') == 'observed'}
            compact = [self._row(row, i, source, known) for i, row in enumerate(rows)]
            result = dict(schema='overwatch-decoder.compact-live-entities/1', privacy='private', source='process_memory_projected_research',
                atomic=False, public_state_eligible=False, visibility='unknown', participant_identity_validated=False,
                continuity_across_gaps=False, values_are_candidates=True, durability_verified=False, recording_state='accepted_not_durability_verified',
                session_id=source['session_id'], segment=source['segment'], event_sequence=source['event_sequence'],
                target={key:source['target'][key] for key in ('pid','creation_file_time','executable_sha256','architecture','image_name')},
                profile_sha256=source['profile_sha256'], timing={k:source['timing'][k]for k in ('sequence','start_ticks','end_ticks','monotonic_frequency','utc_origin','monotonic_origin_ticks')},
                gap_before={k:source['gap_before'][k]for k in ('skipped_slots','previous_end_ticks','current_start_ticks','previous_values_carried')},
                session_epoch=None if source.get('session_epoch')is None else {k:source['session_epoch'][k]for k in ('acquisition','session_start_sha256','acquisition_end_sha256','segment_start_sha256','previous_epoch_last_frame_end_ticks','previous_values_carried')},
                source_frame=dict(sha256=hashlib.sha256(raw).hexdigest(), hash_scope='exact_semantic_jsonl_line_including_lf',
                    native_event_sha256=source['source_artifacts']['live_event_sha256'],
                    acquisition={key:source['source_artifacts']['acquisition'][key] for key in ('manifest_sha256','recipe_sha256','evidence_sha256')},
                    evidence_root='original_source_frame', original_evidence_required=True), players=compact)
            forward = self._forward_projection(source)
            if forward is not None:
                result['forward_owner_projection'], result['forward_owners'] = forward
            if source.get('hero_asset_output_enabled') is True:
                result.update(hero_asset_output_enabled=True, hero_asset_catalog_sha256=source['hero_asset_catalog_sha256'])
            if context_projection is not None:
                result['context_group_projection'] = compact_context(context_projection, '/context_group_projection')
                for i, row in enumerate(compact):
                    row['context_group_candidate'] = _compact_actor_context(source['relations'][i], context_projection, '/relations/'+str(i), '/context_group_projection', (source['relations'][i].get('context_group_evidence')or{}).get('context_reference'))
            changes = self.health_changes.project([
                health_change_sample(row, target=source['target'], timing=source['timing'],
                    artifacts=source['source_artifacts'],
                    epoch=dict(session_id=source['session_id'], segment=source['segment'], session_epoch=source.get('session_epoch')),
                    source_sha256=result['source_frame']['sha256'], evidence_ref='/relations/'+str(i)+'/health_candidate',
                    gap=source['gap_before']['skipped_slots'] > 0)
                for i, row in enumerate(rows)])
            for row, change in zip(compact, changes): row['health_change_candidate'] = change
            encoded = encode(result)
            need(len(encoded) <= MAX_OUTPUT_LINE and self.output_bytes+len(encoded) <= self.max_output, 'compact_output_bound')
            self.input_bytes += len(raw); self.output_bytes += len(encoded); self.frames += 1
            self.input_hash.update(raw); self.output_hash.update(encoded)
            self.players += len(compact); self.unknown += sum(row['relation_status'] == 'unknown' for row in compact)
            for row in compact:
                for key in ('position_candidate','health_candidate','hero_resource_candidate','hero_label_candidate','cached_label_candidate','category_candidate'):
                    self.coverage[key] += row[key]['value'] is not None
                if 'hero_asset_label_candidate'in row:self.coverage['hero_asset_label_candidate'] += row['hero_asset_label_candidate']['value'] is not None
                if 'context_group_candidate'in row:self.coverage['context_group_candidate'] += row['context_group_candidate']['value']is not None
            for row in result.get('forward_owners', []):
                self.coverage['forward_owner_relation'] += row['relation_status'] == 'observed'
                for key in ('position_candidate', 'health_candidate', 'controller_hero_asset_label_candidate'):
                    self.coverage['forward_owner_'+key] += row[key]['value'] is not None
                if 'category_candidate'in row:
                    self.coverage['forward_owner_category_candidate'] += row['category_candidate']['status']=='candidate'
                    self.coverage['forward_owner_raw_flags_candidate'] += row['category_candidate']['raw_status']=='observed'
            self.previous = {k:source[k]for k in ('session_id','target','event_sequence','segment','profile_sha256','timing','source_artifacts')}
            self.previous['session_epoch']=source.get('session_epoch')
            return result
        except (ValueError, KeyError, TypeError, AttributeError, RecursionError, OverflowError):
            self.failed = True
            raise

    def _frame(self, frame):
        need(isinstance(frame, dict) and frame.get('schema') == 'overwatch-decoder.entity-relations-live/1'
             and frame.get('source') == 'process_memory' and frame.get('privacy') == 'private'
             and frame.get('atomic') is False and frame.get('public_state_eligible') is False
             and frame.get('participant_identity_validated') is False and frame.get('continuity_across_gaps') is False
             and frame.get('visibility') == 'unknown' and frame.get('durability_verified') is False
             and frame.get('recording_state') == 'accepted_not_durability_verified', 'invalid_source_qualification')
        recording = frame.get('recording', {})
        need(recording.get('complete') is False and recording.get('partial') is True
             and recording.get('status') == 'accepted_not_durability_verified'
             and recording.get('durability_verified') is False and recording.get('continuity_across_gaps') is False, 'invalid_source_recording')
        target = frame.get('target', {})
        need(integer(target.get('pid')) and target['pid'] > 0 and integer(target.get('creation_file_time'))
             and target['creation_file_time'] > 0 and target.get('architecture') == 'x64', 'invalid_target')
        text(target.get('image_name'),256); digest(target.get('executable_sha256')); digest(frame.get('profile_sha256'))
        need(isinstance(frame.get('session_id'),str) and re.fullmatch('[0-9a-f]{32}',frame['session_id'])
             and integer(frame.get('segment')) and 1 <= frame['segment'] <= 128
             and integer(frame.get('event_sequence')) and frame['event_sequence'] >= 0, 'invalid_source_epoch')
        timing, gap = frame.get('timing', {}), frame.get('gap_before', {})
        need(all(integer(timing.get(k)) for k in ('sequence','start_ticks','end_ticks','monotonic_frequency','monotonic_origin_ticks'))
             and timing['sequence'] >= 0 and 0 <= timing['start_ticks'] <= timing['end_ticks']
             and 0 < timing['monotonic_frequency'] <= 10**12 and timing['monotonic_origin_ticks'] >= 0, 'invalid_frame_time')
        utc=datetime.fromisoformat(timing.get('utc_origin'))
        need(utc.tzinfo is not None and utc.utcoffset() == timezone.utc.utcoffset(None), 'invalid_utc_origin')
        need(integer(gap.get('skipped_slots')) and gap['skipped_slots'] >= 0
             and gap.get('current_start_ticks') == timing['start_ticks'] and gap.get('previous_values_carried') is False, 'invalid_gap')
        artifacts=frame.get('source_artifacts',{}); acquisition=artifacts.get('acquisition',{})
        need(artifacts.get('profile_sha256') == frame['profile_sha256'], 'source_profile_mismatch')
        digest(artifacts.get('live_event_sha256'))
        for key in ('manifest_sha256','recipe_sha256','evidence_sha256'):digest(acquisition.get(key))
        rows=frame.get('relations');need(isinstance(rows,list) and len(rows)<=128 and all(isinstance(r,dict)for r in rows),'invalid_relations')
        controllers=[r.get('controller_object_key')for r in rows if r.get('relation_status')=='observed']
        bodies=[r.get('body_object_key')for r in rows if r.get('relation_status')=='observed']
        need(len(controllers)==len(set(controllers)) and len(bodies)==len(set(bodies)), 'duplicate_observed_object')
        epoch=frame.get('session_epoch')
        if epoch is not None:
            need(isinstance(epoch,dict) and integer(epoch.get('acquisition')) and 1 <= epoch['acquisition'] <= 128
                 and epoch.get('previous_values_carried') is False, 'invalid_session_epoch')
            for key in ('session_start_sha256','acquisition_end_sha256','segment_start_sha256'):digest(epoch.get(key))
        old=self.previous
        if old is None:
            need(timing['sequence']==0 and gap.get('previous_end_ticks') is None, 'source_prefix_must_start_epoch')
        else:
            need(frame['session_id']==old['session_id'] and target==old['target']
                 and frame['event_sequence']>old['event_sequence'] and timing['start_ticks']>=old['timing']['end_ticks']
                 and timing['monotonic_frequency']==old['timing']['monotonic_frequency'], 'source_order_or_target_changed')
            if frame['segment']==old['segment']:
                need(frame['profile_sha256']==old['profile_sha256'] and artifacts['acquisition']==old['source_artifacts']['acquisition']
                     and epoch==old.get('session_epoch') and timing['sequence']==old['timing']['sequence']+1
                     and gap.get('previous_end_ticks')==old['timing']['end_ticks']
                     and all(timing[k]==old['timing'][k]for k in ('monotonic_origin_ticks','utc_origin')), 'source_epoch_changed_without_boundary')
            else:
                need(frame['segment']==old['segment']+1 and timing['sequence']==0 and gap.get('previous_end_ticks') is None
                     and epoch is not None and epoch.get('previous_epoch_last_frame_end_ticks')==old['timing']['end_ticks']
                     and old.get('session_epoch') is not None and epoch['acquisition']>old['session_epoch']['acquisition']
                     and epoch['segment_start_sha256']!=old['session_epoch']['segment_start_sha256']
                     and acquisition['manifest_sha256']!=old['source_artifacts']['acquisition']['manifest_sha256'], 'invalid_new_epoch_admission')
                self.bindings={}
                self.forward_bindings={}

    def _forward_projection(self, frame):
        projected = validate_forward_owner_frame(frame)
        new_epoch = self.previous is None or frame['segment'] != self.previous['segment']
        if projected is None:
            need(new_epoch or self.forward_source is None, 'forward_projection_disabled_within_epoch')
            self.forward_source = None
            return None
        metadata, rows = projected
        pin = tuple(metadata.get(key) for key in ('contract_sha256', 'binding_template_sha256',
                    'controller_hero_output_enabled', 'controller_hero_asset_catalog_sha256', 'reference_groups', *CATEGORY_METADATA_KEYS))
        need(new_epoch or self.forward_source == pin, 'forward_projection_changed_within_epoch')
        self.forward_source = copy.deepcopy(pin)
        for row in rows:
            if row['relation_status'] == 'observed':
                ident = row['binding_id']
                binding = (row['controller_object_key'], row['forward_owner_object_key'], row['owned_field_prefix'])
                need(ident not in self.forward_bindings or self.forward_bindings[ident] == binding,
                     'forward_owner_changed_without_epoch')
                self.forward_bindings[ident] = binding
        return projected

    def _row(self, row, index, frame, known):
        base=f'/relations/{index}'
        asset = compact_hero_asset(row, frame, base)
        controller,body=row.get('controller_object_key'),row.get('body_object_key')
        object_key(controller,'controller');object_key(body,'body')
        status=row.get('relation_status');reason=row.get('reason')
        need(status in ('observed','unknown') and row.get('visibility')=='unknown' and (reason is None or isinstance(reason,str)), 'invalid_relation')
        if status=='observed':
            need(controller is not None and body is not None and reason is None, 'invalid_observed_relation')
            need(controller not in self.bindings or self.bindings[controller]==body, 'body_changed_within_epoch')
            self.bindings[controller]=body
        values={k:row.get(k)for k in ('position_candidate','health_candidate','hero_resource_guid_candidate','hero_label','cached_label_candidate','raw_category_candidate','team_candidate','relative_allegiance_candidate')}
        need(status=='observed' or all(v is None for v in values.values()), 'candidate_without_observed_relation')
        def candidate(value,key,why,evidence_key=None,reads=None,validation=None):
            reason_key=why if why in row else 'reason'
            explanation=row.get(reason_key)
            need(explanation is None or isinstance(explanation,str) and len(explanation)<=1024,'invalid_candidate_reason')
            result=dict(status=(validation or 'candidate')if value is not None else'unknown',value=value,reason=explanation,
                read_span_ticks=reads,
                evidence_ref=base+'/'+evidence_key if evidence_key and row.get(evidence_key)is not None else None)
            if explanation is not None:result['reason_ref']=base+'/'+reason_key
            return result
        position=values['position_candidate'];ps=None
        if position is not None:
            need(isinstance(position,dict) and position.get('type')=='f32x3' and position.get('source')=='process_memory'
                 and position.get('validation_status')=='guarded_research' and position.get('profile_sha256')==frame['profile_sha256'] and position.get('build_sha256')==frame['target']['executable_sha256']
                 and isinstance(position.get('value'),list) and len(position['value'])==3 and all(finite(v)for v in position['value']), 'invalid_position')
            ps=span([position],frame['timing'])
        health=values['health_candidate'];hs=None;hv=None
        if health is not None:
            need(isinstance(health,dict) and health.get('schema')=='overwatch-decoder.actor-pool-sum/1' and health.get('status')=='candidate'
                 and health.get('source')=='process_memory' and health.get('body_object_key')==body
                 and health.get('profile_sha256')==frame['profile_sha256'] and health.get('build_sha256')==frame['target']['executable_sha256']
                 and health.get('acquisition_evidence_sha256')==frame['source_artifacts']['acquisition']['evidence_sha256']
                 and health.get('atomic')is False and health.get('public_state_eligible')is False and health.get('visibility')=='unknown'
                 and health.get('complete_supplied_membership_guarding')is True and finite(health.get('raw_sum')) and health['raw_sum']>=0,
                 'invalid_health_binding')
            contributions=health.get('contributions');hs=span(contributions,frame['timing'])
            indices=[v.get('pool_index')for v in contributions]
            need(all(integer(i)and i>=0 for i in indices)and len(set(indices))==len(indices),'duplicate_health_pool')
            need(all(finite(v.get('value')) and v['value']>=0 for v in contributions)
                 and health['raw_sum']==sum(v['value']for v in contributions)
                 and span([health],frame['timing'])==hs, 'invalid_health_sum_or_span')
            ceiling=health.get('display_ceiling_candidate')
            need(ceiling is None or integer(ceiling) and ceiling==math.ceil(health['raw_sum']),'invalid_health_display_candidate')
            hv={k:health.get(k)for k in ('raw_sum','display_ceiling_candidate')}
        resource=values['hero_resource_guid_candidate'];rs=None
        if resource is not None:
            need(isinstance(resource,dict) and isinstance(resource.get('value'),str) and re.fullmatch('0x[0-9A-Fa-f]{16}',resource['value'])
                 and resource.get('validation_status')=='matching_guarded_resource_research' and resource.get('controller_body_match')is True and resource.get('public_state_eligible')is False, 'invalid_resource')
            words=resource.get('evidence');rs=span(words,frame['timing'])
            need(len(words)==4 and all(integer(w.get('value')) and -(1<<31)<=w['value']<(1<<31) for w in words),'invalid_resource_words')
            c=(words[0]['value']&0xffffffff)|((words[1]['value']&0xffffffff)<<32);b=(words[2]['value']&0xffffffff)|((words[3]['value']&0xffffffff)<<32)
            need(c==b==int(resource['value'],16),'resource_mismatch')
        label=values['hero_label'];ls=None
        if label is not None:
            text(label);e=row.get('hero_label_evidence');ls=evidence(e,frame);digest(e.get('catalog_sha256'))
            need(e.get('validation_status')=='guarded_build_resource_label_research' and resource is not None and e.get('catalog_sha256')==frame.get('hero_catalog_sha256')
                 and e.get('mapping',{}).get('label')==label and e['mapping'].get('resource_guid')==resource['value']
                 and e['mapping'].get('build_sha256')==frame['target']['executable_sha256'],'hero_mapping_mismatch')
        cache=values['cached_label_candidate'];cs=None
        if cache is not None:
            text(cache);e=row.get('cached_label_evidence');cs=evidence(e,frame,acquisition=True)
            need(e.get('validation_status')=='guarded_native_cache_string_research'and e.get('privacy')=='private'and e.get('gameplay_semantics_validated')is False,'invalid_cached_label_claim')
        cat={k:values[k]for k in ('raw_category_candidate','team_candidate','relative_allegiance_candidate')};catspan=None
        if any(v is not None for v in cat.values()):
            need(cat['raw_category_candidate']is None or integer(cat['raw_category_candidate'])and cat['raw_category_candidate']>=0,'invalid_category_value')
            if cat['team_candidate']is not None:text(cat['team_candidate'])
            need(cat['relative_allegiance_candidate']in (None,'self','friendly','enemy'),'invalid_allegiance')
            e=row.get('category_evidence');catspan=evidence(e,frame,acquisition=True)
            need(e.get('validation_status')=='guarded_live_category_roster_research','invalid_category_validation')
            for key in ('native_review_sha256','roster_review_sha256','mode_review_sha256','contract_sha256'):digest(e.get(key))
            admission=e.get('admission',{});scope=e.get('mode_scope',{}).get('live_scope',{})
            expected=dict(session_id=frame['session_id'],segment=frame['segment'],profile_sha256=frame['profile_sha256'],
                acquisition_manifest_sha256=frame['source_artifacts']['acquisition']['manifest_sha256'],
                recipe_sha256=frame['source_artifacts']['acquisition']['recipe_sha256'],evidence_sha256=frame['source_artifacts']['acquisition']['evidence_sha256'],
                event_sequence=frame['event_sequence'],event_sha256=frame['source_artifacts']['live_event_sha256'],
                frame_sequence=frame['timing']['sequence'],frame_start_ticks=frame['timing']['start_ticks'],frame_end_ticks=frame['timing']['end_ticks'],
                monotonic_frequency=frame['timing']['monotonic_frequency'])
            need(all(admission.get(k)==v for k,v in expected.items()) and e.get('durability_verified')is False
                 and frame.get('live_category_output_enabled')is True and e.get('contract_sha256')==frame.get('live_category_contract_sha256')
                 and scope.get('session_id')==frame['session_id'] and scope.get('segment')==frame['segment']
                 and scope.get('monotonic_frequency')==frame['timing']['monotonic_frequency']
                 and integer(scope.get('start_ticks'))and scope['start_ticks']<=frame['timing']['start_ticks'],'invalid_live_category_scope')
            digest(admission.get('frame_sha256'))
            for key in ('session_start_sha256','segment_start_sha256'):digest(scope.get(key))
            need(e.get('mode_scope',{}).get('mode_review_sha256')==e['mode_review_sha256']
                 and e.get('mode_scope',{}).get('roster_review_sha256')==e['roster_review_sha256'],'category_review_scope_mismatch')
            if cat['relative_allegiance_candidate']is not None:
                need(e.get('self_controller_object_key')in known,'category_self_missing')
                ss=span(e.get('self_fields'),frame['timing']);catspan=[min(catspan[0],ss[0]),max(catspan[1],ss[1])]
        else:cat=None
        result=dict(controller_object_key=controller,body_object_key=body,relation_status=status,reason=reason,
            source_ref=base,
            position_candidate=candidate(None if position is None else position['value'],'position_candidate','position_reason','position_candidate',ps,None if position is None else position.get('validation_status')),
            health_candidate=candidate(hv,'health_candidate','health_reason','health_candidate',hs,None if health is None else health.get('status')),
            hero_resource_candidate=candidate(None if resource is None else resource['value'],'hero_resource_guid_candidate','hero_resource_reason','hero_resource_guid_candidate',rs,None if resource is None else resource.get('validation_status')),
            hero_label_candidate=candidate(label,'hero_label','hero_label_reason','hero_label_evidence',ls,(row.get('hero_label_evidence')or{}).get('validation_status')),
            cached_label_candidate=candidate(cache,'cached_label_candidate','cached_label_reason','cached_label_evidence',cs,(row.get('cached_label_evidence')or{}).get('validation_status')),
            category_candidate=candidate(cat,'raw_category_candidate','category_reason','category_evidence',catspan,(row.get('category_evidence')or{}).get('validation_status')))
        if asset is not None:
            result['hero_asset_label_candidate'] = asset
        return result

    def summary(self):
        return dict(schema='overwatch-decoder.compact-live-result/1',frames=self.frames,players=self.players,unknown_relations=self.unknown,
            candidate_coverage=dict(self.coverage),input_bytes=self.input_bytes,output_bytes=self.output_bytes,
            input_sha256=self.input_hash.hexdigest(),output_sha256=self.output_hash.hexdigest(),failed=self.failed,
            privacy='private',atomic=False,public_state_eligible=False,durability_verified=False)


def stream(projector, source, output):
    while True:
        raw=source.readline(MAX_LINE+1)
        if not raw:break
        result=projector.consume(raw)
        output.write(encode(result));output.flush()
    return projector.summary()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--maximum-input-bytes',type=int,default=MAX_BYTES)
    parser.add_argument('--maximum-output-bytes',type=int,default=MAX_BYTES)
    args=parser.parse_args()
    try:result=stream(CompactLiveEntities(maximum_input_bytes=args.maximum_input_bytes,maximum_output_bytes=args.maximum_output_bytes),sys.stdin.buffer,sys.stdout.buffer)
    except (InvalidCompact,ValueError,KeyError,TypeError,AttributeError,RecursionError,OSError)as error:
        print(json.dumps(dict(schema='overwatch-decoder.compact-live-result/1',failed=True,error=str(error),public_state_eligible=False)),file=sys.stderr);return 2
    print(json.dumps(result),file=sys.stderr);return 0


if __name__=='__main__':raise SystemExit(main())
