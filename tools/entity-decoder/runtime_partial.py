"""Independent raw-source observations, never a common-time roster snapshot."""
import copy
import hashlib
from typing import NamedTuple

from aggregate_partitions import canonical, need, parse
from aggregate_live_partitions import LivePartitions, MAX_EVENTS, MAX_TOTAL_BYTES, MAX_LINE_BYTES
from live_roster_epochs import admission


class PartialOutputFailure(ValueError):
    """Global output failure, never a source-admission failure."""


class EncodedPartialEvent(NamedTuple):
    """Immutable publication bytes produced by the parent's trusted formatter."""
    kind: str
    data: bytes


def controller_subset_metadata(expected, primary, actual, context_key):
    """Scope proof supplied only after fresh native admission, never absence proof."""
    need(isinstance(expected,list) and isinstance(primary,list) and isinstance(actual,list)
         and all(isinstance(k,str) for keys in (expected,primary,actual) for k in keys)
         and 1<=len(expected)<=128 and len(primary)<=128 and len(actual)<=128
         and len(expected)==len(set(expected)) and len(primary)==len(set(primary))
         and len(actual)==len(set(actual)), 'partial_subset_duplicate_controller')
    need(bool(primary) and set(primary)<=set(expected) and bool(set(actual)&set(primary))
         and set(actual)<=set(expected), 'partial_subset_controller_scope')
    return dict(schema='overwatch-decoder.controller-subset-admission/1',
        expected_controller_keys=sorted(expected),expected_primary_controller_keys=sorted(primary),
        observed_controller_keys=sorted(actual),required_context_controller_key=context_key,
        omitted_controllers=[dict(controller_object_key=ck,reason='not_in_acquired_subset')
                             for ck in sorted(set(primary)-set(actual))])


class PartialSources:
    """Retain bounded cursors/pins only; never retain or refresh actor values.

    The caller must perform native source_admission for each fresh epoch. This
    layer applies the unchanged per-frame validator before publishing any row.
    Unavailable is a source condition, not proof that an actor died or vanished.
    """
    def __init__(self, target, frequency, primary, recipe_pins, census_source, *, allow_controller_subsets=False, partition_controllers=None, required_context_controller_key=None, event_encoder=None):
        need(1<=len(primary)<=128 and 1<=len(recipe_pins)<=16,'partial_scope_bound')
        need(set(primary.values())<=set(recipe_pins),'partial_primary_source')
        need(type(allow_controller_subsets)is bool,'partial_subset_policy_type')
        # The runtime adds its publication metadata here, before the one bounded
        # encoding. Standalone callers keep the original dictionary-return API.
        need(event_encoder is None or callable(event_encoder),'partial_event_encoder')
        self.event_encoder=event_encoder
        self.allow_controller_subsets=allow_controller_subsets
        self.partition_controllers=copy.deepcopy(partition_controllers)
        self.required_context_controller_key=required_context_controller_key
        if allow_controller_subsets:
            need(isinstance(partition_controllers,dict) and set(partition_controllers)==set(recipe_pins)
                 and required_context_controller_key in primary,'partial_subset_original_scope')
            for sid,keys in partition_controllers.items():
                need(isinstance(keys,list) and len(keys)==len(set(keys)) and set(keys)<=set(primary)
                     and {ck for ck,p in primary.items() if p==sid}<=set(keys),'partial_subset_original_scope')
        self.target=copy.deepcopy(target);self.frequency=frequency
        self.primary=dict(primary);self.recipe_pins=dict(recipe_pins);self.census=copy.deepcopy(census_source)
        self.validators={};self.sources={};self.pins={};self.closed={};self.finished=set();self.rejected=set();self.counts={sid:0 for sid in recipe_pins}
        self.hashes={sid:hashlib.sha256() for sid in recipe_pins};self.last={}
        self.events=self.input_bytes=self.output_bytes=self.output_events=0;self.ended=False;self.output_failed=False

    def admit(self, source, pins):
        sid=source['source_id'];need(not self.ended and sid in self.recipe_pins and sid not in self.closed and sid not in self.finished and sid not in self.rejected,'partial_admission_source')
        epoch=admission(source)
        need(source['acquisition']['recipe_sha256']==self.recipe_pins[sid],'partial_recipe_mismatch')
        expected={ck for ck,primary in self.primary.items() if primary==sid}
        words=[row['controller_object_key'] for row in source['objects']]
        actual=set(words)
        need(len(words)==len(actual),'partial_duplicate_controller')
        if self.allow_controller_subsets:
            scope=controller_subset_metadata(self.partition_controllers[sid],sorted(expected),words,self.required_context_controller_key)
            need(source.get('controller_subset')==pins.get('controller_subset')==scope,'partial_subset_admission_mismatch')
            need(source.get('context_projection')is not None,'partial_subset_context_required')
        else:
            need('controller_subset' not in source and 'controller_subset' not in pins,'partial_subset_not_enabled')
            need(expected<=actual<=set(self.primary),'partial_controller_scope')
        old=self.sources.get(sid)
        if old is None:
            need(source['segment']==1 and epoch['previous_epoch_last_frame_end_ticks'] is None,'partial_initial_epoch')
        else:
            previous=self.last[sid]
            need(self.allow_controller_subsets or actual=={row['controller_object_key'] for row in old['objects']},'partial_epoch_controller_change')
            need(source['session_id']==old['session_id'] and source['segment']==old['segment']+1
                 and epoch['acquisition']>admission(old)['acquisition']
                 and epoch['previous_epoch_last_frame_end_ticks']==previous['end_ticks'],'partial_epoch_order')
        config=dict(schema='overwatch-decoder.live-partition-config/1',epoch_id='partial-'+sid,
            clock_domain_id='independent-source-native-qpc',target=self.target,monotonic_frequency=self.frequency,
            window_origin_ticks=0,window_ticks=self.frequency//10,maximum_skew_ticks=self.frequency*150//1000,
            maximum_origin_offset_ticks=self.frequency//100,sources=[source],
            roster=[dict(row,primary_source_id=sid) for row in source['objects']],
            observation_mode='raw-candidates',allow_unresolved_bodies=True)
        self.validators[sid]=LivePartitions(canonical(config));self.sources[sid]=copy.deepcopy(source);self.pins[sid]=copy.deepcopy(pins)

    def _event(self, kind, sid=None, frame=None, raw=None, reason=None, receipt=None):
        if self.output_failed:raise PartialOutputFailure('partial_output_failed')
        rows=[];observed={}
        if frame is not None and frame['gap_before']['skipped_slots']==0:
            observed={row.get('controller_object_key'):(i,row) for i,row in enumerate(frame['relations'])
                      if row['relation_status']=='observed' and self.primary.get(row.get('controller_object_key'))==sid}
        omitted={sid:{r['controller_object_key']for r in source.get('controller_subset',{}).get('omitted_controllers',[])}
                 for sid,source in self.sources.items()} if self.allow_controller_subsets else {}
        for ck,primary in sorted(self.primary.items()):
            match=observed.get(ck)
            row_reason=('input_ended' if kind=='input_end' else 'source_unavailable' if primary in self.closed
                    else 'not_in_acquired_subset' if ck in omitted.get(primary,()) else 'not_observed_in_this_event')
            rows.append(dict(controller_object_key=ck,primary_source_id=primary,
                body_object_key=match[1]['body_object_key'] if match else None,
                status='observed' if match else 'unknown',
                reason=None if match else row_reason,
                observation_pointer=f'/source_observation/relations/{match[0]}' if match else None))
        value=dict(schema='overwatch-decoder.partial-roster-observation/1',event_index=self.output_events,event=kind,
            target=self.target,monotonic_frequency=self.frequency,census_source=self.census,
            source_id=sid,source_recipe_sha256=self.recipe_pins.get(sid),
            semantic_projection_sha256=None if raw is None else hashlib.sha256(raw).hexdigest(),
            source_admission=self.pins.get(sid),source_observation=frame,relations=rows,
            source_observation_scope='original_validated_source_frame_not_roster_snapshot',
            reason=reason,source_receipt=receipt,coverage='partial_independent_sources',
            common_time_snapshot=False,previous_values_carried=False,atomic=False,visibility='unknown',
            privacy='private',public_state_eligible=False,durability_verified=False)
        try:
            if self.event_encoder is None:
                encoded=canonical(value)+b'\n';result=value
            else:
                encoded=self.event_encoder(value)
                need(isinstance(encoded,bytes) and encoded.endswith(b'\n'),'partial_event_encoding')
                result=EncodedPartialEvent(kind,encoded)
            size=len(encoded);need(size<=4*MAX_LINE_BYTES and self.output_bytes+size<=MAX_TOTAL_BYTES,'partial_output_bound')
        except Exception as exc:
            self.output_failed=True
            raise PartialOutputFailure(str(exc)) from exc
        self.output_bytes+=size;self.output_events+=1
        return result

    def consume(self,sid,raw):
        return self._consume_decoded(sid,raw,None)

    def _consume_decoded(self,sid,raw,frame):
        """Internal parse-once path for the parent that just parsed these bytes.

        External callers use consume. The caller may not substitute a decoded
        object from a different source, prior frame or external transport.
        Every frame, evidence, ordering and byte-limit check still runs.
        """
        try:
            need(frame is None or isinstance(frame,dict),'partial_decoded_frame')
            return self._consume(sid,raw,frame)
        except Exception:
            if sid in self.validators:self.rejected.add(sid)
            raise

    def _consume(self, sid, raw, frame=None):
        need(not self.ended and sid in self.validators and sid not in self.closed and sid not in self.finished and sid not in self.rejected,'partial_source_unavailable')
        need(isinstance(raw,bytes) and 0<len(raw)<=MAX_LINE_BYTES and raw.endswith(b'\n'),'partial_line_bound')
        self.events+=1;self.input_bytes+=len(raw)
        need(self.events<=MAX_EVENTS and self.input_bytes<=MAX_TOTAL_BYTES,'partial_input_bound')
        frame=parse(raw) if frame is None else frame;source=self.sources[sid]
        need(frame.get('session_epoch')==admission(source),'partial_frame_admission_mismatch')
        previous=self.last.get(sid)
        if previous is not None:
            need(frame['timing']['start_ticks']>=previous['end_ticks'] and frame['event_sequence']>previous['event_sequence'],'partial_cross_epoch_order')
        try:self.validators[sid]._consume_decoded(sid,raw,frame,retain=False,context=True)
        except Exception:
            self.rejected.add(sid);raise
        self.counts[sid]+=1;self.hashes[sid].update(raw)
        self.last[sid]=dict(end_ticks=frame['timing']['end_ticks'],event_sequence=frame['event_sequence'])
        return self._event('observation',sid,frame,raw)

    def unavailable(self, sid, reason, receipt):
        need(not self.ended and sid in self.recipe_pins and sid not in self.closed,'partial_source_already_closed')
        self.closed[sid]=dict(reason=reason,receipt=copy.deepcopy(receipt))
        return self._event('source_unavailable',sid,reason=reason,receipt=receipt)

    def finish(self,sid,receipt):
        need(not self.ended and sid in self.sources and sid not in self.closed and sid not in self.finished,'partial_finish_source')
        self.finished.add(sid)
        return self._event('source_end',sid,reason='verified_producer_completed',receipt=receipt)

    def end(self):
        need(not self.ended,'partial_already_ended');self.ended=True
        return self._event('input_end',reason='finite_runtime_completion_not_native_evidence')

    def summary(self):
        result=dict(schema='overwatch-decoder.partial-roster-result/1',coverage='partial_independent_sources',
            common_time_snapshot=False,previous_values_carried=False,frames=sum(self.counts.values()),
            output_events=self.output_events,input_bytes=self.input_bytes,output_bytes=self.output_bytes,
            sources={sid:dict(frames=self.counts[sid],semantic_prefix_sha256=self.hashes[sid].hexdigest(),
                source_recipe_sha256=self.recipe_pins[sid],unavailable=self.closed.get(sid)) for sid in self.recipe_pins})
        if self.allow_controller_subsets:
            omitted=sorted(ck for ck,sid in self.primary.items() if sid not in self.sources
                           or ck not in {r['controller_object_key']for r in self.sources[sid]['objects']})
            result.update(allow_controller_subsets=True,omitted_controller_keys=omitted,
                all_census_primaries_acquired=not omitted,
                coverage_scope='latest_admitted_profiles_only_not_continuous_coverage')
        return result
