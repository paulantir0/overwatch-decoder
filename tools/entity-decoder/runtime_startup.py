"""Bounded startup validation; source JSON is retained, old values are not live."""
import copy
import hashlib

from aggregate_partitions import canonical, need, parse
from aggregate_live_partitions import LivePartitions, MAX_TOTAL_BYTES, MAX_EVENTS, MAX_LINE_BYTES


class StartupSources:
    """Validate every admitted source line while waiting for the whole roster.

    Only one most recent line and its detached metadata survive per source.
    Exact prefix hashes/counts refer to the unchanged saved source JSONL; this
    does not claim those observations were published in the live aggregate.
    """
    def __init__(self, target, frequency, *, raw_candidates):
        self.target=target;self.frequency=frequency;self.raw_candidates=raw_candidates
        self.validators={};self.latest={};self.counts={};self.hashes={};self.spans={}
        self.events=self.bytes=0;self.failed=False

    def add(self, source):
        need(not self.failed and len(self.validators)<16,'startup_source_bound')
        sid=source['source_id'];need(sid not in self.validators,'startup_duplicate_source')
        config=dict(schema='overwatch-decoder.live-partition-config/1',epoch_id='startup-'+sid,
            clock_domain_id='startup-source-native-qpc',target=self.target,monotonic_frequency=self.frequency,
            window_origin_ticks=0,window_ticks=self.frequency//10,maximum_skew_ticks=self.frequency*150//1000,
            maximum_origin_offset_ticks=self.frequency//100,sources=[source],
            roster=[dict(row,primary_source_id=sid)for row in source['objects']])
        if self.raw_candidates:config.update(observation_mode='raw-candidates',allow_unresolved_bodies=True)
        self.validators[sid]=LivePartitions(canonical(config));self.counts[sid]=0;self.hashes[sid]=hashlib.sha256()

    def consume(self, sid, raw):
        need(not self.failed,'startup_validation_failed')
        try:
            need(sid in self.validators and isinstance(raw,bytes)and 0<len(raw)<=MAX_LINE_BYTES,'startup_source_line')
            self.events+=1;self.bytes+=len(raw)
            need(self.events<=MAX_EVENTS and self.bytes<=MAX_TOTAL_BYTES,'startup_input_bound')
            value=parse(raw);source=self.validators[sid].sources[sid]
            need(value.get('segment')==source['segment'],'startup_epoch_changed_restart_required')
            metadata=self.validators[sid]._consume_decoded(sid,raw,value,retain=False,context=True)
            self.counts[sid]+=1;self.hashes[sid].update(raw)
            self.latest[sid]=dict(frame=metadata,raw=raw)
            span=self.spans.setdefault(sid,dict(first_start_ticks=metadata['timing']['start_ticks'],last_end_ticks=None,skipped_slots=0))
            span['last_end_ticks']=metadata['timing']['end_ticks'];span['skipped_slots']+=value['gap_before']['skipped_slots']
            need(all(row['relation_status']=='observed'or row.get('unresolved_body_validated')is True for row in metadata['relations']),
                 'startup_guard_invalidated_restart_required')
            return metadata
        except Exception:
            self.failed=True;raise

    def current(self, source_ids, now_ticks):
        return (set(self.latest)==set(source_ids) and all(0<=now_ticks-node['frame']['timing']['end_ticks']<=self.frequency*150//1000 for node in self.latest.values()))

    def summary(self):
        return dict(schema='overwatch-decoder.live-startup-validation/1',validated_frames=sum(self.counts.values()),attempted_frames=self.events,input_bytes=self.bytes,
            maximum_retained_source_lines=len(self.latest),retained_bytes=sum(len(n['raw'])for n in self.latest.values()),
            all_source_json_frames_preserved=True,observations_published_in_live_aggregate=False,
            previous_values_carried=False,failed=self.failed,
            sources={sid:dict(validated_frames=self.counts[sid],source_prefix_sha256=self.hashes[sid].hexdigest(),
                hash_scope='exact_source_jsonl_prefix_including_lf',session_id=v.sources[sid]['session_id'],segment=v.sources[sid]['segment'],
                profile_sha256=v.sources[sid]['profile_sha256'],**copy.deepcopy(self.spans.get(sid,{})))for sid,v in self.validators.items()})
