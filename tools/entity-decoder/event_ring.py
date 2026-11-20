"""Bounded, neutral projection of confirmed circular-slot version changes.

Caller-normalized head is the most recently written slot; count is occupancy.
This module does not establish the meaning of a record or count producer writes.
"""
from __future__ import annotations
import copy
import hashlib
import json

class InvalidRingSnapshot(ValueError):
    pass

def _need(ok, reason):
    if not ok: raise InvalidRingSnapshot(reason)
def _integer(value, low, high):return type(value) is int and low <= value <= high
def _hash(value):return isinstance(value,str) and len(value)==64 and all(c in '0123456789abcdef' for c in value)
def _canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def _payload(slot):return tuple(slot[k] for k in ('key_u32','tick_u32','amount_i32','flags_u8'))
def _raw(payload):return dict(zip(('key_u32','tick_u32','amount_i32','flags_u8'),payload))

class EventRingProjector:
    """One independently sampled view, at most 128 slots and bounded version state per slot.

    Only changes confirmed by two consecutive valid snapshots are emitted.
    Records are observed slot versions, never a complete log of producer events.
    """
    def __init__(self, *, capacity=32, owned_indices=None):
        _need(_integer(capacity,1,128),'capacity_bound')
        indices=list(range(capacity)) if owned_indices is None else list(owned_indices)
        _need(1<=len(indices)<=capacity and all(_integer(i,0,capacity-1) for i in indices)
              and len(set(indices))==len(indices),'owned_indices')
        self.capacity=capacity;self.indices=tuple(sorted(indices));self._reset()
    def _reset(self):
        self.source=None;self.sequence=None;self.end=None;self.frequency=None;self.metadata=None
        self.versions={};self.pending={};self.gap_serial=0;self.confirmed_gap={};self.has_baseline=False;self.observed={};self.last_snapshot_hash=None
    def _validate(self,snapshot):
        _need(isinstance(snapshot,dict) and set(snapshot)=={'schema','source','sequence','frame_sha256','start_ticks','end_ticks','monotonic_frequency','guards_valid','metadata_before','metadata_after','slots'} and snapshot.get('schema')=='overwatch-decoder.event-ring-snapshot/1','snapshot_schema')
        source=snapshot.get('source');_need(isinstance(source,dict) and set(source)=={'target','controller','epoch','build_sha256','profile_sha256'},'source_shape')
        target=source['target'];controller=source['controller']
        _need(isinstance(target,dict) and set(target)<= {'pid','creation_file_time','executable_sha256','image_name','architecture'} and _integer(target.get('pid'),1,2**31-1)
              and _integer(target.get('creation_file_time'),1,2**63-1)
              and _hash(source['build_sha256']) and target.get('executable_sha256')==source['build_sha256']
              and _hash(source['profile_sha256']),'source_target')
        _need(('image_name' not in target or isinstance(target['image_name'],str) and 1<=len(target['image_name'])<=128)
              and ('architecture' not in target or isinstance(target['architecture'],str) and 1<=len(target['architecture'])<=16),'target_text_bound')
        _need(isinstance(controller,dict) and set(controller)=={'handle_u32','creation_key_u32'}
              and all(_integer(v,0,2**32-1) for v in controller.values()),'source_controller')
        _need(isinstance(source['epoch'],str) and 1<=len(source['epoch'])<=256,'source_epoch')
        _need(len(_canonical(source))<=4096,'source_bound')
        _need(_integer(snapshot.get('sequence'),0,2**63-1) and _hash(snapshot.get('frame_sha256')),'frame_identity')
        start,end=snapshot.get('start_ticks'),snapshot.get('end_ticks')
        _need(_integer(start,0,2**63-1) and _integer(end,start,2**63-1)
              and _integer(snapshot.get('monotonic_frequency'),1,2**63-1),'frame_interval')
        _need(type(snapshot.get('guards_valid'))is bool,'guards_status')
        for name in ('metadata_before','metadata_after'):
            m=snapshot.get(name)
            _need(isinstance(m,dict) and set(m)=={'head','count'} and _integer(m['head'],0,self.capacity-1)
                  and _integer(m['count'],0,self.capacity),'ring_metadata')
        slots=snapshot.get('slots');_need(isinstance(slots,list) and len(slots)==len(self.indices),'slot_view_size')
        by_index={}
        for slot in slots:
            _need(isinstance(slot,dict) and set(slot)=={'index','key_u32','tick_u32','amount_i32','flags_u8','read_start_ticks','read_end_ticks','evidence_sha256'},'slot_shape')
            index=slot['index'];_need(_integer(index,0,self.capacity-1) and index not in by_index,'slot_index')
            _need(_integer(slot['key_u32'],0,2**32-1) and _integer(slot['tick_u32'],0,2**32-1)
                  and _integer(slot['amount_i32'],-2**31,2**31-1) and _integer(slot['flags_u8'],0,255),'slot_payload')
            _need(_integer(slot['read_start_ticks'],start,end) and _integer(slot['read_end_ticks'],slot['read_start_ticks'],end)
                  and _hash(slot['evidence_sha256']),'slot_evidence')
            by_index[index]=slot
        _need(set(by_index)==set(self.indices),'slot_view_changed')
        return by_index
    def _result(self,s,status,reason=None,records=(),gaps=()):
        return dict(schema='overwatch-decoder.event-ring-projection/1',status=status,reason=reason,source=copy.deepcopy(s['source']),
                    sequence=s['sequence'],frame_sha256=s['frame_sha256'],capacity=self.capacity,owned_indices=list(self.indices),
                    records=list(records),gap_reasons=list(dict.fromkeys(gaps)),continuity='unknown',complete_event_count=False,
                    atomic=False,semantics='observed_slot_versions_only')
    @staticmethod
    def _observation(s,slot):
        return dict(sequence=s['sequence'],frame_sha256=s['frame_sha256'],evidence_sha256=slot['evidence_sha256'],
                    frame_start_ticks=s['start_ticks'],frame_end_ticks=s['end_ticks'],read_start_ticks=slot['read_start_ticks'],
                    read_end_ticks=slot['read_end_ticks'],monotonic_frequency=s['monotonic_frequency'])
    def consume(self,snapshot):
        try:slots=self._validate(snapshot)
        except (InvalidRingSnapshot,TypeError,ValueError,OverflowError):
            # A malformed sample cannot help confirm a pending version. Keep only
            # bounded last-confirmed values, never emit from the invalid input.
            self.pending.clear();self.gap_serial+=1
            raise
        s=snapshot;changed_source=self.source is not None and self.source!=s['source']
        if self.source is None or changed_source:
            self._reset();self.source=copy.deepcopy(s['source']);self.frequency=s['monotonic_frequency']
        snapshot_hash=hashlib.sha256(_canonical(s)).hexdigest()
        if self.sequence is not None and s['sequence']==self.sequence and snapshot_hash==self.last_snapshot_hash:
            if not s['guards_valid'] or s['metadata_before']!=s['metadata_after']:
                return self._result(s,'unknown','invalid_duplicate_frame',gaps=['invalid_snapshot'])
            return self._result(s,'unchanged','duplicate_frame')
        if self.sequence is not None and s['sequence']<=self.sequence:
            self.pending.clear();self.gap_serial+=1
            return self._result(s,'unknown','non_increasing_sequence',gaps=['sequence_order'])
        gaps=[]
        if self.sequence is not None and s['sequence']!=self.sequence+1:gaps.append('sequence_gap')
        if self.frequency!=s['monotonic_frequency'] or self.end is not None and s['start_ticks']<self.end:
            self.pending.clear();self.gap_serial+=1
            return self._result(s,'unknown','clock_mismatch',gaps=['clock_mismatch'])
        self.sequence=s['sequence'];self.end=s['end_ticks'];self.last_snapshot_hash=snapshot_hash
        if not s['guards_valid'] or s['metadata_before']!=s['metadata_after']:
            self.pending.clear();self.gap_serial+=1
            return self._result(s,'unknown','guards_unknown' if not s['guards_valid'] else 'metadata_changed',gaps=['invalid_snapshot'])
        meta=s['metadata_after'];head,count=meta['head'],meta['count']
        occupied={(head-n)%self.capacity for n in range(count)}
        if self.metadata is not None:
            previous=self.metadata;advance=(head-previous['head'])%self.capacity
            if count<previous['count']:
                self.pending.clear();self.versions.clear();self.confirmed_gap.clear();self.has_baseline=False;gaps.append('count_regressed')
            elif count<self.capacity and advance!=count-previous['count']:
                gaps.append('cursor_count_inconsistent')
            elif count==self.capacity:
                # Modulo metadata cannot prove whether one or many turns passed.
                # A changed owned slot outside the visible suffix proves that the
                # shortest-advance interpretation alone cannot explain this view.
                suffix={(head-n)%self.capacity for n in range(advance)}
                if any(i in occupied and i in self.observed and _payload(slots[i])!=self.observed[i] and i not in suffix for i in self.indices):
                    gaps.append('possible_wrap_or_overrun')
        if gaps:self.pending.clear();self.gap_serial+=1
        self.metadata=copy.deepcopy(meta);self.observed={i:_payload(slots[i]) for i in self.indices}
        if not self.has_baseline:
            self.versions={i:_payload(slots[i]) if i in occupied else None for i in self.indices}
            self.confirmed_gap={i:self.gap_serial for i in self.indices};self.has_baseline=True
            return self._result(s,'baseline','source_reset' if changed_source else 'initial_or_reset_baseline',gaps=gaps)
        records=[]
        for index in self.indices:
            slot=slots[index];payload=_payload(slot)
            if index not in occupied or payload==self.versions.get(index):
                self.pending.pop(index,None);self.confirmed_gap[index]=self.gap_serial;continue
            pending=self.pending.get(index)
            if pending is not None and pending['payload']==payload and pending['last_sequence']==s['sequence']-1:
                after_gap=self.confirmed_gap.get(index,self.gap_serial)!=self.gap_serial
                first=pending['first'];confirmation=self._observation(s,slot)
                identity=[s['source'],index,first['sequence'],s['sequence'],payload]
                records.append(dict(kind='new_record',record_id=hashlib.sha256(_canonical(identity)).hexdigest(),slot_index=index,
                    raw=_raw(payload),source=copy.deepcopy(s['source']),
                    change='observed_slot_version_changed_after_gap' if after_gap else 'observed_slot_version_changed',
                    first_observation=first,confirmation=confirmation,continuity='unknown',complete_event_count=False,
                    atomic=False,producer_write_count=None))
                self.versions[index]=payload;self.confirmed_gap[index]=self.gap_serial;self.pending.pop(index,None)
            else:self.pending[index]=dict(payload=payload,last_sequence=s['sequence'],first=self._observation(s,slot))
        ambiguity=['modulo_cursor_ambiguous'] if count==self.capacity else []
        return self._result(s,'advanced' if records else 'gap' if gaps else 'warming' if self.pending else 'unchanged',
                            records=records,gaps=gaps+ambiguity)
    def state_size(self):
        """Bounded diagnostic counts; no retained frame history or output queue."""
        return dict(confirmed_slots=len(self.versions),pending_slots=len(self.pending),capacity=self.capacity,owned_slots=len(self.indices))
