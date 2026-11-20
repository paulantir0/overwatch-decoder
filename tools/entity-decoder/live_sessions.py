"""Coordinate bounded native live epochs without process or file transport.

factory(session_start, completed_acquisition, segment_start) must return a fresh
LiveRelations using that epoch's own verified files and optional contracts.
Arguments are detached JSON copies of the exact native objects. consume accepts
original native JSONL bytes and returns at most one unchanged live projection,
with explicit epoch-admission provenance added. Gaps/failed acquisitions emit no
projection; this coordinator never carries object values between epochs.
"""
import copy
import json
import re

from live_relations import LiveRelations, InvalidLive, MAX_LINE
from export_relations import digest, integer, parse
from native_event_envelope import NativeEventEnvelope
from projection_copy import detached_copy
from native_storage import NativeStorage

MAX_EPOCHS = 128
MAX_EVENTS = 100000
MAX_BYTES = 512 * 1024 * 1024
MAX_OUTPUT_LINE = 1024 * 1024


def need(ok, reason):
    if not ok:
        raise InvalidLive(reason)


def hash_value(value):
    need(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'session_invalid_hash')


class LiveSession:
    def __init__(self, factory, *, maximum_events=MAX_EVENTS, maximum_bytes=MAX_BYTES,
                 maximum_output_bytes=MAX_BYTES, maximum_epochs=MAX_EPOCHS, acquisition_resolver=None):
        need(callable(factory), 'session_factory_required')
        need(acquisition_resolver is None or callable(acquisition_resolver), 'session_acquisition_resolver')
        self.acquisition_resolver=acquisition_resolver
        for value, limit in ((maximum_events, MAX_EVENTS), (maximum_bytes, MAX_BYTES),
                             (maximum_output_bytes, MAX_BYTES), (maximum_epochs, MAX_EPOCHS)):
            need(integer(value) and 0 < value <= limit, 'session_invalid_limit')
        self.factory = factory
        self.max_events, self.max_bytes, self.max_output, self.max_epochs = maximum_events, maximum_bytes, maximum_output_bytes, maximum_epochs
        self.events = self.input_bytes = self.output_bytes = self.frames = self.epochs = self.attempts = self.failed_acquisitions = 0
        self.event_sequence = self.last_emitted = self.frequency = None
        self.session_raw = self.session = self.target = self.recipe = None
        self.phase = 'new'
        self.failed = self.ended = False
        self.acquisition_start = self.completed_raw = self.adapter = None
        self.segment = self.active_acquisition = self.segment_start = None
        self.first_frame_start = self.last_frame_end = self.previous_epoch_end = None
        self.segment_frames = 0
        self.gap_end = None
        self.last_gap = None
        self.reacquire_allowed = True
        self.epoch_admission = None
        self.epoch_summaries = []
        self.background_preparation = False
        self.identical_profile_refresh = False
        self.last_frame_refreshable = False
        self.preparation = None
        self.preparation_summaries = []
        self.last_segment_trigger = None
        self._storage = NativeStorage(InvalidLive)

    def consume(self, raw):
        return self._consume_native(raw, include_event=False)

    def consume_with_event(self, raw):
        """Return projection and a detached event snapshot from one strict decode."""
        return self._consume_native(raw, include_event=True)

    def consume_owned(self, raw, consumer, *, with_projection_bytes=False):
        """Call an owned synchronous consumer with projection and read-only event.

        The event borrow lasts for this call only. Retaining/mutating the graph
        through Python base-class escape hatches is outside this internal API.
        Use consume_with_event for a detached, caller-mutable event snapshot.
        An opted-in consumer also receives the exact JSONL bytes used for
        the projection output bound, or None when there is no projection.
        """
        need(callable(consumer), 'session_owned_consumer')
        return self._consume_native(raw, include_event=False, consumer=consumer,
                                    with_projection_bytes=with_projection_bytes)

    def _consume_native(self, raw, *, include_event, consumer=None, with_projection_bytes=False):
        need(not self.failed, 'session_coordinator_closed')
        try:
            need(isinstance(raw, bytes) and 0 < len(raw) <= MAX_LINE and raw.endswith(b'\n'), 'session_line_bound')
            self.events += 1; self.input_bytes += len(raw)
            need(self.events <= self.max_events and self.input_bytes <= self.max_bytes, 'session_input_bound')
            with NativeEventEnvelope(raw).owned() as envelope:
                event = envelope._borrow(raw)
                need(isinstance(event, dict) and event.get('schema') == 'overwatch-decoder.field-live/1', 'session_event_schema')
                seq, ticks, freq = [event.get(k) for k in ('event_sequence', 'emitted_ticks', 'monotonic_frequency')]
                need(integer(seq) and seq == (0 if self.event_sequence is None else self.event_sequence + 1)
                     and integer(ticks) and ticks >= 0 and (self.last_emitted is None or ticks >= self.last_emitted)
                     and integer(freq) and 0 < freq <= 10**12 and (self.frequency is None or freq == self.frequency), 'session_global_event_order')
                self.event_sequence, self.last_emitted, self.frequency = seq, ticks, freq
                if self.phase != 'new':
                    need(event.get('session_id') == self.session['session_id'], 'session_identity_changed')
                need(not self.ended or event.get('kind') == 'session_finalization_error', 'session_event_after_end')
                result = self._event(event, raw, envelope)
                encoded = None
                if result is not None:
                    encoded = json.dumps(result, separators=(',', ':'), allow_nan=False).encode() + b'\n'
                    need(len(encoded) <= MAX_OUTPUT_LINE and self.output_bytes + len(encoded) <= self.max_output, 'session_output_bound')
                    self.output_bytes += len(encoded)
                result = detached_copy(result)
                if consumer is not None:
                    if with_projection_bytes:
                        return consumer(result, event, encoded)
                    return consumer(result, event)
                return (result, envelope.snapshot()) if include_event else result
        except Exception:
            # A factory failure is also an admission failure. Never resume an old
            # decoder after transport/configuration/native evidence was rejected.
            self.failed = True
            self.adapter = None
            raise

    def _consume_adapter(self, raw, envelope):
        # Preserve legacy subclasses' public consume overrides. Optimized
        # adapters instead extend the protected _consume_event hook.
        if type(self.adapter).consume is not LiveRelations.consume:
            return self.adapter.consume(raw)
        return self.adapter._consume_native_event(raw, envelope)

    def _event(self, event, raw, envelope):
        kind = event.get('kind')
        self._storage.check_event(event)
        if self.phase == 'new':
            need(kind == 'session_start', 'session_start_required')
            target = event.get('target', {})
            need(isinstance(event.get('session_id'), str) and re.fullmatch('[0-9a-f]{32}', event['session_id'])
                 and isinstance(target, dict) and integer(target.get('pid')) and target['pid'] > 0
                 and integer(target.get('creation_file_time')) and target['creation_file_time'] > 0
                 and target.get('architecture') == 'x64' and isinstance(target.get('image_name'), str)
                 and event.get('source_kind') == 'native_process_memory'
                 and event.get('recording_frame_included') is True and event.get('atomic') is False
                 and event.get('public_state_eligible') is False, 'session_start_metadata')
            hash_value(target.get('executable_sha256')); hash_value(event.get('recipe_sha256'))
            origin = event.get('monotonic_origin_ticks')
            need(integer(origin) and 0 <= origin <= event['emitted_ticks'], 'session_clock_origin')
            need(type(event.get('background_preparation',False)) is bool, 'session_background_policy')
            self.background_preparation = event.get('background_preparation',False)
            need(type(event.get('identical_profile_refresh',False)) is bool, 'session_identical_refresh_policy')
            self.identical_profile_refresh=event.get('identical_profile_refresh',False)
            need(not self.identical_profile_refresh or self.background_preparation and self.acquisition_resolver is not None,
                 'session_identical_refresh_resolver_required')
            self._storage.start(event)
            self.session, self.session_raw = event, raw
            self.target, self.recipe = target, event['recipe_sha256']
            self.phase = 'idle'
            return None
        if kind == 'session_finalization_error':
            raise InvalidLive('native_session_finalization_error')
        if kind in ('preparation_start','preparation_end','preparation_discard','preparation_no_change'):
            self._preparation_event(event,raw)
            if self.phase == 'active':self._consume_adapter(raw, envelope)
            return None
        if kind == 'acquisition_start':
            need(self.preparation is None, 'session_preparation_pending')
            need(self.phase == 'idle' and self.reacquire_allowed and self.attempts < self.max_epochs, 'session_acquisition_lifecycle')
            ordinal, started = event.get('acquisition'), event.get('start_ticks')
            need(integer(ordinal) and ordinal == self.attempts + 1
                 and integer(started) and self._gap_start() <= started <= event['emitted_ticks']
                 and event.get('observation_gap_open') is True and event.get('gap_start_ticks') == self._gap_start(), 'session_acquisition_start')
            self.attempts += 1
            self.acquisition_start = dict(ordinal=ordinal, start_ticks=started)
            self.phase = 'acquiring'
            return None
        if kind == 'acquisition_end':
            need(type(event.get('prepared',False)) is bool, 'session_prepared_policy')
            if event.get('prepared'):
                self._prepared_end(event,raw)
                return None
            need(self.phase == 'acquiring', 'session_acquisition_end_without_start')
            entry = event.get('acquisition', {})
            need(entry.get('ordinal') == self.acquisition_start['ordinal']
                 and entry.get('directory') == f"acquisition-{self.acquisition_start['ordinal']:04d}"
                 and entry.get('start_ticks') == self.acquisition_start['start_ticks']
                 and integer(entry.get('end_ticks')) and entry['start_ticks'] <= entry['end_ticks'] <= event['emitted_ticks']
                 and type(entry.get('complete')) is bool, 'session_acquisition_end')
            if entry['complete']:
                need(entry.get('error') is None, 'session_completed_acquisition_error')
                hash_value(entry.get('manifest_sha256')); hash_value(entry.get('profile_sha256'))
                self.completed_raw = raw
                self.phase = 'ready'
            else:
                need(isinstance(entry.get('error'), str) and entry['error'] and entry.get('profile_sha256') is None, 'session_failed_acquisition_metadata')
                if entry.get('manifest_sha256') is not None: hash_value(entry['manifest_sha256'])
                self.failed_acquisitions += 1
                self.completed_raw = None
                self.phase = 'idle'
            self.acquisition_start = None
            return None
        if kind == 'segment_start':
            need(self.phase == 'ready' and self.completed_raw is not None and self.epochs < self.max_epochs, 'session_segment_without_completed_acquisition')
            acquired_event = parse(self.completed_raw); entry = acquired_event['acquisition']
            prepared = acquired_event.get('prepared',False)
            need(type(event.get('prepared',False)) is bool and event.get('prepared',False) == prepared, 'session_prepared_segment_marker')
            number = event.get('segment'); started = event.get('start_ticks')
            need(integer(number) and number == self.epochs + 1 and event.get('acquisition') == entry['ordinal']
                 and event.get('profile_sha256') == entry['profile_sha256'] and integer(started)
                 and entry['end_ticks'] <= started <= event['emitted_ticks'], 'session_segment_pins')
            adapter = self.factory(copy.deepcopy(self.session), copy.deepcopy(entry), copy.deepcopy(event))
            need(isinstance(adapter, LiveRelations) and adapter.session == self.session['session_id']
                 and adapter.segment == number and adapter.projector.target == self.target
                 and adapter.projector.hash == entry['profile_sha256']
                 and adapter.acquisition['manifest_sha256'] == entry['manifest_sha256']
                 and adapter.acquisition['recipe_sha256'] == self.recipe, 'session_factory_epoch_pins')
            event_options = {'_native_event': envelope} if type(adapter).begin_epoch is LiveRelations.begin_epoch else {}
            if prepared:
                adapter.begin_epoch(self.session_raw,self.completed_raw,raw,
                    preparation_start_raw=self.preparation['start_raw'],preparation_end_raw=self.preparation['end_raw'], **event_options)
            else:adapter.begin_epoch(self.session_raw, self.completed_raw, raw, **event_options)
            self._storage.begin(event)
            # Each cursor validates once; seed a fresh epoch adapter from the
            # coordinator's validated global prefix, never share mutable state.
            adapter._storage = self._storage.clone()
            self.adapter = adapter
            self.epochs += 1
            self.segment, self.active_acquisition, self.segment_start = number, entry['ordinal'], started
            self.previous_epoch_end = self.last_frame_end
            self.first_frame_start = None
            self.segment_frames = 0
            self.gap_end = None
            self.last_frame_refreshable=False
            self.epoch_admission = dict(acquisition=entry['ordinal'], session_start_sha256=digest(self.session_raw),
                acquisition_end_sha256=digest(self.completed_raw), segment_start_sha256=digest(raw),
                previous_epoch_last_frame_end_ticks=self.previous_epoch_end, previous_values_carried=False)
            if prepared:
                pending=self.preparation
                need(pending is not None and pending['state']=='activation_announced', 'session_prepared_activation_missing')
                self.epoch_admission.update(prepared=True,origin_segment=pending['origin_segment'],
                    preparation_start_sha256=pending['start_sha256'],preparation_end_sha256=pending['end_sha256'],
                    activation_evidence_sha256=acquired_event['activation']['evidence_sha256'])
                self.preparation_summaries.append(dict(acquisition=entry['ordinal'],origin_segment=pending['origin_segment'],
                    outcome='activated',preparation_end_sha256=pending['end_sha256'],
                    activation_evidence_sha256=acquired_event['activation']['evidence_sha256']))
                self.preparation=None
            self.completed_raw = None
            self.phase = 'active'
            return None
        if kind == 'gap':
            need(self.phase in ('idle', 'ready', 'active') and (self.phase != 'active' or self.segment_frames == 0 and self.gap_end is None), 'session_gap_lifecycle')
            interval = event.get('interval', {})
            start, end = interval.get('start_ticks'), interval.get('end_ticks')
            need(integer(start) and integer(end) and start == self._gap_start() <= end <= event['emitted_ticks'], 'session_gap_bracket')
            self.last_gap = dict(start_ticks=start, end_ticks=end)
            if self.phase == 'active':
                self.gap_end = end
                self._consume_adapter(raw, envelope)
            return None
        if kind == 'storage_cohort_sealed':
            need(self.phase == 'active' and self.adapter is not None, 'session_storage_without_active_epoch')
            self._storage.seal(event, raw)
            need(self._consume_adapter(raw, envelope) is None, 'session_storage_projection')
            return None
        if kind == 'frame':
            need(self.phase == 'active' and self.adapter is not None, 'session_frame_without_active_epoch')
            need(self.gap_end is not None, 'session_first_frame_gap_required')
            start, end = event.get('start_ticks'), event.get('end_ticks')
            need(integer(start) and integer(end) and start >= self.segment_start
                 and (self.last_frame_end is None or start >= self.last_frame_end)
                 and (self.segment_frames != 0 or start == self.gap_end), 'session_frame_bracket')
            result = self._consume_adapter(raw, envelope)
            need(result is not None and result.get('session_id') == self.session['session_id']
                 and result.get('segment') == self.segment and result.get('event_sequence') == event['event_sequence']
                 and result.get('profile_sha256') == event['profile_sha256']
                 and result.get('public_state_eligible') is False and result.get('durability_verified') is False,
                 'session_projection_identity')
            if getattr(self.adapter, 'ammunition', None) is not None:
                admission = result.get('ammunition_live_admission', {})
                need(result.get('live_ammunition_output_enabled') is True
                     and admission.get('acquisition') == self.active_acquisition
                     and admission.get('contract_sha256') == self.adapter.ammunition.contract_sha256
                     and all(admission.get(event_key) == self.epoch_admission[epoch_key]
                             for event_key, epoch_key in (
                                 ('session_start_event_sha256', 'session_start_sha256'),
                                 ('acquisition_end_event_sha256', 'acquisition_end_sha256'),
                                 ('segment_start_event_sha256', 'segment_start_sha256'))),
                     'session_ammunition_epoch_admission_mismatch')
            self.first_frame_start = start if self.first_frame_start is None else self.first_frame_start
            self.last_frame_end = end
            captured=event.get('recording_frame',{})
            self.last_frame_refreshable=(event.get('terminal_reason') is None and captured.get('terminal_reason') is None
                and all(isinstance(captured.get('guards_'+phase),list)
                    and len(captured['guards_'+phase])==len(self.adapter.projector.guards)
                    and all(isinstance(g,dict) and g.get('ok') is True and g.get('error') is None
                            for g in captured['guards_'+phase]) for phase in ('before','after')))
            self._storage.frame(event)
            self.segment_frames += 1; self.frames += 1
            result['session_epoch'] = copy.deepcopy(self.epoch_admission)
            return result
        if kind == 'segment_end':
            need(self.phase == 'active' and self.adapter is not None, 'session_segment_end_without_start')
            entry = event.get('segment', {})
            need(entry.get('ordinal') == self.segment and entry.get('acquisition') == self.active_acquisition
                 and entry.get('profile_sha256') == self.adapter.projector.hash and entry.get('start_ticks') == self.segment_start
                 and integer(entry.get('end_ticks')) and self.segment_start <= entry['end_ticks'] <= event['emitted_ticks']
                 and entry.get('frames') == self.segment_frames and integer(entry.get('frames'))
                 and entry.get('first_frame_start_ticks') == self.first_frame_start
                 and entry.get('last_frame_end_ticks') == (self.last_frame_end if self.segment_frames else None), 'session_segment_end_mismatch')
            trigger=entry.get('trigger')
            if trigger=='prepared_reacquisition':
                need(self.background_preparation and self.preparation is not None and self.preparation['state']=='ready'
                     and self.preparation['origin_segment']==self.segment and event.get('failure') is None, 'session_prepared_rotation')
            self.last_segment_trigger=trigger
            self._storage.end(event)
            self._consume_adapter(raw, envelope)
            self.epoch_summaries.append(dict(segment=self.segment, acquisition=self.active_acquisition,
                profile_sha256=self.adapter.projector.hash, frames=self.segment_frames,
                first_frame_start_ticks=self.first_frame_start, last_frame_end_ticks=entry['last_frame_end_ticks'],
                terminal_summary_written=event.get('terminal_summary_written'), failure=event.get('failure')))
            self.adapter = None
            self.reacquire_allowed = entry.get('trigger') in ('guard_invalidation', 'periodic_reacquisition','prepared_reacquisition') and event.get('failure') is None
            self.phase = 'idle'
            return None
        if kind == 'session_end':
            if self.preparation is not None and self.phase=='ready' and self.preparation['state']=='activation_announced':
                pending=self.preparation
                self.preparation_summaries.append(dict(acquisition=pending['ordinal'],origin_segment=pending['origin_segment'],
                    outcome='activation_announced_unstarted',preparation_end_sha256=pending['end_sha256'],
                    acquisition_end_sha256=pending['activation_event_sha256'],activation_evidence_sha256=pending['activation_evidence_sha256'],
                    observed_values_published=False,activation_bytes_verified=False))
                self.preparation=None
            need(self.preparation is None, 'session_unfinished_preparation')
            need(self.phase in ('idle', 'ready'), 'session_end_during_active_operation')
            final = event.get('result_before_this_write', {})
            need(final.get('schema') == 'overwatch-decoder.field-observation/1' and final.get('session_id') == self.session['session_id']
                 and final.get('target') == self.target and final.get('recipe_sha256') == self.recipe
                 and final.get('status') == 'finished' and final.get('public_state_eligible') is False
                 and final.get('atomic') is False and type(final.get('complete')) is bool, 'session_terminal_snapshot')
            self._storage.finish(final)
            self.phase = 'ended'; self.ended = True
            return None
        raise InvalidLive('session_unexpected_event')

    def _preparation_event(self,event,raw):
        need(self.background_preparation, 'session_background_not_enabled')
        kind=event['kind'];pending=self.preparation
        if kind=='preparation_start':
            need(self.phase=='active' and self.segment_frames>0 and pending is None
                 and self.attempts<self.max_epochs, 'session_preparation_lifecycle')
            ordinal,started=event.get('acquisition'),event.get('start_ticks')
            need(integer(ordinal) and ordinal==self.attempts+1 and integer(event.get('origin_segment')) and event['origin_segment']==self.segment
                 and integer(started) and self.segment_start<=started<=event['emitted_ticks']
                 and event.get('observation_gap_open') is False and 'gap_start_ticks' not in event, 'session_preparation_start')
            self.attempts+=1
            self.preparation=dict(ordinal=ordinal,start_ticks=started,origin_segment=self.segment,
                                  state='preparing',start_sha256=digest(raw),start_raw=raw)
            return
        need(pending is not None and self.phase in ('active','idle','ready')
             and integer(event.get('origin_segment')) and event['origin_segment']==pending['origin_segment'], 'session_preparation_without_start')
        if kind=='preparation_end':
            need(pending['state']=='preparing', 'session_preparation_duplicate_end')
            entry=event.get('acquisition',{})
            need(isinstance(entry,dict) and integer(entry.get('ordinal')) and entry['ordinal']==pending['ordinal']
                 and entry.get('directory')==f"acquisition-{pending['ordinal']:04d}"
                 and integer(entry.get('start_ticks')) and entry['start_ticks']==pending['start_ticks'] and integer(entry.get('end_ticks'))
                 and entry['start_ticks']<=entry['end_ticks']<=event['emitted_ticks']
                 and type(entry.get('complete')) is bool, 'session_preparation_end')
            outcome=event.get('outcome')
            if entry['complete']:
                need(outcome=='ready' and entry.get('error') is None, 'session_preparation_ready_error')
                hash_value(entry.get('manifest_sha256'));hash_value(entry.get('profile_sha256'))
                pending.update(state='ready',entry=copy.deepcopy(entry),end_sha256=digest(raw),end_raw=raw)
            else:
                need(outcome in ('failed','cancelled') and isinstance(entry.get('error'),str) and entry['error']
                     and entry.get('profile_sha256') is None
                     and (outcome=='cancelled')==(entry['error']=='cancelled'), 'session_preparation_failed_metadata')
                if entry.get('manifest_sha256') is not None:hash_value(entry['manifest_sha256'])
                self.failed_acquisitions+=1
                self.preparation_summaries.append(dict(acquisition=pending['ordinal'],origin_segment=pending['origin_segment'],
                    outcome=outcome,error=entry['error'],preparation_start_sha256=pending['start_sha256'],preparation_end_sha256=digest(raw)))
                self.preparation=None
            return
        if kind=='preparation_no_change':
            need(self.identical_profile_refresh and self.phase=='active' and pending['state']=='ready'
                 and self.last_frame_refreshable and self.segment==pending['origin_segment'], 'session_unchanged_lifecycle')
            need(integer(event.get('acquisition')) and event['acquisition']==pending['ordinal']
                 and integer(event.get('active_acquisition')) and event['active_acquisition']==self.active_acquisition
                 and event.get('profile_sha256')==pending['entry']['profile_sha256']==self.adapter.projector.hash
                 and event.get('manifest_sha256')==pending['entry']['manifest_sha256']
                 and event.get('preparation_end_sha256')==pending['end_sha256']
                 and event.get('profile_adopted') is False, 'session_unchanged_pins')
            start,end=event.get('comparison_start_ticks'),event.get('comparison_end_ticks')
            need(integer(start) and integer(end) and max(self.last_frame_end,pending['entry']['end_ticks'])<=start<=end<=event['emitted_ticks'],
                 'session_unchanged_time')
            directory=self.acquisition_resolver(copy.deepcopy(pending['entry']))
            evidence=self.adapter.verify_unchanged_preparation(directory,pending['entry'])
            summary=dict(acquisition=pending['ordinal'],active_acquisition=self.active_acquisition,origin_segment=self.segment,
                outcome='unchanged',profile_adopted=False,comparison_start_ticks=start,comparison_end_ticks=end,
                preparation_start_ticks=pending['entry']['start_ticks'],preparation_end_ticks=pending['entry']['end_ticks'],
                preparation_start_sha256=pending['start_sha256'],preparation_end_sha256=pending['end_sha256'],
                no_change_event_sha256=digest(raw),**evidence)
            self.preparation_summaries.append(summary)
            self.epoch_admission['last_unchanged_preparation']=copy.deepcopy(summary)
            self.preparation=None
            return
        need(kind=='preparation_discard' and pending['state'] in ('ready','activation_announced')
             and event.get('acquisition')==pending['ordinal'] and isinstance(event.get('error'),str) and event['error'],
             'session_preparation_discard')
        start,end=event.get('start_ticks'),event.get('end_ticks')
        need(integer(start) and integer(end) and pending['entry']['end_ticks']<=start<=end<=event['emitted_ticks'],
             'session_preparation_discard_time')
        if event.get('evidence_sha256') is not None:hash_value(event['evidence_sha256'])
        self.preparation_summaries.append(dict(acquisition=pending['ordinal'],origin_segment=pending['origin_segment'],
            outcome='discarded',error=event['error'],preparation_end_sha256=pending['end_sha256'],
            discard_event_sha256=digest(raw),activation_evidence_sha256=event.get('evidence_sha256')))
        if pending['state']=='activation_announced':self.completed_raw=None;self.phase='idle'
        self.preparation=None

    def _prepared_end(self,event,raw):
        pending=self.preparation;entry=event.get('acquisition',{});activation=event.get('activation',{})
        need(self.background_preparation and self.phase=='idle' and self.reacquire_allowed
             and self.last_segment_trigger in ('prepared_reacquisition','guard_invalidation')
             and pending is not None and pending['state']=='ready', 'session_prepared_acquisition_lifecycle')
        need(isinstance(entry,dict) and integer(entry.get('ordinal')) and integer(entry.get('start_ticks'))
             and integer(entry.get('end_ticks')) and entry==pending['entry'] and integer(event.get('origin_segment')) and event['origin_segment']==pending['origin_segment']
             and event.get('preparation_end_sha256')==pending['end_sha256'], 'session_prepared_acquisition_pins')
        need(isinstance(activation,dict), 'session_activation_metadata')
        start,end=activation.get('start_ticks'),activation.get('end_ticks')
        need(integer(start) and integer(end) and max(entry['end_ticks'],self.last_frame_end or 0)<=start<=end<=event['emitted_ticks']
             and integer(activation.get('guard_count')) and 1<=activation['guard_count']<=256
             and activation.get('guards_verified') is True, 'session_activation_metadata')
        hash_value(activation.get('evidence_sha256'))
        pending.update(state='activation_announced',activation_event_sha256=digest(raw),activation_evidence_sha256=activation['evidence_sha256'])
        self.completed_raw=raw;self.phase='ready'

    def _gap_start(self):
        return self.session['monotonic_origin_ticks'] if self.last_frame_end is None else self.last_frame_end

    def close(self):
        """Report accepted prefix only; EOF does not synthesize a terminal event."""
        result=dict(schema='overwatch-decoder.live-session-result/1', events=self.events, epochs=self.epochs,
            acquisition_attempts=self.attempts, failed_acquisitions=self.failed_acquisitions, frames=self.frames,
            input_bytes=self.input_bytes, output_bytes=self.output_bytes, native_session_end_seen=self.ended,
            failed=self.failed, phase=self.phase, epochs_observed=list(self.epoch_summaries),
            atomic=False, public_state_eligible=False, durability_verified=False,
            recording_state='accepted_not_durability_verified')
        if self.background_preparation:
            result.update(background_preparation=True,preparations_observed=copy.deepcopy(self.preparation_summaries),
                pending_preparation=None if self.preparation is None else {k:self.preparation[k] for k in ('ordinal','origin_segment','state')})
        if self.identical_profile_refresh:result['identical_profile_refresh']=True
        if self._storage.enabled:result['storage_notifications']=self._storage.receipt()
        return result


def stream(coordinator, source, output):
    while True:
        raw = source.readline(MAX_LINE + 1)
        if not raw: break
        result = coordinator.consume(raw)
        if result is not None:
            encoded = json.dumps(result, separators=(',', ':'), allow_nan=False).encode() + b'\n'
            need(output.write(encoded) == len(encoded), 'session_output_short_write')
            output.flush()
    return coordinator.close()
