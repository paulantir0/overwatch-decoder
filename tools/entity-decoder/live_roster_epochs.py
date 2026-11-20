"""Bounded roster rollover over upstream LiveSession semantic frames.

Caller configurations are reviewed inputs, not independent native proof. This
module never reads process memory, decodes native frames, discovers participants,
or treats a controller replacement as the same participant. All output is private
research. A transition discards observations, retaining only ordering metadata.
"""
import copy

from aggregate_live_partitions import LivePartitions, MAX_EVENTS, MAX_OUTPUT_LINE_BYTES, MAX_WINDOWS, configured_pair
from aggregate_partitions import (MAX_LINE_BYTES, MAX_TOTAL_BYTES, canonical,
    digest, integer, need, object_pair, parse, sha)

MAX_REVISIONS = 128
CURSORS = ('sequence', 'previous_end', 'event_sequence', 'anchor')
ADMISSION_KEYS = ('acquisition', 'session_start_sha256', 'acquisition_end_sha256',
                  'segment_start_sha256', 'previous_epoch_last_frame_end_ticks',
                  'previous_values_carried')
ACCOUNTING = ('events', 'input_bytes', 'output_bytes', 'windows', 'coverage', 'counts', 'reasons')


def admission(source):
    value = source.get('session_epoch')
    need(isinstance(value, dict) and set(value) == set(ADMISSION_KEYS), 'roster_epoch_admission_required')
    for key in ADMISSION_KEYS[1:4]:
        digest(value[key])
    need(integer(value['acquisition']) and 1 <= value['acquisition'] <= 128
         and value['previous_values_carried'] is False, 'roster_epoch_admission_invalid')
    previous = value['previous_epoch_last_frame_end_ticks']
    need(previous is None or integer(previous) and previous >= 0, 'roster_previous_epoch_time')
    # Category scope hashes explicit saved event artifacts; session_epoch hashes
    # original transport lines. Upstream LiveRelations checks their parsed event
    # equality. Different JSON serializations need not have equal byte digests.
    return value


class LiveRosterEpochs:
    """One controlled controller roster, with explicit source epoch admission.

    ``consume`` accepts the exact serialized semantic frame from LiveSession.
    ``admit`` additionally takes one freshly verified source declaration, with
    its expected ``session_epoch``. It consumes the first new frame itself.
    Callers must not send that frame to ``consume`` again. Returned event lists
    contain aggregate windows or explicit unknown transition records. EOF/close
    does not flush pending windows or certify durability.
    """
    def __init__(self, raw_config, *, maximum_events=MAX_EVENTS,
                 maximum_input_bytes=MAX_TOTAL_BYTES, maximum_output_bytes=MAX_TOTAL_BYTES,
                 maximum_revisions=MAX_REVISIONS):
        for value, limit in ((maximum_events, MAX_EVENTS), (maximum_input_bytes, MAX_TOTAL_BYTES),
                             (maximum_output_bytes, MAX_TOTAL_BYTES), (maximum_revisions, MAX_REVISIONS)):
            need(integer(value) and 0 < value <= limit, 'roster_invalid_limit')
        self.aggregate = LivePartitions(raw_config, maximum_output_bytes=maximum_output_bytes)
        self.config = parse(raw_config)
        self.sources = {s['source_id']: copy.deepcopy(s) for s in self.config['sources']}
        for source in self.sources.values():
            a = admission(source)
            need(source['segment'] == 1 and a['previous_epoch_last_frame_end_ticks'] is None,
                 'roster_initial_epoch_required')
        self.controllers = {pair[0]: primary for pair, primary in self.aggregate.roster.items()}
        self.source_controllers = {sid: {p[0] for p in s['object_pairs']}
                                   for sid, s in self.aggregate.sources.items()}
        self.max_events, self.max_input, self.max_output, self.max_revisions = (
            maximum_events, maximum_input_bytes, maximum_output_bytes, maximum_revisions)
        self.events = self.input_bytes = self.output_bytes = 0
        self._accounted_window_bytes = self._accounted_windows = 0
        self.revision = 1
        self.admissions = 0
        self.transition = None
        self.validators = {}
        self.ready = {}
        self.invalidated = set()
        self.failed = self.closed = False
        self.resume_boundary = self.aggregate.origin
        self.last_transition_end = self.aggregate.origin
        self.last_accepted = {}; self.input_end = None

    def _adopt_startup(self, warmup, admission_completed_ticks):
        """Adopt strictly validated cursors, never old candidate rows/buckets."""
        self._check_open()
        try:return self._adopt_startup_checked(warmup,admission_completed_ticks)
        except Exception:
            self.failed=True;raise

    def _adopt_startup_checked(self,warmup,admission_completed_ticks):
        need(self.events==0 and set(warmup.validators)==set(self.sources)and not warmup.failed,'startup_adoption_state')
        need(warmup.target==self.aggregate.target and warmup.frequency==self.aggregate.frequency
             and all(v.target==self.aggregate.target and v.frequency==self.aggregate.frequency for v in warmup.validators.values()),'startup_target_or_clock_mismatch')
        need(integer(admission_completed_ticks)and warmup.current(self.sources,admission_completed_ticks),'startup_sources_not_current')
        first=min(n['frame']['timing']['start_ticks']for n in warmup.latest.values())
        boundary=self.aggregate.origin+((admission_completed_ticks-self.aggregate.origin+self.aggregate.window-1)//self.aggregate.window)*self.aggregate.window
        need(0<=self.aggregate.origin<=first<=admission_completed_ticks<=boundary and (boundary-self.aggregate.origin)//self.aggregate.window<=MAX_WINDOWS,'startup_boundary')
        for sid,validator in warmup.validators.items():
            source=validator.sources[sid]
            for name in ('session_id','segment','profile_sha256','acquisition','objects','fields','session_epoch','context_projection','live_category','unresolved_bodies','forward_owner_projection','ammunition'):
                need(source.get(name)==self.sources[sid].get(name),'startup_source_admission_mismatch')
            need(not validator.pending and validator.windows==0,'startup_carried_values')
            self.aggregate.sources[sid].update({key:copy.deepcopy(source[key])for key in CURSORS})
            last=warmup.latest[sid];self._remember(sid,last['frame'],last['raw'])
            if validator.offset_min is not None:
                self.aggregate.offset_min=validator.offset_min if self.aggregate.offset_min is None else min(self.aggregate.offset_min,validator.offset_min)
                self.aggregate.offset_max=validator.offset_max if self.aggregate.offset_max is None else max(self.aggregate.offset_max,validator.offset_max)
        need(self.aggregate.offset_max-self.aggregate.offset_min<=self.aggregate.tolerance,'clock_anchor_disagreement')
        self.events=self.aggregate.events=warmup.events;self.input_bytes=self.aggregate.input_bytes=warmup.bytes
        need(self.events<=self.max_events and self.input_bytes<=self.max_input,'roster_input_bound')
        self.aggregate.next_window=(boundary-self.aggregate.origin)//self.aggregate.window;self.aggregate.watermark=boundary
        self.resume_boundary=self.last_transition_end=boundary
        evidence=warmup.summary()
        self.startup=dict(start_ticks=self.aggregate.origin,end_ticks=boundary,resume_boundary_ticks=boundary,**evidence)
        event=dict(schema='overwatch-decoder.live-roster-startup/1',status='unknown',revision=1,epoch_id=self.config['epoch_id'],
            next_config_sha256=self.aggregate.hash,target=copy.deepcopy(self.aggregate.target),clock_domain_id=self.aggregate.clock,
            monotonic_frequency=self.aggregate.frequency,start_ticks=self.aggregate.origin,end_ticks=boundary,resume_boundary_ticks=boundary,
            reason='startup_observations_saved_not_published_live',previous_values_carried=False,pending_observations_discarded=True,
            startup_validation=evidence,raw_context_output_enabled=any(s.get('context_projection')is not None for s in self.sources.values()),
            relations=[dict(controller_object_key=ck,body_object_key=None,primary_source_id=sid,status='unknown',reason='startup_not_published',
                authoritative_observation=None,supporting_observations=[],contributor_evidence=[])for ck,sid in sorted(self.controllers.items())],
            configuration_status='reviewed_caller_input_not_native_proof',atomic=False,privacy='private',visibility='unknown',
            public_state_eligible=False,durability_verified=False,recording_state='accepted_not_durability_verified')
        return self._output([event])

    def _check_open(self):
        need(not self.failed and not self.closed and self.input_end is None, 'roster_coordinator_closed')

    def _preflight_frame(self, source_id, raw):
        need(source_id in self.sources, 'roster_unknown_source')
        need(isinstance(raw, bytes) and 0 < len(raw) <= MAX_LINE_BYTES and raw.endswith(b'\n'),
             'roster_frame_bound')

    def _count_frame(self, source_id, raw):
        self._preflight_frame(source_id, raw)
        self.events += 1
        self.input_bytes += len(raw)
        need(self.events <= self.max_events and self.input_bytes <= self.max_input, 'roster_input_bound')

    def _frame(self, source_id, raw):
        self._count_frame(source_id, raw)
        frame = parse(raw)
        need(isinstance(frame, dict), 'roster_frame_object')
        return frame

    def _match_admission(self, source, frame):
        need(frame.get('session_epoch') == admission(source), 'roster_frame_admission_mismatch')

    def _complete(self, source_id, frame):
        rows = frame['relations']
        return (len(rows) == len(self.sources[source_id]['objects'])
                and all(row['relation_status'] == 'observed' or self.aggregate.allow_unresolved
                        and row.get('unresolved_body_validated') is True for row in rows)
                and {configured_pair(row,self.aggregate.allow_unresolved) for row in rows}
                == {configured_pair(row,self.aggregate.allow_unresolved) for row in self.sources[source_id]['objects']})

    def _one_source(self, source):
        config = copy.deepcopy(self.config)
        sid = source['source_id']
        config['sources'] = [copy.deepcopy(source)]
        config['roster'] = [dict(row, primary_source_id=sid) for row in source['objects']]
        return LivePartitions(canonical(config), maximum_output_bytes=self.max_output)

    def _cursor(self, source_id):
        source = (self.validators[source_id] if self.transition else self.aggregate).sources[source_id]
        return {key: copy.deepcopy(source[key]) for key in CURSORS}

    def _output(self, events):
        # LivePartitions already serialized/bounded each window before yielding
        # it. Reuse its cumulative byte count instead of serializing it again.
        windows = sum(event['schema'] == 'overwatch-decoder.partition-research-live/1' for event in events)
        window_bytes = self.aggregate.output_bytes - self._accounted_window_bytes
        need(windows == self.aggregate.windows - self._accounted_windows and window_bytes >= 0,
             'roster_window_accounting_mismatch')
        total = window_bytes
        for event in events:
            if event['schema'] == 'overwatch-decoder.partition-research-live/1':
                continue
            data = canonical(event) + b'\n'
            need(len(data) <= MAX_OUTPUT_LINE_BYTES, 'roster_output_bound')
            total += len(data)
        need(self.output_bytes + total <= self.max_output, 'roster_output_bound')
        self.output_bytes += total
        self._accounted_window_bytes = self.aggregate.output_bytes
        self._accounted_windows = self.aggregate.windows
        return events

    def _transition_event(self, status, end=None):
        value = dict(schema='overwatch-decoder.live-roster-transition/1', status=status, revision=self.revision,
            target=copy.deepcopy(self.aggregate.target), clock_domain_id=self.aggregate.clock,
            monotonic_frequency=self.aggregate.frequency, start_ticks=self.transition['start_ticks'],
            end_ticks=end, previous_config_sha256=self.transition['previous_config_sha256'],
            trigger=copy.deepcopy(self.transition['trigger']),
            configuration_status='reviewed_caller_input_not_native_proof',
            previous_values_carried=False, pending_observations_discarded=True,
            atomic=False, privacy='private', visibility='unknown', public_state_eligible=False,
            durability_verified=False, recording_state='accepted_not_durability_verified',
            relations=[dict(controller_object_key=key, body_object_key=None, status='unknown',
                            reason='roster_epoch_transition', authoritative_observation=None,
                            supporting_observations=[], contributor_evidence=[])
                       for key in sorted(self.controllers)])
        if end is not None:
            value['next_config_sha256'] = self.aggregate.hash
            value['source_admissions'] = {sid: dict(session_id=s['session_id'], segment=s['segment'],
                profile_sha256=s['profile_sha256'], acquisition=copy.deepcopy(s['acquisition']),
                session_epoch=copy.deepcopy(s['session_epoch'])) for sid, s in self.sources.items()}
        return value

    def _suspend(self, source_id, frame, raw, reason):
        if self.transition:
            return []
        return self._start_transition(self._frame_trigger(source_id, frame, raw, reason))

    @staticmethod
    def _frame_trigger(source_id, frame, raw, reason):
        return dict(source_id=source_id, reason=reason, session_id=frame['session_id'],
            segment=frame['segment'], event_sequence=frame['event_sequence'],
            semantic_projection_sha256=sha(raw), live_event_sha256=frame['source_artifacts']['live_event_sha256'],
            read_start_ticks=frame['timing']['start_ticks'], read_end_ticks=frame['timing']['end_ticks'])

    def _remember(self, source_id, frame, raw):
        self.last_accepted[source_id] = self._frame_trigger(source_id, frame, raw, 'last_accepted_frame')

    def _start_transition(self, trigger):
        aggregate = self.aggregate
        frontier = aggregate.origin + aggregate.next_window * aggregate.window
        # The publication frontier does not invent a native sample or read time.
        start = max(frontier, self.last_transition_end)
        self.transition = dict(start_ticks=start, previous_config_sha256=aggregate.hash,
                               trigger=copy.deepcopy(trigger))
        for sid, source in self.sources.items():
            validator = self._one_source(source)
            validator.sources[sid].update({k: copy.deepcopy(aggregate.sources[sid][k]) for k in CURSORS})
            self.validators[sid] = validator
        aggregate.pending.clear()
        aggregate.pending_bytes = 0
        self.ready.clear()
        return [self._transition_event('unknown')]

    def consume(self, source_id, raw_projection):
        return self._consume_decoded(source_id, raw_projection, None)

    def _consume_decoded(self, source_id, raw_projection, decoded_frame):
        """Internal read-only, same-line parse sharing; not external admission.

        The caller must just have parsed raw_projection with the strict parser.
        Passing any altered, cached or separately supplied dictionary is invalid
        use. Public consume always parses its own bounded byte input.
        """
        self._check_open()
        try:
            need(decoded_frame is None or isinstance(decoded_frame,dict),'invalid_decoded_projection')
            self._count_frame(source_id, raw_projection)
            validator = self.validators[source_id] if self.transition else self.aggregate
            frame = validator._consume_decoded(source_id, raw_projection, decoded_frame,
                                      retain=self.transition is None, context=True, minimum_start_ticks=self.resume_boundary)
            self._match_admission(self.sources[source_id], frame)
            self._remember(source_id, frame, raw_projection)
            events = []
            complete = self._complete(source_id, frame)
            if not complete:
                events += self._suspend(source_id, frame, raw_projection, 'source_relations_unknown')
                self.ready.pop(source_id, None)
            elif self.transition:
                if source_id not in self.invalidated:
                    self.ready[source_id] = frame['timing']['end_ticks']
            if self.transition:
                events += self._resume_if_ready()
            else:
                events += self._automatic()
            return self._output(events)
        except Exception:
            self.failed = True
            raise

    def admit(self, source_id, raw_source_config, raw_first_projection):
        """Validate a fresh source epoch and its first actual frame before use."""
        self._check_open()
        try:
            frame = self._frame(source_id, raw_first_projection)
            need(isinstance(raw_source_config, bytes) and 0 < len(raw_source_config) <= 262144,
                 'roster_source_config_bound')
            self.input_bytes += len(raw_source_config)
            need(self.input_bytes <= self.max_input, 'roster_input_bound')
            source = parse(raw_source_config)
            old = self.sources[source_id]
            before, after = admission(old), admission(source)
            cursor = self._cursor(source_id)
            need(source.get('source_id') == source_id and source.get('session_id') == old['session_id']
                 and source.get('segment') == old['segment'] + 1
                 and source.get('acquisition', {}).get('recipe_sha256') == old['acquisition']['recipe_sha256'],
                 'roster_source_identity_changed')
            need(after['acquisition'] > before['acquisition']
                 and after['session_start_sha256'] == before['session_start_sha256']
                 and after['acquisition_end_sha256'] != before['acquisition_end_sha256']
                 and after['segment_start_sha256'] != before['segment_start_sha256']
                 and after['previous_epoch_last_frame_end_ticks'] == cursor['previous_end'],
                 'roster_epoch_order')
            need({configured_pair(row,self.aggregate.allow_unresolved)[0] for row in source['objects']} == self.source_controllers[source_id],
                 'roster_controller_replacement_requires_bootstrap')
            need(source['acquisition']['manifest_sha256'] != old['acquisition']['manifest_sha256']
                 and source['acquisition']['evidence_sha256'] != old['acquisition']['evidence_sha256'],
                 'roster_fresh_acquisition_required')
            self._match_admission(source, frame)
            need(cursor['event_sequence'] is None or frame['event_sequence'] > cursor['event_sequence'],
                 'roster_event_order')
            need(cursor['previous_end'] is None or frame['timing']['start_ticks'] >= cursor['previous_end'],
                 'roster_epoch_time_order')
            self.admissions += 1
            need(self.admissions <= self.max_revisions * len(self.sources), 'roster_admission_bound')
            validator = self._one_source(source)
            frame=validator.consume(source_id, raw_first_projection, retain=False,context=True)
            self._remember(source_id, frame, raw_first_projection)
            events = self._suspend(source_id, frame, raw_first_projection, 'accepted_source_epoch_changed')
            self.sources[source_id] = copy.deepcopy(source)
            self.validators[source_id] = validator
            self.invalidated.discard(source_id)
            if self._complete(source_id, frame):
                self.ready[source_id] = frame['timing']['end_ticks']
            else:
                self.ready.pop(source_id, None)
            events += self._resume_if_ready()
            return self._output(events)
        except Exception:
            self.failed = True
            raise

    def invalidate(self, source_id, raw_terminal_projection):
        """Explicit upstream invalidation, carried by its accepted unknown frame.

        The terminal frame is consumed here exactly once. The caller can use
        ordinary consume instead if it cannot yet distinguish a terminal gap;
        admit will still require fresh epoch evidence before changed values.
        """
        self._check_open()
        try:
            self._preflight_frame(source_id, raw_terminal_projection)
            frame = parse(raw_terminal_projection)
            need(frame.get('relations') and all(row.get('relation_status') == 'unknown'
                 for row in frame['relations']), 'roster_invalidation_requires_unknown_frame')
            self.invalidated.add(source_id)
            return self.consume(source_id, raw_terminal_projection)
        except Exception:
            self.failed = True
            raise

    def _resume_if_ready(self):
        if set(self.ready) != set(self.sources) or self.invalidated:
            return []
        bodies = {}
        for source in self.sources.values():
            for row in source['objects']:
                controller, body = configured_pair(row,self.aggregate.allow_unresolved)
                if controller in bodies and bodies[controller] != body:
                    return []  # Staggered copies of self are not a new roster.
                bodies[controller] = body
        need(set(bodies) == set(self.controllers), 'roster_controller_set_changed')
        present=[body for body in bodies.values()if body is not None]
        need(len(set(present)) == len(present), 'roster_ambiguous_body')
        need(self.revision < self.max_revisions, 'roster_revision_bound')
        config = copy.deepcopy(self.config)
        config['epoch_id'] = 'roster-revision-' + str(self.revision + 1)
        config['sources'] = [copy.deepcopy(self.sources[sid]) for sid in sorted(self.sources)]
        config['roster'] = [dict(controller_object_key=c, body_object_key=bodies[c],
                                 primary_source_id=self.controllers[c]) for c in sorted(bodies)]
        candidate = LivePartitions(canonical(config), maximum_output_bytes=self.max_output)
        old = self.aggregate
        latest = max(self.validators[sid].sources[sid]['previous_end'] for sid in self.sources)
        boundary = max(self.transition['start_ticks'],
                       old.origin + ((latest - old.origin + old.window - 1) // old.window) * old.window)
        candidate.next_window = (boundary - old.origin) // old.window
        need(candidate.next_window <= MAX_WINDOWS, 'window_count_limit')
        candidate.watermark = boundary
        # Reconstruct only ordering state. No projected row, bucket, or old value
        # survives. Clock offsets remain cumulative across all revisions.
        for sid in self.sources:
            candidate.sources[sid].update({key: copy.deepcopy(self.validators[sid].sources[sid][key]) for key in CURSORS})
        for key in ACCOUNTING:
            setattr(candidate, key, copy.deepcopy(getattr(old, key)))
        candidate.offset_min, candidate.offset_max = old.offset_min, old.offset_max
        for validator in self.validators.values():
            if validator.offset_min is not None:
                lo = validator.offset_min if candidate.offset_min is None else min(candidate.offset_min, validator.offset_min)
                hi = validator.offset_max if candidate.offset_max is None else max(candidate.offset_max, validator.offset_max)
                need(hi - lo <= candidate.tolerance, 'clock_anchor_disagreement')
                candidate.offset_min, candidate.offset_max = lo, hi
        self.aggregate, self.config = candidate, config
        self.revision += 1
        self.resume_boundary = self.last_transition_end = boundary
        event = self._transition_event('resumed_without_carried_values', boundary)
        self.transition = None
        self.validators.clear()
        self.ready.clear()
        return [event]

    def _automatic(self):
        watermark = self.aggregate.automatic_watermark
        if watermark is None or watermark < self.aggregate.watermark:
            return []
        return list(self.aggregate.advance(watermark))

    def advance(self, watermark_ticks):
        self._check_open()
        try:
            need(integer(watermark_ticks) and watermark_ticks >= self.aggregate.watermark, 'watermark_order')
            if self.transition:
                # An open unknown interval is explicit; no pending source sample
                # or synthetic value is filled into it, regardless of duration.
                return []
            return self._output(list(self.aggregate.advance(watermark_ticks)))
        except Exception:
            self.failed = True
            raise

    def status(self):
        """Detached metadata snapshot; never closes, flushes, or exposes values."""
        result = dict(schema='overwatch-decoder.live-roster-status/1', revision=self.revision,
            config_sha256=self.aggregate.hash, epoch_id=self.aggregate.epoch,
            next_window_index=self.aggregate.next_window, resume_boundary_ticks=self.resume_boundary,
            finalized_watermark_ticks=self.aggregate.watermark, closed=self.closed,
            source_admissions=self.admissions, input_frames=self.events, input_bytes=self.input_bytes,
            output_bytes=self.output_bytes, failed=self.failed, transition_open=self.transition is not None,
            transition_start_ticks=self.transition['start_ticks'] if self.transition else None,
            pending_windows=len(self.aggregate.pending), pending_bytes=self.aggregate.pending_bytes,
            source_cursors={sid: self._cursor(sid) for sid in self.sources},
            atomic=False, public_state_eligible=False, durability_verified=False,
            recording_state='accepted_not_durability_verified', previous_values_carried=False)
        if self.input_end is not None: result['input_end'] = copy.deepcopy(self.input_end)
        return result

    def end_input(self, stop_ticks, source_result_sha256):
        """Invalidate runtime output after verified producer EOF; never flush.

        Completion hashes are caller-verified result artifacts, not native read
        evidence. Ordinary close() retains its existing offline semantics.
        """
        self._check_open()
        try:
            need(set(self.last_accepted) == set(self.sources), 'roster_end_before_all_sources')
            need(integer(stop_ticks) and stop_ticks >= max(x['read_end_ticks'] for x in self.last_accepted.values()),
                 'roster_end_before_accepted_read')
            need(isinstance(source_result_sha256, dict) and set(source_result_sha256) == set(self.sources),
                 'roster_end_source_results')
            for value in source_result_sha256.values(): digest(value)
            ending = dict(reason='finite_sources_completed', evidence_kind='caller_verified_producer_eof_not_native_sample',
                stop_ticks=stop_ticks, discarded_pending_windows=len(self.aggregate.pending),
                discarded_pending_bytes=self.aggregate.pending_bytes,
                source_result_sha256=copy.deepcopy(source_result_sha256))
            events = []
            if self.transition is None:
                trigger = copy.deepcopy(max(self.last_accepted.values(), key=lambda x:x['read_end_ticks']))
                trigger['reason'] = 'finite_sources_completed'
                events = self._start_transition(trigger)
                events[0]['input_end'] = copy.deepcopy(ending)
            self.aggregate.pending.clear(); self.aggregate.pending_bytes = 0
            self.ready.clear(); self.input_end = ending
            return self._output(events)
        except Exception:
            self.failed = True
            raise

    def close(self):
        self.closed = True
        result = self.status()
        result['schema'] = 'overwatch-decoder.live-roster-result/1'
        return result
