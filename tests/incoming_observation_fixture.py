"""Invented incoming transport examples; no captured game values or proof."""
def incoming_fixture(status='observed', *, untimed=False):
    def interval(start, end): return dict(start_ticks=start, end_ticks=end)
    def point(start, sequence):
        return dict(roster=dict(raw_sha256='b'*64, session_id='fixture-roster', segment=1, sequence=sequence,
            read_interval=interval(start, start+10), evidence=dict(native_event_sha256='c'*64,
            projection_sha256='e'*64, profile_sha256='f'*64, contract_sha256='a'*64)),
            position=dict(status='observed', value=[1, 2, 3], read_interval=interval(start+2, start+3),
            evidence=dict(projection_sha256='e'*64, validation_status='synthetic_only')))
    row=dict(schema='overwatch-decoder.private.incoming-source-observation/1', kind='incoming_source_observation',
        observation_id='a'*64, status=status, reason=None if status=='observed' else 'context_inactive',
        source_actor=dict(identity=dict(entity_id='body:fixture-source', controller_id='controller:fixture-source'),
            hero=dict(status='observed', value=dict(label='FixtureSource')), relation=dict(status='observed', value='enemy'),
            position_observations=[point(80, 1), point(120, 2)]),
        recipient_actor=dict(identity=dict(entity_id='body:fixture-recipient', controller_id='controller:fixture-recipient'),
            hero=dict(value='FixtureRecipient', validation_status='synthetic_only')),
        read_interval=interval(100, 110), source_clock=dict(clock_id='windows_qpc', frequency=1000),
        semantic_review_sha256='d'*64, semantics='repeated_active_source_observation', unique_hit=False,
        exact_damage=None, impact_timestamp=None, numeric_team=None, visibility='unknown', atomic=False,
        continuity='unknown', public_state_eligible=False, attribution_validation='synthetic_only',
        provenance=dict(schema='overwatch-decoder.source-pair-join/1', status='resolved' if status=='observed' else 'unknown', observation_id='a'*64,
            scope=dict(clock_id='windows_qpc', frequency=1000, target=dict(executable_sha256='f'*64)),
            context=dict(raw_sha256='c'*64, session_id='fixture-context', segment=1, sequence=3,
                read_interval=interval(100, 110), evidence=dict(native_event_sha256='b'*64, projection_sha256='e'*64,
                recording_frame_canonical_sha256='a'*64, contract_sha256='c'*64, review_sha256='d'*64))),
        source_sampling_clock=dict(utc_origin='2020-01-01T00:00:00+00:00', utc_origin_before_ticks=0,
            monotonic_origin_ticks=1, monotonic_frequency=1000, session_start_sha256='a'*64,
            meaning='sampler_UTC_origin_mapping_not_impact_time'))
    if status=='unknown': row.update(source_actor=None, recipient_actor=None, source_clock=None)
    if untimed:
        row.update(observation_id=None, read_interval=None, source_sampling_clock=None,
            reason='buffer_overflow', provenance=dict(status='unknown', reason='buffer_overflow'))
    return row
