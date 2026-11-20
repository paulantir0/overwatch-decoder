"""Transport validation for explicitly admitted ammunition projections.

Admission is derived from an already verified native projector, never from a
candidate frame. This validates provenance, bindings, qualifications and exact
row joins; it does not execute native scalar nodes or re-verify process reads.
"""
import copy
import re


class InvalidAmmunitionProjection(ValueError):
    pass


def need(value, reason):
    if not value:
        raise InvalidAmmunitionProjection('ammunition_' + reason)


def digest(value):
    need(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'digest')


def source_admission(projector, *, live_adapter=None):
    """Declare an already constructed GuardedAmmunitionCandidates instance.

    The optional LiveRelations instance must have independently verified its
    native admission artifacts. No sampled frame is an admission authority.
    """
    from ammunition_candidates import GuardedAmmunitionCandidates
    need(isinstance(projector, GuardedAmmunitionCandidates), 'projector_required')
    p = projector
    result = dict(schema='overwatch-decoder.ammunition-source-admission/1', target=p.relations.target,
        profile_sha256=p.relations.hash, contract_sha256=p.contract_sha256,
        native_review_sha256=p.native_review_sha256,
        acquisition=dict(manifest_sha256=p.acquisition_manifest_sha256, **p.source), bindings=[])
    for binding in p.bindings:
        names = list(binding['fields'].values()) + list((binding.get('tick_fields') or {}).values())
        callback = binding.get('callback')
        names += list((callback or {}).get('fields', {}).values())
        if p.semantic is not None:
            names += list(p.semantic['hero']['fields'].values())
        result['bindings'].append(dict(controller_object_key=binding['controller'], body_object_key=binding['body'],
            controller_prefix=binding['prefix'], maximum=binding['maximum'], hud_review_sha256=binding['hud_review_sha256'],
            storage_fields=binding['fields'], tick_fields=binding.get('tick_fields'),
            callback_binding_sha256=None if callback is None else callback['binding_sha256'],
            callback_fields=None if callback is None else callback['fields'],
            fields={n:dict(type=p.relations.fields[n]['type'], guard_ids=p.relations.guard_ids[n]) for n in names}))
    if p.semantic is not None:
        result.update(semantic_review_sha256=p.semantic['review_sha256'],
            participant_review_sha256=p.semantic['participant_sha256'],
            controlled_participant_frame_scope=p.semantic['interval'])
    if live_adapter is not None:
        need(live_adapter.ammunition.contract_sha256 == p.contract_sha256
             and live_adapter.ammunition.relations.hash == p.relations.hash, 'live_projector_mismatch')
        result['live'] = dict(admission=live_adapter.ammunition_admission,
                             admission_sha256=live_adapter.ammunition_admission_sha256)
    validate_source(dict(ammunition=result, profile_sha256=p.relations.hash,
        acquisition=result['acquisition'], objects=result['bindings']))
    return copy.deepcopy(result)


def validate_source(source):
    a = source.get('ammunition')
    if a is None:
        return
    need(isinstance(a, dict) and a.get('schema') == 'overwatch-decoder.ammunition-source-admission/1', 'admission_schema')
    for key in ('profile_sha256', 'contract_sha256', 'native_review_sha256'):
        digest(a.get(key))
    need(a['profile_sha256'] == source.get('profile_sha256'), 'profile_admission')
    need(isinstance(a.get('target'), dict), 'target_admission')
    digest(a['target'].get('executable_sha256'))
    need(isinstance(a.get('acquisition'), dict) and set(a['acquisition']) == {'manifest_sha256','recipe_sha256','evidence_sha256'}, 'source_pins')
    for value in a['acquisition'].values(): digest(value)
    if 'acquisition' in source:
        need(all(source['acquisition'].get(k) == v for k,v in a['acquisition'].items()), 'acquisition_admission')
    if 'acquisition_manifest_sha256' in source:
        need(source['acquisition_manifest_sha256'] == a['acquisition']['manifest_sha256'], 'acquisition_admission')
    bindings = a.get('bindings')
    need(isinstance(bindings, list) and 1 <= len(bindings) <= 32, 'binding_count')
    seen = set()
    pairs = {(r['controller_object_key'],r['body_object_key']) for r in source['objects']}
    declarations = {f['name']:f['type'] for f in source.get('fields', [])}
    for b in bindings:
        pair = b.get('controller_object_key'), b.get('body_object_key')
        need(pair in pairs and pair not in seen and pair[1] is not None, 'binding_identity')
        seen.add(pair)
        need(type(b.get('maximum')) is int and 0 < b['maximum'] < 2**31, 'range')
        need(isinstance(b.get('controller_prefix'), str) and len(b['controller_prefix']) <= 128, 'prefix')
        fields = b.get('fields')
        need(isinstance(fields, dict) and 7 <= len(fields) <= 160, 'declarations')
        for name, spec in fields.items():
            ids = spec.get('guard_ids')
            need(isinstance(name,str) and 1 <= len(name) <= 256 and spec.get('type') in ('i32','u8')
                 and isinstance(ids,list) and 1 <= len(ids) <= 256 and len(set(ids)) == len(ids)
                 and all(type(i) is int and 0 <= i < 256 for i in ids), 'field_guards')
            need(not declarations or declarations.get(name) == spec['type'], 'field_declaration')
        need(isinstance(b.get('storage_fields'),dict) and set(b['storage_fields']) == {
            'expression_count','base_bits','base_type','cached_bits','cached_type','cached_tick','flags'}
            and set(b['storage_fields'].values()) <= set(fields), 'storage_fields')
        for key in ('hud_review_sha256','callback_binding_sha256'):
            if b.get(key) is not None: digest(b[key])
        if b.get('callback_binding_sha256') is not None:
            need(isinstance(b.get('callback_fields'),dict) and set(b['callback_fields'].values()) <= set(fields), 'callback_fields')
        need(b.get('hud_review_sha256') is not None or a.get('semantic_review_sha256') is not None, 'review_required')
    if a.get('semantic_review_sha256') is not None:
        digest(a['semantic_review_sha256']); digest(a.get('participant_review_sha256'))
    live = a.get('live')
    if live is not None:
        digest(live.get('admission_sha256')); d=live.get('admission',{})
        need(d.get('schema') == 'overwatch-decoder.live-ammunition-admission/1' and d.get('target') == a['target']
             and d.get('profile_sha256') == a['profile_sha256'] and d.get('source_acquisition') == a['acquisition']
             and d.get('ammunition_contract_sha256') == a['contract_sha256'], 'live_admission')
        for key in ('session_start_sha256','acquisition_end_sha256','segment_start_sha256'): digest(d.get(key))
        need(re.fullmatch('[0-9a-f]{32}', d.get('session_id','')) and type(d.get('segment')) is int and d['segment'] > 0, 'live_epoch')
        if 'session_id' in source:
            need(source['session_id'] == d['session_id'] and source['segment'] == d['segment'], 'live_epoch')
    else:
        need('session_id' not in source, 'live_admission_required')


def _evidence(items, b, timing):
    need(isinstance(items,list) and len(items) <= 128, 'evidence_list')
    seen=set()
    for item in items:
        name=item.get('field'); spec=b['fields'].get(name)
        need(spec is not None and name not in seen and item.get('guard_ids') == spec['guard_ids'], 'evidence_binding')
        seen.add(name)
        n=item.get('value'); lo,hi=(-2**31,2**31-1) if spec['type']=='i32' else (0,255)
        need(type(n) is int and lo <= n <= hi, 'evidence_value')
        x,y=item.get('read_start_ticks'),item.get('read_end_ticks')
        need(type(x) is int and type(y) is int and timing['start_ticks'] <= x <= y <= timing['end_ticks'], 'evidence_time')
    return {i['field']:i['value'] for i in items}


def validate_frame(frame, source):
    a=source.get('ammunition'); projection=frame.get('ammunition_projection')
    rows=frame.get('relations',[])
    if a is None:
        need(projection is None and not any(k in frame for k in ('ammunition_live_admission','live_ammunition_output_enabled','ammunition_admission_sha256','ammunition_contract_sha256'))
             and not any(any(k in r for k in ('ammunition_candidate','ammunition_evidence_ref','ammunition_reason')) for r in rows), 'not_admitted')
        return None
    need(isinstance(projection,dict) and projection.get('schema') == 'overwatch-decoder.guarded-ammunition-candidates/1', 'projection_required')
    need(frame['target'] == a['target'] and frame['profile_sha256'] == a['profile_sha256']
         and projection.get('target') == a['target'] and projection.get('profile_sha256') == a['profile_sha256']
         and projection.get('timing') == frame['timing'], 'frame_scope')
    for k in ('contract_sha256','native_review_sha256'):
        need(projection.get(k) == a[k], 'projection_pin')
    acq=frame['source_artifacts']['acquisition']
    need(all(acq.get(k)==v for k,v in a['acquisition'].items()) and projection.get('source_evidence') == dict(
        recipe_sha256=a['acquisition']['recipe_sha256'],evidence_sha256=a['acquisition']['evidence_sha256'],
        acquisition_manifest_sha256=a['acquisition']['manifest_sha256']), 'projection_source')
    need(projection.get('source')=='process_memory' and projection.get('visibility')=='unknown'
         and all(projection.get(k) is False for k in ('atomic','durability_verified','continuity_across_gaps','public_state_eligible')), 'qualification')
    for k in ('semantic_review_sha256','participant_review_sha256','controlled_participant_frame_scope'):
        need(projection.get(k)==a.get(k), 'semantic_scope')
    live=frame.get('ammunition_live_admission')
    if a.get('live') is not None:
        d=a['live']['admission']
        need(isinstance(live,dict) and live.get('schema')=='overwatch-decoder.live-ammunition-frame-admission/1'
             and live.get('session_id')==d['session_id']==frame.get('session_id')
             and live.get('segment')==d['segment']==frame.get('segment')
             and live.get('event_sequence')==frame.get('event_sequence')
             and live.get('profile_sha256')==a['profile_sha256'] and live.get('source_acquisition')==a['acquisition']
             and live.get('contract_sha256')==a['contract_sha256'] and frame.get('ammunition_contract_sha256')==a['contract_sha256']
             and live.get('admission_sha256')==a['live']['admission_sha256']==frame.get('ammunition_admission_sha256')
             and frame.get('live_ammunition_output_enabled') is True, 'live_frame_scope')
        for name in ('session_start','acquisition_end','segment_start'):
            need(live.get(name+'_artifact_sha256')==d[name+'_sha256'], 'live_artifact_pin')
            digest(live.get(name+'_event_sha256'))
            if frame.get('session_epoch') is not None:
                need(live[name+'_event_sha256']==frame['session_epoch'].get(name+'_sha256'), 'native_epoch_pin')
        for k in ('live_event_sha256','recording_frame_sha256'): digest(live.get(k))
        need(live.get('live_event_sha256')==frame['source_artifacts'].get('live_event_sha256')
             and live.get('previous_values_carried') is False and live.get('durability_verified') is False
             and live.get('recording_state')=='accepted_not_durability_verified', 'live_event_pin')
    else:
        need(live is None and not frame.get('live_ammunition_output_enabled'), 'unexpected_live_admission')
    projected=projection.get('rows')
    need(isinstance(projected,list) and len(projected)==len(a['bindings']), 'row_count')
    gap=bool(frame.get('gap_before',{}).get('skipped_slots'))
    for row,b in zip(projected,a['bindings']):
        need(isinstance(row,dict) and row.get('status') in ('observed','unknown')
             and row.get('visibility')=='unknown' and row.get('public_state_eligible') is False
             and row.get('is_firing') is None and row.get('reloading') is None
             and row.get('hud_review_sha256')==b['hud_review_sha256'], 'row_qualification')
        values=_evidence(row.get('evidence'),b,frame['timing'])
        if 'semantic_evidence' in row: _evidence(row['semantic_evidence'],b,frame['timing'])
        if a.get('semantic_review_sha256') is not None:
            need(row.get('semantic_review_sha256')==a['semantic_review_sha256']
                 and row.get('participant_review_sha256')==a['participant_review_sha256'], 'row_review_pin')
        candidate=row.get('ammunition_candidate'); callback=row.get('callback_reconstruction_candidate')
        if row['status']=='unknown':
            need(candidate is None and callback is None and row.get('storage_candidate') is None
                 and isinstance(row.get('reason'),str), 'unknown_has_value')
        else:
            if a.get('controlled_participant_frame_scope') is not None:
                scope=a['controlled_participant_frame_scope']; t=frame['timing']
                need(projection.get('semantic_validation')=='empirical_controlled_participant_template'
                     and t['monotonic_frequency']==scope['monotonic_frequency']
                     and scope['start_ticks']<=t['start_ticks']<=t['end_ticks']<=scope['end_ticks'], 'participant_interval')
            need(not gap and row.get('reason') is None
                 and all(row.get(k)==b[k] for k in ('controller_object_key','body_object_key')),
                 'observed_identity_or_gap')
            storage=row.get('storage_candidate')
            need(isinstance(storage,dict) and set(storage)==set(b['storage_fields'])
                 and all(values.get(n)==storage[k] for k,n in b['storage_fields'].items()), 'storage_evidence')
            need(isinstance(candidate,dict) and set(candidate)=={'value','numeric_type','selection','freshness','native_cache_condition','engine_evaluation_validated'}
                 and type(candidate.get('value')) is int and 0<=candidate['value']<=b['maximum']
                 and candidate.get('numeric_type') in ('i32','f32') and candidate.get('engine_evaluation_validated') is False,
                 'candidate_qualification')
            base=storage['expression_count']==0
            need(storage['expression_count']>=0 and candidate.get('selection')==('base' if base else 'cached')
                 and candidate.get('freshness')==('base_storage_read' if base else 'sampled_cache_not_recomputed')
                 and candidate.get('native_cache_condition') in (('not_selected',) if base else
                   ('unknown_without_tick_bindings','native_recompute_required','native_reuse_condition_observed')), 'cache_qualification')
        if b.get('callback_binding_sha256') is None:
            need(not any(k in row for k in ('callback_reconstruction_candidate','callback_reconstruction_evidence','callback_reconstruction_reason')), 'callback_not_admitted')
        else:
            vals=_evidence(row.get('callback_reconstruction_evidence'),b,frame['timing'])
            if callback is not None:
                need(isinstance(callback,dict) and set(callback)=={'value','numeric_type','selection','freshness',
                     'sampled_cache_value','sampled_cache_equal','elapsed_i64','integrated_index_i32','binding_sha256',
                     'rounding_assumption','split_qwords','split_qword_consistency_validated','clock_reads_atomic',
                     'engine_clock_read_policy','sampled_clock_read_count','engine_evaluation_validated'}
                     and row['status']=='observed' and not gap and row.get('callback_reconstruction_reason') is None
                     and set(b['callback_fields'].values()) <= set(vals)
                     and callback.get('binding_sha256')==b['callback_binding_sha256']
                     and callback.get('selection')=='active_descriptor_callback'
                     and callback.get('freshness')=='sequential_operand_reconstruction'
                     and callback.get('engine_evaluation_validated') is False
                     and callback.get('clock_reads_atomic') is False
                     and callback.get('split_qword_consistency_validated') is False
                     and callback.get('sampled_cache_value')==candidate['value']
                     and type(callback.get('value')) is int and 0<=callback['value']<=b['maximum']
                     and callback.get('numeric_type')=='i32'
                     and callback.get('split_qwords') is True
                     and callback.get('rounding_assumption')=='binary32_nearest_even_no_flush_to_zero'
                     and callback.get('engine_clock_read_policy')=='first_compare_then_optional_second_read'
                     and type(callback.get('sampled_clock_read_count')) is int and callback['sampled_clock_read_count']==1
                     and type(callback.get('sampled_cache_equal')) is bool
                     and callback['sampled_cache_equal']==(callback['value']==candidate['value']), 'callback_qualification')
    for row in rows: validate_join(row,projection)
    return projection


def validate_join(row, projection):
    for key in ('ammunition_candidate','ammunition_evidence_ref','ammunition_reason'):
        need(key in row, 'missing_relation_join')
    matches=[(i,r) for i,r in enumerate(projection['rows']) if row.get('relation_status')=='observed'
             and all(r.get(k)==row.get(k) for k in ('controller_object_key','body_object_key'))]
    need(len(matches)<=1, 'ambiguous_join')
    if matches:
        i,r=matches[0]
        need(row['ammunition_evidence_ref']=='/ammunition_projection/rows/'+str(i)
             and row['ammunition_candidate']==r['ammunition_candidate'] and row['ammunition_reason']==r['reason'], 'relation_join')
    else:
        need(row['ammunition_candidate'] is None and row['ammunition_evidence_ref'] is None, 'unbound_relation_value')


LIVE_KEYS=('live_ammunition_output_enabled','ammunition_contract_sha256','ammunition_admission_sha256',
           'ammunition_live_admission','session_id','segment','event_sequence','session_epoch')


def retain(frame, raw_sha256):
    return dict(projection=copy.deepcopy(frame['ammunition_projection']),
        live={k:copy.deepcopy(frame[k]) for k in LIVE_KEYS if k in frame},
        semantic_frame_sha256=raw_sha256, source_gap=copy.deepcopy(frame['gap_before']))


def attach_window(result, manifest, usable):
    admissions={sid:copy.deepcopy(s['ammunition']) for sid,s in manifest.sources.items() if s.get('ammunition') is not None}
    if admissions:
        result['ammunition_sources']=admissions
        result['ammunition_projections']={sid:dict(f['ammunition'], source_id=sid,source_timing=f['timing'],
            source_artifacts=f['artifacts']) for sid,f in usable.items() if 'ammunition' in f}


def validate_window(value):
    admissions=value.get('ammunition_sources'); entries=value.get('ammunition_projections')
    if admissions is None:
        need(entries is None,'unadmitted_window'); return {}
    need(isinstance(admissions,dict) and 1<=len(admissions)<=16 and isinstance(entries,dict)
         and set(entries)<=set(admissions)
         and all(isinstance(sid,str) and re.fullmatch('[A-Za-z0-9_-]{1,64}',sid) for sid in admissions), 'window_sources')
    for sid,a in admissions.items():
        validate_source(dict(ammunition=a,profile_sha256=a['profile_sha256'],objects=a['bindings']))
        need(a['target']==value['target'], 'window_target')
    for sid,e in entries.items():
        need(e.get('source_id')==sid and sid not in value['unavailable_sources'], 'window_unavailable')
        digest(e.get('semantic_frame_sha256'))
        timing=e['source_timing']
        need(value['window_start_ticks']<=timing['end_ticks']<value['window_end_ticks']
             and value['window_end_ticks']-timing['start_ticks']<=value['maximum_skew_ticks']
             and timing['monotonic_frequency']==value['monotonic_frequency']
             and value['observed_read_start_ticks'] is not None
             and value['observed_read_start_ticks']<=timing['start_ticks']<=timing['end_ticks']<=value['observed_read_end_ticks']
             and not e['source_gap'].get('skipped_slots'), 'window_time')
        validate_frame(dict(target=value['target'],profile_sha256=e['source_artifacts']['profile_sha256'],
            source_artifacts=e['source_artifacts'],timing=timing,gap_before=e['source_gap'],
            ammunition_projection=e['projection'],relations=[],**e['live']), dict(ammunition=admissions[sid]))
    return entries


def validate_observation(node, entries, admissions, *, live=True):
    sid=node['source_id']; e=entries.get(sid)
    if sid not in admissions:
        need(not any(k in node.get('relation',{}) for k in ('ammunition_candidate','ammunition_evidence_ref','ammunition_reason')), 'observation_not_admitted')
        return
    need(e is not None and node['source_timing']==e['source_timing'] and node['source_artifacts']==e['source_artifacts'], 'observation_scope')
    if live: need(node['semantic_projection_sha256']==e['semantic_frame_sha256'], 'observation_line_hash')
    if 'relation' in node: validate_join(node['relation'], e['projection'])


def compact_candidate(row, entry, reason=None, base=''):
    result={k:dict(status='unknown',value=None,reason=reason,read_span_ticks=None,evidence_ref=None)
            for k in ('ammunition_candidate','ammunition_callback_candidate')}
    if row is None or entry is None: return result
    validate_join(row,entry['projection'])
    ref=row['ammunition_evidence_ref']
    if ref is None: return result
    index=int(ref.rsplit('/',1)[-1]); r=entry['projection']['rows'][index]
    for output,key,evidence,why in (
        ('ammunition_candidate','ammunition_candidate','evidence','reason'),
        ('ammunition_callback_candidate','callback_reconstruction_candidate','callback_reconstruction_evidence','callback_reconstruction_reason')):
        value=r.get(key); reads=r.get(evidence,[]) + r.get('semantic_evidence',[])
        if output=='ammunition_callback_candidate': reads=reads+r['evidence']
        result[output]=dict(status='candidate' if value is not None else 'unknown',value=copy.deepcopy(value),reason=r.get(why),
            read_span_ticks=None if value is None else [min(i['read_start_ticks'] for i in reads),max(i['read_end_ticks'] for i in reads)],
            evidence_ref=base+'/projection/rows/'+str(index) if value is not None else None)
    return result
