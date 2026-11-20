"""Pure same-frame checks for optional neutral context/category/group projections.

Configured pins are caller admission, not independent native-code proof. The
upstream LiveRelations constructor verifies contracts and actual metadata. This
module never treats a context-selected controller as self, playable, or allied.
"""
import copy
import re

PIN_KEYS = ('configured_admission_sha256', 'contract_sha256', 'category_native_review_sha256',
            'context_native_review_sha256', 'two_group_review_sha256', 'context_scope_review_sha256',
            'frame_scope', 'session_start_sha256', 'segment_start_sha256')
CONTRACT_KEYS = ('raw_category_contract_sha256', 'context_controller_contract_sha256', 'context_group_contract_sha256')
TIME_KEYS = ('sequence', 'start_ticks', 'end_ticks', 'monotonic_frequency')
LEGACY = ('raw_category_candidate', 'team_candidate', 'relative_allegiance_candidate', 'category_evidence')


def need(ok, why):
    if not ok: raise ValueError(why)


def digest(value):
    need(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'context_digest')


def key(value, role):
    need(value is None or isinstance(value, str) and re.fullmatch(role+':[0-9a-f]{64}', value), 'context_object_key')


def private(node):
    need(isinstance(node, dict) and node.get('public_state_eligible') is False
         and node.get('visibility') == 'unknown' and node.get('atomic') is False, 'context_qualification')


def validate_context_source(source):
    """Validate source['context_projection'] pin structure; return it or None."""
    pins = source.get('context_projection')
    if pins is None: return None
    if isinstance(pins, dict) and pins.get('schema') == 'overwatch-decoder.finite-context-source/1':
        names = {'schema','contract_sha256','category_native_review_sha256','context_native_review_sha256',
                 'two_group_review_sha256','context_scope_review_sha256','frame_scope','source_artifacts'}
        need(set(pins)==names, 'finite_context_source_pins')
        contracts=pins['contract_sha256']
        need(isinstance(contracts,dict)and set(contracts)==set(CONTRACT_KEYS)
             and contracts[CONTRACT_KEYS[2]]is None, 'finite_context_contract_pins')
        for name in CONTRACT_KEYS[:2]:digest(contracts[name])
        for name in ('category_native_review_sha256','context_native_review_sha256'):digest(pins[name])
        need(all(pins[n]is None for n in ('two_group_review_sha256','context_scope_review_sha256','frame_scope')), 'unexpected_group_scope')
        artifacts=pins['source_artifacts'];need(isinstance(artifacts,dict),'finite_context_source_artifacts')
        for name in ('profile_sha256','manifest_sha256','samples_prefix_sha256','index_prefix_sha256'):digest(artifacts.get(name))
        acquisition=artifacts.get('acquisition');need(isinstance(acquisition,dict),'finite_context_source_acquisition')
        for name in ('manifest_sha256','recipe_sha256','evidence_sha256'):digest(acquisition.get(name))
        return pins
    need(isinstance(pins, dict) and set(pins) == set(PIN_KEYS), 'context_source_pins')
    for name in ('configured_admission_sha256', 'category_native_review_sha256', 'context_native_review_sha256',
                 'session_start_sha256', 'segment_start_sha256'): digest(pins[name])
    contracts = pins['contract_sha256']
    need(isinstance(contracts, dict) and set(contracts) == set(CONTRACT_KEYS), 'context_contract_pins')
    for name in CONTRACT_KEYS[:2]: digest(contracts[name])
    group = contracts[CONTRACT_KEYS[2]]
    if group is None:
        need(all(pins[n] is None for n in ('two_group_review_sha256', 'context_scope_review_sha256', 'frame_scope')), 'unexpected_group_scope')
    else:
        digest(group); digest(pins['two_group_review_sha256']); digest(pins['context_scope_review_sha256'])
        scope = pins['frame_scope']
        need(isinstance(scope, dict) and set(scope) == {'first_sequence','last_sequence','start_ticks','end_ticks','monotonic_frequency'}, 'context_frame_scope')
        first,last,start,end,freq = [scope[n] for n in ('first_sequence','last_sequence','start_ticks','end_ticks','monotonic_frequency')]
        need(all(type(n) is int for n in (first,last,start,end,freq)) and 0 <= first <= last <= first+100000
             and 0 < freq <= 10**9 and 0 <= start <= end <= start+3600*freq, 'context_frame_scope')
    return pins


def read_span(fields, timing, *, allow_empty=False):
    need(isinstance(fields, list) and len(fields) <= 256 and (allow_empty or fields), 'context_read_evidence')
    if not fields:return None
    for word in fields:
        need(isinstance(word, dict), 'context_read_evidence')
        a,b=word.get('read_start_ticks'),word.get('read_end_ticks')
        need(type(a)is int and type(b)is int and timing['start_ticks'] <= a <= b <= timing['end_ticks'], 'context_read_bracket')
    return [min(w['read_start_ticks']for w in fields),max(w['read_end_ticks']for w in fields)]


def _scope(node, timing, profile, build, declarations=None):
    # Preserve the node/depth budget while visiting containers only. Read
    # brackets need bounds checks, not allocating a list and calculating a span.
    budget=1;containers=(dict,list);start,end=timing['start_ticks'],timing['end_ticks']
    def visit(value,depth):
        nonlocal budget
        if isinstance(value,dict):
            if 'profile_sha256'in value:need(value['profile_sha256']==profile,'context_nested_profile')
            if 'build_sha256'in value:need(value['build_sha256']==build,'context_nested_build')
            if 'read_start_ticks'in value or 'read_end_ticks'in value:
                a,b=value.get('read_start_ticks'),value.get('read_end_ticks')
                need(type(a)is int and type(b)is int and start<=a<=b<=end,'context_read_bracket')
            if declarations is not None and 'field'in value:
                need(value['field']in declarations,'context_undeclared_field')
                if 'type'in value:need(value['type']==declarations[value['field']],'context_field_type')
            children=value.values()
        else:children=value
        size=len(value);budget+=size
        need(budget<=500000 and (not size or depth<24),'context_evidence_bound')
        for child in children:
            if isinstance(child,containers):visit(child,depth+1)
    need(isinstance(node,containers),'context_evidence_object')
    visit(node,0)


def _same_scope(node, schema, contract, frame, source_pins, *, full_time=False):
    private(node)
    need(node.get('schema')==schema and node.get('contract_sha256')==contract
         and node.get('target')==frame['target'] and node.get('profile_sha256')==frame['profile_sha256']
         and node.get('source_evidence')==source_pins and node.get('durability_verified')is False,'context_helper_scope')
    expected=frame['timing']if full_time else {n:frame['timing'][n]for n in TIME_KEYS}
    need(node.get('timing')==expected,'context_helper_timing')


def validate_context_frame(frame, source, target=None):
    """Bind exact optional projection to configured source/admission and actors.

    Return the validated top object, or None for a legacy/disabled source. No
    enable/disable change is admitted without a new configured source epoch.
    """
    pins=validate_context_source(source);top=frame.get('context_group_projection')
    if pins is None:
        need(top is None and frame.get('raw_context_output_enabled',False)is False
             and frame.get('context_group_output_enabled',False)is False,'unconfigured_context_projection')
        for row in frame.get('relations',[]):
            need(row.get('context_group_candidate')is None and row.get('context_group_evidence')is None,'unconfigured_actor_context')
        return None
    group_enabled=pins['contract_sha256'][CONTRACT_KEYS[2]]is not None
    need(frame.get('category_output_enabled')is False and frame.get('live_category_output_enabled',False)is False,'context_legacy_category_conflation')
    need(frame.get('raw_context_output_enabled')is True and frame.get('context_group_output_enabled')is group_enabled,'context_projection_toggle')
    finite=pins.get('schema')=='overwatch-decoder.finite-context-source/1'
    if finite:
        private(top)
        need(frame.get('schema')=='overwatch-decoder.entity-relations-export/1'
             and frame.get('profile_sha256')==source.get('profile_sha256')
             and (target is None or frame.get('target')==target), 'finite_context_frame_source')
        need(top.get('schema')=='overwatch-decoder.finite-context-group-projection/1'
             and all(top.get(n)==frame.get(n)for n in ('profile_sha256','target','timing'))
             and not any(n in top for n in ('session_id','segment','event_sequence'))
             and top.get('privacy')=='private'and top.get('recording_state')=='native_verified_prefix'
             and top.get('durability_verified')is False and top.get('previous_values_carried')is False
             and top.get('contract_sha256')==pins['contract_sha256']and top.get('frame_scope')is None,'finite_context_top_scope')
        acquisition=frame['source_artifacts']['acquisition']
        need(frame['source_artifacts']==pins['source_artifacts']and acquisition==source.get('acquisition'),'context_acquisition')
        recording=frame.get('recording',{})
        need(recording.get('continuity_across_gaps')is False
             and ((recording.get('complete')is True and recording.get('partial')is False and recording.get('status')=='verified_complete')
                  or (recording.get('complete')is False and recording.get('partial')is True and recording.get('status')in ('verified_stopped','recoverable_prefix'))),
             'finite_context_recording')
        admission=top.get('admission',{})
        expected=dict(schema='overwatch-decoder.finite-context-frame-admission/1',source_artifacts=frame['source_artifacts'],
            recording=recording,source_acquisition=acquisition,profile_sha256=frame['profile_sha256'],
            timing={n:frame['timing'][n]for n in TIME_KEYS})
        need(set(admission)==set(expected)|{'native_frame_sha256'}and all(admission.get(n)==v for n,v in expected.items()),'finite_context_frame_admission')
        digest(admission['native_frame_sha256'])
    else:
        need(all(frame.get(n)==source.get(n)for n in ('session_id','segment','profile_sha256'))
             and (target is None or frame.get('target')==target),'context_frame_source')
        private(top)
        need(top.get('schema')=='overwatch-decoder.live-context-group-projection/1'
             and all(top.get(n)==frame.get(n)for n in ('session_id','segment','event_sequence','profile_sha256','target','timing'))
             and top.get('privacy')=='private' and top.get('recording_state')=='accepted_not_durability_verified'
             and top.get('durability_verified')is False and top.get('previous_values_carried')is False
             and top.get('contract_sha256')==pins['contract_sha256'] and top.get('frame_scope')==pins['frame_scope'],'context_top_scope')
        acquisition=frame['source_artifacts']['acquisition'];need(acquisition==source.get('acquisition'),'context_acquisition')
        admission=top.get('admission',{})
        expected=dict(schema='overwatch-decoder.live-context-frame-admission/1',status='accepted_not_durability_verified',durability_verified=False,
            configured_admission_sha256=pins['configured_admission_sha256'],session_id=frame['session_id'],segment=frame['segment'],
            event_sequence=frame['event_sequence'],event_sha256=frame['source_artifacts']['live_event_sha256'],
            frame_sequence=frame['timing']['sequence'],frame_start_ticks=frame['timing']['start_ticks'],frame_end_ticks=frame['timing']['end_ticks'],
            monotonic_frequency=frame['timing']['monotonic_frequency'],profile_sha256=frame['profile_sha256'],source_acquisition=acquisition,
            session_start_sha256=pins['session_start_sha256'],segment_start_sha256=pins['segment_start_sha256'])
        epoch=frame.get('session_epoch',{})
        if source.get('session_epoch')is not None:need(epoch==source['session_epoch'],'context_epoch_metadata')
        expected.update(session_start_event_sha256=epoch.get('session_start_sha256'),segment_start_event_sha256=epoch.get('segment_start_sha256'))
        for name in ('session_start_event_sha256','segment_start_event_sha256'):digest(expected[name])
        need(set(admission)==set(expected)|{'native_frame_sha256'}and all(admission.get(n)==v for n,v in expected.items()),'context_frame_admission')
        digest(admission['native_frame_sha256'])
    native_source=dict(recipe_sha256=acquisition['recipe_sha256'],evidence_sha256=acquisition['evidence_sha256'],acquisition_manifest_sha256=acquisition['manifest_sha256'])
    raw,context,groups=top.get('raw_category_projection'),top.get('context_projection'),top.get('group_projection')
    _same_scope(raw,'overwatch-decoder.guarded-raw-actor-categories/1',pins['contract_sha256'][CONTRACT_KEYS[0]],frame,native_source,full_time=True)
    _same_scope(context,'overwatch-decoder.guarded-context-controller/1',pins['contract_sha256'][CONTRACT_KEYS[1]],frame,native_source)
    need(raw.get('native_review_sha256')==pins['category_native_review_sha256']
         and context.get('native_review_sha256')==pins['context_native_review_sha256'],'context_native_review')
    need(context.get('status')in ('observed','unknown')and context.get('body_status')in ('observed','unknown')
         and context.get('role')=='context_selected_controller'and context.get('local_control_semantics_validated')is False
         and context.get('playable_body_validated')is False and context.get('previous_values_carried')is False,'context_neutral_claim')
    key(context.get('controller_object_key'),'controller');key(context.get('body_object_key'),'body')
    if context['status']=='observed':need(context.get('controller_object_key')is not None,'context_missing_controller')
    if context['body_status']=='observed':need(context['status']=='observed'and context.get('body_object_key')is not None,'context_missing_body')
    raw_rows=raw.get('rows');need(isinstance(raw_rows,list)and len(raw_rows)<=32 and all(isinstance(r,dict)for r in raw_rows),'context_raw_rows')
    if group_enabled:
        _same_scope(groups,'overwatch-decoder.guarded-context-groups/1',pins['contract_sha256'][CONTRACT_KEYS[2]],frame,native_source)
        need(groups.get('category_contract_sha256')==pins['contract_sha256'][CONTRACT_KEYS[0]]
             and groups.get('context_contract_sha256')==pins['contract_sha256'][CONTRACT_KEYS[1]]
             and groups.get('two_group_review_sha256')==pins['two_group_review_sha256']
             and groups.get('context_scope_review_sha256')==pins['context_scope_review_sha256']
             and groups.get('native_frame_sha256')==admission['native_frame_sha256']
             and groups.get('context_controller_object_key')==context['controller_object_key']
             and groups.get('context_body_object_key')==context['body_object_key']
             and groups.get('previous_values_carried')is False,'context_group_scope')
        need(isinstance(groups.get('rows'),list)and len(groups['rows'])<=32 and all(isinstance(r,dict)for r in groups['rows']),'context_group_rows')
        need(groups.get('status')in ('observed','unknown')and groups.get('automatic_spectator_detection')is False
             and groups.get('local_control_semantics_validated')is False and groups.get('playable_body_validated')is False,'context_group_claim')
        interval=pins['frame_scope'];time=frame['timing']
        in_scope=(interval['first_sequence']<=time['sequence']<=interval['last_sequence']
                  and interval['start_ticks']<=time['start_ticks']<=time['end_ticks']<=interval['end_ticks']
                  and interval['monotonic_frequency']==time['monotonic_frequency'])
        if groups['status']=='observed':
            need(in_scope and groups.get('context_use')=='controlled_player_context'
                 and context['status']=='observed'and context['body_status']=='observed'
                 and isinstance(groups.get('context_group_candidate'),str),'context_group_unobserved_scope')
        else:
            need(groups.get('context_group_candidate')is None and all(r.get('status')!='observed'
                 and r.get('global_group_candidate')is None and r.get('group_relation_candidate')is None for r in groups['rows']),'context_unknown_group_carried')
        for row in groups['rows']:
            found=[r for r in raw_rows if r.get('controller_object_key')==row.get('controller_object_key')and r.get('body_object_key')==row.get('body_object_key')]
            need(len(found)==1 and row.get('raw_category_candidate')==found[0].get('raw_category_candidate'),'context_group_raw_join')
            if row.get('status')=='observed':
                need(groups['status']=='observed'and found[0].get('status')=='observed'and row.get('evidence')==found[0].get('evidence')
                     and isinstance(row.get('global_group_candidate'),str)
                     and row.get('group_relation_candidate')==('same_group'if row['global_group_candidate']==groups['context_group_candidate']else'opposing_group'),'context_group_relation')
        need(all(r.get('team_candidate')is None and r.get('relative_allegiance_candidate')is None for r in groups['rows']),'context_legacy_group_conflation')
    else:need(groups is None,'unconfigured_group_projection')
    gap=frame.get('gap_before',{}).get('skipped_slots',0)
    if gap:
        need(context['status']=='unknown'and all(r.get('raw_status')!='observed'for r in raw_rows)
             and (groups is None or groups.get('status')=='unknown'),'context_gap_carried_values')
    declarations=source.get('declarations')
    if declarations is None and 'fields'in source:declarations={f['name']:f['type']for f in source['fields']}
    _scope(top,frame['timing'],frame['profile_sha256'],frame['target']['executable_sha256'],declarations)
    for row in frame.get('relations',[]):validate_actor_context(row,top,profile_sha256=frame['profile_sha256'],build_sha256=frame['target']['executable_sha256'],timing=frame['timing'])
    return top


def validate_actor_context(row, projection, *, profile_sha256, build_sha256, timing):
    """Validate the actor plus a separately top-bound neutral context reference."""
    value,e=row.get('context_group_candidate'),row.get('context_group_evidence')
    need(all(row.get(n)is None for n in LEGACY),'context_legacy_category_conflation')
    if value is None:
        need(e is None,'context_evidence_without_value');return None
    need(projection is not None and row.get('relation_status')=='observed'and isinstance(value,dict),'actor_context_without_relation')
    private(e)
    raw=projection['raw_category_projection'];context=projection['context_projection'];groups=projection['group_projection']
    def matches(rows,ck,bk):return [r for r in rows if r.get('controller_object_key')==ck and r.get('body_object_key')==bk]
    found=matches(raw['rows'],row['controller_object_key'],row['body_object_key'])
    need(len(found)==1 and found[0].get('raw_status')=='observed','actor_context_exact_raw_match');category=found[0]
    anchors=matches(raw['rows'],context['controller_object_key'],context['body_object_key'])
    anchor=anchors[0]if context['status']=='observed'and context['body_status']=='observed'and len(anchors)==1 and anchors[0].get('status')=='observed'else None
    context_category=anchor['raw_category_candidate']if anchor else None
    compared=matches(groups['rows'],row['controller_object_key'],row['body_object_key'])if groups else []
    comparison=compared[0]if len(compared)==1 else None;observed=comparison is not None and comparison.get('status')=='observed'
    expected=dict(raw_flags=category['raw_flags_candidate'],raw_category=category['raw_category_candidate'],raw_status=category['raw_status'],category_status=category['status'],
        context_raw_category=context_category,category_matches_context=(category['raw_category_candidate']==context_category if category['status']=='observed'and context_category is not None else None),
        global_group=comparison['global_group_candidate']if observed else None,relation_to_context=comparison['group_relation_candidate']if observed else None,group_status='observed'if observed else'unknown')
    need(value==expected and (value['category_matches_context']is None or type(value['category_matches_context'])is bool)
         and (value['context_raw_category']is None or type(value['context_raw_category'])is int),'actor_context_candidate_mismatch')
    flags=value['raw_flags'];need(isinstance(flags,dict)and set(flags)=={'low_u32','high_u32','assembled_u64_hex','selected_category_indices'},'actor_context_flags')
    low,high=flags['low_u32'],flags['high_u32'];selected=flags['selected_category_indices']
    need(type(low)is int and type(high)is int and 0<=low<2**32 and 0<=high<2**32 and flags['assembled_u64_hex']==f'0x{high:08x}{low:08x}'
         and isinstance(selected,list)and len(selected)<=32 and len(set(selected))==len(selected)and all(type(n)is int and 0<=n<32 for n in selected),'actor_context_flag_assembly')
    need(value['raw_status']=='observed'and value['category_status']in ('observed','unknown')and value['group_status']in ('observed','unknown')
         and (value['raw_category']is None or type(value['raw_category'])is int and value['raw_category']>=0),'actor_context_status')
    if observed:need(isinstance(value['global_group'],str)and 0<len(value['global_group'])<=128 and value['relation_to_context']in ('same_group','opposing_group'),'actor_context_group_value')
    expected_ref={n:context[n]for n in ('controller_object_key','body_object_key','status','reason','body_status','body_reason')}
    expected_ref.update(projection='context_group_projection.context_projection',raw_category_projection='context_group_projection.raw_category_projection',
        group_context_evidence='context_group_projection.group_projection.context_evidence'if groups else None)
    need(e.get('context_reference')==expected_ref and e.get('profile_sha256')==profile_sha256 and e.get('build_sha256')==build_sha256
         and e.get('admission')==projection['admission'] and e.get('source_acquisition')==projection['admission']['source_acquisition']
         and e.get('contract_sha256')==projection['contract_sha256']and e.get('frame_scope')==projection['frame_scope']
         and e.get('category_native_review_sha256')==raw['native_review_sha256']and e.get('context_native_review_sha256')==context['native_review_sha256']
         and e.get('two_group_review_sha256')==(groups['two_group_review_sha256']if groups else None)
         and e.get('context_scope_review_sha256')==(groups['context_scope_review_sha256']if groups else None)
         and e.get('durability_verified')is False,'actor_context_evidence_scope')
    need(e.get('actor_fields')==category['evidence']and len(e['actor_fields'])==4,'actor_context_read_evidence')
    fields=e['actor_fields'];read_span(fields,timing)
    need((fields[2]['value']&0xffffffff)==low and (fields[3]['value']&0xffffffff)==high,'actor_context_read_flags')
    _scope(e,timing,profile_sha256,build_sha256)
    return e['context_reference']


def compact_context(projection, base):
    context=projection['context_projection'];groups=projection['group_projection']
    result=dict(source_ref=base,admission_ref=base+'/admission',contract_sha256=copy.deepcopy(projection['contract_sha256']),
        context_controller_object_key=context['controller_object_key'],context_body_object_key=context['body_object_key'],
        status=context['status'],reason=context['reason'],body_status=context['body_status'],body_reason=context['body_reason'],
        local_control_semantics_validated=False,playable_body_validated=False,previous_values_carried=False,
        context_evidence_ref=base+'/context_projection',raw_category_projection_ref=base+'/raw_category_projection',
        group_projection_ref=base+'/group_projection'if groups is not None else None)
    fields=[]
    if context.get('selector_evidence')is not None:fields.append(context['selector_evidence'])
    fields.extend(word for item in context.get('candidate_identity_evidence',[]) for word in item.get('words',[]))
    fields.extend(context.get('body_evidence',[]))
    if groups is not None:fields.extend((groups.get('context_evidence')or{}).get('category')or[])
    result['read_span_ticks']=read_span(fields,projection['timing'],allow_empty=True)
    if groups is not None:result.update(group_status=groups['status'],group_reason=groups['reason'],context_group_candidate=groups['context_group_candidate'])
    return result


def compact_actor_context(row, projection, base, projection_base):
    reference=validate_actor_context(row,projection,profile_sha256=projection['profile_sha256'],build_sha256=projection['target']['executable_sha256'],timing=projection['timing'])
    return _compact_actor_context(row,projection,base,projection_base,reference)


def _compact_actor_context(row, projection, base, projection_base, reference):
    """Pure projection after this exact row was validated in the same call."""
    value=row.get('context_group_candidate');fields=(row.get('context_group_evidence')or{}).get('actor_fields')
    return dict(status='candidate'if value is not None else'unknown',value=copy.deepcopy(value),reason=row.get('context_group_reason'),
        read_span_ticks=read_span(fields,projection['timing'])if fields else None,
        evidence_ref=base+'/context_group_evidence'if reference is not None else None,
        context_projection_ref=projection_base)


def validate_context_entry(entry, target):
    """Check the once-per-source aggregate projection and reconstruct its scope."""
    top=entry.get('projection');need(isinstance(top,dict),'aggregate_context_projection')
    if entry.get('source_admission',{}).get('schema')=='overwatch-decoder.finite-context-source/1':
        source=dict(profile_sha256=entry['source_artifacts']['profile_sha256'], acquisition=entry['source_artifacts']['acquisition'],
                    context_projection=entry['source_admission'])
        frame=dict(schema='overwatch-decoder.entity-relations-export/1',profile_sha256=source['profile_sha256'],target=target,
            source_artifacts=entry['source_artifacts'],recording=entry['source_recording'],timing=entry['source_timing'],
            gap_before=entry.get('source_gap',{}),raw_context_output_enabled=True,context_group_output_enabled=False,
            context_group_projection=top,category_output_enabled=False,relations=[])
        validate_context_frame(frame,source,target=target);return top
    source=dict(session_id=top['session_id'],segment=top['segment'],profile_sha256=entry['source_artifacts']['profile_sha256'],
        acquisition=entry['source_artifacts']['acquisition'],context_projection=entry['source_admission'])
    epoch=dict(session_start_sha256=top['admission']['session_start_event_sha256'],segment_start_sha256=top['admission']['segment_start_event_sha256'])
    frame=dict(session_id=top['session_id'],segment=top['segment'],event_sequence=top['event_sequence'],profile_sha256=source['profile_sha256'],target=target,
        source_artifacts=entry['source_artifacts'],timing=entry['source_timing'],session_epoch=epoch,raw_context_output_enabled=True,
        context_group_output_enabled=top['group_projection']is not None,context_group_projection=top,category_output_enabled=False,relations=[])
    validate_context_frame(frame,source,target=target);return top


def context_source_from_frame(frame):
    """Describe accepted semantic pins for a compact-only consumer, not admission.

    Runtime callers must instead supply their independently checked source pins.
    Compact consumers use this only at an explicit semantic epoch boundary, then
    reject pin/enabling changes until the next boundary.
    """
    result={n:copy.deepcopy(frame.get(n))for n in ('session_id','segment','profile_sha256','session_epoch')}
    result['acquisition']=copy.deepcopy(frame['source_artifacts']['acquisition'])
    top=frame.get('context_group_projection')
    if top is None:return result
    raw,context,groups=top['raw_category_projection'],top['context_projection'],top['group_projection']
    admission=top['admission']
    if top.get('schema')=='overwatch-decoder.finite-context-group-projection/1':
        result['context_projection']=dict(schema='overwatch-decoder.finite-context-source/1',contract_sha256=copy.deepcopy(top['contract_sha256']),
            category_native_review_sha256=raw['native_review_sha256'],context_native_review_sha256=context['native_review_sha256'],
            two_group_review_sha256=None,context_scope_review_sha256=None,frame_scope=None,
            source_artifacts=copy.deepcopy(frame['source_artifacts']))
        return result
    result['context_projection']=dict(configured_admission_sha256=admission['configured_admission_sha256'],
        contract_sha256=copy.deepcopy(top['contract_sha256']),category_native_review_sha256=raw['native_review_sha256'],
        context_native_review_sha256=context['native_review_sha256'],two_group_review_sha256=groups['two_group_review_sha256']if groups else None,
        context_scope_review_sha256=groups['context_scope_review_sha256']if groups else None,frame_scope=copy.deepcopy(top['frame_scope']),
        session_start_sha256=admission['session_start_sha256'],segment_start_sha256=admission['segment_start_sha256'])
    return result
