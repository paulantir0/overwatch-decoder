"""Finite local roster orchestration over explicitly reviewed caller artifacts.

Only Popen handles created here may be joined/terminated. Native collectors are
finite children of those producers. Fatal startup failures stop owned jobs promptly;
admitted runs retain their bounded settling period. Evidence stays private.
"""
from pathlib import Path
import argparse
import ctypes
import hashlib
import json
import os
import re
import subprocess
import sys
import time
# Embeddable Python ignores script/cwd search paths: bootstrap this bundle only.
_RUNTIME_DIRECTORY = Path(__file__).resolve().parent
_BUNDLE_ROOT = _RUNTIME_DIRECTORY.parents[1]
sys.path[:0] = [str(_RUNTIME_DIRECTORY), str(_BUNDLE_ROOT)]
from aggregate_partitions import parse
from forward_owner_relations import acquisition_validation_scope

RUNTIME_SCHEMA = "overwatch-decoder.local-roster-runtime/1"
MAX_NATIVE_BYTES = 512 * 1024 * 1024
MAX_LINE = 1024 * 1024
MAX_JSON = 1024 * 1024
RAW_REQUIRED = ('position_candidate', 'health_candidate')
REQUIRED = ('position_candidate','health_candidate','hero_label','cached_label_candidate',
            'raw_category_candidate','team_candidate','relative_allegiance_candidate')


class PreAdmissionFailure(ValueError):
    """Fatal startup failure after its incomplete aggregate receipt is saved."""


class ParentPerformance:
    """Fixed counters only, never a growing per-frame timing history."""
    STAGES=('read','route','parent_parse','row_validation','coordinator','admission',
            'serialize','compact','write','active_proof','status','idle','startup_validation')
    def __init__(self,wall=time.perf_counter_ns,cpu=time.thread_time_ns):
        self.wall,self.cpu=wall,cpu;self.started=self.begin()
        self.rows={key:dict(calls=0,wall_ns=0,thread_cpu_ns=0,max_wall_ns=0,bytes=0)for key in self.STAGES}
    def begin(self):return self.wall(),self.cpu()
    def end(self,stage,start,bytes=0):
        need(stage in self.rows and type(bytes)is int and bytes>=0,'parent_performance_stage_or_bytes')
        row=self.rows[stage];need(row['calls']<1000000,'parent_performance_call_bound')
        wall,cpu=self.begin();elapsed=max(0,wall-start[0]);row['calls']+=1;row['wall_ns']+=elapsed
        row['thread_cpu_ns']+=max(0,cpu-start[1]);row['max_wall_ns']=max(row['max_wall_ns'],elapsed);row['bytes']+=bytes
    def snapshot(self):
        wall,cpu=self.begin()
        return dict(schema='overwatch-decoder.private.parent-performance/1',clock='perf_counter_ns/thread_time_ns',
            measurement_scope='aggregate_loop_and_admissions_excluding_final_hashing',
            elapsed_wall_ns=max(0,wall-self.started[0]),elapsed_thread_cpu_ns=max(0,cpu-self.started[1]),
            nested_stages={'route':['parent_parse','row_validation','coordinator','admission']},
            stages={key:dict(value,mean_wall_ns=0 if not value['calls']else value['wall_ns']//value['calls'])for key,value in self.rows.items()})


class ProofSchedule:
    """Retry a missing proof at most once per second, separately per revision."""
    def __init__(self):self.next_due={};self.attempts=0;self.suppressed=0
    def due(self,revision,complete,proved,now):
        need(type(revision)is int and 1<=revision<=128,'proof_schedule_revision')
        if complete<20 or proved:return False
        if now<self.next_due.get(revision,-1):self.suppressed+=1;return False
        self.next_due[revision]=now+1.;self.attempts+=1;return True
    def snapshot(self):return dict(interval_seconds=1,attempts=self.attempts,suppressed_eligible_windows=self.suppressed,revisions=len(self.next_due))


def write_flushed(file,raw,perf):
    started=perf.begin()
    try:file.write(raw);file.flush()
    finally:perf.end('write',started,len(raw))


def need(ok, reason):
    if not ok: raise ValueError(reason)


def digest(path):
    with Path(path).open('rb') as file: return hashlib.file_digest(file,'sha256').hexdigest()


def save(path, value):
    path=Path(path);temporary=path.with_name(path.name+'.tmp')
    temporary.write_text(json.dumps(value,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    temporary.replace(path)


def shared_bytes(path, maximum=MAX_JSON):
    """Open only the named evidence file, allowing the writer's atomic replace."""
    path=Path(path)
    if sys.platform!='win32':
        with path.open('rb') as file: data=file.read(maximum+1)
    else:
        from ctypes import wintypes
        import msvcrt
        api=ctypes.WinDLL('kernel32',use_last_error=True)
        api.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
        api.CreateFileW.restype=wintypes.HANDLE
        api.CloseHandle.argtypes=[wintypes.HANDLE];api.CloseHandle.restype=wintypes.BOOL
        handle=api.CreateFileW(str(path),0x80000000,7,None,3,0x80,None)
        if handle==ctypes.c_void_p(-1).value: raise ctypes.WinError(ctypes.get_last_error())
        try: fd=msvcrt.open_osfhandle(handle,os.O_RDONLY|os.O_BINARY)
        except BaseException:
            api.CloseHandle(handle);raise
        with os.fdopen(fd,'rb') as file: data=file.read(maximum+1)
    need(len(data)<=maximum,'evidence_file_size')
    return data


def shared_json(path, retries=8):
    error=None
    for attempt in range(retries):
        try:return parse(shared_bytes(path))
        except (OSError,ValueError) as exc:
            error=exc
            if attempt+1<retries:time.sleep(.025)
    raise ValueError('evidence_read_failed: '+str(path)+': '+str(error))


class WindowsClock:
    def __init__(self):
        need(sys.platform=='win32','windows_live_clock_required')
        api=ctypes.WinDLL('kernel32',use_last_error=True)
        api.QueryPerformanceCounter.argtypes=[ctypes.POINTER(ctypes.c_longlong)];api.QueryPerformanceCounter.restype=ctypes.c_int
        api.QueryPerformanceFrequency.argtypes=[ctypes.POINTER(ctypes.c_longlong)];api.QueryPerformanceFrequency.restype=ctypes.c_int
        self.api=api;value=ctypes.c_longlong()
        need(bool(api.QueryPerformanceFrequency(ctypes.byref(value))),'qpc_frequency_failed');self.frequency=value.value
    def tick(self):
        value=ctypes.c_longlong();need(bool(self.api.QueryPerformanceCounter(ctypes.byref(value))),'qpc_failed');return value.value
    def utc_ns(self):return time.time_ns()


def reviewed_inputs(plan, roles, *, raw_candidates=False):
    """Caller-reviewed roles; no native local-owner or roster discovery claim."""
    need(plan.get('schema')=='overwatch-decoder.live-roster-plan/1' and roles.get('schema')==('overwatch-decoder.raw-controller-roster/1' if raw_candidates else 'overwatch-decoder.private.current-controller-roster/1')
         and plan['target']==roles['target'] and roles.get('public_state_eligible') is False,'review_target_or_schema')
    parts=plan.get('partitions',[])
    need(1<=len(parts)<=16 and {p['ordinal']for p in parts}==set(range(1,len(parts)+1)),'bounded_unique_partitions_required')
    rows=roles.get('rows',[]);rolemap={r['controller_object_key']:r for r in rows}
    primary={r['controller_object_key']:r['partition']for r in plan.get('primary_controller_map',[])}
    need(len(rolemap)==len(rows)==len(primary)==len(plan['primary_controller_map'])==plan.get('controller_count') and 1<=len(rows)<=128
         and set(primary)==set(rolemap),'exact_reviewed_controllers_required')
    anchor=plan.get('anchor_controller_key')
    if raw_candidates:
        need(roles.get('census_source')==plan.get('census_source') and roles.get('self_controller_object_key') is None,'raw_roster_census_or_self_claim')
        need(anchor is None or anchor in rolemap and primary[anchor]==1,'partition_anchor_owner')
    else:
        need(anchor==roles['self_controller_object_key'] and primary[anchor]==1,'self_anchor_owner')
    coverage={key:[] for key in rolemap}
    for part in parts:
        actors=part['controllers'];keys=[r['controller_object_key']for r in actors]
        need(len(keys)==len(set(keys)) and set(keys)<=set(rolemap) and (anchor is None or anchor in keys),'partition_controller_set')
        for actor in actors:
            ck=actor['controller_object_key'];coverage[ck].append(part['ordinal'])
            need(actor.get('observation_role')==('primary'if primary[ck]==part['ordinal']else'support'),'partition_primary_role')
            for pkey,rkey in [('full_handle_u32','full_handle'),('creation_key_u32','creation_key')]:
                if pkey in actor and rkey in rolemap[ck]:need(actor[pkey]==rolemap[ck][rkey],'plan_role_identity_mismatch')
    need(all(primary[k]in members and (k==anchor or len(members)==1)for k,members in coverage.items()),'primary_membership_or_duplicate_actor')
    return rolemap,primary


def raw_roster_inputs(plan, census):
    """Guarded census selection, not a self/name/team or live-presence claim."""
    need(plan.get('schema') == 'overwatch-decoder.live-roster-plan/1' and plan.get('target') == census['target']
         and plan.get('census_source') == census['source'], 'raw_plan_census_mismatch')
    need(plan.get('public_state_eligible') is False and plan.get('requires_fresh_native_acquisition') is True,
         'raw_plan_fresh_admission_required')
    identities = {r['controller_object_key']: r for r in census['controllers']}
    need(len(identities) == len(census['controllers']), 'raw_duplicate_census_controller')
    rows = [dict(controller_object_key=k, full_handle=v['full_handle_u32'], creation_key=v['creation_key_u32'])
            for k, v in identities.items()]
    roles = dict(schema='overwatch-decoder.raw-controller-roster/1', target=census['target'], rows=rows,
                 census_source=census['source'], public_state_eligible=False,
                 roster_completeness='supplied_census_only', self_controller_object_key=None)
    reviewed_inputs(plan, roles, raw_candidates=True)
    for part in plan['partitions']:
        for actor in part['controllers']:
            expected = identities[actor['controller_object_key']]
            need(all(actor.get(k) == expected[k] for k in ('full_handle_u32', 'creation_key_u32')),
                 'raw_plan_census_identity_mismatch')
    return roles


class NativeMetadata:
    """Bounded incremental metadata index over each producer's exact raw log.

    Frame payloads are not decoded here. A cheap header filter only avoids
    parsing them; no metadata is admitted without full JSON parsing and its
    exact-byte hash. A missing/unusual header therefore fails closed.
    """
    def __init__(self):self.states={}
    def close(self):
        for state in self.states.values():state['file'].close()
    def actual(self, child, frame):
        sid=child['source_id'];path=Path(child['directory'])/'native.jsonl'
        if sid not in self.states:self.states[sid]=dict(file=path.open('rb'),events={},bytes=0,lines=0)
        state=self.states[sid];wanted=frame['session_epoch'];need(isinstance(wanted,dict),'session_epoch_required')
        while not all(wanted[k]in state['events']for k in ('session_start_sha256','acquisition_end_sha256','segment_start_sha256')):
            file=state['file'];at=file.tell();raw=file.readline(512*1024+1)
            need(len(raw)<=512*1024,'native_metadata_line_bound')
            if not raw or not raw.endswith(b'\n'):
                file.seek(at);raise ValueError('native_metadata_not_yet_complete')
            state['bytes']+=len(raw);state['lines']+=1
            need(state['bytes']<=MAX_NATIVE_BYTES and state['lines']<=100000,'native_metadata_budget')
            head=raw[:512]
            if not any(token in head for token in (b'session_start',b'acquisition_end',b'segment_start')):continue
            event=parse(raw)
            if event.get('kind')in('session_start','acquisition_end','segment_start'):
                state['events'][hashlib.sha256(raw).hexdigest()]=event
                need(len(state['events'])<=257,'native_metadata_event_bound')
        events=[state['events'][wanted[k]]for k in('session_start_sha256','acquisition_end_sha256','segment_start_sha256')]
        need([e.get('kind')for e in events]==['session_start','acquisition_end','segment_start'],'native_metadata_kinds')
        return events


def validate_rows(frame, expected, rolemap, *, initial=False, pairs=None, raw_candidates=False):
    if raw_candidates:
        need(frame.get('category_output_enabled',False) is False and frame.get('live_category_output_enabled',False) is False
             and frame.get('live_category_contract_sha256') is None,'raw_category_output_forbidden')
        enabled=frame.get('raw_context_output_enabled',False)
        need(type(enabled)is bool and (enabled or frame.get('context_group_projection')is None),
             'raw_context_projection_mode')
    rows=frame.get('relations',[])
    need(len(rows)==len(expected),'exact_actor_row_count')
    seen=set()
    for row in rows:
        if raw_candidates:
            need(all(row.get(k) is None for k in ('name', 'team', 'raw_category_candidate', 'team_candidate', 'relative_allegiance_candidate', 'category_evidence')), 'raw_unreviewed_category_or_name')
            need(enabled or all(row.get(k)is None for k in ('context_group_candidate','context_group_evidence')),
                 'unconfigured_context_candidate')
        if row.get('relation_status')!='observed':
            need(all(row.get(k)is None for k in ('context_group_candidate','context_group_evidence')),
                 'unresolved_context_carried_values')
            ck=row.get('controller_object_key')
            if raw_candidates and ck in expected and pairs is not None and pairs.get(ck) is None:
                need(row.get('relation_status')=='unknown' and row.get('body_object_key')is None
                     and all(row.get(k)is None for k in ('position_candidate','health_candidate','hero_resource_guid_candidate','hero_label','cached_label_candidate')),
                     'unresolved_body_carried_values')
                need(ck not in seen,'exact_current_controller_set');seen.add(ck)
                words=row.get('evidence',[]);review=rolemap[ck]
                need(len(words)==2 and words[0]['value']==review['full_handle'] and words[1]['value']==review['creation_key'],'unresolved_controller_words')
                continue
            need(not initial,'initial_actor_unobserved');continue
        ck=row.get('controller_object_key');need(ck in expected and ck not in seen,'exact_current_controller_set');seen.add(ck)
        review=rolemap[ck]
        need(row.get('body_object_key')is not None,'current_actor_body_unknown')
        for field,review_field in ([] if raw_candidates else [('cached_label_candidate','cached_label_candidate'),('relative_allegiance_candidate','visual_roster_role')]):
            value=row.get(field)
            need((value is None and not initial)or value==review[review_field],'current_actor_review_mismatch')
        if pairs is not None:need(row['body_object_key']==pairs[ck],'fresh_epoch_body_mismatch')
        words=row.get('evidence',[])
        if 'full_handle'in review:need(len(words)>=3 and words[0]['value']==review['full_handle']and words[1]['value']==review['creation_key'],'current_actor_full_key_mismatch')
        if initial:
            if not raw_candidates:
                need(row.get('hero_resource_guid_candidate',{}).get('value')==review['controller_resource_guid'],'initial_hero_review_mismatch')
            need(pairs is not None and row['body_object_key']==pairs[ck],'initial_fresh_body_binding_required')
    if initial:need(seen==expected,'initial_exact_controller_set')


def context_source_admission(acquisition, epoch, native_session, native_segment, frame):
    """Resolve fresh context contracts against actual native epoch metadata."""
    enabled=frame.get('raw_context_output_enabled',False)
    need(type(enabled)is bool,'context_output_flag')
    if not enabled:
        need(frame.get('context_group_projection')is None
             and frame.get('context_group_output_enabled',False)is False,'unconfigured_context_projection')
        return None
    from live_relations import LiveRelations
    from runtime_producer import context_adapter_options
    from context_projection_validation import validate_context_frame
    adapter=LiveRelations(acquisition,frame['session_id'],frame['segment'],
        recipe_path=Path(acquisition)/'recipe.json',**context_adapter_options(Path(epoch)/'context'))
    need(adapter.context_session==native_session and adapter.context_segment==native_segment,
         'context_native_metadata_mismatch')
    groups=adapter.context_groups
    configured=dict(configured_admission_sha256=adapter.context_admission_sha256,
        contract_sha256=adapter.context_contracts.copy(),
        category_native_review_sha256=adapter.raw_category.native_review_sha256,
        context_native_review_sha256=adapter.context.native_review_sha256,
        two_group_review_sha256=None if groups is None else groups.group_review_sha256,
        context_scope_review_sha256=None if groups is None else groups.context_scope_review_sha256,
        frame_scope=None if groups is None else groups.interval,
        session_start_sha256=adapter.context_admission['session_start_sha256'],
        segment_start_sha256=adapter.context_admission['segment_start_sha256'])
    source=dict(session_id=frame['session_id'],segment=frame['segment'],
        profile_sha256=frame['profile_sha256'],acquisition=adapter.acquisition.copy(),
        session_epoch=frame.get('session_epoch'),context_projection=configured)
    validate_context_frame(frame,source,target=adapter.projector.target)
    return configured


def ammunition_source_admission(acquisition, epoch, native_session, native_acquisition,
                                 native_segment, frame, *, enabled=False):
    """Admit optional ammunition from verified files for this native epoch."""
    need(type(enabled) is bool, 'ammunition_output_flag')
    if not enabled:
        need(not any(key in frame for key in ('ammunition_projection',
             'ammunition_live_admission', 'live_ammunition_output_enabled',
             'ammunition_contract_sha256', 'ammunition_admission_sha256'))
             and not any(any(key in row for key in ('ammunition_candidate',
                 'ammunition_reason', 'ammunition_evidence_ref'))
                 for row in frame.get('relations', [])), 'unconfigured_ammunition_projection')
        return None
    from live_relations import LiveRelations
    from ammunition_projection_validation import source_admission, validate_frame
    prefix = Path(epoch) / 'ammunition'
    adapter = LiveRelations(acquisition, frame['session_id'], frame['segment'],
        recipe_path=Path(acquisition) / 'recipe.json',
        ammunition_contract=prefix.with_suffix('.contract.json'),
        ammunition_artifacts=prefix.with_suffix('.artifacts.json'),
        ammunition_admission=prefix.with_suffix('.admission.json'))
    need(adapter.ammunition_session == native_session
         and adapter.ammunition_acquisition == native_acquisition
         and adapter.ammunition_segment == native_segment,
         'ammunition_native_metadata_mismatch')
    configured = source_admission(adapter.ammunition, live_adapter=adapter)
    validate_frame(frame, dict(ammunition=configured))
    return configured


def health_ratio_source_admission(acquisition, epoch, frame, *, input_pins=None,
                                  raw_candidates=False, allow_controller_subsets=False):
    """Rebuild optional ratios from this acquisition and the pinned full layout."""
    def absent():
        need(not any(key in frame for key in ('health_ratio_projection',
                 'health_ratio_contract_sha256'))
             and not any('health_ratio_candidate' in row for row in frame.get('relations', [])),
             'unconfigured_health_ratio_projection')

    if input_pins is None:
        absent()
        return None, None
    need(isinstance(input_pins, dict) and set(input_pins) == {
        'health_layout_sha256', 'health_ratio_layout_sha256',
        'health_ratio_native_review_sha256'}, 'health_ratio_input_pins')
    need(type(raw_candidates) is bool and type(allow_controller_subsets) is bool
         and (not allow_controller_subsets or raw_candidates), 'health_ratio_subset_mode')
    from build_health_contracts import build_contracts as build_health, _layout
    from build_health_ratio_contracts import build_contracts
    from export_relations import health_ratio_projection
    from health_ratio_validation import load_ratio_contract, validate_candidate
    from runtime_producer import build_present_health_contracts, health_ratio_inputs
    acquisition, epoch = Path(acquisition), Path(epoch)
    profile_raw = shared_bytes(acquisition/'profile.json', 262144)
    profile = parse(profile_raw)
    manifest = parse(shared_bytes(acquisition/'manifest.json', 262144))
    config = dict(input_pins, target=profile['target'], recipe_sha256=manifest['recipe_sha256'],
        health_layout=str(epoch/'health-ratio-health-layout.json'),
        health_ratio_layout=str(epoch/'health-ratio-layout.json'),
        health_ratio_native_review=str(epoch/'health-ratio-native-review.json'))
    inputs = health_ratio_inputs(config)
    layout_raw = inputs['health_layout']
    if allow_controller_subsets:
        # Parent source admission has separately verified the permitted full keys.
        # Derive the same template subset from this profile, never a saved subset.
        from controller_subset_projection import _filter_layout
        from plan_live_roster import encoded
        from relations import GuardedRelations
        layout, _, _ = _layout(layout_raw)
        prefixes = {p+'_body_0000_' for p in GuardedRelations(profile_raw).prefixes}
        need(prefixes <= set(layout['actor_prefixes']), 'health_ratio_subset_prefixes')
        layout_raw = encoded(_filter_layout(layout, prefixes))
    builder = build_present_health_contracts if raw_candidates else build_health
    health = builder(acquisition, layout_raw, recipe_path=acquisition/'recipe.json')
    need(parse(shared_bytes(epoch/'health-bundle.json')) == health,
         'health_ratio_fresh_health_bundle_mismatch')
    rebuilt = build_contracts(acquisition, inputs['health_ratio_layout'],
        inputs['health_ratio_native_review'], health, recipe_path=acquisition/'recipe.json')
    bundle_raw = shared_bytes(epoch/'health-ratio-bundle.json')
    need(parse(bundle_raw) == rebuilt, 'health_ratio_fresh_bundle_mismatch')
    contracts = []
    for index, descriptor in enumerate(rebuilt['contracts']):
        raw = shared_bytes(epoch/f'health-ratio-contract-{index:04d}.json', 262144)
        need(parse(raw) == descriptor, 'health_ratio_fresh_contract_mismatch')
        contracts.append(load_ratio_contract(profile_raw, raw, inputs['health_ratio_native_review']))
    receipt = dict(input_pins, bundle_sha256=hashlib.sha256(bundle_raw).hexdigest(),
                   contracts=len(contracts), previous_contracts_carried=False)
    if not contracts:
        absent()
        return None, receipt
    projection = health_ratio_projection(contracts)
    need(frame.get('health_ratio_projection') == projection
         and frame.get('health_ratio_contract_sha256') == [c.contract_sha256 for c in contracts],
         'health_ratio_projection_mismatch')
    for row in frame.get('relations', []):
        validate_candidate(row, frame, projection)
    return projection, receipt


def controller_subset_policy(plan, part, primary):
    expected=[r['controller_object_key'] for r in part['controllers']]
    context_key=plan.get('context_controller_object_key')
    need(len(expected)==len(set(expected)) and context_key in primary,'controller_subset_plan_scope')
    primaries=[ck for ck in expected if primary.get(ck)==part['ordinal']]
    need(bool(primaries),'controller_subset_primary_required')
    return dict(expected_controller_keys=sorted(expected),expected_primary_controller_keys=sorted(primaries),
                required_context_controller_key=context_key)


@acquisition_validation_scope()
def source_admission(child, plan, rolemap, primary, metadata, raw=None, *, initial=False, raw_candidates=False, allow_controller_subsets=False):
    need(type(allow_controller_subsets)is bool and (not allow_controller_subsets or raw_candidates),'controller_subsets_require_raw_mode')
    directory=Path(child['directory']);sid=child['source_id']
    if raw is None:
        with (directory/'entities.jsonl').open('rb')as file:raw=file.readline(MAX_LINE+1)
    need(0<len(raw)<=MAX_LINE and raw.endswith(b'\n'),'complete_semantic_line_required')
    frame=parse(raw);part=next(p for p in plan['partitions']if p['ordinal']==child['ordinal'])
    expected={r['controller_object_key']for r in part['controllers']};number=frame.get('segment')
    need(type(number)is int and 1<=number<=128 and frame.get('schema')=='overwatch-decoder.entity-relations-live/1'
         and frame['target']==plan['target']and frame['timing']['sequence']==0
         and (not initial or number==1),'first_frame_epoch_or_target')
    native_session,native_acquisition,native_segment=metadata.actual(child,frame)
    segment=native_segment
    if raw_candidates:
        need(frame.get('live_category_output_enabled', False) is False and frame.get('category_output_enabled') is False and frame.get('live_category_contract_sha256') is None,'raw_category_output_forbidden')
    else:
        epoch=directory/f'epoch-{number:04d}';contract_raw=shared_bytes(epoch/'category.contract.json');contract=parse(contract_raw)
        mode_raw=shared_bytes(epoch/'category.mode-review.json');mode=parse(mode_raw)
        session_raw=shared_bytes(epoch/'category.session-start.json');category_session=parse(session_raw)
        segment_raw=shared_bytes(epoch/'category.segment-start.json');segment=parse(segment_raw)
        need(hashlib.sha256(contract_raw).hexdigest()==frame['live_category_contract_sha256']
             and hashlib.sha256(mode_raw).hexdigest()==contract['mode_review_sha256']
             and hashlib.sha256(session_raw).hexdigest()==contract['session_start_sha256']
             and hashlib.sha256(segment_raw).hexdigest()==contract['segment_start_sha256'],'actual_category_artifact_hash')
        need(category_session==native_session and segment==native_segment,'category_native_metadata_semantic_mismatch')
    admission=frame['session_epoch'];entry=native_acquisition.get('acquisition',{})
    need(native_session['session_id']==native_acquisition['session_id']==segment['session_id']==frame['session_id']
         and native_session['target']==plan['target']and segment['segment']==number
         and segment['profile_sha256']==frame['profile_sha256']
         and segment['acquisition']==entry['ordinal']==admission['acquisition']
         and entry['complete']is True and entry.get('error')is None
         and entry['directory']==f"acquisition-{entry['ordinal']:04d}"
         and (raw_candidates or contract['self_controller_object_key']==plan['anchor_controller_key']
              and mode['live_scope']['segment_start_sha256']==contract['segment_start_sha256']),'actual_epoch_metadata')
    acq=directory/'native'/entry['directory'];acq_raw=shared_bytes(acq/'manifest.json');acquisition=parse(acq_raw)
    profile_raw=shared_bytes(acq/'profile.json');profile=parse(profile_raw)
    need(hashlib.sha256(acq_raw).hexdigest()==entry['manifest_sha256']==frame['source_artifacts']['acquisition']['manifest_sha256']
         and hashlib.sha256(profile_raw).hexdigest()==frame['profile_sha256']==acquisition['profile_sha256']==entry['profile_sha256']
         and acquisition['complete']is True and acquisition.get('error')is None and acquisition['target']==profile['target']==plan['target']
         and acquisition['recipe_sha256']==part['recipe_sha256']==native_session['recipe_sha256']
         and all(acquisition[k]==frame['source_artifacts']['acquisition'][k]for k in('recipe_sha256','evidence_sha256')),'actual_acquisition_or_recipe')
    if not raw_candidates:
        need(contract['acquisition_manifest_sha256']==entry['manifest_sha256'] and contract['profile_sha256']==entry['profile_sha256']
             and contract['target']==plan['target'] and all(contract['source'][k]==acquisition[k] for k in ('recipe_sha256','evidence_sha256')),'actual_category_acquisition')
    evidence=acq/'evidence.jsonl';recipe=acq/'recipe.json'
    need(0<evidence.stat().st_size<=16*1024*1024 and digest(evidence)==acquisition['evidence_sha256'],'actual_evidence_bytes')
    need(hashlib.sha256(shared_bytes(recipe)).hexdigest()==acquisition['recipe_sha256'],'actual_recipe_bytes')
    from runtime_producer import profile_body_bindings
    bindings,objects,unresolved=profile_body_bindings(profile_raw,allow_unresolved=raw_candidates)
    subset=None
    actual=[r['controller_object_key']for r in objects]
    if allow_controller_subsets:
        from runtime_partial import controller_subset_metadata
        policy=controller_subset_policy(plan,part,primary)
        subset=controller_subset_metadata(policy['expected_controller_keys'],policy['expected_primary_controller_keys'],actual,policy['required_context_controller_key'])
    else:
        need(len(objects)==len(expected)and set(actual)==expected,'fresh_profile_exact_controller_set')
    validate_rows(frame,set(actual) if allow_controller_subsets else expected,rolemap,initial=initial,pairs={r['controller_object_key']:r['body_object_key']for r in objects},raw_candidates=raw_candidates)
    config=dict(source_id=sid,session_id=frame['session_id'],segment=number,profile_sha256=frame['profile_sha256'],
        acquisition=frame['source_artifacts']['acquisition'],objects=objects,session_epoch=admission,
        fields=[{k:f[k]for k in('name','type')}for f in segment['fields']])
    pins=dict(first_line_sha256=hashlib.sha256(raw).hexdigest(),raw_native_session_epoch=admission,
        acquisition_manifest_sha256=hashlib.sha256(acq_raw).hexdigest(),profile_sha256=hashlib.sha256(profile_raw).hexdigest(),
        evidence_sha256=acquisition['evidence_sha256'],recipe_sha256=acquisition['recipe_sha256'])
    if unresolved:
        config['unresolved_bodies']=[dict(row,acquisition_evidence_sha256=acquisition['evidence_sha256'])for row in unresolved]
        pins['unresolved_bodies']=config['unresolved_bodies']
    from forward_roster_projection import acquire_source_metadata
    forward=acquire_source_metadata(profile_raw,directory/f'epoch-{number:04d}',frame,config)
    if forward is not None:
        config['forward_owner_projection']=forward
        pins['forward_owner_projection']=forward
    context=context_source_admission(acq,directory/f'epoch-{number:04d}',native_session,native_segment,frame)
    if context is not None:
        need(raw_candidates,'context_projection_requires_raw_mode')
        config['context_projection']=context
        pins['context_projection']=context
    if allow_controller_subsets:
        selected=(frame.get('context_group_projection') or {}).get('context_projection') or {}
        need(context is not None and selected.get('status')=='observed'
             and selected.get('controller_object_key')==subset['required_context_controller_key'],
             'controller_subset_required_context')
        config['controller_subset']=subset
        pins['controller_subset']=subset
    if not raw_candidates:
        category={k:contract[k]for k in('native_review_sha256','roster_review_sha256','mode_review_sha256','mode_id','self_controller_object_key')}
        category.update(contract_sha256=hashlib.sha256(contract_raw).hexdigest(),live_scope=mode['live_scope'])
        config['live_category']=category
        # Preserve the established reviewed artifact key order as well as values.
        pins=dict(first_line_sha256=pins['first_line_sha256'],category_contract_sha256=category['contract_sha256'],
            mode_review_sha256=contract['mode_review_sha256'],category_session_start_sha256=contract['session_start_sha256'],
            category_segment_start_sha256=contract['segment_start_sha256'],raw_native_session_epoch=admission,
            acquisition_manifest_sha256=pins['acquisition_manifest_sha256'],profile_sha256=pins['profile_sha256'],
            evidence_sha256=pins['evidence_sha256'],recipe_sha256=pins['recipe_sha256'])
        if forward is not None:
            pins['forward_owner_projection']=forward
    ammunition = ammunition_source_admission(acq, directory/f'epoch-{number:04d}',
        native_session, native_acquisition, native_segment, frame,
        enabled=child.get('ammunition_output_enabled', False))
    if ammunition is not None:
        config['ammunition'] = ammunition
        pins['ammunition'] = ammunition
    ratios, ratio_receipt = health_ratio_source_admission(acq, directory/f'epoch-{number:04d}',
        frame, input_pins=child.get('health_ratio_input_pins'), raw_candidates=raw_candidates,
        allow_controller_subsets=allow_controller_subsets)
    if ratios is not None:
        config['health_ratio_projection'] = ratios
        pins['health_ratio_projection'] = ratios
    if ratio_receipt is not None:
        pins['health_ratio_inputs'] = ratio_receipt
    return config,frame,pins


def route_projection(adapter, child, raw, current, plan, rolemap, primary, metadata, perf=None, *, raw_candidates=False):
    """Dispatch each complete semantic line exactly once; admission consumes seq0."""
    from aggregate_partitions import canonical
    mark=perf.begin()if perf else None
    frame=parse(raw);sid=child['source_id']
    if perf:perf.end('parent_parse',mark,len(raw))
    if frame.get('segment')!=current['segment']:
        need(frame.get('segment')==current['segment']+1 and frame['timing']['sequence']==0,'new_source_epoch_order')
        mark=perf.begin()if perf else None
        try:fresh,_,pin=source_admission(child,plan,rolemap,primary,metadata,raw,initial=False,raw_candidates=raw_candidates)
        finally:
            if perf:perf.end('admission',mark,len(raw))
        mark=perf.begin()if perf else None
        try:events=adapter.admit(sid,canonical(fresh),raw)
        finally:
            if perf:perf.end('coordinator',mark,len(raw))
        return frame,fresh,pin,events,'admit'
    mark=perf.begin()if perf else None
    try:validate_rows(frame,{r['controller_object_key']for r in current['objects']},rolemap,pairs={r['controller_object_key']:r['body_object_key']for r in current['objects']},raw_candidates=raw_candidates)
    finally:
        if perf:perf.end('row_validation',mark,len(raw))
    mark=perf.begin()if perf else None
    # Share only this freshly parsed, unchanged line inside the trusted pipeline.
    try:events=adapter._consume_decoded(sid,raw,frame)
    finally:
        if perf:perf.end('coordinator',mark,len(raw))
    return frame,current,None,events,'consume'


def retain_native_manifests(out, revision, rows, snapshots, used_bytes):
    """Retain only a successful active-check batch; preserve its exact bytes."""
    need(1<=len(rows)==len(snapshots)<=16 and len({r['source_id']for r in rows})==len(rows) and all(re.fullmatch(r'p(?:[1-9]|1[0-6])',r['source_id']) for r in rows),'manifest_snapshot_sources')
    need(all(isinstance(raw,bytes)and 0<len(raw)<=MAX_JSON and hashlib.sha256(raw).hexdigest()==row['native_manifest_sha256'] for row,raw in zip(rows,snapshots)),'manifest_snapshot_hash')
    total=used_bytes+sum(len(raw)for raw in snapshots);need(total<=8*1024*1024,'manifest_snapshot_total_bound')
    directory=Path(out)/'native-active-proofs'/f'revision-{revision:04d}';directory.mkdir(parents=True,exist_ok=False)
    retained=[]
    for row,raw in zip(rows,snapshots):
        relative=Path('native-active-proofs')/f'revision-{revision:04d}'/(row['source_id']+'.manifest.json')
        with(Path(out)/relative).open('xb')as file:file.write(raw)
        retained.append(dict(row,native_manifest_file=relative.as_posix()))
    return retained,total



def active_source_manifest(child, source, target, clock):
    """Read an actual current native manifest; semantic absence is not proof."""
    if (Path(child['directory'])/'result.json').exists():return None
    data=shared_bytes(Path(child['directory'])/'native/manifest.json');m=parse(data)
    need(m.get('target')==target and m.get('session_id')==source['session_id'],'native_target_or_session_changed')
    expected=f"segment-{source['segment']:04d}"
    if not (m.get('status')=='running' and m.get('active_operation')=='recording' and m.get('active_directory')==expected):return None
    return dict(source_id=child['source_id'],status=m['status'],active_operation=m['active_operation'],
        session_id=m['session_id'],active_directory=m['active_directory'],expected_directory=expected,
        native_manifest_sha256=hashlib.sha256(data).hexdigest(),target=m['target'],read_qpc=clock.tick()),data


class RawAbsenceProofs:
    """Bounded live proof for unresolved epochs even while all windows suspend."""
    def __init__(self):
        self.counts={};self.required=set();self.proofs={};self.next_due={};self.bytes=0
    def observe(self,child,source,frame,raw,out,clock,target,*,live):
        key=(child['source_id'],source['segment'])
        need(1<=source['segment']<=128 and (key in self.counts or len(self.counts)<2048),'raw_epoch_proof_bound')
        valid=all(row.get('controller_object_key') is not None and (row.get('relation_status')=='observed'
                  or row.get('reason')=='unsupported_word_binding')for row in frame['relations'])
        self.counts[key]=self.counts.get(key,0)+int(valid)
        if not source.get('unresolved_bodies'):return
        self.required.add(key)
        if not live or not valid or key in self.proofs:return
        now=time.monotonic()
        if now<self.next_due.get(key,-1):return
        self.next_due[key]=now+1
        found=active_source_manifest(child,source,target,clock)
        if found is None:return
        status,data=found;self.bytes+=len(data);need(self.bytes<=8*1024*1024,'raw_epoch_snapshot_bound')
        relative=Path('unresolved-native-active-proofs')/key[0]/f'segment-{key[1]:04d}.manifest.json'
        path=Path(out)/relative;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb')as file:file.write(data)
        proof=dict(source_id=key[0],segment=key[1],profile_sha256=source['profile_sha256'],
            acquisition=source['acquisition'],session_epoch=source['session_epoch'],
            unresolved_bodies=source['unresolved_bodies'],semantic_projection_sha256=hashlib.sha256(raw).hexdigest(),
            frame_sequence=frame['timing']['sequence'],native_manifest_file=relative.as_posix(),native_manifest=status)
        self.proofs[key]=proof;save(path.with_suffix('.proof.json'),proof)
    def ready(self,sources):
        return (any(s.get('unresolved_bodies')for s in sources.values())
                and all(self.counts.get((sid,s['segment']),0)>=20 for sid,s in sources.items()))
    def summary(self):
        return dict(required=[dict(source_id=s,segment=n)for s,n in sorted(self.required)],
            proofs=[self.proofs[k]for k in sorted(self.proofs)],snapshot_bytes=self.bytes,
            all_required_proved=self.required==set(self.proofs))


def completed_producer_results(children, sources, counts, projection_sha256):
    """Only successful, fully ended producers authorize finite invalidation."""
    result={}
    for child in children:
        path=Path(child['directory'])/'result.json';data=shared_bytes(path);value=parse(data)
        need(value.get('complete')is True and value.get('native_exit')==0 and not value.get('error')
             and value.get('decoder',{}).get('native_session_end_seen')is True
             and value.get('decoder',{}).get('phase')=='ended','producer_completion_unverified')
        sid=child['source_id'];need(sid not in result,'duplicate_completion_source')
        epochs=value.get('epochs');source=sources[sid]
        need(value.get('frames')==counts[sid] and value.get('decoder',{}).get('frames')==counts[sid]
             and value.get('entities_sha256')==projection_sha256[sid]
             and isinstance(epochs,list) and epochs and epochs[-1].get('segment')==source['segment']
             and epochs[-1].get('profile_sha256')==source['profile_sha256'],'producer_completion_source_mismatch')
        result[sid]=hashlib.sha256(data).hexdigest()
    return result


def write_roster_event(value, output, transitions, compact_output, output_order, compactor, output_index, perf):
    """Write one bounded coordinator event through both exact output forms."""
    from compact_live_roster import encode as compact_encode
    from aggregate_partitions import canonical
    mark=perf.begin();encoded=canonical(value)+b'\n';perf.end('serialize',mark,len(encoded));transition=value.get('schema')in ('overwatch-decoder.live-roster-transition/1','overwatch-decoder.live-roster-startup/1')
    need(transition or value.get('schema')=='overwatch-decoder.partition-research-live/1','coordinator_output_schema')
    detailed=transitions if transition else output
    write_flushed(detailed,encoded,perf)
    mark=perf.begin()
    try:compact_value=compactor._consume_decoded(encoded,value)
    finally:perf.end('compact',mark,len(encoded))
    mark=perf.begin();compact_raw=compact_encode(compact_value);perf.end('serialize',mark,len(compact_raw))
    write_flushed(compact_output,compact_raw,perf)
    write_flushed(output_order,json.dumps(dict(output_index=output_index,detailed_file='transitions.jsonl'if transition else'combined-entities.jsonl',schema=value['schema'],detailed_sha256=hashlib.sha256(encoded).hexdigest(),compact_sha256=hashlib.sha256(compact_raw).hexdigest()),separators=(',',':'))+'\n',perf)
    return transition


def aggregate_existing(bundle,plan,roles,children,out,clock,*,live=True,ready_timeout=45,total_timeout=150,raw_candidates=False):
    need(1<=ready_timeout<=60 and 1<=total_timeout<=180,'aggregate_time_bounds')
    # Decoder imports resolve beside this tracked entrypoint.
    from live_roster_epochs import LiveRosterEpochs
    from compact_live_roster import CompactLiveRoster,encode as compact_encode
    from aggregate_partitions import canonical
    rolemap,primary=reviewed_inputs(plan,roles,raw_candidates=raw_candidates)
    need({c['source_id']for c in children}=={f'p{i}'for i in range(1,len(plan['partitions'])+1)} and len(children)==len(plan['partitions']) and {c['ordinal']for c in children}==set(range(1,len(plan['partitions'])+1)),'unique_partition_children')
    started=time.monotonic();deadline=started+min(total_timeout,180);ready={};pins={};streams={};done=set();error=None;adapter=None
    projection_counts={c['source_id']:0 for c in children};projection_hashes={c['source_id']:hashlib.sha256() for c in children}
    metadata=NativeMetadata();compactor=CompactLiveRoster();perf=ParentPerformance();proof_schedule=ProofSchedule();received=full=windows=transition_count=0;maximum_skew=0;sources={};full_by_revision={};proofs={};last_poll=0;manifest_snapshot_bytes=0;absence_proofs=RawAbsenceProofs()
    warm=None;warm_order=None
    if raw_candidates and live:
        from runtime_startup import StartupSources
        warm=StartupSources(plan['target'],clock.frequency,raw_candidates=True)
        warm_order=(Path(out)/'startup-input-order.jsonl').open('xb')
    try:
        while True:
            warm_progress=False
            need(time.monotonic()-started<ready_timeout,'first_frame_readiness_deadline')
            for child in children:
                sid=child['source_id']
                if sid in ready:
                    if warm is not None:
                        file=streams[sid]
                        # Two lines per source keeps all admitted sources fair.
                        # No latest-only read or guard validation is skipped.
                        for _ in range(2):
                            at=file.tell();line=file.readline(MAX_LINE+1);need(len(line)<=MAX_LINE,'oversized_startup_line')
                            if not line or not line.endswith(b'\n'):file.seek(at);break
                            mark=perf.begin()
                            try:meta=warm.consume(sid,line)
                            finally:perf.end('startup_validation',mark,len(line))
                            warm_progress=True
                            write_flushed(warm_order,(json.dumps(dict(startup_index=warm.events-1,source_id=sid,projection_sha256=hashlib.sha256(line).hexdigest(),
                                segment=meta['segment'],frame_sequence=meta['timing']['sequence'],start_ticks=meta['timing']['start_ticks'],end_ticks=meta['timing']['end_ticks']),separators=(',',':'))+'\n').encode(),perf)
                    continue
                directory=Path(child['directory']);epoch=directory/'epoch-0001'
                if (directory/'result.json').exists():
                    result=shared_json(directory/'result.json');need(result.get('complete')is True and not result.get('error'),'producer_failed_before_admission')
                if not all(p.exists()for p in [directory/'entities.jsonl',directory/'native.jsonl'] + ([] if raw_candidates else [epoch/'category.contract.json',epoch/'category.mode-review.json',epoch/'category.segment-start.json'])):continue
                with (directory/'entities.jsonl').open('rb')as f:line=f.readline(MAX_LINE+1)
                need(len(line)<=MAX_LINE,'oversized_first_line')
                if not line.endswith(b'\n'):continue
                mark=perf.begin()
                try:ready[sid]=source_admission(child,plan,rolemap,primary,metadata,initial=True,raw_candidates=raw_candidates)
                except ValueError as exc:
                    if str(exc)!='native_metadata_not_yet_complete':raise
                finally:perf.end('admission',mark,len(line))
                if sid in ready and warm is not None:
                    warm.add(ready[sid][0]);streams[sid]=(directory/'entities.jsonl').open('rb')
            if len(ready)==len(children)and (warm is None or warm.current(ready,clock.tick())):break
            if not warm_progress:
                mark=perf.begin();time.sleep(.025);perf.end('idle',mark)
        roster={};starts=[]
        for child in children:
            sid=child['source_id'];source,frame,pin=ready[sid];sources[sid]=source;pins[sid]=[pin]
            need(frame['timing']['monotonic_frequency']==clock.frequency,'common_windows_qpc_frequency')
            for pair in source['objects']:
                ck=pair['controller_object_key']
                if ck in roster:need(roster[ck]['body_object_key']==pair['body_object_key'],'shared_controller_body_conflict')
                else:roster[ck]=dict(pair,primary_source_id=f'p{primary[ck]}')
            starts.append(frame['timing']['start_ticks'])
            if warm is None:streams[sid]=(Path(child['directory'])/'entities.jsonl').open('rb')
            else:
                projection_counts[sid]=warm.counts[sid];projection_hashes[sid]=warm.hashes[sid].copy()
        width=clock.frequency//10
        config=dict(schema='overwatch-decoder.live-partition-config/1',epoch_id=Path(out).name,clock_domain_id='same-windows-host-native-qpc'if live else'offline_saved_source_clock',
            target=plan['target'],monotonic_frequency=clock.frequency,window_origin_ticks=min(starts)//width*width,
            window_ticks=width,maximum_skew_ticks=clock.frequency*150//1000,maximum_origin_offset_ticks=clock.frequency//100,
            sources=list(sources.values()),roster=list(roster.values()))
        if raw_candidates:config.update(observation_mode='raw-candidates',allow_unresolved_bodies=True)
        raw_config=canonical(config)+b'\n';(Path(out)/'aggregate-config.json').write_bytes(raw_config);save(Path(out)/'source-admissions.json',pins)
        adapter=LiveRosterEpochs(raw_config)
        with (Path(out)/'combined-entities.jsonl').open('xb')as output,(Path(out)/'transitions.jsonl').open('xb')as transitions,(Path(out)/'aggregate-input-order.jsonl').open('x',encoding='utf-8')as order,(Path(out)/'aggregate-receipts.jsonl').open('x',encoding='utf-8')as receipts,(Path(out)/'compact-roster.jsonl').open('xb')as compact_output,(Path(out)/'aggregate-output-order.jsonl').open('x',encoding='utf-8')as output_order:
            if warm is not None:
                for value in adapter._adopt_startup(warm,clock.tick()):
                    need(write_roster_event(value,output,transitions,compact_output,output_order,compactor,windows+transition_count,perf),'startup_must_be_unknown')
                    transition_count+=1
                save(Path(out)/'startup-validation.json',adapter.startup)
            while True:
                need(time.monotonic()<deadline,'aggregate_total_deadline');changed=False
                for child in children:
                    sid=child['source_id']
                    if sid in done:continue
                    mark=perf.begin();file=streams[sid];at=file.tell();raw=file.readline(MAX_LINE+1);perf.end('read',mark,len(raw));need(len(raw)<=MAX_LINE,'projection_line_bound')
                    if not raw or not raw.endswith(b'\n'):
                        file.seek(at);result=Path(child['directory'])/'result.json'
                        if result.exists():
                            need(not raw,'unterminated_completed_projection');r=shared_json(result)
                            need(r.get('complete')is True and r.get('native_exit')==0 and not r.get('error'),'producer_failed')
                            need(1<=len(r.get('epochs',[]))<=128,'producer_epoch_count');done.add(sid)
                        continue
                    mark=perf.begin()
                    try:frame,current,pin,events,operation=route_projection(adapter,child,raw,sources[sid],plan,rolemap,primary,metadata,perf,raw_candidates=raw_candidates)
                    except ValueError as exc:
                        if str(exc)!='native_metadata_not_yet_complete':raise
                        file.seek(at);continue
                    finally:perf.end('route',mark,len(raw))
                    if operation=='admit':
                        sources[sid]=current;pins[sid].append(pin)
                        save(Path(out)/'source-admissions.json',pins);save(Path(out)/f"admission-{sid}-segment-{current['segment']:04d}.json",dict(source=current,pins=pin))
                    changed=True;projection_counts[sid]+=1;projection_hashes[sid].update(raw)
                    write_flushed(order,json.dumps(dict(input_index=received,source_id=sid,operation=operation,segment=frame['segment'],projection_sha256=hashlib.sha256(raw).hexdigest(),accepted_qpc=clock.tick()),separators=(',',':'))+'\n',perf);received+=1
                    if raw_candidates:absence_proofs.observe(child,current,frame,raw,out,clock,plan['target'],live=live)
                    for value in events:
                        transition=write_roster_event(value,output,transitions,compact_output,output_order,compactor,windows+transition_count,perf)
                        if transition:
                            transition_count+=1
                            print(json.dumps(dict(roster_transition=value['status'],revision=value['revision'])),flush=True);continue
                        windows+=1
                        all_fields=len(value['relations'])==len(rolemap) and all(r['status']=='observed'and all(r['authoritative_observation']['relation'].get(k)is not None for k in (RAW_REQUIRED if raw_candidates else REQUIRED))for r in value['relations'])
                        full+=all_fields;maximum_skew=max(maximum_skew,value['observed_skew_ticks']or 0);state=adapter.status();revision=state['revision']
                        full_by_revision[revision]=full_by_revision.get(revision,0)+int(all_fields)
                        published=clock.tick();end=value['observed_read_end_ticks'];need(end is None or published>=end,'publication_before_source_read')
                        receipt=dict(window_index=value['window_index'],revision=revision,config_sha256=value['config_sha256'],publication_qpc=published,monotonic_frequency=clock.frequency,
                            publication_utc_ns=clock.utc_ns(),all_requested_fields=all_fields,mode='connected_windows_local'if live else'offline_saved_source_test',
                            source_result_files_present={c['source_id']:(Path(c['directory'])/'result.json').exists()for c in children},latest_observed_read_end_ticks=end,read_end_to_publication_ticks=None if end is None else published-end)
                        write_flushed(receipts,json.dumps(receipt,separators=(',',':'))+'\n',perf)
                        if all_fields and full_by_revision[revision]==1:print(json.dumps(dict(first_complete_roster=True,revision=revision,actors=len(rolemap),windows=windows)),flush=True)
                        if live and all_fields and proof_schedule.due(revision,full_by_revision[revision],revision in proofs,time.monotonic()):
                            proof_mark=perf.begin();statuses=[];snapshots=[];active=True
                            try:
                                for c in children:
                                    path=Path(c['directory'])/'native/manifest.json';mraw=shared_bytes(path);m=parse(mraw);source=sources[c['source_id']]
                                    need(m.get('target')==plan['target']and m.get('session_id')==source['session_id'],'native_target_or_session_changed')
                                    expected=f"segment-{source['segment']:04d}"
                                    active=active and m.get('status')=='running'and m.get('active_operation')=='recording'and m.get('active_directory')==expected
                                    snapshots.append(mraw)
                                    statuses.append(dict(source_id=c['source_id'],status=m.get('status'),active_operation=m.get('active_operation'),session_id=m['session_id'],active_directory=m.get('active_directory'),expected_directory=expected,native_manifest_sha256=hashlib.sha256(mraw).hexdigest(),target=m['target'],read_qpc=clock.tick()))
                                if active:
                                    statuses,manifest_snapshot_bytes=retain_native_manifests(out,revision,statuses,snapshots,manifest_snapshot_bytes)
                                    proof=dict(revision=revision,after_complete_windows=full_by_revision[revision],window_index=value['window_index'],config_sha256=value['config_sha256'],publication_qpc=published,monotonic_frequency=clock.frequency,read_qpc=clock.tick(),sequential_checks_not_atomic=True,rows=statuses)
                                    proofs[revision]=proof;save(Path(out)/f'aggregate-midrun-proof-revision-{revision:04d}.json',proof)
                                    print(json.dumps(dict(all_sources_native_recording=True,revision=revision,after_complete_windows=full_by_revision[revision])),flush=True)
                            finally:perf.end('active_proof',proof_mark,sum(map(len,snapshots)))
                if live and raw_candidates and absence_proofs.ready(sources):
                    revision=adapter.status()['revision']
                    if proof_schedule.due(revision,20,revision in proofs,time.monotonic()):
                        found=[active_source_manifest(c,sources[c['source_id']],plan['target'],clock)for c in children]
                        if all(item is not None for item in found):
                            statuses=[item[0]for item in found];snapshots=[item[1]for item in found]
                            statuses,manifest_snapshot_bytes=retain_native_manifests(out,revision,statuses,snapshots,manifest_snapshot_bytes)
                            proof=dict(revision=revision,after_complete_windows=full_by_revision.get(revision,0),
                                trigger='twenty_accepted_controller_frames_per_source_during_explicit_body_absence',
                                accepted_frames={sid:absence_proofs.counts[(sid,source['segment'])]for sid,source in sources.items()},
                                config_sha256=adapter.status()['config_sha256'],read_qpc=clock.tick(),
                                monotonic_frequency=clock.frequency,sequential_checks_not_atomic=True,rows=statuses)
                            proofs[revision]=proof;save(Path(out)/f'aggregate-midrun-proof-revision-{revision:04d}.json',proof)
                if time.monotonic()-last_poll>=1:
                    mark=perf.begin();save(Path(out)/'roster-status.json',adapter.status());save(Path(out)/'parent-performance.json',dict(perf.snapshot(),proof_schedule=proof_schedule.snapshot()));perf.end('status',mark);last_poll=time.monotonic()
                if len(done)==len(children):
                    completed=completed_producer_results(children,sources,projection_counts,{sid:h.hexdigest() for sid,h in projection_hashes.items()})
                    for value in adapter.end_input(clock.tick(),completed):
                        need(write_roster_event(value,output,transitions,compact_output,output_order,compactor,windows+transition_count,perf), 'terminal_event_must_be_unknown')
                        transition_count+=1
                    break
                if not changed:
                    mark=perf.begin();time.sleep(.01);perf.end('idle',mark)
    except Exception as exc:error=repr(exc)
    finally:
        for f in streams.values():f.close()
        if warm_order is not None:warm_order.close()
        metadata.close()
        summary={}if adapter is None else adapter.close()  # No EOF advance/flush.
        summary.update(schema='overwatch-decoder.local-roster-runtime-result/1',transport_error=error,input_events=received,windows=windows,transition_records=transition_count,
            complete_field_windows=full,complete_field_windows_by_revision=full_by_revision,active_proof_revisions=sorted(proofs),native_manifest_snapshot_bytes=manifest_snapshot_bytes,maximum_observed_skew_ticks=maximum_skew,
            mode='connected_windows_local'if live else'offline_saved_source_test',elapsed_s=time.monotonic()-started,runtime_schema=RUNTIME_SCHEMA,
            public_state_eligible=False,durability_verified=False,performance=perf.snapshot(),proof_schedule=proof_schedule.snapshot(),compact=compactor.summary(),source_result_hashes={c['source_id']:digest(Path(c['directory'])/'result.json')for c in children if (Path(c['directory'])/'result.json').exists()})
        if warm is not None:
            summary['startup']=getattr(adapter,'startup',warm.summary())
            summary['startup_input_order_sha256']=digest(Path(out)/'startup-input-order.jsonl')
            summary['startup_validated_frames']=sum(warm.counts.values())
            summary['total_validated_input_frames']=received+sum(warm.counts.values())
            summary['input_order_scope']='aggregate-input-order excludes separately hashed startup-input-order'
        if raw_candidates:
            summary.update(observation_mode='raw-candidates',requested_fields=list(RAW_REQUIRED),roster_completeness='supplied_census_only',self_identity_inferred=False,unresolved_native_proofs=absence_proofs.summary())
        f=Path(out)/'combined-entities.jsonl'
        if f.exists():summary['output_sha256']=digest(f)
        if (Path(out)/'transitions.jsonl').exists():summary['transitions_sha256']=digest(Path(out)/'transitions.jsonl')
        if (Path(out)/'compact-roster.jsonl').exists():summary['compact_sha256']=digest(Path(out)/'compact-roster.jsonl')
        if (Path(out)/'aggregate-output-order.jsonl').exists():summary['output_order_sha256']=digest(Path(out)/'aggregate-output-order.jsonl')
        save(Path(out)/'parent-performance.json',dict(summary['performance'],proof_schedule=summary['proof_schedule']))
        save(Path(out)/'aggregate-result.json',summary)
    if error is not None and adapter is None:
        raise PreAdmissionFailure('aggregate_failed: '+str(error))
    need(error is None,'aggregate_failed: '+str(error))
    need(not live or not raw_candidates or absence_proofs.summary()['all_required_proved'],'active_native_proof_not_obtained_for_unresolved_epoch')
    need(not live or set(proofs)==set(range(1,summary['revision']+1)),'active_native_proof_not_obtained_for_every_revision')
    return summary


def observe_partial_sources(bundle,plan,roles,children,out,clock,*,ready_timeout=45,total_timeout=150,live=True,allow_controller_subsets=False):
    """Opt-in independent observations; full-roster admission is not attempted."""
    from runtime_partial import PartialSources,PartialOutputFailure,EncodedPartialEvent,MAX_TOTAL_BYTES,MAX_LINE_BYTES
    from aggregate_partitions import canonical
    rolemap,primary=reviewed_inputs(plan,roles,raw_candidates=True)
    need(1<=ready_timeout<=60 and 1<=total_timeout<=180,'partial_time_bounds')
    ids={f'p{part["ordinal"]}':part['recipe_sha256'] for part in plan['partitions']}
    need({c['source_id'] for c in children}==set(ids) and len(children)==len(ids),'partial_children')
    need(type(allow_controller_subsets)is bool,'controller_subset_policy_type')
    if allow_controller_subsets:
        for part in plan['partitions']:controller_subset_policy(plan,part,primary)
    perf=ParentPerformance()
    def encode_event(value):
        value=dict(value,publication_qpc_scope='before_serialization_write_flush',publication_qpc=clock.tick() if live else None,publication_monotonic_frequency=clock.frequency if live else None,
            publication_mode='windows_local' if live else 'offline_saved_source_replay')
        timing=(value.get('source_observation')or{}).get('timing')
        need(not live or timing is None or value['publication_qpc']>=timing['end_ticks'],'partial_publication_before_read')
        mark=perf.begin()
        encoded=canonical(value)+b'\n'
        perf.end('serialize',mark,len(encoded))
        return encoded
    partial=PartialSources(plan['target'],clock.frequency,{ck:f'p{n}' for ck,n in primary.items()},ids,plan['census_source'],
        allow_controller_subsets=allow_controller_subsets,
        partition_controllers={f'p{part["ordinal"]}':[r['controller_object_key']for r in part['controllers']]for part in plan['partitions']} if allow_controller_subsets else None,
        required_context_controller_key=plan.get('context_controller_object_key'),event_encoder=encode_event)
    metadata=NativeMetadata();streams={};done=set();completed={};pins={};started=time.monotonic();error=None
    emitted_bytes=emitted_events=published_observations=0
    out=Path(out)
    def receipt(child):
        directory=Path(child['directory']);value={}
        for name in ('result.json','native/manifest.json'):
            path=directory/name
            if path.exists():value[name.replace('/','_')+'_sha256']=digest(path)
        return value
    with (out/'partial-entities.jsonl').open('xb') as output:
        def emit(value):
            nonlocal emitted_bytes,emitted_events,published_observations
            try:
                need(isinstance(value,EncodedPartialEvent),'partial_encoded_event_required')
                encoded=value.data
                need(len(encoded)<=4*MAX_LINE_BYTES and emitted_bytes+len(encoded)<=MAX_TOTAL_BYTES,'partial_emitted_output_bound')
                write_flushed(output,encoded,perf)
            except Exception as exc:
                # A failed write may already have emitted a partial JSON line.
                # No later event, including input_end, may append to that line.
                partial.output_failed=True
                raise PartialOutputFailure(str(exc)) from exc
            emitted_bytes+=len(encoded);emitted_events+=1;published_observations+=value.kind=='observation'
        def reject(child,reason):
            sid=child['source_id'];emit(partial.unavailable(sid,reason,receipt(child)));done.add(sid)
        try:
            while len(done)<len(children):
                progress=False
                if time.monotonic()-started>=total_timeout:
                    for child in children:
                        if child['source_id'] not in done:reject(child,'finite_observation_deadline')
                    break
                for child in children:
                    sid=child['source_id'];directory=Path(child['directory'])
                    if sid in done:continue
                    try:
                        if sid not in partial.sources and time.monotonic()-started>=ready_timeout:
                            reject(child,'source_readiness_deadline');continue
                        if sid not in streams and (directory/'entities.jsonl').exists():streams[sid]=(directory/'entities.jsonl').open('rb')
                        mark=perf.begin();file=streams.get(sid);at=file.tell() if file else 0;raw=file.readline(MAX_LINE+1) if file else b'';perf.end('read',mark,len(raw))
                        need(len(raw)<=MAX_LINE,'partial_projection_line_bound')
                        if raw and raw.endswith(b'\n'):
                            mark=perf.begin();frame=parse(raw);perf.end('parent_parse',mark,len(raw));current=partial.sources.get(sid)
                            if current is None or frame.get('segment')!=current['segment']:
                                mark=perf.begin()
                                try:source,_,pin=source_admission(child,plan,rolemap,primary,metadata,raw,initial=current is None,raw_candidates=True,allow_controller_subsets=allow_controller_subsets)
                                except ValueError as exc:
                                    if str(exc)!='native_metadata_not_yet_complete':raise
                                    file.seek(at);continue
                                finally:perf.end('admission',mark,len(raw))
                                partial.admit(source,pin);pins.setdefault(sid,[]).append(dict(source=source,pins=pin))
                                save(out/'partial-source-admissions.json',pins)
                            mark=perf.begin()
                            try:value=partial._consume_decoded(sid,raw,frame)
                            finally:perf.end('coordinator',mark,len(raw))
                            emit(value);progress=True
                        else:
                            if file:file.seek(at)
                            result=directory/'result.json'
                            if result.exists():
                                need(not raw,'unterminated_completed_projection')
                                need(sid in partial.sources,'source_ended_before_admission')
                                completed.update(completed_producer_results([child],partial.sources,partial.counts,
                                    {sid:partial.hashes[sid].hexdigest()}));done.add(sid)
                                emit(partial.finish(sid,dict(result_sha256=completed[sid])))
                            elif sid not in partial.sources and time.monotonic()-started>=ready_timeout:
                                reject(child,'source_readiness_deadline')
                    except PartialOutputFailure:raise
                    except (ValueError,KeyError,TypeError,OSError) as exc:
                        if str(exc) in ('partial_output_bound','partial_input_bound'):raise
                        reject(child,repr(exc)[:1024]);progress=True
                if not progress:
                    mark=perf.begin();time.sleep(.01);perf.end('idle',mark)
        except Exception as exc:error=repr(exc)
        finally:
            for file in streams.values():file.close()
            metadata.close()
            try:emit(partial.end())
            except Exception as exc:error=error or repr(exc)
    performance=perf.snapshot();performance['nested_stages']['coordinator']=['serialize']
    save(out/'partial-performance.json',dict(performance,runtime_mode='partial_independent_sources'))
    summary=partial.summary();summary.update(complete=error is None and not partial.closed and len(completed)==len(children) and summary.get('all_census_primaries_acquired',True),
        error=error,fatal_error=error,capture_finished=error is None and len(done)==len(children),
        attempted_output_events=partial.output_events,output_events=emitted_events,output_bytes=emitted_bytes,published_observations=published_observations,
        all_sources_verified=not partial.closed and len(completed)==len(children),unavailable_sources=sorted(partial.closed),
        mode='windows_local' if live else 'offline_saved_source_replay',
        completed_source_result_sha256=completed,elapsed_s=time.monotonic()-started,
        output_sha256=digest(out/'partial-entities.jsonl'),public_state_eligible=False,durability_verified=False)
    save(out/'partial-result.json',summary)
    return summary


def verify_runtime_inventory(bundle, expected_sha256=None, *, required_modules=(), required_files=()):
    raw=shared_bytes(Path(bundle)/'inventory.json');need(expected_sha256 is None or hashlib.sha256(raw).hexdigest()==expected_sha256,'runtime_inventory_pin');inventory=parse(raw);need(isinstance(inventory,dict)and 0<len(inventory)<=4096,'runtime_inventory_bound')
    total=0;root=Path(bundle).resolve()
    for name,expected in inventory.items():
        path=(root/name).resolve();need(path.is_relative_to(root)and path.is_file(),'runtime_inventory_path')
        size=path.stat().st_size;total+=size;need(total<=512*1024*1024 and size==expected['bytes']and digest(path)==expected['sha256'],'runtime_inventory_mismatch')
    for module in ('runtime_roster.py','runtime_producer.py','runtime_jobs.py',*required_modules):
        relative='tools/entity-decoder/'+module
        need(relative in inventory and digest(Path(__file__).with_name(module))==inventory[relative]['sha256'],'runtime_entrypoint_not_in_inventory')
    for relative in required_files:
        need(relative in inventory
             and digest(_BUNDLE_ROOT/relative)==inventory[relative]['sha256'],
             'runtime_dependency_not_in_inventory')
    return dict(inventory_sha256=hashlib.sha256(raw).hexdigest(),files=len(inventory),bytes=total,runner_sha256=digest(__file__),runtime_schema=RUNTIME_SCHEMA)


def bundled_producer_config(bundle, ordinal):
    """All caller assets executed/read initially must belong to the pinned bundle."""
    root=Path(bundle).resolve();inventory=shared_json(root/'inventory.json')
    relative=f'p{ordinal}.json';need(relative in inventory,'producer_config_not_in_inventory')
    raw=shared_bytes(root/relative)
    need(hashlib.sha256(raw).hexdigest()==inventory[relative]['sha256'],'producer_config_hash')
    config=parse(raw)
    from runtime_producer import asset_keys
    keys=asset_keys(config);raw_candidates=config.get('observation_mode')=='raw-candidates'
    paths=[config.get(key) for key in keys if key!='native_exe']
    modes=config.get('reviewed_mode_sources',[])
    need(isinstance(modes,list) and (raw_candidates and not modes or not raw_candidates and 1<=len(modes)<=32),'producer_mode_sources')
    for value in paths+modes:
        need(isinstance(value,str) and value,'producer_asset_path')
        path=(root/value).resolve()
        need(path.is_relative_to(root) and path.relative_to(root).as_posix() in inventory,'producer_asset_not_in_inventory')
        expected=inventory[path.relative_to(root).as_posix()]
        need(path.stat().st_size==expected['bytes'] and digest(path)==expected['sha256'],'producer_asset_hash')
    # Resolve relative caller paths before saving the child config outside bundle.
    for key in keys:
        config[key]=str((root/config[key]).resolve())
    if not raw_candidates:config['reviewed_mode_sources']=[str((root/path).resolve()) for path in modes]
    return config


def cleanup_owned(workers, deadline):
    """Join/terminate only handles created by this parent, within its deadline."""
    failures=[]
    for process,_,child in workers:
        if process.poll() is None:
            child['owned_collector_termination_required']=True
            try:process.terminate()
            except OSError as exc:failures.append(repr(exc))
    for process,log,child in workers:
        try:
            if process.poll() is None:
                try:process.wait(timeout=max(.001,min(2,deadline-time.monotonic())))
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=max(.001,min(1,deadline-time.monotonic())))
            child['exit_code']=process.poll()
            if child['exit_code'] is None:failures.append('owned_process_not_joined')
        except (OSError,subprocess.TimeoutExpired) as exc:
            child['cleanup_error']=repr(exc);failures.append(repr(exc))
        finally:
            job=getattr(process,'_overwatch_decoder_owned_job',None)
            if job is None:
                child['owned_job_cleanup_error']='owned_producer_job_missing'
                failures.append('owned_producer_job_missing')
            else:
                try:
                    job.terminate_and_close(deadline)
                    child['owned_job_closed']=True
                except OSError as exc:
                    child['owned_job_cleanup_error']=repr(exc);failures.append(repr(exc))
            log.close()
    return failures


def launch(args):
    start=time.monotonic()
    need(sys.platform=='win32','windows_live_clock_required')
    bundle=args.bundle.resolve();out=args.output.resolve();need(not out.exists()and not out.is_relative_to(bundle),'new_output_outside_bundle_required')
    need(Path(__file__).resolve().parent == (bundle/'tools/entity-decoder').resolve(),'execute_bundled_entrypoint_required')
    raw_candidates=args.mode=='raw-candidates'
    partial_sources=getattr(args,'partial_sources',False)
    allow_controller_subsets=getattr(args,'allow_controller_subsets',False)
    need(type(allow_controller_subsets)is bool and (not allow_controller_subsets or partial_sources and raw_candidates),'controller_subsets_require_partial_raw_mode')
    need(type(partial_sources)is bool and (not partial_sources or raw_candidates),'partial_sources_require_raw_mode')
    runtime=verify_runtime_inventory(bundle,args.inventory_sha256,required_modules=(('runtime_partial.py',) if partial_sources else ()) + (('controller_subset_projection.py',) if allow_controller_subsets else ()))
    plan_raw=shared_bytes(args.plan);plan=parse(plan_raw)
    if raw_candidates:
        need(args.role_map is None and args.census_acquisition is not None,'raw_census_without_role_map_required')
        inventory=shared_json(bundle/'inventory.json')
        for asset in [args.plan]+[args.census_acquisition/name for name in ('manifest.json','profile.json','recipe.json','evidence.jsonl')]:
            resolved=asset.resolve();need(resolved.is_relative_to(bundle) and resolved.relative_to(bundle).as_posix() in inventory,'raw_input_not_in_inventory')
            need(digest(resolved)==inventory[resolved.relative_to(bundle).as_posix()]['sha256'],'raw_input_hash')
        from plan_live_roster import verified_census
        roles=raw_roster_inputs(plan,verified_census(args.census_acquisition,expected_target=plan['target']))
        role_raw=(json.dumps(roles,indent=2)+'\n').encode()
    else:
        need(args.role_map is not None and args.census_acquisition is None,'reviewed_role_map_required')
        role_raw=shared_bytes(args.role_map);roles=parse(role_raw)
    reviewed_inputs(plan,roles,raw_candidates=raw_candidates)
    out.mkdir(parents=True);(out/'plan.json').write_bytes(plan_raw);(out/'current-role-map.json').write_bytes(role_raw)
    clock=WindowsClock();workers=[];children=[];error=None;aggregate=None
    aggregate_started=False;stop_before_admission=False
    status=dict(schema=RUNTIME_SCHEMA,complete=False,plan_sha256=hashlib.sha256(plan_raw).hexdigest(),
        role_map_sha256=hashlib.sha256(role_raw).hexdigest(),runner_sha256=digest(__file__),producer_sha256=digest(Path(__file__).with_name('runtime_producer.py')),
        target=plan['target'],runtime=runtime,runtime_schema=RUNTIME_SCHEMA,started_qpc=clock.tick(),monotonic_frequency=clock.frequency,children=children,public_state_eligible=False)
    try:
        ammunition_runtime_checked = False
        health_ratio_runtime_checked = False
        for part in sorted(plan['partitions'],key=lambda p:p['ordinal']):
            n=part['ordinal'];original=bundle/f'p{n}.json';c=bundled_producer_config(bundle,n)
            need((c.get('observation_mode','reviewed')=='raw-candidates')==raw_candidates,'parent_producer_mode_mismatch')
            need(c['target']==plan['target']and c['recipe_sha256']==part['recipe_sha256']and c.get('private_controlled_fixture_reviewed')is True,'producer_config_review')
            need(type(c.get('allow_controller_subsets',False))is bool and c.get('allow_controller_subsets',False)==allow_controller_subsets,'producer_controller_subset_mode_mismatch')
            if allow_controller_subsets:
                _,primary=reviewed_inputs(plan,roles,raw_candidates=True)
                need(c.get('controller_subset_policy')==controller_subset_policy(plan,part,primary),'producer_controller_subset_policy_mismatch')
            else:need(c.get('controller_subset_policy')is None,'producer_controller_subset_policy_disabled')
            if 'ammunition_composer' in c and not ammunition_runtime_checked:
                verify_runtime_inventory(bundle, args.inventory_sha256,
                    required_modules=('ammunition_projection_validation.py',))
                ammunition_runtime_checked = True
            if 'health_ratio_layout' in c and not health_ratio_runtime_checked:
                verify_runtime_inventory(bundle, args.inventory_sha256,
                    required_modules=('build_health_ratio_contracts.py', 'health_ratio_validation.py'),
                    required_files=('overwatch_decoder/__init__.py', 'overwatch_decoder/health_ratio.py', 'overwatch_decoder/health_projection.py'))
                health_ratio_runtime_checked = True
            c.update(output=str(out/f'p{n}'),seconds=args.seconds,interval_ms=args.interval_ms)
            path=out/f'p{n}-config.json';save(path,c);log=(out/f'p{n}-producer.log').open('xb')
            try:
                from runtime_jobs import spawn_producer
                process=spawn_producer([sys.executable,str(Path(__file__).with_name('runtime_producer.py')),str(path)],cwd=bundle,stdout=log,stderr=subprocess.STDOUT)
            except BaseException:
                log.close();raise
            child=dict(source_id=f'p{n}',ordinal=n,pid=process.pid,directory=c['output'],config_sha256=digest(path),original_config_sha256=digest(original),started_qpc=clock.tick())
            if 'ammunition_composer' in c:
                child['ammunition_output_enabled'] = True
            if 'health_ratio_layout' in c:
                child['health_ratio_input_pins'] = {key: c[key] for key in (
                    'health_layout_sha256', 'health_ratio_layout_sha256',
                    'health_ratio_native_review_sha256')}
            children.append(child);workers.append((process,log,child));save(out/'status.json',status)
            time.sleep(.25)
        aggregate_started=True
        if partial_sources:
            aggregate=observe_partial_sources(bundle,plan,roles,children,out,clock,ready_timeout=args.ready_timeout,
                total_timeout=min(args.seconds+args.ready_timeout+15,165-(time.monotonic()-start)),allow_controller_subsets=allow_controller_subsets)
            need(aggregate['complete'],'partial_sources_incomplete')
        else:
            aggregate=aggregate_existing(bundle,plan,roles,children,out,clock,live=True,ready_timeout=args.ready_timeout,total_timeout=min(args.seconds+args.ready_timeout+15,165-(time.monotonic()-start)),raw_candidates=raw_candidates)
    except Exception as exc:
        error=repr(exc);status['error']=error
        stop_before_admission=partial_sources or not aggregate_started or isinstance(exc,PreAdmissionFailure)
        save(out/'status.json',status)
    finally:
        # A failed startup cannot admit a roster. Preserve every producer file,
        # but do not spend the remaining capture window waiting for other jobs.
        # Admitted runs keep the existing bounded settle behavior.
        if not stop_before_admission:
            settle=min(start+args.seconds+args.cleanup_seconds+5,start+165)
            while any(p.poll()is None for p,_,_ in workers)and time.monotonic()<settle:time.sleep(.1)
        cleanup_deadline=min(start+180,time.monotonic()+args.cleanup_seconds) if stop_before_admission else start+180
        cleanup_errors=cleanup_owned(workers,cleanup_deadline)
        if cleanup_errors:error=error or 'owned_cleanup_failed: '+repr(cleanup_errors)
        status.update(complete=error is None and aggregate is not None and all(c.get('exit_code')==0 for c in children),
            finished_qpc=clock.tick(),elapsed_s=time.monotonic()-start,error=error)
        save(out/'status.json',status)
    print(json.dumps(dict(complete=status['complete'],output=str(out),error=error)),flush=True)
    return 0 if status['complete'] else 2


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('bundle','plan','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--role-map',type=Path)
    p.add_argument('--census-acquisition',type=Path)
    p.add_argument('--mode',choices=('reviewed','raw-candidates'),default='reviewed')
    p.add_argument('--partial-sources',action='store_true',help='Raw-only independent partial stream; no common-time aggregate.')
    p.add_argument('--allow-controller-subsets',action='store_true',help='Partial raw sources only: fresh surviving original controllers; omitted primaries remain unknown.')
    p.add_argument('--inventory-sha256',required=True)
    p.add_argument('--seconds',type=int,default=60);p.add_argument('--interval-ms',type=int,default=50)
    p.add_argument('--ready-timeout',type=int,default=45);p.add_argument('--cleanup-seconds',type=int,default=30)
    args=p.parse_args();need(15<=args.seconds<=180 and args.seconds+args.ready_timeout+args.cleanup_seconds+5<=165 and 20<=args.interval_ms<=1000 and 5<=args.ready_timeout<=60 and 5<=args.cleanup_seconds<=60,'finite_time_bounds')
    return launch(args)


if __name__=='__main__':
    try:raise SystemExit(main())
    except (ValueError,OSError,KeyError)as error:print(json.dumps(dict(complete=False,error=str(error))),file=sys.stderr);raise SystemExit(2)
