"""Synthetic live acceptance, epoch, evidence and bounded delivery tests."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from live_relations import LiveRelations, InvalidLive, stream, MAX_LINE
from test_relations import fixture, prepare

SESSION = 'a' * 32

def raw(value):
    return json.dumps(value, separators=(',', ':')).encode() + b'\n'


def setup(root, cache=False, health=False):
    profile, values = fixture()
    if cache:
        for i, byte in enumerate(b'Example\0'):
            name = f'controller_0000_cached_label_0000_byte_{i:04}_value'
            profile['fields'].append(dict(name=name, type='u8', address=0x4000+i)); values[name] = byte
    if health:
        profile['guards'].append(dict(address=0x5000, bytes_hex='01000000'))
        name='controller_0000_body_0000_pool_0000_direct_candidate'
        profile['fields'].append(dict(name=name, type='f32', address=0x5010)); values[name]=125.5
    profile['fields'].append(dict(name='controller_0000_body_0000_position_candidate', type='f32x3', address=0x6000))
    values['controller_0000_body_0000_position_candidate']=[1.0,2.0,3.0]
    decoder, frame = prepare(profile, values)
    for name, value in frame['fields'].items():
        value['type'] = decoder.fields[name]['type']; value['reason']=None
    frame.update(interpretation='profile_declared_research', visibility='research', runtime_semantics_validated=False,
        public_state_eligible=False, atomic=False, scheduled_slot=0, scheduled_ticks=0, jitter_ticks=10,
        skipped_intervals_before=0, skipped_intervals_total=0, utc_origin_before_ticks=0,
        requested_interval_ms=100, scheduler_backend='synthetic', hard_realtime=False)
    recipe=dict(schema='overwatch-decoder.acquisition-recipe/1', target={k:profile['target'][k]for k in('image_name','executable_sha256','architecture')}, stages=[dict(name='fixture')])
    evidence=b'{"kind":"synthetic_fixture"}\n';pr=json.dumps(profile).encode();rr=raw(recipe)
    manifest=dict(schema='overwatch-decoder.acquisition-result/1',complete=True,error=None,target=profile['target'],
        profile_sha256=hashlib.sha256(pr).hexdigest(),recipe_sha256=hashlib.sha256(rr).hexdigest(),
        evidence_sha256=hashlib.sha256(evidence).hexdigest(),stages_completed=1)
    for file,data in [('profile.json',pr),('recipe.json',rr),('manifest.json',raw(manifest)),('evidence.jsonl',evidence)]:
        (root/file).write_bytes(data)
    contracts=[]
    if health:
        descriptor=dict(actor_prefix='controller_0000_body_0000_',acquisition_evidence_sha256=manifest['evidence_sha256'],
            slots=[dict(index=0,membership_address=0x5000,membership_u32=1,field_name=name,scalar_address=0x5010)])
        # The loop above reuses name; pin the declared health scalar explicitly.
        descriptor['slots'][0]['field_name']='controller_0000_body_0000_pool_0000_direct_candidate'
        path=root/'health.json';path.write_bytes(raw(descriptor));contracts=[path]
    return profile,frame,manifest,contracts


def event(kind, index, **kwargs):
    return dict(schema='overwatch-decoder.field-live/1',kind=kind,session_id=SESSION,event_sequence=index,
                emitted_ticks=100+index*100,monotonic_frequency=1000,**kwargs)


def start(profile, manifest):
    return event('segment_start',0,segment=1,profile_sha256=manifest['profile_sha256'],source_stream_schema='overwatch-decoder.field-stream/1',
        fields=[dict(name=f['name'],type=f['type'])for f in profile['fields']])


def live(frame,index=1):
    envelope={k:copy.deepcopy(v)for k,v in frame.items()if k not in('schema','kind','guards_before','guards_after','fields','visibility','runtime_semantics_validated')}
    envelope.update(segment=1,data_classification='private_research',recording_state='accepted_not_durability_verified',
        terminal_reason=None,recording_frame=copy.deepcopy(frame),fields={})
    for name,sample in frame['fields'].items():
        envelope['fields'][name]={k:copy.deepcopy(v)for k,v in sample.items()if k!='guard_ids'}
        envelope['fields'][name].update(source='process_memory',read_attempted=None,read_error=None)
    envelope.pop('monotonic_frequency')
    return event('frame',index,**envelope)


def next_frame(frame, missed=0):
    frame=copy.deepcopy(frame);delta=100*(missed+1)
    for key in('start_ticks','end_ticks'):frame[key]+=delta
    frame['sequence']+=1;frame['scheduled_slot']+=missed+1;frame['scheduled_ticks']+=delta
    frame['skipped_intervals_before']=missed;frame['skipped_intervals_total']+=missed
    for phase in('guards_before','guards_after'):
        for check in frame[phase]:
            for key in('start_ticks','end_ticks'):check[key]+=delta
    for sample in frame['fields'].values():
        for key in('read_start_ticks','read_end_ticks'):sample[key]+=delta
    return frame


class LiveTests(unittest.TestCase):
    def test_project_same_guarded_relation_position_and_private_cache(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);profile,frame,m,_=setup(root,cache=True)
            adapter=LiveRelations(root,SESSION,1,cached_label_recipe_sha256=m['recipe_sha256'])
            adapter.consume(raw(start(profile,m)));result=adapter.consume(raw(live(frame)))
            row=result['relations'][0]
            self.assertEqual(row['relation_status'],'observed');self.assertEqual(row['position_candidate']['value'],[1,2,3])
            self.assertEqual(row['cached_label_candidate'],'Example');self.assertIsNone(row['name'])
            self.assertEqual(result['schema'],'overwatch-decoder.entity-relations-live/1')
            self.assertFalse(result['durability_verified']);self.assertFalse(result['recording']['complete'])
            self.assertEqual(result['recording']['status'],'accepted_not_durability_verified')
            self.assertNotIn('samples_prefix_sha256',result['source_artifacts']);self.assertNotIn(str(root),json.dumps(result))

    def test_health_exact_body_and_gap_null_no_carry(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);p,f,m,c=setup(root,health=True)
            adapter=LiveRelations(root,SESSION,1,health_contracts=c);adapter.consume(raw(start(p,m)))
            row=adapter.consume(raw(live(f)))['relations'][0]
            self.assertEqual(row['health_candidate']['body_object_key'],row['body_object_key'])
            self.assertEqual(row['health_candidate']['raw_sum'],125.5)
            f=next_frame(f,missed=1);e=live(f,2);e['emitted_ticks']=400
            self.assertIsNone(adapter.consume(raw(e))['relations'][0]['health_candidate'])

    def test_guard_failure_outputs_unknown_not_stale_identity(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);p,f,m,_=setup(root);adapter=LiveRelations(root,SESSION,1);adapter.consume(raw(start(p,m)))
            adapter.consume(raw(live(f)));f=next_frame(f)
            f['guards_before'][0].update(ok=False,error='guard_mismatch')
            for sample in f['fields'].values():sample.update(status='unknown',value=None,reason='guard_mismatch_before',read_start_ticks=None,read_end_ticks=None)
            result=adapter.consume(raw(live(f,2)))
            self.assertEqual(result['relations'][0]['relation_status'],'unknown');self.assertIsNone(result['relations'][0]['position_candidate'])

    def test_mismatches_reject_and_latch(self):
        cases=['session','segment','profile','target','envelope_value','envelope_time','guard_ids','field_bracket','guard_bracket','guard_failed_observed','sequence','skip','schema','durability','utc','clock_origin','hard_realtime']
        for case in cases:
            with self.subTest(case=case),tempfile.TemporaryDirectory()as temp:
                root=Path(temp);p,f,m,_=setup(root);adapter=LiveRelations(root,SESSION,1);adapter.consume(raw(start(p,m)));e=live(f);name=next(iter(f['fields']))
                if case=='session':e['session_id']='b'*32
                elif case=='segment':e['segment']=2
                elif case=='profile':e['profile_sha256']='ff'*32
                elif case=='target':e['target']['pid']=99
                elif case=='envelope_value':e['fields'][name]['value']=3
                elif case=='envelope_time':e['end_ticks']+=1
                elif case=='guard_ids':e['recording_frame']['fields'][name]['guard_ids']=[]
                elif case=='field_bracket':
                    for s in(e['fields'][name],e['recording_frame']['fields'][name]):s['read_end_ticks']=1000
                elif case=='guard_bracket':e['recording_frame']['guards_after'][0]['start_ticks']=101
                elif case=='guard_failed_observed':e['recording_frame']['guards_before'][0].update(ok=False,error='guard_mismatch')
                elif case=='sequence':e['sequence']=e['recording_frame']['sequence']=1
                elif case=='skip':e['skipped_intervals_total']=e['recording_frame']['skipped_intervals_total']=1
                elif case=='schema':e['recording_frame']['schema']='overwatch-decoder.field-stream/4'
                elif case=='utc':e['utc_origin']=e['recording_frame']['utc_origin']='2026-01-01T00:00:00'
                elif case=='clock_origin':e['utc_origin_before_ticks']=e['recording_frame']['utc_origin_before_ticks']=1000
                elif case=='hard_realtime':e['hard_realtime']=e['recording_frame']['hard_realtime']=True
                else:e['recording_state']='verified_complete'
                with self.assertRaises(ValueError):adapter.consume(raw(e))
                with self.assertRaisesRegex(InvalidLive,'live_adapter_failed'):adapter.consume(raw(live(f)))

    def test_epoch_change_and_closed_stream_require_new_configuration(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);p,f,m,_=setup(root);a=LiveRelations(root,SESSION,1);a.consume(raw(start(p,m)));a.consume(raw(live(f)))
            a.consume(raw(event('segment_end',2,segment=dict(ordinal=1))))
            with self.assertRaisesRegex(ValueError,'reconfiguration'):a.consume(raw(event('segment_start',3,segment=2)))

    def test_acquisition_tamper_and_health_mismatch_fail_before_projection(self):
        for file in('profile.json','recipe.json','evidence.jsonl'):
            with self.subTest(file=file),tempfile.TemporaryDirectory()as temp:
                root=Path(temp);setup(root);(root/file).write_bytes((root/file).read_bytes()+b' ')
                with self.assertRaises(ValueError):LiveRelations(root,SESSION,1)
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);p,f,m,c=setup(root,health=True);d=json.loads(c[0].read_bytes());d['acquisition_evidence_sha256']='ff'*32;c[0].write_bytes(raw(d))
            with self.assertRaisesRegex(ValueError,'health_acquisition'):LiveRelations(root,SESSION,1,health_contracts=c)

    def test_stream_budgets_no_partial_line_and_no_false_terminal_verification(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);p,f,m,_=setup(root);data=raw(start(p,m))+raw(live(f));out=io.BytesIO()
            summary=stream(LiveRelations(root,SESSION,1),io.BytesIO(data),out)
            self.assertEqual(summary['frames'],1);self.assertFalse(summary['durability_verified']);self.assertFalse(summary['native_epoch_closed'])
            self.assertTrue(out.getvalue().endswith(b'\n'))
            for kwargs in (dict(maximum_output=1),dict(maximum_input=1),dict(maximum_events=1)):
                out=io.BytesIO()
                with self.assertRaises(ValueError):stream(LiveRelations(root,SESSION,1),io.BytesIO(data),out,**kwargs)
                self.assertEqual(out.getvalue(),b'')
            with self.assertRaisesRegex(ValueError,'line_bound'):LiveRelations(root,SESSION,1).consume(b'x'*(MAX_LINE+1))
            with self.assertRaises(ValueError):LiveRelations(root,SESSION,1).consume(b'{"x":1,"x":2}\n')


def category_setup(root):
    from test_live_categories import live_category_fixture
    p,f,c,artifacts,_,mode,_,_,_,session,segment=live_category_fixture()
    for name,sample in f['fields'].items():
        sample.update(type=next(d['type']for d in p['fields']if d['name']==name),reason=None)
    f.update(interpretation='profile_declared_research',visibility='research',runtime_semantics_validated=False,
        public_state_eligible=False,atomic=False,scheduled_slot=0,scheduled_ticks=0,jitter_ticks=10,
        skipped_intervals_before=0,skipped_intervals_total=0,utc_origin_before_ticks=0,
        requested_interval_ms=100,scheduler_backend='synthetic',hard_realtime=False)
    recipe=dict(schema='overwatch-decoder.acquisition-recipe/1',target={k:p['target'][k]for k in('image_name','executable_sha256','architecture')},stages=[dict(name='fixture')])
    evidence=b'{"kind":"synthetic_fixture"}\n';pr=json.dumps(p).encode();rr=raw(recipe)
    sha=lambda b:hashlib.sha256(b).hexdigest()
    manifest=dict(schema='overwatch-decoder.acquisition-result/1',complete=True,error=None,target=p['target'],
        profile_sha256=sha(pr),recipe_sha256=sha(rr),evidence_sha256=sha(evidence),stages_completed=1)
    for file,data in [('profile.json',pr),('recipe.json',rr),('manifest.json',raw(manifest)),('evidence.jsonl',evidence)]:
        (root/file).write_bytes(data)
    def add(value):
        data=raw(value);artifacts[sha(data)]=data;return sha(data)
    session.update(session_id=SESSION,recipe_sha256=manifest['recipe_sha256'])
    segment.update(session_id=SESSION,event_sequence=1)
    c.update(source={k:manifest[k]for k in('recipe_sha256','evidence_sha256')},
        acquisition_manifest_sha256=add(manifest),session_start_sha256=add(session),segment_start_sha256=add(segment))
    mode.update(acquisition_manifest_sha256=c['acquisition_manifest_sha256'],
        live_scope=dict(session_id=SESSION,segment=1,start_ticks=5,monotonic_frequency=1000,
            session_start_sha256=c['session_start_sha256'],segment_start_sha256=c['segment_start_sha256']))
    c['mode_review_sha256']=add(mode)
    paths={}
    for digest,data in artifacts.items():
        path=root/(digest+'.json');path.write_bytes(data);paths[digest]=path.name
    contract=root/'live-category.json';contract.write_bytes(raw(c));mapping=root/'artifacts.json';mapping.write_bytes(raw(paths))
    kwargs=dict(live_category_contract=contract,live_category_artifacts=mapping)
    return p,f,manifest,c,session,segment,kwargs


class LiveCategoryCompositionTests(unittest.TestCase):
    def test_exact_keys_live_provenance_and_default_disabled(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);p,f,m,c,se,sg,kw=category_setup(root)
            a=LiveRelations(root,SESSION,1,**kw);a.consume(raw(se));a.consume(raw(sg))
            # Row order is deliberately unrelated to output relation order.
            original=a.category.project
            def reordered(*args,**kwargs):
                out=original(*args,**kwargs);out['rows'].reverse();return out
            a.category.project=reordered
            e=live(f,2);out=a.consume(raw(e))
            self.assertEqual([r['relative_allegiance_candidate']for r in out['relations']],['self','friendly','enemy'])
            self.assertTrue(out['live_category_output_enabled']);self.assertTrue(out['category_output_enabled'])
            self.assertNotIn('recording_manifest_sha256',json.dumps(out))
            for row in out['relations']:
                self.assertIsNone(row['team']);self.assertFalse(row['category_evidence']['durability_verified'])
                self.assertEqual(row['category_evidence']['admission']['event_sha256'],hashlib.sha256(raw(e)).hexdigest())
                self.assertEqual(row['category_evidence']['acquisition']['manifest_sha256'],c['acquisition_manifest_sha256'])
                self.assertTrue(row['category_evidence']['self_fields'])
            plain=LiveRelations(root,SESSION,1);plain.consume(raw(se));plain.consume(raw(sg))
            result=plain.consume(raw(e));self.assertFalse(result['category_output_enabled'])
            self.assertNotIn('team_candidate',result['relations'][0])

    def test_gap_and_missing_self_null_allegiance_without_carry(self):
        for case in ('gap','self_unknown','cancelled'):
            with self.subTest(case=case),tempfile.TemporaryDirectory()as temp:
                root=Path(temp);p,f,m,c,se,sg,kw=category_setup(root)
                a=LiveRelations(root,SESSION,1,**kw);a.consume(raw(se));a.consume(raw(sg));a.consume(raw(live(f,2)))
                f=next_frame(f,missed=1 if case=='gap'else 0)
                if case=='self_unknown':f['fields']['controller_0000_body_0000_manager_key_candidate_i32'].update(status='unknown',value=None,reason='read_failed')
                if case=='cancelled':
                    for sample in f['fields'].values():sample.update(status='unknown',value=None,reason='cancelled')
                    for check in f['guards_after']:check.update(ok=False,error='cancelled')
                result=a.consume(raw(live(f,3)))
                self.assertTrue(all(r['team_candidate']is None and r['relative_allegiance_candidate']is None for r in result['relations']))
                if case=='gap':self.assertTrue(all(r['raw_category_candidate']is None for r in result['relations']))

    def test_wrong_reviewed_epoch_metadata_and_finite_substitution_reject(self):
        for case in ('session','segment','session_event','segment_event','finite','missing_map','acquisition','missing_session'):
            with self.subTest(case=case),tempfile.TemporaryDirectory()as temp:
                root=Path(temp);p,f,m,c,se,sg,kw=category_setup(root)
                if case=='finite':
                    c['recording_manifest_sha256']='ff'*32;kw['live_category_contract'].write_bytes(raw(c))
                if case=='missing_map':kw.pop('live_category_artifacts')
                if case=='acquisition':
                    m['note']='another acquisition manifest';(root/'manifest.json').write_bytes(raw(m))
                with self.assertRaises(ValueError):
                    a=LiveRelations(root,'b'*32 if case=='session'else SESSION,2 if case=='segment'else 1,**kw)
                    if case=='missing_session':a.consume(raw(sg))
                    if case=='session_event':se['revision']='b'*40
                    a.consume(raw(se))
                    if case=='segment_event':sg['start_ticks']=4
                    a.consume(raw(sg))

    def test_wrong_body_or_duplicate_rows_never_join_and_wrong_source_rejects(self):
        for case in ('body','duplicate','source'):
            with self.subTest(case=case),tempfile.TemporaryDirectory()as temp:
                root=Path(temp);p,f,m,c,se,sg,kw=category_setup(root)
                a=LiveRelations(root,SESSION,1,**kw);a.consume(raw(se));a.consume(raw(sg));original=a.category.project
                def changed(*args,**kwargs):
                    out=original(*args,**kwargs)
                    if case=='body':out['rows'][1]['body_object_key']=out['rows'][2]['body_object_key']
                    elif case=='duplicate':out['rows'].append(copy.deepcopy(out['rows'][1]))
                    else:out['admission_evidence']['evidence_sha256']='ff'*32
                    return out
                a.category.project=changed
                if case=='source':
                    with self.assertRaisesRegex(ValueError,'source_mismatch'):a.consume(raw(live(f,2)))
                else:
                    out=a.consume(raw(live(f,2)))
                    self.assertIsNone(out['relations'][1]['team_candidate']);self.assertIsNone(out['relations'][1]['raw_category_candidate'])
                    self.assertEqual(out['relations'][2]['relative_allegiance_candidate'],'enemy')

def context_setup(root, *, groups=True, additional_anchor=False, context_use='controlled_player_context',
                  frame_scope=None, health=False):
    from test_context_groups import group_fixture
    from test_relations import prepare
    p, f, category_raw, context_raw, group, artifacts, scope, _ = group_fixture(additional_anchor=additional_anchor)
    values = {name: sample['value'] for name, sample in f['fields'].items()}
    prefixes = sorted(f['name'][:-len('_handle_candidate_i32')] for f in p['fields']
                      if f['name'].startswith('controller_') and f['name'].endswith('_handle_candidate_i32')
                      and '_body_' not in f['name'])
    for prefix in prefixes:
        name = prefix + '_body_0000_position_candidate'
        p['fields'].append(dict(name=name, type='f32x3', address=0xb000+len(p['fields'])*16))
        values[name] = [1.0, 2.0, 3.0]
    if health:
        p['guards'].append(dict(address=0xc000, bytes_hex='01000000'))
        p['fields'].append(dict(name='controller_0000_body_0000_pool_0000_direct_candidate', type='f32', address=0xc010))
        values['controller_0000_body_0000_pool_0000_direct_candidate'] = 125.5
    decoder, f = prepare(p, values)
    for name, sample in f['fields'].items():
        sample.update(type=decoder.fields[name]['type'], reason=None)
    f.update(interpretation='profile_declared_research', visibility='research', runtime_semantics_validated=False,
        public_state_eligible=False, atomic=False, scheduled_slot=0, scheduled_ticks=0, jitter_ticks=10,
        skipped_intervals_before=0, skipped_intervals_total=0, utc_origin_before_ticks=0,
        requested_interval_ms=100, scheduler_backend='synthetic', hard_realtime=False)
    category, context = json.loads(category_raw), json.loads(context_raw)
    sha = lambda data: hashlib.sha256(data).hexdigest()
    def add(value):
        data = raw(value); artifacts[sha(data)] = data; return sha(data)
    profile_raw = json.dumps(p).encode()
    manifest = dict(schema='overwatch-decoder.acquisition-result/1', complete=True, error=None, target=p['target'],
                    profile_sha256=sha(profile_raw), stages_completed=0, **category['source'])
    manifest_sha = add(manifest)
    for contract in (category, context):
        contract.update(profile_sha256=sha(profile_raw), acquisition_manifest_sha256=manifest_sha)
    context['required_guard_ids'] = list(range(len(decoder.guards)))
    category_raw, context_raw = raw(category), raw(context)
    group.update(profile_sha256=sha(profile_raw), acquisition_manifest_sha256=manifest_sha,
                 category_contract_sha256=sha(category_raw), context_contract_sha256=sha(context_raw))
    if frame_scope is not None:
        group['frame_scope'] = frame_scope
    scope.update(**{k: copy.deepcopy(v) for k, v in group.items() if k not in ('schema', 'context_scope_review_sha256')},
                 context_use=context_use)
    group['context_scope_review_sha256'] = add(scope)
    group_raw = raw(group)
    session = event('session_start', 0, target=p['target'], recipe_sha256=manifest['recipe_sha256'],
                    recording_frame_included=True, public_state_eligible=False, atomic=False)
    segment = start(p, manifest); segment.update(event_sequence=1, emitted_ticks=200, start_ticks=5)
    admission = dict(schema='overwatch-decoder.live-context-admission/1', target=p['target'], profile_sha256=sha(profile_raw),
        source_acquisition=dict(manifest_sha256=manifest_sha, **category['source']), session_id=SESSION, segment=1,
        raw_category_contract_sha256=sha(category_raw), context_controller_contract_sha256=sha(context_raw),
        context_group_contract_sha256=sha(group_raw) if groups else None,
        session_start_sha256=add(session), segment_start_sha256=add(segment))
    for file, data in [('profile.json', profile_raw), ('manifest.json', raw(manifest)),
                       ('recipe.json', artifacts[manifest['recipe_sha256']]),
                       ('evidence.jsonl', artifacts[manifest['evidence_sha256']]),
                       ('raw-category.json', category_raw), ('context.json', context_raw),
                       ('group.json', group_raw), ('context-admission.json', raw(admission))]:
        (root/file).write_bytes(data)
    paths = {}
    for pin, data in artifacts.items():
        path = root/(pin+'.json'); path.write_bytes(data); paths[pin] = path.name
    (root/'context-artifacts.json').write_bytes(raw(paths))
    kwargs = dict(raw_category_contract=root/'raw-category.json', context_controller_contract=root/'context.json',
        context_projection_admission=root/'context-admission.json', context_projection_artifacts=root/'context-artifacts.json')
    if groups:
        kwargs['context_group_contract'] = root/'group.json'
    if health:
        descriptor = dict(actor_prefix='controller_0000_body_0000_', acquisition_evidence_sha256=manifest['evidence_sha256'],
            slots=[dict(index=0, membership_address=0xc000, membership_u32=1,
                field_name='controller_0000_body_0000_pool_0000_direct_candidate', scalar_address=0xc010)])
        path=root/'health.json'; path.write_bytes(raw(descriptor)); kwargs['health_contracts']=[path]
    return p, f, manifest, session, segment, admission, kwargs


class LiveContextCompositionTests(unittest.TestCase):
    def consume_first(self, root, **options):
        p, f, m, se, sg, admission, kw = context_setup(root, **options)
        adapter = LiveRelations(root, SESSION, 1, **kw)
        adapter.consume(raw(se)); adapter.consume(raw(sg))
        return adapter, f, adapter.consume(raw(live(f, 2))), admission

    def test_exact_new_shape_raw_halves_group_source_and_legacy_separation(self):
        from live_categories import live_frame_sha256
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); a, f, out, admission=self.consume_first(root)
            candidates=[r['context_group_candidate'] for r in out['relations']]
            self.assertEqual([c['global_group'] for c in candidates], ['group-a','group-a','group-b'])
            self.assertEqual([c['relation_to_context'] for c in candidates], ['same_group','same_group','opposing_group'])
            self.assertEqual(set(candidates[0]), {'raw_flags','raw_category','raw_status','category_status',
                'context_raw_category','category_matches_context','global_group','relation_to_context','group_status'})
            self.assertEqual([c['context_raw_category'] for c in candidates],[0,0,0])
            self.assertEqual([c['category_matches_context'] for c in candidates],[True,True,False])
            self.assertEqual(candidates[0]['raw_flags']['high_u32'], 0xffffffff)
            self.assertEqual(candidates[0]['raw_flags']['assembled_u64_hex'], '0xffffffff00000008')
            self.assertFalse(out['category_output_enabled']); self.assertTrue(out['raw_context_output_enabled'])
            self.assertTrue(out['context_group_output_enabled'])
            top=out['context_group_projection']; self.assertEqual(top['schema'],'overwatch-decoder.live-context-group-projection/1')
            self.assertEqual(top['admission']['native_frame_sha256'],live_frame_sha256(f))
            self.assertEqual(top['admission']['event_sha256'],hashlib.sha256(raw(live(f,2))).hexdigest())
            self.assertEqual(top['admission']['session_start_sha256'],admission['session_start_sha256'])
            for row in out['relations']:
                for key in ('raw_category_candidate','team_candidate','relative_allegiance_candidate','category_evidence','team','name'):
                    self.assertIsNone(row[key])
                self.assertIsNone(row['context_group_reason'])
                proof=row['context_group_evidence']; self.assertEqual(len(proof['actor_fields']),4)
                self.assertNotIn('selector',proof['context_reference'])
                self.assertEqual(proof['context_reference']['projection'],'context_group_projection.context_projection')
                self.assertEqual(proof['admission'],top['admission']); self.assertFalse(proof['durability_verified'])
            self.assertFalse(top['public_state_eligible']); self.assertFalse(top['durability_verified'])
            self.assertFalse(top['context_projection']['local_control_semantics_validated'])

    def test_raw_only_scope_unknown_preserves_position_and_health(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); a,f,out,_=self.consume_first(root,groups=False,health=True)
            self.assertIsNone(out['context_group_projection']['group_projection'])
            self.assertFalse(out['context_group_output_enabled'])
            self.assertEqual([row['context_group_candidate']['category_matches_context'] for row in out['relations']],
                             [True,True,False])
            self.assertEqual(out['relations'][0]['health_candidate']['raw_sum'],125.5)
            for row in out['relations']:
                self.assertEqual(row['position_candidate']['value'],[1,2,3])
                self.assertIsNotNone(row['context_group_candidate']['raw_flags'])
                self.assertIsNone(row['context_group_candidate']['global_group'])
                self.assertIsNone(row['context_group_candidate']['relation_to_context'])
                self.assertEqual(row['context_group_reason'],'context_group_not_configured')
            plain=LiveRelations(root,SESSION,1,health_contracts=[root/'health.json'])
            p=json.loads((root/'profile.json').read_bytes()); m=json.loads((root/'manifest.json').read_bytes())
            plain.consume(raw(start(p,m))); baseline=plain.consume(raw(live(f)))
            self.assertEqual(out['relations'][0]['health_candidate'],baseline['relations'][0]['health_candidate'])
            self.assertEqual(out['relations'][0]['position_candidate'],baseline['relations'][0]['position_candidate'])

    def test_finite_scope_and_spectator_do_not_block_raw_or_primary(self):
        for options,reason in [({'context_use':'spectator'},'unsupported_context_scope'),
            ({'context_use':'unknown'},'unsupported_context_scope'),
            ({'frame_scope':dict(first_sequence=1,last_sequence=10,start_ticks=0,end_ticks=500,monotonic_frequency=1000)},'outside_reviewed_frame_scope')]:
            with self.subTest(options=options), tempfile.TemporaryDirectory() as temp:
                a,f,out,_=self.consume_first(Path(temp),**options)
                self.assertEqual(out['context_group_projection']['group_projection']['reason'],reason)
                for row in out['relations']:
                    self.assertEqual(row['relation_status'],'observed')
                    self.assertIsNotNone(row['position_candidate'])
                    self.assertIsNotNone(row['context_group_candidate']['raw_flags'])
                    self.assertEqual(row['context_group_candidate']['group_status'],'unknown')
                    self.assertEqual(row['context_group_reason'],reason)

    def test_custom_anchor_is_context_reference_never_primary_duplicate(self):
        with tempfile.TemporaryDirectory() as temp:
            a,f,out,_=self.consume_first(Path(temp),additional_anchor=True)
            self.assertEqual(len(out['relations']),2)
            self.assertEqual(len(out['context_group_projection']['raw_category_projection']['rows']),3)
            self.assertEqual(a.projector.prefixes,['controller_0000','controller_0001'])
            self.assertEqual(a.context.prefixes,['context_anchor_0000'])
            anchor=out['context_group_projection']['context_projection']['controller_object_key']
            self.assertNotIn(anchor,[r['controller_object_key'] for r in out['relations']])
            self.assertTrue(all(r['context_group_candidate']['relation_to_context']=='opposing_group' for r in out['relations']))
            self.assertTrue(all(r['context_group_evidence']['context_reference']['controller_object_key']==anchor for r in out['relations']))

    def test_gap_selector_unknown_missing_half_and_cancellation_never_carry(self):
        for case in ('gap','selector','half','cancelled'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                a,f,out,_=self.consume_first(Path(temp)); f=next_frame(f,missed=1 if case=='gap' else 0)
                if case in ('selector','half'):
                    field='context_selector_i32' if case=='selector' else 'category_high_0'
                    f['fields'][field].update(status='unknown',value=None,reason='read_failed')
                if case=='cancelled':
                    for sample in f['fields'].values():
                        sample.update(status='unknown',value=None,reason='cancelled',read_start_ticks=None,read_end_ticks=None)
                    for check in f['guards_after']: check.update(ok=False,error='cancelled')
                e=live(f,3);e['emitted_ticks']=500;out=a.consume(raw(e))
                if case in ('gap','cancelled'):
                    self.assertTrue(all(r['context_group_candidate'] is None for r in out['relations']))
                elif case=='selector':
                    self.assertTrue(all(r['context_group_candidate']['relation_to_context'] is None for r in out['relations']))
                    self.assertTrue(all(r['context_group_candidate']['raw_flags'] is not None for r in out['relations']))
                    self.assertTrue(all(r['context_group_candidate']['context_raw_category'] is None for r in out['relations']))
                    self.assertTrue(all(r['context_group_candidate']['category_matches_context'] is None for r in out['relations']))
                else:
                    self.assertIsNone(out['relations'][0]['context_group_candidate'])
                    self.assertIsNotNone(out['relations'][1]['context_group_candidate']['raw_flags'])
                    self.assertIsNone(out['relations'][1]['context_group_candidate']['category_matches_context'])

    def test_raw_only_custom_anchor_equality_missing_or_ambiguous_anchor_unknown(self):
        for case in ('observed','absent','duplicate','body'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);p,f,m,se,sg,_,kw=context_setup(root,groups=False,additional_anchor=True)
                a=LiveRelations(root,SESSION,1,**kw);a.consume(raw(se));a.consume(raw(sg));original=a.raw_category.project
                def changed(*args,**kwargs):
                    out=original(*args,**kwargs)
                    if case=='absent':out['rows']=out['rows'][:-1]
                    if case=='duplicate':out['rows'].append(copy.deepcopy(out['rows'][-1]))
                    if case=='body':out['rows'][-1]['body_object_key']=out['rows'][0]['body_object_key']
                    return out
                a.raw_category.project=changed;out=a.consume(raw(live(f,2)))
                self.assertEqual(len(out['relations']),2)
                for row in out['relations']:
                    c=row['context_group_candidate'];self.assertEqual(c['raw_category'],0)
                    self.assertEqual(c['context_raw_category'],1 if case=='observed' else None)
                    self.assertIs(c['category_matches_context'],False if case=='observed' else None)
                    self.assertIsNone(c['global_group']);self.assertIsNone(c['relation_to_context'])

    def test_unsupported_category_retains_raw_halves_without_group_semantics(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);p,f,m,se,sg,_,kw=context_setup(root)
            f['fields']['category_0']['value']=12
            a=LiveRelations(root,SESSION,1,**kw);a.consume(raw(se));a.consume(raw(sg));out=a.consume(raw(live(f,2)))
            row=out['relations'][0]
            self.assertEqual(row['context_group_candidate']['raw_flags']['low_u32'],12)
            self.assertEqual(row['context_group_candidate']['raw_status'],'observed')
            self.assertEqual(row['context_group_candidate']['category_status'],'unknown')
            self.assertIsNone(row['context_group_candidate']['raw_category'])
            self.assertIsNone(row['context_group_candidate']['relation_to_context'])
            self.assertEqual(row['context_group_reason'],'unsupported_mode_bits')

    def test_epoch_source_contract_and_metadata_pins_reject_before_values(self):
        cases=('session','segment','manifest','source','contract','metadata','extra_key','missing_input','legacy')
        for case in cases:
            with self.subTest(case=case),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);p,f,m,se,sg,admission,kw=context_setup(root)
                if case=='session': admission['session_id']='b'*32
                if case=='segment': admission['segment']=2
                if case=='manifest': admission['source_acquisition']['manifest_sha256']='00'*32
                if case=='source': admission['source_acquisition']['evidence_sha256']='00'*32
                if case=='contract': admission['raw_category_contract_sha256']='00'*32
                if case=='metadata': admission['session_start_sha256']='00'*32
                if case=='extra_key': admission['self_controller_object_key']='controller:'+'00'*32
                if case=='missing_input': kw.pop('context_controller_contract')
                if case=='legacy': kw['live_category_contract']=root/'legacy.json'; kw['live_category_artifacts']=root/'context-artifacts.json'
                (root/'context-admission.json').write_bytes(raw(admission))
                with self.assertRaises(ValueError):LiveRelations(root,SESSION,1,**kw)

    def test_actual_consumed_session_and_segment_events_are_required(self):
        for case in ('missing_session','session','segment'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);p,f,m,se,sg,_,kw=context_setup(root);a=LiveRelations(root,SESSION,1,**kw)
                with self.assertRaises(ValueError):
                    if case=='missing_session':a.consume(raw(sg))
                    if case=='session':se['extra']='unadmitted'
                    a.consume(raw(se))
                    if case=='segment':sg['start_ticks']=6
                    a.consume(raw(sg))
                self.assertTrue(a.failed)

    def test_metadata_artifact_hashes_and_actual_transport_hashes_remain_distinct(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);p,f,m,se,sg,admission,kw=context_setup(root)
            a=LiveRelations(root,SESSION,1,**kw)
            session_raw=json.dumps(se,sort_keys=True,indent=2).encode()+b'\n'
            segment_raw=json.dumps(sg,sort_keys=True,indent=2).encode()+b'\n'
            a.consume(session_raw);a.consume(segment_raw);out=a.consume(raw(live(f,2)))
            proof=out['context_group_projection']['admission']
            self.assertEqual(proof['session_start_event_sha256'],hashlib.sha256(session_raw).hexdigest())
            self.assertEqual(proof['segment_start_event_sha256'],hashlib.sha256(segment_raw).hexdigest())
            self.assertEqual(proof['session_start_sha256'],admission['session_start_sha256'])
            self.assertEqual(proof['segment_start_sha256'],admission['segment_start_sha256'])
            self.assertNotEqual(proof['session_start_event_sha256'],proof['session_start_sha256'])
            self.assertNotEqual(proof['segment_start_event_sha256'],proof['segment_start_sha256'])

    def test_frame_clock_and_start_must_follow_admitted_segment(self):
        for case in ('frequency','start'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);p,f,m,se,sg,admission,kw=context_setup(root)
                if case=='start':
                    sg['start_ticks']=f['start_ticks']+1
                    data=raw(sg);pin=hashlib.sha256(data).hexdigest();path=root/(pin+'.json');path.write_bytes(data)
                    paths=json.loads(kw['context_projection_artifacts'].read_bytes());paths[pin]=path.name
                    kw['context_projection_artifacts'].write_bytes(raw(paths));admission['segment_start_sha256']=pin
                    kw['context_projection_admission'].write_bytes(raw(admission))
                a=LiveRelations(root,SESSION,1,**kw);a.consume(raw(se));a.consume(raw(sg))
                if case=='frequency':f['monotonic_frequency']=2000
                e=live(f,2)
                if case=='frequency':e['monotonic_frequency']=2000
                with self.assertRaisesRegex(ValueError,'context_frame_clock_or_start_mismatch'):a.consume(raw(e))
                self.assertTrue(a.failed)

    def test_group_duplicate_or_wrong_body_keeps_raw_but_cannot_compare(self):
        for case in ('duplicate','body'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);p,f,m,se,sg,_,kw=context_setup(root);a=LiveRelations(root,SESSION,1,**kw)
                a.consume(raw(se));a.consume(raw(sg));original=a.context_groups.project
                def changed(*args,**kwargs):
                    out=original(*args,**kwargs)
                    if case=='duplicate':out['rows'].append(copy.deepcopy(out['rows'][1]))
                    else:out['rows'][1]['body_object_key']=out['rows'][2]['body_object_key']
                    return out
                a.context_groups.project=changed;out=a.consume(raw(live(f,2)))
                candidate=out['relations'][1]['context_group_candidate']
                self.assertEqual(candidate['raw_category'],0)
                self.assertIsNotNone(candidate['raw_flags'])
                self.assertIsNone(candidate['relation_to_context'])
                self.assertEqual(candidate['group_status'],'unknown')
                self.assertEqual(out['relations'][1]['context_group_reason'],'missing_or_ambiguous_group_for_exact_object_keys')

    def test_output_mutations_do_not_poison_next_frame_or_scope(self):
        with tempfile.TemporaryDirectory() as temp:
            a,f,out,_=self.consume_first(Path(temp));out['context_group_projection']['frame_scope']['last_sequence']=0
            out['relations'][0]['context_group_candidate']['raw_flags']['low_u32']=0
            out['relations'][0]['context_group_evidence']['context_reference']['controller_object_key']='wrong'
            f=next_frame(f);result=a.consume(raw(live(f,3)))
            self.assertEqual(result['relations'][0]['context_group_candidate']['raw_category'],0)
            self.assertEqual(result['relations'][0]['context_group_candidate']['relation_to_context'],'same_group')
            self.assertEqual(result['context_group_projection']['frame_scope']['last_sequence'],10)
            self.assertIsNone(a.projector._active_checks);self.assertIsNone(a.raw_category.relations._active_checks)
            self.assertIsNone(a.context.relations._active_checks)

    def test_wrong_projected_source_or_frame_rejects_and_clears_scopes(self):
        for source in ('raw','context','group'):
            with self.subTest(source=source),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);p,f,m,se,sg,_,kw=context_setup(root);a=LiveRelations(root,SESSION,1,**kw)
                a.consume(raw(se));a.consume(raw(sg));obj={'raw':a.raw_category,'context':a.context,'group':a.context_groups}[source]
                original=obj.project
                def changed(*args,**kwargs):
                    out=original(*args,**kwargs);out['profile_sha256']='00'*32;return out
                obj.project=changed
                with self.assertRaisesRegex(ValueError,'source_mismatch'):a.consume(raw(live(f,2)))
                self.assertTrue(a.failed);self.assertIsNone(a.projector._active_checks)
                self.assertIsNone(a.raw_category.relations._active_checks);self.assertIsNone(a.context.relations._active_checks)

    def test_exact_pair_join_order_duplicates_and_wrong_body(self):
        for case in ('order','duplicate','body'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);p,f,m,se,sg,_,kw=context_setup(root);a=LiveRelations(root,SESSION,1,**kw)
                a.consume(raw(se));a.consume(raw(sg));original=a.raw_category.project
                def changed(*args,**kwargs):
                    out=original(*args,**kwargs)
                    if case=='order':out['rows'].reverse()
                    if case=='duplicate':out['rows'].append(copy.deepcopy(out['rows'][1]))
                    if case=='body':out['rows'][1]['body_object_key']=out['rows'][2]['body_object_key']
                    return out
                a.raw_category.project=changed;out=a.consume(raw(live(f,2)))
                if case=='order':self.assertEqual(out['relations'][1]['context_group_candidate']['relation_to_context'],'same_group')
                else:self.assertIsNone(out['relations'][1]['context_group_candidate'])
                self.assertEqual(out['relations'][2]['context_group_candidate']['relation_to_context'],'opposing_group')

    def test_cli_declares_all_new_inputs(self):
        import subprocess, sys
        result=subprocess.run([sys.executable,str(Path(__file__).with_name('live_relations.py')),'--help'],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        for flag in ('raw-category-contract','context-controller-contract','context-group-contract',
                     'context-projection-admission','context-projection-artifacts'):
            self.assertIn('--'+flag,result.stdout)


if __name__=='__main__':unittest.main()
