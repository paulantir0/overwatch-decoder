"""Live source/epoch admission, optional output parity and uncertainty boundaries."""
import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest

from live_relations import LiveRelations, InvalidLive
from live_sessions import LiveSession
from relations import GuardedRelations
import test_ammunition_candidates as ammunition_fixtures
from test_live_relations import SESSION, event, live, next_frame, raw
from test_relations import prepare


def source(root, ordinal):
    case = ammunition_fixtures.CallbackReconstructionTests(); case.setUp()
    p, values, contract, artifacts, native, hud = [copy.deepcopy(getattr(case, name)) for name in
        ('profile', 'values', 'contract', 'artifacts', 'native', 'hud')]
    p['guards'].append(dict(address=0x9000, bytes_hex='01000000'))
    health = 'controller_0000_body_0000_pool_0000_direct_candidate'
    p['fields'] += [dict(name=health, type='f32', address=0x9010),
                    dict(name='controller_0000_body_0000_position_candidate', type='f32x3', address=0x9020)]
    values.update({health: 125.5, 'controller_0000_body_0000_position_candidate': [1., 2., 3.]})
    decoder, f = prepare(p, values)
    for name, sample in f['fields'].items():
        sample.update(type=decoder.fields[name]['type'], reason=None)
    f['fields']['expression_count'].update(read_start_ticks=21, read_end_ticks=22)
    f['fields'][case.callback['fields']['count_after']].update(read_start_ticks=60, read_end_ticks=61)
    delta = ordinal * 1000
    for k in ('start_ticks', 'end_ticks'): f[k] += delta
    for phase in ('guards_before', 'guards_after'):
        for g in f[phase]:
            for k in ('start_ticks', 'end_ticks'): g[k] += delta
    for sample in f['fields'].values():
        for k in ('read_start_ticks', 'read_end_ticks'): sample[k] += delta
    f.update(interpretation='profile_declared_research', visibility='research', runtime_semantics_validated=False,
             public_state_eligible=False, atomic=False, scheduled_slot=0, scheduled_ticks=delta, jitter_ticks=10,
             skipped_intervals_before=0, skipped_intervals_total=0, utc_origin_before_ticks=delta-1,
             monotonic_origin_ticks=delta, requested_interval_ms=100, scheduler_backend='synthetic', hard_realtime=False)
    recipe = dict(schema='overwatch-decoder.acquisition-recipe/1', target={k:p['target'][k] for k in
                  ('image_name','executable_sha256','architecture')}, stages=[dict(name='synthetic')])
    evidence = raw(dict(synthetic_acquisition=ordinal))
    def add(data):
        data = data if isinstance(data, bytes) else raw(data)
        digest = hashlib.sha256(data).hexdigest(); artifacts[digest] = data; return digest
    rr = raw(recipe); pr = json.dumps(p).encode()
    pins = dict(recipe_sha256=add(rr), evidence_sha256=add(evidence))
    manifest = dict(schema='overwatch-decoder.acquisition-result/1', complete=True, error=None, target=p['target'],
                    profile_sha256=decoder.hash, stages_completed=1, **pins)
    contract.update(profile_sha256=decoder.hash, source=pins, acquisition_manifest_sha256=add(manifest))
    native['recipe_sha256'] = pins['recipe_sha256']; contract['native_review_sha256'] = add(native)
    hud['native_review_sha256'] = contract['native_review_sha256']
    contract['bindings'][0].update(required_guard_ids=list(range(len(decoder.guards))), hud_review_sha256=add(hud))
    root.mkdir()
    for n, b in [('profile.json', pr), ('recipe.json', rr), ('manifest.json', raw(manifest)), ('evidence.jsonl', evidence)]:
        (root/n).write_bytes(b)
    (root/'ammunition.json').write_bytes(raw(contract))
    descriptor = dict(actor_prefix='controller_0000_body_0000_', acquisition_evidence_sha256=pins['evidence_sha256'],
        slots=[dict(index=0, membership_address=0x9000, membership_u32=1, field_name=health, scalar_address=0x9010)])
    (root/'health.json').write_bytes(raw(descriptor))
    return dict(root=root, profile=p, frame=f, manifest=manifest, artifacts=artifacts, contract=contract)


def fixture(root):
    sources = {n:source(root/f'acquisition-{n:04d}', n) for n in (1,2)}
    events = []
    def add(kind, ticks, **kwargs):
        item = event(kind, len(events), **kwargs); item['emitted_ticks'] = ticks; events.append(item); return item
    first = sources[1]
    session = add('session_start',100,target=first['profile']['target'],recipe_sha256=first['manifest']['recipe_sha256'],
                  source_kind='native_process_memory',recording_frame_included=True,atomic=False,
                  public_state_eligible=False,monotonic_origin_ticks=0)
    previous = 0
    for n, s in sources.items():
        m, p, f = [s[k] for k in ('manifest','profile','frame')]
        add('acquisition_start',n*1000-790,acquisition=n,start_ticks=n*1000-800,
            observation_gap_open=True,gap_start_ticks=previous)
        acquired = add('acquisition_end',n*1000-190,acquisition=dict(ordinal=n,directory=f'acquisition-{n:04d}',
            start_ticks=n*1000-800,end_ticks=n*1000-200,complete=True,error=None,
            profile_sha256=m['profile_sha256'],manifest_sha256=hashlib.sha256((s['root']/'manifest.json').read_bytes()).hexdigest()))
        segment = add('segment_start',n*1000-90,segment=n,acquisition=n,start_ticks=n*1000-100,
            profile_sha256=m['profile_sha256'],source_stream_schema='overwatch-decoder.field-stream/1',
            fields=[dict(name=d['name'],type=d['type'],min=None,max=None)for d in p['fields']])
        gap=add('gap',f['end_ticks']+10,interval=dict(start_ticks=previous,end_ticks=f['start_ticks'],meaning='synthetic'))
        frame = live(f,len(events)); frame.update(segment=n,emitted_ticks=f['end_ticks']+20); events.append(frame)
        add('segment_end',f['end_ticks']+30,terminal_summary_written=True,failure=None,
            recording_state='closed_manifest_available_not_independently_verified',segment=dict(ordinal=n,acquisition=n,
            profile_sha256=m['profile_sha256'],start_ticks=n*1000-100,end_ticks=f['end_ticks']+25,frames=1,
            first_frame_start_ticks=f['start_ticks'],last_frame_end_ticks=f['end_ticks'],
            trigger='guard_invalidation'if n==1 else'cancelled'))
        previous=f['end_ticks'];artifacts=s['artifacts']; paths={}
        for item in (session,acquired,segment):artifacts[hashlib.sha256(raw(item)).hexdigest()]=raw(item)
        for h,b in artifacts.items():
            path=s['root']/(h+'.json');path.write_bytes(b);paths[h]=str(path)
        admission=dict(schema='overwatch-decoder.live-ammunition-admission/1',target=p['target'],profile_sha256=m['profile_sha256'],
            source_acquisition=dict(manifest_sha256=acquired['acquisition']['manifest_sha256'],
                                    **{k:m[k]for k in('recipe_sha256','evidence_sha256')}),
            ammunition_contract_sha256=hashlib.sha256((s['root']/'ammunition.json').read_bytes()).hexdigest(),
            session_id=SESSION,segment=n,session_start_sha256=hashlib.sha256(raw(session)).hexdigest(),
            acquisition_end_sha256=hashlib.sha256(raw(acquired)).hexdigest(),segment_start_sha256=hashlib.sha256(raw(segment)).hexdigest())
        (s['root']/'artifacts.json').write_bytes(raw(paths));(s['root']/'admission.json').write_bytes(raw(admission))
        s.update(session=session, acquired=acquired, segment=segment, admission=admission, gap=gap)
    add('gap',previous+40,interval=dict(start_ticks=previous,end_ticks=previous+40,meaning='synthetic terminal'))
    add('session_end',previous+50,result_before_this_write=dict(schema='overwatch-decoder.field-observation/1',session_id=SESSION,
        status='finished',complete=True,target=first['profile']['target'],recipe_sha256=first['manifest']['recipe_sha256'],
        public_state_eligible=False,atomic=False))
    return sources,events


def adapter(s, *, enabled=True, **kwargs):
    if enabled:kwargs.update(ammunition_contract=s['root']/'ammunition.json',ammunition_artifacts=s['root']/'artifacts.json',
                             ammunition_admission=s['root']/'admission.json')
    return LiveRelations(s['root'],SESSION,s['segment']['segment'],health_contracts=[s['root']/'health.json'],**kwargs)


def begin(a,s):
    a.begin_epoch(raw(s['session']),raw(s['acquired']),raw(s['segment']))
    a.consume(raw(s['gap']))


def frame_event(s, frame=None):
    f=s['frame']if frame is None else frame;e=live(f,s['segment']['event_sequence']+2)
    e.update(segment=s['segment']['segment'],emitted_ticks=f['end_ticks']+20);return e


class LiveAmmunitionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.sources,self.events=fixture(Path(self.temp.name));self.s=self.sources[1]

    def test_two_epochs_same_profile_need_distinct_fresh_acquisition_admission(self):
        self.assertEqual(self.sources[1]['manifest']['profile_sha256'],self.sources[2]['manifest']['profile_sha256'])
        coordinator=LiveSession(lambda session,acquisition,segment:adapter(self.sources[acquisition['ordinal']]))
        outputs=[x for e in self.events if(x:=coordinator.consume(raw(e)))is not None]
        self.assertEqual(len(outputs),2);self.assertTrue(coordinator.close()['native_session_end_seen'])
        for n,out in enumerate(outputs,1):
            candidate=out['ammunition_projection']['rows'][0]
            self.assertEqual(candidate['ammunition_candidate']['value'],26)
            self.assertEqual(candidate['callback_reconstruction_candidate']['value'],26)
            self.assertEqual(out['relations'][0]['ammunition_evidence_ref'],'/ammunition_projection/rows/0')
            self.assertEqual(out['relations'][0]['health_candidate']['raw_sum'],125.5)
            self.assertEqual(out['relations'][0]['position_candidate']['value'],[1,2,3])
            admission=out['ammunition_live_admission']
            self.assertEqual(admission['acquisition'],n)
            self.assertEqual(admission['acquisition_end_event_sha256'],out['session_epoch']['acquisition_end_sha256'])
            self.assertFalse(admission['durability_verified']);self.assertFalse(out['recording']['complete'])
        self.assertNotEqual(outputs[0]['ammunition_contract_sha256'],outputs[1]['ammunition_contract_sha256'])
        self.assertEqual(outputs[1]['session_epoch']['previous_epoch_last_frame_end_ticks'],1100)

    def test_default_output_has_no_new_keys_and_other_fields_are_unchanged(self):
        configured=adapter(self.s);baseline=adapter(self.s,enabled=False);begin(configured,self.s);begin(baseline,self.s)
        a=configured.consume(raw(frame_event(self.s)));b=baseline.consume(raw(frame_event(self.s)))
        self.assertNotIn('ammunition_projection',b);self.assertNotIn('live_ammunition_output_enabled',b)
        for key in ('ammunition_projection','live_ammunition_output_enabled','ammunition_contract_sha256',
                    'ammunition_admission_sha256','ammunition_live_admission'):a.pop(key)
        for row in a['relations']:
            for key in ('ammunition_candidate','ammunition_reason','ammunition_evidence_ref'):row.pop(key)
        self.assertEqual(a,b)

    def test_new_acquisition_cannot_reuse_contract_even_when_profile_is_identical(self):
        second=self.sources[2]
        (second['root']/'ammunition.json').write_bytes((self.s['root']/'ammunition.json').read_bytes())
        paths=json.loads((second['root']/'artifacts.json').read_bytes())
        paths.update(json.loads((self.s['root']/'artifacts.json').read_bytes()))
        (second['root']/'artifacts.json').write_bytes(raw(paths))
        with self.assertRaisesRegex(ValueError,'ammunition_acquisition_mismatch'):adapter(second)

    def test_partial_options_and_changed_admission_scope_rejected(self):
        with self.assertRaisesRegex(ValueError,'inputs_required_together'):
            adapter(self.s,enabled=False,ammunition_contract=self.s['root']/'ammunition.json')
        original=(self.s['root']/'admission.json').read_bytes()
        for key,value in [('segment',2),('session_id','b'*32),('profile_sha256','0'*64),
                          ('ammunition_contract_sha256','0'*64),('target',{})]:
            with self.subTest(key=key):
                a=json.loads(original);a[key]=value;(self.s['root']/'admission.json').write_bytes(raw(a))
                with self.assertRaisesRegex(ValueError,'admission_scope_mismatch'):adapter(self.s)
        (self.s['root']/'admission.json').write_bytes(original)

    def test_missing_actual_acquisition_metadata_prevents_output_and_latches(self):
        a=adapter(self.s);a.consume(raw(self.s['session']))
        a.event_sequence=self.s['segment']['event_sequence']-1
        with self.assertRaisesRegex(ValueError,'ammunition_admitted_segment_mismatch'):
            a.consume(raw(self.s['segment']))
        with self.assertRaisesRegex(ValueError,'live_adapter_failed'):a.consume(raw(frame_event(self.s)))

    def test_changed_actual_metadata_rejected_even_if_manifest_still_matches(self):
        a=adapter(self.s);bad=copy.deepcopy(self.s['acquired']);bad['acquisition']['end_ticks']-=1
        with self.assertRaisesRegex(ValueError,'ammunition_admitted_acquisition_mismatch'):
            a.begin_epoch(raw(self.s['session']),raw(bad),raw(self.s['segment']))
        self.assertTrue(a.failed)

    def test_semantic_metadata_equality_keeps_actual_transport_hashes(self):
        a=adapter(self.s)
        pretty=lambda x:json.dumps(x,indent=2).encode()+b'\n'
        a.begin_epoch(pretty(self.s['session']),pretty(self.s['acquired']),pretty(self.s['segment']))
        a.consume(raw(self.s['gap']))
        out=a.consume(raw(frame_event(self.s)));admission=out['ammunition_live_admission']
        self.assertNotEqual(admission['session_start_artifact_sha256'],admission['session_start_event_sha256'])
        self.assertEqual(admission['session_start_event_sha256'],hashlib.sha256(pretty(self.s['session'])).hexdigest())

    def test_gap_and_terminal_unknown_never_carry_ammunition_or_callback(self):
        a=adapter(self.s);begin(a,self.s);a.consume(raw(frame_event(self.s)))
        f=next_frame(self.s['frame'],missed=1);e=frame_event(self.s,f);e['event_sequence']+=1
        out=a.consume(raw(e));row=out['ammunition_projection']['rows'][0]
        self.assertIsNone(row['ammunition_candidate']);self.assertIsNone(row['callback_reconstruction_candidate'])
        self.assertEqual(row['reason'],'gap_before_frame')
        f=next_frame(f);f['guards_after'][0].update(ok=False,error='unreadable_range')
        for sample in f['fields'].values():sample.update(status='unknown',value=None,reason='guard_failed_after',
                                                       read_start_ticks=None,read_end_ticks=None)
        e=frame_event(self.s,f);e['event_sequence']+=2;out=a.consume(raw(e))
        self.assertIsNone(out['ammunition_projection']['rows'][0]['ammunition_candidate'])
        self.assertIsNone(out['relations'][0]['ammunition_candidate'])
        self.assertIsNone(out['relations'][0]['body_object_key'])

    def test_optional_callback_read_failure_preserves_sampled_health_and_position(self):
        a=adapter(self.s);begin(a,self.s);f=copy.deepcopy(self.s['frame'])
        f['fields']['callback_clock_low'].update(status='unknown',value=None,reason='read_failed',
                                                read_start_ticks=None,read_end_ticks=None)
        out=a.consume(raw(frame_event(self.s,f)));row=out['ammunition_projection']['rows'][0]
        self.assertEqual(row['ammunition_candidate']['value'],26)
        self.assertIsNone(row['callback_reconstruction_candidate'])
        self.assertEqual(out['relations'][0]['health_candidate']['raw_sum'],125.5)
        self.assertEqual(out['relations'][0]['position_candidate']['value'],[1,2,3])

    def test_metadata_artifact_corruption_and_failed_entry_cannot_be_admitted(self):
        path=self.s['root']/(self.s['admission']['acquisition_end_sha256']+'.json')
        original=path.read_bytes();path.write_bytes(original+b' ')
        with self.assertRaisesRegex(ValueError,'artifact_hash'):adapter(self.s)
        path.write_bytes(original)
        a=copy.deepcopy(self.s['admission']);entry=copy.deepcopy(self.s['acquired']);entry['acquisition']['complete']=False
        data=raw(entry);h=hashlib.sha256(data).hexdigest();new=self.s['root']/(h+'.json');new.write_bytes(data)
        paths=json.loads((self.s['root']/'artifacts.json').read_bytes());paths[h]=str(new)
        (self.s['root']/'artifacts.json').write_bytes(raw(paths));a['acquisition_end_sha256']=h
        (self.s['root']/'admission.json').write_bytes(raw(a))
        with self.assertRaisesRegex(ValueError,'metadata_scope_mismatch'):adapter(self.s)

    def test_legacy_native_events_without_recording_evidence_are_rejected(self):
        coordinator=LiveSession(lambda *_:self.fail('Factory must not run without native evidence mode'))
        session=copy.deepcopy(self.s['session']);session.pop('recording_frame_included')
        with self.assertRaisesRegex(InvalidLive,'session_start_metadata'):coordinator.consume(raw(session))
        a=adapter(self.s);begin(a,self.s);frame=frame_event(self.s);frame.pop('recording_frame')
        with self.assertRaisesRegex(InvalidLive,'unsupported_recording_frame'):a.consume(raw(frame))
        self.assertTrue(a.failed)

    def test_cli_opt_in_uses_explicit_three_paths(self):
        r=self.s['root']
        completed=subprocess.run([sys.executable,str(Path(__file__).with_name('live_relations.py')),
            '--acquisition',str(r),'--session-id',SESSION,'--segment','1',
            '--ammunition-contract',str(r/'ammunition.json'),'--ammunition-artifacts',str(r/'artifacts.json'),
            '--ammunition-admission',str(r/'admission.json')],
            input=b''.join(raw(e)for e in self.events[:7]),capture_output=True,timeout=10)
        self.assertEqual(completed.returncode,0,completed.stderr)
        output=json.loads(completed.stdout)
        self.assertEqual(output['ammunition_projection']['rows'][0]['callback_reconstruction_candidate']['value'],26)
        self.assertEqual(json.loads(completed.stderr)['frames'],1)


if __name__=='__main__':unittest.main()
