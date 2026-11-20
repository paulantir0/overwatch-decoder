import hashlib
import contextlib
import threading
import io
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

import runtime_producer as runtime



def health_acquisition(root, absent=()):
    """Two synthetic guarded controllers and tiny complete pool extents."""
    import struct
    from test_relations import fixture
    from test_live_relations import raw
    p, _ = fixture(2)
    p['fields'] = [f for f in p['fields'] if not any(f['name'].startswith(f'controller_{i:04d}_body_') for i in absent)]
    recipe = dict(schema='overwatch-decoder.acquisition-recipe/1',target={k:p['target'][k] for k in ('image_name','architecture','executable_sha256')},stages=[dict(name='fixture')])
    reads=[]
    def read(address, data, **kw):
        n=len(reads)
        reads.append(dict(kind='read',id=n,address=address,attempted=True,error=None,
            requested_bytes=len(data),returned_bytes=len(data),bytes_hex=data.hex(),read_start_ticks=100+n*10,read_end_ticks=101+n*10,**kw))
        return n
    for i in range(2):
        if i in absent:continue
        base=0x5000+i*0x100
        p['guards'].extend([dict(address=base,bytes_hex='01000000'),dict(address=base+8,bytes_hex='00000000')])
        p['fields'].append(dict(name=f'controller_{i:04d}_body_0000_pool_0000_direct_candidate',type='f32',address=base+4))
        read(base,struct.pack('<IfIf',1,125.5+i,0,0),purpose='recipe',stage='fixture')
    checks=[]
    for g in p['guards']:
        data=bytes.fromhex(g['bytes_hex']);a=read(g['address'],data);b=read(g['address'],data)
        checks.append(dict(kind='guard_check',stage='final_guard_check',matches=True,expected_read_id=a,actual_read_id=b,expected_offset=0))
    start=dict(schema='overwatch-decoder.acquisition-evidence/1',kind='start',target=p['target'],source_kind='native_process_memory',revision='synthetic',recipe_sha256=hashlib.sha256(raw(recipe)).hexdigest(),monotonic_frequency=1000,monotonic_origin_ticks=0)
    evidence=b''.join(raw(x) for x in [start,*reads,*checks,dict(kind='profile_validated',profile_sha256=hashlib.sha256(raw(p)).hexdigest(),fields=len(p['fields']))])
    manifest=dict(schema='overwatch-decoder.acquisition-result/1',complete=True,error=None,target=p['target'],revision='synthetic',stages_completed=1,fields=len(p['fields']),guard_declarations=len(p['guards']),recipe_sha256=hashlib.sha256(raw(recipe)).hexdigest(),profile_sha256=hashlib.sha256(raw(p)).hexdigest(),evidence_sha256=hashlib.sha256(evidence).hexdigest())
    for name,data in [('recipe.json',raw(recipe)),('profile.json',raw(p)),('manifest.json',raw(manifest)),('evidence.jsonl',evidence)]: (root/name).write_bytes(data)
    layout=dict(schema='overwatch-decoder.health-layout/1',executable_sha256=p['target']['executable_sha256'],recipe_sha256=manifest['recipe_sha256'],extent_size=16,read_stage='fixture',slot_count=2,slot_stride=8,membership_offset=0,scalar_offset=4,actor_prefixes=[f'controller_{i:04d}_body_0000_' for i in range(2)],scalar_field_suffix='_direct_candidate')
    return p,raw(layout)

class ProducerTests(unittest.TestCase):
    def test_same_source_subset_keeps_present_contract_and_all_guards(self):
        from build_health_contracts import build_contracts
        from test_live_relations import raw
        for absent in ((),(0,),(0,1)):
            with self.subTest(absent=absent),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);p,layout=health_acquisition(root,absent)
                if absent:
                    with self.assertRaisesRegex(ValueError,'missing_actor_pool_fields'):build_contracts(root,layout)
                result=runtime.build_present_health_contracts(root,layout,recipe_path=root/'recipe.json')
                self.assertEqual(len(result['contracts']),2-len(absent))
                if not absent:self.assertEqual(result,build_contracts(root,layout))
                else:
                    self.assertEqual(len(result['unresolved_bodies']),len(absent))
                    self.assertFalse(result['previous_contracts_carried'])
                    self.assertEqual(result['requested_layout_sha256'],hashlib.sha256(layout).hexdigest())
                    # Removing even an unrelated retained guard check must fail.
                    rows=[json.loads(l) for l in (root/'evidence.jsonl').read_bytes().splitlines()]
                    rows.pop(-2);evidence=b''.join(raw(x) for x in rows)
                    (root/'evidence.jsonl').write_bytes(evidence)
                    m=json.loads((root/'manifest.json').read_bytes());m['evidence_sha256']=hashlib.sha256(evidence).hexdigest();(root/'manifest.json').write_bytes(raw(m))
                    with self.assertRaisesRegex(ValueError,'unchecked_profile_guard'):
                        runtime.build_present_health_contracts(root,layout,recipe_path=root/'recipe.json')

    def test_subset_never_treats_partial_body_or_missing_health_as_absence(self):
        from test_live_relations import raw
        for mutation in ('partial_body','missing_health','wrong_layout','wrong_recipe'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);p,layout=health_acquisition(root,(0,))
                if mutation=='partial_body':p['fields'].append(dict(name='controller_0000_body_0000_handle_candidate_i32',type='i32',address=0x1018))
                elif mutation=='missing_health':p['fields']=[f for f in p['fields']if not f['name'].endswith('_direct_candidate')]
                else:
                    value=json.loads(layout)
                    if mutation=='wrong_layout':value['actor_prefixes'].pop()
                    else:value['recipe_sha256']='ff'*32
                    layout=raw(value)
                if mutation in ('partial_body','missing_health'):
                    # Invalid partial metadata is rejected, even with an updated profile pin.
                    (root/'profile.json').write_bytes(raw(p));m=json.loads((root/'manifest.json').read_bytes());m['profile_sha256']=hashlib.sha256(raw(p)).hexdigest();m['fields']=len(p['fields'])
                    rows=[json.loads(l)for l in (root/'evidence.jsonl').read_bytes().splitlines()]
                    rows[-1].update(profile_sha256=m['profile_sha256'],fields=m['fields'])
                    evidence=b''.join(raw(r)for r in rows);(root/'evidence.jsonl').write_bytes(evidence)
                    m['evidence_sha256']=hashlib.sha256(evidence).hexdigest();(root/'manifest.json').write_bytes(raw(m))
                with self.assertRaisesRegex(ValueError,'missing_actor_pool_fields' if mutation=='missing_health' else '.'):
                    runtime.build_present_health_contracts(root,layout,recipe_path=root/'recipe.json')

    def test_transport_bounds_preserve_complete_lines(self):
        runtime.validate_line(b'{}\n', 3)
        for raw,total in [(b'',0),(b'{}',2),('text\n',5),(b' '*runtime.MAX_LINE+b'\n',runtime.MAX_LINE+1),(b'{}\n',runtime.MAX_BYTES+1)]:
            with self.subTest(raw_type=type(raw)),self.assertRaises(ValueError):
                runtime.validate_line(raw,total)

    def test_config_requires_explicit_review_and_executable_composer_pins(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in ('native','recipe','composer.py'):(root/name).write_text('def main(): pass\n')
            c=dict(seconds=10,interval_ms=50,private_controlled_fixture_reviewed=True,public_state_eligible=False,
                   target={'pid':12},native_revision='reviewed-revision',reviewed_mode_sources=['review.json'])
            for key in ('health_layout','native_review','roster_review','category_artifacts','hero_catalog','hero_artifacts','output'):
                c[key]=key
                if key!='output':(root/key).write_text('{}')
            (root/'review.json').write_text('{}')
            for key,name,pin in [('native_exe','native','native_sha256'),('recipe','recipe','recipe_sha256'),('composer','composer.py','composer_sha256')]:
                c[key]=name;c[pin]=runtime.digest(root/name)
            checked=runtime.validate_config(c,root)
            self.assertEqual(checked['recipe'],str(root/'recipe'))
            runtime.verify_composer(checked['composer'],c['composer_sha256'])
            for update in ({'seconds':True},{'interval_ms':0},{'public_state_eligible':True},{'private_controlled_fixture_reviewed':False},{'composer_sha256':'0'*64}):
                with self.subTest(update=update),self.assertRaises(ValueError):runtime.validate_config(dict(c,**update),root)
            (root/'composer.py').write_text('raise RuntimeError("must not execute")\n')
            with self.assertRaisesRegex(ValueError,'composer_hash'):runtime.verify_composer(root/'composer.py',c['composer_sha256'])

    def test_raw_config_needs_no_label_or_category_assets_and_rejects_partial_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            c=dict(observation_mode='raw-candidates',seconds=10,interval_ms=50,
                   private_controlled_fixture_reviewed=True,public_state_eligible=False,
                   target={'pid':12},native_revision='explicit',output='out')
            for key,pin in [('native_exe','native_sha256'),('recipe','recipe_sha256'),('health_layout','health_layout_sha256')]:
                (root/key).write_text('{}');c[key]=key;c[pin]=runtime.digest(root/key)
            checked=runtime.validate_config(c,root)
            self.assertNotIn('composer',checked)
            (root/'hero_catalog').write_text('{}');(root/'hero_artifacts').write_text('{}')
            with self.assertRaises(ValueError):
                runtime.validate_config(dict(c,hero_catalog='hero_catalog',hero_artifacts='hero_artifacts'),root)
            for update in ({'hero_catalog':'catalog.json'},{'composer':'composer.py'},
                           {'reviewed_mode_sources':[]},{'include_cached_labels':1},
                           {'health_layout_sha256':'0'*64},{'observation_mode':'automatic'}):
                with self.subTest(update=update),self.assertRaises(ValueError):runtime.validate_config(dict(c,**update),root)
            options=runtime.adapter_options(checked,[])
            self.assertIsNone(options['cached_label_recipe_sha256']);self.assertIsNone(options['hero_catalog'])
            self.assertNotIn('live_category_contract',options)

    def test_optional_cache_unknown_preserves_raw_position_and_health(self):
        from test_live_relations import setup,start,live,raw,SESSION
        from live_relations import LiveRelations
        for cache_case in ('absent','invalid_utf8'):
            with self.subTest(cache_case=cache_case),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);p,f,m,health=setup(root,cache=cache_case=='invalid_utf8',health=True)
                if cache_case=='invalid_utf8':
                    f['fields']['controller_0000_cached_label_0000_byte_0000_value']['value']=255
                c=dict(observation_mode='raw-candidates',recipe=str(root/'recipe.json'),recipe_sha256=m['recipe_sha256'],include_cached_labels=True)
                a=LiveRelations(root,SESSION,1,**runtime.adapter_options(c,health));a.consume(raw(start(p,m)))
                result=a.consume(raw(live(f)));row=result['relations'][0]
                self.assertEqual(row['relation_status'],'observed')
                self.assertEqual(row['position_candidate']['value'],[1,2,3]);self.assertEqual(row['health_candidate']['raw_sum'],125.5)
                self.assertIsNone(row['cached_label_candidate']);self.assertIsNotNone(row['cached_label_reason'])
                self.assertIsNone(row['name']);self.assertIsNone(row['team']);self.assertIsNone(row['hero_label'])
                self.assertFalse(result['category_output_enabled'])

    def test_context_composer_is_opt_in_pinned_and_raw_only(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            c=dict(observation_mode='raw-candidates',seconds=10,interval_ms=50,
                   private_controlled_fixture_reviewed=True,public_state_eligible=False,
                   target={'pid':12},native_revision='explicit',output='out')
            assets=[('native_exe','native_sha256'),('recipe','recipe_sha256'),
                    ('health_layout','health_layout_sha256'),('context_composer','context_composer_sha256'),
                    ('context_inputs','context_inputs_sha256')]
            for key,pin in assets:
                (root/key).write_text('{}');c[key]=key;c[pin]=runtime.digest(root/key)
            checked=runtime.validate_config(c,root)
            self.assertEqual(checked['context_composer'],str(root/'context_composer'))
            for missing in ('context_composer','context_composer_sha256','context_inputs','context_inputs_sha256'):
                altered=dict(c);del altered[missing]
                with self.subTest(missing=missing),self.assertRaisesRegex(ValueError,'complete_context'):
                    runtime.validate_config(altered,root)
            for pin in ('context_composer_sha256','context_inputs_sha256'):
                with self.subTest(pin=pin),self.assertRaisesRegex(ValueError,'pinned_file_mismatch'):
                    runtime.validate_config(dict(c,**{pin:'00'*32}),root)
            with self.assertRaisesRegex(ValueError,'requires_raw_mode'):
                runtime.asset_keys(dict(c,observation_mode='reviewed'))

    def test_context_epoch_outputs_are_fixed_complete_and_explicit(self):
        with tempfile.TemporaryDirectory() as temp:
            prefix=Path(temp)/'context'
            runtime.save(prefix.with_suffix('.options.json'),dict(schema='overwatch-decoder.context-projection-options/1',include_groups=False))
            for suffix in ('.category-contract.json','.controller-contract.json','.admission.json','.artifacts.json'):
                prefix.with_suffix(suffix).write_text('{}')
            options=runtime.context_adapter_options(prefix)
            self.assertEqual(set(options),{'raw_category_contract','context_controller_contract',
                                          'context_projection_admission','context_projection_artifacts'})
            self.assertNotIn('context_group_contract',options)
            group=prefix.with_suffix('.group-contract.json');group.write_text('{}')
            with self.assertRaisesRegex(ValueError,'group_output_mismatch'):runtime.context_adapter_options(prefix)
            runtime.save(prefix.with_suffix('.options.json'),dict(schema='overwatch-decoder.context-projection-options/1',include_groups=True))
            self.assertEqual(runtime.context_adapter_options(prefix)['context_group_contract'],group)
            group.write_text('')
            with self.assertRaisesRegex(ValueError,'output_size'):runtime.context_adapter_options(prefix)
            runtime.save(prefix.with_suffix('.options.json'),dict(schema='overwatch-decoder.context-projection-options/1',include_groups=True,
                                                                 raw_category_contract='../unreviewed.json'))
            with self.assertRaisesRegex(ValueError,'projection_options'):runtime.context_adapter_options(prefix)

    def test_composer_is_pinned_bounded_owned_subprocess(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'composer.py';path.write_text('raise RuntimeError("never run in parent")\n')
            with patch.object(runtime.subprocess,'run') as child:
                runtime.run_composer(path,runtime.digest(path),['--acquisition','fresh'],io.BytesIO(),5)
                self.assertEqual(child.call_args.kwargs['timeout'],5)
                self.assertTrue(child.call_args.kwargs['check'])
                self.assertEqual(child.call_args.args[0][2:], ['--compose',str(path),runtime.digest(path),'--','--acquisition','fresh'])
            with self.assertRaisesRegex(ValueError,'timeout_bound'):
                runtime.run_composer(path,runtime.digest(path),[],io.BytesIO(),31)
            with patch.object(runtime.subprocess,'run',side_effect=subprocess.TimeoutExpired('owned composer',1)):
                with self.assertRaises(subprocess.TimeoutExpired):
                    runtime.run_composer(path,runtime.digest(path),[],io.BytesIO(),1)

    def test_isolated_entrypoints_and_composer_import_from_unrelated_cwd(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in ('runtime_producer.py','runtime_roster.py'):
                command=[runtime.sys.executable,'-I',str(Path(runtime.__file__).with_name(name)),'--help']
                result=subprocess.run(command,cwd=root,capture_output=True,timeout=10)
                self.assertEqual(result.returncode,0,result.stderr.decode())
            composer=root/'composer.py';composer.write_text('import overwatch_decoder\nimport aggregate_partitions\nprint("isolated bundle imports passed")\n')
            command=[runtime.sys.executable,'-I',runtime.__file__,'--compose',str(composer),runtime.digest(composer),'--']
            result=subprocess.run(command,cwd=root,capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr.decode())
            self.assertIn(b'isolated bundle imports passed',result.stdout)

    def test_cleanup_only_owned_handle_and_escalates_bounded_wait(self):
        class Worker:
            def __init__(self):self.returncode=None;self.calls=[]
            def poll(self):return self.returncode
            def terminate(self):self.calls.append('terminate')
            def kill(self):self.calls.append('kill');self.returncode=-9
            def wait(self,timeout):
                self.calls.append(timeout)
                if self.returncode is None:raise subprocess.TimeoutExpired('owned',timeout)
                return self.returncode
        worker=Worker();runtime.stop_owned(worker)
        self.assertEqual(worker.calls,['terminate',10,'kill',5])
        runtime.stop_owned(worker);self.assertEqual(len(worker.calls),4)

    def test_original_control_bytes_visible_while_epoch_factory_is_blocked_then_fails(self):
        controls = [b'{ "kind": "session_start", "fixture": 1 }\n',
                    b'{"kind":"acquisition_end","fixture":2}\n',
                    b'{ "kind":"segment_start", "fixture":3 }\n']
        blocked, release = threading.Event(), threading.Event()
        class Worker:
            def __init__(self):
                self.stdout = io.BytesIO(b''.join(controls)); self.returncode = None
            def poll(self): return self.returncode
            def terminate(self): self.returncode = -15
            def wait(self, timeout): return self.returncode
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); config = root/'config.json'; config.write_text('{}')
            c = dict(observation_mode='raw-candidates', output=str(root/'out'),
                     native_exe='synthetic-native', recipe='synthetic-recipe',
                     target={'pid': 12}, seconds=10, interval_ms=50)
            expected = b''.join(controls)
            class Decoder:
                def __init__(self, factory): pass
                def consume(self, raw):
                    if json.loads(raw)['kind'] == 'segment_start':
                        # The real factory runs synchronously here. The file is
                        # still open and has not reached normal context cleanup.
                        self_outer.assertEqual((root/'out/native.jsonl').read_bytes(), expected)
                        blocked.set()
                        if not release.wait(2): raise RuntimeError('fixture_wait_timeout')
                        raise RuntimeError('fixture_epoch_initialization')
                    return None
            self_outer = self
            codes, log = [], io.StringIO()
            with contextlib.redirect_stdout(log), patch('runtime_jobs.enroll_current_producer'), \
                    patch.object(runtime.sys, 'platform', 'win32'), \
                    patch.object(runtime, 'qpc', return_value=100), \
                    patch.object(runtime, 'validate_config', return_value=c), \
                    patch.object(runtime.subprocess, 'Popen', return_value=Worker()), \
                    patch.dict('sys.modules', {'live_sessions': types.SimpleNamespace(LiveSession=Decoder)}):
                worker = threading.Thread(target=lambda: codes.append(runtime.run(config)))
                worker.start()
                try:
                    self.assertTrue(blocked.wait(2), log.getvalue())
                    self.assertTrue(worker.is_alive())
                    self.assertEqual((root/'out/native.jsonl').read_bytes(), expected)
                    self.assertEqual((root/'out/entities.jsonl').read_bytes(), b'')
                finally:
                    release.set(); worker.join(timeout=3)
                self.assertFalse(worker.is_alive())
            self.assertEqual(codes, [1])
            result = json.loads((root/'out/result.json').read_bytes())
            self.assertIn('fixture_epoch_initialization', result['error'])
            self.assertEqual(result['native_bytes'], len(expected))
            self.assertEqual(result['events'], 3)
            self.assertEqual((root/'out/native.jsonl').read_bytes(), expected)

    def test_control_flush_does_not_add_frame_flushes_or_reencode_bytes(self):
        class Output(io.BytesIO):
            def __init__(self): super().__init__(); self.flushes = 0
            def flush(self): self.flushes += 1
        output = Output()
        lines = [b'{ "kind": "session_start" }\n',
                 b'{ "kind": "frame", "value": 1.0 }\n',
                 b'{"kind":"frame","value":null}\n',
                 b'{ "kind": "segment_end" }\n']
        for raw in lines: runtime._write_native_event(output, raw, json.loads(raw))
        self.assertEqual(output.getvalue(), b''.join(lines))
        self.assertEqual(output.flushes, 2)

    def test_bounded_initialization_stage_markers_preserve_result_and_failure(self):
        value = {'untouched': [1]}
        for fail in (False, True):
            with self.subTest(fail=fail), patch.object(runtime, 'qpc', side_effect=[11, 12]):
                log = io.StringIO()
                def operation():
                    if fail: raise ValueError('fixture_stage')
                    return value
                with contextlib.redirect_stdout(log):
                    if fail:
                        with self.assertRaisesRegex(ValueError, 'fixture_stage'):
                            runtime._producer_stage('fixture', 2, 1000, operation)
                    else:
                        self.assertIs(runtime._producer_stage('fixture', 2, 1000, operation), value)
                rows = [json.loads(line) for line in log.getvalue().splitlines()]
                self.assertEqual(len(rows), 2)
                self.assertEqual([r['qpc'] for r in rows], [11, 12])
                self.assertEqual([r['phase'] for r in rows], ['start', 'failed' if fail else 'complete'])
                self.assertTrue(all(r['segment'] == 2 and r['monotonic_frequency'] == 1000 for r in rows))
        self.assertEqual(value, {'untouched': [1]})

    def test_malformed_native_transport_is_recorded_failure_and_owned_child_stopped(self):
        class Worker:
            def __init__(self,raw):self.stdout=io.BytesIO(raw);self.returncode=None;self.terminated=False
            def poll(self):return self.returncode
            def terminate(self):self.terminated=True;self.returncode=-15
            def wait(self,timeout):return self.returncode
        class Decoder:
            def __init__(self,factory):pass
            def consume(self,raw):return None
            def close(self):return {'native_session_end_seen':True,'failed':False}
        for raw in (b'{"kind":"truncated"}', b' '*runtime.MAX_LINE+b'\n'):
            with self.subTest(length=len(raw)),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);config=root/'config.json';config.write_text('{}');worker=Worker(raw)
                c=dict(output=str(root/'out'),composer=__file__,composer_sha256='0'*64,native_exe='explicit-native',recipe='explicit-recipe',target={'pid':12},seconds=10,interval_ms=50)
                with patch('runtime_jobs.enroll_current_producer'),patch.object(runtime.sys,'platform','win32'),patch.object(runtime,'qpc',return_value=100),patch.object(runtime,'validate_config',return_value=c),patch.object(runtime,'verify_composer'),patch.object(runtime.subprocess,'Popen',return_value=worker),patch.dict('sys.modules',{'live_sessions':types.SimpleNamespace(LiveSession=Decoder)}):
                    self.assertEqual(runtime.run(config),1)
                result=json.loads((root/'out/result.json').read_bytes())
                self.assertFalse(result['complete']);self.assertIn('native_line_bound',result['error'])
                self.assertTrue(worker.terminated);self.assertEqual(result['frames'],0)
                self.assertEqual((root/'out/entities.jsonl').read_bytes(),b'')

if __name__=='__main__':unittest.main()
