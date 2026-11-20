"""Portable producer composition tests; these do not claim Windows collection."""
import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import runtime_producer as runtime
from live_relations import LiveRelations
from live_sessions import LiveSession
from test_live_ammunition import fixture
from test_live_relations import raw


# This caller fixture selects a prebuilt synthetic contract for the exact
# acquisition. Production callers must derive and verify their own reviews.
COMPOSER = '''
import argparse,json,shutil
from pathlib import Path
p=argparse.ArgumentParser()
for key in ('acquisition','recipe','session-start','acquisition-end','segment-start','inputs','output-prefix'):
    p.add_argument('--'+key,required=True)
a=p.parse_args();inputs=json.loads(Path(a.inputs).read_bytes())
prefix=Path(a.output_prefix);source=Path(inputs['sources'])/Path(a.acquisition).name
for origin,suffix in [('ammunition.json','.contract.json'),('artifacts.json','.artifacts.json'),('admission.json','.admission.json')]:
    shutil.copyfile(source/origin,str(prefix)+suffix)
Path(str(prefix)+'.called.json').write_text(json.dumps(vars(a)))
'''


class RuntimeAmmunitionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sources, self.events = fixture(self.root)
        self.composer = self.root/'composer.py'
        self.composer.write_text(COMPOSER)
        self.inputs = self.root/'inputs.json'
        runtime.save(self.inputs, dict(sources=str(self.root)))
        self.config = dict(ammunition_composer=str(self.composer),
            ammunition_composer_sha256=runtime.digest(self.composer),
            ammunition_inputs=str(self.inputs),
            ammunition_inputs_sha256=runtime.digest(self.inputs),
            recipe=str(self.sources[1]['root']/'recipe.json'))

    def compose(self, ordinal=1, *, config=None, metadata=None, epoch=None):
        source = self.sources[ordinal]
        epoch = epoch or self.root/f'epoch-{ordinal:04d}'
        epoch.mkdir(exist_ok=True)
        return runtime.ammunition_adapter_options(config or self.config, source['root'], epoch,
            source['session'], source['acquired']['acquisition'], source['segment'],
            metadata or tuple(raw(source[k]) for k in ('session','acquired','segment')), timeout=10)

    def test_optional_configuration_is_complete_pinned_and_mode_independent(self):
        c = dict(self.config, observation_mode='raw-candidates', seconds=10, interval_ms=50,
            private_controlled_fixture_reviewed=True, public_state_eligible=False,
            target={'pid':12}, native_revision='synthetic', output='out')
        for key,pin in [('native_exe','native_sha256'),('recipe','recipe_sha256'),
                        ('health_layout','health_layout_sha256')]:
            path=self.root/key;path.write_bytes(b'{}');c[key]=str(path);c[pin]=runtime.digest(path)
        checked=runtime.validate_config(c,self.root)
        self.assertEqual(checked['ammunition_composer'],str(self.composer))
        for missing in ('ammunition_composer','ammunition_composer_sha256','ammunition_inputs','ammunition_inputs_sha256'):
            altered=dict(c);del altered[missing]
            with self.subTest(missing=missing),self.assertRaisesRegex(ValueError,'complete_ammunition'):
                runtime.validate_config(altered,self.root)
        for pin in ('ammunition_composer_sha256','ammunition_inputs_sha256'):
            with self.subTest(pin=pin),self.assertRaisesRegex(ValueError,'pinned_file_mismatch'):
                runtime.validate_config(dict(c,**{pin:'0'*64}),self.root)
        self.assertIn('ammunition_composer',runtime.asset_keys(dict(c,observation_mode='reviewed')))

    def test_absent_composer_does_not_touch_metadata_or_call_child(self):
        with patch.object(runtime,'run_composer') as run:
            self.assertEqual(runtime.ammunition_adapter_options({},None,None,None,None,None,None,timeout=10),{})
        run.assert_not_called()

    def test_ability_only_raw_config_does_not_require_or_invent_health(self):
        config=dict(self.config,observation_mode='raw-candidates',include_health_candidates=False,
            seconds=10,interval_ms=50,private_controlled_fixture_reviewed=True,public_state_eligible=False,
            target=self.sources[1]['profile']['target'],native_revision='synthetic',output='out')
        config['native_exe']=str(self.composer);config['native_sha256']=runtime.digest(self.composer)
        config['recipe_sha256']=runtime.digest(config['recipe'])
        checked=runtime.validate_config(config,self.root)
        self.assertNotIn('health_layout',runtime.asset_keys(checked))
        for change,reason in [({'include_health_candidates':0},'invalid_health_candidate_option'),
                              ({'observation_mode':'reviewed'},'disabled_health_requires_raw_mode'),
                              ({'health_layout':'some-layout'},'disabled_health_has_layout_inputs'),
                              ({'forward_owner_health_layout':'some-layout'},'disabled_health_has_layout_inputs')]:
            with self.subTest(change=change),self.assertRaisesRegex(ValueError,reason):
                runtime.validate_config(dict(config,**change),self.root)

    def test_two_actual_epoch_envelopes_reach_composer_and_live_adapter(self):
        def factory(session,admitted,segment):
            epoch=self.root/f"epoch-{segment['segment']:04d}";epoch.mkdir()
            source=self.sources[admitted['ordinal']]
            options=runtime.ammunition_adapter_options(self.config,source['root'],epoch,
                session,admitted,segment,(coordinator.session_raw,coordinator.completed_raw,current),timeout=10)
            return LiveRelations(source['root'],session['session_id'],segment['segment'],**options)
        coordinator=LiveSession(factory);outputs=[]
        for event in self.events:
            current=raw(event)
            result=coordinator.consume(current)
            if result is not None:outputs.append(result)
        self.assertTrue(coordinator.close()['native_session_end_seen'])
        self.assertEqual(len(outputs),2)
        for n,result in enumerate(outputs,1):
            self.assertEqual(result['relations'][0]['ammunition_candidate']['value'],26)
            epoch=self.root/f'epoch-{n:04d}'
            invocation=json.loads((epoch/'ammunition.called.json').read_bytes())
            for argument,key in [('session_start','session'),('acquisition_end','acquired'),('segment_start','segment')]:
                data=Path(invocation[argument]).read_bytes()
                self.assertEqual(data,raw(self.sources[n][key]))
                self.assertEqual(hashlib.sha256(data).hexdigest(),result['ammunition_live_admission'][argument+'_event_sha256'])
        self.assertNotEqual(outputs[0]['ammunition_contract_sha256'],outputs[1]['ammunition_contract_sha256'])

    def test_original_pretty_bytes_are_preserved_not_reserialized(self):
        source=self.sources[1]
        metadata=tuple((json.dumps(source[key],indent=3)+'\n').encode() for key in ('session','acquired','segment'))
        self.compose(metadata=metadata)
        for name,data in zip(('session-start','acquisition-end','segment-start'),metadata):
            self.assertEqual((self.root/'epoch-0001'/('ammunition-'+name+'.json')).read_bytes(),data)

    def projected_epochs(self):
        def factory(session, admitted, segment):
            source = self.sources[admitted['ordinal']]
            return LiveRelations(source['root'], session['session_id'], segment['segment'],
                **self.compose(admitted['ordinal']))
        coordinator = LiveSession(factory)
        outputs = [value for event in self.events
                   if (value := coordinator.consume(raw(event))) is not None]
        self.assertTrue(coordinator.close()['native_session_end_seen'])
        return outputs

    def test_parent_ammunition_admission_requires_explicit_configuration(self):
        import runtime_roster as roster
        self.assertIsNone(roster.ammunition_source_admission(None, None, None, None,
                                                           None, {}))
        frame = self.projected_epochs()[0]
        with self.assertRaisesRegex(ValueError, 'unconfigured_ammunition_projection'):
            roster.ammunition_source_admission(None, None, None, None, None, frame)
        with self.assertRaisesRegex(ValueError, 'ammunition_output_flag'):
            roster.ammunition_source_admission(None, None, None, None, None, {}, enabled=1)

    def test_parent_admission_matches_actual_native_metadata_and_frame(self):
        import runtime_roster as roster
        frames = self.projected_epochs()
        frame = frames[0]
        source = self.sources[1]
        metadata = [source[key] for key in ('session', 'acquired', 'segment')]
        def admit(items=metadata, sample=frame):
            return roster.ammunition_source_admission(source['root'], self.root/'epoch-0001',
                *items, sample, enabled=True)
        admission = admit()
        self.assertEqual(admission['contract_sha256'], frame['ammunition_contract_sha256'])
        for index in range(3):
            changed = copy.deepcopy(metadata)
            changed[index]['event_sequence'] += 1
            with self.subTest(metadata=index), self.assertRaisesRegex(
                    ValueError, 'ammunition_native_metadata_mismatch'):
                admit(changed)
        altered = copy.deepcopy(frame)
        altered['relations'][0]['ammunition_candidate'] = dict(
            altered['relations'][0]['ammunition_candidate'], value=99)
        with self.assertRaisesRegex(ValueError, 'ammunition_relation_join'):
            admit(sample=altered)
        second = self.sources[2]
        with self.assertRaisesRegex(ValueError, 'ammunition_acquisition_mismatch'):
            roster.ammunition_source_admission(second['root'], self.root/'epoch-0001',
                second['session'], second['acquired'], second['segment'],
                frames[1], enabled=True)

    def test_parent_source_admission_keeps_each_epochs_verified_ammunition(self):
        import runtime_roster as roster
        frames = self.projected_epochs()
        native = self.root/'native'
        native.mkdir()
        for n in (1, 2):
            (native/f'acquisition-{n:04d}').symlink_to(self.sources[n]['root'], target_is_directory=True)
        (self.root/'native.jsonl').write_bytes(b''.join(raw(event) for event in self.events))
        row = frames[0]['relations'][0]
        key = row['controller_object_key']
        roles = {key: dict(full_handle=row['evidence'][0]['value'],
                          creation_key=row['evidence'][1]['value'])}
        plan = dict(target=frames[0]['target'], partitions=[dict(ordinal=1,
            controllers=[dict(controller_object_key=key)],
            recipe_sha256=self.sources[1]['manifest']['recipe_sha256'])])
        child = dict(source_id='p1', ordinal=1, directory=str(self.root),
                     ammunition_output_enabled=True)
        metadata = roster.NativeMetadata()
        admissions = []
        try:
            for n, frame in enumerate(frames, 1):
                source, _, pins = roster.source_admission(child, plan, roles, {key: 1},
                    metadata, raw(frame), initial=n == 1, raw_candidates=True)
                admissions.append(source['ammunition'])
                self.assertEqual(source['ammunition'], pins['ammunition'])
                self.assertEqual(source['ammunition']['contract_sha256'],
                                 frame['ammunition_contract_sha256'])
                self.assertEqual(source['ammunition']['live']['admission']['segment'], n)
            self.assertNotEqual(admissions[0]['contract_sha256'], admissions[1]['contract_sha256'])
        finally:
            metadata.close()

    def test_stale_acquisition_metadata_is_rejected_before_composer(self):
        source=self.sources[1]
        metadata=tuple(raw(source[key]) for key in ('session','acquired','segment'))
        changed=list(metadata);changed[1]=raw(self.sources[2]['acquired'])
        with patch.object(runtime,'run_composer') as run:
            with self.assertRaisesRegex(ValueError,'original_metadata_mismatch'):
                self.compose(metadata=tuple(changed))
        run.assert_not_called()
        self.assertEqual(list((self.root/'epoch-0001').iterdir()),[])

    def test_changed_input_or_code_pin_is_rejected_at_epoch(self):
        self.inputs.write_text('{}')
        with self.assertRaisesRegex(ValueError,'pinned_file_mismatch:ammunition_inputs'):
            self.compose()
        runtime.save(self.inputs,dict(sources=str(self.root)))
        self.composer.write_text('raise RuntimeError("not authorized")')
        with self.assertRaisesRegex(ValueError,'composer_hash_or_size'):
            self.compose()

    def test_missing_or_oversized_composer_outputs_fail(self):
        def incomplete(path,pin,args,log,timeout):
            prefix=Path(args[args.index('--output-prefix')+1])
            prefix.with_suffix('.contract.json').write_bytes(b'{}')
            prefix.with_suffix('.artifacts.json').write_bytes(b'{}')
        with patch.object(runtime,'run_composer',side_effect=incomplete):
            with self.assertRaisesRegex(ValueError,'output_size:ammunition_admission'):
                self.compose()
        def oversized(path,pin,args,log,timeout):
            prefix=Path(args[args.index('--output-prefix')+1])
            prefix.with_suffix('.contract.json').write_bytes(b' '*(runtime.MAX_LINE+1))
        with patch.object(runtime,'run_composer',side_effect=oversized):
            with self.assertRaisesRegex(ValueError,'output_size:ammunition_contract'):
                self.compose(epoch=self.root/'oversized')

    def test_producer_transport_wires_each_epoch_and_records_optional_output(self):
        self.run_producer_transport(health_enabled=True)

    def test_ability_only_transport_verifies_census_and_emits_no_health(self):
        self.run_producer_transport(health_enabled=False)

    def test_ability_only_transport_rejects_unverified_census_before_composition(self):
        self.run_producer_transport(health_enabled=False, invalid_census=True)

    def run_producer_transport(self, *, health_enabled, invalid_census=False):
        """Real adapters/composer/compact projection with a portable native pipe."""
        source=self.sources[1]
        source['session']['revision']='synthetic'
        metadata=raw(source['session']);pin=hashlib.sha256(metadata).hexdigest()
        for s in self.sources.values():
            metadata_path=s['root']/'session-with-revision.json';metadata_path.write_bytes(metadata)
            artifacts=json.loads((s['root']/'artifacts.json').read_bytes())
            artifacts[pin]=str(metadata_path);runtime.save(s['root']/'artifacts.json',artifacts)
            admission=json.loads((s['root']/'admission.json').read_bytes())
            admission['session_start_sha256']=pin;runtime.save(s['root']/'admission.json',admission)
        config=dict(self.config, observation_mode='raw-candidates', seconds=10, interval_ms=50,
            private_controlled_fixture_reviewed=True, public_state_eligible=False,
            target=source['profile']['target'], native_revision=source['session']['revision'],
            native_exe='synthetic-native', recipe_sha256=source['manifest']['recipe_sha256'],
            health_layout=str(self.root/'layout.json'), output=str(self.root/'out'))
        (self.root/'layout.json').write_bytes(b'{}')
        if not health_enabled:
            config.pop('health_layout')
            config['include_health_candidates']=False
        path=self.root/'config.json';runtime.save(path,config)
        worker=type('Worker',(),{})()
        worker.stdout=io.BytesIO(b''.join(raw(event) for event in self.events))
        worker.returncode=None
        worker.poll=lambda:worker.returncode
        def wait(timeout):
            worker.returncode=0
            return 0
        worker.wait=wait
        worker.terminate=lambda:setattr(worker,'returncode',1)
        real_popen=subprocess.Popen
        def popen(command,**kwargs):
            if command[0]!='synthetic-native':return real_popen(command,**kwargs)
            native=self.root/'out/native';native.mkdir()
            for s in self.sources.values():shutil.copytree(s['root'],native/s['root'].name)
            return worker
        def health(acquisition,layout,*,recipe_path):
            return dict(contracts=[json.loads((Path(acquisition)/'health.json').read_bytes())])
        with patch('runtime_jobs.enroll_current_producer'), \
             patch.object(runtime.sys,'platform','win32'), \
             patch.object(runtime,'qpc',return_value=10000), \
             patch.object(runtime,'validate_config',return_value=config), \
             patch.object(runtime,'build_present_health_contracts',side_effect=health) as health_builder, \
             patch('plan_live_roster.verified_census',return_value={'source':{'synthetic':True}},
                   side_effect=ValueError('fixture_unverified_census') if invalid_census else None) as census, \
             patch.object(runtime.subprocess,'Popen',side_effect=popen), \
             patch('sys.stdout',new=io.StringIO()):
            self.assertEqual(runtime.run(path),1 if invalid_census else 0)
        out=self.root/'out';result=json.loads((out/'result.json').read_bytes())
        if health_enabled:
            self.assertEqual(health_builder.call_count,2)
            census.assert_not_called()
        else:
            health_builder.assert_not_called()
            self.assertEqual(census.call_count,1 if invalid_census else 2)
            for ordinal,call in enumerate(census.call_args_list,1):
                self.assertEqual(call.args,(out/f'native/acquisition-{ordinal:04d}',config['recipe']))
                self.assertEqual(call.kwargs,{'expected_target':config['target']})
        if invalid_census:
            self.assertFalse(result['complete']);self.assertEqual(result['frames'],0)
            self.assertIn('fixture_unverified_census',result['error'])
            self.assertFalse((out/'epoch-0001/ammunition.called.json').exists())
            return
        self.assertTrue(result['complete']);self.assertEqual(result['frames'],2)
        self.assertEqual([epoch['frames']for epoch in result['epochs']],[1,1])
        rows=[json.loads(line)for line in(out/'entities.jsonl').read_bytes().splitlines()]
        self.assertEqual([r['relations'][0]['ammunition_candidate']['value']for r in rows],[26,26])
        self.assertEqual((out/'native.jsonl').read_bytes(),b''.join(raw(event)for event in self.events))
        self.assertEqual(len((out/'compact.jsonl').read_bytes().splitlines()),2)
        self.assertEqual(json.loads((out/'runtime.json').read_bytes())['ammunition_composer_sha256'],config['ammunition_composer_sha256'])
        if not health_enabled:
            for ordinal in (1,2):
                bundle=json.loads((out/f'epoch-{ordinal:04d}/health-bundle.json').read_bytes())
                self.assertEqual(bundle['contracts'],[])
                self.assertEqual(bundle['source'],{'synthetic':True})
                self.assertEqual(bundle['reason'],'explicit_raw_producer_configuration')
            self.assertTrue(all(row['relations'][0]['health_candidate'] is None for row in rows))


if __name__=='__main__':
    unittest.main()
