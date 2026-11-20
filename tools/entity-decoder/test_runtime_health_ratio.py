"""Offline transport tests with synthetic native data, never Windows collection."""
import copy
import io
import json
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch

import runtime_producer as runtime
import runtime_roster as roster
from aggregate_live_partitions import LivePartitions
from compact_live_roster import CompactLiveRoster
from live_relations import LiveRelations
from live_sessions import LiveSession
from test_build_health_ratio_contracts import Saved, raw, sha
from test_live_health_ratio import config_for
from test_live_relations import SESSION, event, live, start, raw as event_raw
from test_relations import prepare


def source_frame(source, ordinal):
    """Read synthetic field values from the fixture's supplied bytes."""
    values = {}
    for field in source.profile['fields']:
        at, kind = field['address'], field['type']
        if kind == 'i32':
            guard = next(g for g in source.profile['guards'] if g['address'] == at)
            value = struct.unpack('<i', bytes.fromhex(guard['bytes_hex']))[0]
        else:
            base, data = next((base, data) for base, data in source.extents
                              if base <= at < base+len(data))
            width = 1 if kind == 'f32' else int(kind[-1])
            parts = struct.unpack_from('<'+'f'*width, data, at-base)
            value = parts[0] if width == 1 else list(parts)
        values[field['name']] = value
    _, frame = prepare(source.profile, values)
    frame['profile_sha256'] = source.manifest['profile_sha256']
    frame.update(interpretation='profile_declared_research', visibility='research',
        runtime_semantics_validated=False, public_state_eligible=False, atomic=False,
        scheduled_slot=0, scheduled_ticks=0, jitter_ticks=10,
        skipped_intervals_before=0, skipped_intervals_total=0, utc_origin_before_ticks=0,
        requested_interval_ms=100, scheduler_backend='synthetic', hard_realtime=False)
    delta = ordinal*1000
    for key in ('start_ticks','end_ticks','scheduled_ticks','monotonic_origin_ticks',
                'utc_origin_before_ticks'):
        frame[key] += delta
    kinds = {f['name']: f['type'] for f in source.profile['fields']}
    for name, sample in frame['fields'].items():
        sample.update(type=kinds[name], reason=None)
        sample['read_start_ticks'] += delta
        sample['read_end_ticks'] += delta
    for phase in ('guards_before','guards_after'):
        for guard in frame[phase]:
            guard['start_ticks'] += delta
            guard['end_ticks'] += delta
    return frame


def native_events(sources):
    events = []
    def add(kind, emitted, **kwargs):
        row = event(kind, len(events), **kwargs)
        row['emitted_ticks'] = emitted
        events.append(row)
    first = sources[0]
    add('session_start', 100, target=first.profile['target'],
        recipe_sha256=first.manifest['recipe_sha256'], revision='fixture',
        source_kind='native_process_memory', recording_frame_included=True,
        atomic=False, public_state_eligible=False, monotonic_origin_ticks=0)
    previous = 0
    for ordinal, source in enumerate(sources, 1):
        frame = source_frame(source, ordinal)
        add('acquisition_start', ordinal*1000-790, acquisition=ordinal,
            start_ticks=ordinal*1000-800, observation_gap_open=True, gap_start_ticks=previous)
        add('acquisition_end', ordinal*1000-190, acquisition=dict(ordinal=ordinal,
            directory=f'acquisition-{ordinal:04d}', start_ticks=ordinal*1000-800,
            end_ticks=ordinal*1000-200, complete=True, error=None,
            profile_sha256=source.manifest['profile_sha256'],
            manifest_sha256=runtime.digest(source.root/'manifest.json')))
        segment = start(source.profile, source.manifest)
        segment.update(event_sequence=len(events), segment=ordinal, acquisition=ordinal,
                       start_ticks=ordinal*1000-100, emitted_ticks=ordinal*1000-90)
        events.append(segment)
        add('gap', frame['end_ticks']+10, interval=dict(start_ticks=previous,
            end_ticks=frame['start_ticks'], meaning='synthetic gap'))
        sample = live(frame, len(events))
        sample.update(segment=ordinal, emitted_ticks=frame['end_ticks']+20)
        events.append(sample)
        add('segment_end', frame['end_ticks']+30, terminal_summary_written=True, failure=None,
            recording_state='closed_manifest_available_not_independently_verified', segment=dict(
                ordinal=ordinal, acquisition=ordinal, profile_sha256=source.manifest['profile_sha256'],
                start_ticks=ordinal*1000-100, end_ticks=frame['end_ticks']+25, frames=1,
                first_frame_start_ticks=frame['start_ticks'], last_frame_end_ticks=frame['end_ticks'],
                trigger='guard_invalidation' if ordinal<len(sources) else 'cancelled'))
        previous = frame['end_ticks']
    add('gap', previous+40, interval=dict(start_ticks=previous, end_ticks=previous+40,
                                         meaning='synthetic terminal gap'))
    add('session_end', previous+50, result_before_this_write=dict(schema='overwatch-decoder.field-observation/1',
        session_id=SESSION, status='finished', complete=True, target=first.profile['target'],
        recipe_sha256=first.manifest['recipe_sha256'], public_state_eligible=False, atomic=False))
    return events


class RuntimeHealthRatioTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = Saved(self.root/'source')
        self.config = self.config_for(self.source)

    def config_for(self, source):
        config = dict(observation_mode='raw-candidates', seconds=10, interval_ms=50,
            private_controlled_fixture_reviewed=True, public_state_eligible=False,
            target=source.profile['target'], native_revision='fixture',
            recipe=str(source.root/'recipe.json'), recipe_sha256=source.manifest['recipe_sha256'],
            output=str(self.root/'out'))
        for key, data in [('health_layout',raw(source.health_layout)),
                          ('health_ratio_layout',raw(source.layout)),
                          ('health_ratio_native_review',source.review), ('native_exe',b'synthetic')]:
            path = source.root/(key+'.json')
            path.write_bytes(data)
            config[key] = str(path)
            config['native_sha256' if key=='native_exe' else key+'_sha256'] = sha(data)
        return config

    def pins(self, config=None):
        c = self.config if config is None else config
        return {key:c[key] for key in ('health_layout_sha256','health_ratio_layout_sha256',
                                       'health_ratio_native_review_sha256')}

    def compose(self, source=None, ordinal=1, config=None):
        source = source or self.source
        epoch = self.root/f'epoch-{ordinal:04d}'
        epoch.mkdir()
        health = source.health()
        runtime.save(epoch/'health-bundle.json', health)
        descriptors = []
        for index, descriptor in enumerate(health['contracts']):
            path = epoch/f'health-contract-{index:04d}.json'
            runtime.save(path, descriptor)
            descriptors.append(path)
        options = runtime.health_ratio_adapter_options(config or self.config, source.root, epoch, health)
        return epoch, dict(health_contracts=descriptors, **options)

    def projected(self, sources=None):
        sources = sources or [self.source]
        events = native_events(sources)
        def factory(session, acquisition, segment):
            number = segment['segment']
            source = sources[number-1]
            _, options = self.compose(source, number)
            return LiveRelations(source.root, SESSION, number, **options)
        coordinator = LiveSession(factory)
        outputs = [value for row in events if (value:=coordinator.consume(raw(row))) is not None]
        self.assertTrue(coordinator.close()['native_session_end_seen'])
        return outputs, events

    def admit(self, frame, *, source=None, ordinal=1, pins=None):
        return roster.health_ratio_source_admission((source or self.source).root,
            self.root/f'epoch-{ordinal:04d}', frame,
            input_pins=self.pins() if pins is None else pins, raw_candidates=True)

    def test_opt_in_configuration_is_complete_bounded_and_pinned(self):
        self.assertEqual(runtime.validate_config(self.config,self.root),self.config)
        for key in ('health_ratio_layout','health_ratio_layout_sha256',
                    'health_ratio_native_review','health_ratio_native_review_sha256'):
            altered = dict(self.config); del altered[key]
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'complete_health_ratio_inputs'):
                runtime.validate_config(altered,self.root)
        for key in self.pins():
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'pinned_file_mismatch'):
                runtime.validate_config(dict(self.config,**{key:'0'*64}),self.root)
        disabled = dict(self.config,include_health_candidates=False)
        disabled.pop('health_layout');disabled.pop('health_layout_sha256')
        with self.assertRaisesRegex(ValueError,'health_ratio_requires_health_candidates'):
            runtime.validate_config(disabled,self.root)
        self.assertIn('health_ratio_layout',runtime.asset_keys(dict(self.config,observation_mode='reviewed')))

    def test_prelaunch_type_build_and_review_checks(self):
        for key, change, reason in (
            ('health_ratio_layout',{'vector_type':'f32x4'},'live_ratio_requires_f32x3'),
            ('health_ratio_layout',{'executable_sha256':'f'*64},'health_ratio_layout_scope'),
            ('health_ratio_layout',{'recipe_sha256':'f'*64},'health_ratio_layout_scope'),
            ('health_ratio_native_review',{'build_sha256':'f'*64},'health_ratio_native_review_scope')):
            config = dict(self.config)
            original = Path(config[key]).read_bytes()
            changed = dict(json.loads(original),**change)
            Path(config[key]).write_bytes(raw(changed));config[key+'_sha256']=sha(raw(changed))
            with self.subTest(change=change),self.assertRaisesRegex(ValueError,reason):
                runtime.validate_config(config,self.root)
            Path(config[key]).write_bytes(original)

    def test_runtime_inventory_requires_arithmetic_code_as_well_as_builder(self):
        bundle=self.root/'bundle';bundle.mkdir();inventory={}
        modules=('runtime_roster.py','runtime_producer.py','runtime_jobs.py',
                 'build_health_ratio_contracts.py','health_ratio_validation.py')
        package=('overwatch_decoder/__init__.py','overwatch_decoder/health_ratio.py','overwatch_decoder/health_projection.py')
        for relative in [*('tools/entity-decoder/'+name for name in modules),*package]:
            data=(Path(__file__).resolve().parents[2]/relative).read_bytes()
            path=bundle/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
            inventory[relative]=dict(bytes=len(data),sha256=sha(data))
        runtime.save(bundle/'inventory.json',inventory)
        self.assertEqual(roster.verify_runtime_inventory(bundle,required_modules=modules[3:],
            required_files=package)['files'],8)
        inventory.pop('overwatch_decoder/health_ratio.py');runtime.save(bundle/'inventory.json',inventory)
        with self.assertRaisesRegex(ValueError,'runtime_dependency_not_in_inventory'):
            roster.verify_runtime_inventory(bundle,required_modules=modules[3:],required_files=package)

    def test_default_has_no_ratio_files_and_rejects_unconfigured_projection(self):
        self.assertEqual(runtime.health_ratio_adapter_options({},None,None,None),{})
        self.assertEqual(roster.health_ratio_source_admission(None,None,{}),(None,None))
        frame = self.projected()[0][0]
        with self.assertRaisesRegex(ValueError,'unconfigured_health_ratio_projection'):
            roster.health_ratio_source_admission(None,None,frame)

    def test_parent_rebuild_reaches_aggregate_and_compact_with_exact_operands(self):
        frame = self.projected()[0][0]
        projection, receipt = self.admit(frame)
        self.assertEqual(projection,frame['health_ratio_projection'])
        self.assertEqual(receipt['contracts'],1)
        value = frame['relations'][0]['health_ratio_candidate']
        self.assertEqual((value['numerator_sum'],value['native_denominator_sum']),(198.,400.))
        config = config_for(frame,self.source.profile)
        config['sources'][0]['health_ratio_projection'] = projection
        adapter = LivePartitions(raw(config))
        adapter.consume('p1',raw(frame))
        windows = list(adapter.advance(1200))
        compact = CompactLiveRoster()
        rows = [compact.consume(raw(window)) for window in windows]
        self.assertEqual(rows[-1]['players'][0]['health_ratio_candidate']['value']['numerator_sum'],198.)
        self.assertIsNone(rows[-1]['players'][0]['health_ratio_candidate']['value']['maximum_health'])

    def test_parent_rejects_empty_slot_omission_stale_bundle_and_changed_frame(self):
        frame = self.projected()[0][0]
        epoch = self.root/'epoch-0001'
        for filename, change, reason in (
            ('health-bundle.json',lambda d:d['contracts'][0]['slots'].pop(1),'fresh_health_bundle'),
            ('health-ratio-bundle.json',lambda d:d.update(profile_sha256='f'*64),'fresh_bundle'),
            ('health-ratio-contract-0000.json',lambda d:d['source'].update(evidence_sha256='f'*64),'fresh_contract')):
            path = epoch/filename; original = path.read_bytes(); altered=json.loads(original)
            change(altered);runtime.save(path,altered)
            with self.subTest(filename=filename),self.assertRaisesRegex(ValueError,reason):
                self.admit(frame)
            path.write_bytes(original)
        altered=copy.deepcopy(frame)
        altered['relations'][0]['health_ratio_candidate']['numerator_sum']=999.
        with self.assertRaisesRegex(ValueError,'ratio_arithmetic_mismatch'):self.admit(altered)
        altered=copy.deepcopy(frame);altered['health_ratio_contract_sha256']=['f'*64]
        with self.assertRaisesRegex(ValueError,'health_ratio_projection_mismatch'):self.admit(altered)

    def test_new_source_and_bodyless_epoch_cannot_carry_previous_ratio(self):
        later = Saved(self.root/'later',bodyless=True)
        frames,_ = self.projected([self.source,later])
        self.assertIsNotNone(self.admit(frames[0])[0])
        projection,receipt = self.admit(frames[1],source=later,ordinal=2)
        self.assertIsNone(projection);self.assertEqual(receipt['contracts'],0)
        self.assertNotIn('health_ratio_candidate',frames[1]['relations'][0])
        with self.assertRaisesRegex(ValueError,'fresh_health_bundle'):
            self.admit(frames[1],source=later,ordinal=1)

    def test_epoch_rechecks_inputs_and_parent_checks_original_bytes(self):
        original = Path(self.config['health_ratio_native_review']).read_bytes()
        Path(self.config['health_ratio_native_review']).write_bytes(original+b' ')
        with self.assertRaisesRegex(ValueError,'pinned_file_mismatch'):
            self.compose()
        Path(self.config['health_ratio_native_review']).write_bytes(original)
        shutil.rmtree(self.root/'epoch-0001')
        frame = self.projected()[0][0]
        path = self.root/'epoch-0001/health-ratio-health-layout.json'
        path.write_bytes(path.read_bytes()+b' ')
        with self.assertRaisesRegex(ValueError,'pinned_file_mismatch:health_layout'):
            self.admit(frame)

    def test_parent_reconstructs_only_same_profile_controller_subset(self):
        from controller_subset_projection import _filter_layout
        from build_health_contracts import _layout
        from plan_live_roster import encoded
        source = Saved(self.root/'subset',actors=2)
        config = self.config_for(source)
        source.profile['fields'] = [f for f in source.profile['fields']
                                    if f['name'].startswith('controller_0000_')]
        source.extents = source.extents[:1]
        source.persist()
        layout,_,_ = _layout(raw(source.health_layout))
        effective = encoded(_filter_layout(layout,{'controller_0000_body_0000_'}))
        health = runtime.build_present_health_contracts(source.root,effective,
                                                       recipe_path=source.root/'recipe.json')
        epoch=self.root/'epoch-0001';epoch.mkdir()
        runtime.save(epoch/'health-bundle.json',health)
        options=runtime.health_ratio_adapter_options(config,source.root,epoch,health)
        path=epoch/'health-contract.json';runtime.save(path,health['contracts'][0])
        events=native_events([source])
        adapter=LiveSession(lambda se,ac,sg:LiveRelations(source.root,SESSION,1,
            health_contracts=[path],**options))
        frame=[value for row in events if (value:=adapter.consume(raw(row))) is not None][0]
        projection,receipt=roster.health_ratio_source_admission(source.root,epoch,frame,
            input_pins=self.pins(config),raw_candidates=True,allow_controller_subsets=True)
        self.assertEqual(projection,frame['health_ratio_projection']);self.assertEqual(receipt['contracts'],1)
        with self.assertRaisesRegex(ValueError,'exact_controller_prefixes'):
            roster.health_ratio_source_admission(source.root,epoch,frame,
                input_pins=self.pins(config),raw_candidates=True)

    def test_complete_producer_transport_and_parent_admission_across_three_epochs(self):
        """Only the native OS process/clock are replaced by an in-memory pipe."""
        replacement = Saved(self.root/'replacement')
        # Replace the body key/storage and pool allocation while the controller
        # remains unchanged. These are synthetic fixture words, not game offsets.
        for field in replacement.profile['fields']:
            name=field['name'];old=field['address']
            if name.endswith('part51_0000_body_key_candidate_i32'):
                next(g for g in replacement.profile['guards'] if g['address']==old)['bytes_hex']='90000080'
            elif '_body_0000_' in name and field['type']=='i32':
                guard=next(g for g in replacement.profile['guards'] if g['address']==old)
                guard['address']+=0x4000;field['address']+=0x4000
                guard['bytes_hex']='90000080' if name.endswith('manager_key_candidate_i32') else '91000080'
            elif '_pool_' in name:
                field['address']+=0x9000
        for guard in replacement.profile['guards']:
            if 0x8000<=guard['address']<0x8000+72:guard['address']+=0x9000
        replacement.extents=[(base+0x9000,data) for base,data in replacement.extents]
        replacement.persist()
        empty=Saved(self.root/'empty',bodyless=True)
        sources=[self.source,replacement,empty]
        events=native_events(sources);native_raw=b''.join(event_raw(row)for row in events)
        config_path=self.root/'config.json';runtime.save(config_path,self.config)
        worker=type('Worker',(),{})()
        worker.stdout=io.BytesIO(native_raw);worker.returncode=None
        worker.poll=lambda:worker.returncode
        def wait(timeout):
            worker.returncode=0
            return 0
        worker.wait=wait;worker.terminate=lambda:setattr(worker,'returncode',1)
        def spawn(command,**kwargs):
            self.assertEqual(command[0],self.config['native_exe'])
            native=self.root/'out/native';native.mkdir()
            for index,source in enumerate(sources,1):
                shutil.copytree(source.root,native/f'acquisition-{index:04d}')
            return worker
        with patch('runtime_jobs.enroll_current_producer'),patch.object(runtime.sys,'platform','win32'), \
             patch.object(runtime,'qpc',return_value=10000), \
             patch.object(runtime.subprocess,'Popen',side_effect=spawn),patch('sys.stdout',new=io.StringIO()):
            self.assertEqual(runtime.run(config_path),0)
        out=self.root/'out';result=json.loads((out/'result.json').read_bytes())
        self.assertTrue(result['complete']);self.assertEqual(result['frames'],3)
        self.assertEqual((out/'native.jsonl').read_bytes(),native_raw)
        frames=[json.loads(line)for line in(out/'entities.jsonl').read_bytes().splitlines()]
        self.assertEqual(len((out/'compact.jsonl').read_bytes().splitlines()),3)
        rows=[frame['relations'][0]for frame in frames]
        self.assertNotEqual(rows[0]['body_object_key'],rows[1]['body_object_key'])
        self.assertIsNone(rows[2]['body_object_key'])
        self.assertNotIn('health_ratio_candidate',rows[2])
        key=rows[0]['controller_object_key']
        roles={key:dict(full_handle=rows[0]['evidence'][0]['value'],
                        creation_key=rows[0]['evidence'][1]['value'])}
        plan=dict(target=frames[0]['target'],partitions=[dict(ordinal=1,
            controllers=[dict(controller_object_key=key)],recipe_sha256=self.config['recipe_sha256'])])
        child=dict(source_id='p1',ordinal=1,directory=str(out),health_ratio_input_pins=self.pins())
        metadata=roster.NativeMetadata();admissions=[]
        try:
            for index,frame in enumerate(frames,1):
                source,_,pins=roster.source_admission(child,plan,roles,{key:1},metadata,
                    raw(frame),initial=index==1,raw_candidates=True)
                admissions.append(source)
                self.assertEqual(pins['health_ratio_inputs']['contracts'],0 if index==3 else 1)
        finally:
            metadata.close()
        self.assertNotEqual(admissions[0]['health_ratio_projection'],admissions[1]['health_ratio_projection'])
        self.assertNotIn('health_ratio_projection',admissions[2])


if __name__=='__main__':
    unittest.main()
