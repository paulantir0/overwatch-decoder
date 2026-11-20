"""No-adoption diagnostics bind actual candidate bytes to the active epoch."""
import copy,tempfile,unittest
from pathlib import Path
from export_relations import digest,parse
from live_sessions import LiveSession
from test_background_preparation import background_fixture,sequence
from test_live_sessions import consume_all
from test_live_relations import live,next_frame,raw


def fixture(root):
    epochs,base,factory,calls,proof=background_fixture(root)
    profile=(root/'1/profile.json').read_bytes();(root/'2/profile.json').write_bytes(profile)
    manifest=parse((root/'2/manifest.json').read_bytes());manifest['profile_sha256']=digest(profile)
    manifest_bytes=raw(manifest);(root/'2/manifest.json').write_bytes(manifest_bytes)
    events=copy.deepcopy(base[:9]);events[0]['identical_profile_refresh']=True
    entry=events[-1]['acquisition'];entry.update(profile_sha256=digest(profile),manifest_sha256=digest(manifest_bytes))
    events.append(dict(schema='overwatch-decoder.field-live/1',kind='preparation_no_change',session_id=events[0]['session_id'],
        event_sequence=0,emitted_ticks=1285,monotonic_frequency=1000,acquisition=2,origin_segment=1,active_acquisition=1,
        profile_sha256=digest(profile),manifest_sha256=digest(manifest_bytes),preparation_end_sha256=None,
        comparison_start_ticks=1280,comparison_end_ticks=1281,profile_adopted=False))
    # Continue the same actual reader with a fresh guarded frame; no epoch reset.
    frame=next_frame(events[7]['recording_frame'])
    for key in ('start_ticks','end_ticks'):frame[key]+=30
    frame['jitter_ticks']+=30
    for phase in ('guards_before','guards_after'):
        for check in frame[phase]:
            for key in ('start_ticks','end_ticks'):check[key]+=30
    for sample in frame['fields'].values():
        for key in ('read_start_ticks','read_end_ticks'):sample[key]+=30
    continued=live(frame,0);continued['emitted_ticks']=1400;events.append(continued)
    stop=copy.deepcopy(base[9]);stop['emitted_ticks']=1410
    stop['segment'].update(frames=3,last_frame_end_ticks=frame['end_ticks'],end_ticks=1405,trigger='cancelled');events.append(stop)
    events.append(dict(base[-2],emitted_ticks=1420,interval=dict(start_ticks=frame['end_ticks'],end_ticks=1420)))
    events.append(dict(base[-1],emitted_ticks=1430));sequence(events)
    events[9]['preparation_end_sha256']=digest(raw(events[8]))
    (root/'2/activation.json').unlink()  # No activation artifact or new projector is needed.
    return events,factory,calls


class NoChangeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.events,self.factory,self.calls=fixture(self.root)
    def coordinator(self,**kwargs):return LiveSession(self.factory,acquisition_resolver=lambda entry:self.root/str(entry['ordinal']),**kwargs)
    def test_identical_actual_bytes_keep_reader_epoch_contract_and_original_pins(self):
        coordinator=self.coordinator();results=consume_all(coordinator,self.events)
        self.assertEqual(len(self.calls),1);self.assertEqual(coordinator.epochs,1);self.assertEqual(coordinator.attempts,2)
        self.assertEqual([r['relations'][0]['health_candidate']['raw_sum'] for r in results],[100.,100.,100.])
        self.assertTrue(all(r['segment']==1 and r['session_epoch']['acquisition']==1 for r in results))
        self.assertEqual(results[0]['source_artifacts'],results[-1]['source_artifacts'] | {'live_event_sha256':results[0]['source_artifacts']['live_event_sha256']})
        summary=coordinator.close()['preparations_observed'][0]
        self.assertEqual(summary['outcome'],'unchanged');self.assertFalse(summary['profile_adopted']);self.assertTrue(summary['profile_bytes_compared'])
        self.assertEqual(summary['preparation_end_sha256'],digest(raw(self.events[8])))
        self.assertEqual(summary['no_change_event_sha256'],digest(raw(self.events[9])))
        self.assertEqual(results[-1]['session_epoch']['acquisition_end_sha256'],results[0]['session_epoch']['acquisition_end_sha256'])
        results[-1]['session_epoch']['last_unchanged_preparation']['candidate_profile_sha256']='mutated'
        self.assertNotEqual(coordinator.epoch_admission['last_unchanged_preparation']['candidate_profile_sha256'],'mutated')
    def test_actual_bytes_manifest_and_evidence_are_rechecked_not_just_cached_hashes(self):
        for filename in ('profile.json','manifest.json','evidence.jsonl'):
            with self.subTest(filename=filename),tempfile.TemporaryDirectory() as d:
                root=Path(d);events,factory,calls=fixture(root);path=root/'2'/filename;path.write_bytes(path.read_bytes()+b' ')
                coordinator=LiveSession(factory,acquisition_resolver=lambda entry:root/str(entry['ordinal']))
                with self.assertRaises(ValueError):consume_all(coordinator,events)
                self.assertTrue(coordinator.failed);self.assertEqual(coordinator.frames,2);self.assertEqual(len(calls),1)
    def test_pin_current_epoch_origin_hash_and_comparison_time_fail_closed(self):
        for patch in ({'active_acquisition':2},{'origin_segment':2},{'acquisition':3},{'profile_sha256':'00'*32},
                      {'manifest_sha256':'00'*32},{'preparation_end_sha256':'00'*32},{'profile_adopted':True},
                      {'comparison_start_ticks':1240},{'comparison_end_ticks':1500}):
            events=copy.deepcopy(self.events);events[9].update(patch)
            with self.subTest(patch=patch),self.assertRaises(ValueError):consume_all(self.coordinator(),events)
    def test_optin_and_actual_resolver_are_required(self):
        with self.assertRaisesRegex(ValueError,'resolver_required'):consume_all(LiveSession(self.factory),self.events)
        events=copy.deepcopy(self.events);events[0].pop('identical_profile_refresh')
        with self.assertRaisesRegex(ValueError,'unchanged_lifecycle'):consume_all(self.coordinator(),events)
        events=copy.deepcopy(self.events);events[0]['background_preparation']=False
        with self.assertRaisesRegex(ValueError,'resolver_required'):consume_all(self.coordinator(),events)
    def test_wrong_directory_cannot_reuse_active_manifest_as_candidate(self):
        coordinator=LiveSession(self.factory,acquisition_resolver=lambda entry:self.root/'1')
        with self.assertRaisesRegex(ValueError,'unchanged_manifest_hash'):consume_all(coordinator,self.events)
    def test_forged_manifest_scope_fails_even_with_updated_pins(self):
        manifest=parse((self.root/'2/manifest.json').read_bytes());manifest['recipe_sha256']='00'*32;data=raw(manifest)
        (self.root/'2/manifest.json').write_bytes(data)
        self.events[8]['acquisition']['manifest_sha256']=digest(data)
        self.events[9].update(manifest_sha256=digest(data),preparation_end_sha256=digest(raw(self.events[8])))
        with self.assertRaisesRegex(ValueError,'unchanged_manifest_scope'):consume_all(self.coordinator(),self.events)
    def test_active_terminal_or_guard_failure_does_not_get_a_no_change_refresh(self):
        for mode in ('terminal','guard'):
            events=copy.deepcopy(self.events)
            if mode=='terminal':events[7]['terminal_reason']='process_exited'
            else:
                events[7]['recording_frame']['guards_after'][0].update(ok=False,error='read_failed')
                for fields in (events[7]['recording_frame']['fields'],events[7]['fields']):
                    for sample in fields.values():sample.update(status='unknown',value=None,reason='guard_failed')
            with self.subTest(mode=mode),self.assertRaises(ValueError):consume_all(self.coordinator(),events)

if __name__=='__main__':unittest.main()
