"""Native-order multi-epoch admission with synthetic source-bound acquisitions."""
import copy
import io
from pathlib import Path
import tempfile
import unittest

from live_relations import LiveRelations, InvalidLive
from live_sessions import LiveSession, stream
from test_live_continuity import epoch
from test_live_relations import SESSION, event, live, raw, start


def fixture(root, count=2):
    epochs = {}
    for n in range(1, count+1):
        epochs[n] = epoch(root / str(n), n, replacement_body=n > 1)
    profile, _, manifest, _ = epochs[1]
    events = []
    def add(kind, emitted, **kwargs):
        e = event(kind, len(events), **kwargs); e['emitted_ticks'] = emitted
        events.append(e); return e
    add('session_start', 100, target=profile['target'], recipe_sha256=manifest['recipe_sha256'],
        source_kind='native_process_memory', recording_frame_included=True,
        atomic=False, public_state_eligible=False, monotonic_origin_ticks=0)
    previous = 0
    for n, (p, f, m, _) in epochs.items():
        acq_start = n*1000-800
        add('acquisition_start', acq_start+10, acquisition=n, start_ticks=acq_start,
            observation_gap_open=True, gap_start_ticks=previous)
        from hashlib import sha256
        entry = dict(ordinal=n, directory=f'acquisition-{n:04d}', start_ticks=acq_start,
            end_ticks=n*1000-200, complete=True, error=None,
            profile_sha256=m['profile_sha256'], manifest_sha256=sha256((root/str(n)/'manifest.json').read_bytes()).hexdigest())
        add('acquisition_end', n*1000-190, acquisition=entry)
        seg = start(p, m);seg.update(event_sequence=len(events), segment=n, acquisition=n,
                                    start_ticks=n*1000-100, emitted_ticks=n*1000-90)
        events.append(seg)
        add('gap', f['end_ticks']+10, interval=dict(start_ticks=previous, end_ticks=f['start_ticks'], meaning='synthetic gap'))
        frame = live(f, len(events)); frame.update(segment=n, emitted_ticks=f['end_ticks']+20)
        events.append(frame)
        add('segment_end', f['end_ticks']+30, terminal_summary_written=True, failure=None,
            recording_state='closed_manifest_available_not_independently_verified', segment=dict(
                ordinal=n, acquisition=n, profile_sha256=m['profile_sha256'], start_ticks=n*1000-100,
                end_ticks=f['end_ticks']+25, frames=1, first_frame_start_ticks=f['start_ticks'],
                last_frame_end_ticks=f['end_ticks'], trigger='guard_invalidation'if n<count else'cancelled'))
        previous = f['end_ticks']
    add('gap', previous+40, interval=dict(start_ticks=previous, end_ticks=previous+40, meaning='synthetic terminal gap'))
    add('session_end', previous+50, result_before_this_write=dict(schema='overwatch-decoder.field-observation/1',
        session_id=SESSION, status='finished', complete=True, target=profile['target'],
        recipe_sha256=manifest['recipe_sha256'], public_state_eligible=False, atomic=False))
    calls = []
    def factory(session, acquisition, segment):
        calls.append((session, acquisition, segment))
        n = acquisition['ordinal']
        return LiveRelations(root/str(n), SESSION, segment['segment'], health_contracts=epochs[n][3])
    return epochs, events, factory, calls


def consume_all(coordinator, events):
    return [result for e in events if (result := coordinator.consume(raw(e))) is not None]


class LiveSessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.epochs, self.events, self.factory, self.calls = fixture(self.root)

    def test_two_epochs_preserve_native_sequences_and_rebind_body_with_fresh_health(self):
        co = LiveSession(self.factory); results = consume_all(co, self.events)
        self.assertEqual([v['event_sequence'] for v in results], [5,11])
        self.assertEqual([v['segment'] for v in results], [1,2])
        first, second = [v['relations'][0] for v in results]
        self.assertEqual(first['controller_object_key'], second['controller_object_key'])
        self.assertNotEqual(first['body_object_key'], second['body_object_key'])
        self.assertEqual([r['health_candidate']['raw_sum'] for r in (first,second)], [100.,50.])
        self.assertEqual(second['health_candidate']['body_object_key'], second['body_object_key'])
        self.assertEqual(results[1]['session_epoch']['previous_epoch_last_frame_end_ticks'],1100)
        self.assertFalse(results[1]['session_epoch']['previous_values_carried'])
        self.assertFalse(results[1]['continuity_across_gaps'])
        self.assertEqual(len(self.calls),2); self.assertTrue(co.close()['native_session_end_seen'])
        self.assertFalse(co.close()['durability_verified'])

    def test_periodic_reacquisition_accepts_fresh_epoch_without_carry(self):
        events = copy.deepcopy(self.events)
        events[6]['segment']['trigger'] = 'periodic_reacquisition'
        coordinator = LiveSession(self.factory)
        results = consume_all(coordinator, events)
        self.assertEqual(len(results), 2)
        self.assertNotEqual(results[0]['relations'][0]['body_object_key'], results[1]['relations'][0]['body_object_key'])
        self.assertFalse(results[1]['session_epoch']['previous_values_carried'])
        self.assertTrue(coordinator.ended)

    def test_unrecognized_rotation_trigger_cannot_reacquire(self):
        events = copy.deepcopy(self.events)
        events[6]['segment']['trigger'] = 'unrecognized_rotation'
        coordinator = LiveSession(self.factory)
        with self.assertRaisesRegex(ValueError, 'session_acquisition_lifecycle'):
            consume_all(coordinator, events)
        self.assertTrue(coordinator.failed)

    def test_factory_receives_detached_original_metadata(self):
        def factory(session, acquisition, segment):
            adapter=self.factory(session, acquisition, segment)
            session['target']['pid']=999; acquisition['profile_sha256']='wrong'; segment['fields']=[]
            return adapter
        self.assertEqual(len(consume_all(LiveSession(factory),self.events)),2)
        self.assertEqual(self.events[0]['target']['pid'],123)

    def test_failed_acquisition_emits_nothing_then_fresh_success_uses_original_ordinal(self):
        events=copy.deepcopy(self.events[:7]); p,_,m,c=self.epochs[1]
        failed=[event('acquisition_start',1,acquisition=1,start_ticks=120,observation_gap_open=True,gap_start_ticks=0),
            event('acquisition_end',2,acquisition=dict(ordinal=1,directory='acquisition-0001',start_ticks=120,end_ticks=140,
                complete=False,error='acquisition_predicate_failed',manifest_sha256=None,profile_sha256=None))]
        failed[0]['emitted_ticks']=130;failed[1]['emitted_ticks']=150
        for e in events[1:]:
            e['event_sequence']+=2
            if e['kind']=='acquisition_start':e['acquisition']=2
            if e['kind']=='acquisition_end':e['acquisition'].update(ordinal=2,directory='acquisition-0002')
            if e['kind']=='segment_start':e['acquisition']=2
            if e['kind']=='segment_end':e['segment']['acquisition']=2
        factory=lambda session,acq,seg:LiveRelations(self.root/'1',SESSION,1,health_contracts=c)
        co=LiveSession(factory); results=consume_all(co,[events[0],*failed,*events[1:]])
        self.assertEqual(len(results),1);self.assertEqual(results[0]['event_sequence'],7)
        self.assertEqual(results[0]['session_epoch']['acquisition'],2)
        self.assertEqual(co.close()['failed_acquisitions'],1)

    def test_gap_and_missing_acquisition_cannot_project_old_frames(self):
        for index in (1,2,3,6,7,8):
            with self.subTest(index=index):
                co=LiveSession(self.factory)
                consume_all(co,self.events[:index])
                e=copy.deepcopy(self.events[5]);e['event_sequence']=index
                e['emitted_ticks']=max(e['emitted_ticks'],self.events[index-1]['emitted_ticks'])
                with self.assertRaises(ValueError):co.consume(raw(e))
                self.assertTrue(co.failed)

    def test_wrong_global_order_session_frequency_and_pins_fail_and_latch(self):
        for case in ('sequence','time','frequency','session','acquisition','profile','declarations','gap'):
            with self.subTest(case=case):
                events=copy.deepcopy(self.events)
                if case=='sequence':events[1]['event_sequence']+=1
                elif case=='time':events[1]['emitted_ticks']=0
                elif case=='frequency':events[1]['monotonic_frequency']+=1
                elif case=='session':events[1]['session_id']='b'*32
                elif case=='acquisition':events[3]['acquisition']=99
                elif case=='profile':events[3]['profile_sha256']='ff'*32
                elif case=='declarations':events[3]['fields']=[]
                else:events[4]['interval']['end_ticks']-=1
                co=LiveSession(self.factory)
                with self.assertRaises(ValueError):consume_all(co,events)
                with self.assertRaisesRegex(InvalidLive,'closed'):co.consume(raw(self.events[0]))

    def test_stale_factory_decoder_and_health_contract_are_rejected(self):
        first=None
        def reused(session,acq,segment):
            nonlocal first
            if first is None:first=self.factory(session,acq,segment)
            return first
        with self.assertRaises(ValueError):consume_all(LiveSession(reused),self.events)
        def stale(session,acq,segment):
            return LiveRelations(self.root/str(acq['ordinal']),SESSION,segment['segment'],health_contracts=self.epochs[1][3])
        co=LiveSession(stale)
        with self.assertRaisesRegex(ValueError,'health_acquisition'):consume_all(co,self.events)
        self.assertTrue(co.failed)

    def test_prior_live_category_contract_cannot_authorize_new_epoch(self):
        from test_live_relations import category_setup
        old = self.root / 'category-old'; old.mkdir()
        *_, kwargs = category_setup(old)
        def factory(session, acquisition, segment):
            if segment['segment'] == 1:
                return self.factory(session, acquisition, segment)
            return LiveRelations(old, SESSION, 2, **kwargs)
        co = LiveSession(factory)
        with self.assertRaisesRegex(ValueError, 'configured_epoch_mismatch'):
            consume_all(co, self.events)
        self.assertTrue(co.failed)
        self.assertEqual(co.frames, 1)

    def test_segment_end_must_match_accepted_epoch_and_counts(self):
        for patch in ({'frames':2},{'acquisition':9},{'profile_sha256':'ff'*32},{'last_frame_end_ticks':999}):
            events=copy.deepcopy(self.events);events[6]['segment'].update(patch)
            with self.subTest(patch=patch),self.assertRaises(ValueError):consume_all(LiveSession(self.factory),events)

    def test_terminal_unknown_frame_is_preserved_without_reviving_old_values(self):
        events=copy.deepcopy(self.events)
        f=events[5]
        f['recording_frame']['guards_before'][0].update(ok=False,error='guard_mismatch')
        for container in (f['fields'],f['recording_frame']['fields']):
            for sample in container.values():sample.update(status='unknown',value=None,reason='guard_mismatch_before',read_start_ticks=None,read_end_ticks=None)
        results=consume_all(LiveSession(self.factory),events)
        first,second=[v['relations'][0]for v in results]
        self.assertIsNone(first['controller_object_key']);self.assertIsNone(first['health_candidate'])
        self.assertIsNotNone(second['controller_object_key']);self.assertEqual(second['health_candidate']['raw_sum'],50.)

    def test_terminal_order_finalization_failure_and_truncated_prefix_are_explicit(self):
        co=LiveSession(self.factory);consume_all(co,self.events)
        e=event('session_finalization_error',len(self.events));e['emitted_ticks']=self.events[-1]['emitted_ticks']+1
        with self.assertRaisesRegex(ValueError,'finalization_error'):co.consume(raw(e))
        self.assertTrue(co.failed)
        for index in (0,3,5):
            prefix=LiveSession(self.factory);consume_all(prefix,self.events[:index])
            self.assertFalse(prefix.close()['native_session_end_seen'])
        co=LiveSession(self.factory);consume_all(co,self.events)
        e=copy.deepcopy(self.events[5]);e['event_sequence']=len(self.events);e['emitted_ticks']=self.events[-1]['emitted_ticks']+1
        with self.assertRaisesRegex(ValueError,'after_end'):co.consume(raw(e))

    def test_input_output_epoch_and_event_limits_include_nonframe_events(self):
        for kwargs in (dict(maximum_bytes=1),dict(maximum_events=1),dict(maximum_output_bytes=1),dict(maximum_epochs=1)):
            co=LiveSession(self.factory,**kwargs)
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):consume_all(co,self.events)
            self.assertTrue(co.failed)
        co=LiveSession(self.factory)
        with self.assertRaises(ValueError):co.consume(b'x'*(512*1024+1))
        self.assertTrue(co.failed)

    def test_stream_emits_only_original_frame_sequences_and_does_not_certify_eof(self):
        output=io.BytesIO();co=LiveSession(self.factory)
        summary=stream(co,io.BytesIO(b''.join(raw(e)for e in self.events[:6])),output)
        self.assertEqual(summary['frames'],1);self.assertFalse(summary['native_session_end_seen'])
        self.assertIn(b'"event_sequence":5',output.getvalue())
        self.assertFalse(summary['durability_verified'])


if __name__=='__main__':unittest.main()
