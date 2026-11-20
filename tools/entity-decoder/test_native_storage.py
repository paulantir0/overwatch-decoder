"""Storage-only native metadata, with real live projection/epoch validation."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from live_relations import LiveRelations, InvalidLive
from live_sessions import LiveSession
from test_live_relations import SESSION, event, live, next_frame, raw
from test_live_sessions import fixture, consume_all


def policy(count=4):
    return dict(schema='overwatch-decoder.field-storage-options/1', cohort_bytes=65536,
        maximum_cohorts=count, sealed_cohorts=0, recording_schema='overwatch-decoder.field-recording/2',
        semantic_epoch_reset=False)


def seal(profile, ordinal, first, lines, terminal, emitted, previous=None, *, segment=1, global_ordinal=None):
    record = dict(schema='overwatch-decoder.field-storage-cohort/1', ordinal=ordinal,
        directory=f'storage-{ordinal:06d}', profile_sha256=profile,
        previous_record_sha256=previous, first_chunk=ordinal-1, chunks=1,
        first_line=first, lines=lines, compressed_bytes=200, json_bytes=10000,
        index_bytes=400, samples_sha256='a'*64, index_sha256='b'*64,
        terminal_summary_included=terminal)
    e = event('storage_cohort_sealed', 0, segment=segment, acquisition=segment,
        profile_sha256=profile, storage_cohort_ordinal=ordinal if global_ordinal is None else global_ordinal,
        index_record=record, index_record_sha256=hashlib.sha256(raw(record)).hexdigest())
    e['emitted_ticks'] = emitted
    return e


def numbering(events):
    for n, e in enumerate(events): e['event_sequence'] = n
    return events


def one_epoch(root, missed=False):
    epochs, original, factory, calls = fixture(root, 1)
    p, frame, m, _ = epochs[1]
    events = copy.deepcopy(original[:5]); events[0]['storage_rotation'] = policy()
    previous = None; frames = []
    for n in range(4):
        if n: frame = next_frame(frame, missed=1 if missed and n==2 else 0)
        frames.append(copy.deepcopy(frame))
    for n, frame in enumerate(frames):
        e = live(frame); e['emitted_ticks'] = frame['end_ticks'] + 20
        events.append(e)
        # Nonterminal seal is inside the NEXT frame's sink write, after its
        # memory read but before its live callback. Final seal follows summary.
        ticks = frames[n+1]['end_ticks'] + 10 if n<3 else frame['end_ticks']+30
        s = seal(m['profile_sha256'], n+1, n, 2 if n==3 else 1, n==3, ticks, previous)
        previous = s['index_record_sha256']; events.append(s)
    end = copy.deepcopy(original[6]); end['emitted_ticks'] = frame['end_ticks']+40
    end['segment'].update(end_ticks=frame['end_ticks']+35, frames=4, last_frame_end_ticks=frame['end_ticks'])
    events.append(end)
    gap = copy.deepcopy(original[7]); gap.update(emitted_ticks=frame['end_ticks']+50)
    gap['interval'].update(start_ticks=frame['end_ticks'], end_ticks=frame['end_ticks']+50); events.append(gap)
    final = copy.deepcopy(original[8]); final['emitted_ticks'] = frame['end_ticks']+60
    final['result_before_this_write']['storage_rotation'] = dict(policy(), sealed_cohorts=4); events.append(final)
    return epochs, numbering(events), factory, calls


class NativeStorageTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup); self.root=Path(self.temp.name)

    def run_events(self, build=one_epoch, **kwargs):
        epochs, events, factory, calls=build(self.root, **kwargs)
        co=LiveSession(factory); projections=consume_all(co,events)
        return epochs,events,factory,calls,co,projections

    def test_three_rolls_do_not_reconfigure_or_change_gameplay_projection(self):
        epochs,events,factory,calls,co,results=self.run_events()
        self.assertEqual((co.frames,co.epochs,co.attempts,len(calls),co._storage.global_ordinal),(4,1,1,1,4))
        self.assertEqual([p['timing']['sequence']for p in results],[0,1,2,3])
        self.assertTrue(co.ended); self.assertFalse(co.close()['storage_notifications']['durability_verified'])
        direct=LiveRelations(self.root/'1',SESSION,1,health_contracts=epochs[1][3]); projected=[]
        for e in events:
            p=direct.consume(raw(e))
            if p is not None: projected.append(p)
        self.assertEqual(direct._storage.global_ordinal,4)
        for a,b in zip(results,projected):
            a=dict(a);a.pop('session_epoch');self.assertEqual(a,b)
        # Flat replay preserves every gameplay result. Only transport event
        # sequences and provenance hashes differ because source bytes differ.
        flat=[copy.deepcopy(e)for e in events if e['kind']!='storage_cohort_sealed']
        flat[0].pop('storage_rotation');flat[-1]['result_before_this_write'].pop('storage_rotation');numbering(flat)
        flat_results=consume_all(LiveSession(factory),flat)
        for a,b in zip(results,flat_results):
            for key in ('relations','timing','gap_before','recording','continuity_across_gaps'):
                self.assertEqual(a[key],b[key],key)

    def test_real_sampling_gap_is_preserved_across_roll(self):
        _,_,_,_,co,results=self.run_events(missed=True)
        self.assertEqual(results[2]['gap_before']['skipped_slots'],1)
        self.assertIsNone(results[2]['relations'][0]['health_candidate'])
        self.assertIsNotNone(results[3]['relations'][0]['health_candidate'])
        self.assertEqual(co.frames,4)

    def test_global_seal_count_crosses_real_body_epoch_without_aliasing_state(self):
        epochs,events,factory,calls=fixture(self.root,2);events[0]['storage_rotation']=policy(2);out=[]
        for e in events:
            if e['kind']=='segment_end':
                n=e['segment']['ordinal'];out.append(seal(e['segment']['profile_sha256'],1,0,2,True,e['emitted_ticks']-1,segment=n,global_ordinal=n))
            if e['kind']=='session_end':e['result_before_this_write']['storage_rotation']=dict(policy(2),sealed_cohorts=2)
            out.append(e)
        co=LiveSession(factory);results=consume_all(co,numbering(out))
        self.assertEqual((co.epochs,co._storage.global_ordinal,len(calls)),(2,2,2))
        self.assertNotEqual(results[0]['relations'][0]['body_object_key'],results[1]['relations'][0]['body_object_key'])
        self.assertFalse(results[1]['session_epoch']['previous_values_carried'])

    def test_direct_sparse_later_epoch_cannot_invent_global_seal_prefix(self):
        epochs,events,_,_=fixture(self.root,2);events[0]['storage_rotation']=policy(2)
        a=LiveRelations(self.root/'2',SESSION,2,health_contracts=epochs[2][3])
        a.begin_epoch(raw(events[0]),raw(events[8]),raw(events[9]))
        a.consume(raw(events[10]))
        a.consume(raw(events[11]))
        s=seal(epochs[2][2]['profile_sha256'],1,0,2,True,2201,segment=2,global_ordinal=2);s['event_sequence']=12
        with self.assertRaisesRegex(InvalidLive,'storage_active_prefix_required'):a.consume(raw(s))

    def test_seal_before_any_frame_can_only_be_terminal_summary(self):
        _,events,factory,_=one_epoch(self.root);events=events[:4]
        s=seal(events[3]['profile_sha256'],1,0,1,True,920);events.append(s)
        e=event('segment_end',0,terminal_summary_written=True,failure=None,segment=dict(ordinal=1,acquisition=1,profile_sha256=events[3]['profile_sha256'],start_ticks=900,end_ticks=930,frames=0,first_frame_start_ticks=None,last_frame_end_ticks=None,trigger='cancelled'));e['emitted_ticks']=940;events.append(e)
        co=LiveSession(factory);self.assertEqual(consume_all(co,numbering(events)),[]);self.assertEqual(co.frames,0)

    def test_missing_final_seal_rejected_but_explicit_write_failure_preserves_prefix(self):
        _,events,factory,_=one_epoch(self.root);events=[e for e in events if not(e['kind']=='storage_cohort_sealed'and e['index_record']['terminal_summary_included'])];numbering(events)
        with self.assertRaisesRegex(InvalidLive,'storage_missing_terminal_seal'):consume_all(LiveSession(factory),events)
        end=next(e for e in events if e['kind']=='segment_end');end['terminal_summary_written']=False;end['failure']='output_io_error'
        events[-1]['result_before_this_write']['storage_rotation']['sealed_cohorts']=3
        co=LiveSession(factory);self.assertEqual(len(consume_all(co,events)),4);self.assertTrue(co.ended)
        self.assertFalse(co.close()['durability_verified'])

    def test_raw_catalog_hash_includes_exact_embedded_bytes_and_lf(self):
        _,events,factory,_=one_epoch(self.root);co=LiveSession(factory)
        for e in events:
            data=raw(e)
            if e['kind']=='storage_cohort_sealed':
                data=data.replace(b'"index_record":{',b'"index_record":{ ')
                with self.assertRaisesRegex(InvalidLive,'storage_record_raw_hash'):co.consume(data)
                return
            co.consume(data)
        self.fail('fixture lacks seal')

    def test_malformed_policy_and_seal_fail_closed(self):
        _,original,factory,_=one_epoch(self.root)
        mutations={
            'not_opted_in':lambda es:es[0].pop('storage_rotation'),
            'null_policy':lambda es:es[0].__setitem__('storage_rotation',None),
            'bool_cap':lambda es:es[0]['storage_rotation'].__setitem__('maximum_cohorts',True),
            'reset':lambda es:es[0]['storage_rotation'].__setitem__('semantic_epoch_reset',True),
            'oversize_cap':lambda es:es[0]['storage_rotation'].__setitem__('cohort_bytes',2**31),
        }
        for key,value in [('segment',2),('acquisition',2),('profile_sha256','c'*64),('storage_cohort_ordinal',2),('index_record_sha256','d'*64)]:
            mutations[key]=lambda es,k=key,v=value:es[6].__setitem__(k,v)
        for key,value in [('directory','../storage-000001'),('ordinal',True),('first_chunk',1),('first_line',1),('lines',2),('chunks',0),('compressed_bytes',65537),('json_bytes',2**40),('index_bytes',2**30),('profile_sha256','e'*64),('previous_record_sha256','f'*64),('terminal_summary_included',1),('samples_sha256','no')]:
            def mutate(es,k=key,v=value):
                es[6]['index_record'][k]=v;es[6]['index_record_sha256']=hashlib.sha256(raw(es[6]['index_record'])).hexdigest()
            mutations['record_'+key]=mutate
        for name,mutate in mutations.items():
            with self.subTest(name=name):
                es=copy.deepcopy(original);mutate(es);co=LiveSession(factory)
                with self.assertRaises(InvalidLive):consume_all(co,es)
                self.assertTrue(co.failed);self.assertIsNone(co.adapter)
                with self.assertRaisesRegex(InvalidLive,'session_coordinator_closed'):co.consume(raw(es[0]))

    def test_terminal_seal_cannot_precede_another_frame_or_metadata(self):
        _,events,factory,_=one_epoch(self.root)
        terminal=next(i for i,e in enumerate(events)if e['kind']=='storage_cohort_sealed'and e['index_record']['terminal_summary_included'])
        for kind in ('frame','preparation_start','storage_cohort_sealed'):
            es=copy.deepcopy(events);extra=copy.deepcopy(es[5]if kind=='frame'else es[6]);extra['kind']=kind;extra['emitted_ticks']=es[terminal]['emitted_ticks'];es.insert(terminal+1,extra);numbering(es)
            with self.subTest(kind=kind),self.assertRaisesRegex(InvalidLive,'storage_event_after_terminal_seal'):consume_all(LiveSession(factory),es)

    def test_direct_adapter_rejects_bad_clock_and_does_not_resume(self):
        epochs,events,_,_=one_epoch(self.root)
        direct=LiveRelations(self.root/'1',SESSION,1,health_contracts=epochs[1][3])
        for e in events[:6]:direct.consume(raw(e))
        malformed=copy.deepcopy(events[6]);malformed['monotonic_frequency']=2000
        with self.assertRaisesRegex(InvalidLive,'storage_active_pins'):direct.consume(raw(malformed))
        self.assertTrue(direct.failed)
        with self.assertRaisesRegex(InvalidLive,'live_adapter_failed'):direct.consume(raw(events[7]))

    def test_native_rotation_cannot_precede_the_pending_frames_memory_read(self):
        _,events,factory,_=one_epoch(self.root)
        events[6]['emitted_ticks']=events[5]['emitted_ticks']+1
        with self.assertRaisesRegex(InvalidLive,'storage_rotation_before_frame_read'):consume_all(LiveSession(factory),events)

    def test_cohort_cap_terminal_snapshot_and_eof_are_not_completion(self):
        _,events,factory,_=one_epoch(self.root)
        capped=copy.deepcopy(events);capped[0]['storage_rotation']['maximum_cohorts']=1
        with self.assertRaisesRegex(InvalidLive,'storage_nonterminal_at_cohort_limit'):consume_all(LiveSession(factory),capped)
        mismatch=copy.deepcopy(events);mismatch[-1]['result_before_this_write']['storage_rotation']['sealed_cohorts']=3
        with self.assertRaisesRegex(InvalidLive,'storage_terminal_policy'):consume_all(LiveSession(factory),mismatch)
        prefix=LiveSession(factory);consume_all(prefix,events[:7]);receipt=prefix.close()
        self.assertFalse(receipt['native_session_end_seen']);self.assertFalse(receipt['durability_verified'])
        self.assertEqual(receipt['storage_notifications']['sealed_cohorts'],1)
        # Metadata events consume the unchanged total event budget too.
        with self.assertRaisesRegex(InvalidLive,'session_input_bound'):consume_all(LiveSession(factory,maximum_events=6),events)

    def test_storage_notification_does_not_advance_watermark_or_admission(self):
        _,events,factory,_=one_epoch(self.root);co=LiveSession(factory)
        for e in events:
            if e['kind']=='storage_cohort_sealed':
                before=(co.last_frame_end,co.segment_frames,copy.deepcopy(co.epoch_admission),co.adapter.frame_sequence,co.adapter.last_end,co.adapter.anchor)
                self.assertIsNone(co.consume(raw(e)))
                self.assertEqual(before,(co.last_frame_end,co.segment_frames,co.epoch_admission,co.adapter.frame_sequence,co.adapter.last_end,co.adapter.anchor))
                self.assertEqual(co.adapter.event_sequence,co.event_sequence)
                self.assertEqual(co.adapter._storage.global_ordinal,co._storage.global_ordinal)
                self.assertIsNot(co.adapter._storage,co._storage)
            else:co.consume(raw(e))


if __name__=='__main__':unittest.main()
