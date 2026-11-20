"""Slow final admission never turns validated old observations into live values."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aggregate_partitions import canonical
from live_roster_epochs import LiveRosterEpochs
from compact_live_roster import CompactLiveRoster,encode
from runtime_startup import StartupSources
from test_live_roster_epochs import fixture,next_frame,unknown
from test_aggregate_partitions import raw


class StartupTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.config,self.frames=fixture(Path(self.tmp.name))
        for frames in self.frames.values():
            for frame in frames:
                for row in frame['relations']:
                    row['position_candidate']['validation_status']='guarded_research'
                    row['health_candidate'].update(status='candidate',display_ceiling_candidate=int(row['health_candidate']['raw_sum']))
                    row['hero_resource_guid_candidate'].update(validation_status='matching_guarded_resource_research',public_state_eligible=False)
                    row['hero_label_evidence'].update(validation_status='guarded_build_resource_label_research',catalog_sha256='ab'*32)
                    row['cached_label_evidence']['validation_status']='guarded_native_cache_string_research'
        self.warm=StartupSources(self.config['target'],1000,raw_candidates=False)

    def populated(self):
        self.warm.add(self.config['sources'][0]);latest={}
        # p1 can be validated while the final source is still being admitted.
        f=self.frames['p1'][0];data=[]
        for i in range(6):
            line=raw(f);self.warm.consume('p1',line);data.append(line);latest['p1']=f;f=next_frame(f,f['timing']['end_ticks']+10)
        self.assertEqual(self.warm.hashes['p1'].hexdigest(),hashlib.sha256(b''.join(data)).hexdigest())
        self.warm.add(self.config['sources'][1]);f=self.frames['p2'][0]
        # A finite recorded burst is validated in full, not a latest-only read.
        for i in range(6):
            self.warm.consume('p2',raw(f));latest['p2']=f;f=next_frame(f,f['timing']['end_ticks']+10)
        return latest

    def test_slow_final_source_adopts_only_cursors_and_publishes_fresh_grid(self):
        latest=self.populated();self.assertEqual(self.warm.events,12)
        self.assertTrue(all(not v.pending for v in self.warm.validators.values()))
        co=LiveRosterEpochs(raw(self.config));events=co._adopt_startup(self.warm,1090)
        self.assertEqual(len(events),1);startup=events[0];self.assertEqual(startup['resume_boundary_ticks'],1100)
        self.assertEqual(startup['startup_validation']['validated_frames'],12)
        compact=CompactLiveRoster();c=compact.consume(canonical(startup)+b'\n')
        self.assertTrue(all(r['body_object_key']is None and r['position_candidate']['value']is None for r in c['players']))
        produced=[]
        for end in (1120,1160):
            for sid in latest:
                f=next_frame(latest[sid],end);
                for row in f['relations']:row['position_candidate']['value'][0]=123
                produced+=co.consume(sid,raw(f));latest[sid]=f
        self.assertEqual(produced[0]['window_start_ticks'],1100)
        self.assertTrue(all(r['authoritative_observation']['relation']['position_candidate']['value'][0]==123 for r in produced[0]['relations']))
        c=compact.consume(canonical(produced[0])+b'\n');self.assertTrue(all(r['position_candidate']['value']is not None for r in c['players']))
        self.assertEqual(co.events,16)
        # Prefix observations remain fully accounted but are not live windows.
        self.assertEqual(startup['end_ticks']-startup['start_ticks'],100)
        self.assertEqual(self.warm.summary()['maximum_retained_source_lines'],2)

    def test_startup_unknown_guard_and_new_epoch_fail_closed_with_exact_saved_prefix(self):
        for case in ('guard','epoch','body','read'):
            with self.subTest(case=case):
                w=StartupSources(self.config['target'],1000,raw_candidates=False);w.add(self.config['sources'][0])
                first=self.frames['p1'][0];w.consume('p1',raw(first));f=next_frame(first,1060)
                if case=='guard':f=unknown(f)
                elif case=='epoch':f['segment']=2
                elif case=='body':f['relations'][0]['health_candidate']['body_object_key']='body:'+'ff'*32
                else:f['relations'][0]['position_candidate']['read_end_ticks']=99999
                with self.assertRaises(ValueError):w.consume('p1',raw(f))
                self.assertTrue(w.failed)
                with self.assertRaises(ValueError):w.consume('p1',raw(f))

    def test_bounds_freshness_and_admission_mismatch(self):
        latest=self.populated();self.assertFalse(self.warm.current([v['source_id']for v in self.config['sources']],10000))
        with self.assertRaises(ValueError):LiveRosterEpochs(raw(self.config))._adopt_startup(self.warm,10000)
        altered=copy.deepcopy(self.config);altered['sources'][0]['profile_sha256']='ff'*32
        with self.assertRaises(ValueError):LiveRosterEpochs(raw(altered))._adopt_startup(self.warm,1090)
        with patch('runtime_startup.MAX_EVENTS',12):
            with self.assertRaises(ValueError):self.warm.consume('p1',raw(next_frame(latest['p1'],1100)))

    def test_parent_startup_prefix_accounting_and_eof_never_replays_old_rows(self):
        import json
        import runtime_roster as runtime
        class Clock:
            frequency=1000
            def tick(self):return 1150
            def utc_ns(self):return 10000000000
        root=Path(self.tmp.name);out=root/'out';out.mkdir();sources={s['source_id']:s for s in self.config['sources']};children=[]
        for ordinal,(sid,frames)in enumerate(self.frames.items(),1):
            path=root/sid;path.mkdir();data=b''.join(raw(v)for v in frames)
            (path/'entities.jsonl').write_bytes(data);(path/'native.jsonl').write_bytes(b'')
            runtime.save(path/'result.json',dict(complete=True,native_exit=0,error=None,frames=len(frames),entities_sha256=hashlib.sha256(data).hexdigest(),
                decoder=dict(native_session_end_seen=True,phase='ended',frames=len(frames)),epochs=[dict(segment=1,profile_sha256=sources[sid]['profile_sha256'])]))
            children.append(dict(source_id=sid,ordinal=ordinal,directory=str(path)))
        primary={r['controller_object_key']:int(r['primary_source_id'][1:])for r in self.config['roster']};roles={k:{}for k in primary}
        def admit(child,*args,**kwargs):return sources[child['source_id']],self.frames[child['source_id']][0],{}
        plan=dict(target=self.config['target'],partitions=[{},{}])
        with patch.object(runtime,'reviewed_inputs',return_value=(roles,primary)),patch.object(runtime,'source_admission',side_effect=admit):
            # All fixture producers already ended: this must not fabricate an
            # active-native proof merely because their saved rows validate.
            with self.assertRaisesRegex(ValueError,'active_native_proof'):
                runtime.aggregate_existing(root,plan,{},children,out,Clock(),live=True,raw_candidates=True,total_timeout=10)
        summary=json.loads((out/'aggregate-result.json').read_bytes())
        self.assertEqual(summary['startup_validated_frames'],4);self.assertEqual(summary['input_events'],0)
        self.assertEqual(summary['total_validated_input_frames'],4);self.assertEqual(summary['windows'],0)
        self.assertEqual(summary['transition_records'],2)
        events=[json.loads(v)for v in (out/'compact-roster.jsonl').read_bytes().splitlines()]
        self.assertEqual(events[0]['schema'],'overwatch-decoder.compact-live-roster-startup/1')
        self.assertTrue(all(r['position_candidate']['value']is None for e in events for r in e['players']))
        self.assertEqual(len((out/'startup-input-order.jsonl').read_bytes().splitlines()),4)

    def test_startup_candidate_and_wrong_resume_rejected(self):
        self.populated();co=LiveRosterEpochs(raw(self.config));event=co._adopt_startup(self.warm,1090)[0]
        for case in ('body','frame_count','hash','span'):
            with self.subTest(case=case):
                bad=copy.deepcopy(event)
                if case=='body':bad['relations'][0]['body_object_key']='body:'+'ff'*32
                elif case=='frame_count':bad['startup_validation']['validated_frames']+=1
                elif case=='hash':bad['startup_validation']['sources']['p1']['source_prefix_sha256']='bad'
                else:bad['end_ticks']-=1
                with self.assertRaises(ValueError):CompactLiveRoster().consume(canonical(bad)+b'\n')

if __name__=='__main__':unittest.main()
