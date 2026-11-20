import copy,unittest
from event_ring import EventRingProjector,InvalidRingSnapshot

def snapshot(seq=0,*,capacity=4,indices=None,head=3,count=4,values=None):
    indices=list(range(capacity)) if indices is None else indices;values=values or {}
    source=dict(target=dict(pid=12,creation_file_time=34,executable_sha256='a'*64),controller=dict(handle_u32=5,creation_key_u32=6),epoch='session:1',build_sha256='a'*64,profile_sha256='b'*64)
    slots=[]
    for i in indices:
        key,tick,amount,flags=values.get(i,(i,10,0,0))
        slots.append(dict(index=i,key_u32=key,tick_u32=tick,amount_i32=amount,flags_u8=flags,read_start_ticks=seq*100+i,read_end_ticks=seq*100+i+1,evidence_sha256='c'*64))
    return dict(schema='overwatch-decoder.event-ring-snapshot/1',source=source,sequence=seq,frame_sha256=f'{seq:064x}',start_ticks=seq*100,end_ticks=seq*100+90,monotonic_frequency=1000,
                guards_valid=True,metadata_before=dict(head=head,count=count),metadata_after=dict(head=head,count=count),slots=slots)

class Tests(unittest.TestCase):
    def test_baseline_confirmation_replay_and_distinct_equal_slots(self):
        p=EventRingProjector(capacity=4);self.assertEqual(p.consume(snapshot())['status'],'baseline')
        values={0:(50,20,7,1),1:(50,20,7,1)}
        a=snapshot(1,head=1,values=values);self.assertEqual(p.consume(a)['records'],[])
        self.assertEqual(p.consume(a)['reason'],'duplicate_frame')
        result=p.consume(snapshot(2,head=1,values=values));self.assertEqual(len(result['records']),2)
        self.assertEqual({r['slot_index'] for r in result['records']},{0,1});self.assertEqual(len({r['record_id'] for r in result['records']}),2)
        self.assertTrue(all(not r['complete_event_count'] and r['producer_write_count'] is None for r in result['records']))
        self.assertEqual(result['records'][0]['first_observation']['sequence'],1)
        self.assertEqual(result['records'][0]['confirmation']['sequence'],2)
        self.assertEqual(p.consume(snapshot(3,head=1,values=values))['records'],[])
    def test_invalid_metadata_breaks_confirmation_retains_changed_version_after_gap(self):
        p=EventRingProjector(capacity=4);p.consume(snapshot());values={0:(9,99,3,255)}
        bad=snapshot(1,head=0,values=values);bad['metadata_after']['head']=1
        self.assertEqual(p.consume(bad)['status'],'unknown')
        self.assertEqual(p.consume(snapshot(2,head=0,values=values))['records'],[])
        result=p.consume(snapshot(3,head=0,values=values));self.assertEqual(len(result['records']),1)
        self.assertEqual(result['records'][0]['change'],'observed_slot_version_changed_after_gap')
    def test_guard_failure_one_frame_transient_and_missing_sequence(self):
        p=EventRingProjector(capacity=4);p.consume(snapshot());values={0:(1,20,8,0)}
        p.consume(snapshot(1,head=0,values=values));bad=snapshot(2,head=0,values=values);bad['guards_valid']=False
        self.assertEqual(p.consume(bad)['reason'],'guards_unknown')
        self.assertEqual(p.consume(snapshot(3,head=0,values=values))['records'],[])
        self.assertEqual(p.consume(snapshot(5,head=0,values=values))['records'],[])
        self.assertIn('after_gap',p.consume(snapshot(6,head=0,values=values))['records'][0]['change'])
        p.consume(snapshot(7,head=1,values={0:(1,20,8,0),1:(2,30,9,0)}))
        self.assertEqual(p.consume(snapshot(8,head=1,values=values))['records'],[])
    def test_source_epoch_controller_build_and_profile_resets_never_replay(self):
        for field in ('epoch','controller','build_sha256','profile_sha256','target'):
            with self.subTest(field=field):
                p=EventRingProjector(capacity=4);p.consume(snapshot());s=snapshot(0,values={0:(99,100,22,1)})
                if field=='controller':s['source'][field]['creation_key_u32']+=1
                elif field=='target':s['source'][field]['creation_file_time']+=1
                elif field=='build_sha256':s['source'][field]='d'*64;s['source']['target']['executable_sha256']='d'*64
                elif field=='epoch':s['source'][field]='next'
                else:s['source'][field]='d'*64
                result=p.consume(s);self.assertEqual(result['status'],'baseline');self.assertEqual(result['records'],[])
    def test_wrap_overrun_and_count_regression_do_not_invent_counts(self):
        p=EventRingProjector(capacity=4);p.consume(snapshot(head=0));values={2:(77,88,9,0)}
        result=p.consume(snapshot(1,head=0,values=values));self.assertIn('possible_wrap_or_overrun',result['gap_reasons'])
        result=p.consume(snapshot(2,head=0,values=values));self.assertEqual(len(result['records']),1);self.assertFalse(result['complete_event_count'])
        result=p.consume(snapshot(3,head=0,count=1,values=values));self.assertEqual(result['status'],'baseline');self.assertIn('count_regressed',result['gap_reasons'])
        result=p.consume(snapshot(4,head=2,count=1,values=values));self.assertIn('cursor_count_inconsistent',result['gap_reasons'])
    def test_partial_views_are_independent_and_own_only_their_indices(self):
        a,b=EventRingProjector(capacity=4,owned_indices=[0,1]),EventRingProjector(capacity=4,owned_indices=[2,3])
        for p,indices in ((a,[0,1]),(b,[2,3])):
            p.consume(snapshot(indices=indices));p.consume(snapshot(1,indices=indices,head=2,values={1:(9,9,9,9),2:(9,9,9,9)}))
            result=p.consume(snapshot(2,indices=indices,head=2,values={1:(9,9,9,9),2:(9,9,9,9)}))
            self.assertEqual(len(result['records']),1);self.assertIn(result['records'][0]['slot_index'],indices);self.assertFalse(result['atomic'])
    def test_malformed_inputs_clock_and_duplicate_mutation_fail_closed(self):
        mutations=[lambda s:s['metadata_before'].update(count=5),lambda s:s['slots'][0].update(flags_u8=256),
                   lambda s:s['slots'][0].update(amount_i32=2**31),lambda s:s['slots'][0].update(read_end_ticks=9999),
                   lambda s:s['slots'].pop(),lambda s:s['source']['controller'].update(creation_key_u32=-1),
                   lambda s:s['slots'][0].update(evidence_sha256='wrong')]
        for mutate in mutations:
            p=EventRingProjector(capacity=4);s=snapshot();mutate(s)
            with self.assertRaises(InvalidRingSnapshot):p.consume(s)
        p=EventRingProjector(capacity=4);p.consume(snapshot());s=snapshot();s['slots'][0]['amount_i32']=1
        self.assertEqual(p.consume(s)['reason'],'non_increasing_sequence')
        s=snapshot(1);s['monotonic_frequency']=2;self.assertEqual(p.consume(s)['reason'],'clock_mismatch')
    def test_empty_ring_and_bounded_memory(self):
        p=EventRingProjector(capacity=4);p.consume(snapshot(head=3,count=0));values={0:(0,10,0,0)}
        p.consume(snapshot(1,head=0,count=1,values=values));self.assertEqual(len(p.consume(snapshot(2,head=0,count=1,values=values))['records']),1)
        p=EventRingProjector(capacity=128,owned_indices=range(64))
        for seq in range(1000):
            s=snapshot(seq,capacity=128,indices=range(64),head=127,values={0:(1,seq//2,seq//2,0)});p.consume(s)
            state=p.state_size();self.assertLessEqual(state['confirmed_slots'],64);self.assertLessEqual(state['pending_slots'],64)
        for capacity in (0,129,True):
            with self.assertRaises(InvalidRingSnapshot):EventRingProjector(capacity=capacity)

if __name__=='__main__':unittest.main()
