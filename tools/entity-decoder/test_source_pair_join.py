import copy
import hashlib
import itertools
import json
import unittest

from source_pair_join import SourcePairJoin


def raw(v):
    return json.dumps(v, allow_nan=False, separators=(',', ':')).encode() + b'\n'


def identity(n=1):
    return dict(entity_id='body-'+str(n), controller_id='controller-'+str(n),
                body_owner_id='owner-body-'+str(n), controller_owner_id='owner-controller-'+str(n),
                body_key_u32=n, controller_key_u32=n+10, body_handle_u32=n+20, controller_handle_u32=n+30)


def scope():
    return dict(target=dict(pid=1, creation_file_time=2, executable_sha256='a'*64,
                            image_name='owned-fixture', architecture='x64'),
                world_id='world', clock_id='qpc', frequency=1000, recipient=identity(99))


def interval(start, end):
    return dict(start_ticks=start, end_ticks=end)


def actor(start, end, n=1):
    def field(value):
        return dict(status='observed', value=value, read_interval=interval(start, end), evidence={'field':'fixture'})
    return dict(identity=identity(n), status='observed', hero=field(dict(resource_id='qualified-resource', label='qualified-label')),
                relation=field('qualified-relation'), position=field([float(start), 2, 3]))


def roster(start=0, end=10, seq=0):
    return dict(schema='overwatch-decoder.source-roster/1', scope=scope(), session_id='roster-session', segment=1,
                sequence=seq, read_interval=interval(start, end), gap_before=False, evidence={'frame':seq},
                actors=[actor(start, end)])


def context(start=20, end=30, seq=0):
    return dict(schema='overwatch-decoder.source-context/1', scope=scope(), session_id='context-session', segment=4,
                sequence=seq, read_interval=interval(start, end), gap_before=False, evidence={'projection_sha256':'b'*64},
                observation_id='observation-'+str(seq), status='observed', source_body_key_u32=1,
                source_controller_key_u32=11)


class SourcePairJoinTests(unittest.TestCase):
    def joined(self, left=None, c=None, right=None):
        s=SourcePairJoin()
        s.observe_roster(raw(roster() if left is None else left))
        s.submit_context(raw(context() if c is None else c))
        result=s.observe_roster(raw(roster(40,50,1) if right is None else right))
        return s,result

    def test_moving_positions_exact_hashes_independent_epochs_and_detachment(self):
        left, c, right=roster(),context(),roster(40,50,1)
        s, rows=self.joined(left,c,right);r=rows[0]
        self.assertEqual(r['status'],'resolved');self.assertEqual(r['bracket_ticks'],50)
        self.assertEqual([e['actor']['position']['value'][0] for e in r['endpoints']],[0.0,40.0])
        self.assertEqual(r['context']['raw_sha256'],hashlib.sha256(raw(c)).hexdigest())
        self.assertEqual(r['endpoints'][0]['roster']['raw_sha256'],hashlib.sha256(raw(left)).hexdigest())
        r['endpoints'][1]['actor']['identity']['body_owner_id']='mutated'
        r['scope']['recipient']['body_key_u32']=3
        c2=context(55,60,1);s.submit_context(raw(c2));r2=s.observe_roster(raw(roster(70,80,2)))[0]
        self.assertEqual(r2['identity'],identity());self.assertEqual(r2['scope'],scope())
        self.assertEqual(left,roster())

    def test_all_source_ordered_arrival_interleavings(self):
        for positions in itertools.combinations(range(3),2):
            s=SourcePairJoin();rs=iter([roster(),roster(40,50,1)]);rows=[]
            for i in range(3):
                rows += s.observe_roster(raw(next(rs))) if i in positions else s.submit_context(raw(context()))
            self.assertEqual([r['status'] for r in rows],['resolved'])

    def test_exact_100ms_boundary_and_one_tick_over(self):
        for end,expected in ((100,'resolved'),(101,'unknown')):
            r=self.joined(right=roster(90,end,1))[1][0]
            self.assertEqual(r['status'],expected)
        c=context();c['scope']['frequency']=1001
        l=roster();l['scope']=copy.deepcopy(c['scope'])
        r=roster(90,101,1);r['scope']=copy.deepcopy(c['scope'])
        self.assertEqual(self.joined(l,c,r)[1][0]['reason'],'bracket_too_old')

    def test_latest_left_and_first_right_never_known_fallback(self):
        s=SourcePairJoin();s.observe_roster(raw(roster()))
        bad=roster(11,15,1);bad['actors'][0]['status']='unknown';s.observe_roster(raw(bad))
        s.submit_context(raw(context()));r=s.observe_roster(raw(roster(40,50,2)))[0]
        self.assertEqual(r['reason'],'pair_missing_unknown_or_aliased')
        s=SourcePairJoin();s.observe_roster(raw(roster()));bad=roster(40,50,1);bad['actors']=[]
        s.observe_roster(raw(bad));s.observe_roster(raw(roster(60,70,2)))
        self.assertEqual(s.submit_context(raw(context()))[0]['reason'],'pair_missing_unknown_or_aliased')

    def test_intervening_overlapping_unknown_and_removal_cannot_bridge(self):
        for mutation in ('unknown','removed','owner'):
            s=SourcePairJoin();s.observe_roster(raw(roster()));s.submit_context(raw(context()))
            middle=roster(15,35,1)
            if mutation=='unknown':middle['actors'][0]['status']='unknown'
            elif mutation=='removed':middle['actors']=[]
            else:middle['actors'][0]['identity']['body_owner_id']='changed'
            s.observe_roster(raw(middle));r=s.observe_roster(raw(roster(40,50,2)))[0]
            self.assertEqual(r['status'],'unknown')

    def test_every_identity_component_is_preserved(self):
        for key in identity():
            r=roster(40,50,1);v=r['actors'][0]['identity'][key]
            r['actors'][0]['identity'][key]=v+1 if type(v) is int else v+'-changed'
            self.assertEqual(self.joined(right=r)[1][0]['status'],'unknown',key)

    def test_zero_or_swapped_controller_and_duplicate_partial_alias(self):
        for b,k in ((1,0),(0,11),(1,12)):
            c=context();c['source_body_key_u32']=b;c['source_controller_key_u32']=k
            s=SourcePairJoin();s.observe_roster(raw(roster()));rows=s.submit_context(raw(c));rows+=s.observe_roster(raw(roster(40,50,1)))
            self.assertEqual(rows[0]['status'],'unknown')
        for mode in ('duplicate','body','controller'):
            r=roster(40,50,1);a=copy.deepcopy(r['actors'][0])
            if mode=='body':a['identity']['controller_key_u32']=12
            if mode=='controller':a['identity']['body_key_u32']=2
            r['actors'].append(a)
            self.assertEqual(self.joined(right=r)[1][0]['status'],'unknown')

    def test_exact_scope_world_local_owner_handle_target_clock(self):
        for part in ('world_id','clock_id','frequency','target','recipient'):
            r=roster(40,50,1)
            if part=='target':r['scope'][part]['creation_file_time']+=1
            elif part=='recipient':r['scope'][part]['body_owner_id']='different-owner'
            elif part=='frequency':r['scope'][part]+=1
            else:r['scope'][part]+='-different'
            self.assertEqual(self.joined(right=r)[1][0]['reason'],'source_epoch_changed')
        c=context();c['scope']['recipient']['controller_handle_u32']+=1
        s=SourcePairJoin();s.observe_roster(raw(roster()))
        self.assertEqual(s.submit_context(raw(c))[0]['reason'],'scope_mismatch')

    def test_roster_gap_epoch_and_context_epoch_flush(self):
        for kind in ('roster-gap','roster-epoch','context-epoch'):
            s=SourcePairJoin();s.observe_roster(raw(roster()));s.submit_context(raw(context()))
            r=roster(40,50,1)
            if kind=='roster-gap':r['gap_before']=True
            elif kind=='roster-epoch':r['segment']+=1
            if kind=='context-epoch':
                c=context(31,32,1);c['segment']+=1;rows=s.submit_context(raw(c))
            else:rows=s.observe_roster(raw(r))
            self.assertEqual(rows[0]['status'],'unknown')

    def test_new_guarded_context_after_context_gap_can_resolve(self):
        s=SourcePairJoin();s.observe_roster(raw(roster()));c=context();c['gap_before']=True
        s.submit_context(raw(c));self.assertEqual(s.observe_roster(raw(roster(40,50,1)))[0]['status'],'resolved')

    def test_unknown_inactive_flush_pending_without_global_roster_gap(self):
        for status in ('unknown','inactive'):
            s=SourcePairJoin();s.observe_roster(raw(roster()));s.submit_context(raw(context()))
            c=context(31,32,1);c['status']=status
            self.assertEqual(len(s.submit_context(raw(c))),2)
            c=context(33,34,2);s.submit_context(raw(c))
            self.assertEqual(s.observe_roster(raw(roster(40,50,1)))[0]['status'],'resolved')

    def test_labels_independent_and_unknown_position_not_carried(self):
        r=roster(40,50,1);r['actors'][0]['hero']['value']['resource_id']='different'
        r['actors'][0]['relation']['status']='unknown';r['actors'][0]['relation']['value']=None
        r['actors'][0]['position']['status']='unknown';r['actors'][0]['position']['value']=None
        result=self.joined(right=r)[1][0]
        self.assertEqual(result['status'],'resolved')
        self.assertEqual(result['fields']['hero']['status'],'unknown')
        self.assertEqual(result['fields']['relation']['status'],'unknown')
        self.assertIsNone(result['endpoints'][1]['actor']['position']['value'])
        self.assertEqual(result['endpoints'][0]['actor']['position']['value'],[0,2,3])

    def test_repeated_contexts_remain_distinct_observations(self):
        s=SourcePairJoin();s.observe_roster(raw(roster()))
        for i in range(3):s.submit_context(raw(context(seq=i)))
        rows=s.observe_roster(raw(roster(40,50,1)))
        self.assertEqual([r['observation_id'] for r in rows],['observation-0','observation-1','observation-2'])
        rows[0]['endpoints'][0]['actor']['identity']['entity_id']='caller-change'
        self.assertEqual(rows[1]['endpoints'][0]['actor']['identity'],identity())

    def test_row_and_byte_overflow_explicit_and_bounded(self):
        for kwargs in (dict(maximum_pending_rows=2),dict(maximum_pending_bytes=len(raw(roster()))+len(raw(context())))):
            s=SourcePairJoin(**kwargs);s.observe_roster(raw(roster()));s.submit_context(raw(context()))
            rows=s.submit_context(raw(context(31,32,1)))
            self.assertEqual([r['reason'] for r in rows],['buffer_overflow','buffer_overflow'])
            self.assertLessEqual(s.buffered_rows,s.maximum_pending_rows)
            self.assertLessEqual(s.buffered_bytes,s.maximum_pending_bytes)
        s=SourcePairJoin(maximum_pending_rows=1);r=roster();r['actors'].append(actor(0,10,2))
        self.assertEqual(s.observe_roster(raw(r))[0]['reason'],'buffer_overflow');self.assertEqual(s.buffered_rows,0)

    def test_history_only_overflow_is_explicit_and_recovery_requires_new_left(self):
        s=SourcePairJoin(maximum_pending_rows=2)
        for i in range(2):self.assertEqual(s.observe_roster(raw(roster(i*10,i*10+5,i))),[])
        self.assertEqual(s.observe_roster(raw(roster(40,50,2)))[0]['reason'],'buffer_overflow')
        self.assertEqual(s.submit_context(raw(context()))[0]['reason'],'missing_left_endpoint')

    def test_safe_history_pruning_bounded_long_stream(self):
        s=SourcePairJoin(maximum_pending_rows=4);s.observe_roster(raw(roster()))
        for i in range(100):
            self.assertEqual(s.submit_context(raw(context(20+i*40,30+i*40,i))),[])
            r=s.observe_roster(raw(roster(40+i*40,50+i*40,i+1)))
            self.assertEqual([x['status'] for x in r],['resolved']);self.assertLessEqual(s.buffered_rows,3)

    def test_finish_stall_terminal_and_actual_clock_requirement(self):
        for finish in (True,False):
            s=SourcePairJoin();s.observe_roster(raw(roster()));s.submit_context(raw(context()))
            with self.assertRaises(ValueError):s.advance(29)
            rows=s.finish(30) if finish else s.advance(30)
            self.assertEqual(rows[0]['reason'],'source_finished' if finish else 'source_stall')
            self.assertEqual(s.buffered_rows,0)
            if finish:
                with self.assertRaises(ValueError):s.submit_context(raw(context(31,32,1)))
            else:
                with self.assertRaises(ValueError):s.observe_roster(raw(roster(20,25,1)))

    def test_source_order_and_invalid_input_rollback(self):
        s=SourcePairJoin();s.observe_roster(raw(roster()));s.submit_context(raw(context()))
        before=(s.buffered_rows,s.buffered_bytes)
        bad=roster(40,50,1);bad['actors'][0]['position']['value']=[True,0,0]
        with self.assertRaises(ValueError):s.observe_roster(raw(bad))
        self.assertEqual((s.buffered_rows,s.buffered_bytes),before)
        for r in (roster(40,50,0),roster(40,50,2),roster(5,6,1)):
            with self.assertRaises(ValueError):s.observe_roster(raw(r))
        self.assertEqual(s.observe_roster(raw(roster(40,50,1)))[0]['status'],'resolved')

    def test_json_interval_key_order_does_not_change_timing(self):
        c=context();c['read_interval']={'end_ticks':30,'start_ticks':20}
        self.assertEqual(self.joined(c=c)[1][0]['status'],'resolved')

    def test_strict_raw_parser_types_duplicate_keys_nonfinite_and_depth(self):
        good=raw(context())
        bads=[context(),bytearray(good),good.decode(),b'\xff',b'{} {}',good.replace(b'"sequence":0',b'"sequence":0,"sequence":1'),
              good.replace(b'"sequence":0',b'"sequence":NaN'),good.replace(b'"sequence":0',b'"sequence":Infinity'),
              good.replace(b'"sequence":0',b'"sequence":true'),b'['*34+b'0'+b']'*34,b' '* (8*1024*1024+1)]
        for bad in bads:
            with self.assertRaises(ValueError):SourcePairJoin().submit_context(bad)
        for change in ('extra','key','interval','scope','unknown','fieldtime'):
            r=roster()
            if change=='extra':r['unexpected']=1
            elif change=='key':r['actors'][0]['identity']['body_key_u32']=2**32
            elif change=='interval':r['read_interval']['start_ticks']=11
            elif change=='scope':r['scope']['recipient']['body_owner_id']=''
            elif change=='unknown':r['actors'][0]['position']['status']='unknown'
            else:r['actors'][0]['position']['read_interval']['end_ticks']=11
            with self.assertRaises(ValueError):SourcePairJoin().observe_roster(raw(r))

    def test_duplicate_owner_handle_or_derived_id_is_ambiguous(self):
        for key in ('entity_id','controller_id','body_owner_id','controller_owner_id',
                    'body_handle_u32','controller_handle_u32'):
            r=roster(40,50,1);a=actor(40,50,2)
            a['identity'][key]=r['actors'][0]['identity'][key];r['actors'].append(a)
            self.assertEqual(self.joined(right=r)[1][0]['reason'],'pair_missing_unknown_or_aliased')

    def test_compact_evidence_boundary_and_oversize_rollback(self):
        # {"x":"..."} contributes8bytes;4096 is accepted,4097 rejected.
        s=SourcePairJoin();c=context();c['evidence']={'x':'a'*4088}
        self.assertEqual(s.submit_context(raw(c)),[])
        c2=context(31,32,1);c2['evidence']={'x':'a'*4089}
        before=(s.buffered_rows,s.buffered_bytes)
        with self.assertRaises(ValueError):s.submit_context(raw(c2))
        self.assertEqual((s.buffered_rows,s.buffered_bytes),before)
        r=roster();r['actors'][0]['position']['evidence']={'x':'a'*4089}
        with self.assertRaises(ValueError):s.observe_roster(raw(r))

    def test_nonfinite_overflow_and_unknown_field_values(self):
        r=roster();r['actors'][0]['position']['value']=[10**400,0,0]
        with self.assertRaises(ValueError):SourcePairJoin().observe_roster(raw(r))
        bad=raw(roster()).replace(b'0.0,2,3',b'1e999,2,3')
        with self.assertRaises(ValueError):SourcePairJoin().observe_roster(bad)

    def test_full_default_row_boundary_and_oversize_roster(self):
        s=SourcePairJoin();r=roster();r['actors']=[actor(0,10,n) for n in range(1,1025)]
        self.assertEqual(s.observe_roster(raw(r)),[]);self.assertEqual(s.buffered_rows,1024)
        r['sequence']=1;r['read_interval']=interval(20,30)
        r['actors']=[actor(20,30,n) for n in range(1,1026)]
        with self.assertRaises(ValueError):s.observe_roster(raw(r))
        self.assertEqual(s.buffered_rows,1024)
        s=SourcePairJoin();s.observe_roster(raw(roster()))
        for i in range(1023):self.assertEqual(s.submit_context(raw(context(seq=i))),[])
        self.assertEqual(s.buffered_rows,1024)
        rows=s.submit_context(raw(context(seq=1023)))
        self.assertEqual(len(rows),1024)
        self.assertTrue(all(r['reason']=='buffer_overflow' for r in rows));self.assertEqual(s.buffered_rows,0)

    def test_escaped_invalid_unicode_rejected_before_state_change(self):
        c=context();c['evidence']={'x':'\ud800'}
        bad=json.dumps(c).encode()
        with self.assertRaises(ValueError):SourcePairJoin().submit_context(bad)

    def test_config_caps_never_above_contract(self):
        for kw in (dict(maximum_pending_rows=1025),dict(maximum_pending_bytes=8*1024*1024+1),
                   dict(maximum_bracket_ms=101),dict(maximum_bracket_ms=True)):
            with self.assertRaises(ValueError):SourcePairJoin(**kw)


if __name__ == '__main__':
    unittest.main()
