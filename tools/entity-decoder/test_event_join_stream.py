import copy
import itertools
import unittest
from event_entity_join import EventEntityJoin
from event_join_stream import EventJoinStream


class StreamTests(unittest.TestCase):
    def setUp(self):
        self.scope = dict(target=dict(pid=1, creation_file_time=2, executable_sha256='a'*64,
            image_name='fixture', architecture='x64'), world_epoch='w', clock_id='qpc', frequency=1000)

    def stream(self, **kwargs):
        return EventJoinStream(scope=self.scope, sources=['a', 'b'], maximum_age_ticks=100, **kwargs)

    def observation(self, tick, key=1, **changes):
        return dict(scope=self.scope, body_key_u32=key, observed_ticks=tick, valid_until_ticks=1000,
            status='observed', body_lifetime='life', entity_id='entity', controller_id='controller',
            hero='fixture', relation='enemy', provenance={'frame':str(tick)}, **changes)

    def pair(self, tick, key=1):
        return self.observation(tick, key), [dict(scope=self.scope, body_key_u32=key,
            body_lifetime='life', entity_id='entity', controller_id='controller', valid_from_ticks=0,
            valid_until_ticks=1000, provenance={'proof':'fixture'})]

    def event(self, tick, key=1):
        return dict(event=dict(scope=self.scope, body_key_u32=key, qpc_ticks=tick,
            provenance={'event':str(tick)}), payload={'original_tick':tick-1})

    def test_all_arrival_interleavings_equal_chronological_oracle(self):
        oracle = EventEntityJoin(maximum_age_ticks=100)
        oracle.observe(*self.pair(10)); label1 = oracle.join(self.event(10)['event'])
        oracle.observe(*self.pair(20)); label2 = oracle.join(self.event(21)['event'])
        for positions in itertools.combinations(range(6), 3):
            a = iter([10,20,30]); b = iter([10,21,30]); s=self.stream(); result=[]
            for n in range(6):
                if n in positions:
                    t=next(a);result += s.submit('a',t,observations=[self.pair(t)] if t<30 else [])
                else:
                    t=next(b);result += s.submit('b',t,events=[self.event(t)] if t<30 else [])
            self.assertEqual([r['label'] for r in result],[label1,label2])
            self.assertEqual(s.watermark,30)

    def test_terminal_invalidates_before_same_time_event(self):
        s=self.stream();s.submit('a',10,observations=[self.pair(10)])
        s.submit('b',10)
        self.assertEqual(s.submit('b',20,events=[self.event(20)]),[])
        self.assertEqual(s.finish('a',20)[0]['status'],'unresolved')
        with self.assertRaises(ValueError):s.submit('a',21)
        s.finish('b',21);self.assertEqual(s.watermark,21)

    def test_gap_invalidation_and_later_recovery(self):
        s=self.stream();s.submit('a',10,observations=[self.pair(10)]);s.submit('b',10)
        s.invalidate('a',20,'gap')
        self.assertEqual(s.submit('b',20,events=[self.event(20)])[0]['status'],'unresolved')
        s.submit('a',30,observations=[self.pair(30)])
        self.assertEqual(s.submit('b',30,events=[self.event(30)])[0]['status'],'resolved')

    def test_conflicting_duplicate_and_identical_duplicate(self):
        for conflict in (False,True):
            s=self.stream();o,p=self.pair(10);other=copy.deepcopy(o)
            if conflict:other['hero']='different'
            s.submit('a',10,observations=[(o,p)])
            r=s.submit('b',10,observations=[(other,p)],events=[self.event(10)])
            self.assertEqual(r[0]['status'],'unresolved' if conflict else 'resolved')

    def test_unknown_removed_replace_labels(self):
        for status in ('unknown','removed','invalid'):
            s=self.stream();s.submit('a',10,observations=[self.pair(10)]);s.submit('b',10)
            o,p=self.pair(20);o['status']=status
            s.submit('a',20,observations=[(o,[])])
            self.assertEqual(s.submit('b',20,events=[self.event(20)])[0]['status'],'unresolved')

    def test_malformed_atomic_and_scope_clock(self):
        for mutation in ('clock','tick','nan','shape','proof'):
            s=self.stream();s.submit('a',10,observations=[self.pair(10)])
            e=copy.deepcopy(self.event(10));obs=[]
            if mutation=='clock':e['event']['scope']['clock_id']='other'
            if mutation=='tick':e['event']['qpc_ticks']=11
            if mutation=='nan':e['payload']=float('nan')
            if mutation=='shape':e['extra']=1
            if mutation=='proof':
                o,p=copy.deepcopy(self.pair(10));p[0]['scope']['world_epoch']='other';obs=[(o,p)]
            with self.assertRaises(ValueError):s.submit('b',10,observations=obs,events=[e])
            self.assertIsNone(s.watermark)
            self.assertEqual(s.submit('b',10,events=[self.event(10)])[0]['status'],'resolved')
        with self.assertRaises(ValueError):self.stream().submit('a',1,observations={})

    def test_bounds_abort_and_payload_copy(self):
        s=self.stream(maximum_pending_rows=1)
        e=self.event(10);s.submit('b',10,events=[e]);e['payload']['original_tick']=999
        with self.assertRaises(ValueError):s.submit('b',11,events=[self.event(11)])
        result=s.abort('deadline');self.assertEqual(result[0]['payload']['original_tick'],9)
        self.assertEqual(result[0]['reason'],'aborted:deadline')
        with self.assertRaises(ValueError):s.submit('a',10)
        with self.assertRaises(ValueError):self.stream(maximum_pending_bytes=20).submit('a',10)

    def test_new_owner_not_invalidated_by_old_owner_terminal(self):
        s=self.stream();s.submit('a',10,observations=[self.pair(10)]);s.submit('b',10)
        s.submit('b',20,observations=[self.pair(20)]);s.submit('a',20)
        s.finish('a',30)
        self.assertEqual(s.submit('b',30,events=[self.event(30)])[0]['status'],'resolved')

    def test_oversized_shared_timestamp_is_atomic(self):
        s=self.stream()
        s.submit('a',10,observations=[self.pair(10,k) for k in range(256)])
        with self.assertRaisesRegex(ValueError,'timestamp_group'):
            s.submit('b',10,observations=[self.pair(10,999)])
        self.assertIsNone(s.watermark)
        r=s.submit('b',10,events=[self.event(10,255)])
        self.assertEqual(r[0]['status'],'resolved')

    def test_rejected_multi_group_submit_rolls_back_prior_row_owner_and_output(self):
        s = self.stream(); s.submit('a', 10, observations=[self.pair(10)]); s.submit('b', 10)
        s.submit('b', 20, observations=[self.pair(20)], events=[self.event(20)])
        s.submit('b', 30, observations=[self.pair(30, 999)])
        def state():
            return (s._join.__dict__, s._owners, s._progress, s._finished, s._pending, s._closed, s.watermark)
        original_join, original_owners = s._join, s._owners
        saved = copy.deepcopy(state())
        with self.assertRaisesRegex(ValueError, 'stream_timestamp_group_limit'):
            s.submit('a', 30, observations=[self.pair(30, key) for key in range(256)])
        self.assertEqual(state(), saved)
        self.assertIs(s._join, original_join); self.assertIs(s._owners, original_owners)
        self.assertEqual(s._owners[1], {'a'})
        # Tick 20 updated the working row/owner and built a result before tick 30
        # rejected. Retry must release that result exactly once with the new label.
        result = s.submit('a', 30, events=[self.event(30)])
        self.assertEqual([(r['tick'], r['status'], r['label']['observation_ticks']) for r in result],
                         [(20, 'resolved', 20), (30, 'resolved', 20)])
        self.assertEqual(s._owners[1], {'b'}); self.assertEqual(s.watermark, 30)

    def test_caller_pending_result_and_label_aliases_are_isolated(self):
        caller_scope = copy.deepcopy(self.scope)
        s = EventJoinStream(scope=caller_scope, sources=['a', 'b'], maximum_age_ticks=100)
        caller_scope['world_epoch'] = 'caller-change'
        observation, proofs = copy.deepcopy(self.pair(10))
        s.submit('a', 10, observations=[(observation, proofs)])
        observation['scope']['target']['pid'] = 999
        observation['provenance']['frame'] = 'caller-change'
        proofs[0]['provenance']['proof'] = 'caller-change'
        wrapper = self.event(10)
        wrapper['payload'] = {'same_event': wrapper['event']}
        result = s.submit('b', 10, events=[wrapper, wrapper])
        wrapper['event']['provenance']['event'] = 'caller-change'
        wrapper['payload']['extra'] = 'caller-change'
        self.assertEqual([r['status'] for r in result], ['resolved', 'resolved'])
        first, second = result; expected = copy.deepcopy(second)
        self.assertIs(first['payload']['same_event'], first['event'])
        self.assertIsNot(first['label']['scope'], first['event']['scope'])
        self.assertIsNot(first['label']['proof_provenance'], second['label']['proof_provenance'])
        first['event']['scope']['world_epoch'] = 'result-change'
        first['label']['observation_provenance']['frame'] = 'result-change'
        first['label']['proof_provenance'][0]['proof'] = 'result-change'
        self.assertEqual(second, expected)
        self.assertEqual(first['payload']['same_event']['scope']['world_epoch'], 'result-change')
        s.submit('a', 20)
        later = s.submit('b', 20, events=[self.event(20)])[0]
        self.assertEqual(later['label']['scope'], self.scope)
        self.assertEqual(later['label']['observation_provenance'], {'frame': '10'})
        self.assertEqual(later['label']['proof_provenance'], [{'proof': 'fixture'}])

    def test_eviction_and_strict_order(self):
        s=self.stream(maximum_keys=1);s.submit('a',10,observations=[self.pair(10,1),self.pair(10,2)])
        r=s.submit('b',10,events=[self.event(10,1),self.event(10,2)])
        self.assertEqual([x['status'] for x in r],['unresolved','resolved'])
        with self.assertRaises(ValueError):s.submit('b',10)

if __name__ == '__main__':unittest.main()
