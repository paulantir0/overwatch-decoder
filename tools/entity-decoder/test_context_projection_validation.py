"""Admission-bound neutral context survives aggregation without actor aliasing."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from test_live_relations import context_setup, LiveRelations, SESSION, raw, live, next_frame
from context_projection_validation import validate_context_frame, context_source_from_frame
from aggregate_live_partitions import LivePartitions
from compact_live_entities import CompactLiveEntities
from compact_live_roster import CompactLiveRoster


class ContextPipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def fixture(self, **options):
        p,f,m,se,sg,_,kw=context_setup(self.root,additional_anchor=True,**options)
        a=LiveRelations(self.root,SESSION,1,**kw);a.consume(raw(se));a.consume(raw(sg))
        epoch=dict(acquisition=1,session_start_sha256=hashlib.sha256(raw(se)).hexdigest(),
            acquisition_end_sha256='ff'*32,segment_start_sha256=hashlib.sha256(raw(sg)).hexdigest(),
            previous_epoch_last_frame_end_ticks=None,previous_values_carried=False)
        def project(frame,index):
            out=a.consume(raw(live(frame,index)));out['session_epoch']=copy.deepcopy(epoch);return out
        out=project(f,2); source=context_source_from_frame(out)
        source.update(source_id='p1',objects=[{k:r[k]for k in ('controller_object_key','body_object_key')}for r in out['relations']],
            fields=[dict(name=v['name'],type=v['type'])for v in p['fields']])
        config=dict(schema='overwatch-decoder.live-partition-config/1',epoch_id='fixture',clock_domain_id='fixture',target=p['target'],
            monotonic_frequency=1000,window_origin_ticks=0,window_ticks=50,maximum_skew_ticks=200,maximum_origin_offset_ticks=10,
            sources=[source],roster=[dict(v,primary_source_id='p1')for v in source['objects']])
        return out,source,config,f,project

    def window(self,out,config):
        a=LivePartitions(raw(config));a.consume('p1',raw(out));return list(a.advance(150))[-1]

    def test_neutral_distinct_context_preserved_in_both_compactors(self):
        out,source,config,_,_=self.fixture()
        top=validate_context_frame(out,source,target=out['target'])
        self.assertNotIn(top['context_projection']['controller_object_key'],[r['controller_object_key']for r in out['relations']])
        single=CompactLiveEntities().consume(raw(out))
        w=self.window(out,config);compact=CompactLiveRoster().consume(raw(w))
        for old,new,roster in zip(out['relations'],single['players'],compact['players']):
            self.assertEqual(new['context_group_candidate']['value'],old['context_group_candidate'])
            self.assertEqual(roster['context_group_candidate']['value'],old['context_group_candidate'])
            self.assertIsNone(old['relative_allegiance_candidate']);self.assertIsNone(old['team_candidate'])
        self.assertEqual(w['context_group_projections']['p1']['projection'],top)
        self.assertFalse(compact['public_state_eligible'])

    def test_source_and_frame_pins_cannot_change(self):
        out,source,config,_,_=self.fixture()
        cases=('admission','epoch','event','review','profile','legacy','reference','boolean','read','ordinary_body')
        for case in cases:
            with self.subTest(case=case):
                bad=copy.deepcopy(out);t=bad['context_group_projection'];r=bad['relations'][0]
                if case=='admission':t['admission']['configured_admission_sha256']='00'*32
                elif case=='epoch':bad['session_epoch']['segment_start_sha256']='00'*32
                elif case=='event':t['admission']['event_sha256']='00'*32
                elif case=='review':t['context_projection']['native_review_sha256']='00'*32
                elif case=='profile':t['raw_category_projection']['profile_sha256']='00'*32
                elif case=='legacy':r['team_candidate']='old-team'
                elif case=='reference':r['context_group_evidence']['context_reference']['body_object_key']=r['body_object_key']
                elif case=='boolean':r['context_group_candidate']['category_matches_context']=int(r['context_group_candidate']['category_matches_context'])
                elif case=='read':t['context_projection']['selector_evidence']['read_end_ticks']=99999
                else:r['position_candidate']['body_object_key']='body:'+'00'*32
                with self.assertRaises((ValueError,KeyError,TypeError)):LivePartitions(raw(config)).consume('p1',raw(bad))

    def test_gap_null_and_next_window_does_not_carry(self):
        out,source,config,f,project=self.fixture()
        a=LivePartitions(raw(config));a.consume('p1',raw(out));w=list(a.advance(150))[-1]
        c=CompactLiveRoster();c.consume(raw(w))
        gap=project(next_frame(f,missed=1),3);validate_context_frame(gap,source,target=out['target'])
        self.assertTrue(all(r['context_group_candidate']is None for r in gap['relations']))
        single=CompactLiveEntities();single.consume(raw(out));g=single.consume(raw(gap))
        self.assertTrue(all(r['context_group_candidate']['value']is None for r in g['players']))
        a.consume('p1',raw(gap));windows=list(a.advance(350))
        for window in windows:
            result=c.consume(raw(window))
            self.assertEqual(window['context_group_projections'],{})
            self.assertTrue(all(r['context_group_candidate']['value']is None for r in result['players']))

    def test_missing_primary_does_not_use_support_context(self):
        out,source,config,_,_=self.fixture()
        support=copy.deepcopy(source);support['source_id']='p2';config['sources'].append(support)
        a=LivePartitions(raw(config));a.consume('p2',raw(out));w=list(a.advance(150))[-1]
        result=CompactLiveRoster().consume(raw(w))
        self.assertIn('p2',w['context_group_projections'])
        self.assertTrue(all(r['context_group_candidate']['value']is None for r in result['players']))
        self.assertTrue(all(r['primary_observation']is None for r in result['players']))

    def test_raw_only_and_spectator_never_infer_groups(self):
        for opts in (dict(groups=False),dict(context_use='spectator')):
            with self.subTest(opts=opts):
                out,source,config,_,_=self.fixture(**opts)
                validate_context_frame(out,source,target=out['target']);result=CompactLiveRoster().consume(raw(self.window(out,config)))
                for row in result['players']:
                    v=row['context_group_candidate']['value'];self.assertIsNotNone(v['raw_flags'])
                    self.assertIsNone(v['global_group']);self.assertIsNone(v['relation_to_context'])

    def test_finite_group_expiry_keeps_only_raw_candidates(self):
        interval=dict(first_sequence=0,last_sequence=0,start_ticks=0,end_ticks=50,monotonic_frequency=1000)
        out,source,config,_,_=self.fixture(frame_scope=interval)
        validate_context_frame(out,source,target=out['target'])
        self.assertTrue(all(r['context_group_candidate']['global_group']is None for r in out['relations']))
        result=CompactLiveRoster().consume(raw(self.window(out,config)))
        self.assertTrue(all(r['context_group_candidate']['value']['raw_flags']is not None for r in result['players']))
        bad=copy.deepcopy(out);bad['context_group_projection']['group_projection']['status']='observed'
        with self.assertRaisesRegex(ValueError,'context_group_unobserved_scope'):validate_context_frame(bad,source)

    def test_context_pins_and_transition_nulls_require_epoch_boundary(self):
        from test_compact_live_roster import transition
        out,source,config,f,project=self.fixture();a=LivePartitions(raw(config));a.consume('p1',raw(out))
        first=list(a.advance(150))[-1];compact=CompactLiveRoster();compact.consume(raw(first))
        later=project(next_frame(f),3);a.consume('p1',raw(later));windows=list(a.advance(250))
        compact.consume(raw(windows[0]));bad=copy.deepcopy(windows[1]);entry=bad['context_group_projections']['p1']
        entry['source_admission']['configured_admission_sha256']='de'*32
        entry['projection']['admission']['configured_admission_sha256']='de'*32
        for row in bad['relations']:
            row['authoritative_observation']['relation']['context_group_evidence']['admission']['configured_admission_sha256']='de'*32
        with self.assertRaisesRegex(ValueError,'context_source_changed_without_epoch'):compact.consume(raw(bad))
        fresh=CompactLiveRoster();fresh.consume(raw(first));opened=fresh.consume(raw(transition(first)))
        self.assertTrue(all(r['context_group_candidate']['value']is None for r in opened['players']))
        self.assertNotIn('context_group_projections',opened)

    def test_context_walk_preserves_primitive_budget_depth_and_read_checks(self):
        from context_projection_validation import _scope
        timing=dict(start_ticks=10,end_ticks=20)
        for node in ({'padding':[0]*500000},{'read_start_ticks':True,'read_end_ticks':20}):
            with self.assertRaises(ValueError):_scope(node,timing,'p','b')
        node=0
        for _ in range(25):node=[node]
        with self.assertRaisesRegex(ValueError,'context_evidence_bound'):_scope(node,timing,'p','b')
        _scope({'read_start_ticks':10,'read_end_ticks':20,'fields':['a','b']},timing,'p','b')

    def test_enabled_disabled_toggle_and_unbound_aggregate_reference_reject(self):
        out,source,config,f,project=self.fixture()
        for bad in (dict(source,context_projection=None),dict(source,context_projection={})):
            with self.assertRaises(ValueError):validate_context_frame(out,bad,target=out['target'])
        later=project(next_frame(f),3);later.pop('context_group_projection');later['raw_context_output_enabled']=False
        p=CompactLiveEntities();p.consume(raw(out))
        with self.assertRaises(ValueError):p.consume(raw(later))
        w=self.window(out,config)
        for case in ('missing','hash','time','reference','field'):
            with self.subTest(case=case):
                bad=copy.deepcopy(w);entry=bad['context_group_projections']['p1'];node=bad['relations'][0]['authoritative_observation']
                if case=='missing':bad.pop('context_group_projections')
                elif case=='hash':entry['semantic_projection_sha256']='00'*32
                elif case=='time':entry['source_timing']['end_ticks']=99999
                elif case=='field':node['relation']['context_group_evidence']['actor_fields'][0]['field']='forged-field'
                else:node['context_group_projection_ref']='/wrong'
                with self.assertRaises((ValueError,KeyError,TypeError)):CompactLiveRoster().consume(raw(bad))

if __name__=='__main__':unittest.main()
