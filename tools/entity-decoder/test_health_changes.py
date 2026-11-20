"""Net pool-sum changes retain exact samples and never bridge missing evidence."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from health_changes import HealthChanges, sample
from compact_live_entities import CompactLiveEntities
from test_compact_live_entities import fixture, raw


class HealthChangeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.frames = fixture(Path(self.tmp.name))

    def samples(self, frame):
        return [sample(r, target=frame['target'], timing=frame['timing'], artifacts=frame['source_artifacts'],
                       epoch=dict(session_id=frame['session_id'], segment=frame['segment'], session_epoch=frame.get('session_epoch')),
                       source_sha256=hashlib.sha256(raw(frame)).hexdigest(), evidence_ref='/relations/'+str(i)+'/health_candidate',
                       gap=frame['gap_before']['skipped_slots'] > 0) for i,r in enumerate(frame['relations'])]

    def test_exact_signed_change_and_two_detached_samples(self):
        a,b=self.frames
        h=b['relations'][0]['health_candidate'];h['contributions'][0]['value']=72.5;h['raw_sum']=72.5;h['display_ceiling_candidate']=73
        t=HealthChanges();self.assertIsNone(t.project(self.samples(a))[0]['value'])
        result=t.project(self.samples(b))[0]
        self.assertEqual(result['value'],-27.5)
        self.assertEqual(result['previous_sample']['raw_sum'],100)
        self.assertEqual(result['current_sample']['raw_sum'],72.5)
        self.assertEqual(result['current_sample']['semantic_projection_sha256'],hashlib.sha256(raw(b)).hexdigest())
        result['current_sample']['scope']['acquisition']['evidence_sha256']='bad'
        self.assertNotEqual(t.previous[b['relations'][0]['controller_object_key']]['scope']['acquisition']['evidence_sha256'],'bad')
        self.assertIsNone(result['attribution']);self.assertFalse(result['atomic'])

    def test_unknown_missing_and_explicit_gap_clear_baseline(self):
        for cause in ('unknown','missing','gap'):
            with self.subTest(cause=cause):
                t=HealthChanges();t.project(self.samples(self.frames[0]));b=copy.deepcopy(self.frames[1])
                if cause=='unknown':b['relations'][0]['health_candidate']=None
                elif cause=='missing':b['relations']=[]
                else:b['gap_before']['skipped_slots']=1
                t.project(self.samples(b));self.assertNotIn(self.frames[0]['relations'][0]['controller_object_key'],t.previous)
                self.assertEqual(t.project(self.samples(self.frames[1]))[0]['reason'],'no_previous_observed_health')

    def test_identity_epoch_membership_and_nonconsecutive_reset(self):
        base=self.samples(self.frames[1])
        for mutation,reason in (
            (lambda s:s.update(body_object_key='body:'+'a'*64),'body_changed'),
            (lambda s:s['scope']['epoch'].update(segment=2),'source_epoch_or_membership_changed'),
            (lambda s:s['scope'].update(profile_sha256='a'*64),'source_epoch_or_membership_changed'),
            (lambda s:s['scope'].update(membership_contract_sha256='b'*64),'source_epoch_or_membership_changed'),
            (lambda s:s['timing'].update(sequence=s['timing']['sequence']+1),'nonconsecutive_source_frames'),
            (lambda s:s['timing'].update(start_ticks=0),'overlapping_source_reads')):
            t=HealthChanges();t.project(self.samples(self.frames[0]));b=copy.deepcopy(base);mutation(b[0]['sample'])
            self.assertEqual(t.project(b)[0]['reason'],reason)

    def test_repeated_frame_and_duplicate_controller_are_not_changes(self):
        t=HealthChanges();a=self.samples(self.frames[0]);t.project(a)
        self.assertEqual(t.project(a)[0]['reason'],'nonconsecutive_source_frames')
        with self.assertRaisesRegex(ValueError,'duplicate_controller'):t.project(a+a)
        self.assertEqual(t.previous,{})
        with self.assertRaisesRegex(ValueError,'failed'):t.project(a)

    def test_invalid_health_binding_sum_and_read_span_rejected(self):
        for mutate in (lambda h:h.update(body_object_key='body:'+'f'*64), lambda h:h.update(raw_sum=99),
                       lambda h:h['contributions'][0].update(read_end_ticks=10**30),
                       lambda h:h.update(acquisition_evidence_sha256='f'*64),
                       lambda h:h.update(complete_supplied_membership_guarding=False)):
            f=copy.deepcopy(self.frames[0]);mutate(f['relations'][0]['health_candidate'])
            with self.assertRaises(ValueError):self.samples(f)

    def test_compact_source_adds_change_without_modifying_health(self):
        c=CompactLiveEntities();a,b=self.frames
        first=c.consume(raw(a));second=c.consume(raw(b))
        self.assertIsNone(first['players'][0]['health_change_candidate']['value'])
        self.assertEqual(second['players'][0]['health_change_candidate']['value'],0)
        self.assertEqual(second['players'][0]['health_candidate']['value']['raw_sum'],100)
        s=self.samples(b);s[0]['sample']['scope']['epoch']['segment']=2
        self.assertIsNone(c.health_changes.project(s)[0]['value'])

    def test_batch_bound_and_transition_clear_every_baseline(self):
        t=HealthChanges();a=self.samples(self.frames[0]);t.project(a);t.clear()
        self.assertIsNone(t.project(self.samples(self.frames[1]))[0]['value'])
        with self.assertRaisesRegex(ValueError,'actor_bound'):t.project(a*129)
        self.assertEqual(t.previous,{})

    def test_roster_transition_discards_baseline_without_values(self):
        from test_compact_live_roster import fixture as roster_fixture, transition
        from compact_live_roster import CompactLiveRoster
        with tempfile.TemporaryDirectory() as d:
            windows=roster_fixture(Path(d));c=CompactLiveRoster()
            c.consume(raw(windows[0]))
            self.assertTrue(c.health_changes.previous)
            end=c.consume(raw(transition(windows[0])))
            self.assertEqual(c.health_changes.previous,{})
            self.assertTrue(all(r['health_change_candidate']['value'] is None for r in end['players']))

    def test_adjacent_source_gap_is_excluded_before_roster_change(self):
        from aggregate_live_partitions import LivePartitions
        from compact_live_roster import CompactLiveRoster
        from test_aggregate_live_partitions import live_fixture
        with tempfile.TemporaryDirectory() as d:
            config, sources = live_fixture(Path(d))
            for frames in sources.values():
                for frame in frames:
                    for row in frame['relations']:
                        row['position_candidate']['validation_status']='guarded_research'
                        row['health_candidate'].update(status='candidate',display_ceiling_candidate=int(row['health_candidate']['raw_sum']))
                        row['hero_resource_guid_candidate'].update(validation_status='matching_guarded_resource_research',public_state_eligible=False)
                        row['hero_label_evidence'].update(validation_status='guarded_build_resource_label_research',catalog_sha256='ab'*32)
                        row['cached_label_evidence']['validation_status']='guarded_native_cache_string_research'
                        row['category_evidence']['validation_status']='guarded_live_category_roster_research'
            coordinator=LivePartitions(raw(config)); compact=CompactLiveRoster()
            for sid in sources:coordinator.consume(sid,raw(sources[sid][0]))
            first=list(coordinator.advance(1050))[0];compact.consume(raw(first))
            # Even a source carrying health on an adjacent but explicitly skipped
            # frame cannot produce an authoritative roster observation.
            skipped=sources['p1'][1];skipped['gap_before']['skipped_slots']=1
            self.assertEqual(skipped['timing']['sequence'],sources['p1'][0]['timing']['sequence']+1)
            self.assertIsNotNone(skipped['relations'][0]['health_candidate'])
            for sid in sources:coordinator.consume(sid,raw(sources[sid][1]))
            window=list(coordinator.advance(1100))[0];result=compact.consume(raw(window))
            self.assertEqual(window['unavailable_sources']['p1'],'gap_in_window')
            affected=0;unaffected=0
            for original,row in zip(window['relations'],result['players']):
                if original['primary_source_id']=='p1':
                    affected+=1;self.assertIsNone(original['authoritative_observation'])
                    self.assertIsNone(row['health_candidate']['value'])
                    self.assertIsNone(row['health_change_candidate']['value'])
                    self.assertNotIn(row['controller_object_key'],compact.health_changes.previous)
                elif row['status']=='observed':
                    unaffected+=1;self.assertEqual(row['health_change_candidate']['value'],0)
            self.assertGreater(affected,0);self.assertGreater(unaffected,0)

    def test_roster_candidates_are_additive_and_use_authoritative_evidence(self):
        from test_compact_live_roster import fixture as roster_fixture
        from compact_live_roster import CompactLiveRoster
        with tempfile.TemporaryDirectory() as d:
            values=roster_fixture(Path(d))
            windows=values
            c=CompactLiveRoster()
            for w in windows:
                r=c.consume(raw(w))
                for row in r['players']:
                    change=row['health_change_candidate']
                    if change['value'] is not None:
                        cur=change['current_sample']
                        self.assertEqual(cur['evidence_container_sha256'],hashlib.sha256(raw(w)).hexdigest())
                        self.assertIn('/authoritative_observation/',cur['evidence_ref'])
