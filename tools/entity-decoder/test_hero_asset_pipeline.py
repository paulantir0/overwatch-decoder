"""Optional typed-asset candidate admission, aggregate and compact parity."""
import copy
from pathlib import Path
import tempfile
import unittest

from aggregate_partitions import validate_row
from aggregate_live_partitions import LivePartitions
from compact_live_entities import CompactLiveEntities
from compact_live_roster import CompactLiveRoster
from test_aggregate_live_partitions import live_fixture
from test_compact_live_entities import fixture as entity_fixture, raw, pointer, new_epoch
from test_compact_live_roster import transition


SUFFIXES = ('_part83_0000_hero_resource_low_candidate_i32', '_part83_0000_hero_resource_high_candidate_i32',
            '_body_0000_hero_resource_low_candidate_i32', '_body_0000_hero_resource_high_candidate_i32')


def add_assets(frame):
    frame.update(hero_asset_output_enabled=True, hero_asset_catalog_sha256='a1'*32)
    for i, row in enumerate(frame['relations']):
        prefix = 'controller_'+str(i).zfill(4); row['controller_prefix'] = prefix
        resource = row['hero_resource_guid_candidate']; guid = '0x02E0000000000003'; resource['value'] = guid
        for word, suffix, value in zip(resource['evidence'], SUFFIXES, [3, 0x02E00000, 3, 0x02E00000]):
            word.update(field=prefix+suffix, value=value)
        row['hero_label_evidence']['mapping']['resource_guid'] = guid
        row.update(hero_asset_label_candidate='Typed Fixture', hero_asset_label_reason=None)
        row['hero_asset_label_evidence'] = dict(mapping=dict(label='Typed Fixture', resource_guid=guid,
            build_sha256=frame['target']['executable_sha256'], locale='enUS', asset_report_sha256='b2'*32,
            asset_decoded_sha256='c3'*32, asset_build={'version':'fixture'}, mapping_scope='caller_build_scoped_typed_asset',
            validation_status='typed_asset_resource_match', runtime_ui_validated=False, public_state_eligible=False),
            fields=copy.deepcopy(resource['evidence']), catalog_sha256=frame['hero_asset_catalog_sha256'],
            profile_sha256=frame['profile_sha256'], build_sha256=frame['target']['executable_sha256'],
            controller_object_key=row['controller_object_key'], body_object_key=row['body_object_key'],
            source_target=copy.deepcopy(frame['target']), frame_timing=copy.deepcopy(frame['timing']),
            acquisition=copy.deepcopy(frame['source_artifacts']['acquisition']), resource_guid=guid,
            binding_scope='controller_and_body', validation_status='guarded_typed_asset_resource_candidate',
            runtime_ui_validated=False, public_state_eligible=False, visibility='unknown')
    return frame


def pipeline_fixture(root):
    config, frames = live_fixture(root)
    for source in config['sources']:
        for frame in frames[source['source_id']]:
            frame.update(participant_identity_validated=False, continuity_across_gaps=False,hero_catalog_sha256='ab'*32)
            for row in frame['relations']:
                row['position_candidate']['validation_status']='guarded_research'
                row['health_candidate'].update(status='candidate',display_ceiling_candidate=int(row['health_candidate']['raw_sum']))
                row['hero_resource_guid_candidate'].update(validation_status='matching_guarded_resource_research',public_state_eligible=False)
                row['hero_label_evidence'].update(validation_status='guarded_build_resource_label_research',catalog_sha256='ab'*32)
                row['cached_label_evidence']['validation_status']='guarded_native_cache_string_research'
                row['category_evidence']['validation_status']='guarded_live_category_roster_research'
            add_assets(frame)
            names={f['name'] for f in source['fields']}
            for row in frame['relations']:
                for word in row['hero_asset_label_evidence']['fields']:
                    if word['field'] not in names:
                        source['fields'].append(dict(name=word['field'],type='i32'));names.add(word['field'])
    return config,frames


class HeroAssetPipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)

    def test_unconfigured_default_bytes_unchanged(self):
        frame=entity_fixture(self.root)[0]
        old=CompactLiveEntities().consume(raw(frame))
        self.assertTrue(all('hero_asset_label_candidate' not in row for row in old['players']))
        self.assertNotIn('hero_asset_output_enabled',old)
        config,frames=live_fixture(self.root)
        adapter=LivePartitions(raw(config))
        for sid in frames:adapter.consume(sid,raw(frames[sid][0]))
        window=list(adapter.advance(1050))[0]
        self.assertTrue(all('hero_asset_projection' not in row['authoritative_observation']for row in window['relations']))

    def test_single_frame_separate_label_and_exact_evidence_pointer(self):
        frame=add_assets(entity_fixture(self.root)[0]);out=CompactLiveEntities().consume(raw(frame))
        self.assertTrue(out['hero_asset_output_enabled']);self.assertEqual(out['hero_asset_catalog_sha256'],'a1'*32)
        for i,row in enumerate(out['players']):
            asset=row['hero_asset_label_candidate'];self.assertEqual(asset['value'],'Typed Fixture')
            self.assertEqual(row['hero_label_candidate']['value'],'Fixture Hero');self.assertFalse(asset['runtime_ui_validated'])
            self.assertEqual(pointer(frame,asset['evidence_ref']),frame['relations'][i]['hero_asset_label_evidence'])
            self.assertEqual(asset['read_span_ticks'],[frame['timing']['start_ticks']+1,frame['timing']['start_ticks']+2])

    def test_forged_candidate_rejected_by_both_admissions(self):
        frame=add_assets(entity_fixture(self.root)[0])
        mutations={
            'label':lambda r:r.update(hero_asset_label_candidate='Forged'),
            'mapping_label':lambda r:r['hero_asset_label_evidence']['mapping'].update(label='Forged'),
            'body':lambda r:r['hero_asset_label_evidence'].update(body_object_key='body:'+'f0'*32),
            'profile':lambda r:r['hero_asset_label_evidence'].update(profile_sha256='f1'*32),
            'span':lambda r:r['hero_asset_label_evidence']['fields'][0].update(read_end_ticks=999999),
            'resource':lambda r:r['hero_asset_label_evidence'].update(resource_guid='0x02E0000000000004'),
            'word':lambda r:r['hero_asset_label_evidence']['fields'][0].update(value=4),
            'field':lambda r:r['hero_asset_label_evidence']['fields'][0].update(field='unrelated'),
            'catalog':lambda r:r['hero_asset_label_evidence'].update(catalog_sha256='f2'*32),
            'target':lambda r:r['hero_asset_label_evidence']['source_target'].update(pid=999),
            'timing':lambda r:r['hero_asset_label_evidence']['frame_timing'].update(sequence=999),
            'acquisition':lambda r:r['hero_asset_label_evidence']['acquisition'].update(evidence_sha256='f3'*32),
            'ui_claim':lambda r:r['hero_asset_label_evidence']['mapping'].update(runtime_ui_validated=True),
            'asset_pin':lambda r:r['hero_asset_label_evidence']['mapping'].update(asset_report_sha256='bad'),
        }
        for name,mutate in mutations.items():
            with self.subTest(name=name):
                bad=copy.deepcopy(frame);mutate(bad['relations'][0])
                with self.assertRaises(ValueError):CompactLiveEntities().consume(raw(bad))
                with self.assertRaises(ValueError):validate_row(bad['relations'][0],bad,{'object_pairs':[],'recording_manifest_sha256':'dd'*32})

    def test_gap_unknown_and_epoch_do_not_fill_asset(self):
        first,second=entity_fixture(self.root);add_assets(first);add_assets(second)
        second['gap_before']['skipped_slots']=1
        for row in second['relations']:
            row.update(hero_asset_label_candidate=None,hero_asset_label_evidence=None,hero_asset_label_reason='gap_before_frame')
        p=CompactLiveEntities();p.consume(raw(first));out=p.consume(raw(second))
        self.assertTrue(all(r['hero_asset_label_candidate']['value']is None for r in out['players']))
        forged=copy.deepcopy(first);forged['gap_before']['skipped_slots']=1
        with self.assertRaises(ValueError):CompactLiveEntities().consume(raw(forged))
        unknown=copy.deepcopy(first)
        for row in unknown['relations']:
            row.update(relation_status='unknown',body_object_key=None,hero_asset_label_candidate=None,hero_asset_label_evidence=None,hero_asset_label_reason='guard_failed')
            for key in ['position_candidate','health_candidate','hero_resource_guid_candidate','hero_label','cached_label_candidate','raw_category_candidate','team_candidate','relative_allegiance_candidate']:row[key]=None
        out=CompactLiveEntities().consume(raw(unknown));self.assertTrue(all(r['hero_asset_label_candidate']['value']is None for r in out['players']))
        forged=copy.deepcopy(first);forged['relations'][0]['relation_status']='unknown'
        with self.assertRaises(ValueError):CompactLiveEntities().consume(raw(forged))
        fresh=add_assets(new_epoch(entity_fixture(self.root)[1],first['timing']['end_ticks']))
        projector=CompactLiveEntities();projector.consume(raw(first));out=projector.consume(raw(fresh))
        self.assertNotEqual(out['players'][0]['body_object_key'],first['relations'][0]['body_object_key'])
        self.assertEqual(out['players'][0]['hero_asset_label_candidate']['value'],'Typed Fixture')
        stale=copy.deepcopy(fresh);stale['relations'][0]['hero_asset_label_evidence']=first['relations'][0]['hero_asset_label_evidence']
        projector=CompactLiveEntities();projector.consume(raw(first))
        with self.assertRaises(ValueError):projector.consume(raw(stale))

    def test_live_aggregate_to_compact_exact_primary_and_unknown_windows(self):
        config,frames=pipeline_fixture(self.root);adapter=LivePartitions(raw(config))
        for sid in frames:adapter.consume(sid,raw(frames[sid][0]))
        first=list(adapter.advance(1050))[0];p=CompactLiveRoster();out=p.consume(raw(first))
        for i,row in enumerate(out['players']):
            original=first['relations'][i]['authoritative_observation']['relation']
            self.assertEqual(row['hero_asset_label_candidate']['value'],original['hero_asset_label_candidate'])
            self.assertEqual(pointer(first,row['hero_asset_label_candidate']['evidence_ref']),original['hero_asset_label_evidence'])
        second=list(adapter.advance(1100))[0];out=p.consume(raw(second))
        self.assertTrue(all(r['hero_asset_label_candidate']['value']is None for r in out['players']))
        event=transition(second);out=p.consume(raw(event))
        self.assertTrue(all(r['hero_asset_label_candidate']['value']is None for r in out['players']))

    def test_static_disagreement_unknown_and_forged_aggregate_rejected(self):
        config,frames=pipeline_fixture(self.root)
        # Different typed label under a different pinned report is a static conflict.
        row=frames['p2'][0]['relations'][0];row['hero_asset_label_candidate']='Other';row['hero_asset_label_evidence']['mapping'].update(label='Other',asset_report_sha256='ee'*32)
        adapter=LivePartitions(raw(config))
        for sid in frames:adapter.consume(sid,raw(frames[sid][0]))
        window=list(adapter.advance(1050))[0]
        self.assertIn('hero_asset_label_candidate',window['relations'][0]['conflicting_static_fields'])
        out=CompactLiveRoster().consume(raw(window));self.assertIsNone(out['players'][0]['hero_asset_label_candidate']['value'])
        config,frames=pipeline_fixture(self.root);adapter=LivePartitions(raw(config))
        for sid in frames:adapter.consume(sid,raw(frames[sid][0]))
        original=list(adapter.advance(1050))[0]
        for key in ['hero_asset_label_candidate','body_object_key','profile_sha256','resource_guid']:
            with self.subTest(key=key):
                bad=copy.deepcopy(original);node=bad['relations'][1]['authoritative_observation']['relation']
                if key=='hero_asset_label_candidate':node[key]='Forged'
                else:node['hero_asset_label_evidence'][key]='bad'
                with self.assertRaises(ValueError):CompactLiveRoster().consume(raw(bad))


if __name__=='__main__':unittest.main()
