"""Stateless forward validation and primary-only compact roster references."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from aggregate_partitions import canonical
from compact_live_entities import CompactLiveEntities,encode
from compact_live_roster import CompactLiveRoster
from forward_owner_validation import validate_forward_owner_frame
from test_compact_forward_owners import attach,unknown
from test_compact_live_entities import fixture as source_fixture,raw,pointer
from test_compact_live_roster import fixture as roster_fixture,transition


def source_admission(projection):
    return dict(schema='overwatch-decoder.forward-owner-source/1',**{key:projection.get(key)for key in ('contract_sha256','binding_template_sha256',
        'controller_hero_output_enabled','controller_hero_asset_catalog_sha256')},bindings=[dict(
        **{key:row[key]for key in ('binding_id','owned_field_prefix','controller_object_key','forward_owner_object_key')},
        identity_fields=[w['field']for w in row['identity_evidence']])for row in projection['relations']])


def with_forward(window,*,support=False):
    window=copy.deepcopy(window);node=window['relations'][0]['authoritative_observation'];sid=node['source_id']
    frame=dict(target=window['target'],profile_sha256=node['source_artifacts']['profile_sha256'],timing=node['source_timing'],
        source_artifacts=node['source_artifacts'],relations=[node['relation']],gap_before=dict(skipped_slots=0,previous_end_ticks=None,
        current_start_ticks=node['source_timing']['start_ticks'],previous_values_carried=False))
    attach(frame);projection=frame['forward_owner_projection'];admission=source_admission(projection)
    entry=dict(source_id=sid,source_timing=frame['timing'],source_artifacts=frame['source_artifacts'],source_recording=node['source_recording'],
        semantic_projection_sha256=node['semantic_projection_sha256'],semantic_hash_scope='projection_line',source_gap=frame['gap_before'],source_admission=admission,projection=projection)
    binding=admission['bindings'][0]
    window.update(forward_owner_sources={sid:admission},forward_owner_projections={sid:entry},forward_owners=[dict(
        **{key:binding[key]for key in ('binding_id','owned_field_prefix','controller_object_key','forward_owner_object_key')},
        primary_source_id=sid,status='observed',reason=None,projection_ref='/forward_owner_projections/'+sid+'/projection',relation_index=0,current_displayed_body=None)])
    if support:
        node=window['relations'][0]['supporting_observations'][0];sid=node['source_id']
        frame=dict(target=window['target'],profile_sha256=node['source_artifacts']['profile_sha256'],timing=node['source_timing'],
            source_artifacts=node['source_artifacts'],relations=[node['relation']],gap_before=dict(skipped_slots=0,previous_end_ticks=None,
            current_start_ticks=node['source_timing']['start_ticks'],previous_values_carried=False))
        attach(frame,label='Supporting Controller');p=frame['forward_owner_projection'];a=source_admission(p)
        window['forward_owner_sources'][sid]=a;window['forward_owner_projections'][sid]=dict(source_id=sid,source_timing=frame['timing'],
            source_artifacts=frame['source_artifacts'],source_recording=node['source_recording'],semantic_projection_sha256=node['semantic_projection_sha256'],
            semantic_hash_scope='projection_line',source_gap=frame['gap_before'],source_admission=a,projection=p)
    return window


class ForwardValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)

    def test_stateless_function_exact_extracted_output_and_declarations(self):
        frame=attach(source_fixture(self.root)[0]);before=copy.deepcopy(frame)
        result=validate_forward_owner_frame(frame);self.assertEqual(result,CompactLiveEntities()._forward_projection(frame));self.assertEqual(frame,before)
        p=frame['forward_owner_projection'];row=p['relations'][0];declarations={w['field']:'i32'for w in row['identity_evidence']}
        declarations.update({name:field['type']for name,field in row['owned_fields'].items()});declarations.update({w['field']:'i32'for w in row['controller_hero_asset_label_evidence']['fields']})
        self.assertEqual(result,validate_forward_owner_frame(frame,declarations,{row['controller_object_key']}))
        self.assertIsNone(validate_forward_owner_frame(source_fixture(self.root)[0]))
        for name in list(declarations):
            with self.subTest(missing=name):
                bad=dict(declarations);bad.pop(name)
                with self.assertRaises(ValueError):validate_forward_owner_frame(frame,bad)
        for name in [row['identity_evidence'][0]['field'],next(iter(row['owned_fields'])),row['controller_hero_asset_label_evidence']['fields'][0]['field']]:
            bad=dict(declarations);bad[name]='f64'
            with self.assertRaises(ValueError):validate_forward_owner_frame(frame,bad)
        with self.assertRaises(ValueError):validate_forward_owner_frame(frame,controllers={'controller:'+'12'*32})
        # No cache: a failed call does not alter the next valid stateless call.
        bad=copy.deepcopy(frame);bad['forward_owner_projection']['relations'][0]['health_candidate']['raw_sum']=999
        with self.assertRaises(ValueError):validate_forward_owner_frame(bad)
        self.assertEqual(result,validate_forward_owner_frame(frame))

    def test_compact_roster_exact_primary_pointer_and_parse_once_parity(self):
        window=with_forward(roster_fixture(self.root)[0],support=True);before=copy.deepcopy(window);line=canonical(window)+b'\n'
        out=CompactLiveRoster().consume(line);fast=CompactLiveRoster()._consume_decoded(line,window)
        self.assertEqual(encode(out),encode(fast));self.assertEqual(window,before)
        row=out['forward_owners'][0];original=window['forward_owner_projections']['p1']['projection']['relations'][0]
        self.assertEqual(row['position_candidate']['value'],original['position_candidate']['value']);self.assertEqual(row['controller_hero_asset_label_candidate']['value'],'Controller Fixture')
        self.assertEqual(pointer(window,row['health_candidate']['evidence_ref']),original['health_candidate'])
        self.assertEqual(pointer(window,row['identity_evidence_ref']),original['identity_evidence']);self.assertIsNone(row['current_displayed_body']);self.assertNotIn('body_object_key',row)
        for sample in row['owned_fields'].values():self.assertIsNotNone(pointer(window,sample['source_ref']))
        self.assertEqual(out['source_frame']['sha256'],hashlib.sha256(line).hexdigest());self.assertEqual(len(out['forward_owner_projections']),2)
        self.assertNotIn('guard_ids',encode(out).decode())

    def test_missing_primary_and_transition_have_no_support_or_historical_fill(self):
        windows=roster_fixture(self.root);first=with_forward(windows[0],support=True);p=CompactLiveRoster();p.consume(raw(first))
        later=copy.deepcopy(windows[1]);later['forward_owner_sources']=copy.deepcopy(first['forward_owner_sources']);later['forward_owner_projections']={}
        row=copy.deepcopy(first['forward_owners'][0]);row.update(status='unknown',reason='missing_frame_in_window',projection_ref=None,relation_index=None)
        later['forward_owners']=[row];out=p.consume(raw(later));self.assertIsNone(out['forward_owners'][0]['health_candidate']['value']);self.assertEqual(out['forward_owners'][0]['owned_fields'],{})
        event=transition(later);out=p.consume(raw(event));self.assertEqual(len(out['forward_owners']),1)
        self.assertIsNone(out['forward_owners'][0]['position_candidate']['value']);self.assertIsNone(out['forward_owners'][0]['controller_hero_asset_label_candidate']['value'])
        self.assertEqual(out['forward_owners'][0]['controller_object_key'],row['controller_object_key']);self.assertIsNone(out['forward_owners'][0]['projection_ref'])

    def test_forged_roster_sources_refs_epochs_and_time_rejected(self):
        window=with_forward(roster_fixture(self.root)[0],support=True)
        mutations={
            'admission_contract':lambda w:w['forward_owner_projections']['p1']['source_admission'].update(contract_sha256='12'*32),
            'profile':lambda w:w['forward_owner_projections']['p1']['projection'].update(profile_sha256='13'*32),
            'source_time':lambda w:w['forward_owner_projections']['p1']['source_timing'].update(end_ticks=0),
            'file_hash_scope':lambda w:w['forward_owner_projections']['p1'].update(semantic_hash_scope='source_file'),
            'gap':lambda w:w['forward_owner_projections']['p1']['source_gap'].update(skipped_slots=1),
            'index':lambda w:w['forward_owners'][0].update(relation_index=99),
            'support_ref':lambda w:w['forward_owners'][0].update(projection_ref='/forward_owner_projections/p2/projection'),
            'nonprimary_owner':lambda w:w['forward_owners'][0].update(primary_source_id='p2'),
            'configured_owner':lambda w:w['forward_owners'][0].update(forward_owner_object_key='owner:'+'14'*32),
            'frame_owner':lambda w:w['forward_owner_projections']['p1']['projection']['relations'][0].update(forward_owner_object_key='owner:'+'15'*32),
            'missing_binding':lambda w:w.update(forward_owners=[]),
            'hero_label':lambda w:w['forward_owner_projections']['p1']['projection']['relations'][0].update(controller_hero_asset_label_candidate='Forged'),
        }
        for name,mutation in mutations.items():
            with self.subTest(name=name):
                bad=copy.deepcopy(window);mutation(bad)
                with self.assertRaises(ValueError):CompactLiveRoster().consume(raw(bad))
        p=CompactLiveRoster();p.consume(raw(window));later=with_forward(roster_fixture(self.root)[1],support=True)
        later['forward_owner_sources']['p1']['contract_sha256']='16'*32
        with self.assertRaises(ValueError):p.consume(raw(later))

    def test_unknown_duplicate_bindings_are_labels_and_not_observations(self):
        window=with_forward(roster_fixture(self.root)[0]);entry=window['forward_owner_projections']['p1'];frame=dict(forward_owner_projection=entry['projection'])
        unknown(frame,reason='duplicate_controller_or_owner');row=entry['projection']['relations'][0]
        row['controller_object_key']=window['forward_owners'][0]['controller_object_key']
        second=copy.deepcopy(row);second.update(binding_id='forward1',owned_field_prefix='controller_0001_forward_0000_');entry['projection']['relations'].append(second)
        binding=copy.deepcopy(window['forward_owner_sources']['p1']['bindings'][0]);binding.update(binding_id='forward1',owned_field_prefix='controller_0001_forward_0000_',
            identity_fields=['controller_0001_handle_candidate_i32','controller_0001_manager_key_candidate_i32','controller_0001_reference_candidate_i32',
                'controller_0001_forward_0000_handle_candidate_i32','controller_0001_forward_0000_manager_key_candidate_i32'])
        window['forward_owner_sources']['p1']['bindings'].append(binding);entry['source_admission']=copy.deepcopy(window['forward_owner_sources']['p1'])
        original=window['forward_owners'][0];original.update(status='unknown',reason='duplicate_controller_or_owner',projection_ref=None,relation_index=None)
        second=copy.deepcopy(original);second.update(binding_id='forward1',owned_field_prefix=binding['owned_field_prefix']);window['forward_owners'].append(second)
        out=CompactLiveRoster().consume(raw(window));self.assertEqual(len(out['forward_owners']),2)
        self.assertTrue(all(r['status']=='unknown'and r['health_candidate']['value']is None for r in out['forward_owners']))


if __name__=='__main__':unittest.main()
