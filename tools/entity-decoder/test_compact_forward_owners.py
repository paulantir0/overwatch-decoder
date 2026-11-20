"""Forward owners stay private non-body observations across gaps and epochs."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from compact_live_entities import CompactLiveEntities, encode
from test_compact_live_entities import fixture, new_epoch, pointer, raw


def attach(frame, *, owner='owner:'+'d4'*32, label='Controller Fixture'):
    row=frame['relations'][0];timing={k:frame['timing'][k]for k in ('sequence','start_ticks','end_ticks','monotonic_frequency')}
    acq=frame['source_artifacts']['acquisition'];source=dict(recipe_sha256=acq['recipe_sha256'],evidence_sha256=acq['evidence_sha256'],acquisition_manifest_sha256=acq['manifest_sha256'])
    start=timing['start_ticks']+1;end=start+1;prefix='controller_0000_forward_0000_';guard_ids=[0,1,2,3,4]
    names=['controller_0000_handle_candidate_i32','controller_0000_manager_key_candidate_i32',
        'controller_0000_part51_0000_forward_key_candidate_i32',prefix+'handle_candidate_i32',prefix+'manager_key_candidate_i32']
    words=[dict(field=n,value=v,read_start_ticks=start,read_end_ticks=end,guard_ids=[i])for i,(n,v)in enumerate(zip(names,[101,102,204,203,204]))]
    def sample(kind,value):return dict(status='observed',type=kind,value=value,reason=None,read_start_ticks=start,read_end_ticks=end,guard_ids=guard_ids.copy())
    owned={names[3]:sample('i32',203),names[4]:sample('i32',204),prefix+'position_candidate':sample('f32x3',[1.5,2.5,3.5]),prefix+'pool_0000_direct_candidate':sample('f32',175.25)}
    # Identity evidence carries each field's exact complete effective guard list.
    for w in words:w['guard_ids']=guard_ids.copy()
    position=dict(owned[prefix+'position_candidate'],field=prefix+'position_candidate',source='process_memory',
        profile_sha256=frame['profile_sha256'],build_sha256=frame['target']['executable_sha256'],forward_owner_object_key=owner,
        validation_status='guarded_forward_owned_field_research',current_displayed_body=None,public_state_eligible=False,visibility='unknown')
    contract='ee'*32;template='dd'*32;catalog='cc'*32
    health=dict(schema='overwatch-decoder.forward-owner-pool-sum/1',status='candidate',source='process_memory',forward_owner_object_key=owner,
        controller_object_key=row['controller_object_key'],owned_field_prefix=prefix,binding_id='forward0',current_displayed_body=None,
        forward_contract_sha256=contract,source_evidence=source,identity_evidence=copy.deepcopy(words),association_kind='native_forward_reference',privacy='private',
        raw_sum=175.25,display_ceiling_candidate=176,contributions=[dict(field=prefix+'pool_0000_direct_candidate',pool_index=0,value=175.25,read_start_ticks=start,read_end_ticks=end)],
        occupied_pool_count=1,supplied_layout_slots=48,complete_supplied_membership_guarding=True,maximum_health=None,pool_roles=None,
        read_start_ticks=start,read_end_ticks=end,profile_sha256=frame['profile_sha256'],build_sha256=frame['target']['executable_sha256'],
        acquisition_evidence_sha256=acq['evidence_sha256'],membership_contract_sha256='bb'*32,atomic=False,continuity_across_gaps=False,public_state_eligible=False,visibility='unknown')
    hero=dict(mapping=dict(label=label,resource_guid='0x02E000000000007A',build_sha256=frame['target']['executable_sha256'],locale='enUS',
        asset_report_sha256='aa'*32,asset_decoded_sha256='99'*32,asset_build={'version':'fixture'},mapping_scope='caller_build_scoped_typed_asset',
        validation_status='typed_asset_resource_match',runtime_ui_validated=False,public_state_eligible=False),
        fields=[dict(field='controller_0000_part83_0000_hero_resource_'+half+'_candidate_i32',value=v,read_start_ticks=start,read_end_ticks=end)for half,v in [('low',0x7A),('high',0x02E00000)]],
        controller_object_key=row['controller_object_key'],binding_scope='controller_only',catalog_sha256=catalog,profile_sha256=frame['profile_sha256'],
        build_sha256=frame['target']['executable_sha256'],frame_timing=timing,source_artifacts=copy.deepcopy(frame['source_artifacts']),
        runtime_ui_validated=False,current_displayed_body=None,public_state_eligible=False,visibility='unknown')
    forward=dict(binding_id='forward0',owned_field_prefix=prefix,controller_object_key=row['controller_object_key'],forward_owner_object_key=owner,
        relation_status='observed',reason=None,identity_evidence=words,owned_fields=owned,current_displayed_body=None,position_candidate=position,health_candidate=health,
        controller_hero_asset_label_candidate=label,controller_hero_asset_label_evidence=hero,controller_hero_asset_label_reason=None)
    frame['forward_owner_projection']=dict(schema='overwatch-decoder.guarded-forward-owner-relations/1',profile_sha256=frame['profile_sha256'],target=copy.deepcopy(frame['target']),
        source='process_memory',contract_sha256=contract,binding_template_sha256=template,source_evidence=source,timing=timing,relations=[forward],
        association_kind='native_forward_reference',atomic=False,continuity_across_gaps=False,previous_values_carried=False,public_state_eligible=False,visibility='unknown',durability_verified=False,
        source_artifacts=copy.deepcopy(frame['source_artifacts']),controller_hero_output_enabled=True,controller_hero_asset_catalog_sha256=catalog)
    return frame


def unknown(frame,reason='scheduled_gap'):
    row=frame['forward_owner_projection']['relations'][0]
    row.update(controller_object_key=None,forward_owner_object_key=None,relation_status='unknown',reason=reason,
        identity_evidence=[],owned_fields={},position_candidate=None,health_candidate=None,
        controller_hero_asset_label_candidate=None,controller_hero_asset_label_evidence=None,controller_hero_asset_label_reason=reason)
    return frame


class CompactForwardOwnerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)

    def test_default_bytes_and_normal_players_are_unchanged(self):
        frame=fixture(self.root)[0];baseline=CompactLiveEntities().consume(raw(frame))
        self.assertNotIn('forward_owners',baseline)
        attached=attach(copy.deepcopy(frame));out=CompactLiveEntities().consume(raw(attached))
        for key in ['forward_owners','forward_owner_projection']:out.pop(key)
        out['source_frame']['sha256']=baseline['source_frame']['sha256']
        self.assertEqual(encode(out),encode(baseline))

    def test_exact_separate_owner_values_and_resolvable_evidence(self):
        frame=attach(fixture(self.root)[0]);line=raw(frame);out=CompactLiveEntities().consume(line);row=out['forward_owners'][0];original=frame['forward_owner_projection']['relations'][0]
        self.assertEqual(out['source_frame']['sha256'],hashlib.sha256(line).hexdigest());self.assertEqual(row['forward_owner_object_key'],original['forward_owner_object_key'])
        self.assertNotIn('body_object_key',row);self.assertIsNone(row['current_displayed_body']);self.assertEqual(row['association_kind'],'native_forward_reference')
        self.assertEqual(row['position_candidate']['value'],original['position_candidate']['value'])
        self.assertEqual(row['health_candidate']['value'],{'raw_sum':175.25,'display_ceiling_candidate':176})
        self.assertEqual(row['controller_hero_asset_label_candidate']['value'],'Controller Fixture')
        self.assertEqual(row['controller_hero_asset_label_candidate']['binding_scope'],'controller_only')
        self.assertFalse(row['controller_hero_asset_label_candidate']['runtime_ui_validated']);self.assertFalse(out['public_state_eligible'])
        self.assertEqual(pointer(frame,row['identity_evidence_ref']),original['identity_evidence'])
        for key in ['position_candidate','health_candidate','controller_hero_asset_label_candidate']:
            self.assertIsNotNone(pointer(frame,row[key]['evidence_ref']));self.assertIsNone(row[key]['current_displayed_body'])
        for name,sample in row['owned_fields'].items():self.assertEqual(sample['value'],pointer(frame,sample['source_ref'])['value'])
        self.assertNotIn('guard_ids',encode(out).decode())

    def test_forged_envelope_identity_samples_health_and_hero_rejected(self):
        frame=attach(fixture(self.root)[0])
        mutations={
            'profile':lambda p:p.update(profile_sha256='f1'*32),
            'target':lambda p:p['target'].update(pid=999),
            'time':lambda p:p['timing'].update(sequence=999),
            'source':lambda p:p['source_evidence'].update(evidence_sha256='12'*32),
            'artifact':lambda p:p['source_artifacts'].update(live_event_sha256='13'*32),
            'reference':lambda p:p['relations'][0]['identity_evidence'][2].update(value=999),
            'span':lambda p:p['relations'][0]['identity_evidence'][0].update(read_end_ticks=99999),
            'displayed_body':lambda p:p['relations'][0].update(current_displayed_body='body:'+'14'*32),
            'raw_guard':lambda p:p['relations'][0]['owned_fields']['controller_0000_forward_0000_position_candidate'].update(guard_ids=[]),
            'raw_sample':lambda p:p['relations'][0]['owned_fields']['controller_0000_forward_0000_position_candidate'].update(value=[9,9,9]),
            'health_owner':lambda p:p['relations'][0]['health_candidate'].update(forward_owner_object_key='owner:'+'15'*32),
            'health_contract':lambda p:p['relations'][0]['health_candidate'].update(forward_contract_sha256='16'*32),
            'health_pool':lambda p:p['relations'][0]['health_candidate']['contributions'][0].update(value=999),
            'health_sum':lambda p:p['relations'][0]['health_candidate'].update(raw_sum=999),
            'partial_health_layout':lambda p:p['relations'][0]['health_candidate'].update(supplied_layout_slots=47),
            'hero_label':lambda p:p['relations'][0].update(controller_hero_asset_label_candidate='Forged'),
            'hero_controller':lambda p:p['relations'][0]['controller_hero_asset_label_evidence'].update(controller_object_key='controller:'+'17'*32),
            'hero_body_promotion':lambda p:p['relations'][0]['controller_hero_asset_label_evidence'].update(binding_scope='controller_and_body'),
            'hero_resource':lambda p:p['relations'][0]['controller_hero_asset_label_evidence']['fields'][0].update(value=888),
            'hero_field':lambda p:p['relations'][0]['controller_hero_asset_label_evidence']['fields'][0].update(field='another_controller_resource'),
            'hero_span':lambda p:p['relations'][0]['controller_hero_asset_label_evidence']['fields'][0].update(read_start_ticks=0),
            'hero_catalog':lambda p:p['relations'][0]['controller_hero_asset_label_evidence'].update(catalog_sha256='18'*32),
        }
        for name,mutation in mutations.items():
            with self.subTest(name=name):
                bad=copy.deepcopy(frame);mutation(bad['forward_owner_projection']);projector=CompactLiveEntities()
                with self.assertRaises(ValueError):projector.consume(raw(bad))
                with self.assertRaises(ValueError):projector.consume(raw(frame))

    def test_gaps_unknowns_and_missing_option_do_not_carry(self):
        first,second=fixture(self.root);attach(first);attach(second);second['gap_before']['skipped_slots']=1;unknown(second)
        p=CompactLiveEntities();p.consume(raw(first));out=p.consume(raw(second));row=out['forward_owners'][0]
        self.assertEqual(row['owned_fields'],{});self.assertEqual(row['relation_status'],'unknown')
        self.assertTrue(all(row[key]['value']is None for key in ['position_candidate','health_candidate','controller_hero_asset_label_candidate']))
        forged=attach(fixture(self.root)[0]);forged['gap_before']['skipped_slots']=1
        with self.assertRaises(ValueError):CompactLiveEntities().consume(raw(forged))
        stale=attach(fixture(self.root)[0]);unknown(stale);stale['forward_owner_projection']['relations'][0]['health_candidate']=first['forward_owner_projection']['relations'][0]['health_candidate']
        with self.assertRaises(ValueError):CompactLiveEntities().consume(raw(stale))
        p=CompactLiveEntities();p.consume(raw(first));second.pop('forward_owner_projection')
        with self.assertRaises(ValueError):p.consume(raw(second))

    def test_epoch_rebinds_only_with_fresh_source_and_contract_pins(self):
        first,second=fixture(self.root);attach(first);fresh=attach(new_epoch(second,first['timing']['end_ticks']),owner='owner:'+'21'*32,label='Fresh Controller')
        fresh['forward_owner_projection']['contract_sha256']='22'*32;fresh['forward_owner_projection']['relations'][0]['health_candidate']['forward_contract_sha256']='22'*32
        p=CompactLiveEntities();p.consume(raw(first));out=p.consume(raw(fresh));self.assertEqual(out['forward_owners'][0]['forward_owner_object_key'],'owner:'+'21'*32)
        stale=copy.deepcopy(fresh);stale['forward_owner_projection']=first['forward_owner_projection'];p=CompactLiveEntities();p.consume(raw(first))
        with self.assertRaises(ValueError):p.consume(raw(stale))
        second=attach(second);second['forward_owner_projection']['contract_sha256']='23'*32;p=CompactLiveEntities();p.consume(raw(first))
        with self.assertRaises(ValueError):p.consume(raw(second))

    def test_duplicate_rows_bounds_unknown_owned_fields(self):
        frame=attach(fixture(self.root)[0]);duplicate=copy.deepcopy(frame);duplicate['forward_owner_projection']['relations']*=2
        with self.assertRaises(ValueError):CompactLiveEntities().consume(raw(duplicate))
        duplicates=unknown(attach(fixture(self.root)[0]),reason='duplicate_controller_or_owner')
        unknown_row=duplicates['forward_owner_projection']['relations'][0]
        unknown_row['controller_object_key']=frame['relations'][0]['controller_object_key']
        second=copy.deepcopy(unknown_row);second.update(binding_id='forward1',owned_field_prefix='controller_0001_forward_0000_')
        duplicates['forward_owner_projection']['relations'].append(second)
        out=CompactLiveEntities().consume(raw(duplicates))
        self.assertEqual(len(out['forward_owners']),2)
        self.assertTrue(all(row['relation_status']=='unknown' for row in out['forward_owners']))
        p=CompactLiveEntities(maximum_output_bytes=1)
        with self.assertRaises(ValueError):p.consume(raw(frame))
        field=frame['forward_owner_projection']['relations'][0]['owned_fields'];field['controller_0000_forward_0000_unknown_scalar']=dict(status='unknown',type='f32',value=None,reason='guard_failed')
        out=CompactLiveEntities().consume(raw(frame));self.assertIsNone(out['forward_owners'][0]['owned_fields']['controller_0000_forward_0000_unknown_scalar']['value'])


if __name__=='__main__':unittest.main()
