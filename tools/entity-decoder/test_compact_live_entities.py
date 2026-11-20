"""Compact source parity, private candidate qualification and gap/epoch rejection."""
import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import compact_live_entities as compact
from test_aggregate_live_partitions import live_fixture


def raw(value):return json.dumps(value,separators=(',',':')).encode()+b'\n'


def fixture(root):
    _,sources=live_fixture(root)
    frames=copy.deepcopy(sources['p1'])
    for frame in frames:
        frame.update(participant_identity_validated=False,continuity_across_gaps=False,hero_catalog_sha256='ab'*32,
            session_epoch=dict(acquisition=1,session_start_sha256='12'*32,acquisition_end_sha256='23'*32,
                segment_start_sha256='34'*32,previous_epoch_last_frame_end_ticks=None,previous_values_carried=False))
        frame['recording']['continuity_across_gaps']=False
        for row in frame['relations']:
            row['position_candidate']['validation_status']='guarded_research'
            row['health_candidate'].update(status='candidate',display_ceiling_candidate=100)
            row['hero_resource_guid_candidate'].update(validation_status='matching_guarded_resource_research',public_state_eligible=False)
            row['hero_label_evidence'].update(validation_status='guarded_build_resource_label_research',catalog_sha256='ab'*32)
            row['cached_label_evidence']['validation_status']='guarded_native_cache_string_research'
            row['category_evidence']['validation_status']='guarded_live_category_roster_research'
    return frames


def pointer(value, path):
    for part in path.split('/')[1:]:
        part=part.replace('~1','/').replace('~0','~')
        value=value[int(part)]if isinstance(value,list)else value[part]
    return value


def new_epoch(frame,previous_end):
    frame=copy.deepcopy(frame);frame.update(segment=2,event_sequence=100,profile_sha256='ef'*32)
    frame['timing']['sequence']=0;frame['gap_before']['previous_end_ticks']=None
    frame['source_artifacts']['profile_sha256']=frame['profile_sha256']
    acquisition=frame['source_artifacts']['acquisition'];acquisition.update(manifest_sha256='ed'*32,evidence_sha256='dc'*32)
    frame['session_epoch'].update(acquisition=2,segment_start_sha256='45'*32,acquisition_end_sha256='56'*32,previous_epoch_last_frame_end_ticks=previous_end)
    for n,row in enumerate(frame['relations']):
        row['body_object_key']='body:'+f'{900+n:064x}'
        for key in ['position_candidate','health_candidate','hero_label_evidence','cached_label_evidence','category_evidence']:
            row[key]['profile_sha256']=frame['profile_sha256']
        row['health_candidate'].update(body_object_key=row['body_object_key'],acquisition_evidence_sha256=acquisition['evidence_sha256'])
        for key in ['cached_label_evidence','category_evidence']:row[key]['acquisition']=copy.deepcopy(acquisition)
        e=row['category_evidence'];e['mode_scope']['live_scope']['segment']=2
        e['admission'].update(segment=2,event_sequence=100,profile_sha256=frame['profile_sha256'],frame_sequence=0,
            acquisition_manifest_sha256=acquisition['manifest_sha256'],evidence_sha256=acquisition['evidence_sha256'])
    return frame


class CompactTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.frames=fixture(Path(self.temp.name))

    def test_exact_values_opaque_keys_and_resolvable_source_evidence(self):
        source=self.frames[0];line=raw(source);result=compact.CompactLiveEntities().consume(line)
        self.assertEqual(result['source_frame']['sha256'],hashlib.sha256(line).hexdigest())
        self.assertEqual(result['target']['executable_sha256'],source['target']['executable_sha256'])
        self.assertFalse(result['public_state_eligible']);self.assertEqual(result['visibility'],'unknown')
        for i,row in enumerate(result['players']):
            original=source['relations'][i]
            self.assertEqual(row['controller_object_key'],original['controller_object_key'])
            self.assertEqual(row['body_object_key'],original['body_object_key'])
            self.assertEqual(pointer(source,row['source_ref']),original)
            self.assertEqual(row['position_candidate']['value'],original['position_candidate']['value'])
            self.assertEqual(row['hero_resource_candidate']['value'],original['hero_resource_guid_candidate']['value'])
            self.assertEqual(row['hero_label_candidate']['value'],original['hero_label'])
            self.assertEqual(row['cached_label_candidate']['value'],original['cached_label_candidate'])
            self.assertEqual(row['health_candidate']['value'],{k:original['health_candidate'][k]for k in ('raw_sum','display_ceiling_candidate')})
            self.assertEqual(row['category_candidate']['value'],{k:original[k]for k in ('raw_category_candidate','team_candidate','relative_allegiance_candidate')})
            self.assertEqual(row['position_candidate']['status'],original['position_candidate']['validation_status'])
            for key,value in row.items():
                if isinstance(value,dict)and value.get('evidence_ref'):self.assertIsNotNone(pointer(source,value['evidence_ref']))
            self.assertNotIn('name',row)
        self.assertNotIn('guard_ids',json.dumps(result))

    def test_gap_keeps_only_fresh_source_values_and_nulls_without_fill(self):
        first,second=self.frames;second['gap_before']['skipped_slots']=1
        for row in second['relations']:
            for field in ['health_candidate','hero_label','cached_label_candidate','raw_category_candidate','team_candidate','relative_allegiance_candidate']:row[field]=None
            for reason in ['hero_label_reason','cached_label_reason','category_reason']:row[reason]='gap_before_frame'
        p=compact.CompactLiveEntities();p.consume(raw(first));out=p.consume(raw(second))
        self.assertEqual(out['gap_before']['skipped_slots'],1)
        for row in out['players']:
            self.assertEqual(row['position_candidate']['status'],'guarded_research')
            self.assertEqual(row['health_candidate']['status'],'unknown');self.assertIsNone(row['health_candidate']['value'])
            self.assertEqual(row['cached_label_candidate']['reason'],'gap_before_frame')
            self.assertIsNone(row['hero_label_candidate']['value']);self.assertIsNone(row['category_candidate']['value'])

    def test_unknown_relation_preserves_reason_and_never_fills_identifiers(self):
        f=self.frames[0]
        for row in f['relations']:
            row.update(relation_status='unknown',reason='guard_mismatch',controller_object_key=None,body_object_key=None)
            for field in ['position_candidate','health_candidate','hero_resource_guid_candidate','hero_label','cached_label_candidate','raw_category_candidate','team_candidate','relative_allegiance_candidate']:row[field]=None
        out=compact.CompactLiveEntities().consume(raw(f))
        for row in out['players']:
            self.assertIsNone(row['controller_object_key']);self.assertIsNone(row['body_object_key'])
            self.assertEqual(row['position_candidate']['reason'],'guard_mismatch')
            self.assertEqual(row['relation_status'],'unknown')

    def test_fresh_epoch_retains_controller_and_rebinds_body_without_old_values(self):
        first,second=self.frames;second=new_epoch(second,first['timing']['end_ticks'])
        p=compact.CompactLiveEntities();a=p.consume(raw(first));b=p.consume(raw(second))
        self.assertEqual(a['players'][0]['controller_object_key'],b['players'][0]['controller_object_key'])
        self.assertNotEqual(a['players'][0]['body_object_key'],b['players'][0]['body_object_key'])
        self.assertEqual(b['segment'],2);self.assertEqual(b['event_sequence'],100)
        self.assertFalse(b['session_epoch']['previous_values_carried'])

    def test_missing_boundary_stale_profile_and_previous_values_reject(self):
        for case in ['body','profile','epoch','acquisition','order','carry']:
            with self.subTest(case=case):
                first,second=copy.deepcopy(self.frames)
                if case=='body':second['relations'][0]['body_object_key']='body:'+'ff'*32
                elif case=='profile':second['profile_sha256']='00'*32
                elif case=='epoch':second=new_epoch(second,first['timing']['end_ticks']);second['session_epoch']=None
                elif case=='acquisition':second['source_artifacts']['acquisition']['evidence_sha256']='00'*32
                elif case=='order':second['event_sequence']=first['event_sequence']
                else:second['gap_before']['previous_values_carried']=True
                p=compact.CompactLiveEntities();p.consume(raw(first))
                with self.assertRaises(ValueError):p.consume(raw(second))
                with self.assertRaisesRegex(ValueError,'failed'):p.consume(raw(first))

    def test_wrong_nested_body_build_time_category_scope_and_qualification_reject(self):
        for case in ['body','build','read','hero','category','public','identity','nonfinite','duplicate_pool']:
            with self.subTest(case=case):
                f=copy.deepcopy(self.frames[0]);row=f['relations'][0]
                if case=='body':row['health_candidate']['body_object_key']='body:'+'ee'*32
                elif case=='build':row['position_candidate']['build_sha256']='cc'*32
                elif case=='read':row['health_candidate']['read_end_ticks']=99999
                elif case=='hero':row['hero_label_evidence']['mapping']['label']='wrong'
                elif case=='category':row['category_evidence']['admission']['segment']=99
                elif case=='public':f['public_state_eligible']=True
                elif case=='identity':f['participant_identity_validated']=True
                elif case=='duplicate_pool':
                    row['health_candidate']['contributions']*=2
                    row['health_candidate'].update(raw_sum=200,display_ceiling_candidate=200)
                else:row['position_candidate']['value'][0]=float('nan')
                with self.assertRaises(ValueError):compact.CompactLiveEntities().consume(raw(f))

    def test_cache_string_never_fills_missing_hero_or_participant_name(self):
        frame=copy.deepcopy(self.frames[0])
        for row in frame['relations']:
            row['hero_label']=None;row.pop('hero_label_evidence')
            row['cached_label_candidate']='Fixture Hero'
        result=compact.CompactLiveEntities().consume(raw(frame))
        for row in result['players']:
            self.assertEqual(row['cached_label_candidate']['value'],'Fixture Hero')
            self.assertIsNone(row['hero_label_candidate']['value'])
            self.assertNotIn('name',row)

    def test_unknown_body_keeps_only_source_controller_id(self):
        frame=copy.deepcopy(self.frames[0])
        for row in frame['relations']:
            row.update(relation_status='unknown',reason='body_missing',body_object_key=None)
            for key in ['position_candidate','health_candidate','hero_resource_guid_candidate','hero_label','cached_label_candidate','raw_category_candidate','team_candidate','relative_allegiance_candidate']:row[key]=None
        result=compact.CompactLiveEntities().consume(raw(frame))
        for source,row in zip(frame['relations'],result['players']):
            self.assertEqual(row['controller_object_key'],source['controller_object_key'])
            self.assertIsNone(row['body_object_key']);self.assertEqual(row['reason'],'body_missing')

    def test_frame_output_total_limits_and_duplicate_json_fail_without_partial_line(self):
        for kwargs in [dict(maximum_input_bytes=1),dict(maximum_output_bytes=1)]:
            output=io.BytesIO();p=compact.CompactLiveEntities(**kwargs)
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):compact.stream(p,io.BytesIO(raw(self.frames[0])),output)
            self.assertEqual(output.getvalue(),b'')
        with patch.object(compact,'MAX_OUTPUT_LINE',1):
            with self.assertRaises(ValueError):compact.CompactLiveEntities().consume(raw(self.frames[0]))
        p=compact.CompactLiveEntities(maximum_frames=1);p.consume(raw(self.frames[0]))
        with self.assertRaises(ValueError):p.consume(raw(self.frames[1]))
        with self.assertRaises(ValueError):compact.CompactLiveEntities().consume(b'{"schema":1,"schema":2}\n')
        with self.assertRaises(ValueError):compact.CompactLiveEntities().consume(b'x'*(compact.MAX_LINE+1))

    def test_zero_values_and_unicode_are_preserved_as_candidates(self):
        frame=copy.deepcopy(self.frames[0]);row=frame['relations'][0]
        row['cached_label_candidate']='Ålex Ω'
        row['position_candidate']['value']=[0.0,-0.0,0]
        row['health_candidate'].update(raw_sum=0,display_ceiling_candidate=0)
        row['health_candidate']['contributions'][0]['value']=0
        result=compact.CompactLiveEntities().consume(raw(frame));projected=result['players'][0]
        self.assertEqual(projected['cached_label_candidate']['value'],'Ålex Ω')
        self.assertEqual(projected['health_candidate']['value']['raw_sum'],0)
        self.assertEqual(projected['health_candidate']['status'],'candidate')
        self.assertIn(b'-0.0',compact.encode(result))
        self.assertTrue(result['values_are_candidates'])

    def test_unrequested_names_and_extra_metadata_are_not_copied(self):
        frame=copy.deepcopy(self.frames[0])
        frame['relations'][0].update(name='private-full-name',private_battletag='private-discriminator')
        frame['session_epoch']['unexpected_name']='private-epoch-name'
        frame['timing']['unexpected_name']='private-timing-name'
        frame['gap_before']['unexpected_name']='private-gap-name'
        result=compact.CompactLiveEntities().consume(raw(frame))
        encoded=compact.encode(result)
        self.assertNotIn(b'private-full-name',encoded)
        self.assertNotIn(b'private-discriminator',encoded)
        self.assertNotIn(b'unexpected_name',encoded)
        self.assertFalse(result['participant_identity_validated'])

    def test_cli_stream_is_bounded_private_and_reports_exact_hashes(self):
        data=b''.join(raw(f)for f in self.frames)
        run=subprocess.run([sys.executable,str(Path(compact.__file__))],input=data,capture_output=True)
        self.assertEqual(run.returncode,0,run.stderr)
        result=json.loads(run.stderr);self.assertEqual(result['frames'],2)
        self.assertEqual(result['input_sha256'],hashlib.sha256(data).hexdigest())
        self.assertEqual(result['output_sha256'],hashlib.sha256(run.stdout).hexdigest())
        self.assertFalse(result['public_state_eligible']);self.assertEqual(len(run.stdout.splitlines()),2)


if __name__=='__main__':unittest.main()
