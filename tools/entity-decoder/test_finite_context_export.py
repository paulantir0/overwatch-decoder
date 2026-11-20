"""Finite native-format fixtures; never synthesize live transport admission."""
import copy
import gzip
import json
from pathlib import Path
import tempfile
import io
import sys
import unittest
from unittest.mock import patch

import export_relations as exporter
from aggregate_partitions import aggregate, canonical
from context_projection_validation import (context_source_from_frame, validate_context_frame,
    validate_context_entry, compact_context, compact_actor_context)
from finite_context import FiniteContextProjection
from test_context_groups import group_fixture
from test_categories import raw, sha


def fixture(root):
    profile, frame, category_raw, context_raw, _, artifacts, _, _ = group_fixture()
    category, context = json.loads(category_raw), json.loads(context_raw)
    manifest = json.loads(artifacts[context['acquisition_manifest_sha256']])
    manifest['stages_completed'] = 0
    manifest_raw = raw(manifest)
    artifacts[sha(manifest_raw)] = manifest_raw
    for contract in (category, context):contract['acquisition_manifest_sha256'] = sha(manifest_raw)
    recording, acquisition = root/'recording', root/'acquisition'
    recording.mkdir(); acquisition.mkdir()
    profile_raw = raw(profile)
    for name, data in {'profile.json':profile_raw, 'manifest.json':manifest_raw,
        'recipe.json':artifacts[context['source']['recipe_sha256']],
        'evidence.jsonl':artifacts[context['source']['evidence_sha256']]}.items():
        (acquisition/name).write_bytes(data)
    frame.update(scheduled_slot=0, scheduled_ticks=0, requested_interval_ms=100,
                 skipped_intervals_before=0, skipped_intervals_total=0)
    data = canonical(frame)+b'\n'
    compressed = gzip.compress(data, mtime=0)
    entry = dict(schema='overwatch-decoder.field-recording-chunk/1', sequence=0, offset=0, compressed_bytes=len(compressed),
                 json_bytes=len(data), first_line=0, lines=1, compressed_sha256=sha(compressed), json_sha256=sha(data))
    index = canonical(entry)+b'\n'
    for name, value in {'profile.json':profile_raw,'manifest.json':raw(dict(schema='overwatch-decoder.field-recording/1',
        target=profile['target'],profile_sha256=sha(profile_raw))), 'samples.jsonl.gz':compressed,'chunks.jsonl':index}.items():
        (recording/name).write_bytes(value)
    verified = dict(valid=True,complete=True,status='verified_complete',verified_chunks=1,
        verified_compressed_bytes=len(compressed),verified_lines=1,frames=1,profile_sha256=sha(profile_raw),
        samples_prefix_sha256=sha(compressed),index_prefix_sha256=sha(index),json_prefix_sha256=sha(data))
    paths = {}
    for pin, value in artifacts.items():
        (root/pin).write_bytes(value);paths[pin]=pin
    (root/'artifacts.json').write_bytes(raw(paths))
    (root/'raw.json').write_bytes(raw(category));(root/'context.json').write_bytes(raw(context))
    options = dict(raw_category_contract=root/'raw.json',context_controller_contract=root/'context.json',
                   context_projection_artifacts=root/'artifacts.json')
    return recording, acquisition, verified, frame, options


class FiniteContextExportTests(unittest.TestCase):
    def export(self, root, options=None):
        recording, acquisition, verified, frame, inputs = fixture(root)
        with patch.object(exporter,'native_verify',return_value=verified):
            report=exporter.export_recording(recording,acquisition,root/'entities.jsonl',['fixture'],**(inputs if options is None else options))
        result=json.loads((root/'entities.jsonl').read_bytes())
        return result, report, frame, inputs

    def test_real_finite_export_aggregate_and_compact_references(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);result,report,frame,_=self.export(root)
            top=result['context_group_projection']
            self.assertEqual(top['schema'],'overwatch-decoder.finite-context-group-projection/1')
            self.assertNotIn('session_id',top);self.assertNotIn('event_sequence',top)
            self.assertEqual([r['context_group_candidate']['raw_category']for r in result['relations']],[0,0,1])
            self.assertTrue(all(r['context_group_candidate']['global_group']is None for r in result['relations']))
            pins=context_source_from_frame(result)
            validate_context_frame(result,pins,target=result['target'])
            artifacts=result['source_artifacts']
            objects=[{k:r[k]for k in ('controller_object_key','body_object_key')}for r in result['relations']]
            source=dict(source_id='p1',path=str(root/'entities.jsonl'),sha256=report['output_sha256'],
                profile_sha256=result['profile_sha256'],recording_manifest_sha256=artifacts['manifest_sha256'],
                acquisition_manifest_sha256=artifacts['acquisition']['manifest_sha256'],objects=objects,
                acquisition=artifacts['acquisition'],context_projection=pins['context_projection'])
            manifest=dict(schema='overwatch-decoder.partition-research-manifest/1',epoch_id='finite-fixture',clock_domain_id='fixture-qpc',
                target=result['target'],monotonic_frequency=1000,window_ticks=200,maximum_skew_ticks=200,
                maximum_origin_offset_ticks=0,roster=[dict(o,primary_source_id='p1')for o in objects],sources=[source])
            (root/'manifest.json').write_bytes(raw(manifest));aggregate(root/'manifest.json',root/'roster.jsonl')
            window=json.loads((root/'roster.jsonl').read_bytes())
            entry=window['context_group_projections']['p1'];projected=validate_context_entry(entry,result['target'])
            self.assertEqual(projected,top)
            self.assertEqual(compact_context(projected,'/context_group_projections/p1/projection')['status'],'observed')
            for row in window['relations']:
                original=row['authoritative_observation']['relation']
                candidate=compact_actor_context(original,projected,'/relations/0/authoritative_observation/relation','/context_group_projections/p1/projection')
                self.assertEqual(candidate['value'],original['context_group_candidate'])

    def test_no_options_remain_exact_and_optional_inputs_all_required(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);result,_,frame,_=self.export(root,options={})
            self.assertNotIn('raw_context_output_enabled',result)
            source=result['source_artifacts'];recording=result['recording'];gap=result['gap_before']
            projector=exporter.GuardedRelations((root/'recording/profile.json').read_bytes())
            self.assertEqual(result,exporter.project_frame(projector,frame,source,recording,gap))
        for supplied in ('raw_category_contract','context_controller_contract','context_projection_artifacts'):
            with tempfile.TemporaryDirectory()as temp:
                root=Path(temp);rec,acq,verified,_,options=fixture(root)
                with patch.object(exporter,'native_verify',return_value=verified),self.assertRaisesRegex(ValueError,'inputs_required_together'):
                    exporter.export_recording(rec,acq,root/'bad.jsonl',['fixture'],**{supplied:options[supplied]})
                self.assertFalse((root/'bad.jsonl').exists())

    def test_cli_forwards_finite_options_without_live_admission(self):
        arguments=['export_relations.py','--recording','recording','--acquisition','acquisition',
            '--output','output','--observer','observer','--raw-category-contract','raw.json',
            '--context-controller-contract','context.json','--context-projection-artifacts','artifacts.json']
        with patch.object(sys,'argv',arguments),patch.object(exporter,'export_recording',return_value={})as run,patch('sys.stdout',new_callable=io.StringIO):
            self.assertEqual(exporter.main(),0)
        self.assertEqual(run.call_args.kwargs['raw_category_contract'],Path('raw.json'))
        self.assertEqual(run.call_args.kwargs['context_controller_contract'],Path('context.json'))
        self.assertEqual(run.call_args.kwargs['context_projection_artifacts'],Path('artifacts.json'))
        self.assertNotIn('context_projection_admission',run.call_args.kwargs)

    def test_gap_and_bad_selector_do_not_carry_context(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);result,_,frame,options=self.export(root)
            d=FiniteContextProjection((root/'recording/profile.json').read_bytes(),options['raw_category_contract'].read_bytes(),
                options['context_controller_contract'].read_bytes(),exporter.load_local_artifacts(options['context_projection_artifacts'],'fixture'))
            for gap in (True,False):
                current=copy.deepcopy(result);f=copy.deepcopy(frame)
                if gap:current['gap_before']['skipped_slots']=1
                else:f['fields']['context_selector_i32']['status']='unknown'
                d.compose(current,f)
                self.assertEqual(current['context_group_projection']['context_projection']['status'],'unknown')
                for row in current['relations']:
                    if gap:self.assertIsNone(row['context_group_candidate'])
                    else:self.assertIsNone(row['context_group_candidate']['category_matches_context'])

    def test_forged_source_frame_and_read_evidence_rejected(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);result,_,_,options=self.export(root)
            source=context_source_from_frame(result)
            mutations=[lambda x:x['context_group_projection']['admission']['source_acquisition'].update(evidence_sha256='00'*32),
                lambda x:x['context_group_projection']['context_projection']['timing'].update(sequence=99),
                lambda x:x['context_group_projection']['raw_category_projection']['source_evidence'].update(recipe_sha256='00'*32),
                lambda x:x['relations'][0]['context_group_evidence']['actor_fields'][0].update(read_end_ticks=100000),
                lambda x:x['relations'][0]['context_group_candidate'].update(raw_category=7)]
            for mutate in mutations:
                bad=copy.deepcopy(result);mutate(bad)
                with self.assertRaises(ValueError):validate_context_frame(bad,source,target=result['target'])
            category=json.loads(options['raw_category_contract'].read_bytes());category['source']['evidence_sha256']='00'*32
            options['raw_category_contract'].write_bytes(raw(category))
            with self.assertRaises(ValueError):
                FiniteContextProjection((root/'recording/profile.json').read_bytes(),options['raw_category_contract'].read_bytes(),
                    options['context_controller_contract'].read_bytes(),exporter.load_local_artifacts(options['context_projection_artifacts'],'fixture'))


if __name__=='__main__':unittest.main()
