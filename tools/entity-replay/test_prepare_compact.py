import importlib.util
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('compact',Path(__file__).with_name('prepare_compact.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class CompactTests(unittest.TestCase):
    def test_incoming_observed_and_unknowns_remain_distinct_from_outgoing_damage(self):
        import sys
        sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tests'))
        from incoming_observation_fixture import incoming_fixture
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'source';output=Path(d)/'out'
            rows=[self.row(50),incoming_fixture(),incoming_fixture('unknown'),incoming_fixture('unknown',untimed=True)]
            source.write_text(''.join(json.dumps(r)+'\n'for r in rows));summary=module.prepare([source],output)
            self.assertEqual(summary['damage_feedback_candidates'],0)
            self.assertEqual(summary['incoming_source_observations'],1);self.assertEqual(summary['incoming_source_unknowns'],2)
            replay=json.loads(output.read_bytes());self.assertEqual(len(replay['events']),2)
            self.assertEqual(replay['events'][0]['t'],.061)
            self.assertEqual(replay['end_seconds'],.061)  # Later source observations must remain seekable.
            self.assertEqual(replay['events'][0]['source_actor']['position_observations'][0]['value'],[1,2,3])
            self.assertEqual(len(replay['untimed_events']),1);self.assertEqual(summary['untimed_source_observations'],1)
            self.assertIsNone(replay['untimed_events'][0]['t']);self.assertIsNone(replay['untimed_events'][0]['timestamp'])
            self.assertIsNone(replay['untimed_events'][0]['source_actor']);self.assertEqual(replay['untimed_events'][0]['kind'],'incoming_source')

    def row(self,tick,worker='a',entities=None):
        return dict(schema='overwatch-decoder.private.selected-compact/1',source='process_memory',scope='configured_controller_window',
                    timestamp=dict(start_ticks=tick-1,end_ticks=tick,monotonic_frequency=1000),source_worker=worker,
                    session_id='fixture',segment=1,entities=entities if entities is not None else [dict(entity_id=worker,is_local=worker=='a',
                    position=[tick,2,3],position_validation='guarded',hero='Fixture',hero_validation='fixture_only',health=50,health_validation='fixture_only')])
    def test_partition_hold_unknown_clear_and_expiry(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'source';o=Path(d)/'out'
            rows=[self.row(100),self.row(110,'b'),self.row(120,'a',[]),self.row(200,'b')]
            p.write_text(''.join(json.dumps(r)+'\n' for r in rows));module.prepare([p],o)
            replay=json.loads(o.read_bytes());self.assertEqual([len(f['objects']) for f in replay['frames']],[1,2,1,1])
            self.assertEqual(replay['field_samples'][replay['frames'][1]['field_refs'][0]]['source_timestamp']['end_ticks'],'100')
            self.assertFalse(replay['whole_match_claim']);self.assertEqual(replay['events'],[])
            script="const m=require(process.argv[1]); const fs=require('fs');m.create(JSON.parse(fs.readFileSync(process.argv[2])));"
            subprocess.run(['node','-e',script,str(Path(__file__).with_name('model.js').resolve()),str(o)],check=True)
    def test_raw_rotations_are_fresh_only_and_unknown_does_not_hide_position(self):
        import sys,copy
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'entity-decoder'))
        from test_selected_quaternion import fixture,project
        from run_selected_live import compact
        pb,c,f,k=fixture();result=project(pb,c,f,k)
        result.update(session_id='fixture',segment=1,event_sequence=1)
        first=compact(result,'ab'*32);first['source_worker']='a'
        second=self.row(first['timestamp']['end_ticks']+1,'b')
        third=copy.deepcopy(first);third['timestamp']={**first['timestamp'],'start_ticks':first['timestamp']['end_ticks']+2,'end_ticks':first['timestamp']['end_ticks']+3}
        third['entities'][0]['raw_quaternion_candidate']=None
        third['entities'][0]['raw_quaternion_candidate_validation']='unknown'
        # Same clock for distinct fixture workers.
        second['timestamp']['monotonic_frequency']=first['timestamp']['monotonic_frequency']
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'source';o=Path(d)/'out'
            p.write_text(''.join(json.dumps(r)+'\n' for r in (first,second,third)))
            module.prepare([p],o);replay=json.loads(o.read_bytes())
            self.assertEqual([len(x['rotations']) for x in replay['frames']],[1,0,0])
            self.assertTrue(replay['frames'][2]['objects'])
            qread=first['entities'][0]['field_evidence']['raw_quaternion_candidate']['reads'][0]
            self.assertEqual(replay['frames'][0]['rotation_reads'][0][1:],[str(qread['read_start_ticks']),str(qread['read_end_ticks'])])
            self.assertEqual(replay['field_samples'][0]['raw_quaternion_candidate']['validation_status'],'raw_orientation_candidate')
            script="const m=require(process.argv[1]);const fs=require('fs');m.create(JSON.parse(fs.readFileSync(process.argv[2])));"
            subprocess.run(['node','-e',script,str(Path(__file__).with_name('model.js').resolve()),str(o)],check=True)

    def test_atomic_failure_keeps_old_output(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'source';o=Path(d)/'out';o.write_text('old');p.write_text(json.dumps(self.row(100))+'\n')
            with self.assertRaises(ValueError):module.prepare([p],o,maximum_bytes=2)
            self.assertEqual(o.read_text(),'old')
    def test_health_loss_does_not_create_damage(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'source';o=Path(d)/'out';rows=[self.row(100),self.row(120)]
            rows[1]['entities'][0]['health']=20;p.write_text(''.join(json.dumps(r)+'\n' for r in rows));module.prepare([p],o)
            self.assertEqual(json.loads(o.read_bytes())['events'],[])

    def cohort_fixture(self, root, *, partial=False):
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'entity-decoder'))
        from combined_storage import CombinedStorageWriter, encoded
        writer=CombinedStorageWriter(root,maximum_cohort_bytes=2200,maximum_total_bytes=65536,
            maximum_cohorts=8,maximum_index_bytes=32768,maximum_receipt_bytes=512)
        original=[]
        for number,tick in enumerate((100,120,140,160)):
            row=self.row(tick);row.update(combined_sequence=number,padding='x'*650)
            data=encoded(row);original.append(data)
            writer.write_compact(data,number)
            writer.commit_receipt(encoded(dict(combined_sequence=number,line_sha256=hashlib.sha256(data).hexdigest())))
        summary=writer.close()
        result=dict(summary,schema='overwatch-decoder.private.combined-run/2',status='partial' if partial else 'complete',
                    cli_exit_code=7 if partial else 0,capture_scope='controlled_practice',error=None,cleanup_errors=[])
        (root/'result.json').write_bytes(encoded(result))
        return b''.join(original),summary

    def test_storage_rotations_preserve_one_window_and_exact_rendered_values(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);cohorts=root/'cohorts';original,summary=self.cohort_fixture(cohorts)
            self.assertGreater(summary['storage_cohorts'],1)
            flat=root/'flat.jsonl';flat.write_bytes(original)
            module.prepare([flat],root/'flat.json');module.prepare([cohorts],root/'cohorts.json')
            a=json.loads((root/'flat.json').read_bytes());b=json.loads((root/'cohorts.json').read_bytes())
            self.assertEqual(len(b['epochs']),1);self.assertEqual(len(b['objects']),1)
            storage=b['epochs'][0]
            self.assertEqual(storage['storage_cohorts'],summary['storage_cohorts'])
            for name in ('storage_format','storage_index_sha256','storage_cohorts','producer_status'):storage.pop(name)
            self.assertEqual(a,b)

    def test_corrupt_unsealed_or_misreported_storage_preserves_old_output(self):
        for mode in ('data','unsealed','result','receipt'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as d:
                root=Path(d);cohorts=root/'cohorts';self.cohort_fixture(cohorts)
                output=root/'out.json';output.write_text('old')
                if mode=='unsealed':
                    p=cohorts/'storage-index.jsonl';p.write_bytes(b''.join(p.read_bytes().splitlines(keepends=True)[:-1]))
                elif mode=='result':
                    p=cohorts/'result.json';value=json.loads(p.read_bytes());value['output_rows']+=1;p.write_text(json.dumps(value))
                else:
                    p=cohorts/'cohort-000001'/('game-state.jsonl' if mode=='data' else 'delivery-receipts.jsonl')
                    p.write_bytes(p.read_bytes().replace(b'0',b'1',1))
                with self.assertRaises(ValueError):module.prepare([cohorts],output)
                self.assertEqual(output.read_text(),'old')

    def test_partial_sealed_storage_retains_status_without_continuity_claim(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);cohorts=root/'cohorts';self.cohort_fixture(cohorts,partial=True)
            module.prepare([cohorts],root/'out.json');value=json.loads((root/'out.json').read_bytes())
            self.assertEqual(value['epochs'][0]['producer_status'],'partial')
            self.assertFalse(value['whole_match_claim']);self.assertEqual(value['events'],[])
            with self.assertRaises(ValueError):module.prepare([cohorts],cohorts/'result.json')

    def test_source_change_after_seal_verification_cannot_replace_output(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);cohorts=root/'cohorts';self.cohort_fixture(cohorts)
            from combined_storage import CombinedStorageIndex
            complete=CombinedStorageIndex.complete
            def change_after_verification(reader):
                result=complete(reader);source=cohorts/'cohort-000001/game-state.jsonl'
                original=source.read_bytes();changed=original.replace(b'"health":50',b'"health":20',1)
                self.assertNotEqual(original,changed);source.write_bytes(changed)
                return result
            output=root/'out.json';output.write_text('old')
            with patch.object(CombinedStorageIndex,'complete',change_after_verification):
                with self.assertRaisesRegex(ValueError,'sealed source changed'):
                    module.prepare([cohorts],output)
            self.assertEqual(output.read_text(),'old')

    def test_recorder_cli_discovers_cohort_window(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);session=root/'session';cohorts=session/'observations/window-0001'
            self.cohort_fixture(cohorts)
            # The Windows recorder writes this beside each window directory.
            (session/'observations/window-0001.log').write_text('producer output\n')
            (session/'session.json').write_text(json.dumps(dict(qpc_origin=0,qpc_frequency=1000)))
            subprocess.run([__import__('sys').executable,str(Path(__file__).with_name('prepare_compact.py')),
                            str(session),str(root/'out.json')],check=True,capture_output=True)
            value=json.loads((root/'out.json').read_bytes());self.assertEqual(value['origin_ticks'],'0')
            self.assertEqual(value['epochs'][0]['storage_format'],'cohorts_v1')

if __name__=='__main__':unittest.main()
