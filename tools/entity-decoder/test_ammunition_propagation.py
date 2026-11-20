"""Source-admitted transport tests; synthetic events are not native acceptance."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from aggregate_live_partitions import LivePartitions
from aggregate_partitions import aggregate, sha
from ammunition_projection_validation import source_admission, validate_frame, validate_source
from compact_live_roster import CompactLiveRoster, compact_finite_roster, encode
from test_live_ammunition import fixture, adapter, begin, frame_event, raw
from test_live_health_ratio import config_for, windows
from test_live_relations import next_frame
from test_compact_live_roster import transition


def live_fixture(root, ordinal=1, enabled=True):
    sources,_=fixture(root);s=sources[ordinal];a=adapter(s,enabled=enabled)
    admission=source_admission(a.ammunition,live_adapter=a) if enabled else None
    begin(a,s);f=a.consume(raw(frame_event(s)))
    c=config_for(f,s['profile'])
    if enabled:c['sources'][0]['ammunition']=admission
    return s,a,f,c


class AmmunitionPropagationTests(unittest.TestCase):
    def test_live_candidate_callback_operands_and_exact_pointers(self):
        with tempfile.TemporaryDirectory() as d:
            s,a,f,c=live_fixture(Path(d));_,out=windows(c,f);compact=CompactLiveRoster()
            results=[compact.consume(encode(w)) for w in out]
            self.assertIsNone(results[0]['players'][0]['ammunition_candidate']['value'])
            row=results[1]['players'][0]
            for key in ('ammunition_candidate','ammunition_callback_candidate'):
                candidate=row[key];self.assertEqual(candidate['value']['value'],26)
                ref=out[1]
                for token in candidate['evidence_ref'].split('/')[1:]:ref=ref[int(token)] if isinstance(ref,list) else ref[token]
                self.assertEqual(ref,f['ammunition_projection']['rows'][0])
            self.assertEqual(out[1]['ammunition_projections']['p1']['semantic_frame_sha256'],sha(raw(f)))
            self.assertEqual(out[1]['ammunition_sources']['p1'],c['sources'][0]['ammunition'])
            self.assertFalse(row['ammunition_candidate']['value']['engine_evaluation_validated'])
            self.assertFalse(row['ammunition_callback_candidate']['value']['clock_reads_atomic'])

    def test_unadmitted_and_corrupt_source_projection_or_join_rejected(self):
        mutators=[lambda f:f['relations'][0]['ammunition_candidate'].update(value=10),
            lambda f:f['relations'][0].update(ammunition_evidence_ref='/ammunition_projection/rows/1'),
            lambda f:f['ammunition_projection'].update(contract_sha256='ff'*32),
            lambda f:f['ammunition_projection']['rows'][0].update(controller_object_key='controller:'+'ff'*32),
            lambda f:f['ammunition_projection']['rows'][0]['evidence'][0].update(guard_ids=[]),
            lambda f:f['ammunition_projection']['rows'][0]['evidence'][0].update(read_start_ticks=0),
            lambda f:f['ammunition_projection']['rows'][0].update(is_firing=True),
            lambda f:f['ammunition_projection']['rows'][0]['callback_reconstruction_candidate'].update(clock_reads_atomic=True),
            lambda f:f['ammunition_live_admission'].update(admission_sha256='ff'*32),
            lambda f:f['ammunition_live_admission'].update(live_event_sha256='ff'*32),
            lambda f:f['ammunition_live_admission'].update(session_id='f'*32),
            lambda f:f['ammunition_projection']['rows'].append(copy.deepcopy(f['ammunition_projection']['rows'][0]))]
        with tempfile.TemporaryDirectory() as d:
            _,_,original,c=live_fixture(Path(d))
            for mutate in mutators:
                f=copy.deepcopy(original);mutate(f)
                with self.subTest(mutation=mutate),self.assertRaises(ValueError): LivePartitions(raw(c)).consume('p1',raw(f))
            c['sources'][0].pop('ammunition')
            with self.assertRaisesRegex(ValueError,'ammunition_not_admitted'):LivePartitions(raw(c)).consume('p1',raw(original))

    def test_native_epoch_hash_crosscheck_and_fresh_admission_required(self):
        with tempfile.TemporaryDirectory() as d:
            _,_,f,c=live_fixture(Path(d))
            f['session_epoch']={n+'_sha256':f['ammunition_live_admission'][n+'_event_sha256'] for n in ('session_start','acquisition_end','segment_start')}
            validate_frame(f,c['sources'][0])
            for name in f['session_epoch']:
                bad=copy.deepcopy(f);bad['session_epoch'][name]='ff'*32
                with self.assertRaisesRegex(ValueError,'native_epoch_pin'):validate_frame(bad,c['sources'][0])
            bad=copy.deepcopy(c['sources'][0]);bad['segment']=2
            with self.assertRaisesRegex(ValueError,'live_epoch'):validate_source(bad)

    def test_unknown_gap_and_missing_window_do_not_carry(self):
        with tempfile.TemporaryDirectory() as d:
            s,a,f,c=live_fixture(Path(d));agg=LivePartitions(raw(c));agg.consume('p1',raw(f))
            current=next_frame(s['frame'],missed=1);e=frame_event(s,current);e['event_sequence']+=1
            g=a.consume(raw(e));self.assertIsNone(g['ammunition_projection']['rows'][0]['ammunition_candidate'])
            agg.consume('p1',raw(g));outputs=list(agg.advance(1500));compact=CompactLiveRoster()
            results=[compact.consume(encode(w)) for w in outputs]
            self.assertTrue(any(r['players'][0]['ammunition_candidate']['value'] is not None for r in results))
            self.assertIsNone(results[-1]['players'][0]['ammunition_candidate']['value'])
            bad=copy.deepcopy(g);bad['ammunition_projection']['rows'][0]=copy.deepcopy(f['ammunition_projection']['rows'][0])
            with self.assertRaises(ValueError):validate_frame(bad,c['sources'][0])

    def test_compact_rejects_unknown_injection_changed_pins_and_bad_join(self):
        with tempfile.TemporaryDirectory() as d:
            _,_,f,c=live_fixture(Path(d));_,out=windows(c,f)
            for kind in ('pin','join','hash','time','unknown'):
                compact=CompactLiveRoster();compact.consume(encode(out[0]));bad=copy.deepcopy(out[1])
                if kind=='pin':bad['ammunition_sources']['p1']['contract_sha256']='ff'*32
                if kind=='join':bad['relations'][0]['authoritative_observation']['relation']['ammunition_candidate']['value']=1
                if kind=='hash':bad['ammunition_projections']['p1']['semantic_frame_sha256']='ff'*32
                if kind=='time':bad['ammunition_projections']['p1']['projection']['timing']['start_ticks']=0
                if kind=='unknown':
                    bad=copy.deepcopy(out[0]);bad['window_index']=1;bad['window_start_ticks']+=100;bad['window_end_ticks']+=100
                    bad['watermark_ticks']=bad['window_end_ticks'];bad['relations'][0]['ammunition_candidate']={'value':40}
                with self.subTest(kind=kind),self.assertRaises(ValueError):compact.consume(encode(bad))

    def test_end_nulls_candidates_and_disabled_bytes_unchanged(self):
        with tempfile.TemporaryDirectory() as d:
            _,_,f,c=live_fixture(Path(d));_,out=windows(c,f);compact=CompactLiveRoster()
            for w in out:compact.consume(encode(w))
            end=compact.consume(encode(transition(out[-1])))
            self.assertIsNone(end['players'][0]['ammunition_candidate']['value'])
            self.assertIsNone(end['players'][0]['ammunition_callback_candidate']['evidence_ref'])
            stripped=copy.deepcopy(f)
            for k in ('ammunition_projection','live_ammunition_output_enabled','ammunition_contract_sha256','ammunition_admission_sha256','ammunition_live_admission'):stripped.pop(k)
            for r in stripped['relations']:
                for k in ('ammunition_candidate','ammunition_evidence_ref','ammunition_reason'):r.pop(k)
            c['sources'][0].pop('ammunition');_,baseline=windows(c,stripped)
            for actual,expected in zip(out,baseline):
                actual=copy.deepcopy(actual);actual.pop('ammunition_sources');actual.pop('ammunition_projections')
                # Frame hashes change because opt-in adds evidence; every other original field is exact.
                def strip(node):
                    if isinstance(node,dict):
                        for k in ('ammunition_candidate','ammunition_evidence_ref','ammunition_reason'):node.pop(k,None)
                        for k,v in node.items():
                            if k=='semantic_projection_sha256':node[k]=sha(raw(stripped))
                            else:strip(v)
                    elif isinstance(node,list):
                        for v in node:strip(v)
                strip(actual);actual['config_sha256']=expected['config_sha256']
                self.assertEqual(actual,expected)

    def test_fresh_epoch_cannot_reuse_prior_values_or_admission(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);sources,_=fixture(root);frames=[];configs=[]
            for n in (1,2):
                a=adapter(sources[n]);begin(a,sources[n]);frame=a.consume(raw(frame_event(sources[n])))
                config=config_for(frame,sources[n]['profile']);config['epoch_id']='epoch-'+str(n)
                config['sources'][0]['ammunition']=source_admission(a.ammunition,live_adapter=a)
                frames.append(frame);configs.append(config)
            first=LivePartitions(raw(configs[0]));first.consume('p1',raw(frames[0]))
            compact=CompactLiveRoster()
            for value in first.advance(1200): compact.consume(encode(value))
            with self.assertRaises(ValueError):LivePartitions(raw(configs[1])).consume('p1',raw(frames[0]))
            second=LivePartitions(raw(configs[1]));second.consume('p1',raw(frames[1]))
            results=[compact.consume(encode(value)) for value in second.advance(2200) if value['window_index']>=2]
            self.assertTrue(all(r['players'][0]['ammunition_candidate']['value'] is None for r in results[:-1]))
            self.assertEqual(results[-1]['players'][0]['ammunition_candidate']['value']['value'],26)
            self.assertNotEqual(configs[0]['sources'][0]['ammunition']['acquisition'],configs[1]['sources'][0]['ammunition']['acquisition'])

    def test_zero_is_observed_and_unknown_injected_projection_cannot_hide(self):
        from test_ammunition_export import AmmunitionExportTests
        case=AmmunitionExportTests();case.setUp();case.frame['fields']['base_bits']['value']=0
        frame=case.project();source={'ammunition':source_admission(case.ammo)}
        validate_frame(frame,source)
        self.assertEqual(frame['ammunition_projection']['rows'][0]['ammunition_candidate']['value'],0)
        frame['relations'][0].update(relation_status='unknown',body_object_key=None)
        with self.assertRaisesRegex(ValueError,'unbound_relation_value'):validate_frame(frame,source)

    def test_finite_pipeline_uses_real_projector_and_preserves_original_projection(self):
        from test_ammunition_export import AmmunitionExportTests
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);case=AmmunitionExportTests();case.setUp()
            frame=case.project();timing=frame['timing'];pair={k:frame['relations'][0][k] for k in ('controller_object_key','body_object_key')}
            frame['source_artifacts'].update(manifest_sha256='11'*32,samples_prefix_sha256='22'*32,index_prefix_sha256='33'*32)
            frame['recording']=dict(complete=True,partial=False,status='verified_complete')
            frame['gap_before']=dict(skipped_slots=0,previous_end_ticks=None,current_start_ticks=timing['start_ticks'],previous_values_carried=False)
            line=encode(frame);(root/'source.jsonl').write_bytes(line)
            source=dict(source_id='p1',path='source.jsonl',sha256=sha(line),profile_sha256=frame['profile_sha256'],objects=[pair],
                acquisition_manifest_sha256=case.ammo.acquisition_manifest_sha256,recording_manifest_sha256='11'*32,
                ammunition=source_admission(case.ammo))
            manifest=dict(schema='overwatch-decoder.partition-research-manifest/1',epoch_id='synthetic',clock_domain_id='synthetic',target=frame['target'],
                monotonic_frequency=timing['monotonic_frequency'],window_ticks=100,maximum_skew_ticks=200,maximum_origin_offset_ticks=0,
                roster=[dict(pair,primary_source_id='p1')],sources=[source])
            (root/'manifest.json').write_bytes(encode(manifest));aggregate(root/'manifest.json',root/'aggregate.jsonl')
            compact_finite_roster(root/'manifest.json',root/'aggregate.jsonl',root/'compact.jsonl')
            result=json.loads((root/'compact.jsonl').read_bytes().splitlines()[0]);self.assertEqual(result['players'][0]['ammunition_candidate']['value']['value'],40)
            full=json.loads((root/'aggregate.jsonl').read_bytes().splitlines()[0]);self.assertEqual(full['ammunition_projections']['p1']['projection'],frame['ammunition_projection'])


if __name__=='__main__':unittest.main()
