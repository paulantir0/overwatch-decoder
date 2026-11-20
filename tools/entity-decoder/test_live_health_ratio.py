"""Synthetic live transport mechanics; real ratio arithmetic was tested finitely.

No fixture in this file is a game capture, original live evidence or gameplay
validation. Epoch/read guards exercise the existing source-admission protocol.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from aggregate_live_partitions import LivePartitions
from aggregate_partitions import canonical
from compact_live_roster import CompactLiveRoster, encode
from export_relations import health_ratio_projection
from health_ratio_validation import load_ratio_contract
from live_relations import LiveRelations
from live_sessions import LiveSession
from test_live_continuity import epoch, begin, sample
from test_live_relations import raw, SESSION, next_frame
from test_live_sessions import fixture as session_fixture, consume_all
from test_relations import prepare, fixture as identity_fixture


PAIR='controller_0000_body_0000_pool_0000_paired'


def add_ratio(root, data, *, width=3, unresolved=False):
    profile, old, manifest, health = data
    profile=copy.deepcopy(profile);manifest=copy.deepcopy(manifest)
    values={name:s['value'] for name,s in old['fields'].items()}
    if unresolved:
        extra,extra_values=identity_fixture(rows=2)
        fields=[d for d in extra['fields'] if d['name'].startswith('controller_0001_')][:3]
        profile['fields'].extend(fields)
        addresses={d['address'] for d in fields}
        profile['guards'].extend(g for g in extra['guards'] if g['address'] in addresses)
        values.update({d['name']:extra_values[d['name']] for d in fields})
    profile['fields'].append(dict(name=PAIR,type='f32x'+str(width),address=0x5008))
    values[PAIR]=[200.,200.,values['controller_0000_body_0000_pool_0000_direct_candidate']]+[0.]*(width-3)
    decoder,frame=prepare(profile,values)
    frame.update({k:copy.deepcopy(v)for k,v in old.items()if k not in ('profile_sha256','fields','guards_before','guards_after')})
    delta=old['start_ticks']-10
    for phase in ('guards_before','guards_after'):
        for guard in frame[phase]:
            guard['start_ticks']+=delta;guard['end_ticks']+=delta
    for name,s in frame['fields'].items():
        s.update(type=decoder.fields[name]['type'],reason=None)
        s['read_start_ticks']+=delta;s['read_end_ticks']+=delta
    profile_raw=json.dumps(profile).encode();manifest['profile_sha256']=hashlib.sha256(profile_raw).hexdigest()
    (root/'profile.json').write_bytes(profile_raw);(root/'manifest.json').write_bytes(raw(manifest))
    review=raw(dict(build_sha256=profile['target']['executable_sha256'],synthetic_mechanics_only=True))
    (root/'ratio-review.json').write_bytes(review)
    source=dict(manifest_sha256=hashlib.sha256((root/'manifest.json').read_bytes()).hexdigest(),
                recipe_sha256=manifest['recipe_sha256'],evidence_sha256=manifest['evidence_sha256'])
    contract=dict(schema='overwatch-decoder.private.actor-health-ratio-contract/1',algorithm='occupied_pool_ratio_f32',
        profile_sha256=decoder.hash,build_sha256=profile['target']['executable_sha256'],
        source=source,native_review_sha256=hashlib.sha256(review).hexdigest(),
        health_contract=json.loads(health[0].read_bytes()),paired_slots=[dict(pool_index=0,field_name=PAIR,
            numerator_component=2,denominator_component=1,denominator_address=0x500c)])
    (root/'ratio.json').write_bytes(raw(contract))
    options=dict(health_contracts=health,health_ratio_contracts=[root/'ratio.json'],health_ratio_native_review=root/'ratio-review.json')
    return profile,frame,manifest,options


def single(root,n=1,replacement=False):
    return add_ratio(root,epoch(root,n,replacement_body=replacement))


def project(root,data,*,enabled=True):
    p,f,m,options=data
    options=options if enabled else dict(health_contracts=options['health_contracts'])
    adapter=LiveRelations(root,SESSION,1,**options)
    adapter.consume(raw(begin(p,m,1,0)))
    return adapter,adapter.consume(raw(sample(f,1,1)))


def config_for(frame,profile):
    row=frame['relations'][0];pair={k:row[k]for k in ('controller_object_key','body_object_key')}
    source=dict(source_id='p1',session_id=frame['session_id'],segment=frame['segment'],
        profile_sha256=frame['profile_sha256'],acquisition=copy.deepcopy(frame['source_artifacts']['acquisition']),
        objects=[pair],fields=[dict(name=d['name'],type=d['type'])for d in profile['fields']])
    if 'health_ratio_projection'in frame:source['health_ratio_projection']=copy.deepcopy(frame['health_ratio_projection'])
    return dict(schema='overwatch-decoder.live-partition-config/1',epoch_id='synthetic',clock_domain_id='synthetic-qpc',
        target=frame['target'],monotonic_frequency=1000,window_origin_ticks=1000,window_ticks=100,
        maximum_skew_ticks=200,maximum_origin_offset_ticks=0,roster=[dict(pair,primary_source_id='p1')],sources=[source])


def windows(config,frame):
    adapter=LivePartitions(raw(config));adapter.consume('p1',raw(frame))
    return adapter,list(adapter.advance(1200))


class LiveHealthRatioTests(unittest.TestCase):
    def test_reviewed_bank_output_survives_live_transport_and_clears_on_gap(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp)/'source';data=single(root)
            path=root/'ratio.json';contract=json.loads(path.read_bytes())
            count=len(contract['health_contract']['slots'])
            groups=[dict(bank_id=i,pool_indices=[i])for i in range(count)]
            review_path=root/'ratio-review.json';review=raw(dict(json.loads(review_path.read_bytes()),bank_groups=groups))
            review_path.write_bytes(review)
            contract.update(bank_groups=groups,native_review_sha256=hashlib.sha256(review).hexdigest())
            path.write_bytes(raw(contract))
            reader,frame=project(root,data)
            ratio=frame['relations'][0]['health_ratio_candidate']
            self.assertEqual(ratio['bank_candidates'][0]['native_ratio_candidate'],.5)
            config=config_for(frame,data[0]);aggregator=LivePartitions(raw(config))
            aggregator.consume('p1',raw(frame))
            f=next_frame(data[1],missed=1);e=sample(f,1,2);e['emitted_ticks']=1600
            gap=reader.consume(raw(e));aggregator.consume('p1',raw(gap))
            outputs=list(aggregator.advance(1400));compact=CompactLiveRoster()
            rows=[compact.consume(encode(w))for w in outputs]
            valid=[r['players'][0]['health_ratio_candidate']['value']for r in rows
                   if r['players'][0]['health_ratio_candidate']['value'] is not None]
            self.assertEqual(valid[0]['bank_candidates'],ratio['bank_candidates'])
            self.assertIsNone(rows[-1]['players'][0]['health_ratio_candidate']['value'])

    def test_opt_in_reader_and_aggregate_compact_keep_exact_pins_and_operand_span(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp)/'source';data=single(root);_,frame=project(root,data)
            ratio=frame['relations'][0]['health_ratio_candidate']
            self.assertEqual(ratio['native_ratio_candidate'],.5)
            config=config_for(frame,data[0]);adapter,outputs=windows(config,frame)
            compact=CompactLiveRoster();results=[compact.consume(encode(w))for w in outputs]
            self.assertIsNone(results[0]['players'][0]['health_ratio_candidate']['value'])
            candidate=results[1]['players'][0]['health_ratio_candidate']
            self.assertEqual(candidate['status'],'static_derived_sampled_operands')
            self.assertEqual(candidate['value']['native_ratio_candidate'],.5)
            self.assertEqual(candidate['read_span_ticks'],[ratio['read_start_ticks'],ratio['read_end_ticks']])
            reference=outputs[1]
            for key in candidate['evidence_ref'].split('/')[1:]:reference=reference[int(key)]if isinstance(reference,list)else reference[key]
            self.assertEqual(reference,ratio)
            self.assertEqual(outputs[1]['health_ratio_sources']['p1']['projection'],frame['health_ratio_projection'])
            selected=outputs[1]['relations'][0]['authoritative_observation']
            self.assertEqual(selected['semantic_frame_sha256'],hashlib.sha256(raw(frame)).hexdigest())
            self.assertEqual(adapter.close()['authoritative_field_coverage']['health_ratio_candidate'],1)
            self.assertIsNone(candidate['value']['maximum_health']);self.assertIsNone(candidate['value']['hud_ratio'])
            self.assertIsNone(candidate['value']['pool_roles']);self.assertFalse(results[1]['durability_verified'])

    def test_disabled_reader_output_is_identical_and_default_aggregate_has_no_ratio_keys(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp)/'source';data=single(root);_,enabled=project(root,data);_,disabled=project(root,data,enabled=False)
            enabled.pop('health_ratio_projection');enabled.pop('health_ratio_contract_sha256')
            for row in enabled['relations']:row.pop('health_ratio_candidate')
            self.assertEqual(raw(enabled),raw(disabled))
            _,outputs=windows(config_for(disabled,data[0]),disabled)
            result=CompactLiveRoster()
            for output in outputs:
                compact=result.consume(encode(output));self.assertNotIn('health_ratio_sources',compact)
                self.assertNotIn('health_ratio_candidate',compact['players'][0])

    def test_gap_unknown_vector_identity_or_membership_failures_never_reuse_ratio(self):
        for mode in ('gap','vector','identity','membership'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory()as temp:
                root=Path(temp)/'source';data=single(root);adapter,first=project(root,data)
                f=next_frame(data[1],missed=1 if mode=='gap'else 0)
                if mode=='vector':f['fields'][PAIR].update(status='unknown',value=None,reason='synthetic unavailable')
                if mode=='identity':
                    name='controller_0000_body_0000_handle_candidate_i32'
                    f['fields'][name].update(status='unknown',value=None,reason='synthetic lifecycle change')
                if mode=='membership':
                    # A failed global membership guard requires all dependent fields unknown.
                    f['guards_after'][-1].update(ok=False,error='synthetic changed membership')
                    for s in f['fields'].values():s.update(status='unknown',value=None,reason='synthetic guard failure')
                e=sample(f,1,2);e['emitted_ticks']=1600
                current=adapter.consume(raw(e))
                self.assertIsNone(current['relations'][0]['health_ratio_candidate'])
                self.assertEqual(first['relations'][0]['health_ratio_candidate']['native_ratio_candidate'],.5)
                if mode=='gap':
                    config=config_for(first,data[0]);aggregate=LivePartitions(raw(config));aggregate.consume('p1',raw(first))
                    aggregate.consume('p1',raw(current));out=list(aggregate.advance(1400));compact=CompactLiveRoster()
                    rows=[compact.consume(encode(w))for w in out]
                    self.assertIsNone(rows[-1]['players'][0]['health_ratio_candidate']['value'])

    def test_source_projection_or_candidate_corruption_is_rejected(self):
        mutations=[lambda f:f['health_ratio_projection']['contracts'][0].update(native_review_sha256='ff'*32),
                   lambda f:f['health_ratio_contract_sha256'].append('ff'*32),
                   lambda f:f['relations'][0]['health_ratio_candidate'].update(native_ratio_candidate=.9),
                   lambda f:f['relations'][0]['health_ratio_candidate'].update(maximum_health=200),
                   lambda f:f['relations'][0]['health_ratio_candidate']['operands'][0].pop('read_end_ticks'),
                   lambda f:f['relations'][0]['health_ratio_candidate'].update(body_object_key='body:'+'ff'*32)]
        for mutate in mutations:
            with tempfile.TemporaryDirectory()as temp:
                root=Path(temp)/'source';data=single(root);_,frame=project(root,data);config=config_for(frame,data[0])
                mutate(frame)
                with self.assertRaises(ValueError):LivePartitions(raw(config)).consume('p1',raw(frame))
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp)/'source';data=single(root);_,frame=project(root,data);config=config_for(frame,data[0])
            config['sources'][0]['fields']=[dict(f,type='f32')if f['name']==PAIR else f for f in config['sources'][0]['fields']]
            with self.assertRaisesRegex(ValueError,'ratio_field_declaration_mismatch'):LivePartitions(raw(config))

    def test_compact_pins_cannot_change_inside_epoch_and_forged_unknown_rejects(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp)/'source';data=single(root);_,frame=project(root,data);_,outputs=windows(config_for(frame,data[0]),frame)
            for mutation in ('metadata','candidate','span','unknown'):
                corrupt=copy.deepcopy(outputs[1])
                if mutation=='metadata':corrupt['health_ratio_sources']['p1']['projection']['contracts'][0]['native_review_sha256']='ff'*32
                elif mutation=='candidate':corrupt['relations'][0]['authoritative_observation']['relation']['health_ratio_candidate']['numerator_sum']=1
                elif mutation=='span':corrupt['relations'][0]['authoritative_observation']['relation']['health_ratio_candidate']['operands'][0]['read_start_ticks']=0
                else:
                    corrupt=copy.deepcopy(outputs[0]);corrupt['relations'][0]['health_ratio_candidate']={'invented':True}
                c=CompactLiveRoster()
                if mutation!='unknown':c.consume(encode(outputs[0]))
                with self.subTest(mutation=mutation),self.assertRaises(ValueError):c.consume(encode(corrupt))
            normal=CompactLiveRoster();trusted=CompactLiveRoster()
            for value in outputs:
                line=canonical(value)+b'\n'
                self.assertEqual(encode(normal.consume(line)),encode(trusted._consume_decoded(line,value)))

    def test_explicit_runtime_end_clears_ratio_and_cannot_resume_old_values(self):
        from test_compact_live_roster import transition
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp)/'source';data=single(root);_,frame=project(root,data)
            _,outputs=windows(config_for(frame,data[0]),frame);c=CompactLiveRoster()
            for output in outputs:observed=c.consume(encode(output))
            self.assertIsNotNone(observed['players'][0]['health_ratio_candidate']['value'])
            ending=transition(outputs[-1]);ending['trigger']['reason']='finite_sources_completed'
            ending['input_end']=dict(reason='finite_sources_completed',evidence_kind='caller_verified_producer_eof_not_native_sample',
                stop_ticks=ending['trigger']['read_end_ticks'],discarded_pending_windows=1,discarded_pending_bytes=1,
                source_result_sha256={'p1':'ab'*32})
            result=c.consume(encode(ending))
            self.assertIsNone(result['players'][0]['health_ratio_candidate']['value'])
            self.assertIsNone(result['players'][0]['health_ratio_candidate']['evidence_ref'])
            self.assertIsNone(result['players'][0]['body_object_key'])
            self.assertFalse(result['previous_values_carried'])
            with self.assertRaises(ValueError):c.consume(encode(outputs[-1]))

    def test_reader_requires_complete_options_and_exact_contract_source(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp)/'source';p,f,m,options=single(root)
            for broken in (dict(health_ratio_contracts=options['health_ratio_contracts']),dict(health_ratio_native_review=options['health_ratio_native_review'])):
                with self.assertRaisesRegex(ValueError,'required_together'):LiveRelations(root,SESSION,1,**broken)
            for key in ('manifest_sha256','recipe_sha256','evidence_sha256'):
                contract=json.loads((root/'ratio.json').read_bytes());contract['source'][key]='ff'*32
                path=root/(key+'.json');path.write_bytes(raw(contract))
                with self.subTest(key=key),self.assertRaises(ValueError):
                    LiveRelations(root,SESSION,1,health_ratio_contracts=[path],health_ratio_native_review=options['health_ratio_native_review'])
            with self.assertRaisesRegex(ValueError,'duplicate_health_ratio_actor'):
                LiveRelations(root,SESSION,1,health_ratio_contracts=options['health_ratio_contracts']*2,
                              health_ratio_native_review=options['health_ratio_native_review'])

    def test_two_synthetic_native_epochs_refresh_contract_and_replace_body(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);epochs,events,_,_=session_fixture(root)
            updated={n:add_ratio(root/str(n),data)for n,data in epochs.items()}
            for e in events:
                if e['kind']=='acquisition_end':
                    n=e['acquisition']['ordinal'];e['acquisition'].update(profile_sha256=updated[n][2]['profile_sha256'],
                        manifest_sha256=hashlib.sha256((root/str(n)/'manifest.json').read_bytes()).hexdigest())
                if e['kind']=='segment_start':
                    n=e['segment'];e['profile_sha256']=updated[n][2]['profile_sha256']
                    e['fields']=[dict(name=d['name'],type=d['type'])for d in updated[n][0]['fields']]
                if e['kind']=='frame':
                    replacement=sample(updated[e['segment']][1],e['segment'],e['event_sequence'])
                    replacement['emitted_ticks']=e['emitted_ticks'];e.clear();e.update(replacement)
                if e['kind']=='segment_end':e['segment']['profile_sha256']=updated[e['segment']['ordinal']][2]['profile_sha256']
            factory=lambda session,acq,seg:LiveRelations(root/str(acq['ordinal']),SESSION,seg['segment'],**updated[acq['ordinal']][3])
            coordinator=LiveSession(factory);results=consume_all(coordinator,events)
            left,right=[f['relations'][0]for f in results]
            self.assertEqual(left['controller_object_key'],right['controller_object_key']);self.assertNotEqual(left['body_object_key'],right['body_object_key'])
            self.assertEqual([r['health_ratio_candidate']['native_ratio_candidate']for r in (left,right)],[.5,.25])
            self.assertNotEqual(left['health_ratio_candidate']['contract_sha256'],right['health_ratio_candidate']['contract_sha256'])
            self.assertTrue(coordinator.close()['native_session_end_seen'])
            with self.assertRaises(ValueError):LiveRelations(root/'2',SESSION,2,**updated[1][3])

    def test_mixed_present_and_unresolved_body_preserves_ratio_metadata_without_filling_unknown(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp)/'source';data=add_ratio(root,epoch(root,1),unresolved=True)
            _,frame=project(root,data);config=config_for(frame,data[0]);source=config['sources'][0]
            unavailable=frame['relations'][1]
            self.assertEqual(unavailable['reason'],'unsupported_word_binding')
            self.assertIsNone(unavailable['body_object_key']);self.assertIsNone(unavailable['health_ratio_candidate'])
            pair={key:unavailable[key]for key in ('controller_object_key','body_object_key')}
            config.update(allow_unresolved_bodies=True,observation_mode='raw-candidates')
            config['roster'].append(dict(pair,primary_source_id='p1'));source['objects'].append(pair)
            source['unresolved_bodies']=[dict(controller_object_key=pair['controller_object_key'],reason='body_fields_not_declared',
                profile_sha256=frame['profile_sha256'],acquisition_evidence_sha256=source['acquisition']['evidence_sha256'],
                profile_guards_sha256=hashlib.sha256(raw(data[0]['guards'])).hexdigest(),body_field_prefix='controller_0001_body_',
                controller_identity_fields=['controller_0001_handle_candidate_i32','controller_0001_manager_key_candidate_i32'],
                body_lookup_key_field='controller_0001_part51_0000_body_key_candidate_i32')]
            _,output=windows(config,frame);compact=CompactLiveRoster();results=[compact.consume(encode(v))for v in output]
            candidate=results[-1]['players'][0]['health_ratio_candidate']
            self.assertEqual(candidate['value']['native_ratio_candidate'],.5)
            unknown=results[-1]['players'][1]
            self.assertEqual(unknown['status'],'unknown');self.assertIsNone(unknown['health_ratio_candidate']['value'])
            node=output[-1]['relations'][1]['unresolved_body_observations'][0]
            self.assertEqual(node['health_ratio_projection'],frame['health_ratio_projection'])
            self.assertEqual(node['semantic_frame_sha256'],hashlib.sha256(raw(frame)).hexdigest())
            self.assertEqual(node['semantic_frame_hash_scope'],'exact_semantic_jsonl_line_including_lf')

    def test_four_component_ratio_is_explicitly_rejected_at_live_constructors(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp)/'source';p,f,m,options=add_ratio(root,epoch(root,1),width=4)
            # Generic finite contract accepts it; only live delivery is restricted.
            contract=load_ratio_contract((root/'profile.json').read_bytes(),(root/'ratio.json').read_bytes(),
                                         (root/'ratio-review.json').read_bytes())
            self.assertEqual(contract.paired_slots[0]['type'],'f32x4')
            with self.assertRaisesRegex(ValueError,'live_ratio_requires_f32x3'):
                LiveRelations(root,SESSION,1,**options)
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp)/'source';data=single(root);_,frame=project(root,data);config=config_for(frame,data[0])
            spec=config['sources'][0]['health_ratio_projection']['contracts'][0]['paired_slots'][0]
            spec.update(type='f32x4',width=4)
            for field in config['sources'][0]['fields']:
                if field['name']==PAIR:field['type']='f32x4'
            with self.assertRaisesRegex(ValueError,'live_ratio_requires_f32x3'):LivePartitions(raw(config))

    def test_stale_cached_overwatch_decoder_does_not_override_live_constructor(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp)/'source';single(root);stale=Path(temp)/'stale'/'overwatch_decoder';stale.mkdir(parents=True)
            (stale/'__init__.py').write_text('stale=True\n')
            (stale/'health_ratio.py').write_text('raise AssertionError("wrong module loaded")\n')
            code="""import sys
sys.path.insert(0,sys.argv[1]);import overwatch_decoder
sys.path.insert(0,sys.argv[2]);from live_relations import LiveRelations
from pathlib import Path
r=Path(sys.argv[3]);a=LiveRelations(r,'a'*32,1,health_ratio_contracts=[r/'ratio.json'],health_ratio_native_review=r/'ratio-review.json')
assert len(a.health_ratios)==1 and overwatch_decoder.stale is True
"""
            run=subprocess.run([sys.executable,'-I','-c',code,str(stale.parent),str(Path(__file__).parent),str(root)],cwd=temp,capture_output=True,text=True)
            self.assertEqual(run.returncode,0,run.stderr)


if __name__=='__main__':unittest.main()
