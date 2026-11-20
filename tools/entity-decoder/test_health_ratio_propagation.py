"""Finite source admission, paired arithmetic, compact evidence and gap boundaries."""
import copy
import json
import os
import subprocess
import shutil
import sys
from pathlib import Path
import tempfile
import unittest

import aggregate_partitions as aggregate
import compact_live_roster as compact
from overwatch_decoder.health_ratio import calculate_ratio, calculate_bank_candidates
from test_aggregate_partitions import fixture, write_fixture


def with_ratios(root):
    manifest, frames = fixture(root)
    for source in manifest['sources']:
        rows = frames[source['source_id']]
        acquisition = rows[0]['source_artifacts']['acquisition']
        spec = dict(pool_index=0, field_name='controller_0000_body_0000_ratio_pair',
                    type='f32x3', width=3, numerator_component=2, denominator_component=1)
        pin = dict(contract_sha256='01'*32, native_review_sha256='02'*32,
                   membership_contract_sha256='03'*32, actor_prefix='controller_0000_body_0000_',
                   source=copy.deepcopy(acquisition), paired_slots=[spec], supplied_layout_slots=48)
        projection = dict(schema='overwatch-decoder.health-ratio-projection/1', contracts=[pin])
        source['health_ratio_projection'] = projection
        for frame in rows:
            frame['health_ratio_projection'] = copy.deepcopy(projection)
            frame['health_ratio_contract_sha256'] = [pin['contract_sha256']]
            for ordinal, row in enumerate(frame['relations']):
                row['controller_prefix'] = f'controller_{ordinal:04}'
                # Give existing candidates the actual export qualifications.
                row['position_candidate']['validation_status'] = 'guarded_research'
                row['health_candidate'].update(status='candidate', display_ceiling_candidate=int(row['health_candidate']['raw_sum']))
                row['hero_resource_guid_candidate'].update(validation_status='matching_guarded_resource_research', public_state_eligible=False)
                row['hero_label_evidence'].update(validation_status='guarded_build_resource_label_research', catalog_sha256='04'*32)
                row['cached_label_evidence']['validation_status'] = 'guarded_native_cache_string_research'
                row['category_evidence'].update(validation_status='guarded_category_roster_research',
                    native_review_sha256='05'*32, roster_review_sha256='06'*32, contract_sha256='07'*32)
                row['health_ratio_candidate'] = None
                if ordinal:
                    continue
                t = frame['timing']
                operand = dict(pool_index=0, field=spec['field_name'], numerator=100, denominator=200,
                               numerator_component=2, denominator_component=1,
                               read_start_ticks=t['start_ticks']+1, read_end_ticks=t['start_ticks']+2)
                row['health_ratio_candidate'] = dict(schema='overwatch-decoder.actor-pool-ratio/1', status='candidate',
                    source='process_memory', validation_status='static_derived_sampled_operands',
                    observation_scope='current_frame_paired_reads', body_object_key=row['body_object_key'],
                    numerator_sum=100.0, native_denominator_sum=200.0, native_ratio_candidate=.5,
                    operands=[operand], occupied_pool_count=1, supplied_layout_slots=48,
                    read_start_ticks=operand['read_start_ticks'], read_end_ticks=operand['read_end_ticks'],
                    profile_sha256=frame['profile_sha256'], build_sha256=frame['target']['executable_sha256'],
                    acquisition_evidence_sha256=acquisition['evidence_sha256'],
                    **{k:pin[k] for k in ('contract_sha256','native_review_sha256','membership_contract_sha256')},
                    maximum_health=None, hud_ratio=None, pool_roles=None, complete_supplied_membership_guarding=True,
                    arithmetic_assumption='binary32_round_to_nearest_even', native_float_control_state_observed=False,
                    native_execution_observed=False, atomic=False, continuity_across_gaps=False,
                    visibility='unknown', public_state_eligible=False)
    write_fixture(root, manifest, frames)
    return manifest, frames


def with_banks(root):
    manifest,frames=with_ratios(root)
    groups=[dict(bank_id=i,pool_indices=list(range(16*i,16*(i+1))))for i in range(3)]
    for source in manifest['sources']:
        source['health_ratio_projection']['contracts'][0]['bank_groups']=copy.deepcopy(groups)
        for frame in frames[source['source_id']]:
            frame['health_ratio_projection']=copy.deepcopy(source['health_ratio_projection'])
            for row in frame['relations']:
                ratio=row['health_ratio_candidate']
                if ratio is not None:
                    ratio['bank_candidates']=calculate_bank_candidates(ratio['operands'],groups)
    write_fixture(root,manifest,frames)
    return manifest,frames


class RatioPropagationTests(unittest.TestCase):
    def pipeline(self, root):
        aggregate.aggregate(root/'manifest.json', root/'aggregate.jsonl')
        report = compact.compact_finite_roster(root/'manifest.json', root/'aggregate.jsonl', root/'compact.jsonl')
        return report, [json.loads(line) for line in (root/'compact.jsonl').read_bytes().splitlines()]

    def test_finite_compact_banks_retain_source_and_empty_bank_evidence(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);_,frames=with_banks(root)
            _,result=self.pipeline(root)
            candidate=result[0]['players'][0]['health_ratio_candidate']
            banks=candidate['value']['bank_candidates']
            self.assertEqual([b['numerator_sum']for b in banks],[100,0,0])
            self.assertEqual([b['native_denominator_sum']for b in banks],[200,0,0])
            self.assertEqual([b['native_ratio_candidate']for b in banks],[.5,0,0])
            self.assertIsNone(banks[1]['operand_read_span_ticks'])
            source=json.loads((root/'aggregate.jsonl').read_bytes().splitlines()[0])
            for key in candidate['evidence_ref'].split('/')[1:]:
                source=source[int(key)]if isinstance(source,list)else source[key]
            self.assertEqual(source['bank_candidates'],banks)
            self.assertEqual(source,frames['p1'][0]['relations'][0]['health_ratio_candidate'])

    def test_altered_bank_roles_empty_values_times_and_membership_reject(self):
        mutations=[lambda b:b[0].update(pool_role='health'),
                   lambda b:b[1].update(numerator_sum=1.),
                   lambda b:b[1].update(operand_read_span_ticks=[0,1]),
                   lambda b:b[0].update(operand_pool_indices=[1]),
                   lambda b:b[0].update(native_ratio_candidate=.6),
                   lambda b:b[0].update(bank_id=False),
                   lambda b:b.pop()]
        for i,mutate in enumerate(mutations):
            with self.subTest(case=i),tempfile.TemporaryDirectory()as temp:
                root=Path(temp);manifest,frames=with_banks(root)
                mutate(frames['p1'][0]['relations'][0]['health_ratio_candidate']['bank_candidates'])
                write_fixture(root,manifest,frames)
                with self.assertRaises(ValueError):aggregate.aggregate(root/'manifest.json',root/'bad.jsonl')
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);manifest,frames=with_ratios(root)
            frames['p1'][0]['relations'][0]['health_ratio_candidate']['bank_candidates']=[]
            write_fixture(root,manifest,frames)
            with self.assertRaisesRegex(ValueError,'ratio_banks_not_admitted'):
                aggregate.aggregate(root/'manifest.json',root/'bad.jsonl')

    def test_finite_end_to_end_keeps_exact_candidate_and_evidence_pointer(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); manifest, frames=with_ratios(root)
            report, result=self.pipeline(root)
            self.assertEqual(report['health_ratio_candidates'], 2)
            self.assertEqual(result[0]['schema'],'overwatch-decoder.compact-finite-roster/1')
            self.assertNotIn('recording_state',result[0]); self.assertNotIn('session_id',result[0])
            original=json.loads((root/'aggregate.jsonl').read_bytes().splitlines()[0])
            candidate=result[0]['players'][0]['health_ratio_candidate']
            self.assertEqual(candidate['status'],'static_derived_sampled_operands')
            self.assertEqual(candidate['value']['native_ratio_candidate'],.5)
            self.assertIsNone(candidate['value']['maximum_health'])
            evidence=original
            for key in candidate['evidence_ref'].split('/')[1:]:
                evidence=evidence[int(key)] if isinstance(evidence,list) else evidence[key]
            self.assertEqual(evidence,frames['p1'][0]['relations'][0]['health_ratio_candidate'])
            self.assertEqual(result[0]['source_frame']['sha256'],aggregate.sha((root/'aggregate.jsonl').read_bytes().splitlines(keepends=True)[0]))
            self.assertEqual(result[0]['players'][0]['primary_observation']['semantic_source_sha256'],manifest['sources'][0]['sha256'])
            source_line=(root/'p1.jsonl').read_bytes().splitlines(keepends=True)[0]
            self.assertEqual(result[0]['players'][0]['primary_observation']['semantic_frame_sha256'],aggregate.sha(source_line))
            self.assertFalse(result[0]['values_carried_between_windows'])
            self.assertIsNone(result[0]['players'][1]['health_ratio_candidate']['value'])

    def test_arithmetic_source_review_identity_and_semantics_mutations_reject(self):
        cases=[('numerator_sum',101),('native_denominator_sum',201),('native_ratio_candidate',.7),
               ('body_object_key','body:'+'ff'*32),('profile_sha256','ff'*32),('build_sha256','ff'*32),
               ('acquisition_evidence_sha256','ff'*32),('contract_sha256','ff'*32),('native_review_sha256','ff'*32),
               ('membership_contract_sha256','ff'*32),('maximum_health',200),('hud_ratio',.5),('pool_roles',['health']),
               ('native_execution_observed',True),('native_float_control_state_observed',True),('atomic',True),
               ('occupied_pool_count',True),('supplied_layout_slots',True),('public_state_eligible',True)]
        for key,bad in cases:
            with self.subTest(key=key),tempfile.TemporaryDirectory() as temp:
                root=Path(temp); manifest,frames=with_ratios(root)
                frames['p1'][0]['relations'][0]['health_ratio_candidate'][key]=bad
                write_fixture(root,manifest,frames)
                with self.assertRaises(ValueError):aggregate.aggregate(root/'manifest.json',root/'bad.jsonl')
                self.assertFalse((root/'bad.jsonl').exists())

    def test_each_pair_and_read_bracket_is_required(self):
        mutations=[lambda c:c['operands'][0].pop('read_end_ticks'),
                   lambda c:c['operands'][0].update(read_start_ticks=0),
                   lambda c:c['operands'][0].update(denominator=201),
                   lambda c:c['operands'][0].update(numerator=101),
                   lambda c:c['operands'][0].update(field='other'),
                   lambda c:c['operands'][0].update(numerator_component=True),
                   lambda c:c['operands'].append(copy.deepcopy(c['operands'][0])),
                   lambda c:c.update(read_end_ticks=c['read_end_ticks']+1)]
        for i,mutate in enumerate(mutations):
            with self.subTest(case=i),tempfile.TemporaryDirectory() as temp:
                root=Path(temp); manifest,frames=with_ratios(root)
                mutate(frames['p1'][0]['relations'][0]['health_ratio_candidate']);write_fixture(root,manifest,frames)
                with self.assertRaises(ValueError):aggregate.aggregate(root/'manifest.json',root/'bad.jsonl')

    def test_external_projection_is_mandatory_and_cannot_change(self):
        for mutate in (lambda m,f:m['sources'][0].pop('health_ratio_projection'),
                       lambda m,f:f['p1'][0]['health_ratio_projection']['contracts'][0].update(native_review_sha256='ff'*32),
                       lambda m,f:f['p1'][0]['health_ratio_contract_sha256'].append('ff'*32),
                       lambda m,f:f['p1'][0]['source_artifacts']['acquisition'].update(recipe_sha256='ff'*32)):
            with tempfile.TemporaryDirectory() as temp:
                root=Path(temp);manifest,frames=with_ratios(root);mutate(manifest,frames);write_fixture(root,manifest,frames)
                with self.assertRaises(ValueError):aggregate.aggregate(root/'manifest.json',root/'bad.jsonl')

    def test_valid_gap_and_missing_frame_are_explicit_unknown_and_no_fill(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);manifest,frames=with_ratios(root)
            frames['p1'][1]['gap_before']['skipped_slots']=1
            for row in frames['p1'][1]['relations']:row['health_ratio_candidate']=None
            write_fixture(root,manifest,frames)
            report,rows=self.pipeline(root)
            self.assertEqual(rows[0]['players'][0]['health_ratio_candidate']['value']['native_ratio_candidate'],.5)
            self.assertEqual(rows[1]['players'][0]['status'],'unknown')
            self.assertIsNone(rows[1]['players'][0]['health_ratio_candidate']['value'])
            self.assertIsNone(rows[1]['players'][0]['health_ratio_candidate']['evidence_ref'])

    def test_gap_unobserved_and_replaced_body_reject_nonnull_ratio(self):
        for mutation in ('gap','unknown','replacement'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);manifest,frames=with_ratios(root);frame=frames['p1'][0];row=frame['relations'][0]
                if mutation=='gap':frame['gap_before']['skipped_slots']=1
                elif mutation=='unknown':row['relation_status']='unknown'
                else:row['body_object_key']='body:'+'ff'*32
                write_fixture(root,manifest,frames)
                with self.assertRaises(ValueError):aggregate.aggregate(root/'manifest.json',root/'bad.jsonl')

    def test_compact_replays_original_finite_source_and_rejects_changed_aggregate(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);with_ratios(root)
            aggregate.aggregate(root/'manifest.json',root/'aggregate.jsonl')
            lines=(root/'aggregate.jsonl').read_bytes().splitlines(keepends=True)
            value=json.loads(lines[0]);value['relations'][0]['authoritative_observation']['relation']['health_ratio_candidate']['native_ratio_candidate']=.9
            lines[0]=aggregate.canonical(value)+b'\n';(root/'aggregate.jsonl').write_bytes(b''.join(lines))
            with self.assertRaisesRegex(ValueError,'finite_aggregate_replay_mismatch'):
                compact.compact_finite_roster(root/'manifest.json',root/'aggregate.jsonl',root/'bad.jsonl')
            self.assertFalse((root/'bad.jsonl').exists())

    def test_direct_compact_ratio_validation_is_not_bypassed(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);_,frames=with_ratios(root);frame=frames['p1'][0]
            row=frame['relations'][0]
            # Finite admission already checked the category scope.
            row['health_ratio_candidate']['native_review_sha256']='ff'*32
            with self.assertRaisesRegex(ValueError,'ratio_native_review_sha256_mismatch'):
                compact.compact_candidates(row,frame,'/relations/0',finite_source=True)

    def test_multiple_pairs_use_native_order_f32_rounding_and_zero_denominator(self):
        from health_ratio_validation import validate_candidate, validate_projection
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); _,frames=with_ratios(root);frame=frames['p1'][0];row=frame['relations'][0]
            candidate=row['health_ratio_candidate'];projection=frame['health_ratio_projection']
            spec=projection['contracts'][0]['paired_slots'][0]
            projection['contracts'][0]['paired_slots'].append(dict(spec,pool_index=1,
                field_name='controller_0000_body_0000_other_pair',type='f32x4',width=4,numerator_component=3,denominator_component=2))
            candidate['operands'].append(dict(candidate['operands'][0],pool_index=1,
                field='controller_0000_body_0000_other_pair',numerator_component=3,denominator_component=2))
            candidate['occupied_pool_count']=2
            for operands in (((16777216,16777216),(1,16777216)),((3,0),(5,0)),((100,1),(10,1))):
                for pair,(n,d) in zip(candidate['operands'],operands):pair.update(numerator=n,denominator=d)
                n,d,r=calculate_ratio(candidate['operands'])
                candidate.update(numerator_sum=n,native_denominator_sum=d,native_ratio_candidate=r)
                validate_projection(projection,frame['source_artifacts']['acquisition'])
                self.assertIs(validate_candidate(row,frame,projection),candidate)
            self.assertEqual(candidate['native_ratio_candidate'],1.0)
            candidate['operands'].reverse()
            with self.assertRaisesRegex(ValueError,'ratio_pair_binding_mismatch'):
                validate_candidate(row,frame,projection)

    def test_malformed_metadata_rejects_without_dynamic_type_coercion(self):
        from health_ratio_validation import validate_projection
        mutations=[lambda p:p['contracts'][0]['paired_slots'][0].update(type=[]),
                   lambda p:p['contracts'][0]['paired_slots'][0].update(width=True),
                   lambda p:p['contracts'][0]['paired_slots'][0].update(pool_index=True),
                   lambda p:p['contracts'].append(copy.deepcopy(p['contracts'][0])),
                   lambda p:p['contracts'][0].update(supplied_layout_slots=True)]
        for mutate in mutations:
            with tempfile.TemporaryDirectory() as temp:
                _,frames=with_ratios(Path(temp));projection=frames['p1'][0]['health_ratio_projection'];mutate(projection)
                with self.assertRaises(ValueError):validate_projection(projection)

    def test_finite_output_byte_cap_leaves_no_partial_publication(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);with_ratios(root);aggregate.aggregate(root/'manifest.json',root/'aggregate.jsonl')
            with self.assertRaisesRegex(ValueError,'compact_roster_output_bound'):
                compact.compact_finite_roster(root/'manifest.json',root/'aggregate.jsonl',root/'bad.jsonl',maximum_output_bytes=1)
            self.assertFalse((root/'bad.jsonl').exists())
            self.assertEqual(list(root.glob('.compact-finite-roster-*')),[])

    def test_finite_cli_runs_from_outside_checkout_without_pythonpath(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);with_ratios(root);aggregate.aggregate(root/'manifest.json',root/'aggregate.jsonl')
            env=dict(os.environ);env.pop('PYTHONPATH',None)
            result=subprocess.run([sys.executable,str(Path(compact.__file__).resolve()),
                '--finite-manifest',str(root/'manifest.json'),'--finite-aggregate',str(root/'aggregate.jsonl'),
                '--finite-output',str(root/'compact.jsonl')],cwd=root,env=env,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads(result.stderr)['health_ratio_candidates'],2)
            self.assertEqual(result.stdout,'')

    def test_finite_owner_and_context_extras_are_explicitly_unsupported(self):
        from test_forward_roster_projection import configure
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);manifest,frames=with_ratios(root)
            configure(manifest['sources'][0],frames['p1']);write_fixture(root,manifest,frames)
            aggregate.aggregate(root/'manifest.json',root/'aggregate.jsonl')
            with self.assertRaisesRegex(ValueError,'finite_compact_unsupported_owner_or_context_projection'):
                compact.compact_finite_roster(root/'manifest.json',root/'aggregate.jsonl',root/'bad.jsonl')
            self.assertFalse((root/'bad.jsonl').exists())
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);manifest,frames=with_ratios(root)
            aggregate.aggregate(root/'manifest.json',root/'aggregate.jsonl')
            manifest['sources'][0]['context_projection']={'schema':'synthetic-unread-context-declaration'}
            # Reject the unsupported option before interpreting its contents.
            write_fixture(root,manifest,frames)
            with self.assertRaisesRegex(ValueError,'finite_compact_unsupported_owner_or_context_projection'):
                compact.compact_finite_roster(root/'manifest.json',root/'aggregate.jsonl',root/'bad.jsonl')
            self.assertFalse((root/'bad.jsonl').exists())

    def test_finite_unrepresented_names_or_ammunition_do_not_silently_disappear(self):
        for key,value in (('name','synthetic-name'),('ammunition_candidate',None)):
            with self.subTest(key=key),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);manifest,frames=with_ratios(root)
                frames['p1'][0]['relations'][0][key]=value;write_fixture(root,manifest,frames)
                if key == 'ammunition_candidate':
                    with self.assertRaisesRegex(ValueError, 'ammunition_not_admitted'):
                        aggregate.aggregate(root/'manifest.json',root/'aggregate.jsonl')
                    continue
                aggregate.aggregate(root/'manifest.json',root/'aggregate.jsonl')
                with self.assertRaisesRegex(ValueError,'finite_compact_unsupported_enrichment'):
                    compact.compact_finite_roster(root/'manifest.json',root/'aggregate.jsonl',root/'bad.jsonl')
                self.assertFalse((root/'bad.jsonl').exists())

    def test_stale_installed_or_cached_overwatch_decoder_cannot_override_exact_ratio_arithmetic(self):
        decoder=Path(compact.__file__).resolve().parent
        for poison,bundled in ((False,False),(True,False),(True,True)):
            with self.subTest(cached_module=poison,bundled=bundled),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);with_ratios(root);aggregate.aggregate(root/'manifest.json',root/'aggregate.jsonl')
                stale=root/'installed'/'overwatch_decoder';stale.mkdir(parents=True)
                (stale/'__init__.py').write_text('marker="stale distribution"\n')
                if poison:
                    (stale/'health_ratio.py').write_text('def calculate_ratio(*args): raise AssertionError("stale arithmetic used")\n')
                actual_decoder=decoder
                if bundled:
                    actual_decoder=root/'bundle'/'tools'/'entity-decoder';actual_decoder.mkdir(parents=True)
                    # These are the outer bundle's existing globbed module paths.
                    for path in decoder.glob('*.py'):
                        if not path.name.startswith('test_'):shutil.copyfile(path,actual_decoder/path.name)
                    package=root/'bundle'/'overwatch_decoder';package.mkdir()
                    for name in ('__init__.py','health_ratio.py','health_projection.py'):
                        shutil.copyfile(decoder.parents[1]/'overwatch_decoder'/name,package/name)
                code="""
import importlib,json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import overwatch_decoder
original=overwatch_decoder
if sys.argv[2]=='poison':import overwatch_decoder.health_ratio
sys.path.insert(0,sys.argv[3])
import aggregate_partitions,compact_live_roster
assert not any(k.startswith('_overwatch_decoder_ratio_projection_') for k in sys.modules), 'disabled import loaded ratio package'
result=compact_live_roster.compact_finite_roster(Path(sys.argv[4])/'manifest.json',Path(sys.argv[4])/'aggregate.jsonl',Path(sys.argv[4])/'compact.jsonl')
assert sys.modules['overwatch_decoder'] is original and overwatch_decoder.marker=='stale distribution'
loaded=[m for n,m in sys.modules.items() if n.startswith('_overwatch_decoder_ratio_projection_') and n.endswith('.health_ratio')]
assert len(loaded)==1 and Path(loaded[0].__file__).resolve()==Path(sys.argv[3]).parents[1]/'overwatch_decoder'/'health_ratio.py'
print(json.dumps(result))
"""
                child=subprocess.run([sys.executable,'-I','-c',code,str(stale.parent),
                    'poison' if poison else 'old',str(actual_decoder),str(root)],cwd=root,capture_output=True,text=True)
                self.assertEqual(child.returncode,0,child.stderr)
                self.assertEqual(json.loads(child.stdout)['health_ratio_candidates'],2)

    def test_missing_pinned_bundle_package_is_lazy_and_never_falls_back_to_site_package(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);decoder=root/'bundle'/'tools'/'entity-decoder';decoder.mkdir(parents=True)
            shutil.copyfile(Path(compact.__file__).with_name('health_ratio_validation.py'),decoder/'health_ratio_validation.py')
            stale=root/'installed'/'overwatch_decoder';stale.mkdir(parents=True)
            (stale/'__init__.py').write_text('')
            (stale/'health_ratio.py').write_text('def calculate_ratio(*args): raise AssertionError("ambient fallback used")\n')
            code="""
import sys
sys.path[:0]=sys.argv[1:]
import overwatch_decoder.health_ratio
import health_ratio_validation as h
h.validate_projection(None)
try:h.calculate_ratio([])
except h.InvalidHealthRatio as error:assert str(error)=='ratio_pinned_package_missing'
else:raise AssertionError('missing bundle was accepted')
"""
            child=subprocess.run([sys.executable,'-I','-c',code,str(decoder),str(stale.parent)],
                cwd=root,capture_output=True,text=True)
            self.assertEqual(child.returncode,0,child.stderr)

    def test_disabled_sources_do_not_add_ratio_keys_or_coverage(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);fixture(root)
            report=aggregate.aggregate(root/'manifest.json',root/'aggregate.jsonl')
            self.assertNotIn('health_ratio_candidate',report['authoritative_field_coverage'])
            self.assertNotIn('health_ratio_projection',(root/'aggregate.jsonl').read_text())


if __name__=='__main__':unittest.main()
