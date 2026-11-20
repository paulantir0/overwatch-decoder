"""Proof-scope invalidation and detached projection ownership regressions."""
import copy
import json
import unittest
import tempfile
import subprocess
import sys
import shutil
import hashlib
from pathlib import Path
from unittest.mock import patch

import forward_owner_relations as forward
from forward_owner_projection import ForwardOwnerProjection
from projection_copy import detached_copy
from relations import GuardedRelations
from test_forward_owner_relations import source_fixture, raw
from test_forward_owner_pipeline import fixture as projection_fixture, write_fixture
from live_relations import LiveRelations
from test_live_relations import SESSION, start, live, next_frame
from test_context_controller import context_fixture, bind


class ProjectionCopyTests(unittest.TestCase):
    def test_json_graph_matches_deepcopy_and_stays_detached(self):
        shared = [{'ok': True, 'value': 3, 'ids': [1, 2], 'reason': None}]
        original = {'before': shared, 'after': shared, 'text': 'x', 'float': 1.5}
        actual = detached_copy(original)
        self.assertEqual(actual, copy.deepcopy(original))
        self.assertIs(actual['before'], actual['after'])
        actual['before'][0]['ids'].append(4)
        self.assertEqual(original['before'][0]['ids'], [1, 2])
        cycle = []; cycle.append(cycle)
        copied = detached_copy(cycle)
        self.assertIs(copied[0], copied)
        self.assertIsNot(copied, cycle)

    def test_custom_objects_and_containers_keep_deepcopy_policy(self):
        class Custom:
            def __deepcopy__(self, memo):
                return 'custom-policy'
        class ListSubclass(list):
            pass
        original = {'custom': Custom(), 'list': ListSubclass([{'n': [1]}]),
                    'tuple': ([2],), 'set': {3}}
        expected, actual = copy.deepcopy(original), detached_copy(original)
        self.assertEqual(expected, actual)
        self.assertIs(type(actual['list']), ListSubclass)
        actual['list'][0]['n'].append(4)
        actual['tuple'][0].append(5)
        self.assertEqual(original['list'][0]['n'], [1])
        self.assertEqual(original['tuple'][0], [2])

    def test_forward_output_mutation_cannot_touch_input_or_later_results(self):
        _, _, _, frame, projector, hero, source, _, _ = projection_fixture()
        decoder = ForwardOwnerProjection(projector, controller_hero=hero)
        original_frame = copy.deepcopy(frame)
        first = decoder.project(frame, source)
        expected = copy.deepcopy(first)
        row = first['relations'][0]
        row['identity_evidence'][0]['guard_ids'].clear()
        row['position_candidate']['value'].append(55)
        row['owned_fields'][row['owned_field_prefix'] + 'position_candidate']['value'].clear()
        first['target']['pid'] += 1
        self.assertEqual(frame, original_frame)
        self.assertEqual(decoder.project(frame, source), expected)

    def test_context_guard_proof_remains_detached(self):
        profile, values = context_fixture()
        decoder, frame, _, _ = bind(profile, values)
        # Nonstandard nested extras also remain detached; normal guard objects
        # contain only immutable JSON scalars.
        frame['guards_before'][0]['extra'] = {'nested': [1]}
        first = decoder.project(frame)
        expected = copy.deepcopy(first)
        first['selector_evidence']['guards_before'][0]['extra']['nested'].append(2)
        first['selector_evidence']['guards_after'][0]['ok'] = False
        self.assertEqual(frame['guards_before'][0]['extra'], {'nested': [1]})
        self.assertTrue(frame['guards_after'][0]['ok'])
        self.assertEqual(decoder.project(frame), expected)


class LiveForwardScopeTests(unittest.TestCase):
    def test_forward_hero_profile_mutation_invalidates_scope_and_recovers_fresh(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            profile, frame, manifest, options = write_fixture(root)
            decoder = LiveRelations(root, SESSION, 1, **options)
            decoder.consume(raw(start(profile, manifest)))
            first = decoder.consume(raw(live(frame)))
            self.assertEqual(first['forward_owner_projection']['relations'][0]
                             ['controller_hero_asset_label_candidate'], 'Synthetic Hero')
            hero = decoder.forward.hero.relations
            original = hero.profile['guards'][0]['bytes_hex']
            hero.profile['guards'][0]['bytes_hex'] = 'ff' * (len(original) // 2)
            second_frame = next_frame(frame)
            second = decoder.consume(raw(live(second_frame, 2)))
            row = second['forward_owner_projection']['relations'][0]
            self.assertIsNone(row['controller_hero_asset_label_candidate'])
            self.assertIsNotNone(row['position_candidate'])
            hero.profile['guards'][0]['bytes_hex'] = original
            third = decoder.consume(raw(live(next_frame(second_frame), 3)))
            self.assertEqual(third['forward_owner_projection']['relations'][0]
                             ['controller_hero_asset_label_candidate'], 'Synthetic Hero')
            self.assertIsNone(hero._active_checks)
            self.assertIsNone(decoder.forward.relations._active_checks)

    def test_projection_exception_closes_all_forward_frame_scopes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            profile, frame, manifest, options = write_fixture(root)
            decoder = LiveRelations(root, SESSION, 1, **options)
            decoder.consume(raw(start(profile, manifest)))
            with patch('live_relations.project_frame', side_effect=ValueError('fixture_projection')):
                with self.assertRaisesRegex(ValueError, 'fixture_projection'):
                    decoder.consume(raw(live(frame)))
            self.assertTrue(decoder.failed)
            self.assertIsNone(decoder.projector._active_checks)
            self.assertIsNone(decoder.forward.relations._active_checks)
            self.assertIsNone(decoder.forward.hero.relations._active_checks)


class IsolatedComposerImportTests(unittest.TestCase):
    def test_runtime_compose_shim_loads_pinned_context_module_and_copy_dependency(self):
        decoder_root = Path(__file__).resolve().parent
        project_root = decoder_root.parents[1]
        with tempfile.TemporaryDirectory(prefix='projection runtime ') as temp:
            root = Path(temp)
            bundle = root / 'bundle'
            scripts = bundle / 'tools/entity-decoder'
            scripts.mkdir(parents=True)
            for path in decoder_root.glob('*.py'):
                if not path.name.startswith('test_'):
                    shutil.copyfile(path, scripts / path.name)
            shutil.copytree(project_root / 'overwatch_decoder', bundle / 'overwatch_decoder',
                            ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
            private = root / 'private'
            private.mkdir()
            module = private / 'context_controller.py'
            shutil.copyfile(decoder_root / 'context_controller.py', module)
            pin = hashlib.sha256(module.read_bytes()).hexdigest()
            composer = private / 'compose.py'
            composer.write_text(
                'from pathlib import Path\n'
                'import hashlib, json, sys, types\n'
                'p=Path(__file__).with_name("context_controller.py")\n'
                'raw=p.read_bytes()\n'
                'assert hashlib.sha256(raw).hexdigest()=="' + pin + '"\n'
                'm=types.ModuleType("private_context");exec(compile(raw,str(p),"exec"),m.__dict__)\n'
                'import live_relations, forward_owner_projection, projection_copy\n'
                'print(json.dumps({"isolated":sys.flags.isolated,"copy_path":projection_copy.__file__}))\n')
            command = [sys.executable, '-I', str(scripts / 'runtime_producer.py'), '--compose',
                       str(composer), hashlib.sha256(composer.read_bytes()).hexdigest(), '--']
            result = subprocess.run(command, cwd=root, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            output = json.loads(result.stdout)
            self.assertEqual(output['isolated'], 1)
            self.assertEqual(Path(output['copy_path']), scripts / 'projection_copy.py')
            (scripts / 'projection_copy.py').unlink()
            shutil.rmtree(scripts / '__pycache__', ignore_errors=True)
            missing = subprocess.run(command, cwd=root, capture_output=True, timeout=10)
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn(b'projection_copy', missing.stderr)


class AcquisitionScopeTests(unittest.TestCase):
    def setUp(self):
        pr, cr, artifacts, _ = source_fixture()
        contract = json.loads(cr)
        self.profile = pr
        self.evidence = artifacts[contract['source']['evidence_sha256']]
        self.manifest = json.loads(artifacts[contract['acquisition_manifest_sha256']])
        self.recipe = json.loads(artifacts[contract['source']['recipe_sha256']])
        self.relations = GuardedRelations(pr)

    def verify(self, **changes):
        args = dict(evidence=self.evidence, manifest=self.manifest, recipe=self.recipe,
                    relations=self.relations)
        args.update(changes)
        return forward._verify_acquisition(**args)

    def test_exact_bytes_share_only_within_explicit_scope(self):
        original = forward._verify_acquisition_uncached
        with patch.object(forward, '_verify_acquisition_uncached', wraps=original) as verify:
            self.verify(); self.verify()
            self.assertEqual(verify.call_count, 2)
            with forward.acquisition_validation_scope():
                self.verify()
                with forward.acquisition_validation_scope(reuse_current=True):
                    self.verify(evidence=bytes(bytearray(self.evidence)),
                                manifest=copy.deepcopy(self.manifest),
                                recipe=copy.deepcopy(self.recipe), relations=GuardedRelations(self.profile))
                self.assertEqual(verify.call_count, 3)
            self.verify()
            self.assertEqual(verify.call_count, 4)
            with forward.acquisition_validation_scope(): self.verify()
            self.assertEqual(verify.call_count, 5)
        self.assertIsNone(forward._ACQUISITION_VALIDATION.get())

    def test_changed_source_and_restoration_never_resume_old_proof(self):
        original = forward._verify_acquisition_uncached
        with patch.object(forward, '_verify_acquisition_uncached', wraps=original) as verify:
            with forward.acquisition_validation_scope():
                self.verify()
                self.verify(evidence=b' ' + self.evidence)
                self.verify()
            self.assertEqual(verify.call_count, 3)

    def test_mutated_guards_target_manifest_recipe_or_fields_revalidate(self):
        for kind in ('guard', 'guard_type', 'target', 'manifest', 'recipe', 'fields'):
            with self.subTest(kind=kind):
                r = GuardedRelations(self.profile)
                m, recipe = copy.deepcopy(self.manifest), copy.deepcopy(self.recipe)
                original = forward._verify_acquisition_uncached
                with patch.object(forward, '_verify_acquisition_uncached', wraps=original) as verify:
                    with forward.acquisition_validation_scope():
                        self.verify(relations=r, manifest=m, recipe=recipe)
                        if kind == 'guard': r.guards[0]['bytes_hex'] = 'ff' * (len(r.guards[0]['bytes_hex']) // 2)
                        if kind == 'guard_type': r.guards[0]['address'] = float(r.guards[0]['address'])
                        if kind == 'target': r.target['pid'] += 1
                        if kind == 'manifest': m['revision'] = 'other'
                        if kind == 'recipe': recipe['stages'].append({'name': 'extra'})
                        if kind == 'fields': r.fields['extra'] = {'type': 'i32'}
                        with self.assertRaises(ValueError): self.verify(relations=r, manifest=m, recipe=recipe)
                        self.verify()
                    self.assertEqual(verify.call_count, 3)

    def test_exception_closes_scope_and_caught_failure_disables_reuse(self):
        original = forward._verify_acquisition_uncached
        with patch.object(forward, '_verify_acquisition_uncached', wraps=original) as verify:
            with forward.acquisition_validation_scope():
                self.verify()
                bad = self.evidence.replace(b'"matches":true', b'"matches":false', 1)
                self.assertNotEqual(bad, self.evidence)
                with self.assertRaises(ValueError): self.verify(evidence=bad)
                self.verify()
            self.assertEqual(verify.call_count, 3)
            with self.assertRaisesRegex(RuntimeError, 'fixture'):
                with forward.acquisition_validation_scope():
                    self.verify()
                    raise RuntimeError('fixture')
            self.assertIsNone(forward._ACQUISITION_VALIDATION.get())
            self.verify()
            self.assertEqual(verify.call_count, 5)

    def test_mutable_evidence_is_always_revalidated(self):
        original = forward._verify_acquisition_uncached
        evidence = bytearray(self.evidence)
        with patch.object(forward, '_verify_acquisition_uncached', wraps=original) as verify:
            with forward.acquisition_validation_scope():
                self.verify(evidence=evidence)
                evidence[:] = evidence.replace(b'"matches":true', b'"matches":false', 1)
                with self.assertRaises(ValueError): self.verify(evidence=evidence)
                self.verify()
            self.assertEqual(verify.call_count, 3)

    def test_returned_collections_cannot_mutate_cached_proof(self):
        original = forward._verify_acquisition_uncached
        evidence = self.evidence.replace(b'{"fields":', b'{"kind":"field_collection","fixture":{"n":[1]}}\n{"fields":', 1)
        # Insert a collection immediately before the final event, preserving all
        # guard reads and final profile validation. This is a synthetic fixture.
        if evidence == self.evidence:
            lines = self.evidence.splitlines(keepends=True)
            evidence = b''.join(lines[:-1]) + b'{"kind":"field_collection","fixture":{"n":[1]}}\n' + lines[-1]
        with patch.object(forward, '_verify_acquisition_uncached', wraps=original) as verify:
            with forward.acquisition_validation_scope():
                first = self.verify(evidence=evidence)
                first[0]['fixture']['n'].append(2)
                self.assertEqual(self.verify(evidence=evidence)[0]['fixture']['n'], [1])
            self.assertEqual(verify.call_count, 1)


if __name__ == '__main__':
    unittest.main()
