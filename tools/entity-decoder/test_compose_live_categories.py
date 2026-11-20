"""Portable composition rejects stale epochs, missing reviews and role conflicts."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from categories import InvalidCategoryEvidence
from compose_live_categories import compose_live_categories, main
from live_categories import GuardedLiveCategories
from test_live_categories import live_category_fixture


def raw(value):
    return json.dumps(value).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def composition_fixture():
    profile, frame, old, artifacts, admission, mode, native, roster, manifest, session, segment = live_category_fixture()
    evidence = b''.join(raw(dict(kind='read', id=i, purpose='fixture-source', stage='fixture-current',
        attempted=True, address=field['address'], requested_bytes=4, returned_bytes=4, error=None,
        bytes_hex=(frame['fields'][field['name']]['value'] & 0xffffffff).to_bytes(4, 'little').hex())) + b'\n'
        for i, field in enumerate(profile['fields']) if field['name'].startswith('category_'))
    recipe = b'synthetic bounded acquisition recipe'
    manifest.update(recipe_sha256=sha(recipe), evidence_sha256=sha(evidence))
    session['recipe_sha256'] = sha(recipe)
    current = dict(schema='overwatch-decoder.live-controller-roster-review/1', reviewed=True,
        review_method='manual_current_controller_roster', complete=True, target=profile['target'],
        build_sha256=old['build_sha256'], mode_id=old['mode_id'], self_controller_object_key=old['self_controller_object_key'],
        sources=roster['sources'], controllers=[dict(controller_object_key=a['controller_object_key'], role=a['role'])
                                               for a in roster['anchors']])
    layout = dict(schema='overwatch-decoder.live-category-layout-review/1', reviewed=True,
        review_method='manual_recipe_native_layout', build_sha256=old['build_sha256'],
        profile_sha256=old['profile_sha256'], recipe_sha256=sha(recipe), native_review_sha256=old['native_review_sha256'],
        sources=native['sources'], controllers=[dict(controller_handle_field=f'controller_{i:04d}_handle_candidate_i32',
            controller_creation_key_field=f'controller_{i:04d}_manager_key_candidate_i32',
            body_handle_field=f'controller_{i:04d}_body_0000_handle_candidate_i32',
            body_creation_key_field=f'controller_{i:04d}_body_0000_manager_key_candidate_i32') for i in range(3)],
        bindings=copy.deepcopy(old['bindings']))
    for binding in layout['bindings']:
        binding['initial_read'] = dict(purpose='fixture-source', stage='fixture-current', requested_bytes=4, flags_byte_offset=0)
    for value in (current, layout):
        artifacts[sha(raw(value))] = raw(value)
    review = dict(schema='overwatch-decoder.live-category-composition-review/1', reviewed=True,
        review_method='manual_current_live_epoch', public_state_eligible=False, visibility='unknown',
        target=profile['target'], build_sha256=old['build_sha256'], mode_id=old['mode_id'],
        self_controller_object_key=old['self_controller_object_key'], profile_sha256=sha(raw(profile)),
        acquisition_manifest_sha256=sha(raw(manifest)), recipe_sha256=sha(recipe), evidence_sha256=sha(evidence),
        session_start_sha256=sha(raw(session)), segment_start_sha256=sha(raw(segment)),
        native_review_sha256=old['native_review_sha256'], roster_review_sha256=old['roster_review_sha256'],
        layout_review_sha256=sha(raw(layout)), current_roster_review_sha256=sha(raw(current)), sources=mode['sources'])
    inputs = dict(profile=raw(profile), acquisition_manifest=raw(manifest), evidence=evidence, recipe=recipe,
        session_start=raw(session), segment_start=raw(segment), composition_review=raw(review), artifacts=artifacts)
    return inputs, frame, admission, old


class ComposeLiveCategoriesTests(unittest.TestCase):
    def setUp(self):
        self.inputs, self.frame, self.admission, self.old = composition_fixture()

    def review(self, **updates):
        value = json.loads(self.inputs['composition_review']); value.update(updates)
        self.inputs['composition_review'] = raw(value)

    def artifact(self, key, mutate):
        review = json.loads(self.inputs['composition_review'])
        value = json.loads(self.inputs['artifacts'][review[key]])
        mutate(value)
        data = raw(value); digest = sha(data); self.inputs['artifacts'][digest] = data
        self.review(**{key: digest})

    def compose(self):
        return compose_live_categories(**self.inputs)

    def rebind_evidence(self, mutate):
        reads = [json.loads(line) for line in self.inputs['evidence'].splitlines()]
        mutate(reads)
        data = b''.join(raw(row) + b'\n' for row in reads); self.inputs['evidence'] = data
        manifest = json.loads(self.inputs['acquisition_manifest']); manifest['evidence_sha256'] = sha(data)
        self.inputs['acquisition_manifest'] = raw(manifest)
        self.review(evidence_sha256=sha(data), acquisition_manifest_sha256=sha(raw(manifest)))

    def test_explicit_review_projects_without_private_paths_or_final_recording(self):
        out = self.compose(); contract = json.loads(out['contract'])
        p = GuardedLiveCategories(self.inputs['profile'], out['contract'], out['artifacts'])
        admission = dict(self.admission, acquisition_manifest_sha256=p.acquisition_manifest_sha256, **p.source)
        projected = p.project(self.frame, admission=admission)
        self.assertEqual([row['relative_allegiance_candidate'] for row in projected['rows']], ['self', 'friendly', 'enemy'])
        self.assertFalse(projected['public_state_eligible']); self.assertFalse(projected['durability_verified'])
        self.assertEqual(projected['visibility'], 'unknown')
        self.assertNotIn('recording_manifest_sha256', contract)
        mode = json.loads(out['mode_review']); review = json.loads(self.inputs['composition_review'])
        for digest in (sha(self.inputs['composition_review']), review['layout_review_sha256'], review['current_roster_review_sha256']):
            self.assertIn(digest, mode['sources'])
        preflight = json.loads(out['preflight'])
        self.assertEqual([row['role'] for row in preflight['rows']], ['self', 'friendly', 'enemy'])
        self.assertNotEqual(sha(out['contract']), sha(raw(self.old)))

    def test_explicit_relative_conditions_resolve_only_supplied_offsets(self):
        def relative(layout):
            for b in layout['bindings']:
                for c in b['conditions']:
                    address = c.pop('address'); c.update(base_field=b['flags_field'], byte_offset=address - 0x6000 - int(b['flags_field'][-1]) * 4)
        self.artifact('layout_review_sha256', relative)
        self.assertEqual(len(json.loads(self.compose()['preflight'])['rows']), 3)

    def test_no_implicit_layout_or_current_review(self):
        for key in ('layout_review_sha256', 'current_roster_review_sha256'):
            with self.subTest(key=key):
                self.setUp(); review = json.loads(self.inputs['composition_review']); review.pop(key)
                self.inputs['composition_review'] = raw(review)
                with self.assertRaises(InvalidCategoryEvidence): self.compose()

    def test_review_cannot_self_assert_automatic_or_public_approval(self):
        for key, value in (('reviewed', False), ('review_method', 'automatic'), ('public_state_eligible', True), ('visibility', 'visible')):
            with self.subTest(key=key):
                self.setUp(); self.review(**{key: value})
                with self.assertRaisesRegex(InvalidCategoryEvidence, 'current_epoch_review_required'): self.compose()

    def test_old_epoch_review_rejects_new_session_or_segment(self):
        for name, key, value in (('session_start', 'session_id', 'later-session'), ('segment_start', 'segment', 2)):
            with self.subTest(name=name):
                self.setUp(); event = json.loads(self.inputs[name]); event[key] = value; self.inputs[name] = raw(event)
                with self.assertRaisesRegex(InvalidCategoryEvidence, 'epoch_pin_mismatch'): self.compose()

    def test_finite_manifest_cannot_be_substituted_for_live_review(self):
        self.review(recording_manifest_sha256='11' * 32)
        with self.assertRaisesRegex(InvalidCategoryEvidence, 'not_finite_recording'): self.compose()

    def test_all_acquisition_source_bytes_must_match(self):
        for key in ('profile', 'recipe', 'evidence'):
            with self.subTest(key=key):
                self.setUp(); self.inputs[key] += b' '
                with self.assertRaisesRegex(InvalidCategoryEvidence, 'acquisition_mismatch'): self.compose()

    def test_incomplete_acquisition_is_not_live_admission(self):
        manifest = json.loads(self.inputs['acquisition_manifest']); manifest['complete'] = False
        self.inputs['acquisition_manifest'] = raw(manifest)
        with self.assertRaisesRegex(InvalidCategoryEvidence, 'acquisition_mismatch'): self.compose()

    def test_layout_is_bound_to_build_profile_recipe_native_review(self):
        for key in ('build_sha256', 'profile_sha256', 'recipe_sha256', 'native_review_sha256'):
            with self.subTest(key=key):
                self.setUp(); self.artifact('layout_review_sha256', lambda x: x.update({key: '00' * 32}))
                with self.assertRaisesRegex(InvalidCategoryEvidence, 'layout_review_scope'): self.compose()

    def test_full_roster_must_be_explicit_complete_unique_and_self_anchored(self):
        changes = (lambda x: x.update(complete=False), lambda x: x['controllers'].append(x['controllers'][0]),
                   lambda x: x['controllers'][0].update(role='friendly'),
                   lambda x: x.update(target=dict(x['target'], creation_file_time=999)))
        for change in changes:
            self.setUp(); self.artifact('current_roster_review_sha256', change)
            with self.assertRaises(InvalidCategoryEvidence): self.compose()

    def test_current_roster_role_contradiction_rejected(self):
        self.artifact('current_roster_review_sha256', lambda x: x['controllers'][1].update(role='enemy'))
        with self.assertRaisesRegex(InvalidCategoryEvidence, 'anchor_conflict'): self.compose()

    def test_selected_unreviewed_controller_cannot_receive_semantics(self):
        self.artifact('current_roster_review_sha256', lambda x: x['controllers'].pop())
        with self.assertRaisesRegex(InvalidCategoryEvidence, 'unreviewed_or_duplicate'): self.compose()

    def test_initial_category_must_agree_with_reviewed_current_role(self):
        self.rebind_evidence(lambda rows: rows[1].update(bytes_hex=(128).to_bytes(4, 'little').hex()))
        with self.assertRaisesRegex(InvalidCategoryEvidence, 'category_roster_conflict'): self.compose()

    def test_initial_special_or_ambiguous_categories_are_not_admitted(self):
        for value in (4 | 8, 8 | 128, 0, 2048):
            self.setUp(); self.rebind_evidence(lambda rows: rows[1].update(bytes_hex=value.to_bytes(4, 'little').hex()))
            with self.assertRaisesRegex(InvalidCategoryEvidence, 'initial_category_unsupported'): self.compose()

    def test_actual_initial_read_must_be_unique_complete_and_selected(self):
        cases = (lambda rows: rows.pop(), lambda rows: rows.append(copy.deepcopy(rows[0])),
                 lambda rows: rows[0].update(returned_bytes=0), lambda rows: rows[0].update(attempted=False),
                 lambda rows: rows[0].update(bytes_hex='08'), lambda rows: rows[0].update(address=999))
        for change in cases:
            self.setUp(); self.rebind_evidence(change)
            with self.assertRaises(InvalidCategoryEvidence): self.compose()

    def test_missing_condition_layout_never_gets_a_default(self):
        self.artifact('layout_review_sha256', lambda x: x['bindings'][0]['conditions'][0].pop('address'))
        with self.assertRaisesRegex(InvalidCategoryEvidence, 'condition_layout_missing'): self.compose()

    def test_ambiguous_condition_or_selector_not_admitted(self):
        self.artifact('layout_review_sha256', lambda x: x['bindings'][0]['conditions'][0].update(base_field='category_0', byte_offset=0))
        with self.assertRaisesRegex(InvalidCategoryEvidence, 'condition_address_ambiguous'): self.compose()
        self.setUp(); self.artifact('layout_review_sha256', lambda x: x['bindings'][0]['initial_read'].pop('flags_byte_offset'))
        with self.assertRaisesRegex(InvalidCategoryEvidence, 'initial_read_layout'): self.compose()

    def test_existing_guarded_constructor_still_rejects_unproven_conditions(self):
        self.artifact('layout_review_sha256', lambda x: x['bindings'][0]['conditions'][0].update(address=999))
        with self.assertRaisesRegex(InvalidCategoryEvidence, 'unguarded_route_condition'): self.compose()

    def test_corrupt_artifact_and_duplicate_json_keys_rejected(self):
        review = json.loads(self.inputs['composition_review']); digest = review['layout_review_sha256']
        self.inputs['artifacts'][digest] += b' '
        with self.assertRaisesRegex(InvalidCategoryEvidence, 'artifact_hash_or_size'): self.compose()
        self.setUp(); self.inputs['composition_review'] = b'{"schema":"a","schema":"b"}'
        with self.assertRaisesRegex(InvalidCategoryEvidence, 'invalid_json'): self.compose()

    def test_cli_writes_only_an_explicit_new_output_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); paths = {}
            for digest, data in self.inputs['artifacts'].items():
                path = root / digest; path.write_bytes(data); paths[digest] = str(path)
            mapping = root / 'paths.json'; mapping.write_bytes(raw(paths)); argv = ['--artifacts', str(mapping), '--output', str(root / 'output')]
            for key, data in self.inputs.items():
                if key == 'artifacts': continue
                path = root / (key + '.json'); path.write_bytes(data); argv.extend(['--' + key.replace('_', '-'), str(path)])
            main(argv)
            self.assertEqual(set(p.name for p in (root / 'output').iterdir()), {'contract.json', 'mode_review.json', 'preflight.json', 'artifacts.json', 'artifacts'})
            outmap = json.loads((root / 'output/artifacts.json').read_bytes())
            p = GuardedLiveCategories(self.inputs['profile'], (root / 'output/contract.json').read_bytes(),
                                      {digest: Path(path).read_bytes() for digest, path in outmap.items()})
            self.assertEqual(p.live_scope['session_id'], 'fixture-live')
            with self.assertRaises(FileExistsError): main(argv)


if __name__ == '__main__':
    unittest.main()
