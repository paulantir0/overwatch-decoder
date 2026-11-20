"""Synthetic context-route contracts; no application bytes, offsets or accounts."""
import copy
import hashlib
import json
import unittest

from context_controller import GuardedContextController, InvalidContextEvidence
from test_relations import fixture, prepare, change_word


def encoded(value):
    return json.dumps(value, sort_keys=True).encode()


def context_fixture(rows=2, prefix=None):
    profile, values = fixture(rows)
    if prefix:
        assert rows == 1
        for field in profile['fields']:
            old = field['name']
            field['name'] = old.replace('controller_0000', prefix)
            values[field['name']] = values.pop(old)
    selected = next(f['name'].removesuffix('_manager_key_candidate_i32') for f in profile['fields']
                    if f['name'].endswith('_manager_key_candidate_i32') and '_body_' not in f['name'])
    value = values[selected + '_manager_key_candidate_i32']
    profile['fields'].append(dict(name='context_selector_i32', type='i32', address=0x9000))
    profile['guards'].append(dict(address=0x9000, bytes_hex=(value & 0xffffffff).to_bytes(4, 'little').hex()))
    values['context_selector_i32'] = value
    return profile, values


def bind(profile, values, *, prefixes=None, scope='complete_profile_census', contract_edit=None):
    relations, frame = prepare(profile, values)
    artifacts = {}
    def art(obj):
        raw = encoded(obj)
        digest = hashlib.sha256(raw).hexdigest()
        artifacts[digest] = raw
        return digest
    recipe = art(dict(schema='overwatch-decoder.acquisition-recipe/1', target={k: profile['target'][k]
                      for k in ('image_name', 'architecture', 'executable_sha256')}, stages=[]))
    evidence = art(dict(synthetic=True))
    manifest = art(dict(schema='overwatch-decoder.acquisition-result/1', complete=True, error=None,
                        target=profile['target'], profile_sha256=relations.hash,
                        recipe_sha256=recipe, evidence_sha256=evidence))
    review = art(dict(schema='overwatch-decoder.native-context-controller-review/1', reviewed=True,
                      review_method='native_consumer_trace', build_sha256=profile['target']['executable_sha256'],
                      required_conditions=['guarded_controller_enumeration', 'world_context_selector',
                                           'exact_controller_key_match'], sources=[art(dict(synthetic_trace=True))]))
    contract = dict(schema='overwatch-decoder.context-controller-contract/1', target=profile['target'],
                    profile_sha256=relations.hash, build_sha256=profile['target']['executable_sha256'],
                    source=dict(recipe_sha256=recipe, evidence_sha256=evidence),
                    acquisition_manifest_sha256=manifest, native_review_sha256=review,
                    selection_scope=scope, candidate_prefixes=prefixes if prefixes is not None else relations.prefixes,
                    selector_field='context_selector_i32', required_guard_ids=relations.guard_ids['context_selector_i32'].copy())
    if contract_edit:
        contract_edit(contract, artifacts)
    return GuardedContextController(json.dumps(profile).encode(), encoded(contract), artifacts), frame, contract, artifacts


class ContextTests(unittest.TestCase):
    def test_current_unique_controller_and_body_without_role_promotion(self):
        p, v = context_fixture()
        d, f, _, _ = bind(p, v)
        out = d.project(f)
        self.assertEqual(out['status'], 'observed')
        self.assertEqual(out['body_status'], 'observed')
        self.assertEqual(out['controller_object_key'], d.relations.project(f)['relations'][0]['controller_object_key'])
        self.assertFalse(out['local_control_semantics_validated'])
        self.assertFalse(out['playable_body_validated'])
        self.assertNotIn('address', json.dumps(out))
        self.assertEqual(out['selector_evidence']['guard_ids'], list(range(len(d.relations.guards))))

    def test_selector_changes_only_under_fresh_guarded_epoch(self):
        p, v = context_fixture()
        d, f, _, _ = bind(p, v)
        first = d.project(f)
        changed = copy.deepcopy(f)
        changed['fields']['context_selector_i32']['value'] = v['controller_0001_manager_key_candidate_i32']
        self.assertEqual(d.project(changed)['status'], 'unknown')
        change_word(p, v, len(p['fields']) - 1, v['controller_0001_manager_key_candidate_i32'] & 0xffffffff)
        d2, f2, _, _ = bind(p, v)
        second = d2.project(f2)
        self.assertEqual(second['status'], 'observed')
        self.assertNotEqual(first['controller_object_key'], second['controller_object_key'])
        self.assertEqual(d2.project(f)['reason'], 'profile_mismatch')

    def test_nonselected_identity_and_guard_failures_make_selection_unknown(self):
        p, v = context_fixture()
        d, f, _, _ = bind(p, v)
        for kind in ('nonselected', 'guard', 'ids', 'bracket', 'target'):
            bad = copy.deepcopy(f)
            if kind == 'nonselected':
                bad['fields']['controller_0001_handle_candidate_i32']['status'] = 'unknown'
            elif kind == 'guard':
                bad['guards_after'][-1]['ok'] = False
            elif kind == 'ids':
                bad['fields']['context_selector_i32']['guard_ids'] = []
            elif kind == 'bracket':
                bad['guards_before'][-1]['end_ticks'] = 50
            else:
                bad['target']['pid'] += 1
            with self.subTest(kind=kind):
                out = d.project(bad)
                self.assertEqual(out['status'], 'unknown')
                self.assertIsNone(out['controller_object_key'])
                self.assertIsNone(out['body_object_key'])
        self.assertEqual(d.project(f, gap=True)['reason'], 'scheduled_gap')
        skipped = copy.deepcopy(f)
        skipped['skipped_intervals_before'] = 1
        self.assertEqual(d.project(skipped)['reason'], 'scheduled_gap')
        skipped['skipped_intervals_before'] = -1
        self.assertEqual(d.project(skipped)['reason'], 'invalid_gap_metadata')
        self.assertEqual(d.project(f)['status'], 'observed')

    def test_no_match_duplicate_key_and_duplicate_handle_are_unknown(self):
        for mode in ('zero', 'unmatched', 'duplicate_key', 'duplicate_handle'):
            p, v = context_fixture()
            if mode in ('zero', 'unmatched'):
                change_word(p, v, len(p['fields']) - 1, 0 if mode == 'zero' else 1234)
            else:
                i = 6 if mode == 'duplicate_key' else 5
                source = 1 if mode == 'duplicate_key' else 0
                change_word(p, v, i, v[p['fields'][source]['name']] & 0xffffffff)
            d, f, _, _ = bind(p, v)
            with self.subTest(mode=mode):
                self.assertEqual(d.project(f)['status'], 'unknown')

    def test_custom_minimal_anchor_has_no_extra_primary_requirement(self):
        p, v = context_fixture(rows=1, prefix='context_anchor_0000')
        d, f, _, _ = bind(p, v, prefixes=['context_anchor_0000'], scope='guarded_selected_anchor')
        self.assertEqual(d.relations.prefixes, [])
        self.assertEqual(d.project(f)['status'], 'observed')
        self.assertEqual(d.project(f)['body_status'], 'observed')

    def test_body_unavailable_or_failed_does_not_recycle_body(self):
        p, v = context_fixture(rows=1)
        d, f, _, _ = bind(p, v)
        old = d.project(f)
        for suffix in ('_body_0000_handle_candidate_i32', '_body_0000_manager_key_candidate_i32'):
            name = 'controller_0000' + suffix
            p['fields'] = [x for x in p['fields'] if x['name'] != name]
            v.pop(name)
        change_word(p, v, 2, 0)
        d2, f2, _, _ = bind(p, v)
        out = d2.project(f2)
        self.assertEqual(out['controller_object_key'], old['controller_object_key'])
        self.assertIsNone(out['body_object_key'])
        self.assertEqual(out['body_key_candidate'], 0)
        self.assertIsNotNone(out['body_reference_evidence'])
        self.assertEqual(d2.project(f)['status'], 'unknown')

    def test_fresh_replacement_body_keeps_controller_and_rejects_old_frame(self):
        p, v = context_fixture(rows=1)
        d, f, _, _ = bind(p, v)
        old = d.project(f)
        change_word(p, v, 2, 0x80000098)
        change_word(p, v, 3, 0x80000099, address=0x7000)
        change_word(p, v, 4, 0x80000098, address=0x7008)
        new, fresh, _, _ = bind(p, v)
        out = new.project(fresh)
        self.assertEqual(out['controller_object_key'], old['controller_object_key'])
        self.assertNotEqual(out['body_object_key'], old['body_object_key'])
        self.assertIsNone(new.project(f)['body_object_key'])
        bad = copy.deepcopy(fresh)
        bad['fields']['controller_0000_part51_0000_body_key_candidate_i32']['value'] += 1
        failed = new.project(bad)
        self.assertEqual(failed['status'], 'observed')
        self.assertIsNone(failed['body_object_key'])
        self.assertEqual(failed['body_reason'], 'body_key_mismatch')

    def test_selected_anchor_requires_one_prefix_and_all_selector_guards(self):
        p, v = context_fixture()
        with self.assertRaises(InvalidContextEvidence):
            bind(p, v, scope='guarded_selected_anchor')
        selector_guard = p['guards'].pop()
        p['fields'][-1]['guards'] = [selector_guard]
        # The selector now has every guard, but identity words omit its private
        # guard; selector checking still catches failure of that dependency.
        d, f, _, _ = bind(p, v)
        f['guards_after'][-1]['ok'] = False
        self.assertEqual(d.project(f)['status'], 'unknown')
        p['fields'][0]['guards'] = [dict(address=0xa000, bytes_hex='00')]
        with self.assertRaises(InvalidContextEvidence):
            bind(p, v)

    def test_unrelated_optional_local_guard_does_not_poison_context(self):
        p, v = context_fixture()
        p['fields'].append(dict(name='optional_cache_word', type='i32', address=0xb000,
                                guards=[dict(address=0xb100, bytes_hex='42')]))
        v['optional_cache_word'] = 12
        d, f, c, _ = bind(p, v)
        self.assertEqual(len(d.relations.guards), len(c['required_guard_ids']) + 1)
        expected = d.project(f)
        for phase in ('before', 'after'):
            bad = copy.deepcopy(f)
            bad['guards_' + phase][-1]['ok'] = False
            bad['fields']['optional_cache_word']['status'] = 'unknown'
            out = d.project(bad)
            self.assertEqual(out['status'], 'observed')
            self.assertEqual(out['body_status'], 'observed')
            self.assertEqual(out['controller_object_key'], expected['controller_object_key'])
            self.assertEqual(out['body_object_key'], expected['body_object_key'])
            self.assertNotIn(len(d.relations.guards) - 1, out['selector_evidence']['guard_ids'])
        # No optional dependency is discarded when it is actually declared on
        # the selector: the same failure must then invalidate selection.
        p['fields'][-2]['guards'] = p['fields'][-1]['guards'].copy()
        d, f, _, _ = bind(p, v)
        f['guards_after'][-1]['ok'] = False
        self.assertEqual(d.project(f)['status'], 'unknown')

    def test_every_core_local_dependency_must_still_be_on_selector(self):
        for prefix in ('controller_0000', 'controller_0001'):
            for suffix in ('_handle_candidate_i32', '_manager_key_candidate_i32',
                           '_part51_0000_body_key_candidate_i32', '_body_0000_handle_candidate_i32',
                           '_body_0000_manager_key_candidate_i32'):
                p, v = context_fixture()
                field = next(f for f in p['fields'] if f['name'] == prefix + suffix)
                field['guards'] = [dict(address=0xb100, bytes_hex='42')]
                with self.subTest(prefix=prefix, suffix=suffix), self.assertRaisesRegex(InvalidContextEvidence, 'incomplete_selector_guards'):
                    bind(p, v)
                p['fields'][-1]['guards'] = field['guards'].copy()
                d, frame, _, _ = bind(p, v)
                frame['guards_before'][-1]['ok'] = False
                self.assertEqual(d.project(frame)['status'], 'unknown')

    def test_optional_global_guard_remains_a_real_selector_dependency(self):
        p, v = context_fixture()
        p['guards'].append(dict(address=0xb100, bytes_hex='42'))
        d, f, c, _ = bind(p, v)
        self.assertIn(len(d.relations.guards) - 1, c['required_guard_ids'])
        f['guards_before'][-1]['ok'] = False
        self.assertEqual(d.project(f)['status'], 'unknown')

    def test_required_ids_remain_exact_ordered_integer_dependencies(self):
        for mutate in (lambda ids: ids[:-1], lambda ids: ids + [ids[-1]],
                       lambda ids: list(reversed(ids)), lambda ids: [False] + ids[1:]):
            p, v = context_fixture()
            with self.subTest(mutate=mutate), self.assertRaisesRegex(InvalidContextEvidence, 'incomplete_selector_guards'):
                bind(p, v, contract_edit=lambda c, a: c.update(required_guard_ids=mutate(c['required_guard_ids'])))

    def test_omitted_census_fixed_key_and_invalid_source_rejected(self):
        p, v = context_fixture()
        edits = [lambda c,a:c.update(candidate_prefixes=['controller_0000']),
                 lambda c,a:c.update(self_controller_object_key='invented'),
                 lambda c,a:c.update(required_guard_ids=c['required_guard_ids'][:-1]),
                 lambda c,a:c.update(build_sha256='00'*32),
                 lambda c,a:a.update({c['source']['evidence_sha256']:b'tampered'}),
                 lambda c,a:c.update(acquisition_manifest_sha256='00'*32)]
        for edit in edits:
            with self.subTest(edit=edit), self.assertRaises(InvalidContextEvidence):
                bind(p, v, contract_edit=edit)

    def test_same_storage_identity_alias_rejected_and_output_detached(self):
        p, v = context_fixture()
        d, f, _, _ = bind(p, v)
        out = d.project(f)
        out['selector_evidence']['guards_before'][0]['ok'] = False
        out['candidate_identity_evidence'][0]['words'][0]['value'] = 0
        self.assertEqual(d.project(f)['status'], 'observed')
        p['fields'][-1]['address'] = p['fields'][1]['address']
        with self.assertRaises(InvalidContextEvidence):
            bind(p, v)


if __name__ == '__main__':
    unittest.main()
