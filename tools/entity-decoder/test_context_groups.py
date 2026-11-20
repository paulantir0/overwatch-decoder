"""Same-frame group comparisons under explicit finite context scope reviews."""
import copy
import unittest
from unittest.mock import patch

from categories import InvalidCategoryEvidence
from context_groups import GuardedContextGroups
from test_categories import raw, sha
from test_raw_categories import raw_fixture
from test_context_controller import bind, encoded


def group_fixture(selector_index=0, additional_anchor=False):
    profile, values, _, category, artifacts, _, _ = raw_fixture()
    if additional_anchor:
        mapping = {}
        for field in profile['fields']:
            name = field['name']
            if name.startswith('controller_0002_'):
                mapping[name] = name.replace('controller_0002', 'context_anchor_0000')
                field['name'] = mapping[name]
        values = {mapping.get(k, k): v for k, v in values.items()}
        for key in ('body_handle_field', 'body_creation_key_field'):
            category['bindings'][2][key] = mapping[category['bindings'][2][key]]
        category['additional_relation_prefixes'] = ['context_anchor_0000']
        selected = values['context_anchor_0000_manager_key_candidate_i32']
    else:
        selected = values[f'controller_{selector_index:04}_manager_key_candidate_i32']
    profile['fields'].append(dict(name='context_selector_i32', type='i32', address=0x9000))
    profile['guards'].append(dict(address=0x9000, bytes_hex=(selected & 0xffffffff).to_bytes(4, 'little').hex()))
    values['context_selector_i32'] = selected
    context, frame, context_contract, context_artifacts = bind(profile, values,
        prefixes=['context_anchor_0000'] if additional_anchor else None,
        scope='guarded_selected_anchor' if additional_anchor else 'complete_profile_census')
    artifacts.update(context_artifacts)
    category.update(profile_sha256=context.relations.hash, source=context.source,
                    acquisition_manifest_sha256=context.acquisition_manifest_sha256)
    category_raw, context_raw = raw(category), encoded(context_contract)
    def add(value):
        data = raw(value)
        artifacts[sha(data)] = data
        return sha(data)
    review = dict(schema='overwatch-decoder.two-group-category-review/1', reviewed=True,
                  review_method='controlled_two_group_context_holdout',
                  build_sha256=profile['target']['executable_sha256'],
                  category_native_review_sha256=category['native_review_sha256'],
                  context_native_review_sha256=context.native_review_sha256, mode_id='synthetic-two-group-mode',
                  category_groups=[dict(category=0, group='group-a'), dict(category=1, group='group-b')],
                  sources=[add(dict(synthetic_holdout=True))])
    contract = dict(schema='overwatch-decoder.context-group-contract/1', target=profile['target'],
                    profile_sha256=context.relations.hash, build_sha256=profile['target']['executable_sha256'],
                    source=context.source, acquisition_manifest_sha256=context.acquisition_manifest_sha256,
                    category_contract_sha256=sha(category_raw), context_contract_sha256=sha(context_raw),
                    two_group_review_sha256=add(review),
                    frame_scope=dict(first_sequence=0, last_sequence=10, start_ticks=0,
                                     end_ticks=500, monotonic_frequency=1000))
    scope = {k: copy.deepcopy(v) for k, v in contract.items() if k != 'schema'}
    scope.update(schema='overwatch-decoder.context-group-epoch-review/1', reviewed=True, review_method='controlled_context_epoch',
                 context_use='controlled_player_context', spectator_supported=False,
                 sources=[add(dict(synthetic_epoch=True))])
    contract['context_scope_review_sha256'] = add(scope)
    return profile, frame, category_raw, context_raw, contract, artifacts, scope, review


class ContextGroupTests(unittest.TestCase):
    def setUp(self):
        (self.profile, self.frame, self.category_raw, self.context_raw, self.contract,
         self.artifacts, self.scope, self.review) = group_fixture()
        self.projector = self.make()

    def make(self):
        return GuardedContextGroups(raw(self.profile), self.category_raw, self.context_raw,
                                    raw(self.contract), self.artifacts)

    def replace(self, key, value):
        data = raw(value)
        self.artifacts[sha(data)] = data
        self.contract[key] = sha(data)

    def test_current_context_without_self_or_roster_keys(self):
        result = self.projector.project(self.frame)
        self.assertEqual(result['status'], 'observed')
        self.assertEqual([r['global_group_candidate'] for r in result['rows']], ['group-a', 'group-a', 'group-b'])
        self.assertEqual([r['group_relation_candidate'] for r in result['rows']], ['same_group', 'same_group', 'opposing_group'])
        self.assertEqual(result['native_frame_sha256'], sha(encoded(self.frame).replace(b': ', b':').replace(b', ', b',')))
        for row in result['rows']:
            self.assertIsNone(row['team_candidate'])
            self.assertIsNone(row['relative_allegiance_candidate'])
            self.assertFalse(row['public_state_eligible'])
        self.assertFalse(result['automatic_spectator_detection'])
        self.assertFalse(result['local_control_semantics_validated'])

    def test_selected_other_group_changes_relative_comparison_not_global_map(self):
        profile, frame, cat, ctx, contract, artifacts, _, _ = group_fixture(2)
        other = GuardedContextGroups(raw(profile), cat, ctx, raw(contract), artifacts)
        result = other.project(frame)
        self.assertEqual([r['global_group_candidate'] for r in result['rows']], ['group-a', 'group-a', 'group-b'])
        self.assertEqual([r['group_relation_candidate'] for r in result['rows']], ['opposing_group', 'opposing_group', 'same_group'])
        old = self.projector.project(frame)
        self.assertTrue(all(r['group_relation_candidate'] is None for r in old['rows']))

    def test_separate_minimal_anchor_can_compare_primary_rows(self):
        profile, frame, cat, ctx, contract, artifacts, _, _ = group_fixture(additional_anchor=True)
        projector = GuardedContextGroups(raw(profile), cat, ctx, raw(contract), artifacts)
        result = projector.project(frame)
        self.assertEqual(result['status'], 'observed')
        self.assertEqual(result['rows'][-1]['controller_prefix'], 'context_anchor_0000')
        self.assertEqual([r['group_relation_candidate'] for r in result['rows']],
                         ['opposing_group', 'opposing_group', 'same_group'])

    def test_unknown_selector_body_or_anchor_category_prevents_every_comparison(self):
        for field in ('context_selector_i32', 'controller_0000_body_0000_handle_candidate_i32',
                      'category_0', 'category_high_0'):
            frame = copy.deepcopy(self.frame)
            frame['fields'][field]['status'] = 'unknown'
            result = self.projector.project(frame)
            self.assertEqual(result['status'], 'unknown', field)
            self.assertTrue(all(r['group_relation_candidate'] is None for r in result['rows']), field)
        self.assertEqual(self.projector.project(self.frame)['status'], 'observed')

    def test_one_unknown_actor_does_not_borrow_old_category(self):
        frame = copy.deepcopy(self.frame)
        frame['fields']['category_1']['status'] = 'unknown'
        result = self.projector.project(frame)
        self.assertIsNone(result['rows'][1]['group_relation_candidate'])
        self.assertEqual(result['rows'][2]['group_relation_candidate'], 'opposing_group')
        self.assertEqual(self.projector.project(self.frame)['rows'][1]['group_relation_candidate'], 'same_group')

    def test_terminal_guards_and_gaps_never_carry(self):
        for mode in ('guard', 'gap', 'skipped'):
            frame = copy.deepcopy(self.frame)
            if mode == 'guard': frame['guards_after'][-1]['ok'] = False
            if mode == 'skipped': frame['skipped_intervals_before'] = 1
            result = self.projector.project(frame, gap=mode == 'gap')
            self.assertTrue(all(r['global_group_candidate'] is None for r in result['rows']))

    def test_spectator_and_unknown_scope_do_not_promote_neutral_selector(self):
        for use in ('spectator', 'unknown'):
            self.scope['context_use'] = use
            self.replace('context_scope_review_sha256', self.scope)
            projector = self.make()
            self.assertEqual(projector.context.project(self.frame)['status'], 'observed')
            result = projector.project(self.frame)
            self.assertEqual(result['reason'], 'unsupported_context_scope')
            self.assertTrue(all(r['group_relation_candidate'] is None for r in result['rows']))

    def test_epoch_interval_cannot_be_extended_without_new_review(self):
        for field, value in (('sequence', 11), ('start_ticks', -1), ('end_ticks', 501),
                             ('monotonic_frequency', 2000)):
            frame = copy.deepcopy(self.frame)
            frame[field] = value
            self.assertEqual(self.projector.project(frame)['reason'], 'outside_reviewed_frame_scope')
        self.contract['frame_scope']['end_ticks'] = 600
        with self.assertRaisesRegex(InvalidCategoryEvidence, 'context_epoch_review_mismatch'): self.make()

    def test_stale_or_other_source_projection_is_rejected_even_with_same_key(self):
        old = self.projector.context.project(self.frame)
        frame = copy.deepcopy(self.frame)
        frame['sequence'] = 1
        with patch.object(self.projector.context, 'project', return_value=old):
            self.assertEqual(self.projector.project(frame)['reason'], 'same_native_frame_scope_mismatch')
        for key, value in (('target', {}), ('source_evidence', {}), ('profile_sha256', '00' * 32)):
            stale = copy.deepcopy(old)
            stale[key] = value
            with patch.object(self.projector.context, 'project', return_value=stale):
                self.assertEqual(self.projector.project(self.frame)['reason'], 'same_native_frame_scope_mismatch')

    def test_same_controller_with_wrong_current_body_cannot_supply_anchor_group(self):
        wrong = self.projector.context.project(self.frame)
        wrong['body_object_key'] = 'body:' + '00' * 32
        with patch.object(self.projector.context, 'project', return_value=wrong):
            self.assertEqual(self.projector.project(self.frame)['reason'], 'context_category_unknown_or_ambiguous')

    def test_matching_mutated_projector_sources_cannot_retag_review(self):
        self.projector.categories.source['evidence_sha256'] = '00' * 32
        self.projector.context.source['evidence_sha256'] = '00' * 32
        self.assertEqual(self.projector.project(self.frame)['reason'], 'same_native_frame_scope_mismatch')

    def test_read_bracket_and_unsupported_category_are_not_group_evidence(self):
        for mutation in ('read', 'special', 'mode', 'multiple'):
            frame = copy.deepcopy(self.frame)
            if mutation == 'read': frame['fields']['context_selector_i32']['read_end_ticks'] = 81
            if mutation == 'special': frame['fields']['category_0']['value'] = 2048
            if mutation == 'mode': frame['fields']['category_0']['value'] = 12
            if mutation == 'multiple': frame['fields']['category_0']['value'] = 136
            self.assertTrue(all(r['group_relation_candidate'] is None for r in self.projector.project(frame)['rows']))

    def test_source_recipe_profile_build_review_and_group_mappings_are_pinned(self):
        for mutation in ('source', 'profile', 'build', 'context', 'map', 'artifact'):
            self.setUp()
            if mutation == 'source': self.contract['source'] = dict(self.contract['source'], recipe_sha256='00' * 32)
            if mutation == 'profile': self.contract['profile_sha256'] = '00' * 32
            if mutation == 'build': self.contract['build_sha256'] = '00' * 32
            if mutation == 'context': self.contract['context_contract_sha256'] = '00' * 32
            if mutation == 'map':
                self.review['category_groups'][1]['group'] = 'group-a'
                self.replace('two_group_review_sha256', self.review)
            if mutation == 'artifact': self.artifacts[self.contract['two_group_review_sha256']] += b'changed'
            with self.subTest(mutation=mutation), self.assertRaises(InvalidCategoryEvidence): self.make()


if __name__ == '__main__':
    unittest.main()
