"""Synthetic evidence-binding and guarded-label tests; no game offsets or roster."""
import copy
import json
import unittest

from hero_labels import GuardedHeroLabels, HeroLabelCatalog, InvalidHeroEvidence, sha
from test_relations import fixture, prepare


def raw(value):
    return json.dumps(value, separators=(',', ':')).encode()


def evidence_fixture():
    profile, values = fixture()
    resource = '0x02E00000000000FF'  # Synthetic index, typed as a hero asset.
    for index, suffix in enumerate(('_part83_0000_hero_resource_low_candidate_i32',
                                    '_part83_0000_hero_resource_high_candidate_i32',
                                    '_body_0000_hero_resource_low_candidate_i32',
                                    '_body_0000_hero_resource_high_candidate_i32')):
        name = 'controller_0000' + suffix
        profile['fields'].append(dict(name=name, type='i32', address=0x9000+index*4))
        values[name] = 255 if index % 2 == 0 else 0x02E00000
    decoder, frame = prepare(profile, values)
    profile_bytes = raw(profile)
    frame['profile_sha256'] = sha(profile_bytes)
    artifacts = {}
    def add(value):
        data = value if isinstance(value, bytes) else raw(value)
        artifacts[sha(data)] = data
        return sha(data)
    profile_hash = add(profile_bytes)
    build = profile['target']['executable_sha256']
    asset = dict(schema='overwatch-decoder.datatool-inspect/2', status='ok', inputs=dict(language='enUS'),
                 build=dict(client_version='older_fixture_asset'), hero=dict(name='Synthetic Hero', guid=resource),
                 assets=[dict(guid=resource, type='0x075', status='decoded', decoded_sha256='cd'*32,
                              root_selection=dict(instance0_class='STUHero', instance0_matches_expected=True))])
    manifest = dict(schema='overwatch-decoder.field-recording/1', complete=True, target=profile['target'],
                    profile_sha256=profile_hash, samples_sha256='ab'*32, index_sha256='bc'*32)
    verified = dict(schema='overwatch-decoder.field-recording-verification/1', mode='strict', status='verified_complete',
                    terminal_summary_verified=True, valid=True, complete=True, frames=2,
                    profile_sha256=profile_hash, samples_prefix_sha256=manifest['samples_sha256'],
                    index_prefix_sha256=manifest['index_sha256'])
    review = dict(schema='overwatch-decoder.hero-label-ui-review/1', reviewed=True, review_method='manual_visual_hud_identity',
                  label='Synthetic Hero', locale='enUS', resource_guid=resource, build_sha256=build,
                  recording_manifest_sha256=add(manifest), native_verification_sha256=add(verified),
                  anchors=[dict(screenshot_sha256=add(b'\x89PNG\r\n\x1a\nfixture'),
                                capture_start_ticks=29, capture_end_ticks=41, read_start_ticks=30, read_end_ticks=40,
                                sequence=0, profile_sha256=profile_hash, reviewed_label='Synthetic Hero',
                                controller_body_match=True, resource_guid=resource)])
    catalog = dict(schema='overwatch-decoder.hero-label-catalog/1', entries=[dict(build_sha256=build, resource_guid=resource,
                   label='Synthetic Hero', locale='enUS', asset_report_sha256=add(asset), runtime_ui_review_sha256=add(review))])
    return profile_bytes, frame, catalog, artifacts, asset, review


class CatalogTests(unittest.TestCase):
    def test_requires_typed_asset_plus_build_scoped_review(self):
        _, _, catalog, artifacts, _, _ = evidence_fixture()
        mapping = HeroLabelCatalog(raw(catalog), artifacts)
        entry = catalog['entries'][0]
        result = mapping.lookup(entry['build_sha256'], entry['resource_guid'])
        self.assertEqual(result['label'], 'Synthetic Hero')
        self.assertFalse(result['public_state_eligible'])
        self.assertIsNone(mapping.lookup('ff'*32, entry['resource_guid']))
        self.assertIsNone(mapping.lookup(entry['build_sha256'], '0x02E00000000000FE'))
        self.assertIsNone(mapping.lookup(entry['build_sha256'], entry['resource_guid'], 'frFR'))

    def test_rejects_corrupt_source_and_conflicting_mapping(self):
        _, _, catalog, artifacts, _, _ = evidence_fixture()
        broken = artifacts.copy()
        broken[catalog['entries'][0]['asset_report_sha256']] += b' '
        with self.assertRaisesRegex(ValueError, 'artifact_hash'):
            HeroLabelCatalog(raw(catalog), broken)
        catalog['entries'].append(copy.deepcopy(catalog['entries'][0]))
        with self.assertRaisesRegex(ValueError, 'duplicate_or_conflicting'):
            HeroLabelCatalog(raw(catalog), artifacts)

    def test_asset_labels_types_ui_build_and_timing_are_not_guessed(self):
        for case in ('label', 'type', 'reviewed', 'build', 'bracket', 'screenshot'):
            with self.subTest(case=case):
                _, _, catalog, artifacts, asset, review = evidence_fixture()
                if case == 'label':
                    asset['hero']['name'] = 'Different Hero'
                elif case == 'type':
                    asset['assets'][0]['type'] = '0x01B'
                elif case == 'reviewed':
                    review['reviewed'] = False
                elif case == 'build':
                    review['build_sha256'] = 'ff'*32
                elif case == 'bracket':
                    review['anchors'][0]['capture_start_ticks'] = 50
                    review['anchors'][0]['capture_end_ticks'] = 60
                else:
                    review['anchors'][0]['screenshot_sha256'] = 'ef'*32
                for key, value in [('asset_report_sha256', asset), ('runtime_ui_review_sha256', review)]:
                    data = raw(value)
                    artifacts[sha(data)] = data
                    catalog['entries'][0][key] = sha(data)
                with self.assertRaises(InvalidHeroEvidence):
                    HeroLabelCatalog(raw(catalog), artifacts)

    def test_resource_type_bits_must_agree_with_typed_hero_report(self):
        _, _, catalog, artifacts, _, _ = evidence_fixture()
        catalog['entries'][0]['resource_guid'] = '0x00000000000000FF'
        with self.assertRaisesRegex(ValueError, 'resource_not_typed_hero'):
            HeroLabelCatalog(raw(catalog), artifacts)


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        profile, self.frame, catalog, artifacts, _, _ = evidence_fixture()
        self.decoder = GuardedHeroLabels(profile, HeroLabelCatalog(raw(catalog), artifacts))

    def row(self, frame=None, **kwargs):
        return self.decoder.project(self.frame if frame is None else frame, **kwargs)['heroes'][0]

    def test_matching_guarded_resource_yields_label_with_provenance(self):
        result = self.decoder.project(self.frame)
        row = result['heroes'][0]
        self.assertEqual(row['hero_label'], 'Synthetic Hero')
        self.assertEqual(row['resource_guid'], '0x02E00000000000FF')
        self.assertEqual(len(row['evidence']), 4)
        self.assertEqual(row['evidence'][0]['read_start_ticks'], 30)
        self.assertEqual(result['visibility'], 'unknown')
        self.assertFalse(result['public_state_eligible'])
        self.assertNotIn('address', json.dumps(result))

    def test_unknown_build_resource_locale_and_gap_stay_unknown(self):
        for case in ('resource', 'locale', 'gap'):
            with self.subTest(case=case):
                frame = copy.deepcopy(self.frame)
                if case == 'resource':
                    for name, value in frame['fields'].items():
                        if 'hero_resource_low_' in name:
                            value['value'] = 254
                elif case == 'locale':
                    self.decoder.locale = 'frFR'
                row = self.row(frame, gap=case == 'gap')
                self.assertIsNone(row['hero_label'])
                self.decoder.locale = 'enUS'
        frame = copy.deepcopy(self.frame)
        frame['target']['executable_sha256'] = 'ff'*32
        self.assertIsNone(self.row(frame)['hero_label'])

    def test_mismatch_unknown_guard_failure_and_stale_profile_fail_closed(self):
        for case in ('mismatch', 'unknown', 'guard', 'profile'):
            with self.subTest(case=case):
                frame = copy.deepcopy(self.frame)
                field = frame['fields']['controller_0000_body_0000_hero_resource_low_candidate_i32']
                if case == 'mismatch': field['value'] += 1
                elif case == 'unknown': field['status'] = 'unknown'
                elif case == 'guard': frame['guards_after'][0]['ok'] = False
                else: frame['profile_sha256'] = '00'*32
                self.assertIsNone(self.row(frame)['hero_label'])
        self.assertEqual(self.row()['hero_label'], 'Synthetic Hero')
        self.frame['fields'] = {}
        self.assertIsNone(self.row()['hero_label'])


if __name__ == '__main__':
    unittest.main()
