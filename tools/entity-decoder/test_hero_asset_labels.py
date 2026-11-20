"""Synthetic candidate tests; no private resource IDs, offsets or names."""
import copy
import json
import unittest
from hero_asset_labels import HeroAssetCatalog, GuardedHeroAssetLabels
from hero_labels import sha
from test_hero_labels import evidence_fixture, raw


def fixture():
    profile, frame, old, artifacts, asset, _ = evidence_fixture()
    entry = {k: v for k, v in old['entries'][0].items()
             if k in ('build_sha256', 'resource_guid', 'locale', 'asset_report_sha256')}
    catalog = dict(schema='overwatch-decoder.hero-asset-catalog/1', entries=[entry])
    return profile, frame, catalog, artifacts, asset


class AssetCandidates(unittest.TestCase):
    def setUp(self):
        self.profile, self.frame, self.catalog, self.artifacts, self.asset = fixture()

    def decoder(self, **kw):
        return GuardedHeroAssetLabels(self.profile, HeroAssetCatalog(raw(self.catalog), self.artifacts), **kw)

    def test_typed_asset_without_ui_is_usable_and_qualified(self):
        self.assertNotIn('runtime_ui_review_sha256', self.catalog['entries'][0])
        row = self.decoder().project(self.frame)['heroes'][0]
        self.assertEqual(row['hero_label_candidate'], 'Synthetic Hero')
        self.assertEqual(row['binding_scope'], 'controller_and_body')
        self.assertFalse(row['runtime_ui_validated'])
        self.assertEqual(len(row['evidence']), 4)
        self.assertEqual(row['mapping_evidence']['validation_status'], 'typed_asset_resource_match')
        self.assertNotIn('address', json.dumps(row))

    def test_wrong_asset_hash_type_guid_locale_and_duplicate_reject(self):
        for case in ('hash', 'root_type', 'root_selection', 'guid', 'locale', 'duplicate', 'control_label'):
            with self.subTest(case=case):
                _, _, catalog, artifacts, asset = fixture()
                if case == 'hash':
                    artifacts[catalog['entries'][0]['asset_report_sha256']] += b' '
                elif case == 'duplicate':
                    catalog['entries'].append(copy.deepcopy(catalog['entries'][0]))
                else:
                    if case == 'root_type': asset['assets'][0]['type'] = '0x001'
                    if case == 'root_selection': asset['assets'][0]['root_selection']['instance0_matches_expected'] = False
                    if case == 'guid': asset['hero']['guid'] = '0x02E00000000000FE'
                    if case == 'locale': asset['inputs']['language'] = 'frFR'
                    if case == 'control_label': asset['hero']['name'] = 'Synthetic\nHero'
                    data = raw(asset); artifacts[sha(data)] = data
                    catalog['entries'][0]['asset_report_sha256'] = sha(data)
                with self.assertRaises(ValueError): HeroAssetCatalog(raw(catalog), artifacts)

    def test_build_resource_locale_mismatch_unknown(self):
        for case in ('build', 'resource', 'locale'):
            with self.subTest(case=case):
                catalog = copy.deepcopy(self.catalog)
                if case == 'build': catalog['entries'][0]['build_sha256'] = 'ff'*32
                decoder = GuardedHeroAssetLabels(self.profile, HeroAssetCatalog(raw(catalog), self.artifacts),
                                                locale='frFR' if case == 'locale' else 'enUS')
                frame = copy.deepcopy(self.frame)
                if case == 'resource':
                    for name, value in frame['fields'].items():
                        if 'hero_resource_low_' in name: value['value'] = 254
                self.assertIsNone(decoder.project(frame)['heroes'][0]['hero_label_candidate'])

    def test_mismatch_guard_unknown_profile_and_gap_do_not_carry(self):
        decoder = self.decoder()
        for case in ('mismatch', 'guard', 'unknown', 'profile', 'skip', 'invalid_skip', 'explicit_gap'):
            with self.subTest(case=case):
                frame = copy.deepcopy(self.frame)
                f = frame['fields']['controller_0000_body_0000_hero_resource_low_candidate_i32']
                if case == 'mismatch': f['value'] += 1
                if case == 'guard': frame['guards_after'][0]['ok'] = False
                if case == 'unknown': f['status'] = 'unknown'
                if case == 'profile': frame['profile_sha256'] = '00'*32
                if case == 'skip': frame['skipped_intervals_before'] = 1
                if case == 'invalid_skip': frame['skipped_intervals_before'] = True
                row = decoder.project(frame, gap=case == 'explicit_gap')['heroes'][0]
                self.assertIsNone(row['hero_label_candidate'])
        self.assertEqual(decoder.project(self.frame)['heroes'][0]['hero_label_candidate'], 'Synthetic Hero')

    def test_controller_only_explicitly_does_not_claim_body(self):
        frame = copy.deepcopy(self.frame)
        for name, field in frame['fields'].items():
            if '_body_' in name: field['status'] = 'unknown'
        self.assertIsNone(self.decoder().project(frame)['heroes'][0]['hero_label_candidate'])
        row = self.decoder(require_body=False).project(frame)['heroes'][0]
        self.assertEqual(row['hero_label_candidate'], 'Synthetic Hero')
        self.assertIsNone(row['body_object_key'])
        self.assertEqual(row['binding_scope'], 'controller_only')

    def test_catalog_lookup_detached_and_no_ui_implicit_promotion(self):
        catalog = HeroAssetCatalog(raw(self.catalog), self.artifacts)
        e = self.catalog['entries'][0]
        row = catalog.lookup(e['build_sha256'], e['resource_guid'])
        row['asset_build']['client_version'] = 'mutated'
        self.assertNotEqual(catalog.lookup(e['build_sha256'], e['resource_guid'])['asset_build']['client_version'], 'mutated')
        with self.assertRaisesRegex(ValueError, 'invalid_body_policy'): self.decoder(require_body=1)


if __name__ == '__main__': unittest.main()
