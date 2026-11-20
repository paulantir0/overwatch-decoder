"""Optional typed-asset configuration is checked before native children start."""
import copy
import tempfile
import unittest
from pathlib import Path

import runtime_producer as runtime
from hero_labels import sha
from test_hero_asset_labels import fixture, raw


def configuration(root):
    config = dict(observation_mode='raw-candidates', seconds=10, interval_ms=50,
                  private_controlled_fixture_reviewed=True, public_state_eligible=False,
                  target={'pid': 12}, native_revision='synthetic', output='out')
    for key, pin in [('native_exe', 'native_sha256'), ('recipe', 'recipe_sha256'),
                     ('health_layout', 'health_layout_sha256')]:
        (root / key).write_text('{}')
        config[key], config[pin] = key, runtime.digest(root / key)
    _, _, catalog, artifacts, _ = fixture()
    report_hash = catalog['entries'][0]['asset_report_sha256']
    (root / 'report.json').write_bytes(artifacts[report_hash])
    (root / 'catalog.json').write_bytes(raw(catalog))
    (root / 'artifacts.json').write_bytes(raw({report_hash: 'report.json'}))
    config.update(hero_asset_catalog='catalog.json', hero_asset_artifacts='artifacts.json')
    return config, catalog


class RuntimeHeroAssets(unittest.TestCase):
    def test_opt_in_resolves_paths_and_passes_catalog_without_reviewed_promotion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = configuration(root)
            checked = runtime.validate_config(config, root)
            options = runtime.adapter_options(checked, [])
            self.assertEqual(options['hero_asset_catalog'], str(root / 'catalog.json'))
            self.assertEqual(options['hero_asset_artifacts'], str(root / 'artifacts.json'))
            self.assertEqual(options['hero_asset_locale'], 'enUS')
            self.assertIsNone(options['hero_catalog'])
            self.assertIsNone(options['cached_label_recipe_sha256'])
            reviewed = runtime.asset_keys(dict(config, observation_mode='reviewed'))
            self.assertIn('hero_asset_catalog', reviewed)
            self.assertIn('hero_catalog', reviewed)
            localized = runtime.validate_config(dict(config, hero_asset_locale='frFR'), root)
            self.assertEqual(runtime.adapter_options(localized, [])['hero_asset_locale'], 'frFR')

    def test_partial_catalog_and_bad_locale_reject_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, _ = configuration(root)
            for missing in ('hero_asset_catalog', 'hero_asset_artifacts'):
                altered = dict(config)
                del altered[missing]
                with self.subTest(missing=missing), self.assertRaisesRegex(ValueError, 'required_together'):
                    runtime.validate_config(altered, root)
            for locale in ('', 'en-US', 1, None):
                with self.subTest(locale=locale), self.assertRaisesRegex(ValueError, 'invalid_hero_asset_locale'):
                    runtime.validate_config(dict(config, hero_asset_locale=locale), root)
            legacy = {k: v for k, v in config.items() if not k.startswith('hero_asset_')}
            with self.assertRaisesRegex(ValueError, 'locale_requires_catalog'):
                runtime.validate_config(dict(legacy, hero_asset_locale='enUS'), root)
            checked = runtime.validate_config(legacy, root)
            self.assertFalse(any(k.startswith('hero_asset_') for k in runtime.adapter_options(checked, [])))

    def test_corrupt_report_wrong_type_and_oversize_catalog_reject_before_launch(self):
        for case in ('hash', 'wrong_type', 'oversize'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                config, catalog = configuration(root)
                if case == 'hash':
                    with (root / 'report.json').open('ab') as stream:
                        stream.write(b' ')
                elif case == 'wrong_type':
                    _, _, _, _, report = fixture()
                    report = copy.deepcopy(report)
                    report['assets'][0]['type'] = '0x001'
                    data = raw(report)
                    (root / 'report.json').write_bytes(data)
                    catalog['entries'][0]['asset_report_sha256'] = sha(data)
                    (root / 'catalog.json').write_bytes(raw(catalog))
                    (root / 'artifacts.json').write_bytes(raw({sha(data): 'report.json'}))
                else:
                    (root / 'catalog.json').write_bytes(b' ' * 65537)
                with self.assertRaises(ValueError):
                    runtime.validate_config(config, root)


if __name__ == '__main__':
    unittest.main()
