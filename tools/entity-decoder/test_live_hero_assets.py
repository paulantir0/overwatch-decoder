"""Portable asset-label composition tests; all resources and actors synthetic."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import export_relations as exporter
from live_relations import LiveRelations
from relations import GuardedRelations
from hero_asset_labels import HeroAssetCatalog, GuardedHeroAssetLabels
from hero_labels import GuardedHeroLabels, HeroLabelCatalog
from test_hero_asset_labels import fixture
from test_hero_labels import evidence_fixture, raw
from test_export_relations import make_fixture
from test_live_relations import setup, start, live, next_frame, SESSION
from test_relations import prepare


def files(root, catalog=None, artifacts=None):
    if catalog is None:
        _, _, catalog, artifacts, _ = fixture()
    paths = {}
    # Only typed assets are needed, never the separate UI-review artifacts.
    for entry in catalog['entries']:
        key = entry['asset_report_sha256']
        (root/key).write_bytes(artifacts[key]); paths[key] = key
    cp, ap = root/'catalog.json', root/'artifacts.json'
    cp.write_bytes(raw(catalog)); ap.write_bytes(raw(paths))
    return dict(hero_asset_catalog=cp, hero_asset_artifacts=ap)


def direct(profile, frame, decoder=None, **kw):
    return exporter.project_frame(GuardedRelations(profile), frame, {'acquisition': {'recipe_sha256': 'ab'*32}},
        {}, dict(skipped_slots=kw.pop('gap', 0)), hero_asset_projector=decoder, **kw)


def live_fixture(root):
    p, old, manifest, health = setup(root, health=True)
    asset_profile, _, catalog, artifacts, _ = fixture()
    values = {name: sample['value'] for name, sample in old['fields'].items()}
    for field in json.loads(asset_profile)['fields']:
        if 'hero_resource_' in field['name']:
            p['fields'].append(field)
            values[field['name']] = 255 if '_low_' in field['name'] else 0x02E00000
    decoder, frame = prepare(p, values)
    for k, v in old.items():
        if k not in ('fields', 'guards_before', 'guards_after', 'profile_sha256'):
            frame[k] = copy.deepcopy(v)
    for name, sample in frame['fields'].items():
        sample.update(type=decoder.fields[name]['type'], reason=None)
    pr = json.dumps(p).encode(); frame['profile_sha256'] = exporter.digest(pr)
    manifest['profile_sha256'] = frame['profile_sha256']
    (root/'profile.json').write_bytes(pr); (root/'manifest.json').write_bytes(raw(manifest))
    return p, frame, manifest, health, files(root, catalog, artifacts)


class ReaderAssets(unittest.TestCase):
    def setUp(self):
        self.profile, self.frame, self.catalog, self.artifacts, _ = fixture()
        self.decoder = GuardedHeroAssetLabels(self.profile, HeroAssetCatalog(raw(self.catalog), self.artifacts))

    def test_separate_candidate_exact_evidence_and_detached_output(self):
        result = direct(self.profile, self.frame, self.decoder)
        row = result['relations'][0]; ev = row['hero_asset_label_evidence']
        self.assertEqual(row['hero_asset_label_candidate'], 'Synthetic Hero')
        self.assertIsNone(row['hero_label']); self.assertIsNone(row['hero_asset_label_reason'])
        self.assertTrue(result['hero_asset_output_enabled'])
        self.assertEqual(ev['controller_object_key'], row['controller_object_key'])
        self.assertEqual(ev['body_object_key'], row['body_object_key'])
        self.assertEqual(ev['frame_timing'], result['timing'])
        self.assertEqual(ev['source_target'], result['target'])
        self.assertEqual(len(ev['fields']), 4)
        self.assertFalse(ev['runtime_ui_validated']); self.assertFalse(ev['public_state_eligible'])
        self.assertEqual(ev['resource_guid'], row['hero_resource_guid_candidate']['value'])
        ev['fields'][0]['value'] = -999; ev['source_target']['pid'] = -1
        fresh = direct(self.profile, self.frame, self.decoder)['relations'][0]['hero_asset_label_evidence']
        self.assertNotEqual(fresh['fields'][0]['value'], -999)
        self.assertNotEqual(fresh['source_target']['pid'], -1)

    def test_defaults_unchanged_and_ui_review_path_independent(self):
        default = direct(self.profile, self.frame)
        configured = direct(self.profile, self.frame, self.decoder)
        for key in ('hero_asset_output_enabled', 'hero_asset_catalog_sha256'): configured.pop(key)
        for row in configured['relations']:
            for key in ('hero_asset_label_candidate', 'hero_asset_label_evidence', 'hero_asset_label_reason'): row.pop(key)
        self.assertEqual(raw(default), raw(configured))
        profile, frame, catalog, artifacts, _, _ = evidence_fixture()
        reviewed = GuardedHeroLabels(profile, HeroLabelCatalog(raw(catalog), artifacts))
        both = direct(profile, frame, self.decoder, hero_projector=reviewed)['relations'][0]
        self.assertEqual(both['hero_label'], both['hero_asset_label_candidate'])
        self.assertNotEqual(both['hero_label_evidence']['validation_status'], both['hero_asset_label_evidence']['validation_status'])

    def test_gap_guard_missing_resource_and_build_do_not_carry(self):
        for case in ('gap', 'guard', 'missing', 'mismatch', 'build', 'locale'):
            with self.subTest(case=case):
                f = copy.deepcopy(self.frame); d = self.decoder
                if case == 'guard': f['guards_after'][0]['ok'] = False
                if case == 'missing': f['fields']['controller_0000_body_0000_hero_resource_low_candidate_i32']['status'] = 'unknown'
                if case == 'mismatch': f['fields']['controller_0000_body_0000_hero_resource_low_candidate_i32']['value'] += 1
                if case in ('build', 'locale'):
                    cat = copy.deepcopy(self.catalog)
                    if case == 'build': cat['entries'][0]['build_sha256'] = 'ff'*32
                    d = GuardedHeroAssetLabels(self.profile, HeroAssetCatalog(raw(cat), self.artifacts), locale='frFR' if case == 'locale' else 'enUS')
                row = direct(self.profile, f, d, gap=case == 'gap')['relations'][0]
                self.assertIsNone(row['hero_asset_label_candidate']); self.assertIsNone(row['hero_asset_label_evidence'])
                self.assertTrue(row['hero_asset_label_reason'])
        self.assertEqual(direct(self.profile, self.frame, self.decoder)['relations'][0]['hero_asset_label_candidate'], 'Synthetic Hero')

    def test_no_prefix_or_controller_only_join_and_root_binding(self):
        original = self.decoder.project(self.frame)
        for case in ('controller', 'body', 'duplicate', 'resource', 'profile', 'target', 'timing', 'catalog', 'ui'):
            with self.subTest(case=case):
                result = copy.deepcopy(original); row = result['heroes'][0]
                if case == 'controller': row['controller_object_key'] = 'controller:'+'ff'*32
                if case == 'body': row['body_object_key'] = None
                if case == 'duplicate': result['heroes'].append(copy.deepcopy(row))
                if case == 'resource': row['resource_guid'] = '0x02E00000000000FE'
                if case == 'profile': result['profile_sha256'] = 'ff'*32
                if case == 'target': result['target']['pid'] += 1
                if case == 'timing': result['timing']['end_ticks'] += 1
                if case == 'catalog': result['catalog_sha256'] = 'ff'*32
                if case == 'ui': result['runtime_ui_validated'] = True
                with patch.object(self.decoder, 'project', return_value=result):
                    if case in ('profile','target','timing','catalog','ui'):
                        with self.assertRaisesRegex(ValueError, 'source_mismatch'): direct(self.profile, self.frame, self.decoder)
                    else: self.assertIsNone(direct(self.profile, self.frame, self.decoder)['relations'][0]['hero_asset_label_candidate'])
        bodyless = GuardedHeroAssetLabels(self.profile, self.decoder.catalog, require_body=False)
        with self.assertRaisesRegex(ValueError, 'body_required'): direct(self.profile, self.frame, bodyless)

    def test_export_pinned_paths_gap_and_count(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); opts = files(root)
            rec, acq, verified, _, _ = make_fixture(root, gap=True, hero_resource=0x02E00000000000FF)
            with patch.object(exporter, 'native_verify', return_value=verified):
                report = exporter.export_recording(rec, acq, root/'out.jsonl', ['unused'], **opts)
            rows = [json.loads(line) for line in (root/'out.jsonl').read_bytes().splitlines()]
            self.assertEqual(report['observed_hero_asset_label_candidates'], 1)
            self.assertEqual(rows[0]['relations'][0]['hero_asset_label_candidate'], 'Synthetic Hero')
            self.assertIsNone(rows[1]['relations'][0]['hero_asset_label_candidate'])
            self.assertEqual(rows[0]['relations'][0]['hero_asset_label_evidence']['acquisition']['manifest_sha256'], exporter.file_digest(acq/'manifest.json'))
            with self.assertRaisesRegex(ValueError, 'required_together'):
                exporter.export_recording(rec, acq, root/'other.jsonl', ['unused'], hero_asset_catalog=opts['hero_asset_catalog'])
            with self.assertRaisesRegex(ValueError, 'mutually_exclusive'):
                exporter.export_recording(rec, acq, root/'other.jsonl', ['unused'], hero_asset_projector=self.decoder, **opts)
            key = self.catalog['entries'][0]['asset_report_sha256']; (root/key).write_bytes(b'corrupt')
            with self.assertRaisesRegex(ValueError, 'artifact_hash'):
                exporter.load_hero_asset_projector(self.profile, opts['hero_asset_catalog'], opts['hero_asset_artifacts'])

    def test_live_pinned_source_health_position_gap_and_failure_scope(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); p, f, m, health, opts = live_fixture(root)
            adapter = LiveRelations(root, SESSION, 1, health_contracts=health, **opts)
            adapter.consume(raw(start(p,m))+b'\n'); result = adapter.consume(raw(live(f))+b'\n')
            row = result['relations'][0]
            self.assertEqual(row['hero_asset_label_candidate'], 'Synthetic Hero')
            self.assertEqual(row['health_candidate']['raw_sum'], 125.5)
            self.assertEqual(row['position_candidate']['value'], [1,2,3])
            self.assertFalse(result['durability_verified']); self.assertIsNone(row['hero_label'])
            self.assertEqual(row['hero_asset_label_evidence']['acquisition'], result['source_artifacts']['acquisition'])
            f = next_frame(f, missed=1); e = live(f,2); e['emitted_ticks'] = 400
            row = adapter.consume(raw(e)+b'\n')['relations'][0]
            self.assertIsNone(row['hero_asset_label_candidate']); self.assertIsNone(row['health_candidate'])
            self.assertEqual(row['hero_asset_label_reason'], 'gap_before_frame')
            # A fresh adapter with an unmapped locale still retains unrelated data.
            other = LiveRelations(root, SESSION, 1, health_contracts=health, **opts, hero_asset_locale='frFR')
            other.consume(raw(start(p,m))+b'\n')
            # Use the original exact frame from a fresh fixture, not a past projected value.
            _, initial, _, _, _ = live_fixture(root)
            row = other.consume(raw(live(initial))+b'\n')['relations'][0]
            self.assertIsNone(row['hero_asset_label_candidate']); self.assertEqual(row['health_candidate']['raw_sum'],125.5)
            self.assertIsNotNone(row['position_candidate'])
            with self.assertRaisesRegex(ValueError, 'required_together'):
                LiveRelations(root, SESSION, 1, hero_asset_artifacts=opts['hero_asset_artifacts'])

    def test_cli_exposes_pinned_options(self):
        for module in ('export_relations.py', 'live_relations.py'):
            output = subprocess.run([sys.executable, str(Path(__file__).with_name(module)), '--help'], capture_output=True, text=True, check=True).stdout
            for name in ('--hero-asset-catalog', '--hero-asset-artifacts', '--hero-asset-locale'): self.assertIn(name, output)


if __name__ == '__main__': unittest.main()
