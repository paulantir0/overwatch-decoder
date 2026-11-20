"""Distinct owner composition through the real live reader; synthetic sources."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from forward_owner_relations import GuardedForwardOwners
from forward_owner_projection import ForwardOwnerProjection
from hero_asset_labels import HeroAssetCatalog, GuardedHeroAssetLabels
from live_relations import LiveRelations
from runtime_producer import forward_adapter_options, validate_config
from test_forward_owner_relations import source_fixture, raw, sha
from test_hero_asset_labels import fixture as asset_fixture
from test_live_hero_assets import files as hero_files
from test_live_relations import SESSION, start, live, next_frame


def fixture():
    asset_profile, _, catalog, assets, _ = asset_fixture()
    def enrich(profile, values):
        for field in json.loads(asset_profile)['fields']:
            if '_part83_' in field['name']:
                profile['fields'].append(field)
                values[field['name']] = 255 if '_low_' in field['name'] else 0x02E00000
        name = 'controller_0000_aux_0000_position_candidate'
        profile['fields'].append(dict(name=name, type='f32x3', address=0x9000))
        values[name] = [1., 2., 3.]
    pr, cr, artifacts, frame = source_fixture(mutate=enrich)
    for field in json.loads(pr)['fields']:
        frame['fields'][field['name']].update(type=field['type'], reason=None)
    forward = GuardedForwardOwners(pr, cr, artifacts)
    hero = GuardedHeroAssetLabels(pr, HeroAssetCatalog(raw(catalog), assets), require_body=False)
    source = dict(profile_sha256=sha(pr), acquisition=dict(
        forward.source, manifest_sha256=forward.manifest_hash))
    return pr, cr, artifacts, frame, forward, hero, source, catalog, assets


def write_fixture(root):
    pr, cr, artifacts, frame, forward, hero, source, catalog, assets = fixture()
    contract = json.loads(cr)
    paths = {}
    for pin, value in artifacts.items():
        path = root/pin
        path.write_bytes(value)
        paths[pin] = pin
    for name, pin in [('manifest.json', contract['acquisition_manifest_sha256']),
                      ('recipe.json', contract['source']['recipe_sha256']),
                      ('evidence.jsonl', contract['source']['evidence_sha256'])]:
        (root/name).write_bytes(artifacts[pin])
    (root/'profile.json').write_bytes(pr)
    (root/'forward.json').write_bytes(cr)
    (root/'forward-artifacts.json').write_bytes(raw(paths))
    (root/'bindings.json').write_bytes(artifacts[contract['binding_template_sha256']])
    frame.update(interpretation='profile_declared_research', visibility='research', runtime_semantics_validated=False,
        public_state_eligible=False, atomic=False, scheduled_slot=0, scheduled_ticks=0, jitter_ticks=10,
        skipped_intervals_before=0, skipped_intervals_total=0, utc_origin_before_ticks=0,
        requested_interval_ms=100, scheduler_backend='synthetic', hard_realtime=False)
    opts = hero_files(root, catalog, assets)
    opts.update(forward_owner_contract=root/'forward.json', forward_owner_artifacts=root/'forward-artifacts.json')
    return json.loads(pr), frame, json.loads((root/'manifest.json').read_bytes()), opts


class ForwardComposition(unittest.TestCase):
    def setUp(self):
        self.pr, self.cr, self.artifacts, self.frame, self.forward, self.hero, self.source, _, _ = fixture()
        self.decoder = ForwardOwnerProjection(self.forward, controller_hero=self.hero)

    def test_position_and_controller_name_without_body_role(self):
        result = self.decoder.project(self.frame, self.source)
        row = result['relations'][0]
        self.assertEqual(row['position_candidate']['value'], [1., 2., 3.])
        self.assertEqual(row['controller_hero_asset_label_candidate'], 'Synthetic Hero')
        self.assertEqual(row['controller_hero_asset_label_evidence']['binding_scope'], 'controller_only')
        self.assertIsNone(row['current_displayed_body'])
        self.assertNotIn('body_object_key', row)
        self.assertIsNone(self.forward.relations.project(self.frame)['relations'][0]['body_object_key'])
        row['position_candidate']['value'][0] = -100
        self.assertEqual(self.decoder.project(self.frame, self.source)['relations'][0]['position_candidate']['value'], [1.,2.,3.])

    def test_identity_loss_gap_and_independent_field_failure(self):
        for mode in ('gap', 'identity', 'position', 'hero'):
            with self.subTest(mode=mode):
                frame = copy.deepcopy(self.frame)
                field = {'identity':'controller_0000_aux_0000_manager_key_candidate_i32',
                         'position':'controller_0000_aux_0000_position_candidate',
                         'hero':'controller_0000_part83_0000_hero_resource_low_candidate_i32'}.get(mode)
                if field: frame['fields'][field].update(status='unknown', value=None, reason='unreadable')
                row = self.decoder.project(frame, self.source, gap=mode=='gap')['relations'][0]
                if mode in ('gap', 'identity'):
                    self.assertIsNone(row['forward_owner_object_key'])
                    self.assertIsNone(row['controller_hero_asset_label_candidate'])
                if mode != 'hero': self.assertIsNone(row['position_candidate'])
                if mode == 'hero':
                    self.assertIsNotNone(row['position_candidate'])
                    self.assertIsNone(row['controller_hero_asset_label_candidate'])

    def test_acquisition_mismatch_and_hero_cross_join_rejected(self):
        for key in ('manifest_sha256', 'recipe_sha256', 'evidence_sha256'):
            source = copy.deepcopy(self.source); source['acquisition'][key] = 'ff'*32
            with self.assertRaisesRegex(ValueError, 'acquisition_mismatch'):
                self.decoder.project(self.frame, source)
        original = self.hero.project(self.frame)
        for mode in ('controller', 'duplicate', 'time', 'body'):
            mutated = copy.deepcopy(original)
            if mode == 'controller': mutated['heroes'][0]['controller_object_key'] = 'controller:'+'00'*32
            if mode == 'duplicate': mutated['heroes'].append(copy.deepcopy(mutated['heroes'][0]))
            if mode == 'time': mutated['timing']['start_ticks'] += 1
            if mode == 'body': mutated['heroes'][0]['body_object_key'] = 'body:'+'00'*32
            with patch.object(self.hero, 'project', return_value=mutated):
                if mode in ('time', 'body'):
                    with self.assertRaises(ValueError): self.decoder.project(self.frame, self.source)
                else:
                    row = self.decoder.project(self.frame, self.source)['relations'][0]
                    self.assertIsNone(row['controller_hero_asset_label_candidate'])

    def test_real_live_adapter_default_parity_and_gap(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); p,f,m,opts = write_fixture(root)
            adapter = LiveRelations(root, SESSION, 1, **opts)
            plain = LiveRelations(root, SESSION, 1, **{k:v for k,v in opts.items() if not k.startswith('forward_')})
            for a in (adapter, plain): a.consume(raw(start(p,m)))
            result = adapter.consume(raw(live(f)))
            baseline = plain.consume(raw(live(f)))
            extra = result.pop('forward_owner_projection')
            self.assertEqual(raw(result), raw(baseline))
            self.assertEqual(extra['relations'][0]['controller_hero_asset_label_candidate'], 'Synthetic Hero')
            self.assertEqual(extra['source_artifacts'], result['source_artifacts'])
            f = next_frame(f, missed=1); event = live(f,2); event['emitted_ticks'] = 400
            row = adapter.consume(raw(event))['forward_owner_projection']['relations'][0]
            self.assertIsNone(row['forward_owner_object_key'])
            self.assertIsNone(row['position_candidate'])

    def test_fresh_runtime_contract_paths_and_tamper(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); p,f,m,_ = write_fixture(root)
            epoch = root/'epoch'; epoch.mkdir()
            config = dict(recipe=str(root/'recipe.json'), forward_owner_bindings=str(root/'bindings.json'),
                          forward_owner_bindings_sha256=sha((root/'bindings.json').read_bytes()))
            opts = forward_adapter_options(config, root, epoch)
            adapter = LiveRelations(root, SESSION, 1, **opts)
            adapter.consume(raw(start(p,m)))
            row = adapter.consume(raw(live(f)))['forward_owner_projection']['relations'][0]
            self.assertEqual(row['position_candidate']['value'], [1.,2.,3.])
            self.assertEqual(forward_adapter_options({}, root, epoch), {})
            (root/'bindings.json').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'template_changed'):
                forward_adapter_options(config, root, epoch)

    def test_runtime_configuration_pins_templates_before_native_start(self):
        from test_runtime_hero_assets import configuration
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config, _ = configuration(root)
            p, _, m, _ = write_fixture(root)
            config.update(target=p['target'], recipe='recipe.json', recipe_sha256=m['recipe_sha256'],
                          forward_owner_bindings='bindings.json',
                          forward_owner_bindings_sha256=sha((root/'bindings.json').read_bytes()))
            checked = validate_config(config, root)
            self.assertEqual(checked['forward_owner_bindings'], str(root/'bindings.json'))
            template = json.loads((root/'bindings.json').read_bytes())
            binding = template['bindings'][0]
            layout = dict(schema='overwatch-decoder.health-layout/1', executable_sha256=template['build_sha256'],
                recipe_sha256=template['recipe_sha256'], supported_forward_owners=[dict(
                    binding_id=binding['binding_id'], owner_prefix=binding['owned_field_prefix'])])
            for mode in ('valid', 'wrong_build', 'old_contract'):
                altered = copy.deepcopy(layout)
                if mode == 'wrong_build': altered['executable_sha256'] = 'ff'*32
                if mode == 'old_contract': altered['supported_forward_owners'][0]['forward_contract_sha256'] = 'ff'*32
                (root/'forward-layout.json').write_bytes(raw(altered))
                c = dict(config, forward_owner_health_layout='forward-layout.json',
                         forward_owner_health_layout_sha256=sha((root/'forward-layout.json').read_bytes()))
                if mode == 'valid': self.assertIn('forward_owner_health_layout', validate_config(c, root))
                else:
                    with self.assertRaises(ValueError): validate_config(c, root)
            c = dict(config); c['forward_owner_bindings_sha256'] = 'ff'*32
            with self.assertRaisesRegex(ValueError, 'pinned_file_mismatch'):
                validate_config(c, root)


if __name__ == '__main__': unittest.main()
