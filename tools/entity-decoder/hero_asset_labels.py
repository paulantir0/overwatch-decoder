"""Guarded hero-resource labels from caller-pinned typed asset reports.

This candidate path does not require a runtime UI review and does not weaken the
separate reviewed HeroLabelCatalog. Callers verify acquisition/recording sources.
Catalog build scoping is explicit caller input, not a claim that asset extraction
independently attested the executable. No game IDs, labels or offsets are bundled.
"""
from __future__ import annotations

import copy
import re
import unicodedata

from hero_labels import InvalidHeroEvidence, digest, guid, need, parse, sha
from relations import GuardedRelations, InvalidBinding


class HeroAssetCatalog:
    def __init__(self, raw_catalog: bytes, artifacts: dict[str, bytes]):
        need(isinstance(raw_catalog, bytes) and len(raw_catalog) <= 65536, 'catalog_size')
        need(isinstance(artifacts, dict), 'artifact_map_type')
        catalog = parse(raw_catalog)
        need(isinstance(catalog, dict) and catalog.get('schema') == 'overwatch-decoder.hero-asset-catalog/1', 'catalog_schema')
        entries = catalog.get('entries')
        need(isinstance(entries, list) and 1 <= len(entries) <= 128, 'entry_count')
        self.hash, self.entries = sha(raw_catalog), {}
        total, seen = 0, set()
        for entry in entries:
            need(isinstance(entry, dict), 'invalid_entry')
            build, resource = digest(entry.get('build_sha256')), guid(entry.get('resource_guid'))
            stored_type = (int(resource, 16) >> 48) & 0xfff
            need(int(f'{stored_type:012b}'[::-1], 2) + 1 == 0x075, 'resource_not_typed_hero')
            locale = entry.get('locale')
            need(isinstance(locale, str) and re.fullmatch(r'[a-z]{2}[A-Z]{2}', locale) is not None, 'invalid_locale')
            asset_hash = digest(entry.get('asset_report_sha256'))
            raw = artifacts.get(asset_hash)
            need(isinstance(raw, bytes) and len(raw) <= 4*1024*1024 and sha(raw) == asset_hash, 'asset_hash_or_size')
            if asset_hash not in seen:
                total += len(raw)
                seen.add(asset_hash)
            need(total <= 64*1024*1024, 'asset_total_size')
            asset = parse(raw)
            need(isinstance(asset, dict) and asset.get('schema') == 'overwatch-decoder.datatool-inspect/2'
                 and asset.get('status') == 'ok' and isinstance(asset.get('inputs'), dict)
                 and asset['inputs'].get('language') == locale, 'asset_report_invalid')
            hero = asset.get('hero')
            need(isinstance(hero, dict) and guid(hero.get('guid')) == resource, 'asset_guid_mismatch')
            label = hero.get('name')
            need(isinstance(label, str) and 1 <= len(label) <= 128
                 and not any(unicodedata.category(c).startswith('C') for c in label), 'invalid_label')
            assets = asset.get('assets')
            need(isinstance(assets, list), 'typed_hero_root_missing')
            roots = [x for x in assets if isinstance(x, dict) and x.get('guid') == hero['guid']]
            need(len(roots) == 1, 'typed_hero_root_missing')
            root = roots[0]
            selection = root.get('root_selection')
            need(root.get('status') == 'decoded' and root.get('type') == '0x075'
                 and isinstance(selection, dict) and selection.get('instance0_class') == 'STUHero'
                 and selection.get('instance0_matches_expected') is True, 'typed_hero_root_missing')
            decoded_hash = digest(root.get('decoded_sha256'))
            key = build, resource, locale
            need(key not in self.entries, 'duplicate_or_conflicting_mapping')
            self.entries[key] = dict(label=label, resource_guid=resource, locale=locale,
                build_sha256=build, asset_report_sha256=asset_hash, asset_decoded_sha256=decoded_hash,
                asset_build=copy.deepcopy(asset.get('build')),
                mapping_scope='caller_build_scoped_typed_asset',
                validation_status='typed_asset_resource_match', runtime_ui_validated=False,
                public_state_eligible=False)

    def lookup(self, build, resource, locale='enUS'):
        result = self.entries.get((build, guid(resource), locale))
        return copy.deepcopy(result) if result is not None else None


class GuardedHeroAssetLabels:
    """Stateless candidates; default requires an observed reciprocal body match.

    Explicit require_body=False supports controller-only metadata. It emits no
    body key and claims no current body/hero association. No prior value is kept.
    """
    def __init__(self, raw_profile, catalog: HeroAssetCatalog, locale='enUS', *, require_body=True):
        need(type(require_body) is bool, 'invalid_body_policy')
        self.relations = GuardedRelations(raw_profile)
        self.catalog, self.locale, self.require_body = catalog, locale, require_body

    def project(self, frame, *, gap=False):
        base = self.relations.project(frame)
        result = {k: v for k, v in base.items() if k != 'relations'}
        result.update(schema='overwatch-decoder.guarded-hero-asset-labels/1', catalog_sha256=self.catalog.hash,
                      runtime_ui_validated=False, heroes=[])
        for relation in base['relations']:
            row = dict(controller_object_key=relation['controller_object_key'],
                       body_object_key=relation['body_object_key'] if self.require_body else None,
                       status='unknown', reason=None, hero_label_candidate=None, resource_guid=None,
                       binding_scope='controller_and_body' if self.require_body else 'controller_only',
                       runtime_ui_validated=False, evidence=[])
            try:
                skipped = frame.get('skipped_intervals_before', 0)
                if type(skipped) is not int or skipped < 0:
                    raise InvalidBinding('invalid_gap_metadata')
                if gap or skipped:
                    raise InvalidBinding('gap_before_frame')
                if relation['controller_object_key'] is None or (self.require_body and relation['relation_status'] != 'observed'):
                    raise InvalidBinding(relation['reason'] or 'relation_unknown')
                prefix = relation['controller_prefix']
                suffixes = ['_part83_0000_hero_resource_low_candidate_i32', '_part83_0000_hero_resource_high_candidate_i32']
                if self.require_body:
                    suffixes += ['_body_0000_hero_resource_low_candidate_i32', '_body_0000_hero_resource_high_candidate_i32']
                words = [self.relations.sample_scalar(prefix + suffix, frame, 'i32') for suffix in suffixes]
                resource_word = (words[0]['value'] & 0xffffffff) | ((words[1]['value'] & 0xffffffff) << 32)
                if self.require_body and resource_word != ((words[2]['value'] & 0xffffffff) | ((words[3]['value'] & 0xffffffff) << 32)):
                    raise InvalidBinding('controller_body_resource_mismatch')
                resource = guid(f'0x{resource_word:016X}')
                mapping = self.catalog.lookup(self.relations.target['executable_sha256'], resource, self.locale)
                if mapping is None:
                    raise InvalidBinding('unmapped_build_resource_or_locale')
                row.update(status='observed', hero_label_candidate=mapping['label'], resource_guid=resource,
                           mapping_evidence=mapping,
                           evidence=[{k: w[k] for k in ('field', 'value', 'read_start_ticks', 'read_end_ticks')} for w in words])
            except (InvalidBinding, InvalidHeroEvidence) as error:
                row['reason'] = str(error)
            result['heroes'].append(row)
        return result
