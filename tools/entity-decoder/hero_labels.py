"""Build-scoped hero labels from pinned typed assets and reviewed runtime UI.

No IDs or target offsets are bundled. Catalog construction checks source hashes
and review declarations; it does not recognize screenshots or replace strict
native recording verification. Callers supply that verified evidence explicitly.
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata

from relations import GuardedRelations, InvalidBinding


class InvalidHeroEvidence(ValueError):
    pass


def need(ok, message):
    if not ok:
        raise InvalidHeroEvidence(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def parse(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'duplicate_json_key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def guid(value):
    need(isinstance(value, str) and re.fullmatch(r'0x[0-9A-Fa-f]{16}', value) is not None, 'invalid_resource_guid')
    need(int(value, 16) != 0, 'zero_resource_guid')
    return f'0x{int(value, 16):016X}'


def digest(value):
    need(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None, 'invalid_digest')
    return value


class HeroLabelCatalog:
    """Evidence-bound mapping; unlisted builds/resources remain unknown."""
    def __init__(self, raw_catalog: bytes, artifacts: dict[str, bytes]):
        need(isinstance(raw_catalog, bytes) and len(raw_catalog) <= 65536, 'catalog_size')
        self.hash = sha(raw_catalog)
        catalog = parse(raw_catalog)
        need(catalog.get('schema') == 'overwatch-decoder.hero-label-catalog/1', 'catalog_schema')
        entries = catalog.get('entries')
        need(isinstance(entries, list) and 1 <= len(entries) <= 128, 'entry_count')
        self.entries = {}
        def artifact(key, maximum=4*1024*1024):
            raw = artifacts.get(digest(key))
            need(isinstance(raw, bytes) and len(raw) <= maximum and sha(raw) == key, 'artifact_hash_or_size')
            return raw
        for entry in entries:
            build, resource = digest(entry['build_sha256']), guid(entry['resource_guid'])
            # TankLib teResourceGUID.Type reverses the stored 12 type bits and
            # adds one. This validates type; it does not map any hero index.
            stored_type = (int(resource, 16) >> 48) & 0xfff
            need(int(f'{stored_type:012b}'[::-1], 2) + 1 == 0x075, 'resource_not_typed_hero')
            label, locale = entry['label'], entry['locale']
            need(isinstance(label, str) and 1 <= len(label) <= 128
                 and not any(unicodedata.category(c).startswith('C') for c in label), 'invalid_label')
            need(isinstance(locale, str) and re.fullmatch(r'[a-z]{2}[A-Z]{2}', locale) is not None, 'invalid_locale')
            asset = parse(artifact(entry['asset_report_sha256']))
            need(asset.get('schema') == 'overwatch-decoder.datatool-inspect/2' and asset.get('status') == 'ok'
                 and asset.get('inputs', {}).get('language') == locale, 'asset_report_invalid')
            need(asset.get('hero', {}).get('name') == label and guid(asset['hero']['guid']) == resource, 'asset_label_or_guid_mismatch')
            roots = [a for a in asset.get('assets', []) if a.get('guid') == asset['hero']['guid']]
            need(len(roots) == 1 and roots[0].get('status') == 'decoded' and roots[0].get('type') == '0x075'
                 and roots[0].get('root_selection', {}).get('instance0_class') == 'STUHero'
                 and roots[0]['root_selection'].get('instance0_matches_expected') is True, 'typed_hero_root_missing')
            digest(roots[0]['decoded_sha256'])
            review = parse(artifact(entry['runtime_ui_review_sha256']))
            need(review.get('schema') == 'overwatch-decoder.hero-label-ui-review/1' and review.get('reviewed') is True
                 and review.get('review_method') == 'manual_visual_hud_identity', 'unreviewed_runtime_ui')
            need(review.get('label') == label and review.get('locale') == locale
                 and guid(review['resource_guid']) == resource and review.get('build_sha256') == build,
                 'runtime_ui_mapping_mismatch')
            manifest = parse(artifact(review['recording_manifest_sha256']))
            profile_bytes = artifact(manifest['profile_sha256'], 262144)
            profile = parse(profile_bytes)
            need(manifest.get('schema') == 'overwatch-decoder.field-recording/1' and manifest.get('complete') is True
                 and manifest.get('target') == profile.get('target')
                 and manifest['target'].get('executable_sha256') == build, 'runtime_source_mismatch')
            verification = parse(artifact(review['native_verification_sha256']))
            need(verification.get('schema') == 'overwatch-decoder.field-recording-verification/1'
                 and verification.get('mode') == 'strict' and verification.get('status') == 'verified_complete'
                 and verification.get('terminal_summary_verified') is True
                 and type(verification.get('frames')) is int and verification['frames'] > 0
                 and verification.get('valid') is True and verification.get('complete') is True
                 and verification.get('profile_sha256') == sha(profile_bytes)
                 and verification.get('samples_prefix_sha256') == manifest.get('samples_sha256')
                 and verification.get('index_prefix_sha256') == manifest.get('index_sha256'), 'native_validation_mismatch')
            anchors = review.get('anchors')
            need(isinstance(anchors, list) and 1 <= len(anchors) <= 64, 'ui_anchor_count')
            for anchor in anchors:
                image = artifact(anchor['screenshot_sha256'], 16*1024*1024)
                need(image.startswith(b'\x89PNG\r\n\x1a\n'), 'ui_image_not_png')
                a, b, c, d = [anchor.get(k) for k in ('capture_start_ticks', 'capture_end_ticks', 'read_start_ticks', 'read_end_ticks')]
                need(all(type(v) is int for v in (a, b, c, d)) and 0 <= a <= b and 0 <= c <= d
                     and c <= b and a <= d, 'ui_memory_brackets_do_not_overlap')
                need(type(anchor.get('sequence')) is int and 0 <= anchor['sequence'] < verification['frames']
                     and anchor.get('reviewed_label') == label and anchor.get('controller_body_match') is True
                     and anchor.get('profile_sha256') == sha(profile_bytes)
                     and guid(anchor['resource_guid']) == resource, 'ui_anchor_mapping_mismatch')
            key = build, resource, locale
            need(key not in self.entries, 'duplicate_or_conflicting_mapping')
            self.entries[key] = dict(label=label, locale=locale, resource_guid=resource, build_sha256=build,
                asset_report_sha256=entry['asset_report_sha256'], asset_decoded_sha256=roots[0]['decoded_sha256'],
                asset_build=asset.get('build'), runtime_ui_review_sha256=entry['runtime_ui_review_sha256'],
                reviewed_anchor_count=len(anchors), mapping_scope='observed_build_resource_label',
                validation_status='typed_asset_and_reviewed_runtime_ui', public_state_eligible=False)

    def lookup(self, build, resource, locale='enUS'):
        value = self.entries.get((build, guid(resource), locale))
        return None if value is None else dict(value)


class GuardedHeroLabels:
    """Stateless projection from freshly sampled controller/body resource words."""
    def __init__(self, raw_profile: bytes, catalog: HeroLabelCatalog, locale='enUS'):
        self.relations = GuardedRelations(raw_profile)
        self.catalog, self.locale = catalog, locale

    def project(self, frame, *, gap=False):
        base = self.relations.project(frame)
        result = {k: v for k, v in base.items() if k != 'relations'}
        result.update(schema='overwatch-decoder.guarded-hero-labels/1', catalog_sha256=self.catalog.hash, heroes=[])
        for relation in base['relations']:
            row = dict(controller_object_key=relation['controller_object_key'], body_object_key=relation['body_object_key'],
                       status='unknown', reason=None, resource_guid=None, hero_label=None, locale=self.locale, evidence=[])
            try:
                if gap:
                    raise InvalidBinding('gap_before_frame')
                if relation['relation_status'] != 'observed':
                    raise InvalidBinding(relation['reason'] or 'relation_unknown')
                prefix = relation['controller_prefix']
                words = [self.relations.sample_scalar(prefix + suffix, frame, 'i32') for suffix in (
                    '_part83_0000_hero_resource_low_candidate_i32', '_part83_0000_hero_resource_high_candidate_i32',
                    '_body_0000_hero_resource_low_candidate_i32', '_body_0000_hero_resource_high_candidate_i32')]
                controller = (words[0]['value'] & 0xffffffff) | ((words[1]['value'] & 0xffffffff) << 32)
                body = (words[2]['value'] & 0xffffffff) | ((words[3]['value'] & 0xffffffff) << 32)
                if controller != body:
                    raise InvalidBinding('controller_body_resource_mismatch')
                resource = guid(f'0x{body:016X}')
                mapping = self.catalog.lookup(self.relations.target['executable_sha256'], resource, self.locale)
                if mapping is None:
                    raise InvalidBinding('unmapped_build_resource_or_locale')
                row.update(status='observed', hero_label=mapping['label'], resource_guid=resource, mapping_evidence=mapping,
                           evidence=[{k: w[k] for k in ('field', 'value', 'read_start_ticks', 'read_end_ticks')} for w in words])
            except (InvalidBinding, InvalidHeroEvidence) as error:
                row['reason'] = str(error)
            result['heroes'].append(row)
        return result
