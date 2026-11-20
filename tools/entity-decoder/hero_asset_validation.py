"""Validate optional typed-asset hero candidates in accepted semantic JSON.

This verifies the source's same-frame claims, not the asset bytes or runtime UI.
Keep the hashed original semantic/native sources and catalog reports. No mapping,
controller-only fallback or historical candidate is introduced here.
"""
import re
import unicodedata


class InvalidHeroAssetCandidate(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise InvalidHeroAssetCandidate(reason)


def digest(value):
    need(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'asset_invalid_digest')
    return value


KEYS = ('hero_asset_label_candidate', 'hero_asset_label_evidence', 'hero_asset_label_reason')


def present(row):
    return any(key in row for key in KEYS)


def metadata(row):
    """Source pins retained with an observation after its frame was validated."""
    if not present(row):
        return None
    evidence = row.get('hero_asset_label_evidence')
    return dict(output_enabled=True, catalog_sha256=None if evidence is None else evidence.get('catalog_sha256'))


def validate_hero_asset_candidate(row, frame, *, detached=False):
    """Return the four-word span, or None for an explicitly unknown candidate.

    ``detached`` is for an aggregate observation, whose metadata comes from its
    already admitted row. Full source frames must pin the top-level opt-in and
    catalog. Detached callers still verify every object/source/time/value pin.
    """
    enabled = frame.get('hero_asset_output_enabled')
    has = present(row)
    if not has:
        need(enabled is not True, 'asset_enabled_row_missing')
        return None
    need(all(key in row for key in KEYS), 'asset_partial_row')
    need(detached or enabled is True, 'asset_unconfigured_candidate')
    catalog = frame.get('hero_asset_catalog_sha256')
    if not detached:
        digest(catalog)
    value, evidence, reason = (row[key] for key in KEYS)
    need(reason is None or isinstance(reason, str) and 0 < len(reason) <= 1024, 'asset_invalid_reason')
    if value is None:
        need(evidence is None, 'asset_unknown_has_evidence')
        return None
    need(row.get('relation_status') == 'observed' and row.get('controller_object_key') is not None
         and row.get('body_object_key') is not None and not frame.get('gap_before', {}).get('skipped_slots'),
         'asset_without_current_body')
    need(isinstance(value, str) and 1 <= len(value) <= 128
         and not any(unicodedata.category(c).startswith('C') for c in value) and reason is None,
         'asset_invalid_label')
    need(isinstance(evidence, dict), 'asset_missing_evidence')
    target, timing, source = frame['target'], frame['timing'], frame['source_artifacts']
    profile, build = frame['profile_sha256'], target['executable_sha256']
    need(evidence.get('profile_sha256') == profile and evidence.get('build_sha256') == build
         and evidence.get('source_target') == target and evidence.get('frame_timing') == timing
         and evidence.get('acquisition') == source['acquisition']
         and evidence.get('controller_object_key') == row['controller_object_key']
         and evidence.get('body_object_key') == row['body_object_key'], 'asset_source_binding_mismatch')
    for key in ('manifest_sha256', 'recipe_sha256', 'evidence_sha256'):
        digest(evidence['acquisition'].get(key))
    pin = digest(evidence.get('catalog_sha256'))
    need(catalog is None and detached or catalog == pin, 'asset_catalog_mismatch')
    need(evidence.get('binding_scope') == 'controller_and_body'
         and evidence.get('validation_status') == 'guarded_typed_asset_resource_candidate'
         and evidence.get('runtime_ui_validated') is False and evidence.get('public_state_eligible') is False
         and evidence.get('visibility') == 'unknown', 'asset_invalid_qualification')
    resource = row.get('hero_resource_guid_candidate')
    need(isinstance(resource, dict) and resource.get('controller_body_match') is True
         and resource.get('value') == evidence.get('resource_guid'), 'asset_resource_mismatch')
    guid = evidence.get('resource_guid')
    need(isinstance(guid, str) and re.fullmatch('0x[0-9A-F]{16}', guid), 'asset_invalid_resource')
    # The native type encoding must identify a hero root, as in HeroAssetCatalog.
    stored_type = (int(guid, 16) >> 48) & 0xfff
    need(int(f'{stored_type:012b}'[::-1], 2) + 1 == 0x075, 'asset_resource_not_hero')
    words = evidence.get('fields')
    need(isinstance(words, list) and len(words) == 4 and all(isinstance(w, dict) for w in words), 'asset_four_words_required')
    expected = ('_part83_0000_hero_resource_low_candidate_i32', '_part83_0000_hero_resource_high_candidate_i32',
                '_body_0000_hero_resource_low_candidate_i32', '_body_0000_hero_resource_high_candidate_i32')
    prefix = row.get('controller_prefix')
    need(isinstance(prefix, str) and [w.get('field') for w in words] == [prefix+s for s in expected],
         'asset_word_field_binding')
    starts, ends = [], []
    for word in words:
        number, start, end = word.get('value'), word.get('read_start_ticks'), word.get('read_end_ticks')
        need(type(number) is int and -(1 << 31) <= number < (1 << 31)
             and type(start) is int and type(end) is int
             and timing['start_ticks'] <= start <= end <= timing['end_ticks'], 'asset_word_value_or_span')
        starts.append(start); ends.append(end)
    controller = (words[0]['value'] & 0xffffffff) | ((words[1]['value'] & 0xffffffff) << 32)
    body = (words[2]['value'] & 0xffffffff) | ((words[3]['value'] & 0xffffffff) << 32)
    need(controller == body == int(guid, 16), 'asset_word_resource_mismatch')
    original = resource.get('evidence')
    need(isinstance(original, list) and len(original) == 4
         and all(all(a.get(k) == b.get(k) for k in ('field', 'value', 'read_start_ticks', 'read_end_ticks'))
                 for a, b in zip(words, original)), 'asset_resource_evidence_mismatch')
    mapping = evidence.get('mapping')
    need(isinstance(mapping, dict) and mapping.get('label') == value and mapping.get('resource_guid') == guid
         and mapping.get('build_sha256') == build and mapping.get('mapping_scope') == 'caller_build_scoped_typed_asset'
         and mapping.get('validation_status') == 'typed_asset_resource_match'
         and mapping.get('runtime_ui_validated') is False and mapping.get('public_state_eligible') is False
         and isinstance(mapping.get('locale'), str) and re.fullmatch('[a-z]{2}[A-Z]{2}', mapping['locale']),
         'asset_mapping_mismatch')
    for key in ('asset_report_sha256', 'asset_decoded_sha256'):
        digest(mapping.get(key))
    return [min(starts), max(ends)]


def compact_hero_asset(row, frame, base, *, detached=False):
    reads = validate_hero_asset_candidate(row, frame, detached=detached)
    if not present(row):
        return None
    value = row['hero_asset_label_candidate']; reason = row['hero_asset_label_reason']
    result = dict(status='guarded_typed_asset_resource_candidate' if value is not None else 'unknown',
                  value=value, reason=reason, read_span_ticks=reads,
                  evidence_ref=base+'/hero_asset_label_evidence' if value is not None else None,
                  runtime_ui_validated=False)
    if reason is not None:
        result['reason_ref'] = base+'/hero_asset_label_reason'
    return result
