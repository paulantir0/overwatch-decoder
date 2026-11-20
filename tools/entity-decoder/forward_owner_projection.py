"""Compose explicitly acquired forward owners without inventing a current body.

The normal reciprocal-body projection remains independent. Hero metadata here
describes the controller; it does not identify the owner's active form.
"""
from __future__ import annotations

from projection_copy import detached_copy


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


class ForwardOwnerProjection:
    def __init__(self, projector, health_contracts=(), controller_hero=None, category_projector=None):
        self.projector = projector
        self.relations = projector.relations
        self.health = tuple(health_contracts)
        self.hero = controller_hero
        self.category = category_projector
        if self.category is not None:
            need(self.category.forward.contract_hash == projector.contract_hash
                 and self.category.forward.relations.hash == self.relations.hash
                 and self.category.forward.relations.target == self.relations.target,
                 'forward_category_scope')
        need(len(self.health) <= 32, 'forward_health_contract_count')
        need(len({c.binding_id for c in self.health}) == len(self.health),
             'duplicate_forward_health_contract')
        if controller_hero is not None:
            need(controller_hero.require_body is False
                 and controller_hero.relations.hash == self.relations.hash
                 and controller_hero.relations.target == self.relations.target,
                 'forward_controller_hero_scope')

    def verify_source(self, source):
        expected = dict(self.projector.source, manifest_sha256=self.projector.manifest_hash)
        acquisition = source.get('acquisition', {})
        need(source.get('profile_sha256') == self.relations.hash
             and all(acquisition.get(k) == v for k, v in expected.items()),
             'forward_acquisition_mismatch')

    def project(self, frame, source, *, gap=False):
        self.verify_source(source)
        base = self.projector.project(frame, gap=gap)
        # project() returns a fresh fully detached tree; no earlier result or
        # input frame owns it. Enrich that tree directly.
        result = base
        result['source_artifacts'] = detached_copy(source)
        result['controller_hero_output_enabled'] = self.hero is not None
        categories = []
        if self.category is not None:
            projection = self.category.project(frame, gap=gap)
            need(projection.get('profile_sha256') == result['profile_sha256']
                 and projection.get('target') == result['target']
                 and projection.get('timing') == result['timing']
                 and projection.get('source_evidence') == result['source_evidence']
                 and projection.get('forward_contract_sha256') == self.projector.contract_hash
                 and projection.get('contract_sha256') == self.category.contract_sha256
                 and projection.get('native_review_sha256') == self.category.category_fields.native_review_sha256,
                 'forward_category_source')
            categories = projection['rows']
            result.update(forward_category_output_enabled=True,
                          forward_category_contract_sha256=self.category.contract_sha256,
                          forward_category_native_review_sha256=projection['native_review_sha256'])
        heroes = []
        if self.hero is not None:
            hero = self.hero.project(frame, gap=gap)
            need(hero.get('profile_sha256') == result['profile_sha256']
                 and hero.get('target') == result['target']
                 and all(hero.get('timing', {}).get(k) == v for k, v in result['timing'].items())
                 and hero.get('catalog_sha256') == self.hero.catalog.hash,
                 'forward_controller_hero_source')
            heroes = hero['heroes']
            result['controller_hero_asset_catalog_sha256'] = hero['catalog_sha256']
        health = {}
        for contract in self.health:
            value = contract.project(frame, forward_relation_projection=base, gap=gap)
            if value is not None:
                key = (value.get('binding_id'), value.get('owned_field_prefix'),
                       value.get('controller_object_key'), value.get('forward_owner_object_key'))
                health[key] = None if key in health else value
        for row in result['relations']:
            row.update(position_candidate=None, health_candidate=None,
                       controller_hero_asset_label_candidate=None,
                       controller_hero_asset_label_evidence=None,
                       controller_hero_asset_label_reason='controller_hero_not_configured')
            if self.category is not None:
                row.update(raw_flags_candidate=None, raw_category_candidate=None,
                           raw_category_evidence=None, raw_category_reason='forward_relation_unknown')
            if row['relation_status'] != 'observed' or gap:
                row['controller_hero_asset_label_reason'] = row.get('reason') or 'forward_relation_unknown'
                continue
            if self.category is not None:
                matches = [c for c in categories if all(c.get(k) == row[k] for k in
                    ('binding_id', 'owned_field_prefix', 'controller_object_key', 'forward_owner_object_key'))]
                row['raw_category_reason'] = 'missing_or_ambiguous_forward_category'
                if len(matches) == 1:
                    c = matches[0]
                    row['raw_category_reason'] = c['reason']
                    if c.get('raw_status') == 'observed':
                        binding = next(b for b in self.category.condition_bindings
                                       if b['binding_id'] == row['binding_id'])
                        fields = self.category.category_fields
                        conditions = []
                        for condition in binding['conditions']:
                            value, ids = fields._guard_value(condition['address'], condition['width'])
                            conditions.append(dict(
                                role=condition['role'], width=condition['width'], mask=condition['mask'],
                                equals=condition['equals'], guarded_value=value, guard_ids=sorted(ids)))
                        row['raw_flags_candidate'] = detached_copy(c['raw_flags_candidate'])
                        row['raw_category_candidate'] = c['raw_category_candidate'] if c.get('status') == 'observed' else None
                        row['raw_category_evidence'] = dict(
                            fields=detached_copy(c['evidence']),
                            forward_identity_fields=detached_copy(c['forward_identity_evidence']),
                            contract_sha256=self.category.contract_sha256,
                            forward_contract_sha256=self.projector.contract_hash,
                            native_review_sha256=projection['native_review_sha256'],
                            profile_sha256=result['profile_sha256'],
                            build_sha256=result['target']['executable_sha256'],
                            source=detached_copy(result['source_evidence']),
                            frame_timing=detached_copy(result['timing']),
                            algorithm=dict(ordered_bits=fields.ordered_bits.copy(),
                                clear_bits=fields.clear_bits.copy(), supported_categories=fields.supported.copy()),
                            conditions=conditions,
                            current_displayed_body=None, public_state_eligible=False, visibility='unknown')
            name = row['owned_field_prefix'] + 'position_candidate'
            position = row['owned_fields'].get(name, {})
            if position.get('status') == 'observed' and position.get('type') == 'f32x3':
                row['position_candidate'] = dict(detached_copy(position), field=name,
                    source='process_memory', profile_sha256=result['profile_sha256'],
                    build_sha256=result['target']['executable_sha256'],
                    forward_owner_object_key=row['forward_owner_object_key'],
                    validation_status='guarded_forward_owned_field_research',
                    current_displayed_body=None, public_state_eligible=False, visibility='unknown')
            row['health_candidate'] = health.get((row['binding_id'], row['owned_field_prefix'],
                                                   row['controller_object_key'], row['forward_owner_object_key']))
            if self.hero is None:
                continue
            matches = [h for h in heroes if h.get('controller_object_key') == row['controller_object_key']]
            if len(matches) != 1 or matches[0].get('status') != 'observed':
                row['controller_hero_asset_label_reason'] = 'missing_or_unknown_controller_hero'
                continue
            h = matches[0]
            need(h.get('binding_scope') == 'controller_only' and h.get('body_object_key') is None
                 and h.get('runtime_ui_validated') is False,
                 'forward_controller_hero_binding')
            row['controller_hero_asset_label_candidate'] = h['hero_label_candidate']
            row['controller_hero_asset_label_evidence'] = detached_copy(dict(
                mapping=h['mapping_evidence'], fields=h['evidence'],
                controller_object_key=row['controller_object_key'], binding_scope='controller_only',
                catalog_sha256=self.hero.catalog.hash, profile_sha256=result['profile_sha256'],
                build_sha256=result['target']['executable_sha256'], frame_timing=result['timing'],
                source_artifacts=source, runtime_ui_validated=False,
                current_displayed_body=None, public_state_eligible=False, visibility='unknown'))
            row['controller_hero_asset_label_reason'] = None
        return result


def load_forward_projection(profile_bytes, contract_path, artifacts_path,
                            health_paths=(), hero_asset_projector=None,
                            category_contract_path=None, category_artifacts_path=None):
    from export_relations import bounded_local_bytes, load_local_artifacts, parse
    from forward_owner_relations import GuardedForwardOwners
    from overwatch_decoder.health_projection import ForwardOwnerHealthContract
    projector = GuardedForwardOwners(profile_bytes,
        bounded_local_bytes(contract_path, 262144, 'forward_contract_size'),
        load_local_artifacts(artifacts_path, 'forward_owner',
                             maximum_artifact=128*1024*1024, maximum_total=130*1024*1024))
    health = []
    need(len(health_paths) <= 32, 'forward_health_contract_count')
    for path in health_paths:
        descriptor = parse(bounded_local_bytes(path, 262144, 'forward_health_descriptor_size'))
        need(descriptor.get('forward_contract_sha256') == projector.contract_hash
             and descriptor.get('acquisition_manifest_sha256') == projector.manifest_hash
             and descriptor.get('acquisition_evidence_sha256') == projector.source['evidence_sha256']
             and descriptor.get('recipe_sha256') == projector.source['recipe_sha256'],
             'forward_health_acquisition_mismatch')
        health.append(ForwardOwnerHealthContract.from_profile(profile_bytes, **descriptor))
    hero = None
    if hero_asset_projector is not None:
        from hero_asset_labels import GuardedHeroAssetLabels
        hero = GuardedHeroAssetLabels(profile_bytes, hero_asset_projector.catalog,
                                     hero_asset_projector.locale, require_body=False)
    need(bool(category_contract_path) == bool(category_artifacts_path),
         'forward_category_contract_and_artifacts_required_together')
    category = None
    if category_contract_path:
        from forward_owner_categories import GuardedForwardOwnerCategories
        artifacts = load_local_artifacts(artifacts_path, 'forward_owner',
            maximum_artifact=128*1024*1024, maximum_total=130*1024*1024)
        artifacts.update(load_local_artifacts(category_artifacts_path, 'forward_category'))
        category = GuardedForwardOwnerCategories(profile_bytes,
            bounded_local_bytes(contract_path, 262144, 'forward_contract_size'),
            bounded_local_bytes(category_contract_path, 262144, 'forward_category_contract_size'), artifacts)
    return ForwardOwnerProjection(projector, health, hero, category)
