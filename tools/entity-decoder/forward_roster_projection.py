"""Preserve acquired forward owners alongside ordinary roster body records."""
import copy
import re

CATEGORY_KEYS = ('forward_category_output_enabled', 'forward_category_contract_sha256',
                 'forward_category_native_review_sha256')


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(value):
    need(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'forward_roster_digest')


def source_metadata(projector, *, hero_enabled=False, hero_catalog=None, category=None):
    """Derive opaque bindings from this acquisition's guarded profile words."""
    bindings = []
    r = projector.relations
    for binding in projector.bindings:
        words = [dict(address=word[0], value=word[1]) for word in binding['words']]
        item=dict(binding_id=binding['binding_id'], owned_field_prefix=binding['owned_field_prefix'],
            controller_object_key=r._key('controller', words[:2]),
            forward_owner_object_key=None if 'acquisition_empty_evidence'in binding else r._key('owner', words[3:]),
            identity_fields=binding['names'].copy())
        if 'acquisition_empty_evidence'in binding:item['acquisition_empty_evidence']=copy.deepcopy(binding['acquisition_empty_evidence'])
        bindings.append(item)
    result = dict(schema='overwatch-decoder.forward-owner-source/1', contract_sha256=projector.contract_hash,
        binding_template_sha256=projector.template_hash, controller_hero_output_enabled=hero_enabled,
        controller_hero_asset_catalog_sha256=hero_catalog, bindings=bindings)
    if projector.reference_groups is not None:
        result['reference_groups']=copy.deepcopy(projector.reference_groups)
    if category is not None:
        need(category.forward.contract_hash == projector.contract_hash,
             'forward_roster_category_forward_contract')
        result.update(forward_category_output_enabled=True,
            forward_category_contract_sha256=category.contract_sha256,
            forward_category_native_review_sha256=category.category_fields.native_review_sha256)
    return result


def validate_source(source):
    metadata = source.get('forward_owner_projection')
    if metadata is None:
        return
    need(isinstance(metadata, dict) and metadata.get('schema') == 'overwatch-decoder.forward-owner-source/1',
         'forward_roster_source_schema')
    for key in ('contract_sha256', 'binding_template_sha256'):
        digest(metadata.get(key))
    enabled = metadata.get('controller_hero_output_enabled')
    need(type(enabled) is bool, 'forward_roster_hero_option')
    if enabled:
        digest(metadata.get('controller_hero_asset_catalog_sha256'))
    else:
        need(metadata.get('controller_hero_asset_catalog_sha256') is None, 'forward_roster_unconfigured_hero')
    if any(key in metadata for key in CATEGORY_KEYS):
        need(metadata.get('forward_category_output_enabled') is True, 'forward_roster_category_option')
        for key in CATEGORY_KEYS[1:]:
            digest(metadata.get(key))
    declarations = source.get('fields')
    need(isinstance(declarations, list) and 1 <= len(declarations) <= 160,
         'forward_roster_field_declarations')
    fields = {}
    for field in declarations:
        need(isinstance(field, dict) and isinstance(field.get('name'), str)
             and 1 <= len(field['name']) <= 256 and field['name'] not in fields
             and field.get('type') in ('u8', 'i32', 'f32', 'f32x3'),
             'forward_roster_field_declarations')
        fields[field['name']] = field['type']
    controllers = {r['controller_object_key'] for r in source['objects']}
    bindings = metadata.get('bindings')
    need(isinstance(bindings, list) and 1 <= len(bindings) <= 32, 'forward_roster_binding_count')
    seen, prefixes = set(), []
    for binding in bindings:
        need(isinstance(binding, dict), 'forward_roster_binding')
        ident, prefix = binding.get('binding_id'), binding.get('owned_field_prefix')
        need(isinstance(ident, str) and re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,63}', ident)
             and ident not in seen, 'forward_roster_binding_id')
        seen.add(ident)
        need(isinstance(prefix, str) and re.fullmatch('[A-Za-z][A-Za-z0-9_]{0,62}_', prefix)
             and all(not prefix.startswith(p) and not p.startswith(prefix) for p in prefixes),
             'forward_roster_prefix')
        prefixes.append(prefix)
        empty=binding.get('acquisition_empty_evidence')
        if empty is not None:
            from forward_owner_validation import validate_acquisition_empty_evidence
            acquisition=source.get('acquisition')
            expected=None if acquisition is None else dict(recipe_sha256=acquisition.get('recipe_sha256'),
                evidence_sha256=acquisition.get('evidence_sha256'),acquisition_manifest_sha256=acquisition.get('manifest_sha256'))
            collection=validate_acquisition_empty_evidence(empty,expected)
            need(prefix==collection['prefix']+'_0000_'and binding.get('forward_owner_object_key')is None
                 and not any(n.startswith(prefix)for n in fields),'forward_roster_empty_payload')
        need(binding.get('controller_object_key') in controllers
             and (binding.get('forward_owner_object_key')is None if empty is not None else isinstance(binding.get('forward_owner_object_key'),str)
                  and re.fullmatch('owner:[0-9a-f]{64}', binding['forward_owner_object_key'])),
             'forward_roster_configured_identity')
        names = binding.get('identity_fields')
        need(isinstance(names, list) and len(names) == (3 if empty is not None else 5)
             and all(isinstance(n, str) for n in names) and len(set(names)) == len(names)
             and all(fields.get(n) == 'i32' for n in names)
             and all(n.startswith(prefix) for n in names[3:]), 'forward_roster_identity_fields')


    from forward_owner_relations import reference_group_membership
    groups=metadata.get('reference_groups')
    need('reference_groups' not in metadata or groups is not None,'reference_group_count')
    reference_group_membership(groups, seen)
    by_id={b['binding_id']:b for b in bindings}
    for group in groups or []:
        members=[by_id[n] for n in group['binding_ids']]
        need(all(b.get('acquisition_empty_evidence')is None for b in members)
             and len({b['controller_object_key'] for b in members})==1
             and len({b['identity_fields'][2] for b in members})==len(members),
             'forward_roster_reference_group_scope')


def validate_frame(frame, source):
    from forward_owner_validation import validate_forward_owner_frame
    expected = source.get('forward_owner_projection')
    node = frame.get('forward_owner_projection')
    need((expected is None) == (node is None), 'forward_roster_source_option_changed')
    if node is None:
        return None
    metadata, _ = validate_forward_owner_frame(frame,
        declarations={f['name']: f['type'] for f in source['fields']},
        controllers={r['controller_object_key'] for r in source['objects']})
    for key in ('contract_sha256', 'binding_template_sha256', 'controller_hero_output_enabled'):
        need(metadata.get(key) == expected[key], 'forward_roster_contract_changed')
    need(metadata.get('controller_hero_asset_catalog_sha256') == expected['controller_hero_asset_catalog_sha256'],
         'forward_roster_hero_catalog_changed')
    need({key: metadata[key] for key in CATEGORY_KEYS if key in metadata}
         == {key: expected[key] for key in CATEGORY_KEYS if key in expected},
         'forward_roster_category_admission_changed')
    need(('reference_groups' in node)==('reference_groups' in expected)
         and metadata.get('reference_groups')==expected.get('reference_groups'),'forward_roster_reference_groups_changed')
    bindings = {b['binding_id']: b for b in expected['bindings']}
    need(len(node['relations']) == len(bindings)
         and {r['binding_id'] for r in node['relations']} == set(bindings), 'forward_roster_binding_set_changed')
    for row in node['relations']:
        binding = bindings[row['binding_id']]
        need(row['owned_field_prefix'] == binding['owned_field_prefix'], 'forward_roster_prefix_changed')
        for key in ('controller_object_key', 'forward_owner_object_key'):
            need(row.get(key) is None or row[key] == binding[key], 'forward_roster_identity_changed_without_epoch')
        need(row.get('acquisition_empty_evidence')==binding.get('acquisition_empty_evidence'),'forward_roster_empty_proof_changed')
        if row['relation_status'] == 'observed' or row.get('reason')=='acquisition_empty':
            need([w['field'] for w in row['identity_evidence']] == binding['identity_fields'],
                 'forward_roster_identity_fields_changed')
    return node


def attach_window(result, manifest, usable):
    """Only fresh primary frames select values; supports never fill a gap."""
    sources = {sid: source['forward_owner_projection'] for sid, source in manifest.sources.items()
               if source.get('forward_owner_projection') is not None}
    if not sources:
        return
    result['forward_owner_sources'] = copy.deepcopy(sources)
    projections = {}
    for sid, frame in usable.items():
        node = frame.get('forward_owner_projection')
        if node is not None:
            projections[sid] = dict(source_id=sid, source_timing=copy.deepcopy(frame['timing']),
                source_artifacts=copy.deepcopy(frame['artifacts']), source_recording=copy.deepcopy(frame['recording']),
                semantic_projection_sha256=frame['semantic_source_sha256'], source_gap=copy.deepcopy(frame['gap']),
                semantic_hash_scope=frame.get('semantic_hash_scope', 'projection_line'),
                source_admission=copy.deepcopy(sources[sid]), projection=copy.deepcopy(node))
    result['forward_owner_projections'] = projections
    primaries = {controller: primary for (controller, _), primary in manifest.roster.items()}
    rows = []
    for sid, metadata in sources.items():
        for binding in metadata['bindings']:
            if primaries[binding['controller_object_key']] != sid:
                continue
            observed = projections.get(sid)
            index = None
            reason = result['unavailable_sources'].get(sid, 'forward_owner_projection_unavailable')
            if observed is not None:
                matches = [(i, r) for i, r in enumerate(observed['projection']['relations'])
                           if r['binding_id'] == binding['binding_id']]
                need(len(matches) == 1, 'forward_window_binding_missing')
                index, row = matches[0]
                reason = None if row['relation_status'] == 'observed' else row['reason']
            rows.append(dict({k: binding[k] for k in ('binding_id', 'owned_field_prefix',
                'controller_object_key', 'forward_owner_object_key')}, primary_source_id=sid,
                status='observed' if reason is None else 'unknown', reason=reason,
                projection_ref=f'/forward_owner_projections/{sid}/projection' if reason is None else None,
                relation_index=index if reason is None else None, current_displayed_body=None))
    result['forward_owners'] = rows


def acquire_source_metadata(profile_bytes, epoch, frame, source):
    """Verify actual producer artifacts, then pin its fresh forward declarations."""
    from export_relations import bounded_local_bytes, load_local_artifacts
    from forward_owner_relations import GuardedForwardOwners
    node = frame.get('forward_owner_projection')
    if node is None:
        need(not (epoch/'forward-contract.json').exists(), 'forward_roster_configured_output_missing')
        return None
    raw_contract = bounded_local_bytes(epoch/'forward-contract.json', 262144, 'forward_contract_size')
    artifacts = load_local_artifacts(epoch/'forward-artifacts.json', 'forward_owner',
                                    maximum_artifact=128*1024*1024, maximum_total=130*1024*1024)
    projector = GuardedForwardOwners(profile_bytes, raw_contract, artifacts)
    need(projector.relations.hash == source['profile_sha256']
         and all(source['acquisition'][k] == v for k, v in projector.source.items())
         and source['acquisition']['manifest_sha256'] == projector.manifest_hash,
         'forward_roster_acquisition_mismatch')
    category = None
    category_path = epoch/'forward-category-contract.json'
    if any(key in node for key in CATEGORY_KEYS):
        from forward_owner_categories import GuardedForwardOwnerCategories
        need(node.get('forward_category_output_enabled') is True, 'forward_roster_category_option')
        artifacts.update(load_local_artifacts(epoch/'forward-category-artifacts.json', 'forward_category'))
        category = GuardedForwardOwnerCategories(profile_bytes, raw_contract,
            bounded_local_bytes(category_path, 262144, 'forward_category_contract_size'), artifacts)
    else:
        need(not category_path.exists(), 'forward_roster_configured_category_missing')
    metadata = source_metadata(projector, hero_enabled=node.get('controller_hero_output_enabled'),
                               hero_catalog=node.get('controller_hero_asset_catalog_sha256'), category=category)
    checked = dict(source, forward_owner_projection=metadata)
    validate_source(checked)
    validate_frame(frame, checked)
    return metadata
