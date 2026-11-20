"""Offline exact-controller planning from a hash-verified native census.

Caller-owned templates supply all application knowledge. Outputs are acquisition
recipes, not current observations: every partition needs a new native acquisition
and fresh semantic contracts. No labels, team roles, or self identity are inferred.

A overwatch-decoder.roster-recipe-template/1 object contains `recipe` plus `selection`:
  scan_pointer: JSON pointer to a scan object within a parent steps array
  maximum_controllers: caller-reviewed partition bound
  full_handle_expression / creation_key_expression: native recipe expressions
The planner appends one filter inside that scan and one exact retained-count
requirement immediately after it. Existing filters, guards, and bounds stay intact.
This is a caller-reviewed template contract; the planner does not establish that
arbitrary supplied expressions implement controller identity or complete a roster.

CLI: --census-acquisition DIR --expected-target TARGET.json --template FILE
     --template-sha256 SHA --partition-size N --output NEW_DIRECTORY
Optional --anchor-controller-key repeats one exact census controller in each
partition, primary only once. This does not label that controller as self. A saved
census cannot establish current liveness; target matching rejects a different
process epoch, and each output must be reacquired and independently admitted.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import stat
from pathlib import Path

from relations import GuardedRelations, InvalidBinding


class InvalidPlan(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise InvalidPlan(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def parse(raw):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            need(key not in out, 'duplicate_json_key')
            out[key] = value
        return out
    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: need(False, 'nonfinite_json'))
    except (ValueError, TypeError, RecursionError) as error:
        raise InvalidPlan('invalid_json') from error


def read(path, maximum):
    path = Path(path)
    with path.open('rb') as file:
        need(stat.S_ISREG(os.fstat(file.fileno()).st_mode), 'not_regular_file')
        raw = file.read(maximum + 1)
    need(len(raw) <= maximum, 'artifact_size')
    return raw


def encoded(value):
    return (json.dumps(value, indent=2, allow_nan=False) + '\n').encode()


def verified_census(directory, recipe_path=None, *, expected_target=None):
    """Verify saved acquisition provenance and final rechecks of every guard.

    This checks the native evidence transcript, not whether the process remains
    alive or the census still describes it. Final checks are sequential, not atomic.
    """
    directory = Path(directory)
    manifest_raw = read(directory/'manifest.json', 262144)
    profile_raw = read(directory/'profile.json', 262144)
    recipe_raw = read(recipe_path or directory/'recipe.json', 1048576)
    evidence_raw = read(directory/'evidence.jsonl', 128*1024*1024)
    manifest, recipe = parse(manifest_raw), parse(recipe_raw)
    need(isinstance(manifest, dict) and isinstance(recipe, dict), 'invalid_acquisition_metadata')
    need(manifest.get('schema') == 'overwatch-decoder.acquisition-result/1'
         and manifest.get('complete') is True and manifest.get('error') is None,
         'incomplete_census')
    for raw, key in ((profile_raw, 'profile_sha256'), (recipe_raw, 'recipe_sha256'),
                     (evidence_raw, 'evidence_sha256')):
        need(digest(raw) == manifest.get(key), 'source_hash_mismatch:' + key)
    try:
        relations = GuardedRelations(profile_raw)
    except (ValueError, KeyError, TypeError) as error:
        raise InvalidPlan('invalid_census_profile') from error
    need(manifest.get('target') == relations.profile['target'], 'source_target_mismatch')
    target = relations.target
    if expected_target is not None:
        need(expected_target == target, 'expected_process_epoch_mismatch')
    need(all(recipe.get('target', {}).get(k) == target[k]
             for k in ('image_name', 'executable_sha256', 'architecture')), 'recipe_target_mismatch')
    need(manifest.get('stages_completed') == len(recipe.get('stages', [])) > 0,
         'incomplete_census_stages')
    declarations = set()
    for guard in relations.guards:
        try:
            b = bytes.fromhex(guard['bytes_hex'])
            at = guard['address']
            need(type(at) is int and 0 < at < 2**63 and 1 <= len(b) <= 64, 'invalid_guard')
            declarations.add((at, b))
        except (ValueError, KeyError, TypeError) as error:
            raise InvalidPlan('invalid_guard') from error
    reads, checked = {}, set()
    start = last = None
    total_read_bytes = 0
    for index, line in enumerate(evidence_raw.splitlines()):
        need(index < 250000 and len(line) <= 4*1024*1024, 'evidence_bounds')
        event = parse(line)
        need(isinstance(event, dict), 'invalid_evidence_event')
        if index == 0:
            start = event
            need(event.get('schema') == 'overwatch-decoder.acquisition-evidence/1'
                 and event.get('kind') == 'start'
                 and event.get('source_kind') == 'native_process_memory'
                 and event.get('target') == relations.profile['target']
                 and event.get('recipe_sha256') == digest(recipe_raw)
                 and event.get('revision') == manifest.get('revision'), 'evidence_source_mismatch')
        kind = event.get('kind')
        if kind == 'read':
            need(type(event.get('id')) is int and event['id'] == len(reads), 'read_sequence')
            try:
                b = bytes.fromhex(event['bytes_hex'])
            except (ValueError, KeyError, TypeError) as error:
                raise InvalidPlan('invalid_read_bytes') from error
            total_read_bytes += len(b)
            need(total_read_bytes <= 64*1024*1024, 'read_bytes_bounds')
            reads[event['id']] = (event, b)
        elif kind == 'guard_check':
            need(event.get('matches') is True, 'failed_census_guard')
            if event.get('stage') == 'final_guard_check':
                expected_id, actual_id = event.get('expected_read_id'), event.get('actual_read_id')
                offset = event.get('expected_offset')
                need(type(expected_id) is int and type(actual_id) is int
                     and expected_id < actual_id and expected_id in reads and actual_id in reads
                     and type(offset) is int and offset >= 0, 'invalid_final_guard_reference')
                expected, original = reads[expected_id]
                actual, data = reads[actual_id]
                width = actual.get('requested_bytes')
                need(type(width) is int and 1 <= width <= 64
                     and actual.get('attempted') is True and actual.get('error') is None
                     and actual.get('returned_bytes') == len(data) == width
                     and expected.get('attempted') is True and expected.get('error') is None
                     and expected.get('returned_bytes') == len(original)
                     and type(expected.get('address')) is int
                     and actual.get('address') == expected['address'] + offset
                     and original[offset:offset+width] == data, 'final_guard_bytes_mismatch')
                ticks = [expected.get('read_start_ticks'), expected.get('read_end_ticks'),
                         actual.get('read_start_ticks'), actual.get('read_end_ticks')]
                need(all(type(t) is int for t in ticks)
                     and 0 <= ticks[0] <= ticks[1] <= ticks[2] <= ticks[3], 'final_guard_timing')
                checked.add((actual['address'], data))
        last = event
    need(start is not None and last.get('kind') == 'profile_validated'
         and last.get('profile_sha256') == relations.hash
         and last.get('fields') == len(relations.fields), 'missing_profile_validation')
    need(declarations and declarations <= checked, 'unchecked_profile_guard')
    need(1 <= len(relations.prefixes) <= 64, 'controller_count_bounds')
    identities = []
    for prefix in relations.prefixes:
        words = []
        try:
            for suffix in ('_handle_candidate_i32', '_manager_key_candidate_i32'):
                address, value = relations._binding(prefix + suffix)
                words.append(dict(address=address, value=value))
        except (InvalidBinding, KeyError, TypeError) as error:
            raise InvalidPlan('unguarded_controller_identity') from error
        identities.append(dict(controller_object_key=relations._key('controller', words),
                               full_handle_u32=words[0]['value'], creation_key_u32=words[1]['value']))
    need(len({x['full_handle_u32'] for x in identities}) == len(identities)
         and len({x['controller_object_key'] for x in identities}) == len(identities),
         'ambiguous_controller_identity')
    identities.sort(key=lambda x: (x['full_handle_u32'], x['creation_key_u32']))
    return dict(target=target, controllers=identities,
                source=dict(manifest_sha256=digest(manifest_raw), profile_sha256=relations.hash,
                            recipe_sha256=digest(recipe_raw), evidence_sha256=digest(evidence_raw),
                            monotonic_origin_ticks=start.get('monotonic_origin_ticks'),
                            monotonic_frequency=start.get('monotonic_frequency')))


def pointer(document, path):
    need(isinstance(path, str) and path.startswith('/') and len(path) <= 1024, 'scan_pointer')
    parts = path[1:].split('/')
    current = document
    try:
        for part in parts[:-1]:
            token = part.replace('~1', '/').replace('~0', '~')
            current = current[int(token)] if isinstance(current, list) else current[token]
        need(isinstance(current, list) and re.fullmatch(r'0|[1-9][0-9]*', parts[-1]), 'scan_parent_not_steps')
        index = int(parts[-1])
        return current, index, current[index]
    except (KeyError, IndexError, TypeError, ValueError) as error:
        raise InvalidPlan('scan_pointer_unresolved') from error


def plan(census, template_raw, *, template_sha256, partition_size, anchor_controller_key=None,
         maximum_total_fields=8192, maximum_total_guards=16384):
    """Append selection only; preserve all caller-owned acquisition dependencies."""
    need(isinstance(template_raw, bytes) and len(template_raw) <= 1048576, 'template_size')
    need(digest(template_raw) == template_sha256, 'template_hash_mismatch')
    template = parse(template_raw)
    need(isinstance(template, dict), 'template_object')
    need(template.get('schema') == 'overwatch-decoder.roster-recipe-template/1', 'template_schema')
    base = template.get('recipe')
    need(isinstance(base, dict) and base.get('schema') == 'overwatch-decoder.acquisition-recipe/1', 'recipe_schema')
    need(all(base.get('target', {}).get(k) == census['target'][k]
             for k in ('image_name', 'executable_sha256', 'architecture')), 'template_target_mismatch')
    selection = template.get('selection', {})
    need(isinstance(selection, dict), 'selection_object')
    maximum = selection.get('maximum_controllers')
    need(type(maximum) is int and 1 <= maximum <= 64
         and type(partition_size) is int and 1 <= partition_size <= maximum, 'partition_bounds')
    expressions = [selection.get(k) for k in ('full_handle_expression', 'creation_key_expression')]
    need(all(isinstance(e, list) and 1 <= len(encoded(e)) <= 8192 for e in expressions),
         'selector_expressions')
    _, _, scan = pointer(base, selection.get('scan_pointer'))
    need(isinstance(scan, dict) and scan.get('op') == 'scan' and isinstance(scan.get('name'), str)
         and isinstance(scan.get('steps'), list), 'selector_not_scan')
    identities = census['controllers']
    anchor = None
    if anchor_controller_key is not None:
        anchors = [x for x in identities if x['controller_object_key'] == anchor_controller_key]
        need(len(anchors) == 1, 'anchor_not_in_census')
        anchor = anchors[0]
    others = [x for x in identities if x is not anchor]
    capacity = partition_size - bool(anchor)
    need(not others or capacity > 0, 'anchor_consumes_partition')
    groups = [others[i:i+capacity] for i in range(0, len(others), capacity)] if others else [[]]
    # These are total admission ceilings, not estimates of dynamic expansion.
    need(type(maximum_total_fields) is int and 1 <= maximum_total_fields <= 8192
         and type(maximum_total_guards) is int and 1 <= maximum_total_guards <= 16384
         and len(groups)*160 <= maximum_total_fields
         and len(groups)*256 <= maximum_total_guards, 'total_admission_budget')
    parts, primary = [], []
    for ordinal, group in enumerate(groups, 1):
        selected = ([anchor] if anchor else []) + group
        # Stable source-independent ordering, including the repeated anchor.
        selected.sort(key=lambda x: (x['full_handle_u32'], x['creation_key_u32']))
        recipe = copy.deepcopy(base)
        parent, index, candidate_scan = pointer(recipe, selection['scan_pointer'])
        clauses = [['both', ['eq', expressions[0], actor['full_handle_u32']],
                    ['eq', expressions[1], actor['creation_key_u32']]] for actor in selected]
        predicate = clauses[0]
        for clause in clauses[1:]:
            predicate = ['either', predicate, clause]
        candidate_scan['steps'].append(dict(op='filter', test=predicate))
        parent.insert(index+1, dict(op='require', test=['eq', ['count', ['var', candidate_scan['name']]], len(selected)]))
        recipe_raw = encoded(recipe)
        need(len(recipe_raw) <= 1048576, 'generated_recipe_size')
        actors = []
        for actor in selected:
            role = 'support' if actor is anchor and ordinal != 1 else 'primary'
            actors.append(dict(actor, observation_role=role))
            if role == 'primary':
                primary.append(dict(controller_object_key=actor['controller_object_key'], partition=ordinal))
        parts.append(dict(ordinal=ordinal, controllers=actors, recipe_sha256=digest(recipe_raw),
                          recipe_file=f'partition-{ordinal:04d}-recipe.json', recipe_bytes=recipe_raw))
    need(len(primary) == len(identities) and len({x['controller_object_key'] for x in primary}) == len(primary),
         'primary_coverage_mismatch')
    return dict(schema='overwatch-decoder.live-roster-plan/1', target=census['target'], census_source=census['source'],
                template_sha256=digest(template_raw), controller_count=len(identities),
                anchor_controller_key=anchor_controller_key, anchor_semantics='caller_supplied_not_inferred',
                primary_controller_map=primary, partitions=parts,
                admission_ceiling=dict(per_partition_fields=160, per_partition_guards=256,
                                       total_fields=len(parts)*160, total_guards=len(parts)*256,
                                       dynamic_expansion_counts_known=False),
                requires_fresh_native_acquisition=True,
                requires_fresh_semantic_contracts=True, native_admission_verified=False,
                roster_completeness='supplied_census_only', atomic=False,
                public_state_eligible=False, privacy='private')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--census-acquisition', type=Path, required=True)
    parser.add_argument('--census-recipe', type=Path)
    parser.add_argument('--template', type=Path, required=True)
    parser.add_argument('--template-sha256', required=True)
    parser.add_argument('--expected-target', type=Path, required=True,
                        help='Explicit expected process identity JSON; rejects a different process epoch.')
    parser.add_argument('--maximum-total-fields', type=int, default=8192)
    parser.add_argument('--maximum-total-guards', type=int, default=16384)
    parser.add_argument('--partition-size', type=int, required=True)
    parser.add_argument('--anchor-controller-key')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        census = verified_census(args.census_acquisition, args.census_recipe,
                                 expected_target=parse(read(args.expected_target, 4096)))
        result = plan(census, read(args.template, 1048576), template_sha256=args.template_sha256,
                      partition_size=args.partition_size, anchor_controller_key=args.anchor_controller_key,
                      maximum_total_fields=args.maximum_total_fields, maximum_total_guards=args.maximum_total_guards)
        # Finish validation before creating any output. Never overwrite artifacts.
        args.output.mkdir(parents=False, exist_ok=False)
        for part in result['partitions']:
            (args.output/part['recipe_file']).write_bytes(part.pop('recipe_bytes'))
        (args.output/'plan.json').write_bytes(encoded(result))
        print(json.dumps(dict(controllers=result['controller_count'], partitions=len(result['partitions']),
                              plan_sha256=digest((args.output/'plan.json').read_bytes()))))
        return 0
    except (InvalidPlan, OSError, KeyError, TypeError) as error:
        parser.exit(2, f'roster plan rejected: {error}\n')


if __name__ == '__main__':
    main()
