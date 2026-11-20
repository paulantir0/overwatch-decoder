"""Fresh native census -> exact-controller plan -> finite raw Windows runtime.

All application knowledge is supplied in a pinned private input bundle. No names,
roles, self anchor, memory layout, process discovery or game controls are inferred.
The outer owner holds a kill-on-close job for its worker and all descendants.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parents[1])]

from build_health_contracts import _layout
from plan_live_roster import encoded, parse, plan, read, verified_census
from runtime_roster import verify_runtime_inventory, raw_roster_inputs, bundled_producer_config

SCHEMA = 'overwatch-decoder.raw-roster-bootstrap-config/1'
RESULT_SCHEMA = 'overwatch-decoder.raw-roster-bootstrap-result/1'
INPUTS = ('census_recipe', 'roster_template', 'health_layout_seed')
ACQUISITION_FILES = ('manifest.json', 'profile.json', 'recipe.json', 'evidence.jsonl')
BUILDER_SCHEMA = 'overwatch-decoder.raw-roster-bundle-builder-result/1'


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(path):
    with Path(path).open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def save(path, value):
    Path(path).write_bytes(encoded(value))


def pinned_asset(bundle, inventory, name):
    need(isinstance(name, str) and name in inventory, 'asset_not_in_inventory')
    need(name and not Path(name).is_absolute() and '\\' not in name and ':' not in name
         and all(part not in ('', '.', '..') for part in name.split('/')), 'asset_name_not_relative')
    path = (bundle / name).resolve()
    need(path.is_relative_to(bundle) and path.is_file(), 'asset_path_escape')
    pin = inventory[name]
    need(path.stat().st_size == pin['bytes'] and digest(path) == pin['sha256'],
         'asset_pin_mismatch')
    return path


def configuration(bundle, inventory_sha256, config_name):
    """Validate the whole input bundle and explicit private layout before launch."""
    bundle = Path(bundle).resolve()
    verify_runtime_inventory(bundle, inventory_sha256)
    inventory = parse(read(bundle / 'inventory.json', 4*1024*1024))
    entry = pinned_asset(bundle, inventory, 'tools/entity-decoder/bootstrap_raw_roster.py')
    need(digest(__file__) == digest(entry), 'bootstrap_entrypoint_mismatch')
    config = parse(read(pinned_asset(bundle, inventory, config_name), 64*1024))
    need(isinstance(config, dict) and config.get('schema') == SCHEMA,
         'bootstrap_config_schema')
    need(config.get('private_controlled_fixture_reviewed') is True
         and config.get('public_state_eligible') is False, 'private_fixture_required')
    need(type(config.get('partial_sources',False)) is bool,'partial_sources_boolean')
    need(type(config.get('allow_controller_subsets',False)) is bool,'controller_subset_boolean')
    need(not config.get('allow_controller_subsets',False) or config.get('partial_sources',False),
         'controller_subsets_require_partial_sources')
    if config.get('partial_sources',False):
        module=pinned_asset(bundle,inventory,'tools/entity-decoder/runtime_partial.py')
        need(digest(module)==digest(HERE/'runtime_partial.py'),'partial_module_pin')
    if config.get('allow_controller_subsets',False):
        module=pinned_asset(bundle,inventory,'tools/entity-decoder/controller_subset_projection.py')
        need(digest(module)==digest(HERE/'controller_subset_projection.py'),'controller_subset_module_pin')
    extension = config.get('bundle_builder')
    need(not config.get('allow_controller_subsets',False) or extension is not None,
         'controller_subsets_require_context_builder')
    for key in (('census_recipe',) if extension is not None else INPUTS):
        pinned_asset(bundle, inventory, config.get(key))
    native = Path(config.get('native_exe', ''))
    need(native.is_absolute() and native.is_file() and native.stat().st_size <= 512*1024*1024
         and digest(native) == config.get('native_sha256'), 'native_executable_pin')
    need(isinstance(config.get('native_revision'), str) and 1 <= len(config['native_revision']) <= 128,
         'native_revision_required')
    maximum = config.get('maximum_partitions')
    need(type(maximum) is int and 1 <= maximum <= 16, 'partition_bounds')
    if extension is not None:
        builder_configuration(bundle, inventory, extension)
        recipe = parse(read(bundle / config['census_recipe'], 1024*1024))
        need(recipe.get('schema') == 'overwatch-decoder.acquisition-recipe/1', 'census_recipe_schema')
        return config, inventory
    size = config.get('partition_size')
    need(type(size) is int and 1 <= size <= 64, 'partition_bounds')
    seed, _, _ = _layout(read(bundle / config['health_layout_seed'], 64*1024))
    need(len(seed['actor_prefixes']) == size, 'layout_prefixes_must_cover_partition')
    template = parse(read(bundle / config['roster_template'], 1024*1024))
    recipe = parse(read(bundle / config['census_recipe'], 1024*1024))
    need(recipe.get('schema') == 'overwatch-decoder.acquisition-recipe/1'
         and template.get('schema') == 'overwatch-decoder.roster-recipe-template/1'
         and recipe.get('target') == template.get('recipe', {}).get('target')
         and recipe['target'].get('executable_sha256') == seed['executable_sha256'],
         'input_build_mismatch')
    return config, inventory


def builder_configuration(bundle, inventory, extension):
    """Only an explicitly inventoried Python entrypoint and inputs can run."""
    need(isinstance(extension, dict) and set(extension) == {'entrypoint', 'inputs', 'timeout_seconds'},
         'bundle_builder_config')
    entry = pinned_asset(bundle, inventory, extension['entrypoint'])
    inputs = pinned_asset(bundle, inventory, extension['inputs'])
    need(entry.suffix == '.py' and entry.stat().st_size <= 4*1024*1024
         and inputs.stat().st_size <= 1024*1024, 'bundle_builder_input_size')
    seconds = extension['timeout_seconds']
    need(type(seconds) is int and 1 <= seconds <= 45, 'bundle_builder_timeout')
    return entry, inputs


def build_extension_bundle(source, inventory, config, census_directory, destination):
    """Run the pinned private builder, then independently admit its fresh bundle.

    In the Windows worker this child inherits the already-enrolled outer job.
    Its output is not trusted until inventory, census and producer checks pass.
    """
    source, census_directory, destination = (Path(p).resolve() for p in
                                             (source, census_directory, destination))
    extension = config['bundle_builder']
    entry, inputs = builder_configuration(source, inventory, extension)
    for name in inventory:
        pinned_asset(source, inventory, name)
    need(parse(read(source / 'inventory.json', 4*1024*1024)) == inventory, 'builder_input_inventory_mismatch')
    input_pin = digest(source / 'inventory.json')
    census = verified_census(census_directory)
    manifest = parse(read(census_directory / 'manifest.json', 262144))
    need(manifest['revision'] == config['native_revision']
         and census['source']['recipe_sha256'] == inventory[config['census_recipe']]['sha256'],
         'census_native_or_recipe_pin')
    need(not destination.exists() and not destination.is_relative_to(source), 'new_runtime_bundle_required')
    receipt_path = destination.parent / 'bundle-builder-result.json'
    log_path = destination.parent / 'bundle-builder.log'
    need(not receipt_path.exists() and not log_path.exists(), 'new_builder_receipts_required')
    command = [sys.executable, '-I', '-B', str(entry), '--input-bundle', str(source),
               '--input-inventory-sha256', input_pin, '--inputs', str(inputs),
               '--census-acquisition', str(census_directory), '--output', str(destination),
               '--receipt', str(receipt_path)]
    # The result travels only through the bounded receipt, not an unbounded
    # stdout pipe/file. The outer enrolled worker owns this child and descendants.
    with log_path.open('xb') as log:
        command_receipt = dict(schema='overwatch-decoder.raw-roster-builder-command/1',
                               entrypoint_sha256=digest(entry), inputs_sha256=digest(inputs),
                               timeout_seconds=extension['timeout_seconds'])
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.STDOUT, timeout=extension['timeout_seconds'], check=False)
        except subprocess.TimeoutExpired:
            log.write(encoded(dict(command_receipt, timed_out=True)))
            raise
        log.write(encoded(dict(command_receipt, timed_out=False, exit_code=result.returncode)))
    need(log_path.stat().st_size <= 4*1024*1024, 'bundle_builder_log_bound')
    if result.returncode != 0:
        failure = parse(read(receipt_path, 64*1024)) if receipt_path.is_file() and not receipt_path.is_symlink() else {}
        need(False, 'bundle_builder_failed: ' + str(failure.get('error', result.returncode)))
    need(receipt_path.is_file() and not receipt_path.is_symlink(), 'bundle_builder_receipt_required')
    receipt = parse(read(receipt_path, 64*1024))
    need(isinstance(receipt, dict) and receipt.get('schema') == BUILDER_SCHEMA
         and receipt.get('complete') is True and receipt.get('input_inventory_sha256') == input_pin
         and receipt.get('target') == census['target'] and receipt.get('census_source') == census['source'],
         'bundle_builder_receipt_scope')
    need(all(isinstance(receipt.get(k), str) and re.fullmatch('[0-9a-f]{64}', receipt[k])
             for k in ('inventory_sha256', 'plan_sha256')), 'bundle_builder_result_digests')
    verify_runtime_inventory(destination, receipt.get('inventory_sha256'))
    output_inventory = parse(read(destination / 'inventory.json', 4*1024*1024))
    actual_files = set()
    total = 0
    for path in destination.rglob('*'):
        need(not path.is_symlink(), 'builder_output_symlink')
        if not path.is_file():
            continue
        actual_files.add(path.relative_to(destination).as_posix())
        total += path.stat().st_size
        need(len(actual_files) <= 4097 and total <= 512*1024*1024 + 4*1024*1024,
             'builder_output_bound')
    need(actual_files == set(output_inventory) | {'inventory.json'}, 'builder_uninventoried_output')
    input_pins = {(pin['bytes'], pin['sha256']) for pin in inventory.values()}
    for name in output_inventory:
        pinned_asset(destination, output_inventory, name)
        if Path(name).suffix.lower() in ('.py', '.pyc', '.pyd', '.dll', '.exe', '.so'):
            pin = output_inventory[name]
            need((pin['bytes'], pin['sha256']) in input_pins, 'builder_generated_code_not_pinned')
        need(Path(name).name not in ('profile.json', 'evidence.jsonl', 'manifest.json')
             or name in {'census/' + n for n in ACQUISITION_FILES}, 'builder_saved_epoch_forbidden')
    # The extension may generate reviewed inputs, but cannot silently replace
    # any pinned input source/dependency while minting a new inventory.
    for name, original in inventory.items():
        pinned_asset(source, inventory, name)
        need(output_inventory.get(name) == original, 'builder_changed_pinned_input')
    fresh_copy = verified_census(destination / 'census', expected_target=census['target'])
    need(fresh_copy == census, 'builder_census_copy_mismatch')
    plan_path = destination / 'roster-plan.json'
    plan_value = parse(read(pinned_asset(destination, output_inventory, 'roster-plan.json'), 1024*1024))
    raw_roster_inputs(plan_value, census)
    need(plan_value.get('anchor_controller_key') is None
         and len(plan_value['partitions']) <= config['maximum_partitions'], 'builder_partition_scope')
    for part in plan_value['partitions']:
        ordinal = part['ordinal']
        producer = bundled_producer_config(destination, ordinal)
        need(producer.get('allow_controller_subsets',False) is config.get('allow_controller_subsets',False),
             'builder_controller_subset_policy_mismatch')
        need(producer.get('schema') == 'overwatch-decoder.private.windows-local-pilot-config/1'
             and producer.get('observation_mode') == 'raw-candidates'
             and producer.get('target') == census['target']
             and producer.get('private_controlled_fixture_reviewed') is True
             and producer.get('public_state_eligible') is False
             and Path(producer['native_exe']).resolve() == Path(config['native_exe']).resolve()
             and all(producer.get(k) == config[k] for k in ('native_sha256', 'native_revision')),
             'builder_producer_scope')
        recipe = pinned_asset(destination, output_inventory, part['recipe_file'])
        need(digest(recipe) == part['recipe_sha256'] == producer.get('recipe_sha256')
             and Path(producer['recipe']).resolve() == recipe, 'builder_producer_recipe')
        need(not any(k in producer for k in ('profile', 'profile_path', 'saved_profile',
                 'acquisition', 'acquisition_directory', 'recording', 'recording_manifest_sha256')),
             'builder_saved_profile_config')
        need(producer.get('include_health_candidates', True) is True,
             'builder_roster_health_required')
        layout_path = Path(producer['health_layout'])
        need(digest(layout_path) == producer.get('health_layout_sha256'), 'builder_health_layout_pin')
        layout, _, _ = _layout(read(layout_path, 64*1024))
        need(layout['executable_sha256'] == census['target']['executable_sha256']
             and layout['recipe_sha256'] == part['recipe_sha256'], 'builder_health_layout_scope')
        for role in ('context', 'ammunition'):
            if role + '_composer' not in producer:
                continue
            composer = Path(producer[role + '_composer'])
            need((composer.stat().st_size, digest(composer)) in input_pins
                 and digest(composer) == producer.get(role + '_composer_sha256'),
                 'builder_' + role + '_code_not_pinned')
            need(digest(producer[role + '_inputs']) == producer.get(role + '_inputs_sha256'),
                 'builder_' + role + '_inputs_pin')
    need(receipt.get('plan_sha256') == digest(plan_path)
         and receipt.get('controllers') == len(census['controllers'])
         and receipt.get('partitions') == len(plan_value['partitions']), 'bundle_builder_result_mismatch')
    return dict(target=census['target'], controllers=len(census['controllers']),
                partitions=len(plan_value['partitions']), census_source=census['source'],
                plan_sha256=digest(plan_path), inventory_sha256=digest(destination / 'inventory.json'),
                bundle_builder_sha256=digest(entry), bundle_builder_inputs_sha256=digest(inputs),
                bundle_builder_receipt_sha256=digest(receipt_path))


def build_bundle(source, inventory, config, census_directory, destination):
    """Deterministic packaging only; each generated partition still acquires afresh.

    The caller declares ordered actor prefixes matching its template's retained
    rows. Only that prefix list and the generated recipe pin vary per partition;
    no layout extent, slot, offset or field semantics are inferred here.
    """
    if 'bundle_builder' in config:
        return build_extension_bundle(source, inventory, config, census_directory, destination)
    source, census_directory, destination = map(Path, (source, census_directory, destination))
    source = source.resolve()
    census = verified_census(census_directory)
    template_path = pinned_asset(source, inventory, config['roster_template'])
    result = plan(census, read(template_path, 1024*1024),
                  template_sha256=inventory[config['roster_template']]['sha256'],
                  partition_size=config['partition_size'])
    need(len(result['partitions']) <= config['maximum_partitions'], 'too_many_partitions')
    seed_raw = read(pinned_asset(source, inventory, config['health_layout_seed']), 64*1024)
    seed, _, _ = _layout(seed_raw)
    need(seed['executable_sha256'] == census['target']['executable_sha256'], 'census_layout_build_mismatch')
    manifest = parse(read(census_directory / 'manifest.json', 262144))
    need(manifest['revision'] == config['native_revision']
         and census['source']['recipe_sha256'] == inventory[config['census_recipe']]['sha256'],
         'census_native_or_recipe_pin')
    generated = {'roster-plan.json'} | {'census/' + n for n in ACQUISITION_FILES}
    for part in result['partitions']:
        n = part['ordinal']
        generated.update({f'p{n}.json', f'p{n}-recipe.json', f'p{n}-health-layout.json'})
    need(not generated.intersection(inventory), 'generated_name_collision')
    need(not destination.exists(), 'new_runtime_bundle_required')
    destination.mkdir(parents=False)
    for name in inventory:
        original = pinned_asset(source, inventory, name)
        copy = destination / name
        copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, copy)
    (destination / 'census').mkdir()
    census_pins = {name: census['source'][key] for name, key in (
        ('manifest.json', 'manifest_sha256'), ('profile.json', 'profile_sha256'),
        ('recipe.json', 'recipe_sha256'), ('evidence.jsonl', 'evidence_sha256'))}
    for name in ACQUISITION_FILES:
        shutil.copyfile(census_directory / name, destination / 'census' / name)
    for part in result['partitions']:
        n = part['ordinal']
        recipe_name, layout_name = f'p{n}-recipe.json', f'p{n}-health-layout.json'
        recipe_raw = part.pop('recipe_bytes')
        (destination / recipe_name).write_bytes(recipe_raw)
        part['recipe_file'] = recipe_name
        layout = dict(seed, recipe_sha256=part['recipe_sha256'],
                      actor_prefixes=seed['actor_prefixes'][:len(part['controllers'])])
        layout_raw = encoded(layout)
        _layout(layout_raw)
        (destination / layout_name).write_bytes(layout_raw)
        producer = dict(schema='overwatch-decoder.private.windows-local-pilot-config/1',
                        observation_mode='raw-candidates', private_controlled_fixture_reviewed=True,
                        public_state_eligible=False, target=census['target'],
                        native_exe=config['native_exe'], native_sha256=config['native_sha256'],
                        native_revision=config['native_revision'], recipe=recipe_name,
                        recipe_sha256=part['recipe_sha256'], health_layout=layout_name,
                        health_layout_sha256=hashlib.sha256(layout_raw).hexdigest(),
                        include_cached_labels=False)
        save(destination / f'p{n}.json', producer)
    save(destination / 'roster-plan.json', result)
    files = {}
    for path in sorted(destination.rglob('*')):
        if path.is_file():
            name = path.relative_to(destination).as_posix()
            pin = dict(bytes=path.stat().st_size, sha256=digest(path))
            # Packaging must not turn a changed source into a new trusted pin.
            # Keep the original input/census hashes through the copy boundary.
            if name in inventory:
                need(pin == inventory[name], 'copied_input_pin_mismatch')
            elif name.startswith('census/'):
                need(pin['sha256'] == census_pins[name.removeprefix('census/')],
                     'copied_census_pin_mismatch')
            files[name] = pin
    save(destination / 'inventory.json', files)
    return dict(target=census['target'], controllers=result['controller_count'],
                partitions=len(result['partitions']), census_source=census['source'],
                plan_sha256=digest(destination / 'roster-plan.json'),
                inventory_sha256=digest(destination / 'inventory.json'),
                layout_seed_sha256=hashlib.sha256(seed_raw).hexdigest())


def run_worker(args):
    source, out = args.bundle.resolve(), args.output.resolve()
    config, inventory = configuration(source, args.inventory_sha256, args.config)
    status = dict(schema=RESULT_SCHEMA, complete=False, stage='acquisition',
                  private=True, public_state_eligible=False, visibility='unknown',
                  input_inventory_sha256=args.inventory_sha256, pid=args.pid)
    if args.target_creation_file_time is not None:
        status['target_creation_file_time'] = args.target_creation_file_time
    save(out / 'bootstrap-worker-status.json', status)
    census = out / 'census'
    with (out / 'census-command.log').open('xb') as log:
        result = subprocess.run([config['native_exe'], 'acquire-fields', '--pid', str(args.pid),
                                 '--recipe', str(source / config['census_recipe']), '--out', str(census)],
                                stdout=log, stderr=subprocess.STDOUT, timeout=45, check=False)
    need(result.returncode == 0, 'fresh_census_failed')
    verified = verified_census(census)
    need(verified['target']['pid'] == args.pid, 'census_pid_mismatch')
    need(args.target_creation_file_time is None
         or verified['target']['creation_file_time'] == args.target_creation_file_time,
         'census_target_creation_mismatch')
    runtime = out / 'runtime-bundle'
    receipt = build_bundle(source, inventory, config, census, runtime)
    status.update(stage='recording', bootstrap=receipt)
    save(out / 'bootstrap-worker-status.json', status)
    command = [sys.executable, '-I', str(runtime / 'tools/entity-decoder/runtime_roster.py'),
               '--bundle', str(runtime), '--inventory-sha256', receipt['inventory_sha256'],
               '--mode', 'raw-candidates', '--census-acquisition', str(runtime / 'census'),
               '--plan', str(runtime / 'roster-plan.json'), '--output', str(out / 'recording'),
               '--seconds', str(args.seconds), '--interval-ms', str(args.interval_ms),
               '--ready-timeout', str(args.ready_timeout), '--cleanup-seconds', str(args.cleanup_seconds)]
    if config.get('partial_sources',False):command.append('--partial-sources')
    if config.get('allow_controller_subsets',False):command.append('--allow-controller-subsets')
    with (out / 'runtime-command.log').open('xb') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=180, check=False)
    runtime_status = parse(read(out / 'recording/status.json', 1024*1024))
    need(result.returncode == 0 and runtime_status.get('complete') is True
         and runtime_status.get('error') is None, 'raw_runtime_failed: '+str(runtime_status.get('error')))
    status.update(stage='finished', complete=True, runtime_status_sha256=digest(out / 'recording/status.json'))
    save(out / 'bootstrap-worker-status.json', status)
    return 0


def worker(args):
    # Enrollment precedes native or runtime process creation. Only the outer
    # owner retains the job handle; the game is never placed in this job.
    from runtime_jobs import enroll_current_producer
    enroll_current_producer(args.job_handle)
    try:
        return run_worker(args)
    except Exception as error:
        path = args.output.resolve() / 'bootstrap-worker-status.json'
        status = parse(read(path, 1024*1024)) if path.exists() else dict(schema=RESULT_SCHEMA)
        status.update(complete=False, error=str(error), failed_stage=status.get('stage'), stage='failed')
        save(path, status)
        raise


def launch(args):
    from runtime_jobs import spawn_producer
    need(sys.platform == 'win32', 'windows_required')
    source, out = args.bundle.resolve(), args.output.resolve()
    need(HERE == source / 'tools/entity-decoder', 'execute_bundled_bootstrap_required')
    need(not out.exists() and not out.is_relative_to(source), 'new_output_outside_bundle_required')
    config, _ = configuration(source, args.inventory_sha256, args.config)
    out.mkdir(parents=True, exist_ok=False)
    status = dict(schema=RESULT_SCHEMA, complete=False, error=None, owned_job_closed=False,
                  input_inventory_sha256=args.inventory_sha256, private=True, public_state_eligible=False)
    if args.target_creation_file_time is not None:
        status['target_creation_file_time'] = args.target_creation_file_time
    save(out / 'bootstrap-status.json', status)
    process = None
    start = time.monotonic()
    command = [sys.executable, '-I', str(HERE / 'bootstrap_raw_roster.py'), '--worker',
               '--bundle', str(source), '--inventory-sha256', args.inventory_sha256,
               '--config', args.config, '--output', str(out), '--pid', str(args.pid),
               '--seconds', str(args.seconds), '--interval-ms', str(args.interval_ms),
               '--ready-timeout', str(args.ready_timeout), '--cleanup-seconds', str(args.cleanup_seconds)]
    if args.target_creation_file_time is not None:
        command.extend(['--target-creation-file-time', str(args.target_creation_file_time)])
    try:
        with (out / 'bootstrap-worker.log').open('xb') as log:
            process = spawn_producer(command, cwd=source, stdout=log, stderr=subprocess.STDOUT)
            status['worker_pid'] = process.pid
            save(out / 'bootstrap-status.json', status)
            exit_code = process.wait(timeout=240 + config.get('bundle_builder', {}).get('timeout_seconds', 0))
        child = parse(read(out / 'bootstrap-worker-status.json', 1024*1024))
        need(exit_code == 0, 'bootstrap_worker_failed: '+str(child.get('error')))
        need(child.get('complete') is True and child.get('stage') == 'finished', 'bootstrap_worker_incomplete')
        status.update(complete=True, worker_status_sha256=digest(out / 'bootstrap-worker-status.json'))
    except Exception as error:
        status.update(complete=False, error=str(error))
    finally:
        if process is not None:
            try:
                process._overwatch_decoder_owned_job.terminate_and_close(time.monotonic()+10)
                process.wait(timeout=5)
                status['owned_job_closed'] = True
            except (OSError, subprocess.TimeoutExpired) as error:
                status.update(complete=False, error='bootstrap_cleanup_failed: '+str(error))
        status['elapsed_s'] = time.monotonic() - start
        save(out / 'bootstrap-status.json', status)
    print(json.dumps(status), flush=True)
    return 0 if status['complete'] else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('bundle', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--inventory-sha256', required=True)
    parser.add_argument('--config', default='bootstrap-config.json')
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--target-creation-file-time', type=int,
                        help='Require this original process lifetime in the verified census before building or recording.')
    parser.add_argument('--seconds', type=int, default=60)
    parser.add_argument('--interval-ms', type=int, default=50)
    parser.add_argument('--ready-timeout', type=int, default=20)
    parser.add_argument('--cleanup-seconds', type=int, default=15)
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--job-handle', type=int, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    need(args.target_creation_file_time is None or 0 < args.target_creation_file_time < 2**63,
         'invalid_target_creation_file_time')
    need(0 < args.pid < 2**32 and 15 <= args.seconds <= 180
         and 20 <= args.interval_ms <= 1000 and 5 <= args.ready_timeout <= 60
         and 5 <= args.cleanup_seconds <= 60
         and args.seconds+args.ready_timeout+args.cleanup_seconds+5 <= 165, 'finite_bootstrap_bounds')
    need(args.worker == (args.job_handle is not None), 'worker_requires_owned_job')
    return worker(args) if args.worker else launch(args)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        print(json.dumps(dict(complete=False, error=str(error))), file=sys.stderr)
        raise SystemExit(2)
