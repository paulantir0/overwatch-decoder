import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import bootstrap_raw_roster as bootstrap
from plan_live_roster import encoded
from test_plan_live_roster import TARGET, fixture


class BootstrapPackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.census = self.root / 'census'
        self.census.mkdir()
        self.template = fixture(self.census, count=5)
        self.source = self.root / 'source'
        self.source.mkdir()
        (self.source / 'template.json').write_bytes(self.template)
        (self.source / 'census-recipe.json').write_bytes((self.census / 'recipe.json').read_bytes())
        self.layout = dict(schema='overwatch-decoder.health-layout/1', executable_sha256=TARGET['executable_sha256'],
                           recipe_sha256='b'*64, extent_size=32, read_stage='synthetic', slot_count=2,
                           slot_stride=8, membership_offset=0, scalar_offset=4,
                           actor_prefixes=['one_', 'two_', 'three_'], scalar_field_suffix='_pool')
        (self.source / 'layout.json').write_bytes(encoded(self.layout))
        self.inventory = {p.name: dict(bytes=p.stat().st_size, sha256=bootstrap.digest(p))
                          for p in self.source.iterdir()}
        self.config = dict(native_revision='fixture', native_exe=str(self.root / 'fixture.exe'),
                           native_sha256='c'*64, roster_template='template.json', census_recipe='census-recipe.json',
                           health_layout_seed='layout.json', partition_size=3, maximum_partitions=2)

    def build(self, name='bundle'):
        return bootstrap.build_bundle(self.source, self.inventory, self.config, self.census, self.root/name)

    def test_five_controllers_need_no_saved_plan_or_role_map(self):
        result = self.build()
        self.assertEqual((result['controllers'], result['partitions']), (5, 2))
        self.assertEqual(result['target'], TARGET)
        root = self.root / 'bundle'
        plan = json.loads((root / 'roster-plan.json').read_bytes())
        self.assertIsNone(plan['anchor_controller_key'])
        self.assertEqual(len(plan['primary_controller_map']), 5)
        self.assertFalse((root / 'current-role-map.json').exists())
        for ordinal, count in [(1, 3), (2, 2)]:
            config = json.loads((root / f'p{ordinal}.json').read_bytes())
            self.assertEqual(config['observation_mode'], 'raw-candidates')
            self.assertNotIn('composer', config)
            layout = json.loads((root / config['health_layout']).read_bytes())
            self.assertEqual(layout['actor_prefixes'], self.layout['actor_prefixes'][:count])
            self.assertEqual(layout['recipe_sha256'], bootstrap.digest(root / config['recipe']))
            unchanged = copy.deepcopy(layout)
            unchanged['recipe_sha256'] = self.layout['recipe_sha256']
            unchanged['actor_prefixes'] = self.layout['actor_prefixes']
            self.assertEqual(unchanged, self.layout)
        inventory = json.loads((root / 'inventory.json').read_bytes())
        for name, pin in inventory.items():
            self.assertEqual(bootstrap.digest(root / name), pin['sha256'])
            self.assertEqual((root / name).stat().st_size, pin['bytes'])
        self.assertEqual(result['inventory_sha256'], bootstrap.digest(root / 'inventory.json'))

    def test_deterministic_output_and_no_overwrite(self):
        self.assertEqual(self.build(), self.build('second'))
        with self.assertRaisesRegex(ValueError, 'new_runtime_bundle_required'):
            self.build()

    def test_recipe_mutation_is_rejected(self):
        (self.source / 'template.json').write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError, 'asset_pin_mismatch'):
            self.build()
        self.assertFalse((self.root / 'bundle').exists())

    def test_native_revision_and_census_recipe_must_match(self):
        self.config['native_revision'] = 'wrong'
        with self.assertRaisesRegex(ValueError, 'census_native_or_recipe_pin'):
            self.build()
        self.config['native_revision'] = 'fixture'
        self.inventory['census-recipe.json']['sha256'] = 'f'*64
        with self.assertRaisesRegex(ValueError, 'census_native_or_recipe_pin'):
            self.build()

    def test_partition_limit_is_checked_before_output(self):
        self.config['maximum_partitions'] = 1
        with self.assertRaisesRegex(ValueError, 'too_many_partitions'):
            self.build()
        self.assertFalse((self.root / 'bundle').exists())

    def test_generated_path_collision_is_rejected_before_output(self):
        self.inventory['p1.json'] = dict(bytes=2, sha256=hashlib.sha256(b'{}').hexdigest())
        with self.assertRaisesRegex(ValueError, 'generated_name_collision'):
            self.build()
        self.assertFalse((self.root / 'bundle').exists())

    def test_copy_gap_cannot_repin_changed_source(self):
        original = shutil.copyfile
        def mutate(source, destination):
            result = original(source, destination)
            if Path(source) == self.source / 'template.json':
                Path(destination).write_bytes(b'{}')
            return result
        with patch.object(bootstrap.shutil, 'copyfile', side_effect=mutate):
            with self.assertRaisesRegex(ValueError, 'copied_input_pin_mismatch'):
                self.build()
        self.assertFalse((self.root / 'bundle/inventory.json').exists())

    def test_census_copy_keeps_original_verified_hash(self):
        original = shutil.copyfile
        def mutate(source, destination):
            result = original(source, destination)
            if Path(source) == self.census / 'evidence.jsonl':
                Path(destination).write_bytes(b'{}\n')
            return result
        with patch.object(bootstrap.shutil, 'copyfile', side_effect=mutate):
            with self.assertRaisesRegex(ValueError, 'copied_census_pin_mismatch'):
                self.build()
        self.assertFalse((self.root / 'bundle/inventory.json').exists())

    def test_asset_path_alias_and_absolute_names_rejected(self):
        for name in ['x/../template.json', '/tmp/template.json', 'x\\template.json', 'C:template.json']:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'asset_name_not_relative'):
                bootstrap.pinned_asset(self.source, {name: {}}, name)

    def test_worker_cannot_start_without_inherited_job(self):
        args = ['--bundle', str(self.source), '--output', str(self.root/'out'),
                '--inventory-sha256', 'a'*64, '--pid', '42']
        with patch.object(bootstrap, 'worker') as worker:
            with self.assertRaisesRegex(ValueError, 'worker_requires_owned_job'):
                bootstrap.main([*args, '--worker'])
            worker.assert_not_called()

    def test_enrolled_worker_preserves_failure_stage_and_reason(self):
        out = self.root / 'output'
        out.mkdir()
        bootstrap.save(out/'bootstrap-worker-status.json', dict(schema=bootstrap.RESULT_SCHEMA,
                        complete=False, stage='recording', bootstrap={'controllers': 5}))
        args = SimpleNamespace(output=out, job_handle=12)
        with patch('runtime_jobs.enroll_current_producer') as enroll, \
             patch.object(bootstrap, 'run_worker', side_effect=ValueError('fixture_capture_failed')):
            with self.assertRaisesRegex(ValueError, 'fixture_capture_failed'):
                bootstrap.worker(args)
        enroll.assert_called_once_with(12)
        status = json.loads((out/'bootstrap-worker-status.json').read_bytes())
        self.assertFalse(status['complete'])
        self.assertEqual(status['failed_stage'], 'recording')
        self.assertEqual(status['error'], 'fixture_capture_failed')
        self.assertEqual(status['bootstrap'], {'controllers': 5})

    def test_duration_cannot_exceed_runtime_budget(self):
        with self.assertRaisesRegex(ValueError, 'finite_bootstrap_bounds'):
            bootstrap.main(['--bundle', str(self.source), '--output', str(self.root/'out'),
                            '--inventory-sha256', 'a'*64, '--pid', '42', '--seconds', '180'])

    def test_partial_flag_reaches_runtime_only_when_enabled(self):
        for enabled, subsets in ((False,False),(True,False),(True,True)):
            with self.subTest(enabled=enabled,subsets=subsets):
                out=self.root/('partial-'+str(enabled)+'-'+str(subsets));out.mkdir()
                config=dict(self.config,partial_sources=enabled,allow_controller_subsets=subsets)
                args=SimpleNamespace(bundle=self.source,output=out,inventory_sha256='a'*64,config='bootstrap-config.json',
                    pid=TARGET['pid'],target_creation_file_time=None,seconds=30,interval_ms=200,ready_timeout=20,cleanup_seconds=15)
                commands=[]
                def run(command,**kwargs):
                    commands.append(command)
                    if 'acquire-fields' in command:shutil.copytree(self.census,Path(command[command.index('--out')+1]))
                    else:
                        dest=out/'recording';dest.mkdir();bootstrap.save(dest/'status.json',dict(complete=True,error=None))
                    return SimpleNamespace(returncode=0)
                with patch.object(bootstrap,'configuration',return_value=(config,self.inventory)), \
                     patch.object(bootstrap,'build_bundle',return_value={'inventory_sha256':'ab'*32}), \
                     patch.object(bootstrap.subprocess,'run',side_effect=run):
                    self.assertEqual(bootstrap.run_worker(args),0)
                self.assertEqual('--partial-sources' in commands[-1],enabled)
                self.assertEqual('--allow-controller-subsets' in commands[-1],subsets)
                self.assertEqual(commands[-1][commands[-1].index('--interval-ms')+1],'200')

    def test_original_lifetime_is_checked_before_builder_or_runtime(self):
        for expected in (None, TARGET['creation_file_time'], TARGET['creation_file_time']+1):
            with self.subTest(expected=expected):
                out=self.root/('lifetime-'+str(expected));out.mkdir()
                args=SimpleNamespace(bundle=self.source,output=out,inventory_sha256='a'*64,
                    config='bootstrap-config.json',pid=TARGET['pid'],target_creation_file_time=expected)
                def native(command,**kwargs):
                    self.assertEqual(command[1],'acquire-fields')
                    destination=Path(command[command.index('--out')+1])
                    shutil.copytree(self.census,destination)
                    return SimpleNamespace(returncode=0)
                with patch.object(bootstrap,'configuration',return_value=(self.config,self.inventory)), \
                     patch.object(bootstrap.subprocess,'run',side_effect=native)as run, \
                     patch.object(bootstrap,'build_bundle',side_effect=RuntimeError('builder_reached'))as build:
                    if expected is not None and expected!=TARGET['creation_file_time']:
                        with self.assertRaisesRegex(ValueError,'census_target_creation_mismatch'):bootstrap.run_worker(args)
                        build.assert_not_called()
                    else:
                        with self.assertRaisesRegex(RuntimeError,'builder_reached'):bootstrap.run_worker(args)
                        build.assert_called_once()
                    self.assertEqual(run.call_count,1)
                status=json.loads((out/'bootstrap-worker-status.json').read_bytes())
                self.assertEqual(status.get('target_creation_file_time'),expected)
                self.assertFalse((out/'runtime-bundle').exists())

    def test_cli_rejects_invalid_creation_time_and_preserves_valid_pin(self):
        args=['--bundle',str(self.source),'--output',str(self.root/'out'),
              '--inventory-sha256','a'*64,'--pid','42']
        with patch.object(bootstrap,'launch',return_value=0)as launch:
            for value in ('0','-1',str(2**63)):
                with self.subTest(value=value),self.assertRaisesRegex(ValueError,'invalid_target_creation_file_time'):
                    bootstrap.main([*args,'--target-creation-file-time',value])
            launch.assert_not_called()
            self.assertEqual(bootstrap.main([*args,'--target-creation-file-time','100']),0)
            self.assertEqual(launch.call_args.args[0].target_creation_file_time,100)


# This private fixture builder executes only copied, inventoried production
# modules. It uses the legacy fixture template to exercise the generic extension
# boundary; application-specific composition is tested separately on saved data.
FIXTURE_BUILDER = r'''
import argparse,json,sys,time,hashlib
from pathlib import Path
p=argparse.ArgumentParser()
for n in ('input-bundle','input-inventory-sha256','inputs','census-acquisition','output','receipt'):p.add_argument('--'+n,required=True)
a=p.parse_args();root=Path(a.input_bundle);sys.path[:0]=[str(root/'tools/entity-decoder'),str(root)]
import bootstrap_raw_roster as b
inventory=b.parse(b.read(root/'inventory.json',4*1024*1024));assert b.digest(root/'inventory.json')==a.input_inventory_sha256
config=b.parse(b.read(a.inputs,1024*1024));mutation=config.pop('fixture_mutation',None)
if mutation=='timeout':time.sleep(10)
if mutation=='exit':raise SystemExit(4)
result=b.build_bundle(root,inventory,config,Path(a.census_acquisition),Path(a.output));dest=Path(a.output)
if mutation=='primary':
 plan=b.parse(b.read(dest/'roster-plan.json',1024*1024));plan['primary_controller_map'][0]['controller_object_key']='controller:'+'f'*64;b.save(dest/'roster-plan.json',plan)
if mutation=='profile':(dest/'old').mkdir();(dest/'old/profile.json').write_bytes(b'{}')
if mutation=='code':(dest/'unreviewed.py').write_bytes(b'raise SystemExit(0)')
if mutation=='no_health':
 config=b.parse((dest/'p1.json').read_bytes());config['include_health_candidates']=False
 config.pop('health_layout');config.pop('health_layout_sha256');b.save(dest/'p1.json',config)
if mutation in ('context_code','ammunition_code'):
 role=mutation.removesuffix('_code')
 code=dest/'renamed-composer';code.write_bytes(b'raise SystemExit(0)')
 inputs=dest/'generated-composer-inputs.json';inputs.write_bytes(b'{}')
 config=b.parse((dest/'p1.json').read_bytes())
 config.update({role+'_composer':code.name,role+'_composer_sha256':b.digest(code),role+'_inputs':inputs.name,role+'_inputs_sha256':b.digest(inputs)})
 b.save(dest/'p1.json',config)
if mutation=='input':(dest/'template.json').write_bytes(b'{}')
if mutation=='census':(dest/'census/evidence.jsonl').write_bytes(b'{}\n')
if mutation=='unlisted':(dest/'unlisted').write_bytes(b'unknown')
if mutation in ('primary','profile','input','census','code','context_code','ammunition_code','no_health'):
 files={p.relative_to(dest).as_posix():dict(bytes=p.stat().st_size,sha256=b.digest(p))for p in dest.rglob('*')if p.is_file()and p.name!='inventory.json'};b.save(dest/'inventory.json',files)
result.update(schema=b.BUILDER_SCHEMA,complete=True,input_inventory_sha256=a.input_inventory_sha256,inventory_sha256=b.digest(dest/'inventory.json'),plan_sha256=b.digest(dest/'roster-plan.json'))
if mutation=='receipt':result['census_source']['recipe_sha256']='0'*64
if mutation=='digest':result.pop('inventory_sha256')
b.save(Path(a.receipt),result)
'''


class BootstrapExtensionTests(unittest.TestCase):
    build = BootstrapPackagingTests.build

    def setUp(self):
        BootstrapPackagingTests.setUp(self)
        here=Path(bootstrap.__file__).resolve().parent
        for folder in ('tools/entity-decoder','overwatch_decoder'):
            original=here.parents[1]/folder
            for path in original.glob('*.py'):
                if path.name.startswith('test_'):continue
                target=self.source/folder/path.name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,target)
        (self.source/'private').mkdir();(self.source/'private/builder.py').write_text(FIXTURE_BUILDER)
        self.legacy=copy.deepcopy(self.config)
        (self.root/'fixture.exe').write_bytes(b'synthetic executable; never launched')
        self.legacy['native_sha256']=bootstrap.digest(self.root/'fixture.exe')
        self.config=dict(self.legacy,schema=bootstrap.SCHEMA,private_controlled_fixture_reviewed=True,public_state_eligible=False,
            bundle_builder=dict(entrypoint='private/builder.py',inputs='private/inputs.json',timeout_seconds=5))
        self.config.pop('roster_template');self.config.pop('health_layout_seed');self.config.pop('partition_size')
        self.save_inputs()

    def save_inputs(self,mutation=None):
        inputs=dict(self.legacy)
        if mutation:inputs['fixture_mutation']=mutation
        bootstrap.save(self.source/'private/inputs.json',inputs);bootstrap.save(self.source/'bootstrap-config.json',self.config)
        self.inventory={p.relative_to(self.source).as_posix():dict(bytes=p.stat().st_size,sha256=bootstrap.digest(p))
            for p in self.source.rglob('*')if p.is_file()and p.name!='inventory.json'}
        bootstrap.save(self.source/'inventory.json',self.inventory)

    def test_partial_sources_opt_in_is_pinned_boolean(self):
        for value in (True,False,1,'true',None):
            with self.subTest(value=value):
                self.config['partial_sources']=value;self.save_inputs()
                if type(value) is bool:
                    config,_=bootstrap.configuration(self.source,bootstrap.digest(self.source/'inventory.json'),'bootstrap-config.json')
                    self.assertIs(config['partial_sources'],value)
                else:
                    with self.assertRaisesRegex(ValueError,'partial_sources_boolean'):
                        bootstrap.configuration(self.source,bootstrap.digest(self.source/'inventory.json'),'bootstrap-config.json')

    def test_partial_module_must_be_in_pinned_inventory(self):
        self.config['partial_sources']=True;self.save_inputs()
        self.inventory.pop('tools/entity-decoder/runtime_partial.py')
        bootstrap.save(self.source/'inventory.json',self.inventory)
        with self.assertRaisesRegex(ValueError,'asset_not_in_inventory'):
            bootstrap.configuration(self.source,bootstrap.digest(self.source/'inventory.json'),'bootstrap-config.json')

    def test_controller_subsets_require_partial_mode_boolean_and_pinned_module(self):
        self.config['partial_sources']=True
        for value in (1,None,'true'):
            self.config['allow_controller_subsets']=value;self.save_inputs()
            with self.assertRaisesRegex(ValueError,'controller_subset_boolean'):
                bootstrap.configuration(self.source,bootstrap.digest(self.source/'inventory.json'),'bootstrap-config.json')
        self.config.update(allow_controller_subsets=True,partial_sources=False);self.save_inputs()
        with self.assertRaisesRegex(ValueError,'controller_subsets_require_partial_sources'):
            bootstrap.configuration(self.source,bootstrap.digest(self.source/'inventory.json'),'bootstrap-config.json')
        self.config['partial_sources']=True;self.save_inputs()
        bootstrap.configuration(self.source,bootstrap.digest(self.source/'inventory.json'),'bootstrap-config.json')
        self.inventory.pop('tools/entity-decoder/controller_subset_projection.py')
        bootstrap.save(self.source/'inventory.json',self.inventory)
        with self.assertRaisesRegex(ValueError,'asset_not_in_inventory'):
            bootstrap.configuration(self.source,bootstrap.digest(self.source/'inventory.json'),'bootstrap-config.json')

    def test_extension_runs_finite_child_and_admits_exact_fresh_bundle(self):
        config,inventory=bootstrap.configuration(self.source,bootstrap.digest(self.source/'inventory.json'),'bootstrap-config.json')
        self.assertEqual(config,self.config);self.assertEqual(inventory,self.inventory)
        result=self.build()
        self.assertEqual((result['controllers'],result['partitions']),(5,2))
        self.assertEqual(result['bundle_builder_sha256'],bootstrap.digest(self.source/'private/builder.py'))
        self.assertEqual(result['bundle_builder_receipt_sha256'],bootstrap.digest(self.root/'bundle-builder-result.json'))
        self.assertEqual(bootstrap.verified_census(self.root/'bundle/census'),bootstrap.verified_census(self.census))
        self.assertEqual(bootstrap.raw_roster_inputs(json.loads((self.root/'bundle/roster-plan.json').read_bytes()),bootstrap.verified_census(self.census))['self_controller_object_key'],None)

    def test_extension_input_assets_timeout_and_schema_are_explicit(self):
        for mutation in ('missing','escape','timeout','schema'):
            with self.subTest(mutation=mutation):
                altered=copy.deepcopy(self.config['bundle_builder'])
                if mutation=='missing':altered['entrypoint']='missing.py'
                if mutation=='escape':altered['inputs']='../private/inputs.json'
                if mutation=='timeout':altered['timeout_seconds']=46
                if mutation=='schema':altered['args']=['unreviewed']
                with self.assertRaises(ValueError):bootstrap.builder_configuration(self.source,self.inventory,altered)
        (self.source/'private/builder.py').write_text('raise SystemExit(0)')
        with self.assertRaisesRegex(ValueError,'asset_pin_mismatch'):self.build()

    def test_extension_failures_do_not_admit_runtime(self):
        for mutation,reason in [('exit','bundle_builder_failed'),('receipt','receipt_scope'),('digest','result_digests'),
            ('primary','exact_reviewed_controllers_required'),('profile','saved_epoch_forbidden'),
            ('context_code','builder_context_code_not_pinned'),('ammunition_code','builder_ammunition_code_not_pinned'),
            ('no_health','builder_roster_health_required'),
            ('input','changed_pinned_input'),('code','generated_code_not_pinned'),('census','source_hash_mismatch'),('unlisted','uninventoried_output')]:
            with self.subTest(mutation=mutation):
                self.save_inputs(mutation)
                attempt=self.root/('attempt-'+mutation);attempt.mkdir()
                with self.assertRaisesRegex(ValueError,reason):
                    bootstrap.build_bundle(self.source,self.inventory,self.config,self.census,attempt/'runtime')
                self.assertFalse((attempt/'bootstrap-worker-status.json').exists())

    def test_extension_child_deadline_is_enforced(self):
        self.config['bundle_builder']['timeout_seconds']=1;self.save_inputs('timeout')
        with self.assertRaises(subprocess.TimeoutExpired):self.build()
        self.assertFalse((self.root/'bundle-builder-result.json').exists())



if __name__ == '__main__':
    unittest.main()
