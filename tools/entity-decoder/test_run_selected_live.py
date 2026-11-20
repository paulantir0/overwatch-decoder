import io,json,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import run_selected_live as r

class Child:
 def __init__(self,timeout=False,ended=False):self.calls=[];self.timeout=timeout;self.ended=ended
 def poll(self):return 0 if self.ended else None
 def terminate(self):self.calls.append('terminate')
 def kill(self):self.calls.append('kill');self.ended=True
 def wait(self,timeout):
  self.calls.append(('wait',timeout))
  if self.timeout and not self.ended:raise subprocess.TimeoutExpired(['owned_child'],timeout)
  self.ended=True;return 0
class Tests(unittest.TestCase):
 def test_owned_child_cleanup(self):
  for slow,calls in [(False,['terminate',('wait',2)]),(True,['terminate',('wait',2),'kill',('wait',2)])]:
   child=Child(timeout=slow);r.stop_owned(child);self.assertEqual(child.calls,calls);self.assertEqual(child.poll(),0)
  ended=Child(ended=True);r.stop_owned(ended);self.assertEqual(ended.calls,[]);r.stop_owned(None)
 def test_byte_budget_has_no_partial_overrun(self):
  import io
  f=io.BytesIO();b=r.Budget(3);b.write(f,b'12')
  with self.assertRaisesRegex(ValueError,'byte_limit'):b.write(f,b'34')
  self.assertEqual(f.getvalue(),b'12')
 def test_compact_unknowns_sources_and_clock(self):
  item=dict(value=None,validation_status='unknown',reason='unmapped_build_resource_or_locale')
  row=dict(entity_id='body:x',controller_id='controller:y',is_local=False,reason=None,visibility='unknown',
   hero=item,health=dict(value=200,validation_status='reviewed'),position=dict(value=[1,2,3],validation_status='reviewed'),relation=dict(value='enemy',validation_status='reviewed'))
  result=dict(entities=[row],session_id='a'*32,segment=1,event_sequence=4,timestamp=dict(monotonic_frequency=10000000,utc_origin='time'),profile_sha256='b'*64)
  c=r.compact(result,'c'*64);self.assertEqual(c['entities'][0]['hero_reason'],item['reason']);self.assertIsNone(c['entities'][0]['hero'])
  self.assertEqual(c['source_clock']['kind'],'windows_qpc');self.assertEqual(c['scope'],'configured_controller_window')
 def test_native_terminal_completion_not_inferred_from_exit_or_eof(self):
  complete=dict(status='finished',complete=True,stop_reason='duration_elapsed')
  partial=dict(status='finished',complete=False,stop_reason='acquisition_attempt_limit')
  self.assertEqual(r.classify_outcome(None,0,complete),dict(status='complete',cli_exit_code=0))
  for native_exit in (0,7):
   self.assertEqual(r.classify_outcome(None,native_exit,partial),dict(status='partial',cli_exit_code=7))
  for native_exit in (2,4):
   self.assertEqual(r.classify_outcome(None,native_exit,partial),dict(status='partial',cli_exit_code=native_exit))
  for terminal in (None,dict(status='finished',complete=None),dict(status='failed',complete=False)):
   self.assertEqual(r.classify_outcome(None,0,terminal)['status'],'failed')
  self.assertEqual(r.classify_outcome(None,7,complete),dict(status='failed',cli_exit_code=7))
  self.assertEqual(r.classify_outcome('admission failed',0,complete),dict(status='failed',cli_exit_code=1))
  self.assertEqual(r.classify_outcome('permission denied',4,None),dict(status='failed',cli_exit_code=4))

 def test_contract_reads_only_caller_pinned_template_and_fields(self):
  from test_selected_entity_view import relative_fixture
  from test_hero_asset_labels import fixture as asset_fixture
  from selected_entity_view import SelectedEntityView
  profile,c,frame,kwargs=relative_fixture()
  _,_,catalog,asset_artifacts,_=asset_fixture()
  artifacts=dict(kwargs['artifacts'],**asset_artifacts)
  proof=c['bindings'][0]['review_sha256'];native=c['category_rule']['review_sha256']
  calibration=b'synthetic caller calibration';calpin=r.sha(calibration);artifacts[calpin]=calibration
  template=dict(schema='overwatch-decoder.selected-runner-template/1',gap_policy='current_frame_only',local_validation_status='template_local',
   binding_validation_status='template_binding',health_validation_status='template_health',
   category_rule={k:v for k,v in c['category_rule'].items() if k not in ('review_sha256','label_review_sha256')})
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);(root/'config.json').write_bytes(r.raw(dict(batches=['00'])));private=root/'private';(private/'recipes').mkdir(parents=True);(private/'artifacts').mkdir()
   for pin,data in artifacts.items():(private/'artifacts'/f'{pin}.bin').write_bytes(data)
   (private/'catalog.json').write_bytes(r.raw(catalog));(private/'selected-template.json').write_bytes(r.raw(template))
   for name,pin in [('selected-review',proof),('native-review',native),('practice-calibration',calpin)]:
    (private/(name+'.sha256')).write_text(pin)
   recipe=b'{}';(private/'recipes/batch00.json').write_bytes(recipe)
   actor=dict(c['bindings'][0]['fields'],ordinal_within_profile_only=0,health_sum='sum')
   (private/'recipes/batch00.bindings.json').write_bytes(r.raw(dict(local_context=c['local_context']['fields'],actors=[actor])))
   acquired=root/'acquisition';acquired.mkdir();(acquired/'profile.json').write_bytes(profile)
   (acquired/'manifest.json').write_bytes(r.raw(dict(recipe_sha256=r.sha(recipe),evidence_sha256='cd'*32)))
   with patch.object(r,'BASE',root):
    projectors=r.Projectors('00',acquired,root/'out');contract,review=projectors.contract(acquired)
    meta=json.loads((private/'recipes/batch00.bindings.json').read_bytes())
    meta.update(allow_empty_local_context=True,local_empty_collection=dict(rows='local_bodies',prefix='local_body'))
    (private/'recipes/batch00.bindings.json').write_bytes(r.raw(meta))
    enabled=r.Projectors('00',acquired,root/'out').contract(acquired)
    self.assertEqual(enabled,(contract,review))
   decoded=r.parse(contract)
   self.assertEqual(decoded['category_rule']['ordered_bits'],template['category_rule']['ordered_bits'])
   self.assertEqual(decoded['local_context']['validation_status'],'template_local')
   self.assertEqual(decoded['gap_policy'],'current_frame_only')
   self.assertEqual(decoded['bindings'][0]['health']['validation_status'],'template_health')
   self.assertEqual(decoded['bindings'][0]['fields'],c['bindings'][0]['fields'])
   SelectedEntityView(profile,contract,source=dict(profile_sha256=r.sha(profile),acquisition=decoded['source']),
    artifacts=projectors.artifacts,hero_catalog=projectors.catalog,allow_profile4=True)

 def test_runner_generates_empty_admission_only_for_explicit_native_collection(self):
  from test_selected_empty_partition import fixture as empty_fixture
  from test_hero_asset_labels import fixture as asset_fixture
  from selected_entity_view import SelectedEntityView
  profile,c,frame,kwargs=empty_fixture();_,_,catalog,asset_artifacts,_=asset_fixture()
  artifacts=dict(kwargs['artifacts'],**asset_artifacts)
  calibration=b'synthetic caller calibration';calpin=r.sha(calibration);artifacts[calpin]=calibration
  template=dict(schema='overwatch-decoder.selected-runner-template/1',gap_policy='current_frame_only',local_validation_status='template_local',
   binding_validation_status='template_binding',health_validation_status='template_health',
   category_rule=dict(c['category_rule'],same_group_label='ally',different_group_label='enemy'))
  template['category_rule'].pop('review_sha256')
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);(root/'config.json').write_bytes(r.raw(dict(batches=['p0'])));private=root/'private'
   (private/'recipes').mkdir(parents=True);(private/'artifacts').mkdir()
   for pin,data in artifacts.items():(private/'artifacts'/f'{pin}.bin').write_bytes(data)
   (private/'catalog.json').write_bytes(r.raw(catalog));(private/'selected-template.json').write_bytes(r.raw(template))
   for name,pin in [('selected-review',c['local_context']['review_sha256']),('native-review',c['category_rule']['review_sha256']),('practice-calibration',calpin)]:
    (private/(name+'.sha256')).write_text(pin)
   (private/'recipes/batchp0.json').write_bytes(artifacts[c['source']['recipe_sha256']])
   meta=dict(local_context=c['local_context']['fields'],actors=[],allow_empty_partition=True,empty_collection=dict(rows='actors',prefix='entity'))
   metadata=private/'recipes/batchp0.bindings.json';metadata.write_bytes(r.raw(meta))
   acquired=root/'acquisition';acquired.mkdir();(acquired/'profile.json').write_bytes(profile)
   for filename,key in [('manifest.json','manifest_sha256'),('evidence.jsonl','evidence_sha256')]:
    (acquired/filename).write_bytes(artifacts[c['source'][key]])
   with patch.object(r,'BASE',root):
    projectors=r.Projectors('p0',acquired,root/'out');contract,review=projectors.contract(acquired)
    decoded=r.parse(contract);self.assertTrue(decoded['allow_empty_bindings']);self.assertEqual(decoded['partition_id'],'p0')
    view=SelectedEntityView(profile,contract,source=dict(profile_sha256=r.sha(profile),acquisition=decoded['source']),
     artifacts=projectors.artifacts,allow_profile4=True)
    self.assertEqual(view.project(frame)['entities'],[])
    meta['allow_empty_partition']=False;metadata.write_bytes(r.raw(meta))
    with self.assertRaisesRegex(ValueError,'empty_partition_not_configured'):r.Projectors('p0',acquired,root/'out').contract(acquired)

if __name__=='__main__':unittest.main()
