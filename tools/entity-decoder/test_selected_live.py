"""Selected-only live admission using synthetic native-shaped v4 evidence."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from live_relations import LiveRelations, InvalidLive
from selected_entity_view import SelectedEntityView
from test_selected_entity_view import pool_fixture
from test_live_relations import raw, event, live, SESSION


def setup(root):
    profile, contract, frame, kwargs = pool_fixture()
    p = json.loads(profile)
    recipe = raw(dict(target={k:p['target'][k] for k in ('image_name','executable_sha256','architecture')}, stages=[]))
    evidence = b'{"synthetic":true}\n'
    sha = lambda b: hashlib.sha256(b).hexdigest()
    manifest = dict(schema='overwatch-decoder.acquisition-result/1',complete=True,error=None,target=p['target'],
        profile_sha256=sha(profile),recipe_sha256=sha(recipe),evidence_sha256=sha(evidence),stages_completed=0)
    mr = raw(manifest)
    pins = dict(manifest_sha256=sha(mr),recipe_sha256=sha(recipe),evidence_sha256=sha(evidence))
    contract['source'] = pins
    for name,data in [('profile.json',profile),('recipe.json',recipe),('manifest.json',mr),
                      ('evidence.jsonl',evidence),('contract.json',raw(contract))]:
        (root/name).write_bytes(data)
    frame.update(interpretation='profile_declared_research',visibility='research',runtime_semantics_validated=False,
        public_state_eligible=False,atomic=False,scheduled_slot=0,scheduled_ticks=0,jitter_ticks=10,
        skipped_intervals_before=0,skipped_intervals_total=0,utc_origin_before_ticks=0,
        requested_interval_ms=100,scheduler_backend='synthetic',hard_realtime=False)
    for name,sample in frame['fields'].items():
        declaration=next(d for d in p['fields'] if d['name']==name)
        sample.setdefault('read_address_hex',f"{declaration['address']:016x}");sample.setdefault('path_id',None)
        sample.setdefault('reason',None);sample.setdefault('read_attempted',True);sample.setdefault('read_error',None)
    session = event('session_start',0,target=p['target'],recipe_sha256=sha(recipe),source_kind='native_process_memory',
        recording_frame_included=True,public_state_eligible=False,atomic=False)
    session['emitted_ticks']=0
    acq = event('acquisition_end',2,acquisition=dict(ordinal=1,directory='acquisition-0001',complete=True,error=None,start_ticks=0,end_ticks=1,
        profile_sha256=sha(profile),manifest_sha256=sha(mr)))
    acq['emitted_ticks']=1
    segment = event('segment_start',3,segment=1,acquisition=1,profile_sha256=sha(profile),
        source_stream_schema='overwatch-decoder.field-stream/4',start_ticks=2,
        fields=[dict(name=f['name'],type=f['type'])for f in p['fields']])
    segment['emitted_ticks']=2
    adapter = LiveRelations(root,SESSION,1,selected_only=True,selected_contract=root/'contract.json',
        selected_artifacts=kwargs['artifacts'])
    adapter.begin_epoch(raw(session),raw(acq),raw(segment))
    e = live(frame,4)
    for name,sample in frame['fields'].items():
        out=e['fields'][name];out['read_attempted']=sample['read_attempted'];out['read_error']=sample['read_error']
        if sample.get('codec')=='pool_sum_f32':
            out['source']='calculated_process_memory'
            out['operands']={k:{n:v for n,v in x.items()if n!='address_hex'}for k,x in sample['operands'].items()}
    return adapter,e


class SelectedLiveTests(unittest.TestCase):
    def test_exact_stateless_projection_and_non_durability(self):
        with tempfile.TemporaryDirectory() as temp:
            a,e=setup(Path(temp));expected=a.selected.project(e['recording_frame'])
            result=a.consume(raw(e))
            self.assertEqual(result['entities'],expected['entities'])
            self.assertEqual(result['entities'][0]['health']['value'],7.)
            self.assertEqual(result['schema'],'overwatch-decoder.selected-entity-live/1')
            self.assertFalse(result['durability_verified']);self.assertFalse(result['recording']['complete'])
            self.assertNotIn(temp,json.dumps(result))

    def test_guard_envelope_codec_tampering_and_failure_latch(self):
        for case in ('guardbytes','guardid','operand','clock','target','profile','order','fieldsource'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as temp:
                a,e=setup(Path(temp))
                if case=='guardbytes':e['recording_frame']['guards_before'][0]['read']['bytes_hex']='00000000'
                elif case=='guardid':e['recording_frame']['guards_before'][0]['guard_id']=1
                elif case=='operand':e['fields']['sum']['operands']['snapshot_a']['bytes_hex']='00'*16
                elif case=='clock':e['monotonic_frequency']=999
                elif case=='target':e['target']['pid']=999
                elif case=='profile':e['profile_sha256']='00'*32
                elif case=='order':e['event_sequence']=99
                else:e['fields']['sum']['source']='process_memory'
                with self.assertRaises(ValueError):a.consume(raw(e))
                with self.assertRaisesRegex(InvalidLive,'live_adapter_failed'):a.consume(raw(e))

    def test_gap_and_membership_change_do_not_reuse_previous_values(self):
        for gap in (False,True):
            with self.subTest(gap=gap),tempfile.TemporaryDirectory() as temp:
                a,e=setup(Path(temp))
                if gap:
                    for obj in (e,e['recording_frame']):
                        obj.update(skipped_intervals_before=1,skipped_intervals_total=1,scheduled_slot=1,
                                   scheduled_ticks=100,jitter_ticks=-90)
                else:
                    for obj in (e['fields']['sum'],e['recording_frame']['fields']['sum']):
                        obj.update(status='unknown',value=None,reason='pool_membership_changed')
                result=a.consume(raw(e))
                self.assertIsNone(result['entities'][0]['health']['value'])
                self.assertFalse(result['gap']['previous_values_carried'])

    def test_defaults_and_source_hash_admission_remain_strict(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);a,e=setup(root)
            with self.assertRaisesRegex(ValueError,'unsupported_live_profile'):LiveRelations(root,SESSION,1)
            with self.assertRaisesRegex(ValueError,'excludes_legacy'):
                LiveRelations(root,SESSION,1,selected_only=True,selected_contract=root/'contract.json',health_contracts=['x'])
            (root/'evidence.jsonl').write_bytes(b'{"changed":true}\n')
            with self.assertRaisesRegex(ValueError,'acquisition_hash'):
                LiveRelations(root,SESSION,1,selected_only=True,selected_contract=root/'contract.json')

    def test_native_guard_read_failure_outputs_unknown(self):
        with tempfile.TemporaryDirectory() as temp:
            a,e=setup(Path(temp));frame=e['recording_frame']
            check=frame['guards_before'][0]
            check.update(ok=False,error='read_failed')
            check['read'].update(returned_bytes=0,bytes_hex=None,error='read_failed')
            for fields in (frame['fields'],e['fields']):
                for sample in fields.values():
                    sample.update(status='unknown',value=None,reason='guard_mismatch_before')
            result=a.consume(raw(e))
            self.assertIsNone(result['entities'][0]['entity_id'])
            self.assertIsNone(result['entities'][0]['health']['value'])

    @staticmethod
    def mark_interrupted_guard(event):
        frame = event['recording_frame']
        event['terminal_reason'] = frame['terminal_reason'] = 'cancelled'
        check = frame['guards_before'][0]
        check.update(ok=False, error='cancelled')
        check['read'].update(returned_bytes=None, bytes_hex=None, error='cancelled')
        for skipped in frame['guards_before'][1:] + frame['guards_after']:
            skipped.update(ok=False, error='cancelled')
            skipped['read'].update(attempted=False, returned_bytes=None, bytes_hex=None, address_hex=None,
                                   start_ticks=None, end_ticks=None, error='cancelled')
        for fields in (event['fields'], frame['fields']):
            for sample in fields.values():
                sample.update(status='unknown', value=None, reason='cancelled', read_start_ticks=None,
                              read_end_ticks=None, read_attempted=False, read_error='cancelled')
                if 'read_address_hex' in sample:
                    sample['read_address_hex'] = None
                for operand in sample.get('operands', {}).values():
                    operand.update(attempted=False, returned_bytes=None, bytes_hex=None,
                                   start_ticks=None, end_ticks=None, error='cancelled')
                    if 'address_hex' in operand:
                        operand['address_hex'] = None
        return frame, check

    def test_cancelled_guard_without_return_count_preserves_unknown_frame(self):
        with tempfile.TemporaryDirectory() as temp:
            adapter, event = setup(Path(temp))
            self.mark_interrupted_guard(event)
            result = adapter.consume(raw(event))
            self.assertIsNone(result['entities'][0]['entity_id'])
            self.assertIsNone(result['entities'][0]['health']['value'])
            self.assertFalse(result['gap']['previous_values_carried'])

    def test_interrupted_guard_rejects_contradictory_evidence(self):
        for fault in ('success', 'time', 'address', 'field', 'reason', 'terminal', 'omitted_count'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temp:
                adapter, event = setup(Path(temp))
                frame, check = self.mark_interrupted_guard(event)
                if fault == 'success':
                    check['read']['error'] = None
                elif fault == 'time':
                    check['read']['end_ticks'] = frame['end_ticks'] + 1
                elif fault == 'address':
                    check['read']['address_hex'] = '0000000000000000'
                elif fault in ('field', 'reason'):
                    for fields in (event['fields'], frame['fields']):
                        if fault == 'field':
                            fields['sum'].update(status='observed', value=7.0, reason=None)
                        else:
                            fields['sum']['reason'] = 'guard_mismatch_before'
                elif fault == 'terminal':
                    event['terminal_reason'] = None
                else:
                    del check['read']['returned_bytes']
                with self.assertRaises(InvalidLive):
                    adapter.consume(raw(event))

    def test_selected_epoch_requires_original_metadata_admission(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);a,e=setup(root)
            fresh=LiveRelations(root,SESSION,1,selected_only=True,selected_contract=root/'contract.json',
                selected_artifacts=a.selected.artifacts if hasattr(a.selected,'artifacts') else pool_fixture()[3]['artifacts'])
            with self.assertRaises(ValueError):fresh.consume(raw(e))

    def test_session_stream_rejects_partial_output(self):
        import io
        from live_sessions import stream
        class Coordinator:
            def consume(self,line):return {'synthetic': True}
            def close(self):return {}
        class Short(io.BytesIO):
            def write(self,data):return super().write(data[:-1])
        with self.assertRaisesRegex(ValueError,'session_output_short_write'):
            stream(Coordinator(),io.BytesIO(b'{}\n'),Short())

    def test_closed_epoch_does_not_accept_another_frame(self):
        with tempfile.TemporaryDirectory() as temp:
            a,e=setup(Path(temp));a.consume(raw(e))
            a.consume(raw(event('segment_end',5,segment=dict(ordinal=1))))
            e['event_sequence']=6;e['emitted_ticks']=800
            with self.assertRaisesRegex(ValueError,'selected_epoch_closed'):a.consume(raw(e))

if __name__=='__main__':unittest.main()
