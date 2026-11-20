import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from live_relations import LiveRelations
from live_sessions import LiveSession
from native_event_envelope import NativeEventEnvelope, borrowed_event
from test_live_sessions import fixture
from test_live_relations import raw,live,next_frame


class NativeEventReuseTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.epochs,self.events,self.factory,_=fixture(self.root,count=1)

    def ready(self, factory=None, **options):
        coordinator = LiveSession(factory or self.factory, **options)
        for event in self.events[:5]:coordinator.consume(raw(event))
        return coordinator

    def test_frame_strictly_decodes_once_across_coordinator_and_protected_hook(self):
        seen=[]
        class Extension(LiveRelations):
            def _consume_event(self,original,envelope):
                result=super()._consume_event(original,envelope)
                event=borrowed_event(envelope,original)
                if result is not None:
                    seen.append(event)
                    with self_test.assertRaises(TypeError):event['recording_frame']['fields'].clear()
                return result
        self_test=self
        def factory(session,acquisition,segment):
            return Extension(self.root/'1',session['session_id'],segment['segment'])
        coordinator=self.ready(factory)
        original=raw(self.events[5]);loads=json.loads
        with patch('native_event_envelope.json.loads',wraps=loads)as decode:
            result,event=coordinator.consume_with_event(original)
        self.assertEqual(decode.call_count,1)
        self.assertEqual(event,json.loads(original));self.assertIs(type(event),dict)
        self.assertIsNot(event,seen[0]);self.assertIsNot(result['source_artifacts'],seen[0].get('source_artifacts'))
        self.assertEqual(coordinator.frames,1)

    def test_public_snapshots_results_and_later_frames_do_not_alias(self):
        coordinator=self.ready();first,event=coordinator.consume_with_event(raw(self.events[5]))
        expected_key=first['relations'][0]['body_object_key'];expected_pin=first['source_artifacts']['acquisition']['recipe_sha256']
        event['recording_frame']['target']['pid']=999
        event['fields'].clear();first['relations'][0]['body_object_key']='caller-mutation'
        first['source_artifacts']['acquisition']['recipe_sha256']='caller-mutation'
        saved=copy.deepcopy(first)
        frame=next_frame(self.epochs[1][1]);next_event=live(frame,6);next_event['emitted_ticks']=frame['end_ticks']+20
        second=coordinator.consume(raw(next_event))
        self.assertEqual(second['relations'][0]['body_object_key'],expected_key)
        self.assertEqual(second['source_artifacts']['acquisition']['recipe_sha256'],expected_pin)
        self.assertEqual(first,saved);self.assertEqual(coordinator.target['pid'],123)

    def test_owned_callback_uses_one_decode_and_read_only_current_event(self):
        coordinator=self.ready();loads=json.loads;retained=[]
        def consumer(result,event):
            self.assertIs(type(result),dict)
            with self.assertRaises(TypeError):event['recording_frame']['fields'].clear()
            retained.append(event)
            return result['event_sequence']
        with patch('native_event_envelope.json.loads',wraps=loads)as decode:
            self.assertEqual(coordinator.consume_owned(raw(self.events[5]),consumer),5)
        self.assertEqual(decode.call_count,1)
        with self.assertRaises(TypeError):retained[0]['target'].update(pid=999)
        self.assertEqual(coordinator.frames,1)

    def test_owned_projection_bytes_match_bound_and_detached_result(self):
        original = raw(self.events[5])
        expected = self.ready().consume(original)
        expected_bytes = json.dumps(expected, separators=(',', ':'), allow_nan=False).encode() + b'\n'
        coordinator = self.ready()
        previous_output = coordinator.output_bytes

        def consumer(projection, event, projection_bytes):
            self.assertIs(type(projection_bytes), bytes)
            self.assertEqual(projection_bytes, expected_bytes)
            self.assertEqual(coordinator.output_bytes, previous_output + len(expected_bytes))
            self.assertEqual(projection, expected)
            with self.assertRaises(TypeError):
                event['recording_frame']['fields'].clear()
            projection['source_artifacts']['acquisition']['recipe_sha256'] = 'caller-mutation'
            self.assertEqual(json.loads(projection_bytes), expected)
            return projection_bytes

        self.assertEqual(coordinator.consume_owned(original, consumer, with_projection_bytes=True), expected_bytes)
        frame = next_frame(self.epochs[1][1])
        following = live(frame, 6)
        following['emitted_ticks'] = frame['end_ticks'] + 20
        subsequent = coordinator.consume(raw(following))
        self.assertEqual(subsequent['source_artifacts']['acquisition']['recipe_sha256'],
                         expected['source_artifacts']['acquisition']['recipe_sha256'])

    def test_owned_projection_bound_rejects_before_callback(self):
        coordinator = self.ready(maximum_output_bytes=1)
        consumer = Mock()
        with self.assertRaisesRegex(ValueError, 'session_output_bound'):
            coordinator.consume_owned(raw(self.events[5]), consumer, with_projection_bytes=True)
        consumer.assert_not_called()
        self.assertTrue(coordinator.failed)
        self.assertIsNone(coordinator.adapter)

    def test_owned_projection_bytes_are_none_without_projection(self):
        coordinator = LiveSession(self.factory)

        def consumer(projection, event, projection_bytes):
            self.assertIsNone(projection)
            self.assertEqual(event['kind'], 'session_start')
            self.assertIsNone(projection_bytes)
            return 'received'

        result = coordinator.consume_owned(raw(self.events[0]), consumer, with_projection_bytes=True)
        self.assertEqual(result, 'received')
        self.assertEqual(coordinator.output_bytes, 0)

    def test_owned_projection_bytes_callback_failure_latches(self):
        coordinator = self.ready()
        consumer = Mock(side_effect=ValueError('fixture_consumer_failure'))
        with self.assertRaisesRegex(ValueError, 'fixture_consumer_failure'):
            coordinator.consume_owned(raw(self.events[5]), consumer, with_projection_bytes=True)
        consumer.assert_called_once()
        self.assertTrue(coordinator.failed)
        self.assertIsNone(coordinator.adapter)

    def test_each_raw_call_decodes_again_and_callback_failure_latches(self):
        coordinator=LiveSession(self.factory);loads=json.loads;original=raw(self.events[0])
        with patch('native_event_envelope.json.loads',wraps=loads)as decode:
            coordinator.consume(original)
            with self.assertRaisesRegex(ValueError,'global_event_order'):coordinator.consume(original)
        self.assertEqual(decode.call_count,2)
        coordinator=self.ready()
        def consumer(result,event):
            event['recording_frame']['fields'].clear()
        with self.assertRaisesRegex(TypeError,'read_only'):
            coordinator.consume_owned(raw(self.events[5]),consumer)
        self.assertTrue(coordinator.failed);self.assertIsNone(coordinator.adapter)

    def test_legacy_consume_override_is_not_bypassed(self):
        calls=[]
        class Legacy(LiveRelations):
            def consume(self,original):
                calls.append(original)
                return super().consume(original)
        def factory(session,acquisition,segment):
            return Legacy(self.root/'1',session['session_id'],segment['segment'])
        coordinator=self.ready(factory);original=raw(self.events[5])
        coordinator.consume(original);self.assertIn(original,calls)

    def test_internal_dispatch_rejects_dict_mismatch_and_expired_envelopes(self):
        for mode in ('dict','mismatch','expired'):
            coordinator=self.ready();adapter=coordinator.adapter;original=raw(self.events[5])
            with self.subTest(mode=mode):
                if mode=='dict':
                    with self.assertRaisesRegex(ValueError,'envelope_required'):adapter._consume_native_event(original,json.loads(original))
                    with self.assertRaisesRegex(ValueError,'envelope_required'):adapter._consume_event(original,json.loads(original))
                else:
                    envelope=NativeEventEnvelope(original)
                    if mode=='mismatch':
                        with envelope.owned(),self.assertRaisesRegex(ValueError,'raw_mismatch'):
                            adapter._consume_native_event(original+b' ',envelope)
                    else:
                        with envelope.owned():pass
                        with self.assertRaisesRegex(ValueError,'not_active'):adapter._consume_native_event(original,envelope)
                self.assertTrue(adapter.failed)

    def test_bad_json_and_input_types_fail_and_latch_with_original_counter_order(self):
        for original,reason,count in [(b'{"x":{"a":1,"a":2}}\n','duplicate_json_key',1),
            (b'{"x":NaN}\n','nonfinite_json',1),(b'null\n','session_event_schema',1),
            ({},'session_line_bound',0),(bytearray(b'{}\n'),'session_line_bound',0)]:
            coordinator=LiveSession(self.factory)
            with self.subTest(reason=reason),self.assertRaisesRegex(ValueError,reason):coordinator.consume(original)
            self.assertTrue(coordinator.failed);self.assertEqual(coordinator.events,count)
            with self.assertRaisesRegex(ValueError,'closed'):coordinator.consume(raw(self.events[0]))

if __name__=='__main__':unittest.main()
