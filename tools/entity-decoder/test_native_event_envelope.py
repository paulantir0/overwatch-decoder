import copy
import json
import unittest
from native_event_envelope import NativeEventEnvelope, borrowed_event


class NativeEventEnvelopeTests(unittest.TestCase):
    def test_raw_binding_active_ownership_and_one_use(self):
        raw = b'{"nested":{"items":[1,{"ok":true}]}}\n'
        envelope = NativeEventEnvelope(raw)
        with self.assertRaisesRegex(ValueError, 'not_active'):borrowed_event(envelope, raw)
        with envelope.owned():
            with self.assertRaisesRegex(ValueError, 'raw_mismatch'):borrowed_event(envelope, b'{}\n')
            with self.assertRaisesRegex(ValueError, 'envelope_required'):borrowed_event(json.loads(raw), raw)
            self.assertEqual(envelope.snapshot(), json.loads(raw))
        with self.assertRaisesRegex(ValueError, 'not_active'):envelope.snapshot()
        with self.assertRaisesRegex(ValueError, 'already_used'):
            with envelope.owned():pass

    def test_nested_borrows_are_read_only_and_snapshots_are_detached(self):
        raw = b'{"x":[{"y":[1,2]}]}\n'; envelope = NativeEventEnvelope(raw)
        with envelope.owned():
            value = borrowed_event(envelope, raw)
            operations = [lambda:value.update(z=1), lambda:value['x'].append(3),
                lambda:value['x'][0].pop('y'), lambda:value['x'][0]['y'].__setitem__(0, 9),
                lambda:value['x'].__iadd__([3]), lambda:value.__ior__({'z':1})]
            for operation in operations:
                with self.assertRaisesRegex(TypeError, 'read_only'):operation()
            first=envelope.snapshot();second=copy.deepcopy(value)
            self.assertIs(type(first),dict);self.assertIs(type(first['x']),list)
            first['x'][0]['y'][0]=99;second['x'].clear()
            self.assertEqual(envelope.snapshot(),json.loads(raw))
        # An expired borrow stays read-only; it is not reused for another call.
        with self.assertRaises(TypeError):value['x'].clear()
        next_envelope=NativeEventEnvelope(raw)
        with next_envelope.owned():self.assertIsNot(borrowed_event(next_envelope,raw),value)

    def test_copy_protocols_cannot_duplicate_a_single_use_lease(self):
        envelope=NativeEventEnvelope(b'{"x":[1]}\n')
        for clone in(copy.copy,copy.deepcopy):
            with self.assertRaisesRegex(TypeError,'not_copyable'):clone(envelope)
        with envelope.owned():
            for clone in(copy.copy,copy.deepcopy):
                with self.assertRaisesRegex(TypeError,'not_copyable'):clone(envelope)

    def test_root_arrays_nested_arrays_and_objects_preserve_types_and_ownership(self):
        raw = b'[null,true,false,0,1.5,"text",[],[1,[{"x":[false,null]}]],{"y":[[]]}]\n'
        envelope = NativeEventEnvelope(raw)
        with envelope.owned():
            value = borrowed_event(envelope, raw)
            self.assertEqual(value, json.loads(raw))
            self.assertEqual([type(v) for v in value[:6]], [type(None), bool, bool, int, float, str])
            containers = [value, value[6], value[7], value[7][1], value[7][1][0],
                          value[7][1][0]['x'], value[8], value[8]['y'], value[8]['y'][0]]
            for container in containers:
                with self.assertRaisesRegex(TypeError, 'read_only'):
                    container.clear()
            snapshot = envelope.snapshot()
            snapshot[7][1][0]['x'][0] = 'changed'
            snapshot[8]['y'][0].append('changed')
            self.assertEqual(value, json.loads(raw))
        with self.assertRaisesRegex(ValueError, 'not_active'):envelope.snapshot()
        for container in containers:
            with self.assertRaisesRegex(TypeError, 'read_only'):container.clear()

    def test_large_flat_array_and_deep_nested_validation_remain_strict(self):
        # A scalar-heavy array exercises the optimized boundary within the
        # native line cap, with independently mutable detached snapshots.
        expected = [1, False, None, 'x'] * 10000
        raw = json.dumps(expected, separators=(',', ':')).encode() + b'\n'
        with NativeEventEnvelope(raw).owned() as envelope:
            value = borrowed_event(envelope, raw)
            self.assertEqual(value, expected)
            snapshot = envelope.snapshot();snapshot[0] = 99
            self.assertEqual(value[0], 1)
            with self.assertRaisesRegex(TypeError, 'read_only'):value[0] = 99
        for payload, reason in ((b'{"x":1,"x":2}', 'duplicate_json_key'),
                                (b'NaN', 'nonfinite_json'), (b'Infinity', 'nonfinite_json')):
            raw = b'[' * 32 + payload + b']' * 32 + b'\n'
            with self.assertRaisesRegex(ValueError, reason):NativeEventEnvelope(raw)

    def test_strict_duplicates_nonfinite_types_and_line_bounds(self):
        for raw in (b'{"x":1,"x":2}\n',b'{"x":[{"a":1,"a":2}]}\n'):
            with self.assertRaisesRegex(ValueError,'duplicate_json_key'):NativeEventEnvelope(raw)
        for token in (b'NaN',b'Infinity',b'-Infinity'):
            with self.assertRaisesRegex(ValueError,'nonfinite_json'):NativeEventEnvelope(b'{"x":'+token+b'}\n')
        for raw in ('{}\n',bytearray(b'{}\n'),memoryview(b'{}\n'),{},None,b'',b'{}',b' '*(512*1024)+b'\n'):
            with self.assertRaisesRegex(ValueError,'line_bound'):NativeEventEnvelope(raw)
        with NativeEventEnvelope(b'null\n').owned()as envelope:self.assertIsNone(envelope.snapshot())
        with self.assertRaises(TypeError):NativeEventEnvelope(b'{}\n',{})

    def test_bulk_object_construction_rejects_decoded_duplicate_keys(self):
        for raw in (b'{"x":[],"\\u0078":{"a":1}}\n',
                    b'{"items":[{"key":[1,2],"key":null}]}\n',
                    b'{"first":{},"last":[],"first":{}}\n'):
            with self.assertRaisesRegex(ValueError, 'duplicate_json_key'):
                NativeEventEnvelope(raw)

    def test_bulk_object_construction_preserves_order_and_freezes_arrays(self):
        raw = b'{"z":[],"a":{"items":[[1],{"n":-0.0}]},"last":false}\n'
        with NativeEventEnvelope(raw).owned() as envelope:
            value = borrowed_event(envelope, raw)
            self.assertEqual(list(value), ['z', 'a', 'last'])
            self.assertEqual(json.dumps(envelope.snapshot()), json.dumps(json.loads(raw)))
            for container in (value, value['z'], value['a'], value['a']['items'],
                              value['a']['items'][0], value['a']['items'][1]):
                with self.assertRaisesRegex(TypeError, 'read_only'):
                    container.clear()

if __name__=='__main__':unittest.main()
