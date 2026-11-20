"""Finite generic capacity boundaries; no application data or process access."""
import json
from pathlib import Path
import tempfile
import unittest

from event_journal import iter_event_journal
from native_event_envelope import NativeEventEnvelope
from relations import GuardedRelations, InvalidBinding
from runtime_producer import validate_line, MAX_BYTES, MAX_LINE
from test_profile_guard_reference_bounds import profile, decoder
from test_live_sessions import fixture
from live_relations import LiveRelations
from live_sessions import LiveSession
from test_live_relations import raw as encode_event


class NativeCapacityBoundsTests(unittest.TestCase):
    def test_fields_at_old_new_and_over_cap_keep_dependency_ids(self):
        for schema in (1, 4):
            for count in (128, 129, 160):
                value=profile(count, 0, schema=schema)
                value['guards']=[dict(address=4096,bytes_hex='01000000')]
                parsed=decoder(value)
                self.assertEqual(len(parsed.fields),count)
                self.assertTrue(all(ids==[0]for ids in parsed.guard_ids.values()))
            with self.assertRaisesRegex(InvalidBinding,'profile_bounds'):
                decoder(profile(161,161,schema=schema))
        # V4 allows twelve declarations per field across all 160 fields.
        # The distinct-guard limit remains 256 after deduplication.
        for value in (profile(160,1921),profile(160,257,distinct=257)):
            with self.assertRaises(InvalidBinding):decoder(value)

    def test_raw_and_journal_line_boundaries_retain_every_byte(self):
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'events.jsonl'
            for size in (256*1024,256*1024+1,512*1024):
                raw=b'{"padding":"'+b'x'*(size-len(b'{"padding":""}\n'))+b'"}\n'
                self.assertEqual(len(raw),size)
                validate_line(raw,size)
                with NativeEventEnvelope(raw).owned()as event:
                    self.assertEqual(event.raw,raw)
                    self.assertEqual(len(event.snapshot()['padding']),size-15)
                path.write_bytes(raw)
                self.assertEqual(list(iter_event_journal(path)),[raw])
            oversized=raw[:-1]+b' \n';path.write_bytes(oversized)
            with self.assertRaisesRegex(ValueError,'line_bound'):validate_line(oversized,len(oversized))
            with self.assertRaisesRegex(ValueError,'line_bound'):NativeEventEnvelope(oversized)
            with self.assertRaisesRegex(ValueError,'journal_line_limit'):list(iter_event_journal(path))
            with self.assertRaisesRegex(ValueError,'total_byte_bound'):validate_line(b'{}\n',MAX_BYTES+1)
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError,'journal_byte_limit'):
                list(iter_event_journal(path,maximum_bytes=len(raw)-1))

    def test_live_session_accepts_exact_native_line_ceiling_and_latches_above(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);_,events,factory,_=fixture(root,count=1)
            original=encode_event(events[0]);line=original[:-1]+b' '*(MAX_LINE-len(original))+b'\n'
            session=LiveSession(factory)
            self.assertIsNone(session.consume(line))
            self.assertEqual(session.input_bytes,MAX_LINE)
            self.assertEqual(session.events,1)
            oversized=line[:-1]+b' \n'
            session=LiveSession(factory)
            with self.assertRaisesRegex(ValueError,'session_line_bound'):session.consume(oversized)
            self.assertTrue(session.failed)
            self.assertEqual(session.events,0)

    def test_profile_and_metadata_caps_do_not_follow_event_line_increase(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);fixture(root,count=1)
            path=root/'1/profile.json';raw=path.read_bytes()
            path.write_bytes(raw+b' '*(256*1024+1-len(raw)))
            with self.assertRaisesRegex(ValueError,'profile_size'):LiveRelations(root/'1','a'*32,1)
        value=profile();raw=json.dumps(value).encode()
        with self.assertRaisesRegex(InvalidBinding,'invalid_profile'):
            GuardedRelations(raw+b' '*(256*1024+1-len(raw)),allow_profile4=True)
        self.assertEqual(MAX_LINE,512*1024)


if __name__=='__main__':unittest.main()
