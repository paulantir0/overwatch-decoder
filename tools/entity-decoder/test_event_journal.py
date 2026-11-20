import gzip
from pathlib import Path
import tempfile
import unittest

from event_journal import open_event_journal_writer, iter_event_journal


class EventJournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, data, *, compression='gzip', name='events'):
        path = self.root/name
        with open_event_journal_writer(path, compression=compression) as stream:
            for line in data.splitlines(keepends=True):
                self.assertEqual(stream.write(line), len(line))
                stream.flush()
        return path

    def test_exact_legacy_and_compressed_bytes_and_deterministic_header(self):
        data = b'{"recording_frame":{"n":-0.0,"s":"\\u0061","i":-2147483648}}\n{"kind":"session_end"}\n'
        plain = self.write(data, compression='none', name='plain')
        packed = self.write(data, name='private-name.jsonl.gz')
        twin = self.write(data, name='different-name.gz')
        for path in (plain, packed):
            self.assertEqual(b''.join(iter_event_journal(path)), data)
        self.assertEqual(packed.read_bytes(), twin.read_bytes())
        self.assertEqual(packed.read_bytes()[3] & 8, 0)  # no filename header
        self.assertEqual(packed.read_bytes()[4:8], bytes(4))

    def test_new_file_only_and_invalid_format(self):
        path = self.write(b'{}\n')
        original = path.read_bytes()
        with self.assertRaises(FileExistsError):
            with open_event_journal_writer(path):
                self.fail('overwrote evidence')
        self.assertEqual(path.read_bytes(), original)
        with self.assertRaisesRegex(ValueError, 'journal_compression'):
            with open_event_journal_writer(self.root/'bad', compression='zip'):
                pass
        self.assertFalse((self.root/'bad').exists())

    def test_corruption_and_truncation_are_not_complete(self):
        data = b'{"kind":"frame","value":123}\n'*20
        path = self.write(data)
        original = path.read_bytes()
        for label, damaged in [('trailer', original[:-3]), ('crc', original[:-8]+bytes([original[-8]^1])+original[-7:])]:
            path.write_bytes(damaged)
            with self.assertRaises((EOFError, gzip.BadGzipFile)):
                list(iter_event_journal(path))
        path.write_bytes(original[:5])
        with self.assertRaises(EOFError):
            list(iter_event_journal(path))

    def test_plain_and_compressed_line_byte_and_stored_bounds(self):
        data = b'{"v":"'+b'a'*1024+b'"}\n'
        for mode in ('none', 'gzip'):
            path = self.write(data, compression=mode, name=mode)
            with self.assertRaisesRegex(ValueError, 'journal_line_limit'):
                list(iter_event_journal(path, maximum_line=64))
            with self.assertRaisesRegex(ValueError, 'journal_byte_limit'):
                list(iter_event_journal(path, maximum_bytes=64))
            with self.assertRaisesRegex(ValueError, 'journal_stored_limit'):
                list(iter_event_journal(path, maximum_stored_bytes=1))
            self.assertEqual(b''.join(iter_event_journal(path, maximum_bytes=len(data))), data)

    def test_partial_final_line_and_empty_journal(self):
        for mode in ('none', 'gzip'):
            path = self.write(b'{"partial":1}', compression=mode, name=mode)
            with self.assertRaisesRegex(ValueError, 'journal_partial_line'):
                list(iter_event_journal(path))
            empty = self.write(b'', compression=mode, name=mode+'-empty')
            self.assertEqual(list(iter_event_journal(empty)), [])

    def test_file_change_after_prefix_rejected_on_exhaustion(self):
        path = self.write(b'{}\n{}\n', compression='none')
        lines = iter_event_journal(path)
        self.assertEqual(next(lines), b'{}\n')
        with path.open('ab') as stream:
            stream.write(b'{}\n')
        with self.assertRaisesRegex(ValueError, 'journal_changed'):
            list(lines)

    def test_runner_opt_in_preserves_legacy_default(self):
        from run_selected_live import journal_options
        self.assertEqual(journal_options({}), dict(path='native-events.jsonl', compression='none'))
        self.assertEqual(journal_options({'native_journal_compression':'gzip'}),
                         dict(path='native-events.jsonl.gz', compression='gzip'))
        for value in (True, None, 'zip'):
            with self.assertRaisesRegex(ValueError, 'native_journal_compression'):
                journal_options({'native_journal_compression':value})

    def test_bounds_reject_bools_and_excessive_limits(self):
        path = self.write(b'{}\n')
        for key, value in [('maximum_line', True), ('maximum_bytes', 0),
                           ('maximum_stored_bytes', -1), ('maximum_line', 1024*1024+1),
                           ('maximum_bytes', 4*1024**3+1)]:
            with self.assertRaisesRegex(ValueError, 'journal_bounds'):
                list(iter_event_journal(path, **{key:value}))


if __name__ == '__main__':
    unittest.main()
