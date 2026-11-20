import contextlib,errno,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import live_file_budget as b

class Entry:
    def __init__(self,entry,before):self.entry=entry;self.path=entry.path;self.before=before
    def stat(self,**kwargs):self.before(self.entry);return self.entry.stat(**kwargs)

class Tests(unittest.TestCase):
    def scan_hook(self,root,hook):
        real=os.scandir
        @contextlib.contextmanager
        def scan(path):
            with real(path) as entries:
                # Enumerate before mutation to deterministically reproduce the
                # Windows publication race between listing and file metadata.
                snapshot=list(entries)
                yield iter(Entry(e,hook) for e in snapshot)
        return patch.object(b.os,'scandir',side_effect=scan)
    def test_atomic_rename_restarts_and_counts_replacement(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);pending=root/'.manifest-fixture.partial';pending.write_bytes(b'x'*40);calls=[]
            def rename(entry):
                calls.append(entry.name)
                if entry.name==pending.name and pending.exists():pending.replace(root/'manifest.json')
            with self.scan_hook(root,rename):self.assertEqual(b.check_directory_budget(root,40),40)
            self.assertEqual(calls,[pending.name,'manifest.json'])
    def test_rename_cannot_bypass_quota(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);pending=root/'.partial';pending.write_bytes(b'x'*41)
            def rename(entry):
                if entry.name=='.partial' and pending.exists():pending.replace(root/'published.json')
            with self.scan_hook(root,rename):
                with self.assertRaisesRegex(ValueError,'runner_disk_limit'):b.check_directory_budget(root,40,error_code='runner_disk_limit')
    def test_unlink_retries_whole_tree_and_counts_remaining_output(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'stable').mkdir();(root/'stable'/'samples').write_bytes(b'x'*19);gone=root/'.partial';gone.write_bytes(b'old')
            def unlink(entry):
                if entry.path==str(gone) and gone.exists():gone.unlink()
            with self.scan_hook(root,unlink):self.assertEqual(b.check_directory_budget(root,19),19)
            with self.assertRaisesRegex(ValueError,'directory_byte_limit'):b.check_directory_budget(root,18)
    def test_permission_and_io_errors_are_not_retried_or_ignored(self):
        for error in (PermissionError(errno.EACCES,'denied'),OSError(errno.EIO,'I/O failure')):
            with self.subTest(error=error),tempfile.TemporaryDirectory() as d:
                (Path(d)/'file').write_bytes(b'x');calls=[]
                def fail(entry):calls.append(entry.name);raise error
                with self.scan_hook(Path(d),fail):
                    with self.assertRaises(type(error)):b.check_directory_budget(d,100)
                self.assertEqual(calls,['file'])
    def test_persistent_disappearance_fails_closed_at_attempt_bound(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d)/'file').write_bytes(b'x');calls=[]
            def gone(entry):calls.append(entry.name);raise FileNotFoundError(errno.ENOENT,'rename race')
            with self.scan_hook(Path(d),gone):
                with self.assertRaises(FileNotFoundError):b.check_directory_budget(d,100,maximum_attempts=3)
            self.assertEqual(len(calls),3)
    def test_directory_publication_race_and_missing_root_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);sub=root/'pending';sub.mkdir();(sub/'data').write_bytes(b'x'*25);real=os.scandir;renamed=False
            def scan(path):
                nonlocal renamed
                if Path(path)==sub and not renamed:sub.rename(root/'published');renamed=True
                return real(path)
            with patch.object(b.os,'scandir',side_effect=scan):self.assertEqual(b.check_directory_budget(root,25),25)
            with self.assertRaises(FileNotFoundError):b.check_directory_budget(root/'absent',100)
    def test_bounds_and_zero_byte_boundary(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(b.check_directory_budget(d,0),0)
            for maximum,attempts in ((-1,3),(True,3),(10,0),(10,9),(10,True)):
                with self.assertRaises(ValueError):b.check_directory_budget(d,maximum,maximum_attempts=attempts)

if __name__=='__main__':unittest.main()
