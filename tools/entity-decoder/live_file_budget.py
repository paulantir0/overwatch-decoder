"""Periodic byte budgets for an owned output tree with atomic file publication."""
from __future__ import annotations
import os
import stat


def check_directory_budget(root, maximum_bytes, *, error_code='directory_byte_limit', maximum_attempts=3):
    """Count a complete traversal, retrying only disappearing entries.

    Never omit an entry whose stat lost a rename/unlink race: restart the whole
    traversal so a replacement under a different name is counted. Repeated churn
    fails closed after a bounded number of attempts. Permission and other I/O
    errors propagate. This remains a periodic, non-atomic observation, not an OS
    quota or a reservation against concurrent writes.
    """
    if type(maximum_bytes) is not int or maximum_bytes < 0:
        raise ValueError('invalid_directory_byte_budget')
    if type(maximum_attempts) is not int or not 1 <= maximum_attempts <= 8:
        raise ValueError('invalid_directory_scan_attempts')
    for attempt in range(maximum_attempts):
        total = 0
        pending = [os.fspath(root)]
        try:
            while pending:
                with os.scandir(pending.pop()) as entries:
                    for entry in entries:
                        info = entry.stat(follow_symlinks=False)
                        if stat.S_ISDIR(info.st_mode):
                            pending.append(entry.path)
                            continue
                        # Match the former is_file() behavior for file symlinks;
                        # do not recurse through directory symlinks.
                        if stat.S_ISLNK(info.st_mode):
                            info = os.stat(entry.path)
                        if stat.S_ISREG(info.st_mode):
                            total += info.st_size
                            if total > maximum_bytes:
                                raise ValueError(error_code)
            return total
        except FileNotFoundError:
            if attempt + 1 == maximum_attempts:
                raise
    raise AssertionError('unreachable')
