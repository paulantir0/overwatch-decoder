"""Own only runtime-created Windows process trees using kill-on-close jobs.

The observed target is never assigned to a job. The parent owns a non-inheritable
job handle. A producer receives one explicit inherited duplicate, enrolls itself,
and closes that duplicate before spawning anything. Descendants inherit job
membership, not the job handle. Denied assignment is an ordinary hard failure.
"""
import ctypes
from ctypes import wintypes
import subprocess
import sys
import time

JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
DUPLICATE_SAME_ACCESS = 2
DWORD = ctypes.c_uint32


class JobError(OSError):
    pass


class _BasicLimits(ctypes.Structure):
    _fields_ = [('PerProcessUserTimeLimit', ctypes.c_longlong),
                ('PerJobUserTimeLimit', ctypes.c_longlong), ('LimitFlags', DWORD),
                ('MinimumWorkingSetSize', ctypes.c_size_t), ('MaximumWorkingSetSize', ctypes.c_size_t),
                ('ActiveProcessLimit', DWORD), ('Affinity', ctypes.c_size_t),
                ('PriorityClass', DWORD), ('SchedulingClass', DWORD)]


class _IoCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in
                ('ReadOperationCount', 'WriteOperationCount', 'OtherOperationCount',
                 'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount')]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [('BasicLimitInformation', _BasicLimits), ('IoInfo', _IoCounters),
                ('ProcessMemoryLimit', ctypes.c_size_t), ('JobMemoryLimit', ctypes.c_size_t),
                ('PeakProcessMemoryUsed', ctypes.c_size_t), ('PeakJobMemoryUsed', ctypes.c_size_t)]


class _BasicAccounting(ctypes.Structure):
    _fields_ = [(name, ctypes.c_longlong) for name in
                ('TotalUserTime', 'TotalKernelTime', 'ThisPeriodTotalUserTime', 'ThisPeriodTotalKernelTime')] + [
                ('TotalPageFaultCount', DWORD), ('TotalProcesses', DWORD),
                ('ActiveProcesses', DWORD), ('TotalTerminatedProcesses', DWORD)]


class Win32Jobs:
    def __init__(self):
        if sys.platform != 'win32':
            raise JobError('windows_job_required')
        self.dll = ctypes.WinDLL('kernel32', use_last_error=True)
        signatures = {
            'CreateJobObjectW': ([ctypes.c_void_p, wintypes.LPCWSTR], wintypes.HANDLE),
            'SetInformationJobObject': ([wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, DWORD], wintypes.BOOL),
            'GetCurrentProcess': ([], wintypes.HANDLE),
            'DuplicateHandle': ([wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
                                 ctypes.POINTER(wintypes.HANDLE), DWORD, wintypes.BOOL, DWORD], wintypes.BOOL),
            'AssignProcessToJobObject': ([wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL),
            'IsProcessInJob': ([wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)], wintypes.BOOL),
            'TerminateJobObject': ([wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
            'QueryInformationJobObject': ([wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, DWORD, ctypes.c_void_p], wintypes.BOOL),
            'CloseHandle': ([wintypes.HANDLE], wintypes.BOOL),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.dll, name)
            function.argtypes, function.restype = arguments, result

    def check(self, ok, operation):
        if not ok:
            raise JobError(f'{operation}_failed: winerror={ctypes.get_last_error()}')

    def create(self):
        handle = self.dll.CreateJobObjectW(None, None)
        self.check(handle, 'create_owned_job')
        return handle

    def configure(self, handle):
        limits = _ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        self.check(self.dll.SetInformationJobObject(handle, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                    ctypes.byref(limits), ctypes.sizeof(limits)), 'configure_kill_on_close_job')

    def duplicate_inheritable(self, handle):
        duplicate = wintypes.HANDLE()
        current = self.dll.GetCurrentProcess()
        self.check(self.dll.DuplicateHandle(current, handle, current, ctypes.byref(duplicate),
                                            0, True, DUPLICATE_SAME_ACCESS), 'duplicate_owned_job')
        return duplicate.value

    def assign_current(self, handle):
        self.check(self.dll.AssignProcessToJobObject(handle, self.dll.GetCurrentProcess()),
                   'enroll_owned_producer')

    def current_in_job(self):
        result = wintypes.BOOL()
        self.check(self.dll.IsProcessInJob(self.dll.GetCurrentProcess(), None, ctypes.byref(result)),
                   'query_composer_job_membership')
        return bool(result.value)

    def terminate(self, handle):
        self.check(self.dll.TerminateJobObject(handle, 1), 'terminate_owned_job')

    def active_processes(self, handle):
        accounting = _BasicAccounting()
        self.check(self.dll.QueryInformationJobObject(handle, 1, ctypes.byref(accounting),
                                                     ctypes.sizeof(accounting), None), 'query_owned_job')
        return accounting.ActiveProcesses

    def close(self, handle):
        self.check(self.dll.CloseHandle(handle), 'close_owned_job_handle')


class OwnedJob:
    def __init__(self, api=None):
        self.api = Win32Jobs() if api is None else api
        self.handle = self.api.create()
        try:
            self.api.configure(self.handle)
        except BaseException:
            self.api.close(self.handle)
            self.handle = None
            raise

    def terminate_and_close(self, deadline=None):
        """Termination also works if an inherited handle is still open on failure."""
        if deadline is None:
            deadline = time.monotonic()+5
        if self.handle is not None:
            handle, self.handle = self.handle, None
            try:
                self.api.terminate(handle)
                while self.api.active_processes(handle):
                    if time.monotonic() >= deadline:
                        raise JobError('owned_job_descendants_not_joined')
                    time.sleep(min(.01, max(0, deadline-time.monotonic())))
            finally:
                self.api.close(handle)


def enroll_current_producer(handle, api=None):
    """Must be called before native/composer spawn; always close inherited handle."""
    if type(handle) is not int or not 0 < handle < (1 << (8*ctypes.sizeof(ctypes.c_void_p))):
        raise JobError('explicit_inherited_job_handle_required')
    api = Win32Jobs() if api is None else api
    try:
        api.assign_current(handle)
    finally:
        api.close(handle)


def require_current_job(api=None):
    api = Win32Jobs() if api is None else api
    if not api.current_in_job():
        raise JobError('composer_requires_existing_job_membership')


def spawn_producer(command, *, cwd, stdout, stderr, api=None, popen=None, startup_factory=None):
    """Create a gated producer with an explicit handle list; never enroll by PID."""
    popen = subprocess.Popen if popen is None else popen
    job = OwnedJob(api)
    inherited = None
    process = None
    try:
        startup_factory = subprocess.STARTUPINFO if startup_factory is None else startup_factory
        inherited = job.api.duplicate_inheritable(job.handle)
        startup = startup_factory()
        startup.lpAttributeList = {'handle_list': [inherited]}
        process = popen([*command, '--job-handle', str(inherited)], cwd=cwd, stdout=stdout,
                        stderr=stderr, close_fds=True, startupinfo=startup)
        # Parent duplicate is closed immediately; the child closes its copy at enrollment.
        job.api.close(inherited)
        inherited = None
        process._overwatch_decoder_owned_job = job
        return process
    except BaseException:
        try:
            # If launch succeeded but handle bookkeeping failed, do not lose ownership.
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=1)
        finally:
            try:
                job.terminate_and_close()
            finally:
                if inherited is not None:
                    job.api.close(inherited)
        raise
