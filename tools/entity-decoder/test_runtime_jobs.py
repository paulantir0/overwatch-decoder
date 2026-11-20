import io
import subprocess
import time
import types
import unittest
from unittest.mock import patch

import runtime_jobs as jobs
import runtime_roster as roster
import runtime_producer as producer


class FakeApi:
    def __init__(self,deny=False,active=None):
        self.calls=[];self.deny=deny;self.active=[0] if active is None else active
    def create(self):self.calls.append(('create',));return 10
    def configure(self,h):self.calls.append(('configure',h))
    def duplicate_inheritable(self,h):self.calls.append(('duplicate',h));return 11
    def assign_current(self,h):
        self.calls.append(('assign_current',h))
        if self.deny:raise jobs.JobError('enroll_owned_producer_failed')
    def terminate(self,h):self.calls.append(('terminate_job',h))
    def close(self,h):self.calls.append(('close',h))
    def active_processes(self,h):
        self.calls.append(('active',h));return self.active.pop(0) if len(self.active)>1 else self.active[0]


class JobTests(unittest.TestCase):
    def test_windows_struct_layout_and_kill_only_limit(self):
        import ctypes
        self.assertEqual(ctypes.sizeof(jobs.DWORD),4)
        self.assertEqual(ctypes.sizeof(jobs._BasicAccounting),48)
        if ctypes.sizeof(ctypes.c_void_p)==8:
            self.assertEqual(ctypes.sizeof(jobs._BasicLimits),64)
            self.assertEqual(ctypes.sizeof(jobs._ExtendedLimits),144)
        self.assertEqual(jobs.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,0x2000)

    def test_direct_windows_composer_requires_existing_membership(self):
        with patch.object(producer.sys,'platform','win32'),patch.object(jobs,'require_current_job',side_effect=jobs.JobError('not in job')),patch.object(producer,'verify_composer')as verify:
            with self.assertRaisesRegex(jobs.JobError,'not in job'):
                producer.main(['--compose','never.py','0'*64,'--'])
            verify.assert_not_called()
        with self.assertRaisesRegex(jobs.JobError,'existing_job'):
            jobs.require_current_job(types.SimpleNamespace(current_in_job=lambda:False))
        jobs.require_current_job(types.SimpleNamespace(current_in_job=lambda:True))

    def test_assignment_gate_closes_inherited_handle_even_if_denied(self):
        for denied in (False,True):
            api=FakeApi(deny=denied)
            if denied:
                with self.assertRaisesRegex(jobs.JobError,'enroll_owned'):jobs.enroll_current_producer(11,api)
            else:jobs.enroll_current_producer(11,api)
            self.assertEqual(api.calls,[('assign_current',11),('close',11)])
        with self.assertRaisesRegex(jobs.JobError,'explicit_inherited'):jobs.enroll_current_producer(None,FakeApi())

    def test_no_child_spawn_when_enrollment_denied(self):
        with patch.object(jobs,'enroll_current_producer',side_effect=jobs.JobError('denied')),patch.object(producer.subprocess,'Popen')as popen,patch.object(producer,'run_composer')as composer:
            with self.assertRaisesRegex(jobs.JobError,'denied'):producer.run(None,job_handle=11)
            popen.assert_not_called();composer.assert_not_called()

    def test_explicit_inherited_duplicate_and_parent_lifetime(self):
        api=FakeApi();captured={};process=types.SimpleNamespace()
        def launch(command,**kwargs):captured.update(command=command,**kwargs);return process
        result=jobs.spawn_producer(['python','producer','config'],cwd='bundle',stdout=io.BytesIO(),stderr=1,
                                   api=api,popen=launch,startup_factory=types.SimpleNamespace)
        self.assertIs(result,process);self.assertEqual(captured['command'][-2:],['--job-handle','11'])
        self.assertTrue(captured['close_fds']);self.assertEqual(captured['startupinfo'].lpAttributeList,{'handle_list':[11]})
        self.assertEqual(api.calls,[('create',),('configure',10),('duplicate',10),('close',11)])
        result._overwatch_decoder_owned_job.terminate_and_close()
        self.assertEqual(api.calls[-3:],[('terminate_job',10),('active',10),('close',10)])

    def test_failed_launch_closes_both_job_handles(self):
        api=FakeApi()
        with self.assertRaisesRegex(OSError,'launch failed'):
            jobs.spawn_producer([],cwd='bundle',stdout=None,stderr=None,api=api,startup_factory=types.SimpleNamespace,
                                popen=lambda *a,**k:(_ for _ in ()).throw(OSError('launch failed')))
        self.assertIn(('close',10),api.calls);self.assertIn(('close',11),api.calls)

    def test_descendant_shutdown_is_verified_and_all_handles_close_on_failure(self):
        class Process:
            def __init__(self,job):self._overwatch_decoder_owned_job=job
            def poll(self):return 0
        stuck=FakeApi(active=[1]);empty=FakeApi();jobs_owned=[jobs.OwnedJob(stuck),jobs.OwnedJob(empty)]
        children=[{},{}];logs=[io.BytesIO(),io.BytesIO()]
        errors=roster.cleanup_owned([(Process(j),log,c)for j,log,c in zip(jobs_owned,logs,children)],time.monotonic()-1)
        self.assertEqual(len(errors),1);self.assertIn('descendants_not_joined',errors[0])
        self.assertTrue(children[1]['owned_job_closed']);self.assertIn('owned_job_cleanup_error',children[0])
        self.assertTrue(all(log.closed for log in logs));self.assertTrue(all(j.handle is None for j in jobs_owned))
        self.assertIn(('close',10),stuck.calls);self.assertIn(('close',10),empty.calls)

    def test_missing_job_cannot_report_successful_tree_cleanup(self):
        process=types.SimpleNamespace(poll=lambda:0);child={};log=io.BytesIO()
        errors=roster.cleanup_owned([(process,log,child)],time.monotonic()+1)
        self.assertEqual(errors,['owned_producer_job_missing'])
        self.assertTrue(log.closed);self.assertEqual(child['owned_job_cleanup_error'],'owned_producer_job_missing')

    def test_active_process_poll_has_shared_deadline(self):
        api=FakeApi(active=[2,1,0]);job=jobs.OwnedJob(api)
        with patch.object(jobs.time,'sleep'):
            job.terminate_and_close(time.monotonic()+1)
        self.assertEqual(api.calls.count(('active',10)),3)
        self.assertEqual(api.calls[-1],('close',10))

if __name__=='__main__':unittest.main()
