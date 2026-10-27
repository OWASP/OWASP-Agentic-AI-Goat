"""Controlled process observations only; never signals or observes host processes."""
import types,unittest
from unittest.mock import patch
import v03_private_process as subject

class Controls(unittest.TestCase):
    def setUp(self):
        self.row=types.SimpleNamespace(pid=200,ppid=100,pgid=200,uid=77,start_sec=1,start_usec=2)
        self.api=types.SimpleNamespace(identity=lambda pid:self.row if pid==200 else None,
            arguments=lambda pid:('node','fixture'),group_pids=lambda pid:[])
        self.expected={'identity':subject.identity(self.row),'argv':['node','fixture']}
        self.request={'version':1,'op':'retire','pid':200,'mainIdentity':None,'expected':self.expected}
        for name,value in [('getuid',77),('getppid',100),('getsid',200)]:
            p=patch.object(subject.os,name,return_value=value);p.start();self.addCleanup(p.stop)
    def test_observe_exact_child(self):
        request={**self.request,'op':'inspect','expected':None}
        self.assertEqual(subject.operation(self.api,request)['observed'],self.expected)
    def test_parent_observation_is_fixed_actual_parent_only(self):
        self.row.pid=100;self.row.pgid=50;self.row.ppid=50
        self.api.identity=lambda pid:self.row if pid==100 else None
        request={**self.request,'op':'parent','pid':100,'expected':None}
        self.assertEqual(subject.operation(self.api,request)['observed']['identity']['pid'],100)
        with self.assertRaisesRegex(RuntimeError,'PARENT_REQUEST'):
            subject.operation(self.api,{**request,'pid':200})
    def test_changed_birth_never_signals(self):
        self.row.start_usec=3;sent=[]
        with self.assertRaisesRegex(RuntimeError,'CHANGED'):
            subject.operation(self.api,self.request,send=lambda *x:sent.append(x))
        self.assertEqual(sent,[])
    def test_foreign_parent_never_signals(self):
        self.row.ppid=99;sent=[]
        with self.assertRaisesRegex(RuntimeError,'PARENT'):
            subject.operation(self.api,self.request,send=lambda *x:sent.append(x))
        self.assertEqual(sent,[])
    def test_exact_term_then_actual_empty_group(self):
        sent=[]
        result=subject.operation(self.api,self.request,send=lambda *x:sent.append(x))
        self.assertEqual(sent,[(200,subject.signal.SIGTERM)])
        self.assertTrue(result['groupAbsent'])
    def test_absent_leader_still_requires_group_empty(self):
        self.api.identity=lambda pid:None
        self.api.group_pids=lambda pid:[201]
        with self.assertRaisesRegex(RuntimeError,'GROUP_CHANGED'):
            subject.operation(self.api,self.request,send=lambda *x:self.fail('unexpected signal'))
    def test_unjoined_group_is_not_absence(self):
        self.api.group_pids=lambda pid:[200];clock=[0]
        def sleep(seconds):clock[0]+=seconds
        with self.assertRaisesRegex(RuntimeError,'GROUP_UNJOINED'):
            subject.operation(self.api,self.request,now=lambda:clock[0],sleep=sleep,send=lambda *x:None)
    def test_signal_failure_does_not_claim_absence(self):
        def denied(*args):raise PermissionError('signal denied')
        with self.assertRaises(PermissionError):subject.operation(self.api,self.request,send=denied)
    def test_wrapper_signals_are_fixed_and_do_not_claim_join(self):
        for op,sig in [('term',subject.signal.SIGTERM),('kill',subject.signal.SIGKILL)]:
            sent=[]
            result=subject.operation(self.api,{**self.request,'op':op},send=lambda *x:sent.append(x))
            self.assertEqual(sent,[(200,sig)])
            self.assertFalse(result['groupAbsent'])
            self.assertTrue(result['signalSent'])
    def test_wrapper_kill_refuses_changed_birth_or_orphan_group(self):
        self.row.start_usec=9
        with self.assertRaisesRegex(RuntimeError,'CHANGED'):
            subject.operation(self.api,{**self.request,'op':'kill'},send=lambda *x:self.fail('unexpected signal'))
        self.api.identity=lambda pid:None;self.api.group_pids=lambda pid:[201]
        with self.assertRaisesRegex(RuntimeError,'GROUP_UNPROVEN'):
            subject.operation(self.api,{**self.request,'op':'kill'},send=lambda *x:self.fail('unexpected signal'))

if __name__=='__main__':unittest.main()
