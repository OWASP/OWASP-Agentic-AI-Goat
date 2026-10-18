import importlib.util,io,json,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
P=Path(__file__).with_name('run-mcp-vm-public-host-key.py');spec=importlib.util.spec_from_file_location('key_runner',P);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class RunnerTests(unittest.TestCase):
    def args(self):
        values={'manifest':'/main/manifest','manifest-sha256':'a'*64,'docker':'/pinned/docker','docker-sha256':'b'*64,'socket':'/pinned/socket','daemon-id':'daemon','image-id':'sha256:'+'c'*64,'python-sha256':'d'*64,'ssh-host':'owned','socket-uid':'501','socket-dev':'1','socket-ino':'2','ssh-port':'2222'}
        return [part for k,v in values.items() for part in ['--'+k,v]]
    def test_plan_does_not_allocate_or_launch(self):
        with patch.object(m,'admit',return_value={}),patch.object(m.tempfile,'mkdtemp',side_effect=AssertionError('allocation')),patch.object(m,'OwnedProcesses',side_effect=AssertionError('launch')),patch('sys.stdout',new_callable=io.StringIO) as out:
            self.assertEqual(m.main(self.args()+['--plan']),0);self.assertFalse(json.loads(out.getvalue())['allocation'])
    def test_duplicate_flag_denied_before_admission(self):
        with patch.object(m,'admit',side_effect=AssertionError('admission')):
            with self.assertRaises(ValueError):m.main(self.args()+['--docker','/other'])
    def test_owned_command_cleanup_and_byte_cap(self):
        for overflow in [False,True]:
            calls=[];child=SimpleNamespace(returncode=0,poll=lambda:0)
            def launch(argv,**kw):
                self.assertTrue(kw['start_new_session']);self.assertEqual(kw['stdin'],m.subprocess.DEVNULL);self.assertEqual(argv,['pinned','info']);kw['stdout'].write(b'x'*(65537 if overflow else 2));kw['stdout'].flush();return child
            owned=SimpleNamespace(launch=launch,finish=lambda c:calls.append(c))
            with tempfile.TemporaryDirectory() as directory:
                work=lambda:m.bounded_command(argv=['pinned','info'],owned=owned,evidence=Path(directory),env={'HOME':'owned'},index=1,timeout=1)
                if overflow:
                    with self.assertRaises(RuntimeError):work()
                else:self.assertEqual(work().stdout,'xx')
            self.assertEqual(calls,[child])
    def test_command_interrupt_and_cleanup_failure_keep_both(self):
        def interrupt():raise KeyboardInterrupt()
        child=SimpleNamespace(poll=interrupt)
        owned=SimpleNamespace(launch=lambda *a,**k:child,finish=lambda c:(_ for _ in ()).throw(RuntimeError('cleanup')))
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(BaseExceptionGroup) as caught:m.bounded_command(argv=['pinned'],owned=owned,evidence=Path(directory),env={},index=1,timeout=1)
        self.assertIsInstance(caught.exception.exceptions[0],KeyboardInterrupt);self.assertIsInstance(caught.exception.exceptions[1],RuntimeError)
    def finalize(self,fail):
        events=[];state={'cleanupVerified':False}
        def action(name,result=None):
            def call(*args):
                events.append(name)
                if name==fail:raise KeyboardInterrupt(name)
                return result
            return call
        code=m.execute_owned(state=state,work=action('work',{'public':True}),check_work=action('after-receipt'),enter_cleanup=action('cleanup-start'),check_cleanup=action('deadline'),cleanup=action('cleanup'),readmit=action('readmit'),publish_receipt=action('receipt-publication'),publish_state=action('journal'),restore=action('restore'))
        return code,state,events
    def test_interrupt_after_receipt_cannot_publish_pass(self):
        code,state,events=self.finalize('after-receipt');self.assertEqual(code,1);self.assertEqual(state['failure'],'KeyboardInterrupt');self.assertEqual(state['status'],'failed');self.assertNotIn('receipt-publication',events);self.assertIn('restore',events);self.assertIn('journal',events)
    def test_cleanup_deadline_and_admission_interrupts_always_restore_and_record(self):
        for failure in ['cleanup-start','deadline','cleanup','readmit']:
            code,state,events=self.finalize(failure);self.assertEqual(code,1);self.assertEqual(state['status'],'failed');self.assertIn('restore',events);self.assertIn('journal',events);self.assertNotIn('receipt-publication',events)
    def test_publication_restoration_or_journal_failure_cannot_return_success(self):
        for failure in ['receipt-publication','restore','journal']:
            code,state,events=self.finalize(failure);self.assertEqual(code,1);self.assertEqual(state['status'],'failed');self.assertIn('restore',events);self.assertIn('journal',events)
        code,state,events=self.finalize(None);self.assertEqual(code,0);self.assertEqual(state['status'],'passed');self.assertLess(events.index('restore'),events.index('journal'))
if __name__=='__main__':unittest.main()
