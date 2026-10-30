"""Offline fake Docker responses only; never starts a command."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from sql_nosql_docker_ownership import verify_daemon, verify_image, inspect_owned, validate_container_layout, cleanup_owned

CID='a'*64
IMAGE='sha256:'+'b'*64
LABELS={'owasp-ai-goat.qualification.nonce':'fixture','owasp-ai-goat.qualification.uid':'123'}

def response(stdout='',stderr='',code=0):
    return SimpleNamespace(returncode=code,stdout=stdout,stderr=stderr)

def container():
    return dict(Id=CID,Name='/owned',Image=IMAGE,Config=dict(Labels=LABELS.copy()),
        HostConfig=dict(Tmpfs={'/var/lib/postgresql':'rw,size=268435456'},Memory=536870912,
                        NanoCpus=2000000000,PidsLimit=256),Mounts=[],
        NetworkSettings=dict(Ports={'5432/tcp':[dict(HostIp='127.0.0.1',HostPort='12345')]}))

class Contract(unittest.TestCase):
    def test_daemon_absence_format_is_exact_and_not_an_outage(self):
        message = 'Error response from daemon: No such container: owned'
        self.assertIsNone(inspect_owned(lambda args:response('[]',message,1),name='owned',labels=LABELS,image=IMAGE))
        for error in [message.replace('owned','sibling'), message+'\nconnection failed', 'Error response from daemon: unavailable']:
            with self.assertRaises(RuntimeError):
                inspect_owned(lambda args:response('[]',error,1),name='owned',labels=LABELS,image=IMAGE)

    def test_daemon_and_local_image_must_match(self):
        verify_daemon(lambda args:response('daemon\n'),'daemon')
        verify_image(lambda args:response(IMAGE+'\n'),IMAGE)
        for fn,expected in [(verify_daemon,'daemon'),(verify_image,IMAGE)]:
            with self.assertRaises(RuntimeError):fn(lambda args:response('wrong'),expected)
        with self.assertRaises(RuntimeError):verify_image(lambda args:response('unused'),'postgres:18')

    def test_layout_and_full_owned_identity(self):
        row=container(); self.assertEqual(validate_container_layout(row),12345)
        self.assertEqual(inspect_owned(lambda args:response(json.dumps([row])),name='owned',labels=LABELS,image=IMAGE,captured_id=CID)['Id'],CID)
        mutations=[lambda r:r.update(Id='short'),lambda r:r.update(Image='sha256:'+'c'*64),
                   lambda r:r.update(Name='/sibling'),lambda r:r['Config']['Labels'].update({'owasp-ai-goat.qualification.nonce':'sibling'})]
        for mutate in mutations:
            row=container();mutate(row)
            with self.assertRaises(RuntimeError):inspect_owned(lambda args:response(json.dumps([row])),name='owned',labels=LABELS,image=IMAGE,captured_id=CID)
        for mutate in [lambda r:r.update(Mounts=[{'Source':'host'}]),lambda r:r['HostConfig'].update(Tmpfs={}),
                       lambda r:r['HostConfig'].update(Memory=0),lambda r:r['HostConfig'].update(NanoCpus=0),
                       lambda r:r['HostConfig'].update(PidsLimit=0),
                       lambda r:r['NetworkSettings']['Ports']['5432/tcp'][0].update(HostIp='0.0.0.0')]:
            row=container();mutate(row)
            with self.assertRaises(RuntimeError):validate_container_layout(row)

    def test_uncertain_creation_resolves_labels_then_removes_only_full_id(self):
        calls=[];removed=False
        def command(args):
            nonlocal removed
            calls.append(args)
            if args[0]=='info':return response('daemon')
            if args[0]=='rm':
                self.assertEqual(args,['rm','--force','--volumes',CID]);removed=True;return response(CID)
            return response(stderr='Error: No such object: owned',code=1) if removed else response(json.dumps([container()]))
        result=cleanup_owned(command,daemon_id='daemon',name='owned',labels=LABELS,image=IMAGE)
        self.assertEqual(result,dict(status='removed_absence_verified',containerId=CID))
        self.assertEqual(sum(args[0]=='rm' for args in calls),1)

    def test_mismatches_and_uncertain_absence_never_remove(self):
        for row in [dict(container(),Id='c'*64),dict(container(),Config=dict(Labels={}))]:
            calls=[]
            def command(args):
                calls.append(args);return response('daemon') if args[0]=='info' else response(json.dumps([row]))
            with self.assertRaises(RuntimeError):cleanup_owned(command,daemon_id='daemon',name='owned',labels=LABELS,image=IMAGE,captured_id=CID)
            self.assertFalse(any(args[0]=='rm' for args in calls))
        for error in ['daemon unavailable','Error: No such object: sibling']:
            with self.assertRaises(RuntimeError):inspect_owned(lambda args:response(stderr=error,code=1),name='owned',labels=LABELS,image=IMAGE)

    def test_creation_intent_precedes_run_and_finally_resolves_uncertain_creation(self):
        text=Path(__file__).with_name('run-sql-nosql-route-isolated.py').read_text()
        self.assertLess(text.index("record_ownership('container-intent.json'"),text.index('created = run('))
        self.assertLess(text.index('creation_intended = True'),text.index('created = run('))
        self.assertIn('if creation_intended:',text)
        self.assertIn('cleanup = cleanup_owned(',text)
        self.assertIn("'status': 'cleanup_unverified'",text)
        self.assertIn("'-p', '127.0.0.1::5432', args.postgres_image_id",text)
        self.assertIn("'--memory', '536870912', '--cpus', '2', '--pids-limit', '256'",text)
        self.assertNotIn("'postgres:18'",text)
        compile(text,'launcher','exec')

if __name__=='__main__':unittest.main()
