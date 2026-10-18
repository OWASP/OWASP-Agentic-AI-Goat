import base64,copy,json,struct,unittest
from types import SimpleNamespace
import mcp_vm_public_host_key as m

NONCE='a'*32;IMAGE='sha256:'+'b'*64;IDENT='c'*64
def output():
    wire=struct.pack('>I',11)+b'ssh-ed25519'+struct.pack('>I',32)+b'x'*32
    return {'version':1,'publicKey':'ssh-ed25519 '+base64.b64encode(wire).decode(),'source':'/etc/ssh/ssh_host_ed25519_key.pub','entry':{'type':'regular-file','uid':0,'gid':0,'mode':0o644,'nlink':1,'size':100,'dev':1,'ino':2},'sourceSha256':'d'*64,'directory':{'uid':0,'mode':0o755},'noFollow':True,'stableRead':True}
def layout():
    p=m.plan(NONCE,IMAGE)
    return {'Id':IDENT,'Name':'/'+p['name'],'Image':IMAGE,'Config':{'Labels':p['labels'],'User':'10001:10001','Entrypoint':['/usr/local/bin/node'],'Env':['NODE_OPTIONS=','NODE_PATH=','LD_PRELOAD=','LD_LIBRARY_PATH='],'Cmd':['-e',m.READER]},'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'Privileged':False,'CapAdd':None,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],'Memory':67108864,'NanoCpus':250000000,'PidsLimit':32,'PidMode':'','IpcMode':'private','Mounts':[{'BindOptions':{'NonRecursive':True}}]},'Mounts':[{'Type':'bind','Source':'/etc/ssh','Destination':'/vm-ssh','RW':False,'Propagation':'rprivate'}],'NetworkSettings':{'Ports':{}},'State':{'Status':'created','Running':False,'ExitCode':0}}
class ReaderTests(unittest.TestCase):
    def test_closed_read_program_and_create_contract(self):
        args=m.create_args(m.plan(NONCE,IMAGE));self.assertIn('type=bind,src=/etc/ssh,dst=/vm-ssh,readonly,bind-nonrecursive=true',args)
        self.assertNotIn('run',args);self.assertNotIn('--privileged',args);self.assertIn('O_NOFOLLOW',m.READER);self.assertNotIn('readdir',m.READER);self.assertNotIn('process.argv',m.READER)
        self.assertEqual(m.parse_public_output(json.dumps(output()))['publicKey'],output()['publicKey'])
    def test_malformed_public_entry_rejected(self):
        for mutate in [lambda x:x.update(publicKey='ssh-ed25519 AAAA'),lambda x:x.update(source='/etc/ssh/ssh_host_ed25519_key'),lambda x:x.update(noFollow=False),lambda x:x['entry'].update(type='symlink'),lambda x:x['entry'].update(mode=0o666),lambda x:x['entry'].update(nlink=2),lambda x:x['directory'].update(mode=0o777)]:
            x=output();mutate(x)
            with self.assertRaises((ValueError,RuntimeError)):m.parse_public_output(json.dumps(x))
    def test_mount_and_privilege_denials(self):
        m.validate_layout(layout())
        for mutate in [lambda x:x['Mounts'][0].update(Source='/'),lambda x:x['Mounts'][0].update(Type='volume'),lambda x:x['Mounts'][0].update(RW=True),lambda x:x['HostConfig'].update(NetworkMode='host'),lambda x:x['HostConfig'].update(CapDrop=[]),lambda x:x['Config'].update(User='0'),lambda x:x['HostConfig']['Mounts'][0].update(BindOptions={}),lambda x:x['Mounts'].append({'Type':'bind'})]:
            x=layout();mutate(x)
            with self.assertRaises(RuntimeError):m.validate_layout(x)
    def execute(self,fail=None,remaining=lambda:10):
        events=[];commands=[];state={'exists':False,'started':False};row=layout()
        def docker(args,**kw):
            commands.append(args);self.assertGreater(kw['timeout'],0)
            stdout='';stderr='';code=0
            if args[0]=='info':stdout='daemon'
            elif args[:2]==['image','inspect']:stdout=IMAGE
            elif args[0]=='inspect':
                if state['exists']:stdout=json.dumps([row])
                else:code=1;stderr='Error: No such object: '+m.plan(NONCE,IMAGE)['name']
            elif args[0]=='create':
                self.assertEqual(events[-1][0],'public-key-create-intent');state['exists']=True
                if fail=='create':raise TimeoutError('ambiguous create')
                stdout=IDENT
            elif args[0]=='start':
                self.assertEqual(events[-1][0],'public-key-start-intent');state['started']=True
                if fail=='start':raise TimeoutError('ambiguous start')
                row['State']['Status']='exited';stdout=json.dumps(output())
            elif args[0]=='rm':
                self.assertEqual(args[2:],[ '--volumes',IDENT]);state['exists']=False
            else:raise AssertionError(args[0])
            return SimpleNamespace(stdout=stdout,stderr=stderr,returncode=code)
        call=lambda:m.read_owned_key(docker=docker,record=lambda *x:events.append(x),remaining=remaining,cleanup_remaining=lambda:7,daemon_id='daemon',image=IMAGE,nonce=NONCE,ssh_host='owned-vm',ssh_port=2222)
        return call,state,events,commands
    def test_inspect_before_start_and_receipt_only_after_absence(self):
        call,state,events,commands=self.execute();receipt=call();self.assertFalse(state['exists']);self.assertEqual(receipt['cleanup']['status'],'removed_absence_verified');self.assertEqual(receipt['containerId'],IDENT);self.assertEqual(events[-1][0],'public-key-cleanup');self.assertLess([c[0] for c in commands].index('inspect'),[c[0] for c in commands].index('start'))
    def test_ambiguous_create_or_start_still_cleans_exact_owner(self):
        for phase in ['create','start']:
            call,state,events,commands=self.execute(phase)
            with self.assertRaises(TimeoutError):call()
            self.assertFalse(state['exists']);self.assertEqual(events[-1][0],'public-key-cleanup')
    def test_expired_work_admission_never_allocates(self):
        call,state,events,commands=self.execute(remaining=lambda:0)
        with self.assertRaises(TimeoutError):call()
        self.assertEqual(commands,[]);self.assertEqual(events,[])
    def test_interrupt_and_cleanup_error_preserve_both_causes(self):
        from unittest.mock import patch
        call,state,events,commands=self.execute('start')
        with patch.object(m,'parse_public_output',side_effect=KeyboardInterrupt('interrupted')),patch.object(m,'cleanup_owned',side_effect=RuntimeError('cleanup failed')):
            call,state,events,commands=self.execute()
            with self.assertRaises(BaseExceptionGroup) as caught:call()
        self.assertEqual(len(caught.exception.exceptions),2)
        self.assertIsInstance(caught.exception.exceptions[0],KeyboardInterrupt)
        self.assertIsInstance(caught.exception.exceptions[1],RuntimeError)
        self.assertTrue(state['exists'])
if __name__=='__main__':unittest.main()
