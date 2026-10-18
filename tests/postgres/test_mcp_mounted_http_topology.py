import unittest
from types import SimpleNamespace
from mcp_mounted_http_topology import resource_plan,profile_members,OwnedMcpTopology,validate_layout,record_and_validate_layout

NONCE='a'*32
IMAGE='sha256:'+'b'*64
TEMPLATE=b'profile @@SUPERVISOR_PROFILE@@ { profile bwrap {} }'
def plan():return resource_plan(NONCE,IMAGE,'sha256:'+'c'*64,TEMPLATE,TEMPLATE)
def response(stdout='',code=0):return SimpleNamespace(stdout=stdout,stderr='',returncode=code)
class TopologyTests(unittest.TestCase):
    def test_rejected_layout_is_retained_before_assertion_without_secrets(self):
        events=[];spec=plan()['resources']['cli']
        row={'State':{'Status':'exited','Running':False,'ExitCode':1,'Error':'SECRET'},'Config':{'Env':['TOKEN=SECRET']},'HostConfig':{'PortBindings':{'8090/tcp':[{'HostIp':'127.0.0.1','HostPort':''}]}},'NetworkSettings':{'Ports':{}}}
        with self.assertRaises(RuntimeError):record_and_validate_layout(row,spec,lambda *args:events.append(args))
        self.assertEqual(events[0][0],'topology-container-layout')
        value=events[0][1];self.assertEqual(value['state']['ExitCode'],1);self.assertEqual(value['ports'],{})
        self.assertEqual(value['requestedBindings']['8090/tcp'][0]['HostIp'],'127.0.0.1')
        self.assertNotIn('SECRET',str(value));self.assertNotIn('Config',value)
    def test_exact_resource_plan_and_no_source_mount(self):
        p=plan();self.assertEqual(set(p['resources']),{'cli','http','mail'})
        self.assertEqual(p['resources']['http']['ports'],[8091]);self.assertEqual(p['resources']['mail']['ports'],[1025,8025])
        self.assertEqual(len({x['name'] for x in p['resources'].values()}),3)
        self.assertNotIn(b'@@',p['resources']['http']['policy'])
        for bad in ['latest','sha256:bad']:
            with self.assertRaises(ValueError):resource_plan(NONCE,bad,IMAGE,TEMPLATE,TEMPLATE)
    def test_profiles_match_actual_production_configuration_grammars(self):
        import re
        from pathlib import Path
        root=Path(__file__).resolve().parents[2]
        cli=(root/'sidecars/sandbox-runner/ownedTargetApi.js').read_text()
        http=(root/'sidecars/sandbox-runner/owned-http/executor.js').read_text()
        # Read the exact anchored regex consumed by each current production constructor.
        cli_pattern=re.search(r'!/(\^dvaia-mcp-sandbox[^/]+)/\.test',cli).group(1)
        http_pattern=re.search(r'!/(\^dvaia-owned-http-[^/]+)/\.test',http).group(1)
        value=plan()
        for kind,pattern in [('cli',cli_pattern),('http',http_pattern)]:
            spec=value['resources'][kind]
            self.assertRegex(spec['profile'],pattern)
            self.assertEqual(spec['profileNames'],[spec['profile'],spec['profile']+'//bwrap'])
            self.assertIn(spec['profile'].encode(),spec['policy'])
            self.assertNotRegex(spec['name'],pattern)
        other=resource_plan('d'*32,IMAGE,'sha256:'+'c'*64,TEMPLATE,TEMPLATE)
        self.assertNotEqual(value['resources']['cli']['profile'],other['resources']['cli']['profile'])
    def test_exact_profile_family_not_prefix_sibling(self):
        self.assertEqual(profile_members(['a (enforce)','a//bwrap (enforce)','ab (enforce)','a-other (enforce)'],'a'),['a (enforce)','a//bwrap (enforce)'])
    def test_remote_binding_requires_pinned_host_keys_without_localhost_bypass(self):
        from pathlib import Path
        good={'uid':501,'daemonId':'daemon','strictHostKeyChecking':True,'noHostAuthenticationForLocalhost':False,'knownHostsSha256':'e'*64,'resolvedConfigurationSha256':'d'*64}
        for change in [{'noHostAuthenticationForLocalhost':True},{'knownHostsSha256':''}]:
            with self.assertRaises(RuntimeError):
                OwnedMcpTopology(plan=plan(),docker=lambda *a,**k:None,remote=lambda *a,**k:None,record=lambda *a:None,remaining=lambda:1,daemon_id='daemon',evidence_root=Path.cwd(),remote_binding={**good,**change})
    def manager(self,remote,record,remaining=lambda:10):
        return OwnedMcpTopology(plan=plan(),docker=lambda args,**kw:response('daemon' if args[0]=='info' else args[-1]),remote=remote,record=record,remaining=remaining,daemon_id='daemon',evidence_root=__import__('pathlib').Path.cwd(),remote_binding={'uid':501,'daemonId':'daemon','strictHostKeyChecking':True,'noHostAuthenticationForLocalhost':False,'knownHostsSha256':'e'*64,'resolvedConfigurationSha256':'d'*64})
    def test_remote_daemon_mismatch_precedes_mutation(self):
        commands=[];events=[]
        m=self.manager(lambda args,**kw:(commands.append(args) or response('foreign')),lambda *x:events.append(x))
        with self.assertRaisesRegex(RuntimeError,'kernel identity'):m.prepare()
        self.assertEqual(len(commands),1);self.assertEqual(events,[])
    def test_durable_intent_precedes_ambiguous_mkdir_failure(self):
        events=[]
        def remote(args,**kw):
            if args[:3]==['sudo','docker','info']:return response('daemon')
            if args[0]=='mkdir':
                self.assertEqual(events[-1][0],'topology-remote-intent');self.assertTrue(events[-1][1]['creationAttempted']);raise TimeoutError('ambiguous')
            return response()
        m=self.manager(remote,lambda *x:events.append(x))
        with self.assertRaises(TimeoutError):m.prepare()
        self.assertTrue(m.remote_attempted)
    def test_expired_parent_deadline_never_dispatches(self):
        calls=[];m=self.manager(lambda *a,**kw:calls.append(a),lambda *a:None,lambda:0)
        with self.assertRaises(TimeoutError):m.prepare()
        self.assertEqual(calls,[])
    def test_runner_cleanup_failure_retains_profiles(self):
        calls=[];m=self.manager(lambda *a,**kw:calls.append(a),lambda *a:None)
        m.remote_attempted=True;m.attempted['http']=True
        m.docker=lambda args,**kw:response('wrong daemon')
        with self.assertRaises(ExceptionGroup):m.cleanup()
        self.assertEqual(calls,[]);self.assertTrue(m.remote_attempted)
    def test_interrupted_prepare_preserves_intent_without_blind_remote_delete(self):
        for fail_at in ['owner','cli.apparmor','http.apparmor','load']:
            with self.subTest(stage=fail_at):
                files={};events=[];commands=[]
                def remote(args,**kw):
                    commands.append(args)
                    if args[:3]==['sudo','docker','info']:return response('daemon')
                    if args[0]=='tee':
                        name=args[-1].split('/')[-1]
                        if name==fail_at:raise TimeoutError('interrupted write')
                        files[name]=kw['input'];return response()
                    if args[0]=='readlink':return response(args[-1])
                    if args[0]=='stat':return response(('directory|700' if args[-1]==plan()['directory'] else 'regular file|600')+'|501|1|123|1|1|1')
                    if args[0]=='cat':return response(files.get(args[-1].split('/')[-1],''))
                    if args[:2]==['sudo','apparmor_parser'] and fail_at=='load':raise TimeoutError('ambiguous load')
                    return response()
                m=self.manager(remote,lambda *x:events.append(x))
                with self.assertRaises((TimeoutError,RuntimeError)):m.prepare()
                self.assertTrue(m.remote_attempted);self.assertEqual(events[0][0],'topology-remote-intent')
                if fail_at!='load':
                    with self.assertRaises(RuntimeError):m.cleanup()
                    self.assertFalse(any(x[0] in ('rm','rmdir') for x in commands))
    def test_remote_symlink_wrong_uid_and_replaced_file_are_denied(self):
        for failure in ['symlink','uid','replacement']:
            with self.subTest(failure=failure):
                reads=0
                def remote(args,**kw):
                    nonlocal reads
                    file=args[-1]
                    if args[0]=='readlink':return response('/other' if failure=='symlink' else file)
                    if args[0]=='stat':
                        if file.endswith('/owner'):reads+=1
                        kind='directory|700' if file==plan()['directory'] else 'regular file|600'
                        uid='0' if failure=='uid' else '501'
                        inode='999' if failure=='replacement' and reads>1 else '123'
                        return response(kind+'|'+uid+'|1|'+inode+'|1|1|1')
                    if args[0]=='cat':return response(NONCE+'\n')
                    raise AssertionError('Unexpected command')
                m=self.manager(remote,lambda *x:None)
                with self.assertRaises(RuntimeError):m.verify_remote()
    def test_envfile_outside_owned_root_or_resolved_link_denied_before_commands(self):
        from pathlib import Path
        from unittest.mock import patch
        calls=[];m=self.manager(lambda *a,**k:calls.append(a),lambda *a:None)
        with self.assertRaisesRegex(RuntimeError,'owned env'):m.launch('http','/tmp/foreign.env')
        with patch.object(Path,'resolve',return_value=Path('/tmp/foreign.env')):
            with self.assertRaisesRegex(RuntimeError,'owned env'):m.launch('http',m.evidence_root/'http.env')
        self.assertEqual(calls,[])
    def test_layout_denies_host_mount_external_port_and_privilege(self):
        import copy
        spec=plan()['resources']['http'];row={'Config':{'User':'10001:10001','Entrypoint':['node'],'Cmd':['/app/owned-http/service.js']},'HostConfig':{'Memory':536870912,'NanoCpus':1000000000,'PidsLimit':128,'NetworkMode':'default','PidMode':'','IpcMode':'private','Tmpfs':{'/sandbox':'rw,uid=10001,gid=10001,mode=0700'},'Privileged':False,'CapAdd':None,'SecurityOpt':['seccomp=unconfined','apparmor='+spec['profile']]},'Mounts':[],'NetworkSettings':{'Ports':{'8091/tcp':[{'HostIp':'127.0.0.1','HostPort':'45678'}]}}}
        self.assertEqual(validate_layout(row,spec),{8091:45678})
        for pinned in ['sha256:c17a5db3bacea934909a58d32a5bdefac88956e58603cefffc239c7e88c672c6','sha256:09c27624ef733fbec300b07edee2ac8c0972dbcaf404b8849fbdeb1babb3664d']:
            current_spec={**spec,'image':pinned};exposed=copy.deepcopy(row);exposed['Image']=pinned;exposed['Config']['ExposedPorts']={'8090/tcp':{},'8091/tcp':{}};exposed['NetworkSettings']['Ports']['8090/tcp']=None
            self.assertEqual(validate_layout(exposed,current_spec),{8091:45678})
            for mutate in [lambda x:x['NetworkSettings']['Ports'].update({'8090/tcp':[]}),lambda x:x['NetworkSettings']['Ports'].update({'8090/tcp':[{'HostIp':'127.0.0.1','HostPort':'40000'}]}),lambda x:x['NetworkSettings']['Ports'].update({'9999/tcp':None}),lambda x:x.update(Image=IMAGE),lambda x:x['Config'].update(ExposedPorts={}),lambda x:x['HostConfig'].update(PortBindings={'8090/tcp':[{'HostIp':'0.0.0.0','HostPort':'40000'}]})]:
                bad=copy.deepcopy(exposed);mutate(bad)
                with self.assertRaises(RuntimeError):validate_layout(bad,current_spec)

        mail_spec=plan()['resources']['mail'];mail_spec['image']='sha256:98b916bd3c8d61f7633a52d3ea2f58d00620cb01ca57ab59edde68c347a95365'
        mail=copy.deepcopy(row);mail['Image']=mail_spec['image'];mail['Config']['ExposedPorts']={'1025/tcp':{},'1110/tcp':{},'8025/tcp':{}};mail['HostConfig'].update(ReadonlyRootfs=True,Tmpfs={'/tmp':'rw,noexec,nosuid,size=16777216'},SecurityOpt=['no-new-privileges']);mail['NetworkSettings']['Ports']={'1025/tcp':[{'HostIp':'127.0.0.1','HostPort':'41000'}],'8025/tcp':[{'HostIp':'127.0.0.1','HostPort':'41001'}],'1110/tcp':None}
        self.assertEqual(validate_layout(mail,mail_spec),{1025:41000,8025:41001})
        for value in ([],[{'HostIp':'127.0.0.1','HostPort':'41002'}]):
            bad=copy.deepcopy(mail);bad['NetworkSettings']['Ports']['1110/tcp']=value
            with self.assertRaises(RuntimeError):validate_layout(bad,mail_spec)
        for mutate in [lambda x:x['Mounts'].append({'Type':'bind'}),lambda x:x['HostConfig'].update(Privileged=True),lambda x:x['HostConfig'].update(Memory=0),lambda x:x['HostConfig'].update(NetworkMode='host'),lambda x:x['Config'].update(User='0'),lambda x:x['Config'].update(Cmd=['unexpected']),lambda x:x['NetworkSettings']['Ports']['8091/tcp'][0].update(HostIp='0.0.0.0')]:
            changed=copy.deepcopy(row);mutate(changed)
            with self.assertRaises(RuntimeError):validate_layout(changed,spec)
if __name__=='__main__':unittest.main()
