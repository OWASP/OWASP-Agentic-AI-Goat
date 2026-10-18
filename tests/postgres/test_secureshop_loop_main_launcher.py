import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

PATH=Path(__file__).with_name('run-secureshop-loop-assessment-isolated.py')
spec=importlib.util.spec_from_file_location('loop_main_launcher',PATH)
module=importlib.util.module_from_spec(spec)
with patch('subprocess.run',side_effect=AssertionError('No resource')),patch('subprocess.Popen',side_effect=AssertionError('No resource')),patch('tempfile.mkdtemp',side_effect=AssertionError('No allocation')):
    spec.loader.exec_module(module)

class Controls(unittest.TestCase):
    def test_registry_role_chat_wire_metadata_is_bounded_separately_from_actor(self):
        self.assertEqual(module.REGISTRY_ROLE_CHAT_ADMISSION,
            {'model':'llama3.1:8b','digest':'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e',
             'chat':53,'tags':359,'external':412,'generate':0})
        for tags in (2,359):
            calls=19
            counts=dict(tags=tags,metadata=tags,chat=calls,external=tags+calls,
                incoming=tags+calls-1,generate=0,version=0)
            self.assertEqual(module.registry_role_chat_wire_counts(counts,calls),counts)
            for patch in ({'tags':1},{'tags':360},{'metadata':tags-1},
                          {'external':tags+calls-1},{'incoming':tags+calls},
                          {'chat':calls+1},{'generate':1},{'version':1}):
                with self.assertRaises(RuntimeError):
                    module.registry_role_chat_wire_counts({**counts,**patch},calls)
        with self.assertRaises(RuntimeError):module.registry_role_chat_wire_counts(None,19)
        with self.assertRaises(RuntimeError):module.registry_role_chat_wire_counts(counts,54)

    def test_registry_role_chat_receipt_and_tap_are_closed(self):
        import copy
        flags=dict.fromkeys(module.REGISTRY_ROLE_CHAT_FLAGS,True)
        proof=dict(status='passed',scope=module.REGISTRY_ROLE_CHAT_SCOPE,
            roleTurns=9,roleActorCalls=18,registeredTurns=2,registeredActorCalls=3,
            modelCalls=21,judgeCalls=0,genuineCredit=0,errors=[],**flags)
        result=dict(modelCalls=21,rendered=dict(registryRoleChat=proof))
        self.assertEqual(module.registry_role_chat_receipt(result),proof)
        for key,bad in [('roleTurns',8),('roleActorCalls',46),('registeredTurns',1),
                        ('registeredActorCalls',9),('modelCalls',20),('judgeCalls',1),
                        ('genuineCredit',1),('errors',['error']),('namedInspection',False)]:
            changed=copy.deepcopy(result);changed['rendered']['registryRoleChat'][key]=bad
            with self.assertRaises(RuntimeError):module.registry_role_chat_receipt(changed)
        with self.assertRaises(RuntimeError):module.registry_role_chat_receipt({**result,'modelCalls':20})
        with self.assertRaises(RuntimeError):module.registry_role_chat_receipt({**result,'rendered':dict(registryRoleChat={**proof,'extra':True})})
        tap=('TAP version 13\n'
            'ok 1 - historical loop cohort selector is closed and exact\n'
            'ok 2 - actual SecureShop review loop records attack outcome, canonical credit and provenance negatives # SKIP\n'
            'ok 3 - main owned registry control plane uses real isolated SDK transport and canonical authority # SKIP\n'
            f'ok 4 - {module.REGISTRY_ROLE_CHAT_TAP}\n'
            '1..4\n# tests 4\n# pass 2\n# fail 0\n# cancelled 0\n# skipped 2\n')
        self.assertTrue(module.registry_role_chat_tap(tap))
        for bad in (tap.replace(module.REGISTRY_ROLE_CHAT_TAP,'other'),
                    tap+'ok 5 - extra\n',
                    tap.replace('ok 1 - historical','ok 1 - other'),
                    tap.replace('ok 2 - actual','ok 2 - unrecognized'),
                    tap.replace('ok 3 - main','ok 3 - unrecognized'),
                    tap.replace(f'ok 4 - {module.REGISTRY_ROLE_CHAT_TAP}',
                        f'ok 4 - {module.REGISTRY_ROLE_CHAT_TAP} # SKIP'),
                    tap.replace('# pass 2','# pass 1'),
                    tap.replace('# skipped 2','# skipped 3'),
                    tap.replace('# fail 0','# fail 1')):
            with self.assertRaises(RuntimeError):module.registry_role_chat_tap(bad)

    def test_actual_chat_receipt_strict_counts_and_proof(self):
        import copy
        chat=dict(actualModelProof=True,sdkReceiptBound=True,rawDecisionBound=True,renderedResponse=True,modelCalls=2,genuineCredit=0)
        value=dict(modelCalls=2,rendered=dict(actualChat=chat))
        self.assertEqual(module.registry_actual_chat_receipt(value),chat)
        for key,bad in [('modelCalls',True),('modelCalls',5),('genuineCredit',1),('sdkReceiptBound',1),('rawDecisionBound',False)]:
            changed=copy.deepcopy(value);changed['rendered']['actualChat'][key]=bad
            with self.assertRaises(RuntimeError):module.registry_actual_chat_receipt(changed)

    def test_upgrade_uses_extra_database_and_canonical_existing_roles(self):
        sql=module.upgrade_database_sql()
        self.assertNotIn('CREATE ROLE',sql)
        self.assertIn('CREATE DATABASE dvaia_test_secureshop_loop_agents_upgrade OWNER dvaia_secureshop_agents_migration',sql)
        self.assertIn('REVOKE CONNECT',sql)
        proof=dict(status='passed',version=1,legacyRows=4,newMappedRows=1,modelCalls=0,remoteCalls=0,genuineCredit=0,exactRowsPreserved=True,wrapperReplayPreserved=True,grantsVerified=True,mappedEndpointDenied=True,secondRunNoop=True)
        module.registry_upgrade_receipt(proof)
        for key,bad in [('legacyRows',True),('remoteCalls',1),('grantsVerified',1),('secondRunNoop',False)]:
            with self.assertRaises(ValueError):module.registry_upgrade_receipt({**proof,key:bad})

    def test_import_inert_and_duplicates(self):
        with self.assertRaises(ValueError):module.parse_main(['--main-workspace','x','--main-workspace','y'])
    def test_plan_does_not_allocate_or_import_helpers(self):
        args=type('Args',(),{'plan':True,'profile':'loop'})()
        with patch.object(module,'parse_main',return_value=args),patch.object(module,'validate_main',return_value=(Path('/controlled'),{})),patch.object(module.importlib.util,'spec_from_file_location',side_effect=AssertionError('No dynamic import')),patch.object(module.tempfile,'mkdtemp',side_effect=AssertionError('No allocation')):
            self.assertEqual(module.main_current([]),0)
    def test_aggregate_log_includes_multiple_files(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'a.log').touch();(root/'b.tap').touch()
            with (root/'a.log').open('wb') as f:f.truncate(33*1024**2)
            with (root/'b.tap').open('wb') as f:f.truncate(33*1024**2)
            with self.assertRaises(RuntimeError):module.check_logs(root)
    def test_child_then_cleanup_log_growth_is_denied(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);p=root/'result.tap';p.write_text('pass')
            self.assertLess(module.check_logs(root),100)
            with p.open('wb') as f:f.truncate(65*1024**2)
            with self.assertRaises(RuntimeError):module.check_logs(root)
    def test_readiness_and_admin_commands_require_final_owned_tcp(self):
        for argv in [module.owned_ready_args('owned'),module.owned_psql_args('owned'),module.owned_psql_args('owned',True)]:
            self.assertEqual(argv[argv.index('-h')+1],'127.0.0.1')
            self.assertEqual(argv[argv.index('-p')+1],'5432')
        self.assertIn('VERBOSITY=sqlstate',module.owned_psql_args('owned'))
    def test_failure_projection_retains_stage_and_state_without_raw_data(self):
        response=type('Response',(),{'returncode':1,'stdout':'private-row','stderr':'ERROR:  25001\npassword=private-secret'})()
        state={'stage':'provision-agents'}
        with self.assertRaisesRegex(RuntimeError,'STORE_PROVISION_FAILED'):
            module.checked_command(response,'STORE_PROVISION_FAILED',state)
        self.assertEqual(state['lastCommand']['sqlStates'],['25001'])
        self.assertEqual(state['stage'],'provision-agents')
        self.assertNotIn('private',module.json.dumps(state))
    def test_running_python_alias_resolves_to_pinned_binary(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);binary=root/'cellar-python';binary.write_bytes(b'controlled executable')
            alias=root/'opt-python';alias.symlink_to(binary)
            with patch.object(module.sys,'executable',str(alias)):
                self.assertEqual(module.validate_running_python(module.digest(binary)),binary.resolve())
                with self.assertRaises(RuntimeError):module.validate_running_python('0'*64)
            with patch.object(module.sys,'executable','relative-python'):
                with self.assertRaises(RuntimeError):module.validate_running_python(module.digest(binary))
    def test_ownership_publication_atomic_private(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'ownership.json';module.publish(p,{'nativeStarted':False});module.publish(p,{'nativeStarted':True,'nativePid':42})
            self.assertEqual(module.json.loads(p.read_text())['nativePid'],42)
            self.assertEqual(p.stat().st_mode&0o777,0o600)
            self.assertEqual([x.name for x in Path(d).iterdir()],['ownership.json'])
if __name__=='__main__':unittest.main()

class RegistryControls(unittest.TestCase):
    def test_registry_pin_contract_closed(self):
        good={'imageId':'sha256:'+'a'*64,'runtimeDigest':'b'*64,'apparmorProfile':'dvaia-owned-mcp-registry-'+'c'*12}
        self.assertEqual(module.validate_registry_config(good),good)
        for patching in [{'imageId':'latest'},{'apparmorProfile':'unconfined'},{'runtimeDigest':'x'},{'url':'http://foreign'}]:
            with self.assertRaises((ValueError,TypeError)):module.validate_registry_config({**good,**patching})
    def test_registry_actual_inspect_layout_denies_host_network_and_public_port(self):
        import copy
        image='sha256:'+'a'*64;labels={'dvaia.owner':'owned'}
        row={'Image':image,'Config':{'Labels':labels,'User':'10001:10001'},'HostConfig':{'NetworkMode':'owned-net','ReadonlyRootfs':True,'CapDrop':['ALL'],'Memory':536870912,'NanoCpus':1000000000,'PidsLimit':128,'Tmpfs':{'/tmp':'rw,nosuid,nodev,noexec,size=16m'}},'Mounts':[],'NetworkSettings':{'Networks':{'owned-net':{}},'Ports':{'8094/tcp':[{'HostIp':'127.0.0.1','HostPort':'65432'}]}}}
        self.assertEqual(module.registry_layout(row,'owned-net',labels,image),65432)
        tmp=copy.deepcopy(row);tmp['Mounts']=[{'Type':'tmpfs','Destination':'/tmp'}];self.assertEqual(module.registry_layout(tmp,'owned-net',labels,image),65432)
        for mutate in [lambda r:r['HostConfig'].update(NetworkMode='host'),lambda r:r['NetworkSettings']['Ports']['8094/tcp'][0].update(HostIp='0.0.0.0'),lambda r:r['Config'].update(User='0'),lambda r:r['Mounts'].append({'Source':'/private'}),lambda r:r['NetworkSettings']['Networks'].update(other={})]:
            bad=copy.deepcopy(row);mutate(bad)
            with self.assertRaises(ValueError):module.registry_layout(bad,'owned-net',labels,image)

    def test_registry_control_bridge_exact_endpoints(self):
        good={'Id':'a'*64,'Name':'owned-net','Driver':'bridge','Internal':False,'EnableIPv6':False,'Labels':{'dvaia.owner':'owned'},'Containers':{}}
        self.assertEqual(module.registry_network_layout(good,'owned-net','owned'),'a'*64)
        live={**good,'Containers':{'container':{}}}
        self.assertEqual(module.registry_network_layout(live,'owned-net','owned','container'),'a'*64)
        for patching in [{'Internal':True},{'Driver':'host'},{'EnableIPv6':True},{'Containers':{'foreign':{}}},{'Name':'foreign'}]:
            with self.assertRaises(ValueError):module.registry_network_layout({**good,**patching},'owned-net','owned')

    def test_registry_launch_labels_satisfy_actual_inspection_and_cleanup(self):
        import ast,json,types
        tree=ast.parse(PATH.read_text())
        calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='command' and n.args and isinstance(n.args[0],ast.List) and any(isinstance(v,ast.Name) and v.id=='registry' for v in n.args[0].elts) and any(isinstance(v,ast.Constant) and v.value=='--detach' for v in n.args[0].elts)]
        self.assertEqual(len(calls),1)
        labels={'dvaia.owner':'controlled-owner','dvaia.cohort':module.COHORT};image='sha256:'+'a'*64
        argv=eval(compile(ast.Expression(calls[0].args[0]),str(PATH),'eval'),{'owner':'controlled-owner','labels':labels,'registry':'controlled-registry','registry_network':'controlled-net','registry_env':{},'config':{'imageId':image,'apparmorProfile':'controlled-profile'}})
        emitted=dict(argv[i+1].split('=',1) for i,v in enumerate(argv) if v=='--label')
        spec=importlib.util.spec_from_file_location('actual_docker_ownership',PATH.with_name('sql_nosql_docker_ownership.py'));ownership=importlib.util.module_from_spec(spec);spec.loader.exec_module(ownership)
        row={'Id':'b'*64,'Name':'/controlled-registry','Image':image,'Config':{'Labels':emitted}};removed=[]
        def command(args):
            if args[0]=='info':return types.SimpleNamespace(returncode=0,stdout='controlled-daemon',stderr='')
            if args[0]=='rm':removed.append(args[-1]);return types.SimpleNamespace(returncode=0,stdout='',stderr='')
            return types.SimpleNamespace(returncode=1 if removed else 0,stdout='' if removed else json.dumps([row]),stderr='Error: No such container: controlled-registry' if removed else '')
        self.assertEqual(ownership.inspect_owned(command,name='controlled-registry',labels=labels,image=image)['Id'],row['Id'])
        result=ownership.cleanup_owned(command,daemon_id='controlled-daemon',name='controlled-registry',labels=labels,image=image,captured_id=row['Id'])
        self.assertEqual(result,{'status':'removed_absence_verified','containerId':row['Id']});self.assertEqual(removed,[row['Id']])

    def test_rendered_receipt_preserves_closed_bounds_and_actual_retirement(self):
        good={k:True for k in ['registration','tools','history','imported','retired','replayReadback','resetView','browserRetired']};good.update(browserRequests=400,directApiRequests=0)
        self.assertEqual(module.registry_rendered_receipt(good),good)
        for change in [{'browserRequests':401},{'browserRequests':True},{'directApiRequests':41},{'directApiRequests':False},{'browserRetired':False},{'resetView':1}]:
            with self.assertRaises(ValueError):module.registry_rendered_receipt({**good,**change})

    def test_only_exact_owned_registry_singleton_links_are_opaque(self):
        import os
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();runtime=root/'runtime';runtime.mkdir(mode=0o700);profile=runtime/'registry-profile';profile.mkdir(mode=0o700)
            link=profile/'SingletonSocket';link.symlink_to('/nonexistent/socket')
            self.assertEqual(module.check_logs(root,allow_registry_profile=True),0)
            (profile/'RunningChromeVersion').symlink_to('/not-followed/version')
            self.assertEqual(module.check_logs(root,allow_registry_profile=True),0)
            with self.assertRaises(RuntimeError):module.check_logs(root)
            outside=root/'outside';outside.symlink_to('/nonexistent/socket')
            with self.assertRaises(RuntimeError):module.check_logs(root,allow_registry_profile=True)
            outside.unlink();extra=profile/'other';extra.symlink_to('/nonexistent/other')
            with self.assertRaises(RuntimeError):module.check_logs(root,allow_registry_profile=True)

    def test_registry_profile_cleanup_requires_real_loop_group_absence(self):
        import os,json
        spec=importlib.util.spec_from_file_location('registry_browser_ownership',PATH.with_name('browser_process_ownership.py'));ownership=importlib.util.module_from_spec(spec);spec.loader.exec_module(ownership)
        with tempfile.TemporaryDirectory() as d:
            runtime=Path(d).resolve();runtime.chmod(0o700);profile=runtime/'registry-profile';profile.mkdir(mode=0o700);(profile/'SingletonCookie').symlink_to('/not-followed')
            journal={'pid':202,'pgid':101,'sessionId':101,'uid':os.getuid(),'qualificationPid':101,'qualificationPgid':101,'qualificationSessionId':101,'workerPid':101,'profile':str(profile),'executableSha256':'a'*64}
            p=runtime/'registry-process.json';p.write_text(json.dumps(journal));p.chmod(0o600)
            child=[{'name':'loop','pid':101,'pgid':101,'sessionId':101,'status':'cleanup_verified'}]
            with self.assertRaises(RuntimeError):module.cleanup_registry_browser(runtime,child,'a'*64,ownership,rows=[(202,101,101,os.getuid())])
            self.assertTrue(profile.exists())
            with self.assertRaises(RuntimeError):module.cleanup_registry_browser(runtime,child,'b'*64,ownership,rows=[])
            with self.assertRaises(RuntimeError):module.cleanup_registry_browser(runtime,child,'a'*64,ownership,successful=True,rows=[])
            result=module.cleanup_registry_browser(runtime,child,'a'*64,ownership,rows=[])
            self.assertTrue(result['pidGroupSessionAbsent']);self.assertTrue(result['profileAbsent']);self.assertFalse(result['gracefulCloseClaimed']);self.assertFalse(profile.exists())

    def test_link_failure_reports_only_safe_relative_path_not_target(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();p=root/'unexpected-link';p.symlink_to('/private/secret-token')
            with self.assertRaisesRegex(RuntimeError,'^OWNED_EVIDENCE_LINK$') as seen:module.check_logs(root,allow_registry_profile=True)
            self.assertEqual(seen.exception.evidence_path,'unexpected-link');self.assertNotIn('secret',str(seen.exception.__dict__))
            p.unlink();(root/'unsafe name').symlink_to('/private/secret-token')
            with self.assertRaises(RuntimeError) as seen:module.check_logs(root,allow_registry_profile=True)
            self.assertEqual(seen.exception.evidence_path,'[nonportable-relative-path]')

class ReplacementControls(unittest.TestCase):
    def test_replacement_receipt_keeps_exact_two_cases_and_no_model(self):
        proof=dict(status='passed',cases=2,modelCalls=0,genuineCredit=0,maintenanceExclusion=True,healthyReplacement=True,reuseVerified=True,rollbackVerified=True,privatePublicationPreserved=True,sharedProfileUnchanged=True)
        module.registry_replacement_receipt(proof)
        for key,bad in [('cases',True),('cases',3),('modelCalls',1),('rollbackVerified',1),('maintenanceExclusion',False)]:
            with self.assertRaises(ValueError):module.registry_replacement_receipt({**proof,key:bad})
    def test_replacement_cleanup_exact_ids_never_profile_or_foreign(self):
        import json,os
        from types import SimpleNamespace
        identity='a'*64;namespace='b'*12;workspace='c'*12;name='dvaia-owned-mcp-registry-'+workspace+'-qualification-'+namespace
        config={'previousBuild':{'imageId':'sha256:'+'1'*64},'nextBuild':{'imageId':'sha256:'+'2'*64}}
        with tempfile.TemporaryDirectory() as tmp:
            evidence=Path(tmp);journal=evidence/'replacement-resources.json';journal.write_text(json.dumps([dict(kind='container',id=identity,name=name,namespace=namespace,workspace=workspace)]));journal.chmod(0o600)
            present=True;calls=[]
            def command(argv):
                nonlocal present
                calls.append(argv)
                if argv[:2]==['container','inspect']:
                    if not present:return SimpleNamespace(returncode=1,stdout='',stderr='No such container')
                    return SimpleNamespace(returncode=0,stderr='',stdout=json.dumps([{'Id':identity,'Name':'/'+name+'-rollback-any','Image':config['previousBuild']['imageId'],'Config':{'Labels':{'dvaia.registry.namespace':namespace}},'State':{'Running':False}}]))
                if argv==['rm',identity]:present=False;return SimpleNamespace(returncode=0,stdout='',stderr='')
                raise AssertionError(argv)
            self.assertTrue(module.cleanup_replacement_resources(command,evidence,config,Path.cwd())['absent'])
            self.assertIn(['rm',identity],calls)
            present=True;config['previousBuild']['imageId']='sha256:'+'3'*64
            # Foreign namespace must fail before any removal.
            data=json.loads(journal.read_text());data[0]['namespace']='d'*12;journal.write_text(json.dumps(data))
            with self.assertRaises(RuntimeError):module.cleanup_replacement_resources(command,evidence,config,Path.cwd())
    def test_rollback_duplicate_name_checked_after_both_exact_ids(self):
        import json
        from types import SimpleNamespace
        original='a'*64;candidate='b'*64;namespace='c'*12;workspace='d'*12;name='dvaia-owned-mcp-registry-'+workspace+'-qualification-'+namespace
        config={'previousBuild':{'imageId':'sha256:'+'1'*64},'nextBuild':{'imageId':'sha256:'+'2'*64}}
        with tempfile.TemporaryDirectory() as tmp:
            evidence=Path(tmp);p=evidence/'replacement-resources.json';p.write_text(json.dumps([dict(kind='container',id=i,name=name,namespace=namespace,workspace=workspace) for i in [original,candidate]]));p.chmod(0o600)
            present=True;removed=[]
            def command(argv):
                nonlocal present
                if argv[:2]==['container','inspect']:
                    if argv[2] in [original,name] and present:return SimpleNamespace(returncode=0,stderr='',stdout=json.dumps([{'Id':original,'Name':'/'+name,'Image':config['previousBuild']['imageId'],'Config':{'Labels':{'dvaia.registry.namespace':namespace}},'State':{'Running':False}}]))
                    return SimpleNamespace(returncode=1,stderr='No such container',stdout='')
                if argv==['rm',original]:present=False;removed.append(original);return SimpleNamespace(returncode=0,stdout='',stderr='')
                raise AssertionError(argv)
            self.assertTrue(module.cleanup_replacement_resources(command,evidence,config,Path.cwd())['absent'])
            self.assertEqual(removed,[original])
