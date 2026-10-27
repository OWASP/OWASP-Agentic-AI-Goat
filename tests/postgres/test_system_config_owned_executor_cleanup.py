"""Resource-free checks of the actual executor cleanup command sequence."""
import tempfile
import hashlib
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from system_config_owned_executor import OwnedSystemExecutor
import system_config_owned_executor as module
import system_diagnostic_owned_executor as identity_contract


class OriginalSystemAdmissionTests(unittest.TestCase):
    def test_recipe_export_is_byte_identical_pure_and_not_execution_authority(self):
        with patch.object(module.subprocess,'Popen',side_effect=AssertionError('No spawn')), \
             patch.object(module.subprocess,'run',side_effect=AssertionError('No process')), \
             patch.object(Path,'read_bytes',side_effect=AssertionError('No read')), \
             patch.object(Path,'write_text',side_effect=AssertionError('No write')):
            recipe=module.original_system_build_recipe()
        self.assertEqual(recipe['dockerfileSha256'], '7e5f852b304d69bd76b446cb4edcf8da4760a9d9064fd7c1bc8fbf9a4209cc5b')
        self.assertEqual(recipe, {'version':1,'target':'v24-system','base':module.BASE,
            'platform':'linux/arm64','sourceRoot':'sidecars/sandbox-runner/owned-system',
            'dockerfile':module.original_system_dockerfile(),'dockerfileSha256':hashlib.sha256(module.original_system_dockerfile().encode()).hexdigest(),
            'packages':['gcc','libc6-dev','bubblewrap'],'user':'10001:10001',
            'entrypoint':['/usr/local/bin/node','/qualification/owned-system/http-listener.js']})
        recipe['packages'].append('not-an-original-package')
        self.assertEqual(module.original_system_build_recipe()['packages'],['gcc','libc6-dev','bubblewrap'])
        import ast
        tree=ast.parse(Path(module.__file__).read_text())
        cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='OwnedSystemExecutor')
        start=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='start')
        assignment=next(n for n in start.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='dockerfile' for t in n.targets))
        self.assertEqual(ast.unparse(assignment.value),'original_system_dockerfile()')
        with self.assertRaisesRegex(RuntimeError,'V24_PRIVATE_RUNTIME_NOT_ADMITTED'):
            module.require_private_system_runtime_admission()

    def test_original_identity_reuses_reviewed_contract_without_changing_base(self):
        self.assertIs(module.admit_original_base_identity, identity_contract.admit_original_base_identity)
        self.assertEqual(module.BASE, 'sha256:3a771f83944bb763050c23c0225c260638c4b7899e7a72485ef75e5e570499e5')
        self.assertEqual(len({module.BASE,module.ARM64_MANIFEST,module.ARM64_CONFIG}),3)
        raw=module.BASE_AUDIT_PATH.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),module.BASE_AUDIT_SHA256)
        for kind,value in [('config',module.ARM64_CONFIG),('manifest',module.ARM64_MANIFEST)]:
            with self.subTest(kind=kind):
                result=module.admit_original_base_identity({'Id':value,'Architecture':'arm64','Os':'linux'},raw,identity_kind=kind)
                self.assertEqual(result['indexDigest'],module.BASE)
                self.assertEqual(result['inspectedId'],value)
                self.assertFalse(result['rawOciChainReverified'])
                self.assertFalse(result['runtimeQualified'])
                self.assertFalse(result['executionApproved'])

    def test_index_swaps_platform_and_audit_mutations_are_not_identity_authority(self):
        raw=module.BASE_AUDIT_PATH.read_bytes()
        for value in [module.BASE,module.ARM64_MANIFEST,module.RESTART_BASE,'node:26.9.0',None,True]:
            with self.subTest(value=value),self.assertRaisesRegex(ValueError,'V24_BASE_IDENTITY'):
                module.admit_original_base_identity({'Id':value,'Architecture':'arm64','Os':'linux'},raw,identity_kind='config')
        info={'Id':module.ARM64_CONFIG,'Architecture':'arm64','Os':'linux'}
        for change in [{'Architecture':'amd64'},{'Os':'windows'},{'Variant':'v7'}]:
            with self.subTest(change=change),self.assertRaisesRegex(ValueError,'V24_BASE_IDENTITY'):
                module.admit_original_base_identity({**info,**change},raw,identity_kind='config')
        for kind in ['auto','index',None,True]:
            with self.subTest(kind=kind),self.assertRaisesRegex(ValueError,'V24_BASE_IDENTITY_KIND'):
                module.admit_original_base_identity(info,raw,identity_kind=kind)
        for altered in [raw+b' ',raw.decode(),b'',b'x'*8193]:
            with self.subTest(kind=type(altered).__name__),self.assertRaisesRegex(ValueError,'V24_BASE_AUDIT_PIN'):
                module.admit_original_base_identity(info,altered,identity_kind='config')

    def test_actual_whole_start_is_closed_before_any_inspection_file_or_process_effect(self):
        tasks=Path(__file__).resolve().parents[2]/'tasks'
        with tempfile.TemporaryDirectory(dir=tasks) as directory:
            root=Path(directory)
            executor=OwnedSystemExecutor(root,root,['never-docker'],
                {'V24_PRIVATE_RUNTIME_NOT_ADMITTED':'false','V24_PRIVATE_RUNTIME_ADMITTED':'true'},
                'controlled-owner',lambda: self.fail('No state persistence before admission'))
            before=dict(executor.state)
            with patch.object(executor,'inspect',side_effect=AssertionError('No image inspection')), \
                 patch.object(executor,'run',side_effect=AssertionError('No Docker commands')), \
                 patch.object(module.subprocess,'Popen',side_effect=AssertionError('No process spawn')), \
                 patch.object(module.subprocess,'run',side_effect=AssertionError('No subprocess')), \
                 patch.object(Path,'read_bytes',side_effect=AssertionError('No audit read')), \
                 patch.object(Path,'mkdir',side_effect=AssertionError('No directories')), \
                 patch.object(Path,'write_text',side_effect=AssertionError('No files')), \
                 patch.object(module.shutil,'copytree',side_effect=AssertionError('No source copies')):
                with self.assertRaisesRegex(RuntimeError,'^V24_PRIVATE_RUNTIME_NOT_ADMITTED$'):
                    executor.start()
            self.assertEqual(executor.state,before)
            self.assertIsNone(executor.build)
            self.assertEqual(list(root.iterdir()),[])

    def test_start_fences_first_and_uses_explicit_config_identity_not_index_equality(self):
        import ast
        tree=ast.parse(Path(module.__file__).read_text())
        cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='OwnedSystemExecutor')
        start=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='start')
        self.assertEqual(ast.unparse(start.body[0]),'require_private_system_runtime_admission()')
        calls=[n for n in ast.walk(start) if isinstance(n,ast.Call)
               and isinstance(n.func,ast.Name) and n.func.id=='admit_original_base_identity']
        self.assertEqual(len(calls),1)
        self.assertEqual(ast.unparse(calls[0]),"admit_original_base_identity(info, BASE_AUDIT_PATH.read_bytes(), identity_kind='config')")
        self.assertFalse(any(isinstance(n,ast.Compare) and ast.unparse(n)=="info['Id'] != BASE" for n in ast.walk(start)))


class ExecutorCleanupTests(unittest.TestCase):
    def fixture(self, root, *, foreign=False, removal_fails=False, retain_final=False):
        owner = 'controlled-owner'
        executor = OwnedSystemExecutor(root, root, ['never-docker'], {}, owner, lambda: None)
        final_id, parent_id = 'sha256:' + 'a' * 64, 'sha256:' + 'b' * 64
        executor.state.update(creationAttempted=True, networkAttempted=True,
                              imageBuildAttempted=True, imageId=final_id)
        present = {'container': True, 'network': True, 'image': True}
        image_ids = {final_id, parent_id}
        commands = []

        def inspect(kind, name):
            self.assertEqual(name, {'container': executor.name, 'network': executor.network,
                                    'image': executor.tag}[kind])
            labels = {'dvaia.test.owner': 'foreign' if kind == 'image' and foreign else owner}
            return {'Config': {'Labels': labels}, 'Labels': labels,
                    'State': {'ExitCode': 0}, 'Containers': {}, 'Id': final_id}

        def absent(kind, name):
            self.assertEqual(name, {'container': executor.name, 'network': executor.network,
                                    'image': executor.tag}[kind])
            return not present[kind]

        def run(args, **kwargs):
            commands.append(args)
            if args == ['stop', '--time', '25', executor.name]:
                pass
            elif args == ['logs', '--tail', '100', executor.name]:
                return SimpleNamespace(stdout=executor.token, stderr='', returncode=0)
            elif args == ['rm', '-f', '-v', executor.name]:
                present['container'] = False
            elif args == ['image', 'rm', '--no-prune', executor.tag]:
                if removal_fails:
                    raise RuntimeError('Controlled removal failure')
                present['image'] = False
                if not retain_final:
                    image_ids.remove(final_id)
            elif args == ['network', 'rm', executor.network]:
                present['network'] = False
            elif args == ['image', 'ls', '--no-trunc', '--format', '{{.ID}}']:
                return SimpleNamespace(stdout='\n'.join(sorted(image_ids)), stderr='', returncode=0)
            else:
                raise AssertionError(f'Unexpected cleanup command: {args}')
            return SimpleNamespace(stdout='', stderr='', returncode=0)

        executor.inspect, executor.absent, executor.run = inspect, absent, run
        return executor, present, image_ids, commands, final_id, parent_id

    def test_owned_cleanup_retains_dependency_parent_but_removes_all_owned_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executor, present, images, commands, final_id, parent_id = self.fixture(root)
            # Any accidental subprocess, Docker, or process-roster call fails this test.
            with patch('system_config_owned_executor.subprocess.run', side_effect=AssertionError('No processes')):
                self.assertTrue(executor.close())
            self.assertEqual(present, {'container': False, 'network': False, 'image': False})
            self.assertEqual(images, {parent_id})
            self.assertNotIn(final_id, images)
            self.assertIn(['image', 'rm', '--no-prune', executor.tag], commands)
            self.assertEqual(executor.state['cleanup'], {
                'containerAbsent': True, 'networkAbsent': True, 'imageAbsent': True,
                'buildPgidAbsent': True, 'imageIdAbsent': True, 'listenerExitCode': 0, 'errors': [],
            })
            self.assertEqual((root / 'executor.log').read_text(), '[REDACTED]')

    def test_foreign_image_is_not_removed_or_reported_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            executor, _, images, commands, final_id, parent_id = self.fixture(Path(directory), foreign=True)
            self.assertFalse(executor.close())
            self.assertFalse(any(command[:2] == ['image', 'rm'] for command in commands))
            self.assertEqual(images, {final_id, parent_id})
            self.assertIn('image:RuntimeError', executor.state['cleanup']['errors'])

    def test_failed_image_removal_remains_cleanup_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            executor, _, _, _, _, _ = self.fixture(Path(directory), removal_fails=True)
            self.assertFalse(executor.close())
            self.assertFalse(executor.state['cleanup']['imageAbsent'])
            self.assertFalse(executor.state['cleanup']['imageIdAbsent'])
            self.assertIn('image:RuntimeError', executor.state['cleanup']['errors'])

    def test_untagging_without_final_image_removal_is_not_cleanup_success(self):
        with tempfile.TemporaryDirectory() as directory:
            executor, _, _, _, _, _ = self.fixture(Path(directory), retain_final=True)
            self.assertFalse(executor.close())
            self.assertTrue(executor.state['cleanup']['imageAbsent'])
            self.assertFalse(executor.state['cleanup']['imageIdAbsent'])
            self.assertIn('absence-not-confirmed', executor.state['cleanup']['errors'])


class OriginalSourceBuildContextTests(unittest.TestCase):
    def build_stage(self, *, change_source=False):
        import ast, hashlib
        import system_config_owned_executor as module
        tasks = Path(__file__).resolve().parents[2] / 'tasks'
        with tempfile.TemporaryDirectory(dir=tasks) as directory:
            root = Path(directory)
            workspace = root / 'workspace'
            source = workspace / 'sidecars/sandbox-runner/owned-system'
            source.mkdir(parents=True)
            original = source / 'http-listener.js'
            original.write_text('original owned System source')
            if not change_source:
                original.chmod(0o444)
            output = root / 'evidence'
            output.mkdir()
            executor = module.OwnedSystemExecutor(output, workspace, ['never-docker'], {},
                                                  'controlled-owner', lambda: None)
            tree = ast.parse(Path(module.__file__).read_text())
            cls = next(row for row in tree.body if isinstance(row, ast.ClassDef)
                       and row.name == 'OwnedSystemExecutor')
            start = next(row for row in cls.body if isinstance(row, ast.FunctionDef)
                         and row.name == 'start')
            first = next(i for i, row in enumerate(start.body) if isinstance(row, ast.Assign)
                         and any(isinstance(target, ast.Name) and target.id == 'context'
                                 for target in row.targets))
            last = next(i for i, row in enumerate(start.body) if isinstance(row, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == 'image'
                                for target in row.targets))
            stage = compile(ast.Module(body=start.body[first:last], type_ignores=[]),
                            '<actual original-source Docker build>', 'exec')
            calls = []
            before = hashlib.sha256(original.read_bytes()).hexdigest()

            def popen(argv, **kwargs):
                calls.append(argv)
                self.assertEqual(argv[-1], str(source))
                self.assertEqual(argv[argv.index('-f') + 1], str(output / 'executor-build/Dockerfile'))
                self.assertTrue(kwargs['start_new_session'])
                self.assertEqual(kwargs['env'], {})
                self.assertEqual({item.name for item in (output / 'executor-build').iterdir()},
                                 {'Dockerfile'})
                dockerfile = (output / 'executor-build/Dockerfile').read_text()
                self.assertIn('COPY . /qualification/owned-system', dockerfile)
                self.assertNotIn('COPY owned-system /qualification/owned-system', dockerfile)

                def wait(**_):
                    if change_source:
                        original.write_text('changed during Docker build')
                    return 0

                return SimpleNamespace(pid=111, wait=wait)

            scope = {'self': executor, 'BASE': module.BASE, 'hashlib': hashlib,
                     'original_system_dockerfile': module.original_system_dockerfile,
                     'restart_content_digest': module.restart_content_digest,
                     'subprocess': SimpleNamespace(Popen=popen, STDOUT=-2)}
            if change_source:
                with self.assertRaisesRegex(RuntimeError, 'source changed during build'):
                    exec(stage, scope)
            else:
                exec(stage, scope)
                self.assertEqual(hashlib.sha256(original.read_bytes()).hexdigest(), before)
                self.assertEqual(executor.state['sourceContext'], str(source))
                self.assertEqual(executor.state['sourceSha256'],
                                 module.restart_content_digest(source))
                self.assertEqual(executor.state['dockerfileSha256'],
                                 hashlib.sha256((output / 'executor-build/Dockerfile').read_bytes()).hexdigest())
            self.assertEqual(len(calls), 1)
            self.assertFalse((output / 'executor-build/owned-system').exists())

    def test_original_source_is_the_exact_docker_context_without_replica(self):
        self.build_stage()

    def test_source_change_during_build_fails_provenance_check(self):
        self.build_stage(change_source=True)


if __name__ == '__main__':
    unittest.main()


class UploadPreviewContextTests(unittest.TestCase):
    def test_closed_mode_and_measured_minimal_context(self):
        import ast,hashlib,json,shutil
        from system_config_owned_executor import OwnedSystemRestartExecutor
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);workspace=root/'workspace';package=workspace/'sidecars/sandbox-runner/owned-system';package.mkdir(parents=True)
            files={}
            for i in range(43):
                name=('upload-preview-runtime/' if i==0 else '')+str(i)+'.js'
                target=package/name;target.parent.mkdir(exist_ok=True);target.write_text('asset'+str(i));files[name]=hashlib.sha256(target.read_bytes()).hexdigest()
            (package/'local-package-manifest.json').write_text(json.dumps({'files':files}))
            (package/'unreviewed-secret').write_text('excluded')
            out=root/'run';out.mkdir();executor=OwnedSystemRestartExecutor(out,workspace,['never'],{},'owned',lambda:None,mode='upload-preview')
            self.assertEqual(executor.mode,'upload-preview');self.assertFalse(executor.state['volumeAttempted'])
            self.assertEqual(OwnedSystemRestartExecutor(out,workspace,['never'],{},'owned',lambda:None).mode,'restart')
            with self.assertRaises(ValueError):OwnedSystemRestartExecutor(out,workspace,['never'],{},'owned',lambda:None,mode='other')
            tree=ast.parse(Path(__file__).with_name('system_config_owned_executor.py').read_text())
            cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='OwnedSystemRestartExecutor')
            start=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='start')
            first=next(i for i,n in enumerate(start.body) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='context' for t in n.targets))
            last=next(i for i,n in enumerate(start.body) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='dockerfile' for t in n.targets))
            stage=compile(ast.Module(body=start.body[first:last],type_ignores=[]),'<actual V07 context>','exec')
            ns={'self':executor,'Path':Path,'json':json,'hashlib':hashlib,'shutil':shutil}
            exec(stage,ns)
            copied=out/'restart-executor-build/owned-system'
            self.assertEqual({p.relative_to(copied).as_posix() for p in copied.rglob('*') if p.is_file()},set(files))
            self.assertEqual(executor.state['packageSourceHashes'],files)
            shutil.rmtree(out/'restart-executor-build');(package/'1.js').write_text('changed')
            with self.assertRaisesRegex(RuntimeError,'asset changed'):exec(stage,ns)


class RestartCacheAdmissionTests(unittest.TestCase):
    def actual_admission(self, root, listed, prior=None):
        import ast,json,hashlib,os
        from system_config_owned_executor import OwnedSystemRestartExecutor,RESTART_BASE,RESTART_CACHE_PREFIX,validate_restart_content_cache
        source_digest='a'*64;cache_tag=RESTART_CACHE_PREFIX+source_digest[:32]
        executor=OwnedSystemRestartExecutor(root,root,['never'],{},'owned',lambda:None,mode='upload-preview')
        commands=[];inspections=[]
        executor.run=lambda args:commands.append(args) or SimpleNamespace(stdout='\n'.join(listed))
        image={'Id':'sha256:'+'b'*64,'Architecture':'arm64','Config':{'Labels':{'dvaia.cache.kind':'system-restart-content','dvaia.cache.source':source_digest,'dvaia.cache.base':RESTART_BASE}}}
        executor.inspect=lambda kind,name:inspections.append((kind,name)) or image
        path=root/'manifest.json'
        if prior is not None:path.write_text(json.dumps(prior))
        def manifest():return json.loads(path.read_text())
        tree=ast.parse(Path(__file__).with_name('system_config_owned_executor.py').read_text())
        cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='OwnedSystemRestartExecutor')
        start=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='start')
        first=next(i for i,n in enumerate(start.body) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='listed' for t in n.targets))
        last=next(i for i,n in enumerate(start.body) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='cache_labels' for t in n.targets))
        ns={'self':executor,'RESTART_CACHE_PREFIX':RESTART_CACHE_PREFIX,'RESTART_BASE':RESTART_BASE,'manifest_path':path,'manifest':manifest,'cache_tag':cache_tag,'source_digest':source_digest}
        exec(compile(ast.Module(body=start.body[first:last],type_ignores=[]),'<actual cache admission>','exec'),ns)
        if cache_tag in listed:
            selected=start.body[last+1]
            assert isinstance(selected,ast.If)
            exec(compile(ast.Module(body=selected.body,type_ignores=[]),'<actual selected-cache branch>','exec'),ns)
            validate_restart_content_cache(ns['prior'],ns['cache'],cache_tag,source_digest)
        return executor,commands,inspections,ns

    def test_unrelated_historical_tag_is_ignored_without_deletion(self):
        with tempfile.TemporaryDirectory() as d:
            executor,commands,inspections,ns=self.actual_admission(Path(d),['dvaia-system-restart-content:unrelated'])
            self.assertEqual(len(commands),1);self.assertEqual(commands[0][:2],['image','ls']);self.assertEqual(inspections,[])
            self.assertIsNone(ns['prior']);self.assertNotIn('contentCache',executor.state)

    def test_selected_tag_still_needs_private_manifest_and_exact_image_proof(self):
        from system_config_owned_executor import RESTART_CACHE_PREFIX,RESTART_BASE
        tag=RESTART_CACHE_PREFIX+'a'*32
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with self.assertRaisesRegex(RuntimeError,'Duplicate selected'):self.actual_admission(root,[tag,tag])
            with self.assertRaisesRegex(RuntimeError,'manifest missing'):self.actual_admission(root,[tag])
            prior={'version':1,'tag':tag,'imageId':'sha256:'+'b'*64,'sourceSha256':'a'*64,'base':RESTART_BASE}
            _,commands,inspections,_=self.actual_admission(root,['dvaia-system-restart-content:unrelated',tag],prior)
            self.assertEqual(len(commands),1);self.assertEqual(inspections,[('image',tag)])
            with self.assertRaisesRegex(RuntimeError,'inspection mismatch'):self.actual_admission(root,[tag],{**prior,'imageId':'sha256:'+'c'*64})

    def test_pre_cache_failure_cleanup_requires_real_owned_absence_without_inspecting_empty_tag(self):
        from system_config_owned_executor import OwnedSystemRestartExecutor
        with tempfile.TemporaryDirectory() as d:
            executor=OwnedSystemRestartExecutor(Path(d),Path(d),['never'],{},'owned',lambda:None,mode='upload-preview')
            executor.absent=lambda kind,name:True;executor.volume_absent=lambda:True;executor.groups=lambda:[]
            executor.inspect=lambda *a:(_ for _ in ()).throw(AssertionError('No cache was admitted'))
            self.assertTrue(executor.close());self.assertTrue(executor.state['cleanup']['contentCacheNotAdmitted'])
            self.assertNotIn('contentCacheRetained',executor.state['cleanup'])
            executor.absent=lambda kind,name:kind!='container'
            self.assertFalse(executor.close());self.assertFalse(executor.state['cleanup']['containerAbsent'])


class UploadPreviewBuildKitTests(unittest.TestCase):
    def test_private_qualified_plugin_configuration_reaches_exact_buildx_preflight(self):
        import json,os
        import system_config_owned_executor as module
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'docker-config';initial={'HOME':'/owned/isolated','PATH':'/pinned','DOCKER_HOST':'unix:///owned'}
            plugin={'path':'/pinned/vendor/docker-buildx','sha256':'a'*64};calls=[]
            def run(argv,**kw):
                calls.append((argv,kw));self.assertEqual(argv,['/pinned/vendor/docker','buildx','version']);self.assertEqual(kw['env']['HOME'],initial['HOME']);self.assertEqual(kw['env']['DOCKER_CONFIG'],str(root));self.assertEqual(kw['env']['DOCKER_BUILDKIT'],'1')
                return SimpleNamespace(stdout='github.com/docker/buildx v0.30.1\n',stderr='')
            with patch.object(module,'upload_preview_buildx_identity',return_value=plugin),patch.object(module.subprocess,'run',side_effect=run):
                env,identity=module.upload_preview_build_environment(root,'/pinned/vendor/docker',initial)
            self.assertEqual(len(calls),1);self.assertEqual(initial,{'HOME':'/owned/isolated','PATH':'/pinned','DOCKER_HOST':'unix:///owned'});self.assertEqual(identity['plugin'],plugin)
            self.assertEqual(json.loads((root/'config.json').read_text()),{'cliPluginsExtraDirs':['/pinned/vendor']});self.assertEqual(root.stat().st_mode&0o777,0o700);self.assertEqual((root/'config.json').stat().st_mode&0o777,0o600)
            with patch.object(module,'upload_preview_buildx_identity',side_effect=RuntimeError('plugin drift')):
                with self.assertRaisesRegex(RuntimeError,'plugin drift'):module.upload_preview_build_environment(Path(directory)/'other','/pinned/vendor/docker',initial)
            self.assertFalse((Path(directory)/'other').exists())

    def test_failed_cache_build_cleanup_checks_selected_tag_absence_and_actual_process_drain(self):
        from system_config_owned_executor import OwnedSystemRestartExecutor
        with tempfile.TemporaryDirectory() as directory:
            executor=OwnedSystemRestartExecutor(Path(directory),Path(directory),['never'],{},'owned',lambda:None,mode='upload-preview')
            executor.build=SimpleNamespace(pid=999);executor.state.update(cacheBuildAttempted=True,selectedCacheTag='owned:selected')
            executor.stop_build=lambda:None;executor.groups=lambda:[];executor.volume_absent=lambda:True;executor.absent=lambda kind,name:True
            self.assertTrue(executor.close());self.assertTrue(executor.state['cleanup']['contentCacheNotAdmitted'])
            executor.absent=lambda kind,name:name!='owned:selected'
            self.assertFalse(executor.close());self.assertFalse(executor.state['cleanup']['contentCacheNotAdmitted'])


class VerifiedLocalChildBuildTests(unittest.TestCase):
    def actual_child(self, root, *, code=0, changed=False):
        import ast,copy
        import system_config_owned_executor as module
        source_digest='a'*64;tag=module.RESTART_CACHE_PREFIX+'a'*32
        cache={'Id':'sha256:'+'b'*64,'Architecture':'arm64','Config':{'Labels':{'dvaia.cache.kind':'system-restart-content','dvaia.cache.source':source_digest,'dvaia.cache.base':module.RESTART_BASE}}}
        prior={'version':1,'tag':tag,'imageId':cache['Id'],'sourceSha256':source_digest,'base':module.RESTART_BASE}
        executor=module.OwnedSystemRestartExecutor(root,root,['never-docker'],{},'owned',lambda:None,mode='upload-preview');context=root/'context';context.mkdir();events=[]
        executor.persist=lambda:events.append(('persist',copy.deepcopy(executor.state)))
        def inspect(kind,name):
            self.assertEqual((kind,name),('image',tag));events.append(('inspect',name));return {**cache,'Id':'sha256:'+'c'*64} if changed else cache
        executor.inspect=inspect
        def popen(argv,**kw):
            self.assertEqual((context/'owned-child/Dockerfile').read_text(),'FROM '+tag+'\nLABEL dvaia.test.owner="owned"\n')
            self.assertIn('--pull=false',argv);self.assertIn('--network=none',argv)
            self.assertEqual(executor.state['contentCache']['imageId'],cache['Id']);events.append(('build',argv));return SimpleNamespace(pid=111,wait=lambda **kw:code)
        tree=ast.parse(Path(__file__).with_name('system_config_owned_executor.py').read_text());cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='OwnedSystemRestartExecutor');start=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='start')
        first=next(i for i,n in enumerate(start.body) if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Name) and n.value.func.id=='validate_restart_content_cache')
        last=next(i for i,n in enumerate(start.body) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='image' for t in n.targets))
        ns={'self':executor,'prior':prior,'cache':cache,'cache_tag':tag,'source_digest':source_digest,'context':context,'RESTART_BASE':module.RESTART_BASE,'validate_restart_content_cache':module.validate_restart_content_cache,'subprocess':SimpleNamespace(Popen=popen,STDOUT=-2)}
        try:exec(compile(ast.Module(body=start.body[first:last],type_ignores=[]),'<actual verified child build>','exec'),ns)
        except RuntimeError as error:return executor,events,error
        return executor,events,None

    def test_build_uses_verified_local_tag_and_rechecks_original_id_afterward(self):
        with tempfile.TemporaryDirectory() as directory:
            executor,events,error=self.actual_child(Path(directory));self.assertIsNone(error)
            self.assertEqual(len([e for e in events if e[0]=='build']),1);self.assertEqual(len([e for e in events if e[0]=='inspect']),2)
        with tempfile.TemporaryDirectory() as directory:
            _,events,error=self.actual_child(Path(directory),changed=True);self.assertRegex(str(error),'inspection mismatch');self.assertFalse(any(e[0]=='build' for e in events))

    def test_child_failure_retains_already_verified_cache_and_requires_owned_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            executor,events,error=self.actual_child(Path(directory),code=1);self.assertRegex(str(error),'image build failed');self.assertIn('contentCache',executor.state)
            executor.absent=lambda kind,name:True;executor.volume_absent=lambda:True;executor.groups=lambda:[]
            self.assertTrue(executor.close());self.assertTrue(executor.state['cleanup']['contentCacheRetained']);self.assertNotIn('contentCacheNotAdmitted',executor.state['cleanup'])
