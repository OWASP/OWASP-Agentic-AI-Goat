import unittest
import json
import os
import pathlib
import subprocess
import tempfile
from secureshop_activation_safety import (recover_after_failed_restart, recover_failed_postrestart,
  validate_application_schema_scope)
from secureshop_activation_safety import validate_generated_output_scope
from secureshop_activation_safety import stage_generated_release_sources
from secureshop_activation_safety import drain_optional_backend,persist_recovery_snapshot,load_recovery_snapshot

class ActivationRecoveryTest(unittest.TestCase):
    def test_restart_failure_restores_before_resuming_prior_service(self):
        calls=[]
        result=recover_after_failed_restart(
          pause_and_drain=lambda:calls.append('pause'),restore=lambda:calls.append('restore'),
          resume=lambda:calls.append('resume'),health=lambda:(calls.append('health') or True))
        self.assertEqual(calls,['pause','restore','resume','health'])
        self.assertEqual(result,{'recovered':True,'stages':['paused_and_drained','source_config_catalog_restored',
          'watcher_resumed','prior_service_healthy']})

    def test_restore_failure_never_resumes_unrestored_source(self):
        calls=[]
        def fail(): calls.append('restore');raise RuntimeError('injected')
        result=recover_after_failed_restart(pause_and_drain=lambda:calls.append('pause'),restore=fail,
          resume=lambda:calls.append('resume'),health=lambda:True)
        self.assertEqual(calls,['pause','restore']);self.assertFalse(result['recovered'])

    def test_failed_prior_health_remains_recovery_debt(self):
        result=recover_after_failed_restart(pause_and_drain=lambda:None,restore=lambda:None,
          resume=lambda:None,health=lambda:False)
        self.assertFalse(result['recovered']);self.assertEqual(result['errorType'],'RuntimeError')

    def test_runner_branch_recovers_only_postrestart_readiness_failure(self):
        calls=[]
        callbacks=dict(pause_and_drain=lambda:calls.append('pause'),restore=lambda:calls.append('restore'),
          resume=lambda:calls.append('resume'),health=lambda:(calls.append('health') or True))
        self.assertIsNone(recover_failed_postrestart(cleanup={'watcherResumed':True,'health200':True},
          promotion_started=True,recovery_available=True,**callbacks))
        self.assertEqual(calls,[])
        result=recover_failed_postrestart(cleanup={'watcherResumed':True,'health200':False},
          promotion_started=True,recovery_available=True,**callbacks)
        self.assertTrue(result['recovered']);self.assertEqual(calls,['pause','restore','resume','health'])

    def test_registered_conversation_schema_is_explicit_and_unknown_schema_fails(self):
        allowed=('dvaia_migrations','graph_runtime','identity','workshop_conversations','workshop_platform')
        value=validate_application_schema_scope(present=(*allowed,'public'),allowed=allowed,public_objects=0)
        self.assertEqual(value['reviewedSchemas'],sorted(allowed))
        with self.assertRaisesRegex(RuntimeError,'unreviewed application schema'):
            validate_application_schema_scope(present=(*allowed,'public','unexpected'),allowed=allowed,public_objects=0)

    def test_runner_uses_exact_eight_output_builder_contract(self):
        outputs=('server/config/secureshopCurriculum.js','server/database/postgres/workshopPlatformSeed.js',
          'server/index.js','server/services/secureshopBoundApplication.js',
          'server/routes/secureshopRuntimeReadiness.js','server/services/secureshopQualifiedManagedConfiguration.js',
          'scripts/install/secureshop-qualified-local-lib.js','scripts/install/secureshop-qualified-local.js')
        self.assertEqual(validate_generated_output_scope(manifest_names=outputs,builder_names=outputs),sorted(outputs))
        with self.assertRaisesRegex(RuntimeError,'output scope changed'):
            validate_generated_output_scope(manifest_names=outputs[:-1],builder_names=outputs)

    def test_actual_builder_stages_exact_manifest_outputs(self):
        root=pathlib.Path(__file__).resolve().parents[2]
        manifest=json.loads((root/'docs/modernization/drafts/secureshop-qualified-activation-manifest-2026-09-14.json').read_text())
        names=json.loads(subprocess.run(['node','-e',
          "process.stdout.write(JSON.stringify(require('./scripts/build-secureshop-qualified-activation').OUTPUTS))"],
          cwd=root,text=True,check=True,capture_output=True).stdout)
        with tempfile.TemporaryDirectory() as directory:
            target=pathlib.Path(directory)/'release-source'
            actual=stage_generated_release_sources(manifest_outputs=manifest['productionOutputs'],
              builder_names=names,target_root=target,build=lambda output:subprocess.run(
                ['node','scripts/build-secureshop-qualified-activation.js',str(output)],cwd=root,
                text=True,check=True,capture_output=True))
            self.assertEqual(actual,manifest['productionOutputs'])
            for name in names:
                subprocess.run(['node','--check',str(target/name)],check=True,capture_output=True)

    def test_private_recovery_snapshot_round_trips_present_and_absent_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence=pathlib.Path(directory);os.chmod(evidence,0o700)
            retained=persist_recovery_snapshot(evidence=evidence,
              sources={'server/a.js':b'a','server/missing.js':None},
              managed={'present':True,'bytes':b'private managed bytes'})
            sources,managed=load_recovery_snapshot(evidence=evidence,
              expected_sources={'server/a.js':None,'server/missing.js':None},
              expected_manifest_sha256=retained['manifestSha256'])
            self.assertEqual(sources,{'server/a.js':b'a','server/missing.js':None})
            self.assertEqual(managed,{'present':True,'bytes':b'private managed bytes','mode':0o600})
            for path in (evidence/'recovery-source').iterdir():
                self.assertEqual(path.stat().st_mode & 0o777,0o600)

    def test_private_recovery_snapshot_rejects_manifest_and_payload_tampering(self):
        for target in ('manifest','payload'):
            with self.subTest(target=target),tempfile.TemporaryDirectory() as directory:
                evidence=pathlib.Path(directory);os.chmod(evidence,0o700)
                retained=persist_recovery_snapshot(evidence=evidence,
                  sources={'server/a.js':b'a'},managed={'present':False,'bytes':None})
                root=evidence/'recovery-source';manifest_path=root/'manifest.json'
                if target=='manifest':manifest_path.write_text('{}\n')
                else:
                    manifest=json.loads(manifest_path.read_text())
                    (root/manifest['sources']['server/a.js']['file']).write_bytes(b'changed')
                with self.assertRaisesRegex(RuntimeError,'manifest changed|payload changed'):
                    load_recovery_snapshot(evidence=evidence,expected_sources={'server/a.js':None},
                      expected_manifest_sha256=retained['manifestSha256'])

    def test_missing_backend_is_drained_without_signaling_and_present_backend_must_exit(self):
        calls=[]
        self.assertEqual(drain_optional_backend(resolve=lambda:None,
          terminate=lambda pid:calls.append(('term',pid)),wait=lambda pid:calls.append(('wait',pid))),
          {'state':'absent','pid':None})
        self.assertEqual(calls,[])
        self.assertEqual(drain_optional_backend(resolve=lambda:17,
          terminate=lambda pid:calls.append(('term',pid)),wait=lambda pid:calls.append(('wait',pid))),
          {'state':'confirmed_exited','pid':17})
        self.assertEqual(calls,[('term',17),('wait',17)])

if __name__=='__main__': unittest.main()
