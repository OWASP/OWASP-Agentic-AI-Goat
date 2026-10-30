"""Offline actual guest-method controls; no guest, daemon, or browser starts."""
import json
import io
import builtins
import importlib.util
import http.client
import stat
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

_spec=importlib.util.spec_from_file_location('v03_controlled_system_runtime',Path(__file__).with_name('test_owned_system_private_http_channel.py'))
_fixture=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fixture)
channel,binding,ControlledRuntime=_fixture.channel,_fixture.binding,_fixture.ControlledRuntime


class DiagnosticRuntime(ControlledRuntime):
    def __init__(self):
        super().__init__()
        value = binding()
        value['target'] = 'original-v03-diagnostic'
        channel.GuestRuntime.__init__(self, value, time.monotonic()+10)

    def diagnostic_lease(self, deadline=None):
        self.events.append('diagnostic-lease')
        return dict(parentRunId='a'*32,runId=self.binding['runId'],combinedPlanSha256='b'*64,
                    guestBootId='01234567-0123-0123-0123-012345678901')

    def docker(self, *args):
        result = super().docker(*args)
        if args[0] == 'create':
            self.row['Config']['Labels'] = {'owasp-ai-goat.diagnostic.runtime':self.binding['runId']}
            self.row['Config']['Entrypoint'] = self.entrypoint
        return result


class DiagnosticControls(unittest.TestCase):
    def test_actual_emitted_health_only_reads_private_token_and_uses_original_get(self):
        raw=('SECURESHOP_SYSTEM_DIAGNOSTIC_HTTP_ENABLED=true\nSECURESHOP_SYSTEM_DIAGNOSTIC_TOKEN='+'x'*43+
             '\nSECURESHOP_SYSTEM_DIAGNOSTIC_HOST=127.0.0.1\nSECURESHOP_SYSTEM_DIAGNOSTIC_PORT=8090\n').encode()
        expected=dict(version='secureshop-owned-system-diagnostic-http.v1',ready=True,
                      isolation='bwrap-system-diagnostic-v1',diagnosticCapability='secureshop-owned-system-diagnostic.v1')
        response=SimpleNamespace(status=200,read=lambda maximum:json.dumps(expected).encode())
        calls=[]
        connection=SimpleNamespace(request=lambda *args,**kwargs:calls.append((args,kwargs)),
                                   getresponse=lambda:response,close=lambda:calls.append('closed'))
        info=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1,st_size=len(raw))
        source=channel.diagnostic_readiness_program('/var/tmp/owasp-ai-goat-v23-build-'+'a'*32+'/fs/diagnostic-runtime.env',12345,120)
        self.assertNotIn('x'*43,source)
        with patch.object(channel.os,'stat',return_value=SimpleNamespace(st_ino=12345)), \
             patch.object(channel.os,'open',return_value=77),patch.object(channel.os,'fstat',return_value=info), \
             patch.object(channel.os,'read',return_value=raw),patch.object(channel.os,'close'), \
             patch.object(channel.time,'monotonic',return_value=100), \
             patch.object(http.client,'HTTPConnection',return_value=connection) as factory:
            exec(compile(source,'<diagnostic-readiness>','exec'),{})
            factory.assert_called_once_with('127.0.0.1',8090,timeout=2)
        self.assertEqual(calls,[(('GET','/secureshop/system/diagnostic-health'),
                               {'headers':{'Authorization':'Bearer '+'x'*43}}),'closed'])
        with self.assertRaises(RuntimeError):channel.diagnostic_readiness_program('/tmp/foreign',12345,120)

    def test_actual_parent_lease_rejects_extension_foreign_binding_and_nonregular(self):
        value=binding();value['target']='original-v03-diagnostic'
        parent='a'*32
        value['runId']=channel.digest((parent+':v03-diagnostic').encode())[:32]
        value['physical']['privateDockerHost']='unix:///var/tmp/owasp-ai-goat-v23-build-'+value['runId']+'/fs/docker.sock'
        with patch.object(channel.time,'monotonic',return_value=100):
            runtime=channel.GuestRuntime(value,110)
        row=dict(version=1,target='original-v03-combined-preparation-lease-v1',runId=value['runId'],parentRunId=parent,
                 clock='linux-monotonic-ms',startedAtMs=0,expiresAtMs=11096000,combinedPlanSha256='e'*64,
                 guestBootId='01234567-0123-0123-0123-012345678901')
        def invoke(candidate,mode=stat.S_IFREG|0o600):
            raw=json.dumps(candidate).encode()
            info=SimpleNamespace(st_mode=mode,st_uid=0,st_nlink=1,st_size=len(raw),
                                 st_dev=1,st_ino=2,st_mtime_ns=3,st_ctime_ns=4)
            with patch.object(channel.os,'open',return_value=77) as opened, \
                 patch.object(channel.os,'fstat',return_value=info), \
                 patch.object(channel.os,'read',return_value=raw), \
                 patch.object(channel.os,'close') as closed, \
                 patch.object(builtins,'open',return_value=io.StringIO('01234567-0123-0123-0123-012345678901\n')), \
                 patch.object(channel.time,'monotonic_ns',return_value=100000000000):
                try:return runtime.diagnostic_lease(1000)
                finally:
                    self.assertTrue(opened.call_args.args[1]&channel.os.O_NONBLOCK)
                    closed.assert_called_once_with(77)
        self.assertEqual(invoke(row),row)
        for key,value in [('expiresAtMs',11096001),('runId','f'*32),('clock','host'),
                          ('target','original-v24-system-total-lease-v1'),('combinedPlanSha256','bad'),
                          ('startedAtMs',True),('expiresAtMs',4500000),('guestBootId','other'),('version',True)]:
            with self.assertRaises(RuntimeError):invoke(dict(row,**{key:value}))
        with self.assertRaises(RuntimeError):invoke(row,stat.S_IFIFO|0o600)

    def test_original_and_diagnostic_target_protocols_stay_distinct(self):
        for target, slot, entry in [
            ('original-v24-system','system','/qualification/owned-system/http-listener.js'),
            ('original-v24-policy','policy','/app/policy-render/listener.js'),
            ('original-v03-diagnostic','diagnostic','/qualification/diagnostic-listener-entry.js')]:
            value = binding(); value['target'] = target
            runtime = channel.GuestRuntime(value,time.monotonic()+10)
            self.assertEqual(runtime.slot,slot)
            self.assertEqual(runtime.entrypoint,['/usr/local/bin/node',entry])
            self.assertEqual(runtime.filename('system-runtime.env'),slot+'-runtime.env')
        value['target']='diagnostic'
        with self.assertRaises(RuntimeError): channel.fixed_binding(value)

    def test_actual_start_and_stop_use_original_diagnostic_entry_and_envelope(self):
        runtime=DiagnosticRuntime()
        profile=Path(__file__).resolve().parents[2]/'sidecars/sandbox-runner/apparmor/owasp-ai-goat-mcp-sandbox.apparmor.in'
        with patch.object(channel.os,'stat',return_value=SimpleNamespace(st_ino=12345)):
            result=runtime.start('x'*43,profile.read_bytes(),time.monotonic()+2100)
            self.assertEqual(result['target'],'original-v03-diagnostic')
            self.assertEqual(runtime.files['system-runtime.env'],
                ('SECURESHOP_SYSTEM_DIAGNOSTIC_HTTP_ENABLED=true\nSECURESHOP_SYSTEM_DIAGNOSTIC_TOKEN='+'x'*43+
                 '\nSECURESHOP_SYSTEM_DIAGNOSTIC_HOST=127.0.0.1\nSECURESHOP_SYSTEM_DIAGNOSTIC_PORT=8090\n').encode())
            self.assertEqual(runtime.row['HostConfig']['Memory'],536870912)
            self.assertEqual(runtime.row['HostConfig']['PidsLimit'],128)
            runtime.row['HostConfig']['Memory']=536870913
            with self.assertRaises(RuntimeError):runtime.inspect(True)
            runtime.row['HostConfig']['Memory']=536870912
            stopped=runtime.stop([])
            self.assertTrue(stopped['containerAbsent'])
            self.assertTrue(stopped['profileAbsent'])
            self.assertFalse(stopped['builderReleaseAllowed'])

    def test_actual_cohort_is_exclusive_and_cannot_exceed_preparation(self):
        runtime=DiagnosticRuntime()
        now=time.monotonic()
        runtime.files['system-runtime.deadline']=str(now+1500).encode()
        phase=dict(runtime.diagnostic_lease(),phase='cohortClaim',startedAtMs=int(now*1000),deadlineMs=int(now*1000)+1210000)
        value=runtime.claim_diagnostic_cohort(phase)
        self.assertTrue(value['claimed'])
        with self.assertRaises(RuntimeError):runtime.claim_diagnostic_cohort(phase)
        for candidate in [float('nan'),float('inf'),True,now-1,now+1211,
                          dict(phase,deadlineMs=phase['deadlineMs']+1),dict(phase,guestBootId='foreign'),
                          dict(phase,parentRunId='f'*32),dict(phase,phase='start'),dict(phase,startedAtMs=True),
                          dict(phase,startedAtMs=phase['startedAtMs']-11000,deadlineMs=phase['deadlineMs']-11000)]:
            with self.assertRaises(RuntimeError):runtime.claim_diagnostic_cohort(candidate)
        runtime.files.pop('system-cohort.deadline')
        runtime.files['system-runtime.deadline']=str(now+30).encode()
        with self.assertRaises(RuntimeError):runtime.claim_diagnostic_cohort(phase)
        with self.assertRaises(RuntimeError):ControlledRuntime().claim_diagnostic_cohort(now+20)

    def test_channel_emission_requires_claim_file_and_fixed1210_infrastructure_bound(self):
        value=binding();value['target']='original-v03-diagnostic'
        source=channel.channel_program(value,'e'*32)
        compile(source,'<diagnostic-channel>','exec')
        self.assertIn("'-cohort.deadline' if DIAGNOSTIC",source)
        with patch.object(channel.time,'monotonic',return_value=100):
            channel.check_runtime_deadline(1310,'original-v03-diagnostic')
            for target in ['original-v24-system','original-v24-policy']:
                with self.assertRaises(RuntimeError):channel.check_runtime_deadline(1300,target)
            with self.assertRaises(RuntimeError):channel.check_runtime_deadline(1311,'original-v03-diagnostic')
            with self.assertRaises(RuntimeError):channel.check_runtime_deadline(101,'foreign')


if __name__=='__main__':unittest.main()
