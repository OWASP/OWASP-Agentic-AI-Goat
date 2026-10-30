#!/usr/bin/env python3
"""Explicit owned relay lifecycle/transport qualification, never build.

Default --plan is local only. --run creates one private 16MiB guest tmpfs and
network namespace through the already verified mux, then retires them. The
default lifecycle phase issues no traffic. Explicit --phase transport admits
three fixed anonymous TLS requests and two real boundary negatives, not image
operations, metadata acquisition, or shared Docker mutation.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
NODE = ROOT / 'tasks/runtime/node/node_modules/node/bin/node'
NODE_SHA = '56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
PROBE_SHA = '43a9ad0c7a69d05cb29261921c779c9d7f53fec46b63c4e0a958c2a518bf6973'
BUILDER_SHA = 'e21940078579af445dce113771038ac384a88835a5d2ad774c34ebd6b058d600'
PROBE_RECEIPT = ROOT / 'tasks/qualification/relay-guest-probe.nwNg9C/result.json'
PROBE_RECEIPT_SHA = '939eaa0a0fbb1543571d7942319e0dea6883d4153413b219dfacfe2c249aa7ce'
MAX_OUTPUT = 2 * 1024 * 1024
WORK_SECONDS = 150
CLEANUP_SECONDS = 90
GUEST_SECONDS = 15
OPERATIONS = {'inventory', 'preflight', 'prepare', 'namespace', 'start', 'authority', 'evidence', 'stop', 'cleanup'}
TRANSPORT_OPERATIONS = OPERATIONS | {'checkpoint', 'client-deny-peer', 'client-deny-host',
    'client-registry', 'client-auth', 'client-debian'}
TRANSPORT_CASES = {'registry': ('registry-1.docker.io', '/v2/', 401),
    'auth': ('auth.docker.io', '/token?service=registry.docker.io', 200),
    'debian': ('deb.debian.org', '/debian/README', 200)}
NODE_PLAN = r'''const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const input=JSON.parse(fs.readFileSync(0,'utf8'));
if(fs.realpathSync(input.root)!==input.root)throw Error('SOURCE_ROOT');process.chdir(input.root);
require(path.join(input.root,'tests/postgres/ownedMcpBoundedBuild'))._internals.lifecycleQualificationPlan(input.root,input.runId,input.phase).then(plan=>{
 const sources={};for(const file of Object.keys(require.cache)){
  if(!file.startsWith(process.cwd()+'/')||fs.realpathSync(file)!==file)throw Error('SOURCE_PATH');
  const info=fs.lstatSync(file);if(!info.isFile()||info.size>8*1024*1024)throw Error('SOURCE_SIZE');
  sources[path.relative(process.cwd(),file)]=crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
 }if(Object.keys(sources).length>512)throw Error('SOURCE_COUNT');
 console.log(JSON.stringify({plan,sources}));
}).catch(()=>{process.stderr.write('LIFECYCLE_PLAN_FAILED\n');process.exitCode=1;});'''


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pinned(path, expected):
    if path.resolve() != path or not stat.S_ISREG(path.lstat().st_mode) or sha(path) != expected:
        raise RuntimeError('LIFECYCLE_SOURCE_PIN')


def load_probe():
    path = ROOT / 'tests/postgres/probe_owned_mcp_relay_guest.py'
    pinned(path, PROBE_SHA)
    spec = importlib.util.spec_from_file_location('lifecycle_probe_transport', path)
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    # A private module instance: this new lane needs its generated source and
    # journals, not the admission probe's smaller 64KiB output allowance.
    probe.MAX_OUTPUT = MAX_OUTPUT
    return probe


def verify_sources(sources):
    for name, expected in sources.items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts:
            raise RuntimeError('LIFECYCLE_SOURCE_PATH')
        pinned(ROOT / relative, expected)


def make_plan(run_id, runner, phase='lifecycle'):
    if not re.fullmatch('[a-f0-9]{32}', run_id):
        raise RuntimeError('LIFECYCLE_RUN_ID')
    if phase not in ('lifecycle', 'transport'):
        raise RuntimeError('LIFECYCLE_PHASE')
    pinned(NODE, NODE_SHA)
    pinned(ROOT / 'tests/postgres/ownedMcpBoundedBuild.js', BUILDER_SHA)
    pinned(PROBE_RECEIPT, PROBE_RECEIPT_SHA)
    result = runner([str(NODE), '-e', NODE_PLAN], input=json.dumps({'root': str(ROOT), 'runId': run_id, 'phase': phase}), timeout=20)
    if result.stderr:
        raise RuntimeError('LIFECYCLE_PLAN_STDERR')
    packet = json.loads(result.stdout)
    plan, sources = packet['plan'], packet['sources']
    if (plan['kind'] != ('private-relay-real-transport' if phase == 'transport' else 'private-relay-lifecycle-only') or plan['runId'] != run_id
            or plan['storageCapBytes'] != 16777216 or set(plan['commands']) != (TRANSPORT_OPERATIONS if phase == 'transport' else OPERATIONS)
            or plan['acquisitionApproved'] is not False or plan['executionApproved'] is not False
            or plan['guest'] != '/var/tmp/owasp-ai-goat-v23-build-' + run_id):
        raise RuntimeError('LIFECYCLE_PLAN_SHAPE')
    sources.update({str(Path(__file__).relative_to(ROOT)): sha(Path(__file__)),
        'tests/postgres/probe_owned_mcp_relay_guest.py': PROBE_SHA,
        str(PROBE_RECEIPT.relative_to(ROOT)): PROBE_RECEIPT_SHA,
        str(NODE.relative_to(ROOT)): NODE_SHA})
    probe = load_probe()
    for name, digest in probe.DEPENDENCIES.items():
        sources['tests/postgres/' + name + '.py'] = digest
    if phase == 'transport':
        sources['tests/postgres/ownedMcpPrivateTransportClient.py'] = plan['clientSha256']
        sources[plan['prerequisite']['path']] = plan['prerequisite']['sha256']
    verify_sources(sources)
    return plan, sources


def persist(directory, name, value):
    file = directory / name
    descriptor = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as target:
        target.write(json.dumps(value, sort_keys=True) + '\n')
        target.flush()
        os.fsync(target.fileno())


def private_directory(value):
    directory = Path(value)
    base = ROOT / 'tasks/qualification'
    if (not directory.is_absolute() or not directory.is_relative_to(base)
            or directory.resolve() != directory or directory == base
            or not directory.parent.is_dir()):
        raise RuntimeError('LIFECYCLE_OUTPUT_PATH')
    directory.mkdir(mode=0o700)
    return directory


def inventory_valid(value):
    if not value.startswith('"945f6fce-3aaf-4d8f-a483-170464fb2416"\n'):
        raise RuntimeError('SHARED_DAEMON_ID')
    if 'sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336 postgres:18' not in value.splitlines():
        raise RuntimeError('SHARED_POSTGRES_IMAGE')
    parts = value.split('\nNETWORK\n')
    if len(parts) != 2:
        raise RuntimeError('SHARED_NETWORK')
    network = json.loads(parts[1])
    if (network.get('version') != 1 or not network.get('bridge')
            or not any(row.get('ifname') == 'docker0' for row in network.get('links', []))):
        raise RuntimeError('SHARED_NETWORK')
    return value


def verify_evidence(value, plan, terminal=False):
    transport = plan['kind'] == 'private-relay-real-transport'
    if (value.get('version') != 1 or value.get('runId') != plan['runId']
            or value.get('lifecycleOnly') is not (not transport)
            or value.get('sourceSha256') != plan['relaySourceSha256']
            or value.get('admission') != plan['admission']):
        raise RuntimeError('LIFECYCLE_EVIDENCE_BINDING')
    storage = value['storage']
    if storage['capBytes'] != 16777216 or type(storage['usedBytes']) is not int or not 0 < storage['usedBytes'] <= 16777216:
        raise RuntimeError('LIFECYCLE_STORAGE_BOUND')
    files = value['files']
    def coordinate(raw):
        if not isinstance(raw, str):
            raise RuntimeError('LIFECYCLE_NAMESPACE_SHAPE')
        value = raw[:-1] if raw.endswith('\n') else raw
        if not re.fullmatch(r'net:\[[1-9][0-9]*\]', value):
            raise RuntimeError('LIFECYCLE_NAMESPACE_SHAPE')
        return value
    if coordinate(files['namespace.inode']) == coordinate(files['shared.inode']):
        raise RuntimeError('LIFECYCLE_NAMESPACE_NOT_PRIVATE')
    for mode in ('connector', 'adapter'):
        lines = [json.loads(line) for line in files['relay.' + mode + '.log'].splitlines()]
        if (not lines or lines[0].get('kind') != 'relay-ready' or lines[0].get('mode') != mode
                or files['relay.' + mode + '.err'] != ''):
            raise RuntimeError('LIFECYCLE_READY_UNPROVEN')
        if terminal:
            terminals = [row for row in lines if row.get('kind') == 'relay-terminal']
            if len(terminals) != 1:
                raise RuntimeError('LIFECYCLE_TERMINAL_UNPROVEN')
            last = terminals[0]
            if (last.get('connections') != (4 if transport else 0)
                    or last.get('unjoinedWorkers') != 0 or last.get('unresolvedResolverCleanup') != 0
                    or last.get('cleanupVerified') is not True):
                raise RuntimeError('LIFECYCLE_TERMINAL_UNPROVEN')
            if transport:
                if len(lines) != 6 or lines[-1].get('trigger') != 'terminal':
                    raise RuntimeError('TRANSPORT_TERMINAL_UNPROVEN')
                verify_audit(lines[-1], plan, mode, 'positive', 4, trigger='terminal')
                records = last.get('records')
                if (not isinstance(records, list) or len(records) != 4
                        or sum(row == {'host': None, 'status': 'denied'} for row in records) != 1
                        or sorted(row['host'] for row in records if row['host'] is not None) != sorted(host for host, _, _ in TRANSPORT_CASES.values())
                        or any(row['status'] != 'closed' for row in records if row['host'] is not None)):
                    raise RuntimeError('TRANSPORT_RECORDS')
                limits = {'registry-1.docker.io': 128*1024**2, 'auth.docker.io': 1024**2, 'deb.debian.org': 132*1024**2}
                totals = last.get('hostBytes', {})
                if (set(totals) != set(limits) or any(type(totals[h]) is not int or not 0 < totals[h] <= limits[h] for h in limits)
                        or sum(totals.values()) != last.get('bytes') or last['bytes'] > 261*1024**2):
                    raise RuntimeError('TRANSPORT_BYTES')
            elif (len(lines) != 2 or last.get('bytes') != 0 or last.get('records') != []
                    or last.get('hostBytes') != {host: 0 for host, _, _ in TRANSPORT_CASES.values()}):
                raise RuntimeError('LIFECYCLE_TERMINAL_UNPROVEN')
    return value


def verify_audit(row, plan, mode, stage, sequence, trigger='checkpoint'):
    expected = dict(dnsSubprocesses=0, externalConnectAttempts=0, unixConnectAttempts=0, peerChecks=0, peerDenied=0)
    if stage in ('denials', 'positive') and mode == 'connector':
        expected.update(peerChecks=1, peerDenied=1)
    if stage == 'positive':
        expected.update(dict(peerChecks=4, dnsSubprocesses=3, externalConnectAttempts=3)
                        if mode == 'connector' else dict(peerChecks=3, unixConnectAttempts=3))
    if (type(row) is not dict
            or set(row) != {'kind','variant','runId','mode','trigger','sequence','activeWorkers','counts'}
            or row.get('kind') != 'transport-audit' or row.get('variant') != 'connect-audit-v1'
            or row.get('runId') != plan['runId'] or row.get('mode') != mode
            or row.get('trigger') != trigger or row.get('sequence') != sequence
            or type(row.get('sequence')) is not int
            or type(row.get('activeWorkers')) is not int or row.get('activeWorkers') != 0
            or type(row.get('counts')) is not dict
            or any(type(value) is not int for value in row['counts'].values())
            or row.get('counts') != expected):
        raise RuntimeError('TRANSPORT_AUDIT_UNPROVEN')


def verify_checkpoint(packet, plan, stage, sequence):
    if (type(packet) is not dict or set(packet) != {'version','runId','variant','rows'}
            or type(packet.get('version')) is not int or packet.get('version') != 1 or packet.get('runId') != plan['runId']
            or packet.get('variant') != 'connect-audit-v1' or type(packet.get('rows')) is not dict
            or set(packet['rows']) != {'connector', 'adapter'}):
        raise RuntimeError('TRANSPORT_CHECKPOINT_BINDING')
    for mode, row in packet['rows'].items():
        verify_audit(row, plan, mode, stage, sequence)


def verify_client(packet, case):
    if (type(packet) is not dict or set(packet) != {'version','ok','closed','result'}
            or type(packet.get('version')) is not int or packet.get('version') != 1
            or packet.get('ok') is not True or packet.get('closed') is not True
            or type(packet.get('result')) is not dict):
        raise RuntimeError('TRANSPORT_CLIENT_FAILED')
    row = packet.get('result', {})
    if case in ('deny-peer', 'deny-host'):
        if (row != {'case': case, 'denied': True, 'effectiveUid': 0 if case == 'deny-peer' else 501, 'responseBytes': 0}
                or row.get('denied') is not True or type(row.get('effectiveUid')) is not int
                or type(row.get('responseBytes')) is not int):
            raise RuntimeError('TRANSPORT_NEGATIVE_FAILED')
    else:
        host, path, status = TRANSPORT_CASES[case]
        if (set(row) != {'case','host','path','status','bodyBytes','bodySha256','certificateSha256','tlsVerified','tlsVersion','effectiveUid'}
                or row['case'] != case or row['host'] != host or row['path'] != path or row['status'] != status
                or type(row['status']) is not int or row['tlsVerified'] is not True
                or type(row['effectiveUid']) is not int or row['effectiveUid'] != 501
                or row['tlsVersion'] not in ('TLSv1.2', 'TLSv1.3')
                or type(row['bodyBytes']) is not int or not 0 < row['bodyBytes'] <= 65536
                or not all(type(row[key]) is str and re.fullmatch('[a-f0-9]{64}', row[key]) for key in ('bodySha256','certificateSha256'))):
            raise RuntimeError('TRANSPORT_POSITIVE_FAILED')


def run_lifecycle(plan, sources, directory, probe, mux, work, cleanup, pause=time.sleep):
    result = {'version': 1, 'kind': plan['kind'], 'runId': plan['runId'], 'passed': False,
              'acquisitionApproved': False, 'buildApproved': False, 'errors': [], 'cleanupErrors': [],
              'commandFailures': []}
    authority = None
    before = None
    intended = started = False
    stopped = True
    retained = True

    def command(operation, runner):
        if operation not in plan['commands']:
            raise RuntimeError('LIFECYCLE_OPERATION')
        argv = mux.mux_command(authority, 'sudo', '-n', 'timeout', '--signal=TERM', '--kill-after=2',
            str(GUEST_SECONDS), '/bin/sh', '-s', '--', plan['guest'], plan['runId'])
        # OpenSSH joins remote arguments using spaces, not an argv channel.
        # Only fixed tokens and strictly validated hex/path coordinates occur.
        response = None
        try:
            client_operation = operation.startswith('client-')
            response = runner(argv, input=plan['commands'][operation], timeout=20, check=not client_operation)
            if client_operation and response.returncode != 0:
                try:
                    packet=json.loads(response.stdout)
                    code=packet.get('error') if isinstance(packet,dict) else None
                except Exception:
                    code=None
                if not isinstance(code,str) or not re.fullmatch('[A-Z_]{1,32}',code):
                    code='CLIENT_RECEIPT_INVALID'
                persist(directory, operation+'.json', {'version':1,'ok':False,
                    'case':operation.removeprefix('client-'),'error':code})
                raise RuntimeError('COMMAND_EXIT_'+str(response.returncode))
            return response.stdout
        except Exception as exc:
            # BoundedRunner deliberately does not expose guest stderr. Retain
            # its closed transport/exit code plus exact operation, not arbitrary
            # exception text, command source, credentials, or output.
            code = str(exc)
            if not re.fullmatch(r'(?:COMMAND_EXIT_-?[0-9]{1,3}|HOST_DEADLINE|COMMAND_DEADLINE|OUTPUT_LIMIT|OWNED_PROCESS_RETIREMENT_UNVERIFIED)', code):
                code = 'COMMAND_FAILED'
            result['commandFailures'].append({'operation': operation, 'code': code})
            # A retired SSH client alone is not guest completion. Permit the
            # fixed remote timeout+KILL grace to finish before owned inspection.
            pause(GUEST_SECONDS + 2)
            raise

    def mux_check(runner, expected):
        return mux.admit_existing_mux(ROOT, expected=expected,
            run=lambda argv, **kw: runner(argv, **(kw | {'timeout': 2})))

    try:
        expected = dict(plan['mux'])
        expected['masterBirth'] = tuple(expected['masterBirth'])
        authority = mux_check(work, expected)
        result['muxBefore'] = authority
        verify_sources(sources)
        before = inventory_valid(command('inventory', work))
        persist(directory, 'inventory-before.json', {'text': before})
        command('preflight', work)
        persist(directory, 'intent.json', {'runId': plan['runId'], 'guest': plan['guest'],
            'lifecycleSourceSha256': plan['lifecycleSourceSha256'], 'storageCapBytes': 16777216})
        intended = True
        command('prepare', work)
        command('namespace', work)
        started = True
        stopped = False
        command('start', work)
        port = command('authority', work).strip()
        if not re.fullmatch('[1-9][0-9]{0,4}', port) or int(port) > 65535:
            raise RuntimeError('LIFECYCLE_PORT')
        snapshot = json.loads(command('evidence', work))
        persist(directory, 'startup.json', snapshot)
        verify_evidence(snapshot, plan)
        result['readyPort'] = int(port)
        if plan['kind'] == 'private-relay-real-transport':
            for stage, sequence, cases in [('baseline',1,()), ('denials',2,('deny-peer','deny-host')),
                                           ('positive',3,('registry','auth','debian'))]:
                for case in cases:
                    packet = json.loads(command('client-'+case, work))
                    try:
                        verify_client(packet, case)
                    except Exception:
                        code=packet.get('error') if isinstance(packet,dict) else None
                        if not isinstance(code,str) or not re.fullmatch('[A-Z_]{1,32}',code):
                            code='CLIENT_RECEIPT_INVALID'
                        persist(directory, 'client-'+case+'.json', {'version':1,'ok':False,'case':case,'error':code})
                        raise
                    persist(directory, 'client-'+case+'.json', packet)
                packet = json.loads(command('checkpoint', work))
                persist(directory, 'checkpoint-'+stage+'.json', packet)
                verify_checkpoint(packet, plan, stage, sequence)
            result['realTransportVerified'] = True
            result['variant'] = plan['variant']
    except Exception as exc:
        result['errors'].append(type(exc).__name__ + ':LIFECYCLE_WORK_FAILED')
    finally:
        if intended:
            # No retirement while an owned host command remains uncertain.
            if any(not c['reaped'] or not c['groupAbsent'] for c in work.children):
                result['cleanupErrors'].append('HOST_QUIESCENCE_UNVERIFIED')
            else:
                if started:
                    try:
                        command('stop', cleanup)
                        stopped = True
                    except Exception:
                        result['cleanupErrors'].append('RELAY_STOP_FAILED')
                    try:
                        snapshot = json.loads(command('evidence', cleanup))
                        persist(directory, 'terminal.json', snapshot)
                        retained = True
                    except Exception:
                        retained = False
                        result['cleanupErrors'].append('TERMINAL_EVIDENCE_UNVERIFIED')
                    if retained:
                        try:
                            verify_evidence(snapshot, plan, terminal=True)
                        except Exception:
                            result['cleanupErrors'].append('TERMINAL_CRITERIA_FAILED')
                if stopped and retained and all(c['reaped'] and c['groupAbsent'] for c in cleanup.children):
                    try:
                        if command('cleanup', cleanup).strip() != 'absent':
                            raise RuntimeError('ABSENCE_UNPROVEN')
                        result['guestAbsent'] = True
                    except Exception:
                        result['cleanupErrors'].append('GUEST_CLEANUP_UNVERIFIED')
                else:
                    result['cleanupErrors'].append('GUEST_RETAINED_FOR_INSPECTION')
        if authority is not None:
            try:
                after = inventory_valid(command('inventory', cleanup))
                persist(directory, 'inventory-after.json', {'text': after})
                if before is None or after != before:
                    raise RuntimeError('SHARED_STATE_CHANGED')
                result['sharedStateUnchanged'] = True
            except Exception:
                result['cleanupErrors'].append('SHARED_POSTFLIGHT_FAILED')
            try:
                result['muxAfter'] = mux_check(cleanup, authority)
                result['muxUnchanged'] = True
            except Exception:
                result['cleanupErrors'].append('MUX_POSTFLIGHT_FAILED')
        try:
            verify_sources(sources)
            result['sourceUnchanged'] = True
        except Exception:
            result['cleanupErrors'].append('SOURCE_POSTFLIGHT_FAILED')
        result['children'] = work.children + cleanup.children
        result['observedOutputBytes'] = work.observed + cleanup.observed
        result['passed'] = (not result['errors'] and not result['cleanupErrors']
            and result.get('guestAbsent') is True and result.get('sharedStateUnchanged') is True)
        persist(directory, 'result.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--plan', action='store_true')
    modes.add_argument('--run', action='store_true')
    parser.add_argument('--run-id', default='a'*32)
    parser.add_argument('--output-dir')
    parser.add_argument('--phase', choices=('lifecycle', 'transport'), default='lifecycle')
    args = parser.parse_args()
    if args.run and (args.run_id == 'a'*32 or not args.output_dir):
        parser.error('--run requires explicit unique --run-id and --output-dir')
    if not args.run and args.output_dir:
        parser.error('--output-dir requires --run')
    probe = load_probe()
    work = probe.BoundedRunner(time.monotonic()+WORK_SECONDS)
    plan, sources = make_plan(args.run_id, work, args.phase)
    if not args.run:
        print(json.dumps({key: value for key, value in plan.items() if key not in ('commands', 'mux')}, sort_keys=True))
        return 0
    directory = private_directory(args.output_dir)
    persist(directory, 'plan.json', plan)
    persist(directory, 'sources.json', sources)
    # The cleanup budget begins on entry to finalization, not before work.
    class CleanupRunner:
        def __init__(self):
            self.actual = None
        @property
        def children(self):
            return self.actual.children if self.actual else []
        @property
        def observed(self):
            return self.actual.observed if self.actual else 0
        def __call__(self, *a, **kw):
            if self.actual is None:
                self.actual = probe.BoundedRunner(time.monotonic()+CLEANUP_SECONDS)
            return self.actual(*a, **kw)
    try:
        mux = probe.load_mux()
    except Exception:
        result = {'passed': False, 'errors': ['LIFECYCLE_MUX_IMPORT_FAILED'],
                  'acquisitionApproved': False, 'buildApproved': False}
        persist(directory, 'result.json', result)
    else:
        result = run_lifecycle(plan, sources, directory, probe, mux, work, CleanupRunner())
    print(json.dumps({'passed': result['passed'], 'result': str(directory/'result.json'),
        'acquisitionApproved': False, 'buildApproved': False}, sort_keys=True))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
