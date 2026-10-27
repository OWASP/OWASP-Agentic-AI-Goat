"""Candidate-only packaged Listings gate, sharing the current-main launcher lifecycle."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import tarfile
import tempfile
import uuid

import listings_native_resources as owned
from sql_nosql_docker_ownership import verify_daemon

FIXTURE = 'tests/fixtures/secureshopOwnedListingsPackaged.native.cjs'
DOCKERFILE = 'sidecars/sandbox-runner/owned-listings/Dockerfile.candidate'
BUILDX_SHA256 = '591a852237e8ed2b8c65f6be8105ef8c2d1ec52edc77c8acf8f263c2240ef4d6'
CHECKS = ['real-supplier-prototype-effect', 'fixed-prototype-no-effect', 'internal-prototype-route-denial',
          'real-json', 'internal-ssrf', 'fixed-denial', 'real-file-entity', 'real-http-entity',
          'external-host-denial', 'restart-no-refetch', 'timeout-child-cleanup', 'readonly-write-denial',
          'authenticated-http', 'retirement-redaction-sibling']


def buildx_identity(api, args):
    path = Path(args.docker).parent / 'docker-buildx'
    state = path.lstat()
    if (not path.is_absolute() or path.resolve() != path or not stat.S_ISREG(state.st_mode)
            or state.st_uid != 0 or state.st_mode & 0o022 or not os.access(path, os.X_OK)
            or api.digest(path) != BUILDX_SHA256):
        raise RuntimeError('Pinned root-owned vendor Buildx required')
    return {'path': str(path), 'sha256': BUILDX_SHA256}


def source_manifest(api, args, source, additional_drivers=(), current_host=None):
    result = subprocess.run([args.node, '-e',
        "const planner=require('./scripts/install/secureshop-owned-listings');"
        "require('./scripts/install/secureshop-owned-listings-qualified-candidate');"
        "const manifest=planner.sourceManifest(process.cwd());"
        "process.stdout.write(JSON.stringify({manifest,loaded:Object.keys(require.cache)}))"],
        cwd=source, env={'PATH': str(Path(args.node).parent)}, capture_output=True, text=True, timeout=20, check=True)
    captured = json.loads(result.stdout)
    manifest = captured['manifest']
    if (not isinstance(manifest, dict) or set(manifest) != {'sha256', 'files'}
            or not re.fullmatch(r'[a-f0-9]{64}', manifest['sha256'])
            or not isinstance(manifest['files'], dict) or not 1 <= len(manifest['files']) <= 128
            or FIXTURE not in manifest['files'] or DOCKERFILE not in manifest['files']):
        raise RuntimeError('Canonical Listings source manifest required')
    # Capture precisely the loaded planner/profile CommonJS imports, including
    # their actual third-party dependency bytes, plus the Python entry imports.
    drivers = ['tests/postgres/run-secureshop-agent-host-transport-main.py',
        'tests/postgres/listings_package_candidate.py', 'tests/postgres/listings_native_resources.py',
        'tests/postgres/sql_nosql_docker_ownership.py', 'tests/postgres/admin_browser_current_main_admission.py']
    if current_host is not None:
        drivers.extend(('tests/postgres/listings_package_goat_current.py',
                        'tests/postgres/secureshop_current_host_admission.py'))
    for name in additional_drivers:
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_./-]+', name):
            raise RuntimeError('Canonical additional package driver required')
        path = source / name
        if (Path(name).is_absolute() or '..' in Path(name).parts or path.is_symlink()
                or path.resolve() != path or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024):
            raise RuntimeError('Canonical additional package driver required')
        drivers.append(name)
    loaded = captured.get('loaded')
    if not isinstance(loaded, list) or not 1 <= len(loaded) <= 256:
        raise RuntimeError('Bounded loaded helper import closure required')
    for name in loaded:
        path = Path(name)
        if (not path.is_absolute() or not path.is_relative_to(source) or path.is_symlink()
                or path.resolve() != path or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024):
            raise RuntimeError('Canonical helper dependency required')
        drivers.append(str(path.relative_to(source)))
    result = {'package': manifest, 'drivers': {name: api.digest(source / name) for name in sorted(set(drivers))},
              'node': api.digest(args.node), 'docker': api.digest(args.docker),
              'buildx': current_host.guest_identity() if current_host is not None else buildx_identity(api, args)}
    if current_host is not None:
        result['currentHostProfile'] = 'goat-q'
    return result


def context_bytes(source, manifest):
    """Stream only manifest-listed current bytes; never create a copied source tree."""
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as archive:
        for name, expected in manifest['files'].items():
            relative = Path(name)
            if relative.is_absolute() or '..' in relative.parts or not re.fullmatch(r'[a-f0-9]{64}', expected):
                raise RuntimeError('Unsafe package source path')
            path = source / relative
            if path.is_symlink() or path.resolve() != path or not path.is_file():
                raise RuntimeError('Package source identity changed')
            data = path.read_bytes()
            if len(data) > 1048576 or hashlib.sha256(data).hexdigest() != expected:
                raise RuntimeError('Package source bytes changed')
            entry = tarfile.TarInfo(name); entry.size = len(data); entry.mode = 0o644
            archive.addfile(entry, io.BytesIO(data))
    if output.tell() > 64 * 1024 * 1024:
        raise RuntimeError('Package build context too large')
    return output.getvalue()


def read_image(command, state):
    result = command(['image', 'inspect', state['imageTag']])
    if result.returncode:
        if result.returncode == 1 and result.stderr.strip() in (
                'Error response from daemon: No such image: ' + state['imageTag'],
                'Error: No such image: ' + state['imageTag']):
            return None
        raise RuntimeError('Candidate image absence unavailable')
    rows = json.loads(result.stdout)
    if not isinstance(rows, list) or len(rows) != 1:
        raise RuntimeError('Candidate image inspection invalid')
    image = rows[0]; labels = image.get('Config', {}).get('Labels')
    if (not re.fullmatch(r'sha256:[a-f0-9]{64}', image.get('Id', ''))
            or image.get('Architecture') != 'arm64' or image.get('Os') != 'linux'
            or image.get('RepoTags') != [state['imageTag']]
            or not isinstance(labels, dict) or any(labels.get(k) != v for k, v in state['labels'].items())
            or state.get('image', image['Id']) != image['Id']):
        raise RuntimeError('Candidate image identity changed')
    state['image'] = image['Id']
    return image


def read_result(path, replay):
    raw = path.read_bytes()
    if len(raw) > 1024 * 1024:
        raise RuntimeError('Packaged output exceeds bound')
    value = json.loads(raw.decode().strip())
    if (not isinstance(value, dict) or set(value) != {'status', 'modelCalls', 'existingReceipt', 'checks', 'runtimeDigest'}
            or value['status'] != 'passed' or type(value['modelCalls']) is not int or value['modelCalls'] != 0
            or value['existingReceipt'] is not replay or value['checks'] != CHECKS
            or not re.fullmatch(r'[a-f0-9]{64}', value['runtimeDigest'])):
        raise RuntimeError('Exact packaged native result required')
    return value


def qualify(api, args, source, after_package=None, expected_runtime_digest=None, expected_source_sha256=None,
            additional_drivers=(), current_host=None):
    if after_package is not None and not callable(after_package):
        raise RuntimeError('Package callback must be callable')
    if expected_runtime_digest is not None and not re.fullmatch(r'[a-f0-9]{64}', expected_runtime_digest):
        raise RuntimeError('Canonical package runtime digest required')
    if expected_source_sha256 is not None and not re.fullmatch(r'[a-f0-9]{64}', expected_source_sha256):
        raise RuntimeError('Canonical package source digest required')
    if not isinstance(additional_drivers, tuple):
        raise RuntimeError('Canonical additional package drivers required')
    if args.plan:
        print(json.dumps({'cohort': 'listings-package-goat-current-v1' if current_host is not None else 'listings-package', 'workspace': str(source), 'stores': [],
            'tests': 2, 'browser': False, 'modelCalls': 0, 'sourceCopy': False,
            'nativeStarted': False, 'candidateOnly': True, 'fixture': FIXTURE}))
        return 0
    if current_host is not None:
        if (not current_host.LIVE_ENABLED or Path(source) != current_host.source
                or getattr(args, 'current_host_profile', None) != 'goat-q'
                or args.docker_daemon != current_host.daemon_id
                or args.docker_host != 'unix://' + str(Path(source) / '.qualification/goat-q/docker.sock')
                or (args.evidence_parent is not None and Path(args.evidence_parent) != current_host.evidence_parent)):
            raise RuntimeError('Reviewed current-host Listings build admission remains closed')
    parent = (Path(current_host.evidence_parent) if current_host is not None else
              Path(args.evidence_parent or Path(tempfile.gettempdir()).resolve() / 'dvaia-listings-package-native'))
    if not parent.is_absolute() or (current_host is None and parent.resolve().is_relative_to(source)):
        raise RuntimeError('Private package evidence parent invalid')
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if parent.is_symlink() or parent.resolve() != parent or parent.stat().st_uid != os.getuid() or parent.stat().st_mode & 0o777 != 0o700:
        raise RuntimeError('Private package evidence parent required')
    prefix = 'run-listings-package-goat-' if current_host is not None else 'run-'
    evidence = Path(tempfile.mkdtemp(prefix=prefix, dir=parent)); evidence.chmod(0o700)
    runtime = evidence / 'runtime'; runtime.mkdir(mode=0o700)
    for name in ('home', 'tmp'): (runtime / name).mkdir(mode=0o700)
    clean = {'PATH': f'{Path(args.node).parent}:{Path(args.docker).parent}:/usr/bin:/bin',
        'HOME': str(runtime / 'home'), 'TMPDIR': str(runtime / 'tmp'), 'LANG': 'C', 'DOCKER_HOST': args.docker_host}
    plugin = current_host.guest_identity() if current_host is not None else buildx_identity(api, args)
    docker_config = runtime / 'docker-config'; docker_config.mkdir(mode=0o700)
    config_path = docker_config / 'config.json'
    api.atomic_json(config_path, {} if current_host is not None else
                    {'cliPluginsExtraDirs': [str(Path(plugin['path']).parent)]})
    config_sha256 = api.digest(config_path)
    clean.update(DOCKER_CONFIG=str(docker_config), DOCKER_BUILDKIT='1')
    command = api.docker_owner_command(args, clean)
    nonce = uuid.uuid4().hex[:12]
    name = ('dvaia-listings-goat-' if current_host is not None else 'dvaia-listings-package-') + nonce
    state = {'container': name, 'volume': name + '-journal', 'network': 'none', 'packaged': True,
        'imageTag': name + ':candidate', 'daemon': args.docker_daemon, 'attempted': [],
        'labels': {'dvaia.owner': str(uuid.uuid4()),
                   'dvaia.cohort': 'listings-package-goat-current-v1' if current_host is not None else 'listings-package'}}
    child = None; failure = None; cleanup = {}; results = {}; post_package = None; pins = None; image_attempted = False
    def persist(): api.atomic_json(evidence / 'resources.json', state)
    def unchanged():
        verify_daemon(command, args.docker_daemon)
        if config_path.is_symlink() or api.digest(config_path) != config_sha256:
            raise RuntimeError('Private Docker plugin configuration changed')
        if source_manifest(api, args, source, additional_drivers, current_host) != pins: raise RuntimeError('Package source/executable drift')
    def execute(parts, label, timeout, data=None):
        nonlocal child
        output = evidence / (label + '.stdout'); error = evidence / (label + '.stderr')
        with output.open('xb') as out, error.open('xb') as err:
            os.chmod(output, 0o600); os.chmod(error, 0o600)
            argv = (current_host.build_argv(parts, builder=state.get('builder')) if current_host is not None and label == 'build' else
                    [args.docker, '--host', args.docker_host, *parts])
            def bounded_output():
                resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024 * 1024, 8 * 1024 * 1024))
            child = subprocess.Popen(argv, env=clean,
                stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL, stdout=out, stderr=err,
                start_new_session=True, preexec_fn=bounded_output if current_host is not None else None)
            state[label + 'Process'] = {'pid': child.pid, 'pgid': os.getpgid(child.pid)}; persist()
            child.communicate(input=data, timeout=timeout)
            if child.returncode != 0: raise RuntimeError('Packaged ' + label + ' failed')
        api.stop_process_group(child)
        child = None
        return output
    try:
        signal.signal(signal.SIGTERM, api.interrupted); signal.signal(signal.SIGINT, api.interrupted)
        verify_daemon(command, args.docker_daemon)
        pins = source_manifest(api, args, source, additional_drivers, current_host); api.atomic_json(evidence / 'source-before.json', pins)
        if expected_source_sha256 is not None and pins['package']['sha256'] != expected_source_sha256:
            raise RuntimeError('Packaged source differs from canonical qualification')
        state['labels']['dvaia.listings.source'] = pins['package']['sha256']
        if expected_runtime_digest is not None:
            state['labels']['dvaia.listings.runtime'] = expected_runtime_digest
        state['profile'] = (current_host.profile_plan(nonce) if current_host is not None else
                            api.listings_profile_plan(source, args.node, args.docker_host, nonce))
        state['environmentSha256'] = hashlib.sha256(('LISTINGS_PROFILE=' + state['profile']['name']).encode()).hexdigest()
        persist()
        for kind in ('container', 'volume'):
            if owned.inspect(command, kind, state[kind]) is not None: raise RuntimeError('Candidate resource name occupied')
        if read_image(command, state) is not None: raise RuntimeError('Candidate image name occupied')
        api.check_listings_profile_absent(source, args.node, clean, state['profile'])
        labels = sum((['--label', k + '=' + v] for k, v in state['labels'].items()), [])
        unchanged(); image_attempted = True; state['imageAttempted'] = True; persist()
        execute(['build', '--platform', 'linux/arm64', '--pull=false', *labels,
            '--tag', state['imageTag'], '--file', DOCKERFILE, '-'], 'build', 300,
            context_bytes(source, pins['package']))
        unchanged()
        if read_image(command, state) is None: raise RuntimeError('Candidate image missing after build')
        persist()
        state['attempted'].append('profile'); persist()
        api.provision_listings_profile(source, args.node, clean, state['profile'])
        state['attempted'].append('volume'); persist()
        if command(['volume', 'create', *labels, state['volume']]).returncode: raise RuntimeError('Candidate volume create failed')
        owned.owned(command, state, 'volume'); persist()
        state['attempted'].append('container'); persist()
        created = command(['create', '--pull', 'never', '--name', name, *labels, '--network', 'none',
            '--read-only', '--user', '10001:10001', '--memory', '512m', '--cpus', '1', '--pids-limit', '128',
            '--cap-drop', 'ALL', '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=16m',
            '--security-opt', 'apparmor=' + state['profile']['name'], '--security-opt', 'seccomp=unconfined',
            '--mount', 'type=volume,source=' + state['volume'] + ',target=/journal',
            '--env', 'LISTINGS_PROFILE=' + state['profile']['name'], '--entrypoint', 'node',
            state['image'], '/app/' + FIXTURE])
        owned.capture_container(command, state); persist()
        for label, replay in [('fresh', False), ('restart', True)]:
            unchanged(); row = owned.capture_container(command, state)
            if row.get('State', {}).get('Status') not in (('exited',) if replay else ('created',)):
                raise RuntimeError('Unexpected packaged container lifecycle')
            output = execute(['start', '--attach', state['containerId']], label, 150)
            unchanged(); row = owned.capture_container(command, state)
            if row.get('State', {}).get('Status') != 'exited' or row['State'].get('ExitCode') != 0:
                raise RuntimeError('Packaged container exit not confirmed')
            results[label] = read_result(output, replay)
        if results['fresh']['runtimeDigest'] != results['restart']['runtimeDigest']:
            raise RuntimeError('Packaged runtime changed on restart')
        if expected_runtime_digest is not None and results['fresh']['runtimeDigest'] != expected_runtime_digest:
            raise RuntimeError('Packaged runtime differs from canonical qualification')
        if after_package is not None:
            callback = after_package({
                'imageId': state['image'], 'imageTag': state['imageTag'],
                'sourceSha256': pins['package']['sha256'],
                'runtimeDigest': results['fresh']['runtimeDigest'],
                'evidence': str(evidence),
            })
            if not isinstance(callback, dict):
                raise RuntimeError('Package callback receipt required')
            post_package = callback
        api.atomic_json(evidence / 'source-after.json', source_manifest(api, args, source, additional_drivers, current_host))
    except Exception as error:
        failure = type(error).__name__ + ': ' + str(error)
    finally:
        errors = []
        try: api.stop_process_group(child)
        except Exception as error: errors.append('process:' + type(error).__name__)
        try:
            cleanup.update(owned.cleanup(command, state,
                lambda plan: api.remove_listings_profile(source, args.node, clean, plan), persist))
        except Exception as error: errors.append('resources:' + type(error).__name__)
        if image_attempted and not errors:
            try:
                verify_daemon(command, args.docker_daemon)
                image = read_image(command, state)
                if image is not None:
                    # No force: an unexpected dependent container/tag is retained.
                    command(['image', 'rm', state['image']])
                    if read_image(command, state) is not None: raise RuntimeError('Candidate image remains')
                    by_id = command(['image', 'inspect', state['image']])
                    if by_id.returncode != 1 or by_id.stderr.strip() not in (
                            'Error response from daemon: No such image: ' + state['image'],
                            'Error: No such image: ' + state['image']):
                        raise RuntimeError('Candidate image ID absence unconfirmed')
                cleanup['imageAbsent'] = True
            except Exception as error: errors.append('image:' + type(error).__name__)
        try:
            if pins is not None: unchanged()
        except Exception as error: errors.append('source:' + type(error).__name__)
        processes = {label: state[label + 'Process'] for label in ('build', 'fresh', 'restart')
                     if label + 'Process' in state}
        try:
            probe = subprocess.run(['/bin/ps', '-axo', 'pgid='], capture_output=True, text=True,
                timeout=10, check=True, env={'PATH': '/usr/bin:/bin'})
            groups = probe.stdout.split()
            if any(not value.isdigit() for value in groups): raise RuntimeError('Process inventory invalid')
            for label in ('build', 'fresh', 'restart'):
                process = processes.get(label)
                absent = bool(process and type(process.get('pid')) is int and process['pid'] > 1
                    and process.get('pgid') == process['pid'] and str(process['pgid']) not in groups)
                cleanup[label + 'PgidAbsent'] = absent
                if process and not absent: raise RuntimeError('Owned process group remains')
        except Exception as error: errors.append('process-absence:' + type(error).__name__)
        cleanup['errors'] = errors
        passed = failure is None and not errors and len(results) == 2
        report = {'version': 3 if current_host is not None else 2,
            'cohort': 'listings-package-goat-current-v1' if current_host is not None else 'listings-package',
            'status': 'passed' if passed else 'failed',
            'candidateOnly': True, 'sourceCopy': False, 'sourceRoot': str(source), 'modelCalls': 0,
            'unusedResources': {'remote': 'not-used', 'buildCa': 'not-used'}, 'ownedProcesses': processes,
            'frozenHashesVerified': pins is not None and not any(e.startswith('source:') for e in errors),
            'frozenFileCount': len(pins['package']['files']) if pins else 0, 'source': pins,
            'imageId': state.get('image'), 'result': results.get('fresh'), 'restartResult': results.get('restart'),
            'postPackage': post_package,
            'reportedCleanup': cleanup, 'error': failure}
        api.atomic_json(evidence / 'qualification.json', report)
    print(json.dumps({'evidence': str(evidence), 'status': report['status'], 'cleanup': cleanup}))
    return 0 if passed else 1
