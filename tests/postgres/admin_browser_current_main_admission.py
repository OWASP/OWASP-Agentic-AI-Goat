"""Import-inert admission for the model-free current-main admin browser cohort."""

import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path


COHORT = 'admin-browser-current-main'
SCOPE = 'admin_production_browser_current_main_pg18'
NODE_VERSION = 'v26.10.0'
NODE_SHA256 = '56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
PRIVATE_EVIDENCE_RELATIVE = Path('backups/private-recovery/admin-current')
EXCLUDED_ROOTS = {'.git', 'node_modules', 'tasks', 'backups', 'coverage'}
REQUIRED_SOURCE = {
    'tests/postgres/run-admin-auth-browser-cohort-isolated.py',
    'tests/postgres/admin_browser_current_main_admission.py',
    'tests/postgres/adminProductionAuthBrowser.integration.test.js',
    'tests/helpers/excludedSecureShopOwnership.js',
    'client/src/pages/ComprehensiveAdminDashboard.js',
    'client/src/context/WorkshopConfigContext.js',
    'server/routes/adminExercises.js',
    'server/routes/postgresAdmin.js',
    'server/routes/postgresWorkshop.js',
    'server/database/postgres/workshopConfigRepository.js',
    'server/database/postgres/workshopProgressRepository.js',
    'server/database/postgres/identityRepository.js',
    'server/database/postgres/workshopPlatformSeed.js',
    'server/config/workshopCatalog.js',
    'package.json', 'package-lock.json',
    'client/package.json', 'client/package-lock.json',
    'client/index.html', 'client/vite.config.mjs',
}


def digest(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def encoded_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()


def validate_evidence_path(source, evidence_path, container_nonce):
    """Admit one fresh nonce-bound run directory in the checkout's private recovery root."""
    source, evidence_path = Path(source), Path(evidence_path)
    if source.is_symlink() or not source.is_dir() or source.resolve() != source:
        raise RuntimeError('exact current-main source required')
    if not re.fullmatch(r'[0-9a-f]{12}', container_nonce or ''):
        raise RuntimeError('current-main evidence nonce invalid')
    boundary = source / PRIVATE_EVIDENCE_RELATIVE
    expected = boundary / f'run-{container_nonce}'
    if not evidence_path.is_absolute() or evidence_path != expected:
        raise RuntimeError('current-main evidence must use exact private checkout path')
    cursor = source
    for part in PRIVATE_EVIDENCE_RELATIVE.parts:
        cursor /= part
        if cursor.is_symlink() or not cursor.is_dir():
            raise RuntimeError('current-main private evidence ancestry invalid')
        state = cursor.lstat()
        if state.st_uid != os.getuid() or state.st_mode & 0o077:
            raise RuntimeError('current-main private evidence ancestry must be owned and private')
    if os.path.lexists(evidence_path) and evidence_path.is_symlink():
        raise RuntimeError('current-main evidence root symlink forbidden')
    if os.path.lexists(evidence_path):
        raise RuntimeError('fresh current-main evidence root required')
    return evidence_path


def current_main_control_path(source, path, stem, suffix, container_nonce):
    source, path = Path(source), Path(path)
    boundary = source / PRIVATE_EVIDENCE_RELATIVE
    expected = boundary / f'{stem}-{container_nonce}.{suffix}'
    if path != expected:
        raise RuntimeError(f'current-main {stem} must use exact private checkout path')
    return path


def publish_launcher_pid(source, pid_path, container_nonce):
    pid_path = current_main_control_path(
        source, pid_path, 'launcher-pid', 'txt', container_nonce)
    descriptor = os.open(pid_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, f'{os.getpid()}\n'.encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return pid_path


def require_fresh_launch_authorization(source, grant_path, handle_path, container_nonce):
    grant_path = current_main_control_path(
        source, grant_path, 'grant', 'json', container_nonce)
    handle_path = current_main_control_path(
        source, handle_path, 'owner-handle', 'txt', container_nonce)
    if os.path.lexists(grant_path) or os.path.lexists(handle_path):
        raise RuntimeError('current-main launch authorization must be created by the live session')
    return grant_path, handle_path


def wait_for_launch_authorization(source, grant_path, handle_path, container_nonce,
                                  timeout_seconds=60, poll_seconds=.1):
    grant_path = current_main_control_path(
        source, grant_path, 'grant', 'json', container_nonce)
    handle_path = current_main_control_path(
        source, handle_path, 'owner-handle', 'txt', container_nonce)
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if os.path.lexists(grant_path) and os.path.lexists(handle_path):
            for path in (grant_path, handle_path):
                state = path.lstat()
                if path.is_symlink() or not path.is_file() or state.st_uid != os.getuid() \
                        or state.st_nlink != 1 or state.st_mode & 0o077:
                    raise RuntimeError('fresh private current-main launch authorization required')
            handle = handle_path.read_text().strip()
            grant = json.loads(grant_path.read_text())
            if not handle.isdecimal() or int(handle) <= 0 \
                    or grant.get('status') != 'granted' \
                    or grant.get('expectedLauncherPid') != os.getpid() \
                    or grant.get('expectedOwnerHandle') != int(handle) \
                    or grant.get('ownerHandle') is not None:
                raise RuntimeError('current-main launch authorization binding invalid')
            return int(handle)
        time.sleep(poll_seconds)
    raise RuntimeError('current-main launch authorization timeout')


def inventory(root):
    root = Path(root)
    if root.is_symlink() or not root.is_dir() or root.resolve() != root:
        raise RuntimeError('canonical installed inventory root required')
    result = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            item = Path(directory) / name
            relative = item.relative_to(root).as_posix()
            before = item.lstat()
            if item.is_symlink():
                resolved = item.resolve(strict=True)
                if not resolved.is_relative_to(root):
                    raise RuntimeError('installed dependency link escapes root')
                result[relative] = {'link': os.readlink(item)}
            elif item.is_dir():
                result[relative] = {'directory': True, 'mode': before.st_mode & 0o777}
            elif item.is_file():
                value = digest(item)
                after = item.lstat()
                if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != \
                        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                    raise RuntimeError('installed file changed during inventory')
                result[relative] = {'mode': before.st_mode & 0o777, 'sha256': value}
            else:
                raise RuntimeError('unsupported installed dependency type')
    return result


def source_inventory(source):
    source = Path(source)
    if source.is_symlink() or not source.is_dir() or source.resolve() != source:
        raise RuntimeError('exact current-main source required')
    result = {}
    for directory, dirs, files in os.walk(source, followlinks=False):
        relative_directory = Path(directory).relative_to(source)
        dirs[:] = [name for name in dirs if name not in {'__pycache__', '.pytest_cache'}]
        if relative_directory == Path('.'):
            dirs[:] = [name for name in dirs if name not in EXCLUDED_ROOTS and name != 'client'] + \
                (['client'] if 'client' in dirs else [])
        if relative_directory == Path('client'):
            dirs[:] = [name for name in dirs if name not in {'node_modules', 'build', 'coverage'}]
        if relative_directory.parts[:2] == ('server', 'logs'):
            dirs[:] = []
            continue
        if any((Path(directory) / name).is_symlink() for name in dirs):
            raise RuntimeError('current-main source directory links forbidden')
        for name in sorted(files):
            if name == '.DS_Store' or name.endswith(('.pyc', '.pyo')):
                continue
            item = Path(directory) / name
            relative = item.relative_to(source)
            if relative.parts[0] in EXCLUDED_ROOTS or 'node_modules' in relative.parts \
                    or relative.parts[:2] in (('client', 'build'), ('server', 'logs')) \
                    or (name.startswith('.env') and name != '.env.example'):
                continue
            if item.is_symlink() or not item.is_file():
                raise RuntimeError('current-main source links and special files forbidden')
            result[relative.as_posix()] = digest(item)
    return result


def capture(source, node, chromium, browser_root):
    source, node, chromium, browser_root = map(Path, (source, node, chromium, browser_root))
    sources = source_inventory(source)
    dependencies = {
        'root': inventory(source / 'node_modules'),
        'client': inventory(source / 'client/node_modules'),
    }
    dependency_links = {
        area: {name: row['link'] for name, row in rows.items() if 'link' in row}
        for area, rows in dependencies.items()
    }
    return {
        'cohort': COHORT, 'scope': SCOPE, 'mode': 'model-free',
        'workspace': str(source), 'actualExecution': False,
        'sourcePins': sources,
        'sourceFilesSha256': encoded_digest(sources),
        'dependencyInventory': dependencies,
        'dependencyFilesSha256': encoded_digest(dependencies),
        'dependencySymlinksSha256': encoded_digest(dependency_links),
        'runtimePins': {
            'python': {'path': str(Path(sys.executable).resolve()),
                       'sha256': digest(Path(sys.executable).resolve())},
            'node': {'path': str(node), 'sha256': digest(node), 'version': NODE_VERSION},
            'chromium': {'path': str(chromium), 'sha256': digest(chromium)},
        },
        'browserRoot': str(browser_root),
        'browserInventory': inventory(browser_root),
        'allowedInheritedEnvironment': ['PATH'],
    }


def validate(source, manifest_path, manifest_sha256, python_sha256,
             node, chromium, browser_root):
    source, manifest_path, node, chromium, browser_root = map(
        Path, (source, manifest_path, node, chromium, browser_root))
    manifest_stat = manifest_path.lstat()
    if manifest_path.is_symlink() or not manifest_path.is_file() \
            or manifest_stat.st_uid != os.getuid() or manifest_stat.st_nlink != 1 \
            or manifest_stat.st_mode & 0o077 or not 0 < manifest_stat.st_size <= 16 * 1024 * 1024 \
            or not re.fullmatch(r'[0-9a-f]{64}', manifest_sha256 or '') \
            or digest(manifest_path) != manifest_sha256:
        raise RuntimeError('current-main manifest identity mismatch')
    manifest = json.loads(manifest_path.read_text())
    fixed = {
        'cohort': COHORT, 'scope': SCOPE, 'mode': 'model-free',
        'workspace': str(source), 'actualExecution': False,
        'allowedInheritedEnvironment': ['PATH'],
    }
    if any(type(manifest.get(key)) is not type(value) or manifest.get(key) != value
           for key, value in fixed.items()):
        raise RuntimeError('current-main manifest boundary mismatch')
    observed = capture(source, node, chromium, browser_root)
    for key in ('sourcePins', 'sourceFilesSha256', 'dependencyInventory',
                'dependencyFilesSha256', 'dependencySymlinksSha256', 'runtimePins',
                'browserRoot', 'browserInventory'):
        if manifest.get(key) != observed[key]:
            raise RuntimeError(f'current-main manifest drift: {key}')
    required = REQUIRED_SOURCE | {
        path.relative_to(source).as_posix()
        for path in (source / 'db/postgres/identity-migrations').glob('*.sql')
    }
    if not required.issubset(manifest['sourcePins']):
        raise RuntimeError('current-main admin browser source closure incomplete')
    for area, name in (('root', 'pg/package.json'), ('root', 'puppeteer/package.json'),
                       ('client', 'vite/package.json')):
        if name not in manifest['dependencyInventory'][area]:
            raise RuntimeError(f'current-main dependency missing: {area}/{name}')
    node_pin = manifest['runtimePins']['node']
    if node_pin != {'path': str(node), 'sha256': NODE_SHA256, 'version': NODE_VERSION}:
        raise RuntimeError('current-main managed Node pin mismatch')
    python = Path(sys.executable).resolve()
    if not re.fullmatch(r'[0-9a-f]{64}', python_sha256 or '') \
            or digest(python) != python_sha256 \
            or manifest['runtimePins']['python'] != {'path': str(python), 'sha256': python_sha256}:
        raise RuntimeError('current-main running Python pin mismatch')
    if not chromium.is_relative_to(browser_root):
        raise RuntimeError('current-main Chromium must belong to captured browser root')
    return manifest


def verify_postflight(source, manifest_path, manifest_sha256, python_sha256, manifest,
                      node, chromium, browser_root):
    observed = validate(source, manifest_path, manifest_sha256, python_sha256,
        node, chromium, browser_root)
    if observed != manifest:
        raise RuntimeError('current-main manifest changed after admission')
    return True
