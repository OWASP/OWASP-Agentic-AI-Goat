"""Fail-closed identity checks for the private FinFlow candidate package."""

import hashlib
import json
import re
from pathlib import Path, PurePosixPath


MANIFEST_KIND = 'private_finflow_customer_policy_candidate'
MANIFEST_VERSION = 2
CANONICAL_GRANT = PurePosixPath('tasks/native-verification-slot.json')
APPROVED_SOURCE_FIXTURES = frozenset({
    'server/workshop_data/transactions/FF-001.json',
    'server/workshop_data/transactions/FF-002.json',
    'server/workshop_data/documents/statement-FF-001-2024.txt',
    'server/workshop_data/documents/statement-FF-002-2024.txt',
    'server/sensitive_files/traversal-fixtures/config/secrets.env',
    'server/sensitive_files/traversal-fixtures/config/llm_config.yml',
    'server/sensitive_files/traversal-fixtures/etc/passwd',
    'server/sensitive_files/logs/access.log',
    'server/sensitive_files/logs/error.log',
    'server/sensitive_files/logs/audit.log',
    'server/sensitive_files/logs/llm_requests.log',
})
_HEX_256 = re.compile(r'^[0-9a-f]{64}$')
_DENIED_PARTS = frozenset({
    '.git', 'node_modules', 'tasks', 'uploads', 'workshop_data',
    'vector-indexes', 'coverage', '.cache', '__pycache__',
})
_DENIED_SUFFIXES = (
    '.db', '.db-wal', '.db-shm', '.db-journal', '.sqlite', '.sqlite3', '.log',
)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def validate_staged_path(relative):
    """Return a normalized source path or reject private/runtime material."""
    if not isinstance(relative, str) or not relative:
        raise RuntimeError('candidate manifest path must be a non-empty string')
    candidate = PurePosixPath(relative)
    if candidate.is_absolute() or str(candidate) != relative or any(
            part in ('', '.', '..') for part in candidate.parts):
        raise RuntimeError(f'candidate manifest path is not normalized: {relative}')
    if relative in APPROVED_SOURCE_FIXTURES:
        return relative
    if any(part in _DENIED_PARTS for part in candidate.parts):
        raise RuntimeError(f'candidate manifest includes a private/runtime path: {relative}')
    if any(part.startswith('.env') for part in candidate.parts):
        raise RuntimeError(f'candidate manifest includes environment material: {relative}')
    if relative.startswith('server/sensitive_files/'):
        raise RuntimeError(f'candidate manifest includes an unapproved sensitive fixture: {relative}')
    if relative.endswith(_DENIED_SUFFIXES):
        raise RuntimeError(f'candidate manifest includes a runtime artifact: {relative}')
    return relative


def _is_within(path, root):
    return path == root or root in path.parents


def verified_source_file(root, relative):
    """Resolve one manifest leaf without allowing a symlink below source root."""
    root = Path(root).resolve()
    lexical = root / validate_staged_path(relative)
    try:
        resolved = lexical.resolve(strict=True)
    except (FileNotFoundError, RuntimeError) as error:
        raise RuntimeError(f'candidate source is missing: {relative}') from error
    if resolved != lexical or not _is_within(resolved, root) or not resolved.is_file():
        raise RuntimeError(f'candidate source path is unsafe: {relative}')
    return resolved


def verify_launch_roots(candidate_root, manifest_path, canonical_workspace,
                        grant_path, *, launcher_root):
    """Bind the running launcher to one private package and one real workspace."""
    raw_candidate = Path(candidate_root)
    raw_manifest = Path(manifest_path)
    raw_canonical = Path(canonical_workspace)
    if not raw_canonical.is_absolute():
        raise RuntimeError('canonical workspace must be supplied as an absolute path')
    if raw_candidate.is_symlink() or raw_manifest.is_symlink():
        raise RuntimeError('candidate source and manifest must not be symlinks')
    candidate_root = raw_candidate.resolve()
    manifest_path = raw_manifest.resolve()
    canonical_workspace = raw_canonical.resolve()
    launcher_root = Path(launcher_root).resolve()
    if candidate_root != launcher_root:
        raise RuntimeError('candidate source root is not the running launcher package')
    if manifest_path != candidate_root.parent / 'private-source-manifest.json':
        raise RuntimeError('candidate manifest must be the package manifest beside source')
    if candidate_root == canonical_workspace or _is_within(candidate_root, canonical_workspace) \
            or _is_within(canonical_workspace, candidate_root):
        raise RuntimeError('candidate source and canonical workspace must be disjoint')
    if not canonical_workspace.is_dir() or not (canonical_workspace / '.git').exists():
        raise RuntimeError('canonical workspace must be a Git working tree')
    if not (canonical_workspace / 'package.json').is_file():
        raise RuntimeError('canonical workspace package marker is missing')
    lexical_grant = canonical_workspace / CANONICAL_GRANT
    if lexical_grant.is_symlink():
        raise RuntimeError('canonical native grant must not be a symlink')
    expected_grant = lexical_grant.resolve()
    supplied_grant = Path(grant_path)
    if not supplied_grant.is_absolute():
        supplied_grant = canonical_workspace / supplied_grant
    if supplied_grant.resolve() != expected_grant or not expected_grant.is_file():
        raise RuntimeError('canonical native grant is required')
    if not manifest_path.is_file():
        raise RuntimeError('candidate manifest must be a regular package file')
    return candidate_root, manifest_path, canonical_workspace, expected_grant


def verify_candidate_source(root, manifest_path, granted_root,
                            granted_manifest_sha256, granted_hashes, *,
                            required_paths):
    """Verify that grant, manifest, candidate files and executable closure agree."""
    root = Path(root).resolve()
    manifest_path = Path(manifest_path).resolve()
    if not isinstance(granted_root, str) or root != Path(granted_root).resolve():
        raise RuntimeError('candidate source root differs from grant')
    if not isinstance(granted_manifest_sha256, str) \
            or sha256(manifest_path) != granted_manifest_sha256:
        raise RuntimeError('candidate manifest hash differs from grant')
    manifest = json.loads(manifest_path.read_text())
    if manifest.get('kind') != MANIFEST_KIND or manifest.get('version') != MANIFEST_VERSION:
        raise RuntimeError('candidate manifest kind/version is not supported')
    manifest_root = manifest.get('candidateSourceRoot')
    if not isinstance(manifest_root, str) or Path(manifest_root).resolve() != root:
        raise RuntimeError('candidate manifest source root differs')
    entries = manifest.get('files')
    if not isinstance(entries, list) or not entries:
        raise RuntimeError('candidate manifest files are required')
    paths = []
    declared = {}
    for row in entries:
        if not isinstance(row, dict) or set(row) != {'path', 'sha256', 'bytes'}:
            raise RuntimeError('candidate manifest file entry is malformed')
        relative = validate_staged_path(row.get('path'))
        expected = row.get('sha256')
        byte_length = row.get('bytes')
        if not isinstance(expected, str) or not _HEX_256.fullmatch(expected) \
                or not isinstance(byte_length, int) or isinstance(byte_length, bool) \
                or byte_length < 0:
            raise RuntimeError('candidate manifest file metadata is malformed')
        if relative in declared:
            raise RuntimeError('candidate manifest contains duplicate paths')
        paths.append(relative)
        declared[relative] = expected
    if paths != sorted(paths):
        raise RuntimeError('candidate manifest paths must be sorted')
    required = sorted(validate_staged_path(path) for path in required_paths)
    if paths != required:
        raise RuntimeError('candidate manifest differs from executable staging closure')
    if manifest.get('fileCount') != len(paths):
        raise RuntimeError('candidate manifest file count differs')
    if not isinstance(granted_hashes, dict) or declared != granted_hashes:
        raise RuntimeError('candidate grant source hashes differ')
    for row in entries:
        relative = row['path']
        path = verified_source_file(root, relative)
        if sha256(path) != row['sha256'] or path.stat().st_size != row['bytes']:
            raise RuntimeError(f'candidate source hash mismatch: {relative}')
    return declared
