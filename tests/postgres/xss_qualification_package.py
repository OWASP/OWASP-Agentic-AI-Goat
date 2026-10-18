"""Read-only full package verification for the isolated XSS qualification runner."""
import hashlib
import json
from pathlib import Path
from full_backend_auth_contract import inventory

SCOPE = 'xss_reflected_rendered'


def package_inventory(source):
    source = Path(source)
    result = inventory(source)
    for name in result['files']:
        if (source / name).stat().st_nlink != 1:
            raise RuntimeError('Hardlinked package file forbidden')
    result['executables'] = sorted(name for name in result['files']
                                   if (source / name).stat().st_mode & 0o111)
    return result


def verify_copy(source, manifest):
    expected_keys = {'version', 'scope', 'files', 'directories', 'symlinks', 'executables'}
    if type(manifest) is not dict or set(manifest) != expected_keys \
            or manifest['version'] != 1 or manifest['scope'] != SCOPE:
        raise RuntimeError('Full XSS package manifest required')
    actual = package_inventory(source)
    if any(manifest[key] != value for key, value in actual.items()):
        raise RuntimeError('Full XSS package inventory mismatch')
    return actual


def validate_package(package, manifest_path, expected_sha256):
    package, manifest_path = Path(package), Path(manifest_path)
    if not package.is_absolute() or package.resolve() != package or package.is_symlink() \
            or not package.is_dir() or package.stat().st_mode & 0o222:
        raise RuntimeError('Immutable exact package directory required')
    if manifest_path.parent != package or manifest_path.is_symlink() \
            or not manifest_path.is_file() or manifest_path.stat().st_mode & 0o222 \
            or manifest_path.stat().st_nlink != 1 or manifest_path.stat().st_size > 32 * 1024 * 1024:
        raise RuntimeError('Immutable bounded manifest required')
    raw = manifest_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise RuntimeError('XSS package manifest digest mismatch')
    manifest = json.loads(raw)
    verify_copy(package / 'source', manifest)
    return manifest
