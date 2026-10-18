"""Reviewed dependency authority for the DPI rendered fixture, never installation."""
import hashlib
from pathlib import Path

NAMES = frozenset(['package.json', 'package-lock.json', 'node_modules/.package-lock.json',
                  'client/package.json', 'client/package-lock.json', 'client/node_modules/.package-lock.json'])

def validate_dpi_dependency_authority(root, supplied, authority):
    if not isinstance(authority, dict) or set(authority) != {'version', 'root', 'sha256'} or authority['version'] != 1:
        raise ValueError('Invalid DPI dependency authority')
    if not isinstance(authority['root'], str) or not isinstance(supplied, dict) or set(supplied) != NAMES:
        raise ValueError('Complete six-hash DPI dependency inventory required')
    approved = authority['sha256']
    if not isinstance(approved, dict) or set(approved) != NAMES or supplied != approved:
        raise ValueError('DPI dependency inventory differs from reviewed authority')
    if any(not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value) for value in supplied.values()):
        raise ValueError('Invalid DPI dependency hash')
    root = Path(root).resolve(strict=True)
    if root != Path(authority['root']).resolve(strict=True):
        raise ValueError('Unreviewed DPI dependency root')
    for name in sorted(NAMES):
        file = root / name
        if not file.is_file() or not file.resolve(strict=True).is_relative_to(root):
            raise ValueError('DPI dependency file missing or escaped')
        if hashlib.sha256(file.read_bytes()).hexdigest() != supplied[name]:
            raise ValueError('DPI dependency file hash mismatch: ' + name)
    return True
