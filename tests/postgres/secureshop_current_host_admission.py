"""Explicit repository-local pins for disposable SecureShop qualification.

The caller still verifies the Docker daemon and image identities immediately
before creating any resources. This module admits only a dedicated socket and
exact executable bytes inside the current checkout.
"""

import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess


SHA256 = re.compile(r'[0-9a-f]{64}\Z')
IMAGE_ID = re.compile(r'sha256:[0-9a-f]{64}\Z')
DAEMON_ID = re.compile(r'[0-9a-f-]{16,}\Z')
PROFILE = re.compile(r'(?:owasp-ai-goat|goat)-[a-z0-9]+(?:-[a-z0-9]+)*\Z')
NODE_VERSION = 'v26.10.0'


def _exact_executable(raw, pinned_sha256, label):
    if not isinstance(pinned_sha256, str) or not SHA256.fullmatch(pinned_sha256):
        raise RuntimeError(f'Exact {label} SHA256 pin required')
    if not isinstance(raw, str):
        raise RuntimeError(f'Canonical {label} executable required')
    path = Path(raw)
    if not path.is_absolute() or path.is_symlink() or path.resolve() != path or not path.is_file():
        raise RuntimeError(f'Canonical {label} executable required')
    mode = path.stat().st_mode
    if not stat.S_ISREG(mode) or not mode & 0o111:
        raise RuntimeError(f'Executable {label} regular file required')
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != pinned_sha256:
        raise RuntimeError(f'{label} digest mismatch')
    return path


def validate_current_host(*, workspace, profile, docker_host, node, node_sha256,
                          docker, docker_sha256, daemon_id, image_id,
                          uid=None, version_runner=subprocess.run):
    """Validate an opt-in local authority, returning pins safe to record.

    ``uid`` permits offline tests. No Docker command is run here, and no
    environment-provided HOME or Docker context is trusted.
    """
    current_uid = os.getuid() if uid is None else uid
    root = Path(workspace)
    if not isinstance(profile, str) or not PROFILE.fullmatch(profile):
        raise RuntimeError('Explicit dedicated qualification profile required')
    if not root.is_absolute() or root.is_symlink() or root.resolve() != root \
            or not root.is_dir() or root.stat().st_uid != current_uid:
        raise RuntimeError('Canonical current checkout required')
    socket = root / '.qualification' / profile / 'docker.sock'
    expected_host = 'unix://' + str(socket)
    if docker_host != expected_host:
        raise RuntimeError('Exact current-user dedicated Docker host required')
    for directory in (socket.parent.parent, socket.parent):
        if directory.is_symlink() or not directory.is_dir() or directory.stat().st_uid != current_uid:
            raise RuntimeError('Current-user qualification profile ownership required')
    if socket.is_symlink() or not socket.exists():
        raise RuntimeError('Exact owned Docker socket required')
    socket_stat = socket.stat()
    if not stat.S_ISSOCK(socket_stat.st_mode) or socket_stat.st_uid != current_uid:
        raise RuntimeError('Exact owned Docker socket required')
    node_path = _exact_executable(node, node_sha256, 'node')
    docker_path = _exact_executable(docker, docker_sha256, 'docker')
    if not node_path.is_relative_to(root) or not docker_path.is_relative_to(root):
        raise RuntimeError('Repository-contained executable authority required')
    if not isinstance(daemon_id, str) or not DAEMON_ID.fullmatch(daemon_id):
        raise RuntimeError('Exact Docker daemon identity required')
    if not isinstance(image_id, str) or not IMAGE_ID.fullmatch(image_id):
        raise RuntimeError('Exact PostgreSQL image ID required')
    version = version_runner([str(node_path), '--version'], check=True, capture_output=True,
                             text=True, timeout=10, env={'PATH': str(node_path.parent)}).stdout.strip()
    if version != NODE_VERSION:
        raise RuntimeError('Managed Node 26.10 required')
    return {
        'profile': profile, 'dockerHost': expected_host,
        'node': str(node_path), 'nodeSha256': node_sha256,
        'docker': str(docker_path), 'dockerSha256': docker_sha256,
        'daemonId': daemon_id, 'postgresImageId': image_id,
    }


def evidence_parent(workspace, requested=None, *, uid=None):
    """Return the sole repository-local evidence parent without creating it."""
    current_uid = os.getuid() if uid is None else uid
    root = Path(workspace)
    if not root.is_absolute() or root.is_symlink() or root.resolve() != root \
            or not root.is_dir() or root.stat().st_uid != current_uid:
        raise RuntimeError('Canonical current checkout required')
    destination = root / 'tasks' / 'qualification'
    if requested is not None:
        if not isinstance(requested, str) or not requested.startswith('/') \
                or any(part in ('.', '..') for part in requested.split('/')) \
                or requested != str(destination):
            raise RuntimeError('Current-host evidence must use repository tasks/qualification')
    for path in (root / 'tasks', destination):
        if path.is_symlink():
            raise RuntimeError('Repository evidence path must not contain a symlink')
        if path.exists() and (not path.is_dir() or path.stat().st_uid != current_uid):
            raise RuntimeError('Owned repository evidence directory required')
    if not (root / 'tasks').is_dir():
        raise RuntimeError('Repository tasks directory required')
    if destination.exists() and destination.stat().st_mode & 0o777 != 0o700:
        raise RuntimeError('Private evidence parent required')
    return destination
