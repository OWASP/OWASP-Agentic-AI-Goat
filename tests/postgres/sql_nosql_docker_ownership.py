"""Injected-command Docker identity/ownership checks; importing never runs Docker."""
import json
import re

IMAGE = re.compile(r'^sha256:[a-f0-9]{64}$')
CONTAINER = re.compile(r'^[a-f0-9]{64}$')


def verify_daemon(command, expected):
    if not isinstance(expected, str) or not expected.strip():
        raise RuntimeError('Expected Docker daemon identity required')
    response = command(['info', '--format', '{{.ID}}'])
    if response.returncode or response.stdout.strip() != expected:
        raise RuntimeError('Docker daemon identity mismatch')


def verify_image(command, expected):
    if not isinstance(expected, str) or not IMAGE.fullmatch(expected):
        raise RuntimeError('Exact PostgreSQL sha256 image required')
    response = command(['image', 'inspect', '--format', '{{.Id}}', expected])
    if response.returncode or response.stdout.strip() != expected:
        raise RuntimeError('Local PostgreSQL image identity mismatch')


def inspect_owned(command, *, name, labels, image, captured_id=None):
    response = command(['inspect', '--type', 'container', name])
    if response.returncode:
        lines = response.stderr.strip().splitlines()
        if len(lines) == 1 and lines[0] in (f'Error: No such object: {name}', f'Error: No such container: {name}',
                                           f'Error response from daemon: No such container: {name}'):
            return None
        raise RuntimeError('Container identity could not be established')
    try:
        rows = json.loads(response.stdout)
        if not isinstance(rows, list) or len(rows) != 1:
            raise ValueError()
        row = rows[0]
        identifier = row['Id']
        if not CONTAINER.fullmatch(identifier) or row['Name'] != '/' + name or row['Image'] != image:
            raise ValueError()
        if captured_id is not None and identifier != captured_id:
            raise ValueError()
        actual_labels = row['Config']['Labels']
        if not isinstance(actual_labels, dict) or not labels or any(actual_labels.get(key) != value for key, value in labels.items()):
            raise ValueError()
        return row
    except (ValueError, KeyError, TypeError):
        raise RuntimeError('Refusing unowned or mismatched container') from None


def validate_container_layout(row):
    try:
        host = row['HostConfig']
        if (host['Tmpfs'] != {'/var/lib/postgresql': 'rw,size=268435456'} or row['Mounts'] != []
                or host['Memory'] != 536870912 or host['NanoCpus'] != 2000000000 or host['PidsLimit'] != 256):
            raise ValueError()
        ports = row['NetworkSettings']['Ports']
        if set(ports) != {'5432/tcp'} or len(ports['5432/tcp']) != 1:
            raise ValueError()
        binding = ports['5432/tcp'][0]
        if binding['HostIp'] != '127.0.0.1' or not str(binding['HostPort']).isdigit() or not 1 <= int(binding['HostPort']) <= 65535:
            raise ValueError()
        return int(binding['HostPort'])
    except (ValueError, KeyError, TypeError):
        raise RuntimeError('Container storage or loopback binding mismatch') from None


def cleanup_owned(command, *, daemon_id, name, labels, image, captured_id=None):
    verify_daemon(command, daemon_id)
    row = inspect_owned(command, name=name, labels=labels, image=image, captured_id=captured_id)
    if row is None:
        return {'status': 'absent', 'containerId': captured_id}
    identifier = row['Id']
    response = command(['rm', '--force', '--volumes', identifier])
    if response.returncode:
        raise RuntimeError('Owned container removal failed')
    # Inspect exact name again: mismatched replacement must not be removed.
    remaining = inspect_owned(command, name=name, labels=labels, image=image, captured_id=identifier)
    if remaining is not None:
        raise RuntimeError('Owned container absence not verified')
    return {'status': 'removed_absence_verified', 'containerId': identifier}
