"""Exact disposable Listings resource admission/cleanup; commands are injected."""
import hashlib
import json
import subprocess
import re

from sql_nosql_docker_ownership import verify_daemon

HEX = re.compile(r'^[a-f0-9]{64}$')


def inspect(command, kind, name):
    parts = ['inspect', '--type', 'container', name] if kind == 'container' else [kind, 'inspect', name]
    result = command(parts)
    if result.returncode:
        absent = {
            'container': [f'Error: No such object: {name}', f'Error: No such container: {name}',
                          f'Error response from daemon: No such container: {name}'],
            'network': [f'Error response from daemon: network {name} not found', f'Error: No such network: {name}'],
            'volume': [f'Error response from daemon: get {name}: no such volume',
                       f'Error response from daemon: no such volume: {name}'],
        }
        if result.returncode == 1 and result.stderr.strip() in absent[kind]:
            return None
        raise RuntimeError('Listings resource absence unavailable')
    rows = json.loads(result.stdout)
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise RuntimeError('Listings resource inspection invalid')
    return rows[0]


def owned(command, state, kind):
    row = inspect(command, kind, state[kind])
    if row is None:
        if kind == 'container' and state.get('containerId') and inspect(command, kind, state['containerId']) is not None:
            raise RuntimeError('Listings container was renamed')
        return None
    labels = row.get('Config', {}).get('Labels') if kind == 'container' else row.get('Labels')
    expected_name = '/' + state[kind] if kind == 'container' else state[kind]
    if row.get('Name') != expected_name or not isinstance(labels, dict) or any(
            labels.get(k) != v for k, v in state['labels'].items()):
        raise RuntimeError('Refusing foreign Listings resource')
    if kind in ('container', 'network'):
        identifier = row.get('Id', '')
        if not HEX.fullmatch(identifier) or state.get(kind + 'Id', identifier) != identifier:
            raise RuntimeError('Listings resource identity changed')
        state[kind + 'Id'] = identifier
    if kind == 'container':
        host = row.get('HostConfig', {})
        mounts = row.get('Mounts')
        packaged = state.get('packaged') is True
        bindings = {} if packaged else {'8095/tcp': [{'HostIp': '127.0.0.1', 'HostPort': state['port']}]}
        if (row.get('Image') != state['image'] or row.get('Config', {}).get('User') != '10001:10001'
                or host.get('NetworkMode') != state['network'] or host.get('ReadonlyRootfs') is not True
                or host.get('Privileged') is not False or host.get('Memory') != 536870912
                or host.get('NanoCpus') != 1000000000 or host.get('PidsLimit') != 128
                or host.get('CapDrop') != ['ALL'] or host.get('CapAdd') not in (None, [])
                or set(host.get('SecurityOpt') or []) != {'apparmor=' + state['profile']['name'], 'seccomp=unconfined'}
                or host.get('Tmpfs') != {'/tmp': 'rw,nosuid,nodev,noexec,size=16m'}
                or (host.get('PortBindings') or {}) != bindings or not isinstance(mounts, list) or len(mounts) != 1
                or mounts[0].get('Type') != 'volume' or mounts[0].get('Name') != state['volume']
                or mounts[0].get('Destination') != '/journal' or mounts[0].get('RW') is not True
                or mounts[0].get('Source') != state.get('volumeMountpoint')):
            raise RuntimeError('Listings container resources changed')
        environment = row.get('Config', {}).get('Env')
        keys = ('LISTINGS_PROFILE',) if packaged else ('LISTINGS_MANAGER_ENABLED', 'LISTINGS_PROFILE', 'LISTINGS_PUBLIC_ORIGIN', 'LISTINGS_CONTROL_TOKEN')
        values = [value for value in environment or [] if isinstance(value, str) and value.split('=', 1)[0] in keys]
        if (len(values) != len(keys) or len({v.split('=', 1)[0] for v in values}) != len(keys)
                or hashlib.sha256('\n'.join(sorted(values)).encode()).hexdigest() != state.get('environmentSha256')):
            raise RuntimeError('Listings manager environment changed')
        networks = row.get('NetworkSettings', {}).get('Networks')
        if not isinstance(networks, dict) or set(networks) - {state['network']}:
            raise RuntimeError('Listings foreign container endpoint')
        if networks and not packaged and networks[state['network']].get('NetworkID') != state.get('networkId'):
            raise RuntimeError('Listings network identity changed')
        if packaged and (row.get('Config', {}).get('Entrypoint') != ['node']
                or row.get('Config', {}).get('Cmd') != ['/app/tests/fixtures/secureshopOwnedListingsPackaged.native.cjs']
                or row.get('NetworkSettings', {}).get('Ports') not in (None, {})):
            raise RuntimeError('Listings packaged fixture identity changed')
    elif kind == 'network':
        endpoints = row.get('Containers')
        if (row.get('Driver') != 'bridge' or row.get('Internal') is not False
                or row.get('Options') not in (None, {}) or not isinstance(endpoints, dict)
                or set(endpoints) - ({state['containerId']} if state.get('containerId') else set())):
            raise RuntimeError('Listings network resources changed')
    else:
        point = row.get('Mountpoint')
        if (row.get('Driver') != 'local' or row.get('Scope') != 'local'
                or row.get('Options') not in (None, {}) or not isinstance(point, str) or not point.startswith('/')
                or state.get('volumeMountpoint', point) != point):
            raise RuntimeError('Listings volume identity changed')
        state['volumeMountpoint'] = point
    return row


def no_foreign_attachments(command, state, allow_owned=False):
    result = command(['ps', '-aq', '--no-trunc'])
    ids = result.stdout.split()
    if result.returncode or len(ids) > 4096 or len(set(ids)) != len(ids) or any(not HEX.fullmatch(i) for i in ids):
        raise RuntimeError('Listings attachment inventory unavailable')
    for identifier in ids:
        row = inspect(command, 'container', identifier)
        if row is None:
            continue
        if allow_owned and identifier == state.get('containerId'):
            continue
        networks = row.get('NetworkSettings', {}).get('Networks')
        mounts = row.get('Mounts')
        status = row.get('State')
        if not isinstance(networks, dict) or not isinstance(mounts, list) or not isinstance(status, dict) or type(status.get('Running')) is not bool:
            raise RuntimeError('Listings attachment inventory invalid')
        profile = row.get('AppArmorProfile')
        security = row.get('HostConfig', {}).get('SecurityOpt') or []
        if ((state['network'] != 'none' and state['network'] in networks)
                or (state.get('networkId') and any(n.get('NetworkID') == state['networkId'] for n in networks.values()))
                or any(m.get('Type') == 'volume' and m.get('Name') == state['volume'] for m in mounts)
                or profile == state['profile']['name']
                or isinstance(profile, str) and profile.startswith(state['profile']['name'] + '//')
                or 'apparmor=' + state['profile']['name'] in security):
            raise RuntimeError('Listings resources attached to another container')


def capture_container(command, state):
    """Recover create acknowledgement only from exact labeled name and resources."""
    verify_daemon(command, state['daemon'])
    # Capture ID before checking the bridge's endpoint set.
    row = inspect(command, 'container', state['container'])
    if row is None:
        raise RuntimeError('Listings manager creation unconfirmed')
    candidate = row.get('Id', '')
    if not HEX.fullmatch(candidate) or state.get('containerId', candidate) != candidate:
        raise RuntimeError('Listings container identity changed')
    state['containerId'] = candidate
    if state.get('packaged') is not True:
        owned(command, state, 'network')
    owned(command, state, 'volume')
    row = owned(command, state, 'container')
    no_foreign_attachments(command, state, allow_owned=True)
    return row


def cleanup(command, state, remove_profile, persist=lambda: None):
    """Preflight the whole owned set, then remove by exact captured identity."""
    verify_daemon(command, state['daemon'])
    attempted = state.get('attempted', [])
    # A lost run response may still have created a labeled container.
    if 'container' in attempted:
        row = inspect(command, 'container', state['container'])
        if row is not None:
            capture_container(command, state)
            persist()
        elif state.get('containerId') and inspect(command, 'container', state['containerId']) is not None:
            raise RuntimeError('Listings container was renamed')
    for kind in ('network', 'volume'):
        if kind in attempted:
            owned(command, state, kind)
    no_foreign_attachments(command, state, allow_owned=True)
    result = {}
    for kind in ('container', 'volume', 'network'):
        if kind not in attempted:
            continue
        verify_daemon(command, state['daemon'])
        row = owned(command, state, kind)
        if row is not None:
            if kind != 'container':
                no_foreign_attachments(command, state)
            target = row['Id'] if kind in ('container', 'network') else row['Name']
            # A lost removal ACK is resolved solely by exact absence below.
            try:
                command(['rm', '--force', target] if kind == 'container' else [kind, 'rm', target])
            except (TimeoutError, OSError, subprocess.TimeoutExpired):
                pass
            if owned(command, state, kind) is not None:
                raise RuntimeError('Listings resource removal unconfirmed')
        result[kind + 'Absent'] = True
        persist()
    if 'profile' in attempted:
        verify_daemon(command, state['daemon'])
        no_foreign_attachments(command, state)
        remove_profile(state['profile'])
        result['profileAbsent'] = True
    return result
