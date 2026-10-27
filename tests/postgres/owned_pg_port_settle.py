"""Bounded observation of one newly attached, owner-verified PG bridge port.

The caller must first verify the Docker daemon, exact owned network/container
attachment, and container layout. This module only reads strict inventory; it
does not normalize or publish an inventory snapshot.
"""
import hashlib
import json
import math
import re
import time


_HEX64 = re.compile(r'^[0-9a-f]{64}$')
_VETH = re.compile(r'^veth[0-9a-f]+$')
_MAC = re.compile(r'^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$')


def _port(inventory, network_id, container_id):
    if not isinstance(inventory, str) or not 0 < len(inventory.encode()) <= 2 * 1024 * 1024:
        raise RuntimeError('Bounded PostgreSQL inventory required')
    prefix, marker, payload = inventory.partition('\nNETWORK\n')
    if not marker or '\nNETWORK\n' in payload:
        raise RuntimeError('PostgreSQL inventory network section invalid')
    _before, marker, containers = prefix.partition('\nCONTAINERS\n')
    if not marker or '\nVOLUMES\n' not in containers:
        raise RuntimeError('PostgreSQL inventory container section invalid')
    rows = containers.split('\nVOLUMES\n', 1)[0].splitlines()
    if rows.count(container_id) != 1:
        raise RuntimeError('Owned PostgreSQL container missing or duplicated in inventory')
    snapshot = json.loads(payload)
    links = snapshot.get('links')
    if not isinstance(links, list) or len(links) > 4096:
        raise RuntimeError('PostgreSQL network links invalid')
    bridge_name = 'br-' + network_id[:12]
    bridges = [row for row in links if row.get('ifname') == bridge_name]
    if len(bridges) != 1 or bridges[0].get('linkinfo', {}).get('info_kind') != 'bridge':
        raise RuntimeError('Exact owned PostgreSQL bridge missing')
    bridge = bridges[0]
    if (type(bridge.get('ifindex')) is not int or bridge['ifindex'] <= 0
            or not isinstance(bridge.get('address'), str) or not _MAC.fullmatch(bridge['address'])):
        raise RuntimeError('Owned PostgreSQL bridge identity invalid')
    ports = [row for row in links if row.get('master') == bridge_name]
    if len(ports) != 1:
        raise RuntimeError('Exact owned PostgreSQL bridge port required')
    row = ports[0]
    info = row.get('linkinfo') or {}
    data = info.get('info_slave_data') or {}
    timer = data.get('forward_delay_timer')
    if (not isinstance(row.get('ifindex'), int) or isinstance(row['ifindex'], bool) or row['ifindex'] <= 0
            or not isinstance(row.get('ifname'), str) or not _VETH.fullmatch(row['ifname'])
            or not isinstance(row.get('address'), str) or not _MAC.fullmatch(row['address'])
            or not isinstance(row.get('link_index'), int) or isinstance(row['link_index'], bool) or row['link_index'] <= 0
            or not isinstance(row.get('link_netnsid'), int) or isinstance(row['link_netnsid'], bool)
            or info.get('info_kind') != 'veth' or info.get('info_slave_kind') != 'bridge'
            or data.get('state') not in ('blocking', 'listening', 'learning', 'forwarding')
            or type(timer) not in (int, float) or not math.isfinite(timer) or timer < 0):
        raise RuntimeError('Owned PostgreSQL bridge port shape invalid')
    identity = (bridge['ifindex'], bridge['address'], row['ifindex'], row['ifname'],
                row['address'], row['link_index'], row['link_netnsid'])
    return identity, timer, data['state']


def wait_owned_pg_port_settled(read_inventory, *, network_id, container_id,
                               now=time.monotonic, sleep=time.sleep,
                               timeout_seconds=15.0, interval_seconds=0.1):
    """Return a raw-snapshot digest only after this exact port reaches zero.

    No normalization, Docker mutation, producer execution, or broad bridge wait
    happens here. The producer must acquire its own strict baseline afterward.
    """
    if (not callable(read_inventory) or not callable(now) or not callable(sleep)
            or not isinstance(network_id, str) or not _HEX64.fullmatch(network_id)
            or not isinstance(container_id, str) or not _HEX64.fullmatch(container_id)
            or type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 30
            or type(interval_seconds) not in (int, float) or not 0 < interval_seconds <= 1):
        raise RuntimeError('Exact bounded PostgreSQL port wait required')
    deadline = now() + timeout_seconds
    first_identity = None
    for attempt in range(math.ceil(timeout_seconds / interval_seconds) + 2):
        remaining = deadline - now()
        if remaining <= 0:
            break
        raw = read_inventory(remaining)
        identity, timer, state = _port(raw, network_id, container_id)
        if first_identity is None:
            first_identity = identity
        elif identity != first_identity:
            raise RuntimeError('Owned PostgreSQL bridge port changed while waiting')
        if timer == 0 and state == 'forwarding' and now() <= deadline:
            return {'version': 1, 'networkId': network_id, 'containerId': container_id,
                    'portIfindex': identity[2], 'portIfname': identity[3],
                    'polls': attempt + 1,
                    'settledInventorySha256': hashlib.sha256(raw.encode()).hexdigest()}
        remaining = deadline - now()
        if remaining <= 0:
            break
        sleep(min(interval_seconds, remaining))
    raise RuntimeError('Owned PostgreSQL bridge port did not settle before deadline')
