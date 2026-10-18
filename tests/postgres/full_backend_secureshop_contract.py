"""Import-inert admission helpers for the opt-in full SecureShop cohort."""
import json
import os
import re
from pathlib import Path


SHA256 = re.compile(r'^[a-f0-9]{64}$')
FIXTURE_NAME = re.compile(r'^fixture_[a-z][a-z0-9_]{0,31}$')
SECURESHOP_MODEL_DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'
RESERVED_PORTS = {5432, 8081, 8082, 11434}
SECURESHOP_REVIEW_OUTCOMES = frozenset({
    'attack_success', 'defensive_control', 'observed_outcome'
})


def _require(condition, message):
    if not condition:
        raise RuntimeError(message)


def _endpoint(value, *, model=False):
    _require(type(value) is dict and set(value) == {'host', 'port'},
             'SecureShop endpoint schema mismatch')
    port = value.get('port')
    _require(value.get('host') == '127.0.0.1' and type(port) is int
             and 1 <= port <= 65535, 'SecureShop endpoint mismatch')
    if model:
        _require(port == 11434, 'SecureShop model endpoint mismatch')
    else:
        _require(port not in RESERVED_PORTS, 'SecureShop reserved endpoint forbidden')
    return value


def validate_secureshop_arguments(enabled, *, rendered, mcp_enabled, model_digest,
                                  renderer_root, renderer_manifest_sha256,
                                  control, owner_handle, review_outcome):
    """Reject partial or ambient cohort pins before any resource action."""
    pins = (model_digest, renderer_root, renderer_manifest_sha256, control, owner_handle,
            review_outcome)
    if not enabled:
        _require(not rendered or all(value is None for value in pins),
                 'SecureShop pins require explicit cohort')
        _require(all(value is None for value in pins),
                 'SecureShop pins require explicit cohort')
        return None
    _require(rendered is True and mcp_enabled is False,
             'SecureShop requires an exclusive rendered cohort')
    _require(model_digest == SECURESHOP_MODEL_DIGEST,
             'Pinned SecureShop model required')
    _require(isinstance(renderer_root, str) and renderer_root
             and isinstance(control, str) and control
             and isinstance(renderer_manifest_sha256, str)
             and SHA256.fullmatch(renderer_manifest_sha256),
             'Complete SecureShop renderer and control pins required')
    _require(isinstance(owner_handle, str) and owner_handle.isdecimal()
             and int(owner_handle) > 0, 'Returned SecureShop owner handle required')
    _require(review_outcome in SECURESHOP_REVIEW_OUTCOMES,
             'Explicit reviewed SecureShop moderation outcome required')
    return True


def validate_secureshop_configuration(enabled, *, rendered, mcp_enabled,
                                      model_digest, endpoints):
    """Validate the exact loopback endpoint manifest consumed by Node admission."""
    if not enabled:
        _require(model_digest is None and endpoints is None,
                 'SecureShop configuration requires explicit cohort')
        return None
    _require(rendered is True and mcp_enabled is False
             and model_digest == SECURESHOP_MODEL_DIGEST,
             'Pinned rendered SecureShop configuration required')
    _require(type(endpoints) is dict
             and set(endpoints) == {'version', 'postgres', 'agentHost', 'model', 'fixtures'}
             and type(endpoints.get('version')) is int and endpoints['version'] == 1
             and type(endpoints.get('fixtures')) is list
             and len(endpoints['fixtures']) <= 8,
             'SecureShop endpoint manifest mismatch')
    postgres = _endpoint(endpoints['postgres'])
    agent_host = _endpoint(endpoints['agentHost'])
    model = _endpoint(endpoints['model'], model=True)
    ports = {postgres['port'], agent_host['port'], model['port']}
    _require(len(ports) == 3, 'SecureShop endpoint collision')
    names = set()
    for fixture in endpoints['fixtures']:
        _require(type(fixture) is dict and set(fixture) == {'name', 'host', 'port'}
                 and isinstance(fixture.get('name'), str)
                 and FIXTURE_NAME.fullmatch(fixture['name'])
                 and fixture['name'] not in names,
                 'SecureShop fixture endpoint mismatch')
        endpoint = _endpoint({'host': fixture['host'], 'port': fixture['port']})
        _require(endpoint['port'] not in ports, 'SecureShop fixture endpoint collision')
        names.add(fixture['name'])
        ports.add(endpoint['port'])
    return endpoints


def _strict_json(path):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise RuntimeError('Duplicate SecureShop control key')
            result[key] = value
        return result
    try:
        return json.loads(path.read_text(), object_pairs_hook=pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError('Invalid SecureShop control') from error


def consume_full_secureshop_control(control, expected, source, evidence):
    """Atomically consume one private grant bound to every parsed launcher argument."""
    _require(type(expected) is dict and expected, 'SecureShop control binding required')
    control, source, evidence = Path(control), Path(source), Path(evidence)
    repository = Path(__file__).resolve().parents[2]
    try:
        stat = control.lstat()
        valid = (control.is_absolute() and control.resolve() == control
                 and not control.is_symlink() and control.is_file()
                 and stat.st_uid == os.getuid() and not stat.st_mode & 0o077
                 and 0 < stat.st_size <= 65536
                 and not any(control.is_relative_to(boundary)
                             for boundary in (source.parent, evidence, repository)))
    except OSError:
        valid = False
    _require(valid, 'Private external full SecureShop control required')
    lock = control.with_name(control.name + '.consume-lock')
    pending = control.with_name(control.name + '.pending')
    lock.mkdir(mode=0o700)
    try:
        value = _strict_json(control)
        _require(type(value) is dict
                 and value.get('scope') == 'full_backend_secureshop'
                 and value.get('status') == 'granted'
                 and type(value.get('allowedLaunches')) is int
                 and value['allowedLaunches'] == 1
                 and all(key in value and value[key] == wanted
                         for key, wanted in expected.items()),
                 'Full SecureShop control binding mismatch')
        value.update(status='consumed', launcherPid=os.getpid())
        with pending.open('x') as output:
            os.chmod(pending, 0o600)
            json.dump(value, output, sort_keys=True)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(pending, control)
        directory = os.open(control.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if pending.exists():
            pending.unlink()
        lock.rmdir()
