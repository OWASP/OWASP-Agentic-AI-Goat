"""Read-only resources for the opt-in full SecureShop cohort. Import inert."""
import errno
import time
import hashlib
import http.client
import json
import os
import re
import socket
from pathlib import Path


SHA256 = re.compile(r'^[a-f0-9]{64}$')
ARTIFACT = re.compile(r'^[A-Za-z0-9_-]+\.c?js$')
MODEL_NAME = 'llama3.1:8b'
MODEL_RESPONSE_LIMIT = 1024 * 1024
PORT_RESERVATION_ATTEMPTS = 32
RESERVED_PORTS = {5432, 8081, 8082, 11434}
RENDERER_SOURCE = 'client/src/pages/secureshop/components/ReviewCard.jsx'


def _require(condition, message):
    if not condition:
        raise RuntimeError(message)


def _digest(value):
    return hashlib.sha256(value).hexdigest()


def _strict_json(data, label):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise RuntimeError('Duplicate ' + label + ' key')
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError('Invalid ' + label) from error


def _canonical_directory(value, *, writable):
    path = Path(value)
    try:
        stat = path.lstat()
        valid = (path.is_absolute() and path.resolve() == path and not path.is_symlink()
                 and path.is_dir() and stat.st_uid == os.getuid()
                 and (stat.st_mode & 0o777 == 0o700 if writable else not stat.st_mode & 0o222))
    except OSError:
        valid = False
    _require(valid, 'Exact owned renderer boundary required')
    return path


def _inside(child, parent):
    return child != parent and child.is_relative_to(parent)


def _immutable_file(path, maximum):
    try:
        stat = path.lstat()
        valid = (path.resolve() == path and not path.is_symlink() and path.is_file()
                 and stat.st_uid == os.getuid() and not stat.st_mode & 0o222
                 and stat.st_nlink == 1 and 0 < stat.st_size <= maximum)
    except OSError:
        valid = False
    _require(valid, 'Exact immutable renderer file required')
    return path.read_bytes()


def validate_renderer_bundle(*, source, renderer_root, manifest_sha256, evidence=None):
    """Validate the complete two-file renderer bundle against frozen source bytes."""
    _require(isinstance(manifest_sha256, str) and SHA256.fullmatch(manifest_sha256),
             'Renderer manifest digest required')
    source = _canonical_directory(source, writable=False)
    renderer = _canonical_directory(renderer_root, writable=False)
    boundaries = [source]
    if evidence is not None:
        boundaries.append(_canonical_directory(evidence, writable=True))
    for boundary in boundaries:
        _require(not _inside(renderer, boundary) and not _inside(boundary, renderer)
                 and renderer != boundary, 'Renderer boundary overlap')
    manifest_bytes = _immutable_file(renderer / 'manifest.json', 8192)
    _require(_digest(manifest_bytes) == manifest_sha256,
             'Renderer manifest identity mismatch')
    manifest = _strict_json(manifest_bytes, 'renderer manifest')
    _require(type(manifest) is dict
             and set(manifest) == {'version', 'component', 'source', 'sourceSha256',
                                   'artifact', 'artifactSha256'}
             and type(manifest.get('version')) is int and manifest['version'] == 1
             and manifest.get('component') == 'SecureShop.ReviewCard'
             and manifest.get('source') == RENDERER_SOURCE
             and isinstance(manifest.get('sourceSha256'), str)
             and SHA256.fullmatch(manifest['sourceSha256'])
             and isinstance(manifest.get('artifactSha256'), str)
             and SHA256.fullmatch(manifest['artifactSha256'])
             and isinstance(manifest.get('artifact'), str)
             and ARTIFACT.fullmatch(manifest['artifact']),
             'Renderer manifest schema mismatch')
    _require(set(entry.name for entry in renderer.iterdir())
             == {'manifest.json', manifest['artifact']},
             'Unexpected renderer bundle inventory')
    source_bytes = _immutable_file(source / RENDERER_SOURCE, 4 * 1024 * 1024)
    artifact_bytes = _immutable_file(renderer / manifest['artifact'], 4 * 1024 * 1024)
    _require(_digest(source_bytes) == manifest['sourceSha256'],
             'Renderer source identity mismatch')
    _require(_digest(artifact_bytes) == manifest['artifactSha256'],
             'Renderer artifact identity mismatch')
    return {'manifestSha256': manifest_sha256,
            'sourceSha256': manifest['sourceSha256'],
            'artifactSha256': manifest['artifactSha256'],
            'artifact': manifest['artifact']}


def inventory_model(model_digest, *, connection_factory=http.client.HTTPConnection):
    """Read a bounded local Ollama inventory and require one exact pinned model."""
    _require(isinstance(model_digest, str) and SHA256.fullmatch(model_digest),
             'Pinned model digest required')
    connection = connection_factory('127.0.0.1', 11434, timeout=10)
    try:
        connection.request('GET', '/api/tags')
        response = connection.getresponse()
        _require(response.status == 200, 'Model inventory unavailable')
        payload = response.read(MODEL_RESPONSE_LIMIT + 1)
        _require(len(payload) <= MODEL_RESPONSE_LIMIT, 'Model inventory response too large')
        value = _strict_json(payload, 'model inventory')
        _require(type(value) is dict and type(value.get('models')) is list,
                 'Model inventory schema mismatch')
        matches = [row for row in value['models'] if type(row) is dict
                   and row.get('name') == MODEL_NAME and row.get('digest') == model_digest]
        _require(len(matches) == 1, 'Pinned model missing or ambiguous')
        return {'name': MODEL_NAME, 'digest': model_digest}
    finally:
        connection.close()


def wait_for_agent_port_release(port, *, assert_processes_absent, socket_factory=socket.socket,
                                monotonic=time.monotonic, sleep=time.sleep):
    """Bare-bind proof only; retry address-in-use within one absolute deadline."""
    started = monotonic()
    deadline = started + 60
    attempts = []
    failures = []
    bound = False
    initial_error = last_error = None
    for index in range(121):
        if index and monotonic() >= deadline:
            break
        probe = None
        error = None
        try:
            if not callable(assert_processes_absent):
                raise RuntimeError('Owned process absence callback required')
            assert_processes_absent()
        except BaseException as caught:
            failures.append('agent_process_absence')
            error = caught
        if error is None and monotonic() >= deadline:
            failures.append('agent_port_deadline')
            error = TimeoutError('Agent port absence deadline reached')
        if error is None:
            try:
                probe = socket_factory(socket.AF_INET, socket.SOCK_STREAM)
                probe.bind(('127.0.0.1', port))
                if probe.getsockname() != ('127.0.0.1', port):
                    raise RuntimeError('Exact agent port bind mismatch')
                bound = True
            except BaseException as caught:
                error = caught
            finally:
                if probe is not None:
                    try:
                        probe.close()
                    except BaseException as caught:
                        failures.append('agent_port_probe_close')
                        bound = False
                        if error is None:
                            error = caught
        diagnostic = None
        if error is not None:
            diagnostic = {'errorType': type(error).__name__,
                          'errno': error.errno if isinstance(error, OSError)
                          and type(error.errno) is int else None}
            if initial_error is None:
                initial_error = diagnostic
            last_error = diagnostic
        attempts.append({'attempt': index + 1,
                         'elapsedMs': max(0, round((monotonic() - started) * 1000)),
                         'bound': bound, 'error': diagnostic})
        if bound or failures:
            break
        if not isinstance(error, OSError) or error.errno != errno.EADDRINUSE:
            break
        remaining = deadline - monotonic()
        if remaining <= 0 or index == 120:
            break
        sleep(min(.5, remaining))
    if not bound:
        failures.append('agent_port_postflight')
    return {'portAbsenceVerified': bound, 'failures': failures,
            'agentPortError': last_error, 'agentPortInitialError': initial_error,
            'agentPortAttempts': attempts, 'agentPortAttemptCount': len(attempts),
            'agentPortElapsedMs': max(0, round((monotonic() - started) * 1000)),
            'agentPortDeadlineMs': 60000}


class FullBackendSecureShopResources:
    """Own the model check, immutable renderer proof and agent-port reservation."""
    def __init__(self, *, record, source, evidence, renderer_root,
                 renderer_manifest_sha256, model_digest,
                 connection_factory=http.client.HTTPConnection,
                 socket_factory=socket.socket, assert_processes_absent=None,
                 monotonic=time.monotonic, sleep=time.sleep):
        self.assert_processes_absent = assert_processes_absent
        self.monotonic, self.sleep = monotonic, sleep
        self.record = record
        self.source, self.evidence = Path(source), Path(evidence)
        self.renderer_root = Path(renderer_root)
        self.renderer_manifest_sha256 = renderer_manifest_sha256
        self.model_digest = model_digest
        self.connection_factory, self.socket_factory = connection_factory, socket_factory
        self.renderer = None
        self.reservation = None
        self.agent_port = None
        self.model_checked = False
        self.released = False
        self.prepared = False

    def _validate_renderer(self):
        return validate_renderer_bundle(source=self.source, evidence=self.evidence,
                                        renderer_root=self.renderer_root,
                                        manifest_sha256=self.renderer_manifest_sha256)

    def _inventory_model(self):
        return inventory_model(self.model_digest,
                               connection_factory=self.connection_factory)

    def prepare(self, postgres_port):
        _require(type(postgres_port) is int and 1 <= postgres_port <= 65535
                 and postgres_port not in RESERVED_PORTS,
                 'SecureShop PostgreSQL endpoint mismatch')
        _require(self.reservation is None and self.agent_port is None,
                 'SecureShop resources already prepared')
        self.renderer = self._validate_renderer()
        model = self._inventory_model()
        self.model_checked = True
        for _attempt in range(PORT_RESERVATION_ATTEMPTS):
            reservation = self.socket_factory(socket.AF_INET, socket.SOCK_STREAM)
            try:
                reservation.bind(('127.0.0.1', 0))
                host, port = reservation.getsockname()[:2]
                if host == '127.0.0.1' and port not in RESERVED_PORTS | {postgres_port}:
                    self.reservation, self.agent_port = reservation, port
                    break
            except BaseException:
                reservation.close()
                raise
            reservation.close()
        else:
            raise RuntimeError('SecureShop agent port reservation exhausted')
        manifest = {'version': 1,
                    'postgres': {'host': '127.0.0.1', 'port': postgres_port},
                    'agentHost': {'host': '127.0.0.1', 'port': self.agent_port},
                    'model': {'host': '127.0.0.1', 'port': 11434},
                    'fixtures': []}
        try:
            self.record('secureshop-resources.json', {
                'status': 'reserved', 'endpoints': manifest, 'model': model,
                'renderer': self.renderer})
        except BaseException:
            self.reservation.close()
            self.reservation = None
            raise
        self.prepared = True
        return manifest

    def release_for_launch(self):
        _require(self.reservation is not None and not self.released,
                 'SecureShop agent port reservation unavailable')
        self.reservation.close()
        self.reservation = None
        self.released = True
        self.record('secureshop-agent-port.json', {
            'status': 'released_for_owned_child', 'host': '127.0.0.1',
            'port': self.agent_port})
        return self.agent_port

    def cleanup(self):
        failures = []
        if not self.prepared:
            failures.append('prepare_incomplete')
        if self.reservation is not None:
            try:
                self.reservation.close()
            except BaseException:
                failures.append('reservation_close')
            self.reservation = None
        port_result = {'portAbsenceVerified': self.agent_port is None,
                       'agentPortError': None, 'agentPortInitialError': None,
                       'agentPortAttempts': [], 'agentPortAttemptCount': 0,
                       'agentPortElapsedMs': 0, 'agentPortDeadlineMs': 60000}
        if self.agent_port is not None:
            port_result = wait_for_agent_port_release(self.agent_port,
                assert_processes_absent=self.assert_processes_absent,
                socket_factory=self.socket_factory, monotonic=self.monotonic, sleep=self.sleep)
            failures.extend(port_result.pop('failures'))
        renderer_postflight = False
        try:
            renderer_postflight = self._validate_renderer() == self.renderer
            if not renderer_postflight:
                failures.append('renderer_postflight')
        except BaseException:
            failures.append('renderer_postflight')
        model_postflight = False
        if self.model_checked:
            try:
                self._inventory_model()
                model_postflight = True
            except BaseException:
                failures.append('model_postflight')
        else:
            failures.append('model_not_checked')
        receipt = {'status': 'verified' if not failures else 'cleanup_unverified',
                   'failures': failures, 'agentHostPort': self.agent_port,
                   'qualificationPrepared': self.prepared,
                   **port_result,
                   'modelPostflight': model_postflight,
                   'rendererPostflight': renderer_postflight,
                   'rendererManifestSha256': self.renderer_manifest_sha256,
                   'modelDigest': self.model_digest}
        self.record('secureshop-resources-cleanup.json', receipt)
        if failures:
            raise RuntimeError('SecureShop resource cleanup unverified: ' + ','.join(failures))
        return receipt
