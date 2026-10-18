"""Owned sidecars for the opt-in full application MCP cohort. Import inert."""
import hashlib
import http.client
import json
import os
import secrets
import time
from pathlib import Path
from mcp_connected_baseline_contract import validate_mailpit_layout
from mcp_strict_runner_ownership import StrictRunner, validate_health
from sql_nosql_docker_ownership import verify_daemon, verify_image, inspect_owned, cleanup_owned, CONTAINER


class FullBackendMcpResources:
    def __init__(self, *, command, remote, record, source, daemon_id, mailpit_image,
                 runner_image, nonce, build_receipt, context_sha256, model_digest):
        self.command, self.record = command, record
        self.daemon_id, self.model_digest = daemon_id, model_digest
        self.mail = dict(name='dvaia-full-mcp-mailpit-' + nonce, image=mailpit_image,
                         labels={'dvaia.qualification': 'full_backend_mcp_indirect',
                                 'dvaia.owner-uid': str(os.getuid()), 'dvaia.run-nonce': nonce},
                         intended=False, captured=None)
        template = (Path(source) / 'sidecars/sandbox-runner/apparmor/dvaia-mcp-sandbox.apparmor.in').read_bytes()
        profile = 'dvaia-mcp-sandbox-' + nonce[:12]
        policy = template.replace(b'@@SUPERVISOR_PROFILE@@', profile.encode())
        self.runner = StrictRunner(docker=command, remote=remote,
            record=lambda name, value: record(name + '.json', value), daemon_id=daemon_id,
            image=runner_image, nonce=nonce, uid=os.getuid(), policy=policy,
            policy_sha256=hashlib.sha256(policy).hexdigest(), build_receipt=build_receipt,
            context_sha256=context_sha256, template_sha256=hashlib.sha256(template).hexdigest(), template=template)
        self.model_checked = False

    def inventory_model(self):
        connection = http.client.HTTPConnection('127.0.0.1', 11434, timeout=10)
        try:
            connection.request('GET', '/api/tags')
            response = connection.getresponse()
            if response.status != 200:
                raise RuntimeError('Model inventory unavailable')
            rows = json.loads(response.read())['models']
            if not any(row.get('name') == 'llama3.1:8b' and row.get('digest') == self.model_digest for row in rows):
                raise RuntimeError('Pinned model missing')
        finally:
            connection.close()

    def launch(self, postgres_port):
        self.inventory_model()
        self.model_checked = True
        verify_daemon(self.command, self.daemon_id)
        verify_image(self.command, self.mail['image'])
        resource = self.mail
        self.record('mailpit-intent.json', dict(resource, daemonId=self.daemon_id))
        resource['intended'] = True
        labels = [part for key, value in resource['labels'].items() for part in ['--label', key + '=' + value]]
        created = self.command(['run', '--detach', '--pull', 'never', '--name', resource['name']] + labels +
            ['--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=16777216',
             '-p', '127.0.0.1::1025', '-p', '127.0.0.1::8025', resource['image']])
        if created.returncode or not CONTAINER.fullmatch(created.stdout.strip()):
            raise RuntimeError('Owned Mailpit creation failed')
        resource['captured'] = created.stdout.strip()
        layout = inspect_owned(self.command, name=resource['name'], labels=resource['labels'],
                               image=resource['image'], captured_id=resource['captured'])
        smtp_port, api_port = validate_mailpit_layout(layout)
        self.record('mailpit-created.json', dict(resource))
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            connection = http.client.HTTPConnection('127.0.0.1', api_port, timeout=1)
            try:
                connection.request('GET', '/api/v1/info')
                if connection.getresponse().status == 200:
                    break
            except (OSError, http.client.HTTPException):
                pass
            finally:
                connection.close()
            time.sleep(.25)
        else:
            raise RuntimeError('Mailpit readiness deadline')
        token = secrets.token_urlsafe(48)
        self.runner.prepare_policy()
        runner_port = self.runner.launch(token)
        runtime = self.command(['exec', self.runner.captured, '/usr/local/bin/node', '--version'])
        if runtime.returncode or runtime.stdout.strip() != 'v26.8.2':
            raise RuntimeError('Owned runner runtime mismatch')
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            connection = http.client.HTTPConnection('127.0.0.1', runner_port, timeout=2)
            try:
                connection.request('GET', '/owned-targets/health', headers={'Authorization': 'Bearer ' + token})
                response = connection.getresponse()
                if response.status == 200:
                    health = json.loads(response.read())
                    validate_health(health, self.runner.profile)
                    self.record('runner-health.json', health)
                    break
            except (OSError, http.client.HTTPException):
                pass
            finally:
                connection.close()
            time.sleep(.25)
        else:
            raise RuntimeError('Strict runner readiness deadline')
        ports = dict(postgres=postgres_port, runner=runner_port, smtp=smtp_port, mailpit=api_port, model=11434)
        if len(set(ports.values())) != 5:
            raise RuntimeError('Owned endpoints must be distinct')
        manifest = dict(version=1, **{name: dict(host='127.0.0.1', port=port) for name, port in ports.items()})
        self.record('mcp-endpoints.json', manifest)
        return manifest, token

    def cleanup(self):
        failures = []
        try:
            self.runner.cleanup()
        except BaseException:
            failures.append('runner_cleanup')
        if self.mail['intended']:
            try:
                result = cleanup_owned(self.command, daemon_id=self.daemon_id, name=self.mail['name'],
                    labels=self.mail['labels'], image=self.mail['image'], captured_id=self.mail['captured'])
                self.record('mailpit-cleanup.json', result)
            except BaseException:
                failures.append('mailpit_cleanup')
        if self.model_checked:
            try:
                self.inventory_model()
            except BaseException:
                failures.append('model_postflight')
        if failures:
            self.record('mcp-cleanup-debt.json', {'failures': failures, 'mailpitId': self.mail['captured'],
                'runnerId': self.runner.captured, 'profile': self.runner.profile, 'directory': self.runner.directory})
            raise RuntimeError('Owned MCP cleanup unverified: ' + ','.join(failures))
