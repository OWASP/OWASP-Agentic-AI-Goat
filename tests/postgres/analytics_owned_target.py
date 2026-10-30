"""One disposable Analytics target cluster, using the launcher's Docker authority.

No commands run on import. The child owns production schema/service setup; this
resource owns only the isolated PostgreSQL cluster and its control database.
"""
import json
import re
import time

from sql_nosql_docker_ownership import (
    inspect_owned, validate_container_layout, verify_daemon, verify_image,
    cleanup_owned,
)


class OwnedAnalyticsTarget:
    def __init__(self, *, command, absent, daemon_id, image, owner, nonce, cohort,
                 persist, pause=time.sleep):
        if not re.fullmatch(r'[a-f0-9]{12}', nonce or ''):
            raise ValueError('Owned Analytics nonce required')
        if not owner or not cohort:
            raise ValueError('Owned Analytics labels required')
        self.command, self.absent, self.persist, self.pause = command, absent, persist, pause
        self.daemon_id, self.image = daemon_id, image
        self.name = 'owasp-ai-goat-coupon-analytics-' + nonce
        self.labels = {'owasp-ai-goat.owner': owner, 'owasp-ai-goat.cohort': cohort,
                       'owasp-ai-goat.role': 'coupon-analytics-target'}
        self.state = {'name': self.name, 'labels': self.labels, 'image': image,
                      'daemonId': daemon_id, 'owner': nonce, 'attempted': False,
                      'containerId': None, 'port': None,
                      'database': 'owasp_ai_goat_analytics_control_' + nonce,
                      'cluster': 'owasp-ai-goat-owned-analytics-' + nonce,
                      'systemIdentifier': None, 'ready': False}

    def _inspect(self):
        return inspect_owned(self.command, name=self.name, labels=self.labels,
                             image=self.image, captured_id=self.state['containerId'])

    def _sql(self, sql):
        result = self.command(['exec', self.state['containerId'], 'psql', '-h',
            '127.0.0.1', '-p', '5432', '-U', 'postgres', '-d', 'postgres',
            '-v', 'ON_ERROR_STOP=1', '-At', '-c', sql])
        if result.returncode:
            raise RuntimeError('Owned Analytics cluster query failed')
        return result.stdout.strip()

    def _startup_diagnostic(self, ready):
        # Never retain arbitrary container output (which could contain private
        # values). Project only closed PostgreSQL startup reasons from its tail.
        diagnostic = {'phase': 'readiness', 'readinessExitCode': ready.returncode,
                      'logTailRead': False, 'reasons': []}
        try:
            verify_daemon(self.command, self.daemon_id)
            if self._inspect() is None:
                raise RuntimeError('Owned Analytics container disappeared')
            logs = self.command(['logs', '--tail', '20', self.state['containerId']])
            diagnostic['logExitCode'] = logs.returncode
            diagnostic['logTailRead'] = logs.returncode == 0
            tail = (logs.stdout + '\n' + logs.stderr)[-8192:]
            for reason in (
                '"min_wal_size" must be at least twice "wal_segment_size"',
                '"max_wal_size" must be at least twice "wal_segment_size"',
                'No space left on device', 'Permission denied',
                'database system is starting up', 'database system is shutting down',
                'database system is ready to accept connections',
            ):
                if reason in tail:
                    diagnostic['reasons'].append(reason)
            diagnostic['otherOutputOmitted'] = True
        except Exception:
            diagnostic['diagnosticUnavailable'] = True
        self.state['startupDiagnostic'] = diagnostic
        try:
            self.persist(self.state)
        except Exception:
            pass  # Preserve the original readiness failure and owned cleanup.

    def start(self):
        if self.state['attempted']:
            raise RuntimeError('Owned Analytics start cannot be repeated')
        verify_daemon(self.command, self.daemon_id)
        verify_image(self.command, self.image)
        if self._inspect() is not None:
            raise RuntimeError('Owned Analytics name occupied')
        self.state['attempted'] = True
        self.persist(self.state)
        labels = sum((['--label', f'{key}={value}'] for key, value in self.labels.items()), [])
        result = self.command(['run', '--detach', '--pull', 'never', '--name', self.name,
            *labels, '--memory', '512m', '--cpus', '2', '--pids-limit', '256',
            '--tmpfs', '/var/lib/postgresql:rw,size=268435456',
            '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
            '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1',
            '-p', '127.0.0.1::5432',
            self.image, '-c', 'max_connections=40', '-c', 'shared_buffers=16MB',
            '-c', 'max_wal_size=16MB', '-c', 'min_wal_size=4MB',
            '-c', 'cluster_name=' + self.state['cluster']])
        if result.returncode or not re.fullmatch(r'[a-f0-9]{64}', result.stdout.strip()):
            raise RuntimeError('Owned Analytics creation acknowledgement unavailable')
        self.state['containerId'] = result.stdout.strip()
        self.persist(self.state)
        verify_daemon(self.command, self.daemon_id)
        row = self._inspect()
        if row is None:
            raise RuntimeError('Owned Analytics container disappeared')
        self.state['port'] = validate_container_layout(row)
        for _ in range(120):
            ready = self.command(['exec', self.state['containerId'], 'pg_isready',
                                  '-h', '127.0.0.1', '-U', 'postgres'])
            if ready.returncode == 0:
                break
            self.pause(.1)
        else:
            self._startup_diagnostic(ready)
            raise RuntimeError('Owned Analytics readiness timeout')
        if self._sql("SELECT count(*) FROM pg_database WHERE datname NOT IN ('postgres','template0','template1')") != '0':
            raise RuntimeError('Owned Analytics fresh cluster required')
        identity = json.loads(self._sql("SELECT json_build_object('systemIdentifier',system_identifier::text,'cluster',current_setting('cluster_name'))::text FROM pg_control_system()"))
        if (not isinstance(identity, dict) or set(identity) != {'systemIdentifier', 'cluster'}
                or not isinstance(identity['systemIdentifier'], str)
                or not re.fullmatch(r'[0-9]{1,24}', identity['systemIdentifier'])
                or identity['cluster'] != self.state['cluster']):
            raise RuntimeError('Owned Analytics PostgreSQL identity mismatch')
        self.state['systemIdentifier'] = identity['systemIdentifier']
        self._sql('CREATE DATABASE ' + self.state['database'])
        for database in ('postgres', 'template0', 'template1', self.state['database']):
            self._sql('REVOKE CONNECT ON DATABASE ' + database + ' FROM PUBLIC')
        self.state['ready'] = True
        self.persist(self.state)
        return self.environment()

    def environment(self):
        if not self.state['ready'] or not self.state['systemIdentifier'] or not self.state['port']:
            raise RuntimeError('Owned Analytics admission unavailable')
        return {'SECURESHOP_COUPON_ANALYTICS_' + key: str(self.state[field])
                for key, field in [('OWNER', 'owner'), ('PORT', 'port'),
                    ('DATABASE', 'database'), ('CLUSTER', 'cluster'),
                    ('SYSTEM_IDENTIFIER', 'systemIdentifier')]}

    def close(self):
        self.state['ready'] = False
        if not self.state['attempted']:
            return {'containerNameAbsent': self.absent(self.name), 'containerIdAbsent': True}
        verify_daemon(self.command, self.daemon_id)
        row = self._inspect()
        if row is not None and self.state['containerId'] is None:
            # Recover a lost create acknowledgement only from the exact labels.
            validate_container_layout(row)
            self.state['containerId'] = row['Id']
            self.persist(self.state)
        identifier = self.state['containerId']
        if row is None and identifier and not self.absent(identifier):
            raise RuntimeError('Captured Analytics container renamed; cleanup withheld')
        cleanup_owned(self.command, daemon_id=self.daemon_id, name=self.name,
                      labels=self.labels, image=self.image, captured_id=identifier)
        result = {'containerNameAbsent': self.absent(self.name),
                  'containerIdAbsent': not identifier or self.absent(identifier)}
        if not all(value is True for value in result.values()):
            raise RuntimeError('Owned Analytics absence unverified')
        self.state['cleanup'] = result
        self.persist(self.state)
        return result
