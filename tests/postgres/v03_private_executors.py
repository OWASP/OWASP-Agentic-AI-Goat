"""V03 inherited-parent facade. No Docker commands or JSON-to-owner conversion.

The parent must already own both producers. Remote ambiguity poisons this
channel; a failed close never authorizes PostgreSQL retirement.
"""
import json
import hashlib
import fcntl
import math
import os
import re
import signal
import socket
import subprocess
import stat
import sys
import time

FRAME_CAP = 16384
ENV_KEYS = frozenset(('SECURESHOP_LISTING_IMAGE_OPTIMIZE_V03_BROWSER_SYSTEM_URL',
    'SECURESHOP_LISTING_IMAGE_OPTIMIZE_V03_BROWSER_SYSTEM_TOKEN',
    'SECURESHOP_LISTINGS_TEST_MANAGER_ORIGIN', 'SECURESHOP_LISTINGS_TEST_MANAGER_TOKEN',
    'SECURESHOP_LISTINGS_TEST_MANAGER_RUNTIME_DIGEST', 'SECURESHOP_LISTINGS_TEST_MANAGER_IMAGE_ID',
    'SECURESHOP_LISTINGS_TEST_MANAGER_SOURCE_SHA256', 'SECURESHOP_LISTINGS_TEST_MANAGER_CONTAINER_ID',
    'SECURESHOP_LISTINGS_TEST_MANAGER_DOCKER_AUTHORITY_SHA256',
    'SECURESHOP_LISTINGS_TEST_DOCKER_HOST', 'SECURESHOP_LISTINGS_TEST_DOCKER_DAEMON_ID'))

def _identity(row):
    return None if row is None else dict(pid=row.pid, ppid=row.ppid, pgid=row.pgid,
        uid=row.uid, birth=[row.start_sec, row.start_usec])

def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError('V03_DUPLICATE_KEY')
        result[key] = value
    return result

def _verify_source(file, digest):
    node_binary=file==os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))+'/tasks/runtime/node/node_modules/node/bin/node'
    fd=os.open(file,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    primary=None
    try:
        initial=os.fstat(fd)
        if (not stat.S_ISREG(initial.st_mode)
                or (initial.st_nlink not in (1,2) if node_binary else initial.st_nlink!=1)
                or initial.st_size>(256 if node_binary else 128)*1024**2):
            raise ValueError('V03_ADMISSION_SOURCE_FILE')
        hashed=hashlib.sha256();count=0
        while True:
            chunk=os.read(fd,65536)
            if not chunk:break
            count+=len(chunk)
            if count>initial.st_size:raise ValueError('V03_ADMISSION_SOURCE_CHANGED')
            hashed.update(chunk)
        final=os.fstat(fd)
        if (count!=initial.st_size or hashed.hexdigest()!=digest or any(getattr(initial,k)!=getattr(final,k)
                for k in ('st_dev','st_ino','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))):raise ValueError('V03_ADMISSION_SOURCE_CHANGED')
    except BaseException as error:
        primary=error
        raise
    finally:
        try:os.close(fd)
        except BaseException as error:
            failure=primary if primary is not None else error
            failure.cleanupDebt=True
            failure.sourceCloseUnproven=True
            if primary is None:raise

class V03PrivateExecutors:
    @classmethod
    def from_admission_fds(cls, *, root, run_id, plan_sha256, source_pins, channel_fd=3, admission_fd=4):
        """Consume the fixed parent's inherited, read-only source admission.

        MAIN supplies its independently checked current admission pins/run/plan,
        never values selected from this packet. There is no path or command RPC.
        """
        if (channel_fd!=3 or admission_fd!=4 or os.path.realpath(root)!=root
                or not os.path.isabs(root) or type(source_pins) is not dict or not source_pins
                or not re.fullmatch('[a-f0-9]{32}',run_id or '')
                or not re.fullmatch('[a-f0-9]{64}',plan_sha256 or '')):
            raise ValueError('V03_FD_ADMISSION')
        required={'tests/postgres/ownedV03PrivateExecutors.js','tests/postgres/v03_private_executors.py',
            'tests/postgres/run-secureshop-agent-host-transport-main.py','tests/postgres/darwin_process_inventory.py',
            'tests/postgres/trusted_process_inspector.py',
            'tasks/runtime/node/node_modules/node/bin/node'}
        if not required.issubset(source_pins):raise ValueError('V03_ADMISSION_SOURCE_SET')
        before=os.fstat(admission_fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or before.st_nlink!=1
                or stat.S_IMODE(before.st_mode)!=0o600 or not 0<before.st_size<=1048576
                or fcntl.fcntl(admission_fd,fcntl.F_GETFL)&os.O_ACCMODE!=os.O_RDONLY):
            raise ValueError('V03_ADMISSION_FILE')
        raw=os.pread(admission_fd,before.st_size+1,0);after=os.fstat(admission_fd)
        if len(raw)!=before.st_size or any(getattr(before,k)!=getattr(after,k) for k in
                ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')):raise ValueError('V03_ADMISSION_CHANGED')
        packet=json.loads(raw,object_pairs_hook=_unique)
        if (type(packet) is not dict or set(packet)!={'version','target','root','runId','planSha256','sourcePins','parentIdentity','mainArgv'}
                or type(packet['version']) is not int or packet['version']!=1 or packet['target']!='original-v03-private-main-admission-v1'
                or packet['root']!=root or packet['runId']!=run_id or packet['planSha256']!=plan_sha256
                or packet['sourcePins']!=source_pins or packet['mainArgv']!=sys.argv):
            raise ValueError('V03_ADMISSION_BINDING')
        for relative,digest in source_pins.items():
            if (type(relative) is not str or relative.startswith('/') or any(p in ('','..','.') for p in relative.split('/'))
                    or not re.fullmatch('[a-f0-9]{64}',digest or '')):raise ValueError('V03_ADMISSION_SOURCE')
            file=root+'/'+relative
            if os.path.realpath(file)!=file:raise ValueError('V03_ADMISSION_SOURCE_PATH')
            _verify_source(file,digest)
        expected_parent_argv=[root+'/tasks/runtime/node/node_modules/node/bin/node',
            root+'/tests/postgres/ownedV03PrivateExecutors.js','--v03-main-parent',run_id,plan_sha256]
        return cls.from_inherited_fd(channel_fd,run_id=run_id,plan_sha256=plan_sha256,
            parent_identity=packet['parentIdentity'],parent_argv=expected_parent_argv)

    @classmethod
    def from_inherited_fd(cls, fd, *, run_id, plan_sha256, parent_identity, parent_argv):
        from darwin_process_inventory import LibProc
        from trusted_process_inspector import peer_identity
        if (type(fd) is not int or fd < 3 or not re.fullmatch('[a-f0-9]{32}', run_id or '')
                or not re.fullmatch('[a-f0-9]{64}', plan_sha256 or '')
                or type(parent_identity) is not dict or parent_identity.get('pid') != os.getppid()):
            raise ValueError('V03_PARENT_ADMISSION')
        api = LibProc()
        if (_identity(api.identity(os.getppid())) != parent_identity
                or list(api.arguments(os.getppid())) != parent_argv):
            raise ValueError('V03_PARENT_BIRTH')
        channel = socket.socket(fileno=fd)
        try:
            if (channel.family != socket.AF_UNIX or channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                    or peer_identity(channel)[1] != os.getuid()):
                raise ValueError('V03_PARENT_CHANNEL')
            self = cls.__new__(cls)
            self.channel, self.api = channel, api
            self.run_id, self.plan_sha256 = run_id, plan_sha256
            self.parent_identity, self.parent_argv = parent_identity, parent_argv
            self.now = time.monotonic
            self.sequence = 0
            self.state = 'new'
            self.debt = False
            self.browser = self.browser_identity = self.receipt = None
            self.deadline = self.now()+11096
            self.cohort_deadline = None
            self.activation_deadline = None
            self.work_deadline = None
            self.pg_intent = None
            self.pg_binding = None
            return self
        except BaseException as primary:
            try:channel.close()
            except BaseException:
                primary.cleanupDebt=True
                primary.channelCloseUnproven=True
            raise

    def _parent(self):
        pid = self.parent_identity['pid']
        if (_identity(self.api.identity(pid)) != self.parent_identity
                or list(self.api.arguments(pid)) != self.parent_argv):
            raise RuntimeError('V03_PARENT_CHANGED')

    def _exchange(self, op, payload, limit):
        if self.debt: raise RuntimeError('V03_REMOTE_DEBT')
        start = self.now()
        try:
            if type(limit) not in (int, float) or not math.isfinite(limit) or limit <= 0:
                raise TimeoutError('V03_PARENT_DEADLINE')
            end = min(self.deadline, start+limit)
            if not math.isfinite(end) or end <= start:
                raise TimeoutError('V03_PARENT_DEADLINE')
            self._parent()
            request = dict(version=1, runId=self.run_id, planSha256=self.plan_sha256,
                sequence=self.sequence, op=op, payload=payload)
            raw = (json.dumps(request, separators=(',', ':'), allow_nan=False)+'\n').encode()
            if len(raw)>FRAME_CAP: raise ValueError('V03_FRAME_CAP')
            remaining = end-self.now()
            if remaining <= 0: raise TimeoutError('V03_PARENT_DEADLINE')
            self.channel.settimeout(remaining)
            if self.now() >= end: raise TimeoutError('V03_PARENT_DEADLINE')
            self.channel.sendall(raw)
            data = bytearray()
            while True:
                if self.now()>=end: raise TimeoutError('V03_PARENT_DEADLINE')
                self.channel.settimeout(end-self.now()); part = self.channel.recv(1)
                if not part: raise EOFError('V03_PARENT_EOF')
                data.extend(part)
                if len(data)>FRAME_CAP: raise ValueError('V03_FRAME_CAP')
                if part == b'\n': break
            response = json.loads(data, object_pairs_hook=_unique)
            expected = {key:request[key] for key in ('version','runId','planSha256','sequence','op')}
            if (type(response) is not dict or set(response)!=set(expected)|{'result'}
                    or any(type(response[k]) is not type(v) or response[k]!=v for k,v in expected.items())):
                raise ValueError('V03_PARENT_RESPONSE')
            self._parent()
            if self.now()>=end: raise TimeoutError('V03_PARENT_DEADLINE')
            self.sequence += 1
            return response['result'], start
        except BaseException:
            self.debt = True
            raise

    def start(self):
        if self.state != 'new': raise RuntimeError('V03_START_ONCE')
        self.state = 'starting'
        # Both preparation owners are ready before MAIN's original wrapper.
        result, sent = self._exchange('start', {}, 40)
        if (type(result) is not dict or set(result)!={'ready','parentRemainingMsAtAdmission','workRemainingMsAtAdmission'} or result['ready'] is not True
                or type(result['parentRemainingMsAtAdmission']) is not int or not 0<result['parentRemainingMsAtAdmission']<=11096000
                or type(result['workRemainingMsAtAdmission']) is not int or not 0<result['workRemainingMsAtAdmission']<=1800000):
            self.debt=True; raise ValueError('V03_START_RESULT')
        self.deadline=min(self.deadline, sent+result['parentRemainingMsAtAdmission']/1000)
        self.work_deadline=min(self.deadline,sent+result['workRemainingMsAtAdmission']/1000)
        self.state='ready'
        return None

    def postgres_create_intent(self, expected_image, expected_daemon):
        if self.state!='ready' or self.pg_intent is not None:raise RuntimeError('V03_PG_INTENT_ONCE')
        result,_=self._exchange('pg-create-intent',{},min(120,self.work_deadline-self.now()))
        name='owasp-ai-goat-merchant-listing-image-optimize-v03-browser-'+hashlib.sha256((self.run_id+':v03-postgres').encode()).hexdigest()[:12]
        expected=dict(version=1,target='original-v03-parent-postgres-v1',runId=self.run_id,planSha256=self.plan_sha256,
            name=name,labels={'owasp-ai-goat.owner':self.run_id,'owasp-ai-goat.cohort':'secureshop-merchant-listing-image-optimize-v03-browser-current-main-v1'},
            image=expected_image,daemonId=expected_daemon)
        if type(result) is not dict or set(result)!={'intent','publication'} or result['intent']!=expected:
            self.debt=True;raise ValueError('V03_PG_INTENT_BINDING')
        self.pg_intent=expected
        return dict(expected)

    def bind_postgres(self, captured_id, expected_port):
        if self.state!='ready' or self.pg_intent is None or self.pg_binding is not None:raise RuntimeError('V03_PG_BIND_ORDER')
        result,_=self._exchange('pg-bind',{'capturedId':captured_id},min(120,self.work_deadline-self.now()))
        if (type(result) is not dict or set(result)!={'bound','id','port','publication'} or result['bound'] is not True
                or result['id']!=captured_id or type(result['port']) is not int or result['port']!=expected_port):
            self.debt=True;raise ValueError('V03_PG_BINDING')
        self.pg_binding=dict(id=captured_id,port=expected_port)
        return dict(self.pg_binding)

    def _validate_environment(self, env):
        if type(env) is not dict or set(env)!=ENV_KEYS or any(type(v) is not str for v in env.values()):
            self.debt=True; raise ValueError('V03_ENVIRONMENT')
        for key in ('SECURESHOP_LISTING_IMAGE_OPTIMIZE_V03_BROWSER_SYSTEM_URL','SECURESHOP_LISTINGS_TEST_MANAGER_ORIGIN'):
            if (not re.fullmatch(r'http://127\.0\.0\.1:[1-9][0-9]{3,4}', env[key])
                    or not 1024<=int(env[key].rsplit(':',1)[1])<=65535):
                self.debt=True; raise ValueError('V03_LOOPBACK')
        for key in ('SECURESHOP_LISTING_IMAGE_OPTIMIZE_V03_BROWSER_SYSTEM_TOKEN','SECURESHOP_LISTINGS_TEST_MANAGER_TOKEN'):
            if not re.fullmatch('[A-Za-z0-9_-]{43,128}', env[key]):
                self.debt=True; raise ValueError('V03_TOKEN')
        for key in ('SECURESHOP_LISTINGS_TEST_MANAGER_RUNTIME_DIGEST','SECURESHOP_LISTINGS_TEST_MANAGER_SOURCE_SHA256',
                    'SECURESHOP_LISTINGS_TEST_MANAGER_CONTAINER_ID','SECURESHOP_LISTINGS_TEST_MANAGER_DOCKER_AUTHORITY_SHA256'):
            if not re.fullmatch('[a-f0-9]{64}',env[key]):self.debt=True;raise ValueError('V03_MANAGER_IDENTITY')
        if not re.fullmatch('sha256:[a-f0-9]{64}',env['SECURESHOP_LISTINGS_TEST_MANAGER_IMAGE_ID']):
            self.debt=True;raise ValueError('V03_MANAGER_IMAGE')
        child_run=hashlib.sha256((self.run_id+':v03-listings').encode('ascii')).hexdigest()[:32]
        if env['SECURESHOP_LISTINGS_TEST_DOCKER_HOST']!='unix:///var/tmp/owasp-ai-goat-v23-build-'+child_run+'/fs/docker.sock':
            self.debt=True;raise ValueError('V03_PRIVATE_DOCKER')
        if not re.fullmatch('[A-Za-z0-9:-]{20,128}',env['SECURESHOP_LISTINGS_TEST_DOCKER_DAEMON_ID']):
            self.debt=True;raise ValueError('V03_PRIVATE_DAEMON')
        return dict(env)

    def claim_cohort(self):
        if self.state!='ready': raise RuntimeError('V03_COHORT_ONCE')
        self.state='claiming'
        result, sent=self._exchange('claim-cohort',{},10)
        if (type(result) is not dict or set(result)!={'originalChildMs','activationMsAtClaim','infrastructureMsAtClaim','clockUncertaintyMs','environment'}
                or type(result['originalChildMs']) is not int or result['originalChildMs']!=1200000
                or type(result['activationMsAtClaim']) is not int or result['activationMsAtClaim']!=10000
                or type(result['infrastructureMsAtClaim']) is not int or result['infrastructureMsAtClaim']!=1210000
                or type(result['clockUncertaintyMs']) is not int or not 0<=result['clockUncertaintyMs']<=2000):
            self.debt=True; raise ValueError('V03_COHORT_RESULT')
        self.environment=self._validate_environment(result['environment'])
        self.cohort_deadline=min(self.deadline,sent+(result['infrastructureMsAtClaim']-result['clockUncertaintyMs'])/1000)
        self.activation_deadline=sent+(result['activationMsAtClaim']-result['clockUncertaintyMs'])/1000
        self.state='claimed'
        self.assert_spawn_ready()
        return self.cohort_deadline

    def fixture_environment(self):
        self.assert_spawn_ready()
        return dict(self.environment)

    def assert_spawn_ready(self):
        now=self.now()
        if (self.state not in ('claimed','attached') or self.debt or self.activation_deadline is None
                or now>=self.activation_deadline or self.cohort_deadline-now<1200):
            self.debt=True;raise RuntimeError('V03_FULL_CHILD_WINDOW_REQUIRED')
        return 1200  # Original child wait; never a clipped remaining-time value.

    def attach_browser(self, child, birth):
        if self.state!='claimed' or self.browser is not None: raise RuntimeError('V03_BROWSER_ONCE')
        # Retain even a mismatched birth as debt; it never becomes signal authority.
        self.browser=child
        row=_identity(self.api.identity(child.pid))
        if (row!=birth or row is None or row['ppid']!=os.getpid()
                or row['uid']!=os.getuid() or row['pid']!=row['pgid']):
            self.debt=True; raise ValueError('V03_BROWSER_BIRTH')
        self.browser_identity=row
        self.assert_spawn_ready()
        result,_=self._exchange('attach-browser',{'birth':row},min(10,self.cohort_deadline-self.now()))
        if result!={'attached':True}:self.debt=True;raise ValueError('V03_BROWSER_ACK')
        self.state='attached'
        self.assert_spawn_ready()

    def close(self, primary=None):
        if self.receipt is not None:return self.receipt
        errors=[];browser_absent=self.browser is None
        try:
            if self.browser is not None:
                child=self.browser
                if child.poll() is None:
                    current=_identity(self.api.identity(child.pid))
                    if current is None or current!=self.browser_identity:raise RuntimeError('V03_BROWSER_RETIREMENT_IDENTITY')
                    os.killpg(child.pid,signal.SIGTERM)
                child.wait(timeout=max(0.001,min(6,self.deadline-self.now())))
                browser_absent=not self.api.group_pids(child.pid)
                if not browser_absent:raise RuntimeError('V03_BROWSER_GROUP_REMAINS')
        except BaseException as error:errors.append(type(error).__name__)
        remote=None
        try:
            remote,_=self._exchange('finish-work',{'browserAbsent':browser_absent,'primaryFailed':primary is not None},
                min(40,(self.work_deadline or self.deadline)-self.now()))
            if remote!={'accepted':True,'cleanupPending':True,'qualificationComplete':False}:
                raise RuntimeError('V03_WORK_HANDOFF_UNPROVEN')
        except BaseException as error:errors.append(type(error).__name__)
        finally:
            try:self.channel.close()
            except BaseException as error:errors.append(type(error).__name__)
        accepted=not errors and not self.debt and browser_absent and remote is not None
        self.state='closed'
        self.receipt=dict(version=1,runId=self.run_id,closed=True,cleanupVerified=False,
            handoffAccepted=accepted,cleanupPending=True,qualificationComplete=False,
            browserAbsent=browser_absent,diagnosticAbsent=False,listingsAbsent=False,
            primaryFailed=primary is not None,evidenceDebt=self.debt or bool(errors),errors=errors)
        return self.receipt

    def may_retire_pg(self):
        # PG is exclusively parent-owned; MAIN's bounded handoff is not proof
        # that either private producer or PostgreSQL has been retired.
        return False
