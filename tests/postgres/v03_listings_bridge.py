"""V03-only bridge activation. Existing standalone600s bridge is unchanged.

The fixed inherited-FD producer calls this class; importing it grants no parent
or image authority. No caller command or guest program is accepted.
"""
import hashlib
import math
import os
import stat
import re
import shlex
import threading
import time
import uuid
from pathlib import Path
from listings_native_resources import PrivateListingsBridge,private_channel_program,private_handoff

def _read_lease_source(source,digest):
    fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    primary=None;data=None
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or not 0<before.st_size<=131072:
            raise ValueError('V03_LISTINGS_LEASE_SOURCE')
        chunks=[];count=0
        while count<before.st_size:
            part=os.read(fd,min(65536,before.st_size-count))
            if not part:raise ValueError('V03_LISTINGS_LEASE_SOURCE')
            chunks.append(part);count+=len(part)
        after=os.fstat(fd);data=b''.join(chunks)
        if (any(getattr(before,k)!=getattr(after,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns'))
                or hashlib.sha256(data).hexdigest()!=digest):raise ValueError('V03_LISTINGS_LEASE_SOURCE')
    except BaseException as error:primary=error
    finally:
        try:os.close(fd)
        except BaseException as error:
            primary=primary or error;primary.cleanupDebt=True;primary.leaseSourceCloseUnproven=True
    if primary:raise primary
    return data


class V03ListingsBridge(PrivateListingsBridge):
    def __init__(self,root,run_id,parent_run_id,plan_sha256,startup_deadline,lease_source_sha256):
        if (not re.fullmatch('[a-f0-9]{32}',parent_run_id or '')
                or hashlib.sha256((parent_run_id+':v03-listings').encode()).hexdigest()[:32]!=run_id
                or not re.fullmatch('[a-f0-9]{64}',plan_sha256 or '')
                or type(startup_deadline) not in (int,float) or not math.isfinite(startup_deadline)
                or not 0<startup_deadline-time.monotonic()<=60):
            raise ValueError('V03_LISTINGS_BRIDGE_ADMISSION')
        super().__init__(root,None,startup_deadline)
        self.run_id,self.parent_run_id,self.plan_sha256=run_id,parent_run_id,plan_sha256
        source=Path(root)/'tests/postgres/ownedV03ListingsLease.js'
        if source.resolve()!=source or not re.fullmatch('[a-f0-9]{64}',lease_source_sha256 or ''):
            raise ValueError('V03_LISTINGS_LEASE_SOURCE')
        data=_read_lease_source(source,lease_source_sha256)
        text=data.decode('utf8')
        if text.count('const GUEST_SOURCE=String.raw`')!=1 or text.count('`;\nfunction command')!=1:
            raise ValueError('V03_LISTINGS_LEASE_SOURCE')
        self.lease_program=text.split('const GUEST_SOURCE=String.raw`',1)[1].split('`;\nfunction command',1)[0]
        compile(self.lease_program,'<fixed-v03-listings-lease>','exec')
        self.claimed=False;self.claim_record=None

    def activate(self,handoff):
        raise RuntimeError('V03_LISTINGS_EXPLICIT_CLAIM_REQUIRED')

    def claim(self,handoff,*,host_deadline,activation_deadline,guest_record):
        now=time.monotonic()
        if (self.claimed or self.stop.is_set() or self.listener is None or self.acceptor is not None
                or type(host_deadline) not in (int,float) or not math.isfinite(host_deadline)
                or type(activation_deadline) not in (int,float) or not math.isfinite(activation_deadline)
                or not now<activation_deadline<=now+10 or not 1200<=host_deadline-now<=1210):
            raise RuntimeError('V03_LISTINGS_ACTIVATION')
        if (type(guest_record) is not dict or set(guest_record)!={'parentRunId','runId','combinedPlanSha256','guestBootId','phase','startedAtMs','deadlineMs'}
                or guest_record['parentRunId']!=self.parent_run_id or guest_record['runId']!=self.run_id
                or guest_record['combinedPlanSha256']!=self.plan_sha256 or guest_record['phase']!='cohortClaim'
                or not re.fullmatch('[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}',guest_record['guestBootId'] or '')
                or type(guest_record['startedAtMs']) is not int or type(guest_record['deadlineMs']) is not int
                or guest_record['startedAtMs']<0 or guest_record['deadlineMs']-guest_record['startedAtMs']!=1210000):
            raise ValueError('V03_LISTINGS_COHORT_BINDING')
        captured=private_handoff(handoff)
        if captured['runId']!=self.run_id or captured['publicOrigin']!=self.origin:
            raise ValueError('V03_LISTINGS_MANAGER_BINDING')
        # This one transition is not a renewed startup timeout. Both absolute
        # host endpoints were conservatively mapped by the fixed parent before
        # this RPC. The FD server must bind them to its admitted claim response.
        self.claimed=True;self.claim_record=dict(guest_record);self.deadline=host_deadline
        if time.monotonic()>=activation_deadline or self.deadline-time.monotonic()<1200:
            self.stop.set();raise RuntimeError('V03_LISTINGS_ACTIVATION')
        super().activate(captured)

    def _program(self,channel,seconds):
        if not self.claimed:raise RuntimeError('V03_LISTINGS_NOT_CLAIMED')
        original=private_channel_program(self._handoff,channel,seconds)
        needle='end=__import__("time").monotonic()+SECONDS'
        if original.count(needle)!=1:raise RuntimeError('V03_LISTINGS_CHANNEL_SOURCE')
        # Revalidate the immutable guest record/boot and exact observed claim
        # before each channel, then cap the existing lock/connect/pump budget
        # by its absolute endpoint. SSH transit can never add runtime.
        expected=repr(self.claim_record)
        prefix="import sys,io,contextlib,json\n_v03_argv=sys.argv\ntry:\n sys.argv=['lease',"+repr('/var/tmp/owasp-ai-goat-v23-build-'+self.run_id)+','+repr(self.run_id)+",'check','cohort']\n _v03_output=io.StringIO()\n with contextlib.redirect_stdout(_v03_output):exec("+repr(self.lease_program)+",{})\n _v03_claim=json.loads(_v03_output.getvalue())\n assert _v03_claim=="+expected+"\nfinally:sys.argv=_v03_argv\n"
        return prefix+original.replace(needle,"end=min(__import__('time').monotonic()+SECONDS,_v03_claim['deadlineMs']/1000)")

    def _connection(self,client):
        try:
            authority=self.mux.admit_existing_mux(self.root,self.authority)
            seconds=min(120,int(self.deadline-time.monotonic())-7)
            if self.stop.is_set():return
            if seconds<1:raise RuntimeError('V03_LISTINGS_CHANNEL_EXPIRED')
            channel=uuid.uuid4().hex
            with self.guard:self.channel_states[channel]='reserved'
            program=self._program(channel,seconds)
            argv=self.mux.mux_command(authority,shlex.join(['sudo','-n','timeout','--signal=TERM','--kill-after=2',
                str(seconds+5),'/usr/bin/python3','-I','-S','-B','-c',program]))
            def before_spawn():
                with self.guard:
                    if self.stop.is_set() or time.monotonic()>=self.deadline or self.channel_states[channel]!='reserved':
                        raise RuntimeError('V03_LISTINGS_CHANNEL_REVOKED')
                    self.channel_states[channel]='spawn_attempted';self.channels.append(channel)
            outcome=self.mux.relay_connection(client,argv,self.stop,self.children,self.guard,before_spawn=before_spawn)
            if outcome=='never_attempted':
                with self.guard:
                    if self.channel_states[channel]!='reserved':raise RuntimeError('V03_LISTINGS_CHANNEL_STATE')
                    self.channel_states[channel]='never_attempted'
        except BaseException as error:
            self.failures.append(type(error).__name__);self.stop.set()
        finally:
            client.close()
            with self.guard:self.clients.discard(client)
