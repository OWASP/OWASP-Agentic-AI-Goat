"""Closed Listings phase facade over an already-owned inherited Unix socket.

No launch, Docker access, plan-to-authority conversion, or standalone live entry.
The parent retains the registered producer process and must join it separately.
"""
import json
import math
import re
import socket
import time


class ListingsPhaseDebt(RuntimeError):
    remote_completion_unverified = True


class ListingsPhaseClient:
    # Frame/window/once-only checks are local; the producer's listingsLifetime
    # remains the authority for ordering phase effects and releasing the builder.
    PHASES = frozenset(('listingsProfileInstall', 'listingsManagerCreate', 'listingsManagerStart',
                       'listingsManagerChannels', 'listingsManagerRetire', 'listingsProfileRetire'))
    RETIREMENT = frozenset(('listingsManagerChannels', 'listingsManagerRetire', 'listingsProfileRetire'))
    FRAME_CAP = 16384  # Existing producer pairChannel framing bound.

    def __init__(self, channel, run_id, plan_sha256, work_deadline, *, now=time.monotonic):
        if (type(channel) is not socket.socket or channel.family != socket.AF_UNIX
                or channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or not re.fullmatch('[a-f0-9]{32}', run_id or '')
                or not re.fullmatch('[a-f0-9]{64}', plan_sha256 or '')
                or type(work_deadline) not in (int, float) or not math.isfinite(work_deadline)
                or not 0 < work_deadline-now() <= 600):
            raise ValueError('LISTINGS_PHASE_ADMISSION')
        self.channel, self.run_id, self.plan_sha256 = channel, run_id, plan_sha256
        self.work_deadline, self.cleanup_deadline, self.now = work_deadline, None, now
        self.sequence = 0; self.admitted = False; self.closed = False; self.debt = False
        self.attempted = set(); self.completed = set(); self.confirmed = False

    def _remaining(self, deadline):
        left = deadline-self.now()
        if not math.isfinite(left) or left <= 0: raise TimeoutError('LISTINGS_PHASE_DEADLINE')
        return left

    def _frame(self, op, payload, deadline):
        if self.closed or self.debt: raise ListingsPhaseDebt('LISTINGS_PHASE_CLOSED_OR_DEBT')
        envelope = dict(version=1, op=op, runId=self.run_id, planSha256=self.plan_sha256,
                        sequence=self.sequence, **payload)
        raw = (json.dumps(envelope, sort_keys=True, separators=(',', ':'))+'\n').encode()
        if len(raw)>self.FRAME_CAP: raise ValueError('LISTINGS_PHASE_FRAME_CAP')
        self.channel.settimeout(self._remaining(deadline)); self.channel.sendall(raw)

    def _read(self, op, keys, deadline):
        data=bytearray()
        while True:
            self.channel.settimeout(self._remaining(deadline))
            chunk=self.channel.recv(1)
            if not chunk: raise EOFError('LISTINGS_PHASE_EOF')
            data.extend(chunk)
            if len(data)>self.FRAME_CAP: raise ValueError('LISTINGS_PHASE_FRAME_CAP')
            if chunk==b'\n': break
        def unique(pairs):
            row={}
            for key,value in pairs:
                if key in row: raise ValueError('LISTINGS_PHASE_DUPLICATE_KEY')
                row[key]=value
            return row
        row=json.loads(data,object_pairs_hook=unique)
        expected=dict(version=1,op=op,runId=self.run_id,planSha256=self.plan_sha256,sequence=self.sequence)
        if (type(row) is not dict or set(row)!=set(expected)|set(keys)
                or any(type(row[k]) is not type(v) or row[k]!=v for k,v in expected.items())):
            raise ValueError('LISTINGS_PHASE_BINDING')
        self._remaining(deadline)
        return row

    def _poison(self, error):
        self.debt=True
        self.close()
        raise ListingsPhaseDebt('LISTINGS_PHASE_COMPLETION_UNPROVEN') from error

    def admit(self):
        if self.admitted or self.sequence: raise ValueError('LISTINGS_PHASE_REPLAY')
        try:
            self._read('hello', (), self.work_deadline)
            self.epoch = self.now()  # Server anchors to its earlier hello send.
            self._frame('admit', dict(remainingMs=int(self._remaining(self.work_deadline)*1000)), self.work_deadline)
            self._read('admitted', (), self.work_deadline)
            self.admitted=True; self.sequence+=1
        except BaseException as error: self._poison(error)

    def begin_retirement(self, deadline):
        if (not self.admitted or self.cleanup_deadline is not None or type(deadline) not in (int,float)
                or not math.isfinite(deadline) or not 0<deadline-self.now()<=600):
            raise ValueError('LISTINGS_PHASE_RETIREMENT_GRANT')
        self.cleanup_deadline=deadline
        try:
            self._frame('retirement',dict(remainingMs=int(self._remaining(deadline)*1000),
                                         deadlineOffsetMs=int((deadline-self.epoch)*1000)),deadline)
            self._read('retirement-admitted',(),deadline);self.sequence+=1
        except BaseException as error:self._poison(error)

    def run_phase(self, name, value=None):
        if not self.admitted or name not in self.PHASES or name in self.attempted:
            raise ValueError('LISTINGS_PHASE_OPERATION')
        retiring=name in self.RETIREMENT
        if retiring!=(self.cleanup_deadline is not None):raise ValueError('LISTINGS_PHASE_WINDOW')
        deadline=self.cleanup_deadline if retiring else self.work_deadline
        self.attempted.add(name)
        try:
            self._frame('phase',dict(name=name,input=value,remainingMs=int(self._remaining(deadline)*1000)),deadline)
            row=self._read('result',('name','output'),deadline)
            if row['name']!=name or type(row['output']) is not str or len(row['output'].encode())>8192:
                raise ValueError('LISTINGS_PHASE_RESULT')
            self.completed.add(name);self.sequence+=1;return row['output']
        except BaseException as error:self._poison(error)

    def confirm_retired(self):
        if self.cleanup_deadline is None or self.confirmed or not self.RETIREMENT<=self.completed:
            raise ValueError('LISTINGS_PHASE_RETIREMENT_UNPROVEN')
        try:
            self._frame('confirm',dict(remainingMs=int(self._remaining(self.cleanup_deadline)*1000)),self.cleanup_deadline)
            self._read('retired',(),self.cleanup_deadline)
            self.confirmed=True;self.sequence+=1
        except BaseException as error:self._poison(error)

    def close(self):
        if self.closed:return
        self.closed=True
        try:self.channel.shutdown(socket.SHUT_RDWR)
        except OSError:pass
        self.channel.close()
