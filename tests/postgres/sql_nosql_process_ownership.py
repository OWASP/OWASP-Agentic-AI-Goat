"""Owned child registration and interrupt unwinding; import has no side effects."""
import signal
import subprocess

class QualificationInterrupted(RuntimeError):
    pass


class OwnedProcesses:
    def __init__(self, stop_group, record=lambda value: None):
        self.stop_group = stop_group
        self.record = record
        self.children = []
        self.previous = {}
        self.creating = False
        self.pending_signal = None

    def _handle_signal(self, signum, _frame):
        if self.creating:
            self.pending_signal = signum
            return
        raise QualificationInterrupted('Qualification interrupted by handled signal')

    def install(self):
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            self.previous[signum] = signal.getsignal(signum)
            signal.signal(signum, self._handle_signal)

    def mask_cleanup_signals(self):
        for signum in self.previous:
            signal.signal(signum, signal.SIG_IGN)

    def restore(self):
        for signum, handler in self.previous.items():
            signal.signal(signum, handler)
        self.previous.clear()

    def launch(self, command, *, name, factory=subprocess.Popen, **kwargs):
        if kwargs.get('start_new_session') is not True:
            raise RuntimeError('Owned child requires a new process session')
        self.creating = True
        try:
            child = factory(command, **kwargs)
            # start_new_session establishes both identities from the child PID;
            # never query an already exited process with getpgid/getsid here.
            self.children.append((name, child))
            self.record(dict(name=name, pid=child.pid, pgid=child.pid, sessionId=child.pid, status='registered'))
        finally:
            self.creating = False
        if self.pending_signal is not None:
            self.pending_signal = None
            raise QualificationInterrupted('Qualification interrupted during child creation')
        return child

    def finish(self, child):
        matches = [(name, value) for name, value in self.children if value is child]
        if not matches:
            return
        name, _ = matches[0]
        self.creating = True
        try:
            self.stop_group(child, child.pid, child.pid)
            # Remove immediately after verified cleanup, before journal I/O. A
            # later journal failure must never re-signal an old/reused group.
            self.children = [(key, value) for key, value in self.children if value is not child]
            self.record(dict(name=name, pid=child.pid, pgid=child.pid, sessionId=child.pid, status='cleanup_verified'))
        finally:
            self.creating = False
        if self.pending_signal is not None:
            self.pending_signal = None
            raise QualificationInterrupted('Qualification interrupted during child cleanup')

    def cleanup(self):
        failures = []
        for _name, child in list(reversed(self.children)):
            try:
                self.finish(child)
            except BaseException as error:
                failures.append(error)
        if failures:
            raise RuntimeError('Owned process cleanup not verified') from failures[0]
