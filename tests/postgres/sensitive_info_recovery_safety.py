"""Pure cleanup/signal primitives for the reset recovery launcher."""

import json
import time

GRACEFUL_SHUTDOWN_SECONDS = 75


def canonicalize_metadata_records(records):
    """Return a deterministic copy without discarding privilege distinctions."""
    return sorted((dict(record) for record in records),
                  key=lambda record:json.dumps(record,sort_keys=True,separators=(',',':')))


def classify_inventory_difference(original, restored):
    comparison = {}
    changed = False
    for store in sorted(set(original)|set(restored)):
        left = original.get(store,{})
        right = restored.get(store,{})
        entries = {}
        for key in sorted(set(left)|set(right)):
            before = left.get(key)
            after = right.get(key)
            matches = before == after
            gating = not key.endswith('_raw')
            if isinstance(before,dict) and before.get('gating') is False: gating = False
            if isinstance(after,dict) and after.get('gating') is False: gating = False
            changed = changed or (gating and not matches)
            entries[key] = {'original':before,'restored':after,
                            'matches':matches,'gating':gating}
        comparison[store] = entries
    return comparison, changed


def classify_process_state(returncode, stdout, *, probe_pid):
    """Classify ps output; only ProcessLookupError proves an absent process."""
    state = stdout.strip()
    if returncode == 0:
        if not state:
            raise RuntimeError('process status query returned no state')
        return state
    if returncode == 1 and not state:
        try:
            probe_pid()
        except ProcessLookupError:
            return None
        except PermissionError as error:
            raise RuntimeError('process existence probe was denied') from error
        raise RuntimeError('process status query failed for an existing process')
    raise RuntimeError('process status query failed unexpectedly')

class SignalGate:
    def __init__(self):
        self.cleanup_started = False
        self.received = []

    def handler(self, signum, _frame=None):
        self.received.append(signum)
        if not self.cleanup_started:
            raise InterruptedError(f'received signal {signum}')

    def protect_cleanup(self):
        self.cleanup_started = True


def wait_for_exit(probe_state, timeout_seconds=GRACEFUL_SHUTDOWN_SECONDS,
                  *, monotonic=time.monotonic, sleeper=time.sleep):
    """Wait until a process is absent or exited-but-unreaped (zombie)."""
    deadline = monotonic() + timeout_seconds
    while True:
        state = probe_state()
        if state is None:
            return 'absent'
        if 'Z' in state:
            return 'zombie'
        if monotonic() >= deadline:
            raise TimeoutError('reviewed backend did not exit within its lifecycle deadline')
        sleeper(.1)


def protected_cleanup(*, started, paused, remove_container, exact_absence,
                      resume_watcher, health_check):
    """Attempt every cleanup stage even when an earlier stage fails."""
    errors = []
    remove_exit_code = None
    absent = None
    watcher_resumed = False
    health = False
    if started:
        try:
            remove_exit_code = remove_container()
        except Exception as error:  # cleanup evidence records type, never secrets
            errors.append(f'remove:{type(error).__name__}')
    try:
        absent = exact_absence()
    except Exception as error:
        errors.append(f'absence:{type(error).__name__}')
    if paused:
        try:
            watcher_resumed = resume_watcher() is True
        except Exception as error:
            errors.append(f'resume:{type(error).__name__}')
        if watcher_resumed:
            try:
                health = health_check() is True
            except Exception as error:
                errors.append(f'health:{type(error).__name__}')
    return {
        'removeExitCode': remove_exit_code,
        'containerAbsent': absent,
        'containerCleanupDebt': absent is not True,
        'watcherResumed': watcher_resumed,
        'health200': health,
        'errors': errors,
    }
