#!/usr/bin/env python3
"""Fixed V30 coordinator outside the worker's repository sandbox.

Only the reviewed full-catalog profile has a live gate. This coordinator's
--plan reports gate state; the MAIN --plan performs resource admission. No
generic process or filesystem operation is exposed over either host channel.
"""
import os
from pathlib import Path
import secrets
import select
import signal
import socket
import subprocess
import sys
import time

import v30_agent_host_controller as host
from trusted_process_inspector import FD_ENV, Inspector, MAX_FRAME as INSPECTOR_MAX_FRAME


def inspector_receive(channel, *, timeout=2):
    # Same unique-key length-prefixed JSON schema and smaller Inspector bound;
    # only this outside coordinator adds an absolute full-frame deadline.
    return host.receive(channel, timeout=timeout, max_frame=INSPECTOR_MAX_FRAME)


def inspector_send(channel, value, *, timeout=2):
    return host.send(channel, value, timeout=timeout, max_frame=INSPECTOR_MAX_FRAME)


def validate_arguments(arguments):
    if not isinstance(arguments, list) or any(type(arg) is not str or '\x00' in arg for arg in arguments):
        raise RuntimeError('V30_CONTROLLER_ARGUMENTS')
    for option, value in (('--cohort', 'v30-original-disclosure'),):
        if arguments.count(option) != 1:
            raise RuntimeError('V30_CONTROLLER_ARGUMENTS')
        index = arguments.index(option)
        if index + 1 == len(arguments) or arguments[index + 1] != value:
            raise RuntimeError('V30_CONTROLLER_ARGUMENTS')
    if not arguments or arguments[0] != '--run' or arguments.count('--run') != 1 or '--plan' in arguments:
        raise RuntimeError('V30_CONTROLLER_ARGUMENTS')
    if arguments.count('--v30-original-profile') != 1:
        raise RuntimeError('V30_CONTROLLER_ARGUMENTS')
    index = arguments.index('--v30-original-profile')
    if index + 1 == len(arguments) or arguments[index + 1] not in host.PROFILES:
        raise RuntimeError('V30_CONTROLLER_ARGUMENTS')
    return arguments[index + 1]


def closed_response(request, code='V30_CONTROLLER_REJECTED'):
    # Do not echo malformed frames, unknown fields, raw exception text, or paths.
    host.exact(request, ('version', 'sequence', 'nonce', 'pid', 'op', 'payload'))
    return {key: request[key] for key in ('version', 'sequence', 'nonce', 'op')} | \
        {'ok': False, 'result': None, 'error': code}


def coordinate(repo, arguments):
    selected_profile = validate_arguments(arguments)
    admitted = host.FULL_LIVE_ENABLED if selected_profile == host.FULL_PROFILE else host.LIVE_ENABLED
    if not admitted:
        raise RuntimeError('V30_CONTROLLER_UNQUALIFIED')
    if sys.platform != 'darwin':
        raise RuntimeError('V30_CONTROLLER_DARWIN_REQUIRED')
    repo = Path(repo)
    if repo.resolve(strict=True) != repo:
        raise RuntimeError('V30_CONTROLLER_SOURCE')
    wrapper = host.canonical_file(repo, 'tasks/run-native-current.sh')
    if any(key in os.environ for key in (FD_ENV, host.LAUNCHER_FD_ENV, host.WORKER_FD_ENV, host.NONCE_ENV)):
        raise RuntimeError('V30_CONTROLLER_NESTED')
    inspector_parent, inspector_child = socket.socketpair()
    launch_parent, launch_child = socket.socketpair()
    worker_parent, worker_child = socket.socketpair()
    pairs = (inspector_parent, inspector_child, launch_parent, launch_child, worker_parent, worker_child)
    for channel in pairs: channel.settimeout(2)
    nonce = secrets.token_hex(32)
    environment = {**os.environ, FD_ENV: str(inspector_child.fileno()),
        host.LAUNCHER_FD_ENV: str(launch_child.fileno()), host.WORKER_FD_ENV: str(worker_child.fileno()),
        host.NONCE_ENV: nonce, 'PYTHONDONTWRITEBYTECODE': '1'}
    child = controller = None
    stopping = False; worker_open = True; launcher_open = True; inspector_open = True
    deadline = time.monotonic() + 1200
    prior = {}
    def interrupted(*_):
        nonlocal stopping
        stopping = True
    for number in (signal.SIGINT, signal.SIGTERM):
        prior[number] = signal.signal(number, interrupted)
    failure = None; cleanup_errors = []; shutdown_deadline = None
    def stop_host():
        try: controller.stop()
        except BaseException as error: cleanup_errors.append(error)
    def begin_shutdown():
        nonlocal shutdown_deadline
        if shutdown_deadline is not None: return
        shutdown_deadline = time.monotonic() + 120
        # Join the outside-owned host before asking the launcher to retire PG.
        # Retain failure but keep its status/inspector channels alive so cleanup
        # can report uncertainty rather than deadlock behind this owner.
        if controller is not None: stop_host()
        if child is not None and child.poll() is None:
            try: child.send_signal(signal.SIGINT)
            except BaseException as error: cleanup_errors.append(error)
    def service_once(shutting_down=False):
        nonlocal launcher_open, worker_open, inspector_open
        def frame_budget():
            limit = shutdown_deadline if shutting_down else deadline
            if not shutting_down and driver.host_started is not None:
                limit = min(limit, driver.host_started + 600)
            budget = min(2, limit-time.monotonic())
            if budget <= 0: raise TimeoutError('V30_CONTROLLER_FRAME_TIMEOUT')
            return budget
        watched = ([launch_parent] if launcher_open else []) + ([inspector_parent] if inspector_open else [])
        if worker_open and controller.worker_pid is not None: watched.append(worker_parent)
        ready, _, _ = select.select(watched, [], [], .1)
        for channel in ready:
            if channel is inspector_parent:
                try:
                    request = inspector_receive(channel, timeout=frame_budget())
                    inspector_send(channel, inspector.handle(request), timeout=frame_budget())
                except Exception:
                    inspector_open = False; channel.close()
                continue
            side = 'launcher' if channel is launch_parent else 'worker'
            try:
                request = host.receive(channel, timeout=frame_budget())
            except Exception:
                if side == 'launcher': launcher_open = False
                else: worker_open = False
                channel.close(); stop_host(); continue
            try:
                # Shutdown permits only already-owned status/retirement. Never
                # issue a new grant, worker birth, or host start while draining.
                if shutting_down and request.get('op') not in ('status', 'stop', 'release', 'signal'):
                    raise RuntimeError('V30_CONTROLLER_SHUTTING_DOWN')
                response = controller.response(side, request)
            except Exception:
                stop_host()
                try: response = closed_response(request)
                except Exception:
                    if side == 'launcher': launcher_open = False
                    else: worker_open = False
                    channel.close(); continue
            try: host.send(channel, response, timeout=frame_budget())
            except Exception:
                stop_host()
                if side == 'launcher': launcher_open = False
                else: worker_open = False
                channel.close()
        controller.status()
    try:
        # --run is an outside-controller capability selector. MAIN's live mode
        # is its default and must never receive this coordinator-only token.
        child = subprocess.Popen(['/bin/bash', str(wrapper), *arguments[1:]], cwd=repo,
            env=environment, close_fds=True,
            pass_fds=(inspector_child.fileno(), launch_child.fileno(), worker_child.fileno()),
            start_new_session=True)
        for channel in (inspector_child, launch_child, worker_child): channel.close()
        driver = host.DarwinDriver(repo, child.pid, expected_profile=selected_profile)
        controller = host.Controller(repo, child.pid, nonce, driver)
        inspector = Inspector(repo, child.pid)
        while child.poll() is None:
            if stopping or time.monotonic() >= deadline:
                begin_shutdown()
            if driver.host_started is not None and time.monotonic() - driver.host_started >= 600:
                begin_shutdown()
            if shutdown_deadline is not None and time.monotonic() >= shutdown_deadline:
                raise RuntimeError('V30_CONTROLLER_LAUNCHER_CLEANUP_TIMEOUT')
            service_once(shutdown_deadline is not None)
        return child.returncode
    except BaseException as error:
        failure = error
        raise
    finally:
        if child is not None and child.poll() is None:
            begin_shutdown()
            # Error exits must service the same private channels too. A real
            # wait/reap is observed by poll; no blocking wait strands cleanup RPC.
            while child.poll() is None and time.monotonic() < shutdown_deadline:
                if controller is not None and 'inspector' in locals():
                    try: service_once(True)
                    except BaseException as error:
                        cleanup_errors.append(error)
                        time.sleep(.05)
                else: time.sleep(.05)
            if child.poll() is None:
                cleanup_errors.append(RuntimeError('V30_CONTROLLER_LAUNCHER_CLEANUP_TIMEOUT'))
        if controller is not None:
            try: controller.close()
            except BaseException as error: cleanup_errors.append(error)
        for channel in pairs:
            try: channel.close()
            except OSError: pass
        for number, handler in prior.items(): signal.signal(number, handler)
        if cleanup_errors and failure is None:
            raise RuntimeError('V30_CONTROLLER_CLEANUP_INCOMPLETE') from cleanup_errors[0]


if __name__ == '__main__':
    if sys.argv[1:] == ['--plan']:
        print(host.encoded({'version': 1, 'liveEnabled': host.LIVE_ENABLED,
            'fullCatalogLiveEnabled': host.FULL_LIVE_ENABLED,
            'profile': host.PROFILE, 'supportedProfiles': host.PROFILES,
            'command': 'agent-host/index.js',
            'hostLimitSeconds': 600, 'arbitrarySpawn': False}).decode())
    else:
        raise SystemExit(coordinate(Path(__file__).resolve().parents[2], sys.argv[1:]))
