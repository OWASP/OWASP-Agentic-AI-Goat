"""Offline controls of the actual Listings bridge and shared relay boundary."""
import socket
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import listings_native_resources as resource
import owned_mcp_mux_relay as relay


ROOT = Path(__file__).resolve().parents[2]


class Client:
    def __init__(self): self.closes = 0; self.blocking = True
    def close(self): self.closes += 1
    def shutdown(self, _how): pass
    def setblocking(self, value): self.blocking = value


class Stream:
    def __init__(self): self.closed = False
    def fileno(self): return 0
    def close(self): self.closed = True


class Child:
    def __init__(self): self.stdin = Stream(); self.stdout = Stream(); self.terminated = False
    def poll(self): return 0 if self.terminated else None
    def terminate(self): self.terminated = True
    def wait(self, timeout=None): return 0


def bridge(command=None):
    value = resource.PrivateListingsBridge.__new__(resource.PrivateListingsBridge)
    value.root = ROOT; value._handoff = {}; value.deadline = time.monotonic() + 30
    value.stop = threading.Event(); value.guard = threading.Lock()
    value.children = set(); value.clients = set(); value.threads = []
    value.channels = []; value.channel_states = {}; value.failures = []
    value.listener = None; value.acceptor = None; value.authority = object()
    value.mux = SimpleNamespace(admit_existing_mux=lambda *_: object(),
        mux_command=command or (lambda _authority, _command: ['/bin/cat']),
        relay_connection=relay.relay_connection)
    return value


class LaunchAccounting(unittest.TestCase):
    def run_connection(self, value, client):
        value.clients.add(client)
        with patch.object(resource, 'private_channel_program', return_value='pass'):
            value._connection(client)

    def test_stop_before_channel_reservation(self):
        value = bridge(); value.stop.set(); client = Client()
        with patch.object(relay.subprocess, 'Popen', side_effect=AssertionError('spawned')):
            self.run_connection(value, client)
        closed = value.close(time.monotonic() + 5)
        self.assertEqual(closed['channelIds'], ())
        self.assertEqual(closed['channelStates'], ())

    def test_stop_during_command_proves_never_attempted(self):
        value = bridge(); client = Client()
        value.mux.mux_command = lambda *_: (value.stop.set() or ['/bin/cat'])
        with patch.object(relay.subprocess, 'Popen', side_effect=AssertionError('spawned')):
            self.run_connection(value, client)
        closed = value.close(time.monotonic() + 5)
        self.assertEqual(closed['channelIds'], ())
        self.assertEqual([row['state'] for row in closed['channelStates']], ['never_attempted'])

    def test_stop_after_callback_before_guest_journal_preserves_attempt(self):
        value = bridge(); client = Client(); child = Child()
        def spawn(*_args, **_kwargs):
            value.stop.set()
            return child
        with patch.object(relay.subprocess, 'Popen', side_effect=spawn), \
                patch.object(relay.os, 'set_blocking'):
            self.run_connection(value, client)
        closed = value.close(time.monotonic() + 5)
        self.assertEqual(len(closed['channelIds']), 1)
        self.assertEqual(closed['channelStates'][0]['state'], 'spawn_attempted')
        self.assertTrue(child.terminated and child.stdin.closed and child.stdout.closed)

    def test_popen_exception_keeps_ambiguous_id_and_failure(self):
        value = bridge(); client = Client()
        with patch.object(relay.subprocess, 'Popen', side_effect=OSError('controlled')):
            self.run_connection(value, client)
        closed = value.close(time.monotonic() + 5)
        self.assertEqual(len(closed['channelIds']), 1)
        self.assertEqual(closed['channelStates'][0]['state'], 'spawn_attempted')
        self.assertEqual(closed['failures'], ('OSError',))

    def test_local_relay_completion_keeps_attempted_id(self):
        value = bridge(); client, peer = socket.socketpair()
        try:
            peer.sendall(b'hello'); peer.shutdown(socket.SHUT_WR)
            self.run_connection(value, client)
            closed = value.close(time.monotonic() + 5)
            self.assertEqual(len(closed['channelIds']), 1)
            self.assertEqual(closed['channelStates'][0]['state'], 'spawn_attempted')
            self.assertFalse(value.children)
            self.assertEqual(peer.recv(16), b'hello')
        finally: peer.close()

    def test_close_joins_transition_before_export(self):
        entered = threading.Event(); release = threading.Event()
        def command(*_):
            entered.set(); self.assertTrue(release.wait(3))
            return ['/bin/cat']
        value = bridge(command); client = Client()
        connection = threading.Thread(target=self.run_connection, args=(value, client))
        value.threads.append(connection); connection.start()
        self.assertTrue(entered.wait(3))
        result = []; errors = []
        def close():
            try: result.append(value.close(time.monotonic() + 5))
            except BaseException as error: errors.append(error)
        closer = threading.Thread(target=close); closer.start()
        self.assertTrue(value.stop.wait(3)); release.set()
        closer.join(5); connection.join(5)
        self.assertFalse(closer.is_alive() or connection.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(result[0]['channelIds'], ())
        self.assertEqual(result[0]['channelStates'][0]['state'], 'never_attempted')

    def test_unresolved_reserved_state_fails_closed(self):
        value = bridge(); value.channel_states['a'*32] = 'reserved'
        with self.assertRaisesRegex(RuntimeError, 'RETIREMENT_UNPROVEN'):
            value.close(time.monotonic() + 5)


if __name__ == '__main__': unittest.main()
