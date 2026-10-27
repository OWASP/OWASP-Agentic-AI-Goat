import hashlib
import base64
import importlib.util
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from owned_pg_port_settle import wait_owned_pg_port_settled


NETWORK = '5233f7d7d89eb35a7966b3d2b2167ace4503eabec745ccb1872b36962ccd6ae0'
CONTAINER = 'ef93d75dd4906b6c14e0ab7944fa6d15fe8c845ddf32a9080d1a6f5fd9113f75'


def inventory(timer, *, network=NETWORK, container=CONTAINER, ifindex=449,
              state='forwarding', extra_port=False):
    bridge = 'br-' + network[:12]
    links = [
        {'ifindex': 448, 'ifname': bridge, 'address': '9e:c6:2c:99:60:ea',
         'linkinfo': {'info_kind': 'bridge'}},
        {'ifindex': ifindex, 'ifname': 'vethe610bf3',
         'address': 'ca:97:76:95:fd:53', 'master': bridge,
         'link_index': 2, 'link_netnsid': 0,
         'linkinfo': {'info_kind': 'veth', 'info_slave_kind': 'bridge',
                      'info_slave_data': {'state': state, 'forward_delay_timer': timer}}},
    ]
    if extra_port:
        links.append({**links[1], 'ifindex': 450, 'ifname': 'veth000001'})
    return ('"daemon"\nimage\n\nCONTAINERS\n' + container + '\n\nVOLUMES\n\nNETWORK\n'
            + json.dumps({'links': links}, separators=(',', ':')))


class Clock:
    def __init__(self):
        self.value = 0.0
        self.sleeps = []

    def now(self):
        return self.value

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.value += seconds


class PortSettleTest(unittest.TestCase):
    def run_wait(self, values, **kwargs):
        clock = Clock()
        received = iter(values)
        result = wait_owned_pg_port_settled(lambda _remaining: next(received),
            network_id=NETWORK, container_id=CONTAINER, now=clock.now,
            sleep=clock.sleep, **kwargs)
        return result, clock

    def test_waits_for_exact_float_zero_without_normalizing_inventory(self):
        values = [inventory(12.67), inventory(6.0), inventory(0.0)]
        result, clock = self.run_wait(values)
        self.assertEqual(result['polls'], 3)
        self.assertEqual(result['portIfindex'], 449)
        self.assertEqual(result['portIfname'], 'vethe610bf3')
        self.assertEqual(result['settledInventorySha256'], hashlib.sha256(values[-1].encode()).hexdigest())
        self.assertEqual(clock.sleeps, [0.1, 0.1])
        self.assertIn('"forward_delay_timer":12.67', values[0])
        self.assertIn('"forward_delay_timer":0.0', values[-1])

    def test_zero_without_forwarding_is_not_ready(self):
        result, _ = self.run_wait([inventory(0.0, state='learning'), inventory(0.0)])
        self.assertEqual(result['polls'], 2)

    def test_missing_container_and_wrong_bridge_fail_closed(self):
        for value in (inventory(0.0, container='a' * 64),
                      inventory(0.0, network='b' * 64), inventory(0.0, extra_port=True)):
            with self.subTest(value=value[:100]), self.assertRaises(RuntimeError):
                self.run_wait([value])

    def test_port_replacement_fails_even_when_new_port_is_ready(self):
        with self.assertRaisesRegex(RuntimeError, 'port changed'):
            self.run_wait([inventory(2.0), inventory(0.0, ifindex=900)])

    def test_timer_type_and_negative_value_fail_closed(self):
        for timer in (True, '0', -1.0):
            with self.subTest(timer=timer), self.assertRaises(RuntimeError):
                self.run_wait([inventory(timer)])

    def test_deadline_exhaustion_is_bounded(self):
        clock = Clock()
        calls = []
        def read(_remaining):
            calls.append(1)
            return inventory(12.67)
        with self.assertRaisesRegex(RuntimeError, 'did not settle'):
            wait_owned_pg_port_settled(read, network_id=NETWORK, container_id=CONTAINER,
                now=clock.now, sleep=clock.sleep, timeout_seconds=.3, interval_seconds=.1)
        self.assertLessEqual(len(calls), 5)
        self.assertEqual(clock.value, .3)

    def test_read_that_finishes_after_deadline_cannot_pass(self):
        clock = Clock()
        def late(_remaining):
            clock.value = 1.0
            return inventory(0.0)
        with self.assertRaisesRegex(RuntimeError, 'did not settle'):
            wait_owned_pg_port_settled(late, network_id=NETWORK, container_id=CONTAINER,
                now=clock.now, sleep=clock.sleep, timeout_seconds=.3)

    def test_main_settle_inventory_is_ephemeral_and_joined(self):
        path = Path(__file__).with_name('run-secureshop-agent-host-transport-main.py')
        spec = importlib.util.spec_from_file_location('owned_pg_main_settle_test', path)
        main = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(main)
        raw = inventory(0.0).encode()
        timeouts = []
        def communicate(timeout):
            timeouts.append(timeout)
            return json.dumps({'version': 1, 'nestedSpawnCount': 1,
                'nestedPid': 100, 'nestedChildCloseObserved': True,
                'kernelBirthUnavailable': True,
                'completed': True, 'nestedGroupAbsent': True,
                'localRetirementVerified': True, 'failureCode': None,
                'inventoryBase64': base64.b64encode(raw).decode(),
                'inventorySha256': hashlib.sha256(raw).hexdigest()}).encode(), b''
        child = SimpleNamespace(returncode=0, communicate=communicate)
        args = SimpleNamespace(cohort=main.V23_ORIGINAL, node='/fixed/node')
        state = {'debt': False}
        with patch.object(main.subprocess, 'Popen', return_value=child) as popen, \
             patch.object(main, 'stop_process_group') as joined, \
             patch.object(main.os, 'killpg', side_effect=ProcessLookupError):
            observed = main.owned_pg_shared_inventory(args, Path('/source'),
                Path('/nonexistent-evidence'), 'a' * 12, 'settle', remaining_seconds=2.0,
                observer_state=state)
        self.assertEqual(observed.encode(), raw)
        self.assertEqual(popen.call_args.kwargs['stdout'], main.subprocess.PIPE)
        self.assertEqual(popen.call_args.kwargs['stderr'], main.subprocess.PIPE)
        self.assertTrue(popen.call_args.kwargs['start_new_session'])
        self.assertEqual(timeouts, [192.0])
        self.assertEqual(state['debt'], False)
        self.assertEqual(state['totalEnvelopeSeconds'], 235)
        self.assertLess(state['elapsedSeconds'], 235)
        joined.assert_called_once_with(child)

    def test_missing_terminal_and_timeout_retain_pg_observer_debt(self):
        path = Path(__file__).with_name('run-secureshop-agent-host-transport-main.py')
        spec = importlib.util.spec_from_file_location('owned_pg_main_debt_test', path)
        main = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(main)
        args = SimpleNamespace(cohort=main.V23_ORIGINAL, node='/fixed/node')
        for outcome in ('missing-terminal', 'timeout'):
            state = {'debt': False}
            def communicate(timeout):
                if outcome == 'timeout':
                    raise TimeoutError('bounded observer timeout')
                return b'{}', b''
            child = SimpleNamespace(returncode=1, communicate=communicate)
            with self.subTest(outcome=outcome), \
                 patch.object(main.subprocess, 'Popen', return_value=child), \
                 patch.object(main, 'stop_process_group') as joined:
                with self.assertRaises((RuntimeError, TimeoutError)):
                    main.owned_pg_shared_inventory(args, Path('/source'), Path('/no-evidence'),
                        'a' * 12, 'settle', remaining_seconds=1,
                        observer_state=state)
                self.assertFalse(main.pg_observer_may_retire(state))
                joined.assert_called_once_with(child)

    def test_outer_group_retirement_failure_retains_debt_after_inner_absence(self):
        path = Path(__file__).with_name('run-secureshop-agent-host-transport-main.py')
        spec = importlib.util.spec_from_file_location('owned_pg_main_outer_debt_test', path)
        main = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(main)
        raw = inventory(0.0).encode()
        terminal = {'version': 1, 'nestedSpawnCount': 1, 'nestedPid': 100,
                    'nestedChildCloseObserved': True, 'kernelBirthUnavailable': True,
                    'completed': True, 'nestedGroupAbsent': True,
                    'localRetirementVerified': True, 'failureCode': None,
                    'inventoryBase64': base64.b64encode(raw).decode(),
                    'inventorySha256': hashlib.sha256(raw).hexdigest()}
        child = SimpleNamespace(returncode=0,
            communicate=lambda timeout: (json.dumps(terminal).encode(), b''))
        state = {'debt': False}
        args = SimpleNamespace(cohort=main.V23_ORIGINAL, node='/fixed/node')
        with patch.object(main.subprocess, 'Popen', return_value=child), \
             patch.object(main.os, 'killpg', side_effect=ProcessLookupError), \
             patch.object(main, 'stop_process_group', side_effect=RuntimeError('outer group remains')):
            with self.assertRaisesRegex(RuntimeError, 'outer group remains'):
                main.owned_pg_shared_inventory(args, Path('/source'), Path('/no-evidence'),
                    'a' * 12, 'settle', remaining_seconds=1,
                    observer_state=state)
        self.assertFalse(main.pg_observer_may_retire(state))


if __name__ == '__main__':
    unittest.main()
