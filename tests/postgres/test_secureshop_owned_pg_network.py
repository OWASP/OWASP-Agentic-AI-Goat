"""Controlled real MAIN network composition; no Docker, VM or models."""
import copy
import importlib.util
import inspect
import json
import os
import re
import subprocess
from pathlib import Path
import tempfile
import textwrap
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location('owned_pg_main', HERE / 'run-secureshop-agent-host-transport-main.py')
main = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(main)
ID = 'a' * 64
PG = 'b' * 64


def response(stdout='', code=0, stderr=''):
    return SimpleNamespace(stdout=stdout, returncode=code, stderr=stderr)


class Docker:
    def __init__(self):
        self.rows = {}; self.calls = []; self.daemon = 'exact-daemon'; self.lost = False
        self.remove_lost = False; self.pg = None; self.network = None; self.effects = []

    def __call__(self, parts):
        self.calls.append(parts)
        if parts == ['info', '--format', '{{.ID}}']:
            return response(self.daemon + '\n')
        if parts[:2] == ['network', 'ls']:
            return response(''.join(key + ' ' + row['Name'] + '\n' for key, row in self.rows.items()))
        if parts[:2] == ['network', 'create']:
            journal = json.loads((self.network.evidence / 'pg-network.json').read_text())
            assert journal['state'] == 'create-intent'
            assert journal['creationIntent'] is True and journal['creationAttempted'] is False
            assert journal['beforeNetworks'] == []
            assert re.fullmatch('[a-f0-9]{64}', journal['sharedBeforeSha256'])
            assert (self.network.evidence / 'pg-network.json').stat().st_mode & 0o777 == 0o600
            self.effects.append('network-create')
            self.rows[ID] = {'Id': ID, 'Name': parts[-1], 'Labels': dict(self.network.labels),
                'Driver': 'bridge', 'Scope': 'local', 'Internal': False, 'Attachable': False,
                'Ingress': False, 'EnableIPv6': False, 'ConfigOnly': False, 'Options': {},
                'IPAM': {'Driver': 'default', 'Options': {}, 'Config': [{'Subnet': '172.20.0.0/16', 'Gateway': '172.20.0.1'}]},
                'Containers': {}}
            return response('' if self.lost else ID + '\n', 1 if self.lost else 0)
        if parts[:2] == ['network', 'inspect']:
            return response(json.dumps([self.rows[parts[2]]]))
        if parts[:2] == ['network', 'rm']:
            assert self.pg is None
            self.effects.append('network-remove'); del self.rows[parts[2]]
            return response('', 1 if self.remove_lost else 0)
        raise AssertionError(parts)


class OwnedNetworkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / 'tasks/tmp')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.docker = Docker(); self.snapshots = []

    def network(self, cohort=None, *, private_listings=False):
        cohort = cohort or main.V23_ORIGINAL
        def snapshot(phase):
            self.snapshots.append(phase)
            self.assertIsNone(self.docker.pg)
            return 'strict-shared-baseline'
        network = main.OwnedPostgresNetwork(cohort, self.docker, 'exact-daemon',
            'owasp-ai-goat-' + cohort + '-abcdef123456-pg-network',
            {'owasp-ai-goat.owner': 'controlled-owner', 'owasp-ai-goat.cohort': cohort}, self.path, snapshot,
            private_listings=private_listings)
        self.docker.network = network
        return network

    def strict_producer_snapshot(self, default_members):
        # Execute the actual emitted Python snapshot with read-only command
        # doubles. The strict admission condition is not reimplemented here.
        text = (HERE / 'ownedMcpBoundedBuild.js').read_text()
        program = text.split('const networkSnapshotProgram = String.raw`', 1)[1].split('`;', 1)[0]
        program = program.rsplit("print(json.dumps(snapshot(), sort_keys=True, separators=(',', ':')))", 1)[0]
        namespace = {}; exec(program, namespace)
        bridge = {'Containers': default_members, 'Options': {'com.docker.network.bridge.name': 'docker0'},
            'IPAM': {'Config': [{'Gateway': '172.17.0.1'}]}}
        def read(parts):
            if parts[0] == 'docker': return json.dumps([bridge])
            if parts[:5] == ['ip', '-json', '-details', 'link', 'show']:
                return json.dumps([{'ifname': 'docker0', 'linkinfo': {'info_kind': 'bridge'}}])
            if parts[:3] == ['ip', '-json', 'address']:
                return json.dumps([{'ifname': 'docker0', 'addr_info': [{'local': '172.17.0.1'}]}])
            if parts[0] == 'ip': return '[]'
            if parts[0] in ('iptables-save', 'ip6tables-save'): return ''
            if parts[0] == 'nft': return '{"nftables":[]}'
            if parts[0] == 'sysctl': return '1\n0\n'
            raise AssertionError(parts)
        namespace['read'] = read
        return namespace['snapshot']()

    def test_only_two_selectors_and_normal_success(self):
        for cohort in (main.V23_ORIGINAL, main.POLICY_INSTRUCTION_BROWSER):
            with self.subTest(cohort=cohort):
                network = self.network(cohort); network.create()
                self.assertEqual(network.attach_args(), ['--network', network.name])
                result = network.close(owner_quiescent=True, pg_absent=True)
                self.assertEqual(result, {'networkAbsent': True, 'sharedStatePreserved': True, 'errors': []})
                self.assertEqual(self.docker.effects[-2:], ['network-create', 'network-remove'])
        self.assertFalse(main.owned_pg_network_selected('transport'))
        with self.assertRaises(RuntimeError): self.network('transport')

    def test_durable_intent_failure_has_zero_creation(self):
        network = self.network()
        with patch.object(main.os, 'fsync', side_effect=OSError('sync failed')):
            with self.assertRaises(OSError): network.create()
        self.assertFalse(network.intent); self.assertEqual(self.docker.effects, [])

    def test_lost_create_ack_retains_original_failure_and_exact_cleanup_identity(self):
        network = self.network(); self.docker.lost = True
        with self.assertRaisesRegex(RuntimeError, 'unacknowledged'): network.create()
        self.assertEqual(network.identifier, ID)
        record = json.loads((self.path / 'pg-network.json').read_text())
        self.assertEqual(record['networkId'], ID)
        self.assertEqual(record['state'], 'create-failed-identity-recovered')
        self.assertEqual(network.close(owner_quiescent=True, pg_absent=True)['errors'], [])

    def test_absent_admission_and_identity_replacement_are_not_adopted(self):
        network = self.network()
        self.docker.rows[ID] = {'Name': network.name}
        with self.assertRaisesRegex(RuntimeError, 'occupied'): network.create()
        self.assertEqual(self.docker.effects, [])
        self.docker.rows.clear(); network = self.network(); network.create()
        original = self.docker.rows.pop(ID)
        self.docker.rows['c' * 64] = {**original, 'Id': 'c' * 64}
        result = network.close(owner_quiescent=True, pg_absent=True)
        self.assertTrue(result['errors']); self.assertFalse(result['networkAbsent'])
        self.assertNotIn('network-remove', self.docker.effects)
        self.assertEqual(self.snapshots[-1], 'after')

    def test_attachment_rejects_default_extra_network_wrong_id_and_sibling(self):
        network = self.network(); network.create()
        self.docker.rows[ID]['Containers'] = {PG: {}}
        original = {'Id': PG, 'HostConfig': {'NetworkMode': network.name},
            'NetworkSettings': {'Networks': {network.name: {'NetworkID': ID}}}}
        network.verify_attachment(original)
        for change in (lambda row: row['HostConfig'].update(NetworkMode='bridge'),
                       lambda row: row['NetworkSettings']['Networks'].update(bridge={'NetworkID': ID}),
                       lambda row: row['NetworkSettings']['Networks'][network.name].update(NetworkID='d' * 64)):
            row = copy.deepcopy(original); change(row)
            with self.assertRaisesRegex(RuntimeError, 'attachment'): network.verify_attachment(row)
        self.docker.rows[ID]['Containers']['d' * 64] = {}
        with self.assertRaisesRegex(RuntimeError, 'attachment'): network.verify_attachment(original)

    def test_debt_or_nonempty_membership_vetoes_deletion(self):
        network = self.network(); network.create()
        for owner, pg in ((False, True), (True, False), (None, True)):
            result = network.close(owner_quiescent=owner, pg_absent=pg)
            self.assertTrue(result['errors']); self.assertNotIn('network-remove', self.docker.effects)
        self.docker.rows[ID]['Containers'][PG] = {}
        result = network.close(owner_quiescent=True, pg_absent=True)
        self.assertTrue(result['errors']); self.assertNotIn('network-remove', self.docker.effects)

    def test_remove_ack_loss_preserves_error_but_independently_proves_absence(self):
        network = self.network(); network.create(); self.docker.remove_lost = True
        result = network.close(owner_quiescent=True, pg_absent=True)
        self.assertTrue(result['errors']); self.assertTrue(result['networkAbsent']); self.assertTrue(result['sharedStatePreserved'])

    def test_identity_and_layout_changes_remain_untouched(self):
        for mutate in (lambda row: row['Labels'].update(extra='foreign'),
                       lambda row: row.update(Driver='host'), lambda row: row.update(Internal=True),
                       lambda row: row.update(Options={'arbitrary': 'value'}),
                       lambda row: row['IPAM']['Config'][0].update(Gateway='192.0.2.1')):
            self.docker = Docker(); network = self.network(); network.create(); mutate(self.docker.rows[ID])
            result = network.close(owner_quiescent=True, pg_absent=True)
            self.assertTrue(result['errors']); self.assertNotIn('network-remove', self.docker.effects)

    def test_daemon_and_malformed_duplicate_listing_fail_before_effect(self):
        network = self.network(); self.docker.daemon = 'foreign'
        with self.assertRaisesRegex(RuntimeError, 'daemon'): network.create()
        self.assertEqual(self.docker.effects, [])
        for output in ('bad\n', ID + ' one\n' + ID + ' two\n', ID + ' one\n' + 'c' * 64 + ' one\n'):
            def command(parts):
                return response('exact-daemon\n') if parts[0] == 'info' else response(output)
            network.command = command
            with self.assertRaises(RuntimeError): network.listing()

    def test_actual_inventory_node_program_with_clean_env_and_real_import_closure(self):
        node = ROOT / 'tasks/runtime/node/node_modules/node/bin/node'
        bootstrap = r"""const assert=require('node:assert/strict');
const cp=require('node:child_process'),{EventEmitter}=require('node:events'),{PassThrough}=require('node:stream');
const {gunzipSync}=require('node:zlib'),{createHash}=require('node:crypto');
assert.equal(process.env.HOME,undefined);
cp.spawn=(file,args,options)=>{
 assert.equal(file,process.cwd()+'/tasks/runtime/container/bin/limactl');
 assert.deepEqual(options.env,{PATH:'/usr/bin:/bin',HOME:require('node:os').userInfo().homedir,
 TMPDIR:process.cwd()+'/tasks/tmp',LIMA_HOME:process.cwd()+'/tasks/l'});
 assert.equal(args[0],'shell');assert.equal(args[3],'colima-goat-q');
 const b=require('./tests/postgres/ownedMcpBoundedBuild');
 const transported=args[args.indexOf('-c')+1];
 assert.match(transported,/^\/usr\/bin\/python3 -I -S -B -c /);
 const encoded=transported.match(/'([A-Za-z0-9+/=]{40,})' '[a-f0-9]{64}' "\$0" "\$@"$/);
 assert(encoded,'actual gzip phase transport must carry one bounded decoded script');
 const script=gunzipSync(Buffer.from(encoded[1],'base64')).toString('utf8');
 assert.equal(script,b._internals.scripts.inventory);
 assert(transported.includes("'"+createHash('sha256').update(script).digest('hex')+"'"));
 const network={version:1,bridge:{Containers:{}},links:[{ifname:'docker0'}],addresses:[],routes4:[],routes6:[],rules4:[],rules6:[],firewall4:'',firewall6:'',nft:{},forwarding:'1'};
 const text=JSON.stringify(b.PINS.daemon)+'\n'+b.PINS.postgres+' postgres:18\nCONTAINERS\n\nVOLUMES\n\nNETWORK\n'+JSON.stringify(network);
 const child=new EventEmitter();Object.assign(child,{pid:undefined,exitCode:null,signalCode:null,
 stdin:new PassThrough(),stdout:new PassThrough(),stderr:new PassThrough()});
 queueMicrotask(()=>{child.stdout.end(text);child.emit('close',0,null)});return child;
};
"""
        original_popen = subprocess.Popen
        launched = []; joined = []
        def launch(command, **kwargs):
            self.assertEqual(command[0], str(node))
            self.assertNotIn('HOME', kwargs['env'])
            launched.append(command)
            command = [*command]; command[2] = bootstrap + command[2]
            return original_popen(command, **kwargs)
        args = SimpleNamespace(cohort=main.V23_ORIGINAL, node=str(node))
        with patch.object(main.subprocess, 'Popen', side_effect=launch), \
                patch.object(main, 'stop_process_group', side_effect=lambda child: joined.append(child.wait(timeout=3))):
            text = main.owned_pg_shared_inventory(args, ROOT, self.path, 'abcdef123456', 'before')
        self.assertEqual(len(launched), 1); self.assertEqual(joined, [0])
        self.assertIn('NETWORK\n', text)
        # Use the actual source_snapshot closure-discovery program (without
        # invoking the unrelated cohort filesystem/browser inventory).
        function = inspect.getsource(main.source_snapshot)
        statement = next(line.strip() for line in function.splitlines() if line.strip().startswith('program = "require(\'./tests/postgres/ownedMcpOriginalBuildAdapter'))
        namespace = {}; exec(statement, namespace)
        result = subprocess.run([str(node), '-e', namespace['program']], cwd=ROOT,
            env={'PATH': str(node.parent)}, capture_output=True, text=True, check=True, timeout=20)
        imported = json.loads(result.stdout)
        self.assertIn('tests/postgres/ownedMcpOriginalBuildAdapter.js', imported)
        self.assertIn('tests/postgres/ownedMcpBoundedBuild.js', imported)
        self.assertIn('scripts/install/secureshop-owned-mcp-registry-setup.js', imported)
        self.assertTrue(all((ROOT / name).is_file() for name in imported))

    def test_main_actual_prepare_attach_strict_inventory_cleanup_composition(self):
        source = inspect.getsource(main.main)
        prepare = textwrap.dedent(source[source.index("        stage = 'container-name-admission'"):
            source.index("        stage = 'postgres-tcp-readiness'")])
        cleanup = textwrap.dedent(source[source.index("        cleanup = {'containerNameAbsent'"):
            source.index('        if audit_creation_attempted:', source.index("        cleanup = {'containerNameAbsent'"))])
        for cohort,private_listings in ((main.V23_ORIGINAL,False),(main.POLICY_INSTRUCTION_BROWSER,False),
                                      ('transport',False),('standalone-listings-browser',True),
                                      ('standalone-listings-browser',False)):
            for debt in (False, True):
                with self.subTest(cohort=cohort, debt=debt):
                    self.docker = Docker(); network = self.network(cohort,private_listings=private_listings) if main.owned_pg_network_selected(cohort,private_listings=private_listings) else None
                    name = 'owasp-ai-goat-' + cohort + '-abcdef123456'
                    args = SimpleNamespace(cohort=cohort, image_id='sha256:' + 'e' * 64,
                        docker_daemon='exact-daemon', pricing_v34_transition_preflight=False)
                    def raw(_args, _clean, parts, timeout):
                        self.assertEqual(parts[0], 'run')
                        if network:
                            self.assertEqual(parts[parts.index('--network') + 1], network.name)
                            self.assertEqual(self.snapshots[-1], 'before')
                            self.assertEqual(self.docker.effects[-1], 'network-create')
                        else: self.assertNotIn('--network', parts)
                        self.docker.pg = PG; self.docker.effects.append('pg-create')
                        if network: self.docker.rows[ID]['Containers'][PG] = {}
                        return response(PG + '\n')
                    def inspected(_command, **kwargs):
                        if self.docker.pg is None: return None
                        return {'Id': PG, 'HostConfig': {'NetworkMode': network.name if network else 'default'},
                            'NetworkSettings': {'Networks': {network.name if network else 'bridge': {'NetworkID': ID}}}}
                    def remove(_command, **kwargs):
                        self.assertEqual(kwargs['captured_id'], PG)
                        self.docker.effects.append('pg-remove'); self.docker.pg = None
                        if network: self.docker.rows[ID]['Containers'].clear()
                        return {'status': 'controlled-absence'}
                    state = dict(vars(main), args=args, clean={}, ownership_command=self.docker, container=name,
                        expected_labels={'owasp-ai-goat.owner': 'controlled-owner', 'owasp-ai-goat.cohort': cohort},
                        labels=[], pg_network=network, creation_attempted=False, captured_id=None,
                        raw_docker_command=raw, inspect_owned=inspected, validate_container_layout=lambda row: 23456,
                        cleanup_owned=remove, docker_absent=lambda *_args: self.docker.pg is None,
                        cleanup_errors=[], v30_v2=False, v30_child_quiescent=True, v30_host_quiescent=True,
                        pg_observer_state={'debt': False},
                        v34_owner_state={'attempted': False, 'retirementVerified': False, 'result': None,
                            'retirementError': None, 'receipt': None, 'receiptPath': None, 'originalPath': None},
                        mail_inline_source_after=True,
                        v24_owner_attempted=debt, v24_owner_quiescent=not debt, v24_owner_result=None,
                        v23_owner_attempted=debt, v23_child_quiescent=not debt, v23_owner_result=None,
                        listings_private_producer=None,primary_error=None)
                    if private_listings:
                        def close():
                            if debt:raise RuntimeError('controlled Listings retirement debt')
                            return dict(cleanupVerified=True,workSucceeded=False,producerExitCode=1,qualificationComplete=False)
                        state['listings_private_producer']=SimpleNamespace(close=close,closed=not debt)
                    exec(prepare, state)
                    if network:
                        # The producer's strict default-bridge rule is unchanged:
                        # the actual MAIN attachment is exclusively on the owned bridge.
                        row = inspected(None)
                        self.assertNotIn('bridge', row['NetworkSettings']['Networks'])
                        self.assertEqual(self.docker.rows[ID]['Containers'], {PG: {}})
                        self.assertEqual(self.strict_producer_snapshot({})['bridge']['Containers'], {})
                        with self.assertRaisesRegex(ValueError, 'shared bridge not idle'):
                            self.strict_producer_snapshot({PG: {}})
                        self.docker.effects.append('strict-producer-inventory')
                    exec(cleanup, state)
                    if network and debt:
                        self.assertNotIn('pg-remove', self.docker.effects)
                        self.assertNotIn('network-remove', self.docker.effects)
                        self.assertTrue(state['cleanup_errors'])
                    else:
                        self.assertIsNone(self.docker.pg)
                        if network:
                            self.assertEqual(self.docker.effects[-2:], ['pg-remove', 'network-remove'])
                            self.assertTrue(state['cleanup']['ownedPostgresNetwork']['sharedStatePreserved'])
                            if private_listings:self.assertEqual(state['primary_error']['type'],'ListingsProducerFailure')
        builder = (HERE / 'ownedMcpBoundedBuild.js').read_text()
        self.assertIn("bridge[0].get('Containers') != {}: raise ValueError('shared bridge not idle')", builder)

    def test_private_listings_network_selection_is_explicit_and_original_cohort_only(self):
        self.assertTrue(main.owned_pg_network_selected('standalone-listings-browser',private_listings=True))
        for cohort,selection in (('standalone-listings-browser',False),('standalone-listings-browser',1),
                                 ('transport',True),('merchant-listings-chat-browser',True)):
            self.assertFalse(main.owned_pg_network_selected(cohort,private_listings=selection))
        with self.assertRaisesRegex(RuntimeError,'Closed owned'):
            self.network('standalone-listings-browser')
        # Execute MAIN's actual construction expression so a selector-only fix
        # cannot omit the admitted flag at the real owner boundary.
        import ast
        tree=ast.parse(inspect.getsource(main.main))
        assignment=next(n for n in ast.walk(tree) if isinstance(n,ast.Assign)
                        and any(isinstance(t,ast.Name) and t.id=='pg_network' for t in n.targets))
        for packet in (None,{'controlled':'already-admitted-plan'}):
            ns=dict(vars(main),args=SimpleNamespace(cohort='standalone-listings-browser',
                    docker_daemon='exact-daemon',pricing_v34_transition_preflight=False),
                    listings_private_admitted=packet,ownership_command=self.docker,
                    container='owasp-ai-goat-standalone-listings-browser-abcdef123456',
                    expected_labels={'owasp-ai-goat.owner':'controlled-owner','owasp-ai-goat.cohort':'standalone-listings-browser'},
                    evidence=self.path,source=ROOT,nonce='abcdef123456')
            exec(compile(ast.Module(body=[assignment],type_ignores=[]),'<actual MAIN construction>','exec'),ns)
            if packet is None:self.assertIsNone(ns['pg_network'])
            else:self.assertIsInstance(ns['pg_network'],main.OwnedPostgresNetwork)


if __name__ == '__main__':
    unittest.main()
