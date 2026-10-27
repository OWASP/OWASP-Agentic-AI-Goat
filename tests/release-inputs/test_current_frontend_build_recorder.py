"""Inert recorder controls; temporary files only, never run Vite or allocate native resources."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
from contextlib import redirect_stdout
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location('frontend_recorder', Path(__file__).with_name('record-current-frontend-build.py'))
RECORDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECORDER)


class RendererRecorderControls(unittest.TestCase):
    def setUp(self):
        self.private = tempfile.TemporaryDirectory()
        self.addCleanup(self.private.cleanup)
        self.root = Path(self.private.name).resolve()
        self.build = self.root / 'output/application'
        self.echo = self.build / 'secureshop-search-echo-renderer'
        self.policy = self.build / 'secureshop-policy-output-renderer'
        self.ticket = self.build / 'secureshop-ticket-renderer'
        specs = [('review', 'SecureShop.ReviewCard', 'ReviewCard.jsx', None, 'renderer.cjs'),
                 ('product-description', 'SecureShop.Product.Description', 'ProductDescription.jsx', None, 'renderer.cjs'),
                 ('mail', 'SecureShop.MailMessageBody', 'MailMessageBody.jsx', 'mailMessageClientRenderer.jsx', 'renderer.js'),
                 ('ticket', 'SecureShop.AdminTicketBody', 'AdminTicketBody.jsx', 'ticketDetailClientRenderer.jsx', 'renderer.js'),
                 ('search-echo', 'SecureShop.SearchEcho', 'AgentLane/SearchEcho.jsx', 'searchEchoClientRenderer.jsx', 'renderer.js'),
                 ('policy-output', 'SecureShop.PolicyFinalResponse', 'AgentLane/Turn.jsx', 'policyOutputClientRenderer.jsx', 'renderer.js')]
        for name, component, source_name, entry_name, artifact in specs:
            directory = self.build / f'secureshop-{name}-renderer'
            directory.mkdir(parents=True)
            source = 'client/src/pages/secureshop/components/' + source_name
            entry = ('client/src/pages/secureshop/' if name in ('search-echo', 'policy-output') else 'client/src/pages/secureshop/components/') + entry_name if entry_name else None
            for rel in [source] + ([entry] if entry else []):
                target = self.root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(f'controlled source {rel}')
            (directory / artifact).write_text(f'controlled artifact {name}')
            manifest = {'version': 1, 'component': component,
                        'source': source, 'sourceSha256': RECORDER.digest(self.root / source),
                        'artifact': artifact, 'artifactSha256': RECORDER.digest(directory / artifact)}
            if entry:
                manifest.update(entry=entry, entrySha256=RECORDER.digest(self.root / entry))
            (directory / 'manifest.json').write_text(json.dumps(manifest))
        self.manifest = json.loads((self.ticket / 'manifest.json').read_text())

    def test_private_command_and_output_environment_include_exact_ticket_config(self):
        node = Path('/pinned/bin/node')
        with patch.object(RECORDER.subprocess, 'run', side_effect=AssertionError('No build execution')):
            command = RECORDER.private_command(node)
            env = RECORDER.private_env(self.root, self.root, node)
        self.assertEqual(command[:3], [str(node), '--input-type=module', '-e'])
        self.assertEqual(command[3].count("'vite.ticket-renderer.config.mjs'"), 1)
        self.assertEqual(command[3].count("'vite.search-echo-renderer.config.mjs'"), 1)
        self.assertEqual(command[3].count("'vite.policy-output-renderer.config.mjs'"), 1)
        self.assertEqual(env['SECURESHOP_POLICY_OUTPUT_RENDERER_OUT_DIR'], str(self.policy))
        self.assertEqual(env['SECURESHOP_SEARCH_ECHO_RENDERER_OUT_DIR'], str(self.echo))
        self.assertEqual(env['SECURESHOP_TICKET_RENDERER_OUT_DIR'], str(self.ticket))
        self.assertTrue(Path(env['SECURESHOP_TICKET_RENDERER_OUT_DIR']).is_relative_to(Path(env['BUILD_PATH'])))
        config = (Path(__file__).resolve().parents[2] / 'client/vite.ticket-renderer.config.mjs').read_text()
        self.assertIn('process.env.SECURESHOP_TICKET_RENDERER_OUT_DIR', config)

    def test_explicit_pinned_repo_node_and_npm_plan_without_build(self):
        node = self.root / 'node'
        npm = self.root / 'npm-cli.js'
        node.write_bytes(b'controlled node')
        node.chmod(0o700)
        npm.write_bytes(b'controlled npm cli')
        npm.chmod(0o700)
        alias = self.root / 'npm'
        alias.symlink_to(npm)
        node_sha = RECORDER.digest(node)
        npm_sha = RECORDER.digest(npm)
        argv = ['recorder', '--repository-only', '--node', str(node), '--node-sha256', node_sha,
                '--npm-cli', str(npm), '--npm-sha256', npm_sha]
        with patch.object(RECORDER, 'REPO_NODE', node), patch.object(RECORDER, 'REVIEWED_NPM', npm), \
                patch.object(RECORDER, 'REVIEWED_NPM_ALIAS', alias), \
                patch.object(sys, 'argv', argv), \
                patch.object(RECORDER.subprocess, 'Popen', side_effect=AssertionError('build launched')):
            output = io.StringIO()
            with redirect_stdout(output):
                RECORDER.main()
        planned = json.loads(output.getvalue())
        self.assertEqual(planned, {'execute': False, 'command': [str(node), str(npm),
            '--prefix', 'client', 'run', 'build']})
        def replace(flag, value):
            updated = list(argv)
            updated[updated.index(flag) + 1] = value
            return updated
        for changed in (replace('--node-sha256', '0' * 64),
                        replace('--npm-sha256', '0' * 64),
                        replace('--node', str(self.root / 'missing')),
                        replace('--npm-cli', str(node))):
            with self.subTest(changed=changed), patch.object(RECORDER, 'REPO_NODE', node), \
                    patch.object(RECORDER, 'REVIEWED_NPM', npm), \
                    patch.object(RECORDER, 'REVIEWED_NPM_ALIAS', alias), \
                    patch.object(sys, 'argv', changed):
                with self.assertRaises(RuntimeError):
                    RECORDER.main()
        alternate = self.root / 'same-npm-bytes.js'
        alternate.write_bytes(npm.read_bytes())
        with patch.object(RECORDER, 'REPO_NODE', node), patch.object(RECORDER, 'REVIEWED_NPM', npm), \
                patch.object(RECORDER, 'REVIEWED_NPM_ALIAS', alias), \
                patch.object(sys, 'argv', replace('--npm-cli', str(alternate))):
            with self.assertRaisesRegex(RuntimeError, 'runtime path'):
                RECORDER.main()
        with patch.object(sys, 'argv', argv + ['--private-external-output']), \
                patch.object(RECORDER.tempfile, 'mkdtemp', side_effect=AssertionError('allocation')):
            with self.assertRaises(SystemExit):
                RECORDER.main()
        link = self.root / 'node-link'
        link.symlink_to(node)
        with self.assertRaisesRegex(RuntimeError, 'canonical'):
            RECORDER.runtime_path(link, node_sha, 'Node', executable=True)
        npm_link = self.root / 'npm-link'
        npm_link.symlink_to(npm)
        with self.assertRaisesRegex(RuntimeError, 'canonical'):
            RECORDER.runtime_path(npm_link, npm_sha, 'npm CLI')
        alias.unlink()
        alias.symlink_to(node)
        with self.assertRaisesRegex(RuntimeError, 'nested npm alias'):
            RECORDER.validate_nested_npm_alias(npm, alias)

    def test_repository_build_path_resolves_nested_npm_with_pinned_node(self):
        self.assertEqual(RECORDER.validate_nested_npm_alias(RECORDER.REVIEWED_NPM),
                         RECORDER.REVIEWED_NPM_ALIAS)
        private = self.root / 'owned-build'
        for name in ('tmp', 'npm-cache', 'config'):
            (private / name).mkdir(parents=True, exist_ok=True)
        (private / 'npmrc').touch()
        env = RECORDER.clean_env(RECORDER.ROOT, private, RECORDER.REPO_NODE,
                                 repository_only=True)
        self.assertEqual(shutil.which('node', path=env['PATH']), str(RECORDER.REPO_NODE))
        self.assertEqual(shutil.which('npm', path=env['PATH']), str(RECORDER.REVIEWED_NPM_ALIAS))
        self.assertEqual(env['PATH'].split(':')[:2],
                         [str(RECORDER.REPO_NODE.parent), '/opt/homebrew/bin'])
        self.assertNotIn('HOME', env)
        result = subprocess.run(['npm', '--version'], env=env, cwd=RECORDER.ROOT,
                                capture_output=True, text=True, timeout=15, check=True)
        self.assertRegex(result.stdout.strip(), r'^\d+\.\d+\.\d+$')

    def test_repo_private_build_environment_has_no_home_or_external_output(self):
        private = self.root / 'tasks' / 'qualification'
        private.mkdir(parents=True, mode=0o700)
        with patch.object(RECORDER, 'ROOT', self.root):
            self.assertEqual(RECORDER.repository_evidence_parent(), private)
        env = RECORDER.clean_env(self.root, private, self.root / 'node', repository_only=True)
        self.assertNotIn('HOME', env)
        self.assertEqual(RECORDER.clean_env(self.root, private, self.root / 'node')['HOME'], str(private / 'home'))
        for name in ('TMPDIR', 'TMP', 'TEMP', 'XDG_CACHE_HOME', 'XDG_CONFIG_HOME',
                     'npm_config_cache', 'npm_config_userconfig'):
            self.assertTrue(Path(env[name]).is_relative_to(private), name)
        private.chmod(0o755)
        with patch.object(RECORDER, 'ROOT', self.root):
            with self.assertRaisesRegex(RuntimeError, 'private'):
                RECORDER.repository_evidence_parent()

    def test_owned_group_cleanup_uses_birth_checked_native_members(self):
        observed = []
        births = []
        responses = iter([[50001], [], [], [], []])
        def group(pgid, seen, witness):
            observed.append(pgid)
            births.append(seen)
            self.assertEqual(witness, (123, 456))
            return next(responses)
        child = type('Child', (), {'pid': 50001, 'poll': lambda self: 0,
            'wait': lambda self, timeout: 0})()
        with patch.object(RECORDER, 'native_members', side_effect=group), \
                patch.object(RECORDER.os, 'killpg') as signals:
            RECORDER.stop(child, 50001, 50001, (123, 456))
        self.assertEqual(observed, [50001] * 5)
        self.assertTrue(all(value is births[0] for value in births))
        signals.assert_called_once_with(50001, RECORDER.signal.SIGTERM)
        with self.assertRaisesRegex(RuntimeError, 'identity'):
            RECORDER.stop(child, 50001, 50002, (123, 456))

    def test_unknown_or_changed_launch_birth_never_signals_group(self):
        child = type('Child', (), {'pid': 50001, 'poll': lambda self: 0,
            'wait': lambda self, timeout: 0})()
        row = SimpleNamespace(pid=50001, pgid=50001, uid=RECORDER.os.getuid(),
            start_sec=123, start_usec=457)
        api = SimpleNamespace(identity=lambda _pid: row)
        inventory = SimpleNamespace(LibProc=lambda: api,
            owned_group_members=lambda _pgid, **_kwargs: [50001])
        with patch.object(RECORDER, 'process_inventory', return_value=inventory), \
                patch.object(RECORDER.os, 'getsid', return_value=50001), \
                patch.object(RECORDER.os, 'killpg') as signals:
            with self.assertRaisesRegex(RuntimeError, 'birth'):
                RECORDER.stop(child, 50001, 50001, (123, 456))
            with self.assertRaisesRegex(RuntimeError, 'witness'):
                RECORDER.stop(child, 50001, 50001, None)
        signals.assert_not_called()
        api.identity = lambda _pid: None
        with patch.object(RECORDER, 'process_inventory', return_value=inventory), \
                patch.object(RECORDER.os, 'killpg') as signals:
            with self.assertRaisesRegex(RuntimeError, 'birth'):
                RECORDER.stop(child, 50001, 50001, (123, 456))
            with self.assertRaisesRegex(RuntimeError, 'witness'):
                RECORDER.capture_birth(50001)
        signals.assert_not_called()

    @unittest.skipUnless(sys.platform == 'darwin', 'Darwin current-host process inspection')
    def test_real_owned_birth_is_visible_inside_repository_wrapper(self):
        child = RECORDER.subprocess.Popen([sys.executable, '-B', '-c',
            'import sys; sys.stdin.read()'], stdin=RECORDER.subprocess.PIPE,
            stdout=RECORDER.subprocess.DEVNULL, stderr=RECORDER.subprocess.DEVNULL,
            start_new_session=True)
        try:
            birth = RECORDER.capture_birth(child.pid)
            self.assertEqual(len(birth), 2)
            self.assertIn(child.pid, RECORDER.members(child.pid, {}, birth))
        finally:
            child.stdin.close()
            child.wait(timeout=5)
        self.assertEqual(RECORDER.members(child.pid, {}, birth), [])

    def test_private_input_receipt_pins_ticket_config_without_installation_environment(self):
        paths = ['package.json', 'package-lock.json', 'client/package.json', 'client/package-lock.json',
                 'client/index.html', 'client/secureshop-frame.html', 'client/vite.config.mjs',
                 'client/vite.review-renderer.config.mjs', 'client/vite.product-description-renderer.config.mjs',
                 'client/vite.mail-renderer.config.mjs', 'client/vite.ticket-renderer.config.mjs', 'client/vite.search-echo-renderer.config.mjs',
                 'client/vite.policy-output-renderer.config.mjs', 'client/vite.opaque-frame-cors.mjs', 'tests/release-inputs/record-current-frontend-build.py',
                 'tests/postgres/sql_nosql_process_ownership.py', 'tests/postgres/darwin_process_inventory.py']
        for rel in paths:
            target = self.root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f'controlled input {rel}')
        (self.root / '.env').write_text('PRIVATE_SENTINEL=do-not-read')
        with patch.object(RECORDER, 'inventory', return_value={}):
            captured = RECORDER.private_inputs(self.root)
        self.assertEqual(captured['configPins']['client/vite.ticket-renderer.config.mjs'],
                         RECORDER.digest(self.root / 'client/vite.ticket-renderer.config.mjs'))
        self.assertEqual(captured['configPins']['client/vite.search-echo-renderer.config.mjs'],
                         RECORDER.digest(self.root / 'client/vite.search-echo-renderer.config.mjs'))
        self.assertEqual(captured['configPins']['client/vite.policy-output-renderer.config.mjs'],
                         RECORDER.digest(self.root / 'client/vite.policy-output-renderer.config.mjs'))
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps(captured))
        self.assertNotIn('environmentPins', captured)

    def test_six_renderer_validation_and_output_receipt_include_original_ticket_bytes(self):
        RECORDER.validate_renderers(self.root, self.build)
        output = RECORDER.inventory(self.build)
        for name in ('manifest.json', 'renderer.js'):
            self.assertEqual(output[f'secureshop-ticket-renderer/{name}']['sha256'], RECORDER.digest(self.ticket / name))
        before = RECORDER.fingerprint(output)
        (self.ticket / 'renderer.js').write_text('changed artifact')
        self.assertNotEqual(RECORDER.fingerprint(RECORDER.inventory(self.build)), before)
        with self.assertRaisesRegex(RuntimeError, 'Renderer artifact mismatch'):
            RECORDER.validate_renderers(self.root, self.build)

    def test_ticket_manifest_missing_changed_or_escaped_output_fails_closed(self):
        mutations = [('version', 2), ('component', 'Surrogate'), ('source', 'client/src/mail.jsx'),
                     ('entry', 'client/src/mail-entry.jsx'), ('artifact', '../renderer.js'),
                     ('sourceSha256', '0' * 64), ('entrySha256', '0' * 64), ('artifactSha256', '0' * 64),
                     ('privateExtra', True)]
        for key, value in mutations:
            with self.subTest(field=key):
                manifest = copy.deepcopy(self.manifest)
                manifest[key] = value
                (self.ticket / 'manifest.json').write_text(json.dumps(manifest))
                with self.assertRaises(RuntimeError):
                    RECORDER.validate_renderers(self.root, self.build)
        (self.ticket / 'manifest.json').write_text(json.dumps(self.manifest))
        artifact = self.ticket / 'renderer.js'
        outside = self.root / 'escaped-renderer.js'
        outside.write_bytes(artifact.read_bytes())
        artifact.unlink(); artifact.symlink_to(outside)
        with self.assertRaisesRegex(RuntimeError, 'Noncanonical renderer artifact'):
            RECORDER.validate_renderers(self.root, self.build)
        artifact.unlink(); artifact.write_bytes(outside.read_bytes())
        (self.ticket / 'manifest.json').unlink()
        with self.assertRaises(FileNotFoundError):
            RECORDER.validate_renderers(self.root, self.build)

    def test_search_echo_manifest_missing_changed_or_escaped_output_fails_closed(self):
        original = json.loads((self.echo / 'manifest.json').read_text())
        mutations = [('version', 2), ('component', 'Surrogate'), ('source', 'client/src/mail.jsx'),
                     ('entry', 'client/src/mail-entry.jsx'), ('artifact', '../renderer.js'),
                     ('sourceSha256', '0' * 64), ('entrySha256', '0' * 64), ('artifactSha256', '0' * 64),
                     ('privateExtra', True)]
        for key, value in mutations:
            with self.subTest(field=key):
                manifest = copy.deepcopy(original)
                manifest[key] = value
                (self.echo / 'manifest.json').write_text(json.dumps(manifest))
                with self.assertRaises(RuntimeError):
                    RECORDER.validate_renderers(self.root, self.build)
        (self.echo / 'manifest.json').write_text(json.dumps(original))
        artifact = self.echo / 'renderer.js'
        outside = self.root / 'escaped-renderer.js'
        outside.write_bytes(artifact.read_bytes())
        artifact.unlink(); artifact.symlink_to(outside)
        with self.assertRaisesRegex(RuntimeError, 'Noncanonical renderer artifact'):
            RECORDER.validate_renderers(self.root, self.build)
        artifact.unlink(); artifact.write_bytes(outside.read_bytes())
        (self.echo / 'manifest.json').unlink()
        with self.assertRaises(FileNotFoundError):
            RECORDER.validate_renderers(self.root, self.build)

    def test_historical_renderer_self_consistent_substitutions_are_rejected(self):
        for name in ('review', 'product-description', 'mail', 'policy-output'):
            directory = self.build / f'secureshop-{name}-renderer'
            file = directory / 'manifest.json'
            original = json.loads(file.read_text())
            changed = copy.deepcopy(original)
            changed.update(component='Wrong.Component', source=self.manifest['source'],
                           sourceSha256=self.manifest['sourceSha256'])
            variants = [changed, {**original, 'component': 'Wrong.Component'},
                        {**original, 'source': self.manifest['source'], 'sourceSha256': self.manifest['sourceSha256']},
                        {**original, 'privateExtra': True}, {**original, 'version': 2}]
            if name in ('mail', 'policy-output'):
                variants.append({**original, 'entry': self.manifest['entry'], 'entrySha256': self.manifest['entrySha256']})
            for value in variants:
                with self.subTest(renderer=name, manifest=value):
                    file.write_text(json.dumps(value))
                    with self.assertRaisesRegex(RuntimeError, 'Renderer manifest mismatch'):
                        RECORDER.validate_renderers(self.root, self.build)
            alternate = directory / ('wrong' + Path(original['artifact']).suffix)
            alternate.write_bytes((directory / original['artifact']).read_bytes())
            file.write_text(json.dumps({**original, 'artifact': alternate.name, 'artifactSha256': RECORDER.digest(alternate)}))
            with self.assertRaisesRegex(RuntimeError, 'Renderer manifest mismatch'):
                RECORDER.validate_renderers(self.root, self.build)
            file.write_text(json.dumps(original))
            outside = self.root / f'outside-{name}'
            directory.rename(outside); directory.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, 'Noncanonical renderer output'):
                RECORDER.validate_renderers(self.root, self.build)
            directory.unlink(); outside.rename(directory)
        RECORDER.validate_renderers(self.root, self.build)


if __name__ == '__main__':
    unittest.main()
