"""Inert recorder controls; temporary files only, never run Vite or allocate native resources."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

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

    def test_private_input_receipt_pins_ticket_config_without_installation_environment(self):
        paths = ['package.json', 'package-lock.json', 'client/package.json', 'client/package-lock.json',
                 'client/index.html', 'client/secureshop-frame.html', 'client/vite.config.mjs',
                 'client/vite.review-renderer.config.mjs', 'client/vite.product-description-renderer.config.mjs',
                 'client/vite.mail-renderer.config.mjs', 'client/vite.ticket-renderer.config.mjs', 'client/vite.search-echo-renderer.config.mjs',
                 'client/vite.policy-output-renderer.config.mjs', 'client/vite.opaque-frame-cors.mjs', 'tests/release-inputs/record-current-frontend-build.py',
                 'tests/postgres/sql_nosql_process_ownership.py']
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
