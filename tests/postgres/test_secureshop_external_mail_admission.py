"""Offline exact MAIN admission function controls; no SMTP or child execution."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
MAIN = ROOT / 'tests/postgres/run-secureshop-agent-host-transport-main.py'
tree = ast.parse(MAIN.read_text())
node = next(item for item in tree.body if isinstance(item, ast.FunctionDef)
            and item.name == 'external_mail_environment')
scope = dict(Path=Path, hashlib=hashlib, json=json, os=os, re=re, stat=stat)
exec(compile(ast.Module(body=[node], type_ignores=[]), str(MAIN), 'exec'), scope)
admit = scope['external_mail_environment']


class ExternalMailAdmission(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='external-mail-admission-', dir=ROOT / 'tasks/tmp')
        self.parent = Path(self.temp.name)
        self.file = self.parent / 'dedicated.json'
        self.data = json.dumps({'sender': 'synthetic@gmail.com', 'appPassword': 'a' * 16}).encode()
        fd = os.open(self.file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(self.data)
        self.args = SimpleNamespace(cohort='standalone-commerce-browser', current_host_profile='current',
            external_mail_private_config=str(self.file), external_mail_config_sha256=hashlib.sha256(self.data).hexdigest(),
            external_mail_recipient='goat-0123456789abcdef@sharklasers.com')

    def tearDown(self):
        self.temp.cleanup()

    def test_default_off(self):
        self.assertEqual(admit(SimpleNamespace(), ROOT), {})

    def test_exact_private_config_only(self):
        result = admit(self.args, ROOT)
        self.assertEqual(set(result), {'SECURESHOP_EXTERNAL_MAIL_RENDERED_SEND',
            'SECURESHOP_EXTERNAL_MAIL_TEST_RECIPIENT', 'SS_EXTERNAL_MAIL_ENABLED',
            'SS_EXTERNAL_MAIL_GMAIL_USER', 'SS_EXTERNAL_MAIL_GMAIL_APP_PASSWORD'})
        self.assertEqual(result['SECURESHOP_EXTERNAL_MAIL_TEST_RECIPIENT'], self.args.external_mail_recipient)

    def test_cross_cohort_and_partial_denied(self):
        for name, value in [('cohort', 'customer-checkout-browser'), ('current_host_profile', None),
                            ('external_mail_recipient', None), ('external_mail_recipient', 'other@sharklasers.com'),
                            ('external_mail_config_sha256', '0' * 64)]:
            with self.subTest(field=name):
                args = SimpleNamespace(**vars(self.args)); setattr(args, name, value)
                with self.assertRaises(RuntimeError): admit(args, ROOT)

    def test_permissions_links_aliases_denied(self):
        os.chmod(self.file, 0o644)
        with self.assertRaises(RuntimeError): admit(self.args, ROOT)
        os.chmod(self.file, 0o600)
        link = self.parent / 'alias.json'; link.symlink_to(self.file)
        self.args.external_mail_private_config = str(link)
        with self.assertRaises(RuntimeError): admit(self.args, ROOT)
        self.args.external_mail_private_config = str(self.file)
        hard = self.parent / 'hard.json'; os.link(self.file, hard)
        with self.assertRaises(RuntimeError): admit(self.args, ROOT)

    def test_no_config_values_in_errors(self):
        self.file.write_bytes(b'{"sender":"private-marker", "appPassword":"private-marker"}')
        self.args.external_mail_config_sha256 = hashlib.sha256(self.file.read_bytes()).hexdigest()
        with self.assertRaises(RuntimeError) as caught: admit(self.args, ROOT)
        self.assertNotIn('private-marker', str(caught.exception))

    def test_duplicate_keys_and_size_denied(self):
        for data in [b'{"sender":"synthetic@gmail.com","sender":"synthetic@gmail.com","appPassword":"aaaaaaaaaaaaaaaa"}', b'x' * 4097]:
            self.file.write_bytes(data)
            self.args.external_mail_config_sha256 = hashlib.sha256(data).hexdigest()
            with self.assertRaises(RuntimeError): admit(self.args, ROOT)

    def test_post_read_metadata_drift(self):
        real = os.fstat; calls = 0
        def changed(fd):
            nonlocal calls
            info = real(fd); calls += 1
            if calls == 1: return info
            result = SimpleNamespace(**{key: getattr(info, key) for key in
                ('st_dev','st_ino','st_uid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')})
            result.st_mtime_ns += 1
            return result
        with patch.object(os, 'fstat', changed):
            with self.assertRaises(RuntimeError): admit(self.args, ROOT)

    def test_read_primary_survives_close_failure_and_close_alone_denies(self):
        real_close = os.close
        def close_fault(fd):
            real_close(fd)
            raise OSError('injected close')
        with patch.object(os, 'close', close_fault):
            with patch.object(os, 'read', side_effect=RuntimeError('injected primary')):
                with self.assertRaisesRegex(RuntimeError, 'injected primary'): admit(self.args, ROOT)
            with self.assertRaisesRegex(RuntimeError, 'PRIVATE_CLOSE_FAILED'): admit(self.args, ROOT)

    def test_fifo_denied_without_blocking(self):
        self.file.unlink(); os.mkfifo(self.file, 0o600)
        with self.assertRaises(RuntimeError): admit(self.args, ROOT)


if __name__ == '__main__':
    unittest.main()
