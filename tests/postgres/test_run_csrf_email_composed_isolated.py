import importlib.util
import io
import json
import signal
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


MODULE_PATH = Path(__file__).with_name("run-csrf-email-composed-isolated.py")
SPEC = importlib.util.spec_from_file_location("run_csrf_email_composed_isolated", MODULE_PATH)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class FakeChild:
    def __init__(self, returncode=0, pgid=8123, name="owned"):
        self.returncode = returncode
        self.pid = pgid
        self._owned_pgid = pgid
        self._owned_name = name
        self.poll_calls = 0

    def poll(self):
        self.poll_calls += 1
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired("fake", timeout)
        return self.returncode


class Clock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, amount):
        self.now += amount


class LauncherContractTests(unittest.TestCase):
    def required_args(self):
        return ["--docker-host", "unix:///owned/docker.sock",
            "--docker-cli", "/missing/docker", "--docker-cli-sha256", "1" * 64,
            "--docker-server-id", "owned-daemon",
            "--node", "/missing/node", "--node-sha256", "2" * 64,
            "--browser", "/missing/browser", "--browser-sha256", "3" * 64,
            "--source-manifest-sha256", "4" * 64,
            "--dependency-manifest-sha256", "5" * 64]

    def test_import_is_inert_and_plan_launches_nothing(self):
        with mock.patch("builtins.print") as output, \
             mock.patch.object(runner, "run_qualification") as qualify:
            self.assertEqual(runner.main(self.required_args()), 0)
        qualify.assert_not_called()
        output.assert_called_once_with(
            "plan: no workspace, container, database, Mailpit, browser, model, or network mutation")

    def test_closed_parser_has_no_suite_or_arbitrary_test_path(self):
        args = runner.parse_args(self.required_args())
        self.assertFalse(args.run)
        with self.assertRaises(SystemExit):
            runner.parse_args(self.required_args() + ["--suite", "foreign"])
        with self.assertRaises(SystemExit):
            runner.parse_args(self.required_args() + ["--test-path", "foreign.js"])

    def test_executable_pin_rejects_symlink_and_wrong_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "node"
            executable.write_bytes(b"owned-node")
            executable.chmod(0o700)
            link = root / "link"
            link.symlink_to(executable)
            with self.assertRaisesRegex(RuntimeError, "identity mismatch"):
                runner.validate_executable(link, runner.sha256(executable), "Node")
            with self.assertRaisesRegex(RuntimeError, "pin mismatch"):
                runner.validate_executable(executable, "0" * 64, "Node")
            self.assertEqual(runner.validate_executable(
                executable, runner.sha256(executable), "Node"), executable.resolve())

    def test_docker_daemon_and_cached_image_are_exact(self):
        calls = []

        def fake_run(command, **_kwargs):
            calls.append(command)
            if "info" in command:
                return SimpleNamespace(returncode=0, stdout='"owned-daemon"\n')
            return SimpleNamespace(returncode=0, stdout=json.dumps(runner.POSTGRES_IMAGE) + "\n")

        docker = ["/owned/docker", "--host", "unix:///owned.sock"]
        self.assertEqual(runner.validate_docker_authority(
            docker, {}, "owned-daemon", runner=fake_run), "owned-daemon")
        runner.validate_image(docker, {}, runner.POSTGRES_IMAGE, runner=fake_run)
        self.assertEqual(len(calls), 2)
        with self.assertRaisesRegex(RuntimeError, "daemon identity mismatch"):
            runner.validate_docker_authority(docker, {}, "other", runner=fake_run)
        with self.assertRaisesRegex(RuntimeError, "local Unix socket"):
            runner.validate_docker_authority(
                ["/owned/docker", "--host", "tcp://127.0.0.1:2375"], {},
                "owned-daemon", runner=fake_run)

    def test_container_commands_are_pinned_labeled_loopback_and_small_wal(self):
        docker = ["docker", "--host", "owned"]
        pg = runner.container_command(docker, name="pg", nonce="nonce",
                                      image=runner.POSTGRES_IMAGE, kind="postgres")
        mail = runner.container_command(docker, name="mail", nonce="nonce",
                                        image=runner.MAILPIT_IMAGE, kind="mailpit")
        self.assertIn("--pull", pg)
        self.assertIn("never", pg)
        self.assertIn("POSTGRES_INITDB_ARGS=--wal-segsize=1", pg)
        self.assertIn("max_wal_size=16MB", pg)
        self.assertIn("127.0.0.1::5432", pg)
        self.assertEqual(pg.count(runner.POSTGRES_IMAGE), 1)
        self.assertIn("--read-only", mail)
        self.assertIn("127.0.0.1::1025", mail)
        self.assertIn("127.0.0.1::8025", mail)
        self.assertEqual(mail.count(runner.MAILPIT_IMAGE), 1)
        for command in (pg, mail):
            self.assertIn(f"{runner.OWNER_LABEL}=csrf-email-composed", command)
            self.assertIn(f"{runner.NONCE_LABEL}=nonce", command)

    def test_stop_group_handles_exited_leader_with_live_descendant(self):
        child = FakeChild(returncode=0)
        states = iter([True, True, False, False, False, False])
        signals = []
        clock = Clock()
        result = runner.stop_group(child,
            group_exists=lambda _pgid, env=None: next(states),
            killpg=lambda pgid, sig: signals.append((pgid, sig)),
            monotonic=clock.monotonic, sleep=clock.sleep)
        self.assertEqual(result, 0)
        self.assertEqual(signals, [(8123, signal.SIGTERM)])
        self.assertGreater(child.poll_calls, 1)

    def test_cleanup_attempts_all_owned_containers_and_proves_names_absent(self):
        intents = [
            {"name": "pg", "nonce": "n", "image": runner.POSTGRES_IMAGE, "containerId": "a" * 64},
            {"name": "mail", "nonce": "n", "image": runner.MAILPIT_IMAGE, "containerId": "b" * 64},
        ]
        calls = []

        def fake_inspect(intent, _docker, _env, runner=None):
            calls.append(("inspect", intent["name"]))
            return intent["containerId"]

        def fake_run(command, **_kwargs):
            calls.append(tuple(command))
            if "inspect" in command:
                return SimpleNamespace(returncode=1, stdout="")
            return SimpleNamespace(returncode=0, stdout="")

        with mock.patch.object(runner, "inspect_owned", side_effect=fake_inspect):
            rows, errors = runner.cleanup_containers(intents, ["docker"], {}, runner=fake_run)
        self.assertEqual(errors, [])
        self.assertTrue(all(row["absent"] for row in rows))
        self.assertEqual([call for call in calls if call[0] == "inspect"],
                         [("inspect", "mail"), ("inspect", "pg")])

    def test_final_evidence_requires_exact_model_digest_and_bounded_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            readiness = Path(directory) / "ready.json"
            readiness.write_text(json.dumps({"modelDigestBefore": runner.MODEL_DIGEST}))
            final = Path(f"{readiness}.final")
            final.write_text(json.dumps({"modelDigestBefore": runner.MODEL_DIGEST,
                "modelDigestAfter": runner.MODEL_DIGEST, "counters": {"modelCalls": 2}}))
            self.assertEqual(runner.validate_fixture_final(readiness)["counters"]["modelCalls"], 2)
            final.write_text(json.dumps({"modelDigestBefore": runner.MODEL_DIGEST,
                "modelDigestAfter": runner.MODEL_DIGEST,
                "counters": {"modelCalls": runner.MAX_MODEL_CALLS + 1}}))
            with self.assertRaisesRegex(RuntimeError, "call evidence invalid"):
                runner.validate_fixture_final(readiness)
            final.write_text(json.dumps({"modelDigestBefore": runner.MODEL_DIGEST,
                "modelDigestAfter": "f" * 64, "counters": {"modelCalls": 2}}))
            with self.assertRaisesRegex(RuntimeError, "digest mismatch"):
                runner.validate_fixture_final(readiness)

    def test_browser_pid_records_are_private_complete_and_browser_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            browser = root / "browser"
            browser.write_bytes(b"browser")
            browser.chmod(0o700)
            digest = runner.sha256(browser)
            for index, (filename, kind) in enumerate(runner.BROWSER_RECORDS, start=1):
                path = root / filename
                path.write_text(json.dumps({"schemaVersion": 1, "processes": [{
                    "kind": kind, "pid": 9000 + index,
                    "startTime": "Fri Sep  8 23:40:22 2026",
                    "executablePath": str(browser.resolve()),
                    "executableSha256": digest,
                }]}))
                path.chmod(0o600)
            rows = runner.read_browser_records(root, browser, digest, require_all=True)
            self.assertEqual({row["kind"] for row in rows},
                             {kind for _, kind in runner.BROWSER_RECORDS})
            self.assertTrue(all(row["startTime"] == "Fri Sep 8 23:40:22 2026" for row in rows))
            (root / runner.BROWSER_RECORDS[0][0]).chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, "not private"):
                runner.read_browser_records(root, browser, digest, require_all=True)

    def test_browser_cleanup_signals_only_exact_captured_identity_and_proves_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            browser = Path(directory) / "browser"
            browser.write_bytes(b"browser")
            browser.chmod(0o700)
            record = {"kind": "qualification_browser", "pid": 9123,
                "startTime": "Fri Sep 18 23:40:22 2026",
                "executablePath": str(browser.resolve())}
            state = {"alive": True}
            signals = []

            def fake_run(_command, **_kwargs):
                if not state["alive"]:
                    return SimpleNamespace(returncode=1, stdout="")
                return SimpleNamespace(returncode=0,
                    stdout=f"Fri Sep 18 23:40:22 2026 {browser.resolve()} --headless\n")

            def fake_kill(pid, sig):
                signals.append((pid, sig))
                state["alive"] = False

            rows, errors = runner.cleanup_browser_processes(
                [record], browser, {}, runner=fake_run, kill=fake_kill,
                monotonic=Clock().monotonic, sleep=lambda _amount: None)
            self.assertEqual(errors, [])
            self.assertTrue(rows[0]["absent"])
            self.assertEqual(signals, [(9123, signal.SIGTERM)])

            state["alive"] = True
            signals.clear()
            wrong = {**record, "startTime": "Thu Sep 17 23:40:22 2026"}
            rows, errors = runner.cleanup_browser_processes(
                [wrong], browser, {}, runner=fake_run, kill=fake_kill)
            self.assertEqual(len(errors), 1)
            self.assertFalse(rows[0]["absent"])
            self.assertEqual(signals, [], "mismatched PID identity must never be signaled")

    def test_browser_inspection_failure_is_not_process_absence(self):
        failed = lambda *_args, **_kwargs: SimpleNamespace(
            returncode=2, stdout="", stderr="ps transport failed\n")
        with self.assertRaisesRegex(RuntimeError, "ps exited 2"):
            runner.browser_process_identity(9123, runner=failed)

    def test_browser_rechecks_executable_identity_before_sigkill(self):
        with tempfile.TemporaryDirectory() as directory:
            browser = Path(directory) / "browser"
            browser.write_bytes(b"browser")
            browser.chmod(0o700)
            record = {"kind": "fixture_browser", "pid": 9124,
                "startTime": "Fri Sep 18 23:40:22 2026",
                "executablePath": str(browser.resolve())}
            calls = {"count": 0}
            signals = []

            def fake_run(_command, **_kwargs):
                calls["count"] += 1
                executable = browser.resolve() if calls["count"] < 4 else "/unexpected/program"
                return SimpleNamespace(returncode=0, stderr="",
                    stdout=f"Fri Sep 18 23:40:22 2026 {executable} --headless\n")

            clock = Clock()
            rows, errors = runner.cleanup_browser_processes(
                [record], browser, {}, runner=fake_run,
                kill=lambda pid, sig: signals.append((pid, sig)),
                monotonic=clock.monotonic, sleep=clock.sleep)
            self.assertEqual(signals, [(9124, signal.SIGTERM)])
            self.assertEqual(len(errors), 1)
            self.assertRegex(str(errors[0]), "identity changed")
            self.assertFalse(rows[0]["absent"])

    def test_tap_gate_requires_real_all_pass_and_zero_skip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.tap"
            path.write_text("TAP version 13\n1..2\n# tests 2\n# pass 2\n# fail 0\n"
                            "# cancelled 0\n# skipped 0\n# todo 0\n")
            self.assertEqual(runner.validate_tap_result(path)["pass"], 2)
            path.write_text("TAP version 13\n1..1\n# tests 1\n# pass 0\n# fail 0\n"
                            "# cancelled 0\n# skipped 1\n# todo 0\n")
            with self.assertRaisesRegex(RuntimeError, "did not execute|non-passing"):
                runner.validate_tap_result(path)
            path.write_text("TAP version 13\n1..0\n# tests 0\n# pass 0\n# fail 0\n"
                            "# cancelled 0\n# skipped 0\n# todo 0\n")
            with self.assertRaisesRegex(RuntimeError, "did not execute"):
                runner.validate_tap_result(path)

    def test_source_names_only_the_closed_fixture_and_qualification(self):
        source = MODULE_PATH.read_text()
        self.assertIn('tests/postgres/csrfEmailComposedFixture.js', source)
        self.assertIn('tests/postgres/csrfEmailComposed.integration.test.js', source)
        self.assertNotIn('--test-path', source)
        self.assertNotIn('--suite', source)
        for value in ["PG_CSRF_EMAIL_COMPOSED_IDENTITY_RUNTIME_URL",
                      "PG_CSRF_EMAIL_COMPOSED_IDENTITY_MIGRATION_URL",
                      "PG_CSRF_EMAIL_COMPOSED_CSRF_RUNTIME_URL",
                      "PG_CSRF_EMAIL_COMPOSED_CSRF_MIGRATION_URL"]:
            self.assertIn(value, source)


class SelectedNativeContracts(unittest.TestCase):
    def test_selected_plan_flag_is_explicit_and_nonmutating(self):
        arguments=[]
        for name in ['docker-host','docker-cli','docker-cli-sha256','docker-server-id','node','node-sha256','browser','browser-sha256','source-manifest-sha256','dependency-manifest-sha256']:
            arguments.extend(['--'+name,'owned'])
        self.assertFalse(runner.parse_args(arguments).controlled_selected)
        with mock.patch.object(runner,'run_qualification') as launch:
            self.assertEqual(runner.main(arguments+['--controlled-selected']),0)
            launch.assert_not_called()
    def test_actual_selected_is_explicit_mutually_exclusive_and_plan_only(self):
        arguments=[]
        for name in ['docker-host','docker-cli','docker-cli-sha256','docker-server-id','node','node-sha256','browser','browser-sha256','source-manifest-sha256','dependency-manifest-sha256']:
            arguments.extend(['--'+name,'owned'])
        self.assertFalse(runner.parse_args(arguments).actual_selected)
        with self.assertRaises(SystemExit):runner.parse_args(arguments+['--actual-selected','--controlled-selected'])
        with mock.patch.object(runner,'run_qualification') as launch:
            self.assertEqual(runner.main(arguments+['--actual-selected']),0)
            launch.assert_not_called()

    def test_selected_browser_evidence_requires_its_actual_browser(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError,'missing'):
                runner.read_browser_records(directory,'/owned/browser','a'*64,require_all=True,records=runner.BROWSER_RECORDS[:1])


class ReadOnlyFrozenCopy(unittest.TestCase):
    def test_second_freeze_links_dependencies_without_changing_source_modes(self):
        import os
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);source=root/"source";destination=root/"destination"
            source.mkdir();destination.mkdir()
            for name in runner.SOURCE_DIRECTORIES:
                (source/name).mkdir()
            for name in runner.SOURCE_FILES:
                (source/name).write_text("{}")
            (source/"node_modules").mkdir();(source/"client/node_modules").mkdir()
            (source/"client/index.js").write_text("// immutable reviewed source")
            os.chmod(source/"client",0o500)
            try:
                rows=runner.inventory(source);deps=runner.dependency_inventory(source)
                runner.copy_frozen_source(source,destination,runner.manifest_digest(rows),runner.manifest_digest(deps))
                self.assertEqual((source/"client").stat().st_mode&0o777,0o500)
                self.assertEqual(runner.inventory(source),rows)
                self.assertTrue((destination/"client/node_modules").is_symlink())
                self.assertEqual((destination/"client/node_modules").resolve(),(source/"client/node_modules").resolve())
                self.assertEqual((destination/"client").stat().st_mode&0o777,0o500)
                self.assertEqual(runner.inventory(destination),rows)
            finally:
                for base in (source,destination):
                    for path in base.rglob("*"):
                        if path.is_dir() and not path.is_symlink():os.chmod(path,0o700)
                    os.chmod(base,0o700)


if __name__ == "__main__":
    unittest.main()
