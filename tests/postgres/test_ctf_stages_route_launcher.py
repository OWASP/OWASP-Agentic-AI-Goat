import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch


RUNNER = Path(__file__).with_name("run-ctf-stages-route-isolated.py")
SPEC = importlib.util.spec_from_file_location("ctf_stages_route_runner", RUNNER)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FakeChild:
    def __init__(self, returncode=1):
        self.pid = 43210
        self.returncode = returncode
        self._owned_pgid = 43210
        self._owned_sid = 43210
        self._owned_uid = 501
        self._owned_birth = (123, 456)
        self._owned_name = "ctf_stages_route_test"

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode


class CtfStagesRouteLauncherTests(unittest.TestCase):
    def test_ten_content_direct_node_test_flag_is_selector_scoped(self):
        node, test_file = Path("/owned/node"), Path("/owned/test.js")
        self.assertEqual(MODULE.child_test_command(node, test_file, ten_content=True),
            [str(node), "--test", "--test-isolation=none", "--test-reporter=tap",
             str(test_file)])
        self.assertEqual(MODULE.child_test_command(node, test_file),
            [str(node), "--test", "--test-reporter=tap", str(test_file)])

    def test_ten_content_browser_roster_fails_closed_before_allocation(self):
        own = {"pid": os.getpid(), "pgid": 12, "sessionId": 12,
               "arguments": ("python",)}
        self.assertTrue(MODULE.ctf_complete_roster(records=lambda: [own]))
        with self.assertRaisesRegex(RuntimeError, "omitted launcher"):
            MODULE.ctf_complete_roster(records=lambda: [])
        with self.assertRaisesRegex(RuntimeError, "profile/group remains"):
            MODULE.ctf_complete_roster(profile=Path("/owned/ctf-profile"), pgid=34,
                records=lambda: [own, {"pid": 90, "pgid": 34,
                    "sessionId": 34, "arguments": ("chrome",)}])
        with self.assertRaisesRegex(RuntimeError, "profile/group remains"):
            MODULE.ctf_complete_roster(profile=Path("/owned/ctf-profile"), pgid=34,
                records=lambda: [own, {"pid": 90, "pgid": 88,
                    "sessionId": 88, "arguments": ("chrome", "--user-data-dir=/owned/ctf-profile")}])
        with self.assertRaisesRegex(RuntimeError, "inventory denied"):
            MODULE.ctf_complete_roster(records=lambda: (_ for _ in ()).throw(
                RuntimeError("inventory denied")))

    def test_ten_content_browser_record_ack_binds_original_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "chrome"
            executable.write_bytes(b"controlled chrome")
            child = FakeChild()
            child.pid = os.getpid()
            child._owned_birth = (123, 456)
            profile = root / "content-profile"
            record = {"schemaVersion": 2, "processes": [{"kind": "ctf_ten_content_browser",
                "pid": 99123, "parentPid": child.pid, "uid": os.getuid(),
                "pgid": child.pid, "sessionId": child.pid, "birth": [111, 222],
                "executablePath": str(executable), "executableSha256": MODULE.sha256(executable)}]}
            path = root / "birth.json"
            ack = root / "ack.json"
            MODULE.write_private_json(path, record)
            row = record["processes"][0]
            with patch.object(MODULE, "validate_ctf_browser_birth", return_value=row):
                self.assertEqual(MODULE.acknowledge_ctf_browser(path, ack, child,
                    executable, profile, stop=threading.Event(),
                    deadline=MODULE.time.monotonic() + 30), row)
            self.assertEqual(json.loads(ack.read_text()), {"schemaVersion": 1,
                "recordSha256": MODULE.sha256(path), "parentPid": child.pid,
                "browserPid": row["pid"], "profile": str(profile)})
            ack.unlink()
            path.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, "Private CTF browser birth record"):
                MODULE.acknowledge_ctf_browser(path, ack, child,
                    executable, profile, stop=threading.Event(),
                    deadline=MODULE.time.monotonic() + 30)

            # The browser starts after DB and seed setup, not at Node launch.
            # A record arriving after 15 seconds is valid within the existing
            # whole-child deadline; no additional child/model time is granted.
            path.unlink()
            clock = [0.0]
            def later_sleep(_duration):
                clock[0] += 1.0
                if clock[0] == 16.0:
                    MODULE.write_private_json(path, record)
            with patch.object(MODULE.time, "monotonic", side_effect=lambda: clock[0]), \
                    patch.object(MODULE, "validate_ctf_browser_birth", return_value=row):
                self.assertEqual(MODULE.acknowledge_ctf_browser(path, ack, child,
                    executable, profile, stop=threading.Event(), deadline=30.0,
                    sleep=later_sleep), row)
            ack.unlink()
            path.unlink()
            clock[0] = 0.0
            with patch.object(MODULE.time, "monotonic", side_effect=lambda: clock[0]):
                with self.assertRaisesRegex(RuntimeError, "not independently acknowledged"):
                    MODULE.acknowledge_ctf_browser(path, ack, child,
                        executable, profile, stop=threading.Event(), deadline=15.0,
                        sleep=lambda _duration: clock.__setitem__(0, clock[0] + 1.0))

    def test_ten_content_browser_birth_rejects_wrong_parent_profile_or_birth(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "chrome"
            executable.write_bytes(b"controlled chrome")
            child = FakeChild()
            child._owned_uid = os.getuid()
            profile = Path(directory) / "content-profile"
            parent = SimpleNamespace(pid=child.pid, ppid=1, uid=os.getuid(),
                ruid=os.getuid(), pgid=child.pid, start_sec=123, start_usec=456,
                status=1)
            browser = SimpleNamespace(pid=99123, ppid=child.pid, uid=os.getuid(),
                ruid=os.getuid(), pgid=child.pid, start_sec=111, start_usec=222,
                status=1)
            rows = {child.pid: parent, browser.pid: browser}
            api = SimpleNamespace(identity=lambda pid: rows.get(pid),
                arguments=lambda _pid: (str(executable), f"--user-data-dir={profile}"))
            record = {"schemaVersion": 2, "processes": [{"kind": "ctf_ten_content_browser",
                "pid": browser.pid, "parentPid": child.pid, "uid": os.getuid(),
                "pgid": child.pid, "sessionId": child.pid, "birth": [111, 222],
                "executablePath": str(executable), "executableSha256": MODULE.sha256(executable)}]}
            with patch.object(MODULE, "process_inventory",
                    return_value=SimpleNamespace(SZOMB=5)):
                self.assertEqual(MODULE.validate_ctf_browser_birth(record, child,
                    executable, profile, api=api, getsid=lambda _pid: child.pid),
                    record["processes"][0])
                for key, value in (("parentPid", child.pid + 1),
                                   ("pgid", child.pid + 1),
                                   ("birth", [111, 223])):
                    changed = json.loads(json.dumps(record))
                    changed["processes"][0][key] = value
                    with self.subTest(key=key), self.assertRaises(RuntimeError):
                        MODULE.validate_ctf_browser_birth(changed, child,
                            executable, profile, api=api, getsid=lambda _pid: child.pid)
                wrong_arguments = SimpleNamespace(identity=api.identity,
                    arguments=lambda _pid: (str(executable), "--user-data-dir=/foreign"))
                with self.assertRaisesRegex(RuntimeError, "executable/profile"):
                    MODULE.validate_ctf_browser_birth(record, child,
                        executable, profile, api=wrong_arguments, getsid=lambda _pid: child.pid)

    def test_preview_browser_birth_accepts_only_the_exact_preview_kind_and_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "chrome"
            executable.write_bytes(b"controlled chrome")
            child = FakeChild()
            child._owned_uid = os.getuid()
            profile = Path(directory) / "preview-profile"
            parent = SimpleNamespace(pid=child.pid, ppid=1, uid=os.getuid(),
                ruid=os.getuid(), pgid=child.pid, start_sec=123, start_usec=456, status=1)
            browser = SimpleNamespace(pid=99124, ppid=child.pid, uid=os.getuid(),
                ruid=os.getuid(), pgid=child.pid, start_sec=111, start_usec=222, status=1)
            api = SimpleNamespace(identity=lambda pid: {child.pid: parent, browser.pid: browser}.get(pid),
                arguments=lambda _pid: (str(executable), f"--user-data-dir={profile}"))
            record = {"schemaVersion": 2, "processes": [{"kind": "ctf_preview_browser",
                "pid": browser.pid, "parentPid": child.pid, "uid": os.getuid(),
                "pgid": child.pid, "sessionId": child.pid, "birth": [111, 222],
                "executablePath": str(executable), "executableSha256": MODULE.sha256(executable)}]}
            with patch.object(MODULE, "process_inventory", return_value=SimpleNamespace(SZOMB=5)):
                self.assertEqual(MODULE.validate_ctf_browser_birth(record, child, executable, profile,
                    kind="ctf_preview_browser", api=api, getsid=lambda _pid: child.pid), record["processes"][0])
                learner_profile = Path(directory) / "learner-entry-hint-profile"
                learner_record = json.loads(json.dumps(record))
                learner_record["processes"][0]["kind"] = "ctf_learner_entry_hint_browser"
                learner_api = SimpleNamespace(identity=api.identity,
                    arguments=lambda _pid: (str(executable), f"--user-data-dir={learner_profile}"))
                self.assertEqual(MODULE.validate_ctf_browser_birth(learner_record, child, executable, learner_profile,
                    kind="ctf_learner_entry_hint_browser", api=learner_api, getsid=lambda _pid: child.pid), learner_record["processes"][0])
                attempt_profile = Path(directory) / "learner-attempt-gate-profile"
                attempt_record = json.loads(json.dumps(record))
                attempt_record["processes"][0]["kind"] = "ctf_learner_attempt_gate_browser"
                attempt_api = SimpleNamespace(identity=api.identity,
                    arguments=lambda _pid: (str(executable), f"--user-data-dir={attempt_profile}"))
                self.assertEqual(MODULE.validate_ctf_browser_birth(attempt_record, child, executable, attempt_profile,
                    kind="ctf_learner_attempt_gate_browser", api=attempt_api, getsid=lambda _pid: child.pid), attempt_record["processes"][0])
                fixed_profile = Path(directory) / "fixed-practice-profile"
                fixed_record = json.loads(json.dumps(record))
                fixed_record["processes"][0]["kind"] = "ctf_fixed_practice_browser"
                fixed_api = SimpleNamespace(identity=api.identity,
                    arguments=lambda _pid: (str(executable), f"--user-data-dir={fixed_profile}"))
                self.assertEqual(MODULE.validate_ctf_browser_birth(fixed_record, child, executable, fixed_profile,
                    kind="ctf_fixed_practice_browser", api=fixed_api, getsid=lambda _pid: child.pid), fixed_record["processes"][0])
                with self.assertRaisesRegex(RuntimeError, "Unrecognized"):
                    MODULE.validate_ctf_browser_birth(record, child, executable, profile,
                        kind="ctf_preview_browser_wrong", api=api, getsid=lambda _pid: child.pid)
                wrong_profile = SimpleNamespace(identity=api.identity,
                    arguments=lambda _pid: (str(executable), "--user-data-dir=/foreign"))
                with self.assertRaisesRegex(RuntimeError, "executable/profile"):
                    MODULE.validate_ctf_browser_birth(record, child, executable, profile,
                        kind="ctf_preview_browser", api=wrong_profile, getsid=lambda _pid: child.pid)

    def test_ten_content_short_tmp_parent_is_bounded_and_repository_owned(self):
        source = Path(__file__).resolve().parents[2]
        parent = MODULE.ten_content_short_tmp_parent(source)
        self.assertEqual(parent, source / "tasks/tmp")
        self.assertLessEqual(len(str(parent).encode()) + len("/c-") + 8, 80)
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory)
            (fake / "tasks").mkdir()
            outside = fake / "outside"
            outside.mkdir()
            (fake / "tasks/tmp").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "repository-owned"):
                MODULE.ten_content_short_tmp_parent(fake)

    def test_stage6_adoption_is_current_main_without_source_copy_or_browser(self):
        argv = self.required_args() + ["--ctf-stage6-adoption",
            "--content-source-manifest-sha256", "a" * 64,
            "--docker-daemon-id", "2c9da9a7-1f8c-490b-af98-87bbf6bf83db"]
        args = MODULE.parse_args(argv)
        self.assertTrue(MODULE.main_no_copy_selection(args),
            "the native launcher must enter the current-main path, never copy_frozen_source")
        selected = MODULE.qualification_selection(args, "abc123")
        self.assertEqual(selected["test"], "tests/postgres/ctfAuthorityApplication.integration.test.js")
        self.assertEqual(selected["mode"], "ctf_stage6_adoption_controlled")
        self.assertEqual(selected["environment"]["CTF_STAGE6_ADOPTION_ISOLATED"], "1")
        self.assertEqual(selected["environment"]["CTF_AUTHORITY_APPLICATION_ISOLATED"], "1")
        self.assertEqual(MODULE.delivery_role(selected), "dvaia_ctf_delivery")
        urls = {name: {role: name + role for role in ("runtime", "migration", "delivery")}
            for name in selected["databases"]}
        self.assertEqual(len(MODULE.database_environment(selected, urls)), 10)
        with self.assertRaises(SystemExit):
            MODULE.parse_args(argv + ["--browser-executable", "/owned/chrome"])

    def test_ten_content_main_workspace_closed_selector(self):
        image_id = "sha256:" + "a" * 64
        argv = self.required_args() + ["--ctf-ten-content", "--image-id", image_id,
            "--browser-executable", "/owned/chrome",
            "--browser-sha256", "a" * 64, "--client-source-sha256", "b" * 64,
            "--client-dependency-sha256", "c" * 64, "--client-build-sha256", "d" * 64, "--client-build-output-sha256", "h" * 64,
            "--client-build-report-sha256", "e" * 64, "--client-build-report", "/owned/report.json", "--client-build-input-sha256", "f" * 64,
            "--client-build-recorder-sha256", "i" * 64, "--content-source-manifest-sha256", "g" * 64, "--docker-daemon-id", "2c9da9a7-1f8c-490b-af98-87bbf6bf83db"]
        selected = MODULE.qualification_selection(MODULE.parse_args(argv), "a" * 12)
        self.assertEqual(selected["mode"], "ctf_ten_content_controlled")
        self.assertEqual(selected["test"], "tests/postgres/ctfAuthorityApplication.integration.test.js")
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (480, 660, 120))
        self.assertEqual(selected["environment"], {"CTF_TEN_CONTENT_ISOLATED": "1", "CTF_RECOVERY_RENDERED_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"})
        urls = {n: {r: n + r for r in ("runtime", "migration", "delivery")} for n in selected["databases"]}
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(len(env), 10)
        self.assertEqual(MODULE.delivery_role(selected), "dvaia_ctf_delivery")
        self.assertEqual(MODULE.parse_args(argv).image_id, image_id)
        for missing in (("--client-build-sha256",), ("--browser-executable", "/owned/chrome", "--browser-sha256", "a" * 64, "--client-source-sha256", "b" * 64, "--client-dependency-sha256", "c" * 64)):
            with self.assertRaises(SystemExit):
                MODULE.parse_args(self.required_args() + ["--ctf-ten-content", *missing])
        for extra in ([], ["--image-id", "sha256:" + "g" * 64],
                      ["--image-id", "sha256:" + "a" * 63]):
            with self.assertRaises(SystemExit):
                MODULE.parse_args(self.required_args() + ["--ctf-ten-content", *extra])
        with self.assertRaises(SystemExit):
            MODULE.parse_args(self.required_args() + ["--ctf-current-read", "--image-id", image_id])

    def test_config_rendered_main_workspace_closed_selector(self):
        image_id = "sha256:" + "a" * 64
        argv = self.required_args() + ["--ctf-config-rendered", "--image-id", image_id,
            "--browser-executable", "/owned/chrome", "--browser-sha256", "a" * 64,
            "--client-source-sha256", "b" * 64, "--client-dependency-sha256", "c" * 64,
            "--client-build-sha256", "d" * 64, "--client-build-output-sha256", "h" * 64,
            "--client-build-report-sha256", "e" * 64, "--client-build-report", "/owned/report.json",
            "--client-build-input-sha256", "f" * 64, "--client-build-recorder-sha256", "i" * 64,
            "--content-source-manifest-sha256", "g" * 64,
            "--docker-daemon-id", "2c9da9a7-1f8c-490b-af98-87bbf6bf83db"]
        args = MODULE.parse_args(argv)
        selected = MODULE.qualification_selection(args, "a" * 12)
        self.assertEqual(selected["mode"], "ctf_config_rendered_controlled")
        self.assertEqual(selected["test"], "tests/postgres/ctfAuthorityApplication.integration.test.js")
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (480, 360, 120))
        self.assertTrue(MODULE.main_no_copy_selection(args))
        self.assertEqual(MODULE.delivery_role(selected), "dvaia_ctf_delivery")
        self.assertEqual(len(selected["databases"]), 4)
        urls = {name: {role: f"postgres://{role}/{name}" for role in ("runtime", "migration", "delivery")}
            for name in selected["databases"]}
        self.assertEqual(len(MODULE.database_environment(selected, urls)), 10)
        for suffix in (("--stage-end", "3"), ("--target-stage", "6"), ("--candidate-set", "reviewer-boundary-v1")):
            with self.assertRaises(SystemExit):
                MODULE.parse_args(argv + list(suffix))

    def test_preview_rendered_main_workspace_closed_selector(self):
        image_id = "sha256:" + "a" * 64
        argv = self.required_args() + ["--ctf-preview-rendered", "--image-id", image_id,
            "--browser-executable", "/owned/chrome", "--browser-sha256", "a" * 64,
            "--client-source-sha256", "b" * 64, "--client-dependency-sha256", "c" * 64,
            "--client-build-sha256", "d" * 64, "--client-build-output-sha256", "h" * 64,
            "--client-build-report-sha256", "e" * 64, "--client-build-report", "/owned/report.json",
            "--client-build-input-sha256", "f" * 64, "--client-build-recorder-sha256", "i" * 64,
            "--content-source-manifest-sha256", "g" * 64,
            "--docker-daemon-id", "2c9da9a7-1f8c-490b-af98-87bbf6bf83db"]
        args = MODULE.parse_args(argv)
        selected = MODULE.qualification_selection(args, "a" * 12)
        self.assertEqual(selected["mode"], "ctf_preview_rendered_controlled")
        self.assertEqual(selected["test"], "tests/postgres/ctfAuthorityApplication.integration.test.js")
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (480, 360, 120))
        self.assertEqual(selected["environment"], {"CTF_PREVIEW_RENDERED_ISOLATED": "1", "CTF_RECOVERY_RENDERED_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"})
        self.assertTrue(MODULE.main_no_copy_selection(args))
        self.assertEqual(MODULE.delivery_role(selected), "dvaia_ctf_delivery")
        self.assertEqual(len(selected["databases"]), 4)
        urls = {name: {role: f"postgres://{role}/{name}" for role in ("runtime", "migration", "delivery")}
            for name in selected["databases"]}
        self.assertEqual(len(MODULE.database_environment(selected, urls)), 10)
        for suffix in (("--stage-end", "3"), ("--target-stage", "6"), ("--candidate-set", "reviewer-boundary-v1")):
            with self.assertRaises(SystemExit):
                MODULE.parse_args(argv + list(suffix))

    def test_learner_entry_hint_rendered_closed_selector(self):
        image_id = "sha256:" + "a" * 64
        argv = self.required_args() + ["--ctf-learner-entry-hint-rendered", "--image-id", image_id,
            "--browser-executable", "/owned/chrome", "--browser-sha256", "a" * 64,
            "--client-source-sha256", "b" * 64, "--client-dependency-sha256", "c" * 64,
            "--client-build-sha256", "d" * 64, "--client-build-output-sha256", "h" * 64,
            "--client-build-report-sha256", "e" * 64, "--client-build-report", "/owned/report.json",
            "--client-build-input-sha256", "f" * 64, "--client-build-recorder-sha256", "i" * 64,
            "--content-source-manifest-sha256", "g" * 64,
            "--docker-daemon-id", "2c9da9a7-1f8c-490b-af98-87bbf6bf83db"]
        args = MODULE.parse_args(argv)
        selected = MODULE.qualification_selection(args, "a" * 12)
        self.assertEqual(selected["mode"], "ctf_learner_entry_hint_rendered_controlled")
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (480, 180, 120))
        self.assertEqual(selected["environment"], {"CTF_LEARNER_ENTRY_HINT_RENDERED_ISOLATED": "1", "CTF_RECOVERY_RENDERED_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"})
        self.assertTrue(MODULE.main_no_copy_selection(args)); self.assertEqual(MODULE.delivery_role(selected), "dvaia_ctf_delivery")
        self.assertEqual(len(selected["databases"]), 4)
        for suffix in (("--stage-end", "3"), ("--target-stage", "6"), ("--candidate-set", "reviewer-boundary-v1")):
            with self.assertRaises(SystemExit): MODULE.parse_args(argv + list(suffix))

    def test_learner_attempt_gate_rendered_closed_selector(self):
        image_id = "sha256:" + "a" * 64
        argv = self.required_args() + ["--ctf-learner-attempt-gate-rendered", "--image-id", image_id,
            "--browser-executable", "/owned/chrome", "--browser-sha256", "a" * 64,
            "--client-source-sha256", "b" * 64, "--client-dependency-sha256", "c" * 64,
            "--client-build-sha256", "d" * 64, "--client-build-output-sha256", "h" * 64,
            "--client-build-report-sha256", "e" * 64, "--client-build-report", "/owned/report.json",
            "--client-build-input-sha256", "f" * 64, "--client-build-recorder-sha256", "i" * 64,
            "--content-source-manifest-sha256", "g" * 64,
            "--docker-daemon-id", "2c9da9a7-1f8c-490b-af98-87bbf6bf83db"]
        args = MODULE.parse_args(argv)
        selected = MODULE.qualification_selection(args, "a" * 12)
        self.assertEqual(selected["mode"], "ctf_learner_attempt_gate_rendered_controlled")
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (480, 360, 120))
        self.assertEqual(selected["environment"], {"CTF_LEARNER_ATTEMPT_GATE_RENDERED_ISOLATED": "1", "CTF_RECOVERY_RENDERED_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"})
        self.assertTrue(MODULE.main_no_copy_selection(args)); self.assertEqual(MODULE.delivery_role(selected), "dvaia_ctf_delivery")
        self.assertEqual(len(selected["databases"]), 4)
        self.assertTrue(all(name.startswith("owasp_ai_goat_test_ctf_learner_attempt_gate_") for name in selected["databases"]))
        urls = {name: {role: f"postgres://{role}/{name}" for role in ("runtime", "migration", "delivery")} for name in selected["databases"]}
        self.assertEqual(len(MODULE.database_environment(selected, urls)), 10)
        for suffix in (("--stage-end", "3"), ("--target-stage", "6"), ("--candidate-set", "reviewer-boundary-v1")):
            with self.assertRaises(SystemExit): MODULE.parse_args(argv + list(suffix))

    def test_fixed_practice_rendered_closed_selector(self):
        image_id = "sha256:" + "a" * 64
        argv = self.required_args() + ["--ctf-fixed-practice-rendered", "--image-id", image_id,
            "--browser-executable", "/owned/chrome", "--browser-sha256", "a" * 64,
            "--client-source-sha256", "b" * 64, "--client-dependency-sha256", "c" * 64,
            "--client-build-sha256", "d" * 64, "--client-build-output-sha256", "h" * 64,
            "--client-build-report-sha256", "e" * 64, "--client-build-report", "/owned/report.json",
            "--client-build-input-sha256", "f" * 64, "--client-build-recorder-sha256", "i" * 64,
            "--content-source-manifest-sha256", "g" * 64,
            "--docker-daemon-id", "2c9da9a7-1f8c-490b-af98-87bbf6bf83db"]
        args = MODULE.parse_args(argv)
        selected = MODULE.qualification_selection(args, "a" * 12)
        self.assertEqual(selected["mode"], "ctf_fixed_practice_rendered_controlled")
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (480, 120, 120))
        self.assertEqual(selected["environment"], {"CTF_FIXED_PRACTICE_RENDERED_ISOLATED": "1", "CTF_RECOVERY_RENDERED_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"})
        self.assertTrue(MODULE.main_no_copy_selection(args)); self.assertEqual(MODULE.delivery_role(selected), "dvaia_ctf_delivery")
        self.assertEqual(len(selected["databases"]), 4)
        self.assertTrue(all(name.startswith("owasp_ai_goat_test_ctf_fixed_practice_") for name in selected["databases"]))
        urls = {name: {role: f"postgres://{role}/{name}" for role in ("runtime", "migration", "delivery")} for name in selected["databases"]}
        self.assertEqual(len(MODULE.database_environment(selected, urls)), 10)
        for suffix in (("--stage-end", "3"), ("--target-stage", "6"), ("--candidate-set", "reviewer-boundary-v1")):
            with self.assertRaises(SystemExit): MODULE.parse_args(argv + list(suffix))

    def test_current_host_postgres_image_inspect_requires_exact_identity_platform_and_version(self):
        image_id = "sha256:" + "a" * 64
        base = {"Id": image_id, "Os": "linux", "Architecture": "arm64",
                "Config": {"Env": ["PG_MAJOR=18", "PG_VERSION=18.1-1.pgdg13+1"]}}
        seen = []
        def runner(command, **kwargs):
            seen.append((command, kwargs))
            return SimpleNamespace(stdout=json.dumps(base))
        self.assertEqual(MODULE.validate_current_host_postgres_image(["docker", "--host", "owned"],
            image_id, {"TMPDIR": "/owned"}, runner=runner),
            {"id": image_id, "os": "linux", "architecture": "arm64",
             "postgresMajor": "18", "postgresVersion": "18.1-1.pgdg13+1"})
        self.assertEqual(seen[0][0], ["docker", "--host", "owned", "image", "inspect",
            image_id, "--format", "{{json .}}"])
        for changed in ({**base, "Id": "sha256:" + "b" * 64},
                        {**base, "Architecture": "amd64"},
                        {**base, "Config": {"Env": ["PG_MAJOR=17", "PG_VERSION=17.1"]}},
                        {**base, "Config": {"Env": ["PG_MAJOR=18"]}}):
            with self.subTest(changed=changed), self.assertRaises(RuntimeError):
                MODULE.validate_current_host_postgres_image(["docker"], image_id, {},
                    runner=lambda *_args, **_kwargs: SimpleNamespace(stdout=json.dumps(changed)))

    def test_ten_content_runtime_environment_is_repo_private_without_home(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "runtime"
            runtime.mkdir(mode=0o700)
            env = MODULE.main_no_copy_environment(runtime, repository_only=True)
            self.assertNotIn("HOME", env)
            for name in ("TMPDIR", "TMP", "TEMP", "XDG_CACHE_HOME",
                         "XDG_CONFIG_HOME", "DOCKER_CONFIG", "PUPPETEER_CACHE_DIR"):
                self.assertTrue(Path(env[name]).is_relative_to(runtime), name)
            self.assertFalse((runtime / "home").exists())
            legacy = MODULE.main_no_copy_environment(runtime)
            self.assertEqual(legacy["HOME"], str(runtime / "home"))

    def test_ten_content_run_parent_is_private_repository_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            tasks = source / "tasks"
            tasks.mkdir()
            parent = tasks / "qualification"
            parent.mkdir(mode=0o700)
            self.assertEqual(MODULE.ten_content_run_parent(source), parent)
            parent.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, "private repository storage"):
                MODULE.ten_content_run_parent(source)
            parent.chmod(0o700)
            foreign = tasks / "foreign"
            foreign.mkdir(mode=0o700)
            parent.rmdir()
            parent.symlink_to(foreign, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "canonical repository storage"):
                MODULE.ten_content_run_parent(source)

    def test_prebuilt_build_manifest_is_exact_and_read_only(self):
        with tempfile.TemporaryDirectory() as d:
            source = Path(d); build = source / "client" / "build"; build.mkdir(parents=True)
            page = build / "index.html"; page.write_text("<!doctype html>\n")
            expected = MODULE.manifest_digest(MODULE.client_inventory(build))
            result = MODULE.validate_prebuilt_build(source, expected)
            self.assertEqual(result["sha256"], expected)
            self.assertEqual(result["count"], 1)
            self.assertEqual(page.read_text(), "<!doctype html>\n")
            with self.assertRaisesRegex(RuntimeError, "manifest pin"):
                MODULE.validate_prebuilt_build(source, "0" * 64)

    def test_fake_frontend_build_report_is_rejected_before_use(self):
        with tempfile.TemporaryDirectory() as d:
            report = Path(d) / "report.json"
            report.write_text('{"qualified":true}\n')
            with self.assertRaisesRegex(RuntimeError, "report pin"):
                MODULE.validate_frontend_build_report(Path(d), report, "0" * 64, "1" * 64, "2" * 64, "3" * 64)

    def test_ten_content_repository_build_report_is_exact_and_private(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            parent = source / "tasks/qualification"
            parent.mkdir(parents=True, mode=0o700)
            run = parent / "frontend-build-controlled"
            run.mkdir(mode=0o700)
            report_path = run / "report.json"
            report_path.write_text("{}")
            node = source / "tasks/runtime/node/node_modules/node/bin/node"
            node.parent.mkdir(parents=True)
            node.write_bytes(b"controlled node")
            npm = source / "readonly-npm-cli.js"
            npm.write_bytes(b"controlled npm")
            report = {"repositoryOnly": True, "workspace": str(source),
                "outputRoot": str(source / "client/build"),
                "command": [str(node), str(npm), "--prefix", "client", "run", "build"],
                "runtimePins": {"node": {"path": str(node), "sha256": MODULE.sha256(node)},
                    "npm": {"path": str(npm), "sha256": MODULE.sha256(npm)}}}
            MODULE.validate_repo_build_provenance(report, source, report_path, npm_path=npm)
            for changed in ({**report, "repositoryOnly": False},
                            {**report, "outputRoot": str(source / "other-build")},
                            {**report, "runtimePins": {**report["runtimePins"], "npm": {"path": str(npm), "sha256": "0" * 64}}},
                            {**report, "command": [str(node), str(npm), "run", "build"]}):
                with self.subTest(changed=changed), self.assertRaises(RuntimeError):
                    MODULE.validate_repo_build_provenance(changed, source, report_path, npm_path=npm)
            wrong_run = parent / "unreviewed"; wrong_run.mkdir(mode=0o700)
            with self.assertRaisesRegex(RuntimeError, "repository-only"):
                MODULE.validate_repo_build_provenance(report, source, wrong_run / "report.json", npm_path=npm)
            link = parent / "frontend-build-link"
            link.symlink_to(run, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "repository-only"):
                MODULE.validate_repo_build_provenance(report, source, link / "report.json", npm_path=npm)
            run.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, "not private"):
                MODULE.validate_repo_build_provenance(report, source, report_path, npm_path=npm)

    def test_blocklist_q05_receipt_is_separate_and_fail_closed(self):
        valid = {"version": 1, "profile": "ctf-blocklist-q05", "modelCalls": 0,
            "judgeCalls": 0, "postCounts": {"technique": 1, "payload": 1},
            "browserPostCounts": {"technique": 1, "payload": 1},
            "cancelPostCounts": {"browser": {"technique": 0, "payload": 0},
                                 "server": {"technique": 0, "payload": 0}},
            "facts": {name: True for name in ("cancelNoPost", "cancelStoresUnchanged",
                "techniqueClearedBothStores", "payloadClearedBothStores",
                "pendingAbaNoStaleUiOrRecovery")},
            "dialogTimeAba": {"noPost": True, "eventsObserved": 2,
                "postCounts": {"browser": {"technique": 0, "payload": 0},
                               "server": {"technique": 0, "payload": 0}}},
            "pendingAba": {"responseReleased": True, "componentRetired": False,
                "eventsObserved": 2}, "unexpectedApiPaths": [], "siblingPreserved": True,
            "stage": "complete"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ctf-blocklist-q05-result.json"
            path.write_text(json.dumps(valid))
            self.assertEqual(MODULE.validate_blocklist_q05_receipt(path), valid)
            variants = [
                {**valid, "postCounts": {"technique": 2, "payload": 1}},
                {**valid, "postCounts": {"technique": True, "payload": 1}},
                {**valid, "browserPostCounts": {"technique": 2, "payload": 1}},
                {**valid, "cancelPostCounts": {"browser": {"technique": 1, "payload": 0},
                                                 "server": {"technique": 0, "payload": 0}}},
                {**valid, "modelCalls": 1},
                {**valid, "facts": {**valid["facts"], "cancelNoPost": False}},
                {**valid, "dialogTimeAba": {"noPost": False, "eventsObserved": 2}},
                {**valid, "stage": "seed"},
                {**valid, "pendingAba": {**valid["pendingAba"], "responseReleased": False}},
                {**valid, "unexpectedApiPaths": ["/unexpected"]},
                {**valid, "siblingPreserved": False},
                {**valid, "extra": True},
            ]
            for value in variants:
                with self.subTest(value=value):
                    path.write_text(json.dumps(value))
                    with self.assertRaises(RuntimeError):
                        MODULE.validate_blocklist_q05_receipt(path)
            path.unlink()
            with self.assertRaisesRegex(RuntimeError, "missing"):
                MODULE.validate_blocklist_q05_receipt(path)
            other = Path(directory) / "other.json"; other.write_text(json.dumps(valid))
            path.symlink_to(other)
            with self.assertRaisesRegex(RuntimeError, "noncanonical"):
                MODULE.validate_blocklist_q05_receipt(path)

    def test_participant_reset_q05_receipt_exact_private_recovery_and_effect_join(self):
        operation = "123e4567-e89b-42d3-a456-426614174000"
        valid = {"version": 2, "profile": "ctf-participant-reset-q05",
            "modelCalls": 0, "judgeCalls": 0, "targetId": 3010,
            "browserPosts": 1, "serverPosts": 1,
            "facts": {name: True for name in ("cancelNoPost", "cancelStateUnchanged",
                "modalAbaNoPost", "modalAbaStateUnchanged",
                "currentProgressClearedBothStores", "registrationRetained",
                "sharedPayloadPreserved", "siblingPreserved",
                "sameIdRecoveryNoSecondPost")},
            "operationId": operation, "commitAckLost": True,
            "firstOperationReadLost": True, "firstOperationReadStatus": 202,
            "firstOperationReadFinished": True, "browserReadFailureObserved": True,
            "parkedBeforeCheck": True,
            "operationReadDrops": 1, "originalPostStatus": 202,
            "outbox": {"operationId": operation, "kind": "owner_reset", "ownerId": "3010"},
            "sameIdGets": 2, "unexpectedApiPaths": [], "generationBefore": "0",
            "generationAfter": "1", "stage": "complete"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ctf-participant-reset-q05-result.json"
            def write(value):
                path.write_text(json.dumps(value), encoding="utf-8")
                path.chmod(0o600)
            write(valid)
            self.assertEqual(MODULE.validate_participant_reset_q05_receipt(path), valid)
            variants = [
                {**valid, "version": 1},
                {**valid, "modelCalls": 1}, {**valid, "judgeCalls": True},
                {**valid, "browserPosts": 0}, {**valid, "serverPosts": 2},
                {**valid, "targetId": 1001}, {**valid, "operationReadDrops": 2},
                {**valid, "originalPostStatus": 200},
                {**valid, "firstOperationReadStatus": 503},
                {**valid, "sameIdGets": 1}, {**valid, "commitAckLost": False},
                {**valid, "firstOperationReadLost": False},
                {**valid, "firstOperationReadFinished": False},
                {**valid, "browserReadFailureObserved": False},
                {**valid, "parkedBeforeCheck": False},
                {**valid, "facts": {**valid["facts"], "siblingPreserved": False}},
                {**valid, "outbox": {**valid["outbox"], "operationId": str(__import__('uuid').uuid4())}},
                {**valid, "outbox": {**valid["outbox"], "kind": "owner_remove"}},
                {**valid, "operationId": operation.upper()},
                {**valid, "generationAfter": "2"},
                {**valid, "generationBefore": "01"},
                {**valid, "unexpectedApiPaths": ["/unexpected"]},
                {**valid, "stage": "pending"}, {**valid, "extra": True},
            ]
            for index, value in enumerate(variants):
                with self.subTest(index=index):
                    write(value)
                    with self.assertRaises(RuntimeError):
                        MODULE.validate_participant_reset_q05_receipt(path)
            write(valid)
            path.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, "not private"):
                MODULE.validate_participant_reset_q05_receipt(path)
            path.chmod(0o600)
            Path(directory).chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, "not private"):
                MODULE.validate_participant_reset_q05_receipt(path)
            Path(directory).chmod(0o700)
            wrong_name = Path(directory) / "unreviewed-reset.json"
            wrong_name.write_text(json.dumps(valid), encoding="utf-8")
            wrong_name.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, "noncanonical"):
                MODULE.validate_participant_reset_q05_receipt(wrong_name)
            path.unlink()
            foreign = Path(directory) / "foreign.json"
            foreign.write_text(json.dumps(valid))
            path.symlink_to(foreign)
            with self.assertRaisesRegex(RuntimeError, "noncanonical"):
                MODULE.validate_participant_reset_q05_receipt(path)
            path.unlink()
            with self.assertRaisesRegex(RuntimeError, "missing"):
                MODULE.validate_participant_reset_q05_receipt(path)

    def test_participant_remove_q05_receipt_is_private_exact_and_does_not_claim_recovery(self):
        operation = "123e4567-e89b-42d3-a456-426614174000"
        registration = "223e4567-e89b-42d3-a456-426614174000"
        valid = {"version": 1, "profile": "ctf-participant-remove-q05",
            "modelCalls": 0, "judgeCalls": 0, "targetId": 3010,
            "oldParticipantId": 3010, "newParticipantId": 3012,
            "mountedActorId": "909", "mountedSessionId": "707",
            "comparisonActorId": "1002", "learnerSessionId": "808",
            "preRemovalRows": {"participant": 1, "progress": 1, "attempts": 0,
                "technique": 0, "leaderboard": 1, "events": 2, "sessions": 1,
                "binding": 1, "currentIdentityProgress": 1},
            "browserPosts": 1, "removeOutboxCount": 1,
            "originalPostStatus": 200,
            "facts": {key: True for key in ("cancelNoPost", "cancelStateUnchanged",
                "modalAbaNoPost", "modalAbaStateUnchanged", "removedCurrentCtfState",
                "oldRegistrationInactive", "historicalIdentityRetained",
                "sharedPayloadPreserved", "siblingPreserved", "reregisteredFresh",
                "noMutationReplay")},
            "dialogTimeAba": {"noPost": True, "eventsObserved": 2},
            "removeOutbox": {"operationId": operation, "kind": "owner_remove",
                "ownerId": "3010", "actorId": "909", "sessionId": "707"},
            "registrationOutbox": {"operationId": registration, "kind": "register",
                "ownerId": "3010", "actorId": "3010", "sessionId": "808",
                "disposition": "reactivate", "oldParticipantId": "3010"},
            "generationBefore": "2", "generationRemoved": "3",
            "generationReregistered": "4", "unexpectedApiPaths": [], "stage": "complete"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ctf-participant-remove-q05-result.json"
            def write(value):
                path.write_text(json.dumps(value), encoding="utf-8")
                path.chmod(0o600)
            write(valid)
            self.assertEqual(MODULE.validate_participant_remove_q05_receipt(path), valid)
            variants = [
                {**valid, "version": True}, {**valid, "profile": "ctf-ten-content"},
                {**valid, "modelCalls": True}, {**valid, "judgeCalls": 1},
                {**valid, "browserPosts": 2}, {**valid, "removeOutboxCount": 0},
                {**valid, "originalPostStatus": 503}, {**valid, "targetId": 1001},
                {**valid, "oldParticipantId": 1001}, {**valid, "newParticipantId": 3010},
                {**valid, "mountedActorId": "1002"},
                {**valid, "comparisonActorId": "909"},
                {**valid, "mountedSessionId": "708"},
                {**valid, "learnerSessionId": "809"},
                {**valid, "preRemovalRows": {**valid["preRemovalRows"], "progress": 0}},
                {**valid, "preRemovalRows": {**valid["preRemovalRows"], "attempts": True}},
                {**valid, "facts": {**valid["facts"], "siblingPreserved": False}},
                {**valid, "facts": {**valid["facts"], "attemptsDeleted": True}},
                {**valid, "dialogTimeAba": {"noPost": True, "eventsObserved": True}},
                {**valid, "removeOutbox": {**valid["removeOutbox"], "kind": "owner_reset"}},
                {**valid, "removeOutbox": {**valid["removeOutbox"], "actorId": "1002"}},
                {**valid, "removeOutbox": {**valid["removeOutbox"], "sessionId": "708"}},
                {**valid, "registrationOutbox": {**valid["registrationOutbox"], "operationId": operation}},
                {**valid, "registrationOutbox": {**valid["registrationOutbox"], "disposition": "active_recovery"}},
                {**valid, "registrationOutbox": {**valid["registrationOutbox"], "sessionId": "809"}},
                {**valid, "generationBefore": "02"}, {**valid, "generationRemoved": "2"},
                {**valid, "generationReregistered": "5"},
                {**valid, "unexpectedApiPaths": [{"path": "/other"}]},
                {**valid, "sameIdRecovery": True}, {**valid, "stage": "pending"},
            ]
            for index, value in enumerate(variants):
                with self.subTest(index=index):
                    write(value)
                    with self.assertRaises(RuntimeError):
                        MODULE.validate_participant_remove_q05_receipt(path)
            write(valid)
            path.write_text(json.dumps(valid).replace('"version": 1', '"version":1,"version":1', 1))
            with self.assertRaisesRegex(RuntimeError, "unreadable"):
                MODULE.validate_participant_remove_q05_receipt(path)
            write(valid)
            path.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, "not private"):
                MODULE.validate_participant_remove_q05_receipt(path)
            path.chmod(0o600)
            Path(directory).chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, "not private"):
                MODULE.validate_participant_remove_q05_receipt(path)
            Path(directory).chmod(0o700)
            linked = Path(directory) / "linked.json"
            os.link(path, linked)
            with self.assertRaisesRegex(RuntimeError, "not private"):
                MODULE.validate_participant_remove_q05_receipt(path)
            linked.unlink()
            path.unlink()
            path.symlink_to(linked)
            with self.assertRaisesRegex(RuntimeError, "noncanonical"):
                MODULE.validate_participant_remove_q05_receipt(path)
            path.unlink()
            with self.assertRaisesRegex(RuntimeError, "missing"):
                MODULE.validate_participant_remove_q05_receipt(path)

    def test_participant_ban_q05_receipt_is_private_exact_and_distinct(self):
        valid = {"version": 1, "profile": "ctf-participant-ban-unban-q05",
            "modelCalls": 0, "judgeCalls": 0, "targetId": 3011,
            "browserPostCounts": {"ban": 1, "unban": 1},
            "serverOperationCounts": {"ban": 1, "unban": 1},
            "cancelPostCounts": {"ban": 0, "unban": 0},
            "abaPostCounts": {"ban": 0, "unban": 0},
            "abaEvents": {"ban": 2, "unban": 2},
            "observedPaths": {"ban": "/api/ctf/admin/participants/3011/ban",
                "unban": "/api/ctf/admin/participants/3011/unban"},
            "flags": {"before": False, "afterBan": True, "afterUnban": False},
            "facts": {key: True for key in ("cancelNoPost", "cancelStateUnchanged",
                "abaNoPost", "abaStateUnchanged", "banDurableBothStores",
                "unbanDurableBothStores", "reloadBan", "reloadUnban",
                "targetEvidencePreserved", "platformPreserved", "siblingPreserved",
                "operationsApplied", "noSecondPost")},
            "unexpectedApiPaths": [], "stage": "complete"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ctf-participant-ban-q05-result.json"
            def write(value):
                path.write_text(json.dumps(value), encoding="utf-8")
                path.chmod(0o600)
            write(valid)
            self.assertEqual(MODULE.validate_participant_ban_q05_receipt(path), valid)
            variants = [
                {**valid, "version": True}, {**valid, "profile": "ctf-ten-content"},
                {**valid, "modelCalls": True}, {**valid, "judgeCalls": 1},
                {**valid, "targetId": 3010},
                {**valid, "browserPostCounts": {"ban": 2, "unban": 1}},
                {**valid, "serverOperationCounts": {"ban": 1, "unban": 0}},
                {**valid, "cancelPostCounts": {"ban": 1, "unban": 0}},
                {**valid, "abaPostCounts": {"ban": 0, "unban": 1}},
                {**valid, "abaEvents": {"ban": 1, "unban": 2}},
                {**valid, "abaEvents": {"ban": True, "unban": 2}},
                {**valid, "observedPaths": {"ban": None, "unban": valid["observedPaths"]["unban"]}},
                {**valid, "observedPaths": {"ban": "/api/ctf/admin/participants/1001/ban",
                    "unban": valid["observedPaths"]["unban"]}},
                {**valid, "observedPaths": {"ban": valid["observedPaths"]["ban"]}},
                {**valid, "flags": {"before": False, "afterBan": False, "afterUnban": False}},
                {**valid, "flags": {"before": 0, "afterBan": True, "afterUnban": False}},
                {**valid, "facts": {**valid["facts"], "reloadUnban": False}},
                {**valid, "facts": {**valid["facts"], "sameIdRecovery": True}},
                {**valid, "unexpectedApiPaths": ["/api/ctf/unexpected"]},
                {**valid, "stage": "pending"}, {**valid, "operationId": "fabricated"},
            ]
            for index, value in enumerate(variants):
                with self.subTest(index=index):
                    write(value)
                    with self.assertRaises(RuntimeError):
                        MODULE.validate_participant_ban_q05_receipt(path)
            write(valid)
            path.write_text(json.dumps(valid).replace('"version": 1', '"version":1,"version":1', 1))
            with self.assertRaisesRegex(RuntimeError, "unreadable"):
                MODULE.validate_participant_ban_q05_receipt(path)
            write(valid)
            path.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, "not private"):
                MODULE.validate_participant_ban_q05_receipt(path)
            path.chmod(0o600)
            Path(directory).chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, "not private"):
                MODULE.validate_participant_ban_q05_receipt(path)
            Path(directory).chmod(0o700)
            linked = Path(directory) / "linked.json"
            os.link(path, linked)
            with self.assertRaisesRegex(RuntimeError, "not private"):
                MODULE.validate_participant_ban_q05_receipt(path)
            linked.unlink()
            path.unlink()
            path.symlink_to(linked)
            with self.assertRaisesRegex(RuntimeError, "noncanonical"):
                MODULE.validate_participant_ban_q05_receipt(path)
            path.unlink()
            with self.assertRaisesRegex(RuntimeError, "missing"):
                MODULE.validate_participant_ban_q05_receipt(path)

    def test_teaching_save_q05_receipt_requires_exact_physical_and_distinct_restore_proof(self):
        first = "123e4567-e89b-42d3-a456-426614174000"
        second = "223e4567-e89b-42d3-a456-426614174000"
        direct = {"originalStatus": 200, "resolvedStatus": 200, "sameIdGets": 0,
            "operationId": first, "sequence": "51", "browserAckOperationId": None,
            "ackMessage": "Stage updated"}
        recovered = {"scope": "content-equivalence-only", "originalStatus": 202,
            "resolvedStatus": 200, "sameIdGets": 1, "operationId": second,
            "sequence": "52", "browserAckOperationId": second, "ackMessage": None}
        facts = ("cancelNoPut", "cancelNoEffect", "dialogAbaNoPut", "dialogAbaNoEffect",
            "confirmedOnePhysicalPut", "physicalRequestFiveFieldsAndBearer", "fiveFieldsExact",
            "canonicalProjectionApplied", "actorSessionBound", "learnerMutationDenied",
            "guardianAndScoringUnchanged", "siblingPreserved", "adminHintsAndSolutionVisible",
            "learnerObjectiveVisible", "learnerRawHintsAndSolutionAbsent",
            "restoreContentEquivalent", "restorationGuardianAndScoringUnchanged")
        valid = {"version": 1, "profile": "ctf-teaching-save-q05", "modelCalls": 0,
            "judgeCalls": 0, "targetStageId": 2, "siblingStageId": 3,
            "mountedActorId": "909", "mountedSessionId": "707",
            "observedPath": "/api/ctf/admin/stages/2/content", "browserPuts": 1,
            "fixtureDeniedPuts": 1, "fixtureRestorePuts": 1,
            "dialogTimeAba": {"eventsObserved": 2, "noPut": True},
            "confirmed": direct, "restore": recovered,
            "facts": {key: True for key in facts},
            "excluded": ["byte-identical-undo", "provenance-rollback"],
            "unexpectedApiPaths": [], "stage": "complete"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ctf-teaching-save-q05-result.json"
            def write(value):
                path.write_text(json.dumps(value), encoding="utf-8")
                path.chmod(0o600)
            write(valid)
            self.assertEqual(MODULE.validate_teaching_save_q05_receipt(path), valid)
            direct_restore = {**recovered, "originalStatus": 200, "sameIdGets": 0,
                "browserAckOperationId": None, "ackMessage": "Stage updated"}
            recovered_confirm = {**direct, "originalStatus": 202, "sameIdGets": 1,
                "browserAckOperationId": first, "ackMessage": None}
            for positive in ({**valid, "restore": direct_restore},
                             {**valid, "confirmed": recovered_confirm}):
                write(positive)
                self.assertEqual(MODULE.validate_teaching_save_q05_receipt(path), positive)
            variants = [
                {**valid, "version": True}, {**valid, "profile": "ctf-ten-content"},
                {**valid, "modelCalls": True}, {**valid, "judgeCalls": 1},
                {**valid, "targetStageId": 3}, {**valid, "targetStageId": 2.0},
                {**valid, "siblingStageId": 2}, {**valid, "siblingStageId": 3.0},
                {**valid, "mountedActorId": "0"}, {**valid, "mountedSessionId": 707},
                {**valid, "observedPath": "/api/ctf/admin/stages/3/content"},
                {**valid, "browserPuts": 2}, {**valid, "fixtureDeniedPuts": 0},
                {**valid, "fixtureRestorePuts": True},
                {**valid, "dialogTimeAba": {"eventsObserved": 1, "noPut": True}},
                {**valid, "dialogTimeAba": {"eventsObserved": True, "noPut": True}},
                {**valid, "dialogTimeAba": {"eventsObserved": 2, "noPut": False}},
                {**valid, "confirmed": {**direct, "originalStatus": 202}},
                {**valid, "confirmed": {**direct, "resolvedStatus": 202}},
                {**valid, "confirmed": {**direct, "sameIdGets": True}},
                {**valid, "confirmed": {**direct, "browserAckOperationId": first}},
                {**valid, "confirmed": {**direct, "ackMessage": None}},
                {**valid, "confirmed": {**direct, "operationId": first.upper()}},
                {**valid, "restore": {**recovered, "sameIdGets": 0}},
                {**valid, "restore": {**recovered, "browserAckOperationId": first}},
                {**valid, "restore": {**recovered, "scope": "byte-identical-undo"}},
                {**valid, "restore": {**recovered, "operationId": first}},
                {**valid, "restore": {**recovered, "sequence": "51"}},
                {**valid, "restore": {**recovered, "sequence": "052"}},
                {**valid, "facts": {**valid["facts"], "learnerMutationDenied": False}},
                {**valid, "facts": {**valid["facts"], "physicalRequestFiveFieldsAndBearer": False}},
                {**valid, "facts": {**valid["facts"], "restorationGuardianAndScoringUnchanged": False}},
                {**valid, "excluded": ["byte-identical-undo"]},
                {**valid, "unexpectedApiPaths": ["/api/ctf/unexpected"]},
                {**valid, "stage": "pending"}, {**valid, "sameIdRecovery": True},
            ]
            for index, value in enumerate(variants):
                with self.subTest(index=index):
                    write(value)
                    with self.assertRaises(RuntimeError):
                        MODULE.validate_teaching_save_q05_receipt(path)
            write(valid)
            path.write_text(json.dumps(valid).replace('"version": 1', '"version":1,"version":1', 1))
            with self.assertRaisesRegex(RuntimeError, "unreadable"):
                MODULE.validate_teaching_save_q05_receipt(path)
            write(valid)
            path.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, "not private"):
                MODULE.validate_teaching_save_q05_receipt(path)
            path.chmod(0o600)
            Path(directory).chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, "not private"):
                MODULE.validate_teaching_save_q05_receipt(path)
            Path(directory).chmod(0o700)
            linked = Path(directory) / "linked.json"
            os.link(path, linked)
            with self.assertRaisesRegex(RuntimeError, "not private"):
                MODULE.validate_teaching_save_q05_receipt(path)
            linked.unlink()
            path.unlink()
            path.symlink_to(linked)
            with self.assertRaisesRegex(RuntimeError, "noncanonical"):
                MODULE.validate_teaching_save_q05_receipt(path)
            path.unlink()
            with self.assertRaisesRegex(RuntimeError, "missing"):
                MODULE.validate_teaching_save_q05_receipt(path)


    def test_advanced_stage_save_q05_receipt_requires_exact_physical_and_distinct_restore_proof(self):
        first = "123e4567-e89b-42d3-a456-426614174000"
        second = "223e4567-e89b-42d3-a456-426614174000"
        direct = {"originalStatus": 200, "resolvedStatus": 200, "sameIdGets": 0,
            "operationId": first, "sequence": "51", "browserAckOperationId": None,
            "ackMessage": "Stage updated"}
        recovered = {"scope": "content-equivalence-only", "originalStatus": 202,
            "resolvedStatus": 200, "sameIdGets": 1, "operationId": second,
            "sequence": "52", "browserAckOperationId": second, "ackMessage": None}
        facts = ("cancelNoPut", "cancelNoEffect", "dialogAbaNoPut", "dialogAbaNoEffect",
            "confirmedOnePhysicalPut", "nineFieldsAndCapturedBearer", "canonicalProjectionApplied",
            "policyAndScoreChanged", "siblingPreserved", "restoreContentEquivalent", "noModelOrJudge")
        valid = {"version": 1, "profile": "ctf-advanced-stage-save-q05", "modelCalls": 0,
            "judgeCalls": 0, "targetStageId": 2, "siblingStageId": 3,
            "mountedActorId": "909", "mountedSessionId": "707",
            "observedPath": "/api/ctf/admin/stages/2", "browserPuts": 1,
            "fixtureRestorePuts": 1, "dialogTimeAba": {"eventsObserved": 2, "noPut": True},
            "confirmed": direct, "restore": recovered, "facts": {key: True for key in facts},
            "excluded": ["byte-identical-undo", "provenance-rollback", "model-qualification"],
            "unexpectedApiPaths": [], "stage": "complete"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ctf-advanced-stage-save-q05-result.json"
            def write(value):
                path.write_text(json.dumps(value), encoding="utf-8")
                path.chmod(0o600)
            write(valid)
            self.assertEqual(MODULE.validate_advanced_stage_save_q05_receipt(path), valid)
            direct_restore = {**recovered, "originalStatus": 200, "sameIdGets": 0,
                "browserAckOperationId": None, "ackMessage": "Stage updated"}
            recovered_confirm = {**direct, "originalStatus": 202, "sameIdGets": 1,
                "browserAckOperationId": first, "ackMessage": None}
            for positive in ({**valid, "restore": direct_restore},
                             {**valid, "confirmed": recovered_confirm}):
                write(positive)
                self.assertEqual(MODULE.validate_advanced_stage_save_q05_receipt(path), positive)
            variants = [
                {**valid, "version": True}, {**valid, "profile": "ctf-teaching-save-q05"},
                {**valid, "modelCalls": 1}, {**valid, "judgeCalls": True},
                {**valid, "targetStageId": 3}, {**valid, "siblingStageId": 2},
                {**valid, "mountedActorId": "0"}, {**valid, "mountedSessionId": 707},
                {**valid, "observedPath": "/api/ctf/admin/stages/2/content"},
                {**valid, "browserPuts": 2}, {**valid, "fixtureRestorePuts": 0},
                {**valid, "dialogTimeAba": {"eventsObserved": 1, "noPut": True}},
                {**valid, "confirmed": {**direct, "originalStatus": 202}},
                {**valid, "confirmed": {**direct, "resolvedStatus": 202}},
                {**valid, "confirmed": {**direct, "sameIdGets": True}},
                {**valid, "confirmed": {**direct, "browserAckOperationId": first}},
                {**valid, "confirmed": {**direct, "ackMessage": None}},
                {**valid, "restore": {**recovered, "sameIdGets": 0}},
                {**valid, "restore": {**recovered, "browserAckOperationId": first}},
                {**valid, "restore": {**recovered, "scope": "byte-identical-undo"}},
                {**valid, "restore": {**recovered, "operationId": first}},
                {**valid, "restore": {**recovered, "sequence": "51"}},
                {**valid, "facts": {**valid["facts"], "nineFieldsAndCapturedBearer": False}},
                {**valid, "facts": {**valid["facts"], "policyAndScoreChanged": False}},
                {**valid, "excluded": ["byte-identical-undo", "provenance-rollback"]},
                {**valid, "unexpectedApiPaths": ["/api/ctf/unexpected"]},
                {**valid, "stage": "pending"}, {**valid, "sameIdRecovery": True},
            ]
            for index, value in enumerate(variants):
                with self.subTest(index=index):
                    write(value)
                    with self.assertRaises(RuntimeError):
                        MODULE.validate_advanced_stage_save_q05_receipt(path)
            write(valid)
            path.write_text(json.dumps(valid).replace('"version": 1', '"version":1,"version":1', 1))
            with self.assertRaisesRegex(RuntimeError, "unreadable"):
                MODULE.validate_advanced_stage_save_q05_receipt(path)
            write(valid)
            path.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, "not private"):
                MODULE.validate_advanced_stage_save_q05_receipt(path)
            path.chmod(0o600)
            Path(directory).chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, "not private"):
                MODULE.validate_advanced_stage_save_q05_receipt(path)
            Path(directory).chmod(0o700)
            linked = Path(directory) / "linked.json"
            os.link(path, linked)
            with self.assertRaisesRegex(RuntimeError, "not private"):
                MODULE.validate_advanced_stage_save_q05_receipt(path)
            linked.unlink()
            path.unlink()
            path.symlink_to(linked)
            with self.assertRaisesRegex(RuntimeError, "noncanonical"):
                MODULE.validate_advanced_stage_save_q05_receipt(path)
            path.unlink()
            with self.assertRaisesRegex(RuntimeError, "missing"):
                MODULE.validate_advanced_stage_save_q05_receipt(path)


    def test_stage_active_q05_receipt_requires_exact_availability_and_distinct_restore_proof(self):
        first = "123e4567-e89b-42d3-a456-426614174000"
        second = "223e4567-e89b-42d3-a456-426614174000"
        direct = {"originalStatus": 200, "resolvedStatus": 200, "sameIdGets": 0,
            "operationId": first, "sequence": "51", "browserAckOperationId": None,
            "ackMessage": "Stage updated"}
        recovered = {"scope": "content-equivalence-only", "originalStatus": 202,
            "resolvedStatus": 200, "sameIdGets": 1, "operationId": second,
            "sequence": "52", "browserAckOperationId": second, "ackMessage": None}
        facts = ("cancelNoPut", "cancelNoEffect", "dialogAbaNoPut", "dialogAbaNoEffect",
            "confirmedOnePhysicalPut", "capturedBearerAndBody", "canonicalProjectionApplied",
            "targetAvailabilityChanged", "nonAvailabilityFieldsUnchanged", "siblingPreserved",
            "restoreContentEquivalent", "noModelOrJudge")
        valid = {"version": 1, "profile": "ctf-stage-active-q05", "modelCalls": 0,
            "judgeCalls": 0, "targetStageId": 2, "siblingStageId": 3,
            "mountedActorId": "909", "mountedSessionId": "707", "originalActive": 1,
            "confirmedActive": 0, "observedPath": "/api/ctf/admin/stages/2", "browserPuts": 1,
            "fixtureRestorePuts": 1, "dialogTimeAba": {"eventsObserved": 2, "noPut": True},
            "confirmed": direct, "restore": recovered, "facts": {key: True for key in facts},
            "excluded": ["byte-identical-undo", "provenance-rollback", "model-qualification"],
            "unexpectedApiPaths": [], "stage": "complete"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ctf-stage-active-q05-result.json"
            def write(value):
                path.write_text(json.dumps(value), encoding="utf-8")
                path.chmod(0o600)
            write(valid)
            self.assertEqual(MODULE.validate_stage_active_q05_receipt(path), valid)
            direct_restore = {**recovered, "originalStatus": 200, "sameIdGets": 0,
                "browserAckOperationId": None, "ackMessage": "Stage updated"}
            recovered_confirm = {**direct, "originalStatus": 202, "sameIdGets": 1,
                "browserAckOperationId": first, "ackMessage": None}
            for positive in ({**valid, "restore": direct_restore},
                             {**valid, "confirmed": recovered_confirm}):
                write(positive)
                self.assertEqual(MODULE.validate_stage_active_q05_receipt(path), positive)
            variants = [
                {**valid, "version": True}, {**valid, "profile": "ctf-advanced-stage-save-q05"},
                {**valid, "modelCalls": 1}, {**valid, "judgeCalls": True},
                {**valid, "targetStageId": 2.0}, {**valid, "siblingStageId": 3.0},
                {**valid, "originalActive": True}, {**valid, "originalActive": 0},
                {**valid, "confirmedActive": False}, {**valid, "confirmedActive": 1},
                {**valid, "mountedActorId": "0"}, {**valid, "mountedSessionId": 707},
                {**valid, "observedPath": "/api/ctf/admin/stages/2/content"},
                {**valid, "browserPuts": 2}, {**valid, "fixtureRestorePuts": 0},
                {**valid, "dialogTimeAba": {"eventsObserved": 1, "noPut": True}},
                {**valid, "confirmed": {**direct, "originalStatus": 202}},
                {**valid, "confirmed": {**direct, "resolvedStatus": 202}},
                {**valid, "confirmed": {**direct, "sameIdGets": True}},
                {**valid, "confirmed": {**direct, "browserAckOperationId": first}},
                {**valid, "restore": {**recovered, "sameIdGets": 33}},
                {**valid, "restore": {**recovered, "browserAckOperationId": first}},
                {**valid, "restore": {**recovered, "scope": "byte-identical-undo"}},
                {**valid, "restore": {**recovered, "operationId": first}},
                {**valid, "restore": {**recovered, "sequence": "51"}},
                {**valid, "facts": {**valid["facts"], "targetAvailabilityChanged": False}},
                {**valid, "facts": {**valid["facts"], "noModelOrJudge": False}},
                {**valid, "excluded": ["byte-identical-undo", "provenance-rollback"]},
                {**valid, "unexpectedApiPaths": ["/api/ctf/unexpected"]},
                {**valid, "stage": "pending"}, {**valid, "sameIdRecovery": True},
            ]
            for index, value in enumerate(variants):
                with self.subTest(index=index):
                    write(value)
                    with self.assertRaises(RuntimeError):
                        MODULE.validate_stage_active_q05_receipt(path)
            write(valid)
            path.write_text(json.dumps(valid).replace('"version": 1', '"version":1,"version":1', 1))
            with self.assertRaisesRegex(RuntimeError, "unreadable"):
                MODULE.validate_stage_active_q05_receipt(path)
            write(valid)
            path.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, "not private"):
                MODULE.validate_stage_active_q05_receipt(path)
            path.chmod(0o600)
            Path(directory).chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, "not private"):
                MODULE.validate_stage_active_q05_receipt(path)
            Path(directory).chmod(0o700)
            linked = Path(directory) / "linked.json"
            os.link(path, linked)
            with self.assertRaisesRegex(RuntimeError, "not private"):
                MODULE.validate_stage_active_q05_receipt(path)
            linked.unlink()
            path.unlink()
            path.symlink_to(linked)
            with self.assertRaisesRegex(RuntimeError, "noncanonical"):
                MODULE.validate_stage_active_q05_receipt(path)
            path.unlink()
            with self.assertRaisesRegex(RuntimeError, "missing"):
                MODULE.validate_stage_active_q05_receipt(path)


    def test_stage_delete_q05_receipt_requires_owned_nonvacuous_delete_evidence(self):
        create_id = "123e4567-e89b-42d3-a456-426614174000"
        start_id = "223e4567-e89b-42d3-a456-426614174000"
        delete_id = "323e4567-e89b-42d3-a456-426614174000"
        direct = lambda operation_id, sequence, message: {"originalStatus": 200,
            "resolvedStatus": 200, "sameIdGets": 0, "operationId": operation_id,
            "sequence": sequence, "browserAckOperationId": None, "ackMessage": message}
        created = direct(create_id, "51", "Stage created")
        started = direct(start_id, "52", "Stage started successfully")
        deleted = {"originalStatus": 202, "resolvedStatus": 200, "sameIdGets": 1,
            "operationId": delete_id, "sequence": "53", "browserAckOperationId": delete_id,
            "ackMessage": None}
        facts = ("cancelNoDelete", "cancelNoEffect", "dialogAbaNoDelete", "dialogAbaNoEffect",
            "confirmedOnePhysicalDelete", "capturedBearerAndEmptyBody", "canonicalCreateAndStart",
            "progressAndEventPopulated", "canonicalDeleteProjection", "progressAndEventCascaded",
            "identityBindingTombstoned", "canonicalTenAndSiblingPreserved", "historyPreserved",
            "noModelOrJudge")
        valid = {"version": 1, "profile": "ctf-stage-delete-q05", "stageNumber": 11,
            "stageOrder": 0, "targetStageId": 11, "mountedActorId": "909",
            "mountedSessionId": "707", "learnerActorId": "3011", "learnerSessionId": "606",
            "observedPath": "/api/ctf/admin/stages/11", "browserDeletes": 1,
            "setup": {"create": created, "start": started}, "confirmed": deleted,
            "dialogTimeAba": {"eventsObserved": 2, "noDelete": True}, "preProgressRows": 1,
            "preEventRows": 1, "facts": {key: True for key in facts},
            "excluded": ["attempts-nonvacuity", "judgment-deletion", "model-qualification",
                         "byte-identical-database-undo"], "unexpectedApiPaths": [],
            "stage": "complete", "modelCalls": 0, "judgeCalls": 0}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ctf-stage-delete-q05-result.json"
            def write(value):
                path.write_text(json.dumps(value), encoding="utf-8")
                path.chmod(0o600)
            write(valid)
            self.assertEqual(MODULE.validate_stage_delete_q05_receipt(path), valid)
            direct_delete = direct(delete_id, "53", "Stage deleted")
            recovered_create = {**created, "originalStatus": 202, "sameIdGets": 1,
                "browserAckOperationId": create_id, "ackMessage": None}
            for positive in ({**valid, "confirmed": direct_delete},
                             {**valid, "setup": {"create": recovered_create, "start": started}}):
                write(positive)
                self.assertEqual(MODULE.validate_stage_delete_q05_receipt(path), positive)
            variants = [
                {**valid, "version": True}, {**valid, "profile": "ctf-stage-active-q05"},
                {**valid, "stageNumber": 11.0}, {**valid, "stageOrder": False},
                {**valid, "targetStageId": 11.0}, {**valid, "targetStageId": 10},
                {**valid, "mountedActorId": "0"}, {**valid, "learnerActorId": 3011},
                {**valid, "learnerActorId": "3012"},
                {**valid, "observedPath": "/api/ctf/admin/stages/12"},
                {**valid, "browserDeletes": True}, {**valid, "preProgressRows": 0},
                {**valid, "preEventRows": True},
                {**valid, "dialogTimeAba": {"eventsObserved": 1, "noDelete": True}},
                {**valid, "setup": {"create": created}},
                {**valid, "setup": {"create": {**created, "sameIdGets": 1}, "start": started}},
                {**valid, "setup": {"create": {**created, "operationId": start_id}, "start": started}},
                {**valid, "confirmed": {**deleted, "sameIdGets": 33}},
                {**valid, "confirmed": {**deleted, "browserAckOperationId": create_id}},
                {**valid, "confirmed": {**deleted, "sequence": "52"}},
                {**valid, "facts": {**valid["facts"], "historyPreserved": False}},
                {**valid, "excluded": ["attempts-nonvacuity", "judgment-deletion"]},
                {**valid, "unexpectedApiPaths": ["/api/ctf/unexpected"]},
                {**valid, "modelCalls": 1}, {**valid, "judgeCalls": True},
                {**valid, "stage": "failed"}, {**valid, "extra": True},
            ]
            for index, value in enumerate(variants):
                with self.subTest(index=index):
                    write(value)
                    with self.assertRaises(RuntimeError):
                        MODULE.validate_stage_delete_q05_receipt(path)
            write(valid)
            path.write_text(json.dumps(valid).replace('"version": 1', '"version":1,"version":1', 1))
            with self.assertRaisesRegex(RuntimeError, "unreadable"):
                MODULE.validate_stage_delete_q05_receipt(path)
            write(valid)
            path.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, "not private"):
                MODULE.validate_stage_delete_q05_receipt(path)
            path.chmod(0o600)
            Path(directory).chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, "not private"):
                MODULE.validate_stage_delete_q05_receipt(path)
            Path(directory).chmod(0o700)
            linked = Path(directory) / "linked.json"
            os.link(path, linked)
            with self.assertRaisesRegex(RuntimeError, "not private"):
                MODULE.validate_stage_delete_q05_receipt(path)
            linked.unlink()
            path.unlink()
            path.symlink_to(linked)
            with self.assertRaisesRegex(RuntimeError, "noncanonical"):
                MODULE.validate_stage_delete_q05_receipt(path)
            path.unlink()
            with self.assertRaisesRegex(RuntimeError, "missing"):
                MODULE.validate_stage_delete_q05_receipt(path)


    def test_config_q05_receipt_requires_all_keys_and_independent_restores(self):
        keys = ["ctf_enabled", "ctf_visible_to_students", "student_leaderboard_visible", "public_leaderboard_visible", "ctf_registration_open", "ctf_max_participants", "ctf_time_limit", "leaderboard_update_interval", "ctf_nav_visible", "ctf_show_technique_feedback", "ctf_show_attempt_counter", "ctf_hint_gating_attempts", "ctf_hint_cost_1", "ctf_hint_cost_2", "ctf_hint_cost_3"]
        def operation(number, sequence, *, restore=False):
            value = {"originalStatus": 200, "resolvedStatus": 200, "sameIdGets": 0,
                "operationId": f"{number:08x}-e89b-42d3-a456-426614174000", "sequence": str(sequence),
                "browserAckOperationId": None, "ackMessage": "Configuration updated successfully"}
            return {"scope": "content-equivalence-only", **value, "contentEquivalent": True} if restore else value
        durable = {"canonicalProjectionApplied": True, "actorSessionBound": True,
            "dbValueMatches": True, "adminGetMatches": True, "publicGetMatches": True}
        cases = []
        for index, key in enumerate(keys):
            cases.append({"key": key, "previous": "false", "proposed": "true",
                "cancel": {"noPost": True, "unchanged": True},
                "dialogTimeAba": {"eventsObserved": 2, "noPost": True, "unchanged": True},
                "confirmed": operation(index * 2 + 1, index * 2 + 1), "durable": durable,
                "restore": operation(index * 2 + 2, index * 2 + 2, restore=True), "siblingPreserved": True})
        receipt = {"version": 1, "profile": "ctf-config-q05", "mountedActorId": "1002",
            "mountedSessionId": "2002", "keys": keys, "cases": cases,
            "facts": {key: True for key in ("cancelNoPost", "dialogAbaNoPost", "onePhysicalPostPerKey", "canonicalProjectionReadback", "distinctRestoreOperations", "siblingStageProgressHistoryPreserved", "noPreview", "noMutationRetry", "noModelJudgeOrCredit")},
            "excluded": ["byte-identical-undo", "provenance-rollback", "model-qualification", "original-55-content"],
            "unexpectedApiPaths": [], "browserActions": 1200, "apiRequests": 1200,
            "stage": "complete", "modelCalls": 0, "judgeCalls": 0}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ctf-config-q05-result.json"
            def write(value): path.write_text(json.dumps(value), encoding="utf-8"); path.chmod(0o600)
            write(receipt)
            self.assertEqual(MODULE.validate_config_q05_receipt(path), receipt)
            variants = [
                {**receipt, "keys": keys[:-1]}, {**receipt, "browserActions": 1201},
                {**receipt, "browserActions": 0}, {**receipt, "apiRequests": 0},
                {**receipt, "apiRequests": True}, {**receipt, "modelCalls": 1},
                {**receipt, "cases": [{**cases[0], "key": "wrong"}, *cases[1:]]},
                {**receipt, "cases": [{**cases[0], "cancel": {"noPost": 1, "unchanged": True}}, *cases[1:]]},
                {**receipt, "cases": [{**cases[0], "cancel": {"noPost": True, "unchanged": "true"}}, *cases[1:]]},
                {**receipt, "cases": [{**cases[0], "confirmed": {**cases[0]["confirmed"], "sameIdGets": 1}}, *cases[1:]]},
                {**receipt, "cases": [{**cases[0], "restore": {**cases[0]["restore"], "operationId": cases[0]["confirmed"]["operationId"]}}, *cases[1:]]},
                {**receipt, "facts": {**receipt["facts"], "noPreview": False}},
            ]
            for value in variants:
                write(value)
                with self.assertRaises(RuntimeError): MODULE.validate_config_q05_receipt(path)
            write(receipt)
            path.write_text(json.dumps(receipt).replace('"version": 1', '"version":1,"version":1', 1))
            with self.assertRaisesRegex(RuntimeError, "unreadable"): MODULE.validate_config_q05_receipt(path)


    def test_preview_q05_receipt_requires_stage_one_bounded_provider_diagnostics_and_no_effect(self):
        cases = {
            "cancel": {"browserPosts": 0, "serverPosts": 0, "providerStarts": 0,
                "uiPublished": False, "stateInvariant": True},
            "dialogAba": {"browserPosts": 0, "serverPosts": 0, "providerStarts": 0,
                "uiPublished": False, "stateInvariant": True, "eventsObserved": 2},
            "singleFlight": {"browserPosts": 1, "serverPosts": 1, "providerStarts": 1,
                "uiPublished": True, "stateInvariant": True, "status": 200},
            "postDispatchClose": {"browserPosts": 1, "serverPosts": 1, "providerStarts": 1,
                "uiPublished": False, "stateInvariant": True, "clientAborted": True},
        }
        receipt = {"version": 1, "profile": "ctf-preview-q05", "targetStageId": 1,
            "siblingStageId": 2, "mountedActorId": "1002", "mountedSessionId": "2002",
            "cases": cases, "providerDiagnostics": {"kind": "controlled-synthetic-transport",
                "physicalStarted": 2, "completed": 1, "clientAborted": 1, "maxPhysicalCalls": 2},
            "storeWitness": {key: True for key in ("targetStageUnchanged", "siblingStageUnchanged",
                "progressUnchanged", "attemptsUnchanged", "judgmentsUnchanged", "historyUnchanged", "outboxUnchanged")},
            "facts": {key: True for key in ("cancelNoPostOrProvider", "dialogAbaNoPostOrProvider",
                "singleFlightOnePostOneProvider", "closeAbortsProviderWithoutPublication",
                "stage1NoLanguageOrOutputDefense", "allDurableStateUnchanged",
                "noObjectiveJudgeOrCredit", "providerDiagnosticsNotQualification")},
            "excluded": ["model-qualification", "objective-judge", "gameplay-credit", "outbox-operation-recovery"],
            "unexpectedApiPaths": [], "browserActions": 7, "apiRequests": 4,
            "stage": "complete", "judgeCalls": 0, "genuineCredit": 0}
        with tempfile.TemporaryDirectory() as directory:
            Path(directory).chmod(0o700)
            path = Path(directory) / "ctf-preview-q05-result.json"
            def write(value): path.write_text(json.dumps(value), encoding="utf-8"); path.chmod(0o600)
            write(receipt)
            self.assertEqual(MODULE.validate_preview_q05_receipt(path), receipt)
            variants = [
                {**receipt, "targetStageId": 2}, {**receipt, "browserActions": 0},
                {**receipt, "providerDiagnostics": {**receipt["providerDiagnostics"], "physicalStarted": True}},
                {**receipt, "providerDiagnostics": {**receipt["providerDiagnostics"], "clientAborted": 0}},
                {**receipt, "cases": {**cases, "cancel": {**cases["cancel"], "serverPosts": 1}}},
                {**receipt, "cases": {**cases, "dialogAba": {**cases["dialogAba"], "eventsObserved": True}}},
                {**receipt, "cases": {**cases, "singleFlight": {**cases["singleFlight"], "uiPublished": False}}},
                {**receipt, "cases": {**cases, "postDispatchClose": {**cases["postDispatchClose"], "clientAborted": 1}}},
                {**receipt, "storeWitness": {**receipt["storeWitness"], "outboxUnchanged": False}},
                {**receipt, "facts": {**receipt["facts"], "providerDiagnosticsNotQualification": False}},
                {**receipt, "judgeCalls": 1}, {**receipt, "genuineCredit": 1},
            ]
            for value in variants:
                write(value)
                with self.assertRaises(RuntimeError): MODULE.validate_preview_q05_receipt(path)
            write(receipt)
            path.write_text(json.dumps(receipt).replace('"version": 1', '"version":1,"version":1', 1))
            with self.assertRaisesRegex(RuntimeError, "unreadable"): MODULE.validate_preview_q05_receipt(path)

    def test_learner_entry_hint_q05_receipt_requires_ordered_operations_and_no_scoring(self):
        def operation(number, sequence):
            return {"originalStatus": 200, "resolvedStatus": 200, "sameIdGets": 0,
                "operationId": f"{number:08x}-e89b-42d3-a456-426614174000", "sequence": str(sequence)}
        register, start, hint = operation(1, 1), operation(2, 2), operation(3, 3)
        receipt = {"version": 1, "profile": "ctf-learner-entry-hint-q05", "actorId": "1002", "sessionId": "2002", "participantId": "1002", "stageId": 1, "siblingOwnerId": 1001,
            "prerequisite": {"hintGate": "0", "source": "pre-bootstrap-config", "defaultAttemptGateProven": False},
            "browserPosts": {"register": 1, "start": 1, "hint": 1}, "serverPosts": {"register": 1, "start": 1, "hint": 1},
            "operations": {"register": register, "start": start, "hint": hint}, "startOperationIds": [start["operationId"]],
            "hintDialog": {"cancelPosts": 0, "abaPosts": 0, "abaEventsObserved": 2, "cancelStateUnchanged": True, "abaStateUnchanged": True},
            "facts": {key: True for key in ("physicalJoin", "physicalStageCard", "automaticStart", "hintCancelNoPost", "hintAbaNoPost", "onePhysicalHintPurchase", "actorSessionOutboxBound", "canonicalProjectionBound", "durableProgressBound", "nonemptySiblingPreserved", "noScoredAttemptOrCredit")},
            "storeWitness": {key: True for key in ("ownerRegistered", "stageStarted", "oneHintPurchased", "costApplied", "siblingBeforeNonempty", "siblingUnchanged", "attemptsUnchanged", "judgmentsUnchanged", "siblingLeaderboardUnchanged")},
            "unexpectedApiPaths": [], "browserActions": 10, "apiRequests": 8, "modelCalls": 0, "judgeCalls": 0, "genuineCredit": 0,
            "excluded": ["default-attempt-gate", "scored-attempt", "fixed-practice", "model-qualification", "objective-judge", "gameplay-credit"], "stage": "complete"}
        with tempfile.TemporaryDirectory() as directory:
            Path(directory).chmod(0o700); path = Path(directory) / "ctf-learner-entry-hint-q05-result.json"
            def write(value): path.write_text(json.dumps(value), encoding="utf-8"); path.chmod(0o600)
            write(receipt); self.assertEqual(MODULE.validate_learner_entry_hint_q05_receipt(path), receipt)
            variants = [
                {**receipt, "stageId": 2}, {**receipt, "browserPosts": {"register": 1, "start": 0, "hint": 1}},
                {**receipt, "serverPosts": {"register": 1, "start": 2, "hint": 1}},
                {**receipt, "startOperationIds": [register["operationId"]]},
                {**receipt, "hintDialog": {**receipt["hintDialog"], "abaPosts": 1}},
                {**receipt, "storeWitness": {**receipt["storeWitness"], "attemptsUnchanged": False}},
                {**receipt, "facts": {**receipt["facts"], "noScoredAttemptOrCredit": False}}, {**receipt, "modelCalls": 1},
            ]
            for value in variants:
                write(value)
                with self.assertRaises(RuntimeError): MODULE.validate_learner_entry_hint_q05_receipt(path)

    def test_learner_attempt_gate_q05_receipt_requires_three_controlled_scored_attempts(self):
        def attempt(ordinal, judge_calls):
            base = ordinal * 3
            return {"ordinal": ordinal,
                "runId": f"{base:08x}-e89b-42d3-a456-426614174000",
                "admissionId": f"{base + 1:08x}-e89b-42d3-a456-426614174000",
                "decisionId": f"{base + 2:08x}-e89b-42d3-a456-426614174000",
                "requestStatus": 202, "publicationStatus": 200, "verdict": "fail", "accepted": False,
                "guardianCalls": 1, "judgeCalls": judge_calls, "sameIdGets": 1,
                "recoveryResumePosts": 0, "recoveryAuthorizePosts": 0,
                "ownerSessionBound": True, "decisionApplied": True, "publicationCurrent": True, "noProviderReplay": True}
        attempts = [attempt(1, 1), attempt(2, 1), attempt(3, 1)]
        receipt = {"version": 1, "profile": "ctf-learner-attempt-gate-q05", "transport": "controlled-synthetic",
            "actorId": "2402", "sessionId": "2002", "participantId": "3402", "stageId": 1, "siblingOwnerId": 1001,
            "gate": {"configured": 3, "initialAttempts": 0, "initialHintVisible": False, "deniedStatus": 409,
                "deniedError": "Hint availability changed; refresh stage status", "deniedOutboxDelta": 0,
                "deniedProgressUnchanged": True, "deniedProviderCalls": 0,
                "afterAttempts": [{"count": 1, "hintVisible": False, "status": "in_progress"}, {"count": 2, "hintVisible": False, "status": "in_progress"}, {"count": 3, "hintVisible": True, "status": "in_progress"}], "afterThirdHintVisible": True},
            "attempts": attempts, "browserPosts": {"register": 1, "start": 1, "attempt": 3, "hint": 0, "resume": 0, "authorize": 0},
            "serverPosts": {"register": 1, "start": 1, "attempt": 3, "hint": 1, "resume": 0, "authorize": 0},
            "lifecycle": {"register": {"operationId": "0000000a-e89b-42d3-a456-426614174000", "sequence": "1", "originalStatus": 200},
                "start": {"operationId": "0000000b-e89b-42d3-a456-426614174000", "sequence": "2", "originalStatus": 202}},
            "reset": {"operationId": "0000000c-e89b-42d3-a456-426614174000", "sequence": "9", "originalStatus": 200,
                "deniedStatus": 409, "deniedError": "CTF request is no longer current", "generationBefore": "0", "generationAfter": "1"},
            "providerCalls": {"guardian": 3, "judge": 3, "total": 6},
            "storeWitness": {key: True for key in ("progressAttemptsThree", "threeAttemptRows", "threeJudgmentRows", "noCompletion", "noHintPurchased", "identityBindingCurrent", "siblingBeforeNonempty", "siblingUnchanged", "resetReferenceFenced", "historicalEvidenceRetained")},
            "facts": {key: True for key in ("physicalJoinAndStart", "defaultGateIsThree", "lockedHintBeforeAttempts", "canonicalHintDenialBeforeAttempts", "threePhysicalScoredSubmissions", "sameReferenceRecoveryNoResubmit", "gateUnlockOnlyAfterThirdAttempt", "mountedSessionBound", "canonicalAttemptProjectionBound", "nonemptySiblingUnchanged", "noActualModelOrGenuineCreditClaim")},
            "excluded": ["actual-model-qualification", "guaranteed-secret-extraction", "genuine-gameplay-credit", "fixed-practice", "post-reset-credit"], "unexpectedApiPaths": [], "browserActions": 20, "apiRequests": 20, "genuineCredit": 0, "stage": "complete"}
        with tempfile.TemporaryDirectory() as directory:
            Path(directory).chmod(0o700); path = Path(directory) / "ctf-learner-attempt-gate-q05-result.json"
            def write(value): path.write_text(json.dumps(value), encoding="utf-8"); path.chmod(0o600)
            write(receipt); self.assertEqual(MODULE.validate_learner_attempt_gate_q05_receipt(path), receipt)
            recovered = json.loads(json.dumps(receipt))
            recovered["attempts"][0]["recoveryResumePosts"] = 1
            recovered["attempts"][0]["recoveryAuthorizePosts"] = 1
            recovered["browserPosts"]["resume"] = recovered["browserPosts"]["authorize"] = 1
            recovered["serverPosts"]["resume"] = recovered["serverPosts"]["authorize"] = 1
            write(recovered); self.assertEqual(MODULE.validate_learner_attempt_gate_q05_receipt(path), recovered)
            variants = [
                {**receipt, "transport": "actual-model"}, {**receipt, "stageId": 2},
                {**receipt, "browserPosts": {"register": 1, "start": 1, "attempt": 2, "hint": 0, "resume": 0, "authorize": 0}},
                {**receipt, "browserPosts": {"register": 1, "start": 2, "attempt": 3, "hint": 0, "resume": 0, "authorize": 0}},
                {**receipt, "providerCalls": {"guardian": 3, "judge": 3, "total": 7}},
                {**receipt, "providerCalls": {"guardian": 3.0, "judge": 3, "total": 6}},
                {**receipt, "attempts": [attempts[0], attempts[0], attempts[2]]},
                {**receipt, "attempts": [{**attempts[0], "requestStatus": 202.0}, *attempts[1:]]},
                {**receipt, "attempts": [{**attempts[0], "publicationStatus": 200.0}, *attempts[1:]]},
                {**receipt, "lifecycle": {**receipt["lifecycle"], "start": {**receipt["lifecycle"]["start"], "operationId": receipt["lifecycle"]["register"]["operationId"]}}},
                {**receipt, "reset": {**receipt["reset"], "deniedStatus": 503}},
                {**receipt, "reset": {**receipt["reset"], "generationAfter": "0"}},
                {**receipt, "reset": {**receipt["reset"], "sequence": "2"}},
                {**receipt, "gate": {**receipt["gate"], "afterThirdHintVisible": False}},
                {**receipt, "gate": {**receipt["gate"], "initialAttempts": False}},
                {**receipt, "gate": {**receipt["gate"], "deniedOutboxDelta": False}},
                {**receipt, "gate": {**receipt["gate"], "afterAttempts": [{**receipt["gate"]["afterAttempts"][0], "count": True}, *receipt["gate"]["afterAttempts"][1:]]}},
                {**receipt, "attempts": [{**attempts[0], "ordinal": True}, *attempts[1:]]},
                {**receipt, "attempts": [{**attempts[0], "guardianCalls": True}, *attempts[1:]]},
                {**receipt, "attempts": [{**attempts[0], "recoveryResumePosts": True}, *attempts[1:]]},
                {**receipt, "attempts": [{**attempts[0], "recoveryAuthorizePosts": 2}, *attempts[1:]]},
                {**receipt, "browserPosts": {**receipt["browserPosts"], "resume": 1}},
                {**receipt, "browserPosts": {**receipt["browserPosts"], "authorize": True}},
                {**receipt, "storeWitness": {**receipt["storeWitness"], "threeAttemptRows": False}},
                {**receipt, "facts": {**receipt["facts"], "noActualModelOrGenuineCreditClaim": False}},
                {**receipt, "actorId": "1002"}, {**receipt, "participantId": "1001"},
                {**receipt, "genuineCredit": 1}, {**receipt, "browserActions": 801},
            ]
            for value in variants:
                write(value)
                with self.assertRaises(RuntimeError): MODULE.validate_learner_attempt_gate_q05_receipt(path)

    def test_fixed_practice_q05_receipt_requires_exact_canonical_staleness_receipt(self):
        cases = {
            "modeSelection": {"browserPosts": 0, "serverPosts": 0, "providerStarts": 0, "responsePublished": False, "stateInvariant": True},
            "submit": {"browserPosts": 1, "serverPosts": 1, "providerStarts": 1, "responsePublished": True, "status": 200, "scoringEligible": False, "protectedContextIncluded": False, "serverSecretProvided": False},
            "staleBeforeDispatch": {"browserPosts": 0, "serverPosts": 0, "providerStarts": 0, "responsePublished": False, "stateInvariant": True},
            "staleBeforeProvider": {"browserPosts": 1, "serverPosts": 1, "providerStarts": 0, "responsePublished": False, "status": 409, "stateInvariant": True},
            "staleAfterDispatch": {"browserPosts": 1, "serverPosts": 1, "providerStarts": 1, "responsePublished": False, "status": 409, "stateInvariant": True},
        }
        phases = ("pre-provider-stale", "pre-provider-restore", "post-provider-stale", "post-provider-restore")
        authority = [{"phase": phase, "operationId": f"0000000{index}-e89b-42d3-a456-426614174000",
            "sequence": str(index), "actorId": "1001", "sessionId": "2001", "stageId": 1}
            for index, phase in enumerate(phases, 1)]
        witness = ("attemptsUnchanged", "progressUnchanged", "judgmentsUnchanged", "leaderboardUnchanged",
            "authorityOutboxExact", "siblingBeforeNonempty", "siblingUnchanged", "controlledFixtureCleaned")
        facts = ("visibleFixedModeDisclosureBeforeSubmit", "modeSelectionNoDispatch", "oneBoundPracticePost",
            "staleBeforeDispatchNoProviderOrPublication", "staleBeforeProviderNoProviderOrPublication",
            "staleAfterDispatchNoPublication", "unscoredPublicContextBoundary",
            "noAttemptProgressJudgeLeaderboardCreditWrites", "noAutomaticRetryOrOperationRecovery",
            "nonemptySiblingPreserved", "canonicalAuthorityStalenessBound",
            "onlyExpectedAuthorityOutboxMutations", "controlledProviderNotQualification")
        receipt = {"version": 1, "profile": "ctf-fixed-practice-q05", "actorId": "2403", "sessionId": "2002",
            "participantId": "3402", "stageId": 1, "siblingOwnerId": "1001", "cases": cases,
            "providerDiagnostics": {"kind": "controlled-synthetic-provider", "physicalStarted": 2, "completed": 1, "staleAfterDispatch": 1, "maxPhysicalCalls": 2},
            "storeWitness": {key: True for key in witness}, "facts": {key: True for key in facts},
            "excluded": ["native-browser-proof", "actual-model-qualification", "objective-judge", "gameplay-credit", "operation-id-recovery", "automatic-retry"],
            "cleanup": {"providerDrained": True, "ownedBrowserHandles": 0, "ownedStoreHandles": 0},
            "authorityOperations": authority, "unexpectedApiPaths": [], "browserActions": 12, "apiRequests": 9,
            "stage": "complete", "judgeCalls": 0, "genuineCredit": 0}
        with tempfile.TemporaryDirectory() as directory:
            Path(directory).chmod(0o700); path = Path(directory) / "ctf-fixed-practice-q05-result.json"
            def write(value): path.write_text(json.dumps(value), encoding="utf-8"); path.chmod(0o600)
            write(receipt); self.assertEqual(MODULE.validate_fixed_practice_q05_receipt(path), receipt)
            variants = [
                {**receipt, "profile": "actual-model"},
                {**receipt, "cases": {**cases, "submit": {**cases["submit"], "status": 202}}},
                {**receipt, "cases": {**cases, "submit": {**cases["submit"], "browserPosts": True}}},
                {**receipt, "providerDiagnostics": {**receipt["providerDiagnostics"], "physicalStarted": 3}},
                {**receipt, "providerDiagnostics": {**receipt["providerDiagnostics"], "completed": True}},
                {**receipt, "authorityOperations": [*authority[:2], {**authority[2], "sequence": "2"}, authority[3]]},
                {**receipt, "authorityOperations": [{**authority[0], "stageId": 2}, *authority[1:]]},
                {**receipt, "authorityOperations": authority[:3]},
                {**receipt, "actorId": "2402"},
                {**receipt, "authorityOperations": [authority[0], {**authority[1], "actorId": "1002"}, *authority[2:]]},
                {**receipt, "authorityOperations": [authority[0], {**authority[1], "sessionId": "2003"}, *authority[2:]]},
                {**receipt, "authorityOperations": [{**operation, "actorId": "2403", "sessionId": "2002"} for operation in authority]},
                {**receipt, "cleanup": {**receipt["cleanup"], "ownedBrowserHandles": 1}},
                {**receipt, "facts": {**receipt["facts"], "canonicalAuthorityStalenessBound": False}},
                {**receipt, "browserActions": 241},
                {**receipt, "judgeCalls": True},
            ]
            for value in variants:
                write(value)
                with self.assertRaises(RuntimeError): MODULE.validate_fixed_practice_q05_receipt(path)


    def test_maintenance_lease_closed_isolation(self):
        argv = self.required_args() + ["--application-maintenance-lease"]
        selected = MODULE.qualification_selection(MODULE.parse_args(argv), "a" * 12)
        self.assertEqual(selected["test"], "tests/postgres/applicationMaintenanceLease.integration.test.js")
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (180, 300, 120))
        self.assertEqual(len(selected["databases"]), 2)
        self.assertIsNone(MODULE.delivery_role(selected))
        urls = {db: {role: db + role for role in ("runtime", "migration")} for db in selected["databases"]}
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(set(env), {f"PG_APPLICATION_LEASE_{i}_{r}_URL" for i in (1, 2) for r in ("RUNTIME", "MIGRATION")})
        self.assertEqual(len(set(env.values())), 4)
        self.assertNotIn("IDENTITY_DATABASE_URL", env)
        from unittest.mock import patch
        with patch.object(MODULE, "run_qualification", side_effect=AssertionError("no resources")):
            self.assertEqual(MODULE.main(argv), 0)
        for extra in (["--ctf-authority-application"], ["--stage-end", "3"], ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit):
                MODULE.parse_args(argv + extra)

    def required_args(self):
        return ["--docker-host", "unix:///owned.sock",
            "--docker-cli", "/missing/docker", "--docker-cli-sha256", "0" * 64,
            "--node", "/missing/node", "--node-sha256", "1" * 64,
            "--source-manifest-sha256", "2" * 64,
            "--dependency-manifest-sha256", "3" * 64]

    def test_bootstrap_closed_four_store_contract(self):
        argv = self.required_args() + ["--ctf-authority-bootstrap"]
        selected = MODULE.qualification_selection(MODULE.parse_args(argv), "a" * 12)
        self.assertEqual(selected["test"], "tests/postgres/ctfAuthorityBootstrap.integration.test.js")
        self.assertEqual(len(set(selected["databases"])), 4)
        self.assertTrue(all(len(x.encode()) <= 63 for x in selected["databases"]))
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (240, 420, 120))
        urls = {db: {role: f"owned-{db}-{role}" for role in ("runtime", "migration")} for db in selected["databases"]}
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(set(env), {f"PG_CTF_BOOTSTRAP_{state}_{kind}_{role}_URL" for state in ("FRESH", "POPULATED") for kind in ("IDENTITY", "CTF") for role in ("RUNTIME", "MIGRATION")})
        self.assertEqual(len(set(env.values())), 8)
        self.assertNotIn("RUN_LIVE_CTF_WORKFLOW", selected["environment"])
        from unittest.mock import patch
        with patch.object(MODULE, "run_qualification", side_effect=AssertionError("no resources")):
            self.assertEqual(MODULE.main(argv), 0)
        for extra in (["--ctf-current-publication"], ["--stage-end", "3"], ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit):
                MODULE.parse_args(argv + extra)

    def test_blocked_publication_closed_selector(self):
        argv = self.required_args() + ["--ctf-blocked-publication"]
        selected = MODULE.qualification_selection(MODULE.parse_args(argv), "a" * 12)
        self.assertEqual(selected["test"], "tests/postgres/ctfBlockedPublication.integration.test.js")
        self.assertEqual(selected["environment"], {"CTF_BLOCKED_PUBLICATION_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"})
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (240, 420, 120))
        self.assertEqual(len(set(selected["databases"])), 4)
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("owasp_ai_goat_test_ctf_blockpub_") for n in selected["databases"]))
        urls = {n: {r: n + r for r in ("runtime", "migration")} for n in selected["databases"]}
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(set(env), {f"PG_CTF_BLOCKED_PUBLICATION_{s}_{k}_{r}_URL" for s in ("FRESH", "POPULATED") for k in ("IDENTITY", "CTF") for r in ("RUNTIME", "MIGRATION")})
        self.assertEqual(len(set(env.values())), 8)
        from unittest.mock import patch
        with patch.object(MODULE, "run_qualification", side_effect=AssertionError("no resources")):
            self.assertEqual(MODULE.main(argv), 0)
        for extra in (["--ctf-current-publication"], ["--target-stage", "8"], ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit):
                MODULE.parse_args(argv + extra)

    def test_rendered_client_copy_checks_both_pins_and_excludes_private_env(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); source = root / "source"; workspace = root / "owned"
            client = source / "client"; client.mkdir(parents=True); workspace.mkdir()
            (client / "src").mkdir(); (client / "src" / "page.js").write_text("export default 1")
            (client / ".env").write_text("PRIVATE=not-copied")
            (client / "node_modules").mkdir(); (client / "node_modules" / "module.js").write_text("module.exports=1")
            source_pin = MODULE.manifest_digest(MODULE.client_inventory(client))
            dependency_pin = MODULE.manifest_digest(MODULE.dependency_inventory(client / "node_modules"))
            with self.assertRaisesRegex(RuntimeError, "source manifest"):
                MODULE.copy_rendered_client(source, workspace, "0" * 64, dependency_pin)
            with self.assertRaisesRegex(RuntimeError, "Dependency manifest"):
                MODULE.copy_rendered_client(source, workspace, source_pin, "0" * 64)
            MODULE.copy_rendered_client(source, workspace, source_pin, dependency_pin)
            self.assertFalse((workspace / "client" / ".env").exists())
            self.assertEqual((workspace / "client" / "src" / "page.js").read_text(), "export default 1")
            self.assertTrue((workspace / "client" / "node_modules").is_symlink())
            workspace.chmod(0o700)

    def test_rendered_readonly_copy_preserves_source_modes_and_writes_only_owned_root(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); source = root / "source"; client = source / "client"; workspace = root / "owned"
            (client / "src").mkdir(parents=True); (client / "node_modules").mkdir(); workspace.mkdir()
            page = client / "src" / "page.js"; page.write_text("export default 1"); page.chmod(0o444)
            (client / "node_modules" / "module.js").write_text("module.exports=1")
            (client / "src").chmod(0o555); client.chmod(0o555); workspace.chmod(0o500)
            source_modes = {p: stat.S_IMODE(p.stat().st_mode) for p in (client, client / "src", page)}
            try:
                source_pin = MODULE.manifest_digest(MODULE.client_inventory(client))
                dependency_pin = MODULE.manifest_digest(MODULE.dependency_inventory(client / "node_modules"))
                MODULE.copy_rendered_client(source, workspace, source_pin, dependency_pin)
                self.assertEqual({p: stat.S_IMODE(p.stat().st_mode) for p in source_modes}, source_modes)
                self.assertEqual(stat.S_IMODE(workspace.stat().st_mode), 0o500)
                self.assertEqual(stat.S_IMODE((workspace / "client").stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE((workspace / "client" / "src").stat().st_mode), 0o555)
                self.assertEqual(stat.S_IMODE((workspace / "client" / "src" / "page.js").stat().st_mode), 0o444)
                self.assertTrue((workspace / "client" / "node_modules").is_symlink())
                (workspace / "client" / "owned-entry.html").write_text("owned build entry")
                self.assertFalse((client / "owned-entry.html").exists())
            finally:
                workspace.chmod(0o700); client.chmod(0o700); (client / "src").chmod(0o700)
                if (workspace / "client" / "src").exists(): (workspace / "client" / "src").chmod(0o700)

    def test_rendered_recovery_closed_selector_and_browser_pin(self):
        argv = self.required_args() + ["--ctf-recovery-rendered", "--browser-executable", "/owned/chrome", "--browser-sha256", "a" * 64, "--client-source-sha256", "b" * 64, "--client-dependency-sha256", "c" * 64]
        selected = MODULE.qualification_selection(MODULE.parse_args(argv), "a" * 12)
        self.assertEqual(selected["environment"]["CTF_RECOVERY_RENDERED_ISOLATED"], "1")
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (480, 660, 120))
        self.assertEqual(MODULE.delivery_role(selected), "dvaia_ctf_delivery")
        urls = {n: {r: n + r for r in ("runtime", "migration", "delivery")} for n in selected["databases"]}
        self.assertEqual(len(MODULE.database_environment(selected, urls)), 10)
        self.assertEqual(len(set(selected["databases"])), 4)
        for extra in (["--ctf-predefense-recovery"], ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit): MODULE.parse_args(argv + extra)
        for suffix in (["--ctf-recovery-rendered"], ["--browser-executable", "/owned/chrome", "--browser-sha256", "a" * 64, "--client-source-sha256", "b" * 64, "--client-dependency-sha256", "c" * 64]):
            with self.assertRaises(SystemExit): MODULE.parse_args(self.required_args() + suffix)

    def test_predefense_recovery_closed_selector(self):
        argv = self.required_args() + ["--ctf-predefense-recovery"]
        selected = MODULE.qualification_selection(MODULE.parse_args(argv), "a" * 12)
        self.assertEqual(selected["test"], "tests/postgres/ctfAuthorityApplication.integration.test.js")
        self.assertEqual(selected["environment"], {"CTF_PREDEFENSE_RECOVERY_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"})
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (240, 420, 120))
        self.assertEqual(len(set(selected["databases"])), 4)
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("owasp_ai_goat_test_ctf_app_") for n in selected["databases"]))
        urls = {n: {r: n + r for r in ("runtime", "migration")} for n in selected["databases"]}
        for db in selected["databases"][1::2]: urls[db]["delivery"] = db + "delivery"
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(set(env), {f"PG_CTF_AUTHORITY_APPLICATION_{s}_{k}_{r}_URL" for s in ("FRESH", "POPULATED") for k in ("IDENTITY", "CTF") for r in ("RUNTIME", "MIGRATION")} | {f"PG_CTF_AUTHORITY_APPLICATION_{state}_CTF_DELIVERY_URL" for state in ("FRESH", "POPULATED")})
        self.assertEqual(len(set(env.values())), 10)
        self.assertEqual(MODULE.delivery_role(selected), "dvaia_ctf_delivery")
        self.assertEqual([MODULE.delivery_database(selected, db) for db in selected["databases"]], [False, True, False, True])
        old = MODULE.qualification_selection(MODULE.parse_args(self.required_args() + ["--ctf-blocked-predefense"]), "b" * 12)
        self.assertIsNone(MODULE.delivery_role(old))
        self.assertFalse(any(MODULE.delivery_database(old, db) for db in old["databases"]))
        from unittest.mock import patch
        with patch.object(MODULE, "run_qualification", side_effect=AssertionError("no resources")):
            self.assertEqual(MODULE.main(argv), 0)
        for extra in (["--ctf-authority-application"], ["--ctf-current-publication"], ["--target-stage", "8"], ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit):
                MODULE.parse_args(argv + extra)

    def test_authority_application_closed_selector(self):
        argv = self.required_args() + ["--ctf-authority-application"]
        selected = MODULE.qualification_selection(MODULE.parse_args(argv), "a" * 12)
        self.assertEqual(selected["test"], "tests/postgres/ctfAuthorityApplication.integration.test.js")
        self.assertEqual(selected["environment"], {"CTF_AUTHORITY_APPLICATION_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"})
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (240, 420, 120))
        self.assertEqual(len(set(selected["databases"])), 4)
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("owasp_ai_goat_test_ctf_app_") for n in selected["databases"]))
        urls = {n: {r: n + r for r in ("runtime", "migration")} for n in selected["databases"]}
        for db in selected["databases"][1::2]: urls[db]["delivery"] = db + "delivery"
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(set(env), {f"PG_CTF_AUTHORITY_APPLICATION_{s}_{k}_{r}_URL" for s in ("FRESH", "POPULATED") for k in ("IDENTITY", "CTF") for r in ("RUNTIME", "MIGRATION")} | {f"PG_CTF_AUTHORITY_APPLICATION_{state}_CTF_DELIVERY_URL" for state in ("FRESH", "POPULATED")})
        self.assertEqual(len(set(env.values())), 10)
        self.assertEqual(MODULE.delivery_role(selected), "dvaia_ctf_delivery")
        self.assertEqual([MODULE.delivery_database(selected, db) for db in selected["databases"]], [False, True, False, True])
        old = MODULE.qualification_selection(MODULE.parse_args(self.required_args() + ["--ctf-blocked-predefense"]), "b" * 12)
        self.assertIsNone(MODULE.delivery_role(old))
        self.assertFalse(any(MODULE.delivery_database(old, db) for db in old["databases"]))
        from unittest.mock import patch
        with patch.object(MODULE, "run_qualification", side_effect=AssertionError("no resources")):
            self.assertEqual(MODULE.main(argv), 0)
        for extra in (["--ctf-current-publication"], ["--target-stage", "8"], ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit):
                MODULE.parse_args(argv + extra)

    def test_production_runtime_closed_selector(self):
        argv = self.required_args() + ["--ctf-production-runtime"]
        selected = MODULE.qualification_selection(MODULE.parse_args(argv), "a" * 12)
        self.assertEqual(selected["test"], "tests/postgres/ctfProductionRuntime.integration.test.js")
        self.assertEqual(selected["environment"], {"CTF_PRODUCTION_RUNTIME_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"})
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (240, 420, 120))
        self.assertEqual(len(set(selected["databases"])), 4)
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("owasp_ai_goat_test_ctf_prod_") for n in selected["databases"]))
        urls = {n: {r: n + r for r in ("runtime", "migration")} for n in selected["databases"]}
        for db in selected["databases"][1::2]: urls[db]["delivery"] = db + "delivery"
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(set(env), {f"PG_CTF_PRODUCTION_RUNTIME_{s}_{k}_{r}_URL" for s in ("FRESH", "POPULATED") for k in ("IDENTITY", "CTF") for r in ("RUNTIME", "MIGRATION")} | {f"PG_CTF_PRODUCTION_RUNTIME_{state}_CTF_DELIVERY_URL" for state in ("FRESH", "POPULATED")})
        self.assertEqual(len(set(env.values())), 10)
        self.assertEqual(MODULE.delivery_role(selected), "dvaia_ctf_delivery")
        self.assertEqual([MODULE.delivery_database(selected, db) for db in selected["databases"]], [False, True, False, True])
        old = MODULE.qualification_selection(MODULE.parse_args(self.required_args() + ["--ctf-blocked-predefense"]), "b" * 12)
        self.assertIsNone(MODULE.delivery_role(old))
        self.assertFalse(any(MODULE.delivery_database(old, db) for db in old["databases"]))
        from unittest.mock import patch
        with patch.object(MODULE, "run_qualification", side_effect=AssertionError("no resources")):
            self.assertEqual(MODULE.main(argv), 0)
        for extra in (["--ctf-current-publication"], ["--target-stage", "8"], ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit):
                MODULE.parse_args(argv + extra)

    def test_authority_runtime_closed_selector(self):
        argv = self.required_args() + ["--ctf-authority-runtime"]
        selected = MODULE.qualification_selection(MODULE.parse_args(argv), "a" * 12)
        self.assertEqual(selected["test"], "tests/postgres/ctfAuthorityRuntime.integration.test.js")
        self.assertEqual(selected["environment"], {"CTF_AUTHORITY_RUNTIME_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"})
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (240, 420, 120))
        self.assertEqual(len(set(selected["databases"])), 4)
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("owasp_ai_goat_test_ctf_runtime_") for n in selected["databases"]))
        urls = {n: {r: n + r for r in ("runtime", "migration")} for n in selected["databases"]}
        for db in selected["databases"][1::2]: urls[db]["delivery"] = db + "delivery"
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(set(env), {f"PG_CTF_AUTHORITY_RUNTIME_{s}_{k}_{r}_URL" for s in ("FRESH", "POPULATED") for k in ("IDENTITY", "CTF") for r in ("RUNTIME", "MIGRATION")} | {f"PG_CTF_AUTHORITY_RUNTIME_{state}_CTF_DELIVERY_URL" for state in ("FRESH", "POPULATED")})
        self.assertEqual(len(set(env.values())), 10)
        self.assertEqual(MODULE.delivery_role(selected), "dvaia_ctf_delivery")
        self.assertEqual([MODULE.delivery_database(selected, db) for db in selected["databases"]], [False, True, False, True])
        old = MODULE.qualification_selection(MODULE.parse_args(self.required_args() + ["--ctf-blocked-predefense"]), "b" * 12)
        self.assertIsNone(MODULE.delivery_role(old))
        self.assertFalse(any(MODULE.delivery_database(old, db) for db in old["databases"]))
        from unittest.mock import patch
        with patch.object(MODULE, "run_qualification", side_effect=AssertionError("no resources")):
            self.assertEqual(MODULE.main(argv), 0)
        for extra in (["--ctf-current-publication"], ["--target-stage", "8"], ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit):
                MODULE.parse_args(argv + extra)

    def test_telemetry_closed_selector(self):
        argv = self.required_args() + ["--ctf-telemetry"]
        selected = MODULE.qualification_selection(MODULE.parse_args(argv), "a" * 12)
        self.assertEqual(selected["test"], "tests/postgres/ctfTelemetry.integration.test.js")
        self.assertEqual(selected["environment"], {"CTF_TELEMETRY_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"})
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (240, 420, 120))
        self.assertEqual(len(set(selected["databases"])), 4)
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("owasp_ai_goat_test_ctf_telemetry_") for n in selected["databases"]))
        urls = {n: {r: n + r for r in ("runtime", "migration")} for n in selected["databases"]}
        for db in selected["databases"][1::2]: urls[db]["delivery"] = db + "delivery"
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(set(env), {f"PG_CTF_TELEMETRY_{s}_{k}_{r}_URL" for s in ("FRESH", "POPULATED") for k in ("IDENTITY", "CTF") for r in ("RUNTIME", "MIGRATION")} | {f"PG_CTF_TELEMETRY_{state}_CTF_DELIVERY_URL" for state in ("FRESH", "POPULATED")})
        self.assertEqual(len(set(env.values())), 10)
        self.assertEqual(MODULE.delivery_role(selected), "dvaia_ctf_delivery")
        self.assertEqual([MODULE.delivery_database(selected, db) for db in selected["databases"]], [False, True, False, True])
        old = MODULE.qualification_selection(MODULE.parse_args(self.required_args() + ["--ctf-blocked-predefense"]), "b" * 12)
        self.assertIsNone(MODULE.delivery_role(old))
        self.assertFalse(any(MODULE.delivery_database(old, db) for db in old["databases"]))
        from unittest.mock import patch
        with patch.object(MODULE, "run_qualification", side_effect=AssertionError("no resources")):
            self.assertEqual(MODULE.main(argv), 0)
        for extra in (["--ctf-current-publication"], ["--target-stage", "8"], ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit):
                MODULE.parse_args(argv + extra)

    def test_delivery_provision_closed_cases_and_owned_secret(self):
        from unittest.mock import patch
        import tempfile
        for case in ("fresh-reuse", "completion-failure"):
            argv = self.required_args() + ["--ctf-delivery-provision-case", case]
            selected = MODULE.qualification_selection(MODULE.parse_args(argv), "a" * 12)
            self.assertEqual(MODULE.provision_case(selected), case)
            self.assertEqual(selected["databases"], ())
            self.assertEqual(selected["tmpfsBytes"], 1073741824)
            self.assertEqual(selected["test"], "tests/postgres/ctfDeliveryProvision.integration.test.js")
            self.assertEqual(selected["environment"]["PG_PROVISION_FRESH_CLUSTER"], "yes")
            self.assertEqual((selected["childSeconds"],selected["workSeconds"],selected["cleanupSeconds"]),(240,420,120))
            with patch.object(MODULE, "run_qualification", side_effect=AssertionError("no resources")):
                self.assertEqual(MODULE.main(argv), 0)
            for extra in (["--ctf-delivery-activation"], ["--target-stage", "8"], ["--candidate-set", "reviewer-boundary-v1"]):
                with self.assertRaises(SystemExit): MODULE.parse_args(argv + extra)
        with self.assertRaises(SystemExit): MODULE.parse_args(self.required_args()+["--ctf-delivery-provision-case","other"])
        with tempfile.TemporaryDirectory() as directory:
            root = MODULE.Path(directory)
            owned, password = MODULE.create_provision_secret(root, "a" * 12)
            self.assertEqual(owned["path"].stat().st_mode & 0o777, 0o600)
            self.assertEqual(owned["path"].read_text(), "POSTGRES_PASSWORD="+password+"\n")
            self.assertEqual(len(password),64)
            with self.assertRaises(FileExistsError): MODULE.create_provision_secret(root, "a" * 12)
            moved=owned["path"].with_suffix(".retained");owned["path"].rename(moved)
            owned["path"].symlink_to(moved)
            with self.assertRaises(RuntimeError): MODULE.remove_provision_secret(owned)
            owned["path"].unlink();moved.rename(owned["path"])
            MODULE.remove_provision_secret(owned);self.assertFalse(owned["path"].exists())

    def test_delivery_activation_closed_selector(self):
        argv = self.required_args() + ["--ctf-delivery-activation"]
        selected = MODULE.qualification_selection(MODULE.parse_args(argv), "a" * 12)
        self.assertEqual(selected["test"], "tests/postgres/ctfDeliveryActivation.integration.test.js")
        self.assertEqual(selected["environment"], {"CTF_DELIVERY_ACTIVATION_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"})
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (240, 420, 120))
        self.assertEqual(len(set(selected["databases"])), 4)
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("owasp_ai_goat_test_ctf_activation_") for n in selected["databases"]))
        urls = {n: {r: n + r for r in ("runtime", "migration")} for n in selected["databases"]}
        for db in selected["databases"][1::2]: urls[db]["delivery"] = db + "delivery"
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(set(env), {f"PG_CTF_ACTIVATION_{s}_{k}_{r}_URL" for s in ("FRESH", "POPULATED") for k in ("IDENTITY", "CTF") for r in ("RUNTIME", "MIGRATION")} | {f"PG_CTF_ACTIVATION_{state}_CTF_DELIVERY_URL" for state in ("FRESH", "POPULATED")})
        self.assertEqual(len(set(env.values())), 10)
        self.assertEqual(MODULE.delivery_role(selected), "dvaia_ctf_delivery")
        self.assertEqual([MODULE.delivery_database(selected, db) for db in selected["databases"]], [False, True, False, True])
        old = MODULE.qualification_selection(MODULE.parse_args(self.required_args() + ["--ctf-blocked-predefense"]), "b" * 12)
        self.assertIsNone(MODULE.delivery_role(old))
        self.assertFalse(any(MODULE.delivery_database(old, db) for db in old["databases"]))
        from unittest.mock import patch
        with patch.object(MODULE, "run_qualification", side_effect=AssertionError("no resources")):
            self.assertEqual(MODULE.main(argv), 0)
        for extra in (["--ctf-current-publication"], ["--target-stage", "8"], ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit):
                MODULE.parse_args(argv + extra)

    def test_registration_locator_closed_selector(self):
        argv = self.required_args() + ["--ctf-registration-locator"]
        selected = MODULE.qualification_selection(MODULE.parse_args(argv), "a" * 12)
        self.assertEqual(selected["test"], "tests/postgres/ctfRegistrationLocator.integration.test.js")
        self.assertEqual(selected["environment"], {"CTF_REGISTRATION_LOCATOR_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"})
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (240, 420, 120))
        self.assertEqual(len(set(selected["databases"])), 4)
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("owasp_ai_goat_test_ctf_locator_") for n in selected["databases"]))
        urls = {n: {r: n + r for r in ("runtime", "migration")} for n in selected["databases"]}
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(set(env), {f"PG_CTF_REGISTRATION_LOCATOR_{s}_{k}_{r}_URL" for s in ("FRESH", "POPULATED") for k in ("IDENTITY", "CTF") for r in ("RUNTIME", "MIGRATION")})
        self.assertEqual(len(set(env.values())), 8)
        from unittest.mock import patch
        with patch.object(MODULE, "run_qualification", side_effect=AssertionError("no resources")):
            self.assertEqual(MODULE.main(argv), 0)
        for extra in (["--ctf-current-publication"], ["--target-stage", "8"], ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit):
                MODULE.parse_args(argv + extra)

    def test_response_diagnostics_closed_selector(self):
        argv = self.required_args() + ["--ctf-response-diagnostics"]
        selected = MODULE.qualification_selection(MODULE.parse_args(argv), "a" * 12)
        self.assertEqual(selected["test"], "tests/postgres/ctfResponseDiagnostics.integration.test.js")
        self.assertEqual(selected["environment"], {"CTF_RESPONSE_DIAGNOSTICS_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"})
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (240, 420, 120))
        self.assertEqual(len(set(selected["databases"])), 4)
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("owasp_ai_goat_test_ctf_diagnostics_") for n in selected["databases"]))
        urls = {n: {r: n + r for r in ("runtime", "migration")} for n in selected["databases"]}
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(set(env), {f"PG_CTF_RESPONSE_DIAGNOSTICS_{s}_{k}_{r}_URL" for s in ("FRESH", "POPULATED") for k in ("IDENTITY", "CTF") for r in ("RUNTIME", "MIGRATION")})
        self.assertEqual(len(set(env.values())), 8)
        from unittest.mock import patch
        with patch.object(MODULE, "run_qualification", side_effect=AssertionError("no resources")):
            self.assertEqual(MODULE.main(argv), 0)
        for extra in (["--ctf-current-publication"], ["--target-stage", "8"], ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit):
                MODULE.parse_args(argv + extra)

    def test_admin_read_closed_selector(self):
        argv = self.required_args() + ["--ctf-admin-read"]
        selected = MODULE.qualification_selection(MODULE.parse_args(argv), "a" * 12)
        self.assertEqual(selected["test"], "tests/postgres/ctfAdminRead.integration.test.js")
        self.assertEqual(selected["environment"], {"CTF_ADMIN_READ_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"})
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (240, 420, 120))
        self.assertEqual(len(set(selected["databases"])), 4)
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("owasp_ai_goat_test_ctf_adminread_") for n in selected["databases"]))
        urls = {n: {r: n + r for r in ("runtime", "migration")} for n in selected["databases"]}
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(set(env), {f"PG_CTF_ADMIN_READ_{s}_{k}_{r}_URL" for s in ("FRESH", "POPULATED") for k in ("IDENTITY", "CTF") for r in ("RUNTIME", "MIGRATION")})
        self.assertEqual(len(set(env.values())), 8)
        from unittest.mock import patch
        with patch.object(MODULE, "run_qualification", side_effect=AssertionError("no resources")):
            self.assertEqual(MODULE.main(argv), 0)
        for extra in (["--ctf-current-publication"], ["--target-stage", "8"], ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit):
                MODULE.parse_args(argv + extra)

    def test_blocked_predefense_closed_selector(self):
        argv = self.required_args() + ["--ctf-blocked-predefense"]
        selected = MODULE.qualification_selection(MODULE.parse_args(argv), "a" * 12)
        self.assertEqual(selected["test"], "tests/postgres/ctfBlockedPredefense.integration.test.js")
        self.assertEqual(selected["environment"], {"CTF_BLOCKED_PREDEFENSE_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"})
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (240, 420, 120))
        self.assertEqual(len(set(selected["databases"])), 4)
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("owasp_ai_goat_test_ctf_blockpre_") for n in selected["databases"]))
        urls = {n: {r: n + r for r in ("runtime", "migration")} for n in selected["databases"]}
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(set(env), {f"PG_CTF_BLOCKED_PREDEFENSE_{s}_{k}_{r}_URL" for s in ("FRESH", "POPULATED") for k in ("IDENTITY", "CTF") for r in ("RUNTIME", "MIGRATION")})
        self.assertEqual(len(set(env.values())), 8)
        from unittest.mock import patch
        with patch.object(MODULE, "run_qualification", side_effect=AssertionError("no resources")):
            self.assertEqual(MODULE.main(argv), 0)
        for extra in (["--ctf-current-publication"], ["--target-stage", "8"], ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit):
                MODULE.parse_args(argv + extra)

    def test_worker_lifecycle_closed_selector(self):
        argv = self.required_args() + ["--ctf-worker-lifecycle"]
        selected = MODULE.qualification_selection(MODULE.parse_args(argv), "a" * 12)
        self.assertEqual(selected["test"], "tests/postgres/ctfProjectionWorkerLifecycle.integration.test.js")
        self.assertEqual(selected["environment"], {"CTF_WORKER_LIFECYCLE_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"})
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (240, 420, 120))
        self.assertEqual(len(set(selected["databases"])), 4)
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("owasp_ai_goat_test_ctf_worklife_") for n in selected["databases"]))
        urls = {n: {r: n + r for r in ("runtime", "migration")} for n in selected["databases"]}
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(set(env), {f"PG_CTF_WORKER_LIFECYCLE_{s}_{k}_{r}_URL" for s in ("FRESH", "POPULATED") for k in ("IDENTITY", "CTF") for r in ("RUNTIME", "MIGRATION")})
        self.assertEqual(len(set(env.values())), 8)
        from unittest.mock import patch
        with patch.object(MODULE, "run_qualification", side_effect=AssertionError("no resources")):
            self.assertEqual(MODULE.main(argv), 0)
        for extra in (["--ctf-current-publication"], ["--target-stage", "8"], ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit):
                MODULE.parse_args(argv + extra)

    def test_predefense_closed_selector(self):
        argv = self.required_args() + ["--ctf-predefense"]
        selected = MODULE.qualification_selection(MODULE.parse_args(argv), "a" * 12)
        self.assertEqual(selected["test"], "tests/postgres/ctfPredefense.integration.test.js")
        self.assertEqual(selected["environment"], {"CTF_PREDEFENSE_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"})
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (240, 420, 120))
        self.assertEqual(len(set(selected["databases"])), 4)
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("owasp_ai_goat_test_ctf_predef_") for n in selected["databases"]))
        urls = {n: {r: n + r for r in ("runtime", "migration")} for n in selected["databases"]}
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(set(env), {f"PG_CTF_PREDEFENSE_{s}_{k}_{r}_URL" for s in ("FRESH", "POPULATED") for k in ("IDENTITY", "CTF") for r in ("RUNTIME", "MIGRATION")})
        self.assertEqual(len(set(env.values())), 8)
        from unittest.mock import patch
        with patch.object(MODULE, "run_qualification", side_effect=AssertionError("no resources")):
            self.assertEqual(MODULE.main(argv), 0)
        for extra in (["--ctf-current-publication"], ["--target-stage", "8"], ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit):
                MODULE.parse_args(argv + extra)

    def test_student_deletion_closed_selector(self):
        argv = self.required_args() + ["--ctf-student-deletion"]
        selected = MODULE.qualification_selection(MODULE.parse_args(argv), "a" * 12)
        self.assertEqual(selected["test"], "tests/postgres/ctfStudentDeletion.integration.test.js")
        self.assertEqual(selected["environment"], {"CTF_DELETION_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"})
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (240, 420, 120))
        self.assertEqual(len(set(selected["databases"])), 4)
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("owasp_ai_goat_test_ctf_delete_") for n in selected["databases"]))
        urls = {n: {r: n + r for r in ("runtime", "migration")} for n in selected["databases"]}
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(set(env), {f"PG_CTF_DELETION_{s}_{k}_{r}_URL" for s in ("FRESH", "POPULATED") for k in ("IDENTITY", "CTF") for r in ("RUNTIME", "MIGRATION")})
        self.assertEqual(len(set(env.values())), 8)
        from unittest.mock import patch
        with patch.object(MODULE, "run_qualification", side_effect=AssertionError("no resources")):
            self.assertEqual(MODULE.main(argv), 0)
        for extra in (["--ctf-current-publication"], ["--target-stage", "8"], ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit):
                MODULE.parse_args(argv + extra)

    def test_admin_response_closed_selector(self):
        argv = self.required_args() + ["--ctf-admin-response"]
        selected = MODULE.qualification_selection(MODULE.parse_args(argv), "a" * 12)
        self.assertEqual(selected["test"], "tests/postgres/ctfAdminResponse.integration.test.js")
        self.assertEqual(selected["environment"], {"CTF_ADMIN_RESPONSE_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"})
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (240, 420, 120))
        self.assertEqual(len(set(selected["databases"])), 4)
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("owasp_ai_goat_test_ctf_opread_") for n in selected["databases"]))
        urls = {n: {r: n + r for r in ("runtime", "migration")} for n in selected["databases"]}
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(set(env), {f"PG_CTF_OPERATION_RECOVERY_{s}_{k}_{r}_URL" for s in ("FRESH", "POPULATED") for k in ("IDENTITY", "CTF") for r in ("RUNTIME", "MIGRATION")})
        self.assertEqual(len(set(env.values())), 8)
        from unittest.mock import patch
        with patch.object(MODULE, "run_qualification", side_effect=AssertionError("no resources")):
            self.assertEqual(MODULE.main(argv), 0)
        for extra in (["--ctf-current-publication"], ["--target-stage", "8"], ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit):
                MODULE.parse_args(argv + extra)

    def test_current_read_closed_selector(self):
        argv = self.required_args() + ["--ctf-current-read"]
        selected = MODULE.qualification_selection(MODULE.parse_args(argv), "a" * 12)
        self.assertEqual(selected["test"], "tests/postgres/ctfCurrentRead.integration.test.js")
        self.assertEqual(selected["environment"], {"CTF_CURRENT_READ_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"})
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (240, 420, 120))
        self.assertEqual(len(set(selected["databases"])), 4)
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("owasp_ai_goat_test_ctf_read_") for n in selected["databases"]))
        urls = {n: {r: n + r for r in ("runtime", "migration")} for n in selected["databases"]}
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(set(env), {f"PG_CTF_CURRENT_READ_{s}_{k}_{r}_URL" for s in ("FRESH", "POPULATED") for k in ("IDENTITY", "CTF") for r in ("RUNTIME", "MIGRATION")})
        self.assertEqual(len(set(env.values())), 8)
        from unittest.mock import patch
        with patch.object(MODULE, "run_qualification", side_effect=AssertionError("no resources")):
            self.assertEqual(MODULE.main(argv), 0)
        for extra in (["--ctf-current-publication"], ["--target-stage", "8"], ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit):
                MODULE.parse_args(argv + extra)

    def test_current_response_closed_selector(self):
        argv = self.required_args() + ["--ctf-current-response"]
        selected = MODULE.qualification_selection(MODULE.parse_args(argv), "a" * 12)
        self.assertEqual(selected["test"], "tests/postgres/ctfCurrentResponse.integration.test.js")
        self.assertEqual(selected["environment"], {"CTF_CURRENT_RESPONSE_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"})
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (240, 420, 120))
        self.assertEqual(len(set(selected["databases"])), 4)
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("owasp_ai_goat_test_ctf_opread_") for n in selected["databases"]))
        urls = {n: {r: n + r for r in ("runtime", "migration")} for n in selected["databases"]}
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(set(env), {f"PG_CTF_OPERATION_RECOVERY_{s}_{k}_{r}_URL" for s in ("FRESH", "POPULATED") for k in ("IDENTITY", "CTF") for r in ("RUNTIME", "MIGRATION")})
        self.assertEqual(len(set(env.values())), 8)
        from unittest.mock import patch
        with patch.object(MODULE, "run_qualification", side_effect=AssertionError("no resources")):
            self.assertEqual(MODULE.main(argv), 0)
        for extra in (["--ctf-current-publication"], ["--target-stage", "8"], ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit):
                MODULE.parse_args(argv + extra)

    def test_session_fence_is_closed_and_resource_free_without_run(self):
        argv = self.required_args() + ["--session-fence-only"]
        from unittest.mock import patch
        with patch.object(MODULE, "run_qualification", side_effect=AssertionError("resources forbidden")):
            self.assertEqual(MODULE.main(argv), 0)
        for other in (["--stage-end", "4"], ["--target-stage", "8"],
                      ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit):
                MODULE.parse_args(argv + other)

    def test_session_fence_exact_two_databases_no_live_model_and_bounds(self):
        args = MODULE.parse_args(self.required_args() + ["--session-fence-only"])
        selected = MODULE.qualification_selection(args, "abc123")
        self.assertEqual(selected["databases"], ("owasp_ai_goat_test_ctf_session_identity_abc123",
                                                 "owasp_ai_goat_test_ctf_session_store_abc123"))
        self.assertEqual(selected["test"], "tests/postgres/ctfAdmittedSessionFence.integration.test.js")
        self.assertEqual([selected[k] for k in ("childSeconds", "workSeconds", "cleanupSeconds")], [180, 300, 120])
        self.assertEqual(selected["environment"]["CTF_SESSION_FENCE_ISOLATED"], "1")
        self.assertEqual(selected["environment"]["AI_PROVIDER"], "mock")
        self.assertEqual(selected["environment"]["JUDGE_PROVIDER"], "mock")
        for forbidden in ("RUN_LIVE_CTF_WORKFLOW", "OLLAMA_BASE_URL", "CTF_STAGES_ROUTE_ISOLATED"):
            self.assertNotIn(forbidden, selected["environment"])

    def test_existing_model_selection_contract_preserved(self):
        for flags, mode, end, seconds in [([], "sequential_prefix", 4, 700),
                (["--target-stage", "8"], "independent_target", 8, 1900)]:
            selected = MODULE.qualification_selection(MODULE.parse_args(self.required_args() + flags), "abc")
            self.assertEqual(selected["mode"], mode)
            self.assertEqual(selected["stageEnd"], end)
            self.assertEqual(selected["childSeconds"], seconds)
            self.assertIsNone(selected["workSeconds"])
            self.assertEqual(selected["environment"]["RUN_LIVE_CTF_WORKFLOW"], "1")
            self.assertEqual(selected["test"], "tests/postgres/ctfStagesRoute.integration.test.js")

    def test_authority_schema_selector_closed_nonmutating(self):
        argv = self.required_args() + ["--authority-schema-only"]
        from unittest.mock import patch
        with patch.object(MODULE, "run_qualification", side_effect=AssertionError("resources forbidden")):
            self.assertEqual(MODULE.main(argv), 0)
        for other in (["--session-fence-only"], ["--stage-end", "4"], ["--target-stage", "8"],
                      ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit): MODULE.parse_args(argv + other)

    def test_authority_schema_exact_four_pairs_no_platform_urls_or_model(self):
        args = MODULE.parse_args(self.required_args() + ["--authority-schema-only"])
        selected = MODULE.qualification_selection(args, "abc123")
        self.assertEqual(selected["test"], "tests/postgres/ctfAuthorityReadModel.integration.test.js")
        expected = tuple(f"owasp_ai_goat_test_ctf_authority_{state}_{kind}_abc123"
            for state in ("fresh", "populated") for kind in ("identity", "ctf"))
        self.assertEqual(selected["databases"], expected)
        urls = {name: {role: name + ":" + role for role in ("runtime", "migration")} for name in expected}
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(len(env), 8)
        for state in ("FRESH", "POPULATED"):
            for kind in ("IDENTITY", "CTF"):
                for role in ("RUNTIME", "MIGRATION"):
                    key = f"PG_CTF_AUTHORITY_{state}_{kind}_{role}_URL"
                    self.assertEqual(env[key], f"owasp_ai_goat_test_ctf_authority_{state.lower()}_{kind.lower()}_abc123:{role.lower()}")
        self.assertFalse(any(key in env for key in ("IDENTITY_DATABASE_URL", "CTF_DATABASE_URL")))
        self.assertFalse(any(key in selected["environment"] for key in ("AI_PROVIDER", "OLLAMA_BASE_URL", "RUN_LIVE_CTF_WORKFLOW")))
        self.assertEqual([selected[k] for k in ("childSeconds", "workSeconds", "cleanupSeconds", "tmpfsBytes")], [240,420,120,536870912])

    def test_lifecycle_sql_selector_closed_four_stores_no_model_or_app_urls(self):
        from unittest.mock import patch
        argv = self.required_args() + ["--ctf-lifecycle-schema"]
        with patch.object(MODULE, "run_qualification", side_effect=AssertionError("resources forbidden")):
            self.assertEqual(MODULE.main(argv), 0)
        for flags in (["--authority-schema-only"], ["--session-fence-only"], ["--target-stage", "8"], ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit): MODULE.parse_args(argv + flags)
        selected = MODULE.qualification_selection(MODULE.parse_args(argv), "abc123")
        self.assertEqual(selected["test"], "tests/postgres/ctfLifecycleProjection.integration.test.js")
        self.assertEqual(len(selected["databases"]), 4)
        self.assertEqual([selected[k] for k in ("childSeconds", "workSeconds", "cleanupSeconds")], [240,420,120])
        urls = {name: {role:name+role for role in ("runtime","migration")} for name in selected["databases"]}
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(len(env),8)
        self.assertTrue(all(key.startswith("PG_CTF_LIFECYCLE_") for key in env))
        self.assertFalse(any(key in selected["environment"] for key in ("AI_PROVIDER","OLLAMA_BASE_URL","RUN_LIVE_CTF_WORKFLOW")))

    def test_existing_session_pair_environment_preserved(self):
        selected = MODULE.qualification_selection(MODULE.parse_args(self.required_args() + ["--session-fence-only"]), "abc")
        urls = {name: {"runtime": name + "R", "migration": name + "M"} for name in selected["databases"]}
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(set(env), {"IDENTITY_DATABASE_URL", "IDENTITY_MIGRATION_DATABASE_URL", "CTF_DATABASE_URL", "CTF_MIGRATION_DATABASE_URL"})
        self.assertEqual(env["CTF_DATABASE_URL"], selected["databases"][1] + "R")

    def test_projection_worker_exact_four_pairs_and_no_inference(self):
        argv = self.required_args() + ["--ctf-projection-worker"]
        selected = MODULE.qualification_selection(MODULE.parse_args(argv), "abc")
        self.assertEqual(selected["test"], "tests/postgres/ctfProjectionWorker.integration.test.js")
        self.assertEqual(selected["childSeconds"], 240)
        self.assertEqual((selected["workSeconds"], selected["cleanupSeconds"]), (420, 120))
        self.assertEqual(len(set(selected["databases"])), 4)
        urls = {name: {"runtime": name + "R", "migration": name + "M"} for name in selected["databases"]}
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(set(env), {f"PG_CTF_WORKER_{state}_{kind}_{role}_URL" for state in ("FRESH", "POPULATED") for kind in ("IDENTITY", "CTF") for role in ("RUNTIME", "MIGRATION")})
        self.assertFalse(any(key in selected["environment"] for key in ("AI_PROVIDER", "JUDGE_PROVIDER", "OLLAMA_BASE_URL", "RUN_LIVE_CTF_WORKFLOW")))
        for flags in (["--ctf-lifecycle-schema"], ["--authority-schema-only"], ["--target-stage", "8"], ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit): MODULE.parse_args(argv + flags)

    def test_decision_schema_four_isolated_pairs_no_inference(self):
        argv = self.required_args() + ["--ctf-decision-schema"]
        selected = MODULE.qualification_selection(MODULE.parse_args(argv), "abc")
        self.assertEqual(selected["test"], "tests/postgres/ctfAuthoritativeDecision.integration.test.js")
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (240, 420, 120))
        self.assertEqual(len(set(selected["databases"])), 4)
        urls = {name: {"runtime": name + "R", "migration": name + "M"} for name in selected["databases"]}
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(set(env), {f"PG_CTF_DECISION_{state}_{kind}_{role}_URL" for state in ("FRESH", "POPULATED") for kind in ("IDENTITY", "CTF") for role in ("RUNTIME", "MIGRATION")})
        self.assertFalse(any(key in selected["environment"] for key in ("AI_PROVIDER", "JUDGE_PROVIDER", "OLLAMA_BASE_URL", "RUN_LIVE_CTF_WORKFLOW")))
        for flags in (["--ctf-projection-worker"], ["--ctf-lifecycle-schema"], ["--authority-schema-only"], ["--target-stage", "8"], ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit): MODULE.parse_args(argv + flags)

    def test_decision_projection_four_isolated_pairs_no_inference(self):
        argv = self.required_args() + ["--ctf-decision-projection"]
        selected = MODULE.qualification_selection(MODULE.parse_args(argv), "abc")
        self.assertEqual(selected["test"], "tests/postgres/ctfDecisionProjection.integration.test.js")
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (240, 420, 120))
        self.assertEqual(len(set(selected["databases"])), 4)
        urls = {name: {"runtime": name + "R", "migration": name + "M"} for name in selected["databases"]}
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(set(env), {f"PG_CTF_DECISION_PROJECTION_{state}_{kind}_{role}_URL" for state in ("FRESH", "POPULATED") for kind in ("IDENTITY", "CTF") for role in ("RUNTIME", "MIGRATION")})
        self.assertFalse(any(key in selected["environment"] for key in ("AI_PROVIDER", "JUDGE_PROVIDER", "OLLAMA_BASE_URL", "RUN_LIVE_CTF_WORKFLOW")))
        for flags in (["--ctf-decision-schema"],["--ctf-projection-worker"], ["--ctf-lifecycle-schema"], ["--authority-schema-only"], ["--target-stage", "8"], ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit): MODULE.parse_args(argv + flags)

    def test_current_publication_four_isolated_pairs_no_inference(self):
        argv = self.required_args() + ["--ctf-current-publication"]
        selected = MODULE.qualification_selection(MODULE.parse_args(argv), "a" * 16)
        self.assertEqual(selected["test"], "tests/postgres/ctfCurrentPublication.integration.test.js")
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (240, 420, 120))
        self.assertEqual(len(set(selected["databases"])), 4)
        self.assertTrue(all(len(name.encode("utf8")) <= 63 for name in selected["databases"]))
        urls = {name: {"runtime": name + "R", "migration": name + "M"} for name in selected["databases"]}
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(set(env), {f"PG_CTF_CURRENT_PUBLICATION_{state}_{kind}_{role}_URL" for state in ("FRESH", "POPULATED") for kind in ("IDENTITY", "CTF") for role in ("RUNTIME", "MIGRATION")})
        self.assertFalse(any(key in selected["environment"] for key in ("AI_PROVIDER", "JUDGE_PROVIDER", "OLLAMA_BASE_URL", "RUN_LIVE_CTF_WORKFLOW")))
        for flags in (["--ctf-decision-recovery"],["--ctf-decision-projection"],["--ctf-decision-schema"],["--ctf-projection-worker"], ["--ctf-lifecycle-schema"], ["--authority-schema-only"], ["--target-stage", "8"], ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit): MODULE.parse_args(argv + flags)

    def test_current_0155_publication_is_distinct_repository_only_four_store_cohort(self):
        args = self.required_args() + ["--ctf-publication-current",
            "--image-id", "sha256:" + "a" * 64,
            "--content-source-manifest-sha256", "b" * 64,
            "--docker-daemon-id", "owned-daemon"]
        parsed = MODULE.parse_args(args)
        self.assertTrue(MODULE.main_no_copy_selection(parsed))
        selected = MODULE.qualification_selection(parsed, "a1b2c3d4e5f6")
        self.assertEqual(selected["mode"], "ctf_publication_current_controlled")
        self.assertEqual(selected["test"], "tests/postgres/ctfAuthenticatedPublicationCurrent.integration.test.js")
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (300, 480, 120))
        self.assertEqual(selected["environment"], {"CTF_PUBLICATION_CURRENT_NATIVE": "1", "AWS_EC2_METADATA_DISABLED": "true"})
        self.assertEqual(selected["databases"], tuple(
            f"owasp_ai_goat_test_ctf_publication_current_{state}_{kind}_a1b2c3d4e5f6"
            for state in ("f", "p") for kind in ("i", "c")))
        self.assertTrue(all(len(name.encode()) <= 63 for name in selected["databases"]))
        self.assertEqual(MODULE.delivery_role(selected), "dvaia_ctf_delivery")
        urls = {name: {role: f"{name}-{role}" for role in ("runtime", "migration", "delivery")}
            for name in selected["databases"]}
        env = MODULE.database_environment(selected, urls)
        expected = {f"PG_CTF_PUBLICATION_CURRENT_{state}_{kind}_{role}_URL"
            for state in ("FRESH", "POPULATED") for kind in ("IDENTITY", "CTF")
            for role in ("RUNTIME", "MIGRATION")}
        expected |= {f"PG_CTF_PUBLICATION_CURRENT_{state}_CTF_DELIVERY_URL"
            for state in ("FRESH", "POPULATED")}
        self.assertEqual(set(env), expected)
        self.assertEqual(len(set(env.values())), 10)
        self.assertEqual(MODULE.qualification_selection(MODULE.parse_args(self.required_args() +
            ["--ctf-current-publication"]), "a1b2c3d4e5f6")["test"],
            "tests/postgres/ctfCurrentPublication.integration.test.js")
        for extra in (["--ctf-current-publication"], ["--ctf-production-runtime"],
                ["--browser-executable", "/owned/browser"], ["--client-build-sha256", "c" * 64],
                ["--candidate-set", "reviewer-boundary-v1"], ["--target-stage", "8"]):
            with self.subTest(extra=extra), self.assertRaises(SystemExit): MODULE.parse_args(args + extra)
        for omitted in ("--image-id", "--content-source-manifest-sha256", "--docker-daemon-id"):
            cut = args[:]
            index = cut.index(omitted)
            del cut[index:index + 2]
            with self.subTest(omitted=omitted), self.assertRaises(SystemExit): MODULE.parse_args(cut)
        with patch.object(MODULE, "run_qualification", side_effect=AssertionError("allocation forbidden")):
            self.assertEqual(MODULE.main(args), 0)

    def test_current_0155_source_pins_are_exact_and_preallocation(self):
        root = RUNNER.parents[2]
        self.assertIsNone(MODULE.assert_current_publication_source(root))
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory)
            for relative in MODULE.CURRENT_PUBLICATION_SOURCE_PINS:
                target = fake / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((root / relative).read_bytes())
            self.assertIsNone(MODULE.assert_current_publication_source(fake))
            fixture = fake / "tests/postgres/ctfAuthenticatedPublicationCurrent.integration.test.js"
            fixture.write_bytes(fixture.read_bytes() + b"\n// drift\n")
            with self.assertRaisesRegex(RuntimeError, "source pin mismatch"):
                MODULE.assert_current_publication_source(fake)
            fixture.unlink()
            fixture.symlink_to(root / "tests/postgres/ctfAuthenticatedPublicationCurrent.integration.test.js")
            with self.assertRaisesRegex(RuntimeError, "source pin mismatch"):
                MODULE.assert_current_publication_source(fake)

    def test_decision_recovery_four_isolated_pairs_no_inference(self):
        argv = self.required_args() + ["--ctf-decision-recovery"]
        selected = MODULE.qualification_selection(MODULE.parse_args(argv), "abc")
        self.assertEqual(selected["test"], "tests/postgres/ctfDecisionRecovery.integration.test.js")
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (240, 420, 120))
        self.assertEqual(len(set(selected["databases"])), 4)
        urls = {name: {"runtime": name + "R", "migration": name + "M"} for name in selected["databases"]}
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(set(env), {f"PG_CTF_DECISION_RECOVERY_{state}_{kind}_{role}_URL" for state in ("FRESH", "POPULATED") for kind in ("IDENTITY", "CTF") for role in ("RUNTIME", "MIGRATION")})
        self.assertFalse(any(key in selected["environment"] for key in ("AI_PROVIDER", "JUDGE_PROVIDER", "OLLAMA_BASE_URL", "RUN_LIVE_CTF_WORKFLOW")))
        for flags in (["--ctf-decision-projection"],["--ctf-decision-schema"],["--ctf-projection-worker"], ["--ctf-lifecycle-schema"], ["--authority-schema-only"], ["--target-stage", "8"], ["--candidate-set", "reviewer-boundary-v1"]):
            with self.assertRaises(SystemExit): MODULE.parse_args(argv + flags)

    def test_generated_database_names_preserve_nonce_without_postgres_truncation(self):
        nonce = "a1b2c3d4e5f6"  # Exact production UUID prefix length.
        for flag in ("--ctf-decision-projection", "--ctf-decision-recovery", "--ctf-decision-schema", "--ctf-projection-worker", "--ctf-lifecycle-schema", "--authority-schema-only", "--session-fence-only"):
            selection = MODULE.qualification_selection(MODULE.parse_args(self.required_args() + [flag]), nonce)
            names = selection["databases"]
            self.assertEqual(len(set(names)), len(names))
            for name in names:
                self.assertLessEqual(len(name.encode("utf-8")), 63, (flag, name))
                self.assertTrue(name.endswith("_" + nonce))
            urls = {name: {"runtime": name + "R", "migration": name + "M"} for name in names}
            env = MODULE.database_environment(selection, urls)
            self.assertEqual(set(env.values()), {value for pair in urls.values() for value in pair.values()})

    def test_default_is_a_nonmutating_plan(self):
        output = io.StringIO()
        with redirect_stdout(output):
            result = MODULE.main(self.required_args())
        self.assertEqual(result, 0)
        self.assertIn("plan: no workspace", output.getvalue())

    def test_target_stage_is_closed_and_mutually_exclusive(self):
        for stage in range(6, 11):
            with self.subTest(stage=stage):
                args = MODULE.parse_args(self.required_args() + ["--target-stage", str(stage)])
                self.assertEqual(args.target_stage, stage)
                self.assertIsNone(args.stage_end)
        for invalid in (5, 11):
            with self.subTest(invalid=invalid), self.assertRaises(SystemExit):
                MODULE.parse_args(self.required_args() + ["--target-stage", str(invalid)])
        with self.assertRaises(SystemExit):
            MODULE.parse_args(self.required_args() +
                ["--target-stage", "7", "--stage-end", "7"])

    def test_research_candidates_require_an_explicit_closed_selection(self):
        args = MODULE.parse_args(self.required_args())
        self.assertEqual(args.candidate_set, "instructor")
        args = MODULE.parse_args(self.required_args() +
            ["--target-stage", "6", "--candidate-set", "reviewer-boundary-v1"])
        self.assertEqual(args.candidate_set, "reviewer-boundary-v1")
        with self.assertRaises(SystemExit):
            MODULE.parse_args(self.required_args() + ["--candidate-set", "../unreviewed"])

    def test_executable_pin_rejects_mismatch_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "node"
            binary.write_bytes(b"owned")
            expected = MODULE.hashlib.sha256(b"owned").hexdigest()
            self.assertEqual(MODULE.validate_executable(binary, expected, "Node"), binary.resolve())
            with self.assertRaisesRegex(RuntimeError, "pin mismatch"):
                MODULE.validate_executable(binary, "0" * 64, "Node")
            link = Path(directory) / "node-link"
            link.symlink_to(binary)
            with self.assertRaisesRegex(RuntimeError, "pin mismatch"):
                MODULE.validate_executable(link, expected, "Node")

    def test_stop_group_checks_descendants_after_leader_exit(self):
        states = iter([True, True, False, False, False])
        signals = []
        identities = []
        child = FakeChild(returncode=1)
        result = MODULE.stop_group(child, group_exists=lambda _pgid, env=None: next(states),
            check_identity=lambda pgid, sid, uid, env=None, birth=None: identities.append((pgid, sid, uid, birth)),
            killpg=lambda pgid, sig: signals.append((pgid, sig)),
            monotonic=lambda: 0, sleep=lambda _seconds: None)
        self.assertEqual(result, 1)
        self.assertEqual(signals, [(43210, MODULE.signal.SIGTERM)])
        self.assertEqual(identities, [(43210, 43210, 501, (123, 456))])

    def test_stop_group_rejects_foreign_owner_before_signaling(self):
        signals = []
        sessions = []
        probes = []
        def runner(command, **kwargs):
            probes.append(command)
            return SimpleNamespace(returncode=0, stdout="43211 43210 502\n")
        def check(pgid, sid, uid, env=None, birth=None):
            return MODULE.assert_group_identity(pgid, sid, uid, env=env,
                runner=runner, getsid=lambda pid: sessions.append(pid) or sid, birth=birth)
        with self.assertRaisesRegex(RuntimeError, "foreign process owner"):
            MODULE.stop_group(FakeChild(), group_exists=lambda _pgid, env=None: True,
                check_identity=check, killpg=lambda *args: signals.append(args))
        self.assertEqual(probes, [["ps", "-axo", "pid=,pgid=,uid="]])
        self.assertEqual(signals, [])
        self.assertEqual(sessions, [])

    @unittest.skipUnless(sys.platform == "darwin", "Darwin current-host process inspection")
    def test_current_host_group_probe_uses_fail_closed_libproc_not_ps(self):
        from unittest.mock import patch
        with patch.object(MODULE, "native_owned_group_members", return_value=[43210]) as inspector:
            self.assertTrue(MODULE.process_group_exists(43210))
            with patch.object(MODULE, "native_leader_birth", return_value=(123, 456)):
                MODULE.assert_group_identity(43210, 43210, os.getuid(), birth=(123, 456))
            self.assertEqual(inspector.call_count, 2)
        with patch.object(MODULE, "native_owned_group_members", return_value=[]) as inspector:
            self.assertFalse(MODULE.process_group_exists(43210))
            with self.assertRaisesRegex(RuntimeError, "foreign process session"):
                MODULE.assert_group_identity(43210, 43211, os.getuid(), birth=(123, 456))
            self.assertEqual(inspector.call_count, 1)
        with patch.object(MODULE, "native_owned_group_members", side_effect=RuntimeError("foreign birth")):
            with self.assertRaisesRegex(RuntimeError, "foreign birth"):
                MODULE.process_group_exists(43210)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin current-host process inspection")
    def test_group_signal_requires_original_launch_birth_even_after_poll(self):
        from unittest.mock import patch
        child = FakeChild(returncode=0)
        child._owned_birth = None
        with patch.object(MODULE.os, "killpg") as signals:
            with self.assertRaisesRegex(RuntimeError, "launch birth"):
                MODULE.stop_group(child)
        signals.assert_not_called()
        child._owned_birth = (123, 456)
        with patch.object(MODULE, "native_owned_group_members", return_value=[child.pid]), \
                patch.object(MODULE, "native_leader_birth", return_value=(123, 457)), \
                patch.object(MODULE.os, "killpg") as signals:
            with self.assertRaisesRegex(RuntimeError, "birth changed"):
                MODULE.stop_group(child)
        signals.assert_not_called()
        with patch.object(MODULE, "native_owned_group_members", return_value=[child.pid]), \
                patch.object(MODULE, "native_leader_birth", side_effect=RuntimeError("leader missing")), \
                patch.object(MODULE.os, "killpg") as signals:
            with self.assertRaisesRegex(RuntimeError, "leader missing"):
                MODULE.stop_group(child)
        signals.assert_not_called()

    @unittest.skipUnless(sys.platform == "darwin", "Darwin current-host process inspection")
    def test_live_owned_group_is_inspectable_inside_repository_wrapper(self):
        child = subprocess.Popen([sys.executable, "-B", "-c", "import sys; sys.stdin.read()"],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        child._owned_sid = child.pid
        child._owned_uid = os.getuid()
        try:
            birth = MODULE.capture_launch_birth(child)
            self.assertEqual(len(birth), 2)
            self.assertIn(child.pid, MODULE.native_owned_group_members(child.pid))
            self.assertTrue(MODULE.process_group_exists(child.pid))
            MODULE.assert_group_identity(child.pid, child.pid, os.getuid(), birth=birth)
        finally:
            child.stdin.close()
            child.wait(timeout=5)
        self.assertFalse(MODULE.process_group_exists(child.pid))

    def test_operation_recovery_closed_selector(self):
        args = MODULE.parse_args(self.required_args() + ["--ctf-operation-recovery"])
        selected = MODULE.qualification_selection(args, "a" * 12)
        self.assertEqual(selected["mode"], "ctf_operation_recovery_controlled")
        self.assertEqual(selected["test"], "tests/postgres/ctfOperationRecovery.integration.test.js")
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (240, 420, 120))
        self.assertEqual(selected["environment"], {"CTF_OPERATION_RECOVERY_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"})
        self.assertEqual(selected["databases"], tuple(
            f"owasp_ai_goat_test_ctf_opread_{state[0]}_{kind[0]}_{'a' * 12}"
            for state in ("fresh", "populated") for kind in ("identity", "ctf")))
        urls = {name: {role: name + role for role in ("runtime", "migration")}
            for name in selected["databases"]}
        expected = {f"PG_CTF_OPERATION_RECOVERY_{state}_{kind}_{role.upper()}_URL": urls[name][role]
            for name, (state, kind) in zip(selected["databases"],
                (("FRESH", "IDENTITY"), ("FRESH", "CTF"), ("POPULATED", "IDENTITY"), ("POPULATED", "CTF")))
            for role in ("runtime", "migration")}
        self.assertEqual(MODULE.database_environment(selected, urls), expected)

        for flags in (["--ctf-current-publication"], ["--ctf-decision-recovery"], ["--ctf-decision-projection"],
                      ["--ctf-decision-schema"], ["--ctf-projection-worker"], ["--ctf-lifecycle-schema"],
                      ["--authority-schema-only"], ["--target-stage", "8"], ["--candidate-set", "reviewer-boundary-v1"]):
            with self.subTest(flags=flags), self.assertRaises(SystemExit):
                MODULE.parse_args(self.required_args() + ["--ctf-operation-recovery"] + flags)

    def test_container_cleanup_attempts_absence_after_remove_failure(self):
        calls = []
        def runner(command, **_kwargs):
            calls.append(command)
            if "inspect" in command:
                return SimpleNamespace(returncode=0, stdout='[{"Id":"' + "a" * 64 + '","Name":"/one","Config":{"Image":"sha256:a","Labels":{"' + MODULE.CONTAINER_OWNER_LABEL + '":"' + MODULE.CONTAINER_OWNER_LABEL + '","' + MODULE.CONTAINER_NONCE_LABEL + '":"one-nonce"}}}]', stderr="")
            if "rm" in command and command[-1] == "a" * 64:
                return SimpleNamespace(returncode=2, stdout="", stderr="failed")
            if "ps" in command:
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        rows, errors = MODULE.cleanup_containers([
            {"name": "one", "nonce": "one-nonce", "owner": MODULE.CONTAINER_OWNER_LABEL, "image": "sha256:a", "containerId": "a" * 64},
            {"name": "two", "nonce": "two-nonce", "owner": MODULE.CONTAINER_OWNER_LABEL, "image": "sha256:a", "containerId": "b" * 64},
        ], ["docker", "--host", "owned"], {}, runner=runner)
        self.assertEqual(len(errors), 2)
        self.assertEqual({row["name"] for row in rows}, {"one", "two"})
        self.assertTrue(all(row["cleanup"] == "absent_verified" for row in rows))
        self.assertEqual(sum("ps" in command for command in calls), 2)

    def test_container_diagnostics_are_explicitly_omitted(self):
        calls = []
        def runner(command, **kwargs):
            calls.append(command)
            if "inspect" in command:
                return SimpleNamespace(returncode=0, stdout='[{"Id":"' + "a" * 64 + '","Name":"/owned","Config":{"Image":"sha256:a","Labels":{"' + MODULE.CONTAINER_OWNER_LABEL + '":"' + MODULE.CONTAINER_OWNER_LABEL + '","' + MODULE.CONTAINER_NONCE_LABEL + '":"abc123"}}}]', stderr="")
            if "ps" in command:
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as directory:
            rows, errors = MODULE.cleanup_containers([{
                "name": "owned", "nonce": "abc123", "owner": MODULE.CONTAINER_OWNER_LABEL, "containerId": "a" * 64, "image": "sha256:a",
                "creationAttempted": True,
            }], ["docker", "--host", "owned"], {}, Path(directory), runner=runner)
            self.assertFalse(errors)
            self.assertEqual(rows[0]["privateLog"]["status"], "omitted")
            self.assertFalse(any("logs" in command for command in calls))

    def test_cleanup_rejects_foreign_identity_before_remove(self):
        calls = []
        def runner(command, **_kwargs):
            calls.append(command)
            if "inspect" in command:
                return SimpleNamespace(returncode=0, stdout='[{"Id":"' + "a" * 64 + '","Name":"/owned","Config":{"Image":"sha256:a","Labels":{"' + MODULE.CONTAINER_OWNER_LABEL + '":"foreign","' + MODULE.CONTAINER_NONCE_LABEL + '":"nonce"}}}]', stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        rows, errors = MODULE.cleanup_containers([{"name":"owned","nonce":"nonce","owner":MODULE.CONTAINER_OWNER_LABEL,"image":"sha256:a","containerId":"a"*64,"creationAttempted":True}], ["docker"], {}, runner=runner)
        self.assertEqual(len(errors), 1)
        self.assertFalse(any("rm" in command for command in calls))

    def test_cleanup_fails_closed_on_absence_probe_error(self):
        def runner(command, **_kwargs):
            if "inspect" in command:
                return SimpleNamespace(returncode=0, stdout='[{"Id":"' + "a" * 64 + '","Name":"/owned","Config":{"Image":"sha256:a","Labels":{"' + MODULE.CONTAINER_OWNER_LABEL + '":"' + MODULE.CONTAINER_OWNER_LABEL + '","' + MODULE.CONTAINER_NONCE_LABEL + '":"nonce"}}}]', stderr="")
            if "ps" in command:
                return SimpleNamespace(returncode=2, stdout="", stderr="probe failed")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        rows, errors = MODULE.cleanup_containers([{"name":"owned","nonce":"nonce","owner":MODULE.CONTAINER_OWNER_LABEL,"image":"sha256:a","containerId":"a"*64}], ["docker"], {}, runner=runner)
        self.assertEqual(rows[0]["cleanup"], "failed")
        self.assertTrue(errors)

    def test_partial_create_discovers_and_removes_exact_owned_id(self):
        calls = []
        def runner(command, **_kwargs):
            calls.append(command)
            if "inspect" in command:
                return SimpleNamespace(returncode=0, stdout='[{"Id":"' + "c" * 64 + '","Name":"/partial","Config":{"Image":"sha256:a","Labels":{"' + MODULE.CONTAINER_OWNER_LABEL + '":"' + MODULE.CONTAINER_OWNER_LABEL + '","' + MODULE.CONTAINER_NONCE_LABEL + '":"partial-nonce"}}}]', stderr="")
            if "ps" in command:
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        rows, errors = MODULE.cleanup_containers([{
            "name":"partial", "nonce":"partial-nonce", "owner":MODULE.CONTAINER_OWNER_LABEL,
            "image":"sha256:a", "creationAttempted":True,
        }], ["docker"], {}, runner=runner)
        self.assertFalse(errors)
        self.assertEqual(rows[0]["cleanup"], "absent_verified")
        self.assertIn("c" * 64, calls[-2])

    def test_cleanup_rejects_remaining_id_or_reused_name(self):
        for remaining in [("a" * 64) + "\towned", ("a" * 64) + "\trenamed", ("b" * 64) + "\towned"]:
            with self.subTest(remaining=remaining):
                def runner(command, **_kwargs):
                    if "inspect" in command:
                        payload = [{"Id": "a" * 64, "Name": "/owned", "Config": {"Image": "sha256:a", "Labels": {MODULE.CONTAINER_OWNER_LABEL: MODULE.CONTAINER_OWNER_LABEL, MODULE.CONTAINER_NONCE_LABEL: "nonce"}}}]
                        return SimpleNamespace(returncode=0, stdout=MODULE.json.dumps(payload), stderr="")
                    return SimpleNamespace(returncode=0, stdout=remaining if "ps" in command else "", stderr="")
                rows, errors = MODULE.cleanup_containers([{"name":"owned", "nonce":"nonce", "owner":MODULE.CONTAINER_OWNER_LABEL, "image":"sha256:a", "containerId":"a"*64}], ["docker"], {}, runner=runner)
                self.assertEqual(rows[0]["cleanup"], "failed")
                self.assertTrue(errors)

    def test_process_receipt_does_not_require_container_intent(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "cleanup.json"
            with patch.object(MODULE, "stop_group", return_value=0):
                errors = MODULE.finalize_owned([FakeChild(0)], [], [], ["docker"], {}, receipt)
            self.assertFalse(errors)
            rows = MODULE.json.loads(receipt.read_text())["processes"]
            self.assertEqual(rows[0]["cleanup"], "absent_verified")
            self.assertEqual(rows[0]["pid"], 43210)

    def test_stream_child_output_rejects_oversized_stream(self):
        child = subprocess.Popen([sys.executable, "-c", "import sys; sys.stdout.write('x' * 20)"], stdout=subprocess.PIPE)
        with tempfile.TemporaryDirectory() as directory:
            try:
                with self.assertRaisesRegex(RuntimeError, "size limit"):
                    MODULE.stream_child_output(child, Path(directory) / "tap", deadline=MODULE.time.monotonic() + 5, max_bytes=8)
            finally:
                child.kill()
                child.wait()

    def test_child_completion_retains_real_exit_and_durable_output(self):
        for exit_code in (0, 7):
            with self.subTest(exit_code=exit_code), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "result.tap"
                child = subprocess.Popen([sys.executable, "-c",
                    f"import sys; print('owned test result'); sys.exit({exit_code})"], stdout=subprocess.PIPE)
                code, size = MODULE.stream_child_output(child, path,
                    deadline=MODULE.time.monotonic() + 5)
                state = {}
                if exit_code:
                    with self.assertRaisesRegex(RuntimeError, r"integration failed \(7\)"):
                        MODULE.record_child_result(state, path, code, size)
                else:
                    MODULE.record_child_result(state, path, code, size)
                self.assertEqual(state["result"]["returncode"], exit_code)
                self.assertEqual(state["result"]["bytes"], len(path.read_bytes()))
                self.assertEqual(state["result"]["sha256"], MODULE.sha256(path))

    def test_private_receipts_and_logs_are_owner_only(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "receipt.json"
            log = Path(directory) / "result.tap"
            MODULE.write_private_json(receipt, {"ok": True})
            handle = MODULE.open_private_log(log)
            handle.write("bounded\n")
            handle.close()
            self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)

    def test_frozen_copy_excludes_application_data_and_matches_source(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            workspace = Path(directory) / "copy"
            workspace.mkdir()
            for name in MODULE.SOURCE_DIRECTORIES:
                (source / name).mkdir(parents=True)
                (source / name / "kept.js").write_text(f"{name}\n")
            for name in MODULE.SOURCE_FILES:
                (source / name).write_text(f"{name}\n")
            (source / "server" / ".env").write_text("SECRET=x")
            (source / "server" / "logs").mkdir()
            (source / "server" / "logs" / "private.log").write_text("private")
            (source / "node_modules").mkdir()
            expected = MODULE.manifest_digest(MODULE.inventory(source))
            result = MODULE.copy_frozen_source(source, workspace, expected)
            self.assertEqual(result["count"],
                len(MODULE.SOURCE_DIRECTORIES) + len(MODULE.SOURCE_FILES))
            self.assertFalse((workspace / "server" / ".env").exists())
            self.assertFalse((workspace / "server" / "logs").exists())
            self.assertTrue((workspace / "node_modules").is_symlink())
            for path in workspace.rglob("*"):
                if not path.is_symlink():
                    os.chmod(path, 0o700 if path.is_dir() else 0o600)
            os.chmod(workspace, 0o700)

    def test_source_and_dependency_manifests_are_exact_pins(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dependencies = root / "node_modules"
            dependencies.mkdir()
            (dependencies / "package.js").write_text("module.exports = 1\n")
            expected = MODULE.manifest_digest(MODULE.dependency_inventory(dependencies))
            self.assertEqual(
                MODULE.verified_dependency_snapshot(dependencies, expected)["count"], 1)
            (dependencies / "package.js").write_text("module.exports = 2\n")
            with self.assertRaisesRegex(RuntimeError, "Dependency manifest pin mismatch"):
                MODULE.verified_dependency_snapshot(dependencies, expected)

    def test_source_copy_rejects_an_unreviewed_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            workspace = Path(directory) / "copy"
            workspace.mkdir()
            for name in MODULE.SOURCE_DIRECTORIES:
                (source / name).mkdir(parents=True)
            for name in MODULE.SOURCE_FILES:
                (source / name).write_text(f"{name}\n")
            with self.assertRaisesRegex(RuntimeError, "Source manifest pin mismatch"):
                MODULE.copy_frozen_source(source, workspace, "0" * 64)

    def test_log_limit_and_image_are_fixed_constants(self):
        self.assertEqual(MODULE.MAX_LOG_BYTES, 16 * 1024 * 1024)
        self.assertRegex(MODULE.POSTGRES_IMAGE_ID, r"^sha256:[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
