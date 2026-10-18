import importlib.util
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace


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
        self._owned_name = "ctf_stages_route_test"

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode


class CtfStagesRouteLauncherTests(unittest.TestCase):
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
        argv = self.required_args() + ["--ctf-ten-content", "--browser-executable", "/owned/chrome",
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
        for missing in (("--client-build-sha256",), ("--browser-executable", "/owned/chrome", "--browser-sha256", "a" * 64, "--client-source-sha256", "b" * 64, "--client-dependency-sha256", "c" * 64)):
            with self.assertRaises(SystemExit):
                MODULE.parse_args(self.required_args() + ["--ctf-ten-content", *missing])

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
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("dvaia_test_ctf_blockpub_") for n in selected["databases"]))
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
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("dvaia_test_ctf_app_") for n in selected["databases"]))
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
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("dvaia_test_ctf_app_") for n in selected["databases"]))
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
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("dvaia_test_ctf_prod_") for n in selected["databases"]))
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
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("dvaia_test_ctf_runtime_") for n in selected["databases"]))
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
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("dvaia_test_ctf_telemetry_") for n in selected["databases"]))
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
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("dvaia_test_ctf_activation_") for n in selected["databases"]))
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
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("dvaia_test_ctf_locator_") for n in selected["databases"]))
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
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("dvaia_test_ctf_diagnostics_") for n in selected["databases"]))
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
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("dvaia_test_ctf_adminread_") for n in selected["databases"]))
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
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("dvaia_test_ctf_blockpre_") for n in selected["databases"]))
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
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("dvaia_test_ctf_worklife_") for n in selected["databases"]))
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
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("dvaia_test_ctf_predef_") for n in selected["databases"]))
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
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("dvaia_test_ctf_delete_") for n in selected["databases"]))
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
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("dvaia_test_ctf_opread_") for n in selected["databases"]))
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
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("dvaia_test_ctf_read_") for n in selected["databases"]))
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
        self.assertTrue(all(len(n.encode()) <= 63 and n.startswith("dvaia_test_ctf_opread_") for n in selected["databases"]))
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
        self.assertEqual(selected["databases"], ("dvaia_test_ctf_session_identity_abc123",
                                                 "dvaia_test_ctf_session_store_abc123"))
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
        expected = tuple(f"dvaia_test_ctf_authority_{state}_{kind}_abc123"
            for state in ("fresh", "populated") for kind in ("identity", "ctf"))
        self.assertEqual(selected["databases"], expected)
        urls = {name: {role: name + ":" + role for role in ("runtime", "migration")} for name in expected}
        env = MODULE.database_environment(selected, urls)
        self.assertEqual(len(env), 8)
        for state in ("FRESH", "POPULATED"):
            for kind in ("IDENTITY", "CTF"):
                for role in ("RUNTIME", "MIGRATION"):
                    key = f"PG_CTF_AUTHORITY_{state}_{kind}_{role}_URL"
                    self.assertEqual(env[key], f"dvaia_test_ctf_authority_{state.lower()}_{kind.lower()}_abc123:{role.lower()}")
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
            check_identity=lambda pgid, sid, uid, env=None: identities.append((pgid, sid, uid)),
            killpg=lambda pgid, sig: signals.append((pgid, sig)),
            monotonic=lambda: 0, sleep=lambda _seconds: None)
        self.assertEqual(result, 1)
        self.assertEqual(signals, [(43210, MODULE.signal.SIGTERM)])
        self.assertEqual(identities, [(43210, 43210, 501)])

    def test_stop_group_rejects_foreign_owner_before_signaling(self):
        signals = []
        sessions = []
        probes = []
        def runner(command, **kwargs):
            probes.append(command)
            return SimpleNamespace(returncode=0, stdout="43211 43210 502\n")
        def check(pgid, sid, uid, env=None):
            return MODULE.assert_group_identity(pgid, sid, uid, env=env,
                runner=runner, getsid=lambda pid: sessions.append(pid) or sid)
        with self.assertRaisesRegex(RuntimeError, "foreign process owner"):
            MODULE.stop_group(FakeChild(), group_exists=lambda _pgid, env=None: True,
                check_identity=check, killpg=lambda *args: signals.append(args))
        self.assertEqual(probes, [["ps", "-axo", "pid=,pgid=,uid="]])
        self.assertEqual(signals, [])
        self.assertEqual(sessions, [])

    def test_operation_recovery_closed_selector(self):
        args = MODULE.parse_args(self.required_args() + ["--ctf-operation-recovery"])
        selected = MODULE.qualification_selection(args, "a" * 12)
        self.assertEqual(selected["mode"], "ctf_operation_recovery_controlled")
        self.assertEqual(selected["test"], "tests/postgres/ctfOperationRecovery.integration.test.js")
        self.assertEqual((selected["childSeconds"], selected["workSeconds"], selected["cleanupSeconds"]), (240, 420, 120))
        self.assertEqual(selected["environment"], {"CTF_OPERATION_RECOVERY_ISOLATED": "1", "AWS_EC2_METADATA_DISABLED": "true"})
        self.assertEqual(selected["databases"], tuple(
            f"dvaia_test_ctf_opread_{state[0]}_{kind[0]}_{'a' * 12}"
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
