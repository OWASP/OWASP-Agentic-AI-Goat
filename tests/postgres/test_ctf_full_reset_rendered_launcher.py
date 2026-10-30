"""Offline admission controls for the separate rendered Full CTF Reset cohort."""

import copy
from contextlib import redirect_stderr
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = Path(__file__).with_name("run-ctf-stages-route-isolated.py")
SPEC = importlib.util.spec_from_file_location("ctf_full_reset_launcher", LAUNCHER)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)
PIN = "a" * 64
IMAGE = "sha256:" + PIN


def selected_args(*extra):
    return ["--docker-host", "unix:///owned/docker.sock", "--docker-cli", "/owned/docker",
        "--docker-cli-sha256", PIN, "--image-id", IMAGE, "--node", "/owned/node",
        "--node-sha256", PIN, "--source-manifest-sha256", PIN,
        "--dependency-manifest-sha256", PIN, "--browser-executable", "/owned/browser",
        "--browser-sha256", PIN, "--client-source-sha256", PIN,
        "--client-dependency-sha256", PIN, "--client-build-sha256", PIN,
        "--client-build-output-sha256", PIN, "--client-build-report", "/owned/build.json",
        "--client-build-report-sha256", PIN, "--client-build-input-sha256", PIN,
        "--client-build-recorder-sha256", PIN, "--content-source-manifest-sha256", PIN,
        "--docker-daemon-id", PIN, "--ctf-full-reset-rendered", *extra]


def complete_receipt():
    cleared = ("ctf_attempts", "ctf_progress", "ctf_technique_blocklist", "ctf_leaderboard",
        "ctf_events", "ctf_sessions", "ctf_payload_blocklist", "ctf_participants")
    retained = ("ctf_stages", "ctf_config", "ctf_stage_teaching_content", "ctf_bans",
        "ctf_judgments")
    facts = ("wrongTokenNoPost", "cancelNoPost", "cancelNoEffect", "dialogAbaNoPost",
        "dialogAbaNoEffect", "onePhysicalPost", "capturedAuthorityAndBody",
        "canonicalOperationApplied", "removedCountMatches", "mutableCtfCleared",
        "mutableIdentityMemoryCleared", "retainedCtfUnchanged",
        "historicalIdentityEvidencePreserved", "platformAndWorkshopSiblingPreserved",
        "unknownUiNoReference", "noAutomaticRetry")
    return {"version": 2, "profile": "ctf-full-reset-q05", "modelCalls": 0,
        "judgeCalls": 0, "actorId": "3011", "sessionId": "2001",
        "path": "/api/ctf/admin/reset", "dialogAbaEventsObserved": 2,
        "requestCounts": {"wrongToken": 0, "cancel": 0, "dialogAba": 0,
            "browserPost": 1, "serverPost": 1, "browserFailed": 1,
            "browserFinished": 0, "serverFinished": 1},
        "responseStage": {"paused": 1, "failed": 1, "continued": 0},
        "serverResponse": {"status": 200, "body": {"message": "CTF reset successfully"},
            "lossPhase": "after-real-http-response-before-browser-consumption"},
        "operation": {"operationId": "00000000-0000-4000-8000-000000000001",
            "sequence": "1", "removedParticipants": 2, "sameIdHarnessGets": 0},
        "pre": {"clearedRows": {table: 2 if table == "ctf_participants" else 1
                for table in cleared}, "retainedRows": {table: 1 for table in retained},
            "immutableBootstrapRows": {table: 1 for table in ("sessions", "pages", "imports")},
            "mutableIdentityMemoryRows": {"technique": 1, "payload": 1}},
        "facts": {fact: True for fact in facts},
        "excluded": ["browser-acknowledged-success", "browser-operation-id-recovery",
            "ctf-sibling-preservation", "ban-deletion", "judgment-deletion",
            "immutable-evidence-deletion", "model-grading", "full-Q05-denominator"],
        "unexpectedApiPaths": [], "stage": "complete"}


class FullResetLauncherControls(unittest.TestCase):
    def test_stop_and_browser_roster_must_be_verified_before_pg_retirement(self):
        class Child:
            pid = 3011
            _owned_name = "ctf_stages_route_test"
            _owned_pgid = 3011
            _owned_sid = 3011
            _owned_uid = os.getuid()
            _owned_birth = (1, 2)

            @staticmethod
            def poll():
                return None

        intent = {"name": "owasp-ai-goat-ctf-stages-owned", "nonce": "b" * 12,
            "owner": RUNNER.CONTAINER_OWNER_LABEL, "image": IMAGE,
            "creationAttempted": True, "containerId": "c" * 64}
        with tempfile.TemporaryDirectory(prefix="full-reset-cleanup-", dir=ROOT / "tasks/tmp") as name:
            path = Path(name) / "cleanup.json"
            with mock.patch.object(RUNNER, "stop_group", side_effect=RuntimeError("unverified stop")), \
                    mock.patch.object(RUNNER, "cleanup_containers") as cleanup:
                errors = RUNNER.finalize_owned([Child()], [], [intent], [], {}, path,
                    require_quiescent_before_container_cleanup=True,
                    quiescence_check=lambda: self.fail("roster must not run after failed stop"))
                self.assertEqual(len(errors), 1)
                cleanup.assert_not_called()
                row = json.loads(path.read_text(encoding="utf-8"))["containers"][0]
                self.assertEqual(row["cleanup"], "retained_quiescence_unverified")
                self.assertEqual(row["containerId"], intent["containerId"])
            with mock.patch.object(RUNNER, "stop_group", return_value=1), \
                    mock.patch.object(RUNNER, "cleanup_containers") as cleanup:
                errors = RUNNER.finalize_owned([Child()], [], [intent], [], {}, path,
                    require_quiescent_before_container_cleanup=True,
                    quiescence_check=lambda: (_ for _ in ()).throw(RuntimeError("browser remains")))
                self.assertEqual(len(errors), 1)
                cleanup.assert_not_called()
                self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["containers"][0]
                    ["cleanup"], "retained_quiescence_unverified")
            with mock.patch.object(RUNNER, "stop_group", return_value=1), \
                    mock.patch.object(RUNNER, "cleanup_containers", return_value=(
                        [dict(intent, cleanup="absent_verified")], [])) as cleanup:
                errors = RUNNER.finalize_owned([Child()], [], [intent], [], {}, path,
                    require_quiescent_before_container_cleanup=True,
                    quiescence_check=lambda: None)
                self.assertEqual(errors, [])
                cleanup.assert_called_once()
                self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["containers"][0]
                    ["cleanup"], "absent_verified")
            with mock.patch.object(RUNNER, "stop_group", side_effect=RuntimeError("old lane stop")), \
                    mock.patch.object(RUNNER, "cleanup_containers", return_value=(
                        [dict(intent, cleanup="absent_verified")], [])) as cleanup:
                errors = RUNNER.finalize_owned([Child()], [], [intent], [], {}, path)
                self.assertEqual(len(errors), 1)
                cleanup.assert_called_once()

    def test_closed_selection_and_exact_two_database_roles(self):
        args = RUNNER.parse_args(selected_args())
        selection = RUNNER.qualification_selection(args, "b" * 12)
        self.assertEqual(selection["mode"], "ctf_full_reset_rendered_controlled")
        self.assertEqual(selection["test"], "tests/postgres/ctfFullResetRendered.integration.test.js")
        self.assertEqual(len(selection["databases"]), 2)
        self.assertEqual(selection["environment"]["CTF_FULL_RESET_RENDERED_ISOLATED"], "1")
        self.assertEqual(RUNNER.delivery_role(selection), "dvaia_ctf_delivery")
        self.assertFalse(RUNNER.delivery_database(selection, selection["databases"][0]))
        self.assertTrue(RUNNER.delivery_database(selection, selection["databases"][1]))
        urls = {database: {role: f"{database}/{role}" for role in
            ("runtime", "migration", "delivery")} for database in selection["databases"]}
        environment = RUNNER.database_environment(selection, urls)
        self.assertEqual(set(environment), {"IDENTITY_DATABASE_URL",
            "IDENTITY_MIGRATION_DATABASE_URL", "CTF_DATABASE_URL",
            "CTF_MIGRATION_DATABASE_URL", "CTF_DELIVERY_DATABASE_URL"})
        self.assertEqual(environment["CTF_DELIVERY_DATABASE_URL"],
            f"{selection['databases'][1]}/delivery")
        self.assertTrue(RUNNER.main_no_copy_selection(args))

    def test_selection_rejects_missing_pins_model_and_stage_overrides(self):
        for suffix in (("--target-stage", "6"), ("--stage-end", "10"),
                ("--candidate-set", "stage6-fixed-v1"), ("--ctf-ten-content",)):
            with self.subTest(suffix=suffix), self.assertRaises(SystemExit):
                with redirect_stderr(io.StringIO()):
                    RUNNER.parse_args(selected_args(*suffix))
        for flag in ("--image-id", "--browser-sha256", "--client-build-report",
                "--content-source-manifest-sha256", "--docker-daemon-id"):
            args = selected_args()
            position = args.index(flag)
            del args[position:position + 2]
            with self.subTest(missing=flag), self.assertRaises(SystemExit):
                with redirect_stderr(io.StringIO()):
                    RUNNER.parse_args(args)

    def test_v2_private_receipt_positive_and_fail_closed_counterfactuals(self):
        with tempfile.TemporaryDirectory(prefix="full-reset-admission-", dir=ROOT / "tasks/tmp") as name:
            runtime = Path(name)
            os.chmod(runtime, 0o700)
            path = runtime / "ctf-full-reset-q05-result.json"
            valid = complete_receipt()

            def admit(value):
                path.write_text(json.dumps(value), encoding="utf-8")
                path.chmod(0o600)
                return RUNNER.validate_full_reset_q05_receipt(path)

            self.assertEqual(admit(valid), valid)
            pending = copy.deepcopy(valid)
            pending["serverResponse"] = {"status": 202,
                "body": {"message": "CTF operation is pending. No completion is being reported.",
                    "operationId": pending["operation"]["operationId"],
                    "pending": True, "success": False},
                "lossPhase": "after-real-http-response-before-browser-consumption"}
            pending["operation"]["sameIdHarnessGets"] = 1
            self.assertEqual(admit(pending), pending)
            mutations = []
            old = copy.deepcopy(valid); old["version"] = 1; mutations.append(old)
            for group, field in (("clearedRows", "ctf_attempts"),
                    ("retainedRows", "ctf_judgments"),
                    ("immutableBootstrapRows", "sessions"),
                    ("mutableIdentityMemoryRows", "payload")):
                row = copy.deepcopy(valid); row["pre"][group][field] = 0; mutations.append(row)
            for key, value in (("browserPost", 2), ("serverPost", 0),
                    ("browserFinished", 1), ("serverFinished", 0)):
                row = copy.deepcopy(valid); row["requestCounts"][key] = value; mutations.append(row)
            row = copy.deepcopy(valid); row["facts"]["mutableIdentityMemoryCleared"] = False; mutations.append(row)
            row = copy.deepcopy(valid); row["facts"]["historicalIdentityEvidencePreserved"] = False; mutations.append(row)
            row = copy.deepcopy(valid); row["operation"]["removedParticipants"] = 1; mutations.append(row)
            row = copy.deepcopy(valid); row["unexpectedApiPaths"] = ["/api/ctf/admin/other"]; mutations.append(row)
            row = copy.deepcopy(valid); row["modelCalls"] = 1; mutations.append(row)
            row = copy.deepcopy(valid); row["stage"] = "pending"; mutations.append(row)
            row = copy.deepcopy(pending); row["serverResponse"]["body"]["operationId"] = \
                "00000000-0000-4000-8000-000000000002"; mutations.append(row)
            row = copy.deepcopy(pending); row["operation"]["sameIdHarnessGets"] = 0; mutations.append(row)
            for index, value in enumerate(mutations):
                with self.subTest(mutation=index), self.assertRaises(RuntimeError):
                    admit(value)
            admit(valid)
            path.chmod(0o644)
            with self.assertRaises(RuntimeError):
                RUNNER.validate_full_reset_q05_receipt(path)
            path.chmod(0o600)
            path.write_text(json.dumps(valid)[:-1] + ',"stage":"complete"}', encoding="utf-8")
            with self.assertRaises(RuntimeError):
                RUNNER.validate_full_reset_q05_receipt(path)


if __name__ == "__main__":
    unittest.main()
