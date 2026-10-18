import ast
import hashlib
import importlib.util
import json
import os
import signal
import stat
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "tests/postgres/run-secureshop-bound-review-composition-isolated.py"


def load_runner():
    spec = importlib.util.spec_from_file_location("bound_review_composition_launcher", RUNNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BoundReviewCompositionLauncherContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_runner()
        cls.source = RUNNER.read_text()

    def test_module_is_import_safe_and_plan_requires_no_resources(self):
        self.assertEqual(self.module.main([
            "--docker-host", "unix:///unused", "--docker-cli", "/unused/docker",
            "--docker-cli-sha256", "0" * 64, "--node", "/unused/node",
            "--node-sha256", "1" * 64,
        ]), 0)

    def test_tap_gate_parses_terminal_counts_and_real_skip_directives(self):
        cases = {
            "pass.tap": "1..1\nok 1 - owner listing\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n",
            "summary-zero.tap": "1..1\nok 1 - owner listing\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n",
        }
        with tempfile.TemporaryDirectory() as directory:
            for name, text in cases.items():
                path = Path(directory) / name
                path.write_text(text)
                self.module.assert_non_skipped_tap(path, "fixture")
            rejected = {
                "skip.tap": "1..1\nok 1 - skipped # SKIP unavailable\n# tests 1\n# pass 0\n# fail 0\n# skipped 1\n",
                "zero.tap": "1..0\n# tests 0\n# pass 0\n# fail 0\n# skipped 0\n",
                "fail.tap": "1..1\nnot ok 1 - failed\n# tests 1\n# pass 0\n# fail 1\n# skipped 0\n",
                "malformed.tap": "1..1\nok 1 - missing terminal counts\n",
                "not-ok-hidden.tap": "1..1\nok 1 - summary lies\nnot ok 2 - hidden failure\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n",
                "cancelled.tap": "1..1\nok 1 - cancelled\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n# cancelled 1\n",
                "mismatched.tap": "1..2\nok 1 - only one\n# tests 2\n# pass 1\n# fail 0\n# skipped 0\n",
                "duplicate-count.tap": "1..1\nok 1 - duplicate\n# tests 1\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n",
            }
            for name, text in rejected.items():
                path = Path(directory) / name
                path.write_text(text)
                with self.assertRaises(RuntimeError, msg=name):
                    self.module.assert_non_skipped_tap(path, "fixture")

    def test_closed_suite_manifests_preserve_composition_and_select_only_sessions(self):
        self.assertEqual(set(self.module.SUITES),
                         {"v01-checkout-audit", "composition", "persona-sessions", "persona-password",
                         "persona-api-keys", "merchant-listings", "refund", "refund-actual-8b",
                         "migration-tails", "identity", "capacity", "capacity-actual-8b",
                         "sql-teaching-copy", "xss-email-owner-listing", "xss-judgment-child",
                         "product-integration", "product-actual-8b", "product-retrieval",
                         "manual-ingest", "embedding-revision", "manual-rag-source", "manual-rag-preimages", "product-similar-browser", "product-summary-browser", "manual-rag-browser", "manual-rag-fixed-browser", "manual-integration", "manual-actual-8b",
                         "manual-retrieval-actual-8b", "manual-rendered", "audit-journal",
                          "audit-composition", "audit-fresh-schema", "audit-actual-8b",
                          "mcp-actual-8b", "mcp-provenance-preflight"})
        v01 = self.module.SUITES["v01-checkout-audit"]
        self.assertEqual(v01["stores"], (("REVIEW", "REVIEW"),))
        self.assertEqual(v01["env_prefix"], "PG_SECURESHOP_V01_CHECKOUT_AUDIT_")
        self.assertEqual(v01["test"],
            "tests/postgres/secureshopV01CheckoutAudit.integration.test.js")
        self.assertIn("v01-checkout-audit", self.module.MAIN_CHECKOUT_SUITES)
        self.assertIn("v01-checkout-audit", self.module.REQUIRES_MAIN_CHECKOUT)
        self.assertEqual(self.module.database_name("v01-checkout-audit", "REVIEW", "f" * 12),
            "dvaia_test_v01_checkout_audit_review_ffffffffffff")
        audit = self.module.SUITES["audit-journal"]
        self.assertEqual(audit["stores"], (("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS"), ("REVIEW", "REVIEW"), ("COMMERCE", "COMMERCE")))
        self.assertEqual(audit["env_prefix"], "PG_SECURESHOP_BOUND_AUDIT_")
        self.assertEqual(audit["test"], "tests/postgres/secureshopBoundAudit.integration.test.js")
        self.assertEqual(self.module.SUITES["identity"]["stores"], (("TEST", "IDENTITY"),))
        self.assertEqual(self.module.SUITES["identity"]["env_prefix"], "PG_IDENTITY_")
        self.assertEqual(self.module.SUITES["identity"]["test"],
                         "tests/postgres/identity.integration.test.js")
        xss = self.module.SUITES["xss-email-owner-listing"]
        self.assertEqual(xss["stores"], (("TEST", "XSS"),))
        self.assertEqual(xss["env_prefix"], "PG_XSS_")
        self.assertEqual(xss["test"], "tests/postgres/xss.integration.test.js")
        self.assertEqual(self.module.ROLE_PAIRS["XSS"],
                         ("dvaia_xss_migration", "dvaia_xss_runtime"))
        self.assertIn('"xss-email-owner-listing": "xss_email_owner_listing"', self.source)
        fixture = (ROOT / xss["test"]).read_text()
        self.assertEqual(f'{xss["env_prefix"]}TEST_RUNTIME_URL', 'PG_XSS_TEST_RUNTIME_URL')
        self.assertEqual(f'{xss["env_prefix"]}TEST_MIGRATION_URL', 'PG_XSS_TEST_MIGRATION_URL')
        self.assertIn('PG_XSS_TEST_RUNTIME_URL', fixture)
        self.assertIn('PG_XSS_TEST_MIGRATION_URL', fixture)
        self.assertIn('assert_non_skipped_tap(log_path, args.suite)', self.source)
        lineage = self.module.SUITES["embedding-revision"]
        self.assertEqual(lineage["stores"], (("FRESH", "REVIEW"), ("POPULATED", "REVIEW")))
        self.assertEqual(lineage["env_prefix"], "EMBEDDING_")
        self.assertEqual(lineage["test"], "tests/postgres/secureshopEmbeddingRevision.integration.test.js")
        self.assertEqual(self.module.database_name("embedding-revision", "FRESH", "f" * 12),
                         "dvaia_test_embedding_fresh_ffffffffffff")
        self.assertIn('env["EMBEDDING_REVISION_NATIVE"] = "1"', self.source)
        adapter = self.module.SUITES["manual-rag-source"]
        self.assertEqual(adapter["stores"], (("IDENTITY", "IDENTITY"),
            ("AGENTS", "AGENTS"), ("REVIEW", "REVIEW")))
        self.assertEqual(adapter["env_prefix"], "PG_SECURESHOP_MANUAL_RAG_SOURCE_")
        self.assertEqual(adapter["test"],
            "tests/postgres/secureshopManualRagSourceAdapter.integration.test.js")
        self.assertIn('env["SECURESHOP_MANUAL_RAG_SOURCE_NATIVE"] = "1"', self.source)
        self.assertIn('env["DVAIA_CURRENT_MAIN_WORKSPACE"] = str(source)', self.source)
        self.assertEqual(self.module.database_name("manual-rag-source", "REVIEW", "f" * 12),
            "dvaia_test_manual_rag_source_review_ffffffffffff")
        preimages = self.module.SUITES["manual-rag-preimages"]
        self.assertEqual(preimages["stores"], (("FRESH_REVIEW", "REVIEW"),
            ("POPULATED_REVIEW", "REVIEW")))
        self.assertEqual(preimages["env_prefix"], "PG_SECURESHOP_MANUAL_RAG_PREIMAGES_")
        self.assertEqual(preimages["test"],
            "tests/postgres/secureshopManualRagPreimages.integration.test.js")
        self.assertIn('env["SECURESHOP_MANUAL_RAG_PREIMAGES_NATIVE"] = "1"', self.source)
        self.assertEqual(self.module.database_name("manual-rag-preimages", "FRESH_REVIEW", "f" * 12),
            "dvaia_test_manual_rag_preimages_fresh_review_ffffffffffff")
        browser = self.module.SUITES["product-similar-browser"]
        self.assertEqual(browser["stores"], (("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS"),
            ("REVIEW", "REVIEW"), ("COMMERCE", "COMMERCE")))
        self.assertEqual(browser["env_prefix"], "PG_SECURESHOP_PRODUCT_SIMILAR_BROWSER_")
        self.assertEqual(browser["test"],
            "tests/postgres/secureshopStandaloneProductSimilarRendered.integration.test.js")
        for store, name in self.module.AGENT_HOST_STORE_NAMES.items():
            self.assertEqual(self.module.database_name("product-similar-browser", store, "f" * 12),
                f"dvaia_test_agent_host_ffffffffffff_{name}")
        self.assertEqual(self.module.SUITES["composition"]["stores"], (
            ("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS"),
            ("REVIEW", "REVIEW"), ("COMMERCE", "COMMERCE")))
        sessions = self.module.SUITES["persona-sessions"]
        self.assertEqual(sessions["stores"], (("COMMERCE", "COMMERCE"),
            ("FRESH_AGENTS", "AGENTS"), ("POPULATED_AGENTS", "AGENTS")))
        self.assertEqual(sessions["test"],
            "tests/postgres/secureshopBoundPersonaSessions.integration.test.js")
        self.assertEqual(len({self.module.ROLE_PAIRS[family]
            for _, family in sessions["stores"]}), 2)
        password = self.module.SUITES["persona-password"]
        self.assertEqual(password["stores"], sessions["stores"])
        self.assertEqual(password["env_prefix"], "PG_SECURESHOP_BOUND_PERSONA_PASSWORD_")
        self.assertEqual(password["test"],
            "tests/postgres/secureshopBoundPersonaPassword.integration.test.js")
        api_keys = self.module.SUITES["persona-api-keys"]
        self.assertEqual(api_keys["stores"], (("COMMERCE", "COMMERCE"),
            ("REVIEW", "REVIEW"), ("FRESH_AGENTS", "AGENTS"),
            ("POPULATED_AGENTS", "AGENTS")))
        self.assertEqual(api_keys["env_prefix"], "PG_SECURESHOP_BOUND_PERSONA_API_KEYS_")
        self.assertEqual(api_keys["test"],
            "tests/postgres/secureshopBoundPersonaApiKeys.integration.test.js")
        listings = self.module.SUITES["merchant-listings"]
        self.assertEqual(listings["stores"], (("FRESH_REVIEW", "REVIEW"),
            ("POPULATED_REVIEW", "REVIEW")))
        self.assertEqual(listings["env_prefix"], "PG_SECURESHOP_BOUND_MERCHANT_LISTINGS_")
        self.assertEqual(listings["test"],
            "tests/postgres/secureshopBoundMerchantListings.integration.test.js")
        self.assertEqual(self.module.DATABASE_FAMILIES["merchant-listings"], "merchant")
        for suite, row in self.module.SUITES.items():
            for store, _family in row["stores"]:
                name = self.module.database_name(suite, store, "f" * 12)
                self.assertLessEqual(len(name.encode("utf-8")), 63)
                self.assertRegex(name, r"^dvaia_(?:test_[a-z0-9_]+|sql_copy_[a-f0-9]{12})$")
        refund = self.module.SUITES["refund"]
        self.assertEqual(refund["stores"], (("REVIEW", "REVIEW"),))
        self.assertEqual(refund["env_prefix"], "PG_SECURESHOP_BOUND_REFUND_")
        self.assertEqual(refund["test"], "tests/postgres/secureshopBoundRefund.integration.test.js")
        tails = self.module.SUITES["migration-tails"]
        self.assertEqual(tails["stores"], (("POPULATED_CTF", "CTF"),
            ("POPULATED_AGENTS", "AGENTS")))
        self.assertEqual(tails["env_prefix"], "PG_CURRENT_MIGRATION_TAILS_")
        self.assertEqual(tails["test"], "tests/postgres/currentMigrationTails.integration.test.js")
        self.assertEqual(len({self.module.ROLE_PAIRS[family]
            for _, family in tails["stores"]}), 2)
        capacity = self.module.SUITES["capacity"]
        self.assertEqual(capacity["stores"], (("CAPACITY", "IDENTITY"),))
        self.assertEqual(capacity["env_prefix"] + capacity["stores"][0][0] + "_MIGRATION_URL",
                         "PG_CAPACITY_MIGRATION_URL")
        self.assertEqual(capacity["test"], "tests/postgres/workshopCapacity.integration.test.js")
        self.assertIn('env["DVAIA_CAPACITY_QUALIFICATION"] = "yes"', self.source)
        actual = self.module.SUITES["capacity-actual-8b"]
        self.assertEqual(actual["stores"], (("IDENTITY", "IDENTITY"),))
        self.assertEqual(actual["env_prefix"], "PG_CAPACITY_ACTUAL8B_")
        self.assertEqual(actual["test"], "tests/postgres/workshopCapacityActual8b.integration.test.js")
        self.assertIn('env.update(DVAIA_CAPACITY_ACTUAL8B="yes"', self.source)
        self.assertIn('"capacity-actual-8b": "capacity_actual_8b"', self.source)
        sql_copy = self.module.SUITES["sql-teaching-copy"]
        self.assertEqual(sql_copy["stores"], (("IDENTITY", "IDENTITY"),))
        self.assertIsNone(sql_copy["env_prefix"])
        self.assertEqual(sql_copy["test"],
            "tests/postgres/sqlTeachingCopyDefaults.integration.test.js")
        self.assertEqual(self.module.database_name("sql-teaching-copy", "IDENTITY", "f" * 12),
            "dvaia_sql_copy_ffffffffffff")
        self.assertIn('env["PG_SQL_TEACHING_COPY_TEST_URL"] = migration_url', self.source)
        self.assertNotIn('PG_SQL_TEACHING_COPY_TEST_RUNTIME_URL', self.source)
        self.assertEqual(self.module.main([
            "--docker-host", "unix:///unused", "--docker-cli", "/unused/docker",
            "--docker-cli-sha256", "0" * 64, "--node", "/unused/node",
            "--node-sha256", "1" * 64, "--suite", "persona-sessions",
        ]), 0)

    def test_unknown_suite_is_rejected_before_any_resource_work(self):
        arguments = ["--docker-host", "unix:///unused", "--docker-cli", "/unused/docker",
            "--docker-cli-sha256", "0" * 64, "--node", "/unused/node",
            "--node-sha256", "1" * 64, "--suite", "arbitrary-test-path"]
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as raised:
            self.module.parse_args(arguments)
        self.assertEqual(raised.exception.code, 2)

    def test_every_admitted_suite_has_an_owned_container_name_before_resource_work(self):
        assignments = [node for node in ast.walk(ast.parse(self.source))
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "container_family"
                    for target in node.targets)]
        self.assertEqual(len(assignments), 1)
        self.assertIsInstance(assignments[0].value, ast.Subscript)
        container_families = ast.literal_eval(assignments[0].value.value)
        self.assertEqual(set(container_families), set(self.module.SUITES))
        self.assertEqual(container_families["manual-rag-source"], "manual-rag-source")

    def test_main_checkout_is_bounded_no_copy_and_has_private_source_inventory(self):
        arguments = ["--docker-host", "unix:///unused", "--docker-cli", "/unused/docker",
            "--docker-cli-sha256", "0" * 64, "--node", "/unused/node",
            "--node-sha256", "1" * 64, "--main-checkout"]
        for suite in ("manual-ingest", "embedding-revision"):
            with mock.patch.object(self.module, "source_inventory", return_value={
                    "digest": "a" * 64, "files": {"pinned.js": "b" * 64}}) as inventory, \
                    redirect_stdout(StringIO()) as output:
                self.assertEqual(self.module.main(arguments + ["--suite", suite]), 0)
            inventory.assert_called_once_with(ROOT)
            self.assertEqual(json.loads(output.getvalue()), {
                "suite": suite, "mode": "main-checkout", "sourceCopy": False,
                "sourceDigest": "a" * 64, "sourceFiles": 1,
                "stores": [store for store, _ in self.module.SUITES[suite]["stores"]],
                "nativeStarted": False})
        with self.assertRaisesRegex(RuntimeError, "limited to the focused"):
            self.module.main(arguments + ["--suite", "composition"])
        tree = ast.parse(self.source)
        guarded = next(node for node in ast.walk(tree) if isinstance(node, ast.If)
            and ast.unparse(node.test) == 'not args.main_checkout'
            and any(isinstance(child, ast.Call) and ast.unparse(child.func) == 'shutil.copytree'
                    for child in ast.walk(ast.Module(body=node.body, type_ignores=[]))))
        copy_calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
            and ast.unparse(node.func) in ('shutil.copytree', 'shutil.copy2')]
        self.assertTrue(copy_calls)
        self.assertTrue(all(guarded.lineno < call.lineno < guarded.end_lineno for call in copy_calls))
        self.assertIn('workspace = source if args.main_checkout else root / "source"', self.source)
        self.assertIn('DVAIA_ISOLATED_TEST_WORKSPACE=str(root if args.main_checkout else workspace)', self.source)
        self.assertIn('write_private_json(root / "source-before.json", source_before)', self.source)
        self.assertIn('write_private_json(root / "source-after.json", source_after)', self.source)

    def test_main_checkout_inventory_detects_source_drift_and_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in self.module.SOURCE_ROOTS:
                (root / name).mkdir(parents=True)
            (root / 'package.json').write_text('{}')
            (root / 'package-lock.json').write_text('{}')
            source = root / 'server/database/postgres/lineage.js'
            source.write_text('first')
            before = self.module.source_inventory(root)
            self.assertEqual(before, self.module.source_inventory(root))
            source.write_text('second')
            self.assertNotEqual(before['digest'], self.module.source_inventory(root)['digest'])
            (root / 'server/database/postgres/link.js').symlink_to(source)
            with self.assertRaisesRegex(RuntimeError, 'source link forbidden'):
                self.module.source_inventory(root)

    def test_manual_rag_source_plan_pins_imported_control_and_exact_tap(self):
        with mock.patch.object(self.module, "source_inventory", return_value={
                "digest": "a" * 64, "files": {"pinned.js": "b" * 64}}) as inventory, \
                redirect_stdout(StringIO()) as output:
            self.assertEqual(self.module.main([
                "--docker-host", "unix:///unused", "--docker-cli", "/unused/docker",
                "--docker-cli-sha256", "0" * 64, "--node", "/unused/node",
                "--node-sha256", "1" * 64, "--main-checkout",
                "--suite", "manual-rag-source"]), 0)
        inventory.assert_called_once_with(ROOT,
            ("tests/secureshopManualRagSourceContract.test.js",))
        self.assertEqual(json.loads(output.getvalue())["stores"],
            ["IDENTITY", "AGENTS", "REVIEW"])
        self.assertIn('"manual-rag-source",', self.source)
        title = "native manual RAG source adapter joins historical uploader and current consumer using immutable SQL evidence"
        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / "result.log"
            result.write_text(f"TAP version 13\n1..1\nok 1 - {title}\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n")
            self.module.assert_non_skipped_tap(result, "manual-rag-source")
            self.module.assert_exact_single_tap(result, title)
            result.write_text(result.read_text().replace(title, "unrelated test"))
            with self.assertRaisesRegex(RuntimeError, "TAP title"):
                self.module.assert_exact_single_tap(result, title)

    def test_product_summary_closed_selection_and_actual_environment(self):
        from types import SimpleNamespace
        suite=self.module.SUITES['product-summary-browser']
        self.assertEqual(suite['stores'],self.module.SUITES['product-similar-browser']['stores'])
        self.assertEqual(suite['test'],self.module.SUITES['product-similar-browser']['test'])
        self.assertIn('product-summary-browser',self.module.REQUIRES_MAIN_CHECKOUT)
        self.assertIn('product-summary-browser',self.module.EMBEDDING_CACHE_SUITES)
        self.assertEqual(self.module.sha256(ROOT/suite['test']),self.module.PRODUCT_SIMILAR_TEST_SHA256)
        for store,_ in suite['stores']:
            self.assertEqual(self.module.database_name('product-summary-browser',store,'f'*12),
                f"dvaia_test_agent_host_{'f'*12}_{self.module.AGENT_HOST_STORE_NAMES[store]}")
        tree=ast.parse(self.source)
        blocks=[n for n in ast.walk(tree) if isinstance(n,ast.If) and ast.unparse(n.test)=="args.suite in ('product-similar-browser', 'product-summary-browser')"
                and any(isinstance(x,ast.Constant) and x.value=='SECURESHOP_PRODUCT_SUMMARY_BROWSER_NATIVE' for x in ast.walk(n))]
        self.assertEqual(len(blocks),1)
        for selected,expected,absent in [('product-summary-browser','SECURESHOP_PRODUCT_SUMMARY_BROWSER_NATIVE','SECURESHOP_PRODUCT_SIMILAR_BROWSER_NATIVE'),('product-similar-browser','SECURESHOP_PRODUCT_SIMILAR_BROWSER_NATIVE','SECURESHOP_PRODUCT_SUMMARY_BROWSER_NATIVE')]:
            env={};ns={'args':SimpleNamespace(suite=selected,browser_sha256='f'*64),'env':env,'source':ROOT,'root':Path('/owned/evidence'),'browser':Path('/owned/browser'),'REFUND_MODEL':self.module.REFUND_MODEL,'REFUND_OLLAMA_BASE_URL':self.module.REFUND_OLLAMA_BASE_URL}
            exec(compile(ast.Module(body=blocks,type_ignores=[]),'<actual-environment>','exec'),ns)
            self.assertEqual(env[expected],'1');self.assertNotIn(absent,env)
            self.assertEqual(env['SECURESHOP_PRODUCT_SIMILAR_BROWSER_BUILD'],str(ROOT/'client/build'))

    def test_product_summary_actual_model_after_branch_preserves_identity_and_budgets(self):
        from types import SimpleNamespace
        tree=ast.parse(self.source)
        blocks=[n for n in ast.walk(tree) if isinstance(n,ast.If) and ast.unparse(n.test)=="args.suite in ('product-similar-browser', 'product-summary-browser')"
                and any(isinstance(x,ast.Constant) and x.value=='product-similar-model-identity.json' for x in ast.walk(n))]
        self.assertEqual(len(blocks),1);identity={'model':'llama3.1:8b','digest':'a'*64};written=[]
        ns={'args':SimpleNamespace(suite='product-summary-browser'),'model_identity_before':identity,'read_refund_model_digest':lambda:dict(identity),'root':Path('/owned/evidence'),'write_private_json':lambda p,v:written.append((p,v))}
        code=compile(ast.Module(body=blocks,type_ignores=[]),'<actual-model-after>','exec');exec(code,ns)
        self.assertEqual(written[0][1],{'before':identity,'after':identity,'maxHttpCalls':20,'maxActorHttpCalls':12,'maxJudgeHttpCalls':8})
        ns['read_refund_model_digest']=lambda:{'digest':'b'*64}
        with self.assertRaisesRegex(RuntimeError,'model changed'):exec(code,ns)

    def test_product_summary_plan_is_nonallocating_and_pin_bound(self):
        args=['--docker-host','unix:///unused','--docker-cli','/unused/docker','--docker-cli-sha256','0'*64,'--node','/unused/node','--node-sha256','1'*64,'--suite','product-summary-browser','--main-checkout']
        fixture=self.module.SUITES['product-summary-browser']['test']
        with mock.patch.object(self.module,'source_inventory',return_value={'digest':'a'*64,'files':{fixture:self.module.PRODUCT_SIMILAR_TEST_SHA256}}),mock.patch.object(self.module,'run_qualification',side_effect=AssertionError('no allocation')),redirect_stdout(StringIO()) as output:
            self.assertEqual(self.module.main(args),0)
        self.assertEqual(json.loads(output.getvalue())['stores'],['IDENTITY','AGENTS','REVIEW','COMMERCE'])
        with mock.patch.object(self.module,'source_inventory',return_value={'digest':'a'*64,'files':{fixture:'0'*64}}):
            with self.assertRaisesRegex(RuntimeError,'fixture pin changed'):self.module.main(args)

    def test_product_summary_receipt_and_wire_are_closed(self):
        import copy
        receipt={k:True for k in self.module.PRODUCT_SUMMARY_FLAGS}
        receipt.update(passed=True,scope=self.module.PRODUCT_SUMMARY_SCOPE,summaryRuns=3,similarRuns=0,selectedSimilarCalls=0,modelCalls=6,judgeCalls=2,errors=[],cleanupErrors=[])
        def call(kind):
            request=json.dumps({'model':self.module.REFUND_MODEL});response='{"done":true}'
            return {'kind':kind,'model':self.module.REFUND_MODEL,'status':200,'responseComplete':True,'responseCaptureTruncated':False,'request':request,'response':response,'requestBytes':len(request.encode()),'responseBytes':len(response.encode()),'requestSha256':hashlib.sha256(request.encode()).hexdigest(),'responseSha256':hashlib.sha256(response.encode()).hexdigest()}
        wire={'model':self.module.REFUND_MODEL,'modelDigest':self.module.REFUND_MODEL_DIGEST,'calls':[call('actor') for _ in range(6)],'judgeCalls':[call('judge') for _ in range(2)],'actorSpans':[],'requests':[{'method':'POST','pathname':'/products/1/summary','status':200,'error':None} for _ in range(3)],'pageErrors':[],'judgeInputs':[{}],'judgeTranscripts':[{}],'summaryCapture':{'turns':[{}, {}, {}],'positiveWireProof':{}}}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            def save(a,b):
                self.module.write_private_json(root/'product-similar-evidence.json',a);self.module.write_private_json(root/'product-similar-original-wire.json',b)
            def clear():
                for p in root.iterdir():p.unlink()
            save(receipt,wire);self.assertEqual(self.module.assert_product_summary_evidence(root),receipt);clear()
            for key,value in [('modelCalls',13),('judgeCalls',9),('summaryRuns',2),('similarRuns',1),('fixtureLocalCandidateAdmission',False),('modelCalls',True),('unexpected',True)]:
                bad=copy.deepcopy(receipt);bad[key]=value;save(bad,wire)
                with self.assertRaises(RuntimeError):self.module.assert_product_summary_evidence(root)
                clear()
            for mutation in ['wireHash','judgeMissing','similar','postCount']:
                bad=copy.deepcopy(wire)
                if mutation=='wireHash':bad['calls'][0]['responseSha256']='0'*64
                elif mutation=='judgeMissing':bad['judgeCalls']=[]
                elif mutation=='similar':bad['requests'][0]['pathname']='/products/1/similar'
                else:bad['requests'].pop()
                save(receipt,bad)
                with self.assertRaises(RuntimeError):self.module.assert_product_summary_evidence(root)
                clear()

    def test_product_similar_browser_requires_main_checkout_and_full_source_closure(self):
        arguments = ["--docker-host", "unix:///unused", "--docker-cli", "/unused/docker",
            "--docker-cli-sha256", "0" * 64, "--node", "/unused/node",
            "--node-sha256", "1" * 64, "--suite", "product-similar-browser"]
        with self.assertRaisesRegex(RuntimeError, "requires --main-checkout"):
            self.module.main(arguments)
        with mock.patch.object(self.module, "source_inventory", return_value={
                "digest": "a" * 64, "files": {
                    self.module.SUITES["product-similar-browser"]["test"]:
                        self.module.PRODUCT_SIMILAR_TEST_SHA256}}) as inventory, \
                redirect_stdout(StringIO()) as output:
            self.assertEqual(self.module.main(arguments + ["--main-checkout"]), 0)
        inventory.assert_called_once_with(ROOT, (),
            ("server/routes", "server/middleware", "server/data"),
            ("client/src", "client/build"))
        plan = json.loads(output.getvalue())
        self.assertEqual(plan["stores"], ["IDENTITY", "AGENTS", "REVIEW", "COMMERCE"])
        self.assertFalse(plan["sourceCopy"])
        with mock.patch.object(self.module, "source_inventory", return_value={
                "digest": "a" * 64, "files": {
                    self.module.SUITES["product-similar-browser"]["test"]: "0" * 64}}):
            with self.assertRaisesRegex(RuntimeError, "fixture pin changed"):
                self.module.main(arguments + ["--main-checkout"])
        self.assertIn('"product-similar-browser": "product-similar-browser"', self.source)
        self.assertIn('read_refund_model_digest()', self.source)
        self.assertIn('"product-similar-browser.json", "product_similar_browser"', self.source)
        self.assertIn("product-similar-browser", self.module.EMBEDDING_CACHE_SUITES)
        self.assertIn('env.update(SS_PRODUCT_QUALIFICATION="1", HF_HUB_OFFLINE="1", XENOVA_CACHE=str(embedding_cache))', self.source)

    def test_manual_rag_browser_has_distinct_no_copy_four_store_admission(self):
        suite = self.module.SUITES["manual-rag-browser"]
        self.assertEqual(suite["stores"], (("IDENTITY", "IDENTITY"), ("AGENTS", "AGENTS"),
            ("REVIEW", "REVIEW"), ("COMMERCE", "COMMERCE")))
        self.assertEqual(suite["env_prefix"], "PG_SECURESHOP_MANUAL_RAG_BROWSER_")
        self.assertEqual(suite["test"], "tests/postgres/secureshopManualRagRendered.integration.test.js")
        for store in ("IDENTITY", "AGENTS", "REVIEW", "COMMERCE"):
            self.assertEqual(self.module.database_name("manual-rag-browser", store, "f" * 12),
                f"dvaia_test_agent_host_{'f' * 12}_{self.module.AGENT_HOST_STORE_NAMES[store]}")
        arguments = ["--docker-host", "unix:///unused", "--docker-cli", "/unused/docker",
            "--docker-cli-sha256", "0" * 64, "--node", "/unused/node",
            "--node-sha256", "1" * 64, "--suite", "manual-rag-browser"]
        with self.assertRaisesRegex(RuntimeError, "requires --main-checkout"):
            self.module.main(arguments)
        with mock.patch.object(self.module, "source_inventory", return_value={
                "digest": "a" * 64, "files": {suite["test"]:
                    self.module.MANUAL_RAG_BROWSER_TEST_SHA256}}) as inventory, \
                redirect_stdout(StringIO()) as output:
            self.assertEqual(self.module.main(arguments + ["--main-checkout"]), 0)
        inventory.assert_called_once_with(ROOT, ("sidecars/sandbox-runner/secureshopFiles.js",),
            ("server/routes", "server/middleware", "server/data"),
            ("client/src", "client/build"))
        self.assertEqual(json.loads(output.getvalue())["stores"],
            ["IDENTITY", "AGENTS", "REVIEW", "COMMERCE"])
        with mock.patch.object(self.module, "source_inventory", return_value={
                "digest": "a" * 64, "files": {suite["test"]: "0" * 64}}):
            with self.assertRaisesRegex(RuntimeError, "fixture pin changed"):
                self.module.main(arguments + ["--main-checkout"])
        self.assertIn('"manual-rag-browser": "manual-rag-browser"', self.source)
        self.assertIn('"manual-rag-browser.json", "manual_rag_browser"', self.source)
        self.assertIn('SECURESHOP_MANUAL_RAG_BROWSER_NATIVE="1"', self.source)
        self.assertIn("manual-rag-browser", self.module.EMBEDDING_CACHE_SUITES)

    def test_manual_rag_fixed_browser_has_exclusive_no_copy_admission(self):
        suite = self.module.SUITES["manual-rag-fixed-browser"]
        original = self.module.SUITES["manual-rag-browser"]
        self.assertEqual(suite["stores"], original["stores"])
        self.assertEqual(suite["env_prefix"], original["env_prefix"])
        self.assertEqual(suite["test"], original["test"])
        self.assertNotEqual(suite["child_name"], original["child_name"])
        for store in ("IDENTITY", "AGENTS", "REVIEW", "COMMERCE"):
            self.assertEqual(self.module.database_name("manual-rag-fixed-browser", store, "f" * 12),
                f"dvaia_test_agent_host_{'f' * 12}_{self.module.AGENT_HOST_STORE_NAMES[store]}")
        arguments = ["--docker-host", "unix:///unused", "--docker-cli", "/unused/docker",
            "--docker-cli-sha256", "0" * 64, "--node", "/unused/node",
            "--node-sha256", "1" * 64, "--suite", "manual-rag-fixed-browser"]
        with self.assertRaisesRegex(RuntimeError, "requires --main-checkout"):
            self.module.main(arguments)
        with mock.patch.object(self.module, "source_inventory", return_value={
                "digest": "a" * 64, "files": {suite["test"]:
                    self.module.MANUAL_RAG_BROWSER_TEST_SHA256}}) as inventory, \
                redirect_stdout(StringIO()) as output:
            self.assertEqual(self.module.main(arguments + ["--main-checkout"]), 0)
        inventory.assert_called_once_with(ROOT, ("sidecars/sandbox-runner/secureshopFiles.js",),
            ("server/routes", "server/middleware", "server/data"),
            ("client/src", "client/build"))
        self.assertEqual(json.loads(output.getvalue())["stores"],
            ["IDENTITY", "AGENTS", "REVIEW", "COMMERCE"])
        self.assertIn('env["SECURESHOP_MANUAL_RAG_FIXED_ONLY"] = "1"', self.source)
        self.assertIn('"manual-rag-fixed-browser": (("manual-rag-browser.json", "manual_rag_browser"),)', self.source)
        self.assertIn("manual-rag-fixed-browser", self.module.EMBEDDING_CACHE_SUITES)
        with mock.patch.object(self.module, "source_inventory", return_value={
                "digest": "a" * 64, "files": {suite["test"]: "0" * 64}}):
            with self.assertRaisesRegex(RuntimeError, "fixture pin changed"):
                self.module.main(arguments + ["--main-checkout"])

    def test_manual_rag_fixed_receipt_requires_actor_only_original_and_no_credit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            documents = '[{"text":"owned synthetic manual"}]'
            receipt_row = {"documentDigest": hashlib.sha256(documents.encode()).hexdigest()}
            response = json.dumps({"mode": "catalog", "retrieved_context": [],
                "modeCapability": {"effectiveMode": "fixed"}})
            call = {"kind": "actor", "model": self.module.REFUND_MODEL, "status": 200,
                "responseComplete": True, "responseCaptureTruncated": False,
                "request": "{}", "requestBytes": 2, "requestSha256": hashlib.sha256(b"{}").hexdigest(),
                "response": "{}", "responseBytes": 2, "responseSha256": hashlib.sha256(b"{}").hexdigest()}
            original = {"method": "POST", "pathname": "/products/7/similar",
                "status": 200, "error": None, "response": response}
            receipt = {flag: True for flag in self.module.MANUAL_RAG_FIXED_FLAGS}
            receipt.update(passed=True, scope=self.module.MANUAL_RAG_FIXED_SCOPE,
                similarRuns=1, modelCalls=4, selectedSimilarCalls=1, judgeCalls=0,
                errors=[], cleanupErrors=[], credit=False, diagnostic=False)
            wire = {"scope": self.module.MANUAL_RAG_FIXED_SCOPE, "credit": False,
                "model": self.module.REFUND_MODEL, "modelDigest": self.module.REFUND_MODEL_DIGEST,
                "actorCalls": [call for _ in range(4)], "judgeCalls": [],
                "actorSpans": [{"result": {"tool_uses": [{"name": "product-search.similar"}]}}],
                "judgeTranscripts": [], "requests": [original], "pageErrors": [],
                "originalCapture": {"fixed": original, "fixedReceipt": receipt_row,
                    "fixedManualPreimage": {"receipt": receipt_row, "documentsJson": documents},
                    "fixedUploader": {}, "fixedConsumer": {},
                    "fixedSavedAssessment": {"status": 200, "body": {"completed": False,
                        "status": "ineligible", "modelEvaluated": False}},
                    "peerBefore": [{}], "peerDenied": {"status": 401},
                    "reset": {"status": "committed"}, "resetDenied": {"status": 401}}}
            receipt_path = root / "manual-rag-evidence.json"
            wire_path = root / "manual-rag-original-wire.json"
            self.module.write_private_json(receipt_path, receipt)
            self.module.write_private_json(wire_path, wire)
            self.assertEqual(self.module.assert_manual_rag_fixed_evidence(root), receipt)
            receipt["judgeCalls"] = 1
            receipt_path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(RuntimeError, "receipt failed"):
                self.module.assert_manual_rag_fixed_evidence(root)
            receipt["judgeCalls"] = False
            receipt_path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(RuntimeError, "receipt failed"):
                self.module.assert_manual_rag_fixed_evidence(root)
            receipt["judgeCalls"] = 0
            receipt_path.write_text(json.dumps(receipt))
            wire["judgeCalls"] = [{}]
            wire_path.write_text(json.dumps(wire))
            with self.assertRaisesRegex(RuntimeError, "wire envelope"):
                self.module.assert_manual_rag_fixed_evidence(root)
            wire["judgeCalls"] = []
            wire["originalCapture"]["fixedSavedAssessment"]["body"]["completed"] = True
            wire_path.write_text(json.dumps(wire))
            with self.assertRaisesRegex(RuntimeError, "no-credit"):
                self.module.assert_manual_rag_fixed_evidence(root)

    def test_manual_rag_browser_distinct_actor_judge_capture_and_no_credit(self):
        def call(kind):
            return {"kind": kind, "model": self.module.REFUND_MODEL, "status": 200,
                "responseComplete": True, "responseCaptureTruncated": False,
                "request": "{}", "requestBytes": 2, "requestSha256": hashlib.sha256(b"{}").hexdigest(),
                "response": "{}", "responseBytes": 2, "responseSha256": hashlib.sha256(b"{}").hexdigest()}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = {flag: True for flag in self.module.MANUAL_RAG_BROWSER_FLAGS}
            receipt.update(passed=True, scope=self.module.MANUAL_RAG_BROWSER_SCOPE,
                similarRuns=2, modelCalls=6, selectedSimilarCalls=2, judgeCalls=2,
                errors=[], cleanupErrors=[], credit=False, diagnostic=True)
            wire = {"scope": self.module.MANUAL_RAG_BROWSER_SCOPE, "credit": False,
                "model": self.module.REFUND_MODEL, "modelDigest": self.module.REFUND_MODEL_DIGEST,
                "actorCalls": [call("actor") for _ in range(6)],
                "judgeCalls": [call("judge") for _ in range(2)],
                "actorSpans": [{"result": {"tool_uses": [{"name": "product-search.similar"}]}} for _ in range(2)],
                "judgeTranscripts": [{"complete": True,
                    "header": {"runId": "run-1", "evidenceDigest": "a" * 64},
                    "calls": [{}, {}]}],
                "requests": [{"method": "POST", "pathname": "/products/7/similar",
                              "status": 200, "error": None} for _ in range(2)],
                "originalCapture": {"packet": {"runId": "run-1", "evidenceDigest": "a" * 64},
                    "judgment": {"provider": "ollama", "model": self.module.REFUND_MODEL,
                                 "verdict": "pass", "evidenceDigest": "a" * 64},
                    "savedAssessment": {"status": 200, "body": {"completed": False,
                        "status": "ineligible", "modelEvaluated": False}},
                    "reset": {"status": "committed"}, "resetDenied": {"status": 401}},
                "pageErrors": []}
            receipt_path = root / "manual-rag-evidence.json"
            wire_path = root / "manual-rag-original-wire.json"
            self.module.write_private_json(receipt_path, receipt)
            self.module.write_private_json(wire_path, wire)
            self.assertEqual(self.module.assert_manual_rag_browser_evidence(root), receipt)
            receipt["credit"] = True
            receipt_path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(RuntimeError, "receipt failed"):
                self.module.assert_manual_rag_browser_evidence(root)
            receipt["credit"] = False
            receipt_path.write_text(json.dumps(receipt))
            wire["judgeCalls"][0]["responseSha256"] = "0" * 64
            wire_path.write_text(json.dumps(wire))
            with self.assertRaisesRegex(RuntimeError, "judge wire"):
                self.module.assert_manual_rag_browser_evidence(root)
            wire["judgeCalls"][0]["responseSha256"] = hashlib.sha256(b"{}").hexdigest()
            wire["judgeTranscripts"][0]["header"]["evidenceDigest"] = "b" * 64
            wire_path.write_text(json.dumps(wire))
            with self.assertRaisesRegex(RuntimeError, "Judge diagnostic"):
                self.module.assert_manual_rag_browser_evidence(root)

    def test_manual_rag_preimages_plan_is_two_owned_review_stores_and_one_named_tap(self):
        arguments = ["--docker-host", "unix:///unused", "--docker-cli", "/unused/docker",
            "--docker-cli-sha256", "0" * 64, "--node", "/unused/node",
            "--node-sha256", "1" * 64, "--suite", "manual-rag-preimages"]
        with self.assertRaisesRegex(RuntimeError, "requires --main-checkout"):
            self.module.main(arguments)
        with mock.patch.object(self.module, "source_inventory", return_value={
                "digest": "a" * 64, "files": {
                    self.module.SUITES["manual-rag-preimages"]["test"]:
                        self.module.MANUAL_RAG_PREIMAGES_TEST_SHA256}}) as inventory, \
                redirect_stdout(StringIO()) as output:
            self.assertEqual(self.module.main(arguments + ["--main-checkout"]), 0)
        inventory.assert_called_once_with(ROOT)
        self.assertEqual(json.loads(output.getvalue())["stores"],
            ["FRESH_REVIEW", "POPULATED_REVIEW"])
        self.assertIn('"manual-rag-preimages": "manual-rag-preimages"', self.source)
        self.assertIn('assert_exact_single_tap(log_path, "native manual RAG preimages preserve original dense vectors across upgrade, replay, rollback and retirement")', self.source)
        with mock.patch.object(self.module, "source_inventory", return_value={
                "digest": "a" * 64, "files": {
                    self.module.SUITES["manual-rag-preimages"]["test"]: "0" * 64}}):
            with self.assertRaisesRegex(RuntimeError, "preimages native fixture pin changed"):
                self.module.main(arguments + ["--main-checkout"])

    def test_product_similar_private_receipt_and_original_wire_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            call = {"kind": "actor", "model": self.module.REFUND_MODEL, "status": 200,
                "responseComplete": True, "responseCaptureTruncated": False,
                "request": "{}", "requestBytes": 2, "requestSha256": hashlib.sha256(b"{}").hexdigest(),
                "response": "{}", "responseBytes": 2, "responseSha256": hashlib.sha256(b"{}").hexdigest()}
            receipt = {flag: True for flag in self.module.PRODUCT_SIMILAR_FLAGS}
            receipt.update(passed=True, scope=self.module.PRODUCT_SIMILAR_SCOPE,
                similarRuns=1, modelCalls=2, selectedSimilarCalls=1, judgeCalls=0,
                errors=[], cleanupErrors=[])
            wire = {"model": self.module.REFUND_MODEL,
                "modelDigest": self.module.REFUND_MODEL_DIGEST, "calls": [call, call],
                "actorSpans": [{"result": {"tool_uses": [{"name": "product-search.similar"}]}}],
                "requests": [{"method": "POST", "pathname": "/products/7/similar",
                              "status": 200, "error": None}], "pageErrors": []}
            receipt_path = root / "product-similar-evidence.json"
            wire_path = root / "product-similar-original-wire.json"
            self.module.write_private_json(receipt_path, receipt)
            self.module.write_private_json(wire_path, wire)
            self.assertEqual(self.module.assert_product_similar_evidence(root), receipt)
            receipt["judgeCalls"] = 1
            self.module.write_private_json(root / "unrelated.json", receipt)
            receipt_path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(RuntimeError, "receipt failed"):
                self.module.assert_product_similar_evidence(root)
            receipt["judgeCalls"] = 0
            receipt_path.write_text(json.dumps(receipt))
            wire["calls"][0]["responseSha256"] = "0" * 64
            wire_path.write_text(json.dumps(wire))
            with self.assertRaisesRegex(RuntimeError, "actor wire"):
                self.module.assert_product_similar_evidence(root)

    def test_browser_cleanup_uses_explicit_suite_record_spec(self):
        browser_helper = ROOT / "tests/postgres/run-csrf-email-composed-isolated.py"
        spec = importlib.util.spec_from_file_location("browser_owner_records", browser_helper)
        owner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(owner)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            browser = root / "browser"
            browser.write_bytes(b"pinned browser")
            digest = hashlib.sha256(browser.read_bytes()).hexdigest()
            record = {"schemaVersion": 1, "processes": [{
                "kind": "product_similar_browser", "pid": 12345,
                "startTime": "Tue Oct 13 06:07:40 2026",
                "executablePath": str(browser.resolve()), "executableSha256": digest}]}
            self.module.write_private_json(root / "product-similar-browser.json", record)
            with self.assertRaisesRegex(RuntimeError, "fixture_browser"):
                owner.read_browser_records(root, browser, digest, require_all=True)
            rows = owner.read_browser_records(root, browser, digest, require_all=True,
                records=(("product-similar-browser.json", "product_similar_browser"),))
            self.assertEqual(rows[0]["pid"], 12345)
            manual_record = {"schemaVersion": 1, "processes": [{
                **record["processes"][0], "kind": "manual_rag_browser", "pid": 12346}]}
            self.module.write_private_json(root / "manual-rag-browser.json", manual_record)
            manual_rows = owner.read_browser_records(root, browser, digest, require_all=True,
                records=(("manual-rag-browser.json", "manual_rag_browser"),))
            self.assertEqual(manual_rows[0]["pid"], 12346)
            with self.assertRaisesRegex(RuntimeError, "kind mismatch"):
                owner.read_browser_records(root, browser, digest, require_all=True,
                    records=(("manual-rag-browser.json", "product_similar_browser"),))
        self.assertEqual(self.source.count("records=browser_record_spec"), 2)

    def test_executable_pins_reject_symlinks_and_hash_mismatches(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "node"
            executable.write_bytes(b"managed executable")
            expected = hashlib.sha256(executable.read_bytes()).hexdigest()
            self.assertEqual(self.module.validate_executable(executable, expected, "Node"), executable.resolve())
            with self.assertRaisesRegex(RuntimeError, "pin mismatch"):
                self.module.validate_executable(executable, "0" * 64, "Node")
            link = root / "node-link"
            link.symlink_to(executable)
            with self.assertRaisesRegex(RuntimeError, "pin mismatch"):
                self.module.validate_executable(link, expected, "Node")

    def test_private_receipts_are_owner_only_and_complete_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            self.module.write_private_json(path, {"status": "complete"})
            self.assertEqual(json.loads(path.read_text()), {"status": "complete"})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            log_path = Path(directory) / "result.log"
            with self.module.open_private_log(log_path) as output:
                output.write("bounded evidence\n")
            self.assertEqual(stat.S_IMODE(log_path.stat().st_mode), 0o600)

    def test_postgres_readiness_waits_for_final_mapped_host(self):
        attempts = []
        times = iter((0, 0, 0.25, 0.5))

        def probe(command, **kwargs):
            attempts.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0 if len(attempts) == 3 else 2,
                                               "1\n" if len(attempts) == 3 else "", "")

        psql = ["psql", "-h", "127.0.0.1", "-p", "36837", "-U", "composition_admin",
                "-d", "postgres", "-v", "ON_ERROR_STOP=1"]
        self.module.wait_postgres_host(psql, {"PGCONNECT_TIMEOUT": "2"}, runner=probe,
                                       monotonic=lambda: next(times), sleep=lambda _delay: None)
        self.assertEqual(len(attempts), 3)
        for command, kwargs in attempts:
            self.assertEqual(command, psql + ["-X", "-A", "-t", "-c", "SELECT 1"])
            self.assertEqual(kwargs["env"], {"PGCONNECT_TIMEOUT": "2"})
            self.assertEqual(kwargs["timeout"], 2)
        self.assertNotIn('"pg_isready"', self.source)
        self.assertIn('wait_postgres_host(psql, base_env)', self.source)

    def test_postgres_readiness_fails_closed_after_deadline(self):
        attempts = []

        def probe(command, **_kwargs):
            attempts.append(command)
            return subprocess.CompletedProcess(command, 2, "", "startup")

        with self.assertRaisesRegex(RuntimeError, "mapped host did not become ready"):
            self.module.wait_postgres_host(["psql"], {}, runner=probe,
                monotonic=iter((0, 0, 0.25, 0.5, 0.75, 1)).__next__,
                sleep=lambda _delay: None, timeout_seconds=1)
        self.assertEqual(len(attempts), 4)

    def test_process_group_cleanup_terminates_descendant_after_leader_exit(self):
        leader = subprocess.Popen(["/bin/sh", "-c", "sleep 30 &"], start_new_session=True)
        leader._owned_pgid = leader.pid
        leader.wait(timeout=2)
        self.assertIsNotNone(leader.returncode)
        self.module.stop_group(leader, term_seconds=2, kill_seconds=2)
        with self.assertRaises(ProcessLookupError):
            os.killpg(leader.pid, 0)

    def test_container_cleanup_attempts_every_predeclared_name_and_verifies_absence(self):
        commands = []

        class Result:
            returncode = 0
            stdout = ""

        def runner(command, **_kwargs):
            commands.append(command)
            return Result()

        intents = [{"name": "first", "image": "sha256:" + "a" * 64},
                   {"name": "second", "image": "sha256:" + "a" * 64}]
        rows, errors = self.module.cleanup_containers(intents, ["docker"], {}, runner=runner)
        self.assertEqual(errors, [])
        self.assertTrue(all(row["cleanup"] == "absent_verified" for row in rows))
        self.assertEqual([command[-1] for command in commands if "rm" in command], ["second", "first"])
        self.assertEqual(len([command for command in commands if "ps" in command]), 2)

    def test_finalizer_attempts_remaining_resources_and_preserves_primary_error(self):
        class Child:
            pid = 101
            returncode = 1
            _owned_name = "child"
            _owned_pgid = 101

            def poll(self):
                return self.returncode

        class Log:
            closed = False

            def close(self):
                self.closed = True

        log = Log()
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(self.module, "stop_group", side_effect=RuntimeError("group failed")), \
                mock.patch.object(self.module, "cleanup_containers",
                                  return_value=([{"name": "pg", "cleanup": "absent_verified"}], [])):
            errors = self.module.finalize_owned([Child()], [log], [{"name": "pg"}], ["docker"], {},
                                                Path(directory) / "cleanup.json")
            self.assertTrue(log.closed)
            self.assertEqual(len(errors), 1)
            receipt = json.loads((Path(directory) / "cleanup.json").read_text())
            self.assertEqual(receipt["containers"][0]["cleanup"], "absent_verified")
            self.assertEqual(receipt["processes"][0]["cleanup"], "failed")
            primary = RuntimeError("primary failure")
            self.module.add_cleanup_errors(primary, errors)
            self.assertIn("group failed", primary.__notes__[0])

    def test_intents_precede_launch_and_wait_and_image_pull_is_disabled(self):
        self.assertIn('parser.add_argument("--node", required=True)', self.source)
        self.assertIn('parser.add_argument("--node-sha256", required=True)', self.source)
        self.assertIn('parser.add_argument("--docker-cli", required=True)', self.source)
        self.assertIn('run(docker + ["image", "inspect", POSTGRES_IMAGE_ID', self.source)
        self.assertIn('"run", "--detach", "--pull", "never"', self.source)
        self.assertLess(self.source.index("write_private_json(container_intent_path"),
                        self.source.index('run(docker + ["run", "--detach"'))
        self.assertLess(self.source.index("write_private_json(child_intent_path"),
                        self.source.index("code = child.wait("))

    def test_actual_refund_suite_is_explicit_loopback_model_only(self):
        live = self.module.SUITES["refund-actual-8b"]
        self.assertEqual(live["stores"], self.module.SUITES["composition"]["stores"])
        self.assertEqual(live["env_prefix"], "PG_SECURESHOP_BOUND_REVIEW_COMPOSITION_")
        self.assertEqual(live["test"], self.module.SUITES["composition"]["test"])
        self.assertEqual(self.module.REFUND_MODEL, "llama3.1:8b")
        self.assertEqual(self.module.REFUND_OLLAMA_BASE_URL, "http://127.0.0.1:11434")
        self.assertEqual(len(self.module.REFUND_MODEL_DIGEST), 64)
        self.assertIn('SS_REFUND_LIVE_MODEL="1"', self.source)
        self.assertIn('OLLAMA_MODEL=REFUND_MODEL', self.source)
        self.assertIn('model_identity_before = read_refund_model_digest()', self.source)
        self.assertIn('model_identity_after = read_refund_model_digest()', self.source)
        self.assertIn('if args.suite in ("audit-composition", "composition", "refund-actual-8b",', self.source)


    def test_rendered_suite_requires_pin_and_private_owned_browser_record(self):
        rendered = self.module.SUITES["manual-rendered"]
        self.assertEqual(rendered["stores"], self.module.SUITES["composition"]["stores"])
        self.assertEqual(rendered["env_prefix"], "PG_SECURESHOP_BOUND_REVIEW_COMPOSITION_")
        self.assertIn('validate_executable(args.browser, args.browser_sha256, "Chromium")', self.source)
        self.assertIn('"manual-rendered": (("product-browser.json", "product_browser"),)', self.source)
        self.assertIn('SS_PRODUCT_BROWSER_RECORD_PATH=str(root / "product-browser.json")', self.source)
        self.assertIn('browser_tools.cleanup_browser_processes(records, browser, base_env)', self.source)
        self.assertIn('require_all=primary is None', self.source)
        self.assertIn('shutil.copytree(source / "client/build", workspace / "client/build")', self.source)


if __name__ == "__main__":
    unittest.main()
