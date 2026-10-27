#!/usr/bin/env python3
"""Closed V12 browser admission over unchanged full IDOR qualification."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
COHORT = 'customer-idor-lesson-browser'
TEST = 'tests/postgres/secureshopStandaloneIdorLessonRendered.integration.test.js'
HELPER = 'tests/fixtures/secureshopIdorBrowserAdmission.js'
CONTRACT = 'tests/secureshopIdorBrowserAdmission.test.js'
MAIN = 'tests/postgres/run-secureshop-agent-host-transport-main.py'
OWNERSHIP = 'tests/postgres/run-secureshop-audit-collection-browser.py'
PINS = {
    TEST: '821fa88682c7724d58fc34a1ba9fab53c775f31d8d36a82008679e1179e545e2',
    HELPER: 'a363bb1c04e0d3735825fb2d0a82932c49b4e7ee9372c4afd7f9f080436b68cb',
    CONTRACT: '229ada3c0dc75812a863abf0dfaee19c28842535ef72a9523c98dbd7cf00beb2',
    MAIN: 'e7c681bce87672d8c05752046eeffa5a92bfb0f2d4344eb9f5c9de107a66d808',
    OWNERSHIP: '9b7136fd685be5100660bc82b867b7f7923d1125d3b9470109b12dd1eac930b8',
}
CONTROL_SOURCES = (
    'tests/postgres/run-secureshop-idor-lesson-browser.py',
    'tests/postgres/run_idor_lesson_with_inspector.py',
    'tests/postgres/run_audit_collection_with_inspector.py',
    'tests/postgres/test_secureshop_idor_browser_admission.py',
    'tests/postgres/secureshop_bound_browser_ownership.py',
    'tests/postgres/secureshop_darwin_browser_birth.py',
    'tests/postgres/darwin_process_inventory.py',
    'tests/postgres/trusted_process_inspector.py',
    'tests/fixtures/secureshopDarwinBrowserBirth.js',
    'tasks/run-in-repository.sh',
)
RECORD = 'idor-lesson-browser.json'
ACK = 'idor-lesson-browser-ack.json'
KIND = 'idor_lesson_browser'
PROFILE = 'dvaia-customer-idor-browser-'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inventory():
    return {name: digest(ROOT / name) for name in (*PINS, *CONTROL_SOURCES)}


def validate_pins():
    for name, pin in PINS.items():
        path = ROOT / name
        if path.is_symlink() or path.resolve() != path or digest(path) != pin:
            raise RuntimeError(f'V12 frozen source mismatch: {name}')


def arguments(argv):
    values = list(argv)
    if values.count('--v12-test-no-sandbox') != 1:
        raise RuntimeError('Exactly one explicit V12 test-only exception required')
    values.remove('--v12-test-no-sandbox')
    if values.count('--cohort') != 1:
        raise RuntimeError('Exactly one full V12 cohort required')
    index = values.index('--cohort')
    if index + 1 == len(values) or values[index + 1] != COHORT:
        raise RuntimeError('Only full cart and order V12 cohort is admitted')
    return values


def direct_command(command, parsed):
    if list(command) != [parsed.node, '--test', '--test-reporter=tap',
                         '--test-concurrency=1', TEST]:
        raise RuntimeError('V12 original test command changed')
    return [parsed.node, '--test-reporter=tap', TEST]


def owned_environment(environment, parsed):
    env = dict(environment)
    if env.get('SECURESHOP_CUSTOMER_IDOR_LESSON_BROWSER_NATIVE') != '1' \
            or env.get('SECURESHOP_CUSTOMER_IDOR_CART_V10_ONLY'):
        raise RuntimeError('V12 full original native environment required')
    evidence = Path(env['SECURESHOP_CUSTOMER_IDOR_LESSON_EVIDENCE_PATH']).parent
    if evidence.parent != ROOT / 'tasks/qualification' or not evidence.name.startswith('run-'):
        raise RuntimeError('V12 evidence outside original owned run')
    env.update(
        SECURESHOP_IDOR_LESSON_TEST_NO_SANDBOX='1',
        SECURESHOP_IDOR_LESSON_BROWSER_RECORD_PATH=str(evidence / RECORD),
        SECURESHOP_IDOR_LESSON_BROWSER_ACK_PATH=str(evidence / ACK),
        SECURESHOP_IDOR_LESSON_BROWSER_SHA256=parsed.browser_sha256,
        SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT=str(ROOT / 'tests/postgres/secureshop_darwin_browser_birth.py'),
        SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON=str(Path(sys.executable).resolve()),
    )
    return env, evidence


class BrowserOwner:
    """Small V12 watcher; signal authority comes only from V36 live capture."""
    def __init__(self, original, parsed, ownership):
        self.original, self.parsed, self.ownership = original, parsed, ownership
        self.evidence = None
        self.captured = self.error = self.retired = None

    def __call__(self, command, *args, **kwargs):
        if TEST not in {str(item) for item in command}:
            return self.original(command, *args, **kwargs)
        command = direct_command(command, self.parsed)
        kwargs['env'], self.evidence = owned_environment(kwargs.get('env') or os.environ, self.parsed)
        child = self.original(command, *args, **kwargs)
        original_wait = child.wait

        def deferred_failure(error):
            self.error = error
            def fail_first_wait(*unused_args, **unused_kwargs):
                child.wait = original_wait
                raise error
            child.wait = fail_first_wait
            return child

        stop = None
        watcher = None
        started = False
        try:
            LibProc, zombie, _, read_record, _ = self.ownership._browser_modules()
            api = LibProc()
            node = api.identity(child.pid)
            if node is None or node.ppid != os.getpid() or node.uid != os.getuid() \
                    or node.ruid != os.getuid() or node.pgid != child.pid \
                    or os.getsid(child.pid) != child.pid or node.status == zombie:
                raise RuntimeError('V12 direct Node child birth unavailable')
            parent_birth = (node.start_sec, node.start_usec)
            stop = threading.Event()

            def watch():
                try:
                    record_path = self.evidence / RECORD
                    deadline = time.monotonic() + 60
                    while not stop.is_set() and time.monotonic() < deadline:
                        if not record_path.exists():
                            stop.wait(0.025)
                            continue
                        records = read_record(self.evidence, RECORD, KIND, self.parsed.browser,
                            self.parsed.browser_sha256, child.pid, parent_pid=child.pid,
                            require_all=True, allow_browser_session=True)
                        timed_capture = getattr(self.ownership, 'capture_live_v36_with_deadline', None)
                        if timed_capture is None:
                            self.captured = self.ownership.capture_live_v36(
                                records[0], parent_birth, self.evidence / 'runtime', api=api)
                        else:
                            self.captured = timed_capture(records[0], parent_birth,
                                self.evidence / 'runtime', api=api, deadline=deadline, stop=stop)
                        ack = {'schemaVersion': 1, 'recordSha256': digest(record_path),
                               'parentPid': child.pid, 'browserPid': records[0]['pid'],
                               'profile': self.captured.profile}
                        temporary = self.evidence / f'{ACK}.{os.getpid()}.tmp'
                        with temporary.open('x', encoding='utf-8') as handle:
                            os.chmod(temporary, 0o600)
                            json.dump(ack, handle, sort_keys=True, separators=(',', ':'))
                            handle.write('\n')
                        os.replace(temporary, self.evidence / ACK)
                        return
                    if not stop.is_set():
                        raise RuntimeError('V12 live browser birth record timed out')
                except BaseException as error:
                    self.error = error

            watcher = threading.Thread(target=watch, name='v12-browser-birth', daemon=True)
            watcher.start()
            started = True

            def wait(*wait_args, **wait_kwargs):
                primary = None
                try:
                    return original_wait(*wait_args, **wait_kwargs)
                except BaseException as error:
                    primary = error
                    raise
                finally:
                    try:
                        stop.set()
                        watcher.join(timeout=2)
                        if watcher.is_alive():
                            raise RuntimeError('V12 browser watcher did not stop')
                        if self.captured is not None:
                            self.retired = self.ownership.retire_live_v36(self.captured, api=api)
                    except BaseException as error:
                        self.error = self.error or error
                        if primary is None:
                            raise
            child.wait = wait
            return child
        except BaseException as error:
            try:
                if stop is not None:
                    stop.set()
                if started:
                    watcher.join(timeout=2)
            except BaseException:
                pass
            # Never throw after spawn before shared main has registered child.
            return deferred_failure(error)


def run(main, argv, parsed, ownership, before):
    original = main.subprocess.Popen
    owner = BrowserOwner(original, parsed, ownership)
    output = io.StringIO()
    main.subprocess.Popen = owner
    primary = None
    result = None
    try:
        with contextlib.redirect_stdout(output):
            code = main.main(argv)
        lines = [line for line in output.getvalue().splitlines() if line.strip()]
        result = json.loads(lines[-1])
        if code != 0 or result.get('passed') is not True:
            raise RuntimeError('V12 original qualification did not pass')
        if owner.error is not None or owner.captured is None:
            raise RuntimeError('V12 independent live capture incomplete') from owner.error
        _, _, _, _, absent = ownership._browser_modules()
        owner.retired = absent([owner.captured.record])
        if inventory() != before:
            raise RuntimeError('V12 source changed during qualification')
        return code
    except BaseException as error:
        primary = error
        raise
    finally:
        main.subprocess.Popen = original
        try:
            after = inventory()
            report = {'version': 1, 'cohort': COHORT, 'adapterPassed': primary is None,
                      'sourceBefore': before, 'sourceAfter': after, 'sourceUnchanged': before == after,
                      'mainOutputSha256': hashlib.sha256(output.getvalue().encode()).hexdigest(),
                      'browserCaptured': owner.captured is not None,
                      'browserRetirement': owner.retired,
                      'failure': None if primary is None else str(primary)[:1000],
                      'captureFailure': None if owner.error is None else str(owner.error)[:1000]}
            if owner.evidence is not None:
                main_result = owner.evidence / 'result.json'
                if main_result.is_file() and not main_result.is_symlink():
                    report['mainResult'] = json.loads(main_result.read_text())
                    report['mainResultSha256'] = digest(main_result)
                target = owner.evidence / 'v12-adapter-report.json'
                with target.open('x', encoding='utf-8') as handle:
                    os.chmod(target, 0o600)
                    json.dump(report, handle, sort_keys=True, separators=(',', ':'))
                    handle.write('\n')
            if primary is None and before != after:
                raise RuntimeError('V12 source changed during qualification')
            if primary is None:
                print(json.dumps(result))
        except BaseException:
            if primary is None:
                raise


def main(argv=None):
    validate_pins()
    before = inventory()
    values = arguments(sys.argv[1:] if argv is None else argv)
    shared = load(MAIN, 'v12_original_launcher')
    # This instance only; default shared launcher remains pinned and unchanged.
    if shared.IDOR_TEST != TEST or shared.IDOR_TEST_SHA256 != \
            PINS[TEST]:
        raise RuntimeError('V12 original shared admission changed')
    shared.IDOR_TEST_SHA256 = PINS[TEST]
    parsed = shared.parse(values)
    if Path(parsed.main_workspace).resolve() != ROOT or parsed.current_host_profile is None \
            or not parsed.browser or not parsed.browser_sha256:
        raise RuntimeError('V12 pinned current-main browser profile required')
    shared.validate_static(parsed)
    if parsed.plan:
        print(json.dumps({'cohort': COHORT, 'test': TEST, 'nativeStarted': False,
                          'sourceCopy': False, 'fullCartAndOrder': True, 'sourceInventory': before}))
        return 0
    if sys.platform != 'darwin':
        raise RuntimeError('V12 browser capture requires Darwin')
    ownership = load(OWNERSHIP, 'v12_independent_browser_ownership')
    ownership.PROFILE_PREFIX = PROFILE
    return run(shared, values, parsed, ownership, before)


if __name__ == '__main__':
    raise SystemExit(main())
