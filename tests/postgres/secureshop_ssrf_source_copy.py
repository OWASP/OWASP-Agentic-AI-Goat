"""Copy the complete controlled-SSRF qualifier source without private/runtime data."""
import shutil
from pathlib import Path

PRIVATE_SOURCE_PATHS = frozenset(('server/config/secrets.env', 'server/platform_secrets.json'))

DIRECTORIES = ('server', 'db', 'tests', 'docs', 'agent-host', 'client')
ROOT_FILES = ('package.json', 'package-lock.json')

def copy_ssrf_source(source, workspace, ignore):
    source = Path(source)
    private = {source / relative for relative in PRIVATE_SOURCE_PATHS}
    def guarded_ignore(directory, names):
        denied = set(ignore(directory, names))
        denied.update(name for name in names if Path(directory) / name in private)
        return sorted(denied)
    for directory in DIRECTORIES:
        shutil.copytree(source / directory, workspace / directory, ignore=guarded_ignore)
    for name in ROOT_FILES:
        shutil.copy2(source / name, workspace / name)
