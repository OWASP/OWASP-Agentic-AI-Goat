"""Prepare only an explicitly hash-reviewed synthetic runner build context.

No Docker, subprocess, network, private host fixtures, or dependency discovery.
The exact labfs allowlist is synthetic teaching material, including its named .env;
callers must supply reviewed SHA256 for every file before any copy is attempted.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

FILES = frozenset('''Dockerfile
package.json
index.js
mcpTargets.js
mcpProtectedState.js
mcpPackageCatalog.js
ownedTargetApi.js
mcpSeccompFilter.c
mcpSeccompProbe.c
entrypoint.sh
labfs/etc/hosts.lab
labfs/etc/passwd
labfs/opt/app/server.js
labfs/opt/app/package.json
labfs/opt/lab/bin/malicious_postinstall.sh
labfs/opt/lab/bin/rotate_keys.sh
labfs/opt/lab/packages/acme-analytics-1.0.0.tgz.sig
labfs/opt/lab/packages/analytics-boost-1.0.0.tgz
labfs/opt/lab/packages/acme-analytics-1.0.0.tgz
labfs/opt/lab/packages/acme-package-signing-public.pem
labfs/opt/app/config/mcp.yml
labfs/opt/app/config/database.yml
labfs/opt/app/config/.env
labfs/var/secrets/master_key.txt
labfs/var/secrets/credentials.json
labfs/var/log/syslog
labfs/home/mcp-admin/notes.txt
labfs/home/mcp-admin/readme.txt
labfs/home/mcp-admin/.bash_history'''.splitlines())
SHA = re.compile(r'^[a-f0-9]{64}$')

def sha(data):return hashlib.sha256(data).hexdigest()
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()

def open_source_root(source):
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in source.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        return directory
    except BaseException:
        os.close(directory)
        raise


def read_owned_input(root_fd, name):
    """Walk only held directory descriptors; never follow a replaced symlink."""
    directory = os.dup(root_fd)
    try:
        parts = name.split('/')
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            if not stat.S_ISREG(os.fstat(leaf).st_mode):
                raise RuntimeError('Regular build input required')
            with os.fdopen(leaf, 'rb', closefd=False) as stream:
                return stream.read()
        finally:
            os.close(leaf)
    except OSError as error:
        raise RuntimeError('Missing or symlinked build input') from error
    finally:
        os.close(directory)


def prepare_context(source, destination, expected_files):
    """Return manifest identity. Destination is an explicit empty owned directory.

    source is the reviewed sandbox-runner root; expected_files is exactly FILES
    mapped to SHA256. Manifest is outside context, so it is not a Docker input.
    Normalized mode/mtime and ordered manifest make repeated preparation identical.
    """
    source,destination=Path(source),Path(destination)
    for path in [source,destination]:
        if not path.is_absolute() or path.resolve()!=path or path.is_symlink() or not path.is_dir():
            raise RuntimeError('Absolute real directories required')
    if (destination.stat().st_uid!=os.getuid() or stat.S_IMODE(destination.stat().st_mode)!=0o700
            or any(destination.iterdir())
            or destination.is_relative_to(source) or source.is_relative_to(destination)):
        raise RuntimeError('Separate empty owned destination required')
    if type(expected_files) is not dict or set(expected_files)!=FILES or any(not isinstance(h,str) or not SHA.fullmatch(h) for h in expected_files.values()):
        raise RuntimeError('Exact reviewed build file hashes required')
    # Validate every byte first. Never recursively copy the input tree.
    contents={}
    root_fd = open_source_root(source)
    try:
        for name in sorted(FILES):
            data=read_owned_input(root_fd,name)
            if sha(data)!=expected_files[name]:raise RuntimeError('Build input hash mismatch')
            contents[name]=data
    finally:
        os.close(root_fd)
    manifest={'version':1,'scope':'mcp_strict_runner_build_context','files':{
        name:{'sha256':sha(data),'bytes':len(data),'mode':0o555 if name.endswith('.sh') else 0o444}
        for name,data in contents.items()}}
    encoded=canonical(manifest);context=destination/'context';context.mkdir(mode=0o700)
    for name,data in contents.items():
        path=context/name;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as output:output.write(data)
        path.chmod(manifest['files'][name]['mode']);os.utime(path,(0,0))
    for path in sorted(context.rglob('*'),key=lambda p:len(p.parts),reverse=True):
        if path.is_dir():path.chmod(0o555);os.utime(path,(0,0))
    context.chmod(0o555);os.utime(context,(0,0))
    output=destination/'context-manifest.json';output.write_bytes(encoded);output.chmod(0o444);os.utime(output,(0,0))
    destination.chmod(0o555)
    return {'context':str(context),'manifest':str(output),'contextSha256':sha(encoded),'fileCount':len(FILES)}
