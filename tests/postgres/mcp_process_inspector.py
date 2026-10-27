"""Read-only, outside-sandbox browser process check for one owned MCP run."""

import json
import os
from pathlib import Path
import re
import stat

from darwin_process_inventory import LibProc
from trusted_process_inspector import _exact, inspect_absence, private_directory


class McpInspector:
    def __init__(self, repo, child_pid, *, api=None, inspect=inspect_absence):
        self.repo = Path(repo).resolve()
        self.child_pid = child_pid
        self.api = api or LibProc()
        self.inspect = inspect
        self.sequence = 0
        self.nonces = set()
        self.binding = None
        self.birth = None
        self.verify_child()

    def verify_child(self):
        row = self.api.identity(self.child_pid)
        if row is None or row.ppid != os.getpid() or row.uid != os.getuid() \
                or row.ruid != os.getuid():
            raise RuntimeError('MCP inspector no longer owns the same-user launcher')
        birth = (row.start_sec, row.start_usec)
        if self.birth is not None and self.birth != birth:
            raise RuntimeError('MCP inspector launcher PID was reused')
        self.birth = birth

    def scope(self, request):
        root = Path(request['runtime'])
        parent = self.repo / 'tasks' / 'qualification'
        try:
            relative = root.relative_to(parent)
        except ValueError as exc:
            raise RuntimeError('MCP inspector root outside checkout qualification') from exc
        if len(relative.parts) != 1 or not re.fullmatch(
                r'dvaia-mcp-assembly-[A-Za-z0-9_-]{8,12}', relative.parts[0]):
            raise RuntimeError('Unsupported MCP inspector root')
        if request['mode'] != 'mcp-browser-root' or request['identity'] != {}:
            raise RuntimeError('Unsupported MCP inspector operation')
        private_directory(parent)
        private_directory(root)
        journal = root / 'ownership.json'
        before = journal.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() \
                or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600 \
                or not 0 < before.st_size <= 1048576:
            raise RuntimeError('Private MCP ownership record required')
        value = json.loads(journal.read_text())
        after = journal.lstat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != \
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise RuntimeError('MCP ownership record changed during inspection')
        owner, profile = value.get('owner'), value.get('profile')
        if value.get('root') != str(root) or value.get('launcherPid') != self.child_pid \
                or not isinstance(owner, str) or not re.fullmatch(r'[a-f0-9]{32}', owner) \
                or not isinstance(profile, str) or not re.fullmatch(
                    r'dvaia-owned-mcp-registry-[a-f0-9]{12}', profile):
            raise RuntimeError('MCP ownership record binding mismatch')
        binding = (str(root), owner, profile)
        if self.binding is not None and binding != self.binding:
            raise RuntimeError('MCP inspector ownership changed')
        self.binding = binding
        return root

    def handle(self, request):
        _exact(request, ('version', 'sequence', 'nonce', 'pid', 'runtime', 'mode', 'identity'))
        if type(request['version']) is not int or request['version'] != 1 \
                or type(request['sequence']) is not int or request['sequence'] != self.sequence + 1 \
                or type(request['pid']) is not int or request['pid'] != self.child_pid \
                or not isinstance(request['nonce'], str) \
                or not re.fullmatch(r'[a-f0-9]{64}', request['nonce']) \
                or request['nonce'] in self.nonces or not isinstance(request['runtime'], str):
            raise RuntimeError('MCP inspector request identity or replay violation')
        self.verify_child()
        root = self.scope(request)
        self.sequence += 1
        self.nonces.add(request['nonce'])
        absent = self.inspect(root, None, required_pid=self.child_pid)
        self.verify_child()
        return {'request': request, 'absent': absent, 'error': None}
