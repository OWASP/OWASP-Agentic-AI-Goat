"""Pure process-selection rules for the MCP live promotion launcher."""

def select_backend_pid(records, *, watcher_pid, source, excluded_pid=None, require_running=False):
    matches = []
    for row in records:
        if not isinstance(row, dict) or not isinstance(row.get('pid'), int):
            continue
        state = str(row.get('state') or '')
        if (not state or state[0] not in 'DRSITtUXWZ'
                or row.get('ppid') != watcher_pid or row.get('cwd') != source
                or not str(row.get('command') or '').endswith('node server/index.js')
                or state.startswith('Z') or (require_running and state.startswith('T'))):
            continue
        if excluded_pid is not None and row['pid'] == excluded_pid:
            continue
        matches.append(row['pid'])
    if len(matches) != 1:
        raise RuntimeError('watcher does not have exactly one eligible backend child')
    return matches[0]
