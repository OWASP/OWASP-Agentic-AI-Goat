"""Pure ownership cleanup orchestration for the XSS isolated launcher."""


def cleanup_owned_containers(names, inspect, remove, absent):
    """Clean captured owned containers, continuing after independent failures.

    ``inspect`` returns a captured identity mapping or ``None`` for exact
    absence, and must raise for an identity mismatch. ``remove`` and ``absent``
    receive the name and captured identity.
    """
    failures = []
    results = []
    for name in reversed(tuple(names)):
        try:
            row = inspect(name)
        except Exception as error:
            failures.append(f'{name}:identity:{type(error).__name__}')
            continue
        if row is None:
            results.append({'name': name, 'status': 'absent'})
            continue
        captured_id = row.get('id') if isinstance(row, dict) else None
        if not captured_id:
            failures.append(f'{name}:identity:missing_id')
            continue
        try:
            remove(name, captured_id)
        except Exception as error:
            failures.append(f'{name}:remove:{type(error).__name__}')
            continue
        try:
            is_absent = absent(name, captured_id)
        except Exception as error:
            failures.append(f'{name}:absence:{type(error).__name__}')
            continue
        if is_absent is not True:
            failures.append(f'container still exists: {name}')
        else:
            results.append({'name': name, 'status': 'removed_absence_verified', 'containerId': captured_id})
    return results, failures
