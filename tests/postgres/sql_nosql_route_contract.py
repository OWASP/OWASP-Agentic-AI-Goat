"""Pure launch contract; importing this module performs no I/O."""
import json

OBJECTIVES = tuple([f'sqli_{n}' for n in range(1, 11)] + [f'nosqli_{n}' for n in range(1, 11)])
MODEL = 'llama3.1:8b'
MODEL_DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'


def selected_objectives(value):
    ids = value.split(',')
    if not ids or len(set(ids)) != len(ids) or any(item not in OBJECTIVES for item in ids):
        raise ValueError('Unique known objective IDs required')
    return tuple(item for item in OBJECTIVES if item in ids)


def cohort_timeout_seconds(ids, lifecycle=False, fixed_session=False, observation_controls=False, credit_gate=False):
    # Each case includes positive probes, ordinary admission, a separate
    # actor/Judge negative and post-reset chat. Reserve 20 minutes per case;
    # the launcher adds a separate two-minute process-cleanup margin.
    selected = selected_objectives(','.join(ids))
    if credit_gate:
        if lifecycle or fixed_session or observation_controls:
            raise ValueError('Credit gate cannot include unrelated qualification cohorts')
        # One actual actor/Judge route per selected objective. The scripted
        # canonical negative is provider-free and remains inside this budget.
        return 120 + 240 * len(selected)
    lifecycle_seconds = 300 * len({item.split('_', 1)[0] for item in selected}) if lifecycle else 0
    fixed_session_seconds = 1200 * len({item.split('_', 1)[0] for item in selected}) if fixed_session else 0
    control_count = (1 if any(item.startswith('sqli_') for item in selected) else 0) + (2 if any(item.startswith('nosqli_') for item in selected) else 0)
    observation_seconds = 300 * control_count if observation_controls else 0
    return 120 + 1200 * len(selected) + lifecycle_seconds + fixed_session_seconds + observation_seconds


def validate_model_inventory(text):
    inventory = json.loads(text)
    if not isinstance(inventory, dict) or not isinstance(inventory.get('models'), list):
        raise ValueError('Model inventory required')
    matches = [row for row in inventory['models']
               if isinstance(row, dict) and (row.get('name') == MODEL or row.get('model') == MODEL)]
    if len(matches) != 1 or matches[0].get('digest') != MODEL_DIGEST:
        raise ValueError('Exact pinned model digest required')
    if any(matches[0].get(key, MODEL) != MODEL for key in ('name', 'model')):
        raise ValueError('Conflicting model identity')
    return {'model': MODEL, 'digest': MODEL_DIGEST}
