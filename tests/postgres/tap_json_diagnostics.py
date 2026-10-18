"""Bounded decoding for JSON diagnostics carried by Node's TAP reporter."""

import json


MAX_TAP_JSON_LINE_BYTES = 131_072
MAX_TAP_JSON_TEXT_BYTES = 16 * 1024 * 1024
MAX_TAP_JSON_LINES = 100_000
MAX_SCOPED_REPORTS = 32
MAX_JSON_NODES = 10_000
MAX_JSON_DEPTH = 64


class TapJsonDiagnosticError(RuntimeError):
    """The input claimed to contain a JSON diagnostic but was not admissible."""


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise TapJsonDiagnosticError('Duplicate TAP JSON object key')
        value[key] = item
    return value


def _reject_constant(_value):
    raise TapJsonDiagnosticError('Nonfinite TAP JSON number')


def decode_tap_json_line(line, *, max_line_bytes=MAX_TAP_JSON_LINE_BYTES):
    """Decode one direct or TAP-commented JSON line, or return ``None``.

    Accepted reporter envelopes are exact and deliberately shallow:

    * ``{...}`` or ``[...]``
    * ``# {...}`` or ``# [...]``
    * ``# \\# {...}`` or ``# \\# [...]``

    Only those outer markers are removed. JSON backslashes, quotes, newlines and
    hash characters are left for ``json.loads`` so their values stay lossless.
    """
    if type(line) is not str or type(max_line_bytes) is not int \
            or not 1 <= max_line_bytes <= MAX_TAP_JSON_LINE_BYTES:
        raise TapJsonDiagnosticError('Invalid TAP JSON line contract')
    if '\n' in line or '\r' in line:
        raise TapJsonDiagnosticError('TAP JSON decoder requires one logical line')
    if len(line.encode('utf-8')) > max_line_bytes:
        raise TapJsonDiagnosticError('TAP JSON diagnostic line exceeds bound')

    # Node can indent diagnostics inside a subtest. Bound and remove only ASCII
    # indentation; never call strip() on the JSON payload itself.
    indent = len(line) - len(line.lstrip(' '))
    if indent > 8:
        return None
    candidate = line[indent:]
    # Node's assertion formatter emits multi-line JavaScript object diffs with
    # indented bare ``{`` / ``}`` lines. They are TAP diagnostic prose, not a
    # JSON reporter envelope. Indented machine diagnostics always retain a TAP
    # comment marker, so only unindented input may use the direct JSON form.
    if indent and not candidate.startswith('# '):
        return None
    if candidate.startswith('# '):
        candidate = candidate[2:]
        if candidate.startswith('\\# '):
            candidate = candidate[3:]
    if not candidate.startswith(('{', '[')):
        return None
    try:
        return json.loads(candidate, object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant)
    except (json.JSONDecodeError, RecursionError) as error:
        raise TapJsonDiagnosticError('Malformed TAP JSON diagnostic') from error


def iter_tap_json_diagnostics(text, *, max_line_bytes=MAX_TAP_JSON_LINE_BYTES,
                              max_lines=MAX_TAP_JSON_LINES,
                              max_text_bytes=MAX_TAP_JSON_TEXT_BYTES):
    """Yield every decoded JSON diagnostic from bounded TAP text."""
    if type(text) is not str or type(max_lines) is not int \
            or not 1 <= max_lines <= MAX_TAP_JSON_LINES \
            or type(max_text_bytes) is not int \
            or not 1 <= max_text_bytes <= MAX_TAP_JSON_TEXT_BYTES:
        raise TapJsonDiagnosticError('Invalid TAP JSON text contract')
    if len(text.encode('utf-8')) > max_text_bytes:
        raise TapJsonDiagnosticError('TAP output exceeds byte bound')
    lines = text.splitlines()
    if len(lines) > max_lines:
        raise TapJsonDiagnosticError('TAP output exceeds line bound')
    for line in lines:
        value = decode_tap_json_line(line, max_line_bytes=max_line_bytes)
        if value is not None:
            yield value


def _find_scope(value, scope, found, *, depth=0, budget=None,
                max_reports=MAX_SCOPED_REPORTS):
    if depth > MAX_JSON_DEPTH:
        raise TapJsonDiagnosticError('TAP JSON nesting exceeds bound')
    budget[0] += 1
    if budget[0] > MAX_JSON_NODES:
        raise TapJsonDiagnosticError('TAP JSON node count exceeds bound')
    if type(value) is dict:
        if value.get('scope') == scope:
            found.append(value)
            if len(found) > max_reports:
                raise TapJsonDiagnosticError('Scoped TAP report count exceeds bound')
        for child in value.values():
            _find_scope(child, scope, found, depth=depth + 1, budget=budget,
                        max_reports=max_reports)
    elif type(value) is list:
        for child in value:
            _find_scope(child, scope, found, depth=depth + 1, budget=budget,
                        max_reports=max_reports)


def scoped_tap_json_reports(text, scope, *, max_reports=MAX_SCOPED_REPORTS,
                            max_line_bytes=MAX_TAP_JSON_LINE_BYTES,
                            max_lines=MAX_TAP_JSON_LINES,
                            max_text_bytes=MAX_TAP_JSON_TEXT_BYTES):
    """Return bounded dicts whose exact ``scope`` occurs in TAP JSON values."""
    if type(scope) is not str or not scope or len(scope) > 256 \
            or type(max_reports) is not int or not 1 <= max_reports <= MAX_SCOPED_REPORTS:
        raise TapJsonDiagnosticError('Invalid scoped TAP report contract')
    found = []
    budget = [0]
    for value in iter_tap_json_diagnostics(
            text, max_line_bytes=max_line_bytes, max_lines=max_lines,
            max_text_bytes=max_text_bytes):
        _find_scope(value, scope, found, budget=budget, max_reports=max_reports)
    return found


def unique_scoped_tap_json_report(text, scope, *, required=False,
                                  max_line_bytes=MAX_TAP_JSON_LINE_BYTES,
                                  max_lines=MAX_TAP_JSON_LINES,
                                  max_text_bytes=MAX_TAP_JSON_TEXT_BYTES):
    """Return the sole exact scoped report; reject duplicates or absence if required."""
    if type(required) is not bool:
        raise TapJsonDiagnosticError('Required flag must be boolean')
    reports = scoped_tap_json_reports(
        text, scope, max_reports=2, max_line_bytes=max_line_bytes,
        max_lines=max_lines, max_text_bytes=max_text_bytes)
    if len(reports) > 1:
        raise TapJsonDiagnosticError('Duplicate scoped TAP JSON reports')
    if not reports:
        if required:
            raise TapJsonDiagnosticError('Required scoped TAP JSON report missing')
        return None
    return reports[0]
