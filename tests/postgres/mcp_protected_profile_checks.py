"""Exact qualification checks for the reviewed parent + bwrap profile tree."""
import re

def expected_profiles(rendered, parent):
    if not re.fullmatch(r'owasp-ai-goat-mcp-sandbox-[a-f0-9]{12}', parent):
        raise ValueError('invalid owned profile name')
    declarations = re.findall(r'^\s*profile\s+(?:"([^"\n]+)"|([^\s{]+))\s+flags=', rendered, re.M)
    names = [quoted or bare for quoted, bare in declarations]
    if names != [parent, 'bwrap']:
        raise ValueError('unreviewed rendered profile declarations')
    return {parent, parent + '//bwrap'}

def owned_profile_lines(listing, parent):
    # Include malformed modes and undeclared descendants so they cannot be ignored.
    return [line.strip() for line in listing.splitlines()
            if line.strip().startswith(parent + ' ') or line.strip().startswith(parent + '//')]

def assert_enforcing(listing, expected, parent):
    lines = owned_profile_lines(listing, parent)
    if len(lines) != len(expected) or set(lines) != {name + ' (enforce)' for name in expected}:
        raise ValueError('owned profile tree does not exactly match enforcing declarations')
    return sorted(lines)

def assert_absent(listing, expected, parent):
    if owned_profile_lines(listing, parent):
        raise ValueError('owned parent or descendant profile remains')
    return {name: True for name in sorted(expected)}
