"""Compare a canonical Judge generation with its PostgreSQL bigint projection."""

import re


MAX_SAFE_GENERATION = 9007199254740991
CANONICAL_DECIMAL = re.compile(r'[1-9][0-9]*', re.ASCII)


def same_scene_generation(packet_value, sql_value):
    """Accept only the same positive, JSON-safe generation in its two native types."""
    return (
        type(packet_value) is int
        and 1 <= packet_value <= MAX_SAFE_GENERATION
        and type(sql_value) is str
        and CANONICAL_DECIMAL.fullmatch(sql_value) is not None
        and str(packet_value) == sql_value
    )
