def parse_pg_boolean(value):
    if value == 'true':
        return True
    if value == 'false':
        return False
    raise RuntimeError('PostgreSQL boolean text is invalid')
