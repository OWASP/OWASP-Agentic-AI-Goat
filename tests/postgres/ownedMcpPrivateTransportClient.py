"""Fixed guest-only transport probe. Importing this file performs no I/O."""
import hashlib
import json
import os
import re
import signal
import socket
import ssl
import sys
import time

CASES = {
    'registry': ('registry-1.docker.io', '/v2/', 401),
    'auth': ('auth.docker.io', '/token?service=registry.docker.io', 200),
    'debian': ('deb.debian.org', '/debian/README', 200),
}
BODY_LIMIT = 65536


def require(condition, code):
    if not condition:
        raise RuntimeError(code)


def headers(reader):
    lines = []
    size = 0
    while True:
        line = reader.readline(8193)
        size += len(line)
        require(line.endswith(b'\r\n') and len(line) <= 8192 and size <= 16384, 'HTTP_HEADERS')
        if line == b'\r\n':
            return lines
        lines.append(line[:-2])


def body_digest(reader, fields):
    count = 0
    digest = hashlib.sha256()
    def consume(data):
        nonlocal count
        count += len(data)
        require(count <= BODY_LIMIT, 'HTTP_BODY_LIMIT')
        digest.update(data)
    def exact(length):
        require(0 <= length <= BODY_LIMIT-count, 'HTTP_BODY_LIMIT')
        while length:
            chunk = reader.read(min(length, 8192))
            require(bool(chunk), 'HTTP_TRUNCATED')
            consume(chunk)
            length -= len(chunk)
    require(not ('transfer-encoding' in fields and 'content-length' in fields), 'HTTP_FRAMING')
    if 'transfer-encoding' in fields:
        require(fields['transfer-encoding'].lower() == 'chunked', 'HTTP_FRAMING')
        while True:
            line = reader.readline(130)
            require(re.fullmatch(b'[0-9a-fA-F]{1,8}\r\n', line) is not None, 'HTTP_CHUNK')
            length = int(line[:-2], 16)
            if not length:
                headers(reader)
                break
            exact(length)
            require(reader.read(2) == b'\r\n', 'HTTP_CHUNK')
    elif 'content-length' in fields:
        require(re.fullmatch('[0-9]{1,8}', fields['content-length']) is not None, 'HTTP_FRAMING')
        exact(int(fields['content-length']))
    else:
        while True:
            chunk = reader.read(8192)
            if not chunk:
                break
            consume(chunk)
    return count, digest.hexdigest()


def execute(case, port, directory, namespace, deadline):
    require(case in {*CASES, 'deny-peer', 'deny-host'}, 'CASE')
    require(type(port) is int and 1 <= port <= 65535, 'PORT')
    require(re.fullmatch('/var/tmp/owasp-ai-goat-v23-relay-[a-f0-9]{32}', directory) is not None, 'DIRECTORY')
    require(re.fullmatch(r'net:\[[1-9][0-9]*\]', namespace) is not None
            and os.readlink('/proc/self/ns/net') == namespace, 'NAMESPACE')
    require(os.geteuid() == (0 if case == 'deny-peer' else 501), 'UID')
    if case != 'deny-peer':
        require(os.getegid() == 1000 and os.getgroups() == [], 'GID_GROUPS')
    require(0 < deadline-time.monotonic() <= 300, 'DEADLINE')
    end = min(deadline, time.monotonic()+10)
    def expired(_signum, _frame):
        raise TimeoutError('TRANSPORT_DEADLINE')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, end-time.monotonic())
    def timeout(sock):
        left = end-time.monotonic()
        require(left > 0, 'DEADLINE')
        sock.settimeout(min(left, 5))
    raw = secure = reader = None
    try:
        raw = socket.socket(socket.AF_UNIX if case == 'deny-peer' else socket.AF_INET, socket.SOCK_STREAM)
        timeout(raw)
        raw.connect(directory+'/connector.sock' if case == 'deny-peer' else ('127.0.0.1', port))
        if case == 'deny-peer':
            # Root can open 0600 Unix sockets, but must fail the real SO_PEERCRED
            # check. Do not chmod either the private directory or its socket.
            try:
                data = raw.recv(1024)
            except ConnectionResetError:
                data = b''
            require(data == b'', 'PEER_NOT_DENIED')
            return {'case': case, 'denied': True, 'effectiveUid': os.geteuid(), 'responseBytes': 0}
        host = 'unadmitted.invalid' if case == 'deny-host' else CASES[case][0]
        raw.sendall(('CONNECT '+host+':443 HTTP/1.1\r\nHost: '+host+':443\r\n\r\n').encode())
        if case == 'deny-host':
            try:
                data = raw.recv(1024)
            except ConnectionResetError:
                data = b''
            require(data == b'', 'HOST_NOT_DENIED')
            return {'case': case, 'denied': True, 'effectiveUid': os.geteuid(), 'responseBytes': 0}
        response = bytearray()
        while not response.endswith(b'\r\n\r\n'):
            timeout(raw)
            chunk = raw.recv(1)
            require(bool(chunk) and len(response) < 8192, 'CONNECT_RESPONSE')
            response.extend(chunk)
        require(bytes(response) == b'HTTP/1.1 200 Connection Established\r\n\r\n', 'CONNECT_RESPONSE')
        context = ssl.create_default_context()
        timeout(raw)
        secure = context.wrap_socket(raw, server_hostname=host)
        timeout(secure)
        certificate = hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest()
        secure.sendall(('GET '+CASES[case][1]+' HTTP/1.1\r\nHost: '+host+'\r\nConnection: close\r\n\r\n').encode())
        reader = secure.makefile('rb')
        lines = headers(reader)
        require(bool(lines) and re.fullmatch(rb'HTTP/1\.[01] [0-9]{3} [\x20-\x7e]*', lines[0]) is not None, 'HTTP_STATUS')
        status = int(lines[0].split(b' ')[1])
        require(status == CASES[case][2], 'HTTP_STATUS')
        fields = {}
        for line in lines[1:]:
            name, separator, value = line.partition(b':')
            require(separator and re.fullmatch(b'[A-Za-z0-9-]+', name) is not None, 'HTTP_HEADERS')
            key = name.decode().lower()
            # Only framing fields are retained even transiently; never print
            # response headers, bearer tokens, or plaintext response bodies.
            if key in ('content-length', 'transfer-encoding'):
                require(key not in fields, 'HTTP_FRAMING')
                fields[key] = value.strip().decode('ascii')
        count, digest = body_digest(reader, fields)
        require(reader.read(1) == b'', 'HTTP_TRAILING_DATA')
        return {'case': case, 'host': host, 'path': CASES[case][1], 'status': status,
            'bodyBytes': count, 'bodySha256': digest, 'certificateSha256': certificate,
            'tlsVerified': True, 'tlsVersion': secure.version(), 'effectiveUid': os.geteuid()}
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        close_errors = []
        for item in (reader, secure, raw):
            if item:
                try:
                    item.close()
                except Exception:
                    close_errors.append(True)
        require(not close_errors, 'CLIENT_CLOSE_UNVERIFIED')


def main():
    try:
        require(len(sys.argv) == 6, 'ARGUMENTS')
        value = execute(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], float(sys.argv[5]))
        print(json.dumps({'version': 1, 'ok': True, 'closed': True, 'result': value}, sort_keys=True))
        return 0
    except Exception as error:
        code = str(error) if type(error) is RuntimeError and re.fullmatch('[A-Z_]{1,32}', str(error)) else 'TRANSPORT_FAILED'
        print(json.dumps({'version': 1, 'ok': False, 'error': code}, sort_keys=True))
        return 1


if __name__ == '__main__':
    sys.exit(main())
