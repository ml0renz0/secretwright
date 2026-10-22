#!/usr/bin/env python3
"""Private end-to-end session and controlling-terminal checks for the dev fixture."""

from pathlib import Path
import errno
import fcntl
import json
import os
import pty
import select
import signal
import stat
import struct
import subprocess
import sys
import termios
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class SmokeFailure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise SmokeFailure(message)


def private_write(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as target:
        target.write(data)


class TerminalSession:
    def __init__(self, binary, fixture, name, environment, args=()):
        self.master, self.slave = pty.openpty()
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack('HHHH', 30, 140, 0, 0))
        self.before = termios.tcgetattr(self.slave)
        self.output_path = fixture / (name + '-stdout.json')
        descriptor = os.open(self.output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.transcript = open(fixture / (name + '-terminal.txt'), 'xb')
        os.chmod(self.transcript.name, 0o600)
        self.buffer = b''
        self.status = None
        self.pid = os.fork()
        if self.pid == 0:
            try:
                os.close(self.master)
                os.setsid()
                fcntl.ioctl(self.slave, termios.TIOCSCTTY, 0)
                os.dup2(self.slave, 0)
                os.dup2(descriptor, 1)
                os.dup2(self.slave, 2)
                if self.slave > 2:
                    os.close(self.slave)
                if descriptor > 2:
                    os.close(descriptor)
                os.chdir(fixture)
                os.execve(str(binary), [str(binary), *args], environment)
            except BaseException:
                os._exit(125)
        os.close(descriptor)
        os.set_blocking(self.master, False)

    def write(self, data):
        os.write(self.master, data)

    def _read(self, timeout):
        readable, _, _ = select.select([self.master], [], [], timeout)
        if not readable:
            return b''
        try:
            data = os.read(self.master, 65536)
        except OSError as error:
            if error.errno in (errno.EAGAIN, errno.EIO):
                return b''
            raise
        self.transcript.write(data)
        self.transcript.flush()
        self.buffer += data
        return data

    def until(self, marker, timeout=8):
        deadline = time.monotonic() + timeout
        while marker not in self.buffer:
            if time.monotonic() >= deadline:
                raise SmokeFailure('Terminal session did not reach its expected state.')
            self._read(min(0.1, max(0, deadline - time.monotonic())))
            if self.poll() is not None and marker not in self.buffer:
                raise SmokeFailure('Terminal session exited before its expected state.')
        end = self.buffer.index(marker) + len(marker)
        result, self.buffer = self.buffer[:end], self.buffer[end:]
        return result

    def prompt(self, cwd='/'):
        return self.until(('secretwright:' + cwd + '> ').encode())

    def poll(self):
        if self.status is None:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.status = os.waitstatus_to_exitcode(status)
        return self.status

    def finish(self, expected=0):
        deadline = time.monotonic() + 8
        while self.poll() is None and time.monotonic() < deadline:
            self._read(0.05)
        require(self.status == expected, 'Terminal session did not return its expected exit code.')
        after = termios.tcgetattr(self.slave)
        mask = termios.ICANON | termios.ECHO | termios.ISIG
        require((after[3] & mask) == (self.before[3] & mask), 'Terminal session did not restore terminal settings.')

    def close(self):
        if self.poll() is None:
            try:
                os.killpg(self.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(self.pid, 0)
        self.transcript.close()
        os.close(self.master)
        os.close(self.slave)


def decode_outputs(path):
    source = path.read_text()
    decoder = json.JSONDecoder()
    values = []
    while source.strip():
        source = source.lstrip()
        value, end = decoder.raw_decode(source)
        values.append(value)
        source = source[end:]
    return values


def main():
    binary = Path(sys.argv[1]).resolve()
    fixture = Path(sys.argv[2]).resolve()
    address = os.environ['VAULT_ADDR']
    root_token = (fixture / 'root-token').read_text().strip()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def provision(path, payload):
        message = urllib.request.Request(address + '/v1/' + path, data=json.dumps(payload).encode(), method='POST')
        message.add_header('X-Vault-Token', root_token)
        message.add_header('Content-Type', 'application/json')
        with opener.open(message, timeout=5) as response:
            data = response.read()
            return json.loads(data) if data else None

    mount = 'f04-smoke-kv'
    provision('sys/mounts/' + mount, {'type': 'kv', 'options': {'version': '2'}})
    for key in ['database', 'nested/item']:
        provision(mount + '/data/allowed/' + key, {'data': {'value': 'private-f04-terminal-value'}})
    policy = '\n'.join([
        'path "' + mount + '/data/allowed/*" { capabilities = ["read"] }',
        'path "' + mount + '/metadata/allowed" { capabilities = ["list"] }',
        'path "' + mount + '/metadata/allowed/*" { capabilities = ["list"] }',
    ])
    provision('sys/policies/acl/f04-smoke', {'policy': policy})
    response = provision('auth/token/create', {'policies': ['f04-smoke'], 'no_default_policy': True, 'ttl': '2m'})
    token = response['auth']['client_token']
    token_file = fixture / 'f04-token'
    private_write(token_file, token.encode())
    environment = dict(os.environ)
    environment['VAULT_TOKEN'] = token
    environment['TERM'] = 'xterm'
    cwd = '/' + mount + '/allowed'

    commands = 'cd ' + cwd + '\npwd\nls\nhistory\n'
    script = fixture / 'f04-operations with spaces.sw'
    private_write(script, commands.encode())
    for name, args, source in [
        ('f04-batch', ['shell', '--no-prompt', '--token-file', str(token_file)], commands.encode()),
        ('f04-script', ['--script', str(script), '--token-file', str(token_file)], b'unread-private-command\n'),
    ]:
        output_file = fixture / (name + '.json')
        error_file = fixture / (name + '.err')
        with open(output_file, 'xb') as output, open(error_file, 'xb') as error:
            os.chmod(output_file, 0o600)
            os.chmod(error_file, 0o600)
            result = subprocess.run([str(binary), *args], input=source, stdout=output, stderr=error, env=environment, timeout=10)
        require(result.returncode == 0 and error_file.read_bytes() == b'', 'Batch shell emitted a prompt or failed to execute its script.')
        values = decode_outputs(output_file)
        require(values == [{'path': cwd}, {'path': cwd}, ['database', 'nested/'], ['cd ' + cwd, 'pwd', 'ls']], 'Batch shell changed cwd, JSON, or its safe history.')

    session = TerminalSession(binary, fixture, 'f04-interactive', environment)
    try:
        session.prompt()
        session.write(('cd ' + cwd + '\r').encode())
        session.prompt(cwd)
        session.write(b'ls dat\t')
        session.until(b'database')
        session.write(b'\x03')
        session.prompt(cwd)
        session.write(b'pwd\r')
        session.prompt(cwd)
        # Edit an approved history entry into a rejected line. Autosave and the
        # library's temporary history entry must not make it searchable later.
        session.write(b'\x1b[A\x15bad-command unretained-fragment\r')
        session.prompt(cwd)
        session.write(b'history\r')
        session.prompt(cwd)
        session.write(b'\x12unretained-fragment')
        search = session.until(b'unretained-fragment')
        session._read(0.15)
        require(b'bad-command' not in search + session.buffer, 'Reverse history search retained a rejected command.')
        session.write(b'\x03')
        session.prompt(cwd)
        session.write(b'\x12pwd\r')
        session.prompt(cwd)
        session.write(b'pwd\r')
        session.prompt(cwd)
        session.write(b'\x04')
        session.finish()
        outputs = decode_outputs(session.output_path)
        require(outputs[0] == {'path': cwd} and outputs[-1] == {'path': cwd}, 'Interactive shell lost its session directory or safe search result.')
        histories = [value for value in outputs if isinstance(value, list)]
        require(histories and all('bad-command' not in entry and 'unretained-fragment' not in entry for entries in histories for entry in entries), 'Interactive history retained rejected input.')
    finally:
        session.close()

    entered = threading.Event()
    release = threading.Event()

    class SlowVault(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            if self.path.startswith('/v1/sys/internal/ui/mounts/'):
                body = json.dumps({'data': {'path': 'secret/', 'type': 'kv', 'options': {'version': '2'}}}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path == '/v1/secret/data/slow':
                entered.set()
                release.wait(10)
            try:
                self.send_response(404)
                self.end_headers()
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), SlowVault)
    server.daemon_threads = True
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    cancellation_env = dict(environment)
    cancellation_env['VAULT_ADDR'] = 'http://127.0.0.1:' + str(server.server_address[1])
    canceled = TerminalSession(binary, fixture, 'f04-interrupt', cancellation_env, ['shell', '--timeout', '5s'])
    try:
        canceled.prompt()
        canceled.write(b'cat /secret/slow\r')
        require(entered.wait(5), 'Cancellation test did not reach its in-flight request.')
        os.killpg(canceled.pid, signal.SIGINT)
        canceled.prompt()
        canceled.write(b'pwd\r')
        canceled.prompt()
        canceled.write(b'\x04')
        canceled.finish()
        require(decode_outputs(canceled.output_path) == [{'path': '/'}], 'Interrupting an HTTP command ended the session or emitted secret data.')
    finally:
        release.set()
        canceled.close()
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)

    for path in fixture.glob('f04-*'):
        if not path.is_file():
            continue
        require(stat.S_IMODE(path.stat().st_mode) == 0o600, 'Shell smoke created a non-private capture.')
        if path == token_file:
            continue
        data = path.read_bytes()
        require(token.encode() not in data and root_token.encode() not in data, 'Shell smoke exposed a credential.')
        require(b'private-f04-terminal-value' not in data, 'Shell completion or history exposed a secret value.')
    print('CLI shell smoke passed: batch, script, PTY navigation, Tab, safe Ctrl-R and interrupts.')


if __name__ == '__main__':
    try:
        main()
    except SmokeFailure as error:
        raise SystemExit(str(error)) from None
    except Exception:
        raise SystemExit('Could not complete the private shell smoke fixture.') from None
