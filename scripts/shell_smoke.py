#!/usr/bin/env python3
"""Private end-to-end session and controlling-terminal checks for the dev fixture."""

from pathlib import Path
import errno
import fcntl
import json
import os
import pty
import re
import select
import signal
import stat
import struct
import subprocess
import sys
import termios
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class SmokeFailure(Exception):
    pass


SMOKE_STAGE = 'startup'


def smoke_stage(value):
    global SMOKE_STAGE
    SMOKE_STAGE = value


def safe_exception_details(error):
    lines = []
    frame = error.__traceback__
    while frame is not None:
        if frame.tb_frame.f_code.co_filename == __file__:
            lines.append(str(frame.tb_lineno))
        frame = frame.tb_next
    return 'stage=' + SMOKE_STAGE + '; class=' + type(error).__name__ + '; script_lines=' + ','.join(lines)


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

    def prompt(self, cwd='/', status=None):
        # Readline redraws the prompt before every edited character. A prompt
        # substring alone therefore does not show that a command finished.
        # Require a clean input line, and use execution barriers at call sites.
        code = rb'[0-9]+' if status is None else str(status).encode()
        marker = rb'\[' + code + rb'\] ' + re.escape(('secretwright:' + cwd + '> ').encode())
        deadline = time.monotonic() + 8
        while True:
            plain = re.sub(rb'\x1b\[[0-?]*[ -/]*[@-~]', b'', self.buffer)
            tail = re.split(rb'[\r\n]', plain)[-1]
            # readline's runebuf.output appends a space and backspace when
            # its final input line is empty. It moves the cursor back while
            # leaving a blank cell; this is still an empty editing prompt.
            if re.fullmatch(marker + rb'(?: \x08)?', tail):
                result, self.buffer = self.buffer, b''
                return result
            require(time.monotonic() < deadline, 'Terminal session did not reach an empty command prompt.')
            self._read(0.05)
            require(self.poll() is None, 'Terminal session exited before its command prompt.')

    def wait_outputs(self, count):
        deadline = time.monotonic() + 8
        while True:
            try:
                values = decode_outputs(self.output_path)
            except json.JSONDecodeError:
                values = []
            if len(values) >= count:
                require(len(values) == count, 'Terminal session executed an unexpected additional command.')
                return values
            require(time.monotonic() < deadline, 'Terminal command did not produce its expected JSON result.')
            self._read(0.05)
            require(self.poll() is None, 'Terminal session exited before its JSON result.')

    def drain(self):
        # Called after a semantic execution barrier: discard already queued
        # redraws so the next search assertion cannot inspect earlier input.
        while select.select([self.master], [], [], 0)[0]:
            if not self._read(0):
                break
        result, self.buffer = self.buffer, b''
        return result

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
    smoke_stage('fixture-startup')
    binary = Path(sys.argv[1]).resolve()
    fixture = Path(sys.argv[2]).resolve()
    address = os.environ['VAULT_ADDR']
    root_token = (fixture / 'root-token').read_text().strip()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def provision(path, payload):
        encoded_path = urllib.parse.quote(path, safe='/')
        message = urllib.request.Request(address + '/v1/' + encoded_path, data=json.dumps(payload).encode(), method='POST')
        message.add_header('X-Vault-Token', root_token)
        message.add_header('Content-Type', 'application/json')
        with opener.open(message, timeout=5) as response:
            data = response.read()
            return json.loads(data) if data else None

    mount = 'f04-smoke-kv'
    provision('sys/mounts/' + mount, {'type': 'kv', 'options': {'version': '2'}})
    smoke_stage('fixture-seed')
    for key in [
        'database', 'nested/item',
        'nested/秘密/apple/item', 'nested/秘密/azure/item',
        'nested/long/x' + 'a' * 199 + '/item',
        'nested/long/x' + 'b' * 199 + '/item',
    ]:
        provision(mount + '/data/allowed/' + key, {'data': {'value': 'private-f04-terminal-value'}})
    policy = '\n'.join([
        'path "' + mount + '/data/allowed/*" { capabilities = ["read"] }',
        'path "' + mount + '/metadata/allowed" { capabilities = ["list"] }',
        'path "' + mount + '/metadata/allowed/*" { capabilities = ["list"] }',
    ])
    smoke_stage('fixture-credential')
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
        smoke_stage(name)
        output_file = fixture / (name + '.json')
        error_file = fixture / (name + '.err')
        with open(output_file, 'xb') as output, open(error_file, 'xb') as error:
            os.chmod(output_file, 0o600)
            os.chmod(error_file, 0o600)
            result = subprocess.run([str(binary), *args], input=source, stdout=output, stderr=error, env=environment, timeout=10)
        require(result.returncode == 0 and error_file.read_bytes() == b'', 'Batch shell emitted a prompt or failed to execute its script.')
        values = decode_outputs(output_file)
        require(values == [{'path': cwd}, {'path': cwd}, ['database', 'nested/'], ['cd ' + cwd, 'pwd', 'ls']], 'Batch shell changed cwd, JSON, or its safe history.')

    smoke_stage('terminal-startup')
    session = TerminalSession(binary, fixture, 'f04-interactive', environment)
    try:
        session.prompt(status=0)
        smoke_stage('terminal-directory')
        session.write(('cd ' + cwd + '\r').encode())
        output_count = 1
        session.wait_outputs(output_count)
        session.prompt(cwd, status=0)
        smoke_stage('terminal-suspend-paste')
        session.write(b'\x1apwd\rpwd\r')
        output_count += 2
        pasted = session.wait_outputs(output_count)
        require(pasted[-2:] == [{'path': cwd}, {'path': cwd}], 'Pasted commands lost the session directory after Ctrl-Z.')
        session.prompt(cwd, status=0)
        smoke_stage('terminal-tab')
        session.write(b'ls dat\t')
        session.until(b'database')
        session.write(b'\x03')
        session.prompt(cwd, status=130)
        session.write(b'pwd\r')
        output_count += 1
        session.wait_outputs(output_count)
        session.prompt(cwd, status=0)
        # Ambiguous completion must survive both wide prefixes and candidate
        # columns wider than the terminal. Exercise selection movement too:
        # the upstream renderer mixes rune counts with display widths here.
        for prefix in [cwd + '/nested/秘密/a', cwd + '/nested/long/x']:
            smoke_stage('terminal-boundary-completion')
            session.write(('ls ' + prefix + '\t\t').encode() + b'\x01\x05\x03\x03')
            session.prompt(cwd, status=130)
            session.write(b'pwd\r')
            output_count += 1
            session.wait_outputs(output_count)
            session.prompt(cwd, status=0)
        # Edit an approved history entry into a rejected line. Autosave and the
        # library's temporary history entry must not make it searchable later.
        smoke_stage('terminal-rejected-history')
        session.write(b'\x1b[A\x15bad-command unretained-fragment\r')
        session.until(b'secretwright: unknown command')
        session.prompt(cwd, status=1)
        session.write(b'history\r')
        output_count += 1
        history_output = session.wait_outputs(output_count)[-1]
        require(isinstance(history_output, list) and all('bad-command' not in entry and 'unretained-fragment' not in entry for entry in history_output), 'Interactive history retained rejected input.')
        session.prompt(cwd, status=0)
        session.drain()
        smoke_stage('terminal-reverse-search-failed')
        session.write(b'\x12unretained-fragment')
        search = session.until(b'failing bck-i-search: unretained-fragment')
        search += session.drain()
        require(b'bad-command' not in search, 'Reverse history search retained a rejected command.')
        session.write(b'\x03\x03')
        session.prompt(cwd, status=130)
        smoke_stage('terminal-reverse-search-approved')
        session.write(b'\x12pwd\r')
        output_count += 1
        session.wait_outputs(output_count)
        session.prompt(cwd, status=0)
        session.write(b'pwd\r')
        output_count += 1
        session.wait_outputs(output_count)
        session.prompt(cwd, status=0)
        smoke_stage('terminal-exit')
        session.write(b'\x04')
        session.finish()
        outputs = decode_outputs(session.output_path)
        require(outputs[0] == {'path': cwd} and outputs[-1] == {'path': cwd}, 'Interactive shell lost its session directory or safe search result.')
        histories = [value for value in outputs if isinstance(value, list)]
        require(histories and all('bad-command' not in entry and 'unretained-fragment' not in entry for entries in histories for entry in entries), 'Interactive history retained rejected input.')
    finally:
        session.close()

    smoke_stage('interrupt-fixture')
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
        smoke_stage('terminal-interrupt')
        canceled.prompt(status=0)
        canceled.write(b'cat /secret/slow\r')
        require(entered.wait(5), 'Cancellation test did not reach its in-flight request.')
        os.killpg(canceled.pid, signal.SIGINT)
        canceled.prompt(status=130)
        canceled.write(b'pwd\r')
        canceled.wait_outputs(1)
        canceled.prompt(status=0)
        canceled.write(b'\x04')
        canceled.finish()
        require(decode_outputs(canceled.output_path) == [{'path': '/'}], 'Interrupting an HTTP command ended the session or emitted secret data.')
    finally:
        release.set()
        canceled.close()
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)

    smoke_stage('capture-audit')
    for path in fixture.glob('f04-*'):
        if not path.is_file():
            continue
        require(stat.S_IMODE(path.stat().st_mode) == 0o600, 'Shell smoke created a non-private capture.')
        if path == token_file:
            continue
        data = path.read_bytes()
        require(token.encode() not in data and root_token.encode() not in data, 'Shell smoke exposed a credential.')
        require(b'private-f04-terminal-value' not in data, 'Shell completion or history exposed a secret value.')
    print('CLI shell smoke passed: batch, script, PTY navigation, safe Tab rendering, Ctrl-R and interrupts.')


if __name__ == '__main__':
    try:
        main()
    except SmokeFailure as error:
        raise SystemExit(str(error) + ' [stage=' + SMOKE_STAGE + ']') from None
    except Exception as error:
        raise SystemExit('Private shell smoke fixture failed: ' + safe_exception_details(error)) from None
