#!/usr/bin/env python3
"""Native Linux acceptance for the packaged image; private captures stay local."""

import argparse
import base64
import contextlib
import http.server
import json
import os
from pathlib import Path
import re
import ssl
import stat
import struct
import subprocess
import tarfile
import tempfile
import threading


class SmokeFailure(Exception):
    pass


STAGE = "startup"
PRIVATE_TOKEN = "private-container-operator-marker"
PRIVATE_KEY = b"private-container-key-marker-1234"[:32]


def require(condition, message):
    if not condition:
        raise SmokeFailure(message)


def command(words, *, expected=0, timeout=40):
    result = subprocess.run(words, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
    require(result.returncode == expected, "A container acceptance command returned an unexpected exit code.")
    return result


def private_file(path, body):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(body.encode() if isinstance(body, str) else body)


def binary_keytab():
    counted = lambda text: struct.pack(">H", len(text.encode())) + text.encode()
    body = struct.pack(">H", 2) + counted("EXAMPLE.TEST") + counted("HTTP") + counted("container.fixture.test")
    body += struct.pack(">IIBHH", 2, 0x90000000, 3, 18, len(PRIVATE_KEY)) + PRIVATE_KEY
    body += struct.pack(">I", 259)
    return b"\x05\x02" + struct.pack(">I", len(body)) + body


@contextlib.contextmanager
def fixture_server(raw, *, tls=None):
    observations = {"keytab_reads": 0, "health_reads": 0, "violations": []}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            if self.path == "/v1/keytabs/data/service":
                observations["keytab_reads"] += 1
                if self.headers.get("X-Vault-Token") != PRIVATE_TOKEN or self.headers.get("X-Vault-Namespace"):
                    observations["violations"].append("operator")
                value = {"data": {"data": {"api_version": "secretwright/keytab/v1", "encoding": "base64",
                                            "data": base64.b64encode(raw).decode()},
                                  "metadata": {"version": 1, "destroyed": False, "deletion_time": ""}}}
            elif self.path == "/v1/sys/health":
                observations["health_reads"] += 1
                if self.headers.get("X-Vault-Token"):
                    observations["violations"].append("health-credential")
                value = {"initialized": True, "sealed": False, "standby": False, "version": "container-fixture"}
            else:
                observations["violations"].append("endpoint")
                self.send_error(404)
                return
            encoded = json.dumps(value).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    if tls:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        scheme = "https" if tls else "http"
        yield scheme + "://127.0.0.1:" + str(server.server_port), observations
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def tls_fixture(directory):
    ca, ca_key = directory / "ca.pem", directory / "ca-key.pem"
    leaf, leaf_key, request = directory / "server.pem", directory / "server-key.pem", directory / "server.csr"
    extension = directory / "server.ext"
    private_file(extension, "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n")
    common = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"]
    command(["openssl", "req", "-x509", *common, "-days", "1", "-subj", "/CN=container-fixture-root",
             "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", str(ca_key), "-out", str(ca)])
    command(["openssl", "req", "-new", *common, "-subj", "/CN=localhost", "-keyout", str(leaf_key), "-out", str(request)])
    command(["openssl", "x509", "-req", "-in", str(request), "-CA", str(ca), "-CAkey", str(ca_key),
             "-CAcreateserial", "-days", "1", "-extfile", str(extension), "-out", str(leaf)])
    for path in directory.iterdir():
        os.chmod(path, 0o600)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(leaf), str(leaf_key))
    return context


def inspect_filesystem(image, directory):
    created = command(["docker", "create", image, "version"]).stdout.decode().strip()
    require(re.fullmatch(r"[0-9a-f]{12,64}", created) is not None, "Docker returned an invalid fixture container identity.")
    exported = directory / "rootfs.tar"
    try:
        command(["docker", "export", "--output", str(exported), created], timeout=90)
        with tarfile.open(exported, "r:") as archive:
            members = {member.name.removeprefix("./"): member for member in archive}
            binary = members.get("usr/local/bin/secretwright")
            require(binary is not None and binary.isfile() and binary.mode & 0o111,
                    "The image lacks its executable entrypoint.")
            ca = members.get("etc/ssl/certs/ca-certificates.crt")
            require(ca is not None and ca.isfile() and 0 < ca.size < 4 * 1024 * 1024,
                    "The image lacks its bounded system CA bundle.")
            require(b"-----BEGIN CERTIFICATE-----" in archive.extractfile(ca).read(),
                    "The image system CA bundle contains no certificates.")
            forbidden_programs = {"sh", "bash", "ash", "busybox", "apt", "apt-get", "apk", "yum", "go", "gcc"}
            for name, member in members.items():
                require(not (member.isfile() and Path(name).parent.as_posix() in
                             {"bin", "sbin", "usr/bin", "usr/sbin", "usr/local/bin"} and Path(name).name in forbidden_programs),
                        "The runtime image contains a shell, compiler or package manager.")
                require(not any(part in {".git", ".container", "tests"} for part in Path(name).parts),
                        "The image contains build context or acceptance fixtures.")
    finally:
        command(["docker", "rm", "--force", created])
        exported.unlink(missing_ok=True)


def main():
    global STAGE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    parser.add_argument("--version", required=True)
    options = parser.parse_args()
    require(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_./:@-]{0,255}", options.image) is not None,
            "Invalid local acceptance image selector.")
    with tempfile.TemporaryDirectory(prefix="secretwright-container-") as temporary:
        directory = Path(temporary)
        os.chmod(directory, 0o700)
        raw = binary_keytab()
        forbidden = [PRIVATE_TOKEN.encode(), PRIVATE_KEY, base64.b64encode(raw), base64.b64encode(PRIVATE_KEY)]
        identity = str(os.getuid()) + ":" + str(os.getgid())

        def run(args, *, expected=0, online=False, mount=False, environment=(), user=None):
            words = ["docker", "run", "--rm", "--pull=never", "--read-only", "--cap-drop=ALL",
                     "--security-opt=no-new-privileges", "--network", "host" if online else "none"]
            if user:
                words += ["--user", user]
            if mount:
                words += ["--mount", "type=bind,src=" + str(directory) + ",dst=/fixtures"]
            for value in environment:
                words += ["--env", value]
            result = command([*words, options.image, *args], expected=expected)
            require(all(marker not in result.stdout + result.stderr for marker in forbidden),
                    "Container output exposed private fixture material.")
            require(not result.stderr if expected == 0 else bool(result.stderr),
                    "Container command returned unexpected diagnostics.")
            return result.stdout

        STAGE = "image-configuration-and-private-context"
        inspected = json.loads(command(["docker", "image", "inspect", options.image]).stdout)
        require(len(inspected) == 1, "Image lookup returned an ambiguous result.")
        config = inspected[0]["Config"]
        require(config.get("User") == "65532:65532" and config.get("Entrypoint") == ["/usr/local/bin/secretwright"]
                and config.get("Cmd") == ["help"] and config.get("WorkingDir") == "/work",
                "Image runtime defaults do not match the unprivileged CLI contract.")
        require(config.get("Labels", {}).get("org.opencontainers.image.version") == options.version,
                "Image metadata does not identify the packaged version.")
        require(not config.get("Volumes") and not config.get("ExposedPorts"),
                "CLI image declares an implicit mount or service port.")
        inspect_filesystem(options.image, directory)

        STAGE = "read-only-offline-defaults"
        require(b"Usage:" in run([]), "Default image command did not show CLI help.")
        require(run(["version"]).decode().strip() == "secretwright " + options.version,
                "Container runtime version differs from its release metadata.")
        offline_env = ["VAULT_ADDR=private-invalid-address", "VAULT_CLIENT_TIMEOUT=invalid-timeout",
                       "VAULT_TOKEN=" + PRIVATE_TOKEN]
        example = run(["keytab", "example"], environment=offline_env).decode()
        require(not example.lstrip().startswith("{") and any(line.startswith("api_version:") for line in example.splitlines()),
                "Offline container policy did not default to YAML.")
        schema = json.loads(run(["keytab", "schema"], environment=offline_env))
        require(schema.get("$id") == "urn:secretwright:keytab:v1", "Offline container schema identity changed.")

        STAGE = "private-bind-mounts"
        source, operator = directory / "service.keytab", directory / "operator-token"
        private_file(source, raw)
        private_file(operator, PRIVATE_TOKEN + "\n")
        inspected = json.loads(run(["keytab", "inspect", "--file", "/fixtures/service.keytab"],
                                   mount=True, user=identity, environment=offline_env))
        require(inspected.get("authentication_checked") is False and inspected["entries"][0].get("kvno") == 259,
                "A private host-owned keytab was not readable with the mapped user.")
        os.chmod(source, 0o644)
        run(["keytab", "inspect", "--file", "/fixtures/service.keytab"], expected=1,
            mount=True, user=identity, environment=offline_env)
        os.chmod(source, 0o600)

        STAGE = "private-export-and-exclusive-output"
        with fixture_server(raw) as (address, observations):
            common = ["keytab", "export", "--address", address, "--namespace", "", "--timeout", "5s",
                      "--mount", "keytabs", "--path", "/keytabs/service", "--token-file", "/fixtures/operator-token"]
            report = json.loads(run([*common, "--out", "/fixtures/restored.keytab"], online=True, mount=True, user=identity))
            restored = directory / "restored.keytab"
            require(restored.read_bytes() == raw and stat.S_IMODE(restored.stat().st_mode) == 0o600,
                    "Container export changed private bytes or output mode.")
            require(report.get("version") == 1 and report.get("report", {}).get("authentication_checked") is False,
                    "Container export did not retain its exact revision and validation scope.")
            run([*common, "--out", "/fixtures/restored.keytab"], expected=4, online=True, mount=True, user=identity)
            require(observations["keytab_reads"] == 1 and not observations["violations"] and restored.read_bytes() == raw,
                    "Existing container output triggered another request or was overwritten.")

        STAGE = "verified-tls-and-explicit-trust"
        tls = tls_fixture(directory)
        with fixture_server(raw, tls=tls) as (address, observations):
            status = ["status", "--address", address, "--timeout", "5s", "--namespace", ""]
            trusted = ["VAULT_CACERT=/fixtures/ca.pem", "VAULT_TOKEN=" + PRIVATE_TOKEN]
            report = json.loads(run(status, online=True, mount=True, user=identity, environment=trusted))
            require(report.get("initialized") is True and report.get("sealed") is False,
                    "Container TLS health did not accept its explicitly trusted CA.")
            run(status, expected=1, online=True, mount=True, user=identity)
            run(status, expected=1, online=True, mount=True, user=identity,
                environment=[*trusted, "VAULT_TLS_SERVER_NAME=wrong.fixture.test"])
            require(observations["health_reads"] == 1 and not observations["violations"],
                    "Untrusted TLS reached the application or health sent a credential.")
        print("Container smoke passed: native Linux, nonroot defaults, read-only offline YAML/schema, private mapped files/export and verified TLS. Other architectures are inspected, not executed.")


if __name__ == "__main__":
    try:
        main()
    except SmokeFailure as failure:
        raise SystemExit("Container smoke failed [stage=" + STAGE + "]: " + str(failure)) from None
    except Exception:
        raise SystemExit("Container smoke failed [stage=" + STAGE + "]; private captures are withheld.") from None
