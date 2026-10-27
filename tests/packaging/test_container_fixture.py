"""Regression for the packaged CLI's independent HTTP acceptance fixture."""

import http.client
import importlib.util
import io
import json
from pathlib import Path
import unittest
from urllib.parse import urlencode


ROOT = Path(__file__).resolve().parents[2]


class ContainerFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("secretwright_container_fixture_test", ROOT / "scripts/container_smoke.py")
        cls.fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.fixture)

    def request(self, target, headers=None):
        # Execute the real BaseHTTPRequestHandler protocol path against memory
        # streams; no Docker daemon, TCP socket or network grant is required.
        observations = {"keytab_reads": 0, "health_reads": 0, "violations": []}
        lines = ["GET " + target + " HTTP/1.0"]
        lines += [key + ": " + value for key, value in ({} if headers is None else headers).items()]

        class MemorySocket:
            def __init__(self, body):
                self.body, self.sent = body, bytearray()

            def makefile(self, *_):
                return io.BytesIO(self.body)

            def sendall(self, body):
                self.sent.extend(body)

        connection = MemorySocket(("\r\n".join(lines) + "\r\n\r\n").encode())
        handler = self.fixture.fixture_handler(self.fixture.binary_keytab(), observations)
        handler(connection, ("127.0.0.1", 0), object())
        response = http.client.HTTPResponse(MemorySocket(bytes(connection.sent)))
        response.begin()
        return response.status, response.read(), observations

    def test_locked_vault_sdk_health_query_reaches_fixture_without_credentials(self):
        # Independent values copied from the locked Vault SDK HealthWithContext
        # API contract, rather than from the fixture implementation.
        query = urlencode({"sealedcode": "299", "uninitcode": "299", "standbycode": "299",
                           "drsecondarycode": "299", "performancestandbycode": "299",
                           "removedcode": "299", "haunhealthycode": "299"})
        status, body, observations = self.request("/v1/sys/health?" + query)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["initialized"], True)
        self.assertEqual(observations["health_reads"], 1)
        self.assertEqual(observations["keytab_reads"], 0)
        self.assertEqual(observations["violations"], [])

    def test_unknown_incomplete_and_duplicated_health_queries_are_rejected(self):
        full = urlencode({"sealedcode": "299", "uninitcode": "299", "standbycode": "299",
                          "drsecondarycode": "299", "performancestandbycode": "299",
                          "removedcode": "299", "haunhealthycode": "299"})
        for query in ("", "?standbycode=299", "?" + full + "&unknown=299", "?" + full + "&sealedcode=299",
                      "?" + full.replace("sealedcode=299", "sealedcode=200")):
            with self.subTest(query_shape=query[:15]):
                status, _, observations = self.request("/v1/sys/health" + query)
                self.assertEqual(status, 400)
                self.assertEqual(observations["health_reads"], 0)
                self.assertEqual(observations["violations"], ["health-query"])

    def test_private_keytab_query_is_not_relaxed_by_health_routing(self):
        status, _, observations = self.request("/v1/keytabs/data/service?version=1",
                                              {"X-Vault-Token": self.fixture.PRIVATE_TOKEN})
        self.assertEqual(status, 404)
        self.assertEqual(observations["keytab_reads"], 0)
        self.assertEqual(observations["health_reads"], 0)
        self.assertEqual(observations["violations"], ["endpoint"])


if __name__ == "__main__":
    unittest.main()
