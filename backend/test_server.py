import json
import threading
import unittest
from datetime import datetime, timezone
from http.client import HTTPConnection
from unittest.mock import patch
from http.server import ThreadingHTTPServer

from backend.server import InventoryHandler, InvalidPayload, parse_device_payload


class FakeCursor:
    def __init__(self, single_row=None, rows=None):
        self.single_row = single_row
        self.rows = rows or []
        self.executed = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def execute(self, query, params=None):
        self.executed.append((query, params))

    def fetchone(self):
        return self.single_row

    def fetchall(self):
        return self.rows


class FakeConnection:
    def __init__(self, cursor):
        self.fake_cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def cursor(self):
        return self.fake_cursor


class InventoryApiTests(unittest.TestCase):
    def setUp(self):
        self.cursor = FakeCursor(
            single_row=(
                1,
                "192.168.2.98",
                9100,
                "unknown",
                datetime(2026, 1, 1, tzinfo=timezone.utc),
                "manual",
            ),
            rows=[
                (
                    1,
                    "192.168.2.98",
                    9100,
                    None,
                    None,
                    None,
                    "unknown",
                    datetime(2026, 1, 1, tzinfo=timezone.utc),
                    "manual",
                )
            ],
        )
        self.connection = FakeConnection(self.cursor)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), InventoryHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.thread.join)
        self.addCleanup(self.server.shutdown)

    def request(self, method, path, body=None, headers=None):
        connection = HTTPConnection("127.0.0.1", self.server.server_port)
        encoded_body = None if body is None else json.dumps(body)
        connection.request(method, path, body=encoded_body, headers=headers or {})
        response = connection.getresponse()
        payload = json.loads(response.read())
        connection.close()
        return response.status, payload

    @patch("backend.server.connect_db")
    def test_health_check_uses_database(self, connect):
        connect.return_value = self.connection
        status, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"status": "ok", "database": "ok"})
        self.assertEqual(self.cursor.executed[0][0], "SELECT 1")

    @patch("backend.server.connect_db")
    def test_add_device_stores_canonical_ip_without_network_probe(self, connect):
        connect.return_value = self.connection
        status, payload = self.request(
            "POST",
            "/api/devices",
            {"target_ip": "192.168.2.98"},
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 201)
        self.assertEqual(payload["device"]["target_ip"], "192.168.2.98")
        self.assertEqual(
            self.cursor.executed[0][1],
            ("192.168.2.98", 9100),
        )
        self.assertNotIn("connect", self.cursor.executed[0][0].lower())

    @patch("backend.server.connect_db")
    def test_list_devices_reads_inventory(self, connect):
        connect.return_value = self.connection
        status, payload = self.request("GET", "/api/devices")
        self.assertEqual(status, 200)
        self.assertEqual(payload["devices"][0]["target_ip"], "192.168.2.98")

    @patch("backend.server.connect_db")
    def test_invalid_ip_is_rejected_before_database_access(self, connect):
        status, payload = self.request(
            "POST",
            "/api/devices",
            {"target_ip": "printer.example"},
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 400)
        self.assertIn("IPv4 or IPv6", payload["error"])
        connect.assert_not_called()


class DevicePayloadTests(unittest.TestCase):
    def test_ipv6_and_custom_port_are_accepted(self):
        self.assertEqual(
            parse_device_payload({"target_ip": "2001:0db8::1", "port": 631}),
            ("2001:db8::1", 631),
        )

    def test_cidr_hostname_and_zone_id_are_rejected(self):
        for target in ("192.168.2.0/24", "printer.example", "fe80::1%eth0"):
            with self.subTest(target=target):
                with self.assertRaises(InvalidPayload):
                    parse_device_payload({"target_ip": target})

    def test_boolean_port_is_rejected(self):
        with self.assertRaises(InvalidPayload):
            parse_device_payload({"target_ip": "192.168.2.98", "port": True})


if __name__ == "__main__":
    unittest.main()
