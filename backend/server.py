import ipaddress
import json
import logging
import os
from contextlib import contextmanager
from datetime import date, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


LOGGER = logging.getLogger("pret.inventory")
MAX_BODY_BYTES = 4096
HOST = "127.0.0.1"
PORT = 8047


class InvalidPayload(ValueError):
    pass


class DatabaseUnavailable(RuntimeError):
    pass


class DeviceAlreadyExists(RuntimeError):
    pass


def parse_device_payload(payload):
    if not isinstance(payload, dict):
        raise InvalidPayload("JSON body must be an object.")

    if set(payload) - {"target_ip", "port"}:
        raise InvalidPayload("Only target_ip and port are accepted.")

    target_ip = payload.get("target_ip")
    if not isinstance(target_ip, str) or "%" in target_ip:
        raise InvalidPayload("target_ip must be an IPv4 or IPv6 address.")

    try:
        address = ipaddress.ip_address(target_ip)
    except ValueError as exc:
        raise InvalidPayload("target_ip must be an IPv4 or IPv6 address.") from exc

    port = payload.get("port", 9100)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise InvalidPayload("port must be an integer between 1 and 65535.")

    return str(address), port


@contextmanager
def connect_db():
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise DatabaseUnavailable("DATABASE_URL is not configured.")
    if not database_url.startswith(("postgresql://", "postgres://")):
        raise DatabaseUnavailable("DATABASE_URL has an unsupported scheme.")

    try:
        import psycopg
    except ImportError as exc:
        raise DatabaseUnavailable("The psycopg dependency is unavailable.") from exc

    try:
        with psycopg.connect(database_url) as connection:
            yield connection
    except psycopg.errors.UniqueViolation as exc:
        raise DeviceAlreadyExists from exc
    except psycopg.Error as exc:
        raise DatabaseUnavailable("The database request failed.") from exc


def json_default(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    raise TypeError("Value is not JSON serializable.")


class InventoryHandler(BaseHTTPRequestHandler):
    server_version = "PRETInventory/0.1"
    sys_version = ""

    def log_message(self, format_string, *args):
        LOGGER.info("%s - %s", self.client_address[0], format_string % args)

    def send_json(self, status, payload):
        body = json.dumps(payload, default=json_default).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/healthz":
            self.health_check()
        elif path == "/api/devices":
            self.list_devices()
        else:
            self.send_json(404, {"error": "Not found."})

    def do_POST(self):
        path = urlsplit(self.path).path
        if path != "/api/devices":
            self.send_json(404, {"error": "Not found."})
            return

        content_type = self.headers.get_content_type()
        if content_type != "application/json":
            self.send_json(415, {"error": "Content-Type must be application/json."})
            return

        try:
            content_length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self.send_json(400, {"error": "A valid Content-Length is required."})
            return

        if content_length < 1 or content_length > MAX_BODY_BYTES:
            self.send_json(413, {"error": "Request body size is invalid or too large."})
            return

        try:
            payload = json.loads(self.rfile.read(content_length))
            target_ip, port = parse_device_payload(payload)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_json(400, {"error": "Request body must contain valid JSON."})
            return
        except InvalidPayload as exc:
            self.send_json(400, {"error": str(exc)})
            return

        try:
            with connect_db() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO public.devices (target_ip, port, source)
                        VALUES (%s::inet, %s, 'manual')
                        RETURNING id, target_ip::text, port, status,
                                  first_seen_at, source
                        """,
                        (target_ip, port),
                    )
                    device = cursor.fetchone()
        except DeviceAlreadyExists:
            self.send_json(409, {"error": "That IP address and port are already registered."})
            return
        except DatabaseUnavailable as exc:
            self.handle_database_error(exc)
            return

        self.send_json(201, {"device": self.device_record(device)})

    def health_check(self):
        try:
            with connect_db() as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    cursor.fetchone()
        except DatabaseUnavailable as exc:
            self.handle_database_error(exc)
            return
        self.send_json(200, {"status": "ok", "database": "ok"})

    def list_devices(self):
        try:
            with connect_db() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT id, target_ip::text, port, hostname, model,
                               firmware, status, first_seen_at, source
                        FROM public.devices
                        ORDER BY id
                        """
                    )
                    devices = cursor.fetchall()
        except DatabaseUnavailable as exc:
            self.handle_database_error(exc)
            return
        self.send_json(
            200,
            {"devices": [self.device_record(device) for device in devices]},
        )

    @staticmethod
    def device_record(row):
        keys = (
            "id",
            "target_ip",
            "port",
            "hostname",
            "model",
            "firmware",
            "status",
            "first_seen_at",
            "source",
        )
        return dict(zip(keys, row))

    def handle_database_error(self, error):
        LOGGER.error("Inventory database request failed: %s", error)
        self.send_json(503, {"error": "Inventory database is unavailable."})


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    server = ThreadingHTTPServer((HOST, PORT), InventoryHandler)
    LOGGER.info("Inventory API listening on http://%s:%s", HOST, PORT)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOGGER.info("Shutting down inventory API.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
