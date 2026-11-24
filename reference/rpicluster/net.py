import http.client
import json
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import attest, tls
from .member import Refused, TransportError

MAX_BODY = 8 * 1024 * 1024
TIMEOUT = 30


def split(address):
    host, _, port = address.rpartition(":")
    return host.strip("[]"), int(port)


def handler_for(node):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def reply(self, status, document):
            body = json.dumps(document).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            method = self.path.removeprefix("/rpc/")
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length > MAX_BODY:
                    return self.reply(413, {"error": "too large"})
                payload = json.loads(self.rfile.read(length) or b"{}")
                self.reply(200, node.handle(method, payload))
            except Refused as refusal:
                self.reply(409, {"error": refusal.reason, "pending": refusal.pending})
            except attest.AttestationError as error:
                self.reply(409, {"error": str(error), "pending": None})
            except (ValueError, KeyError, TypeError) as error:
                self.reply(400, {"error": f"bad request: {error}"})
            except TransportError as error:
                self.reply(502, {"error": str(error)})

    return Handler


class QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass


class Server:
    def __init__(self, node, bind, certfile, keyfile):
        host, port = split(bind)
        self.http = QuietServer((host, port), handler_for(node))
        self.http.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(certfile, keyfile)
        self.http.socket = context.wrap_socket(self.http.socket, server_side=True)
        self.port = self.http.server_address[1]
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self.http.shutdown()
        self.http.server_close()


class HttpsTransport:
    def __init__(self, pins=None):
        self.pins = pins or (lambda address: None)

    def call(self, address, method, payload, fingerprint=None):
        pin = fingerprint or self.pins(address)
        host, port = split(address)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        connection = http.client.HTTPSConnection(host, port, context=context, timeout=TIMEOUT)
        try:
            connection.connect()
            if pin is not None and tls.fingerprint(connection.sock.getpeercert(binary_form=True)) != pin:
                raise TransportError(f"{address}: certificate is not the pinned one")
            body = json.dumps(payload).encode()
            connection.request("POST", f"/rpc/{method}", body, {"Content-Type": "application/json"})
            response = connection.getresponse()
            document = json.loads(response.read(MAX_BODY))
        except (OSError, http.client.HTTPException, ssl.SSLError, socket.timeout, ValueError) as error:
            raise TransportError(f"{address}: {type(error).__name__}: {error}") from None
        finally:
            connection.close()
        if response.status == 409:
            raise Refused(document.get("error", "refused"), pending=document.get("pending"))
        if response.status != 200:
            raise TransportError(f"{address}: HTTP {response.status}: {document.get('error', '')}")
        return document

    def prover(self, address, fingerprint):
        return attest.RemoteProver(lambda method, payload: self.call(address, method, payload, fingerprint))


class ControlServer:
    def __init__(self, node, path):
        import os
        import socketserver
        from pathlib import Path

        class UnixHTTP(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True

            def server_bind(self):
                socketserver.UnixStreamServer.server_bind(self)
                self.server_name, self.server_port = "control", 0

            def handle_error(self, request, client_address):
                pass

        class Handler(handler_for(node)):
            def address_string(self):
                return "control"

        Path(path).parent.mkdir(parents=True, exist_ok=True)
        if os.path.exists(path):
            os.unlink(path)
        self.server = UnixHTTP(str(path), Handler)
        os.chmod(path, 0o600)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


class ControlClient:
    def __init__(self, path):
        self.path = path

    def call(self, method, payload=None):
        class Connection(http.client.HTTPConnection):
            def __init__(inner):
                super().__init__("control")

            def connect(inner):
                inner.sock = socket.socket(socket.AF_UNIX)
                inner.sock.settimeout(TIMEOUT * 4)
                inner.sock.connect(self.path)

        connection = Connection()
        try:
            connection.request("POST", f"/rpc/{method}", json.dumps(payload or {}), {"Content-Type": "application/json"})
            response = connection.getresponse()
            document = json.loads(response.read())
        except (OSError, http.client.HTTPException, ValueError) as error:
            raise TransportError(f"{self.path}: {error}") from None
        finally:
            connection.close()
        if response.status == 409:
            raise Refused(document.get("error", "refused"))
        if response.status != 200:
            raise TransportError(document.get("error", f"HTTP {response.status}"))
        return document
