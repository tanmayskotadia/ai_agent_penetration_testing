"""Real HTTPS/socket acceptance against a disposable server owned by this test."""

import ipaddress
import socket
import ssl
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import UUID

import pytest
from aegistrace.api_check_worker import execute_check, supervised_request
from aegistrace.policy import Destination, PolicyError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

pytest_plugins = ("test_ingestion",)


def test_real_pinned_https_redirect_denial_and_process_deadline(
    tmp_path, monkeypatch, import_context
):
    addresses = [
        item[4][0] for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
    ]
    addresses = [value for value in addresses if not ipaddress.ip_address(value).is_loopback]
    if not addresses:
        pytest.skip("isolated HTTPS harness needs a non-loopback local interface")
    address = addresses[0]
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Disposable API test CA")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(address))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "ca.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    monkeypatch.setenv("SSL_CERT_FILE", str(cert_path))
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            if self.path == "/slow":
                time.sleep(2)
            from test_api_check_workflow import TOKEN

            status = 302 if self.path == "/redirect" else 200
            if self.path == "/forbidden":
                status = 403
            if self.path == "/protected" and self.headers.get("Authorization") != "Bearer " + TOKEN:
                status = 401
            self.send_response(status)
            if self.path == "/redirect":
                self.send_header("Location", "https://external.invalid/must-not-follow")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer((address, 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target = Destination(
        protocol="https",
        host=address,
        port=server.server_port,
        path="/public",
        pinned_addresses=(address,),
    )
    try:
        assert supervised_request(target, "GET", {}, time.time() + 15, lambda: False) == 200
        assert (
            supervised_request(
                target.model_copy(update={"path": "/redirect"}),
                "GET",
                {},
                time.time() + 15,
                lambda: False,
            )
            == 302
        )
        assert requests == ["/public", "/redirect"]
        with pytest.raises(PolicyError):
            supervised_request(
                target.model_copy(update={"path": "/slow"}),
                "GET",
                {},
                time.time() + 0.2,
                lambda: False,
            )
        from test_api_check_workflow import prepare

        client, config = import_context
        origin = f"https://{address}:{server.server_port}"
        base, headers, post, _, check = prepare(import_context, origin)
        post(
            base + "/api-checks/" + check["id"] + "/decision",
            {"decision": "approve", "digest": check["plan"]["digest"]},
        )
        result = execute_check(
            client.app.state.engine, config, UUID(check["assessment_id"]), UUID(check["id"])
        )
        assert result["execution_mode"] == "live-request"
        assert result["attempted_count"] == 3 and result["succeeded_count"] == 2
        saved = client.get(base + "/api-checks/" + check["id"], headers=headers()).json()
        assert saved["state"] == "completed"
        assert saved["result"]["operations"][2]["status_code"] == 403
        # A hostname absent from the SAN cannot inherit the IP certificate.
        with pytest.raises(PolicyError):
            supervised_request(
                target.model_copy(update={"host": "wrong-certificate.invalid"}),
                "GET",
                {},
                time.time() + 15,
                lambda: False,
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
