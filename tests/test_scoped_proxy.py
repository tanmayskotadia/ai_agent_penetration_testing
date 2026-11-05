"""Scoped proxy contract tests use only a benign in-process HTTP fixture."""

import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import ProxyHandler, build_opener

import pytest
from aegistrace.policy import Destination, PolicyError
from aegistrace_workers.adapters.scoped_proxy import ProxyPolicy, ScopedEgressProxy

requires_loopback = pytest.mark.skipif(
    sys.platform == "win32", reason="Windows sandbox blocks loopback sockets"
)


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        return

    def do_GET(self):
        if self.path == "/allowed/redirect":
            self.send_response(302)
            self.send_header("Location", "http://other.example.test:8080/allowed")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = self.path.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def target_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.fixture
def proxy(target_server):
    destination = Destination(
        protocol="http",
        host="target.example.test",
        port=target_server.server_address[1],
        path="/allowed",
        pinned_addresses=("127.0.0.1",),
    )
    policy = ProxyPolicy(
        destination=destination,
        included_paths=("/allowed",),
        excluded_paths=("/allowed/private",),
        deadline=time.monotonic() + 10,
        cancelled=lambda: False,
    )
    with ScopedEgressProxy(policy) as value:
        yield value, destination.port


@requires_loopback
def test_proxy_pins_http_target_and_accepts_included_path(proxy):
    value, port = proxy
    opener = build_opener(ProxyHandler({"http": value.url}))
    response = opener.open(f"http://target.example.test:{port}/allowed/item", timeout=2)
    assert response.status == 200
    assert response.read() == b"/allowed/item"


@pytest.mark.parametrize("path", ["/outside", "/allowed/private", "/allowed/%2e%2e/outside"])
@requires_loopback
def test_proxy_rejects_out_of_scope_http_paths(proxy, path):
    value, port = proxy
    opener = build_opener(ProxyHandler({"http": value.url}))
    with pytest.raises(HTTPError):
        opener.open(f"http://target.example.test:{port}{path}", timeout=2)


@requires_loopback
def test_proxy_rejects_cross_origin_redirect(proxy):
    value, port = proxy
    opener = build_opener(ProxyHandler({"http": value.url}))
    with pytest.raises(HTTPError):
        opener.open(f"http://target.example.test:{port}/allowed/redirect", timeout=2)


@requires_loopback
def test_proxy_rejects_unapproved_connect_authority(proxy):
    value, _ = proxy
    host, port = value.url.removeprefix("http://").split(":")
    connection = socket.create_connection((host, int(port)), timeout=2)
    try:
        connection.sendall(
            b"CONNECT other.example.test:443 HTTP/1.1\r\nHost: other.example.test:443\r\n\r\n"
        )
        assert b"403" in connection.recv(1024)
    finally:
        connection.close()


def test_proxy_rejects_ipv6_pins(target_server):
    destination = Destination(
        protocol="https",
        host="target.example.test",
        port=443,
        path="/",
        pinned_addresses=("2001:db8::1",),
    )
    with pytest.raises(PolicyError, match="IPv4"):
        ProxyPolicy(
            destination=destination,
            included_paths=("/",),
            excluded_paths=(),
            deadline=time.monotonic() + 10,
            cancelled=lambda: False,
        )
