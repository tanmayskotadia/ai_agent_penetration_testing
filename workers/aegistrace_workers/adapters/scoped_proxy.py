"""Per-job loopback proxy with pinned-IP connects and host/path restrictions.

The kernel egress policy remains mandatory: it must deny direct scanner sockets
and permit the worker's control-plane dependencies plus the approved target pins.
HTTPS paths are restricted by the scanner's reviewed context; the proxy allows
CONNECT only to the approved origin and never follows redirects itself.
"""

from __future__ import annotations

import http.client
import ipaddress
import select
import socket
import threading
import time
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import TracebackType
from urllib.parse import unquote, urlsplit

from aegistrace.policy import Destination, PolicyError

_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
_MAX_BODY = 1_048_576
_MAX_RESPONSE = 2_097_152
_MAX_HEADER_BYTES = 32_768
_RequestSocket = socket.socket | tuple[bytes, socket.socket]


def _host(value: str) -> str:
    value = value.rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        try:
            return value.encode("idna").decode("ascii")
        except UnicodeError as error:
            raise PolicyError("invalid target host") from error


def _path_allowed(path: str, included: tuple[str, ...], excluded: tuple[str, ...]) -> bool:
    decoded = path
    for _ in range(4):
        value = unquote(decoded, errors="strict")
        if value == decoded:
            break
        decoded = value
    else:
        return False
    if "\\" in decoded or any(part == ".." for part in decoded.split("/")):
        return False
    normalized = "/" + "/".join(part for part in decoded.split("/") if part not in {"", "."})
    if path.endswith("/") and normalized != "/":
        normalized += "/"

    def within(candidate: str, root: str) -> bool:
        root = root.rstrip("/") or "/"
        return candidate == root or root == "/" or candidate.startswith(root + "/")

    return any(within(normalized, root) for root in included) and not any(
        within(normalized, root) for root in excluded
    )


@dataclass(frozen=True)
class ProxyPolicy:
    destination: Destination
    included_paths: tuple[str, ...]
    excluded_paths: tuple[str, ...]
    deadline: float
    cancelled: Callable[[], bool]

    def __post_init__(self) -> None:
        if (
            self.destination.protocol not in {"http", "https"}
            or not self.destination.pinned_addresses
            or len(self.destination.pinned_addresses) > 8
            or not self.included_paths
            or len(self.included_paths) > 100
            or len(self.excluded_paths) > 100
            or self.deadline <= time.monotonic()
        ):
            raise PolicyError("current pinned target and bounded paths required")
        pins = tuple(ipaddress.ip_address(value) for value in self.destination.pinned_addresses)
        if any(value.version != 4 for value in pins):
            raise PolicyError("scanner egress currently requires pinned IPv4")
        for path in (*self.included_paths, *self.excluded_paths):
            if (
                not path.startswith("/")
                or "?" in path
                or "#" in path
                or "\\" in path
                or any(part == ".." for part in unquote(path).split("/"))
            ):
                raise PolicyError("invalid path scope")

    @property
    def host(self) -> str:
        return _host(self.destination.host)

    @property
    def pins(self) -> tuple[str, ...]:
        return tuple(str(ipaddress.ip_address(value)) for value in self.destination.pinned_addresses)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, policy: ProxyPolicy):
        self.policy = policy
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(("127.0.0.1", 0), _Handler)

    def process_request(self, request: _RequestSocket, client_address: tuple[str, int]) -> None:
        request_socket = request[1] if isinstance(request, tuple) else request
        if not self.slots.acquire(blocking=False):
            request_socket.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(
        self, request: _RequestSocket, client_address: tuple[str, int]
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: _Server

    def log_message(self, format: str, *args: object) -> None:
        return

    def _current(self) -> bool:
        try:
            return time.monotonic() < self.server.policy.deadline and not self.server.policy.cancelled()
        except Exception:
            return False

    def _deny(self, status: int = 403) -> None:
        self.send_error(status)
        self.close_connection = True

    def _connect_host(self, authority: str) -> tuple[str, int] | None:
        if "@" in authority:
            return None
        try:
            parts = urlsplit("//" + authority)
            if (
                parts.path
                or parts.query
                or parts.fragment
                or not parts.hostname
                or parts.port is None
            ):
                return None
            host = _host(parts.hostname)
            port = parts.port
        except (ValueError, PolicyError):
            return None
        expected_port = self.server.policy.destination.port
        if host != self.server.policy.host or port != expected_port:
            return None
        return host, port

    def do_CONNECT(self) -> None:
        if self._connect_host(self.path) is None or not self._current():
            self._deny()
            return
        upstream = None
        for address in self.server.policy.pins:
            try:
                upstream = socket.create_connection(
                    (address, self.server.policy.destination.port),
                    timeout=max(0.1, min(2.0, self.server.policy.deadline - time.monotonic())),
                )
                break
            except OSError:
                continue
        if upstream is None:
            self._deny(502)
            return
        try:
            self.send_response(200, "Connection Established")
            self.end_headers()
            self.connection.setblocking(False)
            upstream.setblocking(False)
            peers = (self.connection, upstream)
            while self._current():
                readable, _, exceptional = select.select(peers, [], peers, 0.1)
                if exceptional:
                    return
                for source in readable:
                    target = upstream if source is self.connection else self.connection
                    try:
                        data = source.recv(65536)
                        if not data:
                            return
                        target.sendall(data)
                    except OSError:
                        return
        finally:
            upstream.close()

    def _plain_http(self) -> None:
        if self.command not in _METHODS or not self._current():
            self._deny()
            return
        try:
            parts = urlsplit(self.path)
            host = _host(parts.hostname or "")
            port = parts.port or (80 if parts.scheme == "http" else 443)
        except (ValueError, PolicyError):
            self._deny()
            return
        headers = self.headers
        host_headers = headers.get_all("Host", [])
        try:
            host_parts = urlsplit("//" + host_headers[0]) if len(host_headers) == 1 else None
            host_header = _host(host_parts.hostname or "") if host_parts is not None else ""
            host_port = (
                host_parts.port if host_parts is not None and host_parts.port is not None else 80
            )
        except (ValueError, PolicyError):
            host_header, host_port = "", 0
        if (
            parts.scheme != "http"
            or parts.username
            or parts.password
            or parts.fragment
            or host != self.server.policy.host
            or port != self.server.policy.destination.port
            or len(host_headers) != 1
            or host_header != self.server.policy.host
            or host_port != self.server.policy.destination.port
            or len(str(headers).encode("iso-8859-1", errors="replace")) > _MAX_HEADER_BYTES
            or headers.get("Transfer-Encoding") is not None
            or headers.get("Expect") is not None
            or not _path_allowed(
                parts.path or "/",
                self.server.policy.included_paths,
                self.server.policy.excluded_paths,
            )
        ):
            self._deny()
            return
        content_lengths = headers.get_all("Content-Length", ["0"])
        if len(content_lengths) != 1 or not content_lengths[0].isdecimal():
            self._deny()
            return
        length = int(content_lengths[0])
        if length > _MAX_BODY:
            self._deny(413)
            return
        body = self.rfile.read(length) if length else None
        if not self._current():
            self._deny(503)
            return
        upstream: http.client.HTTPConnection | None = None
        for address in self.server.policy.pins:
            try:
                upstream = http.client.HTTPConnection(
                    address,
                    self.server.policy.destination.port,
                    timeout=max(0.1, min(3.0, self.server.policy.deadline - time.monotonic())),
                )
                upstream.request(
                    self.command,
                    (parts.path or "/") + ("?" + parts.query if parts.query else ""),
                    body=body,
                    headers={
                        key: value
                        for key, value in headers.items()
                        if key.lower()
                        not in {
                            "host",
                            "connection",
                            "proxy-connection",
                            "proxy-authorization",
                        }
                    }
                    | {"Host": self.server.policy.host},
                )
                break
            except (OSError, http.client.HTTPException):
                if upstream is not None:
                    upstream.close()
                upstream = None
        if upstream is None:
            self._deny(502)
            return
        try:
            response = upstream.getresponse()
            payload = response.read(_MAX_RESPONSE + 1)
            if len(payload) > _MAX_RESPONSE:
                self._deny(502)
                return
            self.send_response(response.status, response.reason)
            for key, value in response.getheaders():
                if key.lower() not in {"connection", "transfer-encoding", "content-length"}:
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)
            self.close_connection = True
        finally:
            upstream.close()

    do_GET = _plain_http
    do_HEAD = _plain_http
    do_POST = _plain_http
    do_PUT = _plain_http
    do_PATCH = _plain_http
    do_DELETE = _plain_http
    do_OPTIONS = _plain_http


class ScopedEgressProxy(AbstractContextManager["ScopedEgressProxy"]):
    """Start a transient loopback proxy whose lifetime is one approved job."""

    def __init__(self, policy: ProxyPolicy):
        self.server = _Server(policy)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def __enter__(self) -> ScopedEgressProxy:
        self.thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
