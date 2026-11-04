"""Benign CI health endpoints, not a vulnerable lab or a scanner."""

import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"CI connectivity fixture only\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_: object) -> None:
        pass


if __name__ == "__main__":
    servers = [ThreadingHTTPServer(("0.0.0.0", int(port)), Handler) for port in sys.argv[1:]]
    for server in servers[1:]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    servers[0].serve_forever()
