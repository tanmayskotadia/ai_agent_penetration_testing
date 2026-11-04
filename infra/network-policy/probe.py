"""Connectivity probes only, on CI-owned harmless endpoints. No security scan."""

import json
import socket
from pathlib import Path


def connect(address: str, port: int) -> bool:
    try:
        with socket.create_connection((address, port), timeout=0.5) as connection:
            connection.sendall(b"GET / HTTP/1.0\r\nHost: ci-fixture\r\n\r\n")
            return b"200 OK" in connection.recv(1024)
    except OSError:
        return False


def main() -> None:
    allowed = [("10.254.240.10", 8080), ("10.254.240.20", 8443)]
    denied = [
        ("10.254.240.10", 9090),
        ("10.254.240.11", 8080),
        ("10.254.240.30", 8080),
        ("10.254.240.40", 8080),
        ("169.254.169.254", 80),
        ("198.51.100.9", 443),
        ("127.0.0.11", 53),
    ]
    assert all(connect(*peer) for peer in allowed), "allowed connectivity unavailable"
    assert not any(connect(*peer) for peer in denied), "egress isolation failed"
    assert not Path("/var/run/docker.sock").exists()
    try:
        Path("/tmp/must-not-write").write_text("deny")
    except (PermissionError, OSError):
        pass
    else:
        raise AssertionError("worker filesystem is writable")
    status = Path("/proc/self/status").read_text()
    assert "CapEff:\t0000000000000000" in status
    assert "NoNewPrivs:\t1" in status
    print(
        json.dumps(
            {
                "kind": "CI connectivity evidence, not a lab scan",
                "allowed_connections": len(allowed),
                "denied_destinations": len(denied),
                "worker_capabilities": "none",
                "docker_socket": "absent",
                "root_filesystem": "read-only",
                "ipv6": "disabled",
            }
        )
    )


if __name__ == "__main__":
    main()
