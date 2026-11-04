"""Trusted-worker process primitive, not a public arbitrary command endpoint."""

import os
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass

import psutil


@dataclass(frozen=True)
class ProcessOutcome:
    state: str
    reason: str
    elapsed_seconds: float
    exit_code: int | None
    termination_confirmed: bool


def running(process: psutil.Process) -> bool:
    try:
        return process.is_running() and process.status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False


def run_managed(
    argv: tuple[str, ...], deadline_seconds: float, should_cancel: Callable[[], bool]
) -> ProcessOutcome:
    if not argv or not 0 < deadline_seconds <= 300:
        raise ValueError("bounded trusted command required")
    started = time.monotonic()
    try:
        cancelled = should_cancel()
    except Exception:
        return ProcessOutcome("cancelled-before-start", "control-unavailable", 0, None, True)
    if cancelled:
        return ProcessOutcome("cancelled-before-start", "stop-requested", 0, None, True)
    environment = {
        name: os.environ[name]
        for name in ["PATH", "SYSTEMROOT", "WINDIR", "LANG", "LC_ALL"]
        if name in os.environ
    }
    if sys.platform == "win32":
        flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
    else:
        flags = 0
    process = subprocess.Popen(
        list(argv),
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=environment,
        start_new_session=os.name != "nt",
        creationflags=flags,
    )
    root = psutil.Process(process.pid)
    reason = "finished"
    known: dict[int, psutil.Process] = {root.pid: root}
    while process.poll() is None:
        try:
            known.update({child.pid: child for child in root.children(recursive=True)})
            cancelled = should_cancel()
        except Exception:
            reason = "control-unavailable"
            break
        if cancelled:
            reason = "stop-requested"
            break
        if time.monotonic() - started >= deadline_seconds:
            reason = "deadline"
            break
        time.sleep(0.05)
    if reason == "finished" and any(
        running(child) for pid, child in known.items() if pid != root.pid
    ):
        reason = "descendants-remain"
    if reason == "finished":
        return ProcessOutcome(
            "finished", reason, time.monotonic() - started, process.returncode, True
        )
    try:
        children = root.children(recursive=True)
    except psutil.NoSuchProcess:
        children = []
    known.update({child.pid: child for child in children})
    tracked = list(known.values())
    if sys.platform != "win32":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    for child in reversed(tracked):
        try:
            child.terminate()
        except psutil.NoSuchProcess:
            pass
    _, alive = psutil.wait_procs(tracked, timeout=0.5)
    if sys.platform != "win32":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    for child in alive:
        try:
            child.kill()
        except psutil.NoSuchProcess:
            pass
    psutil.wait_procs(alive, timeout=0.5)
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        pass
    confirmed = not any(running(child) for child in tracked)
    return ProcessOutcome(
        "terminated" if confirmed else "unknown",
        reason,
        time.monotonic() - started,
        process.poll(),
        confirmed,
    )
