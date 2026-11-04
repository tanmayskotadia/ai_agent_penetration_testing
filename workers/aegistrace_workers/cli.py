"""CLI initialization validates local environment before starting the diagnostic worker."""

from aegistrace_workers.app import create_worker

app = create_worker()
