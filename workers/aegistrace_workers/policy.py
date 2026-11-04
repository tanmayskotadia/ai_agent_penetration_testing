"""Dispatch must reload authority, resolve/pin and reserve limits before any tool call."""

from uuid import UUID

from aegistrace.lab import Profile
from aegistrace.policy import (
    Destination,
    Resolver,
    authorize,
    dns_addresses,
    load_policy,
    reserve_policy,
)
from sqlalchemy import Connection


def dispatch_preflight(
    connection: Connection,
    assessment_id: UUID,
    policy_id: UUID,
    url: str,
    profile: Profile,
    resolver: Resolver = dns_addresses,
    protected_networks: tuple[str, ...] = (),
) -> Destination:
    policy = load_policy(connection, assessment_id, policy_id)
    destination = authorize(policy, url, profile, resolver, protected_networks)
    reserve_policy(connection, policy)
    return destination
