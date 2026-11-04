# Worker network isolation — T14 implementation and remaining acceptance

The participant wants remote hosting and no local setup. `compose.security.yaml` is a CI-owned reproducible network-enforcement profile, not a deployed scanner service or organizer authorization. It runs benign connectivity endpoints only. The existing Celery `worker` in `compose.yaml` remains a control-plane diagnostic worker; it is not a scanner and must not receive arbitrary scan tasks.

The isolated execution profile shares only its gateway's network namespace. The unprivileged worker has zero Linux capabilities, no Docker socket, no control-plane/master/model credentials, no-new-privileges, read-only root filesystem, a process limit and bounded memory. Only the gateway has NET_ADMIN, with all other capabilities dropped. It is a trusted firewall exception, not an execution container. No host network or control-plane application network is attached.

Kernel OUTPUT/INPUT/FORWARD default to DROP. OUTPUT allows only exact pinned IPv4 address/transport/port entries and established replies; all other traffic is rejected with kernel counters. Incoming callbacks are not allowed. IPv6 is disabled for this initial profile and IPv6 policies fail closed in the compiler rather than bypassing the IPv4 firewall. There is no outbound DNS: the control plane resolves/reviews pins before release. Public-shaped addresses, metadata, sibling/control/admin fixtures, changed-IP fixtures and non-approved ports are denied. Required collector traffic is an explicit narrow exception.

`aegistrace.egress.compile_egress` generates fixed structured entries from a reviewed T13 policy and a separately trusted private mutual-TLS collector configuration. It refuses protected control-plane targets and unsupported IPv6. There are no user-selected firewall commands or arbitrary shell fragments. Production manifests expire; expiry flushes established/allow rules and removes readiness. The checked-in manifest works only with the explicitly enabled CI fixture mode and cannot be mistaken for a production authorization record.

Model/intelligence calls stay on a separate control-plane path and receive only explicitly approved sanitized data. No model API key, APP_SECRET, database owner credential or provider secret belongs in a scanner container. Later collector credentials must be assessment/run-scoped, short-lived and verified by the collector; that live collector integration is not implemented here. The CI collector is a harmless HTTP endpoint, deliberately not a claim of deployed mutual TLS.

Any raw-packet privilege needed by a tool requires a separate reviewed profile; the current zero-capability profile does not claim SYN/packet-capture support. Metasploit callbacks and unrestricted inbound listeners remain denied. Future modules need explicit action/module/port/destination authorization and isolated reset handling. Host/Docker administrators can change these controls; namespace confinement is not protection against a compromised kernel or host administrator.

## Actual CI verification

The hosted `egress` job builds the gateway, starts reachable benign target/collector/admin/sibling/changed-IP fixtures, and makes real socket connections from the unprivileged worker. Two allowed destinations must return HTTP 200; seven denied destinations/ports must not. The test checks missing Docker socket, zero effective capabilities, no-new-privileges and an unwritable otherwise-world-writable `/tmp`. It prints kernel rule counters and installed iptables version. Base image digest is pinned; Debian firewall-package resolution is recorded by the CI build, not represented as a fully reproducible apt snapshot. Cleanup always removes the CI profile.

Local policy tests check compilation/configuration; only hosted Linux CI can establish kernel behavior. No participant Docker installation is requested. A passing connectivity check is not a security scan, exploitation, genuine vulnerable lab fixture or production deployment proof.

## Remaining issue acceptance

T14 remains **open/partial** until a genuine authorized scanner runs in an actual deployed isolated runner and its allowed/denied flow evidence is captured. Actual hosted worker selection, collector mutual TLS/limited credential provisioning and scanner-specific privilege verification must accompany that integration. Free Render web hosting does not supply this privileged gateway boundary. Do not silently put scanners into the public application process or treat Python socket monkeypatching as this firewall.

No manual action is required now to build/test this profile. At actual assessment time, a suitable approved remote runner and valid target authority are required. The participant does not need to contact organizers or set up a laptop to continue independent implementation. R03/R04/R31/R32/W01/W07 are covered by the boundary design and tested kernel mechanism; live-lab evidence remains explicitly outstanding.
