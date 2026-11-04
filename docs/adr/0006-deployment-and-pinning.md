# ADR 0006 - Local-first modules, reproducible dependencies and verified isolation

**Status:** accepted for implementation; 4 November 2026.

## Decision

Start with modular API/UI/worker/report processes, PostgreSQL, Redis and private object paths. Provide a local native development path and Linux container/VM execution profile. Do not expose scanner admin services or vulnerable targets publicly. Real lab workers require separately verified egress and organizer authorization; container network labels are insufficient.

T03 resolves compatible supported runtimes/packages and commits exact lockfiles and image digests after build/migration checks. T06 inventories installed editions/feeds/licenses and host requirements. Unsupported or absent tools stay explicit. Avoid prerelease/unpinned production dependencies and unverified benchmark/resource claims.

## Alternatives and consequences

Cloud-first deployment and a large orchestrator add cost/access/network assumptions not needed for the prototype. Local-only undocumented dependencies fail fresh checkout. Containers improve reproducibility but cannot be claimed available on this host: Docker is currently absent on PATH. Windows-specific scanner limitations require Linux/VM verification, not guessed commands.

T03/T04/T14/T66 own deployment/isolation implementation; CI, fresh-environment checks, denial cases and restore review provide proof. No Docker installation, paid provisioning or live test is performed by this decision.
