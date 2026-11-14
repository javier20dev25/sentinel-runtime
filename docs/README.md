# Sentinel Runtime documentation index

This index separates documents that describe shipped behavior from designs and historical reviews.

## Current operational documents

- [Implementation status](IMPLEMENTATION_STATUS.md): code-backed capability inventory, validation evidence, and open release gates.
- [Linux systemd deployment](DEPLOYMENT_SYSTEMD.md): installation paths, account separation, file permissions, sandboxing, and residual risks.
- [Runtime self-protection threat model](threat-model/RUNTIME_SELF_PROTECTION.md): attacker capabilities, implemented controls, validation, and trust limits.
- [Runtime lab report](labs/SR-RT-001-LOCAL-RESILIENCE.md): bounded WSL2 test procedure and observed output boundaries.
- [Cloud host investigation tasks](../packaging/systemd/README.md): the fixed L0 read-only playbook interface and its required Linux permissions.
- [Configuration guide](CONFIGURATION.md): supported environment variables and CLI settings.

## Normative or candidate specifications

- [Event Contract v2 proposal](specs/EVENT_CONTRACT_V2_PROPOSAL.md)
- [Event Contract provenance matrix](specs/EVENT_CONTRACT_PROVENANCE_MATRIX.md)
- [Tetragon v1.8.0 field mapping](specs/TETRAGON_V1_8_0_FIELD_MAPPING.md)

Event Contract v2 remains a development candidate. A schema, mapping, or design document is not proof that a provider emits the event or that the live collector received it.

## Historical reports and reviews

Files named REVIEW, REPORT, CORRECTION, PHASE, or MILESTONE are retained for traceability. Read their status banners and dates before relying on them. They may record superseded claims, incomplete experiments, or design intent. The current source and the three current operational documents above take precedence for shipped behavior.

## Manual scripts and experiments

The scripts under scripts/manual are intentionally excluded from automatic test discovery. The SR-RT-001 runner is bounded, unprivileged, WSL2-only, and limited to local loopback traffic as described in its lab report. Other smoke scripts have separate prerequisites; review each script before using it in a disposable laboratory.
