# Miniweed Tunnel - Next Session Handoff

Last updated: 2026-05-19

## Current state

- Branch: `main`
- Working tree: clean
- Last pushed commit: `70d9a92`

## Completed in this cycle

- Key rotation prepare/confirm/status flow.
- Kill-switch endpoint and hardened generated script.
- Audit chain verification endpoint.
- OpenAPI + Zod request validation for rotate endpoints.
- Docs updates (`README.md`, `MEJORAS_SIN_DEPLOY.md`).
- Local VPS-side helper scripts:
  - `vps-setup/killswitch-service.sh`
  - `wg-client/scripts/killswitch.sh`

## Pending work (next)

1. P4-20: Multi-VPS / failover
   - data model for multiple VPS targets
   - health-based failover strategy
   - API + UI controls
   - tests for failover decisions

2. P4-21: CrowdSec in VPS
   - install/hardening script integration
   - bouncer/firewall interaction checks
   - documentation and recovery steps
   - tests/smoke checks

## Suggested start command

When resuming, start from:

- `miniweed-tunnel/NEXT_SESSION.md`
- `MEJORAS_SIN_DEPLOY.md` (sections P4-20 and P4-21)
