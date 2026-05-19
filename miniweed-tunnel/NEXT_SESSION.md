# Miniweed Tunnel - Session Handoff (Compacted)

Last updated: 2026-05-19

## Current state

- Branch: `main`
- Working tree at handoff: clean
- Latest pushed commit: `267408a`

## What was completed in this chat

### Commits produced

1. `8721702` - Add multi-VPS failover controls and CrowdSec-ready setup scripts
2. `267408a` - Strengthen non-provider failover checks and CrowdSec operations

### P4-20 Multi-VPS / failover implemented

- Config model extended for multiple targets:
  - `vpsTargets[]`
  - `activeVpsId`
- Legacy compatibility kept:
  - old `vpsIp`/`vpsPort`/`vpsPubKey` are normalized into targets
  - active target is mirrored back into legacy fields for compatibility
- WireGuard generation now uses active target dynamically.
- Rotation flow now binds to active target (`buildVpsRotateScript(..., activeTarget)`).
- Health and failover strategy added:
  - per-target health probes
  - streak-based stability: `okStreak` and `failStreak`
  - thresholds and anti-flapping cooldown:
    - `FAILOVER_ACTIVE_FAILURES_REQUIRED=2`
    - `FAILOVER_CANDIDATE_SUCCESSES_REQUIRED=2`
    - `FAILOVER_COOLDOWN_MS=120000`
- Probe strategy without VPS provider API:
  - TCP reachability checks (`22`, fallback `443`) via `net.Socket`
- DNS health check aligns against current active target IP.

### P4-20 API + UI delivered

- New/updated API behavior:
  - `GET /api/vps/targets`
  - `POST /api/vps/failover` (auto if no `targetId`, manual if provided)
  - `GET /api/vps-setup-script?vpsId=...&withCrowdsec=1`
- `GET /api/config` now includes target context and fingerprints per target.
- UI (`web/public/index.html`) now includes:
  - management of additional VPS targets
  - target selector for setup script generation
  - CrowdSec toggle for generated setup script
  - manual failover and auto-failover trigger controls

### P4-21 CrowdSec implemented (without provider API)

- CrowdSec optional section in generated setup script (`withCrowdsec=1`).
- Added VPS operational assets:
  - `vps-setup/crowdsec-smoke.sh`
  - `vps-setup/crowdsec-recovery.md`
- README updated with non-provider CrowdSec workflow.

### Contract and tests improved

- Zod config schema expanded for multi-VPS in `web/api-spec/schemas.js`.
- OpenAPI in `server.js` expanded with:
  - `VpsTarget`, `VpsTargetsResponse`, `VpsFailoverRequest`, `VpsFailoverResponse`, `VpsSetupScriptResponse`
  - paths for `/api/vps/targets`, `/api/vps/failover`, `/api/vps-setup-script`
- Integration tests extended in `web/test/api.test.js`:
  - multi-VPS config + manual failover
  - setup script response with selected VPS and CrowdSec flag
  - vps targets health metadata endpoint
  - openapi contract presence for new failover endpoints/schemas

## Files touched in this chat

- `miniweed-tunnel/web/server.js`
- `miniweed-tunnel/web/public/index.html`
- `miniweed-tunnel/web/api-spec/schemas.js`
- `miniweed-tunnel/web/test/api.test.js`
- `miniweed-tunnel/README.md`
- `miniweed-tunnel/vps-setup/crowdsec-smoke.sh` (new)
- `miniweed-tunnel/vps-setup/crowdsec-recovery.md` (new)
- `miniweed-tunnel/NEXT_SESSION.md` (this handoff rewrite)

## Validation performed

- `npm test -- --runInBand` in `miniweed-tunnel/web` -> passing (18 tests).
- `python3 -m py_compile miniweed-tunnel/wg-client/wg-api.py` -> passing.
- `shellcheck` run on:
  - `miniweed-tunnel/wg-client/entrypoint.sh`
  - `miniweed-tunnel/wg-client/scripts/killswitch.sh`
  - `miniweed-tunnel/vps-setup/killswitch-service.sh`
  - `miniweed-tunnel/vps-setup/crowdsec-smoke.sh`

Note: Jest still reports open handles after tests complete (known behavior from server timers).

## Plan status vs `MEJORAS_SIN_DEPLOY.md`

### Done enough for now (without provider API)

- P0-1, P0-2, P0-3, P0-3-bis
- P1-4, P1-5, P1-6, P1-7, P1-8
- P2-9, P2-10, P2-11, P2-12
- P3-13, P3-14 (repo-level CI exists), P3-15
- P4-18, P4-19
- P4-20 largely implemented
- P4-21 partially-to-strongly implemented without provider API (script + smoke + recovery)

### Still pending / next high-value work

1. P3-16: SPA frontend with build pipeline (current UI is still static `index.html`).
2. P3-17: complete typed API contract pipeline (single source + generated artifacts).
3. P4-20 hardening pass:
   - more failover edge-case tests (flapping, tie-breaks, recovery)
   - optional persistence/telemetry of failover state.
4. P4-21 hardening pass:
   - deeper bouncer/firewall interaction checks in docs/tests.
5. Test hygiene:
   - address Jest open-handles warning cleanly.

## Suggested resume point

When resuming, start from:

- `miniweed-tunnel/NEXT_SESSION.md`
- `MEJORAS_SIN_DEPLOY.md` (focus P3-16 and P3-17 first)
