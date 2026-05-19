# Miniweed Tunnel - Session Handoff (Compacted)

Last updated: 2026-05-19

## Current state

- Branch: `main`
- Working tree at handoff: clean
- Latest pushed commit: `0a85746`

## What was completed in this chat

### Commits produced

1. `8721702` - Add multi-VPS failover controls and CrowdSec-ready setup scripts
2. `267408a` - Strengthen non-provider failover checks and CrowdSec operations
3. `8e5518f` - Document full session handoff and add quick pointer
4. `cfe78d4` - Add SPA scaffold and typed API contract pipeline
5. `713feda` - Improve test/server lifecycle cleanup and quieter Jest output
6. `19e397a` - Migrate core legacy UI flows into SPA frontend
7. `bf0053c` - Refine SPA parity with legacy UI behaviors
8. `cefc559` - Serve SPA as default UI with legacy fallback route
9. `083a835` - Refresh NEXT_SESSION with SPA-default and contract progress
10. `bb9ddad` - Release miniweed-tunnel 1.5.0 with SPA default UI
11. `b59c4d2` - Extend CI with API contract and SPA build checks
12. `0a85746` - Add failover edge-case integration coverage

### P4-20 + P4-21 (without provider API)

- Multi-VPS model in backend (`vpsTargets[]`, `activeVpsId`) with legacy field compatibility.
- Failover implemented with health probes and anti-flapping thresholds/cooldown.
- Endpoints delivered:
  - `GET /api/vps/targets`
  - `POST /api/vps/failover`
  - `GET /api/vps-setup-script?vpsId=...&withCrowdsec=1`
- CrowdSec optional setup integrated in generated script (`withCrowdsec=1`).
- Operational CrowdSec assets delivered:
  - `vps-setup/crowdsec-smoke.sh`
  - `vps-setup/crowdsec-recovery.md`

### P3-16 SPA migration and route switch

- New SPA app under `web/ui/` now includes major parity with legacy tabs/flows:
  - dashboard/status/services links
  - config + auth + services + vps setup/failover
- SPA is now default at `/` and `/index.html` when build exists.
- Legacy UI kept as fallback route at `/legacy` and `/legacy/index.html`.

### P3-17 contract pipeline

- Generated OpenAPI runtime snapshot to `web/api-spec/openapi.json`.
- Generated TypeScript declarations to `web/api-spec/openapi.d.ts`.
- Added tooling scripts:
  - `tools/generate-openapi.js`
  - `tools/check-openapi.js`
- Added npm scripts in `web/package.json`:
  - `api:spec`, `api:spec:check`, `api:types`, `api:contract`, `ui:build`, `build`

### Test/runtime hygiene improvements

- Added background timer lifecycle helpers in server (`ensureBackgroundTimers`, `stopBackgroundTimers`).
- Added explicit test cleanup for server/timers and quieter test logs.
- Jest warning about open handles may still appear in normal run, but suites pass.

### Release and CI updates

- Umbrel app released as `1.5.0` with updated web image digest in `docker-compose.yml`.
- CI now validates API contract snapshot and SPA build in `.github/workflows/ci.yml`.
- Failover edge-case integration tests added for:
  - streak/cooldown/recovery behavior
  - tie-break by lexical name when priorities are equal

## Validation performed

- `npm run api:contract` in `miniweed-tunnel/web` -> passing.
- `npm run ui:build` in `miniweed-tunnel/web` -> passing.
- `npm test -- --runInBand` in `miniweed-tunnel/web` -> passing (20 tests).
- `python3 -m py_compile miniweed-tunnel/wg-client/wg-api.py` -> passing.
- `shellcheck` run on critical scripts in prior phase -> passing.

## Plan status vs `MEJORAS_SIN_DEPLOY.md`

### Done enough for now (without provider API)

- P0-1, P0-2, P0-3, P0-3-bis
- P1-4, P1-5, P1-6, P1-7, P1-8
- P2-9, P2-10, P2-11, P2-12
- P3-13, P3-14, P3-15
- P3-16 mostly implemented (SPA now default, legacy fallback kept)
- P3-17 mostly implemented (OpenAPI + generated types + scripts)
- P4-18, P4-19
- P4-20 largely implemented
- P4-21 partially-to-strongly implemented without provider API

### Still pending / next high-value work

1. P3-16 parity final pass:
   - minor UX/message parity details vs legacy
   - decide removal timeline for legacy route
2. P3-17 hardening:
   - consume generated `openapi.d.ts` types deeply in SPA client code
   - tighten CI to regenerate+diff contract (`api:spec` drift guard)
3. P4-20 hardening pass:
   - extend edge-case tests beyond current coverage (manual/auto interplay, disabled-target recovery)
4. P4-21 hardening pass:
   - deeper CrowdSec bouncer/firewall checks in docs/tests
5. Test hygiene:
   - investigate remaining Jest open-handle warning to fully silence

## Suggested resume point

When resuming, start from:

- `miniweed-tunnel/NEXT_SESSION.md`
- `MEJORAS_SIN_DEPLOY.md` (focus P3-17 hardening + P4 edge-case hardening)
