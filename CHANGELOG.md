# Changelog

All notable changes to `@vaibot/claudecode-circuitbreaker-plugin`.

## [Unreleased] — fresh-install & enforce-by-default

### Changed
- **Default posture is now `enforce`** (was `observe`). When the guard is reachable
  it still publishes the account's `effective_mode`, which wins; this default only
  governs the guard-DOWN fallback.
- **Guard-unreachable now degrades _conditionally_ instead of blanket-denying:**
  - the catastrophic floor is enforced locally in every case (classifier
    `DANGEROUS` → deny) — `rm -rf /`, guard self-protection, fork bombs stay blocked
    even with no daemon running;
  - **cold start** (fresh install, no rendezvous lock) → **allow-with-audit** so a
    new machine can bootstrap the daemon instead of bricking;
  - **established install** whose lock is present but the daemon is gone and
    un-relaunchable → **stays fail-closed (deny) + alerts** (possible tampering);
  - a **reachable-but-erroring** guard/endpoint (5xx, decide failure) stays
    fail-closed — degrade applies only to a truly-absent local daemon, never to an
    endpoint that responded.
- Synced vendored `@vaibot/guard` (system-config commands → approval on the command
  head, `policy.default.json` v0.3, launcher boot log + 10s cold-start budget).

### Notes
- Net effect vs. the old `observe` default: guard-UP behavior is unchanged (account
  mode wins); guard-DOWN is no longer a silent allow-all — it enforces the floor and
  only degrades a genuine fresh install. See the guard's `THREAT-MODEL.md` §9 for the
  tamper-resistance analysis this is scoped against.
