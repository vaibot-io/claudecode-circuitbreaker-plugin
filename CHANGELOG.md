# Changelog

All notable changes to `@vaibot/claudecode-circuitbreaker-plugin`.

## [1.3.2] — 2026-09-27 — the governance exemption is a namespace, not a prefix

### Fixed
- **A look-alike MCP server could take a tool namespace that was never governed.**
  Governance tools are exempt from the breaker so that a governance call cannot
  recurse into governing itself, and so that an operator can still lift containment
  from inside the agent. That exemption matched any tool name merely *beginning*
  with `mcp__vaibot`, so a server called `vaibotage` was handed every tool
  under it: no containment check, no catastrophic floor, no policy at all. And
  because the exemption is tested *before* the containment check, it was a way
  around the account-wide stop added in 1.3.0 as well.

  The exemption now matches at the namespace boundary — exactly `mcp__vaibot`, or a
  name under `mcp__vaibot__`. Nothing an operator needs while contained changed.

## [1.3.1] — 2026-09-27 — vendored guard 2.2.1

### Changed
- Vendored guard refreshed to **2.2.1**, a declaration-only fix: the guard's
  `lib/guard-bootstrap.d.mts` was missing seven exports the module genuinely has.
  Runtime was never affected and this plugin's behaviour is unchanged; the version
  moved only because the vendored content did.

## [1.3.0] — 2026-09-26 — containment on every degraded path

### Added
- **The account-wide containment stop is honoured before any other decision.** The
  guard has enforced containment since 2.2.0, but only for calls that reach the
  daemon. Every path where this plugin degrades — daemon unreachable, no API key,
  breaker tripped, fail-open, hook timeout — skips that call, and so skipped
  containment; observe mode let everything through with a log line. Those are
  exactly the paths an account-wide block has to survive. The check now runs first,
  against the machine-wide record the guard writes, which needs no daemon, no
  network and no credentials.

## [1.2.0] — 2026-07-05 — account key recovery

### Changed
- On `bootstrapped:false` (account exists but no local API key — e.g. the key was
  lost), the plugin now presents **both** recovery paths instead of a dead end:
  run `vaibot login` (re-issues a key via your session) **or** set `VAIBOT_API_KEY` /
  check `credentials.json`. Both are valid; neither replaces the other.

## [1.1.0] — 2026-07-04 — fresh-install, graceful degrade & honest receipts

### Changed
- **Default posture is now `enforce`** (was `observe`). When the guard is reachable
  it still publishes the account's `effective_mode`, which wins; this default only
  governs the guard-DOWN fallback.
- **Guard-unreachable degrades to the local classifier instead of bricking:**
  - the catastrophic floor is always enforced locally (classifier `DANGEROUS` → deny)
    — `rm -rf /`, guard self-protection, fork bombs stay blocked with no daemon;
  - **cold start** (fresh install, no rendezvous lock) → **allow-with-audit** so a new
    machine can bootstrap the daemon;
  - **established install** whose daemon is gone → **governs locally with the
    classifier** (classifier-safe tools + the `vaibot login` recovery path pass, risky
    tools prompt, the floor denies) and **alerts** on possible tampering — a routine
    reboot no longer bricks a working box;
  - a **reachable-but-erroring** guard (5xx / decide failure) stays fail-closed.
- **A missing API key never bricks the agent** — it governs locally (safe tools run,
  risky tools route to the native approval prompt, the floor denies) instead of
  failing closed, and always leaves `vaibot login` reachable to recover.
- **Failing closed over an explicitly-`observe` account is now announced** to stderr,
  so an operator who chose audit-only isn't silently surprised during an outage.

### Vendored guard (2.1.0)
- Destructive host-config verbs hard-deny (`systemctl stop|disable|mask`, `service …
  stop`, `launchctl unload|remove|bootout`, `crontab` install) — matched on
  wrapped/absolute/`sh -c` forms, un-overridable by any preset.
- The guard's OWN lifecycle is allow-listed (systemd + macOS `launchctl io.vaibot.guard`
  + CLI + the `:39111` health probe), so managing the guard never prompts; teardown
  still denies.
- Honest receipts: `risk_level` matches the decision that drove the gate, and an allowed
  action reads `allowed` (not `blocked`).

### Notes
- Net vs. the old `observe` default: guard-UP behavior is unchanged (account mode wins);
  guard-DOWN enforces the floor and degrades gracefully instead of allowing everything
  or bricking. See the guard's `THREAT-MODEL.md` §9 for the tamper-resistance analysis.
