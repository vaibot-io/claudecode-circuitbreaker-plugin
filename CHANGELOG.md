# Changelog

All notable changes to `@vaibot/claudecode-circuitbreaker-plugin`.

## [Unreleased]

### Fixed
- **Every second gated edit to a file was denied `Approval not approved (status=pending)`.**
  The retry pointer was keyed `tool | "Edit <file_path>" | cwd`, so all edits to one file
  shared it, and a "Yes" in Claude Code's dialog never spent it. The edit after an
  approved one presented the approved edit's approval id, which the guard still held as
  `pending`, and the guard denied it. That deny cleared the pointer, so the next edit
  prompted again: allowed, denied, allowed, denied. Re-running an identical approved
  Bash command failed the same way.
  - The pointer is now keyed on the exact call: tool, full input (stable key order) and
    cwd. Different calls never share one. An identical retry after an approval from the
    dashboard or email still finds its own.
  - PostToolUse now treats a gated call reaching it as the user's "Yes". It deletes that
    call's pointer and finalizes with `approval: "approved"`, the same field the deny
    path uses.
  - PostToolUse no longer falls back to "the newest entry for this tool" when the hook
    input has a `tool_use_id` but that id has no entry. That entry belongs to a
    different call, and finalizing it would record an approval nobody gave.
- **A pending approval dialog is no longer treated as a "No".** The ask-in-flight sweeps
  (PreToolUse of any later call, Stop, SubagentStop) resolved *every* ask entry in the
  shared state dir. That included a call whose dialog was still open: a parallel call,
  a subagent's call, or one from another Claude Code session. Its run-state and retry
  pointer were deleted, so a later "Yes" had nothing to finalize. Stop also PATCHed a
  denial for it.

  The sweeps now act only on evidence. Claude Code records a rejection in the session
  transcript as the call's `tool_result` (`is_error: true`, "The user doesn't want to
  proceed…"), and only that record, matched by the call's own `tool_use_id`, counts as a
  "No". Subagent transcripts are searched too. Run-state now stores the hook's
  `transcript_path`. An entry with no verdict is left alone. After 24 h it is dropped
  without recording a denial. The transcript is written asynchronously, so a rejection
  not yet flushed is simply picked up by a later sweep.

- **A call that fails after it was allowed is now finalized.** Claude Code fires
  `PostToolUseFailure`, not `PostToolUse`, when a tool that was allowed to run then
  fails (a non-zero Bash exit, an edit that can't apply, an interrupt). The plugin
  registered only `PostToolUse`, so these runs were never finalized. An ungated one
  expired after 5 minutes. One the user had approved was left for the ask sweep, which
  recorded it as a "No" before the sweep fix above, and afterwards held it for 24 h.
  `PostToolUseFailure` now runs the PostToolUse script. A failed call is finalized
  `ok: false` with its error (prefixed `[interrupted]` for an abort). After an ask, it
  is also finalized `approval: "approved"` and its retry pointer is spent. A permission
  denial returns before the tool runs, so this event is never a "No". This was checked
  against the Claude Code 2.1.296 bundle: the hook is called only from the `catch`
  around the tool's own execution.

## [1.3.2] — 2026-09-28 — the governance exemption, and guard 2.3.0

### Changed
- **Vendored guard refreshed to 2.3.0**, taken from the published tarball and verified
  against the digest the registry reports (`ecdd56a7f87604435e06a2eafc6de4b96bb7918b`),
  so the committed copy is provably what npm serves. It brings:

  - the **git classification fix** — `git -C <path> …` no longer launders
    `reset --hard`, `clean -f` or `push --force` from ask to allow, and `branch -D` /
    `tag -d` are no longer classified as reads;
  - **`floorAsk`**, a verdict tier no preset can make silent;
  - **approval leases** and **batch approvals**, which this breaker inherits through
    the guard's decision path rather than implementing itself.

  **This changes what runs without asking, on the `permissive` preset.** The guard
  gained a third verdict tier — `floorAsk`, which always asks and which no preset can
  lower — so actions that cannot be undone by whoever authorised them now prompt even
  under `permissive`, which previously never prompted. Measured on the vendored
  classifier this breaker uses in-process:

  | command | 2.2.1 | 2.3.0 |
  |---|---|---|
  | `git branch -D <branch>` | allow | **ask** |
  | `git -C <path> reset --hard` | allow | **ask** |
  | `npm publish` · `cargo publish` | allow | **ask** |
  | `git status` · `npm test` | allow | allow |

  Routine work is untouched — there is a test table asserting exactly that, so the
  tier cannot drift into "ask about everything". If the new prompts are unwelcome, the
  lever is the preset, not the breaker version.

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
