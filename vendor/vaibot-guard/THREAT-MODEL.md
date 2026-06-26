# VAIBot Guard — Threat Model (no-allowlist governance)

_Last updated: 2026-05-30. Scope: the universal `@vaibot/guard` daemon and the
no-allowlist decision engine it hosts for the codex / claudecode / openclaw
adapters._

## 1. Model in one paragraph

There is **no allowlist**. "Safe" is *computed* on every call from the intrinsic
properties of the action — never granted once and remembered — so there is no
mutable, poisonable grant store to attack. Enforcement is the composition of
four layers, each of which can only *add* denials:

1. a **signed denylist** (the un-overridable safety floor) carried in an
   Ed25519-signed, versioned policy bundle;
2. a **stateless risk classifier** with a hard-coded destructive floor
   (`rm -rf /`, `curl|sh`, fork bombs, `mkfs`, …) that is **not** table-driven;
3. **ephemeral session approvals** — in-memory, session-scoped, never persisted;
4. **fail-closed verification** — a missing / malformed / expired / unsigned
   bundle falls back to the conservative built-in defaults, never below them.

The only **durable** policy is the server-signed bundle. Everything else
(approvals, classifier verdicts) is recomputed per call or per session.

## 2. Assets

| Asset | Why it matters |
|---|---|
| Integrity of the deny decision | A bypass executes attacker-chosen actions on the developer's machine. |
| Provenance / audit chain | Tier-1 Merkle ledger + tier-2 signed receipts are the verifiable record; a downgrade weakens accountability. |
| The bundle **signing key** (server-held) | Compromise lets an attacker mint policy. Out of scope for the client; mitigated by expiry, anchoring, and (future) revocation. |
| Developer secrets / workspace | The actions the guard gates touch real files, networks, and credentials. |

## 3. Trust boundaries

```
 [ AI agent ]            untrusted — may be prompt-injected
     │  hook (thin client, holds guard token)
     ▼
 [ @vaibot/guard daemon ]   trusted; binds 127.0.0.1 only; token auth; lock 0600
     │  POST /api/prove, receipts
     ▼
 [ V2 governance API ]      trusted server; holds the signing key
     │
     ▼
 [ Base chain ]             public anchor of Merkle roots + bundle hashes
```

The agent is **untrusted**. The hook is a thin client that forwards tool calls;
it cannot make policy. The daemon is the trust anchor on the local machine. The
issuer public key is **pinned by the client**, never read from the bundle.

## 4. Adversaries, attacks, and controls

| # | Adversary / attack | Control | Proven by |
|---|---|---|---|
| A1 | Prompt-injected agent tries to **self-grant** a denied action | Deny is un-overridable: the redemption path re-evaluates current policy; a valid approval may only upgrade an *ask* to *allow*, never resurrect a *deny*. Approvals are param-bound (`paramsHash`) and session-bound. | `guard-security-review.test.mjs` (G-162, G-164) |
| A2 | Agent tries to **mutate the signed policy** at runtime | No policy-write endpoint exists; the bundle is signature-verified and loaded once at startup. | `guard-security-review.test.mjs` (G-164) |
| A3 | **Hostile-but-signed bundle** relaxes a dangerous verb to "safe" | The destructive floor is hard-coded in the classifier (not table-driven). Bundle `classifierTables` that move a protected verb (`curl`, `rm`, `ssh`, …) into `safeCmds` are rejected wholesale → built-in defaults (fail-closed), so network egress keeps earning a receipt. | `guard-security-review.test.mjs` (G-163) |
| A4 | **Tampered / missing / expired** bundle | Fail-closed verification: any verification failure falls back to the safe built-in baseline (empty denylist + conservative classifier), never relaxing enforcement. | `guard-signed-policy.test.mjs` (G-165) |
| A5 | **Offline abuse** — mint a durable grant while the API is unreachable | Approvals are ephemeral and in-memory; the only durable policy is the signed bundle, which can't be created locally. Offline activity mints no durable grant and doesn't weaken policy across a restart. | `guard-security-review.test.mjs` (G-166), `guard-ephemeral-approvals.test.mjs` |
| A6 | **Replay** an approval into a later session | Approvals live in memory scoped to the daemon lifetime and are never written to disk; a restart drops them. Redemption is bound to `sessionId` and `paramsHash`. | `guard-ephemeral-approvals.test.mjs` |
| A7 | **Symlink / path traversal** to escape the workspace boundary | Path boundaries resolve via `realpath()`; mutation outside the workspace or into denied paths is denied outright, not merely flagged high-risk. | guard service (`decideExec` file-mutation posture) |
| A8 | **Foreign daemon** squats the guard port | Identity-validated `/health` (version + instanceId); token auth; localhost-only bind. | guard launch/discovery (L) |

## 5. Residual risks & known gaps

- **Shell-first coverage.** Governance is strongest on shell/exec and file
  tools. Per the Codex docs, some non-shell tools (e.g. WebSearch) are not
  intercepted by the hook surface. Hook-based governance is strong, not
  bulletproof — document, don't hide. (Plan §H.)
- **Codex `PermissionRequest`.** Codex ships a `PermissionRequest` hook
  (allow/deny via `hookSpecificOutput.decision.behavior`, or decline → native
  approval prompt), so an inline allow/deny/escalate UX is implementable. Until
  it is wired, `approval_required` denies with actionable instructions + a
  cached-approval retry path. (Plan E-145, implementable — not blocked.)
- **Governed allow-grants (F) not yet built.** When `vaibot policy request`
  lands, the protected-verb rejection (A3) **must** extend to allow-grant
  patterns — `Bash:*`, `rm *`, `curl *|sh` must be rejected even when signed.
- **Tier-3 anchoring** of the bundle hash and per-action coverage on Base is
  pending verification (plan item 219). Until then, provenance is tier-1/tier-2.
- **Operator-in-the-loop.** An agent holding the guard token can mint and
  resolve its own approval, but cannot escalate it onto a denied action (A1).
  Genuine human approval (dashboard / `vaibot approve` CLI) is the operator's
  responsibility; the guard guarantees the *deny floor*, not that a human, not
  the agent, clicked approve.
- **Signing-key compromise** is out of scope for the client. Mitigations are
  bundle expiry, on-chain anchoring of the bundle hash, and revocation (F-157,
  shipped).
- **Revocation channel integrity (F-157).** The guard refreshes the active bundle
  from `GET /v2/policy` on a timer; a bundle is only applied if it verifies
  against the pinned key, so a forged *bundle* can't be installed. But an
  authoritative "no active policy" (revocation) carries no signature, so a party
  who can MITM the (HTTPS) refresh could force a revocation — i.e. drop the
  user-added denylist back to built-in. The blast radius is bounded: the
  hard-coded destructive floor still applies, so this can only remove user-added
  denials, never relax the safety net. Mitigated in practice by TLS to the
  control plane; a signed revocation list is a future hardening.

## 6. Invariants (must always hold)

1. No input — with or without an approval — yields `allow` for a denylisted tool
   or a destructive-pattern command.
2. A signed bundle can only **add** denials or **raise** receipt tiers; it can
   never relax the built-in destructive floor or downgrade a protected verb.
3. Approvals never touch disk and never survive the session.
4. A verification failure never relaxes enforcement below the built-in baseline.
