# @vaibot/guard

**VAIBot Guard** — a local policy-decision + enforcement daemon with a tamper-evident audit log. It is the **universal decision authority** that the per-host circuit-breaker plugins (Claude Code, Codex, OpenClaw) route every tool call through, so enforcement is **agent-agnostic**: one guard, many hosts.

## Installation

**The guard is generally installed and managed by the VAIBot CLI** — you don't normally install this package by hand:

```bash
vaibot init            # onboard + install the guard as part of setup
vaibot guard install   # install / manage the guard directly
```

Manual install (what the CLI does for you):

```bash
npm install -g @vaibot/guard
```

That provides two binaries: `vaibot-guard` (operator CLI) and `vaibot-guard-service` (the daemon).

## What it does

A local HTTP service that gates agent tool calls and writes a **tamper-evident audit log** (incremental Merkle accumulator, JSONL) under `.vaibot-guard/`. Decisions are driven by a signed policy bundle; receipts can be anchored to the VAIBot provenance chain.

## Credentials (treat as secrets)
- `VAIBOT_GUARD_TOKEN` — bearer token for guard endpoints (recommended)
- `VAIBOT_API_KEY` — optional: anchor receipts to VAIBot `/prove`

## HTTP API
- `GET  /health`
- `POST /v1/decide/exec`   + `POST /v1/finalize`            — shell exec flows
- `POST /v1/decide/tool`   + `POST /v1/finalize/tool`       — tool-call gating
- `POST /v1/approvals/list` + `POST /v1/approvals/resolve`  — approve / deny
- `POST /v1/flush`         — checkpoint flush
- `POST /api/proof`        — Merkle inclusion proofs

When `VAIBOT_GUARD_TOKEN` is set, protected endpoints require `Authorization: Bearer <token>`.

## Per-host enforcement (circuit-breaker plugins)

The guard makes the decisions; a per-host **circuit-breaker plugin** intercepts tool calls and routes them to the guard, so enforcement happens at the host boundary rather than relying on the model to behave. Wire the plugin for your agent with:

```bash
vaibot plugin add <host>   # claudecode | codex | openclaw
```

Each plugin **ensures the guard is present, installing it only if it's missing** — the CLI is the first-class installer; the plugins are the fallback.

## Manual quick start (foreground, no persistence)

```bash
export VAIBOT_GUARD_HOST=127.0.0.1
export VAIBOT_GUARD_PORT=39111
export VAIBOT_POLICY_PATH=references/policy.default.json
export VAIBOT_WORKSPACE="$(pwd)"
export VAIBOT_GUARD_LOG_DIR="$VAIBOT_WORKSPACE/.vaibot-guard"
export VAIBOT_GUARD_TOKEN="<random-token>"

vaibot-guard-service                 # or: node scripts/vaibot-guard-service.mjs
curl -s http://127.0.0.1:39111/health
```

## systemd user service

```bash
vaibot-guard install-local           # or: node scripts/vaibot-guard.mjs install-local
```

Writes `~/.config/systemd/user/vaibot-guard.service` + `~/.config/vaibot-guard/vaibot-guard.env`. The unit adds OpenClaw-gateway ordering **only on OpenClaw hosts**; otherwise it runs standalone. Templates live under `references/systemd/`.

## Policy + schemas

See `references/`: `policy.md`, `policy.default.json`, `receipt-schema.md`, `checkpoint-schema.md`, `inclusion-proofs.md`, `required-mode.md`.

## Tests

```bash
npm test    # node --test tests/*.test.mjs
```

## Threat model

See `THREAT-MODEL.md`.
