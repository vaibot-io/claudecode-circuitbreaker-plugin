# VAIBot Governance Plugin for Claude Code

A Claude Code plugin that intercepts every tool call, sends it to the VAIBot governance API for risk classification and policy evaluation, and enforces the decision before execution proceeds.

## Quick start

```bash
claude --plugin-dir /path/to/claudecode-circuitbreaker-plugin
```

That's it. No API key required — the plugin auto-provisions a free-tier account on first run using a machine fingerprint. Credentials are saved to `~/.vaibot/credentials.json`.

## What it does

- **PreToolUse hook**: Before any tool executes, calls `POST /v2/governance/decide` with tool name, command, target, and workspace context. Based on the response:
  - `allow` → tool proceeds normally
  - `approval_required` → tool is blocked with instructions to approve via dashboard
  - `deny` → tool is blocked with the policy reason

- **PostToolUse hook**: After tool execution, calls `POST /v2/governance/finalize/{run_id}` to record the outcome (allowed/blocked) and close the receipt.

- **Auto-bootstrap**: On first run with no API key, calls `POST /v2/bootstrap` to provision a free-tier account with an API key and a CDP wallet (Base L2, x402-ready).

- **Slash commands**: `/vaibot status`, `/vaibot pending`, `/vaibot approve <hash>`

Every tool call creates a tamper-evident governance receipt with on-chain provenance anchoring.

## Installation

Add to your project's `.claude/plugins.json`:

```json
{
  "plugins": [
    { "path": "./packages/claudecode-circuitbreaker-plugin" }
  ]
}
```

Or run directly:

```bash
claude --plugin-dir /path/to/claudecode-circuitbreaker-plugin
```

## Configuration

All environment variables are optional — the plugin works with zero config.

```bash
# Auto-provisioned if not set (saved to ~/.vaibot/credentials.json)
export VAIBOT_API_KEY="vb_stg_..."

# Optional overrides
export VAIBOT_API_URL="https://api.vaibot.io"  # API base URL (default)
export VAIBOT_MODE="observe"            # "observe" (default) or "enforce"
export VAIBOT_TIMEOUT_MS="10000"        # API timeout in ms
export VAIBOT_FAIL_OPEN="false"         # If true, allow on API errors
```

## Modes

### Observe (default)

All tool calls are allowed, but governance decisions are recorded. Shadow decisions (what would have been blocked) are logged to stderr. Free tier — no payment required.

```bash
export VAIBOT_MODE=observe
```

### Enforce

Tool calls are blocked if the governance API returns `deny` or `approval_required`. The agent sees the policy reason and can inform the user.

```bash
export VAIBOT_MODE=enforce
```

## Onboarding flow

```
1. Install plugin → run Claude Code
2. First tool call → no API key found
3. Plugin calls POST /v2/bootstrap with machine fingerprint
4. API creates: free-tier account + API key + CDP wallet (Base L2)
5. Credentials saved to ~/.vaibot/credentials.json
6. Observe mode starts immediately (free, no wallet funding needed)

Later, to enable enforcement:
7. Set VAIBOT_MODE=enforce
8. Pay per governance decision via x402 (USDC on Base)
   OR subscribe for volume discounts + API key auth
```

## How decisions flow

```
Claude Code                    VAIBot API                    On-chain
    │                              │                            │
    ├─ PreToolUse ────────────────►│                            │
    │  (tool, command, target)     │                            │
    │                              ├─ classifyRisk()            │
    │                              ├─ makeDecision()            │
    │                              ├─ buildReceipt()            │
    │                              ├─ anchorProvenance() ──────►│
    │◄─ allow/deny/approval ──────┤                            │
    │                              │                            │
    ├─ [tool executes]             │                            │
    │                              │                            │
    ├─ PostToolUse ───────────────►│                            │
    │  (outcome, duration)         ├─ finalizeReceipt()         │
    │                              │                            │
```

## Skipped tools

The following are automatically skipped to avoid recursion:
- Any tool starting with `mcp__vaibot` (VAIBot's own MCP tools)

## File structure

```
claudecode-circuitbreaker-plugin/
├── .claude-plugin/
│   └── plugin.json           # Plugin manifest
├── hooks/
│   └── hooks.json            # PreToolUse + PostToolUse hook definitions
├── skills/
│   └── vaibot/
│       └── SKILL.md          # /vaibot slash command
├── scripts/
│   ├── pre-tool-use.mjs      # Governance gate (decide) + auto-bootstrap
│   └── post-tool-use.mjs     # Receipt closer (finalize)
└── README.md
```
