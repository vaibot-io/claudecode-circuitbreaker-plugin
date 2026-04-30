# VAIBot Governance Plugin for Claude Code

A Claude Code plugin that intercepts every tool call, evaluates it against your governance policy, and enforces the decision before execution proceeds.

VAIBot classifies each tool call by risk and returns an allow, deny, or approval-required verdict. Every decision creates a tamper-evident receipt with on-chain provenance anchoring. The plugin works with zero configuration — a free account is provisioned automatically on first run.

## Plugin vs. MCP server

VAIBot also ships an MCP server that exposes governance tools Claude can call voluntarily. The plugin and the MCP server are complementary — they serve different roles:

| | MCP server | This plugin |
|---|---|---|
| Agent queries policy / status | ✓ | ✗ |
| Agent approves actions in-session | ✓ | ✓ |
| Enforcement happens before execution | ✗ | ✓ |
| Agent can skip or bypass the check | ✓ | ✗ |
| Audit trail the agent can't forge | ✗ | ✓ |

The MCP server gives the agent a way to query and interact with VAIBot. This plugin is what makes governance **mandatory** — it hooks into Claude Code's PreToolUse event before the tool executes, regardless of what the agent chooses to do. If the goal is a tamper-evident audit record or blocking a misbehaving agent, the plugin is the enforcement layer that actually enforces it.

Most deployments use both: the plugin for mandatory pre-execution enforcement, the MCP server so the agent can surface policy context and manage approvals in-session.

## Quick start

```bash
claude --plugin-dir /path/to/claudecode-circuitbreaker-plugin
```

Or add to your project's `.claude/plugins.json`:

```json
{
  "plugins": [
    { "path": "./packages/claudecode-circuitbreaker-plugin" }
  ]
}
```

## What you see at runtime

**Allowed tool** — passes through silently. A receipt is recorded in the background.

**Approval required** — Claude Code shows a native approval dialog:
```
VAIBot flagged this Bash call as elevated risk — command writes outside workspace.
content_hash: sha256:a3f9c1...
Approving here will record your decision in the VAIBot audit chain.

Allow?  [Yes]  [No, tell Claude]
```

Clicking **Yes** records the approval and the tool proceeds. Clicking **No** records a denial — the agent is told the action was blocked and why.

If you later approve the same action from the dashboard, the agent retries it automatically on its next attempt.

**Hard deny** — the tool is blocked outright. The agent receives the policy reason and reports it to you.

**In observe mode** — all tools proceed, but the policy verdict is logged to stderr:
```
VAIBot [observe]: Bash would be denial — command writes outside workspace.
```

## Modes

### Observe (default)

All tool calls are allowed. The governance verdict is logged but never enforced. Use this to audit your agent's behaviour before enabling enforcement.

```bash
export VAIBOT_MODE=observe
```

### Enforce

Tool calls are blocked when the policy returns `deny` or `approval_required`. The agent sees the policy reason.

```bash
export VAIBOT_MODE=enforce
```

## Auto-bootstrap

On first run with no API key, the plugin calls `POST /v2/bootstrap` with a machine fingerprint and provisions a free-tier account. Credentials are saved to `~/.vaibot/credentials.json` and reused on every subsequent run.

If the account was already provisioned (e.g. by the OpenClaw plugin on the same machine) but the local key is missing, you'll see:
```
VAIBot: account exists but API key not found locally.
  Check ~/.vaibot/credentials.json or set VAIBOT_API_KEY manually.
```

To claim your account and approve actions from the dashboard, visit the URL printed on first run or run `/vaibot status`.

## Slash commands

| Command | Description |
|---|---|
| `/vaibot status` | Auth context, quota usage, and current governance mode |
| `/vaibot pending` | List tool calls waiting for approval |
| `/vaibot approve <content_hash>` | Approve a pending action |
| `/vaibot deny <content_hash>` | Deny a pending action |
| `/vaibot recent` | Recent governance receipts |
| `/vaibot policy` | Active governance policy |

## Configuration

All environment variables are optional.

| Variable | Default | Description |
|---|---|---|
| `VAIBOT_API_KEY` | _(auto-provisioned)_ | Bearer token for the governance API |
| `VAIBOT_MODE` | `observe` | `observe` or `enforce` |
| `VAIBOT_API_URL` | `https://api.vaibot.io` | API base URL |
| `VAIBOT_TIMEOUT_MS` | `10000` | Request timeout in ms |
| `VAIBOT_FAIL_OPEN` | `false` | If `true`, allow tool calls when the API is unreachable |
| `VAIBOT_DEBUG` | _(unset)_ | Set to `1` for verbose decision logging |

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
    │◄─ allow/deny/ask ───────────┤                            │
    │                              │                            │
    ├─ [tool executes or blocked]  │                            │
    │                              │                            │
    ├─ PostToolUse ───────────────►│                            │
    │  (outcome, duration)         ├─ finalizeReceipt()         │
    │                              │                            │
```

## Skipped tools

Tools prefixed with `mcp__vaibot` are skipped automatically to prevent the governance plugin from governing itself.

## Community & support

**[Join the VAIBot Discord](https://discord.gg/mSHYtP5nV)** — get help, share feedback, and connect with other users.

VAIBot is in early access. If you're installing this plugin now, you're among the first developers putting verifiable AI governance into production. Early community members shape the roadmap directly — feature requests, policy design, and integration patterns all come from conversations in Discord.

To become a founding member, join the Discord and introduce yourself in **#founding-members**. Founding members get:
- Direct access to the VAIBot team
- Early previews of upcoming governance features
- Input on default policy design and approval workflows
- Recognition in the project

## Uninstall

Remove the plugin path from `.claude/plugins.json` or stop passing `--plugin-dir`. No state is written outside `~/.vaibot/` and a system temp directory (`/tmp/vaibot-claudecode/`).
