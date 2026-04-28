---
description: VAIBot governance commands — manage approvals, view receipt status, and query audit receipts
---

# /vaibot

VAIBot governance commands for managing approvals and viewing status.

## Usage

- `/vaibot status` — show auth context, quota usage, and governance mode
- `/vaibot pending` — list actions waiting for approval
- `/vaibot approve <content_hash>` — approve a pending action
- `/vaibot deny <content_hash>` — deny a pending action
- `/vaibot recent` — show recent governance receipts
- `/vaibot policy` — show the active governance policy

## Implementation

When the user runs `/vaibot <subcommand>`, use the appropriate MCP tool:

- `status` → call `mcp__vaibot-governance__vaibot_status` (or production equivalent)
- `pending` → call `mcp__vaibot-governance__vaibot_pending`
- `approve` → call `mcp__vaibot-governance__vaibot_approve` with the content_hash
- `deny` → call `mcp__vaibot-governance__vaibot_deny` with the content_hash
- `recent` → call `mcp__vaibot-governance__vaibot_recent`
- `policy` → call `mcp__vaibot-governance__vaibot_policy`

If no MCP server is available, fall back to REST API calls using `VAIBOT_API_URL` and `VAIBOT_API_KEY`.
