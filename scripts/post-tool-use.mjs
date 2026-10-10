#!/usr/bin/env node
/**
 * VAIBot Claude Code PostToolUse hook.
 *
 * Reads the tool result from stdin (JSON), finds the matching run state saved
 * by pre-tool-use, and finalizes through the local VAIBot guard's
 * /v1/finalize/tool (which proves the finalize receipt) to close the run.
 *
 * Environment variables:
 *   VAIBOT_GUARD_BASE_URL — override the local guard URL (else discovered from the lock file)
 *   VAIBOT_GUARD_TOKEN    — bearer token for the local guard
 *   VAIBOT_TIMEOUT_MS     — request timeout in ms (default: 10000)
 */

import { readFileSync, readdirSync, unlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { readLock } from '../vendor/vaibot-guard/scripts/lib/guard-bootstrap.mjs'

const TIMEOUT_MS = Number(process.env.VAIBOT_TIMEOUT_MS) || 10000

// Resolve the running guard to finalize against. pre-tool-use already launched
// it (lock written) by the time PostToolUse fires; honour the env override if set.
function resolveGuard() {
  const baseUrl = process.env.VAIBOT_GUARD_BASE_URL
  if (baseUrl) {
    try {
      const u = new URL(baseUrl)
      return { host: u.hostname, port: Number(u.port) || 39111, token: process.env.VAIBOT_GUARD_TOKEN || '' }
    } catch { /* fall through */ }
  }
  const lock = readLock()
  return lock && lock.port ? { host: lock.host, port: lock.port, token: lock.token } : null
}

const STATE_DIR = join(tmpdir(), 'vaibot-claudecode')
const PENDING_DIR = join(STATE_DIR, 'pending')
const MAX_STATE_AGE_MS = 5 * 60 * 1000 // 5 minutes

function findRunState(toolName, toolUseId) {
  try {
    const files = readdirSync(STATE_DIR).filter(f => f.endsWith('.json'))
    const now = Date.now()
    let bestMatch = null
    let bestTs = 0

    for (const file of files) {
      try {
        const data = JSON.parse(readFileSync(join(STATE_DIR, file), 'utf-8'))

        // Expire ordinary entries after 5min. Ask-in-flight entries live until
        // a hook sweeps them (PostToolUse here, or PreToolUse/Stop sweep) —
        // human decisions can outlast the normal expiry window.
        if (!data.approval_required && now - data.ts > MAX_STATE_AGE_MS) {
          try { unlinkSync(join(STATE_DIR, file)) } catch { /* ignore */ }
          continue
        }

        // Exact tool_use_id match. The most-recent-tool_name fallback is only
        // for hook input that carries no id: when this call HAS an id and its
        // entry is gone (swept), the newest same-tool entry is a DIFFERENT
        // call — finalizing it would report an approval nobody gave.
        if (toolUseId && data.tool_use_id === toolUseId) {
          bestMatch = { ...data, file }
          break
        }
        if (!toolUseId && data.tool_name === toolName && data.ts > bestTs) {
          bestMatch = { ...data, file }
          bestTs = data.ts
        }
      } catch { /* ignore corrupt files */ }
    }

    // Claim the matched state file before any network call. If a parallel
    // sweep beats us to the unlink, abandon the match so we don't double-
    // resolve the same receipt.
    if (bestMatch) {
      try { unlinkSync(join(STATE_DIR, bestMatch.file)) }
      catch { return null }
    }

    return bestMatch
  } catch {
    return null
  }
}

async function main() {
  let raw = ''
  for await (const chunk of process.stdin) raw += chunk

  let hookInput
  try {
    hookInput = JSON.parse(raw)
  } catch {
    process.exit(0)
  }

  const toolName = hookInput.tool_name ?? hookInput.toolName ?? 'unknown'
  const toolUseId = hookInput.tool_use_id ?? hookInput.toolUseId ?? null
  const error = hookInput.tool_error ?? hookInput.error ?? null
  const durationMs = hookInput.duration_ms ?? hookInput.durationMs ?? null

  // Governance tools are exempt so a governance call cannot recurse into governing
  // itself, and so an operator can still lift containment from inside the agent.
  //
  // Matched at the namespace boundary, NOT as a bare prefix. Claude Code names MCP
  // tools `mcp__<server>__<tool>`, so an exemption that any name merely BEGINNING
  // with `mcp__vaibot` satisfied would hand a server called `vaibotage` a whole
  // tool namespace that is never governed at all -- no containment, no floor,
  // nothing. This check runs before the containment check below, so that gap was a
  // way around the account-wide stop.
  if (toolName === 'mcp__vaibot' || toolName.startsWith('mcp__vaibot__')) process.exit(0)

  const runState = findRunState(toolName, toolUseId)
  if (!runState?.run_id) process.exit(0)

  // PostToolUse firing for an ask-in-flight means the user clicked "Yes" in
  // Claude Code's native UI. That answer resolves the gate, so the call's
  // pending pointer is spent: left behind, the next identical call would
  // present the guard's still-pending approval id, and the guard denies an
  // unresolved approval (`Approval not approved (status=pending)`). Dropped
  // before the guard lookup so it goes even when the guard is unreachable.
  const nativelyApproved = runState.approval_required === true
  if (nativelyApproved && runState.intent_key) {
    try { unlinkSync(join(PENDING_DIR, `${runState.intent_key}.json`)) } catch { /* may not exist */ }
  }

  // Receipt exists and needs closing — having no API key here is a real problem,
  // not a silent skip. Warn so the user sees the receipt will be left open.
  // Direction A: finalize through the local guard (it proves the finalize
  // receipt). The guard recovers the session from the runId's stored context.
  const guard = resolveGuard()
  if (!guard) {
    process.stderr.write(
      `VAIBot [finalize]: no local guard reachable — run ${runState.run_id} left unfinalized.\n`
    )
    process.exit(0)
  }

  const outcome = error ? 'blocked' : 'allowed'
  const result = { outcome }
  // The answer the user gave, stated rather than inferred: the deny path
  // already reports `approval: 'denied'` through this same endpoint.
  if (nativelyApproved) result.approval = 'approved'
  if (typeof durationMs === 'number') result.duration_ms = durationMs
  if (error) result.error = String(error).slice(0, 2000)

  try {
    await fetch(`http://${guard.host}:${guard.port}/v1/finalize/tool`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${guard.token}` },
      body: JSON.stringify({ sessionId: 'claude-code', runId: runState.run_id, result }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    })
  } catch {
    // Best-effort finalization — don't block the session.
  }

  process.exit(0)
}

main().catch(() => process.exit(0))
