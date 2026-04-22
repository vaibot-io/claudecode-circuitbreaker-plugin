#!/usr/bin/env node
/**
 * VAIBot Claude Code PreToolUse hook.
 *
 * Reads tool call details from stdin (JSON), calls the VAIBot governance API,
 * and outputs a permission decision to stdout.
 *
 * On first run with no API key, auto-bootstraps a free-tier account by calling
 * POST /v2/bootstrap with a machine fingerprint. Credentials are saved to
 * ~/.vaibot/credentials.json for subsequent runs.
 *
 * Environment variables:
 *   VAIBOT_API_URL    — base URL of the VAIBot v2 API (default: https://api.vaibot.io)
 *   VAIBOT_API_KEY    — Bearer token for the governance API (auto-provisioned if missing)
 *   VAIBOT_MODE       — "observe" (default) or "enforce"
 *   VAIBOT_TIMEOUT_MS — request timeout in ms (default: 10000)
 *
 * Exit codes:
 *   0 — allow (or observe mode)
 *   2 — deny (reason written to stderr)
 */

import { createHash } from 'node:crypto'
import { writeFileSync, readFileSync, readdirSync, mkdirSync, existsSync, unlinkSync } from 'node:fs'
import { tmpdir, hostname, userInfo } from 'node:os'
import { join } from 'node:path'
import { homedir } from 'node:os'

// ── Credentials file ───────────────────────────────────────────────────────

const CREDS_DIR = join(homedir(), '.vaibot')
const CREDS_FILE = join(CREDS_DIR, 'credentials.json')

function loadSavedCredentials() {
  try {
    if (existsSync(CREDS_FILE)) {
      return JSON.parse(readFileSync(CREDS_FILE, 'utf-8'))
    }
  } catch { /* ignore corrupt file */ }
  return null
}

function saveCredentials(creds) {
  try {
    mkdirSync(CREDS_DIR, { recursive: true, mode: 0o700 })
    writeFileSync(CREDS_FILE, JSON.stringify(creds, null, 2), { mode: 0o600 })
  } catch { /* best-effort */ }
}

// ── Config ──────────────────────────────────────────────────────────────────

const API_URL = (process.env.VAIBOT_API_URL ?? 'https://api.vaibot.io').replace(/\/+$/, '')
const TIMEOUT_MS = Number(process.env.VAIBOT_TIMEOUT_MS) || 10000
const AGENT_MODEL = 'claude-code'
const FAIL_OPEN = process.env.VAIBOT_FAIL_OPEN === 'true'

// API key: env var > saved credentials
const savedCreds = loadSavedCredentials()
let API_KEY = process.env.VAIBOT_API_KEY ?? savedCreds?.api_key ?? ''
const MODE = process.env.VAIBOT_MODE ?? 'observe'

// ── Fingerprint ────────────────────────────────────────────────────────────
// Forensic correlation signal — NOT machine attestation.
// Used for bootstrap idempotency and abuse pattern detection.

function getFingerprint() {
  const user = userInfo().username
  const host = hostname()
  const cwd = process.cwd()
  return createHash('sha256').update(`${user}@${host}:${cwd}`).digest('hex')
}

// ── Auto-bootstrap ─────────────────────────────────────────────────────────

async function bootstrap() {
  const fingerprint = getFingerprint()

  const res = await fetch(`${API_URL}/v2/bootstrap`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ fingerprint, agent: 'claude-code' }),
    signal: AbortSignal.timeout(TIMEOUT_MS),
  })

  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new Error(`Bootstrap failed (${res.status}): ${text.slice(0, 200)}`)
  }

  const data = await res.json()

  if (data.api_key) {
    // New account — wallet address is the canonical identity
    saveCredentials({
      api_key: data.api_key,
      account_id: data.account_id,
      user_id: data.user_id,
      wallet_address: data.wallet_address,
      wallet_network: data.wallet_network,
      api_url: API_URL,
      bootstrapped_at: new Date().toISOString(),
    })
    process.stderr.write(
      `VAIBot: account provisioned. Credentials saved to ${CREDS_FILE}\n` +
      (data.wallet_address ? `VAIBot: identity ${data.wallet_address} on ${data.wallet_network}\n` : '')
    )
    return data.api_key
  }

  if (data.bootstrapped === false) {
    // Already provisioned but we lost the key — tell the user
    process.stderr.write(
      `VAIBot: account exists but API key not found locally.\n` +
      `  Check ${CREDS_FILE} or set VAIBOT_API_KEY manually.\n`
    )
    return null
  }

  return null
}

// ── State file for run tracking ─────────────────────────────────────────────

const STATE_DIR = join(tmpdir(), 'vaibot-claudecode')
const PENDING_DIR = join(STATE_DIR, 'pending')

function saveRunState(toolCallId, state) {
  try {
    mkdirSync(STATE_DIR, { recursive: true })
    writeFileSync(join(STATE_DIR, `${toolCallId}.json`), JSON.stringify(state))
  } catch { /* best-effort */ }
}

// ── Ask-in-flight sweep ────────────────────────────────────────────────────
// When PreToolUse emitted `permissionDecision: 'ask'`, the runState carries
// `approval_required: true`. If the user clicks "Yes", PostToolUse fires and
// consumes the entry (calling PATCH /approve). If the user clicks "No, tell
// Claude", PostToolUse never fires — the entry remains until the next hook
// (PreToolUse of a later call, Stop, or SubagentStop) sweeps it and calls
// PATCH /deny.
//
// Race note: claim the entry by unlinking it BEFORE issuing the network call.
// Whichever process wins the unlink owns the resolution; the loser (e.g. a
// PostToolUse running in parallel) sees ENOENT and bails out. This keeps the
// receipt event chain coherent even if hook processes overlap.

async function sweepPendingApprovals({ excludeToolUseId } = {}) {
  let files
  try {
    files = readdirSync(STATE_DIR).filter((f) => f.endsWith('.json'))
  } catch { return }

  for (const file of files) {
    const path = join(STATE_DIR, file)
    let entry
    try { entry = JSON.parse(readFileSync(path, 'utf-8')) } catch { continue }

    if (!entry?.approval_required) continue
    if (excludeToolUseId && entry.tool_use_id === excludeToolUseId) continue
    if (!entry.content_hash) { try { unlinkSync(path) } catch {} ; continue }

    try { unlinkSync(path) } catch { continue }  // lost the race — another hook is handling it

    try {
      await fetch(`${API_URL}/v2/receipts/${encodeURIComponent(entry.content_hash)}/deny`, {
        method: 'PATCH',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${API_KEY}` },
        signal: AbortSignal.timeout(TIMEOUT_MS),
      })
    } catch { /* best-effort */ }

    if (entry.intent_key) {
      try { unlinkSync(join(PENDING_DIR, `${entry.intent_key}.json`)) } catch {}
    }
  }
}

// ── Pending-approval state (retry awareness) ────────────────────────────────
// Untrusted hint only. The server re-verifies intent (tool + command + cwd)
// against the referenced approved receipt before honoring a short-circuit, so
// a tampered file here cannot redirect an approval onto a different intent.

function intentHash(tool, command, cwd) {
  return createHash('sha256').update(`${tool}|${command ?? ''}|${cwd ?? ''}`).digest('hex').slice(0, 32)
}

function pendingPath(tool, command, cwd) {
  return join(PENDING_DIR, `${intentHash(tool, command, cwd)}.json`)
}

function readPendingApproval(tool, command, cwd) {
  try {
    const p = pendingPath(tool, command, cwd)
    if (!existsSync(p)) return null
    return JSON.parse(readFileSync(p, 'utf-8'))
  } catch { return null }
}

function writePendingApproval(tool, command, cwd, contentHash) {
  try {
    mkdirSync(PENDING_DIR, { recursive: true, mode: 0o700 })
    writeFileSync(pendingPath(tool, command, cwd), JSON.stringify({ content_hash: contentHash, ts: Date.now() }), { mode: 0o600 })
  } catch { /* best-effort */ }
}

function clearPendingApproval(tool, command, cwd) {
  try { unlinkSync(pendingPath(tool, command, cwd)) } catch { /* may not exist */ }
}

// ── Onboarding nudge (one-shot per session) ────────────────────────────────
// On the first approval_required of a session, if the account is still on its
// synthetic @bootstrap.vaibot.io email (claimed:false), nudge the user to
// claim it via the MCP tool so they can approve from the dashboard.

const NUDGED_DIR = join(STATE_DIR, 'nudged')

function nudgeMarkerPath(sessionId) {
  const safe = createHash('sha256').update(String(sessionId)).digest('hex').slice(0, 32)
  return join(NUDGED_DIR, safe)
}

function alreadyNudged(sessionId) {
  try { return existsSync(nudgeMarkerPath(sessionId)) } catch { return false }
}

function markNudged(sessionId) {
  try {
    mkdirSync(NUDGED_DIR, { recursive: true, mode: 0o700 })
    writeFileSync(nudgeMarkerPath(sessionId), String(Date.now()), { mode: 0o600 })
  } catch { /* best-effort */ }
}

async function maybeNudgeUnclaimed(sessionId) {
  if (alreadyNudged(sessionId)) return
  try {
    const res = await fetch(`${API_URL}/v2/accounts/me`, {
      headers: { authorization: `Bearer ${API_KEY}` },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    })
    if (!res.ok) return
    const data = await res.json()
    if (data?.claimed === false) {
      process.stderr.write(
        `VAIBot: claim your account to approve from the dashboard.\n` +
        `  Run via MCP:  vaibot_set_account_email { email: "you@example.com" }\n`
      )
      markNudged(sessionId)
    }
  } catch { /* best-effort */ }
}

async function bestEffortFinalize(runId, outcome, summary) {
  if (!runId) return
  try {
    await fetch(`${API_URL}/v2/governance/finalize/${encodeURIComponent(runId)}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${API_KEY}` },
      body: JSON.stringify({ outcome, result: { summary } }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    })
  } catch { /* non-blocking */ }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function clamp(str, max = 2000) {
  if (typeof str !== 'string') return str
  return str.length > max ? str.slice(0, max) + '…' : str
}

function extractCommand(toolName, input) {
  if (!input) return undefined
  if (toolName === 'Bash') return clamp(input.command)
  if (toolName === 'Edit') return clamp(`Edit ${input.file_path}`)
  if (toolName === 'Write') return clamp(`Write ${input.file_path}`)
  if (toolName === 'Read') return clamp(`Read ${input.file_path}`)
  if (toolName === 'Grep') return clamp(`Grep ${input.pattern}`)
  if (toolName === 'Glob') return clamp(`Glob ${input.pattern}`)
  if (toolName === 'WebFetch') return clamp(input.url)
  if (toolName === 'Agent') return clamp(input.prompt?.slice(0, 500))
  return undefined
}

function extractTarget(toolName, input) {
  if (!input) return undefined
  if (input.file_path) return input.file_path
  if (input.url) return input.url
  if (input.path) return input.path
  return undefined
}

function extractCwd(toolName, input) {
  if (!input) return undefined
  if (input.cwd) return input.cwd
  return process.cwd()
}

function stableHash(obj) {
  const json = JSON.stringify(obj, Object.keys(obj).sort())
  return createHash('sha256').update(json).digest('hex').slice(0, 16)
}

// ── Main ────────────────────────────────────────────────────────────────────

async function main() {
  // Read hook input from stdin
  let raw = ''
  for await (const chunk of process.stdin) raw += chunk

  let hookInput
  try {
    hookInput = JSON.parse(raw)
  } catch {
    // Can't parse input — fail open to avoid blocking Claude Code
    process.exit(0)
  }

  const toolName = hookInput.tool_name ?? hookInput.toolName ?? 'unknown'
  const toolInput = hookInput.tool_input ?? hookInput.toolInput ?? {}
  const sessionId = hookInput.session_id ?? hookInput.sessionId ?? `cc-${Date.now()}`
  const toolUseId = hookInput.tool_use_id ?? hookInput.toolUseId ?? null

  // Skip governance for the governance tools themselves (avoid recursion)
  if (toolName.startsWith('mcp__vaibot')) {
    process.exit(0)
  }

  // No API key — try auto-bootstrap
  if (!API_KEY) {
    try {
      const bootstrapKey = await bootstrap()
      if (bootstrapKey) {
        API_KEY = bootstrapKey
      } else {
        // Bootstrap returned no key (already provisioned but lost) — fail open
        process.exit(0)
      }
    } catch (err) {
      process.stderr.write(`VAIBot [bootstrap]: ${err.message}\n`)
      process.exit(0) // fail open on bootstrap failure
    }
  }

  // Resolve any still-pending ask-in-flight from a prior tool call. If the user
  // clicked "No, tell Claude" on a previous `ask`, no PostToolUse fired — so
  // this sweep is the first place the denial gets recorded server-side.
  await sweepPendingApprovals({ excludeToolUseId: toolUseId })

  const command = extractCommand(toolName, toolInput)
  const target = extractTarget(toolName, toolInput)
  const cwd = extractCwd(toolName, toolInput)
  const toolCallId = toolUseId ?? stableHash({ toolName, ...toolInput, ts: Date.now() })

  const body = {
    session_id: sessionId,
    agent_id: 'claude-code',
    agent_model: AGENT_MODEL,
    tool: toolName,
    workspace_dir: process.cwd(),
    intent: { command, target, cwd },
  }

  // Retry awareness: if we previously got approval_required for this exact
  // intent and saved a pointer, send it. Server re-verifies intent.
  const pending = readPendingApproval(toolName, command, cwd)
  if (pending?.content_hash) {
    body.approved_content_hash = pending.content_hash
  }

  try {
    const res = await fetch(`${API_URL}/v2/governance/decide`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${API_KEY}`,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    })

    if (!res.ok) {
      const text = await res.text().catch(() => '')
      if (FAIL_OPEN || MODE === 'observe') process.exit(0)
      process.stderr.write(`VAIBot: governance API returned ${res.status}: ${text.slice(0, 200)}\n`)
      process.exit(2)
    }

    const data = await res.json()

    // Session-start onboarding nudge — fires once per session on the first
    // tool call (regardless of decision outcome). The marker under STATE_DIR
    // guarantees idempotency across retries. Safe-users who never hit
    // approval_required still see it exactly once early in their flow.
    await maybeNudgeUnclaimed(sessionId)

    // Prefer shadow_decision (raw policy verdict) over decision (post-server-
    // observe-mode). Falls back to decision for older API responses.
    const rawDecision = data.shadow_decision?.decision ?? data.decision?.decision
    const rawReason = data.shadow_decision?.reason ?? data.decision?.reason

    // Save run state for post-tool-use finalization
    saveRunState(toolCallId, {
      run_id: data.run_id,
      content_hash: data.content_hash,
      receipt_id: data.receipt_id,
      decision: rawDecision,
      risk: data.risk?.risk,
      tool_name: toolName,
      tool_call_id: toolCallId,
      tool_use_id: toolUseId,
      approval_required: rawDecision === 'approval_required' && !data.previously_approved,
      intent_key: intentHash(toolName, command, cwd),
      ts: Date.now(),
    })

    // In observe mode, always allow but log the raw policy verdict
    if (MODE === 'observe') {
      if (rawDecision && rawDecision !== 'allow') {
        process.stderr.write(
          `VAIBot [observe]: ${toolName} would be ${rawDecision} — ${rawReason}\n`
        )
      }
      process.exit(0)
    }

    // Enforce mode — act on the raw decision (not server's observe-coerced one).
    // If the server short-circuited via previously_approved, the effective
    // decision is allow regardless of the policy verdict.
    const decision = data.previously_approved ? 'allow' : rawDecision

    if (decision === 'allow') {
      // Approval was consumed (or never needed) — clear pending state.
      clearPendingApproval(toolName, command, cwd)
      const output = {
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'allow',
        }
      }
      process.stdout.write(JSON.stringify(output))
      process.exit(0)
    }

    if (decision === 'approval_required') {
      const reason = rawReason ?? `Approval required for ${toolName}`
      const contentHash = data.content_hash ?? ''
      const riskLabel = data.risk?.risk ?? 'elevated'
      // Save pointer so a retry of this exact intent can short-circuit if the
      // user later approves from the dashboard instead of the native UI.
      if (contentHash) writePendingApproval(toolName, command, cwd, contentHash)
      // Route through Claude Code's native ask UI. The receipt stays in
      // `pending` state server-side: if the user picks Yes, PostToolUse will
      // PATCH /approve; if No, the next hook will sweep + PATCH /deny.
      // No finalize here — that would close the receipt prematurely and the
      // subsequent approve/deny PATCHes would return 404.
      const output = {
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'ask',
          permissionDecisionReason:
            `VAIBot flagged this ${toolName} call as ${riskLabel} risk — ${reason}\n` +
            `content_hash: ${contentHash}\n` +
            `Approving here will record your decision in the VAIBot audit chain.`,
        }
      }
      process.stdout.write(JSON.stringify(output))
      process.exit(0)
    }

    if (decision === 'deny') {
      const reason = rawReason ?? `Denied by policy for ${toolName}`
      // Hard-deny means even prior approval is irrelevant for this intent.
      clearPendingApproval(toolName, command, cwd)
      await bestEffortFinalize(data.run_id, 'blocked', `Plugin enforced: deny`)
      const output = {
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'deny',
          permissionDecisionReason: reason,
        }
      }
      process.stdout.write(JSON.stringify(output))
      process.exit(0)
    }

    // Unknown decision — fail open
    process.exit(0)

  } catch (err) {
    // Network error, timeout, etc.
    if (FAIL_OPEN || MODE === 'observe') {
      process.stderr.write(`VAIBot [error]: ${err.message}\n`)
      process.exit(0)
    }
    process.stderr.write(`VAIBot: governance API unreachable — ${err.message}\n`)
    process.exit(2)
  }
}

main().catch((err) => {
  process.stderr.write(`VAIBot: unexpected error — ${err.message}\n`)
  process.exit(FAIL_OPEN ? 0 : 2)
})
