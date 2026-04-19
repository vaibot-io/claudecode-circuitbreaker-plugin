#!/usr/bin/env node
/**
 * VAIBot Claude Code PostToolUse hook.
 *
 * Reads tool result from stdin (JSON), finds the matching run state from
 * pre-tool-use, and calls the VAIBot finalize endpoint to close the receipt.
 *
 * Environment variables:
 *   VAIBOT_API_URL    — base URL of the VAIBot v2 API (default: https://api.vaibot.io)
 *   VAIBOT_API_KEY    — Bearer token for the governance API
 *   VAIBOT_TIMEOUT_MS — request timeout in ms (default: 10000)
 */

import { existsSync, readFileSync, readdirSync, unlinkSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'

// Credentials file — shared with pre-tool-use.mjs. The pre-hook's auto-bootstrap
// writes the account's api_key here on first run; the post-hook must read the
// same file to finalize receipts the pre-hook created. Reading env takes
// precedence so an explicit VAIBOT_API_KEY always wins.
const CREDS_FILE = join(homedir(), '.vaibot', 'credentials.json')

function loadSavedCredentials() {
  try {
    if (existsSync(CREDS_FILE)) {
      return JSON.parse(readFileSync(CREDS_FILE, 'utf-8'))
    }
  } catch { /* ignore corrupt file */ }
  return null
}

const API_URL = (process.env.VAIBOT_API_URL ?? 'https://api.vaibot.io').replace(/\/+$/, '')
const savedCreds = loadSavedCredentials()
const API_KEY = process.env.VAIBOT_API_KEY ?? savedCreds?.api_key ?? ''
const TIMEOUT_MS = Number(process.env.VAIBOT_TIMEOUT_MS) || 10000

const STATE_DIR = join(tmpdir(), 'vaibot-claudecode')
const MAX_STATE_AGE_MS = 5 * 60 * 1000 // 5 minutes

function findRunState(toolName) {
  try {
    const files = readdirSync(STATE_DIR).filter(f => f.endsWith('.json'))
    const now = Date.now()
    let bestMatch = null
    let bestTs = 0

    for (const file of files) {
      try {
        const data = JSON.parse(readFileSync(join(STATE_DIR, file), 'utf-8'))

        // Clean up expired state files
        if (now - data.ts > MAX_STATE_AGE_MS) {
          try { unlinkSync(join(STATE_DIR, file)) } catch { /* ignore */ }
          continue
        }

        // Match by tool name, take the most recent
        if (data.tool_name === toolName && data.ts > bestTs) {
          bestMatch = { ...data, file }
          bestTs = data.ts
        }
      } catch { /* ignore corrupt files */ }
    }

    // Clean up the matched state file
    if (bestMatch) {
      try { unlinkSync(join(STATE_DIR, bestMatch.file)) } catch { /* ignore */ }
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
  const error = hookInput.tool_error ?? hookInput.error ?? null
  const durationMs = hookInput.duration_ms ?? hookInput.durationMs ?? null

  // Skip governance tools
  if (toolName.startsWith('mcp__vaibot')) process.exit(0)

  const runState = findRunState(toolName)
  if (!runState?.run_id) process.exit(0)

  // Receipt exists and needs closing — having no API key here is a real problem,
  // not a silent skip. Warn so the user sees the receipt will be left open.
  if (!API_KEY) {
    process.stderr.write(
      `VAIBot [finalize]: no API key — receipt ${runState.run_id} left unfinalized. ` +
      `Set VAIBOT_API_KEY or ensure ${CREDS_FILE} is readable.\n`
    )
    process.exit(0)
  }

  const outcome = error ? 'blocked' : 'allowed'

  const body = {
    outcome,
    result: {
      duration_ms: durationMs,
      error: error ? String(error).slice(0, 2000) : undefined,
    },
  }

  try {
    await fetch(`${API_URL}/v2/governance/finalize/${encodeURIComponent(runState.run_id)}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${API_KEY}`,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    })
  } catch {
    // Best-effort finalization — don't block the session
  }

  process.exit(0)
}

main().catch(() => process.exit(0))
