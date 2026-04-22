#!/usr/bin/env node
/**
 * VAIBot Claude Code Stop / SubagentStop hook.
 *
 * Fallback sweep for ask-in-flight receipts that never got resolved by a
 * following PostToolUse or PreToolUse. If the assistant's turn ends with the
 * user having clicked "No, tell Claude" on the last tool call (and Claude
 * didn't attempt another tool), this hook is the final chance to record that
 * denial on the receipt chain.
 *
 * Environment variables:
 *   VAIBOT_API_URL    — base URL of the VAIBot v2 API (default: https://api.vaibot.io)
 *   VAIBOT_API_KEY    — Bearer token (auto-loaded from ~/.vaibot/credentials.json)
 *   VAIBOT_TIMEOUT_MS — request timeout in ms (default: 10000)
 */

import { existsSync, readFileSync, readdirSync, unlinkSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'

const CREDS_FILE = join(homedir(), '.vaibot', 'credentials.json')

function loadSavedCredentials() {
  try {
    if (existsSync(CREDS_FILE)) return JSON.parse(readFileSync(CREDS_FILE, 'utf-8'))
  } catch { /* ignore corrupt file */ }
  return null
}

const API_URL = (process.env.VAIBOT_API_URL ?? 'https://api.vaibot.io').replace(/\/+$/, '')
const savedCreds = loadSavedCredentials()
const API_KEY = process.env.VAIBOT_API_KEY ?? savedCreds?.api_key ?? ''
const TIMEOUT_MS = Number(process.env.VAIBOT_TIMEOUT_MS) || 10000

const STATE_DIR = join(tmpdir(), 'vaibot-claudecode')
const PENDING_DIR = join(STATE_DIR, 'pending')

async function main() {
  // Drain stdin even if we ignore the payload — Claude Code buffers it.
  for await (const _chunk of process.stdin) { /* ignore */ }

  if (!API_KEY) process.exit(0)

  let files
  try {
    files = readdirSync(STATE_DIR).filter((f) => f.endsWith('.json'))
  } catch { process.exit(0) }

  for (const file of files) {
    const path = join(STATE_DIR, file)
    let entry
    try { entry = JSON.parse(readFileSync(path, 'utf-8')) } catch { continue }

    if (!entry?.approval_required || !entry.content_hash) continue

    try { unlinkSync(path) } catch { continue }  // lost race to another hook

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

  process.exit(0)
}

main().catch(() => process.exit(0))
