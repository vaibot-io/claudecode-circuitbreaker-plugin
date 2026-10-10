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
 * Resolution goes through the LOCAL GUARD's finalize, the same path PostToolUse
 * uses for the "Yes" branch. It cannot go straight to the cloud: the only id a
 * hook holds for a gated call is the guard's local approvalId (`appr_<uuid>`),
 * while the API keys receipts by content_hash — and no cloud receipt exists yet
 * at this point anyway, since the guard posts it at finalize. Finalizing is
 * what creates the record of the denial.
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
import { resolveAsk, ASK_OPEN, ASK_REJECTED } from './lib/ask-resolution.mjs'

const TIMEOUT_MS = Number(process.env.VAIBOT_TIMEOUT_MS) || 10000

const STATE_DIR = join(tmpdir(), 'vaibot-claudecode')
const PENDING_DIR = join(STATE_DIR, 'pending')

// Resolve the running guard. By the time Stop fires, pre-tool-use has already
// launched it (lock written); honour the env override if set.
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

async function main() {
  // Drain stdin even if we ignore the payload — Claude Code buffers it.
  for await (const _chunk of process.stdin) { /* ignore */ }

  let files
  try {
    files = readdirSync(STATE_DIR).filter((f) => f.endsWith('.json'))
  } catch { process.exit(0) }

  // Only resolve the guard if there is actually a rejection to record.
  let guard

  for (const file of files) {
    const path = join(STATE_DIR, file)
    let entry
    try { entry = JSON.parse(readFileSync(path, 'utf-8')) } catch { continue }

    if (!entry?.approval_required) continue

    // Only a rejection the transcript records is a denial. Any other entry may
    // be a call whose dialog is still up (a subagent ending, or another session
    // sharing the state dir) — leave it for its own PostToolUse.
    const verdict = resolveAsk(entry)
    if (verdict === ASK_OPEN) continue

    // Claim the entry by unlinking BEFORE the network call — whichever hook
    // wins the unlink owns the resolution, so overlapping hooks can't
    // double-resolve the same run.
    try { unlinkSync(path) } catch { continue }

    // Abandoned: nobody is known to have said no, so record nothing. run_id is
    // what the guard finalizes against — without it there is nothing to record.
    if (verdict === ASK_REJECTED && entry.run_id) {
      if (guard === undefined) guard = resolveGuard()
      if (guard) {
        try {
          await fetch(`http://${guard.host}:${guard.port}/v1/finalize/tool`, {
            method: 'POST',
            headers: { 'content-type': 'application/json', authorization: `Bearer ${guard.token}` },
            body: JSON.stringify({
              sessionId: 'claude-code',
              runId: entry.run_id,
              result: { outcome: 'denied_by_reviewer', approval: 'denied' },
            }),
            signal: AbortSignal.timeout(TIMEOUT_MS),
          })
        } catch { /* best-effort */ }
      }
    }

    if (entry.intent_key) {
      try { unlinkSync(join(PENDING_DIR, `${entry.intent_key}.json`)) } catch {}
    }
  }

  process.exit(0)
}

main().catch(() => process.exit(0))
