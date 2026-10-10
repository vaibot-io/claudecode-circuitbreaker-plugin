/**
 * How an ask-in-flight was answered, read from the session transcript.
 *
 * An ask-in-flight is a run-state entry whose PreToolUse returned
 * `permissionDecision: 'ask'`. "Yes" is seen directly: PostToolUse fires and
 * consumes the entry. "No" fires no hook at all, so the sweeps (PreToolUse of a
 * later call, Stop, SubagentStop) used to treat ANY entry they found as a "No".
 * That was wrong whenever the entry belonged to a call whose dialog was still
 * up: a parallel call in the same turn, a subagent, or another Claude Code
 * session sharing the state dir. Its runState and retry pointer were deleted,
 * so a later "Yes" found nothing to finalize.
 *
 * Claude Code writes the user's rejection into the transcript as the call's
 * tool_result:
 *   { type: 'tool_result', tool_use_id, is_error: true,
 *     content: "The user doesn't want to proceed with this tool use. …" }
 * with `toolUseResult: 'User rejected tool use'` on the enclosing record. That
 * record, keyed by the call's own tool_use_id, is the only evidence a sweep
 * acts on. No record means the dialog may still be open, so the entry is left
 * alone.
 */
import { readFileSync, readdirSync } from 'node:fs'
import { basename, dirname, extname, join } from 'node:path'

export const ASK_REJECTED = 'rejected'
export const ASK_ABANDONED = 'abandoned'
export const ASK_OPEN = 'open'

// An entry with no verdict in the transcript after this long is local garbage:
// no dialog stays up for a day. It is dropped WITHOUT claiming a denial,
// because nobody is known to have said no.
export const ASK_ABANDON_MS = 24 * 60 * 60 * 1000

const REJECTION_TEXT = "The user doesn't want to proceed with this tool use"
const REJECTION_RESULT = 'User rejected tool use'

// A subagent's tool calls are recorded in its own transcript, next to the
// session's: <dir>/<session>.jsonl → <dir>/<session>/subagents/agent-*.jsonl.
function transcriptFiles(transcriptPath) {
  const files = [transcriptPath]
  const subagents = join(dirname(transcriptPath), basename(transcriptPath, extname(transcriptPath)), 'subagents')
  try {
    for (const f of readdirSync(subagents)) {
      if (f.endsWith('.jsonl')) files.push(join(subagents, f))
    }
  } catch { /* no subagents */ }
  return files
}

function isRejectionRecord(record, toolUseId) {
  const content = record?.message?.content
  if (!Array.isArray(content)) return false
  return content.some((c) =>
    c?.type === 'tool_result'
    && c.tool_use_id === toolUseId
    && c.is_error === true
    && (record.toolUseResult === REJECTION_RESULT
      || (typeof c.content === 'string' && c.content.startsWith(REJECTION_TEXT))),
  )
}

/** True only when the transcript shows the user rejected this exact call. */
export function askWasRejected(entry) {
  const toolUseId = entry?.tool_use_id
  const transcriptPath = entry?.transcript_path
  if (!toolUseId || !transcriptPath) return false
  for (const file of transcriptFiles(transcriptPath)) {
    let text
    try { text = readFileSync(file, 'utf-8') } catch { continue }
    if (!text.includes(toolUseId)) continue
    for (const line of text.split('\n')) {
      if (!line.includes(toolUseId)) continue
      let record
      try { record = JSON.parse(line) } catch { continue }
      if (isRejectionRecord(record, toolUseId)) return true
    }
  }
  return false
}

/**
 * ASK_REJECTED  — the user said no: record the denial, drop the entry.
 * ASK_ABANDONED — no verdict after ASK_ABANDON_MS: drop it, record nothing.
 * ASK_OPEN      — no verdict yet: the dialog may be up; leave it alone.
 */
export function resolveAsk(entry, now = Date.now()) {
  if (askWasRejected(entry)) return ASK_REJECTED
  if (typeof entry?.ts === 'number' && now - entry.ts > ASK_ABANDON_MS) return ASK_ABANDONED
  return ASK_OPEN
}
