import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { mkdtempSync, existsSync, writeFileSync, mkdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const SCRIPT = join(__dirname, '..', 'scripts', 'stop.mjs')

const REJECTION = "The user doesn't want to proceed with this tool use. The tool use was rejected (eg. if it was a file edit, the new_string was NOT written to the file). STOP what you are doing and wait for the user to tell you how to proceed."

function startMockGuard() {
  return new Promise((resolve) => {
    const requests = []
    const server = createServer((req, res) => {
      let body = ''
      req.on('data', (c) => { body += c })
      req.on('end', () => {
        requests.push({ method: req.method, url: req.url, auth: req.headers.authorization, body: body ? JSON.parse(body) : null })
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end('{"ok":true}')
      })
    })
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address()
      resolve({ url: `http://127.0.0.1:${port}`, requests, close: () => new Promise((r) => server.close(r)) })
    })
  })
}

// Sandboxed HOME and TMPDIR (state dir): Stop sweeps every entry in the state
// dir, so the shared one would expose other suites' entries.
function sandbox() {
  const root = mkdtempSync(join(tmpdir(), 'vaibot-cc-stop-'))
  const home = join(root, 'home')
  const tmp = join(root, 'tmp')
  mkdirSync(home, { recursive: true })
  mkdirSync(join(tmp, 'vaibot-claudecode', 'pending'), { recursive: true })
  return { root, home, tmp, stateDir: join(tmp, 'vaibot-claudecode') }
}

function seedAsk(sb, toolUseId, transcriptLines, { ts = Date.now(), runId = `run_${toolUseId}` } = {}) {
  const transcriptPath = join(sb.root, `${toolUseId}.jsonl`)
  writeFileSync(transcriptPath, transcriptLines.join('\n') + '\n')
  const entryPath = join(sb.stateDir, `${toolUseId}.json`)
  writeFileSync(entryPath, JSON.stringify({
    tool_name: 'Bash', tool_use_id: toolUseId, run_id: runId ?? undefined,
    content_hash: `appr_${toolUseId}`, approval_required: true,
    intent_key: `ik_${toolUseId}`, transcript_path: transcriptPath, ts,
  }))
  const pointerPath = join(sb.stateDir, 'pending', `ik_${toolUseId}.json`)
  writeFileSync(pointerPath, '{}')
  return { entryPath, pointerPath }
}

function runStop(sb, guardUrl) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [SCRIPT], {
      env: { ...process.env, HOME: sb.home, TMPDIR: sb.tmp, VAIBOT_GUARD_BASE_URL: guardUrl, VAIBOT_GUARD_TOKEN: 'test-guard-token', VAIBOT_TIMEOUT_MS: '2000' },
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    child.on('error', reject)
    child.on('exit', (code) => resolve({ code }))
    child.stdin.end('{}')
  })
}

function rejectionLine(toolUseId) {
  return JSON.stringify({
    type: 'user', toolUseResult: 'User rejected tool use',
    message: { content: [{ type: 'tool_result', tool_use_id: toolUseId, is_error: true, content: REJECTION }] },
  })
}

const finalizes = (g) => g.requests.filter((r) => r.method === 'POST' && r.url === '/v1/finalize/tool')

test('stop: an ask with no answer yet (a subagent or other session ending) is left alone, nothing finalized', async () => {
  const g = await startMockGuard()
  const sb = sandbox()
  try {
    const a = seedAsk(sb, 'tu_open', [])
    await runStop(sb, g.url)
    assert.ok(existsSync(a.entryPath), 'entry kept for its own PostToolUse')
    assert.ok(existsSync(a.pointerPath), 'pointer kept')
    assert.equal(g.requests.length, 0)
  } finally {
    await g.close()
    rmSync(sb.root, { recursive: true, force: true })
  }
})

test('stop: a recorded rejection is finalized through the local guard as denied — no cloud PATCH', async () => {
  const g = await startMockGuard()
  const sb = sandbox()
  try {
    const a = seedAsk(sb, 'tu_no', [rejectionLine('tu_no')])
    await runStop(sb, g.url)
    assert.ok(!existsSync(a.entryPath))
    assert.ok(!existsSync(a.pointerPath))
    const fin = finalizes(g)
    assert.equal(fin.length, 1)
    assert.equal(fin[0].auth, 'Bearer test-guard-token')
    assert.deepEqual(fin[0].body, { sessionId: 'claude-code', runId: 'run_tu_no', result: { outcome: 'denied_by_reviewer', approval: 'denied' } })
    assert.equal(g.requests.filter((r) => r.method === 'PATCH').length, 0, 'the old /v2/receipts/:hash/deny PATCH could only 404')
  } finally {
    await g.close()
    rmSync(sb.root, { recursive: true, force: true })
  }
})

test('stop: an abandoned ask is cleared without claiming a denial', async () => {
  const g = await startMockGuard()
  const sb = sandbox()
  try {
    const a = seedAsk(sb, 'tu_old', [], { ts: Date.now() - 25 * 60 * 60 * 1000 })
    await runStop(sb, g.url)
    assert.ok(!existsSync(a.entryPath))
    assert.ok(!existsSync(a.pointerPath))
    assert.equal(g.requests.length, 0)
  } finally {
    await g.close()
    rmSync(sb.root, { recursive: true, force: true })
  }
})

test('stop: a rejection without a run_id is dropped — there is no run to finalize', async () => {
  const g = await startMockGuard()
  const sb = sandbox()
  try {
    const a = seedAsk(sb, 'tu_norun', [rejectionLine('tu_norun')], { runId: null })
    await runStop(sb, g.url)
    assert.ok(!existsSync(a.entryPath))
    assert.equal(g.requests.length, 0)
  } finally {
    await g.close()
    rmSync(sb.root, { recursive: true, force: true })
  }
})

test('stop: rejections in one sweep each finalize their own run', async () => {
  const g = await startMockGuard()
  const sb = sandbox()
  try {
    seedAsk(sb, 'tu_r1', [rejectionLine('tu_r1')])
    seedAsk(sb, 'tu_r2', [rejectionLine('tu_r2')])
    seedAsk(sb, 'tu_still_open', [])
    await runStop(sb, g.url)
    assert.deepEqual(finalizes(g).map((r) => r.body.runId).sort(), ['run_tu_r1', 'run_tu_r2'])
  } finally {
    await g.close()
    rmSync(sb.root, { recursive: true, force: true })
  }
})
