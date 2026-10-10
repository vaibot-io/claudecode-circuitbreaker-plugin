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

function startMockServer() {
  return new Promise((resolve) => {
    const requests = []
    const server = createServer((req, res) => {
      req.resume()
      req.on('end', () => {
        requests.push({ method: req.method, url: req.url })
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

// Sandboxed HOME (credentials) and TMPDIR (state dir): Stop sweeps every entry
// in the state dir, so the shared one would expose other suites' entries.
function sandbox(apiUrl) {
  const root = mkdtempSync(join(tmpdir(), 'vaibot-cc-stop-'))
  const home = join(root, 'home')
  const tmp = join(root, 'tmp')
  mkdirSync(join(home, '.vaibot'), { recursive: true })
  mkdirSync(join(tmp, 'vaibot-claudecode', 'pending'), { recursive: true })
  writeFileSync(join(home, '.vaibot', 'credentials.json'), JSON.stringify({
    version: 3, active_env: 'staging',
    environments: { staging: { governance: { url: apiUrl }, provenance: { url: apiUrl }, api_key: 'test-key' } },
  }))
  return { root, home, tmp, stateDir: join(tmp, 'vaibot-claudecode') }
}

function seedAsk(sb, toolUseId, transcriptLines, { ts = Date.now() } = {}) {
  const transcriptPath = join(sb.root, 'session.jsonl')
  writeFileSync(transcriptPath, transcriptLines.join('\n') + '\n')
  const entryPath = join(sb.stateDir, `${toolUseId}.json`)
  writeFileSync(entryPath, JSON.stringify({
    tool_name: 'Bash', tool_use_id: toolUseId, run_id: `run_${toolUseId}`,
    content_hash: `sha256:${toolUseId}`, approval_required: true,
    intent_key: `ik_${toolUseId}`, transcript_path: transcriptPath, ts,
  }))
  const pointerPath = join(sb.stateDir, 'pending', `ik_${toolUseId}.json`)
  writeFileSync(pointerPath, '{}')
  return { entryPath, pointerPath }
}

function runStop(sb, apiUrl) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [SCRIPT], {
      env: { ...process.env, HOME: sb.home, TMPDIR: sb.tmp, VAIBOT_API_URL: apiUrl, VAIBOT_API_KEY: 'test-key', VAIBOT_TIMEOUT_MS: '2000' },
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

test('stop: an ask with no answer yet (a subagent or other session ending) is left alone, nothing denied', async () => {
  const server = await startMockServer()
  const sb = sandbox(server.url)
  try {
    const a = seedAsk(sb, 'tu_open', [])
    await runStop(sb, server.url)
    assert.ok(existsSync(a.entryPath), 'entry kept for its own PostToolUse')
    assert.ok(existsSync(a.pointerPath), 'pointer kept')
    assert.equal(server.requests.filter((r) => r.url.endsWith('/deny')).length, 0)
  } finally {
    await server.close()
    rmSync(sb.root, { recursive: true, force: true })
  }
})

test('stop: an ask the transcript records as rejected is denied and cleared', async () => {
  const server = await startMockServer()
  const sb = sandbox(server.url)
  try {
    const a = seedAsk(sb, 'tu_no', [rejectionLine('tu_no')])
    await runStop(sb, server.url)
    assert.ok(!existsSync(a.entryPath))
    assert.ok(!existsSync(a.pointerPath))
    assert.equal(server.requests.filter((r) => r.method === 'PATCH' && r.url.endsWith('/deny')).length, 1)
  } finally {
    await server.close()
    rmSync(sb.root, { recursive: true, force: true })
  }
})

test('stop: an abandoned ask is cleared without claiming a denial', async () => {
  const server = await startMockServer()
  const sb = sandbox(server.url)
  try {
    const a = seedAsk(sb, 'tu_old', [], { ts: Date.now() - 25 * 60 * 60 * 1000 })
    await runStop(sb, server.url)
    assert.ok(!existsSync(a.entryPath))
    assert.ok(!existsSync(a.pointerPath))
    assert.equal(server.requests.filter((r) => r.url.endsWith('/deny')).length, 0)
  } finally {
    await server.close()
    rmSync(sb.root, { recursive: true, force: true })
  }
})
