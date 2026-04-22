import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { writeFileSync, mkdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const SCRIPT = join(__dirname, '..', 'scripts', 'post-tool-use.mjs')
const STATE_DIR = join(tmpdir(), 'vaibot-claudecode')

function startMockServer(handler) {
  return new Promise((resolve) => {
    const requests = []
    const server = createServer((req, res) => {
      let body = ''
      req.on('data', (c) => { body += c })
      req.on('end', () => {
        requests.push({ method: req.method, url: req.url, body: body ? JSON.parse(body) : null })
        const r = handler({ method: req.method, url: req.url }) ?? { status: 200, body: { ok: true } }
        res.writeHead(r.status, { 'content-type': 'application/json' })
        res.end(JSON.stringify(r.body))
      })
    })
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address()
      resolve({ url: `http://127.0.0.1:${port}`, requests, close: () => new Promise((r) => server.close(r)) })
    })
  })
}

function runPost({ apiUrl, input }) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [SCRIPT], {
      env: { ...process.env, VAIBOT_API_URL: apiUrl, VAIBOT_API_KEY: 'test-key', VAIBOT_TIMEOUT_MS: '2000' },
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    child.on('error', reject)
    child.on('exit', (code) => resolve({ code }))
    child.stdin.write(JSON.stringify(input))
    child.stdin.end()
  })
}

// Seed a runState file as if PreToolUse had just written it.
function seedRunState(toolUseId, approvalRequired, contentHash = 'sha256:x') {
  mkdirSync(STATE_DIR, { recursive: true })
  const path = join(STATE_DIR, `${toolUseId}.json`)
  writeFileSync(path, JSON.stringify({
    tool_name: 'Bash', tool_use_id: toolUseId,
    run_id: `run_${toolUseId}`, content_hash: contentHash,
    approval_required: approvalRequired, ts: Date.now(),
  }))
  return path
}

test('approval_required runState → PATCH /approve before finalize', async () => {
  const path = seedRunState('tu_yes', true, 'sha256:yes')
  const server = await startMockServer(() => ({ status: 200, body: { ok: true } }))
  try {
    await runPost({ apiUrl: server.url, input: { tool_name: 'Bash', tool_use_id: 'tu_yes' } })
    const approves = server.requests.filter((r) => r.method === 'PATCH' && r.url.endsWith('/approve'))
    assert.equal(approves.length, 1)
    assert.ok(approves[0].url.includes('sha256%3Ayes'))
  } finally {
    await server.close()
    try { rmSync(path) } catch {}
  }
})

test('non-ask runState → no PATCH /approve, finalize only', async () => {
  const path = seedRunState('tu_plain', false)
  const server = await startMockServer(() => ({ status: 200, body: { ok: true } }))
  try {
    await runPost({ apiUrl: server.url, input: { tool_name: 'Bash', tool_use_id: 'tu_plain' } })
    const approves = server.requests.filter((r) => r.method === 'PATCH' && r.url.endsWith('/approve'))
    const finalizes = server.requests.filter((r) => r.url.startsWith('/v2/governance/finalize/'))
    assert.equal(approves.length, 0)
    assert.equal(finalizes.length, 1)
  } finally {
    await server.close()
    try { rmSync(path) } catch {}
  }
})
