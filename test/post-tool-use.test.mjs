import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { writeFileSync, readFileSync, mkdirSync, mkdtempSync, rmSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const SCRIPT = join(__dirname, '..', 'scripts', 'post-tool-use.mjs')

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

// Per-test isolated STATE_DIR (via TMPDIR) so parallel pre-hook runs in other
// test files can't sweep/claim our seeded run-state. The guard is mocked via
// VAIBOT_GUARD_BASE_URL so post-tool-use finalizes against the mock, not a real
// launched daemon.
function runPost({ apiUrl, input, fakeTmp }) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [SCRIPT], {
      env: {
        ...process.env,
        TMPDIR: fakeTmp,
        VAIBOT_GUARD_BASE_URL: apiUrl,
        VAIBOT_GUARD_TOKEN: 'test-guard-token',
        VAIBOT_TIMEOUT_MS: '2000',
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    child.on('error', reject)
    child.on('exit', (code) => resolve({ code }))
    child.stdin.write(JSON.stringify(input))
    child.stdin.end()
  })
}

// Seed a runState file under the per-test fake TMPDIR as if PreToolUse wrote it.
function seedRunState(fakeTmp, toolUseId, approvalRequired, contentHash = 'sha256:x') {
  const stateDir = join(fakeTmp, 'vaibot-claudecode')
  mkdirSync(stateDir, { recursive: true })
  const path = join(stateDir, `${toolUseId}.json`)
  writeFileSync(path, JSON.stringify({
    tool_name: 'Bash', tool_use_id: toolUseId,
    run_id: `run_${toolUseId}`, content_hash: contentHash,
    approval_required: approvalRequired, ts: Date.now(),
  }))
  return path
}

test('approval_required runState → finalize via guard (no V2 /approve)', async () => {
  const fakeTmp = mkdtempSync(join(tmpdir(), 'vaibot-cc-post-'))
  seedRunState(fakeTmp, 'tu_yes', true, 'sha256:yes')
  const server = await startMockServer(() => ({ status: 200, body: { ok: true } }))
  try {
    await runPost({ apiUrl: server.url, input: { tool_name: 'Bash', tool_use_id: 'tu_yes' }, fakeTmp })
    // The guard owns approvals — no V2 /approve PATCH. The native-UI approval is
    // captured by the finalize receipt; the guard's pending record self-expires.
    const approves = server.requests.filter((r) => r.method === 'PATCH' && r.url.endsWith('/approve'))
    assert.equal(approves.length, 0)
    const finalizes = server.requests.filter((r) => r.url === '/v1/finalize/tool')
    assert.equal(finalizes.length, 1)
    assert.equal(finalizes[0].body.runId, 'run_tu_yes')
  } finally {
    await server.close()
    try { rmSync(fakeTmp, { recursive: true, force: true }) } catch {}
  }
})

test('runState → finalize via guard /v1/finalize/tool, no V2 calls', async () => {
  const fakeTmp = mkdtempSync(join(tmpdir(), 'vaibot-cc-post-'))
  seedRunState(fakeTmp, 'tu_plain', false)
  const server = await startMockServer(() => ({ status: 200, body: { ok: true } }))
  try {
    await runPost({ apiUrl: server.url, input: { tool_name: 'Bash', tool_use_id: 'tu_plain' }, fakeTmp })
    const v2 = server.requests.filter((r) => r.url.startsWith('/v2/'))
    assert.equal(v2.length, 0)
    const finalizes = server.requests.filter((r) => r.url === '/v1/finalize/tool')
    assert.equal(finalizes.length, 1)
    assert.equal(finalizes[0].body.result?.outcome, 'allowed')
  } finally {
    await server.close()
    try { rmSync(fakeTmp, { recursive: true, force: true }) } catch {}
  }
})

// When this call's own entry is gone (swept by another hook), the newest entry
// for the same tool belongs to a DIFFERENT call. Finalizing it would record an
// approval for a call the user has not answered, and drop that call's pointer.
test('a call whose entry is gone does not finalize a different call of the same tool', async () => {
  const fakeTmp = mkdtempSync(join(tmpdir(), 'vaibot-cc-post-'))
  seedRunState(fakeTmp, 'tu_other', true, 'appr_other')
  const server = await startMockServer(() => ({ status: 200, body: { ok: true } }))
  try {
    await runPost({ apiUrl: server.url, input: { tool_name: 'Bash', tool_use_id: 'tu_swept' }, fakeTmp })
    assert.equal(server.requests.filter((r) => r.url === '/v1/finalize/tool').length, 0)
    assert.ok(existsSync(join(fakeTmp, 'vaibot-claudecode', 'tu_other.json')), 'the other call\'s entry is untouched')
  } finally {
    await server.close()
    try { rmSync(fakeTmp, { recursive: true, force: true }) } catch {}
  }
})

test('an ordinary (ungated) run is finalized without an approval claim', async () => {
  const fakeTmp = mkdtempSync(join(tmpdir(), 'vaibot-cc-post-'))
  seedRunState(fakeTmp, 'tu_plain', false)
  const server = await startMockServer(() => ({ status: 200, body: { ok: true } }))
  try {
    await runPost({ apiUrl: server.url, input: { tool_name: 'Bash', tool_use_id: 'tu_plain' }, fakeTmp })
    const fin = server.requests.filter((r) => r.url === '/v1/finalize/tool')
    assert.equal(fin.length, 1)
    assert.equal(fin[0].body.result.approval, undefined)
  } finally {
    await server.close()
    try { rmSync(fakeTmp, { recursive: true, force: true }) } catch {}
  }
})

// A tool that was allowed to run and then failed fires PostToolUseFailure, not
// PostToolUse. A permission denial returns before the tool runs, so this event
// is never a "No": after an ask it is the user's "Yes" followed by a failure.
function seedAsk(fakeTmp, toolUseId) {
  const stateDir = join(fakeTmp, 'vaibot-claudecode')
  mkdirSync(join(stateDir, 'pending'), { recursive: true })
  writeFileSync(join(stateDir, `${toolUseId}.json`), JSON.stringify({
    tool_name: 'Bash', tool_use_id: toolUseId, run_id: `run_${toolUseId}`,
    content_hash: 'appr_f', approval_required: true, intent_key: `ik_${toolUseId}`, ts: Date.now(),
  }))
  const pointer = join(stateDir, 'pending', `ik_${toolUseId}.json`)
  writeFileSync(pointer, '{}')
  return pointer
}

test('PostToolUseFailure after a "Yes": finalized as approved + failed, pointer spent, entry consumed', async () => {
  const fakeTmp = mkdtempSync(join(tmpdir(), 'vaibot-cc-post-'))
  const pointer = seedAsk(fakeTmp, 'tu_fail')
  const server = await startMockServer(() => ({ status: 200, body: { ok: true } }))
  try {
    await runPost({ apiUrl: server.url, fakeTmp, input: {
      hook_event_name: 'PostToolUseFailure', tool_name: 'Bash', tool_use_id: 'tu_fail',
      tool_input: { command: 'false' }, error: 'Exit code 1', is_interrupt: false, duration_ms: 12,
    }})
    const fin = server.requests.filter((r) => r.url === '/v1/finalize/tool')
    assert.equal(fin.length, 1)
    assert.equal(fin[0].body.runId, 'run_tu_fail')
    assert.deepEqual(fin[0].body.result, { outcome: 'blocked', ok: false, approval: 'approved', duration_ms: 12, error: 'Exit code 1' })
    assert.ok(!existsSync(pointer), 'retry pointer spent')
    assert.ok(!existsSync(join(fakeTmp, 'vaibot-claudecode', 'tu_fail.json')), 'entry consumed, not left for the sweep')
  } finally {
    await server.close()
    try { rmSync(fakeTmp, { recursive: true, force: true }) } catch {}
  }
})

test('PostToolUseFailure of an ungated call is finalized as failed, with no approval claim', async () => {
  const fakeTmp = mkdtempSync(join(tmpdir(), 'vaibot-cc-post-'))
  seedRunState(fakeTmp, 'tu_plainfail', false)
  const server = await startMockServer(() => ({ status: 200, body: { ok: true } }))
  try {
    await runPost({ apiUrl: server.url, fakeTmp, input: {
      hook_event_name: 'PostToolUseFailure', tool_name: 'Bash', tool_use_id: 'tu_plainfail',
    }})
    const fin = server.requests.filter((r) => r.url === '/v1/finalize/tool')
    assert.equal(fin.length, 1)
    assert.equal(fin[0].body.result.ok, false)
    assert.equal(fin[0].body.result.error, 'Tool call failed', 'a failure without an error string is still a failure')
    assert.equal(fin[0].body.result.approval, undefined)
  } finally {
    await server.close()
    try { rmSync(fakeTmp, { recursive: true, force: true }) } catch {}
  }
})

test('PostToolUseFailure with is_interrupt marks the error as an interruption', async () => {
  const fakeTmp = mkdtempSync(join(tmpdir(), 'vaibot-cc-post-'))
  seedRunState(fakeTmp, 'tu_int', false)
  const server = await startMockServer(() => ({ status: 200, body: { ok: true } }))
  try {
    await runPost({ apiUrl: server.url, fakeTmp, input: {
      hook_event_name: 'PostToolUseFailure', tool_name: 'Bash', tool_use_id: 'tu_int', error: 'aborted', is_interrupt: true,
    }})
    const fin = server.requests.filter((r) => r.url === '/v1/finalize/tool')
    assert.equal(fin[0].body.result.error, '[interrupted] aborted')
  } finally {
    await server.close()
    try { rmSync(fakeTmp, { recursive: true, force: true }) } catch {}
  }
})

test('a successful PostToolUse is not reported as failed', async () => {
  const fakeTmp = mkdtempSync(join(tmpdir(), 'vaibot-cc-post-'))
  seedRunState(fakeTmp, 'tu_okrun', false)
  const server = await startMockServer(() => ({ status: 200, body: { ok: true } }))
  try {
    await runPost({ apiUrl: server.url, fakeTmp, input: { hook_event_name: 'PostToolUse', tool_name: 'Bash', tool_use_id: 'tu_okrun' } })
    const fin = server.requests.filter((r) => r.url === '/v1/finalize/tool')
    assert.equal(fin[0].body.result.ok, undefined)
    assert.equal(fin[0].body.result.outcome, 'allowed')
  } finally {
    await server.close()
    try { rmSync(fakeTmp, { recursive: true, force: true }) } catch {}
  }
})

test('hooks.json routes PostToolUseFailure to the PostToolUse script', () => {
  const hooks = JSON.parse(readFileSync(join(__dirname, '..', 'hooks', 'hooks.json'), 'utf-8')).hooks
  const cmd = (event) => hooks[event]?.flatMap((m) => m.hooks.map((h) => h.command)) ?? []
  assert.deepEqual(cmd('PostToolUseFailure'), cmd('PostToolUse'))
  assert.ok(cmd('PostToolUseFailure')[0]?.includes('post-tool-use.mjs'))
})
