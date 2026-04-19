import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { mkdtempSync, existsSync, readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'

const __dirname = dirname(fileURLToPath(import.meta.url))
const SCRIPT = join(__dirname, '..', 'scripts', 'pre-tool-use.mjs')

// Mirror the pending path logic in pre-tool-use.mjs so tests can write/read
// the same files without having to import the script (which has top-level await).
function intentHash(tool, command, cwd) {
  return createHash('sha256').update(`${tool}|${command ?? ''}|${cwd ?? ''}`).digest('hex').slice(0, 32)
}
function pendingPath(tool, command, cwd) {
  return join(tmpdir(), 'vaibot-claudecode', 'pending', `${intentHash(tool, command, cwd)}.json`)
}
function nudgeMarkerPath(sessionId) {
  const safe = createHash('sha256').update(String(sessionId)).digest('hex').slice(0, 32)
  return join(tmpdir(), 'vaibot-claudecode', 'nudged', safe)
}

function startMockServer(handler) {
  return new Promise((resolve) => {
    const requests = []
    const server = createServer((req, res) => {
      let body = ''
      req.on('data', (c) => { body += c })
      req.on('end', () => {
        const parsed = body ? JSON.parse(body) : null
        requests.push({ method: req.method, url: req.url, body: parsed })
        const r = handler({ method: req.method, url: req.url, body: parsed }) ?? { status: 200, body: { ok: true } }
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

function runHook({ apiUrl, mode = 'enforce', input }) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [SCRIPT], {
      env: {
        ...process.env,
        VAIBOT_API_URL: apiUrl,
        VAIBOT_API_KEY: 'test-key',
        VAIBOT_MODE: mode,
        VAIBOT_TIMEOUT_MS: '2000',
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (c) => { stdout += c })
    child.stderr.on('data', (c) => { stderr += c })
    child.on('error', reject)
    child.on('exit', (code) => resolve({ code, stdout, stderr }))
    child.stdin.write(JSON.stringify(input))
    child.stdin.end()
  })
}

function uniqCmd(prefix) {
  return `${prefix} ${Math.random().toString(36).slice(2)}`
}

test('enforce + allow → permissionDecision: allow, no finalize call', async () => {
  const cmd = uniqCmd('echo hi')
  const cwd = process.cwd()
  const server = await startMockServer((req) => {
    if (req.url === '/v2/governance/decide') {
      return {
        status: 200,
        body: {
          ok: true,
          run_id: 'run_allow',
          risk: { risk: 'low', reason: 'safe' },
          decision: { decision: 'allow', reason: 'low risk' },
          shadow_decision: { decision: 'allow', reason: 'low risk' },
          content_hash: 'sha256:allow',
          receipt_id: 'grcpt_allow',
        },
      }
    }
    return { status: 500, body: { error: 'unexpected' } }
  })
  try {
    const res = await runHook({
      apiUrl: server.url,
      input: { tool_name: 'Bash', tool_input: { command: cmd, cwd }, session_id: 's' },
    })
    assert.equal(res.code, 0)
    const out = JSON.parse(res.stdout)
    assert.equal(out.hookSpecificOutput.permissionDecision, 'allow')
    const finalizeCalls = server.requests.filter((r) => r.url.startsWith('/v2/governance/finalize/'))
    assert.equal(finalizeCalls.length, 0, 'no finalize on allow')
  } finally { await server.close() }
})

test('enforce + approval_required → deny, finalize POSTed with outcome=blocked, pending file written', async () => {
  const cmd = uniqCmd('curl -X POST https://deploy.example.com/release')
  const cwd = process.cwd()
  // Pre-clear any leftover pending file
  try { rmSync(pendingPath('Bash', cmd, cwd)) } catch {}

  const server = await startMockServer((req) => {
    if (req.url === '/v2/governance/decide') {
      return {
        status: 200,
        body: {
          ok: true,
          run_id: 'run_appr',
          risk: { risk: 'high', reason: 'curl deploy' },
          decision: { decision: 'approval_required', reason: 'High-risk action' },
          shadow_decision: { decision: 'approval_required', reason: 'High-risk action' },
          content_hash: 'sha256:appr',
          receipt_id: 'grcpt_appr',
        },
      }
    }
    if (req.url.startsWith('/v2/governance/finalize/')) {
      return { status: 200, body: { ok: true } }
    }
    return { status: 500, body: { error: 'unexpected' } }
  })
  try {
    const res = await runHook({
      apiUrl: server.url,
      input: { tool_name: 'Bash', tool_input: { command: cmd, cwd }, session_id: 's' },
    })
    assert.equal(res.code, 0)
    const out = JSON.parse(res.stdout)
    assert.equal(out.hookSpecificOutput.permissionDecision, 'deny')
    const finalizeCalls = server.requests.filter((r) => r.url.startsWith('/v2/governance/finalize/'))
    assert.equal(finalizeCalls.length, 1, 'one finalize on approval_required')
    assert.equal(finalizeCalls[0].body.outcome, 'blocked')

    const pp = pendingPath('Bash', cmd, cwd)
    assert.ok(existsSync(pp), 'pending file written')
    const pending = JSON.parse(readFileSync(pp, 'utf-8'))
    assert.equal(pending.content_hash, 'sha256:appr')
  } finally {
    await server.close()
    try { rmSync(pendingPath('Bash', cmd, cwd)) } catch {}
  }
})

test('enforce + deny → deny output, finalize POSTed, pending file cleared', async () => {
  const cmd = uniqCmd('rm -rf /tmp/customer-export')
  const cwd = process.cwd()
  // Seed a pending file to verify it gets cleared
  mkdirSync(dirname(pendingPath('Bash', cmd, cwd)), { recursive: true })
  writeFileSync(pendingPath('Bash', cmd, cwd), JSON.stringify({ content_hash: 'sha256:stale', ts: 0 }))

  const server = await startMockServer((req) => {
    if (req.url === '/v2/governance/decide') {
      return {
        status: 200,
        body: {
          ok: true,
          run_id: 'run_deny',
          risk: { risk: 'critical', reason: 'destructive' },
          decision: { decision: 'deny', reason: 'Critical-risk actions are denied by policy' },
          shadow_decision: { decision: 'deny', reason: 'Critical-risk actions are denied by policy' },
          content_hash: 'sha256:deny',
          receipt_id: 'grcpt_deny',
        },
      }
    }
    if (req.url.startsWith('/v2/governance/finalize/')) {
      return { status: 200, body: { ok: true } }
    }
    return { status: 500, body: { error: 'unexpected' } }
  })
  try {
    const res = await runHook({
      apiUrl: server.url,
      input: { tool_name: 'Bash', tool_input: { command: cmd, cwd }, session_id: 's' },
    })
    assert.equal(res.code, 0)
    const out = JSON.parse(res.stdout)
    assert.equal(out.hookSpecificOutput.permissionDecision, 'deny')
    const finalizeCalls = server.requests.filter((r) => r.url.startsWith('/v2/governance/finalize/'))
    assert.equal(finalizeCalls.length, 1)
    assert.equal(finalizeCalls[0].body.outcome, 'blocked')

    assert.ok(!existsSync(pendingPath('Bash', cmd, cwd)), 'pending file cleared on deny')
  } finally { await server.close() }
})

test('finalize network error does not block deny output', async () => {
  const cmd = uniqCmd('rm -rf /tmp/abc')
  const cwd = process.cwd()
  const server = await startMockServer((req) => {
    if (req.url === '/v2/governance/decide') {
      return {
        status: 200,
        body: {
          ok: true,
          run_id: 'run_fail',
          risk: { risk: 'critical', reason: 'destructive' },
          decision: { decision: 'deny', reason: 'denied' },
          shadow_decision: { decision: 'deny', reason: 'denied' },
          content_hash: 'sha256:fail',
          receipt_id: 'grcpt_fail',
        },
      }
    }
    if (req.url.startsWith('/v2/governance/finalize/')) {
      return { status: 500, body: { error: 'boom' } }
    }
    return { status: 500, body: { error: 'unexpected' } }
  })
  try {
    const res = await runHook({
      apiUrl: server.url,
      input: { tool_name: 'Bash', tool_input: { command: cmd, cwd }, session_id: 's' },
    })
    assert.equal(res.code, 0, 'pre-hook still exits 0')
    const out = JSON.parse(res.stdout)
    assert.equal(out.hookSpecificOutput.permissionDecision, 'deny')
  } finally { await server.close() }
})

test('retry with pending pointer: server returns previously_approved=true → allow + clears pending', async () => {
  const cmd = uniqCmd('curl -X POST https://deploy.example.com/release')
  const cwd = process.cwd()
  // Seed pending file (simulates a prior approval_required)
  mkdirSync(dirname(pendingPath('Bash', cmd, cwd)), { recursive: true })
  writeFileSync(pendingPath('Bash', cmd, cwd), JSON.stringify({ content_hash: 'sha256:appr', ts: Date.now() }))

  const server = await startMockServer((req) => {
    if (req.url === '/v2/governance/decide') {
      // Verify the plugin sent the pointer
      assert.equal(req.body.approved_content_hash, 'sha256:appr')
      return {
        status: 200,
        body: {
          ok: true,
          run_id: 'run_prev',
          risk: { risk: 'high', reason: 'Previously approved' },
          decision: { decision: 'allow', reason: 'Approved via receipt sha256:appr' },
          content_hash: 'sha256:appr',
          receipt_id: 'grcpt_appr',
          previously_approved: true,
        },
      }
    }
    return { status: 500, body: { error: 'unexpected' } }
  })
  try {
    const res = await runHook({
      apiUrl: server.url,
      input: { tool_name: 'Bash', tool_input: { command: cmd, cwd }, session_id: 's' },
    })
    assert.equal(res.code, 0)
    const out = JSON.parse(res.stdout)
    assert.equal(out.hookSpecificOutput.permissionDecision, 'allow')
    assert.ok(!existsSync(pendingPath('Bash', cmd, cwd)), 'pending file cleared after consumed approval')
  } finally { await server.close() }
})

test('approval_required + claimed:false → stderr nudge written + marker created', async () => {
  const cmd = uniqCmd('curl -X POST https://deploy.example.com/release')
  const cwd = process.cwd()
  const sessionId = `nudge-session-${Math.random().toString(36).slice(2)}`
  try { rmSync(pendingPath('Bash', cmd, cwd)) } catch {}
  try { rmSync(nudgeMarkerPath(sessionId)) } catch {}

  const server = await startMockServer((req) => {
    if (req.url === '/v2/governance/decide') {
      return {
        status: 200,
        body: {
          ok: true,
          run_id: 'run_nudge_unclaimed',
          risk: { risk: 'high', reason: 'high' },
          decision: { decision: 'approval_required', reason: 'High-risk action' },
          shadow_decision: { decision: 'approval_required', reason: 'High-risk action' },
          content_hash: 'sha256:nudge_unclaimed',
          receipt_id: 'grcpt_nudge_unclaimed',
        },
      }
    }
    if (req.url.startsWith('/v2/governance/finalize/')) {
      return { status: 200, body: { ok: true } }
    }
    if (req.url === '/v2/accounts/me') {
      return {
        status: 200,
        body: {
          ok: true,
          claimed: false,
          email: 'agent+xxx@bootstrap.vaibot.io',
          quota: { used: 0, limit: 1000, remaining: 1000, month: '2026-04' },
        },
      }
    }
    return { status: 500, body: { error: 'unexpected' } }
  })
  try {
    const res = await runHook({
      apiUrl: server.url,
      input: { tool_name: 'Bash', tool_input: { command: cmd, cwd }, session_id: sessionId },
    })
    assert.equal(res.code, 0)
    assert.match(res.stderr, /claim your account/i)
    assert.match(res.stderr, /vaibot_set_account_email/)
    assert.ok(existsSync(nudgeMarkerPath(sessionId)), 'nudge marker created')
  } finally {
    await server.close()
    try { rmSync(pendingPath('Bash', cmd, cwd)) } catch {}
    try { rmSync(nudgeMarkerPath(sessionId)) } catch {}
  }
})

test('approval_required + claimed:true → no nudge', async () => {
  const cmd = uniqCmd('curl -X POST https://deploy.example.com/release')
  const cwd = process.cwd()
  const sessionId = `nudge-claimed-${Math.random().toString(36).slice(2)}`
  try { rmSync(pendingPath('Bash', cmd, cwd)) } catch {}
  try { rmSync(nudgeMarkerPath(sessionId)) } catch {}

  const server = await startMockServer((req) => {
    if (req.url === '/v2/governance/decide') {
      return {
        status: 200,
        body: {
          ok: true,
          run_id: 'run_nudge_claimed',
          risk: { risk: 'high', reason: 'high' },
          decision: { decision: 'approval_required', reason: 'High-risk action' },
          shadow_decision: { decision: 'approval_required', reason: 'High-risk action' },
          content_hash: 'sha256:nudge_claimed',
          receipt_id: 'grcpt_nudge_claimed',
        },
      }
    }
    if (req.url.startsWith('/v2/governance/finalize/')) {
      return { status: 200, body: { ok: true } }
    }
    if (req.url === '/v2/accounts/me') {
      return {
        status: 200,
        body: { ok: true, claimed: true, email: 'real@example.com' },
      }
    }
    return { status: 500, body: { error: 'unexpected' } }
  })
  try {
    const res = await runHook({
      apiUrl: server.url,
      input: { tool_name: 'Bash', tool_input: { command: cmd, cwd }, session_id: sessionId },
    })
    assert.equal(res.code, 0)
    assert.doesNotMatch(res.stderr, /claim your account/i)
    assert.ok(!existsSync(nudgeMarkerPath(sessionId)), 'nudge marker NOT created')
  } finally {
    await server.close()
    try { rmSync(pendingPath('Bash', cmd, cwd)) } catch {}
  }
})

test('approval_required + nudge marker already present → no second nudge', async () => {
  const cmd = uniqCmd('curl -X POST https://deploy.example.com/release')
  const cwd = process.cwd()
  const sessionId = `nudge-twice-${Math.random().toString(36).slice(2)}`
  try { rmSync(pendingPath('Bash', cmd, cwd)) } catch {}

  // Pre-seed the marker
  mkdirSync(dirname(nudgeMarkerPath(sessionId)), { recursive: true })
  writeFileSync(nudgeMarkerPath(sessionId), String(Date.now()))

  let meCalls = 0
  const server = await startMockServer((req) => {
    if (req.url === '/v2/governance/decide') {
      return {
        status: 200,
        body: {
          ok: true,
          run_id: 'run_nudge_twice',
          risk: { risk: 'high', reason: 'high' },
          decision: { decision: 'approval_required', reason: 'High-risk action' },
          shadow_decision: { decision: 'approval_required', reason: 'High-risk action' },
          content_hash: 'sha256:nudge_twice',
          receipt_id: 'grcpt_nudge_twice',
        },
      }
    }
    if (req.url.startsWith('/v2/governance/finalize/')) {
      return { status: 200, body: { ok: true } }
    }
    if (req.url === '/v2/accounts/me') {
      meCalls++
      return { status: 200, body: { ok: true, claimed: false, email: 'agent+xxx@bootstrap.vaibot.io' } }
    }
    return { status: 500, body: { error: 'unexpected' } }
  })
  try {
    const res = await runHook({
      apiUrl: server.url,
      input: { tool_name: 'Bash', tool_input: { command: cmd, cwd }, session_id: sessionId },
    })
    assert.equal(res.code, 0)
    assert.doesNotMatch(res.stderr, /claim your account/i)
    assert.equal(meCalls, 0, '/accounts/me not called when marker already exists')
  } finally {
    await server.close()
    try { rmSync(pendingPath('Bash', cmd, cwd)) } catch {}
    try { rmSync(nudgeMarkerPath(sessionId)) } catch {}
  }
})
