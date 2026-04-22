import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { mkdtempSync, existsSync, readFileSync, readdirSync, writeFileSync, mkdirSync, rmSync } from 'node:fs'
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

// Minimal decide-only handler for clarity in the ask tests below.
function decideHandler(decisionBody) {
  return (req) => req.url === '/v2/governance/decide'
    ? { status: 200, body: { ok: true, ...decisionBody } }
    : { status: 200, body: { ok: true } }
}

function stateFilePath(toolUseId) {
  return join(tmpdir(), 'vaibot-claudecode', `${toolUseId}.json`)
}

test('approval_required → native ask (not deny)', async () => {
  const server = await startMockServer(decideHandler({
    decision: { decision: 'approval_required', reason: 'High-risk' },
    shadow_decision: { decision: 'approval_required', reason: 'High-risk' },
    content_hash: 'sha256:a', run_id: 'run_a', risk: { risk: 'high' },
  }))
  try {
    const res = await runHook({ apiUrl: server.url, input: {
      tool_name: 'Bash', tool_input: { command: uniqCmd('curl x') },
      session_id: 's', tool_use_id: 'tu_ask1',
    }})
    assert.equal(JSON.parse(res.stdout).hookSpecificOutput.permissionDecision, 'ask')
  } finally {
    await server.close()
    try { rmSync(stateFilePath('tu_ask1')) } catch {}
  }
})

test('approval_required → no finalize POSTed (receipt stays pending server-side)', async () => {
  const server = await startMockServer(decideHandler({
    decision: { decision: 'approval_required' }, shadow_decision: { decision: 'approval_required' },
    content_hash: 'sha256:b', run_id: 'run_b',
  }))
  try {
    await runHook({ apiUrl: server.url, input: {
      tool_name: 'Bash', tool_input: { command: uniqCmd('curl y') },
      session_id: 's', tool_use_id: 'tu_ask2',
    }})
    const finalizes = server.requests.filter((r) => r.url.startsWith('/v2/governance/finalize/'))
    assert.equal(finalizes.length, 0)
  } finally {
    await server.close()
    try { rmSync(stateFilePath('tu_ask2')) } catch {}
  }
})

test('approval_required → runState carries approval_required=true + content_hash', async () => {
  const server = await startMockServer(decideHandler({
    decision: { decision: 'approval_required' }, shadow_decision: { decision: 'approval_required' },
    content_hash: 'sha256:c', run_id: 'run_c',
  }))
  try {
    await runHook({ apiUrl: server.url, input: {
      tool_name: 'Bash', tool_input: { command: uniqCmd('curl z') },
      session_id: 's', tool_use_id: 'tu_ask3',
    }})
    const state = JSON.parse(readFileSync(stateFilePath('tu_ask3'), 'utf-8'))
    assert.equal(state.approval_required, true)
    assert.equal(state.content_hash, 'sha256:c')
  } finally {
    await server.close()
    try { rmSync(stateFilePath('tu_ask3')) } catch {}
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

// Seed a stale ask-in-flight runState as if a prior PreToolUse emitted `ask`
// and the user picked "No, tell Claude" (PostToolUse never fired to consume it).
function seedStaleAsk(contentHash, toolUseId = 'tu_old') {
  const stateDir = join(tmpdir(), 'vaibot-claudecode')
  mkdirSync(stateDir, { recursive: true })
  const path = join(stateDir, `${toolUseId}.json`)
  writeFileSync(path, JSON.stringify({
    tool_name: 'Bash', tool_use_id: toolUseId,
    content_hash: contentHash, approval_required: true, ts: Date.now(),
  }))
  return path
}

test('sweep: stale approval_required runState → PATCH /deny on next PreToolUse', async () => {
  const stalePath = seedStaleAsk('sha256:stale')
  const server = await startMockServer(decideHandler({
    decision: { decision: 'allow' }, shadow_decision: { decision: 'allow' },
    content_hash: 'sha256:next', run_id: 'run_next',
  }))
  try {
    await runHook({ apiUrl: server.url, input: {
      tool_name: 'Bash', tool_input: { command: uniqCmd('echo hi') },
      session_id: 's', tool_use_id: 'tu_new',
    }})
    const denies = server.requests.filter((r) => r.method === 'PATCH' && r.url.endsWith('/deny'))
    assert.equal(denies.length, 1)
    assert.ok(denies[0].url.includes('sha256%3Astale'))
    assert.ok(!existsSync(stalePath))
  } finally {
    await server.close()
    try { rmSync(stalePath) } catch {}
  }
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

test('allow + claimed:false → stderr nudge fires on first tool call of session (session-start behavior)', async () => {
  const cmd = uniqCmd('echo hi')
  const cwd = process.cwd()
  const sessionId = `nudge-allow-${Math.random().toString(36).slice(2)}`
  try { rmSync(nudgeMarkerPath(sessionId)) } catch {}

  const server = await startMockServer((req) => {
    if (req.url === '/v2/governance/decide') {
      return {
        status: 200,
        body: {
          ok: true,
          run_id: 'run_allow_nudge',
          risk: { risk: 'low', reason: 'safe' },
          decision: { decision: 'allow', reason: 'low risk' },
          shadow_decision: { decision: 'allow', reason: 'low risk' },
          content_hash: 'sha256:allow_nudge',
          receipt_id: 'grcpt_allow_nudge',
        },
      }
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
    const out = JSON.parse(res.stdout)
    assert.equal(out.hookSpecificOutput.permissionDecision, 'allow', 'decision is still allow')
    assert.match(res.stderr, /claim your account/i, 'nudge fires even on allow')
    assert.ok(existsSync(nudgeMarkerPath(sessionId)), 'marker created')
  } finally {
    await server.close()
    try { rmSync(nudgeMarkerPath(sessionId)) } catch {}
  }
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
