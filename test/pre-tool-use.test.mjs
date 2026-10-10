import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { mkdtempSync, existsSync, readFileSync, readdirSync, writeFileSync, mkdirSync, rmSync, statSync, chmodSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'

const __dirname = dirname(fileURLToPath(import.meta.url))
const SCRIPT = join(__dirname, '..', 'scripts', 'pre-tool-use.mjs')

// Mirror the pending path logic in pre-tool-use.mjs so tests can write/read
// the same files without having to import the script (which has top-level await).
function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(',')}}`
  }
  return JSON.stringify(value) ?? 'null'
}
function callKey(tool, input, cwd) {
  return createHash('sha256').update(`${tool}|${stableStringify(input ?? {})}|${cwd ?? ''}`).digest('hex').slice(0, 32)
}
function pendingPath(tool, input, cwd) {
  return join(tmpdir(), 'vaibot-claudecode', 'pending', `${callKey(tool, input, cwd)}.json`)
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

// v3 creds resolve the account base (/me nudge, /v2/bootstrap) from the SINGLE
// credentials.json — its per-env governance slot — not an env var. Seed that file
// so the hook reads the mock URL the way a real install reads its stored slot
// (no VAIBOT_GOVERNANCE_URL override, no §5 flag). Merge-writes so a prior
// bootstrap's saved key survives a re-seed.
function seedCredsUrl(homeDir, { env = 'staging', url, apiKey } = {}) {
  const dir = join(homeDir, '.vaibot')
  const file = join(dir, 'credentials.json')
  let store
  try { store = JSON.parse(readFileSync(file, 'utf-8')) } catch { store = { version: 3, active_env: env, environments: {} } }
  store.version = 3
  store.active_env = store.active_env ?? env
  store.environments = store.environments ?? {}
  store.environments[env] = store.environments[env] ?? {}
  store.environments[env].governance = { url }
  store.environments[env].provenance = { url }
  if (apiKey) store.environments[env].api_key = apiKey
  mkdirSync(dir, { recursive: true })
  writeFileSync(file, JSON.stringify(store))
}

function runHook({ apiUrl, mode = 'enforce', input, containment = null, extraEnv = {} }) {
  // Per-call fake HOME isolates the new breaker-state file at
  // ~/.vaibot/breaker-state/claudecode.json from the user's real home and
  // from other test runs. STATE_DIR (/tmp/vaibot-claudecode/) is intentionally
  // NOT sandboxed here — existing tests reach into it via path helpers; the
  // new breaker.test.mjs sandboxes it via TMPDIR for its own scenarios.
  const fakeHome = mkdtempSync(join(tmpdir(), 'vaibot-claudecode-test-home-'))
  seedCredsUrl(fakeHome, { url: apiUrl, apiKey: 'test-key' }) // account base + key from the file (single store), no env override
  // Containment is machine-wide, in the shared rendezvous dir the guard owns —
  // seeded here so the hook reads it the way a real breaker does, with no daemon.
  if (containment) {
    const guardDir = join(fakeHome, '.vaibot', 'guard')
    mkdirSync(guardDir, { recursive: true })
    // A string is written verbatim so a test can seed a corrupt record; an object
    // is serialised the way the guard writes it.
    writeFileSync(join(guardDir, 'containment.json'), typeof containment === 'string' ? containment : JSON.stringify(containment))
  }
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [SCRIPT], {
      env: {
        ...process.env,
        HOME: fakeHome,
        VAIBOT_API_URL: apiUrl,
        VAIBOT_GUARD_BASE_URL: apiUrl,
        VAIBOT_GUARD_TOKEN: 'test-guard-token',
        VAIBOT_API_KEY: 'test-key',
        VAIBOT_MODE: mode,
        VAIBOT_TIMEOUT_MS: '2000',
        ...extraEnv,
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (c) => { stdout += c })
    child.stderr.on('data', (c) => { stderr += c })
    child.on('error', (err) => { try { rmSync(fakeHome, { recursive: true, force: true }) } catch {} ; reject(err) })
    child.on('exit', (code) => {
      try { rmSync(fakeHome, { recursive: true, force: true }) } catch {}
      resolve({ code, stdout, stderr })
    })
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
    if (req.url === '/v1/decide/tool') {
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

// Decide-only handler: translate a V2-style fixture into the guard's
// /v1/decide/tool shape (runId, risk, decision{decision,reason,approvalId}) so
// the hook's decideViaGuard parses it. content_hash rides as the approvalId.
function decideHandler(decisionBody) {
  const inner = decisionBody.decision ?? {}
  const body = {
    ok: true,
    runId: decisionBody.run_id,
    risk: decisionBody.risk,
    decision: { decision: inner.decision, reason: inner.reason, approvalId: decisionBody.content_hash },
  }
  return (req) => (req.url === '/v1/decide/tool' ? { status: 200, body } : { status: 200, body: { ok: true } })
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

test('enforce + deny → deny output, pending file cleared', async () => {
  const cmd = uniqCmd('rm -rf /tmp/customer-export')
  const cwd = process.cwd()
  // Seed a pending file to verify it gets cleared
  mkdirSync(dirname(pendingPath('Bash', { command: cmd, cwd }, cwd)), { recursive: true })
  writeFileSync(pendingPath('Bash', { command: cmd, cwd }, cwd), JSON.stringify({ content_hash: 'sha256:stale', ts: 0 }))

  const server = await startMockServer((req) => {
    if (req.url === '/v1/decide/tool') {
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
    // Pre-hook no longer finalizes on deny — the guard's decide receipt records
    // the verdict; finalize happens only for executed tools via post-tool-use.
    assert.ok(!existsSync(pendingPath('Bash', { command: cmd, cwd }, cwd)), 'pending file cleared on deny')
  } finally { await server.close() }
})

test('finalize network error does not block deny output', async () => {
  const cmd = uniqCmd('rm -rf /tmp/abc')
  const cwd = process.cwd()
  const server = await startMockServer((req) => {
    if (req.url === '/v1/decide/tool') {
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

// The sweep acts only on what the transcript records as the user's answer.
// Each scenario gets its own TMPDIR so the shared state dir (and the sweeps
// other suites' hooks run against it) can't see or claim the seeded entries.
const REJECTION = "The user doesn't want to proceed with this tool use. The tool use was rejected (eg. if it was a file edit, the new_string was NOT written to the file). STOP what you are doing and wait for the user to tell you how to proceed."

function rejectionLine(toolUseId) {
  return JSON.stringify({
    type: 'user', toolUseResult: 'User rejected tool use',
    message: { role: 'user', content: [{ type: 'tool_result', tool_use_id: toolUseId, is_error: true, content: REJECTION }] },
  })
}

function seedSweepScenario({ toolUseId = 'tu_a', transcriptLines = [], ts = Date.now(), transcript = true } = {}) {
  const fakeTmp = mkdtempSync(join(tmpdir(), 'vaibot-cc-sweep-'))
  const stateDir = join(fakeTmp, 'vaibot-claudecode')
  mkdirSync(join(stateDir, 'pending'), { recursive: true })
  const transcriptPath = join(fakeTmp, 'session.jsonl')
  writeFileSync(transcriptPath, transcriptLines.join('\n') + '\n')
  const entryPath = join(stateDir, `${toolUseId}.json`)
  writeFileSync(entryPath, JSON.stringify({
    tool_name: 'Bash', tool_use_id: toolUseId, run_id: `run_${toolUseId}`,
    content_hash: 'sha256:a', approval_required: true, intent_key: 'ik_a',
    transcript_path: transcript ? transcriptPath : undefined, ts,
  }))
  const pointerPath = join(stateDir, 'pending', 'ik_a.json')
  writeFileSync(pointerPath, JSON.stringify({ content_hash: 'sha256:a', ts }))
  return { fakeTmp, transcriptPath, entryPath, pointerPath }
}

async function runSweepingCall(fakeTmp) {
  const server = await startMockServer(decideHandler({
    decision: { decision: 'allow' }, shadow_decision: { decision: 'allow' },
    content_hash: 'sha256:next', run_id: 'run_next',
  }))
  try {
    await runHook({ apiUrl: server.url, extraEnv: { TMPDIR: fakeTmp }, input: {
      tool_name: 'Bash', tool_input: { command: uniqCmd('echo hi') },
      session_id: 's', tool_use_id: 'tu_b',
    }})
    return server.requests
  } finally {
    await server.close()
  }
}

test('sweep: a parallel ask whose dialog is still up is left alone (entry + pointer survive)', async () => {
  // No tool_result for tu_a yet: the user has not answered. Sweeping it here
  // would leave a later "Yes" with nothing to finalize.
  const sc = seedSweepScenario({ transcriptLines: [JSON.stringify({ type: 'assistant', message: { content: [{ type: 'tool_use', id: 'tu_a' }] } })] })
  try {
    await runSweepingCall(sc.fakeTmp)
    assert.ok(existsSync(sc.entryPath), 'open ask-in-flight entry kept')
    assert.ok(existsSync(sc.pointerPath), 'its retry pointer kept')
  } finally { rmSync(sc.fakeTmp, { recursive: true, force: true }) }
})

test('sweep: an ask the transcript records as rejected is resolved (entry + pointer removed, no network /deny)', async () => {
  const sc = seedSweepScenario({ transcriptLines: [rejectionLine('tu_a')] })
  try {
    const requests = await runSweepingCall(sc.fakeTmp)
    assert.ok(!existsSync(sc.entryPath), 'rejected entry swept')
    assert.ok(!existsSync(sc.pointerPath), 'its retry pointer dropped')
    // Guard approvals self-expire server-side; no /deny PATCH is issued.
    assert.equal(requests.filter((r) => r.method === 'PATCH' && r.url.endsWith('/deny')).length, 0)
  } finally { rmSync(sc.fakeTmp, { recursive: true, force: true }) }
})

test('sweep: a successful tool_result (Yes, PostToolUse not yet run) is not read as a rejection', async () => {
  const ok = JSON.stringify({ type: 'user', message: { content: [{ type: 'tool_result', tool_use_id: 'tu_a', content: 'done' }] } })
  const sc = seedSweepScenario({ transcriptLines: [ok] })
  try {
    await runSweepingCall(sc.fakeTmp)
    assert.ok(existsSync(sc.entryPath), 'left for its own PostToolUse')
  } finally { rmSync(sc.fakeTmp, { recursive: true, force: true }) }
})

test('sweep: another call\'s rejection does not resolve this one', async () => {
  const sc = seedSweepScenario({ transcriptLines: [rejectionLine('tu_other')] })
  try {
    await runSweepingCall(sc.fakeTmp)
    assert.ok(existsSync(sc.entryPath))
  } finally { rmSync(sc.fakeTmp, { recursive: true, force: true }) }
})

test('sweep: a rejection recorded in a subagent transcript resolves the entry', async () => {
  const sc = seedSweepScenario()
  const sub = join(sc.fakeTmp, 'session', 'subagents')
  mkdirSync(sub, { recursive: true })
  writeFileSync(join(sub, 'agent-x.jsonl'), rejectionLine('tu_a') + '\n')
  try {
    await runSweepingCall(sc.fakeTmp)
    assert.ok(!existsSync(sc.entryPath))
  } finally { rmSync(sc.fakeTmp, { recursive: true, force: true }) }
})

test('sweep: an entry with no verdict for over a day is dropped; a legacy entry without transcript_path is kept until then', async () => {
  const old = seedSweepScenario({ transcript: false, ts: Date.now() - 25 * 60 * 60 * 1000 })
  const fresh = seedSweepScenario({ transcript: false })
  try {
    await runSweepingCall(old.fakeTmp)
    await runSweepingCall(fresh.fakeTmp)
    assert.ok(!existsSync(old.entryPath), 'abandoned entry dropped')
    assert.ok(existsSync(fresh.entryPath), 'unverifiable recent entry kept')
  } finally {
    rmSync(old.fakeTmp, { recursive: true, force: true })
    rmSync(fresh.fakeTmp, { recursive: true, force: true })
  }
})

test('runState records transcript_path from the hook input', async () => {
  const fakeTmp = mkdtempSync(join(tmpdir(), 'vaibot-cc-sweep-'))
  const server = await startMockServer(decideHandler({
    decision: { decision: 'approval_required', reason: 'r' }, content_hash: 'sha256:t', run_id: 'run_t',
  }))
  try {
    await runHook({ apiUrl: server.url, extraEnv: { TMPDIR: fakeTmp }, input: {
      tool_name: 'Bash', tool_input: { command: uniqCmd('rm x') },
      session_id: 's', tool_use_id: 'tu_t', transcript_path: '/t/session.jsonl',
    }})
    const state = JSON.parse(readFileSync(join(fakeTmp, 'vaibot-claudecode', 'tu_t.json'), 'utf-8'))
    assert.equal(state.transcript_path, '/t/session.jsonl')
  } finally {
    await server.close()
    rmSync(fakeTmp, { recursive: true, force: true })
  }
})

test('retry with pending pointer: server returns previously_approved=true → allow + clears pending', async () => {
  const cmd = uniqCmd('curl -X POST https://deploy.example.com/release')
  const cwd = process.cwd()
  // Seed pending file (simulates a prior approval_required)
  mkdirSync(dirname(pendingPath('Bash', { command: cmd, cwd }, cwd)), { recursive: true })
  writeFileSync(pendingPath('Bash', { command: cmd, cwd }, cwd), JSON.stringify({ content_hash: 'sha256:appr', ts: Date.now() }))

  const server = await startMockServer((req) => {
    if (req.url === '/v1/decide/tool') {
      // Verify the plugin sent the pointer
      assert.equal(req.body.approval?.approvalId, 'sha256:appr')
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
    assert.ok(!existsSync(pendingPath('Bash', { command: cmd, cwd }, cwd)), 'pending file cleared after consumed approval')
  } finally { await server.close() }
})

test('allow + claimed:false → stderr nudge fires on first tool call of session (session-start behavior)', async () => {
  const cmd = uniqCmd('echo hi')
  const cwd = process.cwd()
  const sessionId = `nudge-allow-${Math.random().toString(36).slice(2)}`
  try { rmSync(nudgeMarkerPath(sessionId)) } catch {}

  const server = await startMockServer((req) => {
    if (req.url === '/v1/decide/tool') {
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
  try { rmSync(pendingPath('Bash', { command: cmd, cwd }, cwd)) } catch {}
  try { rmSync(nudgeMarkerPath(sessionId)) } catch {}

  const server = await startMockServer((req) => {
    if (req.url === '/v1/decide/tool') {
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
    assert.match(res.stderr, /\/claim\?api_key=/)
    assert.ok(existsSync(nudgeMarkerPath(sessionId)), 'nudge marker created')
  } finally {
    await server.close()
    try { rmSync(pendingPath('Bash', { command: cmd, cwd }, cwd)) } catch {}
    try { rmSync(nudgeMarkerPath(sessionId)) } catch {}
  }
})

test('approval_required + claimed:true → no nudge', async () => {
  const cmd = uniqCmd('curl -X POST https://deploy.example.com/release')
  const cwd = process.cwd()
  const sessionId = `nudge-claimed-${Math.random().toString(36).slice(2)}`
  try { rmSync(pendingPath('Bash', { command: cmd, cwd }, cwd)) } catch {}
  try { rmSync(nudgeMarkerPath(sessionId)) } catch {}

  const server = await startMockServer((req) => {
    if (req.url === '/v1/decide/tool') {
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
    try { rmSync(pendingPath('Bash', { command: cmd, cwd }, cwd)) } catch {}
  }
})

test('approval_required + nudge marker already present → no second nudge', async () => {
  const cmd = uniqCmd('curl -X POST https://deploy.example.com/release')
  const cwd = process.cwd()
  const sessionId = `nudge-twice-${Math.random().toString(36).slice(2)}`
  try { rmSync(pendingPath('Bash', { command: cmd, cwd }, cwd)) } catch {}

  // Pre-seed the marker
  mkdirSync(dirname(nudgeMarkerPath(sessionId)), { recursive: true })
  writeFileSync(nudgeMarkerPath(sessionId), String(Date.now()))

  let meCalls = 0
  const server = await startMockServer((req) => {
    if (req.url === '/v1/decide/tool') {
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
    try { rmSync(pendingPath('Bash', { command: cmd, cwd }, cwd)) } catch {}
    try { rmSync(nudgeMarkerPath(sessionId)) } catch {}
  }
})

// ── fingerprint idempotency ───────────────────────────────────────────────────
// Regression guard for the cwd-stripping change. Running the hook from two
// different working directories on the same machine MUST send the same
// fingerprint to /v2/bootstrap. Previously the fingerprint included process.cwd
// and a developer would accumulate one bootstrap_accounts row per cwd they ever
// launched Claude Code from.

test('bootstrap fingerprint is identical across different cwds (no cwd in formula)', async () => {
  // Two empty tmp dirs to use as cwd. They differ in path; same machine, same user.
  const cwdA = mkdtempSync(join(tmpdir(), 'fp-cwd-a-'))
  const cwdB = mkdtempSync(join(tmpdir(), 'fp-cwd-b-'))
  // Empty fake HOME so the hook can't read any cached api_key — forces bootstrap call.
  const fakeHome = mkdtempSync(join(tmpdir(), 'fp-home-'))

  const fingerprints = []
  const server = await startMockServer((req) => {
    if (req.url === '/v2/bootstrap') {
      fingerprints.push(req.body.fingerprint)
      return {
        status: 201,
        body: {
          ok: true,
          bootstrapped: true,
          api_key: 'vb_stg_' + 'a'.repeat(48),
          account_id: '0xfake',
          user_id: 'user_fake',
          wallet_address: '0xfake',
          wallet_network: 'base-sepolia',
        },
      }
    }
    if (req.url === '/v1/decide/tool') {
      return {
        status: 200,
        body: {
          ok: true,
          run_id: 'run_x',
          risk: { risk: 'low', reason: 'low' },
          decision: { decision: 'allow', reason: 'low' },
          shadow_decision: { decision: 'allow', reason: 'low' },
          content_hash: 'sha256:fp_test',
          receipt_id: 'grcpt_fp',
        },
      }
    }
    if (req.url === '/v2/accounts/me') {
      return { status: 200, body: { ok: true, claimed: true } }
    }
    return { status: 200, body: { ok: true } }
  })

  function runFromCwd(cwd) {
    return new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [SCRIPT], {
        cwd,
        env: {
          ...process.env,
          HOME: fakeHome,
          VAIBOT_API_URL: server.url,
          // Bootstrap (no key yet) can't read a URL from the slim store — a keyless
          // env record is dropped by migrateStore — so the account base comes from the
          // env override. staging ⇒ honored without the §5 prod flag; mock issues vb_stg_.
          VAIBOT_GOVERNANCE_URL: server.url,
          VAIBOT_ENV: 'staging',
          VAIBOT_GUARD_BASE_URL: server.url,
          VAIBOT_GUARD_TOKEN: 'test-guard-token',
          VAIBOT_API_KEY: '',
          VAIBOT_MODE: 'enforce',
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
      child.stdin.write(JSON.stringify({
        tool_name: 'Bash',
        tool_input: { command: 'echo test', cwd },
        session_id: 'fp-session',
      }))
      child.stdin.end()
    })
  }

  try {
    // First call from cwdA — bootstraps fresh (no cached creds in fakeHome).
    const resA = await runFromCwd(cwdA)
    assert.equal(resA.code, 0, 'first call exits 0')
    // Wipe the credentials.json the first call cached so the second call also
    // takes the bootstrap path. Otherwise it'd reuse the cached api_key and
    // never send a fingerprint.
    try { rmSync(join(fakeHome, '.vaibot'), { recursive: true, force: true }) } catch {}

    const resB = await runFromCwd(cwdB)
    assert.equal(resB.code, 0, 'second call exits 0')

    assert.equal(fingerprints.length, 2, 'both calls hit bootstrap')
    assert.equal(
      fingerprints[0],
      fingerprints[1],
      `cwd-A fingerprint (${fingerprints[0]?.slice(0, 12)}…) must equal cwd-B fingerprint (${fingerprints[1]?.slice(0, 12)}…) — bootstrap idempotency depends on cwd being absent from the formula`,
    )
  } finally {
    await server.close()
    try { rmSync(cwdA, { recursive: true, force: true }) } catch {}
    try { rmSync(cwdB, { recursive: true, force: true }) } catch {}
    try { rmSync(fakeHome, { recursive: true, force: true }) } catch {}
  }
})

const STATE_DIR = join(tmpdir(), 'vaibot-claudecode')

test('STATE_DIR is created 0o700 and saved state files are 0o600 (no metadata leak on shared hosts)', async () => {
  try { rmSync(STATE_DIR, { recursive: true, force: true }) } catch {}
  const server = await startMockServer(() => ({
    status: 200,
    body: {
      ok: true,
      run_id: 'run_perms',
      risk: { risk: 'low', reason: 'safe' },
      decision: { decision: 'allow', reason: 'ok' },
      shadow_decision: { decision: 'allow', reason: 'ok' },
      content_hash: 'sha256:perms',
    },
  }))
  try {
    await runHook({
      apiUrl: server.url,
      input: { tool_name: 'Bash', tool_input: { command: uniqCmd('echo perms') }, session_id: 'sess_perms', tool_use_id: 'tu_perms' },
    })

    const dirMode = statSync(STATE_DIR).mode & 0o777
    assert.equal(dirMode, 0o700, `STATE_DIR should be 0o700, got 0o${dirMode.toString(8)}`)

    const stateFiles = readdirSync(STATE_DIR).filter((f) => f.endsWith('.json'))
    assert.ok(stateFiles.length > 0, 'expected at least one state file')
    for (const f of stateFiles) {
      const m = statSync(join(STATE_DIR, f)).mode & 0o777
      assert.equal(m, 0o600, `state file ${f} should be 0o600, got 0o${m.toString(8)}`)
    }
  } finally {
    await server.close()
    try { rmSync(STATE_DIR, { recursive: true, force: true }) } catch {}
  }
})

test('STATE_DIR perms are tightened on the fly when a legacy 0o755 dir already exists', async () => {
  // Simulates an upgrade from an older plugin version that created STATE_DIR
  // with default (umask-respecting) perms. The current code must chmod down to
  // 0o700 on next touch — otherwise the leak persists across plugin upgrades.
  try { rmSync(STATE_DIR, { recursive: true, force: true }) } catch {}
  mkdirSync(STATE_DIR, { recursive: true })
  chmodSync(STATE_DIR, 0o755)
  assert.equal(statSync(STATE_DIR).mode & 0o777, 0o755, 'precondition: legacy 0o755 dir')

  const server = await startMockServer(() => ({
    status: 200,
    body: {
      ok: true,
      run_id: 'run_chmod',
      risk: { risk: 'low', reason: 'safe' },
      decision: { decision: 'allow', reason: 'ok' },
      shadow_decision: { decision: 'allow', reason: 'ok' },
      content_hash: 'sha256:chmod',
    },
  }))
  try {
    await runHook({
      apiUrl: server.url,
      input: { tool_name: 'Bash', tool_input: { command: uniqCmd('echo chmod') }, session_id: 'sess_chmod', tool_use_id: 'tu_chmod' },
    })
    assert.equal(statSync(STATE_DIR).mode & 0o777, 0o700, 'legacy dir should be tightened to 0o700')
  } finally {
    await server.close()
    try { rmSync(STATE_DIR, { recursive: true, force: true }) } catch {}
  }
})

// ── Containment ───────────────────────────────────────────────────────────────
// Containment is the account-wide stop. The guard enforces it for any call that
// reaches the daemon; these tests pin the half the breaker owns — the paths where
// the daemon is never consulted at all, which are exactly the paths a stop has to
// survive. The record is read with no daemon, no network and no credentials, so
// every assertion below also proves the mock server was never called.

const CONTAINED = { contained: true, reason: 'laptop looks compromised', at: new Date().toISOString() }

function denial(stdout) {
  return JSON.parse(stdout).hookSpecificOutput
}

test('contained: a benign tool call is denied, and the guard is never consulted', async () => {
  const server = await startMockServer(() => ({ status: 200, body: { ok: true } }))
  try {
    const r = await runHook({
      apiUrl: server.url,
      containment: CONTAINED,
      input: { tool_name: 'Read', tool_input: { file_path: '/tmp/notes.txt' }, session_id: 'sess_c1', tool_use_id: 'tu_c1' },
    })
    const out = denial(r.stdout)
    assert.equal(out.permissionDecision, 'deny')
    assert.match(out.permissionDecisionReason, /containment engaged/i)
    assert.match(out.permissionDecisionReason, /laptop looks compromised/, 'the reason given when engaging should reach the agent')
    assert.equal(server.requests.length, 0, 'containment must not need the daemon or the control plane')
  } finally {
    await server.close()
  }
})

test('contained: observe mode does NOT lift it — nothing else survives observe', async () => {
  const server = await startMockServer(() => ({ status: 200, body: { ok: true } }))
  try {
    const r = await runHook({
      apiUrl: server.url,
      mode: 'observe',
      containment: CONTAINED,
      input: { tool_name: 'Read', tool_input: { file_path: '/tmp/notes.txt' }, session_id: 'sess_c2', tool_use_id: 'tu_c2' },
    })
    assert.equal(denial(r.stdout).permissionDecision, 'deny')
    assert.equal(server.requests.length, 0)
  } finally {
    await server.close()
  }
})

test('contained: VAIBOT_FAIL_OPEN does NOT lift it — the fail-open path is the point', async () => {
  const server = await startMockServer(() => ({ status: 200, body: { ok: true } }))
  try {
    const r = await runHook({
      apiUrl: server.url,
      containment: CONTAINED,
      extraEnv: { VAIBOT_FAIL_OPEN: 'true' },
      input: { tool_name: 'Bash', tool_input: { command: 'echo hi' }, session_id: 'sess_c3', tool_use_id: 'tu_c3' },
    })
    assert.equal(denial(r.stdout).permissionDecision, 'deny')
    assert.equal(server.requests.length, 0)
  } finally {
    await server.close()
  }
})

test('contained: the governance tools stay usable, so an operator can lift it', async () => {
  const server = await startMockServer(() => ({ status: 200, body: { ok: true } }))
  try {
    const r = await runHook({
      apiUrl: server.url,
      containment: CONTAINED,
      input: { tool_name: 'mcp__vaibot__vaibot_status', tool_input: {}, session_id: 'sess_c4', tool_use_id: 'tu_c4' },
    })
    assert.equal(r.code, 0)
    assert.equal(r.stdout.trim(), '', 'a governance self-call is not gated, contained or not')
  } finally {
    await server.close()
  }
})

test('contained: a look-alike MCP server gets no exemption — the boundary is `mcp__vaibot__`', async () => {
  // The exemption used to be a bare prefix, so every name BEGINNING with
  // `mcp__vaibot` was ungoverned: a server called `vaibotage` got a whole tool
  // namespace with no containment, no floor and no policy. The exemption is
  // checked before containment, so this was a way around the account-wide stop.
  for (const toolName of ['mcp__vaibotage__run', 'mcp__vaibotage', 'mcp__vaibot_evil__go', 'mcp__vaibotXYZ']) {
    const server = await startMockServer(() => ({ status: 200, body: { ok: true } }))
    try {
      const r = await runHook({
        apiUrl: server.url,
        containment: CONTAINED,
        input: { tool_name: toolName, tool_input: {}, session_id: 'sess_sq', tool_use_id: `tu_${toolName}` },
      })
      const out = denial(r.stdout)
      assert.equal(out.permissionDecision, 'deny', `${toolName} must not be exempt`)
      assert.match(out.permissionDecisionReason, /containment engaged/i)
    } finally {
      await server.close()
    }
  }
})

test('the real governance namespace is still exempt, including the bare server name', async () => {
  // The fix must not cost the operator the way out: these are the names that have
  // to keep working while contained.
  for (const toolName of ['mcp__vaibot', 'mcp__vaibot__vaibot_status', 'mcp__vaibot__vaibot_approve']) {
    const server = await startMockServer(() => ({ status: 200, body: { ok: true } }))
    try {
      const r = await runHook({
        apiUrl: server.url,
        containment: CONTAINED,
        input: { tool_name: toolName, tool_input: {}, session_id: 'sess_gov', tool_use_id: `tu_${toolName}` },
      })
      assert.equal(r.code, 0, `${toolName} must stay usable`)
      assert.equal(r.stdout.trim(), '', `${toolName} must not be gated`)
    } finally {
      await server.close()
    }
  }
})

test('a corrupt containment record does not claim containment, and does not crash the hook', async () => {
  const server = await startMockServer(() => ({ status: 200, body: { ok: true } }))
  try {
    // The breaker reads this on every single tool call; it must never be the
    // thing that takes the hook down, and it must never fail to a stop.
    const r = await runHook({
      apiUrl: server.url,
      containment: '{ not json',
      input: { tool_name: 'Read', tool_input: { file_path: '/tmp/notes.txt' }, session_id: 'sess_c5', tool_use_id: 'tu_c5' },
    })
    const out = r.stdout ? JSON.parse(r.stdout).hookSpecificOutput : null
    assert.notEqual(out?.permissionDecisionReason ?? '', undefined)
    assert.ok(!/containment engaged/i.test(r.stdout), 'an unreadable record must not read as contained')
  } finally {
    await server.close()
  }
})

// Regression: the pointer used to be keyed `tool | "Edit <file_path>" | cwd`, and
// a native "Yes" never spent it. So the call after an approved edit presented that
// edit's still-pending approval id, and the guard denied it as
// `Approval not approved (status=pending)` — every second edit to a file failed.
// Runs PreToolUse and PostToolUse against one isolated TMPDIR, the way Claude Code
// runs them: ask → Yes (PostToolUse) → identical retry → a different edit.
test('native Yes spends the pointer; a different edit to the same file never inherits it', async () => {
  const fakeTmp = mkdtempSync(join(tmpdir(), 'vaibot-cc-yes-'))
  const cwd = process.cwd()
  const file = join(cwd, `yes-${Math.random().toString(36).slice(2)}.md`)
  const editA = { file_path: file, old_string: 'one', new_string: 'two' }
  const editB = { file_path: file, old_string: 'three', new_string: 'four' }
  const pointerFor = (input) => join(fakeTmp, 'vaibot-claudecode', 'pending', `${callKey('Edit', input, cwd)}.json`)

  let n = 0
  const server = await startMockServer((req) => {
    if (req.url !== '/v1/decide/tool') return { status: 200, body: { ok: true } }
    n += 1
    return { status: 200, body: {
      ok: true, runId: `run_yes_${n}`, risk: { risk: 'high' },
      decision: { decision: 'approve', reason: 'File mutation outside workspace', approvalId: `appr_yes_${n}` },
    } }
  })
  const pre = (input, toolUseId) => runHook({ apiUrl: server.url, extraEnv: { TMPDIR: fakeTmp }, input: {
    tool_name: 'Edit', tool_input: input, session_id: 's-yes', tool_use_id: toolUseId,
  } })
  const post = (toolUseId) => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [join(__dirname, '..', 'scripts', 'post-tool-use.mjs')], {
      env: { ...process.env, TMPDIR: fakeTmp, VAIBOT_GUARD_BASE_URL: server.url, VAIBOT_GUARD_TOKEN: 'test-guard-token', VAIBOT_TIMEOUT_MS: '2000' },
      stdio: ['pipe', 'ignore', 'ignore'],
    })
    child.on('error', reject)
    child.on('exit', resolve)
    child.stdin.end(JSON.stringify({ tool_name: 'Edit', tool_use_id: toolUseId }))
  })
  const decides = () => server.requests.filter((r) => r.url === '/v1/decide/tool')

  try {
    // 1. Edit A is gated → native ask, pointer saved for out-of-band approval.
    const a = await pre(editA, 'tu_yes_a')
    assert.equal(JSON.parse(a.stdout).hookSpecificOutput.permissionDecision, 'ask')
    assert.ok(existsSync(pointerFor(editA)), 'pointer saved for the gated call')

    // 2. The user clicks Yes → PostToolUse finalizes A as approved and drops
    //    A's pointer.
    await post('tu_yes_a')
    const fin = server.requests.filter((r) => r.url === '/v1/finalize/tool')
    assert.equal(fin.length, 1)
    assert.equal(fin[0].body.runId, 'run_yes_1')
    assert.equal(fin[0].body.result.approval, 'approved')
    assert.ok(!existsSync(pointerFor(editA)), 'a native Yes spends the pointer')

    // 3. The next edit to the same file gets a fresh decision — this is the
    //    call that used to be denied `status=pending`.
    const b = await pre(editB, 'tu_yes_b')
    assert.equal(JSON.parse(b.stdout).hookSpecificOutput.permissionDecision, 'ask')
    assert.equal(decides().at(-1).body.approval?.approvalId, undefined, 'edit B must not present edit A\'s approval')
    await post('tu_yes_b')

    // 4. Re-running the identical call (e.g. the same `npm test`) also gets a
    //    fresh decision, not a redemption of the approval the Yes already used.
    const a2 = await pre(editA, 'tu_yes_a2')
    assert.equal(JSON.parse(a2.stdout).hookSpecificOutput.permissionDecision, 'ask')
    assert.equal(decides().at(-1).body.approval?.approvalId, undefined, 'spent approval is not re-presented')
  } finally {
    await server.close()
    try { rmSync(fakeTmp, { recursive: true, force: true }) } catch {}
  }
})

test('a live pointer for one edit is never presented for a different edit to the same file', async () => {
  const fakeTmp = mkdtempSync(join(tmpdir(), 'vaibot-cc-key-'))
  const cwd = process.cwd()
  const file = join(cwd, `key-${Math.random().toString(36).slice(2)}.md`)
  const editA = { file_path: file, old_string: 'one', new_string: 'two' }
  const editB = { file_path: file, old_string: 'three', new_string: 'four' }
  // A's approval is still outstanding (e.g. waiting on the dashboard).
  const pointerA = join(fakeTmp, 'vaibot-claudecode', 'pending', `${callKey('Edit', editA, cwd)}.json`)
  mkdirSync(dirname(pointerA), { recursive: true })
  writeFileSync(pointerA, JSON.stringify({ content_hash: 'appr_outstanding', ts: Date.now() }))

  const server = await startMockServer((req) => req.url === '/v1/decide/tool'
    ? { status: 200, body: { ok: true, runId: 'run_key_b', risk: { risk: 'high' },
        decision: { decision: 'approve', reason: 'gated', approvalId: 'appr_key_b' } } }
    : { status: 200, body: { ok: true } })
  try {
    await runHook({ apiUrl: server.url, extraEnv: { TMPDIR: fakeTmp }, input: {
      tool_name: 'Edit', tool_input: editB, session_id: 's-key', tool_use_id: 'tu_key_b',
    } })
    const decide = server.requests.find((r) => r.url === '/v1/decide/tool')
    assert.equal(decide.body.approval?.approvalId, undefined)
    assert.ok(existsSync(pointerA), 'A\'s outstanding pointer is left for A')
  } finally {
    await server.close()
    try { rmSync(fakeTmp, { recursive: true, force: true }) } catch {}
  }
})

test('the pointer key is the exact call: key order is irrelevant, any value change is a new key', () => {
  const cwd = '/w'
  const a = { file_path: '/w/f.md', old_string: 'x', new_string: 'y' }
  const reordered = { new_string: 'y', old_string: 'x', file_path: '/w/f.md' }
  assert.equal(callKey('Edit', a, cwd), callKey('Edit', reordered, cwd))
  assert.notEqual(callKey('Edit', a, cwd), callKey('Edit', { ...a, new_string: 'z' }, cwd))
  assert.notEqual(callKey('Edit', a, cwd), callKey('Write', a, cwd))
  assert.notEqual(callKey('Edit', a, cwd), callKey('Edit', a, '/other'))
  // Nested values count too (a top-level-keys-only replacer would drop them).
  assert.notEqual(
    callKey('MultiEdit', { edits: [{ old_string: 'a', new_string: 'b' }] }, cwd),
    callKey('MultiEdit', { edits: [{ old_string: 'a', new_string: 'c' }] }, cwd),
  )
})
